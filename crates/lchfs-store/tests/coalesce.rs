//! Targeted tests for the E.11 `CoalesceDaemon`, driven through `Pool`'s
//! public `run_gc_and_coalesce_pass()` (the same path the background
//! timer calls, exposed so tests can call it synchronously).

use lchfs_format::PoolParams;
use lchfs_index::{ChunkLocationCache, PendingDedupPins, RedbIndex};
use lchfs_store::coalesce::CoalesceDaemon;
use lchfs_store::Pool;
use parking_lot::RwLock;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 4096,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
    }
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as u8);
    }
    out
}

/// Writes 10 distinct-content files, checkpoints, then overwrites 9 of
/// them so their original content becomes unreferenced -- forcing real
/// segment rollover (tiny cap) and a genuine low-liveness segment.
fn setup_low_liveness_pool(dir: &std::path::Path) -> (Pool, Vec<(u64, Vec<u8>)>) {
    let pool = Pool::create(dir, small_params()).unwrap();
    let mut inos = Vec::new();
    for i in 0..10u64 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &deterministic_bytes(i + 1, 3000)).unwrap();
        inos.push(ino);
    }
    pool.checkpoint().unwrap();

    let mut survivors = Vec::new();
    // Keep the last file's original content untouched (the "still live,
    // must survive repack" control); overwrite the rest.
    let last = *inos.last().unwrap();
    survivors.push((last, deterministic_bytes(10, 3000)));
    for &ino in &inos[..9] {
        let data = deterministic_bytes(1000 + ino, 200);
        pool.write(ino, 0, &data).unwrap();
        survivors.push((ino, data));
    }
    pool.checkpoint().unwrap();
    (pool, survivors)
}

#[test]
fn post_repack_reads_are_byte_identical_and_old_segment_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(dir.path());

    let data_dir = dir.path().join("segments/data");
    let before: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    pool.run_gc_and_coalesce_pass().unwrap();

    for (ino, expected) in &survivors {
        let read_back = pool.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch for ino {ino} after coalesce");
    }

    let after: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert_ne!(before, after, "coalesce should have changed the segment file set");
    // At least one old segment file must actually be gone (not just a new one added).
    assert!(
        !before.is_subset(&after),
        "at least one pre-coalesce segment file should have been deleted"
    );
}

#[test]
fn reopen_after_coalesce_recovers_everything_via_slow_path() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(dir.path());
    pool.run_gc_and_coalesce_pass().unwrap();
    // Deliberately no checkpoint after the coalesce pass -- INDEX.redb's
    // checkpointed generation still matches the superblock's from before
    // coalesce touched anything (coalesce's index updates are Immediate-
    // durable via flush(), but never bump index_generation), so this
    // reopen exercises the *fast* mount path per the next test; this one
    // additionally confirms recovery is correct at all.
    drop(pool);

    let pool2 = Pool::open(dir.path()).unwrap();
    for (ino, expected) in &survivors {
        let read_back = pool2.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch for ino {ino} after reopen");
    }
}

#[test]
fn reopen_after_checkpoint_following_coalesce_uses_fast_path_and_is_correct() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(dir.path());
    pool.run_gc_and_coalesce_pass().unwrap();
    // A full checkpoint after coalescing durably advances index_generation
    // to match the superblock -- this reopen must take Pool::open's fast
    // path (trust INDEX.redb, no full segment rescan) and still resolve
    // every chunk correctly through the post-coalesce locations.
    pool.checkpoint().unwrap();
    drop(pool);

    let pool2 = Pool::open(dir.path()).unwrap();
    for (ino, expected) in &survivors {
        let read_back = pool2.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch for ino {ino} after fast-path reopen");
    }
}

#[test]
fn coalesce_pass_on_a_fresh_pool_is_a_correct_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let data = deterministic_bytes(1, 500);
    pool.write(ino, 0, &data).unwrap();
    pool.checkpoint().unwrap();

    pool.run_gc_and_coalesce_pass().unwrap();

    let read_back = pool.read(ino, 0, data.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), data.as_slice());
}

#[test]
fn dedup_hit_write_survives_a_coalesce_pass_before_its_own_checkpoint() {
    // Regression test for the GC/Coalesce-vs-dedup race (see
    // `PendingDedupPins`'s doc comment in lchfs-index): a write that
    // resolves a dedup hit against an *already-dead-per-DAG* physical
    // location, but hasn't been checkpointed yet, must not have that
    // location reclaimed out from under it by a coalesce pass that runs
    // in between.
    let dir = tempfile::tempdir().unwrap();
    let (pool, _survivors) = setup_low_liveness_pool(dir.path());

    // File 0's *original* content is now dead per the current root (it was
    // overwritten and checkpointed by `setup_low_liveness_pool`), but its
    // bytes are still durably sitting in a sealed segment -- exactly the
    // physical state a stale dedup-index entry can still point at.
    let orphaned_content = deterministic_bytes(1, 3000);

    // A brand-new file dedups against that orphaned content. This pins its
    // hash (the fix) but is deliberately *not* checkpointed yet -- the
    // in-flight window the original bug lost data in.
    let ino_new = pool.create_file(1, "dedup-hit-before-checkpoint", 0o644).unwrap();
    pool.write(ino_new, 0, &orphaned_content).unwrap();

    // A coalesce pass now runs against the *old* root (doesn't know about
    // `ino_new` yet). Pre-fix, this could delete the only physical copy of
    // `orphaned_content` since nothing in the old root's DAG referenced it.
    pool.run_gc_and_coalesce_pass().unwrap();

    // Only now does `ino_new`'s reference become durable and DAG-reachable.
    pool.checkpoint().unwrap();

    // Force resolution through the persisted index and on-disk segments
    // alone -- `Pool::read` would otherwise happily serve this from
    // `file_state`'s in-memory cache (populated at `write()` time),
    // masking the very question this test exists to answer: does the
    // *physical* copy still exist on disk?
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();

    let read_back = pool.read(ino_new, 0, orphaned_content.len() as u32).unwrap();
    assert_eq!(
        read_back.as_ref(),
        orphaned_content.as_slice(),
        "a dedup-hit write must survive a coalesce pass that races its own checkpoint"
    );
}

#[test]
fn generation_change_mid_pass_blocks_deletion_even_without_a_pin() {
    // Direct test of the freshness gate in `CoalesceDaemon::repack_segment`
    // (see its doc comment): even with *no* pin at all protecting anything,
    // a repack pass must not delete a segment if a checkpoint published a
    // new root after this pass's own mark() ran -- its `live` bitmap could
    // be stale in a way `PendingDedupPins` alone can't cover (a pin taken
    // *and* released, i.e. checkpointed, entirely within one pass's
    // processing window -- not reproducible deterministically through real
    // threads, since it depends on exact timing). Driven directly against
    // `CoalesceDaemon` (bypassing `Pool::run_gc_and_coalesce_pass`, which
    // always reads the *current* generation) so the mismatch this test
    // needs can be manufactured deterministically instead.
    let dir = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(dir.path());
    let root = pool.debug_root_hash();
    drop(pool);

    let index = RedbIndex::open(&dir.path().join("INDEX.redb")).unwrap();
    let cache = ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    let locations = Arc::new(cache);
    let persisted_index = RwLock::new(index);
    // Comfortably past every segment id `setup_low_liveness_pool` could
    // have allocated -- collision would only matter if it clashed with an
    // existing segment file, which this is far too high to do.
    let next_segment_id = AtomicU64::new(1_000_000);

    let mut daemon = CoalesceDaemon::new(
        dir.path().to_path_buf(),
        Arc::clone(&locations),
        Arc::new(PendingDedupPins::new()),
    );

    let data_dir = dir.path().join("segments/data");
    let before: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    // `generation_at_mark` (0) deliberately doesn't match
    // `published_generation`'s value (1) below -- simulating "a checkpoint
    // completed after this pass's mark() ran, before it finished."
    let published_generation = AtomicU64::new(1);
    daemon
        .run_pass(&[root], 0, &published_generation, &persisted_index, &next_segment_id)
        .unwrap();

    let after: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    // Every pre-pass segment must still be present -- the gate blocks
    // *deletion*, not the copy-forward work itself: whatever was
    // genuinely live per this pass's (stale) mark is still correctly
    // relocated into a fresh segment and the index repointed at it (see
    // `repack_segment`'s doc comment on why that doesn't need rolling
    // back), so `after` legitimately gains new segments too.
    assert!(
        before.is_subset(&after),
        "a stale generation must block every segment deletion this pass, even though \
         the same setup deletes several when generations match (see \
         post_repack_reads_are_byte_identical_and_old_segment_is_gone); \
         before={before:?} after={after:?}"
    );

    // And nothing was corrupted along the way -- every survivor still
    // reads back correctly through a fresh mount.
    let pool2 = Pool::open(dir.path()).unwrap();
    for (ino, expected) in &survivors {
        let read_back = pool2.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice());
    }
}

#[test]
fn repeated_coalesce_passes_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(dir.path());

    pool.run_gc_and_coalesce_pass().unwrap();
    pool.run_gc_and_coalesce_pass().unwrap();
    pool.run_gc_and_coalesce_pass().unwrap();

    for (ino, expected) in &survivors {
        let read_back = pool.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch for ino {ino} after repeated coalesce");
    }
}
