//! Targeted tests for the E.11 `CoalesceDaemon`, driven through `Pool`'s
//! public `run_gc_and_coalesce_pass()` (the same path the background
//! timer calls, exposed so tests can call it synchronously).

use lchfs_chunk::{Chunker, FastCdcChunker};
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
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
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
    cache.extend(index.iter_preferred_locations().unwrap());
    let locations = Arc::new(cache);
    let persisted_index = RwLock::new(index);
    // Comfortably past every segment id `setup_low_liveness_pool` could
    // have allocated -- collision would only matter if it clashed with an
    // existing segment file, which this is far too high to do.
    let next_segment_id = AtomicU64::new(1_000_000);

    let mut daemon = CoalesceDaemon::new(
        vec![lchfs_store::Vdev::new(0, dir.path().to_path_buf())],
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

#[test]
fn content_rewritten_after_its_segment_was_reclaimed_is_stored_again() {
    // The mirror image of the test above: here the coalesce pass wins
    // outright and deletes the dead content's segment *before* anything
    // writes those bytes again. Reclaiming used to leave the content's
    // dedup-cache and index entries behind, pointing into the deleted
    // segment, so the next write of identical bytes dedup-hit a record
    // that no longer existed and the file came back unreadable. A
    // database writing a page back to an earlier state is all it takes;
    // the torture suite's fault-storm test hit it most runs.
    let dir = tempfile::tempdir().unwrap();
    let (pool, _survivors) = setup_low_liveness_pool(dir.path());
    let resurrected = deterministic_bytes(1, 3000);

    // Enough checkpoints to clear every segment's seal-generation grace,
    // and enough passes for the dead content's segment to actually go.
    for _ in 0..4 {
        pool.checkpoint().unwrap();
        pool.run_gc_and_coalesce_pass().unwrap();
    }

    let ino = pool.create_file(1, "same-bytes-again", 0o644).unwrap();
    pool.write(ino, 0, &resurrected).unwrap();
    pool.checkpoint().unwrap();

    // Through the persisted index and on-disk segments only: an fd the
    // running pool still holds on the unlinked segment could otherwise
    // serve the read and hide the loss.
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let read_back = pool.read(ino, 0, resurrected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), resurrected.as_slice());
}

#[test]
fn a_chunk_identical_to_a_meta_object_reads_back() {
    // The dedup cache is keyed by content hash alone, shared by the Data
    // and Meta streams. The empty root directory's DirectoryObject encodes
    // to eight zero bytes, so a file whose last chunk is eight zero bytes
    // dedup-hits that Meta-stream record -- and reads used to open the
    // segment id in the Data directory, where it does not exist.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();

    // The chunker cuts only while a full `chunk_max_size` is buffered and
    // flushes the rest as one final chunk, so eight zeros become a chunk of
    // their own after a forced max-size cut: a run of one byte value the
    // rolling hash never cuts inside. Which value that is belongs to the
    // chunker, so ask it rather than hard-code one.
    let params = small_params();
    let max = params.chunk_max_size as usize;
    let content = (1..=255u8)
        .map(|b| {
            let mut c = vec![b; max];
            c.extend_from_slice(&[0u8; 8]);
            c
        })
        .find(|c| {
            let mut chunker = FastCdcChunker::new(params.chunk_avg_size, params.chunk_min_size, params.chunk_max_size);
            let mut cuts = chunker.push(c);
            cuts.extend(chunker.finish());
            cuts.last().is_some_and(|last| last.len == 8)
        })
        .expect("setup: some byte value never cuts before chunk_max_size");
    let boundary = max;

    let ino = pool.create_file(1, "zero-tail", 0o644).unwrap();
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    let tail = *pool.debug_chunk_refs(ino).unwrap().last().unwrap();
    assert_eq!((tail.logical_offset, tail.len), (boundary as u64, 8), "setup: the zeros must be a chunk of their own");

    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let read_back = pool.read(ino, 0, content.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), content.as_slice());
    // And the GC mark and fsck, which read every reachable record, still
    // walk it.
    pool.run_gc_and_coalesce_pass().unwrap();
    pool.checkpoint().unwrap();
    drop(pool);
    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &live_roots);
    assert!(report.is_clean(), "fsck: {:?}", report.errors);
}

/// Open descriptors this process holds on files under `root` that have
/// since been unlinked -- what the kernel shows as "(deleted)".
fn deleted_fds_under(root: &std::path::Path) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|target| {
            let target = target.to_string_lossy();
            target.starts_with(&*root.to_string_lossy()) && target.ends_with(" (deleted)")
        })
        .count()
}

#[test]
fn coalesce_closes_its_readers_on_segments_it_deleted() {
    // An open reader keeps an unlinked segment's space allocated and costs
    // a descriptor; the reader cache used to keep one for every segment
    // coalesce ever deleted, for the life of the mount.
    let dir = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(dir.path());
    drop(pool);
    // A fresh mount opens a reader on every segment it scans.
    let pool = Pool::open(dir.path()).unwrap();
    let data_dir = dir.path().join("segments/data");
    let before: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    for _ in 0..4 {
        pool.checkpoint().unwrap();
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    let after: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert!(!before.is_subset(&after), "setup: coalesce must have deleted a segment");

    assert_eq!(deleted_fds_under(dir.path()), 0, "descriptors left open on deleted segments");
    for (ino, expected) in &survivors {
        assert_eq!(pool.read(*ino, 0, expected.len() as u32).unwrap().as_ref(), expected.as_slice());
    }
}

#[test]
fn every_dedup_pin_is_released_by_the_checkpoint_that_captures_it() {
    // Overwrites on the fallback path re-chunk the whole file, so each one
    // pins every unchanged chunk again. Checkpoints used to release one pin
    // per hash they encoded, leaving the rest pinned until remount -- and a
    // pinned hash is never reclaimed, whatever later happens to the file.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let kept = pool.create_file(1, "kept", 0o644).unwrap();
    let doomed = pool.create_file(1, "doomed", 0o644).unwrap();
    pool.write(kept, 0, &deterministic_bytes(3, 40_000)).unwrap();
    pool.write(doomed, 0, &deterministic_bytes(4, 40_000)).unwrap();
    pool.checkpoint().unwrap();

    for k in 0..5u64 {
        pool.write(kept, 20_000 + k * 100, b"x").unwrap();
        pool.write(doomed, 20_000 + k * 100, b"x").unwrap();
    }
    assert!(pool.debug_pinned_hash_count() > 0, "setup: overwrites must dedup-hit");
    // A file unlinked before any checkpoint captured its pins.
    pool.unlink(1, "doomed").unwrap();

    pool.checkpoint().unwrap();
    assert_eq!(pool.debug_pinned_hash_count(), 0);
}
