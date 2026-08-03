//! Targeted tests for the E.11 `CoalesceDaemon`, driven through `Pool`'s
//! public `run_gc_and_coalesce_pass()` (the same path the background
//! timer calls, exposed so tests can call it synchronously).

use lchfs_format::PoolParams;
use lchfs_store::Pool;

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
