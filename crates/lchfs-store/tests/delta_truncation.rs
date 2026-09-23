//! Delta-log truncation (ARCHITECTURE.md §7): a shard's delta segments go
//! once no replay can need them, instead of accumulating for the life of
//! the pool -- and never one a crash-recovering mount still needs.

use lchfs_format::PoolParams;
use lchfs_store::Pool;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 256 * 1024,
        meta_segment_cap_bytes: 256 * 1024,
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

fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// fsyncs a round of writes to `files`, then rolls every shard's log so
/// the round sits in segments truncation may consider.
fn fsync_round(pool: &Pool, files: &[u64], round: u64) {
    for (i, &ino) in files.iter().enumerate() {
        pool.write(ino, 0, &bytes(round * 1000 + i as u64, 3000)).unwrap();
        pool.fsync(ino).unwrap();
    }
    pool.debug_roll_delta_logs().unwrap();
}

#[test]
fn segments_every_published_root_covers_are_deleted_and_the_rest_kept() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let files: Vec<u64> = (0..16).map(|i| pool.create_file(1, &format!("f{i}"), 0o644).unwrap()).collect();

    for round in 0..10 {
        fsync_round(&pool, &files, round);
    }
    let before = pool.debug_delta_segment_count();
    assert!(before >= 40, "every round's segments are still there: {before}");

    // Not yet: truncation lags a published root behind, and there is only
    // the one from create.
    pool.run_gc_and_coalesce_pass().unwrap();
    assert_eq!(pool.debug_delta_segment_count(), before);

    // Two checkpoints later every rolled segment is covered by the older
    // of the last two published roots.
    pool.checkpoint().unwrap();
    pool.checkpoint().unwrap();
    pool.run_gc_and_coalesce_pass().unwrap();
    let after = pool.debug_delta_segment_count();
    // What remains is each shard's current segment.
    assert!(after <= 4, "{after} delta segments left of {before}");

    for (i, &ino) in files.iter().enumerate() {
        assert_eq!(pool.read(ino, 0, 3000).unwrap().as_ref(), bytes(9000 + i as u64, 3000).as_slice());
    }
}

#[test]
fn a_crash_after_truncation_still_replays_every_fsync_since_the_last_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let files: Vec<u64>;
    {
        let pool = Pool::create(dir.path(), small_params()).unwrap();
        files = (0..12).map(|i| pool.create_file(1, &format!("f{i}"), 0o644).unwrap()).collect();
        for round in 0..5 {
            fsync_round(&pool, &files, round);
        }
        let before = pool.debug_delta_segment_count();
        pool.checkpoint().unwrap();
        pool.checkpoint().unwrap();
        pool.run_gc_and_coalesce_pass().unwrap();
        assert!(pool.debug_delta_segment_count() < before, "truncation must have run for this to test anything");
        // fsync'd after the last checkpoint: only the delta log has these,
        // some in rolled segments and some in the current ones.
        fsync_round(&pool, &files, 5);
        for (i, &ino) in files.iter().enumerate().take(6) {
            pool.write(ino, 0, &bytes(6000 + i as u64, 3000)).unwrap();
            pool.fsync(ino).unwrap();
        }
        pool.run_gc_and_coalesce_pass().unwrap();
        // A crash: dropped with no checkpoint (Drop does not run one).
        drop(pool);
    }
    let pool = Pool::open(dir.path()).unwrap();
    for (i, &ino) in files.iter().enumerate() {
        let want = if i < 6 { bytes(6000 + i as u64, 3000) } else { bytes(5000 + i as u64, 3000) };
        assert_eq!(pool.read(ino, 0, 3000).unwrap().as_ref(), want.as_slice(), "file {i}");
    }
}

#[test]
fn concurrent_snapshot_creates_lose_none() {
    let dir = tempfile::tempdir().unwrap();
    let pool = std::sync::Arc::new(Pool::create(dir.path(), small_params()).unwrap());
    let threads: Vec<_> = (0..4)
        .map(|t| {
            let pool = std::sync::Arc::clone(&pool);
            std::thread::spawn(move || {
                for i in 0..8 {
                    pool.create_snapshot(&format!("t{t}-{i}")).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(pool.list_snapshots().unwrap().len(), 32);
    assert!(pool.create_snapshot(&format!("{}x", lchfs_store::RESERVED_SNAPSHOT_PREFIX)).is_err());
}
