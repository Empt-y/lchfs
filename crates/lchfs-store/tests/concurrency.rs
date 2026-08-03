//! Core concurrency test suite for Phase E (E.1-E.9), closing out the plan's
//! test list. fsync/crash-recovery-specific cases already live in
//! tests/crash_recovery.rs; incremental-append-specific cases in
//! tests/incremental_write.rs. This file covers what's left: Send/Sync,
//! general cross-inode and same-inode concurrent writers, single-shard
//! (M=1) contention stress, and checkpoint racing with active writers.

use lchfs_format::PoolParams;
use lchfs_store::Pool;
use std::sync::Arc;

fn small_params(logical_shard_count: u32) -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 256 * 1024,
        meta_segment_cap_bytes: 256 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count,
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

#[test]
fn pool_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Pool>();
}

#[test]
fn concurrent_writers_different_inodes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params(64)).unwrap());

    let mut inos = Vec::new();
    for i in 0..16u64 {
        inos.push(pool.create_file(1, &format!("f{i}"), 0o644).unwrap());
    }

    let handles: Vec<_> = inos
        .iter()
        .enumerate()
        .map(|(idx, &ino)| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let data = deterministic_bytes(idx as u64 + 1, 3000);
                pool.write(ino, 0, &data).unwrap();
                (ino, data)
            })
        })
        .collect();

    let results: Vec<(u64, Vec<u8>)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (ino, data) in &results {
        let read_back = pool.read(*ino, 0, data.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), data.as_slice(), "mismatch for ino {ino}");
    }
}

#[test]
fn concurrent_writers_same_inode_disjoint_offsets() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params(8)).unwrap());
    let ino = pool.create_file(1, "shared", 0o644).unwrap();

    // Pre-size the file so every writer's offset is valid and disjoint --
    // this exercises ino_locks serializing the fallback path's read-
    // modify-write splice against real concurrent contention on one
    // inode, per ARCHITECTURE.md §3's per-inode ordering guarantee.
    const CHUNK: usize = 500;
    const WRITERS: u64 = 10;
    pool.set_size(ino, CHUNK as u64 * WRITERS).unwrap();

    let mut expected = vec![0u8; CHUNK * WRITERS as usize];
    let mut chunks = Vec::new();
    for w in 0..WRITERS {
        let data = deterministic_bytes(w + 1, CHUNK);
        expected[(w as usize * CHUNK)..((w as usize + 1) * CHUNK)].copy_from_slice(&data);
        chunks.push(data);
    }

    let handles: Vec<_> = chunks
        .into_iter()
        .enumerate()
        .map(|(w, data)| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                pool.write(ino, (w * CHUNK) as u64, &data).unwrap();
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let read_back = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());

    pool.checkpoint().unwrap();
    let read_after_checkpoint = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_after_checkpoint.as_ref(), expected.as_slice());
}

#[test]
fn single_shard_stress_many_threads_many_inodes() {
    // M=1: every op routes through one logical shard, one committer ever
    // claims it at a time -- stresses the claimed CAS + ring backpressure
    // path without needing a large M.
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params(1)).unwrap());

    let mut inos = Vec::new();
    for i in 0..12u64 {
        inos.push(pool.create_file(1, &format!("f{i}"), 0o644).unwrap());
    }

    let handles: Vec<_> = inos
        .iter()
        .enumerate()
        .map(|(idx, &ino)| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let mut expected = Vec::new();
                for i in 0..15u64 {
                    let chunk = deterministic_bytes(idx as u64 * 100 + i, 200);
                    let offset = expected.len() as u64;
                    pool.write(ino, offset, &chunk).unwrap();
                    expected.extend_from_slice(&chunk);
                }
                (ino, expected)
            })
        })
        .collect();

    let results: Vec<(u64, Vec<u8>)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (ino, expected) in &results {
        let read_back = pool.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch for ino {ino}");
    }

    pool.checkpoint().unwrap();
    for (ino, expected) in &results {
        let read_back = pool.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch after checkpoint for ino {ino}");
    }
}

#[test]
fn checkpoint_running_concurrently_with_active_writers_no_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params(16)).unwrap());

    let mut inos = Vec::new();
    for i in 0..8u64 {
        inos.push(pool.create_file(1, &format!("f{i}"), 0o644).unwrap());
    }

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let checkpointer = {
        let pool = Arc::clone(&pool);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut count = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                pool.checkpoint().unwrap();
                count += 1;
                if count > 500 {
                    break; // safety valve against an unbounded loop
                }
            }
        })
    };

    let writers: Vec<_> = inos
        .iter()
        .enumerate()
        .map(|(idx, &ino)| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let mut expected = Vec::new();
                for i in 0..30u64 {
                    let chunk = deterministic_bytes(idx as u64 * 1000 + i, 150);
                    let offset = expected.len() as u64;
                    pool.write(ino, offset, &chunk).unwrap();
                    expected.extend_from_slice(&chunk);
                }
                (ino, expected)
            })
        })
        .collect();

    let results: Vec<(u64, Vec<u8>)> = writers.into_iter().map(|h| h.join().unwrap()).collect();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    checkpointer.join().unwrap();

    pool.checkpoint().unwrap(); // final checkpoint, guaranteed durable baseline
    for (ino, expected) in &results {
        let read_back = pool.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch for ino {ino}");
    }

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    for (ino, expected) in &results {
        let read_back = pool2.read(*ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice(), "mismatch after reopen for ino {ino}");
    }
}
