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


/// A read is not under the inode lock, and it must never see a file
/// between states. Files are written the way FUSE's writeback cache
/// delivers them -- a first write that takes the whole-file path, then
/// sequential pieces through an incremental session -- while a pool of
/// readers verifies whatever has been written so far, over and over, and
/// a checkpoint loops as fast as it can. Two races used to show here: the
/// checkpoint snapshotted `file_state` for every dirty inode before
/// taking any inode lock, and could catch a fallback write between
/// putting its bytes in and its chunk list in, publishing an empty chunk
/// list for a file full of data; and it removed a session before
/// publishing what the session held, so a read in that window fell
/// through to the previous (empty, for a new file) ContentRef and came
/// back zeros. On a live mount it was one 128 KiB piece of zeros in a
/// 10 MB file's checksum, once, with the data on disk fine; the readers
/// run continuously here so they land in that per-inode window reliably.
#[test]
fn reads_never_see_a_file_between_states_while_checkpoints_race() {
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let dir = tempfile::tempdir().unwrap();
    // Default parameters: the pattern needs writes large enough that the
    // first one is past the inline threshold and chunks are real.
    let pool = Arc::new(Pool::create(dir.path(), PoolParams::default()).unwrap());
    let done = Arc::new(AtomicBool::new(false));
    let checkpoints = Arc::new(AtomicU64::new(0));
    let bad = Arc::new(AtomicU64::new(0));
    // (ino, seed) for every file whose last piece has been written -- what
    // the readers are allowed to expect complete.
    let ready: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));

    // Small files, many of them: each new file has exactly one window --
    // its first checkpoint, which finalizes the session and publishes the
    // ContentRef -- so thousands of files means thousands of windows. Two
    // chunks each (256 KiB, well past the 64-byte inline threshold), the
    // first 64 KiB write taking the whole-file path and the rest an
    // incremental session, exactly as the writeback cache delivers them.
    let total = 256usize << 10;
    let piece = 64usize << 10;
    let step = 64 * 1024;
    let files = 4000u64;

    let ckpt = {
        let pool = Arc::clone(&pool);
        let done = Arc::clone(&done);
        let checkpoints = Arc::clone(&checkpoints);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                pool.checkpoint().unwrap();
                checkpoints.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // More reader threads than cores: the extra scheduling pressure widens
    // the window a read has to land in.
    let readers: Vec<_> = (0..16)
        .map(|t| {
            let pool = Arc::clone(&pool);
            let done = Arc::clone(&done);
            let bad = Arc::clone(&bad);
            let ready = Arc::clone(&ready);
            std::thread::spawn(move || {
                let mut x = (t as u64) * 2654435761 + 1;
                while !done.load(Ordering::Relaxed) {
                    let pick = {
                        let r = ready.lock();
                        if r.is_empty() {
                            None
                        } else {
                            x ^= x << 13;
                            x ^= x >> 7;
                            x ^= x << 17;
                            Some(r[(x as usize) % r.len()])
                        }
                    };
                    let Some((ino, seed)) = pick else {
                        std::thread::yield_now();
                        continue;
                    };
                    let data = deterministic_bytes(seed, total);
                    let mut off = 0usize;
                    while off < total {
                        let part = pool.read(ino, off as u64, step as u32).unwrap();
                        // A ready file is fully written, so a short or empty
                        // read of an in-range offset is the bug showing (the
                        // file seen mid-checkpoint), same as a byte mismatch.
                        if part.is_empty() || part.as_ref() != &data[off..off + part.len()] {
                            bad.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        off += part.len();
                    }
                }
            })
        })
        .collect();

    for f in 0..files {
        let data = deterministic_bytes(f, total);
        let ino = pool.create_file(1, &format!("f{f}"), 0o644).unwrap();
        for p in 0..(total / piece) {
            pool.write(ino, (p * piece) as u64, &data[p * piece..(p + 1) * piece]).unwrap();
        }
        ready.lock().push((ino, f));
    }
    // Let the readers keep racing the checkpoint for a moment after the
    // last file, so the last few files' first checkpoints are covered too.
    std::thread::sleep(std::time::Duration::from_millis(50));
    done.store(true, Ordering::Relaxed);
    ckpt.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }
    assert!(checkpoints.load(Ordering::Relaxed) > 20, "the checkpoint loop did not race anything");
    assert_eq!(bad.load(Ordering::Relaxed), 0, "reads saw a file mid-checkpoint");

    // And what was persisted is right too.
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    for f in 0..files {
        let ino = pool.lookup(1, &format!("f{f}")).unwrap().unwrap();
        assert_eq!(
            pool.read(ino, 0, total as u32).unwrap().as_ref(),
            deterministic_bytes(f, total).as_slice(),
            "file {f}"
        );
    }
}
