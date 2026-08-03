//! Targeted tests for the E.6 sequential-append fast path (incremental
//! FastCDC chunking through `write_incremental`), which the general
//! `tests/pool.rs` suite doesn't specifically exercise.

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
fn many_sequential_small_writes_build_correct_large_file() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "big", 0o644).unwrap();

    // First write establishes the file above inline_threshold via the
    // fallback path; every subsequent write should be a pure sequential
    // append eligible for the fast path.
    let mut expected = Vec::new();
    for i in 0..200u64 {
        let chunk = deterministic_bytes(i, 137); // odd size, deliberately not a round number
        let offset = expected.len() as u64;
        pool.write(ino, offset, &chunk).unwrap();
        expected.extend_from_slice(&chunk);
    }

    assert!(expected.len() as u32 > small_params().inline_threshold);

    // Read before any checkpoint -- exercises read()'s "active session"
    // assembly path (session never finalized yet).
    let read_back = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());

    // Partial read in the middle.
    let mid = pool.read(ino, 5000, 1000).unwrap();
    assert_eq!(mid.as_ref(), &expected[5000..6000]);

    pool.checkpoint().unwrap();
    let read_after_checkpoint = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_after_checkpoint.as_ref(), expected.as_slice());

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_after_reopen = pool2.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_after_reopen.as_ref(), expected.as_slice());
}

#[test]
fn out_of_order_write_mid_session_falls_back_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let mut expected = Vec::new();
    for i in 0..20u64 {
        let chunk = deterministic_bytes(i, 200);
        let offset = expected.len() as u64;
        pool.write(ino, offset, &chunk).unwrap();
        expected.extend_from_slice(&chunk);
    }
    assert!(expected.len() as u32 > small_params().inline_threshold);

    // A genuine random-access overwrite in the middle -- must trigger the
    // fallback path, not corrupt the incremental session's view.
    let overwrite = deterministic_bytes(999, 50);
    pool.write(ino, 100, &overwrite).unwrap();
    expected[100..150].copy_from_slice(&overwrite);

    let read_back = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());

    // A subsequent sequential append (offset == current size) should
    // start a *fresh* fast-path session seeded from the correct
    // (post-overwrite) chunk list, not silently drop the overwrite.
    let tail = deterministic_bytes(42, 300);
    let offset = expected.len() as u64;
    pool.write(ino, offset, &tail).unwrap();
    expected.extend_from_slice(&tail);

    let read_back2 = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back2.as_ref(), expected.as_slice());

    pool.checkpoint().unwrap();
    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let final_read = pool2.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(final_read.as_ref(), expected.as_slice());
}

#[test]
fn checkpoint_finalizes_session_and_next_write_starts_fresh_session() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let mut expected = Vec::new();
    for i in 0..10u64 {
        let chunk = deterministic_bytes(i, 100);
        let offset = expected.len() as u64;
        pool.write(ino, offset, &chunk).unwrap();
        expected.extend_from_slice(&chunk);
    }
    assert!(expected.len() as u32 > small_params().inline_threshold);
    pool.checkpoint().unwrap();

    // More sequential appends after the checkpoint finalized the first
    // session -- must correctly seed from the checkpointed chunk list via
    // current_chunk_refs, continuing to build on top of it.
    for i in 10..20u64 {
        let chunk = deterministic_bytes(i, 100);
        let offset = expected.len() as u64;
        pool.write(ino, offset, &chunk).unwrap();
        expected.extend_from_slice(&chunk);
    }

    let read_back = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());

    pool.checkpoint().unwrap();
    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let final_read = pool2.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(final_read.as_ref(), expected.as_slice());
}

#[test]
fn set_size_mid_session_discards_session_without_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let mut expected = Vec::new();
    for i in 0..15u64 {
        let chunk = deterministic_bytes(i, 100);
        let offset = expected.len() as u64;
        pool.write(ino, offset, &chunk).unwrap();
        expected.extend_from_slice(&chunk);
    }
    assert!(expected.len() as u32 > small_params().inline_threshold);

    // Truncate mid-session.
    pool.set_size(ino, 500).unwrap();
    expected.truncate(500);
    let read_back = pool.read(ino, 0, 500).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());

    // A fresh sequential append after the truncate should work correctly,
    // not resume the discarded session.
    let tail = deterministic_bytes(7, 200);
    let offset = expected.len() as u64;
    pool.write(ino, offset, &tail).unwrap();
    expected.extend_from_slice(&tail);

    let read_back2 = pool.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back2.as_ref(), expected.as_slice());

    pool.checkpoint().unwrap();
    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let final_read = pool2.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(final_read.as_ref(), expected.as_slice());
}

#[test]
fn concurrent_sequential_appenders_to_different_files_all_correct() {
    let dir = tempfile::tempdir().unwrap();
    let pool = std::sync::Arc::new(Pool::create(dir.path(), small_params()).unwrap());

    let mut inos = Vec::new();
    for i in 0..8u64 {
        inos.push(pool.create_file(1, &format!("f{i}"), 0o644).unwrap());
    }

    let handles: Vec<_> = inos
        .iter()
        .enumerate()
        .map(|(idx, &ino)| {
            let pool = std::sync::Arc::clone(&pool);
            std::thread::spawn(move || {
                let mut expected = Vec::new();
                for i in 0..50u64 {
                    let chunk = deterministic_bytes(idx as u64 * 1000 + i, 150);
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
