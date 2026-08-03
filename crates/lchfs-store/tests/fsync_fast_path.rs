//! Targeted tests for the E.7 per-shard fsync fast path
//! (ARCHITECTURE.md §3's "Subtree durability via per-shard delta logs").
//!
//! E.7 only builds the *write* side (committing to the shard's own delta
//! log instead of running a full checkpoint) -- the *read* side (crash
//! recovery replaying that delta log at mount, so the durability survives
//! a drop+reopen without an intervening `checkpoint()`) is E.9's job.
//! Tests here cover what's true after E.7 alone: `fsync(ino)` doesn't
//! error, doesn't touch other inodes, and its content stays correctly
//! readable for the remainder of the *same* Pool session. The crash-
//! survival property (`fsync`, never `checkpoint`, drop, reopen, assert
//! full recovery) belongs in `tests/concurrency.rs` once E.9 lands --
//! attempting it now would just fail on E.9's still-missing replay, not
//! reveal anything wrong with E.7 itself.

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
        logical_shard_count: 8,
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
fn fsync_makes_content_readable_without_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let data = deterministic_bytes(1, 5000);
    pool.write(ino, 0, &data).unwrap();
    pool.fsync(ino).unwrap();

    let read_back = pool.read(ino, 0, data.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), data.as_slice());
}

#[test]
fn multiple_fsyncs_on_same_inode_stay_correct_within_session() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let mut expected = Vec::new();
    for i in 0..5u64 {
        let chunk = deterministic_bytes(i, 2000);
        let offset = expected.len() as u64;
        pool.write(ino, offset, &chunk).unwrap();
        expected.extend_from_slice(&chunk);
        pool.fsync(ino).unwrap();

        let read_back = pool.read(ino, 0, expected.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), expected.as_slice());
    }
}

#[test]
fn fsync_on_one_inode_does_not_disturb_others_in_the_same_session() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let mut inos = Vec::new();
    for i in 0..8u64 {
        inos.push(pool.create_file(1, &format!("f{i}"), 0o644).unwrap());
    }

    let data_a = deterministic_bytes(10, 3000);
    pool.write(inos[0], 0, &data_a).unwrap();
    pool.fsync(inos[0]).unwrap();

    let data_b = deterministic_bytes(20, 3000);
    pool.write(inos[1], 0, &data_b).unwrap(); // never fsynced

    // Both remain correctly readable within the session regardless.
    assert_eq!(
        pool.read(inos[0], 0, data_a.len() as u32).unwrap().as_ref(),
        data_a.as_slice()
    );
    assert_eq!(
        pool.read(inos[1], 0, data_b.len() as u32).unwrap().as_ref(),
        data_b.as_slice()
    );
}

#[test]
fn fsync_followed_by_checkpoint_and_reopen_recovers_correctly() {
    // Doesn't depend on E.9 -- checkpoint() is the already-working global
    // path, this just confirms fsync() beforehand doesn't leave anything
    // in a state that trips up the subsequent checkpoint or recovery.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let data = deterministic_bytes(3, 6000);
    pool.write(ino, 0, &data).unwrap();
    pool.fsync(ino).unwrap();
    pool.checkpoint().unwrap();

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_back = pool2.read(ino, 0, data.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), data.as_slice());
}

#[test]
fn fsync_on_directory_falls_back_to_checkpoint_without_error() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let dir_ino = pool.mkdir(1, "d", 0o755).unwrap();
    pool.fsync(dir_ino).unwrap();

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    assert!(pool2.lookup(1, "d").unwrap().is_some());
}
