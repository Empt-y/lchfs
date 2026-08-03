//! Targeted tests for E.9's two-tier crash recovery (ARCHITECTURE.md §7):
//! global superblock/InoMap base state, plus per-shard delta-log replay on
//! top of it. This is where the "fsync survives a crash without an
//! intervening checkpoint" property -- deferred from E.7's own test file
//! since it needed this replay logic -- finally holds.

use lchfs_format::PoolParams;
use lchfs_store::ingress::shard_for_inode;
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
fn fsync_fast_path_survives_crash_without_global_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let data = deterministic_bytes(2, 8000);
    pool.write(ino, 0, &data).unwrap();
    pool.fsync(ino).unwrap();

    // Never call checkpoint() -- recovery must come purely from delta-log
    // replay.
    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_back = pool2.read(ino, 0, data.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), data.as_slice());
}

#[test]
fn fsync_independence_across_shards_survives_crash() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let mut inos = Vec::new();
    for i in 0..8u64 {
        inos.push(pool.create_file(1, &format!("f{i}"), 0o644).unwrap());
    }
    pool.checkpoint().unwrap(); // durable baseline: all 8 files exist, empty

    let data_a = deterministic_bytes(10, 3000);
    let ino_a = inos[0];
    pool.write(ino_a, 0, &data_a).unwrap();
    pool.fsync(ino_a).unwrap();

    let data_b = deterministic_bytes(20, 3000);
    let ino_b = inos[1];
    pool.write(ino_b, 0, &data_b).unwrap(); // never fsynced or checkpointed

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();

    let read_a = pool2.read(ino_a, 0, data_a.len() as u32).unwrap();
    assert_eq!(read_a.as_ref(), data_a.as_slice(), "fsynced file must fully recover");

    // B's write was never durable via any path -- must come back as the
    // last durable state (empty from the checkpoint baseline), not
    // corrupted or partially applied.
    let read_b = pool2.read(ino_b, 0, data_b.len() as u32).unwrap();
    assert_ne!(read_b.as_ref(), data_b.as_slice());
    assert_eq!(read_b.len(), 0);
}

#[test]
fn multiple_fsyncs_on_same_inode_survive_crash_in_order() {
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
    }

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_back = pool2.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());
}

#[test]
fn fsyncs_on_many_files_across_shards_all_survive_crash() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let mut results = Vec::new();
    for i in 0..20u64 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        let data = deterministic_bytes(i * 7 + 1, 500 + (i as usize * 37));
        pool.write(ino, 0, &data).unwrap();
        pool.fsync(ino).unwrap();
        results.push((ino, data));
    }

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    for (ino, data) in &results {
        let read_back = pool2.read(*ino, 0, data.len() as u32).unwrap();
        assert_eq!(read_back.as_ref(), data.as_slice(), "mismatch for ino {ino}");
    }
}

#[test]
fn checkpoint_after_fsync_then_more_fsyncs_survive_second_crash() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let first = deterministic_bytes(1, 3000);
    pool.write(ino, 0, &first).unwrap();
    pool.fsync(ino).unwrap();
    pool.checkpoint().unwrap();

    // More content fsynced *after* the checkpoint -- watermark for this
    // shard should reflect the checkpoint's epoch, and this new content
    // must still replay correctly on top of it.
    let second = deterministic_bytes(2, 3000);
    let offset = first.len() as u64;
    pool.write(ino, offset, &second).unwrap();
    pool.fsync(ino).unwrap();

    let mut expected = first.clone();
    expected.extend_from_slice(&second);

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_back = pool2.read(ino, 0, expected.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), expected.as_slice());
}

#[test]
fn reopening_a_cleanly_checkpointed_pool_needs_no_replay_work() {
    // Not a hard behavioral assertion (replay is idempotent either way,
    // per ARCHITECTURE.md §7) -- but confirms watermarks correctly track
    // a shard that had activity fully folded into a checkpoint: reopening
    // must still produce fully correct content, exercising the case where
    // replay_since(watermark) legitimately returns zero entries.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let data = deterministic_bytes(5, 4000);
    pool.write(ino, 0, &data).unwrap();
    pool.fsync(ino).unwrap();
    pool.checkpoint().unwrap();

    drop(pool);
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_back = pool2.read(ino, 0, data.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), data.as_slice());

    // Reopen again -- second consecutive clean mount, still correct.
    drop(pool2);
    let pool3 = Pool::open(dir.path()).unwrap();
    let read_back3 = pool3.read(ino, 0, data.len() as u32).unwrap();
    assert_eq!(read_back3.as_ref(), data.as_slice());
}

#[test]
fn torn_delta_record_from_simulated_mid_fsync_crash_recovers_to_prior_state() {
    let params = small_params();
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), params.clone()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let shard_id = shard_for_inode(ino, params.logical_shard_count);

    let first = deterministic_bytes(1, 2000);
    pool.write(ino, 0, &first).unwrap();
    pool.fsync(ino).unwrap();

    let second = deterministic_bytes(2, 2000);
    pool.write(ino, first.len() as u64, &second).unwrap();
    pool.fsync(ino).unwrap();

    drop(pool);

    // Both fsyncs landed in the same shard's single delta segment (one
    // continuous session, never reopened) -- truncate the file to
    // simulate a crash partway through appending the *second* fsync's
    // trailing record.
    let seg_path = dir
        .path()
        .join(format!("segments/delta/{shard_id:05}/0.dseg"));
    assert!(seg_path.is_file());
    let len = std::fs::metadata(&seg_path).unwrap().len();
    let file = std::fs::OpenOptions::new().write(true).open(&seg_path).unwrap();
    file.set_len(len - 5).unwrap();
    drop(file);

    // Must recover cleanly (no panic/hard error) to at least the first
    // fsync's fully-intact state -- never a hard error, never garbage.
    let pool2 = Pool::open(dir.path()).unwrap();
    let read_back = pool2.read(ino, 0, first.len() as u32).unwrap();
    assert_eq!(&read_back.as_ref()[..first.len()], first.as_slice());
}
