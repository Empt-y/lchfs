//! Standalone tests for `ShardDeltaLog` (E.4) — drop+reopen recovery, torn
//! trailing-record tolerance, and basic replay-since-watermark behavior.
//! No `Pool` involvement.

use lchfs_format::{ExtentKind, Hash32, RecordCrypto};
use lchfs_store::delta_log::{ShardCommitRecord, ShardDeltaLog};

/// A device is where its ring is: a writer refuses to create a segment
/// on a root without one, so a bare directory is given a ring first.
fn device() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    lchfs_store::backend::FileBackend::open(dir.path()).unwrap();
    dir
}


fn inode_record(tag: &str) -> ShardCommitRecord {
    let bytes = format!("inode-object-bytes-{tag}").into_bytes();
    let hash = Hash32::of(&bytes);
    ShardCommitRecord {
        kind: ExtentKind::InodeObject,
        content_hash: hash,
        encoded: bytes,
    }
}

#[test]
fn commit_then_replay_from_zero_returns_all_entries_in_order() {
    let dir = device();
    let mut log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 0).unwrap();

    for i in 1..=5u64 {
        log.commit(i, Hash32::of(format!("hash-{i}").as_bytes()), &[inode_record(&i.to_string())], &RecordCrypto::plaintext())
            .unwrap();
    }

    let replay = log.replay_since(0, &RecordCrypto::plaintext()).unwrap();
    assert_eq!(replay.entries.len(), 5);
    let epochs: Vec<u64> = replay.entries.iter().map(|e| e.epoch).collect();
    assert_eq!(epochs, vec![1, 2, 3, 4, 5]);
    let inos: Vec<u64> = replay.entries.iter().map(|e| e.ino).collect();
    assert_eq!(inos, vec![1, 2, 3, 4, 5]);
    // 5 InodeObject records were also written alongside the 5 entries.
    assert_eq!(replay.locations.len(), 5);
}

#[test]
fn replay_since_watermark_only_returns_newer_entries() {
    let dir = device();
    let mut log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 0).unwrap();
    for i in 1..=5u64 {
        log.commit(i, Hash32::of(format!("hash-{i}").as_bytes()), &[], &RecordCrypto::plaintext())
            .unwrap();
    }

    let replay = log.replay_since(3, &RecordCrypto::plaintext()).unwrap();
    let epochs: Vec<u64> = replay.entries.iter().map(|e| e.epoch).collect();
    assert_eq!(epochs, vec![4, 5]);
}

#[test]
fn state_survives_drop_and_reopen() {
    let dir = device();
    {
        let mut log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 2).unwrap();
        log.commit(10, Hash32::of(b"a"), &[], &RecordCrypto::plaintext()).unwrap();
        log.commit(11, Hash32::of(b"b"), &[], &RecordCrypto::plaintext()).unwrap();
    }

    // Reopen: local_epoch must have survived via the shard superblock, and
    // a fresh commit's epoch must continue from where it left off.
    let mut log2 = ShardDeltaLog::open(&[dir.path().to_path_buf()], 2).unwrap();
    let slot = log2.read_shard_superblock().unwrap();
    assert_eq!(slot.local_epoch, 2);
    assert_eq!(slot.shard_id, 2);

    log2.commit(12, Hash32::of(b"c"), &[], &RecordCrypto::plaintext()).unwrap();
    let replay = log2.replay_since(0, &RecordCrypto::plaintext()).unwrap();
    let epochs: Vec<u64> = replay.entries.iter().map(|e| e.epoch).collect();
    assert_eq!(epochs, vec![1, 2, 3]);
}

#[test]
fn torn_trailing_record_is_tolerated_not_fatal() {
    let dir = device();
    {
        let mut log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 5).unwrap();
        log.commit(1, Hash32::of(b"first"), &[], &RecordCrypto::plaintext()).unwrap();
        log.commit(2, Hash32::of(b"second"), &[], &RecordCrypto::plaintext()).unwrap();
    }

    // Find the shard's single delta segment file (segment_id 0, since
    // ShardDeltaLog::open always starts fresh at 0 for a never-before-used
    // shard) and truncate it mid-way through, simulating a crash during
    // the third append (which never actually happened here, but the byte
    // pattern is the same: a torn trailing record).
    use lchfs_store::testing::{SegmentKind, segment_exists, segment_len, truncate_segment};
    let delta = SegmentKind::Delta { shard: 5 };
    assert!(segment_exists(dir.path(), delta, 0));
    let len = segment_len(dir.path(), delta, 0);
    // Truncate a few bytes off the end, into the middle of the last
    // record's header/payload rather than exactly on a boundary.
    truncate_segment(dir.path(), delta, 0, len - 3);

    let log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 5).unwrap();
    let replay = log.replay_since(0, &RecordCrypto::plaintext()).unwrap();
    // The first, intact record must still be recovered; the torn one is
    // silently dropped, not a hard error.
    assert_eq!(replay.entries.len(), 1);
    assert_eq!(replay.entries[0].ino, 1);
}

#[test]
fn missing_shard_superblock_degrades_to_fresh_state() {
    let dir = device();
    // Never committed anything for this shard — open() must not error.
    let log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 99).unwrap();
    let slot = log.read_shard_superblock().unwrap();
    assert_eq!(slot.local_epoch, 0);
}

#[test]
fn corrupt_shard_superblock_degrades_to_fresh_state_not_a_hard_error() {
    let dir = device();
    {
        let mut log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 1).unwrap();
        log.commit(1, Hash32::of(b"x"), &[], &RecordCrypto::plaintext()).unwrap();
    }
    let mut slot = lchfs_store::testing::read_shard_superblock(dir.path(), 1);
    assert!(slot.iter().any(|&b| b != 0), "the commit wrote shard 1's superblock");
    slot[20..36].fill(0xff);
    lchfs_store::testing::write_shard_superblock(dir.path(), 1, &slot);

    // Must not panic/error — degrades to fresh state (epoch 0), and the
    // delta segments themselves are still fully scannable regardless.
    let log = ShardDeltaLog::open(&[dir.path().to_path_buf()], 1).unwrap();
    let slot = log.read_shard_superblock().unwrap();
    assert_eq!(slot.local_epoch, 0);
    let replay = log.replay_since(0, &RecordCrypto::plaintext()).unwrap();
    assert_eq!(replay.entries.len(), 1);
}
