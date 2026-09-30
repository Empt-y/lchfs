//! A device failing under a mounted pool (Phase 4, M1).
//!
//! Phase 3 handled devices that were absent when the pool was mounted.
//! This is the other case, and the one replication is for: a device that
//! dies while writes are landing on it. The pool drops it, keeps writing
//! to the rest, records in the index exactly which devices took each
//! record, and reports the slot as faulted.
//!
//! Two ways to kill a device: `fault_injection::kill`, which makes every
//! replica operation under a root fail (a disk dying under open
//! descriptors), and moving the root's `segments` tree aside, which lets
//! open descriptors keep working and fails the next rollover (a device
//! that vanished from the filesystem).

use lchfs_format::PoolParams;
use lchfs_store::segment::fault_injection;
use lchfs_store::{Pool, VdevHealth};
use std::path::Path;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 16 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

fn payload(seed: u32) -> Vec<u8> {
    (0..30_000u32)
        .map(|i| ((i ^ seed).wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn data_segments(root: &Path) -> Vec<u64> {
    lchfs_store::testing::segment_ids(root, lchfs_store::testing::SegmentKind::Data)
}

fn read_file(pool: &Pool, name: &str, len: usize) -> Vec<u8> {
    let ino = pool.lookup(1, name).unwrap().expect(name);
    pool.read(ino, 0, len as u32).unwrap().to_vec()
}

/// The device is going away: nothing new can be created on it, while
/// what is already open keeps working.
fn vanish(root: &Path) {
    lchfs_store::testing::vanish(root);
}

fn health(pool: &Pool, id: u16) -> VdevHealth {
    pool.vdev_status().into_iter().find(|s| s.id == id).unwrap().health
}

#[test]
fn a_replica_that_dies_mid_write_is_dropped_and_writes_continue() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let before = payload(1);
    let after = payload(2);

    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "before", 0o644).unwrap();
    pool.write(ino, 0, &before).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Online);

    fault_injection::kill(b.path());
    let ino2 = pool.create_file(1, "after", 0o644).unwrap();
    pool.write(ino2, 0, &after).unwrap();
    pool.checkpoint().unwrap();

    assert_eq!(health(&pool, 1), VdevHealth::Faulted);
    assert_eq!(pool.faulted_vdevs(), vec![1]);
    assert_eq!(pool.missing_vdevs(), vec![1]);
    assert!(pool.is_degraded());
    assert_eq!(read_file(&pool, "before", before.len()), before);
    assert_eq!(read_file(&pool, "after", after.len()), after);
    let stats = pool.repair_stats();
    assert_eq!(stats.failovers, 0, "nothing should have needed the dead device: {stats:?}");
    drop(pool);
    fault_injection::revive(b.path());

    // The index told the truth about where each record went: fsck finds
    // the post-fault records missing from b and nothing else wrong with
    // it beyond having fallen behind.
    let report = lchfs_fsck::check_replicas(&[a.path(), b.path()]);
    let missing_on_b = report
        .errors
        .iter()
        .filter(|e| matches!(e, lchfs_fsck::FsckError::ReplicaMissing { vdev_id: 1, .. }))
        .count();
    assert!(missing_on_b > 0, "{:?}", report.errors);
    assert!(
        report.errors.iter().any(|e| matches!(e, lchfs_fsck::FsckError::VdevBehind { vdev_id: 1, .. })),
        "{:?}",
        report.errors
    );
    assert!(
        !report.errors.iter().any(|e| matches!(
            e,
            lchfs_fsck::FsckError::ReplicaMissing { vdev_id: 0, .. } | lchfs_fsck::FsckError::ReplicaCorrupt { .. }
        )),
        "{:?}",
        report.errors
    );

    // And the pool remounts with b behind, resilvering exactly the delta.
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let [(1, r)] = pool.mount_resilver() else { panic!("{:?}", pool.mount_resilver()) };
    assert_eq!(r.healed as usize, missing_on_b, "{r:?}");
    assert_eq!(read_file(&pool, "after", after.len()), after);
}

#[test]
fn a_fault_during_fsync_is_survived() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(3)).unwrap();
    fault_injection::kill(b.path());
    pool.fsync(ino).unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);
    // Another fsync'd write lands fine on the survivor.
    let ino2 = pool.create_file(1, "g", 0o644).unwrap();
    pool.write(ino2, 0, &payload(4)).unwrap();
    pool.fsync(ino2).unwrap();
    drop(pool);
    fault_injection::revive(b.path());
    // Crash-style reopen: the delta log on a carries both.
    // Crash-style reopen: the delta log on a carries both. By ino, as the
    // crash-recovery tests do -- fsync makes the file durable, not its
    // directory entry, which only a checkpoint writes.
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(pool.read(ino, 0, 30_000).unwrap(), payload(3));
    assert_eq!(pool.read(ino2, 0, 30_000).unwrap(), payload(4));
}

#[test]
fn when_every_replica_is_dead_the_write_fails() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    fault_injection::kill(a.path());
    fault_injection::kill(b.path());
    assert!(pool.write(ino, 0, &payload(5)).is_err());
    fault_injection::revive(a.path());
    fault_injection::revive(b.path());
}

/// A device that vanishes from the filesystem: open descriptors keep
/// working, so nothing fails until a writer opens a new segment there.
#[test]
fn a_device_that_vanishes_is_faulted_at_its_next_rollover() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(6)).unwrap();

    vanish(b.path());
    // Enough data to cross the 16 KiB data segment cap several times.
    for i in 0..4u32 {
        let ino = pool.create_file(1, &format!("more{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(10 + i)).unwrap();
    }
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);
    assert_eq!(read_file(&pool, "more3", 30_000), payload(13));
    pool.checkpoint().unwrap();
}

/// The primary's *segments* can fault like anyone's: reads fail over and
/// writes go to the survivor. What cannot survive is losing its index --
/// that is a remount with another primary, and the status says which slot
/// is the primary so a caller can tell the two apart.
#[test]
fn a_primary_whose_segments_vanish_still_serves_through_the_mirror() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(7)).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(pool.primary_vdev(), 0);

    vanish(a.path());
    for i in 0..4u32 {
        let ino = pool.create_file(1, &format!("more{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(20 + i)).unwrap();
    }
    assert_eq!(health(&pool, 0), VdevHealth::Faulted);
    assert_eq!(pool.faulted_vdevs(), vec![pool.primary_vdev()]);
    // New records went to b only. Reading them back works -- from the
    // working state while the file is fresh, and after a checkpoint and
    // remount from b's copy, since the primary never got one.
    assert_eq!(read_file(&pool, "more3", 30_000), payload(23));
    pool.checkpoint().unwrap();
    // The device comes back (unmounting closed it, which ends the
    // simulation: it reopens whole).
    drop(pool);
    // While it was faulted its superblock was not advanced, so it comes
    // back behind b and is resilvered before the pool serves: the same
    // path a device absent at mount takes.
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let [(0, report)] = pool.mount_resilver() else { panic!("{:?}", pool.mount_resilver()) };
    assert!(report.healed > 0 && report.unrecoverable.is_empty(), "{report:?}");
    assert_eq!(read_file(&pool, "more3", 30_000), payload(23));
    assert_eq!(read_file(&pool, "f", 30_000), payload(7));
    assert!(!data_segments(a.path()).is_empty());
}

/// A segment writer whose last replica failed used to report every later
/// append as a success -- with no device to write to, its loop over the
/// replicas ran zero times -- so a write after losing every device was
/// acknowledged and stored nowhere. (Seen as a committer panic indexing an
/// empty device list when a test machine's disk filled up.)
#[test]
fn a_writer_with_no_replica_left_refuses_every_append() {
    use lchfs_format::{CodecId, ExtentKind, Hash32, StreamKind};
    use lchfs_store::segment::SegmentWriter;
    let dir = tempfile::tempdir().unwrap();
    // A real device: a superblock at its root.
    drop(Pool::create(dir.path(), small_params()).unwrap());
    let mut writer = SegmentWriter::create(&[dir.path()], 999, StreamKind::Data, 0).unwrap();
    writer.append(ExtentKind::RawChunk, Hash32([1; 32]), CodecId::None, 4, b"abcd", Vec::new()).unwrap();
    fault_injection::kill(dir.path());
    assert!(writer.append(ExtentKind::RawChunk, Hash32([2; 32]), CodecId::None, 4, b"efgh", Vec::new()).is_err());
    fault_injection::revive(dir.path());
    let later = writer.append(ExtentKind::RawChunk, Hash32([3; 32]), CodecId::None, 4, b"ijkl", Vec::new());
    assert!(later.is_err(), "an append with no replica left must fail, not report {later:?}");
    assert!(writer.vdev_ids().is_empty());
}
