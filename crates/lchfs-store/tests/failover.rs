//! Read failover and heal (ARCHITECTURE.md §15.2, §15.4).
//!
//! The primary vdev's copy is read first. When it fails -- an I/O error, a
//! missing segment, or bytes that no longer hash to what the header claims
//! -- the read is served from another replica and the bad one is healed
//! from those bytes. Resilver is the same heal applied to every record a
//! vdev is missing or holding corrupt.
//!
//! Every test damages a real on-disk tree and then asserts on what a read
//! returns *and* on what ended up on disk, because the two can disagree:
//! the whole failure mode being guarded against is a read that succeeds
//! while the pool is quietly one device away from losing the data.

use lchfs_format::PoolParams;
use lchfs_index::RedbIndex;
use lchfs_store::Pool;
use std::path::{Path, PathBuf};

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
    }
}

/// Deterministic but not compressible-to-nothing, so chunks carry real
/// payload bytes that corruption can land on.
fn payload() -> Vec<u8> {
    (0..40_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

fn segment_files(root: &Path, stream: &str) -> Vec<PathBuf> {
    let dir = root.join("segments").join(stream);
    let mut out: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// Overwrites a run of bytes in the middle of every data segment on `root`,
/// well past the 4 KiB header page, so at least one record's payload no
/// longer matches its content hash.
fn corrupt_data_segments(root: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let files = segment_files(root, "data");
    assert!(!files.is_empty(), "no data segments to corrupt under {root:?}");
    for path in files {
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len > 8192, "segment {path:?} too small to corrupt safely");
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(len / 2)).unwrap();
        f.write_all(&[0xFFu8; 64]).unwrap();
    }
}

fn write_and_checkpoint(a: &Path, b: &Path) -> u64 {
    let pool = Pool::create_replicated(&[a, b], small_params()).unwrap();
    let ino = pool.create_file(1, "big", 0o644).unwrap();
    pool.write(ino, 0, &payload()).unwrap();
    pool.checkpoint().unwrap();
    ino
}

fn read_all(pool: &Pool, ino: u64) -> Vec<u8> {
    pool.read(ino, 0, payload().len() as u32).unwrap().to_vec()
}

#[test]
fn a_corrupt_primary_record_is_served_from_the_other_vdev_and_healed() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());
    let data_segments_before = segment_files(a.path(), "data").len();

    corrupt_data_segments(a.path());

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_all(&pool, ino), payload(), "read must come back intact from vdev b");

    let stats = pool.repair_stats();
    assert!(stats.failovers >= 1, "expected at least one failover, got {stats:?}");
    assert_eq!(stats.heals, stats.failovers, "every failover should have healed the primary");
    assert_eq!(stats.heal_failures, 0, "{stats:?}");
    assert!(
        segment_files(a.path(), "data").len() > data_segments_before,
        "a heal segment should have appeared on vdev a"
    );

    // The healed copy is now the primary's copy: a second read must not
    // fail over again.
    assert_eq!(read_all(&pool, ino), payload());
    assert_eq!(pool.repair_stats().failovers, stats.failovers, "second read failed over again");
    pool.checkpoint().unwrap();
    drop(pool);

    // And it survives a remount: the index points the primary at the
    // healed location, so vdev b is not consulted at all.
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_all(&pool, ino), payload());
    assert_eq!(pool.repair_stats().failovers, 0, "remounted pool still failing over");
}

#[test]
fn a_missing_primary_segment_fails_over_and_the_heal_is_then_the_only_copy_needed() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());

    for f in segment_files(a.path(), "data") {
        std::fs::remove_file(f).unwrap();
    }

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_all(&pool, ino), payload());
    assert!(pool.repair_stats().failovers >= 1);
    assert!(!segment_files(a.path(), "data").is_empty(), "no heal segment on vdev a");

    // Now lose vdev b's data. Everything the file needs was healed onto a.
    for f in segment_files(b.path(), "data") {
        std::fs::remove_file(f).unwrap();
    }
    let before = pool.repair_stats();
    assert_eq!(read_all(&pool, ino), payload());
    assert_eq!(pool.repair_stats(), before, "read should not have needed vdev b");
}

#[test]
fn a_single_vdev_pool_still_reports_the_error() {
    let a = tempfile::tempdir().unwrap();
    let ino = {
        let pool = Pool::create(a.path(), small_params()).unwrap();
        let ino = pool.create_file(1, "big", 0o644).unwrap();
        pool.write(ino, 0, &payload()).unwrap();
        pool.checkpoint().unwrap();
        ino
    };
    corrupt_data_segments(a.path());
    let pool = Pool::open(a.path()).unwrap();
    let err = pool.read(ino, 0, payload().len() as u32).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("content hash mismatch") || msg.contains("corrupted record"),
        "expected the verification failure to surface, got: {err}"
    );
    assert_eq!(pool.repair_stats(), Default::default());
}

#[test]
fn resilver_recreates_replicas_a_device_never_received() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());

    // Make vdev b look like it was offline for every write: its segments
    // never arrived, and the index never learned of a replica there.
    std::fs::remove_dir_all(b.path().join("segments")).unwrap();
    let expected_missing = {
        let mut index = RedbIndex::open(&a.path().join("INDEX.redb")).unwrap();
        let all = index.iter_all_chunk_locations().unwrap();
        let mut n = 0;
        for (hash, vdev_id, _) in all {
            if vdev_id == 1 {
                index.delete_chunk_location(hash, 1).unwrap();
                n += 1;
            }
        }
        assert!(n > 0, "test setup: no vdev 1 entries to remove");
        n
    };

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let report = pool.resilver(1).unwrap();
    assert_eq!(report.missing, expected_missing, "{report:?}");
    assert_eq!(report.corrupt, 0, "{report:?}");
    assert_eq!(report.healed, expected_missing, "{report:?}");
    assert!(report.unrecoverable.is_empty(), "{report:?}");
    assert!(!segment_files(b.path(), "data").is_empty());
    assert!(!segment_files(b.path(), "meta").is_empty(), "meta objects must be resilvered too");

    // A second pass has nothing left to do.
    let again = pool.resilver(1).unwrap();
    assert_eq!((again.missing, again.corrupt, again.healed), (0, 0, 0), "{again:?}");

    // Proof the resilvered copies are real: lose vdev a's data and read.
    // Reopened first, because the pool holds its segment files open and an
    // unlinked file keeps serving reads through an existing descriptor --
    // which would make this pass for the wrong reason.
    drop(pool);
    for f in segment_files(a.path(), "data") {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_all(&pool, ino), payload());
    assert!(pool.repair_stats().failovers >= 1);
}

#[test]
fn resilver_repairs_replicas_that_went_bad_in_place() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());

    corrupt_data_segments(b.path());

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let report = pool.resilver(1).unwrap();
    assert!(report.corrupt >= 1, "{report:?}");
    assert_eq!(report.missing, 0, "{report:?}");
    assert_eq!(report.healed, report.corrupt, "{report:?}");
    assert!(report.unrecoverable.is_empty(), "{report:?}");

    let again = pool.resilver(1).unwrap();
    assert_eq!((again.missing, again.corrupt, again.healed), (0, 0, 0), "{again:?}");

    drop(pool);
    for f in segment_files(a.path(), "data") {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_all(&pool, ino), payload());
    assert!(pool.repair_stats().failovers >= 1);
}

#[test]
fn resilver_reports_what_no_replica_can_supply() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let _ino = write_and_checkpoint(a.path(), b.path());

    // Both copies of the data are gone; only metadata survives.
    for root in [a.path(), b.path()] {
        for f in segment_files(root, "data") {
            std::fs::remove_file(f).unwrap();
        }
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let report = pool.resilver(1).unwrap();
    assert!(!report.unrecoverable.is_empty(), "{report:?}");
    assert_eq!(report.healed, 0, "{report:?}");
    assert_eq!(pool.repair_stats().heals, 0);
}

#[test]
fn resilver_refuses_a_vdev_the_pool_does_not_have() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    write_and_checkpoint(a.path(), b.path());
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert!(pool.resilver(7).is_err());
    let single = tempfile::tempdir().unwrap();
    let pool = Pool::create(single.path(), small_params()).unwrap();
    assert!(pool.resilver(0).is_err(), "nothing to resilver from");
}

/// A heal segment can exist on one vdev only, with an id higher than
/// anything the primary has. The id allocator is seeded at mount by
/// scanning segment files -- and if it only looked at the primary, the
/// next fresh writer would be handed that id and `create` it (truncating
/// it) on every vdev. Found by exactly that happening.
#[test]
fn a_heal_segment_that_exists_on_one_vdev_survives_a_remount_and_new_writes() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());
    let data_on_b_before = segment_files(b.path(), "data");

    corrupt_data_segments(b.path());
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        let report = pool.resilver(1).unwrap();
        assert!(report.healed >= 1, "{report:?}");
    }
    // New files on b that hold records. (Mounting also opens a fresh,
    // header-only active data segment on every vdev; that is not a heal.)
    let heal_segments: Vec<PathBuf> = segment_files(b.path(), "data")
        .into_iter()
        .filter(|p| !data_on_b_before.contains(p))
        .filter(|p| std::fs::metadata(p).unwrap().len() > 4096)
        .collect();
    assert!(!heal_segments.is_empty(), "resilver left no heal segment on vdev b");
    let sizes_before: Vec<u64> = heal_segments
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect();

    // Remount, and allocate fresh segments by writing and checkpointing.
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        let other = pool.create_file(1, "other", 0o644).unwrap();
        pool.write(other, 0, &payload()[..10_000]).unwrap();
        pool.checkpoint().unwrap();
        assert_eq!(read_all(&pool, ino), payload());
    }
    let sizes_after: Vec<u64> = heal_segments
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect();
    assert_eq!(sizes_after, sizes_before, "a heal segment on vdev b was clobbered by a new writer");
}
