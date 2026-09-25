//! Read failover and heal (ARCHITECTURE.md §15.2, §15.4).
//!
//! The primary vdev's copy is read first. When it fails -- an I/O error, a
//! missing segment, or bytes that no longer hash to what the header claims
//! -- the read is served from another replica and the bad one is healed
//! from those bytes. Resilver is the same heal applied to every record a
//! vdev is missing; scrub is it applied to every record a vdev holds but
//! can no longer read back.
//!
//! Every test damages a real on-disk tree and then asserts on what a read
//! returns *and* on what ended up on disk, because the two can disagree:
//! the whole failure mode being guarded against is a read that succeeds
//! while the pool is quietly one device away from losing the data.

use lchfs_format::{PoolParams, StreamKind};
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
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
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
    // A plaintext pool surfaces this as a content-hash mismatch or a
    // corrupted-record decode failure; an encrypted one catches the same
    // flipped byte earlier, as an AEAD authentication failure on the
    // sealed record -- an equally valid "verification failed" outcome.
    assert!(
        msg.contains("content hash mismatch") || msg.contains("corrupted record") || msg.contains("failed authentication"),
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
        let mut index = RedbIndex::open(a.path()).unwrap();
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
    assert_eq!(report.healed, expected_missing, "{report:?}");
    assert!(report.unrecoverable.is_empty(), "{report:?}");
    assert!(!segment_files(b.path(), "data").is_empty());
    assert!(!segment_files(b.path(), "meta").is_empty(), "meta objects must be resilvered too");

    // A second pass has nothing left to do.
    let again = pool.resilver(1).unwrap();
    assert_eq!((again.missing, again.healed), (0, 0), "{again:?}");

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

/// Resilver is the cheap catch-up and deliberately trusts what the index
/// says a device has; rot in records it already holds is scrub's job.
#[test]
fn resilver_does_not_look_for_corruption() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    write_and_checkpoint(a.path(), b.path());
    corrupt_data_segments(b.path());
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let report = pool.resilver(1).unwrap();
    assert_eq!((report.missing, report.healed), (0, 0), "{report:?}");
}

#[test]
fn scrub_repairs_replicas_that_went_bad_in_place() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());

    corrupt_data_segments(b.path());

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let reports = pool.scrub().unwrap();
    assert_eq!(reports.len(), 2);
    let [ra, rb] = [&reports[0], &reports[1]];
    assert_eq!((ra.vdev_id, rb.vdev_id), (0, 1));
    assert_eq!(ra.corrupt, 0, "vdev a was not touched: {ra:?}");
    assert!(ra.verified > 0, "{ra:?}");
    assert!(rb.corrupt >= 1, "{rb:?}");
    assert_eq!(rb.healed, rb.corrupt, "{rb:?}");
    assert!(rb.unrecoverable.is_empty(), "{rb:?}");

    let again = pool.scrub().unwrap();
    assert!(again.iter().all(|r| r.corrupt == 0 && r.healed == 0), "{again:?}");

    drop(pool);
    for f in segment_files(a.path(), "data") {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_all(&pool, ino), payload());
    assert!(pool.repair_stats().failovers >= 1);
}

#[test]
fn scrub_reports_what_no_replica_can_supply() {
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
    let reports = pool.scrub().unwrap();
    for r in &reports {
        assert!(!r.unrecoverable.is_empty(), "{r:?}");
        assert_eq!(r.healed, 0, "{r:?}");
    }
    assert_eq!(pool.repair_stats().heals, 0);
}

/// A single-vdev pool has nowhere to heal from, but scrub still says what
/// it found -- silent rot on the only copy is worth knowing about early.
#[test]
fn scrub_on_a_single_vdev_reports_without_healing() {
    let a = tempfile::tempdir().unwrap();
    {
        let pool = Pool::create(a.path(), small_params()).unwrap();
        let ino = pool.create_file(1, "big", 0o644).unwrap();
        pool.write(ino, 0, &payload()).unwrap();
        pool.checkpoint().unwrap();
    }
    corrupt_data_segments(a.path());
    let pool = Pool::open(a.path()).unwrap();
    let reports = pool.scrub().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].corrupt >= 1, "{reports:?}");
    assert_eq!(reports[0].healed, 0);
    assert_eq!(reports[0].unrecoverable.len() as u64, reports[0].corrupt);
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
        let reports = pool.scrub().unwrap();
        assert!(reports[1].healed >= 1, "{reports:?}");
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

/// Mounting reads the root, the InoMap, every InodeObject and directory
/// from the primary. None of that used to fail over, so a mirror with one
/// rotten meta segment on vdev 0 was unmountable while a perfect copy sat
/// on vdev 1. Every meta segment on vdev 0 is destroyed here, not just
/// corrupted, so nothing on the primary can be serving these reads.
#[test]
fn a_mirror_still_mounts_when_the_primary_has_lost_its_metadata() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());
    {
        // Some directory structure, so the walk touches DirectoryObjects.
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        let d = pool.mkdir(1, "dir", 0o755).unwrap();
        let f = pool.create_file(d, "inner", 0o644).unwrap();
        pool.write(f, 0, b"inner content").unwrap();
        pool.checkpoint().unwrap();
    }
    for f in segment_files(a.path(), "meta") {
        std::fs::remove_file(f).unwrap();
    }

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    // The mount had to fail over to get here, and the pool says so the
    // same way a read after mount would: the counter moved, and every
    // record served from b is a corruption event against a, unhealed
    // (reads after this heal what they touch; the mount does not).
    let stats = pool.repair_stats();
    assert!(stats.failovers > 0, "mount failovers are not counted: {stats:?}");
    let events = pool.corruption_events();
    assert!(!events.is_empty(), "mount failovers are not recorded");
    assert!(
        events.iter().all(|e| e.vdev_id == 0 && e.stream == StreamKind::Meta && !e.healed),
        "{events:?}"
    );
    assert_eq!(events.len() as u64, stats.failovers);

    assert_eq!(read_all(&pool, ino), payload());
    let d = pool.lookup(1, "dir").unwrap().expect("dir survives");
    let f = pool.lookup(d, "inner").unwrap().expect("inner survives");
    assert_eq!(pool.read(f, 0, 13).unwrap().as_ref(), b"inner content");

    // And scrub puts the primary right again.
    let reports = pool.scrub().unwrap();
    assert!(reports[0].healed > 0, "{reports:?}");
    assert!(reports[0].unrecoverable.is_empty(), "{reports:?}");
}

/// The same for content that only exists in a shard's delta log at mount
/// time -- fsync'd but not yet checkpointed -- which replay reads from the
/// delta stream rather than the index.
#[test]
fn delta_replay_at_mount_fails_over_too() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let data = payload();
    let ino = {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        pool.checkpoint().unwrap();
        let ino = pool.create_file(1, "fsynced", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.fsync(ino).unwrap();
        // No checkpoint: the file lives in the delta log only. Dropping
        // the pool without one is the crash this replay path exists for
        // (Drop stops the timers; it does not checkpoint).
        drop(pool);
        ino
    };
    let delta_dir = a.path().join("segments/delta");
    assert!(delta_dir.is_dir(), "test setup: expected a delta log on vdev a");
    std::fs::remove_dir_all(&delta_dir).unwrap();

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    // Replay's failovers are accounted like the rest of the mount's.
    assert!(pool.repair_stats().failovers > 0);
    let events = pool.corruption_events();
    assert!(
        !events.is_empty() && events.iter().all(|e| e.vdev_id == 0 && e.stream == StreamKind::Delta && !e.healed),
        "{events:?}"
    );
    assert_eq!(pool.read(ino, 0, data.len() as u32).unwrap(), data);
}

// ---- Corruption is data ----------------------------------------------

/// §8 asked for a structured corruption log: which device, which record,
/// what was seen, which inode was being read, whether it was put right.
/// A read that fails over records all of that; the happy path records
/// nothing.
#[test]
fn corruption_found_by_a_read_is_recorded_with_its_inode_and_outcome() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ino = write_and_checkpoint(a.path(), b.path());
    corrupt_data_segments(a.path());

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert!(pool.corruption_events().is_empty(), "nothing has been read yet");
    assert_eq!(read_all(&pool, ino), payload());

    let events = pool.corruption_events();
    assert!(!events.is_empty());
    for e in &events {
        assert_eq!(e.vdev_id, 0, "{e:?}");
        assert_eq!(e.ino, Some(ino), "{e:?}");
        assert!(e.healed, "{e:?}");
        assert!(e.location.is_some(), "{e:?}");
        assert!(!e.detail.is_empty());
    }
    assert_eq!(events.len() as u64, pool.repair_stats().heals);

    // A clean second read adds nothing.
    assert_eq!(read_all(&pool, ino), payload());
    assert_eq!(pool.corruption_events().len(), events.len());
    pool.clear_corruption_events();
    assert!(pool.corruption_events().is_empty());
}

/// Scrub findings are recorded too, without an inode, and say whether
/// the record could be healed.
#[test]
fn corruption_found_by_scrub_is_recorded() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    write_and_checkpoint(a.path(), b.path());
    corrupt_data_segments(b.path());
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let reports = pool.scrub().unwrap();
    let events = pool.corruption_events();
    assert_eq!(events.len() as u64, reports[1].corrupt, "{events:?}");
    assert!(events.iter().all(|e| e.vdev_id == 1 && e.ino.is_none() && e.healed), "{events:?}");
}

/// On a single device nothing can be healed, and the event says so.
#[test]
fn unhealable_corruption_is_recorded_as_such() {
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
    assert!(pool.read(ino, 0, payload().len() as u32).is_err());
    let events = pool.corruption_events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(!events[0].healed);
    assert_eq!(events[0].ino, Some(ino));
}

// ---- Index batching (Phase 5 M1) ----------------------------------------

/// A record's persisted index entries live in its shard's batch until a
/// flush. Anything that reads the persisted index and expects it complete
/// -- a resilver, a scrub, a failover read -- drains the batches first, so
/// a record written a moment ago, with no checkpoint or fsync since, is
/// already accounted for on every device it reached.
#[test]
fn passes_that_read_the_index_see_records_still_in_the_batch() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    pool.checkpoint().unwrap();
    let ino = pool.create_file(1, "fresh", 0o644).unwrap();
    pool.write(ino, 0, &payload()).unwrap();
    // No checkpoint, no fsync: every entry for "fresh" is in a batch.
    let report = pool.resilver(1).unwrap();
    assert!(report.examined > 0);
    assert_eq!(report.missing, 0, "b took every record, and the index must say so: {report:?}");
    let reports = pool.scrub().unwrap();
    assert!(reports.iter().all(|r| r.corrupt == 0 && r.verified > 0), "{reports:?}");
}

/// Records written after the last checkpoint and never fsync'd are not in
/// the persisted index at a crash -- batched or not -- and are recovered
/// by the delta replay and owner-shard rescan exactly as before.
#[test]
fn a_crash_with_records_still_in_the_index_batch_recovers_through_fsync() {
    let a = tempfile::tempdir().unwrap();
    let pool = Pool::create(a.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload()).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);
    let pool = Pool::open(a.path()).unwrap();
    assert_eq!(pool.read(ino, 0, payload().len() as u32).unwrap(), payload());
    // And the next checkpoint leaves an index fsck agrees with.
    pool.checkpoint().unwrap();
    drop(pool);
    let roots = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::verify_index(a.path(), &roots);
    assert!(report.is_clean(), "{:?}", report.errors);
}
