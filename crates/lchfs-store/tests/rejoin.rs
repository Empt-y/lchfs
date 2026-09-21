//! A device coming back into a mounted pool (Phase 4, M2).
//!
//! Rejoining is the live form of what a mount does for a stale member:
//! the device's old index entries are kept -- they describe records it
//! really holds -- and only what it missed is copied. The proof that
//! nothing is missed afterwards is fsck's replica comparison, which
//! shares no code with any of this.

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

fn read_file(pool: &Pool, name: &str, len: usize) -> Vec<u8> {
    let ino = pool.lookup(1, name).unwrap().expect(name);
    pool.read(ino, 0, len as u32).unwrap().to_vec()
}

fn health(pool: &Pool, id: u16) -> VdevHealth {
    pool.vdev_status().into_iter().find(|s| s.id == id).unwrap().health
}

fn clean_replicas(a: &Path, b: &Path) -> Result<(), String> {
    let report = lchfs_fsck::check_replicas(&[a, b]);
    if report.is_clean() {
        Ok(())
    } else {
        Err(format!("{:?}", report.errors))
    }
}

#[test]
fn a_faulted_device_rejoins_and_receives_exactly_what_it_missed() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "before", 0o644).unwrap();
    pool.write(ino, 0, &payload(1)).unwrap();
    pool.checkpoint().unwrap();

    fault_injection::kill(b.path());
    let mut during = Vec::new();
    for i in 0..3u32 {
        let ino = pool.create_file(1, &format!("during{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(10 + i)).unwrap();
        during.push(ino);
    }
    pool.checkpoint().unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);

    // The disk is back.
    fault_injection::revive(b.path());
    let (id, report) = pool.online_vdev(b.path()).unwrap();
    assert_eq!(id, 1);
    assert_eq!(health(&pool, 1), VdevHealth::Online);
    assert!(!pool.is_degraded());
    assert!(report.missing > 0 && report.healed == report.missing, "{report:?}");
    assert!(report.unrecoverable.is_empty(), "{report:?}");
    // Only the delta was copied: "before" was already there. Each 30 KB
    // file is a handful of chunks plus a few meta objects, so the count
    // for three files is well under what four would be.
    assert!(report.missing < report.examined, "everything was recopied: {report:?}");

    // Writes after the rejoin fan out again.
    let ino = pool.create_file(1, "after", 0o644).unwrap();
    pool.write(ino, 0, &payload(20)).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    clean_replicas(a.path(), b.path()).unwrap();
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert!(pool.mount_resilver().is_empty(), "{:?}", pool.mount_resilver());
    assert_eq!(read_file(&pool, "during2", 30_000), payload(12));
    assert_eq!(read_file(&pool, "after", 30_000), payload(20));
}

/// A device absent at mount, plugged in later: brought online without a
/// remount, filled, and a full member from then on.
#[test]
fn a_device_absent_at_mount_can_be_brought_online_later() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "before", 0o644).unwrap();
        pool.write(ino, 0, &payload(2)).unwrap();
        pool.checkpoint().unwrap();
    }
    let pool = Pool::open_degraded(&[a.path()]).unwrap();
    let ino = pool.create_file(1, "while-away", 0o644).unwrap();
    pool.write(ino, 0, &payload(3)).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Absent);

    let (id, report) = pool.online_vdev(b.path()).unwrap();
    assert_eq!(id, 1);
    assert!(report.healed > 0, "{report:?}");
    assert!(!pool.is_degraded());
    pool.checkpoint().unwrap();
    drop(pool);
    clean_replicas(a.path(), b.path()).unwrap();
}

#[test]
fn online_refuses_what_it_should() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let blank = tempfile::tempdir().unwrap();
    drop(Pool::create(other.path(), small_params()).unwrap());
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();

    let err = pool.online_vdev(b.path()).unwrap_err().to_string();
    assert!(err.contains("already online"), "{err}");
    let err = pool.online_vdev(other.path()).unwrap_err().to_string();
    assert!(err.contains("different pool"), "{err}");
    let err = pool.online_vdev(blank.path()).unwrap_err().to_string();
    assert!(err.contains("no superblock"), "{err}");
    assert_eq!(health(&pool, 1), VdevHealth::Online);
}

/// Fault, rejoin, fault again, rejoin again -- under continuous writes,
/// with fsck as the judge at the end.
#[test]
fn repeated_fault_and_rejoin_under_load_loses_nothing() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let pool = Arc::clone(&pool);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut n = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let ino = pool.create_file(1, &format!("w{n}"), 0o644).unwrap();
                pool.write(ino, 0, &payload(100 + n)).unwrap();
                if n.is_multiple_of(3) {
                    pool.fsync(ino).unwrap();
                }
                n += 1;
            }
            n
        })
    };
    for _round in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(30));
        fault_injection::kill(b.path());
        std::thread::sleep(std::time::Duration::from_millis(30));
        // Make sure at least one write has tripped over the dead device.
        while health(&pool, 1) != VdevHealth::Faulted {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        fault_injection::revive(b.path());
        let (_, report) = pool.online_vdev(b.path()).unwrap();
        assert!(report.unrecoverable.is_empty(), "{report:?}");
    }
    stop.store(true, Ordering::Relaxed);
    assert!(writer.join().unwrap() > 0);
    pool.checkpoint().unwrap();
    drop(pool);
    clean_replicas(a.path(), b.path()).unwrap();
}

/// A device that faulted on its own comes back on its own once it
/// answers again; one an operator took offline does not.
#[test]
fn a_faulted_device_that_answers_again_rejoins_by_itself() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(61)).unwrap();

    fault_injection::kill(b.path());
    pool.write(ino, 0, &payload(62)).unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);
    // Dead devices are not brought back: nothing changes in this window.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);

    fault_injection::revive(b.path());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while health(&pool, 1) != VdevHealth::Online && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(health(&pool, 1), VdevHealth::Online, "the failover task should have brought b back");
    pool.checkpoint().unwrap();
    drop(pool);
    clean_replicas(a.path(), b.path()).unwrap();
}

#[test]
fn a_device_taken_offline_on_purpose_stays_offline() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    pool.offline_vdev(1).unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);
    // Well past a probe interval: the device answers, and is left alone.
    std::thread::sleep(std::time::Duration::from_millis(7500));
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);
    let (id, _) = pool.online_vdev(b.path()).unwrap();
    assert_eq!(id, 1);
    assert_eq!(health(&pool, 1), VdevHealth::Online);
}

/// Found on a live mount (§17.3): the probe opened the device's ring with
/// the creating open, so a pulled device's path grew a directory and a
/// blank superblock while it was away -- and the real device, moved back
/// to that path, landed inside the impostor. Probing must create nothing.
#[test]
fn probing_a_pulled_device_creates_nothing_at_its_path() {
    let a = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let b = parent.path().join("b");
    let pool = Pool::create_replicated(&[a.path(), &b], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(71)).unwrap();
    pool.checkpoint().unwrap();

    // Pull it. An open segment file survives its directory's rename, so
    // the fault comes when the shard needs a new segment: the writer
    // will not create one where no ring is.
    let away = parent.path().join("b.pulled");
    std::fs::rename(&b, &away).unwrap();
    pool.seal_idle_segments(std::time::Duration::ZERO).unwrap();
    pool.write(ino, 0, &payload(72)).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);

    // Several probe intervals later, nothing has appeared at the path.
    std::thread::sleep(std::time::Duration::from_millis(7500));
    assert!(!b.exists(), "the probe recreated the pulled device's path");

    // Put it back where it was: the probe finds it and it rejoins.
    std::fs::rename(&away, &b).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while health(&pool, 1) != VdevHealth::Online && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(health(&pool, 1), VdevHealth::Online);
    assert_eq!(read_file(&pool, "f", 30_000), payload(72));
    pool.checkpoint().unwrap();
    drop(pool);
    clean_replicas(a.path(), &b).unwrap();
}

/// A rejoin that fails part-way must leave the device faulted, not lost.
/// `online_vdev` used to take the device out of the faulted set before it
/// tried to bring it back; a failure after that -- the device answering a
/// probe but a write to it still failing, e.g. mid-flap -- dropped the
/// member on the floor, in neither the online nor the faulted set. The
/// failover task's own error handler then called `fault(id)`, which found
/// nothing to fault, so the slot went Absent and `faulted_unintended`
/// never named it again: the device was stranded until a remount, exactly
/// what was seen on a live mount when a pulled device was slow to settle.
/// Here the device is dead for long enough that the failover task tries
/// and fails at least one rejoin; once revived it must still come back on
/// its own, which it cannot if the failed attempt stranded it.
#[test]
fn a_rejoin_that_fails_leaves_the_device_faulted_not_stranded() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(71)).unwrap();
    pool.checkpoint().unwrap();

    // Kill b and write past it, so it has a delta to catch up on and a
    // rejoin has real work (a resilver write) that will fail while dead.
    fault_injection::kill(b.path());
    pool.write(ino, 0, &payload(72)).unwrap();
    assert_eq!(health(&pool, 1), VdevHealth::Faulted);

    // A direct rejoin attempt while b is still dead must fail and must
    // leave b faulted -- never Absent.
    let attempt = pool.online_vdev(b.path());
    assert!(attempt.is_err(), "a write to a dead device cannot resilver: {attempt:?}");
    assert_ne!(health(&pool, 1), VdevHealth::Absent, "a failed rejoin stranded the device");

    // Let the background failover task have several goes at it too, all
    // failing while b is dead. On the buggy code one of these strands b
    // as Absent, after which nothing ever retries it.
    std::thread::sleep(std::time::Duration::from_millis(3500));
    assert_ne!(health(&pool, 1), VdevHealth::Absent, "the failover task stranded the device");

    // Revive it: it must come back on its own. It cannot if it was
    // stranded out of the faulted set.
    fault_injection::revive(b.path());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    while health(&pool, 1) != VdevHealth::Online && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(health(&pool, 1), VdevHealth::Online, "b was never brought back after revival");

    pool.checkpoint().unwrap();
    drop(pool);
    clean_replicas(a.path(), b.path()).unwrap();
}
