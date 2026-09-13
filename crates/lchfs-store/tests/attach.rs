//! Growing a pool and replacing a device (ARCHITECTURE.md §15.10, §15.4).
//!
//! A single-vdev pool created today is byte-identical to vdev 0 of a
//! multi-vdev pool later, which is what makes adding a device a resilver
//! rather than a migration. `attach_vdev` is that: it changes the count,
//! hands the blank device a slot at generation 0, and leaves the copying
//! to the resilver the next mount runs anyway.

use lchfs_format::PoolParams;
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

fn payload(seed: u32) -> Vec<u8> {
    (0..30_000u32)
        .map(|i| ((i ^ seed).wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn data_segments(root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(root.join("segments/data"))
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn read_file(pool: &Pool, name: &str, len: usize) -> Vec<u8> {
    let ino = pool.lookup(1, name).unwrap().expect(name);
    pool.read(ino, 0, len as u32).unwrap().to_vec()
}

#[test]
fn a_single_vdev_pool_becomes_a_mirror_by_attaching_a_blank_device() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let data = payload(1);
    {
        let pool = Pool::create(a.path(), small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }

    assert_eq!(Pool::attach_vdev(&[a.path()], b.path()).unwrap(), 1);

    // The old single-device open must now refuse: the pool has two.
    let err = Pool::open(a.path()).unwrap_err().to_string();
    assert!(err.contains("2 vdevs but 1 were given"), "{err}");

    // The full open resilvers everything onto b before serving.
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        let [(1, report)] = pool.mount_resilver() else {
            panic!("expected a mount-time resilver of vdev 1, got {:?}", pool.mount_resilver());
        };
        assert!(report.missing > 0 && report.healed == report.missing, "{report:?}");
        assert!(report.unrecoverable.is_empty(), "{report:?}");
        assert_eq!(read_file(&pool, "f", data.len()), data);
        // New writes now fan out to both.
        let ino = pool.create_file(1, "g", 0o644).unwrap();
        pool.write(ino, 0, &payload(2)).unwrap();
        pool.checkpoint().unwrap();
    }

    // Everything -- resilvered and fanned out -- is on b alone.
    for f in data_segments(a.path()) {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_file(&pool, "f", data.len()), data);
    assert_eq!(read_file(&pool, "g", 30_000), payload(2));
    assert!(pool.repair_stats().failovers >= 1);
}

#[test]
fn a_dead_device_is_replaced_by_attaching_a_blank_one_into_its_slot() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let b2 = tempfile::tempdir().unwrap();
    let data = payload(3);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    // b dies. Only a is offered, and the replacement goes into slot 1.
    assert_eq!(Pool::attach_vdev(&[a.path()], b2.path()).unwrap(), 1);

    let pool = Pool::open_replicated(&[a.path(), b2.path()]).unwrap();
    assert_eq!(pool.mount_resilver().len(), 1);
    assert_eq!(read_file(&pool, "f", data.len()), data);
    drop(pool);

    for f in data_segments(a.path()) {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b2.path()]).unwrap();
    assert_eq!(read_file(&pool, "f", data.len()), data, "the replacement should carry everything");
}

#[test]
fn attach_refuses_a_device_that_already_holds_a_pool() {
    let a = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    drop(Pool::create(a.path(), small_params()).unwrap());
    drop(Pool::create(other.path(), small_params()).unwrap());
    let err = Pool::attach_vdev(&[a.path()], other.path()).unwrap_err().to_string();
    assert!(err.contains("already exists"), "{err}");
    // And a's count was not touched.
    assert!(Pool::open(a.path()).is_ok());
}

#[test]
fn attach_refuses_while_the_pool_is_mounted() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create(a.path(), small_params()).unwrap();
    let err = Pool::attach_vdev(&[a.path()], b.path()).unwrap_err().to_string();
    assert!(err.contains("already open"), "{err}");
    drop(pool);
}

/// An attach interrupted after the existing members were rewritten but
/// before the new device was, reads as a pool with one slot empty --
/// which a rerun treats as a replacement, and finishes.
#[test]
fn an_interrupted_attach_is_finished_by_running_it_again() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let data = payload(4);
    {
        let pool = Pool::create(a.path(), small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    Pool::attach_vdev(&[a.path()], b.path()).unwrap();
    // "Crash" before b's superblock landed: wipe b entirely.
    std::fs::remove_dir_all(b.path()).unwrap();

    assert_eq!(Pool::attach_vdev(&[a.path()], b.path()).unwrap(), 1);
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_file(&pool, "f", data.len()), data);
}

/// Losing the primary is no different from losing any other device now:
/// the blank replacement takes slot 0, becomes the primary again by virtue
/// of being the lowest slot, and is filled from the survivor.
#[test]
fn a_dead_primary_is_replaced_the_same_way() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let a2 = tempfile::tempdir().unwrap();
    let data = payload(8);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    assert_eq!(Pool::attach_vdev(&[b.path()], a2.path()).unwrap(), 0);

    let pool = Pool::open_replicated(&[a2.path(), b.path()]).unwrap();
    assert_eq!(pool.mount_resilver().len(), 1);
    assert_eq!(pool.mount_resilver()[0].0, 0);
    assert_eq!(read_file(&pool, "f", data.len()), data);
    assert!(a2.path().join("INDEX.redb").exists(), "the new primary built its own index");
    pool.checkpoint().unwrap();
    drop(pool);

    // And it can now carry the pool alone.
    let pool = Pool::open_degraded(&[a2.path()]).unwrap();
    assert_eq!(read_file(&pool, "f", data.len()), data);
}

// ---- Live attach --------------------------------------------------------

/// The everyday case: a running single-device pool grows into a mirror
/// without unmounting. What was there before the attach is copied, what
/// is written after fans out, and the device is current at the next mount.
#[test]
fn a_device_attached_while_mounted_is_filled_and_then_written_to() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let before = payload(11);
    let after = payload(12);

    let pool = Pool::create(a.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "before", 0o644).unwrap();
    pool.write(ino, 0, &before).unwrap();
    pool.checkpoint().unwrap();

    let (id, report) = pool.attach_vdev_live(b.path()).unwrap();
    assert_eq!(id, 1);
    assert!(report.missing > 0 && report.healed == report.missing, "{report:?}");
    assert!(report.unrecoverable.is_empty(), "{report:?}");
    assert!(!pool.is_degraded());
    assert!(pool.missing_vdevs().is_empty());

    let ino2 = pool.create_file(1, "after", 0o644).unwrap();
    pool.write(ino2, 0, &after).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // b is a full member now: no resilver on remount...
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        assert!(pool.mount_resilver().is_empty(), "{:?}", pool.mount_resilver());
    }
    // ...and it carries everything on its own.
    for f in data_segments(a.path()) {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_file(&pool, "before", before.len()), before);
    assert_eq!(read_file(&pool, "after", after.len()), after);
    assert!(pool.repair_stats().failovers >= 1);
}

/// The property that justifies the barrier: with writes arriving the whole
/// time, nothing written before, during or after the attach is missing
/// from the new device -- checked by fsck's own replica comparison, which
/// shares no code with the engine.
#[test]
fn a_live_attach_under_write_load_leaves_no_record_missing() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(a.path(), small_params()).unwrap());
    for i in 0..8u32 {
        let ino = pool.create_file(1, &format!("pre{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(100 + i)).unwrap();
    }
    pool.checkpoint().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let writers: Vec<_> = (0..3u32)
        .map(|t| {
            let pool = Arc::clone(&pool);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut n = 0u32;
                while !stop.load(Ordering::Relaxed) {
                    let name = format!("t{t}-{n}");
                    let ino = pool.create_file(1, &name, 0o644).unwrap();
                    pool.write(ino, 0, &payload(1000 * t + n)).unwrap();
                    if n.is_multiple_of(4) {
                        pool.fsync(ino).unwrap();
                    }
                    n += 1;
                }
                n
            })
        })
        .collect();
    // Let the writers get going before the attach lands in the middle.
    std::thread::sleep(std::time::Duration::from_millis(50));

    let (id, report) = pool.attach_vdev_live(b.path()).unwrap();
    assert_eq!(id, 1);
    assert!(report.healed > 0, "{report:?}");

    std::thread::sleep(std::time::Duration::from_millis(50));
    stop.store(true, Ordering::Relaxed);
    let written: u32 = writers.into_iter().map(|w| w.join().unwrap()).sum();
    assert!(written > 0);
    pool.checkpoint().unwrap();
    drop(pool);

    let fsck = lchfs_fsck::check_replicas(&[a.path(), b.path()]);
    let missing_on_b: Vec<_> = fsck
        .errors
        .iter()
        .filter(|e| matches!(e, lchfs_fsck::FsckError::ReplicaMissing { vdev_id: 1, .. }))
        .collect();
    assert!(missing_on_b.is_empty(), "{} records missing from the attached device: {:?}", missing_on_b.len(), &missing_on_b[..missing_on_b.len().min(3)]);
    assert!(
        !fsck.errors.iter().any(|e| matches!(e, lchfs_fsck::FsckError::VdevBehind { .. })),
        "{:?}",
        fsck.errors
    );
}

/// Replacing a dead device without unmounting: the pool runs degraded,
/// the blank replacement takes the empty slot live, and is filled.
#[test]
fn a_dead_device_is_replaced_while_mounted() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let b2 = tempfile::tempdir().unwrap();
    let data = payload(13);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    let pool = Pool::open_degraded(&[a.path()]).unwrap();
    assert_eq!(pool.missing_vdevs(), vec![1]);
    let (id, report) = pool.attach_vdev_live(b2.path()).unwrap();
    assert_eq!(id, 1);
    assert!(report.healed > 0, "{report:?}");
    assert!(!pool.is_degraded());
    drop(pool);

    for f in data_segments(a.path()) {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b2.path()]).unwrap();
    assert!(pool.mount_resilver().is_empty(), "{:?}", pool.mount_resilver());
    assert_eq!(read_file(&pool, "f", data.len()), data);
}

#[test]
fn a_live_attach_refuses_a_device_that_already_holds_a_pool() {
    let a = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    drop(Pool::create(other.path(), small_params()).unwrap());
    let pool = Pool::create(a.path(), small_params()).unwrap();
    let err = pool.attach_vdev_live(other.path()).unwrap_err().to_string();
    assert!(err.contains("already exists"), "{err}");
    assert!(pool.missing_vdevs().is_empty());
    assert!(!pool.is_degraded());
}
