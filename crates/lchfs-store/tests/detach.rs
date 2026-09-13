//! Removing a device (ARCHITECTURE.md §15.9). For a mirror there is no
//! evacuation: the leaving device's records are copies. Detach proves the
//! survivors are complete, then forgets the slot.

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
fn a_mirror_shrinks_back_to_a_single_device() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let data = payload(21);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }

    assert_eq!(Pool::detach_vdev(&[a.path(), b.path()]).unwrap(), 1);

    // b is no longer a member in any sense.
    assert!(!b.path().join("SUPERBLOCK").exists());
    let err = Pool::open_replicated(&[a.path(), b.path()]).unwrap_err().to_string();
    assert!(err.contains("no valid superblock"), "{err}");

    // a stands alone, as a plain single-vdev pool.
    let pool = Pool::open(a.path()).unwrap();
    assert!(!pool.is_degraded());
    assert_eq!(read_file(&pool, "f", data.len()), data);
    assert_eq!(pool.repair_stats().failovers, 0, "nothing should have needed b");
    pool.scrub().unwrap();
    assert_eq!(pool.repair_stats().heal_failures, 0);
}

/// The leaving device is still a member while the survivors are proven,
/// so anything only it holds gets copied over before it goes.
#[test]
fn detach_first_fills_the_survivors_from_the_leaving_device() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let data = payload(22);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    // a's copies rot; b's are the good ones -- and b is the one leaving.
    for path in data_segments(a.path()) {
        let mut bytes = std::fs::read(&path).unwrap();
        if bytes.len() > 8192 {
            let mid = bytes.len() / 2;
            for x in &mut bytes[mid..mid + 64] {
                *x ^= 0xff;
            }
            std::fs::write(&path, &bytes).unwrap();
        }
    }

    assert_eq!(Pool::detach_vdev(&[a.path(), b.path()]).unwrap(), 1);
    let pool = Pool::open(a.path()).unwrap();
    assert_eq!(read_file(&pool, "f", data.len()), data);
}

/// If the survivors could not stand alone, nothing is changed.
#[test]
fn detach_refuses_when_a_record_would_lose_its_last_good_copy() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let data = payload(23);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    // Both copies of the data are gone: nothing can be proven complete.
    for root in [a.path(), b.path()] {
        for f in data_segments(root) {
            std::fs::remove_file(f).unwrap();
        }
    }
    let err = Pool::detach_vdev(&[a.path(), b.path()]).unwrap_err().to_string();
    assert!(err.contains("refusing to detach"), "{err}");
    assert!(b.path().join("SUPERBLOCK").exists(), "the leaving device must be untouched");
    assert!(Pool::open_replicated(&[a.path(), b.path()]).is_ok(), "the set must still be coherent");
}

#[test]
fn only_the_last_slot_can_leave_and_a_single_device_cannot() {
    let a = tempfile::tempdir().unwrap();
    drop(Pool::create(a.path(), small_params()).unwrap());
    let err = Pool::detach_vdev(&[a.path()]).unwrap_err().to_string();
    assert!(err.contains("nothing to detach"), "{err}");
}

/// Round trip: attach, use, detach, use, attach again.
#[test]
fn a_pool_can_grow_and_shrink_repeatedly() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let one = payload(31);
    let two = payload(32);
    {
        let pool = Pool::create(a.path(), small_params()).unwrap();
        let ino = pool.create_file(1, "one", 0o644).unwrap();
        pool.write(ino, 0, &one).unwrap();
        pool.checkpoint().unwrap();
    }
    Pool::attach_vdev(&[a.path()], b.path()).unwrap();
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        let ino = pool.create_file(1, "two", 0o644).unwrap();
        pool.write(ino, 0, &two).unwrap();
        pool.checkpoint().unwrap();
    }
    Pool::detach_vdev(&[a.path(), b.path()]).unwrap();
    Pool::attach_vdev(&[a.path()], c.path()).unwrap();
    // c is filled at this mount; then a loses its data and c serves.
    {
        let pool = Pool::open_replicated(&[a.path(), c.path()]).unwrap();
        assert_eq!(pool.mount_resilver().len(), 1);
        pool.checkpoint().unwrap();
    }
    for f in data_segments(a.path()) {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), c.path()]).unwrap();
    assert_eq!(read_file(&pool, "one", one.len()), one);
    assert_eq!(read_file(&pool, "two", two.len()), two);
}

/// A detach interrupted after the leaving device's ring was erased but
/// before every survivor was rewritten leaves survivors disagreeing on
/// the count. That must still mount degraded, and a rerun must finish.
#[test]
fn a_detach_interrupted_between_survivors_is_recoverable() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let data = payload(41);
    {
        let pool = Pool::create_replicated(&[a.path(), b.path(), c.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    // Simulate the crash: c's ring gone, a rewritten to 2, b still says 3.
    let b_ring = std::fs::read(b.path().join("SUPERBLOCK")).unwrap();
    Pool::detach_vdev(&[a.path(), b.path(), c.path()]).unwrap();
    std::fs::write(b.path().join("SUPERBLOCK"), &b_ring).unwrap();

    // Highest count wins: the pool is 3 wide with slot 2 empty.
    let err = Pool::open_replicated(&[a.path(), b.path()]).unwrap_err().to_string();
    assert!(err.contains("3 vdevs but 2 were given"), "{err}");
    {
        let pool = Pool::open_degraded(&[a.path(), b.path()]).unwrap();
        assert_eq!(pool.missing_vdevs(), vec![2]);
        assert_eq!(read_file(&pool, "f", data.len()), data);
    }
    // And the rerun, with the leaver already gone, finishes the shrink.
    assert_eq!(Pool::detach_vdev(&[a.path(), b.path()]).unwrap(), 2);
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert!(!pool.is_degraded());
    assert_eq!(read_file(&pool, "f", data.len()), data);
}

// ---- Live ----------------------------------------------------------------

/// The same proof as the offline detach, on a mounted pool, with writes
/// continuing afterwards on the smaller set.
#[test]
fn a_device_leaves_a_mounted_pool() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let one = payload(51);
    let two = payload(52);
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "one", 0o644).unwrap();
    pool.write(ino, 0, &one).unwrap();
    pool.checkpoint().unwrap();

    assert_eq!(pool.detach_vdev_live().unwrap(), 1);
    assert_eq!(pool.vdev_status().len(), 1, "{:?}", pool.vdev_status());
    assert!(!pool.is_degraded());
    assert!(!b.path().join("SUPERBLOCK").exists());

    let ino2 = pool.create_file(1, "two", 0o644).unwrap();
    pool.write(ino2, 0, &two).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(read_file(&pool, "one", one.len()), one);
    drop(pool);

    // A plain single-device pool now, and b is no member of anything.
    let pool = Pool::open(a.path()).unwrap();
    assert_eq!(read_file(&pool, "two", two.len()), two);
    assert!(Pool::open_replicated(&[a.path(), b.path()]).is_err());
    let err = pool.detach_vdev_live().unwrap_err().to_string();
    assert!(err.contains("nothing to detach"), "{err}");
}

#[test]
fn the_primary_cannot_leave_while_mounted() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    // Mount without vdev 0: vdev 1 is the primary *and* the last slot.
    let pool = Pool::open_degraded(&[b.path()]).unwrap();
    assert_eq!(pool.primary_vdev(), 1);
    let err = pool.detach_vdev_live().unwrap_err().to_string();
    assert!(err.contains("primary"), "{err}");
}
