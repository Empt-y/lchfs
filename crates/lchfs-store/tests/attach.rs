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
