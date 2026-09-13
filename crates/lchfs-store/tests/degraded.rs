//! Degraded mount and rejoin (ARCHITECTURE.md §15.5, §15.8).
//!
//! A pool mounts read-write with a device absent, but only when asked to
//! (`open_degraded`) -- a short list to `open_replicated` stays an error,
//! because running degraded by accident is how a pool ends up one failure
//! from data loss without anyone knowing. While degraded, the absent
//! device's superblock is not advanced, so its generation falls behind;
//! that gap is what the next full mount uses to know it must resilver.

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

fn segment_files(root: &Path, stream: &str) -> Vec<PathBuf> {
    let dir = root.join("segments").join(stream);
    let mut out: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// Every file under `dir`, relative path -> bytes.
fn tree(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    fn walk(base: &Path, d: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(d) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if let Ok(bytes) = std::fs::read(&p) {
                out.insert(p.strip_prefix(base).unwrap().to_path_buf(), bytes);
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

fn read_file(pool: &Pool, name: &str, len: usize) -> Vec<u8> {
    let ino = pool.lookup(1, name).unwrap().expect(name);
    pool.read(ino, 0, len as u32).unwrap().to_vec()
}

/// The full story: write with both devices, lose one, keep writing without
/// it, bring it back, and end up able to serve everything from it alone.
#[test]
fn a_device_that_missed_writes_is_resilvered_when_it_rejoins() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let before = payload(1);
    let during = payload(2);

    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "before", 0o644).unwrap();
        pool.write(ino, 0, &before).unwrap();
        pool.checkpoint().unwrap();
    }
    let b_tree_while_away = tree(b.path());

    // vdev b is "unplugged": mount without it, and write.
    {
        let pool = Pool::open_degraded(&[a.path()]).unwrap();
        assert!(pool.is_degraded());
        assert_eq!(pool.missing_vdevs(), &[1]);
        assert!(pool.mount_resilver().is_empty());
        assert_eq!(read_file(&pool, "before", before.len()), before, "old data still readable");
        let ino = pool.create_file(1, "during", 0o644).unwrap();
        pool.write(ino, 0, &during).unwrap();
        pool.checkpoint().unwrap();
    }
    assert_eq!(tree(b.path()), b_tree_while_away, "an absent device must not be written to");

    // vdev b returns. Its generation trails a's, so mount resilvers it.
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        assert!(!pool.is_degraded());
        let [(id, report)] = pool.mount_resilver() else {
            panic!("expected exactly one mount-time resilver, got {:?}", pool.mount_resilver());
        };
        assert_eq!(*id, 1);
        assert!(report.missing > 0, "{report:?}");
        assert_eq!(report.healed, report.missing, "{report:?}");
        assert!(report.unrecoverable.is_empty(), "{report:?}");
        assert!(tree(b.path()).len() > b_tree_while_away.len(), "resilver wrote nothing to b");
        // And the superblock caught up on the very next checkpoint.
        pool.checkpoint().unwrap();
    }
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        assert!(pool.mount_resilver().is_empty(), "b should be current now");
    }

    // The proof: a loses its data, and everything -- including what was
    // written while b was away -- comes back from b.
    for f in segment_files(a.path(), "data") {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(read_file(&pool, "before", before.len()), before);
    assert_eq!(read_file(&pool, "during", during.len()), during);
    assert!(pool.repair_stats().failovers >= 1);
}

#[test]
fn a_short_list_is_still_refused_unless_degraded_is_asked_for() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    let err = Pool::open_replicated(&[a.path()]).unwrap_err().to_string();
    assert!(err.contains("2 vdevs but 1 were given"), "{err}");
    assert!(Pool::open_degraded(&[a.path()]).is_ok());
}

#[test]
fn a_degraded_mount_without_the_primary_is_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    let err = Pool::open_degraded(&[b.path()]).unwrap_err().to_string();
    assert!(err.contains("vdev 0 is not among the devices given"), "{err}");
}

/// Order is derived from the superblocks in a degraded open, so a device
/// named out of order still lands in its own slot -- and two devices
/// claiming the same slot are caught.
#[test]
fn degraded_open_takes_devices_in_any_order_but_never_twice() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path(), c.path()], small_params()).unwrap());

    let pool = Pool::open_degraded(&[c.path(), a.path()]).unwrap();
    assert_eq!(pool.missing_vdevs(), &[1]);
    drop(pool);

    let err = Pool::open_degraded(&[a.path(), a.path()]).unwrap_err().to_string();
    assert!(err.contains("both claim to be vdev 0") || err.contains("lock"), "{err}");
}

#[test]
fn a_foreign_device_is_refused_from_a_degraded_open_too() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    drop(Pool::create(other.path(), small_params()).unwrap());
    let err = Pool::open_degraded(&[a.path(), other.path()]).unwrap_err().to_string();
    assert!(err.contains("different pool"), "{err}");
}

/// The primary holds the index and serves every default read, so a pool
/// whose *primary* fell behind cannot be mounted honestly yet: the newer
/// root lives on a device nothing would read from. Refuse, and say so.
#[test]
fn a_primary_behind_another_device_is_refused_with_a_reason() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    let a_ring_at_creation = std::fs::read(a.path().join("SUPERBLOCK")).unwrap();

    // Advance both devices, then roll only the primary's ring back. a now
    // says vdev 0 at the creation generation; b says vdev 1, two ahead.
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        pool.checkpoint().unwrap();
        pool.checkpoint().unwrap();
    }
    std::fs::write(a.path().join("SUPERBLOCK"), &a_ring_at_creation).unwrap();

    let err = Pool::open_replicated(&[a.path(), b.path()]).unwrap_err().to_string();
    assert!(err.contains("cannot mount from a stale primary"), "{err}");
    assert!(err.contains("vdev 1"), "should name the device that is ahead: {err}");
}
