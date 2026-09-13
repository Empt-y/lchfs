//! Erasure coding end to end (ARCHITECTURE.md §17.2): cold segments are
//! converted to stripes by the coalescing daemon, reads keep working --
//! including with a device gone -- shards are rebuilt by resilver and
//! scrub, and a stripe that goes mostly dead is repacked to a mirror.

use lchfs_format::PoolParams;
use lchfs_store::Pool;
use lchfs_store::stripe::segment_ids_with_shards;
use std::path::{Path, PathBuf};

fn striped_params(k: u8, m: u8) -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 16 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: k,
        stripe_m: m,
        stripe_min_age_segments: 0,
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

fn aseg_files(root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(root.join("segments/data"))
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "aseg")).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// Enough cold, full segments to stripe: 12 files of 30 KB at a 16 KiB
/// segment cap, two extra so the last ones are past the grace window,
/// then as many passes as it takes (4 conversions per pass).
fn populated_and_striped(roots: &[&Path], k: u8, m: u8) -> Pool {
    let pool = Pool::create_replicated(roots, striped_params(k, m)).unwrap();
    for i in 0..14u32 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(i)).unwrap();
    }
    pool.checkpoint().unwrap();
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    pool
}

#[test]
fn cold_segments_become_stripes_and_read_back_from_any_path() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1);

    let striped = segment_ids_with_shards(a.path());
    assert!(!striped.is_empty(), "no segment was converted");
    for root in [a.path(), b.path(), c.path()] {
        assert_eq!(segment_ids_with_shards(root), striped, "every device holds one shard of each stripe");
        for id in &striped {
            assert!(!root.join(format!("segments/data/{id}.aseg")).exists(), "mirror copy of {id} should be gone");
        }
    }
    let mirrored_left = aseg_files(a.path()).len();
    assert!(mirrored_left > 0, "the grace-window segments stay mirrored");

    // Every file reads back, on the live pool.
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    // GC mark still walks everything after conversion.
    pool.run_gc_and_coalesce_pass().unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // Remount: the index carries the striped entries, the cache is
    // warmed with them, and no read needs to fail over.
    let pool = Pool::open_replicated(&[a.path(), b.path(), c.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.repair_stats().failovers, 0);
    drop(pool);

    // And with the index gone, the slow path reassembles the stripes.
    std::fs::remove_file(a.path().join("INDEX.redb")).unwrap();
    let pool = Pool::open_replicated(&[a.path(), b.path(), c.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
}

#[test]
fn striped_data_is_served_with_a_device_missing() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    drop(populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1));
    // Mount without the last device: its shards are reconstructed.
    let pool = Pool::open_degraded(&[a.path(), b.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    drop(pool);
    // Without the primary, the same.
    let pool = Pool::open_degraded(&[b.path(), c.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
}

#[test]
fn resilver_and_scrub_rebuild_lost_and_corrupt_shards() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1);
    let striped = segment_ids_with_shards(c.path());
    assert!(!striped.is_empty());

    // Lose every shard on c.
    for id in &striped {
        for i in lchfs_store::stripe::shards_on(c.path(), *id) {
            std::fs::remove_file(lchfs_store::stripe::shard_path(c.path(), *id, i)).unwrap();
        }
    }
    assert!(segment_ids_with_shards(c.path()).is_empty());
    let report = pool.resilver(2).unwrap();
    assert_eq!(report.shards_rebuilt as usize, striped.len(), "{report:?}");
    assert_eq!(report.missing, 0, "striped records are not mirror obligations: {report:?}");
    assert_eq!(segment_ids_with_shards(c.path()), striped);

    // Corrupt one shard on b; scrub finds and rebuilds it.
    let id = striped[0];
    let i = lchfs_store::stripe::shards_on(b.path(), id)[0];
    let p = lchfs_store::stripe::shard_path(b.path(), id, i);
    let mut bytes = std::fs::read(&p).unwrap();
    let n = bytes.len();
    for x in &mut bytes[n / 2..n / 2 + 64] {
        *x ^= 0xff;
    }
    std::fs::write(&p, &bytes).unwrap();
    let reports = pool.scrub().unwrap();
    let rb = reports.iter().find(|r| r.vdev_id == 1).unwrap();
    assert_eq!(rb.shards_corrupt, 1, "{rb:?}");
    assert_eq!(rb.shards_rebuilt, 1, "{rb:?}");
    assert!(rb.shards_verified as usize >= striped.len());
    let again = pool.scrub().unwrap();
    assert!(again.iter().all(|r| r.shards_corrupt == 0), "{again:?}");
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
}

#[test]
fn a_stripe_that_goes_mostly_dead_is_repacked_to_a_mirror() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1);
    let striped_before = segment_ids_with_shards(a.path());
    assert!(!striped_before.is_empty());

    // Delete nearly everything so the stripes' live fraction collapses.
    for i in 0..13u32 {
        pool.unlink(1, &format!("f{i}")).unwrap();
    }
    pool.checkpoint().unwrap();
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    let striped_after = segment_ids_with_shards(a.path());
    assert!(
        striped_after.len() < striped_before.len(),
        "dead stripes should have been repacked: {striped_before:?} -> {striped_after:?}"
    );
    // The survivor still reads, and the pool is coherent to fsck.
    assert_eq!(read_file(&pool, "f13", 30_000), payload(13));
    pool.checkpoint().unwrap();
    drop(pool);
    let roots = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::check(a.path(), &roots);
    assert!(report.is_clean(), "{:?}", report.errors);
}

#[test]
fn two_devices_get_no_stripes_and_bad_shapes_are_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = populated_and_striped(&[a.path(), b.path()], 2, 1);
    assert!(segment_ids_with_shards(a.path()).is_empty(), "k + m = 3 needs three devices");
    drop(pool);
    let err = Pool::create(&a.path().join("x"), striped_params(1, 1)).unwrap_err().to_string();
    assert!(err.contains("stripe policy"), "{err}");
}
