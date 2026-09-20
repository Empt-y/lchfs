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
    let report = lchfs_fsck::check_devices(&[a.path(), b.path(), c.path()], &roots);
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

/// A stripe's device list is written once; a device that holds shards
/// cannot leave until every stripe naming it is a mirror again
/// (§17.2.4 "detach").
#[test]
fn detach_repacks_the_stripes_that_name_the_leaving_device() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let striped = {
        let pool = populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1);
        let status = pool.stripe_status();
        assert_eq!(status.striped_segments as usize, segment_ids_with_shards(a.path()).len());
        assert_eq!(status.segments_missing_shards, 0);
        assert!(status.shard_bytes < status.mirrored_cost_bytes, "{status:?}");
        assert_eq!(status.shard_bytes_by_vdev.len(), 3);
        pool.checkpoint().unwrap();
        segment_ids_with_shards(a.path())
    };
    assert!(!striped.is_empty());

    assert_eq!(Pool::detach_vdev(&[a.path(), b.path(), c.path()]).unwrap(), 2);
    for root in [a.path(), b.path()] {
        assert!(segment_ids_with_shards(root).is_empty(), "every 2+1 stripe named vdev 2 and must be a mirror again");
    }
    assert!(!c.path().join("SUPERBLOCK").exists());

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.stripe_status().striped_segments, 0);
    // Two devices cannot hold a 2+1 stripe: the pass stays a no-op.
    for _ in 0..4 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    assert!(segment_ids_with_shards(a.path()).is_empty());
    pool.checkpoint().unwrap();
    drop(pool);
    let roots = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::check_devices(&[a.path(), b.path()], &roots);
    assert!(report.is_clean(), "{:?}", report.errors);
    let report = lchfs_fsck::check_replicas(&[a.path(), b.path()]);
    assert!(report.is_clean(), "{:?}", report.errors);
}

#[test]
fn live_detach_repacks_stripes_and_leaves_unrelated_ones_alone() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let d = tempfile::tempdir().unwrap();
    // Four devices, 2+1 stripes: the conversion pass takes the first
    // three online devices, so no stripe names vdev 3.
    let pool = populated_and_striped(&[a.path(), b.path(), c.path(), d.path()], 2, 1);
    let striped = segment_ids_with_shards(a.path());
    assert!(!striped.is_empty());
    assert!(segment_ids_with_shards(d.path()).is_empty(), "no stripe should have a shard on vdev 3");

    assert_eq!(pool.detach_vdev_live().unwrap(), 3);
    assert_eq!(segment_ids_with_shards(a.path()), striped, "stripes not naming the leaver are untouched");
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }

    // Now vdev 2 leaves: every stripe names it, so every one is repacked
    // to a mirror first, and the pool reads whole after.
    assert_eq!(pool.detach_vdev_live().unwrap(), 2);
    assert!(segment_ids_with_shards(a.path()).is_empty());
    assert!(segment_ids_with_shards(b.path()).is_empty());
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.stripe_status().striped_segments, 0);
    pool.checkpoint().unwrap();
    drop(pool);
    let roots = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::check_replicas(&[a.path(), b.path()]);
    assert!(report.is_clean(), "{:?}", report.errors);
    let report = lchfs_fsck::check_devices(&[a.path(), b.path()], &roots);
    assert!(report.is_clean(), "{:?}", report.errors);
}

#[test]
fn detach_refuses_when_a_stripe_cannot_be_read_back() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    drop(populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1));
    let striped = segment_ids_with_shards(a.path());
    // Take two of a stripe's three shards away: one shard cannot rebuild
    // a 2+1 stripe, and that data must not leave with vdev 2.
    let id = striped[0];
    for root in [a.path(), b.path()] {
        for i in lchfs_store::stripe::shards_on(root, id) {
            std::fs::remove_file(lchfs_store::stripe::shard_path(root, id, i)).unwrap();
        }
    }
    let err = Pool::detach_vdev(&[a.path(), b.path(), c.path()]).unwrap_err().to_string();
    assert!(err.contains("refusing to detach"), "{err}");
    assert!(c.path().join("SUPERBLOCK").exists(), "nothing was changed");
}

#[test]
fn the_stripe_policy_changes_live_and_persists() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path(), c.path()], striped_params(0, 0)).unwrap();
    assert!(!pool.stripe_policy().enabled());
    for i in 0..14u32 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(i)).unwrap();
    }
    pool.checkpoint().unwrap();
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    assert!(segment_ids_with_shards(a.path()).is_empty(), "policy off: nothing striped");

    let err = pool.set_stripe_policy(1, 1, None).unwrap_err().to_string();
    assert!(err.contains("stripe policy"), "{err}");
    pool.set_stripe_policy(2, 1, Some(0)).unwrap();
    assert_eq!(
        pool.stripe_policy(),
        lchfs_store::StripePolicyParams { k: 2, m: 1, min_age_segments: 0 }
    );
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    let striped = segment_ids_with_shards(a.path());
    assert!(!striped.is_empty(), "policy on: cold segments convert");
    let status = pool.stripe_status();
    assert_eq!((status.k, status.m), (2, 1));
    assert_eq!(status.striped_segments as usize, striped.len());
    drop(pool);

    // Remount: the policy came back from the root object, as did the
    // stripes.
    let pool = Pool::open_replicated(&[a.path(), b.path(), c.path()]).unwrap();
    assert_eq!(pool.stripe_policy().k, 2);
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    // Off again: existing stripes stay, no new ones form.
    pool.set_stripe_policy(0, 0, None).unwrap();
    for i in 14..20u32 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(i)).unwrap();
    }
    pool.checkpoint().unwrap();
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    assert_eq!(segment_ids_with_shards(a.path()), striped);
}

/// A read that reconstructs is the cold-data failover and is accounted
/// like one: a shard gone from a device that is still there is a
/// corruption event against it, and a device whose root has vanished is
/// faulted -- the pool must not read as healthy while serving from
/// parity.
#[test]
fn a_reconstructing_read_is_counted_and_a_pulled_device_is_faulted() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = populated_and_striped(&[a.path(), b.path(), c.path()], 2, 1);
    let striped = segment_ids_with_shards(c.path());
    let id = striped[0];
    for i in lchfs_store::stripe::shards_on(c.path(), id) {
        std::fs::remove_file(lchfs_store::stripe::shard_path(c.path(), id, i)).unwrap();
    }
    // The location cache is what read_verified consults; a remount reads
    // cold.
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open_replicated(&[a.path(), b.path(), c.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    let stats = pool.repair_stats();
    assert!(stats.failovers > 0, "{stats:?}");
    let events = pool.corruption_events();
    assert!(
        events.iter().any(|e| e.vdev_id == 2 && e.location.is_some_and(|l| l.segment_id == id) && !e.healed),
        "{events:?}"
    );
    assert_eq!(pool.vdev_status().iter().find(|s| s.id == 2).unwrap().health, lchfs_store::VdevHealth::Online);
    // Resilver puts the shard back, and reads stop reconstructing.
    assert_eq!(pool.resilver(2).unwrap().shards_rebuilt, 1);
    let before = pool.repair_stats().failovers;
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.repair_stats().failovers, before);

    // Pull the device: its root is gone, and the next cold read that
    // needs it faults it.
    let pulled = c.path().with_extension("pulled");
    std::fs::rename(c.path(), &pulled).unwrap();
    pool.clear_corruption_events();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.vdev_status().iter().find(|s| s.id == 2).unwrap().health, lchfs_store::VdevHealth::Faulted);
    assert!(pool.corruption_events().is_empty(), "a pulled device is a fault, not corruption");
    std::fs::rename(&pulled, c.path()).unwrap();
}
