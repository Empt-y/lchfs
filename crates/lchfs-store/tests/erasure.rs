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
    lchfs_index::RedbIndex::remove(a.path()).unwrap();
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
    assert!(!lchfs_store::testing::ring_written(c.path()));

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
    assert!(lchfs_store::testing::ring_written(c.path()), "nothing was changed");
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
    let parent = tempfile::tempdir().unwrap();
    let b = parent.path().join("b");
    let c = tempfile::tempdir().unwrap();
    let pool = populated_and_striped(&[a.path(), &b, c.path()], 2, 1);
    let striped = segment_ids_with_shards(&b);
    let id = striped[0];
    // b holds shard 1, a data shard: losing it makes reads of the records
    // in it reconstruct (losing c's parity shard would not).
    for i in lchfs_store::stripe::shards_on(&b, id) {
        assert!(i < 2, "b holds a data shard");
        std::fs::remove_file(lchfs_store::stripe::shard_path(&b, id, i)).unwrap();
    }
    // The location cache is what read_verified consults; a remount reads
    // cold.
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open_replicated(&[a.path(), &b, c.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    let stats = pool.repair_stats();
    assert!(stats.failovers > 0, "{stats:?}");
    let events = pool.corruption_events();
    assert!(
        events.iter().any(|e| e.vdev_id == 1 && e.location.is_some_and(|l| l.segment_id == id) && !e.healed),
        "{events:?}"
    );
    assert_eq!(pool.vdev_status().iter().find(|s| s.id == 1).unwrap().health, lchfs_store::VdevHealth::Online);
    // Resilver puts the shard back, and reads stop reconstructing.
    assert_eq!(pool.resilver(1).unwrap().shards_rebuilt, 1);
    let before = pool.repair_stats().failovers;
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.repair_stats().failovers, before);

    // Pull the device: its root is gone, and the next cold read that
    // needs it faults it.
    let pulled = parent.path().join("b.pulled");
    std::fs::rename(&b, &pulled).unwrap();
    pool.clear_corruption_events();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.vdev_status().iter().find(|s| s.id == 1).unwrap().health, lchfs_store::VdevHealth::Faulted);
    assert!(pool.corruption_events().is_empty(), "a pulled device is a fault, not corruption");
    std::fs::rename(&pulled, &b).unwrap();
}

/// Flips bytes at the start of data shard 0 of `id` on `root`: the
/// first record of the segment, header and all, is now wrong on that
/// device, and the shard's own hash no longer matches.
fn corrupt_first_record_in_shard0(root: &Path, id: u64) {
    let p = lchfs_store::stripe::shard_path(root, id, 0);
    let mut bytes = std::fs::read(&p).unwrap();
    for x in &mut bytes[4096..4096 + 300] {
        *x ^= 0xa5;
    }
    std::fs::write(&p, &bytes).unwrap();
}

/// Which device holds shard 0 of `id`.
fn holder_of_shard0<'a>(roots: &[&'a Path], id: u64) -> &'a Path {
    roots
        .iter()
        .copied()
        .find(|r| lchfs_store::stripe::shards_on(r, id).contains(&0))
        .expect("shard 0 is somewhere")
}

/// A data shard that is present but wrong must be treated as missing
/// by every reader: a read of the record it holds is served through
/// parity rather than failing, scrub rebuilds the shard from its
/// siblings rather than rewriting its own bytes with a matching hash,
/// and fsck's independent parity check agrees afterwards.
#[test]
fn a_present_but_corrupt_shard_is_read_through_parity_and_rebuilt_from_siblings() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    let pool = populated_and_striped(&roots, 2, 1);
    let striped = segment_ids_with_shards(a.path());
    let id = striped[0];
    let holder = holder_of_shard0(&roots, id);
    corrupt_first_record_in_shard0(holder, id);

    // Every file still reads: the record in the corrupt shard comes back
    // through the other two shards.
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }

    // Scrub sees the bad shard and rebuilds it -- and what it writes is
    // what the siblings say, which fsck checks by recomputing parity.
    let reports = pool.scrub().unwrap();
    assert_eq!(reports.iter().map(|r| r.shards_corrupt).sum::<u64>(), 1, "{reports:?}");
    assert_eq!(reports.iter().map(|r| r.shards_rebuilt).sum::<u64>(), 1, "{reports:?}");
    pool.checkpoint().unwrap();
    drop(pool);
    let report = lchfs_fsck::check_stripes(&roots);
    assert!(report.is_clean(), "{:?}", report.errors);
    let live = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::check_devices(&roots, &live);
    assert!(report.is_clean(), "{:?}", report.errors);
}

/// Detach decodes every stripe naming the leaver; a corrupt shard in one
/// of them must be reconstructed, not copied forward -- and nothing may
/// be lost.
#[test]
fn detach_repacks_through_a_corrupt_shard_without_losing_records() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    drop(populated_and_striped(&roots, 2, 1));
    let striped = segment_ids_with_shards(a.path());
    for &id in &striped[..2] {
        corrupt_first_record_in_shard0(holder_of_shard0(&roots, id), id);
    }
    assert_eq!(Pool::detach_vdev(&roots).unwrap(), 2);
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.repair_stats().failovers, 0, "every record has an intact mirror copy");
    pool.checkpoint().unwrap();
    drop(pool);
    let report = lchfs_fsck::check_replicas(&[a.path(), b.path()]);
    assert!(report.is_clean(), "{:?}", report.errors);
}

/// A segment whose primary copy has rotted is not converted: the stripe
/// would be built from the rot and the good mirrors deleted.
#[test]
fn a_segment_with_rot_on_the_primary_is_not_striped() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path(), c.path()], striped_params(2, 1)).unwrap();
    for i in 0..14u32 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(i)).unwrap();
    }
    pool.checkpoint().unwrap();
    // Rot the first record of the oldest sealed segment on the primary
    // only, before any pass has run.
    let oldest = aseg_files(a.path())[0].clone();
    let mut bytes = std::fs::read(&oldest).unwrap();
    for x in &mut bytes[4096..4096 + 64] {
        *x ^= 0xff;
    }
    std::fs::write(&oldest, &bytes).unwrap();
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    let id: u64 = oldest.file_stem().unwrap().to_str().unwrap().parse().unwrap();
    assert!(!segment_ids_with_shards(a.path()).contains(&id), "the rotted segment must stay mirrored");
    assert!(b.path().join(format!("segments/data/{id}.aseg")).exists(), "its good mirrors must survive");
    assert!(!segment_ids_with_shards(a.path()).is_empty(), "other segments still convert");
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
}

/// A descriptor is unchecksummed bytes off disk: a hostile one must make
/// the read fail, never the process.
#[test]
fn a_hostile_descriptor_fails_the_read_and_nothing_else() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    drop(populated_and_striped(&roots, 2, 1));
    let id = segment_ids_with_shards(a.path())[0];
    // Rewrite every shard's descriptor with shard_size = 0 and a device
    // list too short for k + m.
    for root in roots {
        for i in lchfs_store::stripe::shards_on(root, id) {
            let p = lchfs_store::stripe::shard_path(root, id, i);
            let mut file = std::fs::read(&p).unwrap();
            let at = lchfs_format::STRIPE_DESCRIPTOR_OFFSET;
            let len = u32::from_le_bytes(file[at..at + 4].try_into().unwrap()) as usize;
            let mut desc: lchfs_format::StripeDescriptor = lchfs_format::decode(&file[at + 4..at + 4 + len]).unwrap();
            desc.shard_size = 0;
            desc.devices.truncate(1);
            let encoded = lchfs_format::encode(&desc).unwrap();
            file[at..at + 4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
            file[at + 4..at + 4 + encoded.len()].copy_from_slice(&encoded);
            std::fs::write(&p, &file).unwrap();
        }
    }
    let pool = Pool::open_replicated(&roots).unwrap();
    let mut failed = 0;
    for i in 0..14u32 {
        let ino = pool.lookup(1, &format!("f{i}")).unwrap().unwrap();
        if pool.read(ino, 0, 30_000).is_err() {
            failed += 1;
        }
    }
    assert!(failed > 0, "the records in that stripe are unreadable, not silently wrong");
    assert!(pool.scrub().is_ok(), "scrub survives it too");
    drop(pool);
    let report = lchfs_fsck::check_stripes(&roots);
    assert!(
        report.errors.iter().any(|e| matches!(e, lchfs_fsck::FsckError::StripeInconsistent { segment_id, .. } if *segment_id == id)),
        "{:?}",
        report.errors
    );
}

/// The mount path reads stripes too: a file that dedups against cold
/// data, fsync'd and not checkpointed, is replayed from the delta log at
/// the next mount and its chunks are read out of the stripes they now
/// live in. With a data shard gone that read reconstructs, and the mount
/// has to say so the way a read after it would -- counted as a failover,
/// recorded against the device the shard is missing from.
#[test]
fn replay_at_mount_reconstructs_striped_chunks_and_says_so() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    let pool = populated_and_striped(&roots, 2, 1);
    let striped = segment_ids_with_shards(a.path());
    assert!(!striped.is_empty());
    // Same bytes as f0: every chunk is a dedup hit against the stripes.
    let ino = pool.create_file(1, "again", 0o644).unwrap();
    pool.write(ino, 0, &payload(0)).unwrap();
    pool.fsync(ino).unwrap();
    // No checkpoint: replay is the only way this file comes back.
    drop(pool);

    // Lose a data shard of every stripe on whichever device holds it,
    // so whichever stripe f0's chunks landed in has to reconstruct.
    let mut victims = std::collections::BTreeSet::new();
    for &id in &striped {
        let holder = holder_of_shard0(&roots, id);
        std::fs::remove_file(lchfs_store::stripe::shard_path(holder, id, 0)).unwrap();
        victims.insert(roots.iter().position(|r| *r == holder).unwrap() as u16);
    }

    // By inode: the name is namespace state, which only a checkpoint
    // carries, as in failover.rs's delta replay test.
    let pool = Pool::open_replicated(&roots).unwrap();
    // Before any read: this is what the mount itself did.
    let stats = pool.repair_stats();
    assert!(stats.failovers > 0, "reconstruction at mount is not counted: {stats:?}");
    let events = pool.corruption_events();
    assert!(!events.is_empty(), "reconstruction at mount is not recorded");
    assert_eq!(pool.read(ino, 0, 30_000).unwrap().as_ref(), payload(0));
    for e in &events {
        assert!(victims.contains(&e.vdev_id), "{e:?} names a device that lost nothing");
        assert!(striped.contains(&e.location.unwrap().segment_id), "{e:?}");
        assert!(!e.healed, "{e:?}: a read never rebuilds a shard");
    }
    // Resilver puts every shard back; a remount then reconstructs nothing.
    for v in &victims {
        assert!(pool.resilver(*v).unwrap().shards_rebuilt > 0);
    }
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open_replicated(&roots).unwrap();
    assert_eq!(pool.read(ino, 0, 30_000).unwrap().as_ref(), payload(0));
    assert_eq!(pool.repair_stats().failovers, 0);
    assert!(pool.corruption_events().is_empty());
}

/// A copy healed onto a device that was away lives in a heal segment on
/// that device alone. Once the mirror it was healed from has been
/// striped away, that single copy is the record's preferred replica --
/// on a device that is not the primary. The reader used to take the
/// preferred location and open it on the primary regardless, so every
/// read of such a record missed, failed over, healed a copy the primary
/// did not need, and logged corruption against a device with nothing
/// wrong; fsck, from the other side, saw the mirror on one device and
/// not the others and did not credit the stripe that names them.
#[test]
fn a_heal_copy_that_outlives_its_striped_mirror_is_read_where_it_is() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    {
        let pool = Pool::create_replicated(&roots, striped_params(2, 1)).unwrap();
        pool.checkpoint().unwrap();
    }
    // c away: everything written now fans out to a and b only.
    {
        let pool = Pool::open_degraded(&[a.path(), b.path()]).unwrap();
        for i in 0..14u32 {
            let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
            pool.write(ino, 0, &payload(i)).unwrap();
        }
        pool.checkpoint().unwrap();
    }
    // c back: resilvered at mount into heal segments of its own. Then the
    // segments a and b hold go cold and are striped across all three.
    let pool = Pool::open_replicated(&roots).unwrap();
    assert!(pool.mount_resilver().iter().any(|(id, r)| *id == 2 && r.healed > 0));
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    pool.checkpoint().unwrap();
    let striped = segment_ids_with_shards(a.path());
    assert!(!striped.is_empty(), "no segment was converted");
    for id in &striped {
        assert!(!a.path().join(format!("segments/data/{id}.aseg")).exists());
    }
    drop(pool);

    // Cold: the cache is warmed from the index, where the heal copy on c
    // is the preferred replica of every record whose mirror was striped.
    let pool = Pool::open_replicated(&roots).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    let stats = pool.repair_stats();
    assert_eq!(stats.failovers, 0, "{stats:?}");
    assert_eq!(stats.heals, 0, "{stats:?}");
    assert!(pool.corruption_events().is_empty(), "{:?}", &pool.corruption_events()[..3]);
    // No heal segment appeared on the primary for records it holds in stripes.
    let heal_on_a: Vec<_> = aseg_files(a.path());
    pool.checkpoint().unwrap();
    drop(pool);
    assert_eq!(aseg_files(a.path()), heal_on_a);

    let fsck = lchfs_fsck::check_replicas(&roots);
    assert!(fsck.is_clean(), "{:?}", &fsck.errors[..fsck.errors.len().min(3)]);
}
