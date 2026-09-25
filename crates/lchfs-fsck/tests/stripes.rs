//! fsck against erasure-coded segments (ARCHITECTURE.md §17.2.4): a
//! striped pool checks clean when every device is given, one device
//! alone is honestly short, a missing or corrupt shard is a finding and
//! is rebuilt from its siblings, parity that disagrees with the data is
//! caught even when every file's own hash is right, and an index rebuilt
//! by fsck carries the striped entries the mount needs.

use lchfs_format::{Hash32, PoolParams, STRIPE_DESCRIPTOR_OFFSET, StripeDescriptor};
use lchfs_fsck::FsckError;
use lchfs_store::Pool;
use lchfs_store::stripe::{segment_ids_with_shards, shard_path, shards_on};
use std::path::Path;

fn striped_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 16 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: 2,
        stripe_m: 1,
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

/// A three-device pool with cold segments converted to 2+1 stripes,
/// checkpointed and closed.
fn striped_pool(roots: &[&Path]) -> Vec<u64> {
    let pool = Pool::create_replicated(roots, striped_params()).unwrap();
    for i in 0..14u32 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(i)).unwrap();
    }
    pool.checkpoint().unwrap();
    for _ in 0..8 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    pool.checkpoint().unwrap();
    drop(pool);
    let striped = segment_ids_with_shards(roots[0]);
    assert!(!striped.is_empty(), "nothing was striped");
    striped
}

fn all_clean(roots: &[&Path]) {
    let live = lchfs_fsck::collect_live_roots(roots[0]).unwrap();
    let walk = lchfs_fsck::check_devices(roots, &live);
    assert!(walk.is_clean(), "walk: {:?}", walk.errors);
    let replicas = lchfs_fsck::check_replicas(roots);
    assert!(replicas.is_clean(), "replicas: {:?}", replicas.errors);
    let index = lchfs_fsck::verify_index_devices(roots, &live);
    assert!(index.is_clean(), "index: {:?}", index.errors);
}

#[test]
fn a_striped_pool_checks_clean_with_every_device_and_honestly_short_with_one() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    let striped = striped_pool(&roots);
    all_clean(&roots);

    // Every striped record was reached through its shards.
    let live = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let walk = lchfs_fsck::check_devices(&roots, &live);
    let stripes_only = lchfs_fsck::check_stripes(&roots);
    assert!(stripes_only.is_clean(), "{:?}", stripes_only.errors);
    assert!(stripes_only.objects_visited > 0);
    assert!(walk.objects_visited >= stripes_only.objects_visited);

    // One device alone holds one shard of each stripe: fsck says so
    // rather than pretending the data is there.
    let alone = lchfs_fsck::check(a.path(), &live);
    assert!(!alone.is_clean());
    let short: Vec<u64> = alone
        .errors
        .iter()
        .filter_map(|e| match e {
            FsckError::StripeUnrecoverable { segment_id, readable: 1, needed: 2 } => Some(*segment_id),
            _ => None,
        })
        .collect();
    assert_eq!(short, striped);
    assert!(alone.errors.iter().any(|e| matches!(e, FsckError::MissingObject { .. })));
}

#[test]
fn a_missing_shard_is_reported_and_rebuilt() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    let striped = striped_pool(&roots);

    let lost = striped[0];
    let index = shards_on(c.path(), lost)[0];
    std::fs::remove_file(shard_path(c.path(), lost, index)).unwrap();

    let live = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::check_devices(&roots, &live);
    assert_eq!(report.errors.len(), 1, "the stripe is short but every record still reads: {:?}", report.errors);
    assert!(
        matches!(&report.errors[0], FsckError::StripeShardMissing { segment_id, shard_index, vdev_id: 2 } if *segment_id == lost && *shard_index == index),
        "{:?}",
        report.errors
    );
    let replicas = lchfs_fsck::check_replicas(&roots);
    assert!(
        replicas.errors.iter().any(|e| matches!(e, FsckError::StripeShardMissing { segment_id, .. } if *segment_id == lost)),
        "{:?}",
        replicas.errors
    );

    let rebuilt = lchfs_fsck::rebuild_shards(&roots).unwrap();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!((rebuilt[0].segment_id, rebuilt[0].shard_index, rebuilt[0].vdev_id), (lost, index, 2));
    all_clean(&roots);

    // And the engine reads the rebuilt shard like any other.
    let pool = Pool::open_replicated(&roots).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.repair_stats().failovers, 0);
}

#[test]
fn a_corrupt_shard_is_reported_and_rebuilt() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    let striped = striped_pool(&roots);

    let hit = striped[1];
    let index = shards_on(b.path(), hit)[0];
    let path = shard_path(b.path(), hit, index);
    let mut bytes = std::fs::read(&path).unwrap();
    let n = bytes.len();
    for x in &mut bytes[n - 100..n - 40] {
        *x ^= 0x5a;
    }
    std::fs::write(&path, &bytes).unwrap();

    let report = lchfs_fsck::check_stripes(&roots);
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert!(
        matches!(&report.errors[0], FsckError::StripeShardCorrupt { segment_id, shard_index, vdev_id: 1, .. } if *segment_id == hit && *shard_index == index),
        "{:?}",
        report.errors
    );

    let rebuilt = lchfs_fsck::rebuild_shards(&roots).unwrap();
    assert_eq!(rebuilt.len(), 1);
    assert_eq!(rebuilt[0].vdev_id, 1);
    all_clean(&roots);
}

/// Rewrites a parity shard so its contents no longer follow from the data
/// shards, but fixes its descriptor's `shard_hash` to match the new
/// bytes -- the case no per-file check can see.
#[test]
fn parity_that_disagrees_with_the_data_is_caught() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    let striped = striped_pool(&roots);

    let hit = striped[0];
    // Shard 2 is the parity shard of a 2+1 stripe; find whose it is.
    let (root, index) = roots
        .iter()
        .flat_map(|r| shards_on(r, hit).into_iter().map(move |i| (*r, i)))
        .find(|(_, i)| *i == 2)
        .expect("a parity shard");
    let path = shard_path(root, hit, index);
    let mut file = std::fs::read(&path).unwrap();
    let page = 4096usize;
    for x in &mut file[page + 10..page + 30] {
        *x ^= 0xff;
    }
    let at = STRIPE_DESCRIPTOR_OFFSET;
    let len = u32::from_le_bytes(file[at..at + 4].try_into().unwrap()) as usize;
    let mut desc: StripeDescriptor = lchfs_format::decode(&file[at + 4..at + 4 + len]).unwrap();
    desc.shard_hash = Hash32::of(&file[page..]);
    let encoded = lchfs_format::encode(&desc).unwrap();
    assert_eq!(encoded.len(), len, "the descriptor re-encodes to the same size");
    file[at + 4..at + 4 + len].copy_from_slice(&encoded);
    std::fs::write(&path, &file).unwrap();

    let report = lchfs_fsck::check_stripes(&roots);
    assert!(
        report.errors.iter().any(|e| matches!(e, FsckError::StripeInconsistent { segment_id, detail } if *segment_id == hit && detail.contains("parity"))),
        "{:?}",
        report.errors
    );
    assert!(
        !report.errors.iter().any(|e| matches!(e, FsckError::StripeShardCorrupt { .. })),
        "the per-file hash was made to agree: {:?}",
        report.errors
    );
}

#[test]
fn a_rebuilt_index_carries_the_striped_entries() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path(), c.path()];
    striped_pool(&roots);

    lchfs_index::RedbIndex::remove(a.path()).unwrap();
    lchfs_fsck::rebuild_index(a.path(), &[b.path(), c.path()]).unwrap();
    let live = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let report = lchfs_fsck::verify_index_devices(&roots, &live);
    assert!(report.is_clean(), "{:?}", report.errors);

    // The fast mount path trusts that index: every file reads, nothing
    // fails over.
    let pool = Pool::open_replicated(&roots).unwrap();
    for i in 0..14u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert_eq!(pool.repair_stats().failovers, 0);
}
