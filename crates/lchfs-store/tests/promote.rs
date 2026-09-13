//! Losing the primary while mounted (§16.1's single point of failure).
//!
//! The index is a rebuildable cache (§4). When the device holding it
//! faults, the lowest online device is promoted, an index is rebuilt onto
//! it from every online device, and the pool carries on -- writes included.
//! The failover task does this within a second on its own; the tests call
//! it directly so they are not racing a timer.

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

/// The primary's device fails under the pool. (Fault injection fails its
/// segment operations; the index file on it stays writable in this test,
/// which is the kinder case -- with a truly dead disk every write errors
/// until the promotion, and none after it.)
#[test]
fn a_dead_primary_is_replaced_and_the_pool_keeps_writing() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "before", 0o644).unwrap();
    pool.write(ino, 0, &payload(1)).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(pool.primary_vdev(), 0);

    fault_injection::kill(a.path());
    // The fault is noticed by the first write to trip over it.
    let ino2 = pool.create_file(1, "tripped", 0o644).unwrap();
    let _ = pool.write(ino2, 0, &payload(2));
    assert_eq!(health(&pool, 0), VdevHealth::Faulted);
    assert!(pool.primary_faulted());

    let promoted = pool.promote_primary().unwrap();
    assert_eq!(promoted, 1);
    assert_eq!(pool.primary_vdev(), 1);
    assert!(!pool.primary_faulted());
    assert!(b.path().join("INDEX.redb").exists(), "the index was rebuilt on the new primary");
    assert_eq!(pool.repair_stats().promotions, 1);

    // Writes succeed again, and land on b alone.
    let ino3 = pool.create_file(1, "after", 0o644).unwrap();
    pool.write(ino3, 0, &payload(3)).unwrap();
    pool.checkpoint().unwrap();
    assert_eq!(read_file(&pool, "before", 30_000), payload(1));
    assert_eq!(read_file(&pool, "after", 30_000), payload(3));
    drop(pool);
    fault_injection::revive(a.path());

    // Remount: a is lowest, so it is primary again -- with a stale index
    // and a stale superblock. Its index is rebuilt and it is resilvered.
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(pool.primary_vdev(), 0);
    let [(0, r)] = pool.mount_resilver() else { panic!("{:?}", pool.mount_resilver()) };
    assert!(r.healed > 0 && r.unrecoverable.is_empty(), "{r:?}");
    assert_eq!(read_file(&pool, "after", 30_000), payload(3));
    pool.checkpoint().unwrap();
    drop(pool);
    let report = lchfs_fsck::check_replicas(&[a.path(), b.path()]);
    assert!(report.is_clean(), "{:?}", report.errors);
}

/// The failover task does the promotion on its own.
#[test]
fn the_failover_task_promotes_without_being_asked() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &payload(4)).unwrap();
    fault_injection::kill(a.path());
    let _ = pool.write(ino, 0, &payload(5));
    assert!(pool.primary_faulted());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.primary_faulted() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(pool.primary_vdev(), 1, "the failover task should have promoted vdev 1");
    let ino2 = pool.create_file(1, "g", 0o644).unwrap();
    pool.write(ino2, 0, &payload(6)).unwrap();
    fault_injection::revive(a.path());
}

/// Reads keep working across the promotion: what the cache held for the
/// old primary is thrown away and refilled from the new index.
#[test]
fn reads_follow_the_new_primary() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let mut files = Vec::new();
    for i in 0..5u32 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(10 + i)).unwrap();
        files.push(ino);
    }
    pool.checkpoint().unwrap();
    // Push the working state out so reads go to segments.
    drop(pool);
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    fault_injection::kill(a.path());
    let ino = pool.create_file(1, "trip", 0o644).unwrap();
    let _ = pool.write(ino, 0, &payload(99));
    pool.promote_primary().unwrap();
    let before = pool.repair_stats();
    for (i, ino) in files.iter().enumerate() {
        assert_eq!(pool.read(*ino, 0, 30_000).unwrap(), payload(10 + i as u32));
    }
    assert_eq!(
        pool.repair_stats().failovers,
        before.failovers,
        "reads after promotion should hit the new primary, not fail over"
    );
    fault_injection::revive(a.path());
}

#[test]
fn promotion_is_refused_while_the_primary_is_healthy() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
    let err = pool.promote_primary().unwrap_err().to_string();
    assert!(err.contains("has not faulted"), "{err}");
    assert_eq!(pool.primary_vdev(), 0);
    let _ = Path::new("");
}
