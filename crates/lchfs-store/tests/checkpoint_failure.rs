//! A checkpoint that fails part-way must not forget what it was asked to
//! publish. Its own test binary: the failpoint is process-global, and a
//! parallel test's checkpoint would otherwise be the one to trip it.

use lchfs_format::PoolParams;
use lchfs_store::Pool;
use lchfs_store::segment::fault_injection;

fn params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

#[test]
fn a_failed_checkpoint_leaves_its_dirty_inodes_for_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 251) as u8).collect();
    pool.write(ino, 0, &data).unwrap();

    // The checkpoint takes the dirty set and then fails. The one after it
    // succeeds -- and used to publish nothing for `f`, because the failed
    // one had already emptied the set.
    fault_injection::fail_next_checkpoint();
    assert!(pool.checkpoint().is_err(), "the failpoint must fire");
    pool.checkpoint().unwrap();

    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().expect("f survives");
    assert_eq!(pool.read(ino, 0, data.len() as u32).unwrap().as_ref(), data.as_slice());
}
