//! Tests for the `<pool_root>/LOCK` advisory single-writer guard
//! (ARCHITECTURE.md §1's pool layout). Designed in Phase 1 and never built
//! until now: before this, two `Pool::open` calls on one directory -- two
//! `lchfs mount` processes, or a mount racing `lchfs stats`/`snapshot`,
//! each of which opens its own `Pool` with its own background checkpoint,
//! coalesce and dedup threads -- would both succeed and write concurrently.

use lchfs_format::PoolParams;
use lchfs_store::{Pool, PoolError};

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

#[test]
fn create_leaves_the_lock_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    assert!(dir.path().join("LOCK").exists());
    drop(pool);
}

/// `flock(2)` is held by the open file description, not the process, so a
/// second `Pool` in this same test process conflicts exactly as a second
/// process would. That is what makes this testable in-process at all.
#[test]
fn second_open_while_first_is_live_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let first = Pool::create(dir.path(), small_params()).unwrap();

    let second = Pool::open(dir.path());
    assert!(
        matches!(second, Err(PoolError::PoolLocked(_))),
        "expected PoolLocked, got {second:?}"
    );
    drop(first);
}

/// The guard must not be permanent: dropping the `Pool` has to release it,
/// or an ordinary unmount-then-remount would wedge the pool forever.
#[test]
fn lock_is_released_when_the_pool_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"content").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let reopened = Pool::open(dir.path()).expect("lock should be free after drop");
    let ino = reopened.lookup(1, "f").unwrap().unwrap();
    assert_eq!(&reopened.read(ino, 0, 7).unwrap()[..], b"content");
}

/// Repeated open/drop cycles must keep working -- catches a guard that is
/// acquired but never actually released (e.g. a leaked fd).
#[test]
fn lock_can_be_reacquired_repeatedly() {
    let dir = tempfile::tempdir().unwrap();
    drop(Pool::create(dir.path(), small_params()).unwrap());
    for _ in 0..5 {
        let pool = Pool::open(dir.path()).expect("each cycle should reacquire cleanly");
        drop(pool);
    }
}

/// `create` takes the lock too, not just `open` -- otherwise a `create-pool`
/// against a directory a mount already holds would scribble over it.
#[test]
fn create_against_a_locked_pool_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let first = Pool::create(dir.path(), small_params()).unwrap();

    let second = Pool::create(dir.path(), small_params());
    assert!(
        matches!(second, Err(PoolError::PoolLocked(_))),
        "expected PoolLocked, got {second:?}"
    );
    drop(first);
}

/// A leftover `LOCK` file from a previous run is not itself a lock -- only a
/// live `flock` held by a running process is. The kernel drops the lock when
/// that process dies, so a crashed mount must not wedge the pool. Simulated
/// here by leaving the file in place across a clean drop, which is the same
/// on-disk state a killed process leaves behind.
#[test]
fn a_leftover_lock_file_does_not_wedge_the_pool() {
    let dir = tempfile::tempdir().unwrap();
    drop(Pool::create(dir.path(), small_params()).unwrap());
    assert!(dir.path().join("LOCK").exists(), "LOCK file should persist on disk");

    Pool::open(dir.path()).expect("a stale LOCK file must not block reopening");
}

/// The lock must not interfere with fsck, which deliberately never opens a
/// `Pool` (it is a one-shot read-only diagnostic and must stay usable
/// against a pool that is currently mounted).
#[test]
fn fsck_still_works_while_a_pool_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"content").unwrap();
    pool.checkpoint().unwrap();

    // Pool deliberately still held/live here.
    let roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &roots);
    assert!(report.is_clean(), "fsck errors: {:?}", report.errors);
    drop(pool);
}

/// `--rebuild-index` is the one fsck path that writes (it rewrites, and may
/// delete and recreate, INDEX.redb), so unlike the read-only checks it must
/// refuse to run against a pool something else holds open.
#[test]
fn fsck_rebuild_index_is_refused_while_a_pool_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();

    let result = lchfs_fsck::rebuild_index(dir.path());
    assert!(
        matches!(result, Err(lchfs_fsck::FsckError::PoolLocked(_))),
        "expected PoolLocked, got {result:?}"
    );
    drop(pool);

    // ...and succeeds once the pool is released.
    lchfs_fsck::rebuild_index(dir.path()).expect("rebuild should work once unlocked");
}
