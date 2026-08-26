//! Crash-recovery coverage for the Phase 2 features (xattrs, ACL storage,
//! sparse files/fallocate) against the two-tier recovery of ARCHITECTURE.md
//! §7.
//!
//! This file exists because of a specific past bug: a replayed inode's
//! `IndirectHashList` was never re-registered into the global index after
//! crash recovery, so the background GC mark pass aborted on every pass
//! forever after any crash+remount. No unit test caught it, because none
//! combined "crash recovery" with "GC afterwards" in one scenario. Every new
//! feature that touches `InodeObject` or the chunk list deserves that
//! combination, so it is what these tests do.
//!
//! "Crash" here is `drop(pool)` with no checkpoint, matching
//! `crash_recovery.rs`: whatever survives must have come through delta-log
//! replay, not a clean shutdown.

use lchfs_format::{ContentRef, PoolParams};
use lchfs_index::{ChunkLocationCache, PendingDedupPins, RedbIndex};
use lchfs_store::gc::GcEngine;
use lchfs_store::{FallocateMode, Pool, XattrSetFlags};
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 256 * 1024,
        meta_segment_cap_bytes: 256 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 8,
    }
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as u8);
    }
    out
}

/// Runs a real GC mark pass over the recovered root. The assertion that
/// matters is that it completes at all -- an unresolvable hash makes
/// `walk_reachable` bail, which is how the original post-crash GC bug
/// manifested.
fn gc_marks_cleanly(pool_root: &std::path::Path, root: lchfs_format::Hash32) -> bool {
    let index = RedbIndex::open(&pool_root.join("INDEX.redb")).unwrap();
    let cache = ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    let mut gc = GcEngine::new(
        pool_root.to_path_buf(),
        Arc::new(cache),
        Arc::new(PendingDedupPins::new()),
    );
    !gc.mark(&[root]).is_empty()
}

#[test]
fn xattrs_survive_a_crash_after_fsync() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(2, 5000)).unwrap();
    pool.set_xattr(ino, "user.survives", b"yes", XattrSetFlags::None).unwrap();
    pool.checkpoint().unwrap();

    // Second attribute set after the last checkpoint, made durable only by
    // fsync -- so recovery has to come from delta-log replay.
    pool.set_xattr(ino, "user.after_ckpt", b"also", XattrSetFlags::None).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.get_xattr(ino, "user.survives").unwrap(), b"yes");
    assert_eq!(
        pool.get_xattr(ino, "user.after_ckpt").unwrap(),
        b"also",
        "an fsync after setting an xattr must make it durable"
    );
}

#[test]
fn a_punched_hole_survives_a_crash_after_fsync() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(3, 40_000);
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();

    pool.fallocate(ino, 10_000, 15_000, FallocateMode::PunchHole).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    let mut expected = content.clone();
    expected[10_000..25_000].fill(0);
    assert_eq!(&pool.read(ino, 0, 40_000).unwrap()[..], &expected[..]);
    assert_eq!(pool.getattr(ino).unwrap().size, 40_000);
}

/// The bug-#6 shape, applied to sparse files: crash, recover, then run a GC
/// mark pass. A replayed sparse inode's IndirectHashList must be resolvable
/// from the global index, or GC aborts on every pass from then on.
#[test]
fn gc_still_marks_cleanly_after_recovering_a_sparse_file() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(5, 50_000)).unwrap();
    pool.checkpoint().unwrap();

    pool.fallocate(ino, 5_000, 30_000, FallocateMode::PunchHole).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);

    // Recover, then force the checkpoint that re-registers replayed inodes.
    let pool = Pool::open(dir.path()).unwrap();
    pool.checkpoint().unwrap();
    let root = pool.debug_root_hash();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    // Content must still be right after recovery + checkpoint.
    assert!(pool.read(ino, 6_000, 1_000).unwrap().iter().all(|&b| b == 0));
    drop(pool);

    assert!(
        gc_marks_cleanly(dir.path(), root),
        "GC mark aborted after recovering a sparse file -- the post-crash \
         IndirectHashList is not resolvable through the global index"
    );
}

/// Same combination for xattrs: they live inside `InodeObject`, which the
/// recovery path rewrites, so a malformed or lost blob would surface here.
#[test]
fn gc_still_marks_cleanly_after_recovering_xattrs() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(7, 20_000)).unwrap();
    pool.set_xattr(ino, "user.a", b"1", XattrSetFlags::None).unwrap();
    pool.checkpoint().unwrap();

    pool.set_xattr(ino, "user.b", &vec![0xCDu8; 4096], XattrSetFlags::None).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    pool.checkpoint().unwrap();
    let root = pool.debug_root_hash();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.get_xattr(ino, "user.b").unwrap().len(), 4096);
    drop(pool);

    assert!(gc_marks_cleanly(dir.path(), root), "GC mark aborted after recovering xattrs");
}

/// A file that is entirely a hole has an empty chunk list. Recovery, fsck and
/// GC all have to cope with a chunked inode that references no extents at
/// all, which is a shape none of them could previously encounter.
#[test]
fn a_wholly_sparse_file_survives_crash_and_fsck() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(11, 30_000)).unwrap();
    pool.checkpoint().unwrap();

    pool.fallocate(ino, 0, 30_000, FallocateMode::PunchHole).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.getattr(ino).unwrap().size, 30_000);
    assert!(pool.read(ino, 0, 30_000).unwrap().iter().all(|&b| b == 0));
    pool.checkpoint().unwrap();
    drop(pool);

    let roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &roots);
    assert!(report.is_clean(), "fsck errors: {:?}", report.errors);
}

/// Recovery must not resurrect a hole that was refilled, nor lose one that
/// was punched, when both happen between checkpoints.
#[test]
fn punch_then_refill_before_a_crash_recovers_the_refilled_content() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(13, 30_000);
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();

    pool.fallocate(ino, 8_000, 10_000, FallocateMode::PunchHole).unwrap();
    let patch = deterministic_bytes(17, 4_000);
    pool.write(ino, 9_000, &patch).unwrap();
    pool.fsync(ino).unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    let mut expected = content.clone();
    expected[8_000..18_000].fill(0);
    expected[9_000..13_000].copy_from_slice(&patch);
    assert_eq!(&pool.read(ino, 0, 30_000).unwrap()[..], &expected[..]);
}

/// Sanity: an inode whose content is entirely holes should still be a
/// ChunkList (not silently collapsed to inline), because its size is well
/// above `inline_threshold` -- inline would misreport a 30 KB file as a few
/// bytes of embedded content.
#[test]
fn a_wholly_sparse_file_stays_chunked_not_inline() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(19, 30_000)).unwrap();
    pool.fallocate(ino, 0, 30_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();

    match pool.getattr(ino).unwrap().content {
        ContentRef::ChunkList(_) => {}
        other => panic!("expected ChunkList for a 30KB sparse file, got {other:?}"),
    }
}
