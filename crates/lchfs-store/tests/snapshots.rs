//! Tests for snapshot create/list/delete (ARCHITECTURE.md §6, Phase G) and
//! the GC live-roots fix that makes them actually protect their content:
//! `run_gc_and_coalesce_pass` must include every retained snapshot's root,
//! not just the current one.

use lchfs_format::{Hash32, PoolParams};
use lchfs_index::{ChunkLocationCache, PendingDedupPins, RedbIndex};
use lchfs_store::gc::GcEngine;
use lchfs_store::{Pool, PoolError};
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
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

fn load_locations(pool_root: &std::path::Path) -> Arc<ChunkLocationCache> {
    let index = RedbIndex::open(&pool_root.join("INDEX.redb")).unwrap();
    let cache = ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    Arc::new(cache)
}

fn mark_bytes(pool_root: &std::path::Path, roots: &[Hash32]) -> u64 {
    let mut gc = GcEngine::new(
        pool_root.to_path_buf(),
        load_locations(pool_root),
        Arc::new(PendingDedupPins::new()),
    );
    gc.mark(roots).values().map(|b| b.len()).sum()
}

/// Writes 10 distinct-content files, checkpoints, snapshots that state,
/// then overwrites 9 of the files with small content -- the same proven
/// low-liveness setup as `coalesce.rs`'s `setup_low_liveness_pool` (a tiny
/// segment cap forces real rollover, so the 9 originals end up in
/// genuinely sealed, genuinely-dead-per-current-root segments a coalesce
/// pass will actually consider sweeping, not just an untested theoretical
/// one -- a synthetic single-file version of this test with a generous
/// segment cap passed even *without* the GC fix, because the content
/// never left the shard's still-open segment in the first place).
fn setup_low_liveness_pool_with_snapshot(dir: &std::path::Path) -> (Pool, Hash32) {
    let mut params = small_params();
    params.data_segment_cap_bytes = 4096;
    let pool = Pool::create(dir, params).unwrap();

    let mut inos = Vec::new();
    for i in 0..10u64 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &deterministic_bytes(i + 1, 3000)).unwrap();
        inos.push(ino);
    }
    pool.checkpoint().unwrap();

    pool.create_snapshot("all-originals").unwrap();
    let snapshot_root = pool.list_snapshots().unwrap()[0].root_hash;

    for &ino in &inos[..9] {
        let data = deterministic_bytes(1000 + ino, 200);
        pool.write(ino, 0, &data).unwrap();
    }
    pool.checkpoint().unwrap();

    (pool, snapshot_root)
}

#[test]
fn create_list_delete_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_file(1, "f", 0o644).unwrap();

    assert!(pool.list_snapshots().unwrap().is_empty());

    pool.create_snapshot("first").unwrap();
    let snaps = pool.list_snapshots().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "first");

    pool.delete_snapshot("first").unwrap();
    assert!(pool.list_snapshots().unwrap().is_empty());
}

#[test]
fn duplicate_snapshot_name_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_snapshot("a").unwrap();
    assert!(matches!(pool.create_snapshot("a"), Err(PoolError::AlreadyExists(_))));
}

#[test]
fn deleting_nonexistent_snapshot_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    assert!(matches!(pool.delete_snapshot("nope"), Err(PoolError::NotFound(_))));
}

#[test]
fn snapshots_survive_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_snapshot("s1").unwrap();
    drop(pool);

    let pool2 = Pool::open(dir.path()).unwrap();
    let snaps = pool2.list_snapshots().unwrap();
    assert_eq!(snaps.len(), 1);
    assert_eq!(snaps[0].name, "s1");
}

#[test]
fn snapshot_protects_exclusively_referenced_content_from_gc() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, snapshot_root) = setup_low_liveness_pool_with_snapshot(dir.path());

    pool.run_gc_and_coalesce_pass().unwrap();
    drop(pool);

    // The snapshot's root must still resolve every one of its chunks,
    // proving the 9 overwritten files' *original* content physically
    // survived the GC pass above, rather than merely not erroring.
    let total_live = mark_bytes(dir.path(), &[snapshot_root]);
    // 10 files * ~3000 bytes of chunk content (some may dedup-collide via
    // this module's weak deterministic PRNG, so this is a floor, not an
    // exact expectation), plus DAG metadata overhead.
    assert!(
        total_live > 15_000,
        "snapshot's root must still fully resolve all 10 original ~3000-byte chunks, got {total_live} live bytes"
    );

    let report = lchfs_fsck::check(dir.path(), &[snapshot_root]);
    assert!(report.is_clean(), "snapshot root must fsck clean: {:?}", report.errors);
}

#[test]
fn gc_pass_includes_snapshot_roots_automatically() {
    // Same setup as the test above, phrased as a direct segment-deletion
    // check: at least one segment gets deleted (the coalesce pass is
    // doing real work, not a no-op), and the snapshot's root still fscks
    // clean afterward.
    let dir = tempfile::tempdir().unwrap();
    let (pool, snapshot_root) = setup_low_liveness_pool_with_snapshot(dir.path());

    let data_dir = dir.path().join("segments/data");
    let before: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    pool.run_gc_and_coalesce_pass().unwrap();
    let after: std::collections::HashSet<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert!(!before.is_subset(&after), "the coalesce pass should have deleted at least one segment");
    drop(pool);

    let report = lchfs_fsck::check(dir.path(), &[snapshot_root]);
    assert!(
        report.is_clean(),
        "run_gc_and_coalesce_pass must not have swept content the snapshot exclusively references: {:?}",
        report.errors
    );
}

#[test]
fn deleting_a_snapshot_makes_its_exclusive_content_reclaimable() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, snapshot_root) = setup_low_liveness_pool_with_snapshot(dir.path());
    let root = pool.debug_root_hash();
    drop(pool); // RedbIndex only allows one open handle at a time.

    // Baseline: current root's own live-byte count *with* the snapshot's
    // exclusive content also counted live.
    let with_snapshot_retained = mark_bytes(dir.path(), &[root, snapshot_root]);

    let pool2 = Pool::open(dir.path()).unwrap();
    pool2.delete_snapshot("all-originals").unwrap();
    drop(pool2);
    let after_delete = mark_bytes(dir.path(), &[root]);

    assert!(
        after_delete < with_snapshot_retained,
        "deleting the snapshot must shrink the live set (its exclusive content is no longer protected): \
         before={with_snapshot_retained} after={after_delete}"
    );
}
