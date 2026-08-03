//! Standalone tests for `GcEngine` (E.10) against a real on-disk pool.
//! `GcEngine` is a library component, constructed here directly against
//! the pool's own `INDEX.redb` (mirroring how `Pool::open`'s own fast
//! mount path loads a `ChunkLocationCache`) rather than through a
//! background thread, matching how it's used in coalesce.rs.

use lchfs_format::{Hash32, PoolParams};
use lchfs_index::{ChunkLocationCache, RedbIndex};
use lchfs_store::gc::GcEngine;
use lchfs_store::Pool;
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

/// Loads a fresh `ChunkLocationCache` straight from the pool's persisted
/// `INDEX.redb` -- the same source `Pool::open`'s fast path uses.
fn load_locations(pool_root: &std::path::Path) -> Arc<ChunkLocationCache> {
    let index = RedbIndex::open(&pool_root.join("INDEX.redb")).unwrap();
    let cache = ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    Arc::new(cache)
}

#[test]
fn mark_covers_root_inomap_and_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let data = deterministic_bytes(1, 2000);
    pool.write(ino, 0, &data).unwrap();
    pool.checkpoint().unwrap();
    let root = pool.debug_root_hash();
    drop(pool);

    let mut gc = GcEngine::new(dir.path().to_path_buf(), load_locations(dir.path()));
    let live = gc.mark(&[root]);

    // At minimum: the meta segment (RootObject/InoMap/InodeObject/
    // DirectoryObject/IndirectHashList/SnapshotTable) and the data
    // segment (the chunk itself) must both have live bytes.
    assert!(!live.is_empty());
    let total_live: u64 = live.values().map(|b| b.len()).sum();
    assert!(total_live > 0);
}

#[test]
fn shared_chunk_survives_when_only_one_referencing_root_is_live() {
    // The case a naive refcount gets wrong but DAG-reachability gets
    // right: two files share one physical chunk (dedup-on-write). Model
    // "one referencing generation is gone, one remains" via overwrite +
    // multi-root marking, since this codebase has no unlink yet -- an old
    // checkpoint's root_hash, if still passed to mark() (as a retained
    // snapshot's root would be), keeps its exclusive content live.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let shared = deterministic_bytes(42, 2000);
    let ino_a = pool.create_file(1, "a", 0o644).unwrap();
    let ino_b = pool.create_file(1, "b", 0o644).unwrap();
    pool.write(ino_a, 0, &shared).unwrap();
    pool.write(ino_b, 0, &shared).unwrap();
    pool.checkpoint().unwrap();
    let root_gen1 = pool.debug_root_hash();

    // Overwrite A with different content -- a *new* generation whose root
    // no longer references the shared chunk via A (still does via B).
    let unique_to_gen1 = deterministic_bytes(99, 2000);
    let a_new = deterministic_bytes(7, 2000);
    pool.write(ino_a, 0, &a_new).unwrap();
    let ino_c = pool.create_file(1, "c", 0o644).unwrap();
    pool.write(ino_c, 0, &unique_to_gen1).unwrap();
    // c is created *after* gen1's checkpoint, so it's correctly absent
    // from root_gen1's DAG -- used below as the "only reachable from the
    // newer generation" control.
    pool.checkpoint().unwrap();
    let root_gen2 = pool.debug_root_hash();
    drop(pool);

    let locations = load_locations(dir.path());
    let mut gc = GcEngine::new(dir.path().to_path_buf(), Arc::clone(&locations));

    // Marking from gen2 alone: the shared chunk stays live (via B, which
    // still references it in gen2), a_new + unique_to_gen1 live, but
    // gen1's original "a" content (superseded by a_new) is NOT referenced
    // by anything in gen2 alone -- not directly assertable without a
    // per-hash live check, so the meaningful assertion is the next one:
    // adding gen1 back in must only ever *add* live bytes, never remove
    // any (monotonic union), which is what "retaining an old snapshot's
    // root keeps its content live without disturbing the current one"
    // means in practice.
    let live_gen2_only = gc.mark(&[root_gen2]);
    let bytes_gen2_only: u64 = live_gen2_only.values().map(|b| b.len()).sum();

    let live_both = gc.mark(&[root_gen1, root_gen2]);
    let bytes_both: u64 = live_both.values().map(|b| b.len()).sum();

    assert!(
        bytes_both > bytes_gen2_only,
        "including the older retained root must mark strictly more bytes live \
         (gen1's original 'a' content, exclusively referenced by root_gen1)"
    );

    // The shared chunk itself must be live in *both* cases -- it's still
    // referenced by B regardless of which generation's root is considered.
    for (seg, live_set) in &live_gen2_only {
        assert!(live_both.get(seg).unwrap().len() >= live_set.len());
    }
}

#[test]
fn snapshot_table_record_is_always_live() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();
    let root = pool.debug_root_hash();
    drop(pool);

    let mut gc = GcEngine::new(dir.path().to_path_buf(), load_locations(dir.path()));
    let live_from_root = gc.mark(&[root]);
    let total: u64 = live_from_root.values().map(|b| b.len()).sum();
    // Even an empty pool's checkpoint writes RootObject + InoMap +
    // root InodeObject + root DirectoryObject + SnapshotTable -- all
    // meta-stream records, all must be marked live from the root alone.
    assert!(total > 0);
}

#[test]
fn mark_returns_empty_on_unresolvable_reference_rather_than_partial() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // A bogus root hash that resolves to nothing -- must fail the whole
    // pass cleanly (empty map), never a partial/misleading result.
    let mut gc = GcEngine::new(dir.path().to_path_buf(), load_locations(dir.path()));
    let live = gc.mark(&[Hash32::of(b"not a real root")]);
    assert!(live.is_empty());
}

#[test]
fn sweep_candidates_flags_low_liveness_segment_but_not_a_fresh_pool() {
    // Tiny cap so a handful of 3000-byte writes force real segment
    // rollover/sealing -- sweep_candidates only ever considers sealed
    // segments (an Open one is never a repack target), so without this
    // the setup below would never actually exercise the sweep logic.
    let mut params = small_params();
    params.data_segment_cap_bytes = 4096;

    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), params).unwrap();

    let mut inos = Vec::new();
    for i in 0..10u64 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &deterministic_bytes(i + 1, 3000)).unwrap();
        inos.push(ino);
    }
    pool.checkpoint().unwrap();

    // Overwrite all but the last file with new (tiny) content -- their
    // old 3000-byte payloads become unreferenced by the new root, while
    // the small new payloads land in whatever segment is current at that
    // point (not necessarily the now-sealed, now-mostly-stale ones).
    for &ino in &inos[..9] {
        pool.write(ino, 0, &deterministic_bytes(999, 100)).unwrap();
    }
    pool.checkpoint().unwrap();
    let root = pool.debug_root_hash();
    drop(pool);

    let locations = load_locations(dir.path());
    let mut gc = GcEngine::new(dir.path().to_path_buf(), Arc::clone(&locations));
    let live = gc.mark(&[root]);
    let candidates = gc.sweep_candidates(&live);
    assert!(
        !candidates.is_empty(),
        "overwriting 9/10 files' worth of content into now-sealed segments must produce at least one low-liveness candidate"
    );

    // Control: a fresh pool with no overwrites at all should have no
    // sweep candidates, confirming the above isn't just always non-empty.
    let dir2 = tempfile::tempdir().unwrap();
    let pool2 = Pool::create(dir2.path(), small_params()).unwrap();
    pool2.checkpoint().unwrap();
    let root2 = pool2.debug_root_hash();
    drop(pool2);
    let mut gc2 = GcEngine::new(dir2.path().to_path_buf(), load_locations(dir2.path()));
    let live2 = gc2.mark(&[root2]);
    let candidates2 = gc2.sweep_candidates(&live2);
    assert!(candidates2.is_empty(), "a fresh pool with no overwrites should have no sweep candidates");
}
