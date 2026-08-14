//! Targeted tests for the E.12 `DedupScanner`, driven through `Pool`'s
//! public `run_dedup_pass()`. Since this codebase's committer pool
//! already checks the dedup index inline (prep.rs), the race the scanner
//! exists to catch (two shards committing byte-identical *new* content in
//! the same epoch, neither seeing the other's not-yet-indexed write)
//! isn't reliably reproducible via real concurrent writes -- so this uses
//! `Pool::debug_force_duplicate_chunk`, a deterministic bypass of the
//! inline check, to construct the exact race outcome directly.

use lchfs_format::PoolParams;
use lchfs_store::Pool;

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

#[test]
fn scanner_converges_a_forced_duplicate_to_one_canonical_location() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let shared = deterministic_bytes(1, 2000);

    // File A writes the shared content normally (goes through the real
    // inline dedup-checked path, becomes the index's current entry).
    let ino_a = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(ino_a, 0, &shared).unwrap();
    pool.checkpoint().unwrap();

    // Force a second, genuinely duplicate physical copy of the exact same
    // bytes -- bypassing the inline check, simulating the race.
    let loser_loc = pool.debug_force_duplicate_chunk(&shared).unwrap();

    // File B references the same content too (via the normal path, which
    // -- since the index still points at the original, not this forced
    // duplicate -- resolves to the *original* location, same as A).
    let ino_b = pool.create_file(1, "b", 0o644).unwrap();
    pool.write(ino_b, 0, &shared).unwrap();
    pool.checkpoint().unwrap();

    let merges = pool.run_dedup_pass().unwrap();
    let hash = lchfs_format::Hash32::of(&shared);
    let relevant: Vec<_> = merges.iter().filter(|m| m.content_hash == hash).collect();
    assert_eq!(relevant.len(), 1, "expected exactly one merge for the forced-duplicate hash");
    // Which physical copy wins the deterministic tie-break depends on
    // which shard each landed on (segment_id ordering, not write order) --
    // not asserting a specific winner, just that the forced duplicate
    // participated in the collision as one side of it.
    assert_ne!(relevant[0].canonical, relevant[0].loser);
    assert!(
        relevant[0].loser == loser_loc || relevant[0].canonical == loser_loc,
        "the forced-duplicate location should be one side of the detected collision"
    );

    // Both A and B must still read back correctly -- hash-only resolution
    // means neither ever depended on which physical copy was canonical.
    let read_a = pool.read(ino_a, 0, shared.len() as u32).unwrap();
    assert_eq!(read_a.as_ref(), shared.as_slice());
    let read_b = pool.read(ino_b, 0, shared.len() as u32).unwrap();
    assert_eq!(read_b.as_ref(), shared.as_slice());
}

#[test]
fn loser_becomes_reclaimable_by_gc_after_convergence() {
    // Closes the loop end-to-end: force a duplicate, converge via dedup,
    // then confirm a GC mark pass no longer considers the loser's offset
    // live (since the index no longer points anything at it) -- proving
    // dedup.rs's "no special-casing, ordinary GC reclaims it" claim.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let shared = deterministic_bytes(2, 2000);
    let ino = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(ino, 0, &shared).unwrap();
    pool.checkpoint().unwrap();

    let forced_loc = pool.debug_force_duplicate_chunk(&shared).unwrap();
    let hash = lchfs_format::Hash32::of(&shared);
    let merges = pool.run_dedup_pass().unwrap();
    let merge = merges
        .iter()
        .find(|m| m.content_hash == hash)
        .expect("expected a merge for the forced-duplicate hash");
    // Which physical copy wins the tie-break depends on which shard each
    // landed on, not write order -- use the actual merge result as the
    // source of truth for which one is the loser, rather than assuming.
    let loser_loc = merge.loser;
    assert!(loser_loc == forced_loc || merge.canonical == forced_loc);

    let root = pool.debug_root_hash();
    drop(pool);

    let index = lchfs_index::RedbIndex::open(&dir.path().join("INDEX.redb")).unwrap();
    let cache = lchfs_index::ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    let locations = std::sync::Arc::new(cache);
    let mut gc = lchfs_store::gc::GcEngine::new(
        dir.path().to_path_buf(),
        locations,
        std::sync::Arc::new(lchfs_index::PendingDedupPins::new()),
    );
    let live = gc.mark(&[root]);

    let loser_marked_live = live
        .get(&loser_loc.segment_id)
        .map(|bitmap| bitmap.contains(loser_loc.offset))
        .unwrap_or(false);
    assert!(
        !loser_marked_live,
        "the loser's offset should no longer be marked live after dedup convergence"
    );
}

#[test]
fn run_dedup_pass_on_a_pool_with_no_duplicates_is_a_correct_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(1, 1000)).unwrap();
    pool.checkpoint().unwrap();

    let merges = pool.run_dedup_pass().unwrap();
    assert!(merges.is_empty());

    let read_back = pool.read(ino, 0, 1000).unwrap();
    assert_eq!(read_back.as_ref(), deterministic_bytes(1, 1000).as_slice());
}

#[test]
fn repeated_dedup_passes_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let shared = deterministic_bytes(5, 1500);
    let ino = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(ino, 0, &shared).unwrap();
    pool.checkpoint().unwrap();
    pool.debug_force_duplicate_chunk(&shared).unwrap();
    pool.checkpoint().unwrap();

    let first = pool.run_dedup_pass().unwrap();
    let hash = lchfs_format::Hash32::of(&shared);
    let first_merge = first
        .iter()
        .find(|m| m.content_hash == hash)
        .expect("expected a merge on the first pass");

    // Second pass: dedup never deletes anything (can't -- append-only),
    // so both physical copies are still on disk and still get rescanned
    // (the segment cursor doesn't advance past a still-Open segment).
    // Idempotent doesn't mean "silent on repeat" here -- it means the
    // *result* is stable: re-resolving the same collision must always
    // pick the same canonical/loser pair, not flip-flop or diverge.
    let second = pool.run_dedup_pass().unwrap();
    if let Some(second_merge) = second.iter().find(|m| m.content_hash == hash) {
        assert_eq!(second_merge.canonical, first_merge.canonical);
        assert_eq!(second_merge.loser, first_merge.loser);
    }
}
