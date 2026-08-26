//! Tests for sparse files and `fallocate` (ARCHITECTURE.md §9's Phase 2
//! "fallocate punch-hole/zero-range").
//!
//! A hole is represented by absence: the chunk list simply has a gap where
//! the hole is, and `read` returns zeros for any range no chunk covers. That
//! needs no new schema type -- an `IndirectHashList` is still
//! `Vec<ChunkRef>` -- but it does change what a gap *means*, hence the
//! format version bump to 2.

use lchfs_format::{ContentRef, IndirectHashList, PoolParams, StreamKind};
use lchfs_index::{ChunkLocationCache, PendingDedupPins, RedbIndex};
use lchfs_store::gc::GcEngine;
use lchfs_store::{FallocateMode, Pool, PoolError};
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 256 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
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

/// The file's persisted chunk list, read back off disk through
/// `lchfs-fsck`'s public scan plus a `SegmentReader` -- deliberately not via
/// any `Pool` internals, so these tests assert against what actually landed
/// on disk rather than in-memory state.
fn chunk_list(pool_root: &std::path::Path, pool: &Pool, ino: u64) -> IndirectHashList {
    match pool.getattr(ino).unwrap().content {
        ContentRef::ChunkList(hash) => {
            let locations = lchfs_fsck::scan_all_segments(pool_root).unwrap();
            let loc = locations[&hash];
            let reader = lchfs_store::segment::SegmentReader::open(
                pool_root,
                loc.segment_id,
                StreamKind::Meta,
            )
            .unwrap();
            let (_header, bytes) = reader.read_record(loc).unwrap();
            lchfs_format::decode(&bytes).unwrap()
        }
        _ => IndirectHashList { chunks: Vec::new() },
    }
}

/// Total bytes actually stored, i.e. excluding holes.
fn stored_bytes(pool_root: &std::path::Path, pool: &Pool, ino: u64) -> u64 {
    match pool.getattr(ino).unwrap().content {
        ContentRef::Inline(bytes) => bytes.len() as u64,
        ContentRef::ChunkList(_) => chunk_list(pool_root, pool, ino)
            .chunks
            .iter()
            .map(|c| c.len as u64)
            .sum(),
        _ => 0,
    }
}

/// Live bytes reachable from `root`, via a real GC mark pass -- the same
/// measurement gc.rs uses.
fn live_bytes(pool_root: &std::path::Path, root: lchfs_format::Hash32) -> u64 {
    let index = RedbIndex::open(&pool_root.join("INDEX.redb")).unwrap();
    let cache = ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    let mut gc = GcEngine::new(
        pool_root.to_path_buf(),
        Arc::new(cache),
        Arc::new(PendingDedupPins::new()),
    );
    gc.mark(&[root]).values().map(|bitmap| bitmap.len()).sum()
}

#[test]
fn punch_hole_reads_as_zeros_and_leaves_the_rest_intact() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(3, 40_000);
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();

    pool.fallocate(ino, 10_000, 12_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();

    // Size is unchanged by a punch.
    assert_eq!(pool.getattr(ino).unwrap().size, 40_000);

    let mut expected = content.clone();
    expected[10_000..22_000].fill(0);
    assert_eq!(&pool.read(ino, 0, 40_000).unwrap()[..], &expected[..]);
    // Bytes on both sides of the hole are untouched.
    assert_eq!(&pool.read(ino, 9_000, 1_000).unwrap()[..], &content[9_000..10_000]);
    assert_eq!(&pool.read(ino, 22_000, 1_000).unwrap()[..], &content[22_000..23_000]);
}

/// The point of the feature: a punched hole must actually stop occupying
/// space, not become a run of zero-filled chunks.
#[test]
fn a_punched_hole_is_not_stored() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(5, 60_000)).unwrap();
    pool.checkpoint().unwrap();
    let before = stored_bytes(dir.path(), &pool, ino);
    assert!(before >= 59_000, "expected a dense file, stored {before}");

    pool.fallocate(ino, 8_000, 40_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();

    let after = stored_bytes(dir.path(), &pool, ino);
    assert_eq!(pool.getattr(ino).unwrap().size, 60_000, "size must not change");
    assert!(
        after < before - 30_000,
        "hole was not reclaimed: {before} -> {after} stored bytes"
    );
}

#[test]
fn zero_range_zeroes_without_changing_size_when_keep_size() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(7, 20_000);
    pool.write(ino, 0, &content).unwrap();

    pool.fallocate(ino, 5_000, 5_000, FallocateMode::ZeroRange { keep_size: true }).unwrap();
    let mut expected = content.clone();
    expected[5_000..10_000].fill(0);
    assert_eq!(&pool.read(ino, 0, 20_000).unwrap()[..], &expected[..]);
    assert_eq!(pool.getattr(ino).unwrap().size, 20_000);
}

#[test]
fn zero_range_can_extend_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(9, 5_000)).unwrap();

    pool.fallocate(ino, 4_000, 6_000, FallocateMode::ZeroRange { keep_size: false }).unwrap();
    assert_eq!(pool.getattr(ino).unwrap().size, 10_000);
    assert!(pool.read(ino, 4_000, 6_000).unwrap().iter().all(|&b| b == 0));
}

#[test]
fn allocate_extends_the_file_unless_keep_size_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"small").unwrap();

    pool.fallocate(ino, 0, 9_000, FallocateMode::Allocate { keep_size: true }).unwrap();
    assert_eq!(pool.getattr(ino).unwrap().size, 5, "KEEP_SIZE must not grow the file");

    pool.fallocate(ino, 0, 9_000, FallocateMode::Allocate { keep_size: false }).unwrap();
    assert_eq!(pool.getattr(ino).unwrap().size, 9_000);
    assert_eq!(&pool.read(ino, 0, 5).unwrap()[..], b"small");
    assert!(pool.read(ino, 5, 8_995).unwrap().iter().all(|&b| b == 0));
}

#[test]
fn a_hole_survives_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(11, 30_000);
    pool.write(ino, 0, &content).unwrap();
    pool.fallocate(ino, 10_000, 10_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();
    let stored = stored_bytes(dir.path(), &pool, ino);
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    let mut expected = content.clone();
    expected[10_000..20_000].fill(0);
    assert_eq!(&pool.read(ino, 0, 30_000).unwrap()[..], &expected[..]);
    assert_eq!(pool.getattr(ino).unwrap().size, 30_000);
    assert_eq!(stored_bytes(dir.path(), &pool, ino), stored, "hole must stay unstored");
}

/// Writing back into a hole must restore real content there -- the case
/// where hydrate has to place chunks by offset rather than concatenate, or
/// every byte after the hole would land in the wrong place.
#[test]
fn writing_into_a_hole_restores_content_at_the_right_offset() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(13, 30_000);
    pool.write(ino, 0, &content).unwrap();
    pool.fallocate(ino, 10_000, 10_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    let patch = deterministic_bytes(17, 4_000);
    pool.write(ino, 12_000, &patch).unwrap();
    pool.checkpoint().unwrap();

    let mut expected = content.clone();
    expected[10_000..20_000].fill(0);
    expected[12_000..16_000].copy_from_slice(&patch);
    assert_eq!(&pool.read(ino, 0, 30_000).unwrap()[..], &expected[..]);
}

#[test]
fn multiple_holes_in_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(19, 60_000);
    pool.write(ino, 0, &content).unwrap();
    pool.fallocate(ino, 5_000, 8_000, FallocateMode::PunchHole).unwrap();
    pool.fallocate(ino, 30_000, 9_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    let mut expected = content.clone();
    expected[5_000..13_000].fill(0);
    expected[30_000..39_000].fill(0);
    assert_eq!(&pool.read(ino, 0, 60_000).unwrap()[..], &expected[..]);
}

#[test]
fn a_fully_punched_file_stores_nothing_but_keeps_its_size() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(23, 50_000)).unwrap();
    pool.fallocate(ino, 0, 50_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();

    assert_eq!(pool.getattr(ino).unwrap().size, 50_000);
    assert_eq!(chunk_list(dir.path(), &pool, ino).chunks.len(), 0, "a wholly-zero file should store no chunks");
    assert!(pool.read(ino, 0, 50_000).unwrap().iter().all(|&b| b == 0));
}

#[test]
fn invalid_fallocate_arguments_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"content").unwrap();

    assert!(matches!(
        pool.fallocate(ino, 0, 0, FallocateMode::PunchHole),
        Err(PoolError::InvalidArgument(_))
    ));
    assert!(matches!(
        pool.fallocate(ino, u64::MAX, 10, FallocateMode::PunchHole),
        Err(PoolError::InvalidArgument(_))
    ));
    assert!(matches!(
        pool.fallocate(9999, 0, 10, FallocateMode::PunchHole),
        Err(PoolError::NoSuchInode(_))
    ));
}

#[test]
fn fsck_is_clean_on_a_sparse_pool() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(29, 60_000)).unwrap();
    pool.fallocate(ino, 10_000, 20_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &roots);
    assert!(report.is_clean(), "fsck errors: {:?}", report.errors);
}

/// GC must reclaim the extents a hole released. The chunks are no longer
/// referenced by any live root, so an ordinary mark-and-sweep should collect
/// them with no hole-specific handling.
#[test]
fn punched_extents_become_gc_reclaimable() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(31, 60_000)).unwrap();
    pool.checkpoint().unwrap();
    let root_before = pool.debug_root_hash();

    pool.fallocate(ino, 5_000, 45_000, FallocateMode::PunchHole).unwrap();
    pool.checkpoint().unwrap();
    let root_after = pool.debug_root_hash();
    // Both roots stay on disk until GC actually sweeps, so they can be
    // marked independently -- but INDEX.redb only opens once the pool has
    // released it.
    drop(pool);

    let live_before = live_bytes(dir.path(), root_before);
    let live_after = live_bytes(dir.path(), root_after);

    assert!(
        live_after < live_before - 30_000,
        "expected the punched extents to drop out of the live set: {live_before} -> {live_after}"
    );
}

/// A pool written before sparse support (format v1) must still open and read
/// correctly: a v1 chunk list simply has no gaps, which the offset-placing
/// hydrate handles as a special case of the general one. The version guard
/// is deliberately one-directional -- it refuses versions *newer* than this
/// build, never older ones.
#[test]
fn a_v1_pool_still_opens_and_reads_under_v2() {
    use std::io::{Read, Seek, SeekFrom, Write};

    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = deterministic_bytes(37, 25_000);
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // Rewrite every valid slot's version to 1, re-checksumming so the pool
    // is otherwise indistinguishable from one an older build produced.
    {
        use lchfs_format::{
            SUPERBLOCK_MAGIC, SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE, SuperblockSlot,
            compute_superblock_slot_checksum, finalize_superblock_slot_checksum,
        };
        let path = dir.path().join("SUPERBLOCK");
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        for slot_idx in 0..SUPERBLOCK_SLOT_COUNT {
            let offset = slot_idx as u64 * SUPERBLOCK_SLOT_SIZE as u64;
            let mut buf = vec![0u8; SUPERBLOCK_SLOT_SIZE];
            file.seek(SeekFrom::Start(offset)).unwrap();
            if file.read_exact(&mut buf).is_err() {
                continue;
            }
            let encoded_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
            if encoded_len == 0 || 4 + encoded_len > buf.len() {
                continue;
            }
            let Ok(mut slot) = lchfs_format::decode::<SuperblockSlot>(&buf[4..4 + encoded_len])
            else {
                continue;
            };
            if slot.magic != SUPERBLOCK_MAGIC
                || compute_superblock_slot_checksum(&slot) != slot.header_checksum
            {
                continue;
            }
            slot.format_version = 1;
            finalize_superblock_slot_checksum(&mut slot);
            let encoded = lchfs_format::encode(&slot).unwrap();
            let mut out = vec![0u8; SUPERBLOCK_SLOT_SIZE];
            out[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
            out[4..4 + encoded.len()].copy_from_slice(&encoded);
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&out).unwrap();
        }
        file.sync_all().unwrap();
    }

    let pool = Pool::open(dir.path()).expect("a v1 pool must still open");
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(&pool.read(ino, 0, 25_000).unwrap()[..], &content[..]);
    // And partial reads, which is where offset placement would go wrong.
    assert_eq!(&pool.read(ino, 9_876, 4_321).unwrap()[..], &content[9_876..14_197]);
}
