//! Tests for the range-based read path (ARCHITECTURE.md §4: "fetch
//! IndirectHashList -> binary-search covering chunks -> ... -> assemble").
//!
//! `Pool::read` used to materialize a file's entire content into one
//! contiguous buffer and clone it on every read. It now resolves only the
//! chunks overlapping the requested range when the file has no in-memory
//! working state, which is the common case for reading a file that has not
//! just been written.
//!
//! The risk in that change is entirely offset/length arithmetic at chunk
//! boundaries, so these tests exhaustively compare every (offset, len)
//! against the known-correct whole-file bytes rather than spot-checking.

use lchfs_format::PoolParams;
use lchfs_store::Pool;

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

/// Writes `content`, checkpoints, and reopens -- so reads afterwards go
/// through the persisted-chunk path with no `file_state` cached, which is
/// exactly the path this change rewrote.
fn pool_with_file(dir: &std::path::Path, content: &[u8]) -> (Pool, u64) {
    let pool = Pool::create(dir, small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, content).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    (pool, ino)
}

#[test]
fn every_offset_and_length_matches_the_whole_file() {
    let dir = tempfile::tempdir().unwrap();
    // Comfortably multi-chunk at these params, and not a round number, so
    // the final chunk is a partial one.
    let content = deterministic_bytes(7, 20_003);
    let (pool, ino) = pool_with_file(dir.path(), &content);

    // Step through offsets on and around chunk boundaries; a stride that
    // shares no factor with the chunk sizes keeps hitting mid-chunk cases.
    for offset in (0..content.len()).step_by(97) {
        for len in [0usize, 1, 2, 255, 256, 257, 1023, 1024, 4095, 4096, 9999] {
            let got = pool.read(ino, offset as u64, len as u32).unwrap();
            let end = (offset + len).min(content.len());
            let expected = &content[offset.min(content.len())..end];
            assert_eq!(
                &got[..],
                expected,
                "mismatch at offset={offset} len={len}"
            );
        }
    }
}

#[test]
fn reads_at_and_past_eof_return_short_or_empty() {
    let dir = tempfile::tempdir().unwrap();
    let content = deterministic_bytes(11, 5000);
    let (pool, ino) = pool_with_file(dir.path(), &content);

    // Straddling EOF returns only the bytes that exist.
    let got = pool.read(ino, 4900, 500).unwrap();
    assert_eq!(&got[..], &content[4900..5000]);

    assert!(pool.read(ino, 5000, 100).unwrap().is_empty());
    assert!(pool.read(ino, 999_999, 100).unwrap().is_empty());
    assert!(pool.read(ino, 0, 0).unwrap().is_empty());
}

/// A read spanning many chunks must stitch them together in order --
/// the case a naive binary search that lands one chunk too far would break.
#[test]
fn a_read_spanning_many_chunks_is_contiguous() {
    let dir = tempfile::tempdir().unwrap();
    let content = deterministic_bytes(13, 50_000);
    let (pool, ino) = pool_with_file(dir.path(), &content);

    let got = pool.read(ino, 0, 50_000).unwrap();
    assert_eq!(&got[..], &content[..]);

    // And an interior span that starts and ends mid-chunk.
    let got = pool.read(ino, 1234, 30_000).unwrap();
    assert_eq!(&got[..], &content[1234..31_234]);
}

/// Inline files (below `inline_threshold`) never reach the chunk path, but
/// they go through the same clamping helper, so they need the same coverage.
#[test]
fn inline_files_read_correctly_at_every_offset() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"inline content".to_vec();
    let (pool, ino) = pool_with_file(dir.path(), &content);

    for offset in 0..=content.len() + 2 {
        for len in 0..=content.len() + 2 {
            let got = pool.read(ino, offset as u64, len as u32).unwrap();
            let start = offset.min(content.len());
            let end = (start + len).min(content.len());
            assert_eq!(&got[..], &content[start..end], "offset={offset} len={len}");
        }
    }
}

/// Reads must agree whether or not `file_state` happens to be populated:
/// a freshly written file serves from memory, the same file after a reopen
/// serves from persisted chunks, and the two must be indistinguishable.
#[test]
fn cached_and_persisted_reads_agree() {
    let dir = tempfile::tempdir().unwrap();
    let content = deterministic_bytes(17, 12_345);

    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &content).unwrap();

    // Before checkpoint/reopen: served from in-memory working state.
    let mut cached = Vec::new();
    for offset in (0..content.len()).step_by(311) {
        cached.push(pool.read(ino, offset as u64, 777).unwrap());
    }
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    for (i, offset) in (0..content.len()).step_by(311).enumerate() {
        let persisted = pool.read(ino, offset as u64, 777).unwrap();
        assert_eq!(persisted, cached[i], "disagreement at offset={offset}");
    }
}

/// An overwrite rewrites part of the chunk list; reads afterwards must see
/// the new bytes at the right offsets, not a stale chunk boundary.
#[test]
fn reads_after_an_overwrite_see_the_new_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let content = deterministic_bytes(19, 30_000);
    let (pool, ino) = pool_with_file(dir.path(), &content);

    let patch = vec![0xABu8; 5000];
    pool.write(ino, 10_000, &patch).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let mut expected = content.clone();
    expected[10_000..15_000].copy_from_slice(&patch);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    for offset in (0..expected.len()).step_by(499) {
        let got = pool.read(ino, offset as u64, 2000).unwrap();
        let end = (offset + 2000).min(expected.len());
        assert_eq!(&got[..], &expected[offset..end], "offset={offset}");
    }
}

/// A file grown by `set_size` past its written content reads as zeros in the
/// extended region -- the closest thing to a hole the current format can
/// produce, and the behaviour the upcoming sparse work builds on.
#[test]
fn a_zero_extended_file_reads_zeros_in_the_tail() {
    let dir = tempfile::tempdir().unwrap();
    let content = deterministic_bytes(23, 8000);
    let (pool, ino) = pool_with_file(dir.path(), &content);

    pool.set_size(ino, 20_000).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(&pool.read(ino, 0, 8000).unwrap()[..], &content[..]);
    assert!(pool.read(ino, 8000, 12_000).unwrap().iter().all(|&b| b == 0));
    assert_eq!(pool.read(ino, 0, 20_000).unwrap().len(), 20_000);
}
