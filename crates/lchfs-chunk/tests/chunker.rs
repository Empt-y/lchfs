//! Correctness tests for `FastCdcChunker`: reassembly (no gaps/overlaps/lost
//! bytes), determinism, size bounds, and equivalence regardless of how the
//! input is split across `push()` calls (validates the incremental-buffer
//! wrapping is faithful to a single whole-buffer FastCDC pass).

use lchfs_chunk::{ChunkBoundary, Chunker, FastCdcChunker};
use proptest::collection::vec as pvec;
use proptest::prelude::*;

const MIN: u32 = 256;
const AVG: u32 = 1024;
const MAX: u32 = 4096;

/// Feeds `data` to a fresh chunker in one or more pieces (per `split_points`,
/// each taken modulo the remaining length so any input is valid) and returns
/// every boundary in order, including the final `finish()` boundary.
fn chunk_with_splits(data: &[u8], split_points: &[usize]) -> Vec<ChunkBoundary> {
    let mut chunker = FastCdcChunker::new(AVG, MIN, MAX);
    let mut boundaries = Vec::new();
    let mut pos = 0;
    for &raw_split in split_points {
        if pos >= data.len() {
            break;
        }
        let remaining = data.len() - pos;
        let split = 1 + (raw_split % remaining);
        boundaries.extend(chunker.push(&data[pos..pos + split]));
        pos += split;
    }
    if pos < data.len() {
        boundaries.extend(chunker.push(&data[pos..]));
    }
    if let Some(last) = chunker.finish() {
        boundaries.push(last);
    }
    boundaries
}

fn assert_boundaries_reassemble(data: &[u8], boundaries: &[ChunkBoundary]) {
    let mut expected_offset = 0u64;
    for b in boundaries {
        assert_eq!(
            b.offset, expected_offset,
            "boundaries must be contiguous with no gaps/overlaps"
        );
        assert!(b.len > 0, "chunk length must be nonzero");
        expected_offset += b.len as u64;
    }
    assert_eq!(
        expected_offset,
        data.len() as u64,
        "boundaries must cover every byte of input exactly once"
    );
}

proptest! {
    #[test]
    fn reassembles_full_input_single_push(data in pvec(any::<u8>(), 0..20_000)) {
        let mut chunker = FastCdcChunker::new(AVG, MIN, MAX);
        let mut boundaries = chunker.push(&data);
        if let Some(last) = chunker.finish() {
            boundaries.push(last);
        }
        assert_boundaries_reassemble(&data, &boundaries);
    }

    #[test]
    fn reassembles_full_input_across_arbitrary_splits(
        data in pvec(any::<u8>(), 0..20_000),
        split_points in pvec(any::<usize>(), 0..30),
    ) {
        let boundaries = chunk_with_splits(&data, &split_points);
        assert_boundaries_reassemble(&data, &boundaries);
    }

    #[test]
    fn chunking_is_deterministic(data in pvec(any::<u8>(), 0..20_000)) {
        let mut a = FastCdcChunker::new(AVG, MIN, MAX);
        let mut boundaries_a = a.push(&data);
        boundaries_a.extend(a.finish());

        let mut b = FastCdcChunker::new(AVG, MIN, MAX);
        let mut boundaries_b = b.push(&data);
        boundaries_b.extend(b.finish());

        prop_assert_eq!(boundaries_a, boundaries_b);
    }

    #[test]
    fn no_chunk_exceeds_max_size(data in pvec(any::<u8>(), 0..20_000)) {
        let mut chunker = FastCdcChunker::new(AVG, MIN, MAX);
        let mut boundaries = chunker.push(&data);
        boundaries.extend(chunker.finish());
        for b in &boundaries {
            prop_assert!(b.len <= MAX);
        }
    }

    /// The incremental buffering wrapper must be indistinguishable from
    /// running FastCDC once over the whole buffer: splitting the input
    /// across push() calls must never change the resulting boundaries.
    #[test]
    fn split_points_do_not_affect_result(
        data in pvec(any::<u8>(), 0..20_000),
        split_points in pvec(any::<usize>(), 0..30),
    ) {
        let whole = chunk_with_splits(&data, &[]);
        let split = chunk_with_splits(&data, &split_points);
        prop_assert_eq!(whole, split);
    }
}

#[test]
fn empty_input_produces_no_boundaries() {
    let mut chunker = FastCdcChunker::new(AVG, MIN, MAX);
    let boundaries = chunker.push(&[]);
    assert!(boundaries.is_empty());
    assert_eq!(chunker.finish(), None);
}

#[test]
fn calling_finish_twice_is_a_noop_the_second_time() {
    let mut chunker = FastCdcChunker::new(AVG, MIN, MAX);
    chunker.push(&[1, 2, 3]);
    assert!(chunker.finish().is_some());
    assert_eq!(chunker.finish(), None);
}
