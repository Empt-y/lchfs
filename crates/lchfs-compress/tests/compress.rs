//! Correctness tests for `ZstdCodec` and `sample_and_decide`.
//! ARCHITECTURE.md §2: chunking/compression pipeline.

use lchfs_compress::{Codec, CodecId, CompressionDecision, ZstdCodec, sample_and_decide};
use proptest::collection::vec as pvec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn compress_decompress_round_trips(
        data in pvec(any::<u8>(), 0..50_000),
        level in 1i32..19,
    ) {
        let codec = ZstdCodec;
        let compressed = codec.compress(&data, level);
        let decompressed = codec.decompress(&compressed, data.len());
        prop_assert_eq!(data, decompressed);
    }

    #[test]
    fn sample_and_decide_never_panics(data in pvec(any::<u8>(), 0..200_000)) {
        let _ = sample_and_decide(&data);
    }

    /// If a decision to compress is made, actually compressing the whole
    /// chunk (not just the sample) at the decided level must still
    /// round-trip losslessly through decompress.
    #[test]
    fn compress_decision_round_trips_full_chunk(data in pvec(any::<u8>(), 1..200_000)) {
        if let CompressionDecision::Compress { codec, level } = sample_and_decide(&data) {
            prop_assert_eq!(codec, CodecId::Zstd);
            let compressed = ZstdCodec.compress(&data, level);
            let decompressed = ZstdCodec.decompress(&compressed, data.len());
            prop_assert_eq!(data, decompressed);
        }
    }
}

#[test]
fn empty_chunk_stores_raw() {
    assert_eq!(sample_and_decide(&[]), CompressionDecision::StoreRaw);
}

#[test]
fn highly_repetitive_data_is_compressed() {
    let data = vec![0u8; 100_000];
    let decision = sample_and_decide(&data);
    assert!(matches!(decision, CompressionDecision::Compress { .. }));
}

#[test]
fn small_chunk_samples_whole_chunk_and_still_decides() {
    // Below the 4KiB window: build_sample should use the whole chunk, not panic.
    let data = vec![b'x'; 100];
    let decision = sample_and_decide(&data);
    assert!(matches!(decision, CompressionDecision::Compress { .. }));
}
