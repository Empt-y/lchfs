//! Adaptive compression: trial-compress a sample, decide, then compress (or
//! don't) the full chunk. See ARCHITECTURE.md §2's pipeline and §8's
//! "Compression policy" for the exact algorithm and the empirical-trial
//! rationale over a pure entropy-formula estimate.

/// Registry id for the codec used on an Extent Record (ARCHITECTURE.md §1:
/// `codec_id` field). 0 = None is reserved implicitly by absence of this enum's
/// use; this type covers the codecs actually implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecId {
    None = 0,
    Zstd = 1,
}

/// A compression codec. Future codecs (beyond zstd) plug in here without
/// changing callers.
pub trait Codec {
    fn id(&self) -> CodecId;
    fn compress(&self, data: &[u8], level: i32) -> Vec<u8>;
    fn decompress(&self, data: &[u8], uncompressed_len: usize) -> Vec<u8>;
}

pub struct ZstdCodec;

impl Codec for ZstdCodec {
    fn id(&self) -> CodecId {
        CodecId::Zstd
    }

    fn compress(&self, _data: &[u8], _level: i32) -> Vec<u8> {
        // TODO(phase-B): zstd::stream::encode_all or bulk API
        todo!("lchfs-compress: ZstdCodec::compress")
    }

    fn decompress(&self, _data: &[u8], _uncompressed_len: usize) -> Vec<u8> {
        // TODO(phase-B): zstd::stream::decode_all or bulk API
        todo!("lchfs-compress: ZstdCodec::decompress")
    }
}

/// Outcome of `sample_and_decide`: whether to compress the full chunk, and
/// with which codec/level if so. ARCHITECTURE.md §8: trial-compress ~10% of
/// the chunk at zstd level 1; if that sample achieves >=10% reduction,
/// compress the full chunk at the target level (default 3); otherwise store
/// raw. Both `uncompressed_len` and `compressed_len` are always recorded on
/// the resulting Extent Record regardless of the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionDecision {
    StoreRaw,
    Compress { codec: CodecId, level: i32 },
}

pub fn sample_and_decide(_chunk: &[u8]) -> CompressionDecision {
    // TODO(phase-B): sample ~10% (first 4KiB + strided windows, capped),
    // trial-compress at level 1, threshold check per ARCHITECTURE.md §8
    todo!("lchfs-compress: sample_and_decide")
}
