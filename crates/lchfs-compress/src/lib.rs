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

    fn compress(&self, data: &[u8], level: i32) -> Vec<u8> {
        zstd::bulk::compress(data, level)
            .expect("zstd compression of an in-memory buffer should not fail")
    }

    fn decompress(&self, data: &[u8], uncompressed_len: usize) -> Vec<u8> {
        zstd::bulk::decompress(data, uncompressed_len)
            .expect("zstd decompression of a record written by this codec should not fail")
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

/// Size of each sampled window, and the size of the always-included first
/// window ("first 4KiB" per ARCHITECTURE.md §2).
const SAMPLE_WINDOW_BYTES: usize = 4096;
/// Target sample size as a fraction of the chunk ("sample ~10%").
const SAMPLE_FRACTION: f64 = 0.10;
/// Trial-compression level — cheap, just to estimate compressibility.
const TRIAL_LEVEL: i32 = 1;
/// Level used for the real compression pass if the trial looks promising.
const TARGET_LEVEL: i32 = 3;
/// Minimum reduction the trial must show to bother compressing the full
/// chunk ("if the sample achieves >=10% reduction").
const MIN_REDUCTION: f64 = 0.10;

/// Builds the ~10% sample used to decide compressibility: the first
/// `SAMPLE_WINDOW_BYTES` of the chunk, plus additional same-size windows
/// strided evenly through the rest, until the sample reaches ~10% of the
/// chunk's size (or the chunk is small enough that "10%" already covers all
/// of it, in which case the whole chunk is the sample).
fn build_sample(chunk: &[u8]) -> Vec<u8> {
    let target_len = (((chunk.len() as f64) * SAMPLE_FRACTION).ceil() as usize).max(1);
    if chunk.len() <= SAMPLE_WINDOW_BYTES || target_len >= chunk.len() {
        return chunk.to_vec();
    }
    let window = SAMPLE_WINDOW_BYTES;
    let num_windows = (target_len / window).max(1);
    if num_windows == 1 {
        return chunk[..window].to_vec();
    }
    let stride = chunk.len() / num_windows;
    let mut sample = Vec::with_capacity(num_windows * window);
    for i in 0..num_windows {
        let start = (i * stride).min(chunk.len() - window);
        sample.extend_from_slice(&chunk[start..start + window]);
    }
    sample
}

pub fn sample_and_decide(chunk: &[u8]) -> CompressionDecision {
    if chunk.is_empty() {
        return CompressionDecision::StoreRaw;
    }
    let sample = build_sample(chunk);
    let trial = ZstdCodec.compress(&sample, TRIAL_LEVEL);
    let reduction = 1.0 - (trial.len() as f64 / sample.len() as f64);
    if reduction >= MIN_REDUCTION {
        CompressionDecision::Compress {
            codec: CodecId::Zstd,
            level: TARGET_LEVEL,
        }
    } else {
        CompressionDecision::StoreRaw
    }
}
