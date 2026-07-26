//! Content-defined chunking (FastCDC) and overwrite chunk-splicing.
//!
//! See ARCHITECTURE.md §2: chunk boundaries are cut on *uncompressed* bytes
//! (§2's "Chunking on uncompressed bytes" rationale), with avg/min/max sizes
//! tunable via `PoolParams` (lchfs-format). This crate produces byte-range
//! boundaries only — hashing happens in lchfs-crypto, compression in
//! lchfs-compress; this crate has no knowledge of either.

/// A chunk boundary within a byte stream: `[offset, offset + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBoundary {
    pub offset: u64,
    pub len: u32,
}

/// Common interface for cutting a byte stream into content-defined chunks.
pub trait Chunker {
    /// Feed more bytes in; returns any chunk boundaries that can now be
    /// finalized (a chunker may need to buffer a resync window before a
    /// boundary becomes final).
    fn push(&mut self, data: &[u8]) -> Vec<ChunkBoundary>;

    /// Signal end-of-stream; returns the final trailing boundary, if any.
    fn finish(&mut self) -> Option<ChunkBoundary>;
}

/// Default whole-file chunker. ARCHITECTURE.md §2: avg 64KiB / min 16KiB /
/// max 256KiB by default (larger than FastCDC's typical 8-16KiB defaults,
/// deliberately, for a bulk-ingest profile over a dedup-maximizing one).
pub struct FastCdcChunker {
    // TODO(phase-B): wrap fastcdc::v2020::FastCDC or similar, stateful across push() calls
    _avg_size: u32,
    _min_size: u32,
    _max_size: u32,
}

impl FastCdcChunker {
    pub fn new(avg_size: u32, min_size: u32, max_size: u32) -> Self {
        Self { _avg_size: avg_size, _min_size: min_size, _max_size: max_size }
    }
}

impl Chunker for FastCdcChunker {
    fn push(&mut self, _data: &[u8]) -> Vec<ChunkBoundary> {
        // TODO(phase-B): see ARCHITECTURE.md §2
        todo!("lchfs-chunk: FastCdcChunker::push")
    }

    fn finish(&mut self) -> Option<ChunkBoundary> {
        todo!("lchfs-chunk: FastCdcChunker::finish")
    }
}

/// Overwrite-path chunker (ARCHITECTURE.md §2, "Overwrites" paragraph):
/// re-chunks only the touched byte range plus a resync window (~2x avg
/// chunk size), leaving untouched chunks in the IndirectHashList alone.
pub struct SpliceChunker {
    // TODO(phase-B/E): resync-window splice logic against an existing IndirectHashList
}

impl SpliceChunker {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SpliceChunker {
    fn default() -> Self {
        Self::new()
    }
}
