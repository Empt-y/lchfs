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
///
/// Wraps `fastcdc::v2020::FastCDC`, which cuts over a complete in-memory
/// slice rather than a live stream. To make it stateful across `push()`
/// calls, this buffers incoming bytes and only emits a boundary once the
/// buffer holds at least `max_size` bytes — the gear-hash cut decision for
/// any position never looks more than `max_size` bytes ahead, so once that
/// many trailing bytes are buffered, every cut point below them is final
/// and can never change no matter what arrives next.
pub struct FastCdcChunker {
    avg_size: u32,
    min_size: u32,
    max_size: u32,
    buffer: Vec<u8>,
    /// Absolute stream offset corresponding to `buffer[0]`.
    base_offset: u64,
}

impl FastCdcChunker {
    pub fn new(avg_size: u32, min_size: u32, max_size: u32) -> Self {
        Self {
            avg_size,
            min_size,
            max_size,
            buffer: Vec::new(),
            base_offset: 0,
        }
    }
}

impl Chunker for FastCdcChunker {
    fn push(&mut self, data: &[u8]) -> Vec<ChunkBoundary> {
        self.buffer.extend_from_slice(data);
        let mut boundaries = Vec::new();
        while self.buffer.len() >= self.max_size as usize {
            let cutter = fastcdc::v2020::FastCDC::new(
                &self.buffer,
                self.min_size as usize,
                self.avg_size as usize,
                self.max_size as usize,
            );
            let (_hash, cutpoint) = cutter.cut(0, self.buffer.len());
            if cutpoint == 0 {
                break;
            }
            boundaries.push(ChunkBoundary {
                offset: self.base_offset,
                len: cutpoint as u32,
            });
            self.buffer.drain(0..cutpoint);
            self.base_offset += cutpoint as u64;
        }
        boundaries
    }

    /// Flushes whatever is left in the buffer (necessarily fewer than
    /// `max_size` bytes, by `push()`'s loop invariant) as one final chunk.
    /// This may skip an "ideal" interior CDC cut point that could exist
    /// within that tail, but it never drops or exceeds `max_size` on any
    /// byte — a deliberate simplification for the true end-of-stream case.
    fn finish(&mut self) -> Option<ChunkBoundary> {
        if self.buffer.is_empty() {
            return None;
        }
        let boundary = ChunkBoundary {
            offset: self.base_offset,
            len: self.buffer.len() as u32,
        };
        self.buffer.clear();
        self.base_offset += boundary.len as u64;
        Some(boundary)
    }
}

/// Overwrite-path chunker (ARCHITECTURE.md §2, "Overwrites" paragraph):
/// re-chunks only the touched byte range plus a resync window (~2x avg
/// chunk size), leaving untouched chunks in the IndirectHashList alone.
///
/// Deliberately deferred past this crate's initial implementation pass:
/// resync needs to compare candidate new cut points against the *content*
/// of untouched neighboring chunks, which lives in segments on disk and is
/// looked up by hash — that's `lchfs-store`/`lchfs-index` territory, and
/// this crate must not depend on either (ARCHITECTURE.md §11 dependency
/// order: `chunk` sits *below* `format`/`store`/`index`). Real
/// implementation belongs in Phase E once `lchfs-store` exists to supply
/// byte access; see `lchfs-store`'s TODOs for the write-path integration.
// TODO(phase-E): resync-window splice logic against an existing IndirectHashList, wired through lchfs-store for byte access
pub struct SpliceChunker {}

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
