//! Segment file framing. ARCHITECTURE.md §1 ("Segment files"): a fixed-cap
//! append-only file holding back-to-back Extent Records, opened with a
//! header page and closed with a seal footer.

use crate::Hash32;
use serde::{Deserialize, Serialize};

/// Magic identifying a segment file's header page, ASCII "LCHFSEG\0".
pub const SEGMENT_HEADER_MAGIC: [u8; 8] = *b"LCHFSEG\0";

/// Which stream a segment belongs to — data and metadata are kept as
/// separate segment streams (ARCHITECTURE.md §1) so mount-time index
/// rebuild and fsck can scan metadata first without touching bulk data.
///
/// `Delta` (Phase E, ARCHITECTURE.md §3 "Subtree durability via per-shard
/// delta logs") is a third, per-shard-scoped stream: one logical shard's
/// self-contained fast-fsync record stream (freshly-rewritten
/// IndirectHashList/InodeObject records plus DeltaLogEntry pointers into
/// them), kept separate from the global Data/Meta streams so a shard's
/// `fsync()` never contends with any other shard or the global checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamKind {
    Data,
    Meta,
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentState {
    Open,
    Sealed,
    Coalesced,
}

/// A segment file's header page (ARCHITECTURE.md §1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentHeader {
    pub magic: [u8; 8],
    pub segment_id: u64,
    pub stream_kind: StreamKind,
    pub owner_shard: u32,
    pub state: SegmentState,
    pub header_checksum: u32,
}

/// A sealed segment's footer (ARCHITECTURE.md §1: "record count, aggregate
/// fingerprint hash, checksum").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentFooter {
    pub record_count: u64,
    pub aggregate_fingerprint: Hash32,
    pub footer_checksum: u32,
}

/// Same zero-then-CRC32C pattern as `extent::compute_header_checksum`, used
/// for both `SegmentHeader` and `SegmentFooter` (whichever `checksum` field
/// value is passed in is what gets zeroed before hashing).
pub fn compute_segment_header_checksum(header: &SegmentHeader) -> u32 {
    let mut zeroed = header.clone();
    zeroed.header_checksum = 0;
    let bytes = bincode::serialize(&zeroed).expect("SegmentHeader serialization is infallible");
    lchfs_crypto::header_checksum(&bytes)
}

pub fn finalize_segment_header_checksum(header: &mut SegmentHeader) {
    header.header_checksum = compute_segment_header_checksum(header);
}

pub fn compute_segment_footer_checksum(footer: &SegmentFooter) -> u32 {
    let mut zeroed = footer.clone();
    zeroed.footer_checksum = 0;
    let bytes = bincode::serialize(&zeroed).expect("SegmentFooter serialization is infallible");
    lchfs_crypto::header_checksum(&bytes)
}

pub fn finalize_segment_footer_checksum(footer: &mut SegmentFooter) {
    footer.footer_checksum = compute_segment_footer_checksum(footer);
}
