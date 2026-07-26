//! Extent Record format — the core on-disk structure. ARCHITECTURE.md §1
//! ("Extent Record header") and §6 (back-pointers are provenance-only,
//! never trusted by GC).

use crate::Hash32;
use serde::{Deserialize, Serialize};

/// Magic identifying an Extent Record header, ASCII "LCHF". Detects
/// torn/garbage writes before any other parsing is attempted.
pub const EXTENT_RECORD_MAGIC: u32 = 0x4C43_4846;

/// What kind of object an Extent Record's payload decodes to.
/// `DeltaLogEntry` was added alongside the per-shard Delta Log
/// (ARCHITECTURE.md §1, §3) — it reuses this same record framing so the
/// existing magic/checksum/torn-write detection applies uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExtentKind {
    RawChunk = 0,
    InodeObject = 1,
    DirectoryObject = 2,
    IndirectHashList = 3,
    SnapshotTable = 4,
    RootObject = 5,
    DeltaLogEntry = 6,
}

/// Codec used to store an Extent Record's payload. See lchfs-compress for
/// the actual codec implementations; this is just the on-disk tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CodecId {
    None = 0,
    Zstd = 1,
}

/// Where an extent lives: which segment, at what offset, how long.
/// Shared by `lchfs-store` (writer) and `lchfs-index` (Chunk Location Index)
/// so neither needs to depend on the other — ARCHITECTURE.md §11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExtentLocation {
    pub segment_id: u64,
    pub offset: u32,
    pub len: u32,
}

/// The Extent Record header, as laid out on disk (ARCHITECTURE.md §1).
/// `payload` is not included here — callers read `record_len` bytes total
/// and slice the header off the front.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtentRecordHeader {
    pub magic: u32,
    /// Total record length in bytes, including this header — enables
    /// skip-scanning without decoding the payload.
    pub record_len: u32,
    /// BLAKE3-256 of the *uncompressed* logical payload. See
    /// ARCHITECTURE.md §2 for why this is always the uncompressed hash.
    pub content_hash: Hash32,
    pub kind: ExtentKind,
    pub codec_id: CodecId,
    pub flags: u16,
    pub uncompressed_len: u32,
    pub compressed_len: u32,
    /// Provenance-only hints for fsck/coalescing locality — never trusted
    /// by GC. See module docs and ARCHITECTURE.md §1 for why: content is
    /// shared/deduped, so a record can gain new parents after being
    /// written, which an immutable record can't retroactively note.
    pub backpointers: Vec<Hash32>,
    /// CRC32C over the header fields above, checked before spending BLAKE3
    /// cycles on the (possibly much larger) payload.
    pub header_checksum: u32,
}

/// Computes the header's CRC32C over its fields *excluding* `header_checksum`
/// itself (that field is zeroed before hashing, both when a writer commits a
/// header and when a reader recomputes it for comparison). Delegates to
/// `lchfs_crypto::header_checksum` so there is exactly one CRC32C
/// implementation in the codebase.
pub fn compute_header_checksum(header: &ExtentRecordHeader) -> u32 {
    let mut zeroed = header.clone();
    zeroed.header_checksum = 0;
    let bytes =
        bincode::serialize(&zeroed).expect("ExtentRecordHeader serialization is infallible");
    lchfs_crypto::header_checksum(&bytes)
}

/// Sets `header.header_checksum` to the correct value for its current
/// contents. Called by writers (lchfs-store) right before a header is
/// committed to disk.
pub fn finalize_header_checksum(header: &mut ExtentRecordHeader) {
    header.header_checksum = compute_header_checksum(header);
}

/// Mandatory read-side integrity check sequence (ARCHITECTURE.md §1):
/// magic -> bounds -> header_checksum -> decompress if needed -> mandatory
/// `BLAKE3(decompressed) == content_hash`. This function performs the first
/// three steps against an already-parsed header; the caller owns I/O,
/// decompression, and the final content-hash check (`lchfs_crypto::verify`)
/// once the payload is decompressed.
pub fn validate_header(
    header: &ExtentRecordHeader,
    record_bytes: &[u8],
) -> Result<(), ExtentValidationError> {
    if header.magic != EXTENT_RECORD_MAGIC {
        return Err(ExtentValidationError::BadMagic {
            expected: EXTENT_RECORD_MAGIC,
            actual: header.magic,
        });
    }
    if header.record_len as usize > record_bytes.len() {
        return Err(ExtentValidationError::OutOfBounds {
            record_len: header.record_len,
            buf_len: record_bytes.len(),
        });
    }
    if compute_header_checksum(header) != header.header_checksum {
        return Err(ExtentValidationError::HeaderChecksum);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ExtentValidationError {
    #[error("bad magic: expected {expected:#x}, got {actual:#x}")]
    BadMagic { expected: u32, actual: u32 },
    #[error("record_len {record_len} out of bounds for buffer of {buf_len} bytes")]
    OutOfBounds { record_len: u32, buf_len: usize },
    #[error("header checksum mismatch")]
    HeaderChecksum,
    #[error("content hash mismatch")]
    ContentHash,
}
