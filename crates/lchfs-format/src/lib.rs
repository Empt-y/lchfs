//! On-disk schema for LCHFS. No I/O lives here — this crate defines the
//! byte-level structures described in ARCHITECTURE.md §1, and nothing else.
//! `lchfs-store` reads/writes these; `lchfs-index` caches derived lookups
//! over them.

pub mod codec;
pub mod extent;
pub mod objects;
pub mod segment;
pub mod superblock;

pub use codec::{DecodeError, EncodeError, decode, encode};
pub use extent::{
    CodecId, EXTENT_RECORD_MAGIC, ExtentKind, ExtentLocation, ExtentRecordHeader,
    ExtentValidationError, compute_header_checksum, finalize_header_checksum, validate_header,
};
pub use lchfs_crypto::Hash32;
pub use objects::{
    ChunkRef, ContentRef, DeltaLogEntry, DirEntry, DirectoryObject, InoMap, InoMapEntry,
    InodeKind, InodeObject, IndirectHashList, PoolParams, RootObject, SnapshotEntry,
    SnapshotTable, XattrBlob,
};
pub use segment::{
    SEGMENT_HEADER_MAGIC, SegmentFooter, SegmentHeader, SegmentState, StreamKind,
    compute_segment_footer_checksum, compute_segment_header_checksum,
    finalize_segment_footer_checksum, finalize_segment_header_checksum,
};
pub use superblock::{
    SHARD_SUPERBLOCK_MAGIC, SUPERBLOCK_MAGIC, SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE,
    ShardSuperblockSlot, Superblock, SuperblockSlot, SuperblockStats,
    compute_shard_superblock_slot_checksum, compute_superblock_slot_checksum,
    finalize_shard_superblock_slot_checksum, finalize_superblock_slot_checksum,
};

/// On-disk format version, stored in every superblock slot. Bump on any
/// breaking schema change; `lchfs-fsck`/mount-time checks refuse to proceed
/// on an unrecognized version rather than guessing.
///
/// - v1: original format.
/// - v2: sparse files. No *type* changed -- an `IndirectHashList` is still
///   `Vec<ChunkRef>` and decodes identically -- but a gap between chunks is
///   now meaningful, denoting a hole that reads as zeros. A v1 reader
///   concatenates chunks rather than placing them at their `logical_offset`,
///   so it would silently shift every byte after a hole; hence a version
///   bump, so such a reader refuses the pool instead. A v2 reader handles v1
///   pools correctly with no migration, since a v1 chunk list simply has no
///   gaps.
pub const FORMAT_VERSION: u32 = 2;
