//! On-disk schema for LCHFS. No I/O lives here — this crate defines the
//! byte-level structures described in ARCHITECTURE.md §1, and nothing else.
//! `lchfs-store` reads/writes these; `lchfs-index` caches derived lookups
//! over them.

pub mod codec;
pub mod extent;
pub mod objects;
pub mod sealed;
pub mod segment;
pub mod superblock;

pub use codec::{DecodeError, EncodeError, decode, encode};
pub use extent::{
    CodecId, EXTENT_RECORD_MAGIC, ExtentKind, ExtentLocation, ExtentRecordHeader,
    ExtentValidationError, compute_header_checksum, finalize_header_checksum, validate_header,
};
pub use lchfs_crypto::Hash32;
pub use sealed::{Opened, RecordCrypto, SealError, is_sealed, record_epoch};
pub use objects::{
    ChunkRef, ContentRef, DeltaLogEntry, DirEntry, DirectoryObject, InoMap, InoMapEntry,
    InodeKind, InodeObject, IndirectHashList, PoolParams, RootObject, SnapshotEntry,
    SnapshotTable, XattrBlob,
};
pub use segment::{
    SEGMENT_HEADER_MAGIC, SegmentFooter, SegmentHeader, SegmentState, StreamKind,
    compute_segment_footer_checksum, compute_segment_header_checksum,
    finalize_segment_footer_checksum, finalize_segment_header_checksum, STRIPE_DESCRIPTOR_OFFSET,
    StripeDescriptor,
};
pub use superblock::{
    parse_pool_uuid, pool_uuid_hex, SHARD_SUPERBLOCK_MAGIC, SUPERBLOCK_MAGIC, SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE,
    ShardSuperblockSlot, Superblock, SuperblockSlot, SuperblockSlotV2, SuperblockStats,
    compute_shard_superblock_slot_checksum, compute_superblock_slot_checksum,
    finalize_shard_superblock_slot_checksum, finalize_superblock_slot_checksum,
    generate_pool_uuid,
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
///
/// - v5: native encryption (`sealed`). A v5 pool can hold sealed records
///   and a keyring, which a v4 reader would take for corruption; so v5 is
///   written, and v4 is still *read* -- a v4 pool is a valid plaintext v5
///   pool, because a plaintext record's layout did not change.
pub const FORMAT_VERSION: u32 = 5;

/// The oldest format this build still opens (see v5 above).
pub const MIN_READABLE_FORMAT_VERSION: u32 = 4;

/// The largest logical record this build writes or reads, 512 MiB: an
/// allocation bound on everything a record header claims. Defined here,
/// not in the store, so the sealed-record reader bounds itself by the very
/// same ceiling the writer is held to.
pub const MAX_RECORD_LEN: u32 = 512 * 1024 * 1024;
