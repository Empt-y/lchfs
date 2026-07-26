//! On-disk schema for LCHFS. No I/O lives here — this crate defines the
//! byte-level structures described in ARCHITECTURE.md §1, and nothing else.
//! `lchfs-store` reads/writes these; `lchfs-index` caches derived lookups
//! over them.

pub mod codec;
pub mod extent;
pub mod objects;
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
pub use superblock::{ShardSuperblockSlot, Superblock, SuperblockSlot, SuperblockStats};

/// On-disk format version, stored in every superblock slot. Bump on any
/// breaking schema change; `lchfs-fsck`/mount-time checks refuse to proceed
/// on an unrecognized version rather than guessing.
pub const FORMAT_VERSION: u32 = 1;
