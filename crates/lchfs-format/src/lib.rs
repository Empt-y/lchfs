//! On-disk schema for LCHFS. No I/O lives here — this crate defines the
//! byte-level structures described in ARCHITECTURE.md §1, and nothing else.
//! `lchfs-store` reads/writes these; `lchfs-index` caches derived lookups
//! over them.

pub mod extent;
pub mod objects;
pub mod superblock;

pub use extent::{ExtentKind, ExtentLocation, ExtentRecordHeader};
pub use lchfs_crypto::Hash32;
pub use objects::{
    ChunkRef, ContentRef, DeltaLogEntry, DirEntry, DirectoryObject, InoMap, InoMapEntry,
    InodeKind, InodeObject, IndirectHashList, PoolParams, RootObject, SnapshotEntry,
    SnapshotTable,
};
pub use superblock::{ShardSuperblockSlot, Superblock, SuperblockSlot};

/// On-disk format version, stored in every superblock slot. Bump on any
/// breaking schema change; `lchfs-fsck`/mount-time checks refuse to proceed
/// on an unrecognized version rather than guessing.
pub const FORMAT_VERSION: u32 = 1;
