//! Merkle DAG object schemas. ARCHITECTURE.md §1 ("Merkle DAG object
//! schemas"). Each of these is the *payload* of an Extent Record whose
//! `kind` matches (see extent.rs::ExtentKind) — this module defines their
//! decoded, in-memory shape only; encoding is bincode via lchfs-store.

use crate::Hash32;

/// The root of a point-in-time filesystem tree. A superblock's `root_hash`
/// points at one of these. ARCHITECTURE.md §1.
#[derive(Debug, Clone)]
pub struct RootObject {
    pub inomap_hash: Hash32,
    /// Root directory inode number, fixed at 1 by convention (matches
    /// FUSE's reserved root ino).
    pub root_dir_ino: u64,
    /// Monotonic, never reused — even across unlink.
    pub next_ino_counter: u64,
    pub snapshot_table_hash: Hash32,
    pub pool_params: PoolParams,
    /// One entry per logical shard: how far that shard's Delta Log had
    /// been folded into this checkpoint's InoMap. See ARCHITECTURE.md §3
    /// ("Subtree durability via per-shard delta logs") and §7 (recovery).
    pub shard_watermarks: Vec<u64>,
}

/// `ino -> current_object_hash`, sorted by ino. Resolves the tension
/// between content-addressing (hash changes every write) and POSIX's need
/// for stable inode numbers. ARCHITECTURE.md §1: "DirectoryObject entries
/// reference `ino`, not a hash" is the key structural point this enables.
#[derive(Debug, Clone, Default)]
pub struct InoMap {
    pub entries: Vec<InoMapEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InoMapEntry {
    pub ino: u64,
    pub current_object_hash: Hash32,
}

/// What kind of inode a directory entry (or InodeObject) refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    File,
    Directory,
    Symlink,
}

/// A directory's contents: name -> ino mappings, sorted by name for
/// deterministic hashing. ARCHITECTURE.md §1.
#[derive(Debug, Clone, Default)]
pub struct DirectoryObject {
    pub entries: Vec<DirEntry>,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    pub kind: InodeKind,
}

/// A file/dir/symlink's metadata and content pointer. ARCHITECTURE.md §1.
#[derive(Debug, Clone)]
pub struct InodeObject {
    pub kind: InodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub nlink: u32,
    pub atime: (i64, u32),
    pub mtime: (i64, u32),
    pub ctime: (i64, u32),
    /// Reserved, unpopulated in Phase 1 (ARCHITECTURE.md §9: xattrs are
    /// explicitly deferred) — the field exists now so no format migration
    /// is needed when xattr support lands.
    pub xattrs: Option<XattrBlob>,
    pub content: ContentRef,
    pub generation: u64,
}

/// Placeholder for reserved-but-unimplemented xattr storage.
#[derive(Debug, Clone, Default)]
pub struct XattrBlob(pub Vec<u8>);

/// How an InodeObject's content is stored. ARCHITECTURE.md §1: files below
/// `PoolParams::inline_threshold` embed directly (deliberately not
/// dedup'd — see rationale in ARCHITECTURE.md §1).
#[derive(Debug, Clone)]
pub enum ContentRef {
    Inline(Vec<u8>),
    ChunkList(Hash32),
    DirEntries(Hash32),
    SymlinkTarget(String),
}

/// A file's chunk list — the hash-DAG analogue of classic Unix indirect
/// blocks. Sorted by `logical_offset`, capped at 64K entries per level
/// (double-indirect beyond that). ARCHITECTURE.md §1, and §5 for why
/// ingestion order never needs to match this logical order.
#[derive(Debug, Clone, Default)]
pub struct IndirectHashList {
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    pub content_hash: Hash32,
    pub logical_offset: u64,
    pub len: u32,
}

/// Named, retained point-in-time roots. Itself content-addressed and
/// referenced from `RootObject`, so snapshots participate in ordinary GC
/// reachability with no special-casing (ARCHITECTURE.md §6).
#[derive(Debug, Clone, Default)]
pub struct SnapshotTable {
    pub entries: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub name: String,
    pub root_hash: Hash32,
    pub created_at_unix_nanos: i64,
    pub epoch: u64,
}

/// One entry in a logical shard's Delta Log (ARCHITECTURE.md §1, §3, §7):
/// `{ino -> new_object_hash}`, applied on top of the base InoMap during
/// the bounded, idempotent mount-time replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaLogEntry {
    pub ino: u64,
    pub new_object_hash: Hash32,
    pub epoch: u64,
}

/// Pool-wide parameters, set at `create-pool` time and immutable
/// thereafter (referenced from `RootObject`). ARCHITECTURE.md §1, §2.
#[derive(Debug, Clone, Copy)]
pub struct PoolParams {
    pub data_segment_cap_bytes: u32,
    pub meta_segment_cap_bytes: u32,
    /// FastCDC target parameters (ARCHITECTURE.md §2): avg 64KiB / min
    /// 16KiB / max 256KiB by default.
    pub chunk_avg_size: u32,
    pub chunk_min_size: u32,
    pub chunk_max_size: u32,
    /// Files at or below this size inline directly into InodeObject
    /// instead of going through chunking/dedup. Default 512B.
    pub inline_threshold: u32,
    /// Number of logical shards, M in ARCHITECTURE.md §5. Deliberately
    /// much greater than core count.
    pub logical_shard_count: u32,
}

impl Default for PoolParams {
    fn default() -> Self {
        Self {
            data_segment_cap_bytes: 128 * 1024 * 1024,
            meta_segment_cap_bytes: 16 * 1024 * 1024,
            chunk_avg_size: 64 * 1024,
            chunk_min_size: 16 * 1024,
            chunk_max_size: 256 * 1024,
            inline_threshold: 512,
            logical_shard_count: 256,
        }
    }
}
