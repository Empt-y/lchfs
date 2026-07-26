//! The LCHFS engine. ARCHITECTURE.md §3 (write path), §4 (read path), §5
//! (concurrency), §6 (GC), §7 (crash recovery).
//!
//! **Kernel-independence boundary (ARCHITECTURE.md §5a):** this crate has
//! zero knowledge of FUSE. `Pool` is the entire public surface a frontend
//! (today `lchfs-fuse`, potentially a future kernel module) is expected to
//! call. No `fuser`/`nix` dependency here, by design — do not add one.

pub mod backend;
pub mod checkpoint;
pub mod coalesce;
pub mod dedup;
pub mod delta_log;
pub mod gc;
pub mod ingress;
pub mod prep;
pub mod segment;

use bytes::Bytes;
use lchfs_format::Hash32;
use thiserror::Error;

pub use backend::{FileBackend, StorageBackend, Vdev};

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("integrity check failed for hash {0:?}")]
    IntegrityFailure(Hash32),
    #[error("no such inode: {0}")]
    NoSuchInode(u64),
    #[error("format error: {0}")]
    Format(String),
}

/// The engine's entire public API. A frontend (lchfs-fuse today; see
/// ARCHITECTURE.md §5a for the future-kernel-module rationale) is a thin
/// adapter that does nothing but translate protocol calls into these
/// methods — no filesystem logic belongs in a frontend crate.
pub struct Pool {
    // TODO(phase-B): StorageBackend handle, open segments, superblock state,
    // ActiveTreeCache/ChunkLocationCache (lchfs-index), ingress shards
    // (Phase E), checkpoint coordinator handle, background daemon handles.
}

impl Pool {
    /// Open an existing pool at `path`, or create one with `params` if
    /// `create` is set. Runs mount-time recovery per ARCHITECTURE.md §7:
    /// read the global superblock, then replay each logical shard's Delta
    /// Log tail on top of the base InoMap.
    pub fn open(_path: &std::path::Path) -> Result<Self, PoolError> {
        todo!("lchfs-store: Pool::open — see ARCHITECTURE.md §7")
    }

    /// ARCHITECTURE.md §4 (read path).
    pub fn read(&self, _ino: u64, _offset: u64, _len: u32) -> Result<Bytes, PoolError> {
        todo!("lchfs-store: Pool::read")
    }

    /// ARCHITECTURE.md §3 (write path): routes through the logical-shard
    /// ingress ring for `ino`'s shard (Phase B: direct single-threaded
    /// path; Phase E: full sharded ingress).
    pub fn write(&self, _ino: u64, _offset: u64, _buf: &[u8]) -> Result<(), PoolError> {
        todo!("lchfs-store: Pool::write")
    }

    pub fn lookup(&self, _parent_ino: u64, _name: &str) -> Result<Option<u64>, PoolError> {
        todo!("lchfs-store: Pool::lookup")
    }

    /// The fast per-shard fsync path (ARCHITECTURE.md §3, "Subtree
    /// durability via per-shard delta logs") — O(this shard's dirty data),
    /// not O(all dirty data pool-wide).
    pub fn fsync(&self, _ino: u64) -> Result<(), PoolError> {
        todo!("lchfs-store: Pool::fsync — see ARCHITECTURE.md §3")
    }

    /// Forces a full global checkpoint (ARCHITECTURE.md §3, the 5-step
    /// process) regardless of the per-shard fast path — used by unmount,
    /// periodic epochs, and explicit consolidation.
    pub fn checkpoint(&self) -> Result<(), PoolError> {
        todo!("lchfs-store: Pool::checkpoint")
    }
}
