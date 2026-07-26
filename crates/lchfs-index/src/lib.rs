//! Persisted and in-memory indexes over the Merkle DAG. ARCHITECTURE.md §4
//! ("Read path"): **the index is a rebuildable cache, never authoritative**.
//! The DAG itself (lchfs-format objects, walked via lchfs-store) is always
//! ground truth; this crate exists purely to make reads fast.
//!
//! No FUSE dependency here — see ARCHITECTURE.md §5a (kernel-independence
//! boundary). This crate also has no dependency on `lchfs-store`; `store`
//! depends on `index`, not the reverse (ARCHITECTURE.md §11).

use lchfs_format::{ExtentLocation, Hash32, InodeObject};
use thiserror::Error;

/// Abstraction over the persisted index backend. Phase 1 implementation is
/// `RedbIndex` (pure-Rust embedded KV, a stated pragmatic choice over
/// hand-rolling an LSM — ARCHITECTURE.md §4); this trait exists so that
/// choice can change later without touching callers.
pub trait IndexStore {
    fn get_chunk_location(&self, hash: Hash32) -> Result<Option<ExtentLocation>, IndexError>;
    fn put_chunk_location(&mut self, hash: Hash32, loc: ExtentLocation) -> Result<(), IndexError>;

    fn get_inode_hash(&self, ino: u64) -> Result<Option<Hash32>, IndexError>;
    fn put_inode_hash(&mut self, ino: u64, hash: Hash32) -> Result<(), IndexError>;

    /// Checkpoint the index (once per epoch, per ARCHITECTURE.md §4),
    /// recording the generation superblocks compare against at mount.
    fn checkpoint(&mut self, generation: u64) -> Result<(), IndexError>;

    /// The generation of the last checkpoint, compared against the
    /// superblock's `index_generation` at mount to decide fast-mount vs.
    /// lazy/full DAG-walk rebuild (ARCHITECTURE.md §4).
    fn generation(&self) -> u64;
}

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("index backend error: {0}")]
    Backend(String),
    #[error("index corrupt or unreadable, rebuild required")]
    Corrupt,
}

/// `redb`-backed `IndexStore` implementation.
pub struct RedbIndex {
    // TODO(phase-C): redb::Database handle + table definitions
}

impl RedbIndex {
    pub fn open(_path: &std::path::Path) -> Result<Self, IndexError> {
        todo!("lchfs-index: RedbIndex::open — see ARCHITECTURE.md §4")
    }
}

impl IndexStore for RedbIndex {
    fn get_chunk_location(&self, _hash: Hash32) -> Result<Option<ExtentLocation>, IndexError> {
        todo!("lchfs-index: RedbIndex::get_chunk_location")
    }

    fn put_chunk_location(&mut self, _hash: Hash32, _loc: ExtentLocation) -> Result<(), IndexError> {
        todo!("lchfs-index: RedbIndex::put_chunk_location")
    }

    fn get_inode_hash(&self, _ino: u64) -> Result<Option<Hash32>, IndexError> {
        todo!("lchfs-index: RedbIndex::get_inode_hash")
    }

    fn put_inode_hash(&mut self, _ino: u64, _hash: Hash32) -> Result<(), IndexError> {
        todo!("lchfs-index: RedbIndex::put_inode_hash")
    }

    fn checkpoint(&mut self, _generation: u64) -> Result<(), IndexError> {
        todo!("lchfs-index: RedbIndex::checkpoint")
    }

    fn generation(&self) -> u64 {
        todo!("lchfs-index: RedbIndex::generation")
    }
}

/// In-memory `ino -> {current_hash, decoded InodeObject}` cache plus
/// `(parent_ino, name) -> ino` directory-entry cache. ARCHITECTURE.md §4.
#[derive(Default)]
pub struct ActiveTreeCache {
    // TODO(phase-C): HashMap<u64, (Hash32, InodeObject)> + HashMap<(u64, String), u64>
}

impl ActiveTreeCache {
    pub fn get(&self, _ino: u64) -> Option<(Hash32, &InodeObject)> {
        todo!("lchfs-index: ActiveTreeCache::get")
    }
}

/// In-memory `content_hash -> {segment_id, offset, len}` cache, the hot
/// path in front of `IndexStore::get_chunk_location`. ARCHITECTURE.md §4.
#[derive(Default)]
pub struct ChunkLocationCache {
    // TODO(phase-C): HashMap<Hash32, ExtentLocation>, likely with an eviction policy
}

impl ChunkLocationCache {
    pub fn get(&self, _hash: Hash32) -> Option<ExtentLocation> {
        todo!("lchfs-index: ChunkLocationCache::get")
    }
}
