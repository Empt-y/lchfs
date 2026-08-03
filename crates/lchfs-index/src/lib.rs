//! Persisted and in-memory indexes over the Merkle DAG. ARCHITECTURE.md §4
//! ("Read path"): **the index is a rebuildable cache, never authoritative**.
//! The DAG itself (lchfs-format objects, walked via lchfs-store) is always
//! ground truth; this crate exists purely to make reads fast.
//!
//! No FUSE dependency here — see ARCHITECTURE.md §5a (kernel-independence
//! boundary). This crate also has no dependency on `lchfs-store`; `store`
//! depends on `index`, not the reverse (ARCHITECTURE.md §11).

use lchfs_format::{ExtentLocation, Hash32, InodeObject};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
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

const CHUNK_LOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chunk_locations");
const INODE_HASHES: TableDefinition<u64, &[u8]> = TableDefinition::new("inode_hashes");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const GENERATION_KEY: &str = "generation";

fn encode_location(loc: ExtentLocation) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&loc.segment_id.to_le_bytes());
    buf[8..12].copy_from_slice(&loc.offset.to_le_bytes());
    buf[12..16].copy_from_slice(&loc.len.to_le_bytes());
    buf
}

fn decode_location(bytes: &[u8]) -> Result<ExtentLocation, IndexError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| IndexError::Corrupt)?;
    Ok(ExtentLocation {
        segment_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        offset: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        len: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
    })
}

fn err(e: impl std::fmt::Display) -> IndexError {
    IndexError::Backend(e.to_string())
}

/// `redb`-backed `IndexStore` implementation. Every `put_*` commits with
/// `Durability::None` (cheap, buffered) since the index is never
/// authoritative — only `checkpoint` forces an `Immediate` (fsync'd)
/// commit, mirroring `Pool`'s own checkpoint being the actual durability
/// barrier for the DAG itself.
pub struct RedbIndex {
    db: Database,
    generation: AtomicU64,
}

impl RedbIndex {
    /// Creates a fresh, empty index at `path` (must not already exist).
    pub fn create(path: &Path) -> Result<Self, IndexError> {
        let db = Database::create(path).map_err(err)?;
        let txn = db.begin_write().map_err(err)?;
        txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        txn.open_table(INODE_HASHES).map_err(err)?;
        {
            let mut meta = txn.open_table(META).map_err(err)?;
            meta.insert(GENERATION_KEY, 0u64).map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(Self {
            db,
            generation: AtomicU64::new(0),
        })
    }

    /// Opens an existing index at `path`.
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        let db = Database::open(path).map_err(err)?;
        let generation = {
            let txn = db.begin_read().map_err(err)?;
            let table = txn.open_table(META).map_err(err)?;
            table
                .get(GENERATION_KEY)
                .map_err(err)?
                .map(|v| v.value())
                .unwrap_or(0)
        };
        Ok(Self {
            db,
            generation: AtomicU64::new(generation),
        })
    }

    /// Forces a durable (`Durability::Immediate`) commit of whatever's
    /// currently pending, *without* touching the checkpoint/`generation`
    /// metadata `checkpoint()` updates. Used by the Coalescing Daemon
    /// (coalesce.rs) before deleting an old segment: the repointed chunk
    /// locations must be durable first, but a coalesce pass has no
    /// business claiming a new checkpoint generation happened -- that's
    /// still `Pool::checkpoint()`'s job alone.
    pub fn flush(&mut self) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        txn.commit().map_err(err)?;
        Ok(())
    }

    /// Loads every persisted chunk location at once — the mount-time fast
    /// path (ARCHITECTURE.md §4) that lets `Pool::open` skip a full
    /// segment scan when this index's generation matches the superblock's
    /// `index_generation`.
    pub fn iter_chunk_locations(&self) -> Result<Vec<(Hash32, ExtentLocation)>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            let hash: [u8; 32] = k.value().try_into().map_err(|_| IndexError::Corrupt)?;
            out.push((Hash32(hash), decode_location(v.value())?));
        }
        Ok(out)
    }
}

impl IndexStore for RedbIndex {
    fn get_chunk_location(&self, hash: Hash32) -> Result<Option<ExtentLocation>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        match table.get(hash.0.as_slice()).map_err(err)? {
            Some(v) => Ok(Some(decode_location(v.value())?)),
            None => Ok(None),
        }
    }

    fn put_chunk_location(&mut self, hash: Hash32, loc: ExtentLocation) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::None).map_err(err)?;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            table
                .insert(hash.0.as_slice(), encode_location(loc).as_slice())
                .map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    fn get_inode_hash(&self, ino: u64) -> Result<Option<Hash32>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(INODE_HASHES).map_err(err)?;
        match table.get(ino).map_err(err)? {
            Some(v) => {
                let bytes: [u8; 32] = v.value().try_into().map_err(|_| IndexError::Corrupt)?;
                Ok(Some(Hash32(bytes)))
            }
            None => Ok(None),
        }
    }

    fn put_inode_hash(&mut self, ino: u64, hash: Hash32) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::None).map_err(err)?;
        {
            let mut table = txn.open_table(INODE_HASHES).map_err(err)?;
            table.insert(ino, hash.0.as_slice()).map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    fn checkpoint(&mut self, generation: u64) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        {
            let mut meta = txn.open_table(META).map_err(err)?;
            meta.insert(GENERATION_KEY, generation).map_err(err)?;
        }
        txn.commit().map_err(err)?;
        self.generation.store(generation, Ordering::Release);
        Ok(())
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// In-memory `ino -> {current_hash, decoded InodeObject}` cache plus
/// `(parent_ino, name) -> ino` directory-entry cache. ARCHITECTURE.md §4.
#[derive(Default)]
pub struct ActiveTreeCache {
    // TODO(phase-E): HashMap<u64, (Hash32, InodeObject)> + HashMap<(u64, String), u64>
    // -- not yet consumed by Pool, which still keeps its own equivalent
    // maps directly; wiring Pool through this is bundled with Phase E's
    // sharding refactor rather than done piecemeal now.
}

impl ActiveTreeCache {
    pub fn get(&self, _ino: u64) -> Option<(Hash32, &InodeObject)> {
        todo!("lchfs-index: ActiveTreeCache::get")
    }
}

/// Number of internal buckets `ChunkLocationCache` shards its map across.
/// Phase E (ARCHITECTURE.md §5): this is on the hot path for every prep-
/// pool dedup lookup across K committer/prep threads, so a single global
/// `RwLock<HashMap<..>>` would itself become a contention point exactly
/// where the sharding design is trying to avoid one. A fixed bucket count
/// (rather than one lock per logical shard) keeps this independent of
/// `PoolParams::logical_shard_count` — this cache's job is pure content-
/// hash lookup, unrelated to inode-ordering shards.
const CHUNK_LOCATION_CACHE_BUCKETS: usize = 64;

fn bucket_for(hash: Hash32) -> usize {
    (hash.0[0] as usize) % CHUNK_LOCATION_CACHE_BUCKETS
}

/// In-memory `content_hash -> {segment_id, offset, len}` cache, the hot
/// path in front of `IndexStore::get_chunk_location`. ARCHITECTURE.md §4.
pub struct ChunkLocationCache {
    buckets: Vec<RwLock<HashMap<Hash32, ExtentLocation>>>,
}

impl Default for ChunkLocationCache {
    fn default() -> Self {
        Self {
            buckets: (0..CHUNK_LOCATION_CACHE_BUCKETS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
        }
    }
}

impl ChunkLocationCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, hash: Hash32) -> Option<ExtentLocation> {
        let bucket = self.buckets[bucket_for(hash)]
            .read()
            .expect("ChunkLocationCache lock poisoned");
        bucket.get(&hash).copied()
    }

    /// Insert or overwrite `hash`'s location. Used both by the inline
    /// dedup-on-write fast path (a miss followed by a fresh write) and by
    /// the Coalescing/Dedup daemons (E.11/E.12) repointing a hash at a new
    /// canonical location — content-addressing means the newer value is
    /// always for the same bytes, so a plain overwrite is always correct,
    /// no merge logic needed.
    pub fn put(&self, hash: Hash32, loc: ExtentLocation) {
        let mut bucket = self.buckets[bucket_for(hash)]
            .write()
            .expect("ChunkLocationCache lock poisoned");
        bucket.insert(hash, loc);
    }

    /// Bulk-load every entry, e.g. from `RedbIndex::iter_chunk_locations`
    /// on the mount-time fast path, or from a full segment scan on the
    /// cold-rebuild path.
    pub fn extend(&self, entries: impl IntoIterator<Item = (Hash32, ExtentLocation)>) {
        for (hash, loc) in entries {
            self.put(hash, loc);
        }
    }

    pub fn len(&self) -> usize {
        self.buckets
            .iter()
            .map(|b| b.read().expect("ChunkLocationCache lock poisoned").len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
