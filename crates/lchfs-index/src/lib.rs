//! Persisted and in-memory indexes over the Merkle DAG. ARCHITECTURE.md §4
//! ("Read path"): **the index is a rebuildable cache, never authoritative**.
//! The DAG itself (lchfs-format objects, walked via lchfs-store) is always
//! ground truth; this crate exists purely to make reads fast.
//!
//! No FUSE dependency here — see ARCHITECTURE.md §5a (kernel-independence
//! boundary). This crate also has no dependency on `lchfs-store`; `store`
//! depends on `index`, not the reverse (ARCHITECTURE.md §11).

use lchfs_format::{ExtentLocation, Hash32};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use thiserror::Error;

/// Abstraction over the persisted index backend. Phase 1 implementation is
/// `RedbIndex` (pure-Rust embedded KV, a stated pragmatic choice over
/// hand-rolling an LSM — ARCHITECTURE.md §4); this trait exists so that
/// choice can change later without touching callers.
pub trait IndexStore {
    /// The preferred replica's location -- the lowest `vdev_id` holding this
    /// hash. Callers that only need "where can I read this" use this; read
    /// failover uses `chunk_locations` to see the alternates.
    fn get_chunk_location(&self, hash: Hash32) -> Result<Option<ExtentLocation>, IndexError>;
    /// Every replica of `hash`, ascending by `vdev_id` (ARCHITECTURE.md §15.2).
    fn chunk_locations(&self, hash: Hash32) -> Result<Vec<(u16, ExtentLocation)>, IndexError>;
    fn put_chunk_location(
        &mut self,
        hash: Hash32,
        vdev_id: u16,
        loc: ExtentLocation,
    ) -> Result<(), IndexError>;

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
/// A conversion's old-hash -> new-hash map (ARCHITECTURE.md §18): content
/// rewritten into a new key epoch once is found again by its old address
/// without reading it back. Advisory like the rest of the index -- lost on
/// a rebuild, which only costs the conversion re-reads.
const REKEY_MEMO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rekey_memo");
const GENERATION_KEY: &str = "generation";

/// `CHUNK_LOCATIONS` key: `hash || vdev_id` (little-endian u16).
///
/// Composite key rather than a redb multimap (ARCHITECTURE.md §15.1). redb
/// keys are ordered, so every replica of one hash is contiguous and a range
/// scan over `hash||0x0000 ..= hash||0xFFFF` yields them all. The *value*
/// stays the unchanged 16-byte location encoding, so nothing that already
/// reads a location has to care.
fn encode_chunk_key(hash: Hash32, vdev_id: u16) -> [u8; 34] {
    let mut k = [0u8; 34];
    k[0..32].copy_from_slice(&hash.0);
    k[32..34].copy_from_slice(&vdev_id.to_le_bytes());
    k
}

fn chunk_key_bounds(hash: Hash32) -> ([u8; 34], [u8; 34]) {
    (encode_chunk_key(hash, u16::MIN), encode_chunk_key(hash, u16::MAX))
}

fn decode_chunk_key(bytes: &[u8]) -> Result<(Hash32, u16), IndexError> {
    let bytes: [u8; 34] = bytes.try_into().map_err(|_| IndexError::Corrupt)?;
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes[0..32]);
    Ok((Hash32(h), u16::from_le_bytes([bytes[32], bytes[33]])))
}

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
        Ok(self
            .iter_preferred_locations()?
            .into_iter()
            .map(|(hash, _, loc)| (hash, loc))
            .collect())
    }

    /// `iter_chunk_locations` with the preferred replica's `vdev_id` too,
    /// so a caller can tell a striped-only record from a mirrored one.
    pub fn iter_preferred_locations(&self) -> Result<Vec<(Hash32, u16, ExtentLocation)>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        // Keys sort by hash then vdev_id, so the first entry seen for a hash
        // is its lowest-numbered replica -- the preferred one. Callers of
        // this want a hash->where-to-read map (it warms ChunkLocationCache),
        // not every replica, so later ones are skipped.
        let mut out: Vec<(Hash32, u16, ExtentLocation)> = Vec::new();
        for entry in table.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            let (hash, vdev_id) = decode_chunk_key(k.value())?;
            if out.last().is_some_and(|(prev, _, _)| *prev == hash) {
                continue;
            }
            out.push((hash, vdev_id, decode_location(v.value())?));
        }
        Ok(out)
    }
}

impl RedbIndex {
    /// Every `(hash, vdev_id, location)` the index holds, ordered by hash
    /// then vdev -- so one hash's replicas are contiguous. What resilver
    /// walks (ARCHITECTURE.md §15.4); everything else wants the collapsed
    /// `iter_chunk_locations`.
    pub fn iter_all_chunk_locations(&self) -> Result<Vec<(Hash32, u16, ExtentLocation)>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            let (hash, vdev_id) = decode_chunk_key(k.value())?;
            out.push((hash, vdev_id, decode_location(v.value())?));
        }
        Ok(out)
    }

    /// Many `put_chunk_location`s in one transaction. What the committer
    /// flushes its per-shard batch through: one `begin_write`/`commit`
    /// per batch instead of per record, which is the difference between
    /// the index being a lock every chunk takes and one a batch takes.
    pub fn put_chunk_locations(
        &mut self,
        entries: impl IntoIterator<Item = (Hash32, u16, ExtentLocation)>,
    ) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::None).map_err(err)?;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            for (hash, vdev_id, loc) in entries {
                table
                    .insert(
                        encode_chunk_key(hash, vdev_id).as_slice(),
                        encode_location(loc).as_slice(),
                    )
                    .map_err(err)?;
            }
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    /// A page of `(hash, vdev_id, location)` entries in key order, starting
    /// strictly after `after` (or from the beginning), at most `limit` long.
    /// What a pass over the whole index uses instead of
    /// `iter_all_chunk_locations`: a page at a time, so the index lock is
    /// held for a page and the pass costs a page of memory, not the pool.
    pub fn chunk_locations_page(
        &self,
        after: Option<(Hash32, u16)>,
        limit: usize,
    ) -> Result<Vec<(Hash32, u16, ExtentLocation)>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        let mut out = Vec::with_capacity(limit);
        let start = after.map(|(hash, vdev_id)| encode_chunk_key(hash, vdev_id));
        let lower = match &start {
            Some(key) => std::ops::Bound::Excluded(key.as_slice()),
            None => std::ops::Bound::Unbounded,
        };
        let range = table
            .range::<&[u8]>((lower, std::ops::Bound::Unbounded))
            .map_err(err)?;
        for entry in range.take(limit) {
            let (k, v) = entry.map_err(err)?;
            let (hash, vdev_id) = decode_chunk_key(k.value())?;
            out.push((hash, vdev_id, decode_location(v.value())?));
        }
        Ok(out)
    }

    /// Moves a segment's records from mirror entries to the striped entry,
    /// in one transaction: for each `(hash, loc)`, writes `(hash, STRIPED)`
    /// and removes `(hash, v)` for every `v` in `forget` whose location
    /// is in `segment_id`. Entries on other segments -- a mirror copy of
    /// the same content elsewhere -- are left alone: they are real.
    pub fn restripe_segment(
        &mut self,
        segment_id: u64,
        records: &[(Hash32, ExtentLocation)],
        forget: &[u16],
    ) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            for (hash, loc) in records {
                for &v in forget {
                    let key = encode_chunk_key(*hash, v);
                    let stale = table
                        .get(key.as_slice())
                        .map_err(err)?
                        .map(|g| decode_location(g.value()))
                        .transpose()?
                        .is_some_and(|l| l.segment_id == segment_id);
                    if stale {
                        table.remove(key.as_slice()).map_err(err)?;
                    }
                }
                table
                    .insert(
                        encode_chunk_key(*hash, STRIPED_VDEV).as_slice(),
                        encode_location(*loc).as_slice(),
                    )
                    .map_err(err)?;
            }
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    /// The inverse of `restripe_segment`: a striped segment's records got
    /// mirrored copies at `new_locs` on `vdevs`; write those and drop the
    /// striped entries that pointed into `segment_id`.
    pub fn unstripe_segment(
        &mut self,
        segment_id: u64,
        records: &[(Hash32, ExtentLocation)],
        vdevs: &[u16],
    ) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            for (hash, new_loc) in records {
                let key = encode_chunk_key(*hash, STRIPED_VDEV);
                let stale = table
                    .get(key.as_slice())
                    .map_err(err)?
                    .map(|g| decode_location(g.value()))
                    .transpose()?
                    .is_some_and(|l| l.segment_id == segment_id);
                if stale {
                    table.remove(key.as_slice()).map_err(err)?;
                }
                for &v in vdevs {
                    table
                        .insert(encode_chunk_key(*hash, v).as_slice(), encode_location(*new_loc).as_slice())
                        .map_err(err)?;
                }
            }
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    /// Forgets every entry for one vdev, returning how many there were.
    /// What replacing a device needs: the slot's old entries describe
    /// copies on hardware that is gone, and a resilver that trusted them
    /// would copy nothing onto the blank replacement.
    pub fn delete_vdev_locations(&mut self, vdev_id: u16) -> Result<usize, IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        let removed = {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            let doomed: Vec<Vec<u8>> = table
                .iter()
                .map_err(err)?
                .filter_map(|entry| {
                    let (k, _) = entry.ok()?;
                    let (_, v) = decode_chunk_key(k.value()).ok()?;
                    (v == vdev_id).then(|| k.value().to_vec())
                })
                .collect();
            for key in &doomed {
                table.remove(key.as_slice()).map_err(err)?;
            }
            doomed.len()
        };
        txn.commit().map_err(err)?;
        Ok(removed)
    }

    /// Drops the entry for each `(hash, vdev)` in `entries`, but only where
    /// it still points into `segment_id`, in one transaction; returns how
    /// many went. What reclaiming dead records needs: coalesce deletes the
    /// segment that held them, and an entry left behind is a dedup target
    /// for bytes that no longer exist -- the next write of identical
    /// content resolves against it, and the file it lands in references a
    /// record nothing can read. An entry that has since moved (relocated,
    /// or rewritten by a fresh copy of the same content) is real and kept.
    pub fn forget_segment_records(
        &mut self,
        segment_id: u64,
        entries: &[(Hash32, u16)],
    ) -> Result<usize, IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        let mut removed = 0;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            for &(hash, vdev_id) in entries {
                let key = encode_chunk_key(hash, vdev_id);
                let stale = table
                    .get(key.as_slice())
                    .map_err(err)?
                    .map(|g| decode_location(g.value()))
                    .transpose()?
                    .is_some_and(|l| l.segment_id == segment_id);
                if stale {
                    table.remove(key.as_slice()).map_err(err)?;
                    removed += 1;
                }
            }
        }
        txn.commit().map_err(err)?;
        Ok(removed)
    }

    /// The new-epoch address recorded for `old` during a conversion.
    pub fn get_rekey_memo(&self, old: Hash32) -> Result<Option<Hash32>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = match txn.open_table(REKEY_MEMO) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        let Some(v) = table.get(old.0.as_slice()).map_err(err)? else {
            return Ok(None);
        };
        let bytes: [u8; 32] = v.value().try_into().map_err(|_| IndexError::Corrupt)?;
        Ok(Some(Hash32(bytes)))
    }

    /// Records that `old` was rewritten as `new`. Buffered, like every put.
    pub fn put_rekey_memo(&mut self, old: Hash32, new: Hash32) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::None).map_err(err)?;
        {
            let mut table = txn.open_table(REKEY_MEMO).map_err(err)?;
            table.insert(old.0.as_slice(), new.0.as_slice()).map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    /// Rewrites this index into a brand-new file at `path` (where it lives)
    /// holding only what is live: every chunk location and the metadata,
    /// not the conversion memo. What retiring a key epoch ends with -- a
    /// B-tree file keeps the bytes of pages it has freed, so the old
    /// epoch's addresses (for a converted plaintext pool, the unkeyed hash
    /// of every chunk) would otherwise stay readable in it.
    ///
    /// Built beside the old file, fsynced, then renamed over it; a crash
    /// leaves one or the other whole. The open handle moves to the new
    /// file, which the rename does not disturb.
    pub fn rewrite_fresh(&mut self, path: &Path) -> Result<(), IndexError> {
        self.rewrite_fresh_keeping(path, |_, _, _| true)
    }

    /// `rewrite_fresh`, copying only the chunk locations `keep` accepts --
    /// so an entry left naming a segment that no longer exists does not
    /// carry its hash into the new file.
    pub fn rewrite_fresh_keeping(
        &mut self,
        path: &Path,
        keep: impl Fn(Hash32, u16, ExtentLocation) -> bool,
    ) -> Result<(), IndexError> {
        let tmp = path.with_extension("redb.tmp");
        let _ = std::fs::remove_file(&tmp);
        let fresh = Database::create(&tmp).map_err(err)?;
        {
            let read = self.db.begin_read().map_err(err)?;
            let mut txn = fresh.begin_write().map_err(err)?;
            txn.set_durability(Durability::Immediate).map_err(err)?;
            {
                let from = read.open_table(CHUNK_LOCATIONS).map_err(err)?;
                let mut to = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
                for entry in from.iter().map_err(err)? {
                    let (k, v) = entry.map_err(err)?;
                    let (hash, vdev_id) = decode_chunk_key(k.value())?;
                    if keep(hash, vdev_id, decode_location(v.value())?) {
                        to.insert(k.value(), v.value()).map_err(err)?;
                    }
                }
            }
            {
                let from = read.open_table(INODE_HASHES).map_err(err)?;
                let mut to = txn.open_table(INODE_HASHES).map_err(err)?;
                for entry in from.iter().map_err(err)? {
                    let (k, v) = entry.map_err(err)?;
                    to.insert(k.value(), v.value()).map_err(err)?;
                }
            }
            {
                let from = read.open_table(META).map_err(err)?;
                let mut to = txn.open_table(META).map_err(err)?;
                for entry in from.iter().map_err(err)? {
                    let (k, v) = entry.map_err(err)?;
                    to.insert(k.value(), v.value()).map_err(err)?;
                }
            }
            txn.commit().map_err(err)?;
        }
        std::fs::rename(&tmp, path).map_err(err)?;
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(err)?;
        }
        self.db = fresh;
        Ok(())
    }

    /// Forgets one replica's entry. Not used by the engine itself -- a
    /// device that misses writes simply never gets the entry -- but it is
    /// how a test manufactures that state without taking a vdev offline.
    pub fn delete_chunk_location(&mut self, hash: Hash32, vdev_id: u16) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::Immediate).map_err(err)?;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            table
                .remove(encode_chunk_key(hash, vdev_id).as_slice())
                .map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(())
    }
}

impl IndexStore for RedbIndex {
    fn get_chunk_location(&self, hash: Hash32) -> Result<Option<ExtentLocation>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        let (lo, hi) = chunk_key_bounds(hash);
        match table.range(lo.as_slice()..=hi.as_slice()).map_err(err)?.next() {
            Some(entry) => {
                let (_k, v) = entry.map_err(err)?;
                Ok(Some(decode_location(v.value())?))
            }
            None => Ok(None),
        }
    }

    fn chunk_locations(&self, hash: Hash32) -> Result<Vec<(u16, ExtentLocation)>, IndexError> {
        let txn = self.db.begin_read().map_err(err)?;
        let table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
        let (lo, hi) = chunk_key_bounds(hash);
        let mut out = Vec::new();
        for entry in table.range(lo.as_slice()..=hi.as_slice()).map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            let (_h, vdev_id) = decode_chunk_key(k.value())?;
            out.push((vdev_id, decode_location(v.value())?));
        }
        Ok(out)
    }

    fn put_chunk_location(
        &mut self,
        hash: Hash32,
        vdev_id: u16,
        loc: ExtentLocation,
    ) -> Result<(), IndexError> {
        let mut txn = self.db.begin_write().map_err(err)?;
        txn.set_durability(Durability::None).map_err(err)?;
        {
            let mut table = txn.open_table(CHUNK_LOCATIONS).map_err(err)?;
            table
                .insert(
                    encode_chunk_key(hash, vdev_id).as_slice(),
                    encode_location(loc).as_slice(),
                )
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
/// The `vdev_id` an erasure-coded record's index entry is keyed under
/// (ARCHITECTURE.md §17.2.2). Defined here because it is an index key;
/// `lchfs_store::stripe::STRIPED` re-exports it. `u16::MAX` sorts last,
/// so a surviving mirror copy is still the preferred replica.
pub const STRIPED_VDEV: u16 = u16::MAX;

pub struct ChunkLocationCache {
    /// The preferred replica: its location and the device it is on --
    /// `STRIPED_VDEV` for a record whose preferred copy is a stripe. A
    /// reader needs both before it opens anything: a mirror location is
    /// only good on the device that holds that copy. Fan-out writes put
    /// the identical record at the identical offset on every device in a
    /// segment's set, which is why this used to carry only "striped or
    /// not" and assume the primary; a heal segment lives on one device,
    /// and once the original mirror is striped away that single copy is
    /// the preferred replica, on a device that is not the primary.
    buckets: Vec<RwLock<HashMap<Hash32, (ExtentLocation, u16)>>>,
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
        self.get_tagged(hash).map(|(loc, _)| loc)
    }

    /// The location and the device it is on, `STRIPED_VDEV` for a stripe.
    pub fn get_tagged(&self, hash: Hash32) -> Option<(ExtentLocation, u16)> {
        let bucket = self.buckets[bucket_for(hash)]
            .read()
            .expect("ChunkLocationCache lock poisoned");
        bucket.get(&hash).copied()
    }

    /// `put` for a record whose preferred copy is in a striped segment.
    pub fn put_striped(&self, hash: Hash32, loc: ExtentLocation) {
        self.put(hash, loc, STRIPED_VDEV);
    }

    /// Insert or overwrite `hash`'s preferred replica: `loc` on
    /// `vdev_id`. Used both by the inline dedup-on-write fast path (a miss
    /// followed by a fresh write) and by the Coalescing/Dedup daemons
    /// (E.11/E.12) repointing a hash at a new canonical location --
    /// content-addressing means the newer value is always for the same
    /// bytes, so a plain overwrite is always correct, no merge logic
    /// needed.
    pub fn put(&self, hash: Hash32, loc: ExtentLocation, vdev_id: u16) {
        let mut bucket = self.buckets[bucket_for(hash)]
            .write()
            .expect("ChunkLocationCache lock poisoned");
        bucket.insert(hash, (loc, vdev_id));
    }

    /// Removes `hash`'s entry if it is the copy in `segment_id` on
    /// `vdev_id`, returning what was removed so a caller that backs out
    /// can `put_if_absent` it again. Anything else -- no entry, or one
    /// that has already moved -- is left alone.
    pub fn remove_if_in(&self, hash: Hash32, segment_id: u64, vdev_id: u16) -> Option<(ExtentLocation, u16)> {
        let mut bucket = self.buckets[bucket_for(hash)]
            .write()
            .expect("ChunkLocationCache lock poisoned");
        match bucket.get(&hash) {
            Some(&(loc, v)) if loc.segment_id == segment_id && v == vdev_id => bucket.remove(&hash),
            _ => None,
        }
    }

    /// `put`, unless `hash` already has an entry -- which, the content
    /// being the same, is at least as current as the one offered here.
    pub fn put_if_absent(&self, hash: Hash32, loc: ExtentLocation, vdev_id: u16) {
        let mut bucket = self.buckets[bucket_for(hash)]
            .write()
            .expect("ChunkLocationCache lock poisoned");
        bucket.entry(hash).or_insert((loc, vdev_id));
    }

    /// Bulk-load preferred replicas as `iter_preferred_locations` yields
    /// them: on the mount-time fast path, on a promotion, or from a full
    /// segment scan on the cold-rebuild path.
    pub fn extend(&self, entries: impl IntoIterator<Item = (Hash32, u16, ExtentLocation)>) {
        for (hash, vdev_id, loc) in entries {
            self.put(hash, loc, vdev_id);
        }
    }

    /// Drops every entry -- what a promotion does before warming the cache
    /// from the new primary's index, since the old entries were the old
    /// primary's offsets.
    pub fn clear(&self) {
        for bucket in &self.buckets {
            bucket.write().expect("ChunkLocationCache lock poisoned").clear();
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

/// Refcounted set of content hashes with an in-flight dedup-hit write that
/// hasn't yet been captured by a published root.
///
/// GC's mark phase (lchfs-store's `gc.rs`/`dag_walk.rs`) only ever finds
/// content live by walking the *current* root's DAG. A write that resolves
/// against an existing physical location (a dedup hit: `prep.rs`'s
/// `PreparedChunk::Dedup`) starts depending on that location immediately,
/// but the InodeObject/IndirectHashList that will actually *reference* the
/// hash isn't durable and DAG-reachable until the next checkpoint publishes
/// a new root. In between, a concurrent Coalescing Daemon pass, walking the
/// *old* root, would correctly see the hash as unreferenced and could
/// reclaim its only physical copy out from under the in-flight write --
/// silent, durable data loss with no crash or error involved.
///
/// This registry closes that gap: `prepare_chunk` pins a hash *before* it
/// looks it up, keeping the pin only on a hit; `Pool::run_checkpoint` unpins each hash actually
/// captured by the root it just published, once that root is durable and
/// visible (see that function for exactly where). `GcEngine`/`CoalesceDaemon`
/// treat every currently-pinned hash's location as live, in addition to
/// whatever the DAG walk itself finds.
///
/// Pin-then-look-up is what makes the pin airtight. Before deleting a
/// segment, coalesce removes its dead records from `ChunkLocationCache`
/// and only then checks their pins. A write whose lookup came before that
/// removal took its pin earlier still, so the check sees it and coalesce
/// backs off; a lookup after it misses and the write stores a fresh copy.
/// Look-up-then-pin leaves a window where the write holds a location and
/// no pin yet, and a pass can check, find nothing, and delete.
///
/// Refcounted, not a plain set, because the same hash can be pinned by
/// multiple concurrent dedup-hit writes (or the same write's multiple
/// chunks) before any of them are checkpointed -- a hash stays protected
/// until every pin on it has been released.
#[derive(Default)]
pub struct PendingDedupPins {
    refcounts: Mutex<HashMap<Hash32, u32>>,
}

impl PendingDedupPins {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pin(&self, hash: Hash32) {
        let mut refcounts = self.refcounts.lock().expect("PendingDedupPins lock poisoned");
        *refcounts.entry(hash).or_insert(0) += 1;
    }

    /// Safe no-op if `hash` isn't currently pinned -- callers unpin every
    /// chunk hash referenced by a freshly-checkpointed file unconditionally,
    /// including ones that were never a dedup hit to begin with.
    pub fn unpin(&self, hash: Hash32) {
        let mut refcounts = self.refcounts.lock().expect("PendingDedupPins lock poisoned");
        if let std::collections::hash_map::Entry::Occupied(mut e) = refcounts.entry(hash) {
            *e.get_mut() -= 1;
            if *e.get() == 0 {
                e.remove();
            }
        }
    }

    pub fn is_pinned(&self, hash: Hash32) -> bool {
        self.refcounts
            .lock()
            .expect("PendingDedupPins lock poisoned")
            .contains_key(&hash)
    }

    /// Every currently-pinned hash, for GC's mark phase to union into its
    /// DAG-walk-derived live set.
    pub fn snapshot(&self) -> Vec<Hash32> {
        self.refcounts
            .lock()
            .expect("PendingDedupPins lock poisoned")
            .keys()
            .copied()
            .collect()
    }
}
