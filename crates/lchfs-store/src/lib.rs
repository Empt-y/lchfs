//! The LCHFS engine. ARCHITECTURE.md §3 (write path), §4 (read path), §5
//! (concurrency), §6 (GC), §7 (crash recovery).
//!
//! **Kernel-independence boundary (ARCHITECTURE.md §5a):** this crate has
//! zero knowledge of FUSE. `Pool` is the entire public surface a frontend
//! (today `lchfs-fuse`, potentially a future kernel module) is expected to
//! call. No `fuser`/`nix` dependency here, by design — do not add one.
//!
//! **Phase B scope** (ARCHITECTURE.md §12: "single-threaded (no sharding
//! yet) — segment writer, superblock rotation, basic checkpoint, wire in
//! chunk/compress. Validates pillars 1 and 3 before concurrency is added"):
//! everything in this file runs under one `parking_lot::Mutex` — no
//! logical shards, no Ingest Preparation Pool, no per-shard Delta Log (all
//! explicitly deferred to Phase E in ingress.rs/prep.rs/delta_log.rs).
//! `Pool::fsync` therefore runs the same full checkpoint as
//! `Pool::checkpoint` rather than the fast per-shard path §3 describes —
//! that optimization requires the Phase E machinery this Pool doesn't have
//! yet.
//!
//! **No persisted index yet** (that's Phase C's `lchfs-index`): `Pool::open`
//! rebuilds an in-memory `Hash32 -> ExtentLocation` map by scanning every
//! segment once at mount time. This is exactly the "cold rebuild" path
//! ARCHITECTURE.md §4 describes for an index_generation mismatch — Phase B
//! just always takes it, since there's no cached index to compare against.

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
use lchfs_chunk::{ChunkBoundary, Chunker, FastCdcChunker};
use lchfs_compress::{Codec, CompressionDecision, ZstdCodec};
use lchfs_format::{
    ChunkRef, CodecId, ContentRef, DirEntry, DirectoryObject, ExtentKind, ExtentLocation, Hash32,
    InoMap, InoMapEntry, InodeKind, InodeObject, IndirectHashList, PoolParams, RootObject,
    SnapshotTable, StreamKind, SuperblockSlot, SUPERBLOCK_MAGIC, SUPERBLOCK_SLOT_COUNT,
    SUPERBLOCK_SLOT_SIZE, compute_superblock_slot_checksum, finalize_superblock_slot_checksum,
};
use parking_lot::Mutex;
use segment::{SegmentError, SegmentReader, SegmentWriter};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
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
    #[error("not a directory: {0}")]
    NotADirectory(u64),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl From<SegmentError> for PoolError {
    fn from(e: SegmentError) -> Self {
        match e {
            SegmentError::Io(io) => PoolError::Io(io),
            SegmentError::Validation(v) => PoolError::Format(v.to_string()),
            SegmentError::ContentHash { expected, .. } => PoolError::IntegrityFailure(expected),
        }
    }
}

fn now_unix() -> (i64, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos())
}

const ROOT_DIR_INO: u64 = 1;
/// Generous fixed overhead estimate (framing prefix + a header with empty
/// backpointers) used only to decide when to roll a segment over — exact
/// byte-perfect cap enforcement isn't a Phase B correctness requirement.
const RECORD_OVERHEAD_ESTIMATE: u64 = 256;

/// The engine's entire public API. A frontend (lchfs-fuse today; see
/// ARCHITECTURE.md §5a for the future-kernel-module rationale) is a thin
/// adapter that does nothing but translate protocol calls into these
/// methods — no filesystem logic belongs in a frontend crate.
pub struct Pool {
    inner: Mutex<PoolInner>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

struct PoolInner {
    pool_root: PathBuf,
    superblock_backend: FileBackend,
    pool_params: PoolParams,
    generation: u64,

    inodes: HashMap<u64, InodeObject>,
    dirs: HashMap<u64, DirectoryObject>,
    /// Per-file up-to-date chunk list, lazily hydrated from disk on first
    /// access. Authoritative over what's on disk until the next checkpoint
    /// re-derives an IndirectHashList from it.
    file_chunks: HashMap<u64, Vec<ChunkRef>>,
    /// Per-file full byte buffer, lazily hydrated on first write() (Phase B
    /// has no SpliceChunker yet — see lchfs-chunk's TODO(phase-E) — so an
    /// overwrite needs the whole file in memory to re-chunk it).
    file_contents: HashMap<u64, Vec<u8>>,
    next_ino: u64,
    /// `ino -> parent_ino`, for resolving `..` in readdir. Not part of the
    /// on-disk schema (DirectoryObject entries only point child->parent by
    /// virtue of being listed in the parent, not the reverse) — rebuilt at
    /// mount alongside `dirs`/`inodes`.
    parents: HashMap<u64, u64>,

    /// Content-address -> location, for both RawChunk (data stream) and
    /// every meta object kind (meta stream). Rebuilt at mount by scanning
    /// every segment; see module docs for why this stands in for
    /// Phase C's `lchfs-index`.
    locations: HashMap<Hash32, ExtentLocation>,
    readers: HashMap<(u64, StreamKind), SegmentReader>,

    data_writer: SegmentWriter,
    meta_writer: SegmentWriter,
    next_segment_id: u64,

    /// Inodes whose InodeObject (and, if a directory, DirectoryObject)
    /// needs re-encoding at the next checkpoint.
    dirty_inodes: HashSet<u64>,
    snapshot_table_hash: Option<Hash32>,
}

impl Pool {
    /// Creates a brand-new pool at `pool_root` (must not already contain a
    /// valid superblock) with the given `params`, and runs an initial
    /// checkpoint so the empty pool is immediately mountable.
    pub fn create(pool_root: &Path, params: PoolParams) -> Result<Self, PoolError> {
        std::fs::create_dir_all(pool_root)?;
        let superblock_backend = FileBackend::open(pool_root)?;
        if read_superblock(&superblock_backend)?.is_some() {
            return Err(PoolError::AlreadyExists(
                pool_root.display().to_string(),
            ));
        }

        let mut inodes = HashMap::new();
        let (now_secs, now_nanos) = now_unix();
        inodes.insert(
            ROOT_DIR_INO,
            InodeObject {
                kind: InodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 0,
                nlink: 2,
                atime: (now_secs, now_nanos),
                mtime: (now_secs, now_nanos),
                ctime: (now_secs, now_nanos),
                xattrs: None,
                content: ContentRef::DirEntries(Hash32([0; 32])), // patched by first checkpoint
                generation: 0,
            },
        );
        let mut dirs = HashMap::new();
        dirs.insert(ROOT_DIR_INO, DirectoryObject::default());

        let data_writer = SegmentWriter::create(pool_root, 0, StreamKind::Data, 0)?;
        let meta_writer = SegmentWriter::create(pool_root, 1, StreamKind::Meta, 0)?;

        let mut inner = PoolInner {
            pool_root: pool_root.to_path_buf(),
            superblock_backend,
            pool_params: params,
            generation: 0,
            inodes,
            dirs,
            file_chunks: HashMap::new(),
            file_contents: HashMap::new(),
            next_ino: ROOT_DIR_INO + 1,
            parents: HashMap::from([(ROOT_DIR_INO, ROOT_DIR_INO)]),
            locations: HashMap::new(),
            readers: HashMap::new(),
            data_writer,
            meta_writer,
            next_segment_id: 2,
            dirty_inodes: HashSet::from([ROOT_DIR_INO]),
            snapshot_table_hash: None,
        };
        inner.run_checkpoint()?;

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Opens an existing pool at `pool_root`. Runs mount-time recovery per
    /// ARCHITECTURE.md §7: read the global superblock, then (Phase B: no
    /// per-shard delta logs yet, so this is the whole of recovery) walk the
    /// DAG from the recovered root.
    pub fn open(pool_root: &Path) -> Result<Self, PoolError> {
        let superblock_backend = FileBackend::open(pool_root)?;
        let slot = read_superblock(&superblock_backend)?.ok_or_else(|| {
            PoolError::Format(format!(
                "no valid superblock found at {} — was create-pool run?",
                pool_root.display()
            ))
        })?;

        let mut readers: HashMap<(u64, StreamKind), SegmentReader> = HashMap::new();
        let mut locations: HashMap<Hash32, ExtentLocation> = HashMap::new();
        let max_segment_id = scan_segments(pool_root, &mut readers, &mut locations)?;

        let root_bytes = {
            let reader = get_reader(&mut readers, pool_root, slot.root_location.segment_id, StreamKind::Meta)?;
            let (_header, bytes) = reader.read_record(slot.root_location)?;
            bytes
        };
        let root: RootObject = lchfs_format::decode(&root_bytes)
            .map_err(|e| PoolError::Format(e.to_string()))?;

        let inomap_loc = *locations
            .get(&root.inomap_hash)
            .ok_or_else(|| PoolError::Format("InoMap location missing from segment scan".into()))?;
        let inomap_bytes = {
            let reader = get_reader(&mut readers, pool_root, inomap_loc.segment_id, StreamKind::Meta)?;
            let (_h, bytes) = reader.read_record(inomap_loc)?;
            bytes
        };
        let ino_map: InoMap =
            lchfs_format::decode(&inomap_bytes).map_err(|e| PoolError::Format(e.to_string()))?;

        let mut inodes = HashMap::new();
        let mut dirs = HashMap::new();
        let mut parents = HashMap::from([(ROOT_DIR_INO, ROOT_DIR_INO)]);
        for entry in &ino_map.entries {
            let loc = *locations.get(&entry.current_object_hash).ok_or_else(|| {
                PoolError::Format(format!("InodeObject for ino {} missing from scan", entry.ino))
            })?;
            let bytes = {
                let reader = get_reader(&mut readers, pool_root, loc.segment_id, StreamKind::Meta)?;
                let (_h, bytes) = reader.read_record(loc)?;
                bytes
            };
            let inode: InodeObject =
                lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
            if inode.kind == InodeKind::Directory
                && let ContentRef::DirEntries(dir_hash) = &inode.content
            {
                let dir_loc = *locations
                    .get(dir_hash)
                    .ok_or_else(|| PoolError::Format("DirectoryObject missing from scan".into()))?;
                let dir_bytes = {
                    let reader =
                        get_reader(&mut readers, pool_root, dir_loc.segment_id, StreamKind::Meta)?;
                    let (_h, bytes) = reader.read_record(dir_loc)?;
                    bytes
                };
                let dir: DirectoryObject = lchfs_format::decode(&dir_bytes)
                    .map_err(|e| PoolError::Format(e.to_string()))?;
                for child in &dir.entries {
                    parents.insert(child.ino, entry.ino);
                }
                dirs.insert(entry.ino, dir);
            }
            inodes.insert(entry.ino, inode);
        }

        let next_ino = ino_map.entries.iter().map(|e| e.ino).max().unwrap_or(ROOT_DIR_INO) + 1;
        let next_ino = next_ino.max(root.next_ino_counter);

        let data_writer = SegmentWriter::create(pool_root, max_segment_id + 1, StreamKind::Data, 0)?;
        let meta_writer = SegmentWriter::create(pool_root, max_segment_id + 2, StreamKind::Meta, 0)?;

        let inner = PoolInner {
            pool_root: pool_root.to_path_buf(),
            superblock_backend,
            pool_params: root.pool_params,
            generation: slot.generation,
            inodes,
            dirs,
            file_chunks: HashMap::new(),
            file_contents: HashMap::new(),
            next_ino,
            parents,
            locations,
            readers,
            data_writer,
            meta_writer,
            next_segment_id: max_segment_id + 3,
            dirty_inodes: HashSet::new(),
            snapshot_table_hash: Some(root.snapshot_table_hash),
        };

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// ARCHITECTURE.md §4 (read path).
    pub fn read(&self, ino: u64, offset: u64, len: u32) -> Result<Bytes, PoolError> {
        let mut inner = self.inner.lock();
        inner.read(ino, offset, len)
    }

    /// ARCHITECTURE.md §3 (write path): routes through the logical-shard
    /// ingress ring for `ino`'s shard (Phase B: direct single-threaded
    /// path; Phase E: full sharded ingress).
    pub fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<(), PoolError> {
        let mut inner = self.inner.lock();
        inner.write(ino, offset, buf)
    }

    pub fn lookup(&self, parent_ino: u64, name: &str) -> Result<Option<u64>, PoolError> {
        let inner = self.inner.lock();
        inner.lookup(parent_ino, name)
    }

    pub fn getattr(&self, ino: u64) -> Result<InodeObject, PoolError> {
        let inner = self.inner.lock();
        inner
            .inodes
            .get(&ino)
            .cloned()
            .ok_or(PoolError::NoSuchInode(ino))
    }

    pub fn readdir(&self, ino: u64) -> Result<Vec<DirEntry>, PoolError> {
        let inner = self.inner.lock();
        inner
            .dirs
            .get(&ino)
            .map(|d| d.entries.clone())
            .ok_or(PoolError::NotADirectory(ino))
    }

    /// Resolves `ino`'s parent directory's ino — for `..` in readdir. The
    /// root directory is its own parent, matching FUSE convention.
    pub fn parent_of(&self, ino: u64) -> Result<u64, PoolError> {
        let inner = self.inner.lock();
        inner.parents.get(&ino).copied().ok_or(PoolError::NoSuchInode(ino))
    }

    pub fn mkdir(&self, parent_ino: u64, name: &str, mode: u32) -> Result<u64, PoolError> {
        let mut inner = self.inner.lock();
        inner.create_entry(parent_ino, name, mode, InodeKind::Directory)
    }

    pub fn create_file(&self, parent_ino: u64, name: &str, mode: u32) -> Result<u64, PoolError> {
        let mut inner = self.inner.lock();
        inner.create_entry(parent_ino, name, mode, InodeKind::File)
    }

    /// The fast per-shard fsync path (ARCHITECTURE.md §3, "Subtree
    /// durability via per-shard delta logs") — O(this shard's dirty data),
    /// not O(all dirty data pool-wide). Phase B has no shards yet (that
    /// machinery is Phase E, see delta_log.rs), so this runs the same full
    /// checkpoint as `Pool::checkpoint`.
    pub fn fsync(&self, _ino: u64) -> Result<(), PoolError> {
        self.checkpoint()
    }

    /// Forces a full global checkpoint (ARCHITECTURE.md §3, the 5-step
    /// process) regardless of the per-shard fast path — used by unmount,
    /// periodic epochs, and explicit consolidation.
    pub fn checkpoint(&self) -> Result<(), PoolError> {
        let mut inner = self.inner.lock();
        inner.run_checkpoint()
    }
}

fn get_reader<'a>(
    readers: &'a mut HashMap<(u64, StreamKind), SegmentReader>,
    pool_root: &Path,
    segment_id: u64,
    kind: StreamKind,
) -> Result<&'a SegmentReader, PoolError> {
    if let std::collections::hash_map::Entry::Vacant(e) = readers.entry((segment_id, kind)) {
        e.insert(SegmentReader::open(pool_root, segment_id, kind)?);
    }
    Ok(readers.get(&(segment_id, kind)).unwrap())
}

/// Scans every segment file under `pool_root/segments/{data,meta}` once,
/// populating `locations` with every record's `content_hash -> location`
/// and opening a reader for each segment found. Returns the highest
/// segment_id seen (or 0 if none), so the caller can allocate fresh IDs
/// above it. This is Phase B's stand-in for a persisted index — see module
/// docs.
fn scan_segments(
    pool_root: &Path,
    readers: &mut HashMap<(u64, StreamKind), SegmentReader>,
    locations: &mut HashMap<Hash32, ExtentLocation>,
) -> Result<u64, PoolError> {
    let mut max_segment_id = 0u64;
    for kind in [StreamKind::Data, StreamKind::Meta] {
        let sub = match kind {
            StreamKind::Data => "data",
            StreamKind::Meta => "meta",
        };
        let dir = pool_root.join("segments").join(sub);
        if !dir.is_dir() {
            continue;
        }
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let file_name = entry.file_name();
            let stem = Path::new(&file_name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let Ok(segment_id) = stem.parse::<u64>() else {
                continue;
            };
            max_segment_id = max_segment_id.max(segment_id);
            let reader = SegmentReader::open(pool_root, segment_id, kind)?;
            scan_one_segment(&reader, segment_id, locations)?;
            readers.insert((segment_id, kind), reader);
        }
    }
    Ok(max_segment_id)
}

fn scan_one_segment(
    reader: &SegmentReader,
    segment_id: u64,
    locations: &mut HashMap<Hash32, ExtentLocation>,
) -> Result<(), PoolError> {
    let mut offset = segment::SEGMENT_HEADER_PAGE_SIZE as u32;
    while let Some((header, next_offset)) = reader.scan_next(offset) {
        locations.insert(
            header.content_hash,
            ExtentLocation {
                segment_id,
                offset,
                len: header.record_len,
            },
        );
        offset = next_offset;
    }
    Ok(())
}

/// Reads all 16 superblock slots, keeps the CRC-valid ones, returns the
/// highest-generation one. ARCHITECTURE.md §1: "Recovery = read all 16
/// slots, keep CRC-valid ones, take highest generation."
fn read_superblock(backend: &FileBackend) -> Result<Option<SuperblockSlot>, PoolError> {
    let mut best: Option<SuperblockSlot> = None;
    for slot_idx in 0..SUPERBLOCK_SLOT_COUNT {
        let bytes = backend.read_at(
            slot_idx as u64 * SUPERBLOCK_SLOT_SIZE as u64,
            SUPERBLOCK_SLOT_SIZE as u32,
        )?;
        if bytes.len() < 4 {
            continue;
        }
        let encoded_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if encoded_len == 0 || 4 + encoded_len > bytes.len() {
            continue;
        }
        let Ok(slot) = lchfs_format::decode::<SuperblockSlot>(&bytes[4..4 + encoded_len]) else {
            continue;
        };
        if slot.magic != SUPERBLOCK_MAGIC {
            continue;
        }
        if compute_superblock_slot_checksum(&slot) != slot.header_checksum {
            continue;
        }
        if best.as_ref().is_none_or(|b| slot.generation > b.generation) {
            best = Some(slot);
        }
    }
    Ok(best)
}

fn write_superblock_slot(backend: &FileBackend, slot: &SuperblockSlot) -> Result<(), PoolError> {
    let slot_idx = slot.generation % SUPERBLOCK_SLOT_COUNT as u64;
    let encoded = lchfs_format::encode(slot).expect("SuperblockSlot encoding is infallible");
    let mut buf = vec![0u8; SUPERBLOCK_SLOT_SIZE];
    buf[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    buf[4..4 + encoded.len()].copy_from_slice(&encoded);
    backend.write_at(slot_idx * SUPERBLOCK_SLOT_SIZE as u64, &buf)?;
    backend.fsync()?;
    Ok(())
}

impl PoolInner {
    fn ensure_data_room(&mut self, additional: u64) -> Result<(), PoolError> {
        if self.data_writer.current_size() + additional + RECORD_OVERHEAD_ESTIMATE
            > self.pool_params.data_segment_cap_bytes as u64
        {
            let id = self.next_segment_id;
            self.next_segment_id += 1;
            let new_writer = SegmentWriter::create(&self.pool_root, id, StreamKind::Data, 0)?;
            let old = std::mem::replace(&mut self.data_writer, new_writer);
            old.seal()?;
        }
        Ok(())
    }

    fn ensure_meta_room(&mut self, additional: u64) -> Result<(), PoolError> {
        if self.meta_writer.current_size() + additional + RECORD_OVERHEAD_ESTIMATE
            > self.pool_params.meta_segment_cap_bytes as u64
        {
            let id = self.next_segment_id;
            self.next_segment_id += 1;
            let new_writer = SegmentWriter::create(&self.pool_root, id, StreamKind::Meta, 0)?;
            let old = std::mem::replace(&mut self.meta_writer, new_writer);
            old.seal()?;
        }
        Ok(())
    }

    /// Writes a chunk to the data stream if its hash isn't already known
    /// (dedup-on-write, ARCHITECTURE.md §2). Returns its location either
    /// way.
    fn put_chunk(&mut self, data: &[u8]) -> Result<(Hash32, ExtentLocation), PoolError> {
        let hash = Hash32::of(data);
        if let Some(loc) = self.locations.get(&hash) {
            return Ok((hash, *loc));
        }
        let decision = lchfs_compress::sample_and_decide(data);
        let (codec_id, payload): (CodecId, Vec<u8>) = match decision {
            CompressionDecision::StoreRaw => (CodecId::None, data.to_vec()),
            CompressionDecision::Compress { level, .. } => {
                (CodecId::Zstd, ZstdCodec.compress(data, level))
            }
        };
        self.ensure_data_room(payload.len() as u64)?;
        let loc = self.data_writer.append(
            ExtentKind::RawChunk,
            hash,
            codec_id,
            data.len() as u32,
            &payload,
            Vec::new(),
        )?;
        self.locations.insert(hash, loc);
        Ok((hash, loc))
    }

    /// Writes any serde-encodable meta object to the meta stream if its
    /// hash isn't already known. Returns its hash and location.
    fn put_meta_object<T: serde::Serialize>(
        &mut self,
        kind: ExtentKind,
        value: &T,
    ) -> Result<(Hash32, ExtentLocation), PoolError> {
        let encoded = lchfs_format::encode(value).map_err(|e| PoolError::Format(e.to_string()))?;
        let hash = Hash32::of(&encoded);
        if let Some(loc) = self.locations.get(&hash) {
            return Ok((hash, *loc));
        }
        self.ensure_meta_room(encoded.len() as u64)?;
        let loc = self.meta_writer.append(
            kind,
            hash,
            CodecId::None,
            encoded.len() as u32,
            &encoded,
            Vec::new(),
        )?;
        self.locations.insert(hash, loc);
        Ok((hash, loc))
    }

    fn read_meta_object_bytes(&mut self, hash: Hash32) -> Result<Vec<u8>, PoolError> {
        let loc = *self
            .locations
            .get(&hash)
            .ok_or_else(|| PoolError::Format(format!("object {hash:?} not found")))?;
        let reader = get_reader(&mut self.readers, &self.pool_root, loc.segment_id, StreamKind::Meta)?;
        let (_header, bytes) = reader.read_record(loc)?;
        Ok(bytes)
    }

    fn read_chunk_bytes(&mut self, hash: Hash32) -> Result<Vec<u8>, PoolError> {
        let loc = *self
            .locations
            .get(&hash)
            .ok_or_else(|| PoolError::Format(format!("chunk {hash:?} not found")))?;
        let reader = get_reader(&mut self.readers, &self.pool_root, loc.segment_id, StreamKind::Data)?;
        let (_header, bytes) = reader.read_record(loc)?;
        Ok(bytes)
    }

    /// Lazily loads (if not already cached) the full current byte content
    /// of a file inode by resolving its InodeObject's ContentRef.
    fn hydrate_file_contents(&mut self, ino: u64) -> Result<(), PoolError> {
        if self.file_contents.contains_key(&ino) {
            return Ok(());
        }
        let inode = self
            .inodes
            .get(&ino)
            .cloned()
            .ok_or(PoolError::NoSuchInode(ino))?;
        let (bytes, chunks) = match &inode.content {
            ContentRef::Inline(bytes) => (bytes.clone(), Vec::new()),
            ContentRef::ChunkList(hash) => {
                let ihl_bytes = self.read_meta_object_bytes(*hash)?;
                let ihl: IndirectHashList =
                    lchfs_format::decode(&ihl_bytes).map_err(|e| PoolError::Format(e.to_string()))?;
                let mut buf = Vec::with_capacity(inode.size as usize);
                for chunk in &ihl.chunks {
                    let chunk_bytes = self.read_chunk_bytes(chunk.content_hash)?;
                    buf.extend_from_slice(&chunk_bytes);
                }
                (buf, ihl.chunks)
            }
            ContentRef::DirEntries(_) | ContentRef::SymlinkTarget(_) => (Vec::new(), Vec::new()),
        };
        self.file_contents.insert(ino, bytes);
        self.file_chunks.insert(ino, chunks);
        Ok(())
    }

    fn read(&mut self, ino: u64, offset: u64, len: u32) -> Result<Bytes, PoolError> {
        let inode = self
            .inodes
            .get(&ino)
            .cloned()
            .ok_or(PoolError::NoSuchInode(ino))?;
        if inode.kind != InodeKind::File {
            return Err(PoolError::Format(format!("ino {ino} is not a regular file")));
        }
        self.hydrate_file_contents(ino)?;
        let content = &self.file_contents[&ino];
        let start = (offset as usize).min(content.len());
        let end = (start + len as usize).min(content.len());
        Ok(Bytes::copy_from_slice(&content[start..end]))
    }

    fn write(&mut self, ino: u64, offset: u64, buf: &[u8]) -> Result<(), PoolError> {
        let kind = self
            .inodes
            .get(&ino)
            .map(|i| i.kind)
            .ok_or(PoolError::NoSuchInode(ino))?;
        if kind != InodeKind::File {
            return Err(PoolError::Format(format!("ino {ino} is not a regular file")));
        }
        self.hydrate_file_contents(ino)?;

        let content = self.file_contents.get_mut(&ino).unwrap();
        let end = offset as usize + buf.len();
        if content.len() < end {
            content.resize(end, 0);
        }
        content[offset as usize..end].copy_from_slice(buf);
        let new_size = content.len() as u64;
        let content_snapshot = content.clone();

        if new_size <= self.pool_params.inline_threshold as u64 {
            self.file_chunks.insert(ino, Vec::new());
        } else {
            let mut chunker = FastCdcChunker::new(
                self.pool_params.chunk_avg_size,
                self.pool_params.chunk_min_size,
                self.pool_params.chunk_max_size,
            );
            let mut boundaries: Vec<ChunkBoundary> = chunker.push(&content_snapshot);
            if let Some(last) = chunker.finish() {
                boundaries.push(last);
            }
            let mut refs = Vec::with_capacity(boundaries.len());
            for b in boundaries {
                let bytes = &content_snapshot[b.offset as usize..(b.offset + b.len as u64) as usize];
                let (hash, _loc) = self.put_chunk(bytes)?;
                refs.push(ChunkRef {
                    content_hash: hash,
                    logical_offset: b.offset,
                    len: b.len,
                });
            }
            self.file_chunks.insert(ino, refs);
        }

        let (now_secs, now_nanos) = now_unix();
        let inode = self.inodes.get_mut(&ino).unwrap();
        inode.size = new_size;
        inode.mtime = (now_secs, now_nanos);
        inode.ctime = (now_secs, now_nanos);
        self.dirty_inodes.insert(ino);
        Ok(())
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> Result<Option<u64>, PoolError> {
        let dir = self
            .dirs
            .get(&parent_ino)
            .ok_or(PoolError::NotADirectory(parent_ino))?;
        Ok(dir.entries.iter().find(|e| e.name == name).map(|e| e.ino))
    }

    fn create_entry(
        &mut self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        kind: InodeKind,
    ) -> Result<u64, PoolError> {
        if !self.dirs.contains_key(&parent_ino) {
            return Err(PoolError::NotADirectory(parent_ino));
        }
        if self.lookup(parent_ino, name)?.is_some() {
            return Err(PoolError::AlreadyExists(name.to_string()));
        }

        let ino = self.next_ino;
        self.next_ino += 1;

        let (now_secs, now_nanos) = now_unix();
        let (content, nlink) = match kind {
            InodeKind::Directory => (ContentRef::DirEntries(Hash32([0; 32])), 2),
            InodeKind::File => (ContentRef::Inline(Vec::new()), 1),
            InodeKind::Symlink => (ContentRef::SymlinkTarget(String::new()), 1),
        };
        self.inodes.insert(
            ino,
            InodeObject {
                kind,
                mode,
                uid: 0,
                gid: 0,
                size: 0,
                nlink,
                atime: (now_secs, now_nanos),
                mtime: (now_secs, now_nanos),
                ctime: (now_secs, now_nanos),
                xattrs: None,
                content,
                generation: 0,
            },
        );
        if kind == InodeKind::Directory {
            self.dirs.insert(ino, DirectoryObject::default());
        }

        let dir = self.dirs.get_mut(&parent_ino).unwrap();
        dir.entries.push(DirEntry {
            name: name.to_string(),
            ino,
            kind,
        });
        dir.entries.sort_by(|a, b| a.name.cmp(&b.name));
        self.parents.insert(ino, parent_ino);

        self.dirty_inodes.insert(parent_ino);
        self.dirty_inodes.insert(ino);
        Ok(ino)
    }

    /// The 5-step global checkpoint (ARCHITECTURE.md §3): flush/fsync data
    /// -> bottom-up rewrite dirty meta objects -> fsync meta -> build+fsync
    /// RootObject -> write+fsync superblock slot. The invariant that makes
    /// this journal-free: no parent's hash is ever computed over a child
    /// whose bytes aren't yet fsync'd — enforced here simply by ordering
    /// every write before the fsync/superblock steps that depend on it.
    fn run_checkpoint(&mut self) -> Result<(), PoolError> {
        // Barrier #1: every chunk newly written by put_chunk() since the
        // last checkpoint lives in self.data_writer; fsync it before any
        // parent hash referencing it is committed.
        self.data_writer.fsync()?;

        let dirty: Vec<u64> = self.dirty_inodes.drain().collect();
        for ino in dirty {
            let Some(inode) = self.inodes.get(&ino).cloned() else {
                continue; // deleted since being marked dirty (not reachable in Phase B yet, defensive)
            };
            let new_content = match inode.kind {
                InodeKind::Directory => {
                    let dir = self.dirs.get(&ino).cloned().unwrap_or_default();
                    let (hash, _loc) = self.put_meta_object(ExtentKind::DirectoryObject, &dir)?;
                    ContentRef::DirEntries(hash)
                }
                InodeKind::File => {
                    if inode.size as u32 <= self.pool_params.inline_threshold {
                        let bytes = self.file_contents.get(&ino).cloned().unwrap_or_default();
                        ContentRef::Inline(bytes)
                    } else {
                        let chunks = self.file_chunks.get(&ino).cloned().unwrap_or_default();
                        let ihl = IndirectHashList { chunks };
                        let (hash, _loc) =
                            self.put_meta_object(ExtentKind::IndirectHashList, &ihl)?;
                        ContentRef::ChunkList(hash)
                    }
                }
                InodeKind::Symlink => inode.content.clone(),
            };
            let inode_mut = self.inodes.get_mut(&ino).unwrap();
            inode_mut.content = new_content;
        }

        // Snapshot first (owned, independent of `self`) so each
        // put_meta_object call below can freely borrow `self` mutably —
        // also means every InodeObject is encoded+hashed exactly once
        // (put_meta_object's dedup check reuses that hash for the write).
        let mut ino_snapshot: Vec<(u64, InodeObject)> = self
            .inodes
            .iter()
            .map(|(&ino, obj)| (ino, obj.clone()))
            .collect();
        ino_snapshot.sort_by_key(|(ino, _)| *ino);

        let mut ino_entries = Vec::with_capacity(ino_snapshot.len());
        for (ino, inode) in &ino_snapshot {
            let (hash, _loc) = self.put_meta_object(ExtentKind::InodeObject, inode)?;
            ino_entries.push(InoMapEntry {
                ino: *ino,
                current_object_hash: hash,
            });
        }

        let ino_map = InoMap {
            entries: ino_entries,
        };
        let (inomap_hash, _loc) = self.put_meta_object(ExtentKind::IndirectHashList, &ino_map)?;

        let snapshot_table_hash = match self.snapshot_table_hash {
            Some(h) => h,
            None => {
                let (h, _loc) =
                    self.put_meta_object(ExtentKind::SnapshotTable, &SnapshotTable::default())?;
                self.snapshot_table_hash = Some(h);
                h
            }
        };

        let root = RootObject {
            inomap_hash,
            root_dir_ino: ROOT_DIR_INO,
            next_ino_counter: self.next_ino,
            snapshot_table_hash,
            pool_params: self.pool_params,
            shard_watermarks: Vec::new(),
        };
        let (root_hash, root_location) = self.put_meta_object(ExtentKind::RootObject, &root)?;

        // Barrier #2: everything the new superblock slot will point to
        // (InodeObjects, DirectoryObjects, IndirectHashLists, InoMap,
        // SnapshotTable, RootObject) went to self.meta_writer above.
        self.meta_writer.fsync()?;

        self.generation += 1;
        let mut slot = SuperblockSlot {
            magic: SUPERBLOCK_MAGIC,
            format_version: lchfs_format::FORMAT_VERSION,
            generation: self.generation,
            root_hash,
            root_location,
            index_generation: self.generation,
            committed_at_unix_nanos: {
                let (s, n) = now_unix();
                s * 1_000_000_000 + n as i64
            },
            stats: lchfs_format::SuperblockStats {
                live_bytes: 0,
                object_count: self.inodes.len() as u64,
                segment_count: self.next_segment_id,
            },
            header_checksum: 0,
        };
        finalize_superblock_slot_checksum(&mut slot);
        write_superblock_slot(&self.superblock_backend, &slot)?;

        Ok(())
    }
}
