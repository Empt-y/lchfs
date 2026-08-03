//! The LCHFS engine. ARCHITECTURE.md §3 (write path), §4 (read path), §5
//! (concurrency), §6 (GC), §7 (crash recovery).
//!
//! **Kernel-independence boundary (ARCHITECTURE.md §5a):** this crate has
//! zero knowledge of FUSE. `Pool` is the entire public surface a frontend
//! (today `lchfs-fuse`, potentially a future kernel module) is expected to
//! call. No `fuser`/`nix` dependency here, by design — do not add one.
//!
//! **Phase E scope**: `Pool` is `Arc<PoolShared>`-backed rather than one
//! global `Mutex<PoolInner>` (Phase B's shape). Locking is split by what
//! it protects: a small `Namespace` mutex covers directory-structure state
//! (`inodes`/`dirs`/`parents`/`next_ino`/`dirty_inodes` — the ARCHITECTURE
//! §3 carve-out: "directory-structure changes still go through their
//! directory's chain toward the global root," never sharded), a separate
//! `file_state` mutex covers per-open-file working buffers, and content
//! writes route through the Ingest Preparation Pool (prep.rs) and the
//! work-stealing `CommitterPool` (ingress.rs) into M logical shards, each
//! with its own Data-stream segment and `ShardDeltaLog` (delta_log.rs) for
//! the fast per-shard `fsync()` path. See ARCHITECTURE.md §5 for the full
//! concurrency model these pieces implement.
//!
//! **Persisted index (Phase C, `lchfs-index`'s `RedbIndex`)**: `Pool::open`
//! trusts `INDEX.redb`'s chunk-location map and skips the full segment
//! scan only when its checkpointed generation matches the recovered
//! superblock slot's `index_generation`; otherwise it falls back to
//! scanning every segment once (the "cold rebuild" path ARCHITECTURE.md
//! §4 describes for an index_generation mismatch) and rebuilds the index
//! from that scan so the *next* mount can take the fast path. Phase E adds
//! `ChunkLocationCache` (lchfs-index) as the concurrency-safe in-memory
//! hot path in front of it, used for both RawChunk and meta-object hashes
//! exactly as Phase B's flat `locations` map was.

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
use delta_log::ShardDeltaLog;
use ingress::{CommitterPool, IngressOp};
use lchfs_chunk::{ChunkBoundary, Chunker, FastCdcChunker};
use lchfs_format::{
    ChunkRef, CodecId, ContentRef, DirEntry, DirectoryObject, ExtentKind, ExtentLocation, Hash32,
    InoMap, InoMapEntry, InodeKind, InodeObject, IndirectHashList, PoolParams, RootObject,
    SnapshotTable, StreamKind, SuperblockSlot, SUPERBLOCK_MAGIC, SUPERBLOCK_SLOT_COUNT,
    SUPERBLOCK_SLOT_SIZE, compute_superblock_slot_checksum, finalize_superblock_slot_checksum,
};
use lchfs_index::{ChunkLocationCache, IndexError, IndexStore, RedbIndex};
use parking_lot::{Condvar, Mutex, RwLock};
use prep::{IngestPreparationPool, PrepTask, PreparedChunk};
use segment::{SegmentError, SegmentReader, SegmentWriter};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    #[error("index error: {0}")]
    Index(#[from] IndexError),
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
/// byte-perfect cap enforcement isn't a correctness requirement.
const RECORD_OVERHEAD_ESTIMATE: u64 = 256;
/// Bounded MPSC ring capacity per logical shard (ARCHITECTURE.md §5).
const SHARD_RING_CAPACITY: usize = 256;
/// How often the background Checkpoint Coordinator runs a full epoch
/// (ARCHITECTURE.md §3: "every 5s default, or on fsync(), ring pressure,
/// or unmount").
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);

fn index_path(pool_root: &Path) -> PathBuf {
    pool_root.join("INDEX.redb")
}

type SegmentReaders = HashMap<(u64, StreamKind), SegmentReader>;

fn committer_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Namespace-level state (ARCHITECTURE.md §3's directory-structure carve-
/// out): never sharded, always goes through the slower global checkpoint
/// path. Held only briefly — O(1) bookkeeping mutations, never across I/O
/// or CPU-bound work (that's the actual Phase B -> Phase E lock-shrinkage
/// fix: Phase B held one global lock across hashing/compression/segment
/// I/O for a whole file; here that work happens off this lock entirely,
/// through the prep/committer pools).
struct Namespace {
    inodes: HashMap<u64, InodeObject>,
    dirs: HashMap<u64, DirectoryObject>,
    /// `ino -> parent_ino`, for resolving `..` in readdir. Not part of the
    /// on-disk schema — rebuilt at mount alongside `dirs`/`inodes`.
    parents: HashMap<u64, u64>,
    next_ino: u64,
    /// Inodes whose InodeObject (and, if a directory, DirectoryObject)
    /// needs re-encoding at the next checkpoint.
    dirty_inodes: HashSet<u64>,
    generation: u64,
    snapshot_table_hash: Option<Hash32>,
    /// The current global root's content hash. Not used by anything in
    /// the core write/checkpoint/recovery path — kept here for GC's mark
    /// phase (E.10), which needs a cheap `{root_hash, snapshot_table_hash}`
    /// snapshot without touching any segment I/O.
    root_hash: Hash32,
}

/// Per-open-file working buffers. Separate from `Namespace` (a distinct
/// lock) since hydrating/rechunking these can involve real I/O (reading
/// existing chunks back) and CPU work (FastCDC) — deliberately kept off
/// the namespace lock's hot path. Only touched by the non-sequential
/// write/set_size fallback path (E.6) and by checkpoint's dirty-file
/// encoding step; the sequential-append fast path uses `open_files`
/// (`IncrementalWriteState`) instead and never touches this map.
#[derive(Clone, Default)]
struct FileWorkingState {
    /// Full current byte content, lazily hydrated. Phase 1 has no
    /// `SpliceChunker` yet (lchfs-chunk's own TODO(phase-E), explicitly
    /// deferred further — see E.6's doc comment) so an out-of-order
    /// overwrite needs the whole file in memory to re-chunk it.
    contents: Vec<u8>,
    chunks: Vec<ChunkRef>,
}

/// Per-open-file state for the sequential-append fast path (E.6): a live
/// incremental `FastCdcChunker` plus the offset it expects the next
/// `write()` call to start at. Falls back to the whole-file
/// `FileWorkingState` path the moment a write arrives out of order.
struct IncrementalWriteState {
    chunker: FastCdcChunker,
    next_expected_offset: u64,
    /// Finalized chunk refs accumulated so far this "session" (since the
    /// file was first opened for incremental writing, or since the last
    /// fallback). Combined with the chunker's still-buffered tail at
    /// checkpoint/fsync time.
    chunks: Vec<ChunkRef>,
}

struct BackgroundThread {
    handle: JoinHandle<()>,
}

/// The engine's entire public API. A frontend (lchfs-fuse today; see
/// ARCHITECTURE.md §5a for the future-kernel-module rationale) is a thin
/// adapter that does nothing but translate protocol calls into these
/// methods — no filesystem logic belongs in a frontend crate.
///
/// Thin `Arc<PoolShared>` wrapper: background threads (checkpoint timer
/// today; coalesce/dedup scanner in E.11/E.12) hold their own clone of the
/// same `Arc`, spawned from inside `create`/`open` before `Pool` itself
/// exists as a value — the standard shape for "a struct whose methods run
/// on a background thread referencing the struct itself."
pub struct Pool(Arc<PoolShared>);

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

struct PoolShared {
    pool_root: PathBuf,
    pool_params: PoolParams,
    superblock_backend: FileBackend,

    namespace: Mutex<Namespace>,
    file_state: Mutex<HashMap<u64, FileWorkingState>>,
    open_files: Mutex<HashMap<u64, IncrementalWriteState>>,

    /// Content-address -> location, for both RawChunk (data stream) and
    /// every meta object kind (meta stream) — same dual purpose Phase B's
    /// flat `locations` map served. Sharded internally (lchfs-index); the
    /// hot path in front of `persisted_index` below.
    dedup_index: Arc<ChunkLocationCache>,
    /// Persisted `INDEX.redb` (Phase C, ARCHITECTURE.md §4): "a
    /// rebuildable cache, never authoritative." `RwLock` since
    /// `get_chunk_location` only needs shared access while `put_*`/
    /// `checkpoint` need exclusive.
    persisted_index: RwLock<RedbIndex>,
    readers: Mutex<SegmentReaders>,

    meta_writer: Mutex<SegmentWriter>,
    next_segment_id: Arc<AtomicU64>,

    committer_pool: CommitterPool,
    prep_pool: IngestPreparationPool,
    shard_delta_logs: Vec<Mutex<ShardDeltaLog>>,

    checkpoint_lock: Mutex<()>,
    shutdown: Arc<AtomicBool>,
    background_wake: Arc<(Mutex<()>, Condvar)>,
    background: Mutex<Vec<BackgroundThread>>,
}

impl Pool {
    /// Creates a brand-new pool at `pool_root` (must not already contain a
    /// valid superblock) with the given `params`, and runs an initial
    /// checkpoint so the empty pool is immediately mountable.
    pub fn create(pool_root: &Path, params: PoolParams) -> Result<Self, PoolError> {
        std::fs::create_dir_all(pool_root)?;
        let superblock_backend = FileBackend::open(pool_root)?;
        if read_superblock(&superblock_backend)?.is_some() {
            return Err(PoolError::AlreadyExists(pool_root.display().to_string()));
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

        let next_segment_id = Arc::new(AtomicU64::new(0));
        let shard_count = params.logical_shard_count;
        let committer_pool = CommitterPool::new(
            pool_root,
            shard_count,
            committer_thread_count(),
            SHARD_RING_CAPACITY,
            params.data_segment_cap_bytes as u64,
            Arc::clone(&next_segment_id),
        )?;
        let meta_id = next_segment_id.fetch_add(1, Ordering::Relaxed);
        let meta_writer = SegmentWriter::create(pool_root, meta_id, StreamKind::Meta, 0)?;

        let shard_delta_logs = (0..shard_count)
            .map(|id| ShardDeltaLog::open(pool_root, id).map(Mutex::new))
            .collect::<Result<Vec<_>, _>>()?;

        let dedup_index = Arc::new(ChunkLocationCache::new());
        let persisted_index = RedbIndex::create(&index_path(pool_root))?;
        let prep_pool = IngestPreparationPool::new(committer_thread_count(), Arc::clone(&dedup_index));

        let namespace = Namespace {
            inodes,
            dirs,
            parents: HashMap::from([(ROOT_DIR_INO, ROOT_DIR_INO)]),
            next_ino: ROOT_DIR_INO + 1,
            dirty_inodes: HashSet::from([ROOT_DIR_INO]),
            generation: 0,
            snapshot_table_hash: None,
            root_hash: Hash32([0; 32]),
        };

        let shared = Arc::new(PoolShared {
            pool_root: pool_root.to_path_buf(),
            pool_params: params,
            superblock_backend,
            namespace: Mutex::new(namespace),
            file_state: Mutex::new(HashMap::new()),
            open_files: Mutex::new(HashMap::new()),
            dedup_index,
            persisted_index: RwLock::new(persisted_index),
            readers: Mutex::new(HashMap::new()),
            meta_writer: Mutex::new(meta_writer),
            next_segment_id,
            committer_pool,
            prep_pool,
            shard_delta_logs,
            checkpoint_lock: Mutex::new(()),
            shutdown: Arc::new(AtomicBool::new(false)),
            background_wake: Arc::new((Mutex::new(()), Condvar::new())),
            background: Mutex::new(Vec::new()),
        });

        shared.run_checkpoint()?;
        shared.spawn_background_threads();

        Ok(Self(shared))
    }

    /// Opens an existing pool at `pool_root`. Runs mount-time recovery per
    /// ARCHITECTURE.md §7: read the global superblock, then walk the DAG
    /// from the recovered root. (Two-tier per-shard delta-log replay lands
    /// in E.9; this is still the single-tier global-only recovery Phase B
    /// had.)
    pub fn open(pool_root: &Path) -> Result<Self, PoolError> {
        let superblock_backend = FileBackend::open(pool_root)?;
        let slot = read_superblock(&superblock_backend)?.ok_or_else(|| {
            PoolError::Format(format!(
                "no valid superblock found at {} — was create-pool run?",
                pool_root.display()
            ))
        })?;

        let index_file = index_path(pool_root);
        let fresh_index = index_file
            .try_exists()
            .unwrap_or(false)
            .then(|| RedbIndex::open(&index_file).ok())
            .flatten()
            .filter(|idx| idx.generation() == slot.generation);

        let (mut readers, locations, max_segment_id, persisted_index) =
            if let Some(index) = fresh_index {
                let (readers, max_segment_id) = open_all_segment_readers(pool_root)?;
                let locations: HashMap<Hash32, ExtentLocation> =
                    index.iter_chunk_locations()?.into_iter().collect();
                (readers, locations, max_segment_id, index)
            } else {
                let mut readers = HashMap::new();
                let mut locations = HashMap::new();
                let max_segment_id = scan_segments(pool_root, &mut readers, &mut locations)?;
                let index = rebuild_index(&index_file, &locations, slot.generation)?;
                (readers, locations, max_segment_id, index)
            };

        let root_bytes = {
            let reader = get_reader(
                &mut readers,
                pool_root,
                slot.root_location.segment_id,
                StreamKind::Meta,
            )?;
            let (_header, bytes) = reader.read_record(slot.root_location)?;
            bytes
        };
        let root: RootObject =
            lchfs_format::decode(&root_bytes).map_err(|e| PoolError::Format(e.to_string()))?;

        let inomap_loc = *locations
            .get(&root.inomap_hash)
            .ok_or_else(|| PoolError::Format("InoMap location missing from segment scan".into()))?;
        let inomap_bytes = {
            let reader = get_reader(
                &mut readers,
                pool_root,
                inomap_loc.segment_id,
                StreamKind::Meta,
            )?;
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

        let next_segment_id = Arc::new(AtomicU64::new(max_segment_id + 1));
        let shard_count = root.pool_params.logical_shard_count;
        let committer_pool = CommitterPool::new(
            pool_root,
            shard_count,
            committer_thread_count(),
            SHARD_RING_CAPACITY,
            root.pool_params.data_segment_cap_bytes as u64,
            Arc::clone(&next_segment_id),
        )?;
        let meta_id = next_segment_id.fetch_add(1, Ordering::Relaxed);
        let meta_writer = SegmentWriter::create(pool_root, meta_id, StreamKind::Meta, 0)?;

        let shard_delta_logs = (0..shard_count)
            .map(|id| ShardDeltaLog::open(pool_root, id).map(Mutex::new))
            .collect::<Result<Vec<_>, _>>()?;

        let dedup_index = Arc::new(ChunkLocationCache::new());
        dedup_index.extend(locations);
        let prep_pool = IngestPreparationPool::new(committer_thread_count(), Arc::clone(&dedup_index));

        let namespace = Namespace {
            inodes,
            dirs,
            parents,
            next_ino,
            dirty_inodes: HashSet::new(),
            generation: slot.generation,
            snapshot_table_hash: Some(root.snapshot_table_hash),
            root_hash: slot.root_hash,
        };

        let shared = Arc::new(PoolShared {
            pool_root: pool_root.to_path_buf(),
            pool_params: root.pool_params,
            superblock_backend,
            namespace: Mutex::new(namespace),
            file_state: Mutex::new(HashMap::new()),
            open_files: Mutex::new(HashMap::new()),
            dedup_index,
            persisted_index: RwLock::new(persisted_index),
            readers: Mutex::new(readers),
            meta_writer: Mutex::new(meta_writer),
            next_segment_id,
            committer_pool,
            prep_pool,
            shard_delta_logs,
            checkpoint_lock: Mutex::new(()),
            shutdown: Arc::new(AtomicBool::new(false)),
            background_wake: Arc::new((Mutex::new(()), Condvar::new())),
            background: Mutex::new(Vec::new()),
        });

        shared.spawn_background_threads();

        Ok(Self(shared))
    }

    /// ARCHITECTURE.md §4 (read path).
    pub fn read(&self, ino: u64, offset: u64, len: u32) -> Result<Bytes, PoolError> {
        self.0.read(ino, offset, len)
    }

    /// ARCHITECTURE.md §3 (write path): sequential-append writes take the
    /// fast incremental-chunking path straight through the prep/committer
    /// pools (E.6); any other write pattern falls back to the whole-file
    /// rehydrate-and-rechunk path.
    pub fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<(), PoolError> {
        self.0.write(ino, offset, buf)
    }

    /// `setattr`'s `size` field: truncate or zero-extend a file in place.
    pub fn set_size(&self, ino: u64, new_size: u64) -> Result<(), PoolError> {
        self.0.set_size(ino, new_size)
    }

    pub fn lookup(&self, parent_ino: u64, name: &str) -> Result<Option<u64>, PoolError> {
        self.0.lookup(parent_ino, name)
    }

    pub fn getattr(&self, ino: u64) -> Result<InodeObject, PoolError> {
        let namespace = self.0.namespace.lock();
        namespace
            .inodes
            .get(&ino)
            .cloned()
            .ok_or(PoolError::NoSuchInode(ino))
    }

    pub fn readdir(&self, ino: u64) -> Result<Vec<DirEntry>, PoolError> {
        let namespace = self.0.namespace.lock();
        namespace
            .dirs
            .get(&ino)
            .map(|d| d.entries.clone())
            .ok_or(PoolError::NotADirectory(ino))
    }

    /// Resolves `ino`'s parent directory's ino — for `..` in readdir. The
    /// root directory is its own parent, matching FUSE convention.
    pub fn parent_of(&self, ino: u64) -> Result<u64, PoolError> {
        let namespace = self.0.namespace.lock();
        namespace
            .parents
            .get(&ino)
            .copied()
            .ok_or(PoolError::NoSuchInode(ino))
    }

    pub fn mkdir(&self, parent_ino: u64, name: &str, mode: u32) -> Result<u64, PoolError> {
        self.0.create_entry(parent_ino, name, mode, InodeKind::Directory)
    }

    pub fn create_file(&self, parent_ino: u64, name: &str, mode: u32) -> Result<u64, PoolError> {
        self.0.create_entry(parent_ino, name, mode, InodeKind::File)
    }

    /// The fast per-shard fsync path (ARCHITECTURE.md §3, "Subtree
    /// durability via per-shard delta logs") — O(this shard's dirty data),
    /// not O(all dirty data pool-wide). (Upgraded from Phase B's
    /// full-checkpoint fallback in E.7.)
    pub fn fsync(&self, ino: u64) -> Result<(), PoolError> {
        self.0.fsync(ino)
    }

    /// Forces a full global checkpoint (ARCHITECTURE.md §3, the 5-step
    /// process) regardless of the per-shard fast path — used by unmount,
    /// periodic epochs, and explicit consolidation.
    pub fn checkpoint(&self) -> Result<(), PoolError> {
        self.0.run_checkpoint()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.0.shutdown.store(true, Ordering::Release);
        {
            let (lock, cvar) = &*self.0.background_wake;
            let _guard = lock.lock();
            cvar.notify_all();
        }
        let mut background = self.0.background.lock();
        for bg in background.drain(..) {
            let _ = bg.handle.join();
        }
    }
}

impl PoolShared {
    fn spawn_background_threads(self: &Arc<Self>) {
        let shared = Arc::clone(self);
        let shutdown = Arc::clone(&self.shutdown);
        let wake = Arc::clone(&self.background_wake);
        let handle = std::thread::Builder::new()
            .name("lchfs-checkpoint".into())
            .spawn(move || {
                while !shutdown.load(Ordering::Acquire) {
                    let (lock, cvar) = &*wake;
                    let mut guard = lock.lock();
                    cvar.wait_for(&mut guard, CHECKPOINT_INTERVAL);
                    drop(guard);
                    if shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = shared.run_checkpoint();
                }
            })
            .expect("spawn checkpoint thread");
        self.background.lock().push(BackgroundThread { handle });
    }

    fn read(&self, ino: u64, offset: u64, len: u32) -> Result<Bytes, PoolError> {
        let kind = {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .get(&ino)
                .map(|i| i.kind)
                .ok_or(PoolError::NoSuchInode(ino))?
        };
        if kind != InodeKind::File {
            return Err(PoolError::Format(format!("ino {ino} is not a regular file")));
        }
        self.hydrate_file_state(ino)?;
        let file_state = self.file_state.lock();
        let content = &file_state[&ino].contents;
        let start = (offset as usize).min(content.len());
        let end = (start + len as usize).min(content.len());
        Ok(Bytes::copy_from_slice(&content[start..end]))
    }

    /// Lazily loads (if not already cached) the full current byte content
    /// of a file inode by resolving its InodeObject's ContentRef.
    fn hydrate_file_state(&self, ino: u64) -> Result<(), PoolError> {
        if self.file_state.lock().contains_key(&ino) {
            return Ok(());
        }
        let content_ref = {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .get(&ino)
                .map(|i| i.content.clone())
                .ok_or(PoolError::NoSuchInode(ino))?
        };
        let (contents, chunks) = match content_ref {
            ContentRef::Inline(bytes) => (bytes, Vec::new()),
            ContentRef::ChunkList(hash) => {
                let ihl_bytes = self.read_meta_object_bytes(hash)?;
                let ihl: IndirectHashList =
                    lchfs_format::decode(&ihl_bytes).map_err(|e| PoolError::Format(e.to_string()))?;
                let mut buf = Vec::new();
                for chunk in &ihl.chunks {
                    let chunk_bytes = self.read_chunk_bytes(chunk.content_hash)?;
                    buf.extend_from_slice(&chunk_bytes);
                }
                (buf, ihl.chunks)
            }
            ContentRef::DirEntries(_) | ContentRef::SymlinkTarget(_) => (Vec::new(), Vec::new()),
        };
        self.file_state
            .lock()
            .insert(ino, FileWorkingState { contents, chunks });
        Ok(())
    }

    fn read_meta_object_bytes(&self, hash: Hash32) -> Result<Vec<u8>, PoolError> {
        let loc = self
            .dedup_index
            .get(hash)
            .ok_or_else(|| PoolError::Format(format!("object {hash:?} not found")))?;
        let mut readers = self.readers.lock();
        let reader = get_reader(&mut readers, &self.pool_root, loc.segment_id, StreamKind::Meta)?;
        let (_header, bytes) = reader.read_record(loc)?;
        Ok(bytes)
    }

    fn read_chunk_bytes(&self, hash: Hash32) -> Result<Vec<u8>, PoolError> {
        let loc = self
            .dedup_index
            .get(hash)
            .ok_or_else(|| PoolError::Format(format!("chunk {hash:?} not found")))?;
        let mut readers = self.readers.lock();
        let reader = get_reader(&mut readers, &self.pool_root, loc.segment_id, StreamKind::Data)?;
        let (_header, bytes) = reader.read_record(loc)?;
        Ok(bytes)
    }

    /// Runs a chunk through the Ingest Preparation Pool and, on a miss,
    /// the CommitterPool -- the concurrency-safe replacement for Phase B's
    /// direct `self.data_writer.append` call. On a dedup hit this does no
    /// segment I/O at all, just returns the already-known location.
    fn commit_chunk(
        &self,
        inode_id: u64,
        logical_offset: u64,
        raw_bytes: &[u8],
    ) -> Result<(Hash32, ExtentLocation), PoolError> {
        let prepared = self.prep_pool.submit(PrepTask {
            inode_id,
            logical_offset,
            raw_bytes: Bytes::copy_from_slice(raw_bytes),
        });
        match prepared {
            PreparedChunk::Dedup {
                content_hash,
                location,
            } => Ok((content_hash, location)),
            PreparedChunk::New {
                content_hash,
                codec_id,
                uncompressed_len,
                payload,
            } => {
                let (tx, rx) = crossbeam::channel::bounded(1);
                self.committer_pool.push(IngressOp {
                    inode_id,
                    content_hash,
                    codec_id,
                    uncompressed_len,
                    payload,
                    logical_offset,
                    completion: tx,
                });
                let location = rx
                    .recv()
                    .map_err(|_| PoolError::Format("committer pool completion channel closed".into()))??;
                self.dedup_index.put(content_hash, location);
                self.persisted_index
                    .write()
                    .put_chunk_location(content_hash, location)?;
                Ok((content_hash, location))
            }
        }
    }

    /// Writes any serde-encodable meta object to the (global, unsharded)
    /// meta stream if its hash isn't already known. Returns its hash and
    /// location. Not routed through prep/committer — meta writes aren't
    /// sharded (ARCHITECTURE.md §3: only content writes route by shard),
    /// they happen synchronously under `checkpoint_lock`'s serialization.
    fn put_meta_object<T: serde::Serialize>(
        &self,
        kind: ExtentKind,
        value: &T,
    ) -> Result<(Hash32, ExtentLocation), PoolError> {
        let encoded = lchfs_format::encode(value).map_err(|e| PoolError::Format(e.to_string()))?;
        let hash = Hash32::of(&encoded);
        if let Some(loc) = self.dedup_index.get(hash) {
            return Ok((hash, loc));
        }
        let mut meta_writer = self.meta_writer.lock();
        self.ensure_meta_room(&mut meta_writer, encoded.len() as u64)?;
        let loc = meta_writer.append(
            kind,
            hash,
            CodecId::None,
            encoded.len() as u32,
            &encoded,
            Vec::new(),
        )?;
        drop(meta_writer);
        self.dedup_index.put(hash, loc);
        self.persisted_index.write().put_chunk_location(hash, loc)?;
        Ok((hash, loc))
    }

    fn ensure_meta_room(
        &self,
        meta_writer: &mut SegmentWriter,
        additional: u64,
    ) -> Result<(), PoolError> {
        if meta_writer.current_size() + additional + RECORD_OVERHEAD_ESTIMATE
            > self.pool_params.meta_segment_cap_bytes as u64
        {
            let id = self.next_segment_id.fetch_add(1, Ordering::Relaxed);
            let new_writer = SegmentWriter::create(&self.pool_root, id, StreamKind::Meta, 0)?;
            let old = std::mem::replace(meta_writer, new_writer);
            old.seal()?;
        }
        Ok(())
    }

    fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<(), PoolError> {
        let kind = {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .get(&ino)
                .map(|i| i.kind)
                .ok_or(PoolError::NoSuchInode(ino))?
        };
        if kind != InodeKind::File {
            return Err(PoolError::Format(format!("ino {ino} is not a regular file")));
        }

        // E.5: always the whole-file fallback path (ported as-is from
        // Phase B, but committing chunks through prep/committer instead of
        // a direct segment-writer call) — proves the new concurrent
        // plumbing end-to-end before E.6 layers the sequential fast path
        // on top.
        self.hydrate_file_state(ino)?;
        {
            let mut file_state = self.file_state.lock();
            let state = file_state.get_mut(&ino).unwrap();
            let end = offset as usize + buf.len();
            if state.contents.len() < end {
                state.contents.resize(end, 0);
            }
            state.contents[offset as usize..end].copy_from_slice(buf);
        }
        self.rechunk_and_touch(ino)
    }

    /// `setattr`'s `size` field (ARCHITECTURE.md §9): truncate/zero-extend
    /// a file's content, independent of any `write()`.
    fn set_size(&self, ino: u64, new_size: u64) -> Result<(), PoolError> {
        let kind = {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .get(&ino)
                .map(|i| i.kind)
                .ok_or(PoolError::NoSuchInode(ino))?
        };
        if kind != InodeKind::File {
            return Err(PoolError::Format(format!("ino {ino} is not a regular file")));
        }
        self.hydrate_file_state(ino)?;
        self.file_state
            .lock()
            .get_mut(&ino)
            .unwrap()
            .contents
            .resize(new_size as usize, 0);
        self.rechunk_and_touch(ino)
    }

    /// Shared tail of `write()`/`set_size()`: re-derives inline-vs-chunked
    /// representation from `file_state[ino]`'s current bytes, updates
    /// size/mtime/ctime, and marks the inode dirty for the next
    /// checkpoint.
    fn rechunk_and_touch(&self, ino: u64) -> Result<(), PoolError> {
        let content_snapshot = self.file_state.lock()[&ino].contents.clone();
        let new_size = content_snapshot.len() as u64;

        let chunks = if new_size <= self.pool_params.inline_threshold as u64 {
            Vec::new()
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
                let (hash, _loc) = self.commit_chunk(ino, b.offset, bytes)?;
                refs.push(ChunkRef {
                    content_hash: hash,
                    logical_offset: b.offset,
                    len: b.len,
                });
            }
            refs
        };
        self.file_state.lock().get_mut(&ino).unwrap().chunks = chunks;

        let (now_secs, now_nanos) = now_unix();
        let mut namespace = self.namespace.lock();
        let inode = namespace.inodes.get_mut(&ino).unwrap();
        inode.size = new_size;
        inode.mtime = (now_secs, now_nanos);
        inode.ctime = (now_secs, now_nanos);
        namespace.dirty_inodes.insert(ino);
        Ok(())
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> Result<Option<u64>, PoolError> {
        let namespace = self.namespace.lock();
        let dir = namespace
            .dirs
            .get(&parent_ino)
            .ok_or(PoolError::NotADirectory(parent_ino))?;
        Ok(dir.entries.iter().find(|e| e.name == name).map(|e| e.ino))
    }

    fn create_entry(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        kind: InodeKind,
    ) -> Result<u64, PoolError> {
        let mut namespace = self.namespace.lock();
        if !namespace.dirs.contains_key(&parent_ino) {
            return Err(PoolError::NotADirectory(parent_ino));
        }
        if namespace
            .dirs
            .get(&parent_ino)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.name == name)
        {
            return Err(PoolError::AlreadyExists(name.to_string()));
        }

        let ino = namespace.next_ino;
        namespace.next_ino += 1;

        let (now_secs, now_nanos) = now_unix();
        let (content, nlink) = match kind {
            InodeKind::Directory => (ContentRef::DirEntries(Hash32([0; 32])), 2),
            InodeKind::File => (ContentRef::Inline(Vec::new()), 1),
            InodeKind::Symlink => (ContentRef::SymlinkTarget(String::new()), 1),
        };
        namespace.inodes.insert(
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
            namespace.dirs.insert(ino, DirectoryObject::default());
        }

        let dir = namespace.dirs.get_mut(&parent_ino).unwrap();
        dir.entries.push(DirEntry {
            name: name.to_string(),
            ino,
            kind,
        });
        dir.entries.sort_by(|a, b| a.name.cmp(&b.name));
        namespace.parents.insert(ino, parent_ino);

        namespace.dirty_inodes.insert(parent_ino);
        namespace.dirty_inodes.insert(ino);
        Ok(ino)
    }

    /// The fast per-shard fsync path — E.5 placeholder still delegates to
    /// the full checkpoint (upgraded to the real per-shard delta-log path
    /// in E.7).
    fn fsync(&self, _ino: u64) -> Result<(), PoolError> {
        self.run_checkpoint()
    }

    /// The 5-step global checkpoint (ARCHITECTURE.md §3): flush/fsync data
    /// -> bottom-up rewrite dirty meta objects -> fsync meta -> build+fsync
    /// RootObject -> write+fsync superblock slot. The invariant that makes
    /// this journal-free: no parent's hash is ever computed over a child
    /// whose bytes aren't yet fsync'd — enforced here simply by ordering
    /// every write before the fsync/superblock steps that depend on it.
    fn run_checkpoint(&self) -> Result<(), PoolError> {
        let _checkpoint_guard = self.checkpoint_lock.lock();

        // Barrier #1: every shard's committer has appended to its own
        // Data-stream segment since the last checkpoint; fsync all of them
        // before any parent hash referencing their contents is committed.
        // (E.8 upgrade point for shard_watermarks -- fsync_all already
        // covers every shard today.)
        self.committer_pool.fsync_all()?;

        let dirty: Vec<u64> = {
            let mut namespace = self.namespace.lock();
            namespace.dirty_inodes.drain().collect()
        };

        struct DirtyWork {
            ino: u64,
            kind: InodeKind,
            size: u64,
            dir: Option<DirectoryObject>,
        }
        let work: Vec<DirtyWork> = {
            let namespace = self.namespace.lock();
            dirty
                .iter()
                .filter_map(|ino| {
                    namespace.inodes.get(ino).map(|inode| DirtyWork {
                        ino: *ino,
                        kind: inode.kind,
                        size: inode.size,
                        dir: if inode.kind == InodeKind::Directory {
                            namespace.dirs.get(ino).cloned()
                        } else {
                            None
                        },
                    })
                })
                .collect()
        };

        let file_state_snapshot: HashMap<u64, FileWorkingState> = {
            let file_state = self.file_state.lock();
            work.iter()
                .filter(|w| w.kind == InodeKind::File)
                .filter_map(|w| file_state.get(&w.ino).cloned().map(|s| (w.ino, s)))
                .collect()
        };

        let mut new_content: HashMap<u64, ContentRef> = HashMap::new();
        for w in &work {
            let content_ref = match w.kind {
                InodeKind::Directory => {
                    let dir = w.dir.clone().unwrap_or_default();
                    let (hash, _loc) = self.put_meta_object(ExtentKind::DirectoryObject, &dir)?;
                    ContentRef::DirEntries(hash)
                }
                InodeKind::File => {
                    if w.size <= self.pool_params.inline_threshold as u64 {
                        let bytes = file_state_snapshot
                            .get(&w.ino)
                            .map(|s| s.contents.clone())
                            .unwrap_or_default();
                        ContentRef::Inline(bytes)
                    } else {
                        let chunks = file_state_snapshot
                            .get(&w.ino)
                            .map(|s| s.chunks.clone())
                            .unwrap_or_default();
                        let ihl = IndirectHashList { chunks };
                        let (hash, _loc) =
                            self.put_meta_object(ExtentKind::IndirectHashList, &ihl)?;
                        ContentRef::ChunkList(hash)
                    }
                }
                InodeKind::Symlink => continue, // unchanged; content already correct
            };
            new_content.insert(w.ino, content_ref);
        }

        // Snapshot every inode (not just dirty ones) for the InoMap, under
        // one namespace lock, writing back the freshly-derived content
        // refs for dirty ones first.
        let ino_snapshot: Vec<(u64, InodeObject)> = {
            let mut namespace = self.namespace.lock();
            for (ino, content) in new_content {
                if let Some(inode) = namespace.inodes.get_mut(&ino) {
                    inode.content = content;
                }
            }
            let mut snap: Vec<_> = namespace
                .inodes
                .iter()
                .map(|(&ino, obj)| (ino, obj.clone()))
                .collect();
            snap.sort_by_key(|(ino, _)| *ino);
            snap
        };

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

        let existing_snapshot_table_hash = self.namespace.lock().snapshot_table_hash;
        let snapshot_table_hash = match existing_snapshot_table_hash {
            Some(h) => h,
            None => {
                let (h, _loc) =
                    self.put_meta_object(ExtentKind::SnapshotTable, &SnapshotTable::default())?;
                self.namespace.lock().snapshot_table_hash = Some(h);
                h
            }
        };

        let (next_ino_counter, generation_before) = {
            let namespace = self.namespace.lock();
            (namespace.next_ino, namespace.generation)
        };

        // E.8 upgrade point: populate from each shard's ShardDeltaLog
        // local_epoch instead of zeros.
        let shard_watermarks = vec![0u64; self.shard_delta_logs.len()];

        let root = RootObject {
            inomap_hash,
            root_dir_ino: ROOT_DIR_INO,
            next_ino_counter,
            snapshot_table_hash,
            pool_params: self.pool_params,
            shard_watermarks,
        };
        let (root_hash, root_location) = self.put_meta_object(ExtentKind::RootObject, &root)?;

        // Barrier #2: everything the new superblock slot will point to
        // (InodeObjects, DirectoryObjects, IndirectHashLists, InoMap,
        // SnapshotTable, RootObject) went to meta_writer above.
        self.meta_writer.lock().fsync()?;

        let generation = generation_before + 1;

        // Durably checkpoint the persisted index (Durability::Immediate,
        // fsyncs INDEX.redb) *before* the superblock slot below claims
        // `index_generation = generation` is valid -- if we crashed in
        // between, the old superblock slot (still pointing at the
        // previous generation) stays the recovery target and this index
        // checkpoint is simply orphaned, not referenced by anything yet.
        self.persisted_index.write().checkpoint(generation)?;

        let object_count = {
            let mut namespace = self.namespace.lock();
            namespace.generation = generation;
            namespace.root_hash = root_hash;
            namespace.inodes.len() as u64
        };

        let mut slot = SuperblockSlot {
            magic: SUPERBLOCK_MAGIC,
            format_version: lchfs_format::FORMAT_VERSION,
            generation,
            root_hash,
            root_location,
            index_generation: generation,
            committed_at_unix_nanos: {
                let (s, n) = now_unix();
                s * 1_000_000_000 + n as i64
            },
            stats: lchfs_format::SuperblockStats {
                live_bytes: 0,
                object_count,
                segment_count: self.next_segment_id.load(Ordering::Relaxed),
            },
            header_checksum: 0,
        };
        finalize_superblock_slot_checksum(&mut slot);
        write_superblock_slot(&self.superblock_backend, &slot)?;

        Ok(())
    }
}

fn get_reader<'a>(
    readers: &'a mut SegmentReaders,
    pool_root: &Path,
    segment_id: u64,
    kind: StreamKind,
) -> Result<&'a SegmentReader, PoolError> {
    if let std::collections::hash_map::Entry::Vacant(e) = readers.entry((segment_id, kind)) {
        e.insert(SegmentReader::open(pool_root, segment_id, kind)?);
    }
    Ok(readers.get(&(segment_id, kind)).unwrap())
}

/// Opens a `SegmentReader` for every existing segment file under
/// `pool_root/segments/{data,meta}` and returns the highest segment_id
/// seen -- cheap (one `open()` per file, parsed from its filename), no
/// per-record iteration. Shared by `scan_segments` (full scan, below) and
/// `Pool::open`'s fast mount path, which needs the readers and the next
/// segment_id to allocate but not a record-by-record rebuild of
/// `locations` when the persisted index already has it.
fn open_all_segment_readers(pool_root: &Path) -> Result<(SegmentReaders, u64), PoolError> {
    let mut readers = HashMap::new();
    let mut max_segment_id = 0u64;
    for kind in [StreamKind::Data, StreamKind::Meta] {
        let sub = match kind {
            StreamKind::Data => "data",
            StreamKind::Meta => "meta",
            StreamKind::Delta => {
                unreachable!("this loop only ever iterates Data/Meta; Delta streams are shard-scoped, see delta_log.rs")
            }
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
            readers.insert((segment_id, kind), reader);
        }
    }
    Ok((readers, max_segment_id))
}

fn scan_segments(
    pool_root: &Path,
    readers: &mut SegmentReaders,
    locations: &mut HashMap<Hash32, ExtentLocation>,
) -> Result<u64, PoolError> {
    let (opened, max_segment_id) = open_all_segment_readers(pool_root)?;
    for (&(segment_id, _kind), reader) in &opened {
        scan_one_segment(reader, segment_id, locations)?;
    }
    *readers = opened;
    Ok(max_segment_id)
}

/// Rebuilds `INDEX.redb` from a freshly (re)scanned `locations` map and
/// checkpoints it at `generation` so the *next* `Pool::open` can take the
/// fast path. Reuses the existing file if it opens (even if its
/// generation is stale -- old entries are harmless leftovers, since
/// content-addressed extents are immutable), starts fresh only if it's
/// missing or corrupt.
fn rebuild_index(
    index_file: &Path,
    locations: &HashMap<Hash32, ExtentLocation>,
    generation: u64,
) -> Result<RedbIndex, PoolError> {
    let mut index = match RedbIndex::open(index_file) {
        Ok(idx) => idx,
        Err(_) => {
            let _ = std::fs::remove_file(index_file);
            RedbIndex::create(index_file)?
        }
    };
    for (&hash, &loc) in locations {
        index.put_chunk_location(hash, loc)?;
    }
    index.checkpoint(generation)?;
    Ok(index)
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
