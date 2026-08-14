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

pub(crate) mod background;
pub mod backend;
pub mod checkpoint;
pub mod coalesce;
pub(crate) mod dag_walk;
pub mod dedup;
pub mod delta_log;
pub mod gc;
pub mod ingress;
pub mod prep;
pub mod segment;

use bytes::Bytes;
use delta_log::{ShardCommitRecord, ShardDeltaLog};
use ingress::{CommitterPool, IngressOp};
use lchfs_chunk::{ChunkBoundary, Chunker, FastCdcChunker};
use lchfs_format::{
    ChunkRef, CodecId, ContentRef, DirEntry, DirectoryObject, ExtentKind, ExtentLocation, Hash32,
    InoMap, InoMapEntry, InodeKind, InodeObject, IndirectHashList, PoolParams, RootObject,
    SnapshotEntry, SnapshotTable, StreamKind, SuperblockSlot, SUPERBLOCK_MAGIC, SUPERBLOCK_SLOT_COUNT,
    SUPERBLOCK_SLOT_SIZE, compute_superblock_slot_checksum, finalize_superblock_slot_checksum,
};
use lchfs_index::{ChunkLocationCache, IndexError, IndexStore, PendingDedupPins, RedbIndex};
use parking_lot::{Mutex, RwLock};
use prep::{IngestPreparationPool, PrepTask, PreparedChunk, prepare_chunk};
use segment::{SegmentError, SegmentReader, SegmentWriter};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    #[error("requested file size {0} exceeds the maximum ({MAX_FILE_SIZE})")]
    TooLarge(u64),
    #[error("is a directory: {0}")]
    IsADirectory(u64),
    #[error("directory not empty: {0}")]
    NotEmpty(u64),
    #[error("not a symlink: {0}")]
    NotASymlink(u64),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

/// Filesystem-wide usage stats for `statfs` (ARCHITECTURE.md §9). See
/// `PoolShared::statfs`'s doc comment for how each field is derived.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub block_size: u32,
    pub fragment_size: u32,
    pub blocks_total: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files_total: u64,
    pub files_free: u64,
    pub name_max: u32,
}

/// Hard cap on file size while `write()`'s fallback path and `set_size()`
/// still materialize a file's entire content in memory (`file_state`).
/// Not a permanent limit -- once `SpliceChunker` (lchfs-chunk's own
/// tracked TODO) lands and overwrites no longer require a whole-file
/// rehydrate, this can grow substantially. For now it exists purely so a
/// user-triggered `write(2)`/`truncate(2)` to an enormous offset/size
/// returns EFBIG instead of attempting a multi-terabyte allocation that
/// can OOM-kill the whole mount daemon.
const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB

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
/// How often the Coalescing Daemon (which drives GC mark-and-sweep) runs
/// an idle-cycle pass. Deliberately much longer than the checkpoint
/// interval -- this is idle-cycle background work, not foreground-
/// critical durability (ARCHITECTURE.md §5).
const COALESCE_INTERVAL: Duration = Duration::from_secs(60);
/// How often the Dedup Index Scanner runs. Shorter than the coalesce
/// interval: its pass is cheap (header scans + index lookups, no
/// physical rewrite), and faster convergence bounds how long duplicate
/// space sits around before Coalesce/GC can reclaim it.
const DEDUP_INTERVAL: Duration = Duration::from_secs(30);

fn index_path(pool_root: &Path) -> PathBuf {
    pool_root.join("INDEX.redb")
}

pub(crate) type SegmentReaders = HashMap<(u64, StreamKind), SegmentReader>;

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
    /// The file's size when this session began -- `FastCdcChunker`'s own
    /// boundary offsets always start from 0 for a fresh instance, so this
    /// is added back in to get each `ChunkRef`'s true logical offset.
    base_offset: u64,
    next_expected_offset: u64,
    /// Finalized chunk refs: the file's existing chunks as of session
    /// start (seeded via `PoolShared::current_chunk_refs`, cheap -- reads
    /// just the IndirectHashList's metadata, no chunk payloads) plus any
    /// newly committed during this session.
    chunks: Vec<ChunkRef>,
    /// Mirrors `chunker`'s internal buffered tail so a finalized
    /// `ChunkBoundary` (which carries only an offset/len, not bytes) can
    /// be sliced out of *something* -- the chunker itself doesn't expose
    /// its buffer. Drained in lockstep with the chunker's own draining.
    pending_bytes: Vec<u8>,
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
    /// Per-inode lock serializing `write()`/`set_size()`/checkpoint's
    /// dirty-file finalization for a *given* inode end-to-end (splice or
    /// incremental-commit through the Namespace update), matching
    /// ARCHITECTURE.md §3's per-inode ordering guarantee. Cross-inode
    /// writes stay fully concurrent -- only same-inode operations
    /// serialize. Lazily populated, never pruned (one tiny `Arc<Mutex<()>>`
    /// per ever-touched inode for the pool's lifetime -- an accepted,
    /// bounded-in-practice simplification, not addressed here).
    ino_locks: Mutex<HashMap<u64, Arc<Mutex<()>>>>,

    /// Content-address -> location, for both RawChunk (data stream) and
    /// every meta object kind (meta stream) — same dual purpose Phase B's
    /// flat `locations` map served. Sharded internally (lchfs-index); the
    /// hot path in front of `persisted_index` below.
    dedup_index: Arc<ChunkLocationCache>,
    /// Hashes with an in-flight dedup-hit write not yet captured by a
    /// published root -- see `PendingDedupPins`'s doc comment. Protects
    /// `CoalesceDaemon`'s repacks from reclaiming a location a write
    /// still depends on but hasn't checkpointed yet.
    dedup_pins: Arc<PendingDedupPins>,
    /// Persisted `INDEX.redb` (Phase C, ARCHITECTURE.md §4): "a
    /// rebuildable cache, never authoritative." `RwLock` since
    /// `get_chunk_location` only needs shared access while `put_*`/
    /// `checkpoint` need exclusive.
    persisted_index: RwLock<RedbIndex>,
    readers: Mutex<SegmentReaders>,

    meta_writer: Mutex<SegmentWriter>,
    next_segment_id: Arc<AtomicU64>,
    /// Mirrors `Namespace::generation`, updated at the same point
    /// `run_checkpoint` publishes a new root. A plain shared counter (not
    /// a `Namespace` handle) so `CoalesceDaemon`/`GcEngine` can cheaply
    /// detect "a checkpoint happened during this pass" without coupling
    /// coalesce.rs to `Namespace` -- see `CoalesceDaemon::run_pass`'s doc
    /// comment for why that specific check exists.
    published_generation: Arc<AtomicU64>,

    committer_pool: CommitterPool,
    prep_pool: IngestPreparationPool,
    shard_delta_logs: Vec<Mutex<ShardDeltaLog>>,

    checkpoint_lock: Mutex<()>,
    coalesce: Mutex<coalesce::CoalesceDaemon>,
    dedup: Mutex<dedup::DedupScanner>,
    /// `None` until `spawn_background_threads` runs (after this
    /// `PoolShared` is wrapped in its `Arc`, which each timer's closure
    /// needs to clone -- see that method's doc comment).
    checkpoint_task: Mutex<Option<background::PeriodicTask>>,
    coalesce_task: Mutex<Option<background::PeriodicTask>>,
    dedup_task: Mutex<Option<background::PeriodicTask>>,
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
        let dedup_pins = Arc::new(PendingDedupPins::new());
        let persisted_index = RedbIndex::create(&index_path(pool_root))?;
        let prep_pool = IngestPreparationPool::new(
            committer_thread_count(),
            Arc::clone(&dedup_index),
            Arc::clone(&dedup_pins),
        );
        let published_generation = Arc::new(AtomicU64::new(0));

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
            ino_locks: Mutex::new(HashMap::new()),
            dedup_index: Arc::clone(&dedup_index),
            dedup_pins: Arc::clone(&dedup_pins),
            persisted_index: RwLock::new(persisted_index),
            readers: Mutex::new(HashMap::new()),
            meta_writer: Mutex::new(meta_writer),
            next_segment_id,
            published_generation,
            committer_pool,
            prep_pool,
            shard_delta_logs,
            checkpoint_lock: Mutex::new(()),
            coalesce: Mutex::new(coalesce::CoalesceDaemon::new(
                pool_root.to_path_buf(),
                Arc::clone(&dedup_index),
                Arc::clone(&dedup_pins),
            )),
            dedup: Mutex::new(dedup::DedupScanner::new(
                pool_root.to_path_buf(),
                Arc::clone(&dedup_index),
            )),
            checkpoint_task: Mutex::new(None),
            coalesce_task: Mutex::new(None),
            dedup_task: Mutex::new(None),
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

        let (mut readers, mut locations, max_segment_id, persisted_index, took_fast_path) =
            if let Some(index) = fresh_index {
                let (readers, max_segment_id) = open_all_segment_readers(pool_root)?;
                let locations: HashMap<Hash32, ExtentLocation> =
                    index.iter_chunk_locations()?.into_iter().collect();
                (readers, locations, max_segment_id, index, true)
            } else {
                let mut readers = HashMap::new();
                let mut locations = HashMap::new();
                let max_segment_id = scan_segments(pool_root, &mut readers, &mut locations)?;
                let index = rebuild_index(&index_file, &locations, slot.generation)?;
                // The slow path's full scan already covers every segment
                // unconditionally, so it has no analog of the fast path's
                // "index might be missing recent, un-checkpointed
                // entries" gap -- no owner_shard rescan needed here.
                (readers, locations, max_segment_id, index, false)
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

        // Two-tier crash recovery (ARCHITECTURE.md §7): the InoMap walk
        // above is tier one (the last full checkpoint's base state). Tier
        // two replays each shard's delta log for anything committed via
        // `fsync` (E.7) since that checkpoint's `shard_watermarks` entry
        // for it -- unconditional, every mount, never skipped by the
        // index-freshness fast path (that fast path only concerns
        // `locations`/`INDEX.redb`, not delta-log replay, which exists
        // specifically to cover activity *after* the index's own last
        // checkpoint).
        let mut shard_delta_logs = Vec::with_capacity(shard_count as usize);
        let mut file_state_from_replay: HashMap<u64, FileWorkingState> = HashMap::new();
        // Every replayed inode is marked dirty below (not just those with
        // ChunkList content): a replayed InodeObject's own hash was only
        // ever registered in its shard's delta stream, never the global
        // meta stream/dedup_index. The *InodeObject itself* would get
        // re-registered regardless by run_checkpoint's unconditional
        // "snapshot every inode" pass -- but for ChunkList content
        // specifically, the *referenced* IndirectHashList is never
        // independently touched by that pass, only by the per-file dirty-
        // inode loop that re-derives and re-registers it via
        // put_meta_object. Without this, the very first GC mark pass
        // after a crash-recovered mount hits an unresolvable hash and
        // aborts -- found by actually running a live mount through a
        // crash/recover/coalesce cycle, not by unit tests alone (none of
        // which exercised replay immediately followed by GC).
        let mut replayed_inos: HashSet<u64> = HashSet::new();
        for shard_id in 0..shard_count {
            let shard_log = ShardDeltaLog::open(pool_root, shard_id)?;
            let watermark = root
                .shard_watermarks
                .get(shard_id as usize)
                .copied()
                .unwrap_or(0);
            let replay = shard_log.replay_since(watermark)?;

            if !replay.entries.is_empty() {
                // The InodeObject/IndirectHashList records this shard's
                // replayed entries reference live only in its own Delta
                // stream -- resolved from `replay.locations` directly,
                // deliberately kept separate from the shared `locations`/
                // `dedup_index` (which callers elsewhere assume means
                // Data/Meta streams specifically).
                let delta_locations: HashMap<Hash32, ExtentLocation> =
                    replay.locations.into_iter().collect();

                // Backfill this shard's chunk locations that the fast
                // mount path's INDEX.redb snapshot might be missing --
                // see `owner_shard_rescan`'s doc comment. Skipped on the
                // slow path, which already scanned everything.
                if took_fast_path {
                    owner_shard_rescan(&readers, shard_id, &mut locations)?;
                }

                for entry in &replay.entries {
                    let loc = delta_locations.get(&entry.new_object_hash).ok_or_else(|| {
                        PoolError::Format(format!(
                            "replayed InodeObject for ino {} (shard {shard_id}) missing from its delta log",
                            entry.ino
                        ))
                    })?;
                    let delta_reader =
                        SegmentReader::open_delta(pool_root, shard_id, loc.segment_id)?;
                    let (_h, bytes) = delta_reader.read_record(*loc)?;
                    let inode: InodeObject = lchfs_format::decode(&bytes)
                        .map_err(|e| PoolError::Format(e.to_string()))?;

                    // Same reasoning as E.7's fsync: this InodeObject's
                    // ContentRef hash (if ChunkList) is only resolvable
                    // through this shard's own delta log, not the global
                    // index -- so materialize file_state directly here,
                    // at recovery time, rather than leave a dangling
                    // reference an ordinary future read() can't resolve.
                    if inode.kind == InodeKind::File
                        && let ContentRef::ChunkList(ihl_hash) = &inode.content
                    {
                        let ihl_loc = delta_locations.get(ihl_hash).ok_or_else(|| {
                            PoolError::Format(format!(
                                "replayed IndirectHashList for ino {} (shard {shard_id}) missing from its delta log",
                                entry.ino
                            ))
                        })?;
                        let ihl_reader =
                            SegmentReader::open_delta(pool_root, shard_id, ihl_loc.segment_id)?;
                        let (_h, ihl_bytes) = ihl_reader.read_record(*ihl_loc)?;
                        let ihl: IndirectHashList = lchfs_format::decode(&ihl_bytes)
                            .map_err(|e| PoolError::Format(e.to_string()))?;
                        let mut contents = Vec::new();
                        for chunk in &ihl.chunks {
                            let chunk_loc = locations.get(&chunk.content_hash).ok_or_else(|| {
                                PoolError::Format(format!(
                                    "chunk {:?} referenced by replayed ino {} not found",
                                    chunk.content_hash, entry.ino
                                ))
                            })?;
                            let reader = get_reader(
                                &mut readers,
                                pool_root,
                                chunk_loc.segment_id,
                                StreamKind::Data,
                            )?;
                            let (_h, bytes) = reader.read_record(*chunk_loc)?;
                            contents.extend_from_slice(&bytes);
                        }
                        file_state_from_replay.insert(
                            entry.ino,
                            FileWorkingState {
                                contents,
                                chunks: ihl.chunks.clone(),
                            },
                        );
                    }

                    inodes.insert(entry.ino, inode);
                    replayed_inos.insert(entry.ino);
                }
            }

            shard_delta_logs.push(Mutex::new(shard_log));
        }

        let dedup_index = Arc::new(ChunkLocationCache::new());
        dedup_index.extend(locations);
        let dedup_pins = Arc::new(PendingDedupPins::new());
        let prep_pool = IngestPreparationPool::new(
            committer_thread_count(),
            Arc::clone(&dedup_index),
            Arc::clone(&dedup_pins),
        );
        let published_generation = Arc::new(AtomicU64::new(slot.generation));

        let namespace = Namespace {
            inodes,
            dirs,
            parents,
            next_ino,
            dirty_inodes: replayed_inos,
            generation: slot.generation,
            snapshot_table_hash: Some(root.snapshot_table_hash),
            root_hash: slot.root_hash,
        };

        let shared = Arc::new(PoolShared {
            pool_root: pool_root.to_path_buf(),
            pool_params: root.pool_params,
            superblock_backend,
            namespace: Mutex::new(namespace),
            file_state: Mutex::new(file_state_from_replay),
            open_files: Mutex::new(HashMap::new()),
            ino_locks: Mutex::new(HashMap::new()),
            dedup_index: Arc::clone(&dedup_index),
            dedup_pins: Arc::clone(&dedup_pins),
            persisted_index: RwLock::new(persisted_index),
            readers: Mutex::new(readers),
            meta_writer: Mutex::new(meta_writer),
            next_segment_id,
            published_generation,
            committer_pool,
            prep_pool,
            shard_delta_logs,
            checkpoint_lock: Mutex::new(()),
            coalesce: Mutex::new(coalesce::CoalesceDaemon::new(
                pool_root.to_path_buf(),
                Arc::clone(&dedup_index),
                Arc::clone(&dedup_pins),
            )),
            dedup: Mutex::new(dedup::DedupScanner::new(
                pool_root.to_path_buf(),
                Arc::clone(&dedup_index),
            )),
            checkpoint_task: Mutex::new(None),
            coalesce_task: Mutex::new(None),
            dedup_task: Mutex::new(None),
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
        self.0.create_entry(parent_ino, name, mode, InodeKind::Directory, None)
    }

    pub fn create_file(&self, parent_ino: u64, name: &str, mode: u32) -> Result<u64, PoolError> {
        self.0.create_entry(parent_ino, name, mode, InodeKind::File, None)
    }

    /// Creates a symlink at `parent_ino`/`name` pointing at `target`.
    /// Symlink permissions are conventionally ignored by the kernel and
    /// FUSE's own `symlink` callback doesn't pass a mode, so this always
    /// creates with `0o777`.
    pub fn symlink(&self, parent_ino: u64, name: &str, target: &str) -> Result<u64, PoolError> {
        self.0
            .create_entry(parent_ino, name, 0o777, InodeKind::Symlink, Some(target))
    }

    /// The target string of a symlink inode.
    pub fn readlink(&self, ino: u64) -> Result<String, PoolError> {
        let namespace = self.0.namespace.lock();
        let inode = namespace.inodes.get(&ino).ok_or(PoolError::NoSuchInode(ino))?;
        match &inode.content {
            ContentRef::SymlinkTarget(target) => Ok(target.clone()),
            _ => Err(PoolError::NotASymlink(ino)),
        }
    }

    /// Removes a non-directory `DirEntry`. `ENOTDIR`-equivalent
    /// (`PoolError::NotADirectory`) if `parent_ino` isn't a directory,
    /// `PoolError::IsADirectory` if `name` is one (use `rmdir`).
    pub fn unlink(&self, parent_ino: u64, name: &str) -> Result<(), PoolError> {
        self.0.unlink(parent_ino, name)
    }

    /// Removes an empty directory's `DirEntry`. `PoolError::NotEmpty` if
    /// it has any children.
    pub fn rmdir(&self, parent_ino: u64, name: &str) -> Result<(), PoolError> {
        self.0.rmdir(parent_ino, name)
    }

    /// `link` (hardlink): a second `DirEntry` for `ino`, no data I/O.
    pub fn link(&self, ino: u64, new_parent_ino: u64, new_name: &str) -> Result<(), PoolError> {
        self.0.link(ino, new_parent_ino, new_name)
    }

    /// `rename`, same-directory or cross-directory. `no_replace` rejects
    /// (rather than atomically replacing) an existing destination --
    /// FUSE's `RENAME_NOREPLACE`.
    pub fn rename(
        &self,
        parent_ino: u64,
        name: &str,
        new_parent_ino: u64,
        new_name: &str,
        no_replace: bool,
    ) -> Result<(), PoolError> {
        self.0.rename(parent_ino, name, new_parent_ino, new_name, no_replace)
    }

    /// Filesystem-wide usage stats (`statfs`).
    pub fn statfs(&self) -> Result<PoolStats, PoolError> {
        self.0.statfs()
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

    /// The current global root's content hash (test/tooling support --
    /// e.g. constructing a `GcEngine::mark` live-roots list against a
    /// specific past checkpoint without needing real snapshot-retention
    /// support). Not meant for filesystem-logic use; `Pool`'s own
    /// checkpoint/GC machinery reads this from `Namespace` directly.
    pub fn debug_root_hash(&self) -> Hash32 {
        self.0.namespace.lock().root_hash
    }

    /// Runs one GC-mark-and-coalesce pass synchronously (ARCHITECTURE.md
    /// §6). The background `CoalesceDaemon` (coalesce.rs) calls this same
    /// path on its own timer; exposed publicly so tests can call it
    /// directly instead of racing that timer.
    pub fn run_gc_and_coalesce_pass(&self) -> Result<(), PoolError> {
        self.0.run_gc_and_coalesce_pass()
    }

    /// Runs one Dedup Index Scanner pass synchronously. The background
    /// `DedupScanner` (dedup.rs) calls this same path on its own timer;
    /// exposed publicly so tests can call it directly instead of racing
    /// that timer.
    pub fn run_dedup_pass(&self) -> Result<Vec<dedup::DedupMerge>, PoolError> {
        self.0.run_dedup_pass()
    }

    /// Test/tooling support -- see `PoolShared::debug_force_duplicate_chunk`.
    pub fn debug_force_duplicate_chunk(&self, raw_bytes: &[u8]) -> Result<ExtentLocation, PoolError> {
        self.0.debug_force_duplicate_chunk(raw_bytes)
    }

    /// Retains the current state as a named snapshot (ARCHITECTURE.md §6).
    /// `PoolError::AlreadyExists` if `name` is already taken.
    pub fn create_snapshot(&self, name: &str) -> Result<(), PoolError> {
        self.0.create_snapshot(name)
    }

    /// Removes a named snapshot. `PoolError::NotFound` if it doesn't
    /// exist. Its exclusively-referenced content becomes reclaimable by
    /// ordinary GC from the next `run_gc_and_coalesce_pass` on -- no
    /// separate cleanup happens here (ARCHITECTURE.md §6).
    pub fn delete_snapshot(&self, name: &str) -> Result<(), PoolError> {
        self.0.delete_snapshot(name)
    }

    /// Every currently-retained snapshot.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotEntry>, PoolError> {
        self.0.list_snapshots()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // Dropping each PeriodicTask (its own Drop impl) signals its
        // shutdown flag and joins its thread -- see background.rs. Must
        // happen before the Arc's refcount can reach zero (each task's
        // own closure holds a clone), which is exactly what taking them
        // out of their Mutexes and letting them drop right here achieves.
        self.0.checkpoint_task.lock().take();
        self.0.coalesce_task.lock().take();
        self.0.dedup_task.lock().take();
    }
}

impl PoolShared {
    /// Spawns background threads that need to call back into `self` --
    /// must run after this `PoolShared` is wrapped in its `Arc` (`create`/
    /// `open` do so immediately after construction), since each timer's
    /// closure needs its own `Arc<PoolShared>` clone.
    fn spawn_background_threads(self: &Arc<Self>) {
        let checkpoint_shared = Arc::clone(self);
        let checkpoint_task = background::PeriodicTask::spawn(
            "lchfs-checkpoint",
            CHECKPOINT_INTERVAL,
            move || {
                let _ = checkpoint_shared.run_checkpoint();
            },
        );
        *self.checkpoint_task.lock() = Some(checkpoint_task);

        let coalesce_shared = Arc::clone(self);
        let coalesce_task = background::PeriodicTask::spawn(
            "lchfs-coalesce",
            COALESCE_INTERVAL,
            move || {
                let _ = coalesce_shared.run_gc_and_coalesce_pass();
            },
        );
        *self.coalesce_task.lock() = Some(coalesce_task);

        let dedup_shared = Arc::clone(self);
        let dedup_task = background::PeriodicTask::spawn("lchfs-dedup", DEDUP_INTERVAL, move || {
            let _ = dedup_shared.run_dedup_pass();
        });
        *self.dedup_task.lock() = Some(dedup_task);
    }

    /// One idle-cycle GC-mark-and-coalesce pass (ARCHITECTURE.md §6):
    /// snapshot the current root as the live-roots list, then hand off to
    /// `CoalesceDaemon`. `Pool::run_gc_and_coalesce_pass` (below) is the
    /// same thing, exposed publicly for tests to call synchronously
    /// instead of racing the background timer.
    fn run_gc_and_coalesce_pass(&self) -> Result<(), PoolError> {
        let (mut live_roots, generation_at_mark) = {
            let namespace = self.namespace.lock();
            (vec![namespace.root_hash], namespace.generation)
        };
        // ARCHITECTURE.md §6: "Live roots = {current superblock root_hash}
        // ∪ {every SnapshotTable entry's root_hash} ∪ {snapshot_table_hash}".
        // The current root_hash alone (above) already covers the third set
        // member -- walking it marks its own `snapshot_table_hash` record
        // live (see dag_walk.rs's `walk_reachable`) -- but a bare
        // SnapshotTable record deliberately does *not* recurse into its
        // entries' own roots (same doc comment: "its entries' roots are
        // separately present in the caller's live_roots list"), so every
        // retained snapshot's root must be added here explicitly, or its
        // exclusively-referenced content would be silently swept the next
        // time this pass runs -- the entire point of retaining a snapshot
        // is that GC leaves its content alone.
        //
        // A resolution failure here must abort the whole pass, not
        // silently proceed with an incomplete live-roots list (which would
        // read "couldn't find the snapshot table" as "no snapshots exist,"
        // exactly the false-negative `GcEngine::mark`'s own doc comment
        // warns a partial live-set would create).
        let snapshot_table = self.current_snapshot_table()?;
        live_roots.extend(snapshot_table.entries.iter().map(|e| e.root_hash));

        self.coalesce.lock().run_pass(
            &live_roots,
            generation_at_mark,
            &self.published_generation,
            &self.persisted_index,
            &self.next_segment_id,
        )?;
        Ok(())
    }

    /// One idle-cycle Dedup Index Scanner pass. `Pool::run_dedup_pass`
    /// (below) is the same thing, exposed publicly for tests.
    fn run_dedup_pass(&self) -> Result<Vec<dedup::DedupMerge>, PoolError> {
        Ok(self.dedup.lock().run_pass(&self.persisted_index)?)
    }

    /// Resolves and decodes the current `SnapshotTable`. `None` (no table
    /// has ever been created) decodes as empty rather than erroring --
    /// matches `run_checkpoint`'s own lazy-create-on-first-checkpoint
    /// behavior, so this is always meaningful to call, even on a pool
    /// that's never had a snapshot.
    fn current_snapshot_table(&self) -> Result<SnapshotTable, PoolError> {
        let hash = self.namespace.lock().snapshot_table_hash;
        match hash {
            None => Ok(SnapshotTable::default()),
            Some(hash) => {
                let bytes = self.read_meta_object_bytes(hash)?;
                lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))
            }
        }
    }

    /// Durably writes `table` as the new `SnapshotTable` and publishes it
    /// via a checkpoint -- shared tail for `create_snapshot`/`delete_snapshot`.
    fn publish_snapshot_table(&self, table: &SnapshotTable) -> Result<(), PoolError> {
        let (hash, _loc) = self.put_meta_object(ExtentKind::SnapshotTable, table)?;
        self.namespace.lock().snapshot_table_hash = Some(hash);
        self.run_checkpoint()
    }

    /// Retains the current state as a named snapshot (ARCHITECTURE.md §6:
    /// "retaining one = adding a `SnapshotTable` entry, an ordinary
    /// content-addressed write"). Two checkpoints, deliberately: the first
    /// makes whatever's about to be retained durable and gives it a stable
    /// `root_hash` to record; the second durably publishes the updated
    /// `SnapshotTable` itself, so `create_snapshot` returning `Ok` means
    /// the retention has *itself* survived a crash, not just the content
    /// it points at.
    fn create_snapshot(&self, name: &str) -> Result<(), PoolError> {
        self.run_checkpoint()?;
        let (root_to_retain, epoch) = {
            let namespace = self.namespace.lock();
            (namespace.root_hash, namespace.generation)
        };

        let mut table = self.current_snapshot_table()?;
        if table.entries.iter().any(|e| e.name == name) {
            return Err(PoolError::AlreadyExists(name.to_string()));
        }
        let (now_secs, now_nanos) = now_unix();
        table.entries.push(SnapshotEntry {
            name: name.to_string(),
            root_hash: root_to_retain,
            created_at_unix_nanos: now_secs * 1_000_000_000 + now_nanos as i64,
            epoch,
        });

        self.publish_snapshot_table(&table)
    }

    /// Removes a named snapshot's `SnapshotTable` entry. Per ARCHITECTURE.md
    /// §6: "no separate 'snapshot delete' logic" -- content exclusively
    /// referenced by the removed entry simply stops being included in
    /// `run_gc_and_coalesce_pass`'s live-roots list from here on, and
    /// becomes reclaimable on the next ordinary mark-sweep.
    fn delete_snapshot(&self, name: &str) -> Result<(), PoolError> {
        let mut table = self.current_snapshot_table()?;
        let before = table.entries.len();
        table.entries.retain(|e| e.name != name);
        if table.entries.len() == before {
            return Err(PoolError::NotFound(name.to_string()));
        }
        self.publish_snapshot_table(&table)
    }

    fn list_snapshots(&self) -> Result<Vec<SnapshotEntry>, PoolError> {
        Ok(self.current_snapshot_table()?.entries)
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

        // An active incremental-append session (E.6) hasn't been
        // checkpointed/fsync'd yet, so the persisted ContentRef is stale --
        // assemble straight from the session instead of touching
        // `file_state` at all. Rare path (reads interleaved with an
        // in-flight append session), not the hot path this optimization
        // targets, so a straightforward (already-committed chunks read
        // back + buffered tail) assembly is an acceptable cost here.
        let session_snapshot = self
            .open_files
            .lock()
            .get(&ino)
            .map(|s| (s.chunks.clone(), s.pending_bytes.clone()));
        let content = if let Some((chunks, pending)) = session_snapshot {
            let mut buf = Vec::new();
            for chunk in &chunks {
                buf.extend_from_slice(&self.read_chunk_bytes(chunk.content_hash)?);
            }
            buf.extend_from_slice(&pending);
            buf
        } else {
            self.hydrate_file_state(ino)?;
            self.file_state.lock()[&ino].contents.clone()
        };

        let start = (offset as usize).min(content.len());
        let end = (start + len as usize).min(content.len());
        Ok(Bytes::copy_from_slice(&content[start..end]))
    }

    /// The file's current chunk list, for seeding a new incremental-append
    /// session. `Namespace.inodes[ino].content` only gets updated at
    /// checkpoint time (see `run_checkpoint`'s per-file loop) -- it lags
    /// behind `file_state[ino].chunks`, which every fallback-path write
    /// keeps current immediately. So: prefer `file_state` when hydrated
    /// (no chunk-payload reads, just a clone of already-in-memory refs);
    /// only fall back to decoding the persisted `IndirectHashList` (cheap,
    /// metadata only, no chunk payload reads either) when `file_state` was
    /// never populated -- e.g. right after `Pool::open`, before any write
    /// has touched this ino yet. Empty for anything not currently chunked
    /// by either source (inline files, directories, symlinks).
    fn current_chunks_for_new_session(&self, ino: u64) -> Result<Vec<ChunkRef>, PoolError> {
        if let Some(state) = self.file_state.lock().get(&ino) {
            return Ok(state.chunks.clone());
        }
        self.current_chunk_refs(ino)
    }

    fn current_chunk_refs(&self, ino: u64) -> Result<Vec<ChunkRef>, PoolError> {
        let content_ref = {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .get(&ino)
                .map(|i| i.content.clone())
                .ok_or(PoolError::NoSuchInode(ino))?
        };
        match content_ref {
            ContentRef::ChunkList(hash) => {
                let bytes = self.read_meta_object_bytes(hash)?;
                let ihl: IndirectHashList =
                    lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
                Ok(ihl.chunks)
            }
            _ => Ok(Vec::new()),
        }
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

    /// Test/tooling support for exercising `DedupScanner`'s convergence
    /// (dedup.rs) deterministically, without depending on real thread
    /// timing to reproduce the race it's meant to catch (two logical
    /// shards committing byte-identical new content in the same epoch,
    /// neither seeing the other's not-yet-indexed write). This is
    /// `commit_chunk`'s `New` path with the dedup-hit check bypassed
    /// (`prepare_chunk` run against a throwaway, always-empty cache) and,
    /// deliberately, the index update skipped afterward -- updating it
    /// here would immediately erase the very duplicate this exists to
    /// create.
    pub fn debug_force_duplicate_chunk(&self, raw_bytes: &[u8]) -> Result<ExtentLocation, PoolError> {
        let throwaway = ChunkLocationCache::new();
        let throwaway_pins = PendingDedupPins::new();
        let prepared = prepare_chunk(raw_bytes, &throwaway, &throwaway_pins);
        let PreparedChunk::New {
            content_hash,
            codec_id,
            uncompressed_len,
            payload,
        } = prepared
        else {
            unreachable!("a fresh, empty ChunkLocationCache never produces a Dedup hit");
        };

        let (tx, rx) = crossbeam::channel::bounded(1);
        self.committer_pool.push(IngressOp {
            inode_id: 0,
            content_hash,
            codec_id,
            uncompressed_len,
            payload,
            logical_offset: 0,
            completion: tx,
        });
        let location = rx
            .recv()
            .map_err(|_| PoolError::Format("committer pool completion channel closed".into()))??;
        Ok(location)
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

    /// Gets (creating if absent) the per-inode lock serializing this
    /// inode's write-path operations end-to-end (ARCHITECTURE.md §3's
    /// per-inode ordering guarantee -- see `ino_locks`'s doc comment).
    fn lock_for_ino(&self, ino: u64) -> Arc<Mutex<()>> {
        Arc::clone(
            self.ino_locks
                .lock()
                .entry(ino)
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// ARCHITECTURE.md §3 (write path). Sequential-append writes onto an
    /// already-chunked file (the dominant real pattern: cp/tar/log-append)
    /// take the incremental fast path straight through `write_incremental`
    /// -- no whole-file rehydrate, no full rechunk-from-scratch, just the
    /// new bytes. Anything else (a genuine seek/overwrite, or a file still
    /// small enough to be inline) falls back to the whole-file rehydrate-
    /// and-rechunk path, unchanged from E.5/Phase B.
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
        if buf.is_empty() {
            return Ok(());
        }

        let ino_lock = self.lock_for_ino(ino);
        let _guard = ino_lock.lock();

        let continuation = self
            .open_files
            .lock()
            .get(&ino)
            .is_some_and(|s| s.next_expected_offset == offset);
        if continuation {
            return self.write_incremental(ino, buf);
        }

        // Any existing session is now stale relative to this write --
        // either it didn't exist, or this write arrived out of order
        // relative to it. Either way the fallback path below needs
        // file_state to reflect the session's content first (a no-op if
        // no session was open): the session's bytes were never
        // checkpointed, so `hydrate_file_state` below would otherwise read
        // stale on-disk content and silently lose them.
        self.materialize_session_into_file_state(ino)?;

        let fresh_session_eligible = {
            let namespace = self.namespace.lock();
            let inode = namespace.inodes.get(&ino).ok_or(PoolError::NoSuchInode(ino))?;
            offset == inode.size && inode.size > self.pool_params.inline_threshold as u64
        };
        if fresh_session_eligible {
            let existing_chunks = self.current_chunks_for_new_session(ino)?;
            self.open_files.lock().insert(
                ino,
                IncrementalWriteState {
                    chunker: FastCdcChunker::new(
                        self.pool_params.chunk_avg_size,
                        self.pool_params.chunk_min_size,
                        self.pool_params.chunk_max_size,
                    ),
                    base_offset: offset,
                    next_expected_offset: offset,
                    chunks: existing_chunks,
                    pending_bytes: Vec::new(),
                },
            );
            return self.write_incremental(ino, buf);
        }

        // Fallback: whole-file rehydrate + rechunk (ported as-is from
        // Phase B, but committing chunks through prep/committer instead of
        // a direct segment-writer call).
        let end = offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= MAX_FILE_SIZE)
            .ok_or(PoolError::TooLarge(offset.saturating_add(buf.len() as u64)))?;
        let end = end as usize;

        self.hydrate_file_state(ino)?;
        {
            let mut file_state = self.file_state.lock();
            let state = file_state.get_mut(&ino).unwrap();
            if state.contents.len() < end {
                state.contents.resize(end, 0);
            }
            state.contents[offset as usize..end].copy_from_slice(buf);
        }
        self.rechunk_and_touch(ino)
    }

    /// The sequential-append fast path: feed `buf` to `ino`'s live
    /// incremental chunker, commit any newly-finalized boundaries through
    /// prep/committer, update the file's size in `Namespace`. Never
    /// touches `file_state` -- `read()` assembles straight from the
    /// session while one is open (see `read`'s doc comment).
    fn write_incremental(&self, ino: u64, buf: &[u8]) -> Result<(), PoolError> {
        let base_offset;
        let mut prepared: Vec<(u64, Vec<u8>)> = Vec::new();
        {
            let mut open_files = self.open_files.lock();
            let state = open_files.get_mut(&ino).unwrap();
            base_offset = state.base_offset;
            state.pending_bytes.extend_from_slice(buf);
            let boundaries = state.chunker.push(buf);
            for b in &boundaries {
                let bytes: Vec<u8> = state.pending_bytes.drain(0..b.len as usize).collect();
                prepared.push((b.offset, bytes));
            }
        }

        let mut new_refs: Vec<ChunkRef> = Vec::with_capacity(prepared.len());
        for (rel_offset, bytes) in &prepared {
            let logical_offset = base_offset + rel_offset;
            let (hash, _loc) = match self.commit_chunk(ino, logical_offset, bytes) {
                Ok(v) => v,
                Err(e) => {
                    // `new_refs` is about to be discarded -- any dedup-hit
                    // pin already taken for an earlier chunk in this batch
                    // (see `PendingDedupPins`'s doc comment) would otherwise
                    // never be released, since it'll never reach
                    // `checkpointed_chunk_hashes` now. No-op for any hash
                    // that was never pinned (every `New`-path chunk here).
                    for r in &new_refs {
                        self.dedup_pins.unpin(r.content_hash);
                    }
                    return Err(e);
                }
            };
            new_refs.push(ChunkRef {
                content_hash: hash,
                logical_offset,
                len: bytes.len() as u32,
            });
        }

        let new_size = {
            let mut open_files = self.open_files.lock();
            let state = open_files.get_mut(&ino).unwrap();
            state.chunks.extend(new_refs);
            state.next_expected_offset += buf.len() as u64;
            state.next_expected_offset
        };

        let (now_secs, now_nanos) = now_unix();
        let mut namespace = self.namespace.lock();
        // Not `.unwrap()`: `write()`'s own existence check happens before
        // `ino_lock` is acquired (see its doc comment), so a concurrent
        // `unlink`/`rmdir` that drops this ino to nlink 0 in that window
        // can reach here with it already gone. A clean error is the right
        // outcome for "wrote to a file that got deleted out from under
        // you" -- this engine doesn't implement POSIX unlink-while-open
        // semantics (content stays readable via existing handles until
        // release), so there's no more graceful answer available yet.
        let inode = namespace
            .inodes
            .get_mut(&ino)
            .ok_or(PoolError::NoSuchInode(ino))?;
        inode.size = new_size;
        inode.mtime = (now_secs, now_nanos);
        inode.ctime = (now_secs, now_nanos);
        namespace.dirty_inodes.insert(ino);
        Ok(())
    }

    /// Ends `ino`'s open incremental-append session (if any): flushes the
    /// chunker's still-buffered tail as one final chunk, commits it, and
    /// returns the session's complete chunk list. Caller (checkpoint's
    /// dirty-file processing, or E.7's fsync fast path) is responsible for
    /// holding `ino`'s lock (via `lock_for_ino`) across this call and
    /// whatever it does with the result, to close the same race a
    /// concurrent `write()` could otherwise open (see `ino_locks`'s doc
    /// comment).
    fn finalize_incremental_session(&self, ino: u64) -> Result<Option<Vec<ChunkRef>>, PoolError> {
        let mut state = match self.open_files.lock().remove(&ino) {
            Some(s) => s,
            None => return Ok(None),
        };
        if let Some(b) = state.chunker.finish() {
            let bytes: Vec<u8> = state.pending_bytes.drain(0..b.len as usize).collect();
            let logical_offset = state.base_offset + b.offset;
            match self.commit_chunk(ino, logical_offset, &bytes) {
                Ok((hash, _loc)) => {
                    state.chunks.push(ChunkRef {
                        content_hash: hash,
                        logical_offset,
                        len: b.len,
                    });
                }
                Err(e) => {
                    // The whole session -- `state` was already removed
                    // from `open_files` above -- is being discarded here,
                    // including any dedup-hit pins already in
                    // `state.chunks` from earlier `write_incremental` calls
                    // in this same session (see `PendingDedupPins`'s doc
                    // comment). No-op for any hash that was never pinned.
                    for r in &state.chunks {
                        self.dedup_pins.unpin(r.content_hash);
                    }
                    return Err(e);
                }
            }
        }
        // `file_state[ino]`, if present, was populated by an *earlier*
        // fallback-path write and only covers content up to that point --
        // stale relative to what this session just added. Deliberately
        // NOT invalidated here (unlike an earlier version of this
        // function): whether that's safe depends on whether the caller's
        // encoded result ends up globally resolvable (checkpoint's
        // put_meta_object, yes) or not (fsync's shard-local delta log, no
        // -- `read_meta_object_bytes` would fail to resolve it via the
        // global index). Each caller handles this explicitly: checkpoint
        // invalidates (safe, its ContentRef hash is globally indexed);
        // fsync repopulates `file_state` directly instead (its ContentRef
        // hash is only resolvable through the shard's own delta log,
        // which ordinary reads don't know how to consult).
        Ok(Some(state.chunks))
    }

    /// Ends `ino`'s open incremental-append session (if any) and captures
    /// its content into `file_state`, so a caller about to fall back to
    /// the whole-file path doesn't silently lose already-committed-but-
    /// not-yet-checkpointed bytes that only the session (not the on-disk
    /// `InodeObject`, not `file_state`) currently knows about. Unlike
    /// `finalize_incremental_session`, this reads chunk payloads back
    /// (`read_chunk_bytes`) since the fallback path needs full byte
    /// content, not just a chunk list -- more expensive, but only run on
    /// the already-slow-path transition, never in the fast path itself.
    fn materialize_session_into_file_state(&self, ino: u64) -> Result<(), PoolError> {
        let Some(state) = self.open_files.lock().remove(&ino) else {
            return Ok(());
        };
        let mut contents = Vec::new();
        for chunk in &state.chunks {
            contents.extend_from_slice(&self.read_chunk_bytes(chunk.content_hash)?);
        }
        contents.extend_from_slice(&state.pending_bytes);
        self.file_state.lock().insert(
            ino,
            FileWorkingState {
                contents,
                chunks: state.chunks,
            },
        );
        Ok(())
    }

    /// `setattr`'s `size` field (ARCHITECTURE.md §9): truncate/zero-extend
    /// a file's content, independent of any `write()`. Always the
    /// whole-file fallback path -- not worth optimizing a truncate, and it
    /// must invalidate any open incremental session regardless (the
    /// session's assumptions about current size no longer hold).
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
        if new_size > MAX_FILE_SIZE {
            return Err(PoolError::TooLarge(new_size));
        }

        let ino_lock = self.lock_for_ino(ino);
        let _guard = ino_lock.lock();
        // Must materialize (not just discard) any open session first: the
        // resize below needs to operate on the file's true current
        // content, which the session -- not yet checkpointed -- is the
        // only thing that knows about.
        self.materialize_session_into_file_state(ino)?;

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
            let mut refs: Vec<ChunkRef> = Vec::with_capacity(boundaries.len());
            for b in boundaries {
                let bytes = &content_snapshot[b.offset as usize..(b.offset + b.len as u64) as usize];
                let (hash, _loc) = match self.commit_chunk(ino, b.offset, bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        // `refs` is about to be discarded -- see the matching
                        // comment in `write_incremental`.
                        for r in &refs {
                            self.dedup_pins.unpin(r.content_hash);
                        }
                        return Err(e);
                    }
                };
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
        // Not `.unwrap()` -- see the matching comment in `write_incremental`.
        let inode = namespace
            .inodes
            .get_mut(&ino)
            .ok_or(PoolError::NoSuchInode(ino))?;
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
        symlink_target: Option<&str>,
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
        let (content, nlink, size) = match kind {
            InodeKind::Directory => (ContentRef::DirEntries(Hash32([0; 32])), 2, 0),
            InodeKind::File => (ContentRef::Inline(Vec::new()), 1, 0),
            InodeKind::Symlink => {
                let target = symlink_target.unwrap_or_default().to_string();
                let size = target.len() as u64;
                (ContentRef::SymlinkTarget(target), 1, size)
            }
        };
        namespace.inodes.insert(
            ino,
            InodeObject {
                kind,
                mode,
                uid: 0,
                gid: 0,
                size,
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

    /// Decrements `ino`'s `nlink`; if it reaches 0, removes it from the
    /// namespace entirely (`inodes`/`parents`/`dirty_inodes` -- `dirs` too,
    /// though only directories are ever present there) so the next
    /// checkpoint's InoMap no longer includes it. From that point on,
    /// ordinary GC (ARCHITECTURE.md §6) reclaims its content once nothing
    /// else references it -- every DAG reference is by content hash, so a
    /// deleted inode's own InodeObject/IndirectHashList records simply stop
    /// being walked, no special-casing needed.
    ///
    /// For files only -- `unlink`/`rename`'s overwrite path use this;
    /// directories are always fully removed directly by their callers
    /// (`rmdir`, and rename's directory-overwrite branch) rather than going
    /// through refcounting, since a directory can only ever have exactly
    /// one referencing DirEntry in this tree (no hardlinked directories).
    ///
    /// Deliberately does *not* purge any `file_state`/`open_files` entry
    /// for `ino` (mirroring `ino_locks`'s own "lazily populated, never
    /// pruned" simplification, see its doc comment) -- an in-flight
    /// reader/writer that already hydrated this ino's working state keeps
    /// working against it exactly as before. This engine doesn't implement
    /// full POSIX unlink-while-open semantics (content stays readable via
    /// existing handles until `release()`); leaving the cache alone is what
    /// makes that partial behavior work at all, rather than failing
    /// in-flight operations immediately.
    fn release_inode_ref(&self, namespace: &mut Namespace, ino: u64) {
        let Some(inode) = namespace.inodes.get_mut(&ino) else {
            return;
        };
        inode.nlink = inode.nlink.saturating_sub(1);
        if inode.nlink > 0 {
            namespace.dirty_inodes.insert(ino);
            return;
        }
        namespace.inodes.remove(&ino);
        namespace.dirs.remove(&ino);
        namespace.parents.remove(&ino);
        namespace.dirty_inodes.remove(&ino);
    }

    /// Fully removes a directory inode -- always unconditional, never
    /// refcounted (see `release_inode_ref`'s doc comment for why). Callers
    /// (`rmdir`, rename's directory-overwrite branch) are responsible for
    /// having already verified it's empty and detached from its parent's
    /// entries.
    fn remove_directory_inode(&self, namespace: &mut Namespace, ino: u64) {
        namespace.inodes.remove(&ino);
        namespace.dirs.remove(&ino);
        namespace.parents.remove(&ino);
        namespace.dirty_inodes.remove(&ino);
    }

    fn unlink(&self, parent_ino: u64, name: &str) -> Result<(), PoolError> {
        let mut namespace = self.namespace.lock();
        let dir = namespace
            .dirs
            .get(&parent_ino)
            .ok_or(PoolError::NotADirectory(parent_ino))?;
        let entry = dir
            .entries
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .ok_or_else(|| PoolError::NotFound(name.to_string()))?;
        if entry.kind == InodeKind::Directory {
            return Err(PoolError::IsADirectory(entry.ino));
        }
        namespace
            .dirs
            .get_mut(&parent_ino)
            .unwrap()
            .entries
            .retain(|e| e.name != name);
        namespace.dirty_inodes.insert(parent_ino);
        self.release_inode_ref(&mut namespace, entry.ino);
        Ok(())
    }

    fn rmdir(&self, parent_ino: u64, name: &str) -> Result<(), PoolError> {
        let mut namespace = self.namespace.lock();
        let dir = namespace
            .dirs
            .get(&parent_ino)
            .ok_or(PoolError::NotADirectory(parent_ino))?;
        let entry = dir
            .entries
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .ok_or_else(|| PoolError::NotFound(name.to_string()))?;
        if entry.kind != InodeKind::Directory {
            return Err(PoolError::NotADirectory(entry.ino));
        }
        let target_empty = namespace
            .dirs
            .get(&entry.ino)
            .ok_or(PoolError::NoSuchInode(entry.ino))?
            .entries
            .is_empty();
        if !target_empty {
            return Err(PoolError::NotEmpty(entry.ino));
        }
        namespace
            .dirs
            .get_mut(&parent_ino)
            .unwrap()
            .entries
            .retain(|e| e.name != name);
        namespace.dirty_inodes.insert(parent_ino);
        self.remove_directory_inode(&mut namespace, entry.ino);
        Ok(())
    }

    /// `link` (hardlink, ARCHITECTURE.md §9): a second `DirEntry` pointing
    /// at the same `ino` -- no new content_hash, no data I/O, just an
    /// `nlink` bump and a metadata rewrite. Directories can't be
    /// hardlinked (POSIX `EPERM`): this tree's `parents`/GC-reachability
    /// model assumes each directory has exactly one referencing DirEntry.
    fn link(&self, ino: u64, new_parent_ino: u64, new_name: &str) -> Result<(), PoolError> {
        let mut namespace = self.namespace.lock();
        let kind = namespace
            .inodes
            .get(&ino)
            .map(|i| i.kind)
            .ok_or(PoolError::NoSuchInode(ino))?;
        if kind == InodeKind::Directory {
            return Err(PoolError::IsADirectory(ino));
        }
        if !namespace.dirs.contains_key(&new_parent_ino) {
            return Err(PoolError::NotADirectory(new_parent_ino));
        }
        if namespace
            .dirs
            .get(&new_parent_ino)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.name == new_name)
        {
            return Err(PoolError::AlreadyExists(new_name.to_string()));
        }

        namespace.inodes.get_mut(&ino).unwrap().nlink += 1;
        let dir = namespace.dirs.get_mut(&new_parent_ino).unwrap();
        dir.entries.push(DirEntry {
            name: new_name.to_string(),
            ino,
            kind,
        });
        dir.entries.sort_by(|a, b| a.name.cmp(&b.name));

        namespace.dirty_inodes.insert(new_parent_ino);
        namespace.dirty_inodes.insert(ino);
        Ok(())
    }

    /// `rename` (ARCHITECTURE.md §9): "metadata-only DAG rewrite up to the
    /// common ancestor directory, no data copy" -- the moved inode's own
    /// content is never touched, only the two `DirectoryObject`s (one, if
    /// same-directory). `no_replace` is FUSE's `RENAME_NOREPLACE` flag;
    /// `RENAME_EXCHANGE` (atomic two-way swap) isn't implemented -- callers
    /// reject it before reaching here (see lchfs-fuse's `rename`).
    fn rename(
        &self,
        parent_ino: u64,
        name: &str,
        new_parent_ino: u64,
        new_name: &str,
        no_replace: bool,
    ) -> Result<(), PoolError> {
        let mut namespace = self.namespace.lock();
        if !namespace.dirs.contains_key(&parent_ino) {
            return Err(PoolError::NotADirectory(parent_ino));
        }
        if !namespace.dirs.contains_key(&new_parent_ino) {
            return Err(PoolError::NotADirectory(new_parent_ino));
        }

        let src_entry = namespace
            .dirs
            .get(&parent_ino)
            .unwrap()
            .entries
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .ok_or_else(|| PoolError::NotFound(name.to_string()))?;

        // Renaming an entry onto its own name is a defined no-op, not an
        // error -- and must be handled before the cycle guard below, which
        // would otherwise (correctly, but unhelpfully) reject "moving" a
        // directory into itself.
        if parent_ino == new_parent_ino && name == new_name {
            return Ok(());
        }

        // A directory can never be moved into its own subtree -- walk from
        // the destination back up to the root looking for the directory
        // being moved. Bounded by inode count as a defensive guard against
        // an ever-somehow-cyclic `parents` map, not expected to matter in
        // practice.
        if src_entry.kind == InodeKind::Directory {
            let mut walk = new_parent_ino;
            let bound = namespace.inodes.len() as u64 + 1;
            for _ in 0..bound {
                if walk == src_entry.ino {
                    return Err(PoolError::InvalidArgument(
                        "cannot move a directory into its own subtree".to_string(),
                    ));
                }
                if walk == ROOT_DIR_INO {
                    break;
                }
                walk = *namespace.parents.get(&walk).unwrap_or(&ROOT_DIR_INO);
            }
        }

        let dst_existing = namespace
            .dirs
            .get(&new_parent_ino)
            .unwrap()
            .entries
            .iter()
            .find(|e| e.name == new_name)
            .cloned();
        if let Some(existing) = &dst_existing {
            if no_replace {
                return Err(PoolError::AlreadyExists(new_name.to_string()));
            }
            match (src_entry.kind, existing.kind) {
                (InodeKind::Directory, InodeKind::Directory) => {
                    let target_empty = namespace
                        .dirs
                        .get(&existing.ino)
                        .map(|d| d.entries.is_empty())
                        .unwrap_or(true);
                    if !target_empty {
                        return Err(PoolError::NotEmpty(existing.ino));
                    }
                }
                // oldpath is a directory, newpath exists and isn't -- POSIX ENOTDIR.
                (InodeKind::Directory, _) => return Err(PoolError::NotADirectory(existing.ino)),
                // oldpath isn't a directory, newpath exists and is -- POSIX EISDIR.
                (_, InodeKind::Directory) => return Err(PoolError::IsADirectory(existing.ino)),
                _ => {}
            }
        }

        namespace
            .dirs
            .get_mut(&parent_ino)
            .unwrap()
            .entries
            .retain(|e| e.name != name);

        if let Some(existing) = &dst_existing {
            namespace
                .dirs
                .get_mut(&new_parent_ino)
                .unwrap()
                .entries
                .retain(|e| e.name != new_name);
            if existing.kind == InodeKind::Directory {
                self.remove_directory_inode(&mut namespace, existing.ino);
            } else {
                self.release_inode_ref(&mut namespace, existing.ino);
            }
        }

        let dir = namespace.dirs.get_mut(&new_parent_ino).unwrap();
        dir.entries.push(DirEntry {
            name: new_name.to_string(),
            ino: src_entry.ino,
            kind: src_entry.kind,
        });
        dir.entries.sort_by(|a, b| a.name.cmp(&b.name));
        namespace.parents.insert(src_entry.ino, new_parent_ino);

        let (now_secs, now_nanos) = now_unix();
        if let Some(inode) = namespace.inodes.get_mut(&src_entry.ino) {
            inode.ctime = (now_secs, now_nanos);
        }

        namespace.dirty_inodes.insert(parent_ino);
        namespace.dirty_inodes.insert(new_parent_ino);
        namespace.dirty_inodes.insert(src_entry.ino);
        Ok(())
    }

    /// Filesystem-wide usage stats for `statfs` (ARCHITECTURE.md §9).
    /// Block-level numbers come straight from the underlying filesystem at
    /// `pool_root` (`nix::sys::statvfs`) -- a pool has no fixed capacity of
    /// its own, it just grows on-disk, so the host filesystem's free space
    /// *is* the meaningful "how much more can I write" answer. Inode counts
    /// come from `Pool` itself: `files` is the live inode count, `ffree` a
    /// generous constant since `next_ino` is a monotonic in-memory counter
    /// with no real ceiling, not a fixed-size table.
    fn statfs(&self) -> Result<PoolStats, PoolError> {
        let vfs = nix::sys::statvfs::statvfs(self.pool_root.as_path())
            .map_err(|e| PoolError::Io(std::io::Error::from(e)))?;
        let files_total = self.namespace.lock().inodes.len() as u64;
        Ok(PoolStats {
            block_size: vfs.block_size() as u32,
            fragment_size: vfs.fragment_size() as u32,
            blocks_total: vfs.blocks(),
            blocks_free: vfs.blocks_free(),
            blocks_available: vfs.blocks_available(),
            files_total,
            files_free: u32::MAX as u64,
            name_max: 255,
        })
    }

    /// The fast per-shard fsync path (ARCHITECTURE.md §3, "Subtree
    /// durability via per-shard delta logs"): O(this shard's dirty data
    /// since its own last local checkpoint), never touching the global
    /// meta stream, `persisted_index`, or any other shard. Only meaningful
    /// for File inodes -- directory-structure changes always go through
    /// the slower global checkpoint path (ARCHITECTURE.md §3's explicit
    /// carve-out), so `fsync` on a directory/symlink just runs one.
    fn fsync(&self, ino: u64) -> Result<(), PoolError> {
        let kind = {
            let namespace = self.namespace.lock();
            namespace.inodes.get(&ino).ok_or(PoolError::NoSuchInode(ino))?.kind
        };
        if kind != InodeKind::File {
            return self.run_checkpoint();
        }

        let shard_id = ingress::shard_for_inode(ino, self.shard_delta_logs.len() as u32);

        // Barrier: this shard's data segment must be durable before the
        // IndirectHashList we're about to write can reference its chunk
        // hashes.
        self.committer_pool.shard(shard_id).fsync_data()?;

        let ino_lock = self.lock_for_ino(ino);
        let _guard = ino_lock.lock();

        let session_chunks = self.finalize_incremental_session(ino)?;

        // Deliberately not read before `ino_lock` was acquired: a
        // concurrent write() on another thread could otherwise grow the
        // file past inline_threshold between that read and here, and
        // deciding the branch below from a stale size would silently
        // discard `session_chunks` (already committed to disk by
        // `finalize_incremental_session` above) in the inline branch. A
        // session's mere existence already proves the file was chunked
        // (write()'s own eligibility gate requires size >
        // inline_threshold to ever start one) -- see run_checkpoint's
        // matching fix for the same bug.
        let is_chunked = session_chunks.is_some() || {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .get(&ino)
                .is_some_and(|i| i.size > self.pool_params.inline_threshold as u64)
        };

        // Both branches below fall back to `file_state` when there's no
        // active session (the common case: fsync called without an
        // in-flight incremental-append session, e.g. right after a fresh
        // `Pool::open` before this ino has been read or written this
        // session). Without hydrating first, a not-yet-populated
        // `file_state` entry silently defaults to *empty* via
        // `unwrap_or_default()` below -- which then gets committed as
        // this file's new content, discarding whatever was actually
        // there. `hydrate_file_state` is a no-op if already populated,
        // so this is always safe to call. Found via property-testing
        // (lchfs-testkit's model-equivalence harness): fsync-ing a small,
        // just-reopened file with no preceding read/write truncated it to
        // empty.
        if session_chunks.is_none() {
            self.hydrate_file_state(ino)?;
        }

        let mut records = Vec::new();
        let content_ref = if !is_chunked {
            let bytes = self
                .file_state
                .lock()
                .get(&ino)
                .map(|s| s.contents.clone())
                .unwrap_or_default();
            ContentRef::Inline(bytes)
        } else {
            let chunks = session_chunks
                .clone()
                .or_else(|| self.file_state.lock().get(&ino).map(|s| s.chunks.clone()))
                .unwrap_or_default();
            let ihl = IndirectHashList { chunks };
            let encoded =
                lchfs_format::encode(&ihl).map_err(|e| PoolError::Format(e.to_string()))?;
            let hash = Hash32::of(&encoded);
            records.push(ShardCommitRecord {
                kind: ExtentKind::IndirectHashList,
                content_hash: hash,
                encoded,
            });
            ContentRef::ChunkList(hash)
        };

        // A fast-path session was active: unlike checkpoint's equivalent
        // step, this content ref's hash is only resolvable through this
        // shard's own delta log (nothing here touches the global meta
        // stream or persisted_index), so `file_state` must be repopulated
        // directly rather than invalidated -- otherwise the next
        // `hydrate_file_state` (an ordinary `read()`, before the next
        // global checkpoint) would try to resolve it via the global index
        // and fail. Chunk payloads themselves are unaffected (committed to
        // the global Data stream by `commit_chunk`, same as always) --
        // only their *listing* (the IndirectHashList) lives in the
        // shard-local stream here, so reading them back is exactly what a
        // fresh `hydrate_file_state` would otherwise do.
        if let Some(chunks) = &session_chunks {
            let mut contents = Vec::new();
            for chunk in chunks {
                contents.extend_from_slice(&self.read_chunk_bytes(chunk.content_hash)?);
            }
            self.file_state.lock().insert(
                ino,
                FileWorkingState {
                    contents,
                    chunks: chunks.clone(),
                },
            );
        }

        let new_object_hash = {
            let mut namespace = self.namespace.lock();
            let inode = namespace.inodes.get_mut(&ino).ok_or(PoolError::NoSuchInode(ino))?;
            inode.content = content_ref;
            let encoded = lchfs_format::encode(inode).map_err(|e| PoolError::Format(e.to_string()))?;
            let hash = Hash32::of(&encoded);
            records.push(ShardCommitRecord {
                kind: ExtentKind::InodeObject,
                content_hash: hash,
                encoded,
            });
            hash
        };

        self.shard_delta_logs[shard_id as usize]
            .lock()
            .commit(ino, new_object_hash, &records)?;

        Ok(())
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
        self.committer_pool.fsync_all()?;

        // Read every shard's current local_epoch *now*, before the InoMap
        // snapshot below -- not after. `Pool::fsync` (E.7) runs fully
        // concurrently with checkpoint (no shared lock between them by
        // design), so a shard's delta log can advance mid-checkpoint. If
        // watermarks were read *after* the InoMap snapshot, a concurrent
        // fsync landing in between could make a watermark claim more than
        // this checkpoint's InoMap actually reflects -- at recovery (E.9)
        // that would make replay wrongly *skip* an entry it still needs,
        // real data loss. Reading watermarks first means the reverse can
        // happen instead (a watermark under-claims what the InoMap
        // actually has), which is always safe: ARCHITECTURE.md §7's
        // replay is idempotent, so redundantly re-applying an
        // already-reflected entry is a no-op, never a correctness issue.
        let shard_watermarks: Vec<u64> = self
            .shard_delta_logs
            .iter()
            .map(|log| log.lock().read_shard_superblock().map(|slot| slot.local_epoch))
            .collect::<Result<_, _>>()?;

        let dirty: Vec<u64> = {
            let mut namespace = self.namespace.lock();
            namespace.dirty_inodes.drain().collect()
        };

        struct DirtyWork {
            ino: u64,
            kind: InodeKind,
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

        // Every chunk hash that ends up in a freshly-written IndirectHashList
        // this pass -- unpinned (see `PendingDedupPins`) once the root that
        // captures them is published, below. Unconditional: a hash that was
        // never actually pinned (an ordinary `New`-path chunk) makes `unpin`
        // a no-op, so there's no need to track dedup-hit origin separately.
        let mut checkpointed_chunk_hashes: Vec<Hash32> = Vec::new();

        // Applied immediately per-file rather than collected into a map to
        // apply later: for File inodes, `ino`'s lock is held from
        // `finalize_incremental_session` through the Namespace write-back
        // below, in the same scope. This closes a real race a two-step
        // "compute everything, write back everything" version would leave
        // open -- a concurrent `write()` starting a *new* incremental
        // session right after `finalize_incremental_session` removes the
        // old one, but before Namespace reflects this checkpoint's result,
        // would otherwise seed itself from a stale ContentRef via
        // `current_chunk_refs` and silently lose the just-finalized
        // chunks once it's eventually finalized in turn.
        for w in &work {
            match w.kind {
                InodeKind::Directory => {
                    let dir = w.dir.clone().unwrap_or_default();
                    let (hash, _loc) = self.put_meta_object(ExtentKind::DirectoryObject, &dir)?;
                    if let Some(inode) = self.namespace.lock().inodes.get_mut(&w.ino) {
                        inode.content = ContentRef::DirEntries(hash);
                    }
                }
                InodeKind::File => {
                    let ino_lock = self.lock_for_ino(w.ino);
                    let _guard = ino_lock.lock();
                    let session_chunks = self.finalize_incremental_session(w.ino)?;

                    // dirty_inodes marking is "at least once", not exactly
                    // once: write_incremental/rechunk_and_touch mark an
                    // ino dirty on *every* call, so a write can re-mark an
                    // ino dirty after this checkpoint's dirty_inodes.drain()
                    // already ran but before this per-file loop actually
                    // reaches it -- e.g. an earlier write already got
                    // captured and correctly encoded by this *same*
                    // checkpoint pass when it processed this ino, but a
                    // *later* write's redundant dirty-mark (from writes
                    // #1..N-1, not this specific run's own progress) can
                    // also make the ino dirty again for the *next*
                    // checkpoint pass with nothing new to actually encode.
                    // If neither source below has data for this ino, that
                    // is exactly what happened: the previous checkpoint
                    // pass already consumed the session (and, since it was
                    // chunked, invalidated file_state) and wrote the
                    // correct ContentRef. Treating a data-less dirty-mark
                    // as "encode nothing" would be a real, observed bug --
                    // it silently overwrote the correct ChunkList with an
                    // empty one. The safe, correct handling is to leave
                    // the existing ContentRef untouched: there is nothing
                    // new to reflect, and the current one is already
                    // right.
                    let has_fresh_data = session_chunks.is_some() || file_state_snapshot.contains_key(&w.ino);
                    if !has_fresh_data {
                        continue;
                    }

                    // A fast-path session was active (now finalized): any
                    // `file_state[ino]` entry is either absent or stale
                    // relative to it. Safe to invalidate here specifically
                    // because checkpoint's `put_meta_object` below
                    // globally registers the resulting ContentRef's hash
                    // (unlike fsync's shard-local delta log), so the next
                    // `hydrate_file_state` will correctly re-derive fresh
                    // content from it.
                    if session_chunks.is_some() {
                        self.file_state.lock().remove(&w.ino);
                    }

                    // `w.size` was snapshotted before this per-file loop
                    // started and can be stale by the time we reach this
                    // specific ino -- concurrent writes on other threads
                    // may have grown the file well past
                    // `inline_threshold` since then. Deciding the branch
                    // from that stale value would be a real bug, not just
                    // an inefficiency: the inline branch below completely
                    // ignores `session_chunks`, so a session that
                    // `finalize_incremental_session` just committed to
                    // disk above would be silently discarded from the
                    // ContentRef, even though its bytes are already
                    // durably written. A session's mere existence already
                    // proves the file was chunked (write()'s own
                    // eligibility gate requires size > inline_threshold to
                    // ever start one), so that alone is authoritative;
                    // only fall back to a size check (re-read fresh, not
                    // the stale snapshot -- a fallback-path write could
                    // have grown it too) when no session existed.
                    let is_chunked = session_chunks.is_some() || {
                        let namespace = self.namespace.lock();
                        namespace
                            .inodes
                            .get(&w.ino)
                            .is_some_and(|i| i.size > self.pool_params.inline_threshold as u64)
                    };

                    let content_ref = if !is_chunked {
                        let bytes = file_state_snapshot
                            .get(&w.ino)
                            .map(|s| s.contents.clone())
                            .unwrap_or_default();
                        ContentRef::Inline(bytes)
                    } else {
                        let chunks = session_chunks
                            .or_else(|| file_state_snapshot.get(&w.ino).map(|s| s.chunks.clone()))
                            .unwrap_or_default();
                        checkpointed_chunk_hashes.extend(chunks.iter().map(|c| c.content_hash));
                        let ihl = IndirectHashList { chunks };
                        let (hash, _loc) =
                            self.put_meta_object(ExtentKind::IndirectHashList, &ihl)?;
                        ContentRef::ChunkList(hash)
                    };
                    if let Some(inode) = self.namespace.lock().inodes.get_mut(&w.ino) {
                        inode.content = content_ref;
                    }
                }
                InodeKind::Symlink => {} // unchanged; content already correct
            }
        }

        // Snapshot every inode (not just dirty ones) for the InoMap. The
        // freshly-derived content refs for dirty inodes were already
        // written back above, per-file, under that file's own ino lock.
        let ino_snapshot: Vec<(u64, InodeObject)> = {
            let namespace = self.namespace.lock();
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

        // Bump `published_generation` *before* releasing any pin below --
        // `CoalesceDaemon::repack_segment`'s final freshness check relies on
        // this specific order (see its doc comment): as long as a repack
        // pass observes `published_generation` unchanged from its own
        // mark-time snapshot, it can conclude no hash was unpinned out from
        // under it either, since unpinning never happens before this store.
        self.published_generation.store(generation, Ordering::Release);

        // Every chunk hash freshly captured by the root just published is
        // now DAG-reachable in its own right -- release its pin (a no-op
        // for hashes that were never pinned to begin with). See
        // `PendingDedupPins`'s doc comment.
        for hash in &checkpointed_chunk_hashes {
            self.dedup_pins.unpin(*hash);
        }

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

pub(crate) fn get_reader<'a>(
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

/// ARCHITECTURE.md §7's owner_shard-filtered rescan (E.9): on the fast
/// mount path, `locations` comes entirely from the durably-checkpointed
/// `INDEX.redb`, which does not reflect any chunk `commit_chunk` wrote
/// after the last full checkpoint (`persisted_index`'s per-write
/// registration is `Durability::None`, not crash-durable -- only
/// `checkpoint()`'s own `Durability::Immediate` commit is). A shard whose
/// delta log has entries newer than its checkpointed watermark can
/// reference exactly such chunks from its replayed IndirectHashLists, so
/// this does a cheap header-only pass over every Data-stream segment
/// (`read_header` first) and only fully scans (`scan_one_segment`) the
/// ones actually owned by `shard_id`.
fn owner_shard_rescan(
    readers: &SegmentReaders,
    shard_id: u32,
    locations: &mut HashMap<Hash32, ExtentLocation>,
) -> Result<(), PoolError> {
    for (&(segment_id, kind), reader) in readers {
        if kind != StreamKind::Data {
            continue;
        }
        if reader.read_header()?.owner_shard != shard_id {
            continue;
        }
        scan_one_segment(reader, segment_id, locations)?;
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
