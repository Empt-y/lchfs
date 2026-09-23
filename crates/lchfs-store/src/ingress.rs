//! Logical-shard ingress rings and the work-stealing committer pool.
//! ARCHITECTURE.md §5 ("Logical shards vs. physical committer threads").
//!
//! Key design point, stated here so it isn't lost during implementation:
//! stealing applies to *which physical thread services which logical
//! shard next*, never to concurrent writers on one segment. A committer
//! claims exclusive access to a logical shard before touching its ring or
//! segment, and releases the claim when it moves on. See ARCHITECTURE.md
//! §5 for why true work-stealing at the segment-append level was
//! considered and rejected.

use crate::gc::SealGenerations;
use crate::segment::SegmentWriter;
use crate::vdevs::VdevSet;
use crossbeam::deque::{Injector, Steal};
use crossbeam::queue::ArrayQueue;
use lchfs_format::{CodecId, ExtentKind, ExtentLocation, ExtentRecordHeader, Hash32, StreamKind};
use parking_lot::{Condvar, Mutex};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

/// One prepared, ready-to-commit chunk handed off from the Ingest
/// Preparation Pool (prep.rs) to a logical shard's ring. Carries
/// everything `SegmentWriter::append` needs so the committer thread does
/// no further chunk-processing work, only I/O.
pub struct IngressOp {
    pub inode_id: u64,
    pub content_hash: Hash32,
    pub codec_id: CodecId,
    pub uncompressed_len: u32,
    /// Already chunked/hashed/dedup-checked/maybe-compressed payload,
    /// zero-copy shared via `Bytes` (ARCHITECTURE.md §5a: this buffer
    /// choice is deliberately kernel-migration-friendly).
    pub payload: bytes::Bytes,
    /// Set when the prep pool sealed the chunk (an encrypted pool): the
    /// record's final header, with `payload` its envelope.
    pub sealed: Option<ExtentRecordHeader>,
    pub logical_offset: u64,
    /// Signaled once this op lands (or fails). `Pool::write` (E.6) blocks
    /// on this per chunk before returning — see the plan's design decision
    /// on why `write()` stays synchronous despite the async handoff.
    pub completion: crossbeam::channel::Sender<io::Result<Appended>>,
}

/// A logical shard's own currently-open Data-stream segment, plus the
/// bookkeeping needed to roll it over autonomously (mirrors
/// `PoolInner::ensure_data_room`'s mem::replace-and-seal pattern from the
/// single-threaded engine, but scoped to one shard's own writer instead of
/// one global one).
/// Borrow a `[PathBuf]` as the `[&Path]` slice `SegmentWriter` takes.
/// What a committer hands back for one record: where it went, and on
/// which devices. The index records the hash under exactly these slots,
/// which after a live attach can be fewer than the pool has.
#[derive(Debug, Clone)]
pub struct Appended {
    pub location: ExtentLocation,
    pub vdevs: Arc<[u16]>,
}

struct ShardDataWriter {
    /// The segment this shard is appending to, created on the first
    /// append and closed by `close_segment` -- so an idle shard owns no
    /// file, and a mount that never writes to a shard leaves nothing on
    /// disk for it.
    writer: Option<SegmentWriter>,
    /// When the segment last took a record; what `seal_if_idle` reads.
    last_append: std::time::Instant,
    /// The slots `writer`'s segment fans out to, shared with every
    /// completion it produces.
    vdev_ids: Arc<[u16]>,
    /// Landed records not yet in the persisted index. Drained under this
    /// shard's lock by `flush_index`; see `Indexer` for when.
    pending_index: Vec<IndexEntry>,
    indexer: Arc<OnceLock<Indexer>>,
    /// The mount's online devices (§15.3). The Data stream carries file
    /// content, so this is the fan-out that actually replicates user data.
    /// Consulted at every rollover, so a device attached live is written
    /// to from this shard's next segment on.
    vdevs: Arc<VdevSet>,
    shard_id: u32,
    segment_cap_bytes: u64,
    next_segment_id: Arc<AtomicU64>,
    /// Stamped with the current checkpoint generation every time this
    /// shard seals a segment, so the sweep can tell a segment whose
    /// records no published root has captured yet from one it has --
    /// see `SealGenerations`.
    seal_generations: Arc<SealGenerations>,
}

impl ShardDataWriter {
    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        kind: ExtentKind,
        content_hash: Hash32,
        codec_id: CodecId,
        uncompressed_len: u32,
        payload: &[u8],
        sealed: Option<&ExtentRecordHeader>,
    ) -> io::Result<Appended> {
        if self
            .writer
            .as_ref()
            .is_some_and(|w| w.current_size() + payload.len() as u64 > self.segment_cap_bytes)
        {
            self.close_segment()?;
        }
        let writer = self.open_segment()?;
        let result = match sealed {
            Some(header) => writer.append_prebuilt(header, payload),
            None => writer.append(kind, content_hash, codec_id, uncompressed_len, payload, Vec::new()),
        };
        self.last_append = std::time::Instant::now();
        self.report_faults();
        // A segment that has lost every replica is finished: the next
        // append opens a fresh one on whatever is online by then, rather
        // than failing against this one forever.
        if result.is_err() && self.writer.as_ref().is_some_and(|w| w.vdev_ids().is_empty()) {
            self.writer = None;
        }
        Ok(Appended {
            location: result?,
            vdevs: Arc::clone(&self.vdev_ids),
        })
    }

    /// Tells the device set about replicas this segment has dropped, and
    /// refreshes the slot list handed out with each completion so the
    /// index is told only the devices that still take this segment.
    fn report_faults(&mut self) {
        let Some(writer) = self.writer.as_mut() else { return };
        for id in writer.take_faults() {
            self.vdevs.fault(id);
        }
        if self.vdev_ids.as_ref() != writer.vdev_ids() {
            self.vdev_ids = writer.vdev_ids().into();
        }
    }

    /// The current segment, created on the online set if there is none.
    fn open_segment(&mut self) -> io::Result<&mut SegmentWriter> {
        if self.writer.is_none() {
            let new_id = self.next_segment_id.fetch_add(1, Ordering::Relaxed);
            let online = self.vdevs.online();
            let mut writer = SegmentWriter::create_on(&online, new_id, StreamKind::Data, self.shard_id)?;
            for id in writer.take_faults() {
                self.vdevs.fault(id);
            }
            self.vdev_ids = writer.vdev_ids().into();
            self.writer = Some(writer);
        }
        Ok(self.writer.as_mut().expect("just created"))
    }

    /// Seals the current segment if it has taken no record for `idle`.
    /// What the checkpoint calls so a segment that stopped growing short
    /// of the cap still becomes a sealed, sweepable, stripeable segment
    /// rather than staying open for the life of the mount.
    fn seal_if_idle(&mut self, idle: std::time::Duration) -> io::Result<bool> {
        if self.writer.is_none() || self.last_append.elapsed() < idle {
            return Ok(false);
        }
        self.close_segment()?;
        Ok(true)
    }

    /// Hands every pending record to the index in one transaction. Runs
    /// under the shard lock, so nothing appended to this shard can be
    /// unindexed once it returns.
    fn flush_index(&mut self) -> io::Result<()> {
        if self.pending_index.is_empty() {
            return Ok(());
        }
        let Some(index) = self.indexer.get() else {
            self.pending_index.clear();
            return Ok(());
        };
        let result = (index.persist)(&self.pending_index);
        self.pending_index.clear();
        result
    }

    /// Seals the current segment, if any; the next append opens a fresh
    /// one on the online set as it stands then. What every barrier that
    /// needs "no segment in flight includes device X" calls.
    fn close_segment(&mut self) -> io::Result<()> {
        // Everything on the old segment is indexed before it is left
        // behind: the invariant a live attach's barrier rests on.
        self.flush_index()?;
        let Some(old) = self.writer.take() else { return Ok(()) };
        // Before the seal, not after: the sweep looks for sealed segments
        // on disk, so the segment must already be tracked by the time its
        // footer lands. We hold this shard's lock, so its last append is
        // behind us. See `SealGenerations::stamp`.
        self.seal_generations.stamp(old.segment_id());
        // The seal is the last chance to learn a replica failed on it.
        let faults = old.seal()?;
        for id in faults {
            self.vdevs.fault(id);
        }
        Ok(())
    }

    fn fsync(&mut self) -> io::Result<()> {
        if let Some(writer) = self.writer.as_mut() {
            let result = writer.fsync();
            self.report_faults();
            result?;
        }
        self.flush_index()
    }
}

/// M logical shards (ARCHITECTURE.md §5: M ~= 256-1024, configurable,
/// deliberately >> core count). Ordering domain for one inode's writes —
/// `hash(inode_id) % M` always routes to the same `LogicalShard`.
pub struct LogicalShard {
    pub id: u32,
    pub ring: ArrayQueue<IngressOp>,
    /// Lightweight atomic "claimed" flag a committer thread holds while
    /// draining this shard. Uncontended in the common case since M >> K
    /// makes collisions rare (ARCHITECTURE.md §5).
    claimed: AtomicBool,
    /// True while this shard's id has an outstanding entry in the shared
    /// work-stealing `Injector` (or is about to). Guards against enqueuing
    /// the same shard id twice; see `CommitterPool::push`/the committer
    /// loop for the handshake between this flag and `claimed`.
    pending: AtomicBool,
    data: Mutex<ShardDataWriter>,
}

impl LogicalShard {
    fn new(
        id: u32,
        ring_capacity: usize,
        vdevs: Arc<VdevSet>,
        segment_cap_bytes: u64,
        next_segment_id: Arc<AtomicU64>,
        seal_generations: Arc<SealGenerations>,
        indexer: Arc<OnceLock<Indexer>>,
    ) -> io::Result<Self> {
        Ok(Self {
            id,
            ring: ArrayQueue::new(ring_capacity),
            claimed: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            data: Mutex::new(ShardDataWriter {
                vdev_ids: vdevs.online().iter().map(|v| v.id).collect::<Vec<u16>>().into(),
                writer: None,
                last_append: std::time::Instant::now(),
                pending_index: Vec::with_capacity(INDEX_BATCH),
                indexer,
                vdevs,
                shard_id: id,
                segment_cap_bytes,
                next_segment_id,
                seal_generations,
            }),
        })
    }

    /// Try to claim exclusive access; `false` means another committer is
    /// already draining this shard.
    fn try_claim(&self) -> bool {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn release(&self) {
        self.claimed.store(false, Ordering::Release);
    }

    /// fsync this shard's currently-open data segment without sealing it —
    /// used by the multi-shard checkpoint (E.8). Briefly contends with an
    /// active committer draining this shard, same as an ordinary
    /// `fsync()` legitimately blocking on in-flight writes elsewhere.
    pub fn fsync_data(&self) -> io::Result<()> {
        self.data.lock().fsync()
    }
}

/// Routes an inode to its logical shard. ARCHITECTURE.md §3: sharding key
/// is inode_id, not physical core — see that section for why a literal
/// per-core scheme would be incorrect.
pub fn shard_for_inode(inode_id: u64, shard_count: u32) -> u32 {
    // A cheap integer mix (splitmix64's finalizer) rather than the raw
    // modulus, so sequential inode allocation (the overwhelmingly common
    // case — inodes are handed out by an incrementing counter) doesn't
    // cluster on low shard ids whenever shard_count doesn't evenly divide
    // typical allocation runs.
    let mut x = inode_id;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x % shard_count as u64) as u32
}

/// K physical committer threads (K ~= num_cpus) draining a work-stealing
/// deque of "logical shards with pending work". ARCHITECTURE.md §5.
/// One landed record for the index: the hash, where it went, the slots it
/// went to.
pub type IndexEntry = (Hash32, ExtentLocation, Arc<[u16]>);

/// Records a batch of landed records in the pool's persisted index.
/// Called by a committer *under its shard's lock* -- when the shard's
/// batch fills, when its writer rolls, when it fsyncs, or when the pool
/// asks every shard to flush -- so that "this shard's writer has been
/// rolled" still implies "every record on its previous segment is
/// indexed", which is what lets a live attach use the writers' own locks
/// as its barrier (§5). The location *cache* is updated per record, at
/// once, since that is what reads consult; only the redb transaction is
/// batched.
/// The persisting half of an `Indexer`: one call per batch.
pub type PersistBatch = Arc<dyn Fn(&[IndexEntry]) -> io::Result<()> + Send + Sync>;

pub struct Indexer {
    /// Updated per record, at once: reads, dedup and file hydration
    /// consult this, and a record must be findable the moment its write
    /// is acknowledged.
    pub cache: Arc<lchfs_index::ChunkLocationCache>,
    /// The persisted index, fed a batch at a time.
    pub persist: PersistBatch,
}

/// Records a shard buffers before one index transaction takes them all.
/// Large enough that the transaction cost stops mattering, small enough
/// that a failover read of a just-written record (which flushes first)
/// does not wait on much.
pub const INDEX_BATCH: usize = 1024;

pub struct CommitterPool {
    shards: Vec<Arc<LogicalShard>>,
    /// Set once, after the pool's index exists; lock-free to read after
    /// that. `None` (never set) for pools driven directly by tests.
    indexer: Arc<OnceLock<Indexer>>,
    injector: Arc<Injector<u32>>,
    wake: Arc<(Mutex<()>, Condvar)>,
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl CommitterPool {
    /// `new_on` with a bare device set built from `vdev_roots`, slot by
    /// position -- for tests and tooling that drive the pool directly.
    pub fn new(
        vdev_roots: &[PathBuf],
        shard_count: u32,
        worker_count: usize,
        ring_capacity: usize,
        data_segment_cap_bytes: u64,
        next_segment_id: Arc<AtomicU64>,
        seal_generations: Arc<SealGenerations>,
    ) -> io::Result<Self> {
        Self::new_on(
            Arc::new(VdevSet::from_roots(vdev_roots)),
            shard_count,
            worker_count,
            ring_capacity,
            data_segment_cap_bytes,
            next_segment_id,
            seal_generations,
        )
    }

    pub fn new_on(
        vdevs: Arc<VdevSet>,
        shard_count: u32,
        worker_count: usize,
        ring_capacity: usize,
        data_segment_cap_bytes: u64,
        next_segment_id: Arc<AtomicU64>,
        seal_generations: Arc<SealGenerations>,
    ) -> io::Result<Self> {
        let indexer: Arc<OnceLock<Indexer>> = Arc::new(OnceLock::new());
        let mut shards = Vec::with_capacity(shard_count as usize);
        for id in 0..shard_count {
            shards.push(Arc::new(LogicalShard::new(
                id,
                ring_capacity,
                Arc::clone(&vdevs),
                data_segment_cap_bytes,
                Arc::clone(&next_segment_id),
                Arc::clone(&seal_generations),
                Arc::clone(&indexer),
            )?));
        }

        let injector = Arc::new(Injector::new());
        let wake = Arc::new((Mutex::new(()), Condvar::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let workers = (0..worker_count.max(1))
            .map(|worker_idx| {
                let shards = shards.clone();
                let injector = Arc::clone(&injector);
                let wake = Arc::clone(&wake);
                let shutdown = Arc::clone(&shutdown);
                std::thread::Builder::new()
                    .name(format!("lchfs-committer-{worker_idx}"))
                    .spawn(move || committer_loop(shards, injector, wake, shutdown))
                    .expect("spawn committer thread")
            })
            .collect();

        Ok(Self {
            shards,
            indexer,
            injector,
            wake,
            shutdown,
            workers,
        })
    }

    /// Push a prepared op onto its inode's logical shard. Blocks the
    /// caller if the ring is full (ARCHITECTURE.md §5: "block the
    /// producer... never drop" — a dropped write is data loss). A yield-
    /// backoff loop rather than a condvar wait: per §5 this path should be
    /// rare in practice (ingestion is already decoupled from FUSE threads,
    /// load spread across M>>K shards) — a real wake-on-drain condvar for
    /// this specific path is a documented future refinement, not required
    /// for correctness.
    /// Rolls every shard's data writer to a fresh segment, each under its
    /// own lock, so that once this returns every record any committer
    /// appends fans out to the device set as it stands *now*. The barrier
    /// a live attach needs: an append in flight when the set grew finishes
    /// on the old segment and is recorded under the old slots (which is
    /// true), and nothing appended after this can miss the new device.
    /// Installs the index recorder every committer runs under its shard
    /// lock. Once only; a second call is ignored.
    pub fn set_indexer(&self, indexer: Indexer) {
        let _ = self.indexer.set(indexer);
    }

    /// Drains every shard's index batch, each under its own lock. What
    /// the pool calls before anything that reads the persisted index and
    /// expects it complete: a checkpoint, a failover read, a scrub.
    pub fn flush_index(&self) -> io::Result<()> {
        for shard in &self.shards {
            shard.data.lock().flush_index()?;
        }
        Ok(())
    }

    pub fn roll_all_writers(&self) -> io::Result<()> {
        for shard in &self.shards {
            shard.data.lock().close_segment()?;
        }
        Ok(())
    }

    /// Seals every shard's segment that has taken nothing for `idle`;
    /// returns how many were sealed. Called from the checkpoint.
    pub fn seal_idle_writers(&self, idle: std::time::Duration) -> io::Result<usize> {
        let mut sealed = 0;
        for shard in &self.shards {
            if shard.data.lock().seal_if_idle(idle)? {
                sealed += 1;
            }
        }
        Ok(sealed)
    }

    pub fn push(&self, op: IngressOp) {
        let shard_id = shard_for_inode(op.inode_id, self.shards.len() as u32);
        let shard = &self.shards[shard_id as usize];

        let mut op = op;
        loop {
            match shard.ring.push(op) {
                Ok(()) => break,
                Err(returned) => {
                    op = returned;
                    std::thread::yield_now();
                }
            }
        }

        self.mark_pending(shard_id);
    }

    fn mark_pending(&self, shard_id: u32) {
        let shard = &self.shards[shard_id as usize];
        if shard
            .pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.injector.push(shard_id);
            let (lock, cvar) = &*self.wake;
            let _guard = lock.lock();
            cvar.notify_one();
        }
    }

    pub fn shard(&self, id: u32) -> &Arc<LogicalShard> {
        &self.shards[id as usize]
    }

    pub fn shard_count(&self) -> u32 {
        self.shards.len() as u32
    }

    /// fsync every currently-open shard data segment (E.8's multi-shard
    /// checkpoint barrier — replaces the single-writer global fsync the
    /// Phase B engine used).
    pub fn fsync_all(&self) -> io::Result<()> {
        for shard in &self.shards {
            shard.fsync_data()?;
        }
        Ok(())
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let (lock, cvar) = &*self.wake;
        {
            let _guard = lock.lock();
            cvar.notify_all();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
        // A clean shutdown leaves no segment open: what stays Open on
        // disk is, by construction, a crash's, and mount seals it.
        for shard in &self.shards {
            if let Err(e) = shard.data.lock().close_segment() {
                tracing::error!("shard {}: sealing its segment at shutdown failed ({e})", shard.id);
            }
        }
    }
}

impl Drop for CommitterPool {
    fn drop(&mut self) {
        if !self.workers.is_empty() {
            self.shutdown();
        }
    }
}

fn pop_pending(injector: &Injector<u32>) -> Option<u32> {
    loop {
        match injector.steal() {
            Steal::Success(id) => return Some(id),
            Steal::Empty => return None,
            Steal::Retry => continue,
        }
    }
}

fn committer_loop(
    shards: Vec<Arc<LogicalShard>>,
    injector: Arc<Injector<u32>>,
    wake: Arc<(Mutex<()>, Condvar)>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match pop_pending(&injector) {
            Some(shard_id) => {
                let shard = &shards[shard_id as usize];
                // This id is now out of the injector; a push arriving from
                // here on must re-enqueue it (see `mark_pending`).
                shard.pending.store(false, Ordering::Release);

                if !shard.try_claim() {
                    // Vanishingly rare (see module doc): another worker
                    // still holds the claim from a prior injector entry
                    // for this shard. Put it back so someone retries.
                    injector.push(shard_id);
                    std::thread::yield_now();
                    continue;
                }

                let mut data = shard.data.lock();
                while let Some(op) = shard.ring.pop() {
                    let result = data
                        .append(
                            ExtentKind::RawChunk,
                            op.content_hash,
                            op.codec_id,
                            op.uncompressed_len,
                            &op.payload,
                            op.sealed.as_ref(),
                        )
                        .and_then(|appended| {
                            if let Some(index) = data.indexer.get() {
                                index.cache.put(op.content_hash, appended.location, appended.vdevs[0]);
                            }
                            data.pending_index.push((
                                op.content_hash,
                                appended.location,
                                Arc::clone(&appended.vdevs),
                            ));
                            if data.pending_index.len() >= INDEX_BATCH {
                                data.flush_index()?;
                            }
                            Ok(appended)
                        });
                    let _ = op.completion.send(result);
                }
                drop(data);
                shard.release();
            }
            None => {
                let (lock, cvar) = &*wake;
                let mut guard = lock.lock();
                cvar.wait_for(&mut guard, Duration::from_millis(200));
            }
        }
    }
}
