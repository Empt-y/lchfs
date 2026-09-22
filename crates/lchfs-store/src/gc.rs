//! Mark-and-sweep garbage collection. ARCHITECTURE.md §6.
//!
//! Live roots = `{current superblock root_hash} u {every SnapshotTable
//! entry's root_hash} u {snapshot_table_hash}`. `INDEX.redb` is explicitly
//! excluded from GC accounting (it's a cache with its own simpler
//! lifecycle, checkpointed independently -- see lchfs-index).
//!
//! `GcEngine` is a library component, not its own background thread --
//! its `mark`/`sweep_candidates` are the analysis step *inside* the
//! Coalescing Daemon's pass (coalesce.rs owns one), not a fourth
//! independent daemon. Re-reading ARCHITECTURE.md §6 closely: "Sweep:
//! below a liveness threshold... *the coalescing daemon* copies forward
//! only live extents" -- mark-and-sweep feeds directly into coalescing,
//! it isn't a parallel concern.

use crate::crypto::{self, CryptoHandle};
use crate::segment::{SegmentReader, segment_ids_on};
use crate::vdevs::VdevSet;
use crate::{SegmentReaders, StreamKind, Vdev, dag_walk};
use crate::dag_walk::LiveSet;
use std::path::Path;
use lchfs_format::{Hash32, SegmentState};
use lchfs_index::{ChunkLocationCache, PendingDedupPins};
use parking_lot::Mutex;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Below this fraction of a sealed segment's bytes still being live, it's
/// a sweep candidate (ARCHITECTURE.md §6, "default 50%").
const DEFAULT_LIVENESS_THRESHOLD: f64 = 0.5;
/// Never sweep the most-recently-sealed segments, even if they qualify by
/// liveness fraction alone -- "defense in depth" grace period
/// (ARCHITECTURE.md §6), sized in segment count (a pure in-memory recency
/// proxy: segment_id is monotonically allocated, so "exclude the highest
/// N sealed ids" is a correct, zero-persistence stand-in for "current/
/// immediately-prior epoch").
const GRACE_WINDOW_SEGMENTS: usize = 2;
/// How many checkpoints must have completed since a Data segment sealed
/// before coalesce may reclaim it. This is the *correctness* half of the
/// grace period, where `GRACE_WINDOW_SEGMENTS` above is only a recency
/// heuristic.
///
/// Two, not one: a segment sealing while `published_generation == G` may
/// or may not have its records captured by the checkpoint that publishes
/// `G+1` -- that checkpoint's drain of dirty inodes can have run before
/// the seal. The checkpoint publishing `G+2` provably *starts* after
/// `G+1` was published, which was after the seal, so its drain runs after
/// every append the segment ever took, and the published root it writes
/// references all of them.
const CHECKPOINT_GRACE_GENERATIONS: u64 = 2;

/// Above this many tracked segments, `stamp` drops the entries that have
/// already aged past the gate. Purely a memory bound: an absent entry and
/// an aged-out one mean the same thing (eligible).
const SEAL_GENERATIONS_PRUNE_AT: usize = 4096;

/// When each Data segment sealed, counted in published checkpoint
/// generations -- the hard invariant behind coalesce eligibility:
/// *coalesce must never reclaim a segment holding records newer than the
/// last completed checkpoint.*
///
/// The bug this exists to prevent: `mark` counts a chunk live only if it
/// is reachable from a published root or currently dedup-pinned. A fresh
/// (first-occurrence) write's chunk is committed, and can be cap-sealed
/// into a segment, *before* the checkpoint that references it runs -- in
/// that window it is in neither set, and nothing but the count-based
/// `GRACE_WINDOW_SEGMENTS` stood between it and the sweep. Segments seal
/// faster than checkpoints run under any sustained write load (two
/// segments per interval is ~25 MB/s at the default cap), so that window
/// aged out and coalesce reclaimed live data: on a replicated pool
/// silently lost redundancy, on a single-vdev pool real data loss (a
/// PostgreSQL soak on an lchfs mount lost 28 chunks and crash-looped on
/// EIO).
///
/// A segment with *no* entry is eligible: it sealed before this mount, so
/// it survived into the recovered root's world and is checkpointed by
/// definition. Only segments sealed during this mount carry a generation,
/// which is why nothing has to be persisted for this to be safe across a
/// crash.
pub struct SealGenerations {
    published_generation: Arc<AtomicU64>,
    sealed: Mutex<HashMap<u64, u64>>,
}

impl SealGenerations {
    pub fn new(published_generation: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            published_generation,
            sealed: Mutex::new(HashMap::new()),
        })
    }

    /// Records that `segment_id` is sealing now.
    ///
    /// Call this *before* the seal, not after: the sweep finds candidates
    /// by reading segment headers off disk, so a stamp written after the
    /// footer lands leaves a window in which the segment looks sealed and
    /// untracked -- exactly the "no entry means eligible" default, applied
    /// to the one segment it must not be applied to. Every caller stamps
    /// while it still holds whatever lock keeps appends out (the shard
    /// lock, the heal-writer map, its own fresh writer), so the generation
    /// read here is one that was current at or after the segment's last
    /// append, which is what the `+2` argument above rests on.
    ///
    /// Once per segment seal -- a rollover, not a record -- so this never
    /// touches the write path (ARCHITECTURE.md §5: no global lock there).
    pub fn stamp(&self, segment_id: u64) {
        let generation = self.published_generation.load(Ordering::Acquire);
        let mut sealed = self.sealed.lock();
        sealed.insert(segment_id, generation);
        if sealed.len() >= SEAL_GENERATIONS_PRUNE_AT {
            let published = self.published_generation.load(Ordering::Acquire);
            sealed.retain(|_, &mut sealed_at| published < sealed_at + CHECKPOINT_GRACE_GENERATIONS);
        }
    }

    /// Whether coalesce may reclaim `segment_id` yet. Forgets an entry
    /// that has aged past the gate: `published_generation` only ever
    /// rises, so a segment that is eligible once is eligible forever, and
    /// an absent entry already reads as eligible.
    pub fn may_reclaim(&self, segment_id: u64) -> bool {
        let mut sealed = self.sealed.lock();
        let Some(&generation) = sealed.get(&segment_id) else {
            return true;
        };
        let published = self.published_generation.load(Ordering::Acquire);
        if published >= generation + CHECKPOINT_GRACE_GENERATIONS {
            sealed.remove(&segment_id);
            return true;
        }
        false
    }
}

pub struct GcEngine {
    /// The pool's device set; mark reads from whichever device is the
    /// primary when the pass starts.
    vdevs: Arc<VdevSet>,
    locations: Arc<ChunkLocationCache>,
    pins: Arc<PendingDedupPins>,
    readers: SegmentReaders,
    liveness_threshold: f64,
    /// The seal-generation gate (see `SealGenerations`). `None` for an
    /// engine driven directly by a test or an offline tool, where no
    /// writer is running and every segment on disk is therefore already
    /// checkpointed; a mounted pool always installs one.
    seal_generations: Option<Arc<SealGenerations>>,
    /// How to open sealed records during the mark walk. Plaintext for a
    /// pool with no keys; installed once via `set_crypto`, same as
    /// `set_seal_generations`.
    crypto: CryptoHandle,
}

impl GcEngine {
    /// The dedup/resolution cache this engine resolves hashes through --
    /// exposed so `CoalesceDaemon` (which owns a `GcEngine`) can update it
    /// after physically relocating a chunk during a repack, without
    /// needing its own separate `Arc` clone of the same cache.
    pub fn locations(&self) -> &ChunkLocationCache {
        &self.locations
    }

    /// Exposed so `CoalesceDaemon` can re-consult the *live* pin set
    /// itself, right before deleting an old segment -- see
    /// `PendingDedupPins`'s doc comment and `CoalesceDaemon::repack_segment`.
    pub fn pins(&self) -> &PendingDedupPins {
        &self.pins
    }

    pub fn liveness_threshold(&self) -> f64 {
        self.liveness_threshold
    }

    /// The slot mark reads from.
    pub fn primary_id(&self) -> u16 {
        self.vdevs.primary()
    }

    fn primary(&self) -> Vdev {
        let id = self.vdevs.primary();
        Vdev::new(id, self.vdevs.root_of(id).unwrap_or_default())
    }

    pub fn new(pool_root: PathBuf, locations: Arc<ChunkLocationCache>, pins: Arc<PendingDedupPins>) -> Self {
        Self::new_on(Arc::new(VdevSet::from_roots(&[pool_root])), locations, pins)
    }

    /// `new` on a live device set.
    pub fn new_on(vdevs: Arc<VdevSet>, locations: Arc<ChunkLocationCache>, pins: Arc<PendingDedupPins>) -> Self {
        Self {
            vdevs,
            locations,
            pins,
            readers: HashMap::new(),
            liveness_threshold: DEFAULT_LIVENESS_THRESHOLD,
            seal_generations: None,
            crypto: crypto::plaintext_handle(),
        }
    }

    /// Installs the pool's record crypto.
    pub fn set_crypto(&mut self, crypto: CryptoHandle) {
        self.crypto = crypto;
    }

    /// Installs the seal-generation gate. A mounted pool does this at
    /// construction, before any writer can roll a segment.
    pub fn set_seal_generations(&mut self, seal_generations: Arc<SealGenerations>) {
        self.seal_generations = Some(seal_generations);
    }

    /// The gate, for the `CoalesceDaemon` that owns this engine: it stamps
    /// the segments its own repacks seal, and gates the striped segments
    /// it repacks, through the same map.
    pub fn seal_generations(&self) -> Option<&Arc<SealGenerations>> {
        self.seal_generations.as_ref()
    }

    /// Whether the sweep may reclaim `segment_id` yet -- `true` when no
    /// gate is installed (see the field's comment).
    pub fn may_reclaim(&self, segment_id: u64) -> bool {
        self.seal_generations
            .as_ref()
            .is_none_or(|gens| gens.may_reclaim(segment_id))
    }

    /// Walk RootObject -> InoMap -> per-ino InodeObject -> DirectoryObject
    /// entries / IndirectHashList -> chunk hashes, from every live root.
    /// Runs concurrently with live traffic by snapshotting the root
    /// pointer at walk-start -- no lock needed, since the DAG is immutable
    /// (ARCHITECTURE.md §6).
    ///
    /// On any unresolvable reference (a hash reachable from a live root
    /// that isn't in the index) this returns an *empty* map rather than a
    /// partial one, and logs the failure. A partial live-set is
    /// dangerous, not just incomplete: `sweep_candidates` would read
    /// "nothing marked this segment live" as "safe to reclaim," when the
    /// truth is just "this pass couldn't finish." Skipping the whole pass
    /// (retried on the next tick) is the safe failure mode; a real
    /// resolution failure here means either genuine corruption or a bug,
    /// neither of which idle-cycle maintenance should paper over by
    /// guessing.
    pub fn mark(&mut self, live_roots: &[Hash32]) -> LiveSet {
        let mut live = LiveSet::default();
        let primary = self.primary();
        let crypto_guard = self.crypto.load();
        let ctx = dag_walk::WalkCtx {
            primary: &primary,
            vdevs: &self.vdevs,
            crypto: &crypto_guard,
        };
        for &root in live_roots {
            if let Err(e) = dag_walk::walk_reachable(
                root,
                &ctx,
                &self.locations,
                &mut self.readers,
                &mut live,
            ) {
                tracing::error!("GC mark pass aborted: failed to walk root {root:?}: {e}");
                return LiveSet::default();
            }
        }

        // Union in every currently-pinned hash's location (see
        // `PendingDedupPins`'s doc comment): a dedup-hit write can depend
        // on a location before its own reference to it is DAG-reachable
        // from any live root. This is a first-line-of-defense snapshot,
        // not the sole guarantee -- `CoalesceDaemon::repack_segment` also
        // re-consults the live pin set directly (bypassing this snapshot
        // entirely) right before deleting a segment, to cover both pins
        // taken after this snapshot *and* the case immediately below.
        //
        // Deliberately fails open here, unlike a DAG-walk resolution
        // failure above: `pin()` is only ever called right after a
        // successful `dedup_index.get()` hit, and locations are never
        // removed from the index, so this should never actually miss --
        // but if it somehow did, skipping it doesn't create a false "safe
        // to reclaim" signal the way an incomplete DAG walk would (that
        // failure mode is what justifies aborting the whole pass above).
        // It just forgoes this one pre-marking optimization for that hash;
        // `repack_segment`'s own per-record recheck, keyed directly off
        // the hash it's about to consider dropping rather than through
        // this snapshot's resolution, still protects it independently.
        for hash in self.pins.snapshot() {
            match self.locations.get(hash) {
                Some(loc) => live.mark(hash, loc),
                None => tracing::warn!("GC mark: pinned hash {hash:?} not found in index, skipping"),
            }
        }

        live
    }

    /// Compute, per segment, the live-byte fraction from the mark-phase
    /// bitmaps. Segments below the liveness threshold are handed to the
    /// Coalescing Daemon (coalesce.rs) for physical repacking -- GC itself
    /// never rewrites DAG nodes, only decides what's reclaimable. Scoped
    /// to the Data stream: that's where bulk chunk storage (and thus the
    /// actual space to reclaim) lives; Meta-stream segments are far
    /// smaller and churn differently, not addressed by this pass.
    pub fn sweep_candidates(&self, live_sets: &HashMap<u64, RoaringBitmap>) -> Vec<u64> {
        self.sweep_candidates_on(&self.primary().root, live_sets)
    }

    /// `sweep_candidates` for an arbitrary vdev root, given that device's
    /// own live bitmaps (`LiveSet::resolve_on`). Sweep is per-vdev; only
    /// mark is pool-wide (ARCHITECTURE.md §15.7).
    /// Sealed mirrored data segments under `vdev_root`, ascending by id,
    /// with the last `GRACE_WINDOW_SEGMENTS + extra_age` left out -- the
    /// ones old enough for the coalesce or stripe passes to touch.
    pub fn aged_sealed_segments(vdev_root: &Path, extra_age: usize) -> Vec<u64> {
        let dir = vdev_root.join("segments").join("data");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut ids: Vec<u64> = entries
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("aseg"))
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        ids.sort_unstable();
        let sealed: Vec<u64> = ids
            .into_iter()
            .filter(|&id| {
                SegmentReader::open(vdev_root, id, StreamKind::Data)
                    .ok()
                    .and_then(|r| r.read_header().ok())
                    .map(|h| h.state == SegmentState::Sealed)
                    .unwrap_or(false)
            })
            .collect();
        let cutoff = sealed.len().saturating_sub(GRACE_WINDOW_SEGMENTS + extra_age);
        sealed[..cutoff].to_vec()
    }

    pub fn sweep_candidates_on(
        &self,
        vdev_root: &Path,
        live_sets: &HashMap<u64, RoaringBitmap>,
    ) -> Vec<u64> {
        // Segment files of this stream only: a shard file `<id>.ec<i>`
        // shares the stem and belongs to a stripe.
        let segment_ids: Vec<u64> = segment_ids_on(vdev_root, StreamKind::Data);

        // Only ever consider *sealed* segments -- an Open segment is
        // still being actively written to by its shard's committer, never
        // a repack target.
        let sealed_ids: Vec<u64> = segment_ids
            .into_iter()
            .filter(|&id| {
                SegmentReader::open(vdev_root, id, StreamKind::Data)
                    .ok()
                    .and_then(|r| r.read_header().ok())
                    .map(|h| h.state != SegmentState::Open)
                    .unwrap_or(false)
            })
            .collect();

        let grace_cutoff = sealed_ids.len().saturating_sub(GRACE_WINDOW_SEGMENTS);
        let sealed_ids = &sealed_ids;

        sealed_ids[..grace_cutoff]
            .iter()
            .copied()
            // The hard gate: a segment sealed since the last checkpoint
            // holds records no published root references yet, and mark
            // cannot tell those from dead ones. See `SealGenerations`.
            .filter(|&id| self.may_reclaim(id))
            .filter(|&id| {
                let Ok(meta) = std::fs::metadata(crate::segment::segment_path(
                    vdev_root,
                    id,
                    StreamKind::Data,
                )) else {
                    return false;
                };
                let total = meta.len();
                if total == 0 {
                    return false;
                }
                let live_bytes = live_sets.get(&id).map(|b| b.len()).unwrap_or(0);
                (live_bytes as f64 / total as f64) < self.liveness_threshold
            })
            .collect()
    }
}
