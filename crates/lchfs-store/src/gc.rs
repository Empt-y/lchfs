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

use crate::segment::SegmentReader;
use crate::{SegmentReaders, StreamKind, dag_walk};
use lchfs_format::{Hash32, SegmentState};
use lchfs_index::ChunkLocationCache;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

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

pub struct GcEngine {
    pool_root: PathBuf,
    locations: Arc<ChunkLocationCache>,
    readers: SegmentReaders,
    liveness_threshold: f64,
}

impl GcEngine {
    pub fn new(pool_root: PathBuf, locations: Arc<ChunkLocationCache>) -> Self {
        Self {
            pool_root,
            locations,
            readers: HashMap::new(),
            liveness_threshold: DEFAULT_LIVENESS_THRESHOLD,
        }
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
    pub fn mark(&mut self, live_roots: &[Hash32]) -> HashMap<u64, RoaringBitmap> {
        let mut live = HashMap::new();
        for &root in live_roots {
            if let Err(e) = dag_walk::walk_reachable(
                root,
                &self.pool_root,
                &self.locations,
                &mut self.readers,
                &mut live,
            ) {
                tracing::error!("GC mark pass aborted: failed to walk root {root:?}: {e}");
                return HashMap::new();
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
        let dir = self.pool_root.join("segments").join("data");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };

        let mut segment_ids: Vec<u64> = entries
            .flatten()
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        segment_ids.sort_unstable();

        // Only ever consider *sealed* segments -- an Open segment is
        // still being actively written to by its shard's committer, never
        // a repack target.
        let sealed_ids: Vec<u64> = segment_ids
            .into_iter()
            .filter(|&id| {
                SegmentReader::open(&self.pool_root, id, StreamKind::Data)
                    .ok()
                    .and_then(|r| r.read_header().ok())
                    .map(|h| h.state != SegmentState::Open)
                    .unwrap_or(false)
            })
            .collect();

        let grace_cutoff = sealed_ids.len().saturating_sub(GRACE_WINDOW_SEGMENTS);

        sealed_ids[..grace_cutoff]
            .iter()
            .copied()
            .filter(|&id| {
                let Ok(meta) = std::fs::metadata(crate::segment::segment_path(
                    &self.pool_root,
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
