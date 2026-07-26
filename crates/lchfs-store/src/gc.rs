//! Mark-and-sweep garbage collection. ARCHITECTURE.md §6.
//!
//! Live roots = `{current superblock root_hash} u {every SnapshotTable
//! entry's root_hash} u {snapshot_table_hash}`. `INDEX.redb` is explicitly
//! excluded from GC accounting (it's a cache with its own simpler
//! lifecycle, checkpointed independently -- see lchfs-index).

use lchfs_format::Hash32;
use roaring::RoaringBitmap;
use std::collections::HashMap;

pub struct GcEngine {
    // TODO(phase-F): per-segment live-set bitmaps, grace-period tracking
    // (never sweep the current/immediately-prior epoch)
}

impl GcEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Walk RootObject -> InoMap -> per-ino InodeObject -> DirectoryObject
    /// entries / IndirectHashList -> chunk hashes, from every live root.
    /// Runs concurrently with live traffic by snapshotting the root
    /// pointer at walk-start -- no lock needed, since the DAG is immutable
    /// (ARCHITECTURE.md §6).
    pub fn mark(&mut self, _live_roots: &[Hash32]) -> HashMap<u64, RoaringBitmap> {
        todo!("lchfs-store: GcEngine::mark — see ARCHITECTURE.md §6")
    }

    /// Compute, per segment, the live-byte fraction from the mark-phase
    /// bitmaps. Segments below the liveness threshold are handed to the
    /// Coalescing Daemon (coalesce.rs) for physical repacking -- GC itself
    /// never rewrites DAG nodes, only decides what's reclaimable.
    pub fn sweep_candidates(&self, _live_sets: &HashMap<u64, RoaringBitmap>) -> Vec<u64> {
        todo!("lchfs-store: GcEngine::sweep_candidates — see ARCHITECTURE.md §6")
    }
}

impl Default for GcEngine {
    fn default() -> Self {
        Self::new()
    }
}
