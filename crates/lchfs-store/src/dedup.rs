//! The Dedup Index Scanner. ARCHITECTURE.md §5: idle-cycle, background,
//! *identity convergence only* — catches duplicate content that raced
//! past the inline fast-path check in prep.rs (two logical shards writing
//! identical new content in the same epoch, neither seeing the other's
//! not-yet-indexed write).
//!
//! Never deletes the orphaned duplicate directly (can't -- append-only);
//! once nothing references it, ordinary GC (gc.rs) reclaims it with no
//! special-casing.

use lchfs_format::{ExtentLocation, Hash32};

pub struct DedupScanner {
    // TODO(phase-E): cursor over newly-sealed segments since last scan
}

impl DedupScanner {
    pub fn new() -> Self {
        Self {}
    }

    /// Scan newly-sealed segments for `content_hash` collisions the
    /// inline fast path missed. For each: pick a canonical location
    /// (deterministic tie-break, e.g. lowest segment_id), update the
    /// index, rewrite the few InodeObject/IndirectHashList records
    /// pointing at the loser to point at the winner (ARCHITECTURE.md §5).
    pub fn run_pass(&mut self) -> std::io::Result<Vec<DedupMerge>> {
        todo!("lchfs-store: DedupScanner::run_pass — see ARCHITECTURE.md §5")
    }
}

impl Default for DedupScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// One resolved duplicate: `loser` becomes unreferenced (and later
/// GC-reclaimed) once every record pointing at it has been rewritten to
/// point at `canonical` instead.
pub struct DedupMerge {
    pub content_hash: Hash32,
    pub canonical: ExtentLocation,
    pub loser: ExtentLocation,
}
