//! DAG-walk verification. ARCHITECTURE.md §10 ("fsck tool"): walks the
//! full DAG from every live root; verifies content_hash, structural
//! well-formedness (sorted/no-dup dir entries, size == sum of chunk
//! lengths), InoMap referential integrity. `--verify-index` cross-checks
//! `INDEX.redb` against a fresh walk; `--rebuild-index` regenerates it.

use lchfs_format::Hash32;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsckError {
    #[error("content hash mismatch at {location}")]
    ContentHashMismatch { location: String },
    #[error("directory entries not sorted or contain duplicates: {dir_ino}")]
    UnsortedOrDuplicateDirEntries { dir_ino: u64 },
    #[error("size mismatch for ino {ino}: InodeObject says {declared}, chunks sum to {actual}")]
    SizeMismatch { ino: u64, declared: u64, actual: u64 },
    #[error("dangling ino {ino} referenced by directory entry but missing from InoMap")]
    DanglingIno { ino: u64 },
    #[error("index entry for {hash:?} disagrees with fresh DAG walk")]
    IndexMismatch { hash: Hash32 },
}

/// Aggregated results of a full fsck run.
#[derive(Debug, Default)]
pub struct FsckReport {
    pub errors: Vec<FsckError>,
    pub objects_visited: u64,
}

impl FsckReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Walk the full DAG from every live root (current + every retained
/// snapshot) and verify content hashes and structural well-formedness.
/// ARCHITECTURE.md §10.
pub fn check(_live_roots: &[Hash32]) -> FsckReport {
    // TODO(phase-F): recursive walk per ARCHITECTURE.md §6's mark-phase
    // traversal, but verifying rather than just marking reachability
    todo!("lchfs-fsck: check — see ARCHITECTURE.md §10")
}

/// Cross-check `INDEX.redb` against a fresh DAG walk without rebuilding it.
pub fn verify_index(_live_roots: &[Hash32]) -> FsckReport {
    todo!("lchfs-fsck: verify_index")
}

/// Regenerate the persisted index from scratch via a full cold DAG walk
/// (ARCHITECTURE.md §4: the index is a rebuildable cache, never
/// authoritative -- this is the explicit full-rebuild path).
pub fn rebuild_index(_live_roots: &[Hash32]) -> Result<(), FsckError> {
    todo!("lchfs-fsck: rebuild_index")
}
