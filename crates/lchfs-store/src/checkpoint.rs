//! The global Checkpoint Coordinator. ARCHITECTURE.md §3 (the 5-step
//! process) and §5 ("foreground-critical durability, runs every epoch,
//! not idle-cycle" — distinct from the Coalescing Daemon and Dedup Index
//! Scanner, which are both idle-cycle background work).

use lchfs_format::RootObject;

/// Single thread running the periodic global checkpoint (default every
/// 5s, or on unmount, or on explicit consolidation). ARCHITECTURE.md §3.
pub struct CheckpointCoordinator {
    // TODO(phase-B): dirty-inode tracking, segment fsync list, current RootObject
}

impl CheckpointCoordinator {
    pub fn new() -> Self {
        Self {}
    }

    /// Runs the full 5-step global checkpoint (ARCHITECTURE.md §3):
    /// flush dirty shards -> fsync data segments (barrier #1) -> bottom-up
    /// rewrite dirty InodeObject/DirectoryObject nodes -> fsync meta
    /// segment (barrier #2) -> build+fsync new RootObject -> write+fsync
    /// new superblock slot. The invariant that makes this journal-free:
    /// no parent's hash is ever computed over a child not yet fsync'd.
    pub fn run_epoch(&mut self) -> std::io::Result<RootObject> {
        todo!("lchfs-store: CheckpointCoordinator::run_epoch — see ARCHITECTURE.md §3")
    }
}

impl Default for CheckpointCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
