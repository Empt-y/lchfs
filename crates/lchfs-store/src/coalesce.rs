//! The Coalescing Daemon. ARCHITECTURE.md §5: idle-cycle, background,
//! *layout only* — repacks segments with a poor live/dead ratio into
//! fewer, fuller segments. Never makes keep/drop decisions by
//! `content_hash` equality; that's the Dedup Index Scanner's job
//! (dedup.rs), a deliberately separate mechanism (see §5's "Three
//! background daemons, cleanly separated").
//!
//! Also performs the physical repack step of GC sweep (ARCHITECTURE.md
//! §6): because `content_hash` never changes on relocation, repacking
//! only ever updates the Chunk Location Index, never a DAG node.

pub struct CoalesceDaemon {
    // TODO(phase-E): liveness-threshold config (default 50%), segment scan cursor
}

impl CoalesceDaemon {
    pub fn new() -> Self {
        Self {}
    }

    /// One idle-cycle pass: find segments below the liveness threshold
    /// (using the roaring-bitmap live set from gc.rs's mark phase), copy
    /// forward only live extents into a fresh segment, update the Chunk
    /// Location Index, then delete the old segment once the new one is
    /// fsync'd and the index update is durable (ARCHITECTURE.md §6).
    pub fn run_pass(&mut self) -> std::io::Result<()> {
        todo!("lchfs-store: CoalesceDaemon::run_pass — see ARCHITECTURE.md §6")
    }
}

impl Default for CoalesceDaemon {
    fn default() -> Self {
        Self::new()
    }
}
