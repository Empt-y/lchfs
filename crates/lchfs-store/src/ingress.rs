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

use crossbeam::queue::ArrayQueue;
use lchfs_format::Hash32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// One prepared, ready-to-commit chunk (or metadata object) handed off
/// from the Ingest Preparation Pool (prep.rs) to a logical shard's ring.
pub struct IngressOp {
    pub inode_id: u64,
    pub content_hash: Hash32,
    /// Already chunked/hashed/dedup-checked/maybe-compressed payload,
    /// zero-copy shared via `Bytes` (ARCHITECTURE.md §5a: this buffer
    /// choice is deliberately kernel-migration-friendly).
    pub payload: bytes::Bytes,
    pub logical_offset: u64,
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
}

impl LogicalShard {
    pub fn new(id: u32, ring_capacity: usize) -> Self {
        Self {
            id,
            ring: ArrayQueue::new(ring_capacity),
            claimed: AtomicBool::new(false),
        }
    }

    /// Try to claim exclusive access; `false` means another committer is
    /// already draining this shard.
    pub fn try_claim(&self) -> bool {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn release(&self) {
        self.claimed.store(false, Ordering::Release);
    }
}

/// Routes an inode to its logical shard. ARCHITECTURE.md §3: sharding key
/// is inode_id, not physical core — see that section for why a literal
/// per-core scheme would be incorrect.
pub fn shard_for_inode(inode_id: u64, shard_count: u32) -> u32 {
    // TODO(phase-E): a real hash, not the raw modulus (avoid pathological
    // clustering for sequential inode allocation)
    (inode_id % shard_count as u64) as u32
}

/// K physical committer threads (K ~= num_cpus) draining a work-stealing
/// deque of "logical shards with pending work". ARCHITECTURE.md §5.
pub struct CommitterPool {
    shards: Vec<Arc<LogicalShard>>,
    // TODO(phase-E): work-stealing deque (e.g. crossbeam_deque), thread handles
}

impl CommitterPool {
    pub fn new(_shard_count: u32, _worker_count: usize, _ring_capacity: usize) -> Self {
        todo!("lchfs-store: CommitterPool::new — see ARCHITECTURE.md §5")
    }

    /// Push a prepared op onto its inode's logical shard. Blocks the
    /// caller if the ring is full (ARCHITECTURE.md §5: "block the
    /// producer... never drop" — a dropped write is data loss).
    pub fn push(&self, _op: IngressOp) {
        todo!("lchfs-store: CommitterPool::push")
    }

    pub fn shard(&self, id: u32) -> &Arc<LogicalShard> {
        &self.shards[id as usize]
    }
}
