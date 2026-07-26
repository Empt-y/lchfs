//! Superblock formats. ARCHITECTURE.md §1 ("Superblock") and §3/§7 (per-shard
//! Shard Superblock, added to resolve the global-epoch fsync bottleneck).

use crate::{ExtentLocation, Hash32};
use serde::{Deserialize, Serialize};

/// Magic bytes identifying a global superblock slot on disk.
pub const SUPERBLOCK_MAGIC: [u8; 8] = *b"LCHFSBLK";

/// Number of slots in the global superblock ring. Commit always writes the
/// slot *after* the current generation's, never touching the currently-valid
/// one — see ARCHITECTURE.md §1.
pub const SUPERBLOCK_SLOT_COUNT: u32 = 16;

/// Fixed size in bytes of a single superblock slot (matches common
/// SSD/page atomic-write granularity — a documented assumption, not a
/// proof; see ARCHITECTURE.md §7).
pub const SUPERBLOCK_SLOT_SIZE: usize = 4096;

/// The global superblock: a 16-slot ring on disk. This type represents the
/// *logical* superblock (in-memory view); `SuperblockSlot` is the on-disk
/// per-slot record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Superblock {
    pub slots: [SuperblockSlot; SUPERBLOCK_SLOT_COUNT as usize],
}

/// One 4KiB slot of the global superblock ring (ARCHITECTURE.md §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperblockSlot {
    pub magic: [u8; 8],
    pub format_version: u32,
    pub generation: u64,
    pub root_hash: Hash32,
    pub root_location: ExtentLocation,
    /// Staleness marker compared against INDEX.redb's own recorded
    /// generation at mount time (ARCHITECTURE.md §4).
    pub index_generation: u64,
    pub committed_at_unix_nanos: i64,
    pub stats: SuperblockStats,
    pub header_checksum: u32,
}

/// Denormalized, informational-only stats carried in the superblock.
/// Never authoritative — never used for correctness decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SuperblockStats {
    pub live_bytes: u64,
    pub object_count: u64,
    pub segment_count: u64,
}

/// Magic bytes identifying a per-shard superblock slot.
pub const SHARD_SUPERBLOCK_MAGIC: [u8; 8] = *b"LCHFSSB\0";

/// One logical shard's own tiny superblock ring (ARCHITECTURE.md §1, §3):
/// exists so a shard's `fsync` fast path never contends with other shards
/// or with the global superblock ring. A single slot suffices given far
/// less per-slot metadata than the global superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardSuperblockSlot {
    pub magic: [u8; 8],
    pub shard_id: u32,
    pub delta_log_tail: ExtentLocation,
    /// Monotonic per-shard epoch counter, independent of the global
    /// superblock's `generation`.
    pub local_epoch: u64,
    pub header_checksum: u32,
}

/// Same zero-then-CRC32C pattern as `extent::compute_header_checksum`.
pub fn compute_superblock_slot_checksum(slot: &SuperblockSlot) -> u32 {
    let mut zeroed = *slot;
    zeroed.header_checksum = 0;
    let bytes = bincode::serialize(&zeroed).expect("SuperblockSlot serialization is infallible");
    lchfs_crypto::header_checksum(&bytes)
}

pub fn finalize_superblock_slot_checksum(slot: &mut SuperblockSlot) {
    slot.header_checksum = compute_superblock_slot_checksum(slot);
}

pub fn compute_shard_superblock_slot_checksum(slot: &ShardSuperblockSlot) -> u32 {
    let mut zeroed = *slot;
    zeroed.header_checksum = 0;
    let bytes =
        bincode::serialize(&zeroed).expect("ShardSuperblockSlot serialization is infallible");
    lchfs_crypto::header_checksum(&bytes)
}

pub fn finalize_shard_superblock_slot_checksum(slot: &mut ShardSuperblockSlot) {
    slot.header_checksum = compute_shard_superblock_slot_checksum(slot);
}
