//! Per-shard Delta Log. ARCHITECTURE.md §3 ("Subtree durability via
//! per-shard delta logs") and §7 (crash recovery replay).
//!
//! This is the mechanism that resolves the global-epoch fsync bottleneck:
//! a file's content update only ever needs to touch its owning shard's
//! Delta Log + tiny Shard Superblock, never the global root, because
//! `DirectoryObject` entries reference `ino` (not a content hash) and the
//! `InoMap` is the only thing that actually changes on a content write.

use lchfs_format::{DeltaLogEntry, ShardSuperblockSlot};

/// One logical shard's append-only `{ino -> new_object_hash}` stream, plus
/// its own tiny superblock ring. Exists so a shard's `fsync` fast path
/// never contends with other shards or with the global superblock ring
/// (ARCHITECTURE.md §1, §3).
pub struct ShardDeltaLog {
    pub shard_id: u32,
    // TODO(phase-E): open segment/file handle for this shard's delta log stream,
    // current ShardSuperblockSlot state
}

impl ShardDeltaLog {
    pub fn open(_shard_id: u32) -> std::io::Result<Self> {
        todo!("lchfs-store: ShardDeltaLog::open")
    }

    /// The `fsync(fd)` fast path (ARCHITECTURE.md §3): append + fsync a
    /// `{ino, new_hash}` record, then write + fsync this shard's own tiny
    /// superblock slot. Cost is O(this shard's dirty data since its own
    /// last local checkpoint) -- unrelated shards are unaffected.
    pub fn commit(&mut self, _entry: DeltaLogEntry) -> std::io::Result<()> {
        todo!("lchfs-store: ShardDeltaLog::commit — see ARCHITECTURE.md §3")
    }

    /// Read this shard's current tiny superblock slot (its delta log
    /// tail), used both by `commit` and by mount-time recovery.
    pub fn read_shard_superblock(&self) -> std::io::Result<ShardSuperblockSlot> {
        todo!("lchfs-store: ShardDeltaLog::read_shard_superblock")
    }

    /// Replay entries newer than `watermark` (ARCHITECTURE.md §7: "a
    /// small, deliberately bounded, idempotent replay — a list of
    /// key->value overwrites, no undo logic, no arbitrary operation log"),
    /// applying them on top of the base InoMap read from the global
    /// checkpoint.
    pub fn replay_since(&self, _watermark: u64) -> std::io::Result<Vec<DeltaLogEntry>> {
        todo!("lchfs-store: ShardDeltaLog::replay_since — see ARCHITECTURE.md §7")
    }
}
