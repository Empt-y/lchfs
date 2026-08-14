//! Per-shard Delta Log. ARCHITECTURE.md §3 ("Subtree durability via
//! per-shard delta logs") and §7 (crash recovery replay).
//!
//! This is the mechanism that resolves the global-epoch fsync bottleneck:
//! a file's content update only ever needs to touch its owning shard's
//! Delta Log + tiny Shard Superblock, never the global root, because
//! `DirectoryObject` entries reference `ino` (not a content hash) and the
//! `InoMap` is the only thing that actually changes on a content write.
//!
//! Self-contained fast-fsync stream: `commit` writes not just the
//! `DeltaLogEntry` pointer but the freshly-rewritten `InodeObject`/
//! `IndirectHashList` records themselves into this shard's own Delta
//! stream, so `fsync(ino)` never touches the global meta stream or any
//! other shard. The later global checkpoint's "official" rewrite of the
//! same objects naturally dedups against this via content-addressing
//! (same bytes -> same hash -> no-op).

use crate::segment::{SegmentReader, SegmentWriter, delta_segment_dir};
use lchfs_format::{
    DeltaLogEntry, ExtentKind, ExtentLocation, Hash32, SHARD_SUPERBLOCK_MAGIC, ShardSuperblockSlot,
    compute_shard_superblock_slot_checksum, finalize_shard_superblock_slot_checksum,
};
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const SHARD_SUPERBLOCK_FILE_SIZE: u64 = 4096;

fn shard_superblock_path(pool_root: &Path, shard_id: u32) -> PathBuf {
    delta_segment_dir(pool_root, shard_id).join("superblock.sblk")
}

fn decode_error(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// A record (already encoded) to write into a shard's delta stream ahead
/// of the `DeltaLogEntry` that points at it -- typically the file's fresh
/// `InodeObject` and, if it has chunked (non-inline) content, its fresh
/// `IndirectHashList`.
pub struct ShardCommitRecord {
    pub kind: ExtentKind,
    pub content_hash: Hash32,
    pub encoded: Vec<u8>,
}

/// Result of replaying a shard's delta log since some watermark epoch
/// (ARCHITECTURE.md §7). `locations` covers *every* record found in this
/// shard's delta stream (not just those newer than the watermark) so the
/// caller can backfill its location index for any hash a replayed
/// `DeltaLogEntry`'s referenced `InodeObject`/`IndirectHashList` needs to
/// resolve -- those were never written to the global meta stream or
/// `INDEX.redb`, only to this shard's own Delta stream.
pub struct ReplayResult {
    pub entries: Vec<DeltaLogEntry>,
    pub locations: Vec<(Hash32, ExtentLocation)>,
}

/// One logical shard's append-only `{ino -> new_object_hash}` stream, plus
/// its own tiny superblock ring. Exists so a shard's `fsync` fast path
/// never contends with other shards or with the global superblock ring
/// (ARCHITECTURE.md §1, §3).
pub struct ShardDeltaLog {
    pub shard_id: u32,
    pool_root: PathBuf,
    writer: SegmentWriter,
    local_epoch: u64,
    delta_log_tail: ExtentLocation,
}

impl ShardDeltaLog {
    /// Opens shard `shard_id`'s delta log, always starting a *fresh*
    /// segment for new writes (mirroring `Pool::open` always starting
    /// fresh data/meta writers at mount) while recovering `local_epoch`/
    /// `delta_log_tail` from the shard's own superblock file, if present
    /// and valid. A missing or corrupt shard superblock degrades to
    /// "fresh state" (epoch 0) rather than a hard error -- non-fatal,
    /// since `replay_since(0)` against the still-intact, still-scannable
    /// delta segments just replays everything, which is idempotent.
    pub fn open(pool_root: &Path, shard_id: u32) -> io::Result<Self> {
        let dir = delta_segment_dir(pool_root, shard_id);
        let next_id = if dir.is_dir() {
            let mut max_id: Option<u64> = None;
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let file_name = entry.file_name();
                let stem = Path::new(&file_name)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if let Ok(id) = stem.parse::<u64>() {
                    max_id = Some(max_id.map_or(id, |m| m.max(id)));
                }
            }
            max_id.map_or(0, |m| m + 1)
        } else {
            0
        };

        let writer = SegmentWriter::create_delta(pool_root, shard_id, next_id)?;

        let (local_epoch, delta_log_tail) = match read_shard_superblock_file(pool_root, shard_id) {
            Ok(Some(slot)) if slot.shard_id == shard_id => (slot.local_epoch, slot.delta_log_tail),
            _ => (0, ExtentLocation::default()),
        };

        Ok(Self {
            shard_id,
            pool_root: pool_root.to_path_buf(),
            writer,
            local_epoch,
            delta_log_tail,
        })
    }

    /// The `fsync(fd)` fast path (ARCHITECTURE.md §3): append `records`
    /// (typically the file's fresh IndirectHashList then InodeObject) plus
    /// a `DeltaLogEntry{ino, new_object_hash, epoch}` to this shard's own
    /// Delta stream, one `fsync()` covering all of them (none needs to be
    /// durable ahead of the others within a single fsync call -- the
    /// invariant that matters is that they're *all* durable before the
    /// shard superblock slot claims this epoch), then write+fsync this
    /// shard's own tiny superblock slot. Cost is O(this shard's dirty data
    /// since its own last local checkpoint) -- unrelated shards are
    /// unaffected.
    pub fn commit(
        &mut self,
        ino: u64,
        new_object_hash: Hash32,
        records: &[ShardCommitRecord],
    ) -> io::Result<()> {
        for record in records {
            self.writer.append(
                record.kind,
                record.content_hash,
                lchfs_format::CodecId::None,
                record.encoded.len() as u32,
                &record.encoded,
                Vec::new(),
            )?;
        }

        let epoch = self.local_epoch + 1;
        let entry = DeltaLogEntry {
            ino,
            new_object_hash,
            epoch,
        };
        let encoded = lchfs_format::encode(&entry).map_err(decode_error)?;
        let entry_hash = Hash32::of(&encoded);
        let loc = self.writer.append(
            ExtentKind::DeltaLogEntry,
            entry_hash,
            lchfs_format::CodecId::None,
            encoded.len() as u32,
            &encoded,
            Vec::new(),
        )?;

        self.writer.fsync()?;

        self.local_epoch = epoch;
        self.delta_log_tail = loc;
        self.write_shard_superblock()
    }

    fn write_shard_superblock(&self) -> io::Result<()> {
        let mut slot = ShardSuperblockSlot {
            magic: SHARD_SUPERBLOCK_MAGIC,
            shard_id: self.shard_id,
            delta_log_tail: self.delta_log_tail,
            local_epoch: self.local_epoch,
            header_checksum: 0,
        };
        finalize_shard_superblock_slot_checksum(&mut slot);
        let encoded = lchfs_format::encode(&slot).map_err(decode_error)?;
        assert!(
            encoded.len() as u64 + 4 <= SHARD_SUPERBLOCK_FILE_SIZE,
            "ShardSuperblockSlot must fit in the reserved shard superblock file"
        );

        let path = shard_superblock_path(&self.pool_root, self.shard_id);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let mut buf = vec![0u8; SHARD_SUPERBLOCK_FILE_SIZE as usize];
        buf[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf[4..4 + encoded.len()].copy_from_slice(&encoded);
        file.write_all_at(&buf, 0)?;
        file.sync_all()
    }

    /// Read this shard's current tiny superblock slot, used both by
    /// `commit` (via the in-memory `local_epoch`/`delta_log_tail` it
    /// keeps in sync with what's on disk) and by mount-time recovery to
    /// find each shard's `local_epoch` and delta-log tail.
    pub fn read_shard_superblock(&self) -> io::Result<ShardSuperblockSlot> {
        let mut slot = ShardSuperblockSlot {
            magic: SHARD_SUPERBLOCK_MAGIC,
            shard_id: self.shard_id,
            delta_log_tail: self.delta_log_tail,
            local_epoch: self.local_epoch,
            header_checksum: 0,
        };
        finalize_shard_superblock_slot_checksum(&mut slot);
        Ok(slot)
    }

    /// Replay entries newer than `watermark` (ARCHITECTURE.md §7: "a
    /// small, deliberately bounded, idempotent replay -- a list of
    /// key->value overwrites, no undo logic, no arbitrary operation log"),
    /// applying them on top of the base InoMap read from the global
    /// checkpoint. Scans every `.dseg` file for this shard (not a
    /// pointer-chase from `delta_log_tail` -- that field is a resume-point
    /// hint only, correctness comes from `commit`'s own append-fsync-
    /// persist-counter serialization, not from trusting it), tolerating a
    /// torn trailing record from a crash mid-append the same way mount-
    /// time segment scanning already does.
    pub fn replay_since(&self, watermark: u64) -> io::Result<ReplayResult> {
        let dir = delta_segment_dir(&self.pool_root, self.shard_id);
        let mut segment_ids: Vec<u64> = if dir.is_dir() {
            std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let file_name = e.file_name();
                    Path::new(&file_name)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse::<u64>().ok())
                })
                .collect()
        } else {
            Vec::new()
        };
        segment_ids.sort_unstable();

        let mut entries = Vec::new();
        let mut locations = Vec::new();

        for segment_id in segment_ids {
            let reader =
                match SegmentReader::open_delta(&self.pool_root, self.shard_id, segment_id) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
            let mut offset = crate::segment::SEGMENT_HEADER_PAGE_SIZE as u32;
            while let Some((header, next_offset)) = reader.scan_next(offset) {
                let loc = ExtentLocation {
                    segment_id,
                    offset,
                    len: header.record_len,
                };
                if header.kind == ExtentKind::DeltaLogEntry {
                    if let Ok((_h, bytes)) = reader.read_record(loc)
                        && let Ok(entry) = lchfs_format::decode::<DeltaLogEntry>(&bytes)
                    {
                        entries.push(entry);
                    }
                } else {
                    locations.push((header.content_hash, loc));
                }
                offset = next_offset;
            }
        }

        entries.retain(|e| e.epoch > watermark);
        entries.sort_by_key(|e| e.epoch);

        Ok(ReplayResult { entries, locations })
    }
}

fn read_shard_superblock_file(
    pool_root: &Path,
    shard_id: u32,
) -> io::Result<Option<ShardSuperblockSlot>> {
    let path = shard_superblock_path(pool_root, shard_id);
    if !path.is_file() {
        return Ok(None);
    }
    let file = OpenOptions::new().read(true).open(&path)?;
    let mut buf = vec![0u8; SHARD_SUPERBLOCK_FILE_SIZE as usize];
    file.read_exact_at(&mut buf, 0)?;
    if buf.len() < 4 {
        return Ok(None);
    }
    let encoded_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if encoded_len == 0 || 4 + encoded_len > buf.len() {
        return Ok(None);
    }
    let Ok(slot) = lchfs_format::decode::<ShardSuperblockSlot>(&buf[4..4 + encoded_len]) else {
        return Ok(None);
    };
    if slot.magic != SHARD_SUPERBLOCK_MAGIC {
        return Ok(None);
    }
    if compute_shard_superblock_slot_checksum(&slot) != slot.header_checksum {
        return Ok(None);
    }
    Ok(Some(slot))
}
