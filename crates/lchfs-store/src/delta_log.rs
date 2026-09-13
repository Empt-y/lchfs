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
    /// Every vdev this shard's delta segments and shard superblock are
    /// written to. The delta log is the fsync fast path (§3), so without
    /// fan-out here a write made durable by fsync -- rather than by a
    /// checkpoint -- would exist on one device only.
    vdev_roots: Vec<PathBuf>,
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
    pub fn open(vdev_roots: &[PathBuf], shard_id: u32) -> io::Result<Self> {
        if vdev_roots.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a delta log needs at least one vdev",
            ));
        }
        // The next id must clear every segment on *every* device. Seeding
        // it from vdev 0 alone would, with vdev 0's delta directory lost,
        // start again at 0 -- and `create_delta` fans out with truncate,
        // so it would wipe vdev 1's `0.dseg`, the one surviving copy of
        // whatever was fsync'd but not yet checkpointed, before replay
        // ever looked at it.
        let mut max_id: Option<u64> = None;
        for root in vdev_roots {
            for id in delta_segment_ids(root, shard_id)? {
                max_id = Some(max_id.map_or(id, |m| m.max(id)));
            }
        }
        let next_id = max_id.map_or(0, |m| m + 1);

        let writer = SegmentWriter::create_delta(
            &vdev_roots.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
            shard_id,
            next_id,
        )?;

        // The shard superblock fans out too; whichever device's copy is
        // furthest along is the truth, since a crash can land between two
        // devices' writes of the same commit.
        let mut recovered: Option<(u64, ExtentLocation)> = None;
        for root in vdev_roots {
            if let Ok(Some(slot)) = read_shard_superblock_file(root, shard_id)
                && slot.shard_id == shard_id
                && recovered.is_none_or(|(epoch, _)| slot.local_epoch > epoch)
            {
                recovered = Some((slot.local_epoch, slot.delta_log_tail));
            }
        }
        let (local_epoch, delta_log_tail) = recovered.unwrap_or((0, ExtentLocation::default()));

        Ok(Self {
            shard_id,
            vdev_roots: vdev_roots.to_vec(),
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

        let mut buf = vec![0u8; SHARD_SUPERBLOCK_FILE_SIZE as usize];
        buf[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf[4..4 + encoded.len()].copy_from_slice(&encoded);
        for root in &self.vdev_roots {
            let path = shard_superblock_path(root, self.shard_id);
            std::fs::create_dir_all(path.parent().unwrap())?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            file.write_all_at(&buf, 0)?;
            file.sync_all()?;
        }
        Ok(())
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
    ///
    /// Every device is scanned, not just the primary (§15.2). Delta
    /// segments fan out like everything else, so a segment or a record the
    /// primary has lost is still on the others at the same offset. Each
    /// segment id seen on any device is walked on every device, and a
    /// record counts once -- from the first device where it reads back and
    /// verifies -- so a torn or rotted copy on one device neither ends the
    /// scan early nor replays twice.
    pub fn replay_since(&self, watermark: u64) -> io::Result<ReplayResult> {
        let mut segment_ids: Vec<u64> = Vec::new();
        for root in &self.vdev_roots {
            segment_ids.extend(delta_segment_ids(root, self.shard_id)?);
        }
        segment_ids.sort_unstable();
        segment_ids.dedup();

        let mut entries = Vec::new();
        let mut locations = Vec::new();

        for segment_id in segment_ids {
            let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
            for root in &self.vdev_roots {
                let Ok(reader) = SegmentReader::open_delta(root, self.shard_id, segment_id) else {
                    continue;
                };
                let mut offset = crate::segment::SEGMENT_HEADER_PAGE_SIZE as u32;
                while let Some((header, next_offset)) = reader.scan_next(offset) {
                    let loc = ExtentLocation {
                        segment_id,
                        offset,
                        len: header.record_len,
                    };
                    if !seen.contains(&offset) {
                        if header.kind == ExtentKind::DeltaLogEntry {
                            if let Ok((_h, bytes)) = reader.read_record(loc)
                                && let Ok(entry) = lchfs_format::decode::<DeltaLogEntry>(&bytes)
                            {
                                entries.push(entry);
                                seen.insert(offset);
                            }
                        } else {
                            // Content is verified when it is actually read,
                            // through a path that fails over; here only the
                            // framing matters.
                            locations.push((header.content_hash, loc));
                            seen.insert(offset);
                        }
                    }
                    offset = next_offset;
                }
            }
        }

        entries.retain(|e| e.epoch > watermark);
        entries.sort_by_key(|e| e.epoch);

        Ok(ReplayResult { entries, locations })
    }
}

/// Every delta segment id present for `shard_id` under `vdev_root`;
/// empty if the shard has no directory there.
fn delta_segment_ids(vdev_root: &Path, shard_id: u32) -> io::Result<Vec<u64>> {
    let dir = delta_segment_dir(vdev_root, shard_id);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let file_name = entry?.file_name();
        if let Some(id) = Path::new(&file_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
        {
            ids.push(id);
        }
    }
    Ok(ids)
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
