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

use crate::segment::{SegmentReader, SegmentWriter, device};
use crate::vdevs::VdevSet;
use std::sync::Arc;
use lchfs_format::{
    DeltaLogEntry, ExtentKind, ExtentLocation, Hash32, RecordCrypto, SHARD_SUPERBLOCK_MAGIC, ShardSuperblockSlot,
    compute_shard_superblock_slot_checksum, finalize_shard_superblock_slot_checksum,
};
use std::io;
use std::path::{Path, PathBuf};

/// A shard superblock is one 4 KiB slot in the device's shard superblock
/// region (see `lchfs-device`).
const SHARD_SUPERBLOCK_FILE_SIZE: u64 = lchfs_device::DEVICE_BLOCK;

/// A shard's delta segment is rolled once it passes this, so that there
/// are sealed segments for `truncate_through` to reclaim. Without a roll a
/// long mount appended every fsync of its lifetime to one segment, which
/// nothing could ever delete and every mount replayed from the start.
pub const DELTA_ROLL_BYTES: u64 = 16 * 1024 * 1024;

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
    /// The mount's online devices, which this shard's delta segments and
    /// shard superblock fan out to. The delta log is the fsync fast path
    /// (§3), so without fan-out here a write made durable by fsync --
    /// rather than by a checkpoint -- would exist on one device only.
    vdevs: Arc<VdevSet>,
    /// Snapshot of `vdevs` as of the current segment.
    vdev_roots: Vec<PathBuf>,
    /// The segment commits append to. Started by the first commit, not at
    /// open: on a device every segment holds a zone, and most of a pool's
    /// many shards may never see an fsync between two mounts.
    writer: Option<SegmentWriter>,
    /// The id the next segment started takes.
    next_segment_id: u64,
    local_epoch: u64,
    delta_log_tail: ExtentLocation,
}

impl ShardDeltaLog {
    /// Opens shard `shard_id`'s delta log, always starting a *fresh*
    /// segment for new writes -- at its first commit -- (mirroring `Pool::open` always starting
    /// fresh data/meta writers at mount) while recovering `local_epoch`/
    /// `delta_log_tail` from the shard's own superblock file, if present
    /// and valid. A missing or corrupt shard superblock degrades to
    /// "fresh state" (epoch 0) rather than a hard error -- non-fatal,
    /// since `replay_since(0)` against the still-intact, still-scannable
    /// delta segments just replays everything, which is idempotent.
    /// `open_on` with a bare device set built from `vdev_roots`, slot by
    /// position -- for tests that drive the log directly.
    pub fn open(vdev_roots: &[PathBuf], shard_id: u32) -> io::Result<Self> {
        Self::open_on(Arc::new(VdevSet::from_roots(vdev_roots)), shard_id)
    }

    pub fn open_on(vdevs: Arc<VdevSet>, shard_id: u32) -> io::Result<Self> {
        let online = vdevs.online();
        let vdev_roots: Vec<PathBuf> = online.iter().map(|v| v.root.clone()).collect();
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
        for root in &vdev_roots {
            for id in delta_segment_ids(root, shard_id)? {
                max_id = Some(max_id.map_or(id, |m| m.max(id)));
            }
        }
        let next_id = max_id.map_or(0, |m| m + 1);

        // The shard superblock fans out too; whichever device's copy is
        // furthest along is the truth, since a crash can land between two
        // devices' writes of the same commit.
        let mut recovered: Option<(u64, ExtentLocation)> = None;
        for root in &vdev_roots {
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
            vdevs,
            vdev_roots,
            writer: None,
            next_segment_id: next_id,
            local_epoch,
            delta_log_tail,
        })
    }

    /// Starts a fresh delta segment on the device set as it stands now.
    /// What a live attach calls, under this log's lock, so every commit
    /// after it fans out to the new device too. The old segment stays
    /// where it is: replay walks every segment on every device.
    pub fn roll_over(&mut self) -> io::Result<()> {
        let Some(old) = self.writer.take() else {
            // Nothing started yet: the first commit starts on the set as
            // it stands then.
            self.vdev_roots = self.vdevs.online().into_iter().map(|v| v.root).collect();
            return Ok(());
        };
        self.start_segment()?;
        for id in old.seal()? {
            self.vdevs.fault(id);
        }
        Ok(())
    }

    /// Starts a new segment on the device set as it stands now.
    fn start_segment(&mut self) -> io::Result<()> {
        let online = self.vdevs.online();
        let id = self.next_segment_id;
        self.next_segment_id += 1;
        self.writer = Some(SegmentWriter::create_delta_on(&online, self.shard_id, id)?);
        self.vdev_roots = online.into_iter().map(|v| v.root).collect();
        self.report_faults();
        Ok(())
    }

    /// The current segment, started if there is none.
    fn writer(&mut self) -> io::Result<&mut SegmentWriter> {
        if self.writer.is_none() {
            self.start_segment()?;
        }
        Ok(self.writer.as_mut().expect("started above"))
    }

    /// Reports replicas the current segment has dropped, and stops
    /// writing the shard superblock to them.
    fn report_faults(&mut self) {
        let Some(writer) = self.writer.as_mut() else { return };
        let faults = writer.take_faults();
        if faults.is_empty() {
            return;
        }
        for id in &faults {
            self.vdevs.fault(*id);
        }
        let still: Vec<u16> = writer.vdev_ids().to_vec();
        let online = self.vdevs.online();
        self.vdev_roots = online
            .into_iter()
            .filter(|v| still.contains(&v.id))
            .map(|v| v.root)
            .collect();
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
    ///
    /// Each record's `content_hash` must be its address in `crypto`'s
    /// current epoch -- the caller computed them from this same snapshot --
    /// and every record, the entry included, is sealed in that epoch.
    pub fn commit(
        &mut self,
        ino: u64,
        new_object_hash: Hash32,
        records: &[ShardCommitRecord],
        crypto: &RecordCrypto,
    ) -> io::Result<()> {
        let record_epoch = crypto.current_epoch();
        for record in records {
            let appended = crate::crypto::append_fresh(
                self.writer()?,
                crypto,
                record_epoch,
                record.kind,
                record.content_hash,
                lchfs_format::CodecId::None,
                record.encoded.len() as u32,
                &record.encoded,
            );
            self.report_faults();
            appended?;
        }

        let epoch = self.local_epoch + 1;
        let entry = DeltaLogEntry {
            ino,
            new_object_hash,
            epoch,
        };
        let encoded = lchfs_format::encode(&entry).map_err(decode_error)?;
        let entry_hash = crypto.address_in(record_epoch, &encoded);
        let appended = crate::crypto::append_fresh(
            self.writer()?,
            crypto,
            record_epoch,
            ExtentKind::DeltaLogEntry,
            entry_hash,
            lchfs_format::CodecId::None,
            encoded.len() as u32,
            &encoded,
        );
        self.report_faults();
        let loc = appended?;

        let synced = self.writer()?.fsync();
        self.report_faults();
        synced?;

        self.local_epoch = epoch;
        self.delta_log_tail = loc;
        self.write_shard_superblock()?;
        // After the commit is durable and claimed: the roll only starts a
        // new segment for the next one. A commit's records and its entry
        // therefore always share a segment -- what `truncate_through`
        // relies on to delete them together.
        if self.writer()?.current_size() >= DELTA_ROLL_BYTES {
            self.roll_over()?;
        }
        Ok(())
    }

    /// The segment new commits go to -- or, before the first, will go
    /// to; never a truncation candidate, and every segment already on a
    /// device has a lower id.
    pub fn current_segment_id(&self) -> u64 {
        self.writer.as_ref().map_or(self.next_segment_id, SegmentWriter::segment_id)
    }

    /// The roots this log writes to right now.
    pub fn roots(&self) -> Vec<PathBuf> {
        self.vdev_roots.clone()
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
            "ShardSuperblockSlot must fit in its reserved slot"
        );

        let mut buf = vec![0u8; SHARD_SUPERBLOCK_FILE_SIZE as usize];
        buf[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf[4..4 + encoded.len()].copy_from_slice(&encoded);
        // Per device, like the segment writes: a device that cannot take
        // its shard superblock is faulted, and the commit stands on the
        // devices that could.
        let mut wrote_one = false;
        let mut last_err = None;
        let online = self.vdevs.online();
        for root in &self.vdev_roots {
            let write = device(root).and_then(|d| d.write_shard_superblock(self.shard_id, &buf));
            match write {
                Ok(()) => wrote_one = true,
                Err(e) => {
                    if let Some(v) = online.iter().find(|v| &v.root == root) {
                        self.vdevs.fault(v.id);
                    }
                    last_err = Some(e);
                }
            }
        }
        if !wrote_one
            && let Some(e) = last_err
        {
            return Err(e);
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
    ///
    /// A sealed record's outer kind says nothing (it is always `Sealed`),
    /// so sealed records are opened with `crypto` to learn whether they are
    /// entries; one that opens on no device is reported like an unreadable
    /// entry, since it may have been one.
    pub fn replay_since(&self, watermark: u64, crypto: &RecordCrypto) -> io::Result<ReplayResult> {
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
            // Offsets whose framing parsed somewhere but whose entry never
            // read back on any device: a silent drop here is an fsync'd
            // update quietly lost, so at least say so.
            let mut unreadable: std::collections::HashSet<u32> = std::collections::HashSet::new();
            for root in &self.vdev_roots {
                let Ok(reader) = SegmentReader::open_delta(root, self.shard_id, segment_id) else {
                    continue;
                };
                for (header, offset) in reader.scan() {
                    let loc = ExtentLocation {
                        segment_id,
                        offset,
                        len: header.record_len,
                    };
                    if !seen.contains(&offset) {
                        if lchfs_format::is_sealed(&header) {
                            match reader.read_record_with(loc, crypto) {
                                Ok((effective, bytes)) if effective.kind == ExtentKind::DeltaLogEntry => {
                                    if let Ok(entry) = lchfs_format::decode::<DeltaLogEntry>(&bytes) {
                                        entries.push(entry);
                                        seen.insert(offset);
                                        unreadable.remove(&offset);
                                    } else {
                                        unreadable.insert(offset);
                                    }
                                }
                                Ok(_) => {
                                    locations.push((header.content_hash, loc));
                                    seen.insert(offset);
                                    unreadable.remove(&offset);
                                }
                                Err(_) => {
                                    unreadable.insert(offset);
                                }
                            }
                        } else if header.kind == ExtentKind::DeltaLogEntry {
                            if let Ok((_h, bytes)) = reader.read_record_with(loc, crypto)
                                && let Ok(entry) = lchfs_format::decode::<DeltaLogEntry>(&bytes)
                            {
                                entries.push(entry);
                                seen.insert(offset);
                                unreadable.remove(&offset);
                            } else {
                                unreadable.insert(offset);
                            }
                        } else {
                            // Content is verified when it is actually read,
                            // through a path that fails over; here only the
                            // framing matters.
                            locations.push((header.content_hash, loc));
                            seen.insert(offset);
                        }
                    }
                }
            }
            for offset in unreadable {
                tracing::error!(
                    "shard {} delta segment {segment_id} offset {offset}: entry unreadable on every device; an fsync'd update may be lost",
                    self.shard_id
                );
            }
        }

        entries.retain(|e| e.epoch > watermark);
        entries.sort_by_key(|e| e.epoch);

        Ok(ReplayResult { entries, locations })
    }
}

/// Deletes shard `shard_id`'s delta segments that no replay can need: every
/// segment below `current` (the one commits go to) whose entries all have
/// an epoch at or below `watermark`, which must be a watermark some
/// *published* root carries. Replay applies only entries above the
/// published root's watermark, and a replayed entry's records live in the
/// same segment as the entry (`commit` never rolls mid-commit), so such a
/// segment holds nothing any mount will read. A segment with no entry at
/// all -- a commit torn before its entry -- is dead the same way.
///
/// Conservative where it cannot tell: a record that opens on no device may
/// have been an entry of any epoch, so its segment is kept. Sealed records
/// hide their kind, which is why this takes the pool's crypto.
///
/// Takes no lock: segments below `current` are never appended to again,
/// and nothing but a mount reads them. Returns the ids deleted.
pub fn truncate_through(
    roots: &[PathBuf],
    shard_id: u32,
    current: u64,
    watermark: u64,
    crypto: &RecordCrypto,
) -> io::Result<Vec<u64>> {
    let mut ids: Vec<u64> = Vec::new();
    for root in roots {
        ids.extend(delta_segment_ids(root, shard_id)?);
    }
    ids.sort_unstable();
    ids.dedup();
    let mut deleted = Vec::new();
    for segment_id in ids.into_iter().filter(|&id| id < current) {
        if !segment_is_dead(roots, shard_id, segment_id, watermark, crypto) {
            continue;
        }
        for root in roots {
            match crate::segment::remove_delta_segment(root, shard_id, segment_id) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        deleted.push(segment_id);
    }
    Ok(deleted)
}

/// Whether every entry in the segment is at or below `watermark`, judged
/// from whichever device's copy reads each record.
fn segment_is_dead(roots: &[PathBuf], shard_id: u32, segment_id: u64, watermark: u64, crypto: &RecordCrypto) -> bool {
    let mut resolved: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut unresolved: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for root in roots {
        let Ok(reader) = SegmentReader::open_delta(root, shard_id, segment_id) else {
            continue;
        };
        for (header, offset) in reader.scan() {
            if resolved.contains(&offset) {
                continue;
            }
            let loc = ExtentLocation {
                segment_id,
                offset,
                len: header.record_len,
            };
            let plain_object = !lchfs_format::is_sealed(&header) && header.kind != ExtentKind::DeltaLogEntry;
            if plain_object {
                // A plaintext object record: no entry, nothing to check.
                resolved.insert(offset);
                unresolved.remove(&offset);
                continue;
            }
            match reader.read_record_with(loc, crypto) {
                Ok((effective, bytes)) => {
                    if effective.kind == ExtentKind::DeltaLogEntry {
                        match lchfs_format::decode::<DeltaLogEntry>(&bytes) {
                            Ok(entry) if entry.epoch <= watermark => {}
                            _ => return false,
                        }
                    }
                    resolved.insert(offset);
                    unresolved.remove(&offset);
                }
                Err(_) => {
                    unresolved.insert(offset);
                }
            }
        }
    }
    unresolved.is_empty()
}

/// Every delta segment id present for `shard_id` on the device at
/// `vdev_root`; empty if the device is not there.
fn delta_segment_ids(vdev_root: &Path, shard_id: u32) -> io::Result<Vec<u64>> {
    Ok(crate::segment::delta_segment_ids(vdev_root, shard_id))
}

fn read_shard_superblock_file(
    pool_root: &Path,
    shard_id: u32,
) -> io::Result<Option<ShardSuperblockSlot>> {
    let Ok(dev) = device(pool_root) else { return Ok(None) };
    let buf = dev.read_shard_superblock(shard_id)?;
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
