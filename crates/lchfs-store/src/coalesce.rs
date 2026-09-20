//! The Coalescing Daemon. ARCHITECTURE.md §5: idle-cycle, background,
//! *layout only* — repacks segments with a poor live/dead ratio into
//! fewer, fuller segments. Never makes keep/drop decisions by
//! `content_hash` equality; that's the Dedup Index Scanner's job
//! (dedup.rs), a deliberately separate mechanism (see §5's "Three
//! background daemons, cleanly separated").
//!
//! Also performs the physical repack step of GC sweep (ARCHITECTURE.md
//! §6): because `content_hash` never changes on relocation, repacking
//! only ever updates the Chunk Location Index, never a DAG node. Owns a
//! `GcEngine` internally and drives it at the start of every pass — GC's
//! mark-and-sweep is the analysis step feeding this daemon, not a fourth
//! independent one (see gc.rs's module doc comment).

use crate::gc::GcEngine;
use crate::segment::{ScanEnd, self, SegmentReader, SegmentWriter};
use crate::vdevs::VdevSet;
use crate::{StreamKind, Vdev, stripe};
use crate::dag_walk::LiveSet;
use lchfs_format::{ExtentLocation, Hash32};
use lchfs_index::{ChunkLocationCache, IndexStore, PendingDedupPins, RedbIndex};
use parking_lot::RwLock;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn to_io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub struct CoalesceDaemon {
    /// The pool's device set. Each pass repacks every device that is
    /// online *when the pass starts*, each on its own: coalescing rewrites
    /// extents into new segments *on one device*, so the relocations it
    /// records belong to that vdev's replica set and no other
    /// (ARCHITECTURE.md §15.7: mark is pool-global, sweep is per-vdev).
    /// Forcing the devices into lockstep would need distributed
    /// coordination for no correctness gain -- per-vdev locations already
    /// make divergence the represented normal case.
    vdevs: Arc<VdevSet>,
    /// Marks on the primary. One walk serves every target, because the DAG
    /// is content-addressed and identical on every device.
    gc: GcEngine,
}

impl CoalesceDaemon {
    /// `targets` is a fixed online set, ascending by id, whose first entry
    /// is the primary -- for tests and tooling that drive the daemon
    /// directly. A mounted pool uses `new_on` with its live set.
    pub fn new(targets: Vec<Vdev>, locations: Arc<ChunkLocationCache>, pins: Arc<PendingDedupPins>) -> Self {
        Self::new_on(Arc::new(VdevSet::from_vdevs(targets)), locations, pins)
    }

    pub fn new_on(vdevs: Arc<VdevSet>, locations: Arc<ChunkLocationCache>, pins: Arc<PendingDedupPins>) -> Self {
        let gc = GcEngine::new_on(Arc::clone(&vdevs), locations, pins);
        Self { vdevs, gc }
    }

    fn primary_id(&self) -> u16 {
        self.gc.primary_id()
    }

    /// One idle-cycle pass: mark, find segments below the liveness
    /// threshold, copy forward only live extents into a fresh segment,
    /// durably update the Chunk Location Index, then delete the old
    /// segment (ARCHITECTURE.md §6). `persisted_index`/`next_segment_id`
    /// are taken as parameters rather than owned fields: they're
    /// `Pool`-wide shared state this daemon needs momentary access to,
    /// not state that belongs to it.
    ///
    /// `generation_at_mark`/`published_generation` close the residual gap
    /// `PendingDedupPins` alone can't (see `repack_segment`'s doc comment
    /// on the final generation check): they let a repack notice that a
    /// checkpoint published a new root *during* this pass, which can mean
    /// this pass's `live` bitmap is stale in a way no longer covered by any
    /// pin (the pin could have been taken *and released* entirely within
    /// this pass's run). Plain shared counters, not a `Namespace` handle,
    /// to keep this module decoupled from `Namespace` (ARCHITECTURE.md §5a
    /// et al -- this daemon has never reached into `Namespace` directly).
    pub fn run_pass(
        &mut self,
        live_roots: &[Hash32],
        generation_at_mark: u64,
        published_generation: &AtomicU64,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
    ) -> io::Result<()> {
        self.run_pass_with(
            live_roots,
            generation_at_mark,
            published_generation,
            persisted_index,
            next_segment_id,
            StripePolicy::default(),
        )
    }

    /// `run_pass`, with the pool's erasure-coding policy (ARCHITECTURE.md
    /// §17.2). After the sweep: striped segments that have gone mostly
    /// dead are repacked back into fresh mirrored segments, and cold,
    /// mostly-live mirrored segments are converted into stripes.
    pub fn run_pass_with(
        &mut self,
        live_roots: &[Hash32],
        generation_at_mark: u64,
        published_generation: &AtomicU64,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
        policy: StripePolicy,
    ) -> io::Result<()> {
        let live = self.gc.mark(live_roots);
        if live.is_empty() {
            // mark() returns empty both on genuine failure (logged inside
            // gc.rs) and -- vanishingly unlikely, but structurally
            // possible on a freshly created empty pool before its first
            // checkpoint -- truly nothing reachable yet. Either way,
            // nothing safe to do this pass.
            return Ok(());
        }

        let targets = self.vdevs.online();
        for vdev in &targets {
            // The primary's bitmaps come straight out of mark; any other
            // device's are the same hashes at that device's own offsets.
            let bitmaps = if vdev.id == self.primary_id() {
                live.by_segment.clone()
            } else {
                live.resolve_on(vdev.id, persisted_index).map_err(to_io_err)?
            };
            for segment_id in self.gc.sweep_candidates_on(&vdev.root, &bitmaps) {
                self.repack_segment(
                    vdev,
                    segment_id,
                    &bitmaps,
                    generation_at_mark,
                    published_generation,
                    persisted_index,
                    next_segment_id,
                )?;
            }
        }

        if policy.enabled() {
            self.repack_dead_stripes(
                &live,
                generation_at_mark,
                published_generation,
                persisted_index,
                next_segment_id,
                &policy,
            )?;
            self.stripe_cold_segments(&live, persisted_index, &policy)?;
        }
        Ok(())
    }

    /// Converts cold, mostly-live mirrored data segments into stripes
    /// (§17.2.4 "conversion pass"). Bounded in bytes per pass so it never
    /// starves the sweep. A segment is read from the primary and every record
    /// verified before anything is written; a segment with a bad record
    /// is left for read failover and scrub to sort out first.
    fn stripe_cold_segments(
        &mut self,
        live: &LiveSet,
        persisted_index: &RwLock<RedbIndex>,
        policy: &StripePolicy,
    ) -> io::Result<()> {
        let online = self.vdevs.online();
        let (k, m) = (policy.k, policy.m);
        let width = k as usize + m as usize;
        if online.len() < width {
            return Ok(());
        }
        let primary_id = self.primary_id();
        let Some(primary) = online.iter().find(|v| v.id == primary_id).cloned() else {
            return Ok(());
        };
        let mut budget = policy.bytes_per_pass;
        for segment_id in GcEngine::aged_sealed_segments(&primary.root, policy.min_age_segments as usize) {
            if budget == 0 {
                break;
            }
            if !stripe::shards_on(&primary.root, segment_id).is_empty() {
                continue;
            }
            let path = segment::segment_path(&primary.root, segment_id, StreamKind::Data);
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            let total = meta.len().saturating_sub(segment::SEGMENT_HEADER_PAGE_SIZE);
            if total == 0 {
                continue;
            }
            let live_bytes = live.by_segment.get(&segment_id).map(|b| b.len()).unwrap_or(0);
            if (live_bytes as f64 / total as f64) < policy.min_live_fraction {
                continue;
            }
            budget = budget.saturating_sub(total);

            // Read and verify every record from the primary's copy. The
            // scan resyncs past damage and would happily hand over only
            // the records it could parse; a segment whose primary copy
            // is rotted anywhere, or has no footer, is not converted --
            // the stripe would be built from the rot and the good
            // mirrors deleted. Read failover and scrub sort it out first.
            let reader = SegmentReader::open(&primary.root, segment_id, StreamKind::Data)?;
            let mut records = Vec::new();
            let mut clean = true;
            let mut scan = reader.scan();
            for (header, offset) in &mut scan {
                let loc = ExtentLocation {
                    segment_id,
                    offset,
                    len: header.record_len,
                };
                if reader.read_record(loc).is_err() {
                    clean = false;
                    break;
                }
                records.push((header.content_hash, loc));
            }
            if !clean || !scan.damaged.is_empty() || scan.end != Some(ScanEnd::Footer) || records.is_empty() {
                tracing::warn!("stripe: segment {segment_id}'s primary copy does not verify end to end; not converting it");
                continue;
            }
            let mut body = std::fs::read(&path)?;
            body.drain(..segment::SEGMENT_HEADER_PAGE_SIZE as usize);
            // A sealed segment ends in its footer, which is not part of any
            // record; the stripe keeps the whole body as written so record
            // offsets are unchanged.
            let devices: Vec<Vdev> = online.iter().take(width).cloned().collect();
            stripe::write_stripe(&body, segment_id, k, m, &devices)?;

            // Index first, then the cache, then the mirrors go: a crash
            // before the index write leaves orphan shard files (cleaned
            // up by a later pass); after it, the mirrors are spare copies
            // until deleted.
            let forget: Vec<u16> = online.iter().map(|v| v.id).collect();
            persisted_index
                .write()
                .restripe_segment(segment_id, &records, &forget)
                .map_err(to_io_err)?;
            for (hash, loc) in &records {
                self.gc_locations().put_striped(*hash, *loc);
            }
            for vdev in &online {
                let mirror = segment::segment_path(&vdev.root, segment_id, StreamKind::Data);
                if mirror.exists() {
                    let _ = segment::mark_coalesced(&vdev.root, segment_id, StreamKind::Data);
                    std::fs::remove_file(&mirror)?;
                }
            }
            tracing::info!(
                "stripe: segment {segment_id} ({} records, {} bytes) converted to {k}+{m} shards",
                records.len(),
                body.len()
            );
        }
        Ok(())
    }

    /// Striped segments whose live fraction has dropped below the sweep
    /// threshold are repacked into a fresh *mirrored* segment on the
    /// online set -- decode, append the live records, repoint the index,
    /// delete the shards. Never rewritten in place; the segment becomes
    /// cold again and may be striped later.
    fn repack_dead_stripes(
        &mut self,
        live: &LiveSet,
        generation_at_mark: u64,
        published_generation: &AtomicU64,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
        policy: &StripePolicy,
    ) -> io::Result<()> {
        let online = self.vdevs.online();
        let striped_live = live.resolve_on(stripe::STRIPED, persisted_index).map_err(to_io_err)?;
        let mut budget = policy.bytes_per_pass;
        for segment_id in stripe::striped_segment_ids(&online) {
            if budget == 0 {
                break;
            }
            let root_of = |id: u16| self.vdevs.root_of(id);
            let Ok(reader) = stripe::StripeReader::open(segment_id, root_of, &online) else { continue };
            let total = reader.desc.logical_len;
            let live_bytes = striped_live.get(&segment_id).map(|b| b.len()).unwrap_or(0);
            if total == 0 || (live_bytes as f64 / total as f64) >= self.gc.liveness_threshold() {
                continue;
            }
            let empty = RoaringBitmap::new();
            let live_bitmap = striped_live.get(&segment_id).unwrap_or(&empty);
            budget = budget.saturating_sub(total);
            let gate = Some((generation_at_mark, published_generation));
            if let Err(e) = self.unstripe(&reader, Some(live_bitmap), gate, persisted_index, next_segment_id) {
                tracing::warn!("stripe: segment {segment_id} cannot be repacked ({e})");
            }
        }
        Ok(())
    }

    /// Every striped segment whose descriptor names `vdev_id` is decoded
    /// back into a mirrored segment on the online set, keeping every
    /// record (there is no mark to say which are dead; the sweep finds
    /// out later). What detach needs before a device that holds shards
    /// can leave (§17.2.4): a stripe's device list is written once and
    /// never edited, so a shard cannot simply move to a survivor. Returns
    /// the segments repacked; fails on the first stripe that is short of
    /// `k` readable shards, with nothing half done.
    pub fn unstripe_segments_naming(
        &mut self,
        vdev_id: u16,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
    ) -> io::Result<Vec<u64>> {
        let online = self.vdevs.online();
        let mut repacked = Vec::new();
        for segment_id in stripe::striped_segment_ids(&online) {
            let root_of = |id: u16| self.vdevs.root_of(id);
            let reader = stripe::StripeReader::open(segment_id, root_of, &online)?;
            if !reader.desc.devices.contains(&vdev_id) {
                continue;
            }
            self.unstripe(&reader, None, None, persisted_index, next_segment_id)?;
            repacked.push(segment_id);
        }
        Ok(repacked)
    }

    /// Decodes one stripe into a fresh mirrored segment on the online
    /// set and deletes the shards. With `live` given, only the records it
    /// marks (or pinned ones) are kept; without it, every record is.
    /// The body is read through `verified_body`, so a shard that is
    /// present but wrong is reconstructed rather than copied forward --
    /// and a stripe that cannot be made to hash right is left as it is.
    /// Index first, then the cache, then the shards go -- a crash before
    /// the index write leaves the new segment an orphan the sweep
    /// collects; after it, the shards are spare until deleted.
    ///
    /// `gate` is the same freshness check `repack_segment` makes: a
    /// checkpoint published during the pass can mean `live` is stale in
    /// a way no pin covers, and this drops records that are not in it,
    /// so it is checked before the index is touched. On a miss the new
    /// segment is removed again and nothing else changes.
    fn unstripe(
        &mut self,
        reader: &stripe::StripeReader,
        live: Option<&RoaringBitmap>,
        gate: Option<(u64, &AtomicU64)>,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
    ) -> io::Result<Option<u64>> {
        let online = self.vdevs.online();
        let segment_id = reader.segment_id;
        let body = reader.verified_body()?;
        let pins = self.gc.pins();
        let mut keep = Vec::new();
        for (header, offset) in stripe::scan_body(&body) {
            let wanted = match live {
                Some(bitmap) => bitmap.contains(offset) || pins.is_pinned(header.content_hash),
                None => true,
            };
            if wanted {
                let loc = ExtentLocation {
                    segment_id,
                    offset,
                    len: header.record_len,
                };
                let (full, raw) = reader.read_record_raw(loc).map_err(to_io_err)?;
                keep.push((full, raw));
            }
        }
        let new_id = next_segment_id.fetch_add(1, Ordering::Relaxed);
        let mut records = Vec::with_capacity(keep.len());
        let mut written: Vec<u16> = Vec::new();
        if !keep.is_empty() {
            let mut writer = SegmentWriter::create_on(&online, new_id, StreamKind::Data, 0)?;
            for (header, raw) in &keep {
                let new_loc = writer.append(
                    header.kind,
                    header.content_hash,
                    header.codec_id,
                    header.uncompressed_len,
                    raw,
                    header.backpointers.clone(),
                )?;
                records.push((header.content_hash, new_loc));
            }
            written = writer.vdev_ids().to_vec();
            for id in writer.seal()? {
                self.vdevs.fault(id);
            }
        }
        if let Some((at_mark, published)) = gate
            && published.load(Ordering::Acquire) != at_mark
        {
            for vdev in &online {
                let _ = std::fs::remove_file(segment::segment_path(&vdev.root, new_id, StreamKind::Data));
            }
            tracing::info!("stripe: segment {segment_id} not repacked; a checkpoint landed mid-pass");
            return Ok(None);
        }
        persisted_index
            .write()
            .unstripe_segment(segment_id, &records, &written)
            .map_err(to_io_err)?;
        for (hash, loc) in &records {
            self.gc_locations().put(*hash, *loc);
        }
        for vdev in &online {
            for i in stripe::shards_on(&vdev.root, segment_id) {
                std::fs::remove_file(stripe::shard_path(&vdev.root, segment_id, i))?;
            }
        }
        tracing::info!(
            "stripe: segment {segment_id} repacked into mirrored segment {new_id} ({} records kept)",
            keep.len()
        );
        Ok(Some(new_id))
    }

    #[allow(clippy::too_many_arguments)]
    fn repack_segment(
        &mut self,
        vdev: &Vdev,
        old_id: u64,
        live: &HashMap<u64, RoaringBitmap>,
        generation_at_mark: u64,
        published_generation: &AtomicU64,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
    ) -> io::Result<()> {
        let root = vdev.root.as_path();
        let reader = SegmentReader::open(root, old_id, StreamKind::Data)?;
        let old_header = reader.read_header().map_err(to_io_err)?;
        let owner_shard = old_header.owner_shard;

        let empty = RoaringBitmap::new();
        let live_bitmap = live.get(&old_id).unwrap_or(&empty);
        let pins = self.gc.pins();

        // Collect every live record's raw (still-compressed, if
        // applicable) bytes *before* creating anything -- a read failure
        // here aborts cleanly without having allocated a segment_id or
        // touched anything durable. `dropped` remembers just the header
        // (cheap, no payload I/O) for everything the mark-time bitmap
        // didn't cover, for the pin recheck right below.
        let mut live_records = Vec::new();
        let mut dropped = Vec::new();
        for (header, offset) in reader.scan() {
            if live_bitmap.contains(offset) {
                let loc = ExtentLocation {
                    segment_id: old_id,
                    offset,
                    len: header.record_len,
                };
                let (full_header, raw_payload) = reader.read_record_raw(loc).map_err(to_io_err)?;
                live_records.push((full_header, raw_payload));
            } else {
                dropped.push((offset, header));
            }
        }

        // Pull in anything currently pinned among what mark() missed: a
        // dedup-hit write that resolved against this segment's content
        // *after* mark() ran but hasn't been checkpointed yet (see
        // `PendingDedupPins`'s doc comment). Not the final word either --
        // the generation check right before this segment is actually
        // deleted, below, covers what this recheck itself can still miss.
        for &(offset, ref header) in &dropped {
            if pins.is_pinned(header.content_hash) {
                let loc = ExtentLocation {
                    segment_id: old_id,
                    offset,
                    len: header.record_len,
                };
                let (full_header, raw_payload) = reader.read_record_raw(loc).map_err(to_io_err)?;
                live_records.push((full_header, raw_payload));
            }
        }

        if live_records.is_empty() {
            // Fully dead segment: nothing to copy forward, no index
            // update needed -- just tombstone + delete directly, gated on
            // the same freshness check as the normal path below.
            if published_generation.load(Ordering::Acquire) != generation_at_mark {
                return Ok(());
            }
            segment::mark_coalesced(root, old_id, StreamKind::Data)?;
            std::fs::remove_file(segment::segment_path(root, old_id, StreamKind::Data))?;
            return Ok(());
        }

        let new_id = next_segment_id.fetch_add(1, Ordering::Relaxed);
        let mut writer = SegmentWriter::create(&[root], new_id, StreamKind::Data, owner_shard)?;
        let mut relocations = Vec::with_capacity(live_records.len());
        for (header, raw_payload) in &live_records {
            let new_loc = writer.append(
                header.kind,
                header.content_hash,
                header.codec_id,
                header.uncompressed_len,
                raw_payload,
                header.backpointers.clone(),
            )?;
            relocations.push((header.content_hash, new_loc));
        }
        // A repack writes to one device; a failure here is the daemon's
        // to report like any writer's.
        for id in writer.seal()? {
            self.vdevs.fault(id);
        }

        // Durably repoint the index *before* touching the old segment --
        // if we crash after this but before the old segment is deleted,
        // the tombstone step below (or, failing that, a future pass)
        // finishes the cleanup; what matters is the index never points at
        // a segment that's already gone.
        {
            let mut index = persisted_index.write();
            for (hash, loc) in &relocations {
                index.put_chunk_location(*hash, vdev.id, *loc).map_err(to_io_err)?;
            }
            index.flush().map_err(to_io_err)?;
        }
        // The cache holds the primary's locations and nobody else's
        // (§15.1); a relocation on another device is the index's business
        // alone.
        if vdev.id == self.primary_id() {
            for (hash, loc) in &relocations {
                self.gc_locations().put(*hash, *loc);
            }
        }

        // Final freshness gate: if a checkpoint published a new root while
        // this pass was running, this segment's `live` bitmap may now be
        // stale in a way `PendingDedupPins` alone can't cover -- a pin can
        // be taken *and* released (once its write is checkpointed) entirely
        // within one repack's processing window. Bail without touching the
        // old segment; the next pass marks fresh against the new root and
        // repacks it correctly. Whatever was relocated above stays valid
        // regardless -- content genuinely live at mark time stays
        // referenceable forever, a generation bump never un-lives it -- so
        // there's nothing to roll back.
        if published_generation.load(Ordering::Acquire) != generation_at_mark {
            return Ok(());
        }

        segment::mark_coalesced(root, old_id, StreamKind::Data)?;
        std::fs::remove_file(segment::segment_path(root, old_id, StreamKind::Data))?;
        Ok(())
    }

    fn gc_locations(&self) -> &ChunkLocationCache {
        self.gc.locations()
    }
}

/// The pool's erasure-coding policy as the daemon sees it (§17.2.5).
#[derive(Debug, Clone, Copy)]
pub struct StripePolicy {
    pub k: u8,
    pub m: u8,
    /// Sealed segments past the sweep grace window a segment must be
    /// before it counts as cold.
    pub min_age_segments: u32,
    /// Only segments at least this live are worth striping; a mostly-dead
    /// one is repacked first and striped once it is full of live data.
    pub min_live_fraction: f64,
    /// Segment bytes converted (and, separately, repacked) per pass, so
    /// neither starves the sweep. In bytes, not segments: a segment seals
    /// when it goes idle as well as at the cap, so sealed segments are
    /// whatever size a burst of writes left them, and a count would
    /// convert an unpredictable amount per pass.
    pub bytes_per_pass: u64,
}

impl Default for StripePolicy {
    fn default() -> Self {
        Self {
            k: 0,
            m: 0,
            min_age_segments: 8,
            min_live_fraction: 0.9,
            bytes_per_pass: 512 * 1024 * 1024,
        }
    }
}

impl StripePolicy {
    pub fn enabled(&self) -> bool {
        self.k >= 2 && self.m >= 1
    }
}
