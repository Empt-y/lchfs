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
use crate::segment::{self, SegmentReader, SegmentWriter};
use crate::StreamKind;
use lchfs_format::{ExtentLocation, Hash32};
use lchfs_index::{ChunkLocationCache, IndexStore, PendingDedupPins, RedbIndex};
use parking_lot::RwLock;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn to_io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub struct CoalesceDaemon {
    pool_root: PathBuf,
    gc: GcEngine,
}

impl CoalesceDaemon {
    pub fn new(pool_root: PathBuf, locations: Arc<ChunkLocationCache>, pins: Arc<PendingDedupPins>) -> Self {
        let gc = GcEngine::new(pool_root.clone(), locations, pins);
        Self { pool_root, gc }
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
        let live = self.gc.mark(live_roots);
        if live.is_empty() {
            // mark() returns empty both on genuine failure (logged inside
            // gc.rs) and -- vanishingly unlikely, but structurally
            // possible on a freshly created empty pool before its first
            // checkpoint -- truly nothing reachable yet. Either way,
            // nothing safe to do this pass.
            return Ok(());
        }

        for segment_id in self.gc.sweep_candidates(&live) {
            self.repack_segment(
                segment_id,
                &live,
                generation_at_mark,
                published_generation,
                persisted_index,
                next_segment_id,
            )?;
        }
        Ok(())
    }

    fn repack_segment(
        &mut self,
        old_id: u64,
        live: &HashMap<u64, RoaringBitmap>,
        generation_at_mark: u64,
        published_generation: &AtomicU64,
        persisted_index: &RwLock<RedbIndex>,
        next_segment_id: &AtomicU64,
    ) -> io::Result<()> {
        let reader = SegmentReader::open(&self.pool_root, old_id, StreamKind::Data)?;
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
        let mut offset = segment::SEGMENT_HEADER_PAGE_SIZE as u32;
        while let Some((header, next_offset)) = reader.scan_next(offset) {
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
            offset = next_offset;
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
            segment::mark_coalesced(&self.pool_root, old_id, StreamKind::Data)?;
            std::fs::remove_file(segment::segment_path(&self.pool_root, old_id, StreamKind::Data))?;
            return Ok(());
        }

        let new_id = next_segment_id.fetch_add(1, Ordering::Relaxed);
        let mut writer = SegmentWriter::create(&self.pool_root, new_id, StreamKind::Data, owner_shard)?;
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
        writer.seal()?;

        // Durably repoint the index *before* touching the old segment --
        // if we crash after this but before the old segment is deleted,
        // the tombstone step below (or, failing that, a future pass)
        // finishes the cleanup; what matters is the index never points at
        // a segment that's already gone.
        {
            let mut index = persisted_index.write();
            for (hash, loc) in &relocations {
                index.put_chunk_location(*hash, *loc).map_err(to_io_err)?;
            }
            index.flush().map_err(to_io_err)?;
        }
        for (hash, loc) in &relocations {
            self.gc_locations().put(*hash, *loc);
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

        segment::mark_coalesced(&self.pool_root, old_id, StreamKind::Data)?;
        std::fs::remove_file(segment::segment_path(&self.pool_root, old_id, StreamKind::Data))?;
        Ok(())
    }

    fn gc_locations(&self) -> &ChunkLocationCache {
        self.gc.locations()
    }
}
