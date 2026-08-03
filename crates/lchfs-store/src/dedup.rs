//! The Dedup Index Scanner. ARCHITECTURE.md §5: idle-cycle, background,
//! *identity convergence only* — catches duplicate content that raced
//! past the inline fast-path check in prep.rs (two logical shards writing
//! identical new content in the same epoch, neither seeing the other's
//! not-yet-indexed write).
//!
//! **Index-only, never a DAG rewrite.** Every DAG reference in the schema
//! is by `content_hash` alone (`ChunkRef.content_hash`,
//! `ContentRef::ChunkList(Hash32)`, `InoMapEntry.current_object_hash`) --
//! never by physical location. So the "loser" copy in a dedup race was
//! never referenced by any `InodeObject`/`IndirectHashList` in the first
//! place: both physical copies satisfy the same `content_hash` equally,
//! and any `ChunkRef` pointing at that hash resolves correctly through
//! *either* copy's bytes. Convergence is therefore purely an index
//! operation: find hashes with >=2 physical locations, pick a
//! deterministic canonical one, repoint the index. No inode-level lock,
//! no dirty-marking, no race with a live writer to reconcile -- there is
//! nothing to reconcile, by construction. (An earlier version of this
//! comment, matching the original stub, said this rewrites
//! InodeObject/IndirectHashList records -- that was wrong; see the plan
//! this phase was built from for the correction.)
//!
//! Never deletes the orphaned duplicate directly (can't -- append-only);
//! once nothing references it, ordinary GC (gc.rs) reclaims it with no
//! special-casing.

use crate::segment::SegmentReader;
use crate::StreamKind;
use lchfs_format::{ExtentLocation, Hash32, SegmentState};
use lchfs_index::{ChunkLocationCache, IndexStore, RedbIndex};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

fn to_io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub struct DedupScanner {
    pool_root: PathBuf,
    locations: Arc<ChunkLocationCache>,
    /// In-memory only, per stream (today only ever `StreamKind::Data` is
    /// scanned -- see `run_pass`). Losing this on restart is fine: the
    /// scan is idempotent and self-correcting, just re-scans from
    /// scratch. Deliberately advances only up to the *first* still-`Open`
    /// segment encountered in ascending id order, never past it: since M
    /// shards each seal their own segments independently, a lower-
    /// numbered segment can still be `Open` while a higher-numbered one
    /// (a different, busier shard) is already sealed -- advancing the
    /// cursor past that gap would permanently skip the lower one once it
    /// does seal.
    scanned_up_to: HashMap<StreamKind, u64>,
}

impl DedupScanner {
    pub fn new(pool_root: PathBuf, locations: Arc<ChunkLocationCache>) -> Self {
        Self {
            pool_root,
            locations,
            scanned_up_to: HashMap::new(),
        }
    }

    /// Scan newly-sealed Data-stream segments for `content_hash`
    /// collisions the inline fast path missed. For each: pick a
    /// deterministic canonical location (lowest `(segment_id, offset)`),
    /// update the index. Scoped to the Data stream: meta-object content
    /// (always tied to a specific inode's own field values) essentially
    /// never collides in practice, unlike bulk chunk data.
    pub fn run_pass(&mut self, persisted_index: &RwLock<RedbIndex>) -> io::Result<Vec<DedupMerge>> {
        let dir = self.pool_root.join("segments").join("data");
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            return Ok(Vec::new());
        };
        let mut segment_ids: Vec<u64> = read_dir
            .flatten()
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        segment_ids.sort_unstable();

        let cursor = self.scanned_up_to.get(&StreamKind::Data).copied().unwrap_or(0);
        let mut seen_this_pass: HashMap<Hash32, Vec<ExtentLocation>> = HashMap::new();
        // The cursor must stop at the *lowest* still-open id (if any), not
        // just "one past whatever sealed id we happened to process last":
        // segment_ids is sorted ascending, but a lower-numbered segment
        // can still be Open while a higher-numbered one (a different,
        // busier shard) is already sealed -- advancing past that gap
        // would permanently skip the lower one once it does seal.
        let mut lowest_still_open: Option<u64> = None;
        let mut highest_sealed_processed = cursor;

        for &id in &segment_ids {
            if id < cursor {
                continue;
            }
            let Ok(reader) = SegmentReader::open(&self.pool_root, id, StreamKind::Data) else {
                continue;
            };
            let Ok(header) = reader.read_header() else {
                continue;
            };

            // Scanned either way: `scan_next` only ever reads records
            // that are already fully, durably written -- an Open segment
            // being actively appended to poses no risk here (appends only
            // ever happen past whatever's already there), unlike
            // Coalesce's repack, which really does need a segment to be
            // done changing first. What differs is whether the cursor
            // advances past it (see scanned_up_to's doc comment): a still-
            // Open segment gets fully rescanned every future pass too,
            // since more records may land in it later.
            let mut offset = crate::segment::SEGMENT_HEADER_PAGE_SIZE as u32;
            while let Some((rec_header, next_offset)) = reader.scan_next(offset) {
                let loc = ExtentLocation {
                    segment_id: id,
                    offset,
                    len: rec_header.record_len,
                };
                seen_this_pass
                    .entry(rec_header.content_hash)
                    .or_default()
                    .push(loc);
                offset = next_offset;
            }

            if header.state == SegmentState::Open {
                lowest_still_open.get_or_insert(id);
            } else {
                highest_sealed_processed = highest_sealed_processed.max(id + 1);
            }
        }
        let next_cursor = lowest_still_open.unwrap_or(highest_sealed_processed);
        self.scanned_up_to.insert(StreamKind::Data, next_cursor);

        let mut merges = Vec::new();
        for (hash, mut locs) in seen_this_pass {
            // Also consider whatever's currently indexed for this hash --
            // catches a collision that spans "already indexed from a
            // previous pass or the inline fast path" vs "newly seen this
            // pass", not just two duplicates both freshly seen together.
            if let Some(existing) = self.locations.get(hash) {
                locs.push(existing);
            }
            locs.sort_by_key(|l| (l.segment_id, l.offset));
            locs.dedup();
            if locs.len() < 2 {
                continue;
            }

            let canonical = locs[0];
            self.locations.put(hash, canonical);
            {
                let mut index = persisted_index.write();
                index
                    .put_chunk_location(hash, canonical)
                    .map_err(to_io_err)?;
            }
            for &loser in &locs[1..] {
                merges.push(DedupMerge {
                    content_hash: hash,
                    canonical,
                    loser,
                });
            }
        }
        Ok(merges)
    }
}

/// One resolved duplicate: `loser` becomes unreferenced (and later
/// GC-reclaimed) once nothing in the index points at it anymore -- which,
/// per this module's doc comment, is immediate: nothing in the DAG ever
/// pointed at it *by location* to begin with.
pub struct DedupMerge {
    pub content_hash: Hash32,
    pub canonical: ExtentLocation,
    pub loser: ExtentLocation,
}
