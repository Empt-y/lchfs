//! Standalone DAG-reachability walker for GC's mark phase (E.10,
//! ARCHITECTURE.md §6). Separate from `Pool::open`'s own DAG walk: that
//! one materializes live *application state* (inodes/dirs/parents) from
//! the *current* root only, into `Namespace`. This one just needs "which
//! byte ranges, in which segments, are reachable" as per-segment roaring
//! bitmaps, from *arbitrary* roots (including old snapshots) — a
//! different output shape for a different purpose, so it isn't reused
//! directly, though it does reuse the same low-level `get_reader`/
//! `SegmentReader::read_record` primitives.
//!
//! Per ARCHITECTURE.md §6's own wording, this walks `InoMap` *directly*
//! (every entry, once) rather than recursing through `DirectoryObject`
//! entries to discover inodes — `InoMap` is already the flat, complete
//! set of every inode reachable from this root. `DirectoryObject` records
//! still get marked live (an inode's content may point at one), just not
//! used to *discover* further inodes to visit.

use crate::segment::SegmentReader;
use crate::stripe::StripeReader;
use crate::vdevs::VdevSet;
use crate::{PoolError, SegmentReaders, StreamKind, Vdev, get_reader};
use lchfs_format::{ContentRef, ExtentKind, ExtentLocation, Hash32, InoMap, InodeObject, IndirectHashList, RootObject};
use lchfs_index::{ChunkLocationCache, RedbIndex};
use parking_lot::RwLock;
use roaring::RoaringBitmap;
use std::collections::{HashMap, HashSet};

/// What a mark pass found live. Two views of the same set: the primary
/// vdev's byte ranges per segment, which is what sweeping the primary
/// needs and what every existing caller consumed, and the content hashes
/// themselves, which is what sweeping *any other* vdev needs -- its copies
/// sit at its own offsets (ARCHITECTURE.md §15.7: "mark once, sweep N
/// times"). The DAG is content-addressed and identical on every device,
/// so one walk of the primary is enough to know what is live everywhere.
#[derive(Debug, Default)]
pub struct LiveSet {
    pub by_segment: HashMap<u64, RoaringBitmap>,
    pub hashes: HashSet<Hash32>,
}

impl LiveSet {
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Marks `hash`, found at `loc` on the primary, live.
    pub(crate) fn mark(&mut self, hash: Hash32, loc: ExtentLocation) {
        self.hashes.insert(hash);
        mark_location(loc, &mut self.by_segment);
    }

    /// The live byte ranges on `vdev_id`, resolved through that device's
    /// own index entries: one sequential pass over the index, a page at a
    /// time, keeping the entries for `vdev_id` whose hash is live. A hash
    /// with no entry there is simply not on that device (it missed the
    /// write, or has since been reclaimed) and contributes nothing --
    /// there are no bytes to keep.
    pub fn resolve_on(&self, vdev_id: u16, index: &RwLock<RedbIndex>) -> Result<HashMap<u64, RoaringBitmap>, PoolError> {
        let mut out = HashMap::new();
        let mut after: Option<(Hash32, u16)> = None;
        loop {
            let page = index.read().chunk_locations_page(after, crate::INDEX_PAGE)?;
            let Some(&(last_hash, last_vdev, _)) = page.last() else {
                return Ok(out);
            };
            for (hash, v, loc) in &page {
                if *v == vdev_id && self.hashes.contains(hash) {
                    mark_location(*loc, &mut out);
                }
            }
            if page.len() < crate::INDEX_PAGE {
                return Ok(out);
            }
            after = Some((last_hash, last_vdev));
        }
    }
}

/// Marks `loc`'s byte range live in a per-segment bitmap.
pub(crate) fn mark_location(loc: ExtentLocation, live: &mut HashMap<u64, RoaringBitmap>) {
    live.entry(loc.segment_id)
        .or_default()
        .insert_range(loc.offset..(loc.offset + loc.len));
}

/// Resolves `hash` (in `stream`) via `locations`, marks its record's
/// bytes live, and returns its decoded kind + payload bytes for the
/// caller to decode further. Missing/unreadable references are a hard
/// error, deliberately not swallowed: silently treating a reachable-but-
/// unresolvable reference as "not live" could make `sweep_candidates`
/// think bytes that are actually still referenced are safe to reclaim
/// (see `GcEngine::mark`'s doc comment for how the caller handles this).
fn resolve_and_read(
    hash: Hash32,
    stream: StreamKind,
    ctx: &WalkCtx<'_>,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut LiveSet,
) -> Result<(ExtentKind, Vec<u8>), PoolError> {
    let (loc, vdev_id) = locations
        .get_tagged(hash)
        .ok_or_else(|| PoolError::Format(format!("GC mark: {hash:?} not found in index")))?;
    live.mark(hash, loc);
    if vdev_id == crate::stripe::STRIPED {
        // A cold record with no mirror copy: read through its stripe.
        // Its bytes live in shard files that `sweep_candidates` never
        // lists, so the primary bitmap entry `mark` just made is inert;
        // what matters is the hash in the live set.
        let online = ctx.vdevs.online();
        let reader = StripeReader::open(loc.segment_id, |id| ctx.vdevs.root_of(id), &online)?;
        let (header, bytes) = reader.read_record(loc)?;
        return Ok((header.kind, bytes));
    }
    let primary = ctx.primary;
    let reader: &SegmentReader = get_reader(readers, &primary.root, primary.id, loc.segment_id, stream)?;
    let (header, bytes) = reader.read_record(loc)?;
    Ok((header.kind, bytes))
}

/// What a mark walk needs to find bytes: the primary for mirrored
/// records, the device set for striped ones.
pub(crate) struct WalkCtx<'a> {
    pub primary: &'a Vdev,
    pub vdevs: &'a VdevSet,
}

/// Marks `hash`'s own record live and, if it's a `RootObject`, walks
/// everything reachable from it. A bare `SnapshotTable` hash marks only
/// its own record — its entries' roots are separately present in the
/// caller's `live_roots` list (ARCHITECTURE.md §6), so recursing into it
/// here would just be redundant work, not incorrect.
pub(crate) fn walk_reachable(
    hash: Hash32,
    ctx: &WalkCtx<'_>,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut LiveSet,
) -> Result<(), PoolError> {
    let (kind, bytes) = resolve_and_read(hash, StreamKind::Meta, ctx, locations, readers, live)?;
    match kind {
        ExtentKind::RootObject => {
            let root: RootObject =
                lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
            walk_inomap(root.inomap_hash, ctx, locations, readers, live)?;
            // Every RootObject reaches its own SnapshotTable record via
            // this field -- mark it here so it's correctly live whenever
            // *any* retained RootObject is walked, regardless of whether
            // the caller's live_roots also lists snapshot_table_hash
            // separately (ARCHITECTURE.md §6 does list it separately;
            // handling it here too is what makes a bare SnapshotTable
            // hash in live_roots redundant-but-harmless rather than the
            // only path that keeps it live).
            resolve_and_read(
                root.snapshot_table_hash,
                StreamKind::Meta,
                ctx,
                locations,
                readers,
                live,
            )?;
        }
        ExtentKind::SnapshotTable => {}
        other => {
            return Err(PoolError::Format(format!(
                "GC mark: expected a RootObject or SnapshotTable root, got {other:?}"
            )));
        }
    }
    Ok(())
}

fn walk_inomap(
    hash: Hash32,
    ctx: &WalkCtx<'_>,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut LiveSet,
) -> Result<(), PoolError> {
    let (_kind, bytes) = resolve_and_read(hash, StreamKind::Meta, ctx, locations, readers, live)?;
    let ino_map: InoMap =
        lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
    for entry in &ino_map.entries {
        walk_inode(entry.current_object_hash, ctx, locations, readers, live)?;
    }
    Ok(())
}

fn walk_inode(
    hash: Hash32,
    ctx: &WalkCtx<'_>,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut LiveSet,
) -> Result<(), PoolError> {
    let (_kind, bytes) = resolve_and_read(hash, StreamKind::Meta, ctx, locations, readers, live)?;
    let inode: InodeObject =
        lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
    match inode.content {
        ContentRef::DirEntries(dir_hash) => {
            // Marks the DirectoryObject record live; its entries are not
            // used to discover further inodes (InoMap already covers
            // that) -- see this module's doc comment.
            resolve_and_read(dir_hash, StreamKind::Meta, ctx, locations, readers, live)?;
        }
        ContentRef::ChunkList(ihl_hash) => {
            let (_kind, ihl_bytes) =
                resolve_and_read(ihl_hash, StreamKind::Meta, ctx, locations, readers, live)?;
            let ihl: IndirectHashList =
                lchfs_format::decode(&ihl_bytes).map_err(|e| PoolError::Format(e.to_string()))?;
            // A data chunk is a leaf: marking it needs its location, not
            // its bytes. Reading it would make every pass read the whole
            // live dataset, and one rotted chunk on the primary would
            // abort every mark until scrub healed it -- verification is
            // scrub's job, and read failover the reader's.
            for chunk in &ihl.chunks {
                let (loc, _) = locations
                    .get_tagged(chunk.content_hash)
                    .ok_or_else(|| PoolError::Format(format!("GC mark: {:?} not found in index", chunk.content_hash)))?;
                live.mark(chunk.content_hash, loc);
            }
        }
        ContentRef::Inline(_) | ContentRef::SymlinkTarget(_) => {}
    }
    Ok(())
}
