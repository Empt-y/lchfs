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
use crate::{PoolError, SegmentReaders, StreamKind, get_reader};
use lchfs_format::{ContentRef, ExtentKind, ExtentLocation, Hash32, InoMap, InodeObject, IndirectHashList, RootObject};
use lchfs_index::ChunkLocationCache;
use roaring::RoaringBitmap;
use std::collections::HashMap;
use std::path::Path;

/// Marks `loc`'s byte range live in `live`'s per-segment bitmap. Exposed to
/// `gc.rs` so it can mark a pinned hash's current location live the same
/// way a DAG-reachable one is marked (see `PendingDedupPins`).
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
    pool_root: &Path,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut HashMap<u64, RoaringBitmap>,
) -> Result<(ExtentKind, Vec<u8>), PoolError> {
    let loc = locations
        .get(hash)
        .ok_or_else(|| PoolError::Format(format!("GC mark: {hash:?} not found in index")))?;
    mark_location(loc, live);
    let reader: &SegmentReader = get_reader(readers, pool_root, loc.segment_id, stream)?;
    let (header, bytes) = reader.read_record(loc)?;
    Ok((header.kind, bytes))
}

/// Marks `hash`'s own record live and, if it's a `RootObject`, walks
/// everything reachable from it. A bare `SnapshotTable` hash marks only
/// its own record — its entries' roots are separately present in the
/// caller's `live_roots` list (ARCHITECTURE.md §6), so recursing into it
/// here would just be redundant work, not incorrect.
pub(crate) fn walk_reachable(
    hash: Hash32,
    pool_root: &Path,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut HashMap<u64, RoaringBitmap>,
) -> Result<(), PoolError> {
    let (kind, bytes) = resolve_and_read(hash, StreamKind::Meta, pool_root, locations, readers, live)?;
    match kind {
        ExtentKind::RootObject => {
            let root: RootObject =
                lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
            walk_inomap(root.inomap_hash, pool_root, locations, readers, live)?;
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
                pool_root,
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
    pool_root: &Path,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut HashMap<u64, RoaringBitmap>,
) -> Result<(), PoolError> {
    let (_kind, bytes) = resolve_and_read(hash, StreamKind::Meta, pool_root, locations, readers, live)?;
    let ino_map: InoMap =
        lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
    for entry in &ino_map.entries {
        walk_inode(entry.current_object_hash, pool_root, locations, readers, live)?;
    }
    Ok(())
}

fn walk_inode(
    hash: Hash32,
    pool_root: &Path,
    locations: &ChunkLocationCache,
    readers: &mut SegmentReaders,
    live: &mut HashMap<u64, RoaringBitmap>,
) -> Result<(), PoolError> {
    let (_kind, bytes) = resolve_and_read(hash, StreamKind::Meta, pool_root, locations, readers, live)?;
    let inode: InodeObject =
        lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
    match inode.content {
        ContentRef::DirEntries(dir_hash) => {
            // Marks the DirectoryObject record live; its entries are not
            // used to discover further inodes (InoMap already covers
            // that) -- see this module's doc comment.
            resolve_and_read(dir_hash, StreamKind::Meta, pool_root, locations, readers, live)?;
        }
        ContentRef::ChunkList(ihl_hash) => {
            let (_kind, ihl_bytes) =
                resolve_and_read(ihl_hash, StreamKind::Meta, pool_root, locations, readers, live)?;
            let ihl: IndirectHashList =
                lchfs_format::decode(&ihl_bytes).map_err(|e| PoolError::Format(e.to_string()))?;
            for chunk in &ihl.chunks {
                resolve_and_read(chunk.content_hash, StreamKind::Data, pool_root, locations, readers, live)?;
            }
        }
        ContentRef::Inline(_) | ContentRef::SymlinkTarget(_) => {}
    }
    Ok(())
}
