//! DAG-walk verification. ARCHITECTURE.md §10 ("fsck tool"): walks the
//! full DAG from every live root; verifies content_hash, structural
//! well-formedness (sorted/no-dup dir entries, size == sum of chunk
//! lengths), InoMap referential integrity. `--verify-index` cross-checks
//! `INDEX.redb` against a fresh walk; `--rebuild-index` regenerates it.
//!
//! Deliberately independent of `lchfs-store`'s own internal scan/recovery
//! code (`Pool::open`'s cold-rebuild path, `dag_walk.rs`) even though the
//! logic is conceptually similar -- a real fsck tool that shared code
//! with the driver it's meant to audit couldn't catch a bug *in* that
//! code. Everything this crate reads (segment file layout, the superblock
//! ring's on-disk encoding) is the documented on-disk format from
//! ARCHITECTURE.md §1, reconstructed here from lchfs-store's genuinely
//! public API (`segment::SegmentReader`, `backend::FileBackend`) rather
//! than any `pub(crate)`-only helper.

use lchfs_format::{
    ChunkRef, ContentRef, DirectoryObject, ExtentLocation, Hash32, InoMap, InodeKind,
    InodeObject, IndirectHashList, RootObject, SnapshotTable, StreamKind, SUPERBLOCK_MAGIC,
    SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE, SuperblockSlot, compute_superblock_slot_checksum,
};
use lchfs_index::{IndexStore, RedbIndex};
use lchfs_store::backend::{FileBackend, StorageBackend};
use lchfs_store::segment::{SegmentError, SegmentReader};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsckError {
    #[error("content hash mismatch at {location}")]
    ContentHashMismatch { location: String },
    #[error("directory entries not sorted or contain duplicates: {dir_ino}")]
    UnsortedOrDuplicateDirEntries { dir_ino: u64 },
    #[error("size mismatch for ino {ino}: InodeObject says {declared}, chunks sum to {actual}")]
    SizeMismatch { ino: u64, declared: u64, actual: u64 },
    #[error("dangling ino {ino} referenced by directory entry but missing from InoMap")]
    DanglingIno { ino: u64 },
    #[error("index entry for {hash:?} disagrees with fresh DAG walk")]
    IndexMismatch { hash: Hash32 },
    #[error("InoMap entries not sorted by ino, or contain a duplicate ino")]
    UnsortedOrDuplicateInoMap,
    #[error("chunk list for ino {ino} not sorted by logical_offset, or has overlapping ranges")]
    UnsortedOrOverlappingChunkList { ino: u64 },
    #[error(
        "directory entry for ino {ino} claims kind {dir_kind:?}, but its own InodeObject says {actual_kind:?}"
    )]
    KindMismatch { ino: u64, dir_kind: InodeKind, actual_kind: InodeKind },
    #[error("hash {hash:?} referenced but not found in any segment")]
    MissingObject { hash: Hash32 },
    #[error("object {hash:?} unreadable: {detail}")]
    UnreadableObject { hash: Hash32, detail: String },
    #[error("no valid superblock slot found at {0}")]
    NoValidSuperblock(String),
    #[error(
        "pool was written with on-disk format version {found}, but this build only supports up to {supported} -- upgrade lchfs to check it"
    )]
    UnsupportedFormatVersion { found: u32, supported: u32 },
    #[error("I/O error: {0}")]
    Io(String),
}

/// Aggregated results of a full fsck run.
#[derive(Debug, Default)]
pub struct FsckReport {
    pub errors: Vec<FsckError>,
    pub objects_visited: u64,
}

impl FsckReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Scans every segment file under `pool_root` and builds a fresh
/// `content_hash -> location` map, independent of `INDEX.redb` (the whole
/// point of `verify_index`/`rebuild_index` is to never blindly trust the
/// thing being verified or rebuilt). Mirrors ARCHITECTURE.md §1's
/// documented layout directly: `segments/data/*.aseg`,
/// `segments/meta/*.mseg`.
pub fn scan_all_segments(pool_root: &Path) -> Result<HashMap<Hash32, ExtentLocation>, FsckError> {
    let mut locations = HashMap::new();
    for (sub, kind) in [("data", StreamKind::Data), ("meta", StreamKind::Meta)] {
        let dir = pool_root.join("segments").join(sub);
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut ids: Vec<u64> = read_dir
            .flatten()
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .collect();
        ids.sort_unstable();
        for segment_id in ids {
            let reader = SegmentReader::open(pool_root, segment_id, kind)
                .map_err(|e| FsckError::Io(format!("opening segment {segment_id}: {e}")))?;
            let mut offset = lchfs_store::segment::SEGMENT_HEADER_PAGE_SIZE as u32;
            while let Some((header, next_offset)) = reader.scan_next(offset) {
                locations.insert(
                    header.content_hash,
                    ExtentLocation { segment_id, offset, len: header.record_len },
                );
                offset = next_offset;
            }
        }
    }
    Ok(locations)
}

/// Independently reads and validates the global superblock ring (same
/// on-disk encoding `Pool::open` uses, reconstructed here rather than
/// shared with it -- see this module's doc comment): every slot's magic,
/// header checksum, then the highest-generation CRC-valid slot wins.
pub fn read_superblock(pool_root: &Path) -> Result<SuperblockSlot, FsckError> {
    let backend = FileBackend::open(pool_root)
        .map_err(|e| FsckError::Io(format!("opening superblock: {e}")))?;
    let mut best: Option<SuperblockSlot> = None;
    for slot_idx in 0..SUPERBLOCK_SLOT_COUNT {
        let bytes = backend
            .read_at(slot_idx as u64 * SUPERBLOCK_SLOT_SIZE as u64, SUPERBLOCK_SLOT_SIZE as u32)
            .map_err(|e| FsckError::Io(format!("reading superblock slot {slot_idx}: {e}")))?;
        if bytes.len() < 4 {
            continue;
        }
        let encoded_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if encoded_len == 0 || 4 + encoded_len > bytes.len() {
            continue;
        }
        let Ok(slot) = lchfs_format::decode::<SuperblockSlot>(&bytes[4..4 + encoded_len]) else {
            continue;
        };
        if slot.magic != SUPERBLOCK_MAGIC {
            continue;
        }
        if compute_superblock_slot_checksum(&slot) != slot.header_checksum {
            continue;
        }
        // Mirrors lchfs-store's own read_superblock: only trust the version
        // once magic and CRC vouch for the slot, then fail hard rather than
        // skipping to an older slot and diagnosing a stale epoch as if it
        // were current.
        if slot.format_version > lchfs_format::FORMAT_VERSION {
            return Err(FsckError::UnsupportedFormatVersion {
                found: slot.format_version,
                supported: lchfs_format::FORMAT_VERSION,
            });
        }
        if best.as_ref().is_none_or(|b| slot.generation > b.generation) {
            best = Some(slot);
        }
    }
    best.ok_or_else(|| FsckError::NoValidSuperblock(pool_root.display().to_string()))
}

/// Every currently-live root: the current superblock's root, plus every
/// retained snapshot's root (ARCHITECTURE.md §6/§10: "every live root
/// (current + every retained snapshot)"). The convenience entry point
/// `check`/`verify_index`'s callers (the CLI) are expected to use, rather
/// than each re-deriving this walk themselves.
pub fn collect_live_roots(pool_root: &Path) -> Result<Vec<Hash32>, FsckError> {
    let slot = read_superblock(pool_root)?;
    let mut roots = vec![slot.root_hash];

    let reader = SegmentReader::open(pool_root, slot.root_location.segment_id, StreamKind::Meta)
        .map_err(|e| FsckError::Io(format!("opening root object segment: {e}")))?;
    let (_header, bytes) = reader
        .read_record(slot.root_location)
        .map_err(|e| FsckError::Io(format!("reading root object: {e}")))?;
    let root: RootObject = lchfs_format::decode(&bytes)
        .map_err(|e| FsckError::Io(format!("decoding root object: {e}")))?;

    let locations = scan_all_segments(pool_root)?;
    if let Some(&loc) = locations.get(&root.snapshot_table_hash) {
        let reader = SegmentReader::open(pool_root, loc.segment_id, StreamKind::Meta)
            .map_err(|e| FsckError::Io(format!("opening snapshot table segment: {e}")))?;
        if let Ok((_header, bytes)) = reader.read_record(loc)
            && let Ok(table) = lchfs_format::decode::<SnapshotTable>(&bytes)
        {
            roots.extend(table.entries.iter().map(|e| e.root_hash));
        }
    }
    Ok(roots)
}

/// Walks the DAG from a set of live roots, resolving every reference
/// against a pre-scanned `hash -> location` map (see `scan_all_segments`)
/// and recording every structural/integrity problem it finds rather than
/// stopping at the first one -- an fsck tool's job is to report the full
/// extent of the damage, not just confirm there's some.
struct Walker {
    pool_root: PathBuf,
    locations: HashMap<Hash32, ExtentLocation>,
    readers: HashMap<(u64, StreamKind), SegmentReader>,
    /// Every hash successfully read+verified during the walk, alongside
    /// the location it was actually found at -- `verify_index` cross-
    /// checks exactly this set against `INDEX.redb`.
    visited: HashMap<Hash32, ExtentLocation>,
    report: FsckReport,
}

impl Walker {
    fn new(pool_root: PathBuf, locations: HashMap<Hash32, ExtentLocation>) -> Self {
        Self {
            pool_root,
            locations,
            readers: HashMap::new(),
            visited: HashMap::new(),
            report: FsckReport::default(),
        }
    }

    fn reader(&mut self, segment_id: u64, stream: StreamKind) -> Result<&SegmentReader, SegmentError> {
        if let std::collections::hash_map::Entry::Vacant(e) = self.readers.entry((segment_id, stream)) {
            e.insert(SegmentReader::open(&self.pool_root, segment_id, stream)?);
        }
        Ok(self.readers.get(&(segment_id, stream)).unwrap())
    }

    /// Resolves, reads, and content-hash-verifies `hash` (via
    /// `SegmentReader::read_record`, which performs ARCHITECTURE.md §1's
    /// full mandatory check sequence), recording every failure mode as a
    /// distinct `FsckError` rather than a generic one. Returns the
    /// decompressed, verified payload bytes on success.
    fn read_verified(&mut self, hash: Hash32, stream: StreamKind) -> Option<Vec<u8>> {
        let Some(&loc) = self.locations.get(&hash) else {
            self.report.errors.push(FsckError::MissingObject { hash });
            return None;
        };
        let reader = match self.reader(loc.segment_id, stream) {
            Ok(r) => r,
            Err(e) => {
                self.report
                    .errors
                    .push(FsckError::UnreadableObject { hash, detail: e.to_string() });
                return None;
            }
        };
        match reader.read_record(loc) {
            Ok((_header, bytes)) => {
                self.report.objects_visited += 1;
                self.visited.insert(hash, loc);
                Some(bytes)
            }
            Err(SegmentError::ContentHash { segment_id, offset, .. }) => {
                self.report.errors.push(FsckError::ContentHashMismatch {
                    location: format!("segment {segment_id} offset {offset} ({stream:?} stream)"),
                });
                None
            }
            Err(e) => {
                self.report
                    .errors
                    .push(FsckError::UnreadableObject { hash, detail: e.to_string() });
                None
            }
        }
    }

    fn resolve<T: DeserializeOwned>(&mut self, hash: Hash32, stream: StreamKind) -> Option<T> {
        let bytes = self.read_verified(hash, stream)?;
        match lchfs_format::decode(&bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                self.report
                    .errors
                    .push(FsckError::UnreadableObject { hash, detail: e.to_string() });
                None
            }
        }
    }

    fn walk_root(&mut self, root_hash: Hash32) {
        let Some(root) = self.resolve::<RootObject>(root_hash, StreamKind::Meta) else {
            return;
        };
        // Just verify the SnapshotTable record itself is present and
        // decodes -- not a recursive walk into its entries' own roots,
        // which the caller is expected to already have included in
        // `live_roots` (matching lchfs-store's `dag_walk.rs` convention:
        // a bare SnapshotTable hash marks only its own record).
        let _: Option<SnapshotTable> = self.resolve(root.snapshot_table_hash, StreamKind::Meta);
        self.walk_inomap(root.inomap_hash);
    }

    fn walk_inomap(&mut self, inomap_hash: Hash32) {
        let Some(ino_map) = self.resolve::<InoMap>(inomap_hash, StreamKind::Meta) else {
            return;
        };
        if !ino_map.entries.windows(2).all(|w| w[0].ino < w[1].ino) {
            self.report.errors.push(FsckError::UnsortedOrDuplicateInoMap);
        }

        // Resolve every InodeObject once, up front -- both to avoid
        // reading each twice (once for a `dirs`-cross-check pass, once to
        // walk its own content) and because directory entries need to
        // cross-check *other* inodes' kinds, which requires the whole set
        // resolved before any single one can be checked.
        let mut inodes: HashMap<u64, InodeObject> = HashMap::new();
        for entry in &ino_map.entries {
            if let Some(inode) = self.resolve::<InodeObject>(entry.current_object_hash, StreamKind::Meta) {
                inodes.insert(entry.ino, inode);
            }
        }

        let inos: Vec<u64> = inodes.keys().copied().collect();
        for ino in inos {
            let inode = inodes.get(&ino).unwrap().clone();
            self.check_inode_content(ino, &inode, &inodes);
        }
    }

    fn check_inode_content(&mut self, ino: u64, inode: &InodeObject, inodes: &HashMap<u64, InodeObject>) {
        match &inode.content {
            ContentRef::Inline(bytes) => {
                if bytes.len() as u64 != inode.size {
                    self.report.errors.push(FsckError::SizeMismatch {
                        ino,
                        declared: inode.size,
                        actual: bytes.len() as u64,
                    });
                }
            }
            ContentRef::SymlinkTarget(target) => {
                if target.len() as u64 != inode.size {
                    self.report.errors.push(FsckError::SizeMismatch {
                        ino,
                        declared: inode.size,
                        actual: target.len() as u64,
                    });
                }
            }
            ContentRef::ChunkList(hash) => {
                let Some(ihl) = self.resolve::<IndirectHashList>(*hash, StreamKind::Meta) else {
                    return;
                };
                let sorted_no_overlap = ihl
                    .chunks
                    .windows(2)
                    .all(|w| w[0].logical_offset + w[0].len as u64 <= w[1].logical_offset);
                if !sorted_no_overlap {
                    self.report
                        .errors
                        .push(FsckError::UnsortedOrOverlappingChunkList { ino });
                }
                let actual: u64 = ihl.chunks.iter().map(|c: &ChunkRef| c.len as u64).sum();
                if actual != inode.size {
                    self.report.errors.push(FsckError::SizeMismatch { ino, declared: inode.size, actual });
                }
                for chunk in &ihl.chunks {
                    self.read_verified(chunk.content_hash, StreamKind::Data);
                }
            }
            ContentRef::DirEntries(hash) => {
                let Some(dir) = self.resolve::<DirectoryObject>(*hash, StreamKind::Meta) else {
                    return;
                };
                let sorted_no_dup = dir.entries.windows(2).all(|w| w[0].name < w[1].name);
                if !sorted_no_dup {
                    self.report
                        .errors
                        .push(FsckError::UnsortedOrDuplicateDirEntries { dir_ino: ino });
                }
                for entry in &dir.entries {
                    match inodes.get(&entry.ino) {
                        None => self.report.errors.push(FsckError::DanglingIno { ino: entry.ino }),
                        Some(child) if child.kind != entry.kind => {
                            self.report.errors.push(FsckError::KindMismatch {
                                ino: entry.ino,
                                dir_kind: entry.kind,
                                actual_kind: child.kind,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Walk the full DAG from every live root (current + every retained
/// snapshot) and verify content hashes and structural well-formedness.
/// ARCHITECTURE.md §10.
pub fn check(pool_root: &Path, live_roots: &[Hash32]) -> FsckReport {
    let locations = match scan_all_segments(pool_root) {
        Ok(m) => m,
        Err(e) => {
            let mut report = FsckReport::default();
            report.errors.push(e);
            return report;
        }
    };
    let mut walker = Walker::new(pool_root.to_path_buf(), locations);
    for &root in live_roots {
        walker.walk_root(root);
    }
    walker.report
}

/// Cross-check `INDEX.redb` against a fresh DAG walk without rebuilding
/// it: every hash the walk actually visits must be present in the index
/// and agree on location. Structural/content-hash problems the walk
/// itself finds are reported the same as `check`.
pub fn verify_index(pool_root: &Path, live_roots: &[Hash32]) -> FsckReport {
    let locations = match scan_all_segments(pool_root) {
        Ok(m) => m,
        Err(e) => {
            let mut report = FsckReport::default();
            report.errors.push(e);
            return report;
        }
    };
    let index = match RedbIndex::open(&pool_root.join("INDEX.redb")) {
        Ok(idx) => idx,
        Err(e) => {
            let mut report = FsckReport::default();
            report.errors.push(FsckError::Io(format!("opening INDEX.redb: {e}")));
            return report;
        }
    };

    let mut walker = Walker::new(pool_root.to_path_buf(), locations);
    for &root in live_roots {
        walker.walk_root(root);
    }

    for (&hash, &fresh_loc) in &walker.visited {
        match index.get_chunk_location(hash) {
            Ok(Some(indexed_loc)) if indexed_loc == fresh_loc => {}
            Ok(_) => walker.report.errors.push(FsckError::IndexMismatch { hash }),
            Err(_) => walker.report.errors.push(FsckError::IndexMismatch { hash }),
        }
    }

    walker.report
}

/// Regenerate the persisted index from scratch via a full segment scan
/// (ARCHITECTURE.md §4: the index is a rebuildable cache, never
/// authoritative -- this is the explicit full-rebuild path). Checkpoints
/// at the current superblock's generation so the next `Pool::open` can
/// take the fast (index-trusting) mount path.
pub fn rebuild_index(pool_root: &Path) -> Result<(), FsckError> {
    let locations = scan_all_segments(pool_root)?;
    let generation = read_superblock(pool_root)?.generation;

    let index_path = pool_root.join("INDEX.redb");
    let mut index = match RedbIndex::open(&index_path) {
        Ok(idx) => idx,
        Err(_) => {
            let _ = std::fs::remove_file(&index_path);
            RedbIndex::create(&index_path).map_err(|e| FsckError::Io(e.to_string()))?
        }
    };
    for (&hash, &loc) in &locations {
        index
            .put_chunk_location(hash, loc)
            .map_err(|e| FsckError::Io(e.to_string()))?;
    }
    index
        .checkpoint(generation)
        .map_err(|e| FsckError::Io(e.to_string()))?;
    Ok(())
}
