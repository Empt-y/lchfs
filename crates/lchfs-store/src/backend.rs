//! Storage backend abstraction. ARCHITECTURE.md §1 (pool layout: "Phase 1
//! backend is plain files behind a `StorageBackend` trait so a raw-block-
//! device backend can be added later without touching callers") and §8
//! (self-healing/redundancy: `Vec<Vdev>`-shaped from day one even though
//! Phase 1 only ever configures one).
//!
//! Concrete scope decision for Phase B: `StorageBackend` abstracts
//! specifically the fixed-size, fixed-location SUPERBLOCK (the piece whose
//! access pattern — small, random-access, offset-addressed — maps directly
//! onto a future raw-block-device's reserved region). Segment files
//! (growing, append-only, one-per-file under Phase 1's directory layout)
//! are handled directly by `SegmentWriter`/`SegmentReader` (segment.rs)
//! rather than through this trait; that split is what `segments/` living
//! outside any `Vdev` byte range in §1's pool layout implies.

use lchfs_format::{SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE};
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// One physical storage device/file backing (part of) a pool. Phase 1
/// configures exactly one `Vdev`; multi-`Vdev` replication is a labeled
/// future phase (ARCHITECTURE.md §8), not implemented now — this type
/// exists today purely so that future doesn't require a redesign.
pub struct Vdev {
    pub path: PathBuf,
}

impl Vdev {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

/// Abstraction over where pool bytes actually live. `FileBackend` (plain
/// files on a host filesystem) is the only Phase 1 implementation; a raw
/// block-device backend can be added later without touching callers.
pub trait StorageBackend: Send + Sync {
    fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>>;
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;
    fn fsync(&self) -> io::Result<()>;
}

/// Phase 1 backend: the pool's SUPERBLOCK file (ARCHITECTURE.md §1 pool
/// layout). Fixed size — `SUPERBLOCK_SLOT_COUNT * SUPERBLOCK_SLOT_SIZE`
/// bytes — created on first open and never resized after.
pub struct FileBackend {
    _vdevs: Vec<Vdev>,
    file: std::fs::File,
}

impl FileBackend {
    pub fn open(pool_root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(pool_root)?;
        let path = pool_root.join("SUPERBLOCK");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let total_size = (SUPERBLOCK_SLOT_COUNT as u64) * (SUPERBLOCK_SLOT_SIZE as u64);
        if file.metadata()?.len() < total_size {
            file.set_len(total_size)?;
        }
        Ok(Self {
            _vdevs: vec![Vdev::new(path)],
            file,
        })
    }
}

impl StorageBackend for FileBackend {
    fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        self.file.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.file.write_all_at(data, offset)
    }

    fn fsync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}
