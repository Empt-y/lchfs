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

/// One physical storage device backing (part of) a pool.
///
/// `root` is the vdev's directory, not any file inside it: per
/// ARCHITECTURE.md §15.10 a vdev root is self-contained, holding its own
/// `SUPERBLOCK`, `LOCK` and `segments/` tree. It previously held the
/// SUPERBLOCK *file* path, which made the type quietly wrong about what a
/// vdev is — §15.0 records that, and the whole `Vec<Vdev>`-shaped claim it
/// was part of.
///
/// Phase 1 pools configure exactly one vdev; fan-out across several is the
/// remaining Phase 3 work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vdev {
    /// The slot this device occupies in the pool (§15.6) -- what its
    /// superblock's `vdev_id` says, and what its index entries are keyed
    /// by. Carried here rather than implied by position in a list, so a
    /// degraded mount (§15.8) can hold just the online devices without the
    /// ids of the ones after a gap being off by one.
    pub id: u16,
    pub root: PathBuf,
}

impl Vdev {
    pub fn new(id: u16, root: PathBuf) -> Self {
        Self { id, root }
    }

    /// This vdev's superblock ring. Each vdev carries its own (§15.5).
    pub fn superblock_path(&self) -> PathBuf {
        superblock_path(&self.root)
    }
}

/// Where a vdev root keeps its superblock ring.
pub fn superblock_path(vdev_root: &Path) -> PathBuf {
    vdev_root.join("SUPERBLOCK")
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
    /// The vdev root this backend's superblock lives in. A backend is
    /// opened before its superblock has been read, so it cannot know which
    /// slot the device occupies -- only where it is. (Previously a
    /// `_`-prefixed `Vec<Vdev>` that was always length 1 and never read —
    /// dead weight that made the abstraction look more ready for
    /// replication than it was.)
    root: PathBuf,
    file: std::fs::File,
}

impl FileBackend {
    pub fn open(vdev_root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(vdev_root)?;
        let path = superblock_path(vdev_root);
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
            root: vdev_root.to_path_buf(),
            file,
        })
    }

    /// The vdev root this backend reads and writes.
    pub fn root(&self) -> &Path {
        &self.root
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
