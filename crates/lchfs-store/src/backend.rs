//! Storage backend abstraction. ARCHITECTURE.md §1 (pool layout: "Phase 1
//! backend is plain files behind a `StorageBackend` trait so a raw-block-
//! device backend can be added later without touching callers") and §8
//! (self-healing/redundancy: `Vec<Vdev>`-shaped from day one even though
//! Phase 1 only ever configures one).

use std::io;

/// One physical storage device/file backing (part of) a pool. Phase 1
/// configures exactly one `Vdev`; multi-`Vdev` replication is a labeled
/// future phase (ARCHITECTURE.md §8), not implemented now — this type
/// exists today purely so that future doesn't require a redesign.
pub struct Vdev {
    // TODO(phase-B): identity/path for the Phase 1 single-vdev case
}

/// Abstraction over where pool bytes actually live. `FileBackend` (plain
/// files on a host filesystem) is the only Phase 1 implementation; a raw
/// block-device backend can be added later without touching callers.
pub trait StorageBackend: Send + Sync {
    fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>>;
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;
    fn fsync(&self) -> io::Result<()>;
}

/// Phase 1 backend: a pool is a directory of plain files
/// (ARCHITECTURE.md §1 pool layout).
pub struct FileBackend {
    // TODO(phase-B): open file handles for SUPERBLOCK, segments/, etc.
    _vdevs: Vec<Vdev>,
}

impl FileBackend {
    pub fn open(_pool_root: &std::path::Path) -> io::Result<Self> {
        todo!("lchfs-store: FileBackend::open")
    }
}

impl StorageBackend for FileBackend {
    fn read_at(&self, _offset: u64, _len: u32) -> io::Result<Vec<u8>> {
        todo!("lchfs-store: FileBackend::read_at")
    }

    fn write_at(&self, _offset: u64, _data: &[u8]) -> io::Result<()> {
        todo!("lchfs-store: FileBackend::write_at")
    }

    fn fsync(&self) -> io::Result<()> {
        todo!("lchfs-store: FileBackend::fsync")
    }
}
