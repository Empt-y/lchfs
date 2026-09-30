//! Storage backend abstraction. ARCHITECTURE.md §1 and §8
//! (self-healing/redundancy: `Vec<Vdev>`-shaped from day one).
//!
//! A pool's devices are raw block devices formatted by `lchfs-device`
//! (format v6); this module covers the superblock ring, which lives in
//! each device's superblock region. Segments are reached through
//! `SegmentWriter`/`SegmentReader` (segment.rs), over the same device's
//! zones.

use lchfs_device::Device;
use lchfs_format::{SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE};
use std::io;
use std::path::{Path, PathBuf};

/// One physical storage device backing (part of) a pool.
///
/// `root` is the device's path: a block device, or for tests and
/// development an image file or a directory holding one (see
/// `lchfs-device`). Per ARCHITECTURE.md §15.10 a device is
/// self-contained, holding its own superblock ring and segments.
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
}

/// Whether `root` is a formatted device that opens: the device is there.
/// What the existence of its `SUPERBLOCK` file used to answer.
pub fn device_present(root: &Path) -> bool {
    Device::open(root).is_ok()
}

/// Whether the device at `root` has ever had a superblock written: it
/// holds (or held) a pool, as opposed to being freshly formatted.
pub fn ring_written(root: &Path) -> bool {
    Device::open(root).is_ok_and(|d| {
        let region = d.superblock_region();
        let mut ring = vec![0u8; region.len as usize];
        d.read_region(region, 0, &mut ring).is_ok() && ring.iter().any(|&b| b != 0)
    })
}

/// Erases the device's superblock ring: it no longer holds a pool.
pub fn clear_ring(root: &Path) -> io::Result<()> {
    let d = Device::open(root)?;
    let region = d.superblock_region();
    d.write_region(region, 0, &vec![0u8; region.len as usize])?;
    d.sync()
}

/// Abstraction over where pool bytes actually live.
pub trait StorageBackend: Send + Sync {
    fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>>;
    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()>;
    fn fsync(&self) -> io::Result<()>;
}

/// A device's superblock ring: `SUPERBLOCK_SLOT_COUNT * SUPERBLOCK_SLOT_SIZE`
/// bytes in its superblock region. (Named for the file it once was.)
pub struct FileBackend {
    /// The device this backend's ring lives on. A backend is opened before
    /// its superblock has been read, so it cannot know which slot the
    /// device occupies -- only where it is.
    root: PathBuf,
    device: Device,
}

impl FileBackend {
    /// Opens a device's ring: for probing a device that may not be there.
    /// `NotFound` if nothing is at `root`, `InvalidData` if it is not a
    /// formatted device.
    pub fn open_existing(vdev_root: &Path) -> io::Result<Self> {
        let device = Device::open(vdev_root).map_err(|e| {
            if e.kind() == io::ErrorKind::InvalidData {
                io::Error::new(io::ErrorKind::NotFound, format!("{} has no superblock: {e}", vdev_root.display()))
            } else {
                e
            }
        })?;
        Ok(Self { root: vdev_root.to_path_buf(), device })
    }

    /// Opens a device's ring, formatting the device first if it holds no
    /// LCHFS layout (a new pool's device, or an attached blank one).
    pub fn open(vdev_root: &Path) -> io::Result<Self> {
        let device = Device::open_or_format(vdev_root, lchfs_device::FormatOptions::default())?;
        debug_assert_eq!(
            device.superblock_region().len,
            SUPERBLOCK_SLOT_COUNT as u64 * SUPERBLOCK_SLOT_SIZE as u64
        );
        Ok(Self { root: vdev_root.to_path_buf(), device })
    }

    /// The device root this backend reads and writes.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The device itself.
    pub fn device(&self) -> &Device {
        &self.device
    }
}

impl StorageBackend for FileBackend {
    fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        self.device.read_region(self.device.superblock_region(), offset, &mut buf)?;
        Ok(buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.device.write_region(self.device.superblock_region(), offset, data)
    }

    fn fsync(&self) -> io::Result<()> {
        self.device.sync()
    }
}
