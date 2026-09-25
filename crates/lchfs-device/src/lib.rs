//! LCHFS on a raw block device: the layer under the engine that turns one
//! device into fixed regions (superblock ring, keyring, shard superblocks,
//! index) and a zone area holding every segment. See [`layout`] for the
//! byte layout.
//!
//! The engine used to keep each of these as files in a directory; a
//! [`Device`] offers the same few operations over a device instead:
//! segments are created, opened, listed and removed by `(kind, id)`, read
//! and written positionally through a [`SegmentFile`], and synced; regions
//! are read and written in place.
//!
//! **Paths.** A device is named by its path: a block device (`/dev/sdb1`),
//! or -- for tests and development only; the command line accepts block
//! devices alone -- an image file, or a directory, meaning the image file
//! [`IMAGE_NAME`] inside it. Every [`Device::open`] of the same device in
//! one process returns the same handle.
//!
//! **Crash safety** follows the file semantics the engine was written
//! against:
//! - a zone is zeroed before it is used again (removal marks its header
//!   `Freeing` durably first, and a mount finishes any it finds), so a
//!   record scan never meets a previous segment's records;
//! - a segment's written length is persisted in its first zone's header on
//!   every sync, as a file's length is by the filesystem, and zones are
//!   claimed durably before anything is written into them;
//! - a removed segment's zones are released only when its last open
//!   handle closes, as an unlinked file's blocks are.

pub mod layout;

pub use layout::{
    DEVICE_BLOCK, DEVICE_LABEL_MAGIC, DEVICE_LAYOUT_VERSION, DeviceLabel, Region, SegmentKind, ZONE_HEADER_MAGIC,
    ZoneHeader, ZoneState,
};

use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

/// The image file a directory path stands for.
pub const IMAGE_NAME: &str = "lchfs.img";

/// Size of an image file created for a directory path: sparse, so it costs
/// only what is written. `LCHFS_IMAGE_SIZE` (bytes) overrides it.
pub const DEFAULT_IMAGE_SIZE: u64 = 4 << 30;

/// The largest zone size a block device gets by default.
pub const MAX_DEFAULT_ZONE_SIZE: u64 = 16 << 20;

/// The zone size a block device of `device_size` bytes gets by default:
/// about 64Ki zones, so a mount's zone-header scan stays short, but
/// between 1 MiB and 16 MiB. Small devices get small zones, since every
/// open segment (one per busy logical shard) holds at least one zone.
pub fn default_zone_size(device_size: u64) -> u64 {
    (device_size / (64 << 10)).next_power_of_two().clamp(MIB, MAX_DEFAULT_ZONE_SIZE)
}

/// Zone size in an image file: small, so tests with many tiny segments do
/// not need a large image.
pub const DEFAULT_IMAGE_ZONE_SIZE: u64 = 1 << 20;

/// Logical shards a device keeps a superblock slot for: the most a pool
/// may be configured with.
pub const MAX_SHARD_SLOTS: u32 = 1024;

/// Bytes kept for each of the two keyring copies: room for the largest
/// keyring body lchfs-crypto accepts (1 MiB) with its framing.
pub const KEYRING_COPY_LEN: u64 = 2 << 20;

const MIB: u64 = 1 << 20;

fn align_up(v: u64, to: u64) -> u64 {
    v.div_ceil(to) * to
}

/// How to format a device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FormatOptions {
    /// Zone size in bytes: a power of two, at least 64 KiB. `None` picks
    /// [`default_zone_size`], or [`DEFAULT_IMAGE_ZONE_SIZE`] for an image.
    pub zone_size: Option<u64>,
    /// Bytes for each of the two index copies. `None` picks 0.5% of the
    /// device, at least 64 MiB.
    pub index_copy_len: Option<u64>,
}

/// The layout a device of `device_size` bytes gets.
pub fn plan_layout(device_size: u64, zone_size: u64, index_copy_len: Option<u64>) -> io::Result<DeviceLabel> {
    if !zone_size.is_power_of_two() || zone_size < 64 << 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("zone size {zone_size} is not a power of two of at least 64 KiB"),
        ));
    }
    let superblock = Region { offset: DEVICE_BLOCK, len: 16 * DEVICE_BLOCK };
    let keyring = Region { offset: MIB, len: 2 * KEYRING_COPY_LEN };
    let shard_superblocks = Region { offset: keyring.end(), len: MAX_SHARD_SLOTS as u64 * DEVICE_BLOCK };
    let scratch = Region { offset: shard_superblocks.end(), len: DEVICE_BLOCK };
    let index_copy_len = index_copy_len.unwrap_or_else(|| align_up((device_size / 200).max(64 * MIB), MIB));
    let index = Region { offset: align_up(scratch.end(), MIB), len: 2 * index_copy_len };
    let zones_offset = align_up(index.end(), zone_size.min(16 * MIB));
    let usable = device_size.saturating_sub(zones_offset + DEVICE_BLOCK);
    let zone_count = usable / zone_size;
    if zone_count < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "a {device_size}-byte device is too small: its regions need {zones_offset} bytes, and at least 8 \
                 zones of {zone_size} more"
            ),
        ));
    }
    let mut device_uuid = [0u8; 16];
    getrandom::fill(&mut device_uuid).map_err(|e| io::Error::other(e.to_string()))?;
    let mut label = DeviceLabel {
        magic: DEVICE_LABEL_MAGIC,
        layout_version: DEVICE_LAYOUT_VERSION,
        device_uuid,
        generation: 1,
        device_size,
        superblock,
        keyring,
        keyring_copy_len: KEYRING_COPY_LEN,
        shard_superblocks,
        scratch,
        index,
        index_copy_len,
        index_active: 0,
        index_len: [0, 0],
        zones_offset,
        zone_size,
        zone_count,
        checksum: 0,
    };
    label.finalize();
    debug_assert!(label.is_valid());
    Ok(label)
}

/// The file a device path names: itself, or the image inside a directory.
pub fn resolve(path: &Path) -> PathBuf {
    if path.is_dir() { path.join(IMAGE_NAME) } else { path.to_path_buf() }
}

/// Whether `path` is a block device.
pub fn is_block_device(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.file_type().is_block_device())
}

fn device_size(file: &File) -> io::Result<u64> {
    // A block device's metadata reports length 0; seeking to its end gives
    // its size, and works for a regular file too.
    let mut f = file;
    f.seek(SeekFrom::End(0))
}

/// Zeroes `len` bytes at `offset`: a hole punched in an image (which stays
/// sparse), a zero-range on a block device (a discard or write-zeroes the
/// device does itself), else written zeros.
fn zero_range(file: &File, block: bool, offset: u64, len: u64) -> io::Result<()> {
    use nix::fcntl::{FallocateFlags, fallocate};
    let flags = if block {
        FallocateFlags::FALLOC_FL_ZERO_RANGE
    } else {
        FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE
    };
    if fallocate(file, flags, offset as i64, len as i64).is_ok() {
        return Ok(());
    }
    let zeros = vec![0u8; MIB.min(len) as usize];
    let mut at = offset;
    while at < offset + len {
        let n = zeros.len().min((offset + len - at) as usize);
        file.write_all_at(&zeros[..n], at)?;
        at += n as u64;
    }
    Ok(())
}

fn read_label_at(file: &File, at: u64) -> Option<DeviceLabel> {
    let mut block = vec![0u8; DEVICE_BLOCK as usize];
    file.read_exact_at(&mut block, at).ok()?;
    layout::decode_block::<DeviceLabel>(&block).filter(DeviceLabel::is_valid)
}

/// The device's label: the valid copy of A and B with the higher
/// generation.
fn read_label(file: &File) -> Option<DeviceLabel> {
    let a = read_label_at(file, 0);
    let b = device_size(file)
        .ok()
        .and_then(|size| size.checked_sub(DEVICE_BLOCK))
        .and_then(|at| read_label_at(file, at))
        .or_else(|| a.as_ref().and_then(|a| read_label_at(file, a.device_size - DEVICE_BLOCK)));
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.generation > a.generation { b } else { a }),
        (a, b) => a.or(b),
    }
}

/// The superblock ring of the device at `path`, read without opening it
/// for writing or exclusively: what a tool uses to identify a device that
/// a mount may be holding (`lchfs pool status` finding the mount's control
/// socket, say). Only as current as the last ring write that reached it.
pub fn peek_superblock_ring(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(resolve(path))?;
    let label = read_label(&file).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{} is not a formatted LCHFS device", path.display()))
    })?;
    let mut ring = vec![0u8; label.superblock.len as usize];
    file.read_exact_at(&mut ring, label.superblock.offset)?;
    Ok(ring)
}

/// Writes both copies of `label`, each followed by a flush: a torn write
/// of either leaves the other intact.
fn write_label(file: &File, label: &DeviceLabel) -> io::Result<()> {
    let block = layout::encode_block(label);
    file.write_all_at(&block, 0)?;
    file.sync_data()?;
    file.write_all_at(&block, label.device_size - DEVICE_BLOCK)?;
    file.sync_data()
}

/// Whether `path` holds a formatted LCHFS device.
pub fn is_formatted(path: &Path) -> bool {
    File::open(resolve(path)).ok().and_then(|f| read_label(&f)).is_some()
}

/// Formats the device at `path`, destroying whatever it held. A directory
/// path gets an image file created in it. The device must not be open.
pub fn format(path: &Path, options: FormatOptions) -> io::Result<()> {
    let file_path = resolve(path);
    if registry().lock().get(&file_path).and_then(Weak::upgrade).is_some() {
        return Err(io::Error::new(io::ErrorKind::ResourceBusy, format!("{} is open", path.display())));
    }
    let block = is_block_device(&file_path);
    let file = if block {
        OpenOptions::new().read(true).write(true).custom_flags(nix::libc::O_EXCL).open(&file_path)?
    } else {
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&file_path)?;
        if f.metadata()?.len() == 0 {
            let size = std::env::var("LCHFS_IMAGE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_IMAGE_SIZE);
            f.set_len(size)?;
        }
        f
    };
    let size = device_size(&file)?;
    let zone_size =
        options.zone_size.unwrap_or(if block { default_zone_size(size) } else { DEFAULT_IMAGE_ZONE_SIZE });
    let label = plan_layout(size, zone_size, options.index_copy_len)?;
    // Everything a mount reads before the zones must start out empty:
    // an old superblock ring, keyring or shard superblock would be read
    // as this pool's. (Zones need nothing: a zone header written under
    // another device uuid is not this device's.)
    for region in [label.superblock, label.keyring, label.shard_superblocks, label.scratch] {
        zero_range(&file, block, region.offset, region.len)?;
    }
    // The last block, where label B goes, and the first zone header's
    // neighbourhood are covered by the label writes themselves.
    write_label(&file, &label)?;
    Ok(())
}

/// Erases the device's labels, so it is no longer an LCHFS device. The
/// device must not be open.
pub fn wipe(path: &Path) -> io::Result<()> {
    let file_path = resolve(path);
    let file = OpenOptions::new().read(true).write(true).open(&file_path)?;
    let block = is_block_device(&file_path);
    let size = read_label(&file).map(|l| l.device_size).map_or_else(|| device_size(&file), Ok)?;
    zero_range(&file, block, 0, 2 * MIB.min(size))?;
    if size >= DEVICE_BLOCK {
        zero_range(&file, block, size - DEVICE_BLOCK, DEVICE_BLOCK)?;
    }
    file.sync_data()
}

/// Every device open in this process, by resolved path.
fn registry() -> &'static Mutex<HashMap<PathBuf, Weak<Inner>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Weak<Inner>>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// A zone's state as a mount found it, and as allocation keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Zone {
    /// Free and known zero.
    Clean,
    /// Never used under this format, or its header does not read: free,
    /// but zeroed before use.
    Unknown,
    Owned,
    /// Removed, awaiting zeroing (its segment still has an open handle).
    Freeing,
}

struct Inner {
    path: PathBuf,
    file: File,
    block: bool,
    label: RwLock<DeviceLabel>,
    zones: Mutex<Vec<Zone>>,
    segments: Mutex<BTreeMap<(SegmentKind, u64), Arc<SegInner>>>,
    /// Test support: refuse to claim zones, as a device that has gone
    /// away refuses to create anything.
    allocation_blocked: AtomicBool,
}

impl Drop for Inner {
    /// A clean close persists every segment's written length, as closing a
    /// file leaves its length for the next open without an fsync (the page
    /// cache keeps it). Only a crash loses what was never synced.
    fn drop(&mut self) {
        let label = self.label.read().clone();
        let mut wrote = false;
        for seg in self.segments.lock().values() {
            let len = seg.len.load(Ordering::Acquire);
            if seg.removed.load(Ordering::Acquire) || seg.synced_len.load(Ordering::Acquire) == len {
                continue;
            }
            let Some(&first) = seg.zones.read().first() else { continue };
            let mut header = ZoneHeader {
                magic: ZONE_HEADER_MAGIC,
                device_uuid: label.device_uuid,
                state: ZoneState::Owned,
                kind: seg.kind,
                segment_id: seg.id,
                ordinal: 0,
                written_len: len,
                checksum: 0,
            };
            header.finalize();
            let at = label.zones_offset + first * label.zone_size;
            if let Err(e) = self.file.write_all_at(&layout::encode_block(&header), at) {
                tracing::error!("{}: persisting segment {} length at close failed: {e}", self.path.display(), seg.id);
            }
            wrote = true;
        }
        if wrote && let Err(e) = self.file.sync_data() {
            tracing::error!("{}: flush at close failed: {e}", self.path.display());
        }
    }
}

/// An open LCHFS device. Cheap to clone; every clone is the same device.
#[derive(Clone)]
pub struct Device(Arc<Inner>);

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device").field("path", &self.0.path).finish()
    }
}

impl Device {
    /// Opens a formatted device (see the crate docs for what `path` may
    /// be). The same device opened twice in one process is one handle. A
    /// block device is opened exclusively (`O_EXCL`), so neither another
    /// process nor a mount of some filesystem can have it at the same time.
    /// `NotFound` if there is nothing at `path`; `InvalidData` if it is not
    /// a formatted LCHFS device.
    pub fn open(path: &Path) -> io::Result<Device> {
        let file_path = resolve(path);
        let mut reg = registry().lock();
        if let Some(inner) = reg.get(&file_path).and_then(Weak::upgrade) {
            return Ok(Device(inner));
        }
        reg.retain(|_, w| w.strong_count() > 0);
        let block = is_block_device(&file_path);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        if block {
            opts.custom_flags(nix::libc::O_EXCL);
        }
        let file = opts.open(&file_path).map_err(|e| {
            if e.raw_os_error() == Some(nix::libc::EBUSY) {
                io::Error::new(io::ErrorKind::ResourceBusy, format!("{} is in use", file_path.display()))
            } else {
                e
            }
        })?;
        let label = read_label(&file).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not a formatted LCHFS device", file_path.display()),
            )
        })?;
        let inner = Arc::new(Inner {
            path: file_path.clone(),
            file,
            block,
            zones: Mutex::new(Vec::new()),
            segments: Mutex::new(BTreeMap::new()),
            label: RwLock::new(label),
            allocation_blocked: AtomicBool::new(false),
        });
        let device = Device(inner);
        device.scan_zones()?;
        reg.insert(file_path, Arc::downgrade(&device.0));
        Ok(device)
    }

    /// `open`, formatting the device first if it holds no LCHFS layout.
    pub fn open_or_format(path: &Path, options: FormatOptions) -> io::Result<Device> {
        if !is_formatted(path) {
            format(path, options)?;
        }
        Self::open(path)
    }

    /// The device's file (a block device or image).
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    pub fn label(&self) -> DeviceLabel {
        self.0.label.read().clone()
    }

    /// Flushes everything written to the device.
    pub fn sync(&self) -> io::Result<()> {
        self.0.file.sync_data()
    }

    /// Takes the exclusive advisory lock that marks the device as in use by
    /// one pool. `WouldBlock` if something holds it, in this process or
    /// another. Released when the guard drops.
    pub fn lock_exclusive(&self) -> io::Result<File> {
        let file = OpenOptions::new().read(true).open(&self.0.path)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, format!("{} is locked", self.0.path.display())))
            }
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    // -------------------------------------------------------------------
    // Regions.
    // -------------------------------------------------------------------

    fn region_io(region: Region, offset: u64, len: usize) -> io::Result<u64> {
        if offset.checked_add(len as u64).is_none_or(|end| end > region.len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{len} bytes at {offset} are outside a {}-byte region", region.len),
            ));
        }
        Ok(region.offset + offset)
    }

    /// The superblock ring, `SUPERBLOCK_SLOT_COUNT` slots.
    pub fn superblock_region(&self) -> Region {
        self.0.label.read().superblock
    }

    pub fn read_region(&self, region: Region, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let at = Self::region_io(region, offset, buf.len())?;
        self.0.file.read_exact_at(buf, at)
    }

    pub fn write_region(&self, region: Region, offset: u64, data: &[u8]) -> io::Result<()> {
        let at = Self::region_io(region, offset, data.len())?;
        self.0.file.write_all_at(data, at)
    }

    /// Logical shard `shard`'s superblock slot (4 KiB).
    pub fn read_shard_superblock(&self, shard: u32) -> io::Result<Vec<u8>> {
        let region = self.0.label.read().shard_superblocks;
        let mut block = vec![0u8; DEVICE_BLOCK as usize];
        self.read_region(region, shard as u64 * DEVICE_BLOCK, &mut block)?;
        Ok(block)
    }

    /// Overwrites shard `shard`'s slot and flushes it.
    pub fn write_shard_superblock(&self, shard: u32, block: &[u8]) -> io::Result<()> {
        let region = self.0.label.read().shard_superblocks;
        if block.len() as u64 > DEVICE_BLOCK {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a shard superblock is at most 4 KiB"));
        }
        self.write_region(region, shard as u64 * DEVICE_BLOCK, block)?;
        self.sync()
    }

    /// Writes and flushes the scratch sector: proof the device takes writes.
    pub fn probe_write(&self) -> io::Result<()> {
        let region = self.0.label.read().scratch;
        self.write_region(region, 0, &[0x5a; DEVICE_BLOCK as usize])?;
        self.sync()
    }

    // -------------------------------------------------------------------
    // Keyring: two copies, each `[u64 generation][u32 len][u32 crc][bytes]`;
    // the valid one with the higher generation is the keyring.
    // -------------------------------------------------------------------

    fn keyring_copy(&self, copy: u64) -> Option<(u64, Vec<u8>)> {
        let label = self.0.label.read();
        let region = label.keyring;
        let base = copy * label.keyring_copy_len;
        let mut head = [0u8; 16];
        self.read_region(region, base, &mut head).ok()?;
        let generation = u64::from_le_bytes(head[..8].try_into().unwrap());
        let len = u32::from_le_bytes(head[8..12].try_into().unwrap()) as u64;
        let crc = u32::from_le_bytes(head[12..16].try_into().unwrap());
        if generation == 0 || len + 16 > label.keyring_copy_len {
            return None;
        }
        let mut bytes = vec![0u8; len as usize];
        self.read_region(region, base + 16, &mut bytes).ok()?;
        (crc32fast::hash(&bytes) == crc).then_some((generation, bytes))
    }

    /// The keyring's bytes, or `None` if the device holds none.
    pub fn read_keyring(&self) -> Option<Vec<u8>> {
        match (self.keyring_copy(0), self.keyring_copy(1)) {
            (Some(a), Some(b)) => Some(if b.0 > a.0 { b.1 } else { a.1 }),
            (a, b) => a.or(b).map(|(_, bytes)| bytes),
        }
    }

    /// Replaces the keyring: writes the older (or invalid) copy and
    /// flushes, so a torn write leaves the previous keyring whole.
    pub fn write_keyring(&self, bytes: &[u8]) -> io::Result<()> {
        let (region, copy_len) = {
            let l = self.0.label.read();
            (l.keyring, l.keyring_copy_len)
        };
        if bytes.len() as u64 + 16 > copy_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("a {}-byte keyring does not fit the {copy_len}-byte keyring copy", bytes.len()),
            ));
        }
        let (a, b) = (self.keyring_copy(0), self.keyring_copy(1));
        let newest = a.iter().chain(b.iter()).map(|(g, _)| *g).max().unwrap_or(0);
        let target = match (&a, &b) {
            (None, _) => 0,
            (Some(_), None) => 1,
            (Some(a), Some(b)) => u64::from(a.0 > b.0),
        };
        let mut buf = Vec::with_capacity(16 + bytes.len());
        buf.extend_from_slice(&(newest + 1).to_le_bytes());
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&crc32fast::hash(bytes).to_le_bytes());
        buf.extend_from_slice(bytes);
        self.write_region(region, target * copy_len, &buf)?;
        self.sync()
    }

    /// Erases both keyring copies.
    pub fn clear_keyring(&self) -> io::Result<()> {
        let region = self.0.label.read().keyring;
        zero_range(&self.0.file, self.0.block, region.offset, region.len)?;
        self.sync()
    }

    // -------------------------------------------------------------------
    // Index copies.
    // -------------------------------------------------------------------

    /// A redb storage backend over index copy `copy` (0 or 1).
    pub fn index_backend(&self, copy: u8) -> IndexBackend {
        IndexBackend { device: self.clone(), copy }
    }

    /// Which index copy is live.
    pub fn active_index(&self) -> u8 {
        self.0.label.read().index_active
    }

    /// Makes `copy` the live index (one label write).
    pub fn activate_index(&self, copy: u8) -> io::Result<()> {
        self.update_label(|l| l.index_active = copy)
    }

    /// Empties index copy `copy`: zeroed, and its length set to 0.
    pub fn clear_index(&self, copy: u8) -> io::Result<()> {
        let (region, copy_len) = {
            let l = self.0.label.read();
            (l.index, l.index_copy_len)
        };
        zero_range(&self.0.file, self.0.block, region.offset + copy as u64 * copy_len, copy_len)?;
        self.update_label(|l| l.index_len[copy as usize] = 0)
    }

    fn update_label(&self, change: impl FnOnce(&mut DeviceLabel)) -> io::Result<()> {
        let mut label = self.0.label.write();
        let mut next = label.clone();
        change(&mut next);
        next.generation += 1;
        next.finalize();
        write_label(&self.0.file, &next)?;
        *label = next;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Zones and segments.
    // -------------------------------------------------------------------

    fn zone_offset(label: &DeviceLabel, zone: u64) -> u64 {
        label.zones_offset + zone * label.zone_size
    }

    fn read_zone_header(&self, label: &DeviceLabel, zone: u64) -> Option<ZoneHeader> {
        let mut block = vec![0u8; DEVICE_BLOCK as usize];
        self.0.file.read_exact_at(&mut block, Self::zone_offset(label, zone)).ok()?;
        layout::decode_block::<ZoneHeader>(&block).filter(|h| h.is_valid_for(&label.device_uuid))
    }

    fn write_zone_header(&self, label: &DeviceLabel, zone: u64, mut header: ZoneHeader) -> io::Result<()> {
        header.magic = ZONE_HEADER_MAGIC;
        header.device_uuid = label.device_uuid;
        header.finalize();
        self.0.file.write_all_at(&layout::encode_block(&header), Self::zone_offset(label, zone))
    }

    /// Zeroes a zone's payload and marks it free.
    fn zero_and_free(&self, label: &DeviceLabel, zone: u64) -> io::Result<()> {
        let at = Self::zone_offset(label, zone);
        zero_range(&self.0.file, self.0.block, at + DEVICE_BLOCK, label.zone_size - DEVICE_BLOCK)?;
        self.write_zone_header(
            label,
            zone,
            ZoneHeader {
                magic: ZONE_HEADER_MAGIC,
                device_uuid: label.device_uuid,
                state: ZoneState::Free,
                kind: SegmentKind::Data,
                segment_id: 0,
                ordinal: 0,
                written_len: 0,
                checksum: 0,
            },
        )
    }

    /// Reads every zone header: rebuilds the segment table and the free
    /// map, and finishes zeroing any zone a removal left `Freeing`.
    fn scan_zones(&self) -> io::Result<()> {
        let label = self.label();
        let mut zones = vec![Zone::Unknown; label.zone_count as usize];
        // Per segment: (ordinal, zone, written_len) of each zone it owns.
        type Parts = Vec<(u32, u64, u64)>;
        let mut found: BTreeMap<(SegmentKind, u64), Parts> = BTreeMap::new();
        let mut unfinished = Vec::new();
        for z in 0..label.zone_count {
            match self.read_zone_header(&label, z) {
                Some(h) => match h.state {
                    ZoneState::Free => zones[z as usize] = Zone::Clean,
                    ZoneState::Owned => {
                        zones[z as usize] = Zone::Owned;
                        found.entry((h.kind, h.segment_id)).or_default().push((h.ordinal, z, h.written_len));
                    }
                    ZoneState::Freeing => unfinished.push(z),
                },
                None => zones[z as usize] = Zone::Unknown,
            }
        }
        for z in unfinished {
            self.zero_and_free(&label, z)?;
            zones[z as usize] = Zone::Clean;
        }
        let payload = label.zone_size - DEVICE_BLOCK;
        let mut segments = BTreeMap::new();
        let mut orphans = Vec::new();
        for ((kind, id), mut parts) in found {
            parts.sort_unstable();
            // Zones are claimed in order, so a segment's ordinals run
            // 0..n. Anything after a gap (or a duplicate) cannot be part of
            // it: freed rather than guessed at.
            let mut list = Vec::new();
            let mut written = 0;
            for (ordinal, zone, written_len) in parts {
                if ordinal as usize == list.len() {
                    if ordinal == 0 {
                        written = written_len;
                    }
                    list.push(zone);
                } else {
                    tracing::warn!("{}: zone {zone} claims ordinal {ordinal} of {kind:?} segment {id} out of order; freeing it", self.0.path.display());
                    orphans.push(zone);
                }
            }
            if list.is_empty() {
                continue;
            }
            let capacity = list.len() as u64 * payload;
            let len = written.min(capacity);
            segments.insert(
                (kind, id),
                Arc::new(SegInner {
                    device: Arc::downgrade(&self.0),
                    kind,
                    id,
                    zones: RwLock::new(list),
                    len: AtomicU64::new(len),
                    synced_len: AtomicU64::new(len),
                    removed: AtomicBool::new(false),
                }),
            );
        }
        for z in orphans {
            self.zero_and_free(&label, z)?;
            zones[z as usize] = Zone::Clean;
        }
        self.sync()?;
        *self.0.zones.lock() = zones;
        *self.0.segments.lock() = segments;
        Ok(())
    }

    /// Claims a free zone for ordinal `ordinal` of a segment, zeroing it
    /// first if it is not known zero, and makes the claim durable before
    /// anything is written into it.
    fn claim_zone(&self, kind: SegmentKind, id: u64, ordinal: u32) -> io::Result<u64> {
        if self.0.allocation_blocked.load(Ordering::Relaxed) {
            return Err(io::Error::other(format!("{}: the device is gone", self.0.path.display())));
        }
        let label = self.label();
        let zone = {
            let mut zones = self.0.zones.lock();
            let pick = zones
                .iter()
                .position(|z| *z == Zone::Clean)
                .or_else(|| zones.iter().position(|z| *z == Zone::Unknown))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::StorageFull,
                        format!("{}: no free zone left", self.0.path.display()),
                    )
                })?;
            let was = zones[pick];
            zones[pick] = Zone::Owned;
            (pick as u64, was)
        };
        let (z, was) = zone;
        let result = (|| {
            if was == Zone::Unknown {
                let at = Self::zone_offset(&label, z);
                zero_range(&self.0.file, self.0.block, at + DEVICE_BLOCK, label.zone_size - DEVICE_BLOCK)?;
            }
            self.write_zone_header(
                &label,
                z,
                ZoneHeader {
                    magic: ZONE_HEADER_MAGIC,
                    device_uuid: label.device_uuid,
                    state: ZoneState::Owned,
                    kind,
                    segment_id: id,
                    ordinal,
                    written_len: 0,
                    checksum: 0,
                },
            )?;
            self.sync()
        })();
        if let Err(e) = result {
            self.0.zones.lock()[z as usize] = was;
            return Err(e);
        }
        Ok(z)
    }

    /// Creates segment `(kind, id)`, empty. One that already exists is
    /// removed first, as `open(O_TRUNC)` replaces a file's contents. The
    /// first zone is claimed at once, so the segment exists durably.
    pub fn create_segment(&self, kind: SegmentKind, id: u64) -> io::Result<SegmentFile> {
        match self.remove_segment(kind, id) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let zone = self.claim_zone(kind, id, 0)?;
        let seg = Arc::new(SegInner {
            device: Arc::downgrade(&self.0),
            kind,
            id,
            zones: RwLock::new(vec![zone]),
            len: AtomicU64::new(0),
            synced_len: AtomicU64::new(0),
            removed: AtomicBool::new(false),
        });
        self.0.segments.lock().insert((kind, id), Arc::clone(&seg));
        Ok(SegmentFile { dev: Arc::clone(&self.0), seg })
    }

    /// Opens an existing segment. `NotFound` if there is none.
    pub fn open_segment(&self, kind: SegmentKind, id: u64) -> io::Result<SegmentFile> {
        self.0
            .segments
            .lock()
            .get(&(kind, id))
            .map(|s| SegmentFile { dev: Arc::clone(&self.0), seg: Arc::clone(s) })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{}: no {kind:?} segment {id}", self.0.path.display()),
                )
            })
    }

    pub fn segment_exists(&self, kind: SegmentKind, id: u64) -> bool {
        self.0.segments.lock().contains_key(&(kind, id))
    }

    /// Removes a segment. It disappears from `open_segment` and `segments`
    /// at once, and its zones are marked `Freeing` durably; they are zeroed
    /// and reused once the last open [`SegmentFile`] on it is dropped.
    /// `NotFound` if there is none.
    pub fn remove_segment(&self, kind: SegmentKind, id: u64) -> io::Result<()> {
        let seg = self.0.segments.lock().remove(&(kind, id)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{}: no {kind:?} segment {id}", self.0.path.display()))
        })?;
        let label = self.label();
        let zones = seg.zones.read().clone();
        for (ordinal, &z) in zones.iter().enumerate() {
            self.write_zone_header(
                &label,
                z,
                ZoneHeader {
                    magic: ZONE_HEADER_MAGIC,
                    device_uuid: label.device_uuid,
                    state: ZoneState::Freeing,
                    kind,
                    segment_id: id,
                    ordinal: ordinal as u32,
                    written_len: 0,
                    checksum: 0,
                },
            )?;
        }
        self.sync()?;
        {
            let mut map = self.0.zones.lock();
            for &z in &zones {
                map[z as usize] = Zone::Freeing;
            }
        }
        seg.removed.store(true, Ordering::Release);
        Ok(())
    }

    /// Every segment on the device, in `(kind, id)` order.
    pub fn segments(&self) -> Vec<(SegmentKind, u64)> {
        self.0.segments.lock().keys().copied().collect()
    }

    /// Ids of the segments of one kind, ascending.
    pub fn segment_ids(&self, kind: SegmentKind) -> Vec<u64> {
        self.0.segments.lock().keys().filter(|(k, _)| *k == kind).map(|(_, id)| *id).collect()
    }

    /// `(total, free)` bytes of segment space.
    pub fn capacity(&self) -> (u64, u64) {
        let label = self.0.label.read();
        let payload = label.zone_size - DEVICE_BLOCK;
        let zones = self.0.zones.lock();
        let free = zones.iter().filter(|z| matches!(z, Zone::Clean | Zone::Unknown)).count() as u64;
        (label.zone_count * payload, free * payload)
    }

    /// Test support: while blocked, nothing new can be claimed on the
    /// device -- no segment created, none grown past its zones -- while
    /// what is already open keeps working: a device that is going away.
    #[doc(hidden)]
    pub fn block_allocation(&self, blocked: bool) {
        self.0.allocation_blocked.store(blocked, Ordering::Relaxed);
    }

    /// Zones of removed segments still held by an open handle: what an
    /// unlinked-but-open file's blocks were.
    pub fn zones_awaiting_release(&self) -> u64 {
        self.0.zones.lock().iter().filter(|z| matches!(z, Zone::Freeing)).count() as u64
    }

    /// Zones in use by segments, or still being freed.
    pub fn zones_in_use(&self) -> u64 {
        self.0.zones.lock().iter().filter(|z| matches!(z, Zone::Owned | Zone::Freeing)).count() as u64
    }

    /// The segment's whole contents, like `std::fs::read`.
    pub fn read_segment(&self, kind: SegmentKind, id: u64) -> io::Result<Vec<u8>> {
        let f = self.open_segment(kind, id)?;
        let mut buf = vec![0u8; f.len() as usize];
        f.read_exact_at(&mut buf, 0)?;
        Ok(buf)
    }

    /// Releases a removed segment's zones once nothing has it open.
    fn release(&self, zones: &[u64]) {
        let label = self.label();
        for &z in zones {
            match self.zero_and_free(&label, z) {
                Ok(()) => self.0.zones.lock()[z as usize] = Zone::Clean,
                // Left Freeing on disk; the next mount finishes it.
                Err(e) => tracing::error!("{}: zeroing freed zone {z} failed: {e}", self.0.path.display()),
            }
        }
    }
}

struct SegInner {
    device: Weak<Inner>,
    kind: SegmentKind,
    id: u64,
    zones: RwLock<Vec<u64>>,
    /// Bytes written: the largest end of any write.
    len: AtomicU64,
    /// `len` as last persisted in zone 0's header.
    synced_len: AtomicU64,
    removed: AtomicBool,
}

impl Drop for SegInner {
    fn drop(&mut self) {
        if self.removed.load(Ordering::Acquire)
            && let Some(inner) = self.device.upgrade()
        {
            Device(inner).release(&self.zones.read());
        }
    }
}

/// An open segment: positional reads and writes in its own byte space,
/// like a file's. Cheap to clone. Keeps its device open, as an open file
/// keeps its filesystem mounted.
#[derive(Clone)]
pub struct SegmentFile {
    dev: Arc<Inner>,
    seg: Arc<SegInner>,
}

impl std::fmt::Debug for SegmentFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentFile").field("kind", &self.seg.kind).field("id", &self.seg.id).finish()
    }
}

impl SegmentFile {
    fn device(&self) -> io::Result<Device> {
        Ok(Device(Arc::clone(&self.dev)))
    }

    pub fn kind(&self) -> SegmentKind {
        self.seg.kind
    }

    pub fn id(&self) -> u64 {
        self.seg.id
    }

    /// Bytes written so far, like a file's length.
    pub fn len(&self) -> u64 {
        self.seg.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Calls `each(device offset, range in buf)` for the pieces of
    /// `[offset, offset + len)`, claiming zones up to the end if `grow`.
    fn map(&self, offset: u64, len: usize, grow: bool, mut each: impl FnMut(u64, std::ops::Range<usize>) -> io::Result<()>) -> io::Result<()> {
        let device = self.device()?;
        let label = device.label();
        let payload = label.zone_size - DEVICE_BLOCK;
        let end = offset + len as u64;
        let needed = end.div_ceil(payload) as usize;
        // Most writes land in zones the segment already has: the write
        // lock is taken only to add one, since readers of the segment hold
        // the read side while they look its zones up.
        if grow && end > 0 && self.seg.zones.read().len() < needed {
            let mut zones = self.seg.zones.write();
            while zones.len() < needed {
                let z = device.claim_zone(self.seg.kind, self.seg.id, zones.len() as u32)?;
                zones.push(z);
            }
        }
        // The zone numbers are copied out, and the I/O done with no lock
        // held: a zone never moves once claimed.
        if end == offset {
            return Ok(());
        }
        let first = (offset / payload) as usize;
        let zones: Vec<u64> = self.seg.zones.read().get(first..needed).map(<[u64]>::to_vec).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the segment")
        })?;
        let mut at = offset;
        while at < end {
            let ordinal = (at / payload) as usize;
            let within = at % payload;
            let n = (payload - within).min(end - at);
            let zone = zones[ordinal - first];
            let dev_at = Device::zone_offset(&label, zone) + DEVICE_BLOCK + within;
            let from = (at - offset) as usize;
            each(dev_at, from..from + n as usize)?;
            at += n;
        }
        Ok(())
    }

    /// Reads exactly `buf.len()` bytes at `offset`; `UnexpectedEof` past the
    /// written length, as a file read would be.
    pub fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        if offset + buf.len() as u64 > self.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
        }
        let device = self.device()?;
        self.map(offset, buf.len(), false, |at, range| device.0.file.read_exact_at(&mut buf[range], at))
    }

    /// Writes all of `data` at `offset`, growing the segment as needed.
    pub fn write_all_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        let device = self.device()?;
        self.map(offset, data.len(), true, |at, range| device.0.file.write_all_at(&data[range], at))?;
        self.seg.len.fetch_max(offset + data.len() as u64, Ordering::AcqRel);
        Ok(())
    }

    /// Makes everything written so far durable, and the written length
    /// with it.
    pub fn sync_all(&self) -> io::Result<()> {
        let device = self.device()?;
        let len = self.len();
        if self.seg.synced_len.load(Ordering::Acquire) != len && !self.seg.removed.load(Ordering::Acquire) {
            let label = device.label();
            let first = self.seg.zones.read()[0];
            device.write_zone_header(
                &label,
                first,
                ZoneHeader {
                    magic: ZONE_HEADER_MAGIC,
                    device_uuid: label.device_uuid,
                    state: ZoneState::Owned,
                    kind: self.seg.kind,
                    segment_id: self.seg.id,
                    ordinal: 0,
                    written_len: len,
                    checksum: 0,
                },
            )?;
        }
        device.sync()?;
        self.seg.synced_len.fetch_max(len, Ordering::AcqRel);
        Ok(())
    }
}

/// A redb storage backend over one of a device's two index copies.
#[derive(Debug)]
pub struct IndexBackend {
    device: Device,
    copy: u8,
}

impl IndexBackend {
    fn bounds(&self) -> (u64, u64, u64) {
        let l = self.device.0.label.read();
        (l.index.offset + self.copy as u64 * l.index_copy_len, l.index_copy_len, l.index_len[self.copy as usize])
    }
}

impl redb::StorageBackend for IndexBackend {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.bounds().2)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        let (base, cap, _) = self.bounds();
        if offset + out.len() as u64 > cap {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the index region"));
        }
        self.device.0.file.read_exact_at(out, base + offset)
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        let (base, cap, old) = self.bounds();
        if len > cap {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!("the index needs {len} bytes and its region holds {cap}; reformat with a larger index"),
            ));
        }
        if len > old {
            // What a file's extension would read as.
            zero_range(&self.device.0.file, self.device.0.block, base + old, len - old)?;
        }
        let copy = self.copy as usize;
        self.device.update_label(|l| l.index_len[copy] = len)
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        self.device.sync()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let (base, cap, _) = self.bounds();
        if offset + data.len() as u64 > cap {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "write past the index region"));
        }
        self.device.0.file.write_all_at(data, base + offset)
    }
}

#[cfg(test)]
mod tests;
