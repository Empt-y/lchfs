//! Test support: reach into a pool's device the way tests used to reach
//! into its directory -- to read, corrupt, truncate or delete a segment,
//! the superblock ring or the index, and to see every byte a device holds.
//! Nothing in the engine uses this.

pub use lchfs_device::{Device, SegmentKind};
use lchfs_format::StreamKind;
use std::io;
use std::path::Path;

fn dev(root: &Path) -> Device {
    Device::open(root).unwrap_or_else(|e| panic!("{} is not a device: {e}", root.display()))
}

/// The device's name for a Data or Meta segment.
pub fn kind(stream: StreamKind) -> SegmentKind {
    crate::segment::device_kind(stream)
}

/// Ids of the segments of `kind` on a device, ascending.
pub fn segment_ids(root: &Path, kind: SegmentKind) -> Vec<u64> {
    Device::open(root).map(|d| d.segment_ids(kind)).unwrap_or_default()
}

/// Every segment on a device.
pub fn segments(root: &Path) -> Vec<(SegmentKind, u64)> {
    Device::open(root).map(|d| d.segments()).unwrap_or_default()
}

pub fn segment_exists(root: &Path, kind: SegmentKind, id: u64) -> bool {
    Device::open(root).is_ok_and(|d| d.segment_exists(kind, id))
}

/// A segment's whole contents.
pub fn read_segment(root: &Path, kind: SegmentKind, id: u64) -> Vec<u8> {
    dev(root).read_segment(kind, id).unwrap_or_else(|e| panic!("reading {kind:?} {id}: {e}"))
}

/// Replaces a segment's contents with `bytes`, as writing its file did.
pub fn write_segment(root: &Path, kind: SegmentKind, id: u64, bytes: &[u8]) {
    let f = dev(root).create_segment(kind, id).unwrap();
    f.write_all_at(bytes, 0).unwrap();
    f.sync_all().unwrap();
}

/// Overwrites `bytes` at `offset` inside a segment, in place.
pub fn write_at(root: &Path, kind: SegmentKind, id: u64, offset: u64, bytes: &[u8]) {
    let f = dev(root).open_segment(kind, id).unwrap();
    f.write_all_at(bytes, offset).unwrap();
    f.sync_all().unwrap();
}

/// Cuts a segment to its first `len` bytes, as truncating its file did.
pub fn truncate_segment(root: &Path, kind: SegmentKind, id: u64, len: u64) {
    let mut bytes = read_segment(root, kind, id);
    bytes.truncate(len as usize);
    write_segment(root, kind, id, &bytes);
}

/// Deletes a segment.
pub fn remove_segment(root: &Path, kind: SegmentKind, id: u64) -> io::Result<()> {
    dev(root).remove_segment(kind, id)
}

/// Deletes every segment matching `which` -- what deleting a directory of
/// segment files did.
pub fn remove_segments(root: &Path, which: impl Fn(SegmentKind) -> bool) {
    let d = dev(root);
    for (k, id) in d.segments() {
        if which(k) {
            d.remove_segment(k, id).unwrap();
        }
    }
}

/// The device stops taking anything new (see `Device::block_allocation`),
/// as a device going away does; `reappear` undoes it. The device must be
/// open (a pool on it mounted), or this has nothing to act on.
pub fn vanish(root: &Path) {
    dev(root).block_allocation(true);
}

pub fn reappear(root: &Path) {
    dev(root).block_allocation(false);
}

/// The written length of a segment.
pub fn segment_len(root: &Path, kind: SegmentKind, id: u64) -> u64 {
    dev(root).open_segment(kind, id).unwrap().len()
}

/// The superblock ring's bytes.
pub fn read_ring(root: &Path) -> Vec<u8> {
    let d = dev(root);
    let region = d.superblock_region();
    let mut ring = vec![0u8; region.len as usize];
    d.read_region(region, 0, &mut ring).unwrap();
    ring
}

/// Overwrites `bytes` at `offset` in the superblock ring.
pub fn write_ring(root: &Path, offset: u64, bytes: &[u8]) {
    let d = dev(root);
    d.write_region(d.superblock_region(), offset, bytes).unwrap();
    d.sync().unwrap();
}

/// Whether the device holds a superblock ring (it holds, or held, a pool).
pub fn ring_written(root: &Path) -> bool {
    crate::backend::ring_written(root)
}

/// Shard `shard`'s superblock slot.
pub fn read_shard_superblock(root: &Path, shard: u32) -> Vec<u8> {
    dev(root).read_shard_superblock(shard).unwrap()
}

pub fn write_shard_superblock(root: &Path, shard: u32, block: &[u8]) {
    dev(root).write_shard_superblock(shard, block).unwrap();
}

/// Writes garbage over the start of the live index, so it no longer opens.
pub fn corrupt_index(root: &Path) {
    let d = dev(root);
    let label = d.label();
    let copy = label.index_active as u64;
    let offset = copy * label.index_copy_len;
    d.write_region(label.index, offset, b"not a valid redb database").unwrap();
    d.sync().unwrap();
}

/// Every byte a device holds that is not a hole: its regions, and every
/// zone ever written and not since freed (a freed zone is zeroed, which
/// in an image is a hole). What a leakage test searches.
pub fn device_bytes(root: &Path) -> Vec<u8> {
    use nix::unistd::{Whence, lseek};
    use std::os::unix::fs::FileExt;
    let path = lchfs_device::resolve(root);
    let file = std::fs::File::open(&path).unwrap();
    let size = file.metadata().unwrap().len() as i64;
    let mut out = Vec::new();
    let mut at = 0i64;
    while at < size {
        let Ok(data) = lseek(&file, at, Whence::SeekData) else { break };
        let hole = lseek(&file, data, Whence::SeekHole).unwrap_or(size);
        let mut buf = vec![0u8; (hole - data) as usize];
        file.read_exact_at(&mut buf, data as u64).unwrap();
        out.extend_from_slice(&buf);
        at = hole;
    }
    out
}
