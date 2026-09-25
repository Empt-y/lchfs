//! Device layout: how a pool's bytes sit on a raw block device.
//!
//! A pool no longer lives in a directory of files on some other
//! filesystem; each of its devices is formatted, like `mkfs`, into fixed
//! regions and a zone area:
//!
//! ```text
//! 0                 label A (4 KiB)
//! superblock        the superblock ring (16 x 4 KiB, as before)
//! keyring           two alternating copies
//! shard superblocks one 4 KiB slot per logical shard
//! scratch           one 4 KiB sector a device-rejoin probe may overwrite
//! index             two copies of the index region (redb), one active
//! zones             zone_count x zone_size, each opened by a zone header
//! end - 4 KiB       label B, a copy of label A
//! ```
//!
//! Segments -- data, meta, delta and stripe shards alike -- are stored in
//! zones. A zone header names the segment a zone belongs to and its place
//! in it, so the zone headers are to a device what file names were to a
//! directory. A zone's payload is zeroed before the zone is used again,
//! so a record scan never meets an earlier segment's records.
//!
//! No I/O lives in this module, only the byte layouts.

use serde::{Deserialize, Serialize};

/// Magic of a device label, ASCII "LCHFSDEV".
pub const DEVICE_LABEL_MAGIC: [u8; 8] = *b"LCHFSDEV";

/// Magic of a zone header, ASCII "LCHFSZON".
pub const ZONE_HEADER_MAGIC: [u8; 8] = *b"LCHFSZON";

/// The device layout's own version, independent of `FORMAT_VERSION`
/// (which versions the records and objects stored in it).
pub const DEVICE_LAYOUT_VERSION: u32 = 1;

/// Size of a label, a zone header and every fixed slot.
pub const DEVICE_BLOCK: u64 = 4096;

/// `(offset, length)` of a region, in bytes from the start of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub offset: u64,
    pub len: u64,
}

impl Region {
    pub fn end(&self) -> u64 {
        self.offset + self.len
    }
}

/// Where everything on a formatted device is. Written at offset 0 and again
/// in the device's last 4 KiB; the copy with the higher `generation` whose
/// checksum holds wins, so a torn label write leaves the other one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLabel {
    pub magic: [u8; 8],
    pub layout_version: u32,
    /// Drawn at format time. Zone headers carry it, so a zone header left
    /// by an earlier format of the same disk is not taken for this one's.
    pub device_uuid: [u8; 16],
    /// Bumped on every label write.
    pub generation: u64,
    /// Bytes the layout covers (the device's size when it was formatted).
    pub device_size: u64,
    pub superblock: Region,
    /// Two copies of `keyring_copy_len` bytes each, back to back.
    pub keyring: Region,
    pub keyring_copy_len: u64,
    pub shard_superblocks: Region,
    pub scratch: Region,
    /// Two copies of `index_copy_len` bytes each, back to back.
    pub index: Region,
    pub index_copy_len: u64,
    /// Which index copy is live (0 or 1).
    pub index_active: u8,
    /// The live index copy's logical length: redb's "file size".
    pub index_len: [u64; 2],
    /// Start of zone 0.
    pub zones_offset: u64,
    pub zone_size: u64,
    pub zone_count: u64,
    pub checksum: u32,
}

/// What a zone is being used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZoneState {
    /// Unused, payload zero.
    Free,
    /// Part of a segment.
    Owned,
    /// Its segment was deleted; the payload is being zeroed. A mount that
    /// finds one finishes the job.
    Freeing,
}

/// Which kind of segment a zone belongs to -- what a file's directory and
/// extension used to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SegmentKind {
    Data,
    Meta,
    /// A logical shard's delta stream.
    Delta { shard: u32 },
    /// Shard `index` of an erasure-coded data segment.
    StripeShard { index: u8 },
}

/// The first 4 KiB of every zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneHeader {
    pub magic: [u8; 8],
    pub device_uuid: [u8; 16],
    pub state: ZoneState,
    pub kind: SegmentKind,
    pub segment_id: u64,
    /// This zone's place in its segment: 0 holds the segment's first
    /// `zone_size - DEVICE_BLOCK` bytes.
    pub ordinal: u32,
    /// Bytes of the segment written as of its last sync -- what a file's
    /// length was. Kept in ordinal 0's header; 0 in the others.
    pub written_len: u64,
    pub checksum: u32,
}

fn crc_of<T: Serialize>(value: &T) -> u32 {
    crc32fast::hash(&bincode::serialize(value).expect("layout types serialize"))
}

impl DeviceLabel {
    pub fn compute_checksum(&self) -> u32 {
        let mut zeroed = self.clone();
        zeroed.checksum = 0;
        crc_of(&zeroed)
    }

    pub fn finalize(&mut self) {
        self.checksum = self.compute_checksum();
    }

    /// Magic, version and checksum hold, and the regions fit the device in
    /// order without overlapping.
    pub fn is_valid(&self) -> bool {
        if self.magic != DEVICE_LABEL_MAGIC
            || self.layout_version != DEVICE_LAYOUT_VERSION
            || self.checksum != self.compute_checksum()
            || self.index_active > 1
            || self.zone_size <= DEVICE_BLOCK
        {
            return false;
        }
        let ordered = [
            Region { offset: 0, len: DEVICE_BLOCK },
            self.superblock,
            self.keyring,
            self.shard_superblocks,
            self.scratch,
            self.index,
        ];
        let zones_end = self
            .zone_size
            .checked_mul(self.zone_count)
            .and_then(|z| z.checked_add(self.zones_offset));
        ordered.windows(2).all(|w| w[0].end() <= w[1].offset)
            && self.index.end() <= self.zones_offset
            && self.keyring.len == 2 * self.keyring_copy_len
            && self.index.len == 2 * self.index_copy_len
            && self.index_len.iter().all(|&l| l <= self.index_copy_len)
            && zones_end.is_some_and(|end| end + DEVICE_BLOCK <= self.device_size)
    }
}

impl ZoneHeader {
    pub fn compute_checksum(&self) -> u32 {
        let mut zeroed = self.clone();
        zeroed.checksum = 0;
        crc_of(&zeroed)
    }

    pub fn finalize(&mut self) {
        self.checksum = self.compute_checksum();
    }

    /// Magic and checksum hold, and it belongs to the device `device_uuid`.
    pub fn is_valid_for(&self, device_uuid: &[u8; 16]) -> bool {
        self.magic == ZONE_HEADER_MAGIC && &self.device_uuid == device_uuid && self.checksum == self.compute_checksum()
    }
}

/// Encodes a label or zone header into one zero-padded 4 KiB block:
/// `[u32 LE len][bincode]`.
pub fn encode_block<T: Serialize>(value: &T) -> Vec<u8> {
    let encoded = bincode::serialize(value).expect("layout types serialize");
    assert!(encoded.len() + 4 <= DEVICE_BLOCK as usize, "a layout block must fit in 4 KiB");
    let mut block = vec![0u8; DEVICE_BLOCK as usize];
    block[..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    block[4..4 + encoded.len()].copy_from_slice(&encoded);
    block
}

/// The inverse of `encode_block`; `None` for anything that does not decode.
pub fn decode_block<T: serde::de::DeserializeOwned>(block: &[u8]) -> Option<T> {
    let len = u32::from_le_bytes(block.get(..4)?.try_into().ok()?) as usize;
    if len == 0 || len + 4 > block.len() {
        return None;
    }
    bincode::deserialize(&block[4..4 + len]).ok()
}
