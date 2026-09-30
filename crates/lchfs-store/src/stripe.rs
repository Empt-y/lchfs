//! Erasure-coded segments (ARCHITECTURE.md §17.2): a sealed data segment's
//! body split into `k` data shards plus `m` Reed-Solomon parity shards,
//! one shard per device, replacing its N mirror copies. The write
//! path never sees this; a segment is striped by the coalescing daemon
//! once it is cold, and read back through `StripeReader`, which serves a
//! record from the one shard that holds it in the common case and
//! reconstructs from any `k` shards when one is missing.
//!
//! Nothing here is ever updated in place. A stripe is written once; a
//! missing shard is rebuilt as a new one; a repack decodes the live
//! records into a fresh *mirrored* segment. The append-only invariant
//! holds for shards as it does for everything else.

use crate::backend::Vdev;
use crate::segment::{SEGMENT_HEADER_PAGE_SIZE, SegmentError, decode_record_bytes, device, verify_record_with};
use lchfs_device::{SegmentFile, SegmentKind};
use lchfs_format::{
    ExtentLocation, ExtentRecordHeader, Hash32, RecordCrypto, SEGMENT_HEADER_MAGIC, STRIPE_DESCRIPTOR_OFFSET,
    SegmentHeader, SegmentState, StreamKind, StripeDescriptor, finalize_segment_header_checksum,
};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::io;
use std::path::{Path, PathBuf};

/// The `vdev_id` a striped record's index entry is keyed under (§17.2.2).
/// `u16::MAX` sorts last, so a surviving mirror copy is still the
/// preferred replica and a striped one is what failover reaches after
/// the mirrors.
pub const STRIPED: u16 = lchfs_index::STRIPED_VDEV;

/// Shard files are aligned to this so a shard boundary is a page boundary.
const SHARD_ALIGN: u64 = 4096;

/// The device's name for shard `shard_index` of a striped segment.
pub fn shard_kind(shard_index: u8) -> SegmentKind {
    SegmentKind::StripeShard { index: shard_index }
}

/// Every shard index present for `segment_id` on the device at `root`.
pub fn shards_on(root: &Path, segment_id: u64) -> Vec<u8> {
    let Ok(dev) = device(root) else { return Vec::new() };
    dev.segments()
        .into_iter()
        .filter_map(|(kind, id)| match kind {
            SegmentKind::StripeShard { index } if id == segment_id => Some(index),
            _ => None,
        })
        .collect()
}

/// Opens shard `shard_index` of `segment_id` on the device at `root`.
pub fn open_shard(root: &Path, segment_id: u64, shard_index: u8) -> io::Result<SegmentFile> {
    device(root)?.open_segment(shard_kind(shard_index), segment_id)
}

/// Deletes shard `shard_index` of `segment_id` from the device at `root`.
pub fn remove_shard(root: &Path, segment_id: u64, shard_index: u8) -> io::Result<()> {
    device(root)?.remove_segment(shard_kind(shard_index), segment_id)
}

/// Every segment id with a shard file on any of `vdevs`, ascending.
pub fn striped_segment_ids(vdevs: &[Vdev]) -> Vec<u64> {
    let mut ids: Vec<u64> = vdevs.iter().flat_map(|v| segment_ids_with_shards(&v.root)).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// A descriptor that can be acted on: a real Reed-Solomon shape, one
/// device per shard, and sizes that fit the segment's u32 offsets. Read
/// off disk unchecksummed, so every field is checked before it can size
/// an allocation or index a vector.
pub fn descriptor_is_sane(d: &StripeDescriptor) -> bool {
    let total = d.k as usize + d.m as usize;
    d.k >= 2
        && d.m >= 1
        && d.devices.len() == total
        && d.shard_size > 0
        && d.shard_size <= u32::MAX as u64
        && (d.shard_index as usize) < total
        && d.logical_len <= d.shard_size.saturating_mul(d.k as u64)
}

/// Every segment id that has at least one shard on the device at `root`.
pub fn segment_ids_with_shards(root: &Path) -> Vec<u64> {
    let Ok(dev) = device(root) else { return Vec::new() };
    let mut out: Vec<u64> = dev
        .segments()
        .into_iter()
        .filter(|(kind, _)| matches!(kind, SegmentKind::StripeShard { .. }))
        .map(|(_, id)| id)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The records in a segment body held in memory: `(header, file offset)`
/// for each, in order, stopping at the first header that does not parse
/// -- a reassembled body is either whole or not, so there is no damage
/// to resync past. Offsets are file offsets (body offset + header page),
/// the same `ExtentLocation::offset` a mirrored copy would have had.
pub fn scan_body(body: &[u8]) -> Vec<(ExtentRecordHeader, u32)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 < body.len() {
        let Some((header, _consumed)) = crate::segment::parse_record_header(&body[pos..]) else {
            break;
        };
        if header.record_len == 0 || pos + header.record_len as usize > body.len() {
            break;
        }
        out.push((header.clone(), (pos as u64 + SEGMENT_HEADER_PAGE_SIZE) as u32));
        pos += header.record_len as usize;
    }
    out
}

/// Writes one shard -- header page, then its bytes -- as a fresh
/// segment, and syncs it. A shard is only written on a formatted device:
/// never on whatever a pulled device's path now holds.
fn write_shard(root: &Path, segment_id: u64, desc: &StripeDescriptor, bytes: &[u8]) -> io::Result<()> {
    let file = device(root)?.create_segment(shard_kind(desc.shard_index), segment_id)?;
    write_shard_header(&file, segment_id, desc)?;
    file.write_all_at(bytes, SEGMENT_HEADER_PAGE_SIZE)?;
    file.sync_all()
}

fn rs(k: u8, m: u8) -> io::Result<ReedSolomon> {
    ReedSolomon::new(k as usize, m as usize).map_err(|e| io::Error::other(format!("reed-solomon: {e:?}")))
}

/// Splits `body` (a sealed segment's bytes after its header page) into
/// `k` data shards, computes `m` parity shards, and writes one shard on
/// each of `devices` (which must be exactly `k + m` long). Every shard is
/// synced before this returns. Returns the descriptor shard 0 was
/// written with; the others differ only in `shard_index`/`shard_hash`.
pub fn write_stripe(
    body: &[u8],
    segment_id: u64,
    k: u8,
    m: u8,
    devices: &[Vdev],
) -> io::Result<StripeDescriptor> {
    let total = k as usize + m as usize;
    if k < 2 || m < 1 || devices.len() != total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("stripe needs k >= 2, m >= 1 and exactly k + m devices (k={k}, m={m}, devices={})", devices.len()),
        ));
    }
    let shard_size = (body.len() as u64).div_ceil(k as u64).div_ceil(SHARD_ALIGN) * SHARD_ALIGN;
    let shard_size = shard_size.max(SHARD_ALIGN);
    let mut shards: Vec<Vec<u8>> = (0..total).map(|_| vec![0u8; shard_size as usize]).collect();
    for (i, shard) in shards.iter_mut().take(k as usize).enumerate() {
        let start = (i as u64 * shard_size) as usize;
        if start < body.len() {
            let end = (start + shard_size as usize).min(body.len());
            shard[..end - start].copy_from_slice(&body[start..end]);
        }
    }
    rs(k, m)?
        .encode(&mut shards)
        .map_err(|e| io::Error::other(format!("reed-solomon encode: {e:?}")))?;

    let body_hash = Hash32::of(body);
    let mut first = None;
    for (i, (shard, vdev)) in shards.iter().zip(devices).enumerate() {
        let desc = StripeDescriptor {
            k,
            m,
            shard_size,
            shard_index: i as u8,
            devices: devices.iter().map(|v| v.id).collect(),
            logical_len: body.len() as u64,
            body_hash,
            shard_hash: Hash32::of(shard),
        };
        write_shard(&vdev.root, segment_id, &desc, shard)?;
        if first.is_none() {
            first = Some(desc);
        }
    }
    Ok(first.expect("k + m >= 3 shards were written"))
}

/// Rebuilds shard `shard_index` of a stripe from `k` readable siblings and
/// writes it on `onto`. What resilver does for a striped segment whose
/// shard was on a device that is gone.
pub fn rebuild_shard(reader: &StripeReader, shard_index: u8, onto: &Vdev) -> io::Result<()> {
    let desc = &reader.desc;
    let shard = reader.reconstruct_shard(shard_index)?;
    let mut mine = desc.clone();
    mine.shard_index = shard_index;
    mine.shard_hash = Hash32::of(&shard);
    write_shard(&onto.root, reader.segment_id, &mine, &shard)
}

fn write_shard_header(file: &SegmentFile, segment_id: u64, desc: &StripeDescriptor) -> io::Result<()> {
    let mut header = SegmentHeader {
        magic: SEGMENT_HEADER_MAGIC,
        segment_id,
        stream_kind: StreamKind::Data,
        owner_shard: 0,
        state: SegmentState::Striped,
        header_checksum: 0,
    };
    finalize_segment_header_checksum(&mut header);
    let encoded = lchfs_format::encode(&header).expect("SegmentHeader encoding is infallible");
    let encoded_desc = lchfs_format::encode(desc).expect("StripeDescriptor encoding is infallible");
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    assert!(4 + encoded.len() <= STRIPE_DESCRIPTOR_OFFSET, "segment header must fit before the descriptor");
    assert!(
        STRIPE_DESCRIPTOR_OFFSET + 4 + encoded_desc.len() <= page.len(),
        "stripe descriptor must fit in the header page"
    );
    page[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    page[4..4 + encoded.len()].copy_from_slice(&encoded);
    page[STRIPE_DESCRIPTOR_OFFSET..STRIPE_DESCRIPTOR_OFFSET + 4]
        .copy_from_slice(&(encoded_desc.len() as u32).to_le_bytes());
    page[STRIPE_DESCRIPTOR_OFFSET + 4..STRIPE_DESCRIPTOR_OFFSET + 4 + encoded_desc.len()]
        .copy_from_slice(&encoded_desc);
    file.write_all_at(&page, 0)
}

/// Reads a shard's descriptor. `None` if what is there is not a shard.
pub fn read_descriptor(root: &Path, segment_id: u64, shard_index: u8) -> io::Result<Option<StripeDescriptor>> {
    let file = open_shard(root, segment_id, shard_index)?;
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    file.read_exact_at(&mut page, 0)?;
    Ok(parse_descriptor_page(&page))
}

/// The descriptor in a shard file's header page, if the page is one:
/// a `SegmentHeader` in `Striped` state, and a descriptor beside it.
/// Pure on the bytes, so it can be fuzzed; nothing in it is trusted
/// until `descriptor_is_sane` has looked.
pub fn parse_descriptor_page(page: &[u8]) -> Option<StripeDescriptor> {
    if page.len() < SEGMENT_HEADER_PAGE_SIZE as usize {
        return None;
    }
    let header_len = u32::from_le_bytes(page[0..4].try_into().unwrap()) as usize;
    if header_len == 0 || 4 + header_len > STRIPE_DESCRIPTOR_OFFSET {
        return None;
    }
    let header: SegmentHeader = lchfs_format::decode(&page[4..4 + header_len]).ok()?;
    if header.magic != SEGMENT_HEADER_MAGIC || header.state != SegmentState::Striped {
        return None;
    }
    let len = u32::from_le_bytes(
        page[STRIPE_DESCRIPTOR_OFFSET..STRIPE_DESCRIPTOR_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if len == 0 || STRIPE_DESCRIPTOR_OFFSET + 4 + len > page.len() {
        return None;
    }
    lchfs_format::decode(&page[STRIPE_DESCRIPTOR_OFFSET + 4..STRIPE_DESCRIPTOR_OFFSET + 4 + len]).ok()
}

/// One striped segment, opened against whatever shards are reachable.
pub struct StripeReader {
    pub segment_id: u64,
    pub desc: StripeDescriptor,
    /// Shards by shard index; `None` where the shard's device is not
    /// among those offered, or the shard is missing or incomplete.
    shards: Vec<Option<SegmentFile>>,
    /// The device each shard is on, same order.
    roots: Vec<Option<PathBuf>>,
}

impl StripeReader {
    /// Opens the stripe for `segment_id` using `root_of` to find each
    /// shard's device. The descriptor comes from the first shard found;
    /// devices that are offline simply contribute no shard.
    pub fn open(segment_id: u64, root_of: impl Fn(u16) -> Option<PathBuf>, candidates: &[Vdev]) -> io::Result<Self> {
        // The descriptor comes from the first shard whose header page
        // reads, parses and makes sense; a truncated or rotted shard is
        // skipped, not fatal -- its siblings may be fine.
        let mut desc = None;
        'find: for vdev in candidates {
            for i in shards_on(&vdev.root, segment_id) {
                if let Ok(Some(d)) = read_descriptor(&vdev.root, segment_id, i)
                    && descriptor_is_sane(&d)
                {
                    desc = Some(d);
                    break 'find;
                }
            }
        }
        let Some(desc) = desc else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no usable shard of segment {segment_id} on any offered device"),
            ));
        };
        let roots: Vec<Option<PathBuf>> = desc.devices.iter().map(|&vdev_id| root_of(vdev_id)).collect();
        // A shard is exactly a header page plus `shard_size` bytes; any
        // other length is treated as absent, so a torn write never sizes
        // a read.
        let expected_len = SEGMENT_HEADER_PAGE_SIZE + desc.shard_size;
        let shards = roots
            .iter()
            .enumerate()
            .map(|(i, r)| {
                r.as_ref()
                    .and_then(|root| open_shard(root, segment_id, i as u8).ok())
                    .filter(|f| f.len() == expected_len)
            })
            .collect();
        Ok(Self {
            segment_id,
            desc,
            shards,
            roots,
        })
    }

    /// How many shards are readable right now.
    pub fn present(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }

    /// Shard indices with no readable shard.
    pub fn missing(&self) -> Vec<u8> {
        self.shards
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_none())
            .map(|(i, _)| i as u8)
            .collect()
    }

    fn total(&self) -> usize {
        self.desc.k as usize + self.desc.m as usize
    }

    /// Reads `[start, end)` of shard `i` directly, if it is present.
    fn read_shard_range(&self, i: usize, start: u64, end: u64) -> io::Result<Option<Vec<u8>>> {
        let Some(file) = &self.shards[i] else { return Ok(None) };
        let mut buf = vec![0u8; (end - start) as usize];
        match file.read_exact_at(&mut buf, SEGMENT_HEADER_PAGE_SIZE + start) {
            Ok(()) => Ok(Some(buf)),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The rows `[start, end)` of every shard, reconstructing the ones
    /// that are not readable -- or listed in `exclude` -- from any `k`
    /// that are. Reed-Solomon is position-independent, so a row range
    /// decodes on its own.
    fn rows(&self, start: u64, end: u64, exclude: &[usize]) -> io::Result<Vec<Vec<u8>>> {
        let total = self.total();
        let mut rows: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        for i in 0..total {
            rows.push(if exclude.contains(&i) { None } else { self.read_shard_range(i, start, end)? });
        }
        let present = rows.iter().filter(|r| r.is_some()).count();
        if present < self.desc.k as usize {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "segment {} stripe: only {present} of {total} shards usable, need {}",
                    self.segment_id, self.desc.k
                ),
            ));
        }
        if present < total {
            rs(self.desc.k, self.desc.m)?
                .reconstruct(&mut rows)
                .map_err(|e| io::Error::other(format!("reed-solomon reconstruct: {e:?}")))?;
        }
        Ok(rows.into_iter().map(|r| r.expect("reconstructed")).collect())
    }

    /// The whole of shard `i`, reconstructed from its siblings -- never
    /// read from its own file, so a shard whose bytes are wrong is not
    /// rewritten as it stands with a hash that now matches.
    pub fn reconstruct_shard(&self, i: u8) -> io::Result<Vec<u8>> {
        let rows = self.rows(0, self.desc.shard_size, &[i as usize])?;
        Ok(rows[i as usize].clone())
    }

    /// Shard indices whose bytes `[off, off + len)` of the body fall in.
    fn shards_for(&self, off: u64, len: u64) -> Vec<usize> {
        if len == 0 {
            return Vec::new();
        }
        let ss = self.desc.shard_size;
        ((off / ss) as usize..=((off + len - 1) / ss) as usize).collect()
    }

    /// Whether a read of `loc` has to reconstruct: some shard it touches
    /// is not readable.
    pub fn reconstructs(&self, loc: ExtentLocation) -> bool {
        let Ok(off) = Self::body_offset(loc) else { return false };
        self.shards_for(off, loc.len as u64)
            .into_iter()
            .filter(|&i| i < self.shards.len())
            .any(|i| self.shards[i].is_none())
    }

    /// Logical body bytes `[off, off + len)`, from the shard(s) that hold
    /// them; a shard that is missing is reconstructed for just that range.
    pub fn read_body(&self, off: u64, len: u64) -> io::Result<Vec<u8>> {
        self.read_body_excluding(off, len, &[])
    }

    /// `read_body`, treating the shards in `exclude` as if they were
    /// missing: what a retry does after a shard served bytes that did
    /// not verify.
    pub fn read_body_excluding(&self, off: u64, len: u64, exclude: &[usize]) -> io::Result<Vec<u8>> {
        if off.checked_add(len).is_none_or(|end| end > self.desc.logical_len) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("read past the end of striped segment {}", self.segment_id),
            ));
        }
        let ss = self.desc.shard_size;
        let mut out = Vec::with_capacity(len as usize);
        let mut pos = off;
        let end = off + len;
        while pos < end {
            let shard = (pos / ss) as usize;
            let within = pos % ss;
            let take = (ss - within).min(end - pos);
            let direct = if exclude.contains(&shard) {
                None
            } else {
                self.read_shard_range(shard, within, within + take)?
            };
            let piece = match direct {
                Some(bytes) => bytes,
                None => {
                    let rows = self.rows(within, within + take, exclude)?;
                    rows[shard].clone()
                }
            };
            out.extend_from_slice(&piece);
            pos += take;
        }
        Ok(out)
    }

    /// The whole logical body, checked against the descriptor's
    /// `body_hash`. If the straight read does not match, each shard is
    /// verified against its own hash and the ones that fail are
    /// reconstructed from the rest; only a body that hashes right is
    /// returned. What anything that *acts* on a stripe's contents --
    /// repacking it, deleting its shards -- must read through.
    pub fn verified_body(&self) -> io::Result<Vec<u8>> {
        let body = self.read_body(0, self.desc.logical_len)?;
        if Hash32::of(&body) == self.desc.body_hash {
            return Ok(body);
        }
        let mut bad = Vec::new();
        for i in 0..self.total() {
            if self.shards[i].is_some() && !self.verify_shard(i as u8)? {
                bad.push(i);
            }
        }
        let body = self.read_body_excluding(0, self.desc.logical_len, &bad)?;
        if Hash32::of(&body) == self.desc.body_hash {
            return Ok(body);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "segment {} stripe: body does not match its hash even with {} bad shard(s) reconstructed",
                self.segment_id,
                bad.len()
            ),
        ))
    }

    /// A location's offset is a file offset (header page included); a
    /// location that points into the header page is not a record.
    fn body_offset(loc: ExtentLocation) -> io::Result<u64> {
        (loc.offset as u64).checked_sub(SEGMENT_HEADER_PAGE_SIZE).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("offset {} is inside the header page", loc.offset))
        })
    }

    /// The record's bytes, retried through parity when the shard that
    /// served them produced something that does not verify: a shard
    /// present but wrong is a missing shard as far as a read is
    /// concerned, so long as `k` others are there.
    fn record_bytes(
        &self,
        loc: ExtentLocation,
        check: impl Fn(Vec<u8>) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError>,
    ) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        let (off, len) = (Self::body_offset(loc)?, loc.len as u64);
        let first = check(self.read_body(off, len)?);
        let Err(e) = first else { return first };
        let touched = self.shards_for(off, len);
        if self.present() <= self.desc.k as usize || touched.iter().all(|&i| self.shards[i].is_none()) {
            return Err(e);
        }
        let bytes = self.read_body_excluding(off, len, &touched)?;
        check(bytes)
    }

    /// `SegmentReader::read_record` for a striped segment: the same framing
    /// and content-hash checks, on bytes assembled from shards.
    pub fn read_record(&self, loc: ExtentLocation) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        self.read_record_with(loc, crate::segment::plaintext())
    }

    /// `read_record` for a record of any epoch (see
    /// `SegmentReader::read_record_with`). An envelope that fails to
    /// authenticate counts as a bad read, so a damaged shard is
    /// reconstructed around exactly as a failed content hash would be.
    pub fn read_record_with(
        &self,
        loc: ExtentLocation,
        crypto: &RecordCrypto,
    ) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        self.record_bytes(loc, |bytes| {
            let (header, payload) = decode_record_bytes(bytes)?;
            verify_record_with(&header, payload, self.segment_id, loc.offset, crypto)
        })
    }

    /// `SegmentReader::read_record_raw` for a striped segment.
    pub fn read_record_raw(&self, loc: ExtentLocation) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        self.read_record_raw_with(loc, crate::segment::plaintext())
    }

    /// `SegmentReader::read_record_raw_with` for a striped segment.
    pub fn read_record_raw_with(
        &self,
        loc: ExtentLocation,
        crypto: &RecordCrypto,
    ) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        self.record_bytes(loc, |bytes| {
            let (header, payload) = decode_record_bytes(bytes)?;
            verify_record_with(&header, payload.clone(), self.segment_id, loc.offset, crypto)?;
            Ok((header, payload))
        })
    }

    /// Verifies one shard's bytes against the hash in its own
    /// descriptor. `Ok(false)` when the shard is unreadable or does not
    /// match; either way it needs rebuilding.
    pub fn verify_shard(&self, i: u8) -> io::Result<bool> {
        let Some(root) = &self.roots[i as usize] else { return Ok(false) };
        let Some(bytes) = self.read_shard_range(i as usize, 0, self.desc.shard_size)? else {
            return Ok(false);
        };
        let Some(own) = read_descriptor(root, self.segment_id, i)? else { return Ok(false) };
        Ok(own.shard_index == i && Hash32::of(&bytes) == own.shard_hash)
    }
}
