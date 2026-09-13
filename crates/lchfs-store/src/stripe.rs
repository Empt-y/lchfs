//! Erasure-coded segments (ARCHITECTURE.md §17.2): a sealed data segment's
//! body split into `k` data shards plus `m` Reed-Solomon parity shards,
//! one shard file per device, replacing its N mirror copies. The write
//! path never sees this; a segment is striped by the coalescing daemon
//! once it is cold, and read back through `StripeReader`, which serves a
//! record from the one shard that holds it in the common case and
//! reconstructs from any `k` shards when one is missing.
//!
//! Nothing here is ever updated in place. A stripe is written once; a
//! missing shard is rebuilt as a new file; a repack decodes the live
//! records into a fresh *mirrored* segment. The append-only invariant
//! holds for shards as it does for everything else.

use crate::backend::Vdev;
use crate::segment::{
    SEGMENT_HEADER_PAGE_SIZE, SegmentError, decode_record_bytes, segment_dir, verify_record,
};
use lchfs_format::{
    ExtentLocation, ExtentRecordHeader, Hash32, SEGMENT_HEADER_MAGIC, STRIPE_DESCRIPTOR_OFFSET,
    SegmentHeader, SegmentState, StreamKind, StripeDescriptor, finalize_segment_header_checksum,
};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// The `vdev_id` a striped record's index entry is keyed under (§17.2.2).
/// `u16::MAX` sorts last, so a surviving mirror copy is still the
/// preferred replica and a striped one is what failover reaches after
/// the mirrors.
pub const STRIPED: u16 = u16::MAX;

/// Shard files are aligned to this so a shard boundary is a page boundary.
const SHARD_ALIGN: u64 = 4096;

/// `segments/data/<segment_id>.ec<shard_index>` under a device root.
pub fn shard_path(root: &Path, segment_id: u64, shard_index: u8) -> PathBuf {
    segment_dir(root, StreamKind::Data).join(format!("{segment_id}.ec{shard_index}"))
}

/// Every shard index present for `segment_id` under `root`.
pub fn shards_on(root: &Path, segment_id: u64) -> Vec<u8> {
    let prefix = format!("{segment_id}.ec");
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(segment_dir(root, StreamKind::Data)) {
        for e in rd.flatten() {
            if let Some(rest) = e.file_name().to_str().and_then(|n| n.strip_prefix(&prefix))
                && let Ok(i) = rest.parse::<u8>()
            {
                out.push(i);
            }
        }
    }
    out.sort_unstable();
    out
}

fn rs(k: u8, m: u8) -> io::Result<ReedSolomon> {
    ReedSolomon::new(k as usize, m as usize).map_err(|e| io::Error::other(format!("reed-solomon: {e:?}")))
}

/// Splits `body` (a sealed segment's bytes after its header page) into
/// `k` data shards, computes `m` parity shards, and writes one shard file
/// on each of `devices` (which must be exactly `k + m` long). Every file
/// is fsync'd before this returns. Returns the descriptor shard 0 was
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
        std::fs::create_dir_all(segment_dir(&vdev.root, StreamKind::Data))?;
        let path = shard_path(&vdev.root, segment_id, i as u8);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        write_shard_header(&file, segment_id, &desc)?;
        file.write_all_at(shard, SEGMENT_HEADER_PAGE_SIZE)?;
        file.sync_all()?;
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
    std::fs::create_dir_all(segment_dir(&onto.root, StreamKind::Data))?;
    let path = shard_path(&onto.root, reader.segment_id, shard_index);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    write_shard_header(&file, reader.segment_id, &mine)?;
    file.write_all_at(&shard, SEGMENT_HEADER_PAGE_SIZE)?;
    file.sync_all()
}

fn write_shard_header(file: &File, segment_id: u64, desc: &StripeDescriptor) -> io::Result<()> {
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

/// Reads a shard file's descriptor. `None` if the file is not a shard.
pub fn read_descriptor(path: &Path) -> io::Result<Option<StripeDescriptor>> {
    let file = File::open(path)?;
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    file.read_exact_at(&mut page, 0)?;
    let header_len = u32::from_le_bytes(page[0..4].try_into().unwrap()) as usize;
    if header_len == 0 || 4 + header_len > STRIPE_DESCRIPTOR_OFFSET {
        return Ok(None);
    }
    let header: SegmentHeader = match lchfs_format::decode(&page[4..4 + header_len]) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };
    if header.magic != SEGMENT_HEADER_MAGIC || header.state != SegmentState::Striped {
        return Ok(None);
    }
    let len = u32::from_le_bytes(
        page[STRIPE_DESCRIPTOR_OFFSET..STRIPE_DESCRIPTOR_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if len == 0 || STRIPE_DESCRIPTOR_OFFSET + 4 + len > page.len() {
        return Ok(None);
    }
    Ok(lchfs_format::decode(&page[STRIPE_DESCRIPTOR_OFFSET + 4..STRIPE_DESCRIPTOR_OFFSET + 4 + len]).ok())
}

/// One striped segment, opened against whatever shards are reachable.
pub struct StripeReader {
    pub segment_id: u64,
    pub desc: StripeDescriptor,
    /// Shard files by shard index; `None` where the shard's device is not
    /// among those offered, or the file is missing.
    shards: Vec<Option<File>>,
    /// Where each opened shard came from, same order.
    paths: Vec<Option<PathBuf>>,
}

impl StripeReader {
    /// Opens the stripe for `segment_id` using `root_of` to find each
    /// shard's device. The descriptor comes from the first shard file
    /// found; devices that are offline simply contribute no shard.
    pub fn open(segment_id: u64, root_of: impl Fn(u16) -> Option<PathBuf>, candidates: &[Vdev]) -> io::Result<Self> {
        let mut desc = None;
        for vdev in candidates {
            for i in shards_on(&vdev.root, segment_id) {
                if let Some(d) = read_descriptor(&shard_path(&vdev.root, segment_id, i))? {
                    desc = Some(d);
                    break;
                }
            }
            if desc.is_some() {
                break;
            }
        }
        let Some(desc) = desc else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no shard of segment {segment_id} on any offered device"),
            ));
        };
        let paths: Vec<Option<PathBuf>> = desc
            .devices
            .iter()
            .enumerate()
            .map(|(i, &vdev_id)| root_of(vdev_id).map(|root| shard_path(&root, segment_id, i as u8)))
            .collect();
        let shards = paths
            .iter()
            .map(|p| p.as_ref().and_then(|p| File::open(p).ok()))
            .collect();
        Ok(Self {
            segment_id,
            desc,
            shards,
            paths,
        })
    }

    /// How many shards are readable right now.
    pub fn present(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }

    /// Shard indices with no readable file.
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

    /// Reads `[start, end)` of shard `i` directly, if its file is present.
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
    /// that are not readable from any `k` that are. Reed-Solomon is
    /// position-independent, so a row range decodes on its own.
    fn rows(&self, start: u64, end: u64) -> io::Result<Vec<Vec<u8>>> {
        let total = self.total();
        let mut rows: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        for i in 0..total {
            rows.push(self.read_shard_range(i, start, end)?);
        }
        let present = rows.iter().filter(|r| r.is_some()).count();
        if present < self.desc.k as usize {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "segment {} stripe: only {present} of {total} shards readable, need {}",
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

    /// The whole of shard `i`, reconstructed if need be.
    pub fn reconstruct_shard(&self, i: u8) -> io::Result<Vec<u8>> {
        let rows = self.rows(0, self.desc.shard_size)?;
        Ok(rows[i as usize].clone())
    }

    /// Logical body bytes `[off, off + len)`, from the shard(s) that hold
    /// them; a shard that is missing is reconstructed for just that range.
    pub fn read_body(&self, off: u64, len: u64) -> io::Result<Vec<u8>> {
        if off + len > self.desc.logical_len {
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
            let piece = match self.read_shard_range(shard, within, within + take)? {
                Some(bytes) => bytes,
                None => {
                    let rows = self.rows(within, within + take)?;
                    rows[shard].clone()
                }
            };
            out.extend_from_slice(&piece);
            pos += take;
        }
        Ok(out)
    }

    fn body_offset(loc: ExtentLocation) -> u64 {
        loc.offset as u64 - SEGMENT_HEADER_PAGE_SIZE
    }

    /// `SegmentReader::read_record` for a striped segment: the same framing
    /// and content-hash checks, on bytes assembled from shards.
    pub fn read_record(&self, loc: ExtentLocation) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        let bytes = self.read_body(Self::body_offset(loc), loc.len as u64)?;
        let (header, payload) = decode_record_bytes(bytes)?;
        let decompressed = verify_record(&header, payload, self.segment_id, loc.offset)?;
        Ok((header, decompressed))
    }

    /// `SegmentReader::read_record_raw` for a striped segment.
    pub fn read_record_raw(&self, loc: ExtentLocation) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        let bytes = self.read_body(Self::body_offset(loc), loc.len as u64)?;
        let (header, payload) = decode_record_bytes(bytes)?;
        verify_record(&header, payload.clone(), self.segment_id, loc.offset)?;
        Ok((header, payload))
    }

    /// Verifies one shard file's bytes against the hash in its own
    /// descriptor. `Ok(false)` when the shard is unreadable or does not
    /// match; either way it needs rebuilding.
    pub fn verify_shard(&self, i: u8) -> io::Result<bool> {
        let Some(path) = &self.paths[i as usize] else { return Ok(false) };
        let Some(bytes) = self.read_shard_range(i as usize, 0, self.desc.shard_size)? else {
            return Ok(false);
        };
        let Some(own) = read_descriptor(path)? else { return Ok(false) };
        Ok(own.shard_index == i && Hash32::of(&bytes) == own.shard_hash)
    }
}
