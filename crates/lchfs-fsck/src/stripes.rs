//! Striped (erasure-coded) segments, checked from the on-disk format
//! alone (ARCHITECTURE.md §17.2.2): one `segments/data/<id>.ec<i>` file
//! per device, each a header page (`SegmentHeader` in `Striped` state,
//! the `StripeDescriptor` beside it at `STRIPE_DESCRIPTOR_OFFSET`) and
//! then `shard_size` bytes of shard. Data shard `i` is logical body bytes
//! `[i·ss, (i+1)·ss)`; parity shards are Reed-Solomon over the data
//! shards row by row.
//!
//! Like the rest of this crate, nothing here goes through the engine's
//! `StripeReader`: that is the code being audited. The shard files are
//! parsed here, the parity is recomputed here, and a rebuilt shard is
//! written here, from the documented layout and the same GF(2⁸) codec.

use crate::FsckError;
use lchfs_format::{
    ExtentLocation, Hash32, SEGMENT_HEADER_MAGIC, STRIPE_DESCRIPTOR_OFFSET, SegmentHeader, SegmentState,
    StreamKind, StripeDescriptor, finalize_segment_header_checksum,
};
use lchfs_store::segment::{SEGMENT_HEADER_PAGE_SIZE, decode_record_bytes, verify_record};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// One shard file as found on one device.
struct ShardFile {
    vdev_id: u16,
    path: PathBuf,
}

/// A striped segment as fsck sees it: the reference descriptor and, for
/// each shard index, the file that holds a shard that verified. Reads go
/// straight to a data shard when it verified and are reconstructed from
/// any `k` good shards otherwise, so the walk can read every record of a
/// stripe that is short a shard -- and report, separately, that it is.
pub struct Stripe {
    pub segment_id: u64,
    pub desc: StripeDescriptor,
    /// `good[i]` is the verified shard `i`, if any device given holds one.
    good: Vec<Option<File>>,
}

impl Stripe {
    fn total(&self) -> usize {
        self.desc.k as usize + self.desc.m as usize
    }

    /// How many shards verified.
    pub fn present(&self) -> usize {
        self.good.iter().filter(|g| g.is_some()).count()
    }

    /// Whether at least `k` shards verified, so every byte is readable.
    pub fn recoverable(&self) -> bool {
        self.present() >= self.desc.k as usize
    }

    fn shard_rows(&self, i: usize, start: u64, end: u64) -> Option<Vec<u8>> {
        let file = self.good[i].as_ref()?;
        let mut buf = vec![0u8; (end - start) as usize];
        file.read_exact_at(&mut buf, SEGMENT_HEADER_PAGE_SIZE + start).ok()?;
        Some(buf)
    }

    /// Rows `[start, end)` of every shard, reconstructing the absent ones.
    fn rows(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, String> {
        let total = self.total();
        let mut rows: Vec<Option<Vec<u8>>> = (0..total).map(|i| self.shard_rows(i, start, end)).collect();
        let present = rows.iter().filter(|r| r.is_some()).count();
        if present < self.desc.k as usize {
            return Err(format!("only {present} of {total} shards readable, need {}", self.desc.k));
        }
        if present < total {
            codec(self.desc.k, self.desc.m)?
                .reconstruct(&mut rows)
                .map_err(|e| format!("reed-solomon reconstruct: {e:?}"))?;
        }
        Ok(rows.into_iter().map(|r| r.expect("every row is present after reconstruct")).collect())
    }

    /// Logical body bytes `[off, off + len)`.
    pub fn read_body(&self, off: u64, len: u64) -> Result<Vec<u8>, String> {
        if off + len > self.desc.logical_len {
            return Err(format!("read past the end of striped segment {}", self.segment_id));
        }
        let ss = self.desc.shard_size;
        let mut out = Vec::with_capacity(len as usize);
        let mut pos = off;
        while pos < off + len {
            let shard = (pos / ss) as usize;
            let within = pos % ss;
            let take = (ss - within).min(off + len - pos);
            match self.shard_rows(shard, within, within + take) {
                Some(bytes) => out.extend_from_slice(&bytes),
                None => out.extend_from_slice(&self.rows(within, within + take)?[shard]),
            }
            pos += take;
        }
        Ok(out)
    }

    /// The full verifying read of one record, on bytes assembled from the
    /// shards: `SegmentReader::read_record`'s checks, same order.
    pub fn read_record(&self, loc: ExtentLocation) -> Result<Vec<u8>, String> {
        let bytes = self.read_body(loc.offset as u64 - SEGMENT_HEADER_PAGE_SIZE, loc.len as u64)?;
        let (header, payload) = decode_record_bytes(bytes).map_err(|e| e.to_string())?;
        verify_record(&header, payload, self.segment_id, loc.offset).map_err(|e| e.to_string())
    }

}

/// What a stripe scan found.
#[derive(Default)]
pub struct StripeScan {
    pub stripes: HashMap<u64, Stripe>,
    /// `hash -> location` for every record in every recoverable stripe.
    pub locations: HashMap<Hash32, ExtentLocation>,
    pub findings: Vec<FsckError>,
}

fn codec(k: u8, m: u8) -> Result<ReedSolomon, String> {
    ReedSolomon::new(k as usize, m as usize).map_err(|e| format!("reed-solomon: {e:?}"))
}

/// Every `<id>.ec<i>` under a device's data directory.
fn shard_files(root: &Path) -> Vec<(u64, u8, PathBuf)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root.join("segments").join("data")) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let Some((stem, ext)) = name.split_once('.') else { continue };
        if let Some(index) = ext.strip_prefix("ec")
            && let (Ok(id), Ok(i)) = (stem.parse::<u64>(), index.parse::<u8>())
        {
            out.push((id, i, path));
        }
    }
    out
}

/// Parses a shard file's header page from the documented layout.
fn read_shard_header(path: &Path) -> Result<Option<(SegmentHeader, StripeDescriptor)>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    file.read_exact_at(&mut page, 0).map_err(|e| e.to_string())?;
    let header_len = u32::from_le_bytes(page[0..4].try_into().unwrap()) as usize;
    if header_len == 0 || 4 + header_len > STRIPE_DESCRIPTOR_OFFSET {
        return Ok(None);
    }
    let Ok(header) = lchfs_format::decode::<SegmentHeader>(&page[4..4 + header_len]) else {
        return Ok(None);
    };
    if header.magic != SEGMENT_HEADER_MAGIC || header.state != SegmentState::Striped {
        return Ok(None);
    }
    let at = STRIPE_DESCRIPTOR_OFFSET;
    let desc_len = u32::from_le_bytes(page[at..at + 4].try_into().unwrap()) as usize;
    if desc_len == 0 || at + 4 + desc_len > page.len() {
        return Ok(None);
    }
    Ok(lchfs_format::decode::<StripeDescriptor>(&page[at + 4..at + 4 + desc_len])
        .ok()
        .map(|d| (header, d)))
}

/// The fields every shard of one stripe must agree on.
fn descriptor_difference(a: &StripeDescriptor, b: &StripeDescriptor) -> Option<String> {
    if (a.k, a.m) != (b.k, b.m) {
        return Some(format!("k+m {}+{} vs {}+{}", a.k, a.m, b.k, b.m));
    }
    if a.shard_size != b.shard_size {
        return Some(format!("shard_size {} vs {}", a.shard_size, b.shard_size));
    }
    if a.devices != b.devices {
        return Some(format!("devices {:?} vs {:?}", a.devices, b.devices));
    }
    if a.logical_len != b.logical_len {
        return Some(format!("logical_len {} vs {}", a.logical_len, b.logical_len));
    }
    if a.body_hash != b.body_hash {
        return Some("body_hash differs".into());
    }
    None
}

/// Scans the shard files on every device given and checks each stripe
/// (§17.2.4 "fsck"): descriptor agreement across its shards, every shard
/// present on the device the descriptor names, each shard's bytes against
/// its own hash, the parity against the data shards, and the reassembled
/// body against the stripe's body hash. Records of every recoverable
/// stripe are added to `locations` at the offsets a mirror copy would
/// have had, so a DAG walk reads striped data like any other.
///
/// `devices` is `(vdev_id, root)` per device given. A shard whose device
/// was not given is not reported missing -- `VdevAbsent` already says the
/// device is not here -- but it counts against the `k` a stripe needs.
pub fn scan_stripes(devices: &[(u16, &Path)]) -> StripeScan {
    let mut scan = StripeScan::default();
    let given: HashMap<u16, &Path> = devices.iter().copied().collect();

    let mut by_segment: HashMap<u64, Vec<(u8, ShardFile)>> = HashMap::new();
    for &(vdev_id, root) in devices {
        for (segment_id, index, path) in shard_files(root) {
            by_segment
                .entry(segment_id)
                .or_default()
                .push((index, ShardFile { vdev_id, path }));
        }
    }
    let mut ids: Vec<u64> = by_segment.keys().copied().collect();
    ids.sort_unstable();

    for segment_id in ids {
        let files = by_segment.remove(&segment_id).unwrap();
        // Descriptors first: the reference is the first shard that parses;
        // every other shard must agree with it on everything but its own
        // index and hash.
        let mut reference: Option<StripeDescriptor> = None;
        let mut parsed: Vec<(u8, ShardFile, StripeDescriptor)> = Vec::new();
        for (index, file) in files {
            match read_shard_header(&file.path) {
                Ok(Some((header, desc))) => {
                    if header.segment_id != segment_id {
                        scan.findings.push(FsckError::StripeShardCorrupt {
                            segment_id,
                            shard_index: index,
                            vdev_id: file.vdev_id,
                            detail: format!("header says segment {}", header.segment_id),
                        });
                        continue;
                    }
                    if let Some(r) = &reference
                        && let Some(detail) = descriptor_difference(r, &desc)
                    {
                        scan.findings.push(FsckError::StripeInconsistent {
                            segment_id,
                            detail: format!("shard {index} on vdev {} disagrees with its siblings: {detail}", file.vdev_id),
                        });
                        continue;
                    }
                    if reference.is_none() {
                        reference = Some(desc.clone());
                    }
                    parsed.push((index, file, desc));
                }
                Ok(None) => scan.findings.push(FsckError::StripeShardCorrupt {
                    segment_id,
                    shard_index: index,
                    vdev_id: file.vdev_id,
                    detail: "header page does not describe a shard".into(),
                }),
                Err(detail) => scan.findings.push(FsckError::StripeShardCorrupt {
                    segment_id,
                    shard_index: index,
                    vdev_id: file.vdev_id,
                    detail,
                }),
            }
        }
        let Some(desc) = reference else {
            scan.findings.push(FsckError::StripeInconsistent {
                segment_id,
                detail: "no shard file carries a readable descriptor".into(),
            });
            continue;
        };
        let total = desc.k as usize + desc.m as usize;
        if desc.devices.len() != total
            || desc.k < 2
            || desc.m < 1
            || desc.shard_size == 0
            || desc.shard_size > u32::MAX as u64
            || desc.logical_len > desc.shard_size.saturating_mul(desc.k as u64)
        {
            scan.findings.push(FsckError::StripeInconsistent {
                segment_id,
                detail: format!(
                    "descriptor is malformed: k={} m={} shard_size={} logical_len={} devices={:?}",
                    desc.k, desc.m, desc.shard_size, desc.logical_len, desc.devices
                ),
            });
            continue;
        }
        let expected_len = SEGMENT_HEADER_PAGE_SIZE + desc.shard_size;

        // Each shard's bytes against its own hash, on the device the
        // descriptor says it belongs on. A shard file that is there but
        // wrong is corrupt, not missing; only an index no device given
        // has a file for is missing.
        let mut good: Vec<Option<File>> = (0..total).map(|_| None).collect();
        let mut seen: Vec<bool> = vec![false; total];
        for (index, file, own) in parsed {
            let i = index as usize;
            if i < total {
                seen[i] = true;
            }
            if i >= total || own.shard_index != index {
                scan.findings.push(FsckError::StripeShardCorrupt {
                    segment_id,
                    shard_index: index,
                    vdev_id: file.vdev_id,
                    detail: format!("file is shard {index} but its descriptor says shard {}", own.shard_index),
                });
                continue;
            }
            if desc.devices[i] != file.vdev_id {
                scan.findings.push(FsckError::StripeShardCorrupt {
                    segment_id,
                    shard_index: index,
                    vdev_id: file.vdev_id,
                    detail: format!("descriptor places shard {index} on vdev {}", desc.devices[i]),
                });
                continue;
            }
            // The file is exactly a header page plus the shard, and that is
            // checked before its claimed size is allowed to size a buffer:
            // fsck reads corrupt pools for a living and must not be made
            // to allocate by a number on disk.
            let bytes = File::open(&file.path).and_then(|f| {
                let len = f.metadata()?.len();
                if len != expected_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("file is {len} bytes, a shard of this stripe is {expected_len}"),
                    ));
                }
                let mut buf = vec![0u8; desc.shard_size as usize];
                f.read_exact_at(&mut buf, SEGMENT_HEADER_PAGE_SIZE).map(|()| (f, buf))
            });
            match bytes {
                Ok((f, buf)) if Hash32::of(&buf) == own.shard_hash => good[i] = Some(f),
                Ok(_) => scan.findings.push(FsckError::StripeShardCorrupt {
                    segment_id,
                    shard_index: index,
                    vdev_id: file.vdev_id,
                    detail: "shard bytes do not match the descriptor's shard_hash".into(),
                }),
                Err(e) => scan.findings.push(FsckError::StripeShardCorrupt {
                    segment_id,
                    shard_index: index,
                    vdev_id: file.vdev_id,
                    detail: format!("short or unreadable: {e}"),
                }),
            }
        }
        for (i, slot) in good.iter().enumerate() {
            if slot.is_none() && !seen[i] && given.contains_key(&desc.devices[i]) {
                scan.findings.push(FsckError::StripeShardMissing {
                    segment_id,
                    shard_index: i as u8,
                    vdev_id: desc.devices[i],
                });
            }
        }

        let stripe = Stripe { segment_id, desc, good };
        if !stripe.recoverable() {
            scan.findings.push(FsckError::StripeUnrecoverable {
                segment_id,
                readable: stripe.present(),
                needed: stripe.desc.k,
            });
            scan.stripes.insert(segment_id, stripe);
            continue;
        }

        // Parity: recompute from the (reconstructed where need be) data
        // shards and compare with every parity shard that verified. A
        // parity shard whose own hash matched but whose contents disagree
        // with the data means the stripe was written wrong, which no
        // per-file hash can see.
        match stripe.rows(0, stripe.desc.shard_size) {
            Ok(rows) => {
                let k = stripe.desc.k as usize;
                let mut recomputed: Vec<Vec<u8>> = rows[..k].to_vec();
                recomputed.extend((k..total).map(|_| vec![0u8; stripe.desc.shard_size as usize]));
                match codec(stripe.desc.k, stripe.desc.m).and_then(|c| c.encode(&mut recomputed).map_err(|e| format!("{e:?}"))) {
                    Ok(()) => {
                        for j in k..total {
                            if stripe.good[j].is_some() && recomputed[j] != rows[j] {
                                scan.findings.push(FsckError::StripeInconsistent {
                                    segment_id,
                                    detail: format!("parity shard {j} does not match the data shards"),
                                });
                            }
                        }
                    }
                    Err(detail) => scan.findings.push(FsckError::StripeInconsistent { segment_id, detail }),
                }
                let mut body: Vec<u8> = rows[..k].concat();
                body.truncate(stripe.desc.logical_len as usize);
                if Hash32::of(&body) != stripe.desc.body_hash {
                    scan.findings.push(FsckError::StripeInconsistent {
                        segment_id,
                        detail: "reassembled body does not match the descriptor's body_hash".into(),
                    });
                } else {
                    for (header, offset) in lchfs_store::stripe::scan_body(&body) {
                        scan.locations.insert(
                            header.content_hash,
                            ExtentLocation { segment_id, offset, len: header.record_len },
                        );
                    }
                }
            }
            Err(detail) => scan.findings.push(FsckError::StripeInconsistent { segment_id, detail }),
        }
        scan.stripes.insert(segment_id, stripe);
    }
    scan
}

/// Writes shard `index` of `stripe` onto `root` from the documented
/// layout: header page, descriptor with this shard's index and hash, the
/// shard bytes, fsync.
fn write_shard(root: &Path, stripe: &Stripe, index: u8, bytes: &[u8]) -> Result<(), String> {
    let mut desc = stripe.desc.clone();
    desc.shard_index = index;
    desc.shard_hash = Hash32::of(bytes);
    let mut header = SegmentHeader {
        magic: SEGMENT_HEADER_MAGIC,
        segment_id: stripe.segment_id,
        stream_kind: StreamKind::Data,
        owner_shard: 0,
        state: SegmentState::Striped,
        header_checksum: 0,
    };
    finalize_segment_header_checksum(&mut header);
    let encoded = lchfs_format::encode(&header).map_err(|e| e.to_string())?;
    let encoded_desc = lchfs_format::encode(&desc).map_err(|e| e.to_string())?;
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    if 4 + encoded.len() > STRIPE_DESCRIPTOR_OFFSET || STRIPE_DESCRIPTOR_OFFSET + 4 + encoded_desc.len() > page.len() {
        return Err("header and descriptor do not fit the header page".into());
    }
    page[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    page[4..4 + encoded.len()].copy_from_slice(&encoded);
    let at = STRIPE_DESCRIPTOR_OFFSET;
    page[at..at + 4].copy_from_slice(&(encoded_desc.len() as u32).to_le_bytes());
    page[at + 4..at + 4 + encoded_desc.len()].copy_from_slice(&encoded_desc);

    let dir = root.join("segments").join("data");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.ec{index}", stripe.segment_id));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    file.write_all_at(&page, 0).map_err(|e| e.to_string())?;
    file.write_all_at(bytes, SEGMENT_HEADER_PAGE_SIZE).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

/// One shard fsck rewrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuiltShard {
    pub segment_id: u64,
    pub shard_index: u8,
    pub vdev_id: u16,
}

/// Rewrites every shard that `scan` found missing or corrupt on a device
/// that was given, from `k` good siblings. A stripe short of `k` is left
/// alone and stays reported. The caller holds the pool lock.
pub fn rebuild_shards(devices: &[(u16, &Path)], scan: &StripeScan) -> Result<Vec<RebuiltShard>, FsckError> {
    let given: HashMap<u16, &Path> = devices.iter().copied().collect();
    let mut rebuilt = Vec::new();
    let mut ids: Vec<u64> = scan.stripes.keys().copied().collect();
    ids.sort_unstable();
    for segment_id in ids {
        let stripe = &scan.stripes[&segment_id];
        if !stripe.recoverable() {
            continue;
        }
        let wanted: Vec<usize> = (0..stripe.total())
            .filter(|&i| stripe.good[i].is_none() && given.contains_key(&stripe.desc.devices[i]))
            .collect();
        if wanted.is_empty() {
            continue;
        }
        let rows = stripe
            .rows(0, stripe.desc.shard_size)
            .map_err(|detail| FsckError::Io(format!("striped segment {segment_id}: {detail}")))?;
        for i in wanted {
            let vdev_id = stripe.desc.devices[i];
            write_shard(given[&vdev_id], stripe, i as u8, &rows[i])
                .map_err(|detail| FsckError::Io(format!("striped segment {segment_id} shard {i} on vdev {vdev_id}: {detail}")))?;
            rebuilt.push(RebuiltShard { segment_id, shard_index: i as u8, vdev_id });
        }
    }
    Ok(rebuilt)
}
