//! Segment file reading/writing. ARCHITECTURE.md §1 ("Segment files").
//!
//! Per-record physical framing (a concrete choice not fully pinned down by
//! ARCHITECTURE.md, decided here): `[u32 LE header_len][header_len bytes:
//! bincode(ExtentRecordHeader)][payload bytes]`. The explicit `header_len`
//! prefix lets a reader parse the variable-length header (its
//! `backpointers` vec makes its encoded size unpredictable) without first
//! needing to decode anything; `header.record_len` (4 + header_len +
//! payload_len) is still the field ARCHITECTURE.md describes for
//! skip-scanning, and is validated by `lchfs_format::validate_header`.

use lchfs_format::{
    CodecId, EXTENT_RECORD_MAGIC, ExtentKind, ExtentLocation, ExtentRecordHeader,
    ExtentValidationError, Hash32, SEGMENT_HEADER_MAGIC, SegmentFooter, SegmentHeader,
    SegmentState, StreamKind, finalize_header_checksum, finalize_segment_footer_checksum,
    finalize_segment_header_checksum, validate_header,
};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// Fixed-size reserved page at the start of every segment file for its
/// `SegmentHeader`. Records always start at this offset; the header's own
/// encoded size is far smaller, the rest of the page is zero-padded.
pub const SEGMENT_HEADER_PAGE_SIZE: u64 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum SegmentError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("header validation failed: {0}")]
    Validation(#[from] ExtentValidationError),
    #[error("content hash mismatch for record at segment {segment_id} offset {offset}: expected {expected:?}, got {actual:?}")]
    ContentHash {
        segment_id: u64,
        offset: u32,
        expected: Hash32,
        actual: Hash32,
    },
}

fn segment_dir(pool_root: &Path, kind: StreamKind) -> PathBuf {
    let sub = match kind {
        StreamKind::Data => "data",
        StreamKind::Meta => "meta",
        StreamKind::Delta => unreachable!("Delta streams are shard-scoped, use delta_segment_dir"),
    };
    pool_root.join("segments").join(sub)
}

pub(crate) fn segment_path(pool_root: &Path, segment_id: u64, kind: StreamKind) -> PathBuf {
    let ext = match kind {
        StreamKind::Data => "aseg",
        StreamKind::Meta => "mseg",
        StreamKind::Delta => unreachable!("Delta streams are shard-scoped, use delta_segment_path"),
    };
    segment_dir(pool_root, kind).join(format!("{segment_id}.{ext}"))
}

/// Per-shard Delta stream directory (ARCHITECTURE.md §3, Phase E): each
/// logical shard's delta segments live in their own subdirectory so
/// mount-time recovery (§7) can discover exactly one shard's delta history
/// without scanning any other shard's or the global Data/Meta streams.
pub(crate) fn delta_segment_dir(pool_root: &Path, shard_id: u32) -> PathBuf {
    pool_root
        .join("segments")
        .join("delta")
        .join(format!("{shard_id:05}"))
}

fn delta_segment_path(pool_root: &Path, shard_id: u32, segment_id: u64) -> PathBuf {
    delta_segment_dir(pool_root, shard_id).join(format!("{segment_id}.dseg"))
}

/// Append-only writer for one segment, owned exclusively by one logical
/// shard's committer at a time (ARCHITECTURE.md §3, §5 — "no cross-shard
/// writer ever touches the same segment file"). Phase B: single-threaded,
/// so exclusivity is just "the only `SegmentWriter` for this segment_id".
pub struct SegmentWriter {
    file: File,
    segment_id: u64,
    stream_kind: StreamKind,
    owner_shard: u32,
    /// Next write offset; starts right after the reserved header page.
    cursor: u64,
    record_count: u64,
    fingerprint: blake3::Hasher,
}

impl SegmentWriter {
    pub fn create(
        pool_root: &Path,
        segment_id: u64,
        kind: StreamKind,
        owner_shard: u32,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(segment_dir(pool_root, kind))?;
        let path = segment_path(pool_root, segment_id, kind);
        Self::create_at(&path, segment_id, kind, owner_shard)
    }

    /// Open a fresh segment in shard `shard_id`'s own Delta stream
    /// (ARCHITECTURE.md §3, Phase E) — the per-shard fast-fsync path's
    /// dedicated segment stream, kept separate from the global Data/Meta
    /// streams. `owner_shard` is set to `shard_id`, matching every other
    /// segment kind's convention of recording its owning shard in the
    /// header even though only Delta streams are shard-scoped by directory
    /// too.
    pub fn create_delta(pool_root: &Path, shard_id: u32, segment_id: u64) -> io::Result<Self> {
        std::fs::create_dir_all(delta_segment_dir(pool_root, shard_id))?;
        let path = delta_segment_path(pool_root, shard_id, segment_id);
        Self::create_at(&path, segment_id, StreamKind::Delta, shard_id)
    }

    fn create_at(
        path: &Path,
        segment_id: u64,
        kind: StreamKind,
        owner_shard: u32,
    ) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;

        let mut header = SegmentHeader {
            magic: SEGMENT_HEADER_MAGIC,
            segment_id,
            stream_kind: kind,
            owner_shard,
            state: SegmentState::Open,
            header_checksum: 0,
        };
        finalize_segment_header_checksum(&mut header);
        write_header_page(&file, &header)?;

        Ok(Self {
            file,
            segment_id,
            stream_kind: kind,
            owner_shard,
            cursor: SEGMENT_HEADER_PAGE_SIZE,
            record_count: 0,
            fingerprint: blake3::Hasher::new(),
        })
    }

    pub fn segment_id(&self) -> u64 {
        self.segment_id
    }

    pub fn stream_kind(&self) -> StreamKind {
        self.stream_kind
    }

    /// Total bytes written so far, including the header page. Callers
    /// (Pool) compare this against `PoolParams::{data,meta}_segment_cap_bytes`
    /// to decide when to seal and roll over to a new segment.
    pub fn current_size(&self) -> u64 {
        self.cursor
    }

    /// Append one Extent Record; returns its location for the caller to
    /// record in the index. Content hash / compression decision must
    /// already be finalized by the caller (lchfs-chunk / lchfs-compress) —
    /// this only handles the on-disk framing (lchfs-format).
    ///
    /// `uncompressed_len` and `payload` (already compressed if
    /// `codec_id != CodecId::None`) together let this function populate
    /// both length fields ARCHITECTURE.md §1 requires always be present.
    pub fn append(
        &mut self,
        kind: ExtentKind,
        content_hash: Hash32,
        codec_id: CodecId,
        uncompressed_len: u32,
        payload: &[u8],
        backpointers: Vec<Hash32>,
    ) -> io::Result<ExtentLocation> {
        let mut header = ExtentRecordHeader {
            magic: EXTENT_RECORD_MAGIC,
            record_len: 0,
            content_hash,
            kind,
            codec_id,
            flags: 0,
            uncompressed_len,
            compressed_len: payload.len() as u32,
            backpointers,
            header_checksum: 0,
        };
        // Fixed-width fields mean record_len's *value* doesn't change the
        // header's encoded byte length, so encoding once up front is safe
        // to learn header_len before patching record_len in for real.
        let header_len = lchfs_format::encode(&header)
            .expect("ExtentRecordHeader encoding is infallible")
            .len() as u32;
        header.record_len = 4 + header_len + payload.len() as u32;
        finalize_header_checksum(&mut header);
        let encoded = lchfs_format::encode(&header).expect("ExtentRecordHeader encoding is infallible");
        debug_assert_eq!(encoded.len() as u32, header_len);

        let record_offset = self.cursor;
        self.file
            .write_all_at(&header_len.to_le_bytes(), record_offset)?;
        self.file
            .write_all_at(&encoded, record_offset + 4)?;
        self.file
            .write_all_at(payload, record_offset + 4 + header_len as u64)?;

        let loc = ExtentLocation {
            segment_id: self.segment_id,
            offset: record_offset as u32,
            len: header.record_len,
        };
        self.cursor += header.record_len as u64;
        self.record_count += 1;
        self.fingerprint.update(&content_hash.0);
        Ok(loc)
    }

    /// fsync this segment's file without sealing it — used for the
    /// checkpoint durability barriers (ARCHITECTURE.md §3), which fsync
    /// still-open segments long before they fill up and get sealed.
    pub fn fsync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Seal the segment: write record count, aggregate fingerprint hash,
    /// footer checksum (ARCHITECTURE.md §1 "Seal footer"), and flip the
    /// header page's state to `Sealed`.
    pub fn seal(self) -> io::Result<()> {
        let mut footer = SegmentFooter {
            record_count: self.record_count,
            aggregate_fingerprint: Hash32(*self.fingerprint.finalize().as_bytes()),
            footer_checksum: 0,
        };
        finalize_segment_footer_checksum(&mut footer);
        let encoded =
            lchfs_format::encode(&footer).expect("SegmentFooter encoding is infallible");
        self.file
            .write_all_at(&(encoded.len() as u32).to_le_bytes(), self.cursor)?;
        self.file.write_all_at(&encoded, self.cursor + 4)?;

        let mut header = SegmentHeader {
            magic: SEGMENT_HEADER_MAGIC,
            segment_id: self.segment_id,
            stream_kind: self.stream_kind,
            owner_shard: self.owner_shard,
            state: SegmentState::Sealed,
            header_checksum: 0,
        };
        finalize_segment_header_checksum(&mut header);
        write_header_page(&self.file, &header)?;

        self.file.sync_all()
    }
}

/// Flips an already-sealed segment's header page to `SegmentState::Coalesced`
/// in place -- a tombstone the Coalescing Daemon (coalesce.rs) writes
/// after a repack's new segment is durably fsync'd and the index update
/// is durable, but before deleting the old segment file. A crash between
/// the tombstone and the actual deletion leaves something self-describing
/// behind: the segment is unambiguously marked as superseded, safe to
/// finish deleting on the next pass (or, per ARCHITECTURE.md §7, during
/// mount-time recovery, which can treat a `Coalesced` segment as
/// definitely-not-live).
pub(crate) fn mark_coalesced(pool_root: &Path, segment_id: u64, kind: StreamKind) -> io::Result<()> {
    let path = segment_path(pool_root, segment_id, kind);
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    file.read_exact_at(&mut page, 0)?;
    let header_len = u32::from_le_bytes(page[0..4].try_into().unwrap()) as usize;
    let mut header: SegmentHeader = lchfs_format::decode(&page[4..4 + header_len])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    header.state = SegmentState::Coalesced;
    header.header_checksum = 0;
    finalize_segment_header_checksum(&mut header);
    write_header_page(&file, &header)?;
    file.sync_all()
}

fn write_header_page(file: &File, header: &SegmentHeader) -> io::Result<()> {
    let encoded = lchfs_format::encode(header).expect("SegmentHeader encoding is infallible");
    assert!(
        encoded.len() as u64 + 4 <= SEGMENT_HEADER_PAGE_SIZE,
        "segment header must fit in the reserved page"
    );
    let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
    page[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    page[4..4 + encoded.len()].copy_from_slice(&encoded);
    file.write_all_at(&page, 0)
}

/// Random-access reader for a sealed or open segment.
pub struct SegmentReader {
    file: File,
    segment_id: u64,
}

impl SegmentReader {
    pub fn open(pool_root: &Path, segment_id: u64, kind: StreamKind) -> io::Result<Self> {
        let path = segment_path(pool_root, segment_id, kind);
        Self::open_at(&path, segment_id)
    }

    /// Open a reader for shard `shard_id`'s own Delta stream segment
    /// `segment_id`. See `SegmentWriter::create_delta`.
    pub fn open_delta(pool_root: &Path, shard_id: u32, segment_id: u64) -> io::Result<Self> {
        let path = delta_segment_path(pool_root, shard_id, segment_id);
        Self::open_at(&path, segment_id)
    }

    fn open_at(path: &Path, segment_id: u64) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).open(path)?;
        Ok(Self { file, segment_id })
    }

    /// Reads and validates the segment's own header page. Not required for
    /// the direct-location read path (`read_record` trusts its caller's
    /// `ExtentLocation`s), but used by mount-time/fsck-style full scans.
    pub fn read_header(&self) -> Result<SegmentHeader, SegmentError> {
        let mut page = vec![0u8; SEGMENT_HEADER_PAGE_SIZE as usize];
        self.file.read_exact_at(&mut page, 0)?;
        let header_len = u32::from_le_bytes(page[0..4].try_into().unwrap()) as usize;
        let header: SegmentHeader = lchfs_format::decode(&page[4..4 + header_len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if header.magic != SEGMENT_HEADER_MAGIC {
            return Err(SegmentError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad segment header magic",
            )));
        }
        Ok(header)
    }

    /// Shared bounds/checksum-validated raw-bytes extraction for
    /// `read_record`/`read_record_raw` below -- returns the payload
    /// exactly as stored (still compressed, if `codec_id != None`),
    /// structurally validated (magic, bounds, header checksum) but not
    /// yet decompressed or content-hash verified.
    fn read_raw(&self, loc: ExtentLocation) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        let mut record_bytes = vec![0u8; loc.len as usize];
        self.file
            .read_exact_at(&mut record_bytes, loc.offset as u64)?;

        let header_len = u32::from_le_bytes(record_bytes[0..4].try_into().unwrap()) as usize;
        let header: ExtentRecordHeader = lchfs_format::decode(&record_bytes[4..4 + header_len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        validate_header(&header, &record_bytes)?;

        let payload_len = if header.codec_id == CodecId::None {
            header.uncompressed_len as usize
        } else {
            header.compressed_len as usize
        };
        let payload_start = 4 + header_len;
        let payload = record_bytes[payload_start..payload_start + payload_len].to_vec();
        Ok((header, payload))
    }

    /// Read and validate one Extent Record at `loc`. Performs the full
    /// mandatory check sequence from ARCHITECTURE.md §1: magic -> bounds ->
    /// header checksum -> decompress -> BLAKE3(decompressed) == content_hash.
    pub fn read_record(
        &self,
        loc: ExtentLocation,
    ) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        let (header, payload) = self.read_raw(loc)?;

        let decompressed = if header.codec_id == CodecId::None {
            payload
        } else {
            use lchfs_compress::{Codec, ZstdCodec};
            ZstdCodec.decompress(&payload, header.uncompressed_len as usize)
        };

        if let Err(_verify_err) = lchfs_crypto::verify(&decompressed, header.content_hash) {
            let actual = Hash32::of(&decompressed);
            return Err(SegmentError::ContentHash {
                segment_id: self.segment_id,
                offset: loc.offset,
                expected: header.content_hash,
                actual,
            });
        }

        Ok((header, decompressed))
    }

    /// Like `read_record`, but returns the *raw* (still-compressed, if
    /// applicable) payload bytes instead of decompressed ones. Used by
    /// the Coalescing Daemon (coalesce.rs) to physically repack a segment
    /// without a wasted decompress-then-recompress round trip -- the
    /// original compression decision is preserved exactly, so coalescing
    /// a segment full of highly-compressible content doesn't perversely
    /// make it *larger*. Still performs the full mandatory validation,
    /// including content-hash verification (via a throwaway decompress,
    /// discarded): coalescing must never propagate corrupted data forward
    /// into a fresh segment just because the bytes being kept aren't the
    /// ones being verified against.
    pub fn read_record_raw(
        &self,
        loc: ExtentLocation,
    ) -> Result<(ExtentRecordHeader, Vec<u8>), SegmentError> {
        let (header, payload) = self.read_raw(loc)?;

        let decompressed = if header.codec_id == CodecId::None {
            payload.clone()
        } else {
            use lchfs_compress::{Codec, ZstdCodec};
            ZstdCodec.decompress(&payload, header.uncompressed_len as usize)
        };

        if let Err(_verify_err) = lchfs_crypto::verify(&decompressed, header.content_hash) {
            let actual = Hash32::of(&decompressed);
            return Err(SegmentError::ContentHash {
                segment_id: self.segment_id,
                offset: loc.offset,
                expected: header.content_hash,
                actual,
            });
        }

        Ok((header, payload))
    }

    /// Best-effort scan helper for mount-time segment scanning (Phase B's
    /// stand-in for a persisted index — see lchfs-store's module docs):
    /// reads and validates just the *header* framing at `offset` (magic +
    /// header checksum — not bounds, and deliberately not payload
    /// decompression or content-hash verification), collapsing any failure
    /// (EOF, the trailing `SegmentFooter` which isn't a valid Extent
    /// Record, a corrupted header) into `None`, meaning "stop scanning
    /// this segment."
    ///
    /// This must stay structural-only: a corrupted *payload* still has an
    /// intact header, and this function's whole job is to keep discovering
    /// every subsequent record's location regardless — the corruption
    /// itself is only surfaced later, when something actually calls
    /// `read_record` on that specific location and its content-hash check
    /// fails. Using the full verifying read here instead would make one
    /// corrupted record silently erase every *other*, perfectly healthy
    /// record after it from the rebuilt index — the opposite of what
    /// mount-time recovery is supposed to do.
    pub fn scan_next(&self, offset: u32) -> Option<(ExtentRecordHeader, u32)> {
        let mut len_buf = [0u8; 4];
        self.file.read_exact_at(&mut len_buf, offset as u64).ok()?;
        let header_len = u32::from_le_bytes(len_buf);
        if header_len == 0 || header_len > 16 * 1024 * 1024 {
            return None;
        }
        let mut header_buf = vec![0u8; header_len as usize];
        self.file
            .read_exact_at(&mut header_buf, offset as u64 + 4)
            .ok()?;
        let header: ExtentRecordHeader = lchfs_format::decode(&header_buf).ok()?;
        if header.magic != EXTENT_RECORD_MAGIC {
            return None;
        }
        if lchfs_format::compute_header_checksum(&header) != header.header_checksum {
            return None;
        }
        if header.record_len == 0 || header.record_len > 512 * 1024 * 1024 {
            return None;
        }
        let next_offset = offset + header.record_len;
        Some((header, next_offset))
    }
}
