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
use crate::backend::Vdev;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// Fixed-size reserved page at the start of every segment file for its
/// `SegmentHeader`. Records always start at this offset; the header's own
/// encoded size is far smaller, the rest of the page is zero-padded.
pub const SEGMENT_HEADER_PAGE_SIZE: u64 = 4096;

/// Sanity cap on `header_len` itself, checked *before* the length-prefixed
/// `bincode` decode below ever runs -- an attacker/corruption-controlled
/// `header_len` must never be allowed to drive an unbounded allocation on
/// its own, independent of whatever the decode step's own behavior is.
/// `ExtentRecordHeader`'s only unbounded field is `backpointers: Vec<Hash32>`
/// (32 bytes each); 16MiB is already far beyond any header this codebase
/// ever legitimately writes.
const MAX_HEADER_LEN: usize = 16 * 1024 * 1024;
/// The largest record any stream can hold; a header claiming more is
/// corrupt, whatever its checksum says.
pub const MAX_RECORD_LEN: u32 = 512 * 1024 * 1024;
/// `header_len` a resync will consider. A real header is a few dozen
/// bytes plus 32 per backpointer, and nothing writes more than a handful;
/// `MAX_HEADER_LEN` is the read path's generous ceiling, but a resync
/// walks byte by byte through bytes that may be anything, and letting each
/// false magic cost a 16 MiB read would make a hostile segment take hours
/// to scan.
const RESYNC_MAX_HEADER_LEN: usize = 64 * 1024;
/// How much of a damaged segment a resync reads at a time.
const RESYNC_WINDOW: usize = 1024 * 1024;

/// Parses the `[u32 LE header_len][bincode(ExtentRecordHeader)]` prefix
/// shared by every Extent Record's framing, from a buffer that starts
/// exactly at that prefix. Validates magic and header checksum; does
/// *not* validate `record_len` against any caller-known total buffer size
/// (`read_raw`/`scan_next` differ on how much of the full record they
/// have available when they call this, so that check stays with them).
///
/// This is the "Extent Record header parser" ARCHITECTURE.md §10 calls
/// out for fuzzing: `bytes` may be arbitrary/adversarial/truncated in any
/// way, and this must never panic, only return `None`. Extracted here
/// (previously inlined, near-identically, in both `read_raw` and
/// `scan_next`) specifically so it's a small, pure, directly fuzzable
/// function (see `fuzz/fuzz_targets/extent_header.rs`) rather than only
/// reachable through real file I/O.
///
/// Returns the decoded header and how many bytes it consumed (`4 +
/// header_len`) on success.
pub fn parse_record_header(bytes: &[u8]) -> Option<(ExtentRecordHeader, usize)> {
    if bytes.len() < 4 {
        return None;
    }
    let header_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return None;
    }
    let consumed = 4 + header_len;
    if consumed > bytes.len() {
        return None;
    }
    let header: ExtentRecordHeader = lchfs_format::decode(&bytes[4..consumed]).ok()?;
    if header.magic != EXTENT_RECORD_MAGIC {
        return None;
    }
    if lchfs_format::compute_header_checksum(&header) != header.header_checksum {
        return None;
    }
    Some((header, consumed))
}

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
    /// One file per vdev, all carrying byte-identical content
    /// (ARCHITECTURE.md §15.3: writes fan out synchronously to every online
    /// vdev, never quorum). Because every replica receives the same appends
    /// in the same order, offsets agree across them during normal
    /// operation; per-vdev locations exist for what happens *after* a
    /// repair, when heal appends recovered bytes at a fresh offset on one
    /// device only.
    files: Vec<File>,
    /// The slot each of `files` belongs to, in the same order. What the
    /// index records a new record under: the devices this segment actually
    /// fans out to -- which after a live attach is not every device the
    /// pool has, and after a fault is not every device it started with.
    vdev_ids: Vec<u16>,
    /// The device root each of `files` lives under, same order. Only read
    /// by fault injection in tests, but cheap and kept unconditionally so
    /// the layout does not depend on a feature flag.
    roots: Vec<PathBuf>,
    /// Slots whose file failed an operation and was dropped from the
    /// fan-out, not yet collected by the owner (`take_faults`). A device
    /// that fails is left behind by this segment from that record on; the
    /// owner tells the pool's device set, and the next rollover consults
    /// that set, so every other writer drops it at its own next segment.
    faulted: Vec<u16>,
    segment_id: u64,
    stream_kind: StreamKind,
    owner_shard: u32,
    /// Next write offset; starts right after the reserved header page.
    cursor: u64,
    record_count: u64,
    fingerprint: blake3::Hasher,
}

impl SegmentWriter {
    /// `create_on` with the slots taken from position: `vdev_roots[i]` is
    /// vdev `i`. What every pre-replication caller and test expects.
    pub fn create(
        vdev_roots: &[&Path],
        segment_id: u64,
        kind: StreamKind,
        owner_shard: u32,
    ) -> io::Result<Self> {
        let vdevs: Vec<Vdev> = vdev_roots
            .iter()
            .enumerate()
            .map(|(i, r)| Vdev::new(i as u16, r.to_path_buf()))
            .collect();
        Self::create_on(&vdevs, segment_id, kind, owner_shard)
    }

    /// Opens a fresh segment fanning out to exactly `vdevs`, remembering
    /// their slots (`vdev_ids`).
    pub fn create_on(
        vdevs: &[Vdev],
        segment_id: u64,
        kind: StreamKind,
        owner_shard: u32,
    ) -> io::Result<Self> {
        Self::create_at(
            vdevs,
            |vdev| {
                std::fs::create_dir_all(segment_dir(&vdev.root, kind))?;
                Ok(segment_path(&vdev.root, segment_id, kind))
            },
            segment_id,
            kind,
            owner_shard,
        )
    }

    /// Open a fresh segment in shard `shard_id`'s own Delta stream
    /// (ARCHITECTURE.md §3, Phase E) — the per-shard fast-fsync path's
    /// dedicated segment stream, kept separate from the global Data/Meta
    /// streams. `owner_shard` is set to `shard_id`, matching every other
    /// segment kind's convention of recording its owning shard in the
    /// header even though only Delta streams are shard-scoped by directory
    /// too.
    pub fn create_delta(
        vdev_roots: &[&Path],
        shard_id: u32,
        segment_id: u64,
    ) -> io::Result<Self> {
        let vdevs: Vec<Vdev> = vdev_roots
            .iter()
            .enumerate()
            .map(|(i, r)| Vdev::new(i as u16, r.to_path_buf()))
            .collect();
        Self::create_delta_on(&vdevs, shard_id, segment_id)
    }

    /// `create_delta` for an explicit device set.
    pub fn create_delta_on(vdevs: &[Vdev], shard_id: u32, segment_id: u64) -> io::Result<Self> {
        Self::create_at(
            vdevs,
            |vdev| {
                std::fs::create_dir_all(delta_segment_dir(&vdev.root, shard_id))?;
                Ok(delta_segment_path(&vdev.root, shard_id, segment_id))
            },
            segment_id,
            StreamKind::Delta,
            shard_id,
        )
    }

    /// Slots dropped from this segment's fan-out since the last call,
    /// because an operation on their file failed. The owner reports them
    /// to the pool's device set.
    pub fn take_faults(&mut self) -> Vec<u16> {
        std::mem::take(&mut self.faulted)
    }

    /// Runs `op` against every replica file. A file that fails is dropped
    /// from the fan-out and its slot recorded in `faulted`; the operation
    /// as a whole fails only when no replica succeeded. That is the
    /// fault model of §15.3 completed: synchronous to every *online*
    /// device, where a device that has just failed is no longer online.
    fn each_replica(&mut self, mut op: impl FnMut(&File) -> io::Result<()>) -> io::Result<()> {
        let mut last_err: Option<io::Error> = None;
        let mut i = 0;
        while i < self.files.len() {
            #[cfg(feature = "fault-injection")]
            let injected = fault_injection::is_dead(&self.roots[i]);
            #[cfg(not(feature = "fault-injection"))]
            let injected = false;
            let result = if injected {
                Err(io::Error::other("fault injected"))
            } else {
                op(&self.files[i])
            };
            match result {
                Ok(()) => i += 1,
                Err(e) => {
                    let id = self.vdev_ids.remove(i);
                    self.files.remove(i);
                    self.roots.remove(i);
                    tracing::error!(
                        "vdev {id}: {} segment {} failed ({e}); dropping it from this segment's fan-out",
                        match self.stream_kind {
                            StreamKind::Data => "data",
                            StreamKind::Meta => "meta",
                            StreamKind::Delta => "delta",
                        },
                        self.segment_id
                    );
                    self.faulted.push(id);
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) if self.files.is_empty() => Err(e),
            _ => Ok(()),
        }
    }

    /// The slots this segment fans out to.
    pub fn vdev_ids(&self) -> &[u16] {
        &self.vdev_ids
    }

    /// Opens the segment on every device `path_for` can place it on. A
    /// device where the directory or the file cannot be created -- gone
    /// from the filesystem, read-only, full -- is left out and recorded in
    /// `faulted` for the owner to report, exactly as a failed append is.
    /// Creation fails only if no device could take the segment.
    fn create_at(
        vdevs: &[Vdev],
        path_for: impl Fn(&Vdev) -> io::Result<PathBuf>,
        segment_id: u64,
        kind: StreamKind,
        owner_shard: u32,
    ) -> io::Result<Self> {
        if vdevs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a segment needs at least one vdev to be written to",
            ));
        }
        let mut files = Vec::with_capacity(vdevs.len());
        let mut placed: Vec<&Vdev> = Vec::with_capacity(vdevs.len());
        let mut faulted = Vec::new();
        let mut last_err = None;
        for vdev in vdevs {
            #[cfg(feature = "fault-injection")]
            let injected = fault_injection::is_dead(&vdev.root);
            #[cfg(not(feature = "fault-injection"))]
            let injected = false;
            let opened = if injected {
                Err(io::Error::other("fault injected"))
            } else {
                path_for(vdev).and_then(|path| {
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(path)
                })
            };
            match opened {
                Ok(file) => {
                    files.push(file);
                    placed.push(vdev);
                }
                Err(e) => {
                    tracing::error!(
                        "vdev {}: cannot create segment {segment_id} ({e}); leaving it out",
                        vdev.id
                    );
                    faulted.push(vdev.id);
                    last_err = Some(e);
                }
            }
        }
        if files.is_empty() {
            return Err(last_err.expect("no files means at least one error"));
        }
        let vdevs = placed;

        let mut header = SegmentHeader {
            magic: SEGMENT_HEADER_MAGIC,
            segment_id,
            stream_kind: kind,
            owner_shard,
            state: SegmentState::Open,
            header_checksum: 0,
        };
        finalize_segment_header_checksum(&mut header);
        // The header page goes through the same per-replica tolerance as
        // everything after it, once the writer exists.
        let mut writer = Self {
            files,
            vdev_ids: vdevs.iter().map(|v| v.id).collect(),
            roots: vdevs.iter().map(|v| v.root.clone()).collect(),
            faulted,
            segment_id,
            stream_kind: kind,
            owner_shard,
            cursor: SEGMENT_HEADER_PAGE_SIZE,
            record_count: 0,
            fingerprint: blake3::Hasher::new(),
        };
        writer.each_replica(|file| write_header_page(file, &header))?;
        Ok(writer)
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
        // Every replica gets the identical record at the identical offset.
        // §15.3 chose synchronous all-vdev durability over quorum, because
        // acking a write present on only some replicas would need a
        // catch-up log. A replica that *fails* here is a different matter:
        // it leaves the fan-out, the record is acked on the devices that
        // took it, and the index says exactly those (`vdev_ids`), so the
        // catch-up is the ordinary resilver when the device returns.
        self.each_replica(|file| {
            file.write_all_at(&header_len.to_le_bytes(), record_offset)?;
            file.write_all_at(&encoded, record_offset + 4)?;
            file.write_all_at(payload, record_offset + 4 + header_len as u64)
        })?;

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
    pub fn fsync(&mut self) -> io::Result<()> {
        self.sync_replicas()
    }

    /// `each_replica(sync_all)`, but with the syncs issued together. A
    /// synchronous fan-out makes the slowest device set the latency
    /// (§15.9); issuing the syncs serially made it the *sum*. On one disk
    /// there is nothing to gain and a thread per extra device to pay, so
    /// this only bothers when there is more than one replica -- which is
    /// when they can be on different disks.
    fn sync_replicas(&mut self) -> io::Result<()> {
        if self.files.len() < 2 {
            return self.each_replica(|file| file.sync_all());
        }
        #[cfg(feature = "fault-injection")]
        let dead: Vec<bool> = self.roots.iter().map(|r| fault_injection::is_dead(r)).collect();
        #[cfg(not(feature = "fault-injection"))]
        let dead: Vec<bool> = vec![false; self.files.len()];
        let results: Vec<io::Result<()>> = std::thread::scope(|scope| {
            let handles: Vec<_> = self
                .files
                .iter()
                .zip(&dead)
                .map(|(file, &is_dead)| {
                    scope.spawn(move || {
                        if is_dead {
                            Err(io::Error::other("fault injected"))
                        } else {
                            file.sync_all()
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| Err(io::Error::other("fsync thread panicked"))))
                .collect()
        });
        // Apply the outcomes with the same bookkeeping a serial pass does.
        let mut i = 0;
        let mut last_err = None;
        for result in results {
            match result {
                Ok(()) => i += 1,
                Err(e) => {
                    let id = self.vdev_ids.remove(i);
                    self.files.remove(i);
                    self.roots.remove(i);
                    tracing::error!(
                        "vdev {id}: fsync of segment {} failed ({e}); dropping it from this segment's fan-out",
                        self.segment_id
                    );
                    self.faulted.push(id);
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) if self.files.is_empty() => Err(e),
            _ => Ok(()),
        }
    }

    /// Seal the segment: write record count, aggregate fingerprint hash,
    /// footer checksum (ARCHITECTURE.md §1 "Seal footer"), and flip the
    /// header page's state to `Sealed`.
    ///
    /// Returns the slots that failed during the seal and were dropped, for
    /// the owner to report -- a sealed writer is consumed, so this is the
    /// last chance to collect them.
    pub fn seal(mut self) -> io::Result<Vec<u16>> {
        let mut footer = SegmentFooter {
            record_count: self.record_count,
            aggregate_fingerprint: Hash32(*self.fingerprint.finalize().as_bytes()),
            footer_checksum: 0,
        };
        finalize_segment_footer_checksum(&mut footer);
        let encoded =
            lchfs_format::encode(&footer).expect("SegmentFooter encoding is infallible");
        let cursor = self.cursor;
        self.each_replica(|file| {
            file.write_all_at(&(encoded.len() as u32).to_le_bytes(), cursor)?;
            file.write_all_at(&encoded, cursor + 4)
        })?;

        let mut header = SegmentHeader {
            magic: SEGMENT_HEADER_MAGIC,
            segment_id: self.segment_id,
            stream_kind: self.stream_kind,
            owner_shard: self.owner_shard,
            state: SegmentState::Sealed,
            header_checksum: 0,
        };
        finalize_segment_header_checksum(&mut header);
        self.each_replica(|file| write_header_page(file, &header))?;

        // Seal is only durable once every replica that still holds the
        // segment has it.
        self.sync_replicas()?;
        Ok(std::mem::take(&mut self.faulted))
    }
}

/// Test-only fault injection: device roots declared dead fail every
/// replica operation, so a disk that dies under an open descriptor -- the
/// case nothing short of hardware produces on its own -- can be
/// exercised. Compiled out without the `fault-injection` feature; with it,
/// each replica operation costs one lock and one path comparison.
#[cfg(feature = "fault-injection")]
pub mod fault_injection {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    fn dead() -> &'static Mutex<HashSet<PathBuf>> {
        static DEAD: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
        DEAD.get_or_init(|| Mutex::new(HashSet::new()))
    }

    /// Every replica operation under `root` fails from now on.
    pub fn kill(root: &Path) {
        dead().lock().unwrap().insert(root.to_path_buf());
    }

    /// The device works again.
    pub fn revive(root: &Path) {
        dead().lock().unwrap().remove(root);
    }

    pub fn is_dead(root: &Path) -> bool {
        dead().lock().unwrap().contains(root)
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
    if 4 + header_len > page.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "corrupted segment header: header_len prefix out of bounds",
        ));
    }
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

/// Turns a record's on-disk payload back into its logical bytes, applying
/// whatever codec the header says was used. No content-hash check -- the
/// callers that need one keep doing it themselves; this exists so
/// `read_record`, `read_record_raw` and read failover's heal path (lib.rs)
/// share one decode rather than three.
///
/// A payload that will not decompress is reported as a corrupted record,
/// the same shape as a bad length prefix. It cannot be a content-hash
/// mismatch, because there are no bytes to hash yet -- and it must not be
/// a panic, because these bytes came off a disk that may have rotted them.
pub fn decode_payload(
    header: &ExtentRecordHeader,
    payload: Vec<u8>,
) -> Result<Vec<u8>, SegmentError> {
    if header.codec_id == CodecId::None {
        return Ok(payload);
    }
    // The decompressor allocates `uncompressed_len` up front, and that
    // field is a u32 off the disk. A checksum catches a bit flip; it does
    // not stop a deliberately written 4 GiB, and one such header must not
    // be able to take the whole process down on a read.
    if header.uncompressed_len > MAX_RECORD_LEN {
        return Err(SegmentError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "corrupted record: uncompressed_len {} exceeds the {MAX_RECORD_LEN}-byte record limit",
                header.uncompressed_len
            ),
        )));
    }
    use lchfs_compress::{Codec, ZstdCodec};
    ZstdCodec
        .decompress(&payload, header.uncompressed_len as usize)
        .map_err(|e| {
            SegmentError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("corrupted record: payload does not decompress ({e})"),
            ))
        })
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
        if 4 + header_len > page.len() {
            return Err(SegmentError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupted segment header: header_len prefix out of bounds",
            )));
        }
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

        let (header, consumed) = parse_record_header(&record_bytes).ok_or_else(|| {
            SegmentError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupted record: malformed header framing",
            ))
        })?;

        // `parse_record_header` already checked magic + header checksum;
        // `validate_header` re-checks those (cheap, harmless) plus the one
        // thing it alone can: `record_len` against this specific buffer's
        // actual length, which `parse_record_header` deliberately leaves
        // to the caller (see its doc comment).
        validate_header(&header, &record_bytes)?;

        let payload_len = if header.codec_id == CodecId::None {
            header.uncompressed_len as usize
        } else {
            header.compressed_len as usize
        };
        let payload_start = consumed;
        let payload_end = payload_start
            .checked_add(payload_len)
            .filter(|&end| end <= record_bytes.len())
            .ok_or_else(|| {
                SegmentError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "corrupted record: payload length out of bounds",
                ))
            })?;
        let payload = record_bytes[payload_start..payload_end].to_vec();
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
        let decompressed = decode_payload(&header, payload)?;

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
        let decompressed = decode_payload(&header, payload.clone())?;

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
        // Peek just the length prefix first, sanity-capped, before sizing
        // the second read that actually covers the header -- an
        // attacker/corruption-controlled `header_len` must never drive an
        // oversized read (or, via `parse_record_header`, an oversized
        // decode allocation) before anything has validated it.
        let mut len_buf = [0u8; 4];
        self.file.read_exact_at(&mut len_buf, offset as u64).ok()?;
        let header_len = u32::from_le_bytes(len_buf) as usize;
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return None;
        }
        let mut buf = vec![0u8; 4 + header_len];
        self.file.read_exact_at(&mut buf, offset as u64).ok()?;
        let (header, _consumed) = parse_record_header(&buf)?;
        if header.record_len == 0 || header.record_len > MAX_RECORD_LEN {
            return None;
        }
        let next_offset = offset.checked_add(header.record_len)?;
        Some((header, next_offset))
    }
}

/// How a sequential scan of a segment ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEnd {
    /// The sealed segment's footer was reached: a clean end.
    Footer,
    /// End of file with no footer: an open (still being written) segment,
    /// or one whose seal never landed. Also clean, as far as scanning goes.
    Eof,
    /// Nothing parseable from `at` to the end of the file.
    Damaged { at: u32 },
}

/// A sequential walk over a segment's records that survives damage in the
/// middle. `scan_next` stops at the first unparseable header, which is the
/// right thing for a torn tail after a crash and the wrong thing for a run
/// of rotted bytes with perfectly good records behind it -- a scan that
/// stopped there would report every later record as missing from a device
/// that still has them. On a failed header this checks whether the bytes
/// are the footer (clean end) or EOF (open segment), and otherwise searches
/// forward for the next header whose magic and checksum both hold, noting
/// the range it skipped. Healthy segments never pay for any of this: the
/// resync only runs once a header has already failed to parse.
pub struct Scan<'a> {
    reader: &'a SegmentReader,
    offset: u32,
    len: u64,
    /// Byte ranges `[from, to)` that held nothing parseable and were
    /// skipped. Empty for an undamaged segment.
    pub damaged: Vec<(u32, u32)>,
    pub end: Option<ScanEnd>,
}

impl SegmentReader {
    /// Iterates every record `(header, offset)` from the first record page
    /// on, resyncing past damage. See [`Scan`].
    pub fn scan(&self) -> Scan<'_> {
        Scan {
            reader: self,
            offset: SEGMENT_HEADER_PAGE_SIZE as u32,
            len: self.file.metadata().map(|m| m.len()).unwrap_or(0),
            damaged: Vec::new(),
            end: None,
        }
    }

    /// Whether `offset` holds the sealed segment's footer.
    fn footer_at(&self, offset: u32) -> bool {
        let mut len_buf = [0u8; 4];
        if self.file.read_exact_at(&mut len_buf, offset as u64).is_err() {
            return false;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 4096 {
            return false;
        }
        let mut buf = vec![0u8; len];
        if self.file.read_exact_at(&mut buf, offset as u64 + 4).is_err() {
            return false;
        }
        match lchfs_format::decode::<SegmentFooter>(&buf) {
            Ok(footer) => {
                lchfs_format::compute_segment_footer_checksum(&footer) == footer.footer_checksum
            }
            Err(_) => false,
        }
    }

    /// The next offset at or after `from + 1` where a record header parses
    /// with its magic and checksum intact, together with that header and
    /// the offset after the record. The magic sits four bytes into a record
    /// (after the header length prefix), so candidates are found by looking
    /// for it and only then paying for a parse. Reads the file in
    /// `RESYNC_WINDOW` pieces, so a segment that has been extended with
    /// garbage costs a window of memory, not its own size; a candidate's
    /// header is read on its own, bounded by `RESYNC_MAX_HEADER_LEN`.
    fn resync(&self, from: u32, file_len: u64) -> Option<(ExtentRecordHeader, u32, u32)> {
        let magic = lchfs_format::EXTENT_RECORD_MAGIC.to_le_bytes();
        let mut window_start = from as u64 + 1;
        let mut window = vec![0u8; RESYNC_WINDOW];
        // A magic can straddle two windows; overlap by its length.
        while window_start + 8 <= file_len {
            let len = ((file_len - window_start) as usize).min(RESYNC_WINDOW);
            let buf = &mut window[..len];
            self.file.read_exact_at(buf, window_start).ok()?;
            let mut i = 0usize;
            while i + 8 <= len {
                if buf[i + 4..i + 8] == magic
                    && let Some(found) = self.try_header_at(window_start + i as u64, file_len)
                {
                    return Some(found);
                }
                i += 1;
            }
            if window_start + len as u64 >= file_len {
                break;
            }
            window_start += (len - 7) as u64;
        }
        None
    }

    /// Parses the record header at `at` if there is a sound one there:
    /// sane length prefix, magic, checksum, and a `record_len` that fits
    /// in the file.
    fn try_header_at(&self, at: u64, file_len: u64) -> Option<(ExtentRecordHeader, u32, u32)> {
        let mut len_buf = [0u8; 4];
        self.file.read_exact_at(&mut len_buf, at).ok()?;
        let header_len = u32::from_le_bytes(len_buf) as usize;
        if header_len == 0 || header_len > RESYNC_MAX_HEADER_LEN || at + 4 + header_len as u64 > file_len {
            return None;
        }
        let mut buf = vec![0u8; 4 + header_len];
        self.file.read_exact_at(&mut buf, at).ok()?;
        let (header, _consumed) = parse_record_header(&buf)?;
        if header.record_len == 0 || header.record_len > MAX_RECORD_LEN {
            return None;
        }
        let at32 = u32::try_from(at).ok()?;
        let next = at32.checked_add(header.record_len)?;
        if next as u64 > file_len {
            return None;
        }
        Some((header, at32, next))
    }
}

impl Iterator for Scan<'_> {
    type Item = (ExtentRecordHeader, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.end.is_some() {
            return None;
        }
        if let Some((header, next)) = self.reader.scan_next(self.offset) {
            if next as u64 > self.len {
                // The header parsed but the record runs past the end of
                // the file: a tail torn by a crash mid-append. Nothing can
                // follow it, so this is a clean end -- registering the
                // record would only point the index at bytes that cannot
                // be read.
                self.end = Some(ScanEnd::Eof);
                return None;
            }
            let at = self.offset;
            self.offset = next;
            return Some((header, at));
        }
        if self.offset as u64 >= self.len {
            self.end = Some(ScanEnd::Eof);
            return None;
        }
        if self.reader.footer_at(self.offset) {
            self.end = Some(ScanEnd::Footer);
            return None;
        }
        match self.reader.resync(self.offset, self.len) {
            Some((header, at, next)) => {
                self.damaged.push((self.offset, at));
                self.offset = next;
                Some((header, at))
            }
            None => {
                self.damaged.push((self.offset, self.len as u32));
                self.end = Some(ScanEnd::Damaged { at: self.offset });
                None
            }
        }
    }
}
