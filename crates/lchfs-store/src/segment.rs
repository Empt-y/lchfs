//! Segment file reading/writing. ARCHITECTURE.md §1 ("Segment files").

use lchfs_format::{ExtentKind, ExtentLocation, ExtentRecordHeader, Hash32};

/// Which stream a segment belongs to — data and metadata are kept as
/// separate segment streams (ARCHITECTURE.md §1) so mount-time index
/// rebuild and fsck can scan metadata first without touching bulk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Data,
    Meta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    Open,
    Sealed,
    Coalesced,
}

/// Append-only writer for one segment, owned exclusively by one logical
/// shard's committer at a time (ARCHITECTURE.md §3, §5 — "no cross-shard
/// writer ever touches the same segment file").
pub struct SegmentWriter {
    // TODO(phase-B): segment_id, stream_kind, owner_shard, open file handle, write cursor
}

impl SegmentWriter {
    pub fn create(_segment_id: u64, _kind: StreamKind, _owner_shard: u32) -> std::io::Result<Self> {
        todo!("lchfs-store: SegmentWriter::create")
    }

    /// Append one Extent Record; returns its location for the caller to
    /// record in the index. Content hash / compression decision must
    /// already be finalized by the caller (lchfs-chunk / lchfs-compress) —
    /// this only handles the on-disk framing (lchfs-format).
    pub fn append(
        &mut self,
        _kind: ExtentKind,
        _content_hash: Hash32,
        _payload: &[u8],
    ) -> std::io::Result<ExtentLocation> {
        todo!("lchfs-store: SegmentWriter::append")
    }

    /// Seal the segment: write record count, aggregate fingerprint hash,
    /// footer checksum (ARCHITECTURE.md §1 "Seal footer").
    pub fn seal(self) -> std::io::Result<()> {
        todo!("lchfs-store: SegmentWriter::seal")
    }
}

/// Random-access reader for a sealed or open segment.
pub struct SegmentReader {
    // TODO(phase-B): open file handle, header info
}

impl SegmentReader {
    pub fn open(_segment_id: u64, _kind: StreamKind) -> std::io::Result<Self> {
        todo!("lchfs-store: SegmentReader::open")
    }

    /// Read and validate one Extent Record at `loc`. Performs the full
    /// mandatory check sequence from ARCHITECTURE.md §1: magic -> bounds ->
    /// header checksum -> decompress -> BLAKE3(decompressed) == content_hash.
    pub fn read_record(&self, _loc: ExtentLocation) -> std::io::Result<(ExtentRecordHeader, Vec<u8>)> {
        todo!("lchfs-store: SegmentReader::read_record")
    }
}
