//! The Ingest Preparation Pool. ARCHITECTURE.md §5 ("Decoupling ingestion
//! from FUSE worker threads"): chunking, hashing, dedup-index lookup, and
//! compression are CPU-bound and must never run on a `fuser` worker
//! thread. This pool does that work asynchronously; the FUSE thread's
//! `write()` handler only copies bytes into a per-file assembly buffer and
//! hands off here.
//!
//! Safe to parallelize freely, including multiple chunks of the *same*
//! file, because every `ChunkRef` carries its own `logical_offset`
//! (ARCHITECTURE.md §1, §5) — ingestion order and logical order are fully
//! decoupled by design, so no reordering buffer is needed here.

use crate::ingress::IngressOp;
use lchfs_chunk::ChunkBoundary;
use lchfs_compress::CompressionDecision;
use lchfs_format::Hash32;

/// A byte range handed to the prep pool after `FastCdcChunker` (lchfs-chunk)
/// has already cut a boundary. This pool's job is everything *after* that:
/// hash, dedup-check, maybe-compress.
pub struct PrepTask {
    pub inode_id: u64,
    pub boundary: ChunkBoundary,
    pub raw_bytes: bytes::Bytes,
}

/// `rayon`-style work-stealing pool, sized to `num_cpus`
/// (ARCHITECTURE.md §5).
pub struct IngestPreparationPool {
    // TODO(phase-E): rayon::ThreadPool or equivalent
}

impl IngestPreparationPool {
    pub fn new(_worker_count: usize) -> Self {
        todo!("lchfs-store: IngestPreparationPool::new — see ARCHITECTURE.md §5")
    }

    /// Runs the full per-chunk pipeline (ARCHITECTURE.md §2): hash ->
    /// dedup index lookup -> (on miss) sample-and-decide -> maybe compress
    /// -> produce an `IngressOp` ready for its logical shard's ring.
    pub fn submit(&self, _task: PrepTask) -> IngressOp {
        todo!("lchfs-store: IngestPreparationPool::submit — see ARCHITECTURE.md §2")
    }
}

/// One chunk's fully-prepared result, before being wrapped as an
/// `IngressOp`. Exposed separately so tests can exercise the pipeline
/// without a full pool.
pub struct PreparedChunk {
    pub content_hash: Hash32,
    pub decision: CompressionDecision,
    pub payload: bytes::Bytes,
}

pub fn prepare_chunk(_raw_bytes: &[u8]) -> PreparedChunk {
    // TODO(phase-E): Hash32::of -> dedup index lookup (fast path: return
    // early on hit) -> lchfs_compress::sample_and_decide -> compress if
    // decided. See ARCHITECTURE.md §2 for the exact pipeline and ordering
    // rationale (hash uncompressed bytes, dedup before compress).
    todo!("lchfs-store: prepare_chunk")
}
