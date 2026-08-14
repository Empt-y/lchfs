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
//!
//! This pool's job ends at producing a `PreparedChunk` — building the
//! `IngressOp` (with its completion channel) and pushing it onto the
//! `CommitterPool` is `Pool::write`'s orchestration job (see lib.rs), kept
//! out of this crate-internal module so `prepare_chunk` stays a pure,
//! independently testable function with no knowledge of the ingress ring.

use lchfs_compress::{Codec, CompressionDecision, ZstdCodec};
use lchfs_format::{CodecId, ExtentLocation, Hash32};
use lchfs_index::{ChunkLocationCache, PendingDedupPins};
use std::sync::Arc;

/// A byte range handed to the prep pool after `FastCdcChunker` (lchfs-chunk)
/// has already cut a boundary. This pool's job is everything *after* that:
/// hash, dedup-check, maybe-compress.
pub struct PrepTask {
    pub inode_id: u64,
    pub logical_offset: u64,
    pub raw_bytes: bytes::Bytes,
}

/// One chunk's fully-prepared result. Two shapes, not one flat struct,
/// because a dedup hit fundamentally has no ingest work left to do: the
/// bytes are already durable at a known location, so there is nothing to
/// commit through the committer pool at all, and no `payload`/compression
/// `decision` to speak of. The caller (`Pool::write`, E.6) branches on
/// this: `Dedup` skips the committer pool entirely and records a
/// `ChunkRef` at the existing location directly; `New` builds an
/// `IngressOp` and pushes it through `CommitterPool::push`.
pub enum PreparedChunk {
    Dedup {
        content_hash: Hash32,
        location: ExtentLocation,
    },
    New {
        content_hash: Hash32,
        codec_id: CodecId,
        uncompressed_len: u32,
        payload: bytes::Bytes,
    },
}

/// The full per-chunk pipeline (ARCHITECTURE.md §2): hash -> dedup index
/// lookup (fast path: return early on hit) -> sample-and-decide -> maybe
/// compress. Hashing always runs on the *uncompressed* bytes (§2:
/// "Hashing uncompressed bytes" — compression settings can change over
/// time, hashing compressed output would break dedup for identical logical
/// content compressed differently on different occasions).
///
/// A dedup hit pins `content_hash` in `pins` before returning it -- see
/// `PendingDedupPins`'s doc comment for why: the caller is about to start
/// depending on `location` before its own reference to it is checkpointed,
/// and a concurrent GC/Coalesce pass must not reclaim it out from under
/// that in-flight write.
pub fn prepare_chunk(raw_bytes: &[u8], dedup_index: &ChunkLocationCache, pins: &PendingDedupPins) -> PreparedChunk {
    let content_hash = Hash32::of(raw_bytes);
    if let Some(location) = dedup_index.get(content_hash) {
        pins.pin(content_hash);
        return PreparedChunk::Dedup {
            content_hash,
            location,
        };
    }

    let decision = lchfs_compress::sample_and_decide(raw_bytes);
    let (codec_id, payload): (CodecId, Vec<u8>) = match decision {
        CompressionDecision::StoreRaw => (CodecId::None, raw_bytes.to_vec()),
        CompressionDecision::Compress { level, .. } => {
            (CodecId::Zstd, ZstdCodec.compress(raw_bytes, level))
        }
    };

    PreparedChunk::New {
        content_hash,
        codec_id,
        uncompressed_len: raw_bytes.len() as u32,
        payload: bytes::Bytes::from(payload),
    }
}

/// `rayon`-style work-stealing pool, sized to `num_cpus`
/// (ARCHITECTURE.md §5).
pub struct IngestPreparationPool {
    pool: rayon::ThreadPool,
    dedup_index: Arc<ChunkLocationCache>,
    dedup_pins: Arc<PendingDedupPins>,
}

impl IngestPreparationPool {
    pub fn new(worker_count: usize, dedup_index: Arc<ChunkLocationCache>, dedup_pins: Arc<PendingDedupPins>) -> Self {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count.max(1))
            .thread_name(|i| format!("lchfs-prep-{i}"))
            .build()
            .expect("build Ingest Preparation Pool");
        Self {
            pool,
            dedup_index,
            dedup_pins,
        }
    }

    /// Runs `prepare_chunk` on the prep pool, blocking the calling thread
    /// until it completes. Blocking here (via `ThreadPool::install`) is
    /// intentional and matches ARCHITECTURE.md §5's actual intent: what
    /// must not stall is the `fuser` worker thread pool *broadly* (many
    /// concurrent FUSE requests serviced by many worker threads), not this
    /// one `write()` call's own progress — moving the CPU-bound work off
    /// the calling thread and onto a K-wide pool is the actual concurrency
    /// win, not avoiding a blocking wait on its own result.
    pub fn submit(&self, task: PrepTask) -> PreparedChunk {
        let dedup_index = &self.dedup_index;
        let dedup_pins = &self.dedup_pins;
        self.pool
            .install(|| prepare_chunk(&task.raw_bytes, dedup_index, dedup_pins))
    }
}
