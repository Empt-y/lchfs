//! Standalone tests for `prepare_chunk`/`IngestPreparationPool` (E.3)
//! against a fresh `ChunkLocationCache` — no `Pool`/segment I/O involved.

use lchfs_format::{CodecId, ExtentLocation};
use lchfs_index::{ChunkLocationCache, PendingDedupPins};
use lchfs_store::prep::{prepare_chunk, IngestPreparationPool, PrepTask, PreparedChunk};
use std::sync::Arc;

fn no_pins() -> PendingDedupPins {
    PendingDedupPins::new()
}

#[test]
fn miss_produces_new_with_correct_hash() {
    let cache = ChunkLocationCache::new();
    let data = b"some file content that isn't deduped yet";
    let prepared = prepare_chunk(data, &cache, &no_pins());
    match prepared {
        PreparedChunk::New {
            content_hash,
            uncompressed_len,
            ..
        } => {
            assert_eq!(content_hash, lchfs_format::Hash32::of(data));
            assert_eq!(uncompressed_len, data.len() as u32);
        }
        PreparedChunk::Dedup { .. } => panic!("expected a miss on an empty cache"),
    }
}

#[test]
fn hit_short_circuits_to_existing_location() {
    let cache = ChunkLocationCache::new();
    let data = b"already-stored content";
    let hash = lchfs_format::Hash32::of(data);
    let existing = ExtentLocation {
        segment_id: 3,
        offset: 4096,
        len: 64,
    };
    cache.put(hash, existing);

    let prepared = prepare_chunk(data, &cache, &no_pins());
    match prepared {
        PreparedChunk::Dedup {
            content_hash,
            location,
        } => {
            assert_eq!(content_hash, hash);
            assert_eq!(location, existing);
        }
        PreparedChunk::New { .. } => panic!("expected a dedup hit"),
    }
}

#[test]
fn hit_pins_the_hash_until_unpinned() {
    // The whole point of the pin (see `PendingDedupPins`'s doc comment):
    // a dedup hit means the caller is about to start depending on
    // `location` before its own reference is checkpointed, so a
    // concurrent GC/Coalesce pass must be able to see that dependency.
    let cache = ChunkLocationCache::new();
    let data = b"content a concurrent write dedups against";
    let hash = lchfs_format::Hash32::of(data);
    cache.put(
        hash,
        ExtentLocation {
            segment_id: 1,
            offset: 0,
            len: 64,
        },
    );

    let pins = PendingDedupPins::new();
    assert!(!pins.is_pinned(hash));
    let prepared = prepare_chunk(data, &cache, &pins);
    assert!(matches!(prepared, PreparedChunk::Dedup { .. }));
    assert!(pins.is_pinned(hash), "a dedup hit must pin its hash");

    pins.unpin(hash);
    assert!(!pins.is_pinned(hash));
}

#[test]
fn miss_does_not_pin_anything() {
    let cache = ChunkLocationCache::new();
    let data = b"brand new content, never seen before";
    let hash = lchfs_format::Hash32::of(data);
    let pins = PendingDedupPins::new();
    let prepared = prepare_chunk(data, &cache, &pins);
    assert!(matches!(prepared, PreparedChunk::New { .. }));
    assert!(!pins.is_pinned(hash));
}

#[test]
fn incompressible_random_bytes_store_raw() {
    // Not literally random (test determinism), but high-entropy enough
    // that zstd trial compression shouldn't clear the reduction threshold.
    let mut data = Vec::with_capacity(8192);
    let mut x: u64 = 0x243F6A8885A308D3; // arbitrary odd seed
    for _ in 0..8192 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        data.push((x & 0xff) as u8);
    }
    let cache = ChunkLocationCache::new();
    let prepared = prepare_chunk(&data, &cache, &no_pins());
    match prepared {
        PreparedChunk::New { codec_id, .. } => assert_eq!(codec_id, CodecId::None),
        PreparedChunk::Dedup { .. } => panic!("fresh cache should never hit"),
    }
}

#[test]
fn highly_compressible_bytes_get_compressed() {
    let data = vec![b'a'; 16384];
    let cache = ChunkLocationCache::new();
    let prepared = prepare_chunk(&data, &cache, &no_pins());
    match prepared {
        PreparedChunk::New {
            codec_id, payload, ..
        } => {
            assert_eq!(codec_id, CodecId::Zstd);
            assert!(payload.len() < data.len());
        }
        PreparedChunk::Dedup { .. } => panic!("fresh cache should never hit"),
    }
}

#[test]
fn pool_submit_runs_off_calling_thread_and_returns_correct_result() {
    let cache = Arc::new(ChunkLocationCache::new());
    let pool = IngestPreparationPool::new(4, Arc::clone(&cache), Arc::new(PendingDedupPins::new()));

    let data = b"content prepared via the rayon pool, not the caller's thread";
    let task = PrepTask {
        inode_id: 1,
        logical_offset: 0,
        raw_bytes: bytes::Bytes::from_static(data),
    };
    let prepared = pool.submit(task);
    match prepared {
        PreparedChunk::New { content_hash, .. } => {
            assert_eq!(content_hash, lchfs_format::Hash32::of(data));
        }
        PreparedChunk::Dedup { .. } => panic!("expected a miss"),
    }
}

#[test]
fn pool_concurrent_submits_from_many_threads() {
    let cache = Arc::new(ChunkLocationCache::new());
    let pool = Arc::new(IngestPreparationPool::new(
        4,
        Arc::clone(&cache),
        Arc::new(PendingDedupPins::new()),
    ));

    let handles: Vec<_> = (0..32u64)
        .map(|i| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let data = format!("payload-{i}").into_bytes();
                let task = PrepTask {
                    inode_id: i,
                    logical_offset: 0,
                    raw_bytes: bytes::Bytes::from(data.clone()),
                };
                let prepared = pool.submit(task);
                match prepared {
                    PreparedChunk::New { content_hash, .. } => {
                        assert_eq!(content_hash, lchfs_format::Hash32::of(&data));
                    }
                    PreparedChunk::Dedup { .. } => panic!("expected a miss"),
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
