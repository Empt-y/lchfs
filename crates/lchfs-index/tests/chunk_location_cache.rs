//! Standalone tests for `ChunkLocationCache` (Phase E). No `Pool`/segment
//! I/O involved — pure in-memory map behavior, including concurrent access
//! from multiple threads.

use lchfs_format::{ExtentLocation, Hash32};
use lchfs_index::ChunkLocationCache;
use std::sync::Arc;

fn loc(segment_id: u64, offset: u32) -> ExtentLocation {
    ExtentLocation {
        segment_id,
        offset,
        len: 128,
    }
}

#[test]
fn get_on_empty_cache_is_none() {
    let cache = ChunkLocationCache::new();
    assert_eq!(cache.get(Hash32::of(b"nope")), None);
    assert!(cache.is_empty());
}

#[test]
fn put_then_get_round_trips() {
    let cache = ChunkLocationCache::new();
    let hash = Hash32::of(b"some content");
    cache.put(hash, loc(1, 4096));
    assert_eq!(cache.get(hash), Some(loc(1, 4096)));
    assert_eq!(cache.len(), 1);
}

#[test]
fn put_overwrites_existing_entry() {
    let cache = ChunkLocationCache::new();
    let hash = Hash32::of(b"relocated content");
    cache.put(hash, loc(1, 100));
    cache.put(hash, loc(2, 200));
    assert_eq!(cache.get(hash), Some(loc(2, 200)));
    assert_eq!(cache.len(), 1);
}

#[test]
fn extend_bulk_loads_entries() {
    let cache = ChunkLocationCache::new();
    let entries: Vec<_> = (0..20u64)
        .map(|i| (Hash32::of(format!("chunk-{i}").as_bytes()), loc(i, i as u32)))
        .collect();
    cache.extend(entries.clone());
    assert_eq!(cache.len(), 20);
    for (hash, expected_loc) in entries {
        assert_eq!(cache.get(hash), Some(expected_loc));
    }
}

#[test]
fn concurrent_put_and_get_from_many_threads() {
    let cache = Arc::new(ChunkLocationCache::new());
    let handles: Vec<_> = (0..16u64)
        .map(|t| {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                for i in 0..200u64 {
                    let hash = Hash32::of(format!("t{t}-{i}").as_bytes());
                    cache.put(hash, loc(t, i as u32));
                    assert_eq!(cache.get(hash), Some(loc(t, i as u32)));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(cache.len(), 16 * 200);
}
