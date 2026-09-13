//! The background daemons on a replicated pool (ARCHITECTURE.md §15.7):
//! GC marks once, on the primary, and coalesce sweeps every online vdev
//! from that one mark; the dedup scanner likewise visits every device and
//! never overrides a location the engine chose for a reason.

use lchfs_format::PoolParams;
use lchfs_store::Pool;
use std::path::{Path, PathBuf};

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 16 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as u8);
    }
    out
}

fn data_segments(root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(root.join("segments/data"))
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn names(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect()
}

/// Ten files written, nine overwritten with something much smaller: the
/// original segments are mostly dead on *both* devices.
fn setup_low_liveness_pool(a: &Path, b: &Path) -> (Pool, Vec<(u64, Vec<u8>)>) {
    let pool = Pool::create_replicated(&[a, b], small_params()).unwrap();
    let mut inos = Vec::new();
    for i in 0..10u64 {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &deterministic_bytes(i + 1, 3000)).unwrap();
        inos.push(ino);
    }
    pool.checkpoint().unwrap();
    let mut survivors = Vec::new();
    let last = *inos.last().unwrap();
    survivors.push((last, deterministic_bytes(10, 3000)));
    for &ino in &inos[..9] {
        let data = deterministic_bytes(1000 + ino, 200);
        pool.write(ino, 0, &data).unwrap();
        survivors.push((ino, data));
    }
    pool.checkpoint().unwrap();
    // Push the mostly-dead segments out of the sweep's grace window.
    for i in 0..4u64 {
        let ino = pool.create_file(1, &format!("filler{i}"), 0o644).unwrap();
        pool.write(ino, 0, &deterministic_bytes(500 + i, 3000)).unwrap();
        pool.checkpoint().unwrap();
    }
    (pool, survivors)
}

#[test]
fn coalesce_reclaims_dead_space_on_every_vdev_not_just_the_primary() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(a.path(), b.path());
    let a_before = names(&data_segments(a.path()));
    let b_before = names(&data_segments(b.path()));
    assert_eq!(a_before, b_before, "fan-out should have left identical trees");

    pool.run_gc_and_coalesce_pass().unwrap();

    let a_after = names(&data_segments(a.path()));
    let b_after = names(&data_segments(b.path()));
    let removed_on_a: Vec<_> = a_before.iter().filter(|n| !a_after.contains(n)).collect();
    let removed_on_b: Vec<_> = b_before.iter().filter(|n| !b_after.contains(n)).collect();
    assert!(!removed_on_a.is_empty(), "nothing was repacked on the primary: {a_before:?} -> {a_after:?}");
    assert_eq!(
        removed_on_a, removed_on_b,
        "the same dead segments should have been reclaimed on vdev b"
    );

    // Everything still reads, from the pool...
    for (ino, expected) in &survivors {
        assert_eq!(pool.read(*ino, 0, expected.len() as u32).unwrap().as_ref(), expected.as_slice());
    }
    // ...and from vdev b's repacked copies alone, which is the part that
    // would silently be wrong if b's index entries had not followed its
    // relocations.
    pool.checkpoint().unwrap();
    drop(pool);
    for f in data_segments(a.path()) {
        std::fs::remove_file(f).unwrap();
    }
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    for (ino, expected) in &survivors {
        assert_eq!(
            pool.read(*ino, 0, expected.len() as u32).unwrap().as_ref(),
            expected.as_slice(),
            "ino {ino} not recoverable from vdev b after its repack"
        );
    }
}

/// A repack on vdev b must never touch what the primary reads from.
#[test]
fn a_sweep_of_another_vdev_leaves_the_primary_cache_alone() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let (pool, survivors) = setup_low_liveness_pool(a.path(), b.path());
    pool.run_gc_and_coalesce_pass().unwrap();
    let before = pool.repair_stats();
    for (ino, expected) in &survivors {
        assert_eq!(pool.read(*ino, 0, expected.len() as u32).unwrap().as_ref(), expected.as_slice());
    }
    assert_eq!(
        pool.repair_stats(),
        before,
        "reads after a coalesce pass should not be failing over -- the cache is pointing at the wrong device"
    );
}

/// After failover heals a corrupt primary record into a fresh (higher
/// numbered) segment, the dedup scanner sees two physical copies of one
/// hash. Its old rule -- lowest offset wins -- would point the hash back
/// at the corrupt original, and every read would fail over and heal it
/// again, forever.
#[test]
fn dedup_does_not_hand_a_healed_hash_back_to_its_corrupt_copy() {
    use std::io::{Seek, SeekFrom, Write};
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let ino = {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "big", 0o644).unwrap();
        pool.write(ino, 0, &payload).unwrap();
        pool.checkpoint().unwrap();
        ino
    };
    for path in data_segments(a.path()) {
        let len = std::fs::metadata(&path).unwrap().len();
        if len > 8192 {
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.seek(SeekFrom::Start(len / 2)).unwrap();
            f.write_all(&[0xFFu8; 64]).unwrap();
        }
    }

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    assert_eq!(pool.read(ino, 0, payload.len() as u32).unwrap(), payload);
    let after_heal = pool.repair_stats();
    assert!(after_heal.heals >= 1);
    // Seal the heal segment so the scanner will consider it.
    pool.checkpoint().unwrap();

    pool.run_dedup_pass().unwrap();

    assert_eq!(pool.read(ino, 0, payload.len() as u32).unwrap(), payload);
    assert_eq!(
        pool.repair_stats().failovers,
        after_heal.failovers,
        "the read failed over again: dedup repointed the hash at the corrupt copy"
    );
}
