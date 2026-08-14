//! Ring-buffer contention under N concurrent writers (ARCHITECTURE.md §10,
//! benchmark 4 of 4): empirically validates the pillar-2 scaling claim
//! (ARCHITECTURE.md §5 -- M logical-shard ingress rings + work-stealing
//! committer threads) instead of just asserting it. Each thread writes to
//! its *own* file, so this measures shard/committer-pool throughput
//! scaling specifically, not `ino_locks` per-file serialization (a
//! deliberately separate, already-understood restriction -- see
//! `ino_locks`'s own doc comment in lib.rs).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_format::PoolParams;
use lchfs_store::Pool;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

fn bench_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024 * 1024,
        meta_segment_cap_bytes: 16 * 1024 * 1024,
        chunk_avg_size: 64 * 1024,
        chunk_min_size: 16 * 1024,
        chunk_max_size: 256 * 1024,
        inline_threshold: 512,
        // Fixed and generous across every thread-count variant below, so
        // the sweep isolates "does throughput scale with writer count,"
        // not a confound from also varying shard count.
        logical_shard_count: 64,
    }
}

fn pseudo_random_bytes(seed: u64, len: usize) -> Vec<u8> {
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

const WRITES_PER_THREAD: usize = 10;
const WRITE_SIZE: usize = 64 * 1024; // matches chunk_avg_size

fn bench_concurrent_writers(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_writers");
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(10); // real file I/O per iteration -- keep this affordable

    for &threads in &[1usize, 2, 4, 8] {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(Pool::create(dir.path(), bench_params()).unwrap());

        // One file per thread, created up front -- the measured region
        // below is pure write() contention, not create_file()'s own
        // namespace-lock work.
        let inos: Vec<u64> = (0..threads)
            .map(|i| pool.create_file(1, &format!("f{i}"), 0o644).unwrap())
            .collect();
        let payloads: Vec<Vec<u8>> = (0..threads)
            .map(|t| pseudo_random_bytes(t as u64 + 1, WRITE_SIZE))
            .collect();

        let total_bytes = (threads * WRITES_PER_THREAD * WRITE_SIZE) as u64;
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, &threads| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let barrier = Arc::new(Barrier::new(threads));
                    let handles: Vec<_> = (0..threads)
                        .map(|t| {
                            let pool = Arc::clone(&pool);
                            let ino = inos[t];
                            let data = payloads[t].clone();
                            let barrier = Arc::clone(&barrier);
                            std::thread::spawn(move || {
                                barrier.wait();
                                let start = Instant::now();
                                for w in 0..WRITES_PER_THREAD {
                                    pool.write(ino, (w * WRITE_SIZE) as u64, &data).unwrap();
                                }
                                start.elapsed()
                            })
                        })
                        .collect();
                    // Wall-clock for the whole batch is the slowest
                    // thread, since they ran concurrently -- that's what
                    // actually gates end-to-end throughput, not the sum.
                    let slowest = handles
                        .into_iter()
                        .map(|h| h.join().unwrap())
                        .max()
                        .unwrap();
                    total += slowest;
                }
                total
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_concurrent_writers);
criterion_main!(benches);
