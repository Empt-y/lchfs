//! Write-path throughput scaling under N concurrent writers (ARCHITECTURE.md
//! §10 benchmark 4, and the §17.0 open question about 4→8 flattening). Each
//! thread writes to its *own* file, so this measures shard/committer-pool
//! and write-path-lock scaling, not `ino_locks` per-file serialization (a
//! deliberately separate, already-understood restriction -- see `ino_locks`'s
//! own doc comment in lib.rs).
//!
//! Two things this bench is careful about, because the earlier version got
//! both wrong and made the flattening look worse than it is:
//!  - **Steady state, not startup.** Each thread writes `BYTES_PER_THREAD`
//!    (tens of MiB), so fixed per-`write()` overhead amortizes instead of
//!    dominating a 640 KiB burst.
//!  - **Aggregate wall clock, not slowest thread.** Throughput is
//!    `total_bytes / (last_end - first_start)` across all threads -- the real
//!    end-to-end rate -- rather than `max` of the per-thread elapseds, which
//!    is an order statistic that climbs with N even at equal per-thread speed.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_format::PoolParams;
use lchfs_store::Pool;
use std::sync::{Arc, Barrier, Mutex};
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
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
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

const BYTES_PER_THREAD: usize = 32 * 1024 * 1024;
const WRITE_SIZE: usize = 256 * 1024; // a few chunks per write (chunk_avg 64 KiB)
const WRITES_PER_THREAD: usize = BYTES_PER_THREAD / WRITE_SIZE;
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 12, 16];

fn run_sweep(
    c: &mut Criterion,
    group_name: &str,
    make_body: impl Fn(&Arc<Pool>, &[u64], &[Vec<u8>]) -> Box<dyn Fn(usize) + Send + Sync>,
) {
    let mut group = c.benchmark_group(group_name);
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10); // real file I/O per iteration -- keep it affordable

    for &threads in THREAD_COUNTS {
        group.throughput(Throughput::Bytes((threads * BYTES_PER_THREAD) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, &threads| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // A fresh pool per iteration: unique-writer data never
                    // accumulates across iterations (bounded tmpfs use, no
                    // growing-index skew), and every iteration starts from
                    // the same cold-but-equal state. Pool/file setup is
                    // outside the timed region below.
                    let dir = tempfile::tempdir().unwrap();
                    let pool = Arc::new(Pool::create(dir.path(), bench_params()).unwrap());
                    let inos: Vec<u64> = (0..threads)
                        .map(|i| pool.create_file(1, &format!("f{i}"), 0o644).unwrap())
                        .collect();
                    let payloads: Vec<Vec<u8>> = (0..threads)
                        .map(|t| pseudo_random_bytes(t as u64 + 1, WRITE_SIZE))
                        .collect();
                    let body = Arc::new(make_body(&pool, &inos, &payloads));
                    total += batch_wall_clock_dyn(threads, body);
                    // pool + tempdir dropped here, freeing this iteration's data.
                }
                total
            });
        });
    }
    group.finish();
}

/// `batch_wall_clock` for a heap closure shared across threads.
fn batch_wall_clock_dyn(threads: usize, body: Arc<Box<dyn Fn(usize) + Send + Sync>>) -> Duration {
    let barrier = Arc::new(Barrier::new(threads));
    let span: Arc<Mutex<Option<(Instant, Instant)>>> = Arc::new(Mutex::new(None));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let barrier = Arc::clone(&barrier);
            let span = Arc::clone(&span);
            let body = Arc::clone(&body);
            std::thread::spawn(move || {
                barrier.wait();
                let start = Instant::now();
                body(t);
                let end = Instant::now();
                let mut s = span.lock().unwrap();
                *s = Some(match *s {
                    None => (start, end),
                    Some((lo, hi)) => (lo.min(start), hi.max(end)),
                });
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let (lo, hi) = span.lock().unwrap().expect("at least one thread");
    hi - lo
}

fn bench_concurrent_writers(c: &mut Criterion) {
    // Each write repeats this thread's own payload, so after the first
    // chunk everything dedups: measures the prep pool + dedup path + the
    // write-path locks, not the committer/index.
    run_sweep(c, "concurrent_writers", |pool, inos, payloads| {
        let pool = Arc::clone(pool);
        let inos = inos.to_vec();
        let payloads = payloads.to_vec();
        Box::new(move |t: usize| {
            let ino = inos[t];
            let data = &payloads[t];
            for w in 0..WRITES_PER_THREAD {
                pool.write(ino, (w * WRITE_SIZE) as u64, data).unwrap();
            }
        })
    });
}

fn bench_concurrent_unique_writers(c: &mut Criterion) {
    // Every write carries bytes no other write has, so each chunk goes
    // through the committer and the index put rather than a dedup hit:
    // measures the committer/index path plus the write-path locks.
    run_sweep(c, "concurrent_unique_writers", |pool, inos, payloads| {
        let pool = Arc::clone(pool);
        let inos = inos.to_vec();
        let payloads = payloads.to_vec();
        let unique = Arc::new(std::sync::atomic::AtomicU64::new(0));
        Box::new(move |t: usize| {
            let ino = inos[t];
            let mut data = payloads[t].clone();
            for w in 0..WRITES_PER_THREAD {
                let n = unique.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                data[..8].copy_from_slice(&n.to_le_bytes());
                pool.write(ino, (w * WRITE_SIZE) as u64, &data).unwrap();
            }
        })
    });
}

criterion_group!(benches, bench_concurrent_writers, bench_concurrent_unique_writers);
criterion_main!(benches);
