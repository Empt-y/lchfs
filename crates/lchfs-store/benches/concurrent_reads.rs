//! Read-path throughput scaling under N concurrent readers. The write-path
//! sweep (`concurrent_writes`) found the write path was serialized by global
//! per-inode maps; this asks the same question of reads, which take
//! `readers: Mutex<SegmentReaders>` around the whole verifying `read_record`
//! (pread + decompress + hash-check) of every chunk. Each thread reads its
//! *own* file, cold: the pool is written, checkpointed, and reopened so no
//! `file_state`/session shortcut applies and every read goes through the
//! on-disk chunk path.
//!
//! Same honesty as the write bench: steady-state file sizes and aggregate
//! `total_bytes / (last_end - first_start)`, not the slowest thread.

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
const WRITE_SIZE: usize = 256 * 1024;
const READ_SIZE: usize = 256 * 1024;
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 12, 16];

/// Wall clock of the whole concurrent batch: first read start to last read
/// end, which is what actually gates aggregate throughput.
fn batch_wall_clock(threads: usize, body: Arc<dyn Fn(usize) + Send + Sync>) -> Duration {
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

/// Build a pool with `threads` files of `BYTES_PER_THREAD` each, checkpoint,
/// drop, and reopen so its caches are cold -- reads then go through the
/// on-disk chunk path. Returns the reopened pool, its tempdir (kept alive),
/// and the inos. Reads never mutate, so one cold pool serves every
/// iteration.
fn cold_pool(threads: usize) -> (tempfile::TempDir, Arc<Pool>, Vec<u64>) {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..threads).map(|i| format!("f{i}")).collect();
    {
        let pool = Pool::create(dir.path(), bench_params()).unwrap();
        for (t, name) in names.iter().enumerate() {
            let ino = pool.create_file(1, name, 0o644).unwrap();
            let payload = pseudo_random_bytes(t as u64 + 1, WRITE_SIZE);
            for w in 0..(BYTES_PER_THREAD / WRITE_SIZE) {
                pool.write(ino, (w * WRITE_SIZE) as u64, &payload).unwrap();
            }
        }
        pool.checkpoint().unwrap();
    }
    let pool = Arc::new(Pool::open(dir.path()).unwrap());
    let inos: Vec<u64> = names
        .iter()
        .map(|n| pool.lookup(1, n).unwrap().unwrap())
        .collect();
    (dir, pool, inos)
}

fn bench_concurrent_readers(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_readers");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    for &threads in THREAD_COUNTS {
        let (_dir, pool, inos) = cold_pool(threads);
        group.throughput(Throughput::Bytes((threads * BYTES_PER_THREAD) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, &threads| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let pool = Arc::clone(&pool);
                    let inos = inos.clone();
                    let body: Arc<dyn Fn(usize) + Send + Sync> = Arc::new(move |t: usize| {
                        let ino = inos[t];
                        let mut off = 0u64;
                        while (off as usize) < BYTES_PER_THREAD {
                            let got = pool.read(ino, off, READ_SIZE as u32).unwrap();
                            if got.is_empty() {
                                break;
                            }
                            off += got.len() as u64;
                        }
                    });
                    total += batch_wall_clock(threads, body);
                }
                total
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_concurrent_readers);
criterion_main!(benches);
