//! Chunking throughput (ARCHITECTURE.md §10, benchmark 1 of 4): empirically
//! validates FastCDC cost isn't a bottleneck relative to the write path's
//! other stages (hash, compress, segment I/O) it runs alongside.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_chunk::{Chunker, FastCdcChunker};

/// Deterministic, reproducible pseudo-random bytes -- not cryptographically
/// random, just varied enough that FastCDC's rolling hash sees realistic
/// cut-point variety instead of the pathological all-same-byte case.
fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as u8);
    }
    out
}

fn bench_chunking(c: &mut Criterion) {
    // ARCHITECTURE.md §2 defaults: avg 64KiB / min 16KiB / max 256KiB.
    let (avg, min, max) = (64 * 1024, 16 * 1024, 256 * 1024);

    let mut group = c.benchmark_group("fastcdc_chunking");
    for &size_mib in &[1usize, 8, 32] {
        let size = size_mib * 1024 * 1024;
        let data = pseudo_random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(format!("{size_mib}MiB")), &data, |b, data| {
            b.iter(|| {
                let mut chunker = FastCdcChunker::new(avg, min, max);
                let mut boundaries = chunker.push(std::hint::black_box(data));
                if let Some(last) = chunker.finish() {
                    boundaries.push(last);
                }
                std::hint::black_box(boundaries.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_chunking);
criterion_main!(benches);
