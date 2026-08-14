//! Compression throughput (ARCHITECTURE.md §10, benchmark 3 of 4): both the
//! `sample_and_decide` trial-compress step (§8, runs on *every* chunk) and
//! the full compress step (only on chunks that pass the sample's
//! reduction threshold) -- separately, since they run at very different
//! frequencies on the real write path.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_compress::{sample_and_decide, Codec, ZstdCodec};

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

/// Highly compressible: a short repeating pattern tiled out.
fn compressible_bytes(len: usize) -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog, repeatedly, "
        .iter()
        .cycle()
        .take(len)
        .copied()
        .collect()
}

fn bench_sample_and_decide(c: &mut Criterion) {
    let size = 64 * 1024; // ARCHITECTURE.md §2 default avg chunk size
    let mut group = c.benchmark_group("sample_and_decide");
    group.throughput(Throughput::Bytes(size as u64));

    let incompressible = pseudo_random_bytes(size);
    group.bench_with_input(BenchmarkId::new("incompressible", "64KiB"), &incompressible, |b, data| {
        b.iter(|| std::hint::black_box(sample_and_decide(std::hint::black_box(data))));
    });

    let compressible = compressible_bytes(size);
    group.bench_with_input(BenchmarkId::new("compressible", "64KiB"), &compressible, |b, data| {
        b.iter(|| std::hint::black_box(sample_and_decide(std::hint::black_box(data))));
    });
    group.finish();
}

fn bench_full_compress(c: &mut Criterion) {
    let size = 64 * 1024;
    let codec = ZstdCodec;
    let mut group = c.benchmark_group("zstd_compress_level3");
    group.throughput(Throughput::Bytes(size as u64));

    let compressible = compressible_bytes(size);
    group.bench_with_input(BenchmarkId::new("compressible", "64KiB"), &compressible, |b, data| {
        b.iter(|| std::hint::black_box(codec.compress(std::hint::black_box(data), 3)));
    });
    group.finish();
}

criterion_group!(benches, bench_sample_and_decide, bench_full_compress);
criterion_main!(benches);
