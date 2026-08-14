//! Hash throughput (ARCHITECTURE.md §10, benchmark 2 of 4): BLAKE3 runs on
//! every chunk and every meta object, both on write (hash) and read
//! (re-verify) -- this is the write/read path's per-byte floor.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_crypto::Hash32;

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

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash");
    for &size_kib in &[4usize, 64, 1024] {
        let size = size_kib * 1024;
        let data = pseudo_random_bytes(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(format!("{size_kib}KiB")), &data, |b, data| {
            b.iter(|| std::hint::black_box(Hash32::of(std::hint::black_box(data))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hashing);
criterion_main!(benches);
