//! What encryption costs per byte (ARCHITECTURE.md §18, benchmarks): the
//! keyed BLAKE3 an encrypted pool addresses content with, against the
//! unkeyed one a plaintext pool uses, and the XChaCha20-Poly1305 envelope
//! every sealed record goes through on write (seal) and read (open).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_crypto::epoch::EpochKeys;
use lchfs_crypto::{Hash32, Key32, envelope};

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

const SIZES_KIB: &[usize] = &[4, 64, 1024];

fn bench_addressing(c: &mut Criterion) {
    let keys = EpochKeys::derive(1, &Key32::random());
    let mut group = c.benchmark_group("address");
    for &kib in SIZES_KIB {
        let data = pseudo_random_bytes(kib * 1024);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("unkeyed", format!("{kib}KiB")), &data, |b, d| {
            b.iter(|| std::hint::black_box(Hash32::of(std::hint::black_box(d))));
        });
        group.bench_with_input(BenchmarkId::new("keyed", format!("{kib}KiB")), &data, |b, d| {
            b.iter(|| std::hint::black_box(keys.address(std::hint::black_box(d))));
        });
    }
    group.finish();
}

fn bench_envelope(c: &mut Criterion) {
    let key = Key32::random();
    let aad = [7u8; 64];
    let mut group = c.benchmark_group("envelope");
    for &kib in SIZES_KIB {
        let data = pseudo_random_bytes(kib * 1024);
        let sealed = envelope::seal(&key, &aad, &data);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("seal", format!("{kib}KiB")), &data, |b, d| {
            b.iter(|| std::hint::black_box(envelope::seal(&key, &aad, std::hint::black_box(d))));
        });
        group.bench_with_input(BenchmarkId::new("open", format!("{kib}KiB")), &sealed, |b, s| {
            b.iter(|| std::hint::black_box(envelope::open(&key, &aad, std::hint::black_box(s)).unwrap()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_addressing, bench_envelope);
criterion_main!(benches);
