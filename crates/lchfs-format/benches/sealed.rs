//! A whole sealed record (ARCHITECTURE.md §18, benchmarks): inner header
//! encoding, Padmé padding, the envelope, and on the way back the inner
//! header decode and payload copy -- everything `RecordCrypto` adds on top
//! of the bare AEAD measured in lchfs-crypto's `crypto` bench.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use lchfs_crypto::Key32;
use lchfs_crypto::epoch::EpochKeys;
use lchfs_crypto::keyring::Padding;
use lchfs_format::{CodecId, ExtentKind, RecordCrypto};

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

fn bench_records(c: &mut Criterion) {
    let mut group = c.benchmark_group("sealed_record");
    for (name, padding) in [("padme", Padding::Padme), ("unpadded", Padding::None)] {
        let crypto = RecordCrypto::new([9; 16], 1, 1, padding, vec![EpochKeys::derive(1, &Key32::random())]);
        for &kib in &[4usize, 64, 256] {
            let data = pseudo_random_bytes(kib * 1024);
            let (_, hash) = crypto.address(&data);
            let seal = || crypto.seal(1, ExtentKind::RawChunk, hash, CodecId::None, data.len() as u32, &data, Vec::new());
            let (header, envelope) = seal();
            group.throughput(Throughput::Bytes(data.len() as u64));
            group.bench_function(BenchmarkId::new(format!("seal/{name}"), format!("{kib}KiB")), |b| {
                b.iter(|| std::hint::black_box(seal()));
            });
            group.bench_function(BenchmarkId::new(format!("open/{name}"), format!("{kib}KiB")), |b| {
                b.iter(|| std::hint::black_box(crypto.open(&header, envelope.clone()).unwrap()));
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_records);
criterion_main!(benches);
