//! Ad-hoc measurement for ARCHITECTURE.md §15.9's "per-vdev performance
//! skew": how much a synchronous N-way fan-out costs the write path.
//! Not a benchmark harness; run by hand, read the numbers.
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let base: PathBuf = std::env::args().nth(1).expect("base dir").into();
    let total_mb: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(256);
    let params = lchfs_format::PoolParams {
        logical_shard_count: 16,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
        ..Default::default()
    };
    // Incompressible, so the cost measured is I/O and framing, not zstd.
    let mut buf = vec![0u8; 1 << 20];
    let mut x = 0x9E3779B97F4A7C15u64;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
    for n in [1usize, 2, 3] {
        let roots: Vec<PathBuf> = (0..n).map(|i| base.join(format!("v{n}_{i}"))).collect();
        for r in &roots {
            let _ = std::fs::remove_dir_all(r);
        }
        let root_refs: Vec<&std::path::Path> = roots.iter().map(|p| p.as_path()).collect();
        let pool = lchfs_store::Pool::create_replicated(&root_refs, params).unwrap();
        let t = Instant::now();
        for f in 0..8u32 {
            let ino = pool.create_file(1, &format!("f{f}"), 0o644).unwrap();
            let mut off = 0u64;
            for m in 0..(total_mb / 8) {
                // vary content per MB so dedup finds nothing
                buf[0..8].copy_from_slice(&(((f as u64) << 32) | m as u64).to_le_bytes());
                pool.write(ino, off, &buf).unwrap();
                off += buf.len() as u64;
            }
        }
        let write = t.elapsed();
        let t = Instant::now();
        pool.checkpoint().unwrap();
        let ckpt = t.elapsed();
        let mb_s = total_mb as f64 / write.as_secs_f64();
        println!("{n} vdev(s): {total_mb} MB written in {write:.2?} ({mb_s:.0} MB/s), checkpoint {ckpt:.2?}");
        drop(pool);
        for r in &roots {
            let _ = std::fs::remove_dir_all(r);
        }
    }
}
