//! Fuzzes the superblock ring (ARCHITECTURE.md §1): the bytes become a
//! device's superblock ring (the rest of the ring zeroed) and both readers run over it -- fsck's own
//! decoder and the engine's, via `Pool::discover`, which reads nothing
//! but the ring. Neither may panic; a hostile ring is "no pool here".
//!
//!   cargo +nightly fuzz run superblock_ring

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn root() -> &'static std::path::Path {
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        lchfs_store::backend::FileBackend::open(dir.path()).unwrap();
        dir
    })
    .path()
}

fuzz_target!(|data: &[u8]| {
    let root = root();
    let mut ring = vec![0u8; lchfs_store::testing::read_ring(root).len()];
    let n = data.len().min(ring.len());
    ring[..n].copy_from_slice(&data[..n]);
    lchfs_store::testing::write_ring(root, 0, &ring);
    let _ = lchfs_fsck::read_superblock(root);
    let _ = lchfs_store::Pool::discover(&[root], None);
});
