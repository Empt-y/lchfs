//! Fuzzes the superblock ring (ARCHITECTURE.md §1): the bytes become a
//! device's `SUPERBLOCK` and both readers run over it -- fsck's own
//! decoder and the engine's, via `Pool::discover`, which reads nothing
//! but the ring. Neither may panic; a hostile ring is "no pool here".
//!
//!   cargo +nightly fuzz run superblock_ring

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn root() -> &'static std::path::Path {
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

fuzz_target!(|data: &[u8]| {
    let root = root();
    std::fs::write(root.join("SUPERBLOCK"), data).unwrap();
    let _ = lchfs_fsck::read_superblock(root);
    let _ = lchfs_store::Pool::discover(&[root], None);
});
