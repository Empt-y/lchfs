//! End-to-end tests for the Phase B single-threaded engine: real segment
//! I/O, superblock commit/recovery, dedup-on-write, and integrity checking.
//! ARCHITECTURE.md §12 Phase B: "Validates pillars 1 and 3 before
//! concurrency is added."

use lchfs_format::PoolParams;
use lchfs_store::{Pool, PoolError};
use std::io::{Seek, SeekFrom, Write};

fn small_params() -> PoolParams {
    // Small caps/thresholds so tests can exercise segment rollover and
    // chunked (non-inline) content without huge fixtures.
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
    }
}

#[test]
fn create_open_and_read_root() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let entries = pool.readdir(1).unwrap();
    assert!(entries.is_empty());
    drop(pool);

    // Reopen without any writes — must still recover cleanly.
    let pool2 = Pool::open(dir.path()).unwrap();
    assert!(pool2.readdir(1).unwrap().is_empty());
}

#[test]
fn create_twice_fails() {
    let dir = tempfile::tempdir().unwrap();
    Pool::create(dir.path(), small_params()).unwrap();
    let err = Pool::create(dir.path(), small_params()).unwrap_err();
    assert!(matches!(err, PoolError::AlreadyExists(_)));
}

#[test]
fn open_nonexistent_pool_fails() {
    let dir = tempfile::tempdir().unwrap();
    let err = Pool::open(dir.path()).unwrap_err();
    assert!(matches!(err, PoolError::Format(_)));
}

#[test]
fn inline_file_write_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "small.txt", 0o644).unwrap();
    pool.write(ino, 0, b"hello world").unwrap();

    let data = pool.read(ino, 0, 11).unwrap();
    assert_eq!(&data[..], b"hello world");

    let attr = pool.getattr(ino).unwrap();
    assert_eq!(attr.size, 11);
}

#[test]
fn chunked_file_write_read_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "big.bin", 0o644).unwrap();

    // Bigger than inline_threshold (64) and bigger than one chunk (avg
    // 1024) so this must go through FastCdcChunker + multiple RawChunks.
    let content: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    pool.write(ino, 0, &content).unwrap();

    let read_back = pool.read(ino, 0, content.len() as u32).unwrap();
    assert_eq!(&read_back[..], &content[..]);

    // Partial read from the middle.
    let mid = pool.read(ino, 5000, 100).unwrap();
    assert_eq!(&mid[..], &content[5000..5100]);
}

#[test]
fn overwrite_and_sparse_extend() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    pool.write(ino, 0, b"AAAABBBB").unwrap();
    pool.write(ino, 4, b"XXXX").unwrap(); // overwrite middle
    let data = pool.read(ino, 0, 8).unwrap();
    assert_eq!(&data[..], b"AAAAXXXX");

    // Write past the current end — the gap must read back as zero.
    pool.write(ino, 12, b"END").unwrap();
    let data = pool.read(ino, 0, 15).unwrap();
    assert_eq!(&data[..8], b"AAAAXXXX");
    assert_eq!(&data[8..12], &[0, 0, 0, 0]);
    assert_eq!(&data[12..15], b"END");
}

#[test]
fn mkdir_lookup_and_readdir() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let sub = pool.mkdir(1, "subdir", 0o755).unwrap();
    let file = pool.create_file(sub, "note.txt", 0o644).unwrap();
    pool.write(file, 0, b"hi").unwrap();

    assert_eq!(pool.lookup(1, "subdir").unwrap(), Some(sub));
    assert_eq!(pool.lookup(1, "nope").unwrap(), None);
    assert_eq!(pool.lookup(sub, "note.txt").unwrap(), Some(file));

    let root_entries = pool.readdir(1).unwrap();
    assert_eq!(root_entries.len(), 1);
    assert_eq!(root_entries[0].name, "subdir");

    let sub_entries = pool.readdir(sub).unwrap();
    assert_eq!(sub_entries.len(), 1);
    assert_eq!(sub_entries[0].name, "note.txt");
}

#[test]
fn parent_of_resolves_correctly_including_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let pool = Pool::create(dir.path(), small_params()).unwrap();
        let sub = pool.mkdir(1, "subdir", 0o755).unwrap();
        assert_eq!(pool.parent_of(1).unwrap(), 1);
        assert_eq!(pool.parent_of(sub).unwrap(), 1);
        pool.checkpoint().unwrap();
    }
    let pool = Pool::open(dir.path()).unwrap();
    let sub = pool.lookup(1, "subdir").unwrap().unwrap();
    assert_eq!(pool.parent_of(1).unwrap(), 1);
    assert_eq!(pool.parent_of(sub).unwrap(), 1);
}

#[test]
fn create_duplicate_name_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_file(1, "dup", 0o644).unwrap();
    let err = pool.create_file(1, "dup", 0o644).unwrap_err();
    assert!(matches!(err, PoolError::AlreadyExists(_)));
}

/// The core crash-recovery property (ARCHITECTURE.md §7): after a
/// checkpoint, closing and reopening the pool must recover the exact same
/// tree — files, directories, and content all survive a fresh `Pool::open`
/// scan-and-replay with no data loss.
#[test]
fn survives_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let pool = Pool::create(dir.path(), small_params()).unwrap();
        let sub = pool.mkdir(1, "docs", 0o755).unwrap();
        let f1 = pool.create_file(1, "small.txt", 0o644).unwrap();
        pool.write(f1, 0, b"tiny content").unwrap();
        let f2 = pool.create_file(sub, "big.bin", 0o644).unwrap();
        let content: Vec<u8> = (0..20_000u32).map(|i| (i % 200) as u8).collect();
        pool.write(f2, 0, &content).unwrap();
        pool.checkpoint().unwrap();
    }

    let pool = Pool::open(dir.path()).unwrap();
    let sub = pool.lookup(1, "docs").unwrap().expect("docs dir survives");
    let f1 = pool
        .lookup(1, "small.txt")
        .unwrap()
        .expect("small.txt survives");
    let f2 = pool
        .lookup(sub, "big.bin")
        .unwrap()
        .expect("big.bin survives");

    assert_eq!(&pool.read(f1, 0, 12).unwrap()[..], b"tiny content");
    let expected: Vec<u8> = (0..20_000u32).map(|i| (i % 200) as u8).collect();
    assert_eq!(&pool.read(f2, 0, 20_000).unwrap()[..], &expected[..]);
}

/// ARCHITECTURE.md §2: identical content must dedup to the same on-disk
/// chunk rather than being stored twice.
#[test]
fn identical_content_is_deduplicated() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let content: Vec<u8> = (0..10_000u32).map(|i| (i % 100) as u8).collect();
    let f1 = pool.create_file(1, "a.bin", 0o644).unwrap();
    pool.write(f1, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    let size_after_first = std::fs::metadata(dir.path().join("segments/data/0.aseg"))
        .unwrap()
        .len();

    let f2 = pool.create_file(1, "b.bin", 0o644).unwrap();
    pool.write(f2, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    let size_after_second = std::fs::metadata(dir.path().join("segments/data/0.aseg"))
        .unwrap()
        .len();

    assert_eq!(
        size_after_first, size_after_second,
        "writing identical content again must not grow the data segment"
    );
    assert_eq!(&pool.read(f2, 0, 10_000).unwrap()[..], &content[..]);
}

/// ARCHITECTURE.md §1 mandatory read-side check: a bit-flip in a data
/// segment must be caught as an integrity failure, never silently served.
#[test]
fn corrupted_chunk_is_detected_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f.bin", 0o644).unwrap();
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // Flip a byte well past the segment header page, inside chunk payload.
    let data_seg_path = dir.path().join("segments/data/0.aseg");
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&data_seg_path)
        .unwrap();
    f.seek(SeekFrom::Start(4200)).unwrap();
    let mut byte = [0u8; 1];
    std::io::Read::read_exact(&mut f, &mut byte).unwrap();
    byte[0] ^= 0xFF;
    f.seek(SeekFrom::Start(4200)).unwrap();
    f.write_all(&byte).unwrap();
    drop(f);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f.bin").unwrap().unwrap();
    let result = pool.read(ino, 0, 5000);
    assert!(
        matches!(result, Err(PoolError::IntegrityFailure(_))),
        "expected IntegrityFailure, got {result:?}"
    );
}

/// Cheap deterministic pseudo-random byte generator (finalizer-mix style) —
/// high enough entropy that zstd trial-compression won't hit the >=10%
/// reduction threshold, unlike a simple periodic pattern. Needed so this
/// test's content actually stays close to its logical size on disk instead
/// of compressing away to nothing.
fn pseudo_random_byte(file_index: u32, i: u32) -> u8 {
    let mut x = i
        .wrapping_mul(2_654_435_761)
        .wrapping_add(file_index.wrapping_mul(40_503));
    x ^= x >> 13;
    x = x.wrapping_mul(0x85eb_ca6b);
    x ^= x >> 16;
    (x & 0xFF) as u8
}

#[test]
fn segment_rollover_across_many_writes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    // Each file's content is unique (keyed by index) and high-entropy, so
    // nothing dedups or compresses away, forcing genuine segment growth
    // past the small 64KiB cap.
    for i in 0..20u32 {
        let name = format!("f{i}.bin");
        let ino = pool.create_file(1, &name, 0o644).unwrap();
        let content: Vec<u8> = (0..8000u32).map(|b| pseudo_random_byte(i, b)).collect();
        pool.write(ino, 0, &content).unwrap();
    }
    pool.checkpoint().unwrap();

    let data_dir = dir.path().join("segments/data");
    let segment_count = std::fs::read_dir(&data_dir).unwrap().count();
    assert!(
        segment_count > 1,
        "expected multiple data segments after exceeding the cap, got {segment_count}"
    );

    // Everything must still read back correctly across segment boundaries.
    for i in 0..20u32 {
        let name = format!("f{i}.bin");
        let ino = pool.lookup(1, &name).unwrap().unwrap();
        let expected: Vec<u8> = (0..8000u32).map(|b| pseudo_random_byte(i, b)).collect();
        assert_eq!(&pool.read(ino, 0, 8000).unwrap()[..], &expected[..]);
    }
}
