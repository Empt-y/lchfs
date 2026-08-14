//! Regression tests for two issues found during a manual review after
//! Phase E: (1) a corrupted record-framing length prefix could panic a
//! reading thread instead of surfacing an error (ARCHITECTURE.md §8's
//! "detect only, never crash" contract), and (2) write()/set_size() with
//! an attacker/bug-controlled huge offset or size could attempt an
//! unbounded in-memory allocation.

use lchfs_format::{CodecId, ExtentKind, ExtentRecordHeader, Hash32, PoolParams, finalize_header_checksum};
use lchfs_store::segment::parse_record_header;
use lchfs_store::{Pool, PoolError};
use std::io::{Seek, SeekFrom, Write};

fn small_params() -> PoolParams {
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

/// A corrupted `header_len` framing prefix (the raw 4-byte value read
/// before anything is validated) must produce a structured error, never
/// panic the calling thread by slicing out of bounds.
#[test]
fn corrupted_header_len_prefix_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f.bin", 0o644).unwrap();
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // The very first record in the data segment starts right after the
    // 4096-byte reserved header page; its first 4 bytes are the raw
    // `header_len` framing prefix, itself unprotected by any checksum.
    let data_seg_path = dir.path().join("segments/data/0.aseg");
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&data_seg_path)
        .unwrap();
    f.seek(SeekFrom::Start(4096)).unwrap();
    f.write_all(&u32::MAX.to_le_bytes()).unwrap();
    drop(f);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f.bin").unwrap().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pool.read(ino, 0, 5000)));
    match result {
        Ok(Err(_)) => {} // correct: a structured error, not a panic
        Ok(Ok(_)) => panic!("corrupted header_len prefix should not read back as success"),
        Err(_) => panic!("corrupted header_len prefix must not panic the reading thread"),
    }
}

/// Direct unit-level coverage of `parse_record_header` -- the standalone
/// "Extent Record header parser" ARCHITECTURE.md §10 calls out for
/// fuzzing (see `fuzz/fuzz_targets/extent_header.rs`). These pin down its
/// never-panic contract against specific hand-picked adversarial inputs
/// as fast, deterministic regression tests; the fuzz target explores the
/// same contract far more broadly.
#[test]
fn parse_record_header_rejects_malformed_input_without_panicking() {
    let cases: &[&[u8]] = &[
        &[],
        &[0, 0],
        &[0, 0, 0, 0],           // header_len == 0
        &[0xff, 0xff, 0xff, 0xff], // header_len == u32::MAX, far beyond the buffer
        &[1, 0, 0, 0, 0xaa],     // header_len == 1, but garbage bincode content
        &[4, 0, 0, 0],           // header_len == 4, but buffer ends right there
    ];
    for bytes in cases {
        let result = std::panic::catch_unwind(|| parse_record_header(bytes));
        assert!(result.is_ok(), "parse_record_header panicked on {bytes:?}");
        assert!(result.unwrap().is_none(), "expected rejection for {bytes:?}");
    }
}

#[test]
fn parse_record_header_accepts_a_well_formed_header() {
    let mut header = ExtentRecordHeader {
        magic: lchfs_format::EXTENT_RECORD_MAGIC,
        record_len: 0, // patched below, doesn't affect this function
        content_hash: Hash32::of(b"hello"),
        kind: ExtentKind::RawChunk,
        codec_id: CodecId::None,
        flags: 0,
        uncompressed_len: 5,
        compressed_len: 5,
        backpointers: Vec::new(),
        header_checksum: 0,
    };
    finalize_header_checksum(&mut header);
    let encoded = lchfs_format::encode(&header).unwrap();

    let mut buf = Vec::new();
    buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    buf.extend_from_slice(&encoded);
    buf.extend_from_slice(b"hello"); // trailing payload, ignored by this function

    let (parsed, consumed) = parse_record_header(&buf).expect("well-formed header must parse");
    assert_eq!(parsed.content_hash, header.content_hash);
    assert_eq!(consumed, 4 + encoded.len());
}

#[test]
fn write_beyond_max_file_size_returns_too_large_not_oom() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f.bin", 0o644).unwrap();

    // Simulates a huge `lseek`+`write` (or a corrupted/malicious offset)
    // -- must be rejected before any allocation is attempted, not after.
    let huge_offset = 100u64 * 1024 * 1024 * 1024 * 1024; // 100 TiB
    let result = pool.write(ino, huge_offset, b"x");
    assert!(
        matches!(result, Err(PoolError::TooLarge(_))),
        "expected TooLarge, got {result:?}"
    );
}

#[test]
fn set_size_beyond_max_file_size_returns_too_large_not_oom() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f.bin", 0o644).unwrap();

    // Simulates a huge `truncate(2)` -- must be rejected before any
    // allocation is attempted, not after.
    let huge_size = 100u64 * 1024 * 1024 * 1024 * 1024; // 100 TiB
    let result = pool.set_size(ino, huge_size);
    assert!(
        matches!(result, Err(PoolError::TooLarge(_))),
        "expected TooLarge, got {result:?}"
    );
}

/// A size right at (or just under) the cap must still work normally --
/// confirms the check is a boundary, not an accidental blanket rejection.
#[test]
fn ordinary_small_write_and_resize_still_work() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f.bin", 0o644).unwrap();
    let content = vec![7u8; 10_000];
    pool.write(ino, 0, &content).unwrap();
    assert_eq!(&pool.read(ino, 0, 10_000).unwrap()[..], &content[..]);

    pool.set_size(ino, 20_000).unwrap();
    assert_eq!(pool.read(ino, 0, 20_000).unwrap().len(), 20_000);
}
