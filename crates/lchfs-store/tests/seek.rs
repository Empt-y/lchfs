//! `SEEK_DATA`/`SEEK_HOLE` (lseek(2)) over the sparse chunk list.
//!
//! Sparse files landed in dafa741 but nothing exposed the holes to
//! userspace, so `cp --sparse=auto`, `tar -S` and `rsync -S` could not see
//! them. `Pool::seek` reads the same gapped chunk list `Pool::read` does.
//!
//! Assertions are deliberately expressed as *properties* verified against
//! the file's actual bytes rather than as hardcoded offsets: FastCDC
//! boundaries are content-defined, so pinning exact chunk edges would make
//! these tests fragile against unrelated chunker changes without testing
//! anything more.

use lchfs_format::PoolParams;
use lchfs_store::{Pool, SeekWhence};

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 256 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
    }
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // Never emit 0, so a dense file can never contain an all-zero run
        // long enough to be declined as a hole.
        out.push(((x & 0xff) as u8) | 1);
    }
    out
}

/// Reopens so reads/seeks go through the persisted chunk list with no
/// `file_state` cached -- the only path that has real hole structure.
fn reopened(dir: &std::path::Path, build: impl FnOnce(&Pool, u64)) -> (Pool, u64) {
    let pool = Pool::create(dir, small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    build(&pool, ino);
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open(dir).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    (pool, ino)
}

fn byte_at(pool: &Pool, ino: u64, off: u64) -> u8 {
    pool.read(ino, off, 1).unwrap().first().copied().unwrap()
}

#[test]
fn seek_at_or_past_eof_is_enxio() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ino) = reopened(dir.path(), |p, ino| {
        p.write(ino, 0, &deterministic_bytes(1, 4096)).unwrap();
    });
    let size = pool.getattr(ino).unwrap().size;
    assert_eq!(pool.seek(ino, size, SeekWhence::Data).unwrap(), None);
    assert_eq!(pool.seek(ino, size, SeekWhence::Hole).unwrap(), None);
    assert_eq!(pool.seek(ino, size + 4096, SeekWhence::Data).unwrap(), None);
}

/// The key regression risk in the hole walk: a dense file is many adjacent
/// chunks, and every chunk boundary is a chance to report a hole that isn't
/// there. Only EOF may be reported.
#[test]
fn a_dense_multi_chunk_file_has_no_hole_before_eof() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ino) = reopened(dir.path(), |p, ino| {
        p.write(ino, 0, &deterministic_bytes(2, 64 * 1024)).unwrap();
    });
    let size = pool.getattr(ino).unwrap().size;
    assert_eq!(pool.seek(ino, 0, SeekWhence::Hole).unwrap(), Some(size));
    assert_eq!(pool.seek(ino, 0, SeekWhence::Data).unwrap(), Some(0));
    assert_eq!(pool.seek(ino, 1234, SeekWhence::Data).unwrap(), Some(1234));
}

#[test]
fn a_hole_is_found_and_really_reads_as_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ino) = reopened(dir.path(), |p, ino| {
        p.write(ino, 0, &deterministic_bytes(3, 512)).unwrap();
        p.write(ino, 64 * 1024, &deterministic_bytes(4, 512)).unwrap();
    });
    let size = pool.getattr(ino).unwrap().size;

    let hole = pool.seek(ino, 0, SeekWhence::Hole).unwrap().unwrap();
    assert!(hole > 0 && hole < size, "hole {hole} not strictly inside 0..{size}");
    // A reported hole must actually read as zero, or SEEK_HOLE is lying.
    assert_eq!(byte_at(&pool, ino, hole), 0);

    // Already inside the hole -> that same offset is the answer.
    assert_eq!(pool.seek(ino, hole, SeekWhence::Hole).unwrap(), Some(hole));
}

#[test]
fn seek_data_skips_the_hole_and_everything_skipped_is_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ino) = reopened(dir.path(), |p, ino| {
        p.write(ino, 0, &deterministic_bytes(5, 512)).unwrap();
        p.write(ino, 64 * 1024, &deterministic_bytes(6, 512)).unwrap();
    });
    let hole = pool.seek(ino, 0, SeekWhence::Hole).unwrap().unwrap();
    let data = pool.seek(ino, hole, SeekWhence::Data).unwrap().unwrap();
    assert!(data > hole, "SEEK_DATA {data} did not advance past hole {hole}");

    // Everything SEEK_DATA skipped must be zero -- if any non-zero byte were
    // in there, a sparse-aware copy would silently drop it.
    let skipped = pool.read(ino, hole, (data - hole) as u32).unwrap();
    assert!(skipped.iter().all(|&b| b == 0), "skipped range was not all zeros");
    assert_ne!(byte_at(&pool, ino, data), 0, "SEEK_DATA landed on a zero byte");
}

#[test]
fn a_trailing_hole_means_seek_data_is_enxio() {
    let dir = tempfile::tempdir().unwrap();
    let (pool, ino) = reopened(dir.path(), |p, ino| {
        p.write(ino, 0, &deterministic_bytes(7, 512)).unwrap();
        p.set_size(ino, 64 * 1024).unwrap();
    });
    let size = pool.getattr(ino).unwrap().size;
    let hole = pool.seek(ino, 0, SeekWhence::Hole).unwrap().unwrap();
    assert!(hole < size);
    // No data at or after the hole -> ENXIO, per lseek(2).
    assert_eq!(pool.seek(ino, hole, SeekWhence::Data).unwrap(), None);
    // EOF still counts as a hole.
    assert_eq!(pool.seek(ino, hole, SeekWhence::Hole).unwrap(), Some(hole));
}

/// Documents the deliberate conservative branch: with content materialized
/// in memory there is no hole structure to consult, so the file is reported
/// as entirely data. Legal per POSIX (only EOF need be a hole) and the safe
/// direction -- calling data "a hole" would make `cp --sparse` write zeros
/// over real bytes.
#[test]
fn materialized_content_is_conservatively_reported_as_all_data() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(8, 512)).unwrap();
    pool.write(ino, 64 * 1024, &deterministic_bytes(9, 512)).unwrap();
    // No checkpoint/reopen: file_state is still hydrated.
    let size = pool.getattr(ino).unwrap().size;
    assert_eq!(pool.seek(ino, 0, SeekWhence::Hole).unwrap(), Some(size));
    assert_eq!(pool.seek(ino, 4096, SeekWhence::Data).unwrap(), Some(4096));
}

#[test]
fn seek_on_a_directory_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let d = pool.mkdir(1, "d", 0o755).unwrap();
    assert!(pool.seek(d, 0, SeekWhence::Data).is_err());
}
