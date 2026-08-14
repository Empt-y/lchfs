//! End-to-end tests for `lchfs-fsck` against a real on-disk pool.

use lchfs_format::PoolParams;
use lchfs_store::Pool;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
    }
}

fn deterministic_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as u8);
    }
    out
}

/// Builds a reasonably varied pool -- files (inline and chunked),
/// directories, a symlink, a hardlink -- and checkpoints it.
fn setup_populated_pool(dir: &std::path::Path) -> Pool {
    let pool = Pool::create(dir, small_params()).unwrap();
    let d = pool.mkdir(1, "dir", 0o755).unwrap();
    pool.create_file(1, "inline.txt", 0o644).unwrap();
    let ino = pool.create_file(d, "chunked.bin", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(1, 4000)).unwrap();
    pool.symlink(1, "link", "/target").unwrap();
    let a = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(a, 0, b"shared").unwrap();
    pool.link(a, 1, "b").unwrap();
    pool.checkpoint().unwrap();
    pool
}

#[test]
fn clean_pool_reports_no_errors() {
    let dir = tempfile::tempdir().unwrap();
    let pool = setup_populated_pool(dir.path());
    drop(pool);

    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &live_roots);
    assert!(report.is_clean(), "expected a clean report, got {:?}", report.errors);
    assert!(report.objects_visited > 0);
}

#[test]
fn empty_pool_reports_no_errors() {
    let dir = tempfile::tempdir().unwrap();
    Pool::create(dir.path(), small_params()).unwrap();

    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &live_roots);
    assert!(report.is_clean(), "expected a clean report, got {:?}", report.errors);
}

#[test]
fn verify_index_is_clean_on_a_healthy_pool() {
    let dir = tempfile::tempdir().unwrap();
    let pool = setup_populated_pool(dir.path());
    drop(pool);

    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::verify_index(dir.path(), &live_roots);
    assert!(report.is_clean(), "expected a clean report, got {:?}", report.errors);
}

#[test]
fn corrupted_chunk_payload_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(1, 4000)).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    // Flip a byte partway into a data segment's payload region -- past the
    // header page, so this corrupts an actual record's bytes rather than
    // the segment header. With multiple logical shards, most segments are
    // empty (header page only); pick one that actually holds a record.
    let data_dir = dir.path().join("segments/data");
    let mut entries: Vec<_> = std::fs::read_dir(&data_dir).unwrap().collect::<Result<_, _>>().unwrap();
    entries.sort_by_key(|e| e.file_name());
    let target = entries
        .iter()
        .map(|e| e.path())
        .find(|p| std::fs::metadata(p).unwrap().len() > 4096 + 100)
        .expect("at least one data segment must hold the written chunk");
    let mut bytes = std::fs::read(&target).unwrap();
    let corrupt_at = 4096 + 100; // header page + a bit into the first record
    bytes[corrupt_at] ^= 0xff;
    std::fs::write(&target, &bytes).unwrap();

    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &live_roots);
    assert!(!report.is_clean(), "corruption should have been detected");
    assert!(
        report
            .errors
            .iter()
            .any(|e| matches!(e, lchfs_fsck::FsckError::ContentHashMismatch { .. })),
        "expected a ContentHashMismatch, got {:?}",
        report.errors
    );
}

#[test]
fn rebuild_index_produces_a_pool_that_reopens_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let pool = setup_populated_pool(dir.path());
    drop(pool);

    std::fs::remove_file(dir.path().join("INDEX.redb")).unwrap();
    lchfs_fsck::rebuild_index(dir.path()).unwrap();

    let pool2 = Pool::open(dir.path()).unwrap();
    assert_eq!(pool2.lookup(1, "a").unwrap(), pool2.lookup(1, "b").unwrap());
    let ino = pool2.lookup(1, "a").unwrap().unwrap();
    let read_back = pool2.read(ino, 0, 6).unwrap();
    assert_eq!(read_back.as_ref(), b"shared");
    drop(pool2);

    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::verify_index(dir.path(), &live_roots);
    assert!(report.is_clean(), "rebuilt index should verify clean, got {:?}", report.errors);
}

#[test]
fn collect_live_roots_includes_snapshot_table_entries() {
    // No snapshot API exists yet (Phase G), so this just confirms the
    // baseline behavior: exactly the current root, no phantom entries.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let root = pool.debug_root_hash();
    drop(pool);

    let live_roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    assert_eq!(live_roots, vec![root]);
}
