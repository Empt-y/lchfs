//! Tests for the namespace-mutation operations added to close ARCHITECTURE.md
//! §9's Phase 1 POSIX/FUSE surface: unlink, rmdir, rename, symlink/readlink,
//! link (hardlink), statfs.

use lchfs_format::{ContentRef, InodeKind, PoolParams};
use lchfs_store::{Pool, PoolError};

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

#[test]
fn unlink_removes_file_and_frees_the_name() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"hello").unwrap();

    pool.unlink(1, "f").unwrap();
    assert_eq!(pool.lookup(1, "f").unwrap(), None);
    assert!(matches!(pool.getattr(ino), Err(PoolError::NoSuchInode(_))));

    // The name is free again, and a new file can reuse it.
    let ino2 = pool.create_file(1, "f", 0o644).unwrap();
    assert_ne!(ino, ino2);
}

#[test]
fn unlink_nonexistent_name_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    assert!(matches!(pool.unlink(1, "nope"), Err(PoolError::NotFound(_))));
}

#[test]
fn unlink_on_a_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.mkdir(1, "d", 0o755).unwrap();
    assert!(matches!(pool.unlink(1, "d"), Err(PoolError::IsADirectory(_))));
}

#[test]
fn unlink_survives_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &deterministic_bytes(1, 2000)).unwrap();
    pool.checkpoint().unwrap();

    pool.unlink(1, "f").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool2 = Pool::open(dir.path()).unwrap();
    assert_eq!(pool2.lookup(1, "f").unwrap(), None);
}

#[test]
fn unlinked_content_becomes_gc_reclaimable() {
    // Regression-style check that unlink actually removes the inode from
    // the namespace GC walks, not just the directory entry: content only
    // referenced by an unlinked file must be absent from a fresh mark()
    // pass once checkpointed. Compares against an empty pool's own
    // baseline live-byte count (RootObject/InoMap/root-dir/SnapshotTable
    // overhead) rather than an arbitrary threshold, since that overhead
    // isn't a stable constant across format changes.
    let empty_dir = tempfile::tempdir().unwrap();
    let empty_pool = Pool::create(empty_dir.path(), small_params()).unwrap();
    let empty_root = empty_pool.debug_root_hash();
    drop(empty_pool);
    let baseline_live: u64 = {
        let index = lchfs_index::RedbIndex::open(&empty_dir.path().join("INDEX.redb")).unwrap();
        let cache = lchfs_index::ChunkLocationCache::new();
        cache.extend(index.iter_chunk_locations().unwrap());
        let mut gc = lchfs_store::gc::GcEngine::new(
            empty_dir.path().to_path_buf(),
            std::sync::Arc::new(cache),
            std::sync::Arc::new(lchfs_index::PendingDedupPins::new()),
        );
        gc.mark(&[empty_root]).values().map(|b| b.len()).sum()
    };

    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let data = deterministic_bytes(7, 2000);
    pool.write(ino, 0, &data).unwrap();
    pool.checkpoint().unwrap();

    pool.unlink(1, "f").unwrap();
    pool.checkpoint().unwrap();
    let root = pool.debug_root_hash();
    drop(pool);

    let index = lchfs_index::RedbIndex::open(&dir.path().join("INDEX.redb")).unwrap();
    let cache = lchfs_index::ChunkLocationCache::new();
    cache.extend(index.iter_chunk_locations().unwrap());
    let mut gc = lchfs_store::gc::GcEngine::new(
        dir.path().to_path_buf(),
        std::sync::Arc::new(cache),
        std::sync::Arc::new(lchfs_index::PendingDedupPins::new()),
    );
    let live = gc.mark(&[root]);
    let total_live: u64 = live.values().map(|b| b.len()).sum();

    // Some growth over the empty-pool baseline is expected (this pool did
    // have a file created, even though it's now unlinked -- e.g. its
    // now-vacated DirEntry slot's InodeObject/InoMap churn), but nowhere
    // near covering the unlinked file's 2000-byte chunk.
    assert!(
        total_live < baseline_live + 500,
        "unlinked content must not be marked live: baseline={baseline_live} got={total_live}"
    );
}

#[test]
fn rmdir_removes_empty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.mkdir(1, "d", 0o755).unwrap();
    pool.rmdir(1, "d").unwrap();
    assert_eq!(pool.lookup(1, "d").unwrap(), None);
}

#[test]
fn rmdir_on_nonempty_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let d = pool.mkdir(1, "d", 0o755).unwrap();
    pool.create_file(d, "child", 0o644).unwrap();
    assert!(matches!(pool.rmdir(1, "d"), Err(PoolError::NotEmpty(_))));
}

#[test]
fn rmdir_on_a_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_file(1, "f", 0o644).unwrap();
    assert!(matches!(pool.rmdir(1, "f"), Err(PoolError::NotADirectory(_))));
}

#[test]
fn rename_within_same_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "old", 0o644).unwrap();
    pool.write(ino, 0, b"content").unwrap();

    pool.rename(1, "old", 1, "new", false).unwrap();

    assert_eq!(pool.lookup(1, "old").unwrap(), None);
    assert_eq!(pool.lookup(1, "new").unwrap(), Some(ino));
    let read_back = pool.read(ino, 0, 7).unwrap();
    assert_eq!(read_back.as_ref(), b"content");
}

#[test]
fn rename_across_directories() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let src_dir = pool.mkdir(1, "src", 0o755).unwrap();
    let dst_dir = pool.mkdir(1, "dst", 0o755).unwrap();
    let ino = pool.create_file(src_dir, "f", 0o644).unwrap();

    pool.rename(src_dir, "f", dst_dir, "f", false).unwrap();

    assert_eq!(pool.lookup(src_dir, "f").unwrap(), None);
    assert_eq!(pool.lookup(dst_dir, "f").unwrap(), Some(ino));
    assert_eq!(pool.parent_of(ino).unwrap_or(dst_dir), dst_dir);
}

#[test]
fn rename_overwrites_existing_destination_file() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let src = pool.create_file(1, "src", 0o644).unwrap();
    let dst = pool.create_file(1, "dst", 0o644).unwrap();
    pool.write(src, 0, b"new").unwrap();

    pool.rename(1, "src", 1, "dst", false).unwrap();

    assert_eq!(pool.lookup(1, "dst").unwrap(), Some(src));
    assert!(matches!(pool.getattr(dst), Err(PoolError::NoSuchInode(_))));
    let read_back = pool.read(src, 0, 3).unwrap();
    assert_eq!(read_back.as_ref(), b"new");
}

#[test]
fn rename_no_replace_rejects_existing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_file(1, "src", 0o644).unwrap();
    pool.create_file(1, "dst", 0o644).unwrap();
    assert!(matches!(
        pool.rename(1, "src", 1, "dst", true),
        Err(PoolError::AlreadyExists(_))
    ));
}

#[test]
fn rename_onto_own_name_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.rename(1, "f", 1, "f", false).unwrap();
    assert_eq!(pool.lookup(1, "f").unwrap(), Some(ino));
}

#[test]
fn rename_directory_into_its_own_subtree_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let a = pool.mkdir(1, "a", 0o755).unwrap();
    let b = pool.mkdir(a, "b", 0o755).unwrap();
    assert!(matches!(
        pool.rename(1, "a", b, "a-moved-into-itself", false),
        Err(PoolError::InvalidArgument(_))
    ));
}

#[test]
fn rename_replacing_a_nonempty_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.mkdir(1, "a", 0o755).unwrap();
    let b = pool.mkdir(1, "b", 0o755).unwrap();
    pool.create_file(b, "child", 0o644).unwrap();
    assert!(matches!(pool.rename(1, "a", 1, "b", false), Err(PoolError::NotEmpty(_))));
}

#[test]
fn rename_file_onto_existing_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_file(1, "f", 0o644).unwrap();
    pool.mkdir(1, "d", 0o755).unwrap();
    assert!(matches!(pool.rename(1, "f", 1, "d", false), Err(PoolError::IsADirectory(_))));
}

#[test]
fn symlink_create_and_readlink() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.symlink(1, "link", "/some/target").unwrap();
    assert_eq!(pool.readlink(ino).unwrap(), "/some/target");
    let attr = pool.getattr(ino).unwrap();
    assert_eq!(attr.kind, InodeKind::Symlink);
    assert!(matches!(attr.content, ContentRef::SymlinkTarget(t) if t == "/some/target"));
}

#[test]
fn readlink_on_non_symlink_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    assert!(matches!(pool.readlink(ino), Err(PoolError::NotASymlink(_))));
}

#[test]
fn symlink_survives_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.symlink(1, "link", "target-value").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool2 = Pool::open(dir.path()).unwrap();
    assert_eq!(pool2.readlink(ino).unwrap(), "target-value");
}

#[test]
fn link_creates_a_second_name_for_the_same_inode() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(ino, 0, b"shared").unwrap();

    pool.link(ino, 1, "b").unwrap();

    assert_eq!(pool.lookup(1, "b").unwrap(), Some(ino));
    assert_eq!(pool.getattr(ino).unwrap().nlink, 2);
    let read_back = pool.read(ino, 0, 6).unwrap();
    assert_eq!(read_back.as_ref(), b"shared");

    // Unlinking one name leaves the inode (and its content) reachable
    // through the other.
    pool.unlink(1, "a").unwrap();
    assert_eq!(pool.getattr(ino).unwrap().nlink, 1);
    let read_back = pool.read(ino, 0, 6).unwrap();
    assert_eq!(read_back.as_ref(), b"shared");

    pool.unlink(1, "b").unwrap();
    assert!(matches!(pool.getattr(ino), Err(PoolError::NoSuchInode(_))));
}

#[test]
fn link_on_a_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let d = pool.mkdir(1, "d", 0o755).unwrap();
    assert!(matches!(pool.link(d, 1, "d2"), Err(PoolError::IsADirectory(_))));
}

#[test]
fn link_survives_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "a", 0o644).unwrap();
    pool.write(ino, 0, b"shared").unwrap();
    pool.link(ino, 1, "b").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool2 = Pool::open(dir.path()).unwrap();
    assert_eq!(pool2.lookup(1, "b").unwrap(), Some(ino));
    assert_eq!(pool2.getattr(ino).unwrap().nlink, 2);
    let read_back = pool2.read(ino, 0, 6).unwrap();
    assert_eq!(read_back.as_ref(), b"shared");
}

#[test]
fn statfs_reports_sane_values() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.create_file(1, "f", 0o644).unwrap();

    let stats = pool.statfs().unwrap();
    assert!(stats.block_size > 0);
    assert!(stats.blocks_total > 0);
    assert!(stats.blocks_total >= stats.blocks_free);
    assert!(stats.blocks_free >= stats.blocks_available);
    // root dir (ino 1) + the file just created.
    assert_eq!(stats.files_total, 2);
    assert!(stats.files_free > 0);
}
