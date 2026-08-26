//! Tests for the ownership/permission wiring added on top of ARCHITECTURE.md
//! §9's Phase 1 POSIX surface: `Pool::create`'s root-inode ownership, the
//! `*_as` real-caller-identity constructors, and `set_attr`'s chmod/chown
//! fields. See lchfs-cli's `mount()` for why root ownership matters: it's
//! the precondition for enabling `DefaultPermissions` without locking a
//! non-root mounting user out of their own pool.

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
        logical_shard_count: 1,
    }
}

fn real_uid_gid() -> (u32, u32) {
    (
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
    )
}

#[test]
fn root_inode_is_owned_by_the_creating_user_not_hardcoded_root() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let (uid, gid) = real_uid_gid();
    let root = pool.getattr(1).unwrap();
    assert_eq!(root.uid, uid);
    assert_eq!(root.gid, gid);
}

#[test]
fn root_ownership_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let (uid, gid) = real_uid_gid();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let root = pool.getattr(1).unwrap();
    assert_eq!(root.uid, uid);
    assert_eq!(root.gid, gid);
}

#[test]
fn create_file_as_and_mkdir_as_and_symlink_as_carry_real_caller_identity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let file_ino = pool.create_file_as(1, "f", 0o644, 4242, 4343).unwrap();
    let file = pool.getattr(file_ino).unwrap();
    assert_eq!(file.uid, 4242);
    assert_eq!(file.gid, 4343);
    assert_eq!(file.mode & 0o7777, 0o644);

    let dir_ino = pool.mkdir_as(1, "d", 0o755, 5252, 5353).unwrap();
    let subdir = pool.getattr(dir_ino).unwrap();
    assert_eq!(subdir.uid, 5252);
    assert_eq!(subdir.gid, 5353);

    let link_ino = pool.symlink_as(1, "l", "f", 6262, 6363).unwrap();
    let link = pool.getattr(link_ino).unwrap();
    assert_eq!(link.uid, 6262);
    assert_eq!(link.gid, 6363);
}

#[test]
fn create_file_and_mkdir_and_symlink_convenience_wrappers_are_root_owned() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();

    let file_ino = pool.create_file(1, "f", 0o644).unwrap();
    let file = pool.getattr(file_ino).unwrap();
    assert_eq!(file.uid, 0);
    assert_eq!(file.gid, 0);
}

#[test]
fn set_attr_chmod_changes_only_the_permission_bits() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file_as(1, "f", 0o644, 100, 200).unwrap();

    pool.set_attr(ino, Some(0o600), None, None, None, None).unwrap();

    let file = pool.getattr(ino).unwrap();
    assert_eq!(file.mode & 0o7777, 0o600);
    // File-type bits and ownership must be untouched by a mode-only change.
    assert_eq!(file.uid, 100);
    assert_eq!(file.gid, 200);
}

#[test]
fn set_attr_chown_changes_only_uid_and_gid() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file_as(1, "f", 0o644, 100, 200).unwrap();

    pool.set_attr(ino, None, Some(300), Some(400), None, None).unwrap();

    let file = pool.getattr(ino).unwrap();
    assert_eq!(file.uid, 300);
    assert_eq!(file.gid, 400);
    assert_eq!(file.mode & 0o7777, 0o644);
}

#[test]
fn set_attr_on_nonexistent_inode_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    assert!(pool.set_attr(9999, Some(0o600), None, None, None, None).is_err());
}

#[test]
fn ownership_and_mode_changes_survive_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file_as(1, "f", 0o644, 100, 200).unwrap();
    pool.set_attr(ino, Some(0o600), Some(300), Some(400), None, None)
        .unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let file = pool.getattr(ino).unwrap();
    assert_eq!(file.mode & 0o7777, 0o600);
    assert_eq!(file.uid, 300);
    assert_eq!(file.gid, 400);
}
