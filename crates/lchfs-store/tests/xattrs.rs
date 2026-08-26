//! Tests for extended attributes (ARCHITECTURE.md §9's Phase 2+ list).
//! Attributes live inside `InodeObject`, so they ride the ordinary
//! dirty-inode/checkpoint path and need no storage machinery of their own --
//! most of what is worth testing here is the map encoding surviving a
//! checkpoint, and the errno-distinguishing edge cases.

use lchfs_format::PoolParams;
use lchfs_store::{Pool, PoolError, XattrSetFlags};

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

#[test]
fn set_then_get_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    pool.set_xattr(ino, "user.colour", b"blue", XattrSetFlags::None).unwrap();
    assert_eq!(pool.get_xattr(ino, "user.colour").unwrap(), b"blue");
}

#[test]
fn getting_an_unset_attribute_is_no_such_xattr_not_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    // The distinction matters: this maps to ENODATA, whereas NotFound maps
    // to ENOENT, and getfattr/setfacl behave differently on each.
    let result = pool.get_xattr(ino, "user.missing");
    assert!(matches!(result, Err(PoolError::NoSuchXattr(_))), "got {result:?}");
}

#[test]
fn xattr_ops_on_a_missing_inode_fail() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    assert!(matches!(pool.get_xattr(9999, "user.x"), Err(PoolError::NoSuchInode(_))));
    assert!(matches!(pool.list_xattrs(9999), Err(PoolError::NoSuchInode(_))));
}

#[test]
fn list_returns_all_names_sorted_and_reflects_removal() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    pool.set_xattr(ino, "user.zebra", b"1", XattrSetFlags::None).unwrap();
    pool.set_xattr(ino, "user.apple", b"2", XattrSetFlags::None).unwrap();
    assert_eq!(pool.list_xattrs(ino).unwrap(), vec!["user.apple", "user.zebra"]);

    pool.remove_xattr(ino, "user.apple").unwrap();
    assert_eq!(pool.list_xattrs(ino).unwrap(), vec!["user.zebra"]);
}

#[test]
fn an_inode_with_no_xattrs_lists_empty() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    assert!(pool.list_xattrs(ino).unwrap().is_empty());
}

#[test]
fn overwriting_replaces_the_value() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    pool.set_xattr(ino, "user.k", b"first", XattrSetFlags::None).unwrap();
    pool.set_xattr(ino, "user.k", b"second", XattrSetFlags::None).unwrap();
    assert_eq!(pool.get_xattr(ino, "user.k").unwrap(), b"second");
    assert_eq!(pool.list_xattrs(ino).unwrap().len(), 1);
}

#[test]
fn create_flag_refuses_an_existing_attribute() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    pool.set_xattr(ino, "user.k", b"v", XattrSetFlags::None).unwrap();
    let result = pool.set_xattr(ino, "user.k", b"v2", XattrSetFlags::Create);
    assert!(matches!(result, Err(PoolError::AlreadyExists(_))), "got {result:?}");
    // The failed create must not have modified the existing value.
    assert_eq!(pool.get_xattr(ino, "user.k").unwrap(), b"v");
}

#[test]
fn replace_flag_refuses_a_missing_attribute() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let result = pool.set_xattr(ino, "user.k", b"v", XattrSetFlags::Replace);
    assert!(matches!(result, Err(PoolError::NoSuchXattr(_))), "got {result:?}");
    assert!(pool.list_xattrs(ino).unwrap().is_empty());
}

#[test]
fn removing_a_missing_attribute_fails() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let result = pool.remove_xattr(ino, "user.nope");
    assert!(matches!(result, Err(PoolError::NoSuchXattr(_))), "got {result:?}");
}

#[test]
fn an_empty_value_is_stored_and_distinguishable_from_absent() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    pool.set_xattr(ino, "user.empty", b"", XattrSetFlags::None).unwrap();
    assert_eq!(pool.get_xattr(ino, "user.empty").unwrap(), b"");
    assert_eq!(pool.list_xattrs(ino).unwrap(), vec!["user.empty"]);
}

#[test]
fn binary_values_survive_intact() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    // POSIX ACLs are stored as binary blobs with embedded NULs, so this is
    // the case that matters for the ACL work layered on top of this.
    let value: Vec<u8> = (0u8..=255).collect();
    pool.set_xattr(ino, "system.posix_acl_access", &value, XattrSetFlags::None).unwrap();
    assert_eq!(pool.get_xattr(ino, "system.posix_acl_access").unwrap(), value);
}

#[test]
fn oversized_name_and_value_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    let long_name = "user.".to_string() + &"x".repeat(300);
    assert!(matches!(
        pool.set_xattr(ino, &long_name, b"v", XattrSetFlags::None),
        Err(PoolError::TooLarge(_))
    ));

    let big_value = vec![0u8; 128 * 1024];
    assert!(matches!(
        pool.set_xattr(ino, "user.big", &big_value, XattrSetFlags::None),
        Err(PoolError::TooLarge(_))
    ));

    assert!(matches!(
        pool.set_xattr(ino, "", b"v", XattrSetFlags::None),
        Err(PoolError::InvalidArgument(_))
    ));
}

#[test]
fn xattrs_survive_checkpoint_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"file content").unwrap();
    pool.set_xattr(ino, "user.one", b"1", XattrSetFlags::None).unwrap();
    pool.set_xattr(ino, "user.two", b"2", XattrSetFlags::None).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.get_xattr(ino, "user.one").unwrap(), b"1");
    assert_eq!(pool.get_xattr(ino, "user.two").unwrap(), b"2");
    assert_eq!(&pool.read(ino, 0, 12).unwrap()[..], b"file content");
}

/// Removing the last attribute must restore `xattrs: None`, not leave a blob
/// encoding an empty map -- otherwise an inode that briefly had an xattr
/// would hash differently forever from an identical one that never did,
/// silently costing dedup.
#[test]
fn removing_the_last_attribute_survives_reopen_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.set_xattr(ino, "user.k", b"v", XattrSetFlags::None).unwrap();
    pool.remove_xattr(ino, "user.k").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert!(pool.list_xattrs(ino).unwrap().is_empty());
}

#[test]
fn directories_and_symlinks_carry_xattrs_too() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let subdir = pool.mkdir(1, "d", 0o755).unwrap();
    let link = pool.symlink(1, "l", "target").unwrap();

    pool.set_xattr(subdir, "user.on_dir", b"yes", XattrSetFlags::None).unwrap();
    pool.set_xattr(link, "user.on_link", b"yes", XattrSetFlags::None).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open(dir.path()).unwrap();
    let subdir = pool.lookup(1, "d").unwrap().unwrap();
    assert_eq!(pool.get_xattr(subdir, "user.on_dir").unwrap(), b"yes");
}

/// fsck walks every InodeObject; a populated xattr blob must not trip any of
/// its structural checks.
#[test]
fn fsck_is_clean_on_a_pool_with_xattrs() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![3u8; 5000]).unwrap();
    pool.set_xattr(ino, "user.k", b"v", XattrSetFlags::None).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let roots = lchfs_fsck::collect_live_roots(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &roots);
    assert!(report.is_clean(), "fsck errors: {:?}", report.errors);
}
