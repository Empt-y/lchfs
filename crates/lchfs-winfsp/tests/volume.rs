//! The Windows view of a pool, driven the way WinFsp's callbacks drive it
//! (paths with `\`, NTSTATUS codes, FILETIMEs), against a real pool. Runs
//! on every platform: none of it needs WinFsp.

use lchfs_format::PoolParams;
use lchfs_store::Pool;
use lchfs_winfsp::fs::{
    self, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, IO_REPARSE_TAG_SYMLINK, Volume, attr, status,
};
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

fn payload() -> Vec<u8> {
    (0..50_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

fn volume() -> (tempfile::TempDir, Arc<Pool>, Volume) {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params()).unwrap());
    let volume = Volume::new(Arc::clone(&pool), false);
    (dir, pool, volume)
}

fn names(v: &Volume, path: &str) -> Vec<String> {
    let (h, _) = v.open(path, 0).unwrap();
    let mut n: Vec<String> = v.list(&h).unwrap().into_iter().map(|i| i.name).collect();
    n.sort();
    n
}

fn read_all(v: &Volume, path: &str) -> Vec<u8> {
    let (h, info) = v.open(path, 0).unwrap();
    let mut buf = vec![0u8; info.file_size as usize];
    let mut at = 0;
    while at < buf.len() {
        at += v.read(&h, at as u64, &mut buf[at..]).unwrap();
    }
    buf
}

#[test]
fn files_and_directories_round_trip() {
    let (_d, _p, v) = volume();
    let (dir, info) = v.create("\\docs", FILE_DIRECTORY_FILE, 0).unwrap();
    assert!(dir.is_dir());
    assert_eq!(info.attributes & attr::DIRECTORY, attr::DIRECTORY);

    let (f, _) = v.create("\\docs\\report.txt", 0, 0).unwrap();
    let data = payload();
    let (n, info) = v.write(&f, 0, &data, false, false).unwrap();
    assert_eq!(n, data.len());
    assert_eq!(info.file_size, data.len() as u64);
    assert_eq!(info.allocation_size % fs::ALLOCATION_UNIT, 0);
    assert!(info.allocation_size >= info.file_size);
    assert_eq!(read_all(&v, "\\docs\\report.txt"), data);

    // Appending, and paging I/O that may not grow the file.
    let (_, info) = v.write(&f, 0, b"tail", true, false).unwrap();
    assert_eq!(info.file_size, data.len() as u64 + 4, "write-to-end appends whatever the offset");
    let (n, info) = v.write(&f, info.file_size, b"past the end", false, true).unwrap();
    assert_eq!(n, 0, "constrained I/O never extends a file");
    let (n, _) = v.write(&f, info.file_size - 2, b"XYZ", false, true).unwrap();
    assert_eq!(n, 2, "constrained I/O is clipped at the end of the file");
    let back = read_all(&v, "\\docs\\report.txt");
    assert_eq!(&back[..data.len()], &data[..]);
    assert_eq!(&back[data.len()..], b"taXY");

    assert_eq!(names(&v, "\\docs"), [".", "..", "report.txt"]);
    assert_eq!(names(&v, "\\"), ["docs"], "the root has no . or ..");

    let mut buf = [0u8; 8];
    assert_eq!(v.read(&f, 1 << 40, &mut buf), Err(status::END_OF_FILE));
}

#[test]
fn opening_checks_the_kind_the_caller_asked_for() {
    let (_d, _p, v) = volume();
    v.create("\\d", FILE_DIRECTORY_FILE, 0).unwrap();
    v.create("\\f", 0, 0).unwrap();
    assert_eq!(v.open("\\f", FILE_DIRECTORY_FILE).err(), Some(status::NOT_A_DIRECTORY));
    assert_eq!(v.open("\\d", FILE_NON_DIRECTORY_FILE).err(), Some(status::FILE_IS_A_DIRECTORY));
    assert_eq!(v.open("\\missing", 0).err(), Some(status::OBJECT_NAME_NOT_FOUND));
    assert_eq!(v.open("\\missing\\x", 0).err(), Some(status::OBJECT_PATH_NOT_FOUND));
    assert_eq!(v.open("\\f\\x", 0).err(), Some(status::OBJECT_PATH_NOT_FOUND));
    assert_eq!(v.create("\\f", 0, 0).err(), Some(status::OBJECT_NAME_COLLISION));
    assert_eq!(v.create("\\missing\\x", 0, 0).err(), Some(status::OBJECT_PATH_NOT_FOUND));
}

#[test]
fn names_match_regardless_of_case_but_keep_theirs() {
    let (_d, _p, v) = volume();
    v.create("\\ReadMe.TXT", 0, 0).unwrap();
    let (h, _) = v.open("\\readme.txt", 0).unwrap();
    v.write(&h, 0, b"hi", false, false).unwrap();
    assert_eq!(read_all(&v, "\\README.txt"), b"hi");
    assert_eq!(v.create("\\README.TXT", 0, 0).err(), Some(status::OBJECT_NAME_COLLISION));
    assert_eq!(names(&v, "\\"), ["ReadMe.TXT"]);

    // Only the case changes: allowed without "replace".
    v.rename(&h, "\\readme.txt", "\\README.txt", false).unwrap();
    assert_eq!(names(&v, "\\"), ["README.txt"]);
}

#[test]
fn an_exact_match_wins_over_a_case_folded_one() {
    let (_d, pool, v) = volume();
    // Possible from Linux: two names differing only in case.
    let a = pool.create_file(fs::ROOT_INO, "a", 0o644).unwrap();
    let big_a = pool.create_file(fs::ROOT_INO, "A", 0o644).unwrap();
    assert_eq!(v.resolve("\\a").unwrap(), a);
    assert_eq!(v.resolve("\\A").unwrap(), big_a);
}

#[test]
fn deleting_happens_by_path_and_refuses_non_empty_directories() {
    let (_d, _p, v) = volume();
    let (dir, _) = v.create("\\d", FILE_DIRECTORY_FILE, 0).unwrap();
    let (f, _) = v.create("\\d\\f", 0, 0).unwrap();
    assert_eq!(v.can_delete(&dir), Err(status::DIRECTORY_NOT_EMPTY));
    v.can_delete(&f).unwrap();
    v.delete("\\D\\F").unwrap();
    v.can_delete(&dir).unwrap();
    v.delete("\\d").unwrap();
    assert_eq!(names(&v, "\\"), Vec::<String>::new());
    let (root, _) = v.open("\\", 0).unwrap();
    assert_eq!(v.can_delete(&root), Err(status::ACCESS_DENIED));
}

#[test]
fn rename_moves_replaces_and_follows_the_handle() {
    let (_d, _p, v) = volume();
    v.create("\\a", FILE_DIRECTORY_FILE, 0).unwrap();
    v.create("\\b", FILE_DIRECTORY_FILE, 0).unwrap();
    let (f, _) = v.create("\\a\\f", 0, 0).unwrap();
    v.write(&f, 0, b"one", false, false).unwrap();
    let (g, _) = v.create("\\b\\g", 0, 0).unwrap();
    v.write(&g, 0, b"two", false, false).unwrap();

    assert_eq!(v.rename(&f, "\\a\\f", "\\b\\g", false), Err(status::OBJECT_NAME_COLLISION));
    v.rename(&f, "\\a\\f", "\\b\\g", true).unwrap();
    assert_eq!(read_all(&v, "\\b\\g"), b"one");
    assert_eq!(names(&v, "\\a"), [".", ".."]);

    // Onto an existing directory: refused even with replace, as NTFS does.
    assert_eq!(v.rename(&f, "\\b\\g", "\\a", true), Err(status::ACCESS_DENIED));

    // The handle moved with it: renaming to a dot-name makes it hidden.
    v.rename(&f, "\\b\\g", "\\b\\.g", false).unwrap();
    assert_eq!(v.info(&f).unwrap().attributes & attr::HIDDEN, attr::HIDDEN);
}

#[test]
fn attributes_come_from_the_mode_and_map_back() {
    let (_d, pool, v) = volume();
    let (f, info) = v.create("\\f", 0, attr::READONLY).unwrap();
    assert_eq!(info.attributes & attr::READONLY, attr::READONLY);
    assert_eq!(pool.getattr(f.ino()).unwrap().mode & 0o222, 0);

    let info = v.set_basic(&f, attr::ARCHIVE, 0, 0).unwrap();
    assert_eq!(info.attributes & attr::READONLY, 0);
    assert_eq!(pool.getattr(f.ino()).unwrap().mode & 0o200, 0o200);

    let (_, info) = v.create("\\.hidden", 0, 0).unwrap();
    assert_eq!(info.attributes & attr::HIDDEN, attr::HIDDEN);

    // Times: a FILETIME set is the FILETIME read back.
    let t = fs::filetime((1_700_000_000, 123_456_700));
    let info = v.set_basic(&f, attr::INVALID, t, t).unwrap();
    assert_eq!((info.last_access_time, info.last_write_time), (t, t));
    assert_eq!(fs::unix_time(t), (1_700_000_000, 123_456_700));
    assert_eq!(fs::filetime((0, 0)), 116_444_736_000_000_000);
}

#[test]
fn sizes_and_overwrite() {
    let (_d, _p, v) = volume();
    let (f, _) = v.create("\\f", 0, 0).unwrap();
    v.write(&f, 0, &payload(), false, false).unwrap();
    // Growing the allocation allocates nothing; shrinking it truncates.
    assert_eq!(v.set_size(&f, 1 << 30, true).unwrap().file_size, payload().len() as u64);
    assert_eq!(v.set_size(&f, 100, true).unwrap().file_size, 100);
    assert_eq!(v.set_size(&f, 5000, false).unwrap().file_size, 5000);
    let back = read_all(&v, "\\f");
    assert_eq!(&back[..100], &payload()[..100]);
    assert!(back[100..].iter().all(|&b| b == 0), "extension reads as zeros");
    assert_eq!(v.overwrite(&f, 0, false).unwrap().file_size, 0);
}

#[test]
fn symlinks_are_reparse_points() {
    let (_d, pool, v) = volume();
    v.create("\\dir", FILE_DIRECTORY_FILE, 0).unwrap();
    v.create("\\dir\\file", 0, 0).unwrap();
    pool.symlink(fs::ROOT_INO, "to-dir", "dir").unwrap();
    pool.symlink(fs::ROOT_INO, "to-file", "dir/file").unwrap();
    pool.symlink(fs::ROOT_INO, "dangling", "nowhere").unwrap();
    pool.symlink(fs::ROOT_INO, "loop", "loop").unwrap();

    let info = v.info_at("\\to-dir").unwrap();
    assert_eq!(info.reparse_tag, IO_REPARSE_TAG_SYMLINK);
    assert_eq!(info.attributes & (attr::REPARSE_POINT | attr::DIRECTORY), attr::REPARSE_POINT | attr::DIRECTORY);
    for link in ["\\to-file", "\\dangling", "\\loop"] {
        let info = v.info_at(link).unwrap();
        assert_eq!(info.attributes & (attr::REPARSE_POINT | attr::DIRECTORY), attr::REPARSE_POINT, "{link}");
    }

    // The reparse data carries the target with Windows separators.
    let data = v.reparse_point_at("\\to-file").unwrap();
    assert_eq!(fs::parse_symlink_reparse_buffer(&data).unwrap(), "dir/file");
    assert_eq!(&data[..4], &IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    assert_eq!(v.reparse_point_at("\\dir").err(), Some(status::NOT_A_REPARSE_POINT));

    // Deleting a link to a directory removes the link, not the directory.
    v.delete("\\to-dir").unwrap();
    assert_eq!(names(&v, "\\dir"), [".", "..", "file"]);
}

#[test]
fn mklink_turns_a_new_empty_file_into_a_symlink() {
    let (_d, pool, v) = volume();
    v.create("\\target", 0, 0).unwrap();
    let (h, _) = v.create("\\link", 0, 0).unwrap();
    let before = h.ino();
    v.set_symlink(&h, "\\link", &fs::symlink_reparse_buffer("sub\\..\\target")).unwrap();
    assert_ne!(h.ino(), before, "the handle now refers to the link");
    assert_eq!(pool.readlink(h.ino()).unwrap(), "sub/../target");
    assert_eq!(v.info(&h).unwrap().reparse_tag, IO_REPARSE_TAG_SYMLINK);

    // An absolute Windows target cannot be stored.
    let (h2, _) = v.create("\\abs", 0, 0).unwrap();
    let mut abs = fs::symlink_reparse_buffer("\\??\\C:\\Windows");
    abs[16..20].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(v.set_symlink(&h2, "\\abs", &abs), Err(status::INVALID_DEVICE_REQUEST));
}

#[test]
fn a_read_only_volume_refuses_every_change() {
    let (dir, pool, v) = volume();
    let (f, _) = v.create("\\f", 0, 0).unwrap();
    v.write(&f, 0, b"data", false, false).unwrap();
    drop((v, f));
    let ro = Volume::new(Arc::clone(&pool), true);
    let (f, _) = ro.open("\\f", 0).unwrap();
    assert_eq!(read_all(&ro, "\\f"), b"data");
    let denied = Err(status::MEDIA_WRITE_PROTECTED);
    assert_eq!(ro.write(&f, 0, b"x", false, false).map(|_| ()), denied);
    assert_eq!(ro.create("\\g", 0, 0).map(|_| ()), denied);
    assert_eq!(ro.delete("\\f"), denied);
    assert_eq!(ro.rename(&f, "\\f", "\\g", false), denied);
    assert_eq!(ro.set_size(&f, 0, false).map(|_| ()), denied);
    drop(dir);
}

#[test]
fn volume_space_and_flush() {
    let (_d, _p, v) = volume();
    let (total, free) = v.space().unwrap();
    assert!(total > 0 && free <= total);
    let (f, _) = v.create("\\f", 0, 0).unwrap();
    v.write(&f, 0, b"x", false, false).unwrap();
    assert!(v.flush(Some(&f)).unwrap().is_some());
    assert!(v.flush(None).unwrap().is_none());
}

#[test]
fn data_survives_unmount_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let pool = Arc::new(Pool::create(dir.path(), small_params()).unwrap());
        let v = Volume::new(Arc::clone(&pool), false);
        v.create("\\d", FILE_DIRECTORY_FILE, 0).unwrap();
        let (f, _) = v.create("\\d\\f", 0, 0).unwrap();
        v.write(&f, 0, &payload(), false, false).unwrap();
        // What lchfs-win does on Ctrl+C.
        pool.checkpoint().unwrap();
    }
    let pool = Arc::new(Pool::open(dir.path()).unwrap());
    let v = Volume::new(pool, false);
    assert_eq!(read_all(&v, "\\d\\f"), payload());
}

#[test]
fn a_second_mount_of_the_same_pool_is_refused() {
    let (dir, _pool, _v) = volume();
    assert!(matches!(Pool::open(dir.path()), Err(lchfs_store::PoolError::PoolLocked(_))));
}

#[test]
fn an_encrypted_pool_mounts_with_its_passphrase() {
    use lchfs_crypto::keyring::{NewSlot, Padding, Unlock};
    let dir = tempfile::tempdir().unwrap();
    let passphrase = b"correct horse battery staple";
    {
        let setup = lchfs_store::EncryptionSetup {
            padding: Padding::Padme,
            slots: vec![NewSlot::Passphrase {
                passphrase,
                cost: lchfs_crypto::testing::TEST_KDF,
                label: "passphrase".into(),
            }],
        };
        let pool = Arc::new(Pool::create_encrypted(dir.path(), small_params(), setup).unwrap());
        let v = Volume::new(Arc::clone(&pool), false);
        let (f, _) = v.create("\\secret.txt", 0, 0).unwrap();
        v.write(&f, 0, b"hello", false, false).unwrap();
        pool.checkpoint().unwrap();
    }
    // Without a key it will not open. (Under `test-encrypt-all` the engine
    // tries the suite's own passphrase, which this pool refuses.)
    let without_key = Pool::open(dir.path());
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        assert!(without_key.is_err());
    } else {
        assert!(matches!(without_key, Err(lchfs_store::PoolError::KeyRequired)));
    }
    drop(without_key);
    let pool = Arc::new(Pool::open_with(dir.path(), &Unlock::Passphrase(passphrase)).unwrap());
    assert!(pool.is_encrypted());
    assert_eq!(read_all(&Volume::new(pool, false), "\\secret.txt"), b"hello");
}
