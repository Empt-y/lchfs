//! Finding a pool's devices by `pool_uuid` (ARCHITECTURE.md §15.10's open
//! item, Phase 4 M3). Nothing has to remember the device list: point
//! discovery at the directories the devices live under and the identity
//! field does the rest.

use lchfs_format::{PoolParams, parse_pool_uuid, pool_uuid_hex};
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

#[test]
fn two_pools_devices_mixed_in_one_directory_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, c) = (dir.path().join("a"), dir.path().join("b"), dir.path().join("c"));
    let (x, y) = (dir.path().join("x"), dir.path().join("y"));
    std::fs::create_dir(dir.path().join("not-a-device")).unwrap();
    std::fs::write(dir.path().join("a-file"), b"ignored").unwrap();
    let uuid_abc = Pool::create_replicated(&[&a, &b, &c], small_params()).unwrap().pool_uuid();
    let uuid_xy = Pool::create_replicated(&[&x, &y], small_params()).unwrap().pool_uuid();

    let found = Pool::discover(&[dir.path()], None).unwrap();
    assert_eq!(found.pools.len(), 2, "{found:?}");
    let abc = found.pools.iter().find(|p| p.uuid == uuid_abc).unwrap();
    assert_eq!(abc.count, 3);
    assert_eq!(abc.members.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(), vec![0, 1, 2]);
    assert!(abc.missing.is_empty());
    assert_eq!(abc.members[1].2, b);
    let xy = found.pools.iter().find(|p| p.uuid == uuid_xy).unwrap();
    assert_eq!(xy.members.len(), 2);

    // Narrowed to one pool.
    let only = Pool::discover(&[dir.path()], Some(uuid_xy)).unwrap();
    assert_eq!(only.pools.len(), 1);
    assert_eq!(only.pools[0].uuid, uuid_xy);

    // Looking created nothing.
    assert!(!dir.path().join("not-a-device/SUPERBLOCK").exists());
    assert!(!dir.path().join("SUPERBLOCK").exists());
}

#[test]
fn a_missing_device_is_reported_and_degraded_open_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let data: Vec<u8> = (0..20_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    {
        let pool = Pool::create_replicated(&[&a, &b], small_params()).unwrap();
        let ino = pool.create_file(1, "f", 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        pool.checkpoint().unwrap();
    }
    std::fs::remove_dir_all(&b).unwrap();

    let found = Pool::discover(&[dir.path()], None).unwrap();
    assert_eq!(found.pools.len(), 1);
    assert_eq!(found.pools[0].missing, vec![1]);

    let err = Pool::open_discovered(&[dir.path()], None, false).unwrap_err().to_string();
    assert!(err.contains("missing vdevs [1]"), "{err}");
    let pool = Pool::open_discovered(&[dir.path()], None, true).unwrap();
    assert!(pool.is_degraded());
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.read(ino, 0, data.len() as u32).unwrap(), data);
}

#[test]
fn open_discovered_refuses_to_guess_between_pools() {
    let dir = tempfile::tempdir().unwrap();
    drop(Pool::create(&dir.path().join("p1"), small_params()).unwrap());
    drop(Pool::create(&dir.path().join("p2"), small_params()).unwrap());
    let err = Pool::open_discovered(&[dir.path()], None, false).unwrap_err().to_string();
    assert!(err.contains("2 pools found"), "{err}");
    let empty = tempfile::tempdir().unwrap();
    let err = Pool::open_discovered(&[empty.path()], None, false).unwrap_err().to_string();
    assert!(err.contains("no pool devices found"), "{err}");
}

#[test]
fn a_device_named_directly_counts_too_and_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let uuid = Pool::create(&a, small_params()).unwrap().pool_uuid();
    let found = Pool::discover(&[&a], None).unwrap();
    assert_eq!(found.pools.len(), 1);
    assert_eq!(found.pools[0].uuid, uuid);
    // Named and also found under its parent: one device, not two.
    let found = Pool::discover(&[&a, dir.path()], None).unwrap();
    assert_eq!(found.pools.len(), 1);
    assert_eq!(found.pools[0].members.len(), 1, "{:?}", found.pools[0]);
    assert!(Pool::open_discovered(&[&a, dir.path()], None, false).is_ok());
}

#[test]
fn uuid_hex_round_trips_and_tolerates_canonical_form() {
    let uuid = [0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xff];
    let hex = pool_uuid_hex(&uuid);
    assert_eq!(hex.len(), 32);
    assert_eq!(parse_pool_uuid(&hex), Some(uuid));
    assert_eq!(parse_pool_uuid(&hex.to_uppercase()), Some(uuid));
    assert_eq!(parse_pool_uuid("deadbeef-0001-0203-0405-06070809 0aff".replace(' ', "").as_str()), Some(uuid));
    assert_eq!(parse_pool_uuid("nope"), None);
    assert_eq!(parse_pool_uuid(&hex[..30]), None);
}
