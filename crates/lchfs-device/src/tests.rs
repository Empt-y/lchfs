use super::*;

fn fresh() -> (tempfile::TempDir, Device) {
    let dir = tempfile::tempdir().unwrap();
    let dev = Device::open_or_format(dir.path(), FormatOptions::default()).unwrap();
    (dir, dev)
}

fn reopen(dir: &tempfile::TempDir, dev: Device) -> Device {
    drop(dev);
    Device::open(dir.path()).unwrap()
}

#[test]
fn a_directory_stands_for_a_sparse_image_and_the_layout_fits() {
    let (dir, dev) = fresh();
    let img = dir.path().join(IMAGE_NAME);
    assert_eq!(dev.path(), img);
    let label = dev.label();
    assert!(label.is_valid());
    assert_eq!(label.zone_size, DEFAULT_IMAGE_ZONE_SIZE);
    assert!(label.zone_count > 1000);
    // Sparse: formatting wrote a few MiB, not 4 GiB.
    use std::os::unix::fs::MetadataExt;
    assert!(std::fs::metadata(&img).unwrap().blocks() * 512 < 64 << 20);
    assert!(is_formatted(dir.path()));
    assert!(!is_formatted(tempfile::tempdir().unwrap().path()));
}

#[test]
fn opening_twice_is_one_device_and_unformatted_is_refused() {
    let (dir, dev) = fresh();
    let again = Device::open(dir.path()).unwrap();
    assert!(Arc::ptr_eq(&dev.0, &again.0));
    let empty = tempfile::tempdir().unwrap();
    std::fs::write(empty.path().join(IMAGE_NAME), vec![0u8; 1 << 20]).unwrap();
    assert_eq!(Device::open(empty.path()).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(Device::open(&empty.path().join("nothing")).unwrap_err().kind(), io::ErrorKind::NotFound);
}

#[test]
fn segments_read_back_across_zones_and_reopen_with_their_length() {
    let (dir, dev) = fresh();
    let payload = (DEFAULT_IMAGE_ZONE_SIZE - DEVICE_BLOCK) as usize;
    let data: Vec<u8> = (0..payload * 2 + 777).map(|i| (i % 251) as u8).collect();
    let seg = dev.create_segment(SegmentKind::Data, 7).unwrap();
    seg.write_all_at(&data[..1000], 0).unwrap();
    seg.write_all_at(&data[1000..], 1000).unwrap();
    assert_eq!(seg.len(), data.len() as u64);
    seg.sync_all().unwrap();
    let mut back = vec![0u8; data.len()];
    seg.read_exact_at(&mut back, 0).unwrap();
    assert_eq!(back, data);
    assert_eq!(seg.read_exact_at(&mut [0u8; 2], data.len() as u64 - 1).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    drop(seg);

    let dev = reopen(&dir, dev);
    assert_eq!(dev.segments(), vec![(SegmentKind::Data, 7)]);
    assert_eq!(dev.read_segment(SegmentKind::Data, 7).unwrap(), data);
}

#[test]
fn an_unsynced_length_is_not_persisted() {
    let (dir, dev) = fresh();
    let seg = dev.create_segment(SegmentKind::Meta, 1).unwrap();
    seg.write_all_at(b"synced", 0).unwrap();
    seg.sync_all().unwrap();
    seg.write_all_at(b" and not", 6).unwrap();
    drop(seg);
    let dev = reopen(&dir, dev);
    assert_eq!(dev.read_segment(SegmentKind::Meta, 1).unwrap(), b"synced");
}

#[test]
fn a_removed_segments_zones_come_back_zeroed_once_closed() {
    let (dir, dev) = fresh();
    let (_, free_before) = dev.capacity();
    let seg = dev.create_segment(SegmentKind::Data, 1).unwrap();
    seg.write_all_at(&[0xAB; 100_000], 0).unwrap();
    seg.sync_all().unwrap();
    let reader = dev.open_segment(SegmentKind::Data, 1).unwrap();
    drop(seg);
    dev.remove_segment(SegmentKind::Data, 1).unwrap();
    assert!(!dev.segment_exists(SegmentKind::Data, 1));
    assert_eq!(dev.open_segment(SegmentKind::Data, 1).unwrap_err().kind(), io::ErrorKind::NotFound);
    // Still readable through the open handle, like an unlinked file.
    let mut buf = [0u8; 4];
    reader.read_exact_at(&mut buf, 50_000).unwrap();
    assert_eq!(buf, [0xAB; 4]);
    assert!(dev.capacity().1 < free_before);
    drop(reader);
    assert_eq!(dev.capacity().1, free_before);

    // Whatever zone the next segment gets, it reads as zeros.
    let next = dev.create_segment(SegmentKind::Data, 2).unwrap();
    next.write_all_at(&[1], 99_999).unwrap();
    let mut all = vec![0u8; 100_000];
    next.read_exact_at(&mut all, 0).unwrap();
    assert!(all[..99_999].iter().all(|&b| b == 0));
    drop(next);
    let dev = reopen(&dir, dev);
    assert_eq!(dev.segments(), vec![(SegmentKind::Data, 2)], "segment 1 is gone for good");
}

#[test]
fn a_zone_left_freeing_by_a_crash_is_zeroed_at_mount() {
    let (dir, dev) = fresh();
    let seg = dev.create_segment(SegmentKind::Delta { shard: 3 }, 9).unwrap();
    seg.write_all_at(&[0xCD; 5000], 0).unwrap();
    seg.sync_all().unwrap();
    dev.remove_segment(SegmentKind::Delta { shard: 3 }, 9).unwrap();
    // The process dies with the handle still open: the zone stays Freeing.
    std::mem::forget(seg);
    drop(dev);
    registry().lock().clear();
    let dev = Device::open(dir.path()).unwrap();
    assert!(dev.segments().is_empty());
    assert_eq!(dev.zones_in_use(), 0);
    let fresh = dev.create_segment(SegmentKind::Data, 1).unwrap();
    fresh.write_all_at(&[0], 4999).unwrap();
    let mut back = vec![0u8; 5000];
    fresh.read_exact_at(&mut back, 0).unwrap();
    assert!(back.iter().all(|&b| b == 0));
}

#[test]
fn recreating_a_segment_replaces_it() {
    let (_dir, dev) = fresh();
    let a = dev.create_segment(SegmentKind::Data, 4).unwrap();
    a.write_all_at(b"old", 0).unwrap();
    drop(a);
    let b = dev.create_segment(SegmentKind::Data, 4).unwrap();
    assert_eq!(b.len(), 0);
    assert_eq!(dev.segment_ids(SegmentKind::Data), vec![4]);
}

#[test]
fn a_full_device_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join(IMAGE_NAME);
    std::fs::File::create(&img).unwrap().set_len(256 << 20).unwrap();
    let dev = Device::open_or_format(dir.path(), FormatOptions { zone_size: None, index_copy_len: Some(8 << 20) }).unwrap();
    let zones = dev.label().zone_count;
    let mut held = Vec::new();
    for id in 0..zones {
        held.push(dev.create_segment(SegmentKind::Data, id).unwrap());
    }
    assert_eq!(dev.capacity().1, 0);
    assert_eq!(dev.create_segment(SegmentKind::Data, zones).unwrap_err().kind(), io::ErrorKind::StorageFull);
}

#[test]
fn keyring_copies_alternate_and_survive_a_torn_write() {
    let (dir, dev) = fresh();
    assert_eq!(dev.read_keyring(), None);
    dev.write_keyring(b"generation one").unwrap();
    dev.write_keyring(b"generation two").unwrap();
    assert_eq!(dev.read_keyring().unwrap(), b"generation two");
    // Tear the newer copy: the older one is the keyring again.
    let label = dev.label();
    let newer = if dev.keyring_copy(0).unwrap().0 > dev.keyring_copy(1).unwrap().0 { 0 } else { 1 };
    dev.write_region(label.keyring, newer * label.keyring_copy_len + 20, b"XX").unwrap();
    assert_eq!(dev.read_keyring().unwrap(), b"generation one");
    let dev = reopen(&dir, dev);
    dev.clear_keyring().unwrap();
    assert_eq!(dev.read_keyring(), None);
}

#[test]
fn a_torn_label_a_falls_back_to_label_b() {
    let (dir, dev) = fresh();
    dev.activate_index(1).unwrap();
    let label = dev.label();
    drop(dev);
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join(IMAGE_NAME))
        .unwrap()
        .write_all_at(&[0xFF; 64], 0)
        .unwrap();
    let dev = Device::open(dir.path()).unwrap();
    assert_eq!(dev.label(), label);
    assert_eq!(dev.active_index(), 1);
}

#[test]
fn redb_runs_on_an_index_copy() {
    use redb::{ReadableDatabase, TableDefinition};
    const T: TableDefinition<u64, u64> = TableDefinition::new("t");
    let (dir, dev) = fresh();
    {
        let db = redb::Database::builder().create_with_backend(dev.index_backend(0)).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn.open_table(T).unwrap();
            for i in 0..10_000u64 {
                t.insert(i, i * 2).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    let dev = reopen(&dir, dev);
    let db = redb::Database::builder().create_with_backend(dev.index_backend(0)).unwrap();
    let txn = db.begin_read().unwrap();
    assert_eq!(txn.open_table(T).unwrap().get(9_999).unwrap().unwrap().value(), 19_998);
    drop(txn);
    drop(db);
    dev.clear_index(0).unwrap();
    assert_eq!(dev.label().index_len[0], 0);
}

#[test]
fn shard_superblocks_and_the_probe() {
    let (dir, dev) = fresh();
    assert!(dev.read_shard_superblock(1023).unwrap().iter().all(|&b| b == 0));
    dev.write_shard_superblock(5, b"shard five").unwrap();
    dev.probe_write().unwrap();
    let dev = reopen(&dir, dev);
    assert_eq!(&dev.read_shard_superblock(5).unwrap()[..10], b"shard five");
    assert!(dev.write_shard_superblock(0, &[0u8; 4097]).is_err());
}

#[test]
fn the_advisory_lock_is_exclusive() {
    let (_dir, dev) = fresh();
    let held = dev.lock_exclusive().unwrap();
    assert_eq!(dev.lock_exclusive().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    drop(held);
    dev.lock_exclusive().unwrap();
}

#[test]
fn wiping_unformats() {
    let (dir, dev) = fresh();
    drop(dev);
    wipe(dir.path()).unwrap();
    assert!(!is_formatted(dir.path()));
}
