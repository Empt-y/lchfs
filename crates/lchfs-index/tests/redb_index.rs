use lchfs_format::{ExtentLocation, Hash32};
use lchfs_index::{IndexStore, RedbIndex};

#[test]
fn create_open_roundtrip_chunk_location() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("INDEX.redb");

    let hash = Hash32([7u8; 32]);
    let loc = ExtentLocation {
        segment_id: 3,
        offset: 4096,
        len: 128,
    };

    {
        let mut index = RedbIndex::create(&path).unwrap();
        assert_eq!(index.get_chunk_location(hash).unwrap(), None);
        index.put_chunk_location(hash, 0, loc).unwrap();
        assert_eq!(index.get_chunk_location(hash).unwrap(), Some(loc));
        assert_eq!(index.generation(), 0);
        index.checkpoint(5).unwrap();
        assert_eq!(index.generation(), 5);
    }

    // Reopen: put_chunk_location committed with Durability::None but was
    // still followed by an Immediate-durability checkpoint commit, so the
    // whole write transaction history up to and including that point must
    // survive a close/reopen.
    let index = RedbIndex::open(&path).unwrap();
    assert_eq!(index.get_chunk_location(hash).unwrap(), Some(loc));
    assert_eq!(index.generation(), 5);
}

#[test]
fn inode_hash_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("INDEX.redb");
    let mut index = RedbIndex::create(&path).unwrap();

    assert_eq!(index.get_inode_hash(42).unwrap(), None);
    let hash = Hash32([9u8; 32]);
    index.put_inode_hash(42, hash).unwrap();
    assert_eq!(index.get_inode_hash(42).unwrap(), Some(hash));
}

#[test]
fn iter_chunk_locations_returns_everything_put() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("INDEX.redb");
    let mut index = RedbIndex::create(&path).unwrap();

    let entries: Vec<(Hash32, ExtentLocation)> = (0..50)
        .map(|i| {
            (
                Hash32([i as u8; 32]),
                ExtentLocation {
                    segment_id: i,
                    offset: i as u32 * 10,
                    len: 64,
                },
            )
        })
        .collect();
    for (hash, loc) in &entries {
        index.put_chunk_location(*hash, 0, *loc).unwrap();
    }

    let mut loaded = index.iter_chunk_locations().unwrap();
    loaded.sort_by_key(|(h, _)| h.0);
    let mut expected = entries.clone();
    expected.sort_by_key(|(h, _)| h.0);
    assert_eq!(loaded, expected);
}

#[test]
fn fresh_index_starts_at_generation_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("INDEX.redb");
    let index = RedbIndex::create(&path).unwrap();
    assert_eq!(index.generation(), 0);
}

/// One hash, several replicas (ARCHITECTURE.md §15.1). The composite
/// `hash || vdev_id` key has to keep them distinct, return them in vdev
/// order, and still let the common "just tell me where to read this" caller
/// get a single answer without knowing replication exists.
#[test]
fn a_hash_can_hold_a_location_per_vdev() {
    let dir = tempfile::tempdir().unwrap();
    let mut index = RedbIndex::create(&dir.path().join("INDEX.redb")).unwrap();

    let hash = Hash32::of(b"replicated");
    let on_vdev0 = ExtentLocation { segment_id: 1, offset: 64, len: 128 };
    let on_vdev1 = ExtentLocation { segment_id: 9, offset: 4096, len: 128 };
    // Inserted out of order on purpose: ordering must come from the key, not
    // from insertion sequence.
    index.put_chunk_location(hash, 1, on_vdev1).unwrap();
    index.put_chunk_location(hash, 0, on_vdev0).unwrap();

    assert_eq!(
        index.chunk_locations(hash).unwrap(),
        vec![(0, on_vdev0), (1, on_vdev1)],
        "replicas should come back ascending by vdev_id"
    );

    // The preferred replica is the lowest vdev_id, and this is what every
    // existing read path uses.
    assert_eq!(index.get_chunk_location(hash).unwrap(), Some(on_vdev0));

    // Warming the hot-path cache must not multiply entries per replica.
    let all = index.iter_chunk_locations().unwrap();
    assert_eq!(all.len(), 1, "iter should collapse replicas to one entry per hash");
    assert_eq!(all[0], (hash, on_vdev0));
}

#[test]
fn replicas_of_different_hashes_do_not_collide() {
    let dir = tempfile::tempdir().unwrap();
    let mut index = RedbIndex::create(&dir.path().join("INDEX.redb")).unwrap();
    let a = Hash32::of(b"a");
    let b = Hash32::of(b"b");
    let loc = |id| ExtentLocation { segment_id: id, offset: 0, len: 16 };

    index.put_chunk_location(a, 0, loc(1)).unwrap();
    index.put_chunk_location(a, 1, loc(2)).unwrap();
    index.put_chunk_location(b, 0, loc(3)).unwrap();

    assert_eq!(index.chunk_locations(a).unwrap().len(), 2);
    assert_eq!(index.chunk_locations(b).unwrap(), vec![(0, loc(3))]);
    assert_eq!(index.chunk_locations(Hash32::of(b"absent")).unwrap(), vec![]);
}

#[test]
fn iter_all_lists_every_replica_and_delete_forgets_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut index = RedbIndex::create(&dir.path().join("INDEX.redb")).unwrap();
    let a = Hash32([1u8; 32]);
    let b = Hash32([2u8; 32]);
    let loc = |segment_id| ExtentLocation {
        segment_id,
        offset: 4096,
        len: 10,
    };
    index.put_chunk_location(a, 1, loc(11)).unwrap();
    index.put_chunk_location(a, 0, loc(10)).unwrap();
    index.put_chunk_location(b, 0, loc(20)).unwrap();

    assert_eq!(
        index.iter_all_chunk_locations().unwrap(),
        vec![(a, 0, loc(10)), (a, 1, loc(11)), (b, 0, loc(20))],
        "every replica, hash-major then vdev-ascending"
    );

    index.delete_chunk_location(a, 0).unwrap();
    assert_eq!(index.chunk_locations(a).unwrap(), vec![(1, loc(11))]);
    assert_eq!(
        index.get_chunk_location(a).unwrap(),
        Some(loc(11)),
        "preferred replica moves to the next lowest vdev"
    );
    // Deleting what isn't there is not an error.
    index.delete_chunk_location(b, 5).unwrap();
    assert_eq!(index.chunk_locations(b).unwrap(), vec![(0, loc(20))]);
}

#[test]
fn delete_vdev_locations_forgets_one_slot_and_leaves_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let mut index = RedbIndex::create(&dir.path().join("INDEX.redb")).unwrap();
    let loc = |segment_id| ExtentLocation {
        segment_id,
        offset: 4096,
        len: 10,
    };
    for i in 0..5u8 {
        let h = Hash32([i; 32]);
        index.put_chunk_location(h, 0, loc(1)).unwrap();
        index.put_chunk_location(h, 1, loc(2)).unwrap();
    }
    assert_eq!(index.delete_vdev_locations(1).unwrap(), 5);
    assert_eq!(index.delete_vdev_locations(1).unwrap(), 0);
    let all = index.iter_all_chunk_locations().unwrap();
    assert_eq!(all.len(), 5);
    assert!(all.iter().all(|(_, v, _)| *v == 0));
}

#[test]
fn a_fresh_rewrite_keeps_locations_and_generation_and_drops_the_memo() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("INDEX.redb");
    let mut index = RedbIndex::create(&path).unwrap();
    let loc = ExtentLocation { segment_id: 7, offset: 4096, len: 100 };
    let kept = Hash32([0x11; 32]);
    // Only ever a memo key: its bytes must not survive the rewrite.
    let old = Hash32([0xA7; 32]);
    let new = Hash32([0x5C; 32]);
    index.put_chunk_location(kept, 0, loc).unwrap();
    index.put_rekey_memo(old, new).unwrap();
    index.checkpoint(9).unwrap();
    assert_eq!(index.get_rekey_memo(old).unwrap(), Some(new));
    assert!(
        std::fs::read(&path).unwrap().windows(32).any(|w| w == old.0),
        "the check below means nothing unless the old file held the hash"
    );

    index.rewrite_fresh(&path).unwrap();
    assert_eq!(index.get_rekey_memo(old).unwrap(), None);
    assert_eq!(index.get_chunk_location(kept).unwrap(), Some(loc));
    // Still writable through the moved handle.
    index.put_chunk_location(Hash32([0x22; 32]), 0, loc).unwrap();
    index.checkpoint(10).unwrap();
    drop(index);

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(32).any(|w| w == old.0), "the memo's old hash survived in the file");
    assert!(!dir.path().join("INDEX.redb.tmp").exists());
    let index = RedbIndex::open(&path).unwrap();
    assert_eq!(index.generation(), 10);
    assert_eq!(index.get_chunk_location(kept).unwrap(), Some(loc));
}
