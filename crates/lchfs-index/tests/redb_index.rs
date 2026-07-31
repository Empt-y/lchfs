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
        index.put_chunk_location(hash, loc).unwrap();
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
        index.put_chunk_location(*hash, *loc).unwrap();
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
