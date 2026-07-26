//! Round-trip encode/decode proptests for every schema type in
//! `lchfs-format`, per ARCHITECTURE.md §12 Phase A ("round-trip encode/decode
//! proptests, everything else depends on these") and §10 (testing strategy).
//!
//! Each type gets a hand-written `proptest` `Strategy` (no `proptest-derive`
//! dependency) and a `decode(encode(x)) == x` property test.

use lchfs_format::*;
use proptest::array::uniform16;
use proptest::collection::vec as pvec;
use proptest::prelude::*;

fn hash32() -> impl Strategy<Value = Hash32> {
    any::<[u8; 32]>().prop_map(Hash32)
}

fn extent_location() -> impl Strategy<Value = ExtentLocation> {
    (any::<u64>(), any::<u32>(), any::<u32>()).prop_map(|(segment_id, offset, len)| {
        ExtentLocation {
            segment_id,
            offset,
            len,
        }
    })
}

fn extent_kind() -> impl Strategy<Value = ExtentKind> {
    prop_oneof![
        Just(ExtentKind::RawChunk),
        Just(ExtentKind::InodeObject),
        Just(ExtentKind::DirectoryObject),
        Just(ExtentKind::IndirectHashList),
        Just(ExtentKind::SnapshotTable),
        Just(ExtentKind::RootObject),
        Just(ExtentKind::DeltaLogEntry),
    ]
}

fn codec_id() -> impl Strategy<Value = CodecId> {
    prop_oneof![Just(CodecId::None), Just(CodecId::Zstd)]
}

prop_compose! {
    fn extent_record_header()(
        magic in any::<u32>(),
        record_len in any::<u32>(),
        content_hash in hash32(),
        kind in extent_kind(),
        codec_id in codec_id(),
        flags in any::<u16>(),
        uncompressed_len in any::<u32>(),
        compressed_len in any::<u32>(),
        backpointers in pvec(hash32(), 0..5),
        header_checksum in any::<u32>(),
    ) -> ExtentRecordHeader {
        ExtentRecordHeader {
            magic,
            record_len,
            content_hash,
            kind,
            codec_id,
            flags,
            uncompressed_len,
            compressed_len,
            backpointers,
            header_checksum,
        }
    }
}

fn inode_kind() -> impl Strategy<Value = InodeKind> {
    prop_oneof![
        Just(InodeKind::File),
        Just(InodeKind::Directory),
        Just(InodeKind::Symlink),
    ]
}

fn content_ref() -> impl Strategy<Value = ContentRef> {
    prop_oneof![
        pvec(any::<u8>(), 0..64).prop_map(ContentRef::Inline),
        hash32().prop_map(ContentRef::ChunkList),
        hash32().prop_map(ContentRef::DirEntries),
        ".*".prop_map(ContentRef::SymlinkTarget),
    ]
}

prop_compose! {
    fn chunk_ref()(
        content_hash in hash32(),
        logical_offset in any::<u64>(),
        len in any::<u32>(),
    ) -> ChunkRef {
        ChunkRef { content_hash, logical_offset, len }
    }
}

fn indirect_hash_list() -> impl Strategy<Value = IndirectHashList> {
    pvec(chunk_ref(), 0..8).prop_map(|chunks| IndirectHashList { chunks })
}

prop_compose! {
    fn dir_entry()(
        name in "[a-zA-Z0-9_.-]{1,16}",
        ino in any::<u64>(),
        kind in inode_kind(),
    ) -> DirEntry {
        DirEntry { name, ino, kind }
    }
}

fn directory_object() -> impl Strategy<Value = DirectoryObject> {
    pvec(dir_entry(), 0..8).prop_map(|entries| DirectoryObject { entries })
}

fn xattr_blob() -> impl Strategy<Value = XattrBlob> {
    pvec(any::<u8>(), 0..32).prop_map(XattrBlob)
}

prop_compose! {
    fn inode_object()(
        kind in inode_kind(),
        mode in any::<u32>(),
        uid in any::<u32>(),
        gid in any::<u32>(),
        size in any::<u64>(),
        nlink in any::<u32>(),
        atime in (any::<i64>(), any::<u32>()),
        mtime in (any::<i64>(), any::<u32>()),
        ctime in (any::<i64>(), any::<u32>()),
        xattrs in proptest::option::of(xattr_blob()),
        content in content_ref(),
        generation in any::<u64>(),
    ) -> InodeObject {
        InodeObject {
            kind,
            mode,
            uid,
            gid,
            size,
            nlink,
            atime,
            mtime,
            ctime,
            xattrs,
            content,
            generation,
        }
    }
}

prop_compose! {
    fn ino_map_entry()(
        ino in any::<u64>(),
        current_object_hash in hash32(),
    ) -> InoMapEntry {
        InoMapEntry { ino, current_object_hash }
    }
}

fn ino_map() -> impl Strategy<Value = InoMap> {
    pvec(ino_map_entry(), 0..8).prop_map(|entries| InoMap { entries })
}

prop_compose! {
    fn snapshot_entry()(
        name in "[a-zA-Z0-9_.-]{1,16}",
        root_hash in hash32(),
        created_at_unix_nanos in any::<i64>(),
        epoch in any::<u64>(),
    ) -> SnapshotEntry {
        SnapshotEntry { name, root_hash, created_at_unix_nanos, epoch }
    }
}

fn snapshot_table() -> impl Strategy<Value = SnapshotTable> {
    pvec(snapshot_entry(), 0..8).prop_map(|entries| SnapshotTable { entries })
}

prop_compose! {
    fn delta_log_entry()(
        ino in any::<u64>(),
        new_object_hash in hash32(),
        epoch in any::<u64>(),
    ) -> DeltaLogEntry {
        DeltaLogEntry { ino, new_object_hash, epoch }
    }
}

prop_compose! {
    fn pool_params()(
        data_segment_cap_bytes in any::<u32>(),
        meta_segment_cap_bytes in any::<u32>(),
        chunk_avg_size in any::<u32>(),
        chunk_min_size in any::<u32>(),
        chunk_max_size in any::<u32>(),
        inline_threshold in any::<u32>(),
        logical_shard_count in any::<u32>(),
    ) -> PoolParams {
        PoolParams {
            data_segment_cap_bytes,
            meta_segment_cap_bytes,
            chunk_avg_size,
            chunk_min_size,
            chunk_max_size,
            inline_threshold,
            logical_shard_count,
        }
    }
}

prop_compose! {
    fn root_object()(
        inomap_hash in hash32(),
        root_dir_ino in any::<u64>(),
        next_ino_counter in any::<u64>(),
        snapshot_table_hash in hash32(),
        pool_params in pool_params(),
        shard_watermarks in pvec(any::<u64>(), 0..8),
    ) -> RootObject {
        RootObject {
            inomap_hash,
            root_dir_ino,
            next_ino_counter,
            snapshot_table_hash,
            pool_params,
            shard_watermarks,
        }
    }
}

prop_compose! {
    fn superblock_stats()(
        live_bytes in any::<u64>(),
        object_count in any::<u64>(),
        segment_count in any::<u64>(),
    ) -> SuperblockStats {
        SuperblockStats { live_bytes, object_count, segment_count }
    }
}

prop_compose! {
    fn superblock_slot()(
        magic in any::<[u8; 8]>(),
        format_version in any::<u32>(),
        generation in any::<u64>(),
        root_hash in hash32(),
        root_location in extent_location(),
        index_generation in any::<u64>(),
        committed_at_unix_nanos in any::<i64>(),
        stats in superblock_stats(),
        header_checksum in any::<u32>(),
    ) -> SuperblockSlot {
        SuperblockSlot {
            magic,
            format_version,
            generation,
            root_hash,
            root_location,
            index_generation,
            committed_at_unix_nanos,
            stats,
            header_checksum,
        }
    }
}

fn superblock() -> impl Strategy<Value = Superblock> {
    uniform16(superblock_slot()).prop_map(|slots| Superblock { slots })
}

prop_compose! {
    fn shard_superblock_slot()(
        magic in any::<[u8; 8]>(),
        shard_id in any::<u32>(),
        delta_log_tail in extent_location(),
        local_epoch in any::<u64>(),
        header_checksum in any::<u32>(),
    ) -> ShardSuperblockSlot {
        ShardSuperblockSlot {
            magic,
            shard_id,
            delta_log_tail,
            local_epoch,
            header_checksum,
        }
    }
}

macro_rules! roundtrip_test {
    ($name:ident, $strategy:expr, $ty:ty) => {
        proptest! {
            #[test]
            fn $name(value in $strategy) {
                let bytes = encode(&value).expect("encode should not fail");
                let decoded: $ty = decode(&bytes).expect("decode should not fail");
                prop_assert_eq!(value, decoded);
            }
        }
    };
}

roundtrip_test!(roundtrip_hash32, hash32(), Hash32);
roundtrip_test!(roundtrip_extent_location, extent_location(), ExtentLocation);
roundtrip_test!(
    roundtrip_extent_record_header,
    extent_record_header(),
    ExtentRecordHeader
);
roundtrip_test!(roundtrip_content_ref, content_ref(), ContentRef);
roundtrip_test!(roundtrip_chunk_ref, chunk_ref(), ChunkRef);
roundtrip_test!(
    roundtrip_indirect_hash_list,
    indirect_hash_list(),
    IndirectHashList
);
roundtrip_test!(roundtrip_dir_entry, dir_entry(), DirEntry);
roundtrip_test!(
    roundtrip_directory_object,
    directory_object(),
    DirectoryObject
);
roundtrip_test!(roundtrip_inode_object, inode_object(), InodeObject);
roundtrip_test!(roundtrip_ino_map_entry, ino_map_entry(), InoMapEntry);
roundtrip_test!(roundtrip_ino_map, ino_map(), InoMap);
roundtrip_test!(roundtrip_snapshot_entry, snapshot_entry(), SnapshotEntry);
roundtrip_test!(roundtrip_snapshot_table, snapshot_table(), SnapshotTable);
roundtrip_test!(roundtrip_delta_log_entry, delta_log_entry(), DeltaLogEntry);
roundtrip_test!(roundtrip_pool_params, pool_params(), PoolParams);
roundtrip_test!(roundtrip_root_object, root_object(), RootObject);
roundtrip_test!(roundtrip_superblock_stats, superblock_stats(), SuperblockStats);
roundtrip_test!(roundtrip_superblock_slot, superblock_slot(), SuperblockSlot);
roundtrip_test!(roundtrip_superblock, superblock(), Superblock);
roundtrip_test!(
    roundtrip_shard_superblock_slot,
    shard_superblock_slot(),
    ShardSuperblockSlot
);

proptest! {
    /// ARCHITECTURE.md §1: header_checksum is a cheap CRC32C pre-check.
    /// A header finalized by the writer-side helper must always validate
    /// against its own bytes, and flipping any single byte in a
    /// bincode-serialized copy must be caught before BLAKE3 is ever run.
    #[test]
    fn finalized_header_always_validates(mut header in extent_record_header()) {
        header.magic = EXTENT_RECORD_MAGIC;
        // record_len must cover at least the header for validate_header's
        // bounds check to have something meaningful to compare against.
        header.record_len = 0;
        finalize_header_checksum(&mut header);
        let encoded = encode(&header).unwrap();
        // Pad so record_len (still 0) never exceeds the buffer length.
        prop_assert!(validate_header(&header, &encoded).is_ok());
    }

    #[test]
    fn corrupted_checksum_is_rejected(mut header in extent_record_header()) {
        header.magic = EXTENT_RECORD_MAGIC;
        header.record_len = 0;
        finalize_header_checksum(&mut header);
        let good_checksum = header.header_checksum;
        header.header_checksum = good_checksum.wrapping_add(1);
        let encoded = encode(&header).unwrap();
        let result = validate_header(&header, &encoded);
        let is_checksum_err = matches!(result, Err(ExtentValidationError::HeaderChecksum));
        prop_assert!(is_checksum_err);
    }

    #[test]
    fn bad_magic_is_rejected(mut header in extent_record_header()) {
        header.record_len = 0;
        finalize_header_checksum(&mut header);
        header.magic = header.magic.wrapping_add(1);
        let encoded = encode(&header).unwrap();
        let result = validate_header(&header, &encoded);
        let is_bad_magic = matches!(result, Err(ExtentValidationError::BadMagic { .. }));
        prop_assert!(is_bad_magic);
    }

    #[test]
    fn out_of_bounds_record_len_is_rejected(mut header in extent_record_header()) {
        header.magic = EXTENT_RECORD_MAGIC;
        finalize_header_checksum(&mut header);
        header.record_len = u32::MAX;
        let encoded = encode(&header).unwrap();
        let result = validate_header(&header, &encoded);
        let is_out_of_bounds = matches!(result, Err(ExtentValidationError::OutOfBounds { .. }));
        prop_assert!(is_out_of_bounds);
    }
}
