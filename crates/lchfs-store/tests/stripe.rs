//! The stripe primitives on their own (ARCHITECTURE.md §17.2): a sealed
//! segment's body written as k + m shards, read back record by record,
//! reconstructed with shards missing, and a lost shard rebuilt.

use lchfs_format::{CodecId, ExtentKind, ExtentLocation, Hash32, StreamKind};
use lchfs_store::Vdev;
use lchfs_store::segment::{SEGMENT_HEADER_PAGE_SIZE, SegmentReader, SegmentWriter};
use lchfs_store::stripe::{StripeReader, rebuild_shard, shard_path, shards_on, write_stripe};
use std::path::PathBuf;

/// A device is where its ring is: a writer refuses to create a segment
/// on a root without one, so a bare directory is given a ring first.
fn device() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    lchfs_store::backend::FileBackend::open(dir.path()).unwrap();
    dir
}

/// A sealed mirrored segment on one device, with records of varied sizes
/// -- enough to span several shards at k=2 or k=3.
fn sealed_segment(root: &std::path::Path, id: u64) -> Vec<(ExtentLocation, Vec<u8>)> {
    let mut w = SegmentWriter::create(&[root], id, StreamKind::Data, 0).unwrap();
    let mut records = Vec::new();
    for i in 0..40u32 {
        let len = 3_000 + (i as usize * 977) % 9_000;
        let payload: Vec<u8> = (0..len as u32)
            .map(|j| ((j ^ i.wrapping_mul(7919)).wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let loc = w
            .append(ExtentKind::RawChunk, Hash32::of(&payload), CodecId::None, len as u32, &payload, Vec::new())
            .unwrap();
        records.push((loc, payload));
    }
    w.seal().unwrap();
    records
}

fn body_of(root: &std::path::Path, id: u64) -> Vec<u8> {
    let bytes = std::fs::read(root.join(format!("segments/data/{id}.aseg"))).unwrap();
    bytes[SEGMENT_HEADER_PAGE_SIZE as usize..].to_vec()
}

fn devices(dirs: &[&tempfile::TempDir]) -> Vec<Vdev> {
    dirs.iter().enumerate().map(|(i, d)| Vdev::new(i as u16, d.path().to_path_buf())).collect()
}

fn root_of(devs: &[Vdev]) -> impl Fn(u16) -> Option<PathBuf> + '_ {
    move |id| devs.iter().find(|v| v.id == id).map(|v| v.root.clone())
}

#[test]
fn every_record_reads_back_through_the_stripe() {
    let src = device();
    let (a, b, c) = (device(), device(), device());
    let records = sealed_segment(src.path(), 9);
    let body = body_of(src.path(), 9);
    let devs = devices(&[&a, &b, &c]);

    let desc = write_stripe(&body, 9, 2, 1, &devs).unwrap();
    assert_eq!((desc.k, desc.m), (2, 1));
    assert_eq!(desc.logical_len, body.len() as u64);
    assert!(desc.shard_size.is_multiple_of(4096));
    for (i, d) in devs.iter().enumerate() {
        assert_eq!(shards_on(&d.root, 9), vec![i as u8], "one shard per device");
    }

    let reader = StripeReader::open(9, root_of(&devs), &devs).unwrap();
    assert_eq!(reader.present(), 3);
    for (loc, payload) in &records {
        let (header, bytes) = reader.read_record(*loc).unwrap();
        assert_eq!(&bytes, payload);
        assert_eq!(header.content_hash, Hash32::of(payload));
    }
    // The whole body, reassembled, is the body.
    assert_eq!(reader.read_body(0, body.len() as u64).unwrap(), body);
    for i in 0..3 {
        assert!(reader.verify_shard(i).unwrap());
    }
}

#[test]
fn a_missing_shard_is_reconstructed_on_read_and_rebuilt_on_disk() {
    let src = device();
    let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| device()).collect();
    let records = sealed_segment(src.path(), 11);
    let body = body_of(src.path(), 11);
    let devs: Vec<Vdev> = dirs.iter().enumerate().map(|(i, d)| Vdev::new(i as u16, d.path().to_path_buf())).collect();
    write_stripe(&body, 11, 3, 1, &devs).unwrap();

    // Lose data shard 1 entirely.
    std::fs::remove_file(shard_path(&devs[1].root, 11, 1)).unwrap();
    let reader = StripeReader::open(11, root_of(&devs), &devs).unwrap();
    assert_eq!(reader.missing(), vec![1]);
    for (loc, payload) in &records {
        let (_, bytes) = reader.read_record(*loc).unwrap();
        assert_eq!(&bytes, payload, "record at {} not reconstructed correctly", loc.offset);
    }
    assert!(!reader.verify_shard(1).unwrap());

    // Rebuild it, and it verifies like the original.
    rebuild_shard(&reader, 1, &devs[1]).unwrap();
    let reader = StripeReader::open(11, root_of(&devs), &devs).unwrap();
    assert!(reader.missing().is_empty());
    assert!(reader.verify_shard(1).unwrap());
    let rebuilt = std::fs::read(shard_path(&devs[1].root, 11, 1)).unwrap();
    // Byte-identical to what write_stripe would have produced: the same
    // header page and the same shard bytes.
    let fresh = tempfile::tempdir().unwrap();
    let fresh_devs: Vec<Vdev> = (0..4)
        .map(|i| {
            let root = fresh.path().join(i.to_string());
            lchfs_store::backend::FileBackend::open(&root).unwrap();
            Vdev::new(i, root)
        })
        .collect();
    write_stripe(&body, 11, 3, 1, &fresh_devs).unwrap();
    let original = std::fs::read(shard_path(&fresh_devs[1].root, 11, 1)).unwrap();
    assert_eq!(rebuilt, original);
}

#[test]
fn a_parity_shard_can_go_too_and_more_than_m_cannot() {
    let src = device();
    let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| device()).collect();
    let records = sealed_segment(src.path(), 12);
    let body = body_of(src.path(), 12);
    let devs: Vec<Vdev> = dirs.iter().enumerate().map(|(i, d)| Vdev::new(i as u16, d.path().to_path_buf())).collect();
    write_stripe(&body, 12, 2, 2, &devs).unwrap();
    // Two of four gone -- one data, one parity -- still readable at k=2,m=2.
    std::fs::remove_file(shard_path(&devs[0].root, 12, 0)).unwrap();
    std::fs::remove_file(shard_path(&devs[3].root, 12, 3)).unwrap();
    let reader = StripeReader::open(12, root_of(&devs), &devs).unwrap();
    assert_eq!(reader.missing(), vec![0, 3]);
    let (loc, payload) = &records[5];
    assert_eq!(reader.read_record(*loc).unwrap().1, *payload);
    // Three gone is past what m=2 can cover.
    std::fs::remove_file(shard_path(&devs[1].root, 12, 1)).unwrap();
    let reader = StripeReader::open(12, root_of(&devs), &devs).unwrap();
    assert!(reader.read_record(*loc).is_err());
}

#[test]
fn a_corrupted_shard_fails_verification_and_is_read_through_parity() {
    let src = device();
    let dirs: Vec<tempfile::TempDir> = (0..3).map(|_| device()).collect();
    let records = sealed_segment(src.path(), 13);
    let body = body_of(src.path(), 13);
    let devs: Vec<Vdev> = dirs.iter().enumerate().map(|(i, d)| Vdev::new(i as u16, d.path().to_path_buf())).collect();
    write_stripe(&body, 13, 2, 1, &devs).unwrap();
    let p = shard_path(&devs[0].root, 13, 0);
    let mut bytes = std::fs::read(&p).unwrap();
    for x in &mut bytes[SEGMENT_HEADER_PAGE_SIZE as usize + 100..SEGMENT_HEADER_PAGE_SIZE as usize + 164] {
        *x ^= 0xff;
    }
    std::fs::write(&p, &bytes).unwrap();
    let reader = StripeReader::open(13, root_of(&devs), &devs).unwrap();
    assert!(!reader.verify_shard(0).unwrap());
    assert!(reader.verify_shard(1).unwrap());
    // The record whose bytes were hit fails its content-hash check on the
    // straight read and is served through parity instead: a shard that
    // is present but wrong is a missing shard as far as a read goes.
    let (loc0, payload0) = &records[0];
    assert_eq!(reader.read_record(*loc0).unwrap().1, *payload0);
    // With no parity to fall back on, the failure is honest.
    std::fs::remove_file(shard_path(&devs[2].root, 13, 2)).unwrap();
    let reader = StripeReader::open(13, root_of(&devs), &devs).unwrap();
    assert!(reader.read_record(*loc0).is_err());
    let reader = StripeReader::open(13, root_of(&devs), &devs).unwrap();
    let (loc_last, payload_last) = records.last().unwrap();
    assert_eq!(reader.read_record(*loc_last).unwrap().1, *payload_last);
    // And a plain SegmentReader refuses to treat a shard file as a segment.
    assert!(SegmentReader::open(&devs[0].root, 13, StreamKind::Data).is_err());
}
