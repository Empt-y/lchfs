//! Standalone round-trip test for the Delta stream's segment/path layer
//! (Phase E, ARCHITECTURE.md §3 "Subtree durability via per-shard delta
//! logs"). No `Pool` involvement — this only exercises
//! `SegmentWriter::create_delta`/`SegmentReader::open_delta` and the
//! shard-scoped path layout directly, per the E.1 plan.

use lchfs_format::{CodecId, ExtentKind, Hash32};
use lchfs_store::segment::{SegmentReader, SegmentWriter};

#[test]
fn delta_segment_round_trips_and_is_shard_scoped() {
    let dir = tempfile::tempdir().unwrap();

    let mut w7 = SegmentWriter::create_delta(dir.path(), 7, 0).unwrap();
    let payload = b"delta log entry payload";
    let hash = Hash32::of(payload);
    let loc = w7
        .append(
            ExtentKind::DeltaLogEntry,
            hash,
            CodecId::None,
            payload.len() as u32,
            payload,
            Vec::new(),
        )
        .unwrap();
    w7.fsync().unwrap();

    // A different shard's delta stream must be a genuinely separate file —
    // same segment_id 0 is fine, since the shard subdirectory disambiguates.
    let mut w9 = SegmentWriter::create_delta(dir.path(), 9, 0).unwrap();
    let other_payload = b"a different shard's entry";
    let other_hash = Hash32::of(other_payload);
    w9.append(
        ExtentKind::DeltaLogEntry,
        other_hash,
        CodecId::None,
        other_payload.len() as u32,
        other_payload,
        Vec::new(),
    )
    .unwrap();
    w9.fsync().unwrap();

    let r7 = SegmentReader::open_delta(dir.path(), 7, 0).unwrap();
    let (header, bytes) = r7.read_record(loc).unwrap();
    assert_eq!(bytes, payload);
    assert_eq!(header.content_hash, hash);
    assert_eq!(header.kind, ExtentKind::DeltaLogEntry);

    // On-disk layout: shard-scoped subdirectories, not a flat pool.
    assert!(
        dir.path()
            .join("segments/delta/00007/0.dseg")
            .is_file()
    );
    assert!(
        dir.path()
            .join("segments/delta/00009/0.dseg")
            .is_file()
    );
}

#[test]
fn delta_segment_seal_round_trips_stream_kind_and_owner_shard() {
    let dir = tempfile::tempdir().unwrap();
    let w = SegmentWriter::create_delta(dir.path(), 3, 0).unwrap();
    w.seal().unwrap();

    let r = SegmentReader::open_delta(dir.path(), 3, 0).unwrap();
    let header = r.read_header().unwrap();
    assert_eq!(header.stream_kind, lchfs_format::StreamKind::Delta);
    assert_eq!(header.owner_shard, 3);
    assert_eq!(header.state, lchfs_format::SegmentState::Sealed);
}
