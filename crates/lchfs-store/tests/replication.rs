//! Write fan-out across vdevs (ARCHITECTURE.md §15.3).
//!
//! A write is durable when every online vdev has it -- synchronous to all,
//! never quorum. §5 already set that precedent for the ingress rings ("never
//! drop; a dropped write is data loss, unacceptable for a filesystem"), and
//! acking a write present on only some replicas would require a catch-up
//! log, i.e. a second durability mechanism to get wrong.
//!
//! These tests drive `SegmentWriter` directly, with no `Pool`, so they
//! exercise the fan-out itself rather than anything above it.

use lchfs_format::{CodecId, ExtentKind, Hash32, StreamKind};
use lchfs_store::segment::{SegmentReader, SegmentWriter};

fn append_records(w: &mut SegmentWriter, payloads: &[&[u8]]) -> Vec<lchfs_format::ExtentLocation> {
    payloads
        .iter()
        .map(|p| {
            w.append(
                ExtentKind::RawChunk,
                Hash32::of(p),
                CodecId::None,
                p.len() as u32,
                p,
                Vec::new(),
            )
            .unwrap()
        })
        .collect()
}

/// The core property: every replica ends up byte-identical, including the
/// header page and the seal footer.
#[test]
fn every_vdev_receives_a_byte_identical_segment() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();

    let mut w =
        SegmentWriter::create(&[a.path(), b.path(), c.path()], 42, StreamKind::Data, 0).unwrap();
    append_records(&mut w, &[b"first", b"second payload", &[7u8; 5000]]);
    w.fsync().unwrap();
    w.seal().unwrap();

    let read = |root: &std::path::Path| std::fs::read(root.join("segments/data/42.aseg")).unwrap();
    let va = read(a.path());
    assert!(!va.is_empty());
    assert_eq!(va, read(b.path()), "vdev b diverged from vdev a");
    assert_eq!(va, read(c.path()), "vdev c diverged from vdev a");
}

/// Offsets agree across replicas during normal operation, which is why a
/// single returned `ExtentLocation` is meaningful for all of them. (Per-vdev
/// locations exist for what happens *after* a repair, when heal appends
/// recovered bytes at a fresh offset on one device only.)
#[test]
fn a_record_reads_back_identically_from_any_vdev() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();

    let mut w = SegmentWriter::create(&[a.path(), b.path()], 1, StreamKind::Data, 0).unwrap();
    let payload = b"content addressed bytes";
    let locs = append_records(&mut w, &[payload]);
    w.fsync().unwrap();
    w.seal().unwrap();

    for root in [a.path(), b.path()] {
        let reader = SegmentReader::open(root, 1, StreamKind::Data).unwrap();
        let (_header, bytes) = reader.read_record(locs[0]).unwrap();
        assert_eq!(bytes, payload, "replica at {root:?} returned different bytes");
    }
}

#[test]
fn delta_segments_fan_out_too() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();

    let mut w = SegmentWriter::create_delta(&[a.path(), b.path()], 3, 0).unwrap();
    append_records(&mut w, &[b"delta entry"]);
    w.fsync().unwrap();

    let p = "segments/delta/00003/0.dseg";
    assert_eq!(
        std::fs::read(a.path().join(p)).unwrap(),
        std::fs::read(b.path().join(p)).unwrap(),
        "delta replicas diverged"
    );
}

/// A segment with nowhere to go is a programming error, not a silently
/// successful no-op write.
#[test]
fn a_writer_with_no_vdevs_is_rejected() {
    match SegmentWriter::create(&[], 1, StreamKind::Data, 0) {
        Ok(_) => panic!("a writer with no vdevs was accepted"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
    }
}
