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

// ---- End-to-end, through the Pool API -------------------------------

use lchfs_format::PoolParams;
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

/// Every file under `dir`, relative path -> bytes.
fn tree(dir: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    fn walk(
        base: &std::path::Path,
        d: &std::path::Path,
        out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        let Ok(entries) = std::fs::read_dir(d) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if let Ok(bytes) = std::fs::read(&p) {
                out.insert(p.strip_prefix(base).unwrap().to_path_buf(), bytes);
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

/// The whole point: real file content written through `Pool` lands on every
/// vdev, byte-identically, and the pool reopens from the set.
#[test]
fn a_two_vdev_pool_replicates_real_file_content() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();

    let payload = vec![0xA5u8; 40_000]; // multi-chunk at these params
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap();
        let ino = pool.create_file(1, "big", 0o644).unwrap();
        pool.write(ino, 0, &payload).unwrap();
        pool.checkpoint().unwrap();
    }

    // Segment trees must match exactly. INDEX.redb is deliberately excluded:
    // §15.10 keeps it on vdev 0 only, as a rebuildable cache.
    let sa = tree(&a.path().join("segments"));
    let sb = tree(&b.path().join("segments"));
    assert!(!sa.is_empty(), "no segments were written at all");
    assert_eq!(sa.keys().collect::<Vec<_>>(), sb.keys().collect::<Vec<_>>());
    assert_eq!(sa, sb, "vdev b's segments differ from vdev a's");
    assert!(!b.path().join("INDEX.redb").exists(), "the index should not be replicated");

    // And it reopens from the set with content intact.
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    let ino = pool.lookup(1, "big").unwrap().unwrap();
    assert_eq!(pool.read(ino, 0, payload.len() as u32).unwrap(), payload);
}

#[test]
fn a_device_from_another_pool_is_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();

    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());
    drop(Pool::create(foreign.path(), small_params()).unwrap());

    let err = Pool::open_replicated(&[a.path(), foreign.path()]).unwrap_err();
    assert!(
        err.to_string().contains("different pool"),
        "expected a membership refusal, got: {err}"
    );
}

#[test]
fn devices_given_out_of_vdev_order_are_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());

    let err = Pool::open_replicated(&[b.path(), a.path()]).unwrap_err();
    assert!(
        err.to_string().contains("vdev_id order"),
        "expected an ordering refusal, got: {err}"
    );
}

#[test]
fn opening_a_two_vdev_pool_with_one_device_is_refused() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    drop(Pool::create_replicated(&[a.path(), b.path()], small_params()).unwrap());

    // Degraded mount is a designed future capability (§15.8), not something
    // that should happen by accident because a device was left off the list.
    let err = Pool::open(a.path()).unwrap_err();
    assert!(
        err.to_string().contains("2 vdevs but 1"),
        "expected a vdev-count refusal, got: {err}"
    );
}

// ---- Scanning past damage ----------------------------------------------

/// `scan_next` stops at the first unparseable header, which is right for a
/// torn tail and wrong for rot in the middle of a segment: every good
/// record behind the damage would be reported missing from a device that
/// still has it. `scan` resyncs on the next intact header instead.
#[test]
fn a_scan_recovers_the_records_behind_a_damaged_stretch() {
    use lchfs_store::segment::ScanEnd;
    use std::io::{Seek, SeekFrom, Write};

    let dir = tempfile::tempdir().unwrap();
    let payloads: Vec<Vec<u8>> = (0..12u8).map(|i| vec![i; 3000 + i as usize * 7]).collect();
    let mut w = SegmentWriter::create(&[dir.path()], 7, StreamKind::Data, 0).unwrap();
    let locs = append_records(&mut w, &payloads.iter().map(|p| p.as_slice()).collect::<Vec<_>>());
    w.seal().unwrap();

    // Scribble over records 4 and 5 entirely, header and all.
    let path = dir.path().join("segments/data/7.aseg");
    let from = locs[4].offset as u64;
    let to = locs[6].offset as u64;
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(from)).unwrap();
        f.write_all(&vec![0xAB; (to - from) as usize]).unwrap();
    }

    let reader = SegmentReader::open(dir.path(), 7, StreamKind::Data).unwrap();

    // The old primitive gives up at the damage.
    let mut n = 0;
    let mut off = lchfs_store::segment::SEGMENT_HEADER_PAGE_SIZE as u32;
    while let Some((_, next)) = reader.scan_next(off) {
        n += 1;
        off = next;
    }
    assert_eq!(n, 4, "scan_next should stop at the first damaged header");

    // The scan carries on.
    let mut scan = reader.scan();
    let found: Vec<u32> = (&mut scan).map(|(_, offset)| offset).collect();
    let expected: Vec<u32> = locs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4 && *i != 5)
        .map(|(_, l)| l.offset)
        .collect();
    assert_eq!(found, expected, "every intact record, at its real offset");
    assert_eq!(scan.damaged, vec![(locs[4].offset, locs[6].offset)]);
    assert_eq!(scan.end, Some(ScanEnd::Footer), "the sealed footer is a clean end, not damage");

    // And every recovered record reads back and verifies.
    for (i, &offset) in expected.iter().enumerate() {
        let src = if i < 4 { i } else { i + 2 };
        let (_, bytes) = reader.read_record(locs[src]).unwrap();
        assert_eq!(bytes, payloads[src], "record at {offset}");
    }
}

/// An open (unsealed) segment ends at EOF, and one whose tail was torn by
/// a crash ends at the tear -- neither is reported as damage.
#[test]
fn a_clean_tail_is_not_mistaken_for_damage() {
    use lchfs_store::segment::ScanEnd;

    let dir = tempfile::tempdir().unwrap();
    let mut w = SegmentWriter::create(&[dir.path()], 8, StreamKind::Data, 0).unwrap();
    append_records(&mut w, &[b"one", b"two", b"three"]);
    w.fsync().unwrap();
    drop(w); // never sealed

    let reader = SegmentReader::open(dir.path(), 8, StreamKind::Data).unwrap();
    let mut scan = reader.scan();
    assert_eq!((&mut scan).count(), 3);
    assert!(scan.damaged.is_empty());
    assert_eq!(scan.end, Some(ScanEnd::Eof));

    // Tear the last record in half.
    let path = dir.path().join("segments/data/8.aseg");
    let len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(len - 5).unwrap();
    let reader = SegmentReader::open(dir.path(), 8, StreamKind::Data).unwrap();
    let mut scan = reader.scan();
    assert_eq!((&mut scan).count(), 2, "the torn record is dropped, the rest kept");
    // Its header still parses but the record runs past EOF; nothing can
    // follow it, so that is a clean end and not damage.
    assert!(scan.damaged.is_empty(), "{:?}", scan.damaged);
    assert_eq!(scan.end, Some(ScanEnd::Eof));
}
