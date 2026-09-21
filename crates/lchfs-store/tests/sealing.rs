//! When a data segment gets sealed (ARCHITECTURE.md §17.3): at the cap,
//! as always; when it has gone idle, at a checkpoint; at a clean
//! shutdown; and at the next mount if a crash left it open. Only a sealed
//! segment is ever swept, coalesced or striped, so a segment nobody seals
//! is data every daemon ignores for the life of the pool.

use lchfs_format::{PoolParams, SegmentState, StreamKind};
use lchfs_store::Pool;
use lchfs_store::segment::SegmentReader;
use lchfs_store::stripe::segment_ids_with_shards;
use std::path::Path;
use std::time::Duration;

fn params(stripe: bool) -> PoolParams {
    PoolParams {
        // Far above anything these tests write: nothing seals at the cap.
        data_segment_cap_bytes: 8 * 1024 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
        stripe_k: if stripe { 2 } else { 0 },
        stripe_m: if stripe { 1 } else { 0 },
        stripe_min_age_segments: 0,
    }
}

fn payload(seed: u32) -> Vec<u8> {
    (0..30_000u32)
        .map(|i| ((i ^ seed).wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn read_file(pool: &Pool, name: &str, len: usize) -> Vec<u8> {
    let ino = pool.lookup(1, name).unwrap().expect(name);
    pool.read(ino, 0, len as u32).unwrap().to_vec()
}

/// `(segment id, state, file size)` for every data segment on a device.
fn data_segments(root: &Path) -> Vec<(u64, SegmentState, u64)> {
    segments(root, StreamKind::Data)
}

fn segments(root: &Path, kind: StreamKind) -> Vec<(u64, SegmentState, u64)> {
    let (sub, ext) = match kind {
        StreamKind::Data => ("data", "aseg"),
        StreamKind::Meta => ("meta", "mseg"),
        StreamKind::Delta => unreachable!(),
    };
    let mut out: Vec<_> = std::fs::read_dir(root.join("segments").join(sub))
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == ext))
                .map(|e| {
                    let id: u64 = e.path().file_stem().unwrap().to_str().unwrap().parse().unwrap();
                    let state = SegmentReader::open(root, id, kind)
                        .unwrap()
                        .read_header()
                        .unwrap()
                        .state;
                    (id, state, e.metadata().unwrap().len())
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|(id, _, _)| *id);
    out
}

fn write_files(pool: &Pool, n: u32) {
    write_files_from(pool, 0, n);
}

fn write_files_from(pool: &Pool, from: u32, n: u32) {
    for i in from..from + n {
        let ino = pool.create_file(1, &format!("f{i}"), 0o644).unwrap();
        pool.write(ino, 0, &payload(i)).unwrap();
    }
    pool.checkpoint().unwrap();
}

#[test]
fn a_clean_shutdown_seals_every_data_segment_and_leaves_no_empty_files() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], params(false)).unwrap();
        write_files(&pool, 8);
        // Below the cap and not idle: still open while mounted.
        assert!(data_segments(a.path()).iter().any(|(_, s, _)| *s == SegmentState::Open));
    }
    for root in [a.path(), b.path()] {
        let segments = data_segments(root);
        assert!(!segments.is_empty());
        for (id, state, len) in &segments {
            assert_eq!(*state, SegmentState::Sealed, "segment {id} on {}", root.display());
            assert!(*len > 4096, "segment {id} holds records, not just a header page");
        }
    }
    // Segments are created on first use: a mount that wrote nothing to
    // most shards left no file for them.
    assert!(data_segments(a.path()).len() <= 4);
    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    for i in 0..8u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
}

/// The meta stream has the same lifecycle as the data stream: its
/// segment is created by the first object written, sealed at a clean
/// shutdown, and a mount that writes no meta object leaves no meta
/// segment behind. A mount used to open one eagerly and leave the empty
/// header page for the next mount to remove, and never sealed the one
/// it had written at shutdown; a pool mounted and unmounted daily grew
/// an Open segment a day for the next mount to clean up.
#[test]
fn a_clean_shutdown_seals_the_meta_segment_and_an_idle_mount_leaves_none() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    {
        let pool = Pool::create_replicated(&[a.path(), b.path()], params(false)).unwrap();
        write_files(&pool, 4);
    }
    let after_first = segments(a.path(), StreamKind::Meta);
    assert!(!after_first.is_empty());
    for root in [a.path(), b.path()] {
        for (id, state, len) in segments(root, StreamKind::Meta) {
            assert_eq!(state, SegmentState::Sealed, "meta segment {id} on {}", root.display());
            assert!(len > 4096, "meta segment {id} holds records, not just a header page");
        }
    }
    // Mount, read, checkpoint (nothing changed, so every object dedups),
    // unmount: not one new meta segment.
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        for i in 0..4u32 {
            assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
        }
        pool.checkpoint().unwrap();
    }
    assert_eq!(segments(a.path(), StreamKind::Meta), after_first);
    assert_eq!(segments(b.path(), StreamKind::Meta), after_first);
    // And a mount that does write meta seals what it wrote when it goes.
    {
        let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
        write_files_from(&pool, 4, 2);
    }
    let after_third = segments(a.path(), StreamKind::Meta);
    assert!(after_third.len() > after_first.len());
    assert!(after_third.iter().all(|(_, s, len)| *s == SegmentState::Sealed && *len > 4096), "{after_third:?}");
    assert_eq!(segments(b.path(), StreamKind::Meta), after_third);
}

#[test]
fn a_segment_left_open_by_a_crash_is_sealed_at_the_next_mount() {
    let a = tempfile::tempdir().unwrap();
    let image = tempfile::tempdir().unwrap();
    let pool = Pool::create(a.path(), params(false)).unwrap();
    write_files(&pool, 6);
    // A crash image: the directory as it is while the pool is open,
    // segments and all still Open. The lock file does not carry over.
    let crashed = image.path().join("a");
    copy_dir(a.path(), &crashed);
    std::fs::remove_file(crashed.join("LOCK")).ok();
    drop(pool);
    assert!(data_segments(&crashed).iter().any(|(_, s, _)| *s == SegmentState::Open), "the image has open segments");

    let pool = Pool::open(&crashed).unwrap();
    for (id, state, _) in data_segments(&crashed) {
        assert_eq!(state, SegmentState::Sealed, "segment {id} sealed at mount");
    }
    for i in 0..6u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    pool.checkpoint().unwrap();
    drop(pool);
    let roots = lchfs_fsck::collect_live_roots(&crashed).unwrap();
    let report = lchfs_fsck::check(&crashed, &roots);
    assert!(report.is_clean(), "{:?}", report.errors);
}

/// The live-run finding behind §17.3: with only the cap sealing
/// segments, a file written once and left alone sits in an Open segment
/// and is never striped. Sealing on idleness makes it cold.
#[test]
fn idle_segments_seal_at_checkpoint_and_only_then_become_cold() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let c = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path(), c.path()], params(true)).unwrap();
    write_files(&pool, 8);
    for _ in 0..3 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    assert!(segment_ids_with_shards(a.path()).is_empty(), "open segments are not cold");

    // Nothing has been idle for an hour; everything has been idle for 0s.
    assert_eq!(pool.seal_idle_segments(Duration::from_secs(3600)).unwrap(), 0);
    let sealed = pool.seal_idle_segments(Duration::ZERO).unwrap();
    assert!(sealed > 0);
    assert!(data_segments(a.path()).iter().all(|(_, s, _)| *s == SegmentState::Sealed));
    // Sealed and past the grace window, they convert.
    write_files_from(&pool, 8, 2);
    pool.seal_idle_segments(Duration::ZERO).unwrap();
    write_files_from(&pool, 10, 2);
    pool.seal_idle_segments(Duration::ZERO).unwrap();
    for _ in 0..3 {
        pool.run_gc_and_coalesce_pass().unwrap();
    }
    assert!(!segment_ids_with_shards(a.path()).is_empty(), "sealed cold segments are striped");
    for i in 0..12u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// One replica's header page rotted must not stop the pool mounting:
/// that replica is left for scrub, the rest is sealed as usual.
#[test]
fn a_rotted_header_page_on_one_replica_does_not_fail_the_mount() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let image = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated(&[a.path(), b.path()], params(false)).unwrap();
    write_files(&pool, 4);
    let (ia, ib) = (image.path().join("a"), image.path().join("b"));
    copy_dir(a.path(), &ia);
    copy_dir(b.path(), &ib);
    drop(pool);
    for root in [&ia, &ib] {
        std::fs::remove_file(root.join("LOCK")).ok();
    }
    let (id, _, _) = data_segments(&ib)[0];
    let p = ib.join(format!("segments/data/{id}.aseg"));
    let mut bytes = std::fs::read(&p).unwrap();
    for x in &mut bytes[..64] {
        *x ^= 0xff;
    }
    std::fs::write(&p, &bytes).unwrap();

    let pool = Pool::open_replicated(&[&ia, &ib]).unwrap();
    for i in 0..4u32 {
        assert_eq!(read_file(&pool, &format!("f{i}"), 30_000), payload(i));
    }
    assert!(data_segments(&ia).iter().all(|(_, s, _)| *s == SegmentState::Sealed));
}
