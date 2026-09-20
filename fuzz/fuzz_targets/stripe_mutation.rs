//! Structured fuzzing of a real stripe: one 2+1 stripe of a sealed
//! segment is built once; each input is a list of (shard, offset, xor)
//! mutations applied to fresh copies of the three shard files, plus a
//! byte that may truncate one. Then everything that reads a stripe is
//! driven over the result -- the engine's `StripeReader` (open, verify,
//! read every record, reconstruct every shard, `verified_body`) and
//! fsck's `scan_stripes` -- and where both succeed at reading a record
//! they must agree with the original. Nothing may panic, whatever the
//! descriptor says.
//!
//!   cargo +nightly fuzz run stripe_mutation

#![no_main]

use arbitrary::Arbitrary;
use lchfs_format::{CodecId, ExtentKind, ExtentLocation, Hash32, StreamKind};
use lchfs_store::backend::Vdev;
use lchfs_store::segment::{SEGMENT_HEADER_PAGE_SIZE, SegmentReader, SegmentWriter};
use lchfs_store::stripe::{StripeReader, shard_path, write_stripe};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Arbitrary, Debug)]
struct Mutation {
    shard: u8,
    offset: u16,
    xor: u8,
    run: u8,
}

#[derive(Arbitrary, Debug)]
struct Input {
    mutations: Vec<Mutation>,
    truncate_shard: u8,
    truncate_to: u16,
}

struct Fixture {
    /// The pristine shard files, by index.
    shards: Vec<Vec<u8>>,
    records: Vec<(ExtentLocation, Vec<u8>)>,
    work: PathBuf,
    /// Kept so the directory lives as long as the fixture (and so the
    /// leak checker has nothing to say).
    _dir: tempfile::TempDir,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        lchfs_store::backend::FileBackend::open(&src).unwrap();
        let mut w = SegmentWriter::create(&[&src], 7, StreamKind::Data, 0).unwrap();
        let mut records = Vec::new();
        for i in 0..24u32 {
            let len = 700 + (i as usize * 613) % 3000;
            let payload: Vec<u8> = (0..len as u32).map(|j| ((j ^ i.wrapping_mul(7919)).wrapping_mul(2654435761) >> 13) as u8).collect();
            let loc = w.append(ExtentKind::RawChunk, Hash32::of(&payload), CodecId::None, len as u32, &payload, Vec::new()).unwrap();
            records.push((loc, payload));
        }
        w.seal().unwrap();
        let mut body = std::fs::read(src.join("segments/data/7.aseg")).unwrap();
        body.drain(..SEGMENT_HEADER_PAGE_SIZE as usize);
        let devs: Vec<Vdev> = (0..3)
            .map(|i| {
                let root = dir.path().join(format!("d{i}"));
                lchfs_store::backend::FileBackend::open(&root).unwrap();
                Vdev::new(i, root)
            })
            .collect();
        write_stripe(&body, 7, 2, 1, &devs).unwrap();
        let shards = (0..3).map(|i| std::fs::read(shard_path(&devs[i as usize].root, 7, i)).unwrap()).collect();
        let work = dir.path().join("work");
        for i in 0..3 {
            let root = work.join(format!("d{i}"));
            lchfs_store::backend::FileBackend::open(&root).unwrap();
            std::fs::create_dir_all(root.join("segments/data")).unwrap();
        }
        Fixture { shards, records, work, _dir: dir }
    })
}

fuzz_target!(|input: Input| {
    let f = fixture();
    let mut shards = f.shards.clone();
    for m in input.mutations.iter().take(64) {
        let s = &mut shards[(m.shard % 3) as usize];
        let start = (m.offset as usize) % s.len();
        let end = (start + 1 + (m.run as usize % 64)).min(s.len());
        for x in &mut s[start..end] {
            *x ^= m.xor;
        }
    }
    if input.truncate_shard < 3 {
        let s = &mut shards[input.truncate_shard as usize];
        let to = (input.truncate_to as usize) % (s.len() + 1);
        s.truncate(to);
    }
    let devs: Vec<Vdev> = (0..3).map(|i| Vdev::new(i, f.work.join(format!("d{i}")))).collect();
    for (i, bytes) in shards.iter().enumerate() {
        std::fs::write(shard_path(&devs[i].root, 7, i as u8), bytes).unwrap();
    }

    // Engine.
    let root_of = |id: u16| devs.iter().find(|d| d.id == id).map(|d| d.root.clone());
    if let Ok(reader) = StripeReader::open(7, root_of, &devs) {
        for i in 0..3u8 {
            let _ = reader.verify_shard(i);
            let _ = reader.reconstruct_shard(i);
        }
        let _ = reader.verified_body();
        for (loc, payload) in &f.records {
            let _ = reader.reconstructs(*loc);
            if let Ok((_, bytes)) = reader.read_record(*loc) {
                assert_eq!(&bytes, payload, "a record that verifies must be the original");
            }
            let _ = reader.read_record_raw(*loc);
        }
    }

    // fsck, given every device.
    let given: Vec<(u16, &std::path::Path)> = devs.iter().map(|d| (d.id, d.root.as_path())).collect();
    let scan = lchfs_fsck::stripes::scan_stripes(&given);
    if let Some(stripe) = scan.stripes.get(&7) {
        for (loc, payload) in &f.records {
            if let Ok(bytes) = stripe.read_record(*loc) {
                assert_eq!(&bytes, payload, "fsck read a record that verifies but is not the original");
            }
        }
    }
    let _ = lchfs_fsck::stripes::rebuild_shards(&given, &scan);
    let _ = SegmentReader::open(&devs[0].root, 7, StreamKind::Data);
});
