//! Fuzzes a whole segment file: the bytes are written as
//! `segments/data/1.aseg` under a fresh device root and every reader
//! path is driven over it -- header, the resyncing scan (footer or not), a
//! verifying read of each record the scan yields, and the mount-time
//! orphan reopen (which scans and would seal). None may panic on rot.
//!
//!   cargo +nightly fuzz run segment_file

#![no_main]

use lchfs_format::{ExtentLocation, StreamKind};
use lchfs_store::segment::{SegmentReader, SegmentWriter};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn root() -> &'static std::path::Path {
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        lchfs_store::backend::FileBackend::open(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("segments/data")).unwrap();
        dir
    })
    .path()
}

fuzz_target!(|data: &[u8]| {
    let root = root();
    // The header page is 4 KiB; short inputs are padded to it so the
    // fuzzer reaches the header fields, and everything past it is body.
    let mut file = data.to_vec();
    if file.len() < 4096 {
        file.resize(4096, 0);
    }
    std::fs::write(root.join("segments/data/1.aseg"), &file).unwrap();
    let Ok(reader) = SegmentReader::open(root, 1, StreamKind::Data) else { return };
    let _ = reader.read_header();
    let mut scan = reader.scan();
    let mut records = Vec::new();
    for (header, offset) in &mut scan {
        records.push(ExtentLocation { segment_id: 1, offset, len: header.record_len });
    }
    let _ = (&scan.damaged, scan.end);
    for loc in records {
        let _ = reader.read_record(loc);
        let _ = reader.read_record_raw(loc);
    }
    let vdev = lchfs_store::backend::Vdev::new(0, root.to_path_buf());
    for (writer, _records) in SegmentWriter::reopen_open_replicas(&[vdev], 1, StreamKind::Data) {
        let _ = writer.seal();
    }
});
