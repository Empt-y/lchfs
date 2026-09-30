//! `segment_file` for an encrypted pool: the bytes are written as a data
//! segment and every reader path is driven over it with a `RecordCrypto`
//! holding the key the seeds were sealed with -- the resyncing scan, a
//! verifying read of each record found (AEAD open, inner decode,
//! decompress, keyed hash), a raw read, and the orphan reopen. None may
//! panic, and a record that reads back must be what its keyed address
//! says it is.
//!
//!   cargo +nightly fuzz run sealed_segment seeds/sealed_segment -- -max_len=131072

#![no_main]

use lchfs_crypto::Key32;
use lchfs_crypto::epoch::EpochKeys;
use lchfs_crypto::keyring::Padding;
use lchfs_format::{ExtentLocation, RecordCrypto, StreamKind};
use lchfs_store::segment::{SegmentReader, SegmentWriter};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Must match `write_sealed_fuzz_seeds` in lchfs-store's tests.
fn crypto() -> &'static RecordCrypto {
    static C: OnceLock<RecordCrypto> = OnceLock::new();
    C.get_or_init(|| {
        RecordCrypto::new([3; 16], 1, 1, Padding::Padme, vec![EpochKeys::derive(1, &Key32::from_bytes([7; 32]))])
    })
}

fn root() -> &'static std::path::Path {
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        lchfs_store::backend::FileBackend::open(dir.path()).unwrap();
        dir
    })
    .path()
}

fuzz_target!(|data: &[u8]| {
    let root = root();
    let crypto = crypto();
    let mut file = data.to_vec();
    if file.len() < 4096 {
        file.resize(4096, 0);
    }
    lchfs_store::testing::write_segment(root, lchfs_store::testing::SegmentKind::Data, 1, &file);
    let Ok(reader) = SegmentReader::open(root, 1, StreamKind::Data) else { return };
    let _ = reader.read_header();
    let mut scan = reader.scan();
    let mut records = Vec::new();
    for (header, offset) in &mut scan {
        records.push(ExtentLocation { segment_id: 1, offset, len: header.record_len });
    }
    for loc in records {
        if let Ok((header, bytes)) = reader.read_record_with(loc, crypto) {
            let epoch = lchfs_format::record_epoch(&header);
            assert!(crypto.verify(epoch, &bytes, header.content_hash).is_ok(), "a record read back as something else");
        }
        let _ = reader.read_record_raw_with(loc, crypto);
    }
    let vdev = lchfs_store::backend::Vdev::new(0, root.to_path_buf());
    for (writer, _records) in SegmentWriter::reopen_open_replicas(&[vdev], 1, StreamKind::Data) {
        let _ = writer.seal();
    }
});
