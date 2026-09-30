//! Fuzzes what an encrypted pool does with a record *after* its envelope
//! authenticates: `RecordCrypto::open`'s inner-header decode and length
//! checks, then the store's decompress and keyed content-hash check
//! (`verify_record_with`). The fuzzer's bytes are sealed with the real key
//! as the inner plaintext, so they get past the AEAD -- which the fixed-key
//! `envelope_open` target never does. The first byte picks a mode:
//!
//!   even: the rest is the inner plaintext;
//!   odd:  a valid sealed record of the rest's bytes is built, and the
//!         next bytes name outer-header bytes to flip -- which must always
//!         be refused (the whole outer header is bound into the AEAD).
//!
//! Neither may panic.
//!
//!   cargo +nightly fuzz run sealed_inner seeds/sealed_inner

#![no_main]

use lchfs_crypto::Key32;
use lchfs_crypto::epoch::EpochKeys;
use lchfs_crypto::keyring::Padding;
use lchfs_format::{CodecId, ExtentKind, Hash32, RecordCrypto};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn crypto() -> &'static RecordCrypto {
    static C: OnceLock<RecordCrypto> = OnceLock::new();
    C.get_or_init(|| {
        RecordCrypto::new([3; 16], 1, 1, Padding::Padme, vec![EpochKeys::derive(1, &Key32::from_bytes([7; 32]))])
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let crypto = crypto();
    if mode % 2 == 0 {
        let hash = Hash32::of(rest);
        let (header, envelope) = crypto.seal_inner_for_fuzzing(1, hash, rest);
        let _ = lchfs_store::segment::verify_record_with(&header, envelope, 1, 0, crypto);
        return;
    }
    // Split: flips (pairs of index, xor) up to the first 0xFF, then content.
    let split = rest.iter().position(|&b| b == 0xFF).unwrap_or(rest.len());
    let (flips, content) = (&rest[..split], rest.get(split + 1..).unwrap_or(&[]));
    let (_, hash) = crypto.address(content);
    let (header, envelope) = crypto.seal(1, ExtentKind::RawChunk, hash, CodecId::None, content.len() as u32, content, Vec::new());
    let mut outer = lchfs_format::encode(&header).unwrap();
    let mut flipped = false;
    for pair in flips.chunks_exact(2) {
        let i = pair[0] as usize % outer.len();
        if pair[1] != 0 {
            outer[i] ^= pair[1];
            flipped = true;
        }
    }
    let Ok(tampered) = lchfs_format::decode::<lchfs_format::ExtentRecordHeader>(&outer) else { return };
    let result = crypto.open(&tampered, envelope);
    if flipped && tampered != header {
        // The CRC is not what protects a sealed header; the AEAD is. A
        // changed header either fails to open or -- if the change only
        // touched the checksum, which the AEAD deliberately excludes --
        // opens to exactly the original content.
        let only_checksum = {
            let mut a = tampered.clone();
            a.header_checksum = header.header_checksum;
            a == header
        };
        if !only_checksum {
            assert!(result.is_err(), "a sealed record opened under a changed outer header");
        }
    } else {
        assert_eq!(result.expect("an untouched record opens").payload, content);
    }
});
