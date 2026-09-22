//! Fuzzes `lchfs_crypto::envelope::open`, which every sealed record and
//! wrapped key read from disk goes through. It must refuse -- never panic
//! -- on any bytes, whatever their length. The first byte picks how much
//! of the input is associated data.
//!
//!   cargo +nightly fuzz run envelope_open

#![no_main]

use lchfs_crypto::Key32;
use lchfs_crypto::envelope::open;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else { return };
    let split = (split as usize).min(rest.len());
    let (aad, envelope) = rest.split_at(split);
    let _ = open(&Key32::from_bytes([7; 32]), aad, envelope);
});
