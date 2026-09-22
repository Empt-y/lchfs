//! Fuzzes the keyring parser and the post-unlock checks behind it.
//!
//! A keyring is read from every device of a pool before anything is
//! trusted, so a damaged or hostile one must only ever be refused: no
//! panic, no unbounded allocation. After `parse` accepts the framing, the
//! target also runs `unlock_with_kk` with a fixed key -- the MAC check and
//! every epoch unwrap -- and a passphrase unlock, which exercises the
//! slot loop and the Argon2 parameter limits (slots asking for more than
//! a small amount of memory are skipped here, only so the fuzzer stays
//! fast; the limits themselves are tested in the crate).
//!
//!   cargo +nightly fuzz run keyring_parse

#![no_main]

use lchfs_crypto::Key32;
use lchfs_crypto::keyring::{SlotKind, Unlock, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(locked) = parse(data) else { return };
    let _ = locked.unlock_with_kk(Key32::from_bytes([0x42; 32]));
    let cheap = locked.body().slots.iter().all(|s| match &s.kind {
        SlotKind::Passphrase(p) => p.m_kib <= 256 && p.t <= 2,
        _ => true,
    });
    if cheap {
        let _ = locked.unlock(&Unlock::Passphrase(b"fuzz"));
    }
});
