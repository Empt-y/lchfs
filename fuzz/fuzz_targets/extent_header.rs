//! Fuzzes `lchfs_store::segment::parse_record_header` -- "the Extent
//! Record header parser" ARCHITECTURE.md §10 calls out: must never panic
//! on corrupted/adversarial bytes, only return `None`. See that
//! function's doc comment (crates/lchfs-store/src/segment.rs) for exactly
//! what it does and doesn't validate.
//!
//! Run with (needs the nightly toolchain cargo-fuzz itself requires):
//!   cargo +nightly fuzz run extent_header
//!
//! A crash here means `parse_record_header` panicked or the process
//! aborted (e.g. OOM from an unbounded allocation) on some byte sequence
//! that must instead have produced a clean `None`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lchfs_store::segment::parse_record_header(data);
});
