//! Fuzzes both parsers of a shard file's header page (ARCHITECTURE.md
//! §17.2.2): the engine's `stripe::parse_descriptor_page` and fsck's
//! `stripes::parse_shard_page`, plus `descriptor_is_sane` on whatever
//! comes out. Corrupt or hostile bytes must produce `None`/`false`,
//! never a panic. The two parsers are deliberately separate code; they
//! are fuzzed together so a divergence (one accepts what the other
//! rejects) shows up as a crash here too.
//!
//!   cargo +nightly fuzz run shard_page

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A page is 4 KiB; short inputs are padded so the fuzzer can reach
    // the header and descriptor fields without first guessing a length.
    let mut page = data.to_vec();
    if page.len() < 4096 {
        page.resize(4096, 0);
    }
    let data = page.as_slice();
    let engine = lchfs_store::stripe::parse_descriptor_page(data);
    let fsck = lchfs_fsck::stripes::parse_shard_page(data).map(|(_, d)| d);
    assert_eq!(engine, fsck, "the engine and fsck disagree on a shard page");
    if let Some(d) = engine {
        let _ = lchfs_store::stripe::descriptor_is_sane(&d);
    }
});
