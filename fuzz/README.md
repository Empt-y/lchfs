# Fuzz targets

Needs the nightly toolchain and `cargo-fuzz` (`~/.cargo/bin`). The corpus
and artifacts directories are local; `seeds/` is committed and is what to
start a fresh corpus from -- the byte-level targets barely move without a
checksummed example to mutate:

    cargo +nightly fuzz build
    cargo +nightly fuzz run segment_file seeds/segment_file -- -max_len=131072
    cargo +nightly fuzz run shard_page seeds/shard_page -- -max_len=8192
    cargo +nightly fuzz run superblock_ring seeds/superblock_ring -- -max_len=131072
    cargo +nightly fuzz run stripe_mutation
    cargo +nightly fuzz run extent_header

| target | what it drives | must hold |
|---|---|---|
| `extent_header` | `parse_record_header` on raw bytes | returns `None`, never panics |
| `shard_page` | the engine's and fsck's shard header-page parsers, `descriptor_is_sane` | both parsers agree; no panic |
| `segment_file` | a whole `.aseg`: header, resyncing scan, verifying reads, orphan reopen + seal | no panic on any rot |
| `superblock_ring` | fsck's ring decoder and `Pool::discover` | no panic; a bad ring is "no pool" |
| `stripe_mutation` | a real 2+1 stripe with structured byte mutations and truncation; engine `StripeReader` and fsck `scan_stripes`/`rebuild_shards` | no panic; any record that verifies equals the original |

`seeds/` were harvested from `stripe_mutation`'s fixture (a sealed segment of
24 records, its three shards' header pages, a device's ring).
