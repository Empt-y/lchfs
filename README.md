# LCHFS — Log-Structured Cryptographic Hash File System

A from-scratch filesystem built around content-addressed, log-structured storage: every chunk's BLAKE3 hash doubles as its Merkle DAG pointer, its integrity check, and its dedup key. See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design — on-disk format, write/read paths, concurrency model, crash recovery, and the reasoning behind every decision.

## Status

Phases A–E are done: the engine mounts via FUSE3, supports the full Phase 1 POSIX surface (§9 of `ARCHITECTURE.md`) — read/write/mkdir/unlink/rmdir/rename/symlink/link/statfs — with concurrent multi-shard ingress, background GC/coalesce/dedup daemons, and crash recovery. Phase F (verification tooling) is in progress: `lchfs-fsck` and `lchfs-testkit` are real, and a fuzz target now covers the Extent Record header parser; `criterion` benchmarks aren't set up yet.

## Build

```sh
cargo build
```

## Roadmap

Implementation order (§12 of `ARCHITECTURE.md`) — all crates are already scaffolded; this is build sequence, not scope:

- [x] **Phase A** — `lchfs-crypto`, `lchfs-format`: on-disk schema + round-trip proptests
- [x] **Phase B** — `lchfs-store` (single-threaded): segment writer, superblock rotation, basic checkpoint
- [x] **Phase C** — `lchfs-index` (redb-backed): inline dedup-on-write
- [x] **Phase D** — `lchfs-fuse` + `lchfs-cli mount`: first real `cp`/`ls`/`cat` end-to-end
- [x] **Phase E** — concurrency hardening: M logical shards, work-stealing committer pool, per-shard delta logs, coalescing daemon, dedup scanner, GC
- [ ] **Phase F** — `lchfs-fsck` ✅, `lchfs-testkit` ✅, fuzzing ✅ (Extent Record header parser), crash-injection harness ✅ (superblock-scoped), `criterion` benchmarks ⬜
- [ ] **Phase G** — snapshots, multi-root GC validation, `Vdev`/`StorageBackend` extension points

## Fuzzing

`fuzz/` is a separate, self-contained cargo-fuzz project (its own `[workspace]`, not a member of the main one — fuzz targets need nightly-only sanitizer instrumentation the main crates must never be built with). It targets `lchfs_store::segment::parse_record_header`, the Extent Record header parser ARCHITECTURE.md §10 calls out: it must never panic on adversarial bytes, only return `None`.

Requires a nightly toolchain and `cargo-fuzz`, independent of whatever toolchain builds the main workspace (this repo's CI/dev toolchain is stable-only). Via `rustup` (kept separate from a distro-packaged stable toolchain — doesn't need to be, and shouldn't become, your default):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run extent_header           # runs until you Ctrl-C
cargo +nightly fuzz run extent_header -- -max_total_time=60   # bounded run
```

## Layout

```
crates/
  lchfs-crypto/     BLAKE3 + CRC32C
  lchfs-chunk/      FastCDC content-defined chunking
  lchfs-compress/   adaptive zstd
  lchfs-format/     on-disk schema (superblock, extent records, Merkle DAG objects)
  lchfs-index/      persisted hash index (redb-backed)
  lchfs-store/      the engine — segments, ingress, checkpointing, GC
  lchfs-fuse/       FUSE3 frontend (fuser)
  lchfs-fsck/       DAG-walk verification
  lchfs-cli/        create-pool / mount / fsck / snapshot commands
  lchfs-testkit/    reference model + proptest generators (dev-only)
```
