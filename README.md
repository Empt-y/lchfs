# LCHFS — Log-Structured Cryptographic Hash File System

A from-scratch filesystem built around content-addressed, log-structured storage: every chunk's BLAKE3 hash doubles as its Merkle DAG pointer, its integrity check, and its dedup key. See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design — on-disk format, write/read paths, concurrency model, crash recovery, and the reasoning behind every decision.

## Status

Scaffold only. Every crate compiles (`cargo build` succeeds) but contains no real logic yet — types, traits, and module structure are in place per `ARCHITECTURE.md` §11, with `// TODO(phase-X)` markers pointing at what to implement and where.

## Build

```sh
cargo build
```

## Roadmap

Implementation order (§12 of `ARCHITECTURE.md`) — all crates are already scaffolded; this is build sequence, not scope:

- [ ] **Phase A** — `lchfs-crypto`, `lchfs-format`: on-disk schema + round-trip proptests
- [ ] **Phase B** — `lchfs-store` (single-threaded): segment writer, superblock rotation, basic checkpoint
- [ ] **Phase C** — `lchfs-index` (redb-backed): inline dedup-on-write
- [ ] **Phase D** — `lchfs-fuse` + `lchfs-cli mount`: first real `cp`/`ls`/`cat` end-to-end
- [ ] **Phase E** — concurrency hardening: M logical shards, work-stealing committer pool, per-shard delta logs, coalescing daemon, dedup scanner, GC
- [ ] **Phase F** — `lchfs-fsck`, `lchfs-testkit`, crash-injection harness, fuzzing, benchmarks
- [ ] **Phase G** — snapshots, multi-root GC validation, `Vdev`/`StorageBackend` extension points

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
