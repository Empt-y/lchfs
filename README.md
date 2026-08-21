# LCHFS — Log-Structured Cryptographic Hash File System

A FUSE3 filesystem where every chunk of every file is content-addressed: its BLAKE3 hash is simultaneously its pointer in a Merkle DAG, its integrity check, and its dedup key. Nothing is ever overwritten in place — writes append to log-structured segments, and a small ring of self-checksummed superblocks tracks the current root, so the filesystem needs no journal and no replay to recover from a crash.

## How it works

- **Write**: incoming bytes are split into content-defined chunks (FastCDC), each chunk is hashed with BLAKE3, checked against a dedup index, optionally compressed, and appended to a log segment. Parent objects (inode → directory → root) are rebuilt bottom-up and fsync'd in dependency order, so a crash can never leave a parent pointing at unwritten data.
- **Read**: a directory entry resolves to an inode number, which resolves through an index to the file's current object hash, which resolves to a chunk list; each chunk is read, decompressed, and its hash re-verified against the DAG before being returned.
- **Concurrency**: writes are routed by inode ID into one of many independent logical shards (each with its own ring buffer and log), serviced by a small pool of worker threads that steal work from busy shards. No global lock is ever taken on the write path.
- **Space reclamation**: a background mark-and-sweep walks every live root (current tree + all retained snapshots) and copies forward only the chunks still referenced, repacking sparse segments as it goes. Because relocation never changes a chunk's hash, nothing else in the DAG has to be rewritten when GC moves data.

## What's different from ext4 / NTFS / ZFS

| | LCHFS |
|---|---|
| **Allocation** | Log-structured, append-only — no in-place block allocator |
| **Concurrency** | Lockless, sharded by inode across independent ingress rings — no global VFS/allocation lock |
| **Integrity** | Cryptographic hash (BLAKE3) is the addressing scheme itself, not a bolted-on checksum — a chunk simply *is* its hash |
| **Dedup** | Free side effect of content-addressing, not a separate scan-and-merge pass |
| **Snapshots** | A snapshot is one entry in a table pointing at an existing root — no copy, no special-cased deletion path |
| **Hardlinks** | Free — two directory entries pointing at the same inode number, zero data touched |

## Nerd stats

| | |
|---|---|
| Hash function | BLAKE3-256 (32-byte digest), doubles as the DAG pointer, integrity check, and dedup key |
| Chunking | FastCDC, content-defined boundaries — avg 64 KiB / min 16 KiB / max 256 KiB (tunable per pool) |
| Inline threshold | Files ≤ 512 B live directly in the inode object, no chunking or dedup (default, tunable) |
| Chunk address fan-out | 64K chunk refs per `IndirectHashList`, double-indirect beyond that → ~4.3 billion (2³²) addressable chunks per file |
| **Max file size** | **~256 TiB** at default chunk size, up to **1 PiB** at max chunk size — set by the double-indirect fan-out cap above |
| **Max pool/drive size** | No format-imposed ceiling — segment and offset fields are 64-bit; bounded only by the backing storage |
| Segment size | 128 MiB (data) / 16 MiB (metadata) default, configurable at pool creation |
| Superblock | 64 KiB ring, 16 × 4 KiB slots, atomically rotated — recovery = highest-generation CRC-valid slot, no journal |
| Logical write shards | 256–1024 (configurable), deliberately far exceeds core count for even load spread |
| Compression | Adaptive zstd — samples ~10% of each chunk, compresses the full chunk only if the sample shows ≥10% reduction |
| Checkpoint interval | Every 5s by default, or on `fsync()`, ring backpressure, or unmount |
| Crash recovery | Zero-replay base case; bounded, idempotent per-shard delta-log replay when the fast `fsync()` path has been used |

## Build

```sh
cargo build
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
