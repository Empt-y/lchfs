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

## Encryption

Native, per-pool encryption, built in milestones. The design is
in ARCHITECTURE.md §18; the short version:

- **Content:** each chunk is addressed by a *keyed* BLAKE3 hash and sealed
  with XChaCha20-Poly1305 (random 192-bit nonce). Dedup still works
  within a pool. Without the key you can't tell whether the pool holds a
  given file, and nothing is shared across pools. Record sizes are
  Padmé-padded. All metadata (names, sizes, tree shape, xattrs) is
  encrypted too.
- **Keys:** a LUKS-style keyring on every device. A keyring key wraps
  each epoch's content key, and slots wrap the keyring key. There are
  three slot types:
  - **passphrase** (Argon2id);
  - **post-quantum recipient key**: X-Wing, i.e. X25519 + ML-KEM-768
    (FIPS 203), so a copy taken today stays shut against a future
    quantum computer;
  - **TPM2**, sealed to PCRs with an optional PIN.

  A pool always keeps one non-TPM slot.
- **Status:**
  - Milestones 1–4 are on `master`: the crypto core (keyring, slots,
    envelopes, fuzz targets, software-TPM tests in CI), the engine
    integration, the command line, and in-place conversion and key
    rotation.
  - The whole test suite runs twice in CI, once plaintext and once with
    every pool encrypted, and a leakage test checks that no file content,
    name, xattr, symlink target or plaintext content hash reaches the disk.
  - Still to come: memory hardening (mlock, non-dumpable), benchmarks,
    and the full write-up in ARCHITECTURE.md §18.

### Using it

```sh
# A passphrase slot (asked for twice), plus a post-quantum recipient key
# and this machine's TPM with a PIN:
lchfs key generate-recipient ~/.lchfs/recovery      # writes recovery + recovery.pub
lchfs create-pool --encrypt --recipient ~/.lchfs/recovery.pub --tpm --with-pin /pool
lchfs key backup /pool ~/pool-keyring.bak           # keep it: no keyring, no pool

lchfs mount /pool /mnt --tpm --tpm-pin              # or --identity FILE, or a passphrase
lchfs mount /pool /mnt --require-encryption         # refuse a plaintext pool swapped in

lchfs key list /pool                                # needs no key
lchfs key add-passphrase /pool                      # proves with an existing key first
lchfs key revoke 0 /pool                            # remove a slot *and* re-key the keyring
lchfs fsck /pool                                    # asks for a key; without one (or with
                                                    # --structural) checks structure only

lchfs pool encrypt /pool --recipient ~/.lchfs/recovery.pub   # encrypt an existing pool in place
lchfs pool rekey /pool                              # rotate the content key (after a revoke)
lchfs pool encryption-status /pool                  # a mounted pool's conversion progress
```

`pool encrypt` and `pool rekey` work on a mounted pool (the conversion runs
in the background while it stays in use) or an unmounted one (it runs to the
end and prints progress). Either way new writes use the new key at once;
existing content is rewritten; and then the old epoch -- for `encrypt`, the
plaintext -- is removed from every device: data, metadata, delta logs, the
index file and the superblock ring. That last step waits until every device
of the pool is present, since an absent one still holds the old records.
Space the underlying disk's own remapping kept is out of reach; for a
guarantee that no plaintext survives anywhere, create a fresh encrypted
pool and copy into it.

Passphrases never go on the command line: they come from
`--passphrase-file`, `--passphrase-fd`, a no-echo terminal prompt, or an
askpass helper (`LCHFS_ASKPASS`, then `SSH_ASKPASS`). `key` commands on a
mounted pool go through its control socket (owner-only, and every change
must be proven with a key the pool already has); on an unmounted pool they
write every device's keyring directly, under the pool lock.

## Windows

`lchfs-win` mounts a pool as a Windows drive through
[WinFsp](https://winfsp.dev), the Windows counterpart of FUSE: WinFsp's
signed kernel driver does the kernel side, and `lchfs-win` is the
user-mode file system it talks to, running the same engine as Linux.

```bat
:: Install WinFsp first (https://winfsp.dev/rel/), then:
cargo build --release -p lchfs-winfsp

lchfs-win create-pool D:\pool --encrypt      :: asks for a passphrase twice
lchfs-win mount D:\pool                      :: next free drive letter, Z: down
lchfs-win mount D:\pool L: --read-only
lchfs-win mount D:\pool C:\mnt\pool         :: a folder that does not exist yet
lchfs-win mount D:\pool --identity recovery  :: or --passphrase-file FILE
```

Ctrl+C, or closing the window, unmounts after a final checkpoint. A pool
is an ordinary directory, so one kept on an NTFS drive (which Linux reads
and writes too) mounts on either system -- one at a time; the pool lock
refuses a second mount. Keep Windows-side pools off FAT and exFAT: they
cannot drop a file's name while it is still open, which holds up the last
step of `pool encrypt`/`pool rekey` (removing the old key's segments).

How Windows sees a pool:

- **Names** match regardless of case, and keep the case they were created
  with. An exact match wins, so two names that differ only in case (made
  on Linux) both still open.
- **Symlinks** are Windows symlinks, followed by Windows itself; Explorer
  deletes a link to a folder without touching the folder. `mklink` works
  for relative targets (and needs Developer Mode or an elevated prompt,
  as it does on NTFS).
- **Attributes** come from the Unix mode: a file with no owner-write bit
  is read-only, and setting or clearing read-only changes the write bits.
  Names starting with a dot are hidden.
- **Permissions** are not mapped to ACLs: every file grants full access
  to everyone, as on a FAT drive. New files take the owner of their
  folder, so a pool shared with Linux stays writable by its owner there.

Not on Windows yet: TPM key slots, multi-device pools (`--vdev`/`--scan`),
and the `key`/`pool`/`snapshot` commands -- use the Linux CLI for those.

## Build

```sh
cargo build
```

## Layout

```
crates/
  lchfs-crypto/     BLAKE3 + CRC32C, record envelopes, keyring and key slots
  lchfs-chunk/      FastCDC content-defined chunking
  lchfs-compress/   adaptive zstd
  lchfs-format/     on-disk schema (superblock, extent records, Merkle DAG objects)
  lchfs-index/      persisted hash index (redb-backed)
  lchfs-store/      the engine — segments, ingress, checkpointing, GC
  lchfs-fuse/       FUSE3 frontend (fuser)
  lchfs-winfsp/     Windows frontend (WinFsp) and the lchfs-win command
  lchfs-fsck/       DAG-walk verification
  lchfs-cli/        create-pool / mount / fsck / snapshot / key commands
  lchfs-testkit/    reference model + proptest generators (dev-only)
```
