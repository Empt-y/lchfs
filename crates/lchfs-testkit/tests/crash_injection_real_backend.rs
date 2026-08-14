//! Validates `CrashInjectingBackend` against the *real* `FileBackend` and
//! the real on-disk superblock wire format -- the unit tests in
//! `crash_backend.rs` only exercise it against a toy in-memory backend.
//! Uses `lchfs_fsck::read_superblock` (a from-scratch reader, independent
//! of `lchfs-store`'s own private one) to confirm what actually survives.

use lchfs_format::{ExtentLocation, Hash32, SuperblockStats, SUPERBLOCK_SLOT_SIZE, SuperblockSlot, finalize_superblock_slot_checksum};
use lchfs_store::backend::FileBackend;
use lchfs_store::StorageBackend;
use lchfs_testkit::CrashInjectingBackend;

fn slot(generation: u64) -> SuperblockSlot {
    let mut slot = SuperblockSlot {
        magic: lchfs_format::SUPERBLOCK_MAGIC,
        format_version: lchfs_format::FORMAT_VERSION,
        generation,
        root_hash: Hash32::of(generation.to_le_bytes().as_slice()),
        root_location: ExtentLocation { segment_id: 0, offset: 4096, len: 64 },
        index_generation: generation,
        committed_at_unix_nanos: 0,
        stats: SuperblockStats::default(),
        header_checksum: 0,
    };
    finalize_superblock_slot_checksum(&mut slot);
    slot
}

/// Same wire format as `lchfs-store`'s own (private) `write_superblock_slot`:
/// `[u32 LE encoded_len][bincode(SuperblockSlot)][zero padding to 4KiB]`.
fn write_slot(backend: &impl StorageBackend, slot: &SuperblockSlot) {
    let slot_idx = slot.generation % lchfs_format::SUPERBLOCK_SLOT_COUNT as u64;
    let encoded = lchfs_format::encode(slot).unwrap();
    let mut buf = vec![0u8; SUPERBLOCK_SLOT_SIZE];
    buf[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    buf[4..4 + encoded.len()].copy_from_slice(&encoded);
    backend.write_at(slot_idx * SUPERBLOCK_SLOT_SIZE as u64, &buf).unwrap();
}

#[test]
fn crash_mid_superblock_commit_keeps_the_previous_generation() {
    let dir = tempfile::tempdir().unwrap();
    let backend = CrashInjectingBackend::new(FileBackend::open(dir.path()).unwrap());

    write_slot(&backend, &slot(1));
    backend.fsync().unwrap();

    // A second commit starts but never gets fsync'd -- simulating a crash
    // exactly mid-write of the next superblock slot.
    write_slot(&backend, &slot(2));
    backend.inject_crash();
    drop(backend);

    let recovered = lchfs_fsck::read_superblock(dir.path()).unwrap();
    assert_eq!(recovered.generation, 1, "must recover the last fsync'd generation, not the torn one");
}

#[test]
fn crash_after_fsync_keeps_the_new_generation() {
    let dir = tempfile::tempdir().unwrap();
    let backend = CrashInjectingBackend::new(FileBackend::open(dir.path()).unwrap());

    write_slot(&backend, &slot(1));
    backend.fsync().unwrap();
    write_slot(&backend, &slot(2));
    backend.fsync().unwrap();

    backend.inject_crash();
    drop(backend);

    let recovered = lchfs_fsck::read_superblock(dir.path()).unwrap();
    assert_eq!(recovered.generation, 2);
}
