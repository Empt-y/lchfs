//! Pool/vdev identity in the superblock (ARCHITECTURE.md §15.6), and the
//! refusal of pre-v3 pools.
//!
//! The refusal matters more than it looks. A v2 slot cannot decode as v3, and
//! the natural handling -- skip the slot as invalid -- would leave a real v2
//! pool looking *empty*. `Pool::create` treats "no valid superblock" as
//! "nothing here" and proceeds, so a silent skip would let it overwrite an
//! existing pool's superblock. These tests pin that it refuses instead.

use lchfs_format::{
    ExtentLocation, Hash32, PoolParams, SuperblockSlotV2, SuperblockStats, SUPERBLOCK_MAGIC,
    SUPERBLOCK_SLOT_COUNT, SUPERBLOCK_SLOT_SIZE,
};
use lchfs_store::Pool;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

/// Writes a pre-v3 slot into slot 0 with the documented framing:
/// `[u32 LE encoded_len][bincode(SuperblockSlotV2)][zero pad to 4 KiB]`.
fn write_legacy_v2_superblock(pool_root: &std::path::Path) {
    let legacy = SuperblockSlotV2 {
        magic: SUPERBLOCK_MAGIC,
        format_version: 2,
        generation: 7,
        root_hash: Hash32([1u8; 32]),
        root_location: ExtentLocation { segment_id: 0, offset: 4096, len: 64 },
        index_generation: 7,
        committed_at_unix_nanos: 0,
        stats: SuperblockStats::default(),
        header_checksum: 0,
    };
    let encoded = lchfs_format::encode(&legacy).unwrap();
    // Full-size ring, not just one slot: `FileBackend::open` extends a short
    // SUPERBLOCK to the full ring, which would otherwise make the
    // before/after byte comparison below fail on length rather than content.
    let mut buf = vec![0u8; SUPERBLOCK_SLOT_SIZE * SUPERBLOCK_SLOT_COUNT as usize];
    buf[0..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    buf[4..4 + encoded.len()].copy_from_slice(&encoded);

    lchfs_device::format(pool_root, Default::default()).unwrap();
    lchfs_store::testing::write_ring(pool_root, 0, &buf);
}

#[test]
fn a_fresh_pool_gets_a_nonzero_uuid_and_single_vdev_identity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let slot = lchfs_fsck::read_superblock(dir.path()).unwrap();
    assert_ne!(slot.pool_uuid, [0u8; 16], "pool_uuid was never generated");
    assert_eq!(slot.vdev_id, 0);
    assert_eq!(slot.vdev_count, 1);
    assert_eq!(slot.format_version, lchfs_format::FORMAT_VERSION);
}

/// A checkpoint must rewrite the identity it read, never mint a new one --
/// otherwise a pool would stop matching its own vdevs on the second mount.
#[test]
fn pool_uuid_survives_reopen_and_further_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);
    let first = lchfs_fsck::read_superblock(dir.path()).unwrap().pool_uuid;

    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"hello").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let second = lchfs_fsck::read_superblock(dir.path()).unwrap().pool_uuid;
    assert_eq!(first, second, "checkpoint minted a new pool_uuid");
}

#[test]
fn two_pools_get_different_uuids() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for d in [a.path(), b.path()] {
        let p = Pool::create(d, small_params()).unwrap();
        p.checkpoint().unwrap();
    }
    let ua = lchfs_fsck::read_superblock(a.path()).unwrap().pool_uuid;
    let ub = lchfs_fsck::read_superblock(b.path()).unwrap().pool_uuid;
    assert_ne!(ua, ub, "two pools share a uuid; identity is not unique");
}

/// The data-loss guard: a v2 pool must be *refused*, not mistaken for empty.
#[test]
fn a_v2_pool_is_refused_by_open_rather_than_looking_empty() {
    let dir = tempfile::tempdir().unwrap();
    write_legacy_v2_superblock(dir.path());
    let err = Pool::open(dir.path()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("format version 2"),
        "expected an explicit legacy-format refusal, got: {msg}"
    );
}

/// The more dangerous half: `create` must not treat a v2 pool as a free
/// location and overwrite its superblock.
#[test]
fn a_v2_pool_is_not_overwritten_by_create() {
    let dir = tempfile::tempdir().unwrap();
    write_legacy_v2_superblock(dir.path());
    let before = lchfs_store::testing::read_ring(dir.path());

    let err = Pool::create(dir.path(), small_params()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("format version 2"),
        "expected a legacy-format refusal, got: {msg}"
    );

    let after = lchfs_store::testing::read_ring(dir.path());
    assert_eq!(before, after, "create clobbered an existing v2 pool's superblock");
}

/// fsck reports the same thing, via its own independent reader.
#[test]
fn fsck_also_refuses_a_v2_pool() {
    let dir = tempfile::tempdir().unwrap();
    write_legacy_v2_superblock(dir.path());
    let err = lchfs_fsck::read_superblock(dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("format version 2"),
        "fsck did not report the legacy format: {err}"
    );
}

/// `Vdev` describes a *device root*, not a file inside one (§15.10). It used
/// to hold the SUPERBLOCK file path, which made the type quietly wrong about
/// what a vdev is -- and that wrongness was part of what made §8's
/// "`Vec<Vdev>`-shaped from day one" claim look true when it wasn't.
#[test]
fn a_backend_knows_which_vdev_root_it_belongs_to() {
    use lchfs_store::backend::{FileBackend, Vdev};

    let dir = tempfile::tempdir().unwrap();
    let backend = FileBackend::open(dir.path()).unwrap();

    assert_eq!(backend.root(), dir.path(), "a backend is its device's");
    // A backend is opened before the superblock is read, so it knows the
    // root and not the slot; the slot is the Vdev's to carry.
    assert_eq!(Vdev::new(3, dir.path().to_path_buf()).id, 3);
}
