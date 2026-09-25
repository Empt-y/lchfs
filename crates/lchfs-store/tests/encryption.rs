//! Native encryption (ARCHITECTURE.md §18), tested directly through
//! `Pool::create_encrypted`/`open_with` rather than the `test-encrypt-all`
//! switch other test files rely on transparently -- this file's whole job
//! is to prove the encryption itself, so it drives it explicitly.

use lchfs_crypto::keyring::{NewSlot, Padding, Unlock};
use lchfs_crypto::slots::passphrase::KdfCost;
use lchfs_format::PoolParams;
use lchfs_store::{EncryptionSetup, Pool};
use std::collections::BTreeMap;

const PASSPHRASE: &[u8] = b"correct horse battery staple";
/// Cheap on purpose: this file creates several pools.
const CHEAP: KdfCost = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

fn setup() -> EncryptionSetup<'static> {
    EncryptionSetup {
        padding: Padding::Padme,
        slots: vec![NewSlot::Passphrase {
            passphrase: PASSPHRASE,
            cost: CHEAP,
            label: "test".into(),
        }],
    }
}

/// Every byte under `root`, from every ordinary file (not a directory,
/// not a socket) -- segments, delta logs, the superblock, the index, the
/// keyring, all of it. What a leakage check has to grep.
fn all_bytes_under(root: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && entry.file_name() != "LOCK" {
                // The pool's LOCK file is empty, and on Windows the live
                // pool's lock covers it whole, so it cannot be read.
                out.extend(std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The heart of §18's threat model: an attacker holding the pool's files
/// (or devices) while it is unmounted must not be able to tell what is in
/// it. Every kind of content a pool stores -- file bytes, a file's own
/// name, an xattr's value, a symlink's target -- goes in with a unique,
/// searchable marker, and none of the markers, nor the unkeyed hash any
/// of them would have addressed under on a plaintext pool, may appear
/// anywhere in the bytes actually on disk.
#[test]
fn no_plaintext_marker_or_unkeyed_hash_survives_to_disk() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(dir.path(), small_params(), setup()).unwrap();
    assert!(pool.is_encrypted());

    let content_marker = b"LCHFS-LEAKAGE-MARKER-CONTENT-3f8a1c9d7e2b4560";
    let name_marker = "LCHFS-LEAKAGE-MARKER-NAME-6b1d9e4a2c8f0357";
    let xattr_marker = b"LCHFS-LEAKAGE-MARKER-XATTR-9a2e5c1f7b4d8036";
    let symlink_marker = "LCHFS-LEAKAGE-MARKER-SYMLINK-0d4f8a3e6c1b9752";

    // Padded so it clears inline_threshold and is genuinely chunked --
    // exactly the case that would otherwise show up as a RawChunk record.
    let mut content = content_marker.to_vec();
    content.extend(std::iter::repeat_n(b'x', 4000));
    let ino = pool.create_file(1, name_marker, 0o644).unwrap();
    pool.write(ino, 0, &content).unwrap();
    pool.set_xattr(ino, "user.leakage_test", xattr_marker, lchfs_store::XattrSetFlags::None).unwrap();

    let symlink_ino = pool.symlink(1, "a-symlink", symlink_marker).unwrap();
    let _ = symlink_ino;

    pool.checkpoint().unwrap();
    pool.run_gc_and_coalesce_pass().unwrap();
    drop(pool);

    let bytes = all_bytes_under(dir.path());
    assert!(!bytes.is_empty(), "setup: the pool must have written something");

    for (label, marker) in [
        ("file content", content_marker.as_slice()),
        ("file name", name_marker.as_bytes()),
        ("xattr value", xattr_marker.as_slice()),
        ("symlink target", symlink_marker.as_bytes()),
    ] {
        assert!(!contains(&bytes, marker), "{label} marker found in plaintext on disk");
    }

    // The address a plaintext pool would have used for this exact content
    // -- the thing an attacker without the key would compute and search
    // for, to answer "does this pool hold a copy of file X?". A keyed
    // address must never coincide with it.
    let unkeyed_content_hash = lchfs_format::Hash32::of(&content);
    assert!(
        !contains(&bytes, &unkeyed_content_hash.0),
        "the unkeyed content hash appears on disk -- an attacker without the key could still recognise known content"
    );

    // Reopens and reads back correctly with the key -- the leakage check
    // above is worthless if it passed only because nothing was actually
    // stored.
    let pool = Pool::open_with(dir.path(), &Unlock::Passphrase(PASSPHRASE)).unwrap();
    let ino = pool.lookup(1, name_marker).unwrap().unwrap();
    let read_back = pool.read(ino, 0, content.len() as u32).unwrap();
    assert_eq!(read_back.as_ref(), content.as_slice());
    let xattrs = pool.list_xattrs(ino).unwrap();
    assert!(xattrs.iter().any(|n| n == "user.leakage_test"));
    assert_eq!(pool.get_xattr(ino, "user.leakage_test").unwrap(), xattr_marker);
    let symlink_ino = pool.lookup(1, "a-symlink").unwrap().unwrap();
    assert_eq!(pool.readlink(symlink_ino).unwrap(), symlink_marker);
}

/// Two pools, two different keys: a marker written to one must not
/// address (or authenticate against) the other's key, even for the exact
/// same plaintext bytes. This is what "dedup within a pool, never across
/// pools" actually rests on.
#[test]
fn identical_content_addresses_differently_under_different_keys() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let pool_a = Pool::create_encrypted(dir_a.path(), small_params(), setup()).unwrap();
    let pool_b = Pool::create_encrypted(dir_b.path(), small_params(), setup()).unwrap();

    let content = b"the exact same bytes in both pools, seen by both";
    let hash_a = pool_a.debug_content_hash(content);
    let hash_b = pool_b.debug_content_hash(content);
    assert_ne!(hash_a, hash_b, "the same plaintext must not address the same way under two different keys");
    assert_ne!(hash_a, lchfs_format::Hash32::of(content));
}

/// An encrypted pool refuses a wrong passphrase and opens with the right
/// one. `Pool::open` with no key at all is only meaningful to check under
/// the normal build: `test-encrypt-all` makes it *try* one fixed
/// passphrase automatically (so untouched test code still gets an
/// encrypted pool transparently), which is a different, and differently
/// tested, guarantee -- see `unlock_pool`'s doc comment.
#[test]
fn plaintext_pools_need_no_key_and_encrypted_pools_refuse_one_without() {
    // A compile-time `#[cfg(feature = "test-encrypt-all")]` here would
    // only reflect *this crate's own* feature flag being requested by
    // name (`--features lchfs-store/test-encrypt-all`); the workspace
    // suite instead enables `lchfs-crypto/test-encrypt-all` directly,
    // which reaches the same runtime effect (feature unification makes
    // every crate in the build share one compiled lchfs-crypto) without
    // ever setting lchfs-store's own flag. This constant is what
    // `Pool::create` itself checks, so it is what this gate must check
    // too, however the feature was actually turned on.
    if !lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        let plain_dir = tempfile::tempdir().unwrap();
        let plain = Pool::create(plain_dir.path(), small_params()).unwrap();
        assert!(!plain.is_encrypted());
        drop(plain);
        assert!(Pool::open(plain_dir.path()).is_ok());

        let enc_dir = tempfile::tempdir().unwrap();
        let enc = Pool::create_encrypted(enc_dir.path(), small_params(), setup()).unwrap();
        drop(enc);
        let err = Pool::open(enc_dir.path()).unwrap_err();
        assert!(matches!(err, lchfs_store::PoolError::KeyRequired), "expected KeyRequired, got {err}");
    }

    let enc_dir = tempfile::tempdir().unwrap();
    let enc = Pool::create_encrypted(enc_dir.path(), small_params(), setup()).unwrap();
    drop(enc);
    assert!(Pool::open_with(enc_dir.path(), &Unlock::Passphrase(b"wrong passphrase")).is_err());
    assert!(Pool::open_with(enc_dir.path(), &Unlock::Passphrase(PASSPHRASE)).is_ok());
}

/// A recipient (post-quantum X-Wing) slot opens the same pool a passphrase
/// slot does, and each slot yields the identical keyring key.
#[test]
fn a_recipient_slot_opens_the_pool_the_identity_produces_it_for() {
    let identity = lchfs_crypto::slots::recipient::Identity::generate();
    let recipient = identity.recipient();
    let dir = tempfile::tempdir().unwrap();
    let mut setup = setup();
    setup.slots.push(NewSlot::Recipient {
        recipient: &recipient,
        label: "offline recovery".into(),
    });
    let pool = Pool::create_encrypted(dir.path(), small_params(), setup).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"reachable through either slot").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    for how in [Unlock::Passphrase(PASSPHRASE), Unlock::Identity(&identity)] {
        let pool = Pool::open_with(dir.path(), &how).unwrap();
        let ino = pool.lookup(1, "f").unwrap().unwrap();
        assert_eq!(pool.read(ino, 0, 64).unwrap().as_ref(), b"reachable through either slot");
    }
}

/// `EncryptionSetup` with no slots is refused rather than producing a
/// pool nothing can ever unlock.
#[test]
fn creating_an_encrypted_pool_with_no_slots_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let empty = EncryptionSetup {
        padding: Padding::Padme,
        slots: Vec::new(),
    };
    assert!(Pool::create_encrypted(dir.path(), small_params(), empty).is_err());
}

/// Padmé padding rounds a record's on-disk length so the exact size of
/// what was written is not readable straight off the segment. Off entirely
/// leaves the length exact instead -- both are legitimate settings; this
/// just confirms the pool setting actually reaches the record.
#[test]
fn padding_setting_is_honoured_end_to_end() {
    let unpadded_dir = tempfile::tempdir().unwrap();
    let padded_dir = tempfile::tempdir().unwrap();
    let mut unpadded_setup = setup();
    unpadded_setup.padding = Padding::None;
    let unpadded = Pool::create_encrypted(unpadded_dir.path(), small_params(), unpadded_setup).unwrap();
    let padded = Pool::create_encrypted(padded_dir.path(), small_params(), setup()).unwrap();

    // Same content, same chunker settings: any length difference in the
    // resulting Data-stream segment is padding, and nothing else.
    let content = vec![0x42u8; 3001];
    let ino_a = unpadded.create_file(1, "f", 0o644).unwrap();
    unpadded.write(ino_a, 0, &content).unwrap();
    unpadded.checkpoint().unwrap();
    let ino_b = padded.create_file(1, "f", 0o644).unwrap();
    padded.write(ino_b, 0, &content).unwrap();
    padded.checkpoint().unwrap();
    drop(unpadded);
    drop(padded);

    let segment_bytes = |root: &std::path::Path| -> u64 {
        std::fs::read_dir(root.join("segments/data"))
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum()
    };
    assert!(
        segment_bytes(padded_dir.path()) > segment_bytes(unpadded_dir.path()),
        "a padded pool's data segments should be larger for identical content"
    );
}

/// A single flipped byte anywhere in a sealed record makes it refuse to
/// open at all -- not just fail its content-hash check, since the AEAD
/// authentication check runs before the content hash is ever computed.
#[test]
fn every_bit_of_a_sealed_data_segment_is_authenticated() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(dir.path(), small_params(), setup()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    let content = vec![0x99u8; 5000];
    pool.write(ino, 0, &content).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let data_dir = dir.path().join("segments/data");
    let mut flips = 0;
    for entry in std::fs::read_dir(&data_dir).unwrap() {
        let path = entry.unwrap().path();
        let mut bytes = std::fs::read(&path).unwrap();
        if bytes.len() <= 4096 + 50 {
            continue; // header page only, or too small to safely flip
        }
        let original = bytes.clone();
        bytes[4096 + 50] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let pool = Pool::open_with(dir.path(), &Unlock::Passphrase(PASSPHRASE)).unwrap();
        let ino = pool.lookup(1, "f").unwrap().unwrap();
        let result = pool.read(ino, 0, content.len() as u32);
        drop(pool);
        std::fs::write(&path, &original).unwrap();
        if result.is_ok() {
            continue; // this byte wasn't inside the record we wrote
        }
        flips += 1;
        // Whichever byte of the record this landed on -- inside the
        // envelope (an authentication failure), or inside the outer
        // framing itself (a decode/`Io` failure) -- the one outcome that
        // must never happen is the corruption going unnoticed.
        assert!(result.is_err(), "expected a detected corruption, got Ok");
    }
    assert!(flips > 0, "setup: at least one data segment must have held the written chunk");
}

/// Groundwork for M4: every epoch and record kind uses the same map of
/// values everywhere, so a rekey (still to be built) has nothing to
/// special-case on this account.
#[test]
fn every_metadata_kind_ends_up_sealed_not_only_raw_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(dir.path(), small_params(), setup()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![7u8; 5000]).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    let mut kinds: BTreeMap<String, u32> = BTreeMap::new();
    for (sub, kind) in [("data", lchfs_format::StreamKind::Data), ("meta", lchfs_format::StreamKind::Meta)] {
        let seg_dir = dir.path().join("segments").join(sub);
        for entry in std::fs::read_dir(&seg_dir).unwrap() {
            let path = entry.unwrap().path();
            let stem: u64 = path.file_stem().unwrap().to_str().unwrap().parse().unwrap();
            let Ok(reader) = lchfs_store::segment::SegmentReader::open(dir.path(), stem, kind) else { continue };
            for (header, _offset) in reader.scan() {
                *kinds.entry(format!("{:?}", header.kind)).or_insert(0) += 1;
            }
        }
    }
    // Every physical record on disk is the Sealed kind at the framing
    // level -- RootObject/InodeObject/DirectoryObject/IndirectHashList/
    // RawChunk all live *inside* the envelope, invisible to a structural
    // scan without the key.
    assert_eq!(kinds.keys().collect::<Vec<_>>(), vec!["Sealed"], "found unsealed record kinds: {kinds:?}");
}

fn mirror_setup() -> (tempfile::TempDir, tempfile::TempDir) {
    (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
}

/// Review finding: a device detached from an encrypted pool used to keep
/// that pool's keyring, and the next pool built on it -- even a plaintext
/// one -- then demanded a key it never had. Detach now takes the keyring
/// with the superblock.
#[test]
fn a_detached_device_takes_no_keyring_with_it() {
    let (a, b) = mirror_setup();
    let pool = Pool::create_replicated_encrypted(&[a.path(), b.path()], small_params(), setup()).unwrap();
    assert!(lchfs_crypto::keyring::exists_on(b.path()));
    pool.detach_vdev_live().unwrap();
    drop(pool);
    assert!(!lchfs_crypto::keyring::exists_on(b.path()), "the detached device still holds the keyring");

    std::fs::remove_dir_all(b.path().join("segments")).unwrap();
    let reused = Pool::create(b.path(), small_params()).unwrap();
    drop(reused);
    if !lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        assert!(Pool::open(b.path()).is_ok(), "the reused device opens as the plaintext pool it now is");
    }
}

/// A stray keyring makes a device not blank: better refused at create than
/// silently claimed by whatever pool is built there next.
#[test]
fn a_stray_keyring_makes_a_device_not_blank() {
    let donor = tempfile::tempdir().unwrap();
    drop(Pool::create_encrypted(donor.path(), small_params(), setup()).unwrap());
    let target = tempfile::tempdir().unwrap();
    std::fs::copy(
        lchfs_crypto::keyring::path_on(donor.path()),
        lchfs_crypto::keyring::path_on(target.path()),
    )
    .unwrap();
    let err = Pool::create(target.path(), small_params()).unwrap_err();
    assert!(matches!(err, lchfs_store::PoolError::AlreadyExists(_)), "{err}");
}

/// A keyring belonging to another pool, found on a member of this one, says
/// nothing about this pool: a plaintext pool still opens without a key.
#[test]
fn a_foreign_keyring_on_a_plaintext_pool_is_ignored() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return; // every Pool::create is encrypted in that build
    }
    let donor = tempfile::tempdir().unwrap();
    drop(Pool::create_encrypted(donor.path(), small_params(), setup()).unwrap());
    let plain = tempfile::tempdir().unwrap();
    let pool = Pool::create(plain.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"plaintext pool content").unwrap();
    pool.checkpoint().unwrap();
    drop(pool);
    std::fs::copy(
        lchfs_crypto::keyring::path_on(donor.path()),
        lchfs_crypto::keyring::path_on(plain.path()),
    )
    .unwrap();
    let pool = Pool::open(plain.path()).unwrap();
    assert!(!pool.is_encrypted());
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.read(ino, 0, 64).unwrap().as_ref(), b"plaintext pool content");
}

/// Review finding: offline detach mounted the pool with no key, so it could
/// never work on an encrypted pool. And offline attach never gave the new
/// device a keyring, so a pool left with only that device could not unlock.
#[test]
fn offline_attach_and_detach_work_on_an_encrypted_pool() {
    let (a, b) = mirror_setup();
    let pool = Pool::create_encrypted(a.path(), small_params(), setup()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![3u8; 9000]).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);

    Pool::attach_vdev(&[a.path()], b.path()).unwrap();
    assert!(lchfs_crypto::keyring::exists_on(b.path()), "offline attach must give the new device the keyring");
    let unlock = Unlock::Passphrase(PASSPHRASE);
    drop(Pool::open_replicated_with(&[a.path(), b.path()], &unlock).unwrap());

    // The new device alone -- the original lost -- still unlocks and reads.
    let alone = Pool::open_degraded_with(&[b.path()], &unlock).unwrap();
    let ino = alone.lookup(1, "f").unwrap().unwrap();
    assert_eq!(alone.read(ino, 0, 9000).unwrap().as_ref(), vec![3u8; 9000].as_slice());
    drop(alone);

    Pool::detach_vdev_with(&[a.path(), b.path()], Some(&unlock)).unwrap();
    assert!(!lchfs_crypto::keyring::exists_on(b.path()));
    let pool = Pool::open_with(a.path(), &unlock).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    assert_eq!(pool.read(ino, 0, 9000).unwrap().as_ref(), vec![3u8; 9000].as_slice());
}

/// Review finding: fsck given no key reported every record of an encrypted
/// pool as corrupt. It now says, once, that it needs a key.
#[test]
fn fsck_without_a_key_says_so_instead_of_reporting_corruption() {
    // Not the test-encrypt-all passphrase, so fsck cannot unlock it in
    // either build.
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(dir.path(), small_params(), setup()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![1u8; 5000]).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);
    assert!(matches!(lchfs_fsck::collect_live_roots(dir.path()), Err(lchfs_fsck::FsckError::KeyRequired)));
    let report = lchfs_fsck::check(dir.path(), &[]);
    assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    assert!(matches!(report.errors[0], lchfs_fsck::FsckError::KeyRequired));
    let replicas = lchfs_fsck::check_replicas(&[dir.path()]);
    assert!(replicas.errors.iter().all(|e| matches!(e, lchfs_fsck::FsckError::KeyRequired)), "{:?}", replicas.errors);
}
