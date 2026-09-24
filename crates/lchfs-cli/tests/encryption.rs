//! Key management end to end (ARCHITECTURE.md §18): an encrypted pool
//! opened in-process, its keyring changed over the control socket the way
//! `lchfs key` does it, and offline the way it does for an unmounted pool.

use lchfs_cli::control::{ControlServer, KEY_REFUSED, request, request_raw, socket_path};
use lchfs_cli::keyops::{KeyOp, NewSlotSpec};
use lchfs_cli::unlock::Credential;
use lchfs_crypto::keyring::{self, NewSlot, Padding, Unlock};
use lchfs_crypto::slots::passphrase::KdfCost;
use lchfs_format::PoolParams;
use lchfs_store::{EncryptionSetup, Pool, PoolError};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use lchfs_crypto::locked::LockedBytes;

const FIRST: &[u8] = b"first passphrase";
const SECOND: &[u8] = b"second passphrase";
const CHEAP: KdfCost = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };

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

fn setup() -> EncryptionSetup<'static> {
    EncryptionSetup {
        padding: Padding::Padme,
        slots: vec![NewSlot::Passphrase { passphrase: FIRST, cost: CHEAP, label: "first".into() }],
    }
}

fn secret(b: &[u8]) -> LockedBytes {
    LockedBytes::from_slice(b)
}

fn add_second() -> KeyOp {
    KeyOp::Add(NewSlotSpec::Passphrase { passphrase: secret(SECOND), cost: CHEAP, label: "second".into() })
}

fn key_op(sock: &Path, proof: &[u8], op: &KeyOp) -> serde_json::Value {
    request_raw(
        sock,
        &json!({ "cmd": "key-op", "proof": Credential::Passphrase(secret(proof)).to_json(), "op": op.to_json() }),
    )
    .unwrap()
}

/// Every device's keyring, as generations. After a change they must all be
/// the same one.
fn generations(roots: &[&Path]) -> Vec<u64> {
    keyring::read_all(roots).unwrap().iter().map(|(_, k)| k.body().generation).collect()
}

#[test]
fn a_mounted_pools_keyring_changes_over_the_socket_only_with_proof() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path()];
    let pool = Arc::new(Pool::create_replicated_encrypted(&roots, small_params(), setup()).unwrap());
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![7u8; 20_000]).unwrap();
    pool.checkpoint().unwrap();
    let sock = socket_path(&pool);
    let server = ControlServer::start(Arc::clone(&pool), sock.clone()).unwrap();

    // Owner-only, before any request.
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);

    let status = request(&sock, &json!({ "cmd": "status" })).unwrap();
    assert_eq!(status["encryption"]["encrypted"], true);
    let before = generations(&roots);

    // Someone who can reach the socket but holds no key cannot add one.
    let reply = key_op(&sock, b"not the passphrase", &add_second());
    assert_eq!(reply["ok"], false, "{reply}");
    assert_eq!(reply["code"], KEY_REFUSED, "{reply}");
    assert_eq!(generations(&roots), before, "a refused proof must change nothing");

    let reply = key_op(&sock, FIRST, &add_second());
    assert_eq!(reply["ok"], true, "{reply}");
    let added = reply["result"]["result"]["added"].as_u64().unwrap() as u16;
    assert!(reply["result"]["unwritten"].as_array().unwrap().is_empty());
    let after_add = generations(&roots);
    assert_eq!(after_add.len(), 2);
    assert!(after_add.iter().all(|&g| g == before[0] + 1), "{after_add:?}");

    // A change the keyring refuses (the last non-TPM slot... here: a slot
    // that does not exist) is an error, and not a "wrong key" one.
    let reply = key_op(&sock, FIRST, &KeyOp::Remove(99));
    assert_eq!(reply["ok"], false);
    assert!(reply.get("code").is_none(), "{reply}");

    // Revoke the first slot: the second's passphrase rewraps it.
    let mut secrets = BTreeMap::new();
    secrets.insert(added, secret(SECOND));
    let reply = key_op(&sock, SECOND, &KeyOp::Revoke { slot: 0, secrets });
    assert_eq!(reply["ok"], true, "{reply}");
    let slots = request(&sock, &json!({ "cmd": "key-list" })).unwrap();
    assert_eq!(slots["slots"].as_array().unwrap().len(), 1);
    assert_eq!(slots["slots"][0]["label"], "second");

    // The first passphrase is no longer proof of anything.
    let reply = key_op(&sock, FIRST, &KeyOp::Remove(added));
    assert_eq!(reply["code"], KEY_REFUSED, "{reply}");

    drop(server);
    drop(pool);
    let err = Pool::open_replicated_with(&roots, &Unlock::Passphrase(FIRST)).err().unwrap();
    assert!(lchfs_cli::unlock::refused(&err), "{err}");
    let pool = Pool::open_replicated_with(&roots, &Unlock::Passphrase(SECOND)).unwrap();
    assert_eq!(pool.read(ino, 0, 20_000).unwrap().as_ref(), vec![7u8; 20_000].as_slice());
}

#[test]
fn an_offline_keyring_change_refuses_a_mounted_pool() {
    let a = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(a.path(), small_params(), setup()).unwrap();
    let err = Pool::update_keyring_offline(&[a.path()], false, &Unlock::Passphrase(FIRST), |r| add_second().apply(r))
        .err()
        .unwrap();
    assert!(!lchfs_cli::unlock::refused(&err), "a held lock is not a wrong key: {err}");
    drop(pool);
    let (v, failed) =
        Pool::update_keyring_offline(&[a.path()], false, &Unlock::Passphrase(FIRST), |r| add_second().apply(r)).unwrap();
    assert!(failed.is_empty());
    assert_eq!(v["added"], 1);
    Pool::open_with(a.path(), &Unlock::Passphrase(SECOND)).unwrap();
}

#[test]
fn an_offline_change_with_a_device_missing_needs_degraded_and_fsck_reports_it() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path()];
    drop(Pool::create_replicated_encrypted(&roots, small_params(), setup()).unwrap());

    let err = Pool::update_keyring_offline(&[a.path()], false, &Unlock::Passphrase(FIRST), |r| add_second().apply(r))
        .err()
        .unwrap();
    assert!(matches!(err, PoolError::InvalidArgument(_) | PoolError::Format(_)), "{err}");
    Pool::update_keyring_offline(&[a.path()], true, &Unlock::Passphrase(FIRST), |r| add_second().apply(r)).unwrap();

    // b kept the old generation: a warning (the next mount fixes it), not
    // an error.
    let report = lchfs_fsck::check_keyrings(&roots);
    assert!(report.is_clean(), "{:?}", report.errors);
    assert!(
        report.warnings.iter().any(|w| matches!(w, lchfs_fsck::FsckError::KeyringStale { vdev_id: 1, .. })),
        "{:?}",
        report.warnings
    );
    // ...and it does: mounting both brings b up to date.
    drop(Pool::open_replicated_with(&roots, &Unlock::Passphrase(SECOND)).unwrap());
    let report = lchfs_fsck::check_keyrings(&roots);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

#[test]
fn fsck_checks_structure_without_a_key_and_everything_with_one() {
    let a = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(a.path(), small_params(), setup()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![3u8; 50_000]).unwrap();
    pool.checkpoint().unwrap();
    drop(pool);
    let roots = [a.path()];

    assert!(lchfs_fsck::is_encrypted(&roots));
    let structural = lchfs_fsck::structural_check(&roots);
    assert!(structural.is_clean(), "{:?}", structural.errors);
    assert!(structural.objects_visited > 0);

    assert!(lchfs_fsck::unlock(&roots, &Unlock::Passphrase(b"nope")).is_err());
    let key = lchfs_fsck::unlock(&roots, &Unlock::Passphrase(FIRST)).unwrap();
    let live = lchfs_fsck::collect_live_roots_with(a.path(), Some(&key)).unwrap();
    let report = lchfs_fsck::check_devices_with(&roots, &live, Some(&key));
    assert!(report.is_clean(), "{:?}", report.errors);
    assert!(report.objects_visited > structural.objects_visited / 2);

    // A damaged keyring is an error even without a key.
    let path = keyring::path_on(a.path());
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let structural = lchfs_fsck::structural_check(&roots);
    assert!(
        structural.errors.iter().any(|e| matches!(e, lchfs_fsck::FsckError::KeyringDamaged { .. })),
        "{:?}",
        structural.errors
    );
}

#[test]
fn secret_json_is_zeroed_when_dropped() {
    let mut v = json!({ "proof": { "passphrase": "68756e74657232" }, "list": ["abc", 1, null] });
    lchfs_cli::control::scrub(&mut v);
    assert_eq!(v["proof"]["passphrase"], "", "zeroize empties the string after wiping it");
    assert_eq!(v["list"][0], "");
    assert_eq!(v["list"][1], 1);
}

#[test]
fn a_credential_round_trips_through_json() {
    let identity = lchfs_crypto::slots::recipient::Identity::generate();
    for c in [
        Credential::Passphrase(secret(b"\x00\xffbinary\n")),
        Credential::Identity(Box::new(identity)),
        Credential::Tpm(Some(secret(b"1234"))),
        Credential::Tpm(None),
    ] {
        let back = Credential::from_json(&c.to_json()).unwrap();
        assert_eq!(*back.to_json(), *c.to_json());
    }
    let op = KeyOp::Revoke { slot: 3, secrets: [(1, secret(b"a")), (2, secret(b"b"))].into_iter().collect() };
    assert_eq!(*KeyOp::from_json(&op.to_json()).unwrap().to_json(), *op.to_json());
}

#[test]
fn a_mounted_pool_is_encrypted_and_rekeyed_over_the_socket() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return; // a test build has no plaintext pools
    }
    let a = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(a.path(), small_params()).unwrap());
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![9u8; 30_000]).unwrap();
    pool.checkpoint().unwrap();
    let sock = socket_path(&pool);
    let _server = ControlServer::start(Arc::clone(&pool), sock.clone()).unwrap();

    let slot = NewSlotSpec::Passphrase { passphrase: secret(FIRST), cost: CHEAP, label: "first".into() };
    let reply = request(&sock, &json!({ "cmd": "start-encrypt", "slots": [slot.to_json()] })).unwrap();
    assert_eq!(reply["encrypted"], true, "{reply}");
    assert_eq!(reply["conversion"]["phase"], "Rewriting", "{reply}");
    pool.run_conversion_to_completion().unwrap();
    let status = request(&sock, &json!({ "cmd": "encryption-status" })).unwrap();
    assert_eq!((status["current_epoch"].as_u64(), status["min_epoch"].as_u64()), (Some(1), Some(1)), "{status}");
    assert!(status["conversion"].is_null(), "{status}");

    // A rotation needs proof, like any key operation.
    let wrong = request_raw(&sock, &json!({ "cmd": "start-rekey", "proof": Credential::Passphrase(secret(b"no")).to_json() })).unwrap();
    assert_eq!(wrong["code"], KEY_REFUSED, "{wrong}");
    assert!(pool.conversion_status().target_epoch.is_none());
    let right = request(&sock, &json!({ "cmd": "start-rekey", "proof": Credential::Passphrase(secret(FIRST)).to_json() })).unwrap();
    assert_eq!(right["target_epoch"], 2);
    pool.run_conversion_to_completion().unwrap();
    assert_eq!(pool.conversion_status().min_epoch, 2);
    assert_eq!(pool.read(ino, 0, 30_000).unwrap().as_ref(), vec![9u8; 30_000].as_slice());
}

/// Review finding: a secret travels the socket as hex -- twice its size --
/// so a request buffer the size of the largest secret refused anything over
/// half of it, and a key file that worked unmounted failed mounted.
#[test]
fn the_largest_allowed_secret_works_over_the_socket_too() {
    let a = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create_encrypted(a.path(), small_params(), setup()).unwrap());
    let sock = socket_path(&pool);
    let _server = ControlServer::start(Arc::clone(&pool), sock.clone()).unwrap();
    let big: Vec<u8> = (0..LockedBytes::MAX).map(|i| (i % 251) as u8).collect();
    let op = KeyOp::Add(NewSlotSpec::Passphrase { passphrase: secret(&big), cost: CHEAP, label: "keyfile".into() });
    let reply = key_op(&sock, FIRST, &op);
    assert_eq!(reply["ok"], true, "{reply}");
    // And it proves: the big secret is itself accepted as the key.
    let reply = key_op(&sock, &big, &KeyOp::Remove(0));
    assert_eq!(reply["ok"], true, "{reply}");
}

#[test]
fn an_identity_crosses_the_socket_as_its_bare_key_line() {
    let identity = lchfs_crypto::slots::recipient::Identity::generate();
    let json = Credential::Identity(Box::new(identity)).to_json();
    let line = json["identity"].as_str().unwrap();
    assert!(!line.contains('\n') && !line.contains('#'), "{line}");
    assert!(Credential::from_json(&json).is_ok());
}
