//! The `lchfs` binary's encryption options (ARCHITECTURE.md §18), driven
//! as a person or a script would: secrets from files, no terminal, no
//! askpass helper. Everything here stops short of a FUSE mount, which the
//! live run covers; `mount` refuses what it must refuse before mounting.

use std::path::Path;
use std::process::{Command, Output};

const KDF: [&str; 4] = ["--kdf-memory-kib", "64", "--kdf-time", "1"];

/// Runs `lchfs` with no controlling terminal and no askpass helper, so
/// nothing can prompt: every secret must come from where the test says.
fn lchfs(args: &[&str]) -> Output {
    Command::new("setsid")
        .arg("-w")
        .arg(env!("CARGO_BIN_EXE_lchfs"))
        .args(args)
        .env_remove("SSH_ASKPASS")
        .env_remove("LCHFS_ASKPASS")
        .env("RUST_LOG", "error")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("setsid and the lchfs binary run")
}

fn ok(args: &[&str]) -> String {
    let out = lchfs(args);
    assert!(
        out.status.success(),
        "lchfs {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(args: &[&str]) -> String {
    let out = lchfs(args);
    assert!(!out.status.success(), "lchfs {args:?} should have failed:\n{}", String::from_utf8_lossy(&out.stdout));
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn write_secret(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn create_with_passphrase(pool: &Path, pass: &Path) {
    let mut args = vec!["create-pool", "--encrypt", "--passphrase-file", s(pass)];
    args.extend(KDF);
    args.push(s(pool));
    ok(&args);
}

#[test]
fn a_passphrase_file_creates_and_unlocks_and_a_wrong_one_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    let pass = write_secret(t.path(), "pass", "correct horse\n");
    let bad = write_secret(t.path(), "bad", "wrong horse\n");
    create_with_passphrase(&pool, &pass);
    assert!(ok(&["stats", s(&pool)]).contains("encrypted: yes"));

    let err = fails(&["fsck", s(&pool), "--passphrase-file", s(&bad)]);
    assert!(err.contains("none of the keys given opens it"), "{err}");
    assert!(ok(&["fsck", s(&pool), "--passphrase-file", s(&pass)]).contains("No errors found"));
    // The trailing newline is the file's, not the passphrase's.
    let bare = write_secret(t.path(), "bare", "correct horse");
    ok(&["fsck", s(&pool), "--passphrase-file", s(&bare)]);
}

#[test]
fn with_no_key_and_nobody_to_ask_fsck_checks_structure_and_says_so() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return; // every pool's key is known to a test build's fsck
    }
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    create_with_passphrase(&pool, &write_secret(t.path(), "pass", "p"));
    let out = ok(&["fsck", s(&pool)]);
    assert!(out.contains("checked structure only"), "{out}");
    assert!(out.contains("NOT verified"), "{out}");
    let out = ok(&["fsck", s(&pool), "--structural", "--passphrase-file", s(&t.path().join("pass"))]);
    assert!(out.contains("checked structure only"), "{out}");
}

#[test]
fn a_tpm_slot_alone_is_never_created() {
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    // With no passphrase source and no recipient the pool gets a
    // passphrase slot too -- asked for, and here there is no one to ask.
    let err = fails(&["create-pool", "--encrypt", "--tpm", s(&pool)]);
    assert!(err.contains("needs a terminal"), "{err}");
    assert!(!pool.join("SUPERBLOCK").exists() && !lchfs_crypto::keyring::exists_on(&pool), "nothing may be created");
}

#[test]
fn require_encryption_refuses_a_plaintext_pool_before_mounting() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return; // a test build has no plaintext pools
    }
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    ok(&["create-pool", s(&pool)]);
    let mnt = t.path().join("mnt");
    std::fs::create_dir(&mnt).unwrap();
    let err = fails(&["mount", s(&pool), s(&mnt), "--require-encryption"]);
    assert!(err.contains("not encrypted"), "{err}");
    let err = fails(&["serve-nfs", s(&pool), "127.0.0.1:0", "--require-encryption"]);
    assert!(err.contains("not encrypted"), "{err}");
}

#[test]
fn a_recipient_identity_unlocks_and_must_be_private() {
    let t = tempfile::tempdir().unwrap();
    let id = t.path().join("id");
    ok(&["key", "generate-recipient", s(&id)]);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&id).unwrap().permissions().mode() & 0o777, 0o600);
    let public = t.path().join("id.pub");
    assert!(public.exists());
    fails(&["key", "generate-recipient", s(&id)]); // never overwritten

    // A recipient alone is enough: no passphrase asked for.
    let pool = t.path().join("pool");
    ok(&["create-pool", "--encrypt", "--recipient", s(&public), s(&pool)]);
    assert!(ok(&["key", "list", s(&pool)]).contains("recipient"));
    ok(&["fsck", s(&pool), "--identity", s(&id)]);

    // Someone else's identity opens nothing.
    let other = t.path().join("other");
    ok(&["key", "generate-recipient", s(&other)]);
    fails(&["fsck", s(&pool), "--identity", s(&other)]);

    std::fs::set_permissions(&id, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = fails(&["fsck", s(&pool), "--identity", s(&id)]);
    assert!(err.contains("readable by others"), "{err}");
}

#[test]
fn key_slots_change_offline_and_revoke_shuts_the_old_key_out() {
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    let one = write_secret(t.path(), "one", "one");
    let two = write_secret(t.path(), "two", "two");
    let three = write_secret(t.path(), "three", "three");
    create_with_passphrase(&pool, &one);

    let mut add = vec!["key", "add-passphrase", s(&pool), "--passphrase-file", s(&one), "--new-passphrase-file", s(&two)];
    add.extend(KDF);
    assert!(ok(&add).contains("added key slot 1"));
    ok(&["fsck", s(&pool), "--passphrase-file", s(&two)]);

    // change-passphrase --revoke: slot 1 becomes "three", and the keyring
    // key is replaced, so neither "two" nor (slot 0 revoked next) "one"...
    let mut change = vec![
        "key",
        "change-passphrase",
        "1",
        s(&pool),
        "--passphrase-file",
        s(&two),
        "--new-passphrase-file",
        s(&three),
    ];
    change.extend(KDF);
    // ...needs slot 0's passphrase to rewrap it, and there is no one to ask.
    change.push("--revoke");
    let err = fails(&change);
    assert!(err.contains("terminal"), "{err}");
    // With it given, the change goes through: slot 1 is revoked, a new
    // slot 2 holds "three", and slot 0 was rewrapped under the new key.
    let slot0 = format!("0={}", s(&one));
    change.extend(["--secret-file", &slot0]);
    ok(&change);
    fails(&["fsck", s(&pool), "--passphrase-file", s(&two)]);
    ok(&["fsck", s(&pool), "--passphrase-file", s(&three)]);
    ok(&["fsck", s(&pool), "--passphrase-file", s(&one)]);
    let list = ok(&["key", "list", s(&pool)]);
    assert!(list.contains("slot 2:") && !list.contains("slot 1:"), "{list}");

    // Plain revoke of slot 0.
    ok(&["key", "revoke", "0", s(&pool), "--passphrase-file", s(&three), "--secret-file", &format!("2={}", s(&three))]);
    fails(&["fsck", s(&pool), "--passphrase-file", s(&one)]);
    ok(&["fsck", s(&pool), "--passphrase-file", s(&three)]);
    let new_slot = "2";

    // The last passphrase slot cannot be removed.
    let err = fails(&["key", "remove", new_slot, s(&pool), "--passphrase-file", s(&three)]);
    assert!(err.contains("at least one passphrase or recipient slot"), "{err}");
}

#[test]
fn a_keyring_backup_restores_only_what_is_missing_unless_forced() {
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    let one = write_secret(t.path(), "one", "one");
    let two = write_secret(t.path(), "two", "two");
    create_with_passphrase(&pool, &one);
    let backup = t.path().join("keyring.bak");
    ok(&["key", "backup", s(&pool), s(&backup)]);
    fails(&["key", "backup", s(&pool), s(&backup)]); // never overwritten

    // Intact: left alone.
    let out = ok(&["key", "restore", s(&backup), s(&pool), "--passphrase-file", s(&one)]);
    assert!(out.contains("intact"), "{out}");

    // Lost: the pool cannot be opened, and the backup brings it back.
    std::fs::remove_file(lchfs_crypto::keyring::path_on(&pool)).unwrap();
    let out = ok(&["key", "restore", s(&backup), s(&pool), "--passphrase-file", s(&one)]);
    assert!(out.contains("1 device(s) restored"), "{out}");
    ok(&["fsck", s(&pool), "--passphrase-file", s(&one)]);

    // A backup the key does not open restores nothing.
    fails(&["key", "restore", s(&backup), s(&pool), "--passphrase-file", s(&two)]);

    // --force rolls a newer keyring back, loudly.
    let mut add = vec!["key", "add-passphrase", s(&pool), "--passphrase-file", s(&one), "--new-passphrase-file", s(&two)];
    add.extend(KDF);
    ok(&add);
    let out = lchfs(&["key", "restore", s(&backup), s(&pool), "--passphrase-file", s(&one), "--force"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("undone"));
    fails(&["fsck", s(&pool), "--passphrase-file", s(&two)]);

    // Another pool's backup is refused outright.
    let other = t.path().join("other");
    create_with_passphrase(&other, &one);
    let other_backup = t.path().join("other.bak");
    ok(&["key", "backup", s(&other), s(&other_backup)]);
    let err = fails(&["key", "restore", s(&other_backup), s(&pool), "--passphrase-file", s(&one)]);
    assert!(err.contains("different pool"), "{err}");
}

/// Against a software TPM only -- never the machine's own, whose PIN
/// lockout counter a wrong-PIN test would advance. Set LCHFS_TEST_TPM=1
/// and LCHFS_TPM_TCTI to a swtpm (see lchfs-crypto's TPM tests).
#[test]
fn a_tpm_slot_with_a_pin_unlocks_through_the_cli() {
    if std::env::var("LCHFS_TEST_TPM").as_deref() != Ok("1") || std::env::var("LCHFS_TPM_TCTI").is_err() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    let pass = write_secret(t.path(), "pass", "fallback");
    let pin = write_secret(t.path(), "pin", "4321");
    let bad_pin = write_secret(t.path(), "badpin", "0000");
    let mut args = vec!["create-pool", "--encrypt", "--passphrase-file", s(&pass), "--tpm", "--with-pin-file", s(&pin)];
    args.extend(KDF);
    args.push(s(&pool));
    ok(&args);
    assert!(ok(&["key", "list", s(&pool)]).contains("tpm2"));
    ok(&["fsck", s(&pool), "--tpm", "--tpm-pin-file", s(&pin)]);
    // With both given, the TPM is tried first and the passphrase after --
    // a wrong PIN falls through to it. One wrong PIN only: each counts
    // toward the TPM's dictionary-attack lockout, even a software one's.
    ok(&["fsck", s(&pool), "--tpm", "--tpm-pin-file", s(&bad_pin), "--passphrase-file", s(&pass)]);
}
