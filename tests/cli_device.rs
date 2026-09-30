//! `create-pool` on devices: what it formats, and what it refuses to.
//! Images stand in for block devices (`LCHFS_ALLOW_IMAGES`).

use std::path::Path;
use std::process::{Command, Output};

fn lchfs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lchfs"))
        .args(args)
        .env("LCHFS_ALLOW_IMAGES", "1")
        .env("RUST_LOG", "error")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the lchfs binary runs")
}

fn ok(args: &[&str]) {
    let out = lchfs(args);
    assert!(out.status.success(), "lchfs {args:?} failed:\n{}", String::from_utf8_lossy(&out.stderr));
}

fn fails(args: &[&str]) -> String {
    let out = lchfs(args);
    assert!(!out.status.success(), "lchfs {args:?} should have failed");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn the_index_size_is_chosen_at_create() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return; // create-pool without key options makes a plaintext pool
    }
    let t = tempfile::tempdir().unwrap();
    let pool = t.path().join("pool");
    ok(&["create-pool", "--index-size-mib", "96", s(&pool)]);
    let label = lchfs_device::Device::open(&pool).unwrap().label();
    assert_eq!(label.index_copy_len, 96 << 20);
    // Formatting is done once: an existing layout is not silently kept.
    let err = fails(&["create-pool", "--index-size-mib", "128", s(&pool)]);
    assert!(err.contains("already formatted"), "{err}");
}

#[test]
fn force_starts_a_leftover_device_afresh_but_never_formats_over_a_pool() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let dev = t.path().join("dev");
    std::fs::create_dir(&dev).unwrap();
    // A device formatted but holding no pool, with a segment left over (a
    // create cut short, say).
    lchfs_device::format(&dev, Default::default()).unwrap();
    lchfs_device::Device::open(&dev).unwrap().create_segment(lchfs_device::SegmentKind::Data, 3).unwrap();
    let err = fails(&["create-pool", s(&dev)]);
    assert!(err.contains("holds segments"), "{err}");
    ok(&["create-pool", "--force", s(&dev)]);

    let err = fails(&["create-pool", "--force", s(&dev)]);
    assert!(err.to_lowercase().contains("exists"), "{err}");
}
