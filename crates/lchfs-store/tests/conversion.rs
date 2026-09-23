//! In-place conversion and key rotation (ARCHITECTURE.md §18): a pool full
//! of every kind of content is re-keyed while it stays open, its content
//! checked between every step, and at the end nothing of the old epoch --
//! no marker, no old content address -- is left in any file on any device.

use lchfs_crypto::keyring::{NewSlot, Padding, Unlock};
use lchfs_crypto::slots::passphrase::KdfCost;
use lchfs_format::{Hash32, PoolParams};
use lchfs_store::{EncryptionSetup, Pool, XattrSetFlags};
use std::collections::BTreeMap;
use std::path::Path;

const PASSPHRASE: &[u8] = b"conversion test passphrase";
const CHEAP: KdfCost = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };

fn params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 16 * 1024,
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
        slots: vec![NewSlot::Passphrase { passphrase: PASSPHRASE, cost: CHEAP, label: "test".into() }],
    }
}

fn unlock() -> Unlock<'static> {
    Unlock::Passphrase(PASSPHRASE)
}

/// Bytes nobody else would write, with `marker` repeated through them so
/// a leak of any part of the file shows.
fn marked(marker: &str, seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        if out.len() % 997 == 0 {
            out.extend_from_slice(marker.as_bytes());
        } else {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.push(x as u8);
        }
    }
    out.truncate(len);
    out
}

fn all_bytes_under(root: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let ty = entry.file_type().unwrap();
            if ty.is_dir() {
                stack.push(entry.path());
            } else if ty.is_file() {
                out.extend(std::fs::read(entry.path()).unwrap());
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// What the pool must say, file by file: (dir, name) -> bytes.
type Shadow = BTreeMap<(u64, String), Vec<u8>>;

fn check(pool: &Pool, shadow: &Shadow, when: &str) {
    for ((dir, name), want) in shadow {
        let ino = pool.lookup(*dir, name).unwrap().unwrap_or_else(|| panic!("{name} missing {when}"));
        let got = pool.read(ino, 0, want.len() as u32 + 16).unwrap();
        assert_eq!(got.as_ref(), want.as_slice(), "{name} wrong {when}");
    }
}

struct Populated {
    shadow: Shadow,
    markers: Vec<String>,
    /// Every chunk's plaintext-epoch content address before the
    /// conversion: none may survive it anywhere on disk.
    old_hashes: Vec<Hash32>,
    symlink: u64,
    xattr_ino: u64,
}

/// A pool with every kind of content the engine stores, several of them in
/// states only memory holds (an open append session, a fallback-written
/// file, an fsync'd file), and two snapshots.
fn populate(pool: &Pool) -> Populated {
    let mut shadow = Shadow::new();
    let mut markers = Vec::new();
    let put = |pool: &Pool, dir: u64, name: &str, data: Vec<u8>, shadow: &mut Shadow| {
        let ino = pool.create_file(dir, name, 0o644).unwrap();
        pool.write(ino, 0, &data).unwrap();
        shadow.insert((dir, name.to_string()), data);
        ino
    };
    let dir = pool.mkdir(1, "MARKER-DIRNAME-7c1e", 0o755).unwrap();
    markers.push("MARKER-DIRNAME-7c1e".into());

    let m = "MARKER-BIGFILE-19af";
    markers.push(m.into());
    let big = put(pool, dir, "big", marked(m, 1, 60_000), &mut shadow);
    pool.link(big, 1, "big-hardlink").unwrap();
    shadow.insert((1, "big-hardlink".into()), shadow[&(dir, "big".to_string())].clone());

    let m = "MARKER-INLINE-5d";
    markers.push(m.into());
    put(pool, 1, "inline", m.as_bytes().to_vec(), &mut shadow);

    // Sparse: data, a hole, data.
    let m = "MARKER-SPARSE-a4b2";
    markers.push(m.into());
    let sparse = pool.create_file(1, "sparse", 0o644).unwrap();
    let head = marked(m, 2, 5000);
    let tail = marked(m, 3, 5000);
    pool.write(sparse, 0, &head).unwrap();
    pool.write(sparse, 200_000, &tail).unwrap();
    let mut whole = head.clone();
    whole.resize(200_000, 0);
    whole.extend_from_slice(&tail);
    shadow.insert((1, "sparse".into()), whole);

    let m = "MARKER-XATTR-VALUE-3e";
    markers.push(m.into());
    let xattr_ino = put(pool, 1, "has-xattr", marked("MARKER-XATTRFILE-0b", 4, 3000), &mut shadow);
    markers.push("MARKER-XATTRFILE-0b".into());
    pool.set_xattr(xattr_ino, "user.marker", m.as_bytes(), XattrSetFlags::None).unwrap();

    let m = "MARKER-SYMLINK-TARGET-66";
    markers.push(m.into());
    let symlink = pool.symlink(1, "link", &format!("/nowhere/{m}")).unwrap();

    pool.checkpoint().unwrap();
    pool.create_snapshot("first").unwrap();

    // After the first snapshot: an overwrite in the middle (the fallback
    // path, which leaves the file in `file_state`)...
    let m = "MARKER-OVERWRITE-c9";
    markers.push(m.into());
    let over = pool.lookup(dir, "big").unwrap().unwrap();
    let patch = marked(m, 5, 2000);
    pool.write(over, 30_000, &patch).unwrap();
    let mut patched = shadow[&(dir, "big".to_string())].clone();
    patched[30_000..32_000].copy_from_slice(&patch);
    shadow.insert((dir, "big".into()), patched.clone());
    shadow.insert((1, "big-hardlink".into()), patched);

    // ...an fsync'd file...
    let m = "MARKER-FSYNCED-2f";
    markers.push(m.into());
    let synced = put(pool, 1, "synced", marked(m, 6, 20_000), &mut shadow);
    pool.fsync(synced).unwrap();
    pool.create_snapshot("second").unwrap();

    // ...and, never checkpointed, an append session left open.
    let m = "MARKER-APPENDING-8e";
    markers.push(m.into());
    let appending = pool.create_file(1, "appending", 0o644).unwrap();
    let a = marked(m, 7, 12_000);
    let b = marked(m, 8, 9_000);
    pool.write(appending, 0, &a).unwrap();
    pool.checkpoint().unwrap();
    pool.write(appending, a.len() as u64, &b).unwrap();
    let mut ab = a;
    ab.extend_from_slice(&b);
    shadow.insert((1, "appending".into()), ab);

    let mut old_hashes = Vec::new();
    for (dir, name) in shadow.keys() {
        let ino = pool.lookup(*dir, name).unwrap().unwrap();
        old_hashes.extend(pool.debug_chunk_refs(ino).unwrap_or_default().iter().map(|c| c.content_hash));
    }
    Populated {
        shadow,
        markers,
        old_hashes,
        symlink,
        xattr_ino,
    }
}

fn check_extras(pool: &Pool, p: &Populated, when: &str) {
    assert!(pool.readlink(p.symlink).unwrap().contains("MARKER-SYMLINK-TARGET-66"), "symlink {when}");
    assert_eq!(pool.get_xattr(p.xattr_ino, "user.marker").unwrap(), b"MARKER-XATTR-VALUE-3e", "xattr {when}");
    let names: Vec<String> = pool.list_snapshots().unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["first".to_string(), "second".to_string()], "snapshots {when}");
}

fn run_to_end(pool: &Pool, p: &mut Populated) {
    for step in 0..60 {
        check(pool, &p.shadow, &format!("before step {step}"));
        check_extras(pool, p, &format!("before step {step}"));
        // Writes keep landing throughout.
        let name = format!("during-{step}");
        let ino = pool.create_file(1, &name, 0o644).unwrap();
        let data = marked("MARKER-DURING-e3", 100 + step, 3000);
        pool.write(ino, 0, &data).unwrap();
        p.shadow.insert((1, name), data);
        if !pool.conversion_step().unwrap() {
            // The file just written is not durable until a checkpoint, and
            // the callers drop the pool the way a crash would.
            pool.checkpoint().unwrap();
            return;
        }
    }
    panic!("the conversion did not finish in 60 steps: {:?}", pool.conversion_status());
}

fn assert_nothing_old_on_disk(roots: &[&Path], p: &Populated, epoch: u16) {
    for root in roots {
        let bytes = all_bytes_under(root);
        for m in &p.markers {
            assert!(!contains(&bytes, m.as_bytes()), "marker {m} survived under {}", root.display());
        }
        assert!(!contains(&bytes, b"MARKER-DURING-e3"), "a write made during conversion leaked");
        for h in &p.old_hashes {
            assert!(!contains(&bytes, &h.0), "old content address {h:?} survived under {}", root.display());
        }
    }
    let _ = epoch;
}

#[test]
fn a_plaintext_mirror_is_encrypted_in_place_and_nothing_plaintext_survives() {
    if lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        return; // a test build has no plaintext pools
    }
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let roots = [a.path(), b.path()];
    let pool = Pool::create_replicated(&roots, params()).unwrap();
    let mut p = populate(&pool);
    pool.checkpoint().unwrap();
    // The test means nothing unless the plaintext really is on disk now.
    let before = all_bytes_under(a.path());
    assert!(p.markers.iter().all(|m| contains(&before, m.as_bytes())), "not every marker reached the disk");
    assert!(!p.old_hashes.is_empty() && contains(&before, &p.old_hashes[0].0));

    pool.start_encrypt(setup()).unwrap();
    assert!(pool.is_encrypted());
    run_to_end(&pool, &mut p);
    check(&pool, &p.shadow, "after conversion");
    check_extras(&pool, &p, "after conversion");

    let status = pool.conversion_status();
    assert_eq!((status.current_epoch, status.min_epoch, status.target_epoch), (1, 1, None), "{status:?}");
    eprintln!("conversion progress: {:?}", status.progress);
    assert!(status.progress.chunks_rewritten > 50, "{:?}", status.progress);
    assert!(status.progress.snapshots_done == 2, "{:?}", status.progress);
    assert_eq!(pool.old_epoch_census(1).unwrap().total(), 0);
    drop(pool);

    assert_nothing_old_on_disk(&roots, &p, 1);
    assert!(matches!(Pool::open_replicated(&roots), Err(lchfs_store::PoolError::KeyRequired)));
    let pool = Pool::open_replicated_with(&roots, &unlock()).unwrap();
    check(&pool, &p.shadow, "after reopen");
    check_extras(&pool, &p, "after reopen");
    drop(pool);

    let key = lchfs_fsck::unlock(&roots, &unlock()).unwrap();
    let live = lchfs_fsck::collect_live_roots_with(a.path(), Some(&key)).unwrap();
    let mut report = lchfs_fsck::check_devices_with(&roots, &live, Some(&key));
    report.errors.extend(lchfs_fsck::check_replicas_with(&roots, Some(&key)).errors);
    assert!(report.is_clean(), "{:?}", report.errors);
}

#[test]
fn a_key_rotation_destroys_the_old_key_and_refuses_its_records_after() {
    let a = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(a.path(), params(), setup()).unwrap();
    let mut p = populate(&pool);
    pool.checkpoint().unwrap();
    // Kept aside: an epoch-1 data segment, to inject after the rotation.
    let data_dir = a.path().join("segments").join("data");
    let old_segment = std::fs::read_dir(&data_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "aseg"))
        .unwrap();
    let old_bytes = std::fs::read(&old_segment).unwrap();

    assert_eq!(pool.start_rekey().unwrap(), 2);
    run_to_end(&pool, &mut p);
    let status = pool.conversion_status();
    assert_eq!((status.current_epoch, status.min_epoch, status.target_epoch), (2, 2, None), "{status:?}");
    assert_eq!(pool.old_epoch_census(2).unwrap().total(), 0);
    drop(pool);

    // Epoch 1's key is gone from the keyring itself.
    let found = lchfs_crypto::keyring::unlock_newest(&[a.path()], &unlock()).unwrap();
    assert_eq!(found.ring.epochs(), vec![2]);

    let pool = Pool::open_with(a.path(), &unlock()).unwrap();
    check(&pool, &p.shadow, "after rotation and reopen");
    check_extras(&pool, &p, "after rotation and reopen");
    drop(pool);

    // An epoch-1 record put back is refused, not read.
    let injected = data_dir.join("999999.aseg");
    std::fs::write(&injected, &old_bytes).unwrap();
    let key = lchfs_fsck::unlock(&[a.path()], &unlock()).unwrap();
    let reader = lchfs_store::segment::SegmentReader::open(a.path(), 999_999, lchfs_format::StreamKind::Data).unwrap();
    let (header, offset) = reader.scan().next().expect("the injected segment has a record");
    let loc = lchfs_format::ExtentLocation { segment_id: 999_999, offset, len: header.record_len };
    assert!(reader.read_record_with(loc, &key).is_err(), "a record of a destroyed epoch was read");
}

#[test]
fn a_conversion_survives_crashes_in_every_phase() {
    let a = tempfile::tempdir().unwrap();
    let pool = Pool::create_encrypted(a.path(), params(), setup()).unwrap();
    let mut p = populate(&pool);
    pool.checkpoint().unwrap();
    pool.start_rekey().unwrap();
    // Crash 1: right after the start, before any rewriting.
    drop(pool);
    let pool = Pool::open_with(a.path(), &unlock()).unwrap();
    assert_eq!(pool.conversion_status().phase.as_deref(), Some("Rewriting"));
    check(&pool, &p.shadow, "after a crash at the start");
    // Crash 2: after one rewriting pass.
    pool.conversion_step().unwrap();
    drop(pool);
    let pool = Pool::open_with(a.path(), &unlock()).unwrap();
    check(&pool, &p.shadow, "after a crash mid-rewrite");
    // Crash 3: once retiring, before it finishes.
    while pool.conversion_status().phase.as_deref() == Some("Rewriting") {
        pool.conversion_step().unwrap();
    }
    assert_eq!(pool.conversion_status().phase.as_deref(), Some("Retiring"));
    drop(pool);
    let pool = Pool::open_with(a.path(), &unlock()).unwrap();
    check(&pool, &p.shadow, "after a crash while retiring");
    run_to_end(&pool, &mut p);
    assert_eq!(pool.conversion_status().min_epoch, 2);
    drop(pool);
    let pool = Pool::open_with(a.path(), &unlock()).unwrap();
    check(&pool, &p.shadow, "after the conversion finished");
    check_extras(&pool, &p, "after the conversion finished");
}

#[test]
fn retirement_waits_for_an_absent_device_and_finishes_when_it_is_back() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Pool::create_replicated_encrypted(&[a.path(), b.path()], params(), setup()).unwrap();
    let mut p = populate(&pool);
    pool.checkpoint().unwrap();
    pool.start_rekey().unwrap();
    while pool.conversion_status().phase.as_deref() == Some("Rewriting") {
        pool.conversion_step().unwrap();
    }
    pool.offline_vdev(1).unwrap();
    let err = pool.run_conversion_to_completion().unwrap_err().to_string();
    assert!(err.contains("waiting for vdevs [1]"), "{err}");
    assert_eq!(pool.conversion_status().progress.waiting_for_vdevs, vec![1]);
    pool.online_vdev(b.path()).unwrap();
    pool.run_conversion_to_completion().unwrap();
    check(&pool, &p.shadow, "after retiring with both devices");
    assert_eq!(pool.old_epoch_census(2).unwrap().total(), 0);
    drop(pool);
    let _ = &mut p;
    assert_eq!(lchfs_crypto::keyring::unlock_newest(&[a.path(), b.path()], &unlock()).unwrap().ring.epochs(), vec![2]);
}
