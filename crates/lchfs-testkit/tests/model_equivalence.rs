//! Property-based test: random `FsOp` sequences run against both the real
//! engine (`lchfs-store`'s `Pool`, bypassing the kernel/FUSE for speed --
//! ARCHITECTURE.md §10) and `ReferenceModel`, asserting the two agree on
//! every operation's success/failure and on file content after every
//! mutation.
//!
//! `CrashAndRemount` here checkpoints before reopening, so it validates
//! `Pool::open`'s reopen/recovery *path* (does the reconstructed
//! namespace match the model) rather than "does an uncheckpointed write
//! survive a real crash" -- that specific question already has dedicated
//! coverage in `lchfs-store/tests/crash_recovery.rs`. Not asserting error
//! *kinds* against each other either (`PoolError` and `ModelError` are
//! unrelated enums with no claimed 1:1 correspondence) -- just whether
//! each op succeeded or failed, which is exactly the property most likely
//! to catch a real logic bug (an op that should fail silently succeeding,
//! or vice versa) without the brittleness of matching exact error taxonomies.

use lchfs_format::{InodeKind, PoolParams};
use lchfs_store::{FallocateMode, Pool};
use lchfs_testkit::{arb_fs_op, FsOp, ReferenceModel};
use proptest::prelude::*;
use std::path::{Component, Path, PathBuf};

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 4,
    }
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str().map(str::to_string),
            _ => None,
        })
        .collect()
}

/// Resolves `path`'s parent ino + leaf name by walking `Pool`'s own
/// namespace from the root, exactly as a real path-based caller (FUSE)
/// would. `None` if any intermediate component doesn't exist or isn't a
/// directory -- callers fold that into the same "this op fails" bucket as
/// any other rejection.
fn resolve(pool: &Pool, path: &Path) -> Option<(u64, String)> {
    let mut comps = path_components(path);
    let leaf = comps.pop()?;
    let mut ino = 1u64; // ROOT_DIR_INO
    for comp in &comps {
        ino = pool.lookup(ino, comp).ok().flatten()?;
    }
    Some((ino, leaf))
}

struct Harness {
    pool: Option<Pool>,
    model: ReferenceModel,
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pool = Pool::create(dir.path(), small_params()).unwrap();
        Self { pool: Some(pool), model: ReferenceModel::new(), dir }
    }

    fn pool(&self) -> &Pool {
        self.pool.as_ref().unwrap()
    }

    /// Both sides must agree on file content whenever `path` currently
    /// resolves to a regular file on the real side.
    fn assert_content_matches(&self, path: &Path) {
        let Some((parent, name)) = resolve(self.pool(), path) else { return };
        let Ok(Some(ino)) = self.pool().lookup(parent, &name) else { return };
        let Ok(attr) = self.pool().getattr(ino) else { return };
        if attr.kind != InodeKind::File {
            return;
        }
        // Whole-file read, plus a spread of *partial* ranges. The
        // whole-file read alone never exercises `Pool::read`'s binary
        // search (`partition_point`) or its partial-chunk-overlap
        // arithmetic -- the newest and most intricate part of the read
        // path, and completely untested differentially before this.
        let size = attr.size;
        // Assert size explicitly. Reading `size` bytes from *both* sides (as
        // this used to) makes any size divergence structurally invisible:
        // the shorter side simply returns fewer bytes and both agree. That
        // blind spot hid a real oracle bug (a zero-length write extending
        // the model's file) that the generator had been producing all along.
        assert_eq!(
            Some(size),
            self.model.file_len(path),
            "size diverged for {path:?}"
        );
        let mut ranges: Vec<(u64, u32)> = vec![(0, size as u32)];
        for off in [0u64, 1, size / 3, size / 2, size.saturating_sub(1)] {
            for len in [1u32, 7, 300, 1024] {
                ranges.push((off, len));
            }
        }
        for (off, len) in ranges {
            let real_bytes =
                self.pool().read(ino, off, len).map(|b| b.to_vec()).unwrap_or_default();
            let model_bytes = self.model.read(path, off, len as usize).unwrap_or_default();
            assert_eq!(
                real_bytes, model_bytes,
                "content diverged for {path:?} at offset {off} len {len} (size {size})"
            );
        }
    }

    /// The namespace itself, which content comparison never inspects. A
    /// stale or duplicated `DirEntry` left behind by a rename would
    /// otherwise surface only if some later op happened to name that exact
    /// path -- and a duplicate would not show up in `lookup` at all.
    fn assert_namespace_matches(&self) {
        for dir in ["/", "/dir1", "/dir2"] {
            let p = PathBuf::from(dir);
            let ino = if dir == "/" {
                Some(1u64) // ROOT_DIR_INO
            } else {
                resolve(self.pool(), &p)
                    .and_then(|(parent, name)| self.pool().lookup(parent, &name).ok().flatten())
            };
            let real = ino.and_then(|ino| self.pool().readdir(ino).ok()).map(|entries| {
                let mut v: Vec<(String, InodeKind)> =
                    entries.into_iter().map(|e| (e.name, e.kind)).collect();
                v.sort_by(|a, b| a.0.cmp(&b.0));
                v
            });
            assert_eq!(real, self.model.readdir(&p), "directory listing diverged for {p:?}");
        }
    }

    /// Structural check via `lchfs-fsck` -- an independent reader of the
    /// on-disk format that deliberately shares no code with `Pool`'s own
    /// scan/recovery paths, so a bug in those is still catchable here.
    ///
    /// Content assertions can only compare bytes the engine agrees to hand
    /// back. This catches invariants they cannot observe at all: chunk-list
    /// sort/overlap, InoMap sort/dup, dangling inos, dir-entry-kind vs
    /// InodeObject mismatches, and size mismatches -- exactly the shapes the
    /// sparse-file work put at risk by making a gap in a chunk list
    /// meaningful.
    ///
    /// Closes the pool first. fsck's read-only checks are lock-free by
    /// design, but `verify_index` opens INDEX.redb, which the live `Pool`
    /// still holds open.
    fn assert_structurally_sound(&mut self) {
        self.pool().checkpoint().unwrap();
        drop(self.pool.take());
        let root = self.dir.path();
        let live_roots = lchfs_fsck::collect_live_roots(root).expect("collect_live_roots");
        // Guard against a vacuous pass: with no live roots `check` walks
        // nothing and is trivially clean, so the assertion below would say
        // nothing at all about the pool.
        assert!(!live_roots.is_empty(), "no live roots to check");
        let report = lchfs_fsck::check(root, &live_roots);
        assert!(report.is_clean(), "fsck check: {:?}", report.errors);
        assert!(report.objects_visited > 0, "fsck visited no objects");
        let index = lchfs_fsck::verify_index(root, &live_roots);
        assert!(index.is_clean(), "fsck verify_index: {:?}", index.errors);
    }

    fn apply(&mut self, op: &FsOp) {
        self.apply_inner(op);
        // Skipped after FsyncAndCrash: a non-checkpointing crash may
        // legitimately lose a directory entry that was never made durable,
        // so the two sides are allowed to differ there by construction.
        if !matches!(op, FsOp::FsyncAndCrash { .. }) {
            self.assert_namespace_matches();
        }
    }

    fn apply_inner(&mut self, op: &FsOp) {
        match op {
            FsOp::Write { path, offset, data } => {
                let real_ok = (|| -> Option<bool> {
                    let (parent, name) = resolve(self.pool(), path)?;
                    let ino = match self.pool().lookup(parent, &name) {
                        Ok(Some(ino)) => ino,
                        Ok(None) => self.pool().create_file(parent, &name, 0o644).ok()?,
                        Err(_) => return Some(false),
                    };
                    Some(self.pool().write(ino, *offset, data).is_ok())
                })()
                .unwrap_or(false);
                let model_ok = self.model.write(path, *offset, data).is_ok();
                assert_eq!(real_ok, model_ok, "write({path:?}, {offset}, {} bytes) diverged", data.len());
                if real_ok {
                    self.assert_content_matches(path);
                }
            }
            FsOp::Truncate { path, len } => {
                let real_ok = resolve(self.pool(), path)
                    .and_then(|(parent, name)| self.pool().lookup(parent, &name).ok().flatten())
                    .map(|ino| self.pool().set_size(ino, *len).is_ok())
                    .unwrap_or(false);
                let model_ok = self.model.truncate(path, *len).is_ok();
                assert_eq!(real_ok, model_ok, "truncate({path:?}, {len}) diverged");
                if real_ok {
                    self.assert_content_matches(path);
                }
            }
            FsOp::Mkdir { path } => {
                let real_ok = resolve(self.pool(), path)
                    .map(|(parent, name)| self.pool().mkdir(parent, &name, 0o755).is_ok())
                    .unwrap_or(false);
                let model_ok = self.model.mkdir(path).is_ok();
                assert_eq!(real_ok, model_ok, "mkdir({path:?}) diverged");
            }
            FsOp::Rmdir { path } => {
                let real_ok = resolve(self.pool(), path)
                    .map(|(parent, name)| self.pool().rmdir(parent, &name).is_ok())
                    .unwrap_or(false);
                let model_ok = self.model.rmdir(path).is_ok();
                assert_eq!(real_ok, model_ok, "rmdir({path:?}) diverged");
            }
            FsOp::Unlink { path } => {
                let real_ok = resolve(self.pool(), path)
                    .map(|(parent, name)| self.pool().unlink(parent, &name).is_ok())
                    .unwrap_or(false);
                let model_ok = self.model.unlink(path).is_ok();
                assert_eq!(real_ok, model_ok, "unlink({path:?}) diverged");
            }
            FsOp::Rename { from, to } => {
                let real_ok = (|| -> Option<bool> {
                    let (from_parent, from_name) = resolve(self.pool(), from)?;
                    let (to_parent, to_name) = resolve(self.pool(), to)?;
                    Some(
                        self.pool()
                            .rename(from_parent, &from_name, to_parent, &to_name, false)
                            .is_ok(),
                    )
                })()
                .unwrap_or(false);
                let model_ok = self.model.rename(from, to).is_ok();
                assert_eq!(real_ok, model_ok, "rename({from:?}, {to:?}) diverged");
                if real_ok {
                    self.assert_content_matches(to);
                }
            }
            FsOp::Link { path, target } => {
                let real_ok = (|| -> Option<bool> {
                    let (parent, name) = resolve(self.pool(), path)?;
                    let ino = self.pool().lookup(parent, &name).ok().flatten()?;
                    let (t_parent, t_name) = resolve(self.pool(), target)?;
                    Some(self.pool().link(ino, t_parent, &t_name).is_ok())
                })()
                .unwrap_or(false);
                let model_ok = self.model.link(path, target).is_ok();
                assert_eq!(real_ok, model_ok, "link({path:?}, {target:?}) diverged");
                if real_ok {
                    self.assert_content_matches(target);
                }
            }
            FsOp::Symlink { path, target } => {
                let real_ok = resolve(self.pool(), path)
                    .map(|(parent, name)| {
                        self.pool()
                            .symlink(parent, &name, &target.display().to_string())
                            .is_ok()
                    })
                    .unwrap_or(false);
                let model_ok = self.model.symlink(path, target).is_ok();
                assert_eq!(real_ok, model_ok, "symlink({path:?}, {target:?}) diverged");
            }
            FsOp::Fsync { path } => {
                // The model has no durability concept -- fsync succeeding
                // or failing there isn't meaningful, so it isn't asserted
                // against. Just exercise the real path without panicking.
                let _ = resolve(self.pool(), path)
                    .and_then(|(parent, name)| self.pool().lookup(parent, &name).ok().flatten())
                    .map(|ino| self.pool().fsync(ino));
            }
            FsOp::Fallocate { path, offset, len, mode } => {
                // Unlike `write`, fallocate never creates the file.
                let real_ok = resolve(self.pool(), path)
                    .and_then(|(parent, name)| self.pool().lookup(parent, &name).ok().flatten())
                    .map(|ino| self.pool().fallocate(ino, *offset, *len, *mode).is_ok())
                    .unwrap_or(false);
                let model_ok = self.model.fallocate(path, *offset, *len, *mode).is_ok();
                assert_eq!(
                    real_ok, model_ok,
                    "fallocate({path:?}, {offset}, {len}, {mode:?}) diverged"
                );
                if real_ok {
                    self.assert_content_matches(path);
                }
            }
            FsOp::FsyncAndCrash { path } => {
                // Deliberately no checkpoint: recovery must then come from
                // per-shard delta-log replay rather than the InoMap walk.
                let _ = resolve(self.pool(), path)
                    .and_then(|(parent, name)| self.pool().lookup(parent, &name).ok().flatten())
                    .map(|ino| self.pool().fsync(ino));
                drop(self.pool.take());
                self.pool = Some(Pool::open(self.dir.path()).unwrap());
            }
            FsOp::CrashAndRemount => {
                self.pool().checkpoint().unwrap();
                drop(self.pool.take());
                self.pool = Some(Pool::open(self.dir.path()).unwrap());
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn real_engine_matches_reference_model(ops in proptest::collection::vec(arb_fs_op(), 1..30)) {
        let mut harness = Harness::new();
        for op in &ops {
            harness.apply(op);
        }
        harness.assert_structurally_sound();
    }
}

/// A few hand-picked sequences, kept as plain `#[test]`s (not proptest
/// cases) specifically so they run every time and show up by name in
/// failure output, covering combinations worth pinning down directly
/// rather than trusting the random generator to hit them.
#[test]
fn hand_picked_hardlink_then_unlink_original() {
    let mut h = Harness::new();
    h.apply(&FsOp::Write { path: PathBuf::from("/a"), offset: 0, data: b"shared".to_vec() });
    h.apply(&FsOp::Link { path: PathBuf::from("/a"), target: PathBuf::from("/b") });
    h.apply(&FsOp::Unlink { path: PathBuf::from("/a") });
    h.assert_content_matches(&PathBuf::from("/b"));
}

#[test]
fn hand_picked_rename_directory_with_nested_file_survives_reopen() {
    let mut h = Harness::new();
    h.apply(&FsOp::Mkdir { path: PathBuf::from("/dir1") });
    h.apply(&FsOp::Write { path: PathBuf::from("/dir1/x"), offset: 0, data: b"hi".to_vec() });
    h.apply(&FsOp::CrashAndRemount);
    h.assert_content_matches(&PathBuf::from("/dir1/x"));
}

/// Total bytes currently occupied by the pool on disk.
fn pool_disk_bytes(root: &Path) -> u64 {
    fn walk(dir: &Path, total: &mut u64) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&e.path(), total);
            } else if let Ok(m) = e.metadata() {
                *total += m.len();
            }
        }
    }
    let mut total = 0;
    walk(root, &mut total);
    total
}

/// The exact shape of the first corruption bug fixed in `58caaf4`: a hole
/// made durable by **fsync** rather than by a checkpoint recovers through
/// per-shard delta-log replay, which materialized `file_state` by
/// concatenating chunks -- collapsing the hole and shifting every later
/// byte. Every sparse test that existed at the time checkpointed, so none
/// of them could reach this path.
///
/// The file is established durably *first* so the crash cannot legitimately
/// lose its directory entry (`fsync(fd)` does not make the entry durable).
#[test]
fn hand_picked_sparse_hole_survives_fsync_then_crash() {
    let mut h = Harness::new();
    let p = PathBuf::from("/a");
    h.apply(&FsOp::Write { path: p.clone(), offset: 0, data: vec![1u8; 64] });
    h.pool().checkpoint().unwrap();
    // Gap of ~4 KiB, far above the 256-byte chunk_min_size, so the zero run
    // is genuinely declined and stored as absence rather than zero chunks.
    h.apply(&FsOp::Write { path: p.clone(), offset: 4096, data: vec![2u8; 64] });
    h.apply(&FsOp::FsyncAndCrash { path: p.clone() });
    h.assert_content_matches(&p);
}

/// Same recovery path, but with the hole produced by `FALLOC_FL_PUNCH_HOLE`
/// rather than by writing past EOF -- punching zeroes an *existing* range,
/// so it exercises the "chunk list gains a gap in the middle" case.
#[test]
fn hand_picked_punched_hole_survives_fsync_then_crash() {
    let mut h = Harness::new();
    let p = PathBuf::from("/a");
    h.apply(&FsOp::Write { path: p.clone(), offset: 0, data: vec![7u8; 4096] });
    h.pool().checkpoint().unwrap();
    h.apply(&FsOp::Fallocate {
        path: p.clone(),
        offset: 1024,
        len: 2048,
        mode: FallocateMode::PunchHole,
    });
    h.apply(&FsOp::FsyncAndCrash { path: p.clone() });
    h.assert_content_matches(&p);
}

/// Sparseness is a *storage* property, and every content-based test passes
/// whether or not it holds -- `read` returns zeros for a hole and for a
/// stored run of zeros alike. This pins the property itself.
///
/// Formulated as a *scaling* assertion rather than an absolute size: a hole
/// must cost nothing proportional to its length, so quadrupling it must not
/// measurably change what is stored. An absolute threshold would instead
/// have to encode `INDEX.redb`'s growth and the fixed 64 KiB SUPERBLOCK,
/// neither of which is content -- an earlier draft of this test measured the
/// whole pool directory and "failed" at 694 KB purely on that overhead,
/// while the actual stored content was ~38 KB.
#[test]
fn hand_picked_hole_storage_does_not_scale_with_hole_size() {
    fn segment_bytes_for_hole_at(offset: u64) -> u64 {
        let mut h = Harness::new();
        let p = PathBuf::from("/a");
        h.apply(&FsOp::Write { path: p.clone(), offset: 0, data: vec![3u8; 512] });
        h.apply(&FsOp::Write { path: p.clone(), offset, data: vec![4u8; 512] });
        h.pool().checkpoint().unwrap();
        h.assert_content_matches(&p);
        pool_disk_bytes(&h.dir.path().join("segments"))
    }

    let small = segment_bytes_for_hole_at(1024 * 1024);
    let large = segment_bytes_for_hole_at(4 * 1024 * 1024);
    // Were the zero run stored, the extra 3 MiB would add ~3000 ChunkRefs
    // to the IndirectHashList in the meta segment (>100 KiB), far outside
    // this slack.
    assert!(
        large <= small + 16 * 1024,
        "quadrupling the hole grew stored segment bytes {small} -> {large}; \
         the all-zero run is evidently being stored rather than declined"
    );
}

/// Regression: the minimal case the widened generator found. A zero-length
/// write must return success and change nothing -- in particular it must not
/// extend the file to `offset`. POSIX says write(2) with count 0 "may have
/// no other results" for a regular file; the engine has an explicit early
/// return for it, and the reference model used to `resize(offset + 0)`
/// instead, fabricating a 1-byte file.
///
/// Kept as a named test rather than left to a proptest seed file: this is a
/// specific documented POSIX behaviour, and it deserves to fail by name.
#[test]
fn hand_picked_zero_length_write_does_not_extend_the_file() {
    let mut h = Harness::new();
    let p = PathBuf::from("/a");
    h.apply(&FsOp::Write { path: p.clone(), offset: 1, data: Vec::new() });

    // The file exists (created by the open), but is empty on both sides.
    let (parent, name) = resolve(h.pool(), &p).unwrap();
    let ino = h.pool().lookup(parent, &name).unwrap().unwrap();
    assert_eq!(h.pool().getattr(ino).unwrap().size, 0);
    assert_eq!(h.model.file_len(&p), Some(0));
    h.assert_content_matches(&p);
}
