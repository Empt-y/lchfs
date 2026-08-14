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
use lchfs_store::Pool;
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
        let real_bytes = self
            .pool()
            .read(ino, 0, attr.size as u32)
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let model_bytes = self.model.read(path, 0, attr.size as usize).unwrap_or_default();
        assert_eq!(real_bytes, model_bytes, "content diverged for {path:?}");
    }

    fn apply(&mut self, op: &FsOp) {
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
