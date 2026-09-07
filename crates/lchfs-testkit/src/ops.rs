//! Proptest op generators. ARCHITECTURE.md §10: random operation
//! sequences (write/truncate/mkdir/rename/unlink/link/symlink/fsync/
//! "crash-and-remount") run in parallel against the real engine and the
//! reference model.

use std::path::PathBuf;

use lchfs_store::FallocateMode;

/// One filesystem operation in a randomized test sequence.
#[derive(Debug, Clone)]
pub enum FsOp {
    Write { path: PathBuf, offset: u64, data: Vec<u8> },
    Truncate { path: PathBuf, len: u64 },
    Mkdir { path: PathBuf },
    Rename { from: PathBuf, to: PathBuf },
    Unlink { path: PathBuf },
    Link { path: PathBuf, target: PathBuf },
    Symlink { path: PathBuf, target: PathBuf },
    Fsync { path: PathBuf },
    /// `fallocate(2)`. Phase 2's sparse-file work landed with no property
    /// coverage at all -- every sparse test was hand-written -- which is
    /// how two corruption bugs reached `master` before `58caaf4`.
    Fallocate { path: PathBuf, offset: u64, len: u64, mode: FallocateMode },
    /// Simulate a crash (via `CrashInjectingBackend`) followed by a cold
    /// remount -- exercises the ARCHITECTURE.md §7 recovery path.
    CrashAndRemount,
    /// `fsync` then crash+remount with *no* intervening checkpoint.
    ///
    /// Deliberately **not** produced by `arb_fs_op`. The reference model has
    /// no durability concept, and after a non-checkpointing crash a file
    /// whose directory entry was never made durable legitimately disappears
    /// (correct POSIX: `fsync(fd)` does not make the *entry* durable), while
    /// unrelated files legitimately revert to last-checkpoint content.
    /// Asserting equivalence across that boundary would be flaky rather than
    /// correct, so this variant exists for hand-written staged tests, which
    /// can set up a durable baseline first and know exactly what must
    /// survive.
    ///
    /// Deliberately distinct from `CrashAndRemount`, which checkpoints
    /// first. Content made durable by fsync recovers via per-shard
    /// delta-log replay rather than the InoMap walk -- a genuinely
    /// different code path, and the one that carried the first of the two
    /// `58caaf4` corruption bugs. Every sparse test that existed at the
    /// time checkpointed, so none of them could reach it.
    FsyncAndCrash { path: PathBuf },
}

/// A small, fixed namespace of paths -- deliberately *not* fully random
/// strings, so generated op sequences actually collide with and build on
/// each other (a rename onto an existing name, a write into a directory
/// another op just created, ...) rather than almost never touching the
/// same path twice. Includes both top-level and nested paths so `mkdir`
/// followed by an operation *inside* that directory is a realistic,
/// frequent occurrence.
const PATH_NAMESPACE: &[&str] = &["/a", "/b", "/c", "/dir1", "/dir1/x", "/dir1/y", "/dir2", "/dir2/z"];

fn arb_path() -> impl proptest::strategy::Strategy<Value = PathBuf> {
    use proptest::strategy::Strategy;
    proptest::sample::select(PATH_NAMESPACE).prop_map(PathBuf::from)
}

fn arb_data() -> impl proptest::strategy::Strategy<Value = Vec<u8>> {
    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)
}

fn arb_fallocate_mode() -> impl proptest::strategy::Strategy<Value = FallocateMode> {
    use proptest::prelude::*;
    prop_oneof![
        any::<bool>().prop_map(|keep_size| FallocateMode::Allocate { keep_size }),
        Just(FallocateMode::PunchHole),
        any::<bool>().prop_map(|keep_size| FallocateMode::ZeroRange { keep_size }),
    ]
}

/// A `proptest::strategy::Strategy` producing arbitrary `FsOp`s, drawn
/// from `PATH_NAMESPACE` per this module's doc comment.
pub fn arb_fs_op() -> impl proptest::strategy::Strategy<Value = FsOp> {
    use proptest::prelude::*;
    prop_oneof![
        (arb_path(), 0u64..8192, arb_data())
            .prop_map(|(path, offset, data)| FsOp::Write { path, offset, data }),
        (arb_path(), 0u64..8192).prop_map(|(path, len)| FsOp::Truncate { path, len }),
        (arb_path(), 0u64..8192, 0u64..4096, arb_fallocate_mode())
            .prop_map(|(path, offset, len, mode)| FsOp::Fallocate { path, offset, len, mode }),
        arb_path().prop_map(|path| FsOp::Mkdir { path }),
        (arb_path(), arb_path()).prop_map(|(from, to)| FsOp::Rename { from, to }),
        arb_path().prop_map(|path| FsOp::Unlink { path }),
        (arb_path(), arb_path()).prop_map(|(path, target)| FsOp::Link { path, target }),
        (arb_path(), arb_path()).prop_map(|(path, target)| FsOp::Symlink { path, target }),
        arb_path().prop_map(|path| FsOp::Fsync { path }),
        Just(FsOp::CrashAndRemount),
    ]
}
