//! Proptest op generators. ARCHITECTURE.md §10: random operation
//! sequences (write/truncate/mkdir/rename/unlink/link/symlink/fsync/
//! "crash-and-remount") run in parallel against the real engine and the
//! reference model.

use std::path::PathBuf;

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
    /// Simulate a crash (via `CrashInjectingBackend`) followed by a cold
    /// remount -- exercises the ARCHITECTURE.md §7 recovery path.
    CrashAndRemount,
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
    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)
}

/// A `proptest::strategy::Strategy` producing arbitrary `FsOp`s, drawn
/// from `PATH_NAMESPACE` per this module's doc comment.
pub fn arb_fs_op() -> impl proptest::strategy::Strategy<Value = FsOp> {
    use proptest::prelude::*;
    prop_oneof![
        (arb_path(), 0u64..256, arb_data())
            .prop_map(|(path, offset, data)| FsOp::Write { path, offset, data }),
        (arb_path(), 0u64..256).prop_map(|(path, len)| FsOp::Truncate { path, len }),
        arb_path().prop_map(|path| FsOp::Mkdir { path }),
        (arb_path(), arb_path()).prop_map(|(from, to)| FsOp::Rename { from, to }),
        arb_path().prop_map(|path| FsOp::Unlink { path }),
        (arb_path(), arb_path()).prop_map(|(path, target)| FsOp::Link { path, target }),
        (arb_path(), arb_path()).prop_map(|(path, target)| FsOp::Symlink { path, target }),
        arb_path().prop_map(|path| FsOp::Fsync { path }),
        Just(FsOp::CrashAndRemount),
    ]
}
