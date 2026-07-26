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

/// A `proptest::strategy::Strategy` producing arbitrary `FsOp` sequences.
/// TODO(phase-F): implement via `proptest::prop_oneof!` over a bounded
/// namespace of paths so generated sequences actually exercise shared
/// state (renames onto existing files, etc.) rather than never colliding.
pub fn arb_fs_op() -> impl proptest::strategy::Strategy<Value = FsOp> {
    use proptest::prelude::*;
    // Placeholder single-case strategy; real generator composes prop_oneof!
    // over all FsOp variants per the doc comment above.
    Just(FsOp::CrashAndRemount)
}
