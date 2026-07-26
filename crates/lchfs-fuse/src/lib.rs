//! FUSE3 frontend. ARCHITECTURE.md §5a: this crate is a thin protocol
//! adapter over `lchfs_store::Pool` and must contain no filesystem logic
//! of its own -- every operation should be a direct translation of a FUSE
//! callback into a `Pool` method call.
//!
//! ARCHITECTURE.md §9 lists the Phase 1 POSIX/FUSE surface: lookup,
//! getattr, setattr, read, write, open, release, flush,
//! readdir/readdirplus, mkdir, rmdir, unlink, rename, symlink, readlink,
//! link, fsync/fsyncdir, forget/batch_forget, statfs. `fuser::Filesystem`
//! provides ENOSYS-returning defaults for everything, so this scaffold's
//! empty `impl` compiles as-is; Phase D overrides the methods above.

pub mod handles;
pub mod inodes;

pub use handles::FileHandleTable;
pub use inodes::InodeAllocator;

use lchfs_store::Pool;
use std::sync::Arc;

/// The `fuser::Filesystem` implementation. Holds a `Pool` handle and
/// nothing else that could count as filesystem logic -- routing an inode
/// to its logical shard, chunking, hashing, etc. all live in
/// `lchfs-store`/`lchfs-chunk`/`lchfs-crypto`, not here.
// Fields are unused until Phase D wires up the actual fuser::Filesystem
// method overrides (see the TODO below); allowed explicitly rather than
// left as a stray warning.
#[allow(dead_code)]
pub struct LchfsFilesystem {
    pool: Arc<Pool>,
    handles: FileHandleTable,
    inodes: InodeAllocator,
}

impl LchfsFilesystem {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            handles: FileHandleTable::default(),
            inodes: InodeAllocator::default(),
        }
    }
}

// TODO(phase-D): override lookup, getattr, setattr, read, write, open,
// release, flush, readdir/readdirplus, mkdir, rmdir, unlink, rename,
// symlink, readlink, link, fsync/fsyncdir, forget/batch_forget, statfs
// (ARCHITECTURE.md §9) -- each should be a short translation into a
// `Pool` call plus fuser reply plumbing, nothing more.
impl fuser::Filesystem for LchfsFilesystem {}
