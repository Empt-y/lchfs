//! FUSE-side inode number glue. The authoritative `next_ino_counter` lives
//! in `RootObject` (lchfs-format, ARCHITECTURE.md §1) and is advanced
//! through `Pool`; this type is just a thin local cache/lookaside for the
//! FUSE frontend, not a second source of truth.

#[derive(Default)]
pub struct InodeAllocator {
    // TODO(phase-D): local cache mirroring Pool-side allocation, if needed at all
}
