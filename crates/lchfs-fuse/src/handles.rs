//! Open file handle bookkeeping. FUSE `open()` returns an opaque handle
//! that later `read`/`write`/`release` calls reference; this maps those
//! handles to the inode (and any per-open-file assembly buffer state,
//! ARCHITECTURE.md §3 step 2) they belong to.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileHandle(pub u64);

#[derive(Default)]
pub struct FileHandleTable {
    open: HashMap<FileHandle, u64>,
    next: u64,
}

impl FileHandleTable {
    pub fn open(&mut self, ino: u64) -> FileHandle {
        self.next += 1;
        let handle = FileHandle(self.next);
        self.open.insert(handle, ino);
        handle
    }

    pub fn ino_for(&self, handle: FileHandle) -> Option<u64> {
        self.open.get(&handle).copied()
    }

    pub fn close(&mut self, handle: FileHandle) {
        self.open.remove(&handle);
    }
}
