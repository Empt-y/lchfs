//! Crash-injecting `StorageBackend` wrapper. ARCHITECTURE.md §10: "a
//! `StorageBackend` test double that truncates/corrupts only the
//! not-yet-fsync'd tail on command (consistent with the §7
//! device-atomicity assumption)".

use lchfs_store::StorageBackend;
use std::io;

/// Wraps a real `StorageBackend` and, on `inject_crash()`, discards any
/// bytes written since the last `fsync()` -- simulating power loss at
/// exactly the boundary ARCHITECTURE.md §7's recovery invariant relies on.
/// Bytes before that boundary must remain intact; the wrapper must never
/// tear an already-fsync'd write, since that would test a scenario outside
/// the documented device-atomicity assumption, not the recovery logic itself.
pub struct CrashInjectingBackend<B: StorageBackend> {
    inner: B,
    // TODO(phase-F): track bytes written since last fsync() to discard on inject_crash()
}

impl<B: StorageBackend> CrashInjectingBackend<B> {
    pub fn new(inner: B) -> Self {
        Self { inner }
    }

    /// Discard all writes since the last `fsync()`, simulating a crash.
    pub fn inject_crash(&mut self) {
        todo!("lchfs-testkit: CrashInjectingBackend::inject_crash — see ARCHITECTURE.md §10")
    }

    pub fn into_inner(self) -> B {
        self.inner
    }
}

impl<B: StorageBackend> StorageBackend for CrashInjectingBackend<B> {
    fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>> {
        self.inner.read_at(offset, len)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        // TODO(phase-F): record this range as "since last fsync" for inject_crash()
        self.inner.write_at(offset, data)
    }

    fn fsync(&self) -> io::Result<()> {
        // TODO(phase-F): clear the "since last fsync" tracking on success
        self.inner.fsync()
    }
}
