//! Crash-injecting `StorageBackend` wrapper. ARCHITECTURE.md §10: "a
//! `StorageBackend` test double that truncates/corrupts only the
//! not-yet-fsync'd tail on command (consistent with the §7
//! device-atomicity assumption)".
//!
//! `StorageBackend` is deliberately scoped to just the fixed-size
//! SUPERBLOCK file (see lchfs-store's `backend.rs` doc comment); segment
//! files are written directly, outside this trait. So this wrapper's
//! reach is exactly the same: it simulates a crash mid-superblock-commit,
//! not a torn segment write (Phase E's `crash_recovery.rs` tests already
//! cover segment/delta-log crash scenarios, via direct file truncation --
//! see that file's own tests for why a `StorageBackend`-level wrapper
//! isn't needed there).

use lchfs_store::StorageBackend;
use std::io;
use std::sync::Mutex;

/// Wraps a real `StorageBackend` and, on `inject_crash()`, reverts every
/// byte range written since the last `fsync()` back to what it held
/// *before* that write -- simulating power loss at exactly the boundary
/// ARCHITECTURE.md §7's recovery invariant relies on. Bytes already
/// durable as of the last `fsync()` must remain intact; the wrapper must
/// never touch anything outside the not-yet-synced tail, since that would
/// test a scenario outside the documented device-atomicity assumption,
/// not the recovery logic itself.
///
/// The superblock is fixed-size and randomly addressed (not an append-only
/// log), so "discard the tail" means "read-before-write every offset
/// touched since the last fsync, then replay those original bytes back in
/// reverse order on crash" -- reverse order so an offset written twice in
/// one epoch is restored to its state *before either* write, not a stale
/// mid-sequence snapshot.
pub struct CrashInjectingBackend<B: StorageBackend> {
    inner: B,
    since_fsync: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl<B: StorageBackend> CrashInjectingBackend<B> {
    pub fn new(inner: B) -> Self {
        Self { inner, since_fsync: Mutex::new(Vec::new()) }
    }

    /// Discard all writes since the last `fsync()`, simulating a crash.
    /// `&self`, not `&mut self`, matching `StorageBackend`'s own
    /// interior-mutability convention (its methods all take `&self`,
    /// since the real `FileBackend` mutates through a plain `File`).
    pub fn inject_crash(&self) {
        let mut pending = self.since_fsync.lock().expect("CrashInjectingBackend lock poisoned");
        for (offset, original) in pending.drain(..).rev() {
            let _ = self.inner.write_at(offset, &original);
        }
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
        // Snapshot what's there *before* this write, so inject_crash()
        // can restore it. Must happen before the real write, and must
        // fail the whole call (never silently write un-trackably) if the
        // read fails -- an untracked write would make a later
        // inject_crash() wrongly "durable" past where it should be.
        let original = self.inner.read_at(offset, data.len() as u32)?;
        self.inner.write_at(offset, data)?;
        self.since_fsync
            .lock()
            .expect("CrashInjectingBackend lock poisoned")
            .push((offset, original));
        Ok(())
    }

    fn fsync(&self) -> io::Result<()> {
        self.inner.fsync()?;
        self.since_fsync.lock().expect("CrashInjectingBackend lock poisoned").clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// A trivial in-memory `StorageBackend` for testing the wrapper
    /// itself, without touching a real file.
    struct MemBackend {
        bytes: StdMutex<Vec<u8>>,
    }

    impl MemBackend {
        fn new(len: usize) -> Self {
            Self { bytes: StdMutex::new(vec![0u8; len]) }
        }
    }

    impl StorageBackend for MemBackend {
        fn read_at(&self, offset: u64, len: u32) -> io::Result<Vec<u8>> {
            let bytes = self.bytes.lock().unwrap();
            let start = offset as usize;
            let end = start + len as usize;
            Ok(bytes[start..end].to_vec())
        }

        fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            let mut bytes = self.bytes.lock().unwrap();
            let start = offset as usize;
            bytes[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }

        fn fsync(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn crash_before_any_write_is_a_no_op() {
        let backend = CrashInjectingBackend::new(MemBackend::new(16));
        backend.write_at(0, b"durable!").unwrap();
        backend.fsync().unwrap();
        backend.inject_crash();
        assert_eq!(backend.read_at(0, 8).unwrap(), b"durable!");
    }

    #[test]
    fn crash_discards_writes_since_last_fsync() {
        let backend = CrashInjectingBackend::new(MemBackend::new(16));
        backend.write_at(0, b"durable!").unwrap();
        backend.fsync().unwrap();

        backend.write_at(8, b"volatile").unwrap();
        // Not fsync'd yet.
        backend.inject_crash();

        assert_eq!(backend.read_at(0, 8).unwrap(), b"durable!");
        assert_eq!(backend.read_at(8, 8).unwrap(), vec![0u8; 8]);
    }

    #[test]
    fn crash_restores_a_double_written_offset_to_its_pre_epoch_state() {
        let backend = CrashInjectingBackend::new(MemBackend::new(8));
        backend.write_at(0, b"epoch_01").unwrap();
        backend.fsync().unwrap();

        // Two writes to the same offset in the same not-yet-synced epoch.
        backend.write_at(0, b"attempt1").unwrap();
        backend.write_at(0, b"attempt2").unwrap();
        backend.inject_crash();

        // Must land back on the last *fsync'd* value, not "attempt1"
        // (a naive single-snapshot-per-offset implementation would stop
        // there instead of unwinding all the way back).
        assert_eq!(backend.read_at(0, 8).unwrap(), b"epoch_01");
    }

    #[test]
    fn fsync_clears_the_undo_log_so_a_later_crash_keeps_the_synced_write() {
        let backend = CrashInjectingBackend::new(MemBackend::new(8));
        backend.write_at(0, b"epoch_01").unwrap();
        backend.fsync().unwrap();
        backend.write_at(0, b"epoch_02").unwrap();
        backend.fsync().unwrap();

        backend.inject_crash();

        assert_eq!(backend.read_at(0, 8).unwrap(), b"epoch_02");
    }
}
