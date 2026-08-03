//! The global Checkpoint Coordinator. ARCHITECTURE.md §3 (the 5-step
//! process) and §5 ("foreground-critical durability, runs every epoch,
//! not idle-cycle" — distinct from the Coalescing Daemon and Dedup Index
//! Scanner, which are both idle-cycle background work).
//!
//! A thin background-thread timer wrapper, not a relocation of the actual
//! 5-step checkpoint logic: that logic (`PoolShared::run_checkpoint` in
//! lib.rs) is already tightly coupled to `Pool`'s internals (every lock it
//! needs to take), and re-threading `Arc`s to move it here would add
//! plumbing with no functional benefit. This module's only job is the
//! periodic-timer plumbing itself, generic over the actual epoch callback
//! so it carries no dependency on `PoolShared` at all.

use parking_lot::{Condvar, Mutex};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Single thread running the periodic global checkpoint (default every
/// 5s, or on unmount, or on explicit consolidation). ARCHITECTURE.md §3.
pub struct CheckpointCoordinator {
    shutdown: Arc<AtomicBool>,
    wake: Arc<(Mutex<()>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl CheckpointCoordinator {
    /// Spawns the background thread, calling `run_epoch` every `interval`
    /// until dropped or `shutdown()`'d. Waking is edge-triggered via a
    /// `Condvar` (not a raw sleep) so shutdown doesn't wait out a full
    /// idle interval — matters for keeping test teardown fast.
    pub fn spawn(interval: Duration, mut run_epoch: impl FnMut() + Send + 'static) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let wake = Arc::new((Mutex::new(()), Condvar::new()));

        let thread_shutdown = Arc::clone(&shutdown);
        let thread_wake = Arc::clone(&wake);
        let handle = std::thread::Builder::new()
            .name("lchfs-checkpoint".into())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Acquire) {
                    let (lock, cvar) = &*thread_wake;
                    let mut guard = lock.lock();
                    cvar.wait_for(&mut guard, interval);
                    drop(guard);
                    if thread_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    run_epoch();
                }
            })
            .expect("spawn checkpoint thread");

        Self {
            shutdown,
            wake,
            handle: Some(handle),
        }
    }

    /// Signal shutdown and join the thread. Idempotent — safe to call more
    /// than once (a second call is a no-op, `handle` is already taken).
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let (lock, cvar) = &*self.wake;
        {
            let _guard = lock.lock();
            cvar.notify_all();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for CheckpointCoordinator {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.shutdown();
        }
    }
}
