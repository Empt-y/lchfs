//! Generic periodic background-thread wrapper, shared by the three
//! background daemons (ARCHITECTURE.md §5): the Checkpoint Coordinator
//! (checkpoint.rs, foreground-critical, every epoch), the Coalescing
//! Daemon (coalesce.rs, idle-cycle), and the Dedup Index Scanner
//! (dedup.rs, idle-cycle). All three need the same shape -- run a
//! callback on a timer until shutdown, waking promptly rather than
//! sleeping out a full interval -- so it lives here once instead of
//! three times.

use parking_lot::{Condvar, Mutex};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct PeriodicTask {
    shutdown: Arc<AtomicBool>,
    wake: Arc<(Mutex<()>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl PeriodicTask {
    /// Spawns a background thread named `name`, calling `tick` every
    /// `interval` until dropped or `shutdown()`'d. Waking is edge-
    /// triggered via a `Condvar` (not a raw sleep) so shutdown doesn't
    /// wait out a full idle interval — matters for keeping test teardown
    /// fast, especially for the longer idle-cycle intervals (Coalesce/
    /// Dedup) versus the 5s checkpoint interval.
    pub fn spawn(
        name: &'static str,
        interval: Duration,
        mut tick: impl FnMut() + Send + 'static,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let wake = Arc::new((Mutex::new(()), Condvar::new()));

        let thread_shutdown = Arc::clone(&shutdown);
        let thread_wake = Arc::clone(&wake);
        let handle = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Acquire) {
                    let (lock, cvar) = &*thread_wake;
                    let mut guard = lock.lock();
                    cvar.wait_for(&mut guard, interval);
                    drop(guard);
                    if thread_shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    tick();
                }
            })
            .expect("spawn background thread");

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

impl Drop for PeriodicTask {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.shutdown();
        }
    }
}
