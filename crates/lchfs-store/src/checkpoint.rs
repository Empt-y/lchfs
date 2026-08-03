//! The global Checkpoint Coordinator. ARCHITECTURE.md §3 (the 5-step
//! process) and §5 ("foreground-critical durability, runs every epoch,
//! not idle-cycle" — distinct from the Coalescing Daemon and Dedup Index
//! Scanner, which are both idle-cycle background work).
//!
//! The actual 5-step checkpoint logic lives in `PoolShared::run_checkpoint`
//! (lib.rs), not here: it's already tightly coupled to `Pool`'s internals
//! (every lock it needs to take), and re-threading `Arc`s to move it here
//! would add plumbing with no functional benefit. `Pool` spawns its
//! periodic checkpoint tick via `crate::background::PeriodicTask`, the
//! same generic timer wrapper the Coalescing Daemon and Dedup Index
//! Scanner also use — see that module for why it's shared rather than
//! duplicated three times.
