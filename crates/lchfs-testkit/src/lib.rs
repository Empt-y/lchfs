//! Test support, dev-dependency only. ARCHITECTURE.md §10: in-memory
//! reference model (oracle), proptest op generators, and a crash-injecting
//! `StorageBackend` wrapper for crash-consistency testing.

pub mod crash_backend;
pub mod ops;
pub mod reference_model;

pub use crash_backend::CrashInjectingBackend;
pub use ops::{arb_fs_op, FsOp};
pub use reference_model::{ModelError, ReferenceModel};
