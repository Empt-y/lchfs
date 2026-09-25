//! Windows frontend for LCHFS: serves a pool as a drive letter (or an NTFS
//! folder) through [WinFsp](https://winfsp.dev), the Windows counterpart
//! of FUSE. The kernel side is WinFsp's own signed driver; this crate is
//! the user-mode file system it talks to, and -- like `lchfs-fuse` and
//! `lchfs-nfs` -- a thin adapter over `lchfs_store::Pool` holding no
//! filesystem logic of its own.
//!
//! - [`fs`] is the translation itself (paths, NTSTATUS, attributes), in
//!   safe Rust, built and tested on every platform.
//! - `ffi` (Windows only) loads WinFsp and wires its callbacks to [`fs`].

pub mod fs;

#[cfg(windows)]
pub mod ffi;
