//! The places the engine needs something the standard library does not
//! give it the same way on every platform. (Positional I/O and free space
//! moved into `lchfs-device` with format v6.)

/// The owner a freshly created pool's root directory gets.
#[cfg(unix)]
pub(crate) fn current_owner() -> (u32, u32) {
    (nix::unistd::getuid().as_raw(), nix::unistd::getgid().as_raw())
}

/// Windows has no uid/gid. 0/0 means a Unix mount with
/// `DefaultPermissions` needs root (or a `chown`) to write the root
/// directory of a pool created on Windows.
#[cfg(windows)]
pub(crate) fn current_owner() -> (u32, u32) {
    (0, 0)
}
