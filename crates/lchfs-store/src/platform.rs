//! The few places the engine needs something the standard library does not
//! give it the same way on every platform: positional file I/O, the host
//! filesystem's free space, and who "the current user" is.

use std::io;
use std::path::Path;

/// Positional reads and writes that leave no shared cursor to race on
/// (re-exported for lchfs-fsck, which reads segments the same way).
#[cfg(unix)]
pub use std::os::unix::fs::FileExt;

/// `std::os::unix::fs::FileExt`'s two methods the engine uses, over
/// Windows' `seek_read`/`seek_write`. Those move the handle's cursor as a
/// side effect, which is harmless here: every engine file is only ever
/// accessed positionally.
#[cfg(windows)]
pub trait FileExt {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;
}

#[cfg(windows)]
impl FileExt for std::fs::File {
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt as _;
        while !buf.is_empty() {
            match self.seek_read(buf, offset) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer")),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // A read starting at or past the end fails with
                // ERROR_HANDLE_EOF rather than returning 0.
                Err(e) if e.raw_os_error() == Some(38) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt as _;
        while !buf.is_empty() {
            match self.seek_write(buf, offset) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer")),
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

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

/// Space on the filesystem holding `path`, in `statvfs` terms.
pub(crate) struct DiskSpace {
    pub block_size: u32,
    pub fragment_size: u32,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
}

#[cfg(unix)]
pub(crate) fn disk_space(path: &Path) -> io::Result<DiskSpace> {
    let vfs = nix::sys::statvfs::statvfs(path).map_err(io::Error::from)?;
    Ok(DiskSpace {
        block_size: vfs.block_size() as u32,
        fragment_size: vfs.fragment_size() as u32,
        blocks: vfs.blocks() as u64,
        blocks_free: vfs.blocks_free() as u64,
        blocks_available: vfs.blocks_available() as u64,
    })
}

/// Windows reports bytes rather than blocks; they are given here in 4 KiB
/// units, NTFS's usual cluster size. (Through `fs4` so this crate stays
/// free of `unsafe`.)
#[cfg(windows)]
pub(crate) fn disk_space(path: &Path) -> io::Result<DiskSpace> {
    const BLOCK: u64 = 4096;
    Ok(DiskSpace {
        block_size: BLOCK as u32,
        fragment_size: BLOCK as u32,
        blocks: fs4::total_space(path)? / BLOCK,
        blocks_free: fs4::free_space(path)? / BLOCK,
        blocks_available: fs4::available_space(path)? / BLOCK,
    })
}
