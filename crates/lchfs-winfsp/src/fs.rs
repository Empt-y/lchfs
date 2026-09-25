//! The Windows view of a pool, in plain Rust: paths, NTSTATUS codes, file
//! attributes and FILETIMEs in, `Pool` calls out. Like `lchfs-fuse`, it
//! holds no filesystem logic of its own -- only the translation. Kept free
//! of FFI so it builds, and is tested, on every platform; `ffi` (Windows
//! only) is the thin layer that hands WinFsp's callbacks to it.
//!
//! Choices Windows forces that FUSE does not:
//!
//! - **Case.** Windows programs expect names to match regardless of case.
//!   A lookup tries the exact name first and falls back to the first entry
//!   equal ignoring case, so two names differing only in case (possible
//!   from Linux) still both open by their exact spelling.
//! - **Symlinks** are Windows symlink reparse points. Windows, not this
//!   module, follows them, so Explorer deletes a link to a directory
//!   without recursing into its target. A relative target is shown with
//!   `\` separators; an absolute one (`/usr/lib`) as drive-root-relative
//!   (`\usr\lib`), i.e. relative to the pool's root. Links can be created
//!   from Windows only with a relative target.
//! - **Attributes** come from the Unix mode: no owner write bit is
//!   `READONLY` (files only -- on a directory Windows reads it as
//!   "customised folder", not "read-only"); a leading dot is `HIDDEN`,
//!   as Samba shows it. Setting `READONLY` clears every write bit and
//!   clearing it restores the owner's; other attributes are not stored.
//! - **Deletion** happens when the last handle closes (`delete`), the way
//!   Windows' delete-on-close works, after `can_delete` has vetted it.

use lchfs_format::{InodeKind, InodeObject};
use lchfs_store::{Pool, PoolError};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The pool's root directory's inode number.
pub const ROOT_INO: u64 = 1;

/// Symlinks followed, at most, while working out whether one ends at a
/// directory -- Linux's own limit.
const MAX_SYMLINK_HOPS: usize = 40;

/// What `SectorSize * SectorsPerAllocationUnit` reports, and what
/// `AllocationSize` is rounded to. lchfs has no allocation unit of its own.
pub const ALLOCATION_UNIT: u64 = 4096;

/// NTSTATUS values used here (ntstatus.h).
pub mod status {
    pub type NtStatus = i32;
    pub const SUCCESS: NtStatus = 0;
    pub const BUFFER_OVERFLOW: NtStatus = 0x8000_0005_u32 as i32;
    pub const DEVICE_BUSY: NtStatus = 0x8000_0011_u32 as i32;
    pub const INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010_u32 as i32;
    pub const END_OF_FILE: NtStatus = 0xC000_0011_u32 as i32;
    pub const INVALID_PARAMETER: NtStatus = 0xC000_000D_u32 as i32;
    pub const ACCESS_DENIED: NtStatus = 0xC000_0022_u32 as i32;
    pub const OBJECT_NAME_INVALID: NtStatus = 0xC000_0033_u32 as i32;
    pub const OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034_u32 as i32;
    pub const OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035_u32 as i32;
    pub const OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000_003A_u32 as i32;
    pub const DISK_FULL: NtStatus = 0xC000_007F_u32 as i32;
    pub const MEDIA_WRITE_PROTECTED: NtStatus = 0xC000_00A2_u32 as i32;
    pub const FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BA_u32 as i32;
    pub const UNEXPECTED_IO_ERROR: NtStatus = 0xC000_00E9_u32 as i32;
    pub const DIRECTORY_NOT_EMPTY: NtStatus = 0xC000_0101_u32 as i32;
    pub const FILE_CORRUPT_ERROR: NtStatus = 0xC000_0102_u32 as i32;
    pub const NOT_A_DIRECTORY: NtStatus = 0xC000_0103_u32 as i32;
    pub const NAME_TOO_LONG: NtStatus = 0xC000_0106_u32 as i32;
    pub const FILE_TOO_LARGE: NtStatus = 0xC000_0904_u32 as i32;
    pub const NOT_A_REPARSE_POINT: NtStatus = 0xC000_0275_u32 as i32;
    pub const IO_REPARSE_DATA_INVALID: NtStatus = 0xC000_0278_u32 as i32;
}
use status::NtStatus;

pub type Result<T> = std::result::Result<T, NtStatus>;

/// `FILE_ATTRIBUTE_*` (winnt.h).
pub mod attr {
    pub const READONLY: u32 = 0x1;
    pub const HIDDEN: u32 = 0x2;
    pub const DIRECTORY: u32 = 0x10;
    pub const ARCHIVE: u32 = 0x20;
    pub const REPARSE_POINT: u32 = 0x400;
    /// `SetBasicInfo`'s "leave the attributes alone".
    pub const INVALID: u32 = u32::MAX;
}

/// `IO_REPARSE_TAG_SYMLINK`.
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// `SYMLINK_FLAG_RELATIVE`.
const SYMLINK_FLAG_RELATIVE: u32 = 1;
/// Header of a symlink `REPARSE_DATA_BUFFER`, up to `PathBuffer`.
const SYMLINK_HEADER: usize = 20;
/// Tag, data length and reserved: what `ReparseDataLength` does not count.
const REPARSE_HEADER: usize = 8;

pub fn status_for(err: &PoolError) -> NtStatus {
    match err {
        PoolError::NoSuchInode(_) | PoolError::NotFound(_) => status::OBJECT_NAME_NOT_FOUND,
        PoolError::NotADirectory(_) => status::NOT_A_DIRECTORY,
        PoolError::AlreadyExists(_) => status::OBJECT_NAME_COLLISION,
        PoolError::IsADirectory(_) => status::FILE_IS_A_DIRECTORY,
        PoolError::NotEmpty(_) => status::DIRECTORY_NOT_EMPTY,
        PoolError::TooLarge(_) => status::FILE_TOO_LARGE,
        PoolError::NotASymlink(_) => status::NOT_A_REPARSE_POINT,
        // Extended attributes are not exposed to Windows, so no call made
        // here can meet this.
        PoolError::NoSuchXattr(_) => status::OBJECT_NAME_NOT_FOUND,
        PoolError::InvalidArgument(_) => status::INVALID_PARAMETER,
        PoolError::Io(e) if e.kind() == std::io::ErrorKind::StorageFull => status::DISK_FULL,
        // A hash or seal that does not verify is corrupt data, not a
        // failed transfer: say so, as NTFS does for a bad record.
        PoolError::IntegrityFailure(_) | PoolError::Sealed(_) => status::FILE_CORRUPT_ERROR,
        PoolError::Io(_) | PoolError::Format(_) | PoolError::Index(_) => status::UNEXPECTED_IO_ERROR,
        PoolError::PoolLocked(_) => status::DEVICE_BUSY,
        // Only reachable while opening a pool, before anything is mounted.
        PoolError::UnsupportedFormatVersion { .. }
        | PoolError::LegacyFormatVersion { .. }
        | PoolError::KeyRequired
        | PoolError::Keyring(_)
        | PoolError::KeyringChange(_) => status::INVALID_PARAMETER,
    }
}

fn st<T>(r: std::result::Result<T, PoolError>) -> Result<T> {
    r.map_err(|e| status_for(&e))
}

/// Seconds between 1601-01-01 (FILETIME's epoch) and 1970-01-01.
const EPOCH_DELTA_SECS: i64 = 11_644_473_600;

/// Unix `(secs, nanos)` as a FILETIME: 100 ns ticks since 1601. Clamped
/// to 0 before 1601.
pub fn filetime((secs, nanos): (i64, u32)) -> u64 {
    let ticks = (secs as i128 + EPOCH_DELTA_SECS as i128) * 10_000_000 + (nanos / 100) as i128;
    ticks.clamp(0, u64::MAX as i128) as u64
}

pub fn unix_time(filetime: u64) -> (i64, u32) {
    let secs = (filetime / 10_000_000) as i64 - EPOCH_DELTA_SECS;
    let nanos = (filetime % 10_000_000) as u32 * 100;
    (secs, nanos)
}

/// `FSP_FSCTL_FILE_INFO`, minus the fields lchfs always leaves zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub attributes: u32,
    pub reparse_tag: u32,
    pub allocation_size: u64,
    pub file_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub index_number: u64,
}

/// One entry for a directory listing.
#[derive(Debug, Clone)]
pub struct DirItem {
    pub name: String,
    pub info: FileInfo,
}

/// What an open handle refers to. The inode can change under a live
/// handle exactly once: when `set_symlink` turns the empty file it was
/// created as into a symlink. Where it lives -- its directory, and whether
/// its name makes it hidden -- is kept up to date by `rename`, so file
/// info never needs a directory scan.
#[derive(Debug)]
pub struct Handle {
    ino: AtomicU64,
    is_dir: bool,
    /// The directory it was opened through; `ROOT_INO` for the root.
    parent: AtomicU64,
    hidden: AtomicBool,
}

impl Handle {
    fn new(ino: u64, is_dir: bool, parent: u64, name: &str) -> Self {
        Self {
            ino: AtomicU64::new(ino),
            is_dir,
            parent: AtomicU64::new(parent),
            hidden: AtomicBool::new(name.starts_with('.')),
        }
    }

    pub fn ino(&self) -> u64 {
        self.ino.load(Ordering::Acquire)
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
}

/// `CreateOptions` bits (ntioapi.h) the open and create paths look at.
pub const FILE_DIRECTORY_FILE: u32 = 0x1;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x40;

/// A mounted pool as Windows sees it.
pub struct Volume {
    pool: Arc<Pool>,
    read_only: bool,
}

/// The path components of a WinFsp file name (`\dir\file`).
fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('\\').filter(|c| !c.is_empty())
}

/// `(parent path, final name)`; `None` for the root.
fn split_last(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('\\');
    let at = trimmed.rfind('\\')?;
    let name = &trimmed[at + 1..];
    (!name.is_empty()).then(|| (&trimmed[..at], name))
}

impl Volume {
    pub fn new(pool: Arc<Pool>, read_only: bool) -> Self {
        Self { pool, read_only }
    }

    pub fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    fn writable(&self) -> Result<()> {
        if self.read_only { Err(status::MEDIA_WRITE_PROTECTED) } else { Ok(()) }
    }

    /// The entry `name` in directory `dir`: exact match first, else the
    /// first one equal ignoring case. `(ino, name as stored)`.
    fn lookup(&self, dir: u64, name: &str) -> Result<Option<(u64, String)>> {
        if let Some(ino) = st(self.pool.lookup(dir, name))? {
            return Ok(Some((ino, name.to_owned())));
        }
        let lower = name.to_lowercase();
        Ok(st(self.pool.readdir(dir))?
            .into_iter()
            .find(|e| e.name.to_lowercase() == lower)
            .map(|e| (e.ino, e.name)))
    }

    /// The inode `path` names, following no symlinks: a symlink as the
    /// last component is the link itself. One met before that is
    /// `OBJECT_PATH_NOT_FOUND` -- WinFsp resolves those itself, having
    /// asked `reparse_point_at` about every prefix first.
    pub fn resolve(&self, path: &str) -> Result<u64> {
        let mut ino = ROOT_INO;
        let mut parts = components(path).peekable();
        while let Some(part) = parts.next() {
            let last = parts.peek().is_none();
            let not_found = if last { status::OBJECT_NAME_NOT_FOUND } else { status::OBJECT_PATH_NOT_FOUND };
            let dir = st(self.pool.getattr(ino))?;
            if dir.kind != InodeKind::Directory {
                return Err(status::OBJECT_PATH_NOT_FOUND);
            }
            ino = self.lookup(ino, part)?.ok_or(not_found)?.0;
        }
        Ok(ino)
    }

    /// Where a symlink in directory `dir` leads, followed to the end
    /// inside the pool; `None` if it dangles, loops, or leaves the pool.
    fn follow(&self, dir: u64, target: &str) -> Option<u64> {
        let mut hops = 0;
        let mut cur = if target.starts_with('/') { ROOT_INO } else { dir };
        let mut todo: VecDeque<String> = target.split('/').filter(|c| !c.is_empty()).map(str::to_owned).collect();
        while let Some(part) = todo.pop_front() {
            match part.as_str() {
                "." => continue,
                ".." => {
                    cur = self.pool.parent_of(cur).ok()?;
                    continue;
                }
                _ => {}
            }
            let (ino, _) = self.lookup(cur, &part).ok()??;
            let inode = self.pool.getattr(ino).ok()?;
            if inode.kind == InodeKind::Symlink {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return None;
                }
                let next = self.pool.readlink(ino).ok()?;
                if next.starts_with('/') {
                    cur = ROOT_INO;
                }
                for c in next.split('/').filter(|c| !c.is_empty()).rev() {
                    todo.push_front(c.to_owned());
                }
            } else {
                cur = ino;
            }
        }
        Some(cur)
    }

    fn info_of(&self, ino: u64, inode: &InodeObject, name: &str, parent: Option<u64>) -> FileInfo {
        let mut attributes = 0;
        let mut reparse_tag = 0;
        match inode.kind {
            InodeKind::Directory => attributes |= attr::DIRECTORY,
            InodeKind::File => {
                attributes |= attr::ARCHIVE;
                if inode.mode & 0o200 == 0 {
                    attributes |= attr::READONLY;
                }
            }
            InodeKind::Symlink => {
                attributes |= attr::REPARSE_POINT;
                reparse_tag = IO_REPARSE_TAG_SYMLINK;
                // Windows tells file and directory links apart by this bit,
                // and opens (or refuses to open) them accordingly.
                let target_is_dir = parent
                    .zip(self.pool.readlink(ino).ok())
                    .and_then(|(dir, target)| self.follow(dir, &target))
                    .and_then(|t| self.pool.getattr(t).ok())
                    .is_some_and(|t| t.kind == InodeKind::Directory);
                if target_is_dir {
                    attributes |= attr::DIRECTORY;
                }
            }
        }
        if name.starts_with('.') {
            attributes |= attr::HIDDEN;
        }
        let file_size = if inode.kind == InodeKind::File { inode.size } else { 0 };
        FileInfo {
            attributes,
            reparse_tag,
            allocation_size: file_size.div_ceil(ALLOCATION_UNIT) * ALLOCATION_UNIT,
            file_size,
            // lchfs keeps no birth time; ctime is the closest, as the FUSE
            // frontend's `crtime` also has it.
            creation_time: filetime(inode.ctime),
            last_access_time: filetime(inode.atime),
            last_write_time: filetime(inode.mtime),
            change_time: filetime(inode.ctime),
            index_number: ino,
        }
    }

    /// File info for an open handle.
    pub fn info(&self, handle: &Handle) -> Result<FileInfo> {
        let ino = handle.ino();
        let inode = st(self.pool.getattr(ino))?;
        let name = if handle.hidden.load(Ordering::Relaxed) { "." } else { "" };
        Ok(self.info_of(ino, &inode, name, Some(handle.parent.load(Ordering::Relaxed))))
    }

    /// `(parent, ino, name as stored)` for `path`; the root is its own
    /// parent, with an empty name.
    fn locate(&self, path: &str) -> Result<(u64, u64, String)> {
        let Some((parent_path, name)) = split_last(path) else {
            return Ok((ROOT_INO, ROOT_INO, String::new()));
        };
        let parent = self.resolve(parent_path).map_err(|e| {
            if e == status::OBJECT_NAME_NOT_FOUND { status::OBJECT_PATH_NOT_FOUND } else { e }
        })?;
        if st(self.pool.getattr(parent))?.kind != InodeKind::Directory {
            return Err(status::OBJECT_PATH_NOT_FOUND);
        }
        let (ino, stored) = self.lookup(parent, name)?.ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        Ok((parent, ino, stored))
    }

    /// File info for a path, without opening it (`GetSecurityByName`).
    pub fn info_at(&self, path: &str) -> Result<FileInfo> {
        let (parent, ino, name) = self.locate(path)?;
        let inode = st(self.pool.getattr(ino))?;
        Ok(self.info_of(ino, &inode, &name, Some(parent)))
    }

    pub fn open(&self, path: &str, create_options: u32) -> Result<(Handle, FileInfo)> {
        let (parent, ino, name) = self.locate(path)?;
        let inode = st(self.pool.getattr(ino))?;
        let is_dir = inode.kind == InodeKind::Directory;
        if create_options & FILE_DIRECTORY_FILE != 0 && inode.kind == InodeKind::File {
            return Err(status::NOT_A_DIRECTORY);
        }
        if create_options & FILE_NON_DIRECTORY_FILE != 0 && is_dir {
            return Err(status::FILE_IS_A_DIRECTORY);
        }
        let handle = Handle::new(ino, is_dir, parent, &name);
        let info = self.info(&handle)?;
        Ok((handle, info))
    }

    pub fn create(&self, path: &str, create_options: u32, attributes: u32) -> Result<(Handle, FileInfo)> {
        self.writable()?;
        let (parent_path, name) = split_last(path).ok_or(status::OBJECT_NAME_COLLISION)?;
        if name.len() > 255 {
            return Err(status::NAME_TOO_LONG);
        }
        let parent = self.resolve(parent_path).map_err(|e| {
            if e == status::OBJECT_NAME_NOT_FOUND { status::OBJECT_PATH_NOT_FOUND } else { e }
        })?;
        if self.lookup(parent, name)?.is_some() {
            return Err(status::OBJECT_NAME_COLLISION);
        }
        // New entries belong to whoever owns the directory they are made
        // in: Windows callers have no uid, and this keeps a pool shared
        // with Linux writable by its owner there.
        let owner = st(self.pool.getattr(parent))?;
        let is_dir = create_options & FILE_DIRECTORY_FILE != 0;
        let mut mode = if is_dir { 0o755 } else { 0o644 };
        if !is_dir && attributes != attr::INVALID && attributes & attr::READONLY != 0 {
            mode &= !0o222;
        }
        let ino = if is_dir {
            st(self.pool.mkdir_as(parent, name, mode, owner.uid, owner.gid))?
        } else {
            st(self.pool.create_file_as(parent, name, mode, owner.uid, owner.gid))?
        };
        let handle = Handle::new(ino, is_dir, parent, name);
        let info = self.info(&handle)?;
        Ok((handle, info))
    }

    /// `FILE_OVERWRITE`/`FILE_SUPERSEDE` on an existing file: empty it, and
    /// take the caller's attributes.
    pub fn overwrite(&self, handle: &Handle, attributes: u32, replace_attributes: bool) -> Result<FileInfo> {
        self.writable()?;
        st(self.pool.set_size(handle.ino(), 0))?;
        if replace_attributes || attributes & attr::READONLY != 0 {
            self.apply_readonly(handle, attributes & attr::READONLY != 0)?;
        }
        self.info(handle)
    }

    fn apply_readonly(&self, handle: &Handle, readonly: bool) -> Result<()> {
        let inode = st(self.pool.getattr(handle.ino()))?;
        if inode.kind != InodeKind::File {
            return Ok(());
        }
        let mode = if readonly { inode.mode & !0o222 } else { inode.mode | 0o200 };
        if mode != inode.mode {
            st(self.pool.set_attr(handle.ino(), Some(mode), None, None, None, None))?;
        }
        Ok(())
    }

    /// Reads into `buf`; the byte count. At or past the end of the file is
    /// `END_OF_FILE`, as Windows expects.
    pub fn read(&self, handle: &Handle, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let size = st(self.pool.getattr(handle.ino()))?.size;
        if offset >= size {
            return Err(status::END_OF_FILE);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let bytes = st(self.pool.read(handle.ino(), offset, len))?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    /// Writes `data`; the byte count and the file's new info.
    /// `write_to_end` appends; `constrained` (paging I/O) must not grow the
    /// file, so what would lie past its end is dropped.
    pub fn write(
        &self,
        handle: &Handle,
        offset: u64,
        data: &[u8],
        write_to_end: bool,
        constrained: bool,
    ) -> Result<(usize, FileInfo)> {
        self.writable()?;
        let ino = handle.ino();
        let size = st(self.pool.getattr(ino))?.size;
        let offset = if write_to_end { size } else { offset };
        let data = if constrained {
            if offset >= size {
                return Ok((0, self.info(handle)?));
            }
            &data[..data.len().min((size - offset) as usize)]
        } else {
            data
        };
        if !data.is_empty() {
            st(self.pool.write(ino, offset, data))?;
        }
        Ok((data.len(), self.info(handle)?))
    }

    /// `FlushFileBuffers` on a file, or on the volume (`None`).
    pub fn flush(&self, handle: Option<&Handle>) -> Result<Option<FileInfo>> {
        match handle {
            Some(h) => {
                st(self.pool.fsync(h.ino()))?;
                self.info(h).map(Some)
            }
            None => st(self.pool.checkpoint()).map(|()| None),
        }
    }

    /// `SetBasicInfo`. A zero time, or `attr::INVALID`, leaves that field
    /// alone. Creation and change times are not settable: lchfs has no
    /// birth time, and ctime is the engine's to keep.
    pub fn set_basic(&self, handle: &Handle, attributes: u32, last_access: u64, last_write: u64) -> Result<FileInfo> {
        self.writable()?;
        if attributes != attr::INVALID {
            self.apply_readonly(handle, attributes & attr::READONLY != 0)?;
        }
        let atime = (last_access != 0).then(|| unix_time(last_access));
        let mtime = (last_write != 0).then(|| unix_time(last_write));
        if atime.is_some() || mtime.is_some() {
            st(self.pool.set_attr(handle.ino(), None, None, None, atime, mtime))?;
        }
        self.info(handle)
    }

    /// `SetFileSize`. An allocation size only matters when it is below the
    /// file size, which truncates; lchfs allocates nothing ahead.
    pub fn set_size(&self, handle: &Handle, new_size: u64, allocation: bool) -> Result<FileInfo> {
        self.writable()?;
        let size = st(self.pool.getattr(handle.ino()))?.size;
        if !allocation || new_size < size {
            st(self.pool.set_size(handle.ino(), new_size))?;
        }
        self.info(handle)
    }

    /// Whether the entry a handle was opened by may be deleted when the
    /// handle closes.
    pub fn can_delete(&self, handle: &Handle) -> Result<()> {
        self.writable()?;
        let ino = handle.ino();
        if ino == ROOT_INO {
            return Err(status::ACCESS_DENIED);
        }
        if handle.is_dir() && !st(self.pool.readdir(ino))?.is_empty() {
            return Err(status::DIRECTORY_NOT_EMPTY);
        }
        Ok(())
    }

    /// Removes the entry `path` names (the link, for a symlink).
    pub fn delete(&self, path: &str) -> Result<()> {
        self.writable()?;
        let (parent_path, name) = split_last(path).ok_or(status::ACCESS_DENIED)?;
        let parent = self.resolve(parent_path)?;
        let (ino, stored) = self.lookup(parent, name)?.ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        if st(self.pool.getattr(ino))?.kind == InodeKind::Directory {
            st(self.pool.rmdir(parent, &stored))
        } else {
            st(self.pool.unlink(parent, &stored))
        }
    }

    /// Moves `from` to `to`, and the open `handle` with it. Replacing an
    /// existing directory is refused the way NTFS refuses it; renaming only
    /// the case of a name is allowed even without `replace`.
    pub fn rename(&self, handle: &Handle, from: &str, to: &str, replace: bool) -> Result<()> {
        self.writable()?;
        let (from_parent, from_name) = split_last(from).ok_or(status::ACCESS_DENIED)?;
        let (to_parent, to_name) = split_last(to).ok_or(status::OBJECT_NAME_COLLISION)?;
        if to_name.len() > 255 {
            return Err(status::NAME_TOO_LONG);
        }
        let src_dir = self.resolve(from_parent)?;
        let (src_ino, src_name) = self.lookup(src_dir, from_name)?.ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        let dst_dir = self.resolve(to_parent).map_err(|e| {
            if e == status::OBJECT_NAME_NOT_FOUND { status::OBJECT_PATH_NOT_FOUND } else { e }
        })?;
        let mut replace = replace;
        match self.lookup(dst_dir, to_name)? {
            // `foo` -> `Foo`: the same entry, found through case folding.
            Some((ino, _)) if ino == src_ino && dst_dir == src_dir => replace = true,
            Some((ino, stored)) => {
                if !replace {
                    return Err(status::OBJECT_NAME_COLLISION);
                }
                if st(self.pool.getattr(ino))?.kind == InodeKind::Directory {
                    return Err(status::ACCESS_DENIED);
                }
                // Replace the entry as the pool spells it, not a second one
                // differing only in case.
                if stored != to_name {
                    st(self.pool.unlink(dst_dir, &stored))?;
                }
            }
            None => {}
        }
        st(self.pool.rename(src_dir, &src_name, dst_dir, to_name, !replace))?;
        handle.parent.store(dst_dir, Ordering::Relaxed);
        handle.hidden.store(to_name.starts_with('.'), Ordering::Relaxed);
        Ok(())
    }

    /// A directory's entries, with `.` and `..` for all but the root.
    pub fn list(&self, handle: &Handle) -> Result<Vec<DirItem>> {
        let ino = handle.ino();
        let mut items = Vec::new();
        if ino != ROOT_INO {
            let parent = st(self.pool.parent_of(ino))?;
            for (name, dot) in [(".", ino), ("..", parent)] {
                let inode = st(self.pool.getattr(dot))?;
                let mut info = self.info_of(dot, &inode, "", None);
                info.attributes &= !attr::HIDDEN;
                items.push(DirItem { name: name.to_owned(), info });
            }
        }
        for entry in st(self.pool.readdir(ino))? {
            // An entry removed since the listing was taken is skipped, not
            // an error for the whole directory.
            let Ok(inode) = self.pool.getattr(entry.ino) else { continue };
            let info = self.info_of(entry.ino, &inode, &entry.name, Some(ino));
            items.push(DirItem { name: entry.name, info });
        }
        Ok(items)
    }

    /// The symlink `REPARSE_DATA_BUFFER` for `ino`, or
    /// `NOT_A_REPARSE_POINT`.
    pub fn reparse_data(&self, ino: u64) -> Result<Vec<u8>> {
        let target = match self.pool.readlink(ino) {
            Ok(t) => t,
            Err(PoolError::NotASymlink(_)) => return Err(status::NOT_A_REPARSE_POINT),
            Err(e) => return Err(status_for(&e)),
        };
        Ok(symlink_reparse_buffer(&target))
    }

    /// Whether `path` itself (not following it) is a symlink, and if so its
    /// reparse data. For WinFsp's reparse-point resolution, which walks a
    /// path one prefix at a time.
    pub fn reparse_point_at(&self, path: &str) -> Result<Vec<u8>> {
        self.reparse_data(self.resolve(path)?)
    }

    /// `FSCTL_SET_REPARSE_POINT` on a freshly created, empty file: replaces
    /// it with a symlink of the same name (what `mklink` does). Only
    /// relative symlink targets can be stored.
    pub fn set_symlink(&self, handle: &Handle, path: &str, reparse: &[u8]) -> Result<()> {
        self.writable()?;
        let target = parse_symlink_reparse_buffer(reparse)?;
        let ino = handle.ino();
        let inode = st(self.pool.getattr(ino))?;
        if inode.kind != InodeKind::File || inode.size != 0 {
            return Err(status::INVALID_DEVICE_REQUEST);
        }
        let (parent_path, name) = split_last(path).ok_or(status::ACCESS_DENIED)?;
        let parent = self.resolve(parent_path)?;
        let (_, stored) = self.lookup(parent, name)?.ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        st(self.pool.unlink(parent, &stored))?;
        let link = st(self.pool.symlink_as(parent, &stored, &target, inode.uid, inode.gid))?;
        handle.ino.store(link, Ordering::Release);
        Ok(())
    }

    /// `(total, free)` bytes, for `GetVolumeInfo`.
    pub fn space(&self) -> Result<(u64, u64)> {
        let s = st(self.pool.statfs())?;
        let unit = s.fragment_size.max(1) as u64;
        Ok((s.blocks_total * unit, s.blocks_available * unit))
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A symlink `REPARSE_DATA_BUFFER` for a Unix target. The substitute and
/// print names are the same string: `a/b` becomes `a\b` (relative), and
/// `/a/b` becomes `\a\b`, relative to the root of the drive -- the pool's
/// root, which is the only root a Windows reader can reach it through.
pub fn symlink_reparse_buffer(target: &str) -> Vec<u8> {
    let name: Vec<u16> = utf16(&target.replace('/', "\\"));
    let name_bytes = (name.len() * 2) as u16;
    let data_len = (SYMLINK_HEADER - REPARSE_HEADER) as u16 + 2 * name_bytes;
    let mut buf = Vec::with_capacity(REPARSE_HEADER + data_len as usize);
    buf.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    buf.extend_from_slice(&data_len.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    buf.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
    buf.extend_from_slice(&name_bytes.to_le_bytes()); // SubstituteNameLength
    buf.extend_from_slice(&name_bytes.to_le_bytes()); // PrintNameOffset
    buf.extend_from_slice(&name_bytes.to_le_bytes()); // PrintNameLength
    buf.extend_from_slice(&SYMLINK_FLAG_RELATIVE.to_le_bytes());
    for half in name.iter().chain(name.iter()) {
        buf.extend_from_slice(&half.to_le_bytes());
    }
    buf
}

/// The Unix target of a relative symlink `REPARSE_DATA_BUFFER`. Absolute
/// Windows targets (`\??\C:\...`) point outside the pool and cannot be
/// stored; other reparse types are not symlinks.
pub fn parse_symlink_reparse_buffer(buf: &[u8]) -> Result<String> {
    let u16_at = |at: usize| buf.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| buf.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let tag = u32_at(0).ok_or(status::IO_REPARSE_DATA_INVALID)?;
    if tag != IO_REPARSE_TAG_SYMLINK {
        return Err(status::IO_REPARSE_DATA_INVALID);
    }
    let field = |at| u16_at(at).map(usize::from).ok_or(status::IO_REPARSE_DATA_INVALID);
    let (sub_off, sub_len) = (field(8)?, field(10)?);
    let flags = u32_at(16).ok_or(status::IO_REPARSE_DATA_INVALID)?;
    if flags & SYMLINK_FLAG_RELATIVE == 0 {
        return Err(status::INVALID_DEVICE_REQUEST);
    }
    let start = SYMLINK_HEADER + sub_off;
    let raw = buf.get(start..start + sub_len).ok_or(status::IO_REPARSE_DATA_INVALID)?;
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let target = String::from_utf16(&units).map_err(|_| status::OBJECT_NAME_INVALID)?;
    if target.is_empty() {
        return Err(status::IO_REPARSE_DATA_INVALID);
    }
    Ok(target.replace('\\', "/"))
}
