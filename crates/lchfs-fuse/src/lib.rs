//! FUSE3 frontend. ARCHITECTURE.md §5a: this crate is a thin protocol
//! adapter over `lchfs_store::Pool` and must contain no filesystem logic
//! of its own -- every operation should be a direct translation of a FUSE
//! callback into a `Pool` method call.
//!
//! ARCHITECTURE.md §9 lists the Phase 1 POSIX/FUSE surface. `Pool` now
//! implements the full list: lookup, getattr, setattr (size only),
//! opendir/readdir, open/read/write/release, create, mkdir, flush/fsync,
//! unlink, rmdir, rename, symlink, readlink, link, statfs. `RENAME_EXCHANGE`
//! (atomic two-way swap) isn't implemented -- rejected with `EINVAL` rather
//! than silently misbehaving; xattrs/flock/ioctl/fallocate stay deferred
//! per ARCHITECTURE.md §9's explicit Phase 2+ list.

pub mod handles;
pub mod inodes;

pub use handles::FileHandleTable;
pub use inodes::InodeAllocator;

use fuser::{
    Errno, FileAttr, FileType, Filesystem, Generation, INodeNo, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    Request,
};
use lchfs_format::{InodeKind, InodeObject};
use lchfs_store::{Pool, PoolError};
use parking_lot::Mutex;
use std::ffi::OsStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Attribute/entry cache TTL handed back to the kernel. Phase B's `Pool`
/// has no cache-invalidation story of its own, so this is kept short
/// rather than zero purely to avoid hammering `Pool`'s single mutex on
/// every stat -- not a correctness statement about staleness tolerance.
const TTL: Duration = Duration::from_secs(1);
/// `Pool` has no generation/epoch counter exposed per-inode yet, so every
/// entry reply uses generation 0. Safe as long as inode numbers are never
/// reused, which holds today since `Pool` only ever allocates new ones.
const GENERATION: Generation = Generation(0);

/// The `fuser::Filesystem` implementation. Holds a `Pool` handle and
/// nothing else that could count as filesystem logic -- routing an inode
/// to its logical shard, chunking, hashing, etc. all live in
/// `lchfs-store`/`lchfs-chunk`/`lchfs-crypto`, not here.
pub struct LchfsFilesystem {
    pool: Arc<Pool>,
    handles: Mutex<FileHandleTable>,
    #[allow(dead_code)]
    inodes: InodeAllocator,
}

impl LchfsFilesystem {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            handles: Mutex::new(FileHandleTable::default()),
            inodes: InodeAllocator::default(),
        }
    }
}

fn errno_for(err: &PoolError) -> Errno {
    match err {
        PoolError::NoSuchInode(_) | PoolError::NotFound(_) => Errno::ENOENT,
        PoolError::NotADirectory(_) => Errno::ENOTDIR,
        PoolError::AlreadyExists(_) => Errno::EEXIST,
        PoolError::Io(_) | PoolError::Format(_) | PoolError::IntegrityFailure(_) => Errno::EIO,
        PoolError::Index(_) => Errno::EIO,
        PoolError::TooLarge(_) => Errno::EFBIG,
        PoolError::IsADirectory(_) => Errno::EISDIR,
        PoolError::NotEmpty(_) => Errno::ENOTEMPTY,
        PoolError::NotASymlink(_) => Errno::EINVAL,
        PoolError::InvalidArgument(_) => Errno::EINVAL,
        // Only reachable via Pool::open, which happens before the mount is
        // serving callbacks -- mapped for exhaustiveness, not because a live
        // FUSE request can produce it.
        PoolError::UnsupportedFormatVersion { .. } => Errno::EINVAL,
    }
}

fn file_type_for(kind: InodeKind) -> FileType {
    match kind {
        InodeKind::File => FileType::RegularFile,
        InodeKind::Directory => FileType::Directory,
        InodeKind::Symlink => FileType::Symlink,
    }
}

fn system_time((secs, nanos): (i64, u32)) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nanos)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, 0)
    }
}

fn time_or_now_to_unix(t: fuser::TimeOrNow) -> (i64, u32) {
    let system_time = match t {
        fuser::TimeOrNow::SpecificTime(t) => t,
        fuser::TimeOrNow::Now => SystemTime::now(),
    };
    match system_time.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => (-(e.duration().as_secs() as i64), 0),
    }
}

fn file_attr(ino: u64, inode: &InodeObject) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: inode.size,
        blocks: inode.size.div_ceil(512),
        atime: system_time(inode.atime),
        mtime: system_time(inode.mtime),
        ctime: system_time(inode.ctime),
        crtime: system_time(inode.ctime),
        kind: file_type_for(inode.kind),
        perm: (inode.mode & 0o7777) as u16,
        nlink: inode.nlink,
        uid: inode.uid,
        gid: inode.gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

impl LchfsFilesystem {
    fn entry_reply(&self, ino: u64, reply: ReplyEntry) {
        match self.pool.getattr(ino) {
            Ok(inode) => reply.entry(&TTL, &file_attr(ino, &inode), GENERATION),
            Err(e) => reply.error(errno_for(&e)),
        }
    }
}

impl Filesystem for LchfsFilesystem {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self.pool.lookup(parent.0, name) {
            Ok(Some(ino)) => self.entry_reply(ino, reply),
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<fuser::FileHandle>, reply: ReplyAttr) {
        match self.pool.getattr(ino.0) {
            Ok(inode) => reply.attr(&TTL, &file_attr(ino.0, &inode)),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<fuser::FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Some(size) = size
            && let Err(e) = self.pool.set_size(ino.0, size)
        {
            reply.error(errno_for(&e));
            return;
        }
        if mode.is_some() || uid.is_some() || gid.is_some() || atime.is_some() || mtime.is_some() {
            let atime = atime.map(time_or_now_to_unix);
            let mtime = mtime.map(time_or_now_to_unix);
            if let Err(e) = self.pool.set_attr(ino.0, mode, uid, gid, atime, mtime) {
                reply.error(errno_for(&e));
                return;
            }
        }
        match self.pool.getattr(ino.0) {
            Ok(inode) => reply.attr(&TTL, &file_attr(ino.0, &inode)),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let handle = self.handles.lock().open(ino.0);
        reply.opened(fuser::FileHandle(handle.0), fuser::FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let parent = match self.pool.parent_of(ino.0) {
            Ok(p) => p,
            Err(e) => {
                reply.error(errno_for(&e));
                return;
            }
        };
        let children = match self.pool.readdir(ino.0) {
            Ok(entries) => entries,
            Err(e) => {
                reply.error(errno_for(&e));
                return;
            }
        };

        let mut entries: Vec<(u64, FileType, String)> = Vec::with_capacity(children.len() + 2);
        entries.push((ino.0, FileType::Directory, ".".to_string()));
        entries.push((parent, FileType::Directory, "..".to_string()));
        for child in children {
            entries.push((child.ino, file_type_for(child.kind), child.name));
        }

        for (i, (child_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            let next_offset = (i + 1) as u64;
            if reply.add(INodeNo(child_ino), next_offset, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        _flags: fuser::OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.handles.lock().close(handles::FileHandle(fh.0));
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: fuser::OpenFlags, reply: ReplyOpen) {
        let handle = self.handles.lock().open(ino.0);
        reply.opened(fuser::FileHandle(handle.0), fuser::FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        match self.pool.read(ino.0, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.pool.write(ino.0, offset, data) {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.handles.lock().close(handles::FileHandle(fh.0));
        reply.ok();
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self
            .pool
            .create_file_as(parent.0, name, mode & !umask, req.uid(), req.gid())
        {
            Ok(ino) => match self.pool.getattr(ino) {
                Ok(inode) => {
                    let handle = self.handles.lock().open(ino);
                    reply.created(
                        &TTL,
                        &file_attr(ino, &inode),
                        GENERATION,
                        fuser::FileHandle(handle.0),
                        fuser::FopenFlags::empty(),
                    );
                }
                Err(e) => reply.error(errno_for(&e)),
            },
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self
            .pool
            .mkdir_as(parent.0, name, mode & !umask, req.uid(), req.gid())
        {
            Ok(ino) => self.entry_reply(ino, reply),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self.pool.unlink(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(name) = name.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self.pool.rmdir(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let (Some(link_name), Some(target)) = (link_name.to_str(), target.to_str()) else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self
            .pool
            .symlink_as(parent.0, link_name, target, req.uid(), req.gid())
        {
            Ok(ino) => self.entry_reply(ino, reply),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        match self.pool.readlink(ino.0) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn link(
        &self,
        _req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let Some(newname) = newname.to_str() else {
            reply.error(Errno::EINVAL);
            return;
        };
        match self.pool.link(ino.0, newparent.0, newname) {
            Ok(()) => self.entry_reply(ino.0, reply),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (Some(name), Some(newname)) = (name.to_str(), newname.to_str()) else {
            reply.error(Errno::EINVAL);
            return;
        };
        // `RENAME_EXCHANGE` (atomic two-way swap) isn't implemented -- an
        // ordinary replace-rename would silently do the wrong thing (drop
        // the destination instead of swapping), so this must be rejected
        // rather than approximated.
        if flags.contains(fuser::RenameFlags::RENAME_EXCHANGE) {
            reply.error(Errno::EINVAL);
            return;
        }
        let no_replace = flags.contains(fuser::RenameFlags::RENAME_NOREPLACE);
        match self.pool.rename(parent.0, name, newparent.0, newname, no_replace) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.pool.statfs() {
            Ok(stats) => reply.statfs(
                stats.blocks_total,
                stats.blocks_free,
                stats.blocks_available,
                stats.files_total,
                stats.files_free,
                stats.block_size,
                stats.name_max,
                stats.fragment_size,
            ),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: fuser::FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        // Not forcing a checkpoint here (that's `fsync`'s job) -- `flush`
        // fires on every `close()`, including duplicated fds, and fuser's
        // own docs say filesystems shouldn't assume it always precedes a
        // durability guarantee.
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: fuser::FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.pool.fsync(ino.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for(&e)),
        }
    }

    fn destroy(&mut self) {
        // Kernel sends FUSE_DESTROY on a clean unmount; without this,
        // writes that no application explicitly `fsync`'d are silently
        // lost, since nothing else ever calls `Pool::checkpoint`.
        if let Err(e) = self.pool.checkpoint() {
            tracing::error!("checkpoint on unmount failed: {e}");
        }
    }
}
