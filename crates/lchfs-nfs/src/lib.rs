//! LCHFS over NFSv3: the second thin protocol adapter (ARCHITECTURE.md
//! §5a). Like `lchfs-fuse`, this crate translates a wire protocol's
//! callbacks into calls on `Pool`'s public API and holds no filesystem
//! logic of its own -- which is the point: two adapters against one
//! engine is what proves the boundary is real. It is also §13.1's
//! "network/multi-mount door", opened: a pool served this way is reachable
//! from any NFS client.
//!
//! NFS file handles are the pool's inode numbers, wrapped by `nfsserve`
//! with a server generation so a stale handle from a previous run is
//! refused rather than resolved to whatever inode now has that number.

use async_trait::async_trait;
use lchfs_format::{InodeKind, InodeObject};
use lchfs_store::{Pool, PoolError};
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, set_atime,
    set_gid3, set_mode3, set_mtime, set_size3, set_uid3, specdata3,
};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use std::sync::Arc;

pub const ROOT_INO: fileid3 = 1;

pub struct LchfsNfs {
    pool: Arc<Pool>,
    /// A stable id for `fattr3::fsid`, derived from the pool uuid.
    fsid: u64,
}

impl LchfsNfs {
    pub fn new(pool: Arc<Pool>) -> Self {
        let uuid = pool.pool_uuid();
        let fsid = u64::from_le_bytes(uuid[..8].try_into().expect("8 bytes"));
        Self { pool, fsid }
    }

    /// Serves `pool` at `listen` ("ip:port"; port 0 picks one) until the
    /// returned task is dropped or the process ends. Returns the port.
    pub async fn serve(pool: Arc<Pool>, listen: &str) -> std::io::Result<(u16, tokio::task::JoinHandle<()>)> {
        let listener = NFSTcpListener::bind(listen, LchfsNfs::new(pool)).await?;
        let port = listener.get_listen_port();
        let task = tokio::spawn(async move {
            if let Err(e) = listener.handle_forever().await {
                tracing::error!("nfs: listener stopped: {e}");
            }
        });
        Ok((port, task))
    }

    fn attr(&self, ino: u64, inode: &InodeObject) -> fattr3 {
        let time = |(s, n): (i64, u32)| nfstime3 {
            seconds: s.max(0) as u32,
            nseconds: n,
        };
        fattr3 {
            ftype: match inode.kind {
                InodeKind::File => ftype3::NF3REG,
                InodeKind::Directory => ftype3::NF3DIR,
                InodeKind::Symlink => ftype3::NF3LNK,
            },
            mode: inode.mode & 0o7777,
            nlink: inode.nlink,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            used: inode.size.div_ceil(512) * 512,
            rdev: specdata3::default(),
            fsid: self.fsid,
            fileid: ino,
            atime: time(inode.atime),
            mtime: time(inode.mtime),
            ctime: time(inode.ctime),
        }
    }

    async fn getattr_of(&self, ino: u64) -> Result<fattr3, nfsstat3> {
        let pool = Arc::clone(&self.pool);
        let inode = blocking(move || pool.getattr(ino)).await?;
        Ok(self.attr(ino, &inode))
    }
}

/// `Pool` is synchronous; its calls run off the async runtime's threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, PoolError> + Send + 'static,
) -> Result<T, nfsstat3> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(status_for(&e)),
        Err(_) => Err(nfsstat3::NFS3ERR_SERVERFAULT),
    }
}

/// The same mapping `lchfs-fuse` makes to errno, to NFS status.
fn status_for(err: &PoolError) -> nfsstat3 {
    match err {
        PoolError::NoSuchInode(_) | PoolError::NotFound(_) => nfsstat3::NFS3ERR_NOENT,
        PoolError::NotADirectory(_) => nfsstat3::NFS3ERR_NOTDIR,
        PoolError::AlreadyExists(_) => nfsstat3::NFS3ERR_EXIST,
        PoolError::TooLarge(_) => nfsstat3::NFS3ERR_FBIG,
        PoolError::IsADirectory(_) => nfsstat3::NFS3ERR_ISDIR,
        PoolError::NotEmpty(_) => nfsstat3::NFS3ERR_NOTEMPTY,
        PoolError::NotASymlink(_) | PoolError::InvalidArgument(_) | PoolError::NoSuchXattr(_) => {
            nfsstat3::NFS3ERR_INVAL
        }
        _ => nfsstat3::NFS3ERR_IO,
    }
}

fn name(n: &filename3) -> Result<String, nfsstat3> {
    String::from_utf8(n.0.clone()).map_err(|_| nfsstat3::NFS3ERR_INVAL)
}

fn now() -> (i64, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos())
}

#[async_trait]
impl NFSFileSystem for LchfsNfs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_INO
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let name = name(filename)?;
        let pool = Arc::clone(&self.pool);
        match name.as_str() {
            "." => Ok(dirid),
            ".." => blocking(move || pool.parent_of(dirid)).await,
            _ => blocking(move || pool.lookup(dirid, &name))
                .await?
                .ok_or(nfsstat3::NFS3ERR_NOENT),
        }
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        self.getattr_of(id).await
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let mode = match setattr.mode {
            set_mode3::mode(m) => Some(m),
            set_mode3::Void => None,
        };
        let uid = match setattr.uid {
            set_uid3::uid(u) => Some(u),
            set_uid3::Void => None,
        };
        let gid = match setattr.gid {
            set_gid3::gid(g) => Some(g),
            set_gid3::Void => None,
        };
        let atime = match setattr.atime {
            set_atime::DONT_CHANGE => None,
            set_atime::SET_TO_SERVER_TIME => Some(now()),
            set_atime::SET_TO_CLIENT_TIME(t) => Some((t.seconds as i64, t.nseconds)),
        };
        let mtime = match setattr.mtime {
            set_mtime::DONT_CHANGE => None,
            set_mtime::SET_TO_SERVER_TIME => Some(now()),
            set_mtime::SET_TO_CLIENT_TIME(t) => Some((t.seconds as i64, t.nseconds)),
        };
        let size = match setattr.size {
            set_size3::size(s) => Some(s),
            set_size3::Void => None,
        };
        let pool = Arc::clone(&self.pool);
        blocking(move || {
            if let Some(size) = size {
                pool.set_size(id, size)?;
            }
            if mode.is_some() || uid.is_some() || gid.is_some() || atime.is_some() || mtime.is_some() {
                pool.set_attr(id, mode, uid, gid, atime, mtime)?;
            }
            Ok(())
        })
        .await?;
        self.getattr_of(id).await
    }

    async fn read(&self, id: fileid3, offset: u64, count: u32) -> Result<(Vec<u8>, bool), nfsstat3> {
        let pool = Arc::clone(&self.pool);
        let (bytes, size) = blocking(move || {
            let size = pool.getattr(id)?.size;
            let bytes = pool.read(id, offset, count)?;
            Ok((bytes.to_vec(), size))
        })
        .await?;
        let eof = offset + bytes.len() as u64 >= size;
        Ok((bytes, eof))
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let pool = Arc::clone(&self.pool);
        let data = data.to_vec();
        blocking(move || pool.write(id, offset, &data)).await?;
        self.getattr_of(id).await
    }

    async fn create(&self, dirid: fileid3, filename: &filename3, attr: sattr3) -> Result<(fileid3, fattr3), nfsstat3> {
        let name = name(filename)?;
        let mode = match attr.mode {
            set_mode3::mode(m) => m,
            set_mode3::Void => 0o644,
        };
        let uid = match attr.uid {
            set_uid3::uid(u) => u,
            set_uid3::Void => 0,
        };
        let gid = match attr.gid {
            set_gid3::gid(g) => g,
            set_gid3::Void => 0,
        };
        let pool = Arc::clone(&self.pool);
        let ino = blocking(move || {
            // NFS CREATE (unchecked) is create-or-truncate.
            match pool.lookup(dirid, &name)? {
                Some(existing) => {
                    pool.set_size(existing, 0)?;
                    Ok(existing)
                }
                None => pool.create_file_as(dirid, &name, mode, uid, gid),
            }
        })
        .await?;
        Ok((ino, self.getattr_of(ino).await?))
    }

    async fn create_exclusive(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let name = name(filename)?;
        let pool = Arc::clone(&self.pool);
        blocking(move || pool.create_file_as(dirid, &name, 0o644, 0, 0)).await
    }

    async fn mkdir(&self, dirid: fileid3, dirname: &filename3) -> Result<(fileid3, fattr3), nfsstat3> {
        let name = name(dirname)?;
        let pool = Arc::clone(&self.pool);
        let ino = blocking(move || pool.mkdir_as(dirid, &name, 0o755, 0, 0)).await?;
        Ok((ino, self.getattr_of(ino).await?))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let name = name(filename)?;
        let pool = Arc::clone(&self.pool);
        blocking(move || {
            let ino = pool.lookup(dirid, &name)?.ok_or(PoolError::NotFound(name.clone()))?;
            if pool.getattr(ino)?.kind == InodeKind::Directory {
                pool.rmdir(dirid, &name)
            } else {
                pool.unlink(dirid, &name)
            }
        })
        .await
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let from = name(from_filename)?;
        let to = name(to_filename)?;
        let pool = Arc::clone(&self.pool);
        blocking(move || pool.rename(from_dirid, &from, to_dirid, &to, false)).await
    }

    async fn readdir(&self, dirid: fileid3, start_after: fileid3, max_entries: usize) -> Result<ReadDirResult, nfsstat3> {
        let pool = Arc::clone(&self.pool);
        let entries = blocking(move || pool.readdir(dirid)).await?;
        // `start_after` is the fileid of the last entry the client saw;
        // entries are returned in the pool's (name-sorted) order, so the
        // resume point is "after the entry with that id".
        let skip = if start_after == 0 {
            0
        } else {
            entries
                .iter()
                .position(|e| e.ino == start_after)
                .map(|p| p + 1)
                .unwrap_or(0)
        };
        let mut out = ReadDirResult::default();
        let mut remaining = entries.iter().skip(skip).peekable();
        while let Some(e) = remaining.next() {
            let pool = Arc::clone(&self.pool);
            let ino = e.ino;
            let inode = blocking(move || pool.getattr(ino)).await?;
            out.entries.push(DirEntry {
                fileid: e.ino,
                name: e.name.as_bytes().into(),
                attr: self.attr(e.ino, &inode),
            });
            if out.entries.len() >= max_entries {
                out.end = remaining.peek().is_none();
                return Ok(out);
            }
        }
        out.end = true;
        Ok(out)
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let name = name(linkname)?;
        let target = String::from_utf8(symlink.0.clone()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let uid = match attr.uid {
            set_uid3::uid(u) => u,
            set_uid3::Void => 0,
        };
        let gid = match attr.gid {
            set_gid3::gid(g) => g,
            set_gid3::Void => 0,
        };
        let pool = Arc::clone(&self.pool);
        let ino = blocking(move || pool.symlink_as(dirid, &name, &target, uid, gid)).await?;
        Ok((ino, self.getattr_of(ino).await?))
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let pool = Arc::clone(&self.pool);
        let target = blocking(move || pool.readlink(id)).await?;
        Ok(target.as_bytes().into())
    }
}
