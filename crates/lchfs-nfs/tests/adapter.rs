//! The adapter driven the way the NFS server drives it: through the
//! `NFSFileSystem` trait, against a real pool.

use lchfs_format::PoolParams;
use lchfs_nfs::LchfsNfs;
use lchfs_store::Pool;
use nfsserve::nfs::{nfsstat3, sattr3, set_mode3, set_size3};
use nfsserve::vfs::NFSFileSystem;
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
    }
}

fn payload() -> Vec<u8> {
    (0..50_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

#[tokio::test]
async fn files_directories_links_and_renames_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params()).unwrap());
    let fs = LchfsNfs::new(Arc::clone(&pool));
    let root = fs.root_dir();

    let (d, dattr) = fs.mkdir(root, &b"docs".as_slice().into()).await.unwrap();
    assert!(matches!(dattr.ftype, nfsserve::nfs::ftype3::NF3DIR));
    let attr = sattr3 {
        mode: set_mode3::mode(0o640),
        ..Default::default()
    };
    let (f, fattr) = fs.create(d, &b"big.bin".as_slice().into(), attr).await.unwrap();
    assert_eq!(fattr.mode, 0o640);
    assert_eq!(fattr.size, 0);

    // Write in NFS-sized pieces, read back whole and in a window.
    let data = payload();
    for (i, piece) in data.chunks(8192).enumerate() {
        fs.write(f, (i * 8192) as u64, piece).await.unwrap();
    }
    assert_eq!(fs.getattr(f).await.unwrap().size, data.len() as u64);
    let (all, eof) = fs.read(f, 0, data.len() as u32).await.unwrap();
    assert_eq!(all, data);
    assert!(eof);
    let (mid, eof) = fs.read(f, 1000, 500).await.unwrap();
    assert_eq!(mid, &data[1000..1500]);
    assert!(!eof);

    // Lookup, "..", readdir with attributes and paging.
    assert_eq!(fs.lookup(d, &b"big.bin".as_slice().into()).await.unwrap(), f);
    assert_eq!(fs.lookup(d, &b"..".as_slice().into()).await.unwrap(), root);
    assert!(matches!(fs.lookup(d, &b"nope".as_slice().into()).await.unwrap_err(), nfsstat3::NFS3ERR_NOENT));
    for i in 0..5 {
        fs.create(d, &format!("f{i}").as_bytes().into(), sattr3::default()).await.unwrap();
    }
    let page1 = fs.readdir(d, 0, 3).await.unwrap();
    assert_eq!(page1.entries.len(), 3);
    assert!(!page1.end);
    let page2 = fs.readdir(d, page1.entries[2].fileid, 10).await.unwrap();
    assert_eq!(page2.entries.len(), 3, "{:?}", page2.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
    assert!(page2.end);
    assert!(page2.entries.iter().all(|e| e.attr.fileid == e.fileid));

    // Truncate via setattr, symlink, rename, remove.
    fs.setattr(f, sattr3 { size: set_size3::size(100), ..Default::default() }).await.unwrap();
    assert_eq!(fs.getattr(f).await.unwrap().size, 100);
    let (l, lattr) = fs
        .symlink(root, &b"link".as_slice().into(), &b"docs/big.bin".as_slice().into(), &sattr3::default())
        .await
        .unwrap();
    assert!(matches!(lattr.ftype, nfsserve::nfs::ftype3::NF3LNK));
    assert_eq!(fs.readlink(l).await.unwrap().0, b"docs/big.bin");
    fs.rename(d, &b"big.bin".as_slice().into(), root, &b"moved.bin".as_slice().into()).await.unwrap();
    assert_eq!(fs.lookup(root, &b"moved.bin".as_slice().into()).await.unwrap(), f);
    fs.remove(root, &b"moved.bin".as_slice().into()).await.unwrap();
    assert!(matches!(fs.lookup(root, &b"moved.bin".as_slice().into()).await.unwrap_err(), nfsstat3::NFS3ERR_NOENT));
    assert!(matches!(fs.remove(root, &b"docs".as_slice().into()).await.unwrap_err(), nfsstat3::NFS3ERR_NOTEMPTY));

    // CREATE (unchecked) on an existing file truncates rather than fails.
    let (f2, _) = fs.create(root, &b"again".as_slice().into(), sattr3::default()).await.unwrap();
    fs.write(f2, 0, b"hello").await.unwrap();
    let (f3, a3) = fs.create(root, &b"again".as_slice().into(), sattr3::default()).await.unwrap();
    assert_eq!(f2, f3);
    assert_eq!(a3.size, 0);
    // Exclusive create does fail.
    assert!(matches!(fs.create_exclusive(root, &b"again".as_slice().into()).await.unwrap_err(), nfsstat3::NFS3ERR_EXIST));
}

/// The server binds and answers on a real socket.
#[tokio::test]
async fn the_server_listens() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), small_params()).unwrap());
    let (port, task) = LchfsNfs::serve(pool, "127.0.0.1:0").await.unwrap();
    assert!(port > 0);
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    drop(stream);
    task.abort();
}
