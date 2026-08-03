//! Standalone tests for `CommitterPool` (E.2) against synthetic
//! `IngressOp`s — no `Pool`/prep-pool involvement, per the plan's "testable
//! in isolation" requirement. Exercises: shard routing correctness,
//! per-producer commit ordering, and completion signaling.

use lchfs_format::{CodecId, StreamKind};
use lchfs_store::ingress::{shard_for_inode, CommitterPool, IngressOp};
use lchfs_store::segment::SegmentReader;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn make_op(inode_id: u64, logical_offset: u64, payload: &[u8]) -> (IngressOp, crossbeam::channel::Receiver<std::io::Result<lchfs_format::ExtentLocation>>) {
    let hash = lchfs_format::Hash32::of(payload);
    let (tx, rx) = crossbeam::channel::bounded(1);
    let op = IngressOp {
        inode_id,
        content_hash: hash,
        codec_id: CodecId::None,
        uncompressed_len: payload.len() as u32,
        payload: bytes::Bytes::copy_from_slice(payload),
        logical_offset,
        completion: tx,
    };
    (op, rx)
}

#[test]
fn ops_land_in_the_correct_shard_and_are_readable() {
    let dir = tempfile::tempdir().unwrap();
    let pool = CommitterPool::new(dir.path(), 4, 2, 16, 1024 * 1024, Arc::new(AtomicU64::new(0)))
        .unwrap();

    let payload = b"hello from the committer pool";
    let inode_id = 42;
    let expected_shard = shard_for_inode(inode_id, pool.shard_count());
    let (op, rx) = make_op(inode_id, 0, payload);
    pool.push(op);

    let loc = rx.recv().unwrap().unwrap();

    // Read it back directly via a fresh SegmentReader against the shard's
    // Data stream to confirm it landed where routing said it would, and
    // round-trips correctly.
    let reader = SegmentReader::open(dir.path(), loc.segment_id, StreamKind::Data).unwrap();
    let (_record_header, bytes) = reader.read_record(loc).unwrap();
    assert_eq!(bytes, payload);
    let segment_header = reader.read_header().unwrap();
    assert_eq!(segment_header.owner_shard, expected_shard);
}

#[test]
fn per_producer_push_order_is_preserved_in_commit_order() {
    let dir = tempfile::tempdir().unwrap();
    let pool = CommitterPool::new(dir.path(), 4, 3, 64, 1024 * 1024, Arc::new(AtomicU64::new(0)))
        .unwrap();

    // Force every op onto the same inode (same shard) from one producer
    // thread, sequentially, and verify their on-disk offsets come back in
    // strictly increasing order matching push order.
    let inode_id = 7;
    let mut receivers = Vec::new();
    for i in 0..50u64 {
        let payload = format!("chunk-{i}").into_bytes();
        let (op, rx) = make_op(inode_id, i * 100, &payload);
        pool.push(op);
        receivers.push(rx);
    }

    let mut prev_offset: Option<(u64, u32)> = None;
    for rx in receivers {
        let loc = rx.recv().unwrap().unwrap();
        if let Some((prev_seg, prev_off)) = prev_offset {
            // Either the same segment with a strictly later offset, or a
            // later segment (if rollover happened) — never earlier.
            assert!(
                (loc.segment_id == prev_seg && loc.offset > prev_off)
                    || loc.segment_id > prev_seg,
                "commit order violated: prev=({prev_seg},{prev_off}) got=({},{})",
                loc.segment_id,
                loc.offset
            );
        }
        prev_offset = Some((loc.segment_id, loc.offset));
    }
}

#[test]
fn concurrent_producers_to_different_inodes_all_complete() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        CommitterPool::new(dir.path(), 8, 4, 32, 1024 * 1024, Arc::new(AtomicU64::new(0)))
            .unwrap(),
    );

    let handles: Vec<_> = (0..16u64)
        .map(|producer| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let inode_id = 1000 + producer;
                let mut receivers = Vec::new();
                for i in 0..20u64 {
                    let payload = format!("producer-{producer}-chunk-{i}").into_bytes();
                    let (op, rx) = make_op(inode_id, i * 64, &payload);
                    pool.push(op);
                    receivers.push((payload, rx));
                }
                for (payload, rx) in receivers {
                    let loc = rx.recv().unwrap().unwrap();
                    assert_eq!(loc.len as usize > 0, true);
                    let _ = payload;
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}
