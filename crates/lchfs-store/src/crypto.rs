//! The pool's record crypto as the engine holds it.
//!
//! One `RecordCrypto` describes how the pool addresses, seals and opens
//! records right now. It is held behind an `ArcSwap` so every reader and
//! writer loads a snapshot without a lock -- the write path never takes a
//! global one -- and a key-epoch change (conversion, rotation) swaps in a
//! new snapshot atomically. Anything that addresses a record and then
//! seals it does both from the *same* snapshot, so a record can never be
//! hashed under one epoch's key and sealed under another's.

use arc_swap::ArcSwap;
use lchfs_crypto::epoch::PLAINTEXT_EPOCH;
use lchfs_crypto::keyring::UnlockedKeyring;
use lchfs_format::{CodecId, ExtentKind, ExtentLocation, ExtentRecordHeader, Hash32, RecordCrypto};
use std::io;
use std::sync::Arc;

use crate::segment::SegmentWriter;

pub type CryptoHandle = Arc<ArcSwap<RecordCrypto>>;

pub fn plaintext_handle() -> CryptoHandle {
    Arc::new(ArcSwap::from_pointee(RecordCrypto::plaintext()))
}

pub fn handle(crypto: RecordCrypto) -> CryptoHandle {
    Arc::new(ArcSwap::from_pointee(crypto))
}

/// The record crypto an unlocked keyring describes.
pub fn from_keyring(ring: &UnlockedKeyring) -> RecordCrypto {
    let config = ring.config();
    RecordCrypto::new(
        ring.pool_uuid(),
        config.current_epoch,
        config.min_epoch,
        config.padding,
        ring.epoch_keys(),
    )
}

/// A record ready to append: plaintext fields, or a sealed header whose
/// payload is the envelope.
pub enum Framed {
    Plain,
    Sealed(ExtentRecordHeader),
}

/// Seals `payload` in `epoch` if that is not the plaintext epoch. Returns
/// how to frame it and the bytes to write (the envelope, or `payload`
/// itself untouched).
pub fn frame(
    crypto: &RecordCrypto,
    epoch: u16,
    kind: ExtentKind,
    content_hash: Hash32,
    codec_id: CodecId,
    uncompressed_len: u32,
    payload: bytes::Bytes,
) -> (Framed, bytes::Bytes) {
    if epoch == PLAINTEXT_EPOCH {
        return (Framed::Plain, payload);
    }
    let (header, envelope) = crypto.seal(epoch, kind, content_hash, codec_id, uncompressed_len, &payload, Vec::new());
    (Framed::Sealed(header), bytes::Bytes::from(envelope))
}

/// Appends a freshly written record under `epoch` -- sealed, unless that
/// is the plaintext epoch.
#[allow(clippy::too_many_arguments)]
pub fn append_fresh(
    writer: &mut SegmentWriter,
    crypto: &RecordCrypto,
    epoch: u16,
    kind: ExtentKind,
    content_hash: Hash32,
    codec_id: CodecId,
    uncompressed_len: u32,
    payload: &[u8],
) -> io::Result<ExtentLocation> {
    if epoch == PLAINTEXT_EPOCH {
        return writer.append(kind, content_hash, codec_id, uncompressed_len, payload, Vec::new());
    }
    let (header, envelope) = crypto.seal(epoch, kind, content_hash, codec_id, uncompressed_len, payload, Vec::new());
    writer.append_prebuilt(&header, &envelope)
}
