//! Sealed Extent Records: how a record of an encrypted pool is laid out.
//!
//! A sealed record keeps the ordinary `ExtentRecordHeader` framing, so
//! everything that only needs framing -- the mount-time header scan, index
//! rebuild, stripes, heal, resilver, fsck's structural checks -- handles it
//! without a key. What would say anything about the content is moved
//! inside the envelope:
//!
//! ```text
//! outer header: kind = Sealed, codec = None,
//!               flags = SEALED_FLAG | epoch,
//!               uncompressed_len = compressed_len = envelope length,
//!               content_hash = the keyed address, backpointers = []
//! payload:      nonce ‖ XChaCha20-Poly1305(record key of that epoch,
//!                                          aad, inner) ‖ tag
//! inner:        InnerHeader{kind, codec, uncompressed_len, payload_len,
//!                           backpointers} ‖ payload ‖ Padmé zeros
//! aad:          "lchfs-record-v1" ‖ pool uuid ‖ the outer header
//!               (checksum zeroed)
//! ```
//!
//! Binding the whole outer header into the AEAD means the content hash,
//! the epoch and the lengths are authenticated, not just CRC-checked: a
//! sealed record cannot be moved under another hash, epoch or pool.
//!
//! The epoch lives in `flags`, which plaintext records always wrote as
//! zero -- so a plaintext record is simply epoch 0 and a v4 pool is a
//! valid plaintext v5 pool with no migration.

use crate::extent::{CodecId, EXTENT_RECORD_MAGIC, ExtentKind, ExtentRecordHeader, finalize_header_checksum};
use crate::Hash32;
use lchfs_crypto::envelope::{self, OVERHEAD};
use lchfs_crypto::epoch::{EpochKeys, MAX_EPOCH, PLAINTEXT_EPOCH};
use lchfs_crypto::keyring::Padding;
use lchfs_crypto::padme;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `flags` bit marking a sealed record; the low 15 bits are its epoch.
pub const SEALED_FLAG: u16 = 0x8000;
const AAD_PREFIX: &[u8] = b"lchfs-record-v1";
/// Largest inner plaintext a sealed record may claim (matches the
/// store's record ceiling with room for the inner header and padding).
const MAX_INNER_LEN: usize = 64 * 1024 * 1024;

/// The epoch a record was written under; 0 for a plaintext record.
pub fn record_epoch(header: &ExtentRecordHeader) -> u16 {
    if header.flags & SEALED_FLAG != 0 {
        header.flags & MAX_EPOCH
    } else {
        PLAINTEXT_EPOCH
    }
}

pub fn is_sealed(header: &ExtentRecordHeader) -> bool {
    header.flags & SEALED_FLAG != 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InnerHeader {
    kind: ExtentKind,
    codec_id: CodecId,
    uncompressed_len: u32,
    payload_len: u32,
    backpointers: Vec<Hash32>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("record is sealed under epoch {0}, whose key this pool does not hold")]
    UnknownEpoch(u16),
    #[error("record is from epoch {epoch}, below this pool's minimum {min} -- refused as a downgrade")]
    BelowMinimum { epoch: u16, min: u16 },
    #[error("sealed record failed authentication (wrong key, or modified)")]
    Authentication,
    #[error("malformed sealed record: {0}")]
    Malformed(&'static str),
    #[error("this record is sealed and no key was supplied to read it")]
    KeyRequired,
}

/// A record's content-bearing fields, whether it was sealed or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub kind: ExtentKind,
    pub codec_id: CodecId,
    pub uncompressed_len: u32,
    pub backpointers: Vec<Hash32>,
    /// Still compressed if `codec_id` says so.
    pub payload: Vec<u8>,
    pub epoch: u16,
}

/// The outer header a sealed record of this hash, epoch and envelope
/// length has -- the one definition both the sealer (for its AAD) and the
/// segment writer (which writes it) use.
pub fn sealed_header(content_hash: Hash32, epoch: u16, envelope_len: u32) -> ExtentRecordHeader {
    assert!(epoch != PLAINTEXT_EPOCH && epoch <= MAX_EPOCH, "epoch {epoch} cannot seal");
    let mut header = ExtentRecordHeader {
        magic: EXTENT_RECORD_MAGIC,
        record_len: 0,
        content_hash,
        kind: ExtentKind::Sealed,
        codec_id: CodecId::None,
        flags: SEALED_FLAG | epoch,
        uncompressed_len: envelope_len,
        compressed_len: envelope_len,
        backpointers: Vec::new(),
        header_checksum: 0,
    };
    let header_len = crate::encode(&header).expect("header encodes").len() as u32;
    header.record_len = 4 + header_len + envelope_len;
    finalize_header_checksum(&mut header);
    header
}

fn aad(pool_uuid: &[u8; 16], header: &ExtentRecordHeader) -> Vec<u8> {
    let mut zeroed = header.clone();
    zeroed.header_checksum = 0;
    let mut aad = AAD_PREFIX.to_vec();
    aad.extend_from_slice(pool_uuid);
    aad.extend_from_slice(&crate::encode(&zeroed).expect("header encodes"));
    aad
}

/// Everything a pool needs to address, seal and open records: its uuid,
/// which epoch new records go into, which epochs it still accepts, and
/// the keys of every epoch it holds. A plaintext pool is
/// `RecordCrypto::plaintext()` -- epoch 0 current, nothing held.
pub struct RecordCrypto {
    pool_uuid: [u8; 16],
    current: u16,
    min_epoch: u16,
    padding: Padding,
    epochs: BTreeMap<u16, EpochKeys>,
}

impl std::fmt::Debug for RecordCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordCrypto")
            .field("current", &self.current)
            .field("min_epoch", &self.min_epoch)
            .field("padding", &self.padding)
            .field("epochs", &self.epochs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl RecordCrypto {
    pub fn plaintext() -> Self {
        Self {
            pool_uuid: [0; 16],
            current: PLAINTEXT_EPOCH,
            min_epoch: PLAINTEXT_EPOCH,
            padding: Padding::None,
            epochs: BTreeMap::new(),
        }
    }

    /// # Panics
    /// If `current` is an epoch whose keys are not among `epochs`.
    pub fn new(pool_uuid: [u8; 16], current: u16, min_epoch: u16, padding: Padding, epochs: Vec<EpochKeys>) -> Self {
        let epochs: BTreeMap<u16, EpochKeys> = epochs.into_iter().map(|k| (k.epoch(), k)).collect();
        assert!(
            current == PLAINTEXT_EPOCH || epochs.contains_key(&current),
            "current epoch {current} has no keys"
        );
        Self {
            pool_uuid,
            current,
            min_epoch,
            padding,
            epochs,
        }
    }

    /// Whether this pool has any keys at all.
    pub fn is_encrypted(&self) -> bool {
        !self.epochs.is_empty()
    }

    pub fn current_epoch(&self) -> u16 {
        self.current
    }

    pub fn min_epoch(&self) -> u16 {
        self.min_epoch
    }

    /// The content address of `data` in epoch `epoch` -- which must be one
    /// this pool can seal in (0, or one whose keys it holds).
    pub fn address_in(&self, epoch: u16, data: &[u8]) -> Hash32 {
        match epoch {
            PLAINTEXT_EPOCH => Hash32::of(data),
            e => self
                .epochs
                .get(&e)
                .unwrap_or_else(|| panic!("no keys for epoch {e}"))
                .address(data),
        }
    }

    /// The content address of `data` in the current epoch, with that epoch
    /// -- a writer seals under the same epoch it addressed with, so a
    /// record can never be hashed under one key and sealed under another.
    pub fn address(&self, data: &[u8]) -> (u16, Hash32) {
        (self.current, self.address_in(self.current, data))
    }

    /// Checks `data` against a record's content hash, in the record's own
    /// epoch.
    pub fn verify(&self, epoch: u16, data: &[u8], expected: Hash32) -> Result<(), Hash32> {
        let actual = match epoch {
            PLAINTEXT_EPOCH => Hash32::of(data),
            e => match self.epochs.get(&e) {
                Some(k) => k.address(data),
                None => return Err(Hash32([0; 32])),
            },
        };
        if actual == expected { Ok(()) } else { Err(actual) }
    }

    /// Seals one record's content in `epoch` (not the plaintext epoch --
    /// a plaintext record needs no sealing and is written as it is).
    /// Returns the outer header and the envelope that follows it.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &self,
        epoch: u16,
        kind: ExtentKind,
        content_hash: Hash32,
        codec_id: CodecId,
        uncompressed_len: u32,
        payload: &[u8],
        backpointers: Vec<Hash32>,
    ) -> (ExtentRecordHeader, Vec<u8>) {
        let keys = self
            .epochs
            .get(&epoch)
            .unwrap_or_else(|| panic!("sealing in epoch {epoch}, whose keys are not held"));
        let inner_header = InnerHeader {
            kind,
            codec_id,
            uncompressed_len,
            payload_len: payload.len() as u32,
            backpointers,
        };
        let mut inner = crate::encode(&inner_header).expect("inner header encodes");
        inner.extend_from_slice(payload);
        if self.padding == Padding::Padme {
            let padded = padme::padded_len(inner.len() as u64) as usize;
            inner.resize(padded, 0);
        }
        let header = sealed_header(content_hash, epoch, (inner.len() + OVERHEAD) as u32);
        let envelope = envelope::seal(keys.record_key(), &aad(&self.pool_uuid, &header), &inner);
        debug_assert_eq!(envelope.len() as u32, header.compressed_len);
        (header, envelope)
    }

    /// Recovers a record's content-bearing fields: from the header itself
    /// for a plaintext record, by authenticating and decrypting the
    /// envelope for a sealed one. Does not check the content hash (the
    /// payload may still be compressed); the caller does, with `verify`.
    pub fn open(&self, header: &ExtentRecordHeader, payload: Vec<u8>) -> Result<Opened, SealError> {
        let epoch = record_epoch(header);
        if epoch < self.min_epoch {
            return Err(SealError::BelowMinimum {
                epoch,
                min: self.min_epoch,
            });
        }
        if epoch == PLAINTEXT_EPOCH {
            if header.kind == ExtentKind::Sealed {
                return Err(SealError::Malformed("plaintext record of the sealed kind"));
            }
            return Ok(Opened {
                kind: header.kind,
                codec_id: header.codec_id,
                uncompressed_len: header.uncompressed_len,
                backpointers: header.backpointers.clone(),
                payload,
                epoch,
            });
        }
        if header.kind != ExtentKind::Sealed || header.codec_id != CodecId::None || !header.backpointers.is_empty() {
            return Err(SealError::Malformed("sealed flag on a record that is not laid out sealed"));
        }
        let Some(keys) = self.epochs.get(&epoch) else {
            return Err(if self.is_encrypted() {
                SealError::UnknownEpoch(epoch)
            } else {
                SealError::KeyRequired
            });
        };
        let inner = envelope::open(keys.record_key(), &aad(&self.pool_uuid, header), &payload)
            .map_err(|_| SealError::Authentication)?;
        if inner.len() > MAX_INNER_LEN {
            return Err(SealError::Malformed("inner plaintext too large"));
        }
        let mut cursor = std::io::Cursor::new(inner.as_slice());
        let inner_header: InnerHeader = {
            use bincode::Options;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_INNER_LEN as u64)
                .deserialize_from(&mut cursor)
                .map_err(|_| SealError::Malformed("inner header does not decode"))?
        };
        if inner_header.kind == ExtentKind::Sealed {
            return Err(SealError::Malformed("sealed record nested in a sealed record"));
        }
        let start = cursor.position() as usize;
        let end = start
            .checked_add(inner_header.payload_len as usize)
            .filter(|&end| end <= inner.len())
            .ok_or(SealError::Malformed("inner payload length out of bounds"))?;
        Ok(Opened {
            kind: inner_header.kind,
            codec_id: inner_header.codec_id,
            uncompressed_len: inner_header.uncompressed_len,
            backpointers: inner_header.backpointers,
            payload: inner[start..end].to_vec(),
            epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lchfs_crypto::Key32;

    fn crypto(padding: Padding) -> RecordCrypto {
        let keys = EpochKeys::derive(1, &Key32::random());
        RecordCrypto::new([9; 16], 1, 1, padding, vec![keys])
    }

    #[test]
    fn seal_open_round_trip_hides_every_content_field() {
        let c = crypto(Padding::Padme);
        let payload = b"compressed or not, this is the payload".to_vec();
        let (epoch, hash) = c.address(&payload);
        let (header, env) = c.seal(epoch, ExtentKind::DirectoryObject, hash, CodecId::Zstd, 4096, &payload, vec![]);
        assert_eq!(header.kind, ExtentKind::Sealed);
        assert_eq!(header.codec_id, CodecId::None);
        assert_eq!(record_epoch(&header), 1);
        assert_eq!(header.compressed_len as usize, env.len());
        assert!(!env.windows(payload.len()).any(|w| w == payload), "payload in the clear");
        let opened = c.open(&header, env).unwrap();
        assert_eq!(opened.kind, ExtentKind::DirectoryObject);
        assert_eq!(opened.codec_id, CodecId::Zstd);
        assert_eq!(opened.uncompressed_len, 4096);
        assert_eq!(opened.payload, payload);
    }

    #[test]
    fn padding_rounds_the_envelope_up() {
        let plain = crypto(Padding::None);
        let padded = crypto(Padding::Padme);
        // 1001 bytes plus the 24-byte inner header is not a Padmé length
        // (1024 would be, and would come out unpadded).
        let data = vec![1u8; 1001];
        let (_, a) = plain.seal(1, ExtentKind::RawChunk, Hash32([0; 32]), CodecId::None, 1001, &data, vec![]);
        let (_, b) = padded.seal(1, ExtentKind::RawChunk, Hash32([0; 32]), CodecId::None, 1001, &data, vec![]);
        assert!(b.len() > a.len());
        assert_eq!((b.len() - OVERHEAD) as u64, padme::padded_len((a.len() - OVERHEAD) as u64));
    }

    #[test]
    fn a_sealed_record_is_bound_to_its_header() {
        let c = crypto(Padding::Padme);
        let (header, env) = c.seal(1, ExtentKind::RawChunk, Hash32([1; 32]), CodecId::None, 3, b"abc", vec![]);
        // Moved under another hash: refused.
        let mut other = header.clone();
        other.content_hash = Hash32([2; 32]);
        assert_eq!(c.open(&other, env.clone()), Err(SealError::Authentication));
        // Any envelope byte changed: refused.
        for i in 0..env.len() {
            let mut bad = env.clone();
            bad[i] ^= 0x80;
            assert_eq!(c.open(&header, bad), Err(SealError::Authentication), "byte {i}");
        }
        // Another pool's keys: refused.
        assert_eq!(crypto(Padding::Padme).open(&header, env), Err(SealError::Authentication));
    }

    #[test]
    fn plaintext_records_are_refused_once_the_minimum_epoch_rises() {
        let c = crypto(Padding::Padme);
        let plain_header = ExtentRecordHeader {
            magic: EXTENT_RECORD_MAGIC,
            record_len: 0,
            content_hash: Hash32::of(b"x"),
            kind: ExtentKind::RawChunk,
            codec_id: CodecId::None,
            flags: 0,
            uncompressed_len: 1,
            compressed_len: 1,
            backpointers: vec![],
            header_checksum: 0,
        };
        assert_eq!(
            c.open(&plain_header, b"x".to_vec()),
            Err(SealError::BelowMinimum { epoch: 0, min: 1 })
        );
        assert!(RecordCrypto::plaintext().open(&plain_header, b"x".to_vec()).is_ok());
    }

    #[test]
    fn a_plaintext_pool_cannot_open_a_sealed_record() {
        let c = crypto(Padding::None);
        let (header, env) = c.seal(1, ExtentKind::RawChunk, Hash32([1; 32]), CodecId::None, 3, b"abc", vec![]);
        assert_eq!(RecordCrypto::plaintext().open(&header, env), Err(SealError::KeyRequired));
    }

    #[test]
    fn keyed_and_plaintext_verification_use_the_records_own_epoch() {
        let c = crypto(Padding::None);
        let (e, h) = c.address(b"data");
        assert!(c.verify(e, b"data", h).is_ok());
        assert!(c.verify(0, b"data", h).is_err());
        assert!(c.verify(0, b"data", Hash32::of(b"data")).is_ok());
    }
}
