//! BLAKE3 content hashing and CRC32C header checksums.
//!
//! See ARCHITECTURE.md, unifying design principle and §1 (On-disk format):
//! `Hash32` is the single mechanism that serves as Merkle DAG pointer,
//! integrity check, and dedup key throughout LCHFS.

use thiserror::Error;

/// A BLAKE3-256 content hash. The identity of every Extent Record's payload
/// (§1) and the pointer type used throughout the Merkle DAG object schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Compute the content hash of `data`. Callers must always hash the
    /// *uncompressed* logical bytes (ARCHITECTURE.md §2) — never the
    /// compressed on-disk representation.
    pub fn of(data: &[u8]) -> Self {
        Hash32(*blake3::hash(data).as_bytes())
    }
}

/// Errors produced while verifying record integrity.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("header checksum mismatch")]
    HeaderChecksum,
    #[error("content hash mismatch: expected {expected:?}, got {actual:?}")]
    ContentHash { expected: Hash32, actual: Hash32 },
}

/// Cheap CRC32C check over an Extent Record / superblock slot header, run
/// before spending BLAKE3 cycles on the (possibly much larger) payload.
/// ARCHITECTURE.md §1: "header_checksum (cheap CRC32C pre-check before
/// spending BLAKE3 cycles)".
pub fn header_checksum(bytes: &[u8]) -> u32 {
    crc32fast::hash(bytes)
}

/// Mandatory read-side integrity check (ARCHITECTURE.md §1, §4):
/// `BLAKE3(decompressed) == content_hash`, always performed, never optional.
pub fn verify(decompressed: &[u8], expected: Hash32) -> Result<(), VerifyError> {
    let actual = Hash32::of(decompressed);
    if actual == expected {
        Ok(())
    } else {
        Err(VerifyError::ContentHash { expected, actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(Hash32::of(b"hello world"), Hash32::of(b"hello world"));
    }

    #[test]
    fn hash_differs_on_different_input() {
        assert_ne!(Hash32::of(b"hello"), Hash32::of(b"world"));
    }

    #[test]
    fn empty_input_hashes_to_blake3_empty_hash() {
        let expected = blake3::hash(b"");
        assert_eq!(Hash32::of(b"").0, *expected.as_bytes());
    }

    #[test]
    fn verify_succeeds_on_matching_content() {
        let data = b"lchfs extent payload";
        let hash = Hash32::of(data);
        assert!(verify(data, hash).is_ok());
    }

    #[test]
    fn verify_fails_on_mismatched_content() {
        let hash = Hash32::of(b"original");
        let err = verify(b"tampered", hash).unwrap_err();
        match err {
            VerifyError::ContentHash { expected, actual } => {
                assert_eq!(expected, hash);
                assert_eq!(actual, Hash32::of(b"tampered"));
            }
            VerifyError::HeaderChecksum => panic!("wrong variant"),
        }
    }

    #[test]
    fn header_checksum_is_deterministic_and_sensitive() {
        let a = header_checksum(b"header-bytes-v1");
        let b = header_checksum(b"header-bytes-v1");
        let c = header_checksum(b"header-bytes-v2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
