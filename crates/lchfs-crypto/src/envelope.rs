//! Authenticated encryption: XChaCha20-Poly1305 with a random 192-bit
//! nonce, laid out as `nonce ‖ ciphertext ‖ tag`.
//!
//! Every sealed thing in lchfs goes through here -- extent records, the
//! epoch master keys inside a keyring, the keyring key inside each slot.
//! The nonce is random rather than derived from the content: the same
//! content hash can legitimately be written with different inner fields
//! (codec, padding), and one repeated nonce under ChaCha20-Poly1305 leaks
//! the XOR of two plaintexts and the authentication key. 192 bits makes a
//! random collision a non-event however many records a pool holds.

use crate::secret::{Key32, random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use thiserror::Error;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Bytes an envelope adds to its plaintext.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("sealed data is shorter than its nonce and tag")]
    Truncated,
    /// Wrong key, wrong associated data, or bytes that were changed. The
    /// three are indistinguishable by design.
    #[error("authentication failed")]
    Authentication,
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.expose()).expect("a 32-byte key is the XChaCha20-Poly1305 key size")
}

/// Encrypts and authenticates `plaintext`, binding `aad` (authenticated,
/// not encrypted, not stored -- the opener must supply the same bytes).
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let body = cipher(key)
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-range lengths");
    let mut out = Vec::with_capacity(NONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    out
}

/// Verifies and decrypts an envelope made by `seal` with the same key and
/// associated data.
pub fn open(key: &Key32, aad: &[u8], envelope: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if envelope.len() < OVERHEAD {
        return Err(EnvelopeError::Truncated);
    }
    let (nonce, body) = envelope.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
    cipher(key)
        .decrypt(&XNonce::from(nonce), Payload { msg: body, aad })
        .map_err(|_| EnvelopeError::Authentication)
}

/// `seal` for a key: the wrapped form of `secret` under `key`.
pub fn wrap_key(key: &Key32, aad: &[u8], secret: &Key32) -> Vec<u8> {
    seal(key, aad, secret.expose())
}

/// Inverse of `wrap_key`.
pub fn unwrap_key(key: &Key32, aad: &[u8], wrapped: &[u8]) -> Result<Key32, EnvelopeError> {
    let mut plain = open(key, aad, wrapped)?;
    let result = <[u8; 32]>::try_from(plain.as_slice())
        .map(Key32::from_bytes)
        .map_err(|_| EnvelopeError::Authentication);
    zeroize::Zeroize::zeroize(&mut plain);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_randomized() {
        let key = Key32::random();
        let a = seal(&key, b"aad", b"hello");
        let b = seal(&key, b"aad", b"hello");
        assert_ne!(a, b, "a fresh nonce per seal");
        assert_eq!(a.len(), 5 + OVERHEAD);
        assert_eq!(open(&key, b"aad", &a).unwrap(), b"hello");
        assert_eq!(open(&key, b"aad", &b).unwrap(), b"hello");
    }

    #[test]
    fn every_single_bit_flip_is_refused() {
        let key = Key32::random();
        let sealed = seal(&key, b"context", b"the quick brown fox");
        for i in 0..sealed.len() {
            for bit in 0..8 {
                let mut bad = sealed.clone();
                bad[i] ^= 1 << bit;
                assert_eq!(open(&key, b"context", &bad), Err(EnvelopeError::Authentication), "byte {i} bit {bit}");
            }
        }
    }

    #[test]
    fn wrong_key_wrong_aad_and_truncation_are_refused() {
        let key = Key32::random();
        let sealed = seal(&key, b"context", b"data");
        assert_eq!(open(&Key32::random(), b"context", &sealed), Err(EnvelopeError::Authentication));
        assert_eq!(open(&key, b"other", &sealed), Err(EnvelopeError::Authentication));
        assert_eq!(open(&key, b"context", &sealed[..OVERHEAD - 1]), Err(EnvelopeError::Truncated));
        assert_eq!(open(&key, b"context", &sealed[..sealed.len() - 1]), Err(EnvelopeError::Authentication));
    }

    #[test]
    fn key_wrapping_round_trips() {
        let kek = Key32::random();
        let secret = Key32::random();
        let wrapped = wrap_key(&kek, b"slot", &secret);
        assert_eq!(unwrap_key(&kek, b"slot", &wrapped).unwrap(), secret);
        assert!(unwrap_key(&kek, b"other", &wrapped).is_err());
    }
}
