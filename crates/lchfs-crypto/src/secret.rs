//! Key material. Everything secret in lchfs is a `Key32`: it lives in a
//! locked, undumpable slot (`locked::Slot`), zeroes itself on drop, never
//! prints its bytes, compares in constant time, and is only ever copied on
//! purpose. Moving a `Key32` moves a pointer -- the key bytes themselves
//! never get copied around the heap.

use crate::locked::Slot;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit secret: a keyring key, an epoch master key, a key derived
/// from one, or a key-encryption key a slot produced.
pub struct Key32(Slot);

impl Key32 {
    /// Fresh key from the OS CSPRNG, generated straight into its slot.
    pub fn random() -> Self {
        let mut slot = Slot::new();
        getrandom::fill(slot.bytes_mut()).expect("the OS random number generator failed");
        Self(slot)
    }

    /// Copies `bytes` into a slot and zeroes the by-value copy it was given.
    /// (The caller's own copy, if it kept one, is the caller's to zero.)
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let mut slot = Slot::new();
        slot.bytes_mut().copy_from_slice(&bytes);
        bytes.zeroize();
        Self(slot)
    }

    /// A key from 64 hex digits (either case), decoded straight into its
    /// slot: no intermediate buffer ever holds the bytes.
    pub fn from_hex(hex: &str) -> Option<Self> {
        let digits = hex.as_bytes();
        if digits.len() != 64 {
            return None;
        }
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut slot = Slot::new();
        for (out, pair) in slot.bytes_mut().iter_mut().zip(digits.chunks_exact(2)) {
            *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Some(Self(slot))
    }

    /// Lowercase hex of the key, in a string that zeroes itself and is
    /// allocated once at its final size.
    pub fn to_hex(&self) -> zeroize::Zeroizing<String> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = zeroize::Zeroizing::new(String::with_capacity(64));
        for &b in self.expose() {
            s.push(DIGITS[usize::from(b >> 4)] as char);
            s.push(DIGITS[usize::from(b & 0xf)] as char);
        }
        s
    }

    /// The raw bytes, for handing to a primitive. Deliberately not `Deref`:
    /// every place key bytes leave this type should be visible.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.bytes()
    }

    /// `blake3::derive_key` with this key as the input keying material.
    /// `context` must be a fixed, versioned, globally unique string.
    pub fn derive(&self, context: &str) -> Key32 {
        Key32::from_bytes(blake3::derive_key(context, self.expose()))
    }
}

impl Clone for Key32 {
    fn clone(&self) -> Self {
        let mut slot = Slot::new();
        slot.bytes_mut().copy_from_slice(self.expose());
        Self(slot)
    }
}

/// Constant time: an online key proof compares a key a caller presented
/// with the one the pool holds.
impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq_32(self.expose(), other.expose())
    }
}
impl Eq for Key32 {}

impl Zeroize for Key32 {
    fn zeroize(&mut self) {
        self.0.bytes_mut().zeroize();
    }
}

/// Dropping the slot zeroes it.
impl ZeroizeOnDrop for Key32 {}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// `N` bytes from the OS CSPRNG, for nonces and salts -- never for a key,
/// which `Key32::random` generates straight into locked memory. A failing
/// OS RNG leaves nothing safe to do, so it is a panic.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the OS random number generator failed");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_keys_differ_and_debug_hides_them() {
        let a = Key32::random();
        let b = Key32::random();
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "Key32(<redacted>)");
    }

    #[test]
    fn derive_separates_contexts() {
        let k = Key32::random();
        assert_ne!(k.derive("lchfs test context a"), k.derive("lchfs test context b"));
        assert_eq!(k.derive("lchfs test context a"), k.derive("lchfs test context a"));
    }
}
