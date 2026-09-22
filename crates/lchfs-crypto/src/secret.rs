//! Key material. Everything secret in lchfs is a `Key32`: it zeroes itself
//! on drop, never prints its bytes, and is only ever copied on purpose.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit secret: a keyring key, an epoch master key, a key derived
/// from one, or a key-encryption key a slot produced.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Fresh key from the OS CSPRNG.
    pub fn random() -> Self {
        Self(random_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for handing to a primitive. Deliberately not `Deref`:
    /// every place key bytes leave this type should be visible.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// `blake3::derive_key` with this key as the input keying material.
    /// `context` must be a fixed, versioned, globally unique string.
    pub fn derive(&self, context: &str) -> Key32 {
        Key32(blake3::derive_key(context, &self.0))
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// `N` bytes from the OS CSPRNG. A failing OS RNG leaves nothing safe to
/// do -- no key, nonce or salt may be made up -- so it is a panic.
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
