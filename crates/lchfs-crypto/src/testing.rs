//! The `test-encrypt-all` switch (see the feature's comment in
//! Cargo.toml). A const, so a build without the feature carries neither
//! the switch nor anything it guards.

/// Whether this build encrypts every pool it creates without being asked.
pub const TEST_ENCRYPT_ALL: bool = cfg!(feature = "test-encrypt-all");

/// The passphrase such pools are created with and unlocked by.
pub const TEST_PASSPHRASE: &[u8] = b"lchfs test-encrypt-all passphrase";

/// A deliberately cheap derivation: the suite creates thousands of pools.
pub const TEST_KDF: crate::slots::passphrase::KdfCost =
    crate::slots::passphrase::KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };
