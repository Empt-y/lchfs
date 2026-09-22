//! The ways a keyring slot can hold the keyring key.

pub mod passphrase;
pub mod recipient;
#[cfg(feature = "tpm")]
pub mod tpm;
