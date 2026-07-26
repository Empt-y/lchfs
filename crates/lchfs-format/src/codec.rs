//! Generic bincode-over-serde encode/decode for every schema type in this
//! crate. ARCHITECTURE.md §11 lists `serde, bincode` as this crate's only
//! non-crypto dependencies specifically so this is the one place the
//! byte-level encoding lives — `lchfs-store` calls these, never touches
//! bincode directly.

use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, thiserror::Error)]
#[error("failed to encode {type_name}: {source}")]
pub struct EncodeError {
    pub type_name: &'static str,
    #[source]
    pub source: bincode::Error,
}

#[derive(Debug, thiserror::Error)]
#[error("failed to decode {type_name}: {source}")]
pub struct DecodeError {
    pub type_name: &'static str,
    #[source]
    pub source: bincode::Error,
}

/// Serializes any schema type to its canonical on-disk byte representation.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    bincode::serialize(value).map_err(|source| EncodeError {
        type_name: std::any::type_name::<T>(),
        source,
    })
}

/// Inverse of [`encode`]. Never trusts the bytes beyond what `bincode`
/// itself validates — callers still owe the mandatory content-hash check
/// (ARCHITECTURE.md §1) once the payload has been decoded.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    bincode::deserialize(bytes).map_err(|source| DecodeError {
        type_name: std::any::type_name::<T>(),
        source,
    })
}
