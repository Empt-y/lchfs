//! Per-epoch content keys and keyed addressing.
//!
//! An encrypted pool's content lives under a *key epoch*: a random master
//! key `MK_e`, from which two independent keys are derived -- one that
//! computes content addresses, one that encrypts records. Epoch 0 is the
//! plaintext epoch: no key, addresses are unkeyed BLAKE3 exactly as every
//! pool before encryption used them, so those pools need no migration.
//!
//! A keyed address is `BLAKE3-keyed(K_addr, plaintext)`. Without the key it
//! is indistinguishable from random, so an address on disk no longer tells
//! anyone whether the pool holds a file they already have. Dedup still
//! works, because equal plaintexts under one epoch still get equal
//! addresses -- which is also exactly what it leaks: that two records in
//! the same pool are equal, and nothing more.

use crate::Hash32;
use crate::secret::Key32;

/// The plaintext epoch.
pub const PLAINTEXT_EPOCH: u16 = 0;
/// Largest epoch a record header can carry (15 bits of `flags`).
pub const MAX_EPOCH: u16 = 0x7FFF;

const CONTEXT_ADDRESS: &str = "lchfs 2026-09-22 epoch content-address key v1";
const CONTEXT_RECORD: &str = "lchfs 2026-09-22 epoch record-encryption key v1";
const CONTEXT_CHECK: &str = "lchfs 2026-09-22 epoch key-check value v1";

/// The keys one epoch's content is addressed and sealed with.
#[derive(Clone, Debug)]
pub struct EpochKeys {
    epoch: u16,
    address: Key32,
    record: Key32,
}

impl EpochKeys {
    pub fn derive(epoch: u16, master: &Key32) -> Self {
        assert!(epoch != PLAINTEXT_EPOCH && epoch <= MAX_EPOCH, "epoch {epoch} cannot carry keys");
        Self {
            epoch,
            address: master.derive(CONTEXT_ADDRESS),
            record: master.derive(CONTEXT_RECORD),
        }
    }

    pub fn epoch(&self) -> u16 {
        self.epoch
    }

    /// The content address of `data` under this epoch.
    pub fn address(&self, data: &[u8]) -> Hash32 {
        Hash32(*blake3::keyed_hash(self.address.expose(), data).as_bytes())
    }

    /// The key records of this epoch are sealed with.
    pub fn record_key(&self) -> &Key32 {
        &self.record
    }
}

/// A value that identifies a master key without revealing it, stored
/// beside each wrapped epoch key so an unwrap can be confirmed against the
/// keyring's own record of which key that epoch is.
pub fn key_check_value(master: &Key32) -> [u8; 32] {
    *master.derive(CONTEXT_CHECK).expose()
}

/// How a pool computes a content address: unkeyed for the plaintext
/// epoch, keyed for any other.
pub fn address(keys: Option<&EpochKeys>, data: &[u8]) -> Hash32 {
    match keys {
        None => Hash32::of(data),
        Some(k) => k.address(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_addresses_are_stable_per_key_and_unlinkable_across_keys() {
        let a = EpochKeys::derive(1, &Key32::random());
        let b = EpochKeys::derive(1, &Key32::random());
        let data = b"a chunk of file content";
        assert_eq!(a.address(data), a.address(data));
        assert_ne!(a.address(data), b.address(data));
        assert_ne!(a.address(data), Hash32::of(data), "never the unkeyed address");
        assert_eq!(address(None, data), Hash32::of(data));
    }

    #[test]
    fn address_and_record_keys_are_independent() {
        let k = EpochKeys::derive(3, &Key32::random());
        assert_ne!(k.address.expose(), k.record.expose());
    }

    #[test]
    #[should_panic]
    fn the_plaintext_epoch_has_no_keys() {
        let _ = EpochKeys::derive(PLAINTEXT_EPOCH, &Key32::random());
    }
}
