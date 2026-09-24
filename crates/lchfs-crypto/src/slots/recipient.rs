//! Recipient slots: the keyring key wrapped to a public key, post-quantum.
//!
//! The KEM is X-Wing -- X25519 and ML-KEM-768 (FIPS 203) combined so that
//! breaking the slot needs *both* broken: a classical attack on the young
//! lattice scheme leaves X25519 standing, and a quantum computer that
//! breaks X25519 leaves ML-KEM standing. A pool copied today cannot be
//! opened later by whoever builds the quantum computer.
//!
//! The `x-wing` crate implements draft 06 of the X-Wing specification. The
//! slot records that (`RecipientAlg::XWingDraft06`), and the identity and
//! recipient texts carry it in their prefix, so a later revision of the
//! construction is a new algorithm tag beside this one -- never a silent
//! change to what an existing slot means.
//!
//! An *identity* is the 32-byte X-Wing decapsulation seed and opens the
//! slot; a *recipient* is the matching 1216-byte encapsulation key and is
//! all a pool needs to add the slot. Keep the identity offline -- paper, a
//! hardware token, a safe -- and the pool can be recovered with every
//! passphrase lost, without any machine that mounts it ever holding the
//! secret.

use crate::secret::Key32;
use serde::{Deserialize, Serialize};
use x_wing::kem::Decapsulator;
use x_wing::{
    CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE, Decapsulate, DecapsulationKey, ENCAPSULATION_KEY_SIZE, Encapsulate,
    EncapsulationKey, KeyExport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientAlg {
    /// X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem-06.
    XWingDraft06,
}

const IDENTITY_PREFIX: &str = "LCHFS-XWING-D06-SECRET-";
const RECIPIENT_PREFIX: &str = "lchfs-xwing-d06-";
const CONTEXT_KEK: &str = "lchfs 2026-09-22 recipient slot key-encryption key v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecipientError {
    #[error("not an lchfs identity (expected a line starting {IDENTITY_PREFIX})")]
    BadIdentity,
    #[error("not an lchfs recipient (expected a line starting {RECIPIENT_PREFIX})")]
    BadRecipient,
    #[error("malformed recipient slot")]
    BadSlot,
}

/// The secret half. Zeroed on drop (the seed lives in a `Key32`).
#[derive(Debug, Clone)]
pub struct Identity {
    seed: Key32,
}

/// The public half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    encapsulation_key: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Self {
        Self { seed: Key32::random() }
    }

    fn decapsulation_key(&self) -> DecapsulationKey {
        DecapsulationKey::from(*self.seed.expose())
    }

    pub fn recipient(&self) -> Recipient {
        Recipient {
            encapsulation_key: self.decapsulation_key().encapsulation_key().to_bytes().to_vec(),
        }
    }

    /// One line, plus a comment line saying what it is. Zeroes itself.
    pub fn to_text(&self) -> zeroize::Zeroizing<String> {
        const COMMENT: &str = "# lchfs recipient identity (X-Wing: X25519 + ML-KEM-768, draft 06). Keep this secret.\n";
        let line = self.key_line();
        let mut s = zeroize::Zeroizing::new(String::with_capacity(COMMENT.len() + line.len() + 1));
        s.push_str(COMMENT);
        s.push_str(&line);
        s.push('\n');
        s
    }

    /// Just the key line (no comment, no newline) -- what `parse` needs,
    /// and nothing a JSON encoder would have to escape. Zeroes itself.
    pub fn key_line(&self) -> zeroize::Zeroizing<String> {
        let hex = self.seed.to_hex();
        let mut s = zeroize::Zeroizing::new(String::with_capacity(IDENTITY_PREFIX.len() + hex.len()));
        s.push_str(IDENTITY_PREFIX);
        s.push_str(&hex);
        s
    }

    pub fn parse(text: &str) -> Result<Self, RecipientError> {
        let line = key_line(text, IDENTITY_PREFIX).ok_or(RecipientError::BadIdentity)?;
        // Straight into locked memory (the seed is exactly a Key32's size).
        const _: () = assert!(DECAPSULATION_KEY_SIZE == 32);
        let seed = Key32::from_hex(line).ok_or(RecipientError::BadIdentity)?;
        Ok(Self { seed })
    }
}

impl Recipient {
    pub fn to_text(&self) -> String {
        format!("{RECIPIENT_PREFIX}{}\n", hex_encode(&self.encapsulation_key))
    }

    pub fn parse(text: &str) -> Result<Self, RecipientError> {
        let line = key_line(text, RECIPIENT_PREFIX).ok_or(RecipientError::BadRecipient)?;
        let bytes = hex_decode(line).ok_or(RecipientError::BadRecipient)?;
        Self::from_bytes(&bytes).map_err(|_| RecipientError::BadRecipient)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecipientError> {
        if bytes.len() != ENCAPSULATION_KEY_SIZE || EncapsulationKey::try_from(bytes).is_err() {
            return Err(RecipientError::BadRecipient);
        }
        Ok(Self {
            encapsulation_key: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// A fresh encapsulation: the ciphertext to store in the slot, and the
    /// key-encryption key it stands for. `binding` (the pool uuid and slot
    /// id) goes into the key derivation, so a ciphertext lifted from one
    /// slot or pool yields a useless key anywhere else.
    pub fn encapsulate(&self, binding: &[u8]) -> (Vec<u8>, Key32) {
        let ek = EncapsulationKey::try_from(self.encapsulation_key.as_slice())
            .expect("validated when the recipient was made");
        let (ct, shared) = ek.encapsulate();
        (ct.to_vec(), kek(shared.as_slice(), binding))
    }
}

/// The key-encryption key `identity` recovers from a slot's ciphertext.
pub fn decapsulate(identity: &Identity, ciphertext: &[u8], binding: &[u8]) -> Result<Key32, RecipientError> {
    if ciphertext.len() != CIPHERTEXT_SIZE {
        return Err(RecipientError::BadSlot);
    }
    let ct = x_wing::Ciphertext::try_from(ciphertext).map_err(|_| RecipientError::BadSlot)?;
    let shared = identity.decapsulation_key().decapsulate(&ct);
    Ok(kek(shared.as_slice(), binding))
}

fn kek(shared: &[u8], binding: &[u8]) -> Key32 {
    let mut material = Vec::with_capacity(shared.len() + binding.len());
    material.extend_from_slice(shared);
    material.extend_from_slice(binding);
    let key = Key32::from_bytes(blake3::derive_key(CONTEXT_KEK, &material));
    zeroize::Zeroize::zeroize(&mut material);
    key
}

/// The first non-comment line starting with `prefix`, without it.
fn key_line<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(prefix))
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_opens_with_its_identity_only() {
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let (ct, kek_sent) = alice.recipient().encapsulate(b"pool-a slot-1");
        assert_eq!(decapsulate(&alice, &ct, b"pool-a slot-1").unwrap(), kek_sent);
        // ML-KEM decapsulation never "fails"; the wrong identity just gets a
        // different key, which the keyring's AEAD then refuses.
        assert_ne!(decapsulate(&mallory, &ct, b"pool-a slot-1").unwrap(), kek_sent);
        assert_ne!(decapsulate(&alice, &ct, b"pool-b slot-1").unwrap(), kek_sent, "bound to its slot");
    }

    #[test]
    fn text_forms_round_trip_and_reject_each_other() {
        let id = Identity::generate();
        let text = id.to_text();
        let back = Identity::parse(&text).unwrap();
        assert_eq!(back.recipient(), id.recipient());
        let pub_text = id.recipient().to_text();
        assert_eq!(Recipient::parse(&pub_text).unwrap(), id.recipient());
        assert_eq!(Identity::parse(&pub_text).unwrap_err(), RecipientError::BadIdentity);
        assert_eq!(Recipient::parse(&text).unwrap_err(), RecipientError::BadRecipient);
        assert_eq!(Recipient::parse("lchfs-xwing-d06-abcd").unwrap_err(), RecipientError::BadRecipient);
    }

    /// The X-Wing specification's own test vectors (vendored from the
    /// `x-wing` crate, which took them from the draft's repository): the
    /// seed must yield exactly the published public key, and decapsulating
    /// the published ciphertext must yield exactly the published shared
    /// secret. Guards the one construction every recipient slot rests on
    /// against a dependency change that alters it.
    #[test]
    fn specification_test_vectors() {
        #[derive(serde::Deserialize)]
        struct Vector {
            seed: String,
            ss: String,
            pk: String,
            ct: String,
        }
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../../tests/xwing-draft06-vectors.json")).unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let seed: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
            let id = Identity {
                seed: Key32::from_bytes(seed),
            };
            assert_eq!(id.recipient().as_bytes(), hex::decode(&v.pk).unwrap().as_slice());
            let ct = x_wing::Ciphertext::try_from(hex::decode(&v.ct).unwrap().as_slice()).unwrap();
            let shared = id.decapsulation_key().decapsulate(&ct);
            assert_eq!(shared.as_slice(), hex::decode(&v.ss).unwrap().as_slice());
        }
    }
}
