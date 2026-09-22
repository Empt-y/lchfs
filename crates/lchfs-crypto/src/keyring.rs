//! The keyring: which keys an encrypted pool's content is under, and every
//! way (slot) of unlocking them.
//!
//! Two levels, the LUKS arrangement. A random *keyring key* (KK) is what
//! every slot wraps; KK in turn wraps each epoch's master key. So adding,
//! removing or changing a passphrase touches one slot and no content key,
//! and rotating the content key (a new epoch) touches no slot.
//!
//! On disk, one copy per vdev (`<root>/keyring`), newest valid generation
//! wins -- the same rule as superblocks:
//!
//! ```text
//! magic "LCHFSKR\0" | version u32 | body_len u32 | body | mac [32] | checksum [32]
//! ```
//!
//! `checksum` is plain BLAKE3 over everything before it and catches a
//! damaged file before any unlock is attempted. `mac` is keyed with a key
//! derived from KK, so it can only be checked after an unlock -- and is,
//! every time: a slot list, config or epoch table changed by anyone
//! without KK is refused as tampering rather than trusted. The slots and
//! config are otherwise in the clear (there is nothing secret in a salt
//! or a public key); every key in the body is wrapped.

use crate::envelope;
use crate::epoch::{self, EpochKeys, MAX_EPOCH, PLAINTEXT_EPOCH};
use crate::secret::Key32;
use crate::slots::passphrase::{self, KdfCost, PassphraseParams};
use crate::slots::recipient::{self, Identity, Recipient, RecipientAlg};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const KEYRING_MAGIC: [u8; 8] = *b"LCHFSKR\0";
pub const KEYRING_VERSION: u32 = 1;
/// File name at the root of every vdev of an encrypted pool.
pub const KEYRING_FILE: &str = "keyring";
/// A keyring is small (a few KiB even with many recipient slots); refuse
/// to even allocate for anything claiming to be much larger.
const MAX_BODY_LEN: usize = 1 << 20;

const CONTEXT_MAC: &str = "lchfs 2026-09-22 keyring mac key v1";
const AAD_SLOT: &[u8] = b"lchfs-keyring-slot-v1";
const AAD_EPOCH: &[u8] = b"lchfs-keyring-epoch-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Padding {
    None,
    Padme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversionPhase {
    /// New writes use the target epoch; existing content is being
    /// rewritten into it.
    Rewriting,
    /// Everything reachable is in the target epoch; older records and keys
    /// are being destroyed.
    Retiring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conversion {
    pub target_epoch: u16,
    pub phase: ConversionPhase,
}

/// Pool-wide encryption settings, authenticated by the keyring MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringConfig {
    pub padding: Padding,
    /// The epoch new records are written under.
    pub current_epoch: u16,
    /// Records older than this are refused on read. `PLAINTEXT_EPOCH` while
    /// a plaintext pool is being converted; raised when retirement ends,
    /// after which a plaintext record appearing in the pool is a detected
    /// downgrade, not data.
    pub min_epoch: u16,
    pub conversion: Option<Conversion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientSlot {
    pub alg: RecipientAlg,
    /// Kept so the slot can be rewrapped (revocation re-keys KK) without
    /// the identity.
    pub encapsulation_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmSlot {
    /// TPM2B_PUBLIC and TPM2B_PRIVATE of the sealed object, marshalled.
    pub public: Vec<u8>,
    pub private: Vec<u8>,
    /// PCR indices (SHA-256 bank) the seal is bound to.
    pub pcrs: Vec<u8>,
    /// Whether unsealing also needs a PIN.
    pub pin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotKind {
    Passphrase(PassphraseParams),
    Recipient(RecipientSlot),
    Tpm2(TpmSlot),
}

impl SlotKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotKind::Passphrase(_) => "passphrase",
            SlotKind::Recipient(_) => "recipient",
            SlotKind::Tpm2(_) => "tpm2",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    pub id: u16,
    pub label: String,
    pub created_unix: i64,
    pub kind: SlotKind,
    /// KK sealed under this slot's key-encryption key.
    pub wrapped_kk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedEpoch {
    pub epoch: u16,
    pub wrapped_master: Vec<u8>,
    pub check: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringBody {
    pub pool_uuid: [u8; 16],
    pub generation: u64,
    pub config: KeyringConfig,
    pub slots: Vec<Slot>,
    pub epochs: Vec<WrappedEpoch>,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("not a keyring: {0}")]
    Malformed(&'static str),
    #[error("keyring version {0} is not supported (this build reads version {KEYRING_VERSION})")]
    Version(u32),
    #[error("keyring checksum mismatch: the file is damaged")]
    Checksum,
    #[error("no slot accepts this key")]
    NoMatchingSlot,
    #[error("keyring MAC mismatch: the keyring was modified by something without its key")]
    Tampered,
    #[error("epoch {0}'s master key does not match the keyring's record of it")]
    EpochCheck(u16),
    #[error("no such slot {0}")]
    NoSuchSlot(u16),
    #[error("{0}")]
    Refused(String),
    #[error("passphrase derivation: {0}")]
    Kdf(#[from] passphrase::KdfError),
    #[error("TPM: {0}")]
    Tpm(String),
    #[error("keyring I/O: {0}")]
    Io(#[from] io::Error),
    #[error("keyrings on this pool's devices disagree: {0}")]
    Diverged(String),
}

/// How to open a slot.
pub enum Unlock<'a> {
    Passphrase(&'a [u8]),
    Identity(&'a Identity),
    Tpm { pin: Option<&'a [u8]> },
}

/// A slot to add.
pub enum NewSlot<'a> {
    Passphrase {
        passphrase: &'a [u8],
        cost: KdfCost,
        label: String,
    },
    Recipient {
        recipient: &'a Recipient,
        label: String,
    },
    Tpm {
        pcrs: Vec<u8>,
        pin: Option<&'a [u8]>,
        label: String,
    },
}

/// A parsed keyring whose checksum holds, not yet unlocked.
#[derive(Debug, Clone)]
pub struct LockedKeyring {
    body: KeyringBody,
    mac: [u8; 32],
    body_bytes: Vec<u8>,
}

/// An unlocked keyring: KK in hand, every epoch key unwrapped and checked.
#[derive(Debug)]
pub struct UnlockedKeyring {
    body: KeyringBody,
    kk: Key32,
    masters: BTreeMap<u16, Key32>,
}

fn slot_aad(pool_uuid: &[u8; 16], id: u16, kind: &SlotKind) -> Vec<u8> {
    let mut aad = AAD_SLOT.to_vec();
    aad.extend_from_slice(pool_uuid);
    aad.extend_from_slice(&id.to_le_bytes());
    // The slot's own parameters are bound too: a salt, cost or recipient
    // swapped under an existing wrapped KK makes it unopenable, not weaker.
    aad.extend_from_slice(&bincode::serialize(&kind_binding(kind)).expect("slot kind serializes"));
    aad
}

/// What of a slot's kind its wrapped KK is bound to. A recipient slot's
/// ciphertext is excluded -- it is an input to the key, already bound by
/// the KEM -- and so is a TPM slot's private blob, which the TPM itself
/// authenticates; everything that says *how* to derive the key is in.
fn kind_binding(kind: &SlotKind) -> SlotKind {
    match kind {
        SlotKind::Passphrase(p) => SlotKind::Passphrase(p.clone()),
        SlotKind::Recipient(r) => SlotKind::Recipient(RecipientSlot {
            alg: r.alg,
            encapsulation_key: r.encapsulation_key.clone(),
            ciphertext: Vec::new(),
        }),
        SlotKind::Tpm2(t) => SlotKind::Tpm2(TpmSlot {
            public: t.public.clone(),
            private: Vec::new(),
            pcrs: t.pcrs.clone(),
            pin: t.pin,
        }),
    }
}

fn epoch_aad(pool_uuid: &[u8; 16], epoch: u16) -> Vec<u8> {
    let mut aad = AAD_EPOCH.to_vec();
    aad.extend_from_slice(pool_uuid);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// What a recipient or TPM derivation is bound to.
fn slot_binding(pool_uuid: &[u8; 16], id: u16) -> Vec<u8> {
    let mut b = pool_uuid.to_vec();
    b.extend_from_slice(&id.to_le_bytes());
    b
}

fn mac(kk: &Key32, body_bytes: &[u8]) -> [u8; 32] {
    let key = kk.derive(CONTEXT_MAC);
    let mut hasher = blake3::Hasher::new_keyed(key.expose());
    hasher.update(&KEYRING_VERSION.to_le_bytes());
    hasher.update(body_bytes);
    *hasher.finalize().as_bytes()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses and checksums a keyring file. Does not unlock it.
pub fn parse(bytes: &[u8]) -> Result<LockedKeyring, KeyringError> {
    const FIXED: usize = 8 + 4 + 4;
    if bytes.len() < FIXED + 64 {
        return Err(KeyringError::Malformed("too short"));
    }
    if bytes[0..8] != KEYRING_MAGIC {
        return Err(KeyringError::Malformed("bad magic"));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != KEYRING_VERSION {
        return Err(KeyringError::Version(version));
    }
    let body_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if body_len > MAX_BODY_LEN || FIXED + body_len + 64 != bytes.len() {
        return Err(KeyringError::Malformed("length fields disagree with the file"));
    }
    let checksum_at = FIXED + body_len + 32;
    if blake3::hash(&bytes[..checksum_at]).as_bytes() != &bytes[checksum_at..] {
        return Err(KeyringError::Checksum);
    }
    let body_bytes = bytes[FIXED..FIXED + body_len].to_vec();
    let body: KeyringBody = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BODY_LEN as u64)
        .deserialize(&body_bytes)
        .map_err(|_| KeyringError::Malformed("body does not decode"))?;
    let mac: [u8; 32] = bytes[FIXED + body_len..checksum_at].try_into().unwrap();
    Ok(LockedKeyring { body, mac, body_bytes })
}

fn encode_file(body: &KeyringBody, kk: &Key32) -> Vec<u8> {
    let body_bytes = bincode::serialize(body).expect("keyring body serializes");
    assert!(body_bytes.len() <= MAX_BODY_LEN, "keyring body exceeds its own size limit");
    let mut out = Vec::with_capacity(16 + body_bytes.len() + 64);
    out.extend_from_slice(&KEYRING_MAGIC);
    out.extend_from_slice(&KEYRING_VERSION.to_le_bytes());
    out.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&body_bytes);
    out.extend_from_slice(&mac(kk, &body_bytes));
    let checksum = blake3::hash(&out);
    out.extend_from_slice(checksum.as_bytes());
    out
}

impl LockedKeyring {
    pub fn body(&self) -> &KeyringBody {
        &self.body
    }

    /// Tries every slot `how` could open, then checks the MAC and every
    /// epoch key.
    pub fn unlock(&self, how: &Unlock<'_>) -> Result<UnlockedKeyring, KeyringError> {
        let uuid = &self.body.pool_uuid;
        #[cfg_attr(not(feature = "tpm"), allow(unused_mut))]
        let mut last_err: Option<KeyringError> = None;
        for slot in &self.body.slots {
            let kek = match (how, &slot.kind) {
                // A slot whose parameters are refused (a hostile keyring
                // asking for unbounded work) is skipped, not fatal: it must
                // not be able to stop every other slot from opening.
                (Unlock::Passphrase(p), SlotKind::Passphrase(params)) => match passphrase::derive(p, params) {
                    Ok(k) => k,
                    Err(e) => {
                        last_err = Some(e.into());
                        continue;
                    }
                },
                (Unlock::Identity(id), SlotKind::Recipient(r)) => {
                    match recipient::decapsulate(id, &r.ciphertext, &slot_binding(uuid, slot.id)) {
                        Ok(k) => k,
                        Err(_) => continue,
                    }
                }
                #[cfg(feature = "tpm")]
                (Unlock::Tpm { pin }, SlotKind::Tpm2(t)) => match crate::slots::tpm::unseal(t, *pin) {
                    Ok(k) => k,
                    Err(e) => {
                        last_err = Some(KeyringError::Tpm(e.to_string()));
                        continue;
                    }
                },
                _ => continue,
            };
            if let Ok(kk) = envelope::unwrap_key(&kek, &slot_aad(uuid, slot.id, &slot.kind), &slot.wrapped_kk) {
                return self.unlock_with_kk(kk);
            }
        }
        Err(last_err.unwrap_or(KeyringError::NoMatchingSlot))
    }

    /// Unlocks with KK itself -- what a mounted pool, which already holds
    /// it, uses to re-read a keyring it wrote.
    pub fn unlock_with_kk(&self, kk: Key32) -> Result<UnlockedKeyring, KeyringError> {
        if mac(&kk, &self.body_bytes) != self.mac {
            return Err(KeyringError::Tampered);
        }
        let mut masters = BTreeMap::new();
        for e in &self.body.epochs {
            let master = envelope::unwrap_key(&kk, &epoch_aad(&self.body.pool_uuid, e.epoch), &e.wrapped_master)
                .map_err(|_| KeyringError::Tampered)?;
            if epoch::key_check_value(&master) != e.check {
                return Err(KeyringError::EpochCheck(e.epoch));
            }
            masters.insert(e.epoch, master);
        }
        Ok(UnlockedKeyring {
            body: self.body.clone(),
            kk,
            masters,
        })
    }
}

impl UnlockedKeyring {
    /// A new keyring for `pool_uuid` with one epoch (1) current and
    /// `first` as its only slot. `min_epoch` starts at 1: a pool created
    /// encrypted never holds a plaintext record.
    pub fn create(pool_uuid: [u8; 16], padding: Padding, first: NewSlot<'_>) -> Result<Self, KeyringError> {
        let mut ring = Self {
            body: KeyringBody {
                pool_uuid,
                generation: 0,
                config: KeyringConfig {
                    padding,
                    current_epoch: 1,
                    min_epoch: 1,
                    conversion: None,
                },
                slots: Vec::new(),
                epochs: Vec::new(),
            },
            kk: Key32::random(),
            masters: BTreeMap::new(),
        };
        ring.insert_epoch(1, Key32::random());
        ring.add_slot(first)?;
        ring.check_slot_rules()?;
        Ok(ring)
    }

    /// A keyring for a plaintext pool about to be converted: epoch 1
    /// exists and is the target, but `current_epoch` and `min_epoch` stay
    /// at the plaintext epoch until the engine switches writers over.
    pub fn create_for_conversion(pool_uuid: [u8; 16], padding: Padding, first: NewSlot<'_>) -> Result<Self, KeyringError> {
        let mut ring = Self::create(pool_uuid, padding, first)?;
        ring.body.config.current_epoch = PLAINTEXT_EPOCH;
        ring.body.config.min_epoch = PLAINTEXT_EPOCH;
        ring.body.config.conversion = Some(Conversion {
            target_epoch: 1,
            phase: ConversionPhase::Rewriting,
        });
        Ok(ring)
    }

    pub fn body(&self) -> &KeyringBody {
        &self.body
    }

    pub fn config(&self) -> &KeyringConfig {
        &self.body.config
    }

    pub fn config_mut(&mut self) -> &mut KeyringConfig {
        &mut self.body.config
    }

    pub fn pool_uuid(&self) -> [u8; 16] {
        self.body.pool_uuid
    }

    pub fn keyring_key(&self) -> &Key32 {
        &self.kk
    }

    /// Derived content keys for every epoch this keyring holds.
    pub fn epoch_keys(&self) -> Vec<EpochKeys> {
        self.masters.iter().map(|(&e, mk)| EpochKeys::derive(e, mk)).collect()
    }

    pub fn epochs(&self) -> Vec<u16> {
        self.masters.keys().copied().collect()
    }

    fn insert_epoch(&mut self, epoch: u16, master: Key32) {
        let wrapped_master = envelope::wrap_key(&self.kk, &epoch_aad(&self.body.pool_uuid, epoch), &master);
        self.body.epochs.retain(|e| e.epoch != epoch);
        self.body.epochs.push(WrappedEpoch {
            epoch,
            wrapped_master,
            check: epoch::key_check_value(&master),
        });
        self.body.epochs.sort_by_key(|e| e.epoch);
        self.masters.insert(epoch, master);
    }

    /// A fresh epoch with a new random master key, one above the highest
    /// that exists. Does not make it current -- that is the engine's call,
    /// once its writers can use it.
    pub fn add_epoch(&mut self) -> Result<u16, KeyringError> {
        let next = self.masters.keys().max().copied().unwrap_or(PLAINTEXT_EPOCH) + 1;
        if next > MAX_EPOCH {
            return Err(KeyringError::Refused(format!("no epochs left (the limit is {MAX_EPOCH})")));
        }
        self.insert_epoch(next, Key32::random());
        Ok(next)
    }

    /// Destroys an epoch's master key. Refuses the current one, and any the
    /// config still allows records of.
    pub fn drop_epoch(&mut self, epoch: u16) -> Result<(), KeyringError> {
        let c = &self.body.config;
        if epoch == c.current_epoch || epoch >= c.min_epoch || c.conversion.is_some_and(|v| v.target_epoch == epoch) {
            return Err(KeyringError::Refused(format!("epoch {epoch} is still in use")));
        }
        self.body.epochs.retain(|e| e.epoch != epoch);
        self.masters.remove(&epoch);
        Ok(())
    }

    fn next_slot_id(&self) -> u16 {
        self.body.slots.iter().map(|s| s.id + 1).max().unwrap_or(0)
    }

    pub fn add_slot(&mut self, new: NewSlot<'_>) -> Result<u16, KeyringError> {
        let id = self.next_slot_id();
        let slot = self.make_slot(id, new, now_unix())?;
        self.body.slots.push(slot);
        Ok(id)
    }

    fn make_slot(&self, id: u16, new: NewSlot<'_>, created_unix: i64) -> Result<Slot, KeyringError> {
        let uuid = self.body.pool_uuid;
        let (label, kind, kek) = match new {
            NewSlot::Passphrase { passphrase, cost, label } => {
                let params = passphrase::new_params(cost)?;
                let kek = passphrase::derive(passphrase, &params)?;
                (label, SlotKind::Passphrase(params), kek)
            }
            NewSlot::Recipient { recipient, label } => {
                let (ciphertext, kek) = recipient.encapsulate(&slot_binding(&uuid, id));
                let kind = SlotKind::Recipient(RecipientSlot {
                    alg: RecipientAlg::XWingDraft06,
                    encapsulation_key: recipient.as_bytes().to_vec(),
                    ciphertext,
                });
                (label, kind, kek)
            }
            #[cfg(feature = "tpm")]
            NewSlot::Tpm { pcrs, pin, label } => {
                let kek = Key32::random();
                let sealed = crate::slots::tpm::seal(&kek, &pcrs, pin).map_err(|e| KeyringError::Tpm(e.to_string()))?;
                (label, SlotKind::Tpm2(sealed), kek)
            }
            #[cfg(not(feature = "tpm"))]
            NewSlot::Tpm { .. } => {
                return Err(KeyringError::Tpm("this build has no TPM support (the `tpm` feature)".into()));
            }
        };
        let wrapped_kk = envelope::wrap_key(&kek, &slot_aad(&uuid, id, &kind), &self.kk);
        Ok(Slot {
            id,
            label,
            created_unix,
            kind,
            wrapped_kk,
        })
    }

    /// At least one slot, and at least one that is not a TPM: a TPM seal
    /// breaks when its PCRs change (a firmware update, a boot-chain
    /// change), and that must never be able to lock the pool for good.
    fn check_slot_rules(&self) -> Result<(), KeyringError> {
        if !self.body.slots.iter().any(|s| !matches!(s.kind, SlotKind::Tpm2(_))) {
            return Err(KeyringError::Refused(
                "a pool needs at least one passphrase or recipient slot; a TPM slot alone can be locked out by a firmware or boot change".into(),
            ));
        }
        Ok(())
    }

    /// Removes a slot. Whoever knew its secret *and* kept a copy of the old
    /// keyring can still open that copy; `revoke_slot` is what closes that.
    pub fn remove_slot(&mut self, id: u16) -> Result<(), KeyringError> {
        let before = self.body.slots.clone();
        if !self.body.slots.iter().any(|s| s.id == id) {
            return Err(KeyringError::NoSuchSlot(id));
        }
        self.body.slots.retain(|s| s.id != id);
        if let Err(e) = self.check_slot_rules() {
            self.body.slots = before;
            return Err(e);
        }
        Ok(())
    }

    /// Removes a slot *and* replaces KK, rewrapping every remaining slot
    /// and epoch under the new one, so an old copy of the keyring opened
    /// with the revoked secret yields a KK that opens nothing written from
    /// here on. It still opens the epoch keys that copy held -- revocation
    /// cannot reach back into a copy someone already has -- which is why a
    /// revocation should be followed by a rekey to a new epoch.
    ///
    /// Recipient slots are rewrapped from their stored public key. A
    /// passphrase slot needs its passphrase again, and a TPM slot with a
    /// PIN its PIN: `secret_for` supplies them, and each is checked against
    /// its slot before it is used. A TPM slot is resealed only after it is
    /// shown to unseal on *this* machine's TPM -- one sealed to another
    /// host's TPM cannot be resealed here, and is refused by name so it can
    /// be removed first.
    pub fn revoke_slot(
        &mut self,
        id: u16,
        secret_for: &mut dyn FnMut(&Slot) -> Result<Vec<u8>, KeyringError>,
    ) -> Result<(), KeyringError> {
        // Everything is rebuilt aside and swapped in only on success, so a
        // wrong passphrase halfway through leaves the keyring -- including
        // the slot being revoked -- exactly as it was.
        let all_slots = self.body.slots.clone();
        self.remove_slot(id)?;
        let old_slots = std::mem::take(&mut self.body.slots);
        let masters: Vec<(u16, Key32)> = self.masters.iter().map(|(&e, k)| (e, k.clone())).collect();
        let old_kk = std::mem::replace(&mut self.kk, Key32::random());
        let rebuilt = (|| {
            let mut slots = Vec::with_capacity(old_slots.len());
            for slot in &old_slots {
                let new = match &slot.kind {
                    SlotKind::Passphrase(params) => {
                        let mut pass = secret_for(slot)?;
                        let kek = passphrase::derive(&pass, params)?;
                        let proves = envelope::unwrap_key(&kek, &slot_aad(&self.body.pool_uuid, slot.id, &slot.kind), &slot.wrapped_kk)
                            .is_ok_and(|k| k == old_kk);
                        if !proves {
                            zeroize::Zeroize::zeroize(&mut pass);
                            return Err(KeyringError::Refused(format!("wrong passphrase for slot {} ({})", slot.id, slot.label)));
                        }
                        let made = self.make_slot(
                            slot.id,
                            NewSlot::Passphrase {
                                passphrase: &pass,
                                cost: KdfCost::Explicit {
                                    m_kib: params.m_kib,
                                    t: params.t,
                                    p: params.p,
                                },
                                label: slot.label.clone(),
                            },
                            slot.created_unix,
                        );
                        zeroize::Zeroize::zeroize(&mut pass);
                        made?
                    }
                    SlotKind::Recipient(r) => {
                        let recipient = Recipient::from_bytes(&r.encapsulation_key)
                            .map_err(|_| KeyringError::Malformed("recipient slot holds an invalid public key"))?;
                        self.make_slot(
                            slot.id,
                            NewSlot::Recipient {
                                recipient: &recipient,
                                label: slot.label.clone(),
                            },
                            slot.created_unix,
                        )?
                    }
                    SlotKind::Tpm2(t) => self.reseal_tpm_slot(slot, t, &old_kk, secret_for)?,
                };
                slots.push(new);
            }
            Ok(slots)
        })();
        match rebuilt {
            Ok(slots) => {
                self.body.slots = slots;
                self.body.epochs.clear();
                for (e, mk) in masters {
                    self.insert_epoch(e, mk);
                }
                Ok(())
            }
            Err(e) => {
                self.kk = old_kk;
                self.body.slots = all_slots;
                Err(e)
            }
        }
    }

    #[cfg(feature = "tpm")]
    fn reseal_tpm_slot(
        &self,
        slot: &Slot,
        t: &TpmSlot,
        old_kk: &Key32,
        secret_for: &mut dyn FnMut(&Slot) -> Result<Vec<u8>, KeyringError>,
    ) -> Result<Slot, KeyringError> {
        let mut pin = if t.pin { Some(secret_for(slot)?) } else { None };
        let proven = crate::slots::tpm::unseal(t, pin.as_deref())
            .ok()
            .and_then(|kek| {
                envelope::unwrap_key(&kek, &slot_aad(&self.body.pool_uuid, slot.id, &slot.kind), &slot.wrapped_kk).ok()
            })
            .is_some_and(|k| &k == old_kk);
        let made = if proven {
            self.make_slot(
                slot.id,
                NewSlot::Tpm {
                    pcrs: t.pcrs.clone(),
                    pin: pin.as_deref(),
                    label: slot.label.clone(),
                },
                slot.created_unix,
            )
        } else {
            Err(KeyringError::Refused(format!(
                "TPM slot {} ({}) does not unseal on this machine{}; remove it before revoking, or revoke on the machine it belongs to",
                slot.id,
                slot.label,
                if t.pin { " with that PIN" } else { "" }
            )))
        };
        if let Some(p) = pin.as_mut() {
            zeroize::Zeroize::zeroize(p);
        }
        made
    }

    #[cfg(not(feature = "tpm"))]
    fn reseal_tpm_slot(
        &self,
        slot: &Slot,
        _t: &TpmSlot,
        _old_kk: &Key32,
        _secret_for: &mut dyn FnMut(&Slot) -> Result<Vec<u8>, KeyringError>,
    ) -> Result<Slot, KeyringError> {
        Err(KeyringError::Tpm(format!(
            "slot {} is a TPM slot and this build has no TPM support (the `tpm` feature)",
            slot.id
        )))
    }

    /// The file bytes for the next generation of this keyring.
    pub fn to_file(&mut self) -> Vec<u8> {
        self.body.generation += 1;
        encode_file(&self.body, &self.kk)
    }
}

/// The keyring file under one vdev root.
pub fn path_on(root: &Path) -> PathBuf {
    root.join(KEYRING_FILE)
}

pub fn exists_on(root: &Path) -> bool {
    path_on(root).exists()
}

/// Replaces the keyring on one root atomically: a temporary file, fsync,
/// rename over the old one, fsync the directory. A crash leaves the old
/// keyring or the new one, never a torn mix.
pub fn write_on(root: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = root.join(format!("{KEYRING_FILE}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path_on(root))?;
    std::fs::File::open(root)?.sync_all()
}

/// Writes to every root, returning the ones that failed. The caller
/// decides whether that faults a device.
pub fn write_all(roots: &[&Path], bytes: &[u8]) -> Vec<(PathBuf, io::Error)> {
    roots
        .iter()
        .filter_map(|r| write_on(r, bytes).err().map(|e| (r.to_path_buf(), e)))
        .collect()
}

/// Every root's keyring that parses and checksums, highest generation
/// first. Roots with none, or a damaged one, are simply absent. Two
/// different keyrings claiming the same generation, or different pools,
/// are refused rather than guessed between.
pub fn read_all(roots: &[&Path]) -> Result<Vec<(PathBuf, LockedKeyring)>, KeyringError> {
    let mut found: Vec<(PathBuf, LockedKeyring)> = Vec::new();
    for root in roots {
        let bytes = match std::fs::read(path_on(root)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if let Ok(k) = parse(&bytes) {
            found.push((root.to_path_buf(), k));
        }
    }
    if let Some((_, first)) = found.first() {
        let uuid = first.body.pool_uuid;
        if found.iter().any(|(_, k)| k.body.pool_uuid != uuid) {
            return Err(KeyringError::Diverged("keyrings from different pools".into()));
        }
    }
    found.sort_by_key(|(_, k)| std::cmp::Reverse(k.body.generation));
    for pair in found.windows(2) {
        if pair[0].1.body.generation == pair[1].1.body.generation && pair[0].1.body_bytes != pair[1].1.body_bytes {
            return Err(KeyringError::Diverged(format!(
                "{} and {} both claim generation {}",
                pair[0].0.display(),
                pair[1].0.display(),
                pair[0].1.body.generation
            )));
        }
    }
    Ok(found)
}

/// Unlocks the newest keyring across `roots` that `how` opens and whose
/// MAC holds. A newer copy that fails its MAC -- planted, or damaged in a
/// way the checksum missed -- is passed over for the next genuine one,
/// and reported, so the caller can rewrite it.
pub fn unlock_newest(roots: &[&Path], how: &Unlock<'_>) -> Result<(UnlockedKeyring, Vec<PathBuf>), KeyringError> {
    let all = read_all(roots)?;
    if all.is_empty() {
        return Err(KeyringError::Malformed("no keyring on any device"));
    }
    let mut rejected = Vec::new();
    let mut last = KeyringError::NoMatchingSlot;
    for (root, locked) in &all {
        match locked.unlock(how) {
            Ok(ring) => {
                let generation = ring.body.generation;
                let stale: Vec<PathBuf> = roots
                    .iter()
                    .filter(|r| !all.iter().any(|(p, k)| p == *r && k.body.generation == generation))
                    .map(|r| r.to_path_buf())
                    .chain(rejected)
                    .collect();
                return Ok((ring, stale));
            }
            Err(e @ (KeyringError::Tampered | KeyringError::EpochCheck(_))) => {
                rejected.push(root.clone());
                last = e;
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: KdfCost = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };
    const UUID: [u8; 16] = [7; 16];

    fn pass_slot(p: &[u8]) -> NewSlot<'_> {
        NewSlot::Passphrase {
            passphrase: p,
            cost: CHEAP,
            label: "test".into(),
        }
    }

    #[test]
    fn create_write_parse_unlock_round_trip() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"correct horse")).unwrap();
        let id = Identity::generate();
        ring.add_slot(NewSlot::Recipient {
            recipient: &id.recipient(),
            label: "offline recovery".into(),
        })
        .unwrap();
        let keys_before: Vec<_> = ring.epoch_keys().iter().map(|k| k.address(b"x")).collect();
        let bytes = ring.to_file();

        let locked = parse(&bytes).unwrap();
        assert_eq!(locked.body().generation, 1);
        for how in [Unlock::Passphrase(b"correct horse"), Unlock::Identity(&id)] {
            let opened = locked.unlock(&how).unwrap();
            let keys_after: Vec<_> = opened.epoch_keys().iter().map(|k| k.address(b"x")).collect();
            assert_eq!(keys_before, keys_after);
        }
        assert!(matches!(locked.unlock(&Unlock::Passphrase(b"wrong")), Err(KeyringError::NoMatchingSlot)));
        assert!(matches!(
            locked.unlock(&Unlock::Identity(&Identity::generate())),
            Err(KeyringError::NoMatchingSlot)
        ));
    }

    #[test]
    fn any_changed_byte_is_refused_one_way_or_another() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        let bytes = ring.to_file();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            let opened = parse(&bad).and_then(|k| k.unlock(&Unlock::Passphrase(b"pw")));
            assert!(opened.is_err(), "byte {i} changed and the keyring still opened");
        }
    }

    #[test]
    fn a_rewritten_body_with_a_fixed_checksum_is_caught_by_the_mac() {
        // Someone without KK edits the config -- say, to drop padding or
        // lower min_epoch -- and recomputes the plain checksum.
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        let bytes = ring.to_file();
        let mut locked = parse(&bytes).unwrap();
        locked.body.config.padding = Padding::None;
        let body_bytes = bincode::serialize(&locked.body).unwrap();
        let mut forged = Vec::new();
        forged.extend_from_slice(&KEYRING_MAGIC);
        forged.extend_from_slice(&KEYRING_VERSION.to_le_bytes());
        forged.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        forged.extend_from_slice(&body_bytes);
        forged.extend_from_slice(&locked.mac);
        let sum = blake3::hash(&forged);
        forged.extend_from_slice(sum.as_bytes());
        let reparsed = parse(&forged).unwrap();
        assert!(matches!(reparsed.unlock(&Unlock::Passphrase(b"pw")), Err(KeyringError::Tampered)));
    }

    #[test]
    fn a_slot_cannot_be_moved_to_another_pool_or_id() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        let slot = ring.body.slots[0].clone();
        let kek = match &slot.kind {
            SlotKind::Passphrase(p) => passphrase::derive(b"pw", p).unwrap(),
            _ => unreachable!(),
        };
        assert!(envelope::unwrap_key(&kek, &slot_aad(&UUID, slot.id, &slot.kind), &slot.wrapped_kk).is_ok());
        assert!(envelope::unwrap_key(&kek, &slot_aad(&[8; 16], slot.id, &slot.kind), &slot.wrapped_kk).is_err());
        assert!(envelope::unwrap_key(&kek, &slot_aad(&UUID, slot.id + 1, &slot.kind), &slot.wrapped_kk).is_err());
        let _ = ring.to_file();
    }

    #[test]
    fn slot_rules_hold() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        assert!(matches!(ring.remove_slot(0), Err(KeyringError::Refused(_))), "cannot remove the last slot");
        let second = ring.add_slot(pass_slot(b"pw2")).unwrap();
        ring.remove_slot(0).unwrap();
        assert_eq!(ring.body.slots.len(), 1);
        assert_eq!(ring.body.slots[0].id, second);
        assert!(matches!(ring.remove_slot(99), Err(KeyringError::NoSuchSlot(99))));
    }

    #[test]
    fn revocation_replaces_the_keyring_key_and_keeps_content_keys() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"keep")).unwrap();
        let id = Identity::generate();
        ring.add_slot(NewSlot::Recipient {
            recipient: &id.recipient(),
            label: "r".into(),
        })
        .unwrap();
        let leaked = ring.add_slot(pass_slot(b"leaked")).unwrap();
        let old_file = ring.to_file();
        let old_kk = ring.kk.clone();
        let content_before: Vec<_> = ring.epoch_keys().iter().map(|k| k.address(b"c")).collect();

        // A wrong passphrase for the surviving slot aborts and changes nothing.
        let err = ring.revoke_slot(leaked, &mut |_| Ok(b"nope".to_vec()));
        assert!(matches!(err, Err(KeyringError::Refused(_))));
        assert_eq!(ring.kk, old_kk);
        assert_eq!(ring.body.slots.len(), 3);

        ring.revoke_slot(leaked, &mut |_| Ok(b"keep".to_vec())).unwrap();
        assert_ne!(ring.kk, old_kk);
        let new_file = ring.to_file();
        let fresh = parse(&new_file).unwrap();
        assert!(fresh.unlock(&Unlock::Passphrase(b"leaked")).is_err());
        let by_pass = fresh.unlock(&Unlock::Passphrase(b"keep")).unwrap();
        let by_id = fresh.unlock(&Unlock::Identity(&id)).unwrap();
        assert_eq!(by_pass.kk, by_id.kk);
        let content_after: Vec<_> = by_pass.epoch_keys().iter().map(|k| k.address(b"c")).collect();
        assert_eq!(content_before, content_after);
        // The old copy still opens with the revoked secret -- only into the
        // old KK, which the new keyring no longer honours.
        let old = parse(&old_file).unwrap().unlock(&Unlock::Passphrase(b"leaked")).unwrap();
        assert!(fresh.unlock_with_kk(old.kk.clone()).is_err());
    }

    #[test]
    fn epochs_are_added_and_dropped_under_the_rules() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        assert_eq!(ring.epochs(), vec![1]);
        let e2 = ring.add_epoch().unwrap();
        assert_eq!(e2, 2);
        assert!(ring.drop_epoch(1).is_err(), "1 is current");
        ring.config_mut().current_epoch = 2;
        assert!(ring.drop_epoch(1).is_err(), "min_epoch still admits it");
        ring.config_mut().min_epoch = 2;
        ring.drop_epoch(1).unwrap();
        assert_eq!(ring.epochs(), vec![2]);
        let bytes = ring.to_file();
        let reopened = parse(&bytes).unwrap().unlock(&Unlock::Passphrase(b"pw")).unwrap();
        assert_eq!(reopened.epochs(), vec![2]);
    }

    #[test]
    fn newest_valid_generation_wins_and_a_forged_newer_one_is_passed_over() {
        let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let roots: Vec<&Path> = dirs.iter().map(|d| d.path()).collect();
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        let g1 = ring.to_file();
        assert!(write_all(&roots, &g1).is_empty());
        ring.add_slot(pass_slot(b"second")).unwrap();
        let g2 = ring.to_file();
        write_on(roots[0], &g2).unwrap();

        let (opened, stale) = unlock_newest(&roots, &Unlock::Passphrase(b"second")).unwrap();
        assert_eq!(opened.body.generation, 2);
        assert_eq!(stale.len(), 2, "the two devices still on generation 1");

        // A planted generation-9 keyring with the real slots but no valid MAC.
        let mut planted = parse(&g2).unwrap();
        planted.body.generation = 9;
        let body_bytes = bincode::serialize(&planted.body).unwrap();
        let mut forged = Vec::new();
        forged.extend_from_slice(&KEYRING_MAGIC);
        forged.extend_from_slice(&KEYRING_VERSION.to_le_bytes());
        forged.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        forged.extend_from_slice(&body_bytes);
        forged.extend_from_slice(&[0u8; 32]);
        let sum = blake3::hash(&forged);
        forged.extend_from_slice(sum.as_bytes());
        write_on(roots[2], &forged).unwrap();
        let (opened, stale) = unlock_newest(&roots, &Unlock::Passphrase(b"pw")).unwrap();
        assert_eq!(opened.body.generation, 2, "the forgery is passed over");
        assert!(stale.contains(&roots[2].to_path_buf()));
    }

    #[test]
    fn a_hostile_slot_does_not_block_the_others() {
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        // Planted ahead of the real slot, asking for 1 TiB of memory.
        let mut hostile = ring.body.slots[0].clone();
        hostile.id = 9;
        if let SlotKind::Passphrase(p) = &mut hostile.kind {
            p.m_kib = u32::MAX;
        }
        ring.body.slots.insert(0, hostile);
        let bytes = ring.to_file();
        assert!(parse(&bytes).unwrap().unlock(&Unlock::Passphrase(b"pw")).is_ok());
    }

    /// Writes the fuzzers' seed corpus. Run by hand when the format changes:
    /// `cargo test -p lchfs-crypto write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/keyring_parse");
        std::fs::create_dir_all(&dir).unwrap();
        let cheap = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };
        let mut ring = UnlockedKeyring::create(UUID, Padding::Padme, NewSlot::Passphrase {
            passphrase: b"fuzz",
            cost: cheap,
            label: "seed".into(),
        })
        .unwrap();
        std::fs::write(dir.join("one-passphrase-slot"), ring.to_file()).unwrap();
        ring.add_slot(NewSlot::Recipient {
            recipient: &Identity::generate().recipient(),
            label: "recipient".into(),
        })
        .unwrap();
        ring.add_epoch().unwrap();
        std::fs::write(dir.join("recipient-and-two-epochs"), ring.to_file()).unwrap();
        let env_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/envelope_open");
        std::fs::create_dir_all(&env_dir).unwrap();
        let mut seed = vec![4u8];
        seed.extend_from_slice(b"aad!");
        seed.extend_from_slice(&envelope::seal(&Key32::from_bytes([7; 32]), b"aad!", b"payload"));
        std::fs::write(env_dir.join("valid-envelope"), seed).unwrap();
    }

    #[test]
    fn a_conversion_keyring_starts_in_the_plaintext_epoch() {
        let ring = UnlockedKeyring::create_for_conversion(UUID, Padding::Padme, pass_slot(b"pw")).unwrap();
        assert_eq!(ring.config().current_epoch, PLAINTEXT_EPOCH);
        assert_eq!(ring.config().min_epoch, PLAINTEXT_EPOCH);
        assert_eq!(ring.config().conversion.unwrap().target_epoch, 1);
        assert_eq!(ring.epochs(), vec![1]);
    }
}
