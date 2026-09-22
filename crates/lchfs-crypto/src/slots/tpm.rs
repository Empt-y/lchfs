//! TPM2 slots: a key-encryption key sealed to this machine's TPM.
//!
//! The slot's key never exists outside the TPM except while unlocking. It
//! is sealed as a keyed-hash object under the owner hierarchy's storage
//! key, with `userWithAuth` off, so the *only* way to unseal it is the
//! policy it was created with:
//!
//! - `PolicyPCR` over the chosen PCRs (SHA-256 bank) at their values when
//!   the slot was made -- by default PCR 7, the Secure Boot state, as
//!   systemd-cryptenroll does. A different boot chain unseals nothing.
//! - with a PIN, also `PolicyAuthValue`, the PIN being the object's auth
//!   value. The object is *not* `noDA`, so wrong PINs trip the TPM's own
//!   dictionary-attack lockout: a stolen machine does not get unlimited
//!   guesses.
//!
//! The storage key is re-derived from a fixed ECC P-256 template on every
//! use (the TPM derives the same key from the same template), so nothing
//! is ever made persistent in the TPM. Unsealing runs in a policy session
//! salted with that key and with response encryption on, so the key does
//! not cross the bus to the TPM in the clear.
//!
//! The TCTI is `LCHFS_TPM_TCTI` if set (any tpm2-tss TCTI string, e.g.
//! `swtpm:port=2321`), else the kernel resource manager `/dev/tpmrm0`.

use crate::keyring::TpmSlot;
use crate::secret::Key32;
use std::str::FromStr;
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{
    Auth, Digest, EccPoint, KeyedHashScheme, MaxBuffer, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Private,
    Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, TctiNameConf};

/// PCRs a slot binds to when none are given: the Secure Boot policy.
pub const DEFAULT_PCRS: &[u8] = &[7];

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("{0}")]
    Tss(#[from] tss_esapi::Error),
    #[error("invalid PCR index {0} (must be 0..=23)")]
    BadPcr(u8),
    #[error("malformed TPM slot: {0}")]
    BadSlot(&'static str),
    #[error("PIN required")]
    PinRequired,
    #[error("unexpected TPM response: {0}")]
    Unexpected(&'static str),
}

fn context() -> Result<Context, TpmError> {
    let tcti = match std::env::var("LCHFS_TPM_TCTI") {
        Ok(s) => TctiNameConf::from_str(&s)?,
        Err(_) => TctiNameConf::from_str("device:/dev/tpmrm0")?,
    };
    Ok(Context::new(tcti)?)
}

fn storage_template() -> Result<Public, TpmError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

fn storage_key(ctx: &mut Context) -> Result<KeyHandle, TpmError> {
    let template = storage_template()?;
    Ok(ctx
        .execute_with_nullauth_session(|c| c.create_primary(Hierarchy::Owner, template, None, None, None, None))?
        .key_handle)
}

fn selection(pcrs: &[u8]) -> Result<PcrSelectionList, TpmError> {
    let mut slots = Vec::with_capacity(pcrs.len());
    for &p in pcrs {
        if p > 23 {
            return Err(TpmError::BadPcr(p));
        }
        slots.push(PcrSlot::try_from(1u32 << p)?);
    }
    Ok(PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()?)
}

/// SHA-256 over the selected PCRs' current values, in ascending index
/// order -- the digest `PolicyPCR` compares against.
fn current_pcr_digest(ctx: &mut Context, pcrs: &[u8]) -> Result<Digest, TpmError> {
    let mut sorted = pcrs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut concatenated = Vec::with_capacity(sorted.len() * 32);
    // pcr_read returns at most eight digests per call; read one at a time.
    for &p in &sorted {
        let (_, _, digests) = ctx.execute_without_session(|c| c.pcr_read(selection(&[p])?).map_err(TpmError::from))?;
        let value = digests.value().first().ok_or(TpmError::Unexpected("PCR read returned no digest"))?;
        concatenated.extend_from_slice(value.value());
    }
    let (digest, _) = ctx.execute_without_session(|c| {
        c.hash(MaxBuffer::try_from(concatenated)?, HashingAlgorithm::Sha256, Hierarchy::Null)
    })?;
    Ok(digest)
}

fn policy_session(ctx: &mut Context, kind: SessionType, salt: Option<KeyHandle>) -> Result<PolicySession, TpmError> {
    let session = ctx
        .start_auth_session(salt, None, None, kind, SymmetricDefinition::AES_128_CFB, HashingAlgorithm::Sha256)?
        .ok_or(TpmError::Unexpected("no session handle"))?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(session, attributes, mask)?;
    Ok(PolicySession::try_from(session)?)
}

/// The policy a slot's object is sealed under.
fn policy_digest(ctx: &mut Context, pcrs: &[u8], pin: bool) -> Result<Digest, TpmError> {
    let pcr_digest = current_pcr_digest(ctx, pcrs)?;
    let trial = policy_session(ctx, SessionType::Trial, None)?;
    let result = (|| {
        ctx.policy_pcr(trial, pcr_digest, selection(pcrs)?)?;
        if pin {
            ctx.policy_auth_value(trial)?;
        }
        Ok(ctx.policy_get_digest(trial)?)
    })();
    let _ = ctx.flush_context(ObjectHandle::from(tss_esapi::handles::SessionHandle::from(trial)));
    result
}

/// Seals `kek` to this TPM under the current values of `pcrs` (and `pin`,
/// if given).
pub fn seal(kek: &Key32, pcrs: &[u8], pin: Option<&[u8]>) -> Result<TpmSlot, TpmError> {
    let pcrs = if pcrs.is_empty() { DEFAULT_PCRS.to_vec() } else { pcrs.to_vec() };
    let mut ctx = context()?;
    let parent = storage_key(&mut ctx)?;
    let result = (|| {
        let digest = policy_digest(&mut ctx, &pcrs, pin.is_some())?;
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_no_da(pin.is_none())
            .with_admin_with_policy(true)
            .with_user_with_auth(false)
            .build()?;
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_auth_policy(digest)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()?;
        let auth = pin.map(|p| Auth::try_from(p.to_vec())).transpose()?;
        let sensitive = SensitiveData::try_from(kek.expose().to_vec())?;
        let created = ctx.execute_with_nullauth_session(|c| c.create(parent, public, auth, Some(sensitive), None, None))?;
        Ok(TpmSlot {
            public: created.out_public.marshall()?,
            private: created.out_private.value().to_vec(),
            pcrs: pcrs.clone(),
            pin: pin.is_some(),
        })
    })();
    let _ = ctx.flush_context(parent.into());
    result
}

/// Unseals a slot's key-encryption key. Fails if the PCRs have moved, the
/// PIN is wrong (which counts toward the TPM's lockout), or the slot was
/// sealed by a different TPM.
pub fn unseal(slot: &TpmSlot, pin: Option<&[u8]>) -> Result<Key32, TpmError> {
    if slot.pin && pin.is_none() {
        return Err(TpmError::PinRequired);
    }
    let public = Public::unmarshall(&slot.public)?;
    let private = Private::try_from(slot.private.clone())?;
    let mut ctx = context()?;
    let parent = storage_key(&mut ctx)?;
    let mut handles: Vec<ObjectHandle> = vec![parent.into()];
    let result = (|| {
        let object = ctx.execute_with_nullauth_session(|c| c.load(parent, private, public))?;
        handles.push(object.into());
        let session = policy_session(&mut ctx, SessionType::Policy, Some(parent))?;
        handles.push(ObjectHandle::from(tss_esapi::handles::SessionHandle::from(session)));
        // An empty digest makes the TPM compare against the PCRs' values
        // right now.
        ctx.policy_pcr(session, Digest::default(), selection(&slot.pcrs)?)?;
        if slot.pin {
            ctx.policy_auth_value(session)?;
            ctx.tr_set_auth(object.into(), Auth::try_from(pin.unwrap_or_default().to_vec())?)?;
        }
        let secret = ctx.execute_with_session(Some(session.into()), |c| c.unseal(object.into()))?;
        let bytes: [u8; 32] = secret
            .value()
            .try_into()
            .map_err(|_| TpmError::BadSlot("sealed data is not a 32-byte key"))?;
        Ok(Key32::from_bytes(bytes))
    })();
    for h in handles.into_iter().rev() {
        let _ = ctx.flush_context(h);
    }
    result
}

/// These talk to a real TPM and change nothing persistent in it (the
/// storage key is transient). Opt in with `LCHFS_TEST_TPM=1`.
#[cfg(test)]
mod tests {
    use super::*;

    /// A software TPM behind a direct TCTI has no resource manager and only
    /// a few object slots, so these take turns.
    static TPM: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn enabled() -> Option<std::sync::MutexGuard<'static, ()>> {
        std::env::var("LCHFS_TEST_TPM")
            .is_ok_and(|v| v == "1")
            .then(|| TPM.lock().unwrap_or_else(|e| e.into_inner()))
    }

    #[test]
    fn seal_and_unseal_without_pin() {
        let Some(_tpm) = enabled() else { return };
        let kek = Key32::random();
        let slot = seal(&kek, &[7], None).unwrap();
        assert_eq!(unseal(&slot, None).unwrap(), kek);
    }

    #[test]
    fn a_pin_slot_needs_the_right_pin() {
        let Some(_tpm) = enabled() else { return };
        let kek = Key32::random();
        let slot = seal(&kek, &[7], Some(b"2468")).unwrap();
        assert!(matches!(unseal(&slot, None), Err(TpmError::PinRequired)));
        assert_eq!(unseal(&slot, Some(b"2468")).unwrap(), kek);
        // One wrong guess only: each counts toward the TPM's lockout.
        assert!(unseal(&slot, Some(b"1357")).is_err());
    }

    #[test]
    fn a_seal_to_a_pcr_that_has_moved_does_not_open() {
        let Some(_tpm) = enabled() else { return };
        // PCR 16 is the debug PCR, resettable and extendable by anyone;
        // extending it changes its value from what the seal saw.
        let kek = Key32::random();
        let slot = seal(&kek, &[16], None).unwrap();
        assert_eq!(unseal(&slot, None).unwrap(), kek);
        let mut ctx = context().unwrap();
        let digest = tss_esapi::structures::DigestValues::default();
        let mut values = digest;
        values.set(HashingAlgorithm::Sha256, Digest::try_from(vec![0x5a; 32]).unwrap());
        ctx.execute_with_nullauth_session(|c| c.pcr_extend(tss_esapi::handles::PcrHandle::Pcr16, values))
            .unwrap();
        assert!(unseal(&slot, None).is_err());
    }

    #[test]
    fn a_keyring_tpm_slot_unlocks_and_survives_revocation() {
        use crate::keyring::{NewSlot, Padding, Unlock, UnlockedKeyring, parse};
        use crate::slots::passphrase::KdfCost;
        let Some(_tpm) = enabled() else { return };
        let cheap = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };
        // A TPM slot alone is refused -- a PCR change must not brick a pool.
        let mut ring = UnlockedKeyring::create(
            [3; 16],
            Padding::Padme,
            NewSlot::Passphrase { passphrase: b"recovery", cost: cheap, label: "p".into() },
        )
        .unwrap();
        ring.add_slot(NewSlot::Tpm { pcrs: vec![7], pin: Some(b"1234"), label: "this machine".into() }).unwrap();
        let doomed = ring.add_slot(NewSlot::Passphrase { passphrase: b"old", cost: cheap, label: "old".into() }).unwrap();
        let file = ring.to_file();
        let locked = parse(&file).unwrap();
        assert!(locked.unlock(&Unlock::Tpm { pin: None }).is_err(), "the PIN is required");
        let by_tpm = locked.unlock(&Unlock::Tpm { pin: Some(b"1234") }).unwrap();
        assert_eq!(by_tpm.keyring_key(), ring.keyring_key());

        // Revoking reseals the TPM slot under the new keyring key, PIN kept.
        ring.revoke_slot(doomed, &mut |slot| {
            Ok(match slot.kind.type_name() {
                "tpm2" => b"1234".to_vec(),
                _ => b"recovery".to_vec(),
            })
        })
        .unwrap();
        let fresh = parse(&ring.to_file()).unwrap();
        let reopened = fresh.unlock(&Unlock::Tpm { pin: Some(b"1234") }).unwrap();
        assert_eq!(reopened.keyring_key(), ring.keyring_key());
    }
}
