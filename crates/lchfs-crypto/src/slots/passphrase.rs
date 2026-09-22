//! Passphrase slots: Argon2id stretches the passphrase into the key that
//! wraps the keyring key.
//!
//! The cost is chosen once, when the slot is made, and stored with it, so
//! a slot made on a fast machine still opens on a slow one (just slower).
//! `KdfCost::Calibrate` picks the memory cost that takes about a second
//! here, never below 64 MiB: the memory, not the time, is what makes a
//! GPU or ASIC guess expensive.

use crate::secret::{Key32, random_bytes};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// What a passphrase slot records about how its key was derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseParams {
    pub salt: [u8; 32],
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes over that memory.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// How expensive a new passphrase slot's derivation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfCost {
    /// About a second on this machine, at least `MIN_CALIBRATED_M_KIB`.
    Calibrate,
    /// Exactly these parameters. For tests, and for someone who knows why.
    Explicit { m_kib: u32, t: u32, p: u32 },
}

/// Calibration never goes below this memory cost (64 MiB).
pub const MIN_CALIBRATED_M_KIB: u32 = 64 * 1024;
/// ...nor above this (2 GiB): a slot has to open on smaller machines too.
pub const MAX_CALIBRATED_M_KIB: u32 = 2 * 1024 * 1024;
const CALIBRATION_TARGET: Duration = Duration::from_millis(1000);
const CALIBRATED_T: u32 = 3;
/// The `argon2` crate computes lanes one after another, so more lanes buy
/// no speed here -- one lane, and all of the budget spent on memory.
const CALIBRATED_P: u32 = 1;

/// The most any slot may ask of an unlock. The parameters come from the
/// keyring file, and a hostile keyring must not be able to make every
/// mount allocate 4 GiB or spin for an hour: 4 GiB, 64 passes, 16 lanes.
pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
pub const MAX_T: u32 = 64;
pub const MAX_P: u32 = 16;

#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    #[error("invalid Argon2 parameters: {0}")]
    Params(String),
}

fn argon2(m_kib: u32, t: u32, p: u32) -> Result<Argon2<'static>, KdfError> {
    if m_kib > MAX_M_KIB || t > MAX_T || p > MAX_P {
        return Err(KdfError::Params(format!(
            "m={m_kib} KiB t={t} p={p} exceeds the limit of m={MAX_M_KIB} KiB t={MAX_T} p={MAX_P}"
        )));
    }
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|e| KdfError::Params(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// The key-encryption key a passphrase yields under `params`.
pub fn derive(passphrase: &[u8], params: &PassphraseParams) -> Result<Key32, KdfError> {
    let mut out = [0u8; 32];
    argon2(params.m_kib, params.t, params.p)?
        .hash_password_into(passphrase, &params.salt, &mut out)
        .map_err(|e| KdfError::Params(e.to_string()))?;
    let key = Key32::from_bytes(out);
    zeroize::Zeroize::zeroize(&mut out);
    Ok(key)
}

/// Fresh parameters (new salt) at the requested cost.
pub fn new_params(cost: KdfCost) -> Result<PassphraseParams, KdfError> {
    let salt = random_bytes();
    let (m_kib, t, p) = match cost {
        KdfCost::Explicit { m_kib, t, p } => (m_kib, t, p),
        KdfCost::Calibrate => (calibrate()?, CALIBRATED_T, CALIBRATED_P),
    };
    // Validate now, not at unlock time.
    argon2(m_kib, t, p)?;
    Ok(PassphraseParams { salt, m_kib, t, p })
}

/// Doubles the memory cost from the floor until one derivation takes the
/// target time, scaling the last step so it lands near it rather than up
/// to twice past it.
fn calibrate() -> Result<u32, KdfError> {
    let mut m = MIN_CALIBRATED_M_KIB;
    loop {
        let start = Instant::now();
        let mut out = [0u8; 32];
        argon2(m, CALIBRATED_T, CALIBRATED_P)?
            .hash_password_into(b"lchfs calibration", &[0u8; 16], &mut out)
            .map_err(|e| KdfError::Params(e.to_string()))?;
        let took = start.elapsed();
        if took >= CALIBRATION_TARGET || m >= MAX_CALIBRATED_M_KIB {
            return Ok(m.min(MAX_CALIBRATED_M_KIB));
        }
        let scale = CALIBRATION_TARGET.as_secs_f64() / took.as_secs_f64().max(1e-3);
        if scale < 2.0 {
            let scaled = (f64::from(m) * scale) as u32;
            return Ok(scaled.clamp(MIN_CALIBRATED_M_KIB, MAX_CALIBRATED_M_KIB));
        }
        m = m.saturating_mul(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: KdfCost = KdfCost::Explicit { m_kib: 64, t: 1, p: 1 };

    #[test]
    fn same_passphrase_same_key_different_salt_different_key() {
        let params = new_params(CHEAP).unwrap();
        assert_eq!(derive(b"hunter2", &params).unwrap(), derive(b"hunter2", &params).unwrap());
        assert_ne!(derive(b"hunter2", &params).unwrap(), derive(b"hunter3", &params).unwrap());
        let other = new_params(CHEAP).unwrap();
        assert_ne!(derive(b"hunter2", &params).unwrap(), derive(b"hunter2", &other).unwrap());
    }

    #[test]
    fn nonsense_parameters_are_refused_up_front() {
        assert!(new_params(KdfCost::Explicit { m_kib: 1, t: 0, p: 1 }).is_err());
    }

    #[test]
    fn a_hostile_slot_cannot_demand_unbounded_work() {
        for (m_kib, t, p) in [(MAX_M_KIB + 1, 1, 1), (64, MAX_T + 1, 1), (64, 1, MAX_P + 1), (u32::MAX, u32::MAX, u32::MAX)] {
            let params = PassphraseParams { salt: [0; 32], m_kib, t, p };
            assert!(derive(b"x", &params).is_err(), "m={m_kib} t={t} p={p}");
        }
    }
}
