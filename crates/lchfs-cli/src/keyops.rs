//! Keyring changes (ARCHITECTURE.md §18): one description of each, applied
//! the same way to a mounted pool (over the control socket, by the mount,
//! which holds the keyring) and to an unmounted one (by the CLI, under
//! every device's pool lock).

use crate::unlock::unhex;
use crate::secrets::Secret;
use lchfs_crypto::keyring::{KeyringError, NewSlot, SlotKind, UnlockedKeyring};
use lchfs_crypto::slots::passphrase::KdfCost;
use lchfs_crypto::slots::recipient::Recipient;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// A slot to add, owning its secrets.
pub enum NewSlotSpec {
    Passphrase { passphrase: Secret, cost: KdfCost, label: String },
    Recipient { recipient: Box<Recipient>, label: String },
    Tpm { pcrs: Vec<u8>, pin: Option<Secret>, label: String },
}

pub enum KeyOp {
    Add(NewSlotSpec),
    Remove(u16),
    /// Add the new slot, then remove the old one; KK is unchanged.
    Replace { old: u16, new: NewSlotSpec },
    /// Remove a slot and replace KK; `secrets` has every remaining
    /// passphrase slot's passphrase and TPM slot's PIN, by slot id.
    Revoke { slot: u16, secrets: BTreeMap<u16, Secret> },
}

impl NewSlotSpec {
    pub fn as_new_slot(&self) -> NewSlot<'_> {
        match self {
            NewSlotSpec::Passphrase { passphrase, cost, label } => NewSlot::Passphrase {
                passphrase,
                cost: *cost,
                label: label.clone(),
            },
            NewSlotSpec::Recipient { recipient, label } => NewSlot::Recipient {
                recipient,
                label: label.clone(),
            },
            NewSlotSpec::Tpm { pcrs, pin, label } => NewSlot::Tpm {
                pcrs: pcrs.clone(),
                pin: pin.as_ref().map(|p| p.as_slice()),
                label: label.clone(),
            },
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            NewSlotSpec::Passphrase { passphrase, cost, label } => {
                let cost = match cost {
                    KdfCost::Calibrate => Value::Null,
                    KdfCost::Explicit { m_kib, t, p } => json!({ "m_kib": m_kib, "t": t, "p": p }),
                };
                json!({ "type": "passphrase", "passphrase": hex::encode(passphrase.as_slice()), "cost": cost, "label": label })
            }
            NewSlotSpec::Recipient { recipient, label } => {
                json!({ "type": "recipient", "recipient": recipient.to_text(), "label": label })
            }
            NewSlotSpec::Tpm { pcrs, pin, label } => json!({
                "type": "tpm",
                "pcrs": pcrs,
                "pin": pin.as_ref().map(|p| hex::encode(p.as_slice())),
                "label": label,
            }),
        }
    }

    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        let label = v.get("label").and_then(Value::as_str).unwrap_or("").to_string();
        let str_field = |name: &str| {
            v.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("new slot is missing {name:?}"))
        };
        match str_field("type")? {
            "passphrase" => {
                let cost = match v.get("cost") {
                    Some(c) if !c.is_null() => {
                        let n = |k: &str| {
                            c.get(k)
                                .and_then(Value::as_u64)
                                .and_then(|n| u32::try_from(n).ok())
                                .ok_or_else(|| anyhow::anyhow!("cost.{k} must be a u32"))
                        };
                        KdfCost::Explicit { m_kib: n("m_kib")?, t: n("t")?, p: n("p")? }
                    }
                    _ => KdfCost::Calibrate,
                };
                Ok(NewSlotSpec::Passphrase { passphrase: unhex(str_field("passphrase")?)?, cost, label })
            }
            "recipient" => {
                let recipient = Recipient::parse(str_field("recipient")?).map_err(|e| anyhow::anyhow!("recipient: {e}"))?;
                Ok(NewSlotSpec::Recipient { recipient: Box::new(recipient), label })
            }
            "tpm" => {
                let pcrs = v
                    .get("pcrs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("tpm slot needs pcrs"))?
                    .iter()
                    .map(|p| p.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or_else(|| anyhow::anyhow!("bad PCR")))
                    .collect::<anyhow::Result<Vec<u8>>>()?;
                let pin = match v.get("pin").and_then(Value::as_str) {
                    Some(p) => Some(unhex(p)?),
                    None => None,
                };
                Ok(NewSlotSpec::Tpm { pcrs, pin, label })
            }
            other => anyhow::bail!("unknown slot type {other:?}"),
        }
    }
}

impl KeyOp {
    pub fn to_json(&self) -> Value {
        match self {
            KeyOp::Add(new) => json!({ "op": "add", "new": new.to_json() }),
            KeyOp::Remove(id) => json!({ "op": "remove", "slot": id }),
            KeyOp::Replace { old, new } => json!({ "op": "replace", "slot": old, "new": new.to_json() }),
            KeyOp::Revoke { slot, secrets } => json!({
                "op": "revoke",
                "slot": slot,
                "secrets": secrets
                    .iter()
                    .map(|(id, s)| (id.to_string(), Value::String(hex::encode(s.as_slice()))))
                    .collect::<serde_json::Map<_, _>>(),
            }),
        }
    }

    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        let slot = || {
            v.get("slot")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| anyhow::anyhow!("slot must be a u16"))
        };
        let new = || NewSlotSpec::from_json(v.get("new").ok_or_else(|| anyhow::anyhow!("missing new slot"))?);
        match v.get("op").and_then(Value::as_str) {
            Some("add") => Ok(KeyOp::Add(new()?)),
            Some("remove") => Ok(KeyOp::Remove(slot()?)),
            Some("replace") => Ok(KeyOp::Replace { old: slot()?, new: new()? }),
            Some("revoke") => {
                let mut secrets = BTreeMap::new();
                if let Some(map) = v.get("secrets").and_then(Value::as_object) {
                    for (id, s) in map {
                        let id: u16 = id.parse().map_err(|_| anyhow::anyhow!("bad slot id {id:?}"))?;
                        let s = s.as_str().ok_or_else(|| anyhow::anyhow!("secret must be hex"))?;
                        secrets.insert(id, unhex(s)?);
                    }
                }
                Ok(KeyOp::Revoke { slot: slot()?, secrets })
            }
            other => anyhow::bail!("unknown key op {other:?}"),
        }
    }

    /// Applies the change; what it reports back (the new slot's id, if any).
    pub fn apply(&self, ring: &mut UnlockedKeyring) -> Result<Value, KeyringError> {
        match self {
            KeyOp::Add(new) => Ok(json!({ "added": ring.add_slot(new.as_new_slot())? })),
            KeyOp::Remove(id) => {
                ring.remove_slot(*id)?;
                Ok(json!({ "removed": id }))
            }
            KeyOp::Replace { old, new } => {
                if !ring.body().slots.iter().any(|s| s.id == *old) {
                    return Err(KeyringError::NoSuchSlot(*old));
                }
                let added = ring.add_slot(new.as_new_slot())?;
                ring.remove_slot(*old)?;
                Ok(json!({ "added": added, "removed": old }))
            }
            KeyOp::Revoke { slot, secrets } => {
                ring.revoke_slot(*slot, &mut |s| {
                    secrets.get(&s.id).map(|v| v.to_vec()).ok_or_else(|| {
                        KeyringError::Refused(format!("no passphrase or PIN was given for slot {} ({})", s.id, s.label))
                    })
                })?;
                Ok(json!({ "revoked": slot }))
            }
        }
    }
}

/// Which of the slots that survive revoking `revoking` need a secret to be
/// rewrapped, and what to ask for: passphrase slots their passphrase, TPM
/// slots with a PIN their PIN. Recipient slots rewrap from their public key.
pub fn secrets_needed(slots: &[lchfs_crypto::keyring::Slot], revoking: u16) -> Vec<(u16, String)> {
    slots
        .iter()
        .filter(|s| s.id != revoking)
        .filter_map(|s| match &s.kind {
            SlotKind::Passphrase(_) => Some((s.id, format!("Passphrase for slot {} ({}): ", s.id, s.label))),
            SlotKind::Tpm2(t) if t.pin => Some((s.id, format!("TPM PIN for slot {} ({}): ", s.id, s.label))),
            _ => None,
        })
        .collect()
}
