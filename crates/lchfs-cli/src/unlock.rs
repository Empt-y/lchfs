//! Unlocking an encrypted pool from the command line (ARCHITECTURE.md
//! §18): which keys a command was given, trying them in a fixed order, and
//! asking for a passphrase when it was given none.

use crate::secrets::{self, Secret};
use clap::Args;
use lchfs_crypto::keyring::{KeyringError, Unlock};
use lchfs_crypto::slots::recipient::Identity;
use lchfs_store::{Pool, PoolError};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// How many wrong passphrases a person gets before the command gives up.
const PROMPT_ATTEMPTS: usize = 3;

/// The keys a command may unlock an encrypted pool with. With none of
/// them given, it asks for a passphrase (terminal, else askpass). A
/// plaintext pool ignores them all.
#[derive(Args, Debug, Clone, Default)]
pub struct UnlockArgs {
    /// Unlock with a recipient identity (made by `key generate-recipient`).
    #[arg(long, value_name = "FILE")]
    pub identity: Option<PathBuf>,
    /// Unlock with this machine's TPM.
    #[arg(long)]
    pub tpm: bool,
    /// The TPM slot needs its PIN: ask for it.
    #[arg(long, requires = "tpm")]
    pub tpm_pin: bool,
    /// Read the TPM PIN from this file instead of asking.
    #[arg(long, value_name = "FILE", requires = "tpm")]
    pub tpm_pin_file: Option<PathBuf>,
    /// Read the passphrase from this file (one trailing newline is dropped).
    #[arg(long, value_name = "FILE", conflicts_with = "passphrase_fd")]
    pub passphrase_file: Option<PathBuf>,
    /// Read the passphrase from this open file descriptor.
    #[arg(long, value_name = "FD")]
    pub passphrase_fd: Option<i32>,
}

impl UnlockArgs {
    fn passphrase_source(&self) -> secrets::Source {
        secrets::Source {
            file: self.passphrase_file.clone(),
            fd: self.passphrase_fd,
        }
    }

    pub fn is_given(&self) -> bool {
        self.identity.is_some() || self.tpm || self.passphrase_source().is_given()
    }
}

/// One key, owned: what an `Unlock` borrows from, and what travels over
/// the control socket as proof.
pub enum Credential {
    Passphrase(Secret),
    Identity(Box<Identity>),
    Tpm(Option<Secret>),
}

impl Credential {
    pub fn as_unlock(&self) -> Unlock<'_> {
        match self {
            Credential::Passphrase(p) => Unlock::Passphrase(p),
            Credential::Identity(id) => Unlock::Identity(id),
            Credential::Tpm(pin) => Unlock::Tpm { pin: pin.as_ref().map(|p| p.as_slice()) },
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Credential::Passphrase(_) => "passphrase",
            Credential::Identity(_) => "identity",
            Credential::Tpm(_) => "TPM",
        }
    }

    /// For the control socket. Secrets are hex so any byte string survives
    /// JSON; the identity goes as its own text, since the mount may not be
    /// able to read the caller's file.
    pub fn to_json(&self) -> Value {
        match self {
            Credential::Passphrase(p) => json!({ "passphrase": hex::encode(p.as_slice()) }),
            Credential::Identity(id) => json!({ "identity": *Zeroizing::new(id.to_text()) }),
            Credential::Tpm(pin) => json!({ "tpm": { "pin": pin.as_ref().map(|p| hex::encode(p.as_slice())) } }),
        }
    }

    pub fn from_json(v: &Value) -> anyhow::Result<Self> {
        if let Some(p) = v.get("passphrase").and_then(Value::as_str) {
            return Ok(Credential::Passphrase(unhex(p)?));
        }
        if let Some(text) = v.get("identity").and_then(Value::as_str) {
            let id = Identity::parse(text).map_err(|e| anyhow::anyhow!("identity: {e}"))?;
            return Ok(Credential::Identity(Box::new(id)));
        }
        if let Some(t) = v.get("tpm") {
            let pin = match t.get("pin").and_then(Value::as_str) {
                Some(p) => Some(unhex(p)?),
                None => None,
            };
            return Ok(Credential::Tpm(pin));
        }
        anyhow::bail!("no usable key in the request")
    }
}

pub fn unhex(s: &str) -> anyhow::Result<Secret> {
    Ok(Zeroizing::new(hex::decode(s).map_err(|e| anyhow::anyhow!("bad hex: {e}"))?))
}

/// A TPM PIN, from its file or asked for.
pub fn read_pin(file: Option<&Path>, prompt: &str) -> anyhow::Result<Secret> {
    match file {
        Some(path) => Ok(secrets::Source {
            file: Some(path.to_path_buf()),
            fd: None,
        }
        .read()?
        .expect("a file was named")),
        None => secrets::prompt(prompt),
    }
}

/// The keys `args` names, in the order they are tried: identity, TPM,
/// passphrase. The cheap, non-interactive ones first.
fn explicit(args: &UnlockArgs) -> anyhow::Result<Vec<Credential>> {
    let mut out = Vec::new();
    if let Some(path) = &args.identity {
        out.push(Credential::Identity(Box::new(secrets::read_identity(path)?)));
    }
    if args.tpm {
        let pin = if args.tpm_pin || args.tpm_pin_file.is_some() {
            Some(read_pin(args.tpm_pin_file.as_deref(), "TPM PIN: ")?)
        } else {
            None
        };
        out.push(Credential::Tpm(pin));
    }
    if let Some(p) = args.passphrase_source().read()? {
        out.push(Credential::Passphrase(p));
    }
    Ok(out)
}

/// A key the pool refused: try the next one, rather than fail.
pub fn refused(e: &PoolError) -> bool {
    matches!(e, PoolError::Keyring(k) if refused_keyring(k))
}

pub fn refused_keyring(e: &KeyringError) -> bool {
    matches!(
        e,
        KeyringError::NoMatchingSlot | KeyringError::NewestRefuses { .. } | KeyringError::Tpm(_) | KeyringError::Kdf(_)
    )
}

/// Tries each key `args` names, then (if it named none) asks for a
/// passphrase up to three times. `attempt` returns `Ok(None)` when the key
/// was refused, which moves on to the next; any error stops at once.
pub fn with_key<T>(
    args: &UnlockArgs,
    what: &str,
    mut attempt: impl FnMut(&Credential) -> anyhow::Result<Option<T>>,
) -> anyhow::Result<T> {
    let given = explicit(args)?;
    if !given.is_empty() {
        let mut tried = Vec::new();
        for key in &given {
            if let Some(v) = attempt(key)? {
                return Ok(v);
            }
            tried.push(key.describe());
        }
        anyhow::bail!("{what} is encrypted and none of the keys given opens it (tried: {})", tried.join(", "));
    }
    if !secrets::can_prompt() {
        anyhow::bail!(
            "{what} is encrypted: pass --passphrase-file, --passphrase-fd, --identity or --tpm \
             (no terminal or askpass helper to ask for a passphrase)"
        );
    }
    for i in 0..PROMPT_ATTEMPTS {
        let key = Credential::Passphrase(secrets::prompt(&format!("Passphrase for {what}: "))?);
        if let Some(v) = attempt(&key)? {
            return Ok(v);
        }
        if i + 1 < PROMPT_ATTEMPTS {
            eprintln!("No slot accepts that passphrase; try again.");
        }
    }
    anyhow::bail!("no slot accepted any of {PROMPT_ATTEMPTS} passphrases")
}

/// The `--vdev`/`--scan` pair: a pool's other devices, named or found.
#[derive(Args, Debug, Clone, Default)]
pub struct DeviceArgs {
    /// The pool's other vdev roots (ARCHITECTURE.md §15.10).
    #[arg(long = "vdev")]
    pub vdevs: Vec<PathBuf>,
    /// Find the pool's other devices under these directories instead of
    /// naming them: each directory and its immediate children are checked
    /// for a superblock carrying the pool's uuid.
    #[arg(long = "scan")]
    pub scan: Vec<PathBuf>,
}

impl DeviceArgs {
    /// Every device root: `pool` first, then the named or found others.
    pub fn roots(&self, pool: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let mut roots = vec![pool.to_path_buf()];
        if self.scan.is_empty() {
            roots.extend(self.vdevs.iter().cloned());
            return Ok(roots);
        }
        if !self.vdevs.is_empty() {
            anyhow::bail!("--scan finds the other devices; do not also name them with --vdev");
        }
        let uuid = lchfs_fsck::read_superblock(pool)?.pool_uuid;
        let candidates: Vec<&Path> = self.scan.iter().map(|p| p.as_path()).collect();
        let found = Pool::discover(&candidates, Some(uuid))?;
        let pool_abs = std::fs::canonicalize(pool).unwrap_or(pool.to_path_buf());
        for p in &found.pools {
            for (_, _, root) in &p.members {
                if std::fs::canonicalize(root).unwrap_or(root.clone()) != pool_abs {
                    roots.push(root.clone());
                }
            }
        }
        Ok(roots)
    }
}

/// Opens a pool from its devices, unlocking it if it is encrypted: first
/// without a key (a plaintext pool needs none, and the engine says
/// `KeyRequired` before it has taken a lock or read a record, so asking
/// costs nothing), then with each key in turn.
pub fn open_pool(pool: &Path, devices: &DeviceArgs, degraded: bool, args: &UnlockArgs) -> anyhow::Result<Pool> {
    let open = |unlock: Option<&Unlock<'_>>| -> Result<Pool, PoolError> {
        if !devices.scan.is_empty() {
            if !devices.vdevs.is_empty() {
                return Err(PoolError::InvalidArgument(
                    "--scan finds the other devices; do not also name them with --vdev".into(),
                ));
            }
            let uuid = lchfs_fsck::read_superblock(pool)
                .map_err(|e| PoolError::Format(e.to_string()))?
                .pool_uuid;
            let mut candidates: Vec<&Path> = vec![pool];
            candidates.extend(devices.scan.iter().map(|p| p.as_path()));
            Pool::open_discovered_with(&candidates, Some(uuid), degraded, unlock)
        } else {
            let mut roots: Vec<&Path> = vec![pool];
            roots.extend(devices.vdevs.iter().map(|p| p.as_path()));
            match (degraded, unlock) {
                (true, Some(u)) => Pool::open_degraded_with(&roots, u),
                (true, None) => Pool::open_degraded(&roots),
                (false, Some(u)) => Pool::open_replicated_with(&roots, u),
                (false, None) => Pool::open_replicated(&roots),
            }
        }
    };
    match open(None) {
        Err(PoolError::KeyRequired) => with_key(args, &format!("pool {}", pool.display()), |key| {
            match open(Some(&key.as_unlock())) {
                Ok(p) => Ok(Some(p)),
                Err(e) if refused(&e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }),
        Ok(p) => {
            if args.is_given() && !p.is_encrypted() {
                eprintln!("note: pool {} is not encrypted; the key options were ignored", pool.display());
            }
            Ok(p)
        }
        Err(e) => Err(e.into()),
    }
}
