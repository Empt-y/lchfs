//! `lchfs-win`: mounts an LCHFS pool on Windows through WinFsp.
//!
//! ```text
//! lchfs-win mount D:\pool             next free drive letter, from Z: down
//! lchfs-win mount D:\pool L:          a given drive letter
//! lchfs-win mount D:\pool C:\mnt\pool an NTFS folder (must not exist yet)
//! lchfs-win create-pool D:\pool --encrypt
//! ```
//!
//! Ctrl+C (or closing the console window) unmounts, after a final
//! checkpoint.

#[cfg(not(windows))]
fn main() {
    eprintln!("lchfs-win runs on Windows only; on Linux use `lchfs mount`.");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    win::main()
}

#[cfg(windows)]
mod win {
    use anyhow::{Context, bail};
    use clap::{Parser, Subcommand};
    use lchfs_crypto::keyring::{KeyringError, NewSlot, Padding, Unlock};
    use lchfs_crypto::locked::LockedBytes;
    use lchfs_crypto::slots::passphrase::KdfCost;
    use lchfs_crypto::slots::recipient::{Identity, Recipient};
    use lchfs_store::{Pool, PoolError};
    use lchfs_winfsp::ffi::Mount;
    use lchfs_winfsp::fs::Volume;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use zeroize::Zeroize;

    #[derive(Parser)]
    #[command(name = "lchfs-win", version, about = "Mount an LCHFS pool on Windows (needs WinFsp)")]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Serve a pool as a drive until Ctrl+C.
        Mount {
            /// The pool's directory.
            pool: PathBuf,
            /// A drive letter (`L:`) or a folder that does not exist yet.
            /// The next free letter from Z: down if omitted.
            mount_point: Option<String>,
            /// Refuse every change.
            #[arg(long)]
            read_only: bool,
            /// Read the passphrase from this file instead of asking.
            #[arg(long, value_name = "FILE", conflicts_with = "identity")]
            passphrase_file: Option<PathBuf>,
            /// Unlock with a recipient identity (`lchfs key generate-recipient`).
            #[arg(long, value_name = "FILE")]
            identity: Option<PathBuf>,
        },
        /// Create an empty pool in a new or empty directory.
        CreatePool {
            pool: PathBuf,
            /// Encrypt it, with a passphrase slot (asked for twice).
            #[arg(long)]
            encrypt: bool,
            /// Take the new passphrase from this file instead of asking.
            #[arg(long, value_name = "FILE", requires = "encrypt")]
            passphrase_file: Option<PathBuf>,
            /// Also add a post-quantum recipient slot for this public key.
            #[arg(long, value_name = "FILE", requires = "encrypt")]
            recipient: Option<PathBuf>,
        },
    }

    /// Passphrases asked for before giving up, as the Linux CLI does.
    const PROMPT_ATTEMPTS: usize = 3;

    pub fn main() -> anyhow::Result<()> {
        use tracing_subscriber::prelude::*;
        let filter = tracing_subscriber::filter::LevelFilter::WARN;
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(filter)
            .init();
        match Cli::parse().command {
            Command::Mount { pool, mount_point, read_only, passphrase_file, identity } => {
                mount(&pool, mount_point.as_deref(), read_only, passphrase_file.as_deref(), identity.as_deref())
            }
            Command::CreatePool { pool, encrypt, passphrase_file, recipient } => {
                create_pool(&pool, encrypt, passphrase_file.as_deref(), recipient.as_deref())
            }
        }
    }

    fn create_pool(
        dir: &Path,
        encrypt: bool,
        passphrase_file: Option<&Path>,
        recipient: Option<&Path>,
    ) -> anyhow::Result<()> {
        let params = lchfs_format::PoolParams::default();
        let pool = if encrypt {
            let passphrase = match passphrase_file {
                Some(path) => read_secret(path)?,
                None => {
                    let first = prompt("New passphrase: ")?;
                    if first != prompt("Repeat the new passphrase: ")? {
                        bail!("the two entries of the new passphrase differ");
                    }
                    first
                }
            };
            let recipient = recipient
                .map(|path| -> anyhow::Result<(Recipient, String)> {
                    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
                    let r = Recipient::parse(text.trim())
                        .map_err(|e| anyhow::anyhow!("{} is not an lchfs recipient: {e}", path.display()))?;
                    let label = path.file_stem().map_or_else(|| "recipient".into(), |s| s.to_string_lossy().into_owned());
                    Ok((r, label))
                })
                .transpose()?;
            let mut slots = vec![NewSlot::Passphrase {
                passphrase: &passphrase,
                cost: KdfCost::Calibrate,
                label: "passphrase".into(),
            }];
            if let Some((r, label)) = &recipient {
                slots.push(NewSlot::Recipient { recipient: r, label: label.clone() });
            }
            Pool::create_encrypted(dir, params, lchfs_store::EncryptionSetup { padding: Padding::Padme, slots })?
        } else {
            Pool::create(dir, params)?
        };
        println!("pool {} created at {}", lchfs_format::pool_uuid_hex(&pool.pool_uuid()), dir.display());
        if pool.is_encrypted() {
            for slot in pool.keyring_slots() {
                println!("  key slot {}: {} ({})", slot.id, slot.kind, slot.label);
            }
            println!("Back up the keyring (`lchfs key backup` on Linux): lose every copy and the pool cannot be opened.");
        }
        Ok(())
    }

    /// A key that no slot accepts, as opposed to a pool that cannot be read.
    fn refused(e: &PoolError) -> bool {
        matches!(
            e,
            PoolError::Keyring(
                KeyringError::NoMatchingSlot | KeyringError::NewestRefuses { .. } | KeyringError::Kdf(_)
            )
        )
    }

    /// Reads a secret file straight into locked memory.
    fn read_secret(path: &Path) -> anyhow::Result<LockedBytes> {
        let mut file = std::fs::File::open(path).with_context(|| path.display().to_string())?;
        let mut secret = LockedBytes::with_capacity(LockedBytes::MAX);
        secret.read_to_end_from(&mut file).with_context(|| path.display().to_string())?;
        // One trailing newline is the file's, not the passphrase's.
        for end in [b'\n', b'\r'] {
            if secret.last() == Some(&end) {
                secret.pop();
            }
        }
        Ok(secret)
    }

    /// Asks for a secret without echoing it.
    fn prompt(text: &str) -> anyhow::Result<LockedBytes> {
        let mut typed = rpassword::prompt_password(text)?;
        let secret = LockedBytes::from_slice(typed.as_bytes());
        typed.zeroize();
        Ok(secret)
    }

    fn open(
        pool: &Path,
        passphrase_file: Option<&Path>,
        identity: Option<&Path>,
    ) -> anyhow::Result<Pool> {
        let with = |unlock: &Unlock<'_>| Pool::open_with(pool, unlock);
        match Pool::open(pool) {
            Err(PoolError::KeyRequired) => {}
            Ok(p) => {
                if passphrase_file.is_some() || identity.is_some() {
                    eprintln!("note: pool {} is not encrypted; the key options were ignored", pool.display());
                }
                return Ok(p);
            }
            Err(e) => return Err(e.into()),
        }
        if let Some(path) = identity {
            let secret = read_secret(path)?;
            let text = std::str::from_utf8(&secret).map_err(|_| anyhow::anyhow!("{} is not an lchfs identity", path.display()))?;
            let id = Identity::parse(text.trim())
                .map_err(|e| anyhow::anyhow!("{} is not an lchfs identity: {e}", path.display()))?;
            return with(&Unlock::Identity(&id)).map_err(|e| {
                if refused(&e) { anyhow::anyhow!("no slot of pool {} accepts that identity", pool.display()) } else { e.into() }
            });
        }
        if let Some(path) = passphrase_file {
            let secret = read_secret(path)?;
            return with(&Unlock::Passphrase(&secret)).map_err(|e| {
                if refused(&e) { anyhow::anyhow!("no slot of pool {} accepts that passphrase", pool.display()) } else { e.into() }
            });
        }
        for i in 0..PROMPT_ATTEMPTS {
            let secret = prompt(&format!("Passphrase for pool {}: ", pool.display()))?;
            match with(&Unlock::Passphrase(&secret)) {
                Ok(p) => return Ok(p),
                Err(e) if refused(&e) => {
                    if i + 1 < PROMPT_ATTEMPTS {
                        eprintln!("No slot accepts that passphrase; try again.");
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        bail!("no slot accepted any of {PROMPT_ATTEMPTS} passphrases")
    }

    fn mount(
        pool_dir: &Path,
        mount_point: Option<&str>,
        read_only: bool,
        passphrase_file: Option<&Path>,
        identity: Option<&Path>,
    ) -> anyhow::Result<()> {
        // Fail before asking for a passphrase if WinFsp is missing.
        lchfs_winfsp::ffi::load().map_err(anyhow::Error::msg)?;
        let pool = Arc::new(open(pool_dir, passphrase_file, identity)?);
        let uuid = pool.pool_uuid();
        let serial = u32::from_le_bytes([uuid[0], uuid[1], uuid[2], uuid[3]]);
        let volume = Volume::new(Arc::clone(&pool), read_only);
        let mounted = Mount::new(volume, mount_point, serial).map_err(anyhow::Error::msg)?;
        eprintln!(
            "{} mounted at {}{}; press Ctrl+C to unmount",
            pool_dir.display(),
            mounted.mount_point(),
            if read_only { " (read-only)" } else { "" }
        );

        let (tx, rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = tx.send(());
        })?;
        let _ = rx.recv();

        eprintln!("unmounting...");
        drop(mounted);
        // No FUSE destroy() here: the checkpoint on shutdown is ours to run.
        pool.checkpoint()?;
        Ok(())
    }
}
