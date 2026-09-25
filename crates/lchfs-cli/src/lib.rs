//! LCHFS CLI. ARCHITECTURE.md §11: `clap`-based commands
//! create-pool, mount, fsck, snapshot {create,list,delete}, stats.

pub mod control;
pub mod keyops;
pub mod secrets;
pub mod unlock;

use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use unlock::{DeviceArgs, UnlockArgs};

#[derive(Parser)]
#[command(name = "lchfs", about = "Log-Structured Cryptographic Hash File System")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Format a block device (a disk or partition) as a new pool. Everything
    /// on it is lost.
    CreatePool {
        path: PathBuf,
        /// Format the device even though it holds something already (a
        /// partition table, a filesystem, data).
        #[arg(long)]
        force: bool,
        /// Erasure-code cold segments as K data + M parity shards once the
        /// pool has K+M devices (ARCHITECTURE.md §17.2). Both or neither.
        #[arg(long, requires = "stripe_m")]
        stripe_k: Option<u8>,
        #[arg(long, requires = "stripe_k")]
        stripe_m: Option<u8>,
        #[command(flatten)]
        encryption: EncryptArgs,
    },
    /// Mount a pool at the given mountpoint via FUSE3.
    Mount {
        /// Any one of the pool's devices (vdev 0 unless --scan is given).
        pool: PathBuf,
        mountpoint: PathBuf,
        /// The pool's other vdev roots (ARCHITECTURE.md §15.10). A
        /// replicated pool must be given every device unless --degraded.
        #[arg(long = "vdev")]
        vdevs: Vec<PathBuf>,
        /// Find the pool's other devices under these directories instead
        /// of naming them: each directory and its immediate children are
        /// checked for a superblock carrying <POOL>'s uuid.
        #[arg(long = "scan")]
        scan: Vec<PathBuf>,
        /// Mount with devices absent (ARCHITECTURE.md §15.8). Explicit on
        /// purpose: running one device down should be a decision.
        #[arg(long)]
        degraded: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Refuse to mount a pool that turns out not to be encrypted:
        /// defends against a plaintext pool swapped in for yours.
        #[arg(long)]
        require_encryption: bool,
    },
    /// Serve a pool over NFSv3 (ARCHITECTURE.md §5a's second adapter).
    /// Mount it with e.g.
    /// `mount -t nfs -o vers=3,tcp,port=P,mountport=P,nolock 127.0.0.1:/ /mnt`.
    ServeNfs {
        /// Any one of the pool's devices.
        pool: PathBuf,
        /// "ip:port" to listen on; port 0 picks one and prints it.
        #[arg(default_value = "127.0.0.1:11111")]
        listen: String,
        #[arg(long = "vdev")]
        vdevs: Vec<PathBuf>,
        #[arg(long = "scan")]
        scan: Vec<PathBuf>,
        #[arg(long)]
        degraded: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Refuse to serve a pool that turns out not to be encrypted.
        #[arg(long)]
        require_encryption: bool,
    },
    /// List the pools whose devices can be found under the given
    /// directories, with which slots are present and which are missing.
    Discover { dirs: Vec<PathBuf> },
    /// Walk the DAG and verify integrity (ARCHITECTURE.md §10).
    Fsck {
        /// vdev 0's root.
        pool: PathBuf,
        /// The pool's other vdev roots, for a replica comparison
        /// (ARCHITECTURE.md §15.8). Any order; each device's superblock
        /// says which slot it is.
        #[arg(long = "vdev")]
        vdevs: Vec<PathBuf>,
        /// Find the pool's other devices under these directories instead
        /// of naming them; the pool is the one `<POOL>` belongs to.
        #[arg(long = "scan")]
        scan: Vec<PathBuf>,
        #[arg(long)]
        verify_index: bool,
        #[arg(long)]
        rebuild_index: bool,
        /// Rewrite any missing or corrupt shard of an erasure-coded
        /// segment from its siblings (ARCHITECTURE.md §17.2), on the
        /// devices given, before checking.
        #[arg(long)]
        rebuild_shard: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// On an encrypted pool, check only what needs no key (framing,
        /// header checksums, stripes, superblocks, keyrings) rather than
        /// asking for one.
        #[arg(long)]
        structural: bool,
    },
    /// Add a blank device to a pool, or replace a dead one, offline
    /// (ARCHITECTURE.md §15.10). The next mount resilvers onto it.
    AttachVdev {
        /// vdev 0's root.
        pool: PathBuf,
        /// The pool's other current devices, if any.
        #[arg(long = "vdev")]
        vdevs: Vec<PathBuf>,
        /// The blank device to add.
        new_device: PathBuf,
    },
    /// Remove the highest-numbered device from a pool, offline
    /// (ARCHITECTURE.md §15.9). Refuses unless every record has a verified
    /// copy on the devices that remain.
    DetachVdev {
        /// vdev 0's root.
        pool: PathBuf,
        /// Every other device, the last of which leaves.
        #[arg(long = "vdev")]
        vdevs: Vec<PathBuf>,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Talk to a mounted pool over its control socket.
    Pool {
        #[command(subcommand)]
        action: PoolAction,
    },
    /// Snapshot management (ARCHITECTURE.md §6).
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// An encrypted pool's key slots (ARCHITECTURE.md §18). On a mounted
    /// pool the change goes through the mount's control socket; on an
    /// unmounted one, straight to every device's keyring.
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Print pool statistics.
    Stats { pool: PathBuf },
}

#[derive(Subcommand)]
enum PoolAction {
    /// Every slot's health, the repair counters, and what mount did.
    Status { root: PathBuf },
    /// Verify every record on every online device and heal what fails.
    Scrub { root: PathBuf },
    /// Copy onto a device everything it is missing.
    Resilver { root: PathBuf, vdev: u16 },
    /// Add a blank device and fill it.
    Attach { root: PathBuf, device: PathBuf },
    /// Bring back a device that faulted or was absent at mount.
    Online { root: PathBuf, device: PathBuf },
    /// Stop using a device, cleanly.
    Offline { root: PathBuf, vdev: u16 },
    /// Replace a faulted primary now rather than waiting for the failover task.
    Promote { root: PathBuf },
    /// Remove the highest-numbered device while mounted, after proving
    /// the rest can stand alone.
    Detach { root: PathBuf },
    /// Every corruption detected since mount, with what was done about it.
    Corruption {
        root: PathBuf,
        /// Forget the events after printing them.
        #[arg(long)]
        clear: bool,
    },
    /// Set the erasure-coding policy for future conversions of cold
    /// segments (ARCHITECTURE.md §17.2.5): K data + M parity shards, or
    /// 0 0 to stop converting. Existing stripes keep their shape.
    SetStripe {
        root: PathBuf,
        k: u8,
        m: u8,
        /// How many sealed segments past the sweep grace window a
        /// segment must be before it counts as cold.
        #[arg(long)]
        min_age_segments: Option<u32>,
    },
    /// What erasure coding has done: the policy, striped segments, and
    /// bytes saved against a full mirror.
    StripeStatus { root: PathBuf },
    /// Whether the pool is encrypted, its epochs, padding and slots, and
    /// how far a conversion has got.
    EncryptionStatus { root: PathBuf },
    /// Encrypt a plaintext pool in place (ARCHITECTURE.md §18). New writes
    /// are sealed at once; existing content is rewritten, and the plaintext
    /// then destroyed on every device. A mounted pool converts in the
    /// background (watch `encryption-status`); an unmounted one converts
    /// now, with progress.
    Encrypt {
        root: PathBuf,
        #[command(flatten)]
        devices: DeviceArgs,
        #[command(flatten)]
        slots: SlotArgs,
        /// Rewrite at most this many bytes per second.
        #[arg(long, value_name = "BYTES")]
        rate: Option<u64>,
    },
    /// Rotate an encrypted pool's content key: a new epoch, everything
    /// rewritten into it, and the old key destroyed. What to run after
    /// revoking a key slot.
    Rekey {
        root: PathBuf,
        #[command(flatten)]
        devices: DeviceArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long, value_name = "BYTES")]
        rate: Option<u64>,
    },
}

/// `create-pool`'s encryption options (ARCHITECTURE.md §18).
#[derive(Args)]
struct EncryptArgs {
    /// Encrypt the pool. With no --recipient and no passphrase source, asks
    /// for a passphrase.
    #[arg(long)]
    encrypt: bool,
    #[command(flatten)]
    slots: SlotArgs,
}

/// The key slots a pool starts encrypted with (`create-pool --encrypt`,
/// `pool encrypt`).
#[derive(Args)]
struct SlotArgs {
    /// The first passphrase slot's passphrase, from this file.
    #[arg(long, value_name = "FILE", conflicts_with = "passphrase_fd")]
    passphrase_file: Option<PathBuf>,
    /// ...or from this open file descriptor.
    #[arg(long, value_name = "FD")]
    passphrase_fd: Option<i32>,
    /// Add a recipient slot for this public key (`key generate-recipient`);
    /// repeatable.
    #[arg(long = "recipient", value_name = "FILE.pub")]
    recipients: Vec<PathBuf>,
    /// Add a slot sealed to this machine's TPM. Never the only slot.
    #[arg(long)]
    tpm: bool,
    #[command(flatten)]
    tpm_slot: TpmSlotArgs,
    /// Store record sizes exactly rather than padded (Padmé, <=12%):
    /// saves space, and tells an observer each record's exact size.
    #[arg(long)]
    no_padding: bool,
    #[command(flatten)]
    kdf: KdfArgs,
}

impl SlotArgs {
    fn any_given(&self) -> bool {
        self.passphrase_file.is_some()
            || self.passphrase_fd.is_some()
            || !self.recipients.is_empty()
            || self.tpm
            || self.no_padding
    }

    /// Every secret the slots need, gathered before anything is created: a
    /// pool must never end up half-keyed because a prompt was cancelled.
    /// With no passphrase source and no recipient, a passphrase is asked for.
    fn gather(&self) -> anyhow::Result<Vec<keyops::NewSlotSpec>> {
        use keyops::NewSlotSpec;
        let source = secrets::Source { file: self.passphrase_file.clone(), fd: self.passphrase_fd };
        let mut specs = Vec::new();
        if source.is_given() || self.recipients.is_empty() {
            specs.push(NewSlotSpec::Passphrase {
                passphrase: secrets::new_passphrase(&source)?,
                cost: self.kdf.cost(),
                label: "passphrase".into(),
            });
        }
        for path in &self.recipients {
            let label = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "recipient".into());
            specs.push(NewSlotSpec::Recipient { recipient: Box::new(secrets::read_recipient(path)?), label });
        }
        if self.tpm {
            specs.push(NewSlotSpec::Tpm {
                pcrs: self.tpm_slot.tpm_pcrs.clone(),
                pin: new_tpm_pin(&self.tpm_slot)?,
                label: "tpm".into(),
            });
        }
        Ok(specs)
    }

    fn padding(&self) -> lchfs_crypto::keyring::Padding {
        if self.no_padding { lchfs_crypto::keyring::Padding::None } else { lchfs_crypto::keyring::Padding::Padme }
    }
}

/// A new TPM slot's policy.
#[derive(Args, Clone)]
struct TpmSlotArgs {
    /// PCRs the TPM slot is sealed to (comma-separated).
    #[arg(long, value_delimiter = ',', default_value = "7")]
    tpm_pcrs: Vec<u8>,
    /// Also require a PIN to unseal the TPM slot (asked for).
    #[arg(long)]
    with_pin: bool,
    /// Read the new TPM slot's PIN from this file instead of asking.
    #[arg(long, value_name = "FILE")]
    with_pin_file: Option<PathBuf>,
}

/// A new passphrase slot's Argon2id cost. Calibrated to about a second on
/// this machine (at least 64 MiB) unless both are given.
#[derive(Args, Clone)]
struct KdfArgs {
    #[arg(long, requires = "kdf_time", value_name = "KIB")]
    kdf_memory_kib: Option<u32>,
    #[arg(long, requires = "kdf_memory_kib", value_name = "PASSES")]
    kdf_time: Option<u32>,
}

impl KdfArgs {
    fn cost(&self) -> lchfs_crypto::slots::passphrase::KdfCost {
        match (self.kdf_memory_kib, self.kdf_time) {
            (Some(m_kib), Some(t)) => lchfs_crypto::slots::passphrase::KdfCost::Explicit { m_kib, t, p: 1 },
            _ => lchfs_crypto::slots::passphrase::KdfCost::Calibrate,
        }
    }
}

/// Which pool a key command acts on, and the key that proves the caller
/// may change it.
#[derive(Args, Clone)]
struct KeyTarget {
    /// A device of the pool (the primary's root, for a mounted pool).
    pool: PathBuf,
    #[command(flatten)]
    devices: DeviceArgs,
    /// Change an unmounted pool's keyring with devices missing. They keep
    /// the old keyring, and would open with it if ever found alone.
    #[arg(long)]
    degraded: bool,
    #[command(flatten)]
    unlock: UnlockArgs,
}

/// Where a new passphrase comes from (else it is asked for, twice).
#[derive(Args)]
struct NewPassphraseArgs {
    #[arg(long, value_name = "FILE", conflicts_with = "new_passphrase_fd")]
    new_passphrase_file: Option<PathBuf>,
    #[arg(long, value_name = "FD")]
    new_passphrase_fd: Option<i32>,
    #[command(flatten)]
    kdf: KdfArgs,
}

#[derive(Subcommand)]
enum KeyAction {
    /// Make a post-quantum recipient key pair: OUT (the identity, secret,
    /// mode 0600) and OUT.pub (the recipient, for `--recipient`).
    GenerateRecipient { out: PathBuf },
    /// The slots of every device's keyring. Needs no key.
    List {
        pool: PathBuf,
        #[command(flatten)]
        devices: DeviceArgs,
    },
    /// Add a passphrase slot.
    AddPassphrase {
        #[command(flatten)]
        target: KeyTarget,
        #[command(flatten)]
        new: NewPassphraseArgs,
        #[arg(long, default_value = "passphrase")]
        label: String,
    },
    /// Replace a passphrase slot with a new passphrase. Whoever knew the
    /// old one and kept a copy of the old keyring can still open that
    /// copy, unless --revoke.
    ChangePassphrase {
        slot: u16,
        #[command(flatten)]
        target: KeyTarget,
        #[command(flatten)]
        new: NewPassphraseArgs,
        /// Revoke the old slot rather than just remove it: replaces the
        /// keyring key, so no old copy of the keyring opens anything new
        /// (asks for every other passphrase and PIN).
        #[arg(long)]
        revoke: bool,
        /// With --revoke: another slot's passphrase or PIN from a file
        /// instead of asking, as SLOT=FILE; repeatable.
        #[arg(long = "secret-file", value_name = "SLOT=FILE", requires = "revoke")]
        secret_files: Vec<String>,
    },
    /// Add a recipient slot for a public key (FILE.pub).
    AddRecipient {
        recipient: PathBuf,
        #[command(flatten)]
        target: KeyTarget,
        #[arg(long, default_value = "recipient")]
        label: String,
    },
    /// Add a slot sealed to this machine's TPM.
    AddTpm {
        #[command(flatten)]
        target: KeyTarget,
        #[command(flatten)]
        tpm_slot: TpmSlotArgs,
        #[arg(long, default_value = "tpm")]
        label: String,
    },
    /// Remove a slot. Its secret still opens any copy of the old keyring;
    /// use `revoke` if that matters.
    Remove {
        slot: u16,
        #[command(flatten)]
        target: KeyTarget,
    },
    /// Remove a slot and replace the keyring key, rewrapping every other
    /// slot (asks for each passphrase slot's passphrase and each TPM PIN).
    Revoke {
        slot: u16,
        #[command(flatten)]
        target: KeyTarget,
        /// A remaining slot's passphrase or PIN from a file instead of
        /// asking, as SLOT=FILE; repeatable.
        #[arg(long = "secret-file", value_name = "SLOT=FILE")]
        secret_files: Vec<String>,
    },
    /// Copy the newest keyring to OUT. Without it and every device's copy,
    /// an encrypted pool cannot be opened by anyone.
    Backup {
        pool: PathBuf,
        #[command(flatten)]
        devices: DeviceArgs,
        out: PathBuf,
    },
    /// Put a keyring backup back on the devices whose keyring is missing or
    /// damaged. The backup must open with the key given.
    Restore {
        file: PathBuf,
        #[command(flatten)]
        target: KeyTarget,
        /// Also replace keyrings that are intact. That rolls them back to
        /// the backup: any slot added, changed or revoked since is undone.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
    Create {
        pool: PathBuf,
        name: String,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    List {
        pool: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    Delete {
        pool: PathBuf,
        name: String,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
}

pub fn run() -> anyhow::Result<()> {
    init_logging();
    harden_process();
    let cli = Cli::parse();

    match cli.command {
        Command::CreatePool { path, force, stripe_k, stripe_m, encryption } => {
            require_device(&path, force)?;
            create_pool(&path, stripe_k, stripe_m, &encryption)
        }
        Command::Mount { pool, mountpoint, vdevs, scan, degraded, unlock, require_encryption } => {
            let devices = DeviceArgs { vdevs, scan };
            mount(&pool, &devices, degraded, &unlock, require_encryption, &mountpoint)
        }
        Command::Discover { dirs } => discover(&dirs),
        Command::ServeNfs { pool, listen, vdevs, scan, degraded, unlock, require_encryption } => {
            let devices = DeviceArgs { vdevs, scan };
            serve_nfs(&pool, &devices, degraded, &unlock, require_encryption, &listen)
        }
        Command::Fsck { pool, vdevs, scan, verify_index, rebuild_index, rebuild_shard, unlock, structural } => {
            let roots = DeviceArgs { vdevs, scan }.roots(&pool)?;
            let options = FsckOptions { verify_index, rebuild_index, rebuild_shard, structural };
            fsck(&roots, &options, &unlock)
        }
        Command::AttachVdev { pool, vdevs, new_device } => {
            require_device(&new_device, false)?;
            let mut roots: Vec<&std::path::Path> = vec![pool.as_path()];
            roots.extend(vdevs.iter().map(|p| p.as_path()));
            let id = lchfs_store::Pool::attach_vdev(&roots, &new_device)?;
            println!(
                "{} attached as vdev {id}. Mount with every device to resilver it.",
                new_device.display()
            );
            Ok(())
        }
        Command::DetachVdev { pool, vdevs, unlock } => {
            let mut roots: Vec<&std::path::Path> = vec![pool.as_path()];
            roots.extend(vdevs.iter().map(|p| p.as_path()));
            let id = match lchfs_store::Pool::detach_vdev(&roots) {
                Err(lchfs_store::PoolError::KeyRequired) => unlock::with_key(&unlock, &format!("pool {}", pool.display()), |key| {
                    match lchfs_store::Pool::detach_vdev_with(&roots, Some(&key.as_unlock())) {
                        Ok(id) => Ok(Some(id)),
                        Err(e) if unlock::refused(&e) => Ok(None),
                        Err(e) => Err(e.into()),
                    }
                })?,
                other => other?,
            };
            println!("vdev {id} detached; the device can be reused.");
            Ok(())
        }
        Command::Pool { action: PoolAction::Encrypt { root, devices, slots, rate } } => {
            pool_encrypt(&root, &devices, &slots, rate)
        }
        Command::Pool { action: PoolAction::Rekey { root, devices, unlock, rate } } => {
            pool_rekey(&root, &devices, &unlock, rate)
        }
        Command::Pool { action } => pool_control(action),
        Command::Snapshot { action } => snapshot(action),
        Command::Key { action } => key(action),
        Command::Stats { pool } => stats(&pool),
    }
}

/// Set by whoever needs to debug or profile lchfs (gdb, perf, a core
/// dump): turns `harden_process` off.
pub const ALLOW_DEBUG_ENV: &str = "LCHFS_ALLOW_DEBUG";

/// Keeps the keys this process will hold away from everyone but itself
/// (ARCHITECTURE.md §18): not dumpable -- no core file, and other
/// processes of the same user can neither ptrace it nor read its memory
/// through /proc -- and a core size limit of zero for good measure. The
/// pages keys live in are additionally locked and left out of dumps by
/// `lchfs_crypto::locked`. Every subcommand gets this, not only the ones
/// that unlock, so there is no path that forgets it.
fn harden_process() {
    if std::env::var_os(ALLOW_DEBUG_ENV).is_some_and(|v| v == "1") {
        tracing::warn!(
            "{ALLOW_DEBUG_ENV}=1: this process can be core-dumped and debugged, and any key it holds with it"
        );
        return;
    }
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        tracing::warn!("could not make the process non-dumpable: {e}");
    }
    // The soft limit only: the hard one is inherited by what we exec
    // (askpass, fusermount3), and could never be raised again there.
    let core = nix::sys::resource::Resource::RLIMIT_CORE;
    let hard = nix::sys::resource::getrlimit(core).map_or(nix::sys::resource::RLIM_INFINITY, |(_, hard)| hard);
    if let Err(e) = nix::sys::resource::setrlimit(core, 0, hard) {
        tracing::warn!("could not disable core dumps: {e}");
    }
}

/// INFO and up, except the TPM library's, which narrates every context it
/// opens and closes: WARN and up for that one.
fn init_logging() {
    use tracing_subscriber::prelude::*;
    let filter = tracing_subscriber::filter::Targets::new()
        .with_default(tracing::Level::INFO)
        .with_target("tss_esapi", tracing::Level::WARN);
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).with(filter).init();
}

fn create_pool(
    path: &Path,
    stripe_k: Option<u8>,
    stripe_m: Option<u8>,
    enc: &EncryptArgs,
) -> anyhow::Result<()> {
    let mut params = lchfs_format::PoolParams::default();
    if let (Some(k), Some(m)) = (stripe_k, stripe_m) {
        params.stripe_k = k;
        params.stripe_m = m;
    }
    if !enc.encrypt && enc.slots.any_given() {
        anyhow::bail!("key slot options need --encrypt");
    }
    let pool = if enc.encrypt {
        let specs = enc.slots.gather()?;
        let setup = lchfs_store::EncryptionSetup {
            padding: enc.slots.padding(),
            slots: specs.iter().map(|s| s.as_new_slot()).collect(),
        };
        lchfs_store::Pool::create_encrypted(path, params, setup)?
    } else {
        lchfs_store::Pool::create(path, params)?
    };
    println!("pool {} created at {}", lchfs_format::pool_uuid_hex(&pool.pool_uuid()), path.display());
    if pool.is_encrypted() {
        for slot in pool.keyring_slots() {
            println!("  key slot {}: {} ({})", slot.id, slot.kind, slot.label);
        }
        println!("Back up the keyring (`lchfs key backup`): lose every copy and the pool cannot be opened.");
    }
    if params.stripe_k > 0 {
        println!(
            "cold segments will be erasure-coded {}+{} once the pool has {} devices",
            params.stripe_k,
            params.stripe_m,
            params.stripe_k as u16 + params.stripe_m as u16
        );
    }
    Ok(())
}

/// A new TPM slot's PIN, if it is to have one.
fn new_tpm_pin(args: &TpmSlotArgs) -> anyhow::Result<Option<secrets::Secret>> {
    match (&args.with_pin_file, args.with_pin) {
        (Some(path), _) => Ok(Some(unlock::read_pin(Some(path), "")?)),
        (None, true) => Ok(Some(secrets::prompt_new("TPM PIN")?)),
        (None, false) => Ok(None),
    }
}

fn discover(dirs: &[PathBuf]) -> anyhow::Result<()> {
    let candidates: Vec<&std::path::Path> = dirs.iter().map(|p| p.as_path()).collect();
    let found = lchfs_store::Pool::discover(&candidates, None)?;
    if found.pools.is_empty() {
        println!("No pool devices found.");
        return Ok(());
    }
    for pool in &found.pools {
        println!(
            "pool {}: {} slot(s){}",
            lchfs_format::pool_uuid_hex(&pool.uuid),
            pool.count,
            if pool.missing.is_empty() {
                String::new()
            } else {
                format!(", missing {:?}", pool.missing)
            }
        );
        for (id, generation, root) in &pool.members {
            println!("  vdev {id}  generation {generation}  {}", root.display());
        }
    }
    Ok(())
}

/// Opens the pool the way `mount` and `serve-nfs` both do, reports what
/// mount-time recovery did, and starts the control socket.
fn open_for_serving(
    pool: &Path,
    devices: &DeviceArgs,
    degraded: bool,
    unlock: &UnlockArgs,
    require_encryption: bool,
) -> anyhow::Result<(std::sync::Arc<lchfs_store::Pool>, control::ControlServer)> {
    let pool = unlock::open_pool(pool, devices, degraded, unlock)?;
    if require_encryption && !pool.is_encrypted() {
        anyhow::bail!(
            "pool {} is not encrypted, and --require-encryption was given: refusing to serve it",
            lchfs_format::pool_uuid_hex(&pool.pool_uuid())
        );
    }
    if pool.is_degraded() {
        eprintln!("WARNING: mounted degraded; vdevs {:?} are absent", pool.missing_vdevs());
    }
    if pool.is_encrypted() && lchfs_crypto::locked::status() == lchfs_crypto::locked::LockStatus::Unlocked {
        eprintln!(
            "WARNING: could not lock key memory into RAM (RLIMIT_MEMLOCK, see `ulimit -l`): \
             keys may be written to swap. They are still kept out of core dumps."
        );
    }
    for (id, report) in pool.mount_resilver() {
        eprintln!(
            "resilvered vdev {id}: {} of {} records were missing, {} healed, {} unrecoverable",
            report.missing,
            report.examined,
            report.healed,
            report.unrecoverable.len()
        );
    }
    let pool = std::sync::Arc::new(pool);
    let control = control::ControlServer::start(std::sync::Arc::clone(&pool), control::socket_path(&pool))?;
    eprintln!("control socket: {}", control::socket_path(&pool).display());
    Ok((pool, control))
}

fn mount(
    pool: &Path,
    devices: &DeviceArgs,
    degraded: bool,
    unlock: &UnlockArgs,
    require_encryption: bool,
    mountpoint: &Path,
) -> anyhow::Result<()> {
    let (pool, _control) = open_for_serving(pool, devices, degraded, unlock, require_encryption)?;
    let fs = lchfs_fuse::LchfsFilesystem::new(pool);
    // `DefaultPermissions`: the kernel enforces normal read/write/traverse
    // permission checks against each inode's reported mode/uid/gid (lchfs
    // itself never checked these). Safe now that `Pool::create` owns the
    // root inode as the creating user rather than hardcoding uid/gid 0 --
    // see that method's doc comment.
    let mut config = fuser::Config::default();
    config
        .mount_options
        .push(fuser::MountOption::FSName("lchfs".to_string()));
    config
        .mount_options
        .push(fuser::MountOption::DefaultPermissions);
    fuser::mount(fs, mountpoint, &config)?;
    Ok(())
}

fn serve_nfs(
    pool: &Path,
    devices: &DeviceArgs,
    degraded: bool,
    unlock: &UnlockArgs,
    require_encryption: bool,
    listen: &str,
) -> anyhow::Result<()> {
    let (pool, _control) = open_for_serving(pool, devices, degraded, unlock, require_encryption)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let (port, task) = lchfs_nfs::LchfsNfs::serve(std::sync::Arc::clone(&pool), listen).await?;
        eprintln!(
            "serving NFSv3 on port {port}; mount with: mount -t nfs -o vers=3,tcp,port={port},mountport={port},nolock <host>:/ <dir>"
        );
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = task => {}
        }
        anyhow::Ok(())
    })?;
    // No FUSE destroy() here: the checkpoint on shutdown is ours to run.
    pool.checkpoint()?;
    Ok(())
}

struct FsckOptions {
    verify_index: bool,
    rebuild_index: bool,
    rebuild_shard: bool,
    structural: bool,
}

fn fsck(roots: &[PathBuf], options: &FsckOptions, unlock: &UnlockArgs) -> anyhow::Result<()> {
    // No `Pool::open` here: fsck deliberately reads the pool directory
    // directly (see lchfs-fsck's module doc comment) rather than going
    // through the live engine -- opening a `Pool` would also run mount-
    // time crash recovery and spawn its background checkpoint/coalesce/
    // dedup threads, neither of which this one-shot diagnostic needs.
    let roots: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
    let pool = roots[0];
    let other_vdevs = &roots[1..];
    if options.rebuild_shard {
        let rebuilt = lchfs_fsck::rebuild_shards(&roots)?;
        for r in &rebuilt {
            println!(
                "Rebuilt shard {} of striped segment {} onto vdev {}.",
                r.shard_index, r.segment_id, r.vdev_id
            );
        }
        println!("{} shard(s) rebuilt.", rebuilt.len());
    }
    if options.rebuild_index {
        lchfs_fsck::rebuild_index(pool, other_vdevs)?;
        println!("INDEX.redb rebuilt from {} vdev(s).", other_vdevs.len() + 1);
    }

    // An encrypted pool's records can only be verified with its key. With
    // none given and nobody to ask -- or when asked not to -- check what
    // needs no key, and say plainly what that left out.
    let key = if !lchfs_fsck::is_encrypted(&roots) {
        None
    } else if options.structural
        || (!unlock.is_given() && !secrets::can_prompt() && !lchfs_crypto::testing::TEST_ENCRYPT_ALL)
    {
        let report = lchfs_fsck::structural_check(&roots);
        println!("Records scanned: {}", report.objects_visited);
        println!(
            "Encrypted pool, no key given: checked structure only (record framing and header checksums, \
             stripes, superblocks, keyrings). Record contents and the DAG were NOT verified; \
             give a key for a full check."
        );
        return finish_fsck(report);
    } else if !unlock.is_given() && lchfs_crypto::testing::TEST_ENCRYPT_ALL {
        // The fsck crate unlocks a test build's pools by itself.
        None
    } else {
        Some(unlock::with_key(unlock, &format!("pool {}", pool.display()), |k| {
            match lchfs_fsck::unlock(&roots, &k.as_unlock()) {
                Ok(c) => Ok(Some(c)),
                Err(e) if unlock::refused_keyring(&e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })?)
    };

    // The walk audits vdev 0's mirrored segments; striped segments are
    // read through the shards on every device given (§17.2).
    let live_roots = lchfs_fsck::collect_live_roots_with(pool, key.as_ref())?;
    let mut report = if options.verify_index {
        lchfs_fsck::verify_index_devices_with(&roots, &live_roots, key.as_ref())
    } else {
        lchfs_fsck::check_devices_with(&roots, &live_roots, key.as_ref())
    };
    println!("Objects visited: {}", report.objects_visited);

    // With the other devices named, the replicas are compared against
    // each other too; without them, say so when the pool is replicated
    // rather than quietly checking one device of several.
    let superblock = lchfs_fsck::read_superblock(pool)?;
    if !other_vdevs.is_empty() {
        let replicas = lchfs_fsck::check_replicas_with(&roots, key.as_ref());
        println!(
            "Records compared across {} vdevs: {}",
            roots.len(),
            replicas.objects_visited
        );
        report.errors.extend(replicas.errors);
    } else if superblock.vdev_count > 1 {
        println!(
            "Pool has {} vdevs; only vdev 0 was checked. Pass --vdev for each other device to compare replicas.",
            superblock.vdev_count
        );
    }
    let keyrings = lchfs_fsck::check_keyrings(&roots);
    report.errors.extend(keyrings.errors);
    report.warnings.extend(keyrings.warnings);
    finish_fsck(report)
}

fn finish_fsck(report: lchfs_fsck::FsckReport) -> anyhow::Result<()> {
    for w in &report.warnings {
        eprintln!("  warning: {w}");
    }
    if report.is_clean() {
        println!("No errors found.");
        Ok(())
    } else {
        // The replica pass scans vdev 0 again, so a damaged region there
        // would be reported by both passes; one line per finding.
        let mut seen = std::collections::HashSet::new();
        let findings: Vec<String> = report
            .errors
            .iter()
            .map(|e| e.to_string())
            .filter(|line| seen.insert(line.clone()))
            .collect();
        eprintln!("{} error(s) found:", findings.len());
        for line in &findings {
            eprintln!("  - {line}");
        }
        anyhow::bail!("fsck found {} error(s)", findings.len());
    }
}

fn pool_control(action: PoolAction) -> anyhow::Result<()> {
    use serde_json::json;
    let abs = |p: &PathBuf| -> anyhow::Result<String> {
        Ok(std::fs::canonicalize(p)
            .or_else(|_| std::env::current_dir().map(|d| d.join(p)))?
            .display()
            .to_string())
    };
    let (root, req) = match &action {
        PoolAction::Status { root } => (root, json!({ "cmd": "status" })),
        PoolAction::Scrub { root } => (root, json!({ "cmd": "scrub" })),
        PoolAction::Resilver { root, vdev } => (root, json!({ "cmd": "resilver", "vdev": vdev })),
        PoolAction::Attach { root, device } => (root, {
            require_device(device, false)?;
            json!({ "cmd": "attach", "path": abs(device)? })
        }),
        PoolAction::Online { root, device } => (root, json!({ "cmd": "online", "path": abs(device)? })),
        PoolAction::Offline { root, vdev } => (root, json!({ "cmd": "offline", "vdev": vdev })),
        PoolAction::Promote { root } => (root, json!({ "cmd": "promote" })),
        PoolAction::Detach { root } => (root, json!({ "cmd": "detach" })),
        PoolAction::Corruption { root, clear } => (root, json!({ "cmd": "corruption", "clear": clear })),
        PoolAction::SetStripe { root, k, m, min_age_segments } => (
            root,
            json!({ "cmd": "set-stripe", "k": k, "m": m, "min_age_segments": min_age_segments }),
        ),
        PoolAction::StripeStatus { root } => (root, json!({ "cmd": "stripe-status" })),
        PoolAction::EncryptionStatus { root } => (root, json!({ "cmd": "encryption-status" })),
        PoolAction::Encrypt { .. } | PoolAction::Rekey { .. } => unreachable!("dispatched before"),
    };
    let reply = control::request(&control::socket_for_device(root)?, &req)?;
    println!("{}", serde_json::to_string_pretty(&reply)?);
    Ok(())
}

/// `pool encrypt`: through the mount if it is mounted, else in-process.
fn pool_encrypt(root: &Path, devices: &DeviceArgs, slots: &SlotArgs, rate: Option<u64>) -> anyhow::Result<()> {
    use serde_json::json;
    let specs = slots.gather()?;
    let socket = control::socket_for_device(root)?;
    if control::is_live(&socket) {
        if let Some(r) = rate {
            control::request(&socket, &json!({ "cmd": "set-conversion-rate", "bytes_per_sec": r }))?;
        }
        let slots_json: Vec<control::SecretJson> = specs.iter().map(|s| s.to_json()).collect();
        let reply = control::request(
            &socket,
            &control::SecretJson(json!({ "cmd": "start-encrypt", "slots": slots_json, "no_padding": slots.no_padding })),
        )?;
        println!("encryption started on the mounted pool: new writes are sealed from now on.");
        println!("existing content is being rewritten; follow it with `lchfs pool encryption-status {}`", root.display());
        for slot in reply.get("slots").and_then(serde_json::Value::as_array).into_iter().flatten() {
            println!("  key slot {}: {} ({})", slot["id"], slot["kind"].as_str().unwrap_or("?"), slot["label"].as_str().unwrap_or(""));
        }
        return Ok(());
    }
    let pool = unlock::open_pool(root, devices, false, &UnlockArgs::default())?;
    pool.set_conversion_rate(rate);
    pool.start_encrypt(lchfs_store::EncryptionSetup {
        padding: slots.padding(),
        slots: specs.iter().map(|s| s.as_new_slot()).collect(),
    })?;
    drive_conversion(&pool)?;
    for slot in pool.keyring_slots() {
        println!("  key slot {}: {} ({})", slot.id, slot.kind, slot.label);
    }
    println!("Back up the keyring (`lchfs key backup`): lose every copy and the pool cannot be opened.");
    Ok(())
}

/// `pool rekey`: the proof is checked by whoever holds the keyring.
fn pool_rekey(root: &Path, devices: &DeviceArgs, unlock_args: &UnlockArgs, rate: Option<u64>) -> anyhow::Result<()> {
    use serde_json::json;
    let socket = control::socket_for_device(root)?;
    if control::is_live(&socket) {
        if let Some(r) = rate {
            control::request(&socket, &json!({ "cmd": "set-conversion-rate", "bytes_per_sec": r }))?;
        }
        let reply = unlock::with_key(unlock_args, "the mounted pool", |key| {
            let request = control::SecretJson(json!({ "cmd": "start-rekey", "proof": key.to_json() }));
            let reply = control::request_raw(&socket, &request)?;
            if reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                return Ok(Some(reply.get("result").cloned().unwrap_or_default()));
            }
            if reply.get("code").and_then(serde_json::Value::as_str) == Some(control::KEY_REFUSED) {
                return Ok(None);
            }
            anyhow::bail!("{}", reply.get("error").and_then(serde_json::Value::as_str).unwrap_or("unknown error"))
        })?;
        println!(
            "key rotation to epoch {} started on the mounted pool; follow it with `lchfs pool encryption-status {}`",
            reply.get("target_epoch").cloned().unwrap_or_default(),
            root.display()
        );
        return Ok(());
    }
    let pool = unlock::open_pool(root, devices, false, unlock_args)?;
    if !pool.is_encrypted() {
        anyhow::bail!("{} is not encrypted; use `lchfs pool encrypt`", root.display());
    }
    pool.set_conversion_rate(rate);
    let epoch = pool.start_rekey()?;
    println!("rotating to key epoch {epoch}");
    drive_conversion(&pool)
}

/// Runs an offline conversion to the end, one step at a time, saying how
/// far each got.
fn drive_conversion(pool: &lchfs_store::Pool) -> anyhow::Result<()> {
    loop {
        let more = pool.conversion_step()?;
        let s = pool.conversion_status();
        let p = &s.progress;
        if !more || s.target_epoch.is_none() {
            println!(
                "done: epoch {} only; {} chunk(s) ({} bytes) rewritten; the old epoch's records and keys are gone",
                s.current_epoch, p.chunks_rewritten, p.bytes_rewritten
            );
            return Ok(());
        }
        if !p.waiting_for_vdevs.is_empty() {
            anyhow::bail!(
                "retirement needs every device: vdevs {:?} are missing (pass them with --vdev); the conversion resumes on the next mount",
                p.waiting_for_vdevs
            );
        }
        println!(
            "{}: {}/{} files, {}/{} snapshots, {} chunk(s) rewritten; old-epoch segments left {:?}",
            s.phase.as_deref().unwrap_or("?"),
            p.files_done,
            p.files_total,
            p.snapshots_done,
            p.snapshots_total,
            p.chunks_rewritten,
            p.old_segments
        );
    }
}

fn snapshot(action: SnapshotAction) -> anyhow::Result<()> {
    let open = |pool: &Path, unlock: &UnlockArgs| unlock::open_pool(pool, &DeviceArgs::default(), false, unlock);
    match action {
        SnapshotAction::Create { pool, name, unlock } => {
            let pool = open(&pool, &unlock)?;
            pool.create_snapshot(&name)?;
            println!("Created snapshot '{name}'.");
            Ok(())
        }
        SnapshotAction::List { pool, unlock } => {
            let pool = open(&pool, &unlock)?;
            let snapshots = pool.list_snapshots()?;
            if snapshots.is_empty() {
                println!("No snapshots.");
            }
            for entry in snapshots {
                println!("{}\troot={:?}\tepoch={}\tcreated_at_unix_nanos={}", entry.name, entry.root_hash, entry.epoch, entry.created_at_unix_nanos);
            }
            Ok(())
        }
        SnapshotAction::Delete { pool, name, unlock } => {
            let pool = open(&pool, &unlock)?;
            pool.delete_snapshot(&name)?;
            println!("Deleted snapshot '{name}'.");
            Ok(())
        }
    }
}

fn stats(pool: &std::path::Path) -> anyhow::Result<()> {
    use lchfs_index::IndexStore;

    let slot = lchfs_fsck::read_superblock(pool)?;
    println!("pool_uuid: {}", lchfs_format::pool_uuid_hex(&slot.pool_uuid));
    println!("vdev: {} of {}", slot.vdev_id, slot.vdev_count);
    println!("generation: {}", slot.generation);
    println!("root_hash: {:?}", slot.root_hash);
    match keyring_bytes(pool).map(|b| lchfs_crypto::keyring::parse(&b)) {
        Err(_) => println!("encrypted: no"),
        Ok(Ok(k)) => println!(
            "encrypted: yes (keyring generation {}, {} slot(s), current epoch {})",
            k.body().generation,
            k.body().slots.len(),
            k.body().config.current_epoch
        ),
        Ok(Err(e)) => println!("encrypted: yes, but this device's keyring does not parse: {e}"),
    }
    // SuperblockStats is denormalized/informational only (never used for
    // correctness decisions -- see lchfs-format's own doc comment on it),
    // so these three are only as fresh as the last checkpoint.
    println!("live_bytes (denormalized, as of last checkpoint): {}", slot.stats.live_bytes);
    println!("object_count (denormalized, as of last checkpoint): {}", slot.stats.object_count);
    println!("segment_count (denormalized, as of last checkpoint): {}", slot.stats.segment_count);

    let device = lchfs_device::Device::open(pool)?;
    let count_segments = |kind| device.segment_ids(kind).len();
    println!("data segments on disk: {}", count_segments(lchfs_device::SegmentKind::Data));
    println!("meta segments on disk: {}", count_segments(lchfs_device::SegmentKind::Meta));
    let (total, free) = device.capacity();
    println!("device: {} bytes; zone space {total} bytes, {free} free", device.label().device_size);
    drop(device);

    if let Ok(index) = lchfs_index::RedbIndex::open(pool) {
        let entries = index.iter_chunk_locations().map(|v| v.len()).unwrap_or(0);
        println!("index entries: {entries}");
        println!("index generation: {}", index.generation());
    }

    Ok(())
}

fn key(action: KeyAction) -> anyhow::Result<()> {
    use keyops::{KeyOp, NewSlotSpec};
    match action {
        KeyAction::GenerateRecipient { out } => {
            let public = secrets::write_identity(&out)?;
            println!("identity (secret, keep it safe): {}", out.display());
            println!("recipient (public, for --recipient / key add-recipient): {}", public.display());
            Ok(())
        }
        KeyAction::List { pool, devices } => key_list(&devices.roots(&pool)?),
        KeyAction::AddPassphrase { target, new, label } => {
            let passphrase = new_passphrase(&new)?;
            run_key_op(&target, KeyOp::Add(NewSlotSpec::Passphrase { passphrase, cost: new.kdf.cost(), label })).map(drop)
        }
        KeyAction::ChangePassphrase { slot, target, new, revoke, secret_files } => {
            let slots = current_keyring_slots(&target)?;
            let old = slots.iter().find(|s| s.id == slot).ok_or_else(|| anyhow::anyhow!("no slot {slot}"))?;
            if !matches!(old.kind, lchfs_crypto::keyring::SlotKind::Passphrase(_)) {
                anyhow::bail!("slot {slot} is a {} slot, not a passphrase", old.kind.type_name());
            }
            let label = old.label.clone();
            let passphrase = new_passphrase(&new)?;
            if !revoke {
                run_key_op(
                    &target,
                    KeyOp::Replace { old: slot, new: NewSlotSpec::Passphrase { passphrase, cost: new.kdf.cost(), label } },
                )?;
                println!(
                    "Whoever knew the old passphrase and kept a copy of the old keyring can still open that copy; \
                     `change-passphrase --revoke` also replaces the keyring key."
                );
                return Ok(());
            }
            // Revoking needs every other passphrase and PIN; ask before
            // changing anything, then add the new slot and revoke the old.
            let mut others = revoke_secrets(&slots, slot, &secret_files)?;
            let new_pass = passphrase.clone();
            let added = run_key_op(
                &target,
                KeyOp::Add(NewSlotSpec::Passphrase { passphrase, cost: new.kdf.cost(), label }),
            )?;
            let added: u16 = added
                .get("added")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| anyhow::anyhow!("the new slot's id was not reported"))?;
            others.insert(added, new_pass.clone());
            // The new passphrase now opens the pool: it is the proof for the
            // revoke, whatever opened it for the add.
            run_key_op_with(&target, KeyOp::Revoke { slot, secrets: others }, Some(unlock::Credential::Passphrase(new_pass)))?;
            println!("Slot {slot} revoked and the keyring key replaced.");
            Ok(())
        }
        KeyAction::AddRecipient { recipient, target, label } => {
            let recipient = Box::new(secrets::read_recipient(&recipient)?);
            run_key_op(&target, KeyOp::Add(NewSlotSpec::Recipient { recipient, label })).map(drop)
        }
        KeyAction::AddTpm { target, tpm_slot, label } => {
            let pin = new_tpm_pin(&tpm_slot)?;
            run_key_op(&target, KeyOp::Add(NewSlotSpec::Tpm { pcrs: tpm_slot.tpm_pcrs.clone(), pin, label })).map(drop)
        }
        KeyAction::Remove { slot, target } => run_key_op(&target, KeyOp::Remove(slot)).map(drop),
        KeyAction::Revoke { slot, target, secret_files } => {
            let slots = current_keyring_slots(&target)?;
            if !slots.iter().any(|s| s.id == slot) {
                anyhow::bail!("no slot {slot}");
            }
            let secrets_by_slot = revoke_secrets(&slots, slot, &secret_files)?;
            run_key_op(&target, KeyOp::Revoke { slot, secrets: secrets_by_slot })?;
            println!(
                "Slot {slot} revoked and the keyring key replaced. Anyone who held it also held the content keys: \
                 rotate them with `lchfs pool rekey`."
            );
            Ok(())
        }
        KeyAction::Backup { pool, devices, out } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let roots = devices.roots(&pool)?;
            let refs: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
            let found = lchfs_crypto::keyring::read_all(&refs)?;
            let (from, newest) = found.first().ok_or_else(|| anyhow::anyhow!("no keyring on any device: the pool is not encrypted"))?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&out)
                .map_err(|e| anyhow::anyhow!("{}: {e}", out.display()))?;
            f.write_all(newest.file_bytes())?;
            f.sync_all()?;
            println!(
                "keyring generation {} (from {}) backed up to {}",
                newest.body().generation,
                from.display(),
                out.display()
            );
            println!("It opens with the same passphrases and keys as the pool did at this moment; keep it as safe as they are.");
            Ok(())
        }
        KeyAction::Restore { file, target, force } => key_restore(&file, &target, force),
    }
}

/// What revoking `revoking` needs to rewrap every other slot, from the
/// `SLOT=FILE` specs or asked for -- all of it before anything changes.
fn revoke_secrets(
    slots: &[lchfs_crypto::keyring::Slot],
    revoking: u16,
    secret_files: &[String],
) -> anyhow::Result<std::collections::BTreeMap<u16, secrets::Secret>> {
    let mut files = std::collections::BTreeMap::new();
    for spec in secret_files {
        let (id, path) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--secret-file takes SLOT=FILE, not {spec:?}"))?;
        let id: u16 = id.parse().map_err(|_| anyhow::anyhow!("bad slot id in {spec:?}"))?;
        files.insert(id, PathBuf::from(path));
    }
    let mut out = std::collections::BTreeMap::new();
    for (id, prompt) in keyops::secrets_needed(slots, revoking) {
        let secret = match files.get(&id) {
            Some(path) => unlock::read_pin(Some(path), "")?,
            None => secrets::prompt(&prompt)?,
        };
        out.insert(id, secret);
    }
    Ok(out)
}

fn new_passphrase(new: &NewPassphraseArgs) -> anyhow::Result<secrets::Secret> {
    secrets::new_passphrase(&secrets::Source { file: new.new_passphrase_file.clone(), fd: new.new_passphrase_fd })
}

/// A keyring change: through the mount's control socket if the pool is
/// mounted (the mount holds the keyring, and must be the one to change
/// it), else directly under every device's pool lock.
fn run_key_op(target: &KeyTarget, op: keyops::KeyOp) -> anyhow::Result<serde_json::Value> {
    run_key_op_with(target, op, None)
}

/// `run_key_op`, proving with `proof` if given instead of the target's
/// unlock options.
fn run_key_op_with(
    target: &KeyTarget,
    op: keyops::KeyOp,
    proof: Option<unlock::Credential>,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;
    let with_key = |what: &str, attempt: &mut dyn FnMut(&unlock::Credential) -> anyhow::Result<Option<serde_json::Value>>| {
        match &proof {
            Some(key) => attempt(key)?.ok_or_else(|| anyhow::anyhow!("{what}: the key was refused")),
            None => unlock::with_key(&target.unlock, what, attempt),
        }
    };
    let socket = control::socket_for_device(&target.pool)?;
    let (result, unwritten) = if control::is_live(&socket) {
        // The JSON carries hex secrets: `SecretJson` zeroes every string
        // in it when it drops.
        let op_json = op.to_json();
        let reply = with_key("the mounted pool", &mut |key| {
            let request = control::SecretJson(json!({ "cmd": "key-op", "proof": key.to_json(), "op": op_json }));
            let reply = control::request_raw(&socket, &request)?;
            if reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                return Ok(Some(reply.get("result").cloned().unwrap_or_default()));
            }
            if reply.get("code").and_then(serde_json::Value::as_str) == Some(control::KEY_REFUSED) {
                return Ok(None);
            }
            anyhow::bail!("{}", reply.get("error").and_then(serde_json::Value::as_str).unwrap_or("unknown error"))
        })?;
        let unwritten: Vec<String> = reply
            .get("unwritten")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().map(|u| u.to_string()).collect())
            .unwrap_or_default();
        (reply.get("result").cloned().unwrap_or_default(), unwritten)
    } else {
        let roots = target.devices.roots(&target.pool)?;
        let refs: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
        let mut failed = Vec::new();
        let result = with_key(&format!("pool {}", target.pool.display()), &mut |key| {
            match lchfs_store::Pool::update_keyring_offline(&refs, target.degraded, &key.as_unlock(), |ring| op.apply(ring)) {
                Ok((v, f)) => {
                    failed = f.iter().map(|(r, e)| format!("{}: {e}", r.display())).collect();
                    Ok(Some(v))
                }
                Err(e) if unlock::refused(&e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })?;
        (result, failed)
    };
    if let Some(id) = result.get("added") {
        println!("added key slot {id}");
    }
    if let Some(id) = result.get("removed") {
        println!("removed key slot {id}");
    }
    for u in &unwritten {
        eprintln!("WARNING: the new keyring could not be written to {u}; it keeps the old one until the next mount repairs it");
    }
    Ok(result)
}

/// The slots of the newest keyring on the target's devices, read without a
/// key (the slot table is cleartext; its MAC is checked on unlock).
fn current_keyring_slots(target: &KeyTarget) -> anyhow::Result<Vec<lchfs_crypto::keyring::Slot>> {
    let roots = target.devices.roots(&target.pool)?;
    let refs: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
    let found = lchfs_crypto::keyring::read_all(&refs)?;
    let (_, newest) = found.first().ok_or_else(|| anyhow::anyhow!("no keyring on any device: the pool is not encrypted"))?;
    Ok(newest.body().slots.clone())
}

fn key_list(roots: &[PathBuf]) -> anyhow::Result<()> {
    let mut newest: Option<lchfs_crypto::keyring::LockedKeyring> = None;
    for root in roots {
        let vdev = lchfs_fsck::read_superblock(root).map(|s| s.vdev_id.to_string()).unwrap_or_else(|_| "?".into());
        match keyring_bytes(root) {
            Err(_) => println!("vdev {vdev} ({}): no keyring", root.display()),
            Ok(bytes) => match lchfs_crypto::keyring::parse(&bytes) {
                Err(e) => println!("vdev {vdev} ({}): keyring damaged: {e}", root.display()),
                Ok(k) => {
                    println!("vdev {vdev} ({}): keyring generation {}", root.display(), k.body().generation);
                    if newest.as_ref().is_none_or(|n| k.body().generation > n.body().generation) {
                        newest = Some(k);
                    }
                }
            },
        }
    }
    let Some(k) = newest else {
        println!("No keyring: the pool is not encrypted.");
        return Ok(());
    };
    let c = &k.body().config;
    println!(
        "generation {}: padding {:?}, current epoch {}, minimum epoch {}{}",
        k.body().generation,
        c.padding,
        c.current_epoch,
        c.min_epoch,
        c.conversion.map(|v| format!(", converting to epoch {} ({:?})", v.target_epoch, v.phase)).unwrap_or_default()
    );
    for s in &k.body().slots {
        let summary = lchfs_store::SlotSummary::of(s);
        println!("  slot {}: {} ({}), created {}", summary.id, summary.kind, summary.label, summary.created_unix);
    }
    println!("(read without a key: the slot table is authenticated only when the keyring is unlocked)");
    Ok(())
}

fn key_restore(file: &Path, target: &KeyTarget, force: bool) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
    let backup = lchfs_crypto::keyring::parse(&bytes)?;
    let roots = target.devices.roots(&target.pool)?;
    let uuid = lchfs_fsck::read_superblock(&target.pool)?.pool_uuid;
    if backup.body().pool_uuid != uuid {
        anyhow::bail!("{} is a keyring for a different pool", file.display());
    }
    // Proof it is a real keyring for this pool and that the caller can open
    // it: a forged backup must not be able to replace anything.
    unlock::with_key(&target.unlock, &format!("the backup {}", file.display()), |key| match backup.unlock(&key.as_unlock()) {
        Ok(_) => Ok(Some(())),
        Err(e) if unlock::refused_keyring(&e) => Ok(None),
        Err(e) => Err(e.into()),
    })?;
    let _locks = roots
        .iter()
        .map(|r| lchfs_store::lock_pool(r).map_err(|e| anyhow::anyhow!("{}: {e} (unmount the pool first)", r.display())))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut restored = 0;
    for root in &roots {
        let intact = keyring_bytes(root)
            .ok()
            .and_then(|b| lchfs_crypto::keyring::parse(&b).ok())
            .filter(|k| k.body().pool_uuid == uuid);
        match intact {
            Some(k) if !force => {
                println!("{}: keyring generation {} is intact; left as it is", root.display(), k.body().generation);
                continue;
            }
            Some(k) => eprintln!(
                "WARNING: {}: replacing intact keyring generation {} with the backup's {} -- any slot added, changed or revoked since the backup is undone",
                root.display(),
                k.body().generation,
                backup.body().generation
            ),
            None => {}
        }
        lchfs_crypto::keyring::write_on(root, backup.file_bytes())?;
        println!("{}: keyring restored (generation {})", root.display(), backup.body().generation);
        restored += 1;
    }
    println!("{restored} device(s) restored.");
    Ok(())
}

/// A device's keyring bytes; `NotFound` when its keyring region is empty.
fn keyring_bytes(root: &Path) -> std::io::Result<Vec<u8>> {
    lchfs_crypto::keyring::read_on(root)?.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no keyring"))
}

/// Set to `1` to let `create-pool` and the attach commands take a sparse
/// image file (or a directory, for an `lchfs.img` inside it) instead of a
/// block device. For tests and development: a pool belongs on a device.
pub const ALLOW_IMAGES_ENV: &str = "LCHFS_ALLOW_IMAGES";

/// Refuses to format anything that is not a block device, and a block
/// device that holds something already unless `force`: formatting is the
/// one command that destroys data it did not write.
fn require_device(path: &Path, force: bool) -> anyhow::Result<()> {
    let is_block = lchfs_device::is_block_device(path);
    if !is_block && std::env::var_os(ALLOW_IMAGES_ENV).is_none_or(|v| v != "1") {
        anyhow::bail!(
            "{} is not a block device: a pool is created on a disk or partition (e.g. /dev/sdb1)",
            path.display()
        );
    }
    if !is_block || force || lchfs_device::is_formatted(path) {
        // An LCHFS device's own checks (blank, not in another pool) are
        // the engine's.
        return Ok(());
    }
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::open(path)?;
    let mut head = vec![0u8; 1 << 20];
    let mut read = 0;
    while read < head.len() {
        match file.read_at(&mut head[read..], read as u64)? {
            0 => break,
            n => read += n,
        }
    }
    if head[..read].iter().any(|&b| b != 0) {
        anyhow::bail!(
            "{} is not blank: its first MiB holds data (a partition table or filesystem?). \
             Pass --force to format it anyway",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_command_line_definition_is_consistent() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}

