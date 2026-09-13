//! LCHFS CLI. ARCHITECTURE.md §11: `clap`-based commands
//! create-pool, mount, fsck, snapshot {create,list,delete}, stats.

pub mod control;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lchfs", about = "Log-Structured Cryptographic Hash File System")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new pool at the given path.
    CreatePool { path: PathBuf },
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
}

#[derive(Subcommand)]
enum SnapshotAction {
    Create { pool: PathBuf, name: String },
    List { pool: PathBuf },
    Delete { pool: PathBuf, name: String },
}

pub fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Command::CreatePool { path } => create_pool(&path),
        Command::Mount { pool, mountpoint, vdevs, scan, degraded } => {
            mount(&pool, &vdevs, &scan, degraded, &mountpoint)
        }
        Command::Discover { dirs } => discover(&dirs),
        Command::ServeNfs { pool, listen, vdevs, scan, degraded } => {
            serve_nfs(&pool, &vdevs, &scan, degraded, &listen)
        }
        Command::Fsck { pool, vdevs, scan, verify_index, rebuild_index } => {
            let mut vdevs = vdevs;
            if !scan.is_empty() {
                let uuid = lchfs_fsck::read_superblock(&pool)?.pool_uuid;
                let candidates: Vec<&std::path::Path> = scan.iter().map(|p| p.as_path()).collect();
                let found = lchfs_store::Pool::discover(&candidates, Some(uuid))?;
                let pool_abs = std::fs::canonicalize(&pool).unwrap_or(pool.clone());
                for p in &found.pools {
                    for (_, _, root) in &p.members {
                        if std::fs::canonicalize(root).unwrap_or(root.clone()) != pool_abs {
                            vdevs.push(root.clone());
                        }
                    }
                }
            }
            fsck(&pool, &vdevs, verify_index, rebuild_index)
        }
        Command::AttachVdev { pool, vdevs, new_device } => {
            let mut roots: Vec<&std::path::Path> = vec![pool.as_path()];
            roots.extend(vdevs.iter().map(|p| p.as_path()));
            let id = lchfs_store::Pool::attach_vdev(&roots, &new_device)?;
            println!(
                "{} attached as vdev {id}. Mount with every device to resilver it.",
                new_device.display()
            );
            Ok(())
        }
        Command::DetachVdev { pool, vdevs } => {
            let mut roots: Vec<&std::path::Path> = vec![pool.as_path()];
            roots.extend(vdevs.iter().map(|p| p.as_path()));
            let id = lchfs_store::Pool::detach_vdev(&roots)?;
            println!("vdev {id} detached; its segment files can be deleted.");
            Ok(())
        }
        Command::Pool { action } => pool_control(action),
        Command::Snapshot { action } => snapshot(action),
        Command::Stats { pool } => stats(&pool),
    }
}

fn create_pool(path: &std::path::Path) -> anyhow::Result<()> {
    let pool = lchfs_store::Pool::create(path, lchfs_format::PoolParams::default())?;
    println!("pool {} created at {}", lchfs_format::pool_uuid_hex(&pool.pool_uuid()), path.display());
    Ok(())
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
    pool: &std::path::Path,
    other_vdevs: &[PathBuf],
    scan: &[PathBuf],
    degraded: bool,
) -> anyhow::Result<(std::sync::Arc<lchfs_store::Pool>, control::ControlServer)> {
    let pool = if !scan.is_empty() {
        if !other_vdevs.is_empty() {
            anyhow::bail!("--scan finds the other devices; do not also name them with --vdev");
        }
        let uuid = lchfs_fsck::read_superblock(pool)?.pool_uuid;
        let mut candidates: Vec<&std::path::Path> = vec![pool];
        candidates.extend(scan.iter().map(|p| p.as_path()));
        lchfs_store::Pool::open_discovered(&candidates, Some(uuid), degraded)?
    } else {
        let mut roots: Vec<&std::path::Path> = vec![pool];
        roots.extend(other_vdevs.iter().map(|p| p.as_path()));
        if degraded {
            lchfs_store::Pool::open_degraded(&roots)?
        } else {
            lchfs_store::Pool::open_replicated(&roots)?
        }
    };
    if pool.is_degraded() {
        eprintln!("WARNING: mounted degraded; vdevs {:?} are absent", pool.missing_vdevs());
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
    pool: &std::path::Path,
    other_vdevs: &[PathBuf],
    scan: &[PathBuf],
    degraded: bool,
    mountpoint: &std::path::Path,
) -> anyhow::Result<()> {
    let (pool, _control) = open_for_serving(pool, other_vdevs, scan, degraded)?;
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
    pool: &std::path::Path,
    other_vdevs: &[PathBuf],
    scan: &[PathBuf],
    degraded: bool,
    listen: &str,
) -> anyhow::Result<()> {
    let (pool, _control) = open_for_serving(pool, other_vdevs, scan, degraded)?;
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

fn fsck(
    pool: &std::path::Path,
    other_vdevs: &[PathBuf],
    verify_index: bool,
    rebuild_index: bool,
) -> anyhow::Result<()> {
    // No `Pool::open` here: fsck deliberately reads the pool directory
    // directly (see lchfs-fsck's module doc comment) rather than going
    // through the live engine -- opening a `Pool` would also run mount-
    // time crash recovery and spawn its background checkpoint/coalesce/
    // dedup threads, neither of which this one-shot diagnostic needs.
    if rebuild_index {
        let others: Vec<&std::path::Path> = other_vdevs.iter().map(|p| p.as_path()).collect();
        lchfs_fsck::rebuild_index(pool, &others)?;
        println!("INDEX.redb rebuilt from {} vdev(s).", others.len() + 1);
    }

    let live_roots = lchfs_fsck::collect_live_roots(pool)?;
    let mut report = if verify_index {
        lchfs_fsck::verify_index(pool, &live_roots)
    } else {
        lchfs_fsck::check(pool, &live_roots)
    };
    println!("Objects visited: {}", report.objects_visited);

    // The DAG walk above audits vdev 0. With the other devices named, the
    // replicas are compared against each other too; without them, say so
    // when the pool is replicated rather than quietly checking one device
    // of several.
    let superblock = lchfs_fsck::read_superblock(pool)?;
    if !other_vdevs.is_empty() {
        let mut roots: Vec<&std::path::Path> = vec![pool];
        roots.extend(other_vdevs.iter().map(|p| p.as_path()));
        let replicas = lchfs_fsck::check_replicas(&roots);
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
        PoolAction::Attach { root, device } => (root, json!({ "cmd": "attach", "path": abs(device)? })),
        PoolAction::Online { root, device } => (root, json!({ "cmd": "online", "path": abs(device)? })),
        PoolAction::Offline { root, vdev } => (root, json!({ "cmd": "offline", "vdev": vdev })),
        PoolAction::Promote { root } => (root, json!({ "cmd": "promote" })),
        PoolAction::Detach { root } => (root, json!({ "cmd": "detach" })),
        PoolAction::Corruption { root, clear } => (root, json!({ "cmd": "corruption", "clear": clear })),
    };
    let reply = control::request(&root.join(control::SOCKET_NAME), &req)?;
    println!("{}", serde_json::to_string_pretty(&reply)?);
    Ok(())
}

fn snapshot(action: SnapshotAction) -> anyhow::Result<()> {
    match action {
        SnapshotAction::Create { pool, name } => {
            let pool = lchfs_store::Pool::open(&pool)?;
            pool.create_snapshot(&name)?;
            println!("Created snapshot '{name}'.");
            Ok(())
        }
        SnapshotAction::List { pool } => {
            let pool = lchfs_store::Pool::open(&pool)?;
            let snapshots = pool.list_snapshots()?;
            if snapshots.is_empty() {
                println!("No snapshots.");
            }
            for entry in snapshots {
                println!("{}\troot={:?}\tepoch={}\tcreated_at_unix_nanos={}", entry.name, entry.root_hash, entry.epoch, entry.created_at_unix_nanos);
            }
            Ok(())
        }
        SnapshotAction::Delete { pool, name } => {
            let pool = lchfs_store::Pool::open(&pool)?;
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
    // SuperblockStats is denormalized/informational only (never used for
    // correctness decisions -- see lchfs-format's own doc comment on it),
    // so these three are only as fresh as the last checkpoint.
    println!("live_bytes (denormalized, as of last checkpoint): {}", slot.stats.live_bytes);
    println!("object_count (denormalized, as of last checkpoint): {}", slot.stats.object_count);
    println!("segment_count (denormalized, as of last checkpoint): {}", slot.stats.segment_count);

    let count_segments = |sub: &str| {
        std::fs::read_dir(pool.join("segments").join(sub))
            .map(|d| d.count())
            .unwrap_or(0)
    };
    println!("data segments on disk: {}", count_segments("data"));
    println!("meta segments on disk: {}", count_segments("meta"));

    if let Ok(index) = lchfs_index::RedbIndex::open(&pool.join("INDEX.redb")) {
        let entries = index.iter_chunk_locations().map(|v| v.len()).unwrap_or(0);
        println!("index entries: {entries}");
        println!("index generation: {}", index.generation());
    }

    Ok(())
}
