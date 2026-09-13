//! LCHFS CLI. ARCHITECTURE.md §11: `clap`-based commands
//! create-pool, mount, fsck, snapshot {create,list,delete}, stats.

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
    Mount { pool: PathBuf, mountpoint: PathBuf },
    /// Walk the DAG and verify integrity (ARCHITECTURE.md §10).
    Fsck {
        /// vdev 0's root.
        pool: PathBuf,
        /// The pool's other vdev roots, for a replica comparison
        /// (ARCHITECTURE.md §15.8). Any order; each device's superblock
        /// says which slot it is.
        #[arg(long = "vdev")]
        vdevs: Vec<PathBuf>,
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
    /// Snapshot management (ARCHITECTURE.md §6).
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// Print pool statistics.
    Stats { pool: PathBuf },
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
        Command::Mount { pool, mountpoint } => mount(&pool, &mountpoint),
        Command::Fsck { pool, vdevs, verify_index, rebuild_index } => {
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
        Command::Snapshot { action } => snapshot(action),
        Command::Stats { pool } => stats(&pool),
    }
}

fn create_pool(path: &std::path::Path) -> anyhow::Result<()> {
    lchfs_store::Pool::create(path, lchfs_format::PoolParams::default())?;
    Ok(())
}

fn mount(pool: &std::path::Path, mountpoint: &std::path::Path) -> anyhow::Result<()> {
    let pool = std::sync::Arc::new(lchfs_store::Pool::open(pool)?);
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
        eprintln!("{} error(s) found:", report.errors.len());
        for e in &report.errors {
            eprintln!("  - {e}");
        }
        anyhow::bail!("fsck found {} error(s)", report.errors.len());
    }
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
