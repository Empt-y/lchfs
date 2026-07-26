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
        pool: PathBuf,
        #[arg(long)]
        verify_index: bool,
        #[arg(long)]
        rebuild_index: bool,
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
        Command::Fsck { pool, verify_index, rebuild_index } => {
            fsck(&pool, verify_index, rebuild_index)
        }
        Command::Snapshot { action } => snapshot(action),
        Command::Stats { pool } => stats(&pool),
    }
}

fn create_pool(_path: &std::path::Path) -> anyhow::Result<()> {
    // TODO(phase-D): lchfs_store::Pool::open with create semantics + default PoolParams
    todo!("lchfs-cli: create_pool")
}

fn mount(_pool: &std::path::Path, _mountpoint: &std::path::Path) -> anyhow::Result<()> {
    // TODO(phase-D): open Pool, wrap in lchfs_fuse::LchfsFilesystem, fuser::mount2
    todo!("lchfs-cli: mount")
}

fn fsck(_pool: &std::path::Path, _verify_index: bool, _rebuild_index: bool) -> anyhow::Result<()> {
    // TODO(phase-F): open Pool read-only, collect live roots, call lchfs_fsck::check
    todo!("lchfs-cli: fsck")
}

fn snapshot(_action: SnapshotAction) -> anyhow::Result<()> {
    // TODO(phase-G): SnapshotTable create/list/delete via Pool
    todo!("lchfs-cli: snapshot")
}

fn stats(_pool: &std::path::Path) -> anyhow::Result<()> {
    // TODO(phase-G): read denormalized SuperblockStats + live index/segment info
    todo!("lchfs-cli: stats")
}
