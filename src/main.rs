//! LCHFS entry point. All real logic lives in `lchfs-cli`; see ARCHITECTURE.md.

fn main() -> anyhow::Result<()> {
    lchfs_cli::run()
}
