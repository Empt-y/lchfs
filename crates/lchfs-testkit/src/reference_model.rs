//! The oracle. ARCHITECTURE.md §10: "a deliberately simple, obviously-
//! correct `HashMap<PathBuf, Vec<u8>>`-based oracle" -- proptest runs
//! random op sequences against both this and the real engine, and asserts
//! equivalence modulo documented allowed divergence (e.g. mtime precision).

use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReferenceModel {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: std::collections::HashSet<PathBuf>,
}

impl ReferenceModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&mut self, _path: &std::path::Path, _offset: u64, _data: &[u8]) {
        todo!("lchfs-testkit: ReferenceModel::write")
    }

    pub fn read(&self, _path: &std::path::Path, _offset: u64, _len: usize) -> Option<Vec<u8>> {
        todo!("lchfs-testkit: ReferenceModel::read")
    }

    pub fn mkdir(&mut self, _path: &std::path::Path) {
        todo!("lchfs-testkit: ReferenceModel::mkdir")
    }

    pub fn unlink(&mut self, _path: &std::path::Path) {
        todo!("lchfs-testkit: ReferenceModel::unlink")
    }

    pub fn rename(&mut self, _from: &std::path::Path, _to: &std::path::Path) {
        todo!("lchfs-testkit: ReferenceModel::rename")
    }
}
