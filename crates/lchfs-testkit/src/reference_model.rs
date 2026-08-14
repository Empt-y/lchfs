//! The oracle. ARCHITECTURE.md §10: "a deliberately simple, obviously-
//! correct `HashMap<PathBuf, Vec<u8>>`-based oracle" -- proptest runs
//! random op sequences against both this and the real engine, and asserts
//! equivalence modulo documented allowed divergence (e.g. mtime precision).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// A file's content, shared (`Rc<RefCell<_>>`) rather than duplicated per
/// path so `link` (hardlink) can alias the *same* backing bytes across
/// multiple paths, matching real hardlink semantics: writing through one
/// name is visible through every other name for the same inode, and the
/// bytes only really go away once every referencing path is unlinked.
type FileContent = Rc<RefCell<Vec<u8>>>;

#[derive(Debug, Clone, PartialEq)]
pub enum ModelError {
    NotFound,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    NotEmpty,
    /// Exists, but as the wrong kind of node for this operation -- e.g.
    /// writing directly to a symlink's own path (this model never follows
    /// symlinks during resolution, matching how the harness that drives
    /// it resolves paths -- see `write`'s doc comment).
    WrongType,
}

#[derive(Debug, Default, Clone)]
pub struct ReferenceModel {
    files: HashMap<PathBuf, FileContent>,
    dirs: HashSet<PathBuf>,
    symlinks: HashMap<PathBuf, PathBuf>,
}

impl ReferenceModel {
    pub fn new() -> Self {
        let mut model = Self::default();
        model.dirs.insert(PathBuf::from("/"));
        model
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path) || self.dirs.contains(path) || self.symlinks.contains_key(path)
    }

    fn parent_exists_as_dir(&self, path: &Path) -> bool {
        path.parent().is_none_or(|p| self.dirs.contains(p))
    }

    pub fn write(&mut self, path: &Path, offset: u64, data: &[u8]) -> Result<(), ModelError> {
        if self.dirs.contains(path) {
            return Err(ModelError::IsADirectory);
        }
        // Not a real VFS layer -- `path` resolution never follows a
        // symlink (see this model's doc comment / the harness that drives
        // it), so a symlink occupying `path` is a distinct, non-writable
        // node here, exactly like the real engine's `write()` rejecting a
        // non-`File`-kind ino.
        if self.symlinks.contains_key(path) {
            return Err(ModelError::WrongType);
        }
        if !self.files.contains_key(path) {
            if !self.parent_exists_as_dir(path) {
                return Err(ModelError::NotFound);
            }
            self.files.insert(path.to_path_buf(), Rc::new(RefCell::new(Vec::new())));
        }
        let content = self.files.get(path).unwrap();
        let mut bytes = content.borrow_mut();
        let end = (offset as usize) + data.len();
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        bytes[offset as usize..end].copy_from_slice(data);
        Ok(())
    }

    pub fn read(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, ModelError> {
        let content = self.files.get(path).ok_or(ModelError::NotFound)?;
        let bytes = content.borrow();
        let start = (offset as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    pub fn truncate(&mut self, path: &Path, len: u64) -> Result<(), ModelError> {
        let content = self.files.get(path).ok_or(ModelError::NotFound)?;
        content.borrow_mut().resize(len as usize, 0);
        Ok(())
    }

    pub fn mkdir(&mut self, path: &Path) -> Result<(), ModelError> {
        if self.exists(path) {
            return Err(ModelError::AlreadyExists);
        }
        if !self.parent_exists_as_dir(path) {
            return Err(ModelError::NotFound);
        }
        self.dirs.insert(path.to_path_buf());
        Ok(())
    }

    pub fn unlink(&mut self, path: &Path) -> Result<(), ModelError> {
        if self.dirs.contains(path) {
            return Err(ModelError::IsADirectory);
        }
        if self.files.remove(path).is_some() || self.symlinks.remove(path).is_some() {
            Ok(())
        } else {
            Err(ModelError::NotFound)
        }
    }

    pub fn rmdir(&mut self, path: &Path) -> Result<(), ModelError> {
        if !self.dirs.contains(path) {
            return if self.exists(path) { Err(ModelError::NotADirectory) } else { Err(ModelError::NotFound) };
        }
        let has_children = self.files.keys().any(|p| p.parent() == Some(path))
            || self.dirs.iter().any(|p| p.as_path() != path && p.parent() == Some(path))
            || self.symlinks.keys().any(|p| p.parent() == Some(path));
        if has_children {
            return Err(ModelError::NotEmpty);
        }
        self.dirs.remove(path);
        Ok(())
    }

    /// Moves `from` to `to`, POSIX overwrite semantics (an existing `to`
    /// is replaced). If `from` is a directory, every path nested under it
    /// moves too -- this model is a flat map, not a real tree, so a
    /// directory rename has to explicitly re-root everything underneath.
    pub fn rename(&mut self, from: &Path, to: &Path) -> Result<(), ModelError> {
        if !self.exists(from) {
            return Err(ModelError::NotFound);
        }
        if from == to {
            return Ok(());
        }
        if to.starts_with(from) {
            // Moving a directory into its own subtree.
            return Err(ModelError::NotADirectory);
        }
        if !self.parent_exists_as_dir(to) {
            return Err(ModelError::NotFound);
        }

        if self.dirs.contains(from) {
            if self.files.contains_key(to) || self.symlinks.contains_key(to) {
                return Err(ModelError::NotADirectory);
            }
            if self.dirs.contains(to) {
                let dest_has_children = self.files.keys().any(|p| p.parent() == Some(to))
                    || self.dirs.iter().any(|p| p.as_path() != to && p.parent() == Some(to))
                    || self.symlinks.keys().any(|p| p.parent() == Some(to));
                if dest_has_children {
                    return Err(ModelError::NotEmpty);
                }
                self.dirs.remove(to);
            }

            let renest = |p: &Path| -> Option<PathBuf> {
                p.strip_prefix(from).ok().map(|rel| to.join(rel))
            };
            for old in self.dirs.clone().into_iter().filter(|p| p.starts_with(from)) {
                if let Some(new) = renest(&old) {
                    self.dirs.remove(&old);
                    self.dirs.insert(new);
                }
            }
            for old in self.files.keys().cloned().collect::<Vec<_>>().into_iter().filter(|p| p.starts_with(from)) {
                if let Some(new) = renest(&old)
                    && let Some(content) = self.files.remove(&old)
                {
                    self.files.insert(new, content);
                }
            }
            for old in self.symlinks.keys().cloned().collect::<Vec<_>>().into_iter().filter(|p| p.starts_with(from)) {
                if let Some(new) = renest(&old)
                    && let Some(target) = self.symlinks.remove(&old)
                {
                    self.symlinks.insert(new, target);
                }
            }
        } else {
            if self.dirs.contains(to) {
                return Err(ModelError::IsADirectory);
            }
            self.files.remove(to);
            self.symlinks.remove(to);
            if let Some(content) = self.files.remove(from) {
                self.files.insert(to.to_path_buf(), content);
            } else if let Some(target) = self.symlinks.remove(from) {
                self.symlinks.insert(to.to_path_buf(), target);
            }
        }
        Ok(())
    }

    /// Hardlink: `target` becomes a second name for `path`'s *same*
    /// backing bytes (see `FileContent`'s doc comment) -- zero copy, and a
    /// write through either name is visible through the other. Symlinks
    /// can be hardlinked too (matching Linux's actual `link(2)`, which by
    /// default links the symlink itself rather than following it) --
    /// there's no aliasing to model there since a symlink's target string
    /// never changes after creation, so an independent copy behaves
    /// identically to a shared reference would.
    pub fn link(&mut self, path: &Path, target: &Path) -> Result<(), ModelError> {
        if self.exists(target) {
            return Err(ModelError::AlreadyExists);
        }
        if !self.parent_exists_as_dir(target) {
            return Err(ModelError::NotFound);
        }
        if self.dirs.contains(path) {
            return Err(ModelError::IsADirectory);
        }
        if let Some(content) = self.files.get(path).cloned() {
            self.files.insert(target.to_path_buf(), content);
            return Ok(());
        }
        if let Some(link_target) = self.symlinks.get(path).cloned() {
            self.symlinks.insert(target.to_path_buf(), link_target);
            return Ok(());
        }
        Err(ModelError::NotFound)
    }

    pub fn symlink(&mut self, path: &Path, target: &Path) -> Result<(), ModelError> {
        if self.exists(path) {
            return Err(ModelError::AlreadyExists);
        }
        if !self.parent_exists_as_dir(path) {
            return Err(ModelError::NotFound);
        }
        self.symlinks.insert(path.to_path_buf(), target.to_path_buf());
        Ok(())
    }

    pub fn readlink(&self, path: &Path) -> Result<PathBuf, ModelError> {
        self.symlinks.get(path).cloned().ok_or(ModelError::NotFound)
    }

    pub fn is_dir(&self, path: &Path) -> bool {
        self.dirs.contains(path)
    }

    pub fn file_len(&self, path: &Path) -> Option<u64> {
        self.files.get(path).map(|c| c.borrow().len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn write_then_read_roundtrips() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"hello").unwrap();
        assert_eq!(m.read(&p("/a"), 0, 5).unwrap(), b"hello");
    }

    #[test]
    fn write_creates_the_file_if_parent_exists() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"x").unwrap();
        assert!(m.read(&p("/a"), 0, 1).is_ok());
    }

    #[test]
    fn write_under_missing_parent_fails() {
        let mut m = ReferenceModel::new();
        assert_eq!(m.write(&p("/missing/a"), 0, b"x"), Err(ModelError::NotFound));
    }

    #[test]
    fn sparse_write_zero_fills_the_gap() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"ab").unwrap();
        m.write(&p("/a"), 5, b"cd").unwrap();
        assert_eq!(m.read(&p("/a"), 0, 7).unwrap(), b"ab\0\0\0cd");
    }

    #[test]
    fn read_past_eof_is_truncated_not_padded() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"ab").unwrap();
        assert_eq!(m.read(&p("/a"), 0, 100).unwrap(), b"ab");
    }

    #[test]
    fn truncate_shrinks_and_zero_extends() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"abcdef").unwrap();
        m.truncate(&p("/a"), 3).unwrap();
        assert_eq!(m.read(&p("/a"), 0, 100).unwrap(), b"abc");
        m.truncate(&p("/a"), 5).unwrap();
        assert_eq!(m.read(&p("/a"), 0, 100).unwrap(), b"abc\0\0");
    }

    #[test]
    fn mkdir_then_write_inside_it() {
        let mut m = ReferenceModel::new();
        m.mkdir(&p("/d")).unwrap();
        m.write(&p("/d/f"), 0, b"x").unwrap();
        assert_eq!(m.read(&p("/d/f"), 0, 1).unwrap(), b"x");
    }

    #[test]
    fn mkdir_twice_fails() {
        let mut m = ReferenceModel::new();
        m.mkdir(&p("/d")).unwrap();
        assert_eq!(m.mkdir(&p("/d")), Err(ModelError::AlreadyExists));
    }

    #[test]
    fn rmdir_empty_succeeds_nonempty_fails() {
        let mut m = ReferenceModel::new();
        m.mkdir(&p("/d")).unwrap();
        m.write(&p("/d/f"), 0, b"x").unwrap();
        assert_eq!(m.rmdir(&p("/d")), Err(ModelError::NotEmpty));
        m.unlink(&p("/d/f")).unwrap();
        m.rmdir(&p("/d")).unwrap();
        assert!(!m.is_dir(&p("/d")));
    }

    #[test]
    fn unlink_removes_a_file_but_not_a_directory() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"x").unwrap();
        m.unlink(&p("/a")).unwrap();
        assert_eq!(m.read(&p("/a"), 0, 1), Err(ModelError::NotFound));

        m.mkdir(&p("/d")).unwrap();
        assert_eq!(m.unlink(&p("/d")), Err(ModelError::IsADirectory));
    }

    #[test]
    fn rename_within_same_directory() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"x").unwrap();
        m.rename(&p("/a"), &p("/b")).unwrap();
        assert_eq!(m.read(&p("/a"), 0, 1), Err(ModelError::NotFound));
        assert_eq!(m.read(&p("/b"), 0, 1).unwrap(), b"x");
    }

    #[test]
    fn rename_overwrites_existing_destination() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"new").unwrap();
        m.write(&p("/b"), 0, b"old").unwrap();
        m.rename(&p("/a"), &p("/b")).unwrap();
        assert_eq!(m.read(&p("/b"), 0, 3).unwrap(), b"new");
    }

    #[test]
    fn rename_directory_moves_nested_contents() {
        let mut m = ReferenceModel::new();
        m.mkdir(&p("/a")).unwrap();
        m.write(&p("/a/f"), 0, b"x").unwrap();
        m.mkdir(&p("/a/sub")).unwrap();
        m.write(&p("/a/sub/g"), 0, b"y").unwrap();

        m.rename(&p("/a"), &p("/b")).unwrap();

        assert!(m.is_dir(&p("/b")));
        assert!(m.is_dir(&p("/b/sub")));
        assert_eq!(m.read(&p("/b/f"), 0, 1).unwrap(), b"x");
        assert_eq!(m.read(&p("/b/sub/g"), 0, 1).unwrap(), b"y");
        assert_eq!(m.read(&p("/a/f"), 0, 1), Err(ModelError::NotFound));
    }

    #[test]
    fn rename_directory_into_its_own_subtree_fails() {
        let mut m = ReferenceModel::new();
        m.mkdir(&p("/a")).unwrap();
        m.mkdir(&p("/a/b")).unwrap();
        assert!(m.rename(&p("/a"), &p("/a/b/c")).is_err());
    }

    #[test]
    fn link_shares_content_and_survives_partial_unlink() {
        let mut m = ReferenceModel::new();
        m.write(&p("/a"), 0, b"shared").unwrap();
        m.link(&p("/a"), &p("/b")).unwrap();

        // A write through one name is visible through the other.
        m.write(&p("/a"), 6, b"!").unwrap();
        assert_eq!(m.read(&p("/b"), 0, 7).unwrap(), b"shared!");

        m.unlink(&p("/a")).unwrap();
        assert_eq!(m.read(&p("/b"), 0, 7).unwrap(), b"shared!");
    }

    #[test]
    fn link_can_hardlink_a_symlink() {
        let mut m = ReferenceModel::new();
        m.symlink(&p("/link"), &p("/target")).unwrap();
        m.link(&p("/link"), &p("/link2")).unwrap();
        assert_eq!(m.readlink(&p("/link2")).unwrap(), p("/target"));
    }

    #[test]
    fn symlink_and_readlink_roundtrip() {
        let mut m = ReferenceModel::new();
        m.symlink(&p("/link"), &p("/target")).unwrap();
        assert_eq!(m.readlink(&p("/link")).unwrap(), p("/target"));
    }
}
