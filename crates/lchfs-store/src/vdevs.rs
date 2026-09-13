//! The online device set of one mount (ARCHITECTURE.md §15.8, §15.10).
//!
//! Everything that fans a write out -- the per-shard data writers, the
//! meta writer, each shard's delta log -- consults this when it opens a
//! new segment, and every checkpoint writes one superblock per member. It
//! is shared rather than copied so that a device attached while the pool
//! is mounted reaches every writer at its next rollover, and can be
//! *forced* to reach them by rolling each writer under its own lock.

use crate::backend::{FileBackend, Vdev};
use nix::fcntl::Flock;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;

/// One online device, with what the mount holds on it.
pub(crate) struct Member {
    pub vdev: Vdev,
    /// Its superblock ring. `None` only for the bare sets tests build from
    /// paths, which never checkpoint.
    pub superblock: Option<FileBackend>,
    /// The advisory lock on its root, held for the mount's lifetime so two
    /// mounts cannot share even a single device (§15.6). Never read.
    _lock: Option<Flock<File>>,
}

pub(crate) struct VdevSetState {
    /// Ascending by `Vdev::id`.
    pub members: Vec<Member>,
    /// How many slots the pool has, whether or not each has a device here.
    pub count: u16,
    /// Devices that are online for *writes* but whose superblock must not
    /// yet be advanced: a live attach in progress. Their generation stays
    /// behind until the resilver that fills them completes, so a crash
    /// mid-attach leaves a device the next mount knows to resilver rather
    /// than one that claims to be current.
    pub catching_up: HashSet<u16>,
}

pub struct VdevSet {
    state: RwLock<VdevSetState>,
}

impl VdevSet {
    pub(crate) fn new(members: Vec<Member>, count: u16) -> Self {
        Self {
            state: RwLock::new(VdevSetState {
                members,
                count,
                catching_up: HashSet::new(),
            }),
        }
    }

    pub(crate) fn member(vdev: Vdev, superblock: FileBackend, lock: Flock<File>) -> Member {
        Member {
            vdev,
            superblock: Some(superblock),
            _lock: Some(lock),
        }
    }

    /// A set for tests and tooling that drive writers directly: the roots
    /// given, slot by position, no superblocks and no locks.
    pub fn from_roots(roots: &[PathBuf]) -> Self {
        let members = roots
            .iter()
            .enumerate()
            .map(|(i, r)| Member {
                vdev: Vdev::new(i as u16, r.clone()),
                superblock: None,
                _lock: None,
            })
            .collect::<Vec<_>>();
        let count = members.len() as u16;
        Self::new(members, count)
    }

    pub(crate) fn read(&self) -> parking_lot::RwLockReadGuard<'_, VdevSetState> {
        self.state.read()
    }

    /// Every online device, ascending by id. A snapshot: the set can grow
    /// after this returns, which is why writers take one per segment.
    pub fn online(&self) -> Vec<Vdev> {
        self.state.read().members.iter().map(|m| m.vdev.clone()).collect()
    }

    pub fn roots(&self) -> Vec<PathBuf> {
        self.state.read().members.iter().map(|m| m.vdev.root.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.state.read().members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn count(&self) -> u16 {
        self.state.read().count
    }

    pub fn is_online(&self, id: u16) -> bool {
        self.state.read().members.iter().any(|m| m.vdev.id == id)
    }

    pub fn root_of(&self, id: u16) -> Option<PathBuf> {
        self.state
            .read()
            .members
            .iter()
            .find(|m| m.vdev.id == id)
            .map(|m| m.vdev.root.clone())
    }

    /// Slots with no device online.
    pub fn missing(&self) -> Vec<u16> {
        let state = self.state.read();
        let present: HashSet<u16> = state.members.iter().map(|m| m.vdev.id).collect();
        (0..state.count).filter(|id| !present.contains(id)).collect()
    }

    /// Adds a device, growing the slot count if it takes a new slot. It
    /// starts out catching up; `finish_catch_up` ends that once the
    /// resilver that fills it has completed.
    pub(crate) fn attach(&self, member: Member) {
        let mut state = self.state.write();
        let id = member.vdev.id;
        state.count = state.count.max(id + 1);
        state.catching_up.insert(id);
        state.members.push(member);
        state.members.sort_by_key(|m| m.vdev.id);
    }

    pub(crate) fn finish_catch_up(&self, id: u16) {
        self.state.write().catching_up.remove(&id);
    }
}
