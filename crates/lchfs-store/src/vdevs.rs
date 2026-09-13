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
use std::sync::atomic::{AtomicU16, Ordering};

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
    /// Devices that failed an operation while online. Still owned -- their
    /// locks and rings are held -- but no writer fans out to them, no
    /// checkpoint advances their superblock, and reads do not try them.
    /// `rejoin` moves one back once it has been repaired and caught up.
    pub faulted: Vec<Member>,
    /// How many slots the pool has, whether or not each has a device here.
    pub count: u16,
    /// Slots an operator took offline on purpose. A faulted device is
    /// brought back automatically when it answers again; one taken
    /// offline is not -- `online` is the operator's to say.
    pub offlined: HashSet<u16>,
    /// Devices that are online for *writes* but whose superblock must not
    /// yet be advanced: a live attach in progress. Their generation stays
    /// behind until the resilver that fills them completes, so a crash
    /// mid-attach leaves a device the next mount knows to resilver rather
    /// than one that claims to be current.
    pub catching_up: HashSet<u16>,
}

pub struct VdevSet {
    state: RwLock<VdevSetState>,
    /// The slot whose copy of everything is read by default and which
    /// holds the mount's `INDEX.redb` (ARCHITECTURE.md §15.10): the lowest
    /// online slot at mount, and thereafter whatever `promote` last chose.
    /// An atomic because the read path asks for it per read and must not
    /// take a lock to learn it.
    primary: AtomicU16,
}

impl VdevSet {
    pub(crate) fn new(members: Vec<Member>, count: u16) -> Self {
        let primary = members.first().map(|m| m.vdev.id).unwrap_or(0);
        Self {
            state: RwLock::new(VdevSetState {
                members,
                faulted: Vec::new(),
                offlined: HashSet::new(),
                count,
                catching_up: HashSet::new(),
            }),
            primary: AtomicU16::new(primary),
        }
    }

    /// The current primary's slot.
    pub fn primary(&self) -> u16 {
        self.primary.load(Ordering::Acquire)
    }

    /// The current primary's root, if it is still online.
    pub fn primary_root(&self) -> Option<PathBuf> {
        self.root_of(self.primary())
    }

    /// True when the primary has faulted: the mount's index is on a device
    /// it can no longer use, and a promotion is due.
    pub fn primary_faulted(&self) -> bool {
        let primary = self.primary();
        self.state.read().faulted.iter().any(|m| m.vdev.id == primary)
    }

    /// Makes `id` the primary. The caller has already rebuilt the index
    /// on it; this only moves the role.
    pub(crate) fn promote(&self, id: u16) {
        self.primary.store(id, Ordering::Release);
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
        Self::from_vdevs(
            roots
                .iter()
                .enumerate()
                .map(|(i, r)| Vdev::new(i as u16, r.clone()))
                .collect(),
        )
    }

    /// `from_roots` with explicit slots.
    pub fn from_vdevs(vdevs: Vec<Vdev>) -> Self {
        let count = vdevs.iter().map(|v| v.id + 1).max().unwrap_or(0);
        let mut members: Vec<Member> = vdevs
            .into_iter()
            .map(|vdev| Member {
                vdev,
                superblock: None,
                _lock: None,
            })
            .collect();
        members.sort_by_key(|m| m.vdev.id);
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

    /// Slots whose device failed while online (a subset of `missing`).
    pub fn faulted(&self) -> Vec<u16> {
        self.state.read().faulted.iter().map(|m| m.vdev.id).collect()
    }

    /// One line per slot, for status output.
    pub fn status(&self) -> Vec<VdevStatus> {
        let state = self.state.read();
        (0..state.count)
            .map(|id| {
                let health = if state.members.iter().any(|m| m.vdev.id == id) {
                    if state.catching_up.contains(&id) {
                        VdevHealth::CatchingUp
                    } else {
                        VdevHealth::Online
                    }
                } else if state.faulted.iter().any(|m| m.vdev.id == id) {
                    VdevHealth::Faulted
                } else {
                    VdevHealth::Absent
                };
                let root = state
                    .members
                    .iter()
                    .chain(state.faulted.iter())
                    .find(|m| m.vdev.id == id)
                    .map(|m| m.vdev.root.clone());
                VdevStatus { id, health, root }
            })
            .collect()
    }

    /// A device failed an operation: it leaves the online set from now
    /// on. Idempotent -- every writer that trips over the same dead device
    /// reports it, and only the first report does anything. Returns
    /// whether this call was the one that changed state.
    pub fn fault(&self, id: u16) -> bool {
        let mut state = self.state.write();
        let Some(pos) = state.members.iter().position(|m| m.vdev.id == id) else {
            return false;
        };
        let member = state.members.remove(pos);
        state.catching_up.remove(&id);
        tracing::error!(
            "vdev {id} at {} FAULTED; the pool continues without it",
            member.vdev.root.display()
        );
        state.faulted.push(member);
        true
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

    /// Takes a faulted member back out of the set, for `online_vdev` to
    /// re-admit through `attach` once the device is known to work again.
    /// Clears any operator-offline mark: bringing it back is the decision.
    pub(crate) fn take_faulted(&self, id: u16) -> Option<Member> {
        let mut state = self.state.write();
        state.offlined.remove(&id);
        let pos = state.faulted.iter().position(|m| m.vdev.id == id)?;
        Some(state.faulted.remove(pos))
    }

    /// Marks a fault as the operator's doing, so automatic rejoin leaves
    /// the device alone.
    pub(crate) fn mark_offlined(&self, id: u16) {
        self.state.write().offlined.insert(id);
    }

    /// Faulted devices that were not taken offline on purpose, with their
    /// roots: what automatic rejoin probes.
    pub fn faulted_unintended(&self) -> Vec<Vdev> {
        let state = self.state.read();
        state
            .faulted
            .iter()
            .filter(|m| !state.offlined.contains(&m.vdev.id))
            .map(|m| m.vdev.clone())
            .collect()
    }

    /// Removes the last slot from the pool: the member (online or
    /// faulted) is dropped, releasing its lock and ring, and the count
    /// shrinks by one. The caller has proven the survivors complete and
    /// rolls the writers afterwards.
    pub(crate) fn detach_last(&self) -> Option<Member> {
        let mut state = self.state.write();
        let id = state.count.checked_sub(1)?;
        let member = match state.members.iter().position(|m| m.vdev.id == id) {
            Some(pos) => Some(state.members.remove(pos)),
            None => state
                .faulted
                .iter()
                .position(|m| m.vdev.id == id)
                .map(|pos| state.faulted.remove(pos)),
        };
        state.catching_up.remove(&id);
        state.offlined.remove(&id);
        state.count = id;
        member
    }

    pub(crate) fn finish_catch_up(&self, id: u16) {
        self.state.write().catching_up.remove(&id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdevHealth {
    Online,
    /// Online for writes, being filled by a resilver; superblock not yet
    /// advanced.
    CatchingUp,
    /// Failed while online; owned but not used.
    Faulted,
    /// No device for this slot in this mount.
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VdevStatus {
    pub id: u16,
    pub health: VdevHealth,
    pub root: Option<PathBuf>,
}
