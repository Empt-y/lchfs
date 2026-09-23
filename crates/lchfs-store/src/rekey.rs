//! In-place conversion and key rotation (ARCHITECTURE.md §18): rewriting a
//! pool's content into a new key epoch while it stays mounted and in use,
//! then *retiring* the old epoch -- its records and, for a rotation, its
//! key -- from every device.
//!
//! One mechanism serves both. Converting a plaintext pool is re-keying it
//! from epoch 0 (plaintext) to epoch 1; rotating is re-keying from the
//! current epoch to a new one. The keyring records which phase the pool is
//! in (`Conversion`), so a crash at any point resumes on the next mount:
//!
//! - **Rewriting.** New writes already go to the target epoch (the swap in
//!   `start_*`). This phase moves everything else there: every live file's
//!   chunks, every directory, every retained snapshot's whole tree. It ends
//!   when a walk from every published root finds nothing reachable outside
//!   the target epoch.
//! - **Retiring.** Nothing reachable is old any more, so the old epoch's
//!   records are garbage -- but garbage that still says what the pool held.
//!   This phase removes it everywhere: data segments (a forced repack),
//!   meta segments (epoch compaction, which meta has never needed before),
//!   delta segments (truncation), the index file (rewritten fresh, since a
//!   B-tree keeps freed pages' bytes), and the superblock ring. Only then
//!   is `min_epoch` raised and, for a rotation, the old key destroyed.
//!
//! Every step is idempotent: each decides what to do from what is on disk
//! (record epochs are in the clear, in the outer header), never from a
//! memory of having started.

use super::*;
use lchfs_crypto::keyring::{Conversion, ConversionPhase};
use std::collections::BTreeMap;

/// Chunks rewritten per inode-lock hold: long enough to amortize the lock,
/// short enough that a writer to the same file waits at most this many
/// chunk rewrites.
const FILE_BATCH: usize = 256;
/// A snapshot being rewritten publishes its progress every this many
/// inodes: the pins its new chunks hold until then are bounded by it, and
/// a crash loses at most this much work.
const STAGING_EVERY: usize = 4096;
/// ...or once this many chunk pins are waiting on a publish, whichever
/// comes first.
const LEDGER_MAX: usize = 1 << 16;
/// How many superblock slots a checkpoint cycles through (§1). Retirement
/// ends with this many checkpoints, so no slot still names a root from
/// before it.
const SUPERBLOCK_RING: usize = 16;

/// What a conversion has done so far, for `Pool::conversion_status`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Progress {
    pub passes: u64,
    pub files_total: u64,
    pub files_done: u64,
    pub chunks_rewritten: u64,
    pub bytes_rewritten: u64,
    pub snapshots_total: u64,
    pub snapshots_done: u64,
    /// Segments still holding records of another epoch, from the last
    /// retirement census.
    pub old_segments: Census,
    /// Devices retirement is waiting for: an absent device still holds
    /// the old epoch's records, so retirement cannot finish without it.
    pub waiting_for_vdevs: Vec<u16>,
    pub last_error: Option<String>,
}

/// Segments, per stream, holding any record of an epoch other than the
/// target. Counted from outer headers alone -- no key needed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct Census {
    pub data: u64,
    pub meta: u64,
    pub delta: u64,
    pub stripes: u64,
}

impl Census {
    pub fn total(&self) -> u64 {
        self.data + self.meta + self.delta + self.stripes
    }
}

/// A pool's conversion, as `Pool::conversion_status` reports it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConversionStatus {
    pub encrypted: bool,
    pub current_epoch: u16,
    pub min_epoch: u16,
    /// `None` when no conversion is running.
    pub target_epoch: Option<u16>,
    pub phase: Option<String>,
    pub progress: Progress,
}

/// Where a file's authoritative chunk list lives right now -- the same
/// precedence `read` and the checkpoint use.
enum Source {
    Session,
    FileState,
    Content(Hash32),
}

impl PoolShared {
    fn conversion(&self) -> Option<Conversion> {
        self.keyring.lock().as_ref().and_then(|s| s.ring.config().conversion)
    }

    fn cancelled(&self) -> bool {
        self.conversion_cancel.load(Ordering::Acquire)
    }

    /// Writes `ring` as the pool's keyring to every online device and
    /// makes it the mount's; fails, changing nothing, if no device took it.
    fn commit_keyring(&self, state: &mut Option<KeyringState>, mut ring: UnlockedKeyring) -> Result<(), PoolError> {
        let file = ring.to_file();
        let roots: Vec<PathBuf> = self.vdevs.online().into_iter().map(|v| v.root).collect();
        let refs: Vec<&Path> = roots.iter().map(|r| r.as_path()).collect();
        let failed = keyring::write_all(&refs, &file);
        if failed.len() == refs.len() {
            let detail = failed.first().map(|(r, e)| format!("{}: {e}", r.display())).unwrap_or_default();
            return Err(PoolError::Format(format!("the keyring could not be written to any device ({detail})")));
        }
        for (root, e) in failed {
            tracing::warn!("keyring not written to {} ({e}); the next mount repairs it", root.display());
        }
        self.crypto.store(Arc::new(crypto::from_keyring(&ring)));
        *state = Some(KeyringState { ring, file });
        Ok(())
    }

    /// Encrypts a plaintext pool in place: a keyring with `setup`'s slots
    /// and epoch 1 current. From the moment this returns every new record
    /// is sealed; the conversion task rewrites the rest. The keyring is on
    /// disk before any write uses the new epoch, so a crash here leaves
    /// either a plaintext pool or one mid-conversion, never sealed records
    /// nothing can open.
    pub(crate) fn start_encrypt(&self, setup: EncryptionSetup<'_>) -> Result<(), PoolError> {
        let mut guard = self.keyring.lock();
        if guard.is_some() {
            return Err(PoolError::InvalidArgument(
                "the pool is already encrypted; rotate its key with `pool rekey`".into(),
            ));
        }
        // A TPM slot may not be the only one, and the keyring checks that
        // against its first slot: put a non-TPM slot first.
        let mut slots = setup.slots;
        slots.sort_by_key(|s| matches!(s, NewSlot::Tpm { .. }));
        let mut slots = slots.into_iter();
        let first = slots
            .next()
            .ok_or_else(|| PoolError::InvalidArgument("encrypting a pool needs at least one key slot".into()))?;
        let mut ring = UnlockedKeyring::create_for_conversion(self.pool_uuid, setup.padding, first)?;
        for slot in slots {
            ring.add_slot(slot)?;
        }
        let target = ring
            .config()
            .conversion
            .map(|c| c.target_epoch)
            .expect("create_for_conversion records its target");
        ring.config_mut().current_epoch = target;
        *self.conversion_progress.lock() = Progress::default();
        self.commit_keyring(&mut guard, ring)?;
        tracing::info!("encryption started: new writes are sealed; existing content is being rewritten");
        Ok(())
    }

    /// Rotates an encrypted pool's content key: a new epoch, current from
    /// now on, and everything rewritten into it and the old one retired.
    pub(crate) fn start_rekey(&self) -> Result<u16, PoolError> {
        let mut guard = self.keyring.lock();
        let Some(state) = guard.as_ref() else {
            return Err(PoolError::InvalidArgument("the pool is not encrypted; use `pool encrypt`".into()));
        };
        if let Some(c) = state.ring.config().conversion {
            return Err(PoolError::InvalidArgument(format!(
                "a conversion to epoch {} is already running",
                c.target_epoch
            )));
        }
        let mut ring = state.ring.clone();
        let target = ring.add_epoch()?;
        ring.config_mut().current_epoch = target;
        ring.config_mut().conversion = Some(Conversion {
            target_epoch: target,
            phase: ConversionPhase::Rewriting,
        });
        *self.conversion_progress.lock() = Progress::default();
        self.commit_keyring(&mut guard, ring)?;
        tracing::info!("key rotation to epoch {target} started");
        Ok(target)
    }

    fn set_phase(&self, target: u16, phase: ConversionPhase) -> Result<(), PoolError> {
        let mut guard = self.keyring.lock();
        let Some(state) = guard.as_ref() else { return Ok(()) };
        let mut ring = state.ring.clone();
        ring.config_mut().conversion = Some(Conversion { target_epoch: target, phase });
        self.commit_keyring(&mut guard, ring)
    }

    pub(crate) fn conversion_status(&self) -> ConversionStatus {
        let config = self.keyring_config_now();
        let progress = self.conversion_progress.lock().clone();
        match config {
            None => ConversionStatus {
                encrypted: false,
                current_epoch: 0,
                min_epoch: 0,
                target_epoch: None,
                phase: None,
                progress,
            },
            Some(c) => ConversionStatus {
                encrypted: true,
                current_epoch: c.current_epoch,
                min_epoch: c.min_epoch,
                target_epoch: c.conversion.map(|v| v.target_epoch),
                phase: c.conversion.map(|v| format!("{:?}", v.phase)),
                progress,
            },
        }
    }

    fn keyring_config_now(&self) -> Option<lchfs_crypto::keyring::KeyringConfig> {
        self.keyring.lock().as_ref().map(|s| *s.ring.config())
    }

    /// One step of whatever conversion the keyring records: a rewriting
    /// pass, or a retirement attempt. `Ok(false)` when there is none. The
    /// background task calls this every tick and skips when a caller is
    /// already driving one.
    pub(crate) fn conversion_step(&self) -> Result<bool, PoolError> {
        let Some(_one) = self.conversion_lock.try_lock() else {
            return Ok(true);
        };
        self.conversion_step_locked()
    }

    pub(crate) fn conversion_step_locked(&self) -> Result<bool, PoolError> {
        let Some(c) = self.conversion() else {
            return Ok(false);
        };
        match c.phase {
            ConversionPhase::Rewriting => self.rewrite_pass(c.target_epoch)?,
            ConversionPhase::Retiring => self.retire_pass(c.target_epoch)?,
        }
        Ok(true)
    }

    /// Drives the running conversion to its end, synchronously -- what an
    /// offline `pool encrypt`/`pool rekey` and the tests use. Fails if
    /// retirement is waiting for a device that is not here.
    pub(crate) fn run_conversion_to_completion(&self) -> Result<(), PoolError> {
        let _one = self.conversion_lock.lock();
        for _ in 0..200 {
            if self.cancelled() {
                return Err(PoolError::Format("conversion cancelled by shutdown".into()));
            }
            if !self.conversion_step_locked()? {
                return Ok(());
            }
            let waiting = self.conversion_progress.lock().waiting_for_vdevs.clone();
            if !waiting.is_empty() {
                return Err(PoolError::InvalidArgument(format!(
                    "retirement is waiting for vdevs {waiting:?}: they still hold the old epoch's records"
                )));
            }
        }
        Err(PoolError::Format("conversion did not finish after 200 steps".into()))
    }

    // ---------------------------------------------------------------
    // Rewriting
    // ---------------------------------------------------------------

    fn rewrite_pass(&self, target: u16) -> Result<(), PoolError> {
        self.conversion_progress.lock().passes += 1;

        // Directories re-seal when the checkpoint re-puts them, which it
        // does for dirty ones. Inodes themselves (and with them inline
        // content, symlink targets and xattrs), the InoMap and the root are
        // re-put by every checkpoint already.
        {
            let mut namespace = self.namespace.lock();
            let dirs: Vec<u64> = namespace
                .inodes
                .iter()
                .filter(|(_, i)| i.kind == InodeKind::Directory)
                .map(|(&ino, _)| ino)
                .collect();
            namespace.dirty_inodes.extend(dirs);
        }

        let mut files: Vec<u64> = {
            let namespace = self.namespace.lock();
            namespace
                .inodes
                .iter()
                .filter(|(_, i)| i.kind == InodeKind::File)
                .map(|(&ino, _)| ino)
                .collect()
        };
        files.sort_unstable();
        {
            let mut p = self.conversion_progress.lock();
            p.files_total = files.len() as u64;
            p.files_done = 0;
        }
        for ino in files {
            if self.cancelled() {
                return Ok(());
            }
            self.rekey_file(ino, target)?;
            self.conversion_progress.lock().files_done += 1;
        }

        self.rekey_snapshots(target)?;
        if self.cancelled() {
            return Ok(());
        }

        // The SnapshotTable is re-put only when it changes; make sure the
        // one the live root names is in the target epoch too.
        {
            let _table = self.snapshot_lock.lock();
            let table_hash = self.namespace.lock().snapshot_table_hash;
            if let Some(h) = table_hash
                && self.epoch_of(h, StreamKind::Meta)? != target
            {
                let table = self.current_snapshot_table()?;
                self.publish_snapshot_table(&table)?;
            }
        }

        // Two checkpoints: the first captures every inode this pass
        // dirtied; the second publishes past anything that raced it.
        self.run_checkpoint()?;
        self.run_checkpoint()?;

        let remaining = self.unconverted_reachable(target)?;
        if remaining == 0 {
            tracing::info!("conversion: everything reachable is in epoch {target}; retiring older epochs");
            self.set_phase(target, ConversionPhase::Retiring)?;
        } else {
            tracing::info!("conversion: {remaining} reachable record(s) still outside epoch {target}; another pass");
        }
        Ok(())
    }

    /// The epoch of the record `hash` resolves to, from its outer header.
    fn epoch_of(&self, hash: Hash32, stream: StreamKind) -> Result<u16, PoolError> {
        let (loc, vdev_id) = self
            .dedup_index
            .get_tagged(hash)
            .ok_or_else(|| PoolError::Format(format!("conversion: {hash:?} is not in the index")))?;
        if vdev_id == stripe::STRIPED {
            let reader = self.stripe_reader(loc.segment_id)?;
            let (header, _) = reader.read_record_raw_with(loc, &self.crypto.load())?;
            return Ok(lchfs_format::record_epoch(&header));
        }
        let reader = self
            .readers
            .get_or_open(vdev_id, loc.segment_id, stream, || self.vdev_root(vdev_id))?;
        let (header, _) = reader
            .scan_next(loc.offset)
            .ok_or_else(|| PoolError::Format(format!("conversion: no record at {loc:?}")))?;
        Ok(lchfs_format::record_epoch(&header))
    }

    /// Moves one live file's chunks into `target`, a batch at a time under
    /// its inode lock -- whichever of its open session, `file_state` or
    /// ContentRef holds its chunk list.
    fn rekey_file(&self, ino: u64, target: u16) -> Result<(), PoolError> {
        loop {
            if self.cancelled() {
                return Ok(());
            }
            let ino_lock = self.lock_for_ino(ino);
            let _guard = ino_lock.lock();
            let content = {
                let namespace = self.namespace.lock();
                match namespace.inodes.get(&ino) {
                    Some(inode) if inode.kind == InodeKind::File => inode.content.clone(),
                    _ => return Ok(()),
                }
            };
            let session = self.open_files.shard(ino).get(&ino).map(|s| s.chunks.clone());
            let (source, refs) = match session {
                Some(chunks) => (Source::Session, chunks),
                None => match self.file_state.lock().get(&ino).map(|s| s.chunks.clone()) {
                    Some(chunks) => (Source::FileState, chunks),
                    None => match content {
                        ContentRef::ChunkList(ihl) => {
                            let bytes = self.read_meta_object_bytes(ihl, Some(ino))?;
                            let list: IndirectHashList =
                                lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))?;
                            (Source::Content(ihl), list.chunks)
                        }
                        // Inline content and nothing else: re-sealed with
                        // the InodeObject at the next checkpoint.
                        _ => return Ok(()),
                    },
                },
            };

            let mut todo = Vec::new();
            for (i, r) in refs.iter().enumerate() {
                if self.epoch_of(r.content_hash, StreamKind::Data)? != target {
                    todo.push(i);
                    if todo.len() == FILE_BATCH {
                        break;
                    }
                }
            }
            let list_is_old = match source {
                Source::Content(ihl) => self.epoch_of(ihl, StreamKind::Meta)? != target,
                _ => false,
            };
            if todo.is_empty() && !list_is_old {
                return Ok(());
            }

            // Before any chunk this commits exists: the next checkpoint
            // must capture the file, or the new chunks look like garbage.
            self.mark_dirty_before_commit(ino);
            let mut new_refs = refs.clone();
            for &i in &todo {
                new_refs[i] = self.rekey_chunk(ino, refs[i], None)?;
            }
            match source {
                Source::Session => {
                    if let Some(s) = self.open_files.shard(ino).get_mut(&ino) {
                        for &i in &todo {
                            if s.chunks.get(i) == Some(&refs[i]) {
                                s.chunks[i] = new_refs[i];
                            }
                        }
                    }
                }
                Source::FileState => {
                    if let Some(s) = self.file_state.lock().get_mut(&ino) {
                        for &i in &todo {
                            if s.chunks.get(i) == Some(&refs[i]) {
                                s.chunks[i] = new_refs[i];
                            }
                        }
                    }
                }
                Source::Content(old_ihl) => {
                    let (new_ihl, _) =
                        self.put_meta_object(ExtentKind::IndirectHashList, &IndirectHashList { chunks: new_refs })?;
                    let mut namespace = self.namespace.lock();
                    if let Some(inode) = namespace.inodes.get_mut(&ino)
                        && inode.content == ContentRef::ChunkList(old_ihl)
                    {
                        inode.content = ContentRef::ChunkList(new_ihl);
                    }
                    namespace.dirty_inodes.insert(ino);
                }
            }
        }
    }

    /// The chunk `r` in `target`: found again through the memo if it has
    /// been rewritten before, else read (verified, in its own epoch) and
    /// committed afresh, which addresses and seals it in the current one.
    ///
    /// Every hash this returns is pinned until something publishes a root
    /// that reaches it: into the file's `pins_by_ino` (released by the
    /// checkpoint that captures the file), or into `ledger` for a snapshot
    /// rewrite (released by the publish of its staging root).
    fn rekey_chunk(&self, ino: u64, r: ChunkRef, ledger: Option<&mut Vec<Hash32>>) -> Result<ChunkRef, PoolError> {
        let old = r.content_hash;
        let memo = self.persisted_index.read().get_rekey_memo(old)?;
        if let Some(new) = memo {
            // Pin, then look: the same order `prepare_chunk` keeps against
            // coalesce's remove-then-check-pins, so a hit here cannot be a
            // record the sweep is deleting.
            self.dedup_pins.pin(new);
            if self.dedup_index.get(new).is_some() {
                match ledger {
                    Some(l) => l.push(new),
                    None => self.pins_by_ino.shard(ino).entry(ino).or_default().push(new),
                }
                return Ok(ChunkRef { content_hash: new, ..r });
            }
            self.dedup_pins.unpin(new);
        }
        let bytes = self.read_chunk_bytes(old, Some(ino))?;
        let new = match ledger {
            None => self.commit_chunk(ino, r.logical_offset, &bytes)?.0,
            Some(l) => self.commit_chunk_pinned(ino, r.logical_offset, &bytes, l)?,
        };
        self.persisted_index.write().put_rekey_memo(old, new)?;
        {
            let mut p = self.conversion_progress.lock();
            p.chunks_rewritten += 1;
            p.bytes_rewritten += bytes.len() as u64;
        }
        self.throttle(bytes.len() as u64);
        Ok(ChunkRef { content_hash: new, ..r })
    }

    /// `commit_chunk` whose result is pinned into `ledger` whether it was a
    /// dedup hit (pinned by the lookup, as always) or a fresh record (pinned
    /// here). A snapshot's rewritten chunk is reachable only once its
    /// staging root is published, which can be several checkpoints away --
    /// past the grace a freshly sealed segment gets.
    fn commit_chunk_pinned(&self, ino: u64, offset: u64, raw: &[u8], ledger: &mut Vec<Hash32>) -> Result<Hash32, PoolError> {
        let prepared = self.prep_pool.submit(PrepTask {
            inode_id: ino,
            logical_offset: offset,
            raw_bytes: Bytes::copy_from_slice(raw),
        });
        match prepared {
            PreparedChunk::Dedup { content_hash, .. } => {
                ledger.push(content_hash);
                Ok(content_hash)
            }
            PreparedChunk::New {
                content_hash,
                codec_id,
                uncompressed_len,
                payload,
                sealed,
            } => {
                let (tx, rx) = crossbeam::channel::bounded(1);
                self.committer_pool.push(IngressOp {
                    inode_id: ino,
                    content_hash,
                    codec_id,
                    uncompressed_len,
                    payload,
                    sealed,
                    logical_offset: offset,
                    completion: tx,
                });
                rx.recv()
                    .map_err(|_| PoolError::Format("committer pool completion channel closed".into()))??;
                self.dedup_pins.pin(content_hash);
                ledger.push(content_hash);
                Ok(content_hash)
            }
        }
    }

    fn release_ledger(&self, ledger: &mut Vec<Hash32>) {
        for h in ledger.drain(..) {
            self.dedup_pins.unpin(h);
        }
    }

    fn throttle(&self, bytes: u64) {
        if let Some(rate) = *self.conversion_rate.lock()
            && rate > 0
        {
            std::thread::sleep(Duration::from_secs_f64(bytes as f64 / rate as f64));
        }
    }

    /// Rewrites every retained snapshot's tree into `target`.
    fn rekey_snapshots(&self, target: u16) -> Result<(), PoolError> {
        let table = self.current_snapshot_table()?;
        let names: Vec<String> = table
            .entries
            .iter()
            .filter(|e| !e.name.starts_with(RESERVED_SNAPSHOT_PREFIX))
            .map(|e| e.name.clone())
            .collect();
        {
            let mut p = self.conversion_progress.lock();
            p.snapshots_total = names.len() as u64;
            p.snapshots_done = 0;
        }
        for name in names {
            if self.cancelled() {
                return Ok(());
            }
            self.rekey_snapshot(&name, target)?;
            self.conversion_progress.lock().snapshots_done += 1;
        }
        Ok(())
    }

    fn rekey_snapshot(&self, name: &str, target: u16) -> Result<(), PoolError> {
        let staging_name = format!("{RESERVED_SNAPSHOT_PREFIX}{name}");
        let (entry, staging) = {
            let table = self.current_snapshot_table()?;
            let Some(entry) = table.entries.iter().find(|e| e.name == name).cloned() else {
                return Ok(());
            };
            (entry, table.entries.iter().find(|e| e.name == staging_name).cloned())
        };
        if self.epoch_of(entry.root_hash, StreamKind::Meta)? == target {
            return Ok(());
        }
        let root: RootObject = self.decode_meta(entry.root_hash)?;
        let inomap: InoMap = self.decode_meta(root.inomap_hash)?;
        let mut done: BTreeMap<u64, Hash32> = BTreeMap::new();
        if let Some(staging) = &staging {
            let staged: RootObject = self.decode_meta(staging.root_hash)?;
            let staged_map: InoMap = self.decode_meta(staged.inomap_hash)?;
            done.extend(staged_map.entries.iter().map(|e| (e.ino, e.current_object_hash)));
        }
        let table_hash = self.rekey_meta(root.snapshot_table_hash, ExtentKind::SnapshotTable, target)?;

        let mut ledger = Vec::new();
        let result = (|| {
            let mut since_publish = 0;
            for e in &inomap.entries {
                if done.contains_key(&e.ino) {
                    continue;
                }
                if self.cancelled() {
                    return Ok(());
                }
                let new = self.rekey_inode(e.current_object_hash, e.ino, target, &mut ledger)?;
                done.insert(e.ino, new);
                since_publish += 1;
                if since_publish >= STAGING_EVERY || ledger.len() >= LEDGER_MAX {
                    let staged_root = self.put_partial_root(&root, &done, table_hash)?;
                    if !self.replace_snapshot_entry(name, &staging_name, staged_root, &entry, false)? {
                        return Ok(());
                    }
                    self.release_ledger(&mut ledger);
                    since_publish = 0;
                }
            }
            let new_root = self.put_partial_root(&root, &done, table_hash)?;
            self.replace_snapshot_entry(name, &staging_name, new_root, &entry, true)?;
            Ok(())
        })();
        // Whatever was published is reachable; whatever was not is only
        // work lost, redone (mostly from the memo) by the next pass.
        self.release_ledger(&mut ledger);
        result
    }

    /// A RootObject like `root` whose InoMap is exactly `entries`.
    fn put_partial_root(&self, root: &RootObject, entries: &BTreeMap<u64, Hash32>, table_hash: Hash32) -> Result<Hash32, PoolError> {
        let inomap = InoMap {
            entries: entries
                .iter()
                .map(|(&ino, &h)| InoMapEntry { ino, current_object_hash: h })
                .collect(),
        };
        let (inomap_hash, _) = self.put_meta_object(ExtentKind::IndirectHashList, &inomap)?;
        let new_root = RootObject {
            inomap_hash,
            snapshot_table_hash: table_hash,
            ..root.clone()
        };
        Ok(self.put_meta_object(ExtentKind::RootObject, &new_root)?.0)
    }

    /// Publishes progress on snapshot `name`: as its hidden staging entry
    /// (`finished = false`), or, when done, as the snapshot itself with the
    /// staging entry gone. If the user deleted the snapshot meanwhile, the
    /// staging entry is dropped and `false` returned.
    fn replace_snapshot_entry(
        &self,
        name: &str,
        staging_name: &str,
        root_hash: Hash32,
        original: &SnapshotEntry,
        finished: bool,
    ) -> Result<bool, PoolError> {
        let _table = self.snapshot_lock.lock();
        let mut table = self.current_snapshot_table()?;
        let still_there = table.entries.iter().any(|e| e.name == name);
        table.entries.retain(|e| e.name != staging_name);
        if still_there {
            if finished {
                if let Some(e) = table.entries.iter_mut().find(|e| e.name == name) {
                    e.root_hash = root_hash;
                }
            } else {
                table.entries.push(SnapshotEntry {
                    name: staging_name.to_string(),
                    root_hash,
                    created_at_unix_nanos: original.created_at_unix_nanos,
                    epoch: original.epoch,
                });
            }
        }
        self.publish_snapshot_table(&table)?;
        Ok(still_there)
    }

    fn decode_meta<T: serde::de::DeserializeOwned>(&self, hash: Hash32) -> Result<T, PoolError> {
        let bytes = self.read_meta_object_bytes(hash, None)?;
        lchfs_format::decode(&bytes).map_err(|e| PoolError::Format(e.to_string()))
    }

    /// A meta object with no hashes of its own to rewrite, moved into
    /// `target` byte for byte.
    fn rekey_meta(&self, hash: Hash32, kind: ExtentKind, target: u16) -> Result<Hash32, PoolError> {
        if self.epoch_of(hash, StreamKind::Meta)? == target {
            return Ok(hash);
        }
        let bytes = self.read_meta_object_bytes(hash, None)?;
        Ok(self.put_meta_encoded(kind, &bytes)?.0)
    }

    /// One snapshot inode, with its content, in `target`.
    fn rekey_inode(&self, hash: Hash32, ino: u64, target: u16, ledger: &mut Vec<Hash32>) -> Result<Hash32, PoolError> {
        if self.epoch_of(hash, StreamKind::Meta)? == target {
            return Ok(hash);
        }
        // Meta records are never reclaimed while a conversion runs (only
        // retirement compacts them, after it), so a memo'd meta object
        // needs no pin -- only to still be indexed.
        if let Some(new) = self.persisted_index.read().get_rekey_memo(hash)?
            && self.dedup_index.get(new).is_some()
        {
            return Ok(new);
        }
        let mut inode: InodeObject = self.decode_meta(hash)?;
        match inode.content.clone() {
            ContentRef::DirEntries(d) => {
                inode.content = ContentRef::DirEntries(self.rekey_meta(d, ExtentKind::DirectoryObject, target)?);
            }
            ContentRef::ChunkList(ihl) => {
                let list: IndirectHashList = self.decode_meta(ihl)?;
                let mut chunks = Vec::with_capacity(list.chunks.len());
                for r in list.chunks {
                    if self.epoch_of(r.content_hash, StreamKind::Data)? == target {
                        chunks.push(r);
                    } else {
                        chunks.push(self.rekey_chunk(ino, r, Some(ledger))?);
                    }
                }
                let (new_ihl, _) = self.put_meta_object(ExtentKind::IndirectHashList, &IndirectHashList { chunks })?;
                inode.content = ContentRef::ChunkList(new_ihl);
            }
            ContentRef::Inline(_) | ContentRef::SymlinkTarget(_) => {}
        }
        let (new, _) = self.put_meta_object(ExtentKind::InodeObject, &inode)?;
        self.persisted_index.write().put_rekey_memo(hash, new)?;
        Ok(new)
    }

    /// Published roots: the live one and every snapshot table entry's.
    fn published_roots(&self) -> Result<Vec<Hash32>, PoolError> {
        let mut roots = vec![self.namespace.lock().root_hash];
        roots.extend(self.current_snapshot_table()?.entries.iter().map(|e| e.root_hash));
        Ok(roots)
    }

    /// How many records reachable from a published root are outside
    /// `target` -- the completion check. Marks the way GC does, then reads
    /// each marked record's outer header, a segment at a time.
    fn unconverted_reachable(&self, target: u16) -> Result<u64, PoolError> {
        let roots = self.published_roots()?;
        let live = self.coalesce.lock().mark(&roots);
        if live.is_empty() {
            return Err(PoolError::Format("conversion: the completion walk could not mark the pool".into()));
        }
        let primary = self.primary();
        let root = self.vdev_root(primary)?;
        let mut outside = 0u64;
        let mut checked: HashSet<u64> = HashSet::new();
        for (&segment_id, bitmap) in &live.by_segment {
            let Ok(reader) = SegmentReader::open_either(&root, segment_id, StreamKind::Meta) else {
                continue;
            };
            checked.insert(segment_id);
            for (header, offset) in reader.scan() {
                if bitmap.contains(offset) && lchfs_format::record_epoch(&header) != target {
                    outside += 1;
                }
            }
        }
        // Striped records have no segment file on the primary.
        for &hash in &live.hashes {
            if let Some((loc, vdev)) = self.dedup_index.get_tagged(hash)
                && vdev == stripe::STRIPED
                && !checked.contains(&loc.segment_id)
                && self.epoch_of(hash, StreamKind::Data)? != target
            {
                outside += 1;
            }
        }
        Ok(outside)
    }

    // ---------------------------------------------------------------
    // Retiring
    // ---------------------------------------------------------------

    fn retire_pass(&self, target: u16) -> Result<(), PoolError> {
        // An absent or faulted device still holds the old epoch's records,
        // and nothing here can reach it.
        let mut waiting: Vec<u16> = self.vdevs.missing();
        waiting.extend(self.vdevs.faulted());
        waiting.sort_unstable();
        waiting.dedup();
        self.conversion_progress.lock().waiting_for_vdevs = waiting.clone();
        if !waiting.is_empty() {
            tracing::info!("retirement waits for vdevs {waiting:?}");
            return Ok(());
        }

        // 1. Every open segment may hold old records: start fresh ones. The
        // device set holds still meanwhile.
        {
            let _devices = self.attach_lock.lock();
            self.committer_pool.roll_all_writers()?;
            self.close_meta_writer(&mut self.meta_writer.lock())?;
            for log in &self.shard_delta_logs {
                log.lock().roll_over()?;
            }
            self.seal_heal_writers()?;
        }
        // 2. Two checkpoints: every rolled data segment is past the seal
        // gate, and every shard's published watermark is past every entry
        // in its rolled delta segments.
        self.run_checkpoint()?;
        self.run_checkpoint()?;
        if self.cancelled() {
            return Ok(());
        }

        // 3. Data and stripes. Under the checkpoint lock, so the generation
        // the mark was taken at holds for the whole repack and no segment
        // is skipped by `forget_dead`'s freshness gate.
        for _ in 0..8 {
            let held_back = {
                let mut coalesce = self.coalesce.lock();
                let _checkpoints = self.checkpoint_lock.lock();
                let roots = self.published_roots()?;
                let live = coalesce.mark(&roots);
                if live.is_empty() {
                    return Err(PoolError::Format("retirement: the mark pass failed".into()));
                }
                let generation = self.published_generation.load(Ordering::Acquire);
                let held = coalesce.retire_data(
                    &live,
                    target,
                    generation,
                    &self.published_generation,
                    &self.persisted_index,
                    &self.next_segment_id,
                );
                for segment_id in coalesce.take_removed_segments() {
                    self.readers.evict_segment(segment_id);
                }
                held?
            };
            if held_back == 0 {
                break;
            }
            self.run_checkpoint()?;
            self.run_checkpoint()?;
        }

        // 4. Meta.
        self.compact_meta(target)?;
        // 5. Delta logs (the checkpoints above put both published
        // watermarks past every rolled segment).
        self.truncate_delta_logs()?;

        // 6. What is left, by header alone -- on *every* device. The device
        // set is re-checked here, not trusted from the start of the pass: a
        // device that faulted part-way missed the repacks above, and a
        // census of the others would call the pool clean while it still
        // holds the old epoch. From here to the end no device can rejoin
        // (that takes the attach lock), and one that faults now was clean
        // when counted and takes no writes while it is out.
        let _devices = self.attach_lock.lock();
        let mut waiting: Vec<u16> = self.vdevs.missing();
        waiting.extend(self.vdevs.faulted());
        waiting.sort_unstable();
        waiting.dedup();
        if !waiting.is_empty() {
            self.conversion_progress.lock().waiting_for_vdevs = waiting;
            return Ok(());
        }
        let census = self.old_epoch_census(target)?;
        self.conversion_progress.lock().old_segments = census;
        if census.total() > 0 {
            tracing::info!("retirement: {census:?} segment(s) still hold another epoch's records; retrying");
            return Ok(());
        }

        // 7. The index file, rewritten without the old epoch's freed pages.
        {
            let _checkpoints = self.checkpoint_lock.lock();
            self.committer_pool.flush_index()?;
            self.persisted_index.write().rewrite_fresh(&index_path(&self.pool_root))?;
        }
        // 8. Every superblock slot re-written, so none names a root whose
        // segments retirement deleted.
        for _ in 0..SUPERBLOCK_RING {
            self.run_checkpoint()?;
        }
        self.finish_conversion(target)
    }

    /// The end: records below `target` are refused from now on (one
    /// turning up is a downgrade, not data), and every older epoch's key is
    /// destroyed.
    fn finish_conversion(&self, target: u16) -> Result<(), PoolError> {
        let mut guard = self.keyring.lock();
        let Some(state) = guard.as_ref() else { return Ok(()) };
        let mut ring = state.ring.clone();
        ring.config_mut().min_epoch = target;
        ring.config_mut().conversion = None;
        for epoch in ring.epochs() {
            if epoch < target {
                ring.drop_epoch(epoch)?;
            }
        }
        self.commit_keyring(&mut guard, ring)?;
        drop(guard);
        let mut p = self.conversion_progress.lock();
        p.waiting_for_vdevs.clear();
        p.old_segments = Census::default();
        tracing::info!("conversion complete: epoch {target} only; older records and keys are gone");
        Ok(())
    }

    /// Meta epoch compaction. Meta segments were never reclaimed before --
    /// `put_meta_object` reuses any meta hit without a pin because of it --
    /// so this runs under the checkpoint lock throughout, and deletes
    /// nothing until two checkpoints have been published from the copies:
    ///
    /// 1. every distinct record of `target` in a candidate segment is copied
    ///    forward verbatim, once, through the fan-out meta writer (so every
    ///    online device gets it), fsynced, and repointed in the cache and
    ///    the index;
    /// 2. two checkpoints. The superblock's `root_location` is the one place
    ///    a meta *location* (not a hash) is kept, and a checkpoint that
    ///    changes nothing re-puts a byte-identical root -- a dedup hit on
    ///    whatever the cache holds. After step 1 that is the copy, so both
    ///    of the newest superblock slots name roots outside every candidate;
    /// 3. the old epoch's records are forgotten, and the candidates deleted.
    fn compact_meta(&self, target: u16) -> Result<(), PoolError> {
        let _coalesce = self.coalesce.lock();
        let held = self.checkpoint_lock.lock();
        self.close_meta_writer(&mut self.meta_writer.lock())?;
        self.seal_heal_writers()?;
        let before = self.next_segment_id.load(Ordering::Acquire);

        let online = self.vdevs.online();
        let mut candidates: Vec<(Vdev, u64)> = Vec::new();
        for vdev in &online {
            for id in segment::segment_ids_on(&vdev.root, StreamKind::Meta) {
                if id >= before {
                    continue;
                }
                let Ok(reader) = SegmentReader::open(&vdev.root, id, StreamKind::Meta) else { continue };
                if coalesce::holds_other_epoch(&reader, target) {
                    candidates.push((vdev.clone(), id));
                }
            }
        }
        if candidates.is_empty() {
            return Ok(());
        }
        let doomed: HashSet<(u16, u64)> = candidates.iter().map(|(v, id)| (v.id, *id)).collect();

        let crypto = self.crypto.load();
        let mut copied: HashSet<Hash32> = HashSet::new();
        // The devices every copy reached. A device the fan-out writer lost
        // part-way (it faulted, even if it answers again by the time the
        // candidates are deleted) is missing some copies, and deleting its
        // candidates would take its only copy of those records: its
        // candidates stay for the next pass.
        let mut reached: Option<HashSet<u16>> = None;
        let mut dropped: Vec<(u16, u64, Hash32)> = Vec::new();
        for (vdev, id) in &candidates {
            let reader = SegmentReader::open(&vdev.root, *id, StreamKind::Meta)?;
            for (header, offset) in reader.scan() {
                let hash = header.content_hash;
                if lchfs_format::record_epoch(&header) != target {
                    dropped.push((vdev.id, *id, hash));
                    continue;
                }
                // Every distinct record of the target epoch goes forward,
                // not only the ones the index calls canonical: an index
                // entry missing for a device is exactly how a device's only
                // copy of a live record gets dropped (see coalesce's
                // `other_copy_on`). A dead one copied is a few bytes of
                // garbage; a live one skipped is a replica lost.
                if copied.contains(&hash) {
                    continue;
                }
                let loc = ExtentLocation {
                    segment_id: *id,
                    offset,
                    len: header.record_len,
                };
                let (full, raw) = reader.read_record_raw_with(loc, &crypto)?;
                let mut slot = self.meta_writer.lock();
                let writer = self.open_meta_writer(&mut slot)?;
                let new_loc = writer.append_prebuilt(&full, &raw);
                let faults = writer.take_faults();
                let vdev_ids = writer.vdev_ids().to_vec();
                self.report_faults(faults);
                let new_loc = new_loc?;
                self.dedup_index.put(hash, new_loc, vdev_ids[0]);
                self.record_replicated_location(hash, new_loc, &vdev_ids)?;
                drop(slot);
                copied.insert(hash);
                let these: HashSet<u16> = vdev_ids.iter().copied().collect();
                reached = Some(match reached {
                    None => these,
                    Some(r) => r.intersection(&these).copied().collect(),
                });
            }
        }
        if let Some(writer) = self.meta_writer.lock().as_mut() {
            let synced = writer.fsync();
            let after_fsync: HashSet<u16> = writer.vdev_ids().iter().copied().collect();
            self.report_faults(writer.take_faults());
            synced?;
            if let Some(r) = reached.as_mut() {
                r.retain(|v| after_fsync.contains(v));
            }
        }
        self.persisted_index.write().flush()?;
        // With nothing to copy every device trivially has it all.
        let reached: HashSet<u16> = reached.unwrap_or_else(|| online.iter().map(|v| v.id).collect());

        self.checkpoint_locked(&held)?;
        self.checkpoint_locked(&held)?;
        let root_hash = self.namespace.lock().root_hash;
        if let Some((loc, vdev)) = self.dedup_index.get_tagged(root_hash)
            && doomed.contains(&(vdev, loc.segment_id))
        {
            return Err(PoolError::Format(format!(
                "meta compaction: the published root is still in segment {}; nothing deleted",
                loc.segment_id
            )));
        }

        let candidates: Vec<(Vdev, u64)> = candidates.into_iter().filter(|(v, _)| reached.contains(&v.id)).collect();
        let dropped: Vec<(u16, u64, Hash32)> = dropped.into_iter().filter(|(v, _, _)| reached.contains(v)).collect();
        let mut by_segment: HashMap<u64, Vec<(Hash32, u16)>> = HashMap::new();
        for &(vdev, id, hash) in &dropped {
            self.dedup_index.remove_if_in(hash, id, vdev);
            by_segment.entry(id).or_default().push((hash, vdev));
        }
        for (id, entries) in by_segment {
            self.persisted_index.write().forget_segment_records(id, &entries)?;
        }
        for (vdev, id) in &candidates {
            let path = segment::segment_path(&vdev.root, *id, StreamKind::Meta);
            if path.exists() {
                let _ = segment::mark_coalesced(&vdev.root, *id, StreamKind::Meta);
                std::fs::remove_file(&path)?;
            }
            self.readers.evict_segment(*id);
        }
        tracing::info!(
            "meta compaction: {} segment(s) retired, {} record(s) kept, {} dropped",
            candidates.len(),
            copied.len(),
            dropped.len()
        );
        Ok(())
    }

    /// Segments on every online device holding a record of an epoch other
    /// than `target`. Keyless.
    pub(crate) fn old_epoch_census(&self, target: u16) -> Result<Census, PoolError> {
        let mut census = Census::default();
        let online = self.vdevs.online();
        for vdev in &online {
            for (kind, count) in [(StreamKind::Data, &mut census.data), (StreamKind::Meta, &mut census.meta)] {
                for id in segment::segment_ids_on(&vdev.root, kind) {
                    if let Ok(reader) = SegmentReader::open(&vdev.root, id, kind)
                        && coalesce::holds_other_epoch(&reader, target)
                    {
                        *count += 1;
                    }
                }
            }
            let delta_root = vdev.root.join("segments").join("delta");
            for shard_dir in std::fs::read_dir(&delta_root).into_iter().flatten().flatten() {
                let Some(shard_id) = shard_dir.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                    continue;
                };
                for file in std::fs::read_dir(shard_dir.path()).into_iter().flatten().flatten() {
                    let path = file.path();
                    if path.extension().is_none_or(|x| x != "dseg") {
                        continue;
                    }
                    let Some(id) = path.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u64>().ok()) else {
                        continue;
                    };
                    if let Ok(reader) = SegmentReader::open_delta(&vdev.root, shard_id, id)
                        && coalesce::holds_other_epoch(&reader, target)
                    {
                        census.delta += 1;
                    }
                }
            }
        }
        for segment_id in stripe::striped_segment_ids(&online) {
            let Ok(reader) = self.stripe_reader(segment_id) else {
                census.stripes += 1;
                continue;
            };
            let other = reader
                .verified_body()
                .map(|body| stripe::scan_body(&body).iter().any(|(h, _)| lchfs_format::record_epoch(h) != target))
                .unwrap_or(true);
            if other {
                census.stripes += 1;
            }
        }
        Ok(census)
    }
}
