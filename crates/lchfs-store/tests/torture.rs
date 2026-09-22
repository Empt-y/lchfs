//! A suite written to *break* lchfs, not to confirm a feature. The
//! model-equivalence harness (lchfs-testkit) drives the Pool API in a
//! single thread; this attacks the two things it cannot reach:
//!
//!  1. **Concurrency.** Many threads pounding the shared machinery -- the
//!     committer pool, the index, the reader cache, the checkpoint, and the
//!     GC/coalesce/dedup/erasure daemons -- all at once, with a strict
//!     content oracle for files each thread owns, and a no-corruption oracle
//!     for a directory namespace the threads fight over.
//!  2. **Adversarial edges at scale.** Boundary offsets, huge sparse files,
//!     the size ceiling, hardlink/rename corners, and a directory with
//!     thousands of entries.
//!
//! Every test is seeded, so a failure names the seed that reproduces it.
//! The parameters are deliberately hostile: tiny segment caps so segments
//! seal, coalesce, get GC'd and (for the striped pool) erasure-code
//! constantly under the writers, and a small shard count so inodes collide
//! on shards and the committer contends.

use lchfs_format::PoolParams;
use lchfs_store::{FallocateMode, Pool, PoolError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Deterministic, fast, dependency-free RNG (xorshift64*).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

/// Hostile parameters: everything small, so the write path, the sealing,
/// and every daemon run hot and often under the workload.
fn torture_params(shard_count: u32, stripe: bool) -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 32 * 1024,
        meta_segment_cap_bytes: 32 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: shard_count,
        stripe_k: if stripe { 2 } else { 0 },
        stripe_m: if stripe { 1 } else { 0 },
        stripe_min_age_segments: 0,
    }
}

/// A file's expected bytes, mutated in lockstep with the pool so a read can
/// be checked against it. Holes read as zeros, so the shadow just carries
/// zeros where the file has none.
#[derive(Clone, Default)]
struct Shadow {
    bytes: Vec<u8>,
}
impl Shadow {
    fn write(&mut self, off: usize, data: &[u8]) {
        let end = off + data.len();
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
        self.bytes[off..end].copy_from_slice(data);
    }
    fn truncate(&mut self, len: usize) {
        self.bytes.resize(len, 0);
    }
    fn zero_range(&mut self, off: usize, len: usize) {
        let end = (off + len).min(self.bytes.len());
        if off < end {
            self.bytes[off..end].iter_mut().for_each(|b| *b = 0);
        }
    }
}

fn read_all(pool: &Pool, ino: u64, size: usize) -> Vec<u8> {
    pool.read(ino, 0, size as u32).unwrap().to_vec()
}

/// Runs a chaos thread that checkpoints and forces every daemon pass as
/// fast as it can, so writers race real sealing/GC/coalesce/dedup rather
/// than waiting on the background timers. Returns a stop flag + handle.
fn spawn_chaos(pool: Arc<Pool>) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let handle = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = pool.checkpoint();
                let _ = pool.run_gc_and_coalesce_pass();
                let _ = pool.run_dedup_pass();
                std::thread::yield_now();
            }
        })
    };
    (stop, handle)
}

/// Settles the pool before a final `fsck`: checkpoint and run a full
/// GC/coalesce pass until reclamation stops changing anything.
///
/// Reclamation is *per-vdev* (the mark is pool-wide, the sweep is not),
/// so a device that was offline -- or simply slower -- while its peers
/// swept still holds dead records they have already dropped. `fsck`
/// compares the devices' physical contents, so it reports those as
/// `ReplicaMissing` even though nothing a root references is missing
/// anywhere. Letting every online device finish its own sweeps first
/// makes the assertion that follows a statement about live data, which is
/// the one worth making: extra passes can only *drop* dead records, never
/// create a missing live one, so a genuine replica gap still fails.
fn drain_coalesce(pool: &Pool, roots: &[std::path::PathBuf]) {
    let segments = |roots: &[std::path::PathBuf]| -> usize {
        roots
            .iter()
            .map(|r| {
                std::fs::read_dir(r.join("segments").join("data"))
                    .map(|d| d.count())
                    .unwrap_or(0)
            })
            .sum()
    };
    let mut last = usize::MAX;
    let mut stable = 0;
    for _ in 0..60 {
        pool.checkpoint().unwrap();
        pool.run_gc_and_coalesce_pass().unwrap();
        let now = segments(roots);
        stable = if now == last { stable + 1 } else { 0 };
        if stable == 3 {
            return;
        }
        last = now;
    }
}

/// The main event: N threads, each owning a private directory of files,
/// hammering random content operations while a chaos thread checkpoints and
/// drives every daemon underneath them. Each thread verifies its own files
/// against a shadow after every mutating op -- so a read that ever sees the
/// wrong bytes (the read/checkpoint race class) fails immediately -- and
/// after a cold reopen everything must still match and fsck must be clean.
fn run_disjoint_torture(stripe: bool, seed: u64) {
    let roots: Vec<tempfile::TempDir> = (0..(if stripe { 3 } else { 1 }))
        .map(|_| tempfile::tempdir().unwrap())
        .collect();
    let root_paths: Vec<_> = roots.iter().map(|d| d.path().to_path_buf()).collect();
    let params = torture_params(4, stripe);

    let pool = if stripe {
        let refs: Vec<&std::path::Path> = root_paths.iter().map(|p| p.as_path()).collect();
        Arc::new(Pool::create_replicated(&refs, params).unwrap())
    } else {
        Arc::new(Pool::create(&root_paths[0], params).unwrap())
    };

    let threads = 6;
    let steps = 1500;
    let (stop, chaos) = spawn_chaos(Arc::clone(&pool));

    let workers: Vec<_> = (0..threads)
        .map(|t| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let mut rng = Rng::new(seed ^ ((t as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15)));
                let dir = pool.mkdir(1, &format!("t{t}"), 0o755).unwrap();
                // name -> (ino, shadow) for this thread's live files.
                let mut files: HashMap<String, (u64, Shadow)> = HashMap::new();
                let mut next_name = 0u64;

                for _ in 0..steps {
                    // Keep a handful of files around; create when short.
                    if files.len() < 6 || rng.below(20) == 0 {
                        let name = format!("f{next_name}");
                        next_name += 1;
                        let ino = pool.create_file(dir, &name, 0o644).unwrap();
                        files.insert(name, (ino, Shadow::default()));
                        continue;
                    }
                    let names: Vec<String> = files.keys().cloned().collect();
                    let name = names[rng.below(names.len())].clone();
                    let (ino, shadow) = files.get_mut(&name).unwrap();
                    let ino = *ino;
                    let size = shadow.bytes.len();

                    match rng.below(10) {
                        0..=2 => {
                            // Write: sometimes an append, sometimes an
                            // overwrite, sometimes past EOF (a hole).
                            let off = match rng.below(3) {
                                0 => size,                              // append
                                1 if size > 0 => rng.below(size),       // overwrite
                                _ => size + rng.range(0, 4096),         // past EOF
                            };
                            let len = rng.range(1, 6000);
                            let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                            pool.write(ino, off as u64, &data).unwrap();
                            shadow.write(off, &data);
                        }
                        3 => {
                            let len = rng.range(0, size + 4096);
                            pool.set_size(ino, len as u64).unwrap();
                            shadow.truncate(len);
                        }
                        4 => {
                            if size > 0 {
                                let off = rng.below(size);
                                let len = rng.range(1, size - off + 1);
                                pool.fallocate(ino, off as u64, len as u64, FallocateMode::ZeroRange { keep_size: true })
                                    .unwrap();
                                shadow.zero_range(off, len);
                            }
                        }
                        5 => {
                            pool.fsync(ino).unwrap();
                        }
                        6 => {
                            // Unlink and forget; recreate happens above.
                            pool.unlink(dir, &name).unwrap();
                            files.remove(&name);
                            continue;
                        }
                        _ => {
                            // Read-verify, the strict oracle: full file, then
                            // a random sub-range.
                            let got = read_all(&pool, ino, shadow.bytes.len());
                            assert_eq!(
                                got, shadow.bytes,
                                "thread {t} seed {seed}: full read of {name} (ino {ino}) mismatched at size {}",
                                shadow.bytes.len()
                            );
                            if !shadow.bytes.is_empty() {
                                let off = rng.below(shadow.bytes.len());
                                let len = rng.range(1, shadow.bytes.len() - off + 1);
                                let part = pool.read(ino, off as u64, len as u32).unwrap();
                                assert_eq!(
                                    part.as_ref(),
                                    &shadow.bytes[off..off + len],
                                    "thread {t} seed {seed}: range read of {name} [{off},{}) mismatched",
                                    off + len
                                );
                            }
                        }
                    }

                    // After every mutation, read the whole file straight
                    // back: this is what catches a write the machinery lost
                    // or a read that saw the file mid-checkpoint.
                    let got = read_all(&pool, ino, shadow.bytes.len());
                    assert_eq!(
                        got, shadow.bytes,
                        "thread {t} seed {seed}: post-op read of {name} (ino {ino}) mismatched at size {}",
                        shadow.bytes.len()
                    );
                }
                (t, dir, files)
            })
        })
        .collect();

    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    stop.store(true, Ordering::Relaxed);
    chaos.join().unwrap();

    // Cold reopen: everything a thread still had must survive with exactly
    // the bytes its shadow says.
    drain_coalesce(&pool, &root_paths);
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = if stripe {
        let refs: Vec<&std::path::Path> = root_paths.iter().map(|p| p.as_path()).collect();
        Pool::open_replicated(&refs).unwrap()
    } else {
        Pool::open(&root_paths[0]).unwrap()
    };
    for (t, _dir, files) in &results {
        let dir = pool.lookup(1, &format!("t{t}")).unwrap().expect("thread dir survives");
        for (name, (_old_ino, shadow)) in files {
            let ino = pool
                .lookup(dir, name)
                .unwrap()
                .unwrap_or_else(|| panic!("seed {seed}: {name} in t{t} vanished across reopen"));
            let got = read_all(&pool, ino, shadow.bytes.len());
            assert_eq!(
                got, shadow.bytes,
                "seed {seed}: {name} in t{t} wrong after reopen (size {})",
                shadow.bytes.len()
            );
        }
    }

    // The independent check: fsck must find nothing wrong. Both halves
    // matter and neither implies the other -- the DAG walk says every
    // record a root references is physically there and verifies, the
    // replica comparison says every device has its copy of it.
    let refs: Vec<&std::path::Path> = root_paths.iter().map(|p| p.as_path()).collect();
    let live_roots = lchfs_fsck::collect_live_roots(&root_paths[0]).unwrap();
    let mut report = lchfs_fsck::check_devices(&refs, &live_roots);
    if stripe {
        report.errors.extend(lchfs_fsck::check_replicas(&refs).errors);
    }
    assert!(report.is_clean(), "seed {seed}: fsck found {:?}", report.errors);
}

#[test]
fn torture_disjoint_writers_single_vdev() {
    for seed in [0xB16B00B5, 0xF00DCAFE, 0x1234_5678_9ABC_DEF0, 0xDEAD_BEEF] {
        run_disjoint_torture(false, seed);
    }
}

#[test]
fn torture_disjoint_writers_striped() {
    for seed in [0x5EED1234, 0xA5A5_5A5A, 0x0BADF00D] {
        run_disjoint_torture(true, seed);
    }
}

/// The hardest scenario in one test: concurrent writers with a strict
/// content oracle on a two-device mirror, while a fault thread repeatedly
/// kills and revives the secondary underneath them. Writes fan out to the
/// survivor, reads serve from whichever copy is up, and after each revival
/// the device is resilvered -- all racing checkpoints and the daemons. No
/// read may ever return wrong bytes, and after a final heal fsck must find
/// the two devices identical. This is the fault + concurrency intersection
/// that has carried real bugs; the content oracle makes any lapse loud.
#[test]
fn torture_mirror_under_a_fault_storm() {
    use lchfs_store::segment::fault_injection;
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Arc::new(
        Pool::create_replicated(&[a.path(), b.path()], torture_params(4, false)).unwrap(),
    );
    let seed = 0xFA017_u64;
    let (stop, chaos) = spawn_chaos(Arc::clone(&pool));

    // Fault thread: kill the secondary, let writes pile up on the primary,
    // revive it, bring it back online (resilver), repeat. Never touches the
    // primary, so reads always have a good copy and the oracle stays sound.
    let fault_stop = Arc::new(AtomicBool::new(false));
    let fault_thread = {
        let pool = Arc::clone(&pool);
        let fault_stop = Arc::clone(&fault_stop);
        let bpath = b.path().to_path_buf();
        std::thread::spawn(move || {
            let mut rng = Rng::new(seed ^ 0xF);
            while !fault_stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(rng.range(5, 25) as u64));
                fault_injection::kill(&bpath);
                std::thread::sleep(std::time::Duration::from_millis(rng.range(5, 25) as u64));
                fault_injection::revive(&bpath);
                // Bring it back; "already online" (the failover task beat us)
                // is fine, as is a transient error while it settles.
                let _ = pool.online_vdev(&bpath);
            }
        })
    };

    let workers: Vec<_> = (0..6)
        .map(|t| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let mut rng = Rng::new(seed ^ ((t as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15)));
                let dir = pool.mkdir(1, &format!("t{t}"), 0o755).unwrap();
                let mut files: HashMap<String, (u64, Shadow)> = HashMap::new();
                let mut next_name = 0u64;
                for _ in 0..1200 {
                    if files.len() < 6 {
                        let name = format!("f{next_name}");
                        next_name += 1;
                        let ino = pool.create_file(dir, &name, 0o644).unwrap();
                        files.insert(name, (ino, Shadow::default()));
                        continue;
                    }
                    let names: Vec<String> = files.keys().cloned().collect();
                    let name = names[rng.below(names.len())].clone();
                    let (ino, shadow) = files.get_mut(&name).unwrap();
                    let ino = *ino;
                    let size = shadow.bytes.len();
                    if rng.below(3) == 0 {
                        // read-verify
                        let got = read_all(&pool, ino, shadow.bytes.len());
                        assert_eq!(got, shadow.bytes, "t{t} seed {seed}: read of {name} wrong under fault storm");
                    } else {
                        let off = if size > 0 && rng.below(2) == 0 { rng.below(size) } else { size };
                        let len = rng.range(1, 4000);
                        let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                        pool.write(ino, off as u64, &data).unwrap();
                        shadow.write(off, &data);
                        let got = read_all(&pool, ino, shadow.bytes.len());
                        assert_eq!(got, shadow.bytes, "t{t} seed {seed}: post-write read of {name} wrong under fault storm");
                    }
                }
                (t, files)
            })
        })
        .collect();

    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    fault_stop.store(true, Ordering::Relaxed);
    fault_thread.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    chaos.join().unwrap();

    // Settle: make sure the secondary is back, resilvered, and the two
    // devices agree.
    fault_injection::revive(b.path());
    let _ = pool.online_vdev(b.path());
    // Give an in-flight auto-rejoin a moment, then force a resilver + scrub.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = pool.resilver(1);
    drain_coalesce(&pool, &[a.path().to_path_buf(), b.path().to_path_buf()]);
    pool.checkpoint().unwrap();
    drop(pool);

    let pool = Pool::open_replicated(&[a.path(), b.path()]).unwrap();
    for (t, files) in &results {
        let dir = pool.lookup(1, &format!("t{t}")).unwrap().expect("dir survives");
        for (name, (_ino, shadow)) in files {
            let ino = pool.lookup(dir, name).unwrap().unwrap_or_else(|| panic!("{name} vanished"));
            assert_eq!(read_all(&pool, ino, shadow.bytes.len()), shadow.bytes, "{name} in t{t} wrong after fault storm + reopen");
        }
    }
    let refs = [a.path(), b.path()];
    let live_roots = lchfs_fsck::collect_live_roots(a.path()).unwrap();
    let mut report = lchfs_fsck::check_devices(&refs, &live_roots);
    report.errors.extend(lchfs_fsck::check_replicas(&refs).errors);
    assert!(report.is_clean(), "seed {seed}: fsck after fault storm: {:?}", report.errors);
}

/// The other oracle: threads fight over the *same* names in one directory
/// -- create, mkdir, rename, unlink, rmdir the same handful of paths at
/// once. No content oracle is possible here; the contract is weaker but
/// exactly the one that matters: the engine never panics, never returns an
/// integrity failure for a plain namespace race, and fsck is clean at the
/// end. A create that wins is written to and must read back its own bytes.
#[test]
fn torture_shared_namespace_races_never_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(dir.path(), torture_params(4, false)).unwrap());
    let arena = pool.mkdir(1, "arena", 0o755).unwrap();
    let (stop, chaos) = spawn_chaos(Arc::clone(&pool));

    let workers: Vec<_> = (0..8)
        .map(|t| {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let mut rng = Rng::new(0xCA05 ^ (t as u64 + 1).wrapping_mul(2654435761));
                for _ in 0..2000 {
                    let name = format!("n{}", rng.below(8));
                    // Any error is a legal outcome of a race (someone got
                    // there first, or it is gone); a panic or an integrity
                    // failure is not.
                    let bad = |r: Result<(), PoolError>| {
                        if let Err(PoolError::IntegrityFailure(h)) = r {
                            panic!("thread {t}: integrity failure on a namespace race: {h:?}");
                        }
                    };
                    match rng.below(6) {
                        0 => {
                            if let Ok(ino) = pool.create_file(arena, &name, 0o644) {
                                // A create that won must accept and return its bytes.
                                let data: Vec<u8> = (0..300).map(|_| rng.byte()).collect();
                                if pool.write(ino, 0, &data).is_ok()
                                    && let Ok(got) = pool.read(ino, 0, data.len() as u32)
                                {
                                    // The name may have been unlinked and
                                    // recreated by another thread; only
                                    // assert when the bytes came back at
                                    // full length (our own inode).
                                    if got.len() == data.len() {
                                        assert_eq!(got.as_ref(), &data[..], "thread {t}: own write read back wrong");
                                    }
                                }
                            }
                        }
                        1 => bad(pool.mkdir(arena, &name, 0o755).map(|_| ())),
                        2 => bad(pool.unlink(arena, &name)),
                        3 => bad(pool.rmdir(arena, &name)),
                        4 => {
                            let to = format!("n{}", rng.below(8));
                            bad(pool.rename(arena, &name, arena, &to, false));
                        }
                        _ => {
                            let _ = pool.lookup(arena, &name);
                            let _ = pool.readdir(arena);
                        }
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    chaos.join().unwrap();

    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let report = lchfs_fsck::check(dir.path(), &[]);
    assert!(report.is_clean(), "fsck after namespace races: {:?}", report.errors);
    // And it still mounts and reads its directory.
    let arena = pool.lookup(1, "arena").unwrap().expect("arena survives");
    let _ = pool.readdir(arena).unwrap();
}

// ---- adversarial edge cases -------------------------------------------

fn small_params() -> PoolParams {
    torture_params(4, false)
}

#[test]
fn adversarial_boundary_offsets_and_holes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();

    // Writes landing exactly on the segment cap and chunk-size boundaries.
    for &b in &[0usize, 256, 1024, 4096, 32 * 1024, 32 * 1024 + 1, 64 * 1024] {
        let data: Vec<u8> = (0..300).map(|i| (b as u8).wrapping_add(i as u8)).collect();
        pool.write(ino, b as u64, &data).unwrap();
    }
    // A hole in the middle: write far out, leaving a gap that must read zero.
    pool.write(ino, 1_000_000, b"tail").unwrap();
    let whole = pool.read(ino, 0, 1_000_004).unwrap();
    assert_eq!(&whole[1_000_000..1_000_004], b"tail");
    assert!(whole[500_000..600_000].iter().all(|&x| x == 0), "hole not zero");

    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let ino = pool.lookup(1, "f").unwrap().unwrap();
    let whole2 = pool.read(ino, 0, 1_000_004).unwrap();
    assert_eq!(whole2.as_ref(), whole.as_ref(), "content changed across reopen");
    assert!(lchfs_fsck::check(dir.path(), &[]).is_clean());
}

#[test]
fn adversarial_size_ceiling_is_refused_not_panicked() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "big", 0o644).unwrap();
    // A write whose end exceeds MAX_FILE_SIZE must be a clean TooLarge, and
    // a set_size beyond it likewise -- never a panic or a silent wrap.
    let huge = u64::MAX - 10;
    assert!(matches!(pool.write(ino, huge, b"boom"), Err(PoolError::TooLarge(_))));
    assert!(matches!(pool.set_size(ino, huge), Err(PoolError::TooLarge(_))));
    // The file is still intact and usable.
    pool.write(ino, 0, b"fine").unwrap();
    assert_eq!(pool.read(ino, 0, 4).unwrap().as_ref(), b"fine");
}

#[test]
fn adversarial_empty_and_past_eof_reads() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, b"hello").unwrap();
    // Zero-length write is a no-op; reads past EOF and beyond size are empty.
    pool.write(ino, 2, b"").unwrap();
    assert_eq!(pool.read(ino, 0, 5).unwrap().as_ref(), b"hello");
    assert!(pool.read(ino, 5, 100).unwrap().is_empty(), "read at EOF not empty");
    assert!(pool.read(ino, 9999, 100).unwrap().is_empty(), "read past size not empty");
    // A read straddling EOF returns only what exists.
    assert_eq!(pool.read(ino, 3, 100).unwrap().as_ref(), b"lo");
}

#[test]
fn adversarial_hardlink_survives_unlink_of_other_name() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let ino = pool.create_file(1, "a", 0o644).unwrap();
    let data: Vec<u8> = (0..5000).map(|i| i as u8).collect();
    pool.write(ino, 0, &data).unwrap();
    pool.link(ino, 1, "b").unwrap();
    pool.unlink(1, "a").unwrap();
    // Content is reachable through the surviving name.
    let b = pool.lookup(1, "b").unwrap().unwrap();
    assert_eq!(read_all(&pool, b, 5000), data);
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let b = pool.lookup(1, "b").unwrap().unwrap();
    assert_eq!(read_all(&pool, b, 5000), data, "hardlinked content lost across reopen");
    assert!(pool.lookup(1, "a").unwrap().is_none(), "unlinked name came back");
    assert!(lchfs_fsck::check(dir.path(), &[]).is_clean());
}

#[test]
fn adversarial_rename_corners() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let d = pool.mkdir(1, "d", 0o755).unwrap();
    let sub = pool.mkdir(d, "sub", 0o755).unwrap();
    let _ = pool.create_file(d, "sub_file", 0o644).unwrap();

    // Renaming a directory into its own subtree must be refused, not loop.
    assert!(pool.rename(1, "d", sub, "loop", false).is_err(), "dir into own subtree allowed");
    // rmdir on a non-empty directory must be refused.
    assert!(matches!(pool.rmdir(1, "d"), Err(PoolError::NotEmpty(_))), "rmdir non-empty allowed");
    // Rename over an existing file replaces it.
    let f = pool.create_file(1, "src", 0o644).unwrap();
    pool.write(f, 0, b"new").unwrap();
    let _victim = pool.create_file(1, "dst", 0o644).unwrap();
    pool.rename(1, "src", 1, "dst", false).unwrap();
    let dst = pool.lookup(1, "dst").unwrap().unwrap();
    assert_eq!(pool.read(dst, 0, 3).unwrap().as_ref(), b"new");
    assert!(pool.lookup(1, "src").unwrap().is_none());
    assert!(lchfs_fsck::check(dir.path(), &[]).is_clean());
}

#[test]
fn adversarial_large_directory() {
    let dir = tempfile::tempdir().unwrap();
    let pool = Pool::create(dir.path(), small_params()).unwrap();
    let d = pool.mkdir(1, "many", 0o755).unwrap();
    let n = 5000;
    for i in 0..n {
        pool.create_file(d, &format!("e{i:05}"), 0o644).unwrap();
    }
    pool.checkpoint().unwrap();
    drop(pool);
    let pool = Pool::open(dir.path()).unwrap();
    let d = pool.lookup(1, "many").unwrap().unwrap();
    let entries = pool.readdir(d).unwrap();
    // readdir includes "." and ".."; every created name must be present and
    // individually resolvable.
    let names: std::collections::HashSet<String> =
        entries.iter().map(|e| e.name.clone()).collect();
    for i in 0..n {
        let name = format!("e{i:05}");
        assert!(names.contains(&name), "entry {name} missing from readdir");
    }
    assert!(pool.lookup(d, "e02500").unwrap().is_some());
    assert!(lchfs_fsck::check(dir.path(), &[]).is_clean());
}
