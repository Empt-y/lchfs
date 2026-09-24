//! Memory that secrets live in (ARCHITECTURE.md §18, memory hardening).
//!
//! Every key and passphrase lchfs holds sits in pages mapped for the
//! purpose, never on the ordinary heap:
//!
//! - **locked** (`mlock`) so they are never written to swap -- best effort,
//!   since `RLIMIT_MEMLOCK` may be too small; [`status`] says whether it
//!   worked;
//! - **left out of core dumps** (`MADV_DONTDUMP`);
//! - **not inherited by a forked child** (`MADV_DONTFORK`). Deliberately not
//!   `MADV_WIPEONFORK`: a child that somehow went on using a key would then
//!   see an all-zero key and seal data nobody can read back, silently. With
//!   DONTFORK the page is simply absent in the child, and touching it
//!   faults loudly. (lchfs only forks to exec, e.g. an askpass helper.)
//! - **fenced** by an inaccessible guard page on each side, so a linear
//!   overrun from a neighbouring allocation cannot reach them, nor they it.
//!
//! Keys go in a slab of 32-byte slots ([`Slot`], what `Key32` is made of),
//! so moving a key moves a pointer and its bytes never get copied around
//! the heap -- a `BTreeMap` rebalancing or a `Vec` growing would otherwise
//! leave stale copies nobody zeroes. Variable-length secrets get their own
//! fixed-capacity mapping ([`LockedBytes`]) that never reallocates.
//!
//! This is the only module in the workspace allowed to use `unsafe`.

#![allow(unsafe_code)]

use nix::sys::mman::{MapFlags, MmapAdvise, ProtFlags, madvise, mlock, mmap_anonymous, mprotect, munmap};
use std::ffi::c_void;
use std::fmt;
use std::num::NonZeroUsize;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

/// Size of one key slot.
const SLOT: usize = 32;

static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// Whether every secret page so far could be locked into RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    Locked,
    /// At least one `mlock` failed (usually `RLIMIT_MEMLOCK`): those pages
    /// could be swapped out. They are still excluded from core dumps.
    Unlocked,
}

pub fn status() -> LockStatus {
    if LOCK_FAILED.load(Ordering::Relaxed) { LockStatus::Unlocked } else { LockStatus::Locked }
}

fn page_size() -> usize {
    static PAGE: OnceLock<usize> = OnceLock::new();
    *PAGE.get_or_init(|| {
        nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .ok()
            .flatten()
            .map(|p| p as usize)
            .filter(|p| p.is_power_of_two() && *p >= 4096)
            .unwrap_or(4096)
    })
}

/// A private anonymous mapping of `data_len` usable bytes (rounded up to
/// whole pages) between two guard pages. Its bytes start zeroed.
struct Region {
    /// First byte of the whole mapping (the leading guard page).
    mapping: NonNull<c_void>,
    mapping_len: usize,
    /// First usable byte, one page in.
    data: NonNull<u8>,
    data_len: usize,
}

impl Region {
    fn map(len: usize) -> Region {
        let page = page_size();
        let data_len = len.max(1).div_ceil(page) * page;
        let mapping_len = data_len + 2 * page;
        // SAFETY: a fresh anonymous private mapping at an address of the
        // kernel's choosing aliases nothing that exists.
        let mapping = unsafe {
            mmap_anonymous(
                None,
                NonZeroUsize::new(mapping_len).expect("non-zero"),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE,
            )
        }
        .unwrap_or_else(|e| panic!("mapping {mapping_len} bytes for secrets failed: {e}"));
        let base = mapping.as_ptr().cast::<u8>();
        // SAFETY: both offsets stay inside the mapping just created.
        let data = unsafe { NonNull::new_unchecked(base.add(page)) };
        let tail = unsafe { NonNull::new_unchecked(base.add(page + data_len)) };
        // SAFETY: the guard pages are inside our own mapping and nothing
        // points into them. A failure here only loses the fence, never
        // makes memory unsafe, so it is not fatal.
        unsafe {
            let _ = mprotect(mapping, page, ProtFlags::PROT_NONE);
            let _ = mprotect(tail.cast(), page, ProtFlags::PROT_NONE);
        }
        // SAFETY: advice and locking on the data pages of our own mapping
        // change how the kernel treats them, not their contents.
        unsafe {
            let d = data.cast::<c_void>();
            // Kernels too old for either advice return EINVAL; the secret
            // is no less usable for it.
            let _ = madvise(d, data_len, MmapAdvise::MADV_DONTDUMP);
            let _ = madvise(d, data_len, MmapAdvise::MADV_DONTFORK);
            if mlock(d, data_len).is_err() {
                LOCK_FAILED.store(true, Ordering::Relaxed);
            }
        }
        Region {
            mapping,
            mapping_len,
            data,
            data_len,
        }
    }

    /// Zeroes the usable bytes and unmaps the whole region.
    ///
    /// # Safety
    /// Nothing may point into the region afterwards.
    unsafe fn unmap(&mut self) {
        // SAFETY: the data range is ours and writable; the caller vouches
        // no reference into it outlives this call.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_len) }.zeroize();
        // SAFETY: exactly the mapping `map` made. Unmapping also unlocks it.
        let _ = unsafe { munmap(self.mapping, self.mapping_len) };
    }
}

// ---------------------------------------------------------------------------
// The key slab.
// ---------------------------------------------------------------------------

struct Page {
    /// Address of the page's first slot. An address, not a pointer, so the
    /// table can live in a `static`.
    base: usize,
    used: Vec<u64>,
    free: usize,
}

impl Page {
    fn slots() -> usize {
        page_size() / SLOT
    }

    fn contains(&self, addr: usize) -> bool {
        addr >= self.base && addr < self.base + page_size()
    }
}

/// Pages are never unmapped: the slab is bounded by the most keys alive at
/// once, which is a handful per epoch.
static SLAB: Mutex<Vec<Page>> = Mutex::new(Vec::new());

/// One 32-byte slot of locked memory, exclusively owned. Starts zeroed;
/// zeroed again when dropped, before anyone else can be handed it.
pub struct Slot(NonNull<[u8; SLOT]>);

// SAFETY: a `Slot` is the only handle to its 32 bytes, which are plain
// data in a mapping that is never unmapped; handing it to another thread
// is like handing over a `Box<[u8; 32]>`.
unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

impl Slot {
    pub fn new() -> Slot {
        let mut slab = SLAB.lock().unwrap_or_else(|p| p.into_inner());
        let index = match slab.iter().position(|p| p.free > 0) {
            Some(i) => i,
            None => {
                let region = Region::map(page_size());
                let slots = Page::slots();
                slab.push(Page {
                    base: region.data.as_ptr() as usize,
                    used: vec![0; slots.div_ceil(64)],
                    free: slots,
                });
                // `Region` has no `Drop`: letting the handle go leaves the
                // page mapped, the slab's for the life of the process.
                slab.len() - 1
            }
        };
        let page = &mut slab[index];
        let slot = (0..Page::slots())
            .find(|&i| page.used[i / 64] & (1 << (i % 64)) == 0)
            .expect("a page with free > 0 has a clear bit");
        page.used[slot / 64] |= 1 << (slot % 64);
        page.free -= 1;
        let addr = page.base + slot * SLOT;
        // SAFETY: inside a live slab page, SLOT-aligned, non-null.
        Slot(unsafe { NonNull::new_unchecked(addr as *mut [u8; SLOT]) })
    }

    pub fn bytes(&self) -> &[u8; SLOT] {
        // SAFETY: we own the slot exclusively and its page stays mapped.
        unsafe { self.0.as_ref() }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8; SLOT] {
        // SAFETY: as `bytes`, and `&mut self` makes the borrow unique.
        unsafe { self.0.as_mut() }
    }
}

impl Default for Slot {
    fn default() -> Self {
        Slot::new()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.bytes_mut().zeroize();
        let addr = self.0.as_ptr() as usize;
        let mut slab = SLAB.lock().unwrap_or_else(|p| p.into_inner());
        let page = slab
            .iter_mut()
            .find(|p| p.contains(addr))
            .expect("a slot belongs to a slab page");
        let i = (addr - page.base) / SLOT;
        debug_assert!(page.used[i / 64] & (1 << (i % 64)) != 0, "slot freed twice");
        page.used[i / 64] &= !(1 << (i % 64));
        page.free += 1;
    }
}

impl fmt::Debug for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Slot(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Variable-length secrets.
// ---------------------------------------------------------------------------

/// A passphrase, PIN or identity: bytes in their own locked mapping, with a
/// capacity fixed at creation so they are never reallocated (and so never
/// leave a stale copy behind). Zeroed and unmapped when dropped.
pub struct LockedBytes {
    region: Region,
    len: usize,
    cap: usize,
}

// SAFETY: exclusively owns its mapping, like a `Vec<u8>` owns its buffer.
unsafe impl Send for LockedBytes {}
unsafe impl Sync for LockedBytes {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("secret is longer than {0} bytes")]
pub struct TooLong(pub usize);

impl LockedBytes {
    /// The most any secret lchfs reads may hold. A passphrase or key file
    /// larger than this is refused rather than silently truncated.
    pub const MAX: usize = 64 * 1024;

    /// Empty, able to hold `cap` bytes.
    pub fn with_capacity(cap: usize) -> Self {
        LockedBytes {
            region: Region::map(cap),
            len: 0,
            cap,
        }
    }

    /// A copy of `bytes`.
    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut s = Self::with_capacity(bytes.len());
        s.try_extend_from_slice(bytes).expect("capacity is exactly the length");
        s
    }

    /// `len` zero bytes, to be written through `DerefMut`.
    pub fn zeroed(len: usize) -> Self {
        let mut s = Self::with_capacity(len);
        s.len = len;
        s
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), TooLong> {
        if bytes.len() > self.cap - self.len {
            return Err(TooLong(self.cap));
        }
        let start = self.len;
        self.len += bytes.len();
        self[start..].copy_from_slice(bytes);
        Ok(())
    }

    pub fn push(&mut self, byte: u8) -> Result<(), TooLong> {
        self.try_extend_from_slice(&[byte])
    }

    /// Removes and zeroes the last byte.
    pub fn pop(&mut self) -> Option<u8> {
        let last = *self.last()?;
        self.truncate(self.len - 1);
        Some(last)
    }

    /// Shortens to `len`, zeroing what is cut off.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.spare_from(len).zeroize();
            self.len = len;
        }
    }

    /// Appends everything `reader` yields until end of input. More than
    /// the capacity is an error, and what was read is kept zeroed-on-drop
    /// either way. Reads straight into the locked pages, so no bytes pass
    /// through an intermediate buffer.
    pub fn read_to_end_from(&mut self, reader: &mut impl std::io::Read) -> std::io::Result<()> {
        loop {
            if self.len == self.cap {
                // One more byte means too long; zero means we are done.
                let mut probe = [0u8; 1];
                let n = reader.read(&mut probe)?;
                probe.zeroize();
                if n == 0 {
                    return Ok(());
                }
                return Err(std::io::Error::other(TooLong(self.cap)));
            }
            let start = self.len;
            let n = match reader.read(self.spare_from(start)) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                return Ok(());
            }
            self.len += n;
        }
    }

    /// The bytes from `from` to the end of the capacity.
    fn spare_from(&mut self, from: usize) -> &mut [u8] {
        // SAFETY: the data range holds at least `cap` bytes and we own it.
        let all = unsafe { std::slice::from_raw_parts_mut(self.region.data.as_ptr(), self.cap) };
        &mut all[from..]
    }
}

impl std::ops::Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: the first `len` bytes of our own mapping.
        unsafe { std::slice::from_raw_parts(self.region.data.as_ptr(), self.len) }
    }
}

impl std::ops::DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `deref`, uniquely borrowed.
        unsafe { std::slice::from_raw_parts_mut(self.region.data.as_ptr(), self.len) }
    }
}

impl Clone for LockedBytes {
    fn clone(&self) -> Self {
        let mut c = Self::with_capacity(self.cap);
        c.try_extend_from_slice(self).expect("same capacity");
        c
    }
}

/// Constant-time in the contents (a length mismatch is not hidden).
impl PartialEq for LockedBytes {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq::constant_time_eq(self, other)
    }
}
impl Eq for LockedBytes {}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        // SAFETY: every borrow of our bytes is tied to `&self`/`&mut self`,
        // so none outlives this.
        unsafe { self.region.unmap() }
    }
}

impl fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LockedBytes(<{} bytes redacted>)", self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's flags for the mapping that holds `addr`, from
    /// /proc/self/smaps (`dd` = dontdump, `dc` = dontfork, `lo` = locked).
    fn vm_flags(addr: usize) -> Vec<String> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((lo, hi)) = range.split_once('-')
                && let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                inside = (lo..hi).contains(&addr);
                continue;
            }
            if inside && let Some(flags) = line.strip_prefix("VmFlags:") {
                return flags.split_whitespace().map(str::to_owned).collect();
            }
        }
        panic!("no mapping holds {addr:#x}");
    }

    #[test]
    fn slots_start_zeroed_are_distinct_and_are_reused() {
        let mut held: Vec<Slot> = (0..1000).map(|_| Slot::new()).collect();
        let mut addrs: Vec<usize> = held.iter().map(|s| s.0.as_ptr() as usize).collect();
        addrs.sort_unstable();
        addrs.dedup();
        assert_eq!(addrs.len(), 1000, "every live slot is its own memory");
        for (i, s) in held.iter_mut().enumerate() {
            assert_eq!(s.bytes(), &[0; SLOT]);
            s.bytes_mut().fill(i as u8 | 1);
        }
        let pages_before = SLAB.lock().unwrap().len();
        drop(held);
        let again: Vec<Slot> = (0..1000).map(|_| Slot::new()).collect();
        assert!(again.iter().all(|s| s.bytes() == &[0; SLOT]), "a reused slot comes back zeroed");
        // Other tests allocate in parallel, so allow a little growth -- but
        // not a whole second set of pages.
        assert!(SLAB.lock().unwrap().len() <= pages_before + 2, "freed slots were reused");
    }

    #[test]
    fn a_freed_slot_is_zeroed_before_anyone_can_have_it() {
        let mut s = Slot::new();
        s.bytes_mut().fill(0xA5);
        let ptr = s.0.as_ptr().cast::<u8>();
        drop(s);
        // SAFETY: the page stays mapped for the life of the process; a
        // parallel test may since have been handed this slot, and a fresh
        // slot is zero too, so the bytes are zero either way -- never 0xA5.
        let after = unsafe { std::slice::from_raw_parts(ptr, SLOT) };
        assert!(after.iter().all(|&b| b != 0xA5));
    }

    #[test]
    fn secret_pages_are_left_out_of_dumps_and_forks() {
        let slot = Slot::new();
        let bytes = LockedBytes::from_slice(b"hunter2");
        for addr in [slot.0.as_ptr() as usize, bytes.region.data.as_ptr() as usize] {
            let flags = vm_flags(addr);
            assert!(flags.iter().any(|f| f == "dd"), "not excluded from core dumps: {flags:?}");
            assert!(flags.iter().any(|f| f == "dc"), "inherited by fork: {flags:?}");
            if status() == LockStatus::Locked {
                assert!(flags.iter().any(|f| f == "lo"), "not locked: {flags:?}");
            }
        }
    }

    #[test]
    fn locked_bytes_never_grow_past_capacity() {
        let mut b = LockedBytes::with_capacity(4);
        b.try_extend_from_slice(b"abc").unwrap();
        b.push(b'd').unwrap();
        assert_eq!(b.push(b'e'), Err(TooLong(4)));
        assert_eq!(&*b, b"abcd");
        assert_eq!(b.pop(), Some(b'd'));
        b.truncate(1);
        assert_eq!(&*b, b"a");
        assert_eq!(format!("{b:?}"), "LockedBytes(<1 bytes redacted>)");
    }

    #[test]
    fn reading_is_bounded_by_capacity() {
        let mut b = LockedBytes::with_capacity(8);
        b.read_to_end_from(&mut &b"12345678"[..]).unwrap();
        assert_eq!(&*b, b"12345678");
        let mut c = LockedBytes::with_capacity(8);
        let err = c.read_to_end_from(&mut &b"123456789"[..]).unwrap_err();
        assert!(err.to_string().contains("longer than 8"), "{err}");
    }
}
