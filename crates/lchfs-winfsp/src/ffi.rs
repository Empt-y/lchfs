//! WinFsp, from Rust: the handful of its types and functions this crate
//! uses, and the callback table that hands each WinFsp operation to
//! [`fs::Volume`](crate::fs::Volume).
//!
//! Layouts are transcribed from WinFsp's `inc/winfsp/fsctl.h` and
//! `winfsp.h`, whose sizes are ABI (checked below against the sizes those
//! headers assert). The DLL is loaded at run time from WinFsp's install
//! directory, as its own `FspLoad` does, so building needs no WinFsp SDK
//! and a machine without WinFsp gets a clear error rather than a loader
//! failure at start-up.
//!
//! Every callback catches panics: unwinding into WinFsp's dispatcher
//! would abort the process with the volume still mounted.

#![allow(unsafe_code)]
// Field and parameter names follow winfsp.h; callbacks take the arguments
// WinFsp gives them; and `sym!` casts each export to its field's type,
// which is the annotation clippy asks for.
#![allow(non_snake_case, clippy::too_many_arguments, clippy::missing_transmute_annotations)]

use crate::fs::{self, DirItem, FileInfo, Handle, Volume, status};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, null_mut};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY, RegGetValueW};

use status::NtStatus;
type Boolean = u8;

// ---------------------------------------------------------------------------
// fsctl.h
// ---------------------------------------------------------------------------

/// `FSP_FSCTL_VOLUME_PARAMS` (V1). The C bitfields are the two `flags`
/// words; see [`vp`] for the bits used.
#[repr(C)]
pub struct VolumeParams {
    pub Version: u16,
    pub SectorSize: u16,
    pub SectorsPerAllocationUnit: u16,
    pub MaxComponentLength: u16,
    pub VolumeCreationTime: u64,
    pub VolumeSerialNumber: u32,
    pub TransactTimeout: u32,
    pub IrpTimeout: u32,
    pub IrpCapacity: u32,
    pub FileInfoTimeout: u32,
    pub flags: u32,
    pub Prefix: [u16; 192],
    pub FileSystemName: [u16; 16],
    pub flags2: u32,
    pub VolumeInfoTimeout: u32,
    pub DirInfoTimeout: u32,
    pub SecurityTimeout: u32,
    pub StreamInfoTimeout: u32,
    pub EaTimeout: u32,
    pub FsextControlCode: u32,
    pub Reserved32: [u32; 1],
    pub Reserved64: [u64; 2],
}

/// Bit positions in `VolumeParams::flags`, in declaration order
/// (MSVC and GCC both allocate bitfields from the low bit).
pub mod vp {
    pub const CASE_SENSITIVE_SEARCH: u32 = 1 << 0;
    pub const CASE_PRESERVED_NAMES: u32 = 1 << 1;
    pub const UNICODE_ON_DISK: u32 = 1 << 2;
    pub const PERSISTENT_ACLS: u32 = 1 << 3;
    pub const REPARSE_POINTS: u32 = 1 << 4;
    pub const REPARSE_POINTS_ACCESS_CHECK: u32 = 1 << 5;
    pub const READ_ONLY_VOLUME: u32 = 1 << 9;
    pub const POST_CLEANUP_WHEN_MODIFIED_ONLY: u32 = 1 << 10;
    pub const UM_FILE_CONTEXT_IS_USER_CONTEXT2: u32 = 1 << 16;
}

#[repr(C)]
pub struct VolumeInfo {
    pub TotalSize: u64,
    pub FreeSize: u64,
    pub VolumeLabelLength: u16,
    pub VolumeLabel: [u16; 32],
}

#[repr(C)]
#[derive(Default)]
pub struct FspFileInfo {
    pub FileAttributes: u32,
    pub ReparseTag: u32,
    pub AllocationSize: u64,
    pub FileSize: u64,
    pub CreationTime: u64,
    pub LastAccessTime: u64,
    pub LastWriteTime: u64,
    pub ChangeTime: u64,
    pub IndexNumber: u64,
    pub HardLinks: u32,
    pub EaSize: u32,
}

/// `FSP_FSCTL_DIR_INFO` without its trailing name, which follows it.
#[repr(C)]
pub struct DirInfo {
    pub Size: u16,
    pub FileInfo: FspFileInfo,
    pub Padding: [u8; 24],
}

const _: () = {
    assert!(std::mem::size_of::<VolumeParams>() == 504);
    assert!(std::mem::offset_of!(VolumeParams, flags2) == 456);
    assert!(std::mem::size_of::<VolumeInfo>() == 88);
    assert!(std::mem::size_of::<FspFileInfo>() == 72);
    assert!(std::mem::size_of::<DirInfo>() == 104);
    assert!(std::mem::size_of::<FspFileSystemInterface>() == 64 * std::mem::size_of::<usize>());
    assert!(std::mem::offset_of!(FspFileSystem, UserContext) == 8);
};

// ---------------------------------------------------------------------------
// winfsp.h
// ---------------------------------------------------------------------------

/// The head of `FSP_FILE_SYSTEM`, as far as `UserContext` -- the only
/// field read or written here. WinFsp allocates the whole thing.
#[repr(C)]
pub struct FspFileSystem {
    pub Version: u16,
    pub UserContext: *mut c_void,
}

type Fs = *mut FspFileSystem;
type Ctx = *mut c_void;
type Unused = Option<unsafe extern "C" fn()>;

/// `FSP_FILE_SYSTEM_INTERFACE`: 64 function pointers, `None` where WinFsp
/// should answer `STATUS_INVALID_DEVICE_REQUEST` itself.
#[repr(C)]
pub struct FspFileSystemInterface {
    GetVolumeInfo: Option<unsafe extern "C" fn(Fs, *mut VolumeInfo) -> NtStatus>,
    SetVolumeLabel: Unused,
    GetSecurityByName:
        Option<unsafe extern "C" fn(Fs, *mut u16, *mut u32, PSECURITY_DESCRIPTOR, *mut usize) -> NtStatus>,
    Create: Option<
        unsafe extern "C" fn(Fs, *mut u16, u32, u32, u32, PSECURITY_DESCRIPTOR, u64, *mut Ctx, *mut FspFileInfo)
            -> NtStatus,
    >,
    Open: Option<unsafe extern "C" fn(Fs, *mut u16, u32, u32, *mut Ctx, *mut FspFileInfo) -> NtStatus>,
    Overwrite: Option<unsafe extern "C" fn(Fs, Ctx, u32, Boolean, u64, *mut FspFileInfo) -> NtStatus>,
    Cleanup: Option<unsafe extern "C" fn(Fs, Ctx, *mut u16, u32)>,
    Close: Option<unsafe extern "C" fn(Fs, Ctx)>,
    Read: Option<unsafe extern "C" fn(Fs, Ctx, *mut c_void, u64, u32, *mut u32) -> NtStatus>,
    Write: Option<
        unsafe extern "C" fn(Fs, Ctx, *mut c_void, u64, u32, Boolean, Boolean, *mut u32, *mut FspFileInfo) -> NtStatus,
    >,
    Flush: Option<unsafe extern "C" fn(Fs, Ctx, *mut FspFileInfo) -> NtStatus>,
    GetFileInfo: Option<unsafe extern "C" fn(Fs, Ctx, *mut FspFileInfo) -> NtStatus>,
    SetBasicInfo: Option<unsafe extern "C" fn(Fs, Ctx, u32, u64, u64, u64, u64, *mut FspFileInfo) -> NtStatus>,
    SetFileSize: Option<unsafe extern "C" fn(Fs, Ctx, u64, Boolean, *mut FspFileInfo) -> NtStatus>,
    CanDelete: Option<unsafe extern "C" fn(Fs, Ctx, *mut u16) -> NtStatus>,
    Rename: Option<unsafe extern "C" fn(Fs, Ctx, *mut u16, *mut u16, Boolean) -> NtStatus>,
    GetSecurity: Option<unsafe extern "C" fn(Fs, Ctx, PSECURITY_DESCRIPTOR, *mut usize) -> NtStatus>,
    SetSecurity: Unused,
    ReadDirectory: Option<unsafe extern "C" fn(Fs, Ctx, *mut u16, *mut u16, *mut c_void, u32, *mut u32) -> NtStatus>,
    ResolveReparsePoints:
        Option<unsafe extern "C" fn(Fs, *mut u16, u32, Boolean, *mut c_void, *mut c_void, *mut usize) -> NtStatus>,
    GetReparsePoint: Option<unsafe extern "C" fn(Fs, Ctx, *mut u16, *mut c_void, *mut usize) -> NtStatus>,
    SetReparsePoint: Option<unsafe extern "C" fn(Fs, Ctx, *mut u16, *mut c_void, usize) -> NtStatus>,
    DeleteReparsePoint: Unused,
    GetStreamInfo: Unused,
    GetDirInfoByName: Unused,
    Control: Unused,
    SetDelete: Unused,
    CreateEx: Unused,
    OverwriteEx: Unused,
    GetEa: Unused,
    SetEa: Unused,
    Obsolete0: Unused,
    DispatcherStopped: Unused,
    Reserved: [Unused; 31],
}

/// `GetReparsePointByName`, as the reparse helpers call it.
type GetReparsePointByName = unsafe extern "C" fn(Fs, *mut c_void, *mut u16, Boolean, *mut c_void, *mut usize) -> NtStatus;

/// The WinFsp DLL's exports this crate calls.
struct Api {
    _dll: HMODULE,
    FspFileSystemCreate:
        unsafe extern "C" fn(*const u16, *const VolumeParams, *const FspFileSystemInterface, *mut Fs) -> NtStatus,
    FspFileSystemDelete: unsafe extern "C" fn(Fs),
    FspFileSystemSetMountPoint: unsafe extern "C" fn(Fs, *const u16) -> NtStatus,
    FspFileSystemStartDispatcher: unsafe extern "C" fn(Fs, u32) -> NtStatus,
    FspFileSystemStopDispatcher: unsafe extern "C" fn(Fs),
    FspFileSystemAcquireDirectoryBuffer: unsafe extern "C" fn(*mut *mut c_void, Boolean, *mut NtStatus) -> Boolean,
    FspFileSystemFillDirectoryBuffer: unsafe extern "C" fn(*mut *mut c_void, *mut DirInfo, *mut NtStatus) -> Boolean,
    FspFileSystemReleaseDirectoryBuffer: unsafe extern "C" fn(*mut *mut c_void),
    FspFileSystemReadDirectoryBuffer: unsafe extern "C" fn(*mut *mut c_void, *mut u16, *mut c_void, u32, *mut u32),
    FspFileSystemDeleteDirectoryBuffer: unsafe extern "C" fn(*mut *mut c_void),
    FspFileSystemFindReparsePoint:
        unsafe extern "C" fn(Fs, GetReparsePointByName, *mut c_void, *mut u16, *mut u32) -> Boolean,
    FspFileSystemResolveReparsePoints: unsafe extern "C" fn(
        Fs,
        GetReparsePointByName,
        *mut c_void,
        *mut u16,
        u32,
        Boolean,
        *mut c_void,
        *mut c_void,
        *mut usize,
    ) -> NtStatus,
}

// SAFETY: plain function pointers into a DLL that stays loaded for the
// life of the process.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

static API: OnceLock<Api> = OnceLock::new();

fn api() -> &'static Api {
    API.get().expect("WinFsp is loaded before any volume exists")
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

#[cfg(target_arch = "x86_64")]
const DLL_NAME: &str = "winfsp-x64.dll";
#[cfg(target_arch = "aarch64")]
const DLL_NAME: &str = "winfsp-a64.dll";
#[cfg(target_arch = "x86")]
const DLL_NAME: &str = "winfsp-x86.dll";

/// WinFsp's install directory, from the registry key its installer writes.
fn install_dir() -> Option<String> {
    let key = wide("Software\\WinFsp");
    let value = wide("InstallDir");
    let mut buf = [0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: NUL-terminated names; `buf` holds `size` bytes.
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY,
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if err != 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

/// Loads WinFsp's DLL once. Errors name what is missing.
pub fn load() -> Result<(), String> {
    if API.get().is_some() {
        return Ok(());
    }
    let mut tried = Vec::new();
    let mut candidates = Vec::new();
    if let Some(dir) = install_dir() {
        candidates.push(format!("{}\\bin\\{DLL_NAME}", dir.trim_end_matches('\\')));
    }
    candidates.push(DLL_NAME.to_owned());
    let mut dll: HMODULE = null_mut();
    for c in &candidates {
        let w = wide(c);
        // SAFETY: NUL-terminated path.
        dll = unsafe { LoadLibraryW(w.as_ptr()) };
        if !dll.is_null() {
            break;
        }
        tried.push(c.clone());
    }
    if dll.is_null() {
        return Err(format!(
            "WinFsp is not installed (could not load {}); get it from https://winfsp.dev",
            tried.join(" or ")
        ));
    }
    macro_rules! sym {
        ($name:ident) => {{
            let name = concat!(stringify!($name), "\0");
            // SAFETY: a NUL-terminated export name from a loaded module.
            let p = unsafe { GetProcAddress(dll, name.as_ptr()) };
            match p {
                // SAFETY: the export has the signature winfsp.h declares,
                // which is the field's type.
                Some(p) => unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, _>(p) },
                None => {
                    // SAFETY: nothing from the module has been kept.
                    unsafe { FreeLibrary(dll) };
                    return Err(format!("{DLL_NAME} has no {}: WinFsp is too old", stringify!($name)));
                }
            }
        }};
    }
    let api = Api {
        FspFileSystemCreate: sym!(FspFileSystemCreate),
        FspFileSystemDelete: sym!(FspFileSystemDelete),
        FspFileSystemSetMountPoint: sym!(FspFileSystemSetMountPoint),
        FspFileSystemStartDispatcher: sym!(FspFileSystemStartDispatcher),
        FspFileSystemStopDispatcher: sym!(FspFileSystemStopDispatcher),
        FspFileSystemAcquireDirectoryBuffer: sym!(FspFileSystemAcquireDirectoryBuffer),
        FspFileSystemFillDirectoryBuffer: sym!(FspFileSystemFillDirectoryBuffer),
        FspFileSystemReleaseDirectoryBuffer: sym!(FspFileSystemReleaseDirectoryBuffer),
        FspFileSystemReadDirectoryBuffer: sym!(FspFileSystemReadDirectoryBuffer),
        FspFileSystemDeleteDirectoryBuffer: sym!(FspFileSystemDeleteDirectoryBuffer),
        FspFileSystemFindReparsePoint: sym!(FspFileSystemFindReparsePoint),
        FspFileSystemResolveReparsePoints: sym!(FspFileSystemResolveReparsePoints),
        _dll: dll,
    };
    let _ = API.set(api);
    Ok(())
}

// ---------------------------------------------------------------------------
// Security: every file gets the same descriptor. lchfs keeps Unix modes,
// not ACLs, and a mount serves the user who started it.
// ---------------------------------------------------------------------------

struct Descriptor(Vec<u8>);

/// Owner and group Administrators; full access for SYSTEM, Administrators
/// and Everyone -- what WinFsp's own sample file systems use.
fn descriptor() -> &'static [u8] {
    static SD: OnceLock<Descriptor> = OnceLock::new();
    &SD.get_or_init(|| {
        let sddl = wide("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)");
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated SDDL string; `sd` receives a LocalAlloc'd
        // descriptor we copy and then free.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
                == 0
            {
                panic!("the built-in security descriptor failed to parse");
            }
            let len = GetSecurityDescriptorLength(sd) as usize;
            let bytes = std::slice::from_raw_parts(sd.cast::<u8>(), len).to_vec();
            LocalFree(sd);
            Descriptor(bytes)
        }
    })
    .0
}

/// Copies the descriptor out under WinFsp's size protocol: a null size
/// pointer means "not wanted", a short buffer gets the needed size back.
unsafe fn give_descriptor(out: PSECURITY_DESCRIPTOR, size: *mut usize) -> NtStatus {
    if size.is_null() {
        return status::SUCCESS;
    }
    let sd = descriptor();
    // SAFETY: `size` is non-null and WinFsp's; `out` holds `*size` bytes.
    unsafe {
        if *size < sd.len() {
            *size = sd.len();
            return status::BUFFER_OVERFLOW;
        }
        *size = sd.len();
        if !out.is_null() {
            ptr::copy_nonoverlapping(sd.as_ptr(), out.cast::<u8>(), sd.len());
        }
    }
    status::SUCCESS
}

// ---------------------------------------------------------------------------
// Callbacks.
// ---------------------------------------------------------------------------

/// What `UserContext2` points to for each open file.
struct FileCtx {
    handle: Handle,
    /// WinFsp's directory-listing cache for this handle.
    dir_buffer: *mut c_void,
}

unsafe fn volume<'a>(fs: Fs) -> &'a Volume {
    // SAFETY: set to a leaked `Volume` before the dispatcher starts.
    unsafe { &*((*fs).UserContext as *const Volume) }
}

unsafe fn file<'a>(ctx: Ctx) -> &'a mut FileCtx {
    // SAFETY: a `FileCtx` we boxed in open/create, freed only in close.
    unsafe { &mut *(ctx as *mut FileCtx) }
}

/// A NUL-terminated UTF-16 string from WinFsp.
unsafe fn string(p: *const u16) -> Result<String, NtStatus> {
    if p.is_null() {
        return Ok(String::new());
    }
    // SAFETY: WinFsp passes NUL-terminated strings.
    let len = unsafe { (0..).take_while(|&i| *p.add(i) != 0).count() };
    let units = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16(units).map_err(|_| status::OBJECT_NAME_INVALID)
}

unsafe fn put_info(out: *mut FspFileInfo, info: &FileInfo) {
    if out.is_null() {
        return;
    }
    // SAFETY: WinFsp's out-parameter.
    unsafe {
        *out = FspFileInfo {
            FileAttributes: info.attributes,
            ReparseTag: info.reparse_tag,
            AllocationSize: info.allocation_size,
            FileSize: info.file_size,
            CreationTime: info.creation_time,
            LastAccessTime: info.last_access_time,
            LastWriteTime: info.last_write_time,
            ChangeTime: info.change_time,
            IndexNumber: info.index_number,
            HardLinks: 0,
            EaSize: 0,
        }
    };
}

/// Runs a callback body, turning a panic into an I/O error.
fn guard(f: impl FnOnce() -> NtStatus) -> NtStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => status::UNEXPECTED_IO_ERROR,
    }
}

fn code(r: fs::Result<()>) -> NtStatus {
    r.err().unwrap_or(status::SUCCESS)
}

unsafe extern "C" fn get_volume_info(fs: Fs, out: *mut VolumeInfo) -> NtStatus {
    guard(|| unsafe {
        let (total, free) = match volume(fs).space() {
            Ok(s) => s,
            Err(e) => return e,
        };
        let label: Vec<u16> = "LCHFS".encode_utf16().collect();
        let mut info = VolumeInfo { TotalSize: total, FreeSize: free, VolumeLabelLength: 0, VolumeLabel: [0; 32] };
        info.VolumeLabel[..label.len()].copy_from_slice(&label);
        info.VolumeLabelLength = (label.len() * 2) as u16;
        *out = info;
        status::SUCCESS
    })
}

/// `GetReparsePointByName`: `Context` is unused; WinFsp's helpers pass a
/// null `Buffer` when only asking whether `name` is a reparse point.
unsafe extern "C" fn reparse_point_by_name(
    fs: Fs,
    _context: *mut c_void,
    name: *mut u16,
    _is_directory: Boolean,
    buffer: *mut c_void,
    size: *mut usize,
) -> NtStatus {
    guard(|| unsafe {
        let path = match string(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match volume(fs).reparse_point_at(&path) {
            Ok(data) => copy_out(&data, buffer, size),
            Err(e) => e,
        }
    })
}

/// Copies reparse data into a caller's buffer of `*size` bytes.
unsafe fn copy_out(data: &[u8], buffer: *mut c_void, size: *mut usize) -> NtStatus {
    if buffer.is_null() || size.is_null() {
        return status::SUCCESS;
    }
    // SAFETY: WinFsp's buffer of `*size` bytes.
    unsafe {
        if *size < data.len() {
            return status::BUFFER_OVERFLOW;
        }
        ptr::copy_nonoverlapping(data.as_ptr(), buffer.cast::<u8>(), data.len());
        *size = data.len();
    }
    status::SUCCESS
}

/// `STATUS_REPARSE`: a path component before the last is a symlink, and
/// WinFsp should resolve it.
const STATUS_REPARSE: NtStatus = 0x0000_0104;

unsafe extern "C" fn get_security_by_name(
    fs: Fs,
    name: *mut u16,
    attributes: *mut u32,
    sd: PSECURITY_DESCRIPTOR,
    sd_size: *mut usize,
) -> NtStatus {
    guard(|| unsafe {
        if (api().FspFileSystemFindReparsePoint)(fs, reparse_point_by_name, null_mut(), name, attributes) != 0 {
            return STATUS_REPARSE;
        }
        let path = match string(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let info = match volume(fs).info_at(&path) {
            Ok(i) => i,
            Err(e) => return e,
        };
        if !attributes.is_null() {
            *attributes = info.attributes;
        }
        give_descriptor(sd, sd_size)
    })
}

fn boxed(handle: Handle) -> Ctx {
    Box::into_raw(Box::new(FileCtx { handle, dir_buffer: null_mut() })).cast()
}

unsafe extern "C" fn create(
    fs: Fs,
    name: *mut u16,
    create_options: u32,
    _granted_access: u32,
    attributes: u32,
    _sd: PSECURITY_DESCRIPTOR,
    _allocation_size: u64,
    out_ctx: *mut Ctx,
    out_info: *mut FspFileInfo,
) -> NtStatus {
    guard(|| unsafe {
        let path = match string(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match volume(fs).create(&path, create_options, attributes) {
            Ok((handle, info)) => {
                *out_ctx = boxed(handle);
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn open(
    fs: Fs,
    name: *mut u16,
    create_options: u32,
    _granted_access: u32,
    out_ctx: *mut Ctx,
    out_info: *mut FspFileInfo,
) -> NtStatus {
    guard(|| unsafe {
        let path = match string(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match volume(fs).open(&path, create_options) {
            Ok((handle, info)) => {
                *out_ctx = boxed(handle);
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn overwrite(
    fs: Fs,
    ctx: Ctx,
    attributes: u32,
    replace: Boolean,
    _allocation_size: u64,
    out_info: *mut FspFileInfo,
) -> NtStatus {
    guard(|| unsafe {
        match volume(fs).overwrite(&file(ctx).handle, attributes, replace != 0) {
            Ok(info) => {
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

/// `FspCleanupDelete`: the last handle of a file marked for deletion.
const CLEANUP_DELETE: u32 = 0x01;

unsafe extern "C" fn cleanup(fs: Fs, _ctx: Ctx, name: *mut u16, flags: u32) {
    guard(|| unsafe {
        if flags & CLEANUP_DELETE != 0
            && let Ok(path) = string(name)
            && let Err(e) = volume(fs).delete(&path)
        {
            tracing::warn!(path, status = format_args!("{e:#x}"), "delete on close failed");
        }
        status::SUCCESS
    });
}

unsafe extern "C" fn close(_fs: Fs, ctx: Ctx) {
    guard(|| unsafe {
        let mut ctx = Box::from_raw(ctx as *mut FileCtx);
        if !ctx.dir_buffer.is_null() {
            (api().FspFileSystemDeleteDirectoryBuffer)(&mut ctx.dir_buffer);
        }
        status::SUCCESS
    });
}

unsafe extern "C" fn read(fs: Fs, ctx: Ctx, buffer: *mut c_void, offset: u64, len: u32, done: *mut u32) -> NtStatus {
    guard(|| unsafe {
        let buf = std::slice::from_raw_parts_mut(buffer.cast::<u8>(), len as usize);
        match volume(fs).read(&file(ctx).handle, offset, buf) {
            Ok(n) => {
                *done = n as u32;
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn write(
    fs: Fs,
    ctx: Ctx,
    buffer: *mut c_void,
    offset: u64,
    len: u32,
    write_to_end: Boolean,
    constrained: Boolean,
    done: *mut u32,
    out_info: *mut FspFileInfo,
) -> NtStatus {
    guard(|| unsafe {
        let data = std::slice::from_raw_parts(buffer.cast::<u8>(), len as usize);
        match volume(fs).write(&file(ctx).handle, offset, data, write_to_end != 0, constrained != 0) {
            Ok((n, info)) => {
                *done = n as u32;
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn flush(fs: Fs, ctx: Ctx, out_info: *mut FspFileInfo) -> NtStatus {
    guard(|| unsafe {
        let handle = (!ctx.is_null()).then(|| &file(ctx).handle);
        match volume(fs).flush(handle) {
            Ok(Some(info)) => {
                put_info(out_info, &info);
                status::SUCCESS
            }
            Ok(None) => status::SUCCESS,
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn get_file_info(fs: Fs, ctx: Ctx, out_info: *mut FspFileInfo) -> NtStatus {
    guard(|| unsafe {
        match volume(fs).info(&file(ctx).handle) {
            Ok(info) => {
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn set_basic_info(
    fs: Fs,
    ctx: Ctx,
    attributes: u32,
    _creation: u64,
    last_access: u64,
    last_write: u64,
    _change: u64,
    out_info: *mut FspFileInfo,
) -> NtStatus {
    guard(|| unsafe {
        match volume(fs).set_basic(&file(ctx).handle, attributes, last_access, last_write) {
            Ok(info) => {
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn set_file_size(
    fs: Fs,
    ctx: Ctx,
    new_size: u64,
    allocation: Boolean,
    out_info: *mut FspFileInfo,
) -> NtStatus {
    guard(|| unsafe {
        match volume(fs).set_size(&file(ctx).handle, new_size, allocation != 0) {
            Ok(info) => {
                put_info(out_info, &info);
                status::SUCCESS
            }
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn can_delete(fs: Fs, ctx: Ctx, _name: *mut u16) -> NtStatus {
    guard(|| unsafe { code(volume(fs).can_delete(&file(ctx).handle)) })
}

unsafe extern "C" fn rename(fs: Fs, ctx: Ctx, from: *mut u16, to: *mut u16, replace: Boolean) -> NtStatus {
    guard(|| unsafe {
        let (from, to) = match (string(from), string(to)) {
            (Ok(f), Ok(t)) => (f, t),
            (Err(e), _) | (_, Err(e)) => return e,
        };
        code(volume(fs).rename(&file(ctx).handle, &from, &to, replace != 0))
    })
}

unsafe extern "C" fn get_security(_fs: Fs, _ctx: Ctx, sd: PSECURITY_DESCRIPTOR, size: *mut usize) -> NtStatus {
    guard(|| unsafe { give_descriptor(sd, size) })
}

/// Builds one `FSP_FSCTL_DIR_INFO` with its name in 8-byte-aligned
/// storage, and hands it to WinFsp's directory buffer.
unsafe fn fill(buffer: *mut *mut c_void, item: &DirItem, result: &mut NtStatus) -> bool {
    let name: Vec<u16> = item.name.encode_utf16().collect();
    let bytes = std::mem::size_of::<DirInfo>() + name.len() * 2;
    let mut storage = vec![0u64; bytes.div_ceil(8)];
    let di = storage.as_mut_ptr().cast::<DirInfo>();
    // SAFETY: `storage` is large and aligned enough for the header and name.
    unsafe {
        (*di).Size = bytes as u16;
        put_info(&mut (*di).FileInfo, &item.info);
        let dst = di.cast::<u8>().add(std::mem::size_of::<DirInfo>()).cast::<u16>();
        ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
        (api().FspFileSystemFillDirectoryBuffer)(buffer, di, result) != 0
    }
}

unsafe extern "C" fn read_directory(
    fs: Fs,
    ctx: Ctx,
    _pattern: *mut u16,
    marker: *mut u16,
    buffer: *mut c_void,
    len: u32,
    done: *mut u32,
) -> NtStatus {
    guard(|| unsafe {
        let f = file(ctx);
        let api = api();
        let mut result = status::SUCCESS;
        // A null marker starts a new listing, so the cache is rebuilt.
        if (api.FspFileSystemAcquireDirectoryBuffer)(&mut f.dir_buffer, marker.is_null() as Boolean, &mut result) != 0 {
            match volume(fs).list(&f.handle) {
                Ok(items) => {
                    for item in &items {
                        if !fill(&mut f.dir_buffer, item, &mut result) {
                            break;
                        }
                    }
                }
                Err(e) => result = e,
            }
            (api.FspFileSystemReleaseDirectoryBuffer)(&mut f.dir_buffer);
        }
        if result < 0 {
            return result;
        }
        (api.FspFileSystemReadDirectoryBuffer)(&mut f.dir_buffer, marker, buffer, len, done);
        status::SUCCESS
    })
}

unsafe extern "C" fn resolve_reparse_points(
    fs: Fs,
    name: *mut u16,
    index: u32,
    resolve_last: Boolean,
    io_status: *mut c_void,
    buffer: *mut c_void,
    size: *mut usize,
) -> NtStatus {
    guard(|| unsafe {
        (api().FspFileSystemResolveReparsePoints)(
            fs,
            reparse_point_by_name,
            null_mut(),
            name,
            index,
            resolve_last,
            io_status,
            buffer,
            size,
        )
    })
}

unsafe extern "C" fn get_reparse_point(
    fs: Fs,
    ctx: Ctx,
    _name: *mut u16,
    buffer: *mut c_void,
    size: *mut usize,
) -> NtStatus {
    guard(|| unsafe {
        match volume(fs).reparse_data(file(ctx).handle.ino()) {
            Ok(data) => copy_out(&data, buffer, size),
            Err(e) => e,
        }
    })
}

unsafe extern "C" fn set_reparse_point(fs: Fs, ctx: Ctx, name: *mut u16, buffer: *mut c_void, size: usize) -> NtStatus {
    guard(|| unsafe {
        let path = match string(name) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let data = std::slice::from_raw_parts(buffer.cast::<u8>(), size);
        code(volume(fs).set_symlink(&file(ctx).handle, &path, data))
    })
}

static INTERFACE: FspFileSystemInterface = FspFileSystemInterface {
    GetVolumeInfo: Some(get_volume_info),
    SetVolumeLabel: None,
    GetSecurityByName: Some(get_security_by_name),
    Create: Some(create),
    Open: Some(open),
    Overwrite: Some(overwrite),
    Cleanup: Some(cleanup),
    Close: Some(close),
    Read: Some(read),
    Write: Some(write),
    Flush: Some(flush),
    GetFileInfo: Some(get_file_info),
    SetBasicInfo: Some(set_basic_info),
    SetFileSize: Some(set_file_size),
    CanDelete: Some(can_delete),
    Rename: Some(rename),
    GetSecurity: Some(get_security),
    SetSecurity: None,
    ReadDirectory: Some(read_directory),
    ResolveReparsePoints: Some(resolve_reparse_points),
    GetReparsePoint: Some(get_reparse_point),
    SetReparsePoint: Some(set_reparse_point),
    DeleteReparsePoint: None,
    GetStreamInfo: None,
    GetDirInfoByName: None,
    Control: None,
    SetDelete: None,
    CreateEx: None,
    OverwriteEx: None,
    GetEa: None,
    SetEa: None,
    Obsolete0: None,
    DispatcherStopped: None,
    Reserved: [None; 31],
};

// ---------------------------------------------------------------------------
// Mounting.
// ---------------------------------------------------------------------------

/// A mounted volume. Unmounts, and stops serving, when dropped.
pub struct Mount {
    fs: Fs,
    volume: *mut Volume,
}

// SAFETY: the WinFsp object may be stopped and deleted from any thread.
unsafe impl Send for Mount {}

fn check(what: &str, s: NtStatus) -> Result<(), String> {
    if s < 0 { Err(format!("{what} failed: NtStatus {:#010x}", s as u32)) } else { Ok(()) }
}

impl Mount {
    /// Mounts `volume` at `mount_point` (`X:`, or an empty directory that
    /// does not exist yet), or at the next free drive letter from Z: down.
    pub fn new(volume: Volume, mount_point: Option<&str>, serial: u32) -> Result<Mount, String> {
        load()?;
        let api = api();
        let mut params: VolumeParams = unsafe { std::mem::zeroed() };
        params.Version = std::mem::size_of::<VolumeParams>() as u16;
        params.SectorSize = 512;
        params.SectorsPerAllocationUnit = (fs::ALLOCATION_UNIT / 512) as u16;
        params.MaxComponentLength = 255;
        params.VolumeCreationTime = fs::filetime(now());
        params.VolumeSerialNumber = serial;
        // The engine keeps its own caches; the kernel's are kept short, as
        // the FUSE frontend's TTL is.
        params.FileInfoTimeout = 1000;
        params.flags = vp::CASE_PRESERVED_NAMES
            | vp::UNICODE_ON_DISK
            | vp::REPARSE_POINTS
            | vp::POST_CLEANUP_WHEN_MODIFIED_ONLY
            | vp::UM_FILE_CONTEXT_IS_USER_CONTEXT2;
        if volume.read_only() {
            params.flags |= vp::READ_ONLY_VOLUME;
        }
        let name: Vec<u16> = "LCHFS".encode_utf16().collect();
        params.FileSystemName[..name.len()].copy_from_slice(&name);

        let device = wide("WinFsp.Disk");
        let mut fs: Fs = null_mut();
        // SAFETY: valid parameters; `INTERFACE` is static.
        check("FspFileSystemCreate", unsafe {
            (api.FspFileSystemCreate)(device.as_ptr(), &params, &INTERFACE, &mut fs)
        })?;
        let volume = Box::into_raw(Box::new(volume));
        // SAFETY: `fs` was just created; nothing reads `UserContext` until
        // the dispatcher starts.
        unsafe { (*fs).UserContext = volume.cast() };
        let mount = Mount { fs, volume };
        let point = mount_point.map(wide);
        // SAFETY: a live file system; a NUL-terminated mount point or null.
        check("mounting", unsafe {
            (api.FspFileSystemSetMountPoint)(fs, point.as_ref().map_or(ptr::null(), |p| p.as_ptr()))
        })?;
        // SAFETY: as above. 0 threads: WinFsp picks from the CPU count.
        check("starting the dispatcher", unsafe { (api.FspFileSystemStartDispatcher)(fs, 0) })?;
        Ok(mount)
    }

    /// Where it is mounted, e.g. `Z:`.
    pub fn mount_point(&self) -> String {
        // SAFETY: `MountPoint` follows `DispatcherResult` in
        // `FSP_FILE_SYSTEM`; see `mount_point_ptr`.
        unsafe { string(mount_point_ptr(self.fs)).unwrap_or_default() }
    }

    pub fn volume(&self) -> &Volume {
        // SAFETY: freed only in `drop`.
        unsafe { &*self.volume }
    }
}

/// `FSP_FILE_SYSTEM::MountPoint`, at the offset winfsp.h gives it on
/// 64-bit: after Version, UserContext, VolumeName[256 WCHARs],
/// VolumeHandle, EnterOperation, LeaveOperation, Operations[22],
/// Interface, DispatcherThread, DispatcherThreadCount, DispatcherResult.
unsafe fn mount_point_ptr(fs: Fs) -> *const u16 {
    #[cfg(target_pointer_width = "64")]
    const OFFSET: usize = 8 + 8 + 512 + 8 + 8 + 8 + 22 * 8 + 8 + 8 + 4 + 4;
    #[cfg(target_pointer_width = "32")]
    const OFFSET: usize = 4 + 4 + 512 + 4 + 4 + 4 + 22 * 4 + 4 + 4 + 4 + 4;
    // SAFETY: `fs` is a live FSP_FILE_SYSTEM, which is larger than OFFSET.
    unsafe { *(fs.cast::<u8>().add(OFFSET) as *const *const u16) }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let api = api();
        // SAFETY: stopping before deleting means no callback is running,
        // or will run, when the volume is freed.
        unsafe {
            (api.FspFileSystemStopDispatcher)(self.fs);
            (api.FspFileSystemDelete)(self.fs);
            drop(Box::from_raw(self.volume));
        }
    }
}

fn now() -> (i64, u32) {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos())
}
