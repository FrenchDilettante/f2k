//! The loader's exports over the process's module lists (the PEB's Ldr, which the kernel builds at
//! the process's creation: see `rtl::modules`): LdrGetDllHandle, LdrLoadDll and LdrUnloadDll find a
//! module by its name or handle and count its references, LdrGetProcedureAddress finds an export,
//! under the loader lock (the PEB's LoaderLock), as Windows 2000's do. kernel32's GetModuleHandleA,
//! LoadLibraryA, FreeLibrary and GetProcAddress are over them.
//!
//! No module loads from disk yet: LdrLoadDll finds a module the process already has (its image,
//! ntdll, kernel32) or fails with STATUS_DLL_NOT_FOUND; LdrUnloadDll never unmaps one. A module
//! name with a path is made absolute against the current directory and matched against the
//! modules' full paths, as Windows 2000 matches it (without its search along the DLL path, and
//! without opening the file to compare a module reached through another path).

use rtl::modules::{self, entry, Memory};
use rtl::path::MAX_PATH;
use rtl::status::{STATUS_DLL_NOT_FOUND, STATUS_SUCCESS};
use rtl::sys::{self, Native};

use crate::curdir::{self, UnicodeString};

/// The process's own memory, read in place (a bad pointer faults the caller, as on Windows 2000).
struct Mapped;

impl Memory for Mapped {
    fn byte(&self, at: u32) -> u8 {
        // SAFETY: the lists, the images and the strings they name are the process's own.
        unsafe { (at as usize as *const u8).read_volatile() }
    }

    fn half(&self, at: u32) -> u16 {
        // SAFETY: as above.
        unsafe { (at as usize as *const u16).read_unaligned() }
    }

    fn word(&self, at: u32) -> u32 {
        // SAFETY: as above.
        unsafe { (at as usize as *const u32).read_unaligned() }
    }
}

/// The process's PEB_LDR_DATA.
fn ldr() -> u32 {
    sys::read(sys::peb() + modules::peb::LDR as usize) as u32
}

/// `body`, the loader lock held.
fn locked<T>(body: impl FnOnce() -> T) -> T {
    let lock = sys::loader_lock();
    lock.enter(&Native);
    let answer = body();
    lock.leave(&Native);
    answer
}

/// An ANSI_STRING: its length and room in bytes, and its buffer.
#[repr(C)]
pub struct AnsiString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u8,
}

/// The entry of the module `name` names (see `rtl::modules::by_name`; a name with a path made
/// absolute first, RtlGetFullPathName_U's way). Under the loader lock.
fn find(name: &[u16]) -> Option<u32> {
    // The name with its default extension, terminated (the zeroes past it).
    let mut formed = [0u16; MAX_PATH + 8];
    let length = modules::module_name(name, &mut formed[..MAX_PATH + 7])?;
    if !modules::has_path(&formed[..length]) {
        return modules::by_name(&Mapped, ldr(), &formed[..length]);
    }
    let mut full = [0u16; MAX_PATH + 1];
    // SAFETY: the formed name is terminated; the buffer holds MAX_PATH + 1 units.
    let bytes = unsafe {
        curdir::rtl_get_full_path_name_u(formed.as_ptr(), 2 * full.len() as u32, full.as_mut_ptr(), core::ptr::null_mut())
    } as usize;
    if bytes == 0 || bytes >= 2 * full.len() {
        return None; // no full path, or none that fits: no module has it
    }
    modules::by_name(&Mapped, ldr(), &full[..bytes / 2])
}

/// The module's handle (its base).
fn base_of(entry: u32) -> u32 {
    Mapped.word(entry + entry::DLL_BASE)
}

/// Replace a module's load count.
fn set_load_count(entry: u32, count: u16) {
    // SAFETY: the entry is the process's own, on its writable parameters pages.
    unsafe { ((entry + entry::LOAD_COUNT) as usize as *mut u16).write_unaligned(count) }
}

/// LdrGetDllHandle: the handle of the module `name` names, into `handle` (zero when none does,
/// STATUS_DLL_NOT_FOUND). The search path and the characteristics are not consulted.
///
/// # Safety
///
/// `name` is a UNICODE_STRING whose buffer holds its length; `handle` points at a dword.
#[unsafe(export_name = "f2k_export_LdrGetDllHandle")]
pub unsafe extern "system" fn ldr_get_dll_handle(
    _path: *const u16,
    _characteristics: *const u32,
    name: *const UnicodeString,
    handle: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { (*name).units() };
    let found = locked(|| find(name).map(base_of));
    // SAFETY: the caller's handle.
    unsafe { handle.write(found.unwrap_or(0)) };
    found.map_or(STATUS_DLL_NOT_FOUND, |_| STATUS_SUCCESS)
}

/// LdrLoadDll: the module `name` names — one the process already has, F2K loading nothing from disk
/// (STATUS_DLL_NOT_FOUND for any other) — its load count raised (a static module's stays); its
/// handle into `handle`.
///
/// # Safety
///
/// As [`ldr_get_dll_handle`].
#[unsafe(export_name = "f2k_export_LdrLoadDll")]
pub unsafe extern "system" fn ldr_load_dll(
    _path: *const u16,
    _characteristics: *const u32,
    name: *const UnicodeString,
    handle: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { (*name).units() };
    let found = locked(|| {
        let entry = find(name)?;
        set_load_count(entry, modules::referenced(Mapped.half(entry + entry::LOAD_COUNT)));
        Some(base_of(entry))
    });
    // SAFETY: the caller's handle.
    unsafe { handle.write(found.unwrap_or(0)) };
    found.map_or(STATUS_DLL_NOT_FOUND, |_| STATUS_SUCCESS)
}

/// LdrUnloadDll: the module whose handle is `module` has one reference fewer (a static module's
/// count stays; none is ever unmapped). STATUS_DLL_NOT_FOUND for a handle naming no module.
#[unsafe(export_name = "f2k_export_LdrUnloadDll")]
pub extern "system" fn ldr_unload_dll(module: u32) -> u32 {
    locked(|| match modules::by_base(&Mapped, ldr(), module) {
        Some(entry) => {
            set_load_count(entry, modules::released(Mapped.half(entry + entry::LOAD_COUNT)));
            STATUS_SUCCESS
        }
        None => STATUS_DLL_NOT_FOUND,
    })
}

/// LdrGetProcedureAddress: the address of the export `name` (or, with no name, of the ordinal
/// `ordinal`) of the module whose handle is `module`, forwarders followed, into `address` (see
/// `rtl::modules::procedure_address` for the statuses; an ordinal finds nothing yet).
///
/// # Safety
///
/// `name` is null or an ANSI_STRING whose buffer holds its length; `address` points at a dword.
#[unsafe(export_name = "f2k_export_LdrGetProcedureAddress")]
pub unsafe extern "system" fn ldr_get_procedure_address(
    module: u32,
    name: *const AnsiString,
    ordinal: u32,
    address: *mut u32,
) -> u32 {
    // SAFETY: the caller's string, when given.
    let name = unsafe { name.as_ref() }.map(|name| {
        if name.length == 0 {
            &[][..]
        } else {
            // SAFETY: as above.
            unsafe { core::slice::from_raw_parts(name.buffer, usize::from(name.length)) }
        }
    });
    let found = locked(|| match name {
        Some(name) => modules::procedure_address(&Mapped, ldr(), module, name),
        None => modules::procedure_by_ordinal(&Mapped, ldr(), module, ordinal),
    });
    match found {
        Ok(found) => {
            // SAFETY: the caller's address.
            unsafe { address.write(found) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}
