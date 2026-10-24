//! The modules, as Windows 2000's kernel32 serves them: GetModuleHandle and LoadLibrary (A and W),
//! FreeLibrary, GetProcAddress and DisableThreadLibraryCalls over ntdll's loader (LdrGetDllHandle,
//! LdrLoadDll, LdrUnloadDll, LdrGetProcedureAddress, LdrDisableThreadCalloutsForDll), and
//! GetModuleFileName (A and W) over the PEB's module lists, which it walks itself under the loader
//! lock, as Windows 2000's does.
//!
//! A module name converts as Windows 2000's converts it, into a MAX_PATH-character Unicode string
//! (Basep8BitStringToStaticUnicodeString): a longer one is ERROR_FILENAME_EXCED_RANGE, never cut
//! down to fit (which would make a name with a tail past MAX_PATH find kernel32).

use rtl::status::nt_success;

use crate::base::{
    peb,
    read,
    read_pointer,
    set_last_error,
    set_last_nt_error,
    unicode_string,
    units,
    wide_string,
    Text,
};
use crate::files::widen;
use crate::nt::{self, AnsiString};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const STATUS_ORDINAL_NOT_FOUND: u32 = 0xC000_0138;
const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0139;

/// The PEB's ImageBaseAddress, Ldr and LoaderLock.
const PEB_IMAGE_BASE_ADDRESS: usize = 0x08;
const PEB_LDR: usize = 0x0C;
const PEB_LOADER_LOCK: usize = 0xA0;
/// PEB_LDR_DATA's InLoadOrderModuleList, and an LDR_DATA_TABLE_ENTRY's DllBase and FullDllName (its
/// InLoadOrderLinks lead it).
const IN_LOAD_ORDER_MODULE_LIST: usize = 0x0C;
const DLL_BASE: usize = 0x18;
const FULL_DLL_NAME: usize = 0x24;
/// How many entries the walk visits at most (a list corrupted into a cycle ends there).
const MAX_ENTRIES: usize = 1024;

/// The image's handle: its base, the PEB's ImageBaseAddress.
fn image_base() -> u32 {
    read(peb() + PEB_IMAGE_BASE_ADDRESS)
}

/// A loader call: the module's handle (LdrGetDllHandle, LdrLoadDll).
type Loader =
    unsafe extern "system" fn(*const u16, *const u32, *const nt::UnicodeString, *mut u32) -> u32;

/// A loader call over the module name `name` (ANSI), converted to Unicode first; its handle, or 0
/// with the last error set (ERROR_FILENAME_EXCED_RANGE past MAX_PATH, the status's error
/// otherwise).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
unsafe fn by_name(name: *const u8, call: Loader) -> u32 {
    // SAFETY: the caller's string.
    let Some(mut wide) = (unsafe { widen(name) }) else {
        return 0;
    };
    let length = wide.length;
    let string = unicode_string(&mut wide.units, length);
    by_string(&string, call)
}

/// A loader call over the UTF-16 module name `name`, as given: its handle, or 0 with the status's
/// error.
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
unsafe fn by_name_w(name: *const u16, call: Loader) -> u32 {
    // SAFETY: the caller's string.
    let string = unsafe { wide_string(name) };
    by_string(&string, call)
}

/// The loader call over `string`.
fn by_string(string: &nt::UnicodeString, call: Loader) -> u32 {
    let mut handle = 0;
    // SAFETY: ntdll's export, over the caller's string.
    let status = unsafe { call(core::ptr::null(), core::ptr::null(), string, &mut handle) };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    handle
}

/// GetModuleHandleA: the image's handle for a null name (the PEB's ImageBaseAddress), else the
/// handle of the module the name names (LdrGetDllHandle: ERROR_MOD_NOT_FOUND for none).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleHandleA")]
pub unsafe extern "system" fn get_module_handle_a(name: *const u8) -> u32 {
    if name.is_null() {
        return image_base();
    }
    // SAFETY: the caller's string; ntdll's export.
    unsafe { by_name(name, nt::LdrGetDllHandle) }
}

/// GetModuleHandleW (as [`get_module_handle_a`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated UTF-16 string (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleHandleW")]
pub unsafe extern "system" fn get_module_handle_w(name: *const u16) -> u32 {
    if name.is_null() {
        return image_base();
    }
    // SAFETY: the caller's string; ntdll's export.
    unsafe { by_name_w(name, nt::LdrGetDllHandle) }
}

/// LoadLibraryA: the module the name names, loaded (LdrLoadDll: one the process has, or one it
/// finds on the volume; ERROR_MOD_NOT_FOUND for none). A null name is ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// As [`get_module_handle_a`].
#[unsafe(export_name = "f2k_export_LoadLibraryA")]
pub unsafe extern "system" fn load_library_a(name: *const u8) -> u32 {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string; ntdll's export.
    unsafe { by_name(name, nt::LdrLoadDll) }
}

/// LoadLibraryW (as [`load_library_a`]).
///
/// # Safety
///
/// As [`get_module_handle_w`].
#[unsafe(export_name = "f2k_export_LoadLibraryW")]
pub unsafe extern "system" fn load_library_w(name: *const u16) -> u32 {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string; ntdll's export.
    unsafe { by_name_w(name, nt::LdrLoadDll) }
}

/// FreeLibrary: one reference to the module fewer (LdrUnloadDll: a loaded module's last goes with
/// it; the modules the process starts with stay). ERROR_MOD_NOT_FOUND for a handle naming no
/// module, as Windows 2000 maps LdrUnloadDll's STATUS_DLL_NOT_FOUND.
#[unsafe(export_name = "f2k_export_FreeLibrary")]
pub extern "system" fn free_library(module: u32) -> u32 {
    // SAFETY: ntdll's export.
    let status = unsafe { nt::LdrUnloadDll(module) };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// DisableThreadLibraryCalls: the DLL whose handle is `module` gets no DLL_THREAD_ATTACH and
/// DLL_THREAD_DETACH from now on (LdrDisableThreadCalloutsForDll). A handle naming no module is
/// TRUE too, the last error untouched (the dllmain capture); a failed call is FALSE with its
/// status's error.
#[unsafe(export_name = "f2k_export_DisableThreadLibraryCalls")]
pub extern "system" fn disable_thread_library_calls(module: u32) -> u32 {
    // SAFETY: ntdll's export.
    let status = unsafe { nt::LdrDisableThreadCalloutsForDll(module) };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// The longest export name GetProcAddress hands the loader (an ANSI_STRING's length is a word):
/// a longer one names no export.
const MAX_EXPORT_NAME: usize = 0xFFFE;

/// GetProcAddress: the address of the module's export (the image's for a null handle) named
/// `name`, exactly (LdrGetProcedureAddress, forwarders followed), or of the ordinal a value below
/// 0x10000 in its place is (the system DLLs' ordinals are their export specs' numbering; a null
/// name is ordinal 0). ERROR_PROC_NOT_FOUND for a name the module does not export,
/// ERROR_INVALID_ORDINAL for an ordinal it does not, ERROR_INVALID_PARAMETER for ordinal 0,
/// ERROR_MOD_NOT_FOUND for a handle naming no module; an export at the module's own base is no
/// export (Windows 2000's check).
///
/// # Safety
///
/// `name` is an ordinal (below 0x10000) or a NUL-terminated string (a bad pointer faults the
/// caller).
#[unsafe(export_name = "f2k_export_GetProcAddress")]
pub unsafe extern "system" fn get_proc_address(module: u32, name: *const u8) -> u32 {
    let module = if module == 0 { image_base() } else { module };
    let by_name = name as usize > 0xFFFF;
    let mut address = 0;
    let status = if by_name {
        // SAFETY: the caller's string, read to its terminator (or past the longest name).
        let length = (0..=MAX_EXPORT_NAME).find(|&at| unsafe { name.add(at).read() } == 0);
        match length {
            Some(length) => {
                let string = AnsiString {
                    length: length as u16,
                    maximum_length: length as u16 + 1,
                    buffer: name as *mut u8,
                };
                // SAFETY: ntdll's export, over the string above.
                unsafe { nt::LdrGetProcedureAddress(module, &string, 0, &mut address) }
            }
            None => STATUS_ENTRYPOINT_NOT_FOUND,
        }
    } else {
        // SAFETY: ntdll's export.
        unsafe { nt::LdrGetProcedureAddress(module, core::ptr::null(), name as u32, &mut address) }
    };
    let status = match status {
        0 if address == module => {
            if by_name {
                STATUS_ENTRYPOINT_NOT_FOUND
            } else {
                STATUS_ORDINAL_NOT_FOUND
            }
        }
        status => status,
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    address
}

/// The entry of the module whose handle is `module`, walking the PEB's InLoadOrderModuleList.
fn entry_of(module: u32) -> Option<usize> {
    let head = read_pointer(peb() + PEB_LDR) + IN_LOAD_ORDER_MODULE_LIST;
    let mut next = read_pointer(head);
    for _ in 0..MAX_ENTRIES {
        if next == head || next == 0 {
            return None;
        }
        if read_pointer(next + DLL_BASE) as u32 == module {
            return Some(next);
        }
        next = read_pointer(next);
    }
    None
}

/// GetModuleFileNameW's work: the module's full path (the image's for a null handle), its
/// FullDllName in the PEB's lists, into the caller's buffer, terminated when it fits; its length.
/// Windows 2000's truncation: a buffer too small takes exactly its size, unterminated, and that
/// size comes back, the last error untouched. ERROR_MOD_NOT_FOUND for a handle naming no module,
/// the buffer untouched.
///
/// # Safety
///
/// `buffer` holds `size` characters (a bad pointer faults the caller).
unsafe fn module_file_name(module: u32, buffer: Text, size: u32) -> u32 {
    let module = if module == 0 { image_base() } else { module };
    let lock = read_pointer(peb() + PEB_LOADER_LOCK) as *mut u8;
    // SAFETY: ntdll's export, on the PEB's loader lock.
    unsafe { nt::RtlEnterCriticalSection(lock) };
    let copied = entry_of(module).map(|entry| {
        // SAFETY: the module's own path, in the lists.
        let path = unsafe { units(entry + FULL_DLL_NAME) };
        let copy = path.len().min(size as usize);
        // SAFETY: the caller's buffer holds `size` characters.
        unsafe { buffer.put(&path[..copy]) };
        if copy < size as usize {
            // SAFETY: as above.
            unsafe { buffer.put_unit(copy, 0) };
        }
        copy as u32
    });
    // SAFETY: as above.
    unsafe { nt::RtlLeaveCriticalSection(lock) };
    copied.unwrap_or_else(|| {
        set_last_error(ERROR_MOD_NOT_FOUND);
        0
    })
}

/// GetModuleFileNameA (see [`module_file_name`]): the path narrowed.
///
/// # Safety
///
/// `buffer` holds `size` bytes (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleFileNameA")]
pub unsafe extern "system" fn get_module_file_name_a(
    module: u32,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: the caller's buffer.
    unsafe { module_file_name(module, Text::Ansi(buffer), size) }
}

/// GetModuleFileNameW (see [`module_file_name`]).
///
/// # Safety
///
/// `buffer` holds `size` characters (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleFileNameW")]
pub unsafe extern "system" fn get_module_file_name_w(
    module: u32,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    // SAFETY: the caller's buffer.
    unsafe { module_file_name(module, Text::Wide(buffer), size) }
}
