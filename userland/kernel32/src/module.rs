//! The modules, as Windows 2000's kernel32 serves them: GetModuleHandle, LoadLibrary and
//! LoadLibraryEx (A and W), FreeLibrary, GetProcAddress and DisableThreadLibraryCalls over ntdll's
//! loader (LdrGetDllHandle, LdrLoadDll, LdrUnloadDll, LdrGetProcedureAddress,
//! LdrDisableThreadCalloutsForDll), and GetModuleFileName (A and W) over the PEB's module lists,
//! which it walks itself under the loader lock, as Windows 2000's does.
//!
//! LoadLibraryEx's LOAD_LIBRARY_AS_DATAFILE maps a DLL the process has not loaded as a plain file
//! (a read-only view of a data section, NtCreateSection and NtMapViewOfSection): its handle is the
//! view's base with the low bit set, a mapping the loader's lists do not hold (GetModuleHandle does
//! not find it, GetProcAddress finds nothing in it), which FreeLibrary unmaps.
//!
//! A module name converts as Windows 2000's converts it, into a MAX_PATH-character Unicode string
//! (Basep8BitStringToStaticUnicodeString): a longer one is ERROR_FILENAME_EXCED_RANGE, never cut
//! down to fit (which would make a name with a tail past MAX_PATH find kernel32).

use rtl::peb::{LdrDataTableEntry, PebLdrData};
use rtl::status::{STATUS_ENTRYPOINT_NOT_FOUND, STATUS_ORDINAL_NOT_FOUND};
use rtl::winerror::{
    ERROR_BAD_EXE_FORMAT,
    ERROR_FILENAME_EXCED_RANGE,
    ERROR_INVALID_PARAMETER,
    ERROR_MOD_NOT_FOUND,
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_PATH_NOT_FOUND,
};

use crate::base::{last_error, set_last_error, unicode_string, CURRENT_PROCESS};
use crate::edge::{ansi_into, counted, wide_units, CallerChar, CallerStr, InStr, OutBuf, Text};
use crate::error::{answer, bool_answer, Failure};
use crate::files::search::search_default;
use crate::files::{self, NtPath, Wide};
use crate::heap::Owned;
use crate::nt::{AnsiString, UnicodeString};
use crate::ntcall::{self, LoaderLock, NtStatus, View};

/// The ANSI path limit: a module name's longest, in characters.
const MAX_PATH: usize = 260;

/// How many entries the walk visits at most (a list corrupted into a cycle ends there).
const MAX_ENTRIES: usize = 1024;

/// The image's handle: its base, the PEB's ImageBaseAddress.
fn image_base() -> u32 {
    crate::base::image_base() as u32
}

/// The characteristic LdrLoadDll is handed for DONT_RESOLVE_DLL_REFERENCES.
const IMAGE_FILE_EXECUTABLE_IMAGE: u32 = 0x0002;

/// A loader call: the module's handle (LdrGetDllHandle, LdrLoadDll; the second also unresolved).
#[derive(Clone, Copy)]
enum Loader {
    Handle,
    Load,
    LoadUnresolved,
}

impl Loader {
    /// The loader call over the module name.
    fn call(self, name: &UnicodeString) -> Result<u32, NtStatus> {
        match self {
            Loader::Handle => ntcall::get_dll_handle(name),
            Loader::Load => ntcall::load_dll(name),
            Loader::LoadUnresolved => {
                ntcall::load_dll_with(name, Some(IMAGE_FILE_EXECUTABLE_IMAGE))
            }
        }
    }
}

/// A module name as GetModuleHandle and LoadLibrary are handed it: an A call's is converted to
/// Unicode first into a MAX_PATH-character buffer (ERROR_FILENAME_EXCED_RANGE past it), a W call's
/// is taken as given.
type Name<'a> = CallerStr<'a>;

/// A loader call over the module name: its handle, or the failure (ERROR_FILENAME_EXCED_RANGE
/// past MAX_PATH for an A call's name, the status otherwise).
fn by_name(name: Name<'_>, call: Loader) -> Result<u32, Failure> {
    let handle = match name {
        CallerStr::Ansi(name) => {
            let mut units = [0u16; MAX_PATH + 1];
            let length = ansi_into(Some(&name), &mut units)
                .ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))?;
            call.call(&unicode_string(&mut units, length))
        }
        CallerStr::Wide(name) => call.call(&counted(&name)),
    };
    handle.map_err(Failure::Status)
}

/// GetModuleHandle's and LoadLibrary's answer for a name given or none: for none, the image's
/// handle (GetModuleHandle) or ERROR_INVALID_PARAMETER (LoadLibrary); for a name, the loader
/// call's answer.
fn module(name: Option<Name<'_>>, call: Loader) -> u32 {
    match name {
        None if matches!(call, Loader::Handle) => image_base(),
        None => {
            set_last_error(ERROR_INVALID_PARAMETER);
            0
        }
        Some(name) => answer(by_name(name, call), 0),
    }
}

/// GetModuleHandle's and LoadLibrary's export body, either form (see [`module`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string of the form's characters (a bad pointer faults the
/// caller).
unsafe fn module_as<C: CallerChar>(name: *const C, call: Loader) -> u32 {
    // SAFETY: the caller's string, when given (the contract).
    let name = unsafe { C::optional_string(name) };
    module(name, call)
}

/// GetModuleHandleA: the image's handle for a null name (the PEB's ImageBaseAddress), else the
/// handle of the module the name names (LdrGetDllHandle: ERROR_MOD_NOT_FOUND for none).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleHandleA")]
pub unsafe extern "system" fn get_module_handle_a(name: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { module_as(name, Loader::Handle) }
}

/// GetModuleHandleW (as [`get_module_handle_a`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated UTF-16 string (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_GetModuleHandleW")]
pub unsafe extern "system" fn get_module_handle_w(name: *const u16) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { module_as(name, Loader::Handle) }
}

/// LoadLibraryA: the module the name names, loaded (LdrLoadDll: one the process has, or one it
/// finds on the volume; ERROR_MOD_NOT_FOUND for none). A null name is ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// As [`get_module_handle_a`].
#[unsafe(export_name = "f2k_export_LoadLibraryA")]
pub unsafe extern "system" fn load_library_a(name: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { module_as(name, Loader::Load) }
}

/// LoadLibraryW (as [`load_library_a`]).
///
/// # Safety
///
/// As [`get_module_handle_w`].
#[unsafe(export_name = "f2k_export_LoadLibraryW")]
pub unsafe extern "system" fn load_library_w(name: *const u16) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { module_as(name, Loader::Load) }
}

/// LoadLibraryEx's flags.
const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x0000_0001;
const LOAD_LIBRARY_AS_DATAFILE: u32 = 0x0000_0002;

/// The extension a data file's name without one is looked for with.
const DLL_EXTENSION: [u16; 4] = [b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16];

/// LoadLibraryEx's work, either form: LOAD_LIBRARY_AS_DATAFILE a loaded module's reference or the
/// file mapped as data ([`load_as_datafile`]); DONT_RESOLVE_DLL_REFERENCES a module loaded without
/// its imports snapped or its entry point called (LdrLoadDll's IMAGE_FILE_EXECUTABLE_IMAGE);
/// otherwise LoadLibrary's load. The file handle is reserved and not read, and the flags Windows
/// 2000 does not know are passed over (the dll capture's 0x80000000 loads). The search is the
/// default one whatever LOAD_WITH_ALTERED_SEARCH_PATH says: F2K's loader does not consult a search
/// path, so a module with a path of its own is loaded from there and its imports looked for where
/// any module's are.
fn load_library_ex(name: Option<Name<'_>>, flags: u32) -> u32 {
    let Some(name) = name else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if flags & LOAD_LIBRARY_AS_DATAFILE != 0 {
        return answer(load_as_datafile(name), 0);
    }
    let call = if flags & DONT_RESOLVE_DLL_REFERENCES != 0 {
        Loader::LoadUnresolved
    } else {
        Loader::Load
    };
    answer(by_name(name, call), 0)
}

/// LOAD_LIBRARY_AS_DATAFILE: a module the process has loaded is referenced once more and its handle
/// handed back (the dll capture: FreeLibrary of it leaves the module loaded); otherwise the file
/// the default search finds (".dll" added to a name without an extension; ERROR_FILE_NOT_FOUND
/// for none) is mapped read-only as data, its headers an image's (ERROR_BAD_EXE_FORMAT
/// otherwise), and the view's base with its low bit set is the handle. The last error is cleared
/// then, as the capture shows.
fn load_as_datafile(name: Name<'_>) -> Result<u32, Failure> {
    if by_name(name, Loader::Handle).is_ok() {
        return by_name(name, Loader::Load);
    }
    let mut converted = [0u16; MAX_PATH + 1];
    let copied;
    let units: &[u16] = match name {
        CallerStr::Ansi(name) => {
            let length = ansi_into(Some(&name), &mut converted)
                .ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))?;
            &converted[..length]
        }
        CallerStr::Wide(name) => {
            copied = wide_units(&name).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
            &copied
        }
    };
    let name = Wide::of(units).ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))?;
    let extension = Wide::of(&DLL_EXTENSION).expect("a short extension");
    let path = search_default(&name, &extension).ok_or_else(|| Failure::Error(last_error()))?;
    let base = map_datafile(&path)?;
    set_last_error(0);
    Ok(base as u32 | 1)
}

/// The access, the sharing and the options a data file is opened with, and its section's.
const DATAFILE_ACCESS: u32 = files::GENERIC_READ | files::SYNCHRONIZE;
const DATAFILE_SHARE: u32 = files::FILE_SHARE_READ | files::FILE_SHARE_DELETE;
const DATAFILE_OPTIONS: u32 = files::FILE_SYNCHRONOUS_IO_NONALERT | files::FILE_NON_DIRECTORY_FILE;
const SECTION_QUERY: u32 = 0x0001;
const SECTION_MAP_READ: u32 = 0x0004;
const PAGE_READONLY: u32 = 0x02;
const SEC_COMMIT: u32 = 0x0800_0000;
const VIEW_SHARE: u32 = 1;

/// The file at `path` mapped whole, read-only, as data: the view's base, once its headers are
/// found an image's (the view is unmapped again otherwise). The file's and the section's handles
/// are closed: the view holds the section.
#[inline(never)]
fn map_datafile(path: &Wide) -> Result<usize, Failure> {
    let path = NtPath::of(path.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))?;
    let file = Owned(
        files::open(&path, DATAFILE_ACCESS, DATAFILE_SHARE, DATAFILE_OPTIONS)
            .map_err(Failure::Status)?,
    );
    let section = ntcall::create_section(
        SECTION_QUERY | SECTION_MAP_READ,
        None,
        None,
        PAGE_READONLY,
        SEC_COMMIT,
        file.0,
    )
    .map_err(Failure::Status)?;
    let section = Owned(section.handle);
    let view = View {
        base: 0,
        size: 0,
        offset: 0,
        inherit: VIEW_SHARE,
        allocation: 0,
        protect: PAGE_READONLY,
    };
    let base =
        ntcall::map_view_of_section(section.0, CURRENT_PROCESS, view).map_err(Failure::Status)?;
    if ntcall::image_nt_header(base).is_none() {
        let _ = ntcall::unmap_view_of_section(CURRENT_PROCESS, base);
        return Err(Failure::Error(ERROR_BAD_EXE_FORMAT));
    }
    Ok(base)
}

/// LoadLibraryEx's export body, either form (see [`load_library_ex`]).
///
/// # Safety
///
/// As [`module_as`]'s.
unsafe fn load_library_ex_as<C: CallerChar>(name: *const C, flags: u32) -> u32 {
    // SAFETY: the caller's string, when given (the contract).
    let name = unsafe { C::optional_string(name) };
    load_library_ex(name, flags)
}

/// LoadLibraryExA (see [`load_library_ex`]): the name converted as LoadLibraryA's.
///
/// # Safety
///
/// As [`get_module_handle_a`].
#[unsafe(export_name = "f2k_export_LoadLibraryExA")]
pub unsafe extern "system" fn load_library_ex_a(name: *const u8, _file: u32, flags: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { load_library_ex_as(name, flags) }
}

/// LoadLibraryExW (see [`load_library_ex`]).
///
/// # Safety
///
/// As [`get_module_handle_w`].
#[unsafe(export_name = "f2k_export_LoadLibraryExW")]
pub unsafe extern "system" fn load_library_ex_w(name: *const u16, _file: u32, flags: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { load_library_ex_as(name, flags) }
}

/// FreeLibrary: one reference to the module fewer (LdrUnloadDll: a loaded module's last goes with
/// it; the modules the process starts with stay). ERROR_MOD_NOT_FOUND for a handle naming no
/// module, as Windows 2000 maps LdrUnloadDll's STATUS_DLL_NOT_FOUND. A handle with its low bit set
/// is LoadLibraryEx's data file: its view is unmapped.
#[unsafe(export_name = "f2k_export_FreeLibrary")]
pub extern "system" fn free_library(module: u32) -> u32 {
    if module & 1 != 0 {
        let base = (module & !1) as usize;
        return bool_answer(
            ntcall::unmap_view_of_section(CURRENT_PROCESS, base).map_err(Failure::Status),
        );
    }
    bool_answer(ntcall::unload_dll(module).map_err(Failure::Status))
}

/// DisableThreadLibraryCalls: the DLL whose handle is `module` gets no DLL_THREAD_ATTACH and
/// DLL_THREAD_DETACH from now on (LdrDisableThreadCalloutsForDll). A handle naming no module is
/// TRUE too, the last error untouched (the dllmain capture); a failed call is FALSE with its
/// status's error.
#[unsafe(export_name = "f2k_export_DisableThreadLibraryCalls")]
pub extern "system" fn disable_thread_library_calls(module: u32) -> u32 {
    bool_answer(ntcall::disable_thread_callouts(module).map_err(Failure::Status))
}

/// The longest export name GetProcAddress hands the loader (an ANSI_STRING's length is a word):
/// a longer one names no export.
const MAX_EXPORT_NAME: usize = 0xFFFE;

/// What GetProcAddress names an export by.
enum Export<'a> {
    Name(InStr<'a>),
    /// A value below 0x10000 in the name's place.
    Ordinal(u32),
}

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
    let export = if name as usize > 0xFFFF {
        // SAFETY: the caller's string (the contract: past 0xFFFF, the name is one).
        Export::Name(unsafe { InStr::new(name) })
    } else {
        Export::Ordinal(name as u32)
    };
    answer(proc_address(module, export), 0)
}

/// GetProcAddress's work.
fn proc_address(module: u32, export: Export<'_>) -> Result<u32, Failure> {
    let module = if module == 0 { image_base() } else { module };
    let by_name = matches!(export, Export::Name(_));
    let (status, address) = match export {
        // Read to its terminator, or past the longest name.
        Export::Name(name) => match name.bytes_within(MAX_EXPORT_NAME) {
            Some(bytes) => {
                let string = AnsiString {
                    length: bytes.len() as u16,
                    maximum_length: bytes.len() as u16 + 1,
                    buffer: bytes.as_ptr().cast_mut(),
                };
                ntcall::get_procedure_address(module, Some(&string), 0)
            }
            None => (STATUS_ENTRYPOINT_NOT_FOUND, 0),
        },
        Export::Ordinal(ordinal) => ntcall::get_procedure_address(module, None, ordinal),
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
    if !rtl::status::nt_success(status) {
        return Err(Failure::Status(status));
    }
    Ok(address)
}

/// The full path (FullDllName) of the module whose handle is `module`, its entry found walking the
/// PEB's InLoadOrderModuleList, borrowed for as long as the loader lock is held.
fn module_path(_loader: &LoaderLock, module: u32) -> Option<&[u16]> {
    let data = rtl::sys::ldr() as *const PebLdrData<usize>;
    // SAFETY: the loader's PEB_LDR_DATA and its entries, on the process heap for the process's
    // life (an entry leaves the lists only under the loader lock, which `_loader` holds); each
    // field is read in place, and an entry's InLoadOrderLinks lead it. An entry's FullDllName
    // buffer holds its length, made with the entry and freed with it: nothing frees or rewrites it
    // while the lock is held, and the answer's borrow ends with `_loader`'s.
    unsafe {
        let head =
            (&raw const (*data).in_load_order_module_list).cast::<LdrDataTableEntry<usize>>();
        let mut next = (*data).in_load_order_module_list.flink as *const LdrDataTableEntry<usize>;
        for _ in 0..MAX_ENTRIES {
            if next == head || next.is_null() {
                return None;
            }
            if (*next).dll_base as u32 == module {
                return Some((*next).full_dll_name.units());
            }
            next = (*next).in_load_order_links.flink as *const LdrDataTableEntry<usize>;
        }
    }
    None
}

/// GetModuleFileNameW's work: the module's full path (the image's for a null handle), its
/// FullDllName in the PEB's lists, into the caller's buffer, terminated when it fits; its length.
/// Windows 2000's truncation: a buffer too small takes exactly its size, unterminated, and that
/// size comes back, the last error untouched. ERROR_MOD_NOT_FOUND for a handle naming no module,
/// the buffer untouched.
fn module_file_name(module: u32, mut buffer: Text<'_>) -> Result<u32, Failure> {
    let module = if module == 0 { image_base() } else { module };
    let size = buffer.len();
    let loader = LoaderLock::enter();
    let path = module_path(&loader, module).ok_or(Failure::Error(ERROR_MOD_NOT_FOUND))?;
    let copy = path.len().min(size);
    buffer.put(&path[..copy]);
    if copy < size {
        buffer.put_unit(copy, 0);
    }
    Ok(copy as u32)
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
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    answer(module_file_name(module, CallerChar::text(buffer)), 0)
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
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    answer(module_file_name(module, CallerChar::text(buffer)), 0)
}
