//! The loader's exports over the process's module lists (the PEB's Ldr, which the kernel builds at
//! the process's creation: see `rtl::modules`): LdrGetDllHandle, LdrLoadDll and LdrUnloadDll find a
//! module by its name or handle and count its references, LdrGetProcedureAddress finds an export,
//! under the loader lock (the PEB's LoaderLock), as Windows 2000's do. kernel32's GetModuleHandleA,
//! LoadLibraryA, FreeLibrary and GetProcAddress are over them.
//!
//! A module name with a path is made absolute against the current directory and matched against
//! the modules' full paths, as Windows 2000 matches it (without opening the file to compare a
//! module reached through another path).
//!
//! LdrLoadDll loads a module the lists do not hold from the volume: it looks for the file in the
//! current directory, then in the volume's root (a name with a path: there alone; see
//! `rtl::modules::search_place`), opens it (NtOpenFile), and maps it as an image section
//! (NtCreateSection, NtMapViewOfSection: the kernel parses it and maps it at its preferred base,
//! never relocating it, so a base already taken fails the load with STATUS_CONFLICTING_ADDRESSES).
//! Its entry joins the lists, on the process heap; then its imports are snapped against them, a
//! module it imports referenced once more or loaded in turn, each IAT made writable for the snap
//! (NtProtectVirtualMemory) and given its protection back. A load that fails leaves nothing behind.
//! LdrUnloadDll's last reference to a loaded module unmaps it, drops its entry, and releases the
//! modules it imports; the modules the process starts with are never unloaded (their count stays).
//! No entry point is ever called: a loaded DLL's DllMain does not run.

use rtl::modules::{self, entry, Descriptor, Memory, MemoryMut, STATIC_LOAD_COUNT};
use rtl::path::{nt_path, MAX_PATH};
use rtl::status::{
    STATUS_DLL_NOT_FOUND,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_SUCCESS,
};
use rtl::sys::{self, nr, system_service, Native};

use crate::curdir::{self, UnicodeString};

/// The process's own memory, read and written in place (a bad pointer faults the caller, as on
/// Windows 2000).
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

impl MemoryMut for Mapped {
    fn set_word(&mut self, at: u32, value: u32) {
        // SAFETY: the lists' links, on the parameters pages or the process heap, the process's own.
        unsafe { (at as usize as *mut u32).write_unaligned(value) }
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

/// A module name's room, formed: MAX_PATH and its default extension.
const NAME_ROOM: usize = MAX_PATH + 8;

/// The entry of the module `name` names (see `rtl::modules::by_name`; a name with a path made
/// absolute first, RtlGetFullPathName_U's way). Under the loader lock.
fn find(name: &[u16]) -> Option<u32> {
    // The name with its default extension, terminated (the zeroes past it).
    let mut formed = [0u16; NAME_ROOM];
    let length = modules::module_name(name, &mut formed[..NAME_ROOM - 1])?;
    if !modules::has_path(&formed[..length]) {
        return modules::by_name(&Mapped, ldr(), &formed[..length]);
    }
    let mut full = [0u16; MAX_PATH + 1];
    // SAFETY: the formed name is terminated; the buffer holds MAX_PATH + 1 units.
    let bytes = unsafe {
        curdir::rtl_get_full_path_name_u(
            formed.as_ptr(),
            2 * full.len() as u32,
            full.as_mut_ptr(),
            core::ptr::null_mut(),
        )
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

/// A module's load count.
fn load_count(entry: u32) -> u16 {
    Mapped.half(entry + entry::LOAD_COUNT)
}

/// Replace a module's load count.
fn set_load_count(entry: u32, count: u16) {
    // SAFETY: the entry is the process's own, on its writable parameters pages or its heap.
    unsafe { ((entry + entry::LOAD_COUNT) as usize as *mut u16).write_unaligned(count) }
}

/// The current-process pseudo-handle, and the open, section and view arguments a load passes, as
/// Windows 2000's loader passes them: the file opened to read and execute, shared for reading and
/// deleting, synchronously, never a directory; an image section mapped for reading and executing;
/// the view shared, PAGE_READWRITE (an image's pages take their sections' protections).
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const FILE_READ_DATA: u32 = 0x1;
const FILE_EXECUTE: u32 = 0x20;
const SYNCHRONIZE: u32 = 0x10_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_DELETE: u32 = 0x4;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const SECTION_QUERY: u32 = 0x1;
const SECTION_MAP_READ: u32 = 0x4;
const SECTION_MAP_EXECUTE: u32 = 0x8;
const PAGE_READWRITE: u32 = 0x4;
const PAGE_EXECUTE: u32 = 0x10;
const SEC_IMAGE: u32 = 0x0100_0000;
const VIEW_SHARE: u32 = 1;

/// Open the file at the full DOS path `full` to map it: its handle, or the open's status.
fn open_file(full: &[u16]) -> Result<u32, u32> {
    let mut name = [0u16; NAME_ROOM];
    let length = nt_path(full, &mut name).map_err(|_| STATUS_DLL_NOT_FOUND)?;
    let string = UnicodeString {
        length: (2 * length) as u16,
        maximum_length: (2 * length) as u16,
        buffer: name.as_mut_ptr(),
    };
    let attributes: [u32; 6] = [
        24,
        0,
        &string as *const UnicodeString as u32,
        OBJ_CASE_INSENSITIVE,
        0,
        0,
    ];
    let mut io_status = [0u32; 2];
    let mut handle = 0u32;
    let args = [
        &mut handle as *mut u32 as u32,
        FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
        attributes.as_ptr() as u32,
        io_status.as_mut_ptr() as u32,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    ];
    match system_service(nr::NtOpenFile, &args) {
        STATUS_SUCCESS => Ok(handle),
        status => Err(status),
    }
}

/// Close a handle.
fn close(handle: u32) {
    system_service(nr::NtClose, &[handle]);
}

/// Map the image file `file` names as an image section's view: its base and its size.
fn map_image(file: u32) -> Result<(u32, u32), u32> {
    let mut section = 0u32;
    let args = [
        &mut section as *mut u32 as u32,
        SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        0,
        0,
        PAGE_EXECUTE,
        SEC_IMAGE,
        file,
    ];
    match system_service(nr::NtCreateSection, &args) {
        STATUS_SUCCESS => {}
        status => return Err(status),
    }
    let (mut base, mut size) = (0u32, 0u32);
    let args = [
        section,
        CURRENT_PROCESS,
        &mut base as *mut u32 as u32,
        0,
        0,
        0,
        &mut size as *mut u32 as u32,
        VIEW_SHARE,
        0,
        PAGE_READWRITE,
    ];
    let status = system_service(nr::NtMapViewOfSection, &args);
    // The view holds the section.
    close(section);
    match status {
        STATUS_SUCCESS => Ok((base, size)),
        status => Err(status),
    }
}

/// Unmap the view at `base`.
fn unmap(base: u32) {
    system_service(nr::NtUnmapViewOfSection, &[CURRENT_PROCESS, base]);
}

/// Give the pages `[at, at + size)` the protection `protect`: their old protection.
fn protect(at: u32, size: u32, protect: u32) -> Result<u32, u32> {
    let (mut base, mut size, mut old) = (at, size, 0u32);
    let args = [
        CURRENT_PROCESS,
        &mut base as *mut u32 as u32,
        &mut size as *mut u32 as u32,
        protect,
        &mut old as *mut u32 as u32,
    ];
    match system_service(nr::NtProtectVirtualMemory, &args) {
        STATUS_SUCCESS => Ok(old),
        status => Err(status),
    }
}

/// The entry of the module mapped at `base` (`size` bytes) from the full path `path`, made on the
/// process heap (the path's text after it) and joined to the lists; none without room.
fn add_entry(base: u32, size: u32, path: &[u16]) -> Option<u32> {
    let bytes = entry::SIZE as usize + 2 * (path.len() + 1);
    let at = sys::process_heap().alloc(&Native, 0, bytes)? as u32;
    let buffer = at + entry::SIZE;
    let record = modules::loaded_entry(at, &modules::loaded(&Mapped, base, size), buffer, path);
    // SAFETY: a fresh block of `bytes` bytes: the entry, then the path and its terminator.
    unsafe {
        (at as usize as *mut u8).copy_from_nonoverlapping(record.as_ptr(), record.len());
        let text = buffer as usize as *mut u16;
        text.copy_from_nonoverlapping(path.as_ptr(), path.len());
        text.add(path.len()).write(0);
    }
    modules::insert(&mut Mapped, ldr(), at);
    Some(at)
}

/// Load the module `name` (formed: its default extension supplied) from the volume (see the module
/// doc): its entry, its load count 1, its imports snapped. Under the loader lock.
fn load(name: &[u16]) -> Result<u32, u32> {
    let mut current = [0u16; MAX_PATH + 1];
    let (current_length, _) = curdir::current_directory(&mut current);
    let mut full = [0u16; modules::MAX_SEARCH_PATH + 1];
    let mut opened = None;
    let mut index = 0;
    while let Some(length) =
        modules::search_place(name, &current[..current_length], index, &mut full)
    {
        if let Ok(file) = open_file(&full[..length]) {
            opened = Some((file, length));
            break;
        }
        index += 1;
    }
    let (file, length) = opened.ok_or(STATUS_DLL_NOT_FOUND)?;
    let mapped = map_image(file);
    // The section holds the file.
    close(file);
    let (base, size) = mapped?;
    let Some(at) = add_entry(base, size, &full[..length]) else {
        unmap(base);
        return Err(STATUS_NO_MEMORY);
    };
    if let Err((status, referenced)) = snap(base) {
        discard(at, referenced);
        return Err(status);
    }
    Ok(at)
}

/// Snap the imports of the image mapped at `base` against the lists, descriptor by descriptor: each
/// module it imports referenced once more, or loaded. On a failure, its status and how many
/// descriptors' modules were referenced.
fn snap(base: u32) -> Result<(), (u32, usize)> {
    for (index, descriptor) in modules::import_descriptors(&Mapped, base).enumerate() {
        let mut name = [0u16; NAME_ROOM];
        let length = modules::import_module_name(&Mapped, descriptor.name, &mut name)
            .ok_or((STATUS_DLL_NOT_FOUND, index))?;
        let module = match find(&name[..length]) {
            Some(entry) => {
                set_load_count(entry, modules::referenced(load_count(entry)));
                base_of(entry)
            }
            None => base_of(load(&name[..length]).map_err(|status| (status, index))?),
        };
        snap_descriptor(base, &descriptor, module).map_err(|status| (status, index + 1))?;
    }
    Ok(())
}

/// Write each IAT slot of `descriptor` (of the image at `base`) with its import's address in the
/// module whose handle is `module`, the IAT writable meanwhile.
fn snap_descriptor(base: u32, descriptor: &Descriptor, module: u32) -> Result<(), u32> {
    let count = modules::imports(&Mapped, base, descriptor.lookup).count() as u32;
    if count == 0 {
        return Ok(());
    }
    let old = protect(descriptor.iat, 4 * count, PAGE_READWRITE)?;
    let ldr = ldr();
    let mut snapped = Ok(());
    for (index, import) in modules::imports(&Mapped, base, descriptor.lookup).enumerate() {
        match modules::import_address(&Mapped, ldr, module, import) {
            Ok(address) => Mapped.set_word(descriptor.iat + 4 * index as u32, address),
            Err(status) => {
                snapped = Err(status);
                break;
            }
        }
    }
    let _ = protect(descriptor.iat, 4 * count, old);
    snapped
}

/// One reference fewer to the module whose entry is `entry`: a loaded module's last unloads it (a
/// module the process started with keeps its count).
fn dereference(entry: u32) {
    let count = load_count(entry);
    set_load_count(entry, modules::released(count));
    if count == 1 {
        discard(entry, usize::MAX);
    }
}

/// Unload the loaded module whose entry is `entry`: out of the lists, the modules its first
/// `referenced` import descriptors name released, its view unmapped, its entry freed.
fn discard(entry: u32, referenced: usize) {
    let base = base_of(entry);
    set_load_count(entry, 0);
    modules::remove(&mut Mapped, entry);
    for descriptor in modules::import_descriptors(&Mapped, base).take(referenced) {
        let mut name = [0u16; NAME_ROOM];
        if let Some(found) = modules::import_module_name(&Mapped, descriptor.name, &mut name)
            .and_then(|length| find(&name[..length]))
        {
            dereference(found);
        }
    }
    unmap(base);
    sys::process_heap().free(&Native, 0, entry as usize);
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

/// LdrLoadDll: the module `name` names — one the lists hold, its load count raised (a static
/// module's stays), or one loaded from the volume (see the module doc; STATUS_DLL_NOT_FOUND where
/// no file is found) — its handle into `handle` (zero on a failure). The search path and the
/// characteristics are not consulted.
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
        if let Some(entry) = find(name) {
            set_load_count(entry, modules::referenced(load_count(entry)));
            return Ok(base_of(entry));
        }
        let mut formed = [0u16; NAME_ROOM];
        let length =
            modules::module_name(name, &mut formed[..NAME_ROOM - 1]).ok_or(STATUS_DLL_NOT_FOUND)?;
        load(&formed[..length]).map(base_of)
    });
    // SAFETY: the caller's handle.
    unsafe { handle.write(*found.as_ref().unwrap_or(&0)) };
    found.map_or_else(|status| status, |_| STATUS_SUCCESS)
}

/// LdrUnloadDll: the module whose handle is `module` has one reference fewer, a loaded module's
/// last unloading it (see the module doc); a module the process started with stays, its count
/// with it. STATUS_DLL_NOT_FOUND for a handle naming no module.
#[unsafe(export_name = "f2k_export_LdrUnloadDll")]
pub extern "system" fn ldr_unload_dll(module: u32) -> u32 {
    locked(|| match modules::by_base(&Mapped, ldr(), module) {
        Some(entry) if load_count(entry) == STATIC_LOAD_COUNT => STATUS_SUCCESS,
        Some(entry) => {
            dereference(entry);
            STATUS_SUCCESS
        }
        None => STATUS_DLL_NOT_FOUND,
    })
}

/// LdrGetProcedureAddress: the address of the export `name` (or, with no name, of the ordinal
/// `ordinal`) of the module whose handle is `module`, forwarders followed, into `address` (see
/// `rtl::modules::procedure_address` and `procedure_by_ordinal` for the statuses). No name and
/// ordinal 0 is STATUS_INVALID_PARAMETER, before any lookup (Windows 2000's: GetProcAddress of a
/// null name is ERROR_INVALID_PARAMETER).
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
    if name.is_none() && ordinal == 0 {
        return STATUS_INVALID_PARAMETER;
    }
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
