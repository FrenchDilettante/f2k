//! The loader, as Windows 2000's ntdll runs it: every module of the process but the image and
//! ntdll, from the process's first thread to its end, over the PEB's module lists
//! (`rtl::modules`).
//!
//! **The process's initialization** ([`initialize_process`], then [`attach_process`]: the first
//! thread's LdrInitializeThunk). The kernel maps the image and ntdll alone; here the lists are
//! built on the process heap — the image's entry (its FullDllName the process parameters'
//! ImagePathName, buffer and all, as LdrpInitializeProcess takes it), ntdll's (its path under the
//! system root, KUSER_SHARED_DATA's NtSystemRoot) — and every DLL the image imports is loaded from
//! the volume and snapped as LdrLoadDll loads one, kernel32 included, recursively. Every module the
//! process starts with is static (its load count 0xFFFF). Once the thread's TLS is made, every
//! DLL's entry point is called with DLL_PROCESS_ATTACH in initialization order (a DLL after the
//! DLLs it imports), lpReserved non-NULL (the initial context, as Windows 2000 passes it). A module
//! that cannot be found (STATUS_DLL_NOT_FOUND), an import its module does not export
//! (STATUS_ENTRYPOINT_NOT_FOUND by name, STATUS_ORDINAL_NOT_FOUND by ordinal) and an entry point
//! answering FALSE (STATUS_DLL_INIT_FAILED) each fail the initialization: a line on the debugger's
//! channel names it, and the process ends with the status (Windows 2000 raises a hard-error popup
//! first; F2K has none).
//!
//! **The loader's exports**, under the loader lock (the PEB's LoaderLock), as Windows 2000's:
//! LdrGetDllHandle, LdrLoadDll and LdrUnloadDll find a module by its name or handle and count its
//! references, LdrGetProcedureAddress finds an export, LdrDisableThreadCalloutsForDll turns a DLL's
//! thread notifications off. kernel32's GetModuleHandleA, LoadLibraryA, FreeLibrary,
//! GetProcAddress and DisableThreadLibraryCalls are over them. A module name with a path is made
//! absolute against the current directory and matched against the modules' full paths, as Windows
//! 2000 matches it (without opening the file to compare a module reached through another path).
//!
//! LdrLoadDll loads a module the lists do not hold: it looks for the file where Windows 2000 looks
//! (`rtl::modules::search_place`: the program's directory, the current directory, the system
//! directories under the system root, then PATH; a name with a path there alone), opens it
//! (NtOpenFile) and maps it as an image section (NtCreateSection, NtMapViewOfSection: the kernel
//! parses it and maps it at its preferred base, never relocating it, so a base already taken fails
//! the load with STATUS_CONFLICTING_ADDRESSES). Its entry joins the lists, on the process heap;
//! its imports are snapped against them, a module it imports referenced once more or loaded in
//! turn, each IAT made writable for the snap (NtProtectVirtualMemory) and given its protection
//! back; then it joins the initialization order. Every DLL the load brought in then has its entry
//! point called with DLL_PROCESS_ATTACH, lpReserved NULL, the DLLs it imports first; one answering
//! FALSE fails the load (STATUS_DLL_INIT_FAILED) and the DLL asked for is unloaded again (its own
//! DLL_PROCESS_DETACH included, as the documentation of DllMain describes it). A load that fails
//! leaves nothing behind. LdrUnloadDll's last reference to a loaded module calls its entry point
//! with DLL_PROCESS_DETACH (lpReserved NULL), unmaps it, drops its entry, and releases the modules
//! it imports (each one's last reference in turn); the modules the process starts with are never
//! unloaded.
//!
//! **Threads and the process's end.** Each later thread's initialization calls the DLLs' entry
//! points with DLL_THREAD_ATTACH (memory order), LdrShutdownThread with DLL_THREAD_DETACH (reverse
//! initialization order), both only the DLLs that had their DLL_PROCESS_ATTACH and have not turned
//! their thread notifications off; LdrShutdownProcess calls DLL_PROCESS_DETACH, lpReserved
//! non-NULL, in reverse initialization order. While no DLL is owed a call, none of them takes the
//! loader lock: a thread that ExitProcess terminates in the middle of its start must not leave the
//! lock held for the process's own shutdown.
//!
//! Every entry point is called through `f2k_call_dll_entry` (src/ldr.s), which gives the stack
//! pointer and the callee-saved registers back whatever the routine does with them.

use core::fmt::Write;

use rtl::modules::{
    self,
    data,
    entry,
    flags,
    Descriptor,
    Import,
    Memory,
    MemoryMut,
    SearchPath,
    MAX_SEARCH_PATH,
    STATIC_LOAD_COUNT,
};
use rtl::path::{nt_path, MAX_PATH};
use rtl::status::{
    STATUS_DLL_INIT_FAILED,
    STATUS_DLL_NOT_FOUND,
    STATUS_ENTRYPOINT_NOT_FOUND,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_ORDINAL_NOT_FOUND,
    STATUS_SUCCESS,
};
use rtl::stub::Line;
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
        // SAFETY: the lists' entries and links, on the process heap, the process's own.
        unsafe { (at as usize as *mut u32).write_unaligned(value) }
    }
}

/// The process's PEB_LDR_DATA (zero until the process's initialization makes it).
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

/// The reasons an entry point is called with (DllMain's fdwReason).
const DLL_PROCESS_DETACH: u32 = 0;
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_THREAD_ATTACH: u32 = 2;
const DLL_THREAD_DETACH: u32 = 3;

/// The lpReserved of the calls made as the process ends: any non-NULL value says so.
const PROCESS_ENDING: u32 = 1;

/// The loader's own state, past the PEB proper on its page (the system DLLs keep no writable
/// sections; Windows 2000 keeps it in ntdll's data): how many of the process's DLLs are owed calls
/// (their entry point called with DLL_PROCESS_ATTACH, not yet with DLL_PROCESS_DETACH), and whether
/// the process's initialization is under way (its failures are reported on the debugger's
/// channel). Both change under the loader lock.
const PEB_ATTACHED: usize = 0x920;
const PEB_INITIALIZING: usize = 0x924;

/// How many DLLs are owed calls.
fn attached() -> usize {
    sys::read(sys::peb() + PEB_ATTACHED)
}

/// One DLL more (`true`) or fewer owed calls.
fn count_attached(more: bool) {
    let count = attached();
    sys::write(
        sys::peb() + PEB_ATTACHED,
        if more {
            count + 1
        } else {
            count.saturating_sub(1)
        },
    );
}

/// Whether the process's initialization is under way.
fn initializing() -> bool {
    sys::read(sys::peb() + PEB_INITIALIZING) != 0
}

/// Mark the process's initialization under way, or over.
fn set_initializing(under_way: bool) {
    sys::write(sys::peb() + PEB_INITIALIZING, usize::from(under_way));
}

// The routine that calls a DLL's entry point (src/ldr.s).
unsafe extern "C" {
    fn f2k_call_dll_entry(entry_point: u32, base: u32, reason: u32, reserved: u32) -> u32;
}

// The linker's symbol at ntdll's own base: its module handle.
unsafe extern "C" {
    #[link_name = "__ImageBase"]
    static IMAGE_BASE: u8;
}

/// KUSER_SHARED_DATA's NtSystemRoot (`C:\WINNT`, NUL-terminated), on the page every process maps
/// read-only: the one place every system path comes from.
const SYSTEM_ROOT: usize = 0x7FFE_0030;

/// The process parameters' ImagePathName.
const IMAGE_PATH_NAME: usize = 0x38;

/// The environment variable the search's last places come from.
const PATH: [u16; 4] = [b'P' as u16, b'A' as u16, b'T' as u16, b'H' as u16];

/// The longest PATH the search reads, in units (a longer one is cut there).
const PATH_ROOM: usize = 512;

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
    // SAFETY: the entry is the process's own, on its heap.
    unsafe { ((entry + entry::LOAD_COUNT) as usize as *mut u16).write_unaligned(count) }
}

/// A module's LDRP_* flags.
fn flags_of(entry: u32) -> u32 {
    Mapped.word(entry + entry::FLAGS)
}

/// Replace a module's flags.
fn set_flags(entry: u32, value: u32) {
    Mapped.set_word(entry + entry::FLAGS, value);
}

/// Call the entry point of the module whose entry is `entry` with `reason` and `reserved`: its
/// answer (zero: FALSE).
fn call_entry(entry: u32, reason: u32, reserved: u32) -> u32 {
    let entry_point = Mapped.word(entry + entry::ENTRY_POINT);
    // SAFETY: the module's own entry point, as its headers name it: a DllMain.
    unsafe { f2k_call_dll_entry(entry_point, base_of(entry), reason, reserved) }
}

/// A UTF-16 name as the debugger's channel shows it: its ASCII, anything else a `?`.
fn narrow<'a>(units: &[u16], out: &'a mut [u8; 96]) -> &'a str {
    let length = units.len().min(out.len());
    for (byte, &unit) in out.iter_mut().zip(&units[..length]) {
        *byte = if (0x20..0x7F).contains(&unit) {
            unit as u8
        } else {
            b'?'
        };
    }
    core::str::from_utf8(&out[..length]).unwrap_or("?")
}

/// Report a failure of the process's initialization on the debugger's channel (Windows 2000 shows
/// it in a hard-error popup): `body` writes what failed.
fn report(body: impl FnOnce(&mut Line) -> core::fmt::Result) {
    if !initializing() {
        return;
    }
    let mut line = Line::new();
    let _ = line.write_str("LDR: the process cannot start: ");
    let _ = body(&mut line);
    let shown = line.terminated();
    // The NUL the line carries for a C caller is not text.
    crate::dbgprint::print(&shown[..shown.len() - 1]);
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

/// Open the file at the full DOS path `full` to map it: its handle, or the open's status. Never
/// inlined, as [`find_file`].
#[inline(never)]
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

/// The entry of the module mapped at `base` (`size` bytes; none: its headers' SizeOfImage) from
/// the full path `path`, made on the process heap (the path's text after it) and joined to the
/// load and memory orders; none without room.
fn add_entry(base: u32, size: Option<u32>, path: &[u16]) -> Option<u32> {
    let room = 2 * (path.len() + 1);
    let at = sys::process_heap().alloc(&Native, 0, entry::SIZE as usize + room)? as u32;
    let buffer = at + entry::SIZE;
    let module = modules::loaded(&Mapped, base, size);
    let record = modules::loaded_entry(at, &module, buffer, path, room as u32);
    // SAFETY: a fresh block of the entry's size and the path's room: the entry, then the path and
    // its terminator.
    unsafe {
        (at as usize as *mut u8).copy_from_nonoverlapping(record.as_ptr(), record.len());
        let text = buffer as usize as *mut u16;
        text.copy_from_nonoverlapping(path.as_ptr(), path.len());
        text.add(path.len()).write(0);
    }
    modules::insert(&mut Mapped, ldr(), at);
    Some(at)
}

/// The process parameters' ImagePathName: the program's full path.
fn image_path() -> &'static [u16] {
    // SAFETY: the process parameters are mapped for the process's whole life; their ImagePathName's
    // buffer holds its length.
    unsafe { (*((sys::process_parameters() + IMAGE_PATH_NAME) as *const UnicodeString)).units() }
}

/// The system root (KUSER_SHARED_DATA's NtSystemRoot) into `out`: its length in units.
fn system_root(out: &mut [u16; MAX_PATH]) -> usize {
    let mut length = 0;
    while length < MAX_PATH - 1 {
        // SAFETY: the shared data page, mapped read-only into every process.
        let unit = unsafe { ((SYSTEM_ROOT + 2 * length) as *const u16).read_volatile() };
        if unit == 0 {
            break;
        }
        out[length] = unit;
        length += 1;
    }
    length
}

/// Find the file of the module `name` (formed: its default extension supplied) where Windows 2000
/// looks (see the module doc), and open it: its handle, and the full path it was found at (its
/// length, the path in the buffer, terminated). Never inlined: its buffers stay out of the load's
/// frame, which stays below a page (a frame of a page or more calls a stack probe the DLLs' link
/// does not carry).
#[inline(never)]
fn find_file(name: &[u16]) -> Result<(u32, usize, [u16; MAX_SEARCH_PATH + 1]), u32> {
    let mut current = [0u16; MAX_PATH + 1];
    let (current_length, _) = curdir::current_directory(&mut current);
    let mut root = [0u16; MAX_PATH];
    let root_length = system_root(&mut root);
    let mut path = [0u16; PATH_ROOM];
    let path_length = crate::env::process_variable(&PATH, &mut path);
    let search = SearchPath {
        image: image_path(),
        current: &current[..current_length],
        system_root: &root[..root_length],
        path: &path[..path_length],
    };
    let mut full = [0u16; MAX_SEARCH_PATH + 1];
    for index in 0..modules::search_places(name, &search) {
        let Some(length) = modules::search_place(name, &search, index, &mut full) else {
            continue;
        };
        if let Ok(file) = open_file(&full[..length]) {
            return Ok((file, length, full));
        }
    }
    Err(STATUS_DLL_NOT_FOUND)
}

/// Load the module `name` (formed: its default extension supplied) from the volume (see the module
/// doc): its entry, its load count 1, its imports snapped, in the initialization order (its entry
/// point not called yet). Under the loader lock.
fn load(name: &[u16]) -> Result<u32, u32> {
    let (file, length, full) = find_file(name).inspect_err(|_| {
        let mut shown = [0u8; 96];
        report(|line| write!(line, "{} was not found", narrow(name, &mut shown)));
    })?;
    let mapped = map_image(file);
    // The section holds the file.
    close(file);
    let (base, size) = mapped.inspect_err(|&status| {
        let mut shown = [0u8; 96];
        report(|line| {
            write!(
                line,
                "{} could not be mapped (status {status:#010X})",
                narrow(&full[..length], &mut shown)
            )
        });
    })?;
    let Some(at) = add_entry(base, Some(size), &full[..length]) else {
        unmap(base);
        return Err(STATUS_NO_MEMORY);
    };
    if let Err((status, referenced)) = snap(base) {
        discard(at, referenced);
        return Err(status);
    }
    modules::insert_initialized(&mut Mapped, ldr(), at);
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
        snap_descriptor(base, &descriptor, module, &name[..length])
            .map_err(|status| (status, index + 1))?;
    }
    Ok(())
}

/// Write each IAT slot of `descriptor` (of the image at `base`) with its import's address in the
/// module whose handle is `module` (named `name`), the IAT writable meanwhile. An import the
/// module does not export is STATUS_ENTRYPOINT_NOT_FOUND by name, STATUS_ORDINAL_NOT_FOUND by
/// ordinal, as Windows 2000's snap answers.
fn snap_descriptor(
    base: u32,
    descriptor: &Descriptor,
    module: u32,
    name: &[u16],
) -> Result<(), u32> {
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
                snapped = Err(match (status, import) {
                    // A forwarder naming a module the process has not loaded.
                    (STATUS_DLL_NOT_FOUND, _) => status,
                    (_, Import::Ordinal(_)) => STATUS_ORDINAL_NOT_FOUND,
                    (_, Import::Name(_)) => STATUS_ENTRYPOINT_NOT_FOUND,
                });
                report_import(import, name);
                break;
            }
        }
    }
    let _ = protect(descriptor.iat, 4 * count, old);
    snapped
}

/// Report an import that does not resolve (see [`report`]).
fn report_import(import: Import, module: &[u16]) {
    let mut shown = [0u8; 96];
    let module = narrow(module, &mut shown);
    report(|line| match import {
        Import::Ordinal(ordinal) => write!(line, "ordinal {ordinal} was not found in {module}"),
        Import::Name(at) => {
            let mut text = [0u8; 96];
            let length = (0..text.len())
                .find(|&index| {
                    text[index] = Mapped.byte(at + index as u32);
                    text[index] == 0
                })
                .unwrap_or(text.len());
            let name = core::str::from_utf8(&text[..length]).unwrap_or("?");
            write!(line, "the entry point {name} was not found in {module}")
        }
    });
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

/// Unload the loaded module whose entry is `entry`: its entry point called with
/// DLL_PROCESS_DETACH (lpReserved NULL) when it had its DLL_PROCESS_ATTACH, out of the lists, the
/// modules its first `referenced` import descriptors name released, its view unmapped, its entry
/// freed.
fn discard(entry: u32, referenced: usize) {
    let base = base_of(entry);
    set_load_count(entry, 0);
    let flags = flags_of(entry);
    if flags & flags::PROCESS_ATTACH_CALLED != 0 {
        set_flags(entry, flags & !flags::PROCESS_ATTACH_CALLED);
        count_attached(false);
        call_entry(entry, DLL_PROCESS_DETACH, 0);
    }
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

/// The most entries one pass of the entry-point calls takes.
const MAX_CALLS: usize = 64;

/// Call DLL_PROCESS_ATTACH, with `reserved`, on every DLL of the initialization order the loader
/// has not processed yet, in that order (each processed once, whatever its answer): the entry of
/// the first one answering FALSE. Each pass takes the pending entries first, so a load an entry
/// point makes runs its own DLLs' calls alone. Under the loader lock.
fn run_initializers(reserved: u32) -> Result<(), u32> {
    loop {
        let mut pending = [0u32; MAX_CALLS];
        let mut count = 0;
        for entry in modules::initialization_order(&Mapped, ldr(), false) {
            let flags = flags_of(entry);
            if flags & flags::ENTRY_PROCESSED != 0 {
                continue;
            }
            if count == MAX_CALLS {
                break;
            }
            set_flags(entry, flags | flags::ENTRY_PROCESSED);
            pending[count] = entry;
            count += 1;
        }
        if count == 0 {
            return Ok(());
        }
        for &entry in &pending[..count] {
            if Mapped.word(entry + entry::ENTRY_POINT) == 0 {
                continue;
            }
            set_flags(entry, flags_of(entry) | flags::PROCESS_ATTACH_CALLED);
            count_attached(true);
            if call_entry(entry, DLL_PROCESS_ATTACH, reserved) == 0 {
                return Err(entry);
            }
        }
    }
}

/// The process's initialization, on its first thread once the process heap and the locks are made
/// (see the module doc): the lists built, the image's imports loaded and snapped, every module
/// static. The failure's status.
pub(crate) fn initialize_process() -> Result<(), u32> {
    set_initializing(true);
    locked(|| {
        let heap = sys::process_heap();
        let lists = heap
            .alloc(&Native, 0, data::SIZE as usize)
            .ok_or(STATUS_NO_MEMORY)? as u32;
        let bytes = modules::empty_lists(lists);
        // SAFETY: a fresh block of the PEB_LDR_DATA's size.
        unsafe {
            (lists as usize as *mut u8).copy_from_nonoverlapping(bytes.as_ptr(), bytes.len())
        };
        sys::write(sys::peb() + modules::peb::LDR as usize, lists as usize);

        // The image: its full path the process parameters' own string, its entry processed (it is
        // not initialized as a DLL is), in no initialization order.
        let image = sys::image_base() as u32;
        let at = heap
            .alloc(&Native, 0, entry::SIZE as usize)
            .ok_or(STATUS_NO_MEMORY)? as u32;
        // SAFETY: the process parameters are mapped for the process's whole life.
        let path =
            unsafe { &*((sys::process_parameters() + IMAGE_PATH_NAME) as *const UnicodeString) };
        let record = modules::loaded_entry(
            at,
            &modules::loaded(&Mapped, image, None),
            path.buffer as u32,
            image_path(),
            u32::from(path.maximum_length),
        );
        // SAFETY: a fresh block of the entry's size.
        unsafe { (at as usize as *mut u8).copy_from_nonoverlapping(record.as_ptr(), record.len()) };
        for word in [0, 4] {
            Mapped.set_word(at + entry::IN_INITIALIZATION_ORDER_LINKS + word, 0);
        }
        set_flags(at, flags_of(at) | flags::ENTRY_PROCESSED);
        modules::insert(&mut Mapped, lists, at);

        // ntdll: at the system directory, first in the initialization order, its entry processed
        // (it has no entry point).
        let mut root = [0u16; MAX_PATH];
        let root_length = system_root(&mut root);
        let mut path = [0u16; MAX_PATH];
        let file = b"\\system32\\ntdll.dll";
        path[..root_length].copy_from_slice(&root[..root_length]);
        for (unit, &byte) in path[root_length..].iter_mut().zip(file) {
            *unit = u16::from(byte);
        }
        // The linker's symbol, by address only.
        let ntdll_base = core::ptr::addr_of!(IMAGE_BASE) as u32;
        let ntdll = add_entry(ntdll_base, None, &path[..root_length + file.len()])
            .ok_or(STATUS_NO_MEMORY)?;
        set_flags(ntdll, flags_of(ntdll) | flags::ENTRY_PROCESSED);
        modules::insert_initialized(&mut Mapped, lists, ntdll);

        // The image's imports, then every module the process starts with made static.
        snap(image).map_err(|(status, _)| status)?;
        for entry in modules::load_order(&Mapped, lists) {
            set_load_count(entry, STATIC_LOAD_COUNT);
        }
        Ok(())
    })
}

/// The process's DLLs' DLL_PROCESS_ATTACH, on its first thread once its TLS is made, lpReserved
/// `context` (the thread's initial context): STATUS_DLL_INIT_FAILED when an entry point answers
/// FALSE (reported, see [`report`]). The process's initialization is over either way.
pub(crate) fn attach_process(context: u32) -> Result<(), u32> {
    let answer = locked(|| {
        run_initializers(context).map_err(|entry| {
            // SAFETY: the entry's BaseDllName, its buffer holding its length.
            let name = unsafe {
                (*((entry + entry::BASE_DLL_NAME) as usize as *const UnicodeString)).units()
            };
            let mut shown = [0u8; 96];
            report(|line| {
                write!(
                    line,
                    "{}'s initialization failed (its entry point answered FALSE)",
                    narrow(name, &mut shown)
                )
            });
            STATUS_DLL_INIT_FAILED
        })
    });
    set_initializing(false);
    answer
}

/// End the process whose initialization failed with `status` (Windows 2000's hard-error popup
/// aside).
pub(crate) fn fail_process(status: u32) -> ! {
    system_service(nr::NtTerminateProcess, &[CURRENT_PROCESS, status]);
    // NtTerminateProcess of the caller does not return.
    loop {
        core::hint::spin_loop();
    }
}

/// The most DLLs one notification of the threads or of the process's end reaches.
const MAX_NOTIFIED: usize = 128;

/// Call `reason` (lpReserved `reserved`) on the DLLs of `order` that had their DLL_PROCESS_ATTACH,
/// and, for a thread's notifications (`threads`), have not turned them off. They are taken first,
/// then called, under the loader lock; with none owed a call, the lock is not taken.
fn notify(order: Order, reason: u32, reserved: u32, threads: bool) {
    if attached() == 0 || ldr() == 0 {
        return;
    }
    locked(|| {
        let mut owed = [0u32; MAX_NOTIFIED];
        let mut count = 0;
        let mut take = |entry: u32| {
            let flags = flags_of(entry);
            if flags & flags::PROCESS_ATTACH_CALLED != 0
                && !(threads && flags & flags::DONT_CALL_FOR_THREADS != 0)
                && count < MAX_NOTIFIED
            {
                owed[count] = entry;
                count += 1;
            }
        };
        let ldr = ldr();
        match order {
            Order::Memory => modules::memory_order(&Mapped, ldr).for_each(&mut take),
            Order::Unwinding => {
                modules::initialization_order(&Mapped, ldr, true).for_each(&mut take)
            }
        }
        for &entry in &owed[..count] {
            if reason == DLL_PROCESS_DETACH {
                set_flags(entry, flags_of(entry) & !flags::PROCESS_ATTACH_CALLED);
                count_attached(false);
            }
            call_entry(entry, reason, reserved);
        }
    });
}

/// The orders the notifications take: memory order (a thread's attach), and reverse
/// initialization order (a thread's detach, the process's end).
enum Order {
    Memory,
    Unwinding,
}

/// A later thread's DLL_THREAD_ATTACH, on the thread, before its start routine (see the module
/// doc).
pub(crate) fn attach_thread() {
    notify(Order::Memory, DLL_THREAD_ATTACH, 0, true);
}

/// LdrShutdownThread's DLL_THREAD_DETACH, on the thread ending (see the module doc).
pub(crate) fn detach_thread() {
    notify(Order::Unwinding, DLL_THREAD_DETACH, 0, true);
}

/// LdrShutdownProcess's DLL_PROCESS_DETACH, lpReserved non-NULL (see the module doc).
pub(crate) fn detach_process() {
    notify(Order::Unwinding, DLL_PROCESS_DETACH, PROCESS_ENDING, false);
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
/// module's stays), or one loaded from the volume, the DLLs the load brought in attached (see the
/// module doc; STATUS_DLL_NOT_FOUND where no file is found, STATUS_DLL_INIT_FAILED where an entry
/// point answers FALSE) — its handle into `handle` (zero on a failure). The search path the caller
/// passes is not consulted: the default search is ntdll's own (Windows 2000's kernel32 computes
/// the same one and passes it); the characteristics are not consulted.
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
        let entry = load(&formed[..length])?;
        if run_initializers(0).is_err() {
            // The DLL asked for goes again, with what it brought in.
            dereference(entry);
            return Err(STATUS_DLL_INIT_FAILED);
        }
        Ok(base_of(entry))
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

/// LdrDisableThreadCalloutsForDll: the DLL whose handle is `module` gets no DLL_THREAD_ATTACH and
/// DLL_THREAD_DETACH from now on (LDRP_DONT_CALL_FOR_THREADS). STATUS_DLL_NOT_FOUND for a handle
/// naming no module.
#[unsafe(export_name = "f2k_export_LdrDisableThreadCalloutsForDll")]
pub extern "system" fn ldr_disable_thread_callouts_for_dll(module: u32) -> u32 {
    locked(|| match modules::by_base(&Mapped, ldr(), module) {
        Some(entry) => {
            set_flags(entry, flags_of(entry) | flags::DONT_CALL_FOR_THREADS);
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
