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
//!
//! **The stack.** A process's first thread loads its DLLs within the two pages of stack it starts
//! with, as Windows 2000's loader does: the import loading recurses (a DLL's imports load before
//! its own load completes), so its frames keep no MAX_PATH-sized buffers. The paths a level works
//! on live in blocks on the process heap ([`HeapUnits`]), given back before the next level loads;
//! an import's name lives in a frame that ends before it ([`locate_import`]); the failures' reports
//! build their lines in frames of their own.

use core::fmt::Write;
use core::mem::size_of;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicBool, AtomicUsize};

use rtl::heap::HEAP_ZERO_MEMORY;
use rtl::modules::{
    self,
    flags,
    Descriptor,
    Entry,
    Import,
    LdrData,
    Memory,
    MemoryMut,
    Module,
    SearchPath,
    MAX_SEARCH_PATH,
    STATIC_LOAD_COUNT,
};
use rtl::path::{nt_path, MAX_PATH};
use rtl::pod::Pod;
use rtl::status::{
    STATUS_CONFLICTING_ADDRESSES,
    STATUS_DLL_INIT_FAILED,
    STATUS_DLL_NOT_FOUND,
    STATUS_ENTRYPOINT_NOT_FOUND,
    STATUS_IMAGE_NOT_AT_BASE,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_ORDINAL_NOT_FOUND,
    STATUS_SUCCESS,
};
use rtl::string::{AnsiString, UnicodeString};
use rtl::stub::Line;
use rtl::sys::{self, Native};

use crate::curdir;
use crate::params::{image_path, image_path_name};
use crate::service::{self, ObjectAttributes, CURRENT_PROCESS};

/// The process's own memory, read and written in place by address (a bad pointer faults the
/// caller, as on Windows 2000): the loader's lists and what they reach, and the images the process
/// has mapped. Only [`Mapped::new`] makes one, whose caller answers for the addresses; the loader's
/// own code gets it from the loader lock ([`locked`]). A copy vouches for what the original does
/// (a walk of the lists reads through one while the loader changes them through the other).
#[derive(Clone, Copy)]
pub(crate) struct Mapped {
    _vouched: (),
}

impl Mapped {
    /// The handle, for the addresses its caller vouches for.
    ///
    /// # Safety
    ///
    /// Every address read through the handle is in readable memory of the process's own, and
    /// every address written through it in writable memory that nothing else reads or writes
    /// meanwhile: the loader's lists and the entries, images and strings they reach, under the
    /// loader lock; an image the process has mapped, its headers and the structures they name; or
    /// a structure the caller vouches for the same way.
    pub(crate) unsafe fn new() -> Mapped {
        Mapped { _vouched: () }
    }
}

impl Memory for Mapped {
    fn byte(&self, at: u32) -> u8 {
        // SAFETY: a readable address of the process's own (`Mapped::new`'s contract).
        unsafe { (at as usize as *const u8).read_volatile() }
    }

    fn read<T: Pod>(&self, at: u32) -> T {
        // SAFETY: as above, for the `T`'s bytes; any bytes there make a `T` (plain data), read at
        // any alignment.
        unsafe { (at as usize as *const T).read_unaligned() }
    }
}

impl MemoryMut for Mapped {
    fn set_byte(&mut self, at: u32, value: u8) {
        // SAFETY: a writable address of the process's own that nothing else touches meanwhile
        // (`Mapped::new`'s contract): the lists' entries, their links and their strings, on the
        // process heap, and the images' import address tables.
        unsafe { (at as usize as *mut u8).write_volatile(value) }
    }

    fn write<T: Pod>(&mut self, at: u32, value: T) {
        // SAFETY: as above, for the `T`'s bytes, at any alignment.
        unsafe { (at as usize as *mut T).write_unaligned(value) }
    }
}

/// The process's PEB_LDR_DATA (zero until the process's initialization makes it).
fn ldr() -> u32 {
    sys::ldr() as u32
}

/// `body`, the loader lock held, over the process's memory: what the lists hold is the loader's
/// to read and change while it holds the lock.
fn locked<T>(body: impl FnOnce(&mut Mapped) -> T) -> T {
    crate::process::loader_lock().with(&Native, || {
        // SAFETY: under the loader lock, the loader reads and writes through the handle only the
        // lists, the entries, images and strings they reach (on the process heap, or mapped for
        // as long as their entries are listed), and the import address tables it makes writable
        // for a snap; and the images and names its exports' callers pass, as Windows 2000's
        // loader reads them in place.
        let mut memory = unsafe { Mapped::new() };
        body(&mut memory)
    })
}

/// UTF-16 units in a block on the process heap, zeroed, given back when dropped: the buffers the
/// loader would otherwise keep on the stack (see the module doc).
struct HeapUnits {
    at: core::ptr::NonNull<u16>,
    length: usize,
}

impl HeapUnits {
    /// A fresh block of `length` units; none without room.
    fn new(length: usize) -> Option<Self> {
        let at = sys::process_heap().alloc(&Native, HEAP_ZERO_MEMORY, 2 * length)?;
        Some(Self {
            at: core::ptr::NonNull::new(at as *mut u16)?,
            length,
        })
    }
}

impl core::ops::Deref for HeapUnits {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        // SAFETY: the block holds `length` zeroed units, aligned as the heap aligns every block,
        // ours alone until dropped.
        unsafe { core::slice::from_raw_parts(self.at.as_ptr(), self.length) }
    }
}

impl core::ops::DerefMut for HeapUnits {
    fn deref_mut(&mut self) -> &mut [u16] {
        // SAFETY: as above.
        unsafe { core::slice::from_raw_parts_mut(self.at.as_ptr(), self.length) }
    }
}

impl Drop for HeapUnits {
    fn drop(&mut self) {
        sys::process_heap().free(&Native, 0, self.at.as_ptr() as usize);
    }
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

/// The loader's own state, in ntdll's data as on Windows 2000: how many of the process's DLLs are
/// owed calls (their entry point called with DLL_PROCESS_ATTACH, not yet with DLL_PROCESS_DETACH),
/// and whether the process's initialization is under way (its failures are reported on the
/// debugger's channel). Both change under the loader lock.
static ATTACHED: AtomicUsize = AtomicUsize::new(0);
static INITIALIZING: AtomicBool = AtomicBool::new(false);

/// How many DLLs are owed calls.
fn attached() -> usize {
    ATTACHED.load(Relaxed)
}

/// One DLL more (`true`) or fewer owed calls.
fn count_attached(more: bool) {
    let count = attached();
    ATTACHED.store(
        if more {
            count + 1
        } else {
            count.saturating_sub(1)
        },
        Relaxed,
    );
}

/// Whether the process's initialization is under way.
fn initializing() -> bool {
    INITIALIZING.load(Relaxed)
}

/// Mark the process's initialization under way, or over.
fn set_initializing(under_way: bool) {
    INITIALIZING.store(under_way, Relaxed);
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

/// KUSER_SHARED_DATA, as far as its NtSystemRoot (`C:\WINNT`, NUL-terminated): the one place every
/// system path comes from.
#[repr(C)]
struct SharedData {
    tick_count_low: u32,
    tick_count_multiplier: u32,
    /// InterruptTime, SystemTime and TimeZoneBias: KSYSTEM_TIMEs (LowPart, High1Time, High2Time).
    times: [[u32; 3]; 3],
    image_number_low: u16,
    image_number_high: u16,
    nt_system_root: [u16; MAX_PATH],
}

/// Where every process maps KUSER_SHARED_DATA, read-only.
const SHARED_DATA: usize = 0x7FFE_0000;

/// KUSER_SHARED_DATA.
fn shared_data() -> &'static SharedData {
    // SAFETY: the shared data page, mapped read-only into every process for its whole life.
    unsafe { &*(SHARED_DATA as *const SharedData) }
}

/// The environment variable the search's last places come from.
const PATH: [u16; 4] = [b'P' as u16, b'A' as u16, b'T' as u16, b'H' as u16];

/// The longest PATH the search reads, in units (a longer one is cut there).
const PATH_ROOM: usize = 512;

/// The entry of the module `name` names (see `rtl::modules::by_name`; a name with a path made
/// absolute first, RtlGetFullPathName_U's way). Under the loader lock.
fn find(memory: &Mapped, name: &[u16]) -> Option<Module> {
    // The name with its default extension, terminated (the zeroes past it).
    let mut formed = [0u16; NAME_ROOM];
    let length = modules::module_name(name, &mut formed[..NAME_ROOM - 1])?;
    if !modules::has_path(&formed[..length]) {
        return modules::by_name(memory, ldr(), &formed[..length]);
    }
    find_by_path(memory, &formed[..length + 1])
}

/// The entry of the module whose formed name `formed` (terminated) has a path: the name made
/// absolute (RtlGetFullPathName_U) on the process heap (no room there: none found), matched
/// against the modules' full paths. Never inlined: its frame ends before a load goes on.
#[inline(never)]
fn find_by_path(memory: &Mapped, formed: &[u16]) -> Option<Module> {
    let mut full = HeapUnits::new(MAX_PATH + 1)?;
    // SAFETY: the formed name is terminated; the buffer holds its length in units.
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
    modules::by_name(memory, ldr(), &full[..bytes / 2])
}

/// The module's handle (its base).
fn base_of(memory: &Mapped, module: Module) -> u32 {
    module.base(memory)
}

/// A module's load count, raised (or lowered) to `change`'s answer.
fn change_load_count(memory: &mut Mapped, module: Module, change: fn(u16) -> u16) {
    let count = module.load_count(memory);
    module.set_load_count(memory, change(count));
}

/// A module's LDRP_* flags with `set` set and `clear` cleared.
fn change_flags(memory: &mut Mapped, module: Module, set: u32, clear: u32) {
    let flags = module.flags(memory);
    module.set_flags(memory, (flags & !clear) | set);
}

/// Call the entry point of `module` with `reason` and `reserved`: its answer (zero: FALSE).
fn call_entry(memory: &Mapped, module: Module, reason: u32, reserved: u32) -> u32 {
    let entry = module.entry(memory);
    // SAFETY: the module's own entry point, as its headers name it: a DllMain.
    unsafe { f2k_call_dll_entry(entry.entry_point, entry.dll_base, reason, reserved) }
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
/// it in a hard-error popup): `body` writes what failed. Never inlined: its line stays out of the
/// loader's frames.
#[inline(never)]
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

/// The open, section and view arguments a load passes, as Windows 2000's loader passes them: the
/// file opened to read and execute, shared for reading and deleting, synchronously, never a
/// directory; an image section mapped for reading and executing; the view shared, PAGE_READWRITE
/// (an image's pages take their sections' protections).
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
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &string,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };
    service::open_file(
        &attributes,
        FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    )
}

/// Close a handle.
fn close(handle: u32) {
    service::close(handle);
}

/// Map the image file `file` names as an image section's view: its base and its size.
fn map_image(file: u32) -> Result<(u32, u32), u32> {
    let section = service::create_section(
        SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        PAGE_EXECUTE,
        SEC_IMAGE,
        file,
    )?;
    let (mut base, mut size) = (0u32, 0u32);
    let status =
        service::map_view_of_section(section, &mut base, &mut size, VIEW_SHARE, PAGE_READWRITE);
    // The view holds the image (its file's segment), not the section: the section goes now.
    close(section);
    match status {
        STATUS_SUCCESS => Ok((base, size)),
        // Mapped away from its base, which another region holds: the loader does not relocate,
        // so the view goes and the load fails.
        STATUS_IMAGE_NOT_AT_BASE => {
            unmap(base);
            Err(STATUS_CONFLICTING_ADDRESSES)
        }
        status => Err(status),
    }
}

/// Unmap the view of a module's image at `base`, whose entry is out of the lists (or never joined
/// them): nothing reaches it any more.
fn unmap(base: u32) {
    // SAFETY: the view a load mapped, whose module the lists no longer hold: the loader keeps no
    // reference into an image (it reads and writes one by address, through `Mapped`), and reaches
    // a module only through the lists.
    unsafe { service::unmap_view_of_section(base) };
}

/// Give the pages `[at, at + size)` of an image's import address table the protection `protect`:
/// their old protection.
fn protect(at: u32, size: u32, protect: u32) -> Result<u32, u32> {
    let (mut base, mut size) = (at, size);
    // SAFETY: an import address table's pages, which the loader writes by address alone (through
    // `Mapped`, holding no reference into them), and which no code reads while its image's imports
    // are snapped, the image not yet initialized.
    unsafe { service::protect_virtual_memory(&mut base, &mut size, protect) }
}

/// The entry of the module mapped at `base` (`size` bytes; none: its headers' SizeOfImage) from
/// the full path `path`, made on the process heap (the path's text after it) and joined to the
/// load and memory orders; none without room.
fn add_entry(memory: &mut Mapped, base: u32, size: Option<u32>, path: &[u16]) -> Option<Module> {
    let room = 2 * (path.len() + 1);
    let at = sys::process_heap().alloc(&Native, 0, size_of::<Entry>() + room)? as u32;
    let buffer = at + size_of::<Entry>() as u32;
    let module = modules::loaded(memory, base, size);
    // A fresh block of the entry's size and the path's room: the entry, then the path and its
    // terminator.
    memory.write(
        at,
        modules::loaded_entry(at, &module, buffer, path, room as u32),
    );
    for (index, &unit) in path.iter().chain(&[0]).enumerate() {
        memory.write(buffer + 2 * index as u32, unit);
    }
    let module = Module(at);
    modules::insert(memory, ldr(), module);
    Some(module)
}

/// The system root (KUSER_SHARED_DATA's NtSystemRoot), in place, at most MAX_PATH less one units.
fn system_root() -> &'static [u16] {
    let root = &shared_data().nt_system_root[..MAX_PATH - 1];
    &root[..root
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(root.len())]
}

/// Where a search's buffers (see [`find_file`]) sit in its block: the current directory's copy,
/// PATH's value, then each place's full path.
const SEARCH_CURRENT: usize = MAX_PATH + 1;
const SEARCH_PATH: usize = PATH_ROOM;
const SEARCH_FULL: usize = MAX_SEARCH_PATH + 1;

/// A module's file, found and opened: its handle, and the full path it was found at (`length`
/// units, terminated, in the search's block).
struct Found {
    file: u32,
    length: usize,
    buffers: HeapUnits,
}

impl Found {
    /// The full path the file was found at.
    fn path(&self) -> &[u16] {
        let at = SEARCH_CURRENT + SEARCH_PATH;
        &self.buffers[at..at + self.length]
    }
}

/// Find the file of the module `name` (formed: its default extension supplied) where Windows 2000
/// looks (see the module doc), and open it, the search's buffers in one block on the process heap
/// (no room there: STATUS_NO_MEMORY). Never inlined, as [`open_file`]: the search's frames end
/// before the load goes on.
#[inline(never)]
fn find_file(name: &[u16]) -> Result<Found, u32> {
    let mut buffers =
        HeapUnits::new(SEARCH_CURRENT + SEARCH_PATH + SEARCH_FULL).ok_or(STATUS_NO_MEMORY)?;
    let (current, rest) = buffers.split_at_mut(SEARCH_CURRENT);
    let (path, full) = rest.split_at_mut(SEARCH_PATH);
    let (current_length, _) = curdir::current_directory(current);
    let path_length = crate::env::process_variable(&PATH, path);
    let search = SearchPath {
        image: image_path(),
        current: &current[..current_length],
        system_root: system_root(),
        path: &path[..path_length],
    };
    let opened = (0..modules::search_places(name, &search)).find_map(|index| {
        let length = modules::search_place(name, &search, index, full)?;
        open_file(&full[..length]).ok().map(|file| (file, length))
    });
    let (file, length) = opened.ok_or(STATUS_DLL_NOT_FOUND)?;
    Ok(Found {
        file,
        length,
        buffers,
    })
}

/// [`find_file`], a module not found reported (see [`report`]).
fn open_module(name: &[u16]) -> Result<Found, u32> {
    find_file(name).inspect_err(|&status| {
        if status == STATUS_DLL_NOT_FOUND {
            report_not_found(name);
        }
    })
}

/// Report a module that was not found (see [`report`]).
#[inline(never)]
fn report_not_found(name: &[u16]) {
    let mut shown = [0u8; 96];
    report(|line| write!(line, "{} was not found", narrow(name, &mut shown)));
}

/// Report a module's file that could not be mapped (see [`report`]).
#[inline(never)]
fn report_unmapped(path: &[u16], status: u32) {
    let mut shown = [0u8; 96];
    report(|line| {
        write!(
            line,
            "{} could not be mapped (status {status:#010X})",
            narrow(path, &mut shown)
        )
    });
}

/// Load the module `name` (formed: its default extension supplied) from the volume: see
/// [`load_file`].
fn load(memory: &mut Mapped, name: &[u16]) -> Result<Module, u32> {
    load_file(memory, open_module(name)?)
}

/// Load the module whose file `found` opened (see the module doc): its entry, its load count 1, its
/// imports snapped, in the initialization order (its entry point not called yet). The search's
/// buffers go back to the heap before its imports load. Under the loader lock.
fn load_file(memory: &mut Mapped, found: Found) -> Result<Module, u32> {
    let mapped = map_image(found.file);
    // The section holds the file.
    close(found.file);
    let (base, size) = mapped.inspect_err(|&status| report_unmapped(found.path(), status))?;
    let added = add_entry(memory, base, Some(size), found.path());
    drop(found);
    let Some(module) = added else {
        unmap(base);
        return Err(STATUS_NO_MEMORY);
    };
    if let Err((status, referenced)) = snap(memory, base) {
        discard(memory, module, referenced);
        return Err(status);
    }
    modules::insert_initialized(memory, ldr(), module);
    Ok(module)
}

/// What the lists or the volume hold for a module an image imports: its entry, or its file, found
/// and opened.
enum Located {
    Listed(Module),
    Opened(Found),
}

/// The module an import descriptor names (its ANSI name at `name`, formed): its entry in the lists,
/// or else its file, found and opened (a module not found reported). STATUS_DLL_NOT_FOUND for a
/// name that does not fit. Never inlined: the name's buffer stays out of the recursion's frames.
#[inline(never)]
fn locate_import(memory: &Mapped, name: u32) -> Result<Located, u32> {
    let mut formed = [0u16; NAME_ROOM];
    let length =
        modules::import_module_name(memory, name, &mut formed).ok_or(STATUS_DLL_NOT_FOUND)?;
    match find(memory, &formed[..length]) {
        Some(module) => Ok(Located::Listed(module)),
        None => open_module(&formed[..length]).map(Located::Opened),
    }
}

/// The entry of the module an import descriptor names (its ANSI name at `name`), when the lists
/// hold it. Never inlined, as [`locate_import`].
#[inline(never)]
fn find_import(memory: &Mapped, name: u32) -> Option<Module> {
    let mut formed = [0u16; NAME_ROOM];
    let length = modules::import_module_name(memory, name, &mut formed)?;
    find(memory, &formed[..length])
}

/// Snap the imports of the image mapped at `base` against the lists, descriptor by descriptor: each
/// module it imports referenced once more, or loaded. On a failure, its status and how many
/// descriptors' modules were referenced.
fn snap(memory: &mut Mapped, base: u32) -> Result<(), (u32, usize)> {
    // The descriptors are read through a copy of the handle while the loads write through it.
    let image = *memory;
    for (index, descriptor) in modules::import_descriptors(&image, base).enumerate() {
        let located = locate_import(memory, descriptor.name).map_err(|status| (status, index))?;
        let module = match located {
            Located::Listed(module) => {
                change_load_count(memory, module, modules::referenced);
                base_of(memory, module)
            }
            Located::Opened(found) => {
                let module = load_file(memory, found).map_err(|status| (status, index))?;
                base_of(memory, module)
            }
        };
        snap_descriptor(memory, base, &descriptor, module).map_err(|status| (status, index + 1))?;
    }
    Ok(())
}

/// Write each IAT slot of `descriptor` (of the image at `base`) with its import's address in the
/// module whose handle is `module`, the IAT writable meanwhile. An import the module does not
/// export is STATUS_ENTRYPOINT_NOT_FOUND by name, STATUS_ORDINAL_NOT_FOUND by ordinal, as Windows
/// 2000's snap answers.
fn snap_descriptor(
    memory: &mut Mapped,
    base: u32,
    descriptor: &Descriptor,
    module: u32,
) -> Result<(), u32> {
    let count = modules::imports(memory, base, descriptor.lookup).count() as u32;
    if count == 0 {
        return Ok(());
    }
    let old = protect(descriptor.iat, 4 * count, PAGE_READWRITE)?;
    let ldr = ldr();
    let mut snapped = Ok(());
    // The imports are read through a copy of the handle while the slots are written through it.
    let image = *memory;
    for (index, import) in modules::imports(&image, base, descriptor.lookup).enumerate() {
        match modules::import_address(memory, ldr, module, import) {
            Ok(address) => memory.write(descriptor.iat + 4 * index as u32, address),
            Err(status) => {
                snapped = Err(match (status, import) {
                    // A forwarder naming a module the process has not loaded.
                    (STATUS_DLL_NOT_FOUND, _) => status,
                    (_, Import::Ordinal(_)) => STATUS_ORDINAL_NOT_FOUND,
                    (_, Import::Name(_)) => STATUS_ENTRYPOINT_NOT_FOUND,
                });
                report_import(memory, import, descriptor.name);
                break;
            }
        }
    }
    let _ = protect(descriptor.iat, 4 * count, old);
    snapped
}

/// Report an import that does not resolve, of the module an import descriptor names (its ANSI name
/// at `module`; see [`report`]).
#[inline(never)]
fn report_import(memory: &Mapped, import: Import, module: u32) {
    let mut formed = [0u16; NAME_ROOM];
    let length = modules::import_module_name(memory, module, &mut formed).unwrap_or(0);
    let mut shown = [0u8; 96];
    let module = narrow(&formed[..length], &mut shown);
    report(|line| match import {
        Import::Ordinal(ordinal) => write!(line, "ordinal {ordinal} was not found in {module}"),
        Import::Name(at) => {
            let mut text = [0u8; 96];
            let length = (0..text.len())
                .find(|&index| {
                    text[index] = memory.byte(at + index as u32);
                    text[index] == 0
                })
                .unwrap_or(text.len());
            let name = core::str::from_utf8(&text[..length]).unwrap_or("?");
            write!(line, "the entry point {name} was not found in {module}")
        }
    });
}

/// One reference fewer to `module`: a loaded module's last unloads it (a module the process
/// started with keeps its count).
fn dereference(memory: &mut Mapped, module: Module) {
    let count = module.load_count(memory);
    module.set_load_count(memory, modules::released(count));
    if count == 1 {
        discard(memory, module, usize::MAX);
    }
}

/// Unload the loaded `module`: its entry point called with DLL_PROCESS_DETACH (lpReserved NULL)
/// when it had its DLL_PROCESS_ATTACH, out of the lists, the modules its first `referenced` import
/// descriptors name released, its view unmapped, its entry freed.
fn discard(memory: &mut Mapped, module: Module, referenced: usize) {
    let base = base_of(memory, module);
    module.set_load_count(memory, 0);
    if module.flags(memory) & flags::PROCESS_ATTACH_CALLED != 0 {
        change_flags(memory, module, 0, flags::PROCESS_ATTACH_CALLED);
        count_attached(false);
        call_entry(memory, module, DLL_PROCESS_DETACH, 0);
    }
    modules::remove(memory, module);
    // The descriptors are read through a copy of the handle while the releases write through it.
    let image = *memory;
    for descriptor in modules::import_descriptors(&image, base).take(referenced) {
        if let Some(found) = find_import(memory, descriptor.name) {
            dereference(memory, found);
        }
    }
    unmap(base);
    sys::process_heap().free(&Native, 0, module.at() as usize);
}

/// The most entries one pass of the entry-point calls takes.
const MAX_CALLS: usize = 64;

/// Call DLL_PROCESS_ATTACH, with `reserved`, on every DLL of the initialization order the loader
/// has not processed yet, in that order (each processed once, whatever its answer): the first one
/// answering FALSE. Each pass takes the pending entries first, so a load an entry point makes runs
/// its own DLLs' calls alone. Under the loader lock.
fn run_initializers(memory: &mut Mapped, reserved: u32) -> Result<(), Module> {
    loop {
        let mut pending = [Module(0); MAX_CALLS];
        let mut count = 0;
        // The order is walked through a copy of the handle while the flags are written through it.
        let lists = *memory;
        for module in modules::initialization_order(&lists, ldr(), false) {
            if module.flags(memory) & flags::ENTRY_PROCESSED != 0 {
                continue;
            }
            if count == MAX_CALLS {
                break;
            }
            change_flags(memory, module, flags::ENTRY_PROCESSED, 0);
            pending[count] = module;
            count += 1;
        }
        if count == 0 {
            return Ok(());
        }
        for &module in &pending[..count] {
            if module.entry_point(memory) == 0 {
                continue;
            }
            change_flags(memory, module, flags::PROCESS_ATTACH_CALLED, 0);
            count_attached(true);
            if call_entry(memory, module, DLL_PROCESS_ATTACH, reserved) == 0 {
                return Err(module);
            }
        }
    }
}

/// ntdll's entry: its path under the system root (built on the process heap), its base the
/// linker's symbol; none without room.
fn add_ntdll(memory: &mut Mapped) -> Option<Module> {
    let mut path = HeapUnits::new(MAX_PATH)?;
    let root = system_root();
    let file = b"\\system32\\ntdll.dll";
    path[..root.len()].copy_from_slice(root);
    for (unit, &byte) in path[root.len()..].iter_mut().zip(file) {
        *unit = u16::from(byte);
    }
    // The linker's symbol, by address only.
    let base = core::ptr::addr_of!(IMAGE_BASE) as u32;
    add_entry(memory, base, None, &path[..root.len() + file.len()])
}

/// The process's initialization, on its first thread once the process heap and the locks are made
/// (see the module doc): the lists built, the image's imports loaded and snapped, every module
/// static. The failure's status.
pub(crate) fn initialize_process() -> Result<(), u32> {
    set_initializing(true);
    locked(|memory| {
        let heap = sys::process_heap();
        let lists = heap
            .alloc(&Native, 0, size_of::<LdrData>())
            .ok_or(STATUS_NO_MEMORY)? as u32;
        // A fresh block of the PEB_LDR_DATA's size.
        memory.write(lists, modules::empty_lists(lists));
        sys::set_ldr(lists as usize);

        // The image: its full path the process parameters' own string, its entry processed (it is
        // not initialized as a DLL is), in no initialization order.
        let base = sys::image_base() as u32;
        let at = heap
            .alloc(&Native, 0, size_of::<Entry>())
            .ok_or(STATUS_NO_MEMORY)? as u32;
        let path = image_path_name();
        // A fresh block of the entry's size.
        memory.write(
            at,
            modules::loaded_entry(
                at,
                &modules::loaded(memory, base, None),
                path.buffer as u32,
                image_path(),
                u32::from(path.maximum_length),
            ),
        );
        let image = Module(at);
        image.clear_initialization_links(memory);
        change_flags(memory, image, flags::ENTRY_PROCESSED, 0);
        modules::insert(memory, lists, image);

        // ntdll: at the system directory, first in the initialization order, its entry processed
        // (it has no entry point).
        let ntdll = add_ntdll(memory).ok_or(STATUS_NO_MEMORY)?;
        change_flags(memory, ntdll, flags::ENTRY_PROCESSED, 0);
        modules::insert_initialized(memory, lists, ntdll);

        // The image's imports, then every module the process starts with made static.
        snap(memory, base).map_err(|(status, _)| status)?;
        // The order is walked through a copy of the handle while the counts are written through it.
        let walk = *memory;
        for module in modules::load_order(&walk, lists) {
            module.set_load_count(memory, STATIC_LOAD_COUNT);
        }
        Ok(())
    })
}

/// The process's DLLs' DLL_PROCESS_ATTACH, on its first thread once its TLS is made, lpReserved
/// `context` (the thread's initial context): STATUS_DLL_INIT_FAILED when an entry point answers
/// FALSE (reported, see [`report`]). The process's initialization is over either way.
pub(crate) fn attach_process(context: u32) -> Result<(), u32> {
    let answer = locked(|memory| {
        run_initializers(memory, context).map_err(|module| {
            let mut name = [0u16; 96];
            let length =
                modules::string_units(memory, &module.entry(memory).base_dll_name, &mut name);
            let mut shown = [0u8; 96];
            report(|line| {
                write!(
                    line,
                    "{}'s initialization failed (its entry point answered FALSE)",
                    narrow(&name[..length], &mut shown)
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
    service::terminate_process(CURRENT_PROCESS, status);
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
    locked(|memory| {
        let mut owed = [Module(0); MAX_NOTIFIED];
        let mut count = 0;
        let mut take = |module: Module| {
            let flags = module.flags(memory);
            if flags & flags::PROCESS_ATTACH_CALLED != 0
                && !(threads && flags & flags::DONT_CALL_FOR_THREADS != 0)
                && count < MAX_NOTIFIED
            {
                owed[count] = module;
                count += 1;
            }
        };
        let ldr = ldr();
        match order {
            Order::Memory => modules::memory_order(memory, ldr).for_each(&mut take),
            Order::Unwinding => {
                modules::initialization_order(memory, ldr, true).for_each(&mut take)
            }
        }
        for &module in &owed[..count] {
            if reason == DLL_PROCESS_DETACH {
                change_flags(memory, module, 0, flags::PROCESS_ATTACH_CALLED);
                count_attached(false);
            }
            call_entry(memory, module, reason, reserved);
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
    let found = locked(|memory| find(memory, name).map(|module| base_of(memory, module)));
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
    let found = locked(|memory| {
        if let Some(module) = find(memory, name) {
            change_load_count(memory, module, modules::referenced);
            return Ok(base_of(memory, module));
        }
        let mut formed = [0u16; NAME_ROOM];
        let length =
            modules::module_name(name, &mut formed[..NAME_ROOM - 1]).ok_or(STATUS_DLL_NOT_FOUND)?;
        let module = load(memory, &formed[..length])?;
        if run_initializers(memory, 0).is_err() {
            // The DLL asked for goes again, with what it brought in.
            dereference(memory, module);
            return Err(STATUS_DLL_INIT_FAILED);
        }
        Ok(base_of(memory, module))
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
    locked(|memory| match modules::by_base(memory, ldr(), module) {
        Some(module) if module.load_count(memory) == STATIC_LOAD_COUNT => STATUS_SUCCESS,
        Some(module) => {
            dereference(memory, module);
            STATUS_SUCCESS
        }
        None => STATUS_DLL_NOT_FOUND,
    })
}

/// LdrDisableThreadCalloutsForDll: the DLL whose handle is `module` gets no DLL_THREAD_ATTACH and
/// DLL_THREAD_DETACH from now on (LDRP_DONT_CALL_FOR_THREADS). A handle naming no module changes
/// nothing and succeeds (the dllmain capture: DisableThreadLibraryCalls answers TRUE for one, the
/// last error untouched).
#[unsafe(export_name = "f2k_export_LdrDisableThreadCalloutsForDll")]
pub extern "system" fn ldr_disable_thread_callouts_for_dll(module: u32) -> u32 {
    locked(|memory| match modules::by_base(memory, ldr(), module) {
        Some(module) => {
            change_flags(memory, module, flags::DONT_CALL_FOR_THREADS, 0);
            STATUS_SUCCESS
        }
        None => STATUS_SUCCESS,
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
    let found = locked(|memory| match name {
        Some(name) => modules::procedure_address(memory, ldr(), module, name),
        None => modules::procedure_by_ordinal(memory, ldr(), module, ordinal),
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
