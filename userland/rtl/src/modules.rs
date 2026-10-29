//! The loader's module lists and the export directories, as Windows 2000's ntdll keeps and reads
//! them.
//!
//! The PEB's Ldr (PEB_LDR_DATA) heads three lists of the process's modules (LDR_DATA_TABLE_ENTRY):
//! in load order (the image, ntdll, then each DLL as it is mapped), in memory order (the same), and
//! in initialization order (ntdll, then each DLL once its imports are snapped, so a DLL comes after
//! the DLLs it imports; the image is not initialized as a DLL is). Programs and packers walk the
//! lists themselves (to find kernel32's base), so the layout is the platform's, byte for byte
//! (`rtl::peb`'s [`PebLdrData`] and [`LdrDataTableEntry`]). ntdll's process initialization builds
//! them in user mode, on the process heap, as Windows 2000's LdrpInitializeProcess does: the
//! image's entry and ntdll's, then every DLL the image imports, loaded and snapped like any other.
//! A DLL joins them as it is mapped ([`loaded_entry`], [`insert`]), its imports walked and snapped
//! against them ([`import_descriptors`], [`import_address`]), joins the initialization order once
//! they are ([`insert_initialized`]), and leaves them at its last unload ([`remove`]).
//!
//! What ntdll's loader exports do over them (LdrGetDllHandle, LdrGetProcedureAddress, LdrLoadDll,
//! LdrUnloadDll): find a module by its base, or by its name ([`by_name`]: without regard to case,
//! against its BaseDllName, or against its FullDllName for a name with a path, which the caller
//! has made absolute; a name without an extension is taken as `.DLL`); look for a module's file
//! where Windows 2000 looks ([`search_place`]); and find an export of a module by its exact name or
//! by its ordinal, through the module's export directory as mapped ([`procedure_address`],
//! [`procedure_by_ordinal`]), following forwarders (`NTDLL.RtlUnwind`, split at the first dot;
//! `NTDLL.#12` by ordinal) into the modules they name.
//!
//! The reads and writes go through [`Memory`] and [`MemoryMut`], by 32-bit user address, each
//! structure whole as its `#[repr(C)]` type ([`Module`] is an entry's address): the process's own
//! memory on the target, a model in the tests.

use core::cmp::Ordering;
use core::mem::{offset_of, size_of};

use crate::image::{self, ImageExportDirectory, ImageImportDescriptor};
use crate::nt::UnicodeString;
use crate::peb::{LdrDataTableEntry, ListEntry, PebLdrData};
use crate::pod::Pod;
use crate::status::{
    STATUS_DLL_NOT_FOUND,
    STATUS_ENTRYPOINT_NOT_FOUND,
    STATUS_ORDINAL_NOT_FOUND,
    STATUS_PROCEDURE_NOT_FOUND,
};

/// The memory the lists and the images are read from, by user address.
pub trait Memory {
    /// The byte at `at`.
    fn byte(&self, at: u32) -> u8;

    /// The `T` at `at`, read whole, at any alignment (little-endian, as the target and the hosts
    /// the tests run on are).
    fn read<T: Pod>(&self, at: u32) -> T {
        let mut value = T::zeroed();
        for (offset, byte) in value.as_bytes_mut().iter_mut().enumerate() {
            *byte = self.byte(at.wrapping_add(offset as u32));
        }
        value
    }

    /// The word at `at`.
    fn half(&self, at: u32) -> u16 {
        self.read(at)
    }

    /// The dword at `at`.
    fn word(&self, at: u32) -> u32 {
        self.read(at)
    }
}

/// The memory the lists are changed in, by user address.
pub trait MemoryMut: Memory {
    /// Write the byte at `at`.
    fn set_byte(&mut self, at: u32, value: u8);

    /// Write `value` whole at `at`, at any alignment.
    fn write<T: Pod>(&mut self, at: u32, value: T) {
        for (offset, &byte) in value.as_bytes().iter().enumerate() {
            self.set_byte(at.wrapping_add(offset as u32), byte);
        }
    }
}

/// PEB_LDR_DATA and LDR_DATA_TABLE_ENTRY as a 32-bit process's memory holds them.
pub type LdrData = PebLdrData<u32>;
pub type Entry = LdrDataTableEntry<u32>;

/// The LDRP_* flags of an entry: a DLL's image (LDRP_IMAGE_DLL); an entry the loader's
/// initialization pass has taken (LDRP_ENTRY_PROCESSED: its entry point called, or none to call);
/// a DLL whose thread notifications are off (LDRP_DONT_CALL_FOR_THREADS:
/// LdrDisableThreadCalloutsForDll); and a DLL whose entry point has been called with
/// DLL_PROCESS_ATTACH (LDRP_PROCESS_ATTACH_CALLED: it is owed its DLL_PROCESS_DETACH).
pub mod flags {
    pub const IMAGE_DLL: u32 = 0x0000_0004;
    pub const ENTRY_PROCESSED: u32 = 0x0000_4000;
    pub const DONT_CALL_FOR_THREADS: u32 = 0x0004_0000;
    pub const PROCESS_ATTACH_CALLED: u32 = 0x0008_0000;
}

/// The load count of a module loaded with the process (its image's imports): never unloaded, the
/// count not kept.
pub const STATIC_LOAD_COUNT: u16 = 0xFFFF;

/// The extension a module name without one is taken to have.
const DEFAULT_EXTENSION: [u16; 4] = [b'.' as u16, b'D' as u16, b'L' as u16, b'L' as u16];

/// How many entries a walk visits at most: a list a program has corrupted into a cycle ends there.
const MAX_ENTRIES: usize = 1024;

/// How many forwarders a resolution follows, and the longest forwarder string it reads.
const FORWARD_DEPTH: usize = 8;
const FORWARDER_ROOM: usize = 256;

const BACKSLASH: u16 = b'\\' as u16;
const SLASH: u16 = b'/' as u16;
const DOT: u16 = b'.' as u16;

/// Where a LIST_ENTRY's two links sit in it.
const FLINK: u32 = offset_of!(ListEntry<u32>, flink) as u32;
const BLINK: u32 = offset_of!(ListEntry<u32>, blink) as u32;

/// A LIST_ENTRY at `node` linked to itself: an empty list's head, or an entry in no list.
fn self_linked(node: u32) -> ListEntry<u32> {
    ListEntry {
        flink: node,
        blink: node,
    }
}

/// The three lists: load, memory and initialization order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    Load,
    Memory,
    Initialization,
}

impl Order {
    const ALL: [Order; 3] = [Order::Load, Order::Memory, Order::Initialization];

    /// Where the list's head sits in a PEB_LDR_DATA.
    const fn head(self) -> u32 {
        (match self {
            Order::Load => offset_of!(LdrData, in_load_order_module_list),
            Order::Memory => offset_of!(LdrData, in_memory_order_module_list),
            Order::Initialization => offset_of!(LdrData, in_initialization_order_module_list),
        }) as u32
    }

    /// Where an entry's links in the list sit in it.
    const fn links(self) -> u32 {
        (match self {
            Order::Load => offset_of!(Entry, in_load_order_links),
            Order::Memory => offset_of!(Entry, in_memory_order_links),
            Order::Initialization => offset_of!(Entry, in_initialization_order_links),
        }) as u32
    }
}

/// A module of the lists: the address of its LDR_DATA_TABLE_ENTRY ([`Entry`]), which the walks
/// find and the loader makes, read and changed through a [`Memory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module(pub u32);

impl Module {
    /// The entry's address.
    pub fn at(self) -> u32 {
        self.0
    }

    /// The entry, read whole.
    pub fn entry<M: Memory>(self, memory: &M) -> Entry {
        memory.read(self.0)
    }

    /// The module's handle: its image's base.
    pub fn base<M: Memory>(self, memory: &M) -> u32 {
        self.entry(memory).dll_base
    }

    /// The module's entry point (zero for none).
    pub fn entry_point<M: Memory>(self, memory: &M) -> u32 {
        self.entry(memory).entry_point
    }

    /// The module's load count.
    pub fn load_count<M: Memory>(self, memory: &M) -> u16 {
        self.entry(memory).load_count
    }

    /// The module's LDRP_* flags ([`flags`]).
    pub fn flags<M: Memory>(self, memory: &M) -> u32 {
        self.entry(memory).flags
    }

    /// Replace the module's load count, in place.
    pub fn set_load_count<M: MemoryMut>(self, memory: &mut M, count: u16) {
        memory.write(self.0 + offset_of!(Entry, load_count) as u32, count);
    }

    /// Replace the module's flags, in place.
    pub fn set_flags<M: MemoryMut>(self, memory: &mut M, value: u32) {
        memory.write(self.0 + offset_of!(Entry, flags) as u32, value);
    }

    /// Unlink the module from the initialization order's links of its own (zeroes: in no list, as
    /// the image's entry is), in place.
    pub fn clear_initialization_links<M: MemoryMut>(self, memory: &mut M) {
        memory.write(
            self.0 + Order::Initialization.links(),
            ListEntry::<u32>::default(),
        );
    }
}

/// The entries of the list `order` of the PEB_LDR_DATA at `ldr`: from its head's Flink, or from
/// its Blink for `backward`.
fn walk<M: Memory>(
    memory: &M,
    ldr: u32,
    order: Order,
    backward: bool,
) -> impl Iterator<Item = Module> + '_ {
    let head = ldr.wrapping_add(order.head());
    let step = move |node: ListEntry<u32>| if backward { node.blink } else { node.flink };
    let mut next = step(memory.read(head));
    let mut left = MAX_ENTRIES;
    core::iter::from_fn(move || {
        if next == head || next == 0 || left == 0 {
            return None;
        }
        left -= 1;
        let module = Module(next.wrapping_sub(order.links()));
        next = step(memory.read(next));
        Some(module)
    })
}

/// The modules of the PEB_LDR_DATA at `ldr`, in load order.
pub fn load_order<M: Memory>(memory: &M, ldr: u32) -> impl Iterator<Item = Module> + '_ {
    walk(memory, ldr, Order::Load, false)
}

/// The modules of the PEB_LDR_DATA at `ldr`, in memory order (the order the thread attach
/// notifications take).
pub fn memory_order<M: Memory>(memory: &M, ldr: u32) -> impl Iterator<Item = Module> + '_ {
    walk(memory, ldr, Order::Memory, false)
}

/// The modules of the PEB_LDR_DATA at `ldr` in initialization order (a DLL after the DLLs it
/// imports), or in its reverse for `backward` (the order the detach notifications take).
pub fn initialization_order<M: Memory>(
    memory: &M,
    ldr: u32,
    backward: bool,
) -> impl Iterator<Item = Module> + '_ {
    walk(memory, ldr, Order::Initialization, backward)
}

/// The module whose base is `base` (its handle).
pub fn by_base<M: Memory>(memory: &M, ldr: u32, base: u32) -> Option<Module> {
    load_order(memory, ldr).find(|module| module.base(memory) == base)
}

/// Whether a module name carries a path (a separator: it is then matched against the modules' full
/// paths).
pub fn has_path(name: &[u16]) -> bool {
    name.iter().any(|&unit| unit == BACKSLASH || unit == SLASH)
}

/// A module name as the lookups take it, into `out`: a name whose file part has no extension takes
/// `.DLL`, and one ending in a dot (a name without an extension, as the documentation spells it)
/// loses the dot. Its length; none when it does not fit.
pub fn module_name(name: &[u16], out: &mut [u16]) -> Option<usize> {
    let file = &name[name
        .iter()
        .rposition(|&unit| unit == BACKSLASH || unit == SLASH)
        .map_or(0, |at| at + 1)..];
    let (kept, extension): (usize, &[u16]) = if file.last() == Some(&DOT) {
        (name.len() - 1, &[])
    } else if file.contains(&DOT) {
        (name.len(), &[])
    } else {
        (name.len(), &DEFAULT_EXTENSION)
    };
    let length = kept + extension.len();
    if length > out.len() {
        return None;
    }
    out[..kept].copy_from_slice(&name[..kept]);
    out[kept..length].copy_from_slice(extension);
    Some(length)
}

/// Whether `string` (its buffer in `memory`) holds `name`, without regard to case.
fn string_is<M: Memory>(memory: &M, string: &UnicodeString<u32>, name: &[u16]) -> bool {
    usize::from(string.length) / 2 == name.len()
        && name.iter().enumerate().all(|(index, &unit)| {
            crate::path::upcase(memory.half(string.buffer + 2 * index as u32))
                == crate::path::upcase(unit)
        })
}

/// The units of `string` (its buffer in `memory`) into `out`, cut to its room: their count.
pub fn string_units<M: Memory>(memory: &M, string: &UnicodeString<u32>, out: &mut [u16]) -> usize {
    let length = (usize::from(string.length) / 2).min(out.len());
    for (index, unit) in out[..length].iter_mut().enumerate() {
        *unit = memory.half(string.buffer + 2 * index as u32);
    }
    length
}

/// The module `name` names (as [`module_name`] forms it): its BaseDllName without regard to case,
/// or its FullDllName for a name with a path (the caller made it absolute).
pub fn by_name<M: Memory>(memory: &M, ldr: u32, name: &[u16]) -> Option<Module> {
    let full = has_path(name);
    load_order(memory, ldr).find(|module| {
        let entry = module.entry(memory);
        let string = if full {
            &entry.full_dll_name
        } else {
            &entry.base_dll_name
        };
        string_is(memory, string, name)
    })
}

/// LdrLoadDll's count for a module loaded once more: one more reference, a static module's count
/// staying as it is.
pub fn referenced(count: u16) -> u16 {
    if count == STATIC_LOAD_COUNT {
        count
    } else {
        count.wrapping_add(1)
    }
}

/// LdrUnloadDll's count for a module freed once: one reference fewer, a static module's count
/// staying (a module the process started with is never unloaded), a count already at zero too.
pub fn released(count: u16) -> u16 {
    if count == STATIC_LOAD_COUNT || count == 0 {
        count
    } else {
        count - 1
    }
}

/// An export, as the export directory gives it: its address, or the address of its forwarder
/// string (`MODULE.Name`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Export {
    Address(u32),
    Forwarder(u32),
}

/// The NUL-terminated string at `at` against `name`, as strcmp orders them.
fn compare<M: Memory>(memory: &M, at: u32, name: &[u8]) -> Ordering {
    for (index, &byte) in name.iter().enumerate() {
        match memory.byte(at + index as u32).cmp(&byte) {
            Ordering::Equal => {}
            unequal => return unequal,
        }
    }
    if memory.byte(at + name.len() as u32) == 0 {
        Ordering::Equal
    } else {
        Ordering::Greater
    }
}

/// The export directory's fields a lookup reads, of the image mapped at `base`: where the directory
/// lies (a function in it is a forwarder), the ordinal base, and the three tables' sizes and
/// addresses.
struct Directory {
    rva: u32,
    size: u32,
    ordinal_base: u32,
    functions: u32,
    names: u32,
    function_table: u32,
    name_table: u32,
    ordinal_table: u32,
}

impl Directory {
    /// The export directory of the image mapped at `base`; STATUS_PROCEDURE_NOT_FOUND for an image
    /// without one.
    fn of<M: Memory>(memory: &M, base: u32) -> Result<Directory, u32> {
        let place = image::mapped_directory(memory, base, image::DIRECTORY_EXPORT)
            .ok_or(STATUS_PROCEDURE_NOT_FOUND)?;
        let directory: ImageExportDirectory = memory.read(base.wrapping_add(place.virtual_address));
        Ok(Directory {
            rva: place.virtual_address,
            size: place.size,
            ordinal_base: directory.base,
            functions: directory.number_of_functions,
            names: directory.number_of_names,
            function_table: base.wrapping_add(directory.address_of_functions),
            name_table: base.wrapping_add(directory.address_of_names),
            ordinal_table: base.wrapping_add(directory.address_of_name_ordinals),
        })
    }

    /// The export in address-table slot `slot` of the image at `base`: STATUS_ENTRYPOINT_NOT_FOUND
    /// past the table or for an empty slot.
    fn slot<M: Memory>(&self, memory: &M, base: u32, slot: u32) -> Result<Export, u32> {
        if slot >= self.functions {
            return Err(STATUS_ENTRYPOINT_NOT_FOUND);
        }
        let function = memory.word(self.function_table + 4 * slot);
        if function == 0 {
            return Err(STATUS_ENTRYPOINT_NOT_FOUND);
        }
        let forwarder = function >= self.rva && function - self.rva < self.size;
        let address = base.wrapping_add(function);
        Ok(if forwarder {
            Export::Forwarder(address)
        } else {
            Export::Address(address)
        })
    }
}

/// The export named `name` (exactly: case counts) of the image mapped at `base`, by a binary search
/// of its sorted name table (Windows 2000's LdrpNameToOrdinal). STATUS_PROCEDURE_NOT_FOUND for an
/// image without exports, STATUS_ENTRYPOINT_NOT_FOUND for a name it does not export.
pub fn export_by_name<M: Memory>(memory: &M, base: u32, name: &[u8]) -> Result<Export, u32> {
    let directory = Directory::of(memory, base)?;
    let (mut low, mut high) = (0u32, directory.names);
    while low < high {
        let middle = low + (high - low) / 2;
        let candidate = base.wrapping_add(memory.word(directory.name_table + 4 * middle));
        match compare(memory, candidate, name) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => {
                let slot = u32::from(memory.half(directory.ordinal_table + 2 * middle));
                return directory.slot(memory, base, slot);
            }
        }
    }
    Err(STATUS_ENTRYPOINT_NOT_FOUND)
}

/// The export with ordinal `ordinal` of the image mapped at `base`: biased by the directory's
/// ordinal base, through its address table. STATUS_PROCEDURE_NOT_FOUND for an image without
/// exports, STATUS_ORDINAL_NOT_FOUND for an ordinal outside the table or an empty slot (Windows
/// 2000's: GetProcAddress of an ordinal a DLL does not export is ERROR_INVALID_ORDINAL).
pub fn export_by_ordinal<M: Memory>(memory: &M, base: u32, ordinal: u32) -> Result<Export, u32> {
    let directory = Directory::of(memory, base)?;
    let slot = ordinal
        .checked_sub(directory.ordinal_base)
        .ok_or(STATUS_ORDINAL_NOT_FOUND)?;
    directory
        .slot(memory, base, slot)
        .map_err(|_| STATUS_ORDINAL_NOT_FOUND)
}

/// The base of the module a forwarder's module part names (`NTDLL`: a name without an extension, so
/// `NTDLL.DLL`); STATUS_DLL_NOT_FOUND for one the process has not loaded.
fn forwarded_module<M: Memory>(memory: &M, ldr: u32, module: &[u8]) -> Result<u32, u32> {
    let mut wide = [0u16; FORWARDER_ROOM];
    for (unit, &byte) in wide.iter_mut().zip(module) {
        *unit = u16::from(byte);
    }
    let mut name = [0u16; FORWARDER_ROOM + DEFAULT_EXTENSION.len()];
    let length = module_name(&wide[..module.len()], &mut name).ok_or(STATUS_DLL_NOT_FOUND)?;
    by_name(memory, ldr, &name[..length])
        .map(|module| module.base(memory))
        .ok_or(STATUS_DLL_NOT_FOUND)
}

/// A forwarder's target entry (what follows its module part's dot): by name, or by ordinal for a
/// `#` and decimal digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    Name(&'a [u8]),
    Ordinal(u32),
}

/// Split a forwarder string `MODULE.Entry` at its first dot: the module part (everything before it)
/// and the entry (everything after, dots and all; `#n` an ordinal). None without a dot, with an
/// empty part, or with an ordinal that is not decimal digits.
pub fn split_forwarder(text: &[u8]) -> Option<(&[u8], Target<'_>)> {
    let dot = text.iter().position(|&byte| byte == b'.')?;
    let (module, entry) = (&text[..dot], &text[dot + 1..]);
    if module.is_empty() || entry.is_empty() {
        return None;
    }
    let Some(digits) = entry.strip_prefix(b"#") else {
        return Some((module, Target::Name(entry)));
    };
    if digits.is_empty() || digits.len() > 9 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let ordinal = digits
        .iter()
        .fold(0u32, |value, &digit| 10 * value + u32::from(digit - b'0'));
    Some((module, Target::Ordinal(ordinal)))
}

/// `export`'s address, its forwarders followed into the modules they name (each split at its first
/// dot, its entry looked up by name or by ordinal).
fn followed<M: Memory>(memory: &M, ldr: u32, mut export: Export) -> Result<u32, u32> {
    let mut text = [0u8; FORWARDER_ROOM];
    for _ in 0..FORWARD_DEPTH {
        let at = match export {
            Export::Address(address) => return Ok(address),
            Export::Forwarder(at) => at,
        };
        let length = (0..FORWARDER_ROOM)
            .find(|&index| {
                text[index] = memory.byte(at + index as u32);
                text[index] == 0
            })
            .ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
        let (module, target) =
            split_forwarder(&text[..length]).ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
        let base = forwarded_module(memory, ldr, module)?;
        export = match target {
            Target::Name(name) => export_by_name(memory, base, name)?,
            Target::Ordinal(ordinal) => export_by_ordinal(memory, base, ordinal)?,
        };
    }
    match export {
        Export::Address(address) => Ok(address),
        Export::Forwarder(_) => Err(STATUS_ENTRYPOINT_NOT_FOUND),
    }
}

/// LdrGetProcedureAddress's work: the address of the export `name` of the module whose handle is
/// `module`, its forwarders followed. STATUS_DLL_NOT_FOUND for a handle naming no module of the
/// lists (or a forwarder naming a module the process has not loaded); [`export_by_name`]'s
/// statuses for a name the module does not export.
pub fn procedure_address<M: Memory>(
    memory: &M,
    ldr: u32,
    module: u32,
    name: &[u8],
) -> Result<u32, u32> {
    by_base(memory, ldr, module).ok_or(STATUS_DLL_NOT_FOUND)?;
    followed(memory, ldr, export_by_name(memory, module, name)?)
}

/// LdrGetProcedureAddress's work for an ordinal: the address of the export with ordinal `ordinal`
/// of the module whose handle is `module`, its forwarders followed. STATUS_DLL_NOT_FOUND for a
/// handle naming no module of the lists; [`export_by_ordinal`]'s statuses for an ordinal the module
/// does not export.
pub fn procedure_by_ordinal<M: Memory>(
    memory: &M,
    ldr: u32,
    module: u32,
    ordinal: u32,
) -> Result<u32, u32> {
    by_base(memory, ldr, module).ok_or(STATUS_DLL_NOT_FOUND)?;
    followed(memory, ldr, export_by_ordinal(memory, module, ordinal)?)
}

// --- Loading a module: LdrLoadDll's and LdrUnloadDll's work over the lists ---------------------

/// Where a load looks for a module's file: Windows 2000 SP4's default search (SafeDllSearchMode
/// off), as kernel32 computes it for LoadLibrary and the process parameters carry it for the
/// image's imports. A bare name is looked for in the program's directory, the current directory,
/// the system directory (`<SystemRoot>\system32`), the 16-bit system directory
/// (`<SystemRoot>\system`), the Windows directory (`<SystemRoot>`), then each directory of PATH,
/// in its order; a name with a path is used as given, made absolute against the current directory.
/// KnownDLLs is not consulted (there is no registry to list them).
#[derive(Clone, Copy, Debug)]
pub struct SearchPath<'a> {
    /// The program's full path (the process parameters' ImagePathName): its directory is the
    /// first place.
    pub image: &'a [u16],
    /// The current directory's DOS path, its trailing separator included.
    pub current: &'a [u16],
    /// The system root (KUSER_SHARED_DATA's NtSystemRoot, `C:\WINNT`).
    pub system_root: &'a [u16],
    /// PATH's value: directories separated by semicolons (empty entries ignored).
    pub path: &'a [u16],
}

/// The places of the search under the system root, after the program's and the current directory:
/// each one's directory relative to the root.
const SYSTEM_PLACES: [&[u8]; 3] = [b"\\system32", b"\\system", b""];

/// How many places the search for `name` (as [`module_name`] formed it) has: one for a name with a
/// path; for a bare name, the fixed five and PATH's directories.
pub fn search_places(name: &[u16], search: &SearchPath) -> usize {
    if has_path(name) {
        1
    } else {
        2 + SYSTEM_PLACES.len() + path_directories(search.path).count()
    }
}

/// PATH's directories, in order (empty entries skipped).
fn path_directories(path: &[u16]) -> impl Iterator<Item = &[u16]> {
    path.split(|&unit| unit == u16::from(b';'))
        .filter(|directory| !directory.is_empty())
}

/// Place `index` (below [`search_places`]) of the search for `name` (as [`module_name`] formed
/// it): the full DOS path into `out` (terminated), its length; none for a place the name cannot be
/// joined to within MAX_PATH (the search moves on to the next), and for the current directory when
/// it is the program's own (the place was just tried).
pub fn search_place(
    name: &[u16],
    search: &SearchPath,
    index: usize,
    out: &mut [u16],
) -> Option<usize> {
    if has_path(name) {
        return if index == 0 {
            absolute(&[name], search.current, out)
        } else {
            None
        };
    }
    let image_directory = &search.image[..search
        .image
        .iter()
        .rposition(|&unit| unit == BACKSLASH || unit == SLASH)
        .map_or(0, |at| at + 1)];
    let mut system = [0u16; 16];
    let parts: [&[u16]; 3] = match index {
        0 => [image_directory, &[], name],
        1 if same_path(search.current, image_directory) => return None,
        1 => [search.current, &[], name],
        _ if index < 2 + SYSTEM_PLACES.len() => {
            let place = SYSTEM_PLACES[index - 2];
            for (unit, &byte) in system.iter_mut().zip(place) {
                *unit = u16::from(byte);
            }
            [search.system_root, &system[..place.len()], name]
        }
        _ => [
            path_directories(search.path).nth(index - 2 - SYSTEM_PLACES.len())?,
            &[],
            name,
        ],
    };
    absolute(&parts, search.current, out)
}

/// Whether two directories' paths are one, without regard to case.
fn same_path(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(&a, &b)| crate::path::upcase(a) == crate::path::upcase(b))
}

/// `parts` joined into one path (a separator before the last part, the name, unless what precedes
/// it ends in one), made absolute against `current` and folded into `out`, terminated: its length.
/// Never inlined: its buffers stay out of its callers' frames, which the system DLLs keep below a
/// page (a frame of a page or more calls a stack probe the DLLs' link does not carry).
#[inline(never)]
fn absolute(parts: &[&[u16]], current: &[u16], out: &mut [u16]) -> Option<usize> {
    let mut joined = [0u16; MAX_SEARCH_PATH + 1];
    let mut length = 0;
    let last = parts.len() - 1;
    for (index, part) in parts.iter().enumerate() {
        if index == last && length > 0 && !matches!(joined[length - 1], BACKSLASH | SLASH) {
            *joined.get_mut(length)? = BACKSLASH;
            length += 1;
        }
        joined
            .get_mut(length..length + part.len())?
            .copy_from_slice(part);
        length += part.len();
    }
    let mut full = [0u16; MAX_SEARCH_PATH + 1];
    let (length, _) = full_path_name(&joined[..length], current, &mut full).ok()?;
    out.get_mut(..length + 1)?
        .copy_from_slice(&full[..length + 1]);
    Some(length)
}

/// The longest full path a search builds, in units: MAX_PATH less its terminator.
pub const MAX_SEARCH_PATH: usize = crate::path::MAX_PATH - 1;

use crate::path::full_path_name;

/// A module the loader mapped, as its entry records it: its base (its handle), its entry point
/// (zero for none), its size as mapped, its file header's TimeDateStamp, and whether it is a DLL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub base: u32,
    pub entry_point: u32,
    pub size: u32,
    pub time_date_stamp: u32,
    pub dll: bool,
}

/// The facts an entry records of the image mapped at `base`, read from its headers (its size the
/// mapping's, `size`, or the headers' SizeOfImage for none): see [`Loaded`].
pub fn loaded<M: Memory>(memory: &M, base: u32, size: Option<u32>) -> Loaded {
    let nt = image::mapped_headers(memory, base);
    let entry_rva = nt.optional_header.address_of_entry_point;
    Loaded {
        base,
        entry_point: if entry_rva == 0 {
            0
        } else {
            base.wrapping_add(entry_rva)
        },
        size: size.unwrap_or(nt.optional_header.size_of_image),
        time_date_stamp: nt.file_header.time_date_stamp,
        dll: nt.file_header.characteristics & image::FILE_DLL != 0,
    }
}

/// The LDR_DATA_TABLE_ENTRY of a module the loader mapped, to be written at `at`: `module`, its
/// FullDllName the path it was opened by (`path`, in units, at `buffer`, its room `room` bytes),
/// its BaseDllName the path's file part (the name as asked, its default extension supplied); a
/// LoadCount of 1, TlsIndex 0, the hash links empty (no hash table: the lookups walk the lists),
/// the load and memory order links left for [`insert`], and the initialization order's linked to
/// the entry itself until [`insert_initialized`] (so [`remove`] leaves alone an entry that never
/// joined it). Its flags say a DLL's image (LDRP_IMAGE_DLL), nothing processed yet.
pub fn loaded_entry(at: u32, module: &Loaded, buffer: u32, path: &[u16], room: u32) -> Entry {
    let length = 2 * path.len() as u32;
    let file = 2 * path
        .iter()
        .rposition(|&unit| unit == BACKSLASH)
        .map_or(0, |at| at + 1) as u32;
    Entry {
        in_initialization_order_links: self_linked(at + Order::Initialization.links()),
        dll_base: module.base,
        entry_point: module.entry_point,
        size_of_image: module.size,
        full_dll_name: UnicodeString {
            length: length as u16,
            maximum_length: room as u16,
            buffer,
        },
        base_dll_name: UnicodeString {
            length: (length - file) as u16,
            maximum_length: (room - file) as u16,
            buffer: buffer + file,
        },
        flags: if module.dll { flags::IMAGE_DLL } else { 0 },
        load_count: 1,
        hash_links: self_linked(at + offset_of!(Entry, hash_links) as u32),
        time_date_stamp: module.time_date_stamp,
        ..Entry::default()
    }
}

/// Link the LIST_ENTRY at `node` last in the list headed at `head`.
fn link_last<M: MemoryMut>(memory: &mut M, head: u32, node: u32) {
    let last = memory.read::<ListEntry<u32>>(head).blink;
    memory.write(
        node,
        ListEntry {
            flink: head,
            blink: last,
        },
    );
    memory.write(last + FLINK, node);
    memory.write(head + BLINK, node);
}

/// Unlink the LIST_ENTRY at `node` from its list (one linked to itself stays as it is).
fn unlink<M: MemoryMut>(memory: &mut M, node: u32) {
    let ListEntry {
        flink: next,
        blink: previous,
    } = memory.read(node);
    memory.write(previous + FLINK, next);
    memory.write(next + BLINK, previous);
}

/// An empty PEB_LDR_DATA, to be written at `at`: its Length, Initialized, and the three lists'
/// heads linked to themselves.
pub fn empty_lists(at: u32) -> LdrData {
    LdrData {
        length: size_of::<LdrData>() as u32,
        initialized: 1,
        ss_handle: 0,
        in_load_order_module_list: self_linked(at + Order::Load.head()),
        in_memory_order_module_list: self_linked(at + Order::Memory.head()),
        in_initialization_order_module_list: self_linked(at + Order::Initialization.head()),
    }
}

/// `module` joins the load and memory orders of the PEB_LDR_DATA at `ldr`, after their last
/// entries (its image is mapped).
pub fn insert<M: MemoryMut>(memory: &mut M, ldr: u32, module: Module) {
    for order in [Order::Load, Order::Memory] {
        link_last(memory, ldr + order.head(), module.0 + order.links());
    }
}

/// `module` joins the initialization order of the PEB_LDR_DATA at `ldr`, after its last entry (its
/// imports are snapped: every DLL it imports is already there).
pub fn insert_initialized<M: MemoryMut>(memory: &mut M, ldr: u32, module: Module) {
    let order = Order::Initialization;
    link_last(memory, ldr + order.head(), module.0 + order.links());
}

/// `module` leaves the three lists.
pub fn remove<M: MemoryMut>(memory: &mut M, module: Module) {
    for order in Order::ALL {
        unlink(memory, module.0 + order.links());
    }
}

/// One import descriptor of a mapped image, by address: its module's name (an ANSI string), the
/// thunks the walk reads (its import lookup table, or the IAT itself without one), and its IAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub name: u32,
    pub lookup: u32,
    pub iat: u32,
}

/// The longest import tables a walk reads: descriptors, and thunks in one table.
const MAX_DESCRIPTORS: usize = 256;
const MAX_THUNKS: usize = 0x4000;

/// The import descriptors of the image mapped at `base`, to the all-zero one (none for an image
/// without an import directory).
pub fn import_descriptors<M: Memory>(
    memory: &M,
    base: u32,
) -> impl Iterator<Item = Descriptor> + '_ {
    let rva = image::mapped_directory(memory, base, image::DIRECTORY_IMPORT)
        .map_or(0, |place| place.virtual_address);
    let mut at = base.wrapping_add(rva);
    let mut left = if rva == 0 { 0 } else { MAX_DESCRIPTORS };
    core::iter::from_fn(move || {
        if left == 0 {
            return None;
        }
        left -= 1;
        let descriptor: ImageImportDescriptor = memory.read(at);
        if descriptor.name == 0 || descriptor.first_thunk == 0 {
            left = 0;
            return None;
        }
        at += size_of::<ImageImportDescriptor>() as u32;
        let lookup = match descriptor.original_first_thunk {
            0 => descriptor.first_thunk,
            original => original,
        };
        Some(Descriptor {
            name: base.wrapping_add(descriptor.name),
            lookup: base.wrapping_add(lookup),
            iat: base.wrapping_add(descriptor.first_thunk),
        })
    })
}

/// One import, as a thunk names it: by name (the address of its hint/name entry's name, past the
/// entry's two-byte hint), or by ordinal (the thunk's high bit set: IMAGE_ORDINAL_FLAG32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Import {
    Name(u32),
    Ordinal(u32),
}

/// A thunk's ordinal flag (IMAGE_ORDINAL_FLAG32), and the hint before a hint/name entry's name.
const ORDINAL_FLAG: u32 = 0x8000_0000;
const HINT_SIZE: u32 = size_of::<u16>() as u32;

/// The imports of the lookup table at `lookup` of the image at `base`, to its zero thunk.
pub fn imports<M: Memory>(memory: &M, base: u32, lookup: u32) -> impl Iterator<Item = Import> + '_ {
    (0..MAX_THUNKS as u32)
        .map(move |index| memory.word(lookup + 4 * index))
        .take_while(|&thunk| thunk != 0)
        .map(move |thunk| {
            if thunk & ORDINAL_FLAG != 0 {
                Import::Ordinal(thunk & 0xFFFF)
            } else {
                Import::Name(base.wrapping_add(thunk) + HINT_SIZE)
            }
        })
}

/// The longest import name a snap reads.
const MAX_IMPORT_NAME: usize = 256;

/// The address an IAT slot receives for `import` of the module whose handle is `module`: its
/// export by name or by ordinal, forwarders followed ([`procedure_address`],
/// [`procedure_by_ordinal`]).
pub fn import_address<M: Memory>(
    memory: &M,
    ldr: u32,
    module: u32,
    import: Import,
) -> Result<u32, u32> {
    match import {
        Import::Ordinal(ordinal) => procedure_by_ordinal(memory, ldr, module, ordinal),
        Import::Name(at) => {
            let mut name = [0u8; MAX_IMPORT_NAME];
            let length = (0..MAX_IMPORT_NAME)
                .find(|&index| {
                    name[index] = memory.byte(at + index as u32);
                    name[index] == 0
                })
                .ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
            procedure_address(memory, ldr, module, &name[..length])
        }
    }
}

/// The module name a descriptor names (an ANSI string at `at`), as [`module_name`] forms it, into
/// `out`: its length; none when it does not fit.
pub fn import_module_name<M: Memory>(memory: &M, at: u32, out: &mut [u16]) -> Option<usize> {
    let mut wide = [0u16; FORWARDER_ROOM];
    let length = (0..FORWARDER_ROOM).find(|&index| {
        wide[index] = u16::from(memory.byte(at + index as u32));
        wide[index] == 0
    })?;
    module_name(&wide[..length], out)
}

/// A model of a process's memory for the tests, here and in the kernel's: regions of bytes at
/// their addresses.
#[cfg(test)]
pub mod model {
    use super::*;

    /// Regions of bytes, by their base addresses.
    #[derive(Default)]
    pub struct Space(pub std::vec::Vec<(u32, std::vec::Vec<u8>)>);

    impl Memory for Space {
        fn byte(&self, at: u32) -> u8 {
            for (base, bytes) in &self.0 {
                if at >= *base && ((at - base) as usize) < bytes.len() {
                    return bytes[(at - base) as usize];
                }
            }
            panic!("{at:#010x} is not mapped");
        }
    }

    impl MemoryMut for Space {
        fn set_byte(&mut self, at: u32, value: u8) {
            for (base, bytes) in &mut self.0 {
                if at >= *base && ((at - *base) as usize) < bytes.len() {
                    bytes[(at - *base) as usize] = value;
                    return;
                }
            }
            panic!("{at:#010x} is not mapped");
        }
    }

    /// `image` (one [`image`] builds) importing `imports` (module, then each import: a name, or an
    /// ordinal), its descriptors at RVA 0x800, the lookup tables at 0x900, the IATs at 0xA00 and
    /// the names from 0xB00.
    pub fn with_imports(
        mut image: std::vec::Vec<u8>,
        imports: &[(&str, &[Result<&str, u32>])],
    ) -> std::vec::Vec<u8> {
        let put = |image: &mut std::vec::Vec<u8>, at: usize, value: u32| {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes())
        };
        let (mut lookup, mut iat, mut strings) = (0x900, 0xA00, 0xB00);
        for (index, (module, entries)) in imports.iter().enumerate() {
            let descriptor = 0x800 + 20 * index;
            image[strings..strings + module.len()].copy_from_slice(module.as_bytes());
            put(&mut image, descriptor, lookup as u32);
            put(&mut image, descriptor + 12, strings as u32);
            put(&mut image, descriptor + 16, iat as u32);
            strings += module.len() + 1;
            for entry in entries.iter() {
                let thunk = match entry {
                    Ok(name) => {
                        let at = strings as u32;
                        image[strings + 2..strings + 2 + name.len()]
                            .copy_from_slice(name.as_bytes());
                        strings += name.len() + 3;
                        at
                    }
                    Err(ordinal) => 0x8000_0000 | ordinal,
                };
                put(&mut image, lookup, thunk);
                put(&mut image, iat, thunk);
                lookup += 4;
                iat += 4;
            }
            lookup += 4;
            iat += 4;
        }
        put(&mut image, 0x58 + 0x68, 0x800);
        image
    }

    /// A small DLL image's bytes: the headers, and an export directory at RVA 0x200 exporting
    /// `exports` (name, then its function RVA or its forwarder string), its names sorted.
    pub fn image(exports: &[(&str, Result<u32, &str>)]) -> std::vec::Vec<u8> {
        let mut image = std::vec![0u8; 0x1000];
        let put = |image: &mut std::vec::Vec<u8>, at: usize, value: u32| {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes())
        };
        image[0..2].copy_from_slice(b"MZ");
        put(&mut image, 0x3C, 0x40);
        put(&mut image, 0x40, 0x4550);
        image[0x58..0x5A].copy_from_slice(&0x010Bu16.to_le_bytes());
        put(&mut image, 0x58 + 0x5C, 16);
        let mut sorted: std::vec::Vec<_> = exports.to_vec();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let count = sorted.len();
        let directory = 0x200;
        let functions = directory + 0x28;
        let names = functions + 4 * count;
        let ordinals = names + 4 * count;
        let mut strings = ordinals + 2 * count;
        put(&mut image, directory + 0x10, 1);
        put(&mut image, directory + 0x14, count as u32);
        put(&mut image, directory + 0x18, count as u32);
        put(&mut image, directory + 0x1C, functions as u32);
        put(&mut image, directory + 0x20, names as u32);
        put(&mut image, directory + 0x24, ordinals as u32);
        for (index, (name, target)) in sorted.iter().enumerate() {
            // The ordinals run backwards, so a name's index is not its ordinal.
            let ordinal = count - 1 - index;
            image[ordinals + 2 * index..ordinals + 2 * index + 2]
                .copy_from_slice(&(ordinal as u16).to_le_bytes());
            put(&mut image, names + 4 * index, strings as u32);
            image[strings..strings + name.len()].copy_from_slice(name.as_bytes());
            strings += name.len() + 1;
            let function = match target {
                Ok(rva) => *rva,
                Err(forwarder) => {
                    let at = strings;
                    image[strings..strings + forwarder.len()].copy_from_slice(forwarder.as_bytes());
                    strings += forwarder.len() + 1;
                    at as u32
                }
            };
            put(&mut image, functions + 4 * ordinal, function);
        }
        put(&mut image, 0x58 + 0x60, directory as u32);
        put(&mut image, 0x58 + 0x64, (strings - directory) as u32);
        image
    }

    /// A module of a modelled list: its base, its full path, its load count.
    pub struct Listed<'a> {
        pub base: u32,
        pub path: &'a str,
        pub load_count: u16,
    }

    /// A PEB_LDR_DATA at `at` listing `modules` in load and memory order (the first is the image,
    /// left out of the initialization order), each entry's names on the same region.
    pub fn lists(at: u32, modules: &[Listed]) -> std::vec::Vec<u8> {
        let mut space = Space(std::vec![(at, std::vec![0u8; 0x1000])]);
        let entry_at = |index: usize| at + 0x40 + (index * size_of::<Entry>()) as u32;
        let mut strings = entry_at(modules.len());
        let mut entries = std::vec::Vec::new();
        for module in modules {
            let units: std::vec::Vec<u16> = module.path.encode_utf16().collect();
            for (offset, &unit) in units.iter().enumerate() {
                space.write(strings + 2 * offset as u32, unit);
            }
            let file = 2 * units
                .iter()
                .rposition(|&unit| unit == u16::from(b'\\'))
                .map_or(0, |at| at + 1) as u16;
            let length = 2 * units.len() as u16;
            entries.push(Entry {
                dll_base: module.base,
                load_count: module.load_count,
                full_dll_name: UnicodeString {
                    length,
                    maximum_length: length + 2,
                    buffer: strings,
                },
                base_dll_name: UnicodeString {
                    length: length - file,
                    maximum_length: length - file + 2,
                    buffer: strings + u32::from(file),
                },
                ..Entry::default()
            });
            strings += u32::from(length) + 2;
        }
        let mut data = LdrData {
            length: size_of::<LdrData>() as u32,
            initialized: 1,
            ..LdrData::default()
        };
        // Each order's links: the load and memory orders every module, the initialization order all
        // but the image.
        for order in Order::ALL {
            let first = usize::from(order == Order::Initialization);
            let nodes: std::vec::Vec<u32> = core::iter::once(at + order.head())
                .chain((first..modules.len()).map(|index| entry_at(index) + order.links()))
                .collect();
            for index in 0..nodes.len() {
                let links = ListEntry {
                    flink: nodes[(index + 1) % nodes.len()],
                    blink: nodes[(index + nodes.len() - 1) % nodes.len()],
                };
                match index.checked_sub(1) {
                    None => match order {
                        Order::Load => data.in_load_order_module_list = links,
                        Order::Memory => data.in_memory_order_module_list = links,
                        Order::Initialization => data.in_initialization_order_module_list = links,
                    },
                    Some(slot) => {
                        let entry = &mut entries[first + slot];
                        match order {
                            Order::Load => entry.in_load_order_links = links,
                            Order::Memory => entry.in_memory_order_links = links,
                            Order::Initialization => entry.in_initialization_order_links = links,
                        }
                    }
                }
            }
        }
        space.write(at, data);
        for (index, entry) in entries.into_iter().enumerate() {
            space.write(entry_at(index), entry);
        }
        space.0.remove(0).1
    }
}

#[cfg(test)]
mod tests {
    use super::model::{image, lists, with_imports, Listed, Space};
    use super::*;

    const LDR: u32 = 0x0032_0800;
    const IMAGE: u32 = 0x0040_0000;
    const NTDLL: u32 = 0x77F8_0000;
    const KERNEL32: u32 = 0x7C4E_0000;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A process: its image (no exports), ntdll (RtlUnwind at 0x1230, ordinal 1; a dotted export
    /// name) and kernel32 (its own exports, and forwarders into ntdll: to a name, to a name ntdll
    /// lacks, to ordinals in and out of its table, to its dotted name, to a module not loaded).
    fn process() -> Space {
        let mut executable = image(&[]);
        executable[0x58 + 0x5C..0x58 + 0x60].copy_from_slice(&0u32.to_le_bytes()); // no directories
        let ntdll = image(&[
            ("RtlUnwind", Ok(0x1230)),
            ("NtClose", Ok(0x1100)),
            ("Odd.Name", Ok(0x1300)),
        ]);
        let kernel32 = image(&[
            ("GetTickCount", Ok(0x2000)),
            ("ExitProcess", Ok(0x2010)),
            ("RtlUnwind", Err("NTDLL.RtlUnwind")),
            ("Missing", Err("NTDLL.NoSuchName")),
            ("ByOrdinal", Err("NTDLL.#1")),
            ("PastTheTable", Err("NTDLL.#12")),
            ("NotAnOrdinal", Err("NTDLL.#1x")),
            ("Dotted", Err("NTDLL.Odd.Name")),
            ("Elsewhere", Err("USER32.MessageBoxA")),
            ("Hole", Ok(0)),
        ]);
        let modules = [
            Listed {
                base: IMAGE,
                path: "C:\\RUNTIME.EXE",
                load_count: STATIC_LOAD_COUNT,
            },
            Listed {
                base: NTDLL,
                path: "C:\\WINNT\\system32\\ntdll.dll",
                load_count: STATIC_LOAD_COUNT,
            },
            Listed {
                base: KERNEL32,
                path: "C:\\WINNT\\system32\\KERNEL32.DLL",
                load_count: STATIC_LOAD_COUNT,
            },
        ];
        Space(std::vec![
            (LDR, lists(LDR, &modules)),
            (IMAGE, executable),
            (NTDLL, ntdll),
            (KERNEL32, kernel32)
        ])
    }

    fn found(space: &Space, name: &str) -> Option<u32> {
        let mut formed = [0u16; 300];
        let length = module_name(&wide(name), &mut formed)?;
        by_name(space, LDR, &formed[..length]).map(|module| module.base(space))
    }

    /// The load order is the image's, ntdll's, kernel32's; a module is found by its base.
    #[test]
    fn the_lists_walk_in_load_order() {
        let space = process();
        let bases: std::vec::Vec<u32> = load_order(&space, LDR)
            .map(|module| module.base(&space))
            .collect();
        assert_eq!(bases, [IMAGE, NTDLL, KERNEL32]);
        assert!(by_base(&space, LDR, KERNEL32).is_some());
        assert_eq!(by_base(&space, LDR, 0x1234_0000), None);
        assert_eq!(by_base(&space, LDR, 0), None);
    }

    /// Module names: any case, with or without the `.dll` the lookups add, a trailing dot meaning
    /// no extension; a path is matched against the full path, as Windows 2000 matches it (the
    /// caller makes it absolute, its separators backslashes).
    #[test]
    fn modules_answer_to_their_names() {
        let space = process();
        for name in [
            "kernel32.dll",
            "KERNEL32",
            "Kernel32.Dll",
            "C:\\WINNT\\SYSTEM32\\kernel32.dll",
            "c:\\winnt\\system32\\KERNEL32",
        ] {
            assert_eq!(found(&space, name), Some(KERNEL32), "{name}");
        }
        for name in ["ntdll.dll", "NTDLL", "C:\\WINNT\\system32\\NTDLL.DLL"] {
            assert_eq!(found(&space, name), Some(NTDLL), "{name}");
        }
        assert_eq!(found(&space, "runtime.exe"), Some(IMAGE));
        assert_eq!(found(&space, "C:\\runtime.exe"), Some(IMAGE));
        for name in [
            "nosuch.dll",
            "kernel32.exe",
            "runtime",
            "kernel32.",
            "D:\\kernel32.dll",
            "C:\\kernel32.dll",
            "",
        ] {
            assert_eq!(found(&space, name), None, "{name}");
        }
        let mut out = [0u16; 16];
        assert_eq!(
            module_name(&wide("a."), &mut out),
            Some(1),
            "the trailing dot goes"
        );
        let length = module_name(&wide("dir.x\\a"), &mut out).unwrap();
        assert_eq!(
            &out[..length],
            &wide("dir.x\\a.DLL")[..],
            "the file part's extension counts"
        );
        assert_eq!(
            module_name(&wide("abcdef"), &mut [0u16; 8]),
            None,
            "no room for the extension"
        );
    }

    /// Exports: by exact name, through the sorted name table; forwarders followed into the module
    /// they name; the statuses of what is not there.
    #[test]
    fn exports_resolve_by_exact_name() {
        let space = process();
        let address = |module, name: &str| procedure_address(&space, LDR, module, name.as_bytes());
        assert_eq!(address(KERNEL32, "GetTickCount"), Ok(KERNEL32 + 0x2000));
        assert_eq!(address(KERNEL32, "ExitProcess"), Ok(KERNEL32 + 0x2010));
        assert_eq!(
            address(KERNEL32, "RtlUnwind"),
            Ok(NTDLL + 0x1230),
            "the forwarder lands in ntdll"
        );
        assert_eq!(address(NTDLL, "RtlUnwind"), Ok(NTDLL + 0x1230));
        assert_eq!(
            address(KERNEL32, "gettickcount"),
            Err(STATUS_ENTRYPOINT_NOT_FOUND),
            "case counts"
        );
        assert_eq!(
            address(KERNEL32, "GetTickCountx"),
            Err(STATUS_ENTRYPOINT_NOT_FOUND)
        );
        assert_eq!(
            address(KERNEL32, "GetTick"),
            Err(STATUS_ENTRYPOINT_NOT_FOUND)
        );
        assert_eq!(address(KERNEL32, ""), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(
            address(KERNEL32, "Hole"),
            Err(STATUS_ENTRYPOINT_NOT_FOUND),
            "an empty slot"
        );
        assert_eq!(
            address(KERNEL32, "Missing"),
            Err(STATUS_ENTRYPOINT_NOT_FOUND)
        );
        assert_eq!(
            address(KERNEL32, "ByOrdinal"),
            Ok(NTDLL + 0x1230),
            "a forwarder to an ordinal"
        );
        assert_eq!(
            address(KERNEL32, "PastTheTable"),
            Err(STATUS_ORDINAL_NOT_FOUND),
            "an ordinal ntdll lacks"
        );
        assert_eq!(
            address(KERNEL32, "NotAnOrdinal"),
            Err(STATUS_ENTRYPOINT_NOT_FOUND)
        );
        assert_eq!(
            address(KERNEL32, "Dotted"),
            Ok(NTDLL + 0x1300),
            "the first dot splits"
        );
        assert_eq!(address(KERNEL32, "Elsewhere"), Err(STATUS_DLL_NOT_FOUND));
        assert_eq!(
            address(IMAGE, "main"),
            Err(STATUS_PROCEDURE_NOT_FOUND),
            "the image exports nothing"
        );
        assert_eq!(
            address(0x1234_0000, "GetTickCount"),
            Err(STATUS_DLL_NOT_FOUND),
            "no such module"
        );
        let mut long = std::vec![b'x'; 300];
        long[..12].copy_from_slice(b"GetTickCount");
        assert_eq!(
            procedure_address(&space, LDR, KERNEL32, &long),
            Err(STATUS_ENTRYPOINT_NOT_FOUND)
        );
        assert_eq!(
            procedure_by_ordinal(&space, LDR, 0x1234_0000, 1),
            Err(STATUS_DLL_NOT_FOUND)
        );
    }

    /// The ordinal `name` exports under in the image at `base` (the model numbers its slots apart
    /// from its name order).
    fn ordinal_of(space: &Space, base: u32, name: &str) -> u32 {
        let wanted = export_by_name(space, base, name.as_bytes()).unwrap();
        (1..64)
            .find(|&ordinal| export_by_ordinal(space, base, ordinal) == Ok(wanted))
            .unwrap()
    }

    /// Ordinals: biased by the directory's base, through the address table (not the name order);
    /// forwarders followed; outside the table, an empty slot, or the base's own bias undone, no
    /// such ordinal.
    #[test]
    fn exports_resolve_by_ordinal() {
        let space = process();
        let by_ordinal = |module, ordinal| procedure_by_ordinal(&space, LDR, module, ordinal);
        let tick = ordinal_of(&space, KERNEL32, "GetTickCount");
        assert_eq!(by_ordinal(KERNEL32, tick), Ok(KERNEL32 + 0x2000));
        assert_eq!(
            by_ordinal(KERNEL32, ordinal_of(&space, KERNEL32, "RtlUnwind")),
            Ok(NTDLL + 0x1230)
        );
        assert_eq!(
            by_ordinal(KERNEL32, ordinal_of(&space, KERNEL32, "ByOrdinal")),
            Ok(NTDLL + 0x1230)
        );
        assert_eq!(
            by_ordinal(NTDLL, 1),
            Ok(NTDLL + 0x1230),
            "the model's last name takes the first slot"
        );
        assert_eq!(
            by_ordinal(NTDLL, 0),
            Err(STATUS_ORDINAL_NOT_FOUND),
            "below the base"
        );
        assert_eq!(
            by_ordinal(NTDLL, 4),
            Err(STATUS_ORDINAL_NOT_FOUND),
            "past the table"
        );
        assert_eq!(by_ordinal(NTDLL, 0xFFFF), Err(STATUS_ORDINAL_NOT_FOUND));
        // A two-slot image: "A" in slot 1 (ordinal 2), the empty slot 0 (ordinal 1).
        let holed = Space(std::vec![(
            0x1000_0000,
            image(&[("A", Ok(0x10)), ("Hole", Ok(0))])
        )]);
        assert_eq!(
            export_by_ordinal(&holed, 0x1000_0000, 2),
            Ok(Export::Address(0x1000_0010))
        );
        assert_eq!(
            export_by_ordinal(&holed, 0x1000_0000, 1),
            Err(STATUS_ORDINAL_NOT_FOUND),
            "an empty slot"
        );
        assert_eq!(
            by_ordinal(IMAGE, 1),
            Err(STATUS_PROCEDURE_NOT_FOUND),
            "the image exports nothing"
        );
    }

    /// Forwarder strings split at their first dot: the module part before it, the entry (dots and
    /// all) after; `#` and digits an ordinal.
    #[test]
    fn forwarders_split_at_the_first_dot() {
        assert_eq!(
            split_forwarder(b"NTDLL.RtlUnwind"),
            Some((&b"NTDLL"[..], Target::Name(b"RtlUnwind")))
        );
        assert_eq!(
            split_forwarder(b"API.MS.Entry"),
            Some((&b"API"[..], Target::Name(b"MS.Entry")))
        );
        assert_eq!(
            split_forwarder(b"NTDLL.#12"),
            Some((&b"NTDLL"[..], Target::Ordinal(12)))
        );
        for bad in [
            &b"NTDLL"[..],
            b".Entry",
            b"NTDLL.",
            b"NTDLL.#",
            b"NTDLL.#1x",
            b"NTDLL.#1234567890",
        ] {
            assert_eq!(
                split_forwarder(bad),
                None,
                "{:?}",
                core::str::from_utf8(bad)
            );
        }
    }

    /// The load count: a static module's stays; a dynamic one's counts up and down.
    #[test]
    fn load_counts_count() {
        assert_eq!(referenced(STATIC_LOAD_COUNT), STATIC_LOAD_COUNT);
        assert_eq!(released(STATIC_LOAD_COUNT), STATIC_LOAD_COUNT);
        assert_eq!(referenced(1), 2);
        assert_eq!(released(2), 1);
        assert_eq!(released(0), 0);
    }

    /// A list corrupted into a cycle ends the walk.
    #[test]
    fn a_cyclic_list_ends() {
        let mut space = process();
        // The last entry's Flink back to the first entry (not the head).
        let head: ListEntry<u32> = space.read(LDR + Order::Load.head());
        space.write(head.blink + FLINK, head.flink);
        assert_eq!(load_order(&space, LDR).count(), MAX_ENTRIES);
        assert_eq!(by_base(&space, LDR, 0x1234_0000), None);
    }

    /// The bases of the modules the list `order` of the lists at LDR holds, in the order its links
    /// give.
    fn linked(space: &Space, order: Order) -> std::vec::Vec<u32> {
        let head = LDR + order.head();
        let links = |node: u32| space.read::<ListEntry<u32>>(node);
        let mut bases = std::vec::Vec::new();
        let mut node = links(head).flink;
        while node != head {
            bases.push(Module(node - order.links()).base(space));
            assert_eq!(links(links(node).blink).flink, node, "the Blinks agree");
            node = links(node).flink;
        }
        bases
    }

    /// Where a name is looked for, Windows 2000's default order: a bare name in the program's
    /// directory, the current directory (unless it is the program's), the system directory, the
    /// 16-bit system directory, the
    /// Windows directory, then PATH's directories (relative ones against the current directory,
    /// empty entries skipped); a name with a path made absolute against the current directory, one
    /// place; the case as asked, the default extension as `module_name` supplied it.
    #[test]
    fn modules_are_searched_for_where_windows_2000_looks() {
        let places =
            |name: &str, current: &str, path: &str| -> std::vec::Vec<std::string::String> {
                let mut formed = [0u16; 300];
                let length = module_name(&wide(name), &mut formed).unwrap();
                let (image, current, root, path) = (
                    wide("C:\\CORPUS\\RUNTIME.EXE"),
                    wide(current),
                    wide("C:\\WINNT"),
                    wide(path),
                );
                let search = SearchPath {
                    image: &image,
                    current: &current,
                    system_root: &root,
                    path: &path,
                };
                (0..search_places(&formed[..length], &search))
                    .filter_map(|index| {
                        let mut out = [0u16; MAX_SEARCH_PATH + 1];
                        let length = search_place(&formed[..length], &search, index, &mut out)?;
                        assert_eq!(out[length], 0, "terminated");
                        Some(std::string::String::from_utf16(&out[..length]).unwrap())
                    })
                    .collect()
            };
        assert_eq!(
            places("kernel32.dll", "c:\\corpus\\", ""),
            [
                "C:\\CORPUS\\kernel32.dll",
                "C:\\WINNT\\system32\\kernel32.dll",
                "C:\\WINNT\\system\\kernel32.dll",
                "C:\\WINNT\\kernel32.dll",
            ],
            "the current directory the program's: tried once"
        );
        assert_eq!(
            places("Companion", "C:\\CORPUS\\DLLSUB\\", ""),
            [
                "C:\\CORPUS\\Companion.DLL",
                "C:\\CORPUS\\DLLSUB\\Companion.DLL",
                "C:\\WINNT\\system32\\Companion.DLL",
                "C:\\WINNT\\system\\Companion.DLL",
                "C:\\WINNT\\Companion.DLL",
            ]
        );
        assert_eq!(
            places("comp.", "C:\\", ";C:\\TOOLS\\;;bin;"),
            [
                "C:\\CORPUS\\comp",
                "C:\\comp",
                "C:\\WINNT\\system32\\comp",
                "C:\\WINNT\\system\\comp",
                "C:\\WINNT\\comp",
                "C:\\TOOLS\\comp",
                "C:\\bin\\comp",
            ],
            "a trailing dot: no extension; PATH's directories, a relative one made absolute"
        );
        assert_eq!(
            places("sub\\comp", "C:\\CORPUS\\", "C:\\TOOLS"),
            ["C:\\CORPUS\\sub\\comp.DLL"],
            "a relative path: one place"
        );
        assert_eq!(places("..\\comp.dll", "C:\\CORPUS\\", ""), ["C:\\comp.dll"]);
        assert_eq!(
            places("C:\\elsewhere\\COMP.DLL", "C:\\CORPUS\\", ""),
            ["C:\\elsewhere\\COMP.DLL"]
        );
        assert_eq!(
            places("/elsewhere/comp", "C:\\CORPUS\\", ""),
            ["C:\\elsewhere\\comp.DLL"]
        );
        let long = wide(&"x".repeat(300));
        let (image, current, root) = (wide("C:\\A.EXE"), wide("C:\\"), wide("C:\\WINNT"));
        let search = SearchPath {
            image: &image,
            current: &current,
            system_root: &root,
            path: &[],
        };
        assert_eq!(search_places(&long, &search), 5);
        for index in 0..5 {
            assert_eq!(
                search_place(&long, &search, index, &mut [0u16; MAX_SEARCH_PATH + 1]),
                None,
                "past MAX_PATH"
            );
        }
    }

    /// A loaded module's entry: its base, entry point, size and stamp; its full path as opened and
    /// its base name the path's file part, the strings' room a terminator past them; a count of
    /// one, no TLS index, empty hash links; a DLL's flags, its entry point never called.
    #[test]
    fn a_loaded_module_has_its_entry() {
        let module = Loaded {
            base: 0x1000_0000,
            entry_point: 0x1000_1234,
            size: 0x5000,
            time_date_stamp: 0x3A2B_1C0D,
            dll: true,
        };
        let path = wide("C:\\CORPUS\\Companion.DLL");
        let at = 0x0050_0000;
        let buffer = at + size_of::<Entry>() as u32;
        let entry = loaded_entry(at, &module, buffer, &path, 2 * 23 + 2);
        assert_eq!(entry.dll_base, 0x1000_0000);
        assert_eq!(entry.entry_point, 0x1000_1234);
        assert_eq!(entry.size_of_image, 0x5000);
        assert_eq!(entry.time_date_stamp, 0x3A2B_1C0D);
        assert_eq!(
            entry.full_dll_name,
            UnicodeString {
                length: 2 * 23,
                maximum_length: 2 * 23 + 2,
                buffer
            }
        );
        assert_eq!(
            entry.base_dll_name,
            UnicodeString {
                length: 2 * 13,
                maximum_length: 2 * 13 + 2,
                buffer: buffer + 2 * 10
            },
            "Companion.DLL"
        );
        assert_eq!(entry.flags, flags::IMAGE_DLL, "nothing processed yet");
        assert_eq!((entry.load_count, entry.tls_index), (1, 0));
        let hash = at + offset_of!(Entry, hash_links) as u32;
        assert_eq!(entry.hash_links, self_linked(hash));
        let initialization = at + Order::Initialization.links();
        assert_eq!(
            entry.in_initialization_order_links,
            self_linked(initialization),
            "in no initialization order yet"
        );
        let program = Loaded {
            dll: false,
            entry_point: 0,
            ..module
        };
        let entry = loaded_entry(at, &program, buffer, &wide("C:\\x.exe"), 2 * 8 + 2);
        assert_eq!(entry.flags, 0, "a program's image: no DLL flag");
        assert_eq!(entry.entry_point, 0);
        assert_eq!(
            (
                entry.base_dll_name.length,
                entry.base_dll_name.maximum_length
            ),
            (2 * 5, 2 * 8 + 2 - 2 * 3),
            "x.exe"
        );
    }

    /// A loaded module joins the load and memory orders after the last module as it is mapped, and
    /// the initialization order after kernel32 once its imports are snapped; found by its name and
    /// base; it leaves all three, the others' links mended. One that never joined the
    /// initialization order leaves the other two alone.
    #[test]
    fn a_loaded_module_joins_and_leaves_the_lists() {
        let mut space = process();
        const COMPANION: u32 = 0x1000_0000;
        let at = 0x0060_0000;
        let path = wide("C:\\CORPUS\\Companion.DLL");
        let module = Loaded {
            base: COMPANION,
            entry_point: 0,
            size: 0x1000,
            time_date_stamp: 0,
            dll: true,
        };
        let buffer = at + size_of::<Entry>() as u32;
        let mut bytes = loaded_entry(at, &module, buffer, &path, 2 * 23 + 2)
            .as_bytes()
            .to_vec();
        for unit in path.iter().chain([&0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        space.0.push((at, bytes.clone()));
        let companion = Module(at);
        insert(&mut space, LDR, companion);
        let orders = |space: &Space| Order::ALL.map(|order| linked(space, order));
        let mapped = [
            std::vec![IMAGE, NTDLL, KERNEL32, COMPANION],
            std::vec![IMAGE, NTDLL, KERNEL32, COMPANION],
            std::vec![NTDLL, KERNEL32],
        ];
        assert_eq!(orders(&space), mapped, "mapped: not initialized yet");
        insert_initialized(&mut space, LDR, companion);
        assert_eq!(
            orders(&space),
            [
                std::vec![IMAGE, NTDLL, KERNEL32, COMPANION],
                std::vec![IMAGE, NTDLL, KERNEL32, COMPANION],
                std::vec![NTDLL, KERNEL32, COMPANION]
            ]
        );
        assert_eq!(
            initialization_order(&space, LDR, true)
                .map(|module| module.base(&space))
                .collect::<std::vec::Vec<_>>(),
            [COMPANION, KERNEL32, NTDLL],
            "backward"
        );
        assert_eq!(found(&space, "companion"), Some(COMPANION));
        assert_eq!(found(&space, "C:\\CORPUS\\COMPANION.DLL"), Some(COMPANION));
        assert_eq!(by_base(&space, LDR, COMPANION), Some(companion));
        remove(&mut space, companion);
        assert_eq!(
            orders(&space),
            [
                std::vec![IMAGE, NTDLL, KERNEL32],
                std::vec![IMAGE, NTDLL, KERNEL32],
                std::vec![NTDLL, KERNEL32]
            ]
        );
        assert_eq!(found(&space, "companion"), None);
        // Mapped, then refused before its imports were snapped: out of the two orders it joined.
        let at = 0x0060_0000;
        space.0.retain(|(base, _)| *base != at);
        space.0.push((at, bytes));
        insert(&mut space, LDR, companion);
        remove(&mut space, companion);
        assert_eq!(
            orders(&space),
            [
                std::vec![IMAGE, NTDLL, KERNEL32],
                std::vec![IMAGE, NTDLL, KERNEL32],
                std::vec![NTDLL, KERNEL32]
            ]
        );
    }

    /// An empty PEB_LDR_DATA: its length, initialized, each list's head a ring of its own.
    #[test]
    fn the_lists_start_empty() {
        const AT: u32 = 0x0050_0000;
        let space = Space(std::vec![(AT, empty_lists(AT).as_bytes().to_vec())]);
        let data: LdrData = space.read(AT);
        assert_eq!((data.length, data.initialized), (0x24, 1));
        for order in Order::ALL {
            let head = AT + order.head();
            assert_eq!(space.read::<ListEntry<u32>>(head), self_linked(head));
        }
        assert_eq!(load_order(&space, AT).count(), 0);
        assert_eq!(initialization_order(&space, AT, false).count(), 0);
    }

    /// A loaded image's facts come from its headers: the entry point (none at RVA 0), the stamp,
    /// the DLL flag.
    #[test]
    fn a_loaded_image_is_read_from_its_headers() {
        let mut dll = image(&[]);
        dll[0x58 + 0x10..0x58 + 0x14].copy_from_slice(&0x1010u32.to_le_bytes());
        dll[0x48..0x4C].copy_from_slice(&0x3A2B_1C0Du32.to_le_bytes());
        dll[0x56..0x58].copy_from_slice(&0x2102u16.to_le_bytes());
        let space = Space(std::vec![(0x1000_0000, dll)]);
        assert_eq!(
            loaded(&space, 0x1000_0000, Some(0x4000)),
            Loaded {
                base: 0x1000_0000,
                entry_point: 0x1000_1010,
                size: 0x4000,
                time_date_stamp: 0x3A2B_1C0D,
                dll: true
            }
        );
        let space = Space(std::vec![(0x1000_0000, image(&[]))]);
        let facts = loaded(&space, 0x1000_0000, None);
        assert_eq!((facts.entry_point, facts.dll), (0, false));
        assert_eq!(
            facts.size,
            space.word(0x1000_0000 + 0x58 + 0x38),
            "the headers' SizeOfImage"
        );
    }

    /// The import walk: each descriptor's module (named as the lookups take it) and its imports, by
    /// name or by ordinal, to the zero thunk; each resolves through the lists as GetProcAddress
    /// does, forwarders followed; an image without imports has none.
    #[test]
    fn imports_walk_and_resolve_against_the_lists() {
        const COMPANION: u32 = 0x1000_0000;
        let tick = {
            let space = process();
            ordinal_of(&space, KERNEL32, "GetTickCount")
        };
        let companion = with_imports(
            image(&[("Answer", Ok(0x1100))]),
            &[
                (
                    "KERNEL32.dll",
                    &[Ok("ExitProcess"), Ok("RtlUnwind"), Err(tick)],
                ),
                ("ntdll", &[Ok("NtClose")]),
                ("KERNEL32.dll", &[Ok("NoSuchName"), Err(999)]),
            ],
        );
        let mut space = process();
        space.0.push((COMPANION, companion));
        let descriptors: std::vec::Vec<_> = import_descriptors(&space, COMPANION).collect();
        assert_eq!(descriptors.len(), 3);
        let mut name = [0u16; 32];
        let length = import_module_name(&space, descriptors[1].name, &mut name).unwrap();
        assert_eq!(
            &name[..length],
            &wide("ntdll.DLL")[..],
            "the extension supplied"
        );
        assert_eq!(descriptors[0].iat, COMPANION + 0xA00);
        let resolved = |descriptor: &Descriptor| -> std::vec::Vec<Result<u32, u32>> {
            let mut name = [0u16; 32];
            let length = import_module_name(&space, descriptor.name, &mut name).unwrap();
            let module = by_name(&space, LDR, &name[..length])
                .map(|module| module.base(&space))
                .unwrap();
            imports(&space, COMPANION, descriptor.lookup)
                .map(|import| import_address(&space, LDR, module, import))
                .collect()
        };
        assert_eq!(
            resolved(&descriptors[0]),
            [
                Ok(KERNEL32 + 0x2010),
                Ok(NTDLL + 0x1230),
                Ok(KERNEL32 + 0x2000)
            ]
        );
        assert_eq!(resolved(&descriptors[1]), [Ok(NTDLL + 0x1100)]);
        assert_eq!(
            resolved(&descriptors[2]),
            [
                Err(STATUS_ENTRYPOINT_NOT_FOUND),
                Err(STATUS_ORDINAL_NOT_FOUND)
            ]
        );
        assert_eq!(
            import_descriptors(&space, NTDLL).count(),
            0,
            "no import directory"
        );
        assert_eq!(
            import_descriptors(&space, IMAGE).count(),
            0,
            "no directories at all"
        );
    }
}
