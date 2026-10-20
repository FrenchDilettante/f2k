//! The loader's module lists and the export directories, as Windows 2000's ntdll keeps and reads
//! them.
//!
//! The PEB's Ldr (PEB_LDR_DATA) heads three lists of the process's modules (LDR_DATA_TABLE_ENTRY):
//! in load order (the image, ntdll, kernel32), in memory order (the same), and in initialization
//! order (ntdll, kernel32: the image is not initialized as a DLL is). Programs and packers walk the
//! lists themselves (to find kernel32's base), so the layout is the platform's, byte for byte. The
//! kernel builds them at the process's creation (`kernel/src/user/ldr.rs`): Windows 2000's
//! LdrpInitialize builds them in user mode, but F2K's loader of the program still runs in the
//! kernel. A DLL loaded after that (LdrLoadDll) joins them here ([`loaded_entry`], [`insert`]), its
//! imports walked and snapped against them ([`import_descriptors`], [`import_address`]), and leaves
//! them at its last unload ([`remove`]).
//!
//! What ntdll's loader exports do over them (LdrGetDllHandle, LdrGetProcedureAddress, LdrLoadDll,
//! LdrUnloadDll): find a module by its base, or by its name ([`by_name`]: without regard to case,
//! against its BaseDllName, or against its FullDllName for a name with a path, which the caller
//! has made absolute; a name without an extension is taken as `.DLL`); and find an export of a
//! module by its exact name or by its ordinal, through the module's export directory as mapped
//! ([`procedure_address`], [`procedure_by_ordinal`]), following forwarders (`NTDLL.RtlUnwind`,
//! split at the first dot; `NTDLL.#12` by ordinal) into the modules they name.
//!
//! The reads go through [`Memory`], by 32-bit user address: the process's own memory on the target,
//! a model in the tests.

use core::cmp::Ordering;

use crate::status::{
    STATUS_DLL_NOT_FOUND, STATUS_ENTRYPOINT_NOT_FOUND, STATUS_ORDINAL_NOT_FOUND, STATUS_PROCEDURE_NOT_FOUND,
};

/// The memory the lists and the images are read from, by user address.
pub trait Memory {
    /// The byte at `at`.
    fn byte(&self, at: u32) -> u8;

    /// The little-endian word at `at`.
    fn half(&self, at: u32) -> u16 {
        u16::from_le_bytes([self.byte(at), self.byte(at.wrapping_add(1))])
    }

    /// The little-endian dword at `at`.
    fn word(&self, at: u32) -> u32 {
        u32::from(self.half(at)) | u32::from(self.half(at.wrapping_add(2))) << 16
    }
}

/// The PEB's fields the loader keeps: Ldr (the PEB_LDR_DATA) and LoaderLock (the critical section
/// the loader holds while it reads or changes the lists).
pub mod peb {
    pub const LDR: u32 = 0x0C;
    pub const LOADER_LOCK: u32 = 0xA0;
}

/// PEB_LDR_DATA (NT 5.0, x86): its Length, Initialized, SsHandle, and the three lists' heads
/// (LIST_ENTRYs: Flink, Blink).
pub mod data {
    pub const LENGTH: u32 = 0x00;
    pub const INITIALIZED: u32 = 0x04;
    pub const SS_HANDLE: u32 = 0x08;
    pub const IN_LOAD_ORDER_MODULE_LIST: u32 = 0x0C;
    pub const IN_MEMORY_ORDER_MODULE_LIST: u32 = 0x14;
    pub const IN_INITIALIZATION_ORDER_MODULE_LIST: u32 = 0x1C;
    /// Its size, as its Length records it.
    pub const SIZE: u32 = 0x24;
}

/// LDR_DATA_TABLE_ENTRY (NT 5.0, x86): its links in the three lists, the image's base, entry point
/// and size, its full path and file name (UNICODE_STRINGs), the LDRP_* flags, the load count (a
/// word), the TLS index (a word), the hash links (LIST_ENTRY; SectionPointer and CheckSum share
/// them) and the image's TimeDateStamp.
pub mod entry {
    pub const IN_LOAD_ORDER_LINKS: u32 = 0x00;
    pub const IN_MEMORY_ORDER_LINKS: u32 = 0x08;
    pub const IN_INITIALIZATION_ORDER_LINKS: u32 = 0x10;
    pub const DLL_BASE: u32 = 0x18;
    pub const ENTRY_POINT: u32 = 0x1C;
    pub const SIZE_OF_IMAGE: u32 = 0x20;
    pub const FULL_DLL_NAME: u32 = 0x24;
    pub const BASE_DLL_NAME: u32 = 0x2C;
    pub const FLAGS: u32 = 0x34;
    pub const LOAD_COUNT: u32 = 0x38;
    pub const TLS_INDEX: u32 = 0x3A;
    pub const HASH_LINKS: u32 = 0x3C;
    pub const TIME_DATE_STAMP: u32 = 0x44;
    /// Its size.
    pub const SIZE: u32 = 0x48;
}

/// The LDRP_* flags of an entry: a DLL's image (LDRP_IMAGE_DLL), and an entry the process's
/// initialization has processed (LDRP_ENTRY_PROCESSED).
pub mod flags {
    pub const IMAGE_DLL: u32 = 0x0000_0004;
    pub const ENTRY_PROCESSED: u32 = 0x0000_4000;
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

/// The entries of the PEB_LDR_DATA at `ldr`, in load order (each entry's address).
pub fn load_order<M: Memory>(memory: &M, ldr: u32) -> impl Iterator<Item = u32> + '_ {
    let head = ldr.wrapping_add(data::IN_LOAD_ORDER_MODULE_LIST);
    let mut next = memory.word(head);
    let mut left = MAX_ENTRIES;
    core::iter::from_fn(move || {
        if next == head || next == 0 || left == 0 {
            return None;
        }
        left -= 1;
        let entry = next.wrapping_sub(entry::IN_LOAD_ORDER_LINKS);
        next = memory.word(next);
        Some(entry)
    })
}

/// The entry of the module whose base is `base` (its handle).
pub fn by_base<M: Memory>(memory: &M, ldr: u32, base: u32) -> Option<u32> {
    load_order(memory, ldr).find(|&entry| memory.word(entry + entry::DLL_BASE) == base)
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
    let file = &name[name.iter().rposition(|&unit| unit == BACKSLASH || unit == SLASH).map_or(0, |at| at + 1)..];
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

/// Whether the UNICODE_STRING at `at` holds `name`, without regard to case.
fn string_is<M: Memory>(memory: &M, at: u32, name: &[u16]) -> bool {
    let length = usize::from(memory.half(at)) / 2;
    let buffer = memory.word(at + 4);
    length == name.len()
        && name
            .iter()
            .enumerate()
            .all(|(index, &unit)| crate::path::upcase(memory.half(buffer + 2 * index as u32)) == crate::path::upcase(unit))
}

/// The entry of the module `name` names (as [`module_name`] forms it): its BaseDllName without
/// regard to case, or its FullDllName for a name with a path (the caller made it absolute).
pub fn by_name<M: Memory>(memory: &M, ldr: u32, name: &[u16]) -> Option<u32> {
    let field = if has_path(name) { entry::FULL_DLL_NAME } else { entry::BASE_DLL_NAME };
    load_order(memory, ldr).find(|&entry| string_is(memory, entry + field, name))
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
/// staying (F2K never unmaps a module: one the count releases stays where it is).
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

/// The export directory of the image mapped at `base` (its RVA and size); none for an image without
/// one.
fn export_directory<M: Memory>(memory: &M, base: u32) -> Option<(u32, u32)> {
    if memory.half(base) != 0x5A4D {
        return None; // "MZ"
    }
    let nt = base.wrapping_add(memory.word(base + 0x3C));
    if memory.word(nt) != 0x0000_4550 {
        return None; // "PE\0\0"
    }
    let optional = nt + 0x18;
    if memory.half(optional) != 0x010B || memory.word(optional + 0x5C) == 0 {
        return None; // not PE32, or no data directories
    }
    let (rva, size) = (memory.word(optional + 0x60), memory.word(optional + 0x64));
    (rva != 0).then_some((rva, size))
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

/// The export directory's fields a lookup reads, of the image mapped at `base`.
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
        let (rva, size) = export_directory(memory, base).ok_or(STATUS_PROCEDURE_NOT_FOUND)?;
        let at = base.wrapping_add(rva);
        Ok(Directory {
            rva,
            size,
            ordinal_base: memory.word(at + 0x10),
            functions: memory.word(at + 0x14),
            names: memory.word(at + 0x18),
            function_table: base.wrapping_add(memory.word(at + 0x1C)),
            name_table: base.wrapping_add(memory.word(at + 0x20)),
            ordinal_table: base.wrapping_add(memory.word(at + 0x24)),
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
        Ok(if forwarder { Export::Forwarder(address) } else { Export::Address(address) })
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
    let slot = ordinal.checked_sub(directory.ordinal_base).ok_or(STATUS_ORDINAL_NOT_FOUND)?;
    directory.slot(memory, base, slot).map_err(|_| STATUS_ORDINAL_NOT_FOUND)
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
    by_name(memory, ldr, &name[..length]).map(|entry| memory.word(entry + entry::DLL_BASE)).ok_or(STATUS_DLL_NOT_FOUND)
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
    let ordinal = digits.iter().fold(0u32, |value, &digit| 10 * value + u32::from(digit - b'0'));
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
        let (module, target) = split_forwarder(&text[..length]).ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
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
pub fn procedure_address<M: Memory>(memory: &M, ldr: u32, module: u32, name: &[u8]) -> Result<u32, u32> {
    by_base(memory, ldr, module).ok_or(STATUS_DLL_NOT_FOUND)?;
    followed(memory, ldr, export_by_name(memory, module, name)?)
}

/// LdrGetProcedureAddress's work for an ordinal: the address of the export with ordinal `ordinal`
/// of the module whose handle is `module`, its forwarders followed. STATUS_DLL_NOT_FOUND for a
/// handle naming no module of the lists; [`export_by_ordinal`]'s statuses for an ordinal the module
/// does not export.
pub fn procedure_by_ordinal<M: Memory>(memory: &M, ldr: u32, module: u32, ordinal: u32) -> Result<u32, u32> {
    by_base(memory, ldr, module).ok_or(STATUS_DLL_NOT_FOUND)?;
    followed(memory, ldr, export_by_ordinal(memory, module, ordinal)?)
}

// --- Loading a module: LdrLoadDll's and LdrUnloadDll's work over the lists ---------------------

/// The memory the lists are changed in, by user address.
pub trait MemoryMut: Memory {
    /// Write the little-endian dword at `at`.
    fn set_word(&mut self, at: u32, value: u32);
}

/// Where LdrLoadDll looks for a module the lists do not hold, `name` as [`module_name`] formed it:
/// the full DOS path of place `index` into `out` (terminated), its length; none past the last
/// place, or for a path that does not fit. A name with a path has one place, itself made absolute
/// against the current directory `current` (its DOS path, trailing separator included); a bare
/// name is looked for in the current directory, then in the root of its volume (once, when the
/// current directory is the root).
pub fn search_place(name: &[u16], current: &[u16], index: usize, out: &mut [u16]) -> Option<usize> {
    let mut first = [0u16; MAX_SEARCH_PATH + 1];
    let (first_length, _) = full_path_name(name, current, &mut first).ok()?;
    let place = match index {
        0 => &first[..first_length],
        1 if !has_path(name) => {
            let mut rooted = [0u16; MAX_SEARCH_PATH + 1];
            *rooted.first_mut()? = BACKSLASH;
            rooted.get_mut(1..name.len() + 1)?.copy_from_slice(name);
            let mut root = [0u16; MAX_SEARCH_PATH + 1];
            let (length, _) = full_path_name(&rooted[..name.len() + 1], current, &mut root).ok()?;
            if root[..length] == first[..first_length] {
                return None;
            }
            out.get_mut(..length + 1)?.copy_from_slice(&root[..length + 1]);
            return Some(length);
        }
        _ => return None,
    };
    out.get_mut(..place.len() + 1)?.copy_from_slice(&first[..place.len() + 1]);
    Some(place.len())
}

/// The longest full path a search builds, in units: MAX_PATH less its terminator.
pub const MAX_SEARCH_PATH: usize = crate::path::MAX_PATH - 1;

use crate::path::full_path_name;

/// A module LdrLoadDll mapped, as its entry records it: its base (its handle), its entry point
/// (zero for none), its size as mapped, its file header's TimeDateStamp, and whether it is a DLL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub base: u32,
    pub entry_point: u32,
    pub size: u32,
    pub time_date_stamp: u32,
    pub dll: bool,
}

/// The facts an entry records of the image mapped at `base`, read from its headers (its size is
/// the mapping's, `size`): see [`Loaded`].
pub fn loaded<M: Memory>(memory: &M, base: u32, size: u32) -> Loaded {
    let nt = base.wrapping_add(memory.word(base + 0x3C));
    let entry_rva = memory.word(nt + 0x18 + 0x10);
    Loaded {
        base,
        entry_point: if entry_rva == 0 { 0 } else { base.wrapping_add(entry_rva) },
        size,
        time_date_stamp: memory.word(nt + 8),
        dll: memory.half(nt + 22) & 0x2000 != 0,
    }
}

/// The LDR_DATA_TABLE_ENTRY's bytes of a module LdrLoadDll loaded: `module`, its FullDllName the
/// path it was opened by (`path`, in units, at `buffer`, its room the path and a terminator), its
/// BaseDllName the path's file part (the name as asked, its default extension supplied); a
/// LoadCount of 1, TlsIndex 0, the hash links empty (no hash table: the lookups walk the lists),
/// the list links left for [`insert`]. Its flags say a DLL's image (LDRP_IMAGE_DLL) and an entry
/// processed: no entry point is ever called (LDRP_PROCESS_ATTACH_CALLED stays clear, so a DllMain
/// that runs later can tell which entries it has not seen).
pub fn loaded_entry(at: u32, module: &Loaded, buffer: u32, path: &[u16]) -> [u8; entry::SIZE as usize] {
    let mut bytes = [0u8; entry::SIZE as usize];
    let mut put = |offset: u32, value: u32| bytes[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes());
    put(entry::DLL_BASE, module.base);
    put(entry::ENTRY_POINT, module.entry_point);
    put(entry::SIZE_OF_IMAGE, module.size);
    let length = 2 * path.len() as u32;
    put(entry::FULL_DLL_NAME, length | (length + 2) << 16);
    put(entry::FULL_DLL_NAME + 4, buffer);
    let file = 2 * path.iter().rposition(|&unit| unit == BACKSLASH).map_or(0, |at| at + 1) as u32;
    put(entry::BASE_DLL_NAME, (length - file) | (length + 2 - file) << 16);
    put(entry::BASE_DLL_NAME + 4, buffer + file);
    let kind = if module.dll { flags::IMAGE_DLL } else { 0 };
    put(entry::FLAGS, kind | flags::ENTRY_PROCESSED);
    put(entry::LOAD_COUNT, 1);
    put(entry::HASH_LINKS, at + entry::HASH_LINKS);
    put(entry::HASH_LINKS + 4, at + entry::HASH_LINKS);
    put(entry::TIME_DATE_STAMP, module.time_date_stamp);
    bytes
}

/// Link the LIST_ENTRY at `node` last in the list headed at `head`.
fn link_last<M: MemoryMut>(memory: &mut M, head: u32, node: u32) {
    let last = memory.word(head + 4);
    memory.set_word(node, head);
    memory.set_word(node + 4, last);
    memory.set_word(last, node);
    memory.set_word(head + 4, node);
}

/// Unlink the LIST_ENTRY at `node` from its list.
fn unlink<M: MemoryMut>(memory: &mut M, node: u32) {
    let (next, previous) = (memory.word(node), memory.word(node + 4));
    memory.set_word(previous, next);
    memory.set_word(next + 4, previous);
}

/// The three lists' heads and an entry's links in them: load, memory and initialization order.
const ORDERS: [(u32, u32); 3] = [
    (data::IN_LOAD_ORDER_MODULE_LIST, entry::IN_LOAD_ORDER_LINKS),
    (data::IN_MEMORY_ORDER_MODULE_LIST, entry::IN_MEMORY_ORDER_LINKS),
    (data::IN_INITIALIZATION_ORDER_MODULE_LIST, entry::IN_INITIALIZATION_ORDER_LINKS),
];

/// The entry at `entry` joins the lists of the PEB_LDR_DATA at `ldr`: after their last entries,
/// in each order (in the initialization order, after kernel32 and every module loaded before).
pub fn insert<M: MemoryMut>(memory: &mut M, ldr: u32, entry: u32) {
    for (head, links) in ORDERS {
        link_last(memory, ldr + head, entry + links);
    }
}

/// The entry at `entry` leaves the three lists.
pub fn remove<M: MemoryMut>(memory: &mut M, entry: u32) {
    for (_, links) in ORDERS {
        unlink(memory, entry + links);
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
pub fn import_descriptors<M: Memory>(memory: &M, base: u32) -> impl Iterator<Item = Descriptor> + '_ {
    let nt = base.wrapping_add(memory.word(base + 0x3C));
    let optional = nt + 0x18;
    let rva = if memory.word(optional + 0x5C) > 1 { memory.word(optional + 0x68) } else { 0 };
    let mut at = base.wrapping_add(rva);
    let mut left = if rva == 0 { 0 } else { MAX_DESCRIPTORS };
    core::iter::from_fn(move || {
        if left == 0 {
            return None;
        }
        left -= 1;
        let (original, name, first) = (memory.word(at), memory.word(at + 12), memory.word(at + 16));
        if name == 0 || first == 0 {
            left = 0;
            return None;
        }
        at += 20;
        let lookup = if original == 0 { first } else { original };
        Some(Descriptor { name: base.wrapping_add(name), lookup: base.wrapping_add(lookup), iat: base.wrapping_add(first) })
    })
}

/// One import, as a thunk names it: by its hint/name entry's address, or by ordinal (the thunk's
/// high bit set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Import {
    Name(u32),
    Ordinal(u32),
}

/// The imports of the lookup table at `lookup` of the image at `base`, to its zero thunk.
pub fn imports<M: Memory>(memory: &M, base: u32, lookup: u32) -> impl Iterator<Item = Import> + '_ {
    (0..MAX_THUNKS as u32).map(move |index| memory.word(lookup + 4 * index)).take_while(|&thunk| thunk != 0).map(move |thunk| {
        if thunk & 0x8000_0000 != 0 {
            Import::Ordinal(thunk & 0xFFFF)
        } else {
            Import::Name(base.wrapping_add(thunk) + 2)
        }
    })
}

/// The longest import name a snap reads.
const MAX_IMPORT_NAME: usize = 256;

/// The address an IAT slot receives for `import` of the module whose handle is `module`: its
/// export by name or by ordinal, forwarders followed ([`procedure_address`],
/// [`procedure_by_ordinal`]).
pub fn import_address<M: Memory>(memory: &M, ldr: u32, module: u32, import: Import) -> Result<u32, u32> {
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
        fn set_word(&mut self, at: u32, value: u32) {
            for (base, bytes) in &mut self.0 {
                if at >= *base && ((at - *base) as usize) + 4 <= bytes.len() {
                    let offset = (at - *base) as usize;
                    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                    return;
                }
            }
            panic!("{at:#010x} is not mapped");
        }
    }

    /// `image` (one [`image`] builds) importing `imports` (module, then each import: a name, or an
    /// ordinal), its descriptors at RVA 0x800, the lookup tables at 0x900, the IATs at 0xA00 and
    /// the names from 0xB00.
    pub fn with_imports(mut image: std::vec::Vec<u8>, imports: &[(&str, &[Result<&str, u32>])]) -> std::vec::Vec<u8> {
        let put = |image: &mut std::vec::Vec<u8>, at: usize, value: u32| image[at..at + 4].copy_from_slice(&value.to_le_bytes());
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
                        image[strings + 2..strings + 2 + name.len()].copy_from_slice(name.as_bytes());
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
        let put = |image: &mut std::vec::Vec<u8>, at: usize, value: u32| image[at..at + 4].copy_from_slice(&value.to_le_bytes());
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
            image[ordinals + 2 * index..ordinals + 2 * index + 2].copy_from_slice(&(ordinal as u16).to_le_bytes());
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
    pub struct Module<'a> {
        pub base: u32,
        pub path: &'a str,
        pub load_count: u16,
    }

    /// A PEB_LDR_DATA at `at` listing `modules` in load and memory order (the first is the image,
    /// left out of the initialization order), each entry's names on the same region.
    pub fn lists(at: u32, modules: &[Module]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0u8; 0x1000];
        let put = |bytes: &mut std::vec::Vec<u8>, offset: u32, value: u32| {
            bytes[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes())
        };
        let entry_at = |index: usize| 0x40 + index as u32 * entry::SIZE;
        put(&mut bytes, data::LENGTH, data::SIZE);
        put(&mut bytes, data::INITIALIZED, 1);
        let mut strings = entry_at(modules.len());
        for (index, module) in modules.iter().enumerate() {
            let entry = entry_at(index);
            put(&mut bytes, entry + entry::DLL_BASE, module.base);
            bytes[(entry + entry::LOAD_COUNT) as usize..(entry + entry::LOAD_COUNT) as usize + 2]
                .copy_from_slice(&module.load_count.to_le_bytes());
            let units: std::vec::Vec<u16> = module.path.encode_utf16().collect();
            for (offset, unit) in units.iter().enumerate() {
                let place = (strings + 2 * offset as u32) as usize;
                bytes[place..place + 2].copy_from_slice(&unit.to_le_bytes());
            }
            let file = units.iter().rposition(|&unit| unit == u16::from(b'\\')).map_or(0, |at| at + 1);
            let length = 2 * units.len() as u32;
            put(&mut bytes, entry + entry::FULL_DLL_NAME, length | (length + 2) << 16);
            put(&mut bytes, entry + entry::FULL_DLL_NAME + 4, at + strings);
            let base_length = length - 2 * file as u32;
            put(&mut bytes, entry + entry::BASE_DLL_NAME, base_length | (base_length + 2) << 16);
            put(&mut bytes, entry + entry::BASE_DLL_NAME + 4, at + strings + 2 * file as u32);
            strings += length + 2;
        }
        // Each order's links: the load and memory orders every module, the initialization order all
        // but the image.
        for (head, links) in ORDERS {
            let first = if head == data::IN_INITIALIZATION_ORDER_MODULE_LIST { 1 } else { 0 };
            let nodes: std::vec::Vec<u32> =
                core::iter::once(head).chain((first..modules.len()).map(|index| entry_at(index) + links)).collect();
            for (index, &node) in nodes.iter().enumerate() {
                put(&mut bytes, node, at + nodes[(index + 1) % nodes.len()]);
                put(&mut bytes, node + 4, at + nodes[(index + nodes.len() - 1) % nodes.len()]);
            }
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::model::{image, lists, with_imports, Module, Space};
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
        let ntdll = image(&[("RtlUnwind", Ok(0x1230)), ("NtClose", Ok(0x1100)), ("Odd.Name", Ok(0x1300))]);
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
            Module { base: IMAGE, path: "C:\\RUNTIME.EXE", load_count: STATIC_LOAD_COUNT },
            Module { base: NTDLL, path: "C:\\WINNT\\system32\\ntdll.dll", load_count: STATIC_LOAD_COUNT },
            Module { base: KERNEL32, path: "C:\\WINNT\\system32\\KERNEL32.DLL", load_count: STATIC_LOAD_COUNT },
        ];
        Space(std::vec![(LDR, lists(LDR, &modules)), (IMAGE, executable), (NTDLL, ntdll), (KERNEL32, kernel32)])
    }

    fn found(space: &Space, name: &str) -> Option<u32> {
        let mut formed = [0u16; 300];
        let length = module_name(&wide(name), &mut formed)?;
        by_name(space, LDR, &formed[..length]).map(|entry| space.word(entry + entry::DLL_BASE))
    }

    /// The load order is the image's, ntdll's, kernel32's; a module is found by its base.
    #[test]
    fn the_lists_walk_in_load_order() {
        let space = process();
        let bases: std::vec::Vec<u32> = load_order(&space, LDR).map(|entry| space.word(entry + entry::DLL_BASE)).collect();
        assert_eq!(bases, [IMAGE, NTDLL, KERNEL32]);
        assert!(by_base(&space, LDR, KERNEL32).is_some());
        assert_eq!(by_base(&space, LDR, 0x1234_0000), None);
        assert_eq!(by_base(&space, LDR, 0), None);
    }

    /// Module names: any case, with or without the `.dll` the lookups add, a trailing dot meaning no
    /// extension; a path is matched against the full path, as Windows 2000 matches it (the caller
    /// makes it absolute, its separators backslashes).
    #[test]
    fn modules_answer_to_their_names() {
        let space = process();
        for name in ["kernel32.dll", "KERNEL32", "Kernel32.Dll", "C:\\WINNT\\SYSTEM32\\kernel32.dll", "c:\\winnt\\system32\\KERNEL32"] {
            assert_eq!(found(&space, name), Some(KERNEL32), "{name}");
        }
        for name in ["ntdll.dll", "NTDLL", "C:\\WINNT\\system32\\NTDLL.DLL"] {
            assert_eq!(found(&space, name), Some(NTDLL), "{name}");
        }
        assert_eq!(found(&space, "runtime.exe"), Some(IMAGE));
        assert_eq!(found(&space, "C:\\runtime.exe"), Some(IMAGE));
        for name in ["nosuch.dll", "kernel32.exe", "runtime", "kernel32.", "D:\\kernel32.dll", "C:\\kernel32.dll", ""] {
            assert_eq!(found(&space, name), None, "{name}");
        }
        let mut out = [0u16; 16];
        assert_eq!(module_name(&wide("a."), &mut out), Some(1), "the trailing dot goes");
        let length = module_name(&wide("dir.x\\a"), &mut out).unwrap();
        assert_eq!(&out[..length], &wide("dir.x\\a.DLL")[..], "the file part's extension counts");
        assert_eq!(module_name(&wide("abcdef"), &mut [0u16; 8]), None, "no room for the extension");
    }

    /// Exports: by exact name, through the sorted name table; forwarders followed into the module
    /// they name; the statuses of what is not there.
    #[test]
    fn exports_resolve_by_exact_name() {
        let space = process();
        let address = |module, name: &str| procedure_address(&space, LDR, module, name.as_bytes());
        assert_eq!(address(KERNEL32, "GetTickCount"), Ok(KERNEL32 + 0x2000));
        assert_eq!(address(KERNEL32, "ExitProcess"), Ok(KERNEL32 + 0x2010));
        assert_eq!(address(KERNEL32, "RtlUnwind"), Ok(NTDLL + 0x1230), "the forwarder lands in ntdll");
        assert_eq!(address(NTDLL, "RtlUnwind"), Ok(NTDLL + 0x1230));
        assert_eq!(address(KERNEL32, "gettickcount"), Err(STATUS_ENTRYPOINT_NOT_FOUND), "case counts");
        assert_eq!(address(KERNEL32, "GetTickCountx"), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(address(KERNEL32, "GetTick"), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(address(KERNEL32, ""), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(address(KERNEL32, "Hole"), Err(STATUS_ENTRYPOINT_NOT_FOUND), "an empty slot");
        assert_eq!(address(KERNEL32, "Missing"), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(address(KERNEL32, "ByOrdinal"), Ok(NTDLL + 0x1230), "a forwarder to an ordinal");
        assert_eq!(address(KERNEL32, "PastTheTable"), Err(STATUS_ORDINAL_NOT_FOUND), "an ordinal ntdll lacks");
        assert_eq!(address(KERNEL32, "NotAnOrdinal"), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(address(KERNEL32, "Dotted"), Ok(NTDLL + 0x1300), "the first dot splits");
        assert_eq!(address(KERNEL32, "Elsewhere"), Err(STATUS_DLL_NOT_FOUND));
        assert_eq!(address(IMAGE, "main"), Err(STATUS_PROCEDURE_NOT_FOUND), "the image exports nothing");
        assert_eq!(address(0x1234_0000, "GetTickCount"), Err(STATUS_DLL_NOT_FOUND), "no such module");
        let mut long = std::vec![b'x'; 300];
        long[..12].copy_from_slice(b"GetTickCount");
        assert_eq!(procedure_address(&space, LDR, KERNEL32, &long), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(procedure_by_ordinal(&space, LDR, 0x1234_0000, 1), Err(STATUS_DLL_NOT_FOUND));
    }

    /// The ordinal `name` exports under in the image at `base` (the model numbers its slots apart
    /// from its name order).
    fn ordinal_of(space: &Space, base: u32, name: &str) -> u32 {
        let wanted = export_by_name(space, base, name.as_bytes()).unwrap();
        (1..64).find(|&ordinal| export_by_ordinal(space, base, ordinal) == Ok(wanted)).unwrap()
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
        assert_eq!(by_ordinal(KERNEL32, ordinal_of(&space, KERNEL32, "RtlUnwind")), Ok(NTDLL + 0x1230));
        assert_eq!(by_ordinal(KERNEL32, ordinal_of(&space, KERNEL32, "ByOrdinal")), Ok(NTDLL + 0x1230));
        assert_eq!(by_ordinal(NTDLL, 1), Ok(NTDLL + 0x1230), "the model's last name takes the first slot");
        assert_eq!(by_ordinal(NTDLL, 0), Err(STATUS_ORDINAL_NOT_FOUND), "below the base");
        assert_eq!(by_ordinal(NTDLL, 4), Err(STATUS_ORDINAL_NOT_FOUND), "past the table");
        assert_eq!(by_ordinal(NTDLL, 0xFFFF), Err(STATUS_ORDINAL_NOT_FOUND));
        // A two-slot image: "A" in slot 1 (ordinal 2), the empty slot 0 (ordinal 1).
        let holed = Space(std::vec![(0x1000_0000, image(&[("A", Ok(0x10)), ("Hole", Ok(0))]))]);
        assert_eq!(export_by_ordinal(&holed, 0x1000_0000, 2), Ok(Export::Address(0x1000_0010)));
        assert_eq!(export_by_ordinal(&holed, 0x1000_0000, 1), Err(STATUS_ORDINAL_NOT_FOUND), "an empty slot");
        assert_eq!(by_ordinal(IMAGE, 1), Err(STATUS_PROCEDURE_NOT_FOUND), "the image exports nothing");
    }

    /// Forwarder strings split at their first dot: the module part before it, the entry (dots and
    /// all) after; `#` and digits an ordinal.
    #[test]
    fn forwarders_split_at_the_first_dot() {
        assert_eq!(split_forwarder(b"NTDLL.RtlUnwind"), Some((&b"NTDLL"[..], Target::Name(b"RtlUnwind"))));
        assert_eq!(split_forwarder(b"API.MS.Entry"), Some((&b"API"[..], Target::Name(b"MS.Entry"))));
        assert_eq!(split_forwarder(b"NTDLL.#12"), Some((&b"NTDLL"[..], Target::Ordinal(12))));
        for bad in [&b"NTDLL"[..], b".Entry", b"NTDLL.", b"NTDLL.#", b"NTDLL.#1x", b"NTDLL.#1234567890"] {
            assert_eq!(split_forwarder(bad), None, "{:?}", core::str::from_utf8(bad));
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
        let first = space.word(LDR + data::IN_LOAD_ORDER_MODULE_LIST);
        let last = space.word(LDR + data::IN_LOAD_ORDER_MODULE_LIST + 4);
        let offset = (last - LDR) as usize;
        space.0[0].1[offset..offset + 4].copy_from_slice(&first.to_le_bytes());
        assert_eq!(load_order(&space, LDR).count(), MAX_ENTRIES);
        assert_eq!(by_base(&space, LDR, 0x1234_0000), None);
    }

    /// The modules a list holds, in the order `head` links them (each node back to its entry by
    /// `links`).
    fn order(space: &Space, head: u32, links: u32) -> std::vec::Vec<u32> {
        let mut bases = std::vec::Vec::new();
        let mut node = space.word(head);
        while node != head {
            bases.push(space.word(node - links + entry::DLL_BASE));
            assert_eq!(space.word(space.word(node + 4)), node, "the Blinks agree");
            node = space.word(node);
        }
        bases
    }

    /// Where a name is looked for: a bare name in the current directory, then in the volume's root
    /// (once when the two are one); a name with a path made absolute against the current directory,
    /// one place; the case as asked, the default extension as `module_name` supplied it.
    #[test]
    fn modules_are_searched_for_in_the_current_directory_then_the_root() {
        let places = |name: &str, current: &str| -> std::vec::Vec<std::string::String> {
            let mut formed = [0u16; 300];
            let length = module_name(&wide(name), &mut formed).unwrap();
            (0..4)
                .map_while(|index| {
                    let mut out = [0u16; MAX_SEARCH_PATH + 1];
                    let length = search_place(&formed[..length], &wide(current), index, &mut out)?;
                    assert_eq!(out[length], 0, "terminated");
                    Some(std::string::String::from_utf16(&out[..length]).unwrap())
                })
                .collect()
        };
        assert_eq!(places("Companion", "C:\\CORPUS\\"), ["C:\\CORPUS\\Companion.DLL", "C:\\Companion.DLL"]);
        assert_eq!(places("comp.dll", "C:\\CORPUS\\"), ["C:\\CORPUS\\comp.dll", "C:\\comp.dll"]);
        assert_eq!(places("comp.", "C:\\CORPUS\\"), ["C:\\CORPUS\\comp", "C:\\comp"], "a trailing dot: no extension");
        assert_eq!(places("comp", "C:\\"), ["C:\\comp.DLL"], "the root once");
        assert_eq!(places("sub\\comp", "C:\\CORPUS\\"), ["C:\\CORPUS\\sub\\comp.DLL"], "a relative path: one place");
        assert_eq!(places("..\\comp.dll", "C:\\CORPUS\\"), ["C:\\comp.dll"]);
        assert_eq!(places("C:\\elsewhere\\COMP.DLL", "C:\\CORPUS\\"), ["C:\\elsewhere\\COMP.DLL"]);
        assert_eq!(places("/elsewhere/comp", "C:\\CORPUS\\"), ["C:\\elsewhere\\comp.DLL"]);
        let long = "x".repeat(300);
        assert_eq!(search_place(&wide(&long), &wide("C:\\"), 0, &mut [0u16; MAX_SEARCH_PATH + 1]), None, "past MAX_PATH");
    }

    /// A loaded module's entry: its base, entry point, size and stamp; its full path as opened and
    /// its base name the path's file part, the strings' room a terminator past them; a count of
    /// one, no TLS index, empty hash links; a DLL's flags, its entry point never called.
    #[test]
    fn a_loaded_module_has_its_entry() {
        let module = Loaded { base: 0x1000_0000, entry_point: 0x1000_1234, size: 0x5000, time_date_stamp: 0x3A2B_1C0D, dll: true };
        let path = wide("C:\\CORPUS\\Companion.DLL");
        let at = 0x0050_0000;
        let bytes = loaded_entry(at, &module, at + entry::SIZE, &path);
        let mut space = Space(std::vec![(at, bytes.to_vec())]);
        let word = |offset: u32| space.word(at + offset);
        assert_eq!(word(entry::DLL_BASE), 0x1000_0000);
        assert_eq!(word(entry::ENTRY_POINT), 0x1000_1234);
        assert_eq!(word(entry::SIZE_OF_IMAGE), 0x5000);
        assert_eq!(word(entry::TIME_DATE_STAMP), 0x3A2B_1C0D);
        assert_eq!(word(entry::FULL_DLL_NAME), 2 * 23 | (2 * 23 + 2) << 16);
        assert_eq!(word(entry::FULL_DLL_NAME + 4), at + entry::SIZE);
        assert_eq!(word(entry::BASE_DLL_NAME), 2 * 13 | (2 * 13 + 2) << 16, "Companion.DLL");
        assert_eq!(word(entry::BASE_DLL_NAME + 4), at + entry::SIZE + 2 * 10);
        assert_eq!(word(entry::FLAGS), flags::IMAGE_DLL | flags::ENTRY_PROCESSED);
        assert_eq!(space.half(at + entry::LOAD_COUNT), 1);
        assert_eq!(space.half(at + entry::TLS_INDEX), 0);
        assert_eq!((word(entry::HASH_LINKS), word(entry::HASH_LINKS + 4)), (at + entry::HASH_LINKS, at + entry::HASH_LINKS));
        let program = Loaded { dll: false, entry_point: 0, ..module };
        let bytes = loaded_entry(at, &program, at + entry::SIZE, &wide("C:\\x.exe"));
        space.0[0].1 = bytes.to_vec();
        assert_eq!(space.word(at + entry::FLAGS), flags::ENTRY_PROCESSED, "a program's image: no DLL flag");
        assert_eq!(space.word(at + entry::ENTRY_POINT), 0);
        assert_eq!(space.word(at + entry::BASE_DLL_NAME), 2 * 5 | (2 * 8 + 2 - 2 * 3) << 16, "x.exe");
    }

    /// A loaded module joins every order after the last module, the initialization order's after
    /// kernel32; found by its name and base; it leaves all three, the others' links mended.
    #[test]
    fn a_loaded_module_joins_and_leaves_the_lists() {
        let mut space = process();
        const COMPANION: u32 = 0x1000_0000;
        let at = 0x0060_0000;
        let path = wide("C:\\CORPUS\\Companion.DLL");
        let module = Loaded { base: COMPANION, entry_point: 0, size: 0x1000, time_date_stamp: 0, dll: true };
        let mut bytes = loaded_entry(at, &module, at + entry::SIZE, &path).to_vec();
        for unit in path.iter().chain([&0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        space.0.push((at, bytes));
        insert(&mut space, LDR, at);
        let orders = |space: &Space| ORDERS.map(|(head, links)| order(space, LDR + head, links));
        assert_eq!(
            orders(&space),
            [std::vec![IMAGE, NTDLL, KERNEL32, COMPANION], std::vec![IMAGE, NTDLL, KERNEL32, COMPANION], std::vec![NTDLL, KERNEL32, COMPANION]]
        );
        assert_eq!(found(&space, "companion"), Some(COMPANION));
        assert_eq!(found(&space, "C:\\CORPUS\\COMPANION.DLL"), Some(COMPANION));
        assert_eq!(by_base(&space, LDR, COMPANION), Some(at));
        remove(&mut space, at);
        assert_eq!(orders(&space), [std::vec![IMAGE, NTDLL, KERNEL32], std::vec![IMAGE, NTDLL, KERNEL32], std::vec![NTDLL, KERNEL32]]);
        assert_eq!(found(&space, "companion"), None);
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
            loaded(&space, 0x1000_0000, 0x4000),
            Loaded { base: 0x1000_0000, entry_point: 0x1000_1010, size: 0x4000, time_date_stamp: 0x3A2B_1C0D, dll: true }
        );
        let space = Space(std::vec![(0x1000_0000, image(&[]))]);
        let facts = loaded(&space, 0x1000_0000, 0x1000);
        assert_eq!((facts.entry_point, facts.dll), (0, false));
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
            &[("KERNEL32.dll", &[Ok("ExitProcess"), Ok("RtlUnwind"), Err(tick)]), ("ntdll", &[Ok("NtClose")]), ("KERNEL32.dll", &[Ok("NoSuchName"), Err(999)])],
        );
        let mut space = process();
        space.0.push((COMPANION, companion));
        let descriptors: std::vec::Vec<_> = import_descriptors(&space, COMPANION).collect();
        assert_eq!(descriptors.len(), 3);
        let mut name = [0u16; 32];
        let length = import_module_name(&space, descriptors[1].name, &mut name).unwrap();
        assert_eq!(&name[..length], &wide("ntdll.DLL")[..], "the extension supplied");
        assert_eq!(descriptors[0].iat, COMPANION + 0xA00);
        let resolved = |descriptor: &Descriptor| -> std::vec::Vec<Result<u32, u32>> {
            let mut name = [0u16; 32];
            let length = import_module_name(&space, descriptor.name, &mut name).unwrap();
            let module = by_name(&space, LDR, &name[..length]).map(|entry| space.word(entry + entry::DLL_BASE)).unwrap();
            imports(&space, COMPANION, descriptor.lookup).map(|import| import_address(&space, LDR, module, import)).collect()
        };
        assert_eq!(resolved(&descriptors[0]), [Ok(KERNEL32 + 0x2010), Ok(NTDLL + 0x1230), Ok(KERNEL32 + 0x2000)]);
        assert_eq!(resolved(&descriptors[1]), [Ok(NTDLL + 0x1100)]);
        assert_eq!(resolved(&descriptors[2]), [Err(STATUS_ENTRYPOINT_NOT_FOUND), Err(STATUS_ORDINAL_NOT_FOUND)]);
        assert_eq!(import_descriptors(&space, NTDLL).count(), 0, "no import directory");
        assert_eq!(import_descriptors(&space, IMAGE).count(), 0, "no directories at all");
    }
}
