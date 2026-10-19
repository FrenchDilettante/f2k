//! The loader's module lists and the export directories, as Windows 2000's ntdll keeps and reads
//! them.
//!
//! The PEB's Ldr (PEB_LDR_DATA) heads three lists of the process's modules (LDR_DATA_TABLE_ENTRY):
//! in load order (the image, ntdll, kernel32), in memory order (the same), and in initialization
//! order (ntdll, kernel32: the image is not initialized as a DLL is). Programs and packers walk the
//! lists themselves (to find kernel32's base), so the layout is the platform's, byte for byte. The
//! kernel builds them at the process's creation (`kernel/src/user/ldr.rs`): Windows 2000's
//! LdrpInitialize builds them in user mode, but F2K's loader still runs in the kernel. Nothing
//! loads or unloads after that, so a module's LoadCount only counts.
//!
//! What ntdll's loader exports do over them (LdrGetDllHandle, LdrGetProcedureAddress, LdrLoadDll,
//! LdrUnloadDll): find a module by its base, or by its name ([`by_name`]: without regard to case,
//! against its BaseDllName, or against its FullDllName for a name with a path, which the caller
//! has made absolute; a name without an extension is taken as `.DLL`); and find an export of a
//! module by its exact name, through the module's export directory as mapped ([`procedure_address`]),
//! following forwarders (`NTDLL.RtlUnwind`) into the modules they name.
//!
//! The reads go through [`Memory`], by 32-bit user address: the process's own memory on the target,
//! a model in the tests.

use core::cmp::Ordering;

use crate::status::{STATUS_DLL_NOT_FOUND, STATUS_ENTRYPOINT_NOT_FOUND, STATUS_ORDINAL_NOT_FOUND, STATUS_PROCEDURE_NOT_FOUND};

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

/// The export named `name` (exactly: case counts) of the image mapped at `base`, by a binary search
/// of its sorted name table (Windows 2000's LdrpNameToOrdinal). STATUS_PROCEDURE_NOT_FOUND for an
/// image without exports, STATUS_ENTRYPOINT_NOT_FOUND for a name it does not export.
pub fn export_by_name<M: Memory>(memory: &M, base: u32, name: &[u8]) -> Result<Export, u32> {
    let (rva, size) = export_directory(memory, base).ok_or(STATUS_PROCEDURE_NOT_FOUND)?;
    let directory = base.wrapping_add(rva);
    let functions = memory.word(directory + 0x14);
    let names = memory.word(directory + 0x18);
    let function_table = base.wrapping_add(memory.word(directory + 0x1C));
    let name_table = base.wrapping_add(memory.word(directory + 0x20));
    let ordinal_table = base.wrapping_add(memory.word(directory + 0x24));
    let (mut low, mut high) = (0u32, names);
    while low < high {
        let middle = low + (high - low) / 2;
        let candidate = base.wrapping_add(memory.word(name_table + 4 * middle));
        match compare(memory, candidate, name) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => {
                let ordinal = u32::from(memory.half(ordinal_table + 2 * middle));
                if ordinal >= functions {
                    return Err(STATUS_ENTRYPOINT_NOT_FOUND);
                }
                let function = memory.word(function_table + 4 * ordinal);
                if function == 0 {
                    return Err(STATUS_ENTRYPOINT_NOT_FOUND);
                }
                let forwarder = function >= rva && function - rva < size;
                let address = base.wrapping_add(function);
                return Ok(if forwarder { Export::Forwarder(address) } else { Export::Address(address) });
            }
        }
    }
    Err(STATUS_ENTRYPOINT_NOT_FOUND)
}

/// The base of the module a forwarder's module part names (`NTDLL`: a name without an extension, so
/// `NTDLL.DLL`); STATUS_DLL_NOT_FOUND for one the process has not loaded (F2K loads nothing more).
fn forwarded_module<M: Memory>(memory: &M, ldr: u32, module: &[u8]) -> Result<u32, u32> {
    let mut wide = [0u16; FORWARDER_ROOM];
    for (unit, &byte) in wide.iter_mut().zip(module) {
        *unit = u16::from(byte);
    }
    let mut name = [0u16; FORWARDER_ROOM + DEFAULT_EXTENSION.len()];
    let length = module_name(&wide[..module.len()], &mut name).ok_or(STATUS_DLL_NOT_FOUND)?;
    by_name(memory, ldr, &name[..length]).map(|entry| memory.word(entry + entry::DLL_BASE)).ok_or(STATUS_DLL_NOT_FOUND)
}

/// LdrGetProcedureAddress's work: the address of the export `name` of the module whose handle is
/// `module`, its forwarders followed. STATUS_DLL_NOT_FOUND for a handle naming no module of the
/// lists; [`export_by_name`]'s statuses for a name the module does not export; a forwarder naming
/// an ordinal finds nothing (STATUS_ORDINAL_NOT_FOUND: F2K's DLLs' ordinals are not Windows 2000's
/// yet).
pub fn procedure_address<M: Memory>(memory: &M, ldr: u32, module: u32, name: &[u8]) -> Result<u32, u32> {
    by_base(memory, ldr, module).ok_or(STATUS_DLL_NOT_FOUND)?;
    let mut export = export_by_name(memory, module, name)?;
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
        let dot = text[..length].iter().position(|&byte| byte == b'.').ok_or(STATUS_ENTRYPOINT_NOT_FOUND)?;
        let target = forwarded_module(memory, ldr, &text[..dot])?;
        let forwarded = &text[dot + 1..length];
        if forwarded.first() == Some(&b'#') {
            return Err(STATUS_ORDINAL_NOT_FOUND);
        }
        export = export_by_name(memory, target, forwarded)?;
    }
    match export {
        Export::Address(address) => Ok(address),
        Export::Forwarder(_) => Err(STATUS_ENTRYPOINT_NOT_FOUND),
    }
}

/// LdrGetProcedureAddress's work for an ordinal: STATUS_DLL_NOT_FOUND for a handle naming no module
/// of the lists, and otherwise nothing found (STATUS_ORDINAL_NOT_FOUND): F2K's DLLs' ordinals are
/// not Windows 2000's yet, so none is looked up.
pub fn procedure_by_ordinal<M: Memory>(memory: &M, ldr: u32, module: u32, _ordinal: u32) -> Result<u32, u32> {
    by_base(memory, ldr, module).ok_or(STATUS_DLL_NOT_FOUND)?;
    Err(STATUS_ORDINAL_NOT_FOUND)
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
        // The load order's links (the memory order's would match; the walks read the first list).
        let head = data::IN_LOAD_ORDER_MODULE_LIST;
        let links: std::vec::Vec<u32> =
            core::iter::once(head).chain((0..modules.len()).map(|index| entry_at(index) + entry::IN_LOAD_ORDER_LINKS)).collect();
        for (index, &link) in links.iter().enumerate() {
            put(&mut bytes, link, at + links[(index + 1) % links.len()]);
            put(&mut bytes, link + 4, at + links[(index + links.len() - 1) % links.len()]);
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::model::{image, lists, Module, Space};
    use super::*;

    const LDR: u32 = 0x0032_0800;
    const IMAGE: u32 = 0x0040_0000;
    const NTDLL: u32 = 0x77F8_0000;
    const KERNEL32: u32 = 0x7C4E_0000;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A process: its image (no exports), ntdll (RtlUnwind at 0x1230) and kernel32 (its own exports,
    /// and forwarders into ntdll, one to a name ntdll lacks, one to an ordinal, one to a module
    /// not loaded).
    fn process() -> Space {
        let mut executable = image(&[]);
        executable[0x58 + 0x5C..0x58 + 0x60].copy_from_slice(&0u32.to_le_bytes()); // no directories
        let ntdll = image(&[("RtlUnwind", Ok(0x1230)), ("NtClose", Ok(0x1100))]);
        let kernel32 = image(&[
            ("GetTickCount", Ok(0x2000)),
            ("ExitProcess", Ok(0x2010)),
            ("RtlUnwind", Err("NTDLL.RtlUnwind")),
            ("Missing", Err("NTDLL.NoSuchName")),
            ("ByOrdinal", Err("NTDLL.#12")),
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
        assert_eq!(address(KERNEL32, "ByOrdinal"), Err(STATUS_ORDINAL_NOT_FOUND));
        assert_eq!(address(KERNEL32, "Elsewhere"), Err(STATUS_DLL_NOT_FOUND));
        assert_eq!(address(IMAGE, "main"), Err(STATUS_PROCEDURE_NOT_FOUND), "the image exports nothing");
        assert_eq!(address(0x1234_0000, "GetTickCount"), Err(STATUS_DLL_NOT_FOUND), "no such module");
        let mut long = std::vec![b'x'; 300];
        long[..12].copy_from_slice(b"GetTickCount");
        assert_eq!(procedure_address(&space, LDR, KERNEL32, &long), Err(STATUS_ENTRYPOINT_NOT_FOUND));
        assert_eq!(procedure_by_ordinal(&space, LDR, KERNEL32, 1), Err(STATUS_ORDINAL_NOT_FOUND), "ordinals find nothing yet");
        assert_eq!(procedure_by_ordinal(&space, LDR, 0x1234_0000, 1), Err(STATUS_DLL_NOT_FOUND));
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
}
