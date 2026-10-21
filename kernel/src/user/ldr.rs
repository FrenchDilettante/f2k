//! The loader's module lists, as the kernel builds them at a process's creation: the PEB's Ldr (a
//! PEB_LDR_DATA) and an LDR_DATA_TABLE_ENTRY for each module the process starts with — its image,
//! ntdll and kernel32 — linked in load order and in memory order (the image, ntdll, kernel32) and
//! in initialization order (ntdll, kernel32: the image is not initialized as a DLL is). The layout
//! is `rtl::modules`', Windows 2000's: programs and packers walk the lists themselves (to find
//! kernel32's base), and ntdll's loader exports (LdrGetDllHandle, LdrGetProcedureAddress,
//! LdrLoadDll, LdrUnloadDll) and kernel32's GetModuleFileNameA read them.
//!
//! On Windows 2000 ntdll's LdrpInitialize builds the lists in user mode, on the process heap, as it
//! maps the image's imports; F2K's loader still runs in the kernel (it snaps the imports against
//! the embedded DLLs, `exec::modules`), so the kernel writes them, on the process parameters'
//! first page past the block's strings ([`LOADER_DATA`]). The image's entry takes the
//! parameters' ImagePathName as its full path, buffer and all, as LdrpInitializeProcess does; each
//! entry's BaseDllName points into its full path's buffer, at the file name. Every module is
//! static: its LoadCount 0xFFFF. The hash links are empty (no hash table: the lookups walk the load
//! order).

use rtl::modules::{data, entry, flags, STATIC_LOAD_COUNT};

/// Where the lists sit on the parameters pages, from the block (past the image path's room), and
/// the room they and the system DLLs' paths take.
pub const LOADER_DATA: u32 = 0x700;
pub const ROOM: usize = 0x200;

/// Where the entries sit in the room (past the PEB_LDR_DATA), and the system DLLs' paths.
const ENTRIES: u32 = 0x28;
const STRINGS: u32 = ENTRIES + 3 * entry::SIZE;

/// A module the lists record: its base (its handle), its entry point (zero for none), its size,
/// its file header's TimeDateStamp, and whether it is a DLL.
#[derive(Clone, Copy, Debug)]
pub struct Module {
    pub base: u32,
    pub entry_point: u32,
    pub size: u32,
    pub time_date_stamp: u32,
    pub dll: bool,
}

/// A module's full path: its place (a UNICODE_STRING's buffer and room, in bytes) and its text
/// (code page 1252, a unit per byte).
#[derive(Clone, Copy, Debug)]
pub struct Path<'a> {
    pub buffer: u32,
    pub room: u32,
    pub text: &'a [u8],
}

/// The bytes of the lists at `at`: `image`, its full path at `image_path` (the parameters'
/// ImagePathName), then `dlls` (ntdll, kernel32) with their full paths, written in the room.
pub fn lists(at: u32, image: (Module, Path), dlls: [(Module, &[u8]); 2]) -> [u8; ROOM] {
    let mut bytes = [0u8; ROOM];
    let mut put = |offset: u32, value: u32| {
        bytes[offset as usize..offset as usize + 4].copy_from_slice(&value.to_le_bytes())
    };
    put(data::LENGTH, data::SIZE);
    put(data::INITIALIZED, 1);
    // The system DLLs' paths, in UTF-16, each terminated.
    let mut strings = STRINGS;
    let mut paths = [image.1; 2];
    for (index, &(_, text)) in dlls.iter().enumerate() {
        let units = 2 * text.len() as u32;
        paths[index] = Path {
            buffer: at + strings,
            room: units + 2,
            text,
        };
        strings += units + 2;
    }
    assert!(
        strings as usize <= ROOM,
        "the system DLLs' paths fit the lists' room"
    );
    let modules = [
        (image.0, image.1),
        (dlls[0].0, paths[0]),
        (dlls[1].0, paths[1]),
    ];
    let entry_at = |index: usize| ENTRIES + index as u32 * entry::SIZE;
    for (index, (module, path)) in modules.iter().enumerate() {
        let at_entry = entry_at(index);
        put(at_entry + entry::DLL_BASE, module.base);
        put(at_entry + entry::ENTRY_POINT, module.entry_point);
        put(at_entry + entry::SIZE_OF_IMAGE, module.size);
        let length = 2 * path.text.len() as u32;
        put(at_entry + entry::FULL_DLL_NAME, length | path.room << 16);
        put(at_entry + entry::FULL_DLL_NAME + 4, path.buffer);
        let file = 2 * path
            .text
            .iter()
            .rposition(|&byte| byte == b'\\')
            .map_or(0, |at| at + 1) as u32;
        put(
            at_entry + entry::BASE_DLL_NAME,
            (length - file) | (path.room - file) << 16,
        );
        put(at_entry + entry::BASE_DLL_NAME + 4, path.buffer + file);
        let kind = if module.dll { flags::IMAGE_DLL } else { 0 };
        put(at_entry + entry::FLAGS, kind | flags::ENTRY_PROCESSED);
        put(at_entry + entry::LOAD_COUNT, u32::from(STATIC_LOAD_COUNT));
        put(
            at_entry + entry::HASH_LINKS,
            at + at_entry + entry::HASH_LINKS,
        );
        put(
            at_entry + entry::HASH_LINKS + 4,
            at + at_entry + entry::HASH_LINKS,
        );
        put(at_entry + entry::TIME_DATE_STAMP, module.time_date_stamp);
    }
    // Each list from its head, round to it again: Flink forward, Blink back.
    let lists: [(u32, u32, &[usize]); 3] = [
        (
            data::IN_LOAD_ORDER_MODULE_LIST,
            entry::IN_LOAD_ORDER_LINKS,
            &[0, 1, 2],
        ),
        (
            data::IN_MEMORY_ORDER_MODULE_LIST,
            entry::IN_MEMORY_ORDER_LINKS,
            &[0, 1, 2],
        ),
        (
            data::IN_INITIALIZATION_ORDER_MODULE_LIST,
            entry::IN_INITIALIZATION_ORDER_LINKS,
            &[1, 2],
        ),
    ];
    for (head, links, order) in lists {
        let mut nodes = [head; 4];
        for (slot, &index) in nodes[1..].iter_mut().zip(order) {
            *slot = entry_at(index) + links;
        }
        let nodes = &nodes[..order.len() + 1];
        for (index, &node) in nodes.iter().enumerate() {
            put(node, at + nodes[(index + 1) % nodes.len()]);
            put(
                node + 4,
                at + nodes[(index + nodes.len() - 1) % nodes.len()],
            );
        }
    }
    for (index, (_, text)) in dlls.iter().enumerate() {
        let start = (paths[index].buffer - at) as usize;
        crate::user::params::widen(text, &mut bytes[start..start + 2 * text.len()]);
    }
    bytes
}

/// The system DLLs as the lists record them: ntdll and kernel32, at their bases, their full paths.
pub fn system_dlls() -> [(Module, &'static [u8]); 2] {
    use crate::exec::modules::{KERNEL32, NTDLL, SYSTEM_DLLS};
    [NTDLL, KERNEL32].map(|index| {
        let dll = &SYSTEM_DLLS[index];
        let image = dll.image();
        let entry_point = if image.entry_rva == 0 {
            0
        } else {
            image.entry_va()
        };
        let module = Module {
            base: dll.base,
            entry_point,
            size: image.size_of_image,
            time_date_stamp: image.time_date_stamp,
            dll: true,
        };
        (module, dll.path)
    })
}

/// Write the current process's lists on its parameters pages (mapped, the block written): `image`,
/// its path `image_name` (the parameters' ImagePathName's text), then the system DLLs.
#[cfg(target_arch = "x86")]
pub fn map(image: Module, image_name: &[u8]) {
    use crate::user::{params, PARAMS_PAGE};
    let at = PARAMS_PAGE + LOADER_DATA;
    let path = Path {
        buffer: PARAMS_PAGE + params::IMAGE_PATH_BUFFER,
        room: params::PATH_ROOM,
        text: image_name,
    };
    let bytes = lists(at, (image, path), system_dlls());
    let _ = crate::user::syscall::write_user(at, &bytes);
}

#[cfg(test)]
mod tests {
    use rtl::modules::{by_base, by_name, load_order, module_name, procedure_address, Memory};

    use super::*;

    const PARAMS: u32 = 0x0032_0000;

    /// The parameters' first page (the lists and the image's path on it) and the system DLLs'
    /// mapped images, as a process's memory.
    struct Process {
        page: std::vec::Vec<u8>,
        dlls: std::vec::Vec<(u32, std::vec::Vec<u8>)>,
    }

    impl Memory for Process {
        fn byte(&self, at: u32) -> u8 {
            if (PARAMS..PARAMS + 0x1000).contains(&at) {
                return self.page[(at - PARAMS) as usize];
            }
            for (base, image) in &self.dlls {
                if at >= *base && ((at - base) as usize) < image.len() {
                    return image[(at - base) as usize];
                }
            }
            panic!("{at:#010x} is not mapped");
        }
    }

    fn process() -> Process {
        use crate::user::params;
        let mut page = std::vec![0u8; 0x1000];
        let name = b"C:\\RUNTIME.EXE";
        let start = params::IMAGE_PATH_BUFFER as usize;
        params::widen(name, &mut page[start..start + 2 * name.len()]);
        let image = Module {
            base: 0x0040_0000,
            entry_point: 0x0040_1234,
            size: 0x6000,
            time_date_stamp: 0x3A00_0000,
            dll: false,
        };
        let path = Path {
            buffer: PARAMS + params::IMAGE_PATH_BUFFER,
            room: params::PATH_ROOM,
            text: name,
        };
        let at = LOADER_DATA as usize;
        page[at..at + ROOM].copy_from_slice(&lists(
            PARAMS + LOADER_DATA,
            (image, path),
            system_dlls(),
        ));
        let dlls = crate::exec::modules::SYSTEM_DLLS
            .iter()
            .map(|dll| {
                let image = dll.image();
                let mut mapped = std::vec![0u8; image.size_of_image as usize];
                image.map_into(dll.file, &mut mapped);
                (dll.base, mapped)
            })
            .collect();
        Process { page, dlls }
    }

    const LDR: u32 = PARAMS + LOADER_DATA;

    /// The lists' place: past the parameters block's strings on its first page, clear of the
    /// pages' other contents.
    #[test]
    fn the_lists_fit_the_parameters_page() {
        use crate::user::params;
        assert!(LOADER_DATA >= params::IMAGE_PATH_BUFFER + params::PATH_ROOM);
        assert!(LOADER_DATA as usize + ROOM <= 0x1000);
        assert!(LOADER_DATA as usize + ROOM <= params::COMMAND_LINE_BUFFER as usize);
    }

    /// The three lists, as Windows 2000 links them: load and memory order the image, ntdll,
    /// kernel32; initialization order ntdll, kernel32; each a ring through its head, the Blinks
    /// the Flinks reversed.
    #[test]
    fn the_lists_link_the_modules_in_order() {
        let memory = process();
        let walk = |head: u32, links: u32| {
            let mut bases = std::vec::Vec::new();
            let mut node = memory.word(LDR + head);
            while node != LDR + head {
                assert_eq!(
                    memory.word(memory.word(node) + 4),
                    node,
                    "the next node's Blink"
                );
                bases.push(memory.word(node - links + entry::DLL_BASE));
                node = memory.word(node);
            }
            bases
        };
        use crate::exec::modules::{KERNEL32_BASE, NTDLL_BASE};
        assert_eq!(
            walk(data::IN_LOAD_ORDER_MODULE_LIST, entry::IN_LOAD_ORDER_LINKS),
            [0x0040_0000, NTDLL_BASE, KERNEL32_BASE]
        );
        assert_eq!(
            walk(
                data::IN_MEMORY_ORDER_MODULE_LIST,
                entry::IN_MEMORY_ORDER_LINKS
            ),
            [0x0040_0000, NTDLL_BASE, KERNEL32_BASE]
        );
        assert_eq!(
            walk(
                data::IN_INITIALIZATION_ORDER_MODULE_LIST,
                entry::IN_INITIALIZATION_ORDER_LINKS
            ),
            [NTDLL_BASE, KERNEL32_BASE]
        );
        assert_eq!(
            (
                memory.word(LDR + data::LENGTH),
                memory.word(LDR + data::INITIALIZED)
            ),
            (0x24, 1)
        );
        assert_eq!(load_order(&memory, LDR).count(), 3);
    }

    /// Each entry: its base, entry point and size, its names (the base name inside the full
    /// path's buffer), its flags, a static load count and its TimeDateStamp.
    #[test]
    fn the_entries_describe_their_modules() {
        use crate::exec::modules::{KERNEL32_BASE, KERNEL32_SIZE, NTDLL_PATH};
        let memory = process();
        let text = |at: u32| -> std::string::String {
            let length = memory.half(at) as u32 / 2;
            let buffer = memory.word(at + 4);
            char::decode_utf16((0..length).map(|index| memory.half(buffer + 2 * index)))
                .map(|c| c.unwrap())
                .collect()
        };
        let image = by_base(&memory, LDR, 0x0040_0000).unwrap();
        assert_eq!(text(image + entry::FULL_DLL_NAME), "C:\\RUNTIME.EXE");
        assert_eq!(text(image + entry::BASE_DLL_NAME), "RUNTIME.EXE");
        assert_eq!(
            memory.word(image + entry::FULL_DLL_NAME + 4),
            PARAMS + crate::user::params::IMAGE_PATH_BUFFER
        );
        assert_eq!(memory.word(image + entry::ENTRY_POINT), 0x0040_1234);
        assert_eq!(memory.word(image + entry::FLAGS), flags::ENTRY_PROCESSED);
        assert_eq!(memory.word(image + entry::TIME_DATE_STAMP), 0x3A00_0000);
        assert_eq!(memory.half(image + entry::LOAD_COUNT), 0xFFFF);
        assert_eq!(
            memory.word(image + entry::IN_INITIALIZATION_ORDER_LINKS),
            0,
            "not in the initialization order"
        );
        let kernel32 = by_base(&memory, LDR, KERNEL32_BASE).unwrap();
        assert_eq!(
            text(kernel32 + entry::FULL_DLL_NAME),
            "C:\\WINNT\\system32\\KERNEL32.DLL"
        );
        assert_eq!(text(kernel32 + entry::BASE_DLL_NAME), "KERNEL32.DLL");
        assert_eq!(
            memory.half(kernel32 + entry::FULL_DLL_NAME + 2),
            2 * 30 + 2,
            "room for the terminator"
        );
        assert_eq!(
            memory.half(memory.word(kernel32 + entry::FULL_DLL_NAME + 4) + 60),
            0,
            "terminated"
        );
        assert_eq!(memory.word(kernel32 + entry::SIZE_OF_IMAGE), KERNEL32_SIZE);
        assert_eq!(memory.word(kernel32 + entry::ENTRY_POINT), 0, "no DllMain");
        assert_eq!(
            memory.word(kernel32 + entry::FLAGS),
            flags::IMAGE_DLL | flags::ENTRY_PROCESSED
        );
        assert_eq!(memory.half(kernel32 + entry::LOAD_COUNT), 0xFFFF);
        assert_eq!(
            memory.word(kernel32 + entry::HASH_LINKS),
            kernel32 + entry::HASH_LINKS,
            "an empty ring"
        );
        let ntdll = load_order(&memory, LDR).nth(1).unwrap();
        assert_eq!(text(ntdll + entry::FULL_DLL_NAME).as_bytes(), NTDLL_PATH);
        assert_eq!(text(ntdll + entry::BASE_DLL_NAME), "ntdll.dll");
    }

    /// ntdll's lookups over the lists the kernel builds and the DLLs as mapped agree with the
    /// kernel's own resolution (the import snapping's): every export of both DLLs by its name,
    /// kernel32's forwarders landing in ntdll; and the modules answer to their names.
    #[test]
    fn the_user_mode_lookups_agree_with_the_kernel() {
        use crate::exec::modules::{resolve, SYSTEM_DLLS};
        let memory = process();
        for dll in &SYSTEM_DLLS {
            let image = dll.image();
            let exports = image.exports(dll.file).unwrap();
            let mut count = 0;
            for name in exports.names(dll.file) {
                let expected = resolve(dll.file_name, name).unwrap();
                assert_eq!(
                    procedure_address(&memory, LDR, dll.base, name.as_bytes()),
                    Ok(expected),
                    "{}!{name}",
                    dll.file_name
                );
                count += 1;
            }
            assert!(count > 10, "{}: {count} exports", dll.file_name);
        }
        for (name, base) in [
            ("kernel32", 0x7C4E_0000),
            ("NTDLL.DLL", 0x77F8_0000),
            ("runtime.exe", 0x0040_0000),
        ] {
            let units: std::vec::Vec<u16> = name.encode_utf16().collect();
            let mut formed = [0u16; 32];
            let length = module_name(&units, &mut formed).unwrap();
            let found = by_name(&memory, LDR, &formed[..length]).unwrap();
            assert_eq!(memory.word(found + entry::DLL_BASE), base, "{name}");
        }
    }
}
