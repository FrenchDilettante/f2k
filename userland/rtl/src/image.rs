//! A PE32 image's structures, as Windows defines them (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, the
//! section table's rows, the export directory and the import descriptors), all plain data
//! ([`Pod`]), so that a parse reads each one whole from an image's bytes; a data directory as
//! RtlImageDirectoryEntryToData finds it ([`data_directory`]). From a mapped image's first page:
//! its NT headers ([`nt_headers`]), and what the process's start takes from them: the process
//! heap's first segment ([`process_heap_sizes`]); where RtlImageNtHeader finds them
//! ([`nt_headers_offset`]).

use core::mem::{offset_of, size_of};

use crate::pod::Pod;

/// IMAGE_DOS_HEADER: the MZ stub's header, its last word the NT headers' offset from the image's
/// base.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    /// The DOS stub's fields, which Windows does not read.
    pub e_dos: [u16; 29],
    pub e_lfanew: i32,
}

/// IMAGE_FILE_HEADER.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// IMAGE_DATA_DIRECTORY.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// IMAGE_OPTIONAL_HEADER32.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

/// IMAGE_NT_HEADERS32.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageNtHeaders32 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader32,
}

/// IMAGE_SECTION_HEADER: one row of the section table, which follows the optional header.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageSectionHeader {
    /// The section's name, NUL-padded: a name of eight bytes has no terminator.
    pub name: [u8; 8],
    /// Misc.VirtualSize: the section's size in memory.
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// IMAGE_EXPORT_DIRECTORY: the export directory's fixed part. Its three arrays and its strings lie
/// elsewhere in the image, at the RVAs it gives.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    /// The ordinal of the address table's first slot.
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// IMAGE_IMPORT_DESCRIPTOR: one imported module. An all-zero descriptor ends the array.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageImportDescriptor {
    /// OriginalFirstThunk (its union's other name is Characteristics): the lookup array's RVA.
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    /// The module name's RVA.
    pub name: u32,
    /// The import address table's RVA.
    pub first_thunk: u32,
}

const _: () = {
    // The layouts Windows defines.
    assert!(size_of::<ImageDosHeader>() == 0x40);
    assert!(offset_of!(ImageDosHeader, e_lfanew) == 0x3C);
    assert!(size_of::<ImageFileHeader>() == 0x14);
    assert!(offset_of!(ImageFileHeader, time_date_stamp) == 4);
    assert!(offset_of!(ImageFileHeader, size_of_optional_header) == 0x10);
    assert!(offset_of!(ImageFileHeader, characteristics) == 0x12);
    assert!(size_of::<ImageDataDirectory>() == 8);
    assert!(offset_of!(ImageOptionalHeader32, address_of_entry_point) == 0x10);
    assert!(offset_of!(ImageOptionalHeader32, image_base) == 0x1C);
    assert!(offset_of!(ImageOptionalHeader32, major_subsystem_version) == 0x30);
    assert!(offset_of!(ImageOptionalHeader32, size_of_image) == 0x38);
    assert!(offset_of!(ImageOptionalHeader32, subsystem) == 0x44);
    assert!(offset_of!(ImageOptionalHeader32, dll_characteristics) == 0x46);
    assert!(offset_of!(ImageOptionalHeader32, size_of_stack_reserve) == 0x48);
    assert!(offset_of!(ImageOptionalHeader32, size_of_heap_reserve) == 0x50);
    assert!(offset_of!(ImageOptionalHeader32, loader_flags) == 0x58);
    assert!(offset_of!(ImageOptionalHeader32, number_of_rva_and_sizes) == 0x5C);
    assert!(offset_of!(ImageOptionalHeader32, data_directory) == 0x60);
    assert!(size_of::<ImageOptionalHeader32>() == 0xE0);
    assert!(offset_of!(ImageNtHeaders32, file_header) == 4);
    assert!(offset_of!(ImageNtHeaders32, optional_header) == 0x18);
    assert!(size_of::<ImageNtHeaders32>() == 0xF8);
    assert!(offset_of!(ImageSectionHeader, virtual_size) == 8);
    assert!(offset_of!(ImageSectionHeader, pointer_to_raw_data) == 0x14);
    assert!(offset_of!(ImageSectionHeader, number_of_relocations) == 0x20);
    assert!(offset_of!(ImageSectionHeader, characteristics) == 0x24);
    assert!(size_of::<ImageSectionHeader>() == 0x28);
    assert!(offset_of!(ImageExportDirectory, name) == 0x0C);
    assert!(offset_of!(ImageExportDirectory, base) == 0x10);
    assert!(offset_of!(ImageExportDirectory, address_of_name_ordinals) == 0x24);
    assert!(size_of::<ImageExportDirectory>() == 0x28);
    assert!(offset_of!(ImageImportDescriptor, name) == 0x0C);
    assert!(size_of::<ImageImportDescriptor>() == 0x14);
};

// SAFETY: each is a `#[repr(C)]` structure of integers, arrays of them and the structures above,
// without padding (each size asserted above is its fields' sum, every field at its alignment), so
// every byte belongs to a field and every bit pattern is a value.
unsafe impl Pod for ImageDosHeader {}
// SAFETY: as above.
unsafe impl Pod for ImageFileHeader {}
// SAFETY: as above.
unsafe impl Pod for ImageDataDirectory {}
// SAFETY: as above.
unsafe impl Pod for ImageOptionalHeader32 {}
// SAFETY: as above.
unsafe impl Pod for ImageNtHeaders32 {}
// SAFETY: as above.
unsafe impl Pod for ImageSectionHeader {}
// SAFETY: as above.
unsafe impl Pod for ImageExportDirectory {}
// SAFETY: as above.
unsafe impl Pod for ImageImportDescriptor {}

/// "MZ", "PE\0\0", and the PE32 optional header's magic.
pub const DOS_MAGIC: u16 = 0x5A4D;
pub const NT_SIGNATURE: u32 = 0x0000_4550;
pub const PE32_MAGIC: u16 = 0x010B;

/// The data directories' indices (IMAGE_DIRECTORY_ENTRY_*) the system reads, and the format's
/// count of them (IMAGE_NUMBEROF_DIRECTORY_ENTRIES).
pub const DIRECTORY_EXPORT: usize = 0;
pub const DIRECTORY_IMPORT: usize = 1;
pub const DIRECTORY_BASERELOC: usize = 5;
pub const DIRECTORY_IAT: usize = 12;
pub const NUMBER_OF_DIRECTORIES: usize = 16;

/// The data directory `index` of the image whose NT headers are `nt`, as
/// RtlImageDirectoryEntryToData finds it: none at or past the header's NumberOfRvaAndSizes (or the
/// format's sixteen), nor for an entry whose address is zero (the image has no such directory).
pub fn data_directory(nt: &ImageNtHeaders32, index: usize) -> Option<ImageDataDirectory> {
    let optional = &nt.optional_header;
    if index >= optional.number_of_rva_and_sizes as usize {
        return None;
    }
    let entry = *optional.data_directory.get(index)?;
    (entry.virtual_address != 0).then_some(entry)
}

/// The page an image's headers sit in: the loader maps it whole, and the headers are read inside
/// it alone.
const HEADER_PAGE: usize = 0x1000;

/// A copy of the `T` at `offset` into the header page at `base`.
fn header_copy<T: Copy>(base: usize, offset: usize) -> T {
    debug_assert!(offset + size_of::<T>() <= HEADER_PAGE);
    // SAFETY: the callers pass a mapped image's base, whose first page is mapped readable for the
    // image's life, and an offset that keeps the read inside that page; the headers have no
    // alignment promise, hence the unaligned read of a plain-data type.
    unsafe { core::ptr::read_unaligned((base + offset) as *const T) }
}

/// The NT headers of the image mapped at `base` (its first page mapped), copied out: none when its
/// headers are not a PE32 image's, or do not sit in its first page.
pub fn nt_headers(base: usize) -> Option<ImageNtHeaders32> {
    let offset = nt_headers_offset(&header_copy(base, 0))?;
    if offset.checked_add(size_of::<ImageNtHeaders32>())? > HEADER_PAGE {
        return None;
    }
    let nt: ImageNtHeaders32 = header_copy(base, offset);
    (nt.signature == NT_SIGNATURE && nt.optional_header.magic == PE32_MAGIC).then_some(nt)
}

/// Where the NT headers of the image whose DOS header is `dos` start, from the image's base
/// (e_lfanew), as RtlImageNtHeader finds them: none without the MZ signature or for a negative
/// offset. The caller checks the signature found there ([`NT_SIGNATURE`]).
pub fn nt_headers_offset(dos: &ImageDosHeader) -> Option<usize> {
    if dos.e_magic != DOS_MAGIC {
        return None;
    }
    usize::try_from(dos.e_lfanew).ok()
}

/// The process heap's first segment, as the process's image asks for it: its header's
/// SizeOfHeapReserve and SizeOfHeapCommit (reserve, commit). Zeroes, the heaps' defaults, for an
/// image whose headers are not a PE32 image's.
pub fn process_heap_sizes(base: usize) -> (usize, usize) {
    nt_headers(base).map_or((0, 0), |nt| {
        let optional = nt.optional_header;
        (
            optional.size_of_heap_reserve as usize,
            optional.size_of_heap_commit as usize,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header page: MZ, the NT headers at 0xE8, and a PE32 optional header with MSVC 6's heap
    /// sizes (1 MiB reserved, 4 KiB committed).
    fn page() -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_PAGE];
        let mut put = |at: usize, value: &[u8]| bytes[at..at + value.len()].copy_from_slice(value);
        put(0, &DOS_MAGIC.to_le_bytes());
        put(0x3C, &0xE8u32.to_le_bytes());
        put(0xE8, &NT_SIGNATURE.to_le_bytes());
        put(0xE8 + 0x18, &PE32_MAGIC.to_le_bytes());
        put(0xE8 + 0x18 + 0x50, &0x10_0000u32.to_le_bytes());
        put(0xE8 + 0x18 + 0x54, &0x1000u32.to_le_bytes());
        bytes
    }

    /// The heap sizes read from the headers; headers that are not a PE32 image's, or that run past
    /// the first page, give the defaults.
    #[test]
    fn the_process_heap_sizes_come_from_the_headers() {
        let bytes = page();
        assert_eq!(
            process_heap_sizes(bytes.as_ptr() as usize),
            (0x10_0000, 0x1000)
        );
        let mut broken = page();
        broken[0xE8] = 0;
        assert_eq!(process_heap_sizes(broken.as_ptr() as usize), (0, 0));
        let mut pe32_plus = page();
        pe32_plus[0xE8 + 0x19] = 0x02;
        assert_eq!(process_heap_sizes(pe32_plus.as_ptr() as usize), (0, 0));
        let mut far = page();
        far[0x3C..0x40].copy_from_slice(&0xF80u32.to_le_bytes());
        assert!(nt_headers(far.as_ptr() as usize).is_none(), "past the page");
        far[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(
            nt_headers(far.as_ptr() as usize).is_none(),
            "a negative offset"
        );
    }

    /// A data directory is found below NumberOfRvaAndSizes (and the format's sixteen), and only
    /// with a nonzero address.
    #[test]
    fn a_data_directory_is_found_as_rtl_finds_it() {
        let entry = |virtual_address: u32, size: u32| ImageDataDirectory {
            virtual_address,
            size,
        };
        let mut nt = ImageNtHeaders32::zeroed();
        nt.optional_header.number_of_rva_and_sizes = 2;
        nt.optional_header.data_directory[DIRECTORY_EXPORT] = entry(0x2000, 0x40);
        nt.optional_header.data_directory[2] = entry(0x3000, 8);
        assert_eq!(
            data_directory(&nt, DIRECTORY_EXPORT),
            Some(entry(0x2000, 0x40))
        );
        assert_eq!(data_directory(&nt, DIRECTORY_IMPORT), None, "no address");
        assert_eq!(data_directory(&nt, 2), None, "past the count");
        nt.optional_header.number_of_rva_and_sizes = 0x100;
        assert_eq!(data_directory(&nt, 2), Some(entry(0x3000, 8)));
        assert_eq!(
            data_directory(&nt, NUMBER_OF_DIRECTORIES),
            None,
            "past the format's sixteen"
        );
    }

    /// RtlImageNtHeader's offset: e_lfanew behind the MZ signature, none without it or when
    /// negative.
    #[test]
    fn the_nt_headers_offset_is_e_lfanew() {
        let dos = |magic: u16, lfanew: i32| ImageDosHeader {
            e_magic: magic,
            e_dos: [0; 29],
            e_lfanew: lfanew,
        };
        assert_eq!(nt_headers_offset(&dos(DOS_MAGIC, 0xE8)), Some(0xE8));
        assert_eq!(nt_headers_offset(&dos(DOS_MAGIC, 0x2_0000)), Some(0x2_0000));
        assert_eq!(nt_headers_offset(&dos(0x4D5A, 0xE8)), None, "ZM");
        assert_eq!(nt_headers_offset(&dos(DOS_MAGIC, -8)), None);
    }
}
