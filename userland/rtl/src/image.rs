//! A mapped PE32 image's headers, as Windows defines them (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32),
//! read from the image's first page ([`nt_headers`]), and what the process's start takes from them:
//! the process heap's first segment ([`process_heap_sizes`]).

use core::mem::size_of;

/// IMAGE_DOS_HEADER: the MZ stub's header, its last word the NT headers' offset from the image's
/// base.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    /// The DOS stub's fields, which Windows does not read.
    pub e_dos: [u16; 29],
    pub e_lfanew: i32,
}

/// IMAGE_FILE_HEADER.
#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// IMAGE_OPTIONAL_HEADER32.
#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy)]
pub struct ImageNtHeaders32 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader32,
}

const _: () = {
    // The layouts Windows defines.
    assert!(size_of::<ImageDosHeader>() == 0x40);
    assert!(core::mem::offset_of!(ImageDosHeader, e_lfanew) == 0x3C);
    assert!(size_of::<ImageFileHeader>() == 0x14);
    assert!(core::mem::offset_of!(ImageOptionalHeader32, size_of_heap_reserve) == 0x50);
    assert!(core::mem::offset_of!(ImageOptionalHeader32, data_directory) == 0x60);
    assert!(size_of::<ImageOptionalHeader32>() == 0xE0);
    assert!(core::mem::offset_of!(ImageNtHeaders32, optional_header) == 0x18);
};

/// "MZ", "PE\0\0", and the PE32 optional header's magic.
const DOS_MAGIC: u16 = 0x5A4D;
const NT_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x010B;

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
    let dos: ImageDosHeader = header_copy(base, 0);
    if dos.e_magic != DOS_MAGIC {
        return None;
    }
    let offset = usize::try_from(dos.e_lfanew).ok()?;
    if offset.checked_add(size_of::<ImageNtHeaders32>())? > HEADER_PAGE {
        return None;
    }
    let nt: ImageNtHeaders32 = header_copy(base, offset);
    (nt.signature == NT_SIGNATURE && nt.optional_header.magic == PE32_MAGIC).then_some(nt)
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
}
