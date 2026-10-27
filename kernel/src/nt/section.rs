//! The section services: NtCreateSection, NtOpenSection, NtMapViewOfSection,
//! NtUnmapViewOfSection and NtQuerySection. kernel32's CreateFileMappingA, OpenFileMappingA,
//! MapViewOfFile and UnmapViewOfFile are Win32 code over these, as on Windows 2000, and its
//! CreateProcess asks NtQuerySection for an image's entry point and stack sizes.
//!
//! A section is of a file opened for reading, or of the paging file (no file handle). It owns its
//! frames (`mem::vm::SectionFrames`), made as views first need them — a file's pages filled from
//! the file then (a copy as of that moment: later writes to the file are not seen), the
//! paging file's zeroed — and every view maps them, so a write through one view shows in all of
//! them; a PAGE_WRITECOPY view maps them copy-on-write, its writes its own. A view is a reservation
//! of its own in the process's address space (MEM_MAPPED), on the 64 KiB allocation granularity. A
//! section is an object (see [`crate::ob`]), named in `\BaseNamedObjects` through the shared create
//! and open (`nt::sync`): it lives while a handle or a view references it, its frames while it or a
//! view holds them. A file's section holds the file object it was made from, so the file stays
//! open — and cannot be truncated or deleted — while it is mapped.
//!
//! A view's protection needs the section handle's access, as Windows 2000 checks it when it
//! references the handle (SECTION_MAP_WRITE for a read-write view, SECTION_MAP_READ for the others:
//! STATUS_ACCESS_DENIED), and a read-write view needs a section made read-write
//! (STATUS_SECTION_PROTECTION).
//!
//! An image section (SEC_IMAGE) is of a PE file, parsed by the loader's own parse (`exec::pe`): it
//! is the image as mapped, its size the image's. A file the parse refuses is refused as Windows
//! 2000 tells such files apart (see [`image_layout`]): no MZ signature, a DOS, Windows 3.x, OS/2 or
//! LE program, or a PE file that is broken or foreign (STATUS_INVALID_IMAGE_FORMAT). As on Windows
//! 2000, the image itself is the file's one image segment ([`ob::ImageSegment`], NT's image control
//! area), reached from the file's record: the first image section of a file makes it (and parses
//! the image then), every later one shares it, so every process's view of a DLL maps the same
//! frames. The segment holds the file object, so the file stays open — and cannot be truncated or
//! deleted — while any image section or view of it lives; a view holds the segment, not the
//! section, so the section's handle can be closed as soon as the view is mapped. A view is the
//! whole image at its preferred base — an image is never relocated, so a base another region holds
//! is STATUS_CONFLICTING_ADDRESSES — a MEM_IMAGE reservation whose pages carry their sections'
//! protections, as the loader maps a program's (a writable section's pages copy-on-write: the
//! segment's frames stay the file's). The segment's frames are made page by page as a view first
//! needs them, each read from the file through the image's section table. Nothing is snapped: the
//! imports are the mapper's to resolve (ntdll's loader).

use super::call::{Status, STATUS_INVALID_HANDLE};
use super::memory::{STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER_4};

pub const STATUS_ACCESS_DENIED: Status = Status(0xC000_0022);
const STATUS_NOT_MAPPED_VIEW: Status = Status(0xC000_0019);
const STATUS_INVALID_VIEW_SIZE: Status = Status(0xC000_001F);
const STATUS_SECTION_TOO_BIG: Status = Status(0xC000_0040);
const STATUS_SECTION_PROTECTION: Status = Status(0xC000_004E);
const STATUS_INVALID_FILE_FOR_SECTION: Status = Status(0xC000_0020);
const STATUS_INVALID_IMAGE_FORMAT: Status = Status(0xC000_007B);
const STATUS_MEDIA_WRITE_PROTECTED: Status = Status(0xC000_00A2);
const STATUS_INVALID_PARAMETER_6: Status = Status(0xC000_00F4);
const STATUS_INVALID_PARAMETER_8: Status = Status(0xC000_00F6);
const STATUS_INVALID_PARAMETER_9: Status = Status(0xC000_00F7);
const STATUS_MAPPED_FILE_SIZE_ZERO: Status = Status(0xC000_011E);
const STATUS_INVALID_IMAGE_NE_FORMAT: Status = Status(0xC000_011B);
const STATUS_INVALID_IMAGE_LE_FORMAT: Status = Status(0xC000_012E);
const STATUS_INVALID_IMAGE_NOT_MZ: Status = Status(0xC000_012F);
const STATUS_INVALID_IMAGE_PROTECT: Status = Status(0xC000_0130);
const STATUS_INVALID_IMAGE_WIN_16: Status = Status(0xC000_0131);
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
const STATUS_IO_DEVICE_ERROR: Status = Status(0xC000_0185);
const STATUS_MAPPED_ALIGNMENT: Status = Status(0xC000_0220);

/// The page protections a section and a view take.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// NtCreateSection's allocation attributes.
const SEC_FILE: u32 = 0x0080_0000;
const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_RESERVE: u32 = 0x0400_0000;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_NOCACHE: u32 = 0x1000_0000;

/// NtMapViewOfSection's inherit dispositions, and the allocation types it takes: top-down (a hint,
/// never honored) and SEC_NO_CHANGE (the view's protection fixed; not enforced).
const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;
const MEM_TOP_DOWN: u32 = 0x10_0000;
const SEC_NO_CHANGE: u32 = 0x40_0000;

/// The section access rights a view's protection needs, and the generic rights' mapping onto them.
const SECTION_QUERY: u32 = 0x0001;
const SECTION_MAP_WRITE: u32 = 0x0002;
const SECTION_MAP_READ: u32 = 0x0004;
const SECTION_MAP_EXECUTE: u32 = 0x0008;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The allocation granularity: views start on it, and view offsets are multiples of it.
const GRANULARITY: u32 = crate::mem::vm::GRANULARITY;

/// The file a section is made of, as its creation checks it: its size, whether it is a directory,
/// and whether its handle was granted read and write access.
#[derive(Clone, Copy)]
pub struct Backing {
    pub size: u32,
    pub directory: bool,
    pub read: bool,
    pub write: bool,
}

/// What a section's creation settles on: its size, and whether its views may write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub size: u32,
    pub writable: bool,
}

/// NtCreateSection's rules, over the maximum size asked for (none: the file's), the page
/// protection, the allocation attributes and the file (none: the paging file). The paging file's
/// section needs a size (zero or none: STATUS_INVALID_PARAMETER_4); a file's is at most the file's
/// size (a read-only one larger is STATUS_SECTION_TOO_BIG; a read-write one larger would extend the
/// file on Windows 2000 and is refused, STATUS_MEDIA_WRITE_PROTECTED), and an empty file maps
/// nothing (STATUS_MAPPED_FILE_SIZE_ZERO). Its handle must have been granted read access, and write
/// access too for a read-write section (STATUS_ACCESS_DENIED); a directory is no file to map
/// (STATUS_INVALID_HANDLE). A section's frames are named within what its frame tables can hold
/// (STATUS_SECTION_TOO_BIG past it).
pub fn plan(
    maximum: Option<u64>,
    protect: u32,
    allocation: u32,
    file: Option<Backing>,
) -> Result<Plan, Status> {
    if allocation & !(SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE) != 0
        || allocation & (SEC_IMAGE | SEC_RESERVE | SEC_COMMIT) == 0
        || allocation & (SEC_RESERVE | SEC_COMMIT) == SEC_RESERVE | SEC_COMMIT
    {
        return Err(STATUS_INVALID_PARAMETER_6);
    }
    if allocation & SEC_IMAGE != 0 {
        return image_plan(protect, file);
    }
    let writable = match protect {
        PAGE_READONLY | PAGE_WRITECOPY => false,
        PAGE_READWRITE => true,
        _ => return Err(STATUS_INVALID_PAGE_PROTECTION),
    };
    let maximum = maximum.filter(|&size| size != 0);
    let size = match file {
        None => match maximum {
            None => return Err(STATUS_INVALID_PARAMETER_4),
            Some(size) if size > u32::MAX as u64 => return Err(STATUS_INVALID_PARAMETER_4),
            Some(size) => size as u32,
        },
        Some(file) => {
            if file.directory {
                return Err(STATUS_INVALID_HANDLE);
            }
            if !file.read || writable && !file.write {
                return Err(STATUS_ACCESS_DENIED);
            }
            match maximum {
                None if file.size == 0 => return Err(STATUS_MAPPED_FILE_SIZE_ZERO),
                None => file.size,
                Some(size) if size > file.size as u64 => {
                    return Err(if writable {
                        STATUS_MEDIA_WRITE_PROTECTED
                    } else {
                        STATUS_SECTION_TOO_BIG
                    });
                }
                Some(size) => size as u32,
            }
        }
    };
    if size as u64 > crate::mem::vm::SECTION_MAX {
        return Err(STATUS_SECTION_TOO_BIG);
    }
    Ok(Plan { size, writable })
}

/// An image section's rules over its file, before the image itself is read (see
/// [`image_layout`]): a file opened for reading (or executing), and a page protection a view of
/// code takes (any but no-access); the size is the image's, settled by its parse.
fn image_plan(protect: u32, file: Option<Backing>) -> Result<Plan, Status> {
    let file = file.ok_or(STATUS_INVALID_FILE_FOR_SECTION)?;
    if !matches!(
        protect,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    ) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    if file.directory {
        return Err(STATUS_INVALID_HANDLE);
    }
    if !file.read {
        return Err(STATUS_ACCESS_DENIED);
    }
    if file.size == 0 {
        return Err(STATUS_MAPPED_FILE_SIZE_ZERO);
    }
    Ok(Plan {
        size: file.size,
        writable: false,
    })
}

/// The bytes an image section reads first: the file's first page, which holds its headers.
pub const IMAGE_HEADERS: usize = 0x1000;

/// An image's layout, from its first bytes `headers` (up to [`IMAGE_HEADERS`]) in a file of
/// `file_size` bytes: its preferred base and its size as mapped. A file the loader's parse refuses
/// is `not_an_image`'s status.
pub fn image_layout(headers: &[u8], file_size: u32) -> Result<(u32, u32), Status> {
    let image = crate::exec::pe::Image::parse_headers(headers, file_size as usize)
        .map_err(|_| not_an_image(headers))?;
    if image.size_of_image as u64 > crate::mem::vm::SECTION_MAX {
        return Err(STATUS_SECTION_TOO_BIG);
    }
    Ok((image.image_base, image.size_of_image))
}

/// The new header signatures an MZ file's e_lfanew may lead to: a PE image's, a 16-bit NE
/// program's and an LE one's; the NE header's target operating system (Windows', 2: the NE
/// format's documented values are 0 unknown, 1 OS/2, 2 Windows, 3 European MS-DOS 4.x, 4 Windows
/// 386); and the PE32 optional header's magic, its first word (the PE/COFF specification's 0x10B).
const PE_SIGNATURE: &[u8] = b"PE\0\0";
const NE_SIGNATURE: &[u8] = b"NE";
const LE_SIGNATURE: &[u8] = b"LE";
const NE_TARGET_OS: usize = 0x36;
const NE_WINDOWS: u8 = 2;
const PE32_MAGIC: [u8; 2] = 0x10Bu16.to_le_bytes();

/// Why the file whose first bytes are `headers` is no image the parse accepts, with the statuses
/// Windows 2000's section creation tells such files apart by (ntstatus.h): no MZ signature
/// (STATUS_INVALID_IMAGE_NOT_MZ); an MZ file whose new header is a 16-bit NE one, a Windows
/// program's (target 2: STATUS_INVALID_IMAGE_WIN_16) or any other target's, OS/2's and the
/// unknown one included (STATUS_INVALID_IMAGE_NE_FORMAT), or an LE one
/// (STATUS_INVALID_IMAGE_LE_FORMAT); an MZ file without a new header, a DOS program
/// (STATUS_INVALID_IMAGE_PROTECT), and so is one whose PE signature leads to no PE32 optional
/// header (no NT header at all: the spawn fixture's capture has GetBinaryType call a PE signature
/// followed by zeros a DOS program); and STATUS_INVALID_IMAGE_FORMAT for the rest — a PE32 file
/// the parse refuses (broken, truncated or foreign) or a DOS header cut short.
fn not_an_image(headers: &[u8]) -> Status {
    if headers.get(..2) != Some(b"MZ".as_slice()) {
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }
    let Some(new_header) = headers.get(E_LFANEW..E_LFANEW + 4) else {
        return STATUS_INVALID_IMAGE_FORMAT;
    };
    let at = u32::from_le_bytes([new_header[0], new_header[1], new_header[2], new_header[3]]);
    let signature = |wanted: &[u8]| {
        (at as usize)
            .checked_add(wanted.len())
            .and_then(|end| headers.get(at as usize..end))
            == Some(wanted)
    };
    let field = |offset: usize, length: usize| {
        (at as usize)
            .checked_add(offset)
            .and_then(|start| headers.get(start..start.checked_add(length)?))
    };
    if signature(PE_SIGNATURE) {
        if field(OPTIONAL_HEADER, 2) == Some(PE32_MAGIC.as_slice()) {
            STATUS_INVALID_IMAGE_FORMAT
        } else {
            STATUS_INVALID_IMAGE_PROTECT
        }
    } else if signature(NE_SIGNATURE) {
        if field(NE_TARGET_OS, 1) == Some([NE_WINDOWS].as_slice()) {
            STATUS_INVALID_IMAGE_WIN_16
        } else {
            STATUS_INVALID_IMAGE_NE_FORMAT
        }
    } else if signature(LE_SIGNATURE) {
        STATUS_INVALID_IMAGE_LE_FORMAT
    } else {
        STATUS_INVALID_IMAGE_PROTECT
    }
}

/// An image section's view rules: the whole image (no offset, no size short of it) at its
/// preferred base (zero: there), through a handle that may map it for reading or executing.
pub fn image_view(
    access: u32,
    base: u32,
    offset: u64,
    bytes: u32,
    image_base: u32,
    size: u32,
) -> Result<(), Status> {
    if section_access(access) & (SECTION_MAP_READ | SECTION_MAP_EXECUTE) == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if offset != 0 || bytes != 0 && bytes < size {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    if base != 0 && base != image_base {
        return Err(crate::nt::memory::STATUS_CONFLICTING_ADDRESSES);
    }
    Ok(())
}

/// The section access a handle's granted access amounts to, its generic rights mapped as the
/// section type maps them.
fn section_access(access: u32) -> u32 {
    let mut granted = access & 0x00FF_FFFF;
    if access & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        granted |= crate::ob::SECTION_ALL_ACCESS;
    }
    if access & GENERIC_READ != 0 {
        granted |= SECTION_QUERY | SECTION_MAP_READ;
    }
    if access & GENERIC_WRITE != 0 {
        granted |= SECTION_MAP_WRITE;
    }
    if access & GENERIC_EXECUTE != 0 {
        granted |= SECTION_MAP_EXECUTE;
    }
    granted
}

/// A view of `bytes` (zero: to the section's end) from `offset`, at `base` (zero: anywhere), with
/// `protect`, of a section of `size` bytes, `writable` or not, through a handle granted `access`:
/// the view's size in bytes. NtMapViewOfSection's rules.
pub fn view(
    access: u32,
    protect: u32,
    size: u32,
    writable: bool,
    base: u32,
    offset: u64,
    bytes: u32,
) -> Result<u32, Status> {
    let needs = if protect == PAGE_READWRITE {
        SECTION_MAP_WRITE
    } else {
        SECTION_MAP_READ
    };
    if section_access(access) & needs == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if protect == PAGE_READWRITE && !writable {
        return Err(STATUS_SECTION_PROTECTION);
    }
    if offset % GRANULARITY as u64 != 0 || base % GRANULARITY != 0 {
        return Err(STATUS_MAPPED_ALIGNMENT);
    }
    if offset >= size as u64 {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    let rest = size - offset as u32;
    match bytes {
        0 => Ok(rest),
        bytes if bytes > rest => Err(STATUS_INVALID_VIEW_SIZE),
        bytes => Ok(bytes),
    }
}

/// NtMapViewOfSection's own argument checks, before the handle is looked at: the inherit
/// disposition, the allocation type and the view's protection.
pub fn view_arguments(inherit: u32, allocation: u32, protect: u32) -> Result<(), Status> {
    if inherit != VIEW_SHARE && inherit != VIEW_UNMAP {
        return Err(STATUS_INVALID_PARAMETER_8);
    }
    if allocation & !(MEM_TOP_DOWN | SEC_NO_CHANGE) != 0 {
        return Err(STATUS_INVALID_PARAMETER_9);
    }
    if !matches!(
        protect,
        PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
    ) {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    Ok(())
}

// --- NtQuerySection
// -------------------------------------------------------------------------------

/// SECTION_INFORMATION_CLASS: SectionBasicInformation and SectionImageInformation.
pub const SECTION_BASIC_INFORMATION: u32 = 0;
pub const SECTION_IMAGE_INFORMATION: u32 = 1;

/// STATUS_SECTION_NOT_IMAGE: the image information of a data section.
pub const STATUS_SECTION_NOT_IMAGE: Status = Status(0xC000_0049);

/// SECTION_BASIC_INFORMATION: a section's base (zero for every section on Windows 2000, an image
/// section's included: a section has no base of its own, only its views do), its allocation
/// attributes and its size (a LARGE_INTEGER).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionBasicInformation {
    pub base_address: u32,
    pub allocation_attributes: u32,
    pub maximum_size: u64,
}

const _: () = assert!(core::mem::size_of::<SectionBasicInformation>() == 16);

/// What a section is made of, as its basic information names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    /// An image section (SEC_IMAGE | SEC_FILE).
    Image,
    /// A file's data section (SEC_FILE).
    File,
    /// The paging file's, created SEC_COMMIT or SEC_RESERVE.
    PagingFile { reserve: bool },
}

impl SectionBasicInformation {
    /// A section's: its kind's attributes and its size (an image's SizeOfImage, a data
    /// section's maximum size).
    pub fn of(kind: SectionKind, size: u32) -> Self {
        let allocation_attributes = match kind {
            SectionKind::Image => SEC_IMAGE | SEC_FILE,
            SectionKind::File => SEC_FILE,
            SectionKind::PagingFile { reserve: true } => SEC_RESERVE,
            SectionKind::PagingFile { reserve: false } => SEC_COMMIT,
        };
        SectionBasicInformation {
            base_address: 0,
            allocation_attributes,
            maximum_size: size as u64,
        }
    }

    /// The structure's bytes, as the caller's buffer receives them.
    pub fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.base_address.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.allocation_attributes.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.maximum_size.to_le_bytes());
        bytes
    }
}

/// SECTION_IMAGE_INFORMATION as Windows 2000 (NT 5.0) lays it out, 0x30 bytes: what the image's
/// headers say of its first thread and its subsystem, for kernel32's CreateProcess.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionImageInformation {
    /// The entry point's address, at the image's preferred base.
    pub transfer_address: u32,
    /// The zero bits of the image's base: none asked.
    pub zero_bits: u32,
    /// The stack reservation and commit the headers ask for its threads.
    pub maximum_stack_size: u32,
    pub committed_stack_size: u32,
    /// The subsystem, and the subsystem version it was linked for (minor, then major).
    pub subsystem_type: u32,
    pub subsystem_minor_version: u16,
    pub subsystem_major_version: u16,
    /// The global pointer: none on x86.
    pub gp_value: u32,
    /// The file header's characteristics, the optional header's DLL characteristics, and the
    /// machine.
    pub image_characteristics: u16,
    pub dll_characteristics: u16,
    pub machine: u16,
    /// Whether the image holds code (its headers' code size is not zero).
    pub image_contains_code: u8,
    pub spare1: u8,
    /// The optional header's loader flags.
    pub loader_flags: u32,
    pub reserved: [u32; 2],
}

/// SECTION_IMAGE_INFORMATION's size on Windows 2000.
pub const SECTION_IMAGE_INFORMATION_SIZE: u32 = 0x30;

const _: () = {
    use core::mem::offset_of;
    assert!(core::mem::size_of::<SectionImageInformation>() == 0x30);
    assert!(offset_of!(SectionImageInformation, subsystem_minor_version) == 0x14);
    assert!(offset_of!(SectionImageInformation, gp_value) == 0x18);
    assert!(offset_of!(SectionImageInformation, image_characteristics) == 0x1C);
    assert!(offset_of!(SectionImageInformation, machine) == 0x20);
    assert!(offset_of!(SectionImageInformation, image_contains_code) == 0x22);
    assert!(offset_of!(SectionImageInformation, loader_flags) == 0x24);
    assert!(offset_of!(SectionImageInformation, reserved) == 0x28);
};

impl SectionImageInformation {
    /// The structure's bytes, as the caller's buffer receives them.
    pub fn to_bytes(self) -> [u8; SECTION_IMAGE_INFORMATION_SIZE as usize] {
        let mut bytes = [0u8; SECTION_IMAGE_INFORMATION_SIZE as usize];
        let mut put = |at: usize, field: &[u8]| bytes[at..at + field.len()].copy_from_slice(field);
        put(0x00, &self.transfer_address.to_le_bytes());
        put(0x04, &self.zero_bits.to_le_bytes());
        put(0x08, &self.maximum_stack_size.to_le_bytes());
        put(0x0C, &self.committed_stack_size.to_le_bytes());
        put(0x10, &self.subsystem_type.to_le_bytes());
        put(0x14, &self.subsystem_minor_version.to_le_bytes());
        put(0x16, &self.subsystem_major_version.to_le_bytes());
        put(0x18, &self.gp_value.to_le_bytes());
        put(0x1C, &self.image_characteristics.to_le_bytes());
        put(0x1E, &self.dll_characteristics.to_le_bytes());
        put(0x20, &self.machine.to_le_bytes());
        put(0x22, &[self.image_contains_code, self.spare1]);
        put(0x24, &self.loader_flags.to_le_bytes());
        put(0x28, &self.reserved[0].to_le_bytes());
        put(0x2C, &self.reserved[1].to_le_bytes());
        bytes
    }
}

/// The PE header fields the image information reports beyond the loader's parse, by their
/// documented offsets: e_lfanew in the DOS header, where the NT headers start; from there, the
/// machine in the file header (after the 4-byte signature) and the PE32 optional header (after the
/// 20-byte file header), whose code size, DLL characteristics, stack sizes and loader flags follow
/// at their own offsets.
const E_LFANEW: usize = 0x3C;
const FILE_MACHINE: usize = 4;
const OPTIONAL_HEADER: usize = 24;
const OPTIONAL_SIZE_OF_CODE: usize = 4;
const OPTIONAL_DLL_CHARACTERISTICS: usize = 70;
const OPTIONAL_STACK_RESERVE: usize = 72;
const OPTIONAL_STACK_COMMIT: usize = 76;
const OPTIONAL_LOADER_FLAGS: usize = 88;

/// An image's SECTION_IMAGE_INFORMATION, from its first bytes `headers` (up to [`IMAGE_HEADERS`])
/// in a file of `file_size` bytes. STATUS_INVALID_IMAGE_FORMAT for a file the loader's parse
/// refuses (an image section's file never is: its creation parsed it).
pub fn image_information(
    headers: &[u8],
    file_size: u32,
) -> Result<SectionImageInformation, Status> {
    let image = crate::exec::pe::Image::parse_headers(headers, file_size as usize)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    // The parse checked the headers hold the file header and the whole optional header, whose
    // fixed part the fields below lie in.
    let u16_at = |at: usize| u16::from_le_bytes([headers[at], headers[at + 1]]);
    let u32_at = |at: usize| {
        u32::from_le_bytes([
            headers[at],
            headers[at + 1],
            headers[at + 2],
            headers[at + 3],
        ])
    };
    let nt = u32_at(E_LFANEW) as usize;
    let optional = nt + OPTIONAL_HEADER;
    let (major, minor) = image.subsystem_version;
    Ok(SectionImageInformation {
        transfer_address: image.image_base.wrapping_add(image.entry_rva),
        zero_bits: 0,
        maximum_stack_size: u32_at(optional + OPTIONAL_STACK_RESERVE),
        committed_stack_size: u32_at(optional + OPTIONAL_STACK_COMMIT),
        subsystem_type: image.subsystem as u32,
        subsystem_minor_version: minor,
        subsystem_major_version: major,
        gp_value: 0,
        image_characteristics: image.characteristics,
        dll_characteristics: u16_at(optional + OPTIONAL_DLL_CHARACTERISTICS),
        machine: u16_at(nt + FILE_MACHINE),
        image_contains_code: (u32_at(optional + OPTIONAL_SIZE_OF_CODE) != 0) as u8,
        spare1: 0,
        loader_flags: u32_at(optional + OPTIONAL_LOADER_FLAGS),
        reserved: [0; 2],
    })
}

/// NtQuerySection's class and length rules: the class's structure's size, which the buffer must
/// hold at least. STATUS_INVALID_INFO_CLASS for another class, STATUS_INFO_LENGTH_MISMATCH for a
/// shorter buffer.
pub fn query_size(class: u32, length: u32) -> Result<u32, Status> {
    let size = match class {
        SECTION_BASIC_INFORMATION => core::mem::size_of::<SectionBasicInformation>() as u32,
        SECTION_IMAGE_INFORMATION => SECTION_IMAGE_INFORMATION_SIZE,
        _ => return Err(crate::nt::memory::STATUS_INVALID_INFO_CLASS),
    };
    if length < size {
        return Err(crate::nt::memory::STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(size)
}

/// Whether a handle granted `access` may query its section (SECTION_QUERY, its generic rights
/// mapped): STATUS_ACCESS_DENIED otherwise.
pub fn query_access(access: u32) -> Result<(), Status> {
    if section_access(access) & SECTION_QUERY == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// Whether a section handle granted `access` may make a process's image (NtCreateProcess's
/// SectionHandle must grant SECTION_MAP_EXECUTE, its generic rights mapped):
/// STATUS_ACCESS_DENIED otherwise.
pub fn process_image_access(access: u32) -> Result<(), Status> {
    if section_access(access) & SECTION_MAP_EXECUTE == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::mem::vm::{CurrentPages, Kind, PAGE};
    use crate::nt::call::{
        calling_process,
        Handle,
        NtCall,
        NtResult,
        UserAddr,
        UserPtr,
        STATUS_SUCCESS,
    };
    use crate::nt::memory::{
        capture,
        with_space,
        STATUS_CONFLICTING_ADDRESSES,
        STATUS_INVALID_PARAMETER_2,
        STATUS_NO_MEMORY,
    };
    use crate::nt::object::is_console_handle;
    use crate::nt::sync;
    use crate::ob::{self, ObjectId, ObjectType};

    /// A section is gone: it drops its hold on its frames.
    pub fn release_frames(mut frames: crate::mem::vm::SectionFrames) {
        frames.release(&mut CurrentPages);
    }

    /// The file object a handle names, with its file as its record holds it now and the access the
    /// handle's open was granted. STATUS_INVALID_HANDLE for a handle naming nothing (a console
    /// handle included), STATUS_OBJECT_TYPE_MISMATCH for one naming another kind.
    fn file_of(handle: u32) -> Result<(ObjectId, crate::fs::fat32::lookup::File, Backing), Status> {
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let id = calling_process()
            .handles()
            .lookup(handle)
            .and_then(|entry| entry.object_id())
            .ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::File {
            return Err(crate::nt::attributes::STATUS_OBJECT_TYPE_MISMATCH);
        }
        let object = ob::directory().file(id).ok_or(STATUS_INVALID_HANDLE)?;
        let file = crate::fs::file::records().get(object.record).file;
        let backing = Backing {
            size: file.size,
            directory: file.directory,
            read: object.access & crate::fs::file::ACCESS_READ != 0,
            write: object.access & crate::fs::file::ACCESS_WRITE != 0,
        };
        Ok((id, file, backing))
    }

    /// NtCreateSection (see [`plan`]): a section of the file the handle names, or of the paging
    /// file (no handle), named or not (see `sync`'s create). A file's data section holds its file
    /// object, and the file counts it as mapped: the file stays open while the section lives,
    /// and cannot be truncated nor deleted meanwhile. The section's deletion gives both back.
    /// Its frames are made as views need them. An image section holds its file's image segment
    /// instead (see [`create_image_section`]).
    #[allow(clippy::too_many_arguments)]
    pub fn create_section(
        _call: &mut NtCall,
        slot: UserPtr<u32>,
        access: u32,
        attributes: UserAddr,
        maximum: UserPtr<u64>,
        protect: u32,
        allocation: u32,
        file: Handle,
    ) -> NtResult {
        let maximum = if maximum.is_null() {
            None
        } else {
            Some(maximum.read()?)
        };
        let backing = if file.raw() == 0 {
            None
        } else {
            Some(file_of(file.raw())?)
        };
        let plan = plan(
            maximum,
            protect,
            allocation,
            backing.map(|(_, _, backing)| backing),
        )?;
        let section = match backing {
            None => ob::SectionObject {
                size: plan.size,
                writable: plan.writable,
                reserve: allocation & SEC_RESERVE != 0,
                ..ob::SectionObject::none()
            },
            Some((file_object, file, _)) if allocation & SEC_IMAGE != 0 => {
                return create_image_section(slot, access, attributes, file_object, &file);
            }
            Some((file_object, file, _)) => ob::SectionObject {
                file,
                paging_file: false,
                reserve: false,
                frames: crate::mem::vm::SectionFrames::empty(),
                size: plan.size,
                writable: plan.writable,
                file_object: Some(file_object),
                image_base: 0,
                segment: None,
            },
        };
        sync::create(slot, access, attributes, ObjectType::Section, || {
            let directory = ob::directory();
            let id = directory.create_section(section)?;
            if let Some(file_object) = section.file_object {
                let held = directory.reference(file_object);
                debug_assert!(held, "the handle's file object lives");
                let record = directory.file(file_object).expect("held").record;
                crate::fs::file::records().get_mut(record).user_mapped += 1;
            }
            // A failed publication deletes the object, which gives the file back.
            Some(id)
        })
    }

    /// NtCreateSection of an image (SEC_IMAGE): a section of the file's image segment — the one
    /// the file's record names, while it lives, or a new one, the image's layout read and parsed
    /// now (see [`image_layout`]). A new segment holds the file object the handle names, and the
    /// file counts it as mapped; the segment's last reference gives both back.
    fn create_image_section(
        slot: UserPtr<u32>,
        access: u32,
        attributes: UserAddr,
        file_object: ObjectId,
        file: &crate::fs::fat32::lookup::File,
    ) -> NtResult {
        let record = ob::directory()
            .file(file_object)
            .expect("the handle's file object lives")
            .record;
        let segment_of = |directory: &mut ob::Directory| {
            let id = crate::fs::file::records().get(record).image?;
            directory
                .segment(id)
                .map(|segment| (id, segment.image_base, segment.size))
        };
        // A file's first image section reads and parses its headers; later ones take the layout
        // the segment holds.
        let layout = match segment_of(ob::directory()) {
            Some((_, image_base, size)) => (image_base, size),
            None => crate::process::threads::critical_region(|| read_layout(file))?,
        };
        sync::create(slot, access, attributes, ObjectType::Section, || {
            let directory = ob::directory();
            let segment = match segment_of(directory) {
                Some((id, _, _)) => {
                    let held = directory.reference_segment(id);
                    debug_assert!(held, "the file's segment lives");
                    id
                }
                None => {
                    let (image_base, size) = layout;
                    let id = directory.create_segment(ob::ImageSegment {
                        frames: crate::mem::vm::SectionFrames::empty(),
                        file_object,
                        image_base,
                        size,
                    })?;
                    let held = directory.reference(file_object);
                    debug_assert!(held, "the handle's file object lives");
                    let record = crate::fs::file::records().get_mut(record);
                    record.user_mapped += 1;
                    record.image = Some(id);
                    id
                }
            };
            let segment_record = *directory.segment(segment).expect("held");
            let section = directory.create_section(ob::SectionObject {
                file: *file,
                paging_file: false,
                size: segment_record.size,
                image_base: segment_record.image_base,
                segment: Some(segment),
                ..ob::SectionObject::none()
            });
            if section.is_none() {
                // No section record: the segment's reference goes back (and a new segment with
                // it).
                if let Some(followup) = directory.dereference_segment(segment) {
                    crate::user::args::calling_process().finish(followup);
                }
            }
            // A failed publication deletes the section, which drops its hold on the segment.
            section
        })
    }

    /// An image file's layout (see [`image_layout`]), from its first page as the volume holds it.
    fn read_layout(file: &crate::fs::fat32::lookup::File) -> Result<(u32, u32), Status> {
        let mut headers = [0u8; IMAGE_HEADERS];
        let headers = &mut headers[..IMAGE_HEADERS.min(file.size as usize)];
        if crate::fs::io::read_file_at(file, 0, headers).is_none() {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        image_layout(headers, file.size)
    }

    /// NtOpenSection: a new handle to the live section the name binds (see `sync`'s open).
    pub fn open_section(
        _call: &mut NtCall,
        slot: UserPtr<u32>,
        access: u32,
        attributes: UserAddr,
    ) -> NtResult {
        sync::open(slot, access, attributes, ObjectType::Section)
    }

    /// The section a handle names, referenced, with the access the handle was granted.
    fn section_of(handle: u32) -> Result<(ob::ObRef, u32), Status> {
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let entry = calling_process()
            .handles()
            .lookup(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::Section {
            return Err(crate::nt::attributes::STATUS_OBJECT_TYPE_MISMATCH);
        }
        Ok((
            ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?,
            entry.access,
        ))
    }

    /// NtMapViewOfSection (see [`view`]): a view of the section in the calling process, at the base
    /// asked for or anywhere, its pages the section's frames (made now when no view needed them
    /// yet: a file's bytes, zeros past its end, or the paging file's zeros) — read-write for
    /// PAGE_READWRITE, copy-on-write for PAGE_WRITECOPY, read-only or
    /// no-access otherwise. The base, the offset and the view's size (whole pages) written back.
    /// The commit size is not used (a view's pages are all committed).
    #[allow(clippy::too_many_arguments)]
    fn map_view_of_section_held(
        call: &mut NtCall,
        section: Handle,
        process: Handle,
        base: UserPtr<u32>,
        _zero_bits: u32,
        _commit_size: u32,
        offset: UserPtr<u64>,
        size: UserPtr<u32>,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> NtResult {
        view_arguments(inherit, allocation, protect)?;
        let requested = capture(base)?;
        let at = if offset.is_null() {
            0
        } else {
            let at = offset.read()?;
            offset.write(at)?;
            at
        };
        let length = capture(size)?;
        let (object, access) = section_of(section.raw())?;
        let record = *object.section();
        if let Some(segment) = record.segment {
            image_view(
                access,
                requested,
                at,
                length,
                record.image_base,
                record.size,
            )?;
            // The section holds its segment while this call references it.
            let mapped = with_space(call, process, |space, pages| {
                map_image(space, pages, segment)
            })?;
            base.write(mapped.base)?;
            size.write(record.size)?;
            return Ok(STATUS_SUCCESS);
        }
        let bytes = view(
            access,
            protect,
            record.size,
            record.writable,
            requested,
            at,
            length,
        )?;
        let mapped = with_space(call, process, |space, pages| {
            map_view(
                space,
                pages,
                object.id(),
                requested,
                at as u32,
                bytes,
                protect,
            )
        })?;
        base.write(mapped)?;
        size.write(bytes.next_multiple_of(PAGE))?;
        Ok(STATUS_SUCCESS)
    }

    /// NtMapViewOfSection (see [`map_view_of_section_held`]), as one critical region: a file's
    /// pages are read with the section referenced, and a termination requested meanwhile ends the
    /// thread only once the reference has gone.
    #[allow(clippy::too_many_arguments)]
    pub fn map_view_of_section(
        call: &mut NtCall,
        section: Handle,
        process: Handle,
        base: UserPtr<u32>,
        zero_bits: u32,
        commit_size: u32,
        offset: UserPtr<u64>,
        size: UserPtr<u32>,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> NtResult {
        crate::process::threads::critical_region(|| {
            map_view_of_section_held(
                call,
                section,
                process,
                base,
                zero_bits,
                commit_size,
                offset,
                size,
                inherit,
                allocation,
                protect,
            )
        })
    }

    /// Map `bytes` of the section `object` names from `offset` as a reservation of its own (at
    /// `requested`, or the lowest free range), its pages the section's frames.
    fn map_view(
        space: &mut crate::mem::vm::AddressSpace,
        table: &mut CurrentPages,
        object: ObjectId,
        requested: u32,
        offset: u32,
        bytes: u32,
        protect: u32,
    ) -> Result<u32, Status> {
        if !space.has_view_room() {
            return Err(STATUS_NO_MEMORY);
        }
        let directory = ob::directory();
        // A file's pages are made from the file as its record holds it now (the section keeps it
        // open).
        let file = {
            let section = *directory
                .section(object)
                .expect("the caller holds the section");
            match section
                .file_object
                .and_then(|file_object| directory.file(file_object).map(|object| object.record))
            {
                Some(record) => crate::fs::file::records().get(record).file,
                None => section.file,
            }
        };
        let section = directory
            .section(object)
            .expect("the caller holds the section");
        let pages = bytes.div_ceil(PAGE);
        let section_protect = if section.writable {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };
        let base = space
            .reserve(
                (requested != 0).then_some(requested),
                pages * PAGE,
                section_protect,
                Kind::Mapped,
            )
            .map_err(|error| match error {
                crate::mem::vm::VmError::InvalidAddress => STATUS_CONFLICTING_ADDRESSES,
                crate::mem::vm::VmError::InvalidParameter => STATUS_INVALID_PARAMETER_2,
                crate::mem::vm::VmError::NoMemory => STATUS_NO_MEMORY,
            })?;
        let mut buffer = [0u8; PAGE as usize];
        for page in 0..pages {
            let at = offset + page * PAGE;
            let made = section.frames.made(table, at / PAGE);
            // A file's page not yet made is read first: a read that fails maps nothing.
            let take = if made.is_none() && !section.paging_file {
                file.size.saturating_sub(at).min(PAGE) as usize
            } else {
                0
            };
            if take != 0 && crate::fs::io::read_file_at(&file, at, &mut buffer[..take]).is_none() {
                let _ = space.release(table, base);
                return Err(STATUS_IO_DEVICE_ERROR);
            }
            let frame = match made {
                Some(frame) => Ok(frame),
                None => section.frames.frame(table, at / PAGE, |frame| {
                    crate::mem::paging::write_frame(frame, 0, &buffer[..take]);
                }),
            };
            let mapped =
                frame.and_then(|frame| space.map_shared(table, base + page * PAGE, frame, protect));
            if mapped.is_err() {
                let _ = space.release(table, base);
                return Err(STATUS_NO_MEMORY);
            }
        }
        let recorded = space.add_view(base, ob::Mapping::Section(object));
        debug_assert!(recorded, "the view table had room");
        // The view holds its section for as long as it is mapped.
        let held = directory.reference(object);
        debug_assert!(held, "a section being mapped lives");
        Ok(base)
    }

    /// The image segment of the image section `handle` names, for a process's image
    /// (NtCreateProcess): the section referenced, and its segment. The handle's refusals (see
    /// [`section_of`]), one not granted SECTION_MAP_EXECUTE (see [`process_image_access`]), and a
    /// data section STATUS_SECTION_NOT_IMAGE.
    pub fn image_segment_of(handle: u32) -> Result<(ob::ObRef, ob::SegmentId), Status> {
        let (object, access) = section_of(handle)?;
        process_image_access(access)?;
        let segment = object.section().segment.ok_or(STATUS_SECTION_NOT_IMAGE)?;
        Ok((object, segment))
    }

    /// Map the image segment `segment` names as a view: the whole image at its preferred base
    /// (STATUS_CONFLICTING_ADDRESSES when another region holds any of it), a MEM_IMAGE reservation
    /// whose pages carry their sections' protections, every page the segment's frame. A page not
    /// made yet is built from the file, through the image's section table (its headers parsed
    /// again from the file's first page). The view holds the segment, not the section. Returns
    /// what a process made from the image records of it (see [`ImageView`]).
    pub fn map_image(
        space: &mut crate::mem::vm::AddressSpace,
        table: &mut CurrentPages,
        segment: ob::SegmentId,
    ) -> Result<ImageView, Status> {
        use crate::exec::loader::page_protect;
        use crate::mem::vm::PAGE_EXECUTE_WRITECOPY;
        if !space.has_view_room() {
            return Err(STATUS_NO_MEMORY);
        }
        let directory = ob::directory();
        // The file as its record holds it now (the segment keeps it open).
        let file = {
            let file_object = directory
                .segment(segment)
                .expect("the caller holds the segment")
                .file_object;
            let record = directory.file(file_object).expect("held").record;
            crate::fs::file::records().get(record).file
        };
        let mut buffer = [0u8; PAGE as usize];
        let headers = (file.size as usize).min(IMAGE_HEADERS);
        if crate::fs::io::read_file_at(&file, 0, &mut buffer[..headers]).is_none() {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        let image = crate::exec::pe::Image::parse_headers(&buffer[..headers], file.size as usize)
            .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        let segment_record = directory
            .segment(segment)
            .expect("the caller holds the segment");
        let base = space
            .reserve(
                Some(image.image_base),
                image.size_of_image,
                PAGE_EXECUTE_WRITECOPY,
                Kind::Image,
            )
            .map_err(|error| match error {
                crate::mem::vm::VmError::InvalidAddress
                | crate::mem::vm::VmError::InvalidParameter => STATUS_CONFLICTING_ADDRESSES,
                crate::mem::vm::VmError::NoMemory => STATUS_NO_MEMORY,
            })?;
        for page in 0..image.size_of_image.div_ceil(PAGE) {
            let rva = page * PAGE;
            let made = segment_record.frames.made(table, page);
            // A page not yet made is built first: a read that fails maps nothing.
            if made.is_none()
                && !image.map_page(rva, &mut buffer, |offset, out| {
                    crate::fs::io::read_file_at(&file, offset, out).is_some()
                })
            {
                let _ = space.release(table, base);
                return Err(STATUS_IO_DEVICE_ERROR);
            }
            let frame = match made {
                Some(frame) => Ok(frame),
                None => segment_record.frames.frame(table, page, |frame| {
                    crate::mem::paging::write_frame(frame, 0, &buffer);
                }),
            };
            let mapped = frame.and_then(|frame| {
                space.map_shared(table, base + rva, frame, page_protect(&image, rva))
            });
            if mapped.is_err() {
                let _ = space.release(table, base);
                return Err(STATUS_NO_MEMORY);
            }
        }
        let recorded = space.add_view(base, ob::Mapping::Image(segment));
        debug_assert!(recorded, "the view table had room");
        // The view holds the segment for as long as it is mapped.
        let held = directory.reference_segment(segment);
        debug_assert!(held, "a segment being mapped lives");
        Ok(ImageView {
            base,
            subsystem: image.subsystem,
            subsystem_version: image.subsystem_version,
        })
    }

    /// An image's view, as a process made from it records it in its PEB: the view's base (the
    /// image's preferred base), the image's subsystem and the subsystem version it was linked for.
    #[derive(Clone, Copy, Debug)]
    pub struct ImageView {
        pub base: u32,
        pub subsystem: u16,
        pub subsystem_version: (u16, u16),
    }

    /// NtUnmapViewOfSection: unmap the view holding the address — any address inside it names it,
    /// as on Windows 2000 — (a section, or an image segment, nothing names any more goes with its
    /// last view);
    /// STATUS_NOT_MAPPED_VIEW for an address no view holds.
    pub fn unmap_view_of_section(
        call: &mut NtCall,
        process: Handle,
        address: UserAddr,
    ) -> NtResult {
        let mapping = with_space(call, process, |space, pages| {
            // A data view, or an image section's (the image and the system DLLs, mapped by the
            // kernel itself, are no views).
            let base = space
                .region_at(address.raw())
                .filter(|region| matches!(region.kind, Kind::Mapped | Kind::Image))
                .ok_or(STATUS_NOT_MAPPED_VIEW)?
                .base;
            let mapping = space.take_view(base).ok_or(STATUS_NOT_MAPPED_VIEW)?;
            let _ = space.release(pages, base);
            Ok(mapping)
        })?;
        // The view's reference goes; a section or segment nothing else references goes with it.
        ob::release_mapping(mapping);
        Ok(STATUS_SUCCESS)
    }

    /// NtQuerySection(SectionHandle, Class, Information, Length, ResultLength): a section's basic
    /// information (see [`SectionBasicInformation::of`]), or an image section's image information,
    /// read from its image's headers (see [`image_information`]): the file the image segment holds
    /// is read again, inside a critical region, as the section's first creation read it. The class
    /// and the length are checked first (see [`query_size`]), then the buffers are probed for
    /// writing, then the handle — a section handle granted SECTION_QUERY (see [`query_access`]) —
    /// and last whether a data section is asked its image information
    /// (STATUS_SECTION_NOT_IMAGE). The structure's size goes into ResultLength.
    pub fn query_section(
        _call: &mut NtCall,
        section: Handle,
        class: u32,
        information: UserAddr,
        length: u32,
        result_length: UserPtr<u32>,
    ) -> NtResult {
        let size = query_size(class, length)?;
        sync::probe(information.raw(), size)?;
        sync::probe(result_length.addr().raw(), 4)?;
        let (object, access) = section_of(section.raw())?;
        query_access(access)?;
        let record = *object.section();
        if class == SECTION_BASIC_INFORMATION {
            let kind = if record.segment.is_some() {
                SectionKind::Image
            } else if record.file_object.is_some() {
                SectionKind::File
            } else {
                SectionKind::PagingFile {
                    reserve: record.reserve,
                }
            };
            information.write(&SectionBasicInformation::of(kind, record.size).to_bytes())?;
        } else {
            let segment = record.segment.ok_or(STATUS_SECTION_NOT_IMAGE)?;
            let directory = ob::directory();
            let file_object = directory
                .segment(segment)
                .expect("an image section holds its segment")
                .file_object;
            let file_record = directory
                .file(file_object)
                .expect("an image segment holds its file object")
                .record;
            let file = crate::fs::file::records().get(file_record).file;
            let info = crate::process::threads::critical_region(|| {
                let mut headers = [0u8; IMAGE_HEADERS];
                let headers = &mut headers[..IMAGE_HEADERS.min(file.size as usize)];
                if crate::fs::io::read_file_at(&file, 0, headers).is_none() {
                    return Err(STATUS_IO_DEVICE_ERROR);
                }
                image_information(headers, file.size)
            })?;
            information.write(&info.to_bytes())?;
        }
        result_length.write_optional(size)?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(not(target_arch = "x86"))]
pub use host::*;

/// The host builds' section services (see `nt::unserved`): they run against the target's object
/// manager and address space.
#[cfg(not(target_arch = "x86"))]
mod host {
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    /// A section is gone: the host has no frames to give back.
    pub fn release_frames(_frames: crate::mem::vm::SectionFrames) {}

    unserved! {
        create_section(UserPtr<u32>, u32, UserAddr, UserPtr<u64>, u32, u32, Handle);
        open_section(UserPtr<u32>, u32, UserAddr);
        map_view_of_section(Handle, Handle, UserPtr<u32>, u32, u32, UserPtr<u64>, UserPtr<u32>, u32, u32, u32);
        unmap_view_of_section(Handle, UserAddr);
        query_section(Handle, u32, UserAddr, u32, UserPtr<u32>);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error<T: core::fmt::Debug>(result: Result<T, Status>) -> u32 {
        rtl::status::dos_error(result.expect_err("the call fails").0)
    }

    /// The paging file's sections (memory/mapping's): a read-write one of a size; the refusals map
    /// to the errors the captures print.
    #[test]
    fn the_section_rules() {
        let commit = SEC_COMMIT;
        assert_eq!(
            plan(Some(0x10_0000), PAGE_READWRITE, commit, None),
            Ok(Plan {
                size: 0x10_0000,
                writable: true
            })
        );
        assert_eq!(
            plan(Some(0x1000), PAGE_WRITECOPY, SEC_RESERVE, None).map(|plan| plan.writable),
            Ok(false)
        );
        assert_eq!(
            error(plan(None, PAGE_READWRITE, commit, None)),
            87,
            "the paging file needs a size"
        );
        assert_eq!(error(plan(Some(0), PAGE_READWRITE, commit, None)), 87);
        assert_eq!(
            error(plan(Some(0x1000), 0x10, commit, None)),
            87,
            "PAGE_EXECUTE"
        );
        assert_eq!(
            error(plan(Some(0x1000), PAGE_READONLY, 0, None)),
            87,
            "no allocation attribute"
        );
        assert_eq!(
            error(plan(
                Some(0x1000),
                PAGE_READONLY,
                SEC_RESERVE | SEC_COMMIT,
                None
            )),
            87
        );
        assert_eq!(error(plan(Some(1 << 32), PAGE_READWRITE, commit, None)), 87);
        assert_eq!(
            plan(Some(0x1000), PAGE_READONLY, SEC_IMAGE, None),
            Err(STATUS_INVALID_FILE_FOR_SECTION),
            "an image section needs its file"
        );
        assert_eq!(
            error(plan(
                Some(crate::mem::vm::SECTION_MAX + 1),
                PAGE_READWRITE,
                commit,
                None
            )),
            8
        );
    }

    const FILE: Backing = Backing {
        size: 0x2_0000,
        directory: false,
        read: true,
        write: false,
    };

    /// A file's sections (files/mapping's): the file's size when none is asked, no larger than the
    /// file, never of an empty file, of a directory or of an open that may not read; read-write
    /// only over an open that may write.
    #[test]
    fn the_file_section_rules() {
        let commit = SEC_COMMIT;
        assert_eq!(
            plan(None, PAGE_READONLY, commit, Some(FILE)),
            Ok(Plan {
                size: 0x2_0000,
                writable: false
            })
        );
        assert_eq!(
            plan(Some(0x1000), PAGE_READONLY, commit, Some(FILE)),
            Ok(Plan {
                size: 0x1000,
                writable: false
            })
        );
        assert_eq!(
            error(plan(
                Some(0x2_0000 + 100_000),
                PAGE_READONLY,
                commit,
                Some(FILE)
            )),
            8,
            "larger than the file"
        );
        let empty = Backing { size: 0, ..FILE };
        assert_eq!(
            error(plan(None, PAGE_READONLY, commit, Some(empty))),
            1006,
            "an empty file"
        );
        assert_eq!(
            error(plan(None, PAGE_READWRITE, commit, Some(FILE))),
            5,
            "a read-write section of a read-only open"
        );
        let writable = Backing {
            write: true,
            ..FILE
        };
        assert_eq!(
            plan(None, PAGE_READWRITE, commit, Some(writable)),
            Ok(Plan {
                size: 0x2_0000,
                writable: true
            })
        );
        assert_eq!(
            error(plan(Some(0x3_0000), PAGE_READWRITE, commit, Some(writable))),
            19,
            "a read-write section past the file would extend it"
        );
        let unreadable = Backing {
            read: false,
            ..FILE
        };
        assert_eq!(
            error(plan(None, PAGE_READONLY, commit, Some(unreadable))),
            5
        );
        let directory = Backing {
            directory: true,
            ..FILE
        };
        assert_eq!(error(plan(None, PAGE_READONLY, commit, Some(directory))), 6);
        assert_eq!(
            error(plan(None, 0x10, commit, Some(FILE))),
            87,
            "PAGE_EXECUTE"
        );
        assert_eq!(
            error(plan(None, PAGE_READONLY, 0, Some(FILE))),
            87,
            "no allocation attribute"
        );
    }

    /// Image sections (LdrLoadDll's): of a file opened for reading, not empty, not a directory,
    /// with any protection but no-access; the size is the image's, read from its headers.
    #[test]
    fn the_image_section_rules() {
        let image = SEC_IMAGE;
        assert_eq!(
            plan(None, PAGE_EXECUTE, image, Some(FILE)),
            Ok(Plan {
                size: FILE.size,
                writable: false
            })
        );
        assert_eq!(
            plan(None, PAGE_READWRITE, image, Some(FILE)).map(|plan| plan.writable),
            Ok(false)
        );
        assert_eq!(
            plan(None, PAGE_EXECUTE, image, None),
            Err(STATUS_INVALID_FILE_FOR_SECTION)
        );
        assert_eq!(
            plan(None, PAGE_NOACCESS, image, Some(FILE)),
            Err(STATUS_INVALID_PAGE_PROTECTION)
        );
        let directory = Backing {
            directory: true,
            ..FILE
        };
        assert_eq!(
            plan(None, PAGE_EXECUTE, image, Some(directory)),
            Err(STATUS_INVALID_HANDLE)
        );
        let unreadable = Backing {
            read: false,
            ..FILE
        };
        assert_eq!(
            plan(None, PAGE_EXECUTE, image, Some(unreadable)),
            Err(STATUS_ACCESS_DENIED)
        );
        let empty = Backing { size: 0, ..FILE };
        assert_eq!(
            plan(None, PAGE_EXECUTE, image, Some(empty)),
            Err(STATUS_MAPPED_FILE_SIZE_ZERO)
        );
    }

    const EXIT0: &[u8] = include_bytes!("../../../tests/core/exit0/exit0.exe");

    /// An image's layout is its headers' (preferred base, SizeOfImage); a PE file the loader's
    /// parse refuses — a foreign one, a truncated one — is STATUS_INVALID_IMAGE_FORMAT, and a file
    /// that is no PE file at all is told apart (see `not_an_image`'s test): a text file has no MZ,
    /// and a file cut before its new header is an MZ file without one, a DOS program's.
    #[test]
    fn image_layouts_come_from_the_headers() {
        let size = EXIT0.len() as u32;
        assert_eq!(
            image_layout(&EXIT0[..IMAGE_HEADERS], size),
            Ok((0x0040_0000, 0x3000))
        );
        assert_eq!(
            image_layout(b"plain text, not an image", 24),
            Err(STATUS_INVALID_IMAGE_NOT_MZ)
        );
        assert_eq!(
            image_layout(&EXIT0[..0x40], 0x40),
            Err(STATUS_INVALID_IMAGE_PROTECT)
        );
        assert_eq!(
            image_layout(&EXIT0[..IMAGE_HEADERS], size - 1),
            Err(STATUS_INVALID_IMAGE_FORMAT)
        );
        let mut foreign = EXIT0[..IMAGE_HEADERS].to_vec();
        let machine = u32::from_le_bytes(foreign[0x3C..0x40].try_into().unwrap()) as usize + 4;
        foreign[machine..machine + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        assert_eq!(
            image_layout(&foreign, size),
            Err(STATUS_INVALID_IMAGE_FORMAT)
        );
    }

    /// A file that is no PE image, as Windows 2000's section creation refuses it (spawn's
    /// binaryforms block): without MZ (a text file, a single byte), a DOS program (no new header,
    /// one past the headers or of another kind, or a PE signature with no PE32 optional header
    /// after it), a Windows 3.x NE program (target 2) or another NE one (OS/2's, an unknown
    /// target's), an LE one; an MZ file whose DOS header is cut short, or whose PE32 header the
    /// parse refuses, is no image format at all.
    #[test]
    fn files_that_are_no_image_are_told_apart() {
        assert_eq!(
            not_an_image(b"not a program\r\n"),
            STATUS_INVALID_IMAGE_NOT_MZ
        );
        assert_eq!(not_an_image(b"M"), STATUS_INVALID_IMAGE_NOT_MZ);
        let mz = |new_header: u32, signature: &[u8], target: u8| {
            let mut bytes = vec![0u8; 0x200];
            bytes[..2].copy_from_slice(b"MZ");
            bytes[E_LFANEW..E_LFANEW + 4].copy_from_slice(&new_header.to_le_bytes());
            // A new header within the bytes gets its signature and target system.
            let at = new_header as usize;
            if at < 0x100 {
                bytes[at..at + signature.len()].copy_from_slice(signature);
                bytes[at + NE_TARGET_OS] = target;
            }
            bytes
        };
        assert_eq!(
            not_an_image(&mz(0x80, b"\0\0", 0)),
            STATUS_INVALID_IMAGE_PROTECT
        );
        assert_eq!(
            not_an_image(&mz(0x1000, b"", 0)),
            STATUS_INVALID_IMAGE_PROTECT,
            "past the headers"
        );
        assert_eq!(
            not_an_image(&mz(u32::MAX, b"", 0)),
            STATUS_INVALID_IMAGE_PROTECT
        );
        assert_eq!(
            not_an_image(&mz(0x80, b"NE", 2)),
            STATUS_INVALID_IMAGE_WIN_16
        );
        for target in [0, 1, 3, 4] {
            assert_eq!(
                not_an_image(&mz(0x80, b"NE", target)),
                STATUS_INVALID_IMAGE_NE_FORMAT,
                "target {target}"
            );
        }
        assert_eq!(
            not_an_image(&mz(0x80, b"LE", 0)),
            STATUS_INVALID_IMAGE_LE_FORMAT
        );
        assert_eq!(
            not_an_image(&mz(0x80, PE_SIGNATURE, 0)),
            STATUS_INVALID_IMAGE_PROTECT,
            "a PE signature, nothing after it"
        );
        let mut pe32 = mz(0x80, PE_SIGNATURE, 0);
        pe32[0x80 + OPTIONAL_HEADER..0x80 + OPTIONAL_HEADER + 2].copy_from_slice(&PE32_MAGIC);
        assert_eq!(not_an_image(&pe32), STATUS_INVALID_IMAGE_FORMAT);
        assert_eq!(
            not_an_image(b"MZ"),
            STATUS_INVALID_IMAGE_FORMAT,
            "a DOS header cut short"
        );
        assert_eq!(
            image_layout(&mz(0x80, b"NE", 2), 0x200),
            Err(STATUS_INVALID_IMAGE_WIN_16)
        );
    }

    /// SECTION_IMAGE_INFORMATION from an image's headers: the entry point at the preferred base,
    /// the stack sizes, the subsystem and its version, the characteristics and the machine, as
    /// the file's headers hold them; a file the parse refuses is no image.
    #[test]
    fn the_image_information_is_the_headers() {
        let size = EXIT0.len() as u32;
        let info = image_information(&EXIT0[..IMAGE_HEADERS], size).unwrap();
        let image = crate::exec::pe::Image::parse(EXIT0).unwrap();
        let header = |at: usize| u32::from_le_bytes(EXIT0[at..at + 4].try_into().unwrap());
        let optional = header(0x3C) as usize + 24;
        assert_eq!(info.transfer_address, 0x0040_0000 + image.entry_rva);
        assert_eq!(
            (info.maximum_stack_size, info.committed_stack_size),
            (header(optional + 72), header(optional + 76))
        );
        assert_eq!(info.subsystem_type, 3, "a console image");
        assert_eq!(
            (info.subsystem_major_version, info.subsystem_minor_version),
            image.subsystem_version
        );
        assert_eq!(info.machine, 0x14C);
        assert_eq!(info.image_characteristics, image.characteristics);
        assert_eq!(info.image_contains_code, 1);
        assert_eq!(
            (info.zero_bits, info.gp_value, info.reserved),
            (0, 0, [0, 0])
        );
        let bytes = info.to_bytes();
        assert_eq!(bytes.len(), 0x30);
        assert_eq!(&bytes[0..4], &info.transfer_address.to_le_bytes());
        assert_eq!(
            &bytes[0x14..0x16],
            &info.subsystem_minor_version.to_le_bytes()
        );
        assert_eq!(
            &bytes[0x16..0x18],
            &info.subsystem_major_version.to_le_bytes()
        );
        assert_eq!(&bytes[0x20..0x23], &[0x4C, 0x01, 1]);
        assert_eq!(
            image_information(b"plain text, not an image", 24),
            Err(STATUS_INVALID_IMAGE_FORMAT)
        );
    }

    /// SECTION_BASIC_INFORMATION (memory/query's): no base for any section, an image's
    /// included; an image is SEC_IMAGE | SEC_FILE, a file's data section SEC_FILE, the paging
    /// file's SEC_COMMIT or SEC_RESERVE as created; the size a LARGE_INTEGER.
    #[test]
    fn the_basic_information_names_the_section_kind() {
        let image = SectionBasicInformation::of(SectionKind::Image, 0x3000);
        assert_eq!(
            (
                image.base_address,
                image.allocation_attributes,
                image.maximum_size
            ),
            (0, 0x0180_0000, 0x3000)
        );
        let data = SectionBasicInformation::of(SectionKind::File, 0x1234);
        assert_eq!(
            (data.base_address, data.allocation_attributes),
            (0, 0x0080_0000)
        );
        let commit = SectionBasicInformation::of(SectionKind::PagingFile { reserve: false }, 1);
        assert_eq!(commit.allocation_attributes, 0x0800_0000);
        let reserve = SectionBasicInformation::of(SectionKind::PagingFile { reserve: true }, 1);
        assert_eq!(reserve.allocation_attributes, 0x0400_0000);
        let bytes = image.to_bytes();
        assert_eq!(&bytes[..4], &0u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &(SEC_IMAGE | SEC_FILE).to_le_bytes());
        assert_eq!(&bytes[8..16], &0x3000u64.to_le_bytes());
    }

    /// NtQuerySection's classes and lengths, and its access: SECTION_QUERY, or a generic right
    /// that maps to it.
    #[test]
    fn the_query_rules() {
        assert_eq!(query_size(SECTION_BASIC_INFORMATION, 16), Ok(16));
        assert_eq!(query_size(SECTION_IMAGE_INFORMATION, 0x30), Ok(0x30));
        assert_eq!(query_size(SECTION_IMAGE_INFORMATION, 0x40), Ok(0x30));
        assert_eq!(
            query_size(SECTION_IMAGE_INFORMATION, 0x2C),
            Err(crate::nt::memory::STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            query_size(2, 0x100),
            Err(crate::nt::memory::STATUS_INVALID_INFO_CLASS)
        );
        assert_eq!(query_access(SECTION_QUERY), Ok(()));
        assert_eq!(query_access(GENERIC_READ), Ok(()));
        assert_eq!(query_access(crate::ob::SECTION_ALL_ACCESS), Ok(()));
        assert_eq!(query_access(SECTION_MAP_READ), Err(STATUS_ACCESS_DENIED));
        assert_eq!(error(query_access(SECTION_MAP_WRITE)), 5);
    }

    /// A process's image section: its handle must grant SECTION_MAP_EXECUTE, or a generic right
    /// that maps to it (kernel32's CreateProcess opens it with SECTION_ALL_ACCESS); a data section
    /// is no image (STATUS_SECTION_NOT_IMAGE, ERROR_INVALID_PARAMETER to kernel32).
    #[test]
    fn a_process_image_maps_for_executing() {
        assert_eq!(process_image_access(SECTION_MAP_EXECUTE), Ok(()));
        assert_eq!(process_image_access(GENERIC_EXECUTE), Ok(()));
        assert_eq!(process_image_access(crate::ob::SECTION_ALL_ACCESS), Ok(()));
        assert_eq!(process_image_access(MAXIMUM_ALLOWED), Ok(()));
        assert_eq!(
            process_image_access(SECTION_MAP_READ | SECTION_QUERY | GENERIC_READ),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(error(Err::<(), _>(STATUS_SECTION_NOT_IMAGE)), 87);
    }

    /// An image section's view is the whole image at its preferred base: no offset, no size short
    /// of the image, another base a conflict (an image is never relocated); the handle must map it
    /// for reading or executing.
    #[test]
    fn image_views_are_the_whole_image_at_its_base() {
        let (base, size) = (0x1000_0000, 0x3000);
        let map = SECTION_QUERY | SECTION_MAP_READ;
        assert_eq!(image_view(map, 0, 0, 0, base, size), Ok(()));
        assert_eq!(image_view(map, base, 0, size, base, size), Ok(()));
        assert_eq!(
            image_view(SECTION_QUERY | SECTION_MAP_EXECUTE, 0, 0, 0, base, size),
            Ok(())
        );
        assert_eq!(
            image_view(SECTION_QUERY, 0, 0, 0, base, size),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            image_view(map, 0x2000_0000, 0, 0, base, size),
            Err(crate::nt::memory::STATUS_CONFLICTING_ADDRESSES)
        );
        assert_eq!(
            image_view(map, 0, 0x1_0000, 0, base, size),
            Err(STATUS_INVALID_VIEW_SIZE)
        );
        assert_eq!(
            image_view(map, 0, 0, 0x1000, base, size),
            Err(STATUS_INVALID_VIEW_SIZE)
        );
    }

    /// The views' refusals: a read-write view needs SECTION_MAP_WRITE (ERROR_ACCESS_DENIED) and a
    /// read-write section; offsets are on the granularity (ERROR_MAPPED_ALIGNMENT); a view stays
    /// inside the section.
    #[test]
    fn the_view_rules() {
        let read_only_handle = 0x000F_0005;
        assert_eq!(
            error(view(
                read_only_handle,
                PAGE_READWRITE,
                0x2_0000,
                false,
                0,
                0,
                0
            )),
            5
        );
        assert_eq!(
            view(read_only_handle, PAGE_READONLY, 0x2_0000, false, 0, 0, 0),
            Ok(0x2_0000)
        );
        assert_eq!(
            view(
                read_only_handle,
                PAGE_READONLY,
                0x2_0000,
                false,
                0,
                0x1_0000,
                1000
            ),
            Ok(1000)
        );
        assert_eq!(
            error(view(
                read_only_handle,
                PAGE_READONLY,
                0x2_0000,
                false,
                0,
                0x1000,
                1000
            )),
            1132
        );
        assert_eq!(
            error(view(
                crate::ob::SECTION_ALL_ACCESS,
                PAGE_READWRITE,
                0x2_0000,
                false,
                0,
                0,
                0
            )),
            87
        );
        assert_eq!(
            error(view(
                read_only_handle,
                PAGE_READONLY,
                0x2_0000,
                false,
                0,
                0x2_0000,
                0
            )),
            5,
            "past the end"
        );
        assert_eq!(
            error(view(
                read_only_handle,
                PAGE_READONLY,
                0x2_0000,
                false,
                0,
                0x1_0000,
                0x1_0001
            )),
            5
        );
        assert_eq!(
            view(GENERIC_WRITE, PAGE_READWRITE, 0x1000, true, 0, 0, 0),
            Ok(0x1000),
            "generic rights map"
        );
        assert_eq!(
            error(view(SECTION_QUERY, PAGE_READONLY, 0x1000, true, 0, 0, 0)),
            5
        );
        assert_eq!(
            view(
                SECTION_QUERY | SECTION_MAP_READ,
                PAGE_WRITECOPY,
                0x1000,
                true,
                0,
                0,
                0
            ),
            Ok(0x1000),
            "a copy-on-write view reads the section"
        );
        assert_eq!(error(view_arguments(0, 0, PAGE_READONLY)), 87);
        assert_eq!(error(view_arguments(VIEW_SHARE, 0x1000, PAGE_READONLY)), 87);
        assert_eq!(error(view_arguments(VIEW_SHARE, 0, 0x40)), 87);
        assert_eq!(
            view_arguments(VIEW_UNMAP, MEM_TOP_DOWN, PAGE_NOACCESS),
            Ok(())
        );
    }
}
