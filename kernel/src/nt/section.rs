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
//! (STATUS_SECTION_PROTECTION). The view keeps the most it may become ([`view_maximum`]): a later
//! protection change gives its pages nothing more, so a view through a read-only handle, or of a
//! read-only section, never writes the section's frames, and a copy-on-write view's writes stay its
//! own. A view's allocation protection is its own, as a query reports it.
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
//! section, so the section's handle can be closed as soon as the view is mapped. Its last reference
//! leaves it cached, as Windows 2000 keeps an image's control area: its frames parked on Standby
//! ([`park_segment`]), where the allocator may take them, so the next run of the image takes back
//! the pages still its own without reading the file. The segment's first page is the image's
//! header page, built from the file's first page when the segment is made: every view and query
//! parses the headers from it. A cached image is purged when its file is
//! about to be cut, overwritten, deleted or replaced ([`purge_cached_image`], NT's
//! MmFlushImageSection) or written ([`forget_image`]), when its record is needed for another image,
//! at quiescence and at shutdown. A view is the
//! whole image at its preferred base — an image is never relocated, so a base another region holds
//! is STATUS_CONFLICTING_ADDRESSES — a MEM_IMAGE reservation whose pages carry their sections'
//! protections, as the loader maps a program's (a writable section's pages copy-on-write: the
//! segment's frames stay the file's). The segment's frames are made page by page as a view first
//! needs them, each read from the file through the image's section table. Nothing is snapped: the
//! imports are the mapper's to resolve (ntdll's loader).

use rtl::pod::Pod;

use crate::status::*;

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

/// NtMapViewOfSection's inherit dispositions, and the allocation types it takes: top-down (a data
/// view without a base takes the highest free range) and SEC_NO_CHANGE (the view's protection
/// fixed; not enforced).
const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;
const MEM_TOP_DOWN: u32 = 0x10_0000;
const SEC_NO_CHANGE: u32 = 0x40_0000;

// The section access rights a view's protection needs, and the generic rights' mapping onto them.
use rtl::nt::access::{
    GENERIC_ALL,
    GENERIC_EXECUTE,
    GENERIC_READ,
    GENERIC_WRITE,
    MAXIMUM_ALLOWED,
    SECTION_MAP_EXECUTE,
    SECTION_MAP_READ,
    SECTION_MAP_WRITE,
    SECTION_QUERY,
};

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
) -> Result<Plan, NtStatus> {
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
fn image_plan(protect: u32, file: Option<Backing>) -> Result<Plan, NtStatus> {
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
pub fn image_layout(headers: &[u8], file_size: u32) -> Result<(u32, u32), NtStatus> {
    let image = crate::exec::pe::Image::parse_headers(headers, file_size as usize)
        .map_err(|_| not_an_image(headers))?;
    if image.size_of_image() as u64 > crate::mem::vm::SECTION_MAX {
        return Err(STATUS_SECTION_TOO_BIG);
    }
    Ok((image.image_base(), image.size_of_image()))
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
fn not_an_image(headers: &[u8]) -> NtStatus {
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
) -> Result<(), NtStatus> {
    if section_access(access) & (SECTION_MAP_READ | SECTION_MAP_EXECUTE) == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if offset != 0 || bytes != 0 && bytes < size {
        return Err(STATUS_INVALID_VIEW_SIZE);
    }
    if base != 0 && base != image_base {
        return Err(STATUS_CONFLICTING_ADDRESSES);
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
) -> Result<u32, NtStatus> {
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

/// The maximum of a view with `protect` of a section `writable` or not, through a handle granted
/// `access` (see [`crate::mem::vm::Maximum`]): its section's frames are its to write only when the
/// section is read-write and the handle may map it for writing; a copy-on-write view of such a
/// section takes a writable protection copy-on-write; any other view takes none.
pub fn view_maximum(access: u32, protect: u32, writable: bool) -> crate::mem::vm::Maximum {
    use crate::mem::vm::Maximum;
    if !writable || section_access(access) & SECTION_MAP_WRITE == 0 {
        Maximum::Read
    } else if protect == PAGE_WRITECOPY {
        Maximum::CopyOnWrite
    } else {
        Maximum::Write
    }
}

/// NtMapViewOfSection's own argument checks, before the handle is looked at: the zero bits (at
/// most 21: STATUS_INVALID_PARAMETER_4), the inherit disposition, the allocation type and the
/// view's protection. Where a data view without a base goes (see [`crate::mem::vm::Placement`]).
pub fn view_arguments(
    zero_bits: u32,
    inherit: u32,
    allocation: u32,
    protect: u32,
) -> Result<crate::mem::vm::Placement, NtStatus> {
    let placement = crate::mem::vm::Placement::of(zero_bits, allocation & MEM_TOP_DOWN != 0)
        .ok_or(STATUS_INVALID_PARAMETER_4)?;
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
    Ok(placement)
}

// --- A file-backed view's pages -----------------------------------------------------------------
//
// A file-backed data view faults its pages in from the file: mapping writes a prototype entry per
// page (its section page index in the payload bits, the view's protection in the index bits), and
// the fault path ([`crate::mem::backing`]'s Section arm) reads the page from the file at that
// index's offset. A paging-file-backed view's pages are made zeroed as the view maps, as they
// have no file to read. A write-maximum view of a file-backed section writes its touched pages back
// to the file when the view unmaps.

/// The file byte offset of a section's page `index`.
pub fn page_file_offset(index: u32) -> u32 {
    index * crate::mem::vm::PAGE
}

/// How many bytes of a section of `size` bytes its page `index` holds: a page, or less at the
/// section's end.
pub fn page_span_len(size: u32, index: u32) -> usize {
    size.saturating_sub(page_file_offset(index))
        .min(crate::mem::vm::PAGE) as usize
}

/// A view's page at `va`, mapped from `offset` at `base`: its section page index and the file byte
/// offset it reads from. None for an address outside the view or off a page.
pub fn view_page(view_offset: u32, base: u32, va: u32) -> Option<(u32, u32)> {
    let at = va.checked_sub(base)?.checked_add(view_offset)?;
    if at % crate::mem::vm::PAGE != 0 {
        return None;
    }
    Some((at / crate::mem::vm::PAGE, at))
}

/// The write-back of one of a view's pages at unmap: the file offset to write at and how many bytes
/// (clamped to the section's size). None for a page past the section's end.
pub fn write_back_span(
    view_offset: u32,
    base: u32,
    va: u32,
    section_size: u32,
) -> Option<(u32, usize)> {
    let (index, offset) = view_page(view_offset, base, va)?;
    if offset >= section_size {
        return None;
    }
    Some((offset, page_span_len(section_size, index)))
}

/// Read a section's page `index` from `file`'s bytes into `buf`: the bytes the file holds at the
/// page's offset, zero past its end. (Host tests; the target reads through the file system.)
#[cfg_attr(not(test), allow(dead_code))]
pub fn read_section_page(file: &[u8], index: u32, buf: &mut [u8]) {
    buf.fill(0);
    let offset = page_file_offset(index) as usize;
    let len = file.len().saturating_sub(offset).min(buf.len());
    if len > 0 {
        buf[..len].copy_from_slice(&file[offset..offset + len]);
    }
}

/// Write a view's present pages back to its backing: for each page of `[base, end)` whose entry is
/// present, the frame's page is read (`read_frame`) and written at the page's file offset
/// (`write_file`, clamped to `section_size`). False when a read or a write failed.
pub fn write_back_pages(
    pages: &impl crate::mem::vm::Pages,
    base: u32,
    end: u32,
    view_offset: u32,
    section_size: u32,
    read_frame: &mut impl FnMut(u32, &mut [u8]) -> bool,
    write_file: &mut impl FnMut(u32, &[u8]) -> bool,
) -> bool {
    use crate::mem::pte::{FRAME_MASK, PRESENT};
    use crate::mem::vm::PAGE;
    let mut buf = [0u8; PAGE as usize];
    let mut va = base;
    while va < end {
        let entry = pages.entry(va);
        if entry & PRESENT != 0 {
            let frame = entry & FRAME_MASK;
            if !read_frame(frame, &mut buf) {
                return false;
            }
            if let Some((offset, len)) = write_back_span(view_offset, base, va, section_size) {
                if !write_file(offset, &buf[..len]) {
                    return false;
                }
            }
        }
        va += PAGE;
    }
    true
}

// --- NtQuerySection
// -------------------------------------------------------------------------------

info_class! {
    /// The classes NtQuerySection answers (SECTION_INFORMATION_CLASS).
    pub enum SectionClass {
        /// SECTION_BASIC_INFORMATION.
        Basic = 0,
        /// SECTION_IMAGE_INFORMATION.
        Image = 1,
    }
}

impl SectionClass {
    /// The class's structure's size.
    pub fn size(self) -> u32 {
        (match self {
            SectionClass::Basic => size_of::<SectionBasicInformation>(),
            SectionClass::Image => size_of::<SectionImageInformation>(),
        }) as u32
    }
}

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

const _: () = assert!(size_of::<SectionBasicInformation>() == 16);

// SAFETY: two u32s and a u64 at offset 8, 16 bytes without padding (asserted above, on every
// target); any bits make a value.
unsafe impl Pod for SectionBasicInformation {}

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

const _: () = {
    use core::mem::offset_of;
    // Windows 2000's size and offsets.
    assert!(size_of::<SectionImageInformation>() == 0x30);
    assert!(offset_of!(SectionImageInformation, subsystem_minor_version) == 0x14);
    assert!(offset_of!(SectionImageInformation, gp_value) == 0x18);
    assert!(offset_of!(SectionImageInformation, image_characteristics) == 0x1C);
    assert!(offset_of!(SectionImageInformation, machine) == 0x20);
    assert!(offset_of!(SectionImageInformation, image_contains_code) == 0x22);
    assert!(offset_of!(SectionImageInformation, loader_flags) == 0x24);
    assert!(offset_of!(SectionImageInformation, reserved) == 0x28);
};

// SAFETY: integers and an array of them, 0x30 bytes without padding (the size and offsets asserted
// above are the fields' sums); any bits make a value.
unsafe impl Pod for SectionImageInformation {}

/// Where an MZ file's new header lies: e_lfanew, in the DOS header; and where a PE image's
/// optional header starts in its NT headers (after the signature and the file header).
const E_LFANEW: usize = core::mem::offset_of!(rtl::image::ImageDosHeader, e_lfanew);
const OPTIONAL_HEADER: usize = core::mem::offset_of!(rtl::image::ImageNtHeaders32, optional_header);

/// An image's SECTION_IMAGE_INFORMATION, from its first bytes `headers` (up to [`IMAGE_HEADERS`])
/// in a file of `file_size` bytes: the loader's parse, and the header fields it reports beyond
/// it (the stack sizes, the DLL characteristics, the machine, whether there is code, the loader
/// flags). STATUS_INVALID_IMAGE_FORMAT for a file the loader's parse refuses (an image section's
/// file never is: its creation parsed it).
pub fn image_information(
    headers: &[u8],
    file_size: u32,
) -> Result<SectionImageInformation, NtStatus> {
    let image = crate::exec::pe::Image::parse_headers(headers, file_size as usize)
        .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    let nt = image.nt_headers();
    let optional = &nt.optional_header;
    let (major, minor) = image.subsystem_version();
    Ok(SectionImageInformation {
        transfer_address: image.image_base().wrapping_add(image.entry_rva()),
        zero_bits: 0,
        maximum_stack_size: optional.size_of_stack_reserve,
        committed_stack_size: optional.size_of_stack_commit,
        subsystem_type: image.subsystem() as u32,
        subsystem_minor_version: minor,
        subsystem_major_version: major,
        gp_value: 0,
        image_characteristics: image.characteristics(),
        dll_characteristics: optional.dll_characteristics,
        machine: nt.file_header.machine,
        image_contains_code: (optional.size_of_code != 0) as u8,
        spare1: 0,
        loader_flags: optional.loader_flags,
        reserved: [0; 2],
    })
}

/// NtQuerySection's class and length rules: the class, and its structure's size, which the buffer
/// must hold at least. STATUS_INVALID_INFO_CLASS for another class, STATUS_INFO_LENGTH_MISMATCH for
/// a shorter buffer.
pub fn query_size(class: u32, length: u32) -> Result<(SectionClass, u32), NtStatus> {
    let class = SectionClass::try_from(class)?;
    let size = class.size();
    if length < size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok((class, size))
}

/// Whether a handle granted `access` may query its section (SECTION_QUERY, its generic rights
/// mapped): STATUS_ACCESS_DENIED otherwise.
pub fn query_access(access: u32) -> Result<(), NtStatus> {
    if section_access(access) & SECTION_QUERY == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// Whether a section handle granted `access` may make a process's image (NtCreateProcess's
/// SectionHandle must grant SECTION_MAP_EXECUTE, its generic rights mapped):
/// STATUS_ACCESS_DENIED otherwise.
pub fn process_image_access(access: u32) -> Result<(), NtStatus> {
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
    use crate::nt::call::{calling_process, Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::nt::memory::{capture, with_process, with_space};
    use crate::nt::object::is_console_handle;
    use crate::nt::sync;
    use crate::ob::{self, ObjectId, ObjectType};

    /// A section is gone: it drops its hold on its frames. A cached image segment's are parked,
    /// its image `parked` pages long: each still its own comes off Standby first.
    pub fn release_frames(mut frames: crate::mem::vm::SectionFrames, parked: Option<u32>) {
        match parked {
            Some(pages) => frames.release_parked(&mut CurrentPages, pages),
            None => frames.release(&mut CurrentPages),
        }
    }

    /// An image segment's last reference went ([`ob::Followup::Park`]): while it is still cached
    /// (not referenced again meanwhile, nor purged), its frames go to Standby, linked to their
    /// slots, so the allocator may take them and the file's next image section takes back the
    /// ones still its own (see [`ob::ImageSegment`]).
    pub fn park_segment(segment: ob::SegmentId) {
        ob::locked(|directory| {
            if !directory.segment_cached(segment) {
                return;
            }
            let record = directory.segment(segment).expect("a cached segment lives");
            if !record.parked {
                let pages = record.pages();
                record.frames.park(&mut CurrentPages, pages);
                record.parked = true;
            }
        });
    }

    /// The file `record`'s image segment, when it is cached, is purged: the file is about to be
    /// cut, overwritten or deleted (Windows 2000's MmFlushImageSection, which FastFat asks before
    /// each). An active one stays: the file is mapped, and the change is refused.
    pub fn purge_cached_image(record: crate::fs::file::FileRecordId) {
        flush_image(record, false);
    }

    /// The file `record` is written: its image segment is no longer its image. A cached one is
    /// purged; an active one detached, so the file's next image section reads the file again, and
    /// the segment is deleted, not cached, with its last reference.
    pub fn forget_image(record: crate::fs::file::FileRecordId) {
        flush_image(record, true);
    }

    fn flush_image(record: crate::fs::file::FileRecordId, detach: bool) {
        let Some(segment) = crate::fs::file::with_records(|records| records.get(record).image)
        else {
            return;
        };
        let purged = ob::locked(|directory| {
            let cached = directory.segment_cached(segment);
            (cached || detach).then(|| directory.purge_segment(segment))
        });
        let Some(followup) = purged else {
            return;
        };
        // The file's next image section makes a segment of its own.
        crate::fs::file::with_records(|records| {
            let record = records.get_mut(record);
            if record.image == Some(segment) {
                record.image = None;
            }
        });
        if let Some(followup) = followup {
            ob::finish(followup);
        }
    }

    /// Purge every cached image segment (at quiescence, before the leak sweep: a cached segment is
    /// no leak).
    pub fn purge_image_cache() {
        while let Some(followup) = ob::locked(ob::Directory::purge_next_cached) {
            ob::finish(followup);
        }
    }

    /// The record of the file a section's or a segment's file object opens: a disk file's, as
    /// [`file_of`] refuses any other device's.
    pub fn mapped_record(object: &crate::fs::file::FileObject) -> crate::fs::file::FileRecordId {
        object.disk().expect("a mapped file is a disk file")
    }

    /// The file object a handle names, referenced for the caller's use (Windows 2000's
    /// ObReferenceObjectByHandle: another thread closing the handle meanwhile leaves the object,
    /// and its file's record, in place), with its file as its record holds it now and the access
    /// the handle was granted (the handle's, as Windows 2000's NtCreateSection references the file
    /// for the access the section needs: a duplicate made with less access than its open maps
    /// less). STATUS_INVALID_HANDLE for a handle naming nothing (a console
    /// handle included, or one closed before the reference), STATUS_OBJECT_TYPE_MISMATCH for one
    /// naming another kind, STATUS_INVALID_FILE_FOR_SECTION for a file object of a device other
    /// than the disk.
    fn file_of(
        handle: u32,
    ) -> Result<(ob::ObRef, crate::fs::fat32::lookup::File, Backing), NtStatus> {
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let entry = calling_process()
            .lookup_handle(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::File {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        let access = crate::fs::file::rights::share_access(id.kind.granted(entry.access));
        let held = ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?;
        let record = ob::locked(|directory| directory.file(id).map(|object| object.disk()))
            .ok_or(STATUS_INVALID_HANDLE)?;
        // Only a disk file is mapped: another device's file object has no pages to map (Windows
        // 2000's answer for a file object without section pointers).
        let record = record.ok_or(STATUS_INVALID_FILE_FOR_SECTION)?;
        let file = crate::fs::io::file_at(record);
        let backing = Backing {
            size: file.size,
            directory: file.directory,
            read: access & crate::fs::file::ACCESS_READ != 0,
            write: access & crate::fs::file::ACCESS_WRITE != 0,
        };
        Ok((held, file, backing))
    }

    /// NtCreateSection (see [`plan`]): a section of the file the handle names, or of the paging
    /// file (no handle), named or not (see `sync`'s create). A file's data section holds its file
    /// object, and the file counts it as mapped: the file stays open while the section lives,
    /// and cannot be truncated nor deleted meanwhile. The section's deletion gives both back.
    /// Its frames are made as views need them. An image section holds its file's image segment
    /// instead (see [`create_image_section`]).
    #[allow(clippy::too_many_arguments)]
    pub fn create_section(
        call: &mut NtCall,
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
            backing.as_ref().map(|&(_, _, backing)| backing),
        )?;
        // The file object stays referenced to the end of the call (`backing` holds it): its
        // handle's closing meanwhile, on another thread, leaves it and its record in place.
        let section = match &backing {
            None => ob::SectionObject {
                size: plan.size,
                writable: plan.writable,
                reserve: allocation & SEC_RESERVE != 0,
                ..ob::SectionObject::none()
            },
            Some((held, file, _)) if allocation & SEC_IMAGE != 0 => {
                return create_image_section(
                    call.passive(),
                    slot,
                    access,
                    attributes,
                    held.id(),
                    file,
                );
            }
            Some((held, file, _)) => ob::SectionObject {
                file: *file,
                paging_file: false,
                reserve: false,
                frames: crate::mem::vm::SectionFrames::empty(),
                size: plan.size,
                writable: plan.writable,
                file_object: Some(held.id()),
                image_base: 0,
                segment: None,
            },
        };
        sync::create(
            call.passive(),
            slot,
            access,
            attributes,
            ObjectType::Section,
            |directory| {
                let id = directory.create_section(section)?;
                if let Some(file_object) = section.file_object {
                    let held = directory.reference(file_object);
                    debug_assert!(held, "the handle's file object lives");
                    let record = mapped_record(directory.file(file_object).expect("held"));
                    crate::fs::file::with_records(|records| {
                        records.get_mut(record).user_mapped += 1
                    });
                }
                // A failed publication deletes the object, which gives the file back.
                Some(id)
            },
        )
    }

    /// NtCreateSection of an image (SEC_IMAGE): a section of the file's image segment — the one
    /// the file's record names, while it lives, or a new one, the image's layout read and parsed
    /// now (see [`image_layout`]). A new segment holds the file object the handle names, and the
    /// file counts it as mapped; the segment's last reference gives both back.
    fn create_image_section(
        passive: &mut crate::level::At<crate::level::Passive>,
        slot: UserPtr<u32>,
        access: u32,
        attributes: UserAddr,
        file_object: ObjectId,
        file: &crate::fs::fat32::lookup::File,
    ) -> NtResult {
        let record = mapped_record(
            ob::lock(passive)
                .file(file_object)
                .expect("the handle's file object lives"),
        );
        let segment_of = |directory: &mut ob::Directory| {
            let id = crate::fs::file::with_records(|records| records.get(record).image)?;
            directory
                .segment(id)
                .map(|segment| (id, segment.image_base, segment.size))
        };
        // A file's first image section reads and parses its headers, off the disk with the
        // directory released, and builds the image's header page from them; later ones take the
        // layout the segment holds.
        let found = segment_of(&mut ob::lock(passive));
        let (layout, header_page) = match found {
            Some((_, image_base, size)) => ((image_base, size), None),
            None => {
                let (layout, page) =
                    crate::process::threads::critical_region(|| read_image_start(file))?;
                (layout, Some(page))
            }
        };
        // What a section refused leaves (its new segment's frames and file), and the cached
        // segment purged to make room for a new one, finished once the directory is released.
        let mut left = None;
        let mut evicted = None;
        let result = sync::create(
            passive,
            slot,
            access,
            attributes,
            ObjectType::Section,
            |directory| {
                let segment = match segment_of(directory) {
                    Some((id, _, _)) => {
                        // A cached segment revives: the frames it parked and still owns come
                        // back off Standby, no page read again.
                        let cached = directory.segment_cached(id);
                        let held = directory.reference_segment(id);
                        debug_assert!(held, "the file's segment lives");
                        let record = directory.segment(id).expect("held");
                        if cached && record.parked {
                            let pages = record.pages();
                            record.frames.revive(&mut CurrentPages, pages);
                            record.parked = false;
                        }
                        id
                    }
                    None => {
                        let (image_base, size) = layout;
                        evicted = directory.make_room_for_segment();
                        let id = directory.create_segment(ob::ImageSegment::new(
                            file_object,
                            image_base,
                            size,
                        ))?;
                        // The header page is the segment's page 0 from the start, as Windows
                        // 2000's image control area's first prototype PTE is the page its
                        // creation read: every view and query takes the headers from it. Without
                        // a frame for it now, the first view builds it.
                        if let Some(page) = &header_page {
                            let _ = segment_frames(directory, id).image_frame(
                                &mut CurrentPages,
                                0,
                                |frame| {
                                    crate::mem::paging::write_frame(
                                        crate::mem::phys::PhysAddr::new(frame),
                                        0,
                                        page,
                                    );
                                },
                            );
                        }
                        let held = directory.reference(file_object);
                        debug_assert!(held, "the handle's file object lives");
                        crate::fs::file::with_records(|records| {
                            let record = records.get_mut(record);
                            record.user_mapped += 1;
                            record.image = Some(id);
                        });
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
                    left = directory.dereference_segment(segment);
                }
                // A failed publication deletes the section, which drops its hold on the segment.
                section
            },
        );
        for followup in [evicted, left].into_iter().flatten() {
            ob::finish(followup);
        }
        result
    }

    /// An image file's layout (see [`image_layout`]) and its header page as mapped (the image's
    /// page 0: its headers, and whatever part of a section the page holds), from its first page as
    /// the volume holds it. Only a section's bytes past that first page are read again.
    fn read_image_start(
        file: &crate::fs::fat32::lookup::File,
    ) -> Result<((u32, u32), [u8; PAGE as usize]), NtStatus> {
        let mut headers = [0u8; IMAGE_HEADERS];
        let length = IMAGE_HEADERS.min(file.size as usize);
        let headers = &mut headers[..length];
        if crate::fs::io::read_file_at(file, 0, headers).is_none() {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        let layout = image_layout(headers, file.size)?;
        let image = crate::exec::pe::Image::parse_headers(headers, file.size as usize)
            .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        let mut page = [0u8; PAGE as usize];
        let built = image.map_page(0, &mut page, |offset, out| {
            let end = offset as usize + out.len();
            match headers.get(offset as usize..end) {
                Some(read) => {
                    out.copy_from_slice(read);
                    true
                }
                None => crate::fs::io::read_file_at(file, offset, out).is_some(),
            }
        });
        if !built {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        Ok((layout, page))
    }

    /// The headers of the image segment `segment` (which the caller holds), of the file `file`:
    /// the segment's page 0 when it holds it — the header page, as an image's mapping and its
    /// query read the headers through its control area on Windows 2000 — else the file's first
    /// page read again. The page, and how many of its bytes are the headers' to parse (the file's
    /// first page, or the whole of a shorter file).
    fn segment_headers(
        segment: ob::SegmentId,
        file: &crate::fs::fat32::lookup::File,
    ) -> Result<([u8; PAGE as usize], usize), NtStatus> {
        let mut page = [0u8; PAGE as usize];
        let length = (file.size as usize).min(IMAGE_HEADERS);
        let held = ob::locked(|directory| {
            let frame = segment_frames(directory, segment).made(&CurrentPages, 0)?;
            crate::mem::paging::read_frame(crate::mem::phys::PhysAddr::new(frame), 0, &mut page);
            Some(())
        });
        if held.is_none() && crate::fs::io::read_file_at(file, 0, &mut page[..length]).is_none() {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        Ok((page, length))
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
    fn section_of(handle: u32) -> Result<(ob::ObRef, u32), NtStatus> {
        if is_console_handle(handle) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let entry = calling_process()
            .lookup_handle(handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let id = entry.object_id().ok_or(STATUS_INVALID_HANDLE)?;
        if id.kind != ObjectType::Section {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
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
        zero_bits: u32,
        _commit_size: u32,
        offset: UserPtr<u64>,
        size: UserPtr<u32>,
        inherit: u32,
        allocation: u32,
        protect: u32,
    ) -> NtResult {
        let placement = view_arguments(zero_bits, inherit, allocation, protect)?;
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
        let record = object.section();
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
            let mapped = with_process(call, process, |record| {
                map_image(record, &mut CurrentPages, segment)
            })?;
            base.write(mapped.base)?;
            size.write(record.size)?;
            return Ok(if mapped.at_base {
                STATUS_SUCCESS
            } else {
                STATUS_IMAGE_NOT_AT_BASE
            });
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
        let maximum = view_maximum(access, protect, record.writable);
        let mapped = with_process(call, process, |record| {
            map_view(
                record,
                &mut CurrentPages,
                object.id(),
                requested,
                placement,
                at as u32,
                bytes,
                protect,
                maximum,
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
    /// `requested`, or where `placement` puts it) in `process`'s address space, the live one, its
    /// allocation protection `protect` and its maximum `maximum` (see [`view_maximum`]). A
    /// file-backed section's pages are not read now: each page gets a prototype entry naming its
    /// section page index, and the fault path reads it from the file (see
    /// [`crate::mem::backing`]'s Section arm). A paging-file section's pages are made zeroed now,
    /// as the view maps, and shared through the section's frames. The address space is locked a
    /// step at a time: the reservation, each page's entry, the view's record.
    #[allow(clippy::too_many_arguments)]
    fn map_view(
        process: &crate::process::Process,
        table: &mut CurrentPages,
        object: ObjectId,
        requested: u32,
        placement: crate::mem::vm::Placement,
        offset: u32,
        bytes: u32,
        protect: u32,
        maximum: crate::mem::vm::Maximum,
    ) -> Result<u32, NtStatus> {
        if !process.with_space(|space| space.has_view_room()) {
            return Err(STATUS_NO_MEMORY);
        }
        let section = ob::locked(|directory| {
            *directory
                .section(object)
                .expect("the caller holds the section")
        });
        let pages = bytes.div_ceil(PAGE);
        let base = process
            .with_space(|space| {
                space.reserve_placed(
                    (requested != 0).then_some(requested),
                    placement,
                    pages * PAGE,
                    protect,
                    Kind::Mapped(maximum),
                )
            })
            .map_err(|error| match error {
                crate::mem::vm::VmError::InvalidAddress => STATUS_CONFLICTING_ADDRESSES,
                crate::mem::vm::VmError::InvalidParameter => STATUS_INVALID_PARAMETER_2,
                crate::mem::vm::VmError::NoMemory => STATUS_NO_MEMORY,
            })?;
        if section.paging_file {
            // The paging file's pages start zeroed: made now, shared through the section's frames
            // (a write through one view shows in the others).
            for page in 0..pages {
                let made = ob::locked(|directory| {
                    section_frames(directory, object).frame(table, offset / PAGE + page, |_| ())
                });
                let mapped = made.and_then(|frame| {
                    process.with_space(|space| {
                        space.map_shared(table, base + page * PAGE, frame, protect)
                    })
                });
                if mapped.is_err() {
                    let _ = process.with_space(|space| space.release(table, base));
                    return Err(STATUS_NO_MEMORY);
                }
            }
        } else {
            // A file's view: prototype entries, the pages faulted in from the file on first touch.
            for page in 0..pages {
                let index = offset / PAGE + page;
                let entry = crate::mem::pte::encode_backing(
                    crate::mem::pte::PROTOTYPE,
                    index << 12,
                    protect,
                );
                let mapped =
                    process.with_space(|space| space.map_soft(table, base + page * PAGE, entry));
                if mapped.is_err() {
                    let _ = process.with_space(|space| space.release(table, base));
                    return Err(STATUS_NO_MEMORY);
                }
            }
        }
        // The view holds its section for as long as it is mapped: the reference is taken before
        // the view is recorded, as from then on another thread may unmap it and drop it.
        let held = ob::locked(|directory| directory.reference(object));
        debug_assert!(held, "a section being mapped lives");
        keep_view(process, table, base, offset, ob::Mapping::Section(object))?;
        Ok(base)
    }

    /// Record the view just mapped at `base` from `offset` of `mapping`, whose reference the
    /// caller took for it (see [`crate::mem::vm::AddressSpace::record_view`]). The room checked
    /// before the mapping may have gone since, to another thread of the process: the view is
    /// released then, its reference dropped, STATUS_NO_MEMORY.
    fn keep_view(
        process: &crate::process::Process,
        table: &mut CurrentPages,
        base: u32,
        offset: u32,
        mapping: ob::Mapping,
    ) -> Result<(), NtStatus> {
        if process.with_space(|space| space.record_view(table, base, offset, mapping)) {
            return Ok(());
        }
        ob::release_mapping(mapping);
        Err(STATUS_NO_MEMORY)
    }

    /// The frames of the section `object` names, which the caller holds.
    fn section_frames(
        directory: &mut ob::Directory,
        object: ObjectId,
    ) -> &mut crate::mem::vm::SectionFrames {
        &mut directory
            .section(object)
            .expect("the caller holds the section")
            .frames
    }

    /// The frames of the image segment `segment` names, which the caller holds.
    fn segment_frames(
        directory: &mut ob::Directory,
        segment: ob::SegmentId,
    ) -> &mut crate::mem::vm::SectionFrames {
        &mut directory
            .segment(segment)
            .expect("the caller holds the segment")
            .frames
    }

    /// The image segment of the image section `handle` names, for a process's image
    /// (NtCreateProcess): the section referenced, and its segment. The handle's refusals (see
    /// [`section_of`]), one not granted SECTION_MAP_EXECUTE (see [`process_image_access`]), and a
    /// data section STATUS_SECTION_NOT_IMAGE.
    pub fn image_segment_of(handle: u32) -> Result<(ob::ObRef, ob::SegmentId), NtStatus> {
        let (object, access) = section_of(handle)?;
        process_image_access(access)?;
        let segment = object.section().segment.ok_or(STATUS_SECTION_NOT_IMAGE)?;
        Ok((object, segment))
    }

    /// Map the image segment `segment` names as a view: the whole image at its preferred base
    /// (STATUS_CONFLICTING_ADDRESSES when another region holds any of it), a MEM_IMAGE reservation
    /// whose pages carry their sections' protections, every page the segment's frame. A page not
    /// made yet is built from the file, through the image's section table (its headers parsed
    /// from the segment's header page: see [`segment_headers`]). The view holds the segment, not
    /// the section. Returns
    /// what a process made from the image records of it (see [`ImageView`]). The view is made in
    /// `process`'s address space, the live one, locked a step at a time as [`map_view`]'s is.
    pub fn map_image(
        process: &crate::process::Process,
        table: &mut CurrentPages,
        segment: ob::SegmentId,
    ) -> Result<ImageView, NtStatus> {
        use crate::exec::loader::page_protect;
        use crate::mem::vm::PAGE_EXECUTE_WRITECOPY;
        if !process.with_space(|space| space.has_view_room()) {
            return Err(STATUS_NO_MEMORY);
        }
        // The file as its record holds it now (the segment keeps it open).
        let record = ob::locked(|directory| {
            let file_object = directory
                .segment(segment)
                .expect("the caller holds the segment")
                .file_object;
            mapped_record(directory.file(file_object).expect("held"))
        });
        let file = crate::fs::io::file_at(record);
        // The image is a view of its header page, which stays as read while `buffer` builds the
        // pages.
        let (header_page, headers) = segment_headers(segment, &file)?;
        let mut buffer = [0u8; PAGE as usize];
        let image =
            crate::exec::pe::Image::parse_headers(&header_page[..headers], file.size as usize)
                .map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        // The preferred base, else anywhere the address space has room (Windows 2000's view of an
        // image whose base another region holds, STATUS_IMAGE_NOT_AT_BASE: the files fixture's
        // imagesec block maps the running program's own image so). The pages are the segment's
        // as they are: relocating the view is its mapper's work.
        let reserve = |at: Option<u32>| {
            process.with_space(|space| {
                space.reserve(
                    at,
                    image.size_of_image(),
                    PAGE_EXECUTE_WRITECOPY,
                    Kind::Image,
                )
            })
        };
        let base = reserve(Some(image.image_base()))
            .or_else(|error| match error {
                crate::mem::vm::VmError::InvalidAddress
                | crate::mem::vm::VmError::InvalidParameter => reserve(None),
                error => Err(error),
            })
            .map_err(|error| match error {
                crate::mem::vm::VmError::InvalidAddress
                | crate::mem::vm::VmError::InvalidParameter => STATUS_CONFLICTING_ADDRESSES,
                crate::mem::vm::VmError::NoMemory => STATUS_NO_MEMORY,
            })?;
        for page in 0..image.size_of_image().div_ceil(PAGE) {
            let rva = page * PAGE;
            // The segment's frames inside the directory's hold, the file read with it released
            // (see `map_view`).
            let made = ob::locked(|directory| segment_frames(directory, segment).made(table, page));
            // A page not yet made is built first: a read that fails maps nothing.
            if made.is_none()
                && !image.map_page(rva, &mut buffer, |offset, out| {
                    crate::fs::io::read_file_at(&file, offset, out).is_some()
                })
            {
                let _ = process.with_space(|space| space.release(table, base));
                return Err(STATUS_IO_DEVICE_ERROR);
            }
            let frame = match made {
                Some(frame) => Ok(frame),
                None => ob::locked(|directory| {
                    segment_frames(directory, segment).image_frame(table, page, |frame| {
                        crate::mem::paging::write_frame(
                            crate::mem::phys::PhysAddr::new(frame),
                            0,
                            &buffer,
                        );
                    })
                }),
            };
            let mapped = frame.and_then(|frame| {
                process.with_space(|space| {
                    space.map_shared(table, base + rva, frame, page_protect(&image, rva))
                })
            });
            if mapped.is_err() {
                let _ = process.with_space(|space| space.release(table, base));
                return Err(STATUS_NO_MEMORY);
            }
        }
        // The view holds the segment for as long as it is mapped (taken before the view is
        // recorded: see `map_view`).
        let held = ob::locked(|directory| directory.reference_segment(segment));
        debug_assert!(held, "a segment being mapped lives");
        keep_view(process, table, base, 0, ob::Mapping::Image(segment))?;
        Ok(ImageView {
            base,
            at_base: base == image.image_base(),
            subsystem: image.subsystem(),
            subsystem_version: image.subsystem_version(),
        })
    }

    /// An image's view, as a process made from it records it in its PEB: the view's base (the
    /// image's preferred base, unless another region held it), the image's subsystem and the
    /// subsystem version it was linked for.
    #[derive(Clone, Copy, Debug)]
    pub struct ImageView {
        pub base: u32,
        /// Whether the view is at the image's preferred base.
        pub at_base: bool,
        pub subsystem: u16,
        pub subsystem_version: (u16, u16),
    }

    /// NtUnmapViewOfSection: unmap the view holding the address — any address inside it names it,
    /// as on Windows 2000 — (a section, or an image segment, nothing names any more goes with its
    /// last view). A write-maximum view of a file-backed section writes its touched pages back to
    /// the file first (see [`write_back_pages`]). STATUS_NOT_MAPPED_VIEW for an address no view
    /// holds.
    pub fn unmap_view_of_section(
        call: &mut NtCall,
        process: Handle,
        address: UserAddr,
    ) -> NtResult {
        let (view, region) = with_space(call, process, |space, _pages| {
            // A data view, or an image section's (the image and the system DLLs, mapped by the
            // kernel itself, are no views).
            let region = space
                .region_at(address.raw())
                .filter(|region| matches!(region.kind, Kind::Mapped(_) | Kind::Image))
                .ok_or(STATUS_NOT_MAPPED_VIEW)?;
            let view = space.take_view(region.base).ok_or(STATUS_NOT_MAPPED_VIEW)?;
            Ok((view, region))
        })?;
        // The view's pages go back to the file before its frames are dropped (a write-maximum
        // view of a file-backed section); the address space's lock is not held across the file's
        // I/O.
        write_back_view(&view, &region)?;
        with_space(call, process, |space, pages| {
            let _ = space.release(pages, view.base);
            Ok(())
        })?;
        // The view's reference goes; a section or segment nothing else references goes with it.
        ob::release_mapping(view.mapping);
        Ok(STATUS_SUCCESS)
    }

    /// Write a view's present pages back to its section's file, when the view may write its
    /// section (a [`crate::mem::vm::Maximum::Write`] view of a file-backed data section): each
    /// present page of the view's region is read from its frame and written at the page's file
    /// offset. Nothing for a paging-file section (its pages live in the store), a read or
    /// copy-on-write view (their writes never reached the section's frames), or an image.
    fn write_back_view(
        view: &crate::mem::vm::View,
        region: &crate::mem::vm::Region,
    ) -> Result<(), NtStatus> {
        use crate::mem::vm::Maximum;
        if !matches!(region.kind, Kind::Mapped(Maximum::Write)) {
            return Ok(());
        }
        let crate::ob::Mapping::Section(object) = view.mapping else {
            return Ok(());
        };
        let (paging_file, file, size, file_object) = ob::locked(|directory| {
            let section = directory
                .section(object)
                .expect("the caller holds the section");
            (
                section.paging_file,
                section.file,
                section.size,
                section.file_object,
            )
        });
        if paging_file {
            return Ok(());
        }
        let record = file_object.and_then(|object| {
            ob::locked(|directory| directory.file(object).and_then(|file| file.disk()))
        });
        let mut file = match record {
            Some(record) => {
                // The file is written: its image, cached or mapped, is no longer what it holds.
                forget_image(record);
                crate::fs::io::file_at(record)
            }
            None => file,
        };
        let ok = write_back_pages(
            &CurrentPages,
            region.base,
            region.base + region.size,
            view.offset,
            size,
            &mut |frame, out| {
                if out.len() != PAGE as usize {
                    return false;
                }
                crate::mem::paging::read_frame(crate::mem::phys::PhysAddr::new(frame), 0, out);
                true
            },
            &mut |offset, bytes| {
                crate::fs::fat32::volume::with_boot_volume(|volume| {
                    crate::fs::fat32::write::write_at(volume, &mut file, offset, bytes)
                })
                .map(|result| result.is_ok())
                .unwrap_or(false)
            },
        );
        if !ok {
            return Err(STATUS_IO_DEVICE_ERROR);
        }
        // The file as the writes left it goes back to its record and the section's copy.
        if let Some(record) = record {
            crate::fs::io::store_file(record, file);
        }
        ob::locked(|directory| {
            if let Some(section) = directory.section(object) {
                section.file = file;
            }
        });
        Ok(())
    }

    /// NtQuerySection(SectionHandle, Class, Information, Length, ResultLength): a section's basic
    /// information (see [`SectionBasicInformation::of`]), or an image section's image information,
    /// read from its image's headers (see [`image_information`]): the segment's header page (see
    /// [`segment_headers`]), inside a critical region. The class
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
        let (class, size) = query_size(class, length)?;
        information.probe(size)?;
        result_length.addr().probe(4)?;
        let (object, access) = section_of(section.raw())?;
        query_access(access)?;
        let record = object.section();
        match class {
            SectionClass::Basic => {
                let kind = if record.segment.is_some() {
                    SectionKind::Image
                } else if record.file_object.is_some() {
                    SectionKind::File
                } else {
                    SectionKind::PagingFile {
                        reserve: record.reserve,
                    }
                };
                information
                    .cast()
                    .write(SectionBasicInformation::of(kind, record.size))?;
            }
            SectionClass::Image => {
                let segment = record.segment.ok_or(STATUS_SECTION_NOT_IMAGE)?;
                let file_record = ob::locked(|directory| {
                    let file_object = directory
                        .segment(segment)
                        .expect("an image section holds its segment")
                        .file_object;
                    mapped_record(
                        directory
                            .file(file_object)
                            .expect("an image segment holds its file object"),
                    )
                });
                let file = crate::fs::io::file_at(file_record);
                let info = crate::process::threads::critical_region(|| {
                    let (page, length) = segment_headers(segment, &file)?;
                    image_information(&page[..length], file.size)
                })?;
                information.cast().write(info)?;
            }
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
    pub fn release_frames(_frames: crate::mem::vm::SectionFrames, _parked: Option<u32>) {}

    /// A segment's caching: the host has no frames to park.
    pub fn park_segment(_segment: crate::ob::SegmentId) {}

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

    fn error<T: core::fmt::Debug>(result: Result<T, NtStatus>) -> u32 {
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
        assert_eq!(info.transfer_address, 0x0040_0000 + image.entry_rva());
        assert_eq!(
            (info.maximum_stack_size, info.committed_stack_size),
            (header(optional + 72), header(optional + 76))
        );
        assert_eq!(info.subsystem_type, 3, "a console image");
        assert_eq!(
            (info.subsystem_major_version, info.subsystem_minor_version),
            image.subsystem_version()
        );
        assert_eq!(info.machine, 0x14C);
        assert_eq!(info.image_characteristics, image.characteristics());
        assert_eq!(info.image_contains_code, 1);
        assert_eq!(
            (info.zero_bits, info.gp_value, info.reserved),
            (0, 0, [0, 0])
        );
        let bytes = info.as_bytes();
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
        let bytes = image.as_bytes();
        assert_eq!(&bytes[..4], &0u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &(SEC_IMAGE | SEC_FILE).to_le_bytes());
        assert_eq!(&bytes[8..16], &0x3000u64.to_le_bytes());
    }

    /// NtQuerySection's classes and lengths, and its access: SECTION_QUERY, or a generic right
    /// that maps to it.
    #[test]
    fn the_query_rules() {
        assert_eq!(query_size(0, 16), Ok((SectionClass::Basic, 16)));
        assert_eq!(query_size(1, 0x30), Ok((SectionClass::Image, 0x30)));
        assert_eq!(query_size(1, 0x40), Ok((SectionClass::Image, 0x30)));
        assert_eq!(query_size(1, 0x2C), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(query_size(2, 0x100), Err(STATUS_INVALID_INFO_CLASS));
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
            Err(STATUS_CONFLICTING_ADDRESSES)
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
        assert_eq!(error(view_arguments(0, 0, 0, PAGE_READONLY)), 87);
        assert_eq!(
            error(view_arguments(0, VIEW_SHARE, 0x1000, PAGE_READONLY)),
            87
        );
        assert_eq!(error(view_arguments(0, VIEW_SHARE, 0, 0x40)), 87);
        assert_eq!(
            view_arguments(0, VIEW_UNMAP, MEM_TOP_DOWN, PAGE_NOACCESS),
            Ok(crate::mem::vm::Placement {
                end: crate::mem::vm::USER_HIGH,
                top_down: true
            })
        );
        assert_eq!(
            view_arguments(3, VIEW_SHARE, 0, PAGE_READONLY),
            Ok(crate::mem::vm::Placement {
                end: 0x2000_0000,
                top_down: false
            }),
            "the zero bits' limit"
        );
        assert_eq!(
            view_arguments(22, VIEW_SHARE, 0, PAGE_READONLY),
            Err(STATUS_INVALID_PARAMETER_4)
        );
    }

    /// A view's maximum: a read-write section's frames are its to write only through a handle
    /// granted SECTION_MAP_WRITE (its generic rights mapped), and only when it is not mapped
    /// copy-on-write; a read-only or copy-on-write section's views never write them.
    #[test]
    fn a_views_maximum_is_its_sections_and_its_handles() {
        use crate::mem::vm::Maximum;
        let read = SECTION_QUERY | SECTION_MAP_READ;
        let write = read | SECTION_MAP_WRITE;
        assert_eq!(view_maximum(write, PAGE_READWRITE, true), Maximum::Write);
        assert_eq!(view_maximum(write, PAGE_READONLY, true), Maximum::Write);
        assert_eq!(
            view_maximum(GENERIC_WRITE, PAGE_READONLY, true),
            Maximum::Write
        );
        assert_eq!(
            view_maximum(write, PAGE_WRITECOPY, true),
            Maximum::CopyOnWrite
        );
        assert_eq!(view_maximum(read, PAGE_READONLY, true), Maximum::Read);
        assert_eq!(view_maximum(read, PAGE_WRITECOPY, true), Maximum::Read);
        assert_eq!(
            view_maximum(GENERIC_READ, PAGE_READONLY, true),
            Maximum::Read
        );
        assert_eq!(
            view_maximum(crate::ob::SECTION_ALL_ACCESS, PAGE_READONLY, false),
            Maximum::Read
        );
        assert_eq!(view_maximum(write, PAGE_WRITECOPY, false), Maximum::Read);
        assert!(!Maximum::Read.allows(PAGE_READWRITE));
        assert!(Maximum::Read.allows(PAGE_WRITECOPY) && Maximum::Read.allows(PAGE_NOACCESS));
        assert!(Maximum::CopyOnWrite.allows(PAGE_READWRITE));
        assert!(!Maximum::Write.allows(PAGE_EXECUTE_READ));
        assert!(!Maximum::Write.allows(PAGE_EXECUTE_WRITECOPY));
    }

    /// Page tables as a map, for the write-back pass's reads: the entries only.
    #[derive(Default)]
    struct FakePages {
        entries: std::collections::HashMap<u32, u32>,
    }

    impl crate::mem::vm::Pages for FakePages {
        fn entry(&self, va: u32) -> u32 {
            *self.entries.get(&va).unwrap_or(&0)
        }

        fn set_entry(&mut self, va: u32, entry: u32) {
            self.entries.insert(va, entry);
        }

        fn zeroed_frame(&mut self) -> Option<u32> {
            None
        }

        fn free_frame(&mut self, _frame: u32) {}

        fn share_frame(&mut self, _frame: u32) {}

        fn frame_shared(&self, _frame: u32) -> bool {
            false
        }

        fn copy_frame(&mut self, _from: u32, _to: u32) {}

        fn frame_word(&self, _frame: u32, _index: u32) -> u32 {
            0
        }

        fn set_frame_word(&mut self, _frame: u32, _index: u32, _value: u32) {}
    }

    /// A section page's file offset, and how many bytes of a section's size its page holds: a
    /// whole page inside the section, a partial one at its end, none past it.
    #[test]
    fn section_page_offsets_and_spans() {
        use crate::mem::vm::PAGE;
        assert_eq!(page_file_offset(0), 0);
        assert_eq!(page_file_offset(3), 3 * PAGE);
        assert_eq!(page_span_len(0x10_0000, 0), PAGE as usize);
        assert_eq!(page_span_len(0x10_0000, 15), PAGE as usize);
        assert_eq!(
            page_span_len(0x10_800, 16),
            0x800,
            "the section's last partial page"
        );
        assert_eq!(page_span_len(0x10_800, 17), 0, "past the section's end");
        assert_eq!(page_span_len(0, 0), 0);
    }

    /// A view's page at an address: its section page index and file offset, with the view's own
    /// offset added; none for an address outside the view or off a page boundary of the section.
    #[test]
    fn a_views_page_offset_arithmetic() {
        use crate::mem::vm::PAGE;
        let base = 0x40_0000;
        let view_offset = 0x2000;
        assert_eq!(view_page(view_offset, base, base), Some((2, 0x2000)));
        assert_eq!(view_page(view_offset, base, base + PAGE), Some((3, 0x3000)));
        assert_eq!(
            view_page(0, base, base + 0x10),
            None,
            "not page-aligned in the section"
        );
        assert_eq!(
            view_page(view_offset, base, base - PAGE),
            None,
            "below the view"
        );
        assert_eq!(
            view_page(0x1001, base, base),
            None,
            "the view's offset is off-page"
        );
    }

    /// The write-back of one page at unmap: the file offset and the byte count, clamped to the
    /// section's size; none past its end.
    #[test]
    fn the_write_back_span_is_clamped_to_the_section() {
        use crate::mem::vm::PAGE;
        let base = 0x40_0000;
        assert_eq!(
            write_back_span(0, base, base + 2 * PAGE, 0x10_0000),
            Some((2 * PAGE, PAGE as usize))
        );
        assert_eq!(
            write_back_span(0, base, base + 16 * PAGE, 0x10_800),
            Some((0x10_000, 0x800)),
            "the section's last partial page"
        );
        assert_eq!(
            write_back_span(0, base, base + 17 * PAGE, 0x10_800),
            None,
            "past the section's end"
        );
        // With a view offset, the page at the view's base writes at the offset's page.
        assert_eq!(
            write_back_span(0x4000, base, base, 0x10_0000),
            Some((0x4000, PAGE as usize))
        );
    }

    /// A section page read from the file's bytes: the file's bytes at the page's offset, zero past
    /// its end, a whole zero page past the file entirely.
    #[test]
    fn a_section_page_reads_from_the_files_bytes() {
        let mut file = vec![0u8; 0x1800];
        for (index, byte) in file.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let mut buf = [0xFFu8; 0x1000];
        read_section_page(&file, 1, &mut buf);
        assert_eq!(&buf[..0x800], &file[0x1000..0x1800], "the page's bytes");
        assert!(
            buf[0x800..].iter().all(|&byte| byte == 0),
            "zero past the file's end"
        );
        read_section_page(&file, 5, &mut buf);
        assert!(
            buf.iter().all(|&byte| byte == 0),
            "a page past the file entirely"
        );
    }

    /// The write-back pass over a view: every present page of the region is read from its frame
    /// and written at its file offset (clamped to the section's size), pages without a present
    /// entry are skipped, and a failed read or write fails the pass.
    #[test]
    fn the_write_back_pass_writes_each_present_page_at_its_offset() {
        use crate::mem::vm::{encode, PAGE, PAGE_READWRITE};
        let base = 0x40_0000;
        let section_size = 0x2800; // two pages and a half
        let mut pages = FakePages::default();
        // Page 0 present on frame 0x10_0000, page 1 not present, page 2 present on 0x12_0000.
        pages
            .entries
            .insert(base, encode(0x10_0000, PAGE_READWRITE));
        pages
            .entries
            .insert(base + 2 * PAGE, encode(0x12_0000, PAGE_READWRITE));

        // Each frame's page holds its frame number as the first byte; the writes record the
        // offset, the length and the first byte.
        let mut reads = Vec::new();
        let mut writes: Vec<(u32, usize, u8)> = Vec::new();
        let ok = write_back_pages(
            &pages,
            base,
            base + 3 * PAGE,
            0,
            section_size,
            &mut |frame, out| {
                reads.push(frame);
                out.fill(0);
                out[0] = (frame >> 16) as u8;
                true
            },
            &mut |offset, bytes| {
                writes.push((offset, bytes.len(), bytes[0]));
                true
            },
        );
        assert!(ok);
        assert_eq!(
            reads,
            vec![0x10_0000, 0x12_0000],
            "only the present pages, in order"
        );
        assert_eq!(
            writes,
            vec![(0, PAGE as usize, 0x10), (2 * PAGE, 0x800, 0x12)],
            "page 2 writes only the section's remaining 0x800 bytes"
        );

        // A view offset shifts the file offsets; a read or write failure fails the pass.
        let mut writes = Vec::new();
        assert!(write_back_pages(
            &pages,
            base,
            base + PAGE,
            0x4000,
            0x10_0000,
            &mut |_, out| {
                out.fill(7);
                true
            },
            &mut |offset, bytes| {
                writes.push((offset, bytes.len()));
                true
            },
        ));
        assert_eq!(writes, vec![(0x4000, PAGE as usize)]);
        assert!(!write_back_pages(
            &pages,
            base,
            base + PAGE,
            0,
            0x10_0000,
            &mut |_, _| false,
            &mut |_, _| true,
        ));
        assert!(!write_back_pages(
            &pages,
            base,
            base + PAGE,
            0,
            0x10_0000,
            &mut |_, out| {
                out.fill(0);
                true
            },
            &mut |_, _| false,
        ));
    }
}
