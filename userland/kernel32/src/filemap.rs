//! File mappings: kernel32's own code over ntdll's section services, as on Windows 2000. A mapping
//! is a section of a file (its handle) or of the paging file (INVALID_HANDLE_VALUE), made or opened
//! by name in `\BaseNamedObjects` as the
//! synchronization objects are (the shared create and open of [`crate::sync`], relative to the
//! directory's handle, BaseGetNamedObjectDirectory); a view is mapped into the calling process
//! (NtCurrentProcess). A failed service's status sets the last error through BaseSetLastNTError.

use crate::base::{set_last_nt_error, win32_bool, SecurityAttributes, CURRENT_PROCESS};
use crate::ntcall::{self, View};
use crate::sync;

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// The page protections a mapping and a view take.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;

/// The section attributes CreateFileMapping's protection may carry, and the default.
const SEC_FILE: u32 = 0x0080_0000;
const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_RESERVE: u32 = 0x0400_0000;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_NOCACHE: u32 = 0x1000_0000;

/// The access a mapping's handle is made with: STANDARD_RIGHTS_REQUIRED, SECTION_QUERY and
/// SECTION_MAP_READ, and SECTION_MAP_WRITE for a read-write mapping.
const MAPPING_ACCESS: u32 = 0x000F_0000 | 0x0001 | 0x0004;
const SECTION_MAP_WRITE: u32 = 0x0002;

/// The view access rights.
const FILE_MAP_COPY: u32 = 0x0001;
const FILE_MAP_WRITE: u32 = 0x0002;
const FILE_MAP_READ: u32 = 0x0004;

/// NtMapViewOfSection's ViewShare disposition.
const VIEW_SHARE: u32 = 1;

/// CreateFileMappingW: a section of the file (the size asked for, or the file's when none is) or of
/// the paging file (INVALID_HANDLE_VALUE, which needs a size), read-only, read-write or
/// copy-on-write (another protection is ERROR_INVALID_PARAMETER); or the named one already bound
/// (ERROR_ALREADY_EXISTS). The last error is cleared on success (see [`sync::create_w`]). The
/// file's rules are the section service's (an empty file ERROR_FILE_INVALID, one smaller than the
/// size asked ERROR_NOT_ENOUGH_MEMORY).
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES; `name` null or a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_CreateFileMappingW")]
pub unsafe extern "system" fn create_file_mapping_w(
    file: u32,
    security: *const SecurityAttributes,
    protect: u32,
    size_high: u32,
    size_low: u32,
    name: *const u16,
) -> u32 {
    let attributes = protect & (SEC_FILE | SEC_IMAGE | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE);
    let protect = protect ^ attributes;
    let allocation = if attributes == 0 {
        SEC_COMMIT
    } else {
        attributes
    };
    let access = MAPPING_ACCESS
        | if protect == PAGE_READWRITE {
            SECTION_MAP_WRITE
        } else {
            0
        };
    let maximum = (i64::from(size_high) << 32) | i64::from(size_low);
    let file = if file == INVALID_HANDLE_VALUE {
        0
    } else {
        file
    };
    // SAFETY: the caller's arguments.
    unsafe {
        sync::create_w(security, name, |object_attributes| {
            if !matches!(protect, PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)
                || file == 0 && maximum == 0
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let size = (maximum != 0).then_some(&maximum);
            ntcall::create_section(access, object_attributes, size, protect, allocation, file)
        })
    }
}

/// CreateFileMappingA: [`create_file_mapping_w`], the name converted (see [`sync::narrow`]).
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES; `name` null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_CreateFileMappingA")]
pub unsafe extern "system" fn create_file_mapping_a(
    file: u32,
    security: *const SecurityAttributes,
    protect: u32,
    size_high: u32,
    size_low: u32,
    name: *const u8,
) -> u32 {
    // SAFETY: the caller's arguments.
    unsafe {
        sync::narrow(name, |wide| {
            create_file_mapping_w(file, security, protect, size_high, size_low, wide)
        })
    }
}

/// OpenFileMappingW: the named mapping in `\BaseNamedObjects`, with the access asked for
/// (FILE_MAP_COPY asks to read) and inheritable when asked (see [`sync::open_w`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_OpenFileMappingW")]
pub unsafe extern "system" fn open_file_mapping_w(
    access: u32,
    inherit: u32,
    name: *const u16,
) -> u32 {
    let access = if access == FILE_MAP_COPY {
        FILE_MAP_READ
    } else {
        access
    };
    // SAFETY: the caller's string.
    unsafe { sync::open_w(access, inherit, name, ntcall::open_section) }
}

/// OpenFileMappingA: [`open_file_mapping_w`], the name converted (see [`sync::narrow`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_OpenFileMappingA")]
pub unsafe extern "system" fn open_file_mapping_a(
    access: u32,
    inherit: u32,
    name: *const u8,
) -> u32 {
    // SAFETY: the caller's string.
    unsafe { sync::narrow(name, |wide| open_file_mapping_w(access, inherit, wide)) }
}

/// MapViewOfFile: a view of `bytes` of the mapping (zero: to its end) from the offset, anywhere in
/// the process — copy-on-write for FILE_MAP_COPY alone, read-write for FILE_MAP_WRITE, read-only
/// for FILE_MAP_READ, no access otherwise; its base, or null with the status's error.
#[unsafe(export_name = "f2k_export_MapViewOfFile")]
pub extern "system" fn map_view_of_file(
    section: u32,
    access: u32,
    offset_high: u32,
    offset_low: u32,
    bytes: usize,
) -> usize {
    let protect = if access == FILE_MAP_COPY {
        PAGE_WRITECOPY
    } else if access & FILE_MAP_WRITE != 0 {
        PAGE_READWRITE
    } else if access & FILE_MAP_READ != 0 {
        PAGE_READONLY
    } else {
        PAGE_NOACCESS
    };
    let view = View {
        base: 0,
        size: bytes,
        offset: (i64::from(offset_high) << 32) | i64::from(offset_low),
        inherit: VIEW_SHARE,
        allocation: 0,
        protect,
    };
    ntcall::map_view_of_section(section, CURRENT_PROCESS, view).unwrap_or_else(|status| {
        set_last_nt_error(status);
        0
    })
}

/// UnmapViewOfFile: the view holding the address unmapped (the mapping goes with its last handle
/// and view).
#[unsafe(export_name = "f2k_export_UnmapViewOfFile")]
pub extern "system" fn unmap_view_of_file(base: usize) -> u32 {
    win32_bool(ntcall::unmap_view_of_section(CURRENT_PROCESS, base))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{last_error, set_last_error};
    use crate::nt::host::{BASE, DIRECTORY, FAIL_NEXT, HANDLE, LAST_NAME, LAST_SECTION, LAST_VM};

    fn fail_next(status: u32) {
        FAIL_NEXT.with(|cell| cell.set(status));
    }

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The memory fixture's mapping block: a paging-file mapping of 1 MiB (the last error cleared),
    /// a named one made again (ERROR_ALREADY_EXISTS) relative to `\BaseNamedObjects`'s handle, a
    /// missing name (ERROR_FILE_NOT_FOUND).
    #[test]
    fn mappings_are_named_sections() {
        set_last_error(99);
        // SAFETY: no security attributes, no name.
        assert_eq!(
            unsafe {
                create_file_mapping_a(
                    INVALID_HANDLE_VALUE,
                    core::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    0x10_0000,
                    core::ptr::null(),
                )
            },
            HANDLE
        );
        assert_eq!(last_error(), 0);
        let section = LAST_SECTION.with(|cell| cell.take());
        assert_eq!(
            section,
            Some((0x000F_0007, PAGE_READWRITE, SEC_COMMIT, 0, Some(0x10_0000)))
        );
        assert_eq!(LAST_NAME.with(|cell| cell.borrow_mut().take()), None);
        fail_next(rtl::status::STATUS_OBJECT_NAME_EXISTS);
        // SAFETY: a NUL-terminated name.
        assert_eq!(
            unsafe {
                create_file_mapping_a(
                    INVALID_HANDLE_VALUE,
                    core::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    0x1_0000,
                    c"M".as_ptr().cast(),
                )
            },
            HANDLE
        );
        assert_eq!(last_error(), 183);
        let (root, name) = LAST_NAME.with(|cell| cell.borrow_mut().take()).unwrap();
        assert_eq!((root, name), (DIRECTORY, wide("M")));
        fail_next(rtl::status::STATUS_OBJECT_NAME_NOT_FOUND);
        // SAFETY: a NUL-terminated name.
        assert_eq!(
            unsafe { open_file_mapping_a(FILE_MAP_READ, 0, c"missing".as_ptr().cast()) },
            0
        );
        assert_eq!(last_error(), 2);
        let (_, name) = LAST_NAME.with(|cell| cell.borrow_mut().take()).unwrap();
        assert_eq!(name, wide("missing"));
        // SAFETY: an empty name.
        assert_eq!(
            unsafe { open_file_mapping_a(FILE_MAP_READ, 0, c"".as_ptr().cast()) },
            0
        );
        assert_eq!(last_error(), 87);
    }

    /// The refusals made before the call: the paging file needs a size, the protection one of the
    /// three; the attributes pass through. A file's handle goes to the service.
    #[test]
    fn the_refusals_before_the_call() {
        // SAFETY: no security attributes, no name.
        assert_eq!(
            unsafe {
                create_file_mapping_a(
                    INVALID_HANDLE_VALUE,
                    core::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            0
        );
        assert_eq!(last_error(), 87, "the paging file needs a size");
        // SAFETY: as above.
        assert_eq!(
            unsafe {
                create_file_mapping_a(
                    INVALID_HANDLE_VALUE,
                    core::ptr::null(),
                    0x40,
                    0,
                    0x1000,
                    core::ptr::null(),
                )
            },
            0
        );
        assert_eq!(last_error(), 87, "PAGE_EXECUTE_READWRITE");
        assert!(
            LAST_SECTION.with(|cell| cell.take()).is_none(),
            "refused before the call"
        );
        fail_next(rtl::status::STATUS_NOT_IMPLEMENTED);
        // SAFETY: as above.
        assert_eq!(
            unsafe {
                create_file_mapping_a(
                    0x30,
                    core::ptr::null(),
                    PAGE_READONLY | SEC_RESERVE,
                    0,
                    0,
                    core::ptr::null(),
                )
            },
            0
        );
        assert_eq!(
            LAST_SECTION.with(|cell| cell.take()),
            Some((0x000F_0005, PAGE_READONLY, SEC_RESERVE, 0x30, None))
        );
    }

    /// Views: the access picks the protection, the offset passes as asked; the service's refusals
    /// set their errors (files/mapping's 1132 and 5, memory/mapping's 487).
    #[test]
    fn views_map_with_the_access_asked_for() {
        assert_eq!(
            map_view_of_file(HANDLE, FILE_MAP_WRITE, 0, 0x1_0000, 0x1000),
            BASE
        );
        assert_eq!(
            LAST_VM.with(|cell| cell.take()),
            Some((0x1_0000, 0x1000, PAGE_READWRITE))
        );
        assert_eq!(map_view_of_file(HANDLE, FILE_MAP_COPY, 0, 0, 0), BASE);
        assert_eq!(
            LAST_VM.with(|cell| cell.take()),
            Some((0, 0, PAGE_WRITECOPY))
        );
        assert_eq!(
            map_view_of_file(HANDLE, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0),
            BASE
        );
        assert_eq!(
            LAST_VM
                .with(|cell| cell.take())
                .map(|(_, _, protect)| protect),
            Some(PAGE_READONLY)
        );
        fail_next(0xC000_0220);
        assert_eq!(
            map_view_of_file(HANDLE, FILE_MAP_READ, 0, 0x1000, 0x1000),
            0
        );
        assert_eq!(last_error(), 1132, "STATUS_MAPPED_ALIGNMENT");
        fail_next(0xC000_0022);
        assert_eq!(map_view_of_file(HANDLE, FILE_MAP_WRITE, 0, 0, 0), 0);
        assert_eq!(last_error(), 5, "STATUS_ACCESS_DENIED");
        assert_eq!(unmap_view_of_file(BASE), 1);
        fail_next(0xC000_0019);
        assert_eq!(unmap_view_of_file(BASE), 0);
        assert_eq!(last_error(), 487, "STATUS_NOT_MAPPED_VIEW");
    }
}
