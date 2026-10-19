//! File mappings: kernel32's own code over ntdll's section services, as on Windows 2000. A mapping
//! is a section of the paging file (INVALID_HANDLE_VALUE; a file's mapping is the kernel's to refuse
//! until the file objects), made or opened by name in `\BaseNamedObjects`; a view is mapped into
//! the calling process (NtCurrentProcess). A failed service's status sets the last error through
//! BaseSetLastNTError.
//!
//! Windows 2000 names its objects relative to the `\BaseNamedObjects` directory's handle
//! (BaseGetNamedObjectDirectory); until that directory object comes with the synchronization
//! services, the names are spelled absolutely (`\BaseNamedObjects\<name>`), which the object
//! manager resolves to the same place.

use rtl::cp1252;
use rtl::status::nt_success;

use crate::base::{set_last_error, set_last_nt_error, succeeded, SecurityAttributes, CURRENT_PROCESS};
use crate::nt::{self, ObjectAttributes, UnicodeString};

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// OBJECT_ATTRIBUTES' Attributes: OBJ_INHERIT, and OBJ_OPENIF (a create opens an existing object of
/// its name).
const OBJ_INHERIT: u32 = 0x2;
const OBJ_OPENIF: u32 = 0x80;

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

/// The ANSI path limit: an object name's longest, in characters.
const MAX_PATH: usize = 260;

/// The named objects' directory, which an absolute name starts with.
const NAMED_OBJECTS: &[u8] = b"\\BaseNamedObjects\\";

/// Room for an absolute object name: the directory's prefix and the longest name.
const NAME_UNITS: usize = NAMED_OBJECTS.len() + MAX_PATH + 1;

/// An ANSI object name into UTF-16 after the named objects' prefix in `out`: the whole name's length
/// in units, none for an empty name; ERROR_FILENAME_EXCED_RANGE past MAX_PATH characters.
///
/// # Safety
///
/// `name` points at a NUL-terminated string (a bad pointer faults the caller, as on the platform).
unsafe fn absolute_name(name: *const u8, out: &mut [u16; NAME_UNITS]) -> Result<usize, u32> {
    for (unit, &byte) in out.iter_mut().zip(NAMED_OBJECTS) {
        *unit = u16::from(byte);
    }
    let mut length = 0;
    loop {
        // SAFETY: the caller's string, read to its terminator.
        let byte = unsafe { name.add(length).read() };
        if byte == 0 {
            return Ok(NAMED_OBJECTS.len() + length);
        }
        if length == MAX_PATH {
            return Err(ERROR_FILENAME_EXCED_RANGE);
        }
        out[NAMED_OBJECTS.len() + length] = cp1252::MB_TO_WC[byte as usize];
        length += 1;
    }
}

/// A UNICODE_STRING over the first `length` units of `units`.
fn unicode_string(units: &mut [u16], length: usize) -> UnicodeString {
    UnicodeString {
        length: (2 * length) as u16,
        maximum_length: (2 * units.len()) as u16,
        buffer: units.as_mut_ptr(),
    }
}

/// The OBJECT_ATTRIBUTES a create passes (BaseFormatObjectAttributes): none with neither security
/// attributes nor a name; otherwise inheritable as the security attributes ask, and a name is
/// OBJ_OPENIF (an existing object of the name is opened).
///
/// # Safety
///
/// `security` is null or points at a SECURITY_ATTRIBUTES; `name` outlives the attributes' use.
unsafe fn format_object_attributes(
    out: &mut ObjectAttributes,
    security: *const SecurityAttributes,
    name: Option<&UnicodeString>,
) -> *const ObjectAttributes {
    if security.is_null() && name.is_none() {
        return core::ptr::null();
    }
    // SAFETY: the caller's structure, when given.
    let (mut attributes, descriptor) = match unsafe { security.as_ref() } {
        Some(security) => (
            if security.inherit_handle != 0 {
                OBJ_INHERIT
            } else {
                0
            },
            security.security_descriptor,
        ),
        None => (0, core::ptr::null()),
    };
    if name.is_some() {
        attributes |= OBJ_OPENIF;
    }
    *out = ObjectAttributes {
        length: 24,
        root_directory: 0,
        object_name: name.map_or(core::ptr::null(), |name| name as *const UnicodeString),
        attributes,
        security_descriptor: descriptor,
        security_quality_of_service: core::ptr::null(),
    };
    out
}

/// CreateFileMappingA: a section of the paging file (INVALID_HANDLE_VALUE, which needs a size) of
/// the size asked for, read-only, read-write or copy-on-write (another protection is
/// ERROR_INVALID_PARAMETER); or the named one already bound (ERROR_ALREADY_EXISTS). The last error
/// is cleared on success, as Windows clears it on every successful create. A file's handle goes to
/// the service, which refuses it until the file objects.
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
    let file = if file == INVALID_HANDLE_VALUE { 0 } else { file };
    let mut units = [0u16; NAME_UNITS];
    let mut string = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    let named = !name.is_null();
    if named {
        // SAFETY: the caller's string.
        match unsafe { absolute_name(name, &mut units) } {
            Ok(length) => string = unicode_string(&mut units, length),
            Err(error) => {
                set_last_error(error);
                return 0;
            }
        }
    }
    if !matches!(protect, PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)
        || file == 0 && maximum == 0
    {
        set_last_nt_error(STATUS_INVALID_PARAMETER);
        return 0;
    }
    let mut object_attributes = core::mem::MaybeUninit::<ObjectAttributes>::uninit();
    // SAFETY: the caller's security attributes; the name outlives the call.
    let object_attributes = unsafe {
        format_object_attributes(
            &mut *object_attributes.as_mut_ptr(),
            security,
            named.then_some(&string),
        )
    };
    let size = if maximum != 0 {
        &maximum as *const i64
    } else {
        core::ptr::null()
    };
    let mut handle = 0;
    // SAFETY: ntdll's export, over the values above.
    let status = unsafe {
        nt::NtCreateSection(
            &mut handle,
            access,
            object_attributes,
            size,
            protect,
            allocation,
            file,
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    set_last_error(if status == STATUS_OBJECT_NAME_EXISTS {
        ERROR_ALREADY_EXISTS
    } else {
        0
    });
    handle
}

/// OpenFileMappingA: the named mapping in `\BaseNamedObjects`, with the access asked for
/// (FILE_MAP_COPY asks to read) and inheritable when asked. ERROR_INVALID_PARAMETER without a name;
/// the status's error when it cannot be opened. The last error is left alone on success.
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
    let access = if access == FILE_MAP_COPY {
        FILE_MAP_READ
    } else {
        access
    };
    let mut units = [0u16; NAME_UNITS];
    // SAFETY: the caller's string, when given.
    let length = match (!name.is_null()).then(|| unsafe { absolute_name(name, &mut units) }) {
        // An empty name names nothing (an assumption, unverified against Windows 2000).
        None => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        Some(Ok(length)) if length == NAMED_OBJECTS.len() => {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        Some(Err(error)) => {
            set_last_error(error);
            return 0;
        }
        Some(Ok(length)) => length,
    };
    let string = unicode_string(&mut units, length);
    let attributes = ObjectAttributes {
        length: 24,
        root_directory: 0,
        object_name: &string,
        attributes: if inherit != 0 { OBJ_INHERIT } else { 0 },
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let mut handle = 0;
    // SAFETY: ntdll's export, over the attributes above.
    let status = unsafe { nt::NtOpenSection(&mut handle, access, &attributes) };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    handle
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
    let (mut base, mut size) = (0, bytes);
    let mut offset = (i64::from(offset_high) << 32) | i64::from(offset_low);
    // SAFETY: ntdll's export, over the in/out values above.
    let status = unsafe {
        nt::NtMapViewOfSection(
            section,
            CURRENT_PROCESS,
            &mut base,
            0,
            0,
            &mut offset,
            &mut size,
            VIEW_SHARE,
            0,
            protect,
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    base
}

/// UnmapViewOfFile: the view holding the address unmapped (the mapping goes with its last handle
/// and view).
#[unsafe(export_name = "f2k_export_UnmapViewOfFile")]
pub extern "system" fn unmap_view_of_file(base: usize) -> u32 {
    // SAFETY: ntdll's export.
    succeeded(unsafe { nt::NtUnmapViewOfSection(CURRENT_PROCESS, base) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::last_error;
    use crate::nt::host::{BASE, FAIL_NEXT, HANDLE, LAST_NAME, LAST_SECTION, LAST_VM};

    fn fail_next(status: u32) {
        FAIL_NEXT.with(|cell| cell.set(status));
    }

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The memory fixture's mapping block: a paging-file mapping of 1 MiB (the last error cleared),
    /// a named one made again (ERROR_ALREADY_EXISTS) in `\BaseNamedObjects`, a missing name
    /// (ERROR_FILE_NOT_FOUND).
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
        assert_eq!((root, name), (0, wide("\\BaseNamedObjects\\M")));
        fail_next(rtl::status::STATUS_OBJECT_NAME_NOT_FOUND);
        // SAFETY: a NUL-terminated name.
        assert_eq!(
            unsafe { open_file_mapping_a(FILE_MAP_READ, 0, c"missing".as_ptr().cast()) },
            0
        );
        assert_eq!(last_error(), 2);
        let (_, name) = LAST_NAME.with(|cell| cell.borrow_mut().take()).unwrap();
        assert_eq!(name, wide("\\BaseNamedObjects\\missing"));
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
        assert_eq!(map_view_of_file(HANDLE, FILE_MAP_READ, 0, 0x1000, 0x1000), 0);
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
