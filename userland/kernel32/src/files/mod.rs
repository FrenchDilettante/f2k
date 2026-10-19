//! The file API: kernel32's own code over ntdll's file services, as on Windows 2000. The narrow
//! calls convert their names through the ANSI code page into a buffer of MAX_PATH + 1 units
//! (Windows 2000's kernel32 converts into the thread's static Unicode string, of that size: a
//! longer name is ERROR_FILENAME_EXCED_RANGE); ntdll makes the NT path of the DOS one
//! (RtlDosPathNameToNtPathName_U, which fails for a name it cannot make: ERROR_PATH_NOT_FOUND), a
//! relative path under the current directory coming back relative to its handle; and a failed
//! service's status sets the last error through BaseSetLastNTError, but where Windows 2000's kernel32
//! sets its own.
//!
//! [`handle`] holds the calls on a file handle (CreateFileA, ReadFile, WriteFile, SetFilePointer and
//! the rest), [`names`] those on a name (attributes, deletes, renames, directories, the full and
//! short names), [`copy`] CopyFileA's loop, [`find`] the directory searches and [`volume`] the
//! volume's.

pub mod copy;
pub mod find;
pub mod handle;
pub mod names;
pub mod volume;

use rtl::cp1252;

use crate::base::{process_heap, set_last_error, SecurityAttributes, OBJ_INHERIT};
use crate::nt::{self, IoStatus, ObjectAttributes, RelativeName, UnicodeString};

/// The ANSI path limit, terminator included.
pub const MAX_PATH: usize = 260;

pub const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

/// The Win32 errors the file calls set themselves.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_BAD_LENGTH: u32 = 24;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INVALID_NAME: u32 = 123;
pub const ERROR_NEGATIVE_SEEK: u32 = 131;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// The statuses the file calls tell apart.
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;

/// The file access rights and the generic ones the calls ask for.
pub const FILE_LIST_DIRECTORY: u32 = 0x0001;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const DELETE: u32 = 0x0001_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

/// The share modes.
pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const FILE_SHARE_DELETE: u32 = 0x4;
pub const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// The create options.
pub const FILE_DIRECTORY_FILE: u32 = 0x1;
pub const FILE_WRITE_THROUGH: u32 = 0x2;
pub const FILE_SEQUENTIAL_ONLY: u32 = 0x4;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
pub const FILE_RANDOM_ACCESS: u32 = 0x800;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x4000;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x20_0000;
pub const FILE_OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x80_0000;

/// The dispositions, and what an open did (the I/O status's Information).
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE_IF: u32 = 5;
pub const FILE_OPENED: u32 = 1;
pub const FILE_OVERWRITTEN: u32 = 3;

/// The information classes the calls ask.
pub const FILE_BASIC_INFORMATION: u32 = 4;
pub const FILE_STANDARD_INFORMATION: u32 = 5;
pub const FILE_RENAME_INFORMATION: u32 = 10;
pub const FILE_DISPOSITION_INFORMATION: u32 = 13;
pub const FILE_POSITION_INFORMATION: u32 = 14;
pub const FILE_ALL_INFORMATION: u32 = 18;
pub const FILE_ALLOCATION_INFORMATION: u32 = 19;
pub const FILE_END_OF_FILE_INFORMATION: u32 = 20;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
pub const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;

/// OBJECT_ATTRIBUTES' OBJ_CASE_INSENSITIVE.
pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// A name in UTF-16, NUL-terminated, as the W forms take it: Basep8BitStringToStaticUnicodeString's
/// buffer.
pub struct Wide {
    pub units: [u16; MAX_PATH + 1],
    pub length: usize,
}

impl Wide {
    /// The name with its terminator.
    pub fn terminated(&self) -> &[u16] {
        &self.units[..self.length + 1]
    }

    /// The name.
    pub fn text(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// A wide name copied from `units` (a W call's own); none past MAX_PATH.
    pub fn of(units: &[u16]) -> Option<Wide> {
        if units.len() > MAX_PATH {
            return None;
        }
        let mut wide = Wide { units: [0; MAX_PATH + 1], length: units.len() };
        wide.units[..units.len()].copy_from_slice(units);
        Some(wide)
    }
}

/// An ANSI name into UTF-16; none (ERROR_FILENAME_EXCED_RANGE set) past MAX_PATH characters.
///
/// # Safety
///
/// `name` points at a NUL-terminated string (a bad pointer faults the caller, as on the platform).
pub unsafe fn widen(name: *const u8) -> Option<Wide> {
    let mut wide = Wide { units: [0; MAX_PATH + 1], length: 0 };
    loop {
        // SAFETY: the caller's string, read to its terminator.
        let byte = unsafe { name.add(wide.length).read() };
        if byte == 0 {
            return Some(wide);
        }
        if wide.length == MAX_PATH {
            set_last_error(ERROR_FILENAME_EXCED_RANGE);
            return None;
        }
        wide.units[wide.length] = cp1252::MB_TO_WC[byte as usize];
        wide.length += 1;
    }
}

/// UTF-16 units into an ANSI buffer of `size` bytes with its terminator, as the narrow calls hand
/// names back.
///
/// # Safety
///
/// `buffer` holds `size` bytes, and `size` exceeds `units`' length.
pub unsafe fn narrow_into(units: &[u16], buffer: *mut u8) {
    for (at, &unit) in units.iter().enumerate() {
        // SAFETY: the caller's buffer holds the name and its terminator.
        unsafe { buffer.add(at).write(cp1252::wc_to_mb(unit)) };
    }
    // SAFETY: as above.
    unsafe { buffer.add(units.len()).write(0) };
}

/// A DOS path's NT form, as ntdll made it (its buffer on the process heap, freed with it): the name
/// a service opens — relative to the current directory's handle when ntdll made one — and its
/// file part.
pub struct NtPath {
    /// The whole NT path.
    pub full: UnicodeString,
    /// The name an OBJECT_ATTRIBUTES carries: the relative name, or the whole path.
    pub name: UnicodeString,
    /// The directory the name is relative to (zero: none).
    pub root: u32,
    /// Where the last component starts, if the path has one (null otherwise).
    pub file_part: *mut u16,
}

impl NtPath {
    /// The NT path of a NUL-terminated DOS path (RtlDosPathNameToNtPathName_U); none when ntdll
    /// cannot make it.
    pub fn of(dos: &[u16]) -> Option<NtPath> {
        let empty = || UnicodeString { length: 0, maximum_length: 0, buffer: core::ptr::null_mut() };
        let mut full = empty();
        let mut file_part = core::ptr::null_mut();
        let mut relative = RelativeName { name: empty(), containing_directory: 0 };
        // SAFETY: ntdll's export, over a terminated string and the structures above.
        let made = unsafe { nt::RtlDosPathNameToNtPathName_U(dos.as_ptr(), &mut full, &mut file_part, &mut relative) };
        if made as u8 == 0 {
            return None;
        }
        let (name, root) = if relative.name.length != 0 {
            (relative.name, relative.containing_directory)
        } else {
            (UnicodeString { length: full.length, maximum_length: full.maximum_length, buffer: full.buffer }, 0)
        };
        Some(NtPath { full, name, root, file_part })
    }

    /// The OBJECT_ATTRIBUTES naming it, case-insensitively, inheritable when asked.
    pub fn attributes(&self, inherit: bool) -> ObjectAttributes {
        ObjectAttributes {
            length: 24,
            root_directory: self.root,
            object_name: &self.name,
            attributes: OBJ_CASE_INSENSITIVE | if inherit { OBJ_INHERIT } else { 0 },
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        }
    }

    /// The whole NT path's units.
    pub fn units(&self) -> &[u16] {
        // SAFETY: ntdll's buffer holds the path's length.
        unsafe { core::slice::from_raw_parts(self.full.buffer, self.full.length as usize / 2) }
    }
}

impl Drop for NtPath {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over its own block on the process heap.
        unsafe { nt::RtlFreeHeap(process_heap(), 0, self.full.buffer as *mut u8) };
    }
}

/// Whether a SECURITY_ATTRIBUTES asks for an inheritable handle.
///
/// # Safety
///
/// `security` is null or points at a SECURITY_ATTRIBUTES.
pub unsafe fn inherits(security: *const SecurityAttributes) -> bool {
    // SAFETY: the caller's structure, when given.
    unsafe { security.as_ref() }.is_some_and(|security| security.inherit_handle != 0)
}

/// Open `path` with `access`, `share` and `options` (NtOpenFile): the handle, or the status.
pub fn open(path: &NtPath, access: u32, share: u32, options: u32) -> Result<u32, u32> {
    let attributes = path.attributes(false);
    let mut handle = 0;
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, over the attributes above.
    let status = unsafe { nt::NtOpenFile(&mut handle, access, &attributes, &mut io_status, share, options) };
    if rtl::status::nt_success(status) {
        Ok(handle)
    } else {
        Err(status)
    }
}

/// Query `class` of an open file into `out` (NtQueryInformationFile): the status.
pub fn query(handle: u32, class: u32, out: &mut [u8]) -> u32 {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, into the buffer of its length.
    unsafe { nt::NtQueryInformationFile(handle, &mut io_status, out.as_mut_ptr(), out.len() as u32, class) }
}

/// Set `class` of an open file from `information` (NtSetInformationFile): the status.
pub fn set(handle: u32, class: u32, information: &[u8]) -> u32 {
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, from the buffer of its length.
    unsafe { nt::NtSetInformationFile(handle, &mut io_status, information.as_ptr(), information.len() as u32, class) }
}

/// Close a handle the call opened for itself.
pub fn close(handle: u32) {
    // SAFETY: ntdll's export.
    unsafe { nt::NtClose(handle) };
}

/// The dword at `at` of a structure.
pub fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The quadword at `at` of a structure.
pub fn quad(bytes: &[u8], at: usize) -> u64 {
    u64::from(word(bytes, at)) | u64::from(word(bytes, at + 4)) << 32
}

/// Write a dword where a pointer argument asks, when it does.
///
/// # Safety
///
/// `at` is null or points at a dword.
pub unsafe fn put(at: *mut u32, value: u32) {
    if !at.is_null() {
        // SAFETY: the caller's slot.
        unsafe { at.write_unaligned(value) };
    }
}

/// Write a FILETIME where a pointer argument asks, when it does.
///
/// # Safety
///
/// `at` is null or points at a FILETIME.
pub unsafe fn put_time(at: *mut u64, value: u64) {
    if !at.is_null() {
        // SAFETY: the caller's slot.
        unsafe { at.write_unaligned(value) };
    }
}
