//! The file API: kernel32's own code over ntdll's file services, as on Windows 2000. Each call's
//! work is its W form's; the narrow calls convert their names through the ANSI code page (ntdll's
//! RtlAnsiStringToUnicodeString) into a buffer of MAX_PATH + 1 units (Windows 2000's kernel32
//! converts into the thread's static Unicode string, of that size: a longer name is
//! ERROR_FILENAME_EXCED_RANGE), the W calls copy theirs into the same ([`wide`]), and the names a
//! call hands back go to either kind of buffer ([`crate::edge::Text`], an A call's narrowed by
//! ntdll's RtlUnicodeToMultiByteN); ntdll makes the NT path of the DOS one
//! (RtlDosPathNameToNtPathName_U, which fails for a name it cannot make: ERROR_PATH_NOT_FOUND), a
//! relative path under the current directory coming back relative to its handle; and a failed
//! service's status sets the last error through BaseSetLastNTError, but where Windows 2000's
//! kernel32 sets its own.
//!
//! [`handle`] holds the calls on a file handle (CreateFileA, ReadFile, WriteFile, SetFilePointer
//! and the rest), [`names`] those on a name (attributes, deletes, renames, directories, the full
//! and short names), [`copy`] CopyFileA's loop, [`find`] the directory searches, [`search`]
//! SearchPath's look through a list of directories, and [`volume`] the volume's.

pub mod copy;
pub mod find;
pub mod handle;
pub mod names;
pub mod search;
pub mod volume;

use crate::base::{SecurityAttributes, OBJ_INHERIT};
use crate::edge::{ansi_into, wide_units, In, InStr, InWStr, Out};
use crate::error::Failure;
use crate::heap::HeapString;
use crate::nt::{ObjectAttributes, UnicodeString};
use crate::ntcall;

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
pub const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;

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
        let mut wide = Wide {
            units: [0; MAX_PATH + 1],
            length: units.len(),
        };
        wide.units[..units.len()].copy_from_slice(units);
        Some(wide)
    }
}

/// An A call's name converted into UTF-16 (ntdll's conversion, [`crate::edge::ansi_into`]; no
/// name is the empty one): ERROR_FILENAME_EXCED_RANGE past MAX_PATH characters.
pub fn widen(name: Option<&InStr<'_>>) -> Result<Wide, Failure> {
    let mut wide = Wide {
        units: [0; MAX_PATH + 1],
        length: 0,
    };
    wide.length =
        ansi_into(name, &mut wide.units).ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))?;
    Ok(wide)
}

/// A W call's name, copied into the buffer an A call's conversion fills. A W call does not convert:
/// a name past MAX_PATH reaches ntdll, whose DOS path conversion refuses it — ERROR_PATH_NOT_FOUND
/// here (the files capture: CreateFileW of a 300-character path), where an A call's conversion
/// refuses it with ERROR_FILENAME_EXCED_RANGE.
pub fn wide(name: &InWStr<'_>) -> Result<Wide, Failure> {
    let units = wide_units(name).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    Wide::of(&units).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))
}

/// Two names, each read and converted whatever the other's answer, in the order the call reads
/// them: both, or the failure of the one read last that failed (the last error the two leave).
pub fn both<A, B>(
    first: Result<A, Failure>,
    second: Result<B, Failure>,
) -> Result<(A, B), Failure> {
    match (first, second) {
        (Ok(first), Ok(second)) => Ok((first, second)),
        (_, Err(failure)) | (Err(failure), Ok(_)) => Err(failure),
    }
}

/// A DOS path's NT form, as ntdll made it (its buffer on the process heap, freed with it): the name
/// a service opens — relative to the current directory's handle when ntdll made one — and its
/// file part.
pub struct NtPath {
    /// The whole NT path.
    pub full: HeapString,
    /// The name an OBJECT_ATTRIBUTES carries: the relative name, or the whole path.
    pub name: UnicodeString,
    /// The directory the name is relative to (zero: none).
    pub root: u32,
    /// Where the last component starts in the whole path, in units, if the path has one.
    pub file_part: Option<usize>,
}

impl NtPath {
    /// The NT path of a NUL-terminated DOS path (RtlDosPathNameToNtPathName_U); none when ntdll
    /// cannot make it.
    pub fn of(dos: &[u16]) -> Option<NtPath> {
        let made = ntcall::dos_path_name_to_nt_path_name(dos)?;
        let (name, root) = if made.relative.name.length != 0 {
            (made.relative.name, made.relative.containing_directory)
        } else {
            (*made.full.string(), 0)
        };
        Some(NtPath {
            full: made.full,
            name,
            root,
            file_part: made.file_part,
        })
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
        self.full.units()
    }
}

/// Whether a SECURITY_ATTRIBUTES, when given, asks for an inheritable handle.
pub fn inherits(security: Option<In<'_, SecurityAttributes>>) -> bool {
    security.is_some_and(|security| security.read().inherit_handle != 0)
}

/// Open `path` with `access`, `share` and `options` (NtOpenFile): the handle, or the status.
pub fn open(path: &NtPath, access: u32, share: u32, options: u32) -> Result<u32, u32> {
    ntcall::open_file(access, &path.attributes(false), share, options)
}

/// A typed service's answer as the status the file calls test: STATUS_SUCCESS, or the failure.
fn as_status(result: Result<(), ntcall::NtStatus>) -> u32 {
    result.err().unwrap_or(rtl::status::STATUS_SUCCESS)
}

/// Query `class` of an open file into `out` ([`ntcall::query_information_file`]): the status.
pub fn query(handle: u32, class: u32, out: &mut [u8]) -> u32 {
    as_status(ntcall::query_information_file(handle, class, out))
}

/// Set `class` of an open file from `information` ([`ntcall::set_information_file`]): the status.
pub fn set(handle: u32, class: u32, information: &[u8]) -> u32 {
    as_status(ntcall::set_information_file(handle, class, information))
}

/// Query `class` of the volume of the open file `handle` into `out`
/// ([`ntcall::query_volume_information_file`]): the status.
pub fn query_volume(handle: u32, class: u32, out: &mut [u8]) -> u32 {
    as_status(ntcall::query_volume_information_file(handle, class, out))
}

/// A status as the file calls' work answers it: a success, or the failure (its error set through
/// BaseSetLastNTError).
pub fn checked(status: u32) -> Result<(), Failure> {
    if rtl::status::nt_success(status) {
        Ok(())
    } else {
        Err(Failure::Status(status))
    }
}

/// A status as the calls that keep a warning's answer (a name cut to the buffer) take it: only an
/// error fails them.
pub fn unless_error(status: u32) -> Result<(), Failure> {
    if status & 0xC000_0000 == 0xC000_0000 {
        Err(Failure::Status(status))
    } else {
        Ok(())
    }
}

/// Close a handle the call opened for itself (a failure leaves nothing more to do).
pub fn close(handle: u32) {
    let _ = ntcall::close(handle);
}

/// The dword at `at` of a structure.
pub fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The quadword at `at` of a structure.
pub fn quad(bytes: &[u8], at: usize) -> u64 {
    u64::from(word(bytes, at)) | u64::from(word(bytes, at + 4)) << 32
}

/// Write a value where an optional out parameter asks, when it does.
pub fn put<T: Copy>(at: Option<&mut Out<'_, T>>, value: T) {
    if let Some(at) = at {
        at.set(value);
    }
}
