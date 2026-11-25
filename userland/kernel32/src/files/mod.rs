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
//! SearchPath's look through a list of directories, [`temp`] the temporary directory and file
//! names, and [`volume`] the volume's.

pub mod copy;
pub mod find;
pub mod handle;
pub mod names;
pub mod search;
pub mod temp;
pub mod volume;

use crate::base::{SecurityAttributes, OBJ_INHERIT};
use crate::edge::{ansi_into, wide_units, CallerStr, In, InStr, InWStr, Out};
use crate::error::Failure;
use crate::heap::{HeapArray, HeapString};
use crate::nt::{ObjectAttributes, UnicodeString};
use crate::ntcall;

/// The ANSI path limit, terminator included.
pub const MAX_PATH: usize = 260;

pub const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

// The statuses the file calls tell apart.
// The file access rights and the generic ones the calls ask for.
pub use rtl::file::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
pub use rtl::nt::access::{
    DELETE,
    FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES,
    FILE_WRITE_ATTRIBUTES,
    GENERIC_READ,
    GENERIC_WRITE,
    SYNCHRONIZE,
};
use rtl::status::{
    STATUS_END_OF_FILE,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH,
    STATUS_PENDING,
};
// The Win32 errors the file calls set themselves.
use rtl::winerror::{
    ERROR_ALREADY_EXISTS,
    ERROR_BAD_LENGTH,
    ERROR_FILENAME_EXCED_RANGE,
    ERROR_FILE_EXISTS,
    ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_HANDLE,
    ERROR_INVALID_NAME,
    ERROR_INVALID_PARAMETER,
    ERROR_NEGATIVE_SEEK,
    ERROR_NOT_ENOUGH_MEMORY,
    ERROR_PATH_NOT_FOUND,
};
/// The share modes.
pub const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

// The create options.
// The dispositions, and what an open did (the I/O status's Information).
pub use rtl::file::{
    FILE_CREATE,
    FILE_OPEN,
    FILE_OPENED,
    FILE_OPEN_IF,
    FILE_OVERWRITE_IF,
    FILE_OVERWRITTEN,
};
pub use rtl::file::{
    FILE_DELETE_ON_CLOSE,
    FILE_DIRECTORY_FILE,
    FILE_NON_DIRECTORY_FILE,
    FILE_NO_INTERMEDIATE_BUFFERING,
    FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_FOR_FREE_SPACE_QUERY,
    FILE_OPEN_REPARSE_POINT,
    FILE_RANDOM_ACCESS,
    FILE_SEQUENTIAL_ONLY,
    FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_WRITE_THROUGH,
};

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

/// Whether a name is written `\\?\` (exactly: not `//?/`), the prefix that passes a path to the
/// NT namespace untouched, with no MAX_PATH limit.
pub fn is_verbatim(units: &[u16]) -> bool {
    units.starts_with(&(*b"\\\\?\\").map(u16::from))
}

/// A name in UTF-16, NUL-terminated, as the W forms take it: Basep8BitStringToStaticUnicodeString's
/// buffer, or a W call's own name past it.
pub struct Wide {
    pub units: [u16; MAX_PATH + 1],
    pub length: usize,
    /// A W call's name past MAX_PATH, terminated, on the process heap (none: `units` holds the
    /// name).
    long: Option<HeapArray<u16>>,
}

impl Wide {
    /// The empty name, its buffer's room MAX_PATH units and the terminator.
    pub fn empty() -> Wide {
        Wide {
            units: [0; MAX_PATH + 1],
            length: 0,
            long: None,
        }
    }

    /// The name with its terminator.
    pub fn terminated(&self) -> &[u16] {
        match &self.long {
            Some(long) => long,
            None => &self.units[..self.length + 1],
        }
    }

    /// The name.
    pub fn text(&self) -> &[u16] {
        let terminated = self.terminated();
        &terminated[..terminated.len() - 1]
    }

    /// A wide name copied from `units` (a W call's own); none past MAX_PATH.
    pub fn of(units: &[u16]) -> Option<Wide> {
        if units.len() > MAX_PATH {
            return None;
        }
        let mut wide = Wide::empty();
        wide.length = units.len();
        wide.units[..units.len()].copy_from_slice(units);
        Some(wide)
    }

    /// A W call's name, copied: in the buffer up to MAX_PATH units; past it, a `\\?\` path only,
    /// on the process heap (ntdll's conversion takes it whole; it refuses any other).
    fn caller(units: &[u16]) -> Result<Wide, Failure> {
        if let Some(wide) = Wide::of(units) {
            return Ok(wide);
        }
        if !is_verbatim(units) {
            return Err(Failure::Error(ERROR_PATH_NOT_FOUND));
        }
        Wide::long(units)
    }

    /// A name copied onto the process heap, whatever its length.
    fn long(units: &[u16]) -> Result<Wide, Failure> {
        let mut wide = Wide::empty();
        wide.length = units.len();
        let long = HeapArray::joined(&[units, &[0]]);
        wide.long = Some(long.map_err(|_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?);
        Ok(wide)
    }
}

/// An A call's name converted into UTF-16 (ntdll's conversion, [`crate::edge::ansi_into`]; no
/// name is the empty one): ERROR_FILENAME_EXCED_RANGE past MAX_PATH characters.
pub fn widen(name: Option<&InStr<'_>>) -> Result<Wide, Failure> {
    let mut wide = Wide::empty();
    wide.length =
        ansi_into(name, &mut wide.units).ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))?;
    Ok(wide)
}

/// An A call's name converted whole, past MAX_PATH characters too (on the process heap), as
/// Windows 2000's GetFullPathNameA converts its name: no ERROR_FILENAME_EXCED_RANGE.
pub fn widen_whole(name: Option<&InStr<'_>>) -> Result<Wide, Failure> {
    if let Ok(wide) = widen(name) {
        return Ok(wide);
    }
    let bytes = name.map_or(0, |name| name.bytes().len());
    let mut long =
        HeapArray::new(bytes + 1).map_err(|_| Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    let length = ntcall::ansi_to_unicode(name, &mut long).map_err(Failure::Status)?;
    long.truncate(length + 1);
    let mut wide = Wide::empty();
    wide.length = length;
    wide.long = Some(long);
    Ok(wide)
}

/// A W call's name, copied ([`Wide::caller`]). A W call does not convert: a name past MAX_PATH is
/// ntdll's DOS path conversion's to refuse, which it does but for a `\\?\` path —
/// ERROR_PATH_NOT_FOUND here (the files capture: CreateFileW of a 300-character path), where an A
/// call's conversion refuses it with ERROR_FILENAME_EXCED_RANGE; a `\\?\` path past MAX_PATH
/// reaches ntdll whole and opens (the fswrite capture's deep block).
pub fn wide(name: &InWStr<'_>) -> Result<Wide, Failure> {
    let units = wide_units(name).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    Wide::caller(&units)
}

/// A W call's name copied whole, past MAX_PATH characters too, as Windows 2000's GetFullPathNameW
/// hands its name to ntdll.
pub fn wide_whole(name: &InWStr<'_>) -> Result<Wide, Failure> {
    let units = wide_units(name).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    Wide::of(&units).map_or_else(|| Wide::long(&units), Ok)
}

/// A caller's name of either form, into the buffer a path is read into: an A call's converted
/// ([`widen`]: ERROR_FILENAME_EXCED_RANGE past MAX_PATH characters), a W call's copied ([`wide`]:
/// ERROR_PATH_NOT_FOUND past it, but for a `\\?\` path).
pub fn name(name: &CallerStr<'_>) -> Result<Wide, Failure> {
    match name {
        CallerStr::Ansi(name) => widen(Some(name)),
        CallerStr::Wide(name) => wide(name),
    }
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
