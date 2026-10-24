//! The calls on a file's name: its attributes (NtQueryAttributesFile, NtQueryFullAttributesFile,
//! FileBasicInformation), its delete and a directory's removal (an open for DELETE, then
//! FileDispositionInformation: the file goes with the open's close), a rename
//! (FileRenameInformation), a new directory (NtCreateFile), and the full and short forms of a path
//! — as Windows 2000's kernel32 makes them, each in its W form's work with the A and W exports
//! over it.

use rtl::status::nt_success;

use super::find::{find_close, find_first_w, FindDataW};
use super::*;
use crate::base::{set_last_nt_error, Text};

/// The attributes SetFileAttributes may set (FILE_ATTRIBUTE_VALID_SET_FLAGS), and the one it adds
/// so that none still names a change.
const FILE_ATTRIBUTE_VALID_SET_FLAGS: u32 = 0x31A7;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

/// A name's NT path; none with ERROR_PATH_NOT_FOUND when ntdll cannot make it.
fn nt_path(name: &Wide) -> Option<NtPath> {
    let path = NtPath::of(name.terminated());
    if path.is_none() {
        set_last_error(ERROR_PATH_NOT_FOUND);
    }
    path
}

/// A call that answers TRUE, or FALSE with the status's error.
fn succeeded(status: u32) -> u32 {
    if nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

/// GetFileAttributesW's work: the file's or directory's attributes (NtQueryAttributesFile);
/// INVALID_FILE_ATTRIBUTES with the error.
fn file_attributes(name: &Wide) -> u32 {
    let Some(path) = nt_path(name) else {
        return INVALID_FILE_ATTRIBUTES;
    };
    let attributes = path.attributes(false);
    let mut basic = [0u8; 40];
    // SAFETY: ntdll's export, into the structure above.
    let status = unsafe { nt::NtQueryAttributesFile(&attributes, basic.as_mut_ptr()) };
    if !nt_success(status) {
        set_last_nt_error(status);
        return INVALID_FILE_ATTRIBUTES;
    }
    word(&basic, 32)
}

/// GetFileAttributesA (see [`file_attributes`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_GetFileAttributesA")]
pub unsafe extern "system" fn get_file_attributes_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string.
    unsafe { widen(name) }.map_or(INVALID_FILE_ATTRIBUTES, |name| file_attributes(&name))
}

/// GetFileAttributesW (see [`file_attributes`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_GetFileAttributesW")]
pub unsafe extern "system" fn get_file_attributes_w(name: *const u16) -> u32 {
    // SAFETY: the caller's string.
    unsafe { wide(name) }.map_or(INVALID_FILE_ATTRIBUTES, |name| file_attributes(&name))
}

/// GetFileAttributesExW's work for GetFileExInfoStandard: the attributes, the three times and the
/// size (NtQueryFullAttributesFile) into the caller's WIN32_FILE_ATTRIBUTE_DATA.
///
/// # Safety
///
/// `info` points at a WIN32_FILE_ATTRIBUTE_DATA.
unsafe fn file_attributes_ex(name: &Wide, info: *mut u8) -> u32 {
    let Some(path) = nt_path(name) else {
        return 0;
    };
    let attributes = path.attributes(false);
    let mut network = [0u8; 56];
    // SAFETY: ntdll's export, into the structure above.
    let status = unsafe { nt::NtQueryFullAttributesFile(&attributes, network.as_mut_ptr()) };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    let mut data = [0u8; 36];
    data[..4].copy_from_slice(&network[48..52]);
    data[4..28].copy_from_slice(&network[..24]);
    data[28..32].copy_from_slice(&network[44..48]);
    data[32..36].copy_from_slice(&network[40..44]);
    // SAFETY: the caller's structure.
    unsafe { info.copy_from_nonoverlapping(data.as_ptr(), data.len()) };
    1
}

/// GetFileAttributesExA: GetFileExInfoStandard alone (ERROR_INVALID_PARAMETER for another level,
/// before the name is read; see [`file_attributes_ex`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string; `info` points at a WIN32_FILE_ATTRIBUTE_DATA.
#[unsafe(export_name = "f2k_export_GetFileAttributesExA")]
pub unsafe extern "system" fn get_file_attributes_ex_a(
    name: *const u8,
    level: u32,
    info: *mut u8,
) -> u32 {
    if level != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string and structure.
    unsafe { widen(name) }.map_or(0, |name| unsafe { file_attributes_ex(&name, info) })
}

/// GetFileAttributesExW (as [`get_file_attributes_ex_a`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string; `info` points at a WIN32_FILE_ATTRIBUTE_DATA.
#[unsafe(export_name = "f2k_export_GetFileAttributesExW")]
pub unsafe extern "system" fn get_file_attributes_ex_w(
    name: *const u16,
    level: u32,
    info: *mut u8,
) -> u32 {
    if level != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string and structure.
    unsafe { wide(name) }.map_or(0, |name| unsafe { file_attributes_ex(&name, info) })
}

/// SetFileAttributesW's work: an open for FILE_WRITE_ATTRIBUTES, then the attributes (the settable
/// ones, with FILE_ATTRIBUTE_NORMAL so that none still sets) in FileBasicInformation, its times
/// zero (left as they are).
fn set_attributes(name: &Wide, attributes: u32) -> u32 {
    let Some(path) = nt_path(name) else {
        return 0;
    };
    let options =
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
    let handle = match open(
        &path,
        FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_ALL,
        options,
    ) {
        Ok(handle) => handle,
        Err(status) => return succeeded(status),
    };
    let mut basic = [0u8; 40];
    basic[32..36].copy_from_slice(
        &((attributes & FILE_ATTRIBUTE_VALID_SET_FLAGS) | FILE_ATTRIBUTE_NORMAL).to_le_bytes(),
    );
    let status = set(handle, FILE_BASIC_INFORMATION, &basic);
    close(handle);
    succeeded(status)
}

/// SetFileAttributesA (see [`set_attributes`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_SetFileAttributesA")]
pub unsafe extern "system" fn set_file_attributes_a(name: *const u8, attributes: u32) -> u32 {
    // SAFETY: the caller's string.
    unsafe { widen(name) }.map_or(0, |name| set_attributes(&name, attributes))
}

/// SetFileAttributesW (see [`set_attributes`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_SetFileAttributesW")]
pub unsafe extern "system" fn set_file_attributes_w(name: *const u16, attributes: u32) -> u32 {
    // SAFETY: the caller's string.
    unsafe { wide(name) }.map_or(0, |name| set_attributes(&name, attributes))
}

/// The delete DeleteFile and RemoveDirectory share: the open for DELETE (sharing everything), then
/// FileDispositionInformation; the open's close deletes the file, or leaves it to the last open's
/// when others hold it.
fn delete(name: &Wide, access: u32, options: u32) -> u32 {
    let Some(path) = nt_path(name) else {
        return 0;
    };
    let handle = match open(
        &path,
        access,
        FILE_SHARE_ALL,
        options | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
    ) {
        Ok(handle) => handle,
        Err(status) => return succeeded(status),
    };
    let status = set(handle, FILE_DISPOSITION_INFORMATION, &[1]);
    close(handle);
    succeeded(status)
}

/// A file's delete (a directory refuses the open, STATUS_FILE_IS_A_DIRECTORY; a read-only file the
/// disposition, STATUS_CANNOT_DELETE).
fn delete_file(name: &Wide) -> u32 {
    delete(name, DELETE, FILE_NON_DIRECTORY_FILE)
}

/// A directory's delete (a file refuses the open, STATUS_NOT_A_DIRECTORY; a directory with entries
/// the disposition, STATUS_DIRECTORY_NOT_EMPTY).
fn remove_directory(name: &Wide) -> u32 {
    delete(
        name,
        DELETE | SYNCHRONIZE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

/// DeleteFileA (see [`delete_file`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_DeleteFileA")]
pub unsafe extern "system" fn delete_file_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string.
    unsafe { widen(name) }.map_or(0, |name| delete_file(&name))
}

/// DeleteFileW (see [`delete_file`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_DeleteFileW")]
pub unsafe extern "system" fn delete_file_w(name: *const u16) -> u32 {
    // SAFETY: the caller's string.
    unsafe { wide(name) }.map_or(0, |name| delete_file(&name))
}

/// RemoveDirectoryA (see [`remove_directory`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_RemoveDirectoryA")]
pub unsafe extern "system" fn remove_directory_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string.
    unsafe { widen(name) }.map_or(0, |name| remove_directory(&name))
}

/// RemoveDirectoryW (see [`remove_directory`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_RemoveDirectoryW")]
pub unsafe extern "system" fn remove_directory_w(name: *const u16) -> u32 {
    // SAFETY: the caller's string.
    unsafe { wide(name) }.map_or(0, |name| remove_directory(&name))
}

/// MoveFileW's and MoveFileExW's work: the source's open for DELETE (sharing reads and writes),
/// then its rename to the new name's NT path (FileRenameInformation: an existing name replaced
/// when asked, `replace`, and only a file no one holds open, not read-only nor a directory;
/// STATUS_OBJECT_NAME_COLLISION otherwise, ERROR_ALREADY_EXISTS). An empty new name is
/// ERROR_PATH_NOT_FOUND, once the source opened.
fn move_file(from: &Wide, to: &Wide, replace: bool) -> u32 {
    let Some(source) = nt_path(from) else {
        return 0;
    };
    let options =
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
    let handle = match open(
        &source,
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        options,
    ) {
        Ok(handle) => handle,
        Err(status) => return succeeded(status),
    };
    let Some(target) = nt_path(to) else {
        close(handle);
        return 0;
    };
    let units = target.units();
    let mut rename = [0u8; 12 + 2 * (MAX_PATH + 8)];
    rename[0] = u8::from(replace);
    rename[8..12].copy_from_slice(&((2 * units.len()) as u32).to_le_bytes());
    for (at, &unit) in units.iter().enumerate() {
        rename[12 + 2 * at..14 + 2 * at].copy_from_slice(&unit.to_le_bytes());
    }
    let status = set(
        handle,
        FILE_RENAME_INFORMATION,
        &rename[..12 + 2 * units.len()],
    );
    close(handle);
    succeeded(status)
}

/// MoveFileA (see [`move_file`]): both names converted first.
///
/// # Safety
///
/// Both names are NUL-terminated strings.
#[unsafe(export_name = "f2k_export_MoveFileA")]
pub unsafe extern "system" fn move_file_a(from: *const u8, to: *const u8) -> u32 {
    // SAFETY: the caller's strings.
    match (unsafe { widen(from) }, unsafe { widen(to) }) {
        (Some(from), Some(to)) => move_file(&from, &to, false),
        _ => 0,
    }
}

/// MoveFileW (as [`move_file_a`]).
///
/// # Safety
///
/// Both names are NUL-terminated UTF-16 strings.
#[unsafe(export_name = "f2k_export_MoveFileW")]
pub unsafe extern "system" fn move_file_w(from: *const u16, to: *const u16) -> u32 {
    // SAFETY: the caller's strings.
    match (unsafe { wide(from) }, unsafe { wide(to) }) {
        (Some(from), Some(to)) => move_file(&from, &to, false),
        _ => 0,
    }
}

/// MOVEFILE_REPLACE_EXISTING and MOVEFILE_DELAY_UNTIL_REBOOT; MOVEFILE_COPY_ALLOWED and
/// MOVEFILE_WRITE_THROUGH change nothing here: a move never leaves the one volume (the copy is
/// for one that does), and every rename is written through.
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x4;

/// MoveFileExW's work: [`move_file`], the existing name replaced with MOVEFILE_REPLACE_EXISTING
/// (the fswrite capture: not a directory nor a read-only file, ERROR_ALREADY_EXISTS both). A move
/// delayed until the reboot takes the stub path: F2K keeps no list of moves for the next boot.
/// A NULL new name (a delayed delete's) is the empty one: ERROR_PATH_NOT_FOUND.
fn move_file_ex(from: &Wide, to: &Wide, flags: u32) -> u32 {
    move_file(from, to, flags & MOVEFILE_REPLACE_EXISTING != 0)
}

/// MoveFileExA (see [`move_file_ex`]): both names converted first.
///
/// # Safety
///
/// `from` is a NUL-terminated string; `to` is null or one.
#[unsafe(export_name = "f2k_export_MoveFileExA")]
pub unsafe extern "system" fn move_file_ex_a(from: *const u8, to: *const u8, flags: u32) -> u32 {
    if flags & MOVEFILE_DELAY_UNTIL_REBOOT != 0 {
        let args = [from as u64, to as u64, u64::from(flags)];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe {
            crate::stub::stubbed(&crate::spec::MoveFileExA, "not yet implemented", &args)
        };
    }
    // SAFETY: the caller's strings.
    match (unsafe { widen(from) }, unsafe { widen(to) }) {
        (Some(from), Some(to)) => move_file_ex(&from, &to, flags),
        _ => 0,
    }
}

/// MoveFileExW (as [`move_file_ex_a`]).
///
/// # Safety
///
/// `from` is a NUL-terminated UTF-16 string; `to` is null or one.
#[unsafe(export_name = "f2k_export_MoveFileExW")]
pub unsafe extern "system" fn move_file_ex_w(from: *const u16, to: *const u16, flags: u32) -> u32 {
    if flags & MOVEFILE_DELAY_UNTIL_REBOOT != 0 {
        let args = [from as u64, to as u64, u64::from(flags)];
        // SAFETY: the caller's arguments, as the export's kinds read them.
        return unsafe {
            crate::stub::stubbed(&crate::spec::MoveFileExW, "not yet implemented", &args)
        };
    }
    // SAFETY: the caller's strings.
    let to = if to.is_null() {
        Wide::of(&[])
    } else {
        unsafe { wide(to) }
    };
    match (unsafe { wide(from) }, to) {
        (Some(from), Some(to)) => move_file_ex(&from, &to, flags),
        _ => 0,
    }
}

/// CreateDirectoryW's work: a new directory (NtCreateFile, FILE_CREATE): an existing name is
/// STATUS_OBJECT_NAME_COLLISION (ERROR_ALREADY_EXISTS). A directory whose full path leaves no room
/// for an 8.3 name inside MAX_PATH is ERROR_FILENAME_EXCED_RANGE (so `del *.*` can always empty
/// it, as Windows 2000's reason runs); the security attributes are not consulted.
///
/// # Safety
///
/// `security` is null or a SECURITY_ATTRIBUTES.
unsafe fn create_directory(name: &Wide, security: *const SecurityAttributes) -> u32 {
    let Some(path) = nt_path(name) else {
        return 0;
    };
    // The full DOS path is the NT one less its `\??\`; it and an 8.3 name must fit MAX_PATH.
    let full = path.units().len().saturating_sub(4);
    if full + 1 + 12 > MAX_PATH {
        set_last_error(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    // SAFETY: the caller's structure, when given.
    let attributes = path.attributes(unsafe { inherits(security) });
    let mut handle = 0;
    let mut io_status = IoStatus::default();
    // SAFETY: ntdll's export, over the attributes above.
    let status = unsafe {
        nt::NtCreateFile(
            &mut handle,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &attributes,
            &mut io_status,
            core::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
            core::ptr::null(),
            0,
        )
    };
    if nt_success(status) {
        close(handle);
    }
    succeeded(status)
}

/// CreateDirectoryA (see [`create_directory`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string; `security` is null or a SECURITY_ATTRIBUTES.
#[unsafe(export_name = "f2k_export_CreateDirectoryA")]
pub unsafe extern "system" fn create_directory_a(
    name: *const u8,
    security: *const SecurityAttributes,
) -> u32 {
    // SAFETY: the caller's string and structure.
    unsafe { widen(name) }.map_or(0, |name| unsafe { create_directory(&name, security) })
}

/// CreateDirectoryW (see [`create_directory`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string; `security` is null or a SECURITY_ATTRIBUTES.
#[unsafe(export_name = "f2k_export_CreateDirectoryW")]
pub unsafe extern "system" fn create_directory_w(
    name: *const u16,
    security: *const SecurityAttributes,
) -> u32 {
    // SAFETY: the caller's string and structure.
    unsafe { wide(name) }.map_or(0, |name| unsafe { create_directory(&name, security) })
}

/// GetFullPathNameW's work: the path made absolute and folded (RtlGetFullPathName_U; no lookup),
/// its trailing separator kept, into the caller's buffer: its length when it fits with its
/// terminator, the file part pointing at its last component (null when it ends in a separator);
/// otherwise the size it needs, terminator included. An empty path is ERROR_PATH_NOT_FOUND, a full
/// one past MAX_PATH ERROR_FILENAME_EXCED_RANGE (assumptions, unverified against Windows 2000).
///
/// # Safety
///
/// `buffer` holds `size` characters; `file_part` is null or points at a pointer.
unsafe fn full_path(name: &Wide, size: u32, buffer: Text, file_part: *mut usize) -> u32 {
    let mut full = [0u16; MAX_PATH + 1];
    let mut part = core::ptr::null_mut();
    // SAFETY: ntdll's export, into the buffer above.
    let bytes = unsafe {
        nt::RtlGetFullPathName_U(
            name.terminated().as_ptr(),
            2 * full.len() as u32,
            full.as_mut_ptr(),
            &mut part,
        )
    } as usize;
    if bytes == 0 {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0;
    }
    if bytes > 2 * MAX_PATH {
        set_last_error(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    let length = bytes / 2;
    if (size as usize) <= length {
        return length as u32 + 1;
    }
    // SAFETY: the caller's buffer holds the path and its terminator.
    unsafe { buffer.put_terminated(&full[..length]) };
    if !file_part.is_null() {
        let at = (!part.is_null()).then(|| (part as usize - full.as_ptr() as usize) / 2);
        // SAFETY: the caller's slot; the part lies in the caller's buffer.
        unsafe { file_part.write_unaligned(at.map_or(0, |at| buffer.address(at))) };
    }
    length as u32
}

/// GetFullPathNameA (see [`full_path`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string; `buffer` holds `size` bytes; `file_part` is null or points at
/// a pointer.
#[unsafe(export_name = "f2k_export_GetFullPathNameA")]
pub unsafe extern "system" fn get_full_path_name_a(
    name: *const u8,
    size: u32,
    buffer: *mut u8,
    file_part: *mut *mut u8,
) -> u32 {
    let file_part = file_part as *mut usize;
    // SAFETY: the caller's string, buffer and slot.
    unsafe { widen(name) }.map_or(0, |name| unsafe {
        full_path(&name, size, Text::Ansi(buffer), file_part)
    })
}

/// GetFullPathNameW (see [`full_path`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string; `buffer` holds `size` characters; `file_part` is null
/// or points at a pointer.
#[unsafe(export_name = "f2k_export_GetFullPathNameW")]
pub unsafe extern "system" fn get_full_path_name_w(
    name: *const u16,
    size: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    let file_part = file_part as *mut usize;
    // SAFETY: the caller's string, buffer and slot.
    unsafe { wide(name) }.map_or(0, |name| unsafe {
        full_path(&name, size, Text::Wide(buffer), file_part)
    })
}

/// Whether a component is an 8.3 name GetShortPathName leaves as it is (IsShortName_U's test):
/// 1 to 8 name characters, at most one dot and 3 extension characters after it, none a space nor
/// one an 8.3 name cannot hold; `.` and `..` are.
pub fn is_short_name(component: &[u16]) -> bool {
    let dot = u16::from(b'.');
    if component == [dot] || component == [dot, dot] {
        return true;
    }
    let valid =
        |unit: u16| unit > 0x20 && unit < 0x80 && !b"\"*+,/:;<=>?[\\]|".contains(&(unit as u8));
    let (base, extension) = match component.iter().position(|&unit| unit == dot) {
        Some(at) => (&component[..at], Some(&component[at + 1..])),
        None => (component, None),
    };
    (1..=8).contains(&base.len())
        && base.iter().all(|&unit| valid(unit))
        && extension.is_none_or(|extension| {
            extension.len() <= 3 && extension.iter().all(|&unit| unit != dot && valid(unit))
        })
}

/// GetShortPathNameW's work, Windows 2000's walk: the path must name something (its attributes'
/// failure is the call's); its prefix (a drive, a root, a UNC share) is kept, and each component an
/// 8.3 name already stays as written, every other one replaced by its 8.3 name as a search of it
/// reports it. The result into the caller's buffer of `size` characters: its length when it fits
/// with its terminator, otherwise the size it needs.
///
/// # Safety
///
/// `buffer` holds `size` characters.
unsafe fn short_path(long: &Wide, buffer: Text, size: u32) -> u32 {
    if file_attributes(long) == INVALID_FILE_ATTRIBUTES {
        return 0;
    }
    let units = long.text();
    let separator = |unit: u16| unit == u16::from(b'\\') || unit == u16::from(b'/');
    // The prefix: `\\server\share\`, `X:` and its separator, or a root separator.
    let prefix = if units.len() >= 2 && separator(units[0]) && separator(units[1]) {
        let mut seen = 0;
        units
            .iter()
            .position(|&unit| {
                seen += usize::from(separator(unit));
                seen == 4
            })
            .map_or(units.len(), |at| at + 1)
    } else if units.len() >= 2 && units[1] == u16::from(b':') {
        2 + usize::from(units.get(2).is_some_and(|&unit| separator(unit)))
    } else {
        usize::from(units.first().is_some_and(|&unit| separator(unit)))
    };
    let mut out = [0u16; 2 * MAX_PATH + 2];
    out[..prefix].copy_from_slice(&units[..prefix]);
    let mut length = prefix;
    let mut rest = &units[prefix..];
    while !rest.is_empty() {
        let end = rest
            .iter()
            .position(|&unit| separator(unit))
            .unwrap_or(rest.len());
        let component = &rest[..end];
        let mut replacement: FindDataW;
        let short: &[u16] = if component.is_empty() || is_short_name(component) {
            component
        } else {
            // The entry's 8.3 name, by a search of the path so far.
            if length + component.len() > MAX_PATH {
                set_last_error(ERROR_FILENAME_EXCED_RANGE);
                return 0;
            }
            let mut wide = Wide {
                units: [0; MAX_PATH + 1],
                length: length + component.len(),
            };
            wide.units[..length].copy_from_slice(&out[..length]);
            wide.units[length..wide.length].copy_from_slice(component);
            replacement = FindDataW::zeroed();
            let handle = find_first_w(&wide, &mut replacement);
            if handle == INVALID_HANDLE_VALUE {
                return 0;
            }
            find_close(handle);
            if replacement.alternate().is_empty() {
                replacement.name()
            } else {
                replacement.alternate()
            }
        };
        if length + short.len() + 1 >= out.len() {
            set_last_error(ERROR_FILENAME_EXCED_RANGE);
            return 0;
        }
        out[length..length + short.len()].copy_from_slice(short);
        length += short.len();
        if end < rest.len() {
            out[length] = rest[end];
            length += 1;
            rest = &rest[end + 1..];
        } else {
            rest = &[];
        }
    }
    if (size as usize) <= length {
        return length as u32 + 1;
    }
    // SAFETY: the caller's buffer holds the path and its terminator.
    unsafe { buffer.put_terminated(&out[..length]) };
    length as u32
}

/// GetShortPathNameA (see [`short_path`]); a null name is ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// `name` is null or a NUL-terminated string; `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetShortPathNameA")]
pub unsafe extern "system" fn get_short_path_name_a(
    name: *const u8,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string and buffer.
    unsafe { widen(name) }.map_or(0, |long| unsafe {
        short_path(&long, Text::Ansi(buffer), size)
    })
}

/// GetShortPathNameW (as [`get_short_path_name_a`]).
///
/// # Safety
///
/// `name` is null or a NUL-terminated UTF-16 string; `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetShortPathNameW")]
pub unsafe extern "system" fn get_short_path_name_w(
    name: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string and buffer.
    unsafe { wide(name) }.map_or(0, |long| unsafe {
        short_path(&long, Text::Wide(buffer), size)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// The components GetShortPathName keeps as written.
    #[test]
    fn short_names_are_eight_dot_three() {
        for short in [
            "SMALL.TXT",
            "small.txt",
            "SUB",
            "LONGFI~1.TXT",
            ".",
            "..",
            "A.B",
        ] {
            assert!(is_short_name(&wide(short)), "{short}");
        }
        for long in [
            "Long File Name.txt",
            "ABCDEFGHI.TXT",
            "A.TEXT",
            "A.B.C",
            ".X",
            "A+B",
            "",
        ] {
            assert!(!is_short_name(&wide(long)), "{long}");
        }
    }
}
