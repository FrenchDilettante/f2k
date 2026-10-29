//! The calls on a file's name: its attributes (NtQueryAttributesFile, NtQueryFullAttributesFile,
//! FileBasicInformation), its delete and a directory's removal (an open for DELETE, then
//! FileDispositionInformation: the file goes with the open's close), a rename
//! (FileRenameInformation), a new directory (NtCreateFile), and the full and short forms of a path
//! — as Windows 2000's kernel32 makes them, each in its W form's work with the A and W exports
//! over it.

use super::find::{find_first_w, FindDataW};
use super::*;
use crate::edge::{OutBuf, Text};
use crate::error::{answer, bool_answer};

/// The attributes SetFileAttributes may set (FILE_ATTRIBUTE_VALID_SET_FLAGS), and the one it adds
/// so that none still names a change.
const FILE_ATTRIBUTE_VALID_SET_FLAGS: u32 = 0x31A7;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

/// A name's NT path; ERROR_PATH_NOT_FOUND when ntdll cannot make it.
fn nt_path(name: &Wide) -> Result<NtPath, Failure> {
    NtPath::of(name.terminated()).ok_or(Failure::Error(ERROR_PATH_NOT_FOUND))
}

/// GetFileAttributesW's work: the file's or directory's attributes (NtQueryAttributesFile).
pub(crate) fn file_attributes(name: &Wide) -> Result<u32, Failure> {
    let path = nt_path(name)?;
    let basic = ntcall::query_attributes_file(&path.attributes(false)).map_err(Failure::Status)?;
    Ok(word(&basic, 32))
}

/// GetFileAttributesA (see [`file_attributes`]): INVALID_FILE_ATTRIBUTES with the error.
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_GetFileAttributesA")]
pub unsafe extern "system" fn get_file_attributes_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string (null: the empty one).
    let name = unsafe { InStr::optional(name) };
    let attributes = widen(name.as_ref()).and_then(|name| file_attributes(&name));
    answer(attributes, INVALID_FILE_ATTRIBUTES)
}

/// GetFileAttributesW (see [`file_attributes`]): INVALID_FILE_ATTRIBUTES with the error.
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_GetFileAttributesW")]
pub unsafe extern "system" fn get_file_attributes_w(name: *const u16) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { InWStr::new(name) };
    let attributes = wide(&name).and_then(|name| file_attributes(&name));
    answer(attributes, INVALID_FILE_ATTRIBUTES)
}

/// The size of a WIN32_FILE_ATTRIBUTE_DATA.
const WIN32_FILE_ATTRIBUTE_DATA: usize = 36;

/// GetFileAttributesExW's work for GetFileExInfoStandard: the attributes, the three times and the
/// size (NtQueryFullAttributesFile) into the caller's WIN32_FILE_ATTRIBUTE_DATA.
fn file_attributes_ex(name: &Wide, mut info: OutBuf<'_, u8>) -> Result<(), Failure> {
    let path = nt_path(name)?;
    let network =
        ntcall::query_full_attributes_file(&path.attributes(false)).map_err(Failure::Status)?;
    let mut data = [0u8; WIN32_FILE_ATTRIBUTE_DATA];
    data[..4].copy_from_slice(&network[48..52]);
    data[4..28].copy_from_slice(&network[..24]);
    data[28..32].copy_from_slice(&network[44..48]);
    data[32..36].copy_from_slice(&network[40..44]);
    info.put(&data);
    Ok(())
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
    // SAFETY: the caller's string (null: the empty one) and structure (the contract).
    let (name, info) = unsafe {
        (
            InStr::optional(name),
            OutBuf::new(info, WIN32_FILE_ATTRIBUTE_DATA),
        )
    };
    let level = standard_level(level);
    bool_answer(
        level
            .and_then(|()| widen(name.as_ref()))
            .and_then(|name| file_attributes_ex(&name, info)),
    )
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
    // SAFETY: the caller's string and structure (the contract).
    let (name, info) = unsafe {
        (
            InWStr::new(name),
            OutBuf::new(info, WIN32_FILE_ATTRIBUTE_DATA),
        )
    };
    let level = standard_level(level);
    bool_answer(
        level
            .and_then(|()| wide(&name))
            .and_then(|name| file_attributes_ex(&name, info)),
    )
}

/// GetFileAttributesEx's level: GetFileExInfoStandard (0) alone, ERROR_INVALID_PARAMETER for
/// another.
fn standard_level(level: u32) -> Result<(), Failure> {
    if level == 0 {
        Ok(())
    } else {
        Err(Failure::Error(ERROR_INVALID_PARAMETER))
    }
}

/// SetFileAttributesW's work: an open for FILE_WRITE_ATTRIBUTES, then the attributes (the settable
/// ones, with FILE_ATTRIBUTE_NORMAL so that none still sets) in FileBasicInformation, its times
/// zero (left as they are).
fn set_attributes(name: &Wide, attributes: u32) -> Result<(), Failure> {
    let path = nt_path(name)?;
    let options =
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
    let handle = open(
        &path,
        FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_ALL,
        options,
    )
    .map_err(Failure::Status)?;
    let mut basic = [0u8; 40];
    basic[32..36].copy_from_slice(
        &((attributes & FILE_ATTRIBUTE_VALID_SET_FLAGS) | FILE_ATTRIBUTE_NORMAL).to_le_bytes(),
    );
    let status = set(handle, FILE_BASIC_INFORMATION, &basic);
    close(handle);
    checked(status)
}

/// SetFileAttributesA (see [`set_attributes`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_SetFileAttributesA")]
pub unsafe extern "system" fn set_file_attributes_a(name: *const u8, attributes: u32) -> u32 {
    // SAFETY: the caller's string (null: the empty one).
    let name = unsafe { InStr::optional(name) };
    bool_answer(widen(name.as_ref()).and_then(|name| set_attributes(&name, attributes)))
}

/// SetFileAttributesW (see [`set_attributes`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_SetFileAttributesW")]
pub unsafe extern "system" fn set_file_attributes_w(name: *const u16, attributes: u32) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { InWStr::new(name) };
    bool_answer(wide(&name).and_then(|name| set_attributes(&name, attributes)))
}

/// The delete DeleteFile and RemoveDirectory share: the open for DELETE (sharing everything), then
/// FileDispositionInformation; the open's close deletes the file, or leaves it to the last open's
/// when others hold it.
fn delete(name: &Wide, access: u32, options: u32) -> Result<(), Failure> {
    let path = nt_path(name)?;
    let handle = open(
        &path,
        access,
        FILE_SHARE_ALL,
        options | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(Failure::Status)?;
    let status = set(handle, FILE_DISPOSITION_INFORMATION, &[1]);
    close(handle);
    checked(status)
}

/// A file's delete (a directory refuses the open, STATUS_FILE_IS_A_DIRECTORY; a read-only file the
/// disposition, STATUS_CANNOT_DELETE).
fn delete_file(name: &Wide) -> Result<(), Failure> {
    delete(name, DELETE, FILE_NON_DIRECTORY_FILE)
}

/// A directory's delete (a file refuses the open, STATUS_NOT_A_DIRECTORY; a directory with entries
/// the disposition, STATUS_DIRECTORY_NOT_EMPTY).
fn remove_directory(name: &Wide) -> Result<(), Failure> {
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
    // SAFETY: the caller's string (null: the empty one).
    let name = unsafe { InStr::optional(name) };
    bool_answer(widen(name.as_ref()).and_then(|name| delete_file(&name)))
}

/// DeleteFileW (see [`delete_file`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_DeleteFileW")]
pub unsafe extern "system" fn delete_file_w(name: *const u16) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { InWStr::new(name) };
    bool_answer(wide(&name).and_then(|name| delete_file(&name)))
}

/// RemoveDirectoryA (see [`remove_directory`]).
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_RemoveDirectoryA")]
pub unsafe extern "system" fn remove_directory_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string (null: the empty one).
    let name = unsafe { InStr::optional(name) };
    bool_answer(widen(name.as_ref()).and_then(|name| remove_directory(&name)))
}

/// RemoveDirectoryW (see [`remove_directory`]).
///
/// # Safety
///
/// `name` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_RemoveDirectoryW")]
pub unsafe extern "system" fn remove_directory_w(name: *const u16) -> u32 {
    // SAFETY: the caller's string.
    let name = unsafe { InWStr::new(name) };
    bool_answer(wide(&name).and_then(|name| remove_directory(&name)))
}

/// MoveFileW's and MoveFileExW's work: the source's open for DELETE (sharing reads and writes),
/// then its rename to the new name's NT path (FileRenameInformation: an existing name replaced
/// when asked, `replace`, and only a file no one holds open, not read-only nor a directory;
/// STATUS_OBJECT_NAME_COLLISION otherwise, ERROR_ALREADY_EXISTS). An empty new name is
/// ERROR_PATH_NOT_FOUND, once the source opened.
fn move_file(from: &Wide, to: &Wide, replace: bool) -> Result<(), Failure> {
    let source = nt_path(from)?;
    let options =
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
    let handle = open(
        &source,
        DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        options,
    )
    .map_err(Failure::Status)?;
    let target = match nt_path(to) {
        Ok(target) => target,
        Err(failure) => {
            close(handle);
            return Err(failure);
        }
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
    checked(status)
}

/// MoveFileA (see [`move_file`]): both names converted first.
///
/// # Safety
///
/// Both names are NUL-terminated strings.
#[unsafe(export_name = "f2k_export_MoveFileA")]
pub unsafe extern "system" fn move_file_a(from: *const u8, to: *const u8) -> u32 {
    // SAFETY: the caller's strings (null: the empty one).
    let (from, to) = unsafe { (InStr::optional(from), InStr::optional(to)) };
    let names = both(widen(from.as_ref()), widen(to.as_ref()));
    bool_answer(names.and_then(|(from, to)| move_file(&from, &to, false)))
}

/// MoveFileW (as [`move_file_a`]).
///
/// # Safety
///
/// Both names are NUL-terminated UTF-16 strings.
#[unsafe(export_name = "f2k_export_MoveFileW")]
pub unsafe extern "system" fn move_file_w(from: *const u16, to: *const u16) -> u32 {
    // SAFETY: the caller's strings.
    let (from, to) = unsafe { (InWStr::new(from), InWStr::new(to)) };
    let names = both(wide(&from), wide(&to));
    bool_answer(names.and_then(|(from, to)| move_file(&from, &to, false)))
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
fn move_file_ex(from: &Wide, to: &Wide, flags: u32) -> Result<(), Failure> {
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
    // SAFETY: the caller's strings (null: the empty one).
    let (from, to) = unsafe { (InStr::optional(from), InStr::optional(to)) };
    let names = both(widen(from.as_ref()), widen(to.as_ref()));
    bool_answer(names.and_then(|(from, to)| move_file_ex(&from, &to, flags)))
}

/// MoveFileExW (as [`move_file_ex_a`]); the new name is read before the old.
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
    // SAFETY: the caller's strings (the contract: `to` may be null).
    let (from, to) = unsafe { (InWStr::new(from), InWStr::optional(to)) };
    let to = match to {
        Some(to) => wide(&to),
        None => Ok(Wide::of(&[]).expect("the empty name")),
    };
    let names = both(to, wide(&from));
    bool_answer(names.and_then(|(to, from)| move_file_ex(&from, &to, flags)))
}

/// CreateDirectoryW's work: a new directory (NtCreateFile, FILE_CREATE): an existing name is
/// STATUS_OBJECT_NAME_COLLISION (ERROR_ALREADY_EXISTS). A directory whose full path leaves no room
/// for an 8.3 name inside MAX_PATH is ERROR_FILENAME_EXCED_RANGE (so `del *.*` can always empty
/// it, as Windows 2000's reason runs); the security attributes are not consulted beyond their
/// inheritance.
fn create_directory(
    name: &Wide,
    security: Option<In<'_, SecurityAttributes>>,
) -> Result<(), Failure> {
    let path = nt_path(name)?;
    // The full DOS path is the NT one less its `\??\`; it and an 8.3 name must fit MAX_PATH.
    let full = path.units().len().saturating_sub(4);
    if full + 1 + 12 > MAX_PATH {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let created = ntcall::create_file(
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &path.attributes(inherits(security)),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
    )
    .map_err(Failure::Status)?;
    close(created.handle);
    Ok(())
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
    // SAFETY: the caller's string (null: the empty one) and structure, when given.
    let (name, security) = unsafe { (InStr::optional(name), In::optional(security)) };
    bool_answer(widen(name.as_ref()).and_then(|name| create_directory(&name, security)))
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
    // SAFETY: the caller's string and structure, when given.
    let (name, security) = unsafe { (InWStr::new(name), In::optional(security)) };
    bool_answer(wide(&name).and_then(|name| create_directory(&name, security)))
}

/// GetFullPathNameW's work: the path made absolute and folded (RtlGetFullPathName_U; no lookup),
/// its trailing separator kept, into the caller's buffer: its length when it fits with its
/// terminator, the file part pointing at its last component (null when it ends in a separator);
/// otherwise the size it needs, terminator included. An empty path is ERROR_PATH_NOT_FOUND, a full
/// one past MAX_PATH ERROR_FILENAME_EXCED_RANGE (assumptions, unverified against Windows 2000).
fn full_path(
    name: &Wide,
    mut buffer: Text<'_>,
    file_part: Option<Out<'_, usize>>,
) -> Result<u32, Failure> {
    let mut full = [0u16; MAX_PATH + 1];
    let (bytes, part) = ntcall::get_full_path_name(name.terminated(), &mut full);
    if bytes == 0 {
        return Err(Failure::Error(ERROR_PATH_NOT_FOUND));
    }
    if bytes > 2 * MAX_PATH {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let length = bytes / 2;
    if buffer.len() <= length {
        return Ok(length as u32 + 1);
    }
    buffer.put_terminated(&full[..length]);
    if let Some(mut file_part) = file_part {
        // The part lies in the caller's buffer.
        file_part.set(part.map_or(0, |at| buffer.address(at)));
    }
    Ok(length as u32)
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
    // SAFETY: the caller's string (null: the empty one), buffer and slot, when given.
    let (name, buffer, file_part) = unsafe {
        (
            InStr::optional(name),
            OutBuf::new(buffer, size as usize),
            Out::optional(file_part.cast::<usize>()),
        )
    };
    let full =
        widen(name.as_ref()).and_then(|name| full_path(&name, Text::Ansi(buffer), file_part));
    answer(full, 0)
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
    // SAFETY: the caller's string, buffer and slot, when given.
    let (name, buffer, file_part) = unsafe {
        (
            InWStr::new(name),
            OutBuf::new(buffer, size as usize),
            Out::optional(file_part.cast::<usize>()),
        )
    };
    let full = wide(&name).and_then(|name| full_path(&name, Text::Wide(buffer), file_part));
    answer(full, 0)
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
/// reports it. The result into the caller's buffer: its length when it fits with its terminator,
/// otherwise the size it needs.
fn short_path(long: &Wide, mut buffer: Text<'_>) -> Result<u32, Failure> {
    file_attributes(long)?;
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
                return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
            }
            let mut wide = Wide {
                units: [0; MAX_PATH + 1],
                length: length + component.len(),
            };
            wide.units[..length].copy_from_slice(&out[..length]);
            wide.units[length..wide.length].copy_from_slice(component);
            replacement = FindDataW::zeroed();
            // The search closed at once: its first match is all it is asked for.
            drop(find_first_w(&wide, &mut replacement)?);
            if replacement.alternate().is_empty() {
                replacement.name()
            } else {
                replacement.alternate()
            }
        };
        if length + short.len() + 1 >= out.len() {
            return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
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
    if buffer.len() <= length {
        return Ok(length as u32 + 1);
    }
    buffer.put_terminated(&out[..length]);
    Ok(length as u32)
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
    // SAFETY: the caller's string, when given, and buffer.
    let (name, buffer) = unsafe { (InStr::optional(name), OutBuf::new(buffer, size as usize)) };
    let short = name
        .ok_or(Failure::Error(ERROR_INVALID_PARAMETER))
        .and_then(|name| widen(Some(&name)))
        .and_then(|long| short_path(&long, Text::Ansi(buffer)));
    answer(short, 0)
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
    // SAFETY: the caller's string, when given, and buffer.
    let (name, buffer) = unsafe { (InWStr::optional(name), OutBuf::new(buffer, size as usize)) };
    let short = name
        .ok_or(Failure::Error(ERROR_INVALID_PARAMETER))
        .and_then(|name| wide(&name))
        .and_then(|long| short_path(&long, Text::Wide(buffer)));
    answer(short, 0)
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
