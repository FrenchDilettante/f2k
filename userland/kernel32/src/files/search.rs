//! SearchPath (A and W): a file looked for in a list of directories, as Windows 2000's kernel32
//! looks for it — each candidate tried through ntdll's RtlDoesFileExists_U (a file or a directory
//! answers), the one found made full through RtlGetFullPathName_U.
//!
//! The list is the caller's (directories separated by semicolons, relative ones against the current
//! directory, empty ones skipped) or, for none, the default search: the program's directory, the
//! current directory, the system directory (`<system root>\system32`), the 16-bit system directory
//! (`<system root>\system`), the Windows directory (the system root), then PATH's directories — the
//! order the SearchPath documentation gives. A name with a path of its own other than a relative
//! one (RtlDetermineDosPathNameType_U: `C:\`, `\`, `C:`, UNC, device) is tried alone; a relative
//! one (`SUB\FILE.TXT` too) under each directory. The extension is added to a name whose last
//! component has none.

use super::*;
use crate::base::unicode_string;
use crate::edge::{OutBuf, Text};
use crate::error::answer;
use crate::heap::{HeapString, HeapVec, OutOfMemory};

/// RTL_PATH_TYPE's RtlPathTypeRelative: a name the search looks for under each directory.
const RTL_PATH_TYPE_RELATIVE: u32 = 5;

/// STATUS_BUFFER_TOO_SMALL: PATH's value, longer than the probe's empty buffer.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// The default search's places under the system root, after the program's and the current
/// directory.
const SYSTEM_PLACES: [&[u8]; 3] = [b"\\system32", b"\\system", b""];

/// A list of directories on the process heap, separated by semicolons (freed with it).
pub type List = HeapVec<u16>;

/// The default search's list: the program's directory (the process parameters' ImagePathName less
/// its last component), `.` (the current directory), the three places under the system root, then
/// PATH's value (ntdll's RtlQueryEnvironmentVariable_U); none when the heap has no room.
fn default_list() -> Result<List, OutOfMemory> {
    search_list(directory_of(crate::base::image_path_name()))
}

/// A path's directory: the path less its last component (empty without a separator).
pub fn directory_of(path: &[u16]) -> &[u16] {
    &path[..path
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\'))
        .unwrap_or(0)]
}

/// The default search's list for a program in `image_directory` (see [`default_list`]): what
/// CreateProcess passes a new process as its DLL search path; none when the heap has no room.
pub fn search_list(image_directory: &[u16]) -> Result<List, OutOfMemory> {
    let mut root = [0u16; MAX_PATH];
    let root_length = crate::shared::system_root(&mut root);
    let root = &root[..root_length];
    let name: [u16; 4] = b"PATH".map(u16::from);
    let name = UnicodeString::from_units(&name).expect("a short name");
    // PATH's length.
    let mut probe = UnicodeString::empty();
    let status = ntcall::query_environment_variable(&name, &mut probe);
    let path_length = if status == STATUS_BUFFER_TOO_SMALL || status == 0 {
        probe.length as usize / 2
    } else {
        0
    };
    let places: usize = SYSTEM_PLACES.iter().map(|place| place.len()).sum();
    let mut list =
        List::with_capacity(image_directory.len() + 3 * root.len() + places + path_length + 8)?;
    let separator = u16::from(b';');
    list.extend(image_directory.iter().copied());
    list.extend([separator, u16::from(b'.')]);
    for place in SYSTEM_PLACES {
        list.push(separator);
        list.extend(root.iter().copied());
        list.extend(place.iter().copied().map(u16::from));
    }
    if path_length != 0 {
        list.push(separator);
        let room = list.spare_mut();
        assert!(
            room.len() >= path_length,
            "a search list without room for PATH"
        );
        // Into the list's room past the units pushed, no more than the string's room.
        let mut value = unicode_string(&mut room[..path_length], 0);
        if ntcall::query_environment_variable(&name, &mut value) == 0 {
            list.extend_written(value.length as usize / 2);
        }
    }
    Ok(list)
}

/// `directory` and `file` joined (a separator between them unless the directory ends in one) into
/// `out`, terminated: its length; none past MAX_PATH.
fn joined(directory: &[u16], file: &[u16], out: &mut [u16; MAX_PATH + 1]) -> Option<usize> {
    let separator = !directory.is_empty()
        && !matches!(directory.last(), Some(&unit) if unit == u16::from(b'\\') || unit == u16::from(b'/'));
    let length = directory.len() + usize::from(separator) + file.len();
    if length > MAX_PATH {
        return None;
    }
    out[..directory.len()].copy_from_slice(directory);
    if separator {
        out[directory.len()] = u16::from(b'\\');
    }
    out[length - file.len()..length].copy_from_slice(file);
    out[length] = 0;
    Some(length)
}

/// SearchPathW's work: `name` (its extension added when its last component has none) looked for
/// in `path`'s directories, or the default search's for none; the first that exists made full into
/// the caller's buffer: its length when it fits with its terminator, the file part pointing at its
/// last component; otherwise the size it needs, terminator included, nothing written. An empty
/// name is ERROR_INVALID_PARAMETER, one found nowhere ERROR_FILE_NOT_FOUND (a missing directory
/// too: the files capture), a name and extension past MAX_PATH ERROR_FILENAME_EXCED_RANGE.
#[inline(never)]
fn search_path(
    path: Option<&[u16]>,
    name: &Wide,
    extension: Option<&Wide>,
    mut buffer: Text<'_>,
    file_part: Option<Out<'_, usize>>,
) -> Result<u32, Failure> {
    let name = name.text();
    if name.is_empty() {
        return Err(Failure::Error(ERROR_INVALID_PARAMETER));
    }
    let last = name
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\') || unit == u16::from(b'/'))
        .map_or(name, |at| &name[at + 1..]);
    let extension = match extension {
        Some(extension) if !last.contains(&u16::from(b'.')) => extension.text(),
        _ => &[],
    };
    let length = name.len() + extension.len();
    if length > MAX_PATH {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut file = Wide {
        units: [0; MAX_PATH + 1],
        length,
    };
    file.units[..name.len()].copy_from_slice(name);
    file.units[name.len()..length].copy_from_slice(extension);
    let relative = ntcall::dos_path_name_type(file.terminated()) == RTL_PATH_TYPE_RELATIVE;
    let default;
    let list: &[u16] = match path {
        _ if !relative => &[],
        Some(path) => path,
        None => {
            default = default_list()?;
            &default
        }
    };
    let mut candidate = [0u16; MAX_PATH + 1];
    let mut exists = |directory: &[u16]| {
        joined(directory, file.text(), &mut candidate)
            .filter(|&length| ntcall::does_file_exist(&candidate[..=length]))
    };
    let found = if relative {
        list.split(|&unit| unit == u16::from(b';'))
            .filter(|directory| !directory.is_empty())
            .find_map(&mut exists)
    } else {
        exists(&[])
    };
    let found = found.ok_or(Failure::Error(ERROR_FILE_NOT_FOUND))?;
    let mut full = [0u16; MAX_PATH + 1];
    let (bytes, part) = ntcall::get_full_path_name(&candidate[..=found], &mut full);
    if bytes == 0 || bytes > 2 * MAX_PATH {
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

/// SearchPathW's default search for `name`, `extension` added when its last component has none:
/// the full path found, or none with the search's error set as it misses, as SearchPath sets it
/// (see [`search_path`]).
pub fn search_default(name: &Wide, extension: &Wide) -> Option<Wide> {
    let mut found = Wide {
        units: [0; MAX_PATH + 1],
        length: 0,
    };
    let room = found.units.len();
    let buffer = Text::Wide(OutBuf::from(&mut found.units[..]));
    let length = answer(search_path(None, name, Some(extension), buffer, None), 0) as usize;
    if length == 0 || length >= room {
        return None;
    }
    found.length = length;
    Some(found)
}

/// SearchPathA (see [`search_path`]): the list, the name and the extension converted first, the
/// path handed back narrowed.
///
/// # Safety
///
/// `path` and `extension` are null or NUL-terminated strings, `name` one; `buffer` holds `size`
/// bytes; `file_part` is null or points at a pointer.
#[unsafe(export_name = "f2k_export_SearchPathA")]
pub unsafe extern "system" fn search_path_a(
    path: *const u8,
    name: *const u8,
    extension: *const u8,
    size: u32,
    buffer: *mut u8,
    file_part: *mut *mut u8,
) -> u32 {
    // SAFETY: the caller's strings when given (a null name is the empty one), its buffer, and its
    // slot when given (the contract).
    let (path, name, extension, buffer, file_part) = unsafe {
        (
            InStr::optional(path),
            InStr::optional(name),
            InStr::optional(extension),
            OutBuf::new(buffer, size as usize),
            Out::optional(file_part.cast::<usize>()),
        )
    };
    let found = (|| {
        let list = path
            .map(|path| HeapString::of_ansi(Some(&path)).map_err(Failure::Status))
            .transpose()?;
        let name = widen(name.as_ref())?;
        let extension = extension
            .map(|extension| widen(Some(&extension)))
            .transpose()?;
        search_path(
            list.as_ref().map(HeapString::units),
            &name,
            extension.as_ref(),
            Text::Ansi(buffer),
            file_part,
        )
    })();
    answer(found, 0)
}

/// SearchPathW (as [`search_path_a`], over UTF-16 strings).
///
/// # Safety
///
/// `path` and `extension` are null or NUL-terminated UTF-16 strings, `name` one; `buffer` holds
/// `size` characters; `file_part` is null or points at a pointer.
#[unsafe(export_name = "f2k_export_SearchPathW")]
pub unsafe extern "system" fn search_path_w(
    path: *const u16,
    name: *const u16,
    extension: *const u16,
    size: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    // SAFETY: the caller's strings (the list and the extension when given), its buffer, and its
    // slot when given (the contract).
    let (path, name, extension, buffer, file_part) = unsafe {
        (
            InWStr::optional(path),
            InWStr::new(name),
            InWStr::optional(extension),
            OutBuf::new(buffer, size as usize),
            Out::optional(file_part.cast::<usize>()),
        )
    };
    let found = (|| {
        let list = path
            .map(|path| wide_units(&path).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY)))
            .transpose()?;
        let name = wide(&name)?;
        let extension = extension.map(|extension| wide(&extension)).transpose()?;
        search_path(
            list.as_deref(),
            &name,
            extension.as_ref(),
            Text::Wide(buffer),
            file_part,
        )
    })();
    answer(found, 0)
}
