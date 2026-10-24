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
use crate::base::{set_last_nt_error, Text};
use crate::nt::{AnsiString, UnicodeString};

/// RTL_PATH_TYPE's RtlPathTypeRelative: a name the search looks for under each directory.
const RTL_PATH_TYPE_RELATIVE: u32 = 5;

/// STATUS_BUFFER_TOO_SMALL: PATH's value, longer than the probe's empty buffer.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// The default search's places under the system root, after the program's and the current
/// directory.
const SYSTEM_PLACES: [&[u8]; 3] = [b"\\system32", b"\\system", b""];

/// A list of directories on the process heap, separated by semicolons (freed with it).
struct List {
    block: *mut u16,
    length: usize,
}

impl List {
    /// A list of room for `units` units; none when the heap has no room.
    fn new(units: usize) -> Option<List> {
        // SAFETY: ntdll's export, on the process heap.
        let block = unsafe { nt::RtlAllocateHeap(process_heap(), 0, 2 * units.max(1)) };
        (!block.is_null()).then_some(List {
            block: block as *mut u16,
            length: 0,
        })
    }

    /// Add `units` at the end.
    fn push(&mut self, units: impl IntoIterator<Item = u16>) {
        for unit in units {
            // SAFETY: the block was made for every unit pushed.
            unsafe { self.block.add(self.length).write(unit) };
            self.length += 1;
        }
    }

    fn units(&self) -> &[u16] {
        // SAFETY: the block holds the units pushed.
        unsafe { core::slice::from_raw_parts(self.block, self.length) }
    }
}

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over kernel32's own block.
        unsafe { nt::RtlFreeHeap(process_heap(), 0, self.block as *mut u8) };
    }
}

/// The default search's list: the program's directory (the process parameters' ImagePathName less
/// its last component), `.` (the current directory), the three places under the system root, then
/// PATH's value (ntdll's RtlQueryEnvironmentVariable_U); none when the heap has no room.
fn default_list() -> Option<List> {
    // SAFETY: the process parameters' ImagePathName, the process's own string.
    let image = unsafe { crate::base::units(crate::base::process_parameters() + 0x38) };
    let image_directory = &image[..image
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\'))
        .unwrap_or(0)];
    let mut root = [0u16; MAX_PATH];
    let root_length = crate::shared::system_root(&mut root);
    let root = &root[..root_length];
    let name: [u16; 4] = b"PATH".map(u16::from);
    let name = UnicodeString {
        length: 8,
        maximum_length: 8,
        buffer: name.as_ptr() as *mut u16,
    };
    let mut probe = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
    // SAFETY: ntdll's export, over the strings above: PATH's length.
    let status =
        unsafe { nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), &name, &mut probe) };
    let path_length = if status == STATUS_BUFFER_TOO_SMALL || status == 0 {
        probe.length as usize / 2
    } else {
        0
    };
    let places: usize = SYSTEM_PLACES.iter().map(|place| place.len()).sum();
    let mut list = List::new(image_directory.len() + 3 * root.len() + places + path_length + 8)?;
    let separator = u16::from(b';');
    list.push(image_directory.iter().copied());
    list.push([separator, u16::from(b'.')]);
    for place in SYSTEM_PLACES {
        list.push([separator]);
        list.push(root.iter().copied());
        list.push(place.iter().copied().map(u16::from));
    }
    if path_length != 0 {
        list.push([separator]);
        let mut value = UnicodeString {
            length: 0,
            maximum_length: (2 * path_length) as u16,
            // SAFETY: the block holds PATH's value after the units pushed.
            buffer: unsafe { list.block.add(list.length) },
        };
        // SAFETY: ntdll's export, into the list's block.
        let status =
            unsafe { nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), &name, &mut value) };
        if status == 0 {
            list.length += value.length as usize / 2;
        }
    }
    Some(list)
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
/// the caller's buffer of `size` characters: its length when it fits with its terminator, the file
/// part pointing at its last component; otherwise the size it needs, terminator included, nothing
/// written. An empty name is ERROR_INVALID_PARAMETER, one found nowhere ERROR_FILE_NOT_FOUND (a
/// missing directory too: the files capture), a name and extension past MAX_PATH
/// ERROR_FILENAME_EXCED_RANGE.
///
/// # Safety
///
/// `buffer` holds `size` characters; `file_part` is null or points at a pointer.
#[inline(never)]
unsafe fn search_path(
    path: Option<&[u16]>,
    name: &Wide,
    extension: Option<&Wide>,
    size: u32,
    buffer: Text,
    file_part: *mut usize,
) -> u32 {
    let name = name.text();
    if name.is_empty() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
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
        set_last_error(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    let mut file = Wide {
        units: [0; MAX_PATH + 1],
        length,
    };
    file.units[..name.len()].copy_from_slice(name);
    file.units[name.len()..length].copy_from_slice(extension);
    // SAFETY: ntdll's export, over the terminated name.
    let relative = unsafe { nt::RtlDetermineDosPathNameType_U(file.terminated().as_ptr()) }
        == RTL_PATH_TYPE_RELATIVE;
    let default;
    let list: &[u16] = match path {
        _ if !relative => &[],
        Some(path) => path,
        None => {
            default = match default_list() {
                Some(list) => list,
                None => {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return 0;
                }
            };
            default.units()
        }
    };
    let mut candidate = [0u16; MAX_PATH + 1];
    let found = if relative {
        list.split(|&unit| unit == u16::from(b';'))
            .filter(|directory| !directory.is_empty())
            .find(|directory| {
                joined(directory, file.text(), &mut candidate).is_some()
                    // SAFETY: ntdll's export, over the terminated candidate.
                    && unsafe { nt::RtlDoesFileExists_U(candidate.as_ptr()) } != 0
            })
            .is_some()
    } else {
        joined(&[], file.text(), &mut candidate).is_some()
            // SAFETY: as above.
            && unsafe { nt::RtlDoesFileExists_U(candidate.as_ptr()) } != 0
    };
    if !found {
        set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    let mut full = [0u16; MAX_PATH + 1];
    let mut part = core::ptr::null_mut();
    // SAFETY: ntdll's export, into the buffer above.
    let bytes = unsafe {
        nt::RtlGetFullPathName_U(
            candidate.as_ptr(),
            2 * full.len() as u32,
            full.as_mut_ptr(),
            &mut part,
        )
    } as usize;
    if bytes == 0 || bytes > 2 * MAX_PATH {
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

/// A narrow search list converted through the ANSI code page (ntdll's RtlInitAnsiString and
/// RtlAnsiStringToUnicodeString, onto the process heap: freed with it).
struct ConvertedList(UnicodeString);

impl ConvertedList {
    /// The list converted; none (the status's error set) when it does not convert.
    ///
    /// # Safety
    ///
    /// `list` is a NUL-terminated string.
    unsafe fn of(list: *const u8) -> Option<ConvertedList> {
        let mut ansi = AnsiString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        let mut wide = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        // SAFETY: ntdll's exports, over the caller's string and the structures above.
        let status = unsafe {
            nt::RtlInitAnsiString(&mut ansi, list);
            nt::RtlAnsiStringToUnicodeString(&mut wide, &ansi, 1)
        };
        if !rtl::status::nt_success(status) {
            set_last_nt_error(status);
            return None;
        }
        Some(ConvertedList(wide))
    }

    fn units(&self) -> &[u16] {
        if self.0.length == 0 {
            return &[];
        }
        // SAFETY: ntdll's buffer holds the string's length.
        unsafe { core::slice::from_raw_parts(self.0.buffer, self.0.length as usize / 2) }
    }
}

impl Drop for ConvertedList {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over the string its conversion allocated.
        unsafe { nt::RtlFreeUnicodeString(&mut self.0) };
    }
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
    let list = if path.is_null() {
        None
    } else {
        // SAFETY: the caller's string.
        match unsafe { ConvertedList::of(path) } {
            Some(list) => Some(list),
            None => return 0,
        }
    };
    // SAFETY: the caller's strings.
    let Some(name) = (unsafe { widen(name) }) else {
        return 0;
    };
    let extension = if extension.is_null() {
        None
    } else {
        // SAFETY: the caller's string.
        match unsafe { widen(extension) } {
            Some(extension) => Some(extension),
            None => return 0,
        }
    };
    // SAFETY: the caller's buffer and slot.
    unsafe {
        search_path(
            list.as_ref().map(ConvertedList::units),
            &name,
            extension.as_ref(),
            size,
            Text::Ansi(buffer),
            file_part as *mut usize,
        )
    }
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
    // SAFETY: the caller's strings.
    let list = (!path.is_null()).then(|| unsafe { crate::base::wide_units(path) });
    let Some(name) = (unsafe { wide(name) }) else {
        return 0;
    };
    let extension = if extension.is_null() {
        None
    } else {
        // SAFETY: the caller's string.
        match unsafe { wide(extension) } {
            Some(extension) => Some(extension),
            None => return 0,
        }
    };
    // SAFETY: the caller's buffer and slot.
    unsafe {
        search_path(
            list,
            &name,
            extension.as_ref(),
            size,
            Text::Wide(buffer),
            file_part as *mut usize,
        )
    }
}
