//! The calls on a file's name: its attributes (NtQueryAttributesFile, NtQueryFullAttributesFile),
//! and the full and short forms of a path — as Windows 2000's kernel32 makes them. Setting the
//! attributes, a delete, a directory's removal or creation and a rename change the volume: they come
//! with the write side.

use rtl::status::nt_success;

use super::find::{find_close, find_first_w, FindDataW};
use super::*;
use crate::base::set_last_nt_error;

const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;

/// A name's NT path; none with ERROR_PATH_NOT_FOUND when ntdll cannot make it.
fn nt_path(name: &Wide) -> Option<NtPath> {
    let path = NtPath::of(name.terminated());
    if path.is_none() {
        set_last_error(ERROR_PATH_NOT_FOUND);
    }
    path
}

/// GetFileAttributesA: the file's or directory's attributes (NtQueryAttributesFile);
/// INVALID_FILE_ATTRIBUTES with the error.
///
/// # Safety
///
/// `name` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_GetFileAttributesA")]
pub unsafe extern "system" fn get_file_attributes_a(name: *const u8) -> u32 {
    // SAFETY: the caller's string.
    let Some(path) = (unsafe { widen(name) }).as_ref().and_then(nt_path) else {
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

/// GetFileAttributesExA: GetFileExInfoStandard alone (ERROR_INVALID_PARAMETER for another level):
/// the attributes, the three times and the size (NtQueryFullAttributesFile).
///
/// # Safety
///
/// `name` is a NUL-terminated string; `info` points at a WIN32_FILE_ATTRIBUTE_DATA.
#[unsafe(export_name = "f2k_export_GetFileAttributesExA")]
pub unsafe extern "system" fn get_file_attributes_ex_a(name: *const u8, level: u32, info: *mut u8) -> u32 {
    if level != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string.
    let Some(path) = (unsafe { widen(name) }).as_ref().and_then(nt_path) else {
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

/// GetFullPathNameA: the path made absolute and folded (RtlGetFullPathName_U; no lookup), its
/// trailing separator kept, into the caller's buffer: its length when it fits with its terminator,
/// the file part pointing at its last component (null when it ends in a separator); otherwise the
/// size it needs, terminator included. An empty path is ERROR_PATH_NOT_FOUND, a full one past
/// MAX_PATH ERROR_FILENAME_EXCED_RANGE (assumptions, unverified against Windows 2000).
///
/// # Safety
///
/// `name` is a NUL-terminated string; `buffer` holds `size` bytes; `file_part` is null or points at
/// a pointer.
#[unsafe(export_name = "f2k_export_GetFullPathNameA")]
pub unsafe extern "system" fn get_full_path_name_a(name: *const u8, size: u32, buffer: *mut u8, file_part: *mut *mut u8) -> u32 {
    // SAFETY: the caller's string.
    let Some(name) = (unsafe { widen(name) }) else {
        return 0;
    };
    let mut full = [0u16; MAX_PATH + 1];
    let mut part = core::ptr::null_mut();
    // SAFETY: ntdll's export, into the buffer above.
    let bytes = unsafe { nt::RtlGetFullPathName_U(name.terminated().as_ptr(), 2 * full.len() as u32, full.as_mut_ptr(), &mut part) } as usize;
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
    unsafe { narrow_into(&full[..length], buffer) };
    if !file_part.is_null() {
        let at = (!part.is_null()).then(|| (part as usize - full.as_ptr() as usize) / 2);
        // SAFETY: the caller's slot; the part lies in the caller's buffer.
        unsafe { *file_part = at.map_or(core::ptr::null_mut(), |at| buffer.add(at)) };
    }
    length as u32
}

/// Whether a component is an 8.3 name GetShortPathName leaves as it is (IsShortName_U's test):
/// 1 to 8 name characters, at most one dot and 3 extension characters after it, none a space nor
/// one an 8.3 name cannot hold; `.` and `..` are.
pub fn is_short_name(component: &[u16]) -> bool {
    let dot = u16::from(b'.');
    if component == [dot] || component == [dot, dot] {
        return true;
    }
    let valid = |unit: u16| unit > 0x20 && unit < 0x80 && !b"\"*+,/:;<=>?[\\]|".contains(&(unit as u8));
    let (base, extension) = match component.iter().position(|&unit| unit == dot) {
        Some(at) => (&component[..at], Some(&component[at + 1..])),
        None => (component, None),
    };
    (1..=8).contains(&base.len())
        && base.iter().all(|&unit| valid(unit))
        && extension.is_none_or(|extension| extension.len() <= 3 && extension.iter().all(|&unit| unit != dot && valid(unit)))
}

/// GetShortPathNameA, Windows 2000's walk: the path must name something (its attributes'
/// failure is the call's); its prefix (a drive, a root, a UNC share) is kept, and each component an
/// 8.3 name already stays as written, every other one replaced by its 8.3 name as a search of it
/// reports it. The result into the caller's buffer of `size` characters: its length when it fits
/// with its terminator, otherwise the size it needs.
///
/// # Safety
///
/// `name` is a NUL-terminated string; `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetShortPathNameA")]
pub unsafe extern "system" fn get_short_path_name_a(name: *const u8, buffer: *mut u8, size: u32) -> u32 {
    if name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's string.
    if unsafe { get_file_attributes_a(name) } == INVALID_FILE_ATTRIBUTES {
        return 0;
    }
    // SAFETY: as above (it converted once).
    let Some(long) = (unsafe { widen(name) }) else {
        return 0;
    };
    let units = long.text();
    let separator = |unit: u16| unit == u16::from(b'\\') || unit == u16::from(b'/');
    // The prefix: `\\server\share\`, `X:` and its separator, or a root separator.
    let prefix = if units.len() >= 2 && separator(units[0]) && separator(units[1]) {
        let mut seen = 0;
        units.iter().position(|&unit| {
            seen += usize::from(separator(unit));
            seen == 4
        }).map_or(units.len(), |at| at + 1)
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
        let end = rest.iter().position(|&unit| separator(unit)).unwrap_or(rest.len());
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
            let mut wide = Wide { units: [0; MAX_PATH + 1], length: length + component.len() };
            wide.units[..length].copy_from_slice(&out[..length]);
            wide.units[length..wide.length].copy_from_slice(component);
            replacement = FindDataW::zeroed();
            let handle = find_first_w(&wide, &mut replacement);
            if handle == INVALID_HANDLE_VALUE {
                return 0;
            }
            find_close(handle);
            if replacement.alternate().is_empty() { replacement.name() } else { replacement.alternate() }
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
    unsafe { narrow_into(&out[..length], buffer) };
    length as u32
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
        for short in ["SMALL.TXT", "small.txt", "SUB", "LONGFI~1.TXT", ".", "..", "A.B"] {
            assert!(is_short_name(&wide(short)), "{short}");
        }
        for long in ["Long File Name.txt", "ABCDEFGHI.TXT", "A.TEXT", "A.B.C", ".X", "A+B", ""] {
            assert!(!is_short_name(&wide(long)), "{long}");
        }
    }
}
