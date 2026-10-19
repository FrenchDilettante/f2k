//! The current directory's Win32 calls, kernel32's own code over ntdll's (RtlGetCurrentDirectory_U,
//! RtlSetCurrentDirectory_U), as on Windows 2000: the narrow forms convert through the ANSI code
//! page, in a buffer of MAX_PATH units (Windows 2000's kernel32 converts into the thread's static
//! Unicode string, of that size).

use rtl::cp1252;

use crate::base::{set_last_error, set_last_nt_error};
use crate::nt::{self, UnicodeString};

/// The ANSI path limit, terminator included.
const MAX_PATH: usize = 260;
/// ERROR_FILENAME_EXCED_RANGE: a path past MAX_PATH.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// An ANSI path into UTF-16 in `out`: its length in units; None when it does not fit with its
/// terminator.
///
/// # Safety
///
/// `path` points at a NUL-terminated string.
unsafe fn widen(path: *const u8, out: &mut [u16; MAX_PATH]) -> Option<usize> {
    let mut length = 0;
    loop {
        // SAFETY: the caller's string, read to its terminator.
        let byte = unsafe { path.add(length).read() };
        if byte == 0 {
            return Some(length);
        }
        if length + 1 >= MAX_PATH {
            return None;
        }
        out[length] = cp1252::MB_TO_WC[byte as usize];
        length += 1;
    }
}

/// GetCurrentDirectoryA: the current directory (no trailing separator but a root's) into the
/// caller's buffer of `size` bytes: its length when it fits with its terminator; otherwise the size
/// it needs, terminator included, nothing written.
///
/// # Safety
///
/// `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetCurrentDirectoryA")]
pub unsafe extern "system" fn get_current_directory_a(size: u32, buffer: *mut u8) -> u32 {
    let mut wide = [0u16; MAX_PATH + 1];
    // SAFETY: ntdll's export, into a buffer of the length given.
    let bytes = unsafe { nt::RtlGetCurrentDirectory_U((2 * wide.len()) as u32, wide.as_mut_ptr()) } as usize;
    if bytes >= 2 * wide.len() {
        set_last_error(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    let length = bytes / 2;
    if (size as usize) <= length {
        return length as u32 + 1;
    }
    for (at, &unit) in wide[..length].iter().enumerate() {
        // SAFETY: inside the caller's buffer (it holds the path and its terminator).
        unsafe { buffer.add(at).write(cp1252::wc_to_mb(unit)) };
    }
    // SAFETY: as above.
    unsafe { buffer.add(length).write(0) };
    length as u32
}

/// SetCurrentDirectoryA: make the directory current (RtlSetCurrentDirectory_U); FALSE with the
/// status's error when it cannot be opened, ERROR_FILENAME_EXCED_RANGE for a path past MAX_PATH.
///
/// # Safety
///
/// `path` points at a NUL-terminated string.
#[unsafe(export_name = "f2k_export_SetCurrentDirectoryA")]
pub unsafe extern "system" fn set_current_directory_a(path: *const u8) -> u32 {
    let mut wide = [0u16; MAX_PATH];
    // SAFETY: the caller's string.
    let Some(length) = (unsafe { widen(path, &mut wide) }) else {
        set_last_error(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    };
    let string = UnicodeString {
        length: (2 * length) as u16,
        maximum_length: (2 * MAX_PATH) as u16,
        buffer: wide.as_mut_ptr(),
    };
    // SAFETY: ntdll's export, over a string whose buffer holds its length.
    let status = unsafe { nt::RtlSetCurrentDirectory_U(&string) };
    if !rtl::status::nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    1
}
