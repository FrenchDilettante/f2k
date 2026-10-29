//! The current directory's Win32 calls, kernel32's own code over ntdll's (RtlGetCurrentDirectory_U,
//! RtlSetCurrentDirectory_U), as on Windows 2000, each call's work its W form's: the narrow forms
//! convert through the ANSI code page (ntdll's RtlAnsiStringToUnicodeString), in a buffer of
//! MAX_PATH units (Windows 2000's kernel32 converts into the thread's static Unicode string, of
//! that size), and hand theirs back narrowed ([`Text`]). The Windows and system directories, which
//! never change, are here too.

use crate::base::unicode_string;
use crate::edge::{ansi_into, wide_units, InStr, InWStr, OutBuf, Text};
use crate::error::{answer, bool_answer, Failure, ERROR_NOT_ENOUGH_MEMORY};
use crate::ntcall;

/// The ANSI path limit, terminator included.
const MAX_PATH: usize = 260;
/// ERROR_FILENAME_EXCED_RANGE: a path past MAX_PATH.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// GetCurrentDirectoryW's work: the current directory (no trailing separator but a root's) into
/// the caller's buffer: its length when it fits with its terminator; otherwise the size it needs,
/// terminator included, nothing written.
fn current_directory(mut buffer: Text<'_>) -> Result<u32, Failure> {
    let mut wide = [0u16; MAX_PATH + 1];
    let bytes = ntcall::current_directory(&mut wide);
    if bytes >= 2 * wide.len() {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let length = bytes / 2;
    if buffer.len() <= length {
        return Ok(length as u32 + 1);
    }
    buffer.put_terminated(&wide[..length]);
    Ok(length as u32)
}

/// GetCurrentDirectoryA (see [`current_directory`]).
///
/// # Safety
///
/// `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetCurrentDirectoryA")]
pub unsafe extern "system" fn get_current_directory_a(size: u32, buffer: *mut u8) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    answer(current_directory(Text::Ansi(buffer)), 0)
}

/// GetCurrentDirectoryW (see [`current_directory`]).
///
/// # Safety
///
/// `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetCurrentDirectoryW")]
pub unsafe extern "system" fn get_current_directory_w(size: u32, buffer: *mut u16) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    answer(current_directory(Text::Wide(buffer)), 0)
}

/// SetCurrentDirectoryW's work: make the directory of the first `length` units of `wide` current
/// (RtlSetCurrentDirectory_U); FALSE with the status's error when it cannot be opened.
fn set_current_directory(wide: &mut [u16], length: usize) -> Result<(), Failure> {
    ntcall::set_current_directory(&unicode_string(wide, length)).map_err(Failure::Status)
}

/// SetCurrentDirectoryA: the path converted (ERROR_FILENAME_EXCED_RANGE for one past MAX_PATH),
/// then [`set_current_directory`].
///
/// # Safety
///
/// `path` points at a NUL-terminated string.
#[unsafe(export_name = "f2k_export_SetCurrentDirectoryA")]
pub unsafe extern "system" fn set_current_directory_a(path: *const u8) -> u32 {
    // SAFETY: the caller's string (the contract), or null (the empty one).
    let path = unsafe { InStr::optional(path) };
    bool_answer(set_current_directory_narrow(path))
}

/// SetCurrentDirectoryA's work.
fn set_current_directory_narrow(path: Option<InStr<'_>>) -> Result<(), Failure> {
    let mut wide = [0u16; MAX_PATH];
    let length =
        ansi_into(path.as_ref(), &mut wide).ok_or(Failure::Error(ERROR_FILENAME_EXCED_RANGE))?;
    set_current_directory(&mut wide, length)
}

/// SetCurrentDirectoryW: the path copied, as the A call's conversion leaves its own
/// (ERROR_FILENAME_EXCED_RANGE past MAX_PATH: an assumption, unverified), then
/// [`set_current_directory`].
///
/// # Safety
///
/// `path` points at a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_SetCurrentDirectoryW")]
pub unsafe extern "system" fn set_current_directory_w(path: *const u16) -> u32 {
    // SAFETY: the caller's string (the contract).
    let path = unsafe { InWStr::new(path) };
    bool_answer(set_current_directory_wide(&path))
}

/// SetCurrentDirectoryW's work.
fn set_current_directory_wide(path: &InWStr<'_>) -> Result<(), Failure> {
    let units = wide_units(path).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    if units.len() + 1 >= MAX_PATH {
        return Err(Failure::Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut wide = [0u16; MAX_PATH];
    wide[..units.len()].copy_from_slice(&units);
    set_current_directory(&mut wide, units.len())
}

/// The system directory under the system root.
const SYSTEM32: &[u8] = b"\\system32";

/// The Windows directory — the system root, KUSER_SHARED_DATA's NtSystemRoot, where Windows 2000's
/// kernel32 takes it from — or, for `system`, the system directory under it, into the caller's
/// buffer of `size` characters: its length when it fits with its terminator; otherwise the size it
/// needs, terminator included, nothing written and the last error untouched (the runtime capture).
fn windows_directory(system: bool, mut buffer: Text<'_>) -> u32 {
    let mut root = [0u16; MAX_PATH];
    let mut length = crate::shared::system_root(&mut root);
    let mut directory = [0u16; MAX_PATH + SYSTEM32.len()];
    directory[..length].copy_from_slice(&root[..length]);
    if system {
        for &byte in SYSTEM32 {
            directory[length] = u16::from(byte);
            length += 1;
        }
    }
    if buffer.len() <= length {
        return length as u32 + 1;
    }
    buffer.put_terminated(&directory[..length]);
    length as u32
}

/// GetWindowsDirectoryA (see [`windows_directory`]).
///
/// # Safety
///
/// `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetWindowsDirectoryA")]
pub unsafe extern "system" fn get_windows_directory_a(buffer: *mut u8, size: u32) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    windows_directory(false, Text::Ansi(buffer))
}

/// GetWindowsDirectoryW (see [`windows_directory`]).
///
/// # Safety
///
/// `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetWindowsDirectoryW")]
pub unsafe extern "system" fn get_windows_directory_w(buffer: *mut u16, size: u32) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    windows_directory(false, Text::Wide(buffer))
}

/// GetSystemDirectoryA (see [`windows_directory`]): `<system root>\system32`.
///
/// # Safety
///
/// `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetSystemDirectoryA")]
pub unsafe extern "system" fn get_system_directory_a(buffer: *mut u8, size: u32) -> u32 {
    // SAFETY: the caller's buffer (the contract).
    let buffer = unsafe { OutBuf::new(buffer, size as usize) };
    windows_directory(true, Text::Ansi(buffer))
}
