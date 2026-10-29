//! The environment group, kernel32's own code over ntdll's (RtlQueryEnvironmentVariable_U,
//! RtlSetEnvironmentVariable, RtlExpandEnvironmentStrings_U), as on Windows 2000: the narrow forms
//! convert through the ANSI code page (ntdll's RtlAnsiStringToUnicodeString) into buffers on the
//! process heap and share the W forms' work; GetEnvironmentStringsW hands out the live block,
//! GetEnvironmentStrings (and GetEnvironmentStringsA, the same function) an ANSI copy on the
//! process heap (ntdll's RtlUnicodeToMultiByteN).

use crate::base::{set_last_error, set_last_nt_error, unicode_string, wide_string, Text};
use crate::error::ERROR_NOT_ENOUGH_MEMORY;
use crate::heap::{HeapArray, HeapString};
use crate::nt::{self, UnicodeString};
use crate::ntcall::{self, PebLock};

/// STATUS_BUFFER_TOO_SMALL: the value or expansion did not fit.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// An A call's string converted onto the process heap (see [`HeapString::from_ansi`], as Windows
/// 2000's kernel32 converts the environment calls' strings): STATUS_INVALID_PARAMETER_2 for a
/// string whose Unicode form is past a counted string's reach (32766 characters and its
/// terminator), STATUS_NO_MEMORY when the heap has no room.
///
/// # Safety
///
/// `string` is null (the empty string) or points at a NUL-terminated string.
unsafe fn widen(string: *const u8) -> Result<HeapString, u32> {
    // SAFETY: the caller's contract.
    unsafe { HeapString::from_ansi(string) }
}

/// A buffer of `units` UTF-16 units on the process heap for a value ntdll writes, and the string
/// over its start ntdll writes it through, empty, its room the buffer's.
fn value_buffer(units: usize) -> Option<(HeapArray<u16>, UnicodeString)> {
    let mut buffer = HeapArray::new(units).ok()?;
    let string = unicode_string(&mut buffer, 0);
    Some((buffer, string))
}

/// GetEnvironmentStringsW: the environment block itself, as it stands.
#[unsafe(export_name = "f2k_export_GetEnvironmentStringsW")]
pub extern "system" fn get_environment_strings_w() -> *mut u16 {
    crate::base::environment_block()
}

/// FreeEnvironmentStringsW: the block GetEnvironmentStringsW returns is the environment itself;
/// nothing to free.
#[unsafe(export_name = "f2k_export_FreeEnvironmentStringsW")]
pub extern "system" fn free_environment_strings_w(_block: *mut u16) -> u32 {
    1
}

/// GetEnvironmentStringsA: the same function as GetEnvironmentStrings, under its A name (Windows
/// 2000 exports both).
#[unsafe(export_name = "f2k_export_GetEnvironmentStringsA")]
pub extern "system" fn get_environment_strings_a() -> *mut u8 {
    get_environment_strings()
}

/// GetEnvironmentStrings: an ANSI copy of the environment block on the process heap (taken under
/// the PEB lock); null with ERROR_NOT_ENOUGH_MEMORY when the heap has no room.
#[unsafe(export_name = "f2k_export_GetEnvironmentStrings")]
pub extern "system" fn get_environment_strings() -> *mut u8 {
    let copy = {
        let _lock = PebLock::acquire();
        let block = crate::base::environment_block();
        // SAFETY: the process's environment block, read under the PEB lock.
        let bytes = 2 * unsafe { block_length(block) } as u32;
        let mut size = 0;
        // SAFETY: ntdll's export, over the block's `bytes` into the local size.
        unsafe { nt::RtlUnicodeToMultiByteSize(&mut size, block, bytes) };
        let copy = ntcall::allocate_heap(size as usize);
        if let Some(copy) = copy {
            // SAFETY: ntdll's export, from the block's `bytes` into the fresh copy of `size`.
            unsafe {
                nt::RtlUnicodeToMultiByteN(copy.as_ptr(), size, core::ptr::null_mut(), block, bytes)
            };
        }
        copy
    };
    match copy {
        Some(copy) => copy.as_ptr(),
        None => {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            core::ptr::null_mut()
        }
    }
}

/// An environment block's length in units (or bytes, for an ANSI one), its final NUL included:
/// through its final empty entry (an empty block's two NULs count). The block may sit at any
/// address (a caller's).
///
/// # Safety
///
/// `block` points at an environment block: entries each NUL-terminated, an empty one last.
pub unsafe fn block_length<T: Copy + Default + PartialEq>(block: *const T) -> usize {
    let mut at = 0;
    loop {
        // SAFETY: the caller's block, its entries each read to their NUL, through the empty one.
        let entry = unsafe { rtl::cstr::len_until_nul(block.add(at)) };
        if entry == 0 {
            return (at + 1).max(2);
        }
        at += entry + 1;
    }
}

/// FreeEnvironmentStringsA: free a copy GetEnvironmentStrings made (RtlFreeHeap on the process
/// heap: TRUE once freed, and for a null pointer).
///
/// # Safety
///
/// `block` is null or a copy GetEnvironmentStrings made.
#[unsafe(export_name = "f2k_export_FreeEnvironmentStringsA")]
pub unsafe extern "system" fn free_environment_strings_a(block: *mut u8) -> u32 {
    // SAFETY: the caller's copy, on the process heap, which the caller gives back.
    u32::from(block.is_null() || unsafe { ntcall::free_heap(block) })
}

/// GetEnvironmentVariableW's work: the variable's value into the buffer — its length, terminator
/// excluded, when it fits; the size it needs, terminator included, when it does not (nothing
/// written). ERROR_ENVVAR_NOT_FOUND (and 0) for an unset variable.
///
/// # Safety
///
/// `buffer` holds `size` characters.
unsafe fn variable(name_string: &UnicodeString, buffer: Text, size: u32) -> u32 {
    // The value's length first (an empty buffer), then the value itself.
    let mut probe = UnicodeString::empty();
    // SAFETY: ntdll's export, over the strings above.
    let status = unsafe {
        nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), name_string, &mut probe)
    };
    if status != STATUS_BUFFER_TOO_SMALL && status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    let value_length = probe.length as usize / 2;
    if (size as usize) <= value_length {
        return value_length as u32 + 1;
    }
    let Some((value, mut value_string)) = value_buffer(value_length + 1) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    // SAFETY: as above.
    let status = unsafe {
        nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), name_string, &mut value_string)
    };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    let units = &value[..(value_string.length as usize / 2).min(value.len())];
    // SAFETY: the caller's buffer holds the value and its terminator.
    unsafe { buffer.put_terminated(units) };
    units.len() as u32
}

/// GetEnvironmentVariableA (see [`variable`]): ERROR_INVALID_PARAMETER for a name that does not
/// convert ([`widen`]).
///
/// # Safety
///
/// `name` points at a NUL-terminated string, `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetEnvironmentVariableA")]
pub unsafe extern "system" fn get_environment_variable_a(
    name: *const u8,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: the caller's name.
    let wide_name = match unsafe { widen(name) } {
        Ok(wide) => wide,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    // SAFETY: the caller's buffer.
    unsafe { variable(wide_name.string(), Text::Ansi(buffer), size) }
}

/// GetEnvironmentVariableW (see [`variable`]).
///
/// # Safety
///
/// `name` points at a NUL-terminated UTF-16 string, `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_GetEnvironmentVariableW")]
pub unsafe extern "system" fn get_environment_variable_w(
    name: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    // SAFETY: the caller's name and buffer.
    unsafe { variable(&wide_string(name), Text::Wide(buffer), size) }
}

/// SetEnvironmentVariableA: set the variable to the value, or delete it for a null value; FALSE
/// with the status's error when a string does not convert ([`widen`]: ERROR_INVALID_PARAMETER past
/// 32766 characters) or ntdll refuses (an invalid name: ERROR_INVALID_PARAMETER).
///
/// # Safety
///
/// `name` and `value` (when given) point at NUL-terminated strings.
#[unsafe(export_name = "f2k_export_SetEnvironmentVariableA")]
pub unsafe extern "system" fn set_environment_variable_a(name: *const u8, value: *const u8) -> u32 {
    // SAFETY: the caller's strings.
    let converted = unsafe {
        (
            widen(name),
            if value.is_null() {
                Ok(None)
            } else {
                widen(value).map(Some)
            },
        )
    };
    let (wide_name, value) = match converted {
        (Ok(name), Ok(value)) => (name, value),
        (Err(status), _) | (_, Err(status)) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    // SAFETY: ntdll's export, over the strings above.
    let status = unsafe {
        nt::RtlSetEnvironmentVariable(
            core::ptr::null_mut(),
            wide_name.string(),
            value.as_ref().map_or(core::ptr::null(), |wide| {
                wide.string() as *const UnicodeString
            }),
        )
    };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// SetEnvironmentVariableW: as SetEnvironmentVariableA, the strings wide.
///
/// # Safety
///
/// `name` and `value` (when given) point at NUL-terminated strings.
#[unsafe(export_name = "f2k_export_SetEnvironmentVariableW")]
pub unsafe extern "system" fn set_environment_variable_w(
    name: *const u16,
    value: *const u16,
) -> u32 {
    // SAFETY: the caller's strings.
    let (name, value) = unsafe {
        (
            wide_string(name),
            (!value.is_null()).then(|| wide_string(value)),
        )
    };
    // SAFETY: ntdll's export, over the caller's strings.
    let status = unsafe {
        nt::RtlSetEnvironmentVariable(
            core::ptr::null_mut(),
            &name,
            value
                .as_ref()
                .map_or(core::ptr::null(), |string| string as *const UnicodeString),
        )
    };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// ExpandEnvironmentStringsW's work: the expansion and its terminator into the caller's buffer
/// when it fits; the size it needs (terminator included) either way.
///
/// # Safety
///
/// `buffer` holds `size` characters.
unsafe fn expand(source_string: &UnicodeString, buffer: Text, size: u32) -> u32 {
    let mut needed = 0u32;
    let mut probe = UnicodeString::empty();
    // SAFETY: ntdll's export: the size first.
    let status = unsafe {
        nt::RtlExpandEnvironmentStrings_U(
            core::ptr::null_mut(),
            source_string,
            &mut probe,
            &mut needed,
        )
    };
    if status != STATUS_BUFFER_TOO_SMALL && status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    let units = needed as usize / 2;
    if (size as usize) < units {
        return units as u32;
    }
    let Some((out, mut out_string)) = value_buffer(units) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    // SAFETY: as above, into a buffer of the size asked.
    let status = unsafe {
        nt::RtlExpandEnvironmentStrings_U(
            core::ptr::null_mut(),
            source_string,
            &mut out_string,
            &mut needed,
        )
    };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    // SAFETY: the caller's buffer holds the expansion and its terminator.
    unsafe { buffer.put(&out) };
    units as u32
}

/// ExpandEnvironmentStringsA (see [`expand`]): ERROR_INVALID_PARAMETER (and 0) for a source that
/// does not convert ([`widen`]).
///
/// # Safety
///
/// `source` points at a NUL-terminated string, `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_ExpandEnvironmentStringsA")]
pub unsafe extern "system" fn expand_environment_strings_a(
    source: *const u8,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: the caller's source.
    let wide_source = match unsafe { widen(source) } {
        Ok(wide) => wide,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    // SAFETY: the caller's buffer.
    unsafe { expand(wide_source.string(), Text::Ansi(buffer), size) }
}

/// ExpandEnvironmentStringsW (see [`expand`]).
///
/// # Safety
///
/// `source` points at a NUL-terminated UTF-16 string, `buffer` holds `size` characters.
#[unsafe(export_name = "f2k_export_ExpandEnvironmentStringsW")]
pub unsafe extern "system" fn expand_environment_strings_w(
    source: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    // SAFETY: the caller's source and buffer.
    unsafe { expand(&wide_string(source), Text::Wide(buffer), size) }
}
