//! The environment group, kernel32's own code over ntdll's (RtlQueryEnvironmentVariable_U,
//! RtlSetEnvironmentVariable, RtlExpandEnvironmentStrings_U), as on Windows 2000: the narrow forms
//! convert through the ANSI code page (ntdll's RtlAnsiStringToUnicodeString) into buffers on the
//! process heap and share the W forms' work; GetEnvironmentStringsW hands out the live block,
//! GetEnvironmentStrings (and GetEnvironmentStringsA, the same function) an ANSI copy on the
//! process heap (ntdll's RtlUnicodeToMultiByteN).

use crate::base::{set_last_error, unicode_string};
use crate::edge::{counted, InStr, InWStr, OutBuf, Text};
use crate::error::{answer, bool_answer, Failure, ERROR_NOT_ENOUGH_MEMORY};
use crate::heap::{HeapArray, HeapString};
use crate::nt::UnicodeString;
use crate::ntcall::{self, PebLock};

/// STATUS_BUFFER_TOO_SMALL: the value or expansion did not fit.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// An A call's string converted onto the process heap (see [`HeapString::of_ansi`], as Windows
/// 2000's kernel32 converts the environment calls' strings; none is the empty string):
/// STATUS_INVALID_PARAMETER_2 for a string whose Unicode form is past a counted string's reach
/// (32766 characters and its terminator), STATUS_NO_MEMORY when the heap has no room.
fn widen(string: Option<&InStr<'_>>) -> Result<HeapString, Failure> {
    HeapString::of_ansi(string).map_err(Failure::Status)
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
/// the PEB lock), the caller's to free (FreeEnvironmentStrings); null with ERROR_NOT_ENOUGH_MEMORY
/// when the heap has no room.
#[unsafe(export_name = "f2k_export_GetEnvironmentStrings")]
pub extern "system" fn get_environment_strings() -> *mut u8 {
    let copy = {
        let lock = PebLock::acquire();
        let block = environment(&lock);
        HeapArray::<u8>::new(ntcall::unicode_to_multi_byte_size(block)).map(|mut copy| {
            ntcall::unicode_to_multi_byte_into(&mut copy, block);
            copy.into_raw()
        })
    };
    match copy {
        Ok(copy) => copy.as_ptr(),
        Err(full) => {
            set_last_error(full.error());
            core::ptr::null_mut()
        }
    }
}

/// The process's environment block through its final empty entry, read under the PEB lock (ntdll
/// edits and moves it under that lock).
fn environment(_lock: &PebLock) -> &[u16] {
    let block = crate::base::environment_block();
    // SAFETY: the process's environment block, ntdll's (aligned, on the process heap), its
    // entries each NUL-terminated through the empty one: unchanged while the PEB lock, which the
    // borrow holds, is held.
    unsafe { core::slice::from_raw_parts(block, block_length(block)) }
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
fn variable(name: &UnicodeString, mut buffer: Text<'_>) -> Result<u32, Failure> {
    // The value's length first (an empty buffer), then the value itself.
    let mut probe = UnicodeString::empty();
    let status = ntcall::query_environment_variable(name, &mut probe);
    if status != STATUS_BUFFER_TOO_SMALL && status != 0 {
        return Err(Failure::Status(status));
    }
    let value_length = probe.length as usize / 2;
    if buffer.len() <= value_length {
        return Ok(value_length as u32 + 1);
    }
    let (value, mut value_string) =
        value_buffer(value_length + 1).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    let status = ntcall::query_environment_variable(name, &mut value_string);
    if status != 0 {
        return Err(Failure::Status(status));
    }
    let units = &value[..(value_string.length as usize / 2).min(value.len())];
    buffer.put_terminated(units);
    Ok(units.len() as u32)
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
    // SAFETY: the caller's name and buffer (the contract).
    let (name, buffer) = unsafe { (InStr::optional(name), OutBuf::new(buffer, size as usize)) };
    let value = widen(name.as_ref()).and_then(|name| variable(name.string(), Text::Ansi(buffer)));
    answer(value, 0)
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
    // SAFETY: the caller's name and buffer (the contract).
    let (name, buffer) = unsafe { (InWStr::new(name), OutBuf::new(buffer, size as usize)) };
    answer(variable(&counted(&name), Text::Wide(buffer)), 0)
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
    // SAFETY: the caller's strings (the contract).
    let (name, value) = unsafe { (InStr::optional(name), InStr::optional(value)) };
    bool_answer(set_variable_a(name, value))
}

/// SetEnvironmentVariableA's work: both strings converted (the name's failure first), then the
/// variable set.
fn set_variable_a(name: Option<InStr<'_>>, value: Option<InStr<'_>>) -> Result<(), Failure> {
    let converted = (
        widen(name.as_ref()),
        value.map(|value| widen(Some(&value))).transpose(),
    );
    let (name, value) = match converted {
        (Ok(name), Ok(value)) => (name, value),
        (Err(failure), _) | (_, Err(failure)) => return Err(failure),
    };
    ntcall::set_environment_variable(name.string(), value.as_ref().map(HeapString::string))
        .map_err(Failure::Status)
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
    // SAFETY: the caller's strings (the contract).
    let (name, value) = unsafe { (InWStr::new(name), InWStr::optional(value)) };
    let (name, value) = (counted(&name), value.map(|value| counted(&value)));
    bool_answer(ntcall::set_environment_variable(&name, value.as_ref()).map_err(Failure::Status))
}

/// ExpandEnvironmentStringsW's work: the expansion and its terminator into the caller's buffer
/// when it fits; the size it needs (terminator included) either way.
fn expand(source: &UnicodeString, mut buffer: Text<'_>) -> Result<u32, Failure> {
    let mut needed = 0u32;
    let mut probe = UnicodeString::empty();
    // The size first.
    let status = ntcall::expand_environment_strings(source, &mut probe, &mut needed);
    if status != STATUS_BUFFER_TOO_SMALL && status != 0 {
        return Err(Failure::Status(status));
    }
    let units = needed as usize / 2;
    if buffer.len() < units {
        return Ok(units as u32);
    }
    let (out, mut out_string) =
        value_buffer(units).ok_or(Failure::Error(ERROR_NOT_ENOUGH_MEMORY))?;
    // Then the expansion, into a buffer of the size asked.
    let status = ntcall::expand_environment_strings(source, &mut out_string, &mut needed);
    if status != 0 {
        return Err(Failure::Status(status));
    }
    buffer.put(&out);
    Ok(units as u32)
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
    // SAFETY: the caller's source and buffer (the contract).
    let (source, buffer) = unsafe { (InStr::optional(source), OutBuf::new(buffer, size as usize)) };
    let expanded =
        widen(source.as_ref()).and_then(|source| expand(source.string(), Text::Ansi(buffer)));
    answer(expanded, 0)
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
    // SAFETY: the caller's source and buffer (the contract).
    let (source, buffer) = unsafe { (InWStr::new(source), OutBuf::new(buffer, size as usize)) };
    answer(expand(&counted(&source), Text::Wide(buffer)), 0)
}
