//! The environment group, kernel32's own code over ntdll's (RtlQueryEnvironmentVariable_U,
//! RtlSetEnvironmentVariable, RtlExpandEnvironmentStrings_U), as on Windows 2000: the narrow forms
//! convert through the ANSI code page into buffers on the process heap; GetEnvironmentStringsW hands
//! out the live block, GetEnvironmentStrings an ANSI copy on the process heap.

use rtl::cp1252;

use crate::base::{set_last_error, set_last_nt_error};
use crate::error::ERROR_NOT_ENOUGH_MEMORY;
use crate::nt::{self, UnicodeString};

/// STATUS_BUFFER_TOO_SMALL: the value or expansion did not fit.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// A buffer of `units` UTF-16 units on the process heap, freed when dropped.
struct Wide {
    buffer: *mut u16,
    units: usize,
}

impl Wide {
    fn new(units: usize) -> Option<Wide> {
        // SAFETY: ntdll's heap, on the process heap.
        let buffer = unsafe { nt::RtlAllocateHeap(crate::base::process_heap(), 0, 2 * units.max(1)) } as *mut u16;
        (!buffer.is_null()).then_some(Wide { buffer, units })
    }

    /// The string of its first `length` units, its room the buffer's.
    fn string(&self, length: usize) -> UnicodeString {
        UnicodeString { length: (2 * length) as u16, maximum_length: (2 * self.units).min(0xFFFE) as u16, buffer: self.buffer }
    }

    fn units(&self, length: usize) -> &[u16] {
        // SAFETY: the buffer holds `units` units, `length` of them written.
        unsafe { core::slice::from_raw_parts(self.buffer, length.min(self.units)) }
    }
}

impl Drop for Wide {
    fn drop(&mut self) {
        // SAFETY: the buffer this allocated.
        unsafe { nt::RtlFreeHeap(crate::base::process_heap(), 0, self.buffer as *mut u8) };
    }
}

/// The length of the NUL-terminated string at `string`, in units.
///
/// # Safety
///
/// `string` points at a NUL-terminated string.
unsafe fn length<U: Copy + Default + PartialEq>(string: *const U) -> usize {
    let mut at = 0;
    // SAFETY: the caller's string, read to its terminator.
    while unsafe { string.add(at).read_unaligned() } != U::default() {
        at += 1;
    }
    at
}

/// The most characters a counted Unicode string holds with its terminator (its byte length is a
/// word: MAX_USTRING, 0xFFFE bytes, terminator included).
const MAX_CONVERTED: usize = 0xFFFE / 2 - 1;

/// STATUS_INVALID_PARAMETER_2 (RtlAnsiStringToUnicodeString's refusal of a string too long to
/// count) and STATUS_NO_MEMORY.
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// An ANSI string, widened through code page 1252 onto the process heap, as Windows 2000's
/// RtlAnsiStringToUnicodeString converts it: the buffer and its length; STATUS_INVALID_PARAMETER_2
/// past [`MAX_CONVERTED`] characters, STATUS_NO_MEMORY when the heap has no room.
///
/// # Safety
///
/// `string` points at a NUL-terminated string.
unsafe fn widen(string: *const u8) -> Result<(Wide, usize), u32> {
    // SAFETY: the caller's contract.
    let length = unsafe { length(string) };
    if length > MAX_CONVERTED {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    let wide = Wide::new(length + 1).ok_or(STATUS_NO_MEMORY)?;
    for at in 0..length {
        // SAFETY: inside the caller's string and the buffer.
        unsafe { wide.buffer.add(at).write(cp1252::MB_TO_WC[string.add(at).read() as usize]) };
    }
    // SAFETY: inside the buffer.
    unsafe { wide.buffer.add(length).write(0) };
    Ok((wide, length))
}

/// A wide string's UNICODE_STRING (its buffer the caller's).
///
/// # Safety
///
/// `string` points at a NUL-terminated string.
unsafe fn counted(string: *const u16) -> UnicodeString {
    // SAFETY: the caller's contract.
    let length = unsafe { length(string) };
    UnicodeString { length: (2 * length) as u16, maximum_length: (2 * length) as u16, buffer: string as *mut u16 }
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

/// GetEnvironmentStrings: an ANSI copy of the environment block on the process heap (taken under
/// the PEB lock); null with ERROR_NOT_ENOUGH_MEMORY when the heap has no room.
#[unsafe(export_name = "f2k_export_GetEnvironmentStrings")]
pub extern "system" fn get_environment_strings() -> *mut u8 {
    // SAFETY: ntdll's exports; the block is read under the PEB lock.
    unsafe {
        nt::RtlAcquirePebLock();
        let block = crate::base::environment_block();
        let units = block_units(block);
        let copy = nt::RtlAllocateHeap(crate::base::process_heap(), 0, units);
        if !copy.is_null() {
            for at in 0..units {
                copy.add(at).write(cp1252::wc_to_mb(block.add(at).read()));
            }
        }
        nt::RtlReleasePebLock();
        if copy.is_null() {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        }
        copy
    }
}

/// The block's length in units, its final NUL included (an empty block's two NULs count).
///
/// # Safety
///
/// `block` is an environment block.
unsafe fn block_units(block: *const u16) -> usize {
    let mut at = 0;
    // SAFETY: the block's entries each end in a NUL, and a NUL follows the last.
    unsafe {
        while block.add(at).read() != 0 {
            while block.add(at).read() != 0 {
                at += 1;
            }
            at += 1;
        }
    }
    (at + 1).max(2)
}

/// FreeEnvironmentStringsA: free a copy GetEnvironmentStrings made (RtlFreeHeap on the process heap:
/// TRUE once freed, and for a null pointer).
///
/// # Safety
///
/// `block` is null or a copy GetEnvironmentStrings made.
#[unsafe(export_name = "f2k_export_FreeEnvironmentStringsA")]
pub unsafe extern "system" fn free_environment_strings_a(block: *mut u8) -> u32 {
    // SAFETY: the caller's copy, on the process heap.
    u32::from(block.is_null() || unsafe { nt::RtlFreeHeap(crate::base::process_heap(), 0, block) } != 0)
}

/// GetEnvironmentVariableA: the variable's value into the buffer — its length, terminator excluded,
/// when it fits; the size it needs, terminator included, when it does not (nothing written).
/// ERROR_ENVVAR_NOT_FOUND (and 0) for an unset variable, ERROR_INVALID_PARAMETER for a name that
/// does not convert ([`widen`]).
///
/// # Safety
///
/// `name` points at a NUL-terminated string, `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_GetEnvironmentVariableA")]
pub unsafe extern "system" fn get_environment_variable_a(name: *const u8, buffer: *mut u8, size: u32) -> u32 {
    // SAFETY: the caller's name.
    let (wide_name, name_length) = match unsafe { widen(name) } {
        Ok(wide) => wide,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    let name_string = wide_name.string(name_length);
    // The value's length first (an empty buffer), then the value itself.
    let mut probe = UnicodeString { length: 0, maximum_length: 0, buffer: core::ptr::null_mut() };
    // SAFETY: ntdll's export, over the strings above.
    let status = unsafe { nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), &name_string, &mut probe) };
    if status != STATUS_BUFFER_TOO_SMALL && status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    let value_length = probe.length as usize / 2;
    if (size as usize) <= value_length {
        return value_length as u32 + 1;
    }
    let Some(value) = Wide::new(value_length + 1) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    let mut value_string = value.string(0);
    // SAFETY: as above.
    let status = unsafe { nt::RtlQueryEnvironmentVariable_U(core::ptr::null_mut(), &name_string, &mut value_string) };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    let units = value.units(value_string.length as usize / 2);
    for (at, &unit) in units.iter().enumerate() {
        // SAFETY: inside the caller's buffer (it holds the value and its terminator).
        unsafe { buffer.add(at).write(cp1252::wc_to_mb(unit)) };
    }
    // SAFETY: as above.
    unsafe { buffer.add(units.len()).write(0) };
    units.len() as u32
}

/// SetEnvironmentVariableA: set the variable to the value, or delete it for a null value; FALSE with
/// the status's error when a string does not convert ([`widen`]: ERROR_INVALID_PARAMETER past 32766
/// characters) or ntdll refuses (an invalid name: ERROR_INVALID_PARAMETER).
///
/// # Safety
///
/// `name` and `value` (when given) point at NUL-terminated strings.
#[unsafe(export_name = "f2k_export_SetEnvironmentVariableA")]
pub unsafe extern "system" fn set_environment_variable_a(name: *const u8, value: *const u8) -> u32 {
    // SAFETY: the caller's strings.
    let converted = unsafe { (widen(name), if value.is_null() { Ok(None) } else { widen(value).map(Some) }) };
    let ((wide_name, name_length), value) = match converted {
        (Ok(name), Ok(value)) => (name, value),
        (Err(status), _) | (_, Err(status)) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    let name_string = wide_name.string(name_length);
    let value_string = value.as_ref().map(|(wide, length)| wide.string(*length));
    // SAFETY: ntdll's export, over the strings above.
    let status = unsafe {
        nt::RtlSetEnvironmentVariable(
            core::ptr::null_mut(),
            &name_string,
            value_string.as_ref().map_or(core::ptr::null(), |string| string as *const UnicodeString),
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
pub unsafe extern "system" fn set_environment_variable_w(name: *const u16, value: *const u16) -> u32 {
    // SAFETY: the caller's strings.
    let (name, value) = unsafe { (counted(name), (!value.is_null()).then(|| counted(value))) };
    // SAFETY: ntdll's export, over the caller's strings.
    let status = unsafe {
        nt::RtlSetEnvironmentVariable(
            core::ptr::null_mut(),
            &name,
            value.as_ref().map_or(core::ptr::null(), |string| string as *const UnicodeString),
        )
    };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    1
}

/// ExpandEnvironmentStringsA: the expansion and its terminator into the caller's buffer when it
/// fits; the size it needs (terminator included) either way. ERROR_INVALID_PARAMETER (and 0) for a
/// source that does not convert ([`widen`]).
///
/// # Safety
///
/// `source` points at a NUL-terminated string, `buffer` holds `size` bytes.
#[unsafe(export_name = "f2k_export_ExpandEnvironmentStringsA")]
pub unsafe extern "system" fn expand_environment_strings_a(source: *const u8, buffer: *mut u8, size: u32) -> u32 {
    // SAFETY: the caller's source.
    let (wide_source, source_length) = match unsafe { widen(source) } {
        Ok(wide) => wide,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    let source_string = wide_source.string(source_length);
    let mut needed = 0u32;
    let mut probe = UnicodeString { length: 0, maximum_length: 0, buffer: core::ptr::null_mut() };
    // SAFETY: ntdll's export: the size first.
    let status =
        unsafe { nt::RtlExpandEnvironmentStrings_U(core::ptr::null_mut(), &source_string, &mut probe, &mut needed) };
    if status != STATUS_BUFFER_TOO_SMALL && status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    let units = needed as usize / 2;
    if (size as usize) < units {
        return units as u32;
    }
    let Some(out) = Wide::new(units) else {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    };
    let mut out_string = out.string(0);
    // SAFETY: as above, into a buffer of the size asked.
    let status = unsafe { nt::RtlExpandEnvironmentStrings_U(core::ptr::null_mut(), &source_string, &mut out_string, &mut needed) };
    if status != 0 {
        set_last_nt_error(status);
        return 0;
    }
    for (at, &unit) in out.units(units).iter().enumerate() {
        // SAFETY: inside the caller's buffer (it holds the expansion and its terminator).
        unsafe { buffer.add(at).write(cp1252::wc_to_mb(unit)) };
    }
    units as u32
}
