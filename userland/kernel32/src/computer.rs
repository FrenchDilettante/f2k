//! The computer's name: GetComputerNameW and GetComputerNameA, kernel32's own code over ntdll's key
//! services (NtOpenKey, NtQueryValueKey), as Windows 2000's reads the name from the registry:
//! `HKLM\System\CurrentControlSet\Control\ComputerName\ComputerName`'s `ComputerName` value. The A
//! form hands the name back narrowed through the ANSI code page ([`Text`]).

use crate::base::{unicode_string, OBJ_CASE_INSENSITIVE};
use crate::edge::{Out, OutBuf, Text};
use crate::error::{bool_answer, Failure};
use crate::nt::ObjectAttributes;
use crate::ntcall::{self, NtStatus};

/// The longest computer name, in characters (winbase.h's MAX_COMPUTERNAME_LENGTH).
pub const MAX_COMPUTERNAME_LENGTH: usize = 15;
/// ERROR_BUFFER_OVERFLOW: the caller's buffer cannot hold the name and its terminator.
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// The key that holds the name, and its value.
const KEY: &[u8] =
    b"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
const VALUE: &[u8] = b"ComputerName";
/// KEY_QUERY_VALUE: the one right the read needs.
const KEY_QUERY_VALUE: u32 = 0x0001;
/// KeyValuePartialInformation: the value's type and data, after three dwords (its title index,
/// type and data length).
const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;
const PARTIAL_HEADER: usize = 12;
/// The longest name the read takes, in units: past a computer name's limit, so a longer value
/// reads whole (and is cut to the limit).
const READ_UNITS: usize = 2 * MAX_COMPUTERNAME_LENGTH + 2;

/// `text`'s bytes as UTF-16 units into `units`: a counted string over them.
fn widen(text: &[u8], units: &mut [u16]) -> rtl::string::UnicodeString {
    for (unit, &byte) in units.iter_mut().zip(text) {
        *unit = u16::from(byte);
    }
    unicode_string(units, text.len())
}

/// The computer's name, read from the registry, into `name`: its length in units (at most
/// MAX_COMPUTERNAME_LENGTH, its terminator and anything past the limit left out).
fn read_name(name: &mut [u16; MAX_COMPUTERNAME_LENGTH]) -> Result<usize, NtStatus> {
    let mut path = [0u16; KEY.len()];
    let path = widen(KEY, &mut path);
    let attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &path,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: core::ptr::null(),
        security_quality_of_service: core::ptr::null(),
    };
    let key = ntcall::open_key(KEY_QUERY_VALUE, &attributes)?;
    let mut value = [0u16; VALUE.len()];
    let value = widen(VALUE, &mut value);
    let mut information = [0u8; PARTIAL_HEADER + 2 * READ_UNITS];
    let read =
        ntcall::query_value_key(key, &value, KEY_VALUE_PARTIAL_INFORMATION, &mut information);
    let _ = ntcall::close(key);
    read?;
    let data_length = u32::from_le_bytes(information[8..12].try_into().unwrap()) as usize;
    let data = &information[PARTIAL_HEADER..PARTIAL_HEADER + data_length.min(2 * READ_UNITS)];
    let mut length = 0;
    for pair in data.chunks_exact(2).take(MAX_COMPUTERNAME_LENGTH) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        name[length] = unit;
        length += 1;
    }
    Ok(length)
}

/// GetComputerNameW's work: the name and its terminator into the caller's buffer of `size`
/// characters, `size` then its length; a buffer too small is ERROR_BUFFER_OVERFLOW, nothing
/// written and `size` the characters it needs, terminator included (the documented answers). The
/// last error is untouched on success.
fn computer_name(mut buffer: Text<'_>, size: &mut Out<'_, u32>) -> Result<(), Failure> {
    let mut name = [0u16; MAX_COMPUTERNAME_LENGTH];
    let length = read_name(&mut name).map_err(Failure::Status)?;
    if buffer.len() <= length {
        size.set(length as u32 + 1);
        return Err(Failure::Error(ERROR_BUFFER_OVERFLOW));
    }
    buffer.put_terminated(&name[..length]);
    size.set(length as u32);
    Ok(())
}

/// GetComputerNameA (see [`computer_name`]).
///
/// # Safety
///
/// `size` points to the buffer's size in bytes, and `buffer` holds that many.
#[unsafe(export_name = "f2k_export_GetComputerNameA")]
pub unsafe extern "system" fn get_computer_name_a(buffer: *mut u8, size: *mut u32) -> u32 {
    // SAFETY: the caller's size and its buffer of that many bytes (the contract).
    let mut size = unsafe { Out::new(size) };
    // SAFETY: as above.
    let buffer = unsafe { OutBuf::new(buffer, size.get() as usize) };
    bool_answer(computer_name(Text::Ansi(buffer), &mut size))
}

/// GetComputerNameW (see [`computer_name`]).
///
/// # Safety
///
/// `size` points to the buffer's size in characters, and `buffer` holds that many.
#[unsafe(export_name = "f2k_export_GetComputerNameW")]
pub unsafe extern "system" fn get_computer_name_w(buffer: *mut u16, size: *mut u32) -> u32 {
    // SAFETY: the caller's size and its buffer of that many characters (the contract).
    let mut size = unsafe { Out::new(size) };
    // SAFETY: as above.
    let buffer = unsafe { OutBuf::new(buffer, size.get() as usize) };
    bool_answer(computer_name(Text::Wide(buffer), &mut size))
}
