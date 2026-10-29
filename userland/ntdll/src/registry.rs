//! The registry's user-mode share: RtlOpenCurrentUser, the current user's hive by its NT name, as
//! advapi32 opens HKEY_CURRENT_USER; and LdrQueryImageFileExecutionOptions, an image's execution
//! options (`rtl::execution_options`: the key named after the image's file name under Image File
//! Execution Options), read through the key services, NtOpenKey and NtQueryValueKey.

use rtl::execution_options::{self, OPTIONS_KEY};
use rtl::pod::Pod;
use rtl::status::{
    STATUS_BUFFER_OVERFLOW,
    STATUS_INVALID_PARAMETER,
    STATUS_NAME_TOO_LONG,
    STATUS_SUCCESS,
};
use rtl::string::UnicodeString;

use crate::service::{self, ObjectAttributes};

/// OBJECT_ATTRIBUTES' OBJ_CASE_INSENSITIVE.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// KEY_QUERY_VALUE: the access the options' key is opened with.
const KEY_QUERY_VALUE: u32 = 0x0001;

/// NtQueryValueKey's KeyValuePartialInformation class.
const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;

/// The current user's hive: `\Registry\User\<the user>`. Windows names it after the user's SID
/// (RtlFormatCurrentUserKeyPath); F2K's one user is `jeb`.
const CURRENT_USER: &[u8] = b"\\Registry\\User\\jeb";

/// A UNICODE_STRING over `units` (the services only read it).
fn counted(units: &[u16]) -> UnicodeString {
    UnicodeString {
        length: (2 * units.len()) as u16,
        maximum_length: (2 * units.len()) as u16,
        buffer: units.as_ptr() as *mut u16,
    }
}

/// NtOpenKey: the key at the NT path `name` (case-insensitive) opened with `access`; its handle, or
/// the status.
fn open_key(name: &[u16], access: u32) -> Result<u32, u32> {
    let string = counted(name);
    let attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &string,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };
    service::open_key(&attributes, access)
}

/// The data a value's answer holds here: an option's value is short (a debugger's command line, a
/// flag's text or dword).
const VALUE_ROOM: usize = 512;

/// KEY_VALUE_PARTIAL_INFORMATION, with room for the data.
#[repr(C)]
#[derive(Clone, Copy)]
struct PartialValue {
    title_index: u32,
    kind: u32,
    data_length: u32,
    data: [u8; VALUE_ROOM],
}

// SAFETY: three u32s and bytes, without padding (the bytes end the structure, and its alignment's
// four divides their count).
unsafe impl Pod for PartialValue {}

/// NtQueryValueKey: value `name` of `key` into `value` (KeyValuePartialInformation); the status
/// (STATUS_BUFFER_OVERFLOW with the data's length when the data does not fit).
fn query_value(key: u32, name: &[u16], value: &mut PartialValue) -> u32 {
    service::query_value_key(key, &counted(name), KEY_VALUE_PARTIAL_INFORMATION, value)
}

/// RtlOpenCurrentUser: the current user's hive opened with `desired_access` (NtOpenKey), its
/// handle into `key_handle`; the open's status.
///
/// # Safety
///
/// `key_handle` is writable.
#[unsafe(export_name = "f2k_export_RtlOpenCurrentUser")]
pub unsafe extern "system" fn rtl_open_current_user(
    desired_access: u32,
    key_handle: *mut u32,
) -> u32 {
    let mut name = [0u16; CURRENT_USER.len()];
    for (unit, &byte) in name.iter_mut().zip(CURRENT_USER) {
        *unit = byte as u16;
    }
    match open_key(&name, desired_access) {
        Ok(handle) => {
            // SAFETY: the caller's handle slot.
            unsafe { key_handle.write(handle) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// The room of the options key's name: the key and an image's file name.
const KEY_NAME_ROOM: usize = OPTIONS_KEY.len() + 260;

/// LdrQueryImageFileExecutionOptions: option `value_name` of the image `image_name` names (its
/// file name's key under Image File Execution Options), into `buffer` in the form `kind` asks (a
/// REG_SZ value asked for as a REG_DWORD is its text's number), the bytes the answer takes in
/// `returned` when given. The key's open status when the image has no options (F2K's registry
/// holds none: STATUS_OBJECT_NAME_NOT_FOUND), the value query's when the option is not set;
/// STATUS_BUFFER_OVERFLOW when the answer does not fit the buffer.
///
/// # Safety
///
/// `image_name` is null or a UNICODE_STRING whose buffer holds its length; `value_name` is a
/// NUL-terminated string; `buffer` holds `buffer_size` bytes (or is null); `returned` is null or
/// writable.
#[unsafe(export_name = "f2k_export_LdrQueryImageFileExecutionOptions")]
pub unsafe extern "system" fn ldr_query_image_file_execution_options(
    image_name: *const UnicodeString,
    value_name: *const u16,
    kind: u32,
    buffer: *mut u8,
    buffer_size: u32,
    returned: *mut u32,
) -> u32 {
    // SAFETY: the caller's strings, buffer and count.
    let (image, value_name, out, returned) = unsafe {
        let Some(image) = image_name.as_ref() else {
            return STATUS_INVALID_PARAMETER;
        };
        if value_name.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let image: &[u16] = if image.buffer.is_null() || image.length == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(image.buffer, image.length as usize / 2)
        };
        let length = (0..).take_while(|&i| value_name.add(i).read() != 0).count();
        let out: &mut [u8] = if buffer.is_null() {
            &mut []
        } else {
            core::slice::from_raw_parts_mut(buffer, buffer_size as usize)
        };
        (
            image,
            core::slice::from_raw_parts(value_name, length),
            out,
            returned.as_mut(),
        )
    };
    let mut name = [0u16; KEY_NAME_ROOM];
    let Some(length) = execution_options::key_name(image, &mut name) else {
        return STATUS_NAME_TOO_LONG;
    };
    let key = match open_key(&name[..length], KEY_QUERY_VALUE) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let mut value = PartialValue {
        title_index: 0,
        kind: 0,
        data_length: 0,
        data: [0; VALUE_ROOM],
    };
    let queried = query_value(key, value_name, &mut value);
    service::close(key);
    let (status, answer_length) = match queried {
        STATUS_SUCCESS => execution_options::convert(
            kind,
            value.kind,
            &value.data[..value.data_length as usize],
            out,
        ),
        STATUS_BUFFER_OVERFLOW => (STATUS_BUFFER_OVERFLOW, value.data_length as usize),
        status => return status,
    };
    if let Some(returned) = returned {
        *returned = answer_length as u32;
    }
    status
}
