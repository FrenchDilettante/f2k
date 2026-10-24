//! The registry's user-mode share: RtlOpenCurrentUser, the current user's hive by its NT name, as
//! advapi32 opens HKEY_CURRENT_USER.

use rtl::status::STATUS_SUCCESS;
use rtl::string::UnicodeString;
use rtl::sys::{nr, system_service};

/// OBJECT_ATTRIBUTES' OBJ_CASE_INSENSITIVE.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// The current user's hive: `\Registry\User\<the user>`. Windows names it after the user's SID
/// (RtlFormatCurrentUserKeyPath); F2K's one user is `jeb`.
const CURRENT_USER: &[u8] = b"\\Registry\\User\\jeb";

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
    let string = UnicodeString {
        length: (2 * name.len()) as u16,
        maximum_length: (2 * name.len()) as u16,
        buffer: name.as_mut_ptr(),
    };
    let attributes: [u32; 6] = [
        24,
        0,
        &string as *const UnicodeString as u32,
        OBJ_CASE_INSENSITIVE,
        0,
        0,
    ];
    let mut handle = 0u32;
    let args = [
        &mut handle as *mut u32 as u32,
        desired_access,
        attributes.as_ptr() as u32,
    ];
    let status = system_service(nr::NtOpenKey, &args);
    if status == STATUS_SUCCESS {
        // SAFETY: the caller's handle slot.
        unsafe { key_handle.write(handle) };
    }
    status
}
