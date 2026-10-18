//! The handle calls: CloseHandle and DuplicateHandle, as Windows 2000's kernel32 makes them — a
//! console handle goes to its server (CloseConsoleHandle, DuplicateConsoleHandle), any other to
//! the object manager's services. The synchronization objects themselves come with B5.

use crate::base::{is_console_handle, set_last_error, standard_handle, succeeded, CURRENT_PROCESS};
use crate::{console, nt};

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// CloseHandle: the handle closed (NtClose; a standard handle's pseudo-value the process
/// parameters' handle, and a console handle closed by its server, CloseConsoleHandle, as Windows
/// 2000's). FALSE with the status's error for a handle naming nothing.
#[unsafe(export_name = "f2k_export_CloseHandle")]
pub extern "system" fn close_handle(object: u32) -> u32 {
    let object = standard_handle(object);
    if is_console_handle(object) {
        return console::close_console_handle(object);
    }
    // SAFETY: ntdll's export.
    succeeded(unsafe { nt::NtClose(object) })
}

/// DuplicateHandle: a console handle is its server's to duplicate (DuplicateConsoleHandle, as
/// Windows 2000's), within the calling process only (ERROR_INVALID_PARAMETER for another), the new
/// handle stored where asked. Any other handle is NtDuplicateObject's, which comes with the
/// synchronization services (B5): until then ERROR_CALL_NOT_IMPLEMENTED.
///
/// # Safety
///
/// `target` is null or points at a writable HANDLE.
#[unsafe(export_name = "f2k_export_DuplicateHandle")]
pub unsafe extern "system" fn duplicate_handle(
    source_process: u32,
    source: u32,
    target_process: u32,
    target: *mut u32,
    access: u32,
    inherit: u32,
    options: u32,
) -> u32 {
    if is_console_handle(source) {
        if source_process != CURRENT_PROCESS || target_process != CURRENT_PROCESS {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let duplicate = console::duplicate_console_handle(source, access, inherit, options);
        if duplicate == INVALID_HANDLE_VALUE {
            return 0;
        }
        if !target.is_null() {
            // SAFETY: the caller's HANDLE.
            unsafe { target.write_unaligned(duplicate) };
        }
        return 1;
    }
    set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
    0
}
