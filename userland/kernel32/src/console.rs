//! The console: the standard handles (the process parameters' StandardInput, StandardOutput and
//! StandardError), and the console calls, sent to the console server through ntdll's
//! CsrClientCallServer as Windows 2000's kernel32 sends them to csrss (ARCH-6 group 7). F2K's
//! server is the kernel's stand-in for csrss (`rtl::console` holds its message format and rules):
//! console handles are its own, never kernel handles, and its screen is the serial line.
//!
//! kernel32's other calls hand console handles here where Windows 2000's do: WriteFile and ReadFile
//! (WriteConsoleA, ReadConsoleA), FlushFileBuffers (FlushConsoleInputBuffer), GetFileType
//! (VerifyConsoleIoHandle), CloseHandle (CloseConsoleHandle) and DuplicateHandle
//! (DuplicateConsoleHandle), and the waits (the console's input-wait handle, [`wait_handle`]);
//! ReadFile's console branch ([`read_console`]) waits for ReadFile's move to kernel32 (B8). The host
//! tests' CsrClientCallServer serves the same rules, the bytes written recorded
//! ([`console_writes`]).

use rtl::console::api;
use rtl::status::{nt_success, STATUS_INVALID_HANDLE};

use crate::base::{
    is_console_handle, parameters_standard_handle, peb, read, set_last_error, set_last_nt_error,
    set_parameters_standard_handle, standard_handle, standard_slot, under_peb_lock, write,
};
#[cfg(test)]
pub use crate::nt::host::console_writes;
use crate::nt::{self, ApiMessage};

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const ERROR_INVALID_PARAMETER: u32 = 87;

/// kernel32's console input-wait handle's slot, on the PEB's page.
const CONSOLE_INPUT_WAIT: usize = 0x8C0;
/// The input-wait event's access and type: EVENT_ALL_ACCESS, a NotificationEvent.
const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
const NOTIFICATION_EVENT: u32 = 0;

/// Send the API's data to the console server (CsrClientCallServer, no capture buffer: F2K's server
/// reads the client's memory where it is); the status, `data` as the server answered it.
fn call_server(api: u32, data: &mut [usize]) -> u32 {
    let mut message = ApiMessage {
        port_message: [0; 6],
        capture_buffer: 0,
        api_number: 0,
        return_value: 0,
        reserved: 0,
        data: [0; rtl::console::DATA_WORDS],
    };
    message.data[..data.len()].copy_from_slice(data);
    let length = core::mem::size_of_val(data) as u32;
    // SAFETY: ntdll's export, over the message above.
    unsafe { nt::CsrClientCallServer(&mut message, core::ptr::null_mut(), api, length) };
    data.copy_from_slice(&message.data[..data.len()]);
    message.return_value
}

/// A call's answer as a BOOL: TRUE, or FALSE with the status's error set (BaseSetLastNTError).
fn succeeded(status: u32) -> u32 {
    if nt_success(status) {
        1
    } else {
        set_last_nt_error(status);
        0
    }
}

// --- The standard handles --------------------------------------------------------------------------

/// GetStdHandle: the process parameters' StandardInput, StandardOutput or StandardError; any other
/// type is INVALID_HANDLE_VALUE with ERROR_INVALID_HANDLE (BaseSetLastNTError(STATUS_INVALID_HANDLE)),
/// as Windows 2000's.
#[unsafe(export_name = "f2k_export_GetStdHandle")]
pub extern "system" fn get_std_handle(which: u32) -> u32 {
    match standard_slot(which) {
        Some(slot) => parameters_standard_handle(slot),
        None => {
            set_last_nt_error(STATUS_INVALID_HANDLE);
            INVALID_HANDLE_VALUE
        }
    }
}

/// SetStdHandle: the process parameters' standard handle replaced (what GetStdHandle and the file
/// calls' pseudo-values name from then on); any other type is FALSE with ERROR_INVALID_HANDLE, as
/// Windows 2000's.
#[unsafe(export_name = "f2k_export_SetStdHandle")]
pub extern "system" fn set_std_handle(which: u32, handle: u32) -> u32 {
    match standard_slot(which) {
        Some(slot) => {
            set_parameters_standard_handle(slot, handle);
            1
        }
        None => {
            set_last_nt_error(STATUS_INVALID_HANDLE);
            0
        }
    }
}

/// SetHandleCount: the count asked for, as Windows 2000's (its handle tables grow on their own).
#[unsafe(export_name = "f2k_export_SetHandleCount")]
pub extern "system" fn set_handle_count(count: u32) -> u32 {
    count
}

// --- The console's own calls -----------------------------------------------------------------------

/// The console's input or output code page from its server; zero with the status's error.
fn console_cp(output: bool) -> u32 {
    let mut data = [usize::from(output), 0];
    let status = call_server(api::GET_CP, &mut data);
    if succeeded(status) == 0 {
        return 0;
    }
    data[1] as u32
}

/// GetConsoleCP: the console's input code page (the OEM one, 437).
#[unsafe(export_name = "f2k_export_GetConsoleCP")]
pub extern "system" fn get_console_cp() -> u32 {
    console_cp(false)
}

/// GetConsoleOutputCP: the console's output code page (the OEM one, 437).
#[unsafe(export_name = "f2k_export_GetConsoleOutputCP")]
pub extern "system" fn get_console_output_cp() -> u32 {
    console_cp(true)
}

/// GetConsoleMode: a console handle's mode stored; FALSE with ERROR_INVALID_HANDLE for a handle
/// naming no console object (the server's answer).
///
/// # Safety
///
/// `mode` points at a dword.
#[unsafe(export_name = "f2k_export_GetConsoleMode")]
pub unsafe extern "system" fn get_console_mode(console: u32, mode: *mut u32) -> u32 {
    let mut data = [console as usize, 0];
    if succeeded(call_server(api::GET_MODE, &mut data)) == 0 {
        return 0;
    }
    // SAFETY: the caller's dword.
    unsafe { mode.write_unaligned(data[1] as u32) };
    1
}

/// WriteConsoleA: `count` bytes of `buffer` to the console's screen, the count written stored where
/// asked — the full count: the CRT's writer sums it. The reserved argument (WriteFile's OVERLAPPED)
/// must be null (ERROR_INVALID_PARAMETER); a handle that is not an open output handle is
/// ERROR_INVALID_HANDLE, a buffer the caller cannot name ERROR_NOACCESS, one that cannot be read
/// ERROR_INVALID_USER_BUFFER (the server's statuses).
///
/// # Safety
///
/// `written` is null or points at a dword.
#[unsafe(export_name = "f2k_export_WriteConsoleA")]
pub unsafe extern "system" fn write_console_a(
    console: u32,
    buffer: *const u8,
    count: u32,
    written: *mut u32,
    reserved: *const u8,
) -> u32 {
    if !reserved.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut data = [console as usize, buffer as usize, count as usize, 0];
    if succeeded(call_server(api::WRITE_CONSOLE, &mut data)) == 0 {
        return 0;
    }
    if !written.is_null() {
        // SAFETY: the caller's dword.
        unsafe { written.write_unaligned(data[3] as u32) };
    }
    1
}

/// ReadConsoleA, as Windows 2000's ReadFile reaches it (not an export here): up to `count` bytes of
/// the console's input, the count read stored. F2K's console has no keyboard: its input ends at
/// once, so a read on the input handle reads nothing and succeeds (the CRT sees the end of its
/// input); any other handle is ERROR_INVALID_HANDLE.
///
/// # Safety
///
/// `read` is null or points at a dword.
pub unsafe fn read_console(console: u32, buffer: *mut u8, count: u32, read: *mut u32) -> u32 {
    let mut data = [console as usize, buffer as usize, count as usize, 0];
    if succeeded(call_server(api::READ_CONSOLE, &mut data)) == 0 {
        return 0;
    }
    if !read.is_null() {
        // SAFETY: the caller's dword.
        unsafe { read.write_unaligned(data[3] as u32) };
    }
    1
}

/// FlushConsoleInputBuffer, as Windows 2000's FlushFileBuffers reaches it: the input buffer
/// emptied (it always is); an output handle, or one naming nothing, is ERROR_INVALID_HANDLE.
pub fn flush_console_input_buffer(console: u32) -> u32 {
    succeeded(call_server(
        api::FLUSH_INPUT_BUFFER,
        &mut [console as usize],
    ))
}

/// VerifyConsoleIoHandle: whether a console handle names an open console object.
pub fn verify_console_io_handle(console: u32) -> bool {
    let mut data = [console as usize, 0];
    nt_success(call_server(api::VERIFY_IO_HANDLE, &mut data)) && data[1] != 0
}

/// GetConsoleInputWaitHandle: the event a wait on a console handle waits on, signaled while the
/// console's input buffer holds input. Windows 2000's csrss hands it over when the process connects
/// to its console; F2K's console has no keyboard, so kernel32 makes it itself at the first need —
/// a notification event, never signaled — under the PEB lock, and keeps it for the process's life
/// (zero when it cannot be made: the wait then fails on the console handle itself).
pub fn input_wait_handle() -> u32 {
    let slot = peb() + CONSOLE_INPUT_WAIT;
    let handle = read(slot);
    if handle != 0 {
        return handle;
    }
    under_peb_lock(|| {
        if read(slot) == 0 {
            let mut event = 0;
            // SAFETY: ntdll's export, unnamed.
            let status = unsafe {
                nt::NtCreateEvent(
                    &mut event,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    NOTIFICATION_EVENT,
                    0,
                )
            };
            if nt_success(status) {
                write(slot, event);
            }
        }
        read(slot)
    })
}

/// The handle a wait waits on, as Windows 2000's waits make it: a standard handle's pseudo-value is
/// the process parameters' handle, and a console handle naming a console object is the console's
/// input-wait handle; any other handle is itself.
pub fn wait_handle(handle: u32) -> u32 {
    let handle = standard_handle(handle);
    if is_console_handle(handle) && verify_console_io_handle(handle) {
        match input_wait_handle() {
            0 => handle,
            event => event,
        }
    } else {
        handle
    }
}

/// CloseConsoleHandle, as Windows 2000's CloseHandle reaches it: the console handle closed;
/// ERROR_INVALID_HANDLE for one naming nothing.
pub fn close_console_handle(console: u32) -> u32 {
    succeeded(call_server(api::CLOSE_HANDLE, &mut [console as usize]))
}

/// DuplicateConsoleHandle, as Windows 2000's DuplicateHandle reaches it: a new console handle on
/// the same console object (the source closed for DUPLICATE_CLOSE_SOURCE); INVALID_HANDLE_VALUE
/// with the server's error otherwise.
pub fn duplicate_console_handle(console: u32, access: u32, inherit: u32, options: u32) -> u32 {
    let mut data = [
        console as usize,
        access as usize,
        inherit as usize,
        options as usize,
        0,
    ];
    if succeeded(call_server(api::DUP_HANDLE, &mut data)) == 0 {
        return INVALID_HANDLE_VALUE;
    }
    data[4] as u32
}
