//! The console: the standard handles (the process parameters' StandardInput, StandardOutput and
//! StandardError), and the console calls, sent to the console server through ntdll's
//! CsrClientCallServer as Windows 2000's kernel32 sends them to csrss. F2K's
//! server is the kernel's stand-in for csrss (`rtl::console` holds its message format and rules):
//! console handles are its own, never kernel handles; what it shows goes to the screen and to the
//! serial line.
//!
//! kernel32's other calls hand console handles here where Windows 2000's do: CreateFile (CONIN$
//! and CONOUT$, [`open_console`]), WriteFile and ReadFile (WriteConsoleA, ReadConsoleA),
//! FlushFileBuffers (FlushConsoleInputBuffer), GetFileType (VerifyConsoleIoHandle), CloseHandle
//! (CloseConsoleHandle) and DuplicateHandle (DuplicateConsoleHandle), and the waits (the console's
//! input-wait handle, [`wait_handle`]). A read the server cannot complete yet is answered
//! STATUS_PENDING: kernel32 waits on the input-wait handle and asks again
//! ([`call_server_waiting`]), where Windows 2000's csrss holds the reply. The host tests'
//! CsrClientCallServer serves the same rules, the bytes written recorded ([`console_writes`]).

use rtl::console::api;
use rtl::status::{nt_success, STATUS_INVALID_HANDLE, STATUS_NO_MEMORY, STATUS_PENDING};

use crate::base::{
    is_console_handle,
    parameters_standard_handle,
    peb,
    process_heap,
    process_parameters,
    read,
    read_pointer,
    set_last_error,
    set_last_nt_error,
    set_parameters_standard_handle,
    standard_handle,
    standard_slot,
    under_peb_lock,
    write,
    write_pointer,
};
#[cfg(test)]
pub use crate::nt::host::console_writes;
use crate::nt::{self, ApiMessage};

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_INVALID_PARAMETER: u32 = 87;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// kernel32's console input-wait handle's slot, on the PEB's page.
const CONSOLE_INPUT_WAIT: usize = 0x8C0;

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

// --- The standard handles ------------------------------------------------------------------------

/// GetStdHandle: the process parameters' StandardInput, StandardOutput or StandardError; any other
/// type is INVALID_HANDLE_VALUE with ERROR_INVALID_HANDLE
/// (BaseSetLastNTError(STATUS_INVALID_HANDLE)), as Windows 2000's.
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

// --- The console's own calls ---------------------------------------------------------------------

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

/// WriteConsoleW's work: `count` characters of `buffer` (bytes, or UTF-16 units for `unicode`) to
/// the console's screen, the count written stored where asked — the full count: the CRT's writer
/// sums it. The reserved argument (WriteFile's OVERLAPPED) must be null (ERROR_INVALID_PARAMETER);
/// a handle that is not an open output handle is ERROR_INVALID_HANDLE, a buffer the caller cannot
/// name ERROR_NOACCESS, one that cannot be read ERROR_INVALID_USER_BUFFER (the server's statuses).
///
/// # Safety
///
/// `written` is null or points at a dword.
unsafe fn write_console(
    console: u32,
    buffer: usize,
    count: u32,
    written: *mut u32,
    reserved: *const u8,
    unicode: bool,
) -> u32 {
    if !reserved.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut data = [
        console as usize,
        buffer,
        count as usize,
        0,
        usize::from(unicode),
    ];
    if succeeded(call_server(api::WRITE_CONSOLE, &mut data)) == 0 {
        return 0;
    }
    if !written.is_null() {
        // SAFETY: the caller's dword.
        unsafe { written.write_unaligned(data[3] as u32) };
    }
    1
}

/// WriteConsoleA: `count` bytes (see [`write_console`]).
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
    // SAFETY: the caller's dword.
    unsafe { write_console(console, buffer as usize, count, written, reserved, false) }
}

/// WriteConsoleW: `count` UTF-16 units, shown in the console's code page (see [`write_console`]).
///
/// # Safety
///
/// `written` is null or points at a dword.
#[unsafe(export_name = "f2k_export_WriteConsoleW")]
pub unsafe extern "system" fn write_console_w(
    console: u32,
    buffer: *const u16,
    count: u32,
    written: *mut u32,
    reserved: *const u8,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe { write_console(console, buffer as usize, count, written, reserved, true) }
}

/// ReadConsoleA, as Windows 2000's ReadFile reaches it: up to `count` bytes of the console's
/// input, the count read stored ([`read_console_a`]); any handle but an input one is
/// ERROR_INVALID_HANDLE.
///
/// # Safety
///
/// `read` is null or points at a dword.
pub unsafe fn read_console(console: u32, buffer: *mut u8, count: u32, read: *mut u32) -> u32 {
    // SAFETY: the caller's dword.
    unsafe { read_console_as(console, buffer as usize, count, read, false) }
}

/// FlushConsoleInputBuffer (and Windows 2000's FlushFileBuffers on a console handle): the input
/// buffer emptied; an output handle, or one naming nothing, is ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_FlushConsoleInputBuffer")]
pub extern "system" fn flush_console_input_buffer(console: u32) -> u32 {
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

/// GetConsoleInputWaitHandle's handle: the event a wait on a console handle waits on, signaled
/// while the console's input buffer holds records. Windows 2000's csrss hands it over when the
/// process connects to its console; kernel32 asks F2K's server for it at the first need, under the
/// PEB lock, and keeps it for the process's life (zero when the server cannot give one: the wait
/// then fails on the console handle itself).
pub fn input_wait_handle() -> u32 {
    let slot = peb() + CONSOLE_INPUT_WAIT;
    let handle = read(slot);
    if handle != 0 {
        return handle;
    }
    under_peb_lock(|| {
        if read(slot) == 0 {
            let mut data = [0];
            if nt_success(call_server(api::GET_INPUT_WAIT_HANDLE, &mut data)) {
                write(slot, data[0] as u32);
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

// --- Opening the console by name -----------------------------------------------------------------

/// Which console buffer a file name names, as Windows 2000's CreateFile reads it: CONIN$ the input
/// buffer, CONOUT$ the screen buffer (any case), CON the input buffer when asked read access alone
/// and the screen buffer otherwise; none for any other name (a path included).
pub fn console_name(name: &[u16], access: u32) -> Option<bool> {
    let is = |word: &[u8]| {
        name.len() == word.len()
            && name
                .iter()
                .zip(word)
                .all(|(&unit, &byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
    };
    if is(b"CONIN$") {
        Some(false)
    } else if is(b"CONOUT$") {
        Some(true)
    } else if is(b"CON") {
        Some(access & (GENERIC_READ | GENERIC_WRITE) != GENERIC_READ)
    } else {
        None
    }
}

/// OpenConsoleW's work, as Windows 2000's CreateFile hands it CONIN$ and CONOUT$: a new handle on
/// the console's input buffer (or, `output`, its screen buffer) from the console server, the last
/// error cleared; INVALID_HANDLE_VALUE with the server's error otherwise.
pub fn open_console(output: bool, access: u32, inherit: bool, share: u32) -> u32 {
    let mut data = [
        usize::from(output),
        access as usize,
        usize::from(inherit),
        share as usize,
        0,
    ];
    if succeeded(call_server(api::OPEN_CONSOLE, &mut data)) == 0 {
        return INVALID_HANDLE_VALUE;
    }
    set_last_error(0);
    data[4] as u32
}

// --- The screen buffer ---------------------------------------------------------------------------

/// GetConsoleScreenBufferInfo: the screen buffer's size, cursor, attributes, window and largest
/// window (a CONSOLE_SCREEN_BUFFER_INFO's 22 bytes); FALSE with ERROR_INVALID_HANDLE for a handle
/// naming no screen buffer (an input handle, a file, a bogus value).
///
/// # Safety
///
/// `info` points at a CONSOLE_SCREEN_BUFFER_INFO.
#[unsafe(export_name = "f2k_export_GetConsoleScreenBufferInfo")]
pub unsafe extern "system" fn get_console_screen_buffer_info(console: u32, info: *mut u8) -> u32 {
    let mut data = [console as usize, 0, 0, 0, 0, 0, 0];
    if succeeded(call_server(api::GET_SCREEN_BUFFER_INFO, &mut data)) == 0 {
        return 0;
    }
    let mut bytes = [0u8; 24];
    for (chunk, &word) in bytes.chunks_exact_mut(4).zip(&data[1..7]) {
        chunk.copy_from_slice(&(word as u32).to_le_bytes());
    }
    // SAFETY: the caller's structure, 22 bytes.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), info, 22) };
    1
}

// --- Modes and input -----------------------------------------------------------------------------

/// SetConsoleMode: the mode of the buffer a console handle names, every handle on it sharing it.
/// An input mode past the input bits, or echo without line input, and an output mode past its
/// two bits, are ERROR_INVALID_PARAMETER; a handle naming no console object ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_SetConsoleMode")]
pub extern "system" fn set_console_mode(console: u32, mode: u32) -> u32 {
    succeeded(call_server(
        api::SET_MODE,
        &mut [console as usize, mode as usize],
    ))
}

/// GetNumberOfConsoleInputEvents: the records waiting in the input buffer; FALSE with
/// ERROR_INVALID_HANDLE for a handle naming no input buffer.
///
/// # Safety
///
/// `count` points at a dword.
#[unsafe(export_name = "f2k_export_GetNumberOfConsoleInputEvents")]
pub unsafe extern "system" fn get_number_of_console_input_events(
    console: u32,
    count: *mut u32,
) -> u32 {
    let mut data = [console as usize, 0];
    if succeeded(call_server(api::GET_INPUT_COUNT, &mut data)) == 0 {
        return 0;
    }
    // SAFETY: the caller's dword.
    unsafe { count.write_unaligned(data[1] as u32) };
    1
}

/// Send a call the console server may answer STATUS_PENDING (a read with nothing to take yet)
/// until it answers otherwise: each pending answer waited out on the console's input-wait handle
/// (signaled once input waits), the call then sent again as it was. The final status, `data` as
/// the server answered it.
fn call_server_waiting(api: u32, data: &mut [usize]) -> u32 {
    let mut sent = [0usize; rtl::console::DATA_WORDS];
    sent[..data.len()].copy_from_slice(data);
    loop {
        data.copy_from_slice(&sent[..data.len()]);
        let status = call_server(api, data);
        if status != STATUS_PENDING {
            return status;
        }
        let event = input_wait_handle();
        if event == 0 {
            return STATUS_NO_MEMORY;
        }
        // SAFETY: ntdll's export; the process's own event.
        unsafe { nt::NtWaitForSingleObject(event, 0, core::ptr::null()) };
    }
}

/// A read through the console server: up to `count` characters (UTF-16 units, or bytes in the
/// console's code page for the A form) into `buffer`, as the input mode reads them — a line and
/// its CR LF in line mode, the rest of a line kept for the next read; what was typed in raw mode
/// — waiting for the input that completes it. The count read stored where asked.
///
/// # Safety
///
/// `read` is null or points at a dword.
unsafe fn read_console_as(
    console: u32,
    buffer: usize,
    count: u32,
    read: *mut u32,
    unicode: bool,
) -> u32 {
    let mut data = [
        console as usize,
        buffer,
        count as usize,
        0,
        usize::from(unicode),
    ];
    if succeeded(call_server_waiting(api::READ_CONSOLE, &mut data)) == 0 {
        return 0;
    }
    if !read.is_null() {
        // SAFETY: the caller's dword.
        unsafe { read.write_unaligned(data[3] as u32) };
    }
    1
}

/// ReadConsoleA: up to `count` bytes of the console's input (see [`read_console_as`]); a handle
/// naming no input buffer is ERROR_INVALID_HANDLE.
///
/// # Safety
///
/// `read` is null or points at a dword.
#[unsafe(export_name = "f2k_export_ReadConsoleA")]
pub unsafe extern "system" fn read_console_a(
    console: u32,
    buffer: *mut u8,
    count: u32,
    read: *mut u32,
    _reserved: *const u8,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe { read_console_as(console, buffer as usize, count, read, false) }
}

/// ReadConsoleW: up to `count` UTF-16 units of the console's input (see [`read_console_as`]).
///
/// # Safety
///
/// `read` is null or points at a dword.
#[unsafe(export_name = "f2k_export_ReadConsoleW")]
pub unsafe extern "system" fn read_console_w(
    console: u32,
    buffer: *mut u16,
    count: u32,
    read: *mut u32,
    _reserved: *const u8,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe { read_console_as(console, buffer as usize, count, read, true) }
}

/// An input-record call's work: `api` over `length` INPUT_RECORDs at `records`, the A form's
/// characters in the console's code page; the count the server answered stored. Reads go through
/// [`call_server_waiting`]: ReadConsoleInput waits for a record.
///
/// # Safety
///
/// `count` points at a dword.
unsafe fn input_records(
    api: u32,
    console: u32,
    records: usize,
    length: u32,
    count: *mut u32,
    unicode: bool,
) -> u32 {
    let mut data = [
        console as usize,
        records,
        length as usize,
        0,
        usize::from(unicode),
    ];
    let status = if api == api::READ_INPUT {
        call_server_waiting(api, &mut data)
    } else {
        call_server(api, &mut data)
    };
    if succeeded(status) == 0 {
        return 0;
    }
    // SAFETY: the caller's dword.
    unsafe { count.write_unaligned(data[3] as u32) };
    1
}

/// WriteConsoleInputA: `length` records appended to the input buffer as they are (a key event's
/// character from the console's code page), as many as it has room for; the count written.
///
/// # Safety
///
/// `written` points at a dword.
#[unsafe(export_name = "f2k_export_WriteConsoleInputA")]
pub unsafe extern "system" fn write_console_input_a(
    console: u32,
    records: *const u8,
    length: u32,
    written: *mut u32,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe {
        input_records(
            api::WRITE_INPUT,
            console,
            records as usize,
            length,
            written,
            false,
        )
    }
}

/// WriteConsoleInputW: as WriteConsoleInputA, the characters UTF-16 units.
///
/// # Safety
///
/// `written` points at a dword.
#[unsafe(export_name = "f2k_export_WriteConsoleInputW")]
pub unsafe extern "system" fn write_console_input_w(
    console: u32,
    records: *const u8,
    length: u32,
    written: *mut u32,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe {
        input_records(
            api::WRITE_INPUT,
            console,
            records as usize,
            length,
            written,
            true,
        )
    }
}

/// PeekConsoleInputA: up to `length` waiting records copied, oldest first, and left waiting (a
/// key event's character in the console's code page); never waits.
///
/// # Safety
///
/// `read` points at a dword.
#[unsafe(export_name = "f2k_export_PeekConsoleInputA")]
pub unsafe extern "system" fn peek_console_input_a(
    console: u32,
    records: *mut u8,
    length: u32,
    read: *mut u32,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe {
        input_records(
            api::PEEK_INPUT,
            console,
            records as usize,
            length,
            read,
            false,
        )
    }
}

/// PeekConsoleInputW: as PeekConsoleInputA, the characters UTF-16 units.
///
/// # Safety
///
/// `read` points at a dword.
#[unsafe(export_name = "f2k_export_PeekConsoleInputW")]
pub unsafe extern "system" fn peek_console_input_w(
    console: u32,
    records: *mut u8,
    length: u32,
    read: *mut u32,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe {
        input_records(
            api::PEEK_INPUT,
            console,
            records as usize,
            length,
            read,
            true,
        )
    }
}

/// ReadConsoleInputA: as PeekConsoleInputA, the records copied taken out of the input buffer,
/// waiting for one when it is empty.
///
/// # Safety
///
/// `read` points at a dword.
#[unsafe(export_name = "f2k_export_ReadConsoleInputA")]
pub unsafe extern "system" fn read_console_input_a(
    console: u32,
    records: *mut u8,
    length: u32,
    read: *mut u32,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe {
        input_records(
            api::READ_INPUT,
            console,
            records as usize,
            length,
            read,
            false,
        )
    }
}

/// ReadConsoleInputW: as ReadConsoleInputA, the characters UTF-16 units.
///
/// # Safety
///
/// `read` points at a dword.
#[unsafe(export_name = "f2k_export_ReadConsoleInputW")]
pub unsafe extern "system" fn read_console_input_w(
    console: u32,
    records: *mut u8,
    length: u32,
    read: *mut u32,
) -> u32 {
    // SAFETY: the caller's dword.
    unsafe {
        input_records(
            api::READ_INPUT,
            console,
            records as usize,
            length,
            read,
            true,
        )
    }
}

// --- The title -----------------------------------------------------------------------------------

/// A title through the console server into `buffer` of `size` characters (see
/// `rtl::console::api::GET_TITLE`): the answer, 0 with the server's error when it refuses.
fn get_title(buffer: usize, size: u32, unicode: bool) -> u32 {
    let mut data = [buffer, size as usize, 0, usize::from(unicode)];
    if succeeded(call_server(api::GET_TITLE, &mut data)) == 0 {
        return 0;
    }
    data[2] as u32
}

/// GetConsoleTitleA: the title and its terminator in the console's code page when the buffer
/// holds both, the characters copied the answer; 0, nothing written, when it does not, the title
/// is empty or the buffer has no room — Windows 2000's console capture.
#[unsafe(export_name = "f2k_export_GetConsoleTitleA")]
pub extern "system" fn get_console_title_a(buffer: *mut u8, size: u32) -> u32 {
    get_title(buffer as usize, size, false)
}

/// GetConsoleTitleW: as much of the title as fits with its terminator, the characters copied the
/// answer; 0, nothing written, for an empty title or a buffer of no room — Windows 2000's console
/// capture.
#[unsafe(export_name = "f2k_export_GetConsoleTitleW")]
pub extern "system" fn get_console_title_w(buffer: *mut u16, size: u32) -> u32 {
    get_title(buffer as usize, size, true)
}

/// SetConsoleTitleA: the title replaced by the string's characters, read in the console's code
/// page.
///
/// # Safety
///
/// `title` is a NUL-terminated string.
#[unsafe(export_name = "f2k_export_SetConsoleTitleA")]
pub unsafe extern "system" fn set_console_title_a(title: *const u8) -> u32 {
    let mut length = 0;
    // SAFETY: the caller's string, read to its NUL.
    while unsafe { title.add(length).read() } != 0 {
        length += 1;
    }
    succeeded(call_server(
        api::SET_TITLE,
        &mut [title as usize, length, 0],
    ))
}

/// SetConsoleTitleW: the title replaced by the string's characters.
///
/// # Safety
///
/// `title` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_SetConsoleTitleW")]
pub unsafe extern "system" fn set_console_title_w(title: *const u16) -> u32 {
    let mut length = 0;
    // SAFETY: the caller's string, read to its NUL.
    while unsafe { title.add(length).read_unaligned() } != 0 {
        length += 1;
    }
    succeeded(call_server(
        api::SET_TITLE,
        &mut [title as usize, length, 1],
    ))
}

// --- Control handlers ----------------------------------------------------------------------------

/// The process's control handlers, kept as Windows 2000's kernel32 keeps them, a list in the
/// order they were added, grown as needed: its block on the process heap, the handlers it holds
/// and its room, in kernel32's slots on the PEB's page, under the PEB lock.
const CTRL_HANDLERS: usize = 0x8C4;
const CTRL_HANDLER_COUNT: usize = 0x8C8;
const CTRL_HANDLER_ROOM: usize = 0x8CC;

/// The room a fresh list has.
const FIRST_ROOM: u32 = 8;

/// The process parameters' ConsoleFlags, and its bit that makes the process ignore Ctrl+C (what
/// SetConsoleCtrlHandler(NULL, TRUE) sets, and a child inherits).
const CONSOLE_FLAGS: usize = 0x14;
const IGNORE_CTRL_C: u32 = 0x1;

/// SetConsoleCtrlHandler: `routine` added to the process's control handlers (a handler added
/// twice is in the list twice), or one of its entries removed (the latest); a routine the list
/// does not hold is ERROR_INVALID_PARAMETER, a list that cannot grow ERROR_NOT_ENOUGH_MEMORY. A
/// null routine sets or clears the process's ignoring of Ctrl+C, and never fails. Registration
/// only: no control event is delivered yet.
#[unsafe(export_name = "f2k_export_SetConsoleCtrlHandler")]
pub extern "system" fn set_console_ctrl_handler(routine: u32, add: u32) -> u32 {
    if routine == 0 {
        let flags = process_parameters() + CONSOLE_FLAGS;
        under_peb_lock(|| {
            let value = read(flags);
            write(
                flags,
                if add != 0 {
                    value | IGNORE_CTRL_C
                } else {
                    value & !IGNORE_CTRL_C
                },
            );
        });
        return 1;
    }
    let error = under_peb_lock(|| {
        let peb = peb();
        let count = read(peb + CTRL_HANDLER_COUNT) as usize;
        let mut list = read_pointer(peb + CTRL_HANDLERS) as *mut u32;
        if add != 0 {
            let room = read(peb + CTRL_HANDLER_ROOM);
            if count == room as usize {
                let grown = if room == 0 { FIRST_ROOM } else { 2 * room };
                // SAFETY: ntdll's export, the process heap.
                let block = unsafe { nt::RtlAllocateHeap(process_heap(), 0, 4 * grown as usize) }
                    as *mut u32;
                if block.is_null() {
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
                if !list.is_null() {
                    // SAFETY: the old block holds `count` handlers; the new one has room for
                    // them. The old block is the list's own.
                    unsafe {
                        core::ptr::copy_nonoverlapping(list, block, count);
                        nt::RtlFreeHeap(process_heap(), 0, list.cast());
                    }
                }
                list = block;
                write_pointer(peb + CTRL_HANDLERS, list as usize);
                write(peb + CTRL_HANDLER_ROOM, grown);
            }
            // SAFETY: the list's block has room past its `count` handlers.
            unsafe { list.add(count).write(routine) };
            write(peb + CTRL_HANDLER_COUNT, count as u32 + 1);
            return 0;
        }
        if list.is_null() {
            return ERROR_INVALID_PARAMETER;
        }
        // SAFETY: the list's block holds `count` handlers.
        let handlers = unsafe { core::slice::from_raw_parts_mut(list, count) };
        match handlers.iter().rposition(|&held| held == routine) {
            Some(at) => {
                handlers.copy_within(at + 1.., at);
                write(peb + CTRL_HANDLER_COUNT, count as u32 - 1);
                0
            }
            None => ERROR_INVALID_PARAMETER,
        }
    });
    if error != 0 {
        set_last_error(error);
        return 0;
    }
    1
}
