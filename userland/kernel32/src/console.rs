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

use rtl::console::api::{self, InputRecords, Message};
use rtl::console::Api;
use rtl::pod::Pod;
use rtl::status::{nt_success, STATUS_INVALID_HANDLE, STATUS_NO_MEMORY, STATUS_PENDING};
use rtl::sync::{Locked, OnceWord};

use crate::base::{
    is_console_handle,
    own_data,
    parameters_standard_handle,
    set_last_error,
    set_last_nt_error,
    set_parameters_standard_handle,
    standard_handle,
    standard_slot,
    update_console_flags,
};
use crate::edge::{InStr, InWStr, Out, OutBuf};
use crate::heap::{HeapVec, OutOfMemory};
#[cfg(test)]
pub use crate::nt::host::console_writes;
use crate::nt::{self, ApiMessage};
use crate::ntcall::FastPebLock;

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
const ERROR_INVALID_PARAMETER: u32 = 87;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

own_data! {
    /// The console's input-wait handle, once the server gave it.
    fn input_wait() -> &'static OnceWord<FastPebLock> = OnceWord::new(FastPebLock);
}

/// Send an API's message to the console server (CsrClientCallServer, no capture buffer: F2K's
/// server reads the client's memory where it is), as the API's data after the header; the status,
/// `message` as the server answered it.
fn call_server<M: Message>(message: &mut M) -> u32 {
    let mut sent = ApiMessage {
        port_message: [0; 6],
        capture_buffer: 0,
        api_number: 0,
        return_value: 0,
        reserved: 0,
        data: [0; rtl::console::DATA_WORDS],
    };
    let length = core::mem::size_of::<M>();
    sent.data.as_bytes_mut()[..length].copy_from_slice(message.as_bytes());
    let api = M::API.into();
    // SAFETY: ntdll's export, over the message above.
    unsafe { nt::CsrClientCallServer(&mut sent, core::ptr::null_mut(), api, length as u32) };
    message
        .as_bytes_mut()
        .copy_from_slice(&sent.data.as_bytes()[..length]);
    sent.return_value
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
    let mut message = api::GetCp {
        output: usize::from(output),
        code_page: 0,
    };
    if succeeded(call_server(&mut message)) == 0 {
        return 0;
    }
    message.code_page as u32
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
    // SAFETY: the caller's dword (the contract).
    let mode = unsafe { Out::new(mode) };
    console_mode(console, mode)
}

/// GetConsoleMode's work.
fn console_mode(console: u32, mut mode: Out<'_, u32>) -> u32 {
    let mut message = api::GetMode {
        handle: console as usize,
        mode: 0,
    };
    if succeeded(call_server(&mut message)) == 0 {
        return 0;
    }
    mode.set(message.mode as u32);
    1
}

/// WriteConsoleW's work (and WriteFile's on a console handle, as Windows 2000's hands it): `count`
/// characters of `buffer` (bytes, or UTF-16 units for `unicode`) to the console's screen, the
/// count written stored where asked — the full count: the CRT's writer sums it. The reserved
/// argument (WriteFile's OVERLAPPED) must be null (ERROR_INVALID_PARAMETER); a handle that is not
/// an open output handle is ERROR_INVALID_HANDLE, a buffer the caller cannot name ERROR_NOACCESS,
/// one that cannot be read ERROR_INVALID_USER_BUFFER (the server's statuses).
pub fn write_console(
    console: u32,
    buffer: usize,
    count: u32,
    written: Option<Out<'_, u32>>,
    reserved: bool,
    unicode: bool,
) -> u32 {
    if reserved {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut message = api::WriteConsole {
        handle: console as usize,
        buffer,
        count: count as usize,
        written: 0,
        unicode: usize::from(unicode),
    };
    if succeeded(call_server(&mut message)) == 0 {
        return 0;
    }
    if let Some(mut written) = written {
        written.set(message.written as u32);
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
    // SAFETY: the caller's dword, when given (the contract); the buffer goes to the server, which
    // reads it.
    let written = unsafe { Out::optional(written) };
    let reserved = !reserved.is_null();
    write_console(console, buffer as usize, count, written, reserved, false)
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
    // SAFETY: the caller's dword, when given (the contract); the buffer goes to the server, which
    // reads it.
    let written = unsafe { Out::optional(written) };
    let reserved = !reserved.is_null();
    write_console(console, buffer as usize, count, written, reserved, true)
}

/// ReadConsoleA, as Windows 2000's ReadFile reaches it: up to the buffer's bytes of the console's
/// input, the count read stored ([`read_console_a`]); any handle but an input one is
/// ERROR_INVALID_HANDLE.
pub fn read_console(console: u32, buffer: OutBuf<'_, u8>, read: Option<Out<'_, u32>>) -> u32 {
    read_console_as(console, buffer.address(0), buffer.len() as u32, read, false)
}

/// FlushConsoleInputBuffer (and Windows 2000's FlushFileBuffers on a console handle): the input
/// buffer emptied; an output handle, or one naming nothing, is ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_FlushConsoleInputBuffer")]
pub extern "system" fn flush_console_input_buffer(console: u32) -> u32 {
    succeeded(call_server(&mut api::FlushInputBuffer {
        handle: console as usize,
    }))
}

/// VerifyConsoleIoHandle: whether a console handle names an open console object.
pub fn verify_console_io_handle(console: u32) -> bool {
    let mut message = api::VerifyIoHandle {
        handle: console as usize,
        valid: 0,
    };
    nt_success(call_server(&mut message)) && message.valid != 0
}

/// GetConsoleInputWaitHandle's handle: the event a wait on a console handle waits on, signaled
/// while the console's input buffer holds records. Windows 2000's csrss hands it over when the
/// process connects to its console; kernel32 asks F2K's server for it at the first need, under the
/// PEB lock, and keeps it for the process's life (zero when the server cannot give one: the wait
/// then fails on the console handle itself).
pub fn input_wait_handle() -> u32 {
    input_wait().get_or_make(|| {
        let mut message = api::GetInputWaitHandle { handle: 0usize };
        if nt_success(call_server(&mut message)) {
            message.handle as u32 as usize
        } else {
            0
        }
    }) as u32
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
    succeeded(call_server(&mut api::CloseHandle {
        handle: console as usize,
    }))
}

/// DuplicateConsoleHandle, as Windows 2000's DuplicateHandle reaches it: a new console handle on
/// the same console object (the source closed for DUPLICATE_CLOSE_SOURCE); INVALID_HANDLE_VALUE
/// with the server's error otherwise.
pub fn duplicate_console_handle(console: u32, access: u32, inherit: u32, options: u32) -> u32 {
    let mut message = api::DupHandle {
        handle: console as usize,
        access: access as usize,
        inherit: inherit as usize,
        options: options as usize,
        duplicate: 0,
    };
    if succeeded(call_server(&mut message)) == 0 {
        return INVALID_HANDLE_VALUE;
    }
    message.duplicate as u32
}

/// SetHandleInformation's work for a console handle, as Windows 2000's hands it to the console
/// server: the handle's inheritance set from `flags` when `mask` names HANDLE_FLAG_INHERIT (a
/// console handle carries no protection from close: that flag is not looked at);
/// ERROR_INVALID_HANDLE for one naming nothing.
pub fn set_console_handle_information(console: u32, mask: u32, flags: u32) -> u32 {
    succeeded(call_server(&mut api::SetHandleInformation {
        handle: console as usize,
        mask: mask as usize,
        flags: flags as usize,
    }))
}

/// GetHandleInformation's work for a console handle, as Windows 2000's asks the console server:
/// HANDLE_FLAG_INHERIT when the handle is inheritable, no other flag (a console handle carries no
/// protection from close); the server's status (STATUS_INVALID_HANDLE) for one naming nothing.
pub fn get_console_handle_information(console: u32) -> Result<u32, u32> {
    let mut message = api::GetHandleInformation {
        handle: console as usize,
        flags: 0,
    };
    match call_server(&mut message) {
        status if nt_success(status) => Ok(message.flags as u32),
        status => Err(status),
    }
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
/// error cleared; the server's status otherwise.
pub fn open_console(
    output: bool,
    access: u32,
    inherit: bool,
    share: u32,
) -> Result<u32, crate::error::Failure> {
    let mut message = api::OpenConsole {
        output: usize::from(output),
        access: access as usize,
        inherit: usize::from(inherit),
        share: share as usize,
        handle: 0,
    };
    let status = call_server(&mut message);
    if !nt_success(status) {
        return Err(crate::error::Failure::Status(status));
    }
    set_last_error(0);
    Ok(message.handle as u32)
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
    // SAFETY: the caller's structure (the contract).
    let info = unsafe { OutBuf::new(info, SCREEN_BUFFER_INFO_SIZE) };
    screen_buffer_info(console, info)
}

/// sizeof(CONSOLE_SCREEN_BUFFER_INFO).
const SCREEN_BUFFER_INFO_SIZE: usize = 22;

/// GetConsoleScreenBufferInfo's work.
fn screen_buffer_info(console: u32, mut info: OutBuf<'_, u8>) -> u32 {
    let mut message = api::GetScreenBufferInfo {
        handle: console as usize,
        info: [0; 6],
    };
    if succeeded(call_server(&mut message)) == 0 {
        return 0;
    }
    let mut bytes = [0u8; 24];
    for (chunk, &word) in bytes.chunks_exact_mut(4).zip(&message.info) {
        chunk.copy_from_slice(&(word as u32).to_le_bytes());
    }
    info.put(&bytes[..SCREEN_BUFFER_INFO_SIZE]);
    1
}

// --- Modes and input -----------------------------------------------------------------------------

/// SetConsoleMode: the mode of the buffer a console handle names, every handle on it sharing it.
/// An input mode past the input bits, or echo without line input, and an output mode past its
/// two bits, are ERROR_INVALID_PARAMETER; a handle naming no console object ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_SetConsoleMode")]
pub extern "system" fn set_console_mode(console: u32, mode: u32) -> u32 {
    succeeded(call_server(&mut api::SetMode {
        handle: console as usize,
        mode: mode as usize,
    }))
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
    // SAFETY: the caller's dword (the contract).
    let count = unsafe { Out::new(count) };
    input_event_count(console, count)
}

/// GetNumberOfConsoleInputEvents's work.
fn input_event_count(console: u32, mut count: Out<'_, u32>) -> u32 {
    let mut message = api::GetInputCount {
        handle: console as usize,
        count: 0,
    };
    if succeeded(call_server(&mut message)) == 0 {
        return 0;
    }
    count.set(message.count as u32);
    1
}

/// Send a call the console server may answer STATUS_PENDING (a read with nothing to take yet)
/// until it answers otherwise: each pending answer waited out on the console's input-wait handle
/// (signaled once input waits), the call then sent again as it was. The final status, `message` as
/// the server answered it.
fn call_server_waiting<M: Message>(message: &mut M) -> u32 {
    let sent = *message;
    loop {
        *message = sent;
        let status = call_server(message);
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
fn read_console_as(
    console: u32,
    buffer: usize,
    count: u32,
    read: Option<Out<'_, u32>>,
    unicode: bool,
) -> u32 {
    let mut message = api::ReadConsole {
        handle: console as usize,
        buffer,
        count: count as usize,
        read: 0,
        unicode: usize::from(unicode),
    };
    if succeeded(call_server_waiting(&mut message)) == 0 {
        return 0;
    }
    if let Some(mut read) = read {
        read.set(message.read as u32);
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
    // SAFETY: the caller's dword, when given (the contract); the buffer goes to the server, which
    // writes it.
    let read = unsafe { Out::optional(read) };
    read_console_as(console, buffer as usize, count, read, false)
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
    // SAFETY: the caller's dword, when given (the contract); the buffer goes to the server, which
    // writes it.
    let read = unsafe { Out::optional(read) };
    read_console_as(console, buffer as usize, count, read, true)
}

/// An input-record call's work: the API whose message `form` makes ([`api::PeekInput`],
/// [`api::ReadInput`] or [`api::WriteInput`]) over `length` INPUT_RECORDs at `records`, the A
/// form's characters in the console's code page; the count the server answered stored. Reads go
/// through [`call_server_waiting`]: ReadConsoleInput waits for a record.
fn input_records<M: Message + AsRef<InputRecords<usize>>>(
    form: fn(InputRecords<usize>) -> M,
    console: u32,
    records: usize,
    length: u32,
    mut count: Out<'_, u32>,
    unicode: bool,
) -> u32 {
    let mut message = form(InputRecords {
        handle: console as usize,
        records,
        length: length as usize,
        count: 0,
        unicode: usize::from(unicode),
    });
    let status = if M::API == Api::ReadInput {
        call_server_waiting(&mut message)
    } else {
        call_server(&mut message)
    };
    if succeeded(status) == 0 {
        return 0;
    }
    count.set(message.as_ref().count as u32);
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
    // SAFETY: the caller's dword (the contract); the records go to the server, which reads or
    // writes them.
    let written = unsafe { Out::new(written) };
    input_records(
        api::WriteInput,
        console,
        records as usize,
        length,
        written,
        false,
    )
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
    // SAFETY: the caller's dword (the contract); the records go to the server, which reads or
    // writes them.
    let written = unsafe { Out::new(written) };
    input_records(
        api::WriteInput,
        console,
        records as usize,
        length,
        written,
        true,
    )
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
    // SAFETY: the caller's dword (the contract); the records go to the server, which reads or
    // writes them.
    let read = unsafe { Out::new(read) };
    input_records(
        api::PeekInput,
        console,
        records as usize,
        length,
        read,
        false,
    )
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
    // SAFETY: the caller's dword (the contract); the records go to the server, which reads or
    // writes them.
    let read = unsafe { Out::new(read) };
    input_records(
        api::PeekInput,
        console,
        records as usize,
        length,
        read,
        true,
    )
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
    // SAFETY: the caller's dword (the contract); the records go to the server, which reads or
    // writes them.
    let read = unsafe { Out::new(read) };
    input_records(
        api::ReadInput,
        console,
        records as usize,
        length,
        read,
        false,
    )
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
    // SAFETY: the caller's dword (the contract); the records go to the server, which reads or
    // writes them.
    let read = unsafe { Out::new(read) };
    input_records(
        api::ReadInput,
        console,
        records as usize,
        length,
        read,
        true,
    )
}

// --- The title -----------------------------------------------------------------------------------

/// A title through the console server into `buffer` of `size` characters (see
/// [`api::GetTitle`]): the answer, 0 with the server's error when it refuses.
fn get_title(buffer: usize, size: u32, unicode: bool) -> u32 {
    let mut message = api::GetTitle {
        buffer,
        size: size as usize,
        returned: 0,
        unicode: usize::from(unicode),
    };
    if succeeded(call_server(&mut message)) == 0 {
        return 0;
    }
    message.returned as u32
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
    // SAFETY: the caller's string (the contract), read to its NUL.
    let length = unsafe { InStr::new(title) }.bytes().len();
    succeeded(call_server(&mut api::SetTitle {
        buffer: title as usize,
        length,
        unicode: 0,
    }))
}

/// SetConsoleTitleW: the title replaced by the string's characters.
///
/// # Safety
///
/// `title` is a NUL-terminated UTF-16 string.
#[unsafe(export_name = "f2k_export_SetConsoleTitleW")]
pub unsafe extern "system" fn set_console_title_w(title: *const u16) -> u32 {
    // SAFETY: the caller's string (the contract), at any address, read to its NUL.
    let length = unsafe { InWStr::new(title) }.len();
    succeeded(call_server(&mut api::SetTitle {
        buffer: title as usize,
        length,
        unicode: 1,
    }))
}

// --- Control handlers ----------------------------------------------------------------------------

/// The process's control handlers, kept as Windows 2000's kernel32 keeps them, a list in the
/// order they were added, grown as needed, its block on the process heap (none before the first
/// handler).
type CtrlHandlers = Option<HeapVec<u32>>;

own_data! {
    /// The control handlers, under the PEB lock.
    fn ctrl_handlers() -> &'static Locked<CtrlHandlers, FastPebLock> =
        Locked::new(FastPebLock, None);
}

/// The room a fresh list has.
const FIRST_ROOM: usize = 8;

/// `routine` added at the end of the list (made at the first handler, its room doubled when it is
/// full); none, the list as it was, when the heap has no room.
fn add_ctrl_handler(handlers: &mut CtrlHandlers, routine: u32) -> Result<(), OutOfMemory> {
    let list = match handlers.take() {
        Some(list) => list,
        None => HeapVec::with_capacity(FIRST_ROOM)?,
    };
    let list = handlers.insert(list);
    if list.try_push(routine).is_err() {
        list.grow(2 * list.capacity())?;
        list.push(routine);
    }
    Ok(())
}

/// The list's latest entry for `routine` taken out; whether it held one.
fn remove_ctrl_handler(handlers: &mut CtrlHandlers, routine: u32) -> bool {
    let Some(list) = handlers else {
        return false;
    };
    let Some(at) = list.iter().rposition(|&held| held == routine) else {
        return false;
    };
    list.copy_within(at + 1.., at);
    list.truncate(list.len() - 1);
    true
}

/// The process parameters' ConsoleFlags' bit that makes the process ignore Ctrl+C (what
/// SetConsoleCtrlHandler(NULL, TRUE) sets, and a child inherits).
const IGNORE_CTRL_C: u32 = 0x1;

/// SetConsoleCtrlHandler: `routine` added to the process's control handlers (a handler added
/// twice is in the list twice), or one of its entries removed (the latest); a routine the list
/// does not hold is ERROR_INVALID_PARAMETER, a list that cannot grow ERROR_NOT_ENOUGH_MEMORY. A
/// null routine sets or clears the process's ignoring of Ctrl+C, and never fails. Registration
/// only: no control event is delivered yet.
#[unsafe(export_name = "f2k_export_SetConsoleCtrlHandler")]
pub extern "system" fn set_console_ctrl_handler(routine: u32, add: u32) -> u32 {
    if routine == 0 {
        update_console_flags(|flags| {
            if add != 0 {
                flags | IGNORE_CTRL_C
            } else {
                flags & !IGNORE_CTRL_C
            }
        });
        return 1;
    }
    let error = ctrl_handlers().with(|handlers| {
        if add != 0 {
            add_ctrl_handler(handlers, routine).map_or_else(OutOfMemory::error, |()| 0)
        } else if remove_ctrl_handler(handlers, routine) {
            0
        } else {
            ERROR_INVALID_PARAMETER
        }
    });
    if error != 0 {
        set_last_error(error);
        return 0;
    }
    1
}
