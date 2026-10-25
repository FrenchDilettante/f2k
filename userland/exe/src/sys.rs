//! The programs' seam to the system: every kernel32 call they make, imported by name from
//! kernel32.dll (their only import, so they run on Windows 2000 unchanged), each wrapped once in a
//! safe function. The only `unsafe` the programs reach is here.

use crate::output::{Error, Sink, Writer, BUFFER};

/// The longest path a current directory can be, its terminator included (MAX_PATH).
pub const MAX_PATH: usize = 260;

/// GetStdHandle's selectors: the standard output and error handles.
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
/// WideCharToMultiByte's code page: the OEM code page, the console's.
const CP_OEMCP: u32 = 1;

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The calling thread's last error.
    fn GetLastError() -> u32;
    /// The process ends with the code, its DLLs told first.
    fn ExitProcess(code: u32) -> !;
    /// The current directory into a buffer of `size` units: its length, the size it needs when it
    /// does not fit, zero on failure.
    fn GetCurrentDirectoryW(size: u32, buffer: *mut u16) -> u32;
    /// A standard handle.
    fn GetStdHandle(which: u32) -> usize;
    /// A console handle's mode: FALSE for a handle naming no console.
    fn GetConsoleMode(console: usize, mode: *mut u32) -> i32;
    /// UTF-16 units to a console's screen.
    fn WriteConsoleW(
        console: usize,
        buffer: *const u16,
        count: u32,
        written: *mut u32,
        reserved: usize,
    ) -> i32;
    /// Bytes to a file or pipe.
    fn WriteFile(
        file: usize,
        buffer: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: usize,
    ) -> i32;
    /// UTF-16 units converted to a code page's bytes: the count written, zero on failure.
    fn WideCharToMultiByte(
        code_page: u32,
        flags: u32,
        wide: *const u16,
        wide_count: i32,
        bytes: *mut u8,
        byte_count: i32,
        default_char: *const u8,
        used_default: *mut i32,
    ) -> i32;
}

/// The calling thread's last error, as an [`Error`].
fn last_error() -> Error {
    // SAFETY: no arguments; it reads the thread's own TEB.
    Error(unsafe { GetLastError() })
}

/// End the process with `code`.
pub fn exit(code: u32) -> ! {
    // SAFETY: no pointers; the call does not return.
    unsafe { ExitProcess(code) }
}

/// The current directory, in `buffer`: no trailing separator but a root's.
pub fn current_directory(buffer: &mut [u16; MAX_PATH]) -> Result<&[u16], Error> {
    // SAFETY: the buffer holds the MAX_PATH units the call is told of.
    let length = unsafe { GetCurrentDirectoryW(MAX_PATH as u32, buffer.as_mut_ptr()) } as usize;
    match length {
        0 => Err(last_error()),
        // Longer than a current directory can be (ERROR_FILENAME_EXCED_RANGE).
        MAX_PATH.. => Err(Error(206)),
        _ => Ok(&buffer[..length]),
    }
}

/// A standard stream, as Windows 2000's console programs write one: UTF-16 to a console, and to
/// anything else (a file, a pipe: the stream redirected) bytes in the OEM code page.
pub enum Stream {
    Console(usize),
    File(usize),
}

impl Stream {
    /// The standard handle `which` names, a console when GetConsoleMode takes it.
    fn standard(which: u32) -> Stream {
        // SAFETY: no pointers.
        let handle = unsafe { GetStdHandle(which) };
        let mut mode = 0;
        // SAFETY: `mode` is a dword the call writes.
        if unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
            Stream::Console(handle)
        } else {
            Stream::File(handle)
        }
    }
}

impl Sink for Stream {
    fn write(&mut self, units: &[u16]) -> Result<(), Error> {
        match *self {
            Stream::Console(console) => {
                let mut written = 0;
                // SAFETY: the call reads `units.len()` units of `units` and writes a dword.
                let done = unsafe {
                    WriteConsoleW(console, units.as_ptr(), units.len() as u32, &mut written, 0)
                };
                if done == 0 {
                    return Err(last_error());
                }
                Ok(())
            }
            Stream::File(file) => {
                // Two bytes a unit at most, in a double-byte code page: room for the [`BUFFER`]
                // units a writer hands on at once.
                let mut bytes = [0u8; 2 * BUFFER];
                // SAFETY: the call reads `units` and writes at most `bytes.len()` bytes; no
                // default character, no report of its use.
                let count = unsafe {
                    WideCharToMultiByte(
                        CP_OEMCP,
                        0,
                        units.as_ptr(),
                        units.len() as i32,
                        bytes.as_mut_ptr(),
                        bytes.len() as i32,
                        core::ptr::null(),
                        core::ptr::null_mut(),
                    )
                };
                if count <= 0 {
                    return Err(last_error());
                }
                write_all(file, &bytes[..count as usize])
            }
        }
    }
}

/// Write all of `bytes` to `file`.
fn write_all(file: usize, mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        let mut written = 0u32;
        // SAFETY: the call reads `bytes.len()` bytes of `bytes` and writes a dword; no OVERLAPPED.
        let done = unsafe { WriteFile(file, bytes.as_ptr(), bytes.len() as u32, &mut written, 0) };
        if done == 0 {
            return Err(last_error());
        }
        if written == 0 {
            // ERROR_WRITE_FAULT: nothing taken.
            return Err(Error(29));
        }
        bytes = &bytes[(written as usize).min(bytes.len())..];
    }
    Ok(())
}

/// The standard output's writer.
pub fn stdout() -> Writer<Stream> {
    Writer::new(Stream::standard(STD_OUTPUT_HANDLE))
}

/// The standard error's writer.
pub fn stderr() -> Writer<Stream> {
    Writer::new(Stream::standard(STD_ERROR_HANDLE))
}
