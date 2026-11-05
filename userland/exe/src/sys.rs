//! The programs' seam to the system: every call they make, imported by name from kernel32.dll (and
//! user32.dll for the display settings, which only a program that changes them links), as Windows
//! 2000's own programs import them, so they run on Windows 2000 unchanged; each wrapped once in a
//! safe function. The only `unsafe` the programs reach is here.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::command::CommandLine;
use crate::output::{little_endian, Error, Sink, Writer, BUFFER};

/// The longest path a current directory can be, its terminator included (MAX_PATH).
pub const MAX_PATH: usize = 260;

/// GetStdHandle's selectors: the standard input, output and error handles.
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
/// WideCharToMultiByte's code page: the OEM code page, the console's.
const CP_OEMCP: u32 = 1;
/// WaitForSingleObject's timeout that never expires.
pub const INFINITE: u32 = u32::MAX;
/// WaitForSingleObject's answer when the object is signaled.
const WAIT_OBJECT_0: u32 = 0;
/// ERROR_INVALID_PARAMETER: a command line without its terminator.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_FILENAME_EXCED_RANGE: a path longer than a buffer of MAX_PATH units holds.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
/// ERROR_INSUFFICIENT_BUFFER: a value longer than the buffer it is read into.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// ERROR_ENVVAR_NOT_FOUND: no variable goes by the name.
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
/// ERROR_OPERATION_ABORTED: a console read Ctrl+C or Ctrl+Break abandoned.
const ERROR_OPERATION_ABORTED: u32 = 995;
/// The control events a console handler is called with for Ctrl+C and Ctrl+Break.
const CTRL_C_EVENT: u32 = 0;
const CTRL_BREAK_EVENT: u32 = 1;
/// GetFileAttributesW's failure, and a directory's attribute.
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// CreateFileW's access, sharing, disposition and attributes for a file read as it is.
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// CreateFileW's access and dispositions for a redirection's file: written, made anew (or emptied),
/// made when missing (or kept).
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_ALWAYS: u32 = 2;
const OPEN_ALWAYS: u32 = 4;
/// SetFilePointer's origin at the file's end, and its failure.
const FILE_END: u32 = 2;
const INVALID_SET_FILE_POINTER: u32 = u32::MAX;
/// DuplicateHandle's option: the new handle has the source's access.
const DUPLICATE_SAME_ACCESS: u32 = 2;
/// GetCurrentProcess's pseudo-handle.
const CURRENT_PROCESS: usize = usize::MAX;
/// STARTUPINFO's flag that makes its standard-handle fields the new process's.
const STARTF_USESTDHANDLES: u32 = 0x100;
/// ERROR_BROKEN_PIPE: a read of a pipe whose writing end is closed, the input's end.
const ERROR_BROKEN_PIPE: u32 = 109;
/// CreateFileW's failure.
const INVALID_HANDLE_VALUE: usize = usize::MAX;
/// The units a name and a value [`set_environment_variable`] takes hold together, their
/// terminators included, and a name [`environment_variable`] reads at most, its terminator
/// included: a command line's (2,047 units on Windows 2000) and two.
const VARIABLE: usize = 2049;

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
    /// Characters from a console's input buffer: in line mode (a console's default), a line as the
    /// console edits and echoes it, CR LF included.
    fn ReadConsoleW(
        console: usize,
        buffer: *mut u16,
        count: u32,
        read: *mut u32,
        control: usize,
    ) -> i32;
    /// A new process running a program, its handles and ids in `information`.
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_attributes: usize,
        thread_attributes: usize,
        inherit_handles: i32,
        flags: u32,
        environment: usize,
        directory: *const u16,
        startup: *const StartupInfo,
        information: *mut ProcessInformation,
    ) -> i32;
    /// A wait for an object to be signaled: why the wait ended, WAIT_FAILED on failure.
    fn WaitForSingleObject(object: usize, milliseconds: u32) -> u32;
    /// A process's exit code (STILL_ACTIVE while it runs).
    fn GetExitCodeProcess(process: usize, code: *mut u32) -> i32;
    /// A handle closed.
    fn CloseHandle(object: usize) -> i32;
    /// A standard handle replaced: what GetStdHandle answers from then on.
    fn SetStdHandle(which: u32, handle: usize) -> i32;
    /// A handle duplicated, from a process into a process (the current one's pseudo-handle).
    fn DuplicateHandle(
        source_process: usize,
        source: usize,
        target_process: usize,
        target: *mut usize,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    /// An anonymous pipe: its reading end and its writing end.
    fn CreatePipe(
        read: *mut usize,
        write: *mut usize,
        attributes: *const SecurityAttributes,
        size: u32,
    ) -> i32;
    /// A file's position moved: the new position's low dword, INVALID_SET_FILE_POINTER on failure.
    fn SetFilePointer(file: usize, distance: i32, high: *mut i32, method: u32) -> u32;
    /// The path of a module's file (the program's for none) into a buffer of `size` units: its
    /// length, `size` when it was cut short, zero on failure.
    fn GetModuleFileNameW(module: usize, buffer: *mut u16, size: u32) -> u32;
    /// The current directory changed to a NUL-terminated path.
    fn SetCurrentDirectoryW(path: *const u16) -> i32;
    /// The calling thread's last error set.
    fn SetLastError(error: u32);
    /// A console control handler added (`add` TRUE) to the process's list, or removed.
    fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    /// A variable's value into a buffer of `size` units: its length, the size it needs when it
    /// does not fit, zero for no such variable.
    fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;
    /// A variable set to a NUL-terminated value, or deleted (no value).
    fn SetEnvironmentVariableW(name: *const u16, value: *const u16) -> i32;
    /// A copy of the process's environment block: `NAME=value` entries, each ended by a NUL, the
    /// block by another; null on failure.
    fn GetEnvironmentStringsW() -> *mut u16;
    /// A block GetEnvironmentStringsW gave freed.
    fn FreeEnvironmentStringsW(block: *mut u16) -> i32;
    /// The local date and time.
    fn GetLocalTime(time: *mut SystemTime);
    /// A console screen buffer's size, cursor, attributes and window.
    fn GetConsoleScreenBufferInfo(console: usize, info: *mut ScreenBufferInfo) -> i32;
    /// `count` cells from a position (a COORD: X in the low word, Y in the high) set to a
    /// character.
    fn FillConsoleOutputCharacterW(
        console: usize,
        character: u16,
        count: u32,
        at: u32,
        written: *mut u32,
    ) -> i32;
    /// `count` cells from a position set to an attribute.
    fn FillConsoleOutputAttribute(
        console: usize,
        attribute: u16,
        count: u32,
        at: u32,
        written: *mut u32,
    ) -> i32;
    /// A console's cursor moved to a position.
    fn SetConsoleCursorPosition(console: usize, at: u32) -> i32;
    /// Bytes to a console's screen, in its output code page.
    fn WriteConsoleA(
        console: usize,
        buffer: *const u8,
        count: u32,
        written: *mut u32,
        reserved: usize,
    ) -> i32;
    /// A file opened (or created) by a NUL-terminated path: its handle, INVALID_HANDLE_VALUE on
    /// failure.
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        // A SECURITY_ATTRIBUTES's address, or 0 (src/files.rs declares the call so too).
        security: usize,
        disposition: u32,
        attributes: u32,
        template: usize,
    ) -> usize;
    /// Bytes from a file or pipe: zero read at the file's end.
    fn ReadFile(file: usize, buffer: *mut u8, count: u32, read: *mut u32, overlapped: usize)
        -> i32;
    /// The process's command line, NUL-terminated.
    fn GetCommandLineW() -> *const u16;
    /// A NUL-terminated path's attributes: INVALID_FILE_ATTRIBUTES when nothing goes by it.
    fn GetFileAttributesW(path: *const u16) -> u32;
    /// A code page's bytes converted to UTF-16 units: the count written, zero on failure.
    fn MultiByteToWideChar(
        code_page: u32,
        flags: u32,
        bytes: *const u8,
        byte_count: i32,
        wide: *mut u16,
        wide_count: i32,
    ) -> i32;
}

/// STARTUPINFOW: how a new process's window and standard handles start. A zeroed one, its size
/// set, asks for the defaults: a console program shares its parent's console and standard handles;
/// STARTF_USESTDHANDLES hands it the three handles given instead.
#[repr(C)]
#[derive(Default)]
struct StartupInfo {
    cb: u32,
    reserved: usize,
    desktop: usize,
    title: usize,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_size: u16,
    reserved2: usize,
    std_input: usize,
    std_output: usize,
    std_error: usize,
}

/// SECURITY_ATTRIBUTES: whether a handle made is inheritable (no security descriptor).
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: usize,
    inherit: i32,
}

/// The attributes of a handle a child process inherits.
const INHERITABLE: SecurityAttributes = SecurityAttributes {
    length: core::mem::size_of::<SecurityAttributes>() as u32,
    descriptor: 0,
    inherit: 1,
};

/// PROCESS_INFORMATION: what CreateProcessW made, a process and its first thread, by handle and id.
#[repr(C)]
#[derive(Default)]
struct ProcessInformation {
    process: usize,
    thread: usize,
    process_id: u32,
    thread_id: u32,
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
        // Longer than a current directory can be.
        MAX_PATH.. => Err(Error(ERROR_FILENAME_EXCED_RANGE)),
        _ => Ok(&buffer[..length]),
    }
}

/// The current directory changed to `path`, given without a terminator (MAX_PATH - 1 units at
/// most).
pub fn set_current_directory(path: &[u16]) -> Result<(), Error> {
    if path.len() >= MAX_PATH {
        return Err(Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut terminated = [0u16; MAX_PATH];
    terminated[..path.len()].copy_from_slice(path);
    // SAFETY: `terminated` holds the path then at least one NUL, where the call stops reading.
    if unsafe { SetCurrentDirectoryW(terminated.as_ptr()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// What [`read_line`] read.
pub enum Input<'a> {
    /// A line, CR LF included.
    Line(&'a [u16]),
    /// Nothing: Ctrl+C or Ctrl+Break abandoned the line being typed (the console leaves what was
    /// echoed of it, its cursor after it).
    Aborted,
    /// Nothing: the input's end.
    End,
}

/// A line read from the standard input, a console in line mode: the console edits and echoes it,
/// and hands it on once Enter is pressed, CR LF included. It is read into `buffer` (what does not
/// fit waits for the next read). A read Ctrl+C or Ctrl+Break abandons returns nothing with
/// ERROR_OPERATION_ABORTED, which only a process that outlives the event sees (see
/// [`outlive_interrupts`]); any other empty read is the end of the input.
pub fn read_line(buffer: &mut [u16]) -> Result<Input<'_>, Error> {
    // SAFETY: no pointers.
    let console = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let count = buffer.len().min(u32::MAX as usize) as u32;
    let mut read = 0u32;
    // The last error tells an abandoned read from the input's end: the read succeeds either way.
    // SAFETY: no pointers.
    unsafe { SetLastError(0) };
    // SAFETY: the call writes at most `count` units into `buffer` and a dword into `read`; no
    // control structure.
    if unsafe { ReadConsoleW(console, buffer.as_mut_ptr(), count, &mut read, 0) } == 0 {
        return Err(last_error());
    }
    if read == 0 {
        return Ok(if last_error() == Error(ERROR_OPERATION_ABORTED) {
            Input::Aborted
        } else {
            Input::End
        });
    }
    Ok(Input::Line(&buffer[..(read as usize).min(buffer.len())]))
}

/// Whether Ctrl+C or Ctrl+Break reached the process since [`take_interrupt`] last looked: the
/// handler sets it on its own thread.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// The console control handler [`outlive_interrupts`] adds: Ctrl+C and Ctrl+Break handled (TRUE),
/// so no handler after it ends the process, and noted for [`take_interrupt`]; any other event (the
/// console closed, a logoff, a shutdown) passed on to the default handler.
extern "system" fn outlive(event: u32) -> i32 {
    let interrupt = event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT;
    if interrupt {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }
    i32::from(interrupt)
}

/// Whether Ctrl+C or Ctrl+Break reached the process (once [`outlive_interrupts`] has made it
/// outlive them) since the last call: a shell asks before each line of a batch file.
pub fn take_interrupt() -> bool {
    INTERRUPTED.swap(false, Ordering::SeqCst)
}

/// The process's command line, as GetCommandLineW gives it (the program's name first).
pub fn command_line() -> &'static [u16] {
    // SAFETY: no arguments.
    let line = unsafe { GetCommandLineW() };
    if line.is_null() {
        return &[];
    }
    let mut length = 0;
    // SAFETY: the command line is NUL-terminated; each read is within it, up to that NUL. It lives
    // in the process's parameters, as long as the process, unchanged.
    unsafe {
        while *line.add(length) != 0 {
            length += 1;
        }
        core::slice::from_raw_parts(line, length)
    }
}

/// Whether a file (not a directory) goes by `path` (MAX_PATH - 1 units at most).
#[inline(never)]
pub fn file_exists(path: &[u16]) -> bool {
    if path.len() >= MAX_PATH {
        return false;
    }
    let mut terminated = [0u16; MAX_PATH];
    terminated[..path.len()].copy_from_slice(path);
    // SAFETY: the path ends with a NUL within `terminated`.
    let attributes = unsafe { GetFileAttributesW(terminated.as_ptr()) };
    attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_DIRECTORY == 0
}

/// Bytes in the OEM code page (a batch file's) as UTF-16, in `units`: what does not fit is
/// dropped.
pub fn oem_to_wide<'a>(bytes: &[u8], units: &'a mut [u16]) -> Result<&'a [u16], Error> {
    if bytes.is_empty() {
        return Ok(&units[..0]);
    }
    let bytes = &bytes[..bytes.len().min(units.len())];
    // SAFETY: the call reads `bytes` and writes at most `units.len()` units; an OEM code page's
    // byte is one unit at most, so they fit.
    let count = unsafe {
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            units.as_mut_ptr(),
            units.len() as i32,
        )
    };
    if count <= 0 {
        return Err(last_error());
    }
    Ok(&units[..(count as usize).min(units.len())])
}

/// Make the process outlive Ctrl+C and Ctrl+Break, as a shell does: a handler that answers TRUE
/// for them, called on a thread of its own. Not SetConsoleCtrlHandler(NULL, TRUE), whose flag
/// children inherit, so that a program the shell runs still ends on Ctrl+C.
pub fn outlive_interrupts() -> Result<(), Error> {
    // SAFETY: the handler is a function of the image, which lives as long as the process.
    if unsafe { SetConsoleCtrlHandler(Some(outlive), 1) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// The variable `name`'s value, read into `value`: None when there is no such variable (or its
/// name is longer than a command line), ERROR_INSUFFICIENT_BUFFER when it does not fit with its
/// terminator.
#[inline(never)]
pub fn environment_variable<'a>(
    name: &[u16],
    value: &'a mut [u16],
) -> Result<Option<&'a [u16]>, Error> {
    if name.len() >= VARIABLE {
        return Ok(None);
    }
    let mut terminated = [0u16; VARIABLE];
    terminated[..name.len()].copy_from_slice(name);
    let size = value.len().min(u32::MAX as usize) as u32;
    // SAFETY: no pointers.
    unsafe { SetLastError(0) };
    // SAFETY: the name ends with a NUL within `terminated`; the call writes at most `size` units
    // into `value`.
    let length = unsafe { GetEnvironmentVariableW(terminated.as_ptr(), value.as_mut_ptr(), size) };
    if length == 0 && last_error() == Error(ERROR_ENVVAR_NOT_FOUND) {
        return Ok(None);
    }
    if length >= size {
        return Err(Error(ERROR_INSUFFICIENT_BUFFER));
    }
    Ok(Some(&value[..length as usize]))
}

/// The variable `name` set to `value`, or deleted (None). The name and the value together are a
/// console line's units at most.
#[inline(never)]
pub fn set_environment_variable(name: &[u16], value: Option<&[u16]>) -> Result<(), Error> {
    let value_length = value.map_or(0, <[u16]>::len);
    if name.len() + value_length + 2 > VARIABLE {
        return Err(Error(ERROR_FILENAME_EXCED_RANGE));
    }
    // The name, its NUL, the value, its NUL.
    let mut terminated = [0u16; VARIABLE];
    terminated[..name.len()].copy_from_slice(name);
    let (name_part, value_part) = terminated.split_at_mut(name.len() + 1);
    let value_pointer = match value {
        Some(value) => {
            value_part[..value.len()].copy_from_slice(value);
            value_part.as_ptr()
        }
        None => core::ptr::null(),
    };
    // SAFETY: the name, and the value when there is one, each end with a NUL within
    // `terminated`.
    if unsafe { SetEnvironmentVariableW(name_part.as_ptr(), value_pointer) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// A copy of the process's environment block ([`environment`]), freed when it is dropped.
pub struct Environment {
    block: *mut u16,
    /// The block's units, its final NUL excluded.
    length: usize,
}

impl Environment {
    /// The block's entries, `NAME=value` each, in the block's order (Windows keeps it sorted by
    /// name; the drives' current directories, `=C:=C:\`, come first).
    pub fn entries(&self) -> impl Iterator<Item = &[u16]> {
        // SAFETY: the block holds `length` units then a NUL, and lives as long as `self`.
        let units = unsafe { core::slice::from_raw_parts(self.block, self.length) };
        units
            .split(|&unit| unit == 0)
            .filter(|entry| !entry.is_empty())
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        // SAFETY: the block is GetEnvironmentStringsW's, freed once.
        unsafe { FreeEnvironmentStringsW(self.block) };
    }
}

/// The process's environment block, copied.
pub fn environment() -> Result<Environment, Error> {
    // SAFETY: no arguments.
    let block = unsafe { GetEnvironmentStringsW() };
    if block.is_null() {
        return Err(last_error());
    }
    // The block ends with an empty entry: two NULs in a row (or one, for an empty block).
    let mut length = 0;
    // SAFETY: the block is a run of NUL-terminated entries ended by an empty one; each read is
    // within it, up to that final NUL.
    unsafe {
        while *block.add(length) != 0 {
            while *block.add(length) != 0 {
                length += 1;
            }
            length += 1;
        }
    }
    Ok(Environment { block, length })
}

/// SYSTEMTIME: a date and time, as GetLocalTime gives it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    /// 0 for Sunday to 6 for Saturday.
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

/// The local date and time.
pub fn local_time() -> SystemTime {
    let mut time = SystemTime::default();
    // SAFETY: the call writes a SYSTEMTIME into `time`.
    unsafe { GetLocalTime(&mut time) };
    time
}

/// CONSOLE_SCREEN_BUFFER_INFO: a screen buffer's size, cursor and attributes, its window's
/// rectangle and largest size.
#[repr(C)]
#[derive(Default)]
struct ScreenBufferInfo {
    size_x: i16,
    size_y: i16,
    cursor_x: i16,
    cursor_y: i16,
    attributes: u16,
    window: [i16; 4],
    maximum_window: [i16; 2],
}

/// The standard output's screen cleared, as `cls` clears it: every cell a blank in the current
/// attribute, the cursor at the top left. Ok(false), nothing done, when the standard output is no
/// console.
pub fn clear_screen() -> Result<bool, Error> {
    let Stream::Console(console) = Stream::standard(STD_OUTPUT_HANDLE) else {
        return Ok(false);
    };
    let mut info = ScreenBufferInfo::default();
    // SAFETY: the call writes a CONSOLE_SCREEN_BUFFER_INFO into `info`.
    if unsafe { GetConsoleScreenBufferInfo(console, &mut info) } == 0 {
        return Err(last_error());
    }
    let cells = (info.size_x.max(0) as u32) * (info.size_y.max(0) as u32);
    let mut written = 0;
    // SAFETY: each call writes a dword into `written`; the position 0 is the COORD (0, 0).
    let done = unsafe {
        FillConsoleOutputCharacterW(console, u16::from(b' '), cells, 0, &mut written) != 0
            && FillConsoleOutputAttribute(console, info.attributes, cells, 0, &mut written) != 0
            && SetConsoleCursorPosition(console, 0) != 0
    };
    if !done {
        return Err(last_error());
    }
    Ok(true)
}

/// A file [`open_file`] opened for reading, closed when the value is dropped.
pub struct File(usize);

impl File {
    /// The file's next bytes, into `buffer`: how many, zero at its end.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let count = buffer.len().min(u32::MAX as usize) as u32;
        let mut read = 0u32;
        // SAFETY: the call writes at most `count` bytes into `buffer` and a dword into `read`; no
        // OVERLAPPED.
        if unsafe { ReadFile(self.0, buffer.as_mut_ptr(), count, &mut read, 0) } == 0 {
            return Err(last_error());
        }
        Ok((read as usize).min(buffer.len()))
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // SAFETY: no pointers; the handle is this value's own, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The existing file `path` names (MAX_PATH - 1 units at most), opened for reading, others
/// allowed to read and write it meanwhile.
#[inline(never)]
pub fn open_file(path: &[u16]) -> Result<File, Error> {
    if path.len() >= MAX_PATH {
        return Err(Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut terminated = [0u16; MAX_PATH];
    terminated[..path.len()].copy_from_slice(path);
    // SAFETY: the path ends with a NUL within `terminated`; no security attributes or template.
    let handle = unsafe {
        CreateFileW(
            terminated.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(File(handle))
}

/// Bytes to the standard output as they are: to a console in its output code page
/// (WriteConsoleA), to anything else unchanged (WriteFile), or, once [`set_unicode_output`] has
/// turned Unicode output on, read in the OEM code page and written as UTF-16LE (`cmd /u`'s `type`
/// of a file that is not Unicode).
pub fn write_stdout_bytes(bytes: &[u8]) -> Result<(), Error> {
    if UNICODE_OUTPUT.load(Ordering::Relaxed) {
        if let Stream::File(file) = Stream::standard(STD_OUTPUT_HANDLE) {
            // An OEM code page's byte is one unit at most: a chunk's units fit a buffer of
            // as many.
            let mut units = [0u16; BUFFER];
            let mut little = [0u8; 2 * BUFFER];
            for chunk in bytes.chunks(BUFFER) {
                let units = oem_to_wide(chunk, &mut units)?;
                write_all(file, little_endian(units, &mut little))?;
            }
            return Ok(());
        }
    }
    match Stream::standard(STD_OUTPUT_HANDLE) {
        Stream::Console(console) => {
            let mut rest = bytes;
            while !rest.is_empty() {
                let mut written = 0u32;
                // SAFETY: the call reads `rest.len()` bytes of `rest` and writes a dword.
                let done = unsafe {
                    WriteConsoleA(console, rest.as_ptr(), rest.len() as u32, &mut written, 0)
                };
                if done == 0 {
                    return Err(last_error());
                }
                if written == 0 {
                    // ERROR_WRITE_FAULT: nothing taken.
                    return Err(Error(29));
                }
                rest = &rest[(written as usize).min(rest.len())..];
            }
            Ok(())
        }
        Stream::File(file) => write_all(file, bytes),
    }
}

/// A process [`create_process`] started: its handle and its first thread's, closed when the value
/// is dropped.
pub struct Process {
    process: usize,
    thread: usize,
}

impl Process {
    /// Wait for the process to end: its exit code.
    pub fn wait(&self) -> Result<u32, Error> {
        // SAFETY: no pointers; the handle is the process's, open while `self` lives.
        if unsafe { WaitForSingleObject(self.process, INFINITE) } != WAIT_OBJECT_0 {
            return Err(last_error());
        }
        let mut code = 0;
        // SAFETY: `code` is a dword the call writes.
        if unsafe { GetExitCodeProcess(self.process, &mut code) } == 0 {
            return Err(last_error());
        }
        Ok(code)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: no pointers; the handles are this value's own, closed once.
        unsafe {
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

/// A new process running the program `command_line` names, found as CreateProcessW finds one
/// without an application name (the program's directory, the current directory, the system
/// directories, PATH; `.exe` added to a name without an extension). `command_line` holds the line
/// then a NUL, and CreateProcessW may write within it. The process inherits the caller's
/// inheritable handles and shares its console, environment and current directory; its standard
/// handles are the caller's as they are now ([`standard_handle`], handed through STARTUPINFO's
/// STARTF_USESTDHANDLES), which a shell's redirection may have replaced ([`set_standard_handle`]):
/// they must be inheritable, or console handles.
pub fn create_process(command_line: &mut [u16]) -> Result<Process, Error> {
    start(None, command_line, 0, None)
}

/// A new process running the program file `application` (a path, MAX_PATH - 1 units at most,
/// relative ones to the current directory), with `command_line` (the line then a NUL, which
/// CreateProcessW may write within) as its command line, whatever program that names. Otherwise
/// as [`create_process`].
#[inline(never)]
pub fn create_process_of(application: &[u16], command_line: &mut [u16]) -> Result<Process, Error> {
    create_process_in(application, command_line, 0, None)
}

/// [`create_process_of`] with CreateProcessW's creation `flags` (a priority class's, as `start`
/// gives them) and, when there is one, the `directory` the process starts in (MAX_PATH - 1 units
/// at most) rather than the caller's.
#[inline(never)]
pub fn create_process_in(
    application: &[u16],
    command_line: &mut [u16],
    flags: u32,
    directory: Option<&[u16]>,
) -> Result<Process, Error> {
    let terminated = |path: &[u16]| {
        if path.len() >= MAX_PATH {
            return Err(Error(ERROR_FILENAME_EXCED_RANGE));
        }
        let mut terminated = [0u16; MAX_PATH];
        terminated[..path.len()].copy_from_slice(path);
        Ok(terminated)
    };
    let application = terminated(application)?;
    let directory = directory.map(terminated).transpose()?;
    start(
        Some(&application),
        command_line,
        flags,
        directory.as_ref().map(|directory| &directory[..]),
    )
}

/// CreateProcessW with `application` (NUL-terminated, or None), `command_line`, the creation
/// `flags` and the current `directory` (NUL-terminated, or None for the caller's).
fn start(
    application: Option<&[u16]>,
    command_line: &mut [u16],
    flags: u32,
    directory: Option<&[u16]>,
) -> Result<Process, Error> {
    if !command_line.contains(&0)
        || application.is_some_and(|name| !name.contains(&0))
        || directory.is_some_and(|path| !path.contains(&0))
    {
        return Err(Error(ERROR_INVALID_PARAMETER));
    }
    let startup = StartupInfo {
        cb: core::mem::size_of::<StartupInfo>() as u32,
        flags: STARTF_USESTDHANDLES,
        std_input: standard_handle(Standard::Input),
        std_output: standard_handle(Standard::Output),
        std_error: standard_handle(Standard::Error),
        ..StartupInfo::default()
    };
    let mut information = ProcessInformation::default();
    // SAFETY: the command line ends with a NUL within `command_line`, which the call may write up
    // to that terminator, and the application name and the directory, when there are, each with a
    // NUL within it; `startup` is read and `information` written, each its own type; no attributes
    // or environment.
    let done = unsafe {
        CreateProcessW(
            application.map_or(core::ptr::null(), <[u16]>::as_ptr),
            command_line.as_mut_ptr(),
            0,
            0,
            1,
            flags,
            0,
            directory.map_or(core::ptr::null(), <[u16]>::as_ptr),
            &startup,
            &mut information,
        )
    };
    if done == 0 {
        return Err(last_error());
    }
    Ok(Process {
        process: information.process,
        thread: information.thread,
    })
}

/// The three standard handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standard {
    Input,
    Output,
    Error,
}

impl Standard {
    /// GetStdHandle's selector for it.
    fn selector(self) -> u32 {
        match self {
            Standard::Input => STD_INPUT_HANDLE,
            Standard::Output => STD_OUTPUT_HANDLE,
            Standard::Error => STD_ERROR_HANDLE,
        }
    }
}

/// The standard handle `which`, as GetStdHandle gives it (a console's, a file's, a pipe's, or
/// none: 0 or INVALID_HANDLE_VALUE).
pub fn standard_handle(which: Standard) -> usize {
    // SAFETY: no pointers.
    unsafe { GetStdHandle(which.selector()) }
}

/// The standard handle `which` replaced by `handle`: the program's own output ([`stdout`],
/// [`stderr`]) and input then go there, and so do the standard handles of the processes it starts.
pub fn set_standard_handle(which: Standard, handle: usize) -> Result<(), Error> {
    // SAFETY: no pointers.
    if unsafe { SetStdHandle(which.selector(), handle) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Whether the standard input is a console (GetConsoleMode takes it), whose lines [`read_line`]
/// reads; otherwise it is a file or a pipe, which [`read_standard_input`] reads.
pub fn standard_input_is_console() -> bool {
    matches!(Stream::standard(STD_INPUT_HANDLE), Stream::Console(_))
}

/// Bytes from the standard input, a file or a pipe, into `buffer`: how many, zero at its end (a
/// pipe whose writer has closed included).
pub fn read_standard_input(buffer: &mut [u8]) -> Result<usize, Error> {
    let input = standard_handle(Standard::Input);
    let count = buffer.len().min(u32::MAX as usize) as u32;
    let mut read = 0u32;
    // SAFETY: the call writes at most `count` bytes into `buffer` and a dword into `read`; no
    // OVERLAPPED.
    if unsafe { ReadFile(input, buffer.as_mut_ptr(), count, &mut read, 0) } == 0 {
        let error = last_error();
        return if error == Error(ERROR_BROKEN_PIPE) {
            Ok(0)
        } else {
            Err(error)
        };
    }
    Ok((read as usize).min(buffer.len()))
}

/// A handle the program owns, closed when the value is dropped: a redirection's file, a duplicate,
/// a pipe's end.
pub struct Handle(usize);

impl Handle {
    /// The handle's value, for [`set_standard_handle`].
    pub fn raw(&self) -> usize {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: no pointers; the handle is this value's own, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// How a redirection opens its file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redirect {
    /// Read from its start (`<`): the file must exist.
    Read,
    /// Written from its start, made or emptied (`>`).
    Truncate,
    /// Written after its end, made when missing (`>>`).
    Append,
}

/// The file `path` names (MAX_PATH - 1 units at most) opened as a shell's redirection opens it,
/// others allowed to read and write it meanwhile, its handle inheritable so that a program the
/// shell starts can be handed it. A device's name opens the device (`nul`, `con`).
#[inline(never)]
pub fn open_redirection(path: &[u16], redirect: Redirect) -> Result<Handle, Error> {
    if path.len() >= MAX_PATH {
        return Err(Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut terminated = [0u16; MAX_PATH];
    terminated[..path.len()].copy_from_slice(path);
    let (access, disposition) = match redirect {
        Redirect::Read => (GENERIC_READ, OPEN_EXISTING),
        Redirect::Truncate => (GENERIC_WRITE, CREATE_ALWAYS),
        Redirect::Append => (GENERIC_WRITE, OPEN_ALWAYS),
    };
    let inheritable = INHERITABLE;
    // SAFETY: the path ends with a NUL within `terminated`; `inheritable` is a SECURITY_ATTRIBUTES
    // the call reads; no template.
    let handle = unsafe {
        CreateFileW(
            terminated.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &inheritable as *const SecurityAttributes as usize,
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let handle = Handle(handle);
    if redirect == Redirect::Append {
        // SAFETY: no high dword is passed or read back.
        let moved = unsafe { SetFilePointer(handle.0, 0, core::ptr::null_mut(), FILE_END) };
        if moved == INVALID_SET_FILE_POINTER {
            return Err(last_error());
        }
    }
    Ok(handle)
}

/// An inheritable duplicate of `handle` (a console's included), with its access: it shares the
/// original's file object, and its position with it.
pub fn duplicate(handle: usize) -> Result<Handle, Error> {
    let mut copy = 0;
    // SAFETY: `copy` is the handle the call writes; both processes are the current one.
    let done = unsafe {
        DuplicateHandle(
            CURRENT_PROCESS,
            handle,
            CURRENT_PROCESS,
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if done == 0 {
        return Err(last_error());
    }
    Ok(Handle(copy))
}

/// An anonymous pipe, its reading end then its writing end, neither inheritable: a program started
/// is handed the end it needs as an inheritable [`duplicate`], so that it holds no other.
pub fn create_pipe() -> Result<(Handle, Handle), Error> {
    let (mut read, mut write) = (0, 0);
    // SAFETY: the call writes the two handles; no attributes; the default size.
    if unsafe { CreatePipe(&mut read, &mut write, core::ptr::null(), 0) } == 0 {
        return Err(last_error());
    }
    Ok((Handle(read), Handle(write)))
}

/// The program's own file's path, in `buffer`.
pub fn program_path(buffer: &mut [u16; MAX_PATH]) -> Result<&[u16], Error> {
    // SAFETY: the buffer holds the MAX_PATH units the call is told of.
    let length = unsafe { GetModuleFileNameW(0, buffer.as_mut_ptr(), MAX_PATH as u32) } as usize;
    match length {
        0 => Err(last_error()),
        MAX_PATH.. => Err(Error(ERROR_FILENAME_EXCED_RANGE)),
        _ => Ok(&buffer[..length]),
    }
}

/// Whether a redirected standard stream is written as UTF-16LE rather than OEM bytes: off until
/// [`set_unicode_output`] turns it on. The process's alone: a program it starts writes its own
/// way.
static UNICODE_OUTPUT: AtomicBool = AtomicBool::new(false);

/// From now on, the standard output and error, and [`write_stdout_bytes`]' bytes, reach a file or
/// a pipe as UTF-16LE without a byte-order mark (`on`, `cmd /u`), or as bytes in the OEM code page
/// (off, the default, `cmd /a`). A console is written UTF-16 either way.
pub fn set_unicode_output(on: bool) {
    UNICODE_OUTPUT.store(on, Ordering::Relaxed);
}

/// A standard stream, as Windows 2000's console programs write one: UTF-16 to a console, and to
/// anything else (a file, a pipe: the stream redirected) bytes in the OEM code page, or UTF-16LE
/// once [`set_unicode_output`] says so.
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
                // Two bytes a unit at most, in a double-byte code page, and two a unit in
                // UTF-16LE: room for the [`BUFFER`] units a writer hands on at once.
                let mut bytes = [0u8; 2 * BUFFER];
                if UNICODE_OUTPUT.load(Ordering::Relaxed) {
                    return write_all(file, little_endian(units, &mut bytes));
                }
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

// --- The display settings (user32) ---------------------------------------------------------------

/// DEVMODEA, Windows 2000's (156 bytes): the fields ChangeDisplaySettingsA reads for a display
/// mode, and the printer ones it ignores.
#[repr(C)]
#[derive(Clone, Copy)]
struct DevModeA {
    device_name: [u8; 32],
    spec_version: u16,
    driver_version: u16,
    size: u16,
    driver_extra: u16,
    fields: u32,
    printer: [i16; 13],
    form_name: [u8; 32],
    log_pixels: u16,
    bits_per_pel: u32,
    pels_width: u32,
    pels_height: u32,
    display_flags: u32,
    display_frequency: u32,
    icm_and_panning: [u32; 8],
}

const _: () = {
    assert!(core::mem::size_of::<DevModeA>() == 156);
    assert!(core::mem::offset_of!(DevModeA, bits_per_pel) == 104);
};

/// dmFields' bits for the display fields asked.
const DM_BITSPERPEL: u32 = 0x0004_0000;
const DM_PELSWIDTH: u32 = 0x0008_0000;
const DM_PELSHEIGHT: u32 = 0x0010_0000;

#[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// Change the display's mode to the one the DEVMODEA asks: a DISP_CHANGE code.
    fn ChangeDisplaySettingsA(dev_mode: *const DevModeA, flags: u32) -> i32;
}

/// Set the display's mode to `width` by `height` at `bits_per_pixel`, dynamically (no flags): as a
/// Windows 2000 program asks it, through user32's ChangeDisplaySettingsA. The failure's
/// DISP_CHANGE code (negative).
pub fn change_display_mode(width: u32, height: u32, bits_per_pixel: u32) -> Result<(), i32> {
    let mode = DevModeA {
        device_name: [0; 32],
        spec_version: 0x0401, // DM_SPECVERSION, Windows 2000's
        driver_version: 0,
        size: core::mem::size_of::<DevModeA>() as u16,
        driver_extra: 0,
        fields: DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT,
        printer: [0; 13],
        form_name: [0; 32],
        log_pixels: 0,
        bits_per_pel: bits_per_pixel,
        pels_width: width,
        pels_height: height,
        display_flags: 0,
        display_frequency: 0,
        icm_and_panning: [0; 8],
    };
    // SAFETY: the call reads the DEVMODEA, as long as its dmSize says.
    match unsafe { ChangeDisplaySettingsA(&mode, 0) } {
        0 => Ok(()),
        code => Err(code),
    }
}

// --- The process calls (FiSH's) ------------------------------------------------------------------

/// STARTUPINFOA, as CreateProcessA takes it (68 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartupInfoA {
    pub cb: u32,
    pub reserved: *const u8,
    pub desktop: *const u8,
    pub title: *const u8,
    pub values: [u32; 7],
    pub flags: u32,
    pub show_window: u16,
    pub reserved2_length: u16,
    pub reserved2: *const u8,
    pub standard_input: u32,
    pub standard_output: u32,
    pub standard_error: u32,
}

const _: () = assert!(core::mem::size_of::<StartupInfoA>() == 68);

/// PROCESS_INFORMATION, as CreateProcessA fills it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcessInformationA {
    pub process: usize,
    pub thread: usize,
    pub process_id: u32,
    pub thread_id: u32,
}

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The calling process's command line, NUL-terminated.
    fn GetCommandLineA() -> *const u8;
    /// Start a process from `command_line` (the image is its first token), inheriting the
    /// standard handles; nonzero on success.
    fn CreateProcessA(
        application_name: *const u8,
        command_line: *mut u8,
        process_attributes: *const u8,
        thread_attributes: *const u8,
        inherit_handles: u32,
        flags: u32,
        environment_block: *const u8,
        current_directory: *const u8,
        startup_info: *const StartupInfoA,
        process_information: *mut ProcessInformationA,
    ) -> u32;
}

/// The calling process's command line as bytes up to its terminator (empty when none), as
/// GetCommandLineA gives it.
pub fn command_line_a() -> &'static [u8] {
    // SAFETY: the call returns the command line's address, NUL-terminated, for the process's life.
    let pointer = unsafe { GetCommandLineA() };
    if pointer.is_null() {
        return &[];
    }
    // SAFETY: the pointer is the command line's, NUL-terminated.
    let mut length = 0;
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
        }
        core::slice::from_raw_parts(pointer, length)
    }
}

/// A child process: its process and thread handles, closed when it is dropped.
pub struct Child {
    process: usize,
    thread: usize,
}

/// Start the child `command_line` names (its first token is the image), inheriting the standard
/// handles. The failure's last error.
pub fn create_child(command_line: &mut CommandLine) -> Result<Child, Error> {
    let startup = StartupInfoA {
        cb: 68,
        reserved: core::ptr::null(),
        desktop: core::ptr::null(),
        title: core::ptr::null(),
        values: [0; 7],
        flags: 0,
        show_window: 0,
        reserved2_length: 0,
        reserved2: core::ptr::null(),
        standard_input: 0,
        standard_output: 0,
        standard_error: 0,
    };
    let mut information = ProcessInformationA::default();
    // SAFETY: the command line is a writable buffer holding its terminator (`CommandLine`'s
    // invariant), which the call reads to and may write within; `startup` and `information` are
    // the structures the call reads and writes; the rest are null/zero.
    let ok = unsafe {
        CreateProcessA(
            core::ptr::null(),
            command_line.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            1,
            0,
            core::ptr::null(),
            core::ptr::null(),
            &startup,
            &mut information,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(Child {
        process: information.process,
        thread: information.thread,
    })
}

impl Child {
    /// Wait for the child to end, then its exit code. The wait's or the query's last error on
    /// failure. The handles are closed either way.
    pub fn wait_exit_code(self) -> Result<u32, Error> {
        // SAFETY: the process handle is open; INFINITE waits for its end.
        if unsafe { WaitForSingleObject(self.process, INFINITE) } != 0 {
            return Err(last_error());
        }
        let mut code = 0;
        // SAFETY: `code` is a dword the call writes.
        if unsafe { GetExitCodeProcess(self.process, &mut code) } == 0 {
            return Err(last_error());
        }
        Ok(code)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: both handles are the child's, open until now, closed once.
        unsafe {
            CloseHandle(self.process);
            CloseHandle(self.thread);
        }
    }
}
