//! The programs' console calls beyond writing and reading lines: the window's title and size, the
//! screen buffer's colours, and one key read. Each kernel32 call is imported by name and wrapped
//! once, safely.

use crate::output::Error;

/// GetStdHandle's selectors: the standard input and output handles.
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
/// The input mode a key is read in: processed input (Ctrl+C still the console's), neither
/// line-buffered nor echoed.
const ENABLE_PROCESSED_INPUT: u32 = 0x1;
/// The units a title [`set_title`] takes holds, its terminator included: a console line's and one.
const TITLE: usize = 1025;
/// ERROR_FILENAME_EXCED_RANGE: a title longer than [`TITLE`] holds.
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

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

#[link(
    name = "kernel32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
unsafe extern "system" {
    /// The calling thread's last error.
    fn GetLastError() -> u32;
    /// A standard handle.
    fn GetStdHandle(which: u32) -> usize;
    /// A console handle's mode: FALSE for a handle naming no console.
    fn GetConsoleMode(console: usize, mode: *mut u32) -> i32;
    /// A console input handle's mode set.
    fn SetConsoleMode(console: usize, mode: u32) -> i32;
    /// The console window's title set to a NUL-terminated string.
    fn SetConsoleTitleW(title: *const u16) -> i32;
    /// A console screen buffer's size, cursor, attributes and window.
    fn GetConsoleScreenBufferInfo(console: usize, info: *mut ScreenBufferInfo) -> i32;
    /// The attribute the characters written from now on take.
    fn SetConsoleTextAttribute(console: usize, attribute: u16) -> i32;
    /// `count` cells from a position (a COORD: X in the low word, Y in the high) set to an
    /// attribute.
    fn FillConsoleOutputAttribute(
        console: usize,
        attribute: u16,
        count: u32,
        at: u32,
        written: *mut u32,
    ) -> i32;
    /// Characters from a console's input buffer: in a mode without line input, those of the keys
    /// pressed, as soon as there is one.
    fn ReadConsoleW(
        console: usize,
        buffer: *mut u16,
        count: u32,
        read: *mut u32,
        control: usize,
    ) -> i32;
    /// Bytes from a file or pipe: zero read at the file's end.
    fn ReadFile(file: usize, buffer: *mut u8, count: u32, read: *mut u32, overlapped: usize)
        -> i32;
}

/// The calling thread's last error, as an [`Error`].
fn last_error() -> Error {
    // SAFETY: no arguments; it reads the thread's own TEB.
    Error(unsafe { GetLastError() })
}

/// The standard handle `which` names, and its console mode when it is a console's.
fn standard(which: u32) -> (usize, Option<u32>) {
    // SAFETY: no pointers.
    let handle = unsafe { GetStdHandle(which) };
    let mut mode = 0;
    // SAFETY: `mode` is a dword the call writes.
    let console = unsafe { GetConsoleMode(handle, &mut mode) } != 0;
    (handle, console.then_some(mode))
}

/// The console window's title set to `title` (a console line's units at most).
#[inline(never)]
pub fn set_title(title: &[u16]) -> Result<(), Error> {
    if title.len() >= TITLE {
        return Err(Error(ERROR_FILENAME_EXCED_RANGE));
    }
    let mut terminated = [0u16; TITLE];
    terminated[..title.len()].copy_from_slice(title);
    // SAFETY: the title ends with a NUL within `terminated`.
    if unsafe { SetConsoleTitleW(terminated.as_ptr()) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// The standard output's screen buffer: its handle and what it says of itself. None when the
/// standard output is no console.
fn screen() -> Result<Option<(usize, ScreenBufferInfo)>, Error> {
    let (console, Some(_)) = standard(STD_OUTPUT_HANDLE) else {
        return Ok(None);
    };
    let mut info = ScreenBufferInfo::default();
    // SAFETY: the call writes a CONSOLE_SCREEN_BUFFER_INFO into `info`.
    if unsafe { GetConsoleScreenBufferInfo(console, &mut info) } == 0 {
        return Err(last_error());
    }
    Ok(Some((console, info)))
}

/// The attribute the standard output's screen buffer writes with: None when the standard output
/// is no console.
pub fn screen_attribute() -> Result<Option<u16>, Error> {
    Ok(screen()?.map(|(_, info)| info.attributes))
}

/// The standard output's console window: its columns and rows. None when the standard output is
/// no console.
pub fn window_size() -> Result<Option<(u16, u16)>, Error> {
    Ok(screen()?.map(|(_, info)| {
        let [left, top, right, bottom] = info.window;
        let span =
            |from: i16, to: i16| u16::try_from(i32::from(to) - i32::from(from) + 1).unwrap_or(0);
        (span(left, right), span(top, bottom))
    }))
}

/// The standard output's whole screen buffer coloured with `attribute`, every cell's characters
/// kept, and what is written from now on with it, as `color` colours it. Ok(false), nothing done,
/// when the standard output is no console.
pub fn colour_screen(attribute: u16) -> Result<bool, Error> {
    let Some((console, info)) = screen()? else {
        return Ok(false);
    };
    let cells = (info.size_x.max(0) as u32) * (info.size_y.max(0) as u32);
    let mut written = 0;
    // SAFETY: the fill writes a dword into `written`; the position 0 is the COORD (0, 0).
    let done = unsafe {
        FillConsoleOutputAttribute(console, attribute, cells, 0, &mut written) != 0
            && SetConsoleTextAttribute(console, attribute) != 0
    };
    if !done {
        return Err(last_error());
    }
    Ok(true)
}

/// One key's character from the standard input, as `pause` waits for one: from a console, the
/// next key pressed that types a character, neither echoed nor waiting for Enter (the input mode
/// is put back after); from anything else, its next byte. None at the input's end.
#[inline(never)]
pub fn read_key() -> Result<Option<u16>, Error> {
    let (input, mode) = standard(STD_INPUT_HANDLE);
    let Some(mode) = mode else {
        let mut byte = 0u8;
        let mut read = 0u32;
        // SAFETY: the call writes at most one byte into `byte` and a dword into `read`; no
        // OVERLAPPED.
        if unsafe { ReadFile(input, &mut byte, 1, &mut read, 0) } == 0 {
            return Err(last_error());
        }
        return Ok((read != 0).then_some(u16::from(byte)));
    };
    // SAFETY: no pointers.
    if unsafe { SetConsoleMode(input, ENABLE_PROCESSED_INPUT) } == 0 {
        return Err(last_error());
    }
    let mut unit = 0u16;
    let mut read = 0u32;
    // SAFETY: the call writes at most one unit into `unit` and a dword into `read`; no control
    // structure.
    let done = unsafe { ReadConsoleW(input, &mut unit, 1, &mut read, 0) } != 0;
    let error = last_error();
    // SAFETY: no pointers.
    unsafe { SetConsoleMode(input, mode) };
    if !done {
        return Err(error);
    }
    Ok((read != 0).then_some(unit))
}
