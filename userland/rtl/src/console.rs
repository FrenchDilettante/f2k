//! The console server, as kernel32 reaches it through ntdll's CsrClientCallServer: the message
//! format both sides share, and the server's rules over a process's console handles.
//!
//! Windows 2000's kernel32 sends its console work to the client-server runtime (csrss, whose
//! console server owns the console and its handle tables) over an LPC port. F2K has no csrss:
//! ntdll's CsrClientCallServer raises one internal system service, and the kernel's stand-in serves
//! the message with these rules over the console's state ([`Console`]: its input buffer — the
//! records the keyboard's producer appends and the ones clients write, [`input`] — and its mode,
//! the line a line-mode read is building, its screen buffer, [`screen`], and its title). Console
//! handles stay outside the kernel's handle table, as on Windows 2000: they are the console
//! server's own, per process — (index << 2) | 3, the low two bits kernel32's CONSOLE_HANDLE test,
//! the standard handles a fresh process starts with indexes 0 to 2 (stdin 3, stdout 7, stderr 0xB).
//!
//! What mirrors Windows 2000: CsrClientCallServer's signature and answer (the message, an optional
//! capture buffer, the API number, the API data's length; the message's ReturnValue), and the
//! message header's layout ([`header`]: the LPC message header, then the capture buffer pointer,
//! the API number, the return value, a reserved word — the API's data after them), the API's data
//! one structure per API ([`api`]: Windows 2000's CSR_API_MSG holds them in a union). The API
//! numbers are made as Windows 2000's are: the console server's index, 2, in the high word, but the
//! indexes and the structures' layouts are F2K's own: Windows 2000's are internal to its kernel32
//! and csrss. The client's buffers are read where they are (the server is the kernel), never
//! captured: the capture buffer is carried, not used. The structures a console call fills are the
//! public ABI's ([`Coord`], [`SmallRect`], [`ConsoleScreenBufferInfo`]): the server answers them
//! as their bytes, in dwords.
//!
//! The server never blocks. Windows 2000's csrss holds a read's reply until its input arrives; a
//! read F2K's server cannot complete yet (a line without its Enter, an empty input buffer) answers
//! STATUS_PENDING instead, having kept what it took (a line's characters stay in the line being
//! built), and kernel32 waits on the console's input-wait handle — signaled while the input buffer
//! holds records — then asks again.

pub mod api;
pub mod input;
pub mod layout;
pub mod screen;

pub use api::Api;
use api::{Message, Word};
use input::{
    Append,
    InputBuffer,
    InputRecord,
    KeyEventRecord,
    Lights,
    Producer,
    INPUT_RECORD_BYTES,
    KEY_EVENT,
};
use screen::{Cell, Fill, ScreenBuffer, HEIGHT, OUTPUT_MODE_MASK, WIDTH, WINDOW_HEIGHT};

use crate::codepage::{self, CodePage};
use crate::pod::Pod;
use crate::status::{
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_PENDING,
    STATUS_SUCCESS,
};

/// The message header's fields, by offset into the message: Windows 2000's layout ([`CsrApiMsg`]
/// is the same layout as a structure).
pub mod header {
    /// The PORT_MESSAGE that leads every LPC message (unused here: no port carries the message).
    pub const PORT_MESSAGE: usize = 0x00;
    /// The capture buffer the client's call names (null: F2K's server reads the client's memory).
    pub const CAPTURE_BUFFER: usize = 0x18;
    /// The API number the call names.
    pub const API_NUMBER: usize = 0x1C;
    /// The server's answer: an NTSTATUS, which CsrClientCallServer returns too.
    pub const RETURN_VALUE: usize = 0x20;
    pub const RESERVED: usize = 0x24;
    /// The API's own data starts here.
    pub const DATA: usize = 0x28;
}

/// The most API data a message carries, in dwords (the server reads no more).
pub const DATA_WORDS: usize = 8;

/// A whole message's size: the header and the largest API data.
pub const MESSAGE_BYTES: usize = header::DATA + 4 * DATA_WORDS;

/// A PORT_MESSAGE, the header that leads every LPC message, in its 32-bit form: the data's and the
/// whole message's lengths, the message's type and the offset of its data information, the client
/// that sent it, its id, and the client's view size (or the callback's id). No port carries F2K's
/// console messages, so the server neither reads nor writes it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortMessage {
    pub data_length: u16,
    pub total_length: u16,
    pub kind: u16,
    pub data_info_offset: u16,
    pub client_id: crate::nt::ClientId<u32>,
    pub message_id: u32,
    pub client_view_size: u32,
}

/// A CSR_API_MSG as the server reads it from a 32-bit caller: the LPC header, the capture buffer
/// the call names, the API number, the server's answer (an NTSTATUS), a reserved word, then the
/// API's data, as many dwords as the call's length names (the server neither reads nor writes the
/// rest, as Windows 2000's port copies only the message's own length).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CsrApiMsg {
    pub header: PortMessage,
    pub capture_buffer: u32,
    pub api_number: u32,
    pub return_value: u32,
    pub reserved: u32,
    pub data: [u32; DATA_WORDS],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<PortMessage>() == header::CAPTURE_BUFFER);
    assert!(offset_of!(CsrApiMsg, header) == header::PORT_MESSAGE);
    assert!(offset_of!(CsrApiMsg, capture_buffer) == header::CAPTURE_BUFFER);
    assert!(offset_of!(CsrApiMsg, api_number) == header::API_NUMBER);
    assert!(offset_of!(CsrApiMsg, return_value) == header::RETURN_VALUE);
    assert!(offset_of!(CsrApiMsg, reserved) == header::RESERVED);
    assert!(offset_of!(CsrApiMsg, data) == header::DATA);
    assert!(size_of::<CsrApiMsg>() == MESSAGE_BYTES);
};

// SAFETY: 16- and 32-bit integers and a CLIENT_ID of two dwords, laid out back to back with no
// padding (the asserts above pin the size), every bit pattern a value.
unsafe impl crate::pod::Pod for PortMessage {}
// SAFETY: the header (plain data, above) and dwords, with no padding (the asserts above pin every
// field's offset and the size), every bit pattern a value.
unsafe impl crate::pod::Pod for CsrApiMsg {}

/// STATUS_ILLEGAL_FUNCTION: the answer to an API number no server serves (csrss's).
pub const STATUS_ILLEGAL_FUNCTION: u32 = 0xC000_00AF;

/// The console server's index among csrss's servers (Windows 2000's CONSRV_SERVERDLL_INDEX).
pub const CONSOLE_SERVER: u32 = 2;

/// The console's code pages (input and output): the OEM one, 437, as a US Windows 2000 console's.
pub const CONSOLE_CP: u32 = 437;

/// The keyboard layout the console's producer walks: the one switch for a compiled-in change.
pub const LAYOUT: &layout::Layout = &layout::US;

/// The input mode's bits: processed, line-buffered and echoed input, window and mouse events, and
/// the three later systems name ENABLE_INSERT_MODE, ENABLE_QUICK_EDIT_MODE and
/// ENABLE_EXTENDED_FLAGS.
const ENABLE_LINE_INPUT: u32 = 0x2;
const ENABLE_ECHO_INPUT: u32 = 0x4;
const INSERT_AND_QUICK_EDIT: u32 = 0x20 | 0x40;
const EXTENDED_FLAGS: u32 = 0x80;
/// Every input mode bit SetConsoleMode takes.
const INPUT_MODE_MASK: u32 = 0xFF;

/// The modes a fresh console has, as Windows 2000's console capture reports them: processed,
/// line-buffered, echoed input with the insert, quick-edit and extended-flags bits (0xE7);
/// processed output that wraps at the line's end (ENABLE_PROCESSED_OUTPUT |
/// ENABLE_WRAP_AT_EOL_OUTPUT).
pub const INPUT_MODE: u32 = 0xE7;
pub const OUTPUT_MODE: u32 = 0x1 | 0x2;

/// The attribute bits a cell holds: the foreground and background colours.
const COLOR_MASK: u32 = 0xFF;

/// The most title characters the console keeps (a longer title keeps its first ones).
pub const TITLE_UNITS: usize = 1024;

/// The most characters a line-mode read's line holds, its CR LF included: the keys typed past
/// room for them are dropped.
pub const LINE_UNITS: usize = 1024;

/// The characters a line ends with, and the ones an Enter key and a backspace stand for.
const CR: u16 = 0x0D;
const LF: u16 = 0x0A;
const BACKSPACE: u16 = 0x08;

/// COORD: a cell's column (X) and row (Y). As a dword, X is the low word.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Coord {
    pub x: i16,
    pub y: i16,
}

impl Coord {
    pub const fn from_word(word: u32) -> Self {
        Coord {
            x: word as u16 as i16,
            y: (word >> 16) as u16 as i16,
        }
    }

    pub const fn word(self) -> u32 {
        self.x as u16 as u32 | (self.y as u16 as u32) << 16
    }
}

/// SMALL_RECT: an inclusive rectangle of cells.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallRect {
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

impl SmallRect {
    /// The rectangle from its two dwords: left | top << 16, right | bottom << 16.
    pub const fn from_words(top_left: u32, bottom_right: u32) -> Self {
        let (from, to) = (Coord::from_word(top_left), Coord::from_word(bottom_right));
        SmallRect {
            left: from.x,
            top: from.y,
            right: to.x,
            bottom: to.y,
        }
    }
}

/// CONSOLE_SCREEN_BUFFER_INFO: the buffer's size, the cursor, the current attributes, the window
/// onto the buffer and the largest window the buffer allows.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsoleScreenBufferInfo {
    pub size: Coord,
    pub cursor_position: Coord,
    pub attributes: u16,
    pub window: SmallRect,
    pub maximum_window_size: Coord,
}

const _: () = assert!(core::mem::size_of::<ConsoleScreenBufferInfo>() == 22);

impl ConsoleScreenBufferInfo {
    /// The structure's bytes as dwords (the last one's high half zero), the form the server
    /// answers it in.
    pub const fn words(&self) -> [u32; 6] {
        let halves = [
            self.size.x as u16,
            self.size.y as u16,
            self.cursor_position.x as u16,
            self.cursor_position.y as u16,
            self.attributes,
            self.window.left as u16,
            self.window.top as u16,
            self.window.right as u16,
            self.window.bottom as u16,
            self.maximum_window_size.x as u16,
            self.maximum_window_size.y as u16,
            0,
        ];
        let mut words = [0; 6];
        let mut index = 0;
        while index < 6 {
            words[index] = halves[2 * index] as u32 | (halves[2 * index + 1] as u32) << 16;
            index += 1;
        }
        words
    }

    /// The structure from its dwords.
    pub fn from_words(words: [u32; 6]) -> Self {
        let half = |index: usize| (words[index / 2] >> (16 * (index % 2))) as u16;
        ConsoleScreenBufferInfo {
            size: Coord::from_word(words[0]),
            cursor_position: Coord::from_word(words[1]),
            attributes: half(4),
            window: SmallRect {
                left: half(5) as i16,
                top: half(6) as i16,
                right: half(7) as i16,
                bottom: half(8) as i16,
            },
            maximum_window_size: Coord {
                x: half(9) as i16,
                y: half(10) as i16,
            },
        }
    }
}

/// The line a line-mode read builds: the characters typed so far and, once its Enter arrived, the
/// whole line with its CR LF, handed to readers a buffer at a time until all of it is taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    units: [u16; LINE_UNITS],
    length: usize,
    /// How much of a complete line readers have taken.
    taken: usize,
    complete: bool,
}

impl Line {
    const fn new() -> Self {
        Line {
            units: [0; LINE_UNITS],
            length: 0,
            taken: 0,
            complete: false,
        }
    }

    /// The characters typed so far, or the complete line's part no reader took yet.
    pub fn pending(&self) -> &[u16] {
        &self.units[self.taken..self.length]
    }

    /// Whether the line's Enter arrived.
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// The console: its input buffer, the producer that fills it, the input buffer's mode, the line a
/// line-mode read builds, its screen buffer and its title. Each mode is its buffer's, shared by
/// every handle on that buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Console {
    pub screen: ScreenBuffer,
    pub input: InputBuffer,
    /// The keyboard's key-event producer, over [`LAYOUT`].
    pub producer: Producer,
    input_mode: u32,
    line: Line,
    title: [u16; TITLE_UNITS],
    title_length: usize,
}

impl Console {
    /// A fresh console: the default modes, a blank screen buffer, an empty input buffer and an
    /// empty title.
    // TODO: the default title a fresh console reports, captured from one.
    pub const fn new() -> Self {
        Console {
            screen: ScreenBuffer::new(),
            input: InputBuffer::new(),
            producer: Producer::new(LAYOUT),
            input_mode: INPUT_MODE,
            line: Line::new(),
            title: [0; TITLE_UNITS],
            title_length: 0,
        }
    }

    /// The input buffer's mode, as GetConsoleMode reads it: a mode holding the insert or the
    /// quick-edit bit reads with the extended-flags bit too (Windows 2000's capture: 0x20 set reads
    /// back 0xA0).
    pub fn input_mode(&self) -> u32 {
        let mode = self.input_mode;
        if mode & INSERT_AND_QUICK_EDIT != 0 {
            mode | EXTENDED_FLAGS
        } else {
            mode
        }
    }

    /// The line a line-mode read is building.
    pub fn line(&self) -> &Line {
        &self.line
    }

    /// Whether input waits for a reader: what the console's input-wait event shows.
    pub fn input_waiting(&self) -> bool {
        self.input.count() != 0
    }

    /// Take one keyboard byte: each record the producer completes is appended to the input buffer,
    /// and `appended` hears what became of it with the record as it now stands (a kept record as
    /// the input buffer holds it, its repeat count included; any other as the producer made it).
    pub fn key_byte(
        &mut self,
        byte: u8,
        lights: &mut impl Lights,
        appended: &mut impl FnMut(Append, KeyEventRecord),
    ) {
        let Console {
            input, producer, ..
        } = self;
        producer.event(byte, lights, &mut |key| {
            let outcome = input.append(key);
            let record = match (outcome, input.last()) {
                (Append::Stored | Append::Coalesced, Some(last)) => last.key,
                _ => key,
            };
            appended(outcome, record);
        });
    }

    /// The title's characters.
    pub fn title(&self) -> &[u16] {
        &self.title[..self.title_length]
    }

    /// What GetConsoleScreenBufferInfo reports: the buffer's size, the cursor, the attribute
    /// written cells take, the window onto the buffer, and the largest window: the buffer's width
    /// by the rows the screen shows.
    pub fn screen_buffer_info(&self) -> ConsoleScreenBufferInfo {
        let (row, column) = self.screen.cursor();
        let window = self.screen.window();
        ConsoleScreenBufferInfo {
            size: Coord {
                x: WIDTH as i16,
                y: HEIGHT as i16,
            },
            cursor_position: Coord {
                x: column as i16,
                y: row as i16,
            },
            attributes: self.screen.attribute().into(),
            window: SmallRect {
                left: 0,
                top: window.start as i16,
                right: WIDTH as i16 - 1,
                bottom: window.end as i16 - 1,
            },
            maximum_window_size: Coord {
                x: WIDTH as i16,
                y: WINDOW_HEIGHT as i16,
            },
        }
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

/// SetHandleInformation's flag a console handle carries: whether a child process created with
/// inheritance inherits it.
pub const HANDLE_FLAG_INHERIT: u32 = 1;

/// DuplicateHandle's options and the access a console handle carries.
const DUPLICATE_CLOSE_SOURCE: u32 = 1;
const DUPLICATE_SAME_ACCESS: u32 = 2;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// What a console handle names: the console's input buffer or its screen buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Input,
    Output,
}

/// The standard handles a fresh process starts with: stdin, stdout and stderr.
pub const STANDARD_HANDLES: [u32; 3] = [3, 7, 0xB];

/// A process's console handles: 32 slots, handle (index << 2) | 3 for slot `index`.
///
/// The handles a process starts with, and their duplicates, are its standard output: what they
/// write reaches the serial line too ([`Client::show`]'s `logged`), the stand-in for the file the
/// real machine's capture redirects standard output to. A screen buffer opened by name (CONOUT$)
/// shows on the screen alone, as on the real machine, where the capture leaves CONOUT$ on the
/// console.
///
/// Each handle carries its inheritance, as a kernel handle does: a child process created with
/// inheritance takes the inheritable ones, at their values ([`Handles::inherited`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handles {
    /// The open slots.
    open: u32,
    /// Of those, the ones naming the screen buffer (the rest name the input buffer).
    output: u32,
    /// Of those, the standard ones: the process's first handles and their duplicates.
    logged: u32,
    /// Of those, the inheritable ones.
    inheritable: u32,
}

impl Handles {
    /// No handle open.
    pub const fn empty() -> Self {
        Handles {
            open: 0,
            output: 0,
            logged: 0,
            inheritable: 0,
        }
    }

    /// A fresh process's: stdin on the input buffer, stdout and stderr on the screen buffer, opened
    /// in that order, inheritable (a console's standard handles reach the children that inherit,
    /// as a command interpreter's children share its console's).
    pub const fn standard() -> Self {
        let mut handles = Self::empty();
        let kinds = [Kind::Input, Kind::Output, Kind::Output];
        let mut index = 0;
        while index < kinds.len() {
            match handles.open(kinds[index], true) {
                Ok(handle) => assert!(handle == STANDARD_HANDLES[index]),
                Err(_) => panic!("an empty table has room"),
            }
            index += 1;
        }
        handles.logged = handles.open;
        handles
    }

    /// Open a handle on `kind`'s buffer in the lowest free slot, inheritable as `inherit` says;
    /// STATUS_NO_MEMORY when every slot is taken.
    pub const fn open(&mut self, kind: Kind, inherit: bool) -> Result<u32, u32> {
        let free = (!self.open).trailing_zeros();
        if free == 32 {
            return Err(STATUS_NO_MEMORY);
        }
        self.open |= 1 << free;
        if matches!(kind, Kind::Output) {
            self.output |= 1 << free;
        }
        if inherit {
            self.inheritable |= 1 << free;
        }
        Ok((free << 2) | 3)
    }

    /// The slot a console handle names, open or not; none for a value no slot can be.
    fn slot(handle: u32) -> Option<u32> {
        let index = handle >> 2;
        (handle & 0x1000_0003 == 3 && index < 32).then_some(index)
    }

    /// What an open handle names; none for any other value.
    pub fn kind(&self, handle: u32) -> Option<Kind> {
        let slot = Self::slot(handle)?;
        if self.open & (1 << slot) == 0 {
            None
        } else if self.output & (1 << slot) != 0 {
            Some(Kind::Output)
        } else {
            Some(Kind::Input)
        }
    }

    /// Whether an open handle is one of the standard ones, whose writes the serial line carries.
    pub fn logged(&self, handle: u32) -> bool {
        self.kind(handle).is_some() && self.logged & (1 << (handle >> 2)) != 0
    }

    /// Close an open handle: STATUS_INVALID_HANDLE for any other value.
    pub fn close(&mut self, handle: u32) -> Result<(), u32> {
        self.kind(handle).ok_or(STATUS_INVALID_HANDLE)?;
        let bit = 1 << (handle >> 2);
        self.open &= !bit;
        self.output &= !bit;
        self.logged &= !bit;
        self.inheritable &= !bit;
        Ok(())
    }

    /// Whether an open handle is inheritable; none for any other value.
    pub fn inheritable(&self, handle: u32) -> Option<bool> {
        self.kind(handle)?;
        Some(self.inheritable & (1 << (handle >> 2)) != 0)
    }

    /// Make an open handle inheritable or not: STATUS_INVALID_HANDLE for any other value.
    pub fn set_inheritable(&mut self, handle: u32, inherit: bool) -> Result<(), u32> {
        self.kind(handle).ok_or(STATUS_INVALID_HANDLE)?;
        let bit = 1 << (handle >> 2);
        if inherit {
            self.inheritable |= bit;
        } else {
            self.inheritable &= !bit;
        }
        Ok(())
    }

    /// What a child process created with inheritance takes: the inheritable handles, each at its
    /// own value, naming what it names, a standard one still standard; the others are not there.
    pub fn inherited(&self) -> Handles {
        let taken = self.inheritable & self.open;
        Handles {
            open: taken,
            output: self.output & taken,
            logged: self.logged & taken,
            inheritable: taken,
        }
    }

    /// A new handle on what `handle` names, in the lowest free slot, inheritable as `inherit` says
    /// (the source closed for DUPLICATE_CLOSE_SOURCE). A console handle carries read and write
    /// access at most: anything else asked for (without DUPLICATE_SAME_ACCESS) is
    /// STATUS_INVALID_PARAMETER; a full table STATUS_NO_MEMORY.
    pub fn duplicate(
        &mut self,
        handle: u32,
        access: u32,
        inherit: bool,
        options: u32,
    ) -> Result<u32, u32> {
        let kind = self.kind(handle).ok_or(STATUS_INVALID_HANDLE)?;
        if options & DUPLICATE_SAME_ACCESS == 0 && access & !(GENERIC_READ | GENERIC_WRITE) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let duplicate = self.open(kind, inherit)?;
        if self.logged(handle) {
            self.logged |= 1 << (duplicate >> 2);
        }
        if options & DUPLICATE_CLOSE_SOURCE != 0 {
            self.close(handle)?;
        }
        Ok(duplicate)
    }
}

/// The calling client, as the server reaches it: the bytes it shows, and its memory.
pub trait Client {
    /// Show `count` bytes of the client's memory at `buffer` on `screen`, each piece read handed to
    /// [`ScreenBuffer::render`] in order, and, `logged`, to the serial line before it (a standard
    /// handle's write: see [`Handles`]); the status that refuses them (an address the client
    /// cannot name, a buffer that cannot be read: what was read before it shown).
    fn show(
        &mut self,
        screen: &mut ScreenBuffer,
        buffer: usize,
        count: usize,
        logged: bool,
    ) -> Result<(), u32>;
    /// Show `bytes` the server made (a Unicode write's, a read's echo, in the console's code page)
    /// on `screen`, as [`Client::show`] shows the client's own.
    fn print(&mut self, screen: &mut ScreenBuffer, bytes: &[u8], _logged: bool) {
        screen.render(bytes);
    }
    /// Read the client's memory at `buffer` into `into`; the status that refuses it.
    fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32>;
    /// Write `bytes` to the client's memory at `buffer`; the status that refuses it.
    fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32>;
    /// The client process's handle to the console's input-wait event (made or opened for it); the
    /// status that refuses one.
    fn input_wait_handle(&mut self) -> Result<u32, u32>;
}

/// Serve one API call over the console and a process's handles: the message's data (the words
/// after the header, `length` bytes of them the call's) decoded as the message of the API `number`
/// names, answered, and written back as the server left it; the status, the message's ReturnValue.
/// A number no API has is STATUS_ILLEGAL_FUNCTION, a length short of its API's message
/// STATUS_INVALID_PARAMETER.
pub fn serve<W: Word>(
    console: &mut Console,
    handles: &mut Handles,
    client: &mut impl Client,
    number: u32,
    data: &mut [W; DATA_WORDS],
    length: usize,
) -> u32 {
    let Ok(api) = Api::try_from(number) else {
        return STATUS_ILLEGAL_FUNCTION;
    };
    let mut call = Call {
        console,
        handles,
        client,
    };
    let message = Exchange { data, length };
    let answer = match api {
        Api::WriteConsole => message.serve(&mut call, Call::write_console),
        Api::ReadConsole => message.serve(&mut call, Call::read_console),
        Api::GetMode => message.serve(&mut call, Call::get_mode),
        Api::SetMode => message.serve(&mut call, Call::set_mode),
        Api::GetCp => message.serve(&mut call, Call::get_cp),
        Api::VerifyIoHandle => message.serve(&mut call, Call::verify_io_handle),
        Api::FlushInputBuffer => message.serve(&mut call, Call::flush_input_buffer),
        Api::GetInputCount => message.serve(&mut call, Call::get_input_count),
        Api::PeekInput => message.serve(&mut call, Call::peek_input),
        Api::ReadInput => message.serve(&mut call, Call::read_input),
        Api::WriteInput => message.serve(&mut call, Call::write_input),
        Api::OpenConsole => message.serve(&mut call, Call::open_console),
        Api::GetInputWaitHandle => message.serve(&mut call, Call::get_input_wait_handle),
        Api::CloseHandle => message.serve(&mut call, Call::close_handle),
        Api::DupHandle => message.serve(&mut call, Call::dup_handle),
        Api::SetHandleInformation => message.serve(&mut call, Call::set_handle_information),
        Api::GetHandleInformation => message.serve(&mut call, Call::get_handle_information),
        Api::GetCursorPosition => message.serve(&mut call, Call::get_cursor_position),
        Api::SetCursorPosition => message.serve(&mut call, Call::set_cursor_position),
        Api::GetScreenBufferInfo => message.serve(&mut call, Call::get_screen_buffer_info),
        Api::SetTextAttribute => message.serve(&mut call, Call::set_text_attribute),
        Api::FillOutput => message.serve(&mut call, Call::fill_output),
        Api::ScrollRegion => message.serve(&mut call, Call::scroll_region),
        Api::GetTitle => message.serve(&mut call, Call::get_title),
        Api::SetTitle => message.serve(&mut call, Call::set_title),
    };
    match answer {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// A call's data words, as long as the call names them.
struct Exchange<'a, W> {
    data: &'a mut [W; DATA_WORDS],
    length: usize,
}

impl<W: Word> Exchange<'_, W> {
    /// The message decoded from the data, served by `serve` for `call`, and written back as it
    /// was left (on a refusal too: a read refused STATUS_PENDING answers its count of 0);
    /// STATUS_INVALID_PARAMETER, nothing served, when the call's data is shorter than the
    /// message.
    fn serve<C, M: Message<Word = W>>(
        self,
        call: &mut C,
        serve: impl FnOnce(&mut C, &mut M) -> Result<(), u32>,
    ) -> Result<(), u32> {
        let size = core::mem::size_of::<M>();
        if self.length < size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let bytes = &mut self.data.as_bytes_mut()[..size];
        let mut message = M::zeroed();
        message.as_bytes_mut().copy_from_slice(bytes);
        let answer = serve(call, &mut message);
        bytes.copy_from_slice(message.as_bytes());
        answer
    }
}

/// A character as the console's code page holds it: its OEM byte, best fit, else `?`.
fn oem_byte(unit: u16) -> u8 {
    codepage::encode_unit(CodePage::Oem, unit, true).unwrap_or(b'?')
}

/// A Unicode write: `count` UTF-16 units of the client's memory at `buffer`, read a piece at a
/// time, each unit shown as the console's code page holds it; the status that refuses the client's
/// memory, what was read before it shown.
fn show_unicode(
    console: &mut Console,
    client: &mut impl Client,
    buffer: usize,
    count: usize,
    logged: bool,
) -> Result<(), u32> {
    const PIECE: usize = 128;
    let mut done = 0;
    while done < count {
        let take = (count - done).min(PIECE);
        let mut units = [0u8; 2 * PIECE];
        client.read(buffer.wrapping_add(2 * done), &mut units[..2 * take])?;
        let mut bytes = [0u8; PIECE];
        for (at, byte) in bytes[..take].iter_mut().enumerate() {
            *byte = oem_byte(u16::from_le_bytes([units[2 * at], units[2 * at + 1]]));
        }
        client.print(&mut console.screen, &bytes[..take], logged);
        done += take;
    }
    Ok(())
}

/// Characters to the client's buffer at `buffer`: UTF-16 units, or (not `unicode`) each one's
/// byte in the console's code page; written a piece at a time.
fn put_text(
    client: &mut impl Client,
    buffer: usize,
    text: &[u16],
    unicode: bool,
) -> Result<(), u32> {
    const PIECE: usize = 128;
    let width = if unicode { 2 } else { 1 };
    for (index, piece) in text.chunks(PIECE).enumerate() {
        let mut bytes = [0u8; 2 * PIECE];
        for (at, &unit) in piece.iter().enumerate() {
            if unicode {
                bytes[2 * at..2 * at + 2].copy_from_slice(&unit.to_le_bytes());
            } else {
                bytes[at] = oem_byte(unit);
            }
        }
        client.write(
            buffer.wrapping_add(index * PIECE * width),
            &bytes[..piece.len() * width],
        )?;
    }
    Ok(())
}

/// Characters from the client's buffer at `buffer`, `count` of them (UTF-16 units, or bytes in the
/// console's code page), into `into`: at most its room, the rest not read.
fn get_text(
    client: &mut impl Client,
    buffer: usize,
    count: usize,
    unicode: bool,
    into: &mut [u16],
) -> Result<usize, u32> {
    const PIECE: usize = 128;
    let count = count.min(into.len());
    let width = if unicode { 2 } else { 1 };
    let mut done = 0;
    while done < count {
        let take = (count - done).min(PIECE);
        let mut bytes = [0u8; 2 * PIECE];
        client.read(
            buffer.wrapping_add(done * width),
            &mut bytes[..take * width],
        )?;
        for (at, unit) in into[done..done + take].iter_mut().enumerate() {
            *unit = if unicode {
                u16::from_le_bytes([bytes[2 * at], bytes[2 * at + 1]])
            } else {
                codepage::decode_byte(CodePage::Oem, bytes[at])
            };
        }
        done += take;
    }
    Ok(count)
}

/// Echo characters a line-mode read took on the screen (and the serial line: what was typed shows
/// in the boot's log), as one write: each in the console's code page, an Enter as CR LF, a
/// backspace erasing the character before the cursor.
fn echo(console: &mut Console, client: &mut impl Client, units: &[u16]) {
    console.screen.begin_write();
    for &unit in units {
        match unit {
            CR => client.print(&mut console.screen, b"\r\n", true),
            BACKSPACE => client.print(&mut console.screen, b"\x08 \x08", true),
            other => client.print(&mut console.screen, &[oem_byte(other)], true),
        }
    }
    console.screen.end_write();
}

/// A line-mode read's work: the line built from the input buffer's key records — each keydown's
/// character, as many times as it repeats; a backspace takes back the last one; the records
/// without a character are dropped — up to and including the Enter's keydown, which ends the line
/// with CR LF (the records after it stay). Echoed when the mode asks. Then up to `count`
/// characters of the line to the client, the rest kept for the next read; STATUS_PENDING while
/// the line has no Enter yet (what was typed kept in the line).
fn read_line(
    console: &mut Console,
    client: &mut impl Client,
    buffer: usize,
    count: usize,
    unicode: bool,
) -> Result<usize, u32> {
    let echoing = console.input_mode & ENABLE_ECHO_INPUT != 0;
    while !console.line.complete {
        let Some(record) = console.input.pop() else {
            return Err(STATUS_PENDING);
        };
        if !record.is_key_down() || record.key.char == 0 {
            continue;
        }
        let character = record.key.char;
        for _ in 0..record.key.repeat_count.max(1) {
            let line = &mut console.line;
            match character {
                CR => {
                    line.units[line.length] = CR;
                    line.units[line.length + 1] = LF;
                    line.length += 2;
                    line.complete = true;
                }
                BACKSPACE if line.length == 0 => continue,
                BACKSPACE => line.length -= 1,
                // Room is kept for the CR LF.
                _ if line.length + 2 >= LINE_UNITS => continue,
                other => {
                    line.units[line.length] = other;
                    line.length += 1;
                }
            }
            if echoing {
                echo(console, client, &[character]);
            }
            if console.line.complete {
                break;
            }
        }
    }
    let line = &mut console.line;
    let taken = (line.length - line.taken).min(count);
    put_text(
        client,
        buffer,
        &line.units[line.taken..line.taken + taken],
        unicode,
    )?;
    line.taken += taken;
    if line.taken == line.length {
        *line = Line::new();
    }
    Ok(taken)
}

/// The most characters a raw read answers at once.
const RAW_UNITS: usize = 128;

/// A raw read's work (no line input): the first keydown carrying a character, the records before
/// it dropped; STATUS_PENDING (every record dropped) when there is none. With room for more, the
/// characters of the keydowns after it, the records between dropped, until the input buffer is
/// empty or the room is used. What Windows 2000's console answers, as its capture shows (xyz and
/// Enter queued: 4 characters, x, a NUL, y, z): the first character, a NUL, then the following
/// ones, the count the first and the following ones — the last following one past the count.
fn read_raw(
    console: &mut Console,
    client: &mut impl Client,
    buffer: usize,
    count: usize,
    unicode: bool,
) -> Result<usize, u32> {
    let mut first = None;
    let mut repeats = 0;
    while first.is_none() {
        let record = console.input.pop().ok_or(STATUS_PENDING)?;
        if record.is_key_down() && record.key.char != 0 {
            first = Some(record.key.char);
            repeats = record.key.repeat_count.max(1) - 1;
        }
    }
    let first = first.unwrap_or_default();
    // The first character, the NUL after it, then the following ones.
    let mut text = [0u16; RAW_UNITS + 1];
    text[0] = first;
    let room = (count - 1).min(RAW_UNITS - 1);
    let mut following = 0;
    for _ in 0..repeats {
        if following < room {
            text[2 + following] = first;
            following += 1;
        }
    }
    while following < room {
        let Some(record) = console.input.pop() else {
            break;
        };
        if record.is_key_down() && record.key.char != 0 {
            for _ in 0..record.key.repeat_count.max(1) {
                if following < room {
                    text[2 + following] = record.key.char;
                    following += 1;
                }
            }
        }
    }
    let answered = 1 + following;
    put_text(client, buffer, &text[..answered], unicode)?;
    Ok(answered)
}

/// One call being served: the console, the calling process's handles, and the client. Each API's
/// work is a method over its message, the fields it answers written in place.
struct Call<'a, C> {
    console: &'a mut Console,
    handles: &'a mut Handles,
    client: &'a mut C,
}

impl<C: Client> Call<'_, C> {
    /// What the handle names; STATUS_INVALID_HANDLE when it names nothing.
    fn kind(&self, handle: impl Word) -> Result<Kind, u32> {
        self.handles
            .kind(handle.dword())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// STATUS_INVALID_HANDLE unless the handle names the screen buffer.
    fn output(&self, handle: impl Word) -> Result<(), u32> {
        match self.kind(handle) {
            Ok(Kind::Output) => Ok(()),
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// STATUS_INVALID_HANDLE unless the handle names the input buffer.
    fn input(&self, handle: impl Word) -> Result<(), u32> {
        match self.kind(handle) {
            Ok(Kind::Input) => Ok(()),
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    fn write_console<W: Word>(&mut self, message: &mut api::WriteConsole<W>) -> Result<(), u32> {
        self.output(message.handle)?;
        let (buffer, count) = (message.buffer.get(), message.count.get());
        if count != 0 {
            let console = &mut *self.console;
            console.screen.begin_write();
            let logged = self.handles.logged(message.handle.dword());
            let shown = if message.unicode.is_set() {
                show_unicode(console, self.client, buffer, count, logged)
            } else {
                self.client.show(&mut console.screen, buffer, count, logged)
            };
            console.screen.end_write();
            shown?;
        }
        message.written = message.count;
        Ok(())
    }

    fn read_console<W: Word>(&mut self, message: &mut api::ReadConsole<W>) -> Result<(), u32> {
        self.input(message.handle)?;
        let (buffer, count) = (message.buffer.get(), message.count.get());
        let unicode = message.unicode.is_set();
        let read = if count == 0 {
            0
        } else if self.console.input_mode & ENABLE_LINE_INPUT != 0 {
            read_line(self.console, self.client, buffer, count, unicode)?
        } else {
            read_raw(self.console, self.client, buffer, count, unicode)?
        };
        message.read = W::from_usize(read);
        Ok(())
    }

    fn get_mode<W: Word>(&mut self, message: &mut api::GetMode<W>) -> Result<(), u32> {
        message.mode = W::from_dword(match self.kind(message.handle)? {
            Kind::Input => self.console.input_mode(),
            Kind::Output => self.console.screen.mode(),
        });
        Ok(())
    }

    fn set_mode<W: Word>(&mut self, message: &mut api::SetMode<W>) -> Result<(), u32> {
        let mode = message.mode.dword();
        match self.kind(message.handle)? {
            Kind::Input => {
                if mode & !INPUT_MODE_MASK != 0
                    || mode & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) == ENABLE_ECHO_INPUT
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.console.input_mode = mode;
            }
            Kind::Output => {
                if mode & !OUTPUT_MODE_MASK != 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.console.screen.set_mode(mode);
            }
        }
        Ok(())
    }

    fn get_cp<W: Word>(&mut self, message: &mut api::GetCp<W>) -> Result<(), u32> {
        message.code_page = W::from_dword(CONSOLE_CP);
        Ok(())
    }

    fn verify_io_handle<W: Word>(
        &mut self,
        message: &mut api::VerifyIoHandle<W>,
    ) -> Result<(), u32> {
        message.valid = W::from_usize(usize::from(self.kind(message.handle).is_ok()));
        Ok(())
    }

    fn flush_input_buffer<W: Word>(
        &mut self,
        message: &mut api::FlushInputBuffer<W>,
    ) -> Result<(), u32> {
        self.input(message.handle)?;
        self.console.input.flush();
        Ok(())
    }

    fn get_input_count<W: Word>(&mut self, message: &mut api::GetInputCount<W>) -> Result<(), u32> {
        self.input(message.handle)?;
        message.count = W::from_usize(self.console.input.count());
        Ok(())
    }

    fn peek_input<W: Word>(&mut self, message: &mut api::PeekInput<W>) -> Result<(), u32> {
        self.copy_input(&mut message.0, false)
    }

    fn read_input<W: Word>(&mut self, message: &mut api::ReadInput<W>) -> Result<(), u32> {
        self.copy_input(&mut message.0, true)
    }

    /// PeekConsoleInput's work, and ReadConsoleInput's (`remove`: the records copied taken out of
    /// the input buffer, STATUS_PENDING while it is empty).
    fn copy_input<W: Word>(
        &mut self,
        message: &mut api::InputRecords<W>,
        remove: bool,
    ) -> Result<(), u32> {
        self.input(message.handle)?;
        let unicode = message.unicode.is_set();
        let input = &mut self.console.input;
        if remove && message.length.is_set() && input.count() == 0 {
            message.count = W::default();
            return Err(STATUS_PENDING);
        }
        // Every record is copied before any is removed: a buffer that refuses one leaves the
        // input buffer as it was.
        let copied = message.length.get().min(input.count());
        for index in 0..copied {
            let Some(record) = input.get(index) else {
                break;
            };
            let mut bytes = record.bytes();
            if !unicode && record.event_type == KEY_EVENT {
                // An A call's AsciiChar: the character in the console's code page.
                bytes[14..16].copy_from_slice(&[oem_byte(record.key.char), 0]);
            }
            let at = message
                .records
                .get()
                .wrapping_add(index * INPUT_RECORD_BYTES);
            self.client.write(at, &bytes)?;
        }
        if remove {
            input.remove(copied);
        }
        message.count = W::from_usize(copied);
        Ok(())
    }

    fn write_input<W: Word>(&mut self, message: &mut api::WriteInput<W>) -> Result<(), u32> {
        let message = &mut message.0;
        self.input(message.handle)?;
        let unicode = message.unicode.is_set();
        let mut written = 0;
        while written < message.length.get() {
            let mut bytes = [0u8; INPUT_RECORD_BYTES];
            let at = message
                .records
                .get()
                .wrapping_add(written * INPUT_RECORD_BYTES);
            self.client.read(at, &mut bytes)?;
            let mut record = InputRecord::from_bytes(&bytes);
            if !unicode && record.event_type == KEY_EVENT {
                // An A call's AsciiChar, in the console's code page.
                record.key.char = codepage::decode_byte(CodePage::Oem, bytes[14]);
            }
            if !self.console.input.push(record) {
                break;
            }
            written += 1;
        }
        message.count = W::from_usize(written);
        Ok(())
    }

    fn open_console<W: Word>(&mut self, message: &mut api::OpenConsole<W>) -> Result<(), u32> {
        let kind = if message.output.is_set() {
            Kind::Output
        } else {
            Kind::Input
        };
        message.handle = W::from_dword(self.handles.open(kind, message.inherit.is_set())?);
        Ok(())
    }

    fn get_input_wait_handle<W: Word>(
        &mut self,
        message: &mut api::GetInputWaitHandle<W>,
    ) -> Result<(), u32> {
        message.handle = W::from_dword(self.client.input_wait_handle()?);
        Ok(())
    }

    fn close_handle<W: Word>(&mut self, message: &mut api::CloseHandle<W>) -> Result<(), u32> {
        self.handles.close(message.handle.dword())
    }

    fn dup_handle<W: Word>(&mut self, message: &mut api::DupHandle<W>) -> Result<(), u32> {
        let duplicate = self.handles.duplicate(
            message.handle.dword(),
            message.access.dword(),
            message.inherit.is_set(),
            message.options.dword(),
        )?;
        message.duplicate = W::from_dword(duplicate);
        Ok(())
    }

    fn set_handle_information<W: Word>(
        &mut self,
        message: &mut api::SetHandleInformation<W>,
    ) -> Result<(), u32> {
        if message.mask.dword() & HANDLE_FLAG_INHERIT != 0 {
            let inherit = message.flags.dword() & HANDLE_FLAG_INHERIT != 0;
            self.handles
                .set_inheritable(message.handle.dword(), inherit)
        } else {
            self.kind(message.handle).map(drop)
        }
    }

    fn get_handle_information<W: Word>(
        &mut self,
        message: &mut api::GetHandleInformation<W>,
    ) -> Result<(), u32> {
        let inheritable = self
            .handles
            .inheritable(message.handle.dword())
            .ok_or(STATUS_INVALID_HANDLE)?;
        message.flags = W::from_dword(if inheritable { HANDLE_FLAG_INHERIT } else { 0 });
        Ok(())
    }

    fn get_cursor_position<W: Word>(
        &mut self,
        message: &mut api::GetCursorPosition<W>,
    ) -> Result<(), u32> {
        self.output(message.handle)?;
        let at = self.console.screen_buffer_info().cursor_position;
        message.position = W::from_dword(at.word());
        Ok(())
    }

    fn set_cursor_position<W: Word>(
        &mut self,
        message: &mut api::SetCursorPosition<W>,
    ) -> Result<(), u32> {
        self.output(message.handle)?;
        let at = Coord::from_word(message.position.dword());
        if at.x < 0 || at.y < 0 || !self.console.screen.set_cursor(at.y as usize, at.x as usize) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(())
    }

    fn get_screen_buffer_info<W: Word>(
        &mut self,
        message: &mut api::GetScreenBufferInfo<W>,
    ) -> Result<(), u32> {
        self.output(message.handle)?;
        message.info = self.console.screen_buffer_info().words().map(W::from_dword);
        Ok(())
    }

    fn set_text_attribute<W: Word>(
        &mut self,
        message: &mut api::SetTextAttribute<W>,
    ) -> Result<(), u32> {
        self.output(message.handle)?;
        let attribute = message.attributes.dword();
        if attribute & !COLOR_MASK != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.console.screen.set_attribute(attribute as u8);
        Ok(())
    }

    fn fill_output<W: Word>(&mut self, message: &mut api::FillOutput<W>) -> Result<(), u32> {
        self.output(message.handle)?;
        // The cell keeps a character's OEM byte and an attribute's colours: the low byte.
        let value = message.value.get() as u8;
        let fill = match message.element.get() {
            0 => Fill::Character(value),
            1 => Fill::Attribute(value),
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        let at = Coord::from_word(message.origin.dword());
        let count = message.count.get();
        let written = self
            .console
            .screen
            .fill(at.x.into(), at.y.into(), count, fill);
        message.written = W::from_usize(written);
        Ok(())
    }

    fn scroll_region<W: Word>(&mut self, message: &mut api::ScrollRegion<W>) -> Result<(), u32> {
        self.output(message.handle)?;
        let source = SmallRect::from_words(
            message.source_top_left.dword(),
            message.source_bottom_right.dword(),
        );
        let to = Coord::from_word(message.destination.dword());
        let screen = &mut self.console.screen;
        let fill = match message.fill.dword() {
            0 => Cell::blank(screen.attribute()),
            char_info => Cell {
                character: char_info as u8,
                attribute: (char_info >> 16) as u8,
            },
        };
        let clip = (message.clipped.dword() != 0).then(|| {
            SmallRect::from_words(
                message.clip_top_left.dword(),
                message.clip_bottom_right.dword(),
            )
        });
        screen.scroll(source, clip, to.x.into(), to.y.into(), fill);
        Ok(())
    }

    /// GetConsoleTitleW: as much of the title as fits with its terminator, the characters copied
    /// the answer; GetConsoleTitleA: the whole title and its terminator, or nothing at all (0)
    /// when they do not fit. An empty title, or a buffer of no characters, is 0 with nothing
    /// written — Windows 2000's console capture.
    fn get_title<W: Word>(&mut self, message: &mut api::GetTitle<W>) -> Result<(), u32> {
        let (buffer, size) = (message.buffer.get(), message.size.get());
        let unicode = message.unicode.is_set();
        let title = &self.console.title[..self.console.title_length];
        let length = if title.is_empty() || size == 0 {
            0
        } else if unicode {
            title.len().min(size - 1)
        } else if title.len() < size {
            title.len()
        } else {
            0
        };
        if length != 0 {
            put_text(self.client, buffer, &title[..length], unicode)?;
            let end = buffer.wrapping_add(length * if unicode { 2 } else { 1 });
            put_text(self.client, end, &[0], unicode)?;
        }
        message.returned = W::from_usize(length);
        Ok(())
    }

    /// The title is replaced only once the new one is read whole.
    fn set_title<W: Word>(&mut self, message: &mut api::SetTitle<W>) -> Result<(), u32> {
        let mut title = [0u16; TITLE_UNITS];
        let length = get_text(
            self.client,
            message.buffer.get(),
            message.length.get(),
            message.unicode.is_set(),
            &mut title,
        )?;
        self.console.title = title;
        self.console.title_length = length;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// The client's memory: `MEMORY` bytes from 0x40_0000. An address at or above 0x8000_0000 is
    /// refused as the kernel's probe refuses it, 0x1000 as an unmapped page.
    /// The grid's size, as COORD values.
    const W: i16 = WIDTH as i16;
    const H: i16 = HEIGHT as i16;

    const BASE: usize = 0x40_0000;
    const MEMORY: usize = 0x1000;

    /// A client that keeps what it shows.
    struct Kept {
        memory: Vec<u8>,
        shown: Vec<(usize, usize)>,
    }

    impl Default for Kept {
        fn default() -> Self {
            Kept {
                memory: std::vec![0; MEMORY],
                shown: Vec::new(),
            }
        }
    }

    impl Kept {
        fn range(&self, buffer: usize, count: usize) -> Result<core::ops::Range<usize>, u32> {
            match buffer {
                0x8000_0000.. => Err(crate::status::STATUS_ACCESS_VIOLATION),
                0x1000 => Err(0xC000_00E8),
                _ if buffer >= BASE && buffer + count <= BASE + MEMORY => {
                    Ok(buffer - BASE..buffer - BASE + count)
                }
                _ => Err(crate::status::STATUS_ACCESS_VIOLATION),
            }
        }
    }

    impl Client for Kept {
        fn show(
            &mut self,
            screen: &mut ScreenBuffer,
            buffer: usize,
            count: usize,
            _logged: bool,
        ) -> Result<(), u32> {
            let range = self.range(buffer, count)?;
            self.shown.push((buffer, count));
            screen.render(&self.memory[range]);
            Ok(())
        }

        fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32> {
            let range = self.range(buffer, into.len())?;
            into.copy_from_slice(&self.memory[range]);
            Ok(())
        }

        fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32> {
            let range = self.range(buffer, bytes.len())?;
            self.memory[range].copy_from_slice(bytes);
            Ok(())
        }

        fn input_wait_handle(&mut self) -> Result<u32, u32> {
            Ok(WAIT_HANDLE)
        }
    }

    /// The handle the test client hands out for the input-wait event.
    const WAIT_HANDLE: u32 = 0x44;

    /// The server's state and a client.
    struct Server {
        console: Console,
        handles: Handles,
        client: Kept,
    }

    impl Server {
        fn new() -> Self {
            Server {
                console: Console::new(),
                handles: Handles::standard(),
                client: Kept::default(),
            }
        }

        /// The call's answer: its status and data words, the message sent `data` and zeros after
        /// it, as long as the message area.
        fn call(&mut self, api: impl Into<u32>, data: &[usize]) -> (u32, [usize; DATA_WORDS]) {
            let mut words = [0; DATA_WORDS];
            words[..data.len()].copy_from_slice(data);
            let status = serve(
                &mut self.console,
                &mut self.handles,
                &mut self.client,
                api.into(),
                &mut words,
                DATA_WORDS * core::mem::size_of::<usize>(),
            );
            (status, words)
        }

        /// The status alone.
        fn status(&mut self, api: impl Into<u32>, data: &[usize]) -> u32 {
            self.call(api, data).0
        }

        /// Put `bytes` in the client's memory at BASE + `at`.
        fn poke(&mut self, at: usize, bytes: &[u8]) {
            self.client.memory[at..at + bytes.len()].copy_from_slice(bytes);
        }
    }

    #[test]
    fn a_fresh_process_has_the_standard_handles() {
        let handles = Handles::standard();
        let mut opened = Handles::empty();
        assert_eq!(
            [Kind::Input, Kind::Output, Kind::Output].map(|kind| opened.open(kind, true)),
            [Ok(3), Ok(7), Ok(0xB)],
            "allocated in the lowest free slots"
        );
        for handle in [3, 7, 0xB] {
            assert_eq!(opened.kind(handle), handles.kind(handle), "{handle:#x}");
        }
        assert!([3, 7, 0xB].iter().all(|&handle| handles.logged(handle)));
        assert!(
            !opened.logged(7),
            "a handle opened later is not a standard one"
        );
        assert_eq!(handles.kind(3), Some(Kind::Input));
        assert_eq!(handles.kind(7), Some(Kind::Output));
        assert_eq!(handles.kind(0xB), Some(Kind::Output));
        for handle in [0xF, 0, 4, 1, 0xFFFF_FFFF, 0x1000_0007, 0x7F, 0x83] {
            assert_eq!(handles.kind(handle), None, "{handle:#x}");
        }
        assert_eq!(
            STANDARD_HANDLES.map(|handle| handles.kind(handle).is_some()),
            [true; 3]
        );
    }

    #[test]
    fn writes_go_to_the_screen_on_output_handles_only() {
        let mut server = Server::new();
        assert_eq!(
            server.call(Api::WriteConsole, &[7, 0x40_0000, 15, 0xCC, 0]),
            (0, [7, 0x40_0000, 15, 15, 0, 0, 0, 0])
        );
        assert_eq!(
            server
                .call(Api::WriteConsole, &[0xB, 0x40_0000, 0, 0xCC, 0])
                .1[3],
            0
        );
        for handle in [3, 0xF, 4, 0] {
            assert_eq!(
                server
                    .call(Api::WriteConsole, &[handle, 0x40_0000, 1, 0, 0])
                    .0,
                STATUS_INVALID_HANDLE
            );
        }
        assert_eq!(
            server.client.shown,
            [(0x40_0000, 15)],
            "an empty write shows nothing"
        );
        assert_eq!(
            server.call(Api::WriteConsole, &[7, 0x8000_0000, 4, 0, 0]).0,
            0xC000_0005
        );
        assert_eq!(
            server.call(Api::WriteConsole, &[7, 0x1000, 4, 0, 0]).0,
            0xC000_00E8
        );
        assert_eq!(
            crate::status::dos_error(0xC000_0005),
            998,
            "the bare/badptr fixture's kernel address"
        );
        assert_eq!(
            crate::status::dos_error(0xC000_00E8),
            1784,
            "and its unmapped user address"
        );
    }

    #[test]
    fn modes_code_pages_and_reads() {
        let mut server = Server::new();
        assert_eq!(server.call(Api::GetMode, &[3]).1[1], 0xE7);
        assert_eq!(server.call(Api::GetMode, &[7]).1[1], 0x3);
        assert_eq!(server.call(Api::GetMode, &[0xF]).0, STATUS_INVALID_HANDLE);
        assert_eq!(server.call(Api::GetCp, &[0]).1[1], 437);
        assert_eq!(server.call(Api::GetCp, &[1]).1[1], 437);
        assert_eq!(
            server.call(Api::ReadConsole, &[3, 0x40_0000, 8, 0xCC, 1]).0,
            STATUS_PENDING,
            "nothing typed: the read waits"
        );
        assert_eq!(
            server.call(Api::ReadConsole, &[3, 0x40_0000, 0, 0xCC, 1]),
            (0, [3, 0x40_0000, 0, 0, 1, 0, 0, 0]),
            "no room: nothing, at once"
        );
        assert_eq!(
            server.call(Api::ReadConsole, &[7, 0x40_0000, 8, 0, 1]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(server.call(Api::FlushInputBuffer, &[3]).0, 0);
        assert_eq!(
            server.call(Api::FlushInputBuffer, &[7]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            server.call(Api::VerifyIoHandle, &[0xB]),
            (0, [0xB, 1, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            server.call(Api::VerifyIoHandle, &[0xF]),
            (0, [0xF, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(server.call(0x0002_0063u32, &[7]).0, STATUS_ILLEGAL_FUNCTION);
        assert_eq!(
            serve(
                &mut server.console,
                &mut server.handles,
                &mut server.client,
                Api::GetMode.into(),
                &mut [7usize, 0, 0, 0, 0, 0, 0, 0],
                core::mem::size_of::<usize>(),
            ),
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn handles_duplicate_into_the_lowest_free_slot_and_close() {
        let mut server = Server::new();
        let (status, data) =
            server.call(Api::DupHandle, &[7, 0, 0, DUPLICATE_SAME_ACCESS as usize]);
        assert_eq!((status, data[4]), (0, 0xF));
        assert_eq!(server.handles.kind(0xF), Some(Kind::Output));
        assert_eq!(server.call(Api::CloseHandle, &[7]).0, 0);
        assert_eq!(server.call(Api::CloseHandle, &[7]).0, STATUS_INVALID_HANDLE);
        assert_eq!(
            server.call(Api::WriteConsole, &[7, 0x40_0000, 1, 0, 0]).0,
            STATUS_INVALID_HANDLE
        );
        // The freed slot is the next one taken; the source goes when asked.
        assert_eq!(
            server
                .handles
                .duplicate(3, GENERIC_READ, false, DUPLICATE_CLOSE_SOURCE),
            Ok(7)
        );
        assert_eq!(
            (server.handles.kind(7), server.handles.kind(3)),
            (Some(Kind::Input), None)
        );
        assert_eq!(
            server.handles.duplicate(0xB, 0x1F_0000, false, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            server.handles.duplicate(3, 0, false, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        while server
            .handles
            .duplicate(0xB, 0, false, DUPLICATE_SAME_ACCESS)
            .is_ok()
        {}
        assert_eq!(
            server
                .handles
                .duplicate(0xB, 0, false, DUPLICATE_SAME_ACCESS),
            Err(STATUS_NO_MEMORY)
        );
        assert_eq!(server.handles.kind((31 << 2) | 3), Some(Kind::Output));
    }

    /// Each handle carries its inheritance: the standard ones inheritable, an open or a duplicate
    /// as asked, changed through the server; a child created with inheritance takes the
    /// inheritable ones alone, at their values, each naming what it names.
    #[test]
    fn handles_carry_their_inheritance() {
        let mut server = Server::new();
        assert_eq!(
            [3, 7, 0xB].map(|handle| server.handles.inheritable(handle)),
            [Some(true); 3]
        );
        let (status, data) = server.call(Api::OpenConsole, &[1, 0, 0, 0, 0]);
        assert_eq!((status, data[4]), (0, 0xF));
        assert_eq!(server.handles.inheritable(0xF), Some(false));
        let (status, data) = server.call(
            Api::DupHandle,
            &[3, 0, 1, DUPLICATE_SAME_ACCESS as usize, 0],
        );
        assert_eq!((status, data[4]), (0, 0x13));
        assert_eq!(server.handles.inheritable(0x13), Some(true));
        // The mask decides what changes; the inheritance alone is a console handle's.
        assert_eq!(server.call(Api::SetHandleInformation, &[7, 2, 0]).0, 0);
        assert_eq!(server.handles.inheritable(7), Some(true));
        assert_eq!(server.call(Api::SetHandleInformation, &[7, 1, 0]).0, 0);
        assert_eq!(server.handles.inheritable(7), Some(false));
        assert_eq!(server.call(Api::SetHandleInformation, &[0xF, 3, 3]).0, 0);
        assert_eq!(server.handles.inheritable(0xF), Some(true));
        assert_eq!(
            server.call(Api::SetHandleInformation, &[0x17, 1, 1]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            server.call(Api::SetHandleInformation, &[0x17, 0, 0]).0,
            STATUS_INVALID_HANDLE
        );
        // Asked back: the inheritance alone, never a protection from close.
        let (status, data) = server.call(Api::GetHandleInformation, &[0xF, 0]);
        assert_eq!((status, data[1]), (0, 1));
        let (status, data) = server.call(Api::GetHandleInformation, &[7, 0]);
        assert_eq!((status, data[1]), (0, 0));
        assert_eq!(
            server.call(Api::GetHandleInformation, &[0x17, 0]).0,
            STATUS_INVALID_HANDLE
        );
        let child = server.handles.inherited();
        assert_eq!(
            [3, 7, 0xB, 0xF, 0x13].map(|handle| child.kind(handle)),
            [
                Some(Kind::Input),
                None,
                Some(Kind::Output),
                Some(Kind::Output),
                Some(Kind::Input)
            ]
        );
        assert!(child.logged(3) && child.logged(0x13) && !child.logged(0xF));
        assert_eq!(child.inheritable(0xF), Some(true));
        assert_eq!(server.handles.close(0xF), Ok(()));
        assert_eq!(server.handles.inheritable(0xF), None);
        let mut reopened = server.handles;
        assert_eq!(reopened.open(Kind::Output, false), Ok(0xF));
        assert_eq!(
            reopened.inheritable(0xF),
            Some(false),
            "a closed slot keeps no inheritance"
        );
    }

    #[test]
    fn handles_open_in_the_lowest_free_slot() {
        let mut handles = Handles::empty();
        assert_eq!(handles.kind(3), None);
        assert_eq!(handles.open(Kind::Output, false), Ok(3));
        assert_eq!(handles.open(Kind::Input, false), Ok(7));
        assert_eq!(handles.close(3), Ok(()));
        assert_eq!(
            handles.open(Kind::Input, false),
            Ok(3),
            "the freed slot first"
        );
        assert_eq!(
            handles.kind(3),
            Some(Kind::Input),
            "the new kind, not the old"
        );
        while handles.open(Kind::Output, false).is_ok() {}
        assert_eq!(handles.open(Kind::Input, false), Err(STATUS_NO_MEMORY));
        assert_eq!(handles.kind((31 << 2) | 3), Some(Kind::Output));
    }

    /// Writes reach the screen buffer through the renderer, in the output mode the buffer holds.
    #[test]
    fn writes_render_into_the_screen_buffer() {
        let mut server = Server::new();
        server.poke(0, b"Hello\r\nworld");
        assert_eq!(
            server.call(Api::WriteConsole, &[7, BASE, 12, 0, 0]),
            (0, [7, BASE, 12, 12, 0, 0, 0, 0])
        );
        assert_eq!(&server.console.screen.row_text(0)[..6], b"Hello ");
        assert_eq!(&server.console.screen.row_text(1)[..6], b"world ");
        assert_eq!(server.console.screen.cursor(), (1, 5));
        // A refused buffer shows nothing.
        assert_eq!(
            server.status(Api::WriteConsole, &[0xB, 0x8000_0000, 4, 0, 0]),
            0xC000_0005
        );
        assert_eq!(server.console.screen.cursor(), (1, 5));
    }

    #[test]
    fn the_cursor_position_round_trips_inside_the_buffer() {
        let mut server = Server::new();
        let at = Coord { x: W - 1, y: H - 1 }.word() as usize;
        assert_eq!(server.status(Api::SetCursorPosition, &[7, at]), 0);
        assert_eq!(server.call(Api::GetCursorPosition, &[0xB, 0]).1[1], at);
        assert_eq!(server.console.screen.cursor(), (HEIGHT - 1, WIDTH - 1));
        for outside in [
            Coord { x: W, y: 0 },
            Coord { x: 0, y: H },
            Coord { x: -1, y: 0 },
        ] {
            assert_eq!(
                server.status(Api::SetCursorPosition, &[7, outside.word() as usize]),
                STATUS_INVALID_PARAMETER,
                "{outside:?}"
            );
        }
        assert_eq!(
            server.console.screen.cursor(),
            (HEIGHT - 1, WIDTH - 1),
            "a refused move moves nothing"
        );
        for api in [Api::GetCursorPosition, Api::SetCursorPosition] {
            assert_eq!(server.status(api, &[3, 0]), STATUS_INVALID_HANDLE);
            assert_eq!(server.status(api, &[0xF, 0]), STATUS_INVALID_HANDLE);
        }
    }

    #[test]
    fn the_screen_buffer_info_describes_the_buffer() {
        let mut server = Server::new();
        server.console.screen.set_cursor(3, 12);
        let (status, data) = server.call(Api::GetScreenBufferInfo, &[7]);
        assert_eq!(status, 0);
        let mut words = [0u32; 6];
        for (word, &value) in words.iter_mut().zip(&data[1..7]) {
            *word = value as u32;
        }
        let info = ConsoleScreenBufferInfo::from_words(words);
        assert_eq!(
            info,
            ConsoleScreenBufferInfo {
                size: Coord { x: W, y: H },
                cursor_position: Coord { x: 12, y: 3 },
                attributes: 0x07,
                window: SmallRect {
                    left: 0,
                    top: 0,
                    right: W - 1,
                    bottom: WINDOW_HEIGHT as i16 - 1
                },
                maximum_window_size: Coord {
                    x: W,
                    y: WINDOW_HEIGHT as i16
                },
            }
        );
        assert_eq!((W, H), (80, 300), "Windows 2000's default buffer");
        assert_eq!(
            server.status(Api::GetScreenBufferInfo, &[3]),
            STATUS_INVALID_HANDLE
        );
        // The window follows the cursor down the buffer.
        server.console.screen.set_cursor(100, 0);
        let (_, data) = server.call(Api::GetScreenBufferInfo, &[7]);
        let words = [1, 2, 3, 4, 5, 6].map(|index| data[index] as u32);
        let info = ConsoleScreenBufferInfo::from_words(words);
        assert_eq!((info.window.top, info.window.bottom), (76, 100));
    }

    /// The dwords are the structure's bytes: a client copying them over the structure reads the
    /// same fields.
    #[test]
    fn the_info_words_are_the_structures_bytes() {
        let info = ConsoleScreenBufferInfo {
            size: Coord { x: 132, y: 300 },
            cursor_position: Coord { x: -2, y: 7 },
            attributes: 0x1E,
            window: SmallRect {
                left: 1,
                top: 2,
                right: 3,
                bottom: 4,
            },
            maximum_window_size: Coord { x: 5, y: 6 },
        };
        let words = info.words();
        let mut bytes = [0u8; 24];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        // SAFETY: a plain repr(C) structure of integers, read from 22 initialized bytes.
        let read: ConsoleScreenBufferInfo =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) };
        assert_eq!(read, info);
        assert_eq!(words[5] >> 16, 0);
        assert_eq!(ConsoleScreenBufferInfo::from_words(words), info);
        assert_eq!(Coord::from_word(0xFFFF_0005), Coord { x: 5, y: -1 });
    }

    #[test]
    fn the_text_attribute_takes_colours_only() {
        let mut server = Server::new();
        assert_eq!(server.status(Api::SetTextAttribute, &[7, 0x1E]), 0);
        assert_eq!(server.console.screen.attribute(), 0x1E);
        assert_eq!(
            server.call(Api::GetScreenBufferInfo, &[7]).1[3] & 0xFFFF,
            0x1E
        );
        for attribute in [0x100, 0x8000, 0x1_0000] {
            assert_eq!(
                server.status(Api::SetTextAttribute, &[7, attribute]),
                STATUS_INVALID_PARAMETER,
                "{attribute:#x}"
            );
        }
        assert_eq!(server.console.screen.attribute(), 0x1E);
        assert_eq!(
            server.status(Api::SetTextAttribute, &[3, 0x07]),
            STATUS_INVALID_HANDLE
        );
        server.poke(0, b"x");
        server.call(Api::WriteConsole, &[7, BASE, 1, 0, 0]);
        assert_eq!(server.console.screen.cell(0, 0).attribute, 0x1E);
    }

    #[test]
    fn fills_write_characters_or_attributes_and_count_them() {
        let mut server = Server::new();
        let at = |x: i16, y: i16| Coord { x, y }.word() as usize;
        assert_eq!(
            server.call(
                Api::FillOutput,
                &[7, 0, b'#' as usize, 5, at(W - 2, 0), 0xCC]
            ),
            (0, [7, 0, b'#' as usize, 5, at(W - 2, 0), 5, 0, 0])
        );
        let screen = &server.console.screen;
        assert_eq!(&screen.row_text(0)[WIDTH - 2..], b"##");
        assert_eq!(&screen.row_text(1)[..4], b"### ");
        assert_eq!(
            server
                .call(Api::FillOutput, &[7, 1, 0x4F, 3, at(W - 1, 0), 0])
                .1[5],
            3
        );
        let screen = &server.console.screen;
        assert_eq!(
            (
                screen.cell(0, WIDTH - 1),
                screen.cell(1, 1),
                screen.cell(1, 2)
            ),
            (
                Cell {
                    character: b'#',
                    attribute: 0x4F
                },
                Cell {
                    character: b'#',
                    attribute: 0x4F
                },
                Cell {
                    character: b'#',
                    attribute: 0x07
                }
            )
        );
        assert_eq!(
            server
                .call(
                    Api::FillOutput,
                    &[7, 0, b'+' as usize, 9999, at(W - 3, H - 1), 0]
                )
                .1[5],
            3,
            "clipped at the buffer's end"
        );
        assert_eq!(
            server.call(Api::FillOutput, &[7, 0, b'!' as usize, 4, at(W, 0), 0xCC]),
            (0, [7, 0, b'!' as usize, 4, at(W, 0), 0, 0, 0]),
            "outside the buffer: nothing, and success"
        );
        assert_eq!(
            server
                .call(Api::FillOutput, &[7, 0, b'!' as usize, 4, at(-1, 3), 0])
                .1[5],
            0
        );
        assert_eq!(
            server.status(Api::FillOutput, &[7, 2, 0, 1, at(0, 0), 0]),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server.status(Api::FillOutput, &[3, 0, 0, 1, at(0, 0), 0]),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn a_scroll_region_moves_cells_and_fills_the_rest() {
        let mut server = Server::new();
        let words = |left: i16, top: i16, right: i16, bottom: i16| {
            (
                Coord { x: left, y: top }.word() as usize,
                Coord {
                    x: right,
                    y: bottom,
                }
                .word() as usize,
            )
        };
        server.poke(0, b"top\nmid\nend");
        server.call(Api::WriteConsole, &[7, BASE, 11, 0, 0]);
        server.console.screen.set_attribute(0x2A);
        // Rows 1-2 up one; a zero fill is a space in the current attribute.
        let (from, to) = words(0, 1, W - 1, 2);
        assert_eq!(
            server.status(Api::ScrollRegion, &[7, from, to, 0, 0, 0, 0, 0]),
            0
        );
        let screen = &server.console.screen;
        assert_eq!(&screen.row_text(0)[..4], b"mid ");
        assert_eq!(&screen.row_text(1)[..4], b"end ");
        assert!(screen.cells()[2]
            .iter()
            .all(|&cell| cell == Cell::blank(0x2A)));
        // A CHAR_INFO fill, and a clip that keeps row 0.
        let (from, to) = words(0, 0, 2, 1);
        let (clip_from, clip_to) = words(0, 1, W - 1, H - 1);
        let fill = b'.' as usize | 0x1F << 16;
        let at = Coord { x: 0, y: 1 }.word() as usize;
        assert_eq!(
            server.status(
                Api::ScrollRegion,
                &[7, from, to, at, fill, 1, clip_from, clip_to]
            ),
            0
        );
        let screen = &server.console.screen;
        assert_eq!(&screen.row_text(0)[..4], b"mid ", "outside the clip");
        assert_eq!(&screen.row_text(1)[..4], b"mid ");
        assert_eq!(&screen.row_text(2)[..4], b"end ");
        // A source wholly outside: nothing, and success.
        let before = server.console.clone();
        let (from, to) = words(100, 0, 120, 5);
        assert_eq!(
            server.status(Api::ScrollRegion, &[7, from, to, 0, fill, 0, 0, 0]),
            0
        );
        assert_eq!(server.console, before);
        assert_eq!(
            server.status(Api::ScrollRegion, &[3, 0, 0, 0, 0, 0, 0, 0]),
            STATUS_INVALID_HANDLE
        );
    }

    /// The UTF-16 units of `text`.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    impl Server {
        /// Put `text` in the client's memory at BASE + `at` as UTF-16 units.
        fn poke_wide(&mut self, at: usize, text: &str) {
            let bytes: Vec<u8> = wide(text)
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            self.poke(at, &bytes);
        }

        /// GET_TITLE into a buffer of `size` characters at BASE + 0x800 filled with '#' first: the
        /// answer, and the buffer's first `size` + 2 characters' bytes.
        fn title(&mut self, size: usize, unicode: bool) -> (usize, Vec<u8>) {
            let width = if unicode { 2 } else { 1 };
            self.poke(0x800, &std::vec![b'#'; (size + 2) * width]);
            let (status, data) = self.call(
                Api::GetTitle,
                &[BASE + 0x800, size, 0xCC, usize::from(unicode)],
            );
            assert_eq!(status, 0);
            (
                data[2],
                self.client.memory[0x800..0x800 + (size + 2) * width].to_vec(),
            )
        }
    }

    /// The title, set and read back as Windows 2000's console capture shows: GetConsoleTitleW
    /// truncates to the buffer with its terminator; GetConsoleTitleA answers the whole title or
    /// nothing; an empty title, or a buffer of no characters, is 0 with nothing written.
    #[test]
    fn the_title_round_trips() {
        let mut server = Server::new();
        assert_eq!(server.title(64, true).0, 0, "empty to start");
        server.poke_wide(0, "F2K title");
        assert_eq!(server.status(Api::SetTitle, &[BASE, 9, 1]), 0);
        assert_eq!(server.console.title(), wide("F2K title"));
        // A unit the fill left reads as two '#' bytes.
        let units = |text: &str| -> Vec<u8> {
            wide(text)
                .iter()
                .map(|&unit| {
                    if unit == u16::from(b'#') {
                        0x2323
                    } else {
                        unit
                    }
                })
                .flat_map(|unit| unit.to_le_bytes())
                .collect()
        };
        assert_eq!(server.title(10, true), (9, units("F2K title\0##")));
        assert_eq!(server.title(9, true), (8, units("F2K titl\0##")));
        assert_eq!(server.title(4, true), (3, units("F2K\0##")));
        assert_eq!(server.title(0, true), (0, units("##")));
        assert_eq!(server.title(10, false), (9, b"F2K title\0##".to_vec()));
        assert_eq!(server.title(9, false), (0, b"###########".to_vec()));
        assert_eq!(server.title(0, false), (0, b"##".to_vec()));
        // An A title is the console's code page's: 0x82 is e acute.
        server.poke(0x100, b"Caf\x82");
        assert_eq!(server.status(Api::SetTitle, &[BASE + 0x100, 4, 0]), 0);
        assert_eq!(server.console.title(), wide("Caf\u{e9}"));
        assert_eq!(server.title(5, false), (4, b"Caf\x82\0##".to_vec()));
        // An empty title: nothing written either way.
        assert_eq!(server.status(Api::SetTitle, &[BASE, 0, 1]), 0);
        assert_eq!(server.title(4, true), (0, units("######")));
        assert_eq!(server.title(4, false), (0, b"######".to_vec()));
        // A buffer that cannot be read leaves the title; one that cannot be written fails.
        server.poke_wide(0, "Short");
        assert_eq!(server.status(Api::SetTitle, &[BASE, 5, 1]), 0);
        assert_eq!(
            server.status(Api::SetTitle, &[0x8000_0000, 4, 1]),
            0xC000_0005
        );
        assert_eq!(server.console.title(), wide("Short"));
        assert_eq!(
            server.status(Api::GetTitle, &[0x1000, 8, 0, 1]),
            0xC000_00E8
        );
        // A title past the console's room keeps its first characters.
        server.poke(0, &[b'x'; MEMORY]);
        assert_eq!(
            server.status(Api::SetTitle, &[BASE, TITLE_UNITS + 100, 0]),
            0
        );
        assert_eq!(server.console.title(), &[u16::from(b'x'); TITLE_UNITS][..]);
    }

    #[test]
    fn modes_are_per_buffer_and_checked() {
        let mut server = Server::new();
        let mode = |server: &mut Server, handle| server.call(Api::GetMode, &[handle, 0]).1[1];
        assert_eq!(server.status(Api::SetMode, &[7, 0x1]), 0);
        assert_eq!(
            mode(&mut server, 0xB),
            0x1,
            "every handle on the screen buffer"
        );
        assert_eq!(mode(&mut server, 3), 0xE7, "the input buffer's own");
        assert_eq!(server.status(Api::SetMode, &[3, 0x3]), 0);
        assert_eq!(mode(&mut server, 3), 0x3);
        // The insert and quick-edit bits read back with the extended flags (the capture's 0xA0).
        assert_eq!(server.status(Api::SetMode, &[3, 0x20]), 0);
        assert_eq!(mode(&mut server, 3), 0xA0);
        assert_eq!(server.status(Api::SetMode, &[3, 0x41]), 0);
        assert_eq!(mode(&mut server, 3), 0xC1);
        assert_eq!(server.status(Api::SetMode, &[3, 0x1F]), 0);
        for (handle, bad) in [
            (7, 0x4),
            (7, 0x8000_0003),
            (3, 0x8000),
            (3, 0x100),
            (3, 0x4),
            (3, 0x5),
        ] {
            assert_eq!(
                server.status(Api::SetMode, &[handle, bad]),
                STATUS_INVALID_PARAMETER,
                "{handle:#x} {bad:#x}"
            );
        }
        assert_eq!((mode(&mut server, 7), mode(&mut server, 3)), (0x1, 0x1F));
        assert_eq!(
            server.status(Api::SetMode, &[0xF, 0]),
            STATUS_INVALID_HANDLE
        );
        // The stored mode is the one the renderer follows.
        assert_eq!(server.status(Api::SetMode, &[7, 0]), 0);
        server.poke(0, b"a\nb");
        server.call(Api::WriteConsole, &[7, BASE, 3, 0, 0]);
        assert_eq!(&server.console.screen.row_text(0)[..3], b"a\nb");
    }

    impl Server {
        /// Feed keyboard bytes to the console; what became of each record they completed.
        fn keys(&mut self, bytes: &[u8]) -> Vec<Append> {
            let mut outcomes = Vec::new();
            for &byte in bytes {
                self.console
                    .key_byte(byte, &mut (), &mut |outcome, _| outcomes.push(outcome));
            }
            outcomes
        }

        /// The INPUT_RECORDs at BASE + `at`, `count` of them.
        fn records(&self, at: usize, count: usize) -> Vec<[u8; INPUT_RECORD_BYTES]> {
            self.client.memory[at..at + count * INPUT_RECORD_BYTES]
                .chunks_exact(INPUT_RECORD_BYTES)
                .map(|chunk| chunk.try_into().unwrap())
                .collect()
        }
    }

    /// The keyboard's records reach the input buffer, a held key's repeats folded into one.
    #[test]
    fn key_bytes_fill_the_input_buffer() {
        let mut server = Server::new();
        assert_eq!(
            server.keys(&[0x1E, 0x1E, 0x9E, 0xE0, 0x2A]),
            [Append::Stored, Append::Coalesced, Append::Stored]
        );
        let mut reported = Vec::new();
        server
            .console
            .key_byte(0x1E, &mut (), &mut |outcome, record| {
                reported.push((outcome, record.repeat_count))
            });
        server
            .console
            .key_byte(0x1E, &mut (), &mut |outcome, record| {
                reported.push((outcome, record.repeat_count))
            });
        assert_eq!(
            reported,
            [(Append::Stored, 1), (Append::Coalesced, 2)],
            "the record as the buffer holds it"
        );
        assert_eq!(server.console.input.count(), 3);
    }

    /// The count, a peek that leaves the records, a read that takes them, and a flush — on the
    /// input buffer's handles only.
    #[test]
    fn the_input_apis_serve_the_input_buffer() {
        let mut server = Server::new();
        assert_eq!(
            server.call(Api::GetInputCount, &[3, 0xCC]),
            (0, [3, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            server.call(Api::ReadInput, &[3, BASE, 4, 0xCC]),
            (STATUS_PENDING, [3, BASE, 4, 0, 0, 0, 0, 0]),
            "an empty buffer: none, and the read waits"
        );
        assert_eq!(
            server.call(Api::PeekInput, &[3, BASE, 4, 0xCC]),
            (0, [3, BASE, 4, 0, 0, 0, 0, 0]),
            "a peek never waits"
        );
        // a, b, c: down and up each.
        server.keys(&[0x1E, 0x9E, 0x30, 0xB0, 0x2E, 0xAE]);
        assert_eq!(server.call(Api::GetInputCount, &[3, 0]).1[1], 6);
        let (status, data) = server.call(Api::PeekInput, &[3, BASE, 2, 0]);
        assert_eq!((status, data[3]), (0, 2));
        let first = server.console.input.get(0).unwrap().bytes();
        assert_eq!(server.records(0, 2)[0], first);
        assert_eq!(
            &first[..16],
            &[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0x41, 0, 0x1E, 0, b'a', 0]
        );
        assert_eq!(
            server.call(Api::GetInputCount, &[3, 0]).1[1],
            6,
            "a peek takes none"
        );
        let (status, data) = server.call(Api::ReadInput, &[3, BASE + 0x100, 3, 0]);
        assert_eq!((status, data[3]), (0, 3));
        assert_eq!(server.records(0x100, 1)[0], first);
        assert_eq!(server.call(Api::GetInputCount, &[3, 0]).1[1], 3);
        assert_eq!(
            server.console.input.get(0).unwrap().key.virtual_key_code,
            u16::from(b'B'),
            "b's keyup is next"
        );
        assert_eq!(
            server.call(Api::ReadInput, &[3, BASE, 10, 0]).1[3],
            3,
            "what is there"
        );
        assert_eq!(server.call(Api::GetInputCount, &[3, 0]).1[1], 0);
        server.keys(&[0x1E, 0x9E]);
        assert_eq!(server.status(Api::FlushInputBuffer, &[3]), 0);
        assert_eq!(server.call(Api::GetInputCount, &[3, 0]).1[1], 0, "flushed");
        for api in [
            Api::GetInputCount,
            Api::PeekInput,
            Api::ReadInput,
            Api::FlushInputBuffer,
        ] {
            for handle in [7, 0xB, 0xF] {
                assert_eq!(
                    server.status(api, &[handle, BASE, 1, 0]),
                    STATUS_INVALID_HANDLE,
                    "{api:?} {handle:#x}"
                );
            }
        }
    }

    /// A buffer the client cannot name or write fails the call and leaves every record waiting.
    #[test]
    fn a_refused_buffer_takes_nothing() {
        let mut server = Server::new();
        server.keys(&[0x1E, 0x9E]);
        assert_eq!(
            server.status(Api::ReadInput, &[3, 0x8000_0000, 2, 0]),
            0xC000_0005
        );
        assert_eq!(
            server.status(Api::ReadInput, &[3, 0x1000, 2, 0]),
            0xC000_00E8
        );
        assert_eq!(
            server.status(
                Api::ReadInput,
                &[3, BASE + MEMORY - INPUT_RECORD_BYTES, 2, 0]
            ),
            0xC000_0005,
            "the second record falls outside"
        );
        assert_eq!(server.console.input.count(), 2);
        assert_eq!(server.call(Api::ReadInput, &[3, 0x8000_0000, 0, 0]).1[3], 0);
    }

    /// A handle's duplicate shares its buffer's mode.
    #[test]
    fn a_duplicate_shares_the_mode() {
        let mut server = Server::new();
        let (_, data) = server.call(Api::DupHandle, &[7, 0, 0, DUPLICATE_SAME_ACCESS as usize]);
        assert_eq!(server.status(Api::SetMode, &[data[4], 0x2]), 0);
        assert_eq!(server.call(Api::GetMode, &[7, 0]).1[1], 0x2);
    }

    /// Set 1 scan codes of the letters, as the console fixture queues them.
    const SCAN_LETTERS: [u16; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
        0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
    ];

    impl Server {
        /// Queue `text` as typed through WRITE_INPUT (W, or A with `unicode` false): a keydown and
        /// a keyup per character, as the console fixture's queue makes them; the count
        /// written.
        fn queue(&mut self, text: &str, unicode: bool) -> usize {
            let mut bytes = Vec::new();
            for character in text.bytes() {
                let (vk, scan) = match character {
                    b'a'..=b'z' => (
                        u16::from(character - 32),
                        SCAN_LETTERS[usize::from(character - b'a')],
                    ),
                    b' ' => (0x20, 0x39),
                    _ => (0x0D, 0x1C),
                };
                for down in [1u32, 0] {
                    let record = InputRecord::key(KeyEventRecord {
                        key_down: down,
                        repeat_count: 1,
                        virtual_key_code: vk,
                        virtual_scan_code: scan,
                        char: u16::from(character),
                        control_key_state: 0,
                    });
                    bytes.extend(record.bytes());
                }
            }
            self.poke(0x400, &bytes);
            let count = bytes.len() / INPUT_RECORD_BYTES;
            let (status, data) = self.call(
                Api::WriteInput,
                &[3, BASE + 0x400, count, 0xCC, usize::from(unicode)],
            );
            assert_eq!(status, 0);
            data[3]
        }

        /// READ_CONSOLE of `count` characters into BASE + 0xC00: the status, and the text read.
        fn read(&mut self, count: usize, unicode: bool) -> (u32, Vec<u16>) {
            let (status, data) = self.call(
                Api::ReadConsole,
                &[3, BASE + 0xC00, count, 0xCC, usize::from(unicode)],
            );
            if status != 0 {
                return (status, Vec::new());
            }
            let read = data[3];
            let memory = &self.client.memory[0xC00..];
            let text = if unicode {
                (0..read)
                    .map(|at| u16::from_le_bytes([memory[2 * at], memory[2 * at + 1]]))
                    .collect()
            } else {
                memory[..read].iter().map(|&byte| u16::from(byte)).collect()
            };
            (status, text)
        }

        fn events(&mut self) -> usize {
            self.call(Api::GetInputCount, &[3, 0]).1[1]
        }
    }

    /// A key's keydown and keyup records carrying `char`.
    fn press(vk: u16, scan: u16, char: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        for down in [1u32, 0] {
            let record = InputRecord::key(KeyEventRecord {
                key_down: down,
                repeat_count: 1,
                virtual_key_code: vk,
                virtual_scan_code: scan,
                char,
                control_key_state: 0,
            });
            bytes.extend(record.bytes());
        }
        bytes
    }

    /// Line-mode reads over queued input, echo off, as Windows 2000's console capture shows them:
    /// a line and its CR LF, the Enter's keyup left; a buffer shorter than the line, the rest on
    /// the next read before any new input.
    #[test]
    fn a_line_mode_read_takes_a_line() {
        for unicode in [true, false] {
            let mut server = Server::new();
            assert_eq!(server.status(Api::SetMode, &[3, 0x3]), 0);
            assert_eq!(server.queue("dir abc\r", unicode), 16);
            assert_eq!(server.events(), 16);
            assert_eq!(server.read(64, unicode), (0, wide("dir abc\r\n")));
            assert_eq!(server.events(), 1, "the Enter's keyup");
            assert_eq!(server.status(Api::FlushInputBuffer, &[3]), 0);
            assert_eq!(server.queue("abcdefgh\r", unicode), 18);
            assert_eq!(server.read(4, unicode), (0, wide("abcd")));
            assert_eq!(server.queue("zz\r", unicode), 6);
            assert_eq!(server.read(64, unicode), (0, wide("efgh\r\n")));
            assert_eq!(server.events(), 7);
            assert_eq!(server.read(64, unicode), (0, wide("zz\r\n")));
            assert_eq!(server.console.screen.cursor(), (0, 0), "nothing echoed");
        }
    }

    /// A line without its Enter waits, what was typed kept; a backspace takes back a character;
    /// with echo on, the keys show on the screen as they are taken.
    #[test]
    fn a_line_waits_for_its_enter_and_echoes() {
        let mut server = Server::new();
        assert_eq!(server.queue("ab", true), 4);
        assert_eq!(server.read(64, true).0, STATUS_PENDING);
        assert_eq!(server.events(), 0);
        assert_eq!(server.console.line().pending(), &wide("ab")[..]);
        assert!(!server.console.line().is_complete());
        assert_eq!(
            &server.console.screen.row_text(0)[..3],
            b"ab ",
            "echoed (a fresh console echoes)"
        );
        server.poke(0x400, &press(0x08, 0x0E, 0x08));
        assert_eq!(
            server.call(Api::WriteInput, &[3, BASE + 0x400, 2, 0, 1]).1[3],
            2
        );
        server.queue("c\r", true);
        assert_eq!(server.read(64, true), (0, wide("ac\r\n")));
        assert_eq!(&server.console.screen.row_text(0)[..3], b"ac ");
        assert_eq!(
            server.console.screen.cursor(),
            (1, 0),
            "the Enter echoed as CR LF"
        );
    }

    /// A raw read, as Windows 2000's console capture shows it: the first character, a NUL, then
    /// the following ones, counted without the last; a one-character read leaves the rest.
    #[test]
    fn a_raw_read_takes_what_was_typed() {
        for unicode in [true, false] {
            let mut server = Server::new();
            assert_eq!(server.status(Api::SetMode, &[3, 0x1]), 0);
            assert_eq!(server.read(64, unicode).0, STATUS_PENDING, "nothing typed");
            assert_eq!(server.queue("xyz\r", unicode), 8);
            assert_eq!(
                server.read(64, unicode),
                (0, std::vec![0x78, 0, 0x79, 0x7A])
            );
            assert_eq!(server.events(), 0);
            server.queue("pq", unicode);
            assert_eq!(server.read(1, unicode), (0, wide("p")));
            assert_eq!(server.events(), 3);
            assert_eq!(
                server.read(2, unicode),
                (0, wide("q")),
                "q, its NUL: one counted"
            );
            assert_eq!(server.events(), 0, "q's keyup taken, the room unused");
        }
    }

    /// WRITE_INPUT keeps the records as written (an A call's character converted from the
    /// console's code page), as many as fit; an A peek converts back.
    #[test]
    fn written_input_records_are_kept_as_written() {
        let mut server = Server::new();
        let record = InputRecord::key(KeyEventRecord {
            key_down: 1,
            repeat_count: 1,
            virtual_key_code: 0x45,
            virtual_scan_code: 0x12,
            char: 0x82,
            control_key_state: 0x10,
        });
        server.poke(0, &record.bytes());
        server.poke(INPUT_RECORD_BYTES, &record.bytes());
        assert_eq!(server.call(Api::WriteInput, &[3, BASE, 2, 0, 0]).1[3], 2);
        assert_eq!(
            server.console.input.get(0).unwrap().key.char,
            0xE9,
            "e acute"
        );
        assert_eq!(
            server.console.input.get(1),
            server.console.input.get(0),
            "no folding"
        );
        assert_eq!(
            server.call(Api::PeekInput, &[3, BASE + 0x100, 1, 0, 0]).1[3],
            1
        );
        assert_eq!(&server.client.memory[0x100 + 14..0x100 + 16], &[0x82, 0]);
        assert_eq!(
            server.call(Api::PeekInput, &[3, BASE + 0x100, 1, 0, 1]).1[3],
            1
        );
        assert_eq!(&server.client.memory[0x100 + 14..0x100 + 16], &[0xE9, 0]);
        // A full buffer takes what fits.
        for _ in 0..200 {
            server.call(Api::WriteInput, &[3, BASE, 1, 0, 1]);
        }
        assert_eq!(server.events(), input::INPUT_BUFFER_RECORDS);
        assert_eq!(
            server.call(Api::WriteInput, &[3, BASE, 1, 0xCC, 1]),
            (0, [3, BASE, 1, 0, 1, 0, 0, 0])
        );
        assert_eq!(
            server.status(Api::WriteInput, &[7, BASE, 1, 0, 1]),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(server.status(Api::FlushInputBuffer, &[3]), 0);
        assert_eq!(
            server.status(Api::WriteInput, &[3, 0x8000_0000, 1, 0, 1]),
            0xC000_0005
        );
    }

    /// CONIN$ and CONOUT$ open new handles on the input and screen buffers; the input-wait handle
    /// is the client's.
    #[test]
    fn the_console_opens_by_name_and_hands_its_wait_handle() {
        let mut server = Server::new();
        let (status, data) = server.call(Api::OpenConsole, &[0, 0xC000_0000, 0, 3, 0]);
        assert_eq!((status, data[4]), (0, 0xF));
        assert_eq!(server.handles.kind(0xF), Some(Kind::Input));
        assert_eq!(
            server.call(Api::OpenConsole, &[1, 0xC000_0000, 0, 3, 0]).1[4],
            0x13
        );
        assert_eq!(server.handles.kind(0x13), Some(Kind::Output));
        // Only the standard handles, and their duplicates, write to the serial line too.
        assert!(!server.handles.logged(0x13));
        assert!(server.handles.logged(7) && server.handles.logged(0xB));
        let duplicate = server
            .handles
            .duplicate(7, 0, false, DUPLICATE_SAME_ACCESS)
            .unwrap();
        assert!(server.handles.logged(duplicate));
        let duplicate = server
            .handles
            .duplicate(0x13, 0, false, DUPLICATE_SAME_ACCESS)
            .unwrap();
        assert!(!server.handles.logged(duplicate));
        assert_eq!(
            server.call(Api::GetInputWaitHandle, &[0]),
            (0, [WAIT_HANDLE as usize, 0, 0, 0, 0, 0, 0, 0])
        );
        assert!(!server.console.input_waiting());
        server.queue("a", true);
        assert!(server.console.input_waiting());
    }
}
