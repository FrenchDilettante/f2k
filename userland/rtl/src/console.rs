//! The console server, as kernel32 reaches it through ntdll's CsrClientCallServer: the message
//! format both sides share, and the server's rules over a process's console handles.
//!
//! Windows 2000's kernel32 sends its console work to the client-server runtime (csrss, whose
//! console server owns the console and its handle tables) over an LPC port. F2K has no csrss:
//! ntdll's CsrClientCallServer raises one internal system service, and the kernel's stand-in serves
//! the message with these rules over the console's state ([`Console`]: its input buffer — the
//! records the keyboard's producer appends, [`input`] — and its mode, its screen buffer,
//! [`screen`], and its title). Console handles stay
//! outside the kernel's handle table, as on Windows 2000: they are the console server's own, per
//! process — (index << 2) | 3, the low two bits kernel32's CONSOLE_HANDLE test, the standard
//! handles a fresh process starts with indexes 0 to 2 (stdin 3, stdout 7, stderr 0xB).
//!
//! What mirrors Windows 2000: CsrClientCallServer's signature and answer (the message, an optional
//! capture buffer, the API number, the API data's length; the message's ReturnValue), and the
//! message header's layout ([`header`]: the LPC message header, then the capture buffer pointer,
//! the API number, the return value, a reserved word — the API's data after them). The API
//! numbers are made as Windows 2000's are: the console server's index, 2, in the high word, but the
//! indexes and the data's layout ([`api`]) are F2K's own: Windows 2000's are internal to its
//! kernel32 and csrss. The client's buffers are read where they are (the server is the kernel),
//! never captured: the capture buffer is carried, not used. The structures a console call fills
//! are the public ABI's ([`Coord`], [`SmallRect`], [`ConsoleScreenBufferInfo`]): the server
//! answers them as their bytes, in dwords.

pub mod input;
pub mod layout;
pub mod screen;

use input::{Append, InputBuffer, KeyEventRecord, Lights, Producer, INPUT_RECORD_BYTES};
use screen::{Cell, Fill, ScreenBuffer, HEIGHT, OUTPUT_MODE_MASK, WIDTH};

use crate::status::{
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
    STATUS_SUCCESS,
};

/// The message header's fields, by offset into the message: Windows 2000's layout.
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

/// STATUS_ILLEGAL_FUNCTION: the answer to an API number no server serves (csrss's).
pub const STATUS_ILLEGAL_FUNCTION: u32 = 0xC000_00AF;

/// The console server's index among csrss's servers (Windows 2000's CONSRV_SERVERDLL_INDEX).
pub const CONSOLE_SERVER: u32 = 2;

/// The console server's APIs: the server's index in the high word, the API's in the low one, F2K's
/// indexes. Each
/// names its data as dwords after the header, in order; `out` marks what the server writes.
pub mod api {
    use super::CONSOLE_SERVER;

    const fn number(index: u32) -> u32 {
        (CONSOLE_SERVER << 16) | index
    }

    /// ConsolepWriteConsole: [handle, buffer, count, out written, unicode] — the bytes to the
    /// screen, or, with `unicode` nonzero, `count` UTF-16 units (WriteConsoleW's), each shown as
    /// the console's code page holds it.
    pub const WRITE_CONSOLE: u32 = number(0);
    /// ConsolepReadConsole: [handle, buffer, count, out read].
    pub const READ_CONSOLE: u32 = number(1);
    /// ConsolepGetMode: [handle, out mode].
    pub const GET_MODE: u32 = number(2);
    /// ConsolepGetCP: [output (nonzero for the output code page), out code page].
    pub const GET_CP: u32 = number(3);
    /// ConsolepVerifyIoHandle: [handle, out valid] — whether it names a console object.
    pub const VERIFY_IO_HANDLE: u32 = number(4);
    /// ConsolepFlushInputBuffer: [handle].
    pub const FLUSH_INPUT_BUFFER: u32 = number(5);
    /// ConsolepCloseHandle: [handle].
    pub const CLOSE_HANDLE: u32 = number(6);
    /// ConsolepDupHandle: [handle, access, inherit, options, out handle].
    pub const DUP_HANDLE: u32 = number(7);
    /// ConsolepGetCursorPosition: [handle, out position (a COORD)].
    pub const GET_CURSOR_POSITION: u32 = number(8);
    /// ConsolepSetCursorPosition: [handle, position (a COORD)] — inside the buffer.
    pub const SET_CURSOR_POSITION: u32 = number(9);
    /// ConsolepGetScreenBufferInfo: [handle, out info ×6] — the CONSOLE_SCREEN_BUFFER_INFO's 22
    /// bytes in dword order ([`ConsoleScreenBufferInfo::words`](super::ConsoleScreenBufferInfo)).
    pub const GET_SCREEN_BUFFER_INFO: u32 = number(10);
    /// ConsolepSetTextAttribute: [handle, attributes] — what written cells take.
    pub const SET_TEXT_ATTRIBUTE: u32 = number(11);
    /// ConsolepFillOutput: [handle, element (0 the character, 1 the attribute), value, count,
    /// origin (a COORD), out written].
    pub const FILL_OUTPUT: u32 = number(12);
    /// ConsolepScrollRegion: [handle, source left | top << 16, source right | bottom << 16,
    /// destination (a COORD), fill (a CHAR_INFO: character | attributes << 16), clipped (nonzero:
    /// the clip rectangle follows), clip left | top << 16, clip right | bottom << 16].
    pub const SCROLL_REGION: u32 = number(13);
    /// ConsolepGetTitle: [buffer, size, out copied] — the title's bytes, no terminator added.
    pub const GET_TITLE: u32 = number(14);
    /// ConsolepSetTitle: [buffer, length] — the title's bytes.
    pub const SET_TITLE: u32 = number(15);
    /// ConsolepSetMode: [handle, mode] — the mode of the buffer the handle names.
    pub const SET_MODE: u32 = number(16);
    /// ConsolepGetNumberOfInputEvents: [handle, out count] — the records the input buffer holds.
    pub const GET_INPUT_COUNT: u32 = number(17);
    /// ConsolepPeekInput: [handle, buffer, count, out copied] — up to `count` records, oldest
    /// first, copied to the buffer as INPUT_RECORDs and left in the input buffer.
    pub const PEEK_INPUT: u32 = number(18);
    /// ConsolepReadInput: [handle, buffer, count, out copied] — as PEEK_INPUT, the records copied
    /// removed from the input buffer. It never waits: an empty input buffer copies none.
    pub const READ_INPUT: u32 = number(19);

    /// Each API's data length in dwords.
    pub const fn words(api: u32) -> Option<usize> {
        Some(match api {
            WRITE_CONSOLE => 5,
            READ_CONSOLE => 4,
            GET_MODE | GET_CP | VERIFY_IO_HANDLE => 2,
            FLUSH_INPUT_BUFFER | CLOSE_HANDLE => 1,
            DUP_HANDLE => 5,
            GET_CURSOR_POSITION | SET_CURSOR_POSITION | SET_TEXT_ATTRIBUTE => 2,
            GET_SCREEN_BUFFER_INFO => 7,
            FILL_OUTPUT => 6,
            SCROLL_REGION => 8,
            GET_TITLE => 3,
            SET_TITLE | SET_MODE => 2,
            GET_INPUT_COUNT => 2,
            PEEK_INPUT | READ_INPUT => 4,
            _ => return None,
        })
    }
}

/// The console's code pages (input and output): the OEM one, 437, as a US Windows 2000 console's.
pub const CONSOLE_CP: u32 = 437;

/// The keyboard layout the console's producer walks: the one switch for a compiled-in change.
pub const LAYOUT: &layout::Layout = &layout::US;

/// The modes a fresh console has: processed, line-buffered, echoed input with mouse events
/// (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_MOUSE_INPUT); processed
/// output that wraps at the line's end (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT).
pub const INPUT_MODE: u32 = 0x1 | 0x2 | 0x4 | 0x10;
pub const OUTPUT_MODE: u32 = 0x1 | 0x2;

/// The input mode's bits SetConsoleMode checks: line input, its echo, every bit an input buffer
/// holds (processed, line, echo, window and mouse input).
const ENABLE_LINE_INPUT: u32 = 0x2;
const ENABLE_ECHO_INPUT: u32 = 0x4;
const INPUT_MODE_MASK: u32 = 0x1F;

/// The attribute bits a cell holds: the foreground and background colours.
const COLOR_MASK: u32 = 0xFF;

/// The most title bytes the console keeps (a longer title keeps its first ones).
pub const TITLE_BYTES: usize = 1024;

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

/// The console: its input buffer, the producer that fills it, the input buffer's mode, its screen
/// buffer and its title. Each mode is its buffer's, shared by every handle on that buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Console {
    pub screen: ScreenBuffer,
    pub input: InputBuffer,
    /// The keyboard's key-event producer, over [`LAYOUT`].
    pub producer: Producer,
    input_mode: u32,
    title: [u8; TITLE_BYTES],
    title_length: usize,
}

impl Console {
    /// A fresh console: the default modes, a blank screen buffer, an empty input buffer and an
    /// empty title.
    // TODO: the startup modes and the default title a fresh console reports, captured from one.
    pub const fn new() -> Self {
        Console {
            screen: ScreenBuffer::new(),
            input: InputBuffer::new(),
            producer: Producer::new(LAYOUT),
            input_mode: INPUT_MODE,
            title: [0; TITLE_BYTES],
            title_length: 0,
        }
    }

    /// The input buffer's mode.
    pub fn input_mode(&self) -> u32 {
        self.input_mode
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

    /// The title's bytes.
    pub fn title(&self) -> &[u8] {
        &self.title[..self.title_length]
    }

    /// What GetConsoleScreenBufferInfo reports: the buffer and its window the same size, the
    /// largest window the buffer's size.
    // TODO: the buffer size, window and maximum window a fresh console reports, captured from
    // one.
    pub fn screen_buffer_info(&self) -> ConsoleScreenBufferInfo {
        let size = Coord {
            x: WIDTH as i16,
            y: HEIGHT as i16,
        };
        let (row, column) = self.screen.cursor();
        ConsoleScreenBufferInfo {
            size,
            cursor_position: Coord {
                x: column as i16,
                y: row as i16,
            },
            attributes: self.screen.attribute().into(),
            window: SmallRect {
                left: 0,
                top: 0,
                right: WIDTH as i16 - 1,
                bottom: HEIGHT as i16 - 1,
            },
            maximum_window_size: size,
        }
    }
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handles {
    /// The open slots.
    open: u32,
    /// Of those, the ones naming the screen buffer (the rest name the input buffer).
    output: u32,
}

impl Handles {
    /// No handle open.
    pub const fn empty() -> Self {
        Handles { open: 0, output: 0 }
    }

    /// A fresh process's: stdin on the input buffer, stdout and stderr on the screen buffer, opened
    /// in that order.
    pub const fn standard() -> Self {
        let mut handles = Self::empty();
        let kinds = [Kind::Input, Kind::Output, Kind::Output];
        let mut index = 0;
        while index < kinds.len() {
            match handles.open(kinds[index]) {
                Ok(handle) => assert!(handle == STANDARD_HANDLES[index]),
                Err(_) => panic!("an empty table has room"),
            }
            index += 1;
        }
        handles
    }

    /// Open a handle on `kind`'s buffer in the lowest free slot; STATUS_NO_MEMORY when every slot
    /// is taken.
    pub const fn open(&mut self, kind: Kind) -> Result<u32, u32> {
        let free = (!self.open).trailing_zeros();
        if free == 32 {
            return Err(STATUS_NO_MEMORY);
        }
        self.open |= 1 << free;
        if matches!(kind, Kind::Output) {
            self.output |= 1 << free;
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

    /// Close an open handle: STATUS_INVALID_HANDLE for any other value.
    pub fn close(&mut self, handle: u32) -> Result<(), u32> {
        self.kind(handle).ok_or(STATUS_INVALID_HANDLE)?;
        let bit = 1 << (handle >> 2);
        self.open &= !bit;
        self.output &= !bit;
        Ok(())
    }

    /// A new handle on what `handle` names, in the lowest free slot (the source closed for
    /// DUPLICATE_CLOSE_SOURCE). A console handle carries read and write access at most: anything
    /// else asked for (without DUPLICATE_SAME_ACCESS) is STATUS_INVALID_PARAMETER; a full table
    /// STATUS_NO_MEMORY.
    pub fn duplicate(&mut self, handle: u32, access: u32, options: u32) -> Result<u32, u32> {
        let kind = self.kind(handle).ok_or(STATUS_INVALID_HANDLE)?;
        if options & DUPLICATE_SAME_ACCESS == 0 && access & !(GENERIC_READ | GENERIC_WRITE) != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let duplicate = self.open(kind)?;
        if options & DUPLICATE_CLOSE_SOURCE != 0 {
            self.close(handle)?;
        }
        Ok(duplicate)
    }
}

/// The calling client, as the server reaches it: the bytes it shows, and its memory.
pub trait Client {
    /// Show `count` bytes of the client's memory at `buffer` on `screen`, each piece read handed to
    /// [`ScreenBuffer::render`] in order; the status that refuses them (an address the client
    /// cannot name, a buffer that cannot be read: what was read before it shown).
    fn show(&mut self, screen: &mut ScreenBuffer, buffer: usize, count: usize) -> Result<(), u32>;
    /// Show `bytes` the server made (a Unicode write's, in the console's code page) on `screen`, as
    /// [`Client::show`] shows the client's own.
    fn print(&mut self, screen: &mut ScreenBuffer, bytes: &[u8]) {
        screen.render(bytes);
    }
    /// Read the client's memory at `buffer` into `into`; the status that refuses it.
    fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32>;
    /// Write `bytes` to the client's memory at `buffer`; the status that refuses it.
    fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32>;
}

/// Serve one API call over the console and a process's handles: its data (the dwords after the
/// header, as pointer-sized words: the host tests' buffers are the host's addresses) read and
/// answered in place; the status, the message's ReturnValue.
pub fn serve(
    console: &mut Console,
    handles: &mut Handles,
    client: &mut impl Client,
    api: u32,
    data: &mut [usize],
) -> u32 {
    let Some(words) = api::words(api) else {
        return STATUS_ILLEGAL_FUNCTION;
    };
    if data.len() < words {
        return STATUS_INVALID_PARAMETER;
    }
    match answer(console, handles, client, api, data) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// A Unicode write: `count` UTF-16 units of the client's memory at `buffer`, read a piece at a
/// time, each unit shown as the console's code page holds it (best fit, else `?`); the status that
/// refuses the client's memory, what was read before it shown.
fn show_unicode(
    console: &mut Console,
    client: &mut impl Client,
    buffer: usize,
    count: usize,
) -> Result<(), u32> {
    const PIECE: usize = 128;
    let mut done = 0;
    while done < count {
        let take = (count - done).min(PIECE);
        let mut units = [0u8; 2 * PIECE];
        client.read(buffer.wrapping_add(2 * done), &mut units[..2 * take])?;
        let mut bytes = [0u8; PIECE];
        for (at, byte) in bytes[..take].iter_mut().enumerate() {
            let unit = u16::from_le_bytes([units[2 * at], units[2 * at + 1]]);
            *byte = crate::codepage::encode_unit(crate::codepage::CodePage::Oem, unit, true)
                .unwrap_or(b'?');
        }
        client.print(&mut console.screen, &bytes[..take]);
        done += take;
    }
    Ok(())
}

/// The API's work: `data` holds at least its words.
fn answer(
    console: &mut Console,
    handles: &mut Handles,
    client: &mut impl Client,
    api: u32,
    data: &mut [usize],
) -> Result<(), u32> {
    let handle = data[0] as u32;
    let kind = handles.kind(handle);
    let output = || match kind {
        Some(Kind::Output) => Ok(()),
        _ => Err(STATUS_INVALID_HANDLE),
    };
    let input = || match kind {
        Some(Kind::Input) => Ok(()),
        _ => Err(STATUS_INVALID_HANDLE),
    };
    match api {
        api::WRITE_CONSOLE => {
            output()?;
            if data[2] != 0 {
                console.screen.begin_write();
                if data[4] != 0 {
                    show_unicode(console, client, data[1], data[2])?;
                } else {
                    client.show(&mut console.screen, data[1], data[2])?;
                }
            }
            data[3] = data[2];
        }
        api::READ_CONSOLE => {
            if kind != Some(Kind::Input) {
                return Err(STATUS_INVALID_HANDLE);
            }
            // F2K's console has no keyboard: its input ends at once, as an end-of-file key at a
            // line's start ends a Windows 2000 console's read with nothing.
            data[3] = 0;
        }
        api::GET_MODE => {
            data[1] = match kind.ok_or(STATUS_INVALID_HANDLE)? {
                Kind::Input => console.input_mode,
                Kind::Output => console.screen.mode(),
            } as usize;
        }
        api::SET_MODE => {
            let mode = data[1] as u32;
            match kind.ok_or(STATUS_INVALID_HANDLE)? {
                Kind::Input => {
                    if mode & !INPUT_MODE_MASK != 0
                        || mode & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) == ENABLE_ECHO_INPUT
                    {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    console.input_mode = mode;
                }
                Kind::Output => {
                    if mode & !OUTPUT_MODE_MASK != 0 {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    console.screen.set_mode(mode);
                }
            }
        }
        api::GET_CP => data[1] = CONSOLE_CP as usize,
        api::VERIFY_IO_HANDLE => data[1] = usize::from(kind.is_some()),
        api::FLUSH_INPUT_BUFFER => {
            input()?;
            console.input.flush();
        }
        api::GET_INPUT_COUNT => {
            input()?;
            data[1] = console.input.count();
        }
        api::PEEK_INPUT | api::READ_INPUT => {
            input()?;
            // Every record is copied before any is removed: a buffer that refuses one leaves the
            // input buffer as it was.
            let copied = data[2].min(console.input.count());
            for index in 0..copied {
                let Some(record) = console.input.get(index) else {
                    break;
                };
                let at = data[1].wrapping_add(index * INPUT_RECORD_BYTES);
                client.write(at, &record.bytes())?;
            }
            if api == api::READ_INPUT {
                console.input.remove(copied);
            }
            data[3] = copied;
        }
        api::CLOSE_HANDLE => handles.close(handle)?,
        api::DUP_HANDLE => {
            data[4] = handles.duplicate(handle, data[1] as u32, data[3] as u32)? as usize
        }
        api::GET_CURSOR_POSITION => {
            output()?;
            data[1] = console.screen_buffer_info().cursor_position.word() as usize;
        }
        api::SET_CURSOR_POSITION => {
            output()?;
            let at = Coord::from_word(data[1] as u32);
            if at.x < 0 || at.y < 0 || !console.screen.set_cursor(at.y as usize, at.x as usize) {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
        api::GET_SCREEN_BUFFER_INFO => {
            output()?;
            let info = console.screen_buffer_info().words();
            for (slot, value) in data[1..7].iter_mut().zip(info) {
                *slot = value as usize;
            }
        }
        api::SET_TEXT_ATTRIBUTE => {
            output()?;
            let attribute = data[1] as u32;
            if attribute & !COLOR_MASK != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            console.screen.set_attribute(attribute as u8);
        }
        api::FILL_OUTPUT => {
            output()?;
            // The cell keeps a character's OEM byte and an attribute's colours: the low byte.
            let value = data[2] as u8;
            let fill = match data[1] {
                0 => Fill::Character(value),
                1 => Fill::Attribute(value),
                _ => return Err(STATUS_INVALID_PARAMETER),
            };
            let at = Coord::from_word(data[4] as u32);
            data[5] = console.screen.fill(at.x.into(), at.y.into(), data[3], fill);
        }
        api::SCROLL_REGION => {
            output()?;
            let source = SmallRect::from_words(data[1] as u32, data[2] as u32);
            let to = Coord::from_word(data[3] as u32);
            let fill = match data[4] as u32 {
                0 => Cell::blank(console.screen.attribute()),
                char_info => Cell {
                    character: char_info as u8,
                    attribute: (char_info >> 16) as u8,
                },
            };
            let clip = (data[5] as u32 != 0)
                .then(|| SmallRect::from_words(data[6] as u32, data[7] as u32));
            console
                .screen
                .scroll(source, clip, to.x.into(), to.y.into(), fill);
        }
        api::GET_TITLE => {
            let title = console.title();
            let copied = title.len().min(data[1]);
            if copied != 0 {
                client.write(data[0], &title[..copied])?;
            }
            data[2] = copied;
        }
        api::SET_TITLE => {
            // The title is replaced only once the new one is read whole.
            let length = data[1].min(TITLE_BYTES);
            let mut title = [0u8; TITLE_BYTES];
            if length != 0 {
                client.read(data[0], &mut title[..length])?;
            }
            console.title = title;
            console.title_length = length;
        }
        _ => return Err(STATUS_ILLEGAL_FUNCTION),
    }
    Ok(())
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
    }

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

        fn call(&mut self, api: u32, data: &[usize]) -> (u32, [usize; DATA_WORDS]) {
            let mut words = [0; DATA_WORDS];
            words[..data.len()].copy_from_slice(data);
            let status = serve(
                &mut self.console,
                &mut self.handles,
                &mut self.client,
                api,
                &mut words[..api::words(api).unwrap_or(data.len())],
            );
            (status, words)
        }

        /// The status alone.
        fn status(&mut self, api: u32, data: &[usize]) -> u32 {
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
            [Kind::Input, Kind::Output, Kind::Output].map(|kind| opened.open(kind)),
            [Ok(3), Ok(7), Ok(0xB)],
            "allocated in the lowest free slots"
        );
        assert_eq!(opened, handles);
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
            server.call(api::WRITE_CONSOLE, &[7, 0x40_0000, 15, 0xCC, 0]),
            (0, [7, 0x40_0000, 15, 15, 0, 0, 0, 0])
        );
        assert_eq!(
            server
                .call(api::WRITE_CONSOLE, &[0xB, 0x40_0000, 0, 0xCC, 0])
                .1[3],
            0
        );
        for handle in [3, 0xF, 4, 0] {
            assert_eq!(
                server
                    .call(api::WRITE_CONSOLE, &[handle, 0x40_0000, 1, 0, 0])
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
            server
                .call(api::WRITE_CONSOLE, &[7, 0x8000_0000, 4, 0, 0])
                .0,
            0xC000_0005
        );
        assert_eq!(
            server.call(api::WRITE_CONSOLE, &[7, 0x1000, 4, 0, 0]).0,
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
        assert_eq!(server.call(api::GET_MODE, &[3]).1[1], 0x17);
        assert_eq!(server.call(api::GET_MODE, &[7]).1[1], 0x3);
        assert_eq!(server.call(api::GET_MODE, &[0xF]).0, STATUS_INVALID_HANDLE);
        assert_eq!(server.call(api::GET_CP, &[0]).1[1], 437);
        assert_eq!(server.call(api::GET_CP, &[1]).1[1], 437);
        assert_eq!(
            server.call(api::READ_CONSOLE, &[3, 0x40_0000, 8, 0xCC]),
            (0, [3, 0x40_0000, 8, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            server.call(api::READ_CONSOLE, &[7, 0x40_0000, 8, 0]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(server.call(api::FLUSH_INPUT_BUFFER, &[3]).0, 0);
        assert_eq!(
            server.call(api::FLUSH_INPUT_BUFFER, &[7]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            server.call(api::VERIFY_IO_HANDLE, &[0xB]),
            (0, [0xB, 1, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            server.call(api::VERIFY_IO_HANDLE, &[0xF]),
            (0, [0xF, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(server.call(0x0002_0063, &[7]).0, STATUS_ILLEGAL_FUNCTION);
        assert_eq!(
            serve(
                &mut server.console,
                &mut server.handles,
                &mut server.client,
                api::GET_MODE,
                &mut [7]
            ),
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn handles_duplicate_into_the_lowest_free_slot_and_close() {
        let mut server = Server::new();
        let (status, data) =
            server.call(api::DUP_HANDLE, &[7, 0, 0, DUPLICATE_SAME_ACCESS as usize]);
        assert_eq!((status, data[4]), (0, 0xF));
        assert_eq!(server.handles.kind(0xF), Some(Kind::Output));
        assert_eq!(server.call(api::CLOSE_HANDLE, &[7]).0, 0);
        assert_eq!(
            server.call(api::CLOSE_HANDLE, &[7]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            server.call(api::WRITE_CONSOLE, &[7, 0x40_0000, 1, 0, 0]).0,
            STATUS_INVALID_HANDLE
        );
        // The freed slot is the next one taken; the source goes when asked.
        assert_eq!(
            server
                .handles
                .duplicate(3, GENERIC_READ, DUPLICATE_CLOSE_SOURCE),
            Ok(7)
        );
        assert_eq!(
            (server.handles.kind(7), server.handles.kind(3)),
            (Some(Kind::Input), None)
        );
        assert_eq!(
            server.handles.duplicate(0xB, 0x1F_0000, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            server.handles.duplicate(3, 0, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        while server
            .handles
            .duplicate(0xB, 0, DUPLICATE_SAME_ACCESS)
            .is_ok()
        {}
        assert_eq!(
            server.handles.duplicate(0xB, 0, DUPLICATE_SAME_ACCESS),
            Err(STATUS_NO_MEMORY)
        );
        assert_eq!(server.handles.kind((31 << 2) | 3), Some(Kind::Output));
    }

    #[test]
    fn handles_open_in_the_lowest_free_slot() {
        let mut handles = Handles::empty();
        assert_eq!(handles.kind(3), None);
        assert_eq!(handles.open(Kind::Output), Ok(3));
        assert_eq!(handles.open(Kind::Input), Ok(7));
        assert_eq!(handles.close(3), Ok(()));
        assert_eq!(handles.open(Kind::Input), Ok(3), "the freed slot first");
        assert_eq!(
            handles.kind(3),
            Some(Kind::Input),
            "the new kind, not the old"
        );
        while handles.open(Kind::Output).is_ok() {}
        assert_eq!(handles.open(Kind::Input), Err(STATUS_NO_MEMORY));
        assert_eq!(handles.kind((31 << 2) | 3), Some(Kind::Output));
    }

    /// Writes reach the screen buffer through the renderer, in the output mode the buffer holds.
    #[test]
    fn writes_render_into_the_screen_buffer() {
        let mut server = Server::new();
        server.poke(0, b"Hello\r\nworld");
        assert_eq!(
            server.call(api::WRITE_CONSOLE, &[7, BASE, 12, 0, 0]),
            (0, [7, BASE, 12, 12, 0, 0, 0, 0])
        );
        assert_eq!(&server.console.screen.row_text(0)[..6], b"Hello ");
        assert_eq!(&server.console.screen.row_text(1)[..6], b"world ");
        assert_eq!(server.console.screen.cursor(), (1, 5));
        // A refused buffer shows nothing.
        assert_eq!(
            server.status(api::WRITE_CONSOLE, &[0xB, 0x8000_0000, 4, 0, 0]),
            0xC000_0005
        );
        assert_eq!(server.console.screen.cursor(), (1, 5));
    }

    #[test]
    fn the_cursor_position_round_trips_inside_the_buffer() {
        let mut server = Server::new();
        let at = Coord { x: W - 1, y: H - 1 }.word() as usize;
        assert_eq!(server.status(api::SET_CURSOR_POSITION, &[7, at]), 0);
        assert_eq!(server.call(api::GET_CURSOR_POSITION, &[0xB, 0]).1[1], at);
        assert_eq!(server.console.screen.cursor(), (HEIGHT - 1, WIDTH - 1));
        for outside in [
            Coord { x: W, y: 0 },
            Coord { x: 0, y: H },
            Coord { x: -1, y: 0 },
        ] {
            assert_eq!(
                server.status(api::SET_CURSOR_POSITION, &[7, outside.word() as usize]),
                STATUS_INVALID_PARAMETER,
                "{outside:?}"
            );
        }
        assert_eq!(
            server.console.screen.cursor(),
            (HEIGHT - 1, WIDTH - 1),
            "a refused move moves nothing"
        );
        for api in [api::GET_CURSOR_POSITION, api::SET_CURSOR_POSITION] {
            assert_eq!(server.status(api, &[3, 0]), STATUS_INVALID_HANDLE);
            assert_eq!(server.status(api, &[0xF, 0]), STATUS_INVALID_HANDLE);
        }
    }

    #[test]
    fn the_screen_buffer_info_describes_the_buffer() {
        let mut server = Server::new();
        server.console.screen.set_cursor(3, 12);
        let (status, data) = server.call(api::GET_SCREEN_BUFFER_INFO, &[7]);
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
                    bottom: H - 1
                },
                maximum_window_size: Coord { x: W, y: H },
            }
        );
        assert_eq!(
            server.status(api::GET_SCREEN_BUFFER_INFO, &[3]),
            STATUS_INVALID_HANDLE
        );
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
        assert_eq!(server.status(api::SET_TEXT_ATTRIBUTE, &[7, 0x1E]), 0);
        assert_eq!(server.console.screen.attribute(), 0x1E);
        assert_eq!(
            server.call(api::GET_SCREEN_BUFFER_INFO, &[7]).1[3] & 0xFFFF,
            0x1E
        );
        for attribute in [0x100, 0x8000, 0x1_0000] {
            assert_eq!(
                server.status(api::SET_TEXT_ATTRIBUTE, &[7, attribute]),
                STATUS_INVALID_PARAMETER,
                "{attribute:#x}"
            );
        }
        assert_eq!(server.console.screen.attribute(), 0x1E);
        assert_eq!(
            server.status(api::SET_TEXT_ATTRIBUTE, &[3, 0x07]),
            STATUS_INVALID_HANDLE
        );
        server.poke(0, b"x");
        server.call(api::WRITE_CONSOLE, &[7, BASE, 1, 0, 0]);
        assert_eq!(server.console.screen.cell(0, 0).attribute, 0x1E);
    }

    #[test]
    fn fills_write_characters_or_attributes_and_count_them() {
        let mut server = Server::new();
        let at = |x: i16, y: i16| Coord { x, y }.word() as usize;
        assert_eq!(
            server.call(
                api::FILL_OUTPUT,
                &[7, 0, b'#' as usize, 5, at(W - 2, 0), 0xCC]
            ),
            (0, [7, 0, b'#' as usize, 5, at(W - 2, 0), 5, 0, 0])
        );
        let screen = &server.console.screen;
        assert_eq!(&screen.row_text(0)[WIDTH - 2..], b"##");
        assert_eq!(&screen.row_text(1)[..4], b"### ");
        assert_eq!(
            server
                .call(api::FILL_OUTPUT, &[7, 1, 0x4F, 3, at(W - 1, 0), 0])
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
                    api::FILL_OUTPUT,
                    &[7, 0, b'+' as usize, 9999, at(W - 3, H - 1), 0]
                )
                .1[5],
            3,
            "clipped at the buffer's end"
        );
        assert_eq!(
            server.call(api::FILL_OUTPUT, &[7, 0, b'!' as usize, 4, at(W, 0), 0xCC]),
            (0, [7, 0, b'!' as usize, 4, at(W, 0), 0, 0, 0]),
            "outside the buffer: nothing, and success"
        );
        assert_eq!(
            server
                .call(api::FILL_OUTPUT, &[7, 0, b'!' as usize, 4, at(-1, 3), 0])
                .1[5],
            0
        );
        assert_eq!(
            server.status(api::FILL_OUTPUT, &[7, 2, 0, 1, at(0, 0), 0]),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            server.status(api::FILL_OUTPUT, &[3, 0, 0, 1, at(0, 0), 0]),
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
        server.call(api::WRITE_CONSOLE, &[7, BASE, 11, 0, 0]);
        server.console.screen.set_attribute(0x2A);
        // Rows 1-2 up one; a zero fill is a space in the current attribute.
        let (from, to) = words(0, 1, W - 1, 2);
        assert_eq!(
            server.status(api::SCROLL_REGION, &[7, from, to, 0, 0, 0, 0, 0]),
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
                api::SCROLL_REGION,
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
            server.status(api::SCROLL_REGION, &[7, from, to, 0, fill, 0, 0, 0]),
            0
        );
        assert_eq!(server.console, before);
        assert_eq!(
            server.status(api::SCROLL_REGION, &[3, 0, 0, 0, 0, 0, 0, 0]),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn the_title_round_trips() {
        let mut server = Server::new();
        assert_eq!(
            server.call(api::GET_TITLE, &[BASE, 64, 0xCC]).1[2],
            0,
            "empty to start"
        );
        server.poke(0, b"First title");
        assert_eq!(server.status(api::SET_TITLE, &[BASE, 11]), 0);
        server.poke(0x100, b"Short");
        assert_eq!(server.status(api::SET_TITLE, &[BASE + 0x100, 5]), 0);
        assert_eq!(server.console.title(), b"Short", "a set replaces the title");
        let (status, data) = server.call(api::GET_TITLE, &[BASE + 0x200, 64, 0]);
        assert_eq!((status, data[2]), (0, 5));
        assert_eq!(&server.client.memory[0x200..0x206], b"Short\0");
        assert_eq!(
            server.call(api::GET_TITLE, &[BASE + 0x300, 3, 0]).1[2],
            3,
            "the caller's size"
        );
        assert_eq!(&server.client.memory[0x300..0x304], b"Sho\0");
        // A buffer that cannot be read leaves the title; one that cannot be written fails.
        assert_eq!(
            server.status(api::SET_TITLE, &[0x8000_0000, 4]),
            0xC000_0005
        );
        assert_eq!(server.console.title(), b"Short");
        assert_eq!(server.status(api::GET_TITLE, &[0x1000, 8, 0]), 0xC000_00E8);
        // A title past the console's room keeps its first bytes.
        server.poke(0, &[b'x'; MEMORY]);
        assert_eq!(server.status(api::SET_TITLE, &[BASE, TITLE_BYTES + 100]), 0);
        assert_eq!(server.console.title(), &[b'x'; TITLE_BYTES][..]);
        assert_eq!(server.status(api::SET_TITLE, &[BASE, 0]), 0);
        assert_eq!(server.console.title(), b"");
    }

    #[test]
    fn modes_are_per_buffer_and_checked() {
        let mut server = Server::new();
        let mode = |server: &mut Server, handle| server.call(api::GET_MODE, &[handle, 0]).1[1];
        assert_eq!(server.status(api::SET_MODE, &[7, 0x1]), 0);
        assert_eq!(
            mode(&mut server, 0xB),
            0x1,
            "every handle on the screen buffer"
        );
        assert_eq!(mode(&mut server, 3), 0x17, "the input buffer's own");
        assert_eq!(server.status(api::SET_MODE, &[3, 0x3]), 0);
        assert_eq!(mode(&mut server, 3), 0x3);
        assert_eq!(server.status(api::SET_MODE, &[3, 0x1F]), 0);
        for (handle, bad) in [(7, 0x4), (7, 0x8000_0003), (3, 0x20), (3, 0x4), (3, 0x5)] {
            assert_eq!(
                server.status(api::SET_MODE, &[handle, bad]),
                STATUS_INVALID_PARAMETER,
                "{handle:#x} {bad:#x}"
            );
        }
        assert_eq!((mode(&mut server, 7), mode(&mut server, 3)), (0x1, 0x1F));
        assert_eq!(
            server.status(api::SET_MODE, &[0xF, 0]),
            STATUS_INVALID_HANDLE
        );
        // The stored mode is the one the renderer follows.
        assert_eq!(server.status(api::SET_MODE, &[7, 0]), 0);
        server.poke(0, b"a\nb");
        server.call(api::WRITE_CONSOLE, &[7, BASE, 3, 0, 0]);
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
            server.call(api::GET_INPUT_COUNT, &[3, 0xCC]),
            (0, [3, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            server.call(api::READ_INPUT, &[3, BASE, 4, 0xCC]).1[3],
            0,
            "an empty buffer: none, and success"
        );
        // a, b, c: down and up each.
        server.keys(&[0x1E, 0x9E, 0x30, 0xB0, 0x2E, 0xAE]);
        assert_eq!(server.call(api::GET_INPUT_COUNT, &[3, 0]).1[1], 6);
        let (status, data) = server.call(api::PEEK_INPUT, &[3, BASE, 2, 0]);
        assert_eq!((status, data[3]), (0, 2));
        let first = server.console.input.get(0).unwrap().bytes();
        assert_eq!(server.records(0, 2)[0], first);
        assert_eq!(
            &first[..16],
            &[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0x41, 0, 0x1E, 0, b'a', 0]
        );
        assert_eq!(
            server.call(api::GET_INPUT_COUNT, &[3, 0]).1[1],
            6,
            "a peek takes none"
        );
        let (status, data) = server.call(api::READ_INPUT, &[3, BASE + 0x100, 3, 0]);
        assert_eq!((status, data[3]), (0, 3));
        assert_eq!(server.records(0x100, 1)[0], first);
        assert_eq!(server.call(api::GET_INPUT_COUNT, &[3, 0]).1[1], 3);
        assert_eq!(
            server.console.input.get(0).unwrap().key.virtual_key_code,
            u16::from(b'B'),
            "b's keyup is next"
        );
        assert_eq!(
            server.call(api::READ_INPUT, &[3, BASE, 10, 0]).1[3],
            3,
            "what is there"
        );
        assert_eq!(server.call(api::GET_INPUT_COUNT, &[3, 0]).1[1], 0);
        server.keys(&[0x1E, 0x9E]);
        assert_eq!(server.status(api::FLUSH_INPUT_BUFFER, &[3]), 0);
        assert_eq!(
            server.call(api::GET_INPUT_COUNT, &[3, 0]).1[1],
            0,
            "flushed"
        );
        for api in [
            api::GET_INPUT_COUNT,
            api::PEEK_INPUT,
            api::READ_INPUT,
            api::FLUSH_INPUT_BUFFER,
        ] {
            for handle in [7, 0xB, 0xF] {
                assert_eq!(
                    server.status(api, &[handle, BASE, 1, 0]),
                    STATUS_INVALID_HANDLE,
                    "{api:#x} {handle:#x}"
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
            server.status(api::READ_INPUT, &[3, 0x8000_0000, 2, 0]),
            0xC000_0005
        );
        assert_eq!(
            server.status(api::READ_INPUT, &[3, 0x1000, 2, 0]),
            0xC000_00E8
        );
        assert_eq!(
            server.status(
                api::READ_INPUT,
                &[3, BASE + MEMORY - INPUT_RECORD_BYTES, 2, 0]
            ),
            0xC000_0005,
            "the second record falls outside"
        );
        assert_eq!(server.console.input.count(), 2);
        assert_eq!(
            server.call(api::READ_INPUT, &[3, 0x8000_0000, 0, 0]).1[3],
            0
        );
    }

    /// A handle's duplicate shares its buffer's mode.
    #[test]
    fn a_duplicate_shares_the_mode() {
        let mut server = Server::new();
        let (_, data) = server.call(api::DUP_HANDLE, &[7, 0, 0, DUPLICATE_SAME_ACCESS as usize]);
        assert_eq!(server.status(api::SET_MODE, &[data[4], 0x2]), 0);
        assert_eq!(server.call(api::GET_MODE, &[7, 0]).1[1], 0x2);
    }
}
