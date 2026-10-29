//! The console server's APIs and their messages: each API's number ([`Api`]), and the data its
//! message carries after the header ([`CsrApiMsg::data`](super::CsrApiMsg)), one structure per API,
//! as Windows 2000's CSR_API_MSG carries its API's structure in a union.
//!
//! The numbers are made as Windows 2000's are, the console server's index in the high word, but
//! the indexes are F2K's own, and so is each message's layout: Windows 2000's are internal to its
//! kernel32 and csrss. A message is a run of words in the order its structure declares them, which
//! mostly follows the public console call's arguments; the doc comment of a field the server
//! writes says so. A `unicode` word is nonzero for a W call's UTF-16 text, zero for an A call's
//! text in the console's code page (the server converts, as Windows 2000's does).
//!
//! The words are generic ([`Word`]): `u32` as the server reads a 32-bit caller's message (the
//! form the layout asserts hold for), `usize` in the DLLs' own code, the same layout on their
//! target and the host's addresses in the host tests.

use core::fmt::Debug;

use super::CONSOLE_SERVER;
use crate::pod::Pod;

/// A message's word: an integer the width of the caller's pointers.
pub trait Word: Pod + Default + Eq + Debug {
    /// The word holding `value` (its low 32 bits, for a `u32` word).
    fn from_usize(value: usize) -> Self;
    /// The word's value.
    fn get(self) -> usize;

    /// The word holding a dword.
    fn from_dword(value: u32) -> Self {
        Self::from_usize(value as usize)
    }

    /// The word's low dword: a handle, a mode, a COORD, a code page.
    fn dword(self) -> u32 {
        self.get() as u32
    }

    /// Whether the word is nonzero: a flag's answer.
    fn is_set(self) -> bool {
        self.get() != 0
    }
}

impl Word for u32 {
    fn from_usize(value: usize) -> Self {
        value as u32
    }

    fn get(self) -> usize {
        self as usize
    }
}

impl Word for usize {
    fn from_usize(value: usize) -> Self {
        value
    }

    fn get(self) -> usize {
        self
    }
}

/// An API's message: the data after the header, its API's number to send it with.
pub trait Message: Pod {
    /// The message's word.
    type Word: Word;
    /// The API the message is for.
    const API: Api;
}

/// The console server's APIs, by number.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    /// ConsolepWriteConsole ([`WriteConsole`]).
    WriteConsole = number(0),
    /// ConsolepReadConsole ([`ReadConsole`]).
    ReadConsole = number(1),
    /// ConsolepGetMode ([`GetMode`]).
    GetMode = number(2),
    /// ConsolepGetCP ([`GetCp`]).
    GetCp = number(3),
    /// ConsolepVerifyIoHandle ([`VerifyIoHandle`]).
    VerifyIoHandle = number(4),
    /// ConsolepFlushInputBuffer ([`FlushInputBuffer`]).
    FlushInputBuffer = number(5),
    /// ConsolepCloseHandle ([`CloseHandle`]).
    CloseHandle = number(6),
    /// ConsolepDupHandle ([`DupHandle`]).
    DupHandle = number(7),
    /// ConsolepGetCursorPosition ([`GetCursorPosition`]).
    GetCursorPosition = number(8),
    /// ConsolepSetCursorPosition ([`SetCursorPosition`]).
    SetCursorPosition = number(9),
    /// ConsolepGetScreenBufferInfo ([`GetScreenBufferInfo`]).
    GetScreenBufferInfo = number(10),
    /// ConsolepSetTextAttribute ([`SetTextAttribute`]).
    SetTextAttribute = number(11),
    /// ConsolepFillOutput ([`FillOutput`]).
    FillOutput = number(12),
    /// ConsolepScrollRegion ([`ScrollRegion`]).
    ScrollRegion = number(13),
    /// ConsolepGetTitle ([`GetTitle`]).
    GetTitle = number(14),
    /// ConsolepSetTitle ([`SetTitle`]).
    SetTitle = number(15),
    /// ConsolepSetMode ([`SetMode`]).
    SetMode = number(16),
    /// ConsolepGetNumberOfInputEvents ([`GetInputCount`]).
    GetInputCount = number(17),
    /// ConsolepPeekInput ([`PeekInput`]).
    PeekInput = number(18),
    /// ConsolepReadInput ([`ReadInput`]).
    ReadInput = number(19),
    /// ConsolepWriteInput ([`WriteInput`]).
    WriteInput = number(20),
    /// ConsolepOpenConsole ([`OpenConsole`]).
    OpenConsole = number(21),
    /// ConsolepGetInputWaitHandle ([`GetInputWaitHandle`]).
    GetInputWaitHandle = number(22),
    /// ConsolepSetHandleInformation ([`SetHandleInformation`]).
    SetHandleInformation = number(23),
    /// ConsolepGetHandleInformation ([`GetHandleInformation`]).
    GetHandleInformation = number(24),
}

/// An API's number: the console server's index in the high word, the API's in the low one.
const fn number(index: u32) -> u32 {
    (CONSOLE_SERVER << 16) | index
}

/// Every API, at its index.
const APIS: [Api; 25] = [
    Api::WriteConsole,
    Api::ReadConsole,
    Api::GetMode,
    Api::GetCp,
    Api::VerifyIoHandle,
    Api::FlushInputBuffer,
    Api::CloseHandle,
    Api::DupHandle,
    Api::GetCursorPosition,
    Api::SetCursorPosition,
    Api::GetScreenBufferInfo,
    Api::SetTextAttribute,
    Api::FillOutput,
    Api::ScrollRegion,
    Api::GetTitle,
    Api::SetTitle,
    Api::SetMode,
    Api::GetInputCount,
    Api::PeekInput,
    Api::ReadInput,
    Api::WriteInput,
    Api::OpenConsole,
    Api::GetInputWaitHandle,
    Api::SetHandleInformation,
    Api::GetHandleInformation,
];

const _: () = {
    let mut index = 0;
    while index < APIS.len() {
        assert!(APIS[index] as u32 == number(index as u32));
        index += 1;
    }
};

impl TryFrom<u32> for Api {
    /// The number, which names no API of the console server's.
    type Error = u32;

    fn try_from(number: u32) -> Result<Self, u32> {
        if number >> 16 != CONSOLE_SERVER {
            return Err(number);
        }
        APIS.get((number & 0xFFFF) as usize).copied().ok_or(number)
    }
}

impl From<Api> for u32 {
    fn from(api: Api) -> u32 {
        api as u32
    }
}

/// Each message's [`Message`] and [`Pod`] impls, and its layout in its `u32` form: its size in
/// words (no more than a message carries), and its fields' words, in order.
macro_rules! messages {
    ($($name:ident: $words:literal [$($($field:tt).+),+];)*) => {$(
        impl<W: Word> Message for $name<W> {
            type Word = W;
            const API: Api = Api::$name;
        }

        // SAFETY: a `#[repr(C)]` structure whose fields are all words (or an array of them, or a
        // structure of words), so laid out back to back with no padding (a word's size is a
        // multiple of its alignment); and every word is plain data.
        unsafe impl<W: Word> Pod for $name<W> {}

        const _: () = {
            use core::mem::{offset_of, size_of};
            assert!(size_of::<$name<u32>>() == 4 * $words);
            assert!($words <= super::DATA_WORDS);
            let mut word = 0;
            $(
                assert!(offset_of!($name<u32>, $($field).+) == 4 * word);
                word += 1;
            )+
            assert!(word <= $words);
        };
    )*};
}

messages! {
    WriteConsole: 5 [handle, buffer, count, written, unicode];
    ReadConsole: 5 [handle, buffer, count, read, unicode];
    GetMode: 2 [handle, mode];
    GetCp: 2 [output, code_page];
    VerifyIoHandle: 2 [handle, valid];
    FlushInputBuffer: 1 [handle];
    CloseHandle: 1 [handle];
    DupHandle: 5 [handle, access, inherit, options, duplicate];
    GetCursorPosition: 2 [handle, position];
    SetCursorPosition: 2 [handle, position];
    GetScreenBufferInfo: 7 [handle, info];
    SetTextAttribute: 2 [handle, attributes];
    FillOutput: 6 [handle, element, value, count, origin, written];
    ScrollRegion: 8 [
        handle,
        source_top_left,
        source_bottom_right,
        destination,
        fill,
        clipped,
        clip_top_left,
        clip_bottom_right
    ];
    GetTitle: 4 [buffer, size, returned, unicode];
    SetTitle: 3 [buffer, length, unicode];
    SetMode: 2 [handle, mode];
    GetInputCount: 2 [handle, count];
    PeekInput: 5 [0.handle, 0.records, 0.length, 0.count, 0.unicode];
    ReadInput: 5 [0.handle, 0.records, 0.length, 0.count, 0.unicode];
    WriteInput: 5 [0.handle, 0.records, 0.length, 0.count, 0.unicode];
    OpenConsole: 5 [output, access, inherit, share, handle];
    GetInputWaitHandle: 1 [handle];
    SetHandleInformation: 3 [handle, mask, flags];
    GetHandleInformation: 2 [handle, flags];
}

/// WriteConsole: `count` bytes of the client's memory at `buffer` to the screen, or, `unicode`,
/// `count` UTF-16 units (WriteConsoleW's), each shown as the console's code page holds it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteConsole<W> {
    pub handle: W,
    pub buffer: W,
    pub count: W,
    /// Written by the server: the count written (the whole count).
    pub written: W,
    pub unicode: W,
}

/// ReadConsole: up to `count` characters of input into `buffer`, as the input mode reads them;
/// STATUS_PENDING while none can be answered yet.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadConsole<W> {
    pub handle: W,
    pub buffer: W,
    pub count: W,
    /// Written by the server: the characters read.
    pub read: W,
    pub unicode: W,
}

/// GetConsoleMode: the mode of the buffer the handle names.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetMode<W> {
    pub handle: W,
    /// Written by the server.
    pub mode: W,
}

/// GetConsoleCP and GetConsoleOutputCP: a code page of the console's (`output` nonzero for the
/// output one).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetCp<W> {
    pub output: W,
    /// Written by the server.
    pub code_page: W,
}

/// VerifyConsoleIoHandle: whether the handle names a console object.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyIoHandle<W> {
    pub handle: W,
    /// Written by the server: nonzero when it does.
    pub valid: W,
}

/// FlushConsoleInputBuffer: the input buffer the handle names emptied.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushInputBuffer<W> {
    pub handle: W,
}

/// CloseConsoleHandle: the handle closed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CloseHandle<W> {
    pub handle: W,
}

/// DuplicateConsoleHandle: a new handle on the object the handle names, with `access` (or the
/// same access, for DUPLICATE_SAME_ACCESS in `options`), inheritable when `inherit` is nonzero;
/// the source closed for DUPLICATE_CLOSE_SOURCE.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DupHandle<W> {
    pub handle: W,
    pub access: W,
    pub inherit: W,
    pub options: W,
    /// Written by the server: the new handle.
    pub duplicate: W,
}

/// The screen buffer's cursor position, a COORD.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetCursorPosition<W> {
    pub handle: W,
    /// Written by the server: a COORD (X the low word).
    pub position: W,
}

/// SetConsoleCursorPosition: the screen buffer's cursor moved, inside the buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetCursorPosition<W> {
    pub handle: W,
    /// A COORD (X the low word).
    pub position: W,
}

/// GetConsoleScreenBufferInfo: the screen buffer's CONSOLE_SCREEN_BUFFER_INFO.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetScreenBufferInfo<W> {
    pub handle: W,
    /// Written by the server: the structure's 22 bytes in dword order
    /// ([`ConsoleScreenBufferInfo::words`](super::ConsoleScreenBufferInfo::words)).
    pub info: [W; 6],
}

/// SetConsoleTextAttribute: the attributes written cells take.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetTextAttribute<W> {
    pub handle: W,
    pub attributes: W,
}

/// FillConsoleOutputCharacter and FillConsoleOutputAttribute: `count` cells from `origin`
/// written with `value`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FillOutput<W> {
    pub handle: W,
    /// What the fill writes: 0 the character, 1 the attribute.
    pub element: W,
    pub value: W,
    pub count: W,
    /// A COORD (X the low word).
    pub origin: W,
    /// Written by the server: the cells written.
    pub written: W,
}

/// ScrollConsoleScreenBuffer: the source rectangle's cells moved to `destination`, the cells
/// they leave filled.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrollRegion<W> {
    pub handle: W,
    /// The source rectangle: left | top << 16.
    pub source_top_left: W,
    /// right | bottom << 16.
    pub source_bottom_right: W,
    /// A COORD (X the low word).
    pub destination: W,
    /// A CHAR_INFO: the character | the attributes << 16 (zero: a blank in the current
    /// attributes).
    pub fill: W,
    /// Nonzero: the clip rectangle follows.
    pub clipped: W,
    /// The clip rectangle: left | top << 16.
    pub clip_top_left: W,
    /// right | bottom << 16.
    pub clip_bottom_right: W,
}

/// GetConsoleTitleA and GetConsoleTitleW: the title into a buffer of `size` characters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetTitle<W> {
    pub buffer: W,
    pub size: W,
    /// Written by the server: the characters copied (the call's answer).
    pub returned: W,
    pub unicode: W,
}

/// SetConsoleTitleA and SetConsoleTitleW: the title replaced by `length` characters of `buffer`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetTitle<W> {
    pub buffer: W,
    pub length: W,
    pub unicode: W,
}

/// SetConsoleMode: the mode of the buffer the handle names.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetMode<W> {
    pub handle: W,
    pub mode: W,
}

/// GetNumberOfConsoleInputEvents: the records the input buffer holds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetInputCount<W> {
    pub handle: W,
    /// Written by the server.
    pub count: W,
}

/// The data the input-record APIs share ([`PeekInput`], [`ReadInput`], [`WriteInput`]):
/// `length` INPUT_RECORDs at `records`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputRecords<W> {
    pub handle: W,
    pub records: W,
    pub length: W,
    /// Written by the server: the records copied or written.
    pub count: W,
    pub unicode: W,
}

/// PeekConsoleInput: up to `length` records, oldest first, copied to the buffer and left in the
/// input buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeekInput<W>(pub InputRecords<W>);

/// ReadConsoleInput: as [`PeekInput`], the records copied removed from the input buffer;
/// STATUS_PENDING while it is empty.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadInput<W>(pub InputRecords<W>);

/// WriteConsoleInput: `length` records appended to the input buffer as they are, as many as it
/// has room for.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteInput<W>(pub InputRecords<W>);

impl<W> AsRef<InputRecords<W>> for PeekInput<W> {
    fn as_ref(&self) -> &InputRecords<W> {
        &self.0
    }
}

impl<W> AsRef<InputRecords<W>> for ReadInput<W> {
    fn as_ref(&self) -> &InputRecords<W> {
        &self.0
    }
}

impl<W> AsRef<InputRecords<W>> for WriteInput<W> {
    fn as_ref(&self) -> &InputRecords<W> {
        &self.0
    }
}

/// OpenConsoleW, as CreateFile hands it CONIN$ and CONOUT$: a new handle in the lowest free slot
/// on the screen buffer (`output` nonzero, CONOUT$) or the input buffer (CONIN$).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenConsole<W> {
    pub output: W,
    pub access: W,
    pub inherit: W,
    pub share: W,
    /// Written by the server: the new handle.
    pub handle: W,
}

/// GetConsoleInputWaitHandle: the calling process's handle to the console's input-wait event,
/// signaled while the input buffer holds records.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetInputWaitHandle<W> {
    /// Written by the server.
    pub handle: W,
}

/// SetHandleInformation, for a console handle: the handle's inheritance set from `flags` when
/// `mask` holds HANDLE_FLAG_INHERIT.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetHandleInformation<W> {
    pub handle: W,
    pub mask: W,
    pub flags: W,
}

/// GetHandleInformation, for a console handle: HANDLE_FLAG_INHERIT when the handle is
/// inheritable, nothing else (a console handle is never protected from close).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetHandleInformation<W> {
    pub handle: W,
    /// Written by the server.
    pub flags: W,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_name_their_apis() {
        assert_eq!(Api::try_from(0x0002_0000), Ok(Api::WriteConsole));
        assert_eq!(Api::try_from(0x0002_0018), Ok(Api::GetHandleInformation));
        for number in [0x0002_0019, 0x0002_0063, 0x0001_0000, 0x0003_0001, 0] {
            assert_eq!(Api::try_from(number), Err(number), "{number:#x}");
        }
        assert_eq!(u32::from(Api::GetInputWaitHandle), 0x0002_0016);
    }

    #[test]
    fn a_message_is_its_words() {
        let message = WriteConsole::<usize> {
            handle: 7,
            buffer: 0x40_0000,
            count: 15,
            written: 0,
            unicode: 1,
        };
        assert_eq!(
            <[usize; 5]>::from_bytes(message.as_bytes()),
            Some([7, 0x40_0000, 15, 0, 1])
        );
        assert_eq!(core::mem::size_of::<PeekInput<u32>>(), 20);
        assert_eq!(<ReadInput<u32> as Message>::API, Api::ReadInput);
    }
}
