//! The console server, as kernel32 reaches it through ntdll's CsrClientCallServer: the message
//! format both sides share, and the server's rules over a process's console handles.
//!
//! Windows 2000's kernel32 sends its console work to the client-server runtime (csrss, whose console
//! server owns the console and its handle tables) over an LPC port. F2K has no csrss: ntdll's
//! CsrClientCallServer raises one internal system service, and the kernel's stand-in serves the
//! message with these rules, the console's screen being the serial line. Console handles stay
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
//! never captured: the capture buffer is carried, not used.

use crate::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS,
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

    /// ConsolepWriteConsole: [handle, buffer, count, out written] — the bytes to the screen.
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

    /// Each API's data length in dwords.
    pub const fn words(api: u32) -> Option<usize> {
        Some(match api {
            WRITE_CONSOLE | READ_CONSOLE => 4,
            GET_MODE | GET_CP | VERIFY_IO_HANDLE => 2,
            FLUSH_INPUT_BUFFER | CLOSE_HANDLE => 1,
            DUP_HANDLE => 5,
            _ => return None,
        })
    }
}

/// The console's code pages (input and output): the OEM one, 437, as a US Windows 2000 console's.
pub const CONSOLE_CP: u32 = 437;

/// The modes a fresh console has: processed, line-buffered, echoed input with mouse events
/// (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_MOUSE_INPUT); processed
/// output that wraps at the line's end (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT).
pub const INPUT_MODE: u32 = 0x1 | 0x2 | 0x4 | 0x10;
pub const OUTPUT_MODE: u32 = 0x1 | 0x2;

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
    /// A fresh process's: stdin on the input buffer, stdout and stderr on the screen buffer.
    pub const fn standard() -> Self {
        Handles {
            open: 0b111,
            output: 0b110,
        }
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
        let free = (!self.open).trailing_zeros();
        if free == 32 {
            return Err(STATUS_NO_MEMORY);
        }
        self.open |= 1 << free;
        if kind == Kind::Output {
            self.output |= 1 << free;
        }
        if options & DUPLICATE_CLOSE_SOURCE != 0 {
            self.close(handle)?;
        }
        Ok((free << 2) | 3)
    }
}

/// The console's screen: where the server's writes go.
pub trait Screen {
    /// Show `count` bytes of the client's memory at `buffer`; the status that refuses them (an
    /// address the client cannot name, a buffer that cannot be read: what was read before it shown).
    fn write(&mut self, buffer: usize, count: usize) -> Result<(), u32>;
}

/// Serve one API call over a process's handles: its data (the dwords after the header, as pointer-
/// sized words: the host tests' buffers are the host's addresses) read and answered in place; the
/// status, the message's ReturnValue.
pub fn serve(handles: &mut Handles, screen: &mut impl Screen, api: u32, data: &mut [usize]) -> u32 {
    let Some(words) = api::words(api) else {
        return STATUS_ILLEGAL_FUNCTION;
    };
    if data.len() < words {
        return STATUS_INVALID_PARAMETER;
    }
    match answer(handles, screen, api, data) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// The API's work: `data` holds at least its words.
fn answer(
    handles: &mut Handles,
    screen: &mut impl Screen,
    api: u32,
    data: &mut [usize],
) -> Result<(), u32> {
    let handle = data[0] as u32;
    let kind = handles.kind(handle);
    match api {
        api::WRITE_CONSOLE => {
            if kind != Some(Kind::Output) {
                return Err(STATUS_INVALID_HANDLE);
            }
            if data[2] != 0 {
                screen.write(data[1], data[2])?;
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
                Kind::Input => INPUT_MODE,
                Kind::Output => OUTPUT_MODE,
            } as usize;
        }
        api::GET_CP => data[1] = CONSOLE_CP as usize,
        api::VERIFY_IO_HANDLE => data[1] = usize::from(kind.is_some()),
        api::FLUSH_INPUT_BUFFER => {
            // Nothing is ever buffered: the input buffer is empty.
            if kind != Some(Kind::Input) {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        api::CLOSE_HANDLE => handles.close(handle)?,
        api::DUP_HANDLE => {
            data[4] = handles.duplicate(handle, data[1] as u32, data[3] as u32)? as usize
        }
        _ => return Err(STATUS_ILLEGAL_FUNCTION),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// A screen that keeps what it shows; an address at or above 0x8000_0000 is refused as the
    /// kernel's probe refuses it, 0x1000 as an unmapped page.
    #[derive(Default)]
    struct Kept(Vec<(usize, usize)>);

    impl Screen for Kept {
        fn write(&mut self, buffer: usize, count: usize) -> Result<(), u32> {
            match buffer {
                0x8000_0000.. => Err(crate::status::STATUS_ACCESS_VIOLATION),
                0x1000 => Err(0xC000_00E8),
                _ => {
                    self.0.push((buffer, count));
                    Ok(())
                }
            }
        }
    }

    fn call(
        handles: &mut Handles,
        screen: &mut Kept,
        api: u32,
        data: &[usize],
    ) -> (u32, [usize; DATA_WORDS]) {
        let mut words = [0; DATA_WORDS];
        words[..data.len()].copy_from_slice(data);
        (serve(handles, screen, api, &mut words), words)
    }

    #[test]
    fn a_fresh_process_has_the_standard_handles() {
        let handles = Handles::standard();
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
        let (mut handles, mut screen) = (Handles::standard(), Kept::default());
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::WRITE_CONSOLE,
                &[7, 0x40_0000, 15, 0xCC]
            ),
            (0, [7, 0x40_0000, 15, 15, 0, 0, 0, 0])
        );
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::WRITE_CONSOLE,
                &[0xB, 0x40_0000, 0, 0xCC]
            )
            .1[3],
            0
        );
        for handle in [3, 0xF, 4, 0] {
            assert_eq!(
                call(
                    &mut handles,
                    &mut screen,
                    api::WRITE_CONSOLE,
                    &[handle, 0x40_0000, 1, 0]
                )
                .0,
                STATUS_INVALID_HANDLE
            );
        }
        assert_eq!(screen.0, [(0x40_0000, 15)], "an empty write shows nothing");
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::WRITE_CONSOLE,
                &[7, 0x8000_0000, 4, 0]
            )
            .0,
            0xC000_0005
        );
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::WRITE_CONSOLE,
                &[7, 0x1000, 4, 0]
            )
            .0,
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
        let (mut handles, mut screen) = (Handles::standard(), Kept::default());
        assert_eq!(
            call(&mut handles, &mut screen, api::GET_MODE, &[3]).1[1],
            0x17
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::GET_MODE, &[7]).1[1],
            0x3
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::GET_MODE, &[0xF]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(call(&mut handles, &mut screen, api::GET_CP, &[0]).1[1], 437);
        assert_eq!(call(&mut handles, &mut screen, api::GET_CP, &[1]).1[1], 437);
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::READ_CONSOLE,
                &[3, 0x40_0000, 8, 0xCC]
            ),
            (0, [3, 0x40_0000, 8, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::READ_CONSOLE,
                &[7, 0x40_0000, 8, 0]
            )
            .0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::FLUSH_INPUT_BUFFER, &[3]).0,
            0
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::FLUSH_INPUT_BUFFER, &[7]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::VERIFY_IO_HANDLE, &[0xB]),
            (0, [0xB, 1, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::VERIFY_IO_HANDLE, &[0xF]),
            (0, [0xF, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            call(&mut handles, &mut screen, 0x0002_0063, &[7]).0,
            STATUS_ILLEGAL_FUNCTION
        );
        assert_eq!(
            serve(&mut handles, &mut screen, api::GET_MODE, &mut [7]),
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn handles_duplicate_into_the_lowest_free_slot_and_close() {
        let (mut handles, mut screen) = (Handles::standard(), Kept::default());
        let (status, data) = call(
            &mut handles,
            &mut screen,
            api::DUP_HANDLE,
            &[7, 0, 0, DUPLICATE_SAME_ACCESS as usize],
        );
        assert_eq!((status, data[4]), (0, 0xF));
        assert_eq!(handles.kind(0xF), Some(Kind::Output));
        assert_eq!(
            call(&mut handles, &mut screen, api::CLOSE_HANDLE, &[7]).0,
            0
        );
        assert_eq!(
            call(&mut handles, &mut screen, api::CLOSE_HANDLE, &[7]).0,
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call(
                &mut handles,
                &mut screen,
                api::WRITE_CONSOLE,
                &[7, 0x40_0000, 1, 0]
            )
            .0,
            STATUS_INVALID_HANDLE
        );
        // The freed slot is the next one taken; the source goes when asked.
        assert_eq!(
            handles.duplicate(3, GENERIC_READ, DUPLICATE_CLOSE_SOURCE),
            Ok(7)
        );
        assert_eq!(
            (handles.kind(7), handles.kind(3)),
            (Some(Kind::Input), None)
        );
        assert_eq!(
            handles.duplicate(0xB, 0x1F_0000, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(handles.duplicate(3, 0, 0), Err(STATUS_INVALID_HANDLE));
        while handles.duplicate(0xB, 0, DUPLICATE_SAME_ACCESS).is_ok() {}
        assert_eq!(
            handles.duplicate(0xB, 0, DUPLICATE_SAME_ACCESS),
            Err(STATUS_NO_MEMORY)
        );
        assert_eq!(handles.kind((31 << 2) | 3), Some(Kind::Output));
    }
}
