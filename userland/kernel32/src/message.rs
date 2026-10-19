//! System messages: FormatMessageA, kernel32's own code as on Windows 2000, and its text for a
//! Win32 error code.
//!
//! kernel32 carries the system message table's entries for the common error codes, in Windows
//! 2000's English wording, each ending in the CR LF the table stores (a regular line break). A code
//! the table lacks is ERROR_MR_MID_NOT_FOUND, as a missing message is on the platform.
//! FormatMessageA serves system messages, into the caller's buffer or a block it allocates
//! (FORMAT_MESSAGE_ALLOCATE_BUFFER), its lines as the width asks (the low byte of the flags); a
//! message from a string or a module, and insert expansion, are not served.

use crate::base::set_last_error;
use crate::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MR_MID_NOT_FOUND, ERROR_NOT_ENOUGH_MEMORY};
use crate::nt;

/// The messages, by code.
const MESSAGES: &[(u32, &str)] = &[
    (0, "The operation completed successfully."),
    (1, "Incorrect function."),
    (2, "The system cannot find the file specified."),
    (3, "The system cannot find the path specified."),
    (4, "The system cannot open the file."),
    (5, "Access is denied."),
    (6, "The handle is invalid."),
    (8, "Not enough storage is available to process this command."),
    (87, "The parameter is incorrect."),
    (122, "The data area passed to a system call is too small."),
    (126, "The specified module could not be found."),
    (127, "The specified procedure could not be found."),
    (183, "Cannot create a file when that file already exists."),
    (203, "The system could not find the environment option that was entered."),
    (998, "Invalid access to memory location."),
];

/// The message for `code`, without its CR LF.
pub fn message(code: u32) -> Option<&'static str> {
    MESSAGES.iter().find(|&&(c, _)| c == code).map(|&(_, text)| text)
}

/// FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_FROM_HMODULE,
/// FORMAT_MESSAGE_FROM_SYSTEM (inserts are never expanded: FORMAT_MESSAGE_IGNORE_INSERTS or not),
/// and FORMAT_MESSAGE_MAX_WIDTH_MASK, the width's byte.
const ALLOCATE_BUFFER: u32 = 0x0100;
const FROM_STRING: u32 = 0x0400;
const FROM_HMODULE: u32 = 0x0800;
const FROM_SYSTEM: u32 = 0x1000;
const MAX_WIDTH_MASK: u32 = 0x00FF;

/// The room a formatted system message takes: the longest message, its line breaks multiplied
/// (a break in every blank at the narrowest width), and the trailing break.
const FORMATTED_ROOM: usize = 256;

/// A message formatted for the output: its bytes, terminator excluded.
struct Formatted {
    bytes: [u8; FORMATTED_ROOM],
    length: usize,
}

impl Formatted {
    fn push(&mut self, byte: u8) {
        self.bytes[self.length] = byte;
        self.length += 1;
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// `text` as the width (the flags' low byte) lays its lines out. Zero keeps the message's regular
/// line break (CR LF). Any other width ignores it — a blank in its place — and generates none
/// for FORMAT_MESSAGE_MAX_WIDTH_MASK; a width of 1 to 254 breaks a line that would run past it at
/// its last blank, the blank replaced by CR LF, and lets a single word longer than the width run
/// past it rather than split it.
fn format(text: &str, width: u32) -> Formatted {
    let mut out = Formatted { bytes: [0; FORMATTED_ROOM], length: 0 };
    if width == 0 {
        text.bytes().chain(*b"\r\n").for_each(|byte| out.push(byte));
        return out;
    }
    let (mut line, mut blank) = (0, None);
    for byte in text.bytes().chain([b' ']) {
        if width != MAX_WIDTH_MASK && byte != b' ' && out.length - line >= width as usize {
            if let Some(at) = blank.take() {
                // The blank becomes the break: the line's tail moves up one byte past it.
                out.bytes.copy_within(at + 1..out.length, at + 2);
                out.bytes[at..at + 2].copy_from_slice(b"\r\n");
                out.length += 1;
                line = at + 2;
            }
        }
        if byte == b' ' {
            blank = Some(out.length);
        }
        out.push(byte);
    }
    out
}

/// The block FORMAT_MESSAGE_ALLOCATE_BUFFER hands out: a fixed local block of `bytes` on the process
/// heap (LocalFree frees it), as Windows 2000's LocalAlloc(LMEM_FIXED) makes one: ntdll's
/// RtlAllocateHeap; null when the heap has no room.
fn allocate_block(bytes: usize) -> *mut u8 {
    // SAFETY: ntdll's export, on the process heap.
    unsafe { nt::RtlAllocateHeap(crate::base::process_heap(), 0, bytes) }
}

/// FormatMessageA: the system message for the code, laid out to the width (see [`format`]), its
/// length without the terminator. Into the caller's buffer of `size` bytes, or, for
/// FORMAT_MESSAGE_ALLOCATE_BUFFER, into a block of at least `size` bytes on the process heap (a
/// fixed local block: LocalFree frees it) whose address goes where `buffer` points — null there
/// when the call fails. ERROR_MR_MID_NOT_FOUND for a code without a message,
/// ERROR_INSUFFICIENT_BUFFER for a buffer too small, ERROR_NOT_ENOUGH_MEMORY for a block the heap
/// cannot hold, ERROR_INVALID_PARAMETER for a source kernel32 does not serve.
///
/// # Safety
///
/// The buffer holds `size` bytes; for FORMAT_MESSAGE_ALLOCATE_BUFFER it is a pointer's place.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_FormatMessageA")]
pub unsafe extern "system" fn format_message_a(
    flags: u32,
    _source: *const u8,
    code: u32,
    _language: u32,
    buffer: *mut u8,
    size: u32,
    _arguments: *const u8,
) -> u32 {
    let allocate = flags & ALLOCATE_BUFFER != 0;
    if allocate {
        // SAFETY: the caller's pointer place.
        unsafe { (buffer as *mut *mut u8).write_unaligned(core::ptr::null_mut()) };
    }
    if flags & FROM_SYSTEM == 0 || flags & (FROM_STRING | FROM_HMODULE) != 0 {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(text) = message(code) else {
        set_last_error(ERROR_MR_MID_NOT_FOUND);
        return 0;
    };
    let formatted = format(text, flags & MAX_WIDTH_MASK);
    let length = formatted.length;
    let out = if allocate {
        let block = allocate_block((size as usize).max(length + 1));
        if block.is_null() {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        // SAFETY: the caller's pointer place.
        unsafe { (buffer as *mut *mut u8).write_unaligned(block) };
        block
    } else {
        if (size as usize) <= length {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        buffer
    };
    for (at, &byte) in formatted.as_bytes().iter().chain(&[0]).enumerate() {
        // SAFETY: inside the buffer or the block (the message and its terminator fit).
        unsafe { out.add(at).write(byte) };
    }
    length as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture's lengths: the text and its CR LF.
    #[test]
    fn the_captured_messages() {
        assert_eq!(message(2).map(|t| t.len() + 2), Some(44));
        assert_eq!(message(5).map(|t| t.len() + 2), Some(19));
        assert_eq!(message(0x0123_4567), None);
    }

    /// Every message fits the formatting room at the narrowest width, where every blank breaks.
    #[test]
    fn every_message_fits_the_room() {
        for &(code, text) in MESSAGES {
            let blanks = text.bytes().filter(|&byte| byte == b' ').count();
            assert!(text.len() + blanks + 2 < FORMATTED_ROOM, "{code}");
            assert_eq!(format(text, 1).length, text.len() + blanks + 1, "{code}: a break per blank, a trailing blank");
        }
    }
}
