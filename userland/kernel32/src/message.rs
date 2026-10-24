//! System messages: FormatMessageA and FormatMessageW, as Windows 2000's kernel32 serves them.
//!
//! The system messages are kernel32.dll's own message table, its RT_MESSAGETABLE resource (name 1,
//! US English), which its build makes from messages.txt (Windows 2000's English wording, each text
//! ending in the CR LF the message compiler ends a line with). FormatMessage finds a message there
//! through ntdll's RtlFindMessage — ERROR_MR_MID_NOT_FOUND for a code the table lacks, as a missing
//! message is on the platform — and has ntdll's RtlFormatMessage lay it out to the width the flags'
//! low byte asks, into the caller's buffer or a block it allocates
//! (FORMAT_MESSAGE_ALLOCATE_BUFFER). A message from a string or another module is not served, and
//! inserts are not expanded (RtlFormatMessage is asked to ignore them,
//! FORMAT_MESSAGE_IGNORE_INSERTS or not): no system message in the table has one.

use crate::base::{set_last_error, set_last_nt_error, Text};
use crate::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};
use crate::nt;

/// FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_STRING, FORMAT_MESSAGE_FROM_HMODULE,
/// FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_ARGUMENT_ARRAY, and FORMAT_MESSAGE_MAX_WIDTH_MASK,
/// the width's byte.
const ALLOCATE_BUFFER: u32 = 0x0100;
const FROM_STRING: u32 = 0x0400;
const FROM_HMODULE: u32 = 0x0800;
const FROM_SYSTEM: u32 = 0x1000;
const ARGUMENT_ARRAY: u32 = 0x2000;
const MAX_WIDTH_MASK: u32 = 0x00FF;

/// The room a laid-out message takes, in characters, its terminator's included: the longest system
/// message with a break after every character (the narrowest width) fits many times over.
const ROOM: usize = 1024;

/// kernel32's own handle, its base: the module whose message table holds the system messages.
#[cfg(all(target_arch = "x86", not(test)))]
fn own_handle() -> usize {
    unsafe extern "C" {
        /// The image's base, which the linker defines.
        static __ImageBase: u8;
    }
    core::ptr::addr_of!(__ImageBase) as usize
}

/// kernel32's own handle: the host tests' RtlFindMessage reads kernel32's table whatever it is
/// handed.
#[cfg(not(all(target_arch = "x86", not(test))))]
fn own_handle() -> usize {
    0x7C4E_0000
}

/// The block FORMAT_MESSAGE_ALLOCATE_BUFFER hands out: a fixed local block of `bytes` on the
/// process heap (LocalFree frees it), as Windows 2000's LocalAlloc(LMEM_FIXED) makes one: ntdll's
/// RtlAllocateHeap; null when the heap has no room.
fn allocate_block(bytes: usize) -> *mut u8 {
    // SAFETY: ntdll's export, on the process heap.
    unsafe { nt::RtlAllocateHeap(crate::base::process_heap(), 0, bytes) }
}

/// The system message for `code` in `language`, laid out to the width (the flags' low byte:
/// FORMAT_MESSAGE_MAX_WIDTH_MASK is RtlFormatMessage's MAXULONG) into `room`: its characters, the
/// terminator left out; the status of the call that failed.
fn laid_out(
    flags: u32,
    code: u32,
    language: u32,
    arguments: *const u8,
    wide: bool,
    room: &mut [u16; ROOM],
) -> Result<&[u16], u32> {
    let mut entry = core::ptr::null();
    // SAFETY: ntdll's export, over kernel32's own image.
    let status = unsafe {
        nt::RtlFindMessage(
            own_handle(),
            rtl::resource::RT_MESSAGETABLE,
            language,
            code,
            &mut entry,
        )
    };
    if !rtl::status::nt_success(status) {
        return Err(status);
    }
    let width = match flags & MAX_WIDTH_MASK {
        MAX_WIDTH_MASK => rtl::message::NO_LINE_BREAKS,
        width => width,
    };
    let mut returned = 0u32;
    // SAFETY: ntdll's export; the entry's text (UTF-16 in kernel32's table, NUL-terminated) follows
    // its length and flags; the room is ours.
    let status = unsafe {
        nt::RtlFormatMessage(
            entry.add(4) as *const u16,
            width,
            1,
            u32::from(!wide),
            u32::from(flags & ARGUMENT_ARRAY != 0),
            arguments,
            room.as_mut_ptr(),
            (2 * ROOM) as u32,
            &mut returned,
        )
    };
    if !rtl::status::nt_success(status) {
        return Err(status);
    }
    Ok(&room[..(returned as usize / 2).saturating_sub(1)])
}

/// FormatMessageW's work: the system message for the code (see [`laid_out`]), its length without
/// the terminator, as characters (`wide`) or bytes. Into the caller's buffer of `size` characters,
/// or, for FORMAT_MESSAGE_ALLOCATE_BUFFER, into a block of the message's size on the process heap
/// (a fixed local block: LocalFree frees it; `size` is not its least, as the runtime capture shows)
/// whose address goes where `buffer` points — null there when the call fails.
/// ERROR_MR_MID_NOT_FOUND for a code without a message (RtlFindMessage's STATUS_MESSAGE_NOT_FOUND),
/// ERROR_INSUFFICIENT_BUFFER for a buffer too small, ERROR_NOT_ENOUGH_MEMORY for a block the heap
/// cannot hold, ERROR_INVALID_PARAMETER for a source kernel32 does not serve.
///
/// # Safety
///
/// The buffer holds `size` characters; for FORMAT_MESSAGE_ALLOCATE_BUFFER it is a pointer's place.
unsafe fn format_message(
    flags: u32,
    code: u32,
    language: u32,
    buffer: *mut u8,
    size: u32,
    arguments: *const u8,
    wide: bool,
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
    let mut room = [0u16; ROOM];
    let units = match laid_out(flags, code, language, arguments, wide, &mut room) {
        Ok(units) => units,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    // Code page 1252 is one byte a character: the A form's bytes count the characters.
    let length = units.len();
    let unit = if wide { 2 } else { 1 };
    let out = if allocate {
        let block = allocate_block(unit * (length + 1));
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
    let out = if wide {
        Text::Wide(out as *mut u16)
    } else {
        Text::Ansi(out)
    };
    // SAFETY: the buffer or the block holds the message and its terminator.
    unsafe { out.put_terminated(units) };
    length as u32
}

/// FormatMessageA (see [`format_message`]): the size and the length in bytes.
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
    language: u32,
    buffer: *mut u8,
    size: u32,
    arguments: *const u8,
) -> u32 {
    // SAFETY: the caller's buffer.
    unsafe { format_message(flags, code, language, buffer, size, arguments, false) }
}

/// FormatMessageW (see [`format_message`]): the size and the length in characters.
///
/// # Safety
///
/// The buffer holds `size` characters; for FORMAT_MESSAGE_ALLOCATE_BUFFER it is a pointer's place.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_FormatMessageW")]
pub unsafe extern "system" fn format_message_w(
    flags: u32,
    _source: *const u8,
    code: u32,
    language: u32,
    buffer: *mut u16,
    size: u32,
    arguments: *const u8,
) -> u32 {
    // SAFETY: the caller's buffer.
    unsafe {
        format_message(
            flags,
            code,
            language,
            buffer as *mut u8,
            size,
            arguments,
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message as FormatMessageW lays it out with no width, as a string.
    fn message(code: u32) -> Option<std::string::String> {
        let mut room = [0u16; ROOM];
        laid_out(FROM_SYSTEM, code, 0, core::ptr::null(), true, &mut room)
            .ok()
            .map(|units| std::string::String::from_utf16(units).unwrap())
    }

    /// The capture's lengths: the text and its CR LF.
    #[test]
    fn the_captured_messages() {
        assert_eq!(message(2).map(|t| t.len()), Some(44));
        assert_eq!(message(5).as_deref(), Some("Access is denied.\r\n"));
        assert_eq!(message(0x0123_4567), None);
    }

    /// Every message of the table fits the room at the narrowest width, where every character
    /// breaks.
    #[test]
    fn every_message_fits_the_room() {
        let mut room = [0u16; ROOM];
        for code in 0..1000 {
            if message(code).is_some() {
                assert!(
                    laid_out(FROM_SYSTEM | 1, code, 0, core::ptr::null(), true, &mut room).is_ok()
                );
            }
        }
    }

    /// A language other than the table's (and the defaults that stand for it) has no message:
    /// ERROR_RESOURCE_LANG_NOT_FOUND, as on the platform.
    #[test]
    fn another_language_has_no_message() {
        let mut room = [0u16; ROOM];
        assert_eq!(
            laid_out(FROM_SYSTEM, 2, 0x040C, core::ptr::null(), true, &mut room),
            Err(rtl::resource::STATUS_RESOURCE_LANG_NOT_FOUND)
        );
        assert!(laid_out(FROM_SYSTEM, 2, 0x0400, core::ptr::null(), true, &mut room).is_ok());
        assert_eq!(
            rtl::status::dos_error(rtl::resource::STATUS_RESOURCE_LANG_NOT_FOUND),
            1815
        );
        assert_eq!(
            rtl::status::dos_error(rtl::resource::STATUS_MESSAGE_NOT_FOUND),
            crate::error::ERROR_MR_MID_NOT_FOUND
        );
    }
}
