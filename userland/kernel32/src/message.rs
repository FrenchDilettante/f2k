//! Messages: FormatMessageA and FormatMessageW, as Windows 2000's kernel32 serves them.
//!
//! A message comes from a string (FORMAT_MESSAGE_FROM_STRING: the caller's, an A call's converted
//! through the ANSI code page) or from a module's message table (FORMAT_MESSAGE_FROM_HMODULE: the
//! module given, the program's own for NULL; FORMAT_MESSAGE_FROM_SYSTEM: kernel32's, the system
//! messages; with both, the module's first, then the system's), found through ntdll's
//! RtlFindMessage — ERROR_MR_MID_NOT_FOUND for an id the table lacks,
//! ERROR_RESOURCE_LANG_NOT_FOUND for a language it lacks. The system messages are kernel32.dll's
//! own RT_MESSAGETABLE resource (name 1, US English), which its build makes from messages.txt
//! (Windows 2000's English wording, each text ending in the CR LF the message compiler ends a line
//! with); a table entry is UTF-16 (the message compiler's `-U`, as kernel32's and cmd.exe's are) or
//! ANSI (converted through the code page).
//!
//! ntdll's RtlFormatMessage lays the text out: the escapes, the inserts from the arguments (a
//! va_list, or an array with FORMAT_MESSAGE_ARGUMENT_ARRAY; an A call's strings ANSI) unless
//! FORMAT_MESSAGE_IGNORE_INSERTS, and the width the flags' low byte asks
//! (FORMAT_MESSAGE_MAX_WIDTH_MASK is its MAXULONG), into a block of kernel32's on the process heap,
//! grown until the message fits (at most 64 KiB, the documentation's limit for the output). The
//! text then goes into the caller's buffer, or into a block it allocates
//! (FORMAT_MESSAGE_ALLOCATE_BUFFER), an A call's narrowed through the ANSI code page.

use crate::base::{process_heap, read_pointer, set_last_error, set_last_nt_error, Text};
use crate::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ENOUGH_MEMORY};
use crate::nt::{self, AnsiString, UnicodeString};

/// FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_IGNORE_INSERTS, FORMAT_MESSAGE_FROM_STRING,
/// FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_ARGUMENT_ARRAY, and
/// FORMAT_MESSAGE_MAX_WIDTH_MASK, the width's byte.
const ALLOCATE_BUFFER: u32 = 0x0100;
const IGNORE_INSERTS: u32 = 0x0200;
const FROM_STRING: u32 = 0x0400;
const FROM_HMODULE: u32 = 0x0800;
const FROM_SYSTEM: u32 = 0x1000;
const ARGUMENT_ARRAY: u32 = 0x2000;
const MAX_WIDTH_MASK: u32 = 0x00FF;

/// MESSAGE_RESOURCE_UNICODE: a table entry's text is UTF-16.
const MESSAGE_RESOURCE_UNICODE: u16 = 0x0001;

/// The statuses kernel32 tells apart: a block the layout outgrew, and a call it cannot serve.
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// The layout's first room, in characters, and its last: the documentation's 64 KiB.
const FIRST_ROOM: usize = 1024;
const LAST_ROOM: usize = 0x8000;

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

/// The program's own handle, its base (the PEB's ImageBaseAddress): FORMAT_MESSAGE_FROM_HMODULE's
/// module for NULL.
fn program_handle() -> usize {
    read_pointer(crate::base::peb() + 0x08)
}

/// A message's text, NUL-terminated UTF-16: the caller's or a table's in place, or one kernel32
/// converted from ANSI (on the process heap, freed with it).
struct Message {
    text: *const u16,
    converted: Option<UnicodeString>,
}

impl Message {
    /// Text read in place.
    fn borrowed(text: *const u16) -> Message {
        Message {
            text,
            converted: None,
        }
    }

    /// A NUL-terminated ANSI text converted (ntdll's RtlInitAnsiString and
    /// RtlAnsiStringToUnicodeString, onto the process heap); the status of a failed conversion.
    ///
    /// # Safety
    ///
    /// `text` is a NUL-terminated string.
    unsafe fn converted(text: *const u8) -> Result<Message, u32> {
        let mut ansi = AnsiString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        let mut wide = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
        // SAFETY: ntdll's exports, over the caller's string and the structures above.
        let status = unsafe {
            nt::RtlInitAnsiString(&mut ansi, text);
            nt::RtlAnsiStringToUnicodeString(&mut wide, &ansi, 1)
        };
        if !rtl::status::nt_success(status) {
            return Err(status);
        }
        Ok(Message {
            text: wide.buffer,
            converted: Some(wide),
        })
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        if let Some(converted) = self.converted.as_mut() {
            // SAFETY: ntdll's export, over the string its conversion allocated.
            unsafe { nt::RtlFreeUnicodeString(converted) };
        }
    }
}

/// Message `id` of `module`'s message table, in `language` (ntdll's RtlFindMessage): its text,
/// or the lookup's status.
fn table_message(module: usize, id: u32, language: u32) -> Result<Message, u32> {
    let mut entry = core::ptr::null();
    // SAFETY: ntdll's export, over the module's image.
    let status = unsafe {
        nt::RtlFindMessage(
            module,
            rtl::resource::RT_MESSAGETABLE,
            language,
            id,
            &mut entry,
        )
    };
    if !rtl::status::nt_success(status) {
        return Err(status);
    }
    // SAFETY: a MESSAGE_RESOURCE_ENTRY: its length and flags, then its NUL-terminated text.
    let flags = unsafe { (entry.add(2) as *const u16).read_unaligned() };
    if flags & MESSAGE_RESOURCE_UNICODE != 0 {
        // SAFETY: the entry's text, 4 bytes in (after its length and flags), inside the entry
        // RtlFindMessage found in the module's mapped image.
        Ok(Message::borrowed(unsafe { entry.add(4) } as *const u16))
    } else {
        // SAFETY: as above, an ANSI text.
        unsafe { Message::converted(entry.add(4)) }
    }
}

/// The message the flags name: the string `source` points at, or message `id` from the module's
/// table (`source`, the program's for NULL) and then the system's, as asked. A call naming no
/// source is STATUS_INVALID_PARAMETER; one that finds no message has the last lookup's status.
///
/// # Safety
///
/// For FORMAT_MESSAGE_FROM_STRING, `source` is a NUL-terminated string of the call's form.
unsafe fn message(
    flags: u32,
    source: *const u8,
    id: u32,
    language: u32,
    wide: bool,
) -> Result<Message, u32> {
    if flags & FROM_STRING != 0 {
        if wide {
            return Ok(Message::borrowed(source as *const u16));
        }
        // SAFETY: the caller's string.
        return unsafe { Message::converted(source) };
    }
    let mut status = STATUS_INVALID_PARAMETER;
    if flags & FROM_HMODULE != 0 {
        let module = if source.is_null() {
            program_handle()
        } else {
            source as usize
        };
        match table_message(module, id, language) {
            Ok(found) => return Ok(found),
            Err(failed) => status = failed,
        }
    }
    if flags & FROM_SYSTEM != 0 {
        return table_message(own_handle(), id, language);
    }
    Err(status)
}

/// A message laid out: its characters, in a block of kernel32's on the process heap (freed with
/// it).
struct Laid {
    block: *mut u16,
    length: usize,
}

impl Laid {
    fn units(&self) -> &[u16] {
        // SAFETY: the block holds the laid-out characters.
        unsafe { core::slice::from_raw_parts(self.block, self.length) }
    }
}

impl Drop for Laid {
    fn drop(&mut self) {
        // SAFETY: ntdll's export, over kernel32's own block.
        unsafe { nt::RtlFreeHeap(process_heap(), 0, self.block as *mut u8) };
    }
}

/// `text` laid out by ntdll's RtlFormatMessage as the flags ask (the width: the flags' low byte,
/// FORMAT_MESSAGE_MAX_WIDTH_MASK as MAXULONG; the inserts from `arguments` unless ignored), into a
/// block that grows until it fits: the characters, or the status of the call that failed.
///
/// # Safety
///
/// `text` is NUL-terminated; `arguments` holds every value the text's inserts name (a va_list's
/// address, or an array for FORMAT_MESSAGE_ARGUMENT_ARRAY).
unsafe fn laid_out(
    text: *const u16,
    flags: u32,
    arguments: *const u8,
    wide: bool,
) -> Result<Laid, u32> {
    let width = match flags & MAX_WIDTH_MASK {
        MAX_WIDTH_MASK => rtl::message::NO_LINE_BREAKS,
        width => width,
    };
    let mut room = FIRST_ROOM;
    loop {
        // SAFETY: ntdll's export, on the process heap.
        let block = unsafe { nt::RtlAllocateHeap(process_heap(), 0, 2 * room) } as *mut u16;
        if block.is_null() {
            return Err(STATUS_NO_MEMORY);
        }
        let mut laid = Laid { block, length: 0 };
        let mut returned = 0u32;
        // SAFETY: ntdll's export, over the caller's text and arguments, into the block.
        let status = unsafe {
            nt::RtlFormatMessage(
                text,
                width,
                u32::from(flags & IGNORE_INSERTS != 0),
                u32::from(!wide),
                u32::from(flags & ARGUMENT_ARRAY != 0),
                arguments,
                block,
                (2 * room) as u32,
                &mut returned,
            )
        };
        if status == STATUS_BUFFER_OVERFLOW && room < LAST_ROOM {
            room *= 2;
            continue;
        }
        if !rtl::status::nt_success(status) {
            return Err(status);
        }
        laid.length = (returned as usize / 2).saturating_sub(1);
        return Ok(laid);
    }
}

/// FormatMessageW's work: the message the flags name (see [`message`]) laid out (see
/// [`laid_out`]), its length without the terminator, as characters (`wide`) or bytes. Into the
/// caller's buffer of `size` characters (ERROR_INSUFFICIENT_BUFFER, the buffer untouched, when it
/// cannot hold the text and its terminator), or, for FORMAT_MESSAGE_ALLOCATE_BUFFER, into a block
/// of the text's size on the process heap (a fixed local block: LocalFree frees it; `size` is not
/// its least, as the runtime and msgtable captures show) whose address goes where `buffer` points
/// — null there when the call fails or the text is empty. An empty text is no failure: zero, the
/// last error untouched, a W call's buffer given its terminator alone, an A call's untouched (the
/// msgtable capture).
///
/// # Safety
///
/// The buffer holds `size` characters; for FORMAT_MESSAGE_ALLOCATE_BUFFER it is a pointer's place.
/// For FORMAT_MESSAGE_FROM_STRING, `source` is a NUL-terminated string of the call's form;
/// `arguments` holds every value the message's inserts name.
#[allow(clippy::too_many_arguments)]
unsafe fn format_message(
    flags: u32,
    source: *const u8,
    id: u32,
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
    // SAFETY: the caller's source, of the form the flags say (the contract).
    let laid = unsafe { message(flags, source, id, language, wide) }.and_then(|message| {
        // SAFETY: the message's text is NUL-terminated (a string, a table entry's or its
        // conversion, alive while `message` is); `arguments` holds every value its inserts name
        // (the contract).
        unsafe { laid_out(message.text, flags, arguments, wide) }
    });
    let laid = match laid {
        Ok(laid) => laid,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    // Code page 1252 is one byte a character: the A form's bytes count the characters.
    let units = laid.units();
    let length = units.len();
    if length == 0 && (allocate || !wide) {
        return 0;
    }
    let unit = if wide { 2 } else { 1 };
    let out = if allocate {
        // SAFETY: ntdll's export, on the process heap, as LocalAlloc(LMEM_FIXED) makes a block.
        let block = unsafe { nt::RtlAllocateHeap(process_heap(), 0, unit * (length + 1)) };
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
/// The buffer holds `size` bytes; for FORMAT_MESSAGE_ALLOCATE_BUFFER it is a pointer's place. For
/// FORMAT_MESSAGE_FROM_STRING, `source` is a NUL-terminated string; `arguments` holds every value
/// the message's inserts name.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_FormatMessageA")]
pub unsafe extern "system" fn format_message_a(
    flags: u32,
    source: *const u8,
    id: u32,
    language: u32,
    buffer: *mut u8,
    size: u32,
    arguments: *const u8,
) -> u32 {
    // SAFETY: the caller's source, buffer and arguments.
    unsafe { format_message(flags, source, id, language, buffer, size, arguments, false) }
}

/// FormatMessageW (see [`format_message`]): the size and the length in characters.
///
/// # Safety
///
/// The buffer holds `size` characters; for FORMAT_MESSAGE_ALLOCATE_BUFFER it is a pointer's place.
/// For FORMAT_MESSAGE_FROM_STRING, `source` is a NUL-terminated UTF-16 string; `arguments` holds
/// every value the message's inserts name.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_FormatMessageW")]
pub unsafe extern "system" fn format_message_w(
    flags: u32,
    source: *const u16,
    id: u32,
    language: u32,
    buffer: *mut u16,
    size: u32,
    arguments: *const u8,
) -> u32 {
    // SAFETY: the caller's source, buffer and arguments.
    unsafe {
        format_message(
            flags,
            source as *const u8,
            id,
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

    /// The system message `id` in `language` as FormatMessageW lays it out to the width in
    /// `flags`, as a string; the last error when it fails.
    fn system(id: u32, language: u32, flags: u32) -> Result<std::string::String, u32> {
        let mut out = [0u16; 2048];
        // SAFETY: a buffer of its size; no inserts read.
        let length = unsafe {
            format_message_w(
                FROM_SYSTEM | IGNORE_INSERTS | flags,
                core::ptr::null(),
                id,
                language,
                out.as_mut_ptr(),
                out.len() as u32,
                core::ptr::null(),
            )
        };
        if length == 0 {
            return Err(crate::base::last_error());
        }
        Ok(std::string::String::from_utf16(&out[..length as usize]).unwrap())
    }

    /// The capture's lengths: the text and its CR LF.
    #[test]
    fn the_captured_messages() {
        assert_eq!(system(2, 0, 0).map(|t| t.len()), Ok(44));
        assert_eq!(system(5, 0, 0).as_deref(), Ok("Access is denied.\r\n"));
        assert_eq!(
            system(0x0123_4567, 0, 0),
            Err(crate::error::ERROR_MR_MID_NOT_FOUND)
        );
    }

    /// Every message of the table lays out at the narrowest width, where every character breaks.
    #[test]
    fn every_message_lays_out_at_the_narrowest_width() {
        for id in 0..1000 {
            if system(id, 0, 0).is_ok() {
                assert!(system(id, 0, 1).is_ok());
            }
        }
    }

    /// A language other than the table's (and the defaults that stand for it) has no message:
    /// ERROR_RESOURCE_LANG_NOT_FOUND, as on the platform.
    #[test]
    fn another_language_has_no_message() {
        assert_eq!(system(2, 0x040C, 0), Err(1815));
        assert!(system(2, 0x0400, 0).is_ok());
        assert_eq!(
            rtl::status::dos_error(rtl::resource::STATUS_MESSAGE_NOT_FOUND),
            crate::error::ERROR_MR_MID_NOT_FOUND
        );
    }

    /// A string's inserts through an array, in both forms; the A form's strings ANSI.
    #[test]
    fn strings_expand_their_inserts() {
        let mut out = [0u16; 64];
        let one: std::vec::Vec<u16> = "one".encode_utf16().chain([0]).collect();
        let text: std::vec::Vec<u16> = "[%1] %2!d!".encode_utf16().chain([0]).collect();
        let arguments = [one.as_ptr() as usize, 42];
        // SAFETY: the buffers and arguments above.
        let length = unsafe {
            format_message_w(
                FROM_STRING | ARGUMENT_ARRAY,
                text.as_ptr(),
                0,
                0,
                out.as_mut_ptr(),
                out.len() as u32,
                arguments.as_ptr() as *const u8,
            )
        };
        assert_eq!(
            std::string::String::from_utf16(&out[..length as usize]).unwrap(),
            "[one] 42"
        );
        let mut narrow = [0u8; 64];
        let arguments = [b"two\0".as_ptr() as usize, 7];
        // SAFETY: as above.
        let length = unsafe {
            format_message_a(
                FROM_STRING | ARGUMENT_ARRAY,
                b"[%1] %2!d!\0".as_ptr(),
                0,
                0,
                narrow.as_mut_ptr(),
                narrow.len() as u32,
                arguments.as_ptr() as *const u8,
            )
        };
        assert_eq!(&narrow[..=length as usize], b"[two] 7\0");
    }

    /// A buffer too small fails untouched; an empty text is zero, the W buffer terminated, the A
    /// one untouched, the allocated block none.
    #[test]
    fn buffers_and_empty_texts() {
        let text: std::vec::Vec<u16> = "Short.%0".encode_utf16().chain([0]).collect();
        let mut out = [0x23u16; 8];
        crate::base::set_last_error(0);
        // SAFETY: the buffer above, six characters of its eight.
        let length = unsafe {
            format_message_w(
                FROM_STRING,
                text.as_ptr(),
                0,
                0,
                out.as_mut_ptr(),
                6,
                core::ptr::null(),
            )
        };
        assert_eq!((length, crate::base::last_error()), (0, 122));
        assert_eq!(out, [0x23; 8]);
        let empty = [u16::from(b'%'), u16::from(b'0'), 0];
        crate::base::set_last_error(0);
        // SAFETY: as above.
        let length = unsafe {
            format_message_w(
                FROM_STRING,
                empty.as_ptr(),
                0,
                0,
                out.as_mut_ptr(),
                8,
                core::ptr::null(),
            )
        };
        assert_eq!(
            (length, crate::base::last_error(), out[0], out[1]),
            (0, 0, 0, 0x23)
        );
        let mut narrow = [0x23u8; 4];
        // SAFETY: as above.
        let length = unsafe {
            format_message_a(
                FROM_STRING,
                b"%0\0".as_ptr(),
                0,
                0,
                narrow.as_mut_ptr(),
                4,
                core::ptr::null(),
            )
        };
        assert_eq!((length, narrow), (0, [0x23; 4]));
        let mut block = 0x1234usize as *mut u16;
        // SAFETY: the pointer place above.
        let length = unsafe {
            format_message_w(
                FROM_STRING | ALLOCATE_BUFFER,
                empty.as_ptr(),
                0,
                0,
                &mut block as *mut *mut u16 as *mut u16,
                0,
                core::ptr::null(),
            )
        };
        assert_eq!((length, block), (0, core::ptr::null_mut()));
    }
}
