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

use crate::edge::{InStr, InWStr, Out, OutBuf, Text};
use crate::error::{answer, Failure, ERROR_INSUFFICIENT_BUFFER};
use crate::heap::{HeapArray, HeapString, OutOfMemory};
use crate::ntcall::{self, MessageArguments, MessageLayout, MessageText, NtStatus};

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
    crate::base::image_base()
}

/// What FormatMessage's source argument is: the caller's string, of the call's form, for
/// FORMAT_MESSAGE_FROM_STRING; a module's handle otherwise (the program's for NULL).
pub enum Source<'a> {
    Wide(InWStr<'a>),
    Ansi(InStr<'a>),
    Module(usize),
}

/// Where FormatMessage's text goes: the caller's buffer, or for FORMAT_MESSAGE_ALLOCATE_BUFFER the
/// place of a pointer to a block the call allocates.
pub enum Destination<'a> {
    Buffer(Text<'a>),
    Allocate(Out<'a, usize>),
}

/// A message's text, NUL-terminated UTF-16: the caller's or a table's in place, or one kernel32
/// converted from ANSI (on the process heap, freed with it).
enum Message<'a> {
    Borrowed(InWStr<'a>),
    Converted(HeapString),
}

impl Message<'_> {
    /// A NUL-terminated ANSI text converted ([`HeapString::of_ansi`]: ntdll's RtlInitAnsiString
    /// and RtlAnsiStringToUnicodeString, onto the process heap); the status of a failed
    /// conversion.
    fn converted(text: &InStr<'_>) -> Result<Self, NtStatus> {
        HeapString::of_ansi(Some(text)).map(Message::Converted)
    }

    /// The text, to its terminator.
    fn text(&self) -> InWStr<'_> {
        match self {
            Message::Borrowed(text) => *text,
            // The conversion terminates its buffer, which it sized for the terminator too.
            Message::Converted(converted) => converted.terminated(),
        }
    }
}

/// Message `id` of `module`'s message table, in `language` (ntdll's RtlFindMessage): its text,
/// or the lookup's status.
fn table_message(module: usize, id: u32, language: u32) -> Result<Message<'static>, NtStatus> {
    match ntcall::find_message(module, rtl::resource::RT_MESSAGETABLE, language, id)? {
        MessageText::Wide(text) => Ok(Message::Borrowed(text)),
        MessageText::Ansi(text) => Message::converted(&text),
    }
}

/// The message the flags name: the string `source` is, or message `id` from the module's table
/// (`source`, the program's for NULL) and then the system's, as asked. A call naming no source is
/// STATUS_INVALID_PARAMETER; one that finds no message has the last lookup's status.
fn message<'a>(
    flags: u32,
    source: Source<'a>,
    id: u32,
    language: u32,
) -> Result<Message<'a>, NtStatus> {
    let module = match source {
        Source::Wide(text) => return Ok(Message::Borrowed(text)),
        Source::Ansi(text) => return Message::converted(&text),
        Source::Module(module) => module,
    };
    let mut status = STATUS_INVALID_PARAMETER;
    if flags & FROM_HMODULE != 0 {
        let module = if module == 0 {
            program_handle()
        } else {
            module
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

/// `text` laid out by ntdll's RtlFormatMessage as the flags ask (the width: the flags' low byte,
/// FORMAT_MESSAGE_MAX_WIDTH_MASK as MAXULONG; the inserts from `arguments` unless ignored), into a
/// block that grows until it fits: the characters, or the status of the call that failed.
fn laid_out(
    text: &InWStr<'_>,
    flags: u32,
    arguments: MessageArguments,
    wide: bool,
) -> Result<HeapArray<u16>, NtStatus> {
    let layout = MessageLayout {
        width: match flags & MAX_WIDTH_MASK {
            MAX_WIDTH_MASK => rtl::message::NO_LINE_BREAKS,
            width => width,
        },
        ignore_inserts: flags & IGNORE_INSERTS != 0,
        ansi: !wide,
        array: flags & ARGUMENT_ARRAY != 0,
    };
    let mut room = FIRST_ROOM;
    loop {
        let mut laid = HeapArray::<u16>::new(room).map_err(|OutOfMemory| STATUS_NO_MEMORY)?;
        match ntcall::format_message(text, &layout, arguments, &mut laid) {
            Err(STATUS_BUFFER_OVERFLOW) if room < LAST_ROOM => room *= 2,
            Err(status) => return Err(status),
            Ok(returned) => {
                laid.truncate((returned / 2).saturating_sub(1));
                return Ok(laid);
            }
        }
    }
}

/// FormatMessageW's work: the message the flags name (see [`message`]) laid out (see
/// [`laid_out`]), its length without the terminator, as characters (`wide`) or bytes. Into the
/// caller's buffer (ERROR_INSUFFICIENT_BUFFER, the buffer untouched, when it cannot hold the text
/// and its terminator), or, for FORMAT_MESSAGE_ALLOCATE_BUFFER, into a block of the text's size on
/// the process heap (a fixed local block: LocalFree frees it; the size given is not its least, as
/// the runtime and msgtable captures show) whose address goes to the caller's place — null there
/// when the call fails or the text is empty. An empty text is no failure: zero, the last error
/// untouched, a W call's buffer given its terminator alone, an A call's untouched (the msgtable
/// capture).
fn format_message(
    flags: u32,
    (source, id, language): (Source<'_>, u32, u32),
    mut destination: Destination<'_>,
    arguments: MessageArguments,
    wide: bool,
) -> Result<u32, Failure> {
    if let Destination::Allocate(place) = &mut destination {
        place.set(0);
    }
    let laid = message(flags, source, id, language)
        .and_then(|message| laid_out(&message.text(), flags, arguments, wide))
        .map_err(Failure::Status)?;
    // Code page 1252 is one byte a character: the A form's bytes count the characters.
    let units = &*laid;
    let length = units.len();
    let allocate = matches!(destination, Destination::Allocate(_));
    if length == 0 && (allocate || !wide) {
        return Ok(0);
    }
    match destination {
        Destination::Allocate(mut place) => {
            // On the process heap, as LocalAlloc(LMEM_FIXED) makes a block, terminated (the
            // block's values start zero).
            let block = if wide {
                let mut block = HeapArray::<u16>::new(length + 1)?;
                block[..length].copy_from_slice(units);
                block.into_raw().as_ptr() as usize
            } else {
                let mut block = HeapArray::<u8>::new(length + 1)?;
                ntcall::unicode_to_multi_byte_into(&mut block[..length], units);
                block.into_raw().as_ptr() as usize
            };
            place.set(block);
        }
        Destination::Buffer(mut buffer) => {
            if buffer.len() <= length {
                return Err(Failure::Error(ERROR_INSUFFICIENT_BUFFER));
            }
            buffer.put_terminated(units);
        }
    }
    Ok(length as u32)
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
    // SAFETY: the caller's source, buffer and arguments, of the forms the flags say (the
    // contract).
    let (source, destination, arguments) = unsafe {
        (
            if flags & FROM_STRING != 0 {
                Source::Ansi(InStr::new(source))
            } else {
                Source::Module(source as usize)
            },
            if flags & ALLOCATE_BUFFER != 0 {
                Destination::Allocate(Out::new(buffer.cast()))
            } else {
                Destination::Buffer(Text::Ansi(OutBuf::new(buffer, size as usize)))
            },
            MessageArguments::caller(arguments),
        )
    };
    let named = (source, id, language);
    answer(
        format_message(flags, named, destination, arguments, false),
        0,
    )
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
    // SAFETY: the caller's source, buffer and arguments, of the forms the flags say (the
    // contract).
    let (source, destination, arguments) = unsafe {
        (
            if flags & FROM_STRING != 0 {
                Source::Wide(InWStr::new(source))
            } else {
                Source::Module(source as usize)
            },
            if flags & ALLOCATE_BUFFER != 0 {
                Destination::Allocate(Out::new(buffer.cast()))
            } else {
                Destination::Buffer(Text::Wide(OutBuf::new(buffer, size as usize)))
            },
            MessageArguments::caller(arguments),
        )
    };
    let named = (source, id, language);
    answer(
        format_message(flags, named, destination, arguments, true),
        0,
    )
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
