//! Counted strings and the ANSI code page, as ntdll's string functions convert them
//! (RtlInitAnsiString, RtlAnsiStringToUnicodeString, RtlUnicodeStringToAnsiString,
//! RtlFreeUnicodeString, RtlUnicodeToMultiByteN, RtlUnicodeToMultiByteSize): kernel32's narrow
//! calls hand their strings to these, as Windows 2000's kernel32 does. The ANSI code page is 1252
//! ([`crate::cp1252`]), a single-byte one: a character is one byte one way and one unit the other.
//!
//! The structures are the documented ANSI_STRING and UNICODE_STRING: the length and the room in
//! bytes, then the buffer. A string a conversion allocates comes from the process heap, through the
//! allocator its caller hands over (ntdll's heap, or the host tests' stand-in).

use crate::cp1252;
use crate::status::{
    STATUS_BUFFER_OVERFLOW,
    STATUS_INVALID_PARAMETER_2,
    STATUS_NO_MEMORY,
    STATUS_SUCCESS,
};

/// An ANSI_STRING ([`crate::nt::AnsiString`]) over the caller's own memory.
pub type AnsiString = crate::nt::AnsiString<*mut u8>;

/// A UNICODE_STRING ([`crate::nt::UnicodeString`]) over the caller's own memory.
pub type UnicodeString = crate::nt::UnicodeString<*mut u16>;

/// The most bytes a counted string's room holds (its length a word: MAX_USTRING for a Unicode
/// string, the terminator included).
pub const MAX_USTRING: usize = 0xFFFE;
/// The most bytes an ANSI string's room holds.
pub const MAX_STRING: usize = 0xFFFF;

/// RtlMultiByteToUnicodeN's conversion: as many bytes as `out` has room for, each its code-page
/// character; the units written.
pub fn multi_byte_to_unicode(out: &mut [u16], bytes: &[u8]) -> usize {
    let count = out.len().min(bytes.len());
    for (unit, &byte) in out.iter_mut().zip(bytes).take(count) {
        *unit = cp1252::MB_TO_WC[byte as usize];
    }
    count
}

/// RtlUnicodeToMultiByteN's conversion: as many units as `out` has room for, each its code-page
/// byte (the default character for one the code page lacks); the bytes written.
pub fn unicode_to_multi_byte(out: &mut [u8], units: &[u16]) -> usize {
    let count = out.len().min(units.len());
    for (byte, &unit) in out.iter_mut().zip(units).take(count) {
        *byte = cp1252::wc_to_mb(unit);
    }
    count
}

/// RtlUnicodeToMultiByteSize: the bytes `bytes` bytes of UTF-16 take in the code page (one per
/// unit, the code page being single-byte).
pub fn unicode_to_multi_byte_size(bytes: u32) -> u32 {
    bytes / 2
}

/// RtlxAnsiStringToUnicodeSize: the bytes an ANSI string of `length` bytes takes as a Unicode
/// string, its terminator included.
pub fn ansi_to_unicode_size(length: usize) -> usize {
    2 * (length + 1)
}

/// RtlxUnicodeStringToAnsiSize: the bytes a Unicode string of `length` bytes takes as an ANSI
/// string, its terminator included.
pub fn unicode_to_ansi_size(length: usize) -> usize {
    length / 2 + 1
}

/// RtlInitAnsiString: the counted form of the NUL-terminated string at `source` (an empty string
/// with no buffer for null), its room the length and the terminator. A string past the counts'
/// reach is counted as the longest that fits, MAX_STRING - 1 bytes.
///
/// # Safety
///
/// `source` is null or a NUL-terminated string.
pub unsafe fn init_ansi_string(source: *const u8) -> AnsiString {
    if source.is_null() {
        return AnsiString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
    }
    // SAFETY: the caller's string, read to its terminator.
    let length = unsafe { crate::cstr::bytes_until_nul(source) }
        .len()
        .min(MAX_STRING - 1);
    AnsiString {
        length: length as u16,
        maximum_length: length as u16 + 1,
        buffer: source as *mut u8,
    }
}

/// RtlAnsiStringToUnicodeString: `source` converted into `destination`, terminated when its room
/// holds the terminator too. With `allocate`, the buffer comes from `heap` (`destination`'s room
/// the string and its terminator): STATUS_NO_MEMORY when it has none. Otherwise `destination`'s own
/// buffer: STATUS_BUFFER_OVERFLOW, nothing converted, when its room is not past the string's
/// length. STATUS_INVALID_PARAMETER_2 for a string whose Unicode form is past MAX_USTRING.
///
/// # Safety
///
/// `source`'s buffer holds its length; without `allocate`, `destination`'s holds its room.
pub unsafe fn ansi_string_to_unicode_string(
    destination: &mut UnicodeString,
    source: &AnsiString,
    allocate: bool,
    heap: impl FnOnce(usize) -> *mut u8,
) -> u32 {
    let size = ansi_to_unicode_size(source.length as usize);
    if size > MAX_USTRING {
        return STATUS_INVALID_PARAMETER_2;
    }
    let length = size - 2;
    if allocate {
        let buffer = heap(size) as *mut u16;
        if buffer.is_null() {
            return STATUS_NO_MEMORY;
        }
        destination.buffer = buffer;
        destination.maximum_length = size as u16;
    } else if length >= destination.maximum_length as usize {
        return STATUS_BUFFER_OVERFLOW;
    }
    destination.length = length as u16;
    let room = destination.maximum_length as usize / 2;
    // SAFETY: the caller's source; the destination's buffer holds the string, and its terminator
    // when its room does.
    unsafe {
        let out = core::slice::from_raw_parts_mut(destination.buffer, room);
        let count = multi_byte_to_unicode(&mut out[..length / 2], source.bytes());
        if count < room {
            out[count] = 0;
        }
    }
    STATUS_SUCCESS
}

/// RtlUnicodeStringToAnsiString: `source` converted into `destination`, terminated when there is
/// room. With `allocate`, the buffer comes from `heap` (`destination`'s room the string and its
/// terminator): STATUS_NO_MEMORY when it has none. Otherwise `destination`'s own buffer: when its
/// room cannot hold the string and its terminator, what fits of the string is converted and
/// terminated (nothing for no room) and the answer is STATUS_BUFFER_OVERFLOW.
/// STATUS_INVALID_PARAMETER_2 for a string whose ANSI form is past MAX_STRING.
///
/// # Safety
///
/// `source`'s buffer holds its length; without `allocate`, `destination`'s holds its room.
pub unsafe fn unicode_string_to_ansi_string(
    destination: &mut AnsiString,
    source: &UnicodeString,
    allocate: bool,
    heap: impl FnOnce(usize) -> *mut u8,
) -> u32 {
    let size = unicode_to_ansi_size(source.length as usize);
    if size > MAX_STRING {
        return STATUS_INVALID_PARAMETER_2;
    }
    let (mut length, mut status) = (size - 1, STATUS_SUCCESS);
    if allocate {
        let buffer = heap(size);
        if buffer.is_null() {
            return STATUS_NO_MEMORY;
        }
        destination.buffer = buffer;
        destination.maximum_length = size as u16;
    } else if length >= destination.maximum_length as usize {
        if destination.maximum_length == 0 {
            return STATUS_BUFFER_OVERFLOW;
        }
        (length, status) = (
            destination.maximum_length as usize - 1,
            STATUS_BUFFER_OVERFLOW,
        );
    }
    destination.length = length as u16;
    // SAFETY: the caller's source; the destination's buffer holds `length` bytes and a terminator.
    unsafe {
        let out = core::slice::from_raw_parts_mut(destination.buffer, length + 1);
        let count = unicode_to_multi_byte(&mut out[..length], source.units());
        out[count] = 0;
    }
    status
}

/// RtlFreeUnicodeString: a string a conversion allocated, its buffer handed to `free` (none for an
/// empty one) and the string emptied.
pub fn free_unicode_string(string: &mut UnicodeString, free: impl FnOnce(*mut u8)) {
    if !string.buffer.is_null() {
        free(string.buffer as *mut u8);
    }
    *string = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: core::ptr::null_mut(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_unicode(units: &mut [u16]) -> UnicodeString {
        UnicodeString {
            length: 0,
            maximum_length: (2 * units.len()) as u16,
            buffer: units.as_mut_ptr(),
        }
    }

    /// The conversions take the code page's characters: 0x80 is the euro sign one way, the euro
    /// sign 0x80 the other; a character the code page lacks is its default character.
    #[test]
    fn the_conversions_follow_code_page_1252() {
        let mut wide = [0u16; 4];
        assert_eq!(multi_byte_to_unicode(&mut wide, b"a\x80\xE9"), 3);
        assert_eq!(wide, [0x61, 0x20AC, 0xE9, 0]);
        let mut narrow = [0u8; 4];
        assert_eq!(
            unicode_to_multi_byte(&mut narrow, &[0x20AC, 0x3042, 0x41]),
            3
        );
        assert_eq!(narrow, [0x80, b'?', b'A', 0]);
        assert_eq!(
            unicode_to_multi_byte(&mut narrow[..2], &[0x41, 0x42, 0x43]),
            2,
            "no further than the room"
        );
        assert_eq!(unicode_to_multi_byte_size(10), 5);
        assert_eq!(ansi_to_unicode_size(3), 8);
        assert_eq!(unicode_to_ansi_size(6), 4);
    }

    /// RtlInitAnsiString counts to the terminator, its room one more; null is the empty string.
    #[test]
    fn an_ansi_string_counts_to_its_terminator() {
        // SAFETY: a terminated string, and null.
        let (string, empty) = unsafe {
            (
                init_ansi_string(b"name\0".as_ptr()),
                init_ansi_string(core::ptr::null()),
            )
        };
        assert_eq!((string.length, string.maximum_length), (4, 5));
        assert_eq!((empty.length, empty.maximum_length), (0, 0));
        assert!(empty.buffer.is_null());
        let long = std::vec![b'x'; 70_000]
            .into_iter()
            .chain([0])
            .collect::<std::vec::Vec<u8>>();
        // SAFETY: as above.
        let long = unsafe { init_ansi_string(long.as_ptr()) };
        assert_eq!((long.length, long.maximum_length), (0xFFFE, 0xFFFF));
    }

    /// Into the caller's buffer: the string and its terminator when they fit the room, the overflow
    /// when the terminator does not (an A call's MAX_PATH + 1 units hold MAX_PATH characters).
    #[test]
    fn an_ansi_string_converts_into_a_buffer_with_room_for_its_terminator() {
        let mut units = [0xFFFFu16; 261];
        let mut destination = empty_unicode(&mut units);
        let path = [b'a'; 261];
        let source = |length: usize| AnsiString {
            length: length as u16,
            maximum_length: length as u16,
            buffer: path.as_ptr() as *mut u8,
        };
        let refuse = |_| -> *mut u8 { panic!("no allocation") };
        // SAFETY: the strings above, their buffers holding their lengths and rooms.
        unsafe {
            assert_eq!(
                ansi_string_to_unicode_string(&mut destination, &source(260), false, refuse),
                STATUS_SUCCESS
            );
            assert_eq!(destination.length, 520);
            assert_eq!(units[259..], [u16::from(b'a'), 0]);
            let mut destination = empty_unicode(&mut units);
            assert_eq!(
                ansi_string_to_unicode_string(&mut destination, &source(261), false, refuse),
                STATUS_BUFFER_OVERFLOW
            );
        }
    }

    /// The allocating form: a buffer of the string and its terminator from the heap, or
    /// STATUS_NO_MEMORY; a string whose Unicode form is past MAX_USTRING is refused first.
    #[test]
    fn an_ansi_string_converts_onto_the_heap() {
        let mut block = [0xFFFFu16; 8];
        let mut destination = empty_unicode(&mut []);
        let source = AnsiString {
            length: 3,
            maximum_length: 4,
            buffer: b"A\x80c\0".as_ptr() as *mut u8,
        };
        // SAFETY: the strings above; the block holds the conversion.
        unsafe {
            let status = ansi_string_to_unicode_string(&mut destination, &source, true, |size| {
                assert_eq!(size, 8);
                block.as_mut_ptr() as *mut u8
            });
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!((destination.length, destination.maximum_length), (6, 8));
            assert_eq!(block[..4], [0x41, 0x20AC, 0x63, 0]);
            assert_eq!(
                ansi_string_to_unicode_string(&mut destination, &source, true, |_| {
                    core::ptr::null_mut()
                }),
                STATUS_NO_MEMORY
            );
            let long = AnsiString {
                length: 32_767,
                maximum_length: 32_768,
                buffer: core::ptr::null_mut(),
            };
            assert_eq!(
                ansi_string_to_unicode_string(&mut destination, &long, true, |_| {
                    panic!("refused before allocating")
                }),
                STATUS_INVALID_PARAMETER_2
            );
        }
        let mut freed = None;
        free_unicode_string(&mut destination, |buffer| freed = Some(buffer));
        assert_eq!(freed, Some(block.as_mut_ptr() as *mut u8));
        assert!(destination.buffer.is_null() && destination.maximum_length == 0);
    }

    /// The narrowing: into the caller's buffer, what fits converted and terminated with
    /// STATUS_BUFFER_OVERFLOW when the string does not; onto the heap, the string and its
    /// terminator.
    #[test]
    fn a_unicode_string_converts_to_ansi() {
        let mut wide = [0x41u16, 0x20AC, 0x43, 0x44];
        let source = UnicodeString {
            length: 8,
            maximum_length: 8,
            buffer: wide.as_mut_ptr(),
        };
        let mut bytes = [0xFFu8; 5];
        let mut destination = AnsiString {
            length: 0,
            maximum_length: 5,
            buffer: bytes.as_mut_ptr(),
        };
        let refuse = |_| -> *mut u8 { panic!("no allocation") };
        // SAFETY: the strings above, their buffers holding their lengths and rooms.
        unsafe {
            assert_eq!(
                unicode_string_to_ansi_string(&mut destination, &source, false, refuse),
                STATUS_SUCCESS
            );
            assert_eq!((destination.length, bytes), (4, *b"A\x80CD\0"));
            destination.maximum_length = 3;
            assert_eq!(
                unicode_string_to_ansi_string(&mut destination, &source, false, refuse),
                STATUS_BUFFER_OVERFLOW
            );
            assert_eq!((destination.length, &bytes[..3]), (2, &b"A\x80\0"[..]));
            let mut block = [0xFFu8; 5];
            let mut allocated = AnsiString {
                length: 0,
                maximum_length: 0,
                buffer: core::ptr::null_mut(),
            };
            let status = unicode_string_to_ansi_string(&mut allocated, &source, true, |size| {
                assert_eq!(size, 5);
                block.as_mut_ptr()
            });
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!((allocated.length, allocated.maximum_length), (4, 5));
            assert_eq!(block, *b"A\x80CD\0");
        }
    }
}
