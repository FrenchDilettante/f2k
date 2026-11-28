//! Counted strings and the ANSI code page, as ntdll's string functions convert them
//! (RtlInitAnsiString, RtlInitUnicodeString, RtlAnsiStringToUnicodeString,
//! RtlUnicodeStringToAnsiString, RtlFreeUnicodeString, RtlUnicodeToMultiByteN,
//! RtlUnicodeToMultiByteSize), upper-case them (RtlUpcaseUnicodeString) and read their numbers
//! (RtlUnicodeStringToInteger): kernel32's narrow calls and its resource names hand their strings
//! to these, as Windows 2000's kernel32 does. The ANSI code page is 1252 ([`crate::cp1252`]), a
//! single-byte one: a character is one byte one way and one unit the other.
//!
//! The structures are the documented ANSI_STRING and UNICODE_STRING: the length and the room in
//! bytes, then the buffer. A string a conversion allocates comes from the process heap, through the
//! allocator its caller hands over (ntdll's heap, or the host tests' stand-in).

use crate::codepage::sbcs::CP1252;
use crate::cp1252;
use crate::heap::{Block, ProcessHeap};
use crate::status::{
    STATUS_BUFFER_OVERFLOW,
    STATUS_INVALID_PARAMETER,
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
/// byte, best-fit where the code page lacks it (Windows' table for 1252, as the code page's own
/// NLS table carries it: α is `a`), else the default character; the bytes written.
pub fn unicode_to_multi_byte(out: &mut [u8], units: &[u16]) -> usize {
    let count = out.len().min(units.len());
    for (byte, &unit) in out.iter_mut().zip(units).take(count) {
        *byte = CP1252.encode(unit, true).unwrap_or(cp1252::DEFAULT_CHAR);
    }
    count
}

/// RtlUnicodeToMultiByteSize: the bytes `bytes` bytes of UTF-16 take in the code page (one per
/// unit, the code page being single-byte).
pub fn unicode_to_multi_byte_size(bytes: u32) -> u32 {
    bytes / 2
}

/// RtlMultiByteToUnicodeN's shape, as a system DLL imports it (or its host tests' stand-in).
pub type MultiByteToUnicodeN =
    unsafe extern "system" fn(*mut u16, u32, *mut u32, *const u8, u32) -> u32;

/// RtlUnicodeToMultiByteN's shape, as a system DLL imports it (or its host tests' stand-in).
pub type UnicodeToMultiByteN =
    unsafe extern "system" fn(*mut u8, u32, *mut u32, *const u16, u32) -> u32;

/// A system DLL's RtlMultiByteToUnicodeN, `call`, over slices: as much of `source` as
/// `destination` holds, from the ANSI code page to UTF-16: the units written.
///
/// # Safety
///
/// `call` is RtlMultiByteToUnicodeN (or a stand-in keeping its contract): it reads at most the
/// bytes it is given and writes at most the room it is given, and the count.
pub unsafe fn multi_byte_to_unicode_with(
    call: MultiByteToUnicodeN,
    destination: &mut [u16],
    source: &[u8],
) -> usize {
    let mut written = 0u32;
    // SAFETY: the call reads the source's bytes and writes at most the destination's units, and
    // the count of bytes into the local (the caller's contract).
    unsafe {
        call(
            destination.as_mut_ptr(),
            2 * destination.len() as u32,
            &mut written,
            source.as_ptr(),
            source.len() as u32,
        )
    };
    written as usize / 2
}

/// A system DLL's RtlUnicodeToMultiByteN, `call`, over slices: as many of `source`'s units as
/// `destination` holds, converted to the ANSI code page: the bytes written.
///
/// # Safety
///
/// `call` is RtlUnicodeToMultiByteN (or a stand-in keeping its contract): it reads at most the
/// units it is given and writes at most the room it is given, and the count.
pub unsafe fn unicode_to_multi_byte_with(
    call: UnicodeToMultiByteN,
    destination: &mut [u8],
    source: &[u16],
) -> usize {
    let mut written = 0u32;
    // SAFETY: the call reads the source's units and writes at most the destination's bytes, and
    // the count into the local (the caller's contract).
    unsafe {
        call(
            destination.as_mut_ptr(),
            destination.len() as u32,
            &mut written,
            source.as_ptr(),
            2 * source.len() as u32,
        )
    };
    written as usize
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

/// RtlInitUnicodeString: the counted form of the NUL-terminated string at `source` (an empty string
/// with no buffer for null), its room the length and the terminator, in bytes. Each count is
/// truncated to the word it is kept in, as Windows 2000's ntdll keeps it (its string.c, which only
/// later versions clamp to MAX_USTRING): a string of 0x7FFF units has a room of 0, one of 0x8000 a
/// length of 0.
///
/// # Safety
///
/// `source` is null or a NUL-terminated UTF-16 string (at any address).
pub unsafe fn init_unicode_string(source: *const u16) -> UnicodeString {
    if source.is_null() {
        return UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        };
    }
    // SAFETY: the caller's string, read to its terminator.
    let bytes = unsafe { crate::cstr::len_until_nul(source) }.wrapping_mul(2);
    UnicodeString {
        length: bytes as u16,
        maximum_length: bytes.wrapping_add(2) as u16,
        buffer: source as *mut u16,
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

/// RtlUpcaseUnicodeString: `source` upper-cased into `destination`, each unit as LCMapString's
/// LCMAP_UPPERCASE maps it ([`cp1252::map_case`]), no terminator added. With `allocate`, the buffer
/// comes from `heap`, its room the string's length: STATUS_NO_MEMORY when it has none. Otherwise
/// `destination`'s own buffer, which may be `source`'s (the string upper-cased in place):
/// STATUS_BUFFER_OVERFLOW, nothing written, when its room is short of the string's length.
///
/// # Safety
///
/// `source`'s buffer holds its length; without `allocate`, `destination`'s holds its room.
pub unsafe fn upcase_unicode_string(
    destination: &mut UnicodeString,
    source: &UnicodeString,
    allocate: bool,
    heap: impl FnOnce(usize) -> *mut u8,
) -> u32 {
    let length = source.length & !1;
    if allocate {
        let buffer = heap(usize::from(length)) as *mut u16;
        if buffer.is_null() {
            return STATUS_NO_MEMORY;
        }
        destination.buffer = buffer;
        destination.maximum_length = length;
    } else if length > destination.maximum_length {
        return STATUS_BUFFER_OVERFLOW;
    }
    destination.length = length;
    for index in 0..usize::from(length) / 2 {
        // SAFETY: the caller's source holds `length` bytes and the destination's buffer as many;
        // each unit is read before its place is written, the two buffers being one in place.
        unsafe {
            let unit = source.buffer.add(index).read();
            destination
                .buffer
                .add(index)
                .write(cp1252::map_case(unit, true));
        }
    }
    STATUS_SUCCESS
}

/// RtlUnicodeStringToInteger: the number `text` spells in `base` (2, 8, 10 or 16; 0 for decimal
/// unless a prefix says otherwise): blanks skipped, a sign, with base 0 a prefix `0x`
/// (hexadecimal), `0o` (octal) or `0b` (binary), then the digits up to the first that is not one,
/// wrapping around (no digits is zero). STATUS_INVALID_PARAMETER for any other base.
pub fn unicode_string_to_integer(text: &[u16], base: u32) -> Result<u32, u32> {
    if ![0, 2, 8, 10, 16].contains(&base) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut at = text.iter().take_while(|&&unit| unit <= b' ' as u16).count();
    let negative = text.get(at) == Some(&(b'-' as u16));
    if negative || text.get(at) == Some(&(b'+' as u16)) {
        at += 1;
    }
    let mut base = base;
    if base == 0 {
        let prefix = (text.get(at), text.get(at + 1).map(|&unit| unit | 0x20));
        base = match prefix {
            (Some(0x30), Some(0x78)) => 16,
            (Some(0x30), Some(0x6F)) => 8,
            (Some(0x30), Some(0x62)) => 2,
            _ => 10,
        };
        if base != 10 {
            at += 2;
        }
    }
    let value = text[at.min(text.len())..]
        .iter()
        .map_while(|&unit| char::from_u32(unit.into())?.to_digit(base))
        .fold(0u32, |value, digit| {
            value.wrapping_mul(base).wrapping_add(digit)
        });
    Ok(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// The units a narrow string converts into on the stack (MAX_PATH's, its terminator included): a
/// longer one converts in a block of the process heap.
pub const STACK_UNITS: usize = 260;

/// Run `f` on the wide form of the narrow `bytes`, NUL-terminated, as a system DLL's narrow calls
/// convert their strings: `convert` (the DLL's RtlMultiByteToUnicodeN over slices) makes it on the
/// stack when it is short and in a block of the process heap (`H`'s) otherwise; none when the heap
/// has no room for it. `f` gets the units, the terminator included: for a service that takes the
/// string's address.
pub fn with_wide_z<H: ProcessHeap, R>(
    bytes: &[u8],
    convert: impl FnOnce(&mut [u16], &[u8]) -> usize,
    f: impl FnOnce(&[u16]) -> R,
) -> Option<R> {
    if bytes.len() < STACK_UNITS {
        let mut units = [0u16; STACK_UNITS];
        let length = convert(&mut units[..bytes.len()], bytes);
        return Some(f(&units[..=length]));
    }
    let mut block = Block::<H>::new(2 * (bytes.len() + 1))?;
    let units = block.units_mut();
    let room = units.len() - 1;
    let length = convert(&mut units[..room], bytes);
    units[length] = 0;
    Some(f(&units[..=length]))
}

/// Run `f` on the wide form of the narrow `bytes` as [`with_wide_z`] makes it, without the
/// terminator: the string's units alone.
pub fn with_wide<H: ProcessHeap, R>(
    bytes: &[u8],
    convert: impl FnOnce(&mut [u16], &[u8]) -> usize,
    f: impl FnOnce(&[u16]) -> R,
) -> Option<R> {
    with_wide_z::<H, R>(bytes, convert, |units| f(&units[..units.len() - 1]))
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
    /// sign 0x80 the other; a character the code page lacks is its best fit (α is `a`), else its
    /// default character.
    #[test]
    fn the_conversions_follow_code_page_1252() {
        let mut wide = [0u16; 4];
        assert_eq!(multi_byte_to_unicode(&mut wide, b"a\x80\xE9"), 3);
        assert_eq!(wide, [0x61, 0x20AC, 0xE9, 0]);
        let mut narrow = [0u8; 4];
        assert_eq!(
            unicode_to_multi_byte(&mut narrow, &[0x20AC, 0x3042, 0x41, 0x03B1]),
            4
        );
        assert_eq!(narrow, [0x80, b'?', b'A', b'a']);
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

    /// RtlInitUnicodeString counts to the terminator in bytes, its room two more; null is the
    /// empty string; past the word's reach the counts wrap, as Windows 2000's do.
    #[test]
    fn a_unicode_string_counts_to_its_terminator() {
        let name = [b'n' as u16, b'a' as u16, b'm' as u16, b'e' as u16, 0];
        // SAFETY: a terminated string, and null.
        let (string, empty) = unsafe {
            (
                init_unicode_string(name.as_ptr()),
                init_unicode_string(core::ptr::null()),
            )
        };
        assert_eq!((string.length, string.maximum_length), (8, 10));
        assert_eq!(string.buffer.cast_const(), name.as_ptr());
        assert_eq!((empty.length, empty.maximum_length), (0, 0));
        assert!(empty.buffer.is_null());
        // SAFETY: a terminated empty string.
        let blank = unsafe { init_unicode_string([0u16].as_ptr()) };
        assert_eq!((blank.length, blank.maximum_length), (0, 2));
        for (units, length, maximum_length) in [
            (0x7FFE, 0xFFFC, 0xFFFE),
            (0x7FFF, 0xFFFE, 0),
            (0x8000, 0, 2),
            (0x8001, 2, 4),
        ] {
            let long = std::vec![b'x' as u16; units]
                .into_iter()
                .chain([0])
                .collect::<std::vec::Vec<u16>>();
            // SAFETY: as above.
            let long = unsafe { init_unicode_string(long.as_ptr()) };
            assert_eq!(
                (long.length, long.maximum_length),
                (length, maximum_length),
                "{units:#x} units"
            );
        }
        // At an odd address.
        let bytes = [0u8, b'a', 0, b'b', 0, 0, 0];
        // SAFETY: "ab" as UTF-16 from an odd address, terminated.
        let odd = unsafe { init_unicode_string(bytes[1..].as_ptr().cast()) };
        assert_eq!((odd.length, odd.maximum_length), (4, 6));
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

    /// RtlUpcaseUnicodeString upper-cases each unit as LCMapString does: into a buffer of the
    /// caller's (STATUS_BUFFER_OVERFLOW, untouched, when it is short), onto the heap, and in
    /// place; it adds no terminator.
    #[test]
    fn a_unicode_string_upper_cases() {
        let mut text: Vec<u16> = "Caf\u{E9} \u{FF}x1".encode_utf16().collect();
        let upper: Vec<u16> = "CAF\u{C9} \u{178}X1".encode_utf16().collect();
        let source = UnicodeString {
            length: (2 * text.len()) as u16,
            maximum_length: (2 * text.len()) as u16,
            buffer: text.as_mut_ptr(),
        };
        let refuse = |_| -> *mut u8 { panic!("no allocation") };
        let mut out = [0xFFFFu16; 9];
        // SAFETY: the strings above, their buffers holding their lengths and rooms.
        unsafe {
            let mut short = empty_unicode(&mut out[..7]);
            assert_eq!(
                upcase_unicode_string(&mut short, &source, false, refuse),
                STATUS_BUFFER_OVERFLOW
            );
            assert_eq!(out, [0xFFFF; 9]);
            let mut destination = empty_unicode(&mut out[..8]);
            assert_eq!(
                upcase_unicode_string(&mut destination, &source, false, refuse),
                STATUS_SUCCESS
            );
            assert_eq!(destination.length, 16);
            assert_eq!(out[..8], upper[..]);
            assert_eq!(out[8], 0xFFFF, "no terminator");
            let mut block = [0u16; 8];
            let mut allocated = UnicodeString::empty();
            let status = upcase_unicode_string(&mut allocated, &source, true, |size| {
                assert_eq!(size, 16);
                block.as_mut_ptr() as *mut u8
            });
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!((allocated.length, allocated.maximum_length), (16, 16));
            assert_eq!(block[..], upper[..]);
            let mut in_place = source;
            assert_eq!(
                upcase_unicode_string(&mut in_place, &source, false, refuse),
                STATUS_SUCCESS
            );
        }
        assert_eq!(text, upper);
    }

    /// RtlUnicodeStringToInteger reads the digits of its base up to the first that is not one (no
    /// digits is zero); base 0 reads a prefix; another base is refused.
    #[test]
    fn a_unicode_string_reads_as_a_number() {
        let read = |text: &str, base| {
            let units: Vec<u16> = text.encode_utf16().collect();
            unicode_string_to_integer(&units, base)
        };
        for (text, base, value) in [
            ("101", 10, 101u32),
            ("0101", 10, 101),
            ("abc", 10, 0),
            ("", 10, 0),
            ("1a", 10, 1),
            ("70000", 10, 70000),
            (" -2", 10, u32::MAX - 1),
            ("+7", 10, 7),
            ("0x10", 10, 0),
            ("0x10", 0, 16),
            ("0X1f", 0, 31),
            ("ff", 16, 255),
            ("0o17", 0, 15),
            ("0b101", 0, 5),
            ("101", 2, 5),
            ("4294967296", 10, 0),
        ] {
            assert_eq!(read(text, base), Ok(value), "{text} in base {base}");
        }
        assert_eq!(read("10", 7), Err(STATUS_INVALID_PARAMETER));
    }

    /// A short string converts on the stack, a long one through the heap: with its terminator
    /// for `with_wide_z`, without it for `with_wide`; the stack's last length and the heap's
    /// first, and the empty string.
    #[test]
    fn narrow_strings_convert_to_wide() {
        use crate::heap::tests::HostHeap;
        let wide =
            with_wide_z::<HostHeap, _>(b"Hi\x80", multi_byte_to_unicode, |units| units.to_vec());
        assert_eq!(wide, Some(std::vec![0x48, 0x69, 0x20AC, 0]));
        let wide =
            with_wide::<HostHeap, _>(b"Hi\x80", multi_byte_to_unicode, |units| units.to_vec());
        assert_eq!(wide, Some(std::vec![0x48, 0x69, 0x20AC]));
        for length in [STACK_UNITS - 1, STACK_UNITS, 1000] {
            let text = std::vec![b'y'; length];
            let wide =
                with_wide_z::<HostHeap, _>(&text, multi_byte_to_unicode, |units| units.to_vec())
                    .unwrap();
            assert_eq!(wide.len(), length + 1);
            assert_eq!(wide[length], 0);
            assert!(wide[..length].iter().all(|&unit| unit == 0x79));
            let len = with_wide::<HostHeap, _>(&text, multi_byte_to_unicode, |units| units.len());
            assert_eq!(len, Some(length));
        }
        assert_eq!(
            with_wide::<HostHeap, _>(b"", multi_byte_to_unicode, |units| units.len()),
            Some(0)
        );
        assert_eq!(
            with_wide_z::<HostHeap, _>(b"", multi_byte_to_unicode, |units| units.to_vec()),
            Some(std::vec![0])
        );
    }
}
