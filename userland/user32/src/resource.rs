//! The string tables: LoadStringA and LoadStringW, as Windows 2000's user32 reads a module's
//! strings, through kernel32's FindResourceExW, LoadResource, SizeofResource and LockResource
//! ([`imports::find_resource`], [`imports::resource_data`]).
//!
//! A module's string table is a set of RT_STRING resources of 16 strings each, as the resource
//! compiler lays a STRINGTABLE out: string `id` is string `id % 16` of the block numbered
//! `id / 16 + 1`. A block's data is its 16 strings in order, each a WORD count of UTF-16 units and
//! those units, with no terminator; an id the table does not hold has a count of 0 in its block.
//! The block is asked for in language 0, which kernel32 and ntdll search as they do for
//! FindResource.
//!
//! What a call answers, as the real machine's capture shows it:
//!
//! - a string is copied as far as the buffer holds it with a NUL after it (nBufferMax - 1
//!   characters at most; LoadStringA's converted to the ANSI code page), and the characters
//!   copied are the answer, the last error untouched;
//! - an id with no string in its block is the empty string: 0, the NUL written;
//! - an id with no block is the empty string too, with FindResourceExW's last error
//!   (ERROR_RESOURCE_NAME_NOT_FOUND);
//! - LoadStringW with an nBufferMax of 0 writes the string's address in the module's image (where
//!   it is not terminated) into the buffer, as a pointer's place, and answers its length;
//! - LoadStringW with an nBufferMax of 1 writes nothing and answers 0;
//! - LoadStringA with an nBufferMax of 0 writes nothing and answers -1.

use rtl::edge::{Out, OutBuf};

use crate::class::ERROR_NOACCESS;
use crate::imports;
use crate::{caller_bytes_mut, failed};

/// RT_STRING: the resource type of a string table's blocks.
const RT_STRING: u16 = 6;

/// The language a block is asked for: LANG_NEUTRAL with SUBLANG_NEUTRAL, the search FindResource
/// makes.
const ANY_LANGUAGE: u16 = 0;

/// The units LoadStringA converts at a time, on the stack.
const CHUNK: usize = 128;

/// A string of a module's table: its UTF-16 units where its block's data holds them (in the
/// module's image: two bytes each, little-endian, at any alignment).
#[derive(Clone, Copy)]
struct Text(&'static [u8]);

impl Text {
    /// The string of no characters.
    const EMPTY: Text = Text(&[]);

    /// Its length in characters.
    fn len(&self) -> usize {
        self.0.len() / 2
    }

    /// Its characters.
    fn units(&self) -> impl Iterator<Item = u16> + 'static {
        let (units, _) = self.0.as_chunks::<2>();
        units.iter().map(|&unit| u16::from_le_bytes(unit))
    }

    /// Its address, in the module's image.
    fn address(&self) -> usize {
        self.0.as_ptr() as usize
    }
}

/// String `index` (0 to 15) of a block's data: its units' bytes. A block cut short holds what its
/// data holds: a count past the data's end is cut there, a missing count is an empty string at
/// the end.
fn string_in_block(block: &[u8], index: usize) -> &[u8] {
    let mut at = 0;
    for position in 0..=index {
        let Some(count) = block.get(at..at + 2) else {
            return &block[block.len()..];
        };
        let units = u16::from_le_bytes([count[0], count[1]]) as usize;
        let start = at + 2;
        let end = (start + 2 * units).min(block.len());
        if position == index {
            return &block[start..end];
        }
        at = end;
    }
    unreachable!("the loop returns at `index`")
}

/// String `id` of the module `instance`'s table (NULL: the program's), by its low word (a
/// resource's number is a WORD): none, with kernel32's last error, when the module holds no block
/// for it; the empty string when its block holds none.
fn find_string(instance: usize, id: u32) -> Option<Text> {
    let id = id as u16;
    let found = imports::find_resource(instance, RT_STRING, (id >> 4) + 1, ANY_LANGUAGE)?;
    let block = imports::resource_data(instance, found)?;
    Some(Text(string_in_block(block, usize::from(id & 15))))
}

/// LoadStringW's buffer, as its nBufferMax makes it.
enum WideBuffer<'a> {
    /// nBufferMax 0: the place of a pointer, which receives the string's address.
    Pointer(Out<'a, usize>),
    /// A buffer of nBufferMax characters (none for a negative one).
    Units(OutBuf<'a, u16>),
}

/// LoadStringW: string `id` of the module `instance` (NULL: the program's) into the buffer, or
/// its address into the pointer an nBufferMax of 0 makes the buffer (see the module's
/// description); the characters copied, or the string's length for an nBufferMax of 0.
///
/// # Safety
///
/// `buffer` is the caller's buffer of `max` characters, or with `max` 0 the place of a pointer,
/// as for the platform's.
#[unsafe(export_name = "f2k_export_LoadStringW")]
pub unsafe extern "system" fn load_string_w(
    instance: usize,
    id: u32,
    buffer: *mut u16,
    max: i32,
) -> i32 {
    let buffer = if max == 0 {
        // SAFETY: the caller's contract: with no length, the buffer is a pointer's place.
        WideBuffer::Pointer(unsafe { Out::new(buffer.cast()) })
    } else {
        // SAFETY: the caller's contract: `max` characters.
        WideBuffer::Units(unsafe { OutBuf::new(buffer, max.max(0) as usize) })
    };
    load_wide(instance, id, buffer)
}

/// LoadStringW's core, into its buffer.
fn load_wide(instance: usize, id: u32, buffer: WideBuffer<'_>) -> i32 {
    let text = find_string(instance, id);
    match buffer {
        WideBuffer::Pointer(mut place) => text.map_or(0, |text| {
            place.set(text.address());
            text.len() as i32
        }),
        WideBuffer::Units(mut units) => {
            // No room for a character beside the NUL: nothing is written.
            let room = units.len().saturating_sub(1);
            if room == 0 {
                return 0;
            }
            let mut copied = 0;
            for unit in text.unwrap_or(Text::EMPTY).units().take(room) {
                units.set(copied, unit);
                copied += 1;
            }
            units.set(copied, 0);
            copied as i32
        }
    }
}

/// LoadStringA: string `id` of the module `instance` (NULL: the program's), converted to the ANSI
/// code page (through ntdll's RtlUnicodeToMultiByteN, as user32's other A calls convert), at most
/// `max - 1` bytes and a NUL; the bytes copied, -1 for an nBufferMax of 0 (see the module's
/// description).
///
/// # Safety
///
/// The caller's buffer of `max` bytes, as for the platform's.
#[unsafe(export_name = "f2k_export_LoadStringA")]
pub unsafe extern "system" fn load_string_a(
    instance: usize,
    id: u32,
    buffer: *mut u8,
    max: i32,
) -> i32 {
    // SAFETY: the caller's buffer.
    let buffer = unsafe { caller_bytes_mut(buffer, max.max(0) as usize) };
    load_narrow(instance, id, buffer)
}

/// LoadStringA's core, into the caller's buffer (none: one the call cannot reach).
fn load_narrow(instance: usize, id: u32, buffer: Option<&mut [u8]>) -> i32 {
    let text = find_string(instance, id);
    let Some(buffer) = buffer else {
        return failed(ERROR_NOACCESS).unwrap_or(0);
    };
    let Some(room) = buffer.len().checked_sub(1) else {
        return -1;
    };
    let written = narrow_into(&mut buffer[..room], text.unwrap_or(Text::EMPTY));
    buffer[written] = 0;
    written as i32
}

/// As much of `text` as `out` holds, converted to the ANSI code page a chunk at a time (copied out
/// of the image, where they may lie at any alignment, into units ntdll takes): the bytes written.
/// F2K's ANSI code page, 1252, is single-byte: a character is a byte, so the units the room takes
/// are all the conversion needs, and a chunk's bytes follow the last chunk's.
fn narrow_into(out: &mut [u8], text: Text) -> usize {
    let mut units = text.units().take(out.len());
    let mut chunk = [0u16; CHUNK];
    let mut written = 0;
    loop {
        let mut taken = 0;
        for (slot, unit) in chunk.iter_mut().zip(units.by_ref()) {
            *slot = unit;
            taken += 1;
        }
        if taken == 0 {
            return written;
        }
        written += imports::unicode_to_multi_byte(&mut out[written..], &chunk[..taken]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{add_resource, LAST_ERROR, PROGRAM, RESOURCE_LANGUAGES};

    const UNSET: u32 = 0xF2F2_F2F2;

    /// The resource fixture's table: 1 "first string", 2 "second", 17 "seventeen", 100 "a longer
    /// string for the short buffers", in blocks 1, 2 and 7.
    const LONG: &str = "a longer string for the short buffers";

    /// A block's data: each (index, string) at its index, the others empty.
    fn block(strings: &[(usize, &str)]) -> std::vec::Vec<u8> {
        let mut data = std::vec::Vec::new();
        for index in 0..16 {
            let text = strings
                .iter()
                .find(|(at, _)| *at == index)
                .map_or("", |(_, text)| *text);
            let units: std::vec::Vec<u16> = text.encode_utf16().collect();
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for unit in units {
                data.extend_from_slice(&unit.to_le_bytes());
            }
        }
        data
    }

    /// The fixture's table in the program; the address of block 7's data.
    fn table() -> usize {
        add_resource(
            PROGRAM,
            RT_STRING,
            1,
            &block(&[(1, "first string"), (2, "second")]),
        );
        add_resource(PROGRAM, RT_STRING, 2, &block(&[(1, "seventeen")]));
        add_resource(PROGRAM, RT_STRING, 7, &block(&[(4, LONG)]))
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(UNSET));
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    /// LoadStringA into a buffer of '#' of `size` bytes (64 long): the answer, the last error,
    /// and the buffer.
    fn narrow(instance: usize, id: u32, size: i32) -> (i32, u32, [u8; 64]) {
        let mut buffer = [b'#'; 64];
        arm();
        // SAFETY: the tests' own buffer, as long as the size says.
        let answer = unsafe { load_string_a(instance, id, buffer.as_mut_ptr(), size) };
        (answer, last_error(), buffer)
    }

    /// LoadStringW, likewise.
    fn wide(instance: usize, id: u32, size: i32) -> (i32, u32, [u16; 64]) {
        let mut buffer = [0x23u16; 64];
        arm();
        // SAFETY: the tests' own buffer, as long as the size says.
        let answer = unsafe { load_string_w(instance, id, buffer.as_mut_ptr(), size) };
        (answer, last_error(), buffer)
    }

    /// The text before the first NUL, and where the NUL is.
    fn text_of<T: Copy + Into<u32>>(buffer: &[T]) -> (std::string::String, Option<usize>) {
        let nul = buffer.iter().position(|&c| c.into() == 0);
        let text = buffer[..nul.unwrap_or(buffer.len())]
            .iter()
            .map(|&c| char::from_u32(c.into()).unwrap())
            .collect();
        (text, nul)
    }

    /// A block's strings by index; a block cut short holds what is there.
    #[test]
    fn strings_are_found_in_their_block() {
        let data = block(&[(0, "zero"), (3, "three"), (15, "last")]);
        assert_eq!(string_in_block(&data, 0), b"z\0e\0r\0o\0");
        assert_eq!(string_in_block(&data, 1), b"");
        assert_eq!(string_in_block(&data, 3), b"t\0h\0r\0e\0e\0");
        assert_eq!(string_in_block(&data, 15), b"l\0a\0s\0t\0");
        assert_eq!(string_in_block(&data[..5], 0), b"z\0e");
        assert_eq!(string_in_block(&data[..5], 1), b"");
        assert_eq!(string_in_block(&[], 4), b"");
    }

    /// LoadStringA as the capture shows it: the strings that fit, one cut to 7 bytes, a buffer
    /// of 1 holding only the NUL, one of 0 untouched with -1, an empty id and a missing block
    /// both empty (the second with 1814), and NULL for the program; the block asked for in
    /// language 0.
    ///
    /// Pins: user32.LoadStringA
    #[test]
    fn narrow_strings_load_as_the_capture_shows() {
        table();
        for (id, text) in [
            (1, "first string"),
            (2, "second"),
            (17, "seventeen"),
            (100, LONG),
        ] {
            let (answer, error, buffer) = narrow(PROGRAM, id, 64);
            assert_eq!(answer, text.len() as i32, "{id}");
            assert_eq!(error, UNSET);
            assert_eq!(text_of(&buffer), (text.into(), Some(text.len())));
        }
        let (answer, error, buffer) = narrow(PROGRAM, 100, 8);
        assert_eq!((answer, error), (7, UNSET));
        assert_eq!(text_of(&buffer), ("a longe".into(), Some(7)));
        assert_eq!(buffer[8], b'#');
        let (answer, error, buffer) = narrow(PROGRAM, 100, 1);
        assert_eq!((answer, error), (0, UNSET));
        assert_eq!((buffer[0], buffer[1]), (0, b'#'));
        let (answer, error, buffer) = narrow(PROGRAM, 100, 0);
        assert_eq!((answer, error), (-1, UNSET));
        assert!(buffer.iter().all(|&b| b == b'#'));
        let (answer, error, buffer) = narrow(PROGRAM, 3, 64);
        assert_eq!((answer, error, buffer[0], buffer[1]), (0, UNSET, 0, b'#'));
        let (answer, error, buffer) = narrow(PROGRAM, 500, 64);
        assert_eq!((answer, error, buffer[0], buffer[1]), (0, 1814, 0, b'#'));
        let (answer, _, buffer) = narrow(0, 1, 64);
        assert_eq!(answer, 12);
        assert_eq!(text_of(&buffer), ("first string".into(), Some(12)));
        assert!(RESOURCE_LANGUAGES.with(|languages| languages.borrow().iter().all(|&l| l == 0)));
    }

    /// LoadStringW as the capture shows it: as LoadStringA but a buffer of 1 untouched with 0,
    /// and a size of 0 handing back the string's address in its block and its length.
    ///
    /// Pins: user32.LoadStringW
    #[test]
    fn wide_strings_load_as_the_capture_shows() {
        let block_7 = table();
        for (id, text) in [
            (1, "first string"),
            (2, "second"),
            (17, "seventeen"),
            (100, LONG),
        ] {
            let (answer, error, buffer) = wide(PROGRAM, id, 64);
            assert_eq!(answer, text.len() as i32, "{id}");
            assert_eq!(error, UNSET);
            assert_eq!(text_of(&buffer), (text.into(), Some(text.len())));
        }
        let (answer, error, buffer) = wide(PROGRAM, 100, 8);
        assert_eq!((answer, error), (7, UNSET));
        assert_eq!(text_of(&buffer), ("a longe".into(), Some(7)));
        assert_eq!(buffer[8], 0x23);
        let (answer, error, buffer) = wide(PROGRAM, 100, 1);
        assert_eq!((answer, error), (0, UNSET));
        assert!(buffer.iter().all(|&u| u == 0x23));
        let (answer, error, buffer) = wide(PROGRAM, 3, 64);
        assert_eq!((answer, error, buffer[0], buffer[1]), (0, UNSET, 0, 0x23));
        let (answer, error, buffer) = wide(PROGRAM, 500, 64);
        assert_eq!((answer, error, buffer[0], buffer[1]), (0, 1814, 0, 0x23));
        let (answer, _, buffer) = wide(0, 1, 64);
        assert_eq!(answer, 12);
        assert_eq!(text_of(&buffer), ("first string".into(), Some(12)));

        // Block 7 holds strings 96 to 99 empty (a count each) before 100's count.
        let mut place = 0usize;
        arm();
        // SAFETY: a pointer's place of the tests' own, as an nBufferMax of 0 takes it.
        let answer = unsafe { load_string_w(PROGRAM, 100, (&raw mut place).cast(), 0) };
        assert_eq!((answer, last_error()), (37, UNSET));
        assert_eq!(place, block_7 + 4 * 2 + 2);
    }

    /// A string longer than a chunk converts whole, and cut at any length.
    #[test]
    fn long_strings_convert_in_chunks() {
        let long: std::string::String = (0..300).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        add_resource(PROGRAM, RT_STRING, 1, &block(&[(0, &long)]));
        let mut buffer = [b'#'; 400];
        // SAFETY: the tests' own buffer.
        let answer = unsafe { load_string_a(0, 0, buffer.as_mut_ptr(), 400) };
        assert_eq!(answer, 300);
        assert_eq!(&buffer[..300], long.as_bytes());
        assert_eq!((buffer[300], buffer[301]), (0, b'#'));
        let mut buffer = [b'#'; 400];
        // SAFETY: as above, 200 bytes of it.
        let answer = unsafe { load_string_a(0, 0, buffer.as_mut_ptr(), 200) };
        assert_eq!(answer, 199);
        assert_eq!(&buffer[..199], &long.as_bytes()[..199]);
        assert_eq!((buffer[199], buffer[200]), (0, b'#'));
    }
}
