//! The process parameters: RTL_USER_PROCESS_PARAMETERS as NT 5.0 lays it out on x86, the block the
//! PEB's ProcessParameters points at (the standard handles, the current directory, the image's
//! path, the command line, the environment, the startup values), one type for every side: the
//! kernel writes a process's first block with it (`ProcessParameters<u32>`, its pointers 32-bit on
//! any host), ntdll builds one for a new process with it (`ProcessParameters<usize>`, the same
//! layout on the DLLs' target).
//!
//! A block is one allocation: the structure, then its strings' buffers. Laid out by
//! RtlCreateProcessParameters ([`lay_out`]) it is denormalized: each string's buffer is its offset
//! from the block's start, so the block can be copied anywhere (kernel32 writes it into the new
//! process); normalizing it ([`ProcessParameters::normalize`], RTL_USER_PROC_PARAMS_NORMALIZED in
//! its flags) makes the offsets addresses again, as the process that owns it reads them.

use core::mem::size_of;

use crate::pod::Pod;

/// RTL_USER_PROC_PARAMS_NORMALIZED: the strings' buffers are addresses, not offsets.
pub const NORMALIZED: u32 = 1;

/// The current directory's room in bytes: MAX_PATH characters, so that setting it never moves its
/// buffer.
pub const CURRENT_DIRECTORY_ROOM: usize = 2 * 260;

/// A UNICODE_STRING with a pointer of type `P` ([`crate::nt::UnicodeString`]): its buffer an
/// address, or an offset in a denormalized block; zero for none.
pub type CountedString<P> = crate::nt::UnicodeString<P>;

/// CURDIR: the current directory's DOS path and its handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CurrentDirectory<P> {
    pub dos_path: CountedString<P>,
    pub handle: P,
}

/// RTL_DRIVE_LETTER_CURDIR: a drive's current directory, as the block's table keeps them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriveDirectory<P> {
    pub flags: u16,
    pub length: u16,
    pub time_stamp: u32,
    pub dos_path: CountedString<P>,
}

/// RTL_USER_PROCESS_PARAMETERS, NT 5.0's.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessParameters<P> {
    /// The block's size in bytes, its strings included, and the bytes it uses.
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: P,
    pub console_flags: u32,
    pub standard_input: P,
    pub standard_output: P,
    pub standard_error: P,
    pub current_directory: CurrentDirectory<P>,
    pub dll_path: CountedString<P>,
    pub image_path_name: CountedString<P>,
    pub command_line: CountedString<P>,
    /// The environment block: an address in either form (it is not one of the block's strings).
    pub environment: P,
    /// The window's starting place and size, the console's character counts and fill, the
    /// STARTF_* flags and the SW_* value: what GetStartupInfo reports.
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: CountedString<P>,
    pub desktop_info: CountedString<P>,
    pub shell_info: CountedString<P>,
    /// The C runtime's inherited-descriptor block (STARTUPINFO's cbReserved2 and lpReserved2).
    pub runtime_data: CountedString<P>,
    pub current_directories: [DriveDirectory<P>; 32],
}

const _: () = {
    // NT 5.0's layout, with 32-bit pointers on any host.
    type Layout = ProcessParameters<u32>;
    assert!(size_of::<Layout>() == 0x290);
    assert!(core::mem::offset_of!(Layout, console_flags) == 0x14);
    assert!(core::mem::offset_of!(Layout, standard_input) == 0x18);
    assert!(core::mem::offset_of!(Layout, current_directory) == 0x24);
    assert!(core::mem::offset_of!(Layout, dll_path) == 0x30);
    assert!(core::mem::offset_of!(Layout, image_path_name) == 0x38);
    assert!(core::mem::offset_of!(Layout, command_line) == 0x40);
    assert!(core::mem::offset_of!(Layout, environment) == 0x48);
    assert!(core::mem::offset_of!(Layout, show_window_flags) == 0x6C);
    assert!(core::mem::offset_of!(Layout, window_title) == 0x70);
    assert!(core::mem::offset_of!(Layout, runtime_data) == 0x88);
    assert!(core::mem::offset_of!(Layout, current_directories) == 0x90);
};

// SAFETY: integers and their arrays: u32 and u16 fields laid out without padding (the u16 pairs
// fill whole dwords), as the layout asserts above pin.
unsafe impl Pod for ProcessParameters<u32> {}

impl<P> ProcessParameters<P> {
    /// The block's strings, in the order the block holds their buffers.
    fn strings_mut(&mut self) -> [&mut CountedString<P>; 8] {
        [
            &mut self.current_directory.dos_path,
            &mut self.dll_path,
            &mut self.image_path_name,
            &mut self.command_line,
            &mut self.window_title,
            &mut self.desktop_info,
            &mut self.shell_info,
            &mut self.runtime_data,
        ]
    }
}

impl ProcessParameters<usize> {
    /// RtlNormalizeProcessParams' work for the block at `base`: each string's offset made its
    /// address (a string without a buffer keeps none), the flag set; a normalized block is left as
    /// it is.
    pub fn normalize(&mut self, base: usize) {
        if self.flags & NORMALIZED != 0 {
            return;
        }
        for string in self.strings_mut() {
            if string.buffer != 0 {
                string.buffer += base;
            }
        }
        self.flags |= NORMALIZED;
    }

    /// RtlDeNormalizeProcessParams' work for the block at `base`: each string's address made its
    /// offset from the block, the flag cleared; a denormalized block is left as it is.
    pub fn denormalize(&mut self, base: usize) {
        if self.flags & NORMALIZED == 0 {
            return;
        }
        for string in self.strings_mut() {
            if string.buffer != 0 {
                string.buffer -= base;
            }
        }
        self.flags &= !NORMALIZED;
    }
}

/// The strings a new block holds, each a UNICODE_STRING's bytes (its Length). The four optional
/// ones are none when the caller gave none.
#[derive(Clone, Copy, Debug, Default)]
pub struct Strings<'a> {
    pub current_directory: &'a [u8],
    pub dll_path: &'a [u8],
    pub image_path_name: &'a [u8],
    pub command_line: &'a [u8],
    pub window_title: Option<&'a [u8]>,
    pub desktop_info: Option<&'a [u8]>,
    pub shell_info: Option<&'a [u8]>,
    pub runtime_data: Option<&'a [u8]>,
}

/// A string's room in the block: its bytes and a terminator, at least `minimum`, rounded up to a
/// dword (the next buffer stays aligned); none for a string not given.
fn room(bytes: Option<&[u8]>, minimum: usize) -> usize {
    bytes.map_or(0, |bytes| {
        (bytes.len() + 2).max(minimum).next_multiple_of(4)
    })
}

impl Strings<'_> {
    /// The strings in the block's order, with the least room each takes.
    fn in_order(&self) -> [(Option<&[u8]>, usize); 8] {
        [
            (Some(self.current_directory), CURRENT_DIRECTORY_ROOM),
            (Some(self.dll_path), 0),
            (Some(self.image_path_name), 0),
            (Some(self.command_line), 0),
            (self.window_title, 0),
            (self.desktop_info, 0),
            (self.shell_info, 0),
            (self.runtime_data, 0),
        ]
    }

    /// The bytes the strings' buffers take after the structure.
    pub fn room(&self) -> usize {
        self.in_order()
            .iter()
            .map(|&(bytes, minimum)| room(bytes, minimum))
            .sum()
    }

    /// The whole block's size: the structure and the strings' buffers.
    pub fn block_size(&self) -> usize {
        size_of::<ProcessParameters<usize>>() + self.room()
    }
}

/// RtlCreateProcessParameters' layout: the block's structure in `header` and its strings' buffers
/// in `tail` (the [`Strings::room`] bytes right after the structure, zeroed), denormalized. Each
/// string given is copied with a terminator into a room of its own, in the structure's order (the
/// current directory's of MAX_PATH characters); a string not given has no buffer. The block's
/// lengths are its size; the environment is recorded as given; everything else is zero (the
/// caller sets the handles and the startup values).
pub fn lay_out(
    header: &mut ProcessParameters<usize>,
    tail: &mut [u8],
    strings: &Strings,
    environment: usize,
) {
    let size = (size_of::<ProcessParameters<usize>>() + tail.len()) as u32;
    *header = ProcessParameters {
        maximum_length: size,
        length: size,
        environment,
        ..ProcessParameters::default()
    };
    let mut at = 0;
    for ((bytes, minimum), string) in strings.in_order().into_iter().zip(header.strings_mut()) {
        let Some(bytes) = bytes else {
            continue;
        };
        let room = room(Some(bytes), minimum);
        tail[at..at + bytes.len()].copy_from_slice(bytes);
        tail[at + bytes.len()..at + room].fill(0);
        *string = CountedString {
            length: bytes.len() as u16,
            maximum_length: (bytes.len() + 2).max(minimum) as u16,
            buffer: size_of::<ProcessParameters<usize>>() + at,
        };
        at += room;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A string's bytes in a laid-out block, by its offset (the tail follows the structure).
    fn at<'a>(tail: &'a [u8], string: &CountedString<usize>) -> &'a [u8] {
        let start = string.buffer - size_of::<ProcessParameters<usize>>();
        &tail[start..start + string.length as usize]
    }

    /// The strings follow the structure in its order, each terminated in a dword-rounded room (the
    /// current directory's MAX_PATH characters), the offsets from the block's start; the optional
    /// ones not given have no buffer; the lengths are the block's size; the block is denormalized.
    #[test]
    fn the_block_holds_its_strings_after_the_structure() {
        let (directory, dll, image, command, title) = (
            wide("C:\\CORPUS\\"),
            wide("C:\\WINNT\\system32"),
            wide("C:\\CORPUS\\SPAWNKID.EXE"),
            wide("spawnkid args"),
            wide("a title"),
        );
        let strings = Strings {
            current_directory: &directory,
            dll_path: &dll,
            image_path_name: &image,
            command_line: &command,
            window_title: Some(&title),
            desktop_info: Some(&[]),
            shell_info: None,
            runtime_data: Some(&[1, 2, 3]),
        };
        let header_size = size_of::<ProcessParameters<usize>>();
        assert_eq!(
            strings.room(),
            520 + 36 + 48 + 28 + 16 + 4 + 8,
            "rooms of the strings and their terminators, dword-rounded"
        );
        let mut header = ProcessParameters::default();
        let mut tail = vec![0xEEu8; strings.room()];
        lay_out(&mut header, &mut tail, &strings, 0x0001_0000);
        assert_eq!(header.flags & NORMALIZED, 0);
        assert_eq!(header.length as usize, header_size + tail.len());
        assert_eq!(header.maximum_length, header.length);
        assert_eq!(header.environment, 0x0001_0000);
        let directory_string = header.current_directory.dos_path;
        assert_eq!(
            (directory_string.buffer, directory_string.maximum_length),
            (header_size, 520)
        );
        assert_eq!(header.dll_path.buffer, header_size + 520);
        assert_eq!(header.image_path_name.buffer, header_size + 520 + 36);
        assert_eq!(
            (
                header.image_path_name.length,
                header.image_path_name.maximum_length
            ),
            (44, 46)
        );
        assert_eq!(header.command_line.buffer, header_size + 520 + 36 + 48);
        for (string, expected) in [
            (directory_string, &directory),
            (header.dll_path, &dll),
            (header.image_path_name, &image),
            (header.command_line, &command),
            (header.window_title, &title),
        ] {
            assert_eq!(at(&tail, &string), &expected[..]);
            let end = string.buffer - header_size + string.length as usize;
            assert_eq!(tail[end..end + 2], [0, 0], "terminated");
        }
        assert_eq!(
            (
                header.desktop_info.length,
                header.desktop_info.maximum_length
            ),
            (0, 2)
        );
        assert_ne!(header.desktop_info.buffer, 0, "given empty: a buffer");
        assert_eq!(header.shell_info, CountedString::default(), "not given");
        assert_eq!(at(&tail, &header.runtime_data), [1, 2, 3]);
        assert_eq!(
            header.standard_input + header.standard_output + header.standard_error,
            0
        );
        assert_eq!(header.current_directory.handle, 0);
    }

    /// Normalizing adds the block's base to each buffer (none stays none), denormalizing takes it
    /// back; each does nothing to a block already in its form.
    #[test]
    fn normalizing_turns_offsets_into_addresses_and_back() {
        let image = wide("C:\\A.EXE");
        let strings = Strings {
            image_path_name: &image,
            command_line: &image,
            ..Strings::default()
        };
        let mut header = ProcessParameters::default();
        let mut tail = vec![0u8; strings.room()];
        lay_out(&mut header, &mut tail, &strings, 0);
        let denormalized = header;
        header.normalize(0x0002_0000);
        assert_eq!(header.flags, NORMALIZED);
        assert_eq!(
            header.image_path_name.buffer,
            denormalized.image_path_name.buffer + 0x0002_0000
        );
        assert_eq!(header.window_title.buffer, 0, "no buffer stays none");
        let normalized = header;
        header.normalize(0x0002_0000);
        assert_eq!(header, normalized, "already normalized");
        header.denormalize(0x0002_0000);
        assert_eq!(header, denormalized);
        header.denormalize(0x0002_0000);
        assert_eq!(header, denormalized, "already denormalized");
    }

    /// Only the eight strings move: the environment (an address in either form), the handles and
    /// the drive table are left as they are, as is a block's lengths.
    #[test]
    fn normalizing_moves_only_the_strings() {
        let image = wide("C:\\A.EXE");
        let strings = Strings {
            image_path_name: &image,
            command_line: &image,
            ..Strings::default()
        };
        let mut header = ProcessParameters::default();
        let mut tail = vec![0u8; strings.room()];
        lay_out(&mut header, &mut tail, &strings, 0x0001_0000);
        header.console_handle = 0x10;
        header.standard_output = 0x7;
        header.current_directory.handle = 0x24;
        header.current_directories[2].dos_path.buffer = 0x30;
        let before = header;
        header.normalize(0x0002_0000);
        assert_eq!(
            (
                header.environment,
                header.console_handle,
                header.standard_output
            ),
            (0x0001_0000, 0x10, 0x7)
        );
        assert_eq!(header.current_directory.handle, 0x24);
        assert_eq!(header.current_directories, before.current_directories);
        assert_eq!(
            (header.length, header.maximum_length),
            (before.length, before.maximum_length)
        );
        assert_eq!(
            header.current_directory.dos_path.buffer,
            before.current_directory.dos_path.buffer + 0x0002_0000
        );
    }

    /// A current directory longer than MAX_PATH gets the room it needs.
    #[test]
    fn a_long_current_directory_gets_its_room() {
        let long = vec![b'a'; 600];
        let strings = Strings {
            current_directory: &long,
            ..Strings::default()
        };
        assert_eq!(strings.room(), 604 + 3 * 4);
        let mut header = ProcessParameters::default();
        let mut tail = vec![0u8; strings.room()];
        lay_out(&mut header, &mut tail, &strings, 0);
        assert_eq!(header.current_directory.dos_path.maximum_length, 602);
        assert_eq!(
            header.dll_path.buffer,
            size_of::<ProcessParameters<usize>>() + 604
        );
    }
}
