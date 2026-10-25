//! pwd: the current directory, printed. The program (src/main.rs) asks kernel32 for it; this
//! library says what it prints and the codes it ends with.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// The exit code when the current directory cannot be read or printed (POSIX pwd's: greater than
/// zero; 2 stays free for a usage error, and 3 is the runtime's panic).
pub const FAILED: u32 = 1;

/// The line pwd prints: the directory as GetCurrentDirectoryW gives it (UTF-16: an unpaired
/// surrogate shows as U+FFFD), then CR LF.
pub struct Line<'a>(pub &'a [u16]);

impl fmt::Display for Line<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in char::decode_utf16(self.0.iter().copied()) {
            fmt::Write::write_char(f, character.unwrap_or(char::REPLACEMENT_CHARACTER))?;
        }
        f.write_str("\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn the_directory_then_crlf() {
        let directory = wide("C:\\WINNT\\system32");
        assert_eq!(Line(&directory).to_string(), "C:\\WINNT\\system32\r\n");
    }

    #[test]
    fn a_root_keeps_its_separator() {
        assert_eq!(Line(&wide("C:\\")).to_string(), "C:\\\r\n");
    }

    #[test]
    fn characters_beyond_ascii_and_the_basic_plane() {
        let directory = wide("C:\\Données\\\u{1F4C1}");
        assert_eq!(Line(&directory).to_string(), "C:\\Données\\\u{1F4C1}\r\n");
    }

    #[test]
    fn an_unpaired_surrogate_shows_as_the_replacement_character() {
        let directory = [u16::from(b'C'), u16::from(b':'), u16::from(b'\\'), 0xD800];
        assert_eq!(Line(&directory).to_string(), "C:\\\u{FFFD}\r\n");
    }
}
