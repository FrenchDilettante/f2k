//! A command line to start a program with: CreateProcess reads it to its terminator and may write
//! into it, so it is a writable buffer that always holds one.

/// A NUL-terminated command line in a writable buffer of the caller's: what CreateProcessA takes.
/// Made only by [`CommandLine::new`], which writes the terminator, so the system reads no further
/// than the buffer.
pub struct CommandLine<'a> {
    buffer: &'a mut [u8],
}

impl<'a> CommandLine<'a> {
    /// `text` and its terminator in `buffer`; none when they do not fit or `text` holds a NUL
    /// itself (the command line would end there).
    pub fn new(buffer: &'a mut [u8], text: &[u8]) -> Option<Self> {
        if text.contains(&0) {
            return None;
        }
        let line = buffer.get_mut(..text.len() + 1)?;
        line[..text.len()].copy_from_slice(text);
        line[text.len()] = 0;
        Some(CommandLine { buffer: line })
    }

    /// The command line's text, its terminator left out.
    pub fn text(&self) -> &[u8] {
        &self.buffer[..self.buffer.len() - 1]
    }

    /// The buffer's address, for CreateProcessA: NUL-terminated, writable, as long as the line.
    #[cfg_attr(not(all(target_arch = "x86", target_os = "windows")), allow(dead_code))]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_is_terminated_in_its_buffer() {
        let mut buffer = [0xFFu8; 8];
        let line = CommandLine::new(&mut buffer, b"a.exe x").unwrap();
        assert_eq!(line.text(), b"a.exe x");
        assert_eq!(buffer, *b"a.exe x\0");
    }

    #[test]
    fn a_line_without_room_for_its_terminator_is_refused() {
        let mut buffer = [0u8; 7];
        assert!(CommandLine::new(&mut buffer, b"a.exe x").is_none());
        assert!(CommandLine::new(&mut buffer, b"a.exe").is_some());
        assert!(CommandLine::new(&mut buffer, b"a\0b").is_none());
        assert!(CommandLine::new(&mut [], b"").is_none());
    }
}
