//! Batch files: their arguments (`%0` to `%9`, `%*`), their lines as read from the file, and
//! `exit`'s forms.

use crate::{is_blank, skip_blanks, trim_blanks, EQUALS, QUOTE};

/// The calls a batch may nest (`call`, or a batch run from another): past it, the shell stops
/// every batch, as Windows' cmd does once its stack runs out.
pub const DEPTH: usize = 32;

/// What the shell prints when batches nest past [`DEPTH`].
pub const RECURSION: &str = "****** B A T C H   R E C U R S I O N  exceeds STACK limits ******\r\n";

/// What the shell asks when Ctrl+C or Ctrl+Break interrupts a batch.
pub const TERMINATE: &str = "Terminate batch job (Y/N)? ";

/// The bytes a batch file is read in at once.
pub const CHUNK: usize = 512;

/// Whether `unit` separates a batch's arguments: a blank, `,`, `;` or `=`.
fn separates(unit: u16) -> bool {
    is_blank(unit) || unit == u16::from(b',') || unit == u16::from(b';') || unit == EQUALS
}

/// `arguments` (the batch's name as typed, then what followed it on its line) from its first
/// argument on: its leading separators skipped.
fn skip_separators(arguments: &[u16]) -> &[u16] {
    let start = arguments
        .iter()
        .position(|&unit| !separates(unit))
        .unwrap_or(arguments.len());
    &arguments[start..]
}

/// `text`'s first argument and what follows it: an argument runs to a separator outside quotes,
/// its quotes kept.
fn split_argument(text: &[u16]) -> (&[u16], &[u16]) {
    let text = skip_separators(text);
    let mut quoted = false;
    let end = text
        .iter()
        .position(|&unit| {
            if unit == QUOTE {
                quoted = !quoted;
            }
            !quoted && separates(unit)
        })
        .unwrap_or(text.len());
    text.split_at(end)
}

/// The batch's argument `n` (`%0` its name as typed, `%1` to `%9` the arguments after it), quotes
/// kept: None when there are fewer.
pub fn argument(arguments: &[u16], n: usize) -> Option<&[u16]> {
    let mut rest = arguments;
    for _ in 0..n {
        rest = split_argument(rest).1;
    }
    let (argument, _) = split_argument(rest);
    (!argument.is_empty()).then_some(argument)
}

/// `%*`: everything after the name, as it was typed, the blanks after the name left out (the
/// separators after them kept: `x ,;a b` gives `,;a b`).
pub fn all(arguments: &[u16]) -> &[u16] {
    skip_blanks(split_argument(arguments).1)
}

/// An argument without the quotes around it (`%~1`): a leading quote goes, and a trailing one.
pub fn unquote(argument: &[u16]) -> &[u16] {
    let argument = argument.strip_prefix(&[QUOTE]).unwrap_or(argument);
    argument.strip_suffix(&[QUOTE]).unwrap_or(argument)
}

/// A batch file's lines, read a chunk at a time: a line ends at LF, a CR before it dropped.
pub struct LineReader {
    chunk: [u8; CHUNK],
    start: usize,
    end: usize,
    done: bool,
    /// The bytes of the lines given so far, their line breaks included.
    offset: u64,
}

impl Default for LineReader {
    fn default() -> Self {
        LineReader {
            chunk: [0; CHUNK],
            start: 0,
            end: 0,
            done: false,
            offset: 0,
        }
    }
}

impl LineReader {
    /// Where the next line starts: the bytes of the lines given so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The next line, into `line`, without its line break: what does not fit is dropped. `read`
    /// fills a buffer from the file, zero at its end. None at the file's end; a last line without
    /// a line break is a line.
    pub fn next_line<'a, E>(
        &mut self,
        read: &mut dyn FnMut(&mut [u8]) -> Result<usize, E>,
        line: &'a mut [u8],
    ) -> Result<Option<&'a [u8]>, E> {
        let mut length = 0;
        let mut any = false;
        loop {
            if self.start == self.end {
                if self.done {
                    break;
                }
                self.start = 0;
                self.end = read(&mut self.chunk)?.min(CHUNK);
                if self.end == 0 {
                    self.done = true;
                    break;
                }
            }
            any = true;
            let available = &self.chunk[self.start..self.end];
            let (taken, ended) = match available.iter().position(|&byte| byte == b'\n') {
                Some(lf) => (&available[..lf], Some(lf + 1)),
                None => (available, None),
            };
            let room = line.len().saturating_sub(length).min(taken.len());
            line[length..length + room].copy_from_slice(&taken[..room]);
            length += room;
            match ended {
                Some(consumed) => {
                    self.start += consumed;
                    self.offset += consumed as u64;
                    if length > 0 && line[length - 1] == b'\r' {
                        length -= 1;
                    }
                    return Ok(Some(&line[..length]));
                }
                None => {
                    self.offset += taken.len() as u64;
                    self.start = self.end;
                }
            }
        }
        if !any {
            return Ok(None);
        }
        if length > 0 && line[length - 1] == b'\r' {
            length -= 1;
        }
        Ok(Some(&line[..length]))
    }

    /// The lines `read` gives read, from where the reader is, up to the label `label` (see
    /// [`crate::flow::label::names`]), each decoded into `units` by `decode` (its length, None
    /// when it cannot be): whether the label was found, the reader then at the line after it.
    pub fn seek_label<E>(
        &mut self,
        read: &mut dyn FnMut(&mut [u8]) -> Result<usize, E>,
        mut decode: impl FnMut(&[u8], &mut [u16]) -> Option<usize>,
        label: &[u16],
        bytes: &mut [u8],
        units: &mut [u16],
    ) -> bool {
        while let Ok(Some(line)) = self.next_line(read, bytes) {
            if let Some(length) = decode(line, units) {
                if crate::flow::label::names(&units[..length], label) {
                    return true;
                }
            }
        }
        false
    }
}

/// `exit`'s argument: `/B`, ending the batch rather than the shell, and the exit code.
#[derive(Debug, PartialEq, Eq)]
pub struct Exit {
    pub batch: bool,
    /// The code, read as C's `atoi` reads a number (a sign, then decimal digits, 0 without any):
    /// None when there is no argument.
    pub code: Option<u32>,
}

/// `exit`'s argument read.
pub fn exit(argument: &[u16]) -> Exit {
    let mut rest = trim_blanks(argument);
    let mut batch = false;
    if rest.len() >= 2
        && rest[0] == u16::from(b'/')
        && (rest[1] == u16::from(b'b') || rest[1] == u16::from(b'B'))
        && rest.get(2).is_none_or(|&unit| is_blank(unit))
    {
        batch = true;
        rest = skip_blanks(&rest[2..]);
    }
    if rest.is_empty() {
        return Exit { batch, code: None };
    }
    let (negative, digits) = match rest[0] {
        unit if unit == u16::from(b'-') => (true, &rest[1..]),
        unit if unit == u16::from(b'+') => (false, &rest[1..]),
        _ => (false, rest),
    };
    let mut value: u32 = 0;
    for &unit in digits {
        let Some(digit) = char::from_u32(u32::from(unit)).and_then(|c| c.to_digit(10)) else {
            break;
        };
        value = value.wrapping_mul(10).wrapping_add(digit);
    }
    Exit {
        batch,
        code: Some(if negative {
            value.wrapping_neg()
        } else {
            value
        }),
    }
}

/// Whether a line read from a batch file is skipped without being echoed: an empty one, or a
/// label (`:name`, which `::` comments are too).
pub fn skipped(line: &[u16]) -> bool {
    match trim_blanks(line).first() {
        None => true,
        Some(&unit) => unit == u16::from(b':'),
    }
}

/// What a batch file's line (expanded) echoes while echo is on, after the prompt (see
/// [`Echoed`]). None for a line a leading `@` hides, or one of blanks only.
pub fn echoed(line: &[u16]) -> Option<Echoed<'_>> {
    let line = skip_blanks(crate::without_break(line));
    match line.first() {
        Some(&unit) if unit != u16::from(b'@') && !crate::trim_blanks(line).is_empty() => {
            Some(Echoed(line))
        }
        _ => None,
    }
}

/// A batch file's line as echo shows it, its leading blanks dropped: a command with arguments
/// (text after its first word) is followed by a blank, as Windows 2000's cmd writes it
/// (`>echo with echo on `); a word alone is not (`>echo`).
pub struct Echoed<'a>(pub &'a [u16]);

impl core::fmt::Display for Echoed<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let word = self
            .0
            .iter()
            .position(|&unit| is_blank(unit))
            .unwrap_or(self.0.len());
        if skip_blanks(&self.0[word..]).is_empty() {
            crate::Text(&self.0[..word]).fmt(f)
        } else {
            write!(f, "{} ", Lines(self.0))
        }
    }
}

/// A block's text as echo shows it: its lines, as they were read, each but the last ended with
/// CR LF.
struct Lines<'a>(&'a [u16]);

impl core::fmt::Display for Lines<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, line) in self.0.split(|&unit| unit == crate::LF).enumerate() {
            if index > 0 {
                f.write_str("\r\n")?;
            }
            crate::Text(line).fmt(f)?;
        }
        Ok(())
    }
}

/// A batch file's line that holds one command, as echo shows it: the command with its redirections
/// taken out and its escapes resolved (see [`Echoed`]), then each redirection after a blank, as
/// cmd rebuilds them (`echo hi>out` echoes as `echo hi 1>out`).
pub struct EchoedCommand<'a> {
    /// The command's text, as [`crate::syntax::simple`] gives it.
    pub command: &'a [u16],
    pub redirections: &'a [crate::syntax::Redirection<'a>],
}

impl core::fmt::Display for EchoedCommand<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let command = skip_blanks(self.command);
        Echoed(command).fmt(f)?;
        let word = command
            .iter()
            .position(|&unit| is_blank(unit))
            .unwrap_or(command.len());
        // Echoed writes a blank after a command's arguments, none after a word alone.
        let mut separator = if skip_blanks(&command[word..]).is_empty() {
            " "
        } else {
            ""
        };
        for redirection in self.redirections {
            write!(f, "{separator}{redirection}")?;
            separator = " ";
        }
        Ok(())
    }
}

/// The answer to [`TERMINATE`] a line gives: Some(true) for Y, Some(false) for N, None for
/// anything else (the question is asked again).
pub fn answer(line: &[u16]) -> Option<bool> {
    match trim_blanks(crate::without_break(line)) {
        [unit] if *unit == u16::from(b'y') || *unit == u16::from(b'Y') => Some(true),
        [unit] if *unit == u16::from(b'n') || *unit == u16::from(b'N') => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn narrow(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    #[test]
    fn arguments_by_number() {
        let line = wide("t.cmd one,\"two three\"  ;four=five");
        let of = |n| argument(&line, n).map(narrow);
        assert_eq!(of(0).as_deref(), Some("t.cmd"));
        assert_eq!(of(1).as_deref(), Some("one"));
        assert_eq!(of(2).as_deref(), Some("\"two three\""));
        assert_eq!(of(3).as_deref(), Some("four"));
        assert_eq!(of(4).as_deref(), Some("five"));
        assert_eq!(of(5), None);
        assert_eq!(narrow(all(&line)), "one,\"two three\"  ;four=five");
        assert_eq!(narrow(all(&wide("t"))), "");
        assert_eq!(narrow(all(&wide("t   "))), "");
        assert_eq!(narrow(unquote(&wide("\"a b\""))), "a b");
        assert_eq!(narrow(unquote(&wide("ab"))), "ab");
    }

    /// The lines a reader gives, the file handed over `step` bytes a read.
    fn lines(text: &[u8], step: usize, room: usize) -> Vec<Vec<u8>> {
        let mut reader = LineReader::default();
        let mut at = 0;
        let mut read = |buffer: &mut [u8]| -> Result<usize, ()> {
            let count = step.min(buffer.len()).min(text.len() - at);
            buffer[..count].copy_from_slice(&text[at..at + count]);
            at += count;
            Ok(count)
        };
        let mut out = Vec::new();
        let mut line = vec![0; room];
        while let Some(got) = reader.next_line(&mut read, &mut line).unwrap() {
            out.push(got.to_vec());
        }
        out
    }

    #[test]
    fn the_offset_is_where_the_next_line_starts() {
        let text = b"a\r\nbcd\nlast";
        let mut reader = LineReader::default();
        let mut at = 0;
        let mut read = |buffer: &mut [u8]| -> Result<usize, ()> {
            let count = 2.min(buffer.len()).min(text.len() - at);
            buffer[..count].copy_from_slice(&text[at..at + count]);
            at += count;
            Ok(count)
        };
        let mut line = [0; 16];
        let mut offsets = Vec::new();
        while reader.next_line(&mut read, &mut line).unwrap().is_some() {
            offsets.push(reader.offset());
        }
        assert_eq!(offsets, [3, 7, 11]);
    }

    #[test]
    fn a_label_is_looked_for_from_where_the_reader_is() {
        let text = b"@echo off\r\n:top\r\necho one\r\n:END rest\r\necho two\r\n:top\r\nlast\r\n";
        let mut at = 0;
        let mut read = |buffer: &mut [u8]| -> Result<usize, ()> {
            let count = 3.min(buffer.len()).min(text.len() - at);
            buffer[..count].copy_from_slice(&text[at..at + count]);
            at += count;
            Ok(count)
        };
        let mut decode = |line: &[u8], units: &mut [u16]| {
            for (unit, &byte) in units.iter_mut().zip(line) {
                *unit = u16::from(byte);
            }
            Some(line.len())
        };
        let mut reader = LineReader::default();
        let (mut bytes, mut units) = ([0; 64], [0; 64]);
        let mut seek = |reader: &mut LineReader, label: &str| {
            reader.seek_label(&mut read, &mut decode, &wide(label), &mut bytes, &mut units)
        };
        assert!(seek(&mut reader, "end"));
        // The reader is at the line after the label.
        assert_eq!(reader.offset(), 38);
        // The first `:top` is behind: the one ahead is found.
        assert!(seek(&mut reader, "TOP"));
        assert!(!seek(&mut reader, "top"));
    }

    #[test]
    fn a_block_echoes_line_by_line() {
        let shown = Echoed(&wide("if a==a (\n  echo x\n)")).to_string();
        assert_eq!(shown, "if a==a (\r\n  echo x\r\n) ");
    }

    #[test]
    fn lines_end_at_lf_a_cr_before_it_dropped() {
        for step in [1, 2, 3, 7, CHUNK] {
            assert_eq!(
                lines(b"a\r\nbc\n\r\nd", step, 16),
                [b"a".to_vec(), b"bc".to_vec(), b"".to_vec(), b"d".to_vec()]
            );
            assert_eq!(lines(b"x\r\n", step, 16), [b"x".to_vec()]);
            assert!(lines(b"", step, 16).is_empty());
        }
    }

    #[test]
    fn a_line_too_long_is_cut() {
        assert_eq!(
            lines(b"abcdef\r\ngh", 2, 4),
            [b"abcd".to_vec(), b"gh".to_vec()]
        );
        let long = vec![b'x'; 3 * CHUNK];
        let mut text = long.clone();
        text.extend_from_slice(b"\nend");
        let got = lines(&text, CHUNK, 3 * CHUNK);
        assert_eq!(got, [long, b"end".to_vec()]);
    }

    #[test]
    fn exit_s_forms() {
        let of = |text: &str| exit(&wide(text));
        assert_eq!(
            of(""),
            Exit {
                batch: false,
                code: None
            }
        );
        assert_eq!(
            of(" 3 "),
            Exit {
                batch: false,
                code: Some(3)
            }
        );
        assert_eq!(
            of("/B"),
            Exit {
                batch: true,
                code: None
            }
        );
        assert_eq!(
            of("/b 4"),
            Exit {
                batch: true,
                code: Some(4)
            }
        );
        assert_eq!(
            of("-1"),
            Exit {
                batch: false,
                code: Some(u32::MAX)
            }
        );
        assert_eq!(
            of("12abc"),
            Exit {
                batch: false,
                code: Some(12)
            }
        );
        assert_eq!(
            of("abc"),
            Exit {
                batch: false,
                code: Some(0)
            }
        );
        // `/bx` is no /B: atoi reads nothing of it.
        assert_eq!(
            of("/bx"),
            Exit {
                batch: false,
                code: Some(0)
            }
        );
    }

    #[test]
    fn labels_and_empty_lines_are_skipped() {
        assert!(skipped(&wide("")));
        assert!(skipped(&wide("  \t")));
        assert!(skipped(&wide(":end")));
        assert!(skipped(&wide("  :: comment")));
        assert!(!skipped(&wide("echo :")));
    }

    #[test]
    fn a_line_echoes_without_its_leading_blanks_unless_at_hides_it() {
        let shown = |line: &str| echoed(&wide(line)).map(|echoed| echoed.to_string());
        assert_eq!(shown("  echo hi").as_deref(), Some("echo hi "));
        assert_eq!(shown(" @echo off"), None);
        assert_eq!(shown("   "), None);
    }

    #[test]
    fn a_command_with_arguments_echoes_with_a_blank_after_it() {
        // batecho's capture: `>echo with echo on ` and `>echo`.
        let shown = |line: &str| echoed(&wide(line)).unwrap().to_string();
        assert_eq!(shown("echo with echo on"), "echo with echo on ");
        assert_eq!(shown("echo"), "echo");
        assert_eq!(shown("echo  "), "echo");
        assert_eq!(shown("echo   three  "), "echo   three   ");
        assert_eq!(shown("spawnkid exit 3"), "spawnkid exit 3 ");
    }

    #[test]
    fn a_command_echoes_with_its_redirections_rebuilt() {
        let shown = |line: &str| {
            let line = wide(line);
            let mut text = [0; 64];
            let mut redirections = crate::syntax::Redirections::default();
            let command = crate::syntax::simple(&line, &mut text, &mut redirections).unwrap();
            EchoedCommand {
                command,
                redirections: redirections.list(),
            }
            .to_string()
        };
        assert_eq!(shown("echo hi>out"), "echo hi 1>out");
        assert_eq!(shown("echo hi > out"), "echo hi  1>out");
        assert_eq!(shown("echo>out 2>&1"), "echo 1>out 2>&1");
        assert_eq!(shown("x < in"), "x 0<in");
        assert_eq!(shown("echo a^&b"), "echo a&b ");
    }

    #[test]
    fn the_terminate_question_s_answers() {
        assert_eq!(answer(&wide("y\r\n")), Some(true));
        assert_eq!(answer(&wide(" N \r\n")), Some(false));
        assert_eq!(answer(&wide("yes\r\n")), None);
        assert_eq!(answer(&wide("\r\n")), None);
    }
}
