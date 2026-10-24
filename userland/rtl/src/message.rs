//! Message formatting: RtlFormatMessage's work, which FormatMessage hands a message's text to, as
//! Windows 2000's kernel32 does — the escapes, the inserts and the line width the FormatMessage
//! documentation describes.
//!
//! The text runs to its NUL. In it:
//!
//! - a line break (CR LF, or a lone CR or LF) is a regular line break: kept, as CR LF, when no
//!   width is set (zero); a blank in its place otherwise;
//! - `%0` ends the message there, without the line break that would follow; `%n` is a hard line
//!   break (CR LF, whatever the width); `%r` a carriage return alone and `%t` a tab (the message
//!   compiler's escapes); `%` and any other character is that character (`%%`, `%.`, `%!`, `% `);
//! - `%1` to `%99` are inserts: the argument of that number, laid out by the printf format between
//!   exclamation marks that may follow (`%1!d!`), `!s!` when none does. A format's `*` takes the
//!   width or the precision from the argument, the value from the next (the FormatMessage
//!   documentation's `%1!*.*s!` takes the first three). With inserts ignored, an insert is copied
//!   as it is written, format and all.
//!
//! The width (MaximumWidth) lays the lines out: zero keeps the text's line breaks;
//! [`NO_LINE_BREAKS`] makes them blanks and generates none; any other width also breaks a line that
//! would run past it at its last blank (CR LF in the blank's place), and a word longer than the
//! width at the width (the runtime capture: width 5 makes `Acces` and `s is` of "Access is").
//!
//! The arguments are pointer-sized slots, in order (an array, or the va_list's stack). A string
//! insert's `s` is the call's own form (ANSI for an A call's arguments, UTF-16 for a W call's) and
//! `S` the other, `h` and `l` (or `w`) forcing ANSI and UTF-16; `c` and `C` likewise; ANSI text
//! decodes through code page 1252. The numeric conversions are the C runtime's ([`crate::printf`]).

use crate::printf::{self, Args, Sink};
use crate::status::{STATUS_BUFFER_OVERFLOW, STATUS_INVALID_PARAMETER};

/// The width that turns the text's line breaks into blanks and generates none: FormatMessage's
/// FORMAT_MESSAGE_MAX_WIDTH_MASK, which kernel32 hands over as MAXULONG.
pub const NO_LINE_BREAKS: u32 = u32::MAX;

const CR: u16 = 0x0D;
const LF: u16 = 0x0A;
const BLANK: u16 = 0x20;
const TAB: u16 = 0x09;
const PERCENT: u16 = b'%' as u16;
const BANG: u16 = b'!' as u16;

/// The inserts' arguments: pointer-sized slots, the first `%1`'s, and whether the call's strings
/// are ANSI.
#[derive(Clone, Copy)]
pub struct Arguments {
    pub slots: *const usize,
    pub ansi: bool,
}

impl Arguments {
    /// The slot at `index` (zero: `%1`'s).
    fn slot(self, index: usize) -> usize {
        // SAFETY: the caller's arguments hold every slot the message's inserts name.
        unsafe { self.slots.add(index).read_unaligned() }
    }
}

/// The output and its layout state: the line's start, its last blank.
struct Out<'a> {
    buffer: &'a mut [u16],
    length: usize,
    line: usize,
    blank: Option<usize>,
    width: u32,
}

impl Out<'_> {
    /// One unit, as it is; STATUS_BUFFER_OVERFLOW past the buffer.
    fn raw(&mut self, unit: u16) -> Result<(), u32> {
        *self
            .buffer
            .get_mut(self.length)
            .ok_or(STATUS_BUFFER_OVERFLOW)? = unit;
        self.length += 1;
        Ok(())
    }

    /// A line break the text forces (CR LF): the next line starts after it.
    fn hard_break(&mut self) -> Result<(), u32> {
        self.raw(CR)?;
        self.raw(LF)?;
        self.line = self.length;
        self.blank = None;
        Ok(())
    }

    /// A line break of the text: kept without a width, a blank with one.
    fn regular_break(&mut self) -> Result<(), u32> {
        if self.width == 0 {
            self.hard_break()
        } else {
            self.unit(BLANK)
        }
    }

    /// One unit of the message, its line broken first when it would run past the width (a blank
    /// never breaks one).
    fn unit(&mut self, unit: u16) -> Result<(), u32> {
        let wraps = self.width != 0 && self.width != NO_LINE_BREAKS;
        if wraps && unit != BLANK && self.length - self.line >= self.width as usize {
            if let Some(at) = self.blank.take() {
                // The blank becomes the break: the line's tail moves up one unit past it.
                self.raw(0)?;
                self.buffer.copy_within(at + 1..self.length - 1, at + 2);
                self.buffer[at..at + 2].copy_from_slice(&[CR, LF]);
                self.line = at + 2;
            } else {
                // No blank on the line: the word breaks at the width.
                self.raw(CR)?;
                self.raw(LF)?;
                self.line = self.length;
            }
        }
        if unit == BLANK {
            self.blank = Some(self.length);
        }
        self.raw(unit)
    }

    fn units(&mut self, units: &[u16]) -> Result<(), u32> {
        units.iter().try_for_each(|&unit| self.unit(unit))
    }
}

/// RtlFormatMessage's work: `text` (to its NUL) laid out to `width`, its inserts expanded from
/// `arguments` (or copied as written, `ignore_inserts`), into `out`, terminated. The units written,
/// the terminator left out. STATUS_BUFFER_OVERFLOW when `out` cannot hold them and the terminator;
/// STATUS_INVALID_PARAMETER for an insert without arguments, or one whose format is not closed or
/// not served.
pub fn format(
    text: &[u16],
    width: u32,
    ignore_inserts: bool,
    arguments: Option<Arguments>,
    out: &mut [u16],
) -> Result<usize, u32> {
    let text = text.split(|&unit| unit == 0).next().unwrap_or(&[]);
    let mut out = Out {
        buffer: out,
        length: 0,
        line: 0,
        blank: None,
        width,
    };
    let mut at = 0;
    while let Some(&unit) = text.get(at) {
        at += 1;
        match unit {
            CR => {
                if text.get(at) == Some(&LF) {
                    at += 1;
                }
                out.regular_break()?;
            }
            LF => out.regular_break()?,
            PERCENT => {
                let Some(&escape) = text.get(at) else {
                    out.unit(PERCENT)?;
                    break;
                };
                at += 1;
                match escape {
                    0x30 => break, // %0
                    0x31..=0x39 => {
                        let start = at - 2;
                        let mut number = usize::from(escape - 0x30);
                        if let Some(&digit @ 0x30..=0x39) = text.get(at) {
                            number = 10 * number + usize::from(digit - 0x30);
                            at += 1;
                        }
                        let spec = if text.get(at) == Some(&BANG) {
                            let close = text[at + 1..]
                                .iter()
                                .position(|&unit| unit == BANG)
                                .ok_or(STATUS_INVALID_PARAMETER)?;
                            let spec = &text[at + 1..at + 1 + close];
                            at += close + 2;
                            Some(spec)
                        } else {
                            None
                        };
                        if ignore_inserts {
                            out.units(&text[start..at])?;
                        } else {
                            let arguments = arguments.ok_or(STATUS_INVALID_PARAMETER)?;
                            insert(&mut out, number - 1, spec, arguments)?;
                        }
                    }
                    0x6E => out.hard_break()?, // %n
                    0x72 => {
                        // %r: a carriage return alone.
                        out.raw(CR)?;
                        out.line = out.length;
                        out.blank = None;
                    }
                    0x74 => out.unit(TAB)?, // %t
                    other => out.unit(other)?,
                }
            }
            _ => out.unit(unit)?,
        }
    }
    let length = out.length;
    out.raw(0)?;
    Ok(length)
}

/// The longest insert format served, in characters.
const SPEC_ROOM: usize = 24;

/// An insert's format, parsed: where its conversion is, and what it says about strings.
struct Spec {
    /// The format as bytes (`%` first, for printf), and its length.
    bytes: [u8; SPEC_ROOM + 1],
    length: usize,
    left: bool,
    /// The width and the precision: digits, `*` (from an argument), or none.
    width: Option<Count>,
    precision: Option<Count>,
    /// `h` (ANSI), `l` or `w` (UTF-16), or neither.
    narrow: bool,
    wide: bool,
    conversion: u8,
}

#[derive(Clone, Copy)]
enum Count {
    Digits(usize),
    Argument,
}

/// Parse `units` (between the exclamation marks) as a printf format: flags, width, precision,
/// length, conversion; STATUS_INVALID_PARAMETER for anything else.
fn parse(units: &[u16]) -> Result<Spec, u32> {
    let mut spec = Spec {
        bytes: [0; SPEC_ROOM + 1],
        length: units.len() + 1,
        left: false,
        width: None,
        precision: None,
        narrow: false,
        wide: false,
        conversion: 0,
    };
    if units.is_empty() || units.len() > SPEC_ROOM {
        return Err(STATUS_INVALID_PARAMETER);
    }
    spec.bytes[0] = b'%';
    for (byte, &unit) in spec.bytes[1..].iter_mut().zip(units) {
        *byte = u8::try_from(unit)
            .ok()
            .filter(u8::is_ascii_graphic)
            .ok_or(STATUS_INVALID_PARAMETER)?;
    }
    let format = &spec.bytes[1..spec.length];
    let mut at = 0;
    while let Some(&flag @ (b'-' | b'+' | b' ' | b'#' | b'0')) = format.get(at) {
        spec.left |= flag == b'-';
        at += 1;
    }
    let count = |at: &mut usize| -> Option<Count> {
        if format.get(*at) == Some(&b'*') {
            *at += 1;
            return Some(Count::Argument);
        }
        let digits = format[*at..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let value = format[*at..*at + digits]
            .iter()
            .fold(0usize, |value, &digit| {
                10 * value + usize::from(digit - b'0')
            });
        *at += digits;
        (digits != 0).then_some(Count::Digits(value))
    };
    spec.width = count(&mut at);
    if format.get(at) == Some(&b'.') {
        at += 1;
        spec.precision = Some(count(&mut at).unwrap_or(Count::Digits(0)));
    }
    match format.get(at) {
        Some(b'h') => {
            spec.narrow = true;
            at += 1;
        }
        Some(b'l' | b'w') => {
            spec.wide = true;
            at += 1;
            if format.get(at) == Some(&b'l') {
                spec.wide = false;
                at += 1;
            }
        }
        Some(b'I') => at += 3,
        _ => {}
    }
    match format.get(at) {
        Some(&conversion) if at + 1 == format.len() => spec.conversion = conversion,
        _ => return Err(STATUS_INVALID_PARAMETER),
    }
    Ok(spec)
}

/// The numeric conversions' arguments: the slots from an insert's on.
struct Slots {
    arguments: Arguments,
    next: usize,
}

impl Args for Slots {
    fn next_u32(&mut self) -> u32 {
        self.next += 1;
        self.arguments.slot(self.next - 1) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let low = self.next_u32();
        u64::from(low) | u64::from(self.next_u32()) << 32
    }

    fn next_ptr(&mut self) -> usize {
        self.next += 1;
        self.arguments.slot(self.next - 1)
    }
}

/// No memory: the numeric conversions read none.
struct NoMemory;

impl crate::stub::Memory for NoMemory {
    fn readable(&self, _: usize) -> bool {
        false
    }
}

/// The numeric conversions' text, widened into the message.
struct Widened<'a, 'b> {
    out: &'a mut Out<'b>,
    status: Result<(), u32>,
}

impl Sink for Widened<'_, '_> {
    fn put(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.status.is_ok() {
                self.status = self.out.unit(u16::from(byte));
            }
        }
    }
}

/// Insert `index` (zero: `%1`) laid out by `spec` (`s` when none) into `out`.
fn insert(
    out: &mut Out<'_>,
    index: usize,
    spec: Option<&[u16]>,
    arguments: Arguments,
) -> Result<(), u32> {
    let spec = parse(spec.unwrap_or(&[u16::from(b's')]))?;
    let (conversion, mut next) = (spec.conversion, index);
    if !matches!(conversion, b's' | b'S' | b'c' | b'C') {
        let mut slots = Slots { arguments, next };
        let mut sink = Widened {
            out,
            status: Ok(()),
        };
        printf::format(&spec.bytes[..spec.length], &mut slots, &NoMemory, &mut sink)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        return sink.status;
    }
    let mut count = |count: Option<Count>| match count {
        Some(Count::Digits(value)) => Some(value),
        Some(Count::Argument) => {
            next += 1;
            Some((arguments.slot(next - 1) as u32 as i32).max(0) as usize)
        }
        None => None,
    };
    let width = count(spec.width).unwrap_or(0);
    let precision = count(spec.precision);
    let value = arguments.slot(next);
    // The call's own form for `s` and `c`, the other for `S` and `C`, unless a length says.
    let own = conversion.is_ascii_lowercase();
    let wide = if spec.narrow {
        false
    } else if spec.wide {
        true
    } else {
        own != arguments.ansi
    };
    let text = Text {
        address: value,
        wide,
        single: conversion.eq_ignore_ascii_case(&b'c'),
        limit: precision.unwrap_or(usize::MAX),
    };
    let length = text.length();
    let pad = width.saturating_sub(length);
    if !spec.left {
        (0..pad).try_for_each(|_| out.unit(BLANK))?;
    }
    (0..length).try_for_each(|index| out.unit(text.read(index)))?;
    if spec.left {
        (0..pad).try_for_each(|_| out.unit(BLANK))?;
    }
    Ok(())
}

/// A string insert's text: a NUL-terminated string at an address (`(null)` for none), or one
/// character (the slot's value), ANSI or UTF-16, its length bounded by the precision.
struct Text {
    address: usize,
    wide: bool,
    single: bool,
    limit: usize,
}

const NULL_TEXT: &[u8] = b"(null)";

impl Text {
    /// The unit at `index` of the string, read where it lies (a character's own value).
    fn read(&self, index: usize) -> u16 {
        if self.single {
            return if self.wide {
                self.address as u16
            } else {
                crate::cp1252::MB_TO_WC[self.address & 0xFF]
            };
        }
        if self.address == 0 {
            return NULL_TEXT.get(index).map_or(0, |&byte| u16::from(byte));
        }
        // SAFETY: the caller's string, read up to its NUL (a bad pointer faults the caller, as on
        // the platform).
        unsafe {
            if self.wide {
                (self.address as *const u16).add(index).read_unaligned()
            } else {
                crate::cp1252::MB_TO_WC[usize::from((self.address as *const u8).add(index).read())]
            }
        }
    }

    fn length(&self) -> usize {
        if self.single {
            return 1;
        }
        (0..self.limit)
            .take_while(|&index| self.read(index) != 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// `text` formatted to `width` (inserts ignored), as a string; the status on failure.
    fn laid(text: &str, width: u32) -> Result<std::string::String, u32> {
        let mut out = [0u16; 256];
        let length = format(&wide(text), width, true, None, &mut out)?;
        assert_eq!(out[length], 0, "terminated");
        Ok(std::string::String::from_utf16(&out[..length]).unwrap())
    }

    /// `text` formatted with `slots` as the arguments (ANSI strings or not).
    fn with(text: &str, slots: &[usize], ansi: bool) -> Result<std::string::String, u32> {
        let mut out = [0u16; 256];
        let arguments = Arguments {
            slots: slots.as_ptr(),
            ansi,
        };
        let length = format(&wide(text), 0, false, Some(arguments), &mut out)?;
        Ok(std::string::String::from_utf16(&out[..length]).unwrap())
    }

    /// The runtime capture's widths, over the system messages' text (each ending in its CR LF): no
    /// width keeps the line break; FORMAT_MESSAGE_MAX_WIDTH_MASK makes it a blank; a width breaks
    /// at blanks, and a word longer than the width at the width.
    #[test]
    fn the_captured_widths() {
        let file = "The system cannot find the file specified.\r\n";
        assert_eq!(laid(file, 0).unwrap(), file);
        assert_eq!(
            laid(file, NO_LINE_BREAKS).unwrap(),
            "The system cannot find the file specified. "
        );
        assert_eq!(
            laid(file, 20).unwrap(),
            "The system cannot\r\nfind the file\r\nspecified. "
        );
        assert_eq!(
            laid("Access is denied.\r\n", 5).unwrap(),
            "Acces\r\ns is\r\ndenie\r\nd. "
        );
    }

    /// The escapes: %0 ends the message, %n breaks the line whatever the width, %r and %t, and a
    /// character after `%` is itself; a lone LF or CR is a regular break.
    #[test]
    fn the_escapes() {
        assert_eq!(laid("one%0two\r\n", 0).unwrap(), "one");
        assert_eq!(laid("one%ntwo\r\n", NO_LINE_BREAKS).unwrap(), "one\r\ntwo ");
        assert_eq!(laid("a%rb%tc", 0).unwrap(), "a\rb\tc");
        assert_eq!(laid("100%% %. %! % x%", 0).unwrap(), "100% . !  x%");
        assert_eq!(laid("a\nb\rc", 0).unwrap(), "a\r\nb\r\nc");
        assert_eq!(laid("a\nb\rc", 7).unwrap(), "a b c");
    }

    /// Ignored inserts are copied as written, their formats too.
    #[test]
    fn ignored_inserts_are_copied() {
        assert_eq!(
            laid("Copy %1 to %2!d! (%12).", 0).unwrap(),
            "Copy %1 to %2!d! (%12)."
        );
    }

    /// Inserts: `s` by default, in the call's own form; `S` the other; numbers through printf;
    /// `*` taking the width and precision from the arguments (the documentation's example).
    #[test]
    fn inserts_expand_from_the_arguments() {
        let bill: std::vec::Vec<u16> = wide("Bill");
        let bob: std::vec::Vec<u16> = wide("Bob");
        let slots = [
            4,
            2,
            bill.as_ptr() as usize,
            bob.as_ptr() as usize,
            6,
            bill.as_ptr() as usize,
        ];
        assert_eq!(
            with("%1!*.*s! %4 %5!*s!", &slots, false).unwrap(),
            "  Bi Bob   Bill"
        );
        let ansi = b"caf\xE9\0";
        assert_eq!(
            with(
                "%1 %2!S! %1!-6s!|",
                &[ansi.as_ptr() as usize, bob.as_ptr() as usize],
                true
            )
            .unwrap(),
            "caf\u{e9} Bob caf\u{e9}  |"
        );
        assert_eq!(
            with("%1!d! %2!08lX! %3!u! %1!c!", &[65, 0xBEEF, 7], false).unwrap(),
            "65 0000BEEF 7 A"
        );
        assert_eq!(with("[%1]", &[0], false).unwrap(), "[(null)]");
    }

    /// Inserts wrap like the rest of the message.
    #[test]
    fn inserts_wrap_with_the_text() {
        let name = wide("C:\\TEMP\\A.TXT");
        let slots = [name.as_ptr() as usize];
        let mut out = [0u16; 64];
        let arguments = Arguments {
            slots: slots.as_ptr(),
            ansi: false,
        };
        let text = wide("Cannot open %1 now.\r\n");
        let length = format(&text, 12, false, Some(arguments), &mut out).unwrap();
        assert_eq!(
            std::string::String::from_utf16(&out[..length]).unwrap(),
            "Cannot open\r\nC:\\TEMP\\A.TX\r\nT now. "
        );
    }

    /// Refusals: an insert without arguments, an unclosed or unserved format, a buffer without
    /// room for the message and its terminator.
    #[test]
    fn refusals() {
        let mut out = [0u16; 8];
        assert_eq!(
            format(&wide("%1"), 0, false, None, &mut out),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(with("%1!d", &[1], false), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(with("%1!f!", &[1], false), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            format(&wide("12345678"), 0, true, None, &mut out),
            Err(STATUS_BUFFER_OVERFLOW)
        );
        assert_eq!(format(&wide("1234567"), 0, true, None, &mut out), Ok(7));
        assert_eq!(
            format(&wide("1234 5678"), 4, true, None, &mut out),
            Err(STATUS_BUFFER_OVERFLOW),
            "the break needs a unit more"
        );
    }
}
