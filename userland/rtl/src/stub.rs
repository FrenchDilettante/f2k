//! The stubs: exports that exist so programs load, and the paths of implemented exports F2K does
//! not handle yet. Either way the call fails the way the platform's API fails, and says so on the
//! debugger's channel (DbgPrint: the kernel writes it to COM1) with every argument it was given, so
//! the log shows which paths callers take.
//!
//! An export's [`Entry`] is generated from its spec (tools/exportgen: its name, its arguments'
//! kinds and names, its failure return); a stubbed export's generated body hands its arguments to
//! its DLL's stub routine, as does an implemented export's code on a path it does not handle (with
//! a reason of its own). This module writes the line ([`describe`]): the DLLs send it and fail.
//!
//! The line: `stub <dll>.<Export>(<name>=<value>, ...): <reason>`, at most [`LINE_BYTES`] bytes
//! (DbgPrint's buffer), each value as its kind shows it:
//!
//! - `u32`, `handle`: hexadecimal (`0x10`, `0` for zero); `i32`: decimal; `bool`: TRUE or FALSE;
//! - a pointer: `NULL`, or its address in eight hex digits;
//! - a `u64`: hexadecimal;
//! - a string: `NULL`, or quoted (`"C:\\x.txt"`, a quote or a backslash escaped, a byte outside
//!   printable ASCII as `\xNN`, a wide unit outside it as `\u{NNNN}`), cut after [`STRING_UNITS`]
//!   units (`"..."...`); a string whose memory cannot be read shows its address and `(unreadable)`;
//! - the variable arguments of a cdecl export: `...`.

use core::fmt::{self, Write};

/// The longest line: DbgPrint's buffer.
pub const LINE_BYTES: usize = 512;

/// The most units of a string the line shows.
pub const STRING_UNITS: usize = 96;

/// An argument's kind, as its export's spec declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    U32,
    I32,
    Bool,
    Handle,
    Ptr,
    U64,
    StrA,
    StrW,
    /// A cdecl export's variable arguments (`...`): nothing is read for them.
    Varargs,
}

/// What an export returns when it fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fails {
    /// Its failure value (a function's `FALSE`, `NULL`, `INVALID_HANDLE_VALUE`...).
    Value(u32),
    /// It returns nothing: the caller sees no failure but the last error.
    Void,
    /// It cannot fail (it never returns, or has no failure to report): a stub raises instead.
    Never,
}

/// An export, as its spec declares it.
#[derive(Debug)]
pub struct Entry {
    pub dll: &'static str,
    pub name: &'static str,
    /// Its arguments, first first: kind and name.
    pub args: &'static [(Kind, &'static str)],
    pub fails: Fails,
}

/// The caller's memory, as the line reads it: whether the page holding an address can be read.
pub trait Memory {
    fn readable(&self, address: usize) -> bool;
}

/// The lowest address a process maps: below it, 64 KiB no call reads (Windows keeps them free).
pub const LOWEST_MAPPED: usize = 0x1_0000;

/// Whether a page NtQueryVirtualMemory describes (its MEMORY_BASIC_INFORMATION's State and
/// Protect) can be read: committed, neither no-access nor a guard page.
pub fn readable(state: u32, protect: u32) -> bool {
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    state == MEM_COMMIT && protect != 0 && protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
}

/// Write the line for a call to `entry` with `args` (one value per argument, in order) to `out`,
/// ending with `reason`.
pub fn describe(
    entry: &Entry,
    reason: &str,
    args: &[u64],
    memory: &impl Memory,
    out: &mut impl Write,
) -> fmt::Result {
    write!(out, "stub {}.{}(", entry.dll, entry.name)?;
    let mut values = args.iter();
    for (index, &(kind, name)) in entry.args.iter().enumerate() {
        if index > 0 {
            out.write_str(", ")?;
        }
        if kind == Kind::Varargs {
            out.write_str("...")?;
            continue;
        }
        let value = values.next().copied().unwrap_or(0);
        write!(out, "{name}=")?;
        value_of(kind, value, memory, out)?;
    }
    write!(out, "): {reason}")
}

fn value_of(kind: Kind, value: u64, memory: &impl Memory, out: &mut impl Write) -> fmt::Result {
    let word = value as usize;
    match kind {
        Kind::U32 | Kind::Handle | Kind::U64 => {
            if value == 0 {
                out.write_str("0")
            } else {
                write!(out, "{value:#X}")
            }
        }
        Kind::I32 => write!(out, "{}", value as u32 as i32),
        Kind::Bool => out.write_str(if value as u32 != 0 { "TRUE" } else { "FALSE" }),
        Kind::Ptr => pointer(word, out),
        Kind::StrA | Kind::StrW => {
            if word == 0 {
                return out.write_str("NULL");
            }
            string(word, kind == Kind::StrW, memory, out)
        }
        Kind::Varargs => out.write_str("..."),
    }
}

fn pointer(address: usize, out: &mut impl Write) -> fmt::Result {
    if address == 0 {
        out.write_str("NULL")
    } else {
        write!(out, "0x{address:08X}")
    }
}

/// A string at `address`, quoted, read unit by unit while its pages can be read.
fn string(address: usize, wide: bool, memory: &impl Memory, out: &mut impl Write) -> fmt::Result {
    let unit_bytes = if wide { 2 } else { 1 };
    let unit = |index: usize| -> Option<u16> {
        let at = address.checked_add(index * unit_bytes)?;
        // A unit straddling a page boundary needs both pages.
        if !memory.readable(at) || !memory.readable(at + unit_bytes - 1) {
            return None;
        }
        // SAFETY: the page holding the unit can be read (the memory says so).
        Some(unsafe {
            if wide {
                (at as *const u16).read_unaligned()
            } else {
                u16::from((at as *const u8).read())
            }
        })
    };
    let Some(first) = unit(0) else {
        pointer(address, out)?;
        return out.write_str(" (unreadable)");
    };
    out.write_char('"')?;
    let mut index = 0;
    let mut current = Some(first);
    while let Some(value) = current {
        if value == 0 {
            return out.write_char('"');
        }
        if index == STRING_UNITS {
            return out.write_str("\"...");
        }
        match value {
            0x22 => out.write_str("\\\"")?,
            0x5C => out.write_str("\\\\")?,
            0x20..=0x7E => out.write_char(value as u8 as char)?,
            _ if wide => write!(out, "\\u{{{value:04X}}}")?,
            _ => write!(out, "\\x{value:02X}")?,
        }
        index += 1;
        current = unit(index);
    }
    // The string runs into memory that cannot be read.
    out.write_str("\"... (unreadable)")
}

/// A fixed buffer the line is written into: what does not fit is dropped, the cut marked with
/// `...`.
pub struct Line {
    bytes: [u8; LINE_BYTES],
    length: usize,
    cut: bool,
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

impl Line {
    pub const fn new() -> Self {
        Self {
            bytes: [0; LINE_BYTES],
            length: 0,
            cut: false,
        }
    }

    /// The line's bytes, with a final LF, and a NUL after it (for a C caller): the room for
    /// both is kept.
    pub fn terminated(&mut self) -> &[u8] {
        let room = LINE_BYTES - 2;
        if self.cut {
            self.length = room - 3;
            self.bytes[self.length..room].copy_from_slice(b"...");
            self.length = room;
        }
        self.bytes[self.length] = b'\n';
        self.bytes[self.length + 1] = 0;
        &self.bytes[..self.length + 2]
    }

    /// The text written so far (empty if DbgPrint's bytes are not UTF-8).
    pub fn text(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.length]).unwrap_or("")
    }
}

/// DbgPrint's text, bytes as they come (a code page's, not UTF-8).
impl crate::printf::Sink for Line {
    fn put(&mut self, bytes: &[u8]) {
        let room = LINE_BYTES - 2;
        let fits = bytes.len().min(room - self.length);
        self.bytes[self.length..self.length + fits].copy_from_slice(&bytes[..fits]);
        self.length += fits;
        self.cut |= fits < bytes.len();
    }
}

impl Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let room = LINE_BYTES - 2;
        for character in text.chars() {
            let mut encoded = [0u8; 4];
            let encoded = character.encode_utf8(&mut encoded).as_bytes();
            if self.length + encoded.len() > room {
                self.cut = true;
                return Ok(());
            }
            self.bytes[self.length..self.length + encoded.len()].copy_from_slice(encoded);
            self.length += encoded.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every address but the null page can be read, or none past a limit.
    struct Host(usize);

    impl Memory for Host {
        fn readable(&self, address: usize) -> bool {
            address >= 0x1000 && address < self.0
        }
    }

    #[test]
    fn readable_pages_are_committed_and_accessible() {
        assert!(readable(0x1000, 0x04));
        assert!(readable(0x1000, 0x02));
        assert!(!readable(0x2000, 0x04)); // reserved
        assert!(!readable(0x1000, 0x01)); // no access
        assert!(!readable(0x1000, 0x104)); // a guard page
        assert!(!readable(0x1_0000, 0));
    }

    const ALL: Host = Host(usize::MAX);

    const CREATE: Entry = Entry {
        dll: "kernel32",
        name: "CreateProcessW",
        args: &[
            (Kind::StrW, "lpApplicationName"),
            (Kind::StrW, "lpCommandLine"),
            (Kind::Ptr, "lpProcessAttributes"),
            (Kind::Bool, "bInheritHandles"),
            (Kind::U32, "dwCreationFlags"),
            (Kind::I32, "count"),
            (Kind::Handle, "hFile"),
        ],
        fails: Fails::Value(0),
    };

    fn line(entry: &Entry, reason: &str, args: &[u64], memory: &impl Memory) -> String {
        let mut out = String::new();
        describe(entry, reason, args, memory, &mut out).unwrap();
        out
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn every_argument_shows_as_its_kind() {
        let command = wide("hello.exe \"two words\" c:\\x é");
        let args = [
            0,
            command.as_ptr() as u64,
            0,
            1,
            0x10,
            -2i32 as u32 as u64,
            0x24,
        ];
        assert_eq!(
            line(&CREATE, "not yet implemented", &args, &ALL),
            "stub kernel32.CreateProcessW(lpApplicationName=NULL, \
             lpCommandLine=\"hello.exe \\\"two words\\\" c:\\\\x \\u{00E9}\", \
             lpProcessAttributes=NULL, bInheritHandles=TRUE, dwCreationFlags=0x10, count=-2, \
             hFile=0x24): not yet implemented"
        );
    }

    #[test]
    fn narrow_strings_escape_their_bytes() {
        const OPEN: Entry = Entry {
            dll: "kernel32",
            name: "CreateFileA",
            args: &[
                (Kind::StrA, "lpFileName"),
                (Kind::Ptr, "lpSecurityAttributes"),
            ],
            fails: Fails::Value(u32::MAX),
        };
        let name = b"caf\xe9\t.txt\0";
        let args = [name.as_ptr() as u64, 0x0012_FF40];
        assert_eq!(
            line(&OPEN, "FILE_FLAG_OVERLAPPED", &args, &ALL),
            "stub kernel32.CreateFileA(lpFileName=\"caf\\xE9\\x09.txt\", \
             lpSecurityAttributes=0x0012FF40): FILE_FLAG_OVERLAPPED"
        );
    }

    #[test]
    fn long_strings_are_cut() {
        const ONE: Entry = Entry {
            dll: "k",
            name: "F",
            args: &[(Kind::StrA, "s")],
            fails: Fails::Void,
        };
        let long = [b'a'; STRING_UNITS + 10]
            .iter()
            .copied()
            .chain([0])
            .collect::<Vec<u8>>();
        let shown = line(&ONE, "r", &[long.as_ptr() as u64], &ALL);
        assert_eq!(
            shown,
            format!("stub k.F(s=\"{}\"...): r", "a".repeat(STRING_UNITS))
        );
    }

    #[test]
    fn unreadable_strings_show_their_address() {
        const ONE: Entry = Entry {
            dll: "k",
            name: "F",
            args: &[(Kind::StrW, "s")],
            fails: Fails::Never,
        };
        assert_eq!(
            line(&ONE, "r", &[0x10], &ALL),
            "stub k.F(s=0x00000010 (unreadable)): r"
        );
        // A string running into memory that cannot be read.
        const NARROW: Entry = Entry {
            dll: "k",
            name: "F",
            args: &[(Kind::StrA, "s")],
            fails: Fails::Never,
        };
        let text = b"abc";
        let limit = Host(text.as_ptr() as usize + 2);
        assert_eq!(
            line(&NARROW, "r", &[text.as_ptr() as u64], &limit),
            "stub k.F(s=\"ab\"... (unreadable)): r"
        );
    }

    #[test]
    fn variable_arguments_are_not_read() {
        const PRINT: Entry = Entry {
            dll: "ntdll",
            name: "DbgPrint",
            args: &[(Kind::StrA, "Format"), (Kind::Varargs, "")],
            fails: Fails::Value(0xC000_0002),
        };
        let format = b"%I64x\0";
        assert_eq!(
            line(
                &PRINT,
                "the conversion %I64x",
                &[format.as_ptr() as u64],
                &ALL
            ),
            "stub ntdll.DbgPrint(Format=\"%I64x\", ...): the conversion %I64x"
        );
    }

    #[test]
    fn the_line_keeps_room_for_its_end() {
        let mut out = Line::new();
        write!(out, "{}", "x".repeat(LINE_BYTES * 2)).unwrap();
        let bytes = out.terminated();
        assert_eq!(bytes.len(), LINE_BYTES);
        assert!(bytes.ends_with(b"...\n\0"));
        let mut short = Line::new();
        short.write_str("stub").unwrap();
        assert_eq!(short.text(), "stub");
        assert_eq!(short.terminated(), b"stub\n\0");
    }
}
