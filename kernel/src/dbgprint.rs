//! The debugger's print channel: where ntdll's DbgPrint (and through it kernel32's
//! OutputDebugString and the system DLLs' stubs) sends its text.
//!
//! Windows 2000's DbgPrint formats its text in user mode and hands it to the kernel debugger
//! (`int 2Dh`'s print service); with no debugger attached, the text goes nowhere. F2K has no kernel
//! debugger: ntdll raises the internal service
//! [`SYS_DEBUG_PRINT`](crate::user::syscall::SYS_DEBUG_PRINT) with the formatted text, and this
//! module writes it to COM1, each line as `F2K: debug: <line>`, so the suite's logs carry it apart
//! from the program's own output. The text is at most [`MAX_TEXT`] bytes, as DbgPrint's own buffer
//! bounds it.

use core::fmt::Write;

use crate::nt::call::{NtResult, UserAddr};
use crate::status::*;
use crate::user::syscall::ServiceFn;

/// The most text one print carries: DbgPrint's buffer, 512 bytes.
pub const MAX_TEXT: usize = 512;

/// The prefix each line carries on COM1.
const PREFIX: &str = "F2K: debug: ";

/// The service the dispatcher raises SYS_DEBUG_PRINT into: its two dword arguments, the text and
/// its length in bytes, and its body.
pub const SERVICE: (u32, ServiceFn) = (8, service);

#[cfg(target_arch = "x86")]
fn service(
    frame: &mut crate::user::TrapFrame,
    args: &[u32],
    passive: &mut crate::level::At<crate::level::Passive>,
) {
    let call = crate::nt::call::NtCall::new(frame, passive);
    let result = print(UserAddr(args[0]), args[1], &mut |line| {
        crate::serial_println!("{PREFIX}{line}");
    });
    call.finish(result);
}

/// Host builds compile the dispatch but never raise it.
#[cfg(not(target_arch = "x86"))]
fn service(
    _frame: &mut crate::user::TrapFrame,
    _args: &[u32],
    _passive: &mut crate::level::At<crate::level::Passive>,
) {
    unreachable!("the gate is the target's");
}

/// Read `length` bytes of text at `text` (at most [`MAX_TEXT`]: the rest is dropped) and hand each
/// of its lines to `out`. A text the caller cannot name is STATUS_ACCESS_VIOLATION.
fn print(text: UserAddr, length: u32, out: &mut dyn FnMut(Line<'_>)) -> NtResult {
    let mut buffer = [0u8; MAX_TEXT];
    let bytes = &mut buffer[..(length as usize).min(MAX_TEXT)];
    crate::user::syscall::read_user(text.0, bytes)?;
    lines(bytes).for_each(out);
    Ok(STATUS_SUCCESS)
}

/// One line of the text, as COM1 shows it: a byte outside printable ASCII as `\xNN`.
struct Line<'a>(&'a [u8]);

impl core::fmt::Display for Line<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &byte in self.0 {
            if (0x20..0x7F).contains(&byte) {
                f.write_char(byte as char)?;
            } else {
                write!(f, "\\x{byte:02X}")?;
            }
        }
        Ok(())
    }
}

/// The text's lines: split at LF (a CR before it dropped), the empty piece after a final LF left
/// out; none for an empty text.
fn lines(text: &[u8]) -> impl Iterator<Item = Line<'_>> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    (!text.is_empty())
        .then(|| text.split(|&byte| byte == b'\n'))
        .into_iter()
        .flatten()
        .map(|line| Line(line.strip_suffix(b"\r").unwrap_or(line)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(text: &[u8]) -> Vec<String> {
        lines(text).map(|line| line.to_string()).collect()
    }

    #[test]
    fn each_line_is_its_own() {
        assert_eq!(shown(b"one\ntwo\n"), ["one", "two"]);
        assert_eq!(shown(b"no newline"), ["no newline"]);
        assert_eq!(shown(b"crlf\r\nend"), ["crlf", "end"]);
        assert_eq!(shown(b"a\n\nb\n"), ["a", "", "b"]);
        assert!(shown(b"").is_empty());
    }

    #[test]
    fn unprintable_bytes_are_escaped() {
        assert_eq!(
            shown(b"tab\there \x1b[0m \xe9"),
            ["tab\\x09here \\x1B[0m \\xE9"]
        );
    }
}
