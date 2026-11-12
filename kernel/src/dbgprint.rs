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

/// A case a kernel service does not handle yet (win32k's, most of all), on COM1 as the system
/// DLLs' stub routine shows theirs: `F2K: debug: stub <module>.<service>(<args>): <reason>`, its
/// arguments as the service names them. The service carries on as its code does (it fails, or
/// leaves the case out): the line is all this adds. COM1's writes take no lock and wait for
/// nothing, so a service may log under the window manager's lock.
pub fn unhandled(
    module: &str,
    service: &str,
    args: core::fmt::Arguments<'_>,
    reason: core::fmt::Arguments<'_>,
) {
    #[cfg(target_arch = "x86")]
    {
        let mut com1 = crate::hw::serial::com1();
        let _ = write_unhandled(&mut com1, module, service, args, reason);
        crate::hw::serial::write_byte_blocking(b'\n');
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = (module, service, args, reason);
}

/// [`unhandled`] once per process for a site's case: `logged` is the site's set, `process` the
/// calling process's id, `case` the case's own number (its low 16 bits are kept, the process's
/// low 16 bits above them). A path a program may take in a loop logs each case once per process.
pub fn unhandled_once<const N: usize>(
    logged: &rtl::stub::Logged<N>,
    process: u32,
    case: u32,
    module: &str,
    service: &str,
    args: core::fmt::Arguments<'_>,
    reason: core::fmt::Arguments<'_>,
) {
    if logged.first((process & 0xFFFF) << 16 | (case & 0xFFFF)) {
        unhandled(module, service, args, reason);
    }
}

/// [`unhandled`]'s line, without its line end.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
fn write_unhandled(
    out: &mut impl Write,
    module: &str,
    service: &str,
    args: core::fmt::Arguments<'_>,
    reason: core::fmt::Arguments<'_>,
) -> core::fmt::Result {
    write!(out, "{PREFIX}stub {module}.{service}({args}): {reason}")
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

    /// A service's unhandled case is a stub line, as the DLLs' are.
    #[test]
    fn an_unhandled_case_is_a_stub_line() {
        let mut line = std::string::String::new();
        write_unhandled(
            &mut line,
            "win32k",
            "NtUserShowWindow",
            format_args!("hWnd=0x{:X}, nCmdShow={}", 0x24, 6),
            format_args!("{} is not yet implemented", "SW_MINIMIZE"),
        )
        .unwrap();
        assert_eq!(
            line,
            "F2K: debug: stub win32k.NtUserShowWindow(hWnd=0x24, nCmdShow=6): SW_MINIMIZE is not \
             yet implemented"
        );
    }

    #[test]
    fn unprintable_bytes_are_escaped() {
        assert_eq!(
            shown(b"tab\there \x1b[0m \xe9"),
            ["tab\\x09here \\x1B[0m \\xE9"]
        );
    }
}
