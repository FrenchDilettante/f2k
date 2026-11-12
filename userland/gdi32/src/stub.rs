//! gdi32's stub routine: where a stubbed export's generated body goes (`spec`'s entries and the
//! bodies are generated from exports.toml), and where an implemented export's code goes on a path
//! it does not handle yet, with its own reason (see kernel32's `stub`, whose design this shares).
//!
//! The call is logged through ntdll's DbgPrint (the kernel writes it to COM1: `F2K: debug: stub
//! gdi32.<Export>(<every argument>): <reason>`, see `rtl::stub`), a string argument read where the
//! probe finds it readable, then fails as the export fails: its failure value, the last error
//! ERROR_CALL_NOT_IMPLEMENTED. An export that returns nothing (`void`) has no failure to report:
//! it returns. An export that cannot fail (`never`) ends in an invalid opcode instead, as a panic
//! in the system DLLs' code does: Windows 2000's gdi32 imports neither kernel32's RaiseException
//! nor ntdll's raises.
//!
//! An implemented export that meets a case F2K does not handle yet, but carries on (or fails as its
//! own code fails), logs the same line and nothing more ([`unhandled`]): its outcome is its own. A
//! site a program may reach in a loop keeps an [`rtl::stub::Logged`] set beside it, so it logs each
//! case once per process.

use core::ffi::CStr;
use core::fmt::Display;

use rtl::stub::{describe, Entry, Fails, Line};

use crate::imports::{self, Probed};

/// ERROR_CALL_NOT_IMPLEMENTED: "This function is not supported on this system."
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// Log the call to `entry` with `args` (one value per argument, in order) and `reason`, then fail
/// as `entry` fails.
///
/// # Safety
///
/// `args` are the caller's arguments, read as `entry`'s kinds say (a string's pointer is read
/// where its pages can be read).
pub unsafe fn stubbed(entry: &Entry, reason: &str, args: &[u64]) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { unhandled(entry, reason, args) };
    match entry.fails {
        Fails::Value(value) => {
            imports::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
            value
        }
        Fails::Void => 0,
        Fails::Never => panic!("{}.{}: not implemented", entry.dll, entry.name),
    }
}

/// Log the call to `entry` with `args` (one value per argument, in order) and `reason`, the case of
/// it F2K does not handle yet: the line alone, the call's outcome left to its code (no last error
/// set, nothing answered).
///
/// # Safety
///
/// As [`stubbed`]'s: `args` are the caller's arguments, read as `entry`'s kinds say.
pub unsafe fn unhandled(entry: &Entry, reason: impl Display, args: &[u64]) {
    let mut line = Line::new();
    let _ = describe(entry, reason, args, &Probed, &mut line);
    if let Ok(text) = CStr::from_bytes_until_nul(line.terminated()) {
        imports::debug_print(text);
    }
}

/// [`unhandled`] once per process for the case `key` of a site's `logged` set: a path a program
/// may take in a loop (a paint) logs each of its cases once.
///
/// # Safety
///
/// As [`unhandled`]'s.
pub unsafe fn unhandled_once<const N: usize>(
    logged: &rtl::stub::Logged<N>,
    key: u32,
    entry: &Entry,
    reason: impl Display,
    args: &[u64],
) {
    if logged.first(key) {
        // SAFETY: the caller's contract.
        unsafe { unhandled(entry, reason, args) };
    }
}

#[cfg(test)]
mod tests {
    use crate::imports::host::{DEBUG_PRINTS, LAST_ERROR};

    /// The stub routine logs the call's arguments and answers the export's failure value.
    #[test]
    fn a_stub_logs_its_call_and_fails() {
        // SAFETY: the arguments as SetBkMode's kinds read them.
        let result =
            unsafe { super::stubbed(&crate::spec::SetBkMode, "not yet implemented", &[0x7C, 3]) };
        assert_eq!(result, 0);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 120);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(
            printed,
            ["stub gdi32.SetBkMode(hdc=0x7C, iBkMode=3): not yet implemented\n"]
        );
    }
}
