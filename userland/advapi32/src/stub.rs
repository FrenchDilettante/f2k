//! advapi32's stub routine: where a stubbed export's generated body goes (`spec`'s entries and the
//! bodies are generated from exports.toml), and where an implemented export's code goes on a path
//! it does not handle yet, with its own reason (see kernel32's `stub`, whose design this shares).
//!
//! The call is logged through ntdll's DbgPrint (the kernel writes it to COM1: `F2K: debug: stub
//! advapi32.<Export>(<every argument>): <reason>`, see `rtl::stub`), a string argument read where
//! the probe finds it readable, then fails as the export fails: its failure value (a registry
//! call's is the error it returns, ERROR_CALL_NOT_IMPLEMENTED), the last error
//! ERROR_CALL_NOT_IMPLEMENTED. An export that returns nothing (`void`) has no failure to report:
//! it returns. An export that cannot fail (`never`) raises STATUS_NOT_IMPLEMENTED instead, through
//! kernel32's RaiseException (noncontinuable).

use core::ffi::CStr;

// EXCEPTION_NONCONTINUABLE: what a stub that cannot fail raises STATUS_NOT_IMPLEMENTED as.
use rtl::seh::EXCEPTION_NONCONTINUABLE;
use rtl::status::STATUS_NOT_IMPLEMENTED;
use rtl::stub::{describe, Entry, Fails, Line};
// ERROR_CALL_NOT_IMPLEMENTED: "This function is not supported on this system."
use rtl::winerror::ERROR_CALL_NOT_IMPLEMENTED;

use crate::imports::{self, Probed};

/// Log the call to `entry` with `args` (one value per argument, in order) and `reason`, then fail
/// as `entry` fails.
///
/// # Safety
///
/// `args` are the caller's arguments, read as `entry`'s kinds say (a string's pointer is read
/// where its pages can be read).
pub unsafe fn stubbed(entry: &Entry, reason: &str, args: &[u64]) -> u32 {
    let mut line = Line::new();
    let _ = describe(entry, reason, args, &Probed, &mut line);
    if let Ok(text) = CStr::from_bytes_until_nul(line.terminated()) {
        imports::debug_print(text);
    }
    match entry.fails {
        Fails::Value(value) => {
            imports::set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
            value
        }
        Fails::Void => 0,
        Fails::Never => {
            imports::raise_exception(STATUS_NOT_IMPLEMENTED, EXCEPTION_NONCONTINUABLE, &[]);
            // A noncontinuable exception does not resume its raiser.
            unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::imports::host::{DEBUG_PRINTS, LAST_ERROR};

    /// A stubbed call's generated body logs its arguments (the handle as its value) and answers
    /// its failure, the last error ERROR_CALL_NOT_IMPLEMENTED.
    #[test]
    fn a_stub_logs_its_call_and_fails() {
        // SAFETY: the generated body (stdcall), given the handle 0x44.
        let result = unsafe { crate::f2k_stub_CloseServiceHandle(0x44) };
        assert_eq!(result, 0, "FALSE");
        assert_eq!(LAST_ERROR.with(|error| error.get()), 120);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(printed.len(), 1);
        assert!(
            printed[0].starts_with("stub advapi32.CloseServiceHandle(hSCObject=0x00000044"),
            "{}",
            printed[0]
        );
    }
}
