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

use rtl::stub::{describe, Entry, Fails, Line};

use crate::imports::{self, Probed};

/// ERROR_CALL_NOT_IMPLEMENTED: "This function is not supported on this system."
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// STATUS_NOT_IMPLEMENTED: what a stub that cannot fail raises, and EXCEPTION_NONCONTINUABLE.
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const EXCEPTION_NONCONTINUABLE: u32 = 1;

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

    /// A stubbed call's generated body logs its arguments (the handle as its value, the provider as
    /// text) and answers its failure, the last error ERROR_CALL_NOT_IMPLEMENTED.
    #[test]
    fn a_stub_logs_its_call_and_fails() {
        let provider: Vec<u16> = "Windows NT Access Provider\0".encode_utf16().collect();
        // SAFETY: the generated body (stdcall), given a NUL-terminated provider and null slots.
        let result = unsafe {
            crate::f2k_stub_GetSecurityInfoExW(
                0x44,
                1,
                4,
                provider.as_ptr() as usize,
                0,
                0,
                0,
                0,
                0,
            )
        };
        assert_eq!(result, 1204, "ERROR_BAD_PROVIDER");
        assert_eq!(LAST_ERROR.with(|error| error.get()), 120);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(printed.len(), 1);
        assert!(
            printed[0].starts_with(
                "stub advapi32.GetSecurityInfoExW(hObject=0x44, ObjectType=0x1, SecurityInfo=0x4, \
                 lpProvider=\"Windows NT Access Provider\", "
            ),
            "{}",
            printed[0]
        );
    }
}
