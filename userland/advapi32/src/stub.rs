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
    // SAFETY: the imports; the format and the line are NUL-terminated.
    unsafe {
        imports::DbgPrint(b"%s\0".as_ptr(), line.terminated().as_ptr());
        match entry.fails {
            Fails::Value(value) => {
                imports::SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
                value
            }
            Fails::Void => 0,
            Fails::Never => {
                imports::RaiseException(
                    STATUS_NOT_IMPLEMENTED,
                    EXCEPTION_NONCONTINUABLE,
                    0,
                    core::ptr::null(),
                );
                // A noncontinuable exception does not resume its raiser.
                unreachable!()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::imports::host::{DEBUG_PRINTS, LAST_ERROR};

    /// A stubbed registry call's generated body logs its arguments (the predefined key as its
    /// handle value, the subkey as text) and answers ERROR_CALL_NOT_IMPLEMENTED.
    #[test]
    fn a_stub_logs_its_call_and_fails() {
        let subkey = b"Software\\F2K\0";
        let mut key = 0u32;
        // SAFETY: the generated body (stdcall), given a NUL-terminated subkey and a result slot.
        let result = unsafe {
            crate::f2k_stub_RegOpenKeyA(
                0x8000_0001,
                subkey.as_ptr() as usize,
                &mut key as *mut u32 as usize,
            )
        };
        assert_eq!(result, 120);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 120);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(printed.len(), 1);
        assert!(
            printed[0].starts_with(
                "stub advapi32.RegOpenKeyA(hKey=0x80000001, lpSubKey=\"Software\\\\F2K\", phkResult="
            ),
            "{}",
            printed[0]
        );
    }
}
