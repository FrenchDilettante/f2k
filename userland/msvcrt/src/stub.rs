//! msvcrt's stub routine: where a stubbed export's generated body goes (`spec`'s entries and the
//! bodies are generated from exports.toml), and where an implemented export's code goes on a path
//! it does not handle yet, with its own reason (see kernel32's `stub`, whose design this shares).
//!
//! The call is logged through ntdll's DbgPrint (the kernel writes it to COM1: `F2K: debug: stub
//! msvcrt.<Export>(<every argument>): <reason>`, see `rtl::stub`), a string argument read where the
//! probe finds it readable, then fails as the export fails: its failure value, the last error
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

    /// A stubbed export's generated body is cdecl, as every msvcrt export: printf's logs its
    /// format and its variable arguments, then answers its failure value with the last error set.
    #[test]
    fn a_stub_logs_its_call_and_fails() {
        let format = b"%d apples\n\0";
        // SAFETY: the generated body, given a NUL-terminated format.
        let result = unsafe { crate::f2k_stub_printf(format.as_ptr() as usize) };
        assert_eq!(result, u32::MAX);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 120);
        let printed = DEBUG_PRINTS.with(|prints| prints.borrow().clone());
        assert_eq!(
            printed,
            ["stub msvcrt.printf(format=\"%d apples\\x0A\", ...): not yet implemented\n"]
        );
    }
}
