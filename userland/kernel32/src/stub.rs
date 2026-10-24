//! kernel32's stub routine: where a stubbed export's generated body goes (`spec`'s entries and the
//! bodies are generated from exports.toml), and where an implemented export's code goes on a path
//! it does not handle yet, with its own reason:
//!
//! ```ignore
//! if flags & FILE_FLAG_OVERLAPPED != 0 {
//!     return unsafe { stub::stubbed(&spec::CreateFileW, "K32-9: overlapped I/O", &[name as u64, ...]) };
//! }
//! ```
//!
//! Either way the call is logged through ntdll's DbgPrint (the kernel writes it to COM1: `F2K:
//! debug: stub kernel32.<Export>(<every argument>): <reason>`, see `rtl::stub`), then fails as the
//! export fails: its failure value, the last error ERROR_CALL_NOT_IMPLEMENTED, as Windows 95's
//! kernel32 answered the NT-only calls it exported. An export that cannot fail (`never`) raises
//! STATUS_NOT_IMPLEMENTED instead.

use rtl::stub::{describe, Entry, Fails, Line, Memory};

use crate::base::{set_last_error, CURRENT_PROCESS};
use crate::nt;

/// ERROR_CALL_NOT_IMPLEMENTED: "This function is not supported on this system."
pub const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// STATUS_NOT_IMPLEMENTED: what a stub that cannot fail raises.
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// The calling process's memory, as NtQueryVirtualMemory describes it: a page can be read when it
/// is committed and accessible. The lowest 64 KiB are never mapped.
struct Mapped;

impl Memory for Mapped {
    fn readable(&self, address: usize) -> bool {
        if address < rtl::stub::LOWEST_MAPPED {
            return false;
        }
        let mut info = [0u32; 7];
        let mut returned = 0usize;
        // SAFETY: ntdll's export, over the caller's own structure.
        let status = unsafe {
            nt::NtQueryVirtualMemory(
                CURRENT_PROCESS,
                address,
                0, // MemoryBasicInformation
                info.as_mut_ptr().cast(),
                28,
                &mut returned,
            )
        };
        status == 0 && rtl::stub::readable(info[4], info[5])
    }
}

/// Log the call to `entry` with `args` (one value per argument, in order) and `reason`, then fail
/// as `entry` fails.
///
/// # Safety
///
/// `args` are the caller's arguments, read as `entry`'s kinds say (a string's pointer is read
/// where its pages can be read).
pub unsafe fn stubbed(entry: &Entry, reason: &str, args: &[u64]) -> u32 {
    let mut line = Line::new();
    let _ = describe(entry, reason, args, &Mapped, &mut line);
    // SAFETY: ntdll's export; the format and the line are NUL-terminated.
    unsafe { nt::DbgPrint(b"%s\0".as_ptr(), line.terminated().as_ptr()) };
    match entry.fails {
        Fails::Value(value) => {
            set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
            value
        }
        Fails::Void => {
            set_last_error(ERROR_CALL_NOT_IMPLEMENTED);
            0
        }
        // SAFETY: ntdll's export: it does not return.
        Fails::Never => unsafe { nt::RtlRaiseStatus(STATUS_NOT_IMPLEMENTED) },
    }
}
