//! ntdll's stub routine: where a stubbed export's generated body goes, and an implemented export's
//! code on a path it does not handle yet (see kernel32's `stub`, whose design this shares). The
//! call is logged on the debugger's channel (`rtl::stub`'s line, straight to the kernel: ntdll is
//! where DbgPrint lives), then fails with the export's failure value; ntdll's exports set no
//! Win32 last error. An export that cannot fail (`never`) raises STATUS_NOT_IMPLEMENTED.

use rtl::stub::{describe, Entry, Fails, Line, Memory};

use crate::service;

/// STATUS_NOT_IMPLEMENTED: what a stub that cannot fail raises.
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// The calling process's memory, as NtQueryVirtualMemory describes it: a page can be read when it
/// is committed and accessible. The lowest 64 KiB are never mapped.
pub struct Mapped;

impl Memory for Mapped {
    fn readable(&self, address: usize) -> bool {
        if address < rtl::stub::LOWEST_MAPPED {
            return false;
        }
        service::query_virtual_memory(address)
            .is_ok_and(|info| rtl::stub::readable(info.state, info.protect))
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
    let shown = line.terminated();
    crate::dbgprint::print(&shown[..shown.len() - 1]);
    match entry.fails {
        Fails::Value(value) => value,
        Fails::Void => 0,
        // SAFETY: the raise does not return.
        Fails::Never => unsafe { rtl::sys::raise_status(STATUS_NOT_IMPLEMENTED) },
    }
}
