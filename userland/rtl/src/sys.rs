//! The calling thread's system, for user-mode runtime code: its TEB, through FS (the TEB segment's
//! base is the thread's TEB, as on Windows 2000).

use core::arch::asm;

/// The TEB's LastErrorValue.
const TEB_LAST_ERROR_VALUE: u32 = 0x34;
/// The TEB's LastStatusValue (NT 5.0, x86).
const TEB_LAST_STATUS_VALUE: u32 = 0xBF4;

/// Record `status` as the calling thread's last status (its TEB's LastStatusValue, which
/// RtlNtStatusToDosError keeps).
pub fn set_last_status(status: u32) {
    // SAFETY: FS addresses the calling thread's TEB, mapped for its whole life.
    unsafe {
        asm!("mov dword ptr fs:[{offset}], {status}", status = in(reg) status,
             offset = const TEB_LAST_STATUS_VALUE, options(nostack, preserves_flags));
    }
}

/// Set the calling thread's last error (its TEB's LastErrorValue).
pub fn set_last_error(code: u32) {
    // SAFETY: FS addresses the calling thread's TEB, mapped for its whole life.
    unsafe {
        asm!("mov dword ptr fs:[{offset}], {code}", code = in(reg) code,
             offset = const TEB_LAST_ERROR_VALUE, options(nostack, preserves_flags));
    }
}
