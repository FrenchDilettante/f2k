//! The process's end: TerminateProcess, kernel32's own code over ntdll's process service, as on
//! Windows 2000. Only the current process is reachable (its pseudo-handle, or a handle to it): the
//! kernel refuses any other handle (ERROR_INVALID_HANDLE). ExitProcess moves here with the
//! threads' services (B7).

use crate::base::{set_last_error, succeeded};
use crate::nt;

const ERROR_INVALID_HANDLE: u32 = 6;

/// TerminateProcess: NtTerminateProcess on the process its handle names — the caller's own ends it
/// with the code, its loader not told (the C runtime's fatal paths end themselves so); any other
/// handle is ERROR_INVALID_HANDLE (only the calling process is reachable).
#[unsafe(export_name = "f2k_export_TerminateProcess")]
pub extern "system" fn terminate_process(process: u32, code: u32) -> u32 {
    if process == 0 {
        // NtTerminateProcess would take a null handle as the caller's other threads.
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    // SAFETY: ntdll's export.
    succeeded(unsafe { nt::NtTerminateProcess(process, code) })
}
