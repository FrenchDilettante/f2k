//! The process's end and affinity: TerminateProcess and SetProcessAffinityMask, kernel32's own code
//! over ntdll's process services, as on Windows 2000. Only the current process is reachable (its
//! pseudo-handle, or a handle to it): the kernel refuses any other handle (ERROR_INVALID_HANDLE).
//! ExitProcess, the priority class and SetErrorMode move here with the threads' services.

use crate::base::{set_last_error, succeeded};
use crate::nt;

const ERROR_INVALID_HANDLE: u32 = 6;

/// PROCESSINFOCLASS: the class kernel32 sets.
const PROCESS_AFFINITY_MASK: u32 = 21;

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

/// SetProcessAffinityMask: ProcessAffinityMask (a non-empty subset of the one processor, which
/// changes nothing; ERROR_INVALID_PARAMETER otherwise).
#[unsafe(export_name = "f2k_export_SetProcessAffinityMask")]
pub extern "system" fn set_process_affinity_mask(process: u32, mask: u32) -> u32 {
    // SAFETY: ntdll's export, over the mask.
    succeeded(unsafe {
        nt::NtSetInformationProcess(
            process,
            PROCESS_AFFINITY_MASK,
            (&mask as *const u32).cast(),
            4,
        )
    })
}
