//! The process's end, scheduling and error mode: ExitProcess and TerminateProcess, its priority
//! class, its affinity and SetErrorMode — kernel32's own code over ntdll's process services, as on
//! Windows 2000. Only the current process is reachable (its pseudo-handle, or a
//! handle to it): the kernel refuses any other handle (ERROR_INVALID_HANDLE).

use rtl::status::nt_success;

use crate::base::{set_last_error, set_last_nt_error, succeeded, CURRENT_PROCESS};
use crate::nt;

/// PROCESSINFOCLASS: the classes kernel32 asks.
const PROCESS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
const PROCESS_PRIORITY_CLASS: u32 = 18;
const PROCESS_AFFINITY_MASK: u32 = 21;

const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;

/// The *_PRIORITY_CLASS flags, in the order Windows 2000's SetPriorityClass tests them (the first
/// one a value carries wins), with the PROCESS_PRIORITY_CLASS_* value each names.
const PRIORITY_CLASSES: [(u32, u8); 6] = [
    (0x0040, 1), // IDLE_PRIORITY_CLASS
    (0x4000, 5), // BELOW_NORMAL_PRIORITY_CLASS
    (0x0020, 2), // NORMAL_PRIORITY_CLASS
    (0x8000, 6), // ABOVE_NORMAL_PRIORITY_CLASS
    (0x0080, 3), // HIGH_PRIORITY_CLASS
    (0x0100, 4), // REALTIME_PRIORITY_CLASS
];
const NORMAL_PRIORITY_CLASS: u32 = 0x0020;

/// The class a SetPriorityClass value names (its first class flag); none when it names none.
pub fn class_of(flags: u32) -> Option<u8> {
    PRIORITY_CLASSES
        .iter()
        .find(|&&(flag, _)| flags & flag != 0)
        .map(|&(_, class)| class)
}

/// The class flag GetPriorityClass reports for a PROCESS_PRIORITY_CLASS value (anything unknown
/// reads as normal, as on Windows 2000).
pub fn flag_of(class: u8) -> u32 {
    PRIORITY_CLASSES
        .iter()
        .find(|&&(_, c)| c == class)
        .map_or(NORMAL_PRIORITY_CLASS, |&(flag, _)| flag)
}

/// PROCESS_PRIORITY_CLASS: never foreground (no window has the focus), and the class.
#[repr(C)]
#[derive(Default)]
struct PriorityClass {
    foreground: u8,
    class: u8,
}

/// ExitProcess, in Windows 2000's order: under the PEB lock (no other thread is inside a
/// loader-held section as the process goes), every other thread terminated (NtTerminateProcess with
/// no handle), the loader's shutdown (LdrShutdownProcess), then the process ended with the code
/// (NtTerminateProcess of NtCurrentProcess). Windows 2000 also tells the base server (csrss) of the
/// exit between the two; F2K has no base server to tell.
#[unsafe(export_name = "f2k_export_ExitProcess")]
pub extern "system" fn exit_process(code: u32) -> ! {
    // SAFETY: ntdll's exports.
    unsafe {
        nt::RtlAcquirePebLock();
        nt::NtTerminateProcess(0, code);
        nt::LdrShutdownProcess();
        nt::NtTerminateProcess(CURRENT_PROCESS, code);
    }
    // NtTerminateProcess of the caller does not return.
    loop {
        core::hint::spin_loop();
    }
}

/// ExitProcess's body for kernel32's own assembly (src/start.s: the start frames' exception
/// branch).
#[unsafe(no_mangle)]
pub extern "C" fn f2k_k32_exit_process(code: u32) -> ! {
    exit_process(code)
}

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

/// GetPriorityClass: ProcessPriorityClass as its class flag; zero with the status's error.
#[unsafe(export_name = "f2k_export_GetPriorityClass")]
pub extern "system" fn get_priority_class(process: u32) -> u32 {
    let mut class = PriorityClass::default();
    // SAFETY: ntdll's export, over the structure above.
    let status = unsafe {
        nt::NtQueryInformationProcess(
            process,
            PROCESS_PRIORITY_CLASS,
            (&mut class as *mut PriorityClass).cast(),
            2,
            core::ptr::null_mut(),
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    flag_of(class.class)
}

/// SetPriorityClass: the class the value's first class flag names, through ProcessPriorityClass
/// (every thread's priority moves with the process's base); ERROR_INVALID_PARAMETER for a value
/// naming no class. (Windows 2000 falls back to the high class when the realtime one's privilege
/// cannot be had; F2K has no privileges to refuse.)
#[unsafe(export_name = "f2k_export_SetPriorityClass")]
pub extern "system" fn set_priority_class(process: u32, flags: u32) -> u32 {
    let Some(class) = class_of(flags) else {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let class = PriorityClass {
        foreground: 0,
        class,
    };
    // SAFETY: ntdll's export, over the structure above.
    succeeded(unsafe {
        nt::NtSetInformationProcess(
            process,
            PROCESS_PRIORITY_CLASS,
            (&class as *const PriorityClass).cast(),
            2,
        )
    })
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

/// SEM_FAILCRITICALERRORS: the one mode bit the process's hard-error mode stores inverted (its
/// hard-error mode's 1 is "report hard errors").
const SEM_FAILCRITICALERRORS: u32 = 0x0001;

/// GetErrorMode (Windows 2000's internal one): ProcessDefaultHardErrorMode, its
/// SEM_FAILCRITICALERRORS bit inverted; zero with the status's error.
fn error_mode() -> u32 {
    let mut mode = 0u32;
    // SAFETY: ntdll's export, over the value above.
    let status = unsafe {
        nt::NtQueryInformationProcess(
            CURRENT_PROCESS,
            PROCESS_DEFAULT_HARD_ERROR_MODE,
            (&mut mode as *mut u32).cast(),
            4,
            core::ptr::null_mut(),
        )
    };
    if !nt_success(status) {
        set_last_nt_error(status);
        return 0;
    }
    mode ^ SEM_FAILCRITICALERRORS
}

/// SetErrorMode: the previous mode, the new one stored as the process's hard-error mode (its
/// SEM_FAILCRITICALERRORS bit inverted). No hard-error or fault dialog exists to suppress — a fault
/// ends the process with its status either way — so the mode only round-trips.
#[unsafe(export_name = "f2k_export_SetErrorMode")]
pub extern "system" fn set_error_mode(mode: u32) -> u32 {
    let previous = error_mode();
    let stored = mode ^ SEM_FAILCRITICALERRORS;
    // SAFETY: ntdll's export, over the value above; a refusal leaves the mode (and the last error)
    // as they were, as on Windows 2000.
    let _ = unsafe {
        nt::NtSetInformationProcess(
            CURRENT_PROCESS,
            PROCESS_DEFAULT_HARD_ERROR_MODE,
            (&stored as *const u32).cast(),
            4,
        )
    };
    previous
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SetPriorityClass takes the first class flag a value carries (the threads fixture's 0x12345
    /// succeeds: it carries IDLE's 0x40); GetPriorityClass names the class by its flag.
    #[test]
    fn class_flags_name_priority_classes() {
        assert_eq!(class_of(0x20), Some(2));
        assert_eq!(class_of(0x80), Some(3));
        assert_eq!(class_of(0x12345), Some(1));
        assert_eq!(class_of(0x1), None);
        for (flag, class) in PRIORITY_CLASSES {
            assert_eq!(flag_of(class), flag);
        }
        assert_eq!(flag_of(0), NORMAL_PRIORITY_CLASS);
    }
}
