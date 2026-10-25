//! The processes' calls over ntdll's process services, as on Windows 2000: ExitProcess and
//! TerminateProcess, OpenProcess and GetExitCodeProcess, ReadProcessMemory and
//! WriteProcessMemory, the priority class, the affinity and SetErrorMode. A process is named by
//! its handle (the current one's pseudo-handle, or a handle CreateProcess or OpenProcess handed
//! out); the kernel checks the handle's access and answers for the process (CreateProcess itself
//! is [`crate::create`]'s).

use rtl::status::nt_success;

use crate::base::{set_last_error, set_last_nt_error, succeeded, CURRENT_PROCESS};
use crate::nt::{self, ClientId};
use crate::ntcall::{self, Destination, Source};

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

/// TerminateProcess: NtTerminateProcess on the process its handle names, ended with the code — the
/// caller's own, its loader not told (the C runtime's fatal paths end themselves so), or another
/// (a child, a process OpenProcess opened: the kernel refuses a handle without PROCESS_TERMINATE,
/// and a process already ended, ERROR_ACCESS_DENIED both). A null handle names no process here
/// (NtTerminateProcess would take it as the caller's other threads): ERROR_INVALID_HANDLE.
#[unsafe(export_name = "f2k_export_TerminateProcess")]
pub extern "system" fn terminate_process(process: u32, code: u32) -> u32 {
    if process == 0 {
        set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    match ntcall::terminate_process(process, code) {
        Ok(()) => 1,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// OpenProcess: a handle with the access to the process the id names (NtOpenProcess by CLIENT_ID,
/// no thread), inheritable when asked (OBJ_INHERIT); NULL with the error otherwise — a process id
/// naming no process, zero included, is ERROR_INVALID_PARAMETER (the kernel's
/// STATUS_INVALID_CID).
#[unsafe(export_name = "f2k_export_OpenProcess")]
pub extern "system" fn open_process(access: u32, inherit: u32, process_id: u32) -> u32 {
    let attributes = ntcall::unnamed_attributes(inherit != 0, core::ptr::null());
    let client_id = ClientId {
        unique_process: process_id as usize,
        unique_thread: 0,
    };
    match ntcall::open_process(access, &attributes, &client_id) {
        Ok(process) => process,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// STILL_ACTIVE: the exit code of a process still running (STATUS_PENDING).
pub const STILL_ACTIVE: u32 = 259;

/// GetExitCodeProcess: the process's exit status (ProcessBasicInformation's ExitStatus:
/// STILL_ACTIVE while it runs) into `*code`; FALSE with the status's error when the handle cannot
/// be queried (PROCESS_QUERY_INFORMATION). A null `code` faults the caller, as Windows 2000's
/// writes through it.
///
/// # Safety
///
/// `code` is writable.
#[unsafe(export_name = "f2k_export_GetExitCodeProcess")]
pub unsafe extern "system" fn get_exit_code_process(process: u32, code: *mut u32) -> u32 {
    // SAFETY: the caller's slot.
    let Some(code) = (unsafe { code.as_mut() }) else {
        ntcall::raise_status(rtl::status::STATUS_ACCESS_VIOLATION);
    };
    match ntcall::basic_information(process) {
        Ok(information) => {
            *code = information.exit_status;
            1
        }
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// ReadProcessMemory: `size` bytes of the process at `address` into the caller's buffer
/// (NtReadVirtualMemory, PROCESS_VM_READ), the count the service settles on written where asked
/// (a partial copy's too, ERROR_PARTIAL_COPY; an address the service refuses outright leaves it
/// untouched); FALSE with the status's error on any failure.
///
/// # Safety
///
/// `buffer` is the caller's, of `size` bytes, and `count` null or writable (the service probes
/// both: a bad pointer is its error, not a fault).
#[unsafe(export_name = "f2k_export_ReadProcessMemory")]
pub unsafe extern "system" fn read_process_memory(
    process: u32,
    address: usize,
    buffer: *mut u8,
    size: u32,
    count: *mut u32,
) -> u32 {
    // SAFETY: the caller's buffer and count, as the contract says.
    let (destination, count) = unsafe {
        (
            Destination::caller(buffer as usize, size as usize),
            count.as_mut(),
        )
    };
    match ntcall::read_virtual_memory(process, address, destination, count) {
        Ok(()) => 1,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// The page protections WriteProcessMemory tells apart: those that let a write through, and those
/// it refuses to write past (read-only data, no access).
const WRITABLE: u32 = 0x04 | 0x08 | 0x40 | 0x80;
const READ_ONLY: u32 = 0x01 | 0x02;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
/// The protection's modifiers (PAGE_GUARD, PAGE_NOCACHE), set beside its kind.
const PROTECTION_KIND: u32 = 0xFF;

/// ERROR_NOACCESS: what a write into read-only memory is.
const ERROR_NOACCESS: u32 = 998;

/// WriteProcessMemory, as Windows 2000's: the range made writable first (NtProtectVirtualMemory to
/// PAGE_EXECUTE_READWRITE: its refusal's error is the call's — a range not all allocated, a
/// handle without PROCESS_VM_OPERATION). Pages that were writable get their protection back and
/// the bytes written (NtWriteVirtualMemory); pages that were read-only or not accessible get it
/// back and the call fails with ERROR_NOACCESS, nothing written (spawn's capture: the image's
/// read-only header); code pages (execute, execute-read) are written under the temporary
/// protection, then get theirs back. The count is written where asked once a write was tried.
/// Windows 2000 then flushes the instruction cache (NtFlushInstructionCache); ntdll does not
/// export it yet, and on F2K's one i386 processor a write is seen by the next fetch anyway.
///
/// # Safety
///
/// `buffer` is the caller's, of `size` bytes, and `count` null or writable (the service probes
/// the buffer).
#[unsafe(export_name = "f2k_export_WriteProcessMemory")]
pub unsafe extern "system" fn write_process_memory(
    process: u32,
    address: usize,
    buffer: *const u8,
    size: u32,
    count: *mut u32,
) -> u32 {
    // SAFETY: the caller's buffer and count, as the contract says.
    let (source, count) = unsafe {
        (
            Source::caller(buffer as usize, size as usize),
            count.as_mut(),
        )
    };
    let length = size as usize;
    let old = match ntcall::protect_virtual_memory(process, address, length, PAGE_EXECUTE_READWRITE)
    {
        Ok(old) => old,
        Err(status) => {
            set_last_nt_error(status);
            return 0;
        }
    };
    let restore = || {
        let _ = ntcall::protect_virtual_memory(process, address, length, old);
    };
    let kind = old & PROTECTION_KIND;
    let written = if kind & WRITABLE != 0 {
        restore();
        ntcall::write_virtual_memory(process, address, source, count)
    } else if kind & READ_ONLY != 0 {
        restore();
        set_last_error(ERROR_NOACCESS);
        return 0;
    } else {
        let written = ntcall::write_virtual_memory(process, address, source, count);
        restore();
        written
    };
    match written {
        Ok(()) => 1,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
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
