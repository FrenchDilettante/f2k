//! The processes' calls over ntdll's process services, as on Windows 2000: ExitProcess and
//! TerminateProcess, OpenProcess and GetExitCodeProcess, ReadProcessMemory and
//! WriteProcessMemory, the priority class, the affinity, a process's version and SetErrorMode. A
//! process is named by its handle (the current one's pseudo-handle, or a handle CreateProcess or
//! OpenProcess handed out); the kernel checks the handle's access and answers for the process
//! (CreateProcess itself is [`crate::create`]'s).

use core::mem::offset_of;

use rtl::image::{self, ImageDosHeader, ImageNtHeaders32};
use rtl::peb::Peb;
use rtl::pod::Pod;

use crate::base::{
    current_process_id,
    image_base,
    set_last_error,
    set_last_nt_error,
    win32_bool,
    CURRENT_PROCESS,
};
use crate::edge::Out;
use crate::error::{answer, bool_answer, Failure};
use crate::nt::ClientId;
use crate::ntcall::{self, Destination, PebLock, PriorityClass, Source};

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

/// ExitProcess, in Windows 2000's order: under the PEB lock (no other thread is inside a
/// loader-held section as the process goes), every other thread terminated (NtTerminateProcess with
/// no handle), the loader's shutdown (LdrShutdownProcess), then the process ended with the code
/// (NtTerminateProcess of NtCurrentProcess). Windows 2000 also tells the base server (csrss) of the
/// exit between the two; F2K has no base server to tell.
#[unsafe(export_name = "f2k_export_ExitProcess")]
pub extern "system" fn exit_process(code: u32) -> ! {
    // Held to the end: the process goes with it.
    let _lock = PebLock::acquire();
    let _ = ntcall::terminate_process(0, code);
    ntcall::shutdown_process();
    let _ = ntcall::terminate_process(CURRENT_PROCESS, code);
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
    // SAFETY: the caller's slot (the contract), or null.
    let code = unsafe { Out::optional(code) };
    bool_answer(exit_code(process, code))
}

/// GetExitCodeProcess's work.
fn exit_code(process: u32, code: Option<Out<'_, u32>>) -> Result<(), Failure> {
    let mut code = code.ok_or(Failure::Fault(rtl::status::STATUS_ACCESS_VIOLATION))?;
    let information = ntcall::basic_information(process).map_err(Failure::Status)?;
    code.set(information.exit_status);
    Ok(())
}

/// ReadProcessMemory: `size` bytes of the process at `address` into the caller's buffer
/// (NtReadVirtualMemory, PROCESS_VM_READ), the count the service settles on written where asked
/// (a copy that fails part-way, ERROR_PARTIAL_COPY or ERROR_NOACCESS, counts 0; an address the
/// service refuses outright leaves it untouched); FALSE with the status's error on any failure.
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
    let (destination, mut count) = unsafe {
        (
            Destination::caller(buffer as usize, size as usize),
            Out::optional(count),
        )
    };
    match ntcall::read_virtual_memory(process, address, destination, count.as_mut()) {
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
/// protection, then get theirs back. The count is written where asked once a write was tried. A
/// write tried, the process's instruction cache is flushed over the range
/// (NtFlushInstructionCache), as Windows 2000's does: the bytes may be code; the flush's own
/// status does not change the call's.
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
    let (source, mut count) = unsafe {
        (
            Source::caller(buffer as usize, size as usize),
            Out::optional(count),
        )
    };
    bool_answer(write_memory(process, address, source, count.as_mut()))
}

/// WriteProcessMemory's work.
fn write_memory(
    process: u32,
    address: usize,
    source: Source<'_>,
    count: Option<&mut Out<'_, u32>>,
) -> Result<(), Failure> {
    let length = source.len();
    let old = ntcall::protect_virtual_memory(process, address, length, PAGE_EXECUTE_READWRITE)
        .map_err(Failure::Status)?;
    let restore = || {
        let _ = ntcall::protect_virtual_memory(process, address, length, old);
    };
    let kind = old & PROTECTION_KIND;
    let written = if kind & WRITABLE != 0 {
        restore();
        ntcall::write_virtual_memory(process, address, source, count)
    } else if kind & READ_ONLY != 0 {
        restore();
        return Err(Failure::Error(ERROR_NOACCESS));
    } else {
        let written = ntcall::write_virtual_memory(process, address, source, count);
        restore();
        written
    };
    let _ = ntcall::flush_instruction_cache(process, address, length);
    written.map_err(Failure::Status)
}

/// FlushInstructionCache: the process's instruction cache over `[address, address + size)` made
/// to see the writes to its memory (NtFlushInstructionCache, PROCESS_VM_WRITE); TRUE, or FALSE with
/// the status's error.
#[unsafe(export_name = "f2k_export_FlushInstructionCache")]
pub extern "system" fn flush_instruction_cache(process: u32, address: usize, size: u32) -> u32 {
    match ntcall::flush_instruction_cache(process, address, size as usize) {
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
    match ntcall::query_process::<PriorityClass>(process, PROCESS_PRIORITY_CLASS) {
        Ok(class) => flag_of(class.class),
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
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
    // Never foreground: no window has the focus.
    let class = PriorityClass {
        foreground: 0,
        class,
    };
    win32_bool(ntcall::set_process(process, PROCESS_PRIORITY_CLASS, &class))
}

/// SYSTEM_BASIC_INFORMATION, NtQuerySystemInformation's class 0, as dwords (44 bytes), and the
/// index of its ActiveProcessorsAffinityMask.
const SYSTEM_BASIC_INFORMATION: u32 = 0;
const SYSTEM_BASIC_WORDS: usize = 11;
const ACTIVE_PROCESSORS_AFFINITY_MASK: usize = 9;

/// GetProcessAffinityMask: the process's affinity (ProcessBasicInformation,
/// PROCESS_QUERY_INFORMATION) and the system's, its active processors (Windows 2000 reads them from
/// the base server's copy of the system's basic information, csrss's query at its start; F2K asks
/// the same query), each written where asked; FALSE with the status's error otherwise. A bad
/// pointer faults the caller.
///
/// # Safety
///
/// `process_mask` and `system_mask` are writable.
#[unsafe(export_name = "f2k_export_GetProcessAffinityMask")]
pub unsafe extern "system" fn get_process_affinity_mask(
    process: u32,
    process_mask: *mut u32,
    system_mask: *mut u32,
) -> u32 {
    // SAFETY: the caller's slots (the contract), or null.
    let (process_mask, system_mask) =
        unsafe { (Out::optional(process_mask), Out::optional(system_mask)) };
    bool_answer(affinity_masks(process, process_mask, system_mask))
}

/// GetProcessAffinityMask's work.
fn affinity_masks(
    process: u32,
    process_mask: Option<Out<'_, u32>>,
    system_mask: Option<Out<'_, u32>>,
) -> Result<(), Failure> {
    let information = ntcall::basic_information(process).map_err(Failure::Status)?;
    let basic =
        ntcall::query_system_information::<[u32; SYSTEM_BASIC_WORDS]>(SYSTEM_BASIC_INFORMATION)
            .map_err(Failure::Status)?;
    let fault = Failure::Fault(rtl::status::STATUS_ACCESS_VIOLATION);
    process_mask.ok_or(fault)?.set(information.affinity_mask);
    system_mask
        .ok_or(fault)?
        .set(basic[ACTIVE_PROCESSORS_AFFINITY_MASK]);
    Ok(())
}

/// SetProcessAffinityMask: ProcessAffinityMask (a non-empty subset of the one processor, which
/// changes nothing; ERROR_INVALID_PARAMETER otherwise).
#[unsafe(export_name = "f2k_export_SetProcessAffinityMask")]
pub extern "system" fn set_process_affinity_mask(process: u32, mask: u32) -> u32 {
    win32_bool(ntcall::set_process(process, PROCESS_AFFINITY_MASK, &mask))
}

/// What GetProcessVersion opens another process for: its PEB's address (PROCESS_QUERY_INFORMATION)
/// and its memory (PROCESS_VM_READ).
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

/// GetProcessVersion: the Windows version the process's image is built for, its subsystem version
/// as MAKELONG(minor, major) — the calling process's (an id of 0, or its own) from its image's
/// headers (the PEB's ImageBaseAddress, RtlImageNtHeader); another's read out of it, as Windows
/// 2000's kernel32 reads it (OpenProcess, ProcessBasicInformation's PEB, NtReadVirtualMemory of
/// its image base, DOS header and NT headers). 0 with the error otherwise: OpenProcess's for an id
/// naming no process (ERROR_INVALID_PARAMETER), the service's status for a query or read refused,
/// ERROR_BAD_EXE_FORMAT for an image without PE headers.
#[unsafe(export_name = "f2k_export_GetProcessVersion")]
pub extern "system" fn get_process_version(process_id: u32) -> u32 {
    answer(process_version(process_id), 0)
}

/// GetProcessVersion's work.
fn process_version(process_id: u32) -> Result<u32, Failure> {
    if process_id == 0 || process_id == current_process_id() {
        let headers = ntcall::image_nt_header(image_base()).ok_or(BAD_IMAGE)?;
        return Ok(subsystem_version(&headers));
    }
    let attributes = ntcall::unnamed_attributes(false, core::ptr::null());
    let client_id = ClientId {
        unique_process: process_id as usize,
        unique_thread: 0,
    };
    let process = ntcall::open_process(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &attributes,
        &client_id,
    )
    .map_err(Failure::Status)?;
    let version = remote_version(process);
    let _ = ntcall::close(process);
    version
}

/// An image without PE headers: ERROR_BAD_EXE_FORMAT.
const BAD_IMAGE: Failure = Failure::Error(193);

/// The subsystem version an image's NT headers carry, MAKELONG(minor, major).
fn subsystem_version(headers: &ImageNtHeaders32) -> u32 {
    let optional = &headers.optional_header;
    u32::from(optional.major_subsystem_version) << 16 | u32::from(optional.minor_subsystem_version)
}

/// Another process's subsystem version, out of its memory through the open handle.
fn remote_version(process: u32) -> Result<u32, Failure> {
    let peb = ntcall::basic_information(process)
        .map_err(Failure::Status)?
        .peb_base_address;
    let image_base: u32 = remote(
        process,
        peb as usize + offset_of!(Peb<u32>, image_base_address),
    )?;
    let dos: ImageDosHeader = remote(process, image_base as usize)?;
    let offset = image::nt_headers_offset(&dos).ok_or(BAD_IMAGE)?;
    let headers: ImageNtHeaders32 = remote(process, image_base as usize + offset)?;
    if headers.signature != image::NT_SIGNATURE {
        return Err(BAD_IMAGE);
    }
    Ok(subsystem_version(&headers))
}

/// A `T` out of another process's memory at `address` (NtReadVirtualMemory).
fn remote<T: Pod>(process: u32, address: usize) -> Result<T, Failure> {
    let mut value = T::zeroed();
    let destination = Destination::of(value.as_bytes_mut());
    ntcall::read_virtual_memory(process, address, destination, None).map_err(Failure::Status)?;
    Ok(value)
}

/// SetProcessShutdownParameters: the calling process's shutdown level (the order the session's end
/// asks the processes in, the highest first: 0x100-0x1FF last, 0x200-0x2FF in between, 0x300-0x3FF
/// first) and flags (SHUTDOWN_NORETRY), sent to the base server (BasepSetProcessShutdownParam),
/// which keeps them, as Windows 2000's kernel32 sends them to csrss. As Windows 2000's, the server
/// keeps any level, the documentation's ranges notwithstanding, and leaves the parameters as they
/// were for a flag bit other than SHUTDOWN_NORETRY, TRUE either way with the last error untouched;
/// FALSE with the server's status's error should the call itself fail.
#[unsafe(export_name = "f2k_export_SetProcessShutdownParameters")]
pub extern "system" fn set_process_shutdown_parameters(level: u32, flags: u32) -> u32 {
    use rtl::console::base::{ShutdownParameters, SET_PROCESS_SHUTDOWN_PARAM};
    let mut message = ShutdownParameters::<usize> {
        level: level as usize,
        flags: flags as usize,
    };
    let status = crate::console::call_csr(SET_PROCESS_SHUTDOWN_PARAM, message.as_bytes_mut());
    bool_answer(nt_result(status))
}

/// GetProcessShutdownParameters: the calling process's shutdown level and flags, as the base
/// server keeps them (BasepGetProcessShutdownParam: 0x280 and none until the process sets its
/// own), written to the caller's places, as Windows 2000's kernel32 writes them (a place it cannot
/// reach faults it); FALSE with the server's status's error.
///
/// # Safety
///
/// `level` and `flags` are writable.
#[unsafe(export_name = "f2k_export_GetProcessShutdownParameters")]
pub unsafe extern "system" fn get_process_shutdown_parameters(
    level: *mut u32,
    flags: *mut u32,
) -> u32 {
    // SAFETY: the caller's places (the contract); one it cannot reach faults it, as on Windows.
    let (level, flags) = unsafe { (Out::new(level), Out::new(flags)) };
    bool_answer(shutdown_parameters(level, flags))
}

/// GetProcessShutdownParameters' work.
fn shutdown_parameters(mut level: Out<'_, u32>, mut flags: Out<'_, u32>) -> Result<(), Failure> {
    use rtl::console::base::{ShutdownParameters, GET_PROCESS_SHUTDOWN_PARAM};
    let mut message = ShutdownParameters::<usize>::default();
    let status = crate::console::call_csr(GET_PROCESS_SHUTDOWN_PARAM, message.as_bytes_mut());
    nt_result(status)?;
    level.set(message.level as u32);
    flags.set(message.flags as u32);
    Ok(())
}

/// A server's status as a result: its failure reported as its error (BaseSetLastNTError).
fn nt_result(status: u32) -> Result<(), Failure> {
    if rtl::status::nt_success(status) {
        Ok(())
    } else {
        Err(Failure::Status(status))
    }
}

/// SEM_FAILCRITICALERRORS: the one mode bit the process's hard-error mode stores inverted (its
/// hard-error mode's 1 is "report hard errors").
const SEM_FAILCRITICALERRORS: u32 = 0x0001;

/// GetErrorMode (Windows 2000's internal one): ProcessDefaultHardErrorMode, its
/// SEM_FAILCRITICALERRORS bit inverted; zero with the status's error.
fn error_mode() -> u32 {
    match ntcall::query_process::<u32>(CURRENT_PROCESS, PROCESS_DEFAULT_HARD_ERROR_MODE) {
        Ok(mode) => mode ^ SEM_FAILCRITICALERRORS,
        Err(status) => {
            set_last_nt_error(status);
            0
        }
    }
}

/// SetErrorMode: the previous mode, the new one stored as the process's hard-error mode (its
/// SEM_FAILCRITICALERRORS bit inverted). No hard-error or fault dialog exists to suppress — a fault
/// ends the process with its status either way — so the mode only round-trips.
#[unsafe(export_name = "f2k_export_SetErrorMode")]
pub extern "system" fn set_error_mode(mode: u32) -> u32 {
    let previous = error_mode();
    let stored = mode ^ SEM_FAILCRITICALERRORS;
    // A refusal leaves the mode (and the last error) as they were, as on Windows 2000.
    let _ = ntcall::set_process(CURRENT_PROCESS, PROCESS_DEFAULT_HARD_ERROR_MODE, &stored);
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

    /// SetProcessShutdownParameters and GetProcessShutdownParameters, as the shutparm fixture's
    /// capture shows them: the defaults (0x280, no flag) to start; each band's edges, with and
    /// without SHUTDOWN_NORETRY, read back as set; levels outside 0x100-0x3FF kept all the same;
    /// a flag bit other than SHUTDOWN_NORETRY TRUE, the last error untouched, the parameters kept
    /// as they were.
    #[test]
    fn shutdown_parameters_round_trip() {
        use crate::base::last_error;
        const UNTOUCHED: u32 = 0x0F2F_2F2F;
        let get = || {
            let (mut level, mut flags) = (0xDEAD_BEEF, 0xDEAD_BEEF);
            // SAFETY: two places of the test's.
            let ok = unsafe { get_process_shutdown_parameters(&mut level, &mut flags) };
            assert_eq!(ok, 1);
            (level, flags)
        };
        let set = |level, flags| {
            set_last_error(UNTOUCHED);
            assert_eq!(set_process_shutdown_parameters(level, flags), 1);
            assert_eq!(last_error(), UNTOUCHED, "{level:#x} {flags:#x}");
        };
        assert_eq!(get(), (0x280, 0));
        for level in [0x100, 0x1FF, 0x200, 0x2FF, 0x300, 0x3FF] {
            for flags in [0, 1] {
                set(level, flags);
                assert_eq!(get(), (level, flags));
            }
        }
        for level in [0, 0x1, 0xFF, 0x400, 0x4FF, 0x1_0000, 0xFFFF_FFFF] {
            set(level, 0);
            assert_eq!(get(), (level, 0));
        }
        set(0x300, 1);
        for (level, flags) in [(0x280, 2), (0x280, 3), (0x280, 0xFFFF_FFFF), (0xFF, 2)] {
            set(level, flags);
            assert_eq!(get(), (0x300, 1), "{level:#x} {flags:#x}: nothing kept");
        }
    }

    /// FlushInstructionCache: TRUE through a handle the service takes (the calling process's,
    /// with no range), FALSE with the status's error otherwise (spawn's remote block: a null
    /// handle is ERROR_INVALID_HANDLE, a handle without PROCESS_VM_WRITE ERROR_ACCESS_DENIED).
    #[test]
    fn flushes_answer_the_services_status() {
        use crate::base::last_error;
        crate::nt::children::reset();
        assert_eq!(flush_instruction_cache(CURRENT_PROCESS, 0, 0), 1);
        assert_eq!(flush_instruction_cache(0, 0, 0), 0);
        assert_eq!(last_error(), 6);
        crate::nt::children::fail("NtFlushInstructionCache", 0xC000_0022);
        assert_eq!(flush_instruction_cache(CURRENT_PROCESS, 0, 0), 0);
        assert_eq!(last_error(), 5);
    }
}
