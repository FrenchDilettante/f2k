//! The process services: NtTerminateProcess, and NtQueryInformationProcess and
//! NtSetInformationProcess, the classes kernel32's process calls ask. kernel32's
//! ExitProcess, TerminateProcess, GlobalMemoryStatus (the virtual-memory counters),
//! Get/SetPriorityClass, SetProcessAffinityMask and SetErrorMode are Win32 code over these, as on
//! Windows 2000.
//!
//! Only the calling process is reachable: its pseudo-handle (NtCurrentProcess), or a handle to it
//! Any other handle is STATUS_INVALID_HANDLE, checked before the information is.
//! The information's length is the class's structure's exactly, as Windows 2000 checks it
//! (STATUS_INFO_LENGTH_MISMATCH).

use super::call::{
    Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use super::memory::{with_space, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

/// PROCESSINFOCLASS: the classes F2K answers.
/// ProcessBasicInformation: PROCESS_BASIC_INFORMATION (query).
pub const PROCESS_BASIC_INFORMATION: u32 = 0;
/// ProcessVmCounters: VM_COUNTERS (query).
pub const PROCESS_VM_COUNTERS: u32 = 3;
/// ProcessDefaultHardErrorMode: the process's hard-error mode, a ULONG (query and set).
pub const PROCESS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
/// ProcessPriorityClass: PROCESS_PRIORITY_CLASS (query and set).
pub const PROCESS_PRIORITY_CLASS: u32 = 18;
/// ProcessAffinityMask: the processors the process may run on, a KAFFINITY (set).
pub const PROCESS_AFFINITY_MASK: u32 = 21;

/// The classes' structures' sizes: PROCESS_BASIC_INFORMATION (ExitStatus, PebBaseAddress,
/// AffinityMask, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId), VM_COUNTERS, and
/// PROCESS_PRIORITY_CLASS (Foreground, a BOOLEAN; PriorityClass, a UCHAR).
pub const PROCESS_BASIC_INFORMATION_SIZE: u32 = 24;
pub const VM_COUNTERS_SIZE: u32 = 44;
pub const PROCESS_PRIORITY_CLASS_SIZE: u32 = 2;

/// A live process's exit status: STATUS_PENDING (kernel32's STILL_ACTIVE).
const STATUS_PENDING: u32 = 0x103;

/// The priority classes (PROCESS_PRIORITY_CLASS_*), and each one's base priority (Windows 2000's
/// PspPriorityTable): idle 4, normal 8, high 13, realtime 24, below normal 6, above normal 10.
pub const PRIORITY_CLASS_NORMAL: u8 = 2;
const PRIORITY_CLASS_BASES: [i8; 7] = [0, 4, 8, 13, 24, 6, 10];

/// The base priority a priority class gives the process; STATUS_INVALID_PARAMETER for a value
/// naming no class (Windows 2000 refuses past ABOVE_NORMAL, 6; F2K refuses UNKNOWN, 0, as well).
pub fn class_base_priority(class: u8) -> Result<i8, Status> {
    match PRIORITY_CLASS_BASES.get(class as usize) {
        Some(&base) if class != 0 => Ok(base),
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Dwords as the bytes of the structure they lay out (the rest zero).
fn layout<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut bytes = [0u8; N];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// VM_COUNTERS for a process reserving `reserved` bytes: its virtual size (the peak is not kept: it
/// reads as the current size); the page-fault, working-set, pool and paging-file counters zero.
pub fn vm_counters(reserved: u32) -> [u8; VM_COUNTERS_SIZE as usize] {
    layout(&[reserved, reserved])
}

/// PROCESS_BASIC_INFORMATION for the live process `id` at base priority `base`: still running, its
/// PEB at the PEB page, the one processor, no parent recorded.
pub fn basic_information(id: u32, base: i8) -> [u8; PROCESS_BASIC_INFORMATION_SIZE as usize] {
    layout(&[
        STATUS_PENDING,
        crate::user::PEB_PAGE,
        super::thread::SYSTEM_AFFINITY,
        base as u32,
        id,
        0,
    ])
}

/// The class's size: its structure's (none for a class F2K does not answer).
fn size_of(class: u32) -> Option<u32> {
    match class {
        PROCESS_BASIC_INFORMATION => Some(PROCESS_BASIC_INFORMATION_SIZE),
        PROCESS_VM_COUNTERS => Some(VM_COUNTERS_SIZE),
        PROCESS_DEFAULT_HARD_ERROR_MODE | PROCESS_AFFINITY_MASK => Some(4),
        PROCESS_PRIORITY_CLASS => Some(PROCESS_PRIORITY_CLASS_SIZE),
        _ => None,
    }
}

/// The process a handle names, when it is the calling process.
pub(super) fn current(process: Handle) -> Result<(), Status> {
    if crate::nt::object::names_current_process(process.raw()) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtTerminateProcess(ProcessHandle, ExitStatus): no handle terminates every other thread of the
/// calling process with the status, the caller running on (ExitProcess's first step on Windows
/// 2000, before the loader's shutdown); a handle naming the calling process ends it — its other
/// threads first, then the caller — with the status as its exit code. Only the calling process is
/// reachable: any other handle is STATUS_INVALID_HANDLE.
pub fn terminate_process(call: &mut NtCall, process: Handle, status: u32) -> NtResult {
    if process.raw() == 0 {
        #[cfg(target_arch = "x86")]
        crate::process::threads::terminate_other_threads(call.process(), status);
        #[cfg(not(target_arch = "x86"))]
        let _ = call;
        return Ok(STATUS_SUCCESS);
    }
    current(process)?;
    crate::user::process_exited(status)
}

/// NtQueryInformationProcess: the basic information, the virtual-memory counters (of the
/// pseudo-handle's process only, as before), the hard-error mode and the priority class (never
/// foreground: no window has the focus). STATUS_INVALID_INFO_CLASS for the classes F2K does not
/// answer.
pub fn query_information_process(
    call: &mut NtCall,
    process: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let size = match class {
        PROCESS_AFFINITY_MASK => None,
        class => size_of(class),
    }
    .ok_or(STATUS_INVALID_INFO_CLASS)?;
    if length != size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    if class == PROCESS_VM_COUNTERS {
        let reserved = with_space(call, process, |space, _| {
            Ok::<_, Status>(space.reserved_size())
        })?;
        information.write(&vm_counters(reserved))?;
    } else {
        current(process)?;
        #[cfg(target_arch = "x86")]
        {
            let record = call.process();
            match class {
                PROCESS_BASIC_INFORMATION => information.write(&basic_information(
                    record.id(),
                    record.sched.base_priority(),
                ))?,
                PROCESS_DEFAULT_HARD_ERROR_MODE => {
                    UserPtr::<u32>::at(information.raw()).write(record.hard_error_mode())?
                }
                _ => information.write(&[0, record.priority_class()])?,
            }
        }
    }
    return_length.write_optional(size)?;
    Ok(STATUS_SUCCESS)
}

/// NtSetInformationProcess: the hard-error mode (kept for its round trip: no hard-error or fault
/// dialog exists to suppress), the priority class (every thread's priority moves with the process's
/// base, their increments kept; the realtime class needs no privilege here) and the affinity (a
/// non-empty subset of the one processor: nothing to change). The handle is checked first, then
/// the value. STATUS_INVALID_INFO_CLASS for the classes F2K does not answer.
pub fn set_information_process(
    call: &mut NtCall,
    process: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
) -> NtResult {
    let size = match class {
        PROCESS_DEFAULT_HARD_ERROR_MODE | PROCESS_PRIORITY_CLASS | PROCESS_AFFINITY_MASK => {
            size_of(class)
        }
        _ => None,
    }
    .ok_or(STATUS_INVALID_INFO_CLASS)?;
    if length != size {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    current(process)?;
    let mut value = [0u8; 4];
    information.read(&mut value[..size as usize])?;
    match class {
        PROCESS_DEFAULT_HARD_ERROR_MODE => {
            #[cfg(target_arch = "x86")]
            call.process()
                .set_hard_error_mode(u32::from_le_bytes(value));
        }
        PROCESS_PRIORITY_CLASS => {
            let base = class_base_priority(value[1])?;
            #[cfg(target_arch = "x86")]
            {
                let record = call.process();
                crate::sched::idle::dispatcher().set_process_priority(&mut record.sched, base);
                record.set_priority_class(value[1]);
            }
            #[cfg(not(target_arch = "x86"))]
            let _ = base;
        }
        _ => {
            super::thread::affinity_mask(u32::from_le_bytes(value))?;
        }
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = call;
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn the_counters_report_the_virtual_size() {
        assert_eq!(&vm_counters(0x5_0000)[..8], &[0, 0, 5, 0, 0, 0, 5, 0]);
    }

    /// PROCESS_BASIC_INFORMATION's layout: still running, the PEB page, the processor, the base
    /// priority and the client id.
    #[test]
    fn the_basic_information_is_the_nt_layout() {
        let bytes = basic_information(8, 13);
        assert_eq!(
            (word(&bytes, 0), word(&bytes, 4), word(&bytes, 8)),
            (0x103, crate::user::PEB_PAGE, 1)
        );
        assert_eq!(
            (word(&bytes, 12), word(&bytes, 16), word(&bytes, 20)),
            (13, 8, 0)
        );
    }

    /// Only the calling process is reachable: the host has no handle table, so the pseudo-handle
    /// alone names it; anything else is an invalid handle.
    #[test]
    fn only_the_calling_process_is_reachable() {
        assert_eq!(current(Handle(0xFFFF_FFFF)), Ok(()));
        assert_eq!(current(Handle(0x44)), Err(STATUS_INVALID_HANDLE));
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: crate::user::TrapFrame = unsafe { core::mem::zeroed() };
        let mut call = NtCall::new(&mut frame);
        assert_eq!(
            terminate_process(&mut call, Handle(0x44), 3),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    /// The affinity: the class's exact length, the calling process alone, and a non-empty subset of
    /// the one processor (SetProcessAffinityMask's ERROR_INVALID_PARAMETER and ERROR_INVALID_HANDLE).
    #[test]
    fn the_affinity_is_the_one_processor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::user::syscall::host::{install, UserMemory};
        struct Word(Vec<u8>);
        impl UserMemory for Word {
            fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), u32> {
                let at = pointer.checked_sub(0x10000).ok_or(0xC000_0005u32)? as usize;
                bytes.copy_from_slice(self.0.get(at..at + bytes.len()).ok_or(0xC000_0005u32)?);
                Ok(())
            }
            fn write(&mut self, _: u32, _: &[u8]) -> Result<(), u32> {
                Err(0xC000_0005)
            }
        }
        let memory = Rc::new(RefCell::new(Word(1u32.to_le_bytes().to_vec())));
        let _installed = install(memory.clone());
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: crate::user::TrapFrame = unsafe { core::mem::zeroed() };
        let mut call = NtCall::new(&mut frame);
        let me = Handle(0xFFFF_FFFF);
        let at = UserAddr(0x10000);
        assert_eq!(
            set_information_process(&mut call, me, 21, at, 4),
            Ok(STATUS_SUCCESS)
        );
        assert_eq!(
            set_information_process(&mut call, me, 21, at, 8),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            set_information_process(&mut call, me, 13, at, 4),
            Err(STATUS_INVALID_INFO_CLASS)
        );
        assert_eq!(
            set_information_process(&mut call, Handle(0x44), 21, at, 4),
            Err(STATUS_INVALID_HANDLE)
        );
        for mask in [0u32, 2, 3] {
            memory.borrow_mut().0 = mask.to_le_bytes().to_vec();
            assert_eq!(
                set_information_process(&mut call, me, 21, at, 4),
                Err(super::super::call::STATUS_INVALID_PARAMETER),
                "{mask:#x}"
            );
        }
        assert_eq!(rtl::status::dos_error(0xC000_000D), 87);
        assert_eq!(
            set_information_process(&mut call, me, 21, UserAddr(0x20000), 4),
            Err(super::super::call::STATUS_ACCESS_VIOLATION)
        );
    }

    /// The classes' base priorities: the threads fixture's priority block moves the process to the
    /// high class (13) and back to normal (8).
    #[test]
    fn priority_classes_give_windows_2000s_bases() {
        let bases: Vec<_> = (1..=6)
            .map(|class| class_base_priority(class).unwrap())
            .collect();
        assert_eq!(bases, [4, 8, 13, 24, 6, 10]);
        assert_eq!(class_base_priority(PRIORITY_CLASS_NORMAL), Ok(8));
        assert_eq!(class_base_priority(0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(class_base_priority(7), Err(STATUS_INVALID_PARAMETER));
    }
}
