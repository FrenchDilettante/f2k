//! The process services: NtTerminateProcess and NtQueryInformationProcess (the virtual-memory
//! counters). kernel32's TerminateProcess and GlobalMemoryStatus are Win32 code over them, as on
//! Windows 2000.
//!
//! Only the calling process is reachable: its pseudo-handle (NtCurrentProcess), or a handle to its
//! object; any other handle is STATUS_INVALID_HANDLE.

use super::call::{
    Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_HANDLE, STATUS_SUCCESS,
};
use super::system::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

/// ProcessVmCounters: VM_COUNTERS (query), and its size.
pub const PROCESS_VM_COUNTERS: u32 = 3;
pub const VM_COUNTERS_SIZE: u32 = 44;

/// VM_COUNTERS for a process reserving `reserved` bytes: its virtual size (the peak is not kept: it
/// reads as the current size); the page-fault, working-set, pool and paging-file counters zero.
pub fn vm_counters(reserved: u32) -> [u8; VM_COUNTERS_SIZE as usize] {
    super::system::layout(&[reserved, reserved])
}

/// The structure a query of `class` into `length` bytes answers with: the VM counters' size, or
/// the status that refuses it (STATUS_INVALID_INFO_CLASS for the classes F2K does not answer;
/// the counters take their structure's length exactly).
pub fn information_size(class: u32, length: u32) -> Result<u32, Status> {
    if class != PROCESS_VM_COUNTERS {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    if length != VM_COUNTERS_SIZE {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(VM_COUNTERS_SIZE)
}

/// NtQueryInformationProcess: the calling process's virtual-memory counters (see
/// [`vm_counters`]).
pub fn query_information_process(
    call: &mut NtCall,
    process: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
    return_length: UserPtr<u32>,
) -> NtResult {
    let size = information_size(class, length)?;
    let reserved = super::memory::with_space(call, process, |space, _| {
        Ok::<_, Status>(space.reserved_size())
    })?;
    information.write(&vm_counters(reserved))?;
    return_length.write_optional(size)?;
    Ok(STATUS_SUCCESS)
}

/// STATUS_NOT_IMPLEMENTED: the null handle's form, which no caller uses yet.
const STATUS_NOT_IMPLEMENTED: Status = Status(0xC000_0002);

/// The process a handle names, when it is the calling process.
pub(super) fn current(process: Handle) -> Result<(), Status> {
    if super::object::names_current_process(process.raw()) {
        Ok(())
    } else {
        Err(STATUS_INVALID_HANDLE)
    }
}

/// NtTerminateProcess(ProcessHandle, ExitStatus): a handle naming the calling process ends it —
/// its other threads first, then the caller — with the status as its exit code, what kernel32's
/// TerminateProcess of its own process asks. Any other handle is STATUS_INVALID_HANDLE. The null
/// handle (every other thread of the calling process, ExitProcess's first step on Windows 2000)
/// comes with ExitProcess's move to kernel32: STATUS_NOT_IMPLEMENTED until then.
pub fn terminate_process(call: &mut NtCall, process: Handle, status: u32) -> NtResult {
    let _ = call;
    if process.raw() == 0 {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    current(process)?;
    crate::user::process_exited(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the calling process is reachable: the host has no handle table, so the pseudo-handle
    /// alone names it; anything else is an invalid handle, the null handle not implemented yet.
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
        assert_eq!(
            terminate_process(&mut call, Handle(0), 3),
            Err(STATUS_NOT_IMPLEMENTED)
        );
    }

    /// The VM counters: their structure's exact length, the virtual size twice (current and peak);
    /// every other class is not answered.
    #[test]
    fn the_vm_counters_are_the_reservations() {
        assert_eq!(information_size(3, 44), Ok(44));
        assert_eq!(information_size(3, 48), Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(information_size(0, 24), Err(STATUS_INVALID_INFO_CLASS));
        let counters = vm_counters(0x12_3000);
        assert_eq!(&counters[..8], &[0, 0x30, 0x12, 0, 0, 0x30, 0x12, 0]);
        assert!(counters[8..].iter().all(|&byte| byte == 0));
    }
}
