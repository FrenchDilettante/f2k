//! The process services: NtTerminateProcess. kernel32's TerminateProcess is Win32 code over it, as
//! on Windows 2000.
//!
//! Only the calling process is reachable: its pseudo-handle (NtCurrentProcess), or a handle to its
//! object; any other handle is STATUS_INVALID_HANDLE.

use super::call::{Handle, NtCall, NtResult, Status, STATUS_INVALID_HANDLE};

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
/// comes with ExitProcess's move to kernel32 (B7): STATUS_NOT_IMPLEMENTED until then.
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
}
