//! The object services every handle shares: NtClose; and which handles name the calling process.

#[cfg(target_arch = "x86")]
use super::call::STATUS_SUCCESS;
use super::call::{Handle, NtCall, NtResult, STATUS_INVALID_HANDLE};

/// The current-process pseudo-handle (NtCurrentProcess).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;

/// Whether `handle` names the calling process: its pseudo-handle, or a handle to its object. No
/// other process is reachable.
#[cfg(target_arch = "x86")]
pub(crate) fn names_current_process(handle: u32) -> bool {
    let process = crate::process::current();
    handle == CURRENT_PROCESS
        || process
            .handles()
            .lookup(handle)
            .and_then(|entry| entry.object_id())
            == Some(process.object())
}

/// Host builds have no process table: only the pseudo-handle.
#[cfg(not(target_arch = "x86"))]
pub(crate) fn names_current_process(handle: u32) -> bool {
    handle == CURRENT_PROCESS
}

/// NtClose: the handle's entry released from the calling process's handle table (the object goes
/// once its last reference does). STATUS_INVALID_HANDLE for a handle naming no entry.
pub fn close(call: &mut NtCall, handle: Handle) -> NtResult {
    #[cfg(target_arch = "x86")]
    {
        if call.process().close_handle(handle.raw()) {
            Ok(STATUS_SUCCESS)
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, handle);
        Err(STATUS_INVALID_HANDLE)
    }
}
