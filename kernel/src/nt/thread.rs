//! The thread services: so far the one class TlsFree needs of NtSetInformationThread,
//! ThreadZeroTlsCell. The others — NtCreateThread, NtTerminateThread, NtSuspendThread and
//! NtResumeThread, NtQueryInformationThread and the other classes — come with the thread calls.
//!
//! A handle names a thread of the calling process, or is the current-thread pseudo-handle
//! (NtCurrentThread, -2). The information's length is the class's structure's exactly, as Windows
//! 2000 checks it (STATUS_INFO_LENGTH_MISMATCH).

#[cfg(target_arch = "x86")]
use super::call::STATUS_SUCCESS;
use super::call::{Handle, NtCall, NtResult, Status, UserAddr, UserPtr, STATUS_INVALID_PARAMETER};
use super::memory::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

/// ThreadZeroTlsCell: a TLS index whose slot every thread of the process loses, a ULONG (set; the
/// calling thread's handle only).
pub const THREAD_ZERO_TLS_CELL: u32 = 10;

/// The calling thread's pseudo-handle (NtCurrentThread).
const CURRENT_THREAD: u32 = super::object::CURRENT_THREAD;

/// The information's length, which must be the class's structure's exactly.
fn exactly(length: u32, size: u32) -> Result<(), Status> {
    if length == size {
        Ok(())
    } else {
        Err(STATUS_INFO_LENGTH_MISMATCH)
    }
}

/// ThreadZeroTlsCell's value and handle, as Windows 2000 checks them: the calling thread's
/// pseudo-handle and an index below the last; STATUS_INVALID_PARAMETER otherwise.
fn zero_tls_cell(thread: u32, index: u32) -> Result<u32, Status> {
    if thread != CURRENT_THREAD || index >= crate::user::tls::INDEXES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(index)
}

/// NtSetInformationThread: ThreadZeroTlsCell (the index's slot zeroed in every thread of the
/// process that has one; the calling thread's handle only, STATUS_INVALID_PARAMETER otherwise and
/// past the last index). The value is read and checked before the handle is, as Windows 2000
/// orders it. STATUS_INVALID_INFO_CLASS for the classes F2K does not answer yet.
pub fn set_information_thread(
    call: &mut NtCall,
    thread: Handle,
    class: u32,
    information: UserAddr,
    length: u32,
) -> NtResult {
    if class != THREAD_ZERO_TLS_CELL {
        return Err(STATUS_INVALID_INFO_CLASS);
    }
    exactly(length, 4)?;
    let value = UserPtr::<u32>::at(information.raw()).read()?;
    let index = zero_tls_cell(thread.raw(), value)?;
    #[cfg(target_arch = "x86")]
    {
        for (_, teb) in call.process().thread_tebs() {
            if let Some(slot) = crate::user::tls::thread_slot(teb, index) {
                // Each thread's slot, where it has one (its expansion slots are its own heap
                // block); a slot the program made unwritable keeps what it had.
                let _ = UserPtr::<u32>::at(slot).write(0);
            }
        }
        Ok(STATUS_SUCCESS)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, index);
        Err(super::call::STATUS_INVALID_HANDLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ThreadZeroTlsCell takes the calling thread's pseudo-handle and an index below the last
    /// (1088); anything else is STATUS_INVALID_PARAMETER.
    #[test]
    fn the_zero_tls_cell_class_takes_the_caller_and_an_index() {
        assert_eq!(zero_tls_cell(CURRENT_THREAD, 0), Ok(0));
        assert_eq!(zero_tls_cell(CURRENT_THREAD, 1087), Ok(1087));
        assert_eq!(
            zero_tls_cell(CURRENT_THREAD, 1088),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(zero_tls_cell(0x44, 3), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(exactly(4, 4), Ok(()));
        assert_eq!(exactly(8, 4), Err(STATUS_INFO_LENGTH_MISMATCH));
    }
}
