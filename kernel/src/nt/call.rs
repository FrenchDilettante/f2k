//! A system service's view of its call: the context its handler gets first, the result convention,
//! and the argument types (`user::args`) the generated wrappers decode the argument block into.
//!
//! The convention is [`NtCall::finish`]'s: the handler's NTSTATUS goes into EAX, `Ok` carrying a
//! success or informational status (STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_OBJECT_NAME_EXISTS),
//! `Err` an error. The last error is never touched. A fault in the caller's memory is
//! STATUS_ACCESS_VIOLATION, which `?` converts to.

// The status constants and the frame accessor the later services use.
#![allow(dead_code)]

pub use crate::user::args::*;
use crate::user::TrapFrame;

/// An error status (severity error or warning): what fails a system service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(pub u32);

/// A system service's result: its success status, or the status that fails it.
pub type NtResult = Result<u32, Status>;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_ACCESS_VIOLATION: Status = Status(0xC000_0005);
pub const STATUS_INVALID_HANDLE: Status = Status(0xC000_0008);
pub const STATUS_INVALID_PARAMETER: Status = Status(0xC000_000D);

/// A fault in the caller's memory: STATUS_ACCESS_VIOLATION.
impl From<Fault> for Status {
    fn from(_: Fault) -> Status {
        STATUS_ACCESS_VIOLATION
    }
}

/// The call a system service is serving: its trap frame (whose EAX the convention fills).
pub struct NtCall<'f> {
    frame: &'f mut TrapFrame,
}

impl<'f> NtCall<'f> {
    /// The call the wrapper is about to hand its handler.
    pub fn new(frame: &'f mut TrapFrame) -> Self {
        NtCall { frame }
    }

    /// The calling process, borrowed for as long as the handler holds it.
    #[cfg(target_arch = "x86")]
    pub fn process(&mut self) -> &mut crate::process::Process {
        calling_process()
    }

    /// The caller's trap frame, for the services that resume a context into it (NtContinue,
    /// NtRaiseException): what they return is EAX's value then.
    pub fn frame(&mut self) -> &mut TrapFrame {
        self.frame
    }

    /// Apply the result convention: the status into EAX.
    pub fn finish(self, result: NtResult) {
        self.frame.eax = match result {
            Ok(status) => status,
            Err(Status(status)) => status,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_is_the_answer() {
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: TrapFrame = unsafe { core::mem::zeroed() };
        NtCall::new(&mut frame).finish(Ok(0x102));
        assert_eq!(frame.eax, 0x102);
        NtCall::new(&mut frame).finish(Err(STATUS_INVALID_HANDLE));
        assert_eq!(frame.eax, 0xC000_0008);
        assert_eq!(Status::from(Fault), STATUS_ACCESS_VIOLATION);
    }
}
