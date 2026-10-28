//! A system service's view of its call: the context its handler gets first, the result convention,
//! and the argument types (`user::args`) the generated wrappers decode the argument block into.
//!
//! The convention is [`NtCall::finish`]'s: the handler's NTSTATUS goes into EAX, `Ok` carrying a
//! success or informational status (STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_OBJECT_NAME_EXISTS),
//! `Err` an error. The last error is never touched. A fault in the caller's memory is
//! STATUS_ACCESS_VIOLATION, which `?` converts to.

// The frame accessor the later services use.
#![allow(dead_code)]

use crate::level::{At, Passive};
use crate::status::*;
pub use crate::user::args::*;
use crate::user::TrapFrame;

/// A system service's result: its success or informational status, or the status that fails it
/// (an error or a warning).
pub type NtResult = Result<NtStatus, NtStatus>;

/// A fault in the caller's memory: STATUS_ACCESS_VIOLATION.
impl From<Fault> for NtStatus {
    fn from(_: Fault) -> NtStatus {
        STATUS_ACCESS_VIOLATION
    }
}

/// The call a system service is serving: its trap frame (whose EAX the convention fills), and the
/// passive-level token the system-call entry made for it.
pub struct NtCall<'f> {
    frame: &'f mut TrapFrame,
    passive: &'f mut At<Passive>,
}

impl<'f> NtCall<'f> {
    /// The call the wrapper is about to hand its handler.
    pub fn new(frame: &'f mut TrapFrame, passive: &'f mut At<Passive>) -> Self {
        NtCall { frame, passive }
    }

    /// The service's passive-level token: what it raises from (a clock read, a lock) and what a
    /// wait or a user-memory copy takes once they hold tokens.
    pub fn passive(&mut self) -> &mut At<Passive> {
        self.passive
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
        let (Ok(status) | Err(status)) = result;
        self.frame.eax = status.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_is_the_answer() {
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: TrapFrame = unsafe { core::mem::zeroed() };
        let mut passive = crate::level::passive_for_test();
        NtCall::new(&mut frame, &mut passive).finish(Ok(STATUS_TIMEOUT));
        assert_eq!(frame.eax, 0x102);
        NtCall::new(&mut frame, &mut passive).finish(Err(STATUS_INVALID_HANDLE));
        assert_eq!(frame.eax, 0xC000_0008);
        assert_eq!(NtStatus::from(Fault), STATUS_ACCESS_VIOLATION);
    }
}
