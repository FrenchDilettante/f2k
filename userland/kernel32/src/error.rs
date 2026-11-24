//! Why a call failed ([`Failure`]), as the code below the exports returns it up to them: an export
//! answers a failure with the API's failure value, the failure set as the last error ([`answer`],
//! [`bool_answer`]).

// STATUS_UNSUCCESSFUL: the status of a failure that names a Win32 error, not a status.
use rtl::status::STATUS_UNSUCCESSFUL;

use crate::base::{set_last_error, set_last_nt_error};
use crate::heap::OutOfMemory;
use crate::ntcall::{self, NtStatus};

/// Why a call failed: a service's status (its error set through ntdll's mapping,
/// BaseSetLastNTError), a Win32 error kernel32 sets itself, or a fault the caller takes (the status
/// raised in it, as Windows 2000's kernel32 faults reading through a missing pointer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Status(NtStatus),
    Error(u32),
    Fault(NtStatus),
}

impl Failure {
    /// The failure as the last error, or raised.
    pub fn report(self) {
        match self {
            Failure::Status(status) => {
                set_last_nt_error(status);
            }
            Failure::Error(error) => set_last_error(error),
            Failure::Fault(status) => ntcall::raise_status(status),
        }
    }

    /// The status a failure stands for (a Win32 error's is STATUS_UNSUCCESSFUL): what a process
    /// given up on ends with.
    pub fn status(self) -> NtStatus {
        match self {
            Failure::Status(status) | Failure::Fault(status) => status,
            Failure::Error(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

impl From<OutOfMemory> for Failure {
    fn from(full: OutOfMemory) -> Failure {
        Failure::Error(full.error())
    }
}

/// An export's answer: the value, or `failed` with the failure reported (the last error set, or
/// the fault raised).
pub fn answer<T>(result: Result<T, Failure>, failed: T) -> T {
    result.unwrap_or_else(|failure| {
        failure.report();
        failed
    })
}

/// An export's BOOL: TRUE, or FALSE with the failure reported.
pub fn bool_answer<T>(result: Result<T, Failure>) -> u32 {
    answer(result.map(|_| 1), 0)
}
