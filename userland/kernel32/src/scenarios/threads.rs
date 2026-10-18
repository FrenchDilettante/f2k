//! The process's end: TerminateProcess over NtTerminateProcess (the host's stand-in records the
//! calls; only the current process is reachable).

use crate::base::last_error;
use crate::nt::TERMINATED;
use crate::process::terminate_process;

const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
const BOGUS: u32 = 0x1234;

/// TerminateProcess reaches the calling process alone (the current process ends with the code);
/// any other handle is ERROR_INVALID_HANDLE, the null one refused before the kernel is
/// asked.
#[test]
fn terminations_reach_what_their_handles_name() {
    TERMINATED.with(|terminated| terminated.borrow_mut().clear());
    assert_eq!((terminate_process(BOGUS, 3), last_error()), (0, 6));
    assert_eq!((terminate_process(0, 3), last_error()), (0, 6));
    assert_eq!(terminate_process(CURRENT_PROCESS, 3), 1);
    let calls = TERMINATED.with(|terminated| terminated.borrow().clone());
    assert_eq!(calls, [(BOGUS, 3), (CURRENT_PROCESS, 3)]);
}
