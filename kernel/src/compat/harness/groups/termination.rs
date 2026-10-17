//! Termination: the process's end, its own pseudo-handle, and the exception and dynamic-linking
//! imports the CRT carries but the corpus never calls — those answer with a zero floor.

use crate::compat::harness::fake::Call;
use crate::compat::harness::surface::{assert_argument_blocks, Fixture};

pub const MEMBERS: &[&str] = &[
    "ExitProcess",
    "TerminateProcess",
    "GetCurrentProcess",
    "SetErrorMode",
    "UnhandledExceptionFilter",
    "GetProcAddress",
    "LoadLibraryA",
    "RtlUnwind",
    "RaiseException",
    "SetUnhandledExceptionFilter",
    "FreeLibrary",
    "GetModuleHandleA",
];

/// Every member pops the block its callers push. Ledger: termination.
#[test]
#[ignore = "ledger termination: not switched on"]
fn termination_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// ExitProcess ends the process with its exit code: one terminate, carrying the code. Ledger:
/// termination/ExitProcess.
#[test]
#[ignore = "ledger termination/ExitProcess: the existing path ends the process through the \
            scheduler (target-only)"]
fn exit_process_terminates_with_the_exit_code() {
    let mut fixture = Fixture::new();
    fixture.call("ExitProcess", &[3]);
    assert_eq!(fixture.kernel.exit_status(), Some(3));
    assert_eq!(fixture.kernel.calls(), [Call::TerminateProcess(3)]);
}

/// GetCurrentProcess: the pseudo-handle (all ones), with no kernel call and no table slot. Ledger:
/// termination/GetCurrentProcess.
#[test]
#[ignore = "ledger termination/GetCurrentProcess: not switched on"]
fn get_current_process_is_the_pseudo_handle() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("GetCurrentProcess", &[]), 0xFFFF_FFFF);
    assert_eq!(fixture.kernel.calls(), []);
    assert_eq!(fixture.kernel.live_handles(), 0);
}

/// TerminateProcess's floor: zero (FALSE), and the process is not ended. Ledger:
/// termination/TerminateProcess.
#[test]
#[ignore = "ledger termination/TerminateProcess: unpinned floor"]
fn terminate_process_answers_with_the_floor() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("TerminateProcess", &[0xFFFF_FFFF, 3]), 0);
    assert_eq!(fixture.kernel.exit_status(), None);
    assert_eq!(fixture.kernel.calls(), []);
}

