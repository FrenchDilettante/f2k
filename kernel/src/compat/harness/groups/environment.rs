//! Environment: the process's environment block — staged by the kernel, empty — in its wide form;
//! the ANSI form is not served, and freeing either is a successful no-op.

use crate::compat::harness::boundary::KernelBoundary;
use crate::compat::harness::surface::{assert_argument_blocks, Fixture};

pub const MEMBERS: &[&str] = &[
    "GetEnvironmentStrings",
    "GetEnvironmentStringsW",
    "FreeEnvironmentStringsA",
    "FreeEnvironmentStringsW",
    "GetEnvironmentVariableA",
    "SetEnvironmentVariableA",
    "ExpandEnvironmentStringsA",
    "SetEnvironmentVariableW",
];

/// Every member pops the block its callers push. Ledger: environment.
#[test]
#[ignore = "ledger environment: not switched on"]
fn environment_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// GetEnvironmentStringsW: a pointer to the staged block, which is empty — the double-NUL
/// terminator alone. Ledger: environment/GetEnvironmentStringsW.
#[test]
#[ignore = "ledger environment/GetEnvironmentStringsW: not switched on"]
fn get_environment_strings_w_points_at_the_empty_staged_block() {
    let mut fixture = Fixture::new();
    let block = fixture.call("GetEnvironmentStringsW", &[]);
    assert_eq!(block, fixture.kernel.process_parameters().environment);
    assert_eq!(fixture.memory().u32_at(block), 0, "two wide NULs");
    assert_eq!(fixture.call("GetEnvironmentStringsW", &[]), block);
}

/// GetEnvironmentStrings (the ANSI form) reports failure: NULL. The CRT asks for the wide form
/// first and never needs it. Ledger: environment/GetEnvironmentStrings.
#[test]
#[ignore = "ledger environment/GetEnvironmentStrings: not switched on"]
fn get_environment_strings_a_reports_null() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("GetEnvironmentStrings", &[]), 0);
}

/// FreeEnvironmentStringsW frees nothing and succeeds; the block stays readable. Ledger:
/// environment/FreeEnvironmentStringsW.
#[test]
#[ignore = "ledger environment/FreeEnvironmentStringsW: not switched on"]
fn free_environment_strings_w_succeeds() {
    let mut fixture = Fixture::new();
    let block = fixture.call("GetEnvironmentStringsW", &[]);
    assert_eq!(fixture.call("FreeEnvironmentStringsW", &[block]), 1);
    assert_eq!(fixture.memory().u32_at(block), 0);
    assert_eq!(fixture.kernel.calls(), []);
}

/// FreeEnvironmentStringsA succeeds too — on any pointer, the wide block included (the CRT frees
/// the wide block through the ANSI entry). Ledger: environment/FreeEnvironmentStringsA.
#[test]
#[ignore = "ledger environment/FreeEnvironmentStringsA: not switched on"]
fn free_environment_strings_a_succeeds_on_the_wide_block() {
    let mut fixture = Fixture::new();
    let block = fixture.call("GetEnvironmentStringsW", &[]);
    assert_eq!(fixture.call("FreeEnvironmentStringsA", &[block]), 1);
    assert_eq!(fixture.call("FreeEnvironmentStringsA", &[0]), 1);
    assert_eq!(fixture.memory().u32_at(block), 0);
}
