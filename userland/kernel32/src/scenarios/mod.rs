//! kernel32's contract scenarios for its user-mode exports: each a host test the export spec names
//! (`scenarios` in userland/kernel32/exports.toml), calling the export as a program does — by its
//! stdcall body, with the caller's memory where it is. `scripts/ledger.py` reports over them, and
//! runs them. A scenario pinning a known divergence is checked in disabled, its reason leading with
//! the gap's id (`#[ignore = "K32-4: ..."]`, or the increment that closes it, `B5: ...`).
//!
//! An address no call may read (a source a refusal must leave unread) is [`UNREAD`]: dereferencing
//! it faults the test.

mod clocks;
mod console;
mod environment;
mod files;
mod locale;
mod modules;
mod startup;
mod threads;

/// An address the scenarios pass where the call must not read: unmapped on every host.
const UNREAD: usize = 0x10;

/// The calling test thread's last error.
fn last_error() -> u32 {
    crate::base::last_error()
}
