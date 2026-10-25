//! kernel32's contract scenarios for its user-mode exports: each a host test calling the exports it
//! pins as a program does — by their stdcall bodies, with the caller's memory where it is. A
//! scenario names what it pins in its doc comment's last lines, `/// Pins: kernel32.<Name>, ...`
//! (one or more such lines). `scripts/compat.py` checks the pins, runs the scenarios, and reports
//! over them. A scenario pinning a known divergence is checked in disabled, its reason leading with
//! the gap's id (`#[ignore = "K32-4: ..."]`, or the increment that closes it, `B5: ...`).
//!
//! An address no call may read (a source a refusal must leave unread) is [`UNREAD`]: dereferencing
//! it faults the test.

mod binary_type;
mod clocks;
mod console;
mod curdir;
mod environment;
mod files;
mod locale;
mod modules;
mod processes;
mod startup;
mod threads;

/// An address the scenarios pass where the call must not read: unmapped on every host.
const UNREAD: usize = 0x10;

/// The calling test thread's last error.
fn last_error() -> u32 {
    crate::base::last_error()
}
