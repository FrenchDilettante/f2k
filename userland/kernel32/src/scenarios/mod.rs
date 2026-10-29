//! kernel32's contract scenarios for its user-mode exports: each a host test calling the exports it
//! pins as a program does — by their stdcall bodies, with the caller's memory where it is. A
//! scenario names what it pins in its doc comment's last lines, `/// Pins: kernel32.<Name>, ...`
//! (one or more such lines). `scripts/compat.py` checks the pins, runs the scenarios, and reports
//! over them. A scenario pinning a known divergence is checked in disabled, its reason leading with
//! the gap's id (`#[ignore = "K32-4: ..."]`, or the increment that closes it, `B5: ...`).
//!
//! An address no call may read (a source a refusal must leave unread) is [`UNREAD`]: dereferencing
//! it faults the test.
//!
//! The scenarios call the exports through their raw ABI on purpose, so every one of their `unsafe`
//! blocks is the same contract, stated once here rather than at each call: the block calls an
//! `unsafe extern "system"` export (or a stand-in it pins) with what the API asks for — the test's
//! own live buffers and structures, the sizes passed theirs, strings NUL-terminated — save the
//! deliberate bad pointers (null, [`UNREAD`]) a scenario passes to show a call refuses them before
//! it reads, or faults where Windows 2000's does.

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
