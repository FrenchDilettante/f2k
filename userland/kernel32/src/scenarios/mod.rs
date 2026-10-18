//! kernel32's contract scenarios for its user-mode exports: each a host test the export spec names
//! (`scenarios` in userland/kernel32/exports.toml), calling the export as a program does — by its
//! stdcall body, with the caller's memory where it is. `scripts/ledger.py` reports over them, and
//! runs them. A scenario pinning a known divergence is checked in disabled, its reason leading with
//! the gap's id (`#[ignore = "K32-4: ..."]`).
//!
//! None yet: the group modules arrive with the exports they pin, as later work moves them here
//! (the trivial natives are assembly, pinned by the fixtures).
