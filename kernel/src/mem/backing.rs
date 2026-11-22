//! Backing-store page-in: the fault resolutions that need I/O — a private page's slot in the
//! paging file, a section's page — are applied here. The entries are the address-space
//! manager's to write ([`vm::Pages`]).

use super::vm::Pages;

/// Apply a faulting access at `va` whose resolution needs backing-store I/O — `write` for a
/// store, `user` when it came from ring 3. Returns false until the backing-store page-in is
/// wired: the fault then stands for the caller's own paths.
pub fn apply(_pages: &mut impl Pages, _va: u32, _write: bool, _user: bool) -> bool {
    false
}
