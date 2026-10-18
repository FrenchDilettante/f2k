//! The kernel32 contract harness: the surface's behavior as host tests.
//!
//! Layout:
//!
//! - [`surface`]: the export surface under test (the kernel's service handlers, run against a host
//!   memory the scenario stages) and the scenario fixture.
//! - [`groups`]: the scenarios, one module per API group (the export spec's groups).
//!
//! Every scenario is a test the export spec names (`scenarios` in userland/kernel32/exports.toml),
//! and `scripts/ledger.py` reports over the spec. A scenario pinning a known divergence from the
//! platform is checked in disabled, its reason leading with the gap's id
//! (`#[ignore = "K32-4: ..."]`); `scripts/ledger.py --run` fails once it passes, so the marker goes
//! with the fix.

pub mod groups;
pub mod surface;
