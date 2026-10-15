//! The kernel32 contract harness: the surface's behavior as host tests, measurable while the
//! exports move out of the kernel into a user-mode DLL.
//!
//! Layout:
//!
//! - [`boundary`]: the kernel-side operations the exports perform, as a trait named after the
//!   public interface ([`boundary::KernelBoundary`]).
//! - [`fake`]: the fake kernel standing in for it host-side.
//! - [`surface`]: the export surface under test, the existing implementation path behind it, and
//!   the scenario fixture.
//! - [`groups`]: the scenario dump, one module per API group. Every scenario is checked in; the
//!   ones whose export has not been switched on carry `#[ignore]`.
//!
//! The ledger (`scripts/kernel32-ledger.yaml`) maps every export to its group, contract status,
//! and scenarios; `scripts/kernel32-ledger.py` prints the per-group progress from it. Every
//! scenario names its ledger entry in its doc comment (`Ledger: group/Export.`, or
//! `Ledger: group.` for a scenario over the whole group), and a disabled one repeats it in its
//! ignore reason.
//!
//! Switching an export on: route it to the implementation under test in the fixture's surface of
//! record, drop the `#[ignore]` from its scenarios, and set `enabled: true` on them in the ledger.

pub mod boundary;
pub mod fake;
pub mod groups;
pub mod surface;
