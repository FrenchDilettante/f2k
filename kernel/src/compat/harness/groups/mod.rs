//! The scenarios, one module per API group (the export spec's groups): each pins its exports'
//! contract on the host — argument validation order, return values, error returns, the bytes moved
//! — through the real service handlers (see [`super::surface`]). The spec names each export's
//! scenarios (`scenarios` in userland/kernel32/exports.toml); exports whose handlers run on kernel
//! state the host does not build are pinned by the fixtures instead (`pinned_by`).
//!
//! A scenario pinning a known divergence from the platform is checked in disabled, its reason
//! leading with the gap's id (`#[ignore = "K32-4: ..."]`); `scripts/ledger.py --run` fails once it
//! passes, so the marker goes with the fix.

// `GROUPS`: every API group's key, title and members, generated from the export spec
// (userland/kernel32/exports.toml) by the build script.
include!(concat!(env!("OUT_DIR"), "/kernel32_groups.rs"));

/// The groups partition the registry: every kernel32 export the kernel serves is in exactly one
/// group.
#[test]
fn the_groups_partition_the_registry() {
    use crate::compat::kernel32::SERVICES;
    for (name, ..) in SERVICES {
        let owners: Vec<&str> = GROUPS
            .iter()
            .filter(|(_, _, members)| members.contains(&name))
            .map(|(group, ..)| *group)
            .collect();
        assert_eq!(owners.len(), 1, "{name} belongs to {owners:?}");
    }
}
