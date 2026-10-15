//! The scenario dump, one module per API group. Together the groups partition the registry: every
//! export belongs to exactly one.
//!
//! Each group module lists its `MEMBERS` and holds the scenarios pinning their contract: argument
//! validation order, return values, error returns, and the stdcall argument blocks. A scenario
//! the surface of record cannot pass yet is checked in disabled (`#[ignore]`, the reason naming its
//! ledger entry).
//!
//! A new group joins in three steps: a module here with its `MEMBERS` and scenarios, a row in
//! [`GROUPS`], and its entries in `scripts/kernel32-ledger.yaml` (the group under `groups:`, each
//! member under `exports:`). The partition and ledger checks below fail until all three agree.

pub mod console;
pub mod environment;
pub mod files;
pub mod heap;
pub mod locale;
pub mod startup;
pub mod termination;
pub mod threads;
pub mod virtual_memory;

/// Every group: its ledger key and its members.
pub const GROUPS: &[(&str, &[&str])] = &[
    ("termination", termination::MEMBERS),
    ("startup", startup::MEMBERS),
    ("console", console::MEMBERS),
    ("environment", environment::MEMBERS),
    ("heap", heap::MEMBERS),
    ("locale", locale::MEMBERS),
    ("threads", threads::MEMBERS),
    ("files", files::MEMBERS),
    ("virtual-memory", virtual_memory::MEMBERS),
];

/// The ledger, as checked in.
const LEDGER: &str = include_str!("../../../../../scripts/kernel32-ledger.yaml");

/// The groups partition the registry: every export in exactly one group, no name off the surface.
#[test]
fn the_groups_partition_the_registry() {
    use crate::compat::kernel32::SERVICES;
    for (name, ..) in SERVICES {
        let owners: Vec<&str> = GROUPS
            .iter()
            .filter(|(_, members)| members.contains(&name))
            .map(|(group, _)| *group)
            .collect();
        assert_eq!(owners.len(), 1, "{name} belongs to {owners:?}");
    }
    let listed: usize = GROUPS.iter().map(|(_, members)| members.len()).sum();
    assert_eq!(listed, SERVICES.len());
}

/// The ledger agrees with the groups: each group listed once, each export listed once under its
/// group. (A line scan: the ledger's own structure is the report script's to validate.)
#[test]
fn the_ledger_agrees_with_the_groups() {
    let field = |line: &str, key: &str| -> Option<String> {
        let rest = line
            .trim_start()
            .trim_start_matches("- ")
            .strip_prefix(key)?;
        Some(rest.trim().trim_matches('"').to_string())
    };
    let mut ledger_groups = Vec::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut section = "";
    let mut export: Option<String> = None;
    for line in LEDGER.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && line.ends_with(':') {
            section = line.trim_end_matches(':');
            continue;
        }
        match section {
            "groups" => {
                if let Some(key) = field(line, "key:") {
                    ledger_groups.push(key);
                }
            }
            "exports" => {
                if let Some(name) = field(line, "export:") {
                    export = Some(name);
                } else if let Some(group) = field(line, "group:") {
                    let name = export.take().expect("group: follows export:");
                    entries.push((name, group));
                }
            }
            _ => {}
        }
    }
    let keys: Vec<&str> = GROUPS.iter().map(|(key, _)| *key).collect();
    assert_eq!(ledger_groups, keys, "the ledger's groups, in order");
    for (group, members) in GROUPS {
        for member in *members {
            let listed: Vec<&(String, String)> =
                entries.iter().filter(|(name, _)| name == member).collect();
            assert_eq!(listed.len(), 1, "{member} listed once in the ledger");
            assert_eq!(listed[0].1, *group, "{member}'s ledger group");
        }
    }
    assert_eq!(entries.len(), crate::compat::kernel32::SERVICES.len());
}
