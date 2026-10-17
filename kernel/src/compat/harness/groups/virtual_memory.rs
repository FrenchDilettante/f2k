//! Virtual memory: reservations, commits, protections and queries over the process's address space
//! (see `mem::vm`), the system's memory facts, and the pointer probes. The address space is the live
//! process's, so every behavior is target-only (the rules themselves are host-tested in
//! `compat::memapi`); the memory fixture's capture pins them. The scenario here pins the stdcall
//! argument blocks.

use crate::compat::harness::surface::assert_argument_blocks;

pub const MEMBERS: &[&str] = &[
    "VirtualAlloc",
    "VirtualFree",
    "VirtualQuery",
    "VirtualProtect",
    "GetSystemInfo",
    "GlobalMemoryStatus",
    "IsBadReadPtr",
    "IsBadWritePtr",
    "IsBadCodePtr",
    "IsBadStringPtrA",
];

/// Every member pops the block its callers push. Ledger: virtual-memory.
#[test]
#[ignore = "ledger virtual-memory: not switched on"]
fn virtual_memory_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}
