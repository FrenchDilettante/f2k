//! Virtual memory: the CRT's own region — one reservation at NULL landing at a fixed base, committed
//! contiguously from it — and a VirtualFree that frees nothing. The arguments follow the CRT's
//! calls in the hello fixture's real-machine trace.

use crate::compat::harness::fake::{Call, CRT_REGION_BASE, MEM_COMMIT, MEM_RESERVE};
use crate::compat::harness::surface::{assert_argument_blocks, Fixture};

pub const MEMBERS: &[&str] = &["VirtualAlloc", "VirtualFree"];

const PAGE_READWRITE: u32 = 0x04;
const MEM_RELEASE: u32 = 0x8000;
const MEM_DECOMMIT: u32 = 0x4000;

/// A fixture whose CRT region is reserved the way the CRT reserves it: 1 MiB at NULL.
fn reserved() -> Fixture {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.call("VirtualAlloc", &[0, 0x10_0000, MEM_RESERVE, PAGE_READWRITE]),
        CRT_REGION_BASE
    );
    fixture.kernel.clear_calls();
    fixture
}

fn commit(fixture: &mut Fixture, address: u32, size: u32) -> u32 {
    fixture.call("VirtualAlloc", &[address, size, MEM_COMMIT, PAGE_READWRITE])
}

/// Every member pops the block its callers push. Ledger: virtual-memory.
#[test]
#[ignore = "ledger virtual-memory: not switched on"]
fn virtual_memory_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// VirtualAlloc reserving at NULL returns the CRT region's base; the kernel is asked for exactly
/// the reservation. Ledger: virtual-memory/VirtualAlloc.
#[test]
#[ignore = "ledger virtual-memory/VirtualAlloc: the existing path maps pages into the live \
            address space (target-only)"]
fn virtual_alloc_reserves_at_null() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.call("VirtualAlloc", &[0, 0x10_0000, MEM_RESERVE, PAGE_READWRITE]),
        CRT_REGION_BASE
    );
    assert_eq!(
        fixture.kernel.calls(),
        [Call::AllocateVirtualMemory {
            base: 0,
            size: 0x10_0000,
            allocation_type: MEM_RESERVE
        }]
    );
}

/// VirtualAlloc commits from the reservation's base, contiguously: the committed pages are zeroed
/// and writable; a commit inside the committed prefix returns its address; a commit leaving a gap,
/// or reaching past the reservation, returns NULL. Ledger: virtual-memory/VirtualAlloc.
#[test]
#[ignore = "ledger virtual-memory/VirtualAlloc: the existing path maps pages into the live \
            address space (target-only)"]
fn virtual_alloc_commits_contiguously() {
    let mut fixture = reserved();
    assert_eq!(
        commit(&mut fixture, CRT_REGION_BASE, 0x8000),
        CRT_REGION_BASE
    );
    assert_eq!(
        fixture.memory().bytes(CRT_REGION_BASE, 0x8000),
        vec![0; 0x8000]
    );
    fixture
        .memory()
        .write(CRT_REGION_BASE + 0x7FFC, b"tail")
        .unwrap();
    assert_eq!(
        commit(&mut fixture, CRT_REGION_BASE + 0x1000, 0x1000),
        CRT_REGION_BASE + 0x1000
    );
    assert_eq!(
        commit(&mut fixture, CRT_REGION_BASE + 0x8000, 0x8000),
        CRT_REGION_BASE + 0x8000
    );
    assert_eq!(commit(&mut fixture, CRT_REGION_BASE + 0x2_0000, 0x1000), 0);
    assert_eq!(commit(&mut fixture, CRT_REGION_BASE + 0xF_F000, 0x2000), 0);
    assert_eq!(fixture.memory().bytes(CRT_REGION_BASE + 0x7FFC, 4), b"tail");
}

/// VirtualAlloc serves one live reservation, at NULL only; a commit with nothing reserved, or
/// outside the reservation, returns NULL. Ledger: virtual-memory/VirtualAlloc.
#[test]
#[ignore = "ledger virtual-memory/VirtualAlloc: the existing path maps pages into the live \
            address space (target-only)"]
fn virtual_alloc_refuses_other_reservations_and_stray_commits() {
    let mut fixture = Fixture::new();
    assert_eq!(commit(&mut fixture, CRT_REGION_BASE, 0x1000), 0);
    assert_eq!(commit(&mut fixture, 0x0030_0000, 0x1000), 0);
    assert_eq!(
        fixture.call(
            "VirtualAlloc",
            &[0x0030_0000, 0x1_0000, MEM_RESERVE, PAGE_READWRITE]
        ),
        0
    );
    let mut fixture = reserved();
    assert_eq!(
        fixture.call("VirtualAlloc", &[0, 0x1_0000, MEM_RESERVE, PAGE_READWRITE]),
        0
    );
    assert_eq!(commit(&mut fixture, 0x0030_0000, 0x1000), 0);
}

/// A NULL reservation is whole pages and at least one 64 KiB allocation unit; reserving and
/// committing at once commits the request. Ledger: virtual-memory/VirtualAlloc.
#[test]
#[ignore = "ledger virtual-memory/VirtualAlloc: the existing path maps pages into the live \
            address space (target-only)"]
fn virtual_alloc_rounds_reservations() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.call(
            "VirtualAlloc",
            &[0, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE]
        ),
        CRT_REGION_BASE
    );
    assert!(fixture.memory().is_mapped(CRT_REGION_BASE, 0x2000));
    assert_eq!(
        commit(&mut fixture, CRT_REGION_BASE + 0x2000, 0xE000),
        CRT_REGION_BASE + 0x2000
    );
    assert_eq!(commit(&mut fixture, CRT_REGION_BASE + 0x1_0000, 0x1000), 0);
}

/// VirtualFree succeeds and frees nothing: the pages stay committed, the kernel is not asked.
/// Ledger: virtual-memory/VirtualFree.
#[test]
#[ignore = "ledger virtual-memory/VirtualFree: not switched on"]
fn virtual_free_succeeds_without_freeing() {
    let mut fixture = Fixture::new();
    let page = fixture.buffer(0x1000);
    for (address, size, free_type) in [
        (page, 0, MEM_RELEASE),
        (page, 0x1000, MEM_DECOMMIT),
        (0, 0, 0),
    ] {
        assert_eq!(fixture.call("VirtualFree", &[address, size, free_type]), 1);
    }
    assert!(fixture.memory().is_mapped(page, 0x1000));
    assert_eq!(fixture.kernel.calls(), []);
}
