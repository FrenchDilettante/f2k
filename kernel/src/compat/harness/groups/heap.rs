//! Heap: the process heap the CRT allocates from — one fixed heap, its blocks first-fit in a
//! region committed on demand, freed blocks coalesced, a resize moving the block only when it must
//! grow. The arguments follow the CRT's own calls in the hello fixture's real-machine trace.

use crate::compat::harness::fake::{
    Call, HEAP_REGION_BASE, HEAP_REGION_MAX, MEM_COMMIT, PAGE_SIZE,
};
use crate::compat::harness::surface::{
    assert_argument_blocks, prototype_arg_bytes, registry_arg_bytes, Fixture, HEAP_HANDLE,
    HEAP_REALLOC_IN_PLACE_ONLY, HEAP_ZERO_MEMORY,
};

pub const MEMBERS: &[&str] = &[
    "HeapAlloc",
    "HeapCreate",
    "HeapDestroy",
    "HeapFree",
    "HeapReAlloc",
];

/// The CRT's HeapCreate: serialized, 4 KiB initial, growable.
const CRT_HEAP_CREATE: [u32; 3] = [1, 0x1000, 0];

/// A fixture whose heap is created the way the CRT creates it.
fn created() -> Fixture {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("HeapCreate", &CRT_HEAP_CREATE), HEAP_HANDLE);
    fixture.kernel.clear_calls();
    fixture
}

fn alloc(fixture: &mut Fixture, flags: u32, bytes: u32) -> u32 {
    fixture.call("HeapAlloc", &[HEAP_HANDLE, flags, bytes])
}

/// Every member pops the block its callers push. Ledger: heap.
#[test]
fn heap_argument_blocks_match_the_prototypes() {
    assert_argument_blocks(MEMBERS);
}

/// HeapDestroy pops one dword: the CRT's call site (its heap-initialization failure path) pushes
/// exactly one, the heap handle, before the indirect call through the import slot. Ledger:
/// heap/HeapDestroy.
#[test]
fn heap_destroy_pops_one_dword() {
    use crate::exec::pe::Image;
    const RET0: &[u8] = include_bytes!("../../../../../tests/ret0/ret0.exe");
    const MARK: u32 = 0x5EED_0001;
    let image = Image::parse(RET0).expect("ret0 parses");
    let mut mapped = vec![0u8; image.size_of_image as usize];
    image.map_into(RET0, &mut mapped);
    image.snap_imports(RET0, &mut mapped, |module, name| {
        if !crate::exec::pe::same_module(module, "KERNEL32.dll") {
            return Err(crate::exec::pe::Unresolved::NoModule);
        }
        Ok(if name == "HeapDestroy" { MARK } else { 0x1000 })
    });
    let slot = (0..mapped.len() - 4)
        .step_by(4)
        .find(|&rva| mapped[rva..rva + 4] == MARK.to_le_bytes())
        .expect("ret0 imports HeapDestroy") as u32;
    let mut call = vec![0xFF, 0x15];
    call.extend_from_slice(&(image.image_base + slot).to_le_bytes());
    let sites: Vec<usize> = (6..mapped.len() - call.len())
        .filter(|&at| mapped[at..at + call.len()] == call[..])
        .collect();
    assert!(!sites.is_empty(), "ret0 calls HeapDestroy");
    for site in sites {
        assert_eq!(
            mapped[site - 6..site - 4],
            [0xFF, 0x35],
            "push dword [mem] at {site:#x}"
        );
    }
    assert_eq!(prototype_arg_bytes("HeapDestroy"), 4);
    assert_eq!(registry_arg_bytes("HeapDestroy"), 4);
}

/// HeapCreate reports the one heap's handle whatever it is asked for, and commits nothing yet.
/// Ledger: heap/HeapCreate.
#[test]
fn heap_create_reports_the_heap_handle() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.call("HeapCreate", &CRT_HEAP_CREATE), HEAP_HANDLE);
    assert_eq!(fixture.call("HeapCreate", &[0, 0, 0x10_0000]), HEAP_HANDLE);
    assert_eq!(fixture.kernel.calls(), []);
}

/// HeapAlloc serves the CRT's startup requests (its 0x140-byte header block, then its 0x41C4-byte
/// zeroed small-block directory): distinct 8-byte-aligned blocks inside the heap region, the
/// zeroed one zero. Ledger: heap/HeapAlloc.
#[test]
fn heap_alloc_serves_aligned_blocks_inside_the_region() {
    let mut fixture = created();
    let header = alloc(&mut fixture, 0, 0x140);
    let directory = alloc(&mut fixture, HEAP_ZERO_MEMORY, 0x41C4);
    for block in [header, directory] {
        assert_ne!(block, 0);
        assert_eq!(block % 8, 0);
        assert!(block >= HEAP_REGION_BASE && block < HEAP_REGION_BASE + HEAP_REGION_MAX as u32);
    }
    assert!(directory >= header + 0x140, "the blocks do not overlap");
    assert!(fixture
        .memory()
        .bytes(directory, 0x41C4)
        .iter()
        .all(|&byte| byte == 0));
}

/// HeapAlloc commits the region through the kernel on demand, from its base upward, in whole
/// pages, one page beyond what the request needs; requests that fit the committed region commit
/// nothing. Ledger: heap/HeapAlloc.
#[test]
fn heap_alloc_commits_the_region_on_demand() {
    let mut fixture = created();
    alloc(&mut fixture, 0, 0x140);
    assert_eq!(
        fixture.kernel.calls(),
        [Call::AllocateVirtualMemory {
            base: HEAP_REGION_BASE,
            size: 2 * PAGE_SIZE,
            allocation_type: MEM_COMMIT
        }]
    );
    fixture.kernel.clear_calls();
    alloc(&mut fixture, 0, 0x100);
    assert_eq!(fixture.kernel.calls(), []);
    alloc(&mut fixture, 0, 0x2000);
    let [Call::AllocateVirtualMemory { base, .. }] = fixture.kernel.calls() else {
        panic!("one commit: {:?}", fixture.kernel.calls());
    };
    assert_eq!(*base, HEAP_REGION_BASE + 2 * PAGE_SIZE, "contiguous");
}

/// HeapAlloc refuses a handle that is not the heap's before anything else — nothing is committed —
/// and a request the region's cap cannot hold. Ledger: heap/HeapAlloc.
#[test]
fn heap_alloc_refuses_foreign_handles_and_oversized_requests() {
    let mut fixture = created();
    assert_eq!(fixture.call("HeapAlloc", &[0x0013_0000, 0, 16]), 0);
    assert_eq!(fixture.call("HeapAlloc", &[0, 0, 16]), 0);
    assert_eq!(fixture.kernel.calls(), []);
    assert_eq!(alloc(&mut fixture, 0, HEAP_REGION_MAX as u32), 0);
    assert_eq!(alloc(&mut fixture, 0, u32::MAX), 0);
    assert_ne!(alloc(&mut fixture, 0, 16), 0, "the heap still serves");
}

/// HEAP_ZERO_MEMORY zeroes a reused block; without it the old bytes may stay. Ledger:
/// heap/HeapAlloc.
#[test]
fn heap_alloc_zeroes_a_reused_block_on_request() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 64);
    fixture.memory().write(block, &[0xAB; 64]).unwrap();
    assert_eq!(fixture.call("HeapFree", &[HEAP_HANDLE, 0, block]), 1);
    assert_eq!(
        alloc(&mut fixture, HEAP_ZERO_MEMORY, 64),
        block,
        "first fit"
    );
    assert_eq!(fixture.memory().bytes(block, 64), [0; 64]);
}

/// HeapFree releases a live block once: a second free, a pointer into a block's middle, a pointer
/// outside the region, NULL, and a foreign heap handle all fail. Ledger: heap/HeapFree.
#[test]
fn heap_free_releases_live_blocks_only() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 32);
    let free = |fixture: &mut Fixture, heap: u32, pointer: u32| {
        fixture.call("HeapFree", &[heap, 0, pointer])
    };
    assert_eq!(free(&mut fixture, 0x0013_0000, block), 0);
    assert_eq!(free(&mut fixture, HEAP_HANDLE, block + 8), 0);
    assert_eq!(free(&mut fixture, HEAP_HANDLE, 0), 0);
    assert_eq!(free(&mut fixture, HEAP_HANDLE, 0x0040_0000), 0);
    assert_eq!(free(&mut fixture, HEAP_HANDLE, block), 1);
    assert_eq!(free(&mut fixture, HEAP_HANDLE, block), 0);
}

/// HeapFree coalesces: freeing two neighbors makes room for one block spanning both. Ledger:
/// heap/HeapFree.
#[test]
fn heap_free_coalesces_neighbors() {
    let mut fixture = created();
    let first = alloc(&mut fixture, 0, 32);
    let second = alloc(&mut fixture, 0, 32);
    let _fence = alloc(&mut fixture, 0, 32);
    for block in [second, first] {
        assert_eq!(fixture.call("HeapFree", &[HEAP_HANDLE, 0, block]), 1);
    }
    assert_eq!(
        alloc(&mut fixture, 0, 72),
        first,
        "both blocks and the header between"
    );
}

/// HeapReAlloc growing a block moves it: the contents come along, the old block is freed (its
/// space is served again), and HEAP_ZERO_MEMORY zeroes the extension. Ledger: heap/HeapReAlloc.
#[test]
fn heap_realloc_grows_by_moving() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 16);
    fixture.memory().write(block, b"sixteen  bytes!!").unwrap();
    let grown = fixture.call("HeapReAlloc", &[HEAP_HANDLE, HEAP_ZERO_MEMORY, block, 48]);
    assert_ne!(grown, 0);
    assert_ne!(grown, block);
    let bytes = fixture.memory().bytes(grown, 48);
    assert_eq!(&bytes[..16], b"sixteen  bytes!!");
    assert_eq!(bytes[16..], [0; 32]);
    assert_eq!(alloc(&mut fixture, 0, 16), block, "the old block was freed");
}

/// HeapReAlloc shrinking (or keeping the size) keeps the block where it is. Ledger:
/// heap/HeapReAlloc.
#[test]
fn heap_realloc_shrinking_keeps_the_block() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 64);
    for size in [64, 8, 1] {
        assert_eq!(
            fixture.call("HeapReAlloc", &[HEAP_HANDLE, 0, block, size]),
            block
        );
    }
}

/// HEAP_REALLOC_IN_PLACE_ONLY: a resize that keeps the block succeeds in place; one that would
/// move it fails and leaves the block live, contents intact. Ledger: heap/HeapReAlloc.
#[test]
fn heap_realloc_in_place_only_never_moves() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 32);
    let _neighbor = alloc(&mut fixture, 0, 32);
    fixture.memory().write(block, &[0x5A; 32]).unwrap();
    let in_place = |fixture: &mut Fixture, size: u32| {
        fixture.call(
            "HeapReAlloc",
            &[HEAP_HANDLE, HEAP_REALLOC_IN_PLACE_ONLY, block, size],
        )
    };
    assert_eq!(in_place(&mut fixture, 16), block);
    assert_eq!(in_place(&mut fixture, 64), 0);
    assert_eq!(fixture.memory().bytes(block, 32), [0x5A; 32]);
    assert_eq!(
        fixture.call("HeapFree", &[HEAP_HANDLE, 0, block]),
        1,
        "still live"
    );
}

/// HeapReAlloc growth is served from the region already committed: a growth the committed region
/// cannot hold fails (where a fresh HeapAlloc of the same size would commit), and the original
/// block stays live. Ledger: heap/HeapReAlloc.
#[test]
fn heap_realloc_growth_does_not_commit() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 16);
    fixture.kernel.clear_calls();
    assert_eq!(
        fixture.call("HeapReAlloc", &[HEAP_HANDLE, 0, block, 3 * PAGE_SIZE]),
        0
    );
    assert_eq!(fixture.kernel.calls(), []);
    assert_ne!(alloc(&mut fixture, 0, 3 * PAGE_SIZE), 0);
    assert_eq!(
        fixture.call("HeapFree", &[HEAP_HANDLE, 0, block]),
        1,
        "still live"
    );
}

/// HeapReAlloc refuses a foreign handle and a pointer that names no live block. Ledger:
/// heap/HeapReAlloc.
#[test]
fn heap_realloc_refuses_foreign_handles_and_dead_blocks() {
    let mut fixture = created();
    let block = alloc(&mut fixture, 0, 16);
    assert_eq!(fixture.call("HeapReAlloc", &[0x0013_0000, 0, block, 32]), 0);
    assert_eq!(fixture.call("HeapReAlloc", &[HEAP_HANDLE, 0, 0, 32]), 0);
    assert_eq!(fixture.call("HeapFree", &[HEAP_HANDLE, 0, block]), 1);
    assert_eq!(fixture.call("HeapReAlloc", &[HEAP_HANDLE, 0, block, 32]), 0);
}

/// HeapDestroy accepts the heap's handle and resets the heap: the next allocation is served from
/// the region's start again. Any other handle is refused. Ledger: heap/HeapDestroy.
#[test]
fn heap_destroy_resets_the_heap() {
    let mut fixture = created();
    let first = alloc(&mut fixture, 0, 16);
    alloc(&mut fixture, 0, 16);
    assert_eq!(fixture.call("HeapDestroy", &[0x0013_0000]), 0);
    assert_eq!(fixture.call("HeapDestroy", &[HEAP_HANDLE]), 1);
    assert_eq!(alloc(&mut fixture, 0, 16), first);
}
