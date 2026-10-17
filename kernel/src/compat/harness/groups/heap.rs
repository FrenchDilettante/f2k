//! Heap: the Win32 heaps and the Local/Global memory served from the process heap. The heaps live
//! in the process's address space (see `userheap`), so every behavior is target-only; the memory
//! fixture's capture pins them. The scenarios here pin the stdcall argument blocks.

use crate::compat::harness::surface::{assert_argument_blocks, prototype_arg_bytes, registry_arg_bytes};

pub const MEMBERS: &[&str] = &[
    "HeapAlloc",
    "HeapCreate",
    "HeapDestroy",
    "HeapFree",
    "HeapReAlloc",
    "GetProcessHeap",
    "HeapSize",
    "HeapValidate",
    "LocalAlloc",
    "LocalFree",
    "LocalLock",
    "LocalUnlock",
    "LocalHandle",
    "LocalSize",
    "LocalFlags",
    "LocalReAlloc",
    "GlobalAlloc",
    "GlobalFree",
    "GlobalLock",
    "GlobalUnlock",
    "GlobalHandle",
    "GlobalSize",
    "GlobalReAlloc",
];

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
