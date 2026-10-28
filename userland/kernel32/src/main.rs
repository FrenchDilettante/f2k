//! kernel32.dll: the Win32 base DLL every program imports.
//!
//! The library (src/lib.rs) is the home of kernel32's user-mode code; this binary links it into the
//! DLL beside the assembly natives (src/natives.s), the critical sections' initialization
//! (src/critsec.s, over ntdll's), the heap and Local/Global functions (src/memory.s, over ntdll's
//! heap and handle-table exports, their bodies here), the thread start thunks (src/start.s), the
//! pointer probes (src/probe.s), the generated stubs file (empty for kernel32: only ntdll's,
//! user32's and gdi32's system services have generated stubs), and the system messages' table (its
//! resource, which the build links in). RtlUnwind, the critical sections' Enter, Leave, TryEnter
//! and Delete, and HeapAlloc, HeapFree, HeapReAlloc and HeapSize are forwarders: they live in
//! ntdll, as on Windows 2000.

#![no_std]
#![no_main]

extern crate rtl;
// The user-mode exports' bodies (src/lib.rs): the .def exports them from the library.
extern crate kernel32 as _;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("natives.s"),
    include_str!("start.s"),
    include_str!("probe.s"),
    include_str!("critsec.s"),
    include_str!("memory.s"),
);

use kernel32::{nt, ntcall};
use rtl::critsec::CriticalSection;
use rtl::handles::HandleTable;
use rtl::localmem::{HandleCalls, HeapCalls, Memory, Outcome, ENTRY_SIZE, MAXIMUM_HANDLES};
use rtl::sys;

/// InitializeCriticalSection: ntdll's RtlInitializeCriticalSection, its failure raised (as Windows
/// 2000's kernel32 raises it; with no event preallocated it cannot fail). Its body is the
/// critical-section initialization kernel32 keeps itself (src/critsec.s's export calls it, cdecl).
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_initialize_critical_section(section: *mut u8) {
    // SAFETY: the caller's CRITICAL_SECTION, its 24 bytes a section's atomics (ntdll writes it in
    // place; a bad pointer faults the caller there).
    let section = unsafe { &*section.cast::<CriticalSection>() };
    if let Err(status) = ntcall::initialize_critical_section(section) {
        ntcall::raise_status(status);
    }
}

/// The Win32 errors kernel32's own heap calls set.
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// HeapCreate: ntdll's RtlCreateHeap — a heap of `maximum` bytes (growable when zero), `initial`
/// committed; null with ERROR_NOT_ENOUGH_MEMORY when there is no room.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_heap_create(flags: u32, initial: usize, maximum: usize) -> usize {
    // SAFETY: ntdll's export, without a caller-supplied base, lock or parameters.
    match unsafe { nt::RtlCreateHeap(flags, 0, maximum, initial, 0, 0) } {
        0 => {
            sys::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            0
        }
        heap => heap,
    }
}

/// HeapDestroy: ntdll's RtlDestroyHeap, every page of the heap given back; FALSE with
/// ERROR_INVALID_HANDLE when it hands the handle back (the process heap, or a handle naming no
/// heap).
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_heap_destroy(handle: usize) -> u32 {
    // SAFETY: ntdll's export.
    if unsafe { nt::RtlDestroyHeap(handle) } == 0 {
        return 1;
    }
    sys::set_last_error(ERROR_INVALID_HANDLE);
    0
}

/// HeapValidate: ntdll's RtlValidateHeap, its BOOLEAN widened to a BOOL. Windows 2000's kernel32
/// exports it as its own code, not as a forwarder.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_heap_validate(handle: usize, flags: u32, block: usize) -> u32 {
    // SAFETY: ntdll's export; a pointer that is no block of the heap is refused, not followed.
    u32::from(unsafe { nt::RtlValidateHeap(handle, flags, block as *const u8) })
}

/// The process heap, through ntdll's RtlAllocateHeap family (as Windows 2000's kernel32 reaches
/// it for Local and Global memory).
struct ProcessHeap(usize);

impl HeapCalls for ProcessHeap {
    fn alloc(&self, flags: u32, size: usize) -> Option<usize> {
        ntcall::allocate_heap_with(flags, size).map(|block| block.as_ptr() as usize)
    }

    fn free(&self, flags: u32, pointer: usize) -> bool {
        // SAFETY: LocalFree's and GlobalFree's caller gives the block back (nothing of kernel32's
        // uses it); a pointer that is no block of the heap is refused, not followed.
        unsafe { ntcall::free_heap_with(flags, pointer as *mut u8) }
    }

    fn size(&self, flags: u32, pointer: usize) -> Option<usize> {
        // SAFETY: as above; -1 for what is not a block.
        Some(unsafe { nt::RtlSizeHeap(self.0, flags, pointer as *const u8) })
            .filter(|&size| size != usize::MAX)
    }

    fn realloc(&self, flags: u32, pointer: usize, size: usize) -> Option<usize> {
        // SAFETY: as above.
        Some(unsafe { nt::RtlReAllocateHeap(self.0, flags, pointer as *mut u8, size) } as usize)
            .filter(|&block| block != 0)
    }
}

/// kernel32's handle table, where the movable Local and Global blocks' handles come from:
/// kernel32's own data on Windows 2000, here on the PEB's page past the PEB proper, where kernel32
/// keeps its other per-process state (F2K's system DLLs keep no writable data). Zero until the
/// first Local or Global call initializes it (kernel32 has no DllMain to do it at the process's
/// start).
const HANDLE_TABLE: usize = 0x8E0;

/// kernel32's handle table, through ntdll's RtlAllocateHandle family (as Windows 2000's kernel32
/// keeps its movable blocks' handles).
struct BaseHandles(*mut HandleTable);

impl HandleCalls for BaseHandles {
    fn allocate(&self) -> Option<usize> {
        // SAFETY: ntdll's export, over kernel32's initialized table, under the heap's lock.
        Some(unsafe { nt::RtlAllocateHandle(self.0, core::ptr::null_mut()) })
            .filter(|&entry| entry != 0)
    }

    fn free(&self, entry: usize) -> bool {
        // SAFETY: as above; an address that is no entry in use is refused, not followed.
        (unsafe { nt::RtlFreeHandle(self.0, entry) }) != 0
    }

    fn is_valid(&self, entry: usize) -> bool {
        // SAFETY: as above.
        (unsafe { nt::RtlIsValidHandle(self.0, entry) }) != 0
    }
}

/// The process heap's Local and Global memory, over ntdll's heap calls and kernel32's handle table,
/// the heap's lock held across the call (RtlLockHeap, RtlUnlockHeap: the table and the blocks
/// change together, as Windows 2000's kernel32 holds it). The table is initialized at the first
/// call, under the lock.
fn with_memory<R>(body: impl FnOnce(&Memory<'_, ProcessHeap, BaseHandles>) -> R) -> R {
    let heap = ProcessHeap(sys::process_heap_handle());
    let table = (sys::peb() + HANDLE_TABLE) as *mut HandleTable;
    // SAFETY: ntdll's exports; the table is kernel32's slot on the PEB's page, the process's own,
    // changed only under the heap's lock.
    unsafe {
        nt::RtlLockHeap(heap.0);
        if (*table).maximum_number_of_handles == 0 {
            nt::RtlInitializeHandleTable(MAXIMUM_HANDLES, ENTRY_SIZE, table);
        }
    }
    let result = body(&Memory {
        heap: &heap,
        handles: &BaseHandles(table),
    });
    // SAFETY: ntdll's export; the lock taken above.
    unsafe { nt::RtlUnlockHeap(heap.0) };
    result
}

/// A Local/Global call's answer: its value, its last error set when it names one.
fn finish(outcome: Outcome) -> usize {
    if let Some(error) = outcome.error {
        sys::set_last_error(error);
    }
    outcome.value
}

/// LocalAlloc / GlobalAlloc.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_alloc(flags: u32, size: usize) -> usize {
    finish(with_memory(|memory| memory.alloc(flags, size)))
}

/// LocalFree / GlobalFree.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_free(handle: usize) -> usize {
    finish(with_memory(|memory| memory.free(handle)))
}

/// LocalLock / GlobalLock.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_lock(handle: usize) -> usize {
    with_memory(|memory| memory.lock(handle))
}

/// LocalUnlock / GlobalUnlock.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_unlock(handle: usize) -> usize {
    finish(with_memory(|memory| memory.unlock(handle)))
}

/// LocalHandle / GlobalHandle.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_handle(pointer: usize) -> usize {
    with_memory(|memory| memory.handle_of(pointer))
}

/// LocalSize / GlobalSize.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_size(handle: usize) -> usize {
    finish(with_memory(|memory| memory.size(handle)))
}

/// LocalFlags.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_flags(handle: usize) -> usize {
    with_memory(|memory| memory.flags(handle))
}

/// LocalReAlloc / GlobalReAlloc.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_local_realloc(handle: usize, size: usize, flags: u32) -> usize {
    finish(with_memory(|memory| memory.realloc(handle, size, flags)))
}

/// TlsSetValue's first use of an expansion index on this thread: its 1024 expansion slots, zeroed,
/// on the process heap, recorded in its TEB; null when the heap has no room (src/natives.s).
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_tls_expansion() -> usize {
    let Some(slots) =
        ntcall::allocate_heap_with(rtl::heap::HEAP_ZERO_MEMORY, rtl::ldr::EXPANSION_BYTES)
    else {
        return 0;
    };
    let slots = slots.as_ptr() as usize;
    sys::write(sys::teb() + sys::TEB_TLS_EXPANSION_SLOTS, slots);
    slots
}
