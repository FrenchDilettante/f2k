//! kernel32.dll: the Win32 base DLL every program imports.
//!
//! The library (src/lib.rs) is the home of kernel32's user-mode code; this binary links it into the
//! DLL beside the assembly natives (src/natives.s), the critical sections' initialization
//! (src/critsec.s, over ntdll's), the heap and Local/Global functions (src/memory.s, over ntdll's
//! heap exports, their bodies here), the thread start thunks (src/start.s), the pointer probes
//! (src/probe.s), and the generated stubs file (empty for kernel32: only ntdll's system services
//! have generated bodies). RtlUnwind, the
//! critical sections' Enter, Leave, TryEnter and Delete, and HeapAlloc, HeapFree, HeapReAlloc,
//! HeapSize and HeapValidate are forwarders: they live in ntdll, as on Windows 2000.

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

use kernel32::nt;
use rtl::localmem::{HeapCalls, Memory, Outcome};
use rtl::sys;

/// InitializeCriticalSection: ntdll's RtlInitializeCriticalSection, its failure raised (as Windows
/// 2000's kernel32 raises it; with no event preallocated it cannot fail). Its body is the
/// critical-section initialization kernel32 keeps itself (src/critsec.s's export calls it, cdecl).
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_initialize_critical_section(section: *mut u8) {
    // SAFETY: ntdll's exports; the caller's section, written in place (a bad pointer faults the
    // caller).
    unsafe {
        let status = nt::RtlInitializeCriticalSection(section);
        if !rtl::status::nt_success(status) {
            nt::RtlRaiseStatus(status);
        }
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

/// The process heap, through ntdll's RtlAllocateHeap family (as Windows 2000's kernel32 reaches
/// it for Local and Global memory).
struct ProcessHeap(usize);

impl HeapCalls for ProcessHeap {
    fn alloc(&self, flags: u32, size: usize) -> Option<usize> {
        // SAFETY: ntdll's export, on the process heap (which raises no failures).
        Some(unsafe { nt::RtlAllocateHeap(self.0, flags, size) } as usize).filter(|&block| block != 0)
    }

    fn free(&self, flags: u32, pointer: usize) -> bool {
        // SAFETY: ntdll's export; a pointer that is no block of the heap is refused, not followed.
        (unsafe { nt::RtlFreeHeap(self.0, flags, pointer as *mut u8) }) != 0
    }

    fn size(&self, flags: u32, pointer: usize) -> Option<usize> {
        // SAFETY: as above; -1 for what is not a block.
        Some(unsafe { nt::RtlSizeHeap(self.0, flags, pointer as *const u8) }).filter(|&size| size != usize::MAX)
    }

    fn realloc(&self, flags: u32, pointer: usize, size: usize) -> Option<usize> {
        // SAFETY: as above.
        Some(unsafe { nt::RtlReAllocateHeap(self.0, flags, pointer as *mut u8, size) } as usize).filter(|&block| block != 0)
    }
}

/// The process heap's Local and Global memory, over ntdll's heap calls.
fn with_memory<R>(body: impl FnOnce(&Memory<'_, ProcessHeap>) -> R) -> R {
    let heap = ProcessHeap(sys::process_heap_handle());
    body(&Memory { heap: &heap })
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
    // SAFETY: ntdll's export, over the process heap.
    let slots = unsafe {
        nt::RtlAllocateHeap(sys::process_heap_handle(), rtl::heap::HEAP_ZERO_MEMORY, rtl::ldr::EXPANSION_BYTES)
    } as usize;
    if slots == 0 {
        return 0;
    }
    sys::write(sys::teb() + sys::TEB_TLS_EXPANSION_SLOTS, slots);
    slots
}
