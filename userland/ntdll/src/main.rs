//! ntdll.dll: the system DLL Windows 2000 loads into every process first.
//!
//! It carries Windows 2000's system-service stubs (`Nt*`, each under its `Zw` name too, raising the
//! gate on Windows 2000's own number), generated from the export specs (exports.toml);
//! RtlNtStatusToDosError (`src/status.rs`, over `rtl::status`); CsrClientCallServer (`src/csr.s`:
//! kernel32's console calls, to the kernel's console server); the exception dispatcher, entirely in
//! user mode (KiUserExceptionDispatcher, RtlUnwind — kernel32 forwards to it —, RtlRaiseException
//! and RtlRaiseStatus: `src/except.s` and `src/except.rs` over `rtl::seh`); the critical sections,
//! entirely in user mode (the RtlInitializeCriticalSection family, kernel32's Enter, Leave,
//! TryEnter and Delete forwarding here: `src/critsec.s` over `rtl::critsec`) and the PEB lock
//! (RtlAcquirePebLock, RtlReleasePebLock); the heaps, entirely in user mode (the RtlCreateHeap
//! family, kernel32's HeapAlloc, HeapFree, HeapReAlloc, HeapSize and HeapValidate forwarding here:
//! `src/heap.s` over `rtl::heap`); the environment (RtlSetEnvironmentVariable,
//! RtlQueryEnvironmentVariable_U, RtlExpandEnvironmentStrings_U: `src/env.rs` over `rtl::env`);
//! the loader's share of a thread's start, LdrInitializeThunk, which the kernel delivers before a
//! fresh thread's first instruction (`src/ldr.s`: the process heap); and the F2K-internal entry
//! point the kernel sends a thread to (`src/internal.s`): the thread-exit trampoline a child
//! thread's function returns onto. The kernel finds the trampoline, LdrInitializeThunk and the two
//! dispatchers by their export names; kernel32's surface carries Windows 2000's names alone.

#![no_std]
#![no_main]

extern crate rtl;

mod env;
mod except;
mod status;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("internal.s"),
    include_str!("ldr.s"),
    include_str!("except.s"),
    include_str!("csr.s"),
    include_str!("critsec.s"),
    include_str!("heap.s"),
);

use rtl::critsec::{CriticalSection, STATUS_SUCCESS};
use rtl::heap::{HEAP_GENERATE_EXCEPTIONS, HEAP_GROWABLE, HEAP_REALLOC_IN_PLACE_ONLY};
use rtl::sys::{self, Native};

// The critical sections' bodies, cdecl, called by src/critsec.s's exports. A section pointer is
// the caller's: a bad one faults the caller, as on Windows.

/// RtlInitializeCriticalSection: free, no event until the first contention. STATUS_SUCCESS.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_initialize_critical_section(section: *const CriticalSection) -> u32 {
    f2k_rtl_initialize_critical_section_and_spin_count(section, 0)
}

/// RtlInitializeCriticalSectionAndSpinCount: as RtlInitializeCriticalSection, with a spin count
/// (its high bit preallocating the event). STATUS_NO_MEMORY when that event cannot be made.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_initialize_critical_section_and_spin_count(
    section: *const CriticalSection,
    spin_count: u32,
) -> u32 {
    // SAFETY: the caller's section, read and written in place.
    match unsafe { &*section }.initialize(&Native, spin_count) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// RtlEnterCriticalSection. STATUS_SUCCESS (in low memory a contended enter raises instead).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_enter_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: the caller's section.
    unsafe { &*section }.enter(&Native);
    STATUS_SUCCESS
}

/// RtlTryEnterCriticalSection: TRUE when the caller now holds the section.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_try_enter_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: the caller's section.
    unsafe { &*section }.try_enter(&Native) as u32
}

/// RtlLeaveCriticalSection. STATUS_SUCCESS.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_leave_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: the caller's section.
    unsafe { &*section }.leave(&Native);
    STATUS_SUCCESS
}

/// RtlDeleteCriticalSection: its event closed. STATUS_SUCCESS.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_delete_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: the caller's section.
    unsafe { &*section }.delete(&Native);
    STATUS_SUCCESS
}

/// RtlSetCriticalSectionSpinCount: the previous spin count.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_set_critical_section_spin_count(
    section: *const CriticalSection,
    spin_count: u32,
) -> u32 {
    // SAFETY: the caller's section.
    unsafe { &*section }.set_spin_count(&Native, spin_count)
}

/// RtlAcquirePebLock: take the PEB lock.
#[unsafe(export_name = "f2k_export_RtlAcquirePebLock")]
pub extern "system" fn rtl_acquire_peb_lock() {
    sys::peb_lock().enter(&Native);
}

/// RtlReleasePebLock: release it.
#[unsafe(export_name = "f2k_export_RtlReleasePebLock")]
pub extern "system" fn rtl_release_peb_lock() {
    sys::peb_lock().leave(&Native);
}

// The heaps' bodies, cdecl, called by src/heap.s's exports. A handle the process's heap list does
// not hold names no heap: the calls refuse it without touching it.

/// A failed allocation's answer to its export: zero, with the high dword set when it must raise
/// STATUS_NO_MEMORY instead (HEAP_GENERATE_EXCEPTIONS on the call or the heap): src/heap.s raises
/// it from the export, through RtlRaiseException.
fn refused(handle: usize, flags: u32) -> u64 {
    let heap_flags = sys::process().heap(handle).map_or(0, |heap| heap.flags());
    if (flags | heap_flags) & HEAP_GENERATE_EXCEPTIONS != 0 {
        1 << 32
    } else {
        0
    }
}

/// RtlCreateHeap(Flags, HeapBase, ReserveSize, CommitSize): a growable heap (HEAP_GROWABLE, or no
/// reservation size) or one of ReserveSize bytes, CommitSize committed; null when there is no room,
/// or for a caller-supplied base (not supported).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_create_heap(flags: u32, base: usize, reserve: usize, commit: usize) -> usize {
    if base != 0 {
        return 0;
    }
    let maximum = if flags & HEAP_GROWABLE != 0 {
        0
    } else {
        reserve
    };
    sys::process()
        .create(&Native, flags, commit, maximum)
        .map_or(0, |heap| heap.handle())
}

/// RtlDestroyHeap: null once destroyed; the handle back for the process heap or no heap.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_destroy_heap(handle: usize) -> usize {
    if handle == sys::process_heap_handle() || !sys::process().destroy(&Native, handle) {
        return handle;
    }
    0
}

/// RtlAllocateHeap: the block, or the refusal ([`refused`]).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_allocate_heap(handle: usize, flags: u32, size: usize) -> u64 {
    match sys::process()
        .heap(handle)
        .and_then(|heap| heap.alloc(&Native, flags, size))
    {
        Some(block) => block as u64,
        None => refused(handle, flags),
    }
}

/// RtlFreeHeap: TRUE once freed (a null pointer frees nothing and succeeds).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_free_heap(handle: usize, flags: u32, pointer: usize) -> u32 {
    u32::from(
        pointer == 0
            || sys::process()
                .heap(handle)
                .is_some_and(|heap| heap.free(&Native, flags, pointer)),
    )
}

/// RtlReAllocateHeap: the block, or the refusal ([`refused`]; an in-place resize that does not fit
/// is a plain refusal).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_reallocate_heap(
    handle: usize,
    flags: u32,
    pointer: usize,
    size: usize,
) -> u64 {
    match sys::process()
        .heap(handle)
        .and_then(|heap| heap.realloc(&Native, flags, pointer, size))
    {
        Some(block) => block as u64,
        None if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 => 0,
        None => refused(handle, flags),
    }
}

/// RtlSizeHeap: the size asked for; -1 for what is not a block.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_size_heap(handle: usize, flags: u32, pointer: usize) -> usize {
    sys::process()
        .heap(handle)
        .and_then(|heap| heap.size(&Native, flags, pointer))
        .unwrap_or(usize::MAX)
}

/// RtlValidateHeap: the whole heap's headers (a null pointer), or one block.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_validate_heap(handle: usize, flags: u32, pointer: usize) -> u32 {
    u32::from(
        sys::process()
            .heap(handle)
            .is_some_and(|heap| heap.validate(&Native, flags, pointer)),
    )
}

// The loader's share of a thread's start: LdrInitializeThunk's body (src/ldr.s calls it).

/// A fresh thread's initialization, before anything else it runs in user mode: the process's first
/// thread makes the heap list's lock and the process heap (PEB+0x18, the list's first entry). A
/// heap that finds no room is left unmade (the program meets a null process heap). B7 adds the
/// rest of Windows 2000's LdrpInitialize here: the PEB lock and the loader lock (the kernel plants
/// the PEB lock free until then), and every thread's implicit-TLS block (`rtl::ldr`).
#[unsafe(no_mangle)]
extern "C" fn f2k_ldr_initialize() {
    if sys::process_heap_handle() == 0 {
        let process = sys::process();
        // SAFETY: the PEB's lock slot, zero until now (no other thread of the process runs yet).
        let _ = unsafe { &*process.lock }.initialize(&Native, 0);
        if let Some(heap) = process.create(&Native, 0, 0, 0) {
            sys::set_process_heap(heap.handle());
        }
    }
}
