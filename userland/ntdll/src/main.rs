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
//! the current directory and the DOS paths (RtlSetCurrentDirectory_U, RtlGetCurrentDirectory_U,
//! RtlGetFullPathName_U, RtlDosPathNameToNtPathName_U: `src/curdir.rs` over `rtl::path`); the
//! loader's exports over the process's module lists (LdrGetDllHandle, LdrLoadDll, LdrUnloadDll,
//! LdrGetProcedureAddress: `src/loader.rs` over `rtl::modules`); and the loader's share of a
//! thread's start and end: LdrInitializeThunk, which the kernel delivers before a fresh thread's
//! first instruction (`src/ldr.s`: the process heap, the PEB lock and the loader lock, the thread's
//! implicit TLS), and LdrShutdownThread and LdrShutdownProcess, kernel32's ExitThread's and
//! ExitProcess's. The kernel finds LdrInitializeThunk and the two
//! dispatchers by their export names.

#![no_std]
#![no_main]

extern crate rtl;

mod curdir;
mod env;
mod except;
mod loader;
mod status;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("ldr.s"),
    include_str!("except.s"),
    include_str!("csr.s"),
    include_str!("critsec.s"),
    include_str!("heap.s"),
);

use rtl::critsec::{CriticalSection, STATUS_SUCCESS};
use rtl::heap::{HEAP_GENERATE_EXCEPTIONS, HEAP_GROWABLE, HEAP_REALLOC_IN_PLACE_ONLY};
use rtl::ldr;
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

// The loader's share of a thread's start and end: LdrInitializeThunk's body (src/ldr.s calls it),
// LdrShutdownThread (kernel32's ExitThread) and LdrShutdownProcess (kernel32's ExitProcess).

/// A fresh thread's initialization, before anything else it runs in user mode: the process's first
/// thread makes the heap list's lock and the process heap (PEB+0x18), the PEB lock and the loader
/// lock, and opens the starting current directory's handle; every thread its implicit-TLS block, when the image has a TLS directory. What finds no
/// room is left undone (the program meets a null process heap or TLS pointer).
#[unsafe(no_mangle)]
extern "C" fn f2k_ldr_initialize() {
    if sys::process_heap_handle() == 0 {
        let process = sys::process();
        // SAFETY: the PEB's lock slot, zero until now (no other thread exists yet).
        let _ = unsafe { &*process.lock }.initialize(&Native, 0);
        if let Some(heap) = process.create(&Native, 0, 0, 0) {
            sys::set_process_heap(heap.handle());
        }
        // The PEB lock, with the routines that take and release it, then the loader lock.
        unsafe extern "C" {
            #[link_name = "f2k_export_RtlEnterCriticalSection"]
            static ENTER: u8;
            #[link_name = "f2k_export_RtlLeaveCriticalSection"]
            static LEAVE: u8;
        }
        // The exports' code, by address only.
        let (enter, leave) = (
            core::ptr::addr_of!(ENTER) as usize,
            core::ptr::addr_of!(LEAVE) as usize,
        );
        sys::init_peb_lock(enter, leave);
        sys::init_loader_lock();
        curdir::open_starting_directory();
    }
    let base = sys::image_base();
    let Some(directory) =
        ldr::tls_directory(|offset| Some(sys::read(base + offset as usize) as u32))
    else {
        return;
    };
    if sys::process_heap_handle() == 0 || directory.block_size().is_none() {
        return;
    }
    let raw = (directory.end - directory.start) as usize;
    let block = ldr::thread_block(
        &Native,
        sys::process_heap(),
        directory.start as usize,
        raw,
        directory.zero_fill as usize,
    );
    if let Some(array) = block {
        sys::write(sys::teb() + sys::TEB_THREAD_LOCAL_STORAGE_POINTER, array);
    }
}

/// LdrShutdownThread: a thread ending through ExitThread gives its implicit-TLS block and its TLS
/// expansion slots back to the process heap (Windows 2000 also sends DLL_THREAD_DETACH here; F2K
/// calls no DllMain).
#[unsafe(export_name = "f2k_export_LdrShutdownThread")]
pub extern "system" fn ldr_shutdown_thread() -> u32 {
    if sys::process_heap_handle() == 0 {
        return 0;
    }
    let (teb, heap) = (sys::teb(), sys::process_heap());
    let array = sys::read(teb + sys::TEB_THREAD_LOCAL_STORAGE_POINTER);
    if array != 0 {
        sys::write(teb + sys::TEB_THREAD_LOCAL_STORAGE_POINTER, 0);
        ldr::free_thread_block(&Native, heap, array);
    }
    let slots = sys::read(teb + sys::TEB_TLS_EXPANSION_SLOTS);
    if slots != 0 {
        sys::write(teb + sys::TEB_TLS_EXPANSION_SLOTS, 0);
        heap.free(&Native, 0, slots);
    }
    0
}

/// LdrShutdownProcess: kernel32's ExitProcess calls it once the process's other threads are gone.
/// Windows 2000 sends DLL_PROCESS_DETACH and runs the image's TLS callbacks here; F2K calls no
/// DllMain and runs no TLS callback, so nothing is left to do.
#[unsafe(export_name = "f2k_export_LdrShutdownProcess")]
pub extern "system" fn ldr_shutdown_process() -> u32 {
    0
}
