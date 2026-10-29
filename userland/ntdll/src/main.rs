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
//! `src/heap.s` over `rtl::heap`; RtlLockHeap and RtlUnlockHeap); the handle tables kernel32 keeps
//! its movable Local and Global blocks' handles in (RtlInitializeHandleTable, RtlAllocateHandle,
//! RtlFreeHandle, RtlIsValidHandle: `src/handles.rs` over `rtl::handles`); the environment
//! (RtlSetEnvironmentVariable, RtlQueryEnvironmentVariable_U, RtlExpandEnvironmentStrings_U,
//! RtlCreateEnvironment, RtlDestroyEnvironment: `src/env.rs` over `rtl::env`); the process
//! parameters a new process starts with (RtlCreateProcessParameters, RtlDestroyProcessParameters,
//! RtlNormalizeProcessParams, RtlDeNormalizeProcessParams: `src/params.rs` over `rtl::params`); the
//! current directory and the DOS paths (RtlSetCurrentDirectory_U, RtlGetCurrentDirectory_U,
//! RtlGetFullPathName_U, RtlDosPathNameToNtPathName_U, RtlDoesFileExists_U,
//! RtlDetermineDosPathNameType_U: `src/curdir.rs` over `rtl::path`); the counted strings and the
//! ANSI code page, which kernel32's narrow calls convert through
//! (RtlInitAnsiString, RtlAnsiStringToUnicodeString, RtlUnicodeStringToAnsiString,
//! RtlFreeUnicodeString, RtlUnicodeToMultiByteN, RtlMultiByteToUnicodeN, RtlUnicodeToMultiByteSize:
//! `src/strings.rs` over `rtl::string`); the current user's registry hive, as advapi32 opens it,
//! and an image's execution options (RtlOpenCurrentUser, LdrQueryImageFileExecutionOptions:
//! `src/registry.rs`, the options over `rtl::execution_options`); an image's NT headers
//! (RtlImageNtHeader: `src/image.rs` over `rtl::image`); the time conversions (RtlTimeToTimeFields,
//! RtlTimeFieldsToTime: `src/time.rs` over `rtl::time`); the bitmaps kernel32 keeps the TLS slots
//! in (RtlFindClearBitsAndSet, RtlClearBits, RtlAreBitsSet: `src/bitmap.rs` over `rtl::bitmap`);
//! the resources and the messages kernel32's FormatMessage finds and lays out (LdrFindResource_U,
//! LdrFindResourceDirectory_U, LdrAccessResource, RtlFindMessage, RtlFormatMessage:
//! `src/resource.rs` over `rtl::resource` and `rtl::message`); the loader, which loads every DLL of
//! the process but ntdll from the volume, kernel32 included, and calls their entry points
//! (`src/loader.rs` over `rtl::modules`: the process's module lists, LdrGetDllHandle, LdrLoadDll,
//! LdrUnloadDll, LdrGetProcedureAddress,
//! LdrDisableThreadCalloutsForDll); and the loader's share of a thread's start and end:
//! LdrInitializeThunk, which the kernel delivers before a fresh thread's first instruction
//! (`src/ldr.s`: the process heap, the PEB lock and the loader lock and the image's DLLs on the
//! first thread, the thread's implicit TLS, the DLLs' DLL_PROCESS_ATTACH or DLL_THREAD_ATTACH), and
//! LdrShutdownThread and LdrShutdownProcess, kernel32's ExitThread's and ExitProcess's;
//! DbgPrint (`src/dbgprint.s`, `src/dbgprint.rs` over `rtl::printf`: the text to the
//! kernel's debugger channel, COM1) and DbgBreakPoint (`src/dbgprint.s`: a breakpoint, raised
//! inside ntdll); and the stub routine its stubbed exports' generated bodies go
//! to (`src/stub.rs`). The kernel finds LdrInitializeThunk and the two
//! dispatchers by their export names.

#![no_std]
#![no_main]

extern crate rtl;

mod bitmap;
mod curdir;
mod dbgprint;
mod env;
mod except;
mod handles;
mod image;
mod loader;
mod params;
mod process;
mod registry;
mod resource;
mod service;
mod status;
mod strings;
mod stub;
mod time;

// The exports' descriptions (`spec`) and the stubbed exports' bodies, generated from exports.toml
// (tools/exportgen; see `stub`).
include!(concat!(env!("OUT_DIR"), "/exports.rs"));

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("ldr.s"),
    include_str!("except.s"),
    include_str!("csr.s"),
    include_str!("critsec.s"),
    include_str!("heap.s"),
    include_str!("dbgprint.s"),
);

use rtl::critsec::{CriticalSection, STATUS_SUCCESS};
use rtl::heap::{HEAP_GENERATE_EXCEPTIONS, HEAP_GROWABLE, HEAP_REALLOC_IN_PLACE_ONLY};
use rtl::ldr;
use rtl::sys::{self, Native};

// The critical sections' bodies, cdecl, called by src/critsec.s's exports with their caller's
// section pointer, which each converts once into a reference (a bad one faults the caller, as on
// Windows). A section's fields are atomics: the calls of other threads share it.

/// RtlInitializeCriticalSection: free, no event until the first contention. STATUS_SUCCESS.
///
/// # Safety
///
/// `section` points at a CRITICAL_SECTION's storage, aligned for its dwords and live for the call,
/// which the process changes meanwhile only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_initialize_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: the caller's section storage (the function's contract, the same).
    unsafe { f2k_rtl_initialize_critical_section_and_spin_count(section, 0) }
}

/// RtlInitializeCriticalSectionAndSpinCount: as RtlInitializeCriticalSection, with a spin count
/// (its high bit preallocating the event). STATUS_NO_MEMORY when that event cannot be made.
///
/// # Safety
///
/// `section` points at a CRITICAL_SECTION's storage, aligned for its dwords and live for the call,
/// which the process changes meanwhile only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_initialize_critical_section_and_spin_count(
    section: *const CriticalSection,
    spin_count: u32,
) -> u32 {
    // SAFETY: the caller's section storage, aligned and live for the call (the function's
    // contract).
    match unsafe { &*section }.initialize(&Native, spin_count) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// RtlEnterCriticalSection. STATUS_SUCCESS (in low memory a contended enter raises instead).
///
/// # Safety
///
/// `section` points at a critical section RtlInitializeCriticalSection made, aligned for its
/// dwords and live for the call, which the process changes only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_enter_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: the caller's initialized section, aligned and live for the call (the function's
    // contract).
    unsafe { &*section }.enter(&Native);
    STATUS_SUCCESS
}

/// RtlTryEnterCriticalSection: TRUE when the caller now holds the section.
///
/// # Safety
///
/// `section` points at a critical section RtlInitializeCriticalSection made, aligned for its
/// dwords and live for the call, which the process changes only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_try_enter_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: as `f2k_rtl_enter_critical_section`'s.
    unsafe { &*section }.try_enter(&Native) as u32
}

/// RtlLeaveCriticalSection. STATUS_SUCCESS.
///
/// # Safety
///
/// `section` points at a critical section RtlInitializeCriticalSection made, aligned for its
/// dwords and live for the call, which the process changes only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_leave_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: as `f2k_rtl_enter_critical_section`'s.
    unsafe { &*section }.leave(&Native);
    STATUS_SUCCESS
}

/// RtlDeleteCriticalSection: its event closed. STATUS_SUCCESS.
///
/// # Safety
///
/// `section` points at a critical section RtlInitializeCriticalSection made, aligned for its
/// dwords and live for the call, which the process changes only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_delete_critical_section(section: *const CriticalSection) -> u32 {
    // SAFETY: as `f2k_rtl_enter_critical_section`'s.
    unsafe { &*section }.delete(&Native);
    STATUS_SUCCESS
}

/// RtlSetCriticalSectionSpinCount: the previous spin count.
///
/// # Safety
///
/// `section` points at a critical section RtlInitializeCriticalSection made, aligned for its
/// dwords and live for the call, which the process changes only through these routines.
#[unsafe(no_mangle)]
unsafe extern "C" fn f2k_rtl_set_critical_section_spin_count(
    section: *const CriticalSection,
    spin_count: u32,
) -> u32 {
    // SAFETY: as `f2k_rtl_enter_critical_section`'s.
    unsafe { &*section }.set_spin_count(&Native, spin_count)
}

/// RtlAcquirePebLock: take the PEB lock.
#[unsafe(export_name = "f2k_export_RtlAcquirePebLock")]
pub extern "system" fn rtl_acquire_peb_lock() {
    process::peb_lock().enter(&Native);
}

/// RtlReleasePebLock: release it.
#[unsafe(export_name = "f2k_export_RtlReleasePebLock")]
pub extern "system" fn rtl_release_peb_lock() {
    process::peb_lock().leave(&Native);
}

// The heaps' bodies, cdecl, called by src/heap.s's exports. A handle the process's heap list does
// not hold names no heap: the calls refuse it without touching it.

/// A failed allocation's answer to its export: zero, with the high dword set when it must raise
/// STATUS_NO_MEMORY instead (HEAP_GENERATE_EXCEPTIONS on the call or the heap): src/heap.s raises
/// it from the export, through RtlRaiseException.
fn refused(handle: usize, flags: u32) -> u64 {
    let heap_flags = process::heaps().heap(handle).map_or(0, |heap| heap.flags());
    if (flags | heap_flags) & HEAP_GENERATE_EXCEPTIONS != 0 {
        1 << 32
    } else {
        0
    }
}

/// RtlCreateHeap(Flags, HeapBase, ReserveSize, CommitSize): a heap whose first segment reserves
/// ReserveSize bytes with CommitSize committed, which adds segments as it fills when growable
/// (HEAP_GROWABLE, or no reservation size); null when there is no room, or for a caller-supplied
/// base (not supported).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_create_heap(flags: u32, base: usize, reserve: usize, commit: usize) -> usize {
    if base != 0 {
        return 0;
    }
    process::heaps()
        .create_sized(&Native, flags, reserve, commit)
        .map_or(0, |heap| heap.handle())
}

/// RtlDestroyHeap: null once destroyed; the handle back for the process heap or no heap.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_destroy_heap(handle: usize) -> usize {
    if handle == sys::process_heap_handle() || !process::heaps().destroy(&Native, handle) {
        return handle;
    }
    0
}

/// RtlAllocateHeap: the block, or the refusal ([`refused`]).
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_allocate_heap(handle: usize, flags: u32, size: usize) -> u64 {
    match process::heaps()
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
            || process::heaps()
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
    match process::heaps()
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
    process::heaps()
        .heap(handle)
        .and_then(|heap| heap.size(&Native, flags, pointer))
        .unwrap_or(usize::MAX)
}

/// RtlLockHeap: the heap's lock taken, held across the caller's calls on it (kernel32's Local and
/// Global memory holds the process heap's so); FALSE for a handle naming no heap.
#[unsafe(export_name = "f2k_export_RtlLockHeap")]
pub extern "system" fn rtl_lock_heap(handle: usize) -> u32 {
    match process::heaps().heap(handle) {
        Some(heap) => {
            heap.lock(&Native);
            1
        }
        None => 0,
    }
}

/// RtlUnlockHeap: the lock RtlLockHeap took, released; FALSE for a handle naming no heap.
#[unsafe(export_name = "f2k_export_RtlUnlockHeap")]
pub extern "system" fn rtl_unlock_heap(handle: usize) -> u32 {
    match process::heaps().heap(handle) {
        Some(heap) => {
            heap.unlock(&Native);
            1
        }
        None => 0,
    }
}

/// RtlValidateHeap: the whole heap's headers (a null pointer), or one block.
#[unsafe(no_mangle)]
extern "C" fn f2k_rtl_validate_heap(handle: usize, flags: u32, pointer: usize) -> u32 {
    u32::from(
        process::heaps()
            .heap(handle)
            .is_some_and(|heap| heap.validate(&Native, flags, pointer)),
    )
}

// The loader's share of a thread's start and end: LdrInitializeThunk's body (src/ldr.s calls it),
// LdrShutdownThread (kernel32's ExitThread) and LdrShutdownProcess (kernel32's ExitProcess).

/// A fresh thread's initialization, before anything else it runs in user mode, `context` its
/// initial context. The process's first thread makes the heap list's lock and the process heap
/// (PEB+0x18), the PEB lock, the loader lock and the TLS bitmaps' headers (ntdll's own data,
/// `process`, the PEB's fields pointed at them), opens the starting current directory's handle,
/// and builds the module lists, loading the image's DLLs (`loader`); every thread then makes its
/// implicit-TLS block, when the image has a TLS directory; then the DLLs' entry points: the first
/// thread's DLL_PROCESS_ATTACH (lpReserved the context), a later thread's DLL_THREAD_ATTACH. A
/// process whose DLLs do not load or initialize ends here with the status. A TLS block that finds
/// no room is left undone (the program meets a null TLS pointer).
#[unsafe(no_mangle)]
extern "C" fn f2k_ldr_initialize(context: u32) {
    let first = sys::process_heap_handle() == 0;
    if first {
        params::normalize_own_parameters();
        process::initialize_heap_list_lock();
        // The process heap, its first segment as the image's header sizes it.
        // SAFETY: the process's image, mapped for its whole life: its headers are read in place,
        // within their first page.
        let image = unsafe { loader::Mapped::new() };
        let (reserve, commit) = rtl::image::process_heap_sizes(&image, sys::image_base() as u32);
        let heap = process::heaps().create_sized(&Native, HEAP_GROWABLE, reserve, commit);
        if let Some(heap) = heap {
            sys::set_process_heap(heap.handle());
        }
        // The PEB lock, with the routines that take and release it, the loader lock and the TLS
        // bitmaps' headers.
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
        process::initialize(enter, leave);
        if sys::process_heap_handle() == 0 {
            loader::fail_process(rtl::status::STATUS_NO_MEMORY);
        }
        curdir::open_starting_directory();
        if let Err(status) = loader::initialize_process() {
            loader::fail_process(status);
        }
    }
    thread_tls();
    if first {
        if let Err(status) = loader::attach_process(context) {
            loader::fail_process(status);
        }
    } else {
        loader::attach_thread();
    }
}

/// The calling thread's implicit-TLS block, when the image has a TLS directory: its array on the
/// TEB (ThreadLocalStoragePointer), on the process heap.
fn thread_tls() {
    // SAFETY: the image's headers and the directory they name, mapped for the process's whole
    // life, read in place (a malformed image's offsets fault here, in the process's own image).
    let image = unsafe { loader::Mapped::new() };
    let Some(directory) = ldr::tls_directory(&image, sys::image_base() as u32) else {
        return;
    };
    if sys::process_heap_handle() == 0 || directory.block_size().is_none() {
        return;
    }
    let start = directory.start_address_of_raw_data;
    let raw = (directory.end_address_of_raw_data - start) as usize;
    let block = ldr::thread_block(
        &Native,
        sys::process_heap(),
        start as usize,
        raw,
        directory.size_of_zero_fill as usize,
    );
    if let Some(array) = block {
        sys::set_thread_local_storage_pointer(array);
    }
}

/// LdrShutdownThread: a thread ending through ExitThread calls its DLLs' entry points with
/// DLL_THREAD_DETACH (`loader`), then gives its implicit-TLS block and its TLS expansion slots back
/// to the process heap.
#[unsafe(export_name = "f2k_export_LdrShutdownThread")]
pub extern "system" fn ldr_shutdown_thread() -> u32 {
    if sys::process_heap_handle() == 0 {
        return 0;
    }
    loader::detach_thread();
    let heap = sys::process_heap();
    let array = sys::thread_local_storage_pointer();
    if array != 0 {
        sys::set_thread_local_storage_pointer(0);
        ldr::free_thread_block(&Native, heap, array);
    }
    let slots = sys::tls_expansion_slots();
    if slots != 0 {
        sys::set_tls_expansion_slots(0);
        heap.free(&Native, 0, slots);
    }
    0
}

/// LdrShutdownProcess: kernel32's ExitProcess calls it once the process's other threads are gone:
/// the DLLs' entry points get DLL_PROCESS_DETACH, lpReserved non-NULL, in reverse initialization
/// order (`loader`). Windows 2000 also runs the image's TLS callbacks here; F2K runs none.
#[unsafe(export_name = "f2k_export_LdrShutdownProcess")]
pub extern "system" fn ldr_shutdown_process() -> u32 {
    if sys::process_heap_handle() != 0 {
        loader::detach_process();
    }
    0
}
