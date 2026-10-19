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
//! (RtlAcquirePebLock, RtlReleasePebLock); and the F2K-internal entry point the kernel sends a
//! thread to (`src/internal.s`): the thread-exit trampoline a child thread's function returns
//! onto. The kernel finds the trampoline and KiUserExceptionDispatcher by their export names;
//! kernel32's surface carries Windows 2000's names alone.

#![no_std]
#![no_main]

extern crate rtl;

mod except;
mod status;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
    include_str!("internal.s"),
    include_str!("except.s"),
    include_str!("csr.s"),
    include_str!("critsec.s"),
);

use rtl::critsec::{CriticalSection, STATUS_SUCCESS};
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
