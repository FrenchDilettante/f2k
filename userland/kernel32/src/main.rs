//! kernel32.dll: the Win32 base DLL every program imports.
//!
//! The library (src/lib.rs) is the home of kernel32's user-mode code; this binary links it into the
//! DLL beside the assembly natives (src/natives.s), the critical sections' initialization
//! (src/critsec.s, over ntdll's), the main thread's start (src/start.s), the pointer probes
//! (src/probe.s) and the bodies generated from the export spec
//! (exports.toml): the kernel's transitional Win32 services' stubs (EDX = the caller's arguments,
//! EAX = the service number, the gate, then the stdcall return popping the argument block), and the
//! unimplemented exports' (ERROR_CALL_NOT_IMPLEMENTED and the spec's failure value). RtlUnwind and
//! the critical sections' Enter, Leave, TryEnter and Delete are forwarders: they live in ntdll, as
//! on Windows 2000.

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
);

use kernel32::nt;

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

/// TlsSetValue's first use of an expansion index on this thread (src/natives.s): its 1024 expansion
/// slots, zeroed, on the process heap, recorded in its TEB; null when there is no room. The process
/// heap comes with ntdll's (B6): until then there is none, and such a set fails with
/// ERROR_NOT_ENOUGH_MEMORY.
#[unsafe(no_mangle)]
extern "C" fn f2k_k32_tls_expansion() -> usize {
    0
}
