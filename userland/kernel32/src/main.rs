//! kernel32.dll: the Win32 base DLL every program imports.
//!
//! The library (src/lib.rs) is the home of kernel32's user-mode code; this binary links it into the
//! DLL beside the assembly natives (src/natives.s), the main thread's start (src/start.s), the
//! pointer probes (src/probe.s) and the bodies generated from the export spec
//! (exports.toml): the kernel's transitional Win32 services' stubs (EDX = the caller's arguments,
//! EAX = the service number, the gate, then the stdcall return popping the argument block), and the
//! unimplemented exports' (ERROR_CALL_NOT_IMPLEMENTED and the spec's failure value). RtlUnwind is a
//! forwarder: it lives in ntdll, as on Windows 2000.

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
);
