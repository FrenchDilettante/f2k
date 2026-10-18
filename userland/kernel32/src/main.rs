//! kernel32.dll: the Win32 base DLL every program imports.
//!
//! The library (src/lib.rs) is the home of kernel32's user-mode code; this binary links it into the
//! DLL beside the generated service stubs. Every export is still one of the kernel's transitional
//! Win32 services (the kernel's served surface), a generated stub from the export spec (exports.toml:
//! EDX = the caller's arguments, EAX = the service number, the gate, then the stdcall return
//! popping the argument block), or a forwarder: RtlUnwind lives in ntdll, as on Windows 2000.

#![no_std]
#![no_main]

extern crate rtl;
// The user-mode exports' bodies (src/lib.rs): the .def exports them from the library.
extern crate kernel32 as _;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/consts.s")),
    include_str!(concat!(env!("OUT_DIR"), "/stubs.s")),
);
