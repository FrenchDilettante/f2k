//! msvcrt.dll: the C runtime library programs built with /MD import, cmd.exe among them.
//!
//! The library (src/lib.rs) is the home of msvcrt's user-mode code and its exported variables;
//! this binary links it into the DLL beside the exception handling and setjmp exports
//! (src/seh.s) and its entry point, which ntdll's loader calls with each DLL_PROCESS_ and
//! DLL_THREAD_ reason.

#![no_std]
#![no_main]

extern crate rtl;
// The user-mode exports' bodies and the variables (src/lib.rs): the .def exports them from the
// library.
extern crate msvcrt;

core::arch::global_asm!(include_str!("seh.s"));

/// The DLL's entry point: the C runtime's per-process and per-thread set-up and tear-down
/// (msvcrt::dll_main).
#[unsafe(no_mangle)]
extern "system" fn DllMain(_instance: usize, reason: u32, reserved: usize) -> u32 {
    msvcrt::dll_main(reason, reserved)
}
