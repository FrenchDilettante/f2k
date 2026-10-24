//! msvcrt.dll: the C runtime library programs built with /MD import, cmd.exe among them.
//!
//! The library (src/lib.rs) is the home of msvcrt's user-mode code and its exported variables;
//! this binary links it into the DLL beside its entry point, which ntdll's loader calls with each
//! DLL_PROCESS_ and DLL_THREAD_ reason.

#![no_std]
#![no_main]

extern crate rtl;
// The user-mode exports' bodies and the variables (src/lib.rs): the .def exports them from the
// library.
extern crate msvcrt as _;

/// The DLL's entry point: every reason succeeds (DLL_PROCESS_ATTACH answers TRUE). The C runtime's
/// per-process and per-thread set-up joins it as the exports that need it are written.
#[unsafe(no_mangle)]
extern "system" fn DllMain(_instance: usize, _reason: u32, _reserved: usize) -> u32 {
    1
}
