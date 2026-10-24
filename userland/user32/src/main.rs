//! user32.dll: the window manager's client side; for now the window station and desktop calls
//! cmd.exe and the corpus import.
//!
//! The library (src/lib.rs) is the home of user32's user-mode code; this binary links it into the
//! DLL beside its entry point, which ntdll's loader calls with each DLL_PROCESS_ and DLL_THREAD_
//! reason.

#![no_std]
#![no_main]

extern crate rtl;
// The user-mode exports' bodies (src/lib.rs): the .def exports them from the library.
extern crate user32 as _;

/// The DLL's entry point: every reason succeeds (DLL_PROCESS_ATTACH answers TRUE).
#[unsafe(no_mangle)]
extern "system" fn DllMain(_instance: usize, _reason: u32, _reserved: usize) -> u32 {
    1
}
