//! user32.dll: the window manager's client side: the window stations and desktops, the window
//! classes, the windows, their messages and their painting, and the display's face, as cmd.exe and
//! the corpus import them.
//!
//! The library (src/lib.rs) is the home of user32's user-mode code; this binary links it into the
//! DLL beside its entry point, which ntdll's loader calls with each DLL_PROCESS_ and DLL_THREAD_
//! reason.

#![no_std]
#![no_main]

extern crate rtl;
// The user-mode exports' bodies (src/lib.rs): the .def exports them from the library.
extern crate user32;

/// DLL_PROCESS_ATTACH, the reason the loader's first call gives.
const DLL_PROCESS_ATTACH: u32 = 1;

/// The DLL's entry point: every reason succeeds (DLL_PROCESS_ATTACH answers TRUE); the process's
/// attach points the PEB's KernelCallbackTable at user32's callback table.
#[unsafe(no_mangle)]
extern "system" fn DllMain(_instance: usize, reason: u32, _reserved: usize) -> u32 {
    if reason == DLL_PROCESS_ATTACH {
        user32::callback::attach();
    }
    1
}
