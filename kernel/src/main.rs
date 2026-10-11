//! F2K kernel binary.
//!
//! All kernel code lives in the `f2k-kernel` library crate: the Multiboot
//! `_start` stub in its `boot` module calls `kmain` there. This binary
//! exists only to link the kernel ELF. The `#[panic_handler]` must be
//! defined exactly once, in the final binary (a library must not define
//! one), so it lives here and forwards to the library's shared path.

#![no_std]      // No standard library (we are the OS)
#![no_main]     // No main(): the Multiboot stub in the library calls kmain()

use core::panic::PanicInfo;

/// Kernel panics print on COM1 and halt; the implementation is in the
/// library so the kernel code shares the same path.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    f2k_kernel::panic(info)
}
