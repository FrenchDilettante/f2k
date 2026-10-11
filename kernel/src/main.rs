//! F2K Kernel - Windows 2000-compatible operating system
//!
//! This is the entry point for the F2K kernel.
//! It runs in 32-bit protected mode on x86.

#![no_std]      // No standard library (we are the OS)
#![no_main]     // No main(): the Multiboot stub in boot/mod.rs calls kmain()

use core::arch::asm;

// Boot module (Multiboot header and _start stub)
mod boot;

// C library functions for bare-metal
mod c_lib;

// Import our serial port module
mod serial;

/// Panic handler - prints message and halts
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    halt();
}

/// Halt the CPU
fn halt() -> ! {
    loop {
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Kernel entry point
///
/// Called by `_start` (boot/mod.rs) with the values the Multiboot loader left
/// in EAX and EBX.
#[no_mangle]
pub extern "C" fn kmain(magic: u32, multiboot_info: u32) -> ! {
    // Signal that we've started by writing to port 0x80 (POST code port)
    unsafe {
        asm!("out 0x80, al", in("al") 0xFEu8, options(nomem, nostack, preserves_flags));
    }

    // Initialize serial port first (for debugging)
    serial::init();

    if magic != boot::MULTIBOOT_BOOTLOADER_MAGIC {
        serial_println!("F2K: not started by a Multiboot loader (EAX = {:#010x})", magic);
        halt();
    }

    // Print boot message
    serial_println!("F2K Booted Successfully");
    serial_println!("Fenêtre 2000 - Windows 2000 compatible OS in Rust");
    serial_println!("Phase 1: Foundation complete");
    serial_println!("Multiboot info at {:#010x}", multiboot_info);

    // For now, just halt
    // TODO: Continue with kernel initialization
    halt();
}
