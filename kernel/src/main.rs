//! F2K Kernel - Windows 2000-compatible operating system
//!
//! This is the entry point for the F2K kernel.
//! It runs in 32-bit protected mode on x86.

#![no_std]      // No standard library (we are the OS)
#![no_main]     // We don't have a main() - we have _start()

use core::arch::asm;

// Boot module (contains limine header for limine builds)
mod boot;

// C library functions for bare-metal
mod c_lib;

// Import our serial port module
mod serial;
use serial::init as serial_init;

/// Panic handler - prints message and halts
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    halt();
}

/// Halt the CPU
fn halt() -> ! {
    unsafe {
        loop {
            // x86 hlt instruction
            asm!("hlt");
        }
    }
}

/// Kernel entry point
/// 
/// This is called by the bootloader (or QEMU -kernel flag).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Signal that we've started by writing to port 0x80 (POST code port)
    unsafe {
        use core::arch::asm;
        asm!("mov al, 0xFE");
        asm!("out 0x80, al");
    }
    
    // Initialize serial port first (for debugging)
    serial_init();
    
    // Print boot message
    serial_println!("F2K Booted Successfully");
    serial_println!("Fenêtre 2000 - Windows 2000 compatible OS in Rust");
    serial_println!("Phase 1: Foundation complete");
    
    // For now, just halt
    // TODO: Continue with kernel initialization
    halt();
}
