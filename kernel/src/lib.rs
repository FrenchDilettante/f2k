//! F2K kernel library.
//!
//! All kernel code lives in this crate so it can be built two ways:
//! - as the `f2k-kernel` binary (src/main.rs): a 32-bit protected-mode
//!   kernel entered by the Multiboot `_start` stub in `boot`;
//! - as a host-side test harness (`make run-tests`), where the x86-only
//!   assembly is cfg'd out and the pure-Rust parts (descriptor layouts,
//!   exception tables) get unit tests.

#![cfg_attr(not(test), no_std)]

// Host builds exist only to run unit tests: the x86-only machinery is
// cfg'd out there, leaving items that only tests (or kernel code) touch.
#![cfg_attr(not(target_arch = "x86"), allow(dead_code))]

// Boot module (Multiboot header and _start stub)
mod boot;

// CPU tables: GDT (flat kernel + user segments, TSS) and IDT
// (exception handlers, the syscall gate at 0x2E)
mod gdt;
mod idt;

// Memory management: physical frame allocator
mod mem;

// System-call gate and service dispatch (int 0x2E, DPL 3)
mod syscall;

// PE32 image parsing and import resolution (the M4 loader)
mod pe;

// Ring 3: user-mode entry, the user-process smoke, process end
mod user;

// C library functions for bare-metal
mod c_lib;

// Serial port module
mod serial;

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Print the panic message on COM1 and halt.
///
/// The `#[panic_handler]` must be defined exactly once, in the final
/// binary (a library must not define one); the binary's handler forwards
/// here so both crates share this one code path.
#[cfg(not(test))]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    halt()
}

/// Halt the CPU
#[cfg(target_arch = "x86")]
pub(crate) fn halt() -> ! {
    loop {
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Kernel entry point
///
/// Called by `_start` (boot/mod.rs) with the values the Multiboot loader
/// left in EAX and EBX.
#[cfg(target_arch = "x86")]
#[no_mangle]
pub extern "C" fn kmain(magic: u32, multiboot_info: u32) -> ! {
    // Signal that we've started by writing to port 0x80 (POST code port)
    unsafe {
        asm!("out 0x80, al", in("al") 0xFEu8, options(nomem, nostack, preserves_flags));
    }

    // Initialize serial port first (for debugging)
    serial::init();

    // Take over the CPU tables: flat kernel segments, then exception
    // handlers so faults print diagnostics on COM1 instead of triple
    // faulting the machine.
    // SAFETY: boot CPU in ring 0 with interrupts disabled, before any code
    // that might fault; single-threaded boot, the only GDT access.
    unsafe { gdt::init() };
    // SAFETY: the GDT is already loaded (selector 0x08 valid); same boot
    // context, the only access to the IDT.
    unsafe { idt::init() };
    serial_println!("F2K: GDT and IDT initialized");

    // Test-only fault injection (make test-fault-ud / make test-fault-gp):
    // raise an exception right after init to exercise the exception stubs
    // and the COM1 dump on the real target. The diagnostics prove the CPU
    // did not write to the read-only GDT, and record the pre-fault ESP that
    // the dump's reconstructed ESP must match.
    #[cfg(any(feature = "fault-test-ud", feature = "fault-test-gp"))]
    {
        serial_println!(
            "F2K: GDT after load: {:#018x} {:#018x}",
            gdt::debug_descriptor(1),
            gdt::debug_descriptor(2)
        );
        let esp: u32;
        unsafe { asm!("mov {}, esp", out(reg) esp, options(nomem, nostack)) };
        serial_println!("F2K: ESP before fault: {:#010x}", esp);
    }
    #[cfg(feature = "fault-test-ud")]
    {
        serial_println!("F2K: fault test: forcing #UD (no error code)");
        unsafe { asm!("ud2", options(nomem, nostack)) };
    }
    #[cfg(feature = "fault-test-gp")]
    {
        // Selector 0x38 (slot 7) lies beyond the six-entry GDT limit
        // (0x2F): #GP with the CPU-pushed error code 0x38 — the
        // EXC_STUB_ERR path. Segment registers can only be loaded from
        // a general-purpose register.
        serial_println!("F2K: fault test: forcing #GP (error code path)");
        unsafe {
            asm!(
                "mov ax, 0x38",
                "mov ds, ax",
                out("ax") _,
                options(nomem, nostack)
            );
        };
    }

    if magic != boot::MULTIBOOT_BOOTLOADER_MAGIC {
        serial_println!("F2K: not started by a Multiboot loader (EAX = {:#010x})", magic);
        halt();
    }

    // Print boot message
    serial_println!("F2K Booted Successfully");
    serial_println!("Fenêtre 2000 - Windows 2000 compatible OS in Rust");
    serial_println!("Phase 1: Foundation complete");
    serial_println!("Multiboot info at {:#010x}", multiboot_info);

    // Parse the boot memory map and hand every usable frame (minus the
    // kernel image) to the physical frame allocator.
    mem::bootmem::boot_init(multiboot_info);
    mem::bootmem::with_frame_db(|db| {
        serial_println!(
            "F2K: physical memory: {} free frames ({} MiB)",
            db.available(),
            db.available() / 256
        );
        serial_println!(
            "F2K: frame database audit: {}",
            if db.audit().is_ok() { "ok" } else { "FAILED" }
        );
    });

    // The boot memory map is consumed: remove the low identity window
    // and keep only the kernel window. From here on, nothing below
    // KERNEL_BASE is mapped.
    mem::paging::teardown_low_identity();
    serial_println!("F2K: paging on: kernel at {:#010x}, low identity removed", 0x8010_1000u32);
    // Install the runtime table access (the self-map and the scratch
    // page table): the machinery for building user address spaces.
    mem::paging::init_table_access();

    // Kernel heap smoke: allocate, touch, free, audit.
    mem::bootmem::heap_init();
    mem::bootmem::with_heap(|heap| {
        const MARK: u32 = 0x4832_4B46; // "F2KH"
        let block = heap
            .alloc(core::alloc::Layout::from_size_align(256, 8).unwrap())
            .expect("heap smoke allocation");
        // SAFETY: the block is a live, exclusive allocation of 256
        // aligned bytes.
        unsafe { block.cast::<u32>().write(MARK) };
        let read_back = unsafe { block.cast::<u32>().read() };
        heap.dealloc(block);
        assert_eq!(read_back, MARK);
        assert_eq!(heap.audit(), Ok(()));
    });
    serial_println!("F2K: kernel heap: alloc/free ok");

    // M3 smoke: enter ring 3 and let the stub end the process through
    // the syscall gate (the exit service reports marker and exit code
    // on COM1). Run to completion: with the single user process gone,
    // the kernel halts inside the exit path.
    user::ring3_smoke()
}
