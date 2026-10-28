//! F2K kernel library.
//!
//! Built two ways: as the `f2k-kernel` binary (entered by the Multiboot `_start` stub), and as a
//! host test harness where the x86-only assembly is cfg'd out and the pure-Rust parts get unit
//! tests (`make run-tests`). The host's plain library build exists for the documentation tests:
//! the compile-fail examples of the level tokens and the locks, which `make run-tests` runs too.

#![cfg_attr(not(test), no_std)]
// Host builds exist only to run unit tests.
#![cfg_attr(not(target_arch = "x86"), allow(dead_code))]
// The host's plain library build compiles the test-only paths' callees without the tests: what is
// unused there is not the target's concern.
#![cfg_attr(all(not(test), not(target_arch = "x86")), allow(unused))]

// The host's plain library build (the documentation tests' dependency) has std, as the unit tests
// do: the host's processor control region is a thread-local.
#[cfg(all(not(test), not(target_arch = "x86")))]
extern crate std;

// Boot module (Multiboot header and _start stub)
mod boot;

// The CPU tables: GDT (segments, TEB, TSS) and IDT (exceptions, the syscall gate, the
// hardware-vector stubs)
mod cpu;

// The hardware layer: the interrupt controller pair, the interval timer, the IDE disk, and the
// serial port, reached through abstract port I/O
mod hw;

// The interrupt core: interrupt objects, the vector table, the level discipline, the deferred
// procedure call queue, and the interval clock
mod interrupt;

// Level tokens: the interrupt level as a type, and the state each level owns. Public on the host,
// where the documentation tests name it from outside the crate.
#[cfg(target_arch = "x86")]
mod level;
#[cfg(not(target_arch = "x86"))]
pub mod level;

// The processor control region: the level ledger and the deferred procedure call queue
mod pcr;

// Memory management: physical frame allocator
mod mem;

// State outside the level cells: set-once values, static buffers handed out once, and the short
// lock for passive-level state. Public on the host, as the level tokens are.
#[cfg(target_arch = "x86")]
mod sync;
#[cfg(not(target_arch = "x86"))]
pub mod sync;

// Executable loading: PE32 parsing, and the kernel-side loader (staging, section mapping, entry
// into ring 3)
mod exec;

// Ring 3: user-mode entry, the syscall gate and its argument types, the user-mode heap, process end
mod user;

// The NT system services: Windows 2000's Nt* calls, by Windows 2000's numbers, over the object
// manager
mod nt;

// win32k: window stations and desktops, and the second service table (user32's own NtUser* calls,
// by Windows 2000's numbers from 0x1000)
mod win32k;

// The console server: the kernel's stand-in for csrss, which kernel32's console calls reach through
// ntdll's CsrClientCallServer
mod csr;

// The debugger's print channel: ntdll's DbgPrint, written to COM1
mod dbgprint;

// The process object and the suite runner: per-process directory, gate stack, user heap
mod process;

// NT status codes: the documented values the kernel's internal APIs report
mod status;

// Block devices: the description and read contract every storage device implements, partition
// views, and the device registry
mod block;

// File systems: the FAT32 volume over a block device
mod fs;

// The scheduler: thread objects, priority bands, ready queues, the quantum, the dispatcher's state
// machines
mod sched;

// The object manager: the typed object pools, object ids, pointer and handle counts, names
mod ob;

// The configuration manager: the registry's keys and values, in kernel memory
mod cm;

// Wall-clock time and the performance counter: the boot's real-time clock reading, the FILETIME
// the system services and the shared data page report
mod time;

// The opt-in performance trace (the perf-trace feature): the clock interrupt's sampler and the
// COM1 dump the harness turns into a profiler.firefox.com profile
#[cfg(feature = "perf-trace")]
mod perf;

// The C library's memory routines for the target (linker support).
#[cfg(target_arch = "x86")]
mod c_lib;

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Print the panic message on COM1 and halt.
///
/// The `#[panic_handler]` must be defined exactly once, in the final binary (a library must not
/// define one); the binary's handler forwards here so both crates share this one code path.
#[cfg(all(not(test), target_arch = "x86"))]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    halt()
}

/// Halt the CPU with interrupts disabled: the terminal state of a kernel that cannot continue
/// (panic, unhandled fault). Ticks do not resume here.
#[cfg(target_arch = "x86")]
pub(crate) fn halt() -> ! {
    loop {
        // SAFETY: ring 0, where `cli` and `hlt` are permitted; they touch no memory and no stack,
        // and the loop halts again if a non-maskable interrupt wakes the CPU.
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Kernel entry point
///
/// Called by `_start` (boot/mod.rs) with the values the Multiboot loader left in EAX and EBX.
#[cfg(target_arch = "x86")]
#[no_mangle]
pub extern "C" fn kmain(magic: u32, multiboot_info: u32) -> ! {
    // Signal that we've started by writing to port 0x80 (POST code port)
    // SAFETY: ring 0; port 0x80 is the POST diagnostic port, which no device claims, so the write
    // has no effect beyond the code a debug card would display.
    unsafe {
        asm!("out 0x80, al", in("al") 0xFEu8, options(nomem, nostack, preserves_flags));
    }

    // Initialize serial port first (for debugging)
    crate::hw::serial::init();

    // Take over the CPU tables so faults print diagnostics on COM1 instead of triple-faulting.
    // SAFETY: boot CPU, ring 0, interrupts disabled, before any code that might fault; sole GDT/IDT
    // access.
    unsafe { crate::cpu::gdt::init() };
    // SAFETY: the GDT is loaded (selector 0x08 valid); same context.
    unsafe { crate::cpu::idt::init() };
    serial_println!("F2K: GDT and IDT initialized");
    // Every thread's floating-point state is saved with `fxsave`: enabled before the first switch.
    // SAFETY: boot CPU, ring 0, before any thread exists.
    unsafe { crate::cpu::fpu::init() };

    // Test-only fault injection: raise an exception right after init to exercise the stubs and the
    // COM1 dump on target. The diagnostics prove the CPU did not write to the GDT and pin the
    // pre-fault ESP.
    #[cfg(any(feature = "fault-test-ud", feature = "fault-test-gp"))]
    {
        serial_println!(
            "F2K: GDT after load: {:#018x} {:#018x}",
            crate::cpu::gdt::debug_descriptor(1),
            crate::cpu::gdt::debug_descriptor(2)
        );
        let esp: u32;
        // SAFETY: copying ESP into a register reads no memory and changes no state.
        unsafe { asm!("mov {}, esp", out(reg) esp, options(nomem, nostack)) };
        serial_println!("F2K: ESP before fault: {:#010x}", esp);
    }
    #[cfg(feature = "fault-test-ud")]
    {
        serial_println!("F2K: fault test: forcing #UD (no error code)");
        // SAFETY: a deliberate fault in a test-only build: `ud2` raises #UD, whose handler dumps
        // the frame and halts, so execution never continues past it.
        unsafe { asm!("ud2", options(nomem, nostack)) };
    }
    #[cfg(feature = "fault-test-gp")]
    {
        // Selector 0x38 lies one past the seven-entry GDT limit (0x37): #GP with the CPU-pushed
        // error code 0x38 — the EXC_STUB_ERR path. Segment registers can only be loaded from a
        // general-purpose register.
        serial_println!("F2K: fault test: forcing #GP (error code path)");
        // SAFETY: a deliberate fault in a test-only build: loading the out-of-limit selector
        // raises #GP before DS changes, and its handler dumps the frame and halts, so execution
        // never continues past it.
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
        serial_println!(
            "F2K: not started by a Multiboot loader (EAX = {:#010x})",
            magic
        );
        halt();
    }

    serial_println!("F2K Booted Successfully");
    serial_println!("Fenêtre 2000 - Windows 2000 compatible OS in Rust");
    serial_println!("Phase 1: Foundation complete");
    serial_println!("Multiboot info at {:#010x}", multiboot_info);
    // The command line first: it lives in loader memory the frame allocator reclaims next.
    boot::cmdline::capture(multiboot_info);
    if let Some(line) = boot::cmdline::user_command_line(boot::cmdline::kernel_command_line()) {
        serial_println!(
            "F2K: command line: {}",
            core::str::from_utf8(line).unwrap_or("(not ASCII)")
        );
    }

    // Hand every usable frame (minus the kernel image) to the frame allocator.
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

    // The memory map is consumed: remove the low identity window. Nothing below KERNEL_BASE is
    // mapped from here on.
    mem::paging::teardown_low_identity();
    serial_println!(
        "F2K: paging on: kernel at {:#010x}, low identity removed",
        0x8010_1000u32
    );
    // Install the runtime table access (self-map, scratch table).
    mem::paging::init_table_access();
    // The kernel stack region's tables, shared by every address space from the first on.
    mem::paging::init_kernel_stack_tables();

    // The scheduler's resting state: the idle thread, armed while interrupts are still disabled
    // (nothing is schedulable yet; its loop is the kernel's resting state once no thread remains).
    crate::sched::idle::boot();

    // The console's text screen: the fresh console's blank screen buffer over whatever the firmware
    // and loader left on it (silently: the serial line carries the boot's report).
    csr::init();

    // The interactive window station, WinSta0, and its Default desktop: win32k's objects, which
    // every process connects to at its first win32k service.
    win32k::winsta::init();

    // The interrupt subsystem: the remapped controller behind the claim seam, the interval timer at
    // the captured platform rate, the interval clock connected to its vector — and interrupts fly
    // from here on (the idle path and ring 3 both run with them enabled; the gates mask on entry).
    // SAFETY: boot CPU, ring 0, interrupts disabled, sole access to the controllers; the IDT gates
    // (exception, syscall, hardware vectors) are installed.
    unsafe { interrupt::init() };

    // The interrupt/timer diagnostic boot: report the hardware state, wait for the live tick and
    // the clock's deferred work, and audit the whole subsystem — then fall through to the normal
    // boot, proving the tick and the process machinery coexist rather than just the diagnostic
    // running.
    #[cfg(feature = "irq-smoke")]
    interrupt::smoke();

    // The IDE disk: detect the primary master, connect its interrupt, and IDENTIFY it. It needs
    // the interrupt core (its reads complete through IRQ 14); the first user process comes after.
    crate::hw::ide::disk::init();

    // The PS/2 keyboard: reset it, connect IRQ 1, and feed its bytes to the console's input
    // buffer. Its bring-up waits read the tick, so it comes after the interrupt core too.
    crate::hw::kbd::init();

    // The block devices: the disk, if there is one, and a view per primary partition on it.
    if let Some(disk) = crate::hw::ide::disk::block_device() {
        crate::block::registry::scan_disk(disk);
    }

    // The boot volume: the first registered partition, mounted as FAT32. Silent — a boot without
    // a volume is normal, and a refused volume is left unmounted.
    crate::fs::fat32::volume::mount_boot_volume();

    // The disk diagnostic boot: read the drive's identity, the MBR, the volume boot sector, and
    // the first file's sectors through the interrupt-driven path, then fall through to the normal
    // boot.
    #[cfg(feature = "disk-smoke")]
    crate::hw::ide::smoke::run();

    // The interrupt-nesting diagnostic boot: a disk interrupt held behind the keyboard's, both let
    // in at once, then the normal boot.
    #[cfg(feature = "nest-smoke")]
    interrupt::nest_smoke();

    // The user processes (the programs the kernel command line lists, else exit0, through the PE
    // loader, one after another; the fault-test features substitute their own), each entered as
    // its main thread: this boot context becomes the idle thread. An image ends through its exit
    // import, which reports the exit code on COM1; the idle thread then tears the process down
    // and starts the next, or rests.
    user::run_user_process()
}
