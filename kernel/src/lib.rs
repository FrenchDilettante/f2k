//! F2K kernel library.
//!
//! Built two ways: as the `f2k-kernel` binary (entered by the Multiboot `_start` stub), and as a
//! host test harness where the x86-only assembly is cfg'd out and the pure-Rust parts get unit
//! tests (`make run-tests`).

#![cfg_attr(not(test), no_std)]
// Host builds exist only to run unit tests.
#![cfg_attr(not(target_arch = "x86"), allow(dead_code))]

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

// Memory management: physical frame allocator
mod mem;

// Executable loading: PE32 parsing, and the kernel-side loader (staging, section mapping, entry
// into ring 3)
mod exec;

// The Windows compatibility layer: the kernel-synthesized kernel32 and the codepage replay data
// behind its locale services
mod compat;

// Ring 3: user-mode entry, the syscall gate, the user-mode heap, process end
mod user;

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

// C library functions for bare-metal (linker support)
mod c_lib;

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Print the panic message on COM1 and halt.
///
/// The `#[panic_handler]` must be defined exactly once, in the final binary (a library must not
/// define one); the binary's handler forwards here so both crates share this one code path.
#[cfg(not(test))]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    halt()
}

/// Halt the CPU with interrupts disabled: the terminal state of a kernel that cannot continue
/// (panic, unhandled fault). Ticks do not resume here.
#[cfg(target_arch = "x86")]
pub(crate) fn halt() -> ! {
    loop {
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// Sleep until the next interrupt: IF on, halt. The interrupt returns wake it. Interrupts must
/// already be enabled hardware-wide. (The diagnostic boot feature's waiting primitive; the idle
/// thread's loop keeps its own, model-tracked form.)
#[cfg(target_arch = "x86")]
#[cfg(feature = "irq-smoke")]
pub(crate) fn wait_for_interrupt() {
    unsafe {
        asm!("sti", "hlt", options(nomem, nostack));
    }
}

/// Idle forever with interrupts enabled: the kernel's resting state once no thread remains — the
/// idle thread's loop (the deferred-work queue drains at every pass, and the interval clock wakes
/// the idle call).
#[cfg(target_arch = "x86")]
pub(crate) fn idle() -> ! {
    crate::sched::idle::idle_loop()
}

/// Kernel entry point
///
/// Called by `_start` (boot/mod.rs) with the values the Multiboot loader left in EAX and EBX.
#[cfg(target_arch = "x86")]
#[no_mangle]
pub extern "C" fn kmain(magic: u32, multiboot_info: u32) -> ! {
    // Signal that we've started by writing to port 0x80 (POST code port)
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
        // Selector 0x38 lies one past the seven-entry GDT limit (0x37): #GP with the CPU-pushed
        // error code 0x38 — the EXC_STUB_ERR path. Segment registers can only be loaded from a
        // general-purpose register.
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

    // Kernel heap smoke.
    mem::bootmem::heap_init();
    mem::bootmem::with_heap(|heap| {
        const MARK: u32 = 0x4832_4B46; // "F2KH"
        let block = heap
            .alloc(core::alloc::Layout::from_size_align(256, 8).unwrap())
            .expect("heap smoke allocation");
        // SAFETY: the block is a live, exclusive allocation of 256 aligned bytes.
        unsafe { block.cast::<u32>().write(MARK) };
        let read_back = unsafe { block.cast::<u32>().read() };
        heap.dealloc(block);
        assert_eq!(read_back, MARK);
        assert_eq!(heap.audit(), Ok(()));
    });
    serial_println!("F2K: kernel heap: alloc/free ok");

    // The scheduler's resting state: the idle thread, armed while interrupts are still disabled
    // (nothing is schedulable yet; its loop is the kernel's resting state once no thread remains).
    crate::sched::idle::boot();

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
    {
        use interrupt::clock::{ticks, timer_fired};

        serial_println!("F2K: irq-smoke: PIC remapped (master 0x30, slave 0x38, IRQ0 unmasked)");
        serial_println!("F2K: irq-smoke: PIT programmed (mode 3, divisor 11949, 10.0144 ms tick)");

        // Bounded by the tick itself: each `sti;hlt` sleeps until the next interrupt, so progress
        // here means the timer is live.
        while ticks() < 5 {
            wait_for_interrupt();
        }
        serial_println!("F2K: irq-smoke: timer live (>= 5 ticks observed)");

        // The deferred timer work fires only when a timer is due (the table's hand check), so park
        // one: the current thread's (the idle thread's) own timer, due one tick out. The expiry
        // signals it — nobody waits on it — and the DPC's run is the observable.
        {
            use interrupt::clock::INTERVAL_100NS;
            let dispatcher = crate::sched::idle::dispatcher();
            let previous =
                crate::interrupt::irql::state_mut().raise(crate::interrupt::irql::DISPATCH);
            // SAFETY: the current thread (the idle thread, armed at boot) is live and exclusive
            // here; its timer is initialized and on no list.
            let current = unsafe { &mut *dispatcher.current_thread() };
            let now = interrupt::clock::system_time();
            assert!(dispatcher.timer_table().insert(
                &mut current.timer,
                now + INTERVAL_100NS as u64,
                now
            ));
            crate::interrupt::irql::state_mut().lower(previous);
        }

        // The DPC the clock ISR enqueues must have run (the drain is part of every interrupt exit,
        // and the idle path drains too).
        while timer_fired() == 0 {
            wait_for_interrupt();
        }
        serial_println!("F2K: irq-smoke: clock DPC fired");

        let verdict = interrupt::audit();
        if verdict == Ok(()) {
            serial_println!("F2K: irq-smoke: interrupt audit: ok");
        } else {
            serial_println!(
                "F2K: irq-smoke: interrupt audit: FAILED ({})",
                verdict.unwrap_err()
            );
        }
    }

    // The IDE disk: detect the primary master, connect its interrupt, and IDENTIFY it. It needs
    // the interrupt core (its reads complete through IRQ 14); the first user process comes after.
    crate::hw::ide::disk::init();

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

    // The user process: exit0 through the PE loader by default, ret0 (the CRT startup fixture) with
    // the `run-ret0` feature. The image ends through its exit import, which reports the exit code
    // on COM1; the kernel then halts (run to completion).
    user::run_user_process()
}
