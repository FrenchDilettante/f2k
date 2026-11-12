//! Boot entry: the image's entry point, `_start`, and the boot's phases `kmain` runs.
//!
//! Any Multiboot 1 loader starts the boot loader (`kernel/loader`) that carries this image: QEMU's
//! `-kernel`, Limine (`protocol: multiboot1`) and GRUB. The boot loader maps the image at its base,
//! relocates it if it must, maps the kernel image window over physical `[0, 16 MiB)` with the low
//! 16 MiB identity-mapped beside it, turns paging on, and jumps to `_start` with EAX = the
//! Multiboot magic and EBX = the physical address of the Multiboot information structure, as the
//! Multiboot loader left them. It provides no stack, so `_start` sets one up before calling into
//! Rust.

/// Value a Multiboot 1 loader leaves in EAX when it enters the kernel.
pub const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;

/// The kernel command line and the user command line it carries.
pub mod cmdline;

/// The diagnostic boots the smoke and fault-test features select, each run at its place in the
/// boot sequence.
pub mod diagnostics;

// --- The boot's phases ------------------------------------------------------
//
// `kmain` runs these in order, as Windows 2000's initialization runs its Phase 0 (the processor,
// memory, the executive's tables) and its Phase 1 (interrupts, the scheduler, the drivers) before
// its first process.

/// The processor: the POST code, the serial line, the CPU tables (so faults print diagnostics on
/// COM1 instead of triple-faulting) and the floating-point unit.
#[cfg(target_arch = "x86")]
pub fn early() {
    // Signal that we've started by writing to port 0x80 (POST code port)
    // SAFETY: ring 0; port 0x80 is the POST diagnostic port, which no device claims, so the write
    // has no effect beyond the code a debug card would display.
    unsafe {
        core::arch::asm!("out 0x80, al", in("al") 0xFEu8, options(nomem, nostack, preserves_flags));
    }

    // Initialize serial port first (for debugging)
    crate::hw::serial::init();

    // SAFETY: boot CPU, ring 0, interrupts disabled, before any code that might fault.
    unsafe { crate::cpu::init() };
    crate::serial_println!("F2K: GDT and IDT initialized");
    // Every thread's floating-point state is saved with `fxsave`: enabled before the first switch.
    // SAFETY: boot CPU, ring 0, before any thread exists.
    unsafe { crate::cpu::fpu::init() };
}

/// The loader's hand-off and physical memory: the Multiboot magic checked (a kernel some other way
/// started halts), the boot banner, the kernel command line captured, every usable frame handed to
/// the frame database, and paging moved onto the kernel's own tables, in frames of their own.
#[cfg(target_arch = "x86")]
pub fn memory(magic: u32, multiboot_info: u32) {
    if magic != MULTIBOOT_BOOTLOADER_MAGIC {
        crate::serial_println!(
            "F2K: not started by a Multiboot loader (EAX = {:#010x})",
            magic
        );
        crate::halt();
    }

    crate::serial_println!("F2K Booted Successfully");
    crate::serial_println!("Fenêtre 2000 - Windows 2000 compatible OS in Rust");
    crate::serial_println!("Phase 1: Foundation complete");
    crate::serial_println!("Multiboot info at {:#010x}", multiboot_info);
    // The command line first: it lives in loader memory the frame allocator reclaims next.
    cmdline::capture(multiboot_info);
    if let Some(line) = cmdline::user_command_line(cmdline::kernel_command_line()) {
        crate::serial_println!(
            "F2K: command line: {}",
            core::str::from_utf8(line).unwrap_or("(not ASCII)")
        );
    }

    // Hand every usable frame (minus the kernel image's and, for now, the boot loader's) to the
    // frame allocator.
    crate::mem::bootmem::boot_init(multiboot_info);
    crate::mem::bootmem::with_frame_db(|db| {
        crate::serial_println!(
            "F2K: physical memory: {} free frames ({} MiB)",
            db.available(),
            db.available() / 256
        );
        crate::serial_println!(
            "F2K: frame database audit: {}",
            if db.audit().is_ok() { "ok" } else { "FAILED" }
        );
    });

    // Paging moves off the boot loader's tables onto the boot directory and tables, built in frames
    // of the kernel's own with the same picture: the processor never walks the loader's again, and
    // the loader's memory goes back to the frame database.
    crate::mem::paging::install_boot_directory();
    crate::mem::bootmem::release_loader_memory();
    // The memory map is consumed: remove the low identity window. Nothing below KERNEL_BASE is
    // mapped from here on.
    crate::mem::paging::teardown_low_identity();
    crate::serial_println!(
        "F2K: paging on: kernel at {:#010x}, low identity removed",
        crate::mem::layout::NTOSKRNL_BASE
    );
    // Install the runtime table access (self-map, scratch table).
    crate::mem::paging::init_table_access();
    // The kernel stack region's tables, shared by every address space from the first on.
    crate::mem::paging::init_kernel_stack_tables();
    // The nonpaged pool's tables, shared alike.
    crate::mem::paging::init_pool_tables();
    // The framebuffer region's tables, shared alike: the display's linear framebuffer is mapped
    // into them when the graphics mode is set.
    crate::mem::paging::init_framebuffer_tables();
    // The MMIO region's tables, shared alike: device register ranges map into them (MmMapIoSpace).
    crate::mem::paging::init_mmio_tables();
    // The modules region's tables, shared alike: loaded driver images map into them (the .sys
    // loader).
    crate::mem::paging::init_module_tables();
}

/// The executive's tables: the console and the registry.
#[cfg(target_arch = "x86")]
pub fn executive() {
    // The console's text screen: the fresh console's blank screen buffer over whatever the firmware
    // and loader left on it (silently: the serial line carries the boot's report).
    crate::csr::init();

    // The registry: its arena, and the keys Windows 2000 has from its boot on.
    crate::cm::init();
}

/// Interrupts and the scheduler: the interrupt subsystem, the idle thread, then the interactive
/// window station.
#[cfg(target_arch = "x86")]
pub fn interrupts() {
    // The interrupt subsystem: the remapped controller behind the claim seam, the interval timer at
    // the captured platform rate, the interval clock connected to its vector — and interrupts fly
    // from here on (the idle path and ring 3 both run with them enabled; the gates mask on entry).
    // SAFETY: boot CPU, ring 0, interrupts disabled, sole access to the controllers; the IDT gates
    // (exception, syscall, hardware vectors) are installed.
    unsafe { crate::interrupt::init() };

    // The scheduler's resting state: the idle thread (nothing is schedulable yet; its loop is the
    // kernel's resting state once no thread remains). Its install raises to the dispatcher's
    // level, which enables interrupts, so it waits for the interrupt subsystem: an interrupt taken
    // before the controllers are remapped would land on an exception's vector.
    crate::sched::idle::boot();

    // The interactive window station, WinSta0, and its Default desktop: win32k's objects, which
    // every process connects to at its first win32k service. Made under the object directory's
    // lock, whose raise enables interrupts, so it waits for the interrupt subsystem too.
    crate::win32k::winsta::init();
}

/// The devices: the RAM disk, the IDE disk and the keyboard (the last two need the interrupt core),
/// the block devices, and the boot volume.
#[cfg(target_arch = "x86")]
pub fn devices() {
    // The PCI bus: enumerate every reachable function through the config address/data ports,
    // keep the device table and the PIRQ routes for the driver slices that claim these nodes,
    // and report the enumeration on COM1. The scan needs no interrupts, so it comes first.
    crate::hw::pci::init();

    // The device tree: the scan's functions as nodes, each interrupt pin routed through the PIRQ
    // table to its ISA line and its vector in the HAL's band. Reported on COM1, one line per
    // routed pin; the firmware routing table's override seam stays with the ACPI slice.
    let nodes = crate::dev::init_nodes_from_pci();
    crate::serial_println!("F2K: dev: {} nodes", nodes.len());
    for node in nodes.iter() {
        if let Some(interrupt) = node.interrupt {
            crate::serial_println!(
                "F2K: dev: {:02x}:{:02x}.{} pin {} irq {} vector {:#04x}",
                node.address.bus,
                node.address.dev,
                node.address.func,
                interrupt.pin,
                interrupt.isa_line,
                interrupt.vector
            );
        }
    }

    // The RAM disk: the disk image a boot loader loaded as the `f2k-disk` module, if it loaded one
    // (the test boots' disk), over the frames the boot memory plan withheld for it.
    crate::block::ramdisk::init();

    // The IDE disk: detect the primary master, connect its interrupt, and IDENTIFY it. It needs
    // the interrupt core (its reads complete through IRQ 14); the first user process comes after.
    crate::hw::ide::disk::init();

    // The PS/2 keyboard: reset it, connect IRQ 1, and feed its bytes to the console's input
    // buffer. Its bring-up waits read the tick, so it comes after the interrupt core too.
    crate::hw::kbd::init();

    // The block devices: the RAM disk and the IDE disk, those there are, in that order, and a view
    // per primary partition on each.
    crate::block::registry::boot_scan(
        crate::block::ramdisk::block_device()
            .into_iter()
            .chain(crate::hw::ide::disk::block_device()),
    );

    // The boot volume: the first registered partition (the RAM disk's, when there is one), mounted
    // as FAT32. Silent — a boot without a volume is normal, and a refused volume is left unmounted.
    crate::fs::fat32::volume::mount_boot_volume();
}

/// The fonts the system loads at its start (win32k's built-in list standing in for the
/// registry's), from the boot volume: silent when it carries none. After the devices' diagnostics,
/// whose disk smoke counts the disk's interrupts from the mount on.
#[cfg(target_arch = "x86")]
pub fn fonts() {
    crate::win32k::fonts::load_boot_fonts();
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    // 64 KiB boot stack. Generously sized: early boot code keeps whole subsystem structures (frame
    // database, formatting state) as stack locals, and overflowing the stack corrupts adjacent
    // statics. The top is exported: the multi-process runner's context switch lands here between
    // processes (the kernel image window is mapped in every address space).
    ".section .bss.boot_stack, \"aw\", @nobits",
    ".align 16",
    "boot_stack_bottom:",
    ".skip 65536",
    ".global boot_stack_top",
    "boot_stack_top:",
    // The image's entry point. The boot loader jumps here with paging on, the image mapped at its
    // linked addresses, interrupts off, EAX the Multiboot magic and EBX the Multiboot
    // information's physical address; it leaves no stack to run on.
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "    cld",
    "    mov esp, offset boot_stack_top",
    // kmain's entry alignment: the ABI wants ESP + 4 a multiple of 16 at entry (the stack slot
    // just above the return address), which makes the return address land 12 mod 16. Two argument
    // words and the return address below the 16-aligned stack top reach only 4 mod 16, so 8 bytes
    // of padding go between the stack top and the first argument.
    "    sub esp, 8",
    "    push ebx", // kmain arg 2: Multiboot info physical address
    "    push eax", // kmain arg 1: Multiboot magic
    "    call kmain",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
);
