//! Boot entry: Multiboot 1 header and the `_start` stub, and the boot's phases `kmain` runs.
//!
//! Any Multiboot 1 loader can start this kernel: QEMU's `-kernel`, Limine (`protocol: multiboot1`)
//! and GRUB. The loader jumps to `_start` in 32-bit protected mode with paging off, EAX = Multiboot
//! magic and EBX = physical address of the Multiboot information structure. It does not provide a
//! stack, so `_start` sets one up before calling into Rust.

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
/// the frame database, and paging moved onto the kernel's own tables.
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

    // Hand every usable frame (minus the kernel image) to the frame allocator.
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

    // The memory map is consumed: remove the low identity window. Nothing below KERNEL_BASE is
    // mapped from here on.
    crate::mem::paging::teardown_low_identity();
    crate::serial_println!(
        "F2K: paging on: kernel at {:#010x}, low identity removed",
        0x8010_1000u32
    );
    // Install the runtime table access (self-map, scratch table).
    crate::mem::paging::init_table_access();
    // The kernel stack region's tables, shared by every address space from the first on.
    crate::mem::paging::init_kernel_stack_tables();
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

/// The devices: the IDE disk and the keyboard (both need the interrupt core), the block devices,
/// and the boot volume.
#[cfg(target_arch = "x86")]
pub fn devices() {
    // The IDE disk: detect the primary master, connect its interrupt, and IDENTIFY it. It needs
    // the interrupt core (its reads complete through IRQ 14); the first user process comes after.
    crate::hw::ide::disk::init();

    // The PS/2 keyboard: reset it, connect IRQ 1, and feed its bytes to the console's input
    // buffer. Its bring-up waits read the tick, so it comes after the interrupt core too.
    crate::hw::kbd::init();

    // The block devices: the disk, if there is one, and a view per primary partition on it.
    crate::block::registry::boot_scan(crate::hw::ide::disk::block_device());

    // The boot volume: the first registered partition, mounted as FAT32. Silent — a boot without
    // a volume is normal, and a refused volume is left unmounted.
    crate::fs::fat32::volume::mount_boot_volume();
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    // Multiboot header. Must be 4-byte aligned and within the first 8 KiB of the file; the linker
    // script places .multiboot first in .text.
    ".section .multiboot, \"a\"",
    ".align 4",
    ".long 0x1BADB002",                 // header magic
    ".long 0x00000003",                 // flags: page-align modules, provide memory info
    ".long -(0x1BADB002 + 0x00000003)", // checksum: magic + flags + checksum == 0
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
    // Entry point. Runs at the physical load address with paging off (this section is linked VMA
    // == PMA; the rest of the kernel runs in the kernel window at 0x80000000+).
    // Responsibilities:
    //   1. keep the loader state (EAX magic, EBX Multiboot info),
    //   2. build the boot page directory (physical addressing),
    //   3. enable paging and continue in the kernel window,
    //   4. set up the boot stack and call kmain.
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "    mov esi, eax", // Multiboot magic, kept across the switch
    "    mov edi, ebx", // Multiboot info physical address
    // The boot page directory and tables are kernel statics: their physical addresses are the
    // linked addresses minus KERNEL_BASE (0x80000000). Zero the directory, then point entry i of
    // the low identity window (entries 0-3) and of the kernel image window (entries 512-515) at
    // boot table i, for each of the tables (physical [0, 16 MiB), 4 MiB per table).
    "    mov eax, offset BOOT_PD",
    "    sub eax, 0x80000000",
    "    mov edx, eax",
    "    xor ecx, ecx",
    "1:",
    "    mov dword ptr [edx + ecx*4], 0",
    "    inc ecx",
    "    cmp ecx, 1024",
    "    jne 1b",
    "    mov edx, offset BOOT_TABLES",
    "    sub edx, 0x80000000",
    "    or edx, 3", // present | writable
    "    xor ecx, ecx",
    "3:",
    "    mov [eax + ecx*4], edx",
    "    mov [eax + ecx*4 + {image_window}], edx",
    "    add edx, 4096", // the next table
    "    inc ecx",
    "    cmp ecx, {tables}",
    "    jne 3b",
    // Paging on: CR3 = physical directory, CR0.PG = 1, CR0.WP = 1. WP makes read-only mappings
    // bind ring-0 writes too, which the user/kernel split (and later copy-on-write) relies on.
    // Execution continues at the physical EIP through the low identity window.
    "    mov cr3, eax",
    "    mov eax, cr0",
    "    or eax, 0x80010000",
    "    mov cr0, eax",
    // Switch to the kernel window: the same code, at its virtual alias (the low 16 MiB appear
    // identically at 0x80000000+).
    "    mov edx, offset start_high",
    "    add edx, 0x80000000",
    "    jmp edx",
    "start_high:",
    "    cld",
    "    mov esp, offset boot_stack_top",
    // kmain's entry alignment: the ABI wants ESP + 4 a multiple of 16 at entry (the stack slot
    // just above the return address), which makes the return address land 12 mod 16. Two argument
    // words and the return address below the 16-aligned stack top reach only 4 mod 16, so 8 bytes
    // of padding go between the stack top and the first argument.
    "    sub esp, 8",
    "    push edi", // kmain arg 2: Multiboot info physical address
    "    push esi", // kmain arg 1: Multiboot magic
    // Absolute call: a relative call would be encoded against this trampoline's low address and
    // land on kmain's physical alias, leaving the kernel executing in the (temporary) low window.
    "    mov edx, offset kmain",
    "    call edx",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
    // The kernel image window's first directory entry, as a byte offset into the directory.
    image_window = const crate::mem::layout::KERNEL_IMAGE.first_entry() * 4,
    tables = const crate::mem::paging::BOOT_TABLE_COUNT,
);
