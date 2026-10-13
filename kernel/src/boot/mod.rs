//! Boot entry: Multiboot 1 header and the `_start` stub.
//!
//! Any Multiboot 1 loader can start this kernel: QEMU's `-kernel`, Limine
//! (`protocol: multiboot1`) and GRUB. The loader jumps to `_start` in 32-bit
//! protected mode with paging off, EAX = Multiboot magic and EBX = physical
//! address of the Multiboot information structure. It does not provide a
//! stack, so `_start` sets one up before calling into Rust.

/// Value a Multiboot 1 loader leaves in EAX when it enters the kernel.
pub const MULTIBOOT_BOOTLOADER_MAGIC: u32 = 0x2BAD_B002;

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    // Multiboot header. Must be 4-byte aligned and within the first 8 KiB of
    // the file; the linker script places .multiboot first in .text.
    ".section .multiboot, \"a\"",
    ".align 4",
    ".long 0x1BADB002",                 // header magic
    ".long 0x00000003",                 // flags: page-align modules, provide memory info
    ".long -(0x1BADB002 + 0x00000003)", // checksum: magic + flags + checksum == 0
    // 64 KiB boot stack. Generously sized: early boot code keeps whole
    // subsystem structures (frame database, formatting state) as stack
    // locals, and overflowing the stack corrupts adjacent statics.
    // The top is exported: the multi-process runner's context switch
    // lands here between processes (the kernel image window is
    // mapped in every address space).
    ".section .bss.boot_stack, \"aw\", @nobits",
    ".align 16",
    "boot_stack_bottom:",
    ".skip 65536",
    ".global boot_stack_top",
    "boot_stack_top:",
    // Entry point. Runs at the physical load address with paging off
    // (this section is linked VMA == PMA; the rest of the kernel runs
    // in the kernel window at 0x80000000+). Responsibilities:
    //   1. keep the loader state (EAX magic, EBX Multiboot info),
    //   2. build the boot page directory (physical addressing),
    //   3. enable paging and continue in the kernel window,
    //   4. set up the boot stack and call kmain.
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "    mov esi, eax", // Multiboot magic, kept across the switch
    "    mov edi, ebx", // Multiboot info physical address
    // The boot page directory and tables are kernel statics: their
    // physical addresses are the linked addresses minus KERNEL_BASE
    // (0x80000000). Zero the directory, then fill the four entries:
    // 0, 1 = low identity window; 512, 513 = kernel window.
    "    mov eax, offset BOOT_PD",
    "    sub eax, 0x80000000",
    "    mov edx, eax",
    "    xor ecx, ecx",
    "1:",
    "    mov dword ptr [edx + ecx*4], 0",
    "    inc ecx",
    "    cmp ecx, 1024",
    "    jne 1b",
    "    mov edx, offset BOOT_PT_LO",
    "    sub edx, 0x80000000",
    "    or edx, 3", // present | writable
    "    mov [eax], edx",
    "    mov [eax + 2048], edx",
    "    mov edx, offset BOOT_PT_HI",
    "    sub edx, 0x80000000",
    "    or edx, 3",
    "    mov [eax + 4], edx",
    "    mov [eax + 2052], edx",
    // Paging on: CR3 = physical directory, CR0.PG = 1, CR0.WP = 1.
    // WP makes read-only mappings bind ring-0 writes too, which the
    // user/kernel split (and later copy-on-write) relies on. Execution
    // continues at the physical EIP through the low identity window.
    "    mov cr3, eax",
    "    mov eax, cr0",
    "    or eax, 0x80010000",
    "    mov cr0, eax",
    // Switch to the kernel window: the same code, at its virtual
    // alias (the low 8 MiB appear identically at 0x80000000+).
    "    mov edx, offset start_high",
    "    add edx, 0x80000000",
    "    jmp edx",
    "start_high:",
    "    cld",
    "    mov esp, offset boot_stack_top",
    "    push edi", // kmain arg 2: Multiboot info physical address
    "    push esi", // kmain arg 1: Multiboot magic
    // Absolute call: a relative call would be encoded against this
    // trampoline's low address and land on kmain's physical alias,
    // leaving the kernel executing in the (temporary) low window.
    "    mov edx, offset kmain",
    "    call edx",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
);
