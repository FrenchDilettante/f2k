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
    // 16 KiB boot stack.
    ".section .bss.boot_stack, \"aw\", @nobits",
    ".align 16",
    "boot_stack_bottom:",
    ".skip 16384",
    "boot_stack_top:",
    // Entry point.
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "    mov esp, offset boot_stack_top",
    "    cld",
    "    push ebx", // kmain arg 2: Multiboot info pointer
    "    push eax", // kmain arg 1: Multiboot magic
    "    call kmain",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
);
