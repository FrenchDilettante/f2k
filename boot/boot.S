// Simple boot sector for F2K
// Loads kernel at 0x1000 and jumps to it

.code16
.text

.global _start
_start:
    // Disable interrupts
    cli
    
    // Set up segments
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    
    // Load kernel from disk
    // For now, we'll assume the kernel is loaded by QEMU at 0x1000
    // So we just jump to it
    
    // Enable A20 line (to access memory above 1MB)
    in $0x92, %al
    or $0x02, %al
    out %al, $0x92
    
    // Load GDT
    lgdt gdt_descriptor
    
    // Set PE bit in CR0
    mov %cr0, %eax
    or $0x01, %eax
    mov %eax, %cr0
    
    // Far jump to 32-bit code
    ljmp $0x08, $protected_mode

protected_mode:
    // Set up data segments
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    
    // Jump to kernel
    jmp 0x1000

// GDT
.p2align 3

.gdt_start:
    // Null descriptor
    .quad 0x0000000000000000
    
    // Code descriptor
    .quad 0x00CF9A0000000FFFF
    
    // Data descriptor
    .quad 0x00CF920000000FFFF

.gdt_end:

// GDT descriptor
.p2align 3
gdt_descriptor:
    .word .gdt_end - .gdt_start - 1
    .long .gdt_start

// Fill to 510 bytes
.fill 510 - (. - _start), 1, 0

// Boot signature
.word 0xAA55
