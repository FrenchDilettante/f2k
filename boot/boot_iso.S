// Simple boot sector for ISO
// This is a minimal no-emulation boot sector that jumps to our kernel

.code16
.text

.global _start
_start:
    jmp 0x1000
    
    // Boot signature
    .fill 508 - (. - _start), 1, 0
    .word 0xAA55
