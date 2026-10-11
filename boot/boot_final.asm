; Boot sector for F2K
; Loads kernel from sector 1 to 0x7E00, switches to protected mode, jumps to _start at 0x8E70

bits 16
org 0x7C00

start:
    ; Disable interrupts
    cli
    
    ; Set up segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    
    ; Load kernel from sector 1 (immediately after boot sector) to 0x7E00
    ; Destination: ES:BX = 0x7E0:0x0000 = physical 0x7E00
    mov ax, 0x07E0
    mov es, ax
    xor bx, bx
    
    ; Source: Cylinder 0, Head 0, Sector 2 (BIOS sector numbering starts at 1)
    mov ch, 0x00  ; Cylinder 0
    mov cl, 0x02  ; Sector 2 (our sector 1, since BIOS sector 1 is boot sector)
    mov dh, 0x00  ; Head 0
    
    ; Number of sectors to read (134 sectors = 0x86)
    mov al, 0x86  ; 134 decimal = 0x86 hex
    
    ; Read sectors using BIOS
    mov ah, 0x02  ; Read sectors function
    int 0x13
    jc .load_error
    
    ; Success, switch to protected mode
    
    ; Load GDT
    lgdt [gdt_descriptor]
    
    ; Set PE bit in CR0
    mov eax, cr0
    or al, 0x01
    mov cr0, eax
    
    ; Far jump to 32-bit code
    jmp 0x08:protected_mode

.load_error:
    ; Halt on error
    cli
    hlt

bits 32
protected_mode:
    ; Set up data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Jump to kernel entry point at 0x8E70
    jmp 0x8E70

; Include GDT
gdt_start:
    dq 0x0000000000000000  ; Null descriptor
    
    ; Code descriptor (0x08) - entire address space
    dw 0xFFFF, 0x0000, 0x00, 0x9A, 0xCF, 0x00
    
    ; Data descriptor (0x10) - entire address space
    dw 0xFFFF, 0x0000, 0x00, 0x92, 0xCF, 0x00

gdt_end:

align 4
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
