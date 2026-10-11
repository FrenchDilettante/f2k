; Simple boot sector for F2K
; Switches to protected mode and jumps to kernel at 0x7E00

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
    
    ; Print message
    mov si, msg
    call print_string
    
    ; Load GDT
    lgdt [gdt_descriptor]
    
    ; Set PE bit in CR0
    mov eax, cr0
    or al, 0x01
    mov cr0, eax
    
    ; Far jump to 32-bit code
    jmp 0x08:protected_mode

bits 32
protected_mode:
    ; Set up data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Jump to kernel at 0x7E00 (loaded right after boot sector)
    jmp 0x7E00

; Include GDT
gdt_start:
    dq 0x0000000000000000  ; Null descriptor
    
    ; Code descriptor (0x08)
    dw 0xFFFF               ; Limit (bits 0-15)
    dw 0x0000               ; Base (bits 0-15)
    db 0x00                ; Base (bits 16-23)
    db 0x9A                ; Access byte
    db 0xCF                ; Flags + Limit (bits 16-19)
    db 0x00                ; Base (bits 24-31)
    
    ; Data descriptor (0x10)
    dw 0xFFFF               ; Limit (bits 0-15)
    dw 0x0000               ; Base (bits 0-15)
    db 0x00                ; Base (bits 16-23)
    db 0x92                ; Access byte
    db 0xCF                ; Flags + Limit (bits 16-19)
    db 0x00                ; Base (bits 24-31)

gdt_end:

align 4
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Print string function (16-bit mode)
print_string:
    push ax
    mov ah, 0x0E
.print_loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .print_loop
.done:
    pop ax
    ret

; Messages
msg db "Booting F2K...", 0x0D, 0x0A, 0

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
