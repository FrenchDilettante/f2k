; Boot sector for F2K
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
    
    ; Initialize serial port (COM1 at 0x3F8)
    call init_serial
    
    ; Print message
    mov si, msg
    call print_string_serial
    
    ; Switch to protected mode
    
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
    
    ; Print protected mode message
    mov esi, msg_pm
    call print_string_serial_32
    
    ; Jump to kernel at 0x7E00 (loaded right after boot sector)
    ; The kernel was compiled with -Ttext 0x7E00, so it expects to be at that address
    ; In protected mode with identity mapping, physical 0x7E00 = virtual 0x7E00
    jmp 0x7E00

; Include GDT
gdt_start:
    dq 0x0000000000000000  ; Null descriptor
    
    ; Code descriptor (0x08) - covers entire 4GB address space
    dw 0xFFFF               ; Limit (bits 0-15)
    dw 0x0000               ; Base (bits 0-15)
    db 0x00                ; Base (bits 16-23)
    db 0x9A                ; Access byte (Present, Ring 0, Code, Executable, Direction 0, Conforming)
    db 0xCF                ; Flags + Limit (bits 16-19): Granularity (4KB), 32-bit
    db 0x00                ; Base (bits 24-31)
    
    ; Data descriptor (0x10) - covers entire 4GB address space
    dw 0xFFFF               ; Limit (bits 0-15)
    dw 0x0000               ; Base (bits 0-15)
    db 0x00                ; Base (bits 16-23)
    db 0x92                ; Access byte (Present, Ring 0, Data, Expand-up, Writable)
    db 0xCF                ; Flags + Limit (bits 16-19): Granularity (4KB), 32-bit
    db 0x00                ; Base (bits 24-31)

gdt_end:

align 4
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Initialize serial port (COM1 at 0x3F8)
init_serial:
    ; Disable interrupts
    mov dx, 0x3F8 + 1
    mov al, 0x00
    out dx, al
    
    ; Set DLAB (bit 7)
    mov dx, 0x3F8 + 3
    mov al, 0x80
    out dx, al
    
    ; Set baud rate divisor to 3 (38400 baud)
    mov dx, 0x3F8 + 0
    mov al, 0x03
    out dx, al
    
    mov dx, 0x3F8 + 1
    mov al, 0x00
    out dx, al
    
    ; 8 bits, no parity, one stop bit
    mov dx, 0x3F8 + 3
    mov al, 0x03
    out dx, al
    
    ; Enable FIFO, clear them
    mov dx, 0x3F8 + 2
    mov al, 0xC7
    out dx, al
    
    ; Mark DTR and RTS
    mov dx, 0x3F8 + 4
    mov al, 0x0B
    out dx, al
    
    ret

; Print string to serial (16-bit mode)
print_string_serial:
    push ax
    push dx
.print_loop_16:
    lodsb
    test al, al
    jz .done_16
    mov dx, 0x3F8
.wait_tx:
    in al, 0x3FD    ; Line Status Register (0x3F8 + 5 = 0x3FD)
    test al, 0x20    ; Check if Transmit Holding Register is empty
    jz .wait_tx
    mov dx, 0x3F8
    out dx, al
    jmp .print_loop_16
.done_16:
    pop dx
    pop ax
    ret

; Print string to serial (32-bit mode)
print_string_serial_32:
    push eax
    push edx
    cld
.print_loop_32:
    lodsb
    test al, al
    jz .done_32
    mov dx, 0x3F8
.wait_tx_32:
    in al, 0x3FD    ; Line Status Register
    test al, 0x20    ; Check if Transmit Holding Register is empty
    jz .wait_tx_32
    mov dx, 0x3F8
    out dx, al
    jmp .print_loop_32
.done_32:
    pop edx
    pop eax
    ret

; Messages
msg db "F2K Bootloader", 0x0D, 0x0A, 0
msg_pm db "Switching to protected mode...", 0x0D, 0x0A, 0

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
