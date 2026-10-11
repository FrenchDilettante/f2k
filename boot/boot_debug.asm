; Debug boot sector - prints messages to verify loading

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
    
    ; Print booting message
    mov si, msg_booting
    call print_string
    
    ; Load a few sectors from disk
    mov cx, 5  ; Load 5 sectors
    mov ax, 0x07E0
    mov es, ax
    xor bx, bx
    
.load_sector:
    push cx
    
    ; Print loading message
    push bx
    push cx
    mov si, msg_loading
    call print_string
    pop cx
    pop bx
    
    ; Read one sector
    mov ah, 0x02
    mov al, 0x01
    mov ch, 0x00
    mov cl, 0x02  ; Start from sector 2
    mov dh, 0x00
    int 0x13
    jc .load_error
    
    ; Next sector
    inc cl
    add bx, 0x200
    
    pop cx
    loop .load_sector
    
    ; Print done loading
    mov si, msg_done_loading
    call print_string
    
    ; Switch to protected mode and jump to kernel
    lgdt [gdt_descriptor]
    mov eax, cr0
    or al, 0x01
    mov cr0, eax
    jmp 0x08:protected_mode

bits 32
protected_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Print entering PM
    mov esi, msg_pm
    call print_string_pm
    
    ; Jump to kernel
    jmp 0x7E00

; Include GDT
gdt_start:
    dq 0x0000000000000000
    dw 0xFFFF, 0x0000, 0x00, 0x9A, 0xCF, 0x00
    dw 0xFFFF, 0x0000, 0x00, 0x92, 0xCF, 0x00
gdt_end:

align 4
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Print string (16-bit)
print_string:
    push ax
    mov ah, 0x0E
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .loop
.done:
    pop ax
    ret

; Print string (32-bit)
print_string_pm:
    push ax
    mov ah, 0x0E
.loop_pm:
    lodsb
    test al, al
    jz .done_pm
    int 0x10
    jmp .loop_pm
.done_pm:
    pop ax
    ret

.load_error:
    mov si, msg_error
    call print_string
    cli
    hlt

; Messages
msg_booting db "Boot sector running", 0x0D, 0x0A, 0
msg_loading db ".", 0
msg_done_loading db " Done loading", 0x0D, 0x0A, 0
msg_pm db "In protected mode", 0x0D, 0x0A, 0
msg_error db "Error!", 0x0D, 0x0A, 0

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
