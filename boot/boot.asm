; Simple boot sector for F2K
; Loads kernel from disk at sector 512 (0x200) and jumps to it

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
    
    ; Print loading message using BIOS
    mov si, loading_msg
    call print_string
    
    ; Load kernel from disk
    ; Kernel is at sector 512 (0x200), which is at LBA 512
    ; We'll load it to 0x100000 (1MB)
    
    ; Enable A20 line first (to access memory above 1MB)
    in al, 0x92
    or al, 0x02
    out 0x92, al
    
    ; Load kernel using LBA addressing
    ; We'll use INT 13h AH=42h (Extended Read Sectors)
    ; Read sectors from LBA 512 into memory at 0x100000
    
    ; First, check if INT 13h extensions are available
    mov ah, 0x41
    mov bx, 0x55AA
    int 0x13
    jc no_extensions
    cmp bx, 0xAA55
    jne no_extensions
    
    ; Extended read available
    ; Read sectors using LBA
    mov si, disk_address_packet
    mov ah, 0x42
    mov dl, 0x80  ; Drive 0 (first hard disk)
    int 0x13
    jc disk_error
    
    jmp switch_to_pm

no_extensions:
    ; Fallback: use CHS addressing
    ; This is more complex, so for now we'll just error
    mov si, no_ext_msg
    call print_string
    jmp $

disk_error:
    mov si, disk_err_msg
    call print_string
    jmp $

switch_to_pm:
    ; Now switch to protected mode
    
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
    
    ; Jump to kernel at 0x100000
    jmp 0x100000

; Include GDT
gdt_start:
    dq 0x0000000000000000  ; Null descriptor
    
    ; Code descriptor (0x08)
    dw 0xFFFF               ; Limit (bits 0-15)
    dw 0x0000               ; Base (bits 0-15)
    db 0x00                ; Base (bits 16-23)
    db 0x9A                ; Access byte (Code, Read/Execute)
    db 0xCF                ; Flags + Limit (bits 16-19): Granularity, 32-bit
    db 0x00                ; Base (bits 24-31)
    
    ; Data descriptor (0x10)
    dw 0xFFFF               ; Limit (bits 0-15)
    dw 0x0000               ; Base (bits 0-15)
    db 0x00                ; Base (bits 16-23)
    db 0x92                ; Access byte (Data, Read/Write)
    db 0xCF                ; Flags + Limit (bits 16-19): Granularity, 32-bit
    db 0x00                ; Base (bits 24-31)

gdt_end:

; GDT descriptor
align 4
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Disk Address Packet for LBA read
disk_address_packet:
    db 0x10               ; Size of packet
    db 0x00               ; Reserved
    dw 0x0040             ; Number of sectors to read (64 sectors = 32KB, adjust as needed)
    dd 0x00000200        ; LBA address (sector 512)
    dd 0x00100000        ; Transfer buffer (1MB)
    dq 0x0000000000000000 ; Reserved

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
loading_msg db "Loading F2K...", 0x0D, 0x0A, 0
no_ext_msg db "No INT 13h extensions!", 0x0D, 0x0A, 0
disk_err_msg db "Disk read error!", 0x0D, 0x0A, 0

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
