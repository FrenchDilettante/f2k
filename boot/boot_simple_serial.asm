; Simple boot sector - just prints to serial and halts
; COM1 is at 0x3F8

bits 16
org 0x7C00

start:
    ; Disable interrupts
    cli
    
    ; Set up segments
    xor ax, ax
    mov ds, ax
    
    ; Initialize serial port (COM1 at 0x3F8)
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
    
    ; Print 'A' to serial
    mov dx, 0x3F8
    mov al, 'A'
    out dx, al
    
    ; Print 'B' to serial
    mov dx, 0x3F8
    mov al, 'B'
    out dx, al
    
    ; Print newline
    mov dx, 0x3F8
    mov al, 0x0A
    out dx, al
    
    ; Halt
    cli
    hlt

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
