; Test boot sector - just prints 'A' and halts

bits 16
org 0x7C00

start:
    ; Set up segments
    xor ax, ax
    mov ds, ax
    
    ; Print 'A'
    mov ah, 0x0E
    mov al, 'A'
    int 0x10
    
    ; Halt
    cli
    hlt

; Boot signature
times 510 - ($ - $$) db 0
dw 0xAA55
