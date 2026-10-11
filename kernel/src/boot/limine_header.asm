; Limine boot protocol header for F2K kernel
; This must be in the first 8KB of the binary and 8-byte aligned

section .limine_requests progbits alloc noexec nowrite
align 8

; Start marker
 dq 0xf6b8f4b39de7d1ae
 dq 0xfab91a6940fcb9cf
 dq 0x785c6ed015d3e316
 dq 0x181e920a7852b9d9

; Base revision request
 dq 0xf9562b2d5c95a6c8  ; ID part 1
 dq 0x6a7b384944536bdc  ; ID part 2
 dq 0                  ; revision
 dq 0                  ; response pointer

; Stack size request - ask for 16KB stack
 dq 0xc7b1dd30df4c8b88  ; Stack size request ID
 dq 0x0a82e883a194f07b
 dq 0x224ef0460a8e8926
 dq 0xe1cb0fc25f46ea3d
 dq 0                  ; revision
 dq 0                  ; response pointer
 dq 16384              ; stack size = 16KB

; End marker
 dq 0xadc0e0531bb10d03
 dq 0x9572709f31764c62
