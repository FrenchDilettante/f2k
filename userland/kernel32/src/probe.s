# The pointer probes, as Windows 2000's kernel32 writes them: the memory touched in user mode under
# an exception frame of the probe's own (its `__try`), so a touch that faults answers TRUE. Each
# registers (next, handler, resume) on fs:[0] right below its saved EBP; the handler takes any
# exception the touch raises: the chain unwound to the registration (RtlUnwind, src/except.rs), the
# probe's stack and EBP back from it, then on to its resume point with TRUE. A guard page the touch
# meets is spent (the guard violation is the probe's exception); the stack's own guard grows the
# stack as any access does, and the touch goes on.
.text

# The probes' exception handler (cdecl: record, frame, context, dispatcher). An unwind passing
# through searches on.
.p2align 4
_f2k_k32_probe_handler:
    mov eax, dword ptr [esp+4]
    test dword ptr [eax+4], 6
    jnz 1f
    mov ebx, dword ptr [esp+8]
    push eax
    push ebx
    call _f2k_k32_probe_unwind
    mov esp, ebx
    lea ebp, [ebx+12]
    mov eax, 1
    jmp dword ptr [ebx+8]
1:
    mov eax, 1
    ret

# IsBadReadPtr(lp, ucb): TRUE when a byte of the range cannot be read. The probe reads the first
# byte, then the first byte of every later page up to the last byte's; an empty range is good
# untouched, a range that wraps the address space bad untouched.
.p2align 4
.globl _f2k_export_IsBadReadPtr
_f2k_export_IsBadReadPtr:
    push ebp
    mov ebp, esp
    mov eax, offset .Lread_out
    push eax
    mov eax, offset _f2k_k32_probe_handler
    push eax
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    mov ecx, dword ptr [ebp+8]
    mov edx, dword ptr [ebp+12]
    xor eax, eax
    test edx, edx
    jz .Lread_out
    lea edx, [ecx+edx-1]
    inc eax
    cmp edx, ecx
    jb .Lread_out
    mov al, byte ptr [ecx]
    and ecx, 0xFFFFF000
    and edx, 0xFFFFF000
.Lread_page:
    cmp ecx, edx
    je .Lread_good
    add ecx, 0x1000
    mov al, byte ptr [ecx]
    jmp .Lread_page
.Lread_good:
    xor eax, eax
.Lread_out:
    mov ecx, dword ptr [esp]
    mov dword ptr fs:[0], ecx
    mov esp, ebp
    pop ebp
    ret 8

# IsBadWritePtr(lp, ucb): as IsBadReadPtr, each touched byte read and written back (no more atomic
# than Windows 2000's probe).
.p2align 4
.globl _f2k_export_IsBadWritePtr
_f2k_export_IsBadWritePtr:
    push ebp
    mov ebp, esp
    mov eax, offset .Lwrite_out
    push eax
    mov eax, offset _f2k_k32_probe_handler
    push eax
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    mov ecx, dword ptr [ebp+8]
    mov edx, dword ptr [ebp+12]
    xor eax, eax
    test edx, edx
    jz .Lwrite_out
    lea edx, [ecx+edx-1]
    inc eax
    cmp edx, ecx
    jb .Lwrite_out
    mov al, byte ptr [ecx]
    mov byte ptr [ecx], al
    and ecx, 0xFFFFF000
    and edx, 0xFFFFF000
.Lwrite_page:
    cmp ecx, edx
    je .Lwrite_good
    add ecx, 0x1000
    mov al, byte ptr [ecx]
    mov byte ptr [ecx], al
    jmp .Lwrite_page
.Lwrite_good:
    xor eax, eax
.Lwrite_out:
    mov ecx, dword ptr [esp]
    mov dword ptr fs:[0], ecx
    mov esp, ebp
    pop ebp
    ret 8

# IsBadCodePtr(lpfn): IsBadReadPtr of its first byte, as Windows 2000's.
.p2align 4
.globl _f2k_export_IsBadCodePtr
_f2k_export_IsBadCodePtr:
    push 1
    push dword ptr [esp+8]
    call _f2k_export_IsBadReadPtr
    ret 4

# IsBadStringPtrA(lpsz, ucchMax): TRUE when a byte up to the terminator, or the limit's last,
# cannot be read; a zero limit is good untouched.
.p2align 4
.globl _f2k_export_IsBadStringPtrA
_f2k_export_IsBadStringPtrA:
    push ebp
    mov ebp, esp
    mov eax, offset .Lstring_out
    push eax
    mov eax, offset _f2k_k32_probe_handler
    push eax
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    mov ecx, dword ptr [ebp+8]
    mov edx, dword ptr [ebp+12]
    xor eax, eax
    test edx, edx
    jz .Lstring_out
    lea edx, [ecx+edx-1]
.Lstring_byte:
    mov al, byte ptr [ecx]
    test al, al
    jz .Lstring_good
    cmp ecx, edx
    je .Lstring_good
    inc ecx
    jmp .Lstring_byte
.Lstring_good:
    xor eax, eax
.Lstring_out:
    mov ecx, dword ptr [esp]
    mov dword ptr fs:[0], ecx
    mov esp, ebp
    pop ebp
    ret 8
