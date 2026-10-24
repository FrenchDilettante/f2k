# Structured exception handling and setjmp/longjmp, over the frame layout Visual C++ compiles
# `__try` into (Matt Pietrek's "A Crash Course on the Depths of Win32 Structured Exception
# Handling", MSJ, January 1997, describes it publicly):
#
#   [ebp-0x18]  the function's ESP, for its handlers to restore
#   [ebp-0x14]  the EXCEPTION_POINTERS of the exception being filtered (GetExceptionInformation)
#   [ebp-0x10]  the registration on fs:[0]: the next registration, the handler (_except_handler3),
#   [ebp-0x08]    the scope table, and
#   [ebp-0x04]    the try level (-1 outside every __try)
#   [ebp]       the function's saved EBP
#
# Each scope-table entry is three dwords: the enclosing try level, the filter (NULL for a
# __finally) and the handler (the __except block, or the __finally block's funclet). A filter
# and a __finally funclet are called with EBP the function's own and return with `ret`; an
# __except block is jumped to, and restores ESP itself.
#
# setjmp compiles into _setjmp3(buffer, count, ...): MSVC 6's setjmp.h lays out the jump buffer
# (_JUMP_BUFFER: EBP, EBX, EDI, ESI, ESP, EIP, the registration, the try level, the cookie
# 'VC20', the unwind function, its data). In a function with a __try, the compiler passes
# _seh_longjmp_unwind and the try level (count 2); longjmp unwinds the registrations above the
# buffer's (RtlUnwind: their __finally blocks run), then calls the unwind function, which runs
# the __finally blocks of the setjmp's function above its try level.
.text

# _except_handler3(record, registration, context, dispatcher), cdecl: the scope table searched
# from the try level outwards. A filter's EXCEPTION_CONTINUE_EXECUTION (negative) continues the
# exception, EXCEPTION_CONTINUE_SEARCH (0) tries the enclosing level, EXCEPTION_EXECUTE_HANDLER
# (positive) unwinds the registrations above (RtlUnwind), then this function's levels above the
# handler's (_local_unwind2), sets the try level to the handler's enclosing one and jumps to the
# handler. An unwind passing through runs every __finally of the function.
.p2align 4
.globl _f2k_export__except_handler3
_f2k_export__except_handler3:
    push ebp
    mov ebp, esp
    sub esp, 8
    push ebx
    push esi
    push edi
    cld
    mov ebx, dword ptr [ebp+12]
    mov eax, dword ptr [ebp+8]
    test dword ptr [eax+4], 6
    jnz .Leh3_unwinding
    mov dword ptr [ebp-8], eax
    mov eax, dword ptr [ebp+16]
    mov dword ptr [ebp-4], eax
    lea eax, [ebp-8]
    mov dword ptr [ebx-4], eax
    mov esi, dword ptr [ebx+12]
    mov edi, dword ptr [ebx+8]
.Leh3_search:
    cmp esi, -1
    je .Leh3_continue_search
    lea ecx, [esi+esi*2]
    mov eax, dword ptr [edi+ecx*4+4]
    test eax, eax
    jz .Leh3_next
    push ebx
    push esi
    push edi
    push ebp
    lea ebp, [ebx+16]
    call eax
    pop ebp
    pop edi
    pop esi
    pop ebx
    test eax, eax
    js .Leh3_continue_execution
    jnz .Leh3_execute
.Leh3_next:
    lea ecx, [esi+esi*2]
    mov esi, dword ptr [edi+ecx*4]
    jmp .Leh3_search
.Leh3_execute:
    push dword ptr [ebp+8]
    push ebx
    call _f2k_msvcrt_global_unwind
    add esp, 8
    push esi
    push ebx
    call _f2k_export__local_unwind2
    add esp, 8
    lea ecx, [esi+esi*2]
    mov eax, dword ptr [edi+ecx*4]
    mov dword ptr [ebx+12], eax
    mov eax, dword ptr [edi+ecx*4+8]
    lea ebp, [ebx+16]
    jmp eax
.Leh3_unwinding:
    push -1
    push ebx
    call _f2k_export__local_unwind2
    add esp, 8
.Leh3_continue_search:
    mov eax, 1
    jmp .Leh3_out
.Leh3_continue_execution:
    xor eax, eax
.Leh3_out:
    pop edi
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    ret

# The handler of _local_unwind2's own registration: an exception, or an unwind, passing through
# a __finally block that the local unwind runs searches on. (_abnormal_termination recognizes the
# registration by this handler.)
.p2align 4
_f2k_msvcrt_unwind_handler:
    mov eax, 1
    ret

# _local_unwind2(registration, stop), cdecl: the function's __finally blocks run, from its try
# level outwards until the level `stop` (-1: all of them), each level left before its block
# runs. Its own registration (next, handler, the function's registration) marks the unwind
# for _abnormal_termination.
.p2align 4
.globl _f2k_export__local_unwind2
_f2k_export__local_unwind2:
    push ebx
    push esi
    push edi
    push ebp
    mov ebx, dword ptr [esp+20]
    push ebx
    mov eax, offset _f2k_msvcrt_unwind_handler
    push eax
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
.Llu2_loop:
    mov eax, dword ptr [ebx+12]
    cmp eax, -1
    je .Llu2_done
    cmp eax, dword ptr [esp+36]
    je .Llu2_done
    mov esi, dword ptr [ebx+8]
    lea ecx, [eax+eax*2]
    mov edx, dword ptr [esi+ecx*4]
    mov dword ptr [ebx+12], edx
    cmp dword ptr [esi+ecx*4+4], 0
    jne .Llu2_loop
    mov eax, dword ptr [esi+ecx*4+8]
    push ebx
    push ebp
    lea ebp, [ebx+16]
    call eax
    pop ebp
    pop ebx
    jmp .Llu2_loop
.Llu2_done:
    pop dword ptr fs:[0]
    add esp, 8
    pop ebp
    pop edi
    pop esi
    pop ebx
    ret

# _abnormal_termination(), cdecl: 1 inside a __finally block a local unwind runs (an exception,
# a return, a goto or a longjmp leaving its __try), 0 for one entered by the __try's normal end.
.p2align 4
.globl _f2k_export__abnormal_termination
_f2k_export__abnormal_termination:
    xor eax, eax
    mov ecx, dword ptr fs:[0]
    mov edx, offset _f2k_msvcrt_unwind_handler
    cmp dword ptr [ecx+4], edx
    jne 1f
    inc eax
1:
    ret

# _setjmp3(buffer, count, [unwind function, try level, unwind data...]), cdecl: the caller's
# registers, its resume point and its registration recorded; 0.
.p2align 4
.globl _f2k_export__setjmp3
_f2k_export__setjmp3:
    mov edx, dword ptr [esp+4]
    mov dword ptr [edx], ebp
    mov dword ptr [edx+4], ebx
    mov dword ptr [edx+8], edi
    mov dword ptr [edx+12], esi
    lea eax, [esp+4]
    mov dword ptr [edx+16], eax
    mov eax, dword ptr [esp]
    mov dword ptr [edx+20], eax
    mov dword ptr [edx+32], 0x56433230
    mov dword ptr [edx+36], 0
    mov eax, dword ptr fs:[0]
    mov dword ptr [edx+24], eax
    mov dword ptr [edx+28], -1
    cmp eax, -1
    je .Lsj_done
    mov ecx, dword ptr [esp+8]
    test ecx, ecx
    jz .Lsj_done
    mov eax, dword ptr [esp+12]
    mov dword ptr [edx+36], eax
    dec ecx
    jnz .Lsj_level
    mov eax, dword ptr [edx+24]
    mov eax, dword ptr [eax+12]
    mov dword ptr [edx+28], eax
    jmp .Lsj_done
.Lsj_level:
    mov eax, dword ptr [esp+16]
    mov dword ptr [edx+28], eax
    dec ecx
    jz .Lsj_done
    cmp ecx, 6
    jbe .Lsj_data
    mov ecx, 6
.Lsj_data:
    push esi
    push edi
    lea esi, [esp+28]
    lea edi, [edx+40]
    rep movsd
    pop edi
    pop esi
.Lsj_done:
    xor eax, eax
    ret

# longjmp(buffer, value), cdecl: back to the setjmp, which answers `value` (1 for 0): the
# registrations above the buffer's unwound, the buffer's unwind function called (for the
# setjmp's own function's __finally blocks), its registers restored.
.p2align 4
.globl _f2k_export_longjmp
_f2k_export_longjmp:
    mov ebx, dword ptr [esp+4]
    mov esi, dword ptr [esp+8]
    mov eax, dword ptr [ebx+24]
    cmp eax, dword ptr fs:[0]
    je .Llj_local
    push 0
    push eax
    call _f2k_msvcrt_global_unwind
    add esp, 8
.Llj_local:
    cmp dword ptr [ebx+24], -1
    je .Llj_restore
    cmp dword ptr [ebx+32], 0x56433230
    jne .Llj_restore
    mov eax, dword ptr [ebx+36]
    test eax, eax
    jz .Llj_restore
    mov edi, esp
    push ebx
    call eax
    mov esp, edi
.Llj_restore:
    mov eax, esi
    test eax, eax
    jnz 1f
    inc eax
1:
    mov ebp, dword ptr [ebx]
    mov edi, dword ptr [ebx+8]
    mov esi, dword ptr [ebx+12]
    mov esp, dword ptr [ebx+16]
    mov ecx, dword ptr [ebx+20]
    mov ebx, dword ptr [ebx+4]
    jmp ecx

# _seh_longjmp_unwind(buffer), cdecl: the setjmp's function's __finally blocks above the try level
# _setjmp3 recorded.
.p2align 4
.globl _f2k_export__seh_longjmp_unwind
_f2k_export__seh_longjmp_unwind:
    mov eax, dword ptr [esp+4]
    push dword ptr [eax+28]
    push dword ptr [eax+24]
    call _f2k_export__local_unwind2
    add esp, 8
    ret
