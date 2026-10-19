# The exception dispatcher's entry points (Windows 2000's ntdll keeps them in assembly too): the
# kernel's way into user mode for an exception, RtlUnwind's context capture, and ExecuteHandler2's
# registration around a handler's call. Their bodies are Rust (src/except.rs over rtl::seh, cdecl).
.text

# The kernel enters user mode here for every exception it dispatches, a fault's or
# NtRaiseException's first chance: the EXCEPTION_RECORD's address at [esp], the CONTEXT's at
# [esp+4], both written just above. The body (the cdecl call puts them in its argument slots)
# searches the handlers, then resumes the context (NtContinue) or raises the second chance
# (NtRaiseException, FirstChance FALSE); it never returns.
.p2align 4
.globl _f2k_export_KiUserExceptionDispatcher
_f2k_export_KiUserExceptionDispatcher:
    call _f2k_user_exception_dispatch
    ud2

# RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue): the caller's context captured as
# it was at the call (its registers, EFLAGS and segments; EIP its return address, ESP past the
# four arguments, EAX the return value), a record of RtlUnwind's own room beside it, then the walk
# (the cdecl body: the return address, the four arguments, the context, the own record), which
# ends in NtContinue of that context — the caller resumes as from a return — or the second chance.
.p2align 4
.globl _f2k_export_RtlUnwind
_f2k_export_RtlUnwind:
    push ebp
    mov ebp, esp
    pushfd
    sub esp, 0x2CC + 80
    mov dword ptr [esp+0xAC], ecx
    mov dword ptr [esp+0xA8], edx
    mov dword ptr [esp+0xA4], ebx
    mov dword ptr [esp+0xA0], esi
    mov dword ptr [esp+0x9C], edi
    mov eax, dword ptr [ebp+20]
    mov dword ptr [esp+0xB0], eax
    mov eax, dword ptr [ebp]
    mov dword ptr [esp+0xB4], eax
    mov eax, dword ptr [ebp+4]
    mov dword ptr [esp+0xB8], eax
    lea eax, [ebp+24]
    mov dword ptr [esp+0xC4], eax
    mov eax, dword ptr [ebp-4]
    mov dword ptr [esp+0xC0], eax
    xor eax, eax
    mov ax, cs
    mov dword ptr [esp+0xBC], eax
    mov ax, ss
    mov dword ptr [esp+0xC8], eax
    mov ax, ds
    mov dword ptr [esp+0x98], eax
    mov ax, es
    mov dword ptr [esp+0x94], eax
    mov ax, fs
    mov dword ptr [esp+0x90], eax
    mov ax, gs
    mov dword ptr [esp+0x8C], eax
    mov dword ptr [esp], 0x10007
    mov eax, esp
    lea ecx, [esp+0x2CC]
    push ecx
    push eax
    push dword ptr [ebp+20]
    push dword ptr [ebp+16]
    push dword ptr [ebp+12]
    push dword ptr [ebp+8]
    push dword ptr [ebp+4]
    call _f2k_rtl_unwind
    ud2

# ExecuteHandler2 (cdecl: record, frame, context, dispatcher, handler, own handler): call `handler`
# for `frame` as the platform does, handler(record, frame, context, dispatcher), under a
# registration of the dispatcher's own (next, own handler, frame) so an exception raised (or an
# unwind started) while the handler runs reaches it first. The handler's calling convention does
# not matter: the stack comes back from that registration. EBX, ESI and EDI are zero for the
# handler and preserved for the caller.
.p2align 4
.globl _f2k_execute_handler
_f2k_execute_handler:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    push dword ptr [ebp+12]
    push dword ptr [ebp+28]
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    push dword ptr [ebp+20]
    push dword ptr [ebp+16]
    push dword ptr [ebp+12]
    push dword ptr [ebp+8]
    mov ecx, dword ptr [ebp+24]
    xor eax, eax
    xor ebx, ebx
    xor esi, esi
    xor edi, edi
    call ecx
    mov esp, dword ptr fs:[0]
    pop dword ptr fs:[0]
    lea esp, [ebp-12]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
