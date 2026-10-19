# Every main thread's first kernel32 code, as Windows 2000's: the kernel starts an image's main
# thread at BaseProcessStartThunk with EAX its entry point (BaseInitializeContext's CONTEXT, ESP one
# dword below the stack's base). The thunk clears EBP (the end of the frame chain), pushes the entry
# point under a zero return address and jumps to its body, BaseProcessStart(entry). The body
# registers its exception frame (next, handler, resume) on fs:[0] right below its saved EBP — the
# last frame of the thread's chain, its handler kernel32's — then calls the entry point, so [esp]
# at the entry point's first instruction is a return address inside kernel32. The handler is
# `__except (UnhandledExceptionFilter(GetExceptionInformation()))`: on EXECUTE_HANDLER the chain is
# unwound to the frame (RtlUnwind, src/except.rs), the body's stack and EBP come back from it, and
# its resume point calls ExitProcess with the exception's code. The body leaves 0x1C bytes of
# locals below its registration, as Windows 2000's SEH prologue frames them, so the entry point
# sees ESP at the stack's base minus 0x3C (0x0012FFC4 on a Windows 2000 main thread's 0x00130000
# stack).
#
# The entry point's return value ends the process (ExitProcess) until kernel32's ExitThread is user
# code: Windows 2000 hands it to ExitThread, which ends the process only from its last thread.
.text

.p2align 4
.globl _f2k_export_BaseProcessStartThunk
_f2k_export_BaseProcessStartThunk:
    xor ebp, ebp
    push eax
    push 0
    jmp _f2k_k32_base_process_start

# BaseProcessStart(entry), under the thunk's zero return address: the entry point takes no
# arguments.
.p2align 4
_f2k_k32_base_process_start:
    push ebp
    mov ebp, esp
    mov eax, offset .Lprocess_except
    push eax
    mov eax, offset _f2k_k32_start_handler
    push eax
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    sub esp, 0x1C
    call dword ptr [ebp+8]
    push eax
    call _f2k_svc_ExitProcess
.Lprocess_except:
    push eax
    call _f2k_svc_ExitProcess

# The start frame's exception handler (cdecl: record, frame, context, dispatcher): an unwind passing
# through searches on; otherwise UnhandledExceptionFilter, handed the EXCEPTION_POINTERS (the record,
# then the context), decides — continue execution (-1), continue the search (0), or execute the
# handler (1): the chain unwound to the frame, then the body's resume point with EAX the
# exception's code (EBX and ESI survive RtlUnwind, which resumes its caller's context).
.p2align 4
_f2k_k32_start_handler:
    mov eax, dword ptr [esp+4]
    test dword ptr [eax+4], 6
    jnz .Lstart_search
    push dword ptr [esp+12]
    push eax
    push esp
    call _f2k_export_UnhandledExceptionFilter
    add esp, 8
    cmp eax, 1
    je .Lstart_execute
    cmp eax, -1
    jne .Lstart_search
    xor eax, eax
    ret
.Lstart_search:
    mov eax, 1
    ret
.Lstart_execute:
    mov eax, dword ptr [esp+4]
    mov ebx, dword ptr [esp+8]
    mov esi, dword ptr [eax]
    push eax
    push ebx
    call _f2k_k32_probe_unwind
    mov esp, ebx
    lea ebp, [ebx+12]
    mov eax, esi
    jmp dword ptr [ebx+8]
