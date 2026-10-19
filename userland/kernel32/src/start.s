# Every thread's first kernel32 code, as Windows 2000's: the kernel starts an image's main thread at
# BaseProcessStartThunk with EAX its entry point, and kernel32's CreateThread starts a child at
# BaseThreadStartThunk with EAX its start address and EBX its parameter (BaseInitializeContext's
# CONTEXT, ESP one dword below the stack's base). Each thunk clears EBP (the end of the frame chain),
# pushes its registers under a zero return address and jumps to its body: BaseProcessStart(entry),
# BaseThreadStart(start, parameter). A body registers its exception frame (next, handler, resume) on
# fs:[0] right below its saved EBP — the last frame of every thread's chain, its handler kernel32's —
# then calls the routine, so [esp] at the routine's first instruction is a return address inside
# kernel32; the routine's return value goes to ExitThread. The handler is `__except
# (UnhandledExceptionFilter(GetExceptionInformation()))`: on EXECUTE_HANDLER the chain is unwound to
# the frame (RtlUnwind, src/except.rs), the body's stack and EBP come back from it, and its resume
# point calls ExitProcess with the exception's code. Each body leaves 0x1C bytes of locals below its
# registration, as Windows 2000's SEH prologue frames them, so the entry point sees ESP at the
# stack's base minus 0x3C (0x0012FFC4 on a Windows 2000 main thread's 0x00130000 stack).
.text

.p2align 4
.globl _f2k_export_BaseProcessStartThunk
_f2k_export_BaseProcessStartThunk:
    xor ebp, ebp
    push eax
    push 0
    jmp _f2k_k32_base_process_start

.p2align 4
.globl _f2k_export_BaseThreadStartThunk
_f2k_export_BaseThreadStartThunk:
    xor ebp, ebp
    push ebx
    push eax
    push 0
    jmp _f2k_k32_base_thread_start

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
    call _f2k_k32_exit_thread
.Lprocess_except:
    push eax
    call _f2k_k32_exit_process

# BaseThreadStart(start, parameter), under the thunk's zero return address: the start routine
# takes its parameter (stdcall: it pops it).
.p2align 4
_f2k_k32_base_thread_start:
    push ebp
    mov ebp, esp
    mov eax, offset .Lthread_except
    push eax
    mov eax, offset _f2k_k32_start_handler
    push eax
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    sub esp, 0x1C
    push dword ptr [ebp+12]
    call dword ptr [ebp+8]
    push eax
    call _f2k_k32_exit_thread
.Lthread_except:
    push eax
    call _f2k_k32_exit_process

# The start frames' exception handler (cdecl: record, frame, context, dispatcher): an unwind passing
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
