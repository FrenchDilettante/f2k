# kernel32's native exports: functions that run entirely in user mode, as Windows 2000's own
# kernel32 runs them. They read and write the calling thread's TEB through FS (the NT layout:
# ClientId at 20h, LastErrorValue at 34h, the PEB at 30h, TlsSlots at E10h, TlsExpansionSlots at
# F94h), return the pseudo-handles, run the locked read-modify-write sequences (atomic on any
# processor, with no kernel transition), or keep the top-level exception filter. Every export is
# stdcall: its `ret` pops its argument block.
.text

.p2align 4
.globl _f2k_export_GetLastError
_f2k_export_GetLastError:
    mov eax, dword ptr fs:[0x34]
    ret

.p2align 4
.globl _f2k_export_SetLastError
_f2k_export_SetLastError:
    mov eax, dword ptr [esp+4]
    mov dword ptr fs:[0x34], eax
    ret 4

# The calling thread's process's client id (TEB ClientId.UniqueProcess).
.p2align 4
.globl _f2k_export_GetCurrentProcessId
_f2k_export_GetCurrentProcessId:
    mov eax, dword ptr fs:[0x20]
    ret

# The calling thread's client id (TEB ClientId.UniqueThread).
.p2align 4
.globl _f2k_export_GetCurrentThreadId
_f2k_export_GetCurrentThreadId:
    mov eax, dword ptr fs:[0x24]
    ret

# The process heap (the PEB's ProcessHeap, which ntdll's LdrInitializeThunk makes).
.p2align 4
.globl _f2k_export_GetProcessHeap
_f2k_export_GetProcessHeap:
    mov eax, dword ptr fs:[0x30]
    mov eax, dword ptr [eax+0x18]
    ret

# The current-thread pseudo-handle.
.p2align 4
.globl _f2k_export_GetCurrentThread
_f2k_export_GetCurrentThread:
    mov eax, -2
    ret

# The current-process pseudo-handle.
.p2align 4
.globl _f2k_export_GetCurrentProcess
_f2k_export_GetCurrentProcess:
    mov eax, -1
    ret

.p2align 4
.globl _f2k_export_InterlockedIncrement
_f2k_export_InterlockedIncrement:
    mov ecx, dword ptr [esp+4]
    mov eax, 1
    lock xadd dword ptr [ecx], eax
    inc eax
    ret 4

.p2align 4
.globl _f2k_export_InterlockedDecrement
_f2k_export_InterlockedDecrement:
    mov ecx, dword ptr [esp+4]
    mov eax, -1
    lock xadd dword ptr [ecx], eax
    dec eax
    ret 4

# xchg with memory locks implicitly.
.p2align 4
.globl _f2k_export_InterlockedExchange
_f2k_export_InterlockedExchange:
    mov ecx, dword ptr [esp+4]
    mov eax, dword ptr [esp+8]
    xchg dword ptr [ecx], eax
    ret 8

.p2align 4
.globl _f2k_export_InterlockedExchangeAdd
_f2k_export_InterlockedExchangeAdd:
    mov ecx, dword ptr [esp+4]
    mov eax, dword ptr [esp+8]
    lock xadd dword ptr [ecx], eax
    ret 8

# EAX returns the initial value either way.
.p2align 4
.globl _f2k_export_InterlockedCompareExchange
_f2k_export_InterlockedCompareExchange:
    mov ecx, dword ptr [esp+4]
    mov edx, dword ptr [esp+8]
    mov eax, dword ptr [esp+12]
    lock cmpxchg dword ptr [ecx], edx
    ret 12

# Indexes 0..63 live in the TEB's TlsSlots, 64..1087 in the thread's TlsExpansionSlots (on the
# process heap, made by the first TlsSetValue of such an index; a get before it reads zero); anything
# else is ERROR_INVALID_PARAMETER (87). A successful get clears the last error.
.p2align 4
.globl _f2k_export_TlsGetValue
_f2k_export_TlsGetValue:
    mov ecx, dword ptr [esp+4]
    cmp ecx, 64
    jae .Ltls_get_expansion
    mov eax, dword ptr fs:[ecx*4+0xE10]
    mov dword ptr fs:[0x34], 0
    ret 4
.Ltls_get_expansion:
    cmp ecx, 1088
    jae .Ltls_get_invalid
    mov eax, dword ptr fs:[0xF94]
    test eax, eax
    jz .Ltls_get_none
    mov eax, dword ptr [eax+ecx*4-0x100]
.Ltls_get_none:
    mov dword ptr fs:[0x34], 0
    ret 4
.Ltls_get_invalid:
    mov dword ptr fs:[0x34], 87
    xor eax, eax
    ret 4

.p2align 4
.globl _f2k_export_TlsSetValue
_f2k_export_TlsSetValue:
    mov ecx, dword ptr [esp+4]
    mov edx, dword ptr [esp+8]
    cmp ecx, 64
    jae .Ltls_set_expansion
    mov dword ptr fs:[ecx*4+0xE10], edx
    mov eax, 1
    ret 8
.Ltls_set_expansion:
    cmp ecx, 1088
    jae .Ltls_set_invalid
    mov eax, dword ptr fs:[0xF94]
    test eax, eax
    jz .Ltls_set_allocate
.Ltls_set_store:
    mov dword ptr [eax+ecx*4-0x100], edx
    mov eax, 1
    ret 8
# The thread's first expansion index: its slots come from the process heap (ECX and EDX kept
# across the cdecl body); with no room, ERROR_NOT_ENOUGH_MEMORY.
.Ltls_set_allocate:
    push ecx
    push edx
    call _f2k_k32_tls_expansion
    pop edx
    pop ecx
    test eax, eax
    jnz .Ltls_set_store
    mov dword ptr fs:[0x34], 8
    ret 8
.Ltls_set_invalid:
    mov dword ptr fs:[0x34], 87
    xor eax, eax
    ret 8

# The top-level exception filter is kernel32's own data (src/main.rs's TOP_LEVEL_FILTER, by its
# symbol). The previous filter is returned.
.p2align 4
.globl _f2k_export_SetUnhandledExceptionFilter
_f2k_export_SetUnhandledExceptionFilter:
    mov eax, dword ptr [esp+4]
    xchg dword ptr [_f2k_k32_top_level_filter], eax
    ret 4

# The default unhandled-exception verdict, as Windows 2000 gives it with no debugger and the fault
# dialog suppressed: the top-level filter's verdict when it has one other than continue search,
# else execute the handler (the process ends with the exception's code).
.p2align 4
.globl _f2k_export_UnhandledExceptionFilter
_f2k_export_UnhandledExceptionFilter:
    mov eax, dword ptr [_f2k_k32_top_level_filter]
    test eax, eax
    jz .Lfilter_execute
    push dword ptr [esp+4]
    call eax
    test eax, eax
    jnz .Lfilter_done
.Lfilter_execute:
    mov eax, 1
.Lfilter_done:
    ret 4
