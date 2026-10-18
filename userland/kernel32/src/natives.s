# kernel32's native exports: functions that run entirely in user mode, as Windows 2000's own
# kernel32 runs them. They read and write the calling thread's TEB through FS (the NT layout:
# ClientId at 20h, LastErrorValue at 34h), return the pseudo-handles, or run the locked
# read-modify-write sequences (atomic on any processor, with no kernel transition). Every export is
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
