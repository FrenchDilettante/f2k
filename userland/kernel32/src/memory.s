# kernel32's own heap and Local/Global exports (the heap's allocation calls
# forward to ntdll). Their bodies are Rust (src/main.rs: rtl::localmem over ntdll's RtlAllocateHeap
# family on the process heap and its RtlAllocateHandle family on kernel32's handle table, and
# RtlCreateHeap/RtlDestroyHeap, cdecl):
# each export re-pushes its arguments for the body and pops its stdcall block. A Local and a Global
# export share a body, as on NT, but keep exports of their own.
.text

.p2align 4
.globl _f2k_export_HeapCreate
_f2k_export_HeapCreate:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_k32_heap_create
    add esp, 12
    ret 12

.p2align 4
.globl _f2k_export_HeapDestroy
_f2k_export_HeapDestroy:
    push dword ptr [esp+4]
    call _f2k_k32_heap_destroy
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_HeapValidate
_f2k_export_HeapValidate:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_k32_heap_validate
    add esp, 12
    ret 12

.p2align 4
.globl _f2k_export_LocalAlloc
_f2k_export_LocalAlloc:
    push dword ptr [esp+8]
    push dword ptr [esp+8]
    call _f2k_k32_local_alloc
    add esp, 8
    ret 8

.p2align 4
.globl _f2k_export_GlobalAlloc
_f2k_export_GlobalAlloc:
    push dword ptr [esp+8]
    push dword ptr [esp+8]
    call _f2k_k32_local_alloc
    add esp, 8
    ret 8

.p2align 4
.globl _f2k_export_LocalFree
_f2k_export_LocalFree:
    push dword ptr [esp+4]
    call _f2k_k32_local_free
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_GlobalFree
_f2k_export_GlobalFree:
    push dword ptr [esp+4]
    call _f2k_k32_local_free
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_LocalLock
_f2k_export_LocalLock:
    push dword ptr [esp+4]
    call _f2k_k32_local_lock
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_GlobalLock
_f2k_export_GlobalLock:
    push dword ptr [esp+4]
    call _f2k_k32_local_lock
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_LocalUnlock
_f2k_export_LocalUnlock:
    push dword ptr [esp+4]
    call _f2k_k32_local_unlock
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_GlobalUnlock
_f2k_export_GlobalUnlock:
    push dword ptr [esp+4]
    call _f2k_k32_local_unlock
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_LocalHandle
_f2k_export_LocalHandle:
    push dword ptr [esp+4]
    call _f2k_k32_local_handle
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_GlobalHandle
_f2k_export_GlobalHandle:
    push dword ptr [esp+4]
    call _f2k_k32_local_handle
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_LocalSize
_f2k_export_LocalSize:
    push dword ptr [esp+4]
    call _f2k_k32_local_size
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_GlobalSize
_f2k_export_GlobalSize:
    push dword ptr [esp+4]
    call _f2k_k32_local_size
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_LocalFlags
_f2k_export_LocalFlags:
    push dword ptr [esp+4]
    call _f2k_k32_local_flags
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_LocalReAlloc
_f2k_export_LocalReAlloc:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_k32_local_realloc
    add esp, 12
    ret 12

.p2align 4
.globl _f2k_export_GlobalReAlloc
_f2k_export_GlobalReAlloc:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_k32_local_realloc
    add esp, 12
    ret 12
