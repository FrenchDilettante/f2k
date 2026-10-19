# The heaps' exports (Windows 2000's ntdll keeps them; kernel32 forwards HeapAlloc, HeapFree,
# HeapReAlloc, HeapSize and HeapValidate here). Their bodies are Rust (rtl::heap over the calling
# thread's system, src/main.rs, cdecl): each export re-pushes its arguments for the body and pops its
# stdcall block. An allocation the body refuses with its high dword set raises STATUS_NO_MEMORY
# (src/except.rs, through RtlRaiseException), the size as the exception's parameter: continuing it
# returns null to the caller.
.text

.p2align 4
.globl _f2k_export_RtlCreateHeap
_f2k_export_RtlCreateHeap:
    push dword ptr [esp+16]
    push dword ptr [esp+16]
    push dword ptr [esp+16]
    push dword ptr [esp+16]
    call _f2k_rtl_create_heap
    add esp, 16
    ret 24

.p2align 4
.globl _f2k_export_RtlDestroyHeap
_f2k_export_RtlDestroyHeap:
    push dword ptr [esp+4]
    call _f2k_rtl_destroy_heap
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_RtlAllocateHeap
_f2k_export_RtlAllocateHeap:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_rtl_allocate_heap
    add esp, 12
    test edx, edx
    jnz 1f
    ret 12
1:
    push dword ptr [esp+12]
    call _f2k_heap_raise_no_memory
    add esp, 4
    xor eax, eax
    ret 12

.p2align 4
.globl _f2k_export_RtlFreeHeap
_f2k_export_RtlFreeHeap:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_rtl_free_heap
    add esp, 12
    ret 12

.p2align 4
.globl _f2k_export_RtlReAllocateHeap
_f2k_export_RtlReAllocateHeap:
    push dword ptr [esp+16]
    push dword ptr [esp+16]
    push dword ptr [esp+16]
    push dword ptr [esp+16]
    call _f2k_rtl_reallocate_heap
    add esp, 16
    test edx, edx
    jnz 1f
    ret 16
1:
    push dword ptr [esp+16]
    call _f2k_heap_raise_no_memory
    add esp, 4
    xor eax, eax
    ret 16

.p2align 4
.globl _f2k_export_RtlSizeHeap
_f2k_export_RtlSizeHeap:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_rtl_size_heap
    add esp, 12
    ret 12

.p2align 4
.globl _f2k_export_RtlValidateHeap
_f2k_export_RtlValidateHeap:
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    push dword ptr [esp+12]
    call _f2k_rtl_validate_heap
    add esp, 12
    ret 12
