# The critical sections' exports (Windows 2000's ntdll keeps them; kernel32 forwards here). Their
# bodies are Rust (rtl::critsec over the calling thread's system, src/main.rs, cdecl): each export
# re-pushes its arguments for the body and pops its stdcall block.
.text

.p2align 4
.globl _f2k_export_RtlInitializeCriticalSection
_f2k_export_RtlInitializeCriticalSection:
    push dword ptr [esp+4]
    call _f2k_rtl_initialize_critical_section
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_RtlInitializeCriticalSectionAndSpinCount
_f2k_export_RtlInitializeCriticalSectionAndSpinCount:
    push dword ptr [esp+8]
    push dword ptr [esp+8]
    call _f2k_rtl_initialize_critical_section_and_spin_count
    add esp, 8
    ret 8

.p2align 4
.globl _f2k_export_RtlEnterCriticalSection
_f2k_export_RtlEnterCriticalSection:
    push dword ptr [esp+4]
    call _f2k_rtl_enter_critical_section
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_RtlTryEnterCriticalSection
_f2k_export_RtlTryEnterCriticalSection:
    push dword ptr [esp+4]
    call _f2k_rtl_try_enter_critical_section
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_RtlLeaveCriticalSection
_f2k_export_RtlLeaveCriticalSection:
    push dword ptr [esp+4]
    call _f2k_rtl_leave_critical_section
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_RtlDeleteCriticalSection
_f2k_export_RtlDeleteCriticalSection:
    push dword ptr [esp+4]
    call _f2k_rtl_delete_critical_section
    add esp, 4
    ret 4

.p2align 4
.globl _f2k_export_RtlSetCriticalSectionSpinCount
_f2k_export_RtlSetCriticalSectionSpinCount:
    push dword ptr [esp+8]
    push dword ptr [esp+8]
    call _f2k_rtl_set_critical_section_spin_count
    add esp, 8
    ret 8
