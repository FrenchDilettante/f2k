# The critical-section initialization kernel32 keeps itself (the rest forward to ntdll). Its body is
# Rust (rtl::critsec over the calling thread's system, src/main.rs, cdecl): the export re-pushes
# its argument for the body and pops its stdcall block.
.text

.p2align 4
.globl _f2k_export_InitializeCriticalSection
_f2k_export_InitializeCriticalSection:
    push dword ptr [esp+4]
    call _f2k_k32_initialize_critical_section
    add esp, 4
    ret 4

