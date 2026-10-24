# The loader's entry point for a fresh thread, Windows 2000's LdrInitializeThunk: the kernel delivers a
# thread's initialization here like a user APC, over the thread's initial context, before anything
# else it runs in user mode (`user::apc::deliver_initialization`). At ESP the delivery left a
# four-word APC call frame (all zero: no routine), then the CONTEXT; EDI (preserved across the cdecl
# body) keeps the context's address, and the body takes it (the process's DLL_PROCESS_ATTACH passes
# it as lpReserved). The body (src/main.rs, `f2k_ldr_initialize`) makes the process heap, the PEB
# lock and the loader lock on the process's first thread and loads the image's DLLs, makes every
# thread's implicit-TLS block, and calls the DLLs' entry points; then NtContinue resumes the
# context, TestAlert TRUE as KiUserApcDispatcher's: user APCs queued before the thread ran deliver
# next, in queue order, before its first instruction. Only a failed NtContinue returns: its status
# is raised.
.text

.p2align 4
.globl _f2k_export_LdrInitializeThunk
_f2k_export_LdrInitializeThunk:
    lea edi, [esp+0x10]
    push edi
    call _f2k_ldr_initialize
    add esp, 4
    push 1
    push edi
    call _f2k_nt_NtContinue
    push eax
    call _f2k_raise_failed_status
    ud2

# f2k_call_dll_entry(entry_point, base, reason, reserved), cdecl: a DLL's entry point called as
# Windows 2000's loader calls it (LdrpCallInitRoutine), DllMain(base, reason, reserved), stdcall.
# EBP keeps the frame, so the stack pointer comes back whatever the routine pops, and EBX, ESI and
# EDI are saved around it: a routine that does not keep them does not hurt the loader. Its BOOL in
# EAX.
.p2align 4
.globl _f2k_call_dll_entry
_f2k_call_dll_entry:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    push dword ptr [ebp+20]
    push dword ptr [ebp+16]
    push dword ptr [ebp+12]
    call dword ptr [ebp+8]
    lea esp, [ebp-12]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
