# The loader's entry point for a fresh thread, Windows 2000's LdrInitializeThunk: the kernel delivers a
# thread's initialization here like a user APC, over the thread's initial context, before anything
# else it runs in user mode (`user::apc::deliver_initialization`). At ESP the delivery left a
# four-word APC call frame (all zero: no routine), then the CONTEXT; EDI (preserved across the cdecl
# body) keeps the context's address. The body (src/main.rs, `f2k_ldr_initialize`) makes the process
# heap, the PEB lock and the loader lock on the process's first thread, and every thread's
# implicit-TLS block, then NtContinue resumes the context, TestAlert TRUE as KiUserApcDispatcher's:
# user APCs queued before the thread ran deliver next, in queue order, before its first
# instruction. Only a failed NtContinue returns: its status is raised.
.text

.p2align 4
.globl _f2k_export_LdrInitializeThunk
_f2k_export_LdrInitializeThunk:
    lea edi, [esp+0x10]
    call _f2k_ldr_initialize
    push 1
    push edi
    call _f2k_nt_NtContinue
    push eax
    call _f2k_raise_failed_status
    ud2
