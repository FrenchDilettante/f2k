# The F2K-internal entry points: user code the kernel sends a thread to. Each ends in the gate on
# an internal service and never returns.
.text

# A child thread's user function returns here: its return value (EAX) moves to the gate's argument
# register (the service number load would clobber it), and the thread ends.
.p2align 4
.globl _f2k_export_F2kThreadExitTrampoline
_f2k_export_F2kThreadExitTrampoline:
    mov edx, eax
    mov eax, SYS_THREAD_EXIT
    int SYSCALL_VECTOR
