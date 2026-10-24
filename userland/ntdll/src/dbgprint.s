# DbgPrint's entry: cdecl, its variable arguments after the format, which the caller pops. The body
# (src/dbgprint.rs) takes the format and where the variable arguments start. And DbgBreakPoint.
.text

# DbgPrint(format, ...): the formatted text to the debugger's channel; STATUS_SUCCESS, or the stub
# path's STATUS_NOT_IMPLEMENTED for a conversion the formatter does not serve.
.p2align 4
.globl _f2k_export_DbgPrint
_f2k_export_DbgPrint:
    lea eax, [esp+8]
    push eax
    push dword ptr [esp+8]
    call _f2k_dbg_print
    add esp, 8
    ret

# DbgBreakPoint(): a breakpoint for the debugger. With none attached (the kernel has none), the
# int3's exception is the process's own to handle: raised here, inside ntdll, its address the int3
# (kernel32's DebugBreak calls it, as Windows 2000's does).
.p2align 4
.globl _f2k_export_DbgBreakPoint
_f2k_export_DbgBreakPoint:
    int3
    ret
