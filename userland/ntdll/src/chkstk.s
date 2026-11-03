# The stack probe, _chkstk and _alloca_probe: one routine under two names, as Windows 2000's ntdll
# exports it (kernel32, user32, advapi32 and others import it). EAX holds the bytes to allocate;
# each page down to the new ESP is touched in order, then ESP is lowered and the routine returns.
# The body is the one every image links (compiler-helpers' __chkstk): the jump leaves the stack as
# the call made it, so the probe sees its caller's ESP and return address.
.text

.p2align 4
.globl _f2k_export__chkstk
.globl _f2k_export__alloca_probe
_f2k_export__chkstk:
_f2k_export__alloca_probe:
    jmp __chkstk
