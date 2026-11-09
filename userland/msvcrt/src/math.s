# The floating-point helper the compiler calls: _ftol, Visual C++'s conversion of a floating-point
# value to an integer (a cast of a double or a float to an integral type compiles into `call
# __ftol` unless /QIfist is given, as MSDN's /QIfist page says). Its convention is its own: the
# value is in ST0, and the 64-bit integer comes back in EDX:EAX, the value popped; a 32-bit cast
# keeps EAX. C's conversion truncates toward zero, so it stores with the x87's rounding control
# set to chop, then puts the caller's control word back. A value beyond the 64-bit range, or a
# NaN, stores the x87's integer indefinite (0x8000000000000000), the invalid exception masked as
# the C runtime leaves it.
.text

.p2align 4
.globl _f2k_export__ftol
_f2k_export__ftol:
    push ebp
    mov ebp, esp
    sub esp, 12
    fnstcw word ptr [ebp-2]
    movzx eax, word ptr [ebp-2]
    or eax, 0x0C00
    mov word ptr [ebp-4], ax
    fldcw word ptr [ebp-4]
    fistp qword ptr [ebp-12]
    fldcw word ptr [ebp-2]
    mov eax, dword ptr [ebp-12]
    mov edx, dword ptr [ebp-8]
    leave
    ret
