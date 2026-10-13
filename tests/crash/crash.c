/*
 * crash - fault-containment fixture, no C runtime, no imports.
 *
 * The entry point writes through an unmapped low address (the NULL
 * page) as its very first act, then spins as the safety net: the
 * write must raise a page fault before anything else can happen, so
 * the binary imports nothing at all - it never reaches an import.
 * On real Windows 2000 the NULL page is reserved the same way, so
 * the program faults there too.
 *
 * F2K passes when the kernel contains the fault: the process ends
 * with the fault reported on COM1 and the kernel runs the next
 * process to completion.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo crash.c /link /NODEFAULTLIB /ENTRY:CrashMain /SUBSYSTEM:CONSOLE
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void WINAPI CrashMain(void)
{
    *(volatile DWORD *)0 = 0xDEADBEEFu;
    for (;;) {
    }
}
