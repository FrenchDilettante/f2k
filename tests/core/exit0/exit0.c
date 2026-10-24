/*
 * exit0 - process lifecycle baseline, no C runtime.
 *
 * The most minimal useful Windows 2000 console executable: a custom
 * entry point that terminates the process with exit code 0. There is
 * no CRT startup, no console I/O; the only import is ExitProcess.
 *
 * F2K passes when the kernel observes the process exiting with code 0.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void WINAPI ExitMain(void)
{
    ExitProcess(0);
}
