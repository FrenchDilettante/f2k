/*
 * bsscheck - fresh-memory round-trip fixture, no C runtime.
 *
 * The entry point checks that its uninitialized data (the .bss
 * section) is all zero, scribbles a recognizable pattern over it,
 * and exits 0 only if the zero check passed (a nonzero code
 * otherwise). The kernel suite runs this fixture twice in one boot:
 * the second run exits 0 only if teardown handed the image's frames
 * back to the allocator re-zeroed, with no stale mappings left
 * behind.
 *
 * F2K passes when the kernel observes exit code 0 on both runs.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo bsscheck.c /link /NODEFAULTLIB /ENTRY:BssMain /SUBSYSTEM:CONSOLE kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* 4096 DWORDs = 16 KiB of .bss: four pages of fresh-memory proof. */
static DWORD bss_probe[4096];

void WINAPI BssMain(void)
{
    DWORD i;

    for (i = 0; i < 4096; ++i) {
        if (bss_probe[i] != 0) {
            ExitProcess(1);
        }
    }
    for (i = 0; i < 4096; ++i) {
        bss_probe[i] = 0x5A5AA5A5u ^ i;
    }
    ExitProcess(0);
}
