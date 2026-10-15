/*
 * fileio - disk baseline: the file API over the boot volume.
 *
 * Reads the program's own image from the filesystem: open by the
 * module path, read the MZ signature, seek to e_lfanew and read the
 * PE signature, then seek back to the start and read the MZ again.
 * Every printed result is derived from the file's own bytes, so the
 * output is deterministic for one binary and identical on the real
 * machine and under F2K - the measuring stick for the disk stack
 * (the driver, the volume, the file handles, the seek).
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo fileio.c
 */

#include <windows.h>
#include <stdio.h>

/* INVALID_SET_FILE_POINTER postdates the MSVC 6 SDK headers; later
 * headers define it, so guard rather than assume. */
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#endif

static int check(HANDLE f, const char *what)
{
    printf("fileio: %s failed, error %lu\n", what, GetLastError());
    CloseHandle(f);
    return 1;
}

int main(void)
{
    char path[MAX_PATH];
    HANDLE f;
    BYTE buf[4];
    DWORD got;
    DWORD lfanew;

    if (GetModuleFileNameA(NULL, path, sizeof path) == 0) {
        printf("fileio: GetModuleFileNameA failed, error %lu\n", GetLastError());
        return 1;
    }
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        printf("fileio: open failed, error %lu\n", GetLastError());
        return 1;
    }

    if (!ReadFile(f, buf, 2, &got, NULL) || got != 2 ||
        buf[0] != 'M' || buf[1] != 'Z') {
        return check(f, "MZ read");
    }
    printf("MZ ok\n");

    /* A small image never legitimately seeks to 0xFFFFFFFF, so the
     * plain INVALID_SET_FILE_POINTER check is exact here. */
    if (SetFilePointer(f, 0x3c, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return check(f, "seek to e_lfanew");
    }
    if (!ReadFile(f, buf, 4, &got, NULL) || got != 4) {
        return check(f, "e_lfanew read");
    }
    lfanew = (DWORD)buf[0] | ((DWORD)buf[1] << 8) |
             ((DWORD)buf[2] << 16) | ((DWORD)buf[3] << 24);

    if (SetFilePointer(f, lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return check(f, "seek to PE header");
    }
    if (!ReadFile(f, buf, 4, &got, NULL) || got != 4 ||
        buf[0] != 'P' || buf[1] != 'E' || buf[2] != 0 || buf[3] != 0) {
        return check(f, "PE read");
    }
    printf("PE ok\n");

    if (SetFilePointer(f, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        return check(f, "seek back to start");
    }
    if (!ReadFile(f, buf, 2, &got, NULL) || got != 2 ||
        buf[0] != 'M' || buf[1] != 'Z') {
        return check(f, "MZ re-read");
    }
    printf("MZ again ok\n");

    CloseHandle(f);
    printf("fileio: ok\n");
    return 0;
}
