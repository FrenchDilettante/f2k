/*
 * stackkid - the threads fixture's companion program: linked with
 * /STACK:0x400000, so its image asks for 4 MiB stack reservations, and
 * started by threads.exe's stacksize section. It prints nothing: its exit
 * code says, two bits for each, whether 3 MiB of recursion ran on its
 * main thread (bits 0-1), on a thread created with stack size 0 (bits
 * 2-3), and on one created with stack size 0x10000 (bits 4-5): 1 when the
 * recursion ran, 2 when it overflowed (STATUS_STACK_OVERFLOW caught), 3
 * for any other exception, 0 when the thread never ran. Windows 2000
 * gives every thread the image's reservation unless a larger stack size
 * is asked for, so all three ran there.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat threads):
 *   cl /nologo /MT stackkid.c /link /STACK:0x400000
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static DWORD recurse(DWORD depth)
{
    volatile BYTE pad[1024];

    pad[1023] = (BYTE)depth;
    pad[0] = (BYTE)depth;
    if (depth == 0) {
        return 0;
    }
    return recurse(depth - 1) + pad[0] - pad[1023];
}

/* 3 MiB of recursion under __try: 1 ran, 2 overflowed, 3 another fault. */
static DWORD deep(void)
{
    DWORD result;

    __try {
        result = recurse(3 * 1024) == 0 ? 1 : 3;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = GetExceptionCode() == STATUS_STACK_OVERFLOW ? 2 : 3;
    }
    return result;
}

static DWORD WINAPI thread_deep(LPVOID param)
{
    *(DWORD *)param = deep();
    return 0;
}

/* A thread with stack size `stack` running deep(): its result, 0 when it
   never ran. */
static DWORD on_thread(DWORD stack)
{
    DWORD result = 0;
    HANDLE h = CreateThread(NULL, stack, thread_deep, &result, 0, NULL);

    if (h != NULL) {
        WaitForSingleObject(h, 10000);
        CloseHandle(h);
    }
    return result;
}

int main(void)
{
    DWORD code;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    code = deep();
    code |= on_thread(0) << 2;
    code |= on_thread(0x10000) << 4;
    return (int)code;
}
