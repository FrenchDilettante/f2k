/*
 * suspend - suspend/resume baseline.
 *
 * The main thread watches a shared phase flag while a worker runs.
 * After suspending the worker, the main thread sleeps long enough
 * that the worker would have finished had it been runnable - a
 * suspended thread makes no progress even with the CPU free. After
 * resuming it, the worker completes. The suspend and resume calls
 * return the documented previous suspend counts (0 then 1).
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo suspend.c
 */

#include <windows.h>
#include <stdio.h>

static volatile DWORD phase;

DWORD WINAPI worker_main(LPVOID param)
{
    (void)param;

    phase = 1;
    while (phase != 2) {
    }
    phase = 3;
    return 0;
}

int main(void)
{
    HANDLE hworker;
    DWORD prev;

    hworker = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
    if (hworker == NULL) {
        printf("main: CreateThread failed, error %lu\n", GetLastError());
        return 1;
    }
    while (phase < 1) {
    }
    prev = SuspendThread(hworker);
    printf("suspend returned %lu\n", prev);
    Sleep(100);
    printf("worker frozen: %s\n", phase == 1 ? "yes" : "no");
    prev = ResumeThread(hworker);
    printf("resume returned %lu\n", prev);
    phase = 2;
    while (phase < 3) {
        Sleep(10);
    }
    CloseHandle(hworker);
    printf("suspend: ok\n");
    return 0;
}
