/*
 * sleep - timer baseline: Sleep and a timed wait.
 *
 * Two observables: Sleep(200) spans a bounded tick count measured
 * with GetTickCount before and after, and a wait with a timeout on
 * a never-signaled event reports timeout after the requested time
 * - not early, and without blocking forever. Together they prove
 * the thread is off the ready queue until due (the timer
 * machinery, not spinning): during both waits another thread or
 * the idle path owns the CPU.
 *
 * Sleep(0) is a pure yield: with no other ready thread it returns
 * immediately.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo sleep.c
 */

#include <windows.h>
#include <stdio.h>

int main(void)
{
    HANDLE ev;
    DWORD t0, t1;
    DWORD r;

    t0 = GetTickCount();
    Sleep(200);
    t1 = GetTickCount();
    printf("sleep 200ms spanned %lu ticks\n", t1 - t0);

    Sleep(0);
    printf("sleep 0 returned\n");

    ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ev == NULL) {
        printf("main: CreateEvent failed, error %lu\n", GetLastError());
        return 1;
    }
    t0 = GetTickCount();
    r = WaitForSingleObject(ev, 100);
    t1 = GetTickCount();
    if (r == WAIT_TIMEOUT) {
        printf("timed wait: timeout after %lu ticks\n", t1 - t0);
    } else {
        printf("timed wait: wrong result %lu\n", r);
        return 1;
    }
    CloseHandle(ev);
    printf("sleep: ok\n");
    return 0;
}
