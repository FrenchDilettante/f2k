/*
 * pingpong - blocking-wait baseline through two auto-reset events.
 *
 * The main thread ("pong") and one child ("ping") alternate
 * strictly for five turns: each side prints one line per turn,
 * then hands the turn over by signaling the other's event and
 * blocking on its own. Proves: a blocking wait actually blocks
 * (the CPU has nowhere to go but the other thread or idle),
 * auto-reset event semantics (a signal wakes exactly one waiter),
 * and that a thread handle becomes waitable at thread exit -
 * the final wait on the child's handle returns 0 only after the
 * child has finished.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo pingpong.c
 */

#include <windows.h>
#include <stdio.h>

#define TURNS 5

static HANDLE turn_ping;
static HANDLE turn_pong;

DWORD WINAPI ping_main(LPVOID param)
{
    DWORD i;
    (void)param;

    for (i = 0; i < TURNS; i++) {
        if (WaitForSingleObject(turn_ping, INFINITE) != WAIT_OBJECT_0) {
            return 1;
        }
        printf("ping %lu\n", i);
        SetEvent(turn_pong);
    }
    return 0;
}

int main(void)
{
    HANDLE hchild;
    DWORD r;
    DWORD i;

    turn_ping = CreateEvent(NULL, FALSE, FALSE, NULL);
    turn_pong = CreateEvent(NULL, FALSE, TRUE, NULL);
    if (turn_ping == NULL || turn_pong == NULL) {
        printf("main: CreateEvent failed, error %lu\n", GetLastError());
        return 1;
    }
    hchild = CreateThread(NULL, 0, ping_main, NULL, 0, NULL);
    if (hchild == NULL) {
        printf("main: CreateThread failed, error %lu\n", GetLastError());
        return 1;
    }

    for (i = 0; i < TURNS; i++) {
        if (WaitForSingleObject(turn_pong, INFINITE) != WAIT_OBJECT_0) {
            printf("main: unexpected wait result %lu\n", GetLastError());
            return 1;
        }
        printf("pong %lu\n", i);
        SetEvent(turn_ping);
    }

    r = WaitForSingleObject(hchild, INFINITE);
    printf("child handle wait returned %lu\n", r);
    CloseHandle(hchild);
    CloseHandle(turn_ping);
    CloseHandle(turn_pong);
    printf("pingpong: ok\n");
    return 0;
}
