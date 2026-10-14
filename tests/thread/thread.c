/*
 * thread - thread creation and the context-switch baseline.
 *
 * The main thread creates one child, which prints from its own
 * stack and exits; the main thread observes the child's completion
 * through a shared flag and then exits 0. Proves: CreateThread
 * starts a thread from scratch (a fresh user stack and a fresh TEB
 * per thread), the scheduler switches to the child and back, and
 * the process ends only after both threads are done.
 *
 * The completion handoff uses a shared flag rather than a wait
 * API: the main thread spins until the child reports, which on a
 * single-CPU machine also forces a quantum end - the scheduler must
 * take the CPU away from a spinning thread before the child can
 * run.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo thread.c
 */

#include <windows.h>
#include <stdio.h>

static volatile DWORD child_state;

DWORD WINAPI child_main(LPVOID param)
{
    (void)param;

    child_state = 1;
    printf("child: running on my own stack\n");
    child_state = 2;
    return 0;
}

int main(void)
{
    HANDLE hchild;
    DWORD tid;

    printf("main: creating a child thread\n");
    hchild = CreateThread(NULL, 0, child_main, NULL, 0, &tid);
    if (hchild == NULL) {
        printf("main: CreateThread failed, error %lu\n", GetLastError());
        return 1;
    }
    if (child_state == 0) {
        printf("main: child not started yet, spinning until it reports\n");
    }
    while (child_state < 2) {
    }
    printf("main: child finished\n");
    CloseHandle(hchild);
    printf("thread: ok\n");
    return 0;
}
