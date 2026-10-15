/*
 * respawn - thread-slot reuse after a thread has exited.
 *
 * The main thread creates a child, waits for it to finish, closes
 * its handle, and repeats - three rounds, one child alive at a time.
 * Each child prints its round from its own stack and returns.
 * Proves: a thread's kernel resources are released at its exit and
 * can be handed to the next thread (the second and third children
 * reuse what the first one gave back). The imports are the
 * pingpong fixture's thread set, nothing new.
 *
 * Every round waits for its child before creating the next, so no
 * two children ever overlap: a kernel that never reclaims an exited
 * thread's stack, or reclaims it without unmapping it, fails on the
 * second round.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo respawn.c
 */

#include <windows.h>
#include <stdio.h>

#define ROUNDS 3

DWORD WINAPI child_main(LPVOID param)
{
    DWORD round = (DWORD)param;

    printf("child %lu: running\n", round);
    return 0;
}

int main(void)
{
    DWORD round;
    HANDLE hchild;
    DWORD wait;

    for (round = 1; round <= ROUNDS; round++) {
        hchild = CreateThread(NULL, 0, child_main, (LPVOID)round, 0, NULL);
        if (hchild == NULL) {
            printf("main: round %lu: CreateThread failed, error %lu\n",
                   round, GetLastError());
            return 1;
        }
        wait = WaitForSingleObject(hchild, INFINITE);
        if (wait != WAIT_OBJECT_0) {
            printf("main: round %lu: wait returned %lu\n", round, wait);
            return 1;
        }
        printf("main: round %lu: child finished\n", round);
        CloseHandle(hchild);
    }
    printf("respawn: ok\n");
    return 0;
}
