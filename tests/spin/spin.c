/*
 * spin - preemption baseline.
 *
 * Three threads run identical counted work, printing a progress
 * line every chunk. Two spinners start at normal priority and,
 * with round-robin quantum end, advance in alternation without
 * any explicit handoff - the interleaved progress lines show it.
 * The third is then created and raised above normal priority:
 * once ready it runs to completion before the spinners make
 * further progress, a higher-priority arrival preempting running
 * threads. The checksum in each done line proves the work loop
 * actually ran to the end.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo spin.c
 */

#include <windows.h>
#include <stdio.h>

#define CHUNKS 10
#define CHUNK_LOOPS 5000000UL

static DWORD WINAPI spinner(LPVOID param)
{
    char id;
    DWORD i;
    DWORD sum;

    id = *(char *)param;
    sum = 0;
    for (i = 0; i < CHUNKS * CHUNK_LOOPS; i++) {
        sum += i;
        if ((i % CHUNK_LOOPS) == (CHUNK_LOOPS - 1)) {
            printf("%c %lu\n", id, i + 1);
        }
    }
    printf("%c done, checksum %lu\n", id, sum);
    return 0;
}

int main(void)
{
    static char id_a = 'A';
    static char id_b = 'B';
    static char id_c = 'C';
    HANDLE ha, hb, hc;

    ha = CreateThread(NULL, 0, spinner, (LPVOID)&id_a, 0, NULL);
    hb = CreateThread(NULL, 0, spinner, (LPVOID)&id_b, 0, NULL);
    if (ha == NULL || hb == NULL) {
        printf("main: CreateThread failed, error %lu\n", GetLastError());
        return 1;
    }
    printf("main: spinners started\n");
    Sleep(100);
    printf("main: starting high-priority thread\n");
    hc = CreateThread(NULL, 0, spinner, (LPVOID)&id_c, 0, NULL);
    if (hc == NULL) {
        printf("main: CreateThread failed, error %lu\n", GetLastError());
        return 1;
    }
    if (!SetThreadPriority(hc, THREAD_PRIORITY_ABOVE_NORMAL)) {
        printf("main: SetThreadPriority failed, error %lu\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(ha, INFINITE);
    WaitForSingleObject(hb, INFINITE);
    WaitForSingleObject(hc, INFINITE);
    printf("main: all threads finished\n");
    CloseHandle(ha);
    CloseHandle(hb);
    CloseHandle(hc);
    printf("spin: ok\n");
    return 0;
}
