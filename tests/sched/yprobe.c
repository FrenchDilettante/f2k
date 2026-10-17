/*
 * yprobe - a throwaway diagnostic for sched's yield section (not a fixture).
 *
 * Why does a BELOW_NORMAL thread not run while its NORMAL creator sits in
 * Sleep(10)? Each trial creates a thread the way sched.c's start() does,
 * lets the creator sleep, and reports whether the thread ran before the
 * sleep, during it, and when (milliseconds from the sleep's start; negative
 * means before it), plus the priority the thread saw.
 *
 *   yprobe        pinned to CPU 0, as sched.exe is
 *   yprobe free   without SetProcessAffinityMask
 *
 * Build: cl /nologo /MT yprobe.c
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

static volatile LONG ran;
static LARGE_INTEGER ran_at;
static volatile int ran_prio;
static LARGE_INTEGER freq;

static DWORD WINAPI probe(LPVOID param)
{
    (void)param;
    QueryPerformanceCounter(&ran_at);
    ran_prio = GetThreadPriority(GetCurrentThread());
    ran = 1;
    return 0;
}

static double ms(LARGE_INTEGER a, LARGE_INTEGER b)
{
    return (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)freq.QuadPart;
}

#define SLEEP0 1      /* Sleep(0) before the timed sleep, as sched.c does */
#define SUSPENDED 2   /* CREATE_SUSPENDED, set the priority, then ResumeThread */
#define NORMALPRIO 4  /* leave the thread at NORMAL (the control) */
#define WAITHANDLE 8  /* WaitForSingleObject(thread, d) instead of Sleep(d) */
#define IDLEPRIO 16   /* THREAD_PRIORITY_IDLE instead of BELOW_NORMAL */

static void trial(const char *name, int flags, DWORD d)
{
    HANDLE h;
    LARGE_INTEGER t0, t1;
    int before, during, prio;

    prio = (flags & NORMALPRIO) ? THREAD_PRIORITY_NORMAL
         : (flags & IDLEPRIO) ? THREAD_PRIORITY_IDLE
         : THREAD_PRIORITY_BELOW_NORMAL;
    ran = 0;
    ran_prio = 99;
    if (flags & SUSPENDED) {
        h = CreateThread(NULL, 0, probe, NULL, CREATE_SUSPENDED, NULL);
        SetThreadPriority(h, prio);
        ResumeThread(h);
    } else {
        h = CreateThread(NULL, 0, probe, NULL, 0, NULL);
        SetThreadPriority(h, prio);
    }
    if (flags & SLEEP0) {
        Sleep(0);
    }
    before = ran;
    QueryPerformanceCounter(&t0);
    if (flags & WAITHANDLE) {
        WaitForSingleObject(h, d);
    } else {
        Sleep(d);
    }
    QueryPerformanceCounter(&t1);
    during = ran;
    WaitForSingleObject(h, INFINITE);
    printf("%-22s d=%4lu  before=%d during=%d  slept %6.1f ms  ran at %+8.1f ms  prio %d\n",
           name, d, before, during, ms(t0, t1), ms(t0, ran_at), ran_prio);
    CloseHandle(h);
}

int main(int argc, char **argv)
{
    SYSTEM_INFO si;
    DWORD pmask, smask;
    int round;

    GetSystemInfo(&si);
    if (argc < 2 || strcmp(argv[1], "free") != 0) {
        if (!SetProcessAffinityMask(GetCurrentProcess(), 1)) {
            printf("SetProcessAffinityMask failed err=%lu\n", GetLastError());
        }
    }
    GetProcessAffinityMask(GetCurrentProcess(), &pmask, &smask);
    printf("processors %lu, process affinity 0x%lx, system affinity 0x%lx\n",
           si.dwNumberOfProcessors, (unsigned long)pmask, (unsigned long)smask);
    QueryPerformanceFrequency(&freq);

    /* sched.c's main runs HIGHEST, and the yield section drops it to NORMAL. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    for (round = 1; round <= 3; round++) {
        printf("-- round %d\n", round);
        trial("sched sequence", SLEEP0, 10);
        trial("sched sequence", SLEEP0, 20);
        trial("sched sequence", SLEEP0, 50);
        trial("sched sequence", SLEEP0, 200);
        trial("no Sleep(0)", 0, 10);
        trial("suspended+resume", SLEEP0 | SUSPENDED, 10);
        trial("wait on the thread", SLEEP0 | WAITHANDLE, 10);
        trial("idle priority", SLEEP0 | IDLEPRIO, 10);
        trial("normal (control)", NORMALPRIO, 10);
    }
    return 0;
}
