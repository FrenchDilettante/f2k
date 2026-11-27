/*
 * manythrd - many threads alive at once in one process.
 *
 * Linked with a 64 KiB stack reservation (/STACK:0x10000,0x1000), which
 * every thread CreateThread makes with a stack size of 0 takes: 2,000
 * threads' stacks then reserve 125 MiB of the 2 GiB address space, where
 * the default 1 MiB would take all of it. Thread ids are
 * machine-specific: only their relations print.
 *
 * Sections:
 *
 *   alive  2,000 threads, each counting itself in and then waiting on
 *          one event: how many were made, and how many were running
 *          together; their ids as relations (multiples of 4, distinct,
 *          none of them this thread's); then the event set, and how many
 *          ended and with their exit code (each its own index); and
 *          OpenThread (through GetProcAddress: MSVC 6's headers lack it)
 *          by the first one's id once it has ended and its handle is
 *          closed. A creation that fails ends the creating there, its
 *          error printed: the counts then show how far the machine went.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat manythrd):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% manythrd.c /link /STACK:0x10000,0x1000
 */

#include "../common/f2kt.h"
#include <stdlib.h>

/* How many threads alive at once: past F2K's old 128 and 1,024 caps, and
 * its 455 kernel stacks. */
#define THREADS 2000

/* The longest wait for the threads to start, or for one to end. */
#define THREAD_MS 60000

typedef HANDLE (WINAPI *open_thread_fn)(DWORD, BOOL, DWORD);

static HANDLE go;
static LONG running;
static HANDLE handles[THREADS];
static DWORD tids[THREADS];
static DWORD sorted[THREADS + 1];

static DWORD WINAPI holder(LPVOID arg)
{
    InterlockedIncrement(&running);
    WaitForSingleObject(go, 2 * THREAD_MS);
    return (DWORD)arg;
}

static int by_value(const void *a, const void *b)
{
    DWORD x = *(const DWORD *)a;
    DWORD y = *(const DWORD *)b;

    return x < y ? -1 : x > y;
}

/* Whether the n values are distinct (sorts them). */
static int distinct(DWORD *v, int n)
{
    int i;

    qsort(v, n, sizeof *v, by_value);
    for (i = 1; i < n; i++) {
        if (v[i] == v[i - 1]) {
            return 0;
        }
    }
    return 1;
}

static void sec_alive(void)
{
    open_thread_fn open_thread;
    HANDLE h;
    int made = 0;
    int ended = 0;
    int coded = 0;
    int by4 = 1;
    int i;
    DWORD waited;
    DWORD code;

    go = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (go == NULL) {
        line("the event: not made err=%s", le());
        return;
    }
    for (i = 0; i < THREADS; i++) {
        arm();
        handles[i] = CreateThread(NULL, 0, holder, (LPVOID)i, 0, &tids[i]);
        if (handles[i] == NULL) {
            line("CreateThread, thread %d: failed err=%s", i + 1, le());
            break;
        }
        made++;
    }
    line("threads made: %d of %d", made, THREADS);

    for (waited = 0; running < made && waited < THREAD_MS; waited += 10) {
        Sleep(10);
    }
    line("running together, each waiting on the event: %ld", running);

    for (i = 0; i < made; i++) {
        by4 &= (tids[i] & 3) == 0 && tids[i] != 0;
        sorted[i] = tids[i];
    }
    sorted[made] = GetCurrentThreadId();
    line("their ids: multiples of 4 %s, distinct and none this thread's %s", yesno(by4),
        yesno(distinct(sorted, made + 1)));

    SetEvent(go);
    for (i = 0; i < made; i++) {
        if (WaitForSingleObject(handles[i], THREAD_MS) == WAIT_OBJECT_0) {
            ended++;
        }
        if (GetExitCodeThread(handles[i], &code) && code == (DWORD)i) {
            coded++;
        }
        CloseHandle(handles[i]);
    }
    line("the event set: ended %d, with their own exit code %d", ended, coded);
    CloseHandle(go);

    open_thread = (open_thread_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenThread");
    if (open_thread == NULL || made == 0) {
        line("OpenThread: exported %s, threads made %d", yesno(open_thread != NULL), made);
        return;
    }
    arm();
    h = open_thread(THREAD_QUERY_INFORMATION, FALSE, tids[0]);
    line("OpenThread by the first one's id, ended and its handle closed: a handle %s err=%s", yesno(h != NULL),
        le());
    if (h != NULL) {
        CloseHandle(h);
    }
}

static const section_t sections[] = {
    { "alive", sec_alive, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("manythrd", sections, argc, argv);
}
