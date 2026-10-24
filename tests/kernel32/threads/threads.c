/*
 * threads - thread lifecycle and per-thread state.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create     CreateThread: the parameter and the return value, the
 *              thread id against GetCurrentThreadId, STILL_ACTIVE while
 *              running, the pseudo-handles, a NULL lpThreadId, a real
 *              handle to the current thread through DuplicateHandle
 *   exit       ExitThread, TerminateThread of a blocked thread, exit
 *              codes after each, a handle closed before its thread ends
 *              (the thread runs on), GetExitCodeThread on a bad handle
 *   suspend    CREATE_SUSPENDED, nested suspend counts, ResumeThread
 *              of a running thread, the suspend-count limit, a thread
 *              suspending itself, suspension during a timed wait and
 *              during a signal, suspending an exited thread
 *   priority   Get/SetThreadPriority at every level, invalid levels,
 *              priority classes, priority boost settings, priority of
 *              an exited thread
 *   scale      32 sequential create/wait/close rounds, 20 threads alive
 *              at once, 100 fire-and-forget threads, 200 events created
 *              and closed, 100 handles alive at once
 *   tls        TlsAlloc/TlsGetValue/TlsSetValue isolation, slot
 *              exhaustion, __declspec(thread) variables (the image's
 *              TLS directory) with their initializers in a new thread
 *   perthread  last error, errno, the FPU control word and structured
 *              exception handling, each per thread
 *   crt        _beginthreadex (suspended, with _endthreadex) and
 *              _beginthread
 *
 * Named-only sections (they end the process):
 *
 *   mainexit   the main thread calls ExitThread while a child runs: the
 *              process lives on and exits with the last thread's code
 *   procexit   a child calls ExitProcess while the main thread waits
 *
 * Build (real Windows 2000 machine, MSVC 6), the multithreaded CRT:
 *   cl /nologo /MT threads.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <float.h>
#include <process.h>

/* --- helpers ------------------------------------------------------- */

static HANDLE start(LPTHREAD_START_ROUTINE fn, void *param, DWORD flags, DWORD *tid)
{
    HANDLE h = CreateThread(NULL, 0, fn, param, flags, tid);

    if (h == NULL) {
        line("CreateThread failed err=%lu", GetLastError());
    }
    return h;
}

static DWORD join(HANDLE h)
{
    DWORD w = WaitForSingleObject(h, WAIT_MS);

    if (w != WAIT_OBJECT_0) {
        line("join: wait %s", wr(w));
    }
    return w;
}

static DWORD exit_code(HANDLE h)
{
    DWORD code = 0xDEADDEAD;

    GetExitCodeThread(h, &code);
    return code;
}

/* --- create -------------------------------------------------------- */

static volatile DWORD child_tid;
static HANDLE gate;

static DWORD WINAPI doubler(LPVOID param)
{
    child_tid = GetCurrentThreadId();
    return (DWORD)param * 2;
}

static DWORD WINAPI gated(LPVOID param)
{
    WaitForSingleObject(gate, WAIT_MS);
    return (DWORD)param;
}

static void sec_create(void)
{
    HANDLE h, h2, self;
    DWORD tid, tid2;
    BOOL r;

    h = start(doubler, (void *)21, 0, &tid);
    join(h);
    line("child returned its parameter doubled: exit code %lu", exit_code(h));
    line("lpThreadId matches the child's GetCurrentThreadId: %s, nonzero %s",
         yesno(tid == child_tid), yesno(tid != 0));
    line("child id differs from main's: %s", yesno(tid != GetCurrentThreadId()));
    CloseHandle(h);

    gate = CreateEvent(NULL, TRUE, FALSE, NULL);
    h = start(gated, (void *)5, 0, &tid);
    h2 = start(gated, (void *)6, 0, &tid2);
    line("two live children have distinct ids: %s", yesno(tid != tid2));
    line("exit code while running: %lu (STILL_ACTIVE is 259)", exit_code(h));
    SetEvent(gate);
    join(h);
    join(h2);
    line("exit codes after the gate opened: %lu %lu", exit_code(h), exit_code(h2));
    CloseHandle(h);
    CloseHandle(h2);
    CloseHandle(gate);

    h = CreateThread(NULL, 0, doubler, (void *)1, 0, NULL);
    line("CreateThread with a NULL lpThreadId: handle %s", yesno(h != NULL));
    if (h != NULL) {
        join(h);
        CloseHandle(h);
    }

    line("GetCurrentThread: 0x%08lX, GetCurrentProcess: 0x%08lX",
         (DWORD)GetCurrentThread(), (DWORD)GetCurrentProcess());
    arm();
    r = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &self, 0, FALSE,
                        DUPLICATE_SAME_ACCESS);
    line("DuplicateHandle(current thread): ret=%d err=%s, a real handle %s",
         r, le(), yesno(r && self != GetCurrentThread()));
    if (r) {
        line("waiting on the own thread handle times out: %s", wr(WaitForSingleObject(self, 0)));
        line("its exit code: %lu", exit_code(self));
        CloseHandle(self);
    }
}

/* --- exit ---------------------------------------------------------- */

static HANDLE ran_event;

static DWORD WINAPI exit_thread_77(LPVOID param)
{
    (void)param;
    ExitThread(77);
    return 1;
}

static DWORD WINAPI block_forever(LPVOID param)
{
    (void)param;
    WaitForSingleObject(gate, INFINITE);
    return 1;
}

static DWORD WINAPI late_signal(LPVOID param)
{
    (void)param;
    Sleep(200);
    SetEvent(ran_event);
    return 3;
}

static void sec_exit(void)
{
    HANDLE h;
    DWORD code;
    const char *e;
    BOOL r;

    h = start(exit_thread_77, NULL, 0, NULL);
    join(h);
    line("ExitThread(77): exit code %lu", exit_code(h));
    CloseHandle(h);

    gate = CreateEvent(NULL, TRUE, FALSE, NULL);
    h = start(block_forever, NULL, 0, NULL);
    Sleep(50);
    arm();
    r = TerminateThread(h, 88);
    line("TerminateThread of a blocked thread: ret=%d err=%s", r, le());
    line("its handle is signaled: %s", wr(WaitForSingleObject(h, WAIT_MS)));
    line("exit code %lu", exit_code(h));
    arm();
    r = TerminateThread(h, 99);
    e = le();
    line("TerminateThread again: ret=%d err=%s, exit code %lu", r, e, exit_code(h));
    CloseHandle(h);
    CloseHandle(gate);

    ran_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    h = start(late_signal, NULL, 0, NULL);
    arm();
    r = CloseHandle(h);
    line("close a running thread's handle: ret=%d err=%s", r, le());
    line("the thread ran on and signaled: %s", wr(WaitForSingleObject(ran_event, WAIT_MS)));
    CloseHandle(ran_event);

    code = 0;
    arm();
    r = GetExitCodeThread((HANDLE)0x1234, &code);
    line("GetExitCodeThread(bogus): ret=%d err=%s", r, le());
}

/* --- suspend ------------------------------------------------------- */

static volatile DWORD progress;
static volatile DWORD stop;
static volatile DWORD wait_result;
static HANDLE wait_event;

static DWORD WINAPI counter(LPVOID param)
{
    (void)param;
    while (!stop) {
        progress++;
    }
    return 0;
}

static DWORD WINAPI self_suspender(LPVOID param)
{
    (void)param;
    progress = 1;
    SuspendThread(GetCurrentThread());
    progress = 2;
    return 0;
}

static DWORD WINAPI timed_waiter(LPVOID param)
{
    wait_result = WaitForSingleObject(wait_event, (DWORD)param);
    return 0;
}

static void sec_suspend(void)
{
    HANDLE h;
    DWORD r1, r2, r3, r4;
    DWORD before, after;
    int i, limit;

    progress = 0;
    stop = 0;
    h = start(counter, NULL, CREATE_SUSPENDED, NULL);
    Sleep(100);
    line("CREATE_SUSPENDED: no progress before resume %s", yesno(progress == 0));
    r1 = ResumeThread(h);
    Sleep(50);
    line("ResumeThread returned %lu, progress after %s", r1, yesno(progress != 0));

    r1 = SuspendThread(h);
    r2 = SuspendThread(h);
    before = progress;
    Sleep(100);
    after = progress;
    r3 = ResumeThread(h);
    r4 = ResumeThread(h);
    line("suspend, suspend, resume, resume returned %lu %lu %lu %lu", r1, r2, r3, r4);
    line("suspended thread made no progress: %s", yesno(before == after));
    arm();
    r1 = ResumeThread(h);
    line("ResumeThread of a running thread: %lu err=%s", r1, le());

    limit = 0;
    for (i = 0; i < 200; i++) {
        arm();
        r1 = SuspendThread(h);
        if (r1 == (DWORD)-1) {
            line("suspend-count limit: refused after %d suspensions err=%s", limit, le());
            break;
        }
        limit++;
    }
    if (i == 200) {
        line("suspend-count limit: not reached after 200 suspensions");
    }
    for (i = 0; i < limit; i++) {
        ResumeThread(h);
    }
    before = progress;
    Sleep(50);
    line("running again after resuming every suspension: %s", yesno(progress != before));
    stop = 1;
    join(h);
    arm();
    r1 = SuspendThread(h);
    line("SuspendThread of an exited thread: %ld err=%s", (LONG)r1, le());
    arm();
    r1 = ResumeThread(h);
    line("ResumeThread of an exited thread: %ld err=%s", (LONG)r1, le());
    CloseHandle(h);

    progress = 0;
    h = start(self_suspender, NULL, 0, NULL);
    Sleep(100);
    line("thread suspended itself: progress %lu", progress);
    r1 = ResumeThread(h);
    join(h);
    line("resumed by main (returned %lu): progress %lu", r1, progress);
    CloseHandle(h);

    /* Suspended during a timed wait that expires while suspended. */
    wait_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    wait_result = 0xFFFF;
    h = start(timed_waiter, (void *)300, 0, NULL);
    Sleep(50);
    SuspendThread(h);
    Sleep(600);
    line("timed wait expired while suspended: still pending %s", yesno(wait_result == 0xFFFF));
    ResumeThread(h);
    join(h);
    line("after resume the wait returned %s", wr(wait_result));
    CloseHandle(h);

    /* Signaled while suspended in the wait. */
    wait_result = 0xFFFF;
    h = start(timed_waiter, (void *)WAIT_MS, 0, NULL);
    Sleep(50);
    SuspendThread(h);
    SetEvent(wait_event);
    Sleep(100);
    line("signaled while suspended: still pending %s", yesno(wait_result == 0xFFFF));
    ResumeThread(h);
    join(h);
    line("after resume the wait returned %s", wr(wait_result));
    line("the auto-reset signal was consumed by it: %s", wr(WaitForSingleObject(wait_event, 0)));
    CloseHandle(h);
    CloseHandle(wait_event);
}

/* --- priority ------------------------------------------------------ */

static void sec_priority(void)
{
    static const int levels[] = {
        THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
        THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST,
        THREAD_PRIORITY_TIME_CRITICAL
    };
    static const int invalid[] = { 3, -3, 16, -16, 7 };
    HANDLE h, me = GetCurrentThread();
    BOOL r, boost;
    char buf[256];
    int i, len;

    line("initial priority: %d", GetThreadPriority(me));
    len = 0;
    for (i = 0; i < 7; i++) {
        r = SetThreadPriority(me, levels[i]);
        len += sprintf(buf + len, " %d->%d/%d", levels[i], r, GetThreadPriority(me));
    }
    line("set/get round trips:%s", buf);
    len = 0;
    for (i = 0; i < 5; i++) {
        arm();
        r = SetThreadPriority(me, invalid[i]);
        len += sprintf(buf + len, " %d->%d/%s", invalid[i], r, le());
    }
    line("invalid levels:%s", buf);
    SetThreadPriority(me, THREAD_PRIORITY_NORMAL);

    line("GetPriorityClass: 0x%lX", GetPriorityClass(GetCurrentProcess()));
    arm();
    r = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    line("SetPriorityClass(high): ret=%d err=%s, class now 0x%lX, thread priority %d",
         r, le(), GetPriorityClass(GetCurrentProcess()), GetThreadPriority(me));
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    arm();
    r = SetPriorityClass(GetCurrentProcess(), 0x12345);
    line("SetPriorityClass(bogus): ret=%d err=%s", r, le());

    boost = 7;
    r = GetThreadPriorityBoost(me, &boost);
    line("GetThreadPriorityBoost: ret=%d disabled %d", r, boost);
    SetThreadPriorityBoost(me, TRUE);
    GetThreadPriorityBoost(me, &boost);
    line("after disabling: disabled %d", boost);
    SetThreadPriorityBoost(me, FALSE);

    h = start(doubler, (void *)1, 0, NULL);
    join(h);
    arm();
    r = SetThreadPriority(h, THREAD_PRIORITY_HIGHEST);
    line("SetThreadPriority of an exited thread: ret=%d err=%s", r, le());
    CloseHandle(h);
}

/* --- scale --------------------------------------------------------- */

static volatile LONG finished;
static HANDLE go;

static DWORD WINAPI count_one(LPVOID param)
{
    (void)param;
    InterlockedIncrement((LPLONG)&finished);
    return 0;
}

static DWORD WINAPI wait_then_count(LPVOID param)
{
    *(DWORD *)param = GetCurrentThreadId();
    WaitForSingleObject(go, WAIT_MS);
    InterlockedIncrement((LPLONG)&finished);
    return 0;
}

static void sec_scale(void)
{
    HANDLE hs[100];
    DWORD ids[20];
    DWORD t0;
    int i, j, ok, distinct, created;

    ok = 1;
    for (i = 0; i < 32; i++) {
        HANDLE h = CreateThread(NULL, 0, doubler, (void *)i, 0, NULL);

        if (h == NULL) {
            ok = 0;
            line("sequential round %d: CreateThread failed err=%lu", i, GetLastError());
            break;
        }
        ok &= WaitForSingleObject(h, WAIT_MS) == WAIT_OBJECT_0 && exit_code(h) == (DWORD)i * 2;
        CloseHandle(h);
    }
    line("32 sequential create/wait/close rounds: %s", ok ? "ok" : "failed");

    finished = 0;
    go = CreateEvent(NULL, TRUE, FALSE, NULL);
    created = 0;
    for (i = 0; i < 20; i++) {
        ids[i] = 0;
        hs[i] = CreateThread(NULL, 0, wait_then_count, &ids[i], 0, NULL);
        created += hs[i] != NULL;
    }
    Sleep(200);
    distinct = 1;
    for (i = 0; i < 20; i++) {
        for (j = i + 1; j < 20; j++) {
            distinct &= ids[i] != ids[j];
        }
    }
    line("20 threads alive at once: created %d, distinct ids %s, none finished early %s",
         created, yesno(distinct), yesno(finished == 0));
    SetEvent(go);
    for (i = 0; i < 20; i++) {
        if (hs[i] != NULL) {
            join(hs[i]);
            CloseHandle(hs[i]);
        }
    }
    line("all 20 released and finished: %ld", finished);
    CloseHandle(go);

    finished = 0;
    created = 0;
    for (i = 0; i < 100; i++) {
        HANDLE h = CreateThread(NULL, 0, count_one, NULL, 0, NULL);

        if (h != NULL) {
            created++;
            CloseHandle(h);
        }
    }
    t0 = GetTickCount();
    while (finished < created && GetTickCount() - t0 < WAIT_MS) {
        Sleep(10);
    }
    line("100 fire-and-forget threads: created %d, finished %ld", created, finished);

    ok = 1;
    for (i = 0; i < 200; i++) {
        HANDLE e = CreateEvent(NULL, FALSE, FALSE, NULL);

        ok &= e != NULL && CloseHandle(e);
    }
    line("200 events created and closed one at a time: %s", ok ? "ok" : "failed");

    created = 0;
    ok = 1;
    for (i = 0; i < 100; i++) {
        hs[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (hs[i] != NULL) {
            created++;
            ok &= ((DWORD)hs[i] & 3) == 0;
        }
    }
    distinct = 1;
    for (i = 0; i < 100; i++) {
        for (j = i + 1; j < 100; j++) {
            distinct &= hs[i] == NULL || hs[i] != hs[j];
        }
    }
    line("100 events alive at once: created %d, distinct %s, multiples of 4 %s", created, yesno(distinct), yesno(ok));
    for (i = 0; i < 100; i++) {
        if (hs[i] != NULL) {
            CloseHandle(hs[i]);
        }
    }
}

/* --- tls ----------------------------------------------------------- */

static DWORD tls_index;
static volatile LPVOID child_initial;
static volatile DWORD child_initial_err;
static volatile LPVOID child_after;

static __declspec(thread) int tls_counter = 42;
static __declspec(thread) char tls_text[16] = "initial";
static volatile int child_tls_counter;
static char child_tls_text[16];

static DWORD WINAPI tls_child(LPVOID param)
{
    (void)param;
    SetLastError(12345);
    child_initial = TlsGetValue(tls_index);
    child_initial_err = GetLastError();
    TlsSetValue(tls_index, (LPVOID)0x2222);
    child_after = TlsGetValue(tls_index);

    child_tls_counter = tls_counter;
    strcpy(child_tls_text, tls_text);
    tls_counter = 7;
    strcpy(tls_text, "child");
    return 0;
}

static void sec_tls(void)
{
    static DWORD slots[2000];
    HANDLE h;
    LPVOID v;
    BOOL r;
    DWORD i, count, err;

    arm();
    tls_index = TlsAlloc();
    line("TlsAlloc: valid %s err=%s", yesno(tls_index != TLS_OUT_OF_INDEXES), le());
    arm();
    v = TlsGetValue(tls_index);
    line("fresh slot reads NULL: %s err=%s", yesno(v == NULL), le());
    TlsSetValue(tls_index, (LPVOID)0x1111);

    tls_counter = 5;
    strcpy(tls_text, "main");
    h = start(tls_child, NULL, 0, NULL);
    join(h);
    CloseHandle(h);
    line("child: slot started NULL %s with last error %s, kept its own value %s",
         yesno(child_initial == NULL), le_of(child_initial_err), yesno(child_after == (LPVOID)0x2222));
    line("main: slot unchanged by the child %s", yesno(TlsGetValue(tls_index) == (LPVOID)0x1111));
    line("__declspec(thread) in the child started at the initializers: %d [%s]",
         child_tls_counter, child_tls_text);
    line("__declspec(thread) in main untouched by the child: %d [%s]", tls_counter, tls_text);

    arm();
    r = TlsFree(tls_index);
    line("TlsFree: ret=%d err=%s", r, le());

    count = 0;
    for (i = 0; i < 2000; i++) {
        slots[i] = TlsAlloc();
        if (slots[i] == TLS_OUT_OF_INDEXES) {
            break;
        }
        count++;
    }
    err = GetLastError();
    line("TlsAlloc until exhaustion: %lu slots, then err=%lu", count, err);
    for (i = 0; i < count; i++) {
        TlsFree(slots[i]);
    }
    arm();
    i = TlsAlloc();
    line("TlsAlloc after freeing them: valid %s err=%s", yesno(i != TLS_OUT_OF_INDEXES), le());
    TlsFree(i);
}

/* --- perthread ----------------------------------------------------- */

typedef struct {
    DWORD last_error;
    int err_no;
    unsigned fpu;
    DWORD seh_code;
} thread_state;

static DWORD WINAPI state_child(LPVOID param)
{
    thread_state *s = (thread_state *)param;

    SetLastError(222);
    errno = 0;
    strtol("99999999999", NULL, 10);
    s->err_no = errno;
    s->fpu = _controlfp(0, 0);
    _controlfp(_RC_UP, _MCW_RC);
    s->seh_code = 0;
    __try {
        *(volatile int *)0 = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s->seh_code = GetExceptionCode();
    }
    s->last_error = GetLastError();
    return 0;
}

static void sec_perthread(void)
{
    thread_state s;
    unsigned main_fpu;
    HANDLE h;

    SetLastError(111);
    errno = 0;
    _controlfp(_RC_CHOP, _MCW_RC);
    main_fpu = _controlfp(0, 0);
    h = start(state_child, &s, 0, NULL);
    join(h);
    CloseHandle(h);

    line("last error: main %lu, child %lu", GetLastError(), s.last_error);
    line("errno: main %d, child %d", errno, s.err_no);
    line("FPU control word: child started with 0x%08X (not main's 0x%08X: %s)",
         s.fpu, main_fpu, yesno(s.fpu != main_fpu));
    line("main's rounding mode unchanged by the child: %s", yesno(_controlfp(0, 0) == main_fpu));
    line("child caught its own access violation: 0x%08lX", s.seh_code);
    _controlfp(_RC_NEAR, _MCW_RC);
}

/* --- crt ----------------------------------------------------------- */

static volatile DWORD beginthread_ran;

static unsigned __stdcall ex_child(void *param)
{
    (void)param;
    _endthreadex(55);
    return 1;
}

static void __cdecl plain_child(void *param)
{
    beginthread_ran = (DWORD)param;
    SetEvent(ran_event);
}

static void sec_crt(void)
{
    unsigned tid;
    unsigned long h;
    DWORD r;

    h = _beginthreadex(NULL, 0, ex_child, NULL, CREATE_SUSPENDED, &tid);
    line("_beginthreadex(suspended): handle %s, id nonzero %s", yesno(h != 0), yesno(tid != 0));
    if (h != 0) {
        r = ResumeThread((HANDLE)h);
        join((HANDLE)h);
        line("resumed (returned %lu), _endthreadex(55): exit code %lu", r, exit_code((HANDLE)h));
        CloseHandle((HANDLE)h);
    }

    ran_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    beginthread_ran = 0;
    h = _beginthread(plain_child, 0, (void *)9);
    line("_beginthread: handle %s", yesno(h != (unsigned long)-1));
    r = WaitForSingleObject(ran_event, WAIT_MS);
    line("its routine ran: %s, parameter %lu", wr(r), beginthread_ran);
    CloseHandle(ran_event);
}

/* --- mainexit, procexit (named only) ------------------------------- */

static DWORD WINAPI outlive_main(LPVOID param)
{
    (void)param;
    Sleep(300);
    line("child: still running after main's ExitThread");
    return 9;
}

static void sec_mainexit(void)
{
    HANDLE h = start(outlive_main, NULL, 0, NULL);

    CloseHandle(h);
    line("main: ExitThread(5) with a child running");
    ExitThread(5);
}

static DWORD WINAPI exit_process_child(LPVOID param)
{
    (void)param;
    Sleep(100);
    line("child: ExitProcess(3)");
    ExitProcess(3);
    return 1;
}

static void sec_procexit(void)
{
    HANDLE h = start(exit_process_child, NULL, 0, NULL);

    line("main: waiting on the child");
    WaitForSingleObject(h, INFINITE);
    line("main: survived the child's ExitProcess");
}

static const section_t sections[] = {
    { "create", sec_create, 0 },
    { "exit", sec_exit, 0 },
    { "suspend", sec_suspend, 0 },
    { "priority", sec_priority, 0 },
    { "scale", sec_scale, 0 },
    { "tls", sec_tls, 0 },
    { "perthread", sec_perthread, 0 },
    { "crt", sec_crt, 0 },
    { "mainexit", sec_mainexit, 1 },
    { "procexit", sec_procexit, 1 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("threads", sections, argc, argv);
}
