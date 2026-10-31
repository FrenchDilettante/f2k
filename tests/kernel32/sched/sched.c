/*
 * sched - time and scheduling, as verdicts.
 *
 * Timing is machine-dependent, so nothing here prints a raw duration or
 * count: every timing-shaped fact is a verdict against a band wide
 * enough for the real machine and F2K alike. The process pins itself to
 * one CPU first (SetProcessAffinityMask), so the scheduling verdicts
 * mean the same on a multiprocessor capture machine as on F2K.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   sleep    Sleep(200), Sleep(0), Sleep(1), ten Sleep(10)s, SleepEx,
 *            and a timed wait on a never-signaled event, each in a band
 *   clock    GetTickCount monotonic with a coarse step, the performance
 *            counter, GetSystemTimeAsFileTime and GetSystemTime /
 *            GetLocalTime, the CRT's time() and clock()
 *   timer    waitable timers: relative and absolute due times, periodic,
 *            manual and auto-reset, cancel, a completion APC, named
 *   rr       two equal-priority spinners alternate by quantum end
 *   preempt  a higher-priority arrival runs to completion while two
 *            spinners are frozen
 *   yield    a new thread does not preempt its equal-priority creator;
 *            Sleep(0) and SwitchToThread hand it the CPU; a lower-priority
 *            one runs during a Sleep(10) started just after a clock tick,
 *            not during a Sleep(0)
 *   boost    the order between an event's setter and its woken waiter
 *   freeze   a suspended spinner makes no progress; a suspended sleeper
 *            wakes only after it is resumed
 *   starve   an idle-priority thread starved by a normal-priority
 *            spinner still runs within a few seconds (the balance-set
 *            boost); takes about six seconds
 *
 * The named timers run twice: through the A calls, then through their W
 * twins on the same name (the W lines carry the W names, or "(W)").
 *
 * Build (real Windows 2000 machine, MSVC 6), the multithreaded CRT:
 *   cl /nologo /MT sched.c
 */

#include "../common/f2kt.h"
#include <time.h>

static HANDLE start(LPTHREAD_START_ROUTINE fn, void *param, int priority, DWORD flags)
{
    HANDLE h = CreateThread(NULL, 0, fn, param, flags, NULL);

    if (h == NULL) {
        line("CreateThread failed err=%lu", GetLastError());
        return NULL;
    }
    SetThreadPriority(h, priority);
    return h;
}

static void join(HANDLE h)
{
    DWORD w = WaitForSingleObject(h, 30000);

    if (w != WAIT_OBJECT_0) {
        line("join: wait %s", wr(w));
    }
    CloseHandle(h);
}

/* 100 ns FILETIME units between two FILETIMEs, in milliseconds. */
static DWORD ft_ms(const FILETIME *a, const FILETIME *b)
{
    ULARGE_INTEGER x, y;

    x.LowPart = a->dwLowDateTime;
    x.HighPart = a->dwHighDateTime;
    y.LowPart = b->dwLowDateTime;
    y.HighPart = b->dwHighDateTime;
    return (DWORD)((y.QuadPart - x.QuadPart) / 10000);
}

/* --- sleep --------------------------------------------------------- */

static void sec_sleep(void)
{
    HANDLE ev;
    DWORD t0, t1, r;
    int i;

    t0 = GetTickCount();
    Sleep(200);
    t1 = GetTickCount();
    line("Sleep(200) in [190, 300] ms: %s", band(t1 - t0, 190, 300));

    t0 = GetTickCount();
    Sleep(0);
    t1 = GetTickCount();
    line("Sleep(0) returns at once (< 20 ms): %s", yesno(t1 - t0 < 20));

    t0 = GetTickCount();
    Sleep(1);
    t1 = GetTickCount();
    line("Sleep(1) in [0, 40] ms: %s", band(t1 - t0, 0, 40));

    t0 = GetTickCount();
    for (i = 0; i < 10; i++) {
        Sleep(10);
    }
    t1 = GetTickCount();
    line("ten Sleep(10) in [90, 320] ms: %s", band(t1 - t0, 90, 320));

    t0 = GetTickCount();
    r = SleepEx(100, FALSE);
    t1 = GetTickCount();
    line("SleepEx(100, FALSE): returned %lu, in [90, 200] ms %s", r, band(t1 - t0, 90, 200));

    ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    t0 = GetTickCount();
    r = WaitForSingleObject(ev, 100);
    t1 = GetTickCount();
    line("timed wait of 100 ms on an unsignaled event: %s, in [90, 200] ms %s", wr(r), band(t1 - t0, 90, 200));
    t0 = GetTickCount();
    r = WaitForSingleObject(ev, 0);
    t1 = GetTickCount();
    line("zero-timeout wait: %s, immediate %s", wr(r), yesno(t1 - t0 < 20));
    CloseHandle(ev);
}

/* --- clock --------------------------------------------------------- */

static void sec_clock(void)
{
    LARGE_INTEGER freq, c0, c1;
    FILETIME f0, f1;
    SYSTEMTIME st, lt;
    DWORD t0, t1, prev, now, step, min_step, steps;
    int monotonic;
    clock_t k0, k1;
    time_t tt;
    BOOL r;

    monotonic = 1;
    min_step = 0xFFFFFFFF;
    steps = 0;
    prev = GetTickCount();
    t0 = prev;
    while (steps < 10 && GetTickCount() - t0 < 2000) {
        now = GetTickCount();
        if (now < prev) {
            monotonic = 0;
        }
        if (now != prev) {
            step = now - prev;
            if (step < min_step) {
                min_step = step;
            }
            steps++;
        }
        prev = now;
    }
    line("GetTickCount: monotonic %s, advances in steps of at most 16 ms %s", yesno(monotonic),
         yesno(steps == 10 && min_step <= 16));

    r = QueryPerformanceFrequency(&freq);
    line("QueryPerformanceFrequency: ret=%d nonzero %s", r, yesno(freq.QuadPart != 0));
    QueryPerformanceCounter(&c0);
    GetSystemTimeAsFileTime(&f0);
    k0 = clock();
    t0 = GetTickCount();
    Sleep(200);
    QueryPerformanceCounter(&c1);
    GetSystemTimeAsFileTime(&f1);
    k1 = clock();
    t1 = GetTickCount();
    if (freq.QuadPart != 0) {
        line("performance counter across Sleep(200) in [190, 300] ms: %s",
             band((DWORD)((c1.QuadPart - c0.QuadPart) * 1000 / freq.QuadPart), 190, 300));
    }
    line("system time across Sleep(200) in [150, 300] ms: %s", band(ft_ms(&f0, &f1), 150, 300));
    line("clock() across Sleep(200) in [150, 300] ms: %s",
         band((DWORD)((k1 - k0) * 1000 / CLOCKS_PER_SEC), 150, 300));
    line("tick count across Sleep(200) in [190, 300] ms: %s", band(t1 - t0, 190, 300));

    GetSystemTime(&st);
    GetLocalTime(&lt);
    line("GetSystemTime fields valid: %s", yesno(st.wYear >= 2000 && st.wMonth >= 1 && st.wMonth <= 12 &&
                                                 st.wDay >= 1 && st.wDay <= 31 && st.wHour < 24 &&
                                                 st.wMinute < 60 && st.wSecond < 60 && st.wMilliseconds < 1000 &&
                                                 st.wDayOfWeek < 7));
    line("GetLocalTime fields valid: %s", yesno(lt.wYear >= 2000 && lt.wMonth >= 1 && lt.wMonth <= 12 &&
                                                lt.wHour < 24 && lt.wDayOfWeek < 7));
    tt = time(NULL);
    line("time() after 2000-01-01: %s", yesno(tt > 946684800));
}

/* --- timer --------------------------------------------------------- */

static volatile DWORD timer_apc_arg;
static volatile DWORD timer_apc_count;

static VOID CALLBACK timer_apc(LPVOID arg, DWORD low, DWORD high)
{
    (void)low;
    (void)high;
    timer_apc_arg = (DWORD)arg;
    timer_apc_count++;
}

/* The named timers, through the A calls or (wide) their W twins. */
static void named_timers(int wide)
{
    const char *aw = wide ? "W" : "A";
    const char *tag = wide ? " (W)" : "";
    HANDLE n1, n2;
    LARGE_INTEGER due;

    n1 = wide ? CreateWaitableTimerW(NULL, TRUE, L"F2K.sched.timer")
              : CreateWaitableTimerA(NULL, TRUE, "F2K.sched.timer");
    SetLastError(F2KT_UNTOUCHED);
    n2 = wide ? CreateWaitableTimerW(NULL, TRUE, L"F2K.sched.timer")
              : CreateWaitableTimerA(NULL, TRUE, "F2K.sched.timer");
    line("named timer again%s: created %s err=%s", tag, yesno(n2 != NULL), le());
    due.QuadPart = -10 * 10000;
    SetWaitableTimer(n1, &due, 0, NULL, NULL, FALSE);
    line("set through one handle, waited through the other%s: %s", tag,
         wr(WaitForSingleObject(n2, WAIT_MS)));
    CloseHandle(n2);
    n2 = wide ? OpenWaitableTimerW(TIMER_ALL_ACCESS, FALSE, L"F2K.sched.timer")
              : OpenWaitableTimerA(TIMER_ALL_ACCESS, FALSE, "F2K.sched.timer");
    line("OpenWaitableTimer%s: opened %s, signaled %s", aw, yesno(n2 != NULL), wr(WaitForSingleObject(n2, 0)));
    CloseHandle(n2);
    CloseHandle(n1);
}

static void sec_timer(void)
{
    HANDLE t, a;
    LARGE_INTEGER due;
    FILETIME now;
    DWORD t0, t1, r;
    BOOL ok;
    int i;

    t = CreateWaitableTimer(NULL, TRUE, NULL);
    line("CreateWaitableTimer(manual): created %s, unsignaled %s", yesno(t != NULL), wr(WaitForSingleObject(t, 0)));
    due.QuadPart = -100 * 10000;
    t0 = GetTickCount();
    ok = SetWaitableTimer(t, &due, 0, NULL, NULL, FALSE);
    r = WaitForSingleObject(t, WAIT_MS);
    t1 = GetTickCount();
    line("relative 100 ms: set %d, wait %s, in [90, 200] ms %s", ok, wr(r), band(t1 - t0, 90, 200));
    line("manual timer stays signaled: %s", wr(WaitForSingleObject(t, 0)));

    GetSystemTimeAsFileTime(&now);
    due.LowPart = now.dwLowDateTime;
    due.HighPart = now.dwHighDateTime;
    due.QuadPart += 150 * 10000;
    t0 = GetTickCount();
    ok = SetWaitableTimer(t, &due, 0, NULL, NULL, FALSE);
    line("re-arming resets it: %s", wr(WaitForSingleObject(t, 0)));
    r = WaitForSingleObject(t, WAIT_MS);
    t1 = GetTickCount();
    line("absolute now+150 ms: set %d, wait %s, in [100, 260] ms %s", ok, wr(r), band(t1 - t0, 100, 260));

    a = CreateWaitableTimer(NULL, FALSE, NULL);
    due.QuadPart = -50 * 10000;
    t0 = GetTickCount();
    ok = SetWaitableTimer(a, &due, 50, NULL, NULL, FALSE);
    for (i = 0; i < 5; i++) {
        r = WaitForSingleObject(a, WAIT_MS);
        if (r != WAIT_OBJECT_0) {
            break;
        }
    }
    t1 = GetTickCount();
    line("periodic 50 ms, auto-reset: set %d, five periods %s, in [200, 400] ms %s", ok,
         yesno(i == 5), band(t1 - t0, 200, 400));
    line("auto-reset consumed by the wait: %s", wr(WaitForSingleObject(a, 0)));
    ok = CancelWaitableTimer(a);
    line("CancelWaitableTimer: ret=%d, then a 200 ms wait %s", ok, wr(WaitForSingleObject(a, 200)));

    timer_apc_arg = 0;
    timer_apc_count = 0;
    due.QuadPart = -50 * 10000;
    SetWaitableTimer(a, &due, 0, timer_apc, (LPVOID)7, FALSE);
    r = SleepEx(WAIT_MS, TRUE);
    line("completion routine: SleepEx returned %s, ran %lu time(s) with argument %lu", wr(r),
         timer_apc_count, timer_apc_arg);
    CloseHandle(a);
    CloseHandle(t);

    named_timers(0);
    named_timers(1);
}

/* --- rr, preempt --------------------------------------------------- */

static volatile LONG owner;
static volatile LONG switches;
static volatile DWORD progress[3];
static volatile DWORD stop_spinning;
static volatile DWORD c_frozen_ok;

static DWORD WINAPI spinner(LPVOID param)
{
    LONG me = (LONG)param;

    while (!stop_spinning) {
        if (owner != me) {
            owner = me;
            switches++;
        }
        progress[me]++;
    }
    return 0;
}

/* The high-priority arrival: spins 200 ms of tick time and checks that
 * A and B made no progress meanwhile. */
static DWORD WINAPI arrival(LPVOID param)
{
    DWORD a0 = progress[0];
    DWORD b0 = progress[1];
    DWORD t0 = GetTickCount();

    (void)param;
    while (GetTickCount() - t0 < 200) {
        progress[2]++;
    }
    c_frozen_ok = progress[0] == a0 && progress[1] == b0;
    return 0;
}

static void sec_rr(void)
{
    HANDLE a, b;
    DWORD t0;

    owner = -1;
    switches = 0;
    stop_spinning = 0;
    progress[0] = progress[1] = 0;
    a = start(spinner, (void *)0, THREAD_PRIORITY_NORMAL, 0);
    b = start(spinner, (void *)1, THREAD_PRIORITY_NORMAL, 0);
    t0 = GetTickCount();
    while (switches < 20 && GetTickCount() - t0 < 5000) {
        Sleep(50);
    }
    stop_spinning = 1;
    join(a);
    join(b);
    line("two equal spinners: alternated at least 20 times within 5 s %s, both progressed %s",
         yesno(switches >= 20), yesno(progress[0] != 0 && progress[1] != 0));
}

static void sec_preempt(void)
{
    HANDLE a, b, c;

    stop_spinning = 0;
    progress[0] = progress[1] = progress[2] = 0;
    c_frozen_ok = 0;
    a = start(spinner, (void *)0, THREAD_PRIORITY_NORMAL, 0);
    b = start(spinner, (void *)1, THREAD_PRIORITY_NORMAL, 0);
    Sleep(100);
    c = start(arrival, NULL, THREAD_PRIORITY_ABOVE_NORMAL, CREATE_SUSPENDED);
    ResumeThread(c);
    join(c);
    line("above-normal arrival ran while both spinners were frozen: %s", yesno(c_frozen_ok));
    stop_spinning = 1;
    join(a);
    join(b);
    line("spinners resumed afterwards: %s", yesno(progress[0] != 0 && progress[1] != 0));
}

/* --- yield, boost -------------------------------------------------- */

static volatile DWORD flag;
static volatile DWORD after_set;
static HANDLE boost_event;

static DWORD WINAPI set_flag(LPVOID param)
{
    flag = (DWORD)param;
    return 0;
}

static DWORD WINAPI setter(LPVOID param)
{
    (void)param;
    SetEvent(boost_event);
    after_set = 1;
    return 0;
}

static void sec_yield(void)
{
    HANDLE h;
    BOOL r;
    DWORD tick;

    /* Main at the same priority as the threads it hands the CPU to. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    flag = 0;
    h = start(set_flag, (void *)1, THREAD_PRIORITY_NORMAL, 0);
    line("a new equal-priority thread did not preempt its creator: %s", yesno(flag == 0));
    Sleep(0);
    line("after Sleep(0) it had run: %s", yesno(flag == 1));
    join(h);

    flag = 0;
    h = start(set_flag, (void *)2, THREAD_PRIORITY_NORMAL, 0);
    r = SwitchToThread();
    line("SwitchToThread: returned %d, the new thread had run %s", r != 0, yesno(flag == 2));
    join(h);

    flag = 0;
    h = start(set_flag, (void *)3, THREAD_PRIORITY_BELOW_NORMAL, 0);
    Sleep(0);
    line("Sleep(0) does not hand the CPU to a lower-priority thread: %s", yesno(flag == 0));
    /* A relative wait is due its interval past the interrupt time of the
     * last clock tick, so a Sleep(10) begun late in a tick ends at the next
     * one, which may come before the new thread has started. Begin it just
     * after a tick, spinning to the tick count's change (the spin hands
     * nothing to the lower-priority thread), so it lasts a whole tick. */
    tick = GetTickCount();
    while (GetTickCount() == tick) {
    }
    Sleep(10);
    line("Sleep(10) does: %s", yesno(flag == 3));
    join(h);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

static void sec_boost(void)
{
    HANDLE h;
    DWORD r;

    /* Main waits at the setter's priority: only the wake boost can let it
     * preempt the setter. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    boost_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    after_set = 0;
    h = start(setter, NULL, THREAD_PRIORITY_NORMAL, 0);
    r = WaitForSingleObject(boost_event, WAIT_MS);
    line("woken waiter ran before its setter continued past SetEvent: %s (wait %s)",
         yesno(after_set == 0), wr(r));
    join(h);
    CloseHandle(boost_event);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

/* --- freeze -------------------------------------------------------- */

static volatile DWORD slept_ms;

static DWORD WINAPI sleeper(LPVOID param)
{
    DWORD t0 = GetTickCount();

    (void)param;
    Sleep(100);
    slept_ms = GetTickCount() - t0;
    return 0;
}

static void sec_freeze(void)
{
    HANDLE h;
    DWORD c0, c1;

    stop_spinning = 0;
    progress[0] = 0;
    h = start(spinner, (void *)0, THREAD_PRIORITY_NORMAL, 0);
    Sleep(50);
    SuspendThread(h);
    c0 = progress[0];
    Sleep(100);
    c1 = progress[0];
    line("suspended spinner made no progress: %s", yesno(c0 == c1));
    ResumeThread(h);
    Sleep(50);
    line("resumed spinner progressed: %s", yesno(progress[0] != c1));
    stop_spinning = 1;
    join(h);

    slept_ms = 0;
    h = start(sleeper, NULL, THREAD_PRIORITY_NORMAL, 0);
    Sleep(20);
    SuspendThread(h);
    Sleep(300);
    line("sleeper's 100 ms Sleep had not returned while suspended: %s", yesno(slept_ms == 0));
    ResumeThread(h);
    join(h);
    line("it returned after the resume, at least 300 ms in: %s", yesno(slept_ms >= 300));
}

/* --- starve -------------------------------------------------------- */

static volatile DWORD starved_ran_at;

static DWORD WINAPI starved(LPVOID param)
{
    (void)param;
    starved_ran_at = GetTickCount();
    return 0;
}

static void sec_starve(void)
{
    HANDLE hog, low;
    DWORD t0;

    stop_spinning = 0;
    starved_ran_at = 0;
    hog = start(spinner, (void *)0, THREAD_PRIORITY_NORMAL, 0);
    t0 = GetTickCount();
    low = start(starved, NULL, THREAD_PRIORITY_IDLE, 0);
    Sleep(6000);
    stop_spinning = 1;
    join(hog);
    join(low);
    line("idle-priority thread starved by a spinner still ran: %s, within [1, 6] s %s",
         yesno(starved_ran_at != 0), starved_ran_at != 0 ? band(starved_ran_at - t0, 1000, 6000) : "no");
}

static const section_t sections[] = {
    { "sleep", sec_sleep, 0 },
    { "clock", sec_clock, 0 },
    { "timer", sec_timer, 0 },
    { "rr", sec_rr, 0 },
    { "preempt", sec_preempt, 0 },
    { "yield", sec_yield, 0 },
    { "boost", sec_boost, 0 },
    { "freeze", sec_freeze, 0 },
    { "starve", sec_starve, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    BOOL r;

    r = SetProcessAffinityMask(GetCurrentProcess(), 1);
    if (!r) {
        line("SetProcessAffinityMask failed err=%lu", GetLastError());
    }
    /* Above the spinners: main must get the CPU back whenever it wakes. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    return run_sections("sched", sections, argc, argv);
}
