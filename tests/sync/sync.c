/*
 * sync - synchronization objects and waits.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   event        manual and auto-reset events, initial states, Set/Reset,
 *                PulseEvent with no, one and two waiters, named events
 *                (ERROR_ALREADY_EXISTS, OpenEventA, a name taken by
 *                another object type), bad handles and wrong types
 *   semaphore    initial and maximum counts, ReleaseSemaphore's previous
 *                count, over-release, invalid creation, named semaphores
 *   mutex        recursive ownership, release by a non-owner, a mutex
 *                abandoned by its owner's exit, named mutexes
 *   waitmulti    WaitForMultipleObjects: wait-any picks the lowest
 *                signaled index, wait-all consumes nothing until every
 *                object is signaled, mixed objects, abandonment, 64
 *                objects and 65, an empty array, duplicates, bad handles;
 *                waits on the process and thread pseudo-handles
 *   apc          QueueUserAPC: delivery in alertable SleepEx and
 *                WaitForSingleObjectEx (WAIT_IO_COMPLETION), deferral
 *                through non-alertable waits, FIFO order, APCs to self
 *   critsec      critical sections: recursion and ownership fields,
 *                TryEnterCriticalSection, an exact total under
 *                contention from four threads
 *   interlocked  InterlockedIncrement/Decrement/Exchange/ExchangeAdd/
 *                CompareExchange return values and an exact contended total
 *   handles      DuplicateHandle, closing a handle another thread waits
 *                on, double close, closing NULL and pseudo-handles
 *   pingpong     the original pingpong fixture: two threads alternate
 *                strictly through two auto-reset events, then the same
 *                again through SignalObjectAndWait
 *
 * Build (real Windows 2000 machine, MSVC 6), the multithreaded CRT:
 *   cl /nologo /MT sync.c
 */

#include "../common/f2kt.h"

/* --- helpers ------------------------------------------------------- */

static HANDLE start(LPTHREAD_START_ROUTINE fn, void *param)
{
    HANDLE h = CreateThread(NULL, 0, fn, param, 0, NULL);

    if (h == NULL) {
        line("CreateThread failed err=%lu", GetLastError());
    }
    return h;
}

static void join(HANDLE h)
{
    DWORD w = WaitForSingleObject(h, WAIT_MS);

    if (w != WAIT_OBJECT_0) {
        line("join: wait %s", wr(w));
    }
    CloseHandle(h);
}

/* Poll one object; the result by name. Callers sequence their polls into
 * locals: argument evaluation order is unspecified in C. */
static const char *poll(HANDLE h)
{
    return wr(WaitForSingleObject(h, 0));
}

/* InterlockedCompareExchange: the MSVC 6 headers declare it over PVOIDs,
 * later ones over LONGs (and as a compiler intrinsic); MSVC 6 calls the
 * kernel32 export either way. */
static LONG cmpxchg(LONG *dst, LONG exchange, LONG comparand)
{
#if defined(_MSC_VER) && _MSC_VER <= 1200
    return (LONG)InterlockedCompareExchange((PVOID *)dst, (PVOID)exchange, (PVOID)comparand);
#else
    return InterlockedCompareExchange(dst, exchange, comparand);
#endif
}

/* --- event --------------------------------------------------------- */

static HANDLE shared_event;
static volatile LONG woken;

static DWORD WINAPI event_waiter(LPVOID param)
{
    (void)param;
    if (WaitForSingleObject(shared_event, WAIT_MS) == WAIT_OBJECT_0) {
        InterlockedIncrement((LPLONG)&woken);
    }
    return 0;
}

static void pulse_case(const char *what, BOOL manual, int waiters)
{
    HANDLE hs[2];
    int i;

    shared_event = CreateEvent(NULL, manual, FALSE, NULL);
    woken = 0;
    for (i = 0; i < waiters; i++) {
        hs[i] = start(event_waiter, NULL);
    }
    Sleep(200);
    PulseEvent(shared_event);
    Sleep(200);
    line("%s: woken %ld, event left %s", what, woken, wr(WaitForSingleObject(shared_event, 0)));
    SetEvent(shared_event);
    for (i = 0; i < waiters; i++) {
        join(hs[i]);
    }
    CloseHandle(shared_event);
}

static void sec_event(void)
{
    HANDLE m, a, n1, n2, o, t;
    const char *p1, *p2;
    BOOL r;

    m = CreateEvent(NULL, TRUE, TRUE, NULL);
    p1 = poll(m);
    p2 = poll(m);
    line("manual, initially set: %s, still %s", p1, p2);
    arm();
    r = ResetEvent(m);
    p1 = le();
    line("ResetEvent: ret=%d err=%s, now %s", r, p1, poll(m));
    arm();
    r = SetEvent(m);
    p1 = le();
    line("SetEvent: ret=%d err=%s, now %s", r, p1, poll(m));
    CloseHandle(m);

    a = CreateEvent(NULL, FALSE, TRUE, NULL);
    p1 = poll(a);
    p2 = poll(a);
    line("auto, initially set: %s, then %s", p1, p2);
    SetEvent(a);
    SetEvent(a);
    p1 = poll(a);
    p2 = poll(a);
    line("auto set twice: %s, then %s", p1, p2);
    CloseHandle(a);

    pulse_case("PulseEvent manual, no waiters", TRUE, 0);
    pulse_case("PulseEvent manual, two waiters", TRUE, 2);
    pulse_case("PulseEvent auto, two waiters", FALSE, 2);

    shared_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    woken = 0;
    {
        HANDLE w1 = start(event_waiter, NULL);
        HANDLE w2 = start(event_waiter, NULL);

        Sleep(200);
        SetEvent(shared_event);
        Sleep(200);
        line("SetEvent auto, two waiters: woken %ld", woken);
        SetEvent(shared_event);
        join(w1);
        join(w2);
        line("second SetEvent: woken %ld", woken);
    }
    CloseHandle(shared_event);

    arm();
    n1 = CreateEventA(NULL, TRUE, FALSE, "F2K.sync.event");
    line("named event: created %s err=%s", yesno(n1 != NULL), le());
    arm();
    n2 = CreateEventA(NULL, FALSE, TRUE, "F2K.sync.event");
    p1 = le();
    line("named event again: created %s err=%s, initial state ignored: %s", yesno(n2 != NULL), p1, poll(n1));
    SetEvent(n2);
    line("set through the second handle, seen through the first: %s", wr(WaitForSingleObject(n1, 0)));
    arm();
    o = OpenEventA(EVENT_ALL_ACCESS, FALSE, "F2K.sync.event");
    line("OpenEventA: opened %s err=%s", yesno(o != NULL), le());
    ResetEvent(o);
    line("reset through the opened handle: %s", wr(WaitForSingleObject(n1, 0)));
    arm();
    t = OpenEventA(EVENT_ALL_ACCESS, FALSE, "F2K.sync.nosuch");
    line("OpenEventA(missing): null %s err=%s", yesno(t == NULL), le());
    arm();
    t = CreateMutexA(NULL, FALSE, "F2K.sync.event");
    line("CreateMutexA on the event's name: null %s err=%s", yesno(t == NULL), le());
    if (t != NULL) {
        CloseHandle(t);
    }
    CloseHandle(o);
    CloseHandle(n2);
    CloseHandle(n1);

    arm();
    r = SetEvent((HANDLE)0x1234);
    line("SetEvent(bogus): ret=%d err=%s", r, le());
    shared_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    t = start(event_waiter, NULL);
    arm();
    r = SetEvent(t);
    line("SetEvent(thread handle): ret=%d err=%s", r, le());
    SetEvent(shared_event);
    join(t);
    CloseHandle(shared_event);
}

/* --- semaphore ----------------------------------------------------- */

static void sec_semaphore(void)
{
    HANDLE s, n1, n2;
    const char *p1, *p2, *p3;
    LONG prev;
    BOOL r;

    s = CreateSemaphore(NULL, 2, 3, NULL);
    p1 = poll(s);
    p2 = poll(s);
    p3 = poll(s);
    line("count 2 of 3: waits %s %s %s", p1, p2, p3);
    prev = -1;
    arm();
    r = ReleaseSemaphore(s, 1, &prev);
    line("release 1: ret=%d previous %ld err=%s", r, prev, le());
    prev = -1;
    arm();
    r = ReleaseSemaphore(s, 3, &prev);
    line("release 3 past the maximum: ret=%d previous %ld err=%s", r, prev, le());
    p1 = poll(s);
    p2 = poll(s);
    line("count unchanged by the refused release: %s %s", p1, p2);
    prev = -1;
    r = ReleaseSemaphore(s, 3, &prev);
    line("release 3 from zero: ret=%d previous %ld", r, prev);
    arm();
    r = ReleaseSemaphore(s, 0, &prev);
    line("release 0: ret=%d err=%s", r, le());
    CloseHandle(s);

    arm();
    s = CreateSemaphore(NULL, 4, 3, NULL);
    line("initial above maximum: null %s err=%s", yesno(s == NULL), le());
    arm();
    s = CreateSemaphore(NULL, 0, 0, NULL);
    line("maximum zero: null %s err=%s", yesno(s == NULL), le());
    arm();
    s = CreateSemaphore(NULL, -1, 3, NULL);
    line("negative initial: null %s err=%s", yesno(s == NULL), le());

    n1 = CreateSemaphoreA(NULL, 1, 5, "F2K.sync.semaphore");
    arm();
    n2 = CreateSemaphoreA(NULL, 0, 1, "F2K.sync.semaphore");
    line("named semaphore again: created %s err=%s", yesno(n2 != NULL), le());
    prev = -1;
    ReleaseSemaphore(n2, 2, &prev);
    line("release through the second handle: previous %ld (the first creation's counts hold)", prev);
    CloseHandle(n2);
    n2 = OpenSemaphoreA(SEMAPHORE_ALL_ACCESS, FALSE, "F2K.sync.semaphore");
    line("OpenSemaphoreA: opened %s, wait %s", yesno(n2 != NULL), wr(WaitForSingleObject(n2, 0)));
    CloseHandle(n2);
    CloseHandle(n1);
}

/* --- mutex --------------------------------------------------------- */

static HANDLE shared_mutex;
static volatile DWORD child_wait;
static volatile BOOL child_release;
static volatile DWORD child_release_err;

static DWORD WINAPI mutex_prober(LPVOID param)
{
    (void)param;
    child_wait = WaitForSingleObject(shared_mutex, 100);
    SetLastError(F2KT_UNTOUCHED);
    child_release = ReleaseMutex(shared_mutex);
    child_release_err = GetLastError();
    return 0;
}

static DWORD WINAPI mutex_abandoner(LPVOID param)
{
    (void)param;
    child_wait = WaitForSingleObject(shared_mutex, WAIT_MS);
    return 0;
}

static void sec_mutex(void)
{
    HANDLE n1, n2, o;
    const char *p1, *p2;
    BOOL r, r1, r2, r3;
    DWORD w;

    shared_mutex = CreateMutex(NULL, TRUE, NULL);
    p1 = poll(shared_mutex);
    p2 = poll(shared_mutex);
    line("created owned: recursive waits %s %s", p1, p2);
    join(start(mutex_prober, NULL));
    line("another thread: wait %s, ReleaseMutex ret=%d err=%s", wr(child_wait), child_release,
         le_of(child_release_err));
    r1 = ReleaseMutex(shared_mutex);
    r2 = ReleaseMutex(shared_mutex);
    r3 = ReleaseMutex(shared_mutex);
    line("three releases: %d %d %d", r1, r2, r3);
    arm();
    r = ReleaseMutex(shared_mutex);
    line("a fourth release: ret=%d err=%s", r, le());
    join(start(mutex_prober, NULL));
    line("unowned: another thread waits %s and releases ret=%d", wr(child_wait), child_release);
    CloseHandle(shared_mutex);

    shared_mutex = CreateMutex(NULL, FALSE, NULL);
    join(start(mutex_abandoner, NULL));
    line("owner exited holding it (its wait was %s)", wr(child_wait));
    w = WaitForSingleObject(shared_mutex, 0);
    line("next wait: %s", wr(w));
    arm();
    r = ReleaseMutex(shared_mutex);
    line("release after taking an abandoned mutex: ret=%d err=%s", r, le());
    line("then a normal wait: %s", wr(WaitForSingleObject(shared_mutex, 0)));
    ReleaseMutex(shared_mutex);
    CloseHandle(shared_mutex);

    n1 = CreateMutexA(NULL, TRUE, "F2K.sync.mutex");
    arm();
    n2 = CreateMutexA(NULL, TRUE, "F2K.sync.mutex");
    line("named mutex again: created %s err=%s", yesno(n2 != NULL), le());
    arm();
    o = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, "F2K.sync.mutex");
    line("OpenMutexA: opened %s err=%s", yesno(o != NULL), le());
    r1 = ReleaseMutex(o);
    r2 = ReleaseMutex(n2);
    line("releases through the opened then the second handle (owned once): %d %d", r1, r2);
    CloseHandle(o);
    CloseHandle(n2);
    CloseHandle(n1);
}

/* --- waitmulti ----------------------------------------------------- */

static void sec_waitmulti(void)
{
    HANDLE ev[65];
    HANDLE hs[3];
    HANDLE t;
    const char *p1, *p2, *p3;
    DWORD w;
    int i, created;

    for (i = 0; i < 3; i++) {
        hs[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
    }
    SetEvent(hs[1]);
    SetEvent(hs[2]);
    p1 = wr(WaitForMultipleObjects(3, hs, FALSE, 0));
    p2 = wr(WaitForMultipleObjects(3, hs, FALSE, 0));
    p3 = wr(WaitForMultipleObjects(3, hs, FALSE, 0));
    line("any, indices 1 and 2 signaled: %s, then %s, then %s", p1, p2, p3);

    SetEvent(hs[0]);
    SetEvent(hs[1]);
    line("all, two of three signaled: %s", wr(WaitForMultipleObjects(3, hs, TRUE, 0)));
    p1 = poll(hs[0]);
    p2 = poll(hs[1]);
    p3 = poll(hs[2]);
    line("nothing consumed: %s %s %s", p1, p2, p3);
    for (i = 0; i < 3; i++) {
        SetEvent(hs[i]);
    }
    line("all, three of three signaled: %s", wr(WaitForMultipleObjects(3, hs, TRUE, 0)));
    line("all consumed: %s", wr(WaitForMultipleObjects(3, hs, FALSE, 0)));
    for (i = 0; i < 3; i++) {
        CloseHandle(hs[i]);
    }

    hs[0] = CreateEvent(NULL, TRUE, TRUE, NULL);
    hs[1] = CreateMutex(NULL, FALSE, NULL);
    hs[2] = CreateSemaphore(NULL, 1, 1, NULL);
    line("all over event, mutex and semaphore: %s", wr(WaitForMultipleObjects(3, hs, TRUE, 0)));
    p1 = poll(hs[0]);
    p2 = poll(hs[2]);
    line("after: manual event %s, semaphore %s", p1, p2);
    ReleaseMutex(hs[1]);
    CloseHandle(hs[0]);
    CloseHandle(hs[2]);

    shared_mutex = hs[1];
    join(start(mutex_abandoner, NULL));
    hs[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    line("any over an event and an abandoned mutex: %s", wr(WaitForMultipleObjects(2, hs, FALSE, 0)));
    ReleaseMutex(hs[1]);
    CloseHandle(hs[0]);
    CloseHandle(hs[1]);

    created = 0;
    for (i = 0; i < 65; i++) {
        ev[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
        created += ev[i] != NULL;
    }
    line("65 events created: %d", created);
    SetEvent(ev[63]);
    line("any over 64, the last signaled: %s", wr(WaitForMultipleObjects(64, ev, FALSE, 0)));
    arm();
    w = WaitForMultipleObjects(65, ev, FALSE, 0);
    line("any over 65: %s err=%s", wr(w), le());
    arm();
    w = WaitForMultipleObjects(0, ev, FALSE, 0);
    line("an empty array: %s err=%s", wr(w), le());
    hs[0] = ev[0];
    hs[1] = ev[0];
    arm();
    w = WaitForMultipleObjects(2, hs, TRUE, 0);
    line("all with a duplicate: %s err=%s", wr(w), le());
    arm();
    w = WaitForMultipleObjects(2, hs, FALSE, 0);
    line("any with a duplicate: %s err=%s", wr(w), le());
    hs[1] = (HANDLE)0x1234;
    arm();
    w = WaitForMultipleObjects(2, hs, FALSE, 0);
    line("any with a bogus handle: %s err=%s", wr(w), le());
    for (i = 0; i < 65; i++) {
        if (ev[i] != NULL) {
            CloseHandle(ev[i]);
        }
    }
    hs[1] = ev[1];
    arm();
    w = WaitForMultipleObjects(2, hs, FALSE, 0);
    line("any over closed handles: %s err=%s", wr(w), le());

    arm();
    w = WaitForSingleObject((HANDLE)0x1234, 0);
    line("single on a bogus handle: %s err=%s", wr(w), le());
    arm();
    w = WaitForSingleObject(NULL, 0);
    line("single on NULL: %s err=%s", wr(w), le());
    line("single on the current process: %s", wr(WaitForSingleObject(GetCurrentProcess(), 0)));
    line("single on the current thread: %s", wr(WaitForSingleObject(GetCurrentThread(), 0)));

    shared_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    hs[0] = start(event_waiter, NULL);
    hs[1] = start(event_waiter, NULL);
    t = shared_event;
    line("any over two running threads: %s", wr(WaitForMultipleObjects(2, hs, FALSE, 100)));
    SetEvent(t);
    line("all over the two threads after release: %s", wr(WaitForMultipleObjects(2, hs, TRUE, WAIT_MS)));
    CloseHandle(hs[0]);
    CloseHandle(hs[1]);
    CloseHandle(t);
}

/* --- apc ----------------------------------------------------------- */

static char apc_trail[64];
static volatile DWORD apc_count;
static volatile DWORD sleep_result;
static volatile DWORD late_result;
static volatile DWORD seen_before_alertable;
static HANDLE apc_ready;

static VOID CALLBACK apc_fn(DWORD param)
{
    char d[4];

    d[0] = (char)('0' + param);
    d[1] = 0;
    strcat(apc_trail, d);
    apc_count++;
}

static DWORD WINAPI alertable_sleeper(LPVOID param)
{
    (void)param;
    SetEvent(apc_ready);
    sleep_result = SleepEx(WAIT_MS, TRUE);
    return 0;
}

static DWORD WINAPI late_alertable(LPVOID param)
{
    (void)param;
    SetEvent(apc_ready);
    Sleep(300);
    seen_before_alertable = apc_count;
    late_result = SleepEx(0, TRUE);
    return 0;
}

static DWORD WINAPI alertable_waiter(LPVOID param)
{
    (void)param;
    SetEvent(apc_ready);
    sleep_result = WaitForSingleObjectEx(shared_event, WAIT_MS, TRUE);
    return 0;
}

static void sec_apc(void)
{
    HANDLE h;
    DWORD r;
    BOOL q;

    apc_ready = CreateEvent(NULL, FALSE, FALSE, NULL);

    apc_trail[0] = 0;
    apc_count = 0;
    h = start(alertable_sleeper, NULL);
    WaitForSingleObject(apc_ready, WAIT_MS);
    Sleep(100);
    arm();
    q = QueueUserAPC(apc_fn, h, 1);
    line("QueueUserAPC to an alertable sleeper: ret=%d err=%s", q, le());
    join(h);
    line("SleepEx returned %s, APCs run [%s]", wr(sleep_result), apc_trail);

    apc_trail[0] = 0;
    apc_count = 0;
    h = start(late_alertable, NULL);
    WaitForSingleObject(apc_ready, WAIT_MS);
    Sleep(50);
    QueueUserAPC(apc_fn, h, 1);
    QueueUserAPC(apc_fn, h, 2);
    QueueUserAPC(apc_fn, h, 3);
    join(h);
    line("three APCs to a thread in a non-alertable Sleep: run before it turned alertable %lu", seen_before_alertable);
    line("then SleepEx(0, TRUE) returned %s, APCs run [%s]", wr(late_result), apc_trail);

    apc_trail[0] = 0;
    shared_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    h = start(alertable_waiter, NULL);
    WaitForSingleObject(apc_ready, WAIT_MS);
    Sleep(100);
    QueueUserAPC(apc_fn, h, 4);
    join(h);
    line("alertable WaitForSingleObjectEx returned %s, APCs run [%s]", wr(sleep_result), apc_trail);
    CloseHandle(shared_event);

    apc_trail[0] = 0;
    QueueUserAPC(apc_fn, GetCurrentThread(), 5);
    line("APC to self: not run before an alertable wait [%s]", apc_trail);
    r = SleepEx(0, TRUE);
    line("SleepEx(0, TRUE) returned %s, APCs run [%s]", wr(r), apc_trail);
    r = SleepEx(0, TRUE);
    line("SleepEx(0, TRUE) with nothing queued: %s", wr(r));

    h = start(alertable_sleeper, NULL);
    QueueUserAPC(apc_fn, h, 6);
    join(h);
    arm();
    q = QueueUserAPC(apc_fn, h, 7);
    line("QueueUserAPC to a closed handle: ret=%d err=%s", q, le());
    CloseHandle(apc_ready);
}

/* --- critsec ------------------------------------------------------- */

static CRITICAL_SECTION cs;
static volatile LONG plain_total;
static volatile BOOL child_try;

static DWORD WINAPI try_enter_child(LPVOID param)
{
    (void)param;
    child_try = TryEnterCriticalSection(&cs);
    if (child_try) {
        LeaveCriticalSection(&cs);
    }
    return 0;
}

static DWORD WINAPI cs_worker(LPVOID param)
{
    int i;

    (void)param;
    for (i = 0; i < 100000; i++) {
        EnterCriticalSection(&cs);
        plain_total = plain_total + 1;
        LeaveCriticalSection(&cs);
    }
    return 0;
}

static void sec_critsec(void)
{
    HANDLE hs[4];
    int i;

    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    EnterCriticalSection(&cs);
    line("entered twice: RecursionCount %ld, owned by this thread %s", cs.RecursionCount,
         yesno((DWORD)cs.OwningThread == GetCurrentThreadId()));
    join(start(try_enter_child, NULL));
    line("TryEnterCriticalSection from another thread while owned: %d", child_try);
    line("TryEnterCriticalSection recursively: %d", TryEnterCriticalSection(&cs));
    LeaveCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    LeaveCriticalSection(&cs);
    line("left: RecursionCount %ld, owner cleared %s", cs.RecursionCount, yesno(cs.OwningThread == 0));
    join(start(try_enter_child, NULL));
    line("TryEnterCriticalSection from another thread when free: %d", child_try);

    plain_total = 0;
    for (i = 0; i < 4; i++) {
        hs[i] = start(cs_worker, NULL);
    }
    for (i = 0; i < 4; i++) {
        join(hs[i]);
    }
    line("4 threads x 100000 increments under the critical section: %ld", plain_total);
    DeleteCriticalSection(&cs);
}

/* --- interlocked --------------------------------------------------- */

static volatile LONG counter;

static DWORD WINAPI interlocked_worker(LPVOID param)
{
    int i;

    (void)param;
    for (i = 0; i < 100000; i++) {
        InterlockedIncrement((LPLONG)&counter);
    }
    return 0;
}

static void sec_interlocked(void)
{
    LONG v = 0;
    LONG r1, r2, r3;
    HANDLE hs[4];
    int i;

    r1 = InterlockedIncrement(&v);
    r2 = InterlockedDecrement(&v);
    r3 = InterlockedDecrement(&v);
    line("increment, decrement, decrement from 0: %ld %ld %ld, value %ld", r1, r2, r3, v);
    r1 = InterlockedExchange(&v, 10);
    line("exchange: returned %ld, value %ld", r1, v);
    r1 = InterlockedExchangeAdd(&v, 5);
    line("exchange-add 5: returned %ld, value %ld", r1, v);
    r1 = cmpxchg(&v, 20, 15);
    line("compare-exchange hit: returned %ld, value %ld", r1, v);
    r1 = cmpxchg(&v, 30, 15);
    line("compare-exchange miss: returned %ld, value %ld", r1, v);

    counter = 0;
    for (i = 0; i < 4; i++) {
        hs[i] = start(interlocked_worker, NULL);
    }
    for (i = 0; i < 4; i++) {
        join(hs[i]);
    }
    line("4 threads x 100000 InterlockedIncrement: %ld", counter);
}

/* --- handles ------------------------------------------------------- */

static volatile DWORD closed_wait;

static DWORD WINAPI wait_on_closed(LPVOID param)
{
    closed_wait = WaitForSingleObject((HANDLE)param, 300);
    return 0;
}

static void sec_handles(void)
{
    HANDLE e, d, h;
    BOOL r;

    e = CreateEvent(NULL, TRUE, FALSE, NULL);
    arm();
    r = DuplicateHandle(GetCurrentProcess(), e, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS);
    line("DuplicateHandle(event): ret=%d err=%s, a different handle %s", r, le(), yesno(d != e));
    SetEvent(d);
    line("set through the duplicate, seen through the original: %s", wr(WaitForSingleObject(e, 0)));
    CloseHandle(e);
    line("the duplicate outlives the original: %s", wr(WaitForSingleObject(d, 0)));
    CloseHandle(d);

    e = CreateEvent(NULL, TRUE, FALSE, NULL);
    closed_wait = 0xFFFF;
    h = start(wait_on_closed, e);
    Sleep(100);
    arm();
    r = CloseHandle(e);
    line("close a handle another thread waits on: ret=%d err=%s", r, le());
    join(h);
    line("the waiter's wait ended with %s", wr(closed_wait));

    arm();
    r = CloseHandle(e);
    line("close it again: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(NULL);
    line("close NULL: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(INVALID_HANDLE_VALUE);
    line("close INVALID_HANDLE_VALUE (the process pseudo-handle): ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(GetCurrentThread());
    line("close the thread pseudo-handle: ret=%d err=%s", r, le());
}

/* --- pingpong ------------------------------------------------------ */

#define TURNS 5

static HANDLE turn_ping;
static HANDLE turn_pong;

static DWORD WINAPI ping_main(LPVOID param)
{
    DWORD i;

    (void)param;
    for (i = 0; i < TURNS; i++) {
        if (WaitForSingleObject(turn_ping, WAIT_MS) != WAIT_OBJECT_0) {
            return 1;
        }
        line("ping %lu", i);
        SetEvent(turn_pong);
    }
    return 0;
}

static DWORD WINAPI signal_ping(LPVOID param)
{
    DWORD i;

    (void)param;
    WaitForSingleObject(turn_ping, WAIT_MS);
    for (i = 0; i < TURNS; i++) {
        line("signal ping %lu", i);
        if (i + 1 < TURNS) {
            SignalObjectAndWait(turn_pong, turn_ping, WAIT_MS, FALSE);
        } else {
            SetEvent(turn_pong);
        }
    }
    return 0;
}

static void sec_pingpong(void)
{
    HANDLE h;
    DWORD i, r;

    turn_ping = CreateEvent(NULL, FALSE, FALSE, NULL);
    turn_pong = CreateEvent(NULL, FALSE, TRUE, NULL);
    h = start(ping_main, NULL);
    for (i = 0; i < TURNS; i++) {
        if (WaitForSingleObject(turn_pong, WAIT_MS) != WAIT_OBJECT_0) {
            line("pong: wait failed");
            break;
        }
        line("pong %lu", i);
        SetEvent(turn_ping);
    }
    r = WaitForSingleObject(h, WAIT_MS);
    line("child handle wait returned %lu", r);
    CloseHandle(h);

    ResetEvent(turn_pong);
    h = start(signal_ping, NULL);
    for (i = 0; i < TURNS; i++) {
        r = SignalObjectAndWait(turn_ping, turn_pong, WAIT_MS, FALSE);
        if (r != WAIT_OBJECT_0) {
            line("signal pong: SignalObjectAndWait %s", wr(r));
            break;
        }
        line("signal pong %lu", i);
    }
    join(h);
    CloseHandle(turn_ping);
    CloseHandle(turn_pong);
}

static const section_t sections[] = {
    { "event", sec_event, 0 },
    { "semaphore", sec_semaphore, 0 },
    { "mutex", sec_mutex, 0 },
    { "waitmulti", sec_waitmulti, 0 },
    { "apc", sec_apc, 0 },
    { "critsec", sec_critsec, 0 },
    { "interlocked", sec_interlocked, 0 },
    { "handles", sec_handles, 0 },
    { "pingpong", sec_pingpong, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("sync", sections, argc, argv);
}
