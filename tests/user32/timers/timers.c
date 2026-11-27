/*
 * timers - SetTimer and KillTimer as programs lean on them: the ids
 * SetTimer answers for window and thread timers, a timer set again,
 * WM_TIMER's coalescing (one message however many periods passed
 * unread), its place among the queue's messages (after posted
 * messages and WM_PAINT), the order two due timers are read in,
 * TIMERPROC callbacks through DispatchMessage, filtered peeks, and the
 * elapse values at the edges.
 *
 * guimsg's killtimer section covers KillTimer's own cases; this one
 * kills its timers only to end them.
 *
 * Each section creates a hidden popup of a class it registers itself
 * (shown, without activation, where WM_PAINT takes part), drains its
 * queue first, and kills every timer it set. Timing-shaped facts print
 * as verdicts against bands; the timer ids the program chose print as
 * they are, the ones SetTimer chose only as relations (zero or not,
 * distinct or not).
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   ids       SetTimer on the window with ids 1, 0 and 0xFFFF (the
 *             return against the id), the same id again; SetTimer(NULL)
 *             twice with id 0 and once with an id (whether each answer
 *             is non-zero and distinct, and the id given ignored);
 *             SetTimer with the answer of an earlier thread timer
 *             (replacing it); a destroyed window, another thread's
 *             window, and the desktop window
 *   coalesce  a 20 ms timer left unread for 500 ms: how many WM_TIMER a
 *             PeekMessageW loop finds (one), and whether a second comes
 *             within 200 ms; the wParam and hwnd of each
 *   order     the queue's order with a posted message, an invalidated
 *             window and a due timer all pending: each message as
 *             GetMessageW returns it; then two timers due together, set
 *             in the order 11 then 12, and 12 then 11
 *   reset     a 300 ms timer set again after 200 ms: whether its
 *             WM_TIMER comes before 400 ms (no: the period restarts);
 *             set again with another period
 *   proc      a window timer and a thread timer with a TIMERPROC: the
 *             callback's window, message, id and time against
 *             GetTickCount; DispatchMessageW's return; the WM_TIMER's
 *             lParam; a WM_TIMER posted by hand whose lParam is the
 *             TIMERPROC (whether DispatchMessageW calls it) and one
 *             with lParam 0 (the window procedure gets it)
 *   filter    PeekMessageW for WM_TIMER alone, PM_NOREMOVE twice (the
 *             same timer both times) and PM_REMOVE; a filter for
 *             another window; a range that leaves WM_TIMER out
 *   elapse    SetTimer with elapse 0, 1 and 0x7FFFFFFF, 0x80000000 and
 *             0xFFFFFFFF: the return and whether a WM_TIMER comes
 *             within 200 ms
 *   rate      a 50 ms timer read for one second: how many WM_TIMER come
 *             (a band around 20, the tick's quantum allowing), and
 *             whether each message's time is after the one before
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat timers):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% timers.c user32.lib
 */

#include "../common/f2kt.h"

#define MSG_TEST (WM_USER + 50)

static HWND main_window;
static int paints;
static int proc_timers;
static WPARAM proc_last_id;

static LRESULT CALLBACK timer_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    PAINTSTRUCT ps;

    if (msg == WM_PAINT) {
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        paints++;
        return 0;
    }
    if (msg == WM_TIMER) {
        proc_timers++;
        proc_last_id = wparam;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void register_class(void)
{
    static BOOL done;
    WNDCLASSW wc;

    if (done) {
        return;
    }
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = timer_wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"F2KTimers";
    done = RegisterClassW(&wc) != 0;
}

static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
}

static HWND make_window(void)
{
    register_class();
    main_window = CreateWindowExW(WS_EX_TOOLWINDOW, L"F2KTimers", L"timers", WS_POPUP, 0, 0, 64, 48, NULL,
                                  NULL, GetModuleHandleA(NULL), NULL);
    line("setup: the window created: %s", yesno(main_window != NULL));
    drain();
    paints = 0;
    proc_timers = 0;
    return main_window;
}

static void end_window(void)
{
    DestroyWindow(main_window);
    main_window = NULL;
    drain();
}

static const char *msg_name(UINT m)
{
    switch (m) {
    case WM_TIMER: return "WM_TIMER";
    case WM_PAINT: return "WM_PAINT";
    case MSG_TEST: return "MSG_TEST (posted)";
    }
    return "another message";
}

/* --- ids ------------------------------------------------------------- */

static UINT set(const char *what, HWND h, UINT id, UINT ms)
{
    UINT r;

    arm();
    r = (UINT)SetTimer(h, id, ms, NULL);
    line("SetTimer(%s): %s err=%s", what, r == 0 ? "0" : r == id ? "the id given" : r == 1 ? "1" : "another non-zero",
         le());
    return r;
}

static HWND other_window;
static HANDLE other_ready, other_stop;

static DWORD WINAPI other_thread(LPVOID param)
{
    MSG m;

    other_window = CreateWindowExW(0, L"F2KTimers", L"other", WS_POPUP, 0, 0, 10, 10, NULL, NULL,
                                   GetModuleHandleA(NULL), NULL);
    SetEvent(other_ready);
    while (MsgWaitForMultipleObjects(1, &other_stop, FALSE, 10000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            DispatchMessageW(&m);
        }
    }
    DestroyWindow(other_window);
    return 0;
}

static void sec_ids(void)
{
    HWND h, dead;
    UINT a, b, c, d;
    HANDLE t;
    DWORD tid;
    MSG m;
    int got;
    DWORD start;

    h = make_window();
    set("h, id 1, 1000 ms", h, 1, 1000);
    set("h, id 0, 1000 ms", h, 0, 1000);
    set("h, id 0xFFFF, 1000 ms", h, 0xFFFF, 1000);
    set("h, id 0x12345, 1000 ms", h, 0x12345, 1000);
    set("h, id 1 again, 1000 ms", h, 1, 1000);
    KillTimer(h, 1);
    KillTimer(h, 0);
    KillTimer(h, 0xFFFF);
    KillTimer(h, 0x12345);

    a = set("NULL, id 0, 1000 ms", NULL, 0, 1000);
    b = set("NULL, id 0, 1000 ms, again", NULL, 0, 1000);
    c = set("NULL, id 77, 1000 ms", NULL, 77, 1000);
    line("the three thread timers' ids are distinct: %s", yesno(a != b && b != c && a != c));
    d = set("NULL, the first one's id, 50 ms (replacing it)", NULL, a, 50);
    line("  the same id answered: %s", yesno(d == a));
    start = GetTickCount();
    got = 0;
    while (GetTickCount() - start < 500) {
        if (PeekMessageW(&m, NULL, WM_TIMER, WM_TIMER, PM_REMOVE)) {
            got = 1;
            line("  a WM_TIMER came: hwnd NULL %s, wParam is that id: %s", yesno(m.hwnd == NULL),
                 yesno(m.wParam == a));
            break;
        }
        Sleep(10);
    }
    if (!got) {
        line("  no WM_TIMER within 500 ms");
    }
    KillTimer(NULL, a);
    KillTimer(NULL, b);
    KillTimer(NULL, c);

    register_class();
    dead = CreateWindowExW(0, L"F2KTimers", L"dead", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleA(NULL),
                           NULL);
    DestroyWindow(dead);
    set("a destroyed window, id 3", dead, 3, 1000);
    other_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    other_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    t = CreateThread(NULL, 0, other_thread, NULL, 0, &tid);
    WaitForSingleObject(other_ready, WAIT_MS);
    set("another thread's window, id 4", other_window, 4, 1000);
    KillTimer(other_window, 4);
    SetEvent(other_stop);
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    CloseHandle(other_ready);
    CloseHandle(other_stop);
    set("the desktop window, id 5", GetDesktopWindow(), 5, 1000);
    KillTimer(GetDesktopWindow(), 5);
    end_window();
}

/* --- coalesce -------------------------------------------------------- */

static void sec_coalesce(void)
{
    HWND h;
    MSG m;
    int n = 0, right = 1;
    DWORD start;

    h = make_window();
    SetTimer(h, 21, 20, NULL);
    Sleep(500);
    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        if (m.message == WM_TIMER) {
            n++;
            if (m.hwnd != h || m.wParam != 21) {
                right = 0;
            }
        }
    }
    line("a 20 ms timer unread for 500 ms: %d WM_TIMER found, each for the window and id 21: %s", n, yesno(right));
    start = GetTickCount();
    n = 0;
    while (GetTickCount() - start < 200) {
        if (PeekMessageW(&m, NULL, WM_TIMER, WM_TIMER, PM_REMOVE)) {
            n++;
        }
        Sleep(5);
    }
    line("then within 200 ms: 2 or more WM_TIMER: %s", yesno(n >= 2));
    KillTimer(h, 21);
    drain();
    end_window();
}

/* --- order ----------------------------------------------------------- */

static void read_order(const char *what, int count)
{
    MSG m;
    int i;
    char buf[200] = "";

    for (i = 0; i < count; i++) {
        if (!PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            strcat(buf, " (empty)");
            break;
        }
        strcat(buf, " ");
        strcat(buf, msg_name(m.message));
        if (m.message == WM_TIMER && m.hwnd != NULL) {
            sprintf(buf + strlen(buf), "(%lu)", (unsigned long)m.wParam);
        } else if (m.message == WM_TIMER) {
            strcat(buf, "(the thread timer)");
        }
        DispatchMessageW(&m);
    }
    line("%s:%s", what, buf);
}

static void sec_order(void)
{
    HWND h;
    UINT id;

    h = make_window();
    ShowWindow(h, SW_SHOWNA);
    UpdateWindow(h);
    drain();
    SetTimer(h, 10, 20, NULL);
    Sleep(100);
    InvalidateRect(h, NULL, FALSE);
    PostMessageW(h, MSG_TEST, 0, 0);
    read_order("a timer due, the window invalidated, a message posted", 3);
    KillTimer(h, 10);
    drain();

    SetTimer(h, 11, 20, NULL);
    SetTimer(h, 12, 20, NULL);
    Sleep(100);
    read_order("timers 11 then 12 set, both due", 2);
    KillTimer(h, 11);
    KillTimer(h, 12);
    drain();
    SetTimer(h, 12, 20, NULL);
    SetTimer(h, 11, 20, NULL);
    Sleep(100);
    read_order("timers 12 then 11 set, both due", 2);
    KillTimer(h, 11);
    KillTimer(h, 12);
    drain();
    SetTimer(h, 13, 20, NULL);
    id = (UINT)SetTimer(NULL, 0, 20, NULL);
    Sleep(100);
    read_order("a window timer (13) then a thread timer set, both due", 2);
    KillTimer(h, 13);
    KillTimer(NULL, id);
    drain();
    ShowWindow(h, SW_HIDE);
    end_window();
}

/* --- reset ----------------------------------------------------------- */

static void first_timer(const char *what, DWORD start, DWORD lo, DWORD hi)
{
    MSG m;

    while (GetTickCount() - start < 2000) {
        if (PeekMessageW(&m, NULL, WM_TIMER, WM_TIMER, PM_REMOVE)) {
            line("%s: the first WM_TIMER in %lu to %lu ms: %s", what, lo, hi, band(GetTickCount() - start, lo, hi));
            return;
        }
        Sleep(5);
    }
    line("%s: no WM_TIMER within 2 s", what);
}

static void sec_reset(void)
{
    HWND h;
    DWORD start;
    UINT r;

    h = make_window();
    start = GetTickCount();
    SetTimer(h, 30, 300, NULL);
    Sleep(200);
    arm();
    r = (UINT)SetTimer(h, 30, 300, NULL);
    line("SetTimer(h, 30, 300 ms) again after 200 ms: %s err=%s", r == 30 ? "the id" : r == 0 ? "0" : "another", le());
    first_timer("from the first SetTimer", start, 450, 650);
    KillTimer(h, 30);
    drain();
    start = GetTickCount();
    SetTimer(h, 31, 1000, NULL);
    Sleep(100);
    SetTimer(h, 31, 100, NULL);
    first_timer("a 1000 ms timer set again to 100 ms after 100 ms, from the first SetTimer", start, 150, 400);
    KillTimer(h, 31);
    drain();
    end_window();
}

/* --- proc ------------------------------------------------------------ */

static int cb_calls;
static HWND cb_hwnd;
static UINT cb_msg;
static UINT cb_id;
static DWORD cb_time;
static DWORD cb_tick;

static VOID CALLBACK timer_cb(HWND h, UINT msg, UINT id, DWORD time)
{
    cb_calls++;
    cb_hwnd = h;
    cb_msg = msg;
    cb_id = id;
    cb_time = time;
    cb_tick = GetTickCount();
}

static void wait_timer(MSG *m)
{
    DWORD start = GetTickCount();

    ZeroMemory(m, sizeof *m);
    while (GetTickCount() - start < 1000) {
        if (PeekMessageW(m, NULL, WM_TIMER, WM_TIMER, PM_REMOVE)) {
            return;
        }
        Sleep(5);
    }
}

static void callback_report(const char *what, HWND expect, UINT id)
{
    line("%s: the callback ran %d time(s)", what, cb_calls);
    if (cb_calls > 0) {
        line("  window %s, message %s, id is %s, time within 50 ms of GetTickCount: %s",
             cb_hwnd == expect ? (expect == NULL ? "NULL" : "the window") : "another",
             cb_msg == WM_TIMER ? "WM_TIMER" : "another", cb_id == id ? "the timer's" : "another",
             yesno((LONG)(cb_tick - cb_time) >= 0 && cb_tick - cb_time <= 50));
    }
}

static void sec_proc(void)
{
    HWND h;
    MSG m;
    LRESULT r;
    UINT id;

    h = make_window();
    SetTimer(h, 40, 30, timer_cb);
    wait_timer(&m);
    line("a window timer with a TIMERPROC: WM_TIMER read %s, lParam is the TIMERPROC: %s",
         yesno(m.message == WM_TIMER), yesno(m.lParam == (LPARAM)timer_cb));
    cb_calls = 0;
    proc_timers = 0;
    arm();
    r = DispatchMessageW(&m);
    line("DispatchMessageW: ret=%ld err=%s, the window procedure's WM_TIMER count %d", (long)r, le(), proc_timers);
    callback_report("  then", h, 40);
    KillTimer(h, 40);
    drain();

    id = (UINT)SetTimer(NULL, 0, 30, timer_cb);
    wait_timer(&m);
    line("a thread timer with a TIMERPROC: WM_TIMER read %s, hwnd NULL %s, lParam is the TIMERPROC: %s",
         yesno(m.message == WM_TIMER), yesno(m.hwnd == NULL), yesno(m.lParam == (LPARAM)timer_cb));
    cb_calls = 0;
    arm();
    r = DispatchMessageW(&m);
    line("DispatchMessageW: ret=%ld err=%s", (long)r, le());
    callback_report("  then", NULL, id);
    KillTimer(NULL, id);
    drain();

    cb_calls = 0;
    proc_timers = 0;
    PostMessageW(h, WM_TIMER, 99, (LPARAM)timer_cb);
    wait_timer(&m);
    arm();
    r = DispatchMessageW(&m);
    line("a WM_TIMER posted by hand, lParam the TIMERPROC: DispatchMessageW ret=%ld err=%s, window procedure %d",
         (long)r, le(), proc_timers);
    callback_report("  then", h, 99);
    cb_calls = 0;
    proc_timers = 0;
    PostMessageW(h, WM_TIMER, 98, 0);
    wait_timer(&m);
    arm();
    r = DispatchMessageW(&m);
    line("a WM_TIMER posted by hand, lParam 0: DispatchMessageW ret=%ld err=%s, window procedure %d, id %lu",
         (long)r, le(), proc_timers, (unsigned long)proc_last_id);
    line("  the callback ran %d time(s)", cb_calls);
    end_window();
}

/* --- filter ---------------------------------------------------------- */

static void peek(const char *what, HWND h, UINT lo, UINT hi, UINT flags)
{
    MSG m;
    BOOL r;

    arm();
    r = PeekMessageW(&m, h, lo, hi, flags);
    line("PeekMessageW(%s): ret=%d err=%s%s", what, r, le(),
         r ? (m.message == WM_TIMER ? (m.wParam == 50 ? ", WM_TIMER 50" : ", WM_TIMER, another id") : ", another message") : "");
}

static void sec_filter(void)
{
    HWND h, other;

    h = make_window();
    other = CreateWindowExW(0, L"F2KTimers", L"other", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleA(NULL),
                            NULL);
    drain();
    SetTimer(h, 50, 20, NULL);
    Sleep(100);
    peek("h, WM_TIMER only, PM_NOREMOVE", h, WM_TIMER, WM_TIMER, PM_NOREMOVE);
    peek("h, WM_TIMER only, PM_NOREMOVE again", h, WM_TIMER, WM_TIMER, PM_NOREMOVE);
    peek("another window of the thread, any message", other, 0, 0, PM_NOREMOVE);
    peek("h, WM_USER to 0x7FFF", h, WM_USER, 0x7FFF, PM_NOREMOVE);
    peek("h, WM_NULL to WM_KEYLAST", h, 0, WM_KEYLAST, PM_NOREMOVE);
    peek("NULL, WM_TIMER only, PM_REMOVE", NULL, WM_TIMER, WM_TIMER, PM_REMOVE);
    peek("NULL, WM_TIMER only, PM_REMOVE at once again", NULL, WM_TIMER, WM_TIMER, PM_REMOVE);
    peek("(HWND)-1 (thread messages only), any message", (HWND)-1, 0, 0, PM_NOREMOVE);
    KillTimer(h, 50);
    peek("NULL, any message, after KillTimer", NULL, 0, 0, PM_REMOVE);
    DestroyWindow(other);
    end_window();
}

/* --- elapse ---------------------------------------------------------- */

static void elapse(HWND h, const char *what, UINT ms)
{
    UINT r;
    MSG m;
    DWORD start;
    int got = 0;

    arm();
    r = (UINT)SetTimer(h, 60, ms, NULL);
    line("SetTimer(h, 60, %s): %s err=%s", what, r == 60 ? "the id" : r == 0 ? "0" : "another", le());
    start = GetTickCount();
    while (GetTickCount() - start < 200) {
        if (PeekMessageW(&m, NULL, WM_TIMER, WM_TIMER, PM_REMOVE)) {
            got = 1;
            break;
        }
        Sleep(5);
    }
    line("  a WM_TIMER within 200 ms: %s", yesno(got));
    KillTimer(h, 60);
    drain();
}

static void sec_elapse(void)
{
    HWND h;

    h = make_window();
    elapse(h, "0", 0);
    elapse(h, "1", 1);
    elapse(h, "0x7FFFFFFF", 0x7FFFFFFF);
    elapse(h, "0x80000000", 0x80000000);
    elapse(h, "0xFFFFFFFF", 0xFFFFFFFF);
    end_window();
}

/* --- rate ------------------------------------------------------------ */

static void sec_rate(void)
{
    HWND h;
    MSG m;
    DWORD start, last = 0;
    int n = 0, rising = 1;

    h = make_window();
    SetTimer(h, 70, 50, NULL);
    start = GetTickCount();
    while (GetTickCount() - start < 1000) {
        if (MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_TIMER) == WAIT_OBJECT_0) {
            while (PeekMessageW(&m, NULL, WM_TIMER, WM_TIMER, PM_REMOVE)) {
                if (n > 0 && (LONG)(m.time - last) <= 0) {
                    rising = 0;
                }
                last = m.time;
                n++;
            }
        }
    }
    KillTimer(h, 70);
    line("a 50 ms timer read for 1 s: 15 to 21 WM_TIMER: %s; each message's time after the one before: %s",
         n >= 15 && n <= 21 ? "yes" : "no", yesno(rising));
    drain();
    end_window();
}

static const section_t sections[] = {
    { "ids", sec_ids, F2KT_ALWAYS },
    { "coalesce", sec_coalesce, F2KT_ALWAYS },
    { "order", sec_order, F2KT_ALWAYS },
    { "reset", sec_reset, F2KT_ALWAYS },
    { "proc", sec_proc, F2KT_ALWAYS },
    { "filter", sec_filter, F2KT_ALWAYS },
    { "elapse", sec_elapse, F2KT_ALWAYS },
    { "rate", sec_rate, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("timers", sections, argc, argv);
}
