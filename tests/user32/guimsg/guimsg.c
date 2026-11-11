/*
 * guimsg - the user32 message-loop calls: PostMessageA, GetMessageA,
 * PeekMessageA, PostQuitMessage, TranslateMessage, DispatchMessageA,
 * SendMessageA/W, DefWindowProcA/W, and a PostThreadMessageA to the
 * current thread.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value,
 * address or thread id is printed, only whether one came back and how
 * two compare (yesno()); every call under observation is armed with
 * the last-error sentinel and its line prints ret= and err=. A
 * module-level wndproc records the last message/wParam/lParam, a call
 * count and its own return value; the recorded values print after the
 * calls, never from inside the wndproc. Each section starts by
 * draining the queue (a PeekMessageA PM_REMOVE loop) so the sections
 * are independent, and creates its own hidden window (explicit
 * 320x200) of a class it registers itself.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   post       PostMessageA(h, WM_USER+1, 11, 22); GetMessageA returns
 *              1 with the posted message: message match, wParam,
 *              lParam, hwnd==h
 *   peek       two posts; PeekMessageA PM_NOREMOVE twice (the same
 *              message both times), PM_REMOVE twice (the first, then
 *              the second), then ret=0 on the empty queue
 *   quit       PostQuitMessage(7); GetMessageA returns 0 with WM_QUIT
 *              and wParam 7
 *   dispatch   post WM_USER+5; GetMessageA; TranslateMessage;
 *              DispatchMessageA returns the wndproc's 0; the recorded
 *              message/wParam/lParam/count
 *   send       SendMessageA(h, WM_USER+6, 55, 66) returns the wndproc's
 *              0, the recorded values; then SendMessageW on the same
 *              inputs
 *   defproc    DefWindowProcA(h, WM_CLOSE, 0, 0) (WM_CLOSE destroys the
 *              window) and IsWindow after; DefWindowProcW with WM_NULL
 *              on a second window
 *   threadmsg  PostThreadMessageA to the current thread, WM_USER+7;
 *              GetMessageA returns it with hwnd NULL
 *   regmsg     RegisterWindowMessageW and RegisterWindowMessageA: the
 *              range, the same name (in either form, in other case)
 *              answering the same value, another name another one, the
 *              empty name, NULL (inside __try); RegisterClipboardFormatW
 *              of the same name; the registered message sent to a
 *              window
 *   msgpos     GetMessageTime and GetMessagePos before any message and
 *              after GetMessageW, PeekMessageW PM_REMOVE and
 *              PM_NOREMOVE of posted messages, and inside and after a
 *              sent one: against each MSG's time and pt, the ticks
 *              around the post, and 100 ms between two posts
 *   wait       WaitMessage with a message already posted (at once),
 *              after that message was peeked (it waits for a 300 ms
 *              timer), and while a second thread posts after 200 ms
 *   smto       SendMessageTimeoutW (and A) to the thread's own window
 *              (SMTO_NORMAL, timeout 0, SMTO_ABORTIFHUNG, no result
 *              pointer), to a second thread's pumping window, and to a
 *              second thread busy for 1.5 s with a 300 ms timeout
 *              (SMTO_NORMAL and SMTO_ABORTIFHUNG); a bogus window; how
 *              many timed-out messages the busy thread handles later
 *   hung       a second thread that read its queue once and then does
 *              not for 9 s: IsHungAppWindow of its window and
 *              SendMessageTimeoutW SMTO_ABORTIFHUNG at once and after
 *              6.5 s (when Windows deems it hung: no input read for 5
 *              s), SMTO_NORMAL then, and both after it reads again
 *   notify     SendNotifyMessageW (and A) to the thread's own window
 *              (handled before the return) and to a second thread's
 *              (returning at once, handled there later); WM_SETTEXT,
 *              whose lParam is a pointer, to the second thread's; a
 *              bogus window
 *
 * The sections from regmsg on use a window of a class registered with
 * RegisterClassW, F2KGuimsgW, whose procedure records the test
 * message WM_USER+30 and the registered message (the count, the last
 * parameters, the thread it ran on as a relation, GetMessageTime
 * inside it) and answers wParam+lParam. A second thread makes its own
 * window of the class, reads its queue once, sleeps as long as the
 * section says, then pumps until a WM_QUIT. Durations print as
 * verdicts against bands. IsHungAppWindow is found with
 * GetProcAddress (the MSVC 6-era user32.lib may not export it).
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guimsg):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guimsg.c user32.lib
 */

#include "../common/f2kt.h"

/* What the wndproc saw last, printed after the calls. */
static UINT last_msg;
static WPARAM last_wparam;
static LPARAM last_lparam;
static int call_count;
static LRESULT last_ret;

/* The setup calls' last errors, captured where each call ran. */
static DWORD reg_err;
static DWORD create_err;

/* The wndproc: records and answers 0 to everything. */
static LRESULT CALLBACK recorder(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    /* WM_NCCREATE returning zero cancels the creation (CreateWindowEx
     * then returns NULL), so everything the section does not record
     * goes to DefWindowProc. */
    last_msg = msg;
    last_wparam = wparam;
    last_lparam = lparam;
    call_count++;
    last_ret = 0;
    return DefWindowProc(hwnd, msg, wparam, lparam);
}

static void reset_recorder(void)
{
    last_msg = 0;
    last_wparam = 0;
    last_lparam = 0;
    call_count = 0;
    last_ret = 0;
}

static void print_recorded(void)
{
    line("wndproc recorded: message=%lu wParam=%lu lParam=%ld count=%d ret=%ld",
         (unsigned long)last_msg, (unsigned long)last_wparam, (long)last_lparam, call_count,
         (long)last_ret);
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* Register the section's class; the result prints through reg_err. */
static ATOM register_class(const char *name)
{
    WNDCLASS wc;
    HMODULE inst;
    ATOM a;

    inst = GetModuleHandle(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = recorder;
    wc.hInstance = inst;
    wc.lpszClassName = name;
    arm();
    a = RegisterClass(&wc);
    reg_err = GetLastError();
    return a;
}

/* A hidden window of the class, explicit 320x200 at 0,0. */
static HWND make_window(const char *class_name)
{
    HMODULE inst;
    HWND h;

    inst = GetModuleHandle(NULL);
    arm();
    h = CreateWindowEx(0, class_name, "guimsg", WS_POPUP, 0, 0, 320, 200, NULL, NULL, inst, NULL);
    create_err = GetLastError();
    return h;
}

/* Register the class and create its window, printing both calls. */
static HWND open_window(const char *class_name)
{
    ATOM a;
    HWND h;

    a = register_class(class_name);
    line("RegisterClass(%s): atom nonzero %s err=%s", class_name, yesno(a != 0), le_of(reg_err));
    h = make_window(class_name);
    line("CreateWindowEx(%s, hidden, 320x200): non-NULL %s err=%s", class_name, yesno(h != NULL),
         le_of(create_err));
    return h;
}

static void destroy_window(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
}

/* --- post ---------------------------------------------------------- */

static void sec_post(void)
{
    HWND h;
    MSG msg;
    BOOL r;

    drain();
    reset_recorder();
    h = open_window("F2KGuimsgPost");

    arm();
    r = PostMessageA(h, WM_USER + 1, 11, 22);
    line("PostMessageA(h, WM_USER+1, 11, 22): ret=%d err=%s", r, le());

    arm();
    r = GetMessageA(&msg, NULL, 0, 0);
    line("GetMessageA(&msg, NULL, 0, 0): ret=%d err=%s message==WM_USER+1 %s wParam=%lu lParam=%ld "
         "hwnd==h %s",
         r, le(), yesno(msg.message == WM_USER + 1), (unsigned long)msg.wParam, (long)msg.lParam,
         yesno(msg.hwnd == h));

    destroy_window(h);
}

/* --- peek ---------------------------------------------------------- */

static void sec_peek(void)
{
    HWND h;
    MSG m;
    BOOL r;

    drain();
    reset_recorder();
    h = open_window("F2KGuimsgPeek");

    arm();
    r = PostMessageA(h, WM_USER + 1, 1, 0);
    line("PostMessageA(h, WM_USER+1, 1, 0): ret=%d err=%s", r, le());
    arm();
    r = PostMessageA(h, WM_USER + 2, 2, 0);
    line("PostMessageA(h, WM_USER+2, 2, 0): ret=%d err=%s", r, le());

    arm();
    r = PeekMessageA(&m, NULL, 0, 0, PM_NOREMOVE);
    line("PeekMessageA(&m, NULL, 0, 0, PM_NOREMOVE): ret=%d err=%s message=%lu wParam=%lu", r, le(),
         (unsigned long)m.message, (unsigned long)m.wParam);
    arm();
    r = PeekMessageA(&m, NULL, 0, 0, PM_NOREMOVE);
    line("PeekMessageA(..., PM_NOREMOVE), again: ret=%d err=%s message=%lu wParam=%lu", r, le(),
         (unsigned long)m.message, (unsigned long)m.wParam);
    arm();
    r = PeekMessageA(&m, NULL, 0, 0, PM_REMOVE);
    line("PeekMessageA(..., PM_REMOVE): ret=%d err=%s message=%lu wParam=%lu", r, le(),
         (unsigned long)m.message, (unsigned long)m.wParam);
    arm();
    r = PeekMessageA(&m, NULL, 0, 0, PM_REMOVE);
    line("PeekMessageA(..., PM_REMOVE), again: ret=%d err=%s message=%lu wParam=%lu", r, le(),
         (unsigned long)m.message, (unsigned long)m.wParam);
    arm();
    r = PeekMessageA(&m, NULL, 0, 0, PM_REMOVE);
    line("PeekMessageA(..., PM_REMOVE), empty queue: ret=%d err=%s", r, le());

    destroy_window(h);
}

/* --- quit ---------------------------------------------------------- */

static void sec_quit(void)
{
    MSG msg;
    BOOL r;

    drain();
    arm();
    PostQuitMessage(7);
    line("PostQuitMessage(7): err=%s", le());
    arm();
    r = GetMessageA(&msg, NULL, 0, 0);
    line("GetMessageA(&msg, NULL, 0, 0): ret=%d err=%s message==WM_QUIT %s wParam=%lu", r, le(),
         yesno(msg.message == WM_QUIT), (unsigned long)msg.wParam);
}

/* --- dispatch ------------------------------------------------------ */

static void sec_dispatch(void)
{
    HWND h;
    MSG msg;
    BOOL r;
    LRESULT d;

    drain();
    reset_recorder();
    h = open_window("F2KGuimsgDispatch");

    arm();
    r = PostMessageA(h, WM_USER + 5, 33, 44);
    line("PostMessageA(h, WM_USER+5, 33, 44): ret=%d err=%s", r, le());
    arm();
    r = GetMessageA(&msg, NULL, 0, 0);
    line("GetMessageA(&msg, NULL, 0, 0): ret=%d err=%s message=%lu wParam=%lu lParam=%ld", r, le(),
         (unsigned long)msg.message, (unsigned long)msg.wParam, (long)msg.lParam);
    arm();
    r = TranslateMessage(&msg);
    line("TranslateMessage(&msg): ret=%d err=%s", r, le());
    arm();
    d = DispatchMessageA(&msg);
    line("DispatchMessageA(&msg): ret=%ld err=%s", (long)d, le());
    print_recorded();

    destroy_window(h);
}

/* --- send ---------------------------------------------------------- */

static void sec_send(void)
{
    HWND h;
    LRESULT r;

    drain();
    reset_recorder();
    h = open_window("F2KGuimsgSend");

    arm();
    r = SendMessageA(h, WM_USER + 6, 55, 66);
    line("SendMessageA(h, WM_USER+6, 55, 66): ret=%ld err=%s", (long)r, le());
    print_recorded();

    reset_recorder();
    arm();
    r = SendMessageW(h, WM_USER + 6, 55, 66);
    line("SendMessageW(h, WM_USER+6, 55, 66): ret=%ld err=%s", (long)r, le());
    print_recorded();

    destroy_window(h);
}

/* --- defproc ------------------------------------------------------- */

static void sec_defproc(void)
{
    HWND h1, h2;
    LRESULT r;
    BOOL b;

    drain();
    reset_recorder();
    h1 = open_window("F2KGuimsgDefproc");
    h2 = make_window("F2KGuimsgDefproc");
    line("CreateWindowEx(F2KGuimsgDefproc, hidden, 320x200), second: non-NULL %s err=%s",
         yesno(h2 != NULL), le_of(create_err));

    arm();
    r = DefWindowProcA(h1, WM_CLOSE, 0, 0);
    line("DefWindowProcA(h, WM_CLOSE, 0, 0): ret=%ld err=%s", (long)r, le());
    print_recorded();
    arm();
    b = IsWindow(h1);
    line("IsWindow(h) after the WM_CLOSE: %s err=%s", yesno(b != FALSE), le());

    reset_recorder();
    arm();
    r = DefWindowProcW(h2, WM_NULL, 0, 0);
    line("DefWindowProcW(h2, WM_NULL, 0, 0): ret=%ld err=%s", (long)r, le());
    print_recorded();

    destroy_window(h2);
}

/* --- threadmsg ----------------------------------------------------- */

static void sec_threadmsg(void)
{
    MSG m;
    DWORD tid;
    BOOL r;

    drain();
    tid = GetCurrentThreadId();
    arm();
    r = PostThreadMessageA(tid, WM_USER + 7, 1, 2);
    line("PostThreadMessageA(GetCurrentThreadId(), WM_USER+7, 1, 2): ret=%d err=%s", r, le());
    arm();
    r = GetMessageA(&m, NULL, 0, 0);
    line("GetMessageA(&m, NULL, 0, 0): ret=%d err=%s hwnd==NULL %s message=%lu wParam=%lu "
         "lParam=%ld",
         r, le(), yesno(m.hwnd == NULL), (unsigned long)m.message, (unsigned long)m.wParam,
         (long)m.lParam);
}

/* --- the wide window and the second thread ------------------------- */

#define MSG_TEST (WM_USER + 30)

/* A window handle no window has. */
#define BOGUS_HWND ((HWND)0x7FFFFFFC)

/* The registered message the wide procedure records too (0: none). */
static UINT g_registered;

/* What the wide procedure saw: the count of test and registered
 * messages, the last one's parameters, its thread, GetMessageTime
 * inside it; the event set on each. */
static volatile LONG w_count;
static UINT w_msg;
static WPARAM w_wparam;
static LPARAM w_lparam;
static DWORD w_thread;
static LONG w_time;
static HANDLE w_handled;

static LRESULT CALLBACK wide_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == MSG_TEST || (g_registered != 0 && msg == g_registered)) {
        w_msg = msg;
        w_wparam = wparam;
        w_lparam = lparam;
        w_thread = GetCurrentThreadId();
        w_time = GetMessageTime();
        InterlockedIncrement((LONG *)&w_count);
        if (w_handled != NULL) {
            SetEvent(w_handled);
        }
        return (LRESULT)(wparam + lparam);
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void reset_wide(void)
{
    w_count = 0;
    w_msg = 0;
    w_wparam = 0;
    w_lparam = 0;
    w_thread = 0;
    w_time = 0;
    if (w_handled == NULL) {
        w_handled = CreateEventA(NULL, FALSE, FALSE, NULL);
    }
    ResetEvent(w_handled);
}

static HWND make_wide(const WCHAR *title)
{
    static BOOL registered;
    WNDCLASSW wc;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = wide_proc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = L"F2KGuimsgW";
        registered = RegisterClassW(&wc) != 0;
    }
    return CreateWindowExW(0, L"F2KGuimsgW", title, WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                           GetModuleHandle(NULL), NULL);
}

/* What the wide procedure recorded, after a call; then a fresh start. */
static void print_wide(DWORD expected_thread)
{
    line("  procedure saw: count=%ld message is the test one %s, the registered one %s, "
         "wParam=%lu lParam=%ld, on the expected thread %s",
         (long)w_count, yesno(w_msg == MSG_TEST), yesno(g_registered != 0 && w_msg == g_registered),
         (unsigned long)w_wparam, (long)w_lparam, yesno(w_count > 0 && w_thread == expected_thread));
    reset_wide();
}

static void drain_w(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
}

typedef struct {
    DWORD busy_ms;  /* how long it sleeps after reading its queue once */
    HANDLE ready;
    HANDLE thread;
    DWORD tid;
    HWND window;
} worker_t;

static DWORD WINAPI worker_main(LPVOID param)
{
    worker_t *w = (worker_t *)param;
    MSG m;

    w->window = make_wide(L"worker");
    PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    SetEvent(w->ready);
    if (w->busy_ms != 0) {
        Sleep(w->busy_ms);
    }
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        DispatchMessageW(&m);
    }
    if (w->window != NULL) {
        DestroyWindow(w->window);
    }
    return 0;
}

/* Start the second thread and wait until its window is made. */
static int start_worker(worker_t *w, DWORD busy_ms)
{
    DWORD r;

    ZeroMemory(w, sizeof *w);
    w->busy_ms = busy_ms;
    w->ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    w->thread = CreateThread(NULL, 0, worker_main, w, 0, &w->tid);
    r = w->thread != NULL ? WaitForSingleObject(w->ready, WAIT_MS) : WAIT_FAILED;
    line("the second thread made its window (busy %lu ms after): %s, %s", busy_ms, wr(r),
         yesno(w->window != NULL));
    return r == WAIT_OBJECT_0 && w->window != NULL;
}

/* Ask it to quit, and wait for it as long as it may still be busy. */
static void stop_worker(worker_t *w)
{
    DWORD r;

    if (w->thread != NULL) {
        PostThreadMessageW(w->tid, WM_QUIT, 0, 0);
        r = WaitForSingleObject(w->thread, w->busy_ms + WAIT_MS);
        line("the second thread ended: %s", wr(r));
        if (r != WAIT_OBJECT_0) {
            TerminateThread(w->thread, 1);
        }
        CloseHandle(w->thread);
    }
    if (w->ready != NULL) {
        CloseHandle(w->ready);
    }
}

/* --- regmsg -------------------------------------------------------- */

static void print_registered(const char *call, UINT r, UINT first)
{
    line("%s: in 0xC000-0xFFFF %s, the first value %s err=%s", call,
         yesno(r >= 0xC000 && r <= 0xFFFF), yesno(r == first), le());
}

static void sec_regmsg(void)
{
    UINT first, r;
    HWND h;
    LRESULT lr;
    int faulted = 0;

    drain_w();
    reset_wide();
    arm();
    first = RegisterWindowMessageW(L"F2KGuimsgRegistered");
    print_registered("RegisterWindowMessageW(L\"F2KGuimsgRegistered\")", first, first);
    arm();
    r = RegisterWindowMessageW(L"F2KGuimsgRegistered");
    print_registered("RegisterWindowMessageW(L\"F2KGuimsgRegistered\") again", r, first);
    arm();
    r = RegisterWindowMessageA("F2KGuimsgRegistered");
    print_registered("RegisterWindowMessageA(\"F2KGuimsgRegistered\")", r, first);
    arm();
    r = RegisterWindowMessageW(L"f2kguimsgREGISTERED");
    print_registered("RegisterWindowMessageW(L\"f2kguimsgREGISTERED\")", r, first);
    arm();
    r = RegisterWindowMessageA("f2kguimsgREGISTERED");
    print_registered("RegisterWindowMessageA(\"f2kguimsgREGISTERED\")", r, first);
    arm();
    r = RegisterWindowMessageW(L"F2KGuimsgOther");
    print_registered("RegisterWindowMessageW(L\"F2KGuimsgOther\")", r, first);
    arm();
    r = RegisterClipboardFormatW(L"F2KGuimsgRegistered");
    print_registered("RegisterClipboardFormatW(L\"F2KGuimsgRegistered\")", r, first);
    arm();
    r = RegisterWindowMessageW(L"");
    line("RegisterWindowMessageW(L\"\"): ret=%u err=%s", r, le());
    arm();
    __try {
        r = RegisterWindowMessageW(NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    if (faulted) {
        line("RegisterWindowMessageW(NULL): faulted err=%s", le());
    } else {
        line("RegisterWindowMessageW(NULL): ret=%u err=%s", r, le());
    }

    g_registered = first;
    h = make_wide(L"regmsg");
    arm();
    lr = SendMessageW(h, first, 3, 4);
    line("SendMessageW(h, the registered message, 3, 4): ret=%ld err=%s", (long)lr, le());
    print_wide(GetCurrentThreadId());
    g_registered = 0;
    DestroyWindow(h);
    drain_w();
}

/* --- msgpos -------------------------------------------------------- */

/* GetMessageTime and GetMessagePos against a retrieved message. */
static void print_pos(const char *after, const MSG *m)
{
    LONG t;
    DWORD p;

    t = GetMessageTime();
    p = GetMessagePos();
    line("  after %s: GetMessageTime the message's time %s, GetMessagePos the message's pt %s",
         after, yesno(t == (LONG)m->time),
         yesno((short)LOWORD(p) == m->pt.x && (short)HIWORD(p) == m->pt.y));
}

static void sec_msgpos(void)
{
    HWND h;
    MSG m1, m2, m3, m4;
    DWORD t0, t1;
    LONG before;
    BOOL r;

    drain_w();
    reset_wide();
    arm();
    before = GetMessageTime();
    line("GetMessageTime before any message: 0 %s err=%s", yesno(before == 0), le());
    h = make_wide(L"msgpos");

    t0 = GetTickCount();
    PostMessageW(h, MSG_TEST, 1, 0);
    Sleep(100);
    PostMessageW(h, MSG_TEST, 2, 0);
    t1 = GetTickCount();
    line("two messages posted 100 ms apart");

    arm();
    r = GetMessageW(&m1, NULL, 0, 0);
    line("GetMessageW: ret=%d err=%s wParam=%lu; its time within the posting's ticks %s", r, le(),
         (unsigned long)m1.wParam, yesno(m1.time - t0 <= t1 - t0));
    print_pos("the first GetMessageW", &m1);
    arm();
    r = GetMessageW(&m2, NULL, 0, 0);
    line("GetMessageW: ret=%d err=%s wParam=%lu; 80-1000 ms after the first %s", r, le(),
         (unsigned long)m2.wParam, band(m2.time - m1.time, 80, 1000));
    print_pos("the second GetMessageW", &m2);

    arm();
    SendMessageW(h, MSG_TEST, 3, 0);
    line("SendMessageW(h, WM_USER+30, 3, 0): GetMessageTime inside the procedure the second "
         "message's %s",
         yesno(w_time == (LONG)m2.time));
    reset_wide();
    print_pos("SendMessageW", &m2);

    PostMessageW(h, MSG_TEST, 4, 0);
    Sleep(50);
    PostMessageW(h, MSG_TEST, 5, 0);
    arm();
    r = PeekMessageW(&m3, NULL, 0, 0, PM_REMOVE);
    line("PeekMessageW(PM_REMOVE): ret=%d err=%s wParam=%lu", r, le(), (unsigned long)m3.wParam);
    print_pos("PeekMessageW PM_REMOVE", &m3);
    arm();
    r = PeekMessageW(&m4, NULL, 0, 0, PM_NOREMOVE);
    line("PeekMessageW(PM_NOREMOVE): ret=%d err=%s wParam=%lu; GetMessageTime the third "
         "message's %s",
         r, le(), (unsigned long)m4.wParam, yesno(GetMessageTime() == (LONG)m3.time));
    print_pos("PeekMessageW PM_NOREMOVE", &m4);

    DestroyWindow(h);
    drain_w();
}

/* --- wait ---------------------------------------------------------- */

static DWORD WINAPI late_poster(LPVOID param)
{
    Sleep(200);
    PostMessageW((HWND)param, MSG_TEST, 9, 0);
    return 0;
}

static void sec_wait(void)
{
    HWND h;
    MSG m;
    DWORD t, elapsed;
    BOOL r;
    HANDLE th;
    DWORD tid;

    drain_w();
    reset_wide();
    h = make_wide(L"wait");

    PostMessageW(h, MSG_TEST, 1, 0);
    t = GetTickCount();
    arm();
    r = WaitMessage();
    elapsed = GetTickCount() - t;
    line("WaitMessage with a message posted: ret=%d err=%s, at once (0-300 ms) %s", r, le(),
         band(elapsed, 0, 300));
    arm();
    r = PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    line("PeekMessageW(PM_NOREMOVE): ret=%d err=%s the posted message %s", r, le(),
         yesno(r && m.message == MSG_TEST));

    SetTimer(h, 1, 300, NULL);
    t = GetTickCount();
    arm();
    r = WaitMessage();
    elapsed = GetTickCount() - t;
    line("WaitMessage after the message was peeked, a 300 ms timer set: ret=%d err=%s, "
         "200-3000 ms %s",
         r, le(), band(elapsed, 200, 3000));
    KillTimer(h, 1);
    drain_w();

    SetTimer(h, 2, 4000, NULL);
    th = CreateThread(NULL, 0, late_poster, h, 0, &tid);
    t = GetTickCount();
    arm();
    r = WaitMessage();
    elapsed = GetTickCount() - t;
    line("WaitMessage while a second thread posts after 200 ms: ret=%d err=%s, 100-3000 ms %s", r,
         le(), band(elapsed, 100, 3000));
    arm();
    r = PeekMessageW(&m, NULL, MSG_TEST, MSG_TEST, PM_REMOVE);
    line("PeekMessageW(WM_USER+30, PM_REMOVE): ret=%d err=%s wParam=%lu", r, le(),
         r ? (unsigned long)m.wParam : 0ul);
    KillTimer(h, 2);
    if (th != NULL) {
        WaitForSingleObject(th, WAIT_MS);
        CloseHandle(th);
    }
    DestroyWindow(h);
    drain_w();
}

/* --- smto ---------------------------------------------------------- */

/* The result's sentinel: the procedures never answer it. */
#define RESULT_UNSET 0xDEADBEEF

static void smto_w(const char *label, HWND h, WPARAM wp, LPARAM lp, UINT flags, UINT timeout,
                   DWORD expected_thread)
{
    DWORD res = RESULT_UNSET;
    DWORD t, elapsed;
    LRESULT r;
    DWORD e;

    t = GetTickCount();
    arm();
    r = SendMessageTimeoutW(h, MSG_TEST, wp, lp, flags, timeout, &res);
    e = GetLastError();
    elapsed = GetTickCount() - t;
    line("SendMessageTimeoutW(%s, %lu, %ld, timeout %u): ret=%ld err=%s result=%s; "
         "under 200 ms %s, 250-1500 ms %s",
         label, (unsigned long)wp, (long)lp, timeout, (long)r, le_of(e),
         res == RESULT_UNSET ? "untouched" : res == wp + lp ? "the procedure's" : "another",
         band(elapsed, 0, 199), band(elapsed, 250, 1500));
    print_wide(expected_thread);
}

static void sec_smto(void)
{
    HWND h;
    worker_t w;
    DWORD res = RESULT_UNSET;
    LRESULT r;
    LONG later;

    drain_w();
    reset_wide();
    h = make_wide(L"smto");

    smto_w("h, SMTO_NORMAL", h, 3, 4, SMTO_NORMAL, 1000, GetCurrentThreadId());
    smto_w("h, SMTO_NORMAL", h, 5, 6, SMTO_NORMAL, 0, GetCurrentThreadId());
    smto_w("h, SMTO_ABORTIFHUNG", h, 7, 8, SMTO_ABORTIFHUNG, 1000, GetCurrentThreadId());
    arm();
    r = SendMessageTimeoutW(h, MSG_TEST, 9, 10, SMTO_NORMAL, 1000, NULL);
    line("SendMessageTimeoutW(h, SMTO_NORMAL, 9, 10, timeout 1000, no result pointer): ret=%ld "
         "err=%s",
         (long)r, le());
    print_wide(GetCurrentThreadId());
    arm();
    r = SendMessageTimeoutA(h, MSG_TEST, 11, 12, SMTO_NORMAL, 1000, &res);
    line("SendMessageTimeoutA(h, SMTO_NORMAL, 11, 12, timeout 1000): ret=%ld err=%s result=%s",
         (long)r, le(), res == RESULT_UNSET ? "untouched" : res == 23 ? "the procedure's" : "another");
    print_wide(GetCurrentThreadId());
    smto_w("a bogus window, SMTO_NORMAL", BOGUS_HWND, 1, 1, SMTO_NORMAL, 1000, 0);

    if (start_worker(&w, 0)) {
        smto_w("the second thread's window, SMTO_NORMAL", w.window, 13, 14, SMTO_NORMAL, 2000,
               w.tid);
        smto_w("the second thread's window, SMTO_ABORTIFHUNG", w.window, 15, 16,
               SMTO_ABORTIFHUNG, 2000, w.tid);
    }
    stop_worker(&w);
    reset_wide();

    if (start_worker(&w, 1500)) {
        smto_w("the busy thread's window, SMTO_NORMAL", w.window, 17, 18, SMTO_NORMAL, 300,
               w.tid);
        smto_w("the busy thread's window, SMTO_ABORTIFHUNG", w.window, 19, 20, SMTO_ABORTIFHUNG,
               300, w.tid);
    }
    stop_worker(&w);
    later = w_count;
    line("the timed-out messages the busy thread handled once it read its queue: %ld",
         (long)later);
    reset_wide();

    DestroyWindow(h);
    drain_w();
}

/* --- hung ---------------------------------------------------------- */

typedef BOOL (WINAPI *is_hung_fn)(HWND);

static void hung_check(is_hung_fn is_hung, HWND h, const char *when)
{
    BOOL r;

    if (is_hung == NULL) {
        return;
    }
    arm();
    r = is_hung(h);
    line("IsHungAppWindow(the second thread's window) %s: ret=%d err=%s", when, r, le());
}

static void sec_hung(void)
{
    is_hung_fn is_hung;
    worker_t w;
    HWND h;
    DWORD r;

    drain_w();
    reset_wide();
    is_hung = (is_hung_fn)GetProcAddress(GetModuleHandle("user32.dll"), "IsHungAppWindow");
    line("GetProcAddress(user32, IsHungAppWindow): non-NULL %s", yesno(is_hung != NULL));

    /* The thread idles in a message wait once first: a program still
     * starting up is never deemed hung. */
    h = make_wide(L"hung");
    SetTimer(h, 1, 100, NULL);
    WaitMessage();
    KillTimer(h, 1);
    drain_w();

    if (start_worker(&w, 9000)) {
        hung_check(is_hung, w.window, "at once");
        smto_w("the sleeping thread's window, SMTO_ABORTIFHUNG", w.window, 1, 2,
               SMTO_ABORTIFHUNG, 300, w.tid);
        Sleep(6500);
        line("6.5 s later");
        hung_check(is_hung, w.window, "after 6.5 s");
        smto_w("the sleeping thread's window, SMTO_ABORTIFHUNG", w.window, 3, 4,
               SMTO_ABORTIFHUNG, 2000, w.tid);
        smto_w("the sleeping thread's window, SMTO_NORMAL", w.window, 5, 6, SMTO_NORMAL, 300,
               w.tid);
        r = WaitForSingleObject(w_handled, WAIT_MS);
        line("the second thread handled a message once it read its queue again: %s", wr(r));
        Sleep(200);
        hung_check(is_hung, w.window, "after it read its queue again");
    }
    stop_worker(&w);
    line("messages the second thread handled: %ld", (long)w_count);
    reset_wide();
    DestroyWindow(h);
    drain_w();
}

/* --- notify -------------------------------------------------------- */

static void sec_notify(void)
{
    static const WCHAR text[] = { 'x', 0 };
    HWND h;
    worker_t w;
    DWORD t, elapsed, r;
    BOOL b;
    LONG count;

    drain_w();
    reset_wide();
    h = make_wide(L"notify");

    arm();
    b = SendNotifyMessageW(h, MSG_TEST, 1, 2);
    line("SendNotifyMessageW(h, WM_USER+30, 1, 2): ret=%d err=%s, handled before the return %s",
         b, le(), yesno(w_count == 1));
    print_wide(GetCurrentThreadId());
    arm();
    b = SendNotifyMessageA(h, MSG_TEST, 3, 4);
    line("SendNotifyMessageA(h, WM_USER+30, 3, 4): ret=%d err=%s, handled before the return %s",
         b, le(), yesno(w_count == 1));
    print_wide(GetCurrentThreadId());
    arm();
    b = SendNotifyMessageW(BOGUS_HWND, MSG_TEST, 1, 2);
    line("SendNotifyMessageW(a bogus window): ret=%d err=%s", b, le());

    if (start_worker(&w, 300)) {
        t = GetTickCount();
        arm();
        b = SendNotifyMessageW(w.window, MSG_TEST, 5, 6);
        elapsed = GetTickCount() - t;
        count = w_count;
        line("SendNotifyMessageW(the second thread's window, WM_USER+30, 5, 6): ret=%d err=%s, "
             "under 200 ms %s, handled before the return %s",
             b, le(), band(elapsed, 0, 199), yesno(count != 0));
        r = WaitForSingleObject(w_handled, WAIT_MS);
        line("the second thread handled it: %s", wr(r));
        print_wide(w.tid);
        arm();
        b = SendNotifyMessageW(w.window, WM_SETTEXT, 0, (LPARAM)text);
        line("SendNotifyMessageW(the second thread's window, WM_SETTEXT, 0, L\"x\"): ret=%d err=%s",
             b, le());
    }
    stop_worker(&w);
    reset_wide();
    DestroyWindow(h);
    drain_w();
}

static const section_t sections[] = {
    { "post", sec_post, F2KT_ALWAYS },
    { "peek", sec_peek, F2KT_ALWAYS },
    { "quit", sec_quit, F2KT_ALWAYS },
    { "dispatch", sec_dispatch, F2KT_ALWAYS },
    { "send", sec_send, F2KT_ALWAYS },
    { "defproc", sec_defproc, F2KT_ALWAYS },
    { "threadmsg", sec_threadmsg, F2KT_ALWAYS },
    { "regmsg", sec_regmsg, F2KT_ALWAYS },
    { "msgpos", sec_msgpos, F2KT_ALWAYS },
    { "wait", sec_wait, F2KT_ALWAYS },
    { "smto", sec_smto, F2KT_ALWAYS },
    { "hung", sec_hung, F2KT_ALWAYS },
    { "notify", sec_notify, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guimsg", sections, argc, argv);
}
