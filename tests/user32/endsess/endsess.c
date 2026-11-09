/*
 * endsess - the session's end as a window procedure sees it:
 * WM_QUERYENDSESSION and WM_ENDSESSION sent to the program's own windows
 * through SendMessageA/W, what the procedure receives (wParam, lParam,
 * on which thread) and what the sender gets back, and DefWindowProc's
 * answers to both. The session's end itself (csrss asking every
 * program's top-level windows, then ending them) cannot be captured on
 * the real machine; F2K's own boots drive it with the companion program
 * endkid.exe (built beside it from endkid.c), which the capture never
 * runs.
 *
 * Nothing here asks for a session's end: every message is sent by this
 * program to its own windows, and nothing it does depends on how the
 * system would answer them.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value, address
 * or thread id is printed, only whether one came back and how two
 * compare (yesno()); every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=. The window
 * procedure records the last of the two messages it received (message,
 * wParam, lParam, whether on the window's own thread), a count of them
 * and its answer; the recorded values print after the calls, never from
 * inside the procedure. lParam prints as eight hex digits:
 * ENDSESSION_LOGOFF is 0x80000000. Each section creates its own hidden
 * top-level window (explicit 320x200) of a class it registers itself,
 * and destroys it at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   query     SendMessageA(h, WM_QUERYENDSESSION, 0, 0) and with lParam
 *             ENDSESSION_LOGOFF to a procedure answering TRUE, then one
 *             answering FALSE; SendMessageW to a procedure that hands
 *             the message to DefWindowProc: the returns, the recorded
 *             values, DefWindowProc's answer inside the procedure
 *   end       SendMessageA(h, WM_ENDSESSION, TRUE, 0) and (FALSE,
 *             ENDSESSION_LOGOFF), SendMessageW(h, WM_ENDSESSION, TRUE,
 *             ENDSESSION_LOGOFF), each to a procedure that hands it to
 *             DefWindowProc: the returns, the recorded values, and
 *             IsWindow after each (the window stays)
 *   defproc   DefWindowProcA/W(h, WM_QUERYENDSESSION, 0, 0) and with
 *             ENDSESSION_LOGOFF, DefWindowProcA/W(h, WM_ENDSESSION,
 *             FALSE, 0), called directly: the answers, the procedure not
 *             called, IsWindow after
 *   thread    the two messages sent with SendMessageA to a window a
 *             second thread created and pumps: the returns, the values
 *             its procedure recorded, on that thread
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat endsess):
 *   cl /nologo /MD endkid.c user32.lib
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% endsess.c user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate it. */
#ifndef ENDSESSION_LOGOFF
#define ENDSESSION_LOGOFF 0x80000000
#endif

/* How the procedure answers the two messages. */
#define ANSWER_TRUE 0      /* TRUE to WM_QUERYENDSESSION, 0 to WM_ENDSESSION */
#define ANSWER_FALSE 1     /* 0 to both */
#define ANSWER_DEFAULT 2   /* DefWindowProc's answer */

/* The private message the thread section's window ends its thread on. */
#define WM_ENDSESS_STOP (WM_USER + 1)

static int answer_mode;

/* What the procedure saw last of the two messages, printed after the
 * calls. */
static UINT last_msg;
static WPARAM last_wparam;
static LPARAM last_lparam;
static DWORD last_tid;
static int call_count;
static LRESULT last_ret;

/* The setup calls' last errors, captured where each call ran. */
static DWORD reg_err;
static DWORD create_err;

/* The thread section's window and its thread. */
static HWND thread_window;
static DWORD thread_tid;
static HANDLE thread_ready;

static LRESULT CALLBACK recorder(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    LRESULT r;

    if (msg == WM_ENDSESS_STOP) {
        DestroyWindow(hwnd);
        PostQuitMessage(0);
        return 0;
    }
    if (msg != WM_QUERYENDSESSION && msg != WM_ENDSESSION) {
        return DefWindowProc(hwnd, msg, wparam, lparam);
    }
    if (answer_mode == ANSWER_DEFAULT) {
        r = DefWindowProc(hwnd, msg, wparam, lparam);
    } else if (answer_mode == ANSWER_TRUE && msg == WM_QUERYENDSESSION) {
        r = TRUE;
    } else {
        r = 0;
    }
    last_msg = msg;
    last_wparam = wparam;
    last_lparam = lparam;
    last_tid = GetCurrentThreadId();
    call_count++;
    last_ret = r;
    return r;
}

static void reset_recorder(int mode)
{
    answer_mode = mode;
    last_msg = 0;
    last_wparam = 0;
    last_lparam = 0;
    last_tid = 0;
    call_count = 0;
    last_ret = 0;
}

static const char *message_name(UINT msg)
{
    switch (msg) {
    case 0:
        return "none";
    case WM_QUERYENDSESSION:
        return "WM_QUERYENDSESSION";
    case WM_ENDSESSION:
        return "WM_ENDSESSION";
    }
    return "another";
}

/* The recorded values; `tid` is the thread the window belongs to. */
static void print_recorded(DWORD tid)
{
    line("procedure recorded: message=%s wParam=%lu lParam=0x%08lX on the window's thread %s "
         "count=%d ret=%ld",
         message_name(last_msg), (unsigned long)last_wparam, (unsigned long)last_lparam,
         yesno(call_count > 0 && last_tid == tid), call_count, (long)last_ret);
}

/* Register the section's class; the result prints through reg_err. */
static ATOM register_class(const char *name)
{
    WNDCLASS wc;
    ATOM a;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = recorder;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = name;
    arm();
    a = RegisterClass(&wc);
    reg_err = GetLastError();
    return a;
}

/* A hidden top-level window of the class, explicit 320x200 at 0,0. */
static HWND make_window(const char *class_name)
{
    HWND h;

    arm();
    h = CreateWindowEx(0, class_name, "endsess", WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                       GetModuleHandle(NULL), NULL);
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

/* --- query --------------------------------------------------------- */

static void sec_query(void)
{
    HWND h;
    LRESULT r;
    DWORD me;

    me = GetCurrentThreadId();
    h = open_window("F2KEndsessQuery");

    reset_recorder(ANSWER_TRUE);
    arm();
    r = SendMessageA(h, WM_QUERYENDSESSION, 0, 0);
    line("SendMessageA(h, WM_QUERYENDSESSION, 0, 0), answering TRUE: ret=%ld err=%s", (long)r, le());
    print_recorded(me);

    reset_recorder(ANSWER_TRUE);
    arm();
    r = SendMessageA(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF);
    line("SendMessageA(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF), answering TRUE: ret=%ld err=%s",
         (long)r, le());
    print_recorded(me);

    reset_recorder(ANSWER_FALSE);
    arm();
    r = SendMessageA(h, WM_QUERYENDSESSION, 0, 0);
    line("SendMessageA(h, WM_QUERYENDSESSION, 0, 0), answering FALSE: ret=%ld err=%s", (long)r, le());
    print_recorded(me);

    reset_recorder(ANSWER_DEFAULT);
    arm();
    r = SendMessageW(h, WM_QUERYENDSESSION, 0, 0);
    line("SendMessageW(h, WM_QUERYENDSESSION, 0, 0), DefWindowProc's answer: ret=%ld err=%s", (long)r,
         le());
    print_recorded(me);

    reset_recorder(ANSWER_DEFAULT);
    arm();
    r = SendMessageW(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF);
    line("SendMessageW(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF), DefWindowProc's answer: ret=%ld "
         "err=%s",
         (long)r, le());
    print_recorded(me);

    destroy_window(h);
}

/* --- end ----------------------------------------------------------- */

static void sec_end(void)
{
    static const struct {
        int wide;
        WPARAM wparam;
        LPARAM lparam;
        const char *name;
    } calls[] = {
        { 0, TRUE, 0, "SendMessageA(h, WM_ENDSESSION, TRUE, 0)" },
        { 0, FALSE, (LPARAM)ENDSESSION_LOGOFF, "SendMessageA(h, WM_ENDSESSION, FALSE, ENDSESSION_LOGOFF)" },
        { 1, TRUE, (LPARAM)ENDSESSION_LOGOFF, "SendMessageW(h, WM_ENDSESSION, TRUE, ENDSESSION_LOGOFF)" },
    };
    HWND h;
    LRESULT r;
    BOOL alive;
    DWORD me;
    int i;

    me = GetCurrentThreadId();
    h = open_window("F2KEndsessEnd");

    for (i = 0; i < (int)(sizeof calls / sizeof calls[0]); i++) {
        reset_recorder(ANSWER_DEFAULT);
        arm();
        if (calls[i].wide) {
            r = SendMessageW(h, WM_ENDSESSION, calls[i].wparam, calls[i].lparam);
        } else {
            r = SendMessageA(h, WM_ENDSESSION, calls[i].wparam, calls[i].lparam);
        }
        line("%s, DefWindowProc's answer: ret=%ld err=%s", calls[i].name, (long)r, le());
        print_recorded(me);
        arm();
        alive = IsWindow(h);
        line("IsWindow(h) after it: %s err=%s", yesno(alive != FALSE), le());
    }

    destroy_window(h);
}

/* --- defproc ------------------------------------------------------- */

static void sec_defproc(void)
{
    HWND h;
    LRESULT r;
    BOOL alive;

    h = open_window("F2KEndsessDefproc");
    reset_recorder(ANSWER_TRUE);

    arm();
    r = DefWindowProcA(h, WM_QUERYENDSESSION, 0, 0);
    line("DefWindowProcA(h, WM_QUERYENDSESSION, 0, 0): ret=%ld err=%s", (long)r, le());
    arm();
    r = DefWindowProcA(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF);
    line("DefWindowProcA(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF): ret=%ld err=%s", (long)r, le());
    arm();
    r = DefWindowProcW(h, WM_QUERYENDSESSION, 0, 0);
    line("DefWindowProcW(h, WM_QUERYENDSESSION, 0, 0): ret=%ld err=%s", (long)r, le());
    arm();
    r = DefWindowProcW(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF);
    line("DefWindowProcW(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF): ret=%ld err=%s", (long)r, le());
    arm();
    r = DefWindowProcA(h, WM_ENDSESSION, FALSE, 0);
    line("DefWindowProcA(h, WM_ENDSESSION, FALSE, 0): ret=%ld err=%s", (long)r, le());
    arm();
    r = DefWindowProcW(h, WM_ENDSESSION, FALSE, 0);
    line("DefWindowProcW(h, WM_ENDSESSION, FALSE, 0): ret=%ld err=%s", (long)r, le());
    line("procedure called: %s", yesno(call_count != 0));
    arm();
    alive = IsWindow(h);
    line("IsWindow(h) after them: %s err=%s", yesno(alive != FALSE), le());

    destroy_window(h);
}

/* --- thread -------------------------------------------------------- */

/* The second thread: its window, made on this thread, then its message
 * loop until the window's WM_ENDSESS_STOP ends it. */
static DWORD WINAPI window_thread(LPVOID unused)
{
    MSG m;

    (void)unused;
    thread_window = make_window("F2KEndsessThread");
    SetEvent(thread_ready);
    if (thread_window == NULL) {
        return 1;
    }
    while (GetMessageA(&m, NULL, 0, 0) > 0) {
        DispatchMessageA(&m);
    }
    return 0;
}

static void sec_thread(void)
{
    HANDLE th;
    LRESULT r;
    DWORD w;
    ATOM a;

    a = register_class("F2KEndsessThread");
    line("RegisterClass(F2KEndsessThread): atom nonzero %s err=%s", yesno(a != 0), le_of(reg_err));
    reset_recorder(ANSWER_TRUE);
    thread_window = NULL;
    thread_ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, window_thread, NULL, 0, &thread_tid);
    if (th == NULL || thread_ready == NULL) {
        line("CreateThread or CreateEventA failed, err=%lu", GetLastError());
        return;
    }
    w = WaitForSingleObject(thread_ready, WAIT_MS);
    line("the second thread's window: made %s err=%s (wait %s)", yesno(thread_window != NULL),
         le_of(create_err), wr(w));
    if (thread_window == NULL) {
        WaitForSingleObject(th, WAIT_MS);
        CloseHandle(th);
        CloseHandle(thread_ready);
        return;
    }

    arm();
    r = SendMessageA(thread_window, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF);
    line("SendMessageA(h, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF), answering TRUE: ret=%ld err=%s",
         (long)r, le());
    print_recorded(thread_tid);
    arm();
    r = SendMessageA(thread_window, WM_ENDSESSION, TRUE, ENDSESSION_LOGOFF);
    line("SendMessageA(h, WM_ENDSESSION, TRUE, ENDSESSION_LOGOFF): ret=%ld err=%s", (long)r, le());
    print_recorded(thread_tid);

    PostMessageA(thread_window, WM_ENDSESS_STOP, 0, 0);
    w = WaitForSingleObject(th, WAIT_MS);
    line("the second thread's end: %s", wr(w));
    if (w != WAIT_OBJECT_0) {
        TerminateThread(th, 1);
    }
    CloseHandle(th);
    CloseHandle(thread_ready);
}

static const section_t sections[] = {
    { "query", sec_query, F2KT_ALWAYS },
    { "end", sec_end, F2KT_ALWAYS },
    { "defproc", sec_defproc, F2KT_ALWAYS },
    { "thread", sec_thread, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("endsess", sections, argc, argv);
}
