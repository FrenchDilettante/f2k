/*
 * msgwait - the queue calls guimsg does not cover: MsgWaitForMultipleObjects
 * (and its Ex form) against each QS_* mask, GetQueueStatus's current and
 * new bits, GetInputState, InSendMessage and InSendMessageEx's ISMEX_*
 * flags, ReplyMessage, SendMessageCallbackA/W and when the callback
 * runs, BroadcastSystemMessage(A/W) to the program's own window,
 * Get/SetMessageExtraInfo, SetMessageQueue and WaitForInputIdle.
 *
 * Each section creates a hidden popup of a class it registers itself
 * (a visible top-most one for input) and drains its queue first. The
 * window procedure and the callbacks record what they see into a log
 * (with the thread they ran on as "main" or "second"); the log prints
 * after the calls, never from inside a procedure. Waits print their
 * result by name and how long they took as a verdict against a band.
 *
 * The input section injects keys and a mouse move with SendInput (found
 * with GetProcAddress, as keyinput does) only while its window is the
 * foreground window, and says so otherwise; the keys are Shift alone,
 * pressed and released. Nobody touches the machine while it runs.
 *
 * broadcast sends a message registered under the program's own name
 * (RegisterWindowMessageW), which no other program on the machine
 * handles; the recipients are BSM_APPLICATIONS, the program's window
 * among them; its BSF_QUERY case uses BSF_NOHANG.
 *
 * idle runs this program again as a child (msgwait.exe --child <mode>)
 * for WaitForInputIdle: a GUI child pumping at once, one sleeping
 * 1.5 s before its first read, and one that never reads a queue.
 *
 * MsgWaitForMultipleObjectsEx, InSendMessageEx, SetMessageExtraInfo,
 * SetMessageQueue and BroadcastSystemMessage(A/W) are found with
 * GetProcAddress (MSVC 6's headers lack the first three and the A/W
 * broadcast forms); a section says so and stops when one is missing.
 * QuerySendMessage and TranslateMessageEx are user32's internal
 * exports, undocumented, and not called.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value, address
 * or thread id is printed; every call under observation is armed with
 * the last-error sentinel and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   masks     MsgWaitForMultipleObjects with no handles, 0 ms, for each
 *             QS_* mask alone against a posted message, a message sent
 *             by a second thread (QS_SENDMESSAGE), a due timer
 *             (QS_TIMER), an invalidated window (QS_PAINT); a message
 *             already peeked (not new) and MWMO_INPUTAVAILABLE on it;
 *             an event signaled and a message together; fWaitAll over
 *             two events with and without a message
 *   status    GetQueueStatus (each word) after each step: an empty
 *             queue, a post, a second call, a peek without removing, a
 *             peek removing, an invalidation, a due timer, a second
 *             thread's send waiting, a PostQuitMessage; masks that
 *             leave the bits out
 *   input     the foreground window's GetInputState and GetQueueStatus
 *             before and after SendInput of Shift and of a mouse move,
 *             MsgWaitForMultipleObjects for QS_KEY, QS_MOUSEMOVE and
 *             QS_INPUT; GetMessageExtraInfo after reading input sent
 *             with dwExtraInfo 0x5A5A0001
 *   insend    InSendMessage and InSendMessageEx outside any send, in a
 *             send from the same thread, a SendMessageW, a
 *             SendNotifyMessageW and a SendMessageCallbackW from a
 *             second thread, and after ReplyMessage inside one
 *   reply     ReplyMessage outside a send and inside one from the same
 *             thread (FALSE), inside a second thread's SendMessageW:
 *             TRUE, the sender's result (the reply's, not the
 *             procedure's), whether the sender woke before the
 *             procedure returned, a second ReplyMessage
 *   callback  SendMessageCallbackW and A to the thread's own window (the
 *             procedure and the callback, in order, against the return)
 *             and to a second thread's window (the return at once, the
 *             callback only when the sender reads its queue); the
 *             callback's window, message, data and result; a bad window
 *   broadcast BroadcastSystemMessage, A and W, BSF_POSTMESSAGE,
 *             BSF_SENDNOTIFYMESSAGE and BSF_QUERY | BSF_NOHANG with the
 *             window answering BROADCAST_QUERY_DENY, BSF_IGNORECURRENTTASK;
 *             the returns, the recipients left, what the window got;
 *             unknown flags and recipients
 *   extra     SetMessageExtraInfo's previous value and GetMessageExtraInfo
 *             after it, and after GetMessageW of a posted message
 *   queue     SetMessageQueue(100), (1) and (0)
 *   idle      WaitForInputIdle on children that pump at once, sleep
 *             1.5 s first (300 ms: a timeout; then INFINITE), never make
 *             a window; on the program itself; on a closed handle
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat msgwait):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% msgwait.c user32.lib
 */

#include "../common/f2kt.h"

#ifndef QS_ALLPOSTMESSAGE
#define QS_ALLPOSTMESSAGE 0x0100
#endif
#define F2K_MWMO_WAITALL 0x0001
#define F2K_MWMO_ALERTABLE 0x0002
#define F2K_MWMO_INPUTAVAILABLE 0x0004
#define F2K_ISMEX_NOSEND 0x0000
#define F2K_ISMEX_SEND 0x0001
#define F2K_ISMEX_NOTIFY 0x0002
#define F2K_ISMEX_CALLBACK 0x0004
#define F2K_ISMEX_REPLIED 0x0008
#ifndef BSF_QUERY
#define BSF_QUERY 0x00000001
#define BSF_IGNORECURRENTTASK 0x00000002
#define BSF_POSTMESSAGE 0x00000010
#define BSM_APPLICATIONS 0x00000008
#endif
#ifndef BSF_NOHANG
#define BSF_NOHANG 0x00000008
#endif
#ifndef BSF_SENDNOTIFYMESSAGE
#define BSF_SENDNOTIFYMESSAGE 0x00000100
#endif
#ifndef BROADCAST_QUERY_DENY
#define BROADCAST_QUERY_DENY 0x424D5144
#endif

#define MSG_TEST (WM_USER + 40)
#define MSG_REPLY (WM_USER + 41)
#define MSG_INSEND (WM_USER + 42)

typedef DWORD (WINAPI *mwex_fn)(DWORD, const HANDLE *, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *insendex_fn)(LPVOID);
typedef LPARAM (WINAPI *setextra_fn)(LPARAM);
typedef BOOL (WINAPI *setqueue_fn)(int);
typedef long (WINAPI *bsm_fn)(DWORD, LPDWORD, UINT, WPARAM, LPARAM);

static mwex_fn mw_ex;
static insendex_fn in_send_ex;
static setextra_fn set_extra;
static setqueue_fn set_queue;
static bsm_fn bsm, bsm_a, bsm_w;

/* SendInput, as keyinput and mousein declare it. */
typedef struct {
    LONG dx;
    LONG dy;
    DWORD mouseData;
    DWORD dwFlags;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_mouse_input;

typedef struct {
    WORD wVk;
    WORD wScan;
    DWORD dwFlags;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_keybd_input;

typedef struct {
    DWORD type;
    union {
        f2k_mouse_input mi;
        f2k_keybd_input ki;
    } u;
} f2k_input;

typedef UINT (WINAPI *send_input_fn)(UINT, f2k_input *, int);
static send_input_fn send_input;

/* --- the log --------------------------------------------------------- */

#define LOG_MAX 48
static char log_lines[LOG_MAX][120];
static int log_count;
static CRITICAL_SECTION log_lock;
static DWORD main_thread;

static void note(const char *fmt, ...)
{
    va_list ap;
    char buf[100];

    va_start(ap, fmt);
    _vsnprintf(buf, sizeof buf - 1, fmt, ap);
    buf[sizeof buf - 1] = '\0';
    va_end(ap);
    EnterCriticalSection(&log_lock);
    if (log_count < LOG_MAX) {
        sprintf(log_lines[log_count], "%s: %s", GetCurrentThreadId() == main_thread ? "main" : "second", buf);
        log_count++;
    }
    LeaveCriticalSection(&log_lock);
}

static void print_log(const char *what)
{
    int i;

    EnterCriticalSection(&log_lock);
    line("%s: %d event(s)", what, log_count);
    for (i = 0; i < log_count; i++) {
        line("  %s", log_lines[i]);
    }
    log_count = 0;
    LeaveCriticalSection(&log_lock);
}

/* --- the window ------------------------------------------------------ */

static HWND main_window;
static UINT broadcast_msg;
static int reply_mode;          /* MSG_REPLY: 1 reply then sleep, 2 reply twice */
static BOOL reply_ret[2];
static DWORD reply_done_tick;
static DWORD insend_flags;
static BOOL insend_plain;

static const char *ismex(DWORD f)
{
    static char b[4][80];
    static int n;
    char *s = b[n++ & 3];

    sprintf(s, "0x%lX%s%s%s%s", f, f == 0 ? " ISMEX_NOSEND" : "", (f & F2K_ISMEX_SEND) ? " ISMEX_SEND" : "",
            (f & F2K_ISMEX_NOTIFY) ? " ISMEX_NOTIFY" : "", (f & F2K_ISMEX_CALLBACK) ? " ISMEX_CALLBACK" : "");
    if (f & F2K_ISMEX_REPLIED) {
        strcat(s, " ISMEX_REPLIED");
    }
    return s;
}

static LRESULT CALLBACK wait_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == MSG_TEST) {
        note("the procedure: MSG_TEST wParam=%lu", (unsigned long)wparam);
        return (LRESULT)(wparam + 100);
    }
    if (msg == MSG_INSEND) {
        insend_plain = InSendMessage();
        insend_flags = in_send_ex != NULL ? in_send_ex(NULL) : 0xFFFF;
        note("the procedure: InSendMessage %d, InSendMessageEx %s", insend_plain, ismex(insend_flags));
        if (wparam == 1) {
            ReplyMessage(5);
            insend_flags = in_send_ex != NULL ? in_send_ex(NULL) : 0xFFFF;
            note("the procedure: after ReplyMessage, InSendMessageEx %s", ismex(insend_flags));
        }
        return 0;
    }
    if (msg == MSG_REPLY) {
        arm();
        reply_ret[0] = ReplyMessage(42);
        note("the procedure: ReplyMessage(42): ret=%d err=%s", reply_ret[0], le());
        if (reply_mode == 2) {
            arm();
            reply_ret[1] = ReplyMessage(43);
            note("the procedure: ReplyMessage(43) again: ret=%d err=%s", reply_ret[1], le());
        }
        Sleep(300);
        reply_done_tick = GetTickCount();
        return 7;
    }
    if (msg == broadcast_msg && broadcast_msg != 0) {
        note("the procedure: the broadcast message wParam=%lu", (unsigned long)wparam);
        return wparam == 3 ? BROADCAST_QUERY_DENY : TRUE;
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
    wc.lpfnWndProc = wait_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"F2KMsgwait";
    done = RegisterClassW(&wc) != 0;
}

static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
}

static HWND make_window(DWORD ex, DWORD style)
{
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    register_class();
    main_window = CreateWindowExW(ex, L"F2KMsgwait", L"msgwait", WS_POPUP | style, (cx - 200) / 2,
                                  (cy - 150) / 2, 200, 150, NULL, NULL, GetModuleHandleA(NULL), NULL);
    line("setup: the window created: %s", yesno(main_window != NULL));
    if (style & WS_VISIBLE) {
        UpdateWindow(main_window);
    }
    drain();
    log_count = 0;
    return main_window;
}

static void end_window(void)
{
    DestroyWindow(main_window);
    main_window = NULL;
    drain();
    log_count = 0;
}

/* A second thread that sends main_window a message (and blocks there
 * until the main thread takes it), or does another job. */
typedef struct {
    int job;                /* 1 SendMessageW, 2 SendNotifyMessageW, 3 SendMessageCallbackW,
                               4 SendMessageW MSG_REPLY, 5 make a window and pump */
    UINT msg;
    WPARAM wparam;
    LRESULT result;
    DWORD result_tick;
    HWND window;
    HANDLE ready;
    HANDLE stop;
} job_t;

static VOID CALLBACK nothing_cb(HWND h, UINT m, DWORD d, LRESULT r)
{
}

static DWORD WINAPI job_thread(LPVOID param)
{
    job_t *j = (job_t *)param;
    MSG m;

    switch (j->job) {
    case 1:
    case 4:
        j->result = SendMessageW(main_window, j->msg, j->wparam, 0);
        j->result_tick = GetTickCount();
        break;
    case 2:
        SendNotifyMessageW(main_window, j->msg, j->wparam, 0);
        break;
    case 3:
        SendMessageCallbackW(main_window, j->msg, j->wparam, 0, nothing_cb, 0);
        Sleep(500);
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            DispatchMessageW(&m);
        }
        break;
    case 5:
        j->window = CreateWindowExW(0, L"F2KMsgwait", L"second", WS_POPUP, 0, 0, 10, 10, NULL, NULL,
                                    GetModuleHandleA(NULL), NULL);
        SetEvent(j->ready);
        while (MsgWaitForMultipleObjects(1, &j->stop, FALSE, 10000, QS_ALLINPUT) == WAIT_OBJECT_0 + 1) {
            while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
                DispatchMessageW(&m);
            }
        }
        DestroyWindow(j->window);
        break;
    }
    return 0;
}

static HANDLE start_job(job_t *j, int job, UINT msg, WPARAM wparam)
{
    DWORD tid;

    ZeroMemory(j, sizeof *j);
    j->job = job;
    j->msg = msg;
    j->wparam = wparam;
    j->ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    j->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    return CreateThread(NULL, 0, job_thread, j, 0, &tid);
}

static void end_job(job_t *j, HANDLE t)
{
    SetEvent(j->stop);
    if (t != NULL) {
        /* Keep taking sends while it ends. */
        while (MsgWaitForMultipleObjects(1, &t, FALSE, WAIT_MS, QS_SENDMESSAGE) == WAIT_OBJECT_0 + 1) {
            MSG m;
            PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
        }
        CloseHandle(t);
    }
    CloseHandle(j->ready);
    CloseHandle(j->stop);
}

/* Wait until the second thread's send is queued: QS_SENDMESSAGE shows
 * in GetQueueStatus (its call does not take the send). */
static int send_waiting(void)
{
    DWORD start = GetTickCount();

    while (GetTickCount() - start < 2000) {
        if (HIWORD(GetQueueStatus(QS_SENDMESSAGE)) & QS_SENDMESSAGE) {
            return 1;
        }
        Sleep(10);
    }
    return 0;
}

/* --- masks ----------------------------------------------------------- */

static const char *mw_result(DWORD r, DWORD n)
{
    static char b[4][40];
    static int k;
    char *s = b[k++ & 3];

    if (r == WAIT_OBJECT_0 + n) {
        sprintf(s, "WAIT_OBJECT_0+%lu (input)", n);
    } else if (r < WAIT_OBJECT_0 + n) {
        sprintf(s, "WAIT_OBJECT_0+%lu", r);
    } else {
        return wr(r);
    }
    return s;
}

static void mw(const char *what, DWORD n, const HANDLE *h, BOOL all, DWORD ms, DWORD mask)
{
    DWORD r, start = GetTickCount();

    arm();
    r = MsgWaitForMultipleObjects(n, (HANDLE *)h, all, ms, mask);
    line("MsgWaitForMultipleObjects(%s): %s err=%s, at once: %s", what, mw_result(r, n), le(),
         band(GetTickCount() - start, 0, 100));
}

static void mwx(const char *what, DWORD n, const HANDLE *h, DWORD ms, DWORD mask, DWORD flags)
{
    DWORD r, start = GetTickCount();

    arm();
    r = mw_ex(n, h, ms, mask, flags);
    line("MsgWaitForMultipleObjectsEx(%s): %s err=%s, at once: %s", what, mw_result(r, n), le(),
         band(GetTickCount() - start, 0, 100));
}

static const struct {
    DWORD mask;
    const char *name;
} masks[] = {
    { QS_KEY, "QS_KEY" },
    { QS_MOUSEMOVE, "QS_MOUSEMOVE" },
    { QS_MOUSEBUTTON, "QS_MOUSEBUTTON" },
    { QS_POSTMESSAGE, "QS_POSTMESSAGE" },
    { QS_TIMER, "QS_TIMER" },
    { QS_PAINT, "QS_PAINT" },
    { QS_SENDMESSAGE, "QS_SENDMESSAGE" },
    { QS_HOTKEY, "QS_HOTKEY" },
    { QS_ALLPOSTMESSAGE, "QS_ALLPOSTMESSAGE" },
    { QS_INPUT, "QS_INPUT" },
    { QS_ALLEVENTS, "QS_ALLEVENTS" },
    { QS_ALLINPUT, "QS_ALLINPUT" },
    { 0, NULL }
};

static void each_mask(const char *state)
{
    int i;
    char what[96];

    for (i = 0; masks[i].name != NULL; i++) {
        sprintf(what, "%s, %s", state, masks[i].name);
        mw(what, 0, NULL, FALSE, 0, masks[i].mask);
    }
}

static void sec_masks(void)
{
    HWND h;
    MSG m;
    HANDLE ev[2], t;
    job_t j;
    BOOL got;

    h = make_window(0, 0);
    ev[0] = CreateEventW(NULL, TRUE, TRUE, NULL);
    ev[1] = CreateEventW(NULL, TRUE, FALSE, NULL);

    each_mask("the queue empty");
    PostMessageW(h, MSG_TEST, 1, 0);
    each_mask("a message posted");
    drain();
    PostThreadMessageW(GetCurrentThreadId(), MSG_TEST, 2, 0);
    mw("a thread message posted, QS_POSTMESSAGE", 0, NULL, FALSE, 0, QS_POSTMESSAGE);
    mw("a thread message posted, QS_ALLPOSTMESSAGE", 0, NULL, FALSE, 0, QS_ALLPOSTMESSAGE);
    drain();

    t = start_job(&j, 1, MSG_TEST, 3);
    line("a second thread's send is waiting: %s", yesno(send_waiting()));
    each_mask("a second thread's send waiting");
    mw("the send waiting, QS_POSTMESSAGE, 300 ms", 0, NULL, FALSE, 300, QS_POSTMESSAGE);
    drain();
    end_job(&j, t);
    line("the second thread's send returned %ld", (long)j.result);
    print_log("received");

    SetTimer(h, 7, 50, NULL);
    Sleep(150);
    each_mask("a timer due");
    KillTimer(h, 7);
    drain();

    ShowWindow(h, SW_SHOWNA);
    ValidateRect(h, NULL);
    drain();
    InvalidateRect(h, NULL, FALSE);
    each_mask("the window invalidated");
    ShowWindow(h, SW_HIDE);
    ValidateRect(h, NULL);
    drain();

    PostMessageW(h, MSG_TEST, 4, 0);
    got = PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    line("a message posted, then peeked (PM_NOREMOVE): seen %s", yesno(got && m.message == MSG_TEST));
    mw("the peeked message, QS_ALLINPUT", 0, NULL, FALSE, 0, QS_ALLINPUT);
    mw("the peeked message, QS_ALLINPUT, 200 ms", 0, NULL, FALSE, 200, QS_ALLINPUT);
    if (mw_ex != NULL) {
        mwx("the peeked message, QS_ALLINPUT, MWMO_INPUTAVAILABLE", 0, NULL, 0, QS_ALLINPUT,
            F2K_MWMO_INPUTAVAILABLE);
        mwx("the peeked message, QS_ALLINPUT, MWMO_WAITALL", 0, NULL, 0, QS_ALLINPUT, F2K_MWMO_WAITALL);
        mwx("the peeked message, QS_ALLINPUT, MWMO_ALERTABLE", 0, NULL, 0, QS_ALLINPUT, F2K_MWMO_ALERTABLE);
    } else {
        line("GetProcAddress(user32, MsgWaitForMultipleObjectsEx): NULL");
    }
    drain();

    PostMessageW(h, MSG_TEST, 5, 0);
    mw("a signaled event and a message posted, QS_ALLINPUT", 1, ev, FALSE, 0, QS_ALLINPUT);
    mw("a signaled and an unsignaled event, fWaitAll, a message posted, QS_ALLINPUT", 2, ev, TRUE, 0,
       QS_ALLINPUT);
    drain();
    mw("a signaled and an unsignaled event, fWaitAll, no message, QS_ALLINPUT", 2, ev, TRUE, 0, QS_ALLINPUT);
    SetEvent(ev[1]);
    mw("two signaled events, fWaitAll, no message, QS_ALLINPUT", 2, ev, TRUE, 0, QS_ALLINPUT);
    PostMessageW(h, MSG_TEST, 6, 0);
    mw("two signaled events, fWaitAll, a message posted, QS_ALLINPUT", 2, ev, TRUE, 0, QS_ALLINPUT);
    mw("two signaled events, fWaitAll, that message again, QS_ALLINPUT", 2, ev, TRUE, 0, QS_ALLINPUT);
    drain();
    mw("no handles, mask 0, 0 ms", 0, NULL, FALSE, 0, 0);
    mw("no handles, mask 0x8000", 0, NULL, FALSE, 0, 0x8000);
    CloseHandle(ev[0]);
    CloseHandle(ev[1]);
    end_window();
}

/* --- status ---------------------------------------------------------- */

static void qs(const char *what, UINT mask)
{
    DWORD r;

    arm();
    r = GetQueueStatus(mask);
    line("GetQueueStatus(%s): current 0x%04X new 0x%04X err=%s", what, HIWORD(r), LOWORD(r), le());
}

static void sec_status(void)
{
    HWND h;
    MSG m;
    HANDLE t;
    job_t j;

    h = make_window(0, 0);
    qs("QS_ALLINPUT), the queue empty (", QS_ALLINPUT);
    PostMessageW(h, MSG_TEST, 1, 0);
    qs("QS_ALLINPUT), a message posted (", QS_ALLINPUT);
    qs("QS_ALLINPUT), again (", QS_ALLINPUT);
    PostMessageW(h, MSG_TEST, 2, 0);
    qs("QS_ALLINPUT), a second message posted (", QS_ALLINPUT);
    PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    qs("QS_ALLINPUT), after PeekMessageW PM_NOREMOVE (", QS_ALLINPUT);
    PeekMessageW(&m, NULL, 0, 0, PM_REMOVE);
    qs("QS_ALLINPUT), one message removed of two (", QS_ALLINPUT);
    PeekMessageW(&m, NULL, 0, 0, PM_REMOVE);
    qs("QS_ALLINPUT), both removed (", QS_ALLINPUT);
    PostMessageW(h, MSG_TEST, 3, 0);
    qs("QS_TIMER | QS_PAINT), a message posted (", QS_TIMER | QS_PAINT);
    qs("QS_POSTMESSAGE), the same message (", QS_POSTMESSAGE);
    qs("0), the same message (", 0);
    drain();

    ShowWindow(h, SW_SHOWNA);
    ValidateRect(h, NULL);
    drain();
    qs("QS_ALLINPUT), the window shown and validated (", QS_ALLINPUT);
    InvalidateRect(h, NULL, FALSE);
    qs("QS_ALLINPUT), the window invalidated (", QS_ALLINPUT);
    UpdateWindow(h);
    qs("QS_ALLINPUT), after UpdateWindow (", QS_ALLINPUT);
    ShowWindow(h, SW_HIDE);
    drain();

    SetTimer(h, 9, 50, NULL);
    qs("QS_ALLINPUT), a 50 ms timer set (", QS_ALLINPUT);
    Sleep(150);
    qs("QS_ALLINPUT), the timer due (", QS_ALLINPUT);
    KillTimer(h, 9);
    qs("QS_ALLINPUT), the timer killed (", QS_ALLINPUT);
    drain();

    t = start_job(&j, 1, MSG_TEST, 4);
    line("a second thread's send is waiting: %s", yesno(send_waiting()));
    qs("QS_ALLINPUT), a second thread's send waiting (", QS_ALLINPUT);
    qs("QS_SENDMESSAGE), the same (", QS_SENDMESSAGE);
    drain();
    end_job(&j, t);
    qs("QS_ALLINPUT), the send taken (", QS_ALLINPUT);
    print_log("received");

    PostQuitMessage(3);
    qs("QS_ALLINPUT), after PostQuitMessage (", QS_ALLINPUT);
    qs("QS_POSTMESSAGE), the same (", QS_POSTMESSAGE);
    drain();
    qs("QS_ALLINPUT), the queue drained (", QS_ALLINPUT);
    end_window();
}

/* --- input ----------------------------------------------------------- */

static void input_state(const char *when)
{
    BOOL r;

    arm();
    r = GetInputState();
    line("GetInputState %s: %s err=%s", when, r ? "non-zero" : "0", le());
}

static void sec_input(void)
{
    HWND h;
    f2k_input in[2];
    UINT sent;
    MSG m;
    RECT r;
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);
    LPARAM extra;
    POINT saved;

    line("GetProcAddress(user32, SendInput): non-NULL %s", yesno(send_input != NULL));
    if (send_input == NULL) {
        return;
    }
    GetCursorPos(&saved);
    h = make_window(WS_EX_TOPMOST, WS_VISIBLE);
    SetForegroundWindow(h);
    drain();
    Sleep(100);
    drain();
    line("the window is the foreground window: %s", yesno(GetForegroundWindow() == h));
    if (GetForegroundWindow() != h) {
        end_window();
        return;
    }
    input_state("with no input");
    PostMessageW(h, WM_KEYDOWN, VK_SHIFT, 0);
    input_state("with a WM_KEYDOWN posted");
    qs("QS_ALLINPUT), a WM_KEYDOWN posted (", QS_ALLINPUT);
    drain();

    ZeroMemory(in, sizeof in);
    in[0].type = 1;     /* INPUT_KEYBOARD */
    in[0].u.ki.wVk = VK_SHIFT;
    in[0].u.ki.dwExtraInfo = 0x5A5A0001;
    in[1] = in[0];
    in[1].u.ki.dwFlags = 0x0002;    /* KEYEVENTF_KEYUP */
    arm();
    sent = send_input(2, in, sizeof(f2k_input));
    line("SendInput(Shift down and up): ret=%u err=%s", sent, le());
    Sleep(100);
    input_state("after it");
    qs("QS_ALLINPUT), after it (", QS_ALLINPUT);
    mw("the keys queued, QS_KEY", 0, NULL, FALSE, 0, QS_KEY);
    mw("the keys queued, QS_MOUSE", 0, NULL, FALSE, 0, QS_MOUSE);
    mw("the keys queued, QS_INPUT", 0, NULL, FALSE, 0, QS_INPUT);
    if (GetMessageW(&m, NULL, 0, 0) > 0) {
        extra = GetMessageExtraInfo();
        line("GetMessageW: %s, GetMessageExtraInfo after: %s", m.message == WM_KEYDOWN ? "WM_KEYDOWN" : "another message",
             extra == 0x5A5A0001 ? "the input's" : extra == 0 ? "0" : "another value");
    }
    drain();
    input_state("the keys read");

    GetWindowRect(h, &r);
    ZeroMemory(in, sizeof in);
    in[0].type = 0;     /* INPUT_MOUSE */
    in[0].u.mi.dx = (((r.left + r.right) + 1) * 32768) / cx;
    in[0].u.mi.dy = (((r.top + r.bottom) + 1) * 32768) / cy;
    in[0].u.mi.dwFlags = 0x8001;    /* MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE */
    in[0].u.mi.dwExtraInfo = 0x5A5A0002;
    arm();
    sent = send_input(1, in, sizeof(f2k_input));
    line("SendInput(a mouse move onto the window): ret=%u err=%s", sent, le());
    Sleep(100);
    input_state("after it");
    qs("QS_ALLINPUT), after it (", QS_ALLINPUT);
    mw("the move queued, QS_MOUSEMOVE", 0, NULL, FALSE, 0, QS_MOUSEMOVE);
    mw("the move queued, QS_MOUSEBUTTON", 0, NULL, FALSE, 0, QS_MOUSEBUTTON);
    mw("the move queued, QS_KEY", 0, NULL, FALSE, 0, QS_KEY);
    if (PeekMessageW(&m, NULL, WM_MOUSEMOVE, WM_MOUSEMOVE, PM_REMOVE)) {
        extra = GetMessageExtraInfo();
        line("PeekMessageW: WM_MOUSEMOVE, GetMessageExtraInfo after: %s",
             extra == 0x5A5A0002 ? "the input's" : extra == 0 ? "0" : "another value");
    } else {
        line("PeekMessageW: no WM_MOUSEMOVE");
    }
    drain();
    SetCursorPos(saved.x, saved.y);
    drain();
    end_window();
}

/* --- insend ---------------------------------------------------------- */

static void sec_insend(void)
{
    HWND h;
    HANDLE t;
    job_t j;
    BOOL r;
    DWORD f;

    line("GetProcAddress(user32, InSendMessageEx): non-NULL %s", yesno(in_send_ex != NULL));
    h = make_window(0, 0);
    arm();
    r = InSendMessage();
    line("InSendMessage outside any send: %d err=%s", r, le());
    if (in_send_ex != NULL) {
        arm();
        f = in_send_ex(NULL);
        line("InSendMessageEx outside any send: %s err=%s", ismex(f), le());
    }
    SendMessageW(h, MSG_INSEND, 0, 0);
    print_log("SendMessageW from the same thread");
    PostMessageW(h, MSG_INSEND, 0, 0);
    drain();
    print_log("PostMessageW, dispatched");

    t = start_job(&j, 1, MSG_INSEND, 0);
    send_waiting();
    drain();
    end_job(&j, t);
    print_log("SendMessageW from a second thread");
    t = start_job(&j, 2, MSG_INSEND, 0);
    send_waiting();
    drain();
    end_job(&j, t);
    print_log("SendNotifyMessageW from a second thread");
    t = start_job(&j, 3, MSG_INSEND, 0);
    send_waiting();
    drain();
    end_job(&j, t);
    print_log("SendMessageCallbackW from a second thread");
    t = start_job(&j, 1, MSG_INSEND, 1);
    send_waiting();
    drain();
    end_job(&j, t);
    print_log("SendMessageW from a second thread, ReplyMessage(5) inside");
    line("  the second thread's SendMessageW returned %ld", (long)j.result);
    end_window();
}

/* --- reply ----------------------------------------------------------- */

static void sec_reply(void)
{
    HWND h;
    HANDLE t;
    job_t j;
    BOOL r;

    h = make_window(0, 0);
    arm();
    r = ReplyMessage(1);
    line("ReplyMessage(1) outside any send: ret=%d err=%s", r, le());
    reply_mode = 1;
    line("SendMessageW(MSG_REPLY) from the same thread: %ld", (long)SendMessageW(h, MSG_REPLY, 0, 0));
    print_log("the procedure");

    t = start_job(&j, 4, MSG_REPLY, 0);
    send_waiting();
    drain();
    end_job(&j, t);
    print_log("SendMessageW(MSG_REPLY) from a second thread");
    line("  its SendMessageW returned %ld; it woke before the procedure returned: %s", (long)j.result,
         yesno((LONG)(reply_done_tick - j.result_tick) > 100));
    reply_mode = 2;
    t = start_job(&j, 4, MSG_REPLY, 0);
    send_waiting();
    drain();
    end_job(&j, t);
    print_log("again, ReplyMessage twice");
    line("  its SendMessageW returned %ld", (long)j.result);
    reply_mode = 0;
    end_window();
}

/* --- callback -------------------------------------------------------- */

static HWND cb_window_expected;

static VOID CALLBACK record_cb(HWND h, UINT m, DWORD data, LRESULT result)
{
    note("the callback: window %s, message %s, data 0x%lX, result %ld",
         h == cb_window_expected ? "the target" : h == NULL ? "NULL" : "another", m == MSG_TEST ? "MSG_TEST" : "another",
         (unsigned long)data, (long)result);
}

static void sec_callback(void)
{
    HWND h;
    HANDLE t;
    job_t j;
    BOOL r;
    MSG m;

    h = make_window(0, 0);
    cb_window_expected = h;
    arm();
    r = SendMessageCallbackW(h, MSG_TEST, 1, 0, record_cb, 0x1111);
    note("SendMessageCallbackW returned %d err=%s", r, le());
    print_log("SendMessageCallbackW to the thread's own window, before any read");
    PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    print_log("after PeekMessageW");
    arm();
    r = SendMessageCallbackA(h, MSG_TEST, 2, 0, record_cb, 0x2222);
    note("SendMessageCallbackA returned %d err=%s", r, le());
    drain();
    print_log("SendMessageCallbackA to the thread's own window, then the queue read");

    t = start_job(&j, 5, 0, 0);
    WaitForSingleObject(j.ready, WAIT_MS);
    cb_window_expected = j.window;
    arm();
    r = SendMessageCallbackW(j.window, MSG_TEST, 3, 0, record_cb, 0x3333);
    note("SendMessageCallbackW returned %d err=%s", r, le());
    Sleep(300);
    print_log("SendMessageCallbackW to a second thread's window, 300 ms later, the queue unread");
    qs("QS_ALLINPUT), then (", QS_ALLINPUT);
    drain();
    print_log("the queue read");
    arm();
    r = SendMessageCallbackA(j.window, MSG_TEST, 4, 0, NULL, 0);
    line("SendMessageCallbackA(the second thread's window, no callback): ret=%d err=%s", r, le());
    Sleep(200);
    drain();
    print_log("then");
    end_job(&j, t);
    arm();
    r = SendMessageCallbackW((HWND)0x1234, MSG_TEST, 5, 0, record_cb, 0);
    line("SendMessageCallbackW(a bogus window): ret=%d err=%s", r, le());
    drain();
    print_log("then");
    end_window();
}

/* --- broadcast ------------------------------------------------------- */

static void bc(const char *what, bsm_fn fn, DWORD flags, DWORD recipients, int with_recipients, WPARAM wparam)
{
    long r;
    DWORD rec = recipients;

    arm();
    r = fn(flags, with_recipients ? &rec : NULL, broadcast_msg, wparam, 0);
    line("%s: ret=%s err=%s%s", what, r > 0 ? "positive" : r == 0 ? "0" : "-1", le(),
         with_recipients ? (rec == recipients ? ", recipients unchanged" : ", recipients changed") : "");
    Sleep(100);
    drain();
    print_log("  the window then");
}

static void sec_broadcast(void)
{
    line("GetProcAddress(user32, BroadcastSystemMessage, A, W): %s %s %s", yesno(bsm != NULL),
         yesno(bsm_a != NULL), yesno(bsm_w != NULL));
    if (bsm == NULL || bsm_a == NULL || bsm_w == NULL) {
        return;
    }
    broadcast_msg = RegisterWindowMessageW(L"F2KMsgwaitBroadcast");
    make_window(0, 0);
    bc("BroadcastSystemMessageW(BSF_POSTMESSAGE, BSM_APPLICATIONS)", bsm_w, BSF_POSTMESSAGE, BSM_APPLICATIONS, 1, 1);
    bc("BroadcastSystemMessageA(BSF_POSTMESSAGE, BSM_APPLICATIONS)", bsm_a, BSF_POSTMESSAGE, BSM_APPLICATIONS, 1, 1);
    bc("BroadcastSystemMessage(BSF_POSTMESSAGE, BSM_APPLICATIONS)", bsm, BSF_POSTMESSAGE, BSM_APPLICATIONS, 1, 1);
    bc("BroadcastSystemMessageW(BSF_SENDNOTIFYMESSAGE, BSM_APPLICATIONS)", bsm_w, BSF_SENDNOTIFYMESSAGE,
       BSM_APPLICATIONS, 1, 2);
    bc("BroadcastSystemMessageW(BSF_QUERY | BSF_NOHANG, BSM_APPLICATIONS), the window denying", bsm_w,
       BSF_QUERY | BSF_NOHANG, BSM_APPLICATIONS, 1, 3);
    bc("BroadcastSystemMessageW(BSF_QUERY | BSF_NOHANG, BSM_APPLICATIONS), the window agreeing", bsm_w,
       BSF_QUERY | BSF_NOHANG, BSM_APPLICATIONS, 1, 4);
    bc("BroadcastSystemMessageW(BSF_POSTMESSAGE | BSF_IGNORECURRENTTASK, BSM_APPLICATIONS)", bsm_w,
       BSF_POSTMESSAGE | BSF_IGNORECURRENTTASK, BSM_APPLICATIONS, 1, 5);
    bc("BroadcastSystemMessageW(BSF_POSTMESSAGE, no recipients pointer)", bsm_w, BSF_POSTMESSAGE, 0, 0, 6);
    bc("BroadcastSystemMessageW(BSF_POSTMESSAGE, recipients 0)", bsm_w, BSF_POSTMESSAGE, 0, 1, 7);
    bc("BroadcastSystemMessageW(flags 0x80000000, BSM_APPLICATIONS)", bsm_w, 0x80000000, BSM_APPLICATIONS, 1, 8);
    bc("BroadcastSystemMessageW(BSF_POSTMESSAGE, recipients 0x80000000)", bsm_w, BSF_POSTMESSAGE, 0x80000000, 1, 9);
    end_window();
    broadcast_msg = 0;
}

/* --- extra ----------------------------------------------------------- */

static void sec_extra(void)
{
    HWND h;
    LPARAM r;
    MSG m;

    line("GetProcAddress(user32, SetMessageExtraInfo): non-NULL %s", yesno(set_extra != NULL));
    if (set_extra == NULL) {
        return;
    }
    h = make_window(0, 0);
    arm();
    r = GetMessageExtraInfo();
    line("GetMessageExtraInfo at the start: 0x%lX err=%s", (unsigned long)r, le());
    arm();
    r = set_extra(0x1234);
    line("SetMessageExtraInfo(0x1234): previous 0x%lX err=%s", (unsigned long)r, le());
    arm();
    r = set_extra(0x5678);
    line("SetMessageExtraInfo(0x5678): previous 0x%lX err=%s", (unsigned long)r, le());
    arm();
    r = GetMessageExtraInfo();
    line("GetMessageExtraInfo: 0x%lX err=%s", (unsigned long)r, le());
    PostMessageW(h, MSG_TEST, 1, 0);
    GetMessageW(&m, NULL, 0, 0);
    r = GetMessageExtraInfo();
    line("GetMessageExtraInfo after GetMessageW of a posted message: 0x%lX", (unsigned long)r);
    set_extra(0x9ABC);
    SendMessageW(h, MSG_TEST, 2, 0);
    r = GetMessageExtraInfo();
    line("GetMessageExtraInfo after a SendMessageW to the thread's own window: 0x%lX", (unsigned long)r);
    set_extra(0);
    drain();
    log_count = 0;
    end_window();
}

/* --- queue ----------------------------------------------------------- */

static void sec_queue(void)
{
    BOOL r;

    line("GetProcAddress(user32, SetMessageQueue): non-NULL %s", yesno(set_queue != NULL));
    if (set_queue == NULL) {
        return;
    }
    arm();
    r = set_queue(100);
    line("SetMessageQueue(100): ret=%d err=%s", r, le());
    arm();
    r = set_queue(1);
    line("SetMessageQueue(1): ret=%d err=%s", r, le());
    arm();
    r = set_queue(0);
    line("SetMessageQueue(0): ret=%d err=%s", r, le());
}

/* --- idle ------------------------------------------------------------ */

static int child(const char *mode)
{
    HWND h;
    MSG m;
    DWORD start;

    if (strcmp(mode, "console") == 0) {
        Sleep(2000);
        return 0;
    }
    register_class();
    h = CreateWindowExW(0, L"F2KMsgwait", L"child", WS_POPUP, 0, 0, 10, 10, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    if (strcmp(mode, "late") == 0) {
        Sleep(1500);
    }
    start = GetTickCount();
    while (GetTickCount() - start < 3000) {
        if (MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_ALLINPUT) == WAIT_OBJECT_0) {
            while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
                DispatchMessageW(&m);
            }
        }
    }
    DestroyWindow(h);
    return 0;
}

static HANDLE spawn(const char *mode)
{
    char path[MAX_PATH], cmd[MAX_PATH + 40];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    GetModuleFileNameA(NULL, path, sizeof path);
    sprintf(cmd, "\"%s\" --child %s", path, mode);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        line("CreateProcessA(%s): failed err=%lu", mode, GetLastError());
        return NULL;
    }
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

static void idle(const char *what, HANDLE p, DWORD ms, DWORD lo, DWORD hi)
{
    DWORD r, start = GetTickCount();

    arm();
    r = WaitForInputIdle(p, ms);
    line("WaitForInputIdle(%s): %s err=%s, in %lu to %lu ms: %s", what,
         r == (DWORD)-1 ? "WAIT_FAILED" : wr(r), le(), lo, hi, band(GetTickCount() - start, lo, hi));
}

static void sec_idle(void)
{
    HANDLE p, dup;

    p = spawn("pump");
    if (p != NULL) {
        idle("a child pumping at once, 5000 ms", p, 5000, 0, 2000);
        WaitForSingleObject(p, WAIT_MS);
        idle("that child, ended", p, 1000, 0, 100);
        CloseHandle(p);
    }
    p = spawn("late");
    if (p != NULL) {
        idle("a child sleeping 1.5 s before its first read, 300 ms", p, 300, 250, 700);
        idle("the same child, INFINITE", p, INFINITE, 800, 2500);
        WaitForSingleObject(p, WAIT_MS);
        CloseHandle(p);
    }
    p = spawn("console");
    if (p != NULL) {
        idle("a child that never makes a window, 1000 ms", p, 1000, 0, 1200);
        WaitForSingleObject(p, WAIT_MS);
        CloseHandle(p);
    }
    idle("the program itself, 0 ms", GetCurrentProcess(), 0, 0, 100);
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &dup, 0, FALSE,
                    DUPLICATE_SAME_ACCESS);
    CloseHandle(dup);
    idle("a closed handle, 0 ms", dup, 0, 0, 100);
}

static const section_t sections[] = {
    { "masks", sec_masks, F2KT_ALWAYS },
    { "status", sec_status, F2KT_ALWAYS },
    { "input", sec_input, F2KT_ALWAYS },
    { "insend", sec_insend, F2KT_ALWAYS },
    { "reply", sec_reply, F2KT_ALWAYS },
    { "callback", sec_callback, F2KT_ALWAYS },
    { "broadcast", sec_broadcast, F2KT_ALWAYS },
    { "extra", sec_extra, F2KT_ALWAYS },
    { "queue", sec_queue, F2KT_ALWAYS },
    { "idle", sec_idle, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    if (argc >= 3 && strcmp(argv[1], "--child") == 0) {
        return child(argv[2]);
    }
    InitializeCriticalSection(&log_lock);
    main_thread = GetCurrentThreadId();
    mw_ex = (mwex_fn)GetProcAddress(user, "MsgWaitForMultipleObjectsEx");
    in_send_ex = (insendex_fn)GetProcAddress(user, "InSendMessageEx");
    set_extra = (setextra_fn)GetProcAddress(user, "SetMessageExtraInfo");
    set_queue = (setqueue_fn)GetProcAddress(user, "SetMessageQueue");
    bsm = (bsm_fn)GetProcAddress(user, "BroadcastSystemMessage");
    bsm_a = (bsm_fn)GetProcAddress(user, "BroadcastSystemMessageA");
    bsm_w = (bsm_fn)GetProcAddress(user, "BroadcastSystemMessageW");
    send_input = (send_input_fn)GetProcAddress(user, "SendInput");
    return run_sections("msgwait", sections, argc, argv);
}
