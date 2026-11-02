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

static const section_t sections[] = {
    { "post", sec_post, F2KT_ALWAYS },
    { "peek", sec_peek, F2KT_ALWAYS },
    { "quit", sec_quit, F2KT_ALWAYS },
    { "dispatch", sec_dispatch, F2KT_ALWAYS },
    { "send", sec_send, F2KT_ALWAYS },
    { "defproc", sec_defproc, F2KT_ALWAYS },
    { "threadmsg", sec_threadmsg, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guimsg", sections, argc, argv);
}
