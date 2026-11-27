/*
 * guiwin - the window lifecycle and cursor calls of user32:
 * CreateWindowExA/W, DestroyWindow, GetDesktopWindow, IsWindow and
 * LoadCursorA/W.
 *
 * No handle value is printed: only whether one came back and how two
 * compare. A module-level wndproc counts the WM_NCCREATE, WM_CREATE
 * and WM_DESTROY messages it receives and records the last message it
 * saw; the counts print after the calls that delivered them, since
 * creation and destruction send those messages synchronously. The
 * suite runs each section as its own process, so each section that
 * needs a window registers the class and creates its own. Windows are
 * created at an explicit 320x200 and never shown, no window position
 * is printed (CW_USEDEFAULT varies with the machine), a paint is
 * forced synchronously with UpdateWindow, and posted messages are
 * drained with GetMessage after a PostQuitMessage, so the loop always
 * ends.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   register class "F2KGuiWin"; CreateWindowExA of a
 *            WS_OVERLAPPEDWINDOW window, IsWindow on it and the
 *            wndproc's WM_NCCREATE/WM_CREATE counts; CreateWindowExW
 *            on the same class; CreateWindowExA against an
 *            unregistered class name
 *   desktop  GetDesktopWindow, and IsWindow on it
 *   destroy  DestroyWindow of the section's own window (its
 *            WM_DESTROY count), IsWindow on the dead handle, and a
 *            second DestroyWindow of it
 *   cursor   LoadCursorA/W of the IDC_ARROW stock cursor, and
 *            LoadCursorA of a non-stock id
 *   refuse   CreateWindowExA/W of a class whose procedure refuses the
 *            creation: WM_NCCREATE answering 0, WM_CREATE answering -1,
 *            and WM_CREATE answering -2; the return, the last error,
 *            and the creation and destruction messages the procedure
 *            received, in order
 *   uniq     the section's first window's handle (its high word
 *            nonzero); the window destroyed and another made at once:
 *            the new handle against the old (the same, the same low
 *            word, the high word one more), IsWindow and DestroyWindow
 *            of the stale handle, and the new window after
 *   nest     a window whose WM_CREATE makes a child window of its own
 *            class, whose WM_CREATE makes the next, 20 levels deep:
 *            the levels reached and whether every child was made; a
 *            second thread's SendMessage to it received inside the
 *            main thread's GetMessage (InSendMessage, the answer);
 *            and a send alone during WaitMessage, the thread posting
 *            half a second later: whether WaitMessage returned only
 *            once the post was there
 *   diecreate  a procedure destroying its own window inside
 *            WM_NCCREATE, then inside WM_CREATE (A and W): the
 *            creation's return and last error, every message the
 *            procedure received in order (its DestroyWindow's span
 *            between [ and ]), that DestroyWindow's return and error,
 *            and IsWindow of the handle after; a first window is made
 *            and destroyed beforehand, so the process's first
 *            creation's error stays out of it
 *   dienest  DestroyWindow of a window whose WM_DESTROY destroys it
 *            again: both DestroyWindows' returns and errors, the
 *            messages received (WM_DESTROY and WM_NCDESTROY counted),
 *            IsWindow after
 *   err183pop, err183ovl (named-only: each needs a fresh process)
 *            which step of a process's first window creation leaves
 *            the last error 183 (ERROR_ALREADY_EXISTS): GetDesktopWindow,
 *            RegisterClassA, the first window (a popup, or an
 *            overlapped window), a second like it, one of the other
 *            kind, their DestroyWindows, and another thread's first
 *            window, each armed, with the modules each step loaded and
 *            the last error each message found on entry to the
 *            procedure (which re-arms it)
 *
 * refuse and uniq make WS_POPUP windows at an explicit position. uniq's
 * low-word relation holds while no other program makes a user object
 * between the destruction and the creation.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guiwin):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guiwin.c user32.lib
 */

#include "../common/f2kt.h"

/* What the wndproc has seen so far. */
static int n_nccreate;
static int n_create;
static int n_destroy;
static UINT last_msg;

/* The process instance, once asked for. */
static HINSTANCE hinst;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    last_msg = msg;
    switch (msg) {
    case WM_NCCREATE:
        n_nccreate++;
        break;
    case WM_CREATE:
        n_create++;
        break;
    case WM_DESTROY:
        n_destroy++;
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* Drain the thread's posted messages: the WM_QUIT the wndproc posted
 * on WM_DESTROY, or the one the caller posts, ends the loop. */
static void drain(void)
{
    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

/* Register "F2KGuiWin" (the first call in the process does) and create
 * one 320x200 WS_OVERLAPPEDWINDOW window of it. */
static HWND make_window(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    ATOM a;

    if (hinst == NULL) {
        arm();
        hinst = GetModuleHandleA(NULL);
        line("GetModuleHandleA(NULL): non-NULL %s err=%s", yesno(hinst != NULL), le());
        ZeroMemory(&wc, sizeof wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = wndproc;
        wc.hInstance = hinst;
        wc.lpszClassName = "F2KGuiWin";
        arm();
        a = RegisterClassA(&wc);
        line("RegisterClassA(F2KGuiWin): nonzero %s err=%s", yesno(a != 0), le());
    }
    arm();
    hwnd = CreateWindowExA(0, "F2KGuiWin", "t", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                           NULL, NULL, hinst, NULL);
    line("CreateWindowExA(F2KGuiWin): non-NULL %s err=%s", yesno(hwnd != NULL), le());
    return hwnd;
}

/* --- create -------------------------------------------------------- */

static void sec_create(void)
{
    HWND hwnd, hwnd_w, hwnd_bad;
    BOOL r;

    hwnd = make_window();

    arm();
    r = IsWindow(hwnd);
    line("IsWindow(the new window): %s err=%s", yesno(r), le());

    line("wndproc: WM_NCCREATE=%d WM_CREATE=%d last=0x%lX",
         n_nccreate, n_create, (unsigned long)last_msg);

    arm();
    r = UpdateWindow(hwnd);
    line("UpdateWindow: ret=%d err=%s", r, le());

    arm();
    hwnd_w = CreateWindowExW(0, L"F2KGuiWin", L"t", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                             NULL, NULL, hinst, NULL);
    line("CreateWindowExW(F2KGuiWin): non-NULL %s err=%s", yesno(hwnd_w != NULL), le());

    arm();
    hwnd_bad = CreateWindowExA(0, "NoSuchClass", "t", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                               NULL, NULL, hinst, NULL);
    line("CreateWindowExA(NoSuchClass): NULL %s err=%s", yesno(hwnd_bad == NULL), le());

    PostQuitMessage(0);
    drain();
    line("wndproc: WM_NCCREATE=%d WM_CREATE=%d WM_DESTROY=%d last=0x%lX",
         n_nccreate, n_create, n_destroy, (unsigned long)last_msg);
}

/* --- desktop ------------------------------------------------------- */

static void sec_desktop(void)
{
    HWND hwnd;
    BOOL r;

    arm();
    hwnd = GetDesktopWindow();
    line("GetDesktopWindow: non-NULL %s err=%s", yesno(hwnd != NULL), le());
    arm();
    r = IsWindow(hwnd);
    line("IsWindow(the desktop window): %s err=%s", yesno(r), le());
}

/* --- destroy ------------------------------------------------------- */

static void sec_destroy(void)
{
    HWND hwnd;
    BOOL r;

    hwnd = make_window();

    arm();
    r = DestroyWindow(hwnd);
    line("DestroyWindow: ret=%d err=%s", r, le());
    line("wndproc: WM_DESTROY=%d last=0x%lX", n_destroy, (unsigned long)last_msg);

    arm();
    r = IsWindow(hwnd);
    line("IsWindow(the destroyed window): %s err=%s", yesno(r), le());

    arm();
    r = DestroyWindow(hwnd);
    line("DestroyWindow(the destroyed window): ret=%d err=%s", r, le());

    drain();
    line("wndproc: WM_DESTROY=%d last=0x%lX", n_destroy, (unsigned long)last_msg);
}

/* --- cursor -------------------------------------------------------- */

static void sec_cursor(void)
{
    HCURSOR c_arrow_a, c_arrow_w, c_other;

    arm();
    c_arrow_a = LoadCursorA(NULL, IDC_ARROW);
    line("LoadCursorA(IDC_ARROW): non-NULL %s err=%s", yesno(c_arrow_a != NULL), le());
    arm();
    c_arrow_w = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    line("LoadCursorW(IDC_ARROW): non-NULL %s err=%s", yesno(c_arrow_w != NULL), le());
    line("the A and W cursors are the same: %s", yesno(c_arrow_a == c_arrow_w));
    arm();
    c_other = LoadCursorA(NULL, MAKEINTRESOURCE(32767));
    line("LoadCursorA(32767): NULL %s err=%s", yesno(c_other == NULL), le());
}

/* --- refuse ------------------------------------------------------- */

/* What the refusing procedure answers: 0 lets every message through,
 * 1 refuses WM_NCCREATE (0), 2 refuses WM_CREATE (-1), 3 answers
 * WM_CREATE with -2. */
static int refuse_mode;

/* The creation and destruction messages it received, in order. */
static char refuse_log[256];

static void refuse_note(const char *name)
{
    if (strlen(refuse_log) + strlen(name) + 2 < sizeof refuse_log) {
        if (refuse_log[0] != '\0') {
            strcat(refuse_log, " ");
        }
        strcat(refuse_log, name);
    }
}

static LRESULT CALLBACK refuse_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_GETMINMAXINFO:
        refuse_note("WM_GETMINMAXINFO");
        break;
    case WM_NCCREATE:
        refuse_note("WM_NCCREATE");
        if (refuse_mode == 1) {
            return 0;
        }
        break;
    case WM_NCCALCSIZE:
        refuse_note("WM_NCCALCSIZE");
        break;
    case WM_CREATE:
        refuse_note("WM_CREATE");
        if (refuse_mode == 2) {
            return -1;
        }
        if (refuse_mode == 3) {
            return -2;
        }
        break;
    case WM_DESTROY:
        refuse_note("WM_DESTROY");
        break;
    case WM_NCDESTROY:
        refuse_note("WM_NCDESTROY");
        break;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void refuse_create(const char *what, int mode, int wide)
{
    HWND h;
    DWORD e;

    refuse_mode = mode;
    refuse_log[0] = '\0';
    arm();
    if (wide) {
        h = CreateWindowExW(0, L"F2KGuiWinRefuse", L"t", WS_POPUP, 10, 10, 200, 100, NULL, NULL,
                            hinst, NULL);
    } else {
        h = CreateWindowExA(0, "F2KGuiWinRefuse", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL,
                            hinst, NULL);
    }
    e = GetLastError();
    line("CreateWindowEx%s, %s: NULL %s err=%s", wide ? "W" : "A", what, yesno(h == NULL), le_of(e));
    line("  the procedure received: %s", refuse_log);
    refuse_mode = 0;
    if (h != NULL) {
        line("  IsWindow: %s", yesno(IsWindow(h)));
        DestroyWindow(h);
    }
}

static void sec_refuse(void)
{
    WNDCLASSA wc;

    hinst = GetModuleHandleA(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = refuse_proc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWinRefuse";
    RegisterClassA(&wc);

    refuse_create("let through", 0, 0);
    refuse_create("WM_NCCREATE answering 0", 1, 0);
    refuse_create("WM_NCCREATE answering 0", 1, 1);
    refuse_create("WM_CREATE answering -1", 2, 0);
    refuse_create("WM_CREATE answering -1", 2, 1);
    refuse_create("WM_CREATE answering -2", 3, 0);
}

/* --- uniq ---------------------------------------------------------- */

static HWND uniq_create(void)
{
    return CreateWindowExA(0, "F2KGuiWin", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL, hinst,
                           NULL);
}

static void sec_uniq(void)
{
    WNDCLASSA wc;
    HWND h1, h2;
    BOOL r;

    hinst = GetModuleHandleA(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWin";
    RegisterClassA(&wc);

    h1 = uniq_create();
    line("the first window: non-NULL %s, its high word nonzero %s", yesno(h1 != NULL),
         yesno(HIWORD((DWORD)h1) != 0));
    arm();
    r = DestroyWindow(h1);
    line("DestroyWindow(the first): ret=%d err=%s", r, le());
    h2 = uniq_create();
    line("a second window made at once: non-NULL %s, its high word nonzero %s", yesno(h2 != NULL),
         yesno(HIWORD((DWORD)h2) != 0));
    line("  the first's handle %s, its low word %s, its high word plus one %s", yesno(h2 == h1),
         yesno(LOWORD((DWORD)h2) == LOWORD((DWORD)h1)),
         yesno(HIWORD((DWORD)h2) == (WORD)(HIWORD((DWORD)h1) + 1)));
    arm();
    r = IsWindow(h1);
    line("IsWindow(the first, destroyed): %s err=%s", yesno(r), le());
    arm();
    r = DestroyWindow(h1);
    line("DestroyWindow(the first, destroyed): ret=%d err=%s", r, le());
    arm();
    r = IsWindow(h2);
    line("IsWindow(the second) after: %s err=%s", yesno(r), le());
    if (IsWindow(h2)) {
        DestroyWindow(h2);
    }
    PostQuitMessage(0);
    drain();
}

/* --- nest ---------------------------------------------------------- */

/* How deep the creations nest, the level the next WM_CREATE is at,
 * and how many children were made. */
#define NEST_DEPTH 20
static int nest_level;
static int nest_made;

/* What the procedure saw of the other thread's send. */
static int nest_in_send = -1;
static WPARAM nest_wparam;

static LRESULT CALLBACK nest_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HWND child;
    int level;

    switch (msg) {
    case WM_CREATE:
        level = ++nest_level;
        if (level < NEST_DEPTH) {
            child = CreateWindowExA(0, "F2KGuiWinNest", NULL, WS_CHILD | WS_VISIBLE, 1, 1, 100,
                                    60, hwnd, (HMENU)level, hinst, NULL);
            if (child != NULL) {
                nest_made++;
            }
        }
        return 0;
    case WM_USER + 1:
        nest_in_send = InSendMessage() ? 1 : 0;
        nest_wparam = wParam;
        return 42;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* The other thread: a send while the main thread reads, its answer
 * kept; a post to end the read; then a send alone while the main
 * thread waits in WaitMessage, and a post half a second later. */
static LRESULT nest_answer;
static LRESULT nest_wait_answer;

static DWORD WINAPI nest_sender(LPVOID param)
{
    HWND hwnd = (HWND)param;

    nest_answer = SendMessageA(hwnd, WM_USER + 1, 7, 0);
    PostMessageA(hwnd, WM_USER + 2, 0, 0);
    Sleep(500);
    nest_wait_answer = SendMessageA(hwnd, WM_USER + 1, 8, 0);
    Sleep(500);
    PostMessageA(hwnd, WM_USER + 3, 0, 0);
    return 0;
}

static void sec_nest(void)
{
    WNDCLASSA wc;
    HWND h;
    HANDLE thread;
    DWORD id;
    MSG msg;
    BOOL posted;

    hinst = GetModuleHandleA(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = nest_proc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWinNest";
    RegisterClassA(&wc);

    h = CreateWindowExA(0, "F2KGuiWinNest", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL, hinst,
                        NULL);
    line("CreateWindowExA, nesting: non-NULL %s", yesno(h != NULL));
    line("  levels reached %d, every child made %s", nest_level,
         yesno(nest_made == NEST_DEPTH - 1));
    if (h == NULL) {
        return;
    }

    thread = CreateThread(NULL, 0, nest_sender, h, 0, &id);
    while (GetMessageA(&msg, NULL, 0, 0)) {
        if (msg.message == WM_USER + 2) {
            break;
        }
        DispatchMessageA(&msg);
    }
    line("another thread's send inside GetMessage: InSendMessage %d, wParam %d, answered %d",
         nest_in_send, (int)nest_wparam, (int)nest_answer);

    nest_in_send = -1;
    WaitMessage();
    posted = PeekMessageA(&msg, NULL, WM_USER + 3, WM_USER + 3, PM_NOREMOVE);
    line("WaitMessage with a send alone: the send received %s, returned only once the post came %s",
         yesno(nest_in_send == 1 && nest_wparam == 8), yesno(posted));
    WaitForSingleObject(thread, INFINITE);
    line("  the thread's send answered %d", (int)nest_wait_answer);
    CloseHandle(thread);

    DestroyWindow(h);
    line("DestroyWindow: IsWindow after %s", yesno(IsWindow(h)));
}

/* --- diecreate, dienest -------------------------------------------- */

/* A message's name as the logs print it: the creation, size, activation
 * and destruction messages by name, any other in hex. */
static const char *msg_name(UINT msg)
{
    static char hex[16];

    switch (msg) {
    case WM_GETMINMAXINFO: return "WM_GETMINMAXINFO";
    case WM_NCCREATE: return "WM_NCCREATE";
    case WM_NCCALCSIZE: return "WM_NCCALCSIZE";
    case WM_CREATE: return "WM_CREATE";
    case WM_SIZE: return "WM_SIZE";
    case WM_MOVE: return "WM_MOVE";
    case WM_SHOWWINDOW: return "WM_SHOWWINDOW";
    case WM_WINDOWPOSCHANGING: return "WM_WINDOWPOSCHANGING";
    case WM_WINDOWPOSCHANGED: return "WM_WINDOWPOSCHANGED";
    case WM_NCACTIVATE: return "WM_NCACTIVATE";
    case WM_ACTIVATE: return "WM_ACTIVATE";
    case WM_ACTIVATEAPP: return "WM_ACTIVATEAPP";
    case WM_SETFOCUS: return "WM_SETFOCUS";
    case WM_KILLFOCUS: return "WM_KILLFOCUS";
    case WM_DESTROY: return "WM_DESTROY";
    case WM_NCDESTROY: return "WM_NCDESTROY";
    }
    sprintf(hex, "0x%04X", msg);
    return hex;
}

/* Where the dying procedure destroys its own window: 0 never, 1 inside
 * WM_NCCREATE, 2 inside WM_CREATE, 3 inside WM_DESTROY. It does so once
 * (die_done), keeping the handle it destroyed, the DestroyWindow's
 * return and last error, and the messages it received in order, the
 * span of its own DestroyWindow between "[" and "]". */
static int die_mode;
static int die_done;
static HWND die_hwnd;
static BOOL die_ret;
static DWORD die_err;
static int die_n_destroy;
static int die_n_ncdestroy;
static char die_log[512];

static void die_note(const char *name)
{
    if (strlen(die_log) + strlen(name) + 2 < sizeof die_log) {
        if (die_log[0] != '\0') {
            strcat(die_log, " ");
        }
        strcat(die_log, name);
    }
}

static LRESULT CALLBACK die_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    die_note(msg_name(msg));
    if (msg == WM_DESTROY) {
        die_n_destroy++;
    }
    if (msg == WM_NCDESTROY) {
        die_n_ncdestroy++;
    }
    if (!die_done && ((die_mode == 1 && msg == WM_NCCREATE) || (die_mode == 2 && msg == WM_CREATE)
                      || (die_mode == 3 && msg == WM_DESTROY))) {
        die_done = 1;
        die_hwnd = hwnd;
        die_note("[");
        arm();
        die_ret = DestroyWindow(hwnd);
        die_err = GetLastError();
        die_note("]");
    }
    /* Once destroyed, the handle no longer reaches DefWindowProc (which
     * would set 1400): the procedure answers alone, WM_NCCREATE TRUE so
     * that the creation goes on as far as Windows lets it. */
    if (die_done) {
        return msg == WM_NCCREATE ? TRUE : 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void die_reset(int mode)
{
    die_mode = mode;
    die_done = 0;
    die_hwnd = NULL;
    die_ret = 0;
    die_err = F2KT_UNTOUCHED;
    die_n_destroy = 0;
    die_n_ncdestroy = 0;
    die_log[0] = '\0';
}

static HWND die_window(int wide)
{
    if (wide) {
        return CreateWindowExW(0, L"F2KGuiWinDie", L"t", WS_POPUP, 10, 10, 200, 100, NULL, NULL,
                               hinst, NULL);
    }
    return CreateWindowExA(0, "F2KGuiWinDie", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL, hinst,
                           NULL);
}

/* Register the dying class and make and destroy one window of it, so
 * that whatever the process's first creation leaves as the last error
 * (guiwin err183pop) is out of the way. */
static void die_setup(void)
{
    WNDCLASSA wc;
    HWND h;

    hinst = GetModuleHandleA(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = die_proc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWinDie";
    RegisterClassA(&wc);
    die_reset(0);
    h = die_window(0);
    line("a first window made and destroyed: %s", yesno(h != NULL && DestroyWindow(h)));
}

static void die_create(const char *what, int mode, int wide)
{
    HWND h;
    DWORD e;

    die_reset(mode);
    arm();
    h = die_window(wide);
    e = GetLastError();
    line("CreateWindowEx%s, DestroyWindow inside %s: NULL %s err=%s", wide ? "W" : "A", what,
         yesno(h == NULL), le_of(e));
    line("  the procedure received: %s", die_log);
    if (die_done) {
        line("  its DestroyWindow: ret=%d err=%s", die_ret, le_of(die_err));
    } else {
        line("  its DestroyWindow: never called");
    }
    line("  IsWindow of the window it destroyed: %s", yesno(die_hwnd != NULL && IsWindow(die_hwnd)));
    if (h != NULL) {
        line("  the handle returned is the procedure's: %s", yesno(h == die_hwnd));
        if (IsWindow(h)) {
            DestroyWindow(h);
        }
    }
    die_mode = 0;
}

static void sec_diecreate(void)
{
    die_setup();
    die_create("WM_NCCREATE", 1, 0);
    die_create("WM_NCCREATE", 1, 1);
    die_create("WM_CREATE", 2, 0);
    die_create("WM_CREATE", 2, 1);
}

static void sec_dienest(void)
{
    HWND h;
    BOOL r;
    DWORD e;

    die_setup();
    die_reset(3);
    h = die_window(0);
    line("CreateWindowExA: non-NULL %s", yesno(h != NULL));
    if (h == NULL) {
        return;
    }
    die_log[0] = '\0';
    arm();
    r = DestroyWindow(h);
    e = GetLastError();
    line("DestroyWindow, its WM_DESTROY destroying it again: ret=%d err=%s", r, le_of(e));
    line("  the procedure received: %s", die_log);
    line("  WM_DESTROY %d time(s), WM_NCDESTROY %d time(s)", die_n_destroy, die_n_ncdestroy);
    if (die_done) {
        line("  the nested DestroyWindow: ret=%d err=%s, of the same window %s", die_ret,
             le_of(die_err), yesno(die_hwnd == h));
    } else {
        line("  the nested DestroyWindow: never called");
    }
    arm();
    r = IsWindow(h);
    line("IsWindow after: %s err=%s", yesno(r), le());
    die_mode = 0;
}

/* --- err183pop, err183ovl ------------------------------------------ */

/* Which step of a process's first window creation leaves
 * ERROR_ALREADY_EXISTS (183): each step armed, its last error printed,
 * with the modules the step loaded into the process, and the
 * procedure noting each message with the last error as it found it on
 * entry (re-armed then), so an error set before the procedure is first
 * called (a hook, the thread's IME window) shows on the first message
 * and one set on the way out on the return. Named-only: the answer
 * needs a fresh process, so each runs alone (as tests\capture.bat runs
 * every section). */
#define PROBE_MAX_MSGS 32
#define PROBE_MAX_MODS 128
#define PROBE_NAME 64
static UINT probe_msg[PROBE_MAX_MSGS];
static DWORD probe_msg_err[PROBE_MAX_MSGS];
static int probe_n;
static int probe_logging;

static char probe_mods[PROBE_MAX_MODS][PROBE_NAME];
static int probe_nmods;
static char probe_now[PROBE_MAX_MODS][PROBE_NAME];
static char probe_new[512];

static LRESULT CALLBACK probe_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    DWORD e = GetLastError();

    if (probe_logging) {
        if (probe_n < PROBE_MAX_MSGS) {
            probe_msg[probe_n] = msg;
            probe_msg_err[probe_n] = e;
            probe_n++;
        }
        SetLastError(F2KT_UNTOUCHED);
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* The process's PEB, from the TEB's pointer to it (fs:[0x30]). */
static BYTE *probe_peb(void)
{
    BYTE *peb;

#ifdef _MSC_VER
    __asm {
        mov eax, fs:[0x30]
        mov peb, eax
    }
#else
    __asm__("movl %%fs:0x30, %0" : "=r"(peb));
#endif
    return peb;
}

/* The process's modules now, read from the loader's own list (the
 * PEB's PEB_LDR_DATA at 0x0C, its load-order list at 0x0C, each entry's
 * BaseDllName at 0x2C), which no call reaches without touching the last
 * error; probe_new names those the last look did not see ("none"),
 * lowercased. */
static void probe_modules(void)
{
    BYTE *ldr, *head, *entry;
    USHORT length;
    WCHAR *name;
    int n = 0, i, j, k;

    probe_new[0] = '\0';
    ldr = *(BYTE **)(probe_peb() + 0x0C);
    head = ldr + 0x0C;
    for (entry = *(BYTE **)head; entry != head && n < PROBE_MAX_MODS; entry = *(BYTE **)entry) {
        length = *(USHORT *)(entry + 0x2C);
        name = *(WCHAR **)(entry + 0x30);
        for (k = 0; k < length / 2 && k < PROBE_NAME - 1 && name != NULL; k++) {
            WCHAR c = name[k];

            if (c >= 'A' && c <= 'Z') {
                c = (WCHAR)(c - 'A' + 'a');
            }
            probe_now[n][k] = c < 0x80 ? (char)c : '?';
        }
        probe_now[n][k] = '\0';
        n++;
    }
    for (i = 0; i < n; i++) {
        for (j = 0; j < probe_nmods; j++) {
            if (strcmp(probe_now[i], probe_mods[j]) == 0) {
                break;
            }
        }
        if (j == probe_nmods && strlen(probe_new) + strlen(probe_now[i]) + 2 < sizeof probe_new) {
            if (probe_new[0] != '\0') {
                strcat(probe_new, " ");
            }
            strcat(probe_new, probe_now[i]);
        }
    }
    if (probe_new[0] == '\0') {
        strcpy(probe_new, "none");
    }
    memcpy(probe_mods, probe_now, sizeof probe_mods);
    probe_nmods = n;
}

/* One step's line, then the messages it delivered, if any. */
static void probe_report(const char *what, int ok, DWORD e)
{
    char log[512];
    char item[48];
    int i;

    line("%s: %s err=%s, modules loaded: %s", what, yesno(ok), le_of(e), probe_new);
    if (probe_n == 0) {
        return;
    }
    log[0] = '\0';
    for (i = 0; i < probe_n; i++) {
        sprintf(item, "%s%s:%s", i ? " " : "", msg_name(probe_msg[i]), le_of(probe_msg_err[i]));
        if (strlen(log) + strlen(item) < sizeof log) {
            strcat(log, item);
        }
    }
    line("  the messages, each with the error found on entry: %s", log);
}

static HWND probe_window(int overlapped)
{
    if (overlapped) {
        return CreateWindowExA(0, "F2KGuiWinProbe", "t", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                               CW_USEDEFAULT, 320, 200, NULL, NULL, hinst, NULL);
    }
    return CreateWindowExA(0, "F2KGuiWinProbe", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL, hinst,
                           NULL);
}

/* The other thread's first window: what it saw, for the main thread
 * to print once it has ended. */
static int probe_thread_overlapped;
static int probe_thread_ok;
static DWORD probe_thread_err;

static DWORD WINAPI probe_thread(LPVOID param)
{
    HWND h;

    (void)param;
    probe_n = 0;
    probe_logging = 1;
    arm();
    h = probe_window(probe_thread_overlapped);
    probe_thread_err = GetLastError();
    probe_logging = 0;
    probe_thread_ok = h != NULL;
    if (h != NULL) {
        DestroyWindow(h);
    }
    return 0;
}

static void probe_run(int overlapped_first)
{
    const char *first = overlapped_first ? "an overlapped window" : "a popup";
    const char *other = overlapped_first ? "a popup" : "an overlapped window";
    char what[96];
    WNDCLASSA wc;
    HWND h[3];
    BOOL r[3];
    DWORD e[3];
    HANDLE thread;
    DWORD id;
    HWND d;
    ATOM a;
    int i;

    hinst = GetModuleHandleA(NULL);
    probe_modules();

    arm();
    d = GetDesktopWindow();
    e[0] = GetLastError();
    probe_modules();
    probe_n = 0;
    probe_report("GetDesktopWindow", d != NULL, e[0]);

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = probe_proc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWinProbe";
    arm();
    a = RegisterClassA(&wc);
    e[0] = GetLastError();
    probe_modules();
    probe_report("RegisterClassA", a != 0, e[0]);

    for (i = 0; i < 3; i++) {
        probe_n = 0;
        probe_logging = 1;
        arm();
        h[i] = probe_window(i < 2 ? overlapped_first : !overlapped_first);
        e[i] = GetLastError();
        probe_logging = 0;
        probe_modules();
        if (i == 0) {
            sprintf(what, "CreateWindowExA, the first window (%s)", first);
        } else if (i == 1) {
            sprintf(what, "CreateWindowExA, a second one (%s)", first);
        } else {
            sprintf(what, "CreateWindowExA, then %s", other);
        }
        probe_report(what, h[i] != NULL, e[i]);
    }

    for (i = 0; i < 3; i++) {
        arm();
        r[i] = DestroyWindow(h[i]);
        e[i] = GetLastError();
    }
    probe_modules();
    line("DestroyWindow of each: ret=%d %d %d err=%s %s %s, modules loaded: %s", r[0], r[1], r[2],
         le_of(e[0]), le_of(e[1]), le_of(e[2]), probe_new);

    probe_thread_overlapped = overlapped_first;
    probe_thread_ok = 0;
    probe_thread_err = F2KT_UNTOUCHED;
    probe_n = 0;
    thread = CreateThread(NULL, 0, probe_thread, NULL, 0, &id);
    if (thread == NULL) {
        line("CreateThread failed");
        return;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    probe_modules();
    sprintf(what, "another thread's first window (%s)", first);
    probe_report(what, probe_thread_ok, probe_thread_err);
}

static void sec_err183pop(void)
{
    probe_run(0);
}

static void sec_err183ovl(void)
{
    probe_run(1);
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "desktop", sec_desktop, F2KT_ALWAYS },
    { "destroy", sec_destroy, F2KT_ALWAYS },
    { "cursor", sec_cursor, F2KT_ALWAYS },
    { "refuse", sec_refuse, F2KT_ALWAYS },
    { "uniq", sec_uniq, F2KT_ALWAYS },
    { "nest", sec_nest, F2KT_ALWAYS },
    { "diecreate", sec_diecreate, F2KT_ALWAYS },
    { "dienest", sec_dienest, F2KT_ALWAYS },
    /* Named-only: each needs a fresh process's first creation. */
    { "err183pop", sec_err183pop, F2KT_NAMED },
    { "err183ovl", sec_err183ovl, F2KT_NAMED },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad class name or a dead window handle goes to the calls:
     * should one fault, no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guiwin", sections, argc, argv);
}
