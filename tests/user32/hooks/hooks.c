/*
 * hooks - thread-local windows hooks and WinEvents: WH_CBT (as MFC's
 * AfxHookWindowCreate uses it, and its vetoes), WH_GETMESSAGE,
 * WH_CALLWNDPROC and WH_CALLWNDPROCRET, WH_MSGFILTER through a modal
 * dialog's loop and CallMsgFilter, WH_KEYBOARD and WH_MOUSE with
 * SendInput, hook chains and CallNextHookEx, UnhookWindowsHookEx, the
 * Windows 3.x SetWindowsHook and UnhookWindowsHook, and the errors; then
 * SetWinEventHook, UnhookWinEvent and NotifyWinEvent out of context on
 * the program's own thread.
 *
 * Every hook is installed for the program's own thread
 * (GetCurrentThreadId, a NULL module): no global hook, nothing loaded
 * into another process. Each section removes every hook it installed.
 * The hook procedures record what they see into a log (the hook code
 * by name, the message by name, which of the section's windows), which
 * prints after the calls; a procedure never prints.
 *
 * The keyboard and mouse sections inject Shift and a mouse move with
 * SendInput (found with GetProcAddress, as keyinput does) into a
 * visible top-most window of their own, only while it is the
 * foreground window, and say so otherwise; the cursor is put back.
 * Nobody touches the machine while it runs. The msgfilter section
 * shows a modal dialog (an in-memory template) that ends itself.
 *
 * SetWindowsHookA/W, UnhookWindowsHook, CallMsgFilter (the plain name),
 * SetWinEventHook, UnhookWinEvent and NotifyWinEvent are found with
 * GetProcAddress (MSVC 6's winuser.h declares none of the WinEvent
 * calls); a section says so and stops when one is missing.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   cbt       WH_CBT through SetWindowsHookExW: the codes a window's
 *             life brings (create, activate, set focus, min/max, the
 *             system command, destroy), with CBT_CREATEWND's class name
 *             and parent; the MFC pattern: the hook subclasses the
 *             window in HCBT_CREATEWND and unhooks itself, the new
 *             procedure's first message; a child's creation; the same
 *             through SetWindowsHookExA (the class name as ANSI)
 *   veto      WH_CBT answering non-zero to HCBT_CREATEWND (the
 *             creation's return, its last error, the messages the window
 *             procedure got) and to HCBT_DESTROYWND (DestroyWindow's
 *             return, IsWindow after), HCBT_ACTIVATE and HCBT_SETFOCUS
 *   getmsg    WH_GETMESSAGE for GetMessageW and PeekMessageW with and
 *             without PM_REMOVE: the hook's wParam, the message; a hook
 *             changing the message's wParam (what GetMessageW returns)
 *   callwnd   WH_CALLWNDPROC and WH_CALLWNDPROCRET around SendMessageW
 *             to the thread's own window: the order against the window
 *             procedure, the hook's wParam, CWPRETSTRUCT's lResult; a
 *             posted message dispatched (not hooked); a second thread's
 *             send
 *   msgfilter WH_MSGFILTER through a modal dialog's loop (the codes
 *             seen, MSGF_DIALOGBOX); CallMsgFilterW, A and the plain
 *             name with a code of the program's own, the hook answering
 *             0 and 1; with no hook installed
 *   keyboard  WH_KEYBOARD with SendInput of Shift: the codes (HC_ACTION,
 *             HC_NOREMOVE for a PM_NOREMOVE peek), the key, the
 *             transition bit; a hook swallowing the key (what the
 *             window then gets)
 *   mouse     WH_MOUSE with SendInput of a move onto the window: the
 *             code, the message, MOUSEHOOKSTRUCT's window and hit-test
 *             code
 *   chain     two WH_GETMESSAGE hooks: the order they run, CallNextHookEx
 *             (with the hook handle and NULL) reaching the first, the
 *             last one not calling it; UnhookWindowsHookEx inside the
 *             hook; UnhookWindowsHookEx twice, of NULL; SetWindowsHookExW
 *             with an unknown id, a NULL procedure, thread 0 with no
 *             module, a thread that does not exist
 *   oldstyle  SetWindowsHookW and A (WH_GETMESSAGE): a message seen,
 *             UnhookWindowsHook by id and procedure, twice
 *   winevent  SetWinEventHook(WINEVENT_OUTOFCONTEXT) for this thread:
 *             the events a window's creation, showing, naming and
 *             destruction raise for it (EVENT_OBJECT_*), when they are
 *             delivered (only as the thread reads its queue),
 *             NotifyWinEvent of an event of the program's own,
 *             WINEVENT_SKIPOWNTHREAD; UnhookWinEvent twice; an inverted
 *             range and WINEVENT_INCONTEXT with no module
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat hooks):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% hooks.c user32.lib
 */

#include "../common/f2kt.h"

#define MSG_TEST (WM_USER + 60)
#define MSGF_OWN 0x4242

#define F2K_WINEVENT_OUTOFCONTEXT 0x0000
#define F2K_WINEVENT_SKIPOWNTHREAD 0x0001
#define F2K_WINEVENT_INCONTEXT 0x0004
#define F2K_EVENT_OBJECT_CREATE 0x8000
#define F2K_EVENT_OBJECT_DESTROY 0x8001
#define F2K_EVENT_OBJECT_SHOW 0x8002
#define F2K_EVENT_OBJECT_HIDE 0x8003
#define F2K_EVENT_OBJECT_NAMECHANGE 0x800C
#define F2K_EVENT_OBJECT_LOCATIONCHANGE 0x800B
#define F2K_EVENT_OBJECT_REORDER 0x8004
#define F2K_EVENT_OBJECT_FOCUS 0x8005
#define F2K_EVENT_OBJECT_STATECHANGE 0x800A
#define F2K_EVENT_SYSTEM_FOREGROUND 0x0003
#define F2K_EVENT_OWN 0x8F00     /* inside the OBJECT range no system event uses */
#define F2K_EVENT_MIN 0x00000001
#define F2K_EVENT_MAX 0x7FFFFFFF

typedef HANDLE f2k_hwineventhook;
typedef VOID (CALLBACK *wineventproc_t)(f2k_hwineventhook, DWORD, HWND, LONG, LONG, DWORD, DWORD);
typedef f2k_hwineventhook (WINAPI *setwinevent_fn)(DWORD, DWORD, HMODULE, wineventproc_t, DWORD, DWORD, DWORD);
typedef BOOL (WINAPI *unhookwinevent_fn)(f2k_hwineventhook);
typedef VOID (WINAPI *notifywinevent_fn)(DWORD, HWND, LONG, LONG);
typedef HHOOK (WINAPI *sethook_fn)(int, HOOKPROC);
typedef BOOL (WINAPI *unhook_fn)(int, HOOKPROC);
typedef BOOL (WINAPI *callmsgfilter_fn)(LPMSG, int);

static setwinevent_fn set_win_event_hook;
static unhookwinevent_fn unhook_win_event;
static notifywinevent_fn notify_win_event;
static sethook_fn set_hook_a, set_hook_w;
static unhook_fn unhook_old;
static callmsgfilter_fn call_msg_filter;

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

/* --- the log ----------------------------------------------------------- */

#define LOG_MAX 64
static char log_lines[LOG_MAX][110];
static int log_count;
static int log_lost;

static void note(const char *fmt, ...)
{
    va_list ap;

    if (log_count == LOG_MAX) {
        log_lost++;
        return;
    }
    va_start(ap, fmt);
    _vsnprintf(log_lines[log_count], sizeof log_lines[0] - 1, fmt, ap);
    log_lines[log_count][sizeof log_lines[0] - 1] = '\0';
    va_end(ap);
    log_count++;
}

static void print_log(const char *what)
{
    int i;

    line("%s: %d record(s)%s", what, log_count, log_lost ? ", more lost" : "");
    for (i = 0; i < log_count; i++) {
        line("  %s", log_lines[i]);
    }
    log_count = 0;
    log_lost = 0;
}

/* --- names ------------------------------------------------------------- */

static HWND win_a, win_b, win_child;

static const char *which(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == win_a) {
        return "A";
    }
    if (h == win_b) {
        return "B";
    }
    if (h == win_child) {
        return "the child";
    }
    if (h == GetDesktopWindow()) {
        return "the desktop";
    }
    return "another";
}

static const char *cbt_name(int code)
{
    switch (code) {
    case HCBT_MOVESIZE: return "HCBT_MOVESIZE";
    case HCBT_MINMAX: return "HCBT_MINMAX";
    case HCBT_QS: return "HCBT_QS";
    case HCBT_CREATEWND: return "HCBT_CREATEWND";
    case HCBT_DESTROYWND: return "HCBT_DESTROYWND";
    case HCBT_ACTIVATE: return "HCBT_ACTIVATE";
    case HCBT_CLICKSKIPPED: return "HCBT_CLICKSKIPPED";
    case HCBT_KEYSKIPPED: return "HCBT_KEYSKIPPED";
    case HCBT_SYSCOMMAND: return "HCBT_SYSCOMMAND";
    case HCBT_SETFOCUS: return "HCBT_SETFOCUS";
    }
    return "another code";
}

static const char *msg_name(UINT m)
{
    static char b[4][24];
    static int n;
    char *s;

    switch (m) {
    case WM_NULL: return "WM_NULL";
    case WM_CREATE: return "WM_CREATE";
    case WM_DESTROY: return "WM_DESTROY";
    case WM_NCCREATE: return "WM_NCCREATE";
    case WM_NCDESTROY: return "WM_NCDESTROY";
    case WM_NCCALCSIZE: return "WM_NCCALCSIZE";
    case WM_GETMINMAXINFO: return "WM_GETMINMAXINFO";
    case WM_SETTEXT: return "WM_SETTEXT";
    case WM_KEYDOWN: return "WM_KEYDOWN";
    case WM_KEYUP: return "WM_KEYUP";
    case WM_MOUSEMOVE: return "WM_MOUSEMOVE";
    case WM_NCMOUSEMOVE: return "WM_NCMOUSEMOVE";
    case WM_TIMER: return "WM_TIMER";
    case WM_PAINT: return "WM_PAINT";
    case MSG_TEST: return "MSG_TEST";
    }
    s = b[n++ & 3];
    sprintf(s, "0x%04X", m);
    return s;
}

/* --- windows ----------------------------------------------------------- */

static int proc_log;    /* the window procedure logs too */

static LRESULT CALLBACK hook_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (proc_log && (msg == MSG_TEST || msg == WM_NCCREATE || msg == WM_CREATE || msg == WM_DESTROY
                     || msg == WM_KEYDOWN || msg == WM_KEYUP)) {
        note("the window procedure: %s wParam=%lu", msg_name(msg), (unsigned long)wparam);
    }
    if (msg == MSG_TEST) {
        return (LRESULT)(wparam * 2);
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
    wc.lpfnWndProc = hook_wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"F2KHooks";
    done = RegisterClassW(&wc) != 0;
}

static HWND make(DWORD ex, DWORD style, HWND parent, int x, int y, int w, int h)
{
    register_class();
    return CreateWindowExW(ex, L"F2KHooks", L"hooks", style, x, y, w, h, parent, NULL, GetModuleHandleA(NULL),
                           NULL);
}

static HWND make_popup(void)
{
    return make(WS_EX_TOOLWINDOW, WS_POPUP, NULL, 0, 0, 64, 48);
}

static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

static void unhook(const char *what, HHOOK h)
{
    BOOL r;

    arm();
    r = UnhookWindowsHookEx(h);
    line("UnhookWindowsHookEx(%s): ret=%d err=%s", what, r, le());
}

static HHOOK hook_w(const char *what, int id, HOOKPROC proc)
{
    HHOOK h;

    arm();
    h = SetWindowsHookExW(id, proc, NULL, GetCurrentThreadId());
    line("SetWindowsHookExW(%s, this thread): non-NULL %s err=%s", what, yesno(h != NULL), le());
    return h;
}

/* --- cbt --------------------------------------------------------------- */

static HHOOK cbt_hook;
static int cbt_mfc;             /* subclass in HCBT_CREATEWND, then unhook */
static int cbt_veto;            /* the code to answer non-zero to */
static WNDPROC mfc_old;
static int mfc_first;

static LRESULT CALLBACK mfc_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (!mfc_first) {
        mfc_first = 1;
        note("the subclass procedure's first message: %s", msg_name(msg));
    }
    return CallWindowProcW(mfc_old, hwnd, msg, wparam, lparam);
}

static LRESULT CALLBACK cbt_proc_w(int code, WPARAM wparam, LPARAM lparam)
{
    CBT_CREATEWNDW *cw;
    char cls[64];

    if (code == HCBT_CREATEWND) {
        cw = (CBT_CREATEWNDW *)lparam;
        if (HIWORD((DWORD)cw->lpcs->lpszClass) != 0) {
            sprintf(cls, "%s", ws(cw->lpcs->lpszClass));
        } else {
            strcpy(cls, "an atom");
        }
        note("WH_CBT: HCBT_CREATEWND, class %s, parent %s, IsWindow %s, its procedure the class's: %s", cls,
             which(cw->lpcs->hwndParent), yesno(IsWindow((HWND)wparam)),
             yesno(GetWindowLongW((HWND)wparam, GWL_WNDPROC) == (LONG)hook_wndproc));
        if (cbt_mfc) {
            mfc_first = 0;
            mfc_old = (WNDPROC)SetWindowLongW((HWND)wparam, GWL_WNDPROC, (LONG)mfc_proc);
            note("  subclassed; UnhookWindowsHookEx from inside: %d", UnhookWindowsHookEx(cbt_hook));
            cbt_mfc = 0;
            return 0;
        }
    } else if (code == HCBT_ACTIVATE) {
        CBTACTIVATESTRUCT *a = (CBTACTIVATESTRUCT *)lparam;

        note("WH_CBT: HCBT_ACTIVATE of %s, fMouse %d, the active window before: %s", which((HWND)wparam),
             a->fMouse, which(a->hWndActive));
    } else if (code == HCBT_SETFOCUS) {
        note("WH_CBT: HCBT_SETFOCUS to %s from %s", which((HWND)wparam), which((HWND)lparam));
    } else if (code == HCBT_MINMAX) {
        note("WH_CBT: HCBT_MINMAX of %s, show command %ld", which((HWND)wparam), (long)LOWORD(lparam));
    } else if (code == HCBT_SYSCOMMAND) {
        note("WH_CBT: HCBT_SYSCOMMAND 0x%04lX", (unsigned long)(wparam & 0xFFF0));
    } else if (code == HCBT_DESTROYWND) {
        note("WH_CBT: HCBT_DESTROYWND of %s", which((HWND)wparam));
    } else {
        note("WH_CBT: %s", cbt_name(code));
    }
    if (code == cbt_veto) {
        note("  answered 1");
        return 1;
    }
    return CallNextHookEx(cbt_hook, code, wparam, lparam);
}

static LRESULT CALLBACK cbt_proc_a(int code, WPARAM wparam, LPARAM lparam)
{
    CBT_CREATEWNDA *cw;

    if (code == HCBT_CREATEWND) {
        cw = (CBT_CREATEWNDA *)lparam;
        note("WH_CBT (A): HCBT_CREATEWND, class \"%s\", window name \"%s\"",
             HIWORD((DWORD)cw->lpcs->lpszClass) != 0 ? cw->lpcs->lpszClass : "(an atom)",
             cw->lpcs->lpszName != NULL ? cw->lpcs->lpszName : "(null)");
    } else {
        note("WH_CBT (A): %s", cbt_name(code));
    }
    return CallNextHookEx(cbt_hook, code, wparam, lparam);
}

static void sec_cbt(void)
{
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    cbt_hook = hook_w("WH_CBT", WH_CBT, cbt_proc_w);
    if (cbt_hook == NULL) {
        return;
    }
    win_a = make(WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW, NULL, (cx - 200) / 2, (cy - 150) / 2, 200, 150);
    print_log("CreateWindowExW(an overlapped window, A)");
    ShowWindow(win_a, SW_SHOW);
    drain();
    print_log("ShowWindow(A, SW_SHOW)");
    win_child = make(0, WS_CHILD | WS_VISIBLE, win_a, 0, 0, 20, 20);
    print_log("CreateWindowExW(a child of A)");
    SetFocus(win_child);
    print_log("SetFocus(the child)");
    ShowWindow(win_a, SW_MINIMIZE);
    drain();
    print_log("ShowWindow(A, SW_MINIMIZE)");
    SendMessageW(win_a, WM_SYSCOMMAND, SC_RESTORE, 0);
    drain();
    print_log("WM_SYSCOMMAND SC_RESTORE to A");
    DestroyWindow(win_a);
    drain();
    print_log("DestroyWindow(A)");
    win_a = NULL;
    win_child = NULL;
    unhook("the WH_CBT hook", cbt_hook);

    cbt_hook = hook_w("WH_CBT, the MFC pattern", WH_CBT, cbt_proc_w);
    cbt_mfc = 1;
    win_a = make_popup();
    print_log("CreateWindowExW(a popup, A), subclassed in HCBT_CREATEWND");
    line("  the procedure after: the subclass %s", yesno(GetWindowLongW(win_a, GWL_WNDPROC) == (LONG)mfc_proc));
    win_b = make_popup();
    print_log("CreateWindowExW(another popup, B), the hook gone");
    DestroyWindow(win_a);
    DestroyWindow(win_b);
    win_a = win_b = NULL;
    drain();
    log_count = 0;
    unhook("the hook it removed itself", cbt_hook);

    arm();
    cbt_hook = SetWindowsHookExA(WH_CBT, cbt_proc_a, NULL, GetCurrentThreadId());
    line("SetWindowsHookExA(WH_CBT, this thread): non-NULL %s err=%s", yesno(cbt_hook != NULL), le());
    if (cbt_hook != NULL) {
        win_a = CreateWindowExA(WS_EX_TOOLWINDOW, "F2KHooks", "ansi", WS_POPUP, 0, 0, 64, 48, NULL, NULL,
                                GetModuleHandleA(NULL), NULL);
        print_log("CreateWindowExA(a popup)");
        win_b = make_popup();
        print_log("CreateWindowExW(a popup)");
        DestroyWindow(win_a);
        DestroyWindow(win_b);
        win_a = win_b = NULL;
        print_log("both destroyed");
        unhook("the WH_CBT hook (A)", cbt_hook);
    }
    drain();
}

/* --- veto -------------------------------------------------------------- */

static void sec_veto(void)
{
    HWND h;
    BOOL r;
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    cbt_hook = hook_w("WH_CBT", WH_CBT, cbt_proc_w);
    if (cbt_hook == NULL) {
        return;
    }
    proc_log = 1;
    cbt_veto = HCBT_CREATEWND;
    arm();
    h = make_popup();
    line("CreateWindowExW, HCBT_CREATEWND vetoed: NULL %s err=%s", yesno(h == NULL), le());
    print_log("  then");
    cbt_veto = 0;
    win_a = make_popup();
    log_count = 0;
    cbt_veto = HCBT_DESTROYWND;
    arm();
    r = DestroyWindow(win_a);
    line("DestroyWindow, HCBT_DESTROYWND vetoed: ret=%d err=%s, IsWindow after: %s", r, le(),
         yesno(IsWindow(win_a)));
    print_log("  then");
    cbt_veto = 0;
    DestroyWindow(win_a);
    log_count = 0;

    win_a = make(WS_EX_TOPMOST, WS_POPUP | WS_CAPTION, NULL, (cx - 200) / 2, (cy - 150) / 2, 200, 150);
    win_child = make(0, WS_CHILD | WS_VISIBLE, win_a, 0, 0, 20, 20);
    log_count = 0;
    cbt_veto = HCBT_ACTIVATE;
    ShowWindow(win_a, SW_SHOW);
    drain();
    line("ShowWindow(A), HCBT_ACTIVATE vetoed: A visible %s, the active window: %s", yesno(IsWindowVisible(win_a)),
         which(GetActiveWindow()));
    print_log("  then");
    cbt_veto = 0;
    SetForegroundWindow(win_a);
    SetActiveWindow(win_a);
    SetFocus(win_a);
    drain();
    log_count = 0;
    cbt_veto = HCBT_SETFOCUS;
    arm();
    h = SetFocus(win_child);
    line("SetFocus(the child), HCBT_SETFOCUS vetoed: ret %s err=%s, GetFocus after: %s", which(h), le(),
         which(GetFocus()));
    print_log("  then");
    cbt_veto = 0;
    proc_log = 0;
    DestroyWindow(win_a);
    win_a = win_child = NULL;
    drain();
    log_count = 0;
    unhook("the WH_CBT hook", cbt_hook);
}

/* --- getmsg ------------------------------------------------------------ */

static int getmsg_change;

static LRESULT CALLBACK getmsg_proc(int code, WPARAM wparam, LPARAM lparam)
{
    MSG *m = (MSG *)lparam;

    if (m->message == MSG_TEST) {
        note("WH_GETMESSAGE: code %d, %s, %s wParam=%lu window %s", code,
             wparam == PM_REMOVE ? "PM_REMOVE" : wparam == PM_NOREMOVE ? "PM_NOREMOVE" : "another wParam",
             msg_name(m->message), (unsigned long)m->wParam, which(m->hwnd));
        if (getmsg_change) {
            m->wParam = 999;
        }
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static void sec_getmsg(void)
{
    HHOOK h;
    MSG m;

    win_a = make_popup();
    h = hook_w("WH_GETMESSAGE", WH_GETMESSAGE, getmsg_proc);
    if (h == NULL) {
        DestroyWindow(win_a);
        return;
    }
    PostMessageW(win_a, MSG_TEST, 1, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log("GetMessageW of a posted message");
    PostMessageW(win_a, MSG_TEST, 2, 0);
    PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    print_log("PeekMessageW(PM_NOREMOVE)");
    PeekMessageW(&m, NULL, 0, 0, PM_REMOVE);
    print_log("PeekMessageW(PM_REMOVE)");
    SendMessageW(win_a, MSG_TEST, 3, 0);
    print_log("SendMessageW (not through the queue)");
    getmsg_change = 1;
    PostMessageW(win_a, MSG_TEST, 4, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log("GetMessageW, the hook setting wParam 999");
    line("  GetMessageW's message: wParam=%lu", (unsigned long)m.wParam);
    getmsg_change = 0;
    PostThreadMessageW(GetCurrentThreadId(), MSG_TEST, 5, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log("GetMessageW of a thread message");
    unhook("the WH_GETMESSAGE hook", h);
    PostMessageW(win_a, MSG_TEST, 6, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log("GetMessageW after the unhook");
    DestroyWindow(win_a);
    win_a = NULL;
    drain();
}

/* --- callwnd ----------------------------------------------------------- */

static LRESULT CALLBACK callwnd_proc(int code, WPARAM wparam, LPARAM lparam)
{
    CWPSTRUCT *c = (CWPSTRUCT *)lparam;

    if (c->message == MSG_TEST) {
        note("WH_CALLWNDPROC: code %d, wParam (sent by this thread) %s, %s %lu to %s", code,
             wparam ? "non-zero" : "0", msg_name(c->message), (unsigned long)c->wParam, which(c->hwnd));
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static LRESULT CALLBACK callwndret_proc(int code, WPARAM wparam, LPARAM lparam)
{
    CWPRETSTRUCT *c = (CWPRETSTRUCT *)lparam;

    if (c->message == MSG_TEST) {
        note("WH_CALLWNDPROCRET: code %d, wParam %s, %s %lu to %s, lResult %ld", code,
             wparam ? "non-zero" : "0", msg_name(c->message), (unsigned long)c->wParam, which(c->hwnd),
             (long)c->lResult);
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static DWORD WINAPI send_thread(LPVOID param)
{
    SendMessageW(win_a, MSG_TEST, 7, 0);
    return 0;
}

static void sec_callwnd(void)
{
    HHOOK h1, h2;
    LRESULT r;
    HANDLE t;
    DWORD tid;
    MSG m;

    win_a = make_popup();
    proc_log = 1;
    log_count = 0;
    h1 = hook_w("WH_CALLWNDPROC", WH_CALLWNDPROC, callwnd_proc);
    h2 = hook_w("WH_CALLWNDPROCRET", WH_CALLWNDPROCRET, callwndret_proc);
    r = SendMessageW(win_a, MSG_TEST, 1, 0);
    print_log("SendMessageW(A, MSG_TEST, 1)");
    line("  its return: %ld", (long)r);
    PostMessageW(win_a, MSG_TEST, 2, 0);
    drain();
    print_log("PostMessageW(A, MSG_TEST, 2), dispatched");
    r = CallWindowProcW(hook_wndproc, win_a, MSG_TEST, 3, 0);
    print_log("CallWindowProcW(the procedure, A, MSG_TEST, 3)");
    t = CreateThread(NULL, 0, send_thread, NULL, 0, &tid);
    while (t != NULL && MsgWaitForMultipleObjects(1, &t, FALSE, WAIT_MS, QS_SENDMESSAGE) == WAIT_OBJECT_0 + 1) {
        PeekMessageW(&m, NULL, 0, 0, PM_NOREMOVE);
    }
    if (t != NULL) {
        CloseHandle(t);
    }
    print_log("a second thread's SendMessageW(A, MSG_TEST, 7)");
    if (h1 != NULL) {
        unhook("the WH_CALLWNDPROC hook", h1);
    }
    if (h2 != NULL) {
        unhook("the WH_CALLWNDPROCRET hook", h2);
    }
    proc_log = 0;
    DestroyWindow(win_a);
    win_a = NULL;
    drain();
    log_count = 0;
}

/* --- msgfilter --------------------------------------------------------- */

static int filter_answer;
static int filter_dialog_codes;
static int filter_other_codes;
static int filter_logged;

static LRESULT CALLBACK msgfilter_proc(int code, WPARAM wparam, LPARAM lparam)
{
    MSG *m = (MSG *)lparam;

    if (code == MSGF_DIALOGBOX) {
        filter_dialog_codes++;
        if (m->message == MSG_TEST && !filter_logged) {
            filter_logged = 1;
            note("WH_MSGFILTER: MSGF_DIALOGBOX, %s wParam=%lu", msg_name(m->message), (unsigned long)m->wParam);
        }
    } else if (code == MSGF_OWN) {
        note("WH_MSGFILTER: the program's code 0x%X, %s wParam=%lu, answering %d", code, msg_name(m->message),
             (unsigned long)m->wParam, filter_answer);
        return filter_answer;
    } else if (code >= 0) {
        filter_other_codes++;
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static BOOL CALLBACK dlg_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_INITDIALOG) {
        PostMessageW(hwnd, MSG_TEST, 1, 0);
        return TRUE;
    }
    if (msg == MSG_TEST) {
        EndDialog(hwnd, 5);
        return TRUE;
    }
    return FALSE;
}

/* An empty dialog template: DLGTEMPLATE, then empty menu, class and
 * title (three WORDs), DWORD-aligned. */
static struct {
    DLGTEMPLATE t;
    WORD menu;
    WORD cls;
    WORD title;
    WORD pad;
} dlg_template;

static void filter_call(const char *what, callmsgfilter_fn fn, int answer)
{
    MSG m;
    BOOL r;

    ZeroMemory(&m, sizeof m);
    m.message = MSG_TEST;
    m.wParam = 8;
    filter_answer = answer;
    arm();
    r = fn(&m, MSGF_OWN);
    line("%s(MSG_TEST, the program's code): ret=%d err=%s", what, r, le());
    print_log("  the hook");
}

static BOOL WINAPI call_w(LPMSG m, int code)
{
    return CallMsgFilterW(m, code);
}

static BOOL WINAPI call_a(LPMSG m, int code)
{
    return CallMsgFilterA(m, code);
}

static void sec_msgfilter(void)
{
    HHOOK h;
    int r;
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    line("GetProcAddress(user32, CallMsgFilter): non-NULL %s", yesno(call_msg_filter != NULL));
    h = hook_w("WH_MSGFILTER", WH_MSGFILTER, msgfilter_proc);
    if (h == NULL) {
        return;
    }
    ZeroMemory(&dlg_template, sizeof dlg_template);
    dlg_template.t.style = WS_POPUP | WS_CAPTION | DS_MODALFRAME;
    dlg_template.t.x = (short)(cx / 8);
    dlg_template.t.y = (short)(cy / 8);
    dlg_template.t.cx = 80;
    dlg_template.t.cy = 40;
    filter_dialog_codes = filter_other_codes = filter_logged = 0;
    arm();
    r = DialogBoxIndirectParamW(GetModuleHandleA(NULL), &dlg_template.t, NULL, dlg_proc, 0);
    line("DialogBoxIndirectParamW, the dialog ending itself: ret=%ld err=%s", (long)r, le());
    print_log("  the hook");
    line("  MSGF_DIALOGBOX calls: some %s; other codes: %s", yesno(filter_dialog_codes > 0),
         filter_other_codes ? "some" : "none");
    filter_call("CallMsgFilterW", call_w, 0);
    filter_call("CallMsgFilterW", call_w, 1);
    filter_call("CallMsgFilterA", call_a, 1);
    if (call_msg_filter != NULL) {
        filter_call("CallMsgFilter", call_msg_filter, 1);
    }
    unhook("the WH_MSGFILTER hook", h);
    filter_call("CallMsgFilterW, no hook", call_w, 1);
}

/* --- keyboard and mouse ------------------------------------------------ */

static int key_swallow;

static LRESULT CALLBACK keyboard_proc(int code, WPARAM wparam, LPARAM lparam)
{
    if (wparam == VK_SHIFT) {
        note("WH_KEYBOARD: %s, VK_SHIFT, %s, repeat %lu", code == HC_ACTION ? "HC_ACTION" : code == HC_NOREMOVE ? "HC_NOREMOVE" : "another code",
             (lparam & 0x80000000) ? "up" : "down", (unsigned long)(lparam & 0xFFFF));
        if (key_swallow && code == HC_ACTION) {
            note("  answered 1");
            return 1;
        }
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static int fg_window(void)
{
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    line("GetProcAddress(user32, SendInput): non-NULL %s", yesno(send_input != NULL));
    if (send_input == NULL) {
        return 0;
    }
    win_a = make(WS_EX_TOPMOST, WS_POPUP | WS_VISIBLE, NULL, (cx - 200) / 2, (cy - 150) / 2, 200, 150);
    UpdateWindow(win_a);
    SetForegroundWindow(win_a);
    SetFocus(win_a);
    drain();
    Sleep(100);
    drain();
    line("the window is the foreground window: %s", yesno(GetForegroundWindow() == win_a));
    return GetForegroundWindow() == win_a;
}

static void shift(void)
{
    f2k_input in[2];

    ZeroMemory(in, sizeof in);
    in[0].type = 1;
    in[0].u.ki.wVk = VK_SHIFT;
    in[1] = in[0];
    in[1].u.ki.dwFlags = 0x0002;
    line("SendInput(Shift down and up): ret=%u", send_input(2, in, sizeof(f2k_input)));
    Sleep(100);
}

static void sec_keyboard(void)
{
    HHOOK h;
    MSG m;

    if (!fg_window()) {
        if (win_a != NULL) {
            DestroyWindow(win_a);
        }
        win_a = NULL;
        return;
    }
    h = hook_w("WH_KEYBOARD", WH_KEYBOARD, keyboard_proc);
    if (h != NULL) {
        proc_log = 1;
        log_count = 0;
        shift();
        PeekMessageW(&m, NULL, WM_KEYFIRST, WM_KEYLAST, PM_NOREMOVE);
        drain();
        print_log("a PM_NOREMOVE peek, then the queue read");
        key_swallow = 1;
        shift();
        drain();
        print_log("the hook swallowing the key, the queue read");
        key_swallow = 0;
        proc_log = 0;
        unhook("the WH_KEYBOARD hook", h);
    }
    DestroyWindow(win_a);
    win_a = NULL;
    drain();
}

static LRESULT CALLBACK mouse_proc(int code, WPARAM wparam, LPARAM lparam)
{
    MOUSEHOOKSTRUCT *mh = (MOUSEHOOKSTRUCT *)lparam;

    if (log_count < 6) {
        note("WH_MOUSE: %s, %s, window %s, hit-test %u", code == HC_ACTION ? "HC_ACTION" : code == HC_NOREMOVE ? "HC_NOREMOVE" : "another code",
             msg_name((UINT)wparam), which(mh->hwnd), mh->wHitTestCode);
    }
    return CallNextHookEx(NULL, code, wparam, lparam);
}

static void sec_mouse(void)
{
    HHOOK h;
    f2k_input in;
    RECT r;
    POINT saved;
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    GetCursorPos(&saved);
    SetCursorPos(0, 0);
    if (!fg_window()) {
        if (win_a != NULL) {
            DestroyWindow(win_a);
        }
        win_a = NULL;
        SetCursorPos(saved.x, saved.y);
        return;
    }
    h = hook_w("WH_MOUSE", WH_MOUSE, mouse_proc);
    if (h != NULL) {
        log_count = 0;
        GetWindowRect(win_a, &r);
        ZeroMemory(&in, sizeof in);
        in.type = 0;
        in.u.mi.dx = ((r.left + r.right + 1) * 32768) / cx;
        in.u.mi.dy = ((r.top + r.bottom + 1) * 32768) / cy;
        in.u.mi.dwFlags = 0x8001;
        line("SendInput(a move onto A's centre): ret=%u", send_input(1, &in, sizeof in));
        Sleep(100);
        drain();
        print_log("the queue read (the first six calls)");
        unhook("the WH_MOUSE hook", h);
    }
    DestroyWindow(win_a);
    win_a = NULL;
    SetCursorPos(saved.x, saved.y);
    drain();
}

/* --- chain ------------------------------------------------------------- */

static HHOOK chain_first, chain_second;
static int chain_mode;      /* 0 call next with the handle, 1 with NULL, 2 not at all, 3 unhook self */

static LRESULT CALLBACK chain_proc1(int code, WPARAM wparam, LPARAM lparam)
{
    if (((MSG *)lparam)->message == MSG_TEST) {
        note("the first hook installed");
    }
    return CallNextHookEx(chain_first, code, wparam, lparam);
}

static LRESULT CALLBACK chain_proc2(int code, WPARAM wparam, LPARAM lparam)
{
    LRESULT r = 0;

    if (((MSG *)lparam)->message != MSG_TEST) {
        return CallNextHookEx(chain_second, code, wparam, lparam);
    }
    note("the second hook installed");
    if (chain_mode == 0) {
        r = CallNextHookEx(chain_second, code, wparam, lparam);
        note("  CallNextHookEx(its handle) returned %ld", (long)r);
    } else if (chain_mode == 1) {
        r = CallNextHookEx(NULL, code, wparam, lparam);
        note("  CallNextHookEx(NULL) returned %ld", (long)r);
    } else if (chain_mode == 3) {
        note("  UnhookWindowsHookEx(itself): %d", UnhookWindowsHookEx(chain_second));
        r = CallNextHookEx(chain_second, code, wparam, lparam);
        note("  CallNextHookEx after: %ld", (long)r);
        chain_second = NULL;
    }
    return r;
}

static void chain_post(const char *what)
{
    MSG m;

    PostMessageW(win_a, MSG_TEST, 1, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log(what);
}

static void bad(const char *what, int id, HOOKPROC proc, HINSTANCE mod, DWORD tid)
{
    HHOOK h;

    arm();
    h = SetWindowsHookExW(id, proc, mod, tid);
    line("SetWindowsHookExW(%s): non-NULL %s err=%s", what, yesno(h != NULL), le());
    if (h != NULL) {
        UnhookWindowsHookEx(h);
    }
}

static void sec_chain(void)
{
    win_a = make_popup();
    chain_first = hook_w("WH_GETMESSAGE, the first", WH_GETMESSAGE, chain_proc1);
    chain_second = hook_w("WH_GETMESSAGE, the second", WH_GETMESSAGE, chain_proc2);
    if (chain_first == NULL || chain_second == NULL) {
        DestroyWindow(win_a);
        return;
    }
    chain_mode = 0;
    chain_post("a message read, CallNextHookEx with the hook's handle");
    chain_mode = 1;
    chain_post("a message read, CallNextHookEx with NULL");
    chain_mode = 2;
    chain_post("a message read, the second not calling the next");
    chain_mode = 3;
    chain_post("a message read, the second removing itself");
    chain_post("a message read after");
    unhook("the first", chain_first);
    unhook("the first again", chain_first);
    unhook("NULL", NULL);
    DestroyWindow(win_a);
    win_a = NULL;
    drain();

    bad("id 99", 99, chain_proc1, NULL, GetCurrentThreadId());
    bad("id -2", -2, chain_proc1, NULL, GetCurrentThreadId());
    bad("WH_GETMESSAGE, a NULL procedure", WH_GETMESSAGE, NULL, NULL, GetCurrentThreadId());
    bad("WH_GETMESSAGE, thread 0, no module", WH_GETMESSAGE, chain_proc1, NULL, 0);
    bad("WH_GETMESSAGE, a thread id no thread has", WH_GETMESSAGE, chain_proc1, NULL, 0xFFFFFFF0);
    bad("WH_GETMESSAGE, this thread, the program's module", WH_GETMESSAGE, chain_proc1, GetModuleHandleA(NULL),
        GetCurrentThreadId());
}

/* --- oldstyle ---------------------------------------------------------- */

static HHOOK old_hook;

static LRESULT CALLBACK old_proc(int code, WPARAM wparam, LPARAM lparam)
{
    if (((MSG *)lparam)->message == MSG_TEST) {
        note("the old-style hook: code %d, %s", code, msg_name(((MSG *)lparam)->message));
    }
    return CallNextHookEx(old_hook, code, wparam, lparam);
}

static void old_round(const char *what, sethook_fn set)
{
    MSG m;
    BOOL r;

    arm();
    old_hook = set(WH_GETMESSAGE, old_proc);
    line("%s(WH_GETMESSAGE): non-NULL %s err=%s", what, yesno(old_hook != NULL), le());
    PostMessageW(win_a, MSG_TEST, 1, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log("  a message read");
    arm();
    r = unhook_old(WH_GETMESSAGE, old_proc);
    line("UnhookWindowsHook(WH_GETMESSAGE, the procedure): ret=%d err=%s", r, le());
    arm();
    r = unhook_old(WH_GETMESSAGE, old_proc);
    line("UnhookWindowsHook again: ret=%d err=%s", r, le());
    PostMessageW(win_a, MSG_TEST, 2, 0);
    GetMessageW(&m, NULL, 0, 0);
    print_log("  a message read after");
}

static void sec_oldstyle(void)
{
    line("GetProcAddress(user32, SetWindowsHookW, SetWindowsHookA, UnhookWindowsHook): %s %s %s",
         yesno(set_hook_w != NULL), yesno(set_hook_a != NULL), yesno(unhook_old != NULL));
    if (set_hook_w == NULL || set_hook_a == NULL || unhook_old == NULL) {
        return;
    }
    win_a = make_popup();
    old_round("SetWindowsHookW", set_hook_w);
    old_round("SetWindowsHookA", set_hook_a);
    DestroyWindow(win_a);
    win_a = NULL;
    drain();
}

/* --- winevent ---------------------------------------------------------- */

static const char *event_name(DWORD e)
{
    static char b[4][16];
    static int n;
    char *s;

    switch (e) {
    case F2K_EVENT_OBJECT_CREATE: return "EVENT_OBJECT_CREATE";
    case F2K_EVENT_OBJECT_DESTROY: return "EVENT_OBJECT_DESTROY";
    case F2K_EVENT_OBJECT_SHOW: return "EVENT_OBJECT_SHOW";
    case F2K_EVENT_OBJECT_HIDE: return "EVENT_OBJECT_HIDE";
    case F2K_EVENT_OBJECT_NAMECHANGE: return "EVENT_OBJECT_NAMECHANGE";
    case F2K_EVENT_OBJECT_LOCATIONCHANGE: return "EVENT_OBJECT_LOCATIONCHANGE";
    case F2K_EVENT_OBJECT_REORDER: return "EVENT_OBJECT_REORDER";
    case F2K_EVENT_OBJECT_FOCUS: return "EVENT_OBJECT_FOCUS";
    case F2K_EVENT_OBJECT_STATECHANGE: return "EVENT_OBJECT_STATECHANGE";
    case F2K_EVENT_SYSTEM_FOREGROUND: return "EVENT_SYSTEM_FOREGROUND";
    case F2K_EVENT_OWN: return "the program's event";
    }
    s = b[n++ & 3];
    sprintf(s, "0x%04lX", e);
    return s;
}

static f2k_hwineventhook we_hook;
static int we_calls;

static VOID CALLBACK winevent_proc(f2k_hwineventhook hook, DWORD event, HWND h, LONG obj, LONG child, DWORD thread,
                                   DWORD time)
{
    we_calls++;
    if (h != NULL && h != win_a && h != win_child) {
        return;     /* another window's event: not the program's to print */
    }
    note("WinEvent: %s, window %s, idObject %ld, idChild %ld, the hook's handle %s, this thread %s",
         event_name(event), which(h), (long)obj, (long)child, yesno(hook == we_hook),
         yesno(thread == GetCurrentThreadId()));
}

static f2k_hwineventhook we_set(const char *what, DWORD lo, DWORD hi, HMODULE mod, DWORD flags)
{
    f2k_hwineventhook h;

    arm();
    h = set_win_event_hook(lo, hi, mod, winevent_proc, GetCurrentProcessId(), GetCurrentThreadId(), flags);
    line("SetWinEventHook(%s): non-NULL %s err=%s", what, yesno(h != NULL), le());
    return h;
}

static void we_unhook(const char *what, f2k_hwineventhook h)
{
    BOOL r;

    arm();
    r = unhook_win_event(h);
    line("UnhookWinEvent(%s): ret=%d err=%s", what, r, le());
}

static void sec_winevent(void)
{
    f2k_hwineventhook h;

    line("GetProcAddress(user32, SetWinEventHook, UnhookWinEvent, NotifyWinEvent): %s %s %s",
         yesno(set_win_event_hook != NULL), yesno(unhook_win_event != NULL), yesno(notify_win_event != NULL));
    if (set_win_event_hook == NULL || unhook_win_event == NULL || notify_win_event == NULL) {
        return;
    }
    we_hook = we_set("EVENT_OBJECT_CREATE to EVENT_OBJECT_DESTROY, out of context", F2K_EVENT_OBJECT_CREATE,
                     F2K_EVENT_OBJECT_DESTROY, NULL, F2K_WINEVENT_OUTOFCONTEXT);
    if (we_hook == NULL) {
        return;
    }
    win_a = make_popup();
    line("a popup created, before the queue is read: %d record(s)", log_count);
    drain();
    print_log("then the queue read");
    DestroyWindow(win_a);
    drain();
    print_log("the popup destroyed, the queue read");
    win_a = NULL;
    we_unhook("it", we_hook);
    we_unhook("it again", we_hook);

    we_hook = we_set("EVENT_MIN to EVENT_MAX, out of context", F2K_EVENT_MIN, F2K_EVENT_MAX, NULL,
                     F2K_WINEVENT_OUTOFCONTEXT);
    if (we_hook != NULL) {
        win_a = make_popup();
        drain();
        SetWindowTextW(win_a, L"renamed");
        drain();
        ShowWindow(win_a, SW_SHOWNA);
        drain();
        ShowWindow(win_a, SW_HIDE);
        drain();
        print_log("a popup created, renamed, shown and hidden");
        notify_win_event(F2K_EVENT_OWN, win_a, 0, 7);
        line("NotifyWinEvent(the program's event, the popup, 0, 7), before the queue is read: %d record(s)", log_count);
        drain();
        print_log("then the queue read");
        DestroyWindow(win_a);
        win_a = NULL;
        drain();
        log_count = 0;
        we_unhook("it", we_hook);
    }

    we_hook = we_set("the program's event only, WINEVENT_SKIPOWNTHREAD", F2K_EVENT_OWN, F2K_EVENT_OWN, NULL,
                     F2K_WINEVENT_SKIPOWNTHREAD);
    if (we_hook != NULL) {
        win_a = make_popup();
        notify_win_event(F2K_EVENT_OWN, win_a, 0, 0);
        drain();
        print_log("NotifyWinEvent of it, the queue read");
        DestroyWindow(win_a);
        win_a = NULL;
        drain();
        log_count = 0;
        we_unhook("it", we_hook);
    }
    h = we_set("an inverted range", F2K_EVENT_OBJECT_DESTROY, F2K_EVENT_OBJECT_CREATE, NULL, F2K_WINEVENT_OUTOFCONTEXT);
    if (h != NULL) {
        unhook_win_event(h);
    }
    h = we_set("WINEVENT_INCONTEXT, no module", F2K_EVENT_OBJECT_CREATE, F2K_EVENT_OBJECT_DESTROY, NULL,
               F2K_WINEVENT_INCONTEXT);
    if (h != NULL) {
        unhook_win_event(h);
    }
    we_unhook("NULL", NULL);
    we_hook = NULL;
}

static const section_t sections[] = {
    { "cbt", sec_cbt, F2KT_ALWAYS },
    { "veto", sec_veto, F2KT_ALWAYS },
    { "getmsg", sec_getmsg, F2KT_ALWAYS },
    { "callwnd", sec_callwnd, F2KT_ALWAYS },
    { "msgfilter", sec_msgfilter, F2KT_ALWAYS },
    { "keyboard", sec_keyboard, F2KT_ALWAYS },
    { "mouse", sec_mouse, F2KT_ALWAYS },
    { "chain", sec_chain, F2KT_ALWAYS },
    { "oldstyle", sec_oldstyle, F2KT_ALWAYS },
    { "winevent", sec_winevent, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    set_win_event_hook = (setwinevent_fn)GetProcAddress(user, "SetWinEventHook");
    unhook_win_event = (unhookwinevent_fn)GetProcAddress(user, "UnhookWinEvent");
    notify_win_event = (notifywinevent_fn)GetProcAddress(user, "NotifyWinEvent");
    set_hook_a = (sethook_fn)GetProcAddress(user, "SetWindowsHookA");
    set_hook_w = (sethook_fn)GetProcAddress(user, "SetWindowsHookW");
    unhook_old = (unhook_fn)GetProcAddress(user, "UnhookWindowsHook");
    call_msg_filter = (callmsgfilter_fn)GetProcAddress(user, "CallMsgFilter");
    send_input = (send_input_fn)GetProcAddress(user, "SendInput");
    return run_sections("hooks", sections, argc, argv);
}
