/*
 * focus - keyboard focus, enabling and activation in user32: SetFocus
 * and GetFocus, EnableWindow and IsWindowEnabled, SetActiveWindow and
 * GetActiveWindow, and the WM_SETFOCUS, WM_KILLFOCUS, WM_ENABLE,
 * WM_ACTIVATE, WM_NCACTIVATE, WM_ACTIVATEAPP and WM_CANCELMODE the
 * program's windows receive, in their order.
 *
 * The windows: top1, a visible WS_POPUP | WS_CAPTION window at screen
 * (40,40), 200x120, with three children: child1 at (10,10) and child2
 * at (80,10), both 60x30 and visible, and hidden at (10,60), 60x30,
 * without WS_VISIBLE; the active and destroy sections add top2, the
 * same at (260,40), shown without activation (SW_SHOWNOACTIVATE).
 * Activation needs visible windows, so these show on the screen while
 * the section runs.
 *
 * Which messages come, and in which order, may depend on whether the
 * program is the foreground: each section starts by showing top1 and
 * asking for the foreground (SetForegroundWindow(top1)), and prints
 * whether top1 is then the foreground window (GetForegroundWindow).
 * tests\capture.bat runs from a console that is the foreground, so a
 * program it starts may take it; when top1 is not the foreground, the
 * block shows it and goes on.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed: a window prints by its label ("top1", "top2",
 * "child1", "child2", "hidden", "dead" for a destroyed window's handle,
 * "NULL", "other" for any other, another program's window included);
 * every call under observation is armed with the last-error sentinel
 * and its line prints ret= and err=. The window procedure records the
 * messages above (the window, the message, and: WM_SETFOCUS's and
 * WM_KILLFOCUS's wParam as a label, WM_ENABLE's and WM_NCACTIVATE's
 * wParam, WM_ACTIVATE's state, minimized flag and other window,
 * WM_ACTIVATEAPP's wParam; never WM_ACTIVATEAPP's lParam, a thread id),
 * hands every message to DefWindowProcA and calls nothing else; after
 * each call the program dispatches what its queue holds for 100 ms, then
 * prints the call and the records, never from inside the procedure.
 * Each section registers the class (once per process), creates its own
 * windows and destroys them at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   focus     SetFocus to child1, child2, top1, NULL and the hidden
 *             child, and to a destroyed window: the returns (the window
 *             that had the focus), GetFocus after each, the records
 *   enable    IsWindowEnabled; EnableWindow(FALSE) on the focused
 *             child1 (its previous state, GetFocus after), again,
 *             SetFocus to the disabled child1, EnableWindow(TRUE);
 *             EnableWindow(FALSE) on top1 with child2 focused (GetFocus,
 *             GetActiveWindow, IsWindowEnabled of top1 and child2), then
 *             TRUE again; EnableWindow on a destroyed window
 *   active    SetActiveWindow to top2, back to top1, to child1, to a
 *             disabled top2, and to a destroyed window: the returns,
 *             GetActiveWindow, GetFocus and GetForegroundWindow after
 *             each, the records
 *   destroy   DestroyWindow of the focused child1, then of top1 with
 *             child2 focused: GetFocus, GetActiveWindow and
 *             GetForegroundWindow after each, the records
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat focus):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% focus.c user32.lib
 */

#include "../common/f2kt.h"

#define CLASS_NAME "F2KFocusWin"

static HWND top1, top2, child1, child2, hidden;
/* A window created and destroyed again: its handle names no window. */
static HWND dead;

/* The procedure's records, printed after each call. */
#define MAX_RECORDS 48

typedef struct {
    HWND hwnd;
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
} record_t;

static record_t records[MAX_RECORDS];
static int record_count;
static int records_lost;

static LRESULT CALLBACK recorder(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_ENABLE:
    case WM_ACTIVATE:
    case WM_NCACTIVATE:
    case WM_ACTIVATEAPP:
    case WM_CANCELMODE:
        if (record_count < MAX_RECORDS) {
            records[record_count].hwnd = hwnd;
            records[record_count].msg = msg;
            records[record_count].wparam = wparam;
            records[record_count].lparam = lparam;
            record_count++;
        } else {
            records_lost++;
        }
        break;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

static const char *label(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == top1) {
        return "top1";
    }
    if (h == top2) {
        return "top2";
    }
    if (h == child1) {
        return "child1";
    }
    if (h == child2) {
        return "child2";
    }
    if (h == hidden) {
        return "hidden";
    }
    if (h == dead) {
        return "dead";
    }
    return "other";
}

static void reset_records(void)
{
    record_count = 0;
    records_lost = 0;
}

static void print_records(void)
{
    int i;
    const record_t *r;

    if (record_count == 0) {
        line("  messages: none");
    }
    for (i = 0; i < record_count; i++) {
        r = &records[i];
        switch (r->msg) {
        case WM_SETFOCUS:
            line("  %s WM_SETFOCUS from %s", label(r->hwnd), label((HWND)r->wparam));
            break;
        case WM_KILLFOCUS:
            line("  %s WM_KILLFOCUS to %s", label(r->hwnd), label((HWND)r->wparam));
            break;
        case WM_ENABLE:
            line("  %s WM_ENABLE wParam=%lu", label(r->hwnd), (unsigned long)r->wparam);
            break;
        case WM_ACTIVATE:
            line("  %s WM_ACTIVATE state=%u minimized=%u other=%s", label(r->hwnd),
                 (unsigned)LOWORD(r->wparam), (unsigned)HIWORD(r->wparam), label((HWND)r->lparam));
            break;
        case WM_NCACTIVATE:
            line("  %s WM_NCACTIVATE wParam=%lu", label(r->hwnd), (unsigned long)r->wparam);
            break;
        case WM_ACTIVATEAPP:
            line("  %s WM_ACTIVATEAPP wParam=%lu", label(r->hwnd), (unsigned long)r->wparam);
            break;
        case WM_CANCELMODE:
            line("  %s WM_CANCELMODE", label(r->hwnd));
            break;
        }
    }
    if (records_lost) {
        line("  (%d more not recorded)", records_lost);
    }
    reset_records();
}

/* Dispatch what the queue holds for 100 ms: whatever the call queued
 * for the program's windows reaches them before the records print. */
static void settle(void)
{
    MSG m;
    DWORD start = GetTickCount();

    for (;;) {
        while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
        if (GetTickCount() - start >= 100) {
            break;
        }
        Sleep(10);
    }
}

/* The state after a call: the focus and the active window, and the
 * foreground window when asked for. */
static void state(int with_foreground)
{
    HWND h;

    arm();
    h = GetFocus();
    line("  GetFocus: %s err=%s", label(h), le());
    arm();
    h = GetActiveWindow();
    line("  GetActiveWindow: %s err=%s", label(h), le());
    if (with_foreground) {
        arm();
        h = GetForegroundWindow();
        line("  GetForegroundWindow: %s err=%s", label(h), le());
    }
}

static BOOL register_class(void)
{
    static BOOL registered;
    WNDCLASSA wc;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = recorder;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = CLASS_NAME;
        registered = RegisterClassA(&wc) != 0;
    }
    return registered;
}

static HWND make(HWND owner, DWORD style, int x, int y, int cx, int cy, int id)
{
    return CreateWindowExA(0, CLASS_NAME, "focus", style, x, y, cx, cy, owner, (HMENU)id,
                           GetModuleHandleA(NULL), NULL);
}

/* The windows (top2 only when asked for), top1 shown and asked to be the
 * foreground; the records start empty. */
static void setup(int with_top2)
{
    MSG m;
    BOOL ok;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
    }
    top1 = top2 = child1 = child2 = hidden = dead = NULL;
    ok = register_class();
    top1 = make(NULL, WS_POPUP | WS_CAPTION, 40, 40, 200, 120, 0);
    child1 = make(top1, WS_CHILD | WS_VISIBLE, 10, 10, 60, 30, 1);
    child2 = make(top1, WS_CHILD | WS_VISIBLE, 80, 10, 60, 30, 2);
    hidden = make(top1, WS_CHILD, 10, 60, 60, 30, 3);
    dead = make(NULL, WS_POPUP, 0, 0, 10, 10, 0);
    if (dead != NULL) {
        DestroyWindow(dead);
    }
    ok = ok && top1 != NULL && child1 != NULL && child2 != NULL && hidden != NULL && dead != NULL;
    if (with_top2) {
        top2 = make(NULL, WS_POPUP | WS_CAPTION, 260, 40, 200, 120, 0);
        ok = ok && top2 != NULL;
    }
    line("setup: the class and the windows created: %s", yesno(ok));
    ShowWindow(top1, SW_SHOW);
    if (top2 != NULL) {
        ShowWindow(top2, SW_SHOWNOACTIVATE);
    }
    SetForegroundWindow(top1);
    settle();
    line("SetForegroundWindow(top1): top1 is the foreground: %s",
         yesno(GetForegroundWindow() == top1));
    state(0);
    reset_records();
}

static void teardown(void)
{
    if (top2 != NULL && IsWindow(top2)) {
        DestroyWindow(top2);
    }
    if (top1 != NULL && IsWindow(top1)) {
        DestroyWindow(top1);
    }
    settle();
    reset_records();
}

/* --- focus --------------------------------------------------------- */

static void set_focus(const char *name, HWND h)
{
    HWND r;
    DWORD e;

    arm();
    r = SetFocus(h);
    e = GetLastError();
    settle();
    line("SetFocus(%s): ret=%s err=%s", name, label(r), le_of(e));
    print_records();
    state(0);
}

static void sec_focus(void)
{
    setup(0);
    set_focus("child1", child1);
    set_focus("child2", child2);
    set_focus("child2", child2);
    set_focus("top1", top1);
    set_focus("child1", child1);
    set_focus("NULL", NULL);
    set_focus("child2", child2);
    set_focus("hidden", hidden);
    set_focus("a destroyed window", dead);
    teardown();
}

/* --- enable -------------------------------------------------------- */

static void enable(const char *name, HWND h, BOOL on)
{
    BOOL r;
    DWORD e;

    arm();
    r = EnableWindow(h, on);
    e = GetLastError();
    settle();
    line("EnableWindow(%s, %s): ret=%d err=%s", name, on ? "TRUE" : "FALSE", r, le_of(e));
    print_records();
    state(0);
}

static void is_enabled(const char *name, HWND h)
{
    BOOL r;

    arm();
    r = IsWindowEnabled(h);
    line("IsWindowEnabled(%s): ret=%d err=%s", name, r, le());
}

static void sec_enable(void)
{
    setup(0);
    set_focus("child1", child1);
    is_enabled("child1", child1);
    enable("child1", child1, FALSE);
    is_enabled("child1", child1);
    enable("child1", child1, FALSE);
    set_focus("child1", child1);
    enable("child1", child1, TRUE);
    is_enabled("child1", child1);
    enable("child1", child1, TRUE);

    set_focus("child2", child2);
    enable("top1", top1, FALSE);
    is_enabled("top1", top1);
    is_enabled("child2", child2);
    set_focus("child2", child2);
    enable("top1", top1, TRUE);
    is_enabled("top1", top1);

    enable("a destroyed window", dead, FALSE);
    is_enabled("a destroyed window", dead);
    teardown();
}

/* --- active -------------------------------------------------------- */

static void set_active(const char *name, HWND h)
{
    HWND r;
    DWORD e;

    arm();
    r = SetActiveWindow(h);
    e = GetLastError();
    settle();
    line("SetActiveWindow(%s): ret=%s err=%s", name, label(r), le_of(e));
    print_records();
    state(1);
}

static void sec_active(void)
{
    setup(1);
    set_active("top2", top2);
    set_active("top1", top1);
    set_active("top1", top1);
    set_active("child1", child1);
    enable("top2", top2, FALSE);
    set_active("top2", top2);
    enable("top2", top2, TRUE);
    set_active("a destroyed window", dead);
    teardown();
}

/* --- destroy ------------------------------------------------------- */

static void destroy(const char *name, HWND h)
{
    BOOL r;
    DWORD e;

    arm();
    r = DestroyWindow(h);
    e = GetLastError();
    settle();
    line("DestroyWindow(%s): ret=%d err=%s", name, r, le_of(e));
    print_records();
    state(1);
}

static void sec_destroy(void)
{
    setup(1);
    set_focus("child1", child1);
    destroy("child1", child1);
    set_focus("child2", child2);
    destroy("top1", top1);
    teardown();
}

static const section_t sections[] = {
    { "focus", sec_focus, F2KT_ALWAYS },
    { "enable", sec_enable, F2KT_ALWAYS },
    { "active", sec_active, F2KT_ALWAYS },
    { "destroy", sec_destroy, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("focus", sections, argc, argv);
}
