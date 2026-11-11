/*
 * caret - the caret in user32: CreateCaret, DestroyCaret, ShowCaret,
 * HideCaret, SetCaretPos and GetCaretPos; the hide count ShowCaret and
 * HideCaret keep, and the caret against focus changes and its window's
 * destruction.
 *
 * Whether the caret shows, its window and its rectangle come from
 * GetGUIThreadInfo (reached through GetProcAddress, the MSVC 6 headers
 * predating it; its GUITHREADINFO declared here): hwndCaret, rcCaret
 * (client coordinates) and the GUI_CARETBLINKING flag, set while the
 * caret is visible. The caret blinks by a timer the thread's message
 * retrieval serves, so each state prints at once after the call, with
 * no message retrieved between: the blink cannot turn it.
 *
 * The windows: top, a visible WS_POPUP | WS_CAPTION window at screen
 * (40,40), 240x160, of the section's own class; child1 at (10,10) and
 * child2 at (120,10), both 100x30 and visible; in focus, edit1 and
 * edit2, children of a second class whose procedure does what the
 * documentation asks of a window with a caret: on WM_SETFOCUS it
 * creates the caret (2x16), puts it at (5,5) and shows it, on
 * WM_KILLFOCUS it destroys it. Each section asks for the foreground
 * (SetForegroundWindow(top)) and prints whether top is then the
 * foreground window, as the focus fixture does.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed: a window prints by its label ("top", "child1",
 * "child2", "edit1", "edit2", "NULL", "other"); every call under
 * observation is armed with the last-error sentinel and its line
 * prints ret= and err=. GetCaretPos's point holds (-7,-7) before the
 * call. The caret's sizes are the program's own, and the default
 * width and height (0 asked for) print as relations to SM_CXBORDER and
 * SM_CYBORDER. Each section creates its windows and destroys them at
 * its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   the caret before there is one; CreateCaret of a solid
 *            2x16 caret (the state, GetCaretPos), SetCaretPos inside
 *            and outside the client area; a gray caret ((HBITMAP)1)
 *            replacing it; width and height 0; CreateCaret of NULL and
 *            of a destroyed window; DestroyCaret, twice; GetCaretPos,
 *            SetCaretPos, ShowCaret and HideCaret with no caret
 *   show     the hide count: ShowCaret twice, HideCaret twice, then
 *            ShowCaret until it shows; ShowCaret(NULL) and
 *            HideCaret(NULL); ShowCaret and HideCaret on a window that
 *            does not own the caret; SetCaretPos while hidden; a new
 *            caret after HideCaret (hidden again or not)
 *   focus    a caret on child1 as the focus moves to child2, to top and
 *            back; CreateCaret on child2 while child1 owns it;
 *            DestroyWindow of the owner; the documented pattern's edit1
 *            and edit2 as the focus moves between them and away;
 *            another thread's CreateCaret, HideCaret and DestroyCaret
 *            on this thread's windows, and the caret after
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat caret):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% caret.c user32.lib
 */

#include "../common/f2kt.h"

#define TOP_CLASS L"F2KCaretTop"
#define EDIT_CLASS L"F2KCaretEdit"

#ifndef GUI_CARETBLINKING
#define GUI_CARETBLINKING 0x00000001
#endif

/* GUITHREADINFO, as Windows 2000 lays it out. */
typedef struct {
    DWORD cbSize;
    DWORD flags;
    HWND hwndActive;
    HWND hwndFocus;
    HWND hwndCapture;
    HWND hwndMenuOwner;
    HWND hwndMoveSize;
    HWND hwndCaret;
    RECT rcCaret;
} gui_thread_info_t;

typedef BOOL (WINAPI *get_gui_thread_info_t)(DWORD, gui_thread_info_t *);

static get_gui_thread_info_t get_gui_thread_info;
static DWORD main_thread;

static HWND top, child1, child2, edit1, edit2, dead;

static HINSTANCE instance(void)
{
    return GetModuleHandleW(NULL);
}

static const char *label(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == top) {
        return "top";
    }
    if (h == child1) {
        return "child1";
    }
    if (h == child2) {
        return "child2";
    }
    if (h == edit1) {
        return "edit1";
    }
    if (h == edit2) {
        return "edit2";
    }
    return "other";
}

/* The thread's caret, from GetGUIThreadInfo. */
static void print_caret(void)
{
    gui_thread_info_t g;

    if (get_gui_thread_info == NULL) {
        line("  GetGUIThreadInfo: not exported");
        return;
    }
    ZeroMemory(&g, sizeof g);
    g.cbSize = sizeof g;
    if (!get_gui_thread_info(main_thread, &g)) {
        line("  GetGUIThreadInfo failed: err=%lu", GetLastError());
        return;
    }
    if (g.hwndCaret == NULL) {
        line("  caret: none (hwndCaret NULL) visible %s", yesno(g.flags & GUI_CARETBLINKING));
        return;
    }
    line("  caret: window %s visible %s rect (%ld,%ld)-(%ld,%ld)", label(g.hwndCaret),
         yesno(g.flags & GUI_CARETBLINKING), (long)g.rcCaret.left, (long)g.rcCaret.top, (long)g.rcCaret.right,
         (long)g.rcCaret.bottom);
}

/* The caret's size against the border sizes (a caret of width and
 * height 0). */
static void print_caret_size_rel(void)
{
    gui_thread_info_t g;

    if (get_gui_thread_info == NULL) {
        return;
    }
    ZeroMemory(&g, sizeof g);
    g.cbSize = sizeof g;
    if (get_gui_thread_info(main_thread, &g) && g.hwndCaret != NULL) {
        line("  width SM_CXBORDER %s height SM_CYBORDER %s",
             yesno(g.rcCaret.right - g.rcCaret.left == GetSystemMetrics(SM_CXBORDER)),
             yesno(g.rcCaret.bottom - g.rcCaret.top == GetSystemMetrics(SM_CYBORDER)));
    }
}

static void create_caret(HWND h, HBITMAP bmp, int w, int ht, const char *what)
{
    BOOL r;

    arm();
    r = CreateCaret(h, bmp, w, ht);
    line("CreateCaret(%s): ret=%d err=%s", what, r, le());
    print_caret();
}

static void destroy_caret(const char *what)
{
    BOOL r;

    arm();
    r = DestroyCaret();
    line("DestroyCaret(%s): ret=%d err=%s", what, r, le());
    print_caret();
}

static void show_caret(HWND h, const char *what)
{
    BOOL r;

    arm();
    r = ShowCaret(h);
    line("ShowCaret(%s): ret=%d err=%s", what, r, le());
    print_caret();
}

static void hide_caret(HWND h, const char *what)
{
    BOOL r;

    arm();
    r = HideCaret(h);
    line("HideCaret(%s): ret=%d err=%s", what, r, le());
    print_caret();
}

static void set_pos(int x, int y)
{
    BOOL r;

    arm();
    r = SetCaretPos(x, y);
    line("SetCaretPos(%d, %d): ret=%d err=%s", x, y, r, le());
    print_caret();
}

static void get_pos(const char *what)
{
    POINT p;
    BOOL r;

    p.x = -7;
    p.y = -7;
    arm();
    r = GetCaretPos(&p);
    line("GetCaretPos(%s): ret=%d err=%s point (%ld,%ld)", what, r, le(), (long)p.x, (long)p.y);
}

static void set_focus(HWND h)
{
    HWND r;

    arm();
    r = SetFocus(h);
    line("SetFocus(%s): ret=%s err=%s focus %s", label(h), label(r), le(), label(GetFocus()));
    print_caret();
}

/* --- The windows ------------------------------------------------------- */

static LRESULT CALLBACK top_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/* The documented pattern: the caret made on WM_SETFOCUS and destroyed
 * on WM_KILLFOCUS. */
static LRESULT CALLBACK edit_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_SETFOCUS:
        CreateCaret(hwnd, NULL, 2, 16);
        SetCaretPos(5, 5);
        ShowCaret(hwnd);
        return 0;
    case WM_KILLFOCUS:
        DestroyCaret();
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void register_classes(void)
{
    WNDCLASSW wc;
    ATOM a, b;
    DWORD err;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = top_proc;
    wc.hInstance = instance();
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = TOP_CLASS;
    arm();
    a = RegisterClassW(&wc);
    err = GetLastError();
    wc.lpfnWndProc = edit_proc;
    wc.lpszClassName = EDIT_CLASS;
    b = RegisterClassW(&wc);
    line("RegisterClassW(F2KCaretTop, F2KCaretEdit): atoms nonzero %s err=%s", yesno(a != 0 && b != 0),
         le_of(err));
}

/* top, child1 and child2, top shown and asked to be the foreground. */
static void open_windows(void)
{
    get_gui_thread_info = (get_gui_thread_info_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetGUIThreadInfo");
    main_thread = GetCurrentThreadId();
    edit1 = NULL;
    edit2 = NULL;
    register_classes();
    top = CreateWindowExW(0, TOP_CLASS, L"caret", WS_POPUP | WS_CAPTION | WS_VISIBLE, 40, 40, 240, 160, NULL, NULL,
                          instance(), NULL);
    child1 = CreateWindowExW(0, TOP_CLASS, L"child1", WS_CHILD | WS_VISIBLE, 10, 10, 100, 30, top, (HMENU)1,
                             instance(), NULL);
    child2 = CreateWindowExW(0, TOP_CLASS, L"child2", WS_CHILD | WS_VISIBLE, 120, 10, 100, 30, top, (HMENU)2,
                             instance(), NULL);
    line("the windows top, child1, child2: non-NULL %s",
         yesno(top != NULL && child1 != NULL && child2 != NULL));
    dead = CreateWindowExW(0, TOP_CLASS, L"dead", WS_POPUP, 0, 0, 10, 10, NULL, NULL, instance(), NULL);
    DestroyWindow(dead);
    SetForegroundWindow(top);
    line("SetForegroundWindow(top): top is the foreground: %s", yesno(GetForegroundWindow() == top));
    SetFocus(top);
    line("SetFocus(top): focus %s", label(GetFocus()));
}

static void close_windows(void)
{
    MSG m;
    int n = 0;

    if (top != NULL) {
        DestroyWindow(top);
    }
    while (n++ < 500 && PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
    UnregisterClassW(EDIT_CLASS, instance());
    UnregisterClassW(TOP_CLASS, instance());
}

/* --- create ------------------------------------------------------------ */

static void sec_create(void)
{
    open_windows();
    line("-- no caret yet");
    print_caret();
    get_pos("no caret");

    create_caret(top, NULL, 2, 16, "top, NULL, 2, 16");
    get_pos("top's");
    set_pos(10, 20);
    get_pos("top's");
    set_pos(-5, 300);
    get_pos("top's");
    create_caret(top, (HBITMAP)1, 3, 10, "top, (HBITMAP)1 (gray), 3, 10");
    get_pos("the new caret");
    create_caret(top, NULL, 0, 0, "top, NULL, 0, 0");
    print_caret_size_rel();
    create_caret(child1, NULL, 4, 8, "child1, NULL, 4, 8");
    create_caret(NULL, NULL, 2, 16, "NULL, NULL, 2, 16");
    create_caret(dead, NULL, 2, 16, "a destroyed window, NULL, 2, 16");

    destroy_caret("the caret");
    destroy_caret("no caret");
    get_pos("no caret");
    set_pos(1, 1);
    show_caret(top, "top, no caret");
    hide_caret(top, "top, no caret");
    close_windows();
}

/* --- show -------------------------------------------------------------- */

static void sec_show(void)
{
    open_windows();
    create_caret(top, NULL, 2, 16, "top, NULL, 2, 16");
    show_caret(top, "top");
    show_caret(top, "top, again");
    hide_caret(top, "top");
    hide_caret(top, "top, again");
    show_caret(top, "top");
    show_caret(top, "top");
    show_caret(top, "top");
    hide_caret(NULL, "NULL");
    show_caret(NULL, "NULL");
    hide_caret(child1, "child1 (not the owner)");
    show_caret(child1, "child1 (not the owner)");
    hide_caret(dead, "a destroyed window");
    hide_caret(top, "top");
    set_pos(30, 40);
    get_pos("top's, hidden");
    show_caret(top, "top");
    hide_caret(top, "top");
    hide_caret(top, "top");
    hide_caret(top, "top");
    create_caret(top, NULL, 2, 16, "top, NULL, 2, 16, a new caret after three HideCaret");
    show_caret(top, "top");
    destroy_caret("top's");
    close_windows();
}

/* --- focus ------------------------------------------------------------- */

/* What the other thread's calls returned. */
static BOOL other_create, other_hide, other_destroy;
static DWORD other_create_err, other_hide_err, other_destroy_err;

static DWORD WINAPI other_thread(LPVOID unused)
{
    (void)unused;
    SetLastError(F2KT_UNTOUCHED);
    other_create = CreateCaret(child2, NULL, 6, 6);
    other_create_err = GetLastError();
    SetLastError(F2KT_UNTOUCHED);
    other_hide = HideCaret(child2);
    other_hide_err = GetLastError();
    SetLastError(F2KT_UNTOUCHED);
    other_destroy = DestroyCaret();
    other_destroy_err = GetLastError();
    return 0;
}

static void sec_focus(void)
{
    HANDLE t;
    DWORD tid, w;

    open_windows();
    set_focus(child1);
    create_caret(child1, NULL, 2, 16, "child1, NULL, 2, 16");
    set_pos(3, 4);
    show_caret(child1, "child1");
    set_focus(child2);
    set_focus(top);
    hide_caret(child1, "child1 (the owner, not the focus)");
    show_caret(child1, "child1");
    set_focus(child1);
    create_caret(child2, NULL, 2, 16, "child2 (child1 owns the caret and has the focus), NULL, 2, 16");
    show_caret(child2, "child2");
    hide_caret(child1, "child1 (no longer the owner)");
    set_focus(child2);

    t = CreateThread(NULL, 0, other_thread, NULL, 0, &tid);
    w = WaitForSingleObject(t, WAIT_MS);
    CloseHandle(t);
    line("another thread: %s; its CreateCaret(child2): ret=%d err=%s; HideCaret(child2): ret=%d err=%s; "
         "DestroyCaret: ret=%d err=%s",
         wr(w), other_create, le_of(other_create_err), other_hide, le_of(other_hide_err), other_destroy,
         le_of(other_destroy_err));
    print_caret();

    arm();
    w = DestroyWindow(child2);
    line("DestroyWindow(child2, the owner and the focus): ret=%lu err=%s focus %s", w, le(), label(GetFocus()));
    child2 = NULL;
    print_caret();

    edit1 = CreateWindowExW(0, EDIT_CLASS, L"edit1", WS_CHILD | WS_VISIBLE, 10, 60, 100, 30, top, (HMENU)3,
                            instance(), NULL);
    edit2 = CreateWindowExW(0, EDIT_CLASS, L"edit2", WS_CHILD | WS_VISIBLE, 120, 60, 100, 30, top, (HMENU)4,
                            instance(), NULL);
    line("edit1 and edit2, of the class whose procedure makes the caret: non-NULL %s",
         yesno(edit1 != NULL && edit2 != NULL));
    set_focus(edit1);
    set_focus(edit2);
    set_focus(top);
    set_focus(edit1);
    set_focus(NULL);
    set_focus(edit2);
    arm();
    w = DestroyWindow(edit2);
    line("DestroyWindow(edit2, the focus): ret=%lu err=%s focus %s", w, le(), label(GetFocus()));
    edit2 = NULL;
    print_caret();
    close_windows();
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "show", sec_show, F2KT_ALWAYS },
    { "focus", sec_focus, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("caret", sections, argc, argv);
}
