/*
 * guigeo - window geometry and visibility in user32: ShowWindow,
 * ShowWindowAsync, UpdateWindow, SetWindowPos, MoveWindow, GetWindowRect
 * and IsWindowVisible.
 *
 * Conventions as in common/f2kt.h: every call under observation is
 * armed with the sentinel and prints ret= and err=; no handle values,
 * addresses or raw timings are printed. Visibility prints as yes/no,
 * rects as four plain numbers. Each section registers its own class and
 * creates one hidden 320x200 window at explicit coordinates (creation
 * never uses CW_USEDEFAULT), so no line depends on where the system
 * would have placed a window; MoveWindow/SetWindowPos set the position
 * before any GetWindowRect prints it. ShowWindowAsync's effect is
 * applied while the thread's queue is next read, so each async call is
 * followed by a silent drain (PeekMessage/DispatchMessage until the
 * queue is empty); the messages it retrieves are not printed. The
 * wndproc counts the WM_PAINT messages it handles in a global, printed
 * after the calls that could have sent them. GetClientRect is not
 * covered here: window decoration differs deliberately, so client sizes
 * are not printed.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   show     ShowWindow SW_SHOW, SW_HIDE, SW_SHOW again, each with its
 *            return and IsWindowVisible after; then ShowWindowAsync
 *            SW_HIDE and SW_SHOW, each with a queue drain after it and
 *            IsWindowVisible
 *   move     MoveWindow to 100,100 sized 300x250, and the GetWindowRect
 *            after it
 *   setpos   SetWindowPos to 50,60 sized 200x150 and the rect after it,
 *            then a SWP_NOSIZE|SWP_NOMOVE call changing only z-order
 *   update   ShowWindow(SW_SHOW), InvalidateRect, then UpdateWindow
 *            twice: the return and the wndproc's WM_PAINT count
 *   errors   MoveWindow, GetWindowRect, SetWindowPos and IsWindowVisible
 *            on a bogus handle
 *   minmax   IsIconic and IsZoomed (and IsWindowVisible, and the
 *            WM_SIZE messages' count and last wParam) around ShowWindow
 *            SW_MINIMIZE, SW_RESTORE, SW_MAXIMIZE, SW_MINIMIZE from
 *            maximized, SW_RESTORE twice, SW_HIDE of a minimized
 *            window and SW_SHOWNORMAL; and on a bogus handle
 *   placement GetWindowPlacement and SetWindowPlacement: the length, the
 *            flags, showCmd, ptMinPosition and ptMaxPosition (as -1,
 *            -32000 or another value), rcNormalPosition as a relation to
 *            the window rect and to the rectangle set; set minimized and
 *            normal, then through SW_MAXIMIZE, SW_MINIMIZE and two
 *            SW_RESTORE (WPF_RESTORETOMAXIMIZED); length 0, SW_HIDE and
 *            a bogus handle
 *   defer    BeginDeferWindowPos, DeferWindowPos and EndDeferWindowPos
 *            over three windows (the handle each returns against the
 *            first, the windows unmoved until the end, their rects
 *            after), one window twice, SWP_NOMOVE, a top-level window
 *            and its child in one batch; a bogus window, counts 0 and
 *            -1, and EndDeferWindowPos(NULL)
 *
 *   sizemsg  WM_SIZE, WM_MOVE and WM_WINDOWPOSCHANGED as the window
 *            procedure receives them, in order: each WM_SIZE's wParam and
 *            whether its lParam is the client area's size then (and
 *            whether it is 0), each WM_MOVE's lParam against the client
 *            area's origin on the screen, each WM_WINDOWPOSCHANGED's
 *            flags; around the creation of a hidden window shaped as
 *            calc.exe's (WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX with
 *            a menu, 260x254) and of a 2x2 child at (0,206), ShowWindow
 *            SW_SHOW, calc's own sizing (SetWindowPos to the height the
 *            first WM_SIZE implies puts the child's bottom at the
 *            client's), MoveWindow, a move-only and an unchanged
 *            SetWindowPos; then a window whose procedure keeps
 *            WM_WINDOWPOSCHANGED from DefWindowProc, shown and resized
 *
 *   edits    a procedure editing what DefWindowProc answers: WM_NCCALCSIZE
 *            shrunk by 10 on each side (the client area against the
 *            window rect, after the creation and after a resize);
 *            WM_GETMINMAXINFO with a minimum and maximum tracking size, a
 *            maximized size and position (the window's size against them
 *            at the creation, after SetWindowPos below, between and
 *            above them, and maximized); WM_WINDOWPOSCHANGING adding
 *            SWP_NOMOVE and setting cx (SetWindowPos and MoveWindow: moved
 *            or not, the width the procedure's or the asked one)
 *   createmax WS_MAXIMIZE and WS_MINIMIZE given to CreateWindowEx, hidden
 *            and with WS_VISIBLE: IsZoomed, IsIconic, the visibility, the
 *            style bit kept, the WM_SIZE count and last wParam during the
 *            creation, the rect against the one asked; then SW_RESTORE
 *   swpshow  SetWindowPos with SWP_SHOWWINDOW and a new position and size
 *            on a hidden window and on a shown one, and with
 *            SWP_HIDEWINDOW on a shown one: the visibility, and whether
 *            the window moved and took the size
 *   mmdefault WM_GETMINMAXINFO from a procedure that hands every message
 *            to DefWindowProc: the creation's messages in order (a popup,
 *            a thick-framed popup, a WS_OVERLAPPEDWINDOW window), the
 *            window manager's MINMAXINFO as relations to the screen, the
 *            work area and the tracking metrics, the messages' count and
 *            the size a SetWindowPos gives (inside, above and below the
 *            tracking sizes, SWP_NOSIZE, and with WM_WINDOWPOSCHANGING
 *            kept from DefWindowProc), and SW_MAXIMIZE's
 *   xedits   the edits section's procedure on a window another thread
 *            made and serves (GetMessage), the main thread calling
 *            SetWindowPos, MoveWindow and ShowWindow: the client area,
 *            the tracking and maximized sizes and the WINDOWPOS edits as
 *            in edits, and whether the procedure ran on the window's
 *            thread inside a send (InSendMessage); the procedure sending
 *            to and moving a window of the main thread's while the main
 *            thread waits in SetWindowPos; and the window's thread
 *            ending inside WM_WINDOWPOSCHANGING (SetWindowPos returns,
 *            the window gone)
 *
 * The edits, createmax and swpshow windows sit at small explicit
 * positions; what prints is only how their rects relate to the ones
 * asked, the procedure's, or each other.
 *
 * The minimized and maximized rectangles depend on the screen, so
 * minmax and placement print them only as relations to the normal
 * one; a child's rectangle prints in its parent's client coordinates.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guigeo):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guigeo.c user32.lib
 */

#include "../common/f2kt.h"

/* A window handle no window has. */
#define BOGUS_HWND ((HWND)0x7FFFFFFC)

/* The WM_PAINT messages the wndproc has handled; printed after the
 * calls that could have sent them. */
static int paint_count;

/* The WM_SIZE messages since the last print, and the last one's
 * wParam (SIZE_RESTORED, SIZE_MINIMIZED, SIZE_MAXIMIZED). */
static int size_count;
static WPARAM last_size;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;

        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        paint_count++;
        return 0;
    }
    case WM_SIZE:
        size_count++;
        last_size = wParam;
        return DefWindowProc(hwnd, msg, wParam, lParam);
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

/* Read the thread's queue until it is empty. Dispatching a retrieved
 * WM_PAINT validates the window in the wndproc, so the loop ends; the
 * messages themselves are not printed. */
static void drain(void)
{
    MSG m;

    while (PeekMessage(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessage(&m);
    }
}

/* Register `class_name` and create one hidden 320x200 window of it at
 * explicit coordinates. */
static HWND make_window(const char *class_name)
{
    WNDCLASS wc;
    HINSTANCE inst;
    HWND h;

    inst = (HINSTANCE)GetModuleHandle(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;
    RegisterClass(&wc);
    h = CreateWindowEx(0, class_name, "F2K guigeo", WS_OVERLAPPEDWINDOW,
                       0, 0, 320, 200, NULL, NULL, inst, NULL);
    return h;
}

/* --- show ---------------------------------------------------------- */

static void sec_show(void)
{
    HWND h;
    BOOL r;
    int v;

    h = make_window("F2KGuigeoShow");
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(SW_SHOW): ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindow(h, SW_HIDE);
    line("ShowWindow(SW_HIDE): ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(SW_SHOW) again: ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindowAsync(h, SW_HIDE);
    line("ShowWindowAsync(SW_HIDE): ret=%d err=%s", r, le());
    drain();
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible after the queue drained: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindowAsync(h, SW_SHOW);
    line("ShowWindowAsync(SW_SHOW): ret=%d err=%s", r, le());
    drain();
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible after the queue drained: %s err=%s", yesno(v), le());
}

/* --- move ---------------------------------------------------------- */

static void sec_move(void)
{
    HWND h;
    RECT rc;
    BOOL r;

    h = make_window("F2KGuigeoMove");
    arm();
    r = MoveWindow(h, 100, 100, 300, 250, TRUE);
    line("MoveWindow(100, 100, 300, 250, TRUE): ret=%d err=%s", r, le());
    arm();
    r = GetWindowRect(h, &rc);
    line("GetWindowRect: ret=%d err=%s rect=%ld %ld %ld %ld", r, le(),
         rc.left, rc.top, rc.right, rc.bottom);
}

/* --- setpos -------------------------------------------------------- */

static void sec_setpos(void)
{
    HWND h;
    RECT rc;
    BOOL r;

    h = make_window("F2KGuigeoSetPos");
    arm();
    r = SetWindowPos(h, HWND_TOP, 50, 60, 200, 150, SWP_NOACTIVATE);
    line("SetWindowPos(HWND_TOP, 50, 60, 200, 150, SWP_NOACTIVATE): ret=%d err=%s", r, le());
    arm();
    r = GetWindowRect(h, &rc);
    line("GetWindowRect: ret=%d err=%s rect=%ld %ld %ld %ld", r, le(),
         rc.left, rc.top, rc.right, rc.bottom);
    arm();
    r = SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    line("SetWindowPos(HWND_TOP, SWP_NOSIZE|SWP_NOMOVE): ret=%d err=%s", r, le());
}

/* --- update -------------------------------------------------------- */

static void sec_update(void)
{
    HWND h;
    BOOL r;

    h = make_window("F2KGuigeoUpdate");
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(SW_SHOW): ret=%d err=%s", r, le());
    paint_count = 0;
    arm();
    r = InvalidateRect(h, NULL, TRUE);
    line("InvalidateRect(NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    r = UpdateWindow(h);
    line("UpdateWindow: ret=%d err=%s paints=%d", r, le(), paint_count);
    arm();
    r = UpdateWindow(h);
    line("UpdateWindow again: ret=%d err=%s paints=%d", r, le(), paint_count);
}

/* --- errors -------------------------------------------------------- */

static void sec_errors(void)
{
    HWND h;
    RECT rc;
    BOOL r;
    int v;

    h = make_window("F2KGuigeoErrors");
    (void)h;
    arm();
    r = MoveWindow(BOGUS_HWND, 1, 2, 3, 4, TRUE);
    line("MoveWindow(a bogus handle): ret=%d err=%s", r, le());
    arm();
    r = GetWindowRect(BOGUS_HWND, &rc);
    line("GetWindowRect(a bogus handle): ret=%d err=%s", r, le());
    arm();
    r = SetWindowPos(BOGUS_HWND, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    line("SetWindowPos(a bogus handle): ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(BOGUS_HWND);
    line("IsWindowVisible(a bogus handle): %s err=%s", yesno(v), le());
}

/* --- minmax -------------------------------------------------------- */

/* Two rectangles compared without an API call (EqualRect is not what
 * these sections observe). */
static int same_rect(const RECT *a, const RECT *b)
{
    return a->left == b->left && a->top == b->top && a->right == b->right &&
           a->bottom == b->bottom;
}

/* The window's state after a call, and the WM_SIZE messages since the
 * last print; `normal` is the rect the window had before any
 * minimize or maximize. */
static void minmax_state(HWND h, const RECT *normal)
{
    BOOL iconic, zoomed;
    DWORD ei, ez;
    RECT rc;

    arm();
    iconic = IsIconic(h);
    ei = GetLastError();
    arm();
    zoomed = IsZoomed(h);
    ez = GetLastError();
    GetWindowRect(h, &rc);
    line("  IsIconic=%d err=%s IsZoomed=%d err=%s visible %s; WM_SIZE count=%d last wParam=%lu; "
         "the rect: the normal one %s, larger both ways %s",
         iconic, le_of(ei), zoomed, le_of(ez), yesno(IsWindowVisible(h)), size_count,
         (unsigned long)last_size, yesno(same_rect(&rc, normal)),
         yesno(rc.right - rc.left > normal->right - normal->left &&
               rc.bottom - rc.top > normal->bottom - normal->top));
    size_count = 0;
    last_size = 0;
}

static void show_cmd(HWND h, const char *name, int cmd, const RECT *normal)
{
    BOOL r;

    size_count = 0;
    last_size = 0;
    arm();
    r = ShowWindow(h, cmd);
    line("ShowWindow(%s): ret=%d err=%s", name, r, le());
    drain();
    minmax_state(h, normal);
}

static void sec_minmax(void)
{
    HWND h;
    RECT normal;
    BOOL r;

    h = make_window("F2KGuigeoMinMax");
    MoveWindow(h, 100, 80, 300, 200, FALSE);
    GetWindowRect(h, &normal);
    drain();
    size_count = 0;
    last_size = 0;
    line("a hidden window at 100,80 sized 300x200: rect=%ld %ld %ld %ld", normal.left, normal.top,
         normal.right, normal.bottom);
    minmax_state(h, &normal);
    show_cmd(h, "SW_MINIMIZE", SW_MINIMIZE, &normal);
    show_cmd(h, "SW_RESTORE", SW_RESTORE, &normal);
    show_cmd(h, "SW_MAXIMIZE", SW_MAXIMIZE, &normal);
    show_cmd(h, "SW_MINIMIZE", SW_MINIMIZE, &normal);
    show_cmd(h, "SW_RESTORE", SW_RESTORE, &normal);
    show_cmd(h, "SW_RESTORE", SW_RESTORE, &normal);
    show_cmd(h, "SW_MINIMIZE", SW_MINIMIZE, &normal);
    show_cmd(h, "SW_HIDE", SW_HIDE, &normal);
    show_cmd(h, "SW_SHOWNORMAL", SW_SHOWNORMAL, &normal);
    arm();
    r = IsIconic(BOGUS_HWND);
    line("IsIconic(a bogus handle): ret=%d err=%s", r, le());
    arm();
    r = IsZoomed(BOGUS_HWND);
    line("IsZoomed(a bogus handle): ret=%d err=%s", r, le());
    DestroyWindow(h);
    drain();
}

/* --- placement ----------------------------------------------------- */

/* A placement point as printed: the two values that are not screen
 * positions, or "another point". */
static const char *pt_class(POINT p)
{
    if (p.x == -1 && p.y == -1) {
        return "(-1,-1)";
    }
    if (p.x == -32000 && p.y == -32000) {
        return "(-32000,-32000)";
    }
    return "another point";
}

static void get_placement(HWND h, const RECT *set)
{
    WINDOWPLACEMENT wp;
    RECT rc;
    BOOL r;
    DWORD e;

    memset(&wp, 0xCC, sizeof wp);
    wp.length = sizeof wp;
    arm();
    r = GetWindowPlacement(h, &wp);
    e = GetLastError();
    GetWindowRect(h, &rc);
    line("GetWindowPlacement: ret=%d err=%s length=%u flags=0x%X showCmd=%u ptMinPosition %s "
         "ptMaxPosition %s",
         r, le_of(e), wp.length, wp.flags, wp.showCmd, pt_class(wp.ptMinPosition),
         pt_class(wp.ptMaxPosition));
    line("  rcNormalPosition: the window rect %s, its size %s, the rect set %s; IsIconic=%d "
         "IsZoomed=%d visible %s",
         yesno(same_rect(&wp.rcNormalPosition, &rc)),
         yesno(wp.rcNormalPosition.right - wp.rcNormalPosition.left == rc.right - rc.left &&
               wp.rcNormalPosition.bottom - wp.rcNormalPosition.top == rc.bottom - rc.top),
         yesno(set != NULL && same_rect(&wp.rcNormalPosition, set)), IsIconic(h), IsZoomed(h),
         yesno(IsWindowVisible(h)));
}

static void set_placement(HWND h, const char *name, UINT length, UINT show, const RECT *normal)
{
    WINDOWPLACEMENT wp;
    RECT rc;
    BOOL r;

    memset(&wp, 0, sizeof wp);
    wp.length = length;
    wp.flags = 0;
    wp.showCmd = show;
    wp.ptMinPosition.x = -1;
    wp.ptMinPosition.y = -1;
    wp.ptMaxPosition.x = -1;
    wp.ptMaxPosition.y = -1;
    wp.rcNormalPosition = *normal;
    arm();
    r = SetWindowPlacement(h, &wp);
    line("SetWindowPlacement(length %u, %s, rcNormalPosition %ld %ld %ld %ld): ret=%d err=%s",
         length, name, normal->left, normal->top, normal->right, normal->bottom, r, le());
    drain();
    memset(&rc, 0, sizeof rc);
    GetWindowRect(h, &rc);
    line("  the window rect: the rcNormalPosition set %s", yesno(same_rect(&rc, normal)));
}

static void sec_placement(void)
{
    HWND h;
    WINDOWPLACEMENT wp;
    RECT first, second;
    BOOL r;

    h = make_window("F2KGuigeoPlace");
    MoveWindow(h, 100, 80, 300, 200, FALSE);
    drain();
    line("a hidden window at 100,80 sized 300x200");
    get_placement(h, NULL);

    memset(&wp, 0xCC, sizeof wp);
    wp.length = 0;
    arm();
    r = GetWindowPlacement(h, &wp);
    line("GetWindowPlacement, length 0: ret=%d err=%s length=%u showCmd=%u", r, le(), wp.length,
         wp.showCmd);

    SetRect(&first, 150, 120, 450, 330);
    set_placement(h, "SW_SHOWMINIMIZED", sizeof wp, SW_SHOWMINIMIZED, &first);
    get_placement(h, &first);
    SetRect(&second, 120, 90, 420, 290);
    set_placement(h, "SW_SHOWNORMAL", sizeof wp, SW_SHOWNORMAL, &second);
    get_placement(h, &second);

    arm();
    r = ShowWindow(h, SW_MAXIMIZE);
    line("ShowWindow(SW_MAXIMIZE): ret=%d err=%s", r, le());
    drain();
    get_placement(h, &second);
    arm();
    r = ShowWindow(h, SW_MINIMIZE);
    line("ShowWindow(SW_MINIMIZE): ret=%d err=%s", r, le());
    drain();
    get_placement(h, &second);
    arm();
    r = ShowWindow(h, SW_RESTORE);
    line("ShowWindow(SW_RESTORE): ret=%d err=%s", r, le());
    drain();
    get_placement(h, &second);
    arm();
    r = ShowWindow(h, SW_RESTORE);
    line("ShowWindow(SW_RESTORE): ret=%d err=%s", r, le());
    drain();
    get_placement(h, &second);

    set_placement(h, "SW_SHOWNORMAL", 0, SW_SHOWNORMAL, &first);
    get_placement(h, &second);
    set_placement(h, "SW_HIDE", sizeof wp, SW_HIDE, &first);
    get_placement(h, &first);

    memset(&wp, 0xCC, sizeof wp);
    wp.length = sizeof wp;
    arm();
    r = GetWindowPlacement(BOGUS_HWND, &wp);
    line("GetWindowPlacement(a bogus handle): ret=%d err=%s", r, le());
    set_placement(BOGUS_HWND, "SW_SHOWNORMAL, a bogus handle", sizeof wp, SW_SHOWNORMAL, &first);
    DestroyWindow(h);
    drain();
}

/* --- defer --------------------------------------------------------- */

static void print_rect(const char *name, HWND h)
{
    RECT rc;

    GetWindowRect(h, &rc);
    line("  %s: rect=%ld %ld %ld %ld", name, rc.left, rc.top, rc.right, rc.bottom);
}

/* A child's rect in its parent's client coordinates. */
static void print_child_rect(const char *name, HWND h, HWND parent)
{
    RECT rc;

    GetWindowRect(h, &rc);
    MapWindowPoints(NULL, parent, (POINT *)&rc, 2);
    line("  %s: rect in the parent's client area=%ld %ld %ld %ld", name, rc.left, rc.top, rc.right,
         rc.bottom);
}

static HDWP defer(HDWP d, HDWP first, const char *name, HWND h, int x, int y, int cx, int cy,
                  UINT flags)
{
    HDWP r;

    arm();
    r = DeferWindowPos(d, h, NULL, x, y, cx, cy, flags);
    line("DeferWindowPos(%s, %d, %d, %d, %d): non-NULL %s, the first handle %s err=%s", name, x, y,
         cx, cy, yesno(r != NULL), yesno(r == first), le());
    return r;
}

static void end_defer(HDWP d)
{
    BOOL r;

    arm();
    r = EndDeferWindowPos(d);
    line("EndDeferWindowPos: ret=%d err=%s", r, le());
    drain();
}

static HDWP begin_defer(int n)
{
    HDWP r;

    arm();
    r = BeginDeferWindowPos(n);
    line("BeginDeferWindowPos(%d): non-NULL %s err=%s", n, yesno(r != NULL), le());
    return r;
}

static void sec_defer(void)
{
    HWND w1, w2, w3, child;
    HDWP first, d;
    UINT flags = SWP_NOZORDER | SWP_NOACTIVATE;

    w1 = make_window("F2KGuigeoDefer");
    w2 = make_window("F2KGuigeoDefer");
    w3 = make_window("F2KGuigeoDefer");
    child = CreateWindowEx(0, "F2KGuigeoDefer", "child", WS_CHILD, 10, 10, 50, 40, w1, NULL,
                           (HINSTANCE)GetModuleHandle(NULL), NULL);
    line("three hidden 320x200 windows at 0,0 and a child of the first: %s",
         yesno(w1 != NULL && w2 != NULL && w3 != NULL && child != NULL));

    first = begin_defer(2);
    d = defer(first, first, "w1", w1, 10, 20, 200, 100, flags);
    d = defer(d, first, "w2", w2, 30, 40, 210, 110, flags);
    d = defer(d, first, "w3", w3, 50, 60, 220, 120, flags);
    line("before EndDeferWindowPos:");
    print_rect("w1", w1);
    end_defer(d);
    print_rect("w1", w1);
    print_rect("w2", w2);
    print_rect("w3", w3);

    first = begin_defer(1);
    d = defer(first, first, "w1", w1, 1, 2, 100, 50, flags);
    d = defer(d, first, "w1 again", w1, 5, 6, 150, 70, flags);
    end_defer(d);
    print_rect("w1", w1);

    first = begin_defer(1);
    d = defer(first, first, "w2, SWP_NOMOVE", w2, 999, 999, 90, 80, flags | SWP_NOMOVE);
    end_defer(d);
    print_rect("w2", w2);

    first = begin_defer(2);
    d = defer(first, first, "w3", w3, 70, 80, 230, 130, flags);
    d = defer(d, first, "the child of w1", child, 20, 30, 60, 50, flags);
    end_defer(d);
    print_rect("w3", w3);
    print_child_rect("the child", child, w1);

    first = begin_defer(1);
    d = defer(first, first, "a bogus handle", BOGUS_HWND, 1, 2, 3, 4, flags);
    if (d != NULL) {
        end_defer(d);
    }
    first = begin_defer(0);
    if (first != NULL) {
        d = defer(first, first, "w1", w1, 11, 12, 130, 60, flags);
        end_defer(d);
        print_rect("w1", w1);
    }
    first = begin_defer(-1);
    if (first != NULL) {
        end_defer(first);
    }
    end_defer(NULL);

    DestroyWindow(w1);
    DestroyWindow(w2);
    DestroyWindow(w3);
    drain();
}

/* --- sizemsg ------------------------------------------------------- */

/* Whether the size procedure prints what it receives; whether it keeps
 * WM_WINDOWPOSCHANGED from DefWindowProc; the last WM_SIZE's lParam. */
static int sizelog_on;
static int sizelog_nodef;
static LPARAM sizelog_last;

static LRESULT CALLBACK size_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT cr;
    POINT origin;

    switch (msg) {
    case WM_SIZE:
        sizelog_last = lParam;
        if (sizelog_on) {
            GetClientRect(hwnd, &cr);
            line("  WM_SIZE wParam=%lu, lParam the client's size %s, lParam 0 %s", (unsigned long)wParam,
                 yesno(LOWORD(lParam) == cr.right && HIWORD(lParam) == cr.bottom), yesno(lParam == 0));
        }
        break;
    case WM_MOVE:
        if (sizelog_on) {
            origin.x = 0;
            origin.y = 0;
            ClientToScreen(hwnd, &origin);
            line("  WM_MOVE, lParam the client's origin %s",
                 yesno((short)LOWORD(lParam) == origin.x && (short)HIWORD(lParam) == origin.y));
        }
        break;
    case WM_WINDOWPOSCHANGED:
        if (sizelog_on) {
            line("  WM_WINDOWPOSCHANGED flags=0x%04X", ((WINDOWPOS *)lParam)->flags);
        }
        if (sizelog_nodef) {
            return 0;
        }
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* A hidden window of the size class, shaped as calc.exe's main window:
 * a caption, the system menu, a minimize box and a menu bar. */
static HWND make_sized(int x, int y)
{
    HMENU menu;

    menu = CreateMenu();
    AppendMenuA(menu, MF_STRING, 1, "&Edit");
    return CreateWindowEx(0, "F2KGuigeoSize", "F2K sizemsg", WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, x, y, 260,
                          254, NULL, menu, (HINSTANCE)GetModuleHandle(NULL), NULL);
}

static void print_client_rect(const char *when, HWND h)
{
    RECT wr;
    RECT cr;

    GetWindowRect(h, &wr);
    GetClientRect(h, &cr);
    line("%s: window %ldx%ld, client %ldx%ld", when, wr.right - wr.left, wr.bottom - wr.top, cr.right, cr.bottom);
}

static void sec_sizemsg(void)
{
    WNDCLASS wc;
    HWND h;
    HWND marker;
    RECT wr;
    RECT mr;
    POINT p;
    LONG height;
    BOOL r;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = size_proc;
    wc.hInstance = (HINSTANCE)GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "F2KGuigeoSize";
    RegisterClass(&wc);

    line("CreateWindowEx(calc's shape, hidden, 260x254):");
    sizelog_on = 1;
    h = make_sized(20, 20);
    sizelog_on = 0;
    line("  non-NULL %s", yesno(h != NULL));
    if (h == NULL) {
        return;
    }
    print_client_rect("after the creation", h);
    marker = CreateWindowEx(0, "Static", "", WS_CHILD | WS_VISIBLE, 0, 206, 2, 2, h, (HMENU)1000,
                            (HINSTANCE)GetModuleHandle(NULL), NULL);
    line("the 2x2 child at (0,206): non-NULL %s", yesno(marker != NULL));

    line("ShowWindow(SW_SHOW):");
    sizelog_last = 0;
    sizelog_on = 1;
    ShowWindow(h, SW_SHOW);
    sizelog_on = 0;
    drain();
    print_client_rect("after the show", h);

    /* calc's sizing: the window grows or shrinks by what separates the
     * child's bottom from the client's bottom as WM_SIZE told it. */
    GetWindowRect(h, &wr);
    GetWindowRect(marker, &mr);
    p.x = mr.right;
    p.y = mr.bottom;
    ScreenToClient(h, &p);
    height = (wr.bottom - wr.top) + p.y - HIWORD(sizelog_last);
    line("SetWindowPos(SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE) to the height the last WM_SIZE implies:");
    sizelog_on = 1;
    r = SetWindowPos(h, NULL, 0, 0, wr.right - wr.left, height, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    sizelog_on = 0;
    line("  ret=%d", r);
    print_client_rect("after it", h);
    GetClientRect(h, &wr);
    line("the client's bottom is the child's %s", yesno(wr.bottom == p.y));

    line("MoveWindow(30,40 300x200, TRUE):");
    sizelog_on = 1;
    MoveWindow(h, 30, 40, 300, 200, TRUE);
    sizelog_on = 0;
    line("SetWindowPos(50,60, SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE):");
    sizelog_on = 1;
    SetWindowPos(h, NULL, 50, 60, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    sizelog_on = 0;
    line("SetWindowPos(50,60 300x200, SWP_NOZORDER|SWP_NOACTIVATE), unchanged:");
    sizelog_on = 1;
    SetWindowPos(h, NULL, 50, 60, 300, 200, SWP_NOZORDER | SWP_NOACTIVATE);
    sizelog_on = 0;
    DestroyWindow(h);
    drain();

    line("a window keeping WM_WINDOWPOSCHANGED from DefWindowProc, ShowWindow(SW_SHOW):");
    h = make_sized(20, 20);
    if (h == NULL) {
        return;
    }
    sizelog_nodef = 1;
    sizelog_on = 1;
    ShowWindow(h, SW_SHOW);
    line("SetWindowPos(SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE) to 300x200:");
    SetWindowPos(h, NULL, 0, 0, 300, 200, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    sizelog_on = 0;
    sizelog_nodef = 0;
    DestroyWindow(h);
    drain();
}

/* --- edits -------------------------------------------------------- */

#define EDIT_NCCALC 1
#define EDIT_MINMAX 2
#define EDIT_POSCHANGING 4

/* The edits the procedure makes now (EDIT_ bits). */
static int edit_mode;

static LRESULT CALLBACK edits_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LRESULT r;

    r = DefWindowProc(hwnd, msg, wParam, lParam);
    if (msg == WM_NCCALCSIZE && (edit_mode & EDIT_NCCALC)) {
        /* rgrc[0] (wParam TRUE) and the lone rect (FALSE) both come first. */
        InflateRect((RECT *)lParam, -10, -10);
    } else if (msg == WM_GETMINMAXINFO && (edit_mode & EDIT_MINMAX)) {
        MINMAXINFO *mm = (MINMAXINFO *)lParam;

        mm->ptMinTrackSize.x = 300;
        mm->ptMinTrackSize.y = 250;
        mm->ptMaxTrackSize.x = 400;
        mm->ptMaxTrackSize.y = 300;
        mm->ptMaxSize.x = 380;
        mm->ptMaxSize.y = 280;
        mm->ptMaxPosition.x = 20;
        mm->ptMaxPosition.y = 30;
    } else if (msg == WM_WINDOWPOSCHANGING && (edit_mode & EDIT_POSCHANGING)) {
        WINDOWPOS *wp = (WINDOWPOS *)lParam;

        wp->flags |= SWP_NOMOVE;
        wp->cx = 250;
    }
    return r;
}

static void register_class_proc(const char *name, WNDPROC proc)
{
    WNDCLASS wc;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = (HINSTANCE)GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = name;
    RegisterClass(&wc);
}

static HWND create_at(const char *class_name, DWORD style, int x, int y, int cx, int cy)
{
    return CreateWindowEx(0, class_name, "F2K guigeo", style, x, y, cx, cy, NULL, NULL,
                          (HINSTANCE)GetModuleHandle(NULL), NULL);
}

/* The client area against the window rect less 10 on each side. */
static void print_nccalc(const char *when, HWND h)
{
    RECT wr, cr;
    POINT o;

    GetWindowRect(h, &wr);
    GetClientRect(h, &cr);
    o.x = 0;
    o.y = 0;
    ClientToScreen(h, &o);
    line("  %s: the client the window less 10 on each side %s, the window's own size %s", when,
         yesno(cr.right == wr.right - wr.left - 20 && cr.bottom == wr.bottom - wr.top - 20 &&
               o.x == wr.left + 10 && o.y == wr.top + 10),
         yesno(cr.right == wr.right - wr.left && cr.bottom == wr.bottom - wr.top));
}

/* The window's size against the one asked and the procedure's bounds. */
static void print_minmax(const char *when, HWND h, int cx, int cy)
{
    RECT wr;
    long w, ht;

    GetWindowRect(h, &wr);
    w = wr.right - wr.left;
    ht = wr.bottom - wr.top;
    line("  %s: the size asked %s, the minimum tracking size %s, the maximum tracking size %s, "
         "the maximized size %s at the maximized position %s",
         when, yesno(w == cx && ht == cy), yesno(w == 300 && ht == 250),
         yesno(w == 400 && ht == 300), yesno(w == 380 && ht == 280),
         yesno(wr.left == 20 && wr.top == 30));
}

/* Where the window went against where it was and what was asked. */
static void print_poschanging(const char *call, BOOL r, HWND h, const RECT *before, int x, int y,
                              int cx, int cy)
{
    RECT wr;

    GetWindowRect(h, &wr);
    line("%s: ret=%d; moved %s, to the position asked %s; the width the procedure's 250 %s, the "
         "asked %s; the height the asked %s",
         call, r, yesno(wr.left != before->left || wr.top != before->top),
         yesno(wr.left == x && wr.top == y), yesno(wr.right - wr.left == 250),
         yesno(wr.right - wr.left == cx), yesno(wr.bottom - wr.top == cy));
}

static void sec_edits(void)
{
    HWND h;
    RECT before;
    BOOL r;

    register_class_proc("F2KGuigeoEdits", edits_proc);

    line("WM_NCCALCSIZE shrunk by 10 on each side, a WS_POPUP window 200x100:");
    edit_mode = EDIT_NCCALC;
    h = create_at("F2KGuigeoEdits", WS_POPUP, 10, 10, 200, 100);
    line("  non-NULL %s", yesno(h != NULL));
    if (h != NULL) {
        print_nccalc("after the creation", h);
        SetWindowPos(h, NULL, 0, 0, 240, 120, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_nccalc("after SetWindowPos to 240x120", h);
        DestroyWindow(h);
    }
    edit_mode = 0;
    drain();

    line("WM_GETMINMAXINFO: tracking 300x250 to 400x300, maximized 380x280 at 20,30; a "
         "WS_OVERLAPPEDWINDOW window:");
    edit_mode = EDIT_MINMAX;
    h = create_at("F2KGuigeoEdits", WS_OVERLAPPEDWINDOW, 10, 10, 100, 100);
    line("  CreateWindowEx asking 100x100: non-NULL %s", yesno(h != NULL));
    if (h != NULL) {
        print_minmax("after the creation", h, 100, 100);
        SetWindowPos(h, NULL, 0, 0, 350, 280, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_minmax("SetWindowPos to 350x280", h, 350, 280);
        SetWindowPos(h, NULL, 0, 0, 100, 100, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_minmax("SetWindowPos to 100x100", h, 100, 100);
        SetWindowPos(h, NULL, 0, 0, 600, 450, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_minmax("SetWindowPos to 600x450", h, 600, 450);
        ShowWindow(h, SW_MAXIMIZE);
        drain();
        print_minmax("ShowWindow(SW_MAXIMIZE)", h, 0, 0);
        DestroyWindow(h);
    }
    edit_mode = 0;
    drain();

    line("WM_WINDOWPOSCHANGING adding SWP_NOMOVE and setting cx to 250, a WS_POPUP window "
         "200x100:");
    h = create_at("F2KGuigeoEdits", WS_POPUP, 10, 10, 200, 100);
    line("  non-NULL %s", yesno(h != NULL));
    if (h != NULL) {
        edit_mode = EDIT_POSCHANGING;
        GetWindowRect(h, &before);
        r = SetWindowPos(h, NULL, 60, 70, 220, 130, SWP_NOZORDER | SWP_NOACTIVATE);
        print_poschanging("  SetWindowPos(60,70 220x130)", r, h, &before, 60, 70, 220, 130);
        GetWindowRect(h, &before);
        r = MoveWindow(h, 80, 90, 230, 140, FALSE);
        print_poschanging("  MoveWindow(80,90 230x140)", r, h, &before, 80, 90, 230, 140);
        edit_mode = 0;
        GetWindowRect(h, &before);
        r = SetWindowPos(h, NULL, 60, 70, 220, 130, SWP_NOZORDER | SWP_NOACTIVATE);
        print_poschanging("  with no edit, SetWindowPos(60,70 220x130)", r, h, &before, 60, 70,
                          220, 130);
        DestroyWindow(h);
    }
    drain();
}

/* --- createmax ----------------------------------------------------- */

static void created_state(const char *what, DWORD style, const RECT *asked)
{
    HWND h;
    RECT rc;
    DWORD e;

    size_count = 0;
    last_size = 0;
    arm();
    h = create_at("F2KGuigeoCreateMax", style, asked->left, asked->top,
                  asked->right - asked->left, asked->bottom - asked->top);
    e = GetLastError();
    line("CreateWindowEx(WS_OVERLAPPEDWINDOW | %s): non-NULL %s err=%s", what, yesno(h != NULL),
         le_of(e));
    if (h == NULL) {
        return;
    }
    GetWindowRect(h, &rc);
    line("  IsZoomed=%d IsIconic=%d visible %s; WS_MAXIMIZE kept %s, WS_MINIMIZE kept %s; WM_SIZE "
         "count=%d last wParam=%lu",
         IsZoomed(h), IsIconic(h), yesno(IsWindowVisible(h)),
         yesno((GetWindowLong(h, GWL_STYLE) & WS_MAXIMIZE) != 0),
         yesno((GetWindowLong(h, GWL_STYLE) & WS_MINIMIZE) != 0), size_count,
         (unsigned long)last_size);
    line("  the rect: the one asked %s, larger both ways %s, at -32000,-32000 %s",
         yesno(same_rect(&rc, asked)),
         yesno(rc.right - rc.left > asked->right - asked->left &&
               rc.bottom - rc.top > asked->bottom - asked->top),
         yesno(rc.left == -32000 && rc.top == -32000));
    size_count = 0;
    last_size = 0;
    ShowWindow(h, SW_RESTORE);
    drain();
    GetWindowRect(h, &rc);
    line("  ShowWindow(SW_RESTORE): IsZoomed=%d IsIconic=%d; WM_SIZE count=%d last wParam=%lu; "
         "the rect the one asked %s",
         IsZoomed(h), IsIconic(h), size_count, (unsigned long)last_size,
         yesno(same_rect(&rc, asked)));
    DestroyWindow(h);
    drain();
}

static void sec_createmax(void)
{
    RECT asked;

    register_class_proc("F2KGuigeoCreateMax", wndproc);
    SetRect(&asked, 100, 80, 400, 280);
    created_state("WS_MAXIMIZE", WS_OVERLAPPEDWINDOW | WS_MAXIMIZE, &asked);
    created_state("WS_MAXIMIZE | WS_VISIBLE", WS_OVERLAPPEDWINDOW | WS_MAXIMIZE | WS_VISIBLE,
                  &asked);
    created_state("WS_MINIMIZE", WS_OVERLAPPEDWINDOW | WS_MINIMIZE, &asked);
    created_state("WS_MINIMIZE | WS_VISIBLE", WS_OVERLAPPEDWINDOW | WS_MINIMIZE | WS_VISIBLE,
                  &asked);
}

/* --- swpshow ------------------------------------------------------- */

static void swp_show(HWND h, const char *what, int x, int y, int cx, int cy, UINT flags)
{
    RECT before, rc;
    BOOL r;

    GetWindowRect(h, &before);
    arm();
    r = SetWindowPos(h, HWND_TOP, x, y, cx, cy, flags | SWP_NOACTIVATE);
    line("SetWindowPos(%s, %d,%d %dx%d): ret=%d err=%s", what, x, y, cx, cy, r, le());
    drain();
    GetWindowRect(h, &rc);
    line("  visible %s; moved %s, to the position asked %s; the size asked %s, the size before %s",
         yesno(IsWindowVisible(h)), yesno(rc.left != before.left || rc.top != before.top),
         yesno(rc.left == x && rc.top == y),
         yesno(rc.right - rc.left == cx && rc.bottom - rc.top == cy),
         yesno(rc.right - rc.left == before.right - before.left &&
               rc.bottom - rc.top == before.bottom - before.top));
}

static void sec_swpshow(void)
{
    HWND h;

    register_class_proc("F2KGuigeoSwpShow", wndproc);
    h = create_at("F2KGuigeoSwpShow", WS_OVERLAPPEDWINDOW, 100, 80, 300, 200);
    line("a hidden window at 100,80 300x200: non-NULL %s", yesno(h != NULL));
    if (h == NULL) {
        return;
    }
    swp_show(h, "SWP_SHOWWINDOW on the hidden window", 120, 90, 250, 180, SWP_SHOWWINDOW);
    swp_show(h, "SWP_SHOWWINDOW on the shown window", 140, 100, 260, 190, SWP_SHOWWINDOW);
    swp_show(h, "SWP_HIDEWINDOW on the shown window", 160, 110, 270, 170, SWP_HIDEWINDOW);
    DestroyWindow(h);
    drain();
}

/* --- mmdefault ----------------------------------------------------- */

/* The WM_GETMINMAXINFO messages the procedure received, and the first
 * one's MINMAXINFO as the window manager filled it in. */
static int mm_count;
static MINMAXINFO mm_first;

/* The creation's messages, in order, while mm_logging. */
static int mm_logging;
static char mm_log[256];

/* 1: the procedure keeps WM_WINDOWPOSCHANGING from DefWindowProc. */
static int mm_keep_changing;

static void mm_note(const char *name)
{
    if (mm_logging && strlen(mm_log) + strlen(name) + 2 < sizeof mm_log) {
        if (mm_log[0] != '\0') {
            strcat(mm_log, " ");
        }
        strcat(mm_log, name);
    }
}

static LRESULT CALLBACK mmdefault_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_GETMINMAXINFO:
        if (mm_count == 0) {
            mm_first = *(MINMAXINFO *)lParam;
        }
        mm_count++;
        mm_note("WM_GETMINMAXINFO");
        break;
    case WM_NCCREATE:
        mm_note("WM_NCCREATE");
        break;
    case WM_NCCALCSIZE:
        mm_note("WM_NCCALCSIZE");
        break;
    case WM_CREATE:
        mm_note("WM_CREATE");
        break;
    case WM_WINDOWPOSCHANGING:
        if (mm_keep_changing) {
            return 0;
        }
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* A window of the class with `style`, 200x150 at 10,10, the creation's
 * messages printed. */
static HWND mm_create(const char *what, DWORD style)
{
    HWND h;

    mm_count = 0;
    mm_log[0] = '\0';
    mm_logging = 1;
    h = create_at("F2KGuigeoMmDefault", style, 10, 10, 200, 150);
    mm_logging = 0;
    line("CreateWindowEx(%s, 200x150): non-NULL %s", what, yesno(h != NULL));
    line("  the creation's messages: %s", mm_log);
    return h;
}

/* SetWindowPos of `h` to cx by cy with `flags`: the WM_GETMINMAXINFO
 * count, and the size: the one asked, the minimum tracking size, or
 * against the screen's. */
static void mm_resize(const char *what, HWND h, int cx, int cy, UINT flags)
{
    RECT wr;
    long w, ht;

    mm_count = 0;
    SetWindowPos(h, NULL, 0, 0, cx, cy, flags | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    GetWindowRect(h, &wr);
    w = wr.right - wr.left;
    ht = wr.bottom - wr.top;
    if (w == cx && ht == cy) {
        line("  %s: WM_GETMINMAXINFO count=%d; the size asked", what, mm_count);
    } else if (w == GetSystemMetrics(SM_CXMINTRACK) && ht == GetSystemMetrics(SM_CYMINTRACK)) {
        line("  %s: WM_GETMINMAXINFO count=%d; SM_CXMINTRACK by SM_CYMINTRACK", what, mm_count);
    } else {
        line("  %s: WM_GETMINMAXINFO count=%d; the screen's plus %ld by plus %ld", what, mm_count,
             w - GetSystemMetrics(SM_CXSCREEN), ht - GetSystemMetrics(SM_CYSCREEN));
    }
}

static void sec_mmdefault(void)
{
    HWND h;
    RECT work, wr;
    long cx_screen, cy_screen;

    register_class_proc("F2KGuigeoMmDefault", mmdefault_proc);
    cx_screen = GetSystemMetrics(SM_CXSCREEN);
    cy_screen = GetSystemMetrics(SM_CYSCREEN);
    SystemParametersInfo(SPI_GETWORKAREA, 0, &work, 0);

    h = mm_create("WS_POPUP", WS_POPUP);
    if (h != NULL) {
        DestroyWindow(h);
    }
    h = mm_create("WS_POPUP | WS_THICKFRAME", WS_POPUP | WS_THICKFRAME);
    if (h != NULL) {
        DestroyWindow(h);
    }
    h = mm_create("WS_OVERLAPPEDWINDOW", WS_OVERLAPPEDWINDOW);
    if (h == NULL) {
        return;
    }
    line("  WM_GETMINMAXINFO count=%d; the first one's defaults:", mm_count);
    line("    ptReserved %ld,%ld", (long)mm_first.ptReserved.x, (long)mm_first.ptReserved.y);
    line("    ptMaxSize the screen's plus %ld by plus %ld, the work area's plus %ld by plus %ld",
         (long)mm_first.ptMaxSize.x - cx_screen, (long)mm_first.ptMaxSize.y - cy_screen,
         (long)(mm_first.ptMaxSize.x - (work.right - work.left)),
         (long)(mm_first.ptMaxSize.y - (work.bottom - work.top)));
    line("    ptMaxPosition the work area's corner less %ld,%ld",
         (long)(work.left - mm_first.ptMaxPosition.x), (long)(work.top - mm_first.ptMaxPosition.y));
    line("    ptMinTrackSize SM_CXMINTRACK by SM_CYMINTRACK %s",
         yesno(mm_first.ptMinTrackSize.x == GetSystemMetrics(SM_CXMINTRACK) &&
               mm_first.ptMinTrackSize.y == GetSystemMetrics(SM_CYMINTRACK)));
    line("    ptMaxTrackSize the screen's plus %ld by plus %ld; SM_CXMAXTRACK by SM_CYMAXTRACK %s",
         (long)mm_first.ptMaxTrackSize.x - cx_screen, (long)mm_first.ptMaxTrackSize.y - cy_screen,
         yesno(mm_first.ptMaxTrackSize.x == GetSystemMetrics(SM_CXMAXTRACK) &&
               mm_first.ptMaxTrackSize.y == GetSystemMetrics(SM_CYMAXTRACK)));
    mm_resize("SetWindowPos to 300x200", h, 300, 200, 0);
    mm_resize("SetWindowPos to 300x200 with SWP_NOSIZE", h, 300, 200, SWP_NOSIZE);
    mm_resize("SetWindowPos to 3000x3000", h, 3000, 3000, 0);
    mm_resize("SetWindowPos to 50x20", h, 50, 20, 0);
    mm_keep_changing = 1;
    mm_resize("WM_WINDOWPOSCHANGING kept from DefWindowProc, SetWindowPos to 50x20", h, 50, 20, 0);
    mm_resize("WM_WINDOWPOSCHANGING kept from DefWindowProc, SetWindowPos to 3000x3000", h, 3000,
              3000, 0);
    mm_keep_changing = 0;
    mm_count = 0;
    ShowWindow(h, SW_MAXIMIZE);
    drain();
    GetWindowRect(h, &wr);
    line("  ShowWindow(SW_MAXIMIZE): WM_GETMINMAXINFO count=%d; past the work area by %ld left, "
         "%ld above, %ld right, %ld below",
         mm_count, (long)(work.left - wr.left), (long)(work.top - wr.top),
         (long)(wr.right - work.right), (long)(wr.bottom - work.bottom));
    DestroyWindow(h);
    drain();
}

/* --- xedits ------------------------------------------------------- */

/* The window a second thread makes and serves, and the main thread's
 * own window, which the second thread's procedure sends to while the
 * main thread waits. */
static HWND x_window;
static HWND x_main;
static DWORD x_owner;
static HANDLE x_ready;

/* What the second thread's procedure does on WM_WINDOWPOSCHANGING
 * besides edits_proc's edit. */
#define X_NEST 1
#define X_EXIT 2
static int x_mode;

/* The edited messages (WM_NCCALCSIZE, WM_GETMINMAXINFO,
 * WM_WINDOWPOSCHANGING) the second thread's procedure handled, those
 * handled on another thread than the window's, and those for which
 * InSendMessage answered TRUE; and what the main window received. */
static volatile LONG x_handled;
static volatile LONG x_foreign;
static volatile LONG x_insend;
static volatile LONG x_main_user;
static volatile LONG x_main_changing;

static LRESULT CALLBACK xedits_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCALCSIZE || msg == WM_GETMINMAXINFO || msg == WM_WINDOWPOSCHANGING) {
        InterlockedIncrement((LONG *)&x_handled);
        if (GetCurrentThreadId() != x_owner) {
            InterlockedIncrement((LONG *)&x_foreign);
        }
        if (InSendMessage()) {
            InterlockedIncrement((LONG *)&x_insend);
        }
    }
    if (msg == WM_WINDOWPOSCHANGING && (x_mode & X_NEST)) {
        x_mode &= ~X_NEST;
        SendMessage(x_main, WM_USER + 5, 0, 0);
        SetWindowPos(x_main, NULL, 0, 0, 150, 100, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    if (msg == WM_WINDOWPOSCHANGING && (x_mode & X_EXIT)) {
        x_mode &= ~X_EXIT;
        ExitThread(7);
    }
    return edits_proc(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK xmain_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_USER + 5) {
        InterlockedIncrement((LONG *)&x_main_user);
        return 0;
    }
    if (msg == WM_WINDOWPOSCHANGING) {
        InterlockedIncrement((LONG *)&x_main_changing);
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* The second thread: its window (the style the parameter names, 10,10
 * 200x100), made with no edit, then its messages until WM_QUIT. */
static DWORD WINAPI x_thread_main(LPVOID param)
{
    MSG m;

    x_window = create_at("F2KGuigeoXEdits", (DWORD)param, 10, 10, 200, 100);
    SetEvent(x_ready);
    if (x_window == NULL) {
        return 1;
    }
    while (GetMessage(&m, NULL, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessage(&m);
    }
    DestroyWindow(x_window);
    return 0;
}

/* Start the second thread with its window; NULL when either failed. */
static HANDLE x_start(DWORD style)
{
    HANDLE t;

    x_window = NULL;
    x_mode = 0;
    edit_mode = 0;
    ResetEvent(x_ready);
    t = CreateThread(NULL, 0, x_thread_main, (LPVOID)style, 0, &x_owner);
    if (t == NULL) {
        return NULL;
    }
    WaitForSingleObject(x_ready, WAIT_MS);
    if (x_window == NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
        return NULL;
    }
    x_handled = 0;
    x_foreign = 0;
    x_insend = 0;
    return t;
}

/* End the second thread: WM_QUIT, and its end waited for. */
static void x_stop(HANDLE t)
{
    edit_mode = 0;
    x_mode = 0;
    PostThreadMessage(x_owner, WM_QUIT, 0, 0);
    WaitForSingleObject(t, WAIT_MS);
    CloseHandle(t);
}

/* Where the edited messages were handled. */
static void x_where(void)
{
    line("  the procedure ran on the window's thread %s, every time inside a send from another "
         "thread %s",
         yesno(x_handled > 0 && x_foreign == 0), yesno(x_handled > 0 && x_insend == x_handled));
}

static void sec_xedits(void)
{
    HANDLE t;
    RECT before;
    BOOL r;
    DWORD code;

    register_class_proc("F2KGuigeoXEdits", xedits_proc);
    register_class_proc("F2KGuigeoXMain", xmain_proc);
    x_ready = CreateEvent(NULL, TRUE, FALSE, NULL);

    line("WM_NCCALCSIZE shrunk by 10 on each side, another thread's WS_POPUP window 200x100:");
    t = x_start(WS_POPUP);
    line("  the window made: %s", yesno(t != NULL));
    if (t != NULL) {
        edit_mode = EDIT_NCCALC;
        SetWindowPos(x_window, NULL, 0, 0, 240, 120, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_nccalc("after SetWindowPos to 240x120", x_window);
        x_where();
        x_stop(t);
    }

    line("WM_GETMINMAXINFO: tracking 300x250 to 400x300, maximized 380x280 at 20,30; another "
         "thread's WS_OVERLAPPEDWINDOW window:");
    t = x_start(WS_OVERLAPPEDWINDOW);
    line("  the window made: %s", yesno(t != NULL));
    if (t != NULL) {
        edit_mode = EDIT_MINMAX;
        SetWindowPos(x_window, NULL, 0, 0, 100, 100, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_minmax("SetWindowPos to 100x100", x_window, 100, 100);
        SetWindowPos(x_window, NULL, 0, 0, 600, 450, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        print_minmax("SetWindowPos to 600x450", x_window, 600, 450);
        /* Before the show: its activation reaches the window's thread
         * on its own time. */
        x_where();
        ShowWindow(x_window, SW_SHOWMAXIMIZED);
        print_minmax("ShowWindow(SW_SHOWMAXIMIZED)", x_window, 0, 0);
        x_stop(t);
    }

    line("WM_WINDOWPOSCHANGING adding SWP_NOMOVE and setting cx to 250, another thread's "
         "WS_POPUP window 200x100:");
    t = x_start(WS_POPUP);
    line("  the window made: %s", yesno(t != NULL));
    if (t != NULL) {
        edit_mode = EDIT_POSCHANGING;
        GetWindowRect(x_window, &before);
        r = SetWindowPos(x_window, NULL, 60, 70, 220, 130, SWP_NOZORDER | SWP_NOACTIVATE);
        print_poschanging("  SetWindowPos(60,70 220x130)", r, x_window, &before, 60, 70, 220, 130);
        GetWindowRect(x_window, &before);
        r = MoveWindow(x_window, 80, 90, 230, 140, FALSE);
        print_poschanging("  MoveWindow(80,90 230x140)", r, x_window, &before, 80, 90, 230, 140);
        x_where();
        x_stop(t);
    }

    line("the procedure sending back to the main thread's window while the main thread waits:");
    x_main = create_at("F2KGuigeoXMain", WS_POPUP, 30, 30, 200, 120);
    t = x_start(WS_POPUP);
    line("  the windows made: %s", yesno(x_main != NULL && t != NULL));
    if (x_main != NULL && t != NULL) {
        x_main_user = 0;
        x_main_changing = 0;
        x_mode = X_NEST;
        r = SetWindowPos(x_window, NULL, 0, 0, 220, 130, SWP_NOMOVE | SWP_NOZORDER |
                         SWP_NOACTIVATE);
        GetWindowRect(x_main, &before);
        line("  SetWindowPos: ret=%d; the main window's WM_USER+5 received %ld, "
             "WM_WINDOWPOSCHANGING received %s, its size 150x100 %s",
             r, x_main_user, yesno(x_main_changing > 0),
             yesno(before.right - before.left == 150 && before.bottom - before.top == 100));
        x_stop(t);
    }
    if (x_main != NULL) {
        DestroyWindow(x_main);
    }
    drain();

    line("the window's thread ending inside WM_WINDOWPOSCHANGING:");
    t = x_start(WS_POPUP);
    line("  the window made: %s", yesno(t != NULL));
    if (t != NULL) {
        x_mode = X_EXIT;
        SetWindowPos(x_window, NULL, 0, 0, 220, 130, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        line("  SetWindowPos returned; the thread ended %s, its code %lu; the window gone %s",
             yesno(WaitForSingleObject(t, WAIT_MS) == WAIT_OBJECT_0),
             GetExitCodeThread(t, &code) ? code : 0xFFFFFFFFu, yesno(!IsWindow(x_window)));
        CloseHandle(t);
    }
    CloseHandle(x_ready);
}

static const section_t sections[] = {
    { "show", sec_show, 0 },
    { "move", sec_move, 0 },
    { "setpos", sec_setpos, 0 },
    { "update", sec_update, 0 },
    { "errors", sec_errors, 0 },
    { "minmax", sec_minmax, 0 },
    { "placement", sec_placement, 0 },
    { "defer", sec_defer, 0 },
    { "sizemsg", sec_sizemsg, 0 },
    { "edits", sec_edits, 0 },
    { "createmax", sec_createmax, 0 },
    { "swpshow", sec_swpshow, 0 },
    { "mmdefault", sec_mmdefault, 0 },
    { "xedits", sec_xedits, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bogus handle goes to the calls: should one fault, no dialog
     * stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guigeo", sections, argc, argv);
}
