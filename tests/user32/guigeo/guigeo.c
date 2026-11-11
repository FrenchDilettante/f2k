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

static const section_t sections[] = {
    { "show", sec_show, 0 },
    { "move", sec_move, 0 },
    { "setpos", sec_setpos, 0 },
    { "update", sec_update, 0 },
    { "errors", sec_errors, 0 },
    { "minmax", sec_minmax, 0 },
    { "placement", sec_placement, 0 },
    { "defer", sec_defer, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bogus handle goes to the calls: should one fault, no dialog
     * stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guigeo", sections, argc, argv);
}
