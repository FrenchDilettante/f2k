/*
 * scroll - scroll bars in user32: a window's own bars (WS_VSCROLL and
 * WS_HSCROLL) and the ScrollBar control, through SetScrollInfo and
 * GetScrollInfo (the range, the page, the position clamped to
 * nMax - nPage + 1, SIF_DISABLENOSCROLL), SetScrollPos, SetScrollRange,
 * GetScrollPos and GetScrollRange, ShowScrollBar and EnableScrollBar,
 * the control's SBM_* messages; and ScrollWindowEx and ScrollWindow,
 * their returns and the region they leave to repaint.
 *
 * The windows: a WS_POPUP window with no border, 200x150 at screen
 * (40,40), visible, of the section's own class, with the bars its
 * section names; ScrollBar controls are children of it. Without a
 * border the window's rectangle is its client area's plus the bars,
 * so a bar shows as the client area narrower (a vertical bar) or
 * shorter (a horizontal one) by SM_CXVSCROLL or SM_CYHSCROLL: the
 * blocks print that, as a relation, never a size. scrollex's window is
 * 200x100, topmost (WS_EX_TOPMOST), with no bars, so no other window
 * covers it and its client area is the same on every screen: the
 * rectangles it prints are in its client coordinates, as relations to
 * the rectangle the documentation leads one to expect.
 *
 * A scroll bar's arrows enabled or not show only through
 * EnableScrollBar's return, zero when the arrows were in the asked
 * state already: enable probes them that way.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=. A SCROLLINFO
 * a call fills is filled with 0xA5 bytes before, and a member it left
 * prints as "untouched"; GetScrollRange's outputs hold -7 before. Each
 * section creates its windows and destroys them at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   info     a WS_VSCROLL | WS_HSCROLL window's bars: GetScrollInfo
 *            (SIF_ALL) as created; SetScrollInfo's return (the
 *            position) and GetScrollInfo after, for SIF_RANGE,
 *            SIF_PAGE, SIF_POS past either end, a page larger than the
 *            range, an inverted range, SIF_ALL at once, SIF_TRACKPOS;
 *            a range needing no scrolling, with and without
 *            SIF_DISABLENOSCROLL (the bar hidden or kept); fMask 0,
 *            cbSize 0, SB_CTL and SB_BOTH on the window, a NULL window
 *   added    a window created without bars: GetScrollInfo, then
 *            SetScrollInfo of SB_VERT and SB_HORZ, the style and the
 *            client area after each
 *   control  ScrollBar controls (SBS_VERT, SBS_HORZ): the class, the
 *            style, GetScrollInfo(SB_CTL) as created, SetScrollInfo's
 *            clamping, SIF_DISABLENOSCROLL (visible and enabled after),
 *            SB_VERT on the control; SBM_GETSCROLLINFO,
 *            SBM_SETSCROLLINFO, SBM_SETRANGE, SBM_GETRANGE, SBM_SETPOS
 *            and SBM_GETPOS
 *   posrange SetScrollRange and SetScrollPos on a window's bars and a
 *            control: the previous position, the clamping (with a
 *            page too), an inverted range, a range of 0 to 0 (the bar
 *            hidden), a range wider than MAXLONG; GetScrollPos and
 *            GetScrollRange after each; a window without bars
 *   show     ShowScrollBar of SB_VERT, SB_HORZ and SB_BOTH, hiding and
 *            showing (the style and the client area after), the scroll
 *            information kept across; a window without bars; SB_CTL on
 *            a control (IsWindowVisible after); NULL
 *   enable   EnableScrollBar with each ESB_* flag on SB_VERT, SB_HORZ,
 *            SB_BOTH and a control (IsWindowEnabled after), each twice;
 *            whether SetScrollInfo, SIF_DISABLENOSCROLL and
 *            ShowScrollBar change the arrows' state (probed); a hidden
 *            bar, a window without bars, a bad flag
 *   scrollex ScrollWindowEx up, left, diagonally, by more than the
 *            client area, by nothing, with prcScroll and prcClip, with
 *            and without SW_INVALIDATE and SW_ERASE: the return (the
 *            region's type), prcUpdate and hrgnUpdate's box against
 *            the uncovered rectangle, the window's update region
 *            after; SW_SCROLLCHILDREN and a child's place after;
 *            ScrollWindow; a hidden window; NULL
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat scroll):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% scroll.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

#define WINDOW_CLASS L"F2KScrollWin"

/* What GetScrollInfo finds in a member it left alone. */
#define SI_PATTERN ((int)0xA5A5A5A5u)

/* The windows' size. */
#define WIN_W 200
#define WIN_H 150
#define EX_W 200
#define EX_H 100

/* --- Helpers ----------------------------------------------------------- */

static HINSTANCE instance(void)
{
    return GetModuleHandleW(NULL);
}

/* Dispatch what is queued, a bounded number of messages. */
static void drain(void)
{
    MSG m;
    int n = 0;

    while (n++ < 500 && PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        if (m.message == WM_QUIT) {
            continue;
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void register_class(void)
{
    WNDCLASSW wc;
    ATOM a;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance();
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WINDOW_CLASS;
    arm();
    a = RegisterClassW(&wc);
    line("RegisterClassW(F2KScrollWin): atom nonzero %s err=%s", yesno(a != 0), le());
}

static void unregister_class(void)
{
    UnregisterClassW(WINDOW_CLASS, instance());
}

/* The section's window: WS_POPUP | WS_VISIBLE and the bars asked for. */
static HWND open_window(DWORD bars, const char *what)
{
    HWND h;

    arm();
    h = CreateWindowExW(0, WINDOW_CLASS, L"scroll", WS_POPUP | WS_VISIBLE | bars, 40, 40, WIN_W, WIN_H, NULL, NULL,
                        instance(), NULL);
    line("CreateWindowExW(F2KScrollWin, WS_POPUP | WS_VISIBLE%s): non-NULL %s err=%s", what, yesno(h != NULL),
         le());
    drain();
    return h;
}

/* A ScrollBar control, a child of the window. */
static HWND open_control(HWND parent, DWORD style, int id, const char *what)
{
    HWND h;
    int vert = (style & SBS_VERT) != 0;

    arm();
    h = CreateWindowExW(0, L"ScrollBar", L"", WS_CHILD | WS_VISIBLE | style, vert ? 10 : 40, vert ? 10 : 120,
                        vert ? 20 : 100, vert ? 100 : 20, parent, (HMENU)id, instance(), NULL);
    line("CreateWindowExW(\"ScrollBar\", %s, id %d): non-NULL %s err=%s", what, id, yesno(h != NULL), le());
    return h;
}

/* A difference of the window's and its client area's sizes, as printed. */
static const char *by(int d, int bar)
{
    static char bufs[4][24];
    static int next;
    char *b = bufs[next++ & 3];

    if (d == 0) {
        return "nothing";
    }
    if (d == bar) {
        return "a bar";
    }
    sprintf(b, "other (%d)", d);
    return b;
}

/* The style's bars and the client area against the window's rectangle. */
static void print_bars(HWND h)
{
    RECT wr, cr;
    LONG style;

    GetWindowRect(h, &wr);
    GetClientRect(h, &cr);
    style = GetWindowLongW(h, GWL_STYLE);
    line("  style WS_VSCROLL %s WS_HSCROLL %s; the client area narrower by %s, shorter by %s",
         yesno(style & WS_VSCROLL), yesno(style & WS_HSCROLL),
         by((wr.right - wr.left) - (cr.right - cr.left), GetSystemMetrics(SM_CXVSCROLL)),
         by((wr.bottom - wr.top) - (cr.bottom - cr.top), GetSystemMetrics(SM_CYHSCROLL)));
}

static const char *int_label(int v)
{
    static char bufs[8][16];
    static int next;
    char *b = bufs[next++ & 7];

    if (v == SI_PATTERN) {
        return "untouched";
    }
    sprintf(b, "%d", v);
    return b;
}

static const char *bar_name(int bar)
{
    switch (bar) {
    case SB_HORZ: return "SB_HORZ";
    case SB_VERT: return "SB_VERT";
    case SB_CTL: return "SB_CTL";
    case SB_BOTH: return "SB_BOTH";
    }
    return "?";
}

static void print_si(const SCROLLINFO *si)
{
    line("  nMin=%s nMax=%s nPage=%s nPos=%s nTrackPos=%s", int_label(si->nMin), int_label(si->nMax),
         int_label((int)si->nPage), int_label(si->nPos), int_label(si->nTrackPos));
}

/* GetScrollInfo with a pattern-filled struct, cbSize given. */
static void get_info_sized(HWND h, int bar, UINT size, UINT mask, const char *what)
{
    SCROLLINFO si;
    BOOL r;

    memset(&si, 0xA5, sizeof si);
    si.cbSize = size;
    si.fMask = mask;
    arm();
    r = GetScrollInfo(h, bar, &si);
    line("GetScrollInfo(%s, %s): ret=%d err=%s", what, bar_name(bar), r, le());
    print_si(&si);
}

static void get_info(HWND h, int bar, const char *what)
{
    get_info_sized(h, bar, sizeof(SCROLLINFO), SIF_ALL, what);
}

/* SetScrollInfo with the members given, redraw TRUE; its return is the
 * position after. */
static void set_info_sized(HWND h, int bar, UINT size, UINT mask, int min, int max, UINT page, int pos,
                           const char *what)
{
    SCROLLINFO si;
    int r;

    ZeroMemory(&si, sizeof si);
    si.cbSize = size;
    si.fMask = mask;
    si.nMin = min;
    si.nMax = max;
    si.nPage = page;
    si.nPos = pos;
    si.nTrackPos = pos;
    arm();
    r = SetScrollInfo(h, bar, &si, TRUE);
    line("SetScrollInfo(%s, %s): ret=%d err=%s", what, bar_name(bar), r, le());
}

static void set_info(HWND h, int bar, UINT mask, int min, int max, UINT page, int pos, const char *what)
{
    set_info_sized(h, bar, sizeof(SCROLLINFO), mask, min, max, page, pos, what);
}

static void get_pos(HWND h, int bar, const char *what)
{
    int r;

    arm();
    r = GetScrollPos(h, bar);
    line("GetScrollPos(%s, %s): ret=%d err=%s", what, bar_name(bar), r, le());
}

static void get_range(HWND h, int bar, const char *what)
{
    int lo = -7, hi = -7;
    BOOL r;

    arm();
    r = GetScrollRange(h, bar, &lo, &hi);
    line("GetScrollRange(%s, %s): ret=%d err=%s min=%d max=%d", what, bar_name(bar), r, le(), lo, hi);
}

static void set_pos(HWND h, int bar, int pos, const char *what)
{
    int r;

    arm();
    r = SetScrollPos(h, bar, pos, TRUE);
    line("SetScrollPos(%s, %s, %d): ret=%d err=%s", what, bar_name(bar), pos, r, le());
}

static void set_range(HWND h, int bar, int lo, int hi, const char *what)
{
    BOOL r;

    arm();
    r = SetScrollRange(h, bar, lo, hi, TRUE);
    line("SetScrollRange(%s, %s, %d, %d): ret=%d err=%s", what, bar_name(bar), lo, hi, r, le());
}

/* --- info -------------------------------------------------------------- */

static void sec_info(void)
{
    HWND h;

    register_class();
    h = open_window(WS_VSCROLL | WS_HSCROLL, " | WS_VSCROLL | WS_HSCROLL");
    print_bars(h);
    get_info(h, SB_VERT, "the window");
    get_info(h, SB_HORZ, "the window");
    get_info_sized(h, SB_VERT, sizeof(SCROLLINFO), SIF_POS, "the window, SIF_POS alone");
    get_info_sized(h, SB_VERT, sizeof(SCROLLINFO), SIF_TRACKPOS, "the window, SIF_TRACKPOS alone");

    set_info(h, SB_VERT, SIF_RANGE, 0, 99, 0, 0, "the window, SIF_RANGE 0-99");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_PAGE, 0, 0, 10, 0, "the window, SIF_PAGE 10");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_POS, 0, 0, 0, 50, "the window, SIF_POS 50");
    set_info(h, SB_VERT, SIF_POS, 0, 0, 0, 90, "the window, SIF_POS 90 (nMax - nPage + 1)");
    set_info(h, SB_VERT, SIF_POS, 0, 0, 0, 95, "the window, SIF_POS 95");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_POS, 0, 0, 0, -5, "the window, SIF_POS -5");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_POS, 0, 0, 0, 60, "the window, SIF_POS 60");
    set_info(h, SB_VERT, SIF_PAGE, 0, 0, 50, 0, "the window, SIF_PAGE 50 (position 60 now past the end)");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_PAGE, 0, 0, 200, 0, "the window, SIF_PAGE 200 (more than the range)");
    get_info(h, SB_VERT, "the window");
    print_bars(h);
    set_info(h, SB_VERT, SIF_PAGE | SIF_RANGE, 50, 10, 0, 0, "the window, SIF_PAGE 0 | SIF_RANGE 50-10 (inverted)");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_ALL, 0, 20, 5, 30, "the window, SIF_ALL 0-20, page 5, pos 30");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_ALL, -10, 10, 4, -20, "the window, SIF_ALL -10-10, page 4, pos -20");
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_TRACKPOS, 0, 0, 0, 3, "the window, SIF_TRACKPOS 3");
    get_info(h, SB_VERT, "the window");
    print_bars(h);

    /* A range the page covers: the bar hidden, or kept but disabled. */
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 9, 10, 0, "the window, 0-9, page 10, pos 0");
    print_bars(h);
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE | SIF_DISABLENOSCROLL, 0, 9, 10, 0,
             "the window, 0-9, page 10, SIF_DISABLENOSCROLL");
    print_bars(h);
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE, 0, 99, 10, 0, "the window, 0-99, page 10");
    print_bars(h);
    set_info(h, SB_VERT, SIF_RANGE | SIF_DISABLENOSCROLL, 0, 0, 0, 0, "the window, SIF_RANGE 0-0 | SIF_DISABLENOSCROLL");
    print_bars(h);
    set_info(h, SB_VERT, SIF_RANGE, 0, 0, 0, 0, "the window, SIF_RANGE 0-0");
    print_bars(h);
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE, 0, 99, 10, 0, "the window, 0-99, page 10");
    print_bars(h);

    /* The horizontal bar. */
    set_info(h, SB_HORZ, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 49, 25, 40, "the window, 0-49, page 25, pos 40");
    get_info(h, SB_HORZ, "the window");
    set_info(h, SB_HORZ, SIF_RANGE | SIF_PAGE, 0, 9, 20, 0, "the window, 0-9, page 20");
    print_bars(h);
    get_info(h, SB_HORZ, "the window");

    /* Calls that fail, or do nothing. */
    set_info(h, SB_VERT, 0, 0, 5, 1, 1, "the window, fMask 0");
    get_info(h, SB_VERT, "the window");
    set_info_sized(h, SB_VERT, 0, SIF_POS, 0, 0, 0, 7, "the window, cbSize 0, SIF_POS 7");
    get_info_sized(h, SB_VERT, 0, SIF_ALL, "the window, cbSize 0");
    get_info_sized(h, SB_VERT, sizeof(SCROLLINFO), 0, "the window, fMask 0");
    get_info(h, SB_CTL, "the window");
    set_info(h, SB_CTL, SIF_POS, 0, 0, 0, 5, "the window, SIF_POS 5");
    set_info(h, SB_BOTH, SIF_POS, 0, 0, 0, 5, "the window, SIF_POS 5");
    get_info(h, SB_BOTH, "the window");
    get_info(NULL, SB_VERT, "NULL");
    set_info(NULL, SB_VERT, SIF_POS, 0, 0, 0, 5, "NULL, SIF_POS 5");

    DestroyWindow(h);
    drain();
    unregister_class();
}

/* --- added ------------------------------------------------------------- */

static void sec_added(void)
{
    HWND h;

    register_class();
    h = open_window(0, "");
    print_bars(h);
    get_info(h, SB_VERT, "the window (no bars)");
    get_info(h, SB_HORZ, "the window (no bars)");
    get_pos(h, SB_VERT, "the window (no bars)");
    get_range(h, SB_VERT, "the window (no bars)");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 99, 10, 30, "the window, 0-99, page 10, pos 30");
    print_bars(h);
    get_info(h, SB_VERT, "the window");
    set_info(h, SB_HORZ, SIF_RANGE | SIF_PAGE, 0, 9, 10, 0, "the window, 0-9, page 10 (nothing to scroll)");
    print_bars(h);
    get_info(h, SB_HORZ, "the window");
    set_info(h, SB_HORZ, SIF_RANGE | SIF_PAGE, 0, 49, 10, 0, "the window, 0-49, page 10");
    print_bars(h);
    get_info(h, SB_HORZ, "the window");

    DestroyWindow(h);
    drain();
    unregister_class();
}

/* --- control ----------------------------------------------------------- */

static void sbm(HWND h, UINT msg, WPARAM wparam, LPARAM lparam, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, msg, wparam, lparam);
    line("SendMessageW(%s): ret=%ld err=%s", what, (long)r, le());
}

static void sec_control(void)
{
    HWND h, v, hz;
    WCHAR cls[32];
    SCROLLINFO si;
    int lo, hi;
    LRESULT r;

    register_class();
    h = open_window(0, "");
    v = open_control(h, SBS_VERT, 101, "SBS_VERT");
    hz = open_control(h, SBS_HORZ, 102, "SBS_HORZ");
    cls[0] = 0;
    GetClassNameW(v, cls, 32);
    line("  class %s style=0x%08lX", ws(cls), (unsigned long)GetWindowLongW(v, GWL_STYLE));
    cls[0] = 0;
    GetClassNameW(hz, cls, 32);
    line("  class %s style=0x%08lX", ws(cls), (unsigned long)GetWindowLongW(hz, GWL_STYLE));

    get_info(v, SB_CTL, "the SBS_VERT control");
    get_info(hz, SB_CTL, "the SBS_HORZ control");
    get_info(v, SB_VERT, "the SBS_VERT control");
    set_info(v, SB_CTL, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 99, 10, 95, "the SBS_VERT control, 0-99, page 10, pos 95");
    get_info(v, SB_CTL, "the SBS_VERT control");
    set_info(v, SB_CTL, SIF_POS, 0, 0, 0, -1, "the SBS_VERT control, SIF_POS -1");
    set_info(v, SB_CTL, SIF_PAGE, 0, 0, 500, 0, "the SBS_VERT control, SIF_PAGE 500");
    get_info(v, SB_CTL, "the SBS_VERT control");
    set_info(v, SB_CTL, SIF_RANGE | SIF_PAGE, 0, 9, 10, 0, "the SBS_VERT control, 0-9, page 10");
    line("  visible %s enabled %s", yesno(IsWindowVisible(v)), yesno(IsWindowEnabled(v)));
    set_info(v, SB_CTL, SIF_RANGE | SIF_PAGE | SIF_DISABLENOSCROLL, 0, 9, 10, 0,
             "the SBS_VERT control, 0-9, page 10, SIF_DISABLENOSCROLL");
    line("  visible %s enabled %s", yesno(IsWindowVisible(v)), yesno(IsWindowEnabled(v)));
    set_info(v, SB_CTL, SIF_RANGE | SIF_PAGE, 0, 99, 10, 0, "the SBS_VERT control, 0-99, page 10");
    line("  visible %s enabled %s", yesno(IsWindowVisible(v)), yesno(IsWindowEnabled(v)));
    set_info(v, SB_VERT, SIF_POS, 0, 0, 0, 5, "the SBS_VERT control, SIF_POS 5");
    print_bars(v);

    /* The control's own messages. */
    memset(&si, 0xA5, sizeof si);
    si.cbSize = sizeof si;
    si.fMask = SIF_ALL;
    arm();
    r = SendMessageW(v, SBM_GETSCROLLINFO, 0, (LPARAM)&si);
    line("SendMessageW(the SBS_VERT control, SBM_GETSCROLLINFO, SIF_ALL): ret=%ld err=%s", (long)r, le());
    print_si(&si);
    ZeroMemory(&si, sizeof si);
    si.cbSize = sizeof si;
    si.fMask = SIF_POS;
    si.nPos = 42;
    arm();
    r = SendMessageW(v, SBM_SETSCROLLINFO, TRUE, (LPARAM)&si);
    line("SendMessageW(the SBS_VERT control, SBM_SETSCROLLINFO, SIF_POS 42): ret=%ld err=%s", (long)r, le());
    get_pos(v, SB_CTL, "the SBS_VERT control");
    sbm(hz, SBM_SETRANGE, 5, 25, "the SBS_HORZ control, SBM_SETRANGE 5, 25");
    lo = -7;
    hi = -7;
    arm();
    r = SendMessageW(hz, SBM_GETRANGE, (WPARAM)&lo, (LPARAM)&hi);
    line("SendMessageW(the SBS_HORZ control, SBM_GETRANGE): ret=%ld err=%s min=%d max=%d", (long)r, le(), lo, hi);
    sbm(hz, SBM_SETPOS, 30, TRUE, "the SBS_HORZ control, SBM_SETPOS 30");
    sbm(hz, SBM_GETPOS, 0, 0, "the SBS_HORZ control, SBM_GETPOS");
    sbm(hz, SBM_SETPOS, 10, TRUE, "the SBS_HORZ control, SBM_SETPOS 10");
    sbm(hz, SBM_GETPOS, 0, 0, "the SBS_HORZ control, SBM_GETPOS");
    get_info(hz, SB_CTL, "the SBS_HORZ control");

    DestroyWindow(h);
    drain();
    unregister_class();
}

/* --- posrange ---------------------------------------------------------- */

static void sec_posrange(void)
{
    HWND h, plain, v;

    register_class();
    h = open_window(WS_VSCROLL | WS_HSCROLL, " | WS_VSCROLL | WS_HSCROLL");
    get_range(h, SB_VERT, "the window");
    get_pos(h, SB_VERT, "the window");
    set_range(h, SB_VERT, 0, 50, "the window");
    get_range(h, SB_VERT, "the window");
    set_pos(h, SB_VERT, 20, "the window");
    get_pos(h, SB_VERT, "the window");
    set_pos(h, SB_VERT, 80, "the window");
    get_pos(h, SB_VERT, "the window");
    set_pos(h, SB_VERT, -3, "the window");
    get_pos(h, SB_VERT, "the window");
    set_pos(h, SB_VERT, 25, "the window");
    set_info(h, SB_VERT, SIF_PAGE, 0, 0, 10, 0, "the window, SIF_PAGE 10");
    set_pos(h, SB_VERT, 50, "the window");
    get_pos(h, SB_VERT, "the window");
    get_info(h, SB_VERT, "the window");
    set_range(h, SB_VERT, 0, 30, "the window (position 41 past the new end)");
    get_pos(h, SB_VERT, "the window");
    get_info(h, SB_VERT, "the window");
    set_range(h, SB_VERT, 10, 5, "the window (inverted)");
    get_range(h, SB_VERT, "the window");
    get_info(h, SB_VERT, "the window");
    set_range(h, SB_VERT, 0, 0, "the window");
    print_bars(h);
    get_range(h, SB_VERT, "the window");
    set_pos(h, SB_VERT, 5, "the window (range 0-0)");
    set_range(h, SB_VERT, 0, 0x7FFFFFFF, "the window (0 to MAXLONG)");
    get_range(h, SB_VERT, "the window");
    set_range(h, SB_VERT, -1, 0x7FFFFFFF, "the window (wider than MAXLONG)");
    get_range(h, SB_VERT, "the window");
    set_range(h, SB_VERT, 0, 100, "the window");
    print_bars(h);
    set_range(h, SB_HORZ, -20, 20, "the window");
    set_pos(h, SB_HORZ, -30, "the window");
    get_pos(h, SB_HORZ, "the window");
    get_range(h, SB_HORZ, "the window");
    set_pos(h, SB_CTL, 5, "the window");
    set_pos(h, SB_BOTH, 5, "the window");
    get_pos(h, SB_CTL, "the window");
    set_range(h, SB_CTL, 0, 10, "the window");
    get_range(h, SB_CTL, "the window");
    set_pos(NULL, SB_VERT, 5, "NULL");
    get_pos(NULL, SB_VERT, "NULL");

    plain = CreateWindowExW(0, WINDOW_CLASS, L"plain", WS_POPUP, 0, 0, 50, 50, NULL, NULL, instance(), NULL);
    line("a second window, hidden, without bars: non-NULL %s", yesno(plain != NULL));
    get_pos(plain, SB_VERT, "the second window");
    get_range(plain, SB_VERT, "the second window");
    set_pos(plain, SB_VERT, 5, "the second window");
    print_bars(plain);
    set_range(plain, SB_HORZ, 0, 10, "the second window");
    print_bars(plain);
    get_pos(plain, SB_HORZ, "the second window");

    v = open_control(h, SBS_VERT, 101, "SBS_VERT");
    get_range(v, SB_CTL, "the control");
    set_range(v, SB_CTL, 0, 10, "the control");
    set_pos(v, SB_CTL, 7, "the control");
    set_pos(v, SB_CTL, 70, "the control");
    get_pos(v, SB_CTL, "the control");
    get_range(v, SB_CTL, "the control");

    DestroyWindow(plain);
    DestroyWindow(h);
    drain();
    unregister_class();
}

/* --- show -------------------------------------------------------------- */

static void show_bar(HWND h, int bar, BOOL show, const char *what)
{
    BOOL r;

    arm();
    r = ShowScrollBar(h, bar, show);
    line("ShowScrollBar(%s, %s, %s): ret=%d err=%s", what, bar_name(bar), show ? "TRUE" : "FALSE", r, le());
}

static void sec_show(void)
{
    HWND h, plain, v;

    register_class();
    h = open_window(WS_VSCROLL | WS_HSCROLL, " | WS_VSCROLL | WS_HSCROLL");
    print_bars(h);
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 99, 10, 30, "the window, 0-99, page 10, pos 30");
    show_bar(h, SB_VERT, FALSE, "the window");
    print_bars(h);
    show_bar(h, SB_VERT, FALSE, "the window, again");
    get_info(h, SB_VERT, "the window (its bar hidden)");
    set_pos(h, SB_VERT, 40, "the window (its bar hidden)");
    show_bar(h, SB_VERT, TRUE, "the window");
    print_bars(h);
    get_info(h, SB_VERT, "the window");
    show_bar(h, SB_HORZ, FALSE, "the window");
    print_bars(h);
    show_bar(h, SB_BOTH, FALSE, "the window");
    print_bars(h);
    show_bar(h, SB_BOTH, TRUE, "the window");
    print_bars(h);
    show_bar(h, SB_VERT, TRUE, "the window, again");
    print_bars(h);

    plain = open_window(0, "");
    show_bar(plain, SB_VERT, TRUE, "a window without bars");
    print_bars(plain);
    get_info(plain, SB_VERT, "that window");
    show_bar(plain, SB_HORZ, FALSE, "that window");
    print_bars(plain);
    show_bar(plain, 7, TRUE, "that window, a bad bar 7");
    DestroyWindow(plain);

    v = open_control(h, SBS_VERT, 101, "SBS_VERT");
    show_bar(v, SB_CTL, FALSE, "the control");
    line("  the control visible %s", yesno(IsWindowVisible(v)));
    show_bar(v, SB_CTL, TRUE, "the control");
    line("  the control visible %s", yesno(IsWindowVisible(v)));
    show_bar(v, SB_VERT, TRUE, "the control");
    print_bars(v);
    show_bar(NULL, SB_VERT, TRUE, "NULL");

    DestroyWindow(h);
    drain();
    unregister_class();
}

/* --- enable ------------------------------------------------------------ */

static const char *esb_name(UINT f)
{
    switch (f) {
    case ESB_ENABLE_BOTH: return "ESB_ENABLE_BOTH";
    case ESB_DISABLE_LTUP: return "ESB_DISABLE_LTUP";
    case ESB_DISABLE_RTDN: return "ESB_DISABLE_RTDN";
    case ESB_DISABLE_BOTH: return "ESB_DISABLE_BOTH";
    }
    return "a bad flag 7";
}

static void enable_bar(HWND h, int bar, UINT flags, const char *what)
{
    BOOL r;

    arm();
    r = EnableScrollBar(h, bar, flags);
    line("EnableScrollBar(%s, %s, %s): ret=%d err=%s", what, bar_name(bar), esb_name(flags), r, le());
}

static void sec_enable(void)
{
    HWND h, plain, v;

    register_class();
    h = open_window(WS_VSCROLL | WS_HSCROLL, " | WS_VSCROLL | WS_HSCROLL");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 99, 10, 30, "the window, 0-99, page 10, pos 30");
    set_info(h, SB_HORZ, SIF_RANGE | SIF_PAGE | SIF_POS, 0, 99, 10, 30, "the window, 0-99, page 10, pos 30");

    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window, again");
    enable_bar(h, SB_VERT, ESB_ENABLE_BOTH, "the window");
    enable_bar(h, SB_VERT, ESB_ENABLE_BOTH, "the window, again");
    enable_bar(h, SB_VERT, ESB_DISABLE_UP, "the window");
    enable_bar(h, SB_VERT, ESB_DISABLE_UP, "the window, again");
    enable_bar(h, SB_VERT, ESB_DISABLE_DOWN, "the window (up disabled)");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window (both disabled one by one)");
    enable_bar(h, SB_VERT, ESB_ENABLE_BOTH, "the window");
    enable_bar(h, SB_HORZ, ESB_DISABLE_LEFT, "the window");
    enable_bar(h, SB_HORZ, ESB_DISABLE_RIGHT, "the window");
    enable_bar(h, SB_HORZ, ESB_ENABLE_BOTH, "the window");
    enable_bar(h, SB_BOTH, ESB_DISABLE_BOTH, "the window");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window (after SB_BOTH)");
    enable_bar(h, SB_HORZ, ESB_DISABLE_BOTH, "the window (after SB_BOTH)");
    enable_bar(h, SB_BOTH, ESB_ENABLE_BOTH, "the window");
    enable_bar(h, SB_VERT, 7, "the window");

    /* Whether other calls change the arrows: probed by disabling. */
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window");
    set_info(h, SB_VERT, SIF_POS, 0, 0, 0, 40, "the window, SIF_POS 40");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window, a probe after SetScrollInfo(SIF_POS)");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE, 0, 50, 10, 0, "the window, 0-50, page 10");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window, a probe after SetScrollInfo(SIF_RANGE | SIF_PAGE)");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE | SIF_DISABLENOSCROLL, 0, 9, 10, 0,
             "the window, 0-9, page 10, SIF_DISABLENOSCROLL");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window, a probe after SIF_DISABLENOSCROLL");
    enable_bar(h, SB_VERT, ESB_ENABLE_BOTH, "the window");
    set_info(h, SB_VERT, SIF_RANGE | SIF_PAGE, 0, 99, 10, 0, "the window, 0-99, page 10");
    enable_bar(h, SB_VERT, ESB_ENABLE_BOTH, "the window, a probe after a range to scroll");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window");
    ShowScrollBar(h, SB_VERT, FALSE);
    line("ShowScrollBar(the window, SB_VERT, FALSE)");
    enable_bar(h, SB_VERT, ESB_ENABLE_BOTH, "the window (its bar hidden)");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window (its bar hidden)");
    ShowScrollBar(h, SB_VERT, TRUE);
    line("ShowScrollBar(the window, SB_VERT, TRUE)");
    enable_bar(h, SB_VERT, ESB_DISABLE_BOTH, "the window, a probe after ShowScrollBar");

    plain = open_window(0, "");
    enable_bar(plain, SB_VERT, ESB_DISABLE_BOTH, "a window without bars");
    enable_bar(plain, SB_CTL, ESB_DISABLE_BOTH, "that window");
    DestroyWindow(plain);

    v = open_control(h, SBS_VERT, 101, "SBS_VERT");
    set_info(v, SB_CTL, SIF_RANGE | SIF_PAGE, 0, 99, 10, 0, "the control, 0-99, page 10");
    enable_bar(v, SB_CTL, ESB_DISABLE_BOTH, "the control");
    line("  the control enabled %s", yesno(IsWindowEnabled(v)));
    enable_bar(v, SB_CTL, ESB_DISABLE_BOTH, "the control, again");
    enable_bar(v, SB_CTL, ESB_ENABLE_BOTH, "the control");
    line("  the control enabled %s", yesno(IsWindowEnabled(v)));
    enable_bar(v, SB_CTL, ESB_DISABLE_UP, "the control");
    line("  the control enabled %s", yesno(IsWindowEnabled(v)));
    sbm(v, SBM_ENABLE_ARROWS, ESB_ENABLE_BOTH, 0, "the control, SBM_ENABLE_ARROWS ESB_ENABLE_BOTH");
    sbm(v, SBM_ENABLE_ARROWS, ESB_ENABLE_BOTH, 0, "the control, SBM_ENABLE_ARROWS ESB_ENABLE_BOTH again");
    EnableWindow(v, FALSE);
    line("EnableWindow(the control, FALSE)");
    enable_bar(v, SB_CTL, ESB_DISABLE_BOTH, "the control, a probe after EnableWindow(FALSE)");
    enable_bar(v, SB_CTL, ESB_ENABLE_BOTH, "the control");
    line("  the control enabled %s", yesno(IsWindowEnabled(v)));
    enable_bar(v, SB_VERT, ESB_DISABLE_BOTH, "the control");
    enable_bar(NULL, SB_VERT, ESB_DISABLE_BOTH, "NULL");

    DestroyWindow(h);
    drain();
    unregister_class();
}

/* --- scrollex ---------------------------------------------------------- */

static HWND ex_window;

static const char *region_name(int r)
{
    static char b[16];

    switch (r) {
    case ERROR: return "ERROR";
    case NULLREGION: return "NULLREGION";
    case SIMPLEREGION: return "SIMPLEREGION";
    case COMPLEXREGION: return "COMPLEXREGION";
    }
    sprintf(b, "%d", r);
    return b;
}

/* ScrollWindowEx of ex_window, validated first, with an update region
 * and rectangle; `expect` is the rectangle the scroll uncovers, in
 * client coordinates, `expect_name` that rectangle as printed. */
static void scroll_ex(int dx, int dy, const RECT *scroll, const RECT *clip, UINT flags, const RECT *expect,
                      const char *expect_name, const char *what)
{
    HRGN rgn;
    RECT upd, box, ur;
    int r, type;
    BOOL has;
    DWORD err;

    ValidateRect(ex_window, NULL);
    rgn = CreateRectRgn(0, 0, 0, 0);
    SetRect(&upd, -7, -7, -7, -7);
    arm();
    r = ScrollWindowEx(ex_window, dx, dy, scroll, clip, rgn, &upd, flags);
    err = GetLastError();
    type = GetRgnBox(rgn, &box);
    has = GetUpdateRect(ex_window, &ur, FALSE);
    line("ScrollWindowEx(%s): ret=%s err=%s", what, region_name(r), le_of(err));
    line("  prcUpdate %s: %s; hrgnUpdate %s, its box prcUpdate %s; the window's update region %s",
         expect_name, yesno(EqualRect(&upd, expect)), region_name(type), yesno(EqualRect(&box, &upd)),
         !has ? "empty" : (EqualRect(&ur, &upd) ? "prcUpdate" : "other"));
    DeleteObject(rgn);
    drain();
}

static void sec_scrollex(void)
{
    HWND child, hidden;
    RECT expect, scroll, clip, empty, cr, before, after;
    BOOL b;
    int r;

    register_class();
    arm();
    ex_window = CreateWindowExW(WS_EX_TOPMOST, WINDOW_CLASS, L"scrollex", WS_POPUP | WS_VISIBLE, 40, 40, EX_W, EX_H,
                                NULL, NULL, instance(), NULL);
    line("CreateWindowExW(F2KScrollWin, WS_EX_TOPMOST, WS_POPUP | WS_VISIBLE, 200x100): non-NULL %s err=%s",
         yesno(ex_window != NULL), le());
    UpdateWindow(ex_window);
    drain();
    GetClientRect(ex_window, &cr);
    line("  the client area 200x100: %s", yesno(cr.right == EX_W && cr.bottom == EX_H));
    SetRectEmpty(&empty);

    SetRect(&expect, 0, 90, 200, 100);
    scroll_ex(0, -10, NULL, NULL, 0, &expect, "(0,90)-(200,100)", "0, -10, NULL, NULL, 0");
    scroll_ex(0, -10, NULL, NULL, SW_INVALIDATE, &expect, "(0,90)-(200,100)", "0, -10, NULL, NULL, SW_INVALIDATE");
    scroll_ex(0, -10, NULL, NULL, SW_INVALIDATE | SW_ERASE, &expect, "(0,90)-(200,100)",
              "0, -10, NULL, NULL, SW_INVALIDATE | SW_ERASE");
    SetRect(&expect, 0, 0, 200, 10);
    scroll_ex(0, 10, NULL, NULL, SW_INVALIDATE, &expect, "(0,0)-(200,10)", "0, 10, NULL, NULL, SW_INVALIDATE");
    SetRect(&expect, 0, 0, 20, 100);
    scroll_ex(20, 0, NULL, NULL, SW_INVALIDATE, &expect, "(0,0)-(20,100)", "20, 0, NULL, NULL, SW_INVALIDATE");
    SetRect(&expect, 180, 0, 200, 100);
    scroll_ex(-20, 0, NULL, NULL, SW_INVALIDATE, &expect, "(180,0)-(200,100)", "-20, 0, NULL, NULL, SW_INVALIDATE");
    SetRect(&expect, 0, 0, 200, 100);
    scroll_ex(5, 5, NULL, NULL, SW_INVALIDATE, &expect, "the client area (its bounds)",
              "5, 5, NULL, NULL, SW_INVALIDATE");
    scroll_ex(0, -150, NULL, NULL, SW_INVALIDATE, &expect, "the client area", "0, -150, NULL, NULL, SW_INVALIDATE");
    scroll_ex(0, 0, NULL, NULL, SW_INVALIDATE, &empty, "empty", "0, 0, NULL, NULL, SW_INVALIDATE");

    SetRect(&scroll, 50, 0, 150, 100);
    SetRect(&expect, 50, 90, 150, 100);
    scroll_ex(0, -10, &scroll, NULL, SW_INVALIDATE, &expect, "(50,90)-(150,100)",
              "0, -10, (50,0)-(150,100), NULL, SW_INVALIDATE");
    SetRect(&clip, 0, 0, 200, 50);
    SetRect(&expect, 0, 0, 200, 10);
    scroll_ex(0, 10, NULL, &clip, SW_INVALIDATE, &expect, "(0,0)-(200,10)",
              "0, 10, NULL, (0,0)-(200,50), SW_INVALIDATE");
    SetRect(&clip, 0, 50, 200, 100);
    SetRect(&expect, 50, 90, 150, 100);
    scroll_ex(0, -10, &scroll, &clip, SW_INVALIDATE, &expect, "(50,90)-(150,100)",
              "0, -10, (50,0)-(150,100), (0,50)-(200,100), SW_INVALIDATE");

    /* No region, no rectangle. */
    ValidateRect(ex_window, NULL);
    arm();
    r = ScrollWindowEx(ex_window, 0, -10, NULL, NULL, NULL, NULL, SW_INVALIDATE);
    line("ScrollWindowEx(0, -10, NULL, NULL, NULL region, NULL rectangle, SW_INVALIDATE): ret=%s err=%s",
         region_name(r), le());
    b = GetUpdateRect(ex_window, &after, FALSE);
    SetRect(&expect, 0, 90, 200, 100);
    line("  the window's update region (0,90)-(200,100): %s", yesno(b && EqualRect(&after, &expect)));
    drain();

    /* A child scrolled along, or not. */
    child = CreateWindowExW(0, WINDOW_CLASS, L"child", WS_CHILD | WS_VISIBLE, 10, 10, 30, 30, ex_window, (HMENU)1,
                            instance(), NULL);
    line("a child at (10,10), 30x30: non-NULL %s", yesno(child != NULL));
    drain();
    GetWindowRect(child, &before);
    SetRect(&expect, 0, 0, 200, 15);
    scroll_ex(0, 15, NULL, NULL, SW_INVALIDATE | SW_SCROLLCHILDREN, &expect, "(0,0)-(200,15)",
              "0, 15, NULL, NULL, SW_INVALIDATE | SW_SCROLLCHILDREN");
    GetWindowRect(child, &after);
    line("  the child moved by (%ld,%ld)", (long)(after.left - before.left), (long)(after.top - before.top));
    before = after;
    scroll_ex(0, 15, NULL, NULL, SW_INVALIDATE, &expect, "(0,0)-(200,15)", "0, 15, NULL, NULL, SW_INVALIDATE");
    GetWindowRect(child, &after);
    line("  the child moved by (%ld,%ld)", (long)(after.left - before.left), (long)(after.top - before.top));
    before = after;
    SetRect(&scroll, 100, 0, 200, 100);
    SetRect(&expect, 100, 0, 200, 15);
    scroll_ex(0, 15, &scroll, NULL, SW_INVALIDATE | SW_SCROLLCHILDREN, &expect, "(100,0)-(200,15)",
              "0, 15, (100,0)-(200,100) (not the child's), NULL, SW_INVALIDATE | SW_SCROLLCHILDREN");
    GetWindowRect(child, &after);
    line("  the child moved by (%ld,%ld)", (long)(after.left - before.left), (long)(after.top - before.top));
    DestroyWindow(child);
    drain();

    /* ScrollWindow. */
    ValidateRect(ex_window, NULL);
    arm();
    b = ScrollWindow(ex_window, 0, -10, NULL, NULL);
    line("ScrollWindow(0, -10, NULL, NULL): ret=%d err=%s", b, le());
    b = GetUpdateRect(ex_window, &after, FALSE);
    SetRect(&expect, 0, 90, 200, 100);
    line("  the window's update region (0,90)-(200,100): %s", yesno(b && EqualRect(&after, &expect)));
    drain();

    /* A hidden window, NULL. */
    hidden = ex_window;
    ShowWindow(hidden, SW_HIDE);
    drain();
    SetRectEmpty(&expect);
    scroll_ex(0, -10, NULL, NULL, SW_INVALIDATE, &expect, "empty", "the window hidden, 0, -10, NULL, NULL, SW_INVALIDATE");
    arm();
    r = ScrollWindowEx(NULL, 0, -10, NULL, NULL, NULL, NULL, SW_INVALIDATE);
    line("ScrollWindowEx(NULL, 0, -10): ret=%s err=%s", region_name(r), le());

    DestroyWindow(ex_window);
    drain();
    unregister_class();
}

static const section_t sections[] = {
    { "info", sec_info, F2KT_ALWAYS },
    { "added", sec_added, F2KT_ALWAYS },
    { "control", sec_control, F2KT_ALWAYS },
    { "posrange", sec_posrange, F2KT_ALWAYS },
    { "show", sec_show, F2KT_ALWAYS },
    { "enable", sec_enable, F2KT_ALWAYS },
    { "scrollex", sec_scrollex, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("scroll", sections, argc, argv);
}
