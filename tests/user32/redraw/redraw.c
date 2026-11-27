/*
 * redraw - window redrawing and window regions beyond InvalidateRgn and
 * GetUpdateRgn (gdi32/regions' update section): RedrawWindow's RDW_*
 * flags, ValidateRgn, ExcludeUpdateRgn, LockWindowUpdate, SetWindowRgn
 * and GetWindowRgn (the region's hit-testing and clipping), and
 * ScrollDC.
 *
 * The window sections use a visible top-most popup of the program's
 * own class at the screen's top-left corner, 120x90, with a child
 * 40x30 at client (10, 10), shown without activation; the procedures
 * record WM_NCPAINT, WM_ERASEBKGND and WM_PAINT (BeginPaint's fErase
 * and rcPaint as a relation to the client rectangle) per window, and
 * the records print after each step. Nothing drawn on the screen is
 * read back. ScrollDC's section scrolls a 32-bit DIB section in a
 * memory DC, read back as rows of letters.
 *
 * Regions print as their types and boxes, relative to the window or
 * the canvas; no handle prints. GetWindowRgnBox is Windows XP's and
 * not called.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   redraw    RedrawWindow with RDW_INVALIDATE (a rectangle, a region,
 *             the whole window), RDW_ERASE, RDW_FRAME, RDW_INTERNALPAINT,
 *             RDW_VALIDATE | RDW_NOINTERNALPAINT, RDW_UPDATENOW and
 *             RDW_ERASENOW (the messages before the return),
 *             RDW_ALLCHILDREN and RDW_NOCHILDREN (the child's update),
 *             RDW_NOERASE, RDW_NOFRAME; the update region after each
 *             and the messages a pump then brings; flags 0; a NULL
 *             window is not called
 *   validate  ValidateRgn of part of the update region, of all of it
 *             (NULL), of a region outside it, on a window with none;
 *             the update region after each; ExcludeUpdateRgn on the
 *             window's DC with an update region and without: its
 *             return and the DC's clip box after
 *   lock      LockWindowUpdate of the window: the window's DC's clip
 *             box while locked, an invalidation's WM_PAINT while
 *             locked and after the unlock; a second lock of another
 *             window; LockWindowUpdate(NULL) twice
 *   wrgn      SetWindowRgn of an elliptic region and of a rectangle:
 *             the return, GetWindowRgn's type and box and EqualRgn to
 *             a copy; the region given still a region; WindowFromPoint
 *             inside the window's rectangle and outside the region;
 *             the window DC's clip box; the messages SetWindowRgn
 *             brings with bRedraw TRUE and FALSE; SetWindowRgn(NULL);
 *             GetWindowRgn of a window with no region; a destroyed
 *             window
 *   scrolldc  ScrollDC of a striped 16x6 canvas: by (4, 0) and (-3, 2)
 *             over all of it, with a scroll rectangle, with a clip
 *             rectangle; the rows, the update rectangle and region; a
 *             scroll of (0, 0)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat redraw):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% redraw.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

static HWND top, child, other;

/* --- the log ----------------------------------------------------------- */

#define LOG_MAX 32
static char log_lines[LOG_MAX][96];
static int log_count;

static void note(const char *fmt, ...)
{
    va_list ap;

    if (log_count == LOG_MAX) {
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

    line("%s: %d message(s)", what, log_count);
    for (i = 0; i < log_count; i++) {
        line("  %s", log_lines[i]);
    }
    log_count = 0;
}

static const char *who(HWND h)
{
    return h == top ? "the window" : h == child ? "the child" : h == other ? "the other window" : "another";
}

static const char *paint_rect(HWND h, const RECT *r)
{
    static char b[2][64];
    static int n;
    char *s = b[n++ & 1];
    RECT c;

    GetClientRect(h, &c);
    if (IsRectEmpty(r)) {
        return "empty";
    }
    if (EqualRect(r, &c)) {
        return "the client area";
    }
    sprintf(s, "(%ld,%ld)-(%ld,%ld)", r->left, r->top, r->right, r->bottom);
    return s;
}

static LRESULT CALLBACK redraw_proc(HWND h, UINT msg, WPARAM wparam, LPARAM lparam)
{
    PAINTSTRUCT ps;
    LRESULT r;

    switch (msg) {
    case WM_NCPAINT:
        note("%s: WM_NCPAINT", who(h));
        break;
    case WM_ERASEBKGND:
        note("%s: WM_ERASEBKGND", who(h));
        return 1;
    case WM_PAINT:
        BeginPaint(h, &ps);
        note("%s: WM_PAINT, fErase %d, rcPaint %s", who(h), ps.fErase, paint_rect(h, &ps.rcPaint));
        EndPaint(h, &ps);
        return 0;
    case WM_WINDOWPOSCHANGING:
        note("%s: WM_WINDOWPOSCHANGING", who(h));
        break;
    case WM_WINDOWPOSCHANGED:
        note("%s: WM_WINDOWPOSCHANGED", who(h));
        break;
    case WM_NCCALCSIZE:
        note("%s: WM_NCCALCSIZE", who(h));
        break;
    }
    r = DefWindowProcW(h, msg, wparam, lparam);
    return r;
}

static void pump(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
}

static void setup(void)
{
    static BOOL registered;
    WNDCLASSW wc;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = redraw_proc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"F2KRedraw";
        registered = RegisterClassW(&wc) != 0;
    }
    top = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"F2KRedraw", L"redraw", WS_POPUP | WS_BORDER, 0, 0, 120,
                          90, NULL, NULL, GetModuleHandleA(NULL), NULL);
    child = CreateWindowExW(0, L"F2KRedraw", L"child", WS_CHILD | WS_VISIBLE, 10, 10, 40, 30, top, NULL,
                            GetModuleHandleA(NULL), NULL);
    line("setup: the window and its child created: %s", yesno(top != NULL && child != NULL));
    ShowWindow(top, SW_SHOWNA);
    UpdateWindow(top);
    pump();
    log_count = 0;
}

static void teardown(void)
{
    DestroyWindow(top);
    if (other != NULL) {
        DestroyWindow(other);
    }
    top = child = other = NULL;
    pump();
    log_count = 0;
}

static const char *rtype(int t)
{
    switch (t) {
    case ERROR: return "ERROR";
    case NULLREGION: return "NULLREGION";
    case SIMPLEREGION: return "SIMPLEREGION";
    case COMPLEXREGION: return "COMPLEXREGION";
    }
    return "?";
}

/* The update region of a window: its type and box. */
static void update_of(const char *what, HWND h)
{
    HRGN r = CreateRectRgn(0, 0, 0, 0);
    RECT box;
    int t;

    t = GetUpdateRgn(h, r, FALSE);
    GetRgnBox(r, &box);
    if (t == SIMPLEREGION || t == COMPLEXREGION) {
        line("%s: %s's update region %s, box %s", what, who(h), rtype(t), paint_rect(h, &box));
    } else {
        line("%s: %s's update region %s", what, who(h), rtype(t));
    }
    DeleteObject(r);
}

/* --- redraw ------------------------------------------------------------ */

static void rdw(const char *what, const RECT *rc, HRGN rgn, UINT flags)
{
    BOOL r;

    log_count = 0;
    arm();
    r = RedrawWindow(top, rc, rgn, flags);
    line("RedrawWindow(%s): ret=%d err=%s", what, r, le());
    print_log("  before it returned");
    update_of("  then", top);
    update_of("  then", child);
    pump();
    print_log("  a pump then");
}

static void sec_redraw(void)
{
    RECT rc;
    HRGN rgn;

    setup();
    SetRect(&rc, 60, 40, 80, 60);
    rgn = CreateRectRgn(70, 5, 100, 25);
    rdw("RDW_INVALIDATE, a rectangle outside the child", &rc, NULL, RDW_INVALIDATE);
    rdw("RDW_INVALIDATE | RDW_ERASE, a region", NULL, rgn, RDW_INVALIDATE | RDW_ERASE);
    rdw("RDW_INVALIDATE | RDW_ERASE, all", NULL, NULL, RDW_INVALIDATE | RDW_ERASE);
    rdw("RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN, all", NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
    rdw("RDW_INVALIDATE | RDW_NOCHILDREN, all", NULL, NULL, RDW_INVALIDATE | RDW_NOCHILDREN);
    rdw("RDW_INVALIDATE | RDW_FRAME, all", NULL, NULL, RDW_INVALIDATE | RDW_FRAME);
    rdw("RDW_INVALIDATE | RDW_NOFRAME, all", NULL, NULL, RDW_INVALIDATE | RDW_NOFRAME);
    rdw("RDW_INTERNALPAINT", NULL, NULL, RDW_INTERNALPAINT);
    RedrawWindow(top, NULL, NULL, RDW_INVALIDATE | RDW_INTERNALPAINT);
    rdw("RDW_VALIDATE | RDW_NOINTERNALPAINT after RDW_INVALIDATE | RDW_INTERNALPAINT", NULL, NULL,
        RDW_VALIDATE | RDW_NOINTERNALPAINT);
    rdw("RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW, all", NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW);
    rdw("RDW_INVALIDATE | RDW_ERASE | RDW_ERASENOW, all", NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ERASENOW);
    rdw("RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW", NULL, NULL,
        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
    RedrawWindow(top, NULL, NULL, RDW_INVALIDATE | RDW_ERASE);
    rdw("RDW_NOERASE after RDW_INVALIDATE | RDW_ERASE", NULL, NULL, RDW_NOERASE);
    RedrawWindow(top, NULL, NULL, RDW_INVALIDATE);
    rdw("RDW_VALIDATE, a rectangle, after RDW_INVALIDATE", &rc, NULL, RDW_VALIDATE);
    rdw("0", NULL, NULL, 0);
    DeleteObject(rgn);
    teardown();
}

/* --- validate ---------------------------------------------------------- */

static void vrgn(const char *what, HRGN r)
{
    BOOL rv;

    arm();
    rv = ValidateRgn(top, r);
    line("ValidateRgn(%s): ret=%d err=%s", what, rv, le());
    update_of("  then", top);
}

static void exclude(const char *what)
{
    HDC dc = GetDC(top);
    int t;
    RECT box;

    arm();
    t = ExcludeUpdateRgn(dc, top);
    GetClipBox(dc, &box);
    line("ExcludeUpdateRgn(the window's DC, %s): %s err=%s, the DC's clip box %s", what, rtype(t), le(),
         paint_rect(top, &box));
    ReleaseDC(top, dc);
}

static void sec_validate(void)
{
    HRGN part, outside;

    setup();
    part = CreateRectRgn(0, 0, 60, 90);
    outside = CreateRectRgn(500, 500, 510, 510);
    InvalidateRect(top, NULL, TRUE);
    update_of("InvalidateRect(all)", top);
    vrgn("the left half", part);
    vrgn("a region outside the window", outside);
    exclude("the right half invalid");
    vrgn("NULL", NULL);
    vrgn("NULL, nothing invalid", NULL);
    exclude("nothing invalid");
    arm();
    line("ValidateRgn(NULL window, NULL): ret=%d err=%s", ValidateRgn(NULL, NULL), le());
    pump();
    print_log("a pump then");
    DeleteObject(part);
    DeleteObject(outside);
    teardown();
}

/* --- lock -------------------------------------------------------------- */

static void clip_of(const char *what, HWND h)
{
    HDC dc = GetDC(h);
    RECT box;
    int t;

    t = GetClipBox(dc, &box);
    line("%s: GetDC's clip box %s %s", what, rtype(t), t == NULLREGION ? "" : paint_rect(h, &box));
    ReleaseDC(h, dc);
}

static void lock(const char *what, HWND h)
{
    BOOL r;

    arm();
    r = LockWindowUpdate(h);
    line("LockWindowUpdate(%s): ret=%d err=%s", what, r, le());
}

static void sec_lock(void)
{
    setup();
    other = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"F2KRedraw", L"other", WS_POPUP, 130, 0, 40, 30, NULL,
                            NULL, GetModuleHandleA(NULL), NULL);
    ShowWindow(other, SW_SHOWNA);
    pump();
    log_count = 0;
    clip_of("before", top);
    lock("the window", top);
    clip_of("locked", top);
    clip_of("locked", child);
    clip_of("locked", other);
    InvalidateRect(top, NULL, TRUE);
    UpdateWindow(top);
    pump();
    print_log("an invalidation while locked, UpdateWindow and a pump");
    update_of("  then", top);
    lock("the other window, while locked", other);
    lock("the window again", top);
    lock("NULL", NULL);
    pump();
    print_log("the unlock, a pump");
    clip_of("after", top);
    lock("NULL again", NULL);
    teardown();
}

/* --- wrgn -------------------------------------------------------------- */

static void wrgn_of(const char *what, HWND h, HRGN like)
{
    HRGN r = CreateRectRgn(0, 0, 0, 0);
    RECT box;
    int t;

    arm();
    t = GetWindowRgn(h, r);
    GetRgnBox(r, &box);
    line("GetWindowRgn(%s): %s err=%s", what, rtype(t), le());
    if (t == SIMPLEREGION || t == COMPLEXREGION) {
        line("  box (%ld,%ld)-(%ld,%ld), equal to the region set %s", box.left, box.top, box.right, box.bottom,
             like != NULL ? yesno(EqualRgn(r, like)) : "-");
    }
    DeleteObject(r);
}

static void from_point(const char *what, int x, int y)
{
    POINT p;
    HWND h;

    p.x = x;
    p.y = y;
    h = WindowFromPoint(p);
    line("WindowFromPoint(%s): %s", what, h == top ? "the window" : h == child ? "the child" : "another window");
}

static void window_clip(const char *what)
{
    HDC dc = GetWindowDC(top);
    RECT box;
    int t;

    t = GetClipBox(dc, &box);
    line("%s: GetWindowDC's clip box %s (%ld,%ld)-(%ld,%ld)", what, rtype(t), box.left, box.top, box.right, box.bottom);
    ReleaseDC(top, dc);
}

static void sec_wrgn(void)
{
    HRGN ell, copy, rect, rcopy;
    int r;
    HWND dead;

    setup();
    wrgn_of("a window with no region", top, NULL);
    window_clip("no region");
    ell = CreateEllipticRgn(0, 0, 120, 90);
    copy = CreateEllipticRgn(0, 0, 120, 90);
    log_count = 0;
    arm();
    r = SetWindowRgn(top, ell, TRUE);
    line("SetWindowRgn(an ellipse over the window, TRUE): ret=%d err=%s", r, le());
    print_log("  before it returned");
    line("  the region given is still a region: %s", yesno(GetObjectType(ell) == OBJ_REGION));
    pump();
    print_log("  a pump then");
    wrgn_of("the window", top, copy);
    from_point("the window's top-left corner, outside the ellipse", 1, 1);
    from_point("the window's centre", 60, 45);
    window_clip("the ellipse");

    rect = CreateRectRgn(0, 0, 60, 45);
    rcopy = CreateRectRgn(0, 0, 60, 45);
    log_count = 0;
    arm();
    r = SetWindowRgn(top, rect, FALSE);
    line("SetWindowRgn(the top-left quarter, FALSE): ret=%d err=%s", r, le());
    print_log("  before it returned");
    pump();
    print_log("  a pump then");
    wrgn_of("the window", top, rcopy);
    line("  the ellipse set before is still a region: %s", yesno(GetObjectType(ell) == OBJ_REGION));
    from_point("the window's centre, outside the quarter", 70, 50);
    from_point("inside the quarter", 30, 20);
    window_clip("the quarter");

    log_count = 0;
    arm();
    r = SetWindowRgn(top, NULL, TRUE);
    line("SetWindowRgn(NULL, TRUE): ret=%d err=%s", r, le());
    pump();
    print_log("  then");
    wrgn_of("the window", top, NULL);
    from_point("the window's centre", 70, 50);

    dead = CreateWindowExW(0, L"F2KRedraw", L"dead", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleA(NULL), NULL);
    DestroyWindow(dead);
    arm();
    r = SetWindowRgn(dead, NULL, FALSE);
    line("SetWindowRgn(a destroyed window, NULL): ret=%d err=%s", r, le());
    wrgn_of("a destroyed window", dead, NULL);
    DeleteObject(copy);
    DeleteObject(rcopy);
    teardown();
}

/* --- scrolldc ---------------------------------------------------------- */

typedef struct {
    HDC dc;
    HBITMAP bmp;
    HGDIOBJ old;
    DWORD *bits;
} canvas_t;

static canvas_t cv;

static int canvas_open(void)
{
    BITMAPINFO bi;
    void *p = NULL;

    cv.dc = CreateCompatibleDC(NULL);
    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = 16;
    bi.bmiHeader.biHeight = -6;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    cv.bmp = CreateDIBSection(cv.dc, &bi, DIB_RGB_COLORS, &p, NULL, 0);
    if (cv.bmp == NULL || p == NULL) {
        line("canvas: not made");
        return 0;
    }
    cv.bits = (DWORD *)p;
    cv.old = SelectObject(cv.dc, cv.bmp);
    return 1;
}

/* Columns lettered a, b, c... by x, rows by y: the pixel's value says
 * where it came from (x + 16 * y + 1). */
static void stripes(void)
{
    int x, y;

    GdiFlush();
    for (y = 0; y < 6; y++) {
        for (x = 0; x < 16; x++) {
            cv.bits[y * 16 + x] = (DWORD)(x + 16 * y + 1);
        }
    }
}

/* Each pixel as the column letter (a-p) and row digit (0-5) it was
 * drawn at, '??' for any other value; one line per row. */
static void show(void)
{
    char row[64];
    int x, y, n;
    DWORD v;

    GdiFlush();
    for (y = 0; y < 6; y++) {
        n = 0;
        for (x = 0; x < 16; x++) {
            v = cv.bits[y * 16 + x];
            if (v >= 1 && v <= 96) {
                row[n++] = (char)('a' + (v - 1) % 16);
                row[n++] = (char)('0' + (v - 1) / 16);
            } else {
                row[n++] = '?';
                row[n++] = '?';
            }
        }
        row[n] = '\0';
        line("  row %d: %s", y, row);
    }
}

static void scroll(const char *what, int dx, int dy, const RECT *scr, const RECT *clip)
{
    HRGN upd = CreateRectRgn(0, 0, 0, 0);
    RECT ur, box;
    BOOL r;
    int t;

    stripes();
    SetRect(&ur, -1, -1, -1, -1);
    arm();
    r = ScrollDC(cv.dc, dx, dy, scr, clip, upd, &ur);
    t = GetRgnBox(upd, &box);
    line("ScrollDC(%s): ret=%d err=%s", what, r, le());
    line("  the update rectangle (%ld,%ld)-(%ld,%ld); the region %s (%ld,%ld)-(%ld,%ld)", ur.left, ur.top, ur.right,
         ur.bottom, rtype(t), box.left, box.top, box.right, box.bottom);
    show();
    DeleteObject(upd);
}

static void sec_scrolldc(void)
{
    RECT scr, clip;
    BOOL r;

    if (!canvas_open()) {
        return;
    }
    line("each pixel prints as the column letter and row digit it was drawn at");
    scroll("dx 4, dy 0, all of it", 4, 0, NULL, NULL);
    scroll("dx -3, dy 2, all of it", -3, 2, NULL, NULL);
    SetRect(&scr, 2, 1, 10, 5);
    scroll("dx 2, dy 1, the scroll rectangle (2,1)-(10,5)", 2, 1, &scr, NULL);
    SetRect(&clip, 0, 0, 8, 6);
    scroll("dx 4, dy 0, the clip rectangle (0,0)-(8,6)", 4, 0, NULL, &clip);
    scroll("dx 4, dy 0, the scroll rectangle (2,1)-(10,5), the clip rectangle (0,0)-(8,6)", 4, 0, &scr, &clip);
    scroll("dx 0, dy 0", 0, 0, NULL, NULL);
    arm();
    r = ScrollDC(cv.dc, 1, 0, NULL, NULL, NULL, NULL);
    line("ScrollDC(dx 1, no update region or rectangle): ret=%d err=%s", r, le());
    SelectObject(cv.dc, cv.old);
    DeleteObject(cv.bmp);
    DeleteDC(cv.dc);
}

static const section_t sections[] = {
    { "redraw", sec_redraw, F2KT_ALWAYS },
    { "validate", sec_validate, F2KT_ALWAYS },
    { "lock", sec_lock, F2KT_ALWAYS },
    { "wrgn", sec_wrgn, F2KT_ALWAYS },
    { "scrolldc", sec_scrolldc, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("redraw", sections, argc, argv);
}
