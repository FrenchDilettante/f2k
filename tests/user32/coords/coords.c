/*
 * coords - window coordinates in user32: GetClientRect and
 * GetWindowRect, MapWindowPoints, ScreenToClient and ClientToScreen,
 * ChildWindowFromPoint and ChildWindowFromPointEx, IsChild, OffsetRect,
 * and CharNextA/W and CharPrevA/W; then the non-client area: the frame
 * and caption metrics, AdjustWindowRect and AdjustWindowRectEx, the
 * client areas windows of each frame style get, the default window
 * procedure's WM_NCCALCSIZE and WM_NCHITTEST.
 *
 * The windows: a hidden WS_POPUP top-level window with no border at
 * screen (200,150), 300x200, so its client area is its window and every
 * coordinate it and its children give is fixed and prints as is. Its
 * children, at client positions:
 *
 *   child1      (10,20)   50x30, visible, id 1
 *   child2      (100,20)  60x40, visible, id 2
 *   grandchild  (5,5)     20x10 in child2, visible, id 5
 *   hidden      (10,100)  40x40, without WS_VISIBLE, id 3
 *   disabled    (100,100) 40x40, visible and WS_DISABLED, id 4
 *
 * A window with a frame or a caption sits where its frame's metrics put
 * it, which a machine's settings may change: those windows print only
 * their client area's offset and size less what the metrics account
 * for, never the values themselves. The non-client sections are the
 * exception: they are about those metrics, so adjust prints them, and
 * adjust, frames, nccalc and nchittest print sizes and offsets in
 * pixels, as the capture machine's standard scheme at 96 DPI gives
 * them. Their frame styles (WS_EX_DLGMODALFRAME with a caption is what
 * a DS_MODALFRAME dialog template gives its window):
 *
 *   WS_OVERLAPPEDWINDOW; WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
 *   (calc's); WS_POPUP | WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME;
 *   WS_POPUP | WS_BORDER; WS_POPUP; WS_POPUP | WS_DLGFRAME; WS_POPUP |
 *   WS_THICKFRAME; WS_CHILD | WS_BORDER; WS_CHILD, WS_EX_CLIENTEDGE;
 *   WS_OVERLAPPEDWINDOW, WS_EX_CLIENTEDGE; WS_POPUP, WS_EX_STATICEDGE;
 *   WS_CAPTION | WS_SYSMENU, WS_EX_TOOLWINDOW; WS_OVERLAPPED alone;
 *   WS_CAPTION | WS_VSCROLL | WS_HSCROLL; WS_CHILD | WS_CAPTION
 *
 * Their children sit in a hidden WS_POPUP parent with no border at
 * screen (0,0), 400x300; their windows are hidden, at (60,70),
 * 240x160, but nchittest's, shown at (100,80), 300x200.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed: a window prints by its label above ("parent",
 * "NULL", "other" for any other), a character pointer as its offset in
 * its string; every call under observation is armed with the last-error
 * sentinel and its line prints ret= and err=. Each section registers
 * the class (once per process), creates the windows and destroys them
 * at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   client    GetClientRect and GetWindowRect of the parent, child1,
 *             the grandchild and the hidden child, GetClientRect(NULL);
 *             a WS_POPUP | WS_BORDER window and a WS_OVERLAPPED |
 *             WS_CAPTION one: the client origin's offset from the
 *             window's (ClientToScreen) and the client size's shortfall,
 *             each less the border or the fixed frame and caption
 *             metrics
 *   map       MapWindowPoints child to parent, parent to child, the
 *             grandchild to the parent, the hidden child to the parent,
 *             a window to the screen (NULL) and back, a window to
 *             itself, a RECT as two points between siblings, a
 *             destroyed window: the points and the return's two signed
 *             16-bit halves
 *   screen    ScreenToClient and ClientToScreen on the children and the
 *             parent, NULL and a destroyed window
 *   childpt   ChildWindowFromPoint and ChildWindowFromPointEx (CWP_ALL,
 *             CWP_SKIPINVISIBLE, CWP_SKIPDISABLED, both) at points in
 *             each child, the grandchild, the parent alone, the edges,
 *             and outside, with the parent shown (SW_SHOWNA); one point
 *             with the parent still hidden; from child2 to the
 *             grandchild; NULL
 *   ischild   IsChild for a child, the grandchild, siblings, the window
 *             itself, the parent of its parent, NULL
 *   rect      OffsetRect by positive, negative and zero offsets, and on
 *             an inverted rectangle
 *   charnext  CharNextA/W walked from a string's start to its end, and
 *             CharPrevA/W from its end to its start, as offsets: "abc",
 *             the empty string, and in W "e" + U+0301 + "x", U+0301 +
 *             "x", "a" + U+0300 + U+0301 + "b" and a surrogate pair
 *   adjust    GetSystemMetrics of the border, frame, edge, caption,
 *             menu, caption-button, menu-check, small-icon and minimum
 *             sizes; AdjustWindowRectEx over (100,100)-(300,250) for
 *             each frame style, with a menu too for
 *             WS_OVERLAPPEDWINDOW, calc's style, the modal frame and
 *             the captioned child; AdjustWindowRect for
 *             WS_OVERLAPPEDWINDOW with and without a menu: the
 *             result's deltas from the rectangle given
 *   frames    a window of each frame style: its window and client
 *             sizes, the client origin's offset from the window's,
 *             whether it has a caption (WS_OVERLAPPED gets one), and
 *             whether AdjustWindowRectEx of its client rectangle gives
 *             back its window rectangle
 *   nccalc    WM_NCCALCSIZE sent (to DefWindowProcA) to a window of
 *             five styles: wParam FALSE with the window's rectangle
 *             and with (0,0)-(100,50), wParam TRUE with an
 *             NCCALCSIZE_PARAMS holding the window's rectangle twice,
 *             the client's and a WINDOWPOS: the answer and each
 *             rectangle's deltas from what was put in
 *   nchittest WM_NCHITTEST sent (to DefWindowProcW) to a visible
 *             window of five styles at (100,80), 300x200, along the
 *             caption's middle row, the top row, the middle column,
 *             the left column and the bottom row, each from 2 pixels
 *             outside the window to 2 outside it: the runs of equal
 *             answers, as offsets from the scan's start, and the codes
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat coords):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% coords.c user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate these. */
#ifndef CWP_ALL
#define CWP_ALL 0x0000
#endif
#ifndef CWP_SKIPINVISIBLE
#define CWP_SKIPINVISIBLE 0x0001
#endif
#ifndef CWP_SKIPDISABLED
#define CWP_SKIPDISABLED 0x0002
#endif
#ifndef SM_CXFIXEDFRAME
#define SM_CXFIXEDFRAME SM_CXDLGFRAME
#endif
#ifndef SM_CYFIXEDFRAME
#define SM_CYFIXEDFRAME SM_CYDLGFRAME
#endif
#ifndef HTCLOSE
#define HTCLOSE 20
#endif
#ifndef HTHELP
#define HTHELP 21
#endif

#define CLASS_NAME "F2KCoordsWin"

static HWND parent, child1, child2, grandchild, hidden, disabled;
/* A window created and destroyed again: its handle names no window. */
static HWND dead;

static LRESULT CALLBACK plain(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

static const char *label(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == parent) {
        return "parent";
    }
    if (h == child1) {
        return "child1";
    }
    if (h == child2) {
        return "child2";
    }
    if (h == grandchild) {
        return "grandchild";
    }
    if (h == hidden) {
        return "hidden";
    }
    if (h == disabled) {
        return "disabled";
    }
    if (h == dead) {
        return "dead";
    }
    return "other";
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* Register the class once per process. */
static BOOL register_class(void)
{
    static BOOL registered;
    WNDCLASSA wc;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = plain;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = CLASS_NAME;
        registered = RegisterClassA(&wc) != 0;
    }
    return registered;
}

static HWND make(HWND owner, DWORD style, int x, int y, int cx, int cy, int id)
{
    return CreateWindowExA(0, CLASS_NAME, "coords", style, x, y, cx, cy, owner,
                           (HMENU)id, GetModuleHandleA(NULL), NULL);
}

/* The parent and its children, as the header lists them; and the dead
 * handle. */
static void make_tree(void)
{
    BOOL ok;

    drain();
    ok = register_class();
    parent = make(NULL, WS_POPUP, 200, 150, 300, 200, 0);
    child1 = make(parent, WS_CHILD | WS_VISIBLE, 10, 20, 50, 30, 1);
    child2 = make(parent, WS_CHILD | WS_VISIBLE, 100, 20, 60, 40, 2);
    grandchild = make(child2, WS_CHILD | WS_VISIBLE, 5, 5, 20, 10, 5);
    hidden = make(parent, WS_CHILD, 10, 100, 40, 40, 3);
    disabled = make(parent, WS_CHILD | WS_VISIBLE | WS_DISABLED, 100, 100, 40, 40, 4);
    dead = make(NULL, WS_POPUP, 0, 0, 10, 10, 0);
    if (dead != NULL) {
        DestroyWindow(dead);
    }
    line("setup: the class, the parent, its children and the grandchild created: %s",
         yesno(ok && parent != NULL && child1 != NULL && child2 != NULL && grandchild != NULL
               && hidden != NULL && disabled != NULL && dead != NULL));
}

static void destroy_tree(void)
{
    if (parent != NULL) {
        DestroyWindow(parent);
    }
}

static void print_rect(const char *what, BOOL r, const RECT *rc)
{
    const char *e = le();

    line("%s: ret=%d err=%s rect=(%ld,%ld)-(%ld,%ld)", what, r, e, rc->left, rc->top, rc->right,
         rc->bottom);
}

/* --- client -------------------------------------------------------- */

static void client_rect(const char *name, HWND h)
{
    RECT rc;
    BOOL r;
    char what[64];

    rc.left = rc.top = rc.right = rc.bottom = -1;
    sprintf(what, "GetClientRect(%s)", name);
    arm();
    r = GetClientRect(h, &rc);
    print_rect(what, r, &rc);
}

static void window_rect(const char *name, HWND h)
{
    RECT rc;
    BOOL r;
    char what[64];

    rc.left = rc.top = rc.right = rc.bottom = -1;
    sprintf(what, "GetWindowRect(%s)", name);
    arm();
    r = GetWindowRect(h, &rc);
    print_rect(what, r, &rc);
}

/* A framed window's client area against its window, less the frame
 * (fx, fy on each side) and the caption (cap, above the client). */
static void framed(const char *name, DWORD style, int fx, int fy, int cap)
{
    HWND h;
    RECT wr, cr;
    POINT origin;
    BOOL r1, r2, r3;
    DWORD e1, e2, e3;

    h = CreateWindowExA(0, CLASS_NAME, "coords", style, 60, 70, 240, 160, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    line("CreateWindowExA(%s, hidden, 240x160): non-NULL %s", name, yesno(h != NULL));
    arm();
    r1 = GetWindowRect(h, &wr);
    e1 = GetLastError();
    arm();
    r2 = GetClientRect(h, &cr);
    e2 = GetLastError();
    origin.x = 0;
    origin.y = 0;
    arm();
    r3 = ClientToScreen(h, &origin);
    e3 = GetLastError();
    line("  GetWindowRect ret=%d err=%s, GetClientRect ret=%d err=%s, ClientToScreen ret=%d err=%s",
         r1, le_of(e1), r2, le_of(e2), r3, le_of(e3));
    line("  GetClientRect's origin: (%ld,%ld)", cr.left, cr.top);
    line("  the client origin's offset less the frame and caption: (%ld,%ld)",
         origin.x - wr.left - fx, origin.y - wr.top - fy - cap);
    line("  the client size's shortfall less the frame and caption: (%ld,%ld)",
         (wr.right - wr.left) - (cr.right - cr.left) - 2 * fx,
         (wr.bottom - wr.top) - (cr.bottom - cr.top) - 2 * fy - cap);
    if (h != NULL) {
        DestroyWindow(h);
    }
}

static void sec_client(void)
{
    RECT rc;
    BOOL r;

    make_tree();
    client_rect("parent", parent);
    client_rect("child1", child1);
    client_rect("grandchild", grandchild);
    client_rect("hidden", hidden);
    window_rect("parent", parent);
    window_rect("child1", child1);
    window_rect("grandchild", grandchild);
    window_rect("hidden", hidden);
    window_rect("disabled", disabled);

    rc.left = rc.top = rc.right = rc.bottom = -1;
    arm();
    r = GetClientRect(NULL, &rc);
    print_rect("GetClientRect(NULL)", r, &rc);
    rc.left = rc.top = rc.right = rc.bottom = -1;
    arm();
    r = GetWindowRect(dead, &rc);
    print_rect("GetWindowRect(a destroyed window)", r, &rc);

    framed("WS_POPUP | WS_BORDER", WS_POPUP | WS_BORDER, GetSystemMetrics(SM_CXBORDER),
           GetSystemMetrics(SM_CYBORDER), 0);
    framed("WS_OVERLAPPED | WS_CAPTION", WS_OVERLAPPED | WS_CAPTION,
           GetSystemMetrics(SM_CXFIXEDFRAME), GetSystemMetrics(SM_CYFIXEDFRAME),
           GetSystemMetrics(SM_CYCAPTION));
    destroy_tree();
}

/* --- map ----------------------------------------------------------- */

static void map_one(const char *from_name, HWND from, const char *to_name, HWND to, LONG x, LONG y)
{
    POINT pt;
    int r;

    pt.x = x;
    pt.y = y;
    arm();
    r = MapWindowPoints(from, to, &pt, 1);
    line("MapWindowPoints(%s, %s, (%ld,%ld)): ret=(%d,%d) err=%s point=(%ld,%ld)", from_name,
         to_name, x, y, (int)(short)LOWORD(r), (int)(short)HIWORD(r), le(), pt.x, pt.y);
}

static void sec_map(void)
{
    RECT rc;
    int r;

    make_tree();
    map_one("child1", child1, "parent", parent, 0, 0);
    map_one("parent", parent, "child1", child1, 15, 25);
    map_one("grandchild", grandchild, "parent", parent, 1, 1);
    map_one("hidden", hidden, "parent", parent, 0, 0);
    map_one("parent", parent, "NULL", NULL, 0, 0);
    map_one("child1", child1, "NULL", NULL, 3, 4);
    map_one("NULL", NULL, "child1", child1, 215, 175);
    map_one("NULL", NULL, "grandchild", grandchild, 0, 0);
    map_one("child1", child1, "child1", child1, 3, 4);
    map_one("NULL", NULL, "NULL", NULL, 3, 4);
    map_one("a destroyed window", dead, "parent", parent, 0, 0);
    map_one("parent", parent, "a destroyed window", dead, 0, 0);

    rc.left = 0;
    rc.top = 0;
    rc.right = 50;
    rc.bottom = 30;
    arm();
    r = MapWindowPoints(child1, child2, (LPPOINT)&rc, 2);
    line("MapWindowPoints(child1, child2, RECT (0,0)-(50,30) as 2 points): ret=(%d,%d) err=%s "
         "rect=(%ld,%ld)-(%ld,%ld)",
         (int)(short)LOWORD(r), (int)(short)HIWORD(r), le(), rc.left, rc.top, rc.right, rc.bottom);
    destroy_tree();
}

/* --- screen -------------------------------------------------------- */

static void to_client(const char *name, HWND h, LONG x, LONG y)
{
    POINT pt;
    BOOL r;

    pt.x = x;
    pt.y = y;
    arm();
    r = ScreenToClient(h, &pt);
    line("ScreenToClient(%s, (%ld,%ld)): ret=%d err=%s point=(%ld,%ld)", name, x, y, r, le(), pt.x,
         pt.y);
}

static void to_screen(const char *name, HWND h, LONG x, LONG y)
{
    POINT pt;
    BOOL r;

    pt.x = x;
    pt.y = y;
    arm();
    r = ClientToScreen(h, &pt);
    line("ClientToScreen(%s, (%ld,%ld)): ret=%d err=%s point=(%ld,%ld)", name, x, y, r, le(), pt.x,
         pt.y);
}

static void sec_screen(void)
{
    make_tree();
    to_client("child1", child1, 215, 175);
    to_client("parent", parent, 0, 0);
    to_client("grandchild", grandchild, 305, 175);
    to_client("hidden", hidden, 210, 250);
    to_client("NULL", NULL, 10, 10);
    to_client("a destroyed window", dead, 10, 10);
    to_screen("child2", child2, 1, 2);
    to_screen("grandchild", grandchild, 0, 0);
    to_screen("parent", parent, -10, -20);
    to_screen("disabled", disabled, 0, 0);
    to_screen("NULL", NULL, 10, 10);
    to_screen("a destroyed window", dead, 10, 10);
    destroy_tree();
}

/* --- childpt ------------------------------------------------------- */

typedef struct {
    const char *what;
    LONG x, y;
} spot_t;

static const spot_t spots[] = {
    { "in child1", 15, 25 },
    { "in child2", 105, 40 },
    { "in the grandchild", 107, 27 },
    { "in the hidden child", 15, 105 },
    { "in the disabled child", 105, 105 },
    { "in the parent alone", 250, 180 },
    { "child1's top-left corner", 10, 20 },
    { "child1's bottom-right corner", 59, 49 },
    { "just past child1's right edge", 60, 25 },
    { "the parent's bottom-right corner", 299, 199 },
    { "outside, left", -5, 10 },
    { "outside, right", 300, 10 },
    { "outside, below", 10, 200 },
    { NULL, 0, 0 }
};

static void child_at(const char *name, HWND h, const spot_t *s)
{
    POINT pt;
    HWND r0, r1, r2, r3, r4;
    DWORD e0, e1, e2, e3, e4;

    pt.x = s->x;
    pt.y = s->y;
    arm();
    r0 = ChildWindowFromPoint(h, pt);
    e0 = GetLastError();
    arm();
    r1 = ChildWindowFromPointEx(h, pt, CWP_ALL);
    e1 = GetLastError();
    arm();
    r2 = ChildWindowFromPointEx(h, pt, CWP_SKIPINVISIBLE);
    e2 = GetLastError();
    arm();
    r3 = ChildWindowFromPointEx(h, pt, CWP_SKIPDISABLED);
    e3 = GetLastError();
    arm();
    r4 = ChildWindowFromPointEx(h, pt, CWP_SKIPINVISIBLE | CWP_SKIPDISABLED);
    e4 = GetLastError();
    line("%s, %s (%ld,%ld): ChildWindowFromPoint %s err=%s; Ex CWP_ALL %s err=%s, "
         "CWP_SKIPINVISIBLE %s err=%s, CWP_SKIPDISABLED %s err=%s, both %s err=%s",
         name, s->what, s->x, s->y, label(r0), le_of(e0), label(r1), le_of(e1), label(r2),
         le_of(e2), label(r3), le_of(e3), label(r4), le_of(e4));
}

static void sec_childpt(void)
{
    const spot_t *s;
    spot_t in_grandchild;

    make_tree();
    line("the parent hidden:");
    child_at("parent", parent, &spots[0]);
    ShowWindow(parent, SW_SHOWNA);
    line("the parent shown (SW_SHOWNA): visible %s", yesno(IsWindowVisible(parent)));
    for (s = spots; s->what != NULL; s++) {
        child_at("parent", parent, s);
    }
    in_grandchild.what = "in the grandchild";
    in_grandchild.x = 7;
    in_grandchild.y = 7;
    child_at("child2", child2, &in_grandchild);
    child_at("NULL", NULL, &spots[0]);
    destroy_tree();
}

/* --- ischild ------------------------------------------------------- */

static void is_child(const char *pname, HWND p, const char *cname, HWND c)
{
    BOOL r;

    arm();
    r = IsChild(p, c);
    line("IsChild(%s, %s): ret=%d err=%s", pname, cname, r, le());
}

static void sec_ischild(void)
{
    make_tree();
    is_child("parent", parent, "child1", child1);
    is_child("parent", parent, "hidden", hidden);
    is_child("parent", parent, "disabled", disabled);
    is_child("parent", parent, "grandchild", grandchild);
    is_child("child2", child2, "grandchild", grandchild);
    is_child("child1", child1, "grandchild", grandchild);
    is_child("child1", child1, "child2", child2);
    is_child("child1", child1, "parent", parent);
    is_child("grandchild", grandchild, "parent", parent);
    is_child("parent", parent, "parent", parent);
    is_child("NULL", NULL, "child1", child1);
    is_child("parent", parent, "NULL", NULL);
    is_child("parent", parent, "a destroyed window", dead);
    destroy_tree();
}

/* --- rect ---------------------------------------------------------- */

static void offset(LONG l, LONG t, LONG r, LONG b, int dx, int dy)
{
    RECT rc;
    BOOL ret;
    char what[96];

    rc.left = l;
    rc.top = t;
    rc.right = r;
    rc.bottom = b;
    sprintf(what, "OffsetRect((%ld,%ld)-(%ld,%ld), %d, %d)", l, t, r, b, dx, dy);
    arm();
    ret = OffsetRect(&rc, dx, dy);
    print_rect(what, ret, &rc);
}

static void sec_rect(void)
{
    offset(1, 2, 3, 4, 5, -7);
    offset(10, 20, 30, 40, -10, 10);
    offset(10, 20, 30, 40, 0, 0);
    offset(0, 0, 0, 0, -3, -4);
    offset(5, 5, 1, 1, 2, 2);
    offset(-100, -100, 100, 100, 1000, -1000);
}

/* --- charnext ------------------------------------------------------ */

/* Walk CharNextA from the start until it stops moving (at most the
 * string's length + 2 calls), then CharPrevA from the terminator back
 * to the start: each call's offset, and the last call's error. */
static void walk_a(const char *name, const char *s)
{
    char buf[256];
    int n = 0;
    int len = (int)strlen(s);
    int i;
    const char *p;
    const char *q;
    const char *e;

    p = s;
    n += sprintf(buf + n, "%d", 0);
    e = "-";
    for (i = 0; i < len + 2; i++) {
        arm();
        q = CharNextA(p);
        e = le();
        n += sprintf(buf + n, " -> %d", (int)(q - s));
        if (q == p) {
            break;
        }
        p = q;
    }
    line("CharNextA over %s: %s err=%s", name, buf, e);

    n = 0;
    p = s + len;
    n += sprintf(buf + n, "%d", len);
    for (i = 0; i < len + 2; i++) {
        arm();
        q = CharPrevA(s, p);
        e = le();
        n += sprintf(buf + n, " -> %d", (int)(q - s));
        if (q == p) {
            break;
        }
        p = q;
    }
    line("CharPrevA over %s: %s err=%s", name, buf, e);
}

static void walk_w(const char *name, const WCHAR *s)
{
    char buf[256];
    int n = 0;
    int len = 0;
    int i;
    const WCHAR *p;
    const WCHAR *q;
    const char *e;

    while (s[len] != 0) {
        len++;
    }
    p = s;
    n += sprintf(buf + n, "%d", 0);
    e = "-";
    for (i = 0; i < len + 2; i++) {
        arm();
        q = CharNextW(p);
        e = le();
        n += sprintf(buf + n, " -> %d", (int)(q - s));
        if (q == p) {
            break;
        }
        p = q;
    }
    line("CharNextW over %s: %s err=%s", name, buf, e);

    n = 0;
    p = s + len;
    n += sprintf(buf + n, "%d", len);
    for (i = 0; i < len + 2; i++) {
        arm();
        q = CharPrevW(s, p);
        e = le();
        n += sprintf(buf + n, " -> %d", (int)(q - s));
        if (q == p) {
            break;
        }
        p = q;
    }
    line("CharPrevW over %s: %s err=%s", name, buf, e);
}

static void sec_charnext(void)
{
    static const WCHAR abc[] = { 'a', 'b', 'c', 0 };
    static const WCHAR empty[] = { 0 };
    static const WCHAR acute[] = { 'e', 0x0301, 'x', 0 };
    static const WCHAR leading[] = { 0x0301, 'x', 0 };
    static const WCHAR two[] = { 'a', 0x0300, 0x0301, 'b', 0 };
    static const WCHAR pair[] = { 'a', 0xD800, 0xDC00, 'x', 0 };

    walk_a("\"abc\"", "abc");
    walk_a("\"\"", "");
    walk_w("\"abc\"", abc);
    walk_w("\"\"", empty);
    walk_w("\"e\" U+0301 \"x\"", acute);
    walk_w("U+0301 \"x\"", leading);
    walk_w("\"a\" U+0300 U+0301 \"b\"", two);
    walk_w("\"a\" U+D800 U+DC00 \"x\"", pair);
}

/* --- the frames' styles -------------------------------------------- */

/* A style the frame sections try: its name as printed, the style and
 * the extended style, and whether adjust tries it with a menu too. */
typedef struct {
    const char *name;
    DWORD style;
    DWORD ex;
    int menu_too;
} frame_style;

static const frame_style frame_styles[] = {
    { "WS_OVERLAPPEDWINDOW", WS_OVERLAPPEDWINDOW, 0, 1 },
    { "WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX", WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 0, 1 },
    { "WS_POPUP | WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME", WS_POPUP | WS_CAPTION | WS_SYSMENU,
      WS_EX_DLGMODALFRAME, 1 },
    { "WS_POPUP | WS_BORDER", WS_POPUP | WS_BORDER, 0, 0 },
    { "WS_POPUP", WS_POPUP, 0, 0 },
    { "WS_POPUP | WS_DLGFRAME", WS_POPUP | WS_DLGFRAME, 0, 0 },
    { "WS_POPUP | WS_THICKFRAME", WS_POPUP | WS_THICKFRAME, 0, 0 },
    { "WS_CHILD | WS_BORDER", WS_CHILD | WS_BORDER, 0, 0 },
    { "WS_CHILD, WS_EX_CLIENTEDGE", WS_CHILD, WS_EX_CLIENTEDGE, 0 },
    { "WS_OVERLAPPEDWINDOW, WS_EX_CLIENTEDGE", WS_OVERLAPPEDWINDOW, WS_EX_CLIENTEDGE, 0 },
    { "WS_POPUP, WS_EX_STATICEDGE", WS_POPUP, WS_EX_STATICEDGE, 0 },
    { "WS_CAPTION | WS_SYSMENU, WS_EX_TOOLWINDOW", WS_CAPTION | WS_SYSMENU, WS_EX_TOOLWINDOW, 0 },
    { "WS_OVERLAPPED", WS_OVERLAPPED, 0, 0 },
    { "WS_CAPTION | WS_VSCROLL | WS_HSCROLL", WS_CAPTION | WS_VSCROLL | WS_HSCROLL, 0, 0 },
    { "WS_CHILD | WS_CAPTION", WS_CHILD | WS_CAPTION, 0, 1 },
    { NULL, 0, 0, 0 }
};

/* The hidden WS_POPUP window the frame sections' children sit in, at
 * screen (0,0), 400x300, with no border. */
static HWND frame_parent;

static void make_frame_parent(void)
{
    drain();
    frame_parent = NULL;
    if (register_class()) {
        frame_parent = CreateWindowExA(0, CLASS_NAME, "coords", WS_POPUP, 0, 0, 400, 300, NULL, NULL,
                                       GetModuleHandleA(NULL), NULL);
    }
    line("setup: the class and the children's parent created: %s", yesno(frame_parent != NULL));
}

static void destroy_frame_parent(void)
{
    if (frame_parent != NULL) {
        DestroyWindow(frame_parent);
        frame_parent = NULL;
    }
    drain();
}

/* A hidden window of a frame style at (60,70), 240x160: a child of
 * the frame parent for a WS_CHILD style. */
static HWND make_framed(const frame_style *s)
{
    return CreateWindowExA(s->ex, CLASS_NAME, "coords", s->style, 60, 70, 240, 160,
                           (s->style & WS_CHILD) ? frame_parent : NULL, NULL, GetModuleHandleA(NULL),
                           NULL);
}

/* --- adjust -------------------------------------------------------- */

/* A metric, printed by its name. */
#define METRIC(m) line("GetSystemMetrics(" #m "): %d", GetSystemMetrics(m))

/* AdjustWindowRectEx over (100,100)-(300,250), printed as the result's
 * deltas from it. */
static void adjust_one(const frame_style *s, BOOL menu)
{
    RECT r;
    BOOL ok;

    SetRect(&r, 100, 100, 300, 250);
    arm();
    ok = AdjustWindowRectEx(&r, s->style, menu, s->ex);
    line("AdjustWindowRectEx(%s, menu %s): ret=%d err=%s deltas (%ld,%ld,%ld,%ld)", s->name,
         menu ? "TRUE" : "FALSE", ok, le(), r.left - 100, r.top - 100, r.right - 300,
         r.bottom - 250);
}

static void sec_adjust(void)
{
    const frame_style *s;
    RECT r;
    BOOL ok;
    int menu;

    METRIC(SM_CXBORDER);
    METRIC(SM_CYBORDER);
    METRIC(SM_CXDLGFRAME);
    METRIC(SM_CYDLGFRAME);
    METRIC(SM_CXFRAME);
    METRIC(SM_CYFRAME);
    METRIC(SM_CXEDGE);
    METRIC(SM_CYEDGE);
    METRIC(SM_CYCAPTION);
    METRIC(SM_CYSMCAPTION);
    METRIC(SM_CYMENU);
    METRIC(SM_CXSIZE);
    METRIC(SM_CYSIZE);
    METRIC(SM_CXSMSIZE);
    METRIC(SM_CYSMSIZE);
    METRIC(SM_CXMENUSIZE);
    METRIC(SM_CYMENUSIZE);
    METRIC(SM_CXMENUCHECK);
    METRIC(SM_CYMENUCHECK);
    METRIC(SM_CXSMICON);
    METRIC(SM_CYSMICON);
    METRIC(SM_CXMIN);
    METRIC(SM_CYMIN);
    METRIC(SM_CXMINTRACK);
    METRIC(SM_CYMINTRACK);

    for (s = frame_styles; s->name != NULL; s++) {
        adjust_one(s, FALSE);
        if (s->menu_too) {
            adjust_one(s, TRUE);
        }
    }
    for (menu = 0; menu < 2; menu++) {
        SetRect(&r, 100, 100, 300, 250);
        arm();
        ok = AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, menu);
        line("AdjustWindowRect(WS_OVERLAPPEDWINDOW, menu %s): ret=%d err=%s deltas (%ld,%ld,%ld,%ld)",
             menu ? "TRUE" : "FALSE", ok, le(), r.left - 100, r.top - 100, r.right - 300,
             r.bottom - 250);
    }
}

/* --- frames -------------------------------------------------------- */

static void sec_frames(void)
{
    const frame_style *s;
    HWND h;
    RECT wr, cr, adjusted;
    POINT origin;
    DWORD style;

    make_frame_parent();
    for (s = frame_styles; s->name != NULL; s++) {
        h = make_framed(s);
        line("CreateWindowExA(%s, hidden, 240x160): non-NULL %s", s->name, yesno(h != NULL));
        if (h == NULL) {
            continue;
        }
        GetWindowRect(h, &wr);
        GetClientRect(h, &cr);
        origin.x = 0;
        origin.y = 0;
        ClientToScreen(h, &origin);
        style = (DWORD)GetWindowLongA(h, GWL_STYLE);
        line("  window %ldx%ld, client %ldx%ld, the client origin's offset (%ld,%ld), captioned: %s",
             wr.right - wr.left, wr.bottom - wr.top, cr.right, cr.bottom, origin.x - wr.left,
             origin.y - wr.top, yesno((style & WS_CAPTION) == WS_CAPTION));
        adjusted.left = origin.x;
        adjusted.top = origin.y;
        adjusted.right = origin.x + cr.right;
        adjusted.bottom = origin.y + cr.bottom;
        AdjustWindowRectEx(&adjusted, style, FALSE, (DWORD)GetWindowLongA(h, GWL_EXSTYLE));
        line("  AdjustWindowRectEx of the client: the window's rect: %s",
             yesno(EqualRect(&adjusted, &wr)));
        DestroyWindow(h);
    }
    destroy_frame_parent();
}

/* --- nccalc -------------------------------------------------------- */

/* A rectangle's deltas from the one put in, printed after `what`. */
static void print_deltas(const char *what, const RECT *got, const RECT *put)
{
    line("  %s: deltas (%ld,%ld,%ld,%ld)", what, got->left - put->left, got->top - put->top,
         got->right - put->right, got->bottom - put->bottom);
}

static void nccalc_one(const frame_style *s)
{
    HWND h;
    HWND owner;
    RECT wr, cr, r, before;
    POINT origin;
    NCCALCSIZE_PARAMS p;
    NCCALCSIZE_PARAMS put;
    WINDOWPOS pos;
    LRESULT ret;

    h = make_framed(s);
    line("CreateWindowExA(%s, hidden, 240x160): non-NULL %s", s->name, yesno(h != NULL));
    if (h == NULL) {
        return;
    }
    /* The window's and the client's rectangles in the coordinates the
     * message takes: the screen's for a top-level window, its parent's
     * client area's for a child. */
    owner = (s->style & WS_CHILD) ? frame_parent : NULL;
    GetWindowRect(h, &wr);
    GetClientRect(h, &cr);
    origin.x = 0;
    origin.y = 0;
    ClientToScreen(h, &origin);
    OffsetRect(&cr, origin.x, origin.y);
    if (owner != NULL) {
        MapWindowPoints(NULL, owner, (POINT *)&wr, 2);
        MapWindowPoints(NULL, owner, (POINT *)&cr, 2);
    }

    r = wr;
    before = r;
    arm();
    ret = SendMessageA(h, WM_NCCALCSIZE, FALSE, (LPARAM)&r);
    line("  WM_NCCALCSIZE(FALSE, the window's rect): ret=%ld err=%s", (long)ret, le());
    print_deltas("the rect", &r, &before);

    SetRect(&r, 0, 0, 100, 50);
    before = r;
    arm();
    ret = SendMessageA(h, WM_NCCALCSIZE, FALSE, (LPARAM)&r);
    line("  WM_NCCALCSIZE(FALSE, (0,0)-(100,50)): ret=%ld err=%s", (long)ret, le());
    print_deltas("the rect", &r, &before);

    ZeroMemory(&pos, sizeof pos);
    pos.hwnd = h;
    pos.hwndInsertAfter = NULL;
    pos.x = wr.left;
    pos.y = wr.top;
    pos.cx = wr.right - wr.left;
    pos.cy = wr.bottom - wr.top;
    pos.flags = 0;
    p.rgrc[0] = wr;
    p.rgrc[1] = wr;
    p.rgrc[2] = cr;
    p.lppos = &pos;
    put = p;
    arm();
    ret = SendMessageA(h, WM_NCCALCSIZE, TRUE, (LPARAM)&p);
    line("  WM_NCCALCSIZE(TRUE, the window's rect twice and the client's): ret=0x%lX err=%s",
         (unsigned long)ret, le());
    print_deltas("rgrc[0]", &p.rgrc[0], &put.rgrc[0]);
    print_deltas("rgrc[1]", &p.rgrc[1], &put.rgrc[1]);
    print_deltas("rgrc[2]", &p.rgrc[2], &put.rgrc[2]);
    line("  lppos the same: %s", yesno(p.lppos == &pos));
    DestroyWindow(h);
}

static void sec_nccalc(void)
{
    static const frame_style styles[] = {
        { "WS_OVERLAPPEDWINDOW", WS_OVERLAPPEDWINDOW, 0, 0 },
        { "WS_POPUP", WS_POPUP, 0, 0 },
        { "WS_POPUP | WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME", WS_POPUP | WS_CAPTION | WS_SYSMENU,
          WS_EX_DLGMODALFRAME, 0 },
        { "WS_CHILD | WS_BORDER, WS_EX_CLIENTEDGE", WS_CHILD | WS_BORDER, WS_EX_CLIENTEDGE, 0 },
        { "WS_CAPTION | WS_SYSMENU, WS_EX_TOOLWINDOW", WS_CAPTION | WS_SYSMENU, WS_EX_TOOLWINDOW, 0 },
        { NULL, 0, 0, 0 }
    };
    const frame_style *s;

    make_frame_parent();
    for (s = styles; s->name != NULL; s++) {
        nccalc_one(s);
    }
    destroy_frame_parent();
}

/* --- nchittest ----------------------------------------------------- */

#define HIT_CLASS L"F2KCoordsHit"

/* A style nchittest tries, with the metric of its frame's height (the
 * caption's row is that far below the window's top, plus half the
 * caption). */
typedef struct {
    const char *name;
    DWORD style;
    DWORD ex;
    int frame;
} hit_style;

static LRESULT CALLBACK plain_w(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/* Dispatch what is queued: a shown window's WM_PAINT stays queued
 * until its procedure paints, so it is dispatched, never dropped. */
static void pump_w(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
}

static const char *ht_name(LRESULT r)
{
    switch (r) {
    case HTERROR: return "HTERROR";
    case HTTRANSPARENT: return "HTTRANSPARENT";
    case HTNOWHERE: return "HTNOWHERE";
    case HTCLIENT: return "HTCLIENT";
    case HTCAPTION: return "HTCAPTION";
    case HTSYSMENU: return "HTSYSMENU";
    case HTGROWBOX: return "HTGROWBOX";
    case HTMENU: return "HTMENU";
    case HTHSCROLL: return "HTHSCROLL";
    case HTVSCROLL: return "HTVSCROLL";
    case HTMINBUTTON: return "HTMINBUTTON";
    case HTMAXBUTTON: return "HTMAXBUTTON";
    case HTLEFT: return "HTLEFT";
    case HTRIGHT: return "HTRIGHT";
    case HTTOP: return "HTTOP";
    case HTTOPLEFT: return "HTTOPLEFT";
    case HTTOPRIGHT: return "HTTOPRIGHT";
    case HTBOTTOM: return "HTBOTTOM";
    case HTBOTTOMLEFT: return "HTBOTTOMLEFT";
    case HTBOTTOMRIGHT: return "HTBOTTOMRIGHT";
    case HTBORDER: return "HTBORDER";
    case HTCLOSE: return "HTCLOSE";
    case HTHELP: return "HTHELP";
    }
    return "?";
}

/* WM_NCHITTEST at `count` points from (x, y), a step of (dx, dy)
 * apart, printed as runs of equal answers: each run's offsets from the
 * scan's start, [first, past its last), and its code. */
static void scan(HWND h, const char *what, int x, int y, int dx, int dy, int count)
{
    char buf[900];
    int n;
    int i;
    int start;
    LRESULT run;
    LRESULT r;

    n = sprintf(buf, "  %s:", what);
    start = 0;
    run = SendMessageW(h, WM_NCHITTEST, 0, MAKELPARAM(x, y));
    r = run;
    for (i = 1; i <= count; i++) {
        if (i < count) {
            r = SendMessageW(h, WM_NCHITTEST, 0, MAKELPARAM(x + i * dx, y + i * dy));
        }
        if (i == count || r != run) {
            if (n < (int)sizeof buf - 48) {
                n += sprintf(buf + n, "%s [%d,%d) %ld %s", start == 0 ? "" : ",", start, i,
                             (long)run, ht_name(run));
            }
            start = i;
            run = r;
        }
    }
    line("%s", buf);
}

/* A window's five scans: the caption's middle row, the top row (1 in),
 * the middle column, the left column (1 in) and the bottom row (2 in),
 * each from 2 outside the window to 2 outside it. */
static void scan_window(HWND h, int frame)
{
    RECT wr;
    int width, height;

    GetWindowRect(h, &wr);
    width = wr.right - wr.left + 4;
    height = wr.bottom - wr.top + 4;
    scan(h, "the caption's middle row, from 2 left", wr.left - 2,
         wr.top + GetSystemMetrics(frame) + GetSystemMetrics(SM_CYCAPTION) / 2, 1, 0, width);
    scan(h, "the top row (1 in), from 2 left", wr.left - 2, wr.top + 1, 1, 0, width);
    scan(h, "the middle column, from 2 above", (wr.left + wr.right) / 2, wr.top - 2, 0, 1, height);
    scan(h, "the left column (1 in), from 2 above", wr.left + 1, wr.top - 2, 0, 1, height);
    scan(h, "the bottom row (2 in), from 2 left", wr.left - 2, wr.bottom - 2, 1, 0, width);
}

static void sec_nchittest(void)
{
    static const hit_style styles[] = {
        { "WS_OVERLAPPEDWINDOW", WS_OVERLAPPEDWINDOW, 0, SM_CYFRAME },
        { "WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX", WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 0,
          SM_CYFIXEDFRAME },
        { "WS_POPUP | WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME", WS_POPUP | WS_CAPTION | WS_SYSMENU,
          WS_EX_DLGMODALFRAME, SM_CYFIXEDFRAME },
        { "WS_POPUP | WS_BORDER", WS_POPUP | WS_BORDER, 0, SM_CYBORDER },
        { "WS_OVERLAPPEDWINDOW, WS_EX_CLIENTEDGE", WS_OVERLAPPEDWINDOW, WS_EX_CLIENTEDGE, SM_CYFRAME },
        { NULL, 0, 0, 0 }
    };
    const hit_style *s;
    WNDCLASSW wc;
    ATOM atom;
    HWND h;

    drain();
    UnregisterClassW(HIT_CLASS, GetModuleHandleW(NULL));
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = plain_w;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = HIT_CLASS;
    atom = RegisterClassW(&wc);
    line("RegisterClassW(F2KCoordsHit): atom nonzero %s", yesno(atom != 0));
    for (s = styles; s->name != NULL; s++) {
        h = CreateWindowExW(s->ex, HIT_CLASS, L"coords", s->style | WS_VISIBLE, 100, 80, 300, 200, NULL,
                            NULL, GetModuleHandleW(NULL), NULL);
        line("CreateWindowExW(%s, visible, 300x200): non-NULL %s", s->name, yesno(h != NULL));
        if (h == NULL) {
            continue;
        }
        pump_w();
        scan_window(h, s->frame);
        DestroyWindow(h);
        pump_w();
    }
    UnregisterClassW(HIT_CLASS, GetModuleHandleW(NULL));
}

static const section_t sections[] = {
    { "client", sec_client, F2KT_ALWAYS },
    { "map", sec_map, F2KT_ALWAYS },
    { "screen", sec_screen, F2KT_ALWAYS },
    { "childpt", sec_childpt, F2KT_ALWAYS },
    { "ischild", sec_ischild, F2KT_ALWAYS },
    { "rect", sec_rect, F2KT_ALWAYS },
    { "charnext", sec_charnext, F2KT_ALWAYS },
    { "adjust", sec_adjust, F2KT_ALWAYS },
    { "frames", sec_frames, F2KT_ALWAYS },
    { "nccalc", sec_nccalc, F2KT_ALWAYS },
    { "nchittest", sec_nchittest, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("coords", sections, argc, argv);
}
