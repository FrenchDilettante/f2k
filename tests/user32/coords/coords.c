/*
 * coords - window coordinates in user32: GetClientRect and
 * GetWindowRect, MapWindowPoints, ScreenToClient and ClientToScreen,
 * ChildWindowFromPoint and ChildWindowFromPointEx, IsChild, OffsetRect,
 * and CharNextA/W and CharPrevA/W.
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
 * for, never the values themselves.
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

static const section_t sections[] = {
    { "client", sec_client, F2KT_ALWAYS },
    { "map", sec_map, F2KT_ALWAYS },
    { "screen", sec_screen, F2KT_ALWAYS },
    { "childpt", sec_childpt, F2KT_ALWAYS },
    { "ischild", sec_ischild, F2KT_ALWAYS },
    { "rect", sec_rect, F2KT_ALWAYS },
    { "charnext", sec_charnext, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("coords", sections, argc, argv);
}
