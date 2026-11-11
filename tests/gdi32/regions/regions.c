/*
 * regions - gdi32's regions and a DC's clipping: CreateRectRgn and
 * CreateRectRgnIndirect, CreatePolygonRgn under both fill modes,
 * CombineRgn in each mode with the region type it answers, OffsetRgn,
 * SetRectRgn, GetRgnBox, PtInRegion, EqualRgn and GetRegionData;
 * FillRgn; SelectClipRgn, ExtSelectClipRgn in each mode,
 * IntersectClipRect, ExcludeClipRect, OffsetClipRgn, GetClipBox,
 * GetClipRgn, PtVisible and RectVisible, with drawing clipped and read
 * back; and user32's InvalidateRgn and GetUpdateRgn on the program's own
 * window.
 *
 * A region prints as its type (ERROR, NULLREGION, SIMPLEREGION,
 * COMPLEXREGION), its bounding box, the rectangles GetRegionData gives,
 * or a grid of PtInRegion answers (# inside, . outside), one row per y.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled white through its
 * bits pointer (which no clipping touches) and read back through it
 * (GdiFlush first) as rows of letters: # black, . white, R red, ? any
 * other (counted). A clipped drawing is PatBlt(BLACKNESS) over the whole
 * canvas: the black pixels are the clipping region.
 *
 * The update section's window is a 64x48 WS_POPUP at the screen's
 * corner, topmost and shown (a hidden window keeps no update region),
 * so nothing covers its client area; its update region prints as its
 * type and as the same as a region the program built or not, in client
 * coordinates. Nothing paints it: the program never dispatches its
 * messages.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   rect      CreateRectRgn, CreateRectRgnIndirect, reversed and empty
 *             rectangles (GetObjectType, GetRgnBox, EqualRgn); PtInRegion
 *             on and off the edges; SetRectRgn, empty and reversed;
 *             OffsetRgn of a rectangle and of an empty region; a deleted
 *             region's GetRgnBox, EqualRgn, PtInRegion and OffsetRgn
 *   combine   CombineRgn of two overlapping squares in RGN_AND, RGN_OR,
 *             RGN_XOR, RGN_DIFF and RGN_COPY (type, box, rectangles,
 *             grid); disjoint, adjacent and self-cancelling operands, a
 *             destination that is a source, RGN_COPY of a NULL second
 *             source, the modes 0 and 6, a deleted source
 *   polygon   CreatePolygonRgn of a triangle and a pentagram under
 *             ALTERNATE and WINDING (box, rectangle count, grid), of two
 *             points, of one, and with the fill mode 0
 *   data      GetRegionData of a complex region: its size, its header
 *             and rectangles, a buffer one byte short, one header long;
 *             of a rectangle and of an empty region
 *   fill      FillRgn of a complex region, of an empty one, with the
 *             null brush, after OffsetRgn, through a window origin, and
 *             of a deleted region
 *   clip      GetClipRgn, GetClipBox, PtVisible and RectVisible with no
 *             clipping region; SelectClipRgn of a rectangle, then
 *             IntersectClipRect, ExcludeClipRect and OffsetClipRgn, each
 *             with GetClipBox and a clipped drawing; GetClipRgn's
 *             rectangles; PtVisible and RectVisible; SelectClipRgn(NULL)
 *   extclip   ExtSelectClipRgn over a rectangle in RGN_AND, RGN_OR,
 *             RGN_XOR, RGN_DIFF and RGN_COPY, of NULL with RGN_COPY and
 *             RGN_AND, and with no clipping region; ExcludeClipRect
 *             with none; IntersectClipRect through a window origin
 *             (GetClipBox logical, GetClipRgn device); FillRgn clipped
 *   update    InvalidateRgn and GetUpdateRgn: none, one rectangle, two
 *             (their union), one past the client area (clipped to it),
 *             NULL (the client area), an empty region, with erasing;
 *             both on a destroyed window
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat regions):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% regions.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* A memory DC holding a 32-bit top-down DIB section of w x h pixels. */
typedef struct {
    HDC dc;
    HBITMAP bmp;
    HGDIOBJ old;
    DWORD *bits;
    int w;
    int h;
} canvas_t;

/* A region's data with room for 64 rectangles. */
typedef struct {
    RGNDATAHEADER h;
    RECT rc[64];
} rgndata_t;

/* --- helpers ------------------------------------------------------- */

static int canvas_open(canvas_t *c, int w, int h)
{
    BITMAPINFO bi;
    void *p = NULL;

    c->w = w;
    c->h = h;
    c->bits = NULL;
    c->dc = CreateCompatibleDC(NULL);
    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    c->bmp = CreateDIBSection(c->dc, &bi, DIB_RGB_COLORS, &p, NULL, 0);
    if (c->dc == NULL || c->bmp == NULL || p == NULL) {
        line("canvas %dx%d: not made err=%lu", w, h, (unsigned long)GetLastError());
        if (c->bmp != NULL) {
            DeleteObject(c->bmp);
        }
        if (c->dc != NULL) {
            DeleteDC(c->dc);
        }
        c->dc = NULL;
        return 0;
    }
    c->bits = (DWORD *)p;
    c->old = SelectObject(c->dc, c->bmp);
    return 1;
}

static void canvas_close(canvas_t *c)
{
    if (c->dc == NULL) {
        return;
    }
    SelectObject(c->dc, c->old);
    DeleteObject(c->bmp);
    DeleteDC(c->dc);
    c->dc = NULL;
}

static void canvas_fill(canvas_t *c, DWORD v)
{
    int i;

    GdiFlush();
    for (i = 0; i < c->w * c->h; i++) {
        c->bits[i] = v;
    }
}

static void letter_rows(canvas_t *c)
{
    char row[80];
    DWORD v, first = 0;
    int x, y, other = 0;

    GdiFlush();
    for (y = 0; y < c->h; y++) {
        for (x = 0; x < c->w && x < (int)sizeof row - 1; x++) {
            v = c->bits[y * c->w + x] & 0x00FFFFFF;
            if (v == 0x000000) {
                row[x] = '#';
            } else if (v == 0xFFFFFF) {
                row[x] = '.';
            } else if (v == 0xFF0000) {
                row[x] = 'R';
            } else {
                row[x] = '?';
                if (other == 0) {
                    first = c->bits[y * c->w + x];
                }
                other++;
            }
        }
        row[x] = '\0';
        line("  row %2d: %s", y, row);
    }
    if (other != 0) {
        line("  other colors: %d, the first 0x%08lX", other, (unsigned long)first);
    }
}

/* The canvas white, then PatBlt(BLACKNESS) over all of it, clipped. */
static void clipped(canvas_t *c)
{
    BOOL r;

    canvas_fill(c, 0x00FFFFFF);
    r = PatBlt(c->dc, 0, 0, c->w, c->h, BLACKNESS);
    line("  PatBlt(the whole canvas, BLACKNESS): ret=%d", r);
    letter_rows(c);
}

/* A region type by name. Rotates through a few buffers, as le() does. */
static const char *rtype(int t)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    switch (t) {
    case ERROR: return "ERROR";
    case NULLREGION: return "NULLREGION";
    case SIMPLEREGION: return "SIMPLEREGION";
    case COMPLEXREGION: return "COMPLEXREGION";
    }
    sprintf(b, "%d", t);
    return b;
}

static void box(const char *what, HRGN r)
{
    RECT rc;
    int t;

    rc.left = rc.top = rc.right = rc.bottom = -99;
    arm();
    t = GetRgnBox(r, &rc);
    line("GetRgnBox(%s): %s err=%s box %ld,%ld,%ld,%ld", what, rtype(t), le(), (long)rc.left,
         (long)rc.top, (long)rc.right, (long)rc.bottom);
}

/* The rectangles of a region, from GetRegionData, eight to a line. */
static void rects(HRGN r)
{
    rgndata_t d;
    char buf[300];
    DWORD got, i;
    int k;

    ZeroMemory(&d, sizeof d);
    got = GetRegionData(r, sizeof d, (RGNDATA *)&d);
    if (got == 0) {
        line("  rects: GetRegionData failed err=%lu", (unsigned long)GetLastError());
        return;
    }
    line("  rects: %lu", (unsigned long)d.h.nCount);
    k = 0;
    buf[0] = '\0';
    for (i = 0; i < d.h.nCount && i < 64; i++) {
        k += sprintf(buf + k, " %ld,%ld,%ld,%ld", (long)d.rc[i].left, (long)d.rc[i].top,
                     (long)d.rc[i].right, (long)d.rc[i].bottom);
        if (i % 8 == 7 || i + 1 == d.h.nCount) {
            line("   %s", buf);
            k = 0;
            buf[0] = '\0';
        }
    }
}

/* PtInRegion over w x h points, a row per y. */
static void grid(HRGN r, int w, int h)
{
    char row[80];
    int x, y;

    for (y = 0; y < h; y++) {
        for (x = 0; x < w && x < (int)sizeof row - 1; x++) {
            row[x] = PtInRegion(r, x, y) ? '#' : '.';
        }
        row[x] = '\0';
        line("  grid %2d: %s", y, row);
    }
}

/* --- rect ---------------------------------------------------------- */

static void sec_rect(void)
{
    static const int probes[6][2] = { { 2, 1 }, { 7, 4 }, { 8, 4 }, { 7, 5 }, { 1, 1 }, { 5, 3 } };
    HRGN a, b, c, e, e2, d;
    RECT rc;
    DWORD type;
    int i, t, in;
    BOOL r;

    arm();
    a = CreateRectRgn(2, 1, 8, 5);
    line("CreateRectRgn(2, 1, 8, 5): non-NULL %s err=%s", yesno(a != NULL), le());
    arm();
    type = GetObjectType(a);
    line("GetObjectType(it): ret=%lu err=%s", (unsigned long)type, le());
    box("it", a);
    rc.left = 2;
    rc.top = 1;
    rc.right = 8;
    rc.bottom = 5;
    arm();
    b = CreateRectRgnIndirect(&rc);
    line("CreateRectRgnIndirect(2,1,8,5): non-NULL %s err=%s", yesno(b != NULL), le());
    arm();
    t = EqualRgn(a, b);
    line("EqualRgn(the two): ret=%d err=%s", t, le());
    arm();
    c = CreateRectRgn(8, 5, 2, 1);
    line("CreateRectRgn(8, 5, 2, 1): non-NULL %s err=%s", yesno(c != NULL), le());
    box("it", c);
    arm();
    t = EqualRgn(a, c);
    line("EqualRgn(it, CreateRectRgn(2, 1, 8, 5)'s): ret=%d err=%s", t, le());
    arm();
    e = CreateRectRgn(3, 3, 3, 9);
    line("CreateRectRgn(3, 3, 3, 9): non-NULL %s err=%s", yesno(e != NULL), le());
    box("it", e);
    e2 = CreateRectRgn(0, 0, 0, 0);
    arm();
    t = EqualRgn(e, e2);
    line("EqualRgn(it, CreateRectRgn(0, 0, 0, 0)'s): ret=%d err=%s", t, le());

    for (i = 0; i < 6; i++) {
        arm();
        in = PtInRegion(a, probes[i][0], probes[i][1]);
        line("PtInRegion(2,1,8,5, %d, %d): ret=%d err=%s", probes[i][0], probes[i][1], in, le());
    }

    arm();
    r = SetRectRgn(a, 0, 0, 4, 4);
    line("SetRectRgn(0, 0, 4, 4): ret=%d err=%s", r, le());
    box("it", a);
    arm();
    r = SetRectRgn(a, 5, 5, 5, 5);
    line("SetRectRgn(5, 5, 5, 5): ret=%d err=%s", r, le());
    box("it", a);
    arm();
    r = SetRectRgn(a, 6, 2, 1, 0);
    line("SetRectRgn(6, 2, 1, 0): ret=%d err=%s", r, le());
    box("it", a);
    arm();
    t = OffsetRgn(a, 3, -2);
    line("OffsetRgn(it, 3, -2): %s err=%s", rtype(t), le());
    box("it", a);
    arm();
    t = OffsetRgn(e, 3, 3);
    line("OffsetRgn(an empty region, 3, 3): %s err=%s", rtype(t), le());
    box("it", e);

    d = CreateRectRgn(0, 0, 4, 4);
    DeleteObject(d);
    box("a deleted region", d);
    arm();
    t = EqualRgn(a, d);
    line("EqualRgn(a region, a deleted one): ret=%d err=%s", t, le());
    arm();
    in = PtInRegion(d, 1, 1);
    line("PtInRegion(a deleted region, 1, 1): ret=%d err=%s", in, le());
    arm();
    t = OffsetRgn(d, 1, 1);
    line("OffsetRgn(a deleted region, 1, 1): %s err=%s", rtype(t), le());

    DeleteObject(a);
    DeleteObject(b);
    DeleteObject(c);
    DeleteObject(e);
    DeleteObject(e2);
}

/* --- combine ------------------------------------------------------- */

static const struct mode_s {
    const char *name;
    int mode;
} rgn_modes[] = {
    { "RGN_AND", RGN_AND },
    { "RGN_OR", RGN_OR },
    { "RGN_XOR", RGN_XOR },
    { "RGN_DIFF", RGN_DIFF },
    { "RGN_COPY", RGN_COPY },
    { NULL, 0 }
};

static void combine(HRGN d, HRGN s1, HRGN s2, int mode, const char *what)
{
    int t;

    arm();
    t = CombineRgn(d, s1, s2, mode);
    line("CombineRgn(%s): %s err=%s", what, rtype(t), le());
}

static void sec_combine(void)
{
    HRGN a, b, c, d, l, r, gone;
    char what[64];
    int i;

    a = CreateRectRgn(0, 0, 6, 6);
    b = CreateRectRgn(3, 3, 9, 9);
    d = CreateRectRgn(0, 0, 0, 0);
    line("a: 0,0,6,6; b: 3,3,9,9");
    for (i = 0; rgn_modes[i].name != NULL; i++) {
        sprintf(what, "d, a, b, %s", rgn_modes[i].name);
        combine(d, a, b, rgn_modes[i].mode, what);
        box("d", d);
        rects(d);
        grid(d, 10, 10);
    }

    c = CreateRectRgn(7, 0, 9, 2);
    combine(d, a, c, RGN_AND, "d, a, 7,0,9,2, RGN_AND");
    box("d", d);
    l = CreateRectRgn(0, 0, 3, 3);
    r = CreateRectRgn(3, 0, 6, 3);
    combine(d, l, r, RGN_OR, "d, 0,0,3,3, 3,0,6,3, RGN_OR");
    box("d", d);
    rects(d);
    combine(d, a, a, RGN_DIFF, "d, a, a, RGN_DIFF");
    box("d", d);
    combine(a, a, b, RGN_OR, "a, a, b, RGN_OR");
    box("a", a);
    rects(a);
    combine(d, b, NULL, RGN_COPY, "d, b, NULL, RGN_COPY");
    box("d", d);
    combine(d, a, b, 0, "d, a, b, 0");
    combine(d, a, b, 6, "d, a, b, 6");
    box("d", d);
    gone = CreateRectRgn(0, 0, 2, 2);
    DeleteObject(gone);
    combine(d, a, gone, RGN_OR, "d, a, a deleted region, RGN_OR");

    DeleteObject(a);
    DeleteObject(b);
    DeleteObject(c);
    DeleteObject(d);
    DeleteObject(l);
    DeleteObject(r);
}

/* --- polygon ------------------------------------------------------- */

static void polygon(const char *what, const POINT *p, int n, int mode, int w, int h)
{
    HRGN r;
    rgndata_t d;

    arm();
    r = CreatePolygonRgn(p, n, mode);
    line("CreatePolygonRgn(%s): non-NULL %s err=%s", what, yesno(r != NULL), le());
    if (r == NULL) {
        return;
    }
    box("it", r);
    ZeroMemory(&d, sizeof d);
    GetRegionData(r, sizeof d, (RGNDATA *)&d);
    line("  rectangles: %lu", (unsigned long)d.h.nCount);
    if (w > 0) {
        grid(r, w, h);
    }
    DeleteObject(r);
}

static void sec_polygon(void)
{
    static const POINT tri[3] = { { 0, 0 }, { 8, 0 }, { 0, 8 } };
    static const POINT star[5] = { { 6, 0 }, { 10, 11 }, { 0, 4 }, { 12, 4 }, { 2, 11 } };
    HRGN ra, rw;
    int t;

    polygon("0,0 8,0 0,8, ALTERNATE", tri, 3, ALTERNATE, 10, 10);
    polygon("the same, WINDING", tri, 3, WINDING, 0, 0);
    ra = CreatePolygonRgn(tri, 3, ALTERNATE);
    rw = CreatePolygonRgn(tri, 3, WINDING);
    arm();
    t = EqualRgn(ra, rw);
    line("EqualRgn(the triangle under ALTERNATE, under WINDING): ret=%d err=%s", t, le());
    DeleteObject(ra);
    DeleteObject(rw);
    polygon("6,0 10,11 0,4 12,4 2,11, ALTERNATE", star, 5, ALTERNATE, 13, 12);
    polygon("the same, WINDING", star, 5, WINDING, 13, 12);
    polygon("0,0 8,0, two points, ALTERNATE", tri, 2, ALTERNATE, 0, 0);
    polygon("0,0, one point, ALTERNATE", tri, 1, ALTERNATE, 0, 0);
    polygon("the triangle, fill mode 0", tri, 3, 0, 0, 0);
}

/* --- data ---------------------------------------------------------- */

static void data_of(const char *what, HRGN r)
{
    rgndata_t d;
    DWORD need, got;

    arm();
    need = GetRegionData(r, 0, NULL);
    line("GetRegionData(%s, 0, NULL): ret=%lu err=%s", what, (unsigned long)need, le());
    if (need == 0 || need > sizeof d) {
        return;
    }
    ZeroMemory(&d, sizeof d);
    arm();
    got = GetRegionData(r, need, (RGNDATA *)&d);
    line("GetRegionData(%s, %lu): ret=%lu err=%s", what, (unsigned long)need, (unsigned long)got, le());
    line("  dwSize=%lu iType=%lu nCount=%lu nRgnSize=%lu rcBound=%ld,%ld,%ld,%ld",
         (unsigned long)d.h.dwSize, (unsigned long)d.h.iType, (unsigned long)d.h.nCount,
         (unsigned long)d.h.nRgnSize, (long)d.h.rcBound.left, (long)d.h.rcBound.top,
         (long)d.h.rcBound.right, (long)d.h.rcBound.bottom);
    rects(r);
}

static void sec_data(void)
{
    HRGN a, b, x, e;
    rgndata_t d;
    DWORD need, got;

    a = CreateRectRgn(0, 0, 6, 6);
    b = CreateRectRgn(3, 3, 9, 9);
    x = CreateRectRgn(0, 0, 0, 0);
    CombineRgn(x, a, b, RGN_XOR);
    line("x: 0,0,6,6 XOR 3,3,9,9");
    data_of("x", x);
    need = GetRegionData(x, 0, NULL);
    ZeroMemory(&d, sizeof d);
    arm();
    got = GetRegionData(x, need - 1, (RGNDATA *)&d);
    line("GetRegionData(x, its size - 1): ret=%lu err=%s nCount=%lu", (unsigned long)got, le(),
         (unsigned long)d.h.nCount);
    ZeroMemory(&d, sizeof d);
    arm();
    got = GetRegionData(x, sizeof(RGNDATAHEADER), (RGNDATA *)&d);
    line("GetRegionData(x, sizeof(RGNDATAHEADER)): ret=%lu err=%s nCount=%lu", (unsigned long)got,
         le(), (unsigned long)d.h.nCount);
    data_of("0,0,6,6", a);
    e = CreateRectRgn(0, 0, 0, 0);
    data_of("an empty region", e);
    DeleteObject(a);
    DeleteObject(b);
    DeleteObject(x);
    DeleteObject(e);
}

/* --- fill ---------------------------------------------------------- */

static void sec_fill(void)
{
    canvas_t c;
    HRGN a, b, x, e, gone;
    HBRUSH red;
    BOOL r;

    if (!canvas_open(&c, 12, 10)) {
        return;
    }
    a = CreateRectRgn(0, 0, 6, 6);
    b = CreateRectRgn(3, 3, 9, 9);
    x = CreateRectRgn(0, 0, 0, 0);
    CombineRgn(x, a, b, RGN_XOR);
    red = CreateSolidBrush(RGB(255, 0, 0));
    line("x: 0,0,6,6 XOR 3,3,9,9; the canvas 12x10");

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = FillRgn(c.dc, x, red);
    line("FillRgn(x, red): ret=%d err=%s", r, le());
    letter_rows(&c);
    e = CreateRectRgn(0, 0, 0, 0);
    arm();
    r = FillRgn(c.dc, e, red);
    line("FillRgn(an empty region, red): ret=%d err=%s", r, le());
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = FillRgn(c.dc, x, (HBRUSH)GetStockObject(NULL_BRUSH));
    line("FillRgn(x, NULL_BRUSH): ret=%d err=%s", r, le());
    letter_rows(&c);
    OffsetRgn(x, 2, 1);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = FillRgn(c.dc, x, (HBRUSH)GetStockObject(BLACK_BRUSH));
    line("FillRgn(x offset by 2, 1, BLACK_BRUSH): ret=%d err=%s", r, le());
    letter_rows(&c);
    OffsetRgn(x, -2, -1);
    SetWindowOrgEx(c.dc, -1, -1, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = FillRgn(c.dc, x, red);
    line("FillRgn(x, red) through the window origin -1,-1: ret=%d err=%s", r, le());
    letter_rows(&c);
    SetWindowOrgEx(c.dc, 0, 0, NULL);
    gone = CreateRectRgn(0, 0, 2, 2);
    DeleteObject(gone);
    arm();
    r = FillRgn(c.dc, gone, red);
    line("FillRgn(a deleted region, red): ret=%d err=%s", r, le());

    DeleteObject(red);
    DeleteObject(a);
    DeleteObject(b);
    DeleteObject(x);
    DeleteObject(e);
    canvas_close(&c);
}

/* --- clip ---------------------------------------------------------- */

static void clip_box(HDC dc)
{
    RECT rc;
    int t;

    rc.left = rc.top = rc.right = rc.bottom = -99;
    arm();
    t = GetClipBox(dc, &rc);
    line("GetClipBox: %s err=%s %ld,%ld,%ld,%ld", rtype(t), le(), (long)rc.left, (long)rc.top,
         (long)rc.right, (long)rc.bottom);
}

static void clip_rgn(HDC dc)
{
    HRGN r;
    int n;

    r = CreateRectRgn(0, 0, 0, 0);
    arm();
    n = GetClipRgn(dc, r);
    line("GetClipRgn: ret=%d err=%s", n, le());
    if (n == 1) {
        box("the clipping region", r);
        rects(r);
    }
    DeleteObject(r);
}

static void visible(HDC dc, int x, int y)
{
    BOOL v;

    arm();
    v = PtVisible(dc, x, y);
    line("PtVisible(%d, %d): ret=%d err=%s", x, y, v, le());
}

static void rect_visible(HDC dc, int l, int t, int r, int b)
{
    RECT rc;
    BOOL v;

    rc.left = l;
    rc.top = t;
    rc.right = r;
    rc.bottom = b;
    arm();
    v = RectVisible(dc, &rc);
    line("RectVisible(%d,%d,%d,%d): ret=%d err=%s", l, t, r, b, v, le());
}

static void sec_clip(void)
{
    canvas_t c;
    HRGN r;
    int t;

    if (!canvas_open(&c, 16, 12)) {
        return;
    }
    line("-- the canvas 16x12, no clipping region");
    clip_rgn(c.dc);
    clip_box(c.dc);
    visible(c.dc, 15, 11);
    visible(c.dc, 16, 0);
    visible(c.dc, -1, 0);
    rect_visible(c.dc, 14, 10, 20, 20);
    rect_visible(c.dc, 16, 0, 20, 4);

    r = CreateRectRgn(2, 2, 10, 8);
    arm();
    t = SelectClipRgn(c.dc, r);
    line("SelectClipRgn(2,2,10,8): %s err=%s", rtype(t), le());
    DeleteObject(r);
    line("the region deleted after its selection");
    clip_box(c.dc);
    clip_rgn(c.dc);
    clipped(&c);

    arm();
    t = IntersectClipRect(c.dc, 4, 0, 16, 6);
    line("IntersectClipRect(4, 0, 16, 6): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    clipped(&c);

    arm();
    t = ExcludeClipRect(c.dc, 6, 3, 8, 5);
    line("ExcludeClipRect(6, 3, 8, 5): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    clip_rgn(c.dc);
    clipped(&c);
    visible(c.dc, 6, 3);
    visible(c.dc, 5, 3);
    visible(c.dc, 9, 5);
    rect_visible(c.dc, 6, 3, 8, 5);
    rect_visible(c.dc, 5, 3, 7, 4);
    rect_visible(c.dc, 0, 0, 4, 12);

    arm();
    t = OffsetClipRgn(c.dc, 2, 3);
    line("OffsetClipRgn(2, 3): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    clipped(&c);

    arm();
    t = SelectClipRgn(c.dc, NULL);
    line("SelectClipRgn(NULL): %s err=%s", rtype(t), le());
    clip_rgn(c.dc);
    clip_box(c.dc);
    arm();
    t = OffsetClipRgn(c.dc, 1, 1);
    line("OffsetClipRgn(1, 1) with no clipping region: %s err=%s", rtype(t), le());
    clip_rgn(c.dc);
    canvas_close(&c);
}

/* --- extclip ------------------------------------------------------- */

static void sec_extclip(void)
{
    canvas_t c;
    HRGN a, b, red_rgn;
    HBRUSH red;
    int i, t;

    if (!canvas_open(&c, 16, 12)) {
        return;
    }
    a = CreateRectRgn(2, 2, 10, 8);
    b = CreateRectRgn(6, 5, 14, 11);
    line("a: 2,2,10,8; b: 6,5,14,11; the canvas 16x12");
    for (i = 0; rgn_modes[i].name != NULL; i++) {
        SelectClipRgn(c.dc, a);
        arm();
        t = ExtSelectClipRgn(c.dc, b, rgn_modes[i].mode);
        line("SelectClipRgn(a), ExtSelectClipRgn(b, %s): %s err=%s", rgn_modes[i].name, rtype(t), le());
        clip_box(c.dc);
        clipped(&c);
    }
    arm();
    t = ExtSelectClipRgn(c.dc, NULL, RGN_COPY);
    line("ExtSelectClipRgn(NULL, RGN_COPY): %s err=%s", rtype(t), le());
    clip_rgn(c.dc);
    SelectClipRgn(c.dc, a);
    arm();
    t = ExtSelectClipRgn(c.dc, NULL, RGN_AND);
    line("SelectClipRgn(a), ExtSelectClipRgn(NULL, RGN_AND): %s err=%s", rtype(t), le());
    clip_box(c.dc);

    SelectClipRgn(c.dc, NULL);
    arm();
    t = ExtSelectClipRgn(c.dc, b, RGN_AND);
    line("with no clipping region, ExtSelectClipRgn(b, RGN_AND): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    SelectClipRgn(c.dc, NULL);
    arm();
    t = ExtSelectClipRgn(c.dc, b, RGN_OR);
    line("with no clipping region, ExtSelectClipRgn(b, RGN_OR): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    SelectClipRgn(c.dc, NULL);
    arm();
    t = ExtSelectClipRgn(c.dc, b, RGN_DIFF);
    line("with no clipping region, ExtSelectClipRgn(b, RGN_DIFF): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    clipped(&c);

    SelectClipRgn(c.dc, NULL);
    arm();
    t = ExcludeClipRect(c.dc, 4, 4, 8, 8);
    line("with no clipping region, ExcludeClipRect(4, 4, 8, 8): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    clipped(&c);

    SelectClipRgn(c.dc, NULL);
    SetWindowOrgEx(c.dc, 2, 1, NULL);
    arm();
    t = IntersectClipRect(c.dc, 2, 1, 6, 4);
    line("window origin 2,1: IntersectClipRect(2, 1, 6, 4): %s err=%s", rtype(t), le());
    clip_box(c.dc);
    clip_rgn(c.dc);
    clipped(&c);
    SetWindowOrgEx(c.dc, 0, 0, NULL);

    SelectClipRgn(c.dc, a);
    red = CreateSolidBrush(RGB(255, 0, 0));
    red_rgn = CreateRectRgn(0, 0, 16, 6);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    t = FillRgn(c.dc, red_rgn, red);
    line("clipped to a: FillRgn(0,0,16,6, red): ret=%d err=%s", t, le());
    letter_rows(&c);
    DeleteObject(red_rgn);
    DeleteObject(red);
    SelectClipRgn(c.dc, NULL);
    DeleteObject(a);
    DeleteObject(b);
    canvas_close(&c);
}

/* --- update -------------------------------------------------------- */

static const WCHAR update_class[] = L"F2KRegionsWindow";

static void update_rgn(HWND h, HRGN out, HRGN like, const char *what)
{
    const char *err;
    int t, same;

    arm();
    t = GetUpdateRgn(h, out, FALSE);
    err = le();
    same = like != NULL ? EqualRgn(out, like) : -1;
    line("GetUpdateRgn(FALSE): %s err=%s%s%s%s", rtype(t), err, like != NULL ? "; the same as " : "",
         like != NULL ? what : "", like != NULL ? (same == TRUE ? ": yes" : ": no") : "");
}

static void invalidate(HWND h, HRGN r, BOOL erase, const char *what)
{
    BOOL ok;

    arm();
    ok = InvalidateRgn(h, r, erase);
    line("InvalidateRgn(%s, %s): ret=%d err=%s", what, erase ? "TRUE" : "FALSE", ok, le());
}

static void sec_update(void)
{
    WNDCLASSW wc;
    HINSTANCE inst;
    HWND h;
    HRGN out, a, b, u, c, cc, client, empty;
    RECT rc;

    inst = GetModuleHandleW(NULL);
    UnregisterClassW(update_class, inst);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = inst;
    wc.lpszClassName = update_class;
    RegisterClassW(&wc);
    h = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, update_class, L"F2K regions",
                        WS_POPUP | WS_VISIBLE, 0, 0, 64, 48, NULL, NULL, inst, NULL);
    line("CreateWindowExW(a 64x48 popup at 0,0, topmost, visible): non-NULL %s", yesno(h != NULL));
    if (h == NULL) {
        UnregisterClassW(update_class, inst);
        return;
    }
    GetClientRect(h, &rc);
    line("its client area: %ld,%ld,%ld,%ld", (long)rc.left, (long)rc.top, (long)rc.right,
         (long)rc.bottom);
    ValidateRect(h, NULL);

    out = CreateRectRgn(0, 0, 0, 0);
    a = CreateRectRgn(4, 4, 20, 12);
    b = CreateRectRgn(10, 8, 30, 30);
    u = CreateRectRgn(0, 0, 0, 0);
    CombineRgn(u, a, b, RGN_OR);
    c = CreateRectRgn(50, 40, 80, 60);
    cc = CreateRectRgn(50, 40, 64, 48);
    client = CreateRectRgn(0, 0, 64, 48);
    empty = CreateRectRgn(0, 0, 0, 0);

    line("-- validated");
    update_rgn(h, out, NULL, NULL);
    invalidate(h, a, FALSE, "4,4,20,12");
    update_rgn(h, out, a, "4,4,20,12");
    invalidate(h, b, FALSE, "10,8,30,30");
    update_rgn(h, out, u, "the union of the two");
    ValidateRect(h, NULL);
    line("-- validated");
    update_rgn(h, out, NULL, NULL);
    invalidate(h, c, FALSE, "50,40,80,60");
    update_rgn(h, out, cc, "50,40,64,48");
    update_rgn(h, out, c, "50,40,80,60");
    ValidateRect(h, NULL);
    line("-- validated");
    invalidate(h, NULL, FALSE, "NULL");
    update_rgn(h, out, client, "the client area");
    ValidateRect(h, NULL);
    line("-- validated");
    invalidate(h, empty, FALSE, "an empty region");
    update_rgn(h, out, NULL, NULL);
    invalidate(h, a, TRUE, "4,4,20,12");
    update_rgn(h, out, a, "4,4,20,12");
    ValidateRect(h, NULL);

    DestroyWindow(h);
    line("-- the window destroyed");
    invalidate(h, a, FALSE, "4,4,20,12");
    update_rgn(h, out, NULL, NULL);

    DeleteObject(out);
    DeleteObject(a);
    DeleteObject(b);
    DeleteObject(u);
    DeleteObject(c);
    DeleteObject(cc);
    DeleteObject(client);
    DeleteObject(empty);
    UnregisterClassW(update_class, inst);
}

static const section_t sections[] = {
    { "rect", sec_rect, F2KT_ALWAYS },
    { "combine", sec_combine, F2KT_ALWAYS },
    { "polygon", sec_polygon, F2KT_ALWAYS },
    { "data", sec_data, F2KT_ALWAYS },
    { "fill", sec_fill, F2KT_ALWAYS },
    { "clip", sec_clip, F2KT_ALWAYS },
    { "extclip", sec_extclip, F2KT_ALWAYS },
    { "update", sec_update, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("regions", sections, argc, argv);
}
