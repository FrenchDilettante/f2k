/*
 * shapes - gdi32's pens, lines and shapes, drawn into a DIB section and
 * read back pixel by pixel: CreatePen in each style and width and
 * ExtCreatePen (cosmetic and geometric, its end caps and joins), with
 * GetObjectW of each; MoveToEx, LineTo (the end pixel left out) and
 * GetCurrentPositionEx; Polyline, Polygon under both fill modes
 * (SetPolyFillMode/GetPolyFillMode), Rectangle, Ellipse and RoundRect,
 * with the null pen and the null brush; and SetROP2/GetROP2 over every
 * mix mode.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled through its bits
 * pointer before each drawing and read back through it (GdiFlush
 * first). A canvas prints as rows of letters, one per pixel's low 24
 * bits: # black, . white, R red, G green, B blue, ? any other (counted,
 * the first printed), and the count of pixels whose top byte is set
 * follows when any is; the mix modes' canvas prints its values in hex.
 * Unless a line says otherwise, the pen is the stock BLACK_PEN, the
 * brush a solid red one, and the canvas white.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   pens     CreatePen in PS_SOLID, PS_DASH, PS_DOT, PS_DASHDOT,
 *            PS_DASHDOTDOT, PS_NULL and PS_INSIDEFRAME at widths 0, 1
 *            and 3 (GetObjectW's LOGPEN), the styles 7, 8 and 9, a
 *            negative width, GetObjectW's size, an EXTLOGPEN-sized
 *            buffer, and GetObjectType; each style drawn as a
 *            horizontal line at width 1, and four at width 3
 *   extpen   ExtCreatePen: cosmetic solid, alternate, a user style
 *            {3, 1} and dotted; geometric at width 3 with flat, square
 *            and round end caps, and dashed at width 2; a cosmetic pen
 *            of width 2 and a user style with no entries; GetObjectType,
 *            GetObjectW's size, EXTLOGPEN and a LOGPEN-sized buffer;
 *            each drawn as a horizontal line, and a width-5 corner under
 *            miter, bevel and round joins
 *   lines    MoveToEx (the previous position), LineTo, GetCurrentPosition-
 *            Ex; horizontal, vertical and one-pixel lines; a shallow and
 *            a steep diagonal drawn both ways; a zero-length line
 *   poly     Polyline (the current position untouched), of one point;
 *            GetPolyFillMode/SetPolyFillMode; Polygon of a pentagram
 *            under ALTERNATE and WINDING; a triangle with the null pen
 *            and with the null brush; Polygon of two points
 *   shapes   Rectangle, reversed, with the null pen, the null brush, 1x1
 *            and 0 wide; Ellipse, small, with the null pen and the null
 *            brush; RoundRect with 4x4 corners, 0x0, and corners larger
 *            than itself; Rectangle and Ellipse with a width-3 PS_SOLID
 *            and PS_INSIDEFRAME pen
 *   rop2     GetROP2 of a new DC; every mix mode 1-16 drawn over four
 *            fixed values (hex); R2_XORPEN drawn twice, R2_NOT and
 *            R2_COPYPEN over red and white, Rectangle under R2_XORPEN;
 *            the modes 0 and 17
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat shapes):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% shapes.c gdi32.lib
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

static char letter(DWORD v)
{
    switch (v & 0x00FFFFFF) {
    case 0x000000: return '#';
    case 0xFFFFFF: return '.';
    case 0xFF0000: return 'R';
    case 0x00FF00: return 'G';
    case 0x0000FF: return 'B';
    }
    return '?';
}

static void letter_rows(canvas_t *c)
{
    char row[80];
    DWORD v, first = 0;
    int x, y, other = 0, high = 0;

    GdiFlush();
    for (y = 0; y < c->h; y++) {
        for (x = 0; x < c->w && x < (int)sizeof row - 1; x++) {
            v = c->bits[y * c->w + x];
            if (v & 0xFF000000u) {
                high++;
            }
            row[x] = letter(v);
            if (row[x] == '?') {
                if (other == 0) {
                    first = v;
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
    if (high != 0) {
        line("  top byte set: %d", high);
    }
}

/* n 32-bit values as hex. Rotates through a few buffers, as le() does. */
static const char *hexdwords(const DWORD *p, int n)
{
    static char bufs[4][256];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    for (i = 0; i < n && k < (int)sizeof bufs[0] - 10; i++) {
        k += sprintf(b + k, "%s%08lX", i ? " " : "", (unsigned long)p[i]);
    }
    b[k] = '\0';
    return b;
}

/* A canvas with the default black pen and a solid red brush selected. */
typedef struct {
    canvas_t c;
    HBRUSH red;
    HGDIOBJ oldb;
    HGDIOBJ oldp;
} board_t;

static int board_open(board_t *b, int w, int h)
{
    if (!canvas_open(&b->c, w, h)) {
        return 0;
    }
    b->red = CreateSolidBrush(RGB(255, 0, 0));
    b->oldb = SelectObject(b->c.dc, b->red);
    b->oldp = SelectObject(b->c.dc, GetStockObject(BLACK_PEN));
    canvas_fill(&b->c, 0x00FFFFFF);
    return 1;
}

static void board_close(board_t *b)
{
    SelectObject(b->c.dc, b->oldp);
    SelectObject(b->c.dc, b->oldb);
    DeleteObject(b->red);
    canvas_close(&b->c);
}

/* --- pens ---------------------------------------------------------- */

static const struct style_s {
    const char *name;
    int style;
} styles[] = {
    { "PS_SOLID", PS_SOLID },
    { "PS_DASH", PS_DASH },
    { "PS_DOT", PS_DOT },
    { "PS_DASHDOT", PS_DASHDOT },
    { "PS_DASHDOTDOT", PS_DASHDOTDOT },
    { "PS_NULL", PS_NULL },
    { "PS_INSIDEFRAME", PS_INSIDEFRAME },
    { NULL, 0 }
};

static void make_pen(const char *name, int style, int width)
{
    HPEN pen;
    LOGPEN lp;
    int n;

    arm();
    pen = CreatePen(style, width, RGB(0, 0, 255));
    line("CreatePen(%s, %d, blue): non-NULL %s err=%s", name, width, yesno(pen != NULL), le());
    if (pen == NULL) {
        return;
    }
    ZeroMemory(&lp, sizeof lp);
    arm();
    n = GetObjectW(pen, sizeof lp, &lp);
    line("  GetObjectW(sizeof(LOGPEN)): ret=%d err=%s lopnStyle=%u lopnWidth=%ld,%ld lopnColor=0x%06lX",
         n, le(), lp.lopnStyle, (long)lp.lopnWidth.x, (long)lp.lopnWidth.y,
         (unsigned long)lp.lopnColor);
    DeleteObject(pen);
}

static void sec_pens(void)
{
    static const int widths[] = { 0, 1, 3 };
    canvas_t c;
    HPEN pen;
    HGDIOBJ oldp;
    BYTE big[64];
    DWORD type;
    int i, k, n;
    char name[32];

    for (i = 0; styles[i].name != NULL; i++) {
        for (k = 0; k < 3; k++) {
            make_pen(styles[i].name, styles[i].style, widths[k]);
        }
    }
    for (i = 7; i <= 9; i++) {
        sprintf(name, "%d", i);
        make_pen(name, i, 1);
    }
    make_pen("PS_SOLID", PS_SOLID, -1);

    pen = CreatePen(PS_DASH, 1, RGB(0, 0, 255));
    arm();
    n = GetObjectW(pen, 0, NULL);
    line("GetObjectW(a PS_DASH pen, 0, NULL): ret=%d err=%s", n, le());
    ZeroMemory(big, sizeof big);
    arm();
    n = GetObjectW(pen, sizeof big, big);
    line("GetObjectW(it, 64 bytes): ret=%d err=%s", n, le());
    arm();
    type = GetObjectType(pen);
    line("GetObjectType(it): ret=%lu err=%s", (unsigned long)type, le());
    DeleteObject(pen);

    line("-- each style at width 1, black, from x 0 to 32 on row i");
    if (!canvas_open(&c, 32, 7)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    for (i = 0; styles[i].name != NULL; i++) {
        pen = CreatePen(styles[i].style, 1, RGB(0, 0, 0));
        oldp = SelectObject(c.dc, pen);
        MoveToEx(c.dc, 0, i, NULL);
        LineTo(c.dc, 32, i);
        SelectObject(c.dc, oldp);
        DeleteObject(pen);
    }
    letter_rows(&c);
    canvas_close(&c);

    line("-- PS_SOLID, PS_DASH, PS_DOT and PS_INSIDEFRAME at width 3, black, from x 2 to 30 on rows 2,"
         " 6, 10 and 14");
    if (!canvas_open(&c, 32, 17)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    for (i = 0; i < 4; i++) {
        k = i == 0 ? PS_SOLID : i == 1 ? PS_DASH : i == 2 ? PS_DOT : PS_INSIDEFRAME;
        pen = CreatePen(k, 3, RGB(0, 0, 0));
        oldp = SelectObject(c.dc, pen);
        MoveToEx(c.dc, 2, 2 + 4 * i, NULL);
        LineTo(c.dc, 30, 2 + 4 * i);
        SelectObject(c.dc, oldp);
        DeleteObject(pen);
    }
    letter_rows(&c);
    canvas_close(&c);
}

/* --- extpen -------------------------------------------------------- */

typedef struct {
    EXTLOGPEN e;
    DWORD more[16];
} extlogpen_t;

static const DWORD user_style[2] = { 3, 1 };

static const struct ext_s {
    const char *name;
    DWORD style;
    DWORD width;
    DWORD entries;
} exts[] = {
    { "PS_COSMETIC | PS_SOLID", PS_COSMETIC | PS_SOLID, 1, 0 },
    { "PS_COSMETIC | PS_ALTERNATE", PS_COSMETIC | PS_ALTERNATE, 1, 0 },
    { "PS_COSMETIC | PS_USERSTYLE {3, 1}", PS_COSMETIC | PS_USERSTYLE, 1, 2 },
    { "PS_COSMETIC | PS_DOT", PS_COSMETIC | PS_DOT, 1, 0 },
    { "PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT", PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT, 3, 0 },
    { "PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_SQUARE", PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_SQUARE, 3, 0 },
    { "PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_ROUND", PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_ROUND, 3, 0 },
    { "PS_GEOMETRIC | PS_DASH | PS_ENDCAP_FLAT", PS_GEOMETRIC | PS_DASH | PS_ENDCAP_FLAT, 2, 0 },
    { NULL, 0, 0, 0 }
};

static HPEN ext_pen(const char *name, DWORD style, DWORD width, DWORD entries)
{
    LOGBRUSH lb;
    HPEN pen;
    extlogpen_t ep;
    LOGPEN lp;
    DWORD type, i;
    char list[64];
    int n, k;

    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    arm();
    pen = ExtCreatePen(style, width, &lb, entries, entries ? user_style : NULL);
    line("ExtCreatePen(%s, %lu, solid black, %lu entries): non-NULL %s err=%s", name,
         (unsigned long)width, (unsigned long)entries, yesno(pen != NULL), le());
    if (pen == NULL) {
        return NULL;
    }
    type = GetObjectType(pen);
    arm();
    n = GetObjectW(pen, 0, NULL);
    line("  GetObjectType=%lu GetObjectW(0, NULL): ret=%d err=%s", (unsigned long)type, n, le());
    ZeroMemory(&ep, sizeof ep);
    arm();
    n = GetObjectW(pen, sizeof ep, &ep);
    k = 0;
    list[0] = '\0';
    for (i = 0; i < ep.e.elpNumEntries && i < 8; i++) {
        k += sprintf(list + k, " %lu", (unsigned long)ep.e.elpStyleEntry[i]);
    }
    line("  GetObjectW(EXTLOGPEN): ret=%d err=%s elpPenStyle=0x%08lX elpWidth=%lu elpBrushStyle=%u"
         " elpColor=0x%06lX elpNumEntries=%lu entries:%s", n, le(), (unsigned long)ep.e.elpPenStyle,
         (unsigned long)ep.e.elpWidth, ep.e.elpBrushStyle, (unsigned long)ep.e.elpColor,
         (unsigned long)ep.e.elpNumEntries, list);
    ZeroMemory(&lp, sizeof lp);
    arm();
    n = GetObjectW(pen, sizeof lp, &lp);
    line("  GetObjectW(sizeof(LOGPEN)): ret=%d err=%s", n, le());
    return pen;
}

static void sec_extpen(void)
{
    static const struct join_s {
        const char *name;
        DWORD join;
    } joins[] = {
        { "PS_JOIN_MITER", PS_JOIN_MITER },
        { "PS_JOIN_BEVEL", PS_JOIN_BEVEL },
        { "PS_JOIN_ROUND", PS_JOIN_ROUND },
        { NULL, 0 }
    };
    static const POINT corner[3] = { { 2, 12 }, { 7, 3 }, { 12, 12 } };
    canvas_t c;
    LOGBRUSH lb;
    HPEN pen;
    HGDIOBJ oldp;
    int i;
    BOOL r;
    char name[96];

    if (!canvas_open(&c, 20, 5 * 8)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    for (i = 0; exts[i].name != NULL; i++) {
        pen = ext_pen(exts[i].name, exts[i].style, exts[i].width, exts[i].entries);
        if (pen != NULL) {
            oldp = SelectObject(c.dc, pen);
            MoveToEx(c.dc, 4, 2 + 5 * i, NULL);
            LineTo(c.dc, 16, 2 + 5 * i);
            SelectObject(c.dc, oldp);
            DeleteObject(pen);
        }
    }
    line("-- each pen above, in order, from x 4 to 16 on rows 2, 7, 12, ...");
    letter_rows(&c);
    canvas_close(&c);

    pen = ext_pen("PS_COSMETIC | PS_SOLID", PS_COSMETIC | PS_SOLID, 2, 0);
    if (pen != NULL) {
        DeleteObject(pen);
    }
    pen = ext_pen("PS_COSMETIC | PS_USERSTYLE", PS_COSMETIC | PS_USERSTYLE, 1, 0);
    if (pen != NULL) {
        DeleteObject(pen);
    }

    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    for (i = 0; joins[i].name != NULL; i++) {
        sprintf(name, "PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | %s", joins[i].name);
        arm();
        pen = ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | joins[i].join, 5, &lb, 0, NULL);
        line("ExtCreatePen(%s, 5): non-NULL %s err=%s", name, yesno(pen != NULL), le());
        if (pen == NULL || !canvas_open(&c, 15, 15)) {
            if (pen != NULL) {
                DeleteObject(pen);
            }
            continue;
        }
        canvas_fill(&c, 0x00FFFFFF);
        oldp = SelectObject(c.dc, pen);
        arm();
        r = Polyline(c.dc, corner, 3);
        line("  Polyline(2,12 7,3 12,12): ret=%d err=%s", r, le());
        letter_rows(&c);
        SelectObject(c.dc, oldp);
        DeleteObject(pen);
        canvas_close(&c);
    }
}

/* --- lines --------------------------------------------------------- */

static void line_to(HDC dc, int x0, int y0, int x1, int y1)
{
    POINT prev;
    BOOL r1, r2;

    prev.x = prev.y = -99;
    arm();
    r1 = MoveToEx(dc, x0, y0, &prev);
    r2 = LineTo(dc, x1, y1);
    line("MoveToEx(%d, %d) LineTo(%d, %d): rets %d %d err=%s", x0, y0, x1, y1, r1, r2, le());
}

static void both_ways(int w, int h, int x0, int y0, int x1, int y1)
{
    board_t b;

    if (!board_open(&b, w, h)) {
        return;
    }
    line_to(b.c.dc, x0, y0, x1, y1);
    letter_rows(&b.c);
    canvas_fill(&b.c, 0x00FFFFFF);
    line_to(b.c.dc, x1, y1, x0, y0);
    letter_rows(&b.c);
    board_close(&b);
}

static void sec_lines(void)
{
    board_t b;
    POINT prev, cur;
    BOOL r;

    if (!board_open(&b, 12, 8)) {
        return;
    }
    cur.x = cur.y = -99;
    arm();
    r = GetCurrentPositionEx(b.c.dc, &cur);
    line("GetCurrentPositionEx(a new DC): ret=%d err=%s %ld,%ld", r, le(), (long)cur.x, (long)cur.y);
    prev.x = prev.y = -99;
    arm();
    r = MoveToEx(b.c.dc, 1, 1, &prev);
    line("MoveToEx(1, 1): ret=%d err=%s previous=%ld,%ld", r, le(), (long)prev.x, (long)prev.y);
    arm();
    r = LineTo(b.c.dc, 6, 1);
    line("LineTo(6, 1): ret=%d err=%s", r, le());
    arm();
    r = GetCurrentPositionEx(b.c.dc, &cur);
    line("GetCurrentPositionEx: ret=%d err=%s %ld,%ld", r, le(), (long)cur.x, (long)cur.y);
    arm();
    r = LineTo(b.c.dc, 6, 5);
    line("LineTo(6, 5): ret=%d err=%s", r, le());
    arm();
    r = MoveToEx(b.c.dc, 9, 3, NULL);
    line("MoveToEx(9, 3, NULL): ret=%d err=%s", r, le());
    arm();
    r = LineTo(b.c.dc, 10, 3);
    line("LineTo(10, 3), one pixel long: ret=%d err=%s", r, le());
    line_to(b.c.dc, 9, 6, 9, 6);
    r = GetCurrentPositionEx(b.c.dc, &cur);
    line("GetCurrentPositionEx: %ld,%ld", (long)cur.x, (long)cur.y);
    line_to(b.c.dc, 2, 7, 2, 3);
    letter_rows(&b.c);
    board_close(&b);

    line("-- a shallow diagonal, both ways");
    both_ways(10, 5, 0, 0, 9, 4);
    line("-- a steep diagonal, both ways");
    both_ways(5, 10, 0, 0, 3, 9);
    line("-- a 45-degree diagonal up and to the left, both ways");
    both_ways(7, 7, 6, 6, 1, 1);
}

/* --- poly ---------------------------------------------------------- */

static void sec_poly(void)
{
    static const POINT zig[4] = { { 1, 8 }, { 3, 1 }, { 6, 8 }, { 9, 1 } };
    static const POINT star[5] = { { 6, 0 }, { 10, 11 }, { 0, 4 }, { 12, 4 }, { 2, 11 } };
    static const POINT tri[3] = { { 1, 1 }, { 10, 1 }, { 1, 8 } };
    board_t b;
    POINT cur;
    HGDIOBJ old;
    int mode;
    BOOL r;

    if (!board_open(&b, 11, 10)) {
        return;
    }
    MoveToEx(b.c.dc, 0, 9, NULL);
    arm();
    r = Polyline(b.c.dc, zig, 4);
    GetCurrentPositionEx(b.c.dc, &cur);
    line("Polyline(1,8 3,1 6,8 9,1): ret=%d err=%s the current position still 0,9: %s", r, le(),
         yesno(cur.x == 0 && cur.y == 9));
    letter_rows(&b.c);
    arm();
    r = Polyline(b.c.dc, zig, 1);
    line("Polyline of one point: ret=%d err=%s", r, le());
    board_close(&b);

    if (!board_open(&b, 13, 12)) {
        return;
    }
    arm();
    mode = GetPolyFillMode(b.c.dc);
    line("GetPolyFillMode(a new DC): ret=%d err=%s", mode, le());
    arm();
    r = Polygon(b.c.dc, star, 5);
    line("Polygon(6,0 10,11 0,4 12,4 2,11) under ALTERNATE: ret=%d err=%s", r, le());
    letter_rows(&b.c);
    canvas_fill(&b.c, 0x00FFFFFF);
    arm();
    mode = SetPolyFillMode(b.c.dc, WINDING);
    line("SetPolyFillMode(WINDING): previous=%d err=%s", mode, le());
    arm();
    r = Polygon(b.c.dc, star, 5);
    line("Polygon(the same) under WINDING: ret=%d err=%s", r, le());
    letter_rows(&b.c);
    arm();
    mode = SetPolyFillMode(b.c.dc, 0);
    line("SetPolyFillMode(0): ret=%d err=%s", mode, le());
    arm();
    mode = SetPolyFillMode(b.c.dc, 3);
    line("SetPolyFillMode(3): ret=%d err=%s", mode, le());
    arm();
    mode = GetPolyFillMode(b.c.dc);
    line("GetPolyFillMode: ret=%d err=%s", mode, le());
    SetPolyFillMode(b.c.dc, ALTERNATE);

    canvas_fill(&b.c, 0x00FFFFFF);
    old = SelectObject(b.c.dc, GetStockObject(NULL_PEN));
    arm();
    r = Polygon(b.c.dc, tri, 3);
    line("Polygon(1,1 10,1 1,8) with the null pen: ret=%d err=%s", r, le());
    letter_rows(&b.c);
    SelectObject(b.c.dc, old);
    canvas_fill(&b.c, 0x00FFFFFF);
    old = SelectObject(b.c.dc, GetStockObject(NULL_BRUSH));
    arm();
    r = Polygon(b.c.dc, tri, 3);
    line("Polygon(the same) with the null brush: ret=%d err=%s", r, le());
    letter_rows(&b.c);
    SelectObject(b.c.dc, old);
    canvas_fill(&b.c, 0x00FFFFFF);
    arm();
    r = Polygon(b.c.dc, tri, 2);
    line("Polygon of two points (1,1 10,1): ret=%d err=%s", r, le());
    letter_rows(&b.c);
    board_close(&b);
}

/* --- shapes -------------------------------------------------------- */

#define SHAPE_RECT 0
#define SHAPE_ELLIPSE 1
#define SHAPE_ROUND 2

/* One shape on a fresh 14x10 board, with the pen and brush given (NULL:
 * the board's own), printed. */
static void shape(const char *what, int kind, int l, int t, int r, int b, int cw, int ch,
                  HGDIOBJ pen, HGDIOBJ brush)
{
    board_t bd;
    HGDIOBJ oldp = NULL, oldb = NULL;
    BOOL ret;

    if (!board_open(&bd, 14, 10)) {
        return;
    }
    if (pen != NULL) {
        oldp = SelectObject(bd.c.dc, pen);
    }
    if (brush != NULL) {
        oldb = SelectObject(bd.c.dc, brush);
    }
    arm();
    if (kind == SHAPE_RECT) {
        ret = Rectangle(bd.c.dc, l, t, r, b);
        line("Rectangle(%d, %d, %d, %d)%s: ret=%d err=%s", l, t, r, b, what, ret, le());
    } else if (kind == SHAPE_ELLIPSE) {
        ret = Ellipse(bd.c.dc, l, t, r, b);
        line("Ellipse(%d, %d, %d, %d)%s: ret=%d err=%s", l, t, r, b, what, ret, le());
    } else {
        ret = RoundRect(bd.c.dc, l, t, r, b, cw, ch);
        line("RoundRect(%d, %d, %d, %d, %d, %d)%s: ret=%d err=%s", l, t, r, b, cw, ch, what, ret,
             le());
    }
    letter_rows(&bd.c);
    if (oldb != NULL) {
        SelectObject(bd.c.dc, oldb);
    }
    if (oldp != NULL) {
        SelectObject(bd.c.dc, oldp);
    }
    board_close(&bd);
}

static void sec_shapes(void)
{
    HGDIOBJ null_pen = GetStockObject(NULL_PEN);
    HGDIOBJ null_brush = GetStockObject(NULL_BRUSH);
    HPEN solid3, frame3;

    shape("", SHAPE_RECT, 1, 1, 8, 6, 0, 0, NULL, NULL);
    shape(", reversed", SHAPE_RECT, 8, 6, 1, 1, 0, 0, NULL, NULL);
    shape(" with the null pen", SHAPE_RECT, 1, 1, 8, 6, 0, 0, null_pen, NULL);
    shape(" with the null brush", SHAPE_RECT, 1, 1, 8, 6, 0, 0, NULL, null_brush);
    shape(", 1x1", SHAPE_RECT, 1, 1, 2, 2, 0, 0, NULL, NULL);
    shape(", 2x2", SHAPE_RECT, 1, 1, 3, 3, 0, 0, NULL, NULL);
    shape(", 0 wide", SHAPE_RECT, 3, 1, 3, 6, 0, 0, NULL, NULL);
    shape("", SHAPE_ELLIPSE, 1, 1, 13, 9, 0, 0, NULL, NULL);
    shape(", small", SHAPE_ELLIPSE, 1, 1, 5, 5, 0, 0, NULL, NULL);
    shape(" with the null pen", SHAPE_ELLIPSE, 1, 1, 13, 9, 0, 0, null_pen, NULL);
    shape(" with the null brush", SHAPE_ELLIPSE, 1, 1, 13, 9, 0, 0, NULL, null_brush);
    shape("", SHAPE_ROUND, 1, 1, 13, 9, 4, 4, NULL, NULL);
    shape("", SHAPE_ROUND, 1, 1, 13, 9, 0, 0, NULL, NULL);
    shape(", corners larger than itself", SHAPE_ROUND, 1, 1, 13, 9, 20, 20, NULL, NULL);
    shape(" with the null pen", SHAPE_ROUND, 1, 1, 13, 9, 6, 4, null_pen, NULL);

    arm();
    solid3 = CreatePen(PS_SOLID, 3, RGB(0, 0, 0));
    line("CreatePen(PS_SOLID, 3, black): non-NULL %s err=%s", yesno(solid3 != NULL), le());
    arm();
    frame3 = CreatePen(PS_INSIDEFRAME, 3, RGB(0, 0, 0));
    line("CreatePen(PS_INSIDEFRAME, 3, black): non-NULL %s err=%s", yesno(frame3 != NULL), le());
    shape(" with the PS_SOLID width-3 pen", SHAPE_RECT, 2, 2, 12, 8, 0, 0, solid3, NULL);
    shape(" with the PS_INSIDEFRAME width-3 pen", SHAPE_RECT, 2, 2, 12, 8, 0, 0, frame3, NULL);
    shape(" with the PS_SOLID width-3 pen", SHAPE_ELLIPSE, 2, 2, 12, 8, 0, 0, solid3, NULL);
    shape(" with the PS_INSIDEFRAME width-3 pen", SHAPE_ELLIPSE, 2, 2, 12, 8, 0, 0, frame3, NULL);
    DeleteObject(solid3);
    DeleteObject(frame3);
}

/* --- rop2 ---------------------------------------------------------- */

static const DWORD rop2_dst[4] = { 0x00000000, 0x00FFFFFF, 0x00F0CC0F, 0x00336699 };

static void sec_rop2(void)
{
    canvas_t c;
    HPEN pen, green;
    HGDIOBJ oldp, oldb;
    HBRUSH blue;
    DWORD row1[8];
    int i, x, prev, got, same;
    BOOL r;

    if (!canvas_open(&c, 4, 16)) {
        return;
    }
    arm();
    got = GetROP2(c.dc);
    line("GetROP2(a new DC): ret=%d err=%s", got, le());
    line("-- each mix mode r drawn on row r - 1 by a pen RGB(0xCC, 0x99, 0x66) over %s",
         hexdwords(rop2_dst, 4));
    GdiFlush();
    for (i = 0; i < 16; i++) {
        memcpy(c.bits + 4 * i, rop2_dst, sizeof rop2_dst);
    }
    pen = CreatePen(PS_SOLID, 1, RGB(0xCC, 0x99, 0x66));
    oldp = SelectObject(c.dc, pen);
    for (i = 1; i <= 16; i++) {
        arm();
        prev = SetROP2(c.dc, i);
        MoveToEx(c.dc, 0, i - 1, NULL);
        LineTo(c.dc, 4, i - 1);
        GdiFlush();
        line("SetROP2(%d): previous=%d err=%s -> %s", i, prev, le(), hexdwords(c.bits + 4 * (i - 1), 4));
    }
    SelectObject(c.dc, oldp);
    DeleteObject(pen);
    canvas_close(&c);

    if (!canvas_open(&c, 8, 3)) {
        return;
    }
    GdiFlush();
    for (i = 0; i < 24; i++) {
        x = i % 8;
        c.bits[i] = x < 4 ? 0x00FF0000 : 0x00FFFFFF;
    }
    line("-- a green pen over red (x 0-3) and white (x 4-7), 8x3");
    green = CreatePen(PS_SOLID, 1, RGB(0, 255, 0));
    oldp = SelectObject(c.dc, green);
    arm();
    prev = SetROP2(c.dc, R2_XORPEN);
    line("SetROP2(R2_XORPEN): previous=%d err=%s", prev, le());
    MoveToEx(c.dc, 0, 1, NULL);
    LineTo(c.dc, 8, 1);
    GdiFlush();
    memcpy(row1, c.bits + 8, sizeof row1);
    line("  row 1 after a line: %s", hexdwords(row1, 8));
    MoveToEx(c.dc, 0, 1, NULL);
    LineTo(c.dc, 8, 1);
    GdiFlush();
    same = 1;
    for (x = 0; x < 8; x++) {
        if (c.bits[8 + x] != (x < 4 ? 0x00FF0000u : 0x00FFFFFFu)) {
            same = 0;
        }
    }
    line("  row 1 after the same line again: %s; back as it was: %s", hexdwords(c.bits + 8, 8),
         yesno(same));
    arm();
    prev = SetROP2(c.dc, R2_NOT);
    line("SetROP2(R2_NOT): previous=%d err=%s", prev, le());
    MoveToEx(c.dc, 0, 2, NULL);
    LineTo(c.dc, 8, 2);
    arm();
    prev = SetROP2(c.dc, R2_COPYPEN);
    line("SetROP2(R2_COPYPEN): previous=%d err=%s", prev, le());
    MoveToEx(c.dc, 0, 0, NULL);
    LineTo(c.dc, 8, 0);
    GdiFlush();
    line("  row 0 (R2_COPYPEN): %s", hexdwords(c.bits, 8));
    line("  row 2 (R2_NOT):     %s", hexdwords(c.bits + 16, 8));

    GdiFlush();
    for (i = 0; i < 24; i++) {
        x = i % 8;
        c.bits[i] = x < 4 ? 0x00FF0000 : 0x00FFFFFF;
    }
    blue = CreateSolidBrush(RGB(0, 0, 255));
    oldb = SelectObject(c.dc, blue);
    SetROP2(c.dc, R2_XORPEN);
    arm();
    r = Rectangle(c.dc, 0, 0, 8, 3);
    GdiFlush();
    line("Rectangle(0, 0, 8, 3) under R2_XORPEN, green pen, blue brush: ret=%d err=%s", r, le());
    for (i = 0; i < 3; i++) {
        line("  row %d: %s", i, hexdwords(c.bits + 8 * i, 8));
    }
    SelectObject(c.dc, oldb);
    DeleteObject(blue);
    SelectObject(c.dc, oldp);
    DeleteObject(green);

    arm();
    prev = SetROP2(c.dc, 0);
    line("SetROP2(0): ret=%d err=%s", prev, le());
    arm();
    prev = SetROP2(c.dc, 17);
    line("SetROP2(17): ret=%d err=%s", prev, le());
    arm();
    got = GetROP2(c.dc);
    line("GetROP2: ret=%d err=%s", got, le());
    canvas_close(&c);
}

static const section_t sections[] = {
    { "pens", sec_pens, F2KT_ALWAYS },
    { "extpen", sec_extpen, F2KT_ALWAYS },
    { "lines", sec_lines, F2KT_ALWAYS },
    { "poly", sec_poly, F2KT_ALWAYS },
    { "shapes", sec_shapes, F2KT_ALWAYS },
    { "rop2", sec_rop2, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("shapes", sections, argc, argv);
}
