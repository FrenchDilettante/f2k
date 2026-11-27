/*
 * curves - gdi32's curves and the line calls beyond MoveToEx/LineTo,
 * drawn into a DIB section and read back pixel by pixel: PolyBezier and
 * PolyBezierTo, PolylineTo and PolyPolyline, PolyDraw, Arc, ArcTo and
 * AngleArc with GetArcDirection/SetArcDirection, LineDDA's points,
 * GetMiterLimit/SetMiterLimit with a mitered geometric pen, and
 * CreatePenIndirect.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled through its bits
 * pointer before each drawing and read back through it (GdiFlush
 * first). A canvas prints as rows of letters, one per pixel's low 24
 * bits: # black, . white, R red, G green, B blue, ? any other (counted,
 * the first printed), and the count of pixels whose top byte is set
 * follows when any is. Unless a line says otherwise, the pen is the
 * stock BLACK_PEN (a cosmetic one-pixel pen, so the curves print the
 * points Windows 2000's line and curve rasterizer chooses), the brush
 * the stock NULL_BRUSH, and the canvas white.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   bezier    PolyBezier of one and of two segments, of 3 and of 1
 *             points; PolyBezierTo of one segment and the current
 *             position after it, of 2 points
 *   polyto    PolylineTo and the current position after it; PolyPolyline
 *             of two polylines, with a polyline of one point, and of no
 *             polyline
 *   polydraw  PolyDraw of a move, a line, a Bezier and a closing line,
 *             the current position after it; a point of an unknown type;
 *             a Bezier one point short
 *   arcs      GetArcDirection of a new DC; Arc counterclockwise and
 *             clockwise (SetArcDirection's previous value), from a
 *             radial to the same radial, and a direction of 3; ArcTo and
 *             the current position after it; AngleArc over +90 and -90
 *             degrees from a current position, and a radius of 0
 *   linedda   LineDDA's points (its callback records them) along a
 *             shallow, a steep, a reversed, a leftward and a zero-length
 *             line
 *   miter     GetMiterLimit of a new DC, SetMiterLimit's previous value
 *             and its refusal under 1; a width-5 geometric pen's sharp
 *             mitered corner drawn under the limits 10 and 1
 *   penind    CreatePenIndirect of a dashed, a width-3 and an undefined
 *             style, GetObjectW's LOGPEN back, and the dashed pen drawn
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat curves):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% curves.c gdi32.lib
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
    SelectObject(c->dc, GetStockObject(BLACK_PEN));
    SelectObject(c->dc, GetStockObject(NULL_BRUSH));
    return 1;
}

static void canvas_close(canvas_t *c)
{
    if (c->dc == NULL) {
        return;
    }
    SelectObject(c->dc, GetStockObject(BLACK_PEN));
    SelectObject(c->dc, GetStockObject(WHITE_BRUSH));
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

/* How many pixels are not white. */
static int inked(canvas_t *c)
{
    int i, n = 0;

    GdiFlush();
    for (i = 0; i < c->w * c->h; i++) {
        if ((c->bits[i] & 0x00FFFFFF) != 0x00FFFFFF) {
            n++;
        }
    }
    return n;
}

static void where(canvas_t *c)
{
    POINT p;

    GetCurrentPositionEx(c->dc, &p);
    line("  current position: %ld,%ld", (long)p.x, (long)p.y);
}

/* --- bezier -------------------------------------------------------- */

static void sec_bezier(void)
{
    static const POINT one[4] = { { 1, 14 }, { 5, 1 }, { 20, 1 }, { 30, 14 } };
    static const POINT two[7] = { { 1, 8 }, { 4, 0 }, { 10, 0 }, { 14, 8 }, { 18, 15 }, { 26, 15 },
                                  { 30, 8 } };
    static const POINT to[3] = { { 8, 0 }, { 22, 15 }, { 30, 2 } };
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 32, 16)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 3, 3, NULL);
    arm();
    r = PolyBezier(c.dc, one, 4);
    line("PolyBezier((1,14) (5,1) (20,1) (30,14)): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyBezier(c.dc, two, 7);
    line("PolyBezier((1,8) (4,0) (10,0) (14,8) (18,15) (26,15) (30,8)): ret=%d err=%s", r, le());
    letter_rows(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyBezier(c.dc, one, 3);
    line("PolyBezier(3 points): ret=%d err=%s inked=%d", r, le(), inked(&c));
    arm();
    r = PolyBezier(c.dc, one, 1);
    line("PolyBezier(1 point): ret=%d err=%s inked=%d", r, le(), inked(&c));

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 1, 14, NULL);
    arm();
    r = PolyBezierTo(c.dc, to, 3);
    line("MoveToEx(1, 14), PolyBezierTo((8,0) (22,15) (30,2)): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 1, 14, NULL);
    arm();
    r = PolyBezierTo(c.dc, to, 2);
    line("MoveToEx(1, 14), PolyBezierTo(2 points): ret=%d err=%s inked=%d", r, le(), inked(&c));
    where(&c);
    canvas_close(&c);
}

/* --- polyto -------------------------------------------------------- */

static void sec_polyto(void)
{
    static const POINT to[3] = { { 12, 2 }, { 12, 8 }, { 2, 8 } };
    static const POINT pp[5] = { { 1, 1 }, { 6, 1 }, { 6, 6 }, { 9, 2 }, { 14, 7 } };
    static const DWORD counts[2] = { 3, 2 };
    static const DWORD bad[2] = { 3, 1 };
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 16, 10)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 2, 2, NULL);
    arm();
    r = PolylineTo(c.dc, to, 3);
    line("MoveToEx(2, 2), PolylineTo((12,2) (12,8) (2,8)): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 0, 9, NULL);
    arm();
    r = PolyPolyline(c.dc, pp, counts, 2);
    line("PolyPolyline({(1,1) (6,1) (6,6)}, {(9,2) (14,7)}): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyPolyline(c.dc, pp, bad, 2);
    line("PolyPolyline(counts 3 and 1): ret=%d err=%s inked=%d", r, le(), inked(&c));
    arm();
    r = PolyPolyline(c.dc, pp, counts, 0);
    line("PolyPolyline(no polyline): ret=%d err=%s inked=%d", r, le(), inked(&c));
    arm();
    r = PolylineTo(c.dc, to, 0);
    line("PolylineTo(0 points): ret=%d err=%s", r, le());
    canvas_close(&c);
}

/* --- polydraw ------------------------------------------------------ */

static void sec_polydraw(void)
{
    static const POINT pts[7] = { { 2, 2 }, { 14, 2 }, { 14, 8 }, { 8, 13 }, { 2, 8 }, { 2, 5 },
                                  { 9, 6 } };
    static const BYTE types[7] = { PT_MOVETO, PT_LINETO, PT_BEZIERTO, PT_BEZIERTO, PT_BEZIERTO,
                                   PT_LINETO | PT_CLOSEFIGURE, PT_MOVETO };
    static const BYTE badtype[3] = { PT_MOVETO, 0x10, PT_LINETO };
    static const BYTE shortbez[4] = { PT_MOVETO, PT_LINETO, PT_BEZIERTO, PT_BEZIERTO };
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 16, 14)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 0, 0, NULL);
    arm();
    r = PolyDraw(c.dc, pts, types, 7);
    line("PolyDraw(move 2,2; line 14,2; bezier 14,8 8,13 2,8; line+close 2,5; move 9,6): ret=%d err=%s",
         r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 0, 0, NULL);
    arm();
    r = PolyDraw(c.dc, pts, badtype, 3);
    line("PolyDraw(move, type 0x10, line): ret=%d err=%s inked=%d", r, le(), inked(&c));
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 0, 0, NULL);
    arm();
    r = PolyDraw(c.dc, pts, shortbez, 4);
    line("PolyDraw(move, line, two bezier points): ret=%d err=%s inked=%d", r, le(), inked(&c));
    where(&c);
    canvas_close(&c);
}

/* --- arcs ---------------------------------------------------------- */

static void sec_arcs(void)
{
    canvas_t c;
    int prev, got;
    BOOL r;

    if (!canvas_open(&c, 24, 24)) {
        return;
    }
    arm();
    got = GetArcDirection(c.dc);
    line("GetArcDirection(a new DC): ret=%d err=%s", got, le());

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 0, 0, NULL);
    arm();
    r = Arc(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("Arc(2,2-22,22, from 22,12 to 12,2), counterclockwise: ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    arm();
    prev = SetArcDirection(c.dc, AD_CLOCKWISE);
    line("SetArcDirection(AD_CLOCKWISE): previous=%d err=%s now=%d", prev, le(), GetArcDirection(c.dc));
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Arc(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("Arc(the same), clockwise: ret=%d err=%s", r, le());
    letter_rows(&c);

    arm();
    prev = SetArcDirection(c.dc, 3);
    line("SetArcDirection(3): ret=%d err=%s now=%d", prev, le(), GetArcDirection(c.dc));
    SetArcDirection(c.dc, AD_COUNTERCLOCKWISE);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Arc(c.dc, 4, 6, 20, 18, 20, 12, 20, 12);
    line("Arc(4,6-20,18, from 20,12 to the same radial): ret=%d err=%s", r, le());
    letter_rows(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 0, 23, NULL);
    arm();
    r = ArcTo(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("MoveToEx(0, 23), ArcTo(2,2-22,22, from 22,12 to 12,2): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 2, 12, NULL);
    arm();
    r = AngleArc(c.dc, 12, 12, 8, 0.0f, 90.0f);
    line("MoveToEx(2, 12), AngleArc(12,12, radius 8, start 0, sweep 90): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 12, 2, NULL);
    arm();
    r = AngleArc(c.dc, 12, 12, 8, 45.0f, -90.0f);
    line("MoveToEx(12, 2), AngleArc(12,12, radius 8, start 45, sweep -90): ret=%d err=%s", r, le());
    letter_rows(&c);
    where(&c);

    canvas_fill(&c, 0x00FFFFFF);
    MoveToEx(c.dc, 2, 2, NULL);
    arm();
    r = AngleArc(c.dc, 12, 12, 0, 0.0f, 90.0f);
    line("MoveToEx(2, 2), AngleArc(radius 0): ret=%d err=%s inked=%d", r, le(), inked(&c));
    where(&c);
    canvas_close(&c);
}

/* --- linedda ------------------------------------------------------- */

typedef struct {
    int n;
    char text[512];
    int len;
} dda_t;

static VOID CALLBACK dda_point(int x, int y, LPARAM data)
{
    dda_t *d = (dda_t *)data;

    if (d->n < 40) {
        d->len += sprintf(d->text + d->len, " %d,%d", x, y);
    }
    d->n++;
}

static void dda(int x1, int y1, int x2, int y2)
{
    dda_t d;
    BOOL r;

    d.n = 0;
    d.len = 0;
    d.text[0] = '\0';
    arm();
    r = LineDDA(x1, y1, x2, y2, dda_point, (LPARAM)&d);
    line("LineDDA(%d,%d to %d,%d): ret=%d err=%s %d points:%s", x1, y1, x2, y2, r, le(), d.n, d.text);
}

static void sec_linedda(void)
{
    dda(0, 0, 7, 3);
    dda(7, 3, 0, 0);
    dda(2, 1, 3, 9);
    dda(0, 0, -4, 2);
    dda(5, 5, 5, 5);
    dda(0, 0, 6, 6);
    dda(0, 0, 9, 4);
}

/* --- miter --------------------------------------------------------- */

static void sec_miter(void)
{
    static const POINT corner[3] = { { 2, 14 }, { 10, 2 }, { 14, 14 } };
    canvas_t c;
    FLOAT old, got;
    LOGBRUSH lb;
    HPEN pen;
    HGDIOBJ oldp;
    BOOL r;

    if (!canvas_open(&c, 18, 18)) {
        return;
    }
    got = -1.0f;
    arm();
    r = GetMiterLimit(c.dc, &got);
    line("GetMiterLimit(a new DC): ret=%d err=%s limit=%.3f", r, le(), (double)got);
    old = -1.0f;
    arm();
    r = SetMiterLimit(c.dc, 3.0f, &old);
    GetMiterLimit(c.dc, &got);
    line("SetMiterLimit(3.0): ret=%d err=%s previous=%.3f now=%.3f", r, le(), (double)old, (double)got);
    old = -1.0f;
    arm();
    r = SetMiterLimit(c.dc, 0.5f, &old);
    GetMiterLimit(c.dc, &got);
    line("SetMiterLimit(0.5): ret=%d err=%s previous=%.3f now=%.3f", r, le(), (double)old, (double)got);
    arm();
    r = SetMiterLimit(c.dc, 1.0f, NULL);
    GetMiterLimit(c.dc, &got);
    line("SetMiterLimit(1.0, NULL): ret=%d err=%s now=%.3f", r, le(), (double)got);

    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    pen = ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_FLAT | PS_JOIN_MITER, 5, &lb, 0, NULL);
    oldp = SelectObject(c.dc, pen);

    SetMiterLimit(c.dc, 10.0f, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Polyline(c.dc, corner, 3);
    line("a width-5 mitered corner (2,14) (10,2) (14,14), limit 10: ret=%d err=%s inked=%d", r, le(),
         inked(&c));
    letter_rows(&c);

    SetMiterLimit(c.dc, 1.0f, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Polyline(c.dc, corner, 3);
    line("the same, limit 1: ret=%d err=%s inked=%d", r, le(), inked(&c));
    letter_rows(&c);

    SelectObject(c.dc, oldp);
    DeleteObject(pen);
    canvas_close(&c);
}

/* --- penind -------------------------------------------------------- */

static HPEN pen_indirect(const char *name, UINT style, LONG width)
{
    LOGPEN lp, back;
    HPEN pen;
    int n;

    lp.lopnStyle = style;
    lp.lopnWidth.x = width;
    lp.lopnWidth.y = 99;
    lp.lopnColor = RGB(0, 0, 255);
    arm();
    pen = CreatePenIndirect(&lp);
    line("CreatePenIndirect(%s, width %ld,99, blue): non-NULL %s err=%s", name, (long)width,
         yesno(pen != NULL), le());
    if (pen == NULL) {
        return NULL;
    }
    ZeroMemory(&back, sizeof back);
    arm();
    n = GetObjectW(pen, sizeof back, &back);
    line("  GetObjectW(LOGPEN): ret=%d err=%s lopnStyle=%u lopnWidth=%ld,%ld lopnColor=0x%06lX"
         " GetObjectType=%lu", n, le(), back.lopnStyle, (long)back.lopnWidth.x, (long)back.lopnWidth.y,
         (unsigned long)back.lopnColor, (unsigned long)GetObjectType(pen));
    return pen;
}

static void sec_penind(void)
{
    canvas_t c;
    HPEN pen;
    HGDIOBJ oldp;

    pen = pen_indirect("PS_SOLID", PS_SOLID, 3);
    if (pen != NULL) {
        DeleteObject(pen);
    }
    pen = pen_indirect("9", 9, 1);
    if (pen != NULL) {
        DeleteObject(pen);
    }
    pen = pen_indirect("PS_DASH", PS_DASH, 1);
    if (pen == NULL || !canvas_open(&c, 40, 3)) {
        if (pen != NULL) {
            DeleteObject(pen);
        }
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    oldp = SelectObject(c.dc, pen);
    MoveToEx(c.dc, 0, 1, NULL);
    LineTo(c.dc, 40, 1);
    line("  the PS_DASH pen from 0,1 to 40,1:");
    letter_rows(&c);
    SelectObject(c.dc, oldp);
    DeleteObject(pen);
    canvas_close(&c);
}

static const section_t sections[] = {
    { "bezier", sec_bezier, F2KT_ALWAYS },
    { "polyto", sec_polyto, F2KT_ALWAYS },
    { "polydraw", sec_polydraw, F2KT_ALWAYS },
    { "arcs", sec_arcs, F2KT_ALWAYS },
    { "linedda", sec_linedda, F2KT_ALWAYS },
    { "miter", sec_miter, F2KT_ALWAYS },
    { "penind", sec_penind, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("curves", sections, argc, argv);
}
