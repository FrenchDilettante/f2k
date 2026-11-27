/*
 * fills - gdi32's filled shapes and brushes beyond Rectangle, Ellipse
 * and Polygon, drawn into a DIB section and read back pixel by pixel:
 * Chord and Pie, PolyPolygon, FloodFill and ExtFloodFill, CreateHatchBrush
 * in its six styles, CreateBrushIndirect, UnrealizeObject and
 * FixBrushOrgEx, PolyPatBlt, and SetPixelV.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled through its bits
 * pointer before each drawing and read back through it (GdiFlush
 * first). A canvas prints as rows of letters, one per pixel's low 24
 * bits: # black, . white, R red, G green, B blue, ? any other (counted,
 * the first printed), and the count of pixels whose top byte is set
 * follows when any is. Unless a line says otherwise, the pen is the
 * stock BLACK_PEN, the brush a solid red one, and the canvas white.
 *
 * PolyPatBlt is gdi32's own, never declared by the SDK headers: the
 * program finds it with GetProcAddress, its structure declared here
 * from ReactOS's and Wine's headers (POLYPATBLT: a rectangle and a
 * brush), and says so when gdi32 does not export it.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   chordpie  Chord and Pie counterclockwise and clockwise, from a
 *             radial to the same radial, and with the null pen
 *   polypoly  PolyPolygon of two nested squares under ALTERNATE and
 *             WINDING, of the outer one reversed, a polygon of 2
 *             points, and of no polygon
 *   flood     FloodFill inside a black frame, on the frame, outside the
 *             canvas; ExtFloodFill with FLOODFILLBORDER and
 *             FLOODFILLSURFACE inside and outside the frame, and
 *             FLOODFILLSURFACE from a pixel of another color
 *   hatch     CreateHatchBrush in HS_HORIZONTAL to HS_DIAGCROSS and the
 *             undefined 6, GetObjectW's LOGBRUSH, each blue pattern
 *             blitted over green (OPAQUE) and over white (TRANSPARENT)
 *   brushind  CreateBrushIndirect of BS_SOLID, BS_NULL, BS_HOLLOW,
 *             BS_HATCHED, BS_PATTERN and the undefined 99, GetObjectW's
 *             LOGBRUSH back and GetObjectType, each blitted
 *   unrealize UnrealizeObject of a brush, a stock brush, a pen, a
 *             palette, a deleted brush and NULL; FixBrushOrgEx; a
 *             pattern brush blitted after SetBrushOrgEx and
 *             UnrealizeObject, selected again and not
 *   polypat   PolyPatBlt of a red and a blue rectangle with PATCOPY,
 *             one rectangle with a NULL brush, PATINVERT, and a count
 *             of 0
 *   setpixelv SetPixelV inside, outside the canvas and on a NULL DC,
 *             each pixel read back
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat fills):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% fills.c gdi32.lib
 */

#include "../common/f2kt.h"

/* PolyPatBlt's rectangle (ReactOS's and Wine's POLYPATBLT). */
typedef struct {
    int nXLeft;
    int nYLeft;
    int nWidth;
    int nHeight;
    HBRUSH hBrush;
} polypatblt_t;

typedef BOOL (WINAPI *polypatblt_fn)(HDC, DWORD, polypatblt_t *, DWORD, DWORD);

/* A memory DC holding a 32-bit top-down DIB section of w x h pixels. */
typedef struct {
    HDC dc;
    HBITMAP bmp;
    HGDIOBJ old;
    DWORD *bits;
    int w;
    int h;
    HBRUSH red;
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
    c->red = CreateSolidBrush(RGB(255, 0, 0));
    SelectObject(c->dc, GetStockObject(BLACK_PEN));
    SelectObject(c->dc, c->red);
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
    DeleteObject(c->red);
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

/* A brush's LOGBRUSH: a hatched brush's lbHatch is its style, any other's
 * prints as zero or not (a pattern brush's holds a handle). */
static void print_logbrush(const char *what, HGDIOBJ brush)
{
    LOGBRUSH lb;
    char hatch[16];
    int n;

    ZeroMemory(&lb, sizeof lb);
    arm();
    n = GetObjectW(brush, sizeof lb, &lb);
    if (lb.lbStyle == BS_HATCHED) {
        sprintf(hatch, "%lu", (unsigned long)lb.lbHatch);
    } else {
        strcpy(hatch, lb.lbHatch == 0 ? "0" : "nonzero");
    }
    line("  GetObjectW(%s, LOGBRUSH): ret=%d err=%s lbStyle=%u lbColor=0x%06lX lbHatch=%s"
         " GetObjectType=%lu", what, n, le(), lb.lbStyle, (unsigned long)lb.lbColor, hatch,
         (unsigned long)GetObjectType(brush));
}

/* --- chordpie ------------------------------------------------------ */

static void sec_chordpie(void)
{
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 24, 24)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Chord(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("Chord(2,2-22,22, from 22,12 to 12,2), counterclockwise: ret=%d err=%s", r, le());
    letter_rows(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Pie(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("Pie(the same), counterclockwise: ret=%d err=%s", r, le());
    letter_rows(&c);

    SetArcDirection(c.dc, AD_CLOCKWISE);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Pie(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("Pie(the same), clockwise: ret=%d err=%s", r, le());
    letter_rows(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Chord(c.dc, 2, 2, 22, 22, 22, 12, 12, 2);
    line("Chord(the same), clockwise: ret=%d err=%s", r, le());
    letter_rows(&c);
    SetArcDirection(c.dc, AD_COUNTERCLOCKWISE);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Pie(c.dc, 4, 6, 20, 18, 20, 12, 20, 12);
    line("Pie(4,6-20,18, from 20,12 to the same radial): ret=%d err=%s inked=%d", r, le(), inked(&c));

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Chord(c.dc, 4, 6, 20, 18, 20, 12, 20, 12);
    line("Chord(4,6-20,18, from 20,12 to the same radial): ret=%d err=%s inked=%d", r, le(), inked(&c));

    SelectObject(c.dc, GetStockObject(NULL_PEN));
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Pie(c.dc, 2, 2, 22, 22, 2, 12, 12, 22);
    line("Pie(2,2-22,22, from 2,12 to 12,22), the null pen: ret=%d err=%s", r, le());
    letter_rows(&c);
    canvas_close(&c);
}

/* --- polypoly ------------------------------------------------------ */

static void sec_polypoly(void)
{
    /* The outer square clockwise on the screen, the inner one too. */
    static const POINT nested[8] = { { 1, 1 }, { 14, 1 }, { 14, 14 }, { 1, 14 },
                                     { 5, 5 }, { 10, 5 }, { 10, 10 }, { 5, 10 } };
    /* The outer square the other way round. */
    static const POINT reversed[8] = { { 1, 1 }, { 1, 14 }, { 14, 14 }, { 14, 1 },
                                       { 5, 5 }, { 10, 5 }, { 10, 10 }, { 5, 10 } };
    static const INT counts[2] = { 4, 4 };
    static const INT bad[2] = { 4, 2 };
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 16, 16)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyPolygon(c.dc, nested, counts, 2);
    line("PolyPolygon(two nested squares, both clockwise), ALTERNATE: ret=%d err=%s", r, le());
    letter_rows(&c);

    SetPolyFillMode(c.dc, WINDING);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyPolygon(c.dc, nested, counts, 2);
    line("PolyPolygon(the same), WINDING: ret=%d err=%s", r, le());
    letter_rows(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyPolygon(c.dc, reversed, counts, 2);
    line("PolyPolygon(the outer square reversed), WINDING: ret=%d err=%s", r, le());
    letter_rows(&c);
    SetPolyFillMode(c.dc, ALTERNATE);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyPolygon(c.dc, nested, bad, 2);
    line("PolyPolygon(counts 4 and 2): ret=%d err=%s inked=%d", r, le(), inked(&c));
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PolyPolygon(c.dc, nested, counts, 0);
    line("PolyPolygon(no polygon): ret=%d err=%s inked=%d", r, le(), inked(&c));
    canvas_close(&c);
}

/* --- flood --------------------------------------------------------- */

/* The canvas white with a black frame from 2,2 to 13,9 inclusive. */
static void framed(canvas_t *c)
{
    canvas_fill(c, 0x00FFFFFF);
    SelectObject(c->dc, GetStockObject(NULL_BRUSH));
    Rectangle(c->dc, 2, 2, 14, 10);
    SelectObject(c->dc, c->red);
}

static void sec_flood(void)
{
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 16, 12)) {
        return;
    }
    framed(&c);
    arm();
    r = FloodFill(c.dc, 5, 5, RGB(0, 0, 0));
    line("FloodFill(5, 5, black) inside a black frame: ret=%d err=%s", r, le());
    letter_rows(&c);

    framed(&c);
    arm();
    r = FloodFill(c.dc, 0, 0, RGB(0, 0, 0));
    line("FloodFill(0, 0, black) outside it: ret=%d err=%s", r, le());
    letter_rows(&c);

    framed(&c);
    arm();
    r = FloodFill(c.dc, 2, 2, RGB(0, 0, 0));
    line("FloodFill(2, 2, black) on the frame: ret=%d err=%s inked=%d", r, le(), inked(&c));

    framed(&c);
    arm();
    r = FloodFill(c.dc, 50, 50, RGB(0, 0, 0));
    line("FloodFill(50, 50, black) outside the canvas: ret=%d err=%s inked=%d", r, le(), inked(&c));

    framed(&c);
    arm();
    r = ExtFloodFill(c.dc, 5, 5, RGB(0, 0, 0), FLOODFILLBORDER);
    line("ExtFloodFill(5, 5, black, FLOODFILLBORDER): ret=%d err=%s inked=%d", r, le(), inked(&c));

    framed(&c);
    arm();
    r = ExtFloodFill(c.dc, 5, 5, RGB(255, 255, 255), FLOODFILLSURFACE);
    line("ExtFloodFill(5, 5, white, FLOODFILLSURFACE): ret=%d err=%s", r, le());
    letter_rows(&c);

    framed(&c);
    arm();
    r = ExtFloodFill(c.dc, 0, 11, RGB(255, 255, 255), FLOODFILLSURFACE);
    line("ExtFloodFill(0, 11, white, FLOODFILLSURFACE) outside the frame: ret=%d err=%s", r, le());
    letter_rows(&c);

    framed(&c);
    arm();
    r = ExtFloodFill(c.dc, 2, 2, RGB(0, 0, 0), FLOODFILLSURFACE);
    line("ExtFloodFill(2, 2, black, FLOODFILLSURFACE) on the frame: ret=%d err=%s", r, le());
    letter_rows(&c);

    framed(&c);
    arm();
    r = ExtFloodFill(c.dc, 5, 5, RGB(0, 0, 255), FLOODFILLSURFACE);
    line("ExtFloodFill(5, 5, blue, FLOODFILLSURFACE) on a white pixel: ret=%d err=%s inked=%d", r, le(),
         inked(&c));

    framed(&c);
    arm();
    r = ExtFloodFill(c.dc, 5, 5, RGB(0, 0, 0), 7);
    line("ExtFloodFill(5, 5, black, 7): ret=%d err=%s inked=%d", r, le(), inked(&c));
    canvas_close(&c);
}

/* --- hatch --------------------------------------------------------- */

static void sec_hatch(void)
{
    static const char *names[] = { "HS_HORIZONTAL", "HS_VERTICAL", "HS_FDIAGONAL", "HS_BDIAGONAL",
                                   "HS_CROSS", "HS_DIAGCROSS", "6" };
    canvas_t c;
    HBRUSH b[7];
    HGDIOBJ old;
    int i;

    for (i = 0; i < 7; i++) {
        arm();
        b[i] = CreateHatchBrush(i, RGB(0, 0, 255));
        line("CreateHatchBrush(%s, blue): non-NULL %s err=%s", names[i], yesno(b[i] != NULL), le());
        if (b[i] != NULL) {
            print_logbrush("it", b[i]);
        }
    }
    if (!canvas_open(&c, 6 * 9, 8)) {
        return;
    }
    line("-- each style blitted 8x8 at x 9*i, blue over a green OPAQUE background");
    SetBkColor(c.dc, RGB(0, 255, 0));
    SetBkMode(c.dc, OPAQUE);
    canvas_fill(&c, 0x00FFFFFF);
    for (i = 0; i < 6; i++) {
        if (b[i] != NULL) {
            old = SelectObject(c.dc, b[i]);
            PatBlt(c.dc, 9 * i, 0, 8, 8, PATCOPY);
            SelectObject(c.dc, old);
        }
    }
    letter_rows(&c);

    line("-- the same, TRANSPARENT, with Rectangle and the null pen (9*i, 0, 9*i+9, 9)");
    SetBkMode(c.dc, TRANSPARENT);
    SelectObject(c.dc, GetStockObject(NULL_PEN));
    canvas_fill(&c, 0x00FFFFFF);
    for (i = 0; i < 6; i++) {
        if (b[i] != NULL) {
            old = SelectObject(c.dc, b[i]);
            Rectangle(c.dc, 9 * i, 0, 9 * i + 9, 9);
            SelectObject(c.dc, old);
        }
    }
    letter_rows(&c);
    canvas_close(&c);
    for (i = 0; i < 7; i++) {
        if (b[i] != NULL) {
            DeleteObject(b[i]);
        }
    }
}

/* --- brushind ------------------------------------------------------ */

static const WORD checker[8] = { 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA };

static void sec_brushind(void)
{
    static const struct bs_s {
        const char *name;
        UINT style;
        LONG hatch;
    } styles[] = {
        { "BS_SOLID, red", BS_SOLID, 0 },
        { "BS_NULL", BS_NULL, 0 },
        { "BS_HOLLOW", BS_HOLLOW, 0 },
        { "BS_HATCHED, HS_CROSS, red", BS_HATCHED, HS_CROSS },
        { "BS_PATTERN, an 8x8 checker", BS_PATTERN, -1 },
        { "99", 99, 0 },
        { NULL, 0, 0 }
    };
    canvas_t c;
    LOGBRUSH lb;
    HBITMAP pattern;
    HBRUSH b;
    HGDIOBJ old;
    int i;

    pattern = CreateBitmap(8, 8, 1, 1, checker);
    if (!canvas_open(&c, 8, 2)) {
        DeleteObject(pattern);
        return;
    }
    SetBkColor(c.dc, RGB(0, 255, 0));
    SetTextColor(c.dc, RGB(0, 0, 255));
    for (i = 0; styles[i].name != NULL; i++) {
        lb.lbStyle = styles[i].style;
        lb.lbColor = RGB(255, 0, 0);
        lb.lbHatch = styles[i].hatch < 0 ? (LONG)pattern : styles[i].hatch;
        arm();
        b = CreateBrushIndirect(&lb);
        line("CreateBrushIndirect(%s): non-NULL %s err=%s", styles[i].name, yesno(b != NULL), le());
        if (b == NULL) {
            continue;
        }
        print_logbrush("it", b);
        canvas_fill(&c, 0x00FFFFFF);
        old = SelectObject(c.dc, b);
        PatBlt(c.dc, 0, 0, 8, 2, PATCOPY);
        SelectObject(c.dc, old);
        line("  PatBlt 8x2, text blue, background green:");
        letter_rows(&c);
        DeleteObject(b);
    }
    canvas_close(&c);
    DeleteObject(pattern);
}

/* --- unrealize ----------------------------------------------------- */

static void sec_unrealize(void)
{
    static const WORD stripe[8] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
    canvas_t c;
    struct {
        LOGPALETTE lp;
        PALETTEENTRY more[1];
    } pal;
    HBRUSH b;
    HPEN pen;
    HPALETTE hpal;
    HBITMAP bmp;
    POINT pt;
    BOOL r;

    b = CreateSolidBrush(RGB(0, 0, 255));
    arm();
    r = UnrealizeObject(b);
    line("UnrealizeObject(a solid brush): ret=%d err=%s", r, le());
    arm();
    r = UnrealizeObject(GetStockObject(GRAY_BRUSH));
    line("UnrealizeObject(GRAY_BRUSH): ret=%d err=%s", r, le());
    pen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    arm();
    r = UnrealizeObject(pen);
    line("UnrealizeObject(a pen): ret=%d err=%s", r, le());
    DeleteObject(pen);
    ZeroMemory(&pal, sizeof pal);
    pal.lp.palVersion = 0x300;
    pal.lp.palNumEntries = 2;
    pal.lp.palPalEntry[0].peRed = 255;
    pal.more[0].peBlue = 255;
    hpal = CreatePalette(&pal.lp);
    arm();
    r = UnrealizeObject(hpal);
    line("UnrealizeObject(a palette): ret=%d err=%s", r, le());
    DeleteObject(hpal);
    DeleteObject(b);
    arm();
    r = UnrealizeObject(b);
    line("UnrealizeObject(the brush, deleted): ret=%d err=%s", r, le());
    arm();
    r = UnrealizeObject(NULL);
    line("UnrealizeObject(NULL): ret=%d err=%s", r, le());

    if (!canvas_open(&c, 8, 1)) {
        return;
    }
    pt.x = pt.y = -7;
    arm();
    r = FixBrushOrgEx(c.dc, 3, 4, &pt);
    line("FixBrushOrgEx(3, 4): ret=%d err=%s previous=%ld,%ld", r, le(), (long)pt.x, (long)pt.y);
    GetBrushOrgEx(c.dc, &pt);
    line("  GetBrushOrgEx after it: %ld,%ld", (long)pt.x, (long)pt.y);
    SetBrushOrgEx(c.dc, 0, 0, NULL);

    /* A one-pixel stripe at x 0 of each 8, text blue, background green. */
    bmp = CreateBitmap(8, 8, 1, 1, stripe);
    b = CreatePatternBrush(bmp);
    SetBkColor(c.dc, RGB(0, 255, 0));
    SetTextColor(c.dc, RGB(0, 0, 255));
    SelectObject(c.dc, b);
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 8, 1, PATCOPY);
    line("a pattern brush's stripe (x 0 of 8), origin 0,0:");
    letter_rows(&c);
    SetBrushOrgEx(c.dc, 3, 0, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 8, 1, PATCOPY);
    line("SetBrushOrgEx(3, 0), the brush still selected:");
    letter_rows(&c);
    SelectObject(c.dc, GetStockObject(WHITE_BRUSH));
    arm();
    r = UnrealizeObject(b);
    SelectObject(c.dc, b);
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 8, 1, PATCOPY);
    line("deselected, UnrealizeObject: ret=%d err=%s; selected again:", r, le());
    letter_rows(&c);
    SelectObject(c.dc, c.red);
    DeleteObject(b);
    DeleteObject(bmp);
    canvas_close(&c);
}

/* --- polypat ------------------------------------------------------- */

static void sec_polypat(void)
{
    canvas_t c;
    polypatblt_t pp[2];
    polypatblt_fn polypat;
    HBRUSH blue, green;
    BOOL r;

    polypat = (polypatblt_fn)GetProcAddress(GetModuleHandleA("gdi32.dll"), "PolyPatBlt");
    if (polypat == NULL) {
        line("PolyPatBlt: not exported by gdi32");
        return;
    }
    if (!canvas_open(&c, 12, 6)) {
        return;
    }
    blue = CreateSolidBrush(RGB(0, 0, 255));
    green = CreateSolidBrush(RGB(0, 255, 0));
    pp[0].nXLeft = 1;
    pp[0].nYLeft = 1;
    pp[0].nWidth = 4;
    pp[0].nHeight = 3;
    pp[0].hBrush = c.red;
    pp[1].nXLeft = 6;
    pp[1].nYLeft = 2;
    pp[1].nWidth = 5;
    pp[1].nHeight = 4;
    pp[1].hBrush = blue;
    SelectObject(c.dc, green);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = polypat(c.dc, PATCOPY, pp, 2, 0);
    line("PolyPatBlt(PATCOPY, red 1,1 4x3; blue 6,2 5x4), green selected: ret=%d err=%s", r, le());
    letter_rows(&c);

    pp[1].hBrush = NULL;
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = polypat(c.dc, PATCOPY, pp, 2, 0);
    line("PolyPatBlt(the second with a NULL brush): ret=%d err=%s", r, le());
    letter_rows(&c);

    pp[1].hBrush = blue;
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = polypat(c.dc, PATINVERT, pp, 2, 0);
    line("PolyPatBlt(PATINVERT) over white: ret=%d err=%s", r, le());
    letter_rows(&c);

    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = polypat(c.dc, PATCOPY, pp, 0, 0);
    line("PolyPatBlt(count 0): ret=%d err=%s inked=%d", r, le(), inked(&c));
    SelectObject(c.dc, c.red);
    DeleteObject(blue);
    DeleteObject(green);
    canvas_close(&c);
}

/* --- setpixelv ----------------------------------------------------- */

static void sec_setpixelv(void)
{
    canvas_t c;
    BOOL r;

    if (!canvas_open(&c, 4, 2)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = SetPixelV(c.dc, 1, 0, RGB(255, 0, 0));
    line("SetPixelV(1, 0, red): ret=%d err=%s", r, le());
    arm();
    r = SetPixelV(c.dc, 2, 1, RGB(0x12, 0x34, 0x56));
    line("SetPixelV(2, 1, 0x563412): ret=%d err=%s", r, le());
    arm();
    r = SetPixelV(c.dc, 9, 9, RGB(0, 0, 255));
    line("SetPixelV(9, 9, blue) outside the canvas: ret=%d err=%s", r, le());
    arm();
    r = SetPixelV(c.dc, -1, 0, RGB(0, 0, 255));
    line("SetPixelV(-1, 0, blue): ret=%d err=%s", r, le());
    letter_rows(&c);
    GdiFlush();
    line("  pixel 2,1: 0x%08lX", (unsigned long)c.bits[1 * 4 + 2]);
    arm();
    r = SetPixelV(NULL, 0, 0, RGB(0, 0, 255));
    line("SetPixelV(NULL, ...): ret=%d err=%s", r, le());
    canvas_close(&c);
}

static const section_t sections[] = {
    { "chordpie", sec_chordpie, F2KT_ALWAYS },
    { "polypoly", sec_polypoly, F2KT_ALWAYS },
    { "flood", sec_flood, F2KT_ALWAYS },
    { "hatch", sec_hatch, F2KT_ALWAYS },
    { "brushind", sec_brushind, F2KT_ALWAYS },
    { "unrealize", sec_unrealize, F2KT_ALWAYS },
    { "polypat", sec_polypat, F2KT_ALWAYS },
    { "setpixelv", sec_setpixelv, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("fills", sections, argc, argv);
}
