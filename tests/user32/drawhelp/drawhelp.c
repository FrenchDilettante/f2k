/*
 * drawhelp - user32's drawing helpers, read back through a DIB section:
 * FillRect, FrameRect, InvertRect, DrawFocusRect, DrawEdge,
 * DrawFrameControl and DrawTextA/W (implemented in F2K, pinned here),
 * and DrawTextExA/W, DrawStateA/W, GrayStringA/W, TabbedTextOutA/W,
 * GetTabbedTextExtentA/W, DrawCaption and DrawAnimatedRects.
 *
 * Every drawing goes into a 32-bit top-down DIB section selected into a
 * memory DC, first filled with a background no system colour has
 * (magenta), read back through its bits pointer after GdiFlush.
 *
 * What prints is font-independent: the glyph-free drawings (fills,
 * frames, the focus rectangle, edges, a push button's frame) print
 * exactly, as rows of letters, one per pixel, by the system colour it
 * is ('.' the background, F COLOR_3DFACE, H COLOR_3DHILIGHT,
 * L COLOR_3DLIGHT, S COLOR_3DSHADOW, D COLOR_3DDKSHADOW, # black,
 * W white, ? anything else, with the first such value); anything with
 * text or a glyph prints as relations: whether there is ink, whether
 * any falls outside a rectangle, which colours it holds, the ink's
 * bounding box against the rectangle, extents against
 * GetTextExtentPoint32's and the font's height, and counts against
 * another drawing's. The capture machine's colour scheme is Windows
 * Standard, whose COLOR_3DLIGHT is COLOR_3DFACE (both print F).
 *
 * The DC's font is its default (the System font); text is drawn
 * transparent, black.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   fills     FillRect with a brush and with COLOR_WINDOW+1, FrameRect,
 *             InvertRect over part of it, and each with an empty and an
 *             inverted rectangle: the rows
 *   focus     DrawFocusRect on white: the rows; drawn again (gone)
 *   edge      DrawEdge EDGE_RAISED, EDGE_SUNKEN, EDGE_ETCHED, EDGE_BUMP
 *             with BF_RECT, BF_RECT | BF_MIDDLE, BF_FLAT, BF_MONO,
 *             BF_LEFT | BF_BOTTOM, BF_DIAGONAL_ENDBOTTOMRIGHT: the rows;
 *             BF_ADJUST's rectangle after
 *   frame     DrawFrameControl: a push button, pushed, flat (the rows);
 *             a check box, checked; a radio button; the scroll arrows;
 *             the caption's close box; the menu's check mark: ink,
 *             outside, colours; an unknown type
 *   text      DrawTextA/W: DT_CALCRECT single line against the extent
 *             and the font's height, DT_CALCRECT | DT_WORDBREAK in a
 *             narrow rectangle (the lines), DT_SINGLELINE | DT_CENTER |
 *             DT_VCENTER (the ink centred), DT_END_ELLIPSIS and
 *             DT_PATH_ELLIPSIS with DT_MODIFYSTRING (the string after),
 *             DT_EXPANDTABS and DT_TABSTOP, a prefix against
 *             DT_NOPREFIX, the return
 *   textex    DrawTextExW/A: a NULL DRAWTEXTPARAMS, iLeftMargin and
 *             iRightMargin (the ink moved), iTabLength, uiLengthDrawn,
 *             a bad cbSize
 *   tabbed    TabbedTextOutA/W and GetTabbedTextExtentA/W: no tab stops
 *             (the default), one stop (repeated), two stops, a tab
 *             origin; the returned width against the stops and the
 *             segments' extents; the height against the font's
 *   state     DrawStateW and A: DST_TEXT, DST_PREFIXTEXT, DST_BITMAP
 *             (a monochrome bitmap of the program's), DST_ICON (the
 *             stock application icon), DST_COMPLEX (the callback's
 *             arguments and return), with DSS_NORMAL, DSS_DISABLED (its
 *             colours), DSS_UNION, DSS_MONO with a brush, DSS_RIGHT
 *   gray      GrayStringW and A with no callback (ink against TextOut's,
 *             its colours), with a callback (its DC, data, count, and
 *             answering FALSE), count 0, a brush
 *   caption   DrawCaption on a popup with a caption: DC_ACTIVE and not,
 *             DC_GRADIENT, DC_TEXT, DC_ICON, DC_SMALLCAP, DC_INBUTTON:
 *             which caption colours fill it, ink of the text colour
 *   animated  DrawAnimatedRects IDANI_CAPTION, IDANI_OPEN and an unknown
 *             id: the returns
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat drawhelp):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% drawhelp.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

#ifndef DC_GRADIENT
#define DC_GRADIENT 0x0020
#endif
#ifndef COLOR_GRADIENTACTIVECAPTION
#define COLOR_GRADIENTACTIVECAPTION 27
#define COLOR_GRADIENTINACTIVECAPTION 28
#endif
#ifndef SPI_GETGRADIENTCAPTIONS
#define SPI_GETGRADIENTCAPTIONS 0x1008
#endif
#ifndef IDANI_OPEN
#define IDANI_OPEN 1
#endif
#ifndef IDANI_CAPTION
#define IDANI_CAPTION 3
#endif

#define BG 0x00FF00FFu      /* magenta, as the DIB holds it */

typedef struct {
    HDC dc;
    HBITMAP bmp;
    HGDIOBJ old;
    DWORD *bits;
    int w;
    int h;
} canvas_t;

static canvas_t cv;

static int canvas_open(int w, int h)
{
    BITMAPINFO bi;
    void *p = NULL;

    cv.w = w;
    cv.h = h;
    cv.dc = CreateCompatibleDC(NULL);
    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    cv.bmp = CreateDIBSection(cv.dc, &bi, DIB_RGB_COLORS, &p, NULL, 0);
    if (cv.dc == NULL || cv.bmp == NULL || p == NULL) {
        line("canvas %dx%d: not made err=%lu", w, h, (unsigned long)GetLastError());
        return 0;
    }
    cv.bits = (DWORD *)p;
    cv.old = SelectObject(cv.dc, cv.bmp);
    SetBkMode(cv.dc, TRANSPARENT);
    SetTextColor(cv.dc, RGB(0, 0, 0));
    return 1;
}

static void canvas_close(void)
{
    if (cv.dc == NULL) {
        return;
    }
    SelectObject(cv.dc, cv.old);
    DeleteObject(cv.bmp);
    DeleteDC(cv.dc);
    cv.dc = NULL;
}

static void canvas_fill(DWORD v)
{
    int i;

    GdiFlush();
    for (i = 0; i < cv.w * cv.h; i++) {
        cv.bits[i] = v;
    }
}

/* A COLORREF as the DIB holds it. */
static DWORD dib(COLORREF c)
{
    return ((DWORD)GetRValue(c) << 16) | ((DWORD)GetGValue(c) << 8) | GetBValue(c);
}

static DWORD px(int x, int y)
{
    return cv.bits[y * cv.w + x] & 0x00FFFFFF;
}

static char letter(DWORD v)
{
    if (v == BG) {
        return '.';
    }
    if (v == dib(GetSysColor(COLOR_3DFACE))) {
        return 'F';
    }
    if (v == dib(GetSysColor(COLOR_3DHILIGHT))) {
        return 'H';
    }
    if (v == dib(GetSysColor(COLOR_3DLIGHT))) {
        return 'L';
    }
    if (v == dib(GetSysColor(COLOR_3DSHADOW))) {
        return 'S';
    }
    if (v == dib(GetSysColor(COLOR_3DDKSHADOW))) {
        return 'D';
    }
    if (v == 0) {
        return '#';
    }
    if (v == 0xFFFFFF) {
        return 'W';
    }
    return '?';
}

/* The rows of the canvas's top-left w x h pixels. */
static void rows(int w, int h)
{
    char row[80];
    int x, y, other = 0;
    DWORD first = 0;

    GdiFlush();
    for (y = 0; y < h; y++) {
        for (x = 0; x < w && x < 79; x++) {
            row[x] = letter(px(x, y));
            if (row[x] == '?' && other++ == 0) {
                first = px(x, y);
            }
        }
        row[x] = '\0';
        line("  row %2d: %s", y, row);
    }
    if (other != 0) {
        line("  other colours: %d, the first 0x%06lX", other, (unsigned long)first);
    }
}

/* Ink: pixels other than the background `bg`. */
typedef struct {
    int count;
    int outside;    /* outside the rectangle given */
    RECT box;       /* the ink's bounding box */
} ink_t;

static ink_t ink_of(const RECT *r, DWORD bg)
{
    ink_t k;
    int x, y;

    GdiFlush();
    ZeroMemory(&k, sizeof k);
    SetRect(&k.box, cv.w, cv.h, -1, -1);
    for (y = 0; y < cv.h; y++) {
        for (x = 0; x < cv.w; x++) {
            if (px(x, y) == bg) {
                continue;
            }
            k.count++;
            if (r != NULL && (x < r->left || x >= r->right || y < r->top || y >= r->bottom)) {
                k.outside++;
            }
            if (x < k.box.left) {
                k.box.left = x;
            }
            if (y < k.box.top) {
                k.box.top = y;
            }
            if (x + 1 > k.box.right) {
                k.box.right = x + 1;
            }
            if (y + 1 > k.box.bottom) {
                k.box.bottom = y + 1;
            }
        }
    }
    return k;
}

static int count_of(DWORD v)
{
    int i, n = 0;

    GdiFlush();
    for (i = 0; i < cv.w * cv.h; i++) {
        if ((cv.bits[i] & 0x00FFFFFF) == v) {
            n++;
        }
    }
    return n;
}

/* Which of the 3-D colours and black the ink holds, and how many other
 * colours' pixels. */
static void colours(const char *what)
{
    static const struct {
        int idx;
        char c;
    } sc[] = { { COLOR_3DFACE, 'F' }, { COLOR_3DHILIGHT, 'H' }, { COLOR_3DSHADOW, 'S' },
               { COLOR_3DDKSHADOW, 'D' }, { COLOR_GRAYTEXT, 'G' }, { -1, '#' } };
    char got[16];
    int i, n = 0, known = 0;

    for (i = 0; i < 6; i++) {
        DWORD v = sc[i].idx < 0 ? 0 : dib(GetSysColor(sc[i].idx));
        int c = count_of(v);

        if (c > 0) {
            got[n++] = sc[i].c;
        }
    }
    got[n] = '\0';
    for (i = 0; i < 6; i++) {
        known += count_of(sc[i].idx < 0 ? 0 : dib(GetSysColor(sc[i].idx)));
    }
    line("%s: the colours F H S D G # present: \"%s\"; pixels of no such colour: %s", what, got,
         ink_of(NULL, BG).count - known > 0 ? "some" : "none");
}

static void ink_line(const char *what, const RECT *r)
{
    ink_t k = ink_of(r, BG);

    line("%s: ink %s, outside the rectangle %s", what, k.count > 0 ? "yes" : "no", k.outside > 0 ? "some" : "none");
}

static SIZE extent_a(const char *s)
{
    SIZE z;

    GetTextExtentPoint32A(cv.dc, s, lstrlenA(s), &z);
    return z;
}

static int font_height(void)
{
    TEXTMETRICA tm;

    GetTextMetricsA(cv.dc, &tm);
    return tm.tmHeight;
}

/* --- fills ------------------------------------------------------------- */

static void sec_fills(void)
{
    RECT r, e, inv;
    int rv;
    HBRUSH black = (HBRUSH)GetStockObject(BLACK_BRUSH);

    if (!canvas_open(12, 8)) {
        return;
    }
    SetRect(&e, 3, 3, 3, 6);
    SetRect(&inv, 8, 6, 2, 1);
    canvas_fill(BG);
    SetRect(&r, 1, 1, 7, 5);
    arm();
    rv = FillRect(cv.dc, &r, black);
    line("FillRect((1,1)-(7,5), BLACK_BRUSH): ret=%d err=%s", rv, le());
    SetRect(&r, 5, 3, 11, 7);
    arm();
    rv = FillRect(cv.dc, &r, (HBRUSH)(COLOR_3DSHADOW + 1));
    line("FillRect((5,3)-(11,7), COLOR_3DSHADOW+1): ret=%d err=%s", rv, le());
    rows(12, 8);
    arm();
    rv = FillRect(cv.dc, &e, black);
    line("FillRect(an empty rectangle): ret=%d err=%s", rv, le());
    arm();
    rv = FillRect(cv.dc, &inv, black);
    line("FillRect(an inverted rectangle): ret=%d err=%s", rv, le());
    rows(12, 8);

    canvas_fill(BG);
    SetRect(&r, 1, 1, 9, 6);
    arm();
    rv = FrameRect(cv.dc, &r, black);
    line("FrameRect((1,1)-(9,6), BLACK_BRUSH): ret=%d err=%s", rv, le());
    SetRect(&r, 4, 4, 5, 5);
    arm();
    rv = FrameRect(cv.dc, &r, black);
    line("FrameRect((4,4)-(5,5)): ret=%d err=%s", rv, le());
    arm();
    rv = FrameRect(cv.dc, &e, black);
    line("FrameRect(an empty rectangle): ret=%d err=%s", rv, le());
    arm();
    rv = FrameRect(cv.dc, &inv, black);
    line("FrameRect(an inverted rectangle): ret=%d err=%s", rv, le());
    rows(12, 8);

    canvas_fill(0x00FFFFFF);
    SetRect(&r, 0, 0, 6, 8);
    FillRect(cv.dc, &r, black);
    SetRect(&r, 3, 2, 10, 6);
    arm();
    rv = InvertRect(cv.dc, &r);
    line("InvertRect((3,2)-(10,6)) over black and white: ret=%d err=%s", rv, le());
    arm();
    rv = InvertRect(cv.dc, &e);
    line("InvertRect(an empty rectangle): ret=%d err=%s", rv, le());
    arm();
    rv = InvertRect(cv.dc, &inv);
    line("InvertRect(an inverted rectangle): ret=%d err=%s", rv, le());
    rows(12, 8);
    canvas_close();
}

/* --- focus ------------------------------------------------------------- */

static void sec_focus(void)
{
    RECT r;
    BOOL rv;

    if (!canvas_open(12, 8)) {
        return;
    }
    canvas_fill(0x00FFFFFF);
    SetRect(&r, 1, 1, 11, 7);
    arm();
    rv = DrawFocusRect(cv.dc, &r);
    line("DrawFocusRect((1,1)-(11,7)) on white: ret=%d err=%s", rv, le());
    rows(12, 8);
    arm();
    rv = DrawFocusRect(cv.dc, &r);
    line("DrawFocusRect again: ret=%d err=%s, the canvas all white again: %s", rv, le(),
         yesno(count_of(0xFFFFFF) == 12 * 8));
    canvas_close();
}

/* --- edge -------------------------------------------------------------- */

static void edge(const char *what, UINT e, UINT f)
{
    RECT r;
    BOOL rv;

    canvas_fill(BG);
    SetRect(&r, 1, 1, 9, 7);
    arm();
    rv = DrawEdge(cv.dc, &r, e, f);
    line("DrawEdge((1,1)-(9,7), %s): ret=%d err=%s", what, rv, le());
    if (f & BF_ADJUST) {
        line("  the rectangle after: (%ld,%ld)-(%ld,%ld)", r.left, r.top, r.right, r.bottom);
    }
    rows(10, 8);
}

static void sec_edge(void)
{
    if (!canvas_open(10, 8)) {
        return;
    }
    edge("EDGE_RAISED, BF_RECT", EDGE_RAISED, BF_RECT);
    edge("EDGE_SUNKEN, BF_RECT", EDGE_SUNKEN, BF_RECT);
    edge("EDGE_ETCHED, BF_RECT", EDGE_ETCHED, BF_RECT);
    edge("EDGE_BUMP, BF_RECT", EDGE_BUMP, BF_RECT);
    edge("EDGE_RAISED, BF_RECT | BF_MIDDLE", EDGE_RAISED, BF_RECT | BF_MIDDLE);
    edge("EDGE_SUNKEN, BF_RECT | BF_FLAT", EDGE_SUNKEN, BF_RECT | BF_FLAT);
    edge("EDGE_RAISED, BF_RECT | BF_MONO", EDGE_RAISED, BF_RECT | BF_MONO);
    edge("BDR_RAISEDOUTER, BF_LEFT | BF_BOTTOM", BDR_RAISEDOUTER, BF_LEFT | BF_BOTTOM);
    edge("EDGE_RAISED, BF_DIAGONAL_ENDBOTTOMRIGHT", EDGE_RAISED, BF_DIAGONAL_ENDBOTTOMRIGHT);
    edge("EDGE_SUNKEN, BF_RECT | BF_ADJUST", EDGE_SUNKEN, BF_RECT | BF_ADJUST);
    edge("0, BF_RECT", 0, BF_RECT);
    canvas_close();
}

/* --- frame ------------------------------------------------------------- */

static void frame(const char *what, UINT type, UINT state, int exact)
{
    RECT r;
    BOOL rv;

    canvas_fill(BG);
    SetRect(&r, 2, 2, exact ? 12 : 18, exact ? 9 : 18);
    arm();
    rv = DrawFrameControl(cv.dc, &r, type, state);
    line("DrawFrameControl(%s): ret=%d err=%s", what, rv, le());
    if (exact) {
        rows(14, 11);
    } else {
        ink_line("  ", &r);
        colours("  ");
    }
}

static void sec_frame(void)
{
    if (!canvas_open(20, 20)) {
        return;
    }
    frame("(2,2)-(12,9), DFC_BUTTON, DFCS_BUTTONPUSH", DFC_BUTTON, DFCS_BUTTONPUSH, 1);
    frame("(2,2)-(12,9), DFC_BUTTON, DFCS_BUTTONPUSH | DFCS_PUSHED", DFC_BUTTON, DFCS_BUTTONPUSH | DFCS_PUSHED, 1);
    frame("(2,2)-(12,9), DFC_BUTTON, DFCS_BUTTONPUSH | DFCS_FLAT", DFC_BUTTON, DFCS_BUTTONPUSH | DFCS_FLAT, 1);
    frame("(2,2)-(18,18), DFC_BUTTON, DFCS_BUTTONCHECK", DFC_BUTTON, DFCS_BUTTONCHECK, 0);
    frame("(2,2)-(18,18), DFC_BUTTON, DFCS_BUTTONCHECK | DFCS_CHECKED", DFC_BUTTON,
          DFCS_BUTTONCHECK | DFCS_CHECKED, 0);
    frame("(2,2)-(18,18), DFC_BUTTON, DFCS_BUTTONRADIO | DFCS_CHECKED", DFC_BUTTON,
          DFCS_BUTTONRADIO | DFCS_CHECKED, 0);
    frame("(2,2)-(18,18), DFC_SCROLL, DFCS_SCROLLUP", DFC_SCROLL, DFCS_SCROLLUP, 0);
    frame("(2,2)-(18,18), DFC_SCROLL, DFCS_SCROLLDOWN | DFCS_INACTIVE", DFC_SCROLL,
          DFCS_SCROLLDOWN | DFCS_INACTIVE, 0);
    frame("(2,2)-(18,18), DFC_CAPTION, DFCS_CAPTIONCLOSE", DFC_CAPTION, DFCS_CAPTIONCLOSE, 0);
    frame("(2,2)-(18,18), DFC_MENU, DFCS_MENUCHECK", DFC_MENU, DFCS_MENUCHECK, 0);
    frame("(2,2)-(18,18), type 9", 9, 0, 0);
    canvas_close();
}

/* --- text -------------------------------------------------------------- */

static const char sample_a[] = "Draw help text";
static const WCHAR sample_w[] = L"Draw help text";

static void text_ink(const char *what, const RECT *r)
{
    ink_t k = ink_of(r, BG);

    line("%s: ink %s, outside the rectangle %s", what, k.count > 0 ? "yes" : "no", k.outside > 0 ? "some" : "none");
}

static void sec_text(void)
{
    RECT r, c;
    int rv, h, lines, lmargin, rmargin, tmargin, bmargin;
    SIZE z;
    ink_t k, k2;
    char buf[64];
    WCHAR wbuf[64];

    if (!canvas_open(240, 80)) {
        return;
    }
    h = font_height();
    z = extent_a(sample_a);

    SetRect(&c, 0, 0, 0, 0);
    arm();
    rv = DrawTextA(cv.dc, sample_a, -1, &c, DT_CALCRECT | DT_SINGLELINE);
    line("DrawTextA(DT_CALCRECT | DT_SINGLELINE): ret is the font's height %s err=%s; the width is the extent's %s, "
         "the height the font's %s", yesno(rv == h), le(), yesno(c.right - c.left == z.cx), yesno(c.bottom - c.top == h));
    SetRect(&c, 0, 0, 0, 0);
    arm();
    rv = DrawTextW(cv.dc, sample_w, -1, &c, DT_CALCRECT | DT_SINGLELINE);
    line("DrawTextW(the same): ret is the font's height %s err=%s; the width is the extent's %s", yesno(rv == h), le(),
         yesno(c.right - c.left == z.cx));

    SetRect(&c, 0, 0, z.cx / 2, 0);
    arm();
    rv = DrawTextA(cv.dc, sample_a, -1, &c, DT_CALCRECT | DT_WORDBREAK);
    lines = h > 0 ? (c.bottom - c.top) / h : 0;
    line("DrawTextA(DT_CALCRECT | DT_WORDBREAK, half the extent wide): err=%s; lines %d, a whole number of lines %s, "
         "the return the height %s, the width within the half %s", le(), lines, yesno(h > 0 && (c.bottom - c.top) % h == 0),
         yesno(rv == c.bottom - c.top), yesno(c.right - c.left <= z.cx / 2));

    canvas_fill(BG);
    SetRect(&r, 10, 10, 230, 70);
    arm();
    rv = DrawTextA(cv.dc, sample_a, -1, &r, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
    k = ink_of(&r, BG);
    lmargin = k.box.left - r.left;
    rmargin = r.right - k.box.right;
    tmargin = k.box.top - r.top;
    bmargin = r.bottom - k.box.bottom;
    line("DrawTextA(DT_SINGLELINE | DT_CENTER | DT_VCENTER): ret is the font's height %s err=%s", yesno(rv == h), le());
    line("  ink %s, outside none %s; left and right margins within 2 px %s, top and bottom within the font's height %s",
         yesno(k.count > 0), yesno(k.outside == 0), yesno(lmargin - rmargin <= 2 && rmargin - lmargin <= 2),
         yesno(tmargin - bmargin <= h && bmargin - tmargin <= h));
    canvas_fill(BG);
    DrawTextW(cv.dc, sample_w, -1, &r, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
    k2 = ink_of(&r, BG);
    line("DrawTextW, the same: the same ink count %s and box %s", yesno(k2.count == k.count),
         yesno(EqualRect(&k2.box, &k.box)));

    lstrcpyA(buf, "A rather long line of text for an ellipsis");
    SetRect(&r, 0, 0, z.cx, h);
    canvas_fill(BG);
    arm();
    rv = DrawTextA(cv.dc, buf, -1, &r, DT_SINGLELINE | DT_END_ELLIPSIS | DT_MODIFYSTRING);
    line("DrawTextA(DT_END_ELLIPSIS | DT_MODIFYSTRING, as wide as the sample): ret=%s err=%s; the string ends \"...\": %s, "
         "begins \"A rather\": %s, its extent within the width: %s", rv == h ? "the height" : "another", le(),
         yesno(lstrlenA(buf) >= 3 && lstrcmpA(buf + lstrlenA(buf) - 3, "...") == 0),
         yesno(strncmp(buf, "A rather", 8) == 0), yesno(extent_a(buf).cx <= z.cx));
    text_ink("  ", &r);
    lstrcpyW(wbuf, L"C:\\folder\\another folder\\file.txt");
    canvas_fill(BG);
    arm();
    rv = DrawTextW(cv.dc, wbuf, -1, &r, DT_SINGLELINE | DT_PATH_ELLIPSIS | DT_MODIFYSTRING);
    line("DrawTextW(DT_PATH_ELLIPSIS | DT_MODIFYSTRING): err=%s; the string: %s", le(), ws(wbuf));

    SetRect(&c, 0, 0, 0, 0);
    DrawTextA(cv.dc, "a\tb", -1, &c, DT_CALCRECT | DT_SINGLELINE | DT_EXPANDTABS);
    line("DrawTextA(\"a<tab>b\", DT_CALCRECT | DT_EXPANDTABS): the width is a tab stop of 8 average characters plus "
         "\"b\": %s", yesno(c.right - c.left >= extent_a("b").cx));
    {
        TEXTMETRICA tm;
        int w1, w2;

        GetTextMetricsA(cv.dc, &tm);
        SetRect(&c, 0, 0, 0, 0);
        DrawTextA(cv.dc, "a\tb", -1, &c, DT_CALCRECT | DT_SINGLELINE | DT_EXPANDTABS);
        w1 = c.right - c.left;
        SetRect(&c, 0, 0, 0, 0);
        DrawTextA(cv.dc, "a\tb", -1, &c, DT_CALCRECT | DT_SINGLELINE | DT_EXPANDTABS | DT_TABSTOP | 0x0400);
        w2 = c.right - c.left;
        line("  DT_EXPANDTABS: the width is 8 x tmAveCharWidth plus \"b\": %s; with DT_TABSTOP and 4: 4 x plus \"b\": %s",
             yesno(w1 == 8 * tm.tmAveCharWidth + extent_a("b").cx), yesno(w2 == 4 * tm.tmAveCharWidth + extent_a("b").cx));
    }

    canvas_fill(BG);
    SetRect(&r, 0, 0, 240, 40);
    DrawTextA(cv.dc, "&File", -1, &r, DT_SINGLELINE);
    k = ink_of(&r, BG);
    canvas_fill(BG);
    DrawTextA(cv.dc, "&File", -1, &r, DT_SINGLELINE | DT_NOPREFIX);
    k2 = ink_of(&r, BG);
    line("DrawTextA(\"&File\"): its ink box against DT_NOPREFIX's: narrower %s; lower (the underline) %s",
         yesno(k.box.right - k.box.left < k2.box.right - k2.box.left), yesno(k.box.bottom >= k2.box.bottom));
    canvas_fill(BG);
    DrawTextA(cv.dc, "File", -1, &r, DT_SINGLELINE);
    k2 = ink_of(&r, BG);
    line("  its ink against \"File\" with no prefix: more %s", yesno(k.count > k2.count));
    arm();
    rv = DrawTextA(cv.dc, "", -1, &r, DT_SINGLELINE);
    line("DrawTextA(\"\"): ret=%s err=%s", rv == h ? "the height" : rv == 0 ? "0" : "another", le());
    arm();
    rv = DrawTextA(NULL, sample_a, -1, &r, DT_SINGLELINE);
    line("DrawTextA(a NULL DC): ret=%d err=%s", rv, le());
    canvas_close();
}

/* --- textex ------------------------------------------------------------ */

static void sec_textex(void)
{
    RECT r;
    DRAWTEXTPARAMS p;
    ink_t k0, k1;
    int rv, h;
    char tabbed[] = "a\tb";

    if (!canvas_open(240, 40)) {
        return;
    }
    h = font_height();
    SetRect(&r, 0, 0, 240, 40);
    canvas_fill(BG);
    arm();
    rv = DrawTextExW(cv.dc, (LPWSTR)sample_w, -1, &r, DT_SINGLELINE, NULL);
    line("DrawTextExW(DT_SINGLELINE, no parameters): ret is the height %s err=%s", yesno(rv == h), le());
    k0 = ink_of(&r, BG);

    ZeroMemory(&p, sizeof p);
    p.cbSize = sizeof p;
    p.iLeftMargin = 20;
    canvas_fill(BG);
    arm();
    rv = DrawTextExW(cv.dc, (LPWSTR)sample_w, -1, &r, DT_SINGLELINE, &p);
    k1 = ink_of(&r, BG);
    line("DrawTextExW(iLeftMargin 20): ret is the height %s err=%s; the ink moved right by 20: %s, the same ink: %s, "
         "uiLengthDrawn %u", yesno(rv == h), le(), yesno(k1.box.left - k0.box.left == 20), yesno(k1.count == k0.count),
         p.uiLengthDrawn);

    ZeroMemory(&p, sizeof p);
    p.cbSize = sizeof p;
    p.iRightMargin = 20;
    canvas_fill(BG);
    DrawTextExW(cv.dc, (LPWSTR)sample_w, -1, &r, DT_SINGLELINE | DT_RIGHT, &p);
    k1 = ink_of(&r, BG);
    line("DrawTextExW(DT_RIGHT, iRightMargin 20): the ink ends 20 or more from the right: %s",
         yesno(240 - k1.box.right >= 20 && 240 - k1.box.right <= 24));

    ZeroMemory(&p, sizeof p);
    p.cbSize = sizeof p;
    p.iTabLength = 2;
    SetRect(&r, 0, 0, 0, 0);
    arm();
    rv = DrawTextExA(cv.dc, tabbed, -1, &r, DT_CALCRECT | DT_SINGLELINE | DT_EXPANDTABS | DT_TABSTOP, &p);
    {
        TEXTMETRICA tm;

        GetTextMetricsA(cv.dc, &tm);
        line("DrawTextExA(\"a<tab>b\", DT_CALCRECT | DT_EXPANDTABS | DT_TABSTOP, iTabLength 2): err=%s; the width is "
             "2 x tmAveCharWidth plus \"b\": %s, uiLengthDrawn %u", le(),
             yesno(r.right - r.left == 2 * tm.tmAveCharWidth + extent_a("b").cx), p.uiLengthDrawn);
    }
    ZeroMemory(&p, sizeof p);
    p.cbSize = 4;
    SetRect(&r, 0, 0, 240, 40);
    arm();
    rv = DrawTextExA(cv.dc, (LPSTR)sample_a, -1, &r, DT_SINGLELINE, &p);
    line("DrawTextExA(cbSize 4): ret=%d err=%s", rv, le());
    canvas_close();
}

/* --- tabbed ------------------------------------------------------------ */

static void tab_line(const char *what, LONG r, int expect_w, int h)
{
    line("%s: width as expected %s, height the font's %s", what, yesno(LOWORD(r) == expect_w), yesno(HIWORD(r) == h));
}

static void sec_tabbed(void)
{
    int h, one[1] = { 40 }, two[2] = { 30, 90 }, ave;
    LONG r, ra;
    DWORD e;
    TEXTMETRICA tm;
    ink_t k;
    RECT box;

    if (!canvas_open(240, 40)) {
        return;
    }
    h = font_height();
    GetTextMetricsA(cv.dc, &tm);
    ave = tm.tmAveCharWidth;

    canvas_fill(BG);
    arm();
    r = TabbedTextOutA(cv.dc, 0, 0, "ab\tc", 4, 0, NULL, 0);
    line("TabbedTextOutA(\"ab<tab>c\", no tab stops): err=%s", le());
    tab_line("  the default stop of 8 average characters", r, 8 * ave + extent_a("c").cx, h);
    k = ink_of(NULL, BG);
    line("  ink %s, ending at the width returned (within 2 px) %s", yesno(k.count > 0),
         yesno(k.box.right <= LOWORD(r) && k.box.right >= LOWORD(r) - 2));
    arm();
    e = GetTabbedTextExtentA(cv.dc, "ab\tc", 4, 0, NULL);
    line("GetTabbedTextExtentA(the same): the same %s err=%s", yesno(e == (DWORD)r), le());
    arm();
    e = GetTabbedTextExtentW(cv.dc, L"ab\tc", 4, 0, NULL);
    line("GetTabbedTextExtentW(the same): the same %s err=%s", yesno(e == (DWORD)r), le());

    canvas_fill(BG);
    arm();
    r = TabbedTextOutW(cv.dc, 0, 0, L"a\tb\tc", 5, 1, one, 0);
    line("TabbedTextOutW(\"a<tab>b<tab>c\", one stop of 40): err=%s", le());
    tab_line("  repeated every 40", r, 80 + extent_a("c").cx, h);
    ra = (LONG)GetTabbedTextExtentW(cv.dc, L"a\tb\tc", 5, 1, one);
    line("GetTabbedTextExtentW(the same): the same %s", yesno(ra == r));

    canvas_fill(BG);
    r = TabbedTextOutA(cv.dc, 0, 0, "a\tb\tc", 5, 2, two, 0);
    tab_line("TabbedTextOutA(\"a<tab>b<tab>c\", stops 30 and 90)", r, 90 + extent_a("c").cx, h);
    r = TabbedTextOutA(cv.dc, 0, 0, "a\tb\tc\td", 7, 2, two, 0);
    line("TabbedTextOutA(three tabs, stops 30 and 90): width past 90 + \"d\": %s",
         yesno(LOWORD(r) > 90 + extent_a("d").cx));

    canvas_fill(BG);
    r = TabbedTextOutA(cv.dc, 20, 0, "a\tb", 3, 1, one, 20);
    tab_line("TabbedTextOutA(at x 20, \"a<tab>b\", stop 40, origin 20)", r, 40 + extent_a("b").cx, h);
    k = ink_of(NULL, BG);
    SetRect(&box, 20, 0, 20 + LOWORD(r), h);
    line("  the ink within x 20 to 20 + the width: %s", yesno(k.box.left >= box.left && k.box.right <= box.right));
    canvas_fill(BG);
    r = TabbedTextOutA(cv.dc, 20, 0, "a\tb", 3, 1, one, 0);
    tab_line("TabbedTextOutA(at x 20, \"a<tab>b\", stop 40, origin 0)", r, 20 + extent_a("b").cx, h);
    arm();
    r = TabbedTextOutA(cv.dc, 0, 0, "", 0, 0, NULL, 0);
    line("TabbedTextOutA(\"\", 0): width %u, height the font's %s err=%s", LOWORD(r), yesno(HIWORD(r) == h), le());
    canvas_close();
}

/* --- state ------------------------------------------------------------- */

static int complex_calls;
static LPARAM complex_l;
static WPARAM complex_w;
static int complex_cx, complex_cy;
static HDC complex_dc;
static BOOL complex_answer;

static BOOL CALLBACK complex_proc(HDC dc, LPARAM l, WPARAM w, int cx, int cy)
{
    RECT r;

    complex_calls++;
    complex_dc = dc;
    complex_l = l;
    complex_w = w;
    complex_cx = cx;
    complex_cy = cy;
    SetRect(&r, 0, 0, cx, cy);
    FillRect(dc, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));
    return complex_answer;
}

static BOOL state_w(const char *what, HBRUSH br, DRAWSTATEPROC proc, LPARAM l, WPARAM w, int x, int y, int cx, int cy,
                    UINT flags)
{
    BOOL rv;

    canvas_fill(BG);
    arm();
    rv = DrawStateW(cv.dc, br, proc, l, w, x, y, cx, cy, flags);
    line("DrawStateW(%s): ret=%d err=%s", what, rv, le());
    return rv;
}

static void sec_state(void)
{
    RECT r;
    ink_t k, kd;
    HBITMAP mono;
    static const WORD bits[8] = { 0x81, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x81 };
    HICON icon;
    BOOL rv;
    SIZE z;

    if (!canvas_open(120, 40)) {
        return;
    }
    z = extent_a(sample_a);
    SetRect(&r, 0, 0, 120, 40);
    state_w("DST_TEXT, DSS_NORMAL, the length given", NULL, NULL, (LPARAM)sample_w, 4, 2, 2, 0, 0, DST_TEXT | DSS_NORMAL);
    k = ink_of(&r, BG);
    line("  ink %s, starting at x 2 or after %s", yesno(k.count > 0), yesno(k.box.left >= 2));
    canvas_fill(BG);
    arm();
    rv = DrawStateA(cv.dc, NULL, NULL, (LPARAM)"Draw", 4, 2, 2, 0, 0, DST_TEXT | DSS_NORMAL);
    kd = ink_of(&r, BG);
    line("DrawStateA(the same): ret=%d err=%s; the same ink %s", rv, le(), yesno(kd.count == k.count));
    state_w("DST_TEXT, DSS_DISABLED", NULL, NULL, (LPARAM)sample_w, 4, 2, 2, 0, 0, DST_TEXT | DSS_DISABLED);
    colours("  the colours");
    state_w("DST_TEXT, DSS_UNION", NULL, NULL, (LPARAM)sample_w, 4, 2, 2, 0, 0, DST_TEXT | DSS_UNION);
    kd = ink_of(&r, BG);
    line("  ink %s, less than DSS_NORMAL's %s", yesno(kd.count > 0), yesno(kd.count < k.count));
    state_w("DST_TEXT, DSS_MONO with BLACK_BRUSH", (HBRUSH)GetStockObject(BLACK_BRUSH), NULL, (LPARAM)sample_w, 4, 2, 2,
            0, 0, DST_TEXT | DSS_MONO);
    kd = ink_of(&r, BG);
    line("  black only %s", yesno(kd.count > 0 && count_of(0) == kd.count));
    state_w("DST_TEXT, length 0 (the whole string)", NULL, NULL, (LPARAM)sample_w, 0, 2, 2, 0, 0, DST_TEXT);
    kd = ink_of(&r, BG);
    line("  as wide as the whole string's extent (within 2 px) %s",
         yesno(kd.box.right - kd.box.left <= z.cx && kd.box.right - kd.box.left >= z.cx - 2));
    state_w("DST_TEXT, DSS_RIGHT, width 100", NULL, NULL, (LPARAM)L"ab", 2, 0, 2, 100, 20, DST_TEXT | DSS_RIGHT);
    kd = ink_of(&r, BG);
    line("  the ink ends near x 100 %s", yesno(kd.box.right <= 100 && kd.box.right >= 90));
    state_w("DST_PREFIXTEXT \"&Ab\"", NULL, NULL, (LPARAM)L"&Ab", 3, 2, 2, 0, 0, DST_PREFIXTEXT);
    k = ink_of(&r, BG);
    state_w("DST_TEXT \"&Ab\"", NULL, NULL, (LPARAM)L"&Ab", 3, 2, 2, 0, 0, DST_TEXT);
    kd = ink_of(&r, BG);
    line("  DST_PREFIXTEXT's ink box against DST_TEXT's: narrower %s", yesno(k.box.right - k.box.left < kd.box.right - kd.box.left));

    mono = CreateBitmap(8, 8, 1, 1, NULL);
    {
        BYTE b[16];
        int i;

        for (i = 0; i < 8; i++) {
            b[i * 2] = (BYTE)~bits[i];
            b[i * 2 + 1] = 0;
        }
        SetBitmapBits(mono, sizeof b, b);
    }
    state_w("DST_BITMAP, a monochrome 8x8 cross at (2,2)", NULL, NULL, (LPARAM)mono, 0, 2, 2, 0, 0, DST_BITMAP);
    rows(12, 12);
    state_w("DST_BITMAP, DSS_DISABLED", NULL, NULL, (LPARAM)mono, 0, 2, 2, 0, 0, DST_BITMAP | DSS_DISABLED);
    rows(12, 12);
    DeleteObject(mono);

    icon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    state_w("DST_ICON, the application icon", NULL, NULL, (LPARAM)icon, 0, 2, 2, 0, 0, DST_ICON);
    SetRect(&r, 2, 2, 2 + GetSystemMetrics(SM_CXICON), 2 + GetSystemMetrics(SM_CYICON));
    ink_line("  ", &r);
    state_w("DST_ICON, DSS_DISABLED", NULL, NULL, (LPARAM)icon, 0, 2, 2, 0, 0, DST_ICON | DSS_DISABLED);
    colours("  the colours");

    complex_answer = TRUE;
    complex_calls = 0;
    state_w("DST_COMPLEX, 10x6, the callback answering TRUE", NULL, complex_proc, 0x1234, 0x5678, 2, 3, 10, 6, DST_COMPLEX);
    line("  the callback: %d call(s), lParam 0x%lX, wParam 0x%lX, %dx%d, the canvas's DC %s", complex_calls,
         (unsigned long)complex_l, (unsigned long)complex_w, complex_cx, complex_cy, yesno(complex_dc == cv.dc));
    SetRect(&r, 2, 3, 12, 9);
    ink_line("  ", &r);
    complex_answer = FALSE;
    complex_calls = 0;
    state_w("DST_COMPLEX, the callback answering FALSE", NULL, complex_proc, 0, 0, 2, 3, 10, 6, DST_COMPLEX);
    line("  the callback: %d call(s)", complex_calls);
    complex_answer = TRUE;
    complex_calls = 0;
    state_w("DST_COMPLEX, DSS_DISABLED", NULL, complex_proc, 0, 0, 2, 3, 10, 6, DST_COMPLEX | DSS_DISABLED);
    line("  the callback: %d call(s), the canvas's DC %s", complex_calls, yesno(complex_dc == cv.dc));
    colours("  the colours");
    state_w("type 7", NULL, NULL, 0, 0, 2, 2, 10, 10, 7);
    canvas_close();
}

/* --- gray -------------------------------------------------------------- */

static int gray_calls;
static HDC gray_dc;
static LPARAM gray_data;
static int gray_count;
static BOOL gray_answer;

static BOOL CALLBACK gray_proc(HDC dc, LPARAM data, int count)
{
    gray_calls++;
    gray_dc = dc;
    gray_data = data;
    gray_count = count;
    TextOutA(dc, 0, 0, "Gray", 4);
    return gray_answer;
}

static void sec_gray(void)
{
    RECT r;
    ink_t k, kt;
    BOOL rv;
    SIZE z;

    if (!canvas_open(120, 40)) {
        return;
    }
    SetRect(&r, 0, 0, 120, 40);
    z = extent_a("Gray");
    canvas_fill(BG);
    TextOutA(cv.dc, 2, 2, "Gray", 4);
    kt = ink_of(&r, BG);
    canvas_fill(BG);
    arm();
    rv = GrayStringA(cv.dc, NULL, NULL, (LPARAM)"Gray", 4, 2, 2, 0, 0);
    k = ink_of(&r, BG);
    line("GrayStringA(\"Gray\", no brush, no callback): ret=%d err=%s; ink %s, less than TextOutA's %s, within its box %s", rv,
         le(), yesno(k.count > 0), yesno(k.count < kt.count),
         yesno(k.box.left >= kt.box.left && k.box.right <= kt.box.right && k.box.top >= kt.box.top
               && k.box.bottom <= kt.box.bottom));
    colours("  the colours");
    canvas_fill(BG);
    arm();
    rv = GrayStringW(cv.dc, NULL, NULL, (LPARAM)L"Gray", 4, 2, 2, 0, 0);
    line("GrayStringW(the same): ret=%d err=%s; the same ink %s", rv, le(), yesno(ink_of(&r, BG).count == k.count));
    canvas_fill(BG);
    arm();
    rv = GrayStringA(cv.dc, NULL, NULL, (LPARAM)"Gray", 0, 2, 2, 0, 0);
    line("GrayStringA(count 0): ret=%d err=%s; the same ink %s", rv, le(), yesno(ink_of(&r, BG).count == k.count));
    canvas_fill(BG);
    arm();
    rv = GrayStringA(cv.dc, (HBRUSH)GetStockObject(BLACK_BRUSH), NULL, (LPARAM)"Gray", 4, 2, 2, 0, 0);
    line("GrayStringA(BLACK_BRUSH): ret=%d err=%s; black only %s", rv, le(),
         yesno(ink_of(&r, BG).count > 0 && count_of(0) == ink_of(&r, BG).count));

    gray_answer = TRUE;
    gray_calls = 0;
    canvas_fill(BG);
    arm();
    rv = GrayStringA(cv.dc, NULL, gray_proc, 0x4321, 4, 2, 2, z.cx, z.cy);
    line("GrayStringA(a callback answering TRUE, the extent given): ret=%d err=%s; %d call(s), the canvas's DC %s, "
         "data 0x%lX, count %d", rv, le(), gray_calls, yesno(gray_dc == cv.dc), (unsigned long)gray_data, gray_count);
    ink_line("  ", &r);
    gray_answer = FALSE;
    gray_calls = 0;
    canvas_fill(BG);
    arm();
    rv = GrayStringW(cv.dc, NULL, gray_proc, 0x4321, 4, 2, 2, z.cx, z.cy);
    line("GrayStringW(a callback answering FALSE): ret=%d err=%s; %d call(s)", rv, le(), gray_calls);
    ink_line("  ", &r);
    gray_answer = TRUE;
    gray_calls = 0;
    arm();
    rv = GrayStringA(cv.dc, NULL, gray_proc, 0x4321, 0, 2, 2, 0, 0);
    line("GrayStringA(a callback, count 0, no extent): ret=%d err=%s; %d call(s)", rv, le(), gray_calls);
    canvas_close();
}

/* --- caption ----------------------------------------------------------- */

static LRESULT CALLBACK cap_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    return DefWindowProcW(h, m, w, l);
}

static void caption(HWND h, const char *what, UINT flags)
{
    RECT r;
    BOOL rv;
    int act, inact, gact, ginact, face, txt, itxt;

    canvas_fill(BG);
    SetRect(&r, 0, 0, 160, GetSystemMetrics(SM_CYCAPTION) - 1);
    arm();
    rv = DrawCaption(h, cv.dc, &r, flags);
    act = count_of(dib(GetSysColor(COLOR_ACTIVECAPTION)));
    inact = count_of(dib(GetSysColor(COLOR_INACTIVECAPTION)));
    gact = count_of(dib(GetSysColor(COLOR_GRADIENTACTIVECAPTION)));
    ginact = count_of(dib(GetSysColor(COLOR_GRADIENTINACTIVECAPTION)));
    face = count_of(dib(GetSysColor(COLOR_3DFACE)));
    txt = count_of(dib(GetSysColor(COLOR_CAPTIONTEXT)));
    itxt = count_of(dib(GetSysColor(COLOR_INACTIVECAPTIONTEXT)));
    line("DrawCaption(%s): ret=%d err=%s", what, rv, le());
    line("  pixels of: COLOR_ACTIVECAPTION %s, INACTIVECAPTION %s, GRADIENTACTIVECAPTION %s, GRADIENTINACTIVECAPTION %s, "
         "3DFACE %s, CAPTIONTEXT %s, INACTIVECAPTIONTEXT %s; outside the rectangle %s",
         act ? "some" : "none", inact ? "some" : "none", gact ? "some" : "none", ginact ? "some" : "none",
         face ? "some" : "none", txt ? "some" : "none", itxt ? "some" : "none", ink_of(&r, BG).outside ? "some" : "none");
}

static void sec_caption(void)
{
    WNDCLASSW wc;
    HWND h;
    BOOL grad = FALSE;

    if (!canvas_open(170, 40)) {
        return;
    }
    SystemParametersInfoW(SPI_GETGRADIENTCAPTIONS, 0, &grad, 0);
    line("SPI_GETGRADIENTCAPTIONS: %d", grad);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = cap_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    wc.lpszClassName = L"F2KDrawhelpCap";
    RegisterClassW(&wc);
    h = CreateWindowExW(0, L"F2KDrawhelpCap", L"Caption", WS_POPUP | WS_CAPTION | WS_SYSMENU, 0, 0, 200, 100, NULL,
                        NULL, GetModuleHandleA(NULL), NULL);
    line("setup: the window created: %s", yesno(h != NULL));
    caption(h, "DC_ACTIVE", DC_ACTIVE);
    caption(h, "0", 0);
    caption(h, "DC_ACTIVE | DC_GRADIENT", DC_ACTIVE | DC_GRADIENT);
    caption(h, "DC_GRADIENT", DC_GRADIENT);
    caption(h, "DC_ACTIVE | DC_TEXT", DC_ACTIVE | DC_TEXT);
    caption(h, "DC_TEXT", DC_TEXT);
    caption(h, "DC_ACTIVE | DC_ICON | DC_TEXT", DC_ACTIVE | DC_ICON | DC_TEXT);
    caption(h, "DC_ACTIVE | DC_SMALLCAP | DC_TEXT", DC_ACTIVE | DC_SMALLCAP | DC_TEXT);
    caption(h, "DC_INBUTTON | DC_TEXT", DC_INBUTTON | DC_TEXT);
    caption(NULL, "a NULL window, DC_ACTIVE | DC_TEXT", DC_ACTIVE | DC_TEXT);
    DestroyWindow(h);
    canvas_close();
}

/* --- animated ---------------------------------------------------------- */

static void sec_animated(void)
{
    WNDCLASSW wc;
    HWND h;
    RECT from, to;
    BOOL rv;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = cap_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = L"F2KDrawhelpAni";
    RegisterClassW(&wc);
    h = CreateWindowExW(0, L"F2KDrawhelpAni", L"animated", WS_POPUP | WS_CAPTION, 0, 0, 100, 60, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    SetRect(&from, 10, 10, 110, 70);
    SetRect(&to, 200, 200, 240, 220);
    arm();
    rv = DrawAnimatedRects(h, IDANI_CAPTION, &from, &to);
    line("DrawAnimatedRects(IDANI_CAPTION): ret=%d err=%s", rv, le());
    arm();
    rv = DrawAnimatedRects(h, IDANI_OPEN, &from, &to);
    line("DrawAnimatedRects(IDANI_OPEN): ret=%d err=%s", rv, le());
    arm();
    rv = DrawAnimatedRects(h, 99, &from, &to);
    line("DrawAnimatedRects(id 99): ret=%d err=%s", rv, le());
    arm();
    rv = DrawAnimatedRects(NULL, IDANI_CAPTION, &from, &to);
    line("DrawAnimatedRects(a NULL window, IDANI_CAPTION): ret=%d err=%s", rv, le());
    DestroyWindow(h);
}

static const section_t sections[] = {
    { "fills", sec_fills, F2KT_ALWAYS },
    { "focus", sec_focus, F2KT_ALWAYS },
    { "edge", sec_edge, F2KT_ALWAYS },
    { "frame", sec_frame, F2KT_ALWAYS },
    { "text", sec_text, F2KT_ALWAYS },
    { "textex", sec_textex, F2KT_ALWAYS },
    { "tabbed", sec_tabbed, F2KT_ALWAYS },
    { "state", sec_state, F2KT_ALWAYS },
    { "gray", sec_gray, F2KT_ALWAYS },
    { "caption", sec_caption, F2KT_ALWAYS },
    { "animated", sec_animated, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("drawhelp", sections, argc, argv);
}
