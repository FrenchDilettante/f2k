/*
 * txlayout - gdi32's text layout and attributes over a memory DC's
 * default font, the stock SYSTEM_FONT: SetTextAlign/GetTextAlign
 * (every TA_ alignment, TA_UPDATECP), SetTextCharacterExtra/
 * GetTextCharacterExtra, SetTextJustification, GetTextExtentPointA,
 * GetTextExtentExPointA/W/I, GetTextExtentPointI, GetCharacterPlacement-
 * A/W, PolyTextOutA/W, and the charset calls: GetTextCharset,
 * GetTextCharsetInfo, TranslateCharsetInfo and GetFontLanguageInfo.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled white through its
 * bits pointer before each drawing and read back through it (GdiFlush
 * first). Text is drawn black on a green opaque background, so the
 * pixels it touches are exactly its character cells: a drawing prints
 * as the box of the pixels that are not white (inclusive), and the
 * number of green ones, which depend only on the font's widths and
 * metrics and never on its glyphs' shapes.
 *
 * The font is the memory DC's default, the stock SYSTEM_FONT, whose
 * widths and metrics print first (tmHeight, tmAscent, tmDescent and the
 * extent of the strings used): every position below follows from them.
 * F2K's boot carries the system's fonts (system_fonts), as guidc's.
 *
 * GetTextExtentPointI, GetTextExtentExPointI and GetGlyphIndicesW are
 * Windows 2000's additions: the program finds them with GetProcAddress,
 * as MSVC 6's headers and import library may lack them, and says so
 * when gdi32 does not export them. Glyph indices print only as
 * relations (an extent through them against the same text's).
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   metrics    the font's tmHeight, tmAscent, tmDescent, tmBreakChar
 *              and the extents of "Ab", "Hello" and "a b c"
 *   align      GetTextAlign of a new DC; SetTextAlign's previous value
 *              for each TA_ combination, an undefined bit, and a NULL
 *              DC; TextOutA("Ab") at 48,24 under each horizontal and
 *              vertical alignment, its cell box
 *   updatecp   TA_UPDATECP with TA_LEFT, TA_RIGHT and TA_CENTER:
 *              TextOutA's own coordinates ignored, the current
 *              position before and after, the cell box; ExtTextOutA
 *              with an advances array under it
 *   extra      GetTextCharacterExtra of a new DC, SetTextCharacterExtra
 *              3, -2 and a NULL DC, GetTextExtentPoint32A of "Hello"
 *              under each, and "Ab" drawn with 4
 *   justify    SetTextJustification(10, 2) over "a b c": the extent,
 *              the cell box; 11 over 2 breaks; breaks 0; a negative
 *              extra; cleared; a NULL DC
 *   extentex   GetTextExtentExPointA/W of "Hello world" with maximum
 *              extents 0, 20, 40 and the whole, the fit and the
 *              partial extents, NULL fit and NULL array; a count of 0;
 *              GetTextExtentPointA/W; GetGlyphIndicesW, and
 *              GetTextExtentPointI and GetTextExtentExPointI over the
 *              indices against the text's extents
 *   placement  GetCharacterPlacementA/W of "Hello" with no flags, the
 *              advances, carets, order and the returned size; with
 *              GCP_MAXEXTENT under 20; with a NULL GCP_RESULTS; a
 *              count of 0
 *   polytext   PolyTextOutA/W of two strings at two places, each one's
 *              cell box; with ETO_OPAQUE and a rectangle; a count of 0
 *   charset    GetTextCharset, GetTextCharsetInfo (its FONTSIGNATURE in
 *              hex, and with NULL), GetFontLanguageInfo of the font;
 *              TranslateCharsetInfo from charsets 0, 2, 128, 161, 204,
 *              238, 255 and 99, from code pages 1252, 1250, 932, 437
 *              and 0, and from font signatures; an unknown flag
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat txlayout):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% txlayout.c gdi32.lib
 */

#include "../common/f2kt.h"

/* Windows 2000's additions, which MSVC 6's headers may lack. */
#ifndef TA_RTLREADING
#define TA_RTLREADING 256
#endif
#ifndef GGI_MARK_NONEXISTING_GLYPHS
#define GGI_MARK_NONEXISTING_GLYPHS 0x0001
#endif

typedef BOOL (WINAPI *extent_i_fn)(HDC, LPWORD, int, LPSIZE);
typedef BOOL (WINAPI *extent_ex_i_fn)(HDC, LPWORD, int, int, LPINT, LPINT, LPSIZE);
typedef DWORD (WINAPI *glyph_indices_fn)(HDC, LPCWSTR, int, LPWORD, DWORD);

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
    /* Black text on a green opaque background. */
    SetTextColor(c->dc, RGB(0, 0, 0));
    SetBkColor(c->dc, RGB(0, 255, 0));
    SetBkMode(c->dc, OPAQUE);
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

static void canvas_clear(canvas_t *c)
{
    int i;

    GdiFlush();
    for (i = 0; i < c->w * c->h; i++) {
        c->bits[i] = 0x00FFFFFF;
    }
}

/* The box of the pixels in rows y0..y1-1 that are not white, and how
 * many are green, as text. Rotates through a few buffers, as le() does. */
static const char *box_rows(canvas_t *c, int y0, int y1)
{
    static char bufs[4][96];
    static int next;
    char *b = bufs[next++ & 3];
    int x, y, l = c->w, r = -1, t = c->h, btm = -1, green = 0;
    DWORD v;

    GdiFlush();
    for (y = y0; y < y1; y++) {
        for (x = 0; x < c->w; x++) {
            v = c->bits[y * c->w + x] & 0x00FFFFFF;
            if (v == 0x00FFFFFF) {
                continue;
            }
            if (v == 0x0000FF00) {
                green++;
            }
            if (x < l) l = x;
            if (x > r) r = x;
            if (y < t) t = y;
            if (y > btm) btm = y;
        }
    }
    if (r < 0) {
        sprintf(b, "box empty");
    } else {
        sprintf(b, "box x %d..%d y %d..%d, green %d", l, r, t, btm, green);
    }
    return b;
}

static const char *box(canvas_t *c)
{
    return box_rows(c, 0, c->h);
}

/* n ints as a list. Rotates through a few buffers. */
static const char *ints(const int *p, int n)
{
    static char bufs[4][256];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    b[0] = '\0';
    for (i = 0; i < n && k < (int)sizeof bufs[0] - 12; i++) {
        k += sprintf(b + k, "%s%d", i ? " " : "", p[i]);
    }
    return b;
}

static const char *uints(const UINT *p, int n)
{
    int v[32];
    int i;

    for (i = 0; i < n && i < 32; i++) {
        v[i] = (int)p[i];
    }
    return ints(v, i);
}

/* A TA_ value by its flags' names. Rotates through a few buffers. */
static const char *ta_name(UINT v)
{
    static char bufs[4][96];
    static int next;
    char *b = bufs[next++ & 3];

    if (v == GDI_ERROR) {
        return "GDI_ERROR";
    }
    sprintf(b, "%s|%s|%s",
            (v & TA_CENTER) == TA_CENTER ? "TA_CENTER" : (v & TA_RIGHT) ? "TA_RIGHT" : "TA_LEFT",
            (v & TA_BASELINE) == TA_BASELINE ? "TA_BASELINE" : (v & TA_BOTTOM) ? "TA_BOTTOM" : "TA_TOP",
            (v & TA_UPDATECP) ? "TA_UPDATECP" : "TA_NOUPDATECP");
    if (v & ~(UINT)(TA_CENTER | TA_BASELINE | TA_UPDATECP | TA_RTLREADING)) {
        sprintf(b + strlen(b), " (0x%X)", v);
    } else if (v & TA_RTLREADING) {
        strcat(b, "|TA_RTLREADING");
    }
    return b;
}

static FARPROC gdi_proc(const char *name)
{
    FARPROC p = GetProcAddress(GetModuleHandleA("gdi32.dll"), name);

    if (p == NULL) {
        line("%s: not exported by gdi32", name);
    }
    return p;
}

/* --- metrics ------------------------------------------------------- */

static void sec_metrics(void)
{
    canvas_t c;
    TEXTMETRICA tm;
    SIZE sz;
    BOOL r;

    if (!canvas_open(&c, 8, 8)) {
        return;
    }
    ZeroMemory(&tm, sizeof tm);
    arm();
    r = GetTextMetricsA(c.dc, &tm);
    line("GetTextMetricsA: ret=%d err=%s tmHeight=%ld tmAscent=%ld tmDescent=%ld tmBreakChar=%d"
         " tmCharSet=%d", r, le(), (long)tm.tmHeight, (long)tm.tmAscent, (long)tm.tmDescent,
         tm.tmBreakChar, tm.tmCharSet);
    GetTextExtentPoint32A(c.dc, "Ab", 2, &sz);
    line("extent of \"Ab\": %ld,%ld", (long)sz.cx, (long)sz.cy);
    GetTextExtentPoint32A(c.dc, "Hello", 5, &sz);
    line("extent of \"Hello\": %ld,%ld", (long)sz.cx, (long)sz.cy);
    GetTextExtentPoint32A(c.dc, "a b c", 5, &sz);
    line("extent of \"a b c\": %ld,%ld", (long)sz.cx, (long)sz.cy);
    GetTextExtentPoint32A(c.dc, " ", 1, &sz);
    line("extent of \" \": %ld,%ld", (long)sz.cx, (long)sz.cy);
    canvas_close(&c);
}

/* --- align --------------------------------------------------------- */

static const struct ta_s {
    const char *name;
    UINT ta;
} aligns[] = {
    { "TA_LEFT|TA_TOP", TA_LEFT | TA_TOP },
    { "TA_CENTER|TA_TOP", TA_CENTER | TA_TOP },
    { "TA_RIGHT|TA_TOP", TA_RIGHT | TA_TOP },
    { "TA_LEFT|TA_BASELINE", TA_LEFT | TA_BASELINE },
    { "TA_LEFT|TA_BOTTOM", TA_LEFT | TA_BOTTOM },
    { "TA_CENTER|TA_BASELINE", TA_CENTER | TA_BASELINE },
    { "TA_RIGHT|TA_BOTTOM", TA_RIGHT | TA_BOTTOM },
    { NULL, 0 }
};

static void sec_align(void)
{
    canvas_t c;
    UINT prev, got;
    BOOL r;
    int i;

    if (!canvas_open(&c, 96, 48)) {
        return;
    }
    arm();
    got = GetTextAlign(c.dc);
    line("GetTextAlign(a new DC): ret=%s err=%s", ta_name(got), le());
    for (i = 0; aligns[i].name != NULL; i++) {
        arm();
        prev = SetTextAlign(c.dc, aligns[i].ta);
        got = GetTextAlign(c.dc);
        line("SetTextAlign(%s): previous=%s err=%s now=%s", aligns[i].name, ta_name(prev), le(),
             ta_name(got));
        canvas_clear(&c);
        arm();
        r = TextOutA(c.dc, 48, 24, "Ab", 2);
        line("  TextOutA(48, 24, \"Ab\"): ret=%d err=%s %s", r, le(), box(&c));
    }
    arm();
    prev = SetTextAlign(c.dc, TA_RTLREADING);
    line("SetTextAlign(TA_RTLREADING): previous=%s err=%s now=%s", ta_name(prev), le(),
         ta_name(GetTextAlign(c.dc)));
    arm();
    prev = SetTextAlign(c.dc, 0x1000);
    line("SetTextAlign(0x1000): previous=%s err=%s now=%s", ta_name(prev), le(),
         ta_name(GetTextAlign(c.dc)));
    arm();
    prev = SetTextAlign(c.dc, TA_RIGHT | TA_BASELINE | TA_UPDATECP);
    line("SetTextAlign(TA_RIGHT|TA_BASELINE|TA_UPDATECP): previous=%s err=%s now=%s", ta_name(prev),
         le(), ta_name(GetTextAlign(c.dc)));
    arm();
    prev = SetTextAlign(NULL, TA_CENTER);
    line("SetTextAlign(NULL, TA_CENTER): ret=%s err=%s", ta_name(prev), le());
    arm();
    got = GetTextAlign(NULL);
    line("GetTextAlign(NULL): ret=%s err=%s", ta_name(got), le());
    canvas_close(&c);
}

/* --- updatecp ------------------------------------------------------ */

static void sec_updatecp(void)
{
    static const struct ta_s cps[] = {
        { "TA_LEFT|TA_UPDATECP", TA_LEFT | TA_UPDATECP },
        { "TA_RIGHT|TA_UPDATECP", TA_RIGHT | TA_UPDATECP },
        { "TA_CENTER|TA_UPDATECP", TA_CENTER | TA_UPDATECP },
        { "TA_LEFT|TA_BASELINE|TA_UPDATECP", TA_LEFT | TA_BASELINE | TA_UPDATECP },
        { NULL, 0 }
    };
    static const int dx[3] = { 10, 12, 14 };
    canvas_t c;
    POINT p;
    BOOL r;
    int i;

    if (!canvas_open(&c, 96, 48)) {
        return;
    }
    for (i = 0; cps[i].name != NULL; i++) {
        SetTextAlign(c.dc, cps[i].ta);
        canvas_clear(&c);
        MoveToEx(c.dc, 40, 10, NULL);
        arm();
        r = TextOutA(c.dc, 5, 30, "Ab", 2);
        GetCurrentPositionEx(c.dc, &p);
        line("%s: MoveToEx(40, 10), TextOutA(5, 30, \"Ab\"): ret=%d err=%s position=%ld,%ld %s",
             cps[i].name, r, le(), (long)p.x, (long)p.y, box(&c));
        arm();
        r = TextOutA(c.dc, 5, 30, "Ab", 2);
        GetCurrentPositionEx(c.dc, &p);
        line("  again: ret=%d err=%s position=%ld,%ld", r, le(), (long)p.x, (long)p.y);
    }
    SetTextAlign(c.dc, TA_LEFT | TA_UPDATECP);
    canvas_clear(&c);
    MoveToEx(c.dc, 20, 10, NULL);
    arm();
    r = ExtTextOutA(c.dc, 0, 0, 0, NULL, "abc", 3, dx);
    GetCurrentPositionEx(c.dc, &p);
    line("TA_LEFT|TA_UPDATECP: MoveToEx(20, 10), ExtTextOutA(\"abc\", dx 10 12 14): ret=%d err=%s"
         " position=%ld,%ld %s", r, le(), (long)p.x, (long)p.y, box(&c));
    SetTextAlign(c.dc, TA_LEFT | TA_TOP);
    MoveToEx(c.dc, 20, 10, NULL);
    TextOutA(c.dc, 0, 0, "Ab", 2);
    GetCurrentPositionEx(c.dc, &p);
    line("TA_NOUPDATECP: TextOutA after MoveToEx(20, 10): position=%ld,%ld", (long)p.x, (long)p.y);
    canvas_close(&c);
}

/* --- extra --------------------------------------------------------- */

static void sec_extra(void)
{
    canvas_t c;
    SIZE sz;
    int prev, got;
    BOOL r;

    if (!canvas_open(&c, 96, 32)) {
        return;
    }
    arm();
    got = GetTextCharacterExtra(c.dc);
    line("GetTextCharacterExtra(a new DC): ret=%d err=%s", got, le());
    arm();
    prev = SetTextCharacterExtra(c.dc, 3);
    line("SetTextCharacterExtra(3): previous=%d err=%s now=%d", prev, le(), GetTextCharacterExtra(c.dc));
    arm();
    r = GetTextExtentPoint32A(c.dc, "Hello", 5, &sz);
    line("  GetTextExtentPoint32A(\"Hello\"): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    arm();
    prev = SetTextCharacterExtra(c.dc, -2);
    line("SetTextCharacterExtra(-2): previous=%d err=%s now=%d", prev, le(), GetTextCharacterExtra(c.dc));
    GetTextExtentPoint32A(c.dc, "Hello", 5, &sz);
    line("  GetTextExtentPoint32A(\"Hello\"): %ld,%ld", (long)sz.cx, (long)sz.cy);
    SetTextCharacterExtra(c.dc, 4);
    canvas_clear(&c);
    arm();
    r = TextOutA(c.dc, 10, 8, "Ab", 2);
    line("extra 4: TextOutA(10, 8, \"Ab\"): ret=%d err=%s %s", r, le(), box(&c));
    SetTextCharacterExtra(c.dc, 0);
    canvas_clear(&c);
    TextOutA(c.dc, 10, 8, "Ab", 2);
    line("extra 0: TextOutA(10, 8, \"Ab\"): %s", box(&c));
    arm();
    prev = SetTextCharacterExtra(NULL, 1);
    line("SetTextCharacterExtra(NULL, 1): ret=0x%X err=%s", (unsigned)prev, le());
    arm();
    got = GetTextCharacterExtra(NULL);
    line("GetTextCharacterExtra(NULL): ret=0x%X err=%s", (unsigned)got, le());
    canvas_close(&c);
}

/* --- justify ------------------------------------------------------- */

static void sec_justify(void)
{
    canvas_t c;
    SIZE sz;
    BOOL r;

    if (!canvas_open(&c, 96, 32)) {
        return;
    }
    arm();
    r = SetTextJustification(c.dc, 10, 2);
    line("SetTextJustification(10, 2): ret=%d err=%s", r, le());
    GetTextExtentPoint32A(c.dc, "a b c", 5, &sz);
    line("  GetTextExtentPoint32A(\"a b c\"): %ld,%ld", (long)sz.cx, (long)sz.cy);
    canvas_clear(&c);
    TextOutA(c.dc, 10, 8, "a b c", 5);
    line("  TextOutA(10, 8, \"a b c\"): %s", box(&c));
    canvas_clear(&c);
    TextOutA(c.dc, 10, 8, "a b c", 5);
    line("  drawn again: %s", box(&c));

    arm();
    r = SetTextJustification(c.dc, 11, 2);
    line("SetTextJustification(11, 2): ret=%d err=%s", r, le());
    GetTextExtentPoint32A(c.dc, "a b c", 5, &sz);
    line("  GetTextExtentPoint32A(\"a b c\"): %ld,%ld", (long)sz.cx, (long)sz.cy);
    GetTextExtentPoint32A(c.dc, "a b", 3, &sz);
    line("  GetTextExtentPoint32A(\"a b\"): %ld,%ld", (long)sz.cx, (long)sz.cy);
    canvas_clear(&c);
    TextOutA(c.dc, 10, 8, "a b c", 5);
    line("  TextOutA(10, 8, \"a b c\"): %s", box(&c));

    arm();
    r = SetTextJustification(c.dc, 6, 0);
    line("SetTextJustification(6, 0): ret=%d err=%s", r, le());
    GetTextExtentPoint32A(c.dc, "a b c", 5, &sz);
    line("  GetTextExtentPoint32A(\"a b c\"): %ld,%ld", (long)sz.cx, (long)sz.cy);

    arm();
    r = SetTextJustification(c.dc, -4, 2);
    line("SetTextJustification(-4, 2): ret=%d err=%s", r, le());
    GetTextExtentPoint32A(c.dc, "a b c", 5, &sz);
    line("  GetTextExtentPoint32A(\"a b c\"): %ld,%ld", (long)sz.cx, (long)sz.cy);

    arm();
    r = SetTextJustification(c.dc, 0, 0);
    line("SetTextJustification(0, 0): ret=%d err=%s", r, le());
    GetTextExtentPoint32A(c.dc, "a b c", 5, &sz);
    line("  GetTextExtentPoint32A(\"a b c\"): %ld,%ld", (long)sz.cx, (long)sz.cy);

    arm();
    r = SetTextJustification(NULL, 10, 2);
    line("SetTextJustification(NULL, 10, 2): ret=%d err=%s", r, le());
    canvas_close(&c);
}

/* --- extentex ------------------------------------------------------ */

static void sec_extentex(void)
{
    static const int maxes[] = { 0, 20, 40, 1000 };
    static const WCHAR textw[] = L"Hello world";
    canvas_t c;
    int dx[16], fit, i;
    SIZE sz, whole, wsz;
    WORD gi[16];
    DWORD n;
    BOOL r;
    extent_i_fn extent_i;
    extent_ex_i_fn extent_ex_i;
    glyph_indices_fn indices;

    if (!canvas_open(&c, 8, 8)) {
        return;
    }
    GetTextExtentPoint32A(c.dc, "Hello world", 11, &whole);
    line("GetTextExtentPoint32A(\"Hello world\"): %ld,%ld", (long)whole.cx, (long)whole.cy);
    for (i = 0; i < 4; i++) {
        ZeroMemory(dx, sizeof dx);
        fit = -1;
        arm();
        r = GetTextExtentExPointA(c.dc, "Hello world", 11, maxes[i], &fit, dx, &sz);
        line("GetTextExtentExPointA(\"Hello world\", max %d): ret=%d err=%s fit=%d size=%ld,%ld dx=%s",
             maxes[i], r, le(), fit, (long)sz.cx, (long)sz.cy, ints(dx, fit > 0 && fit <= 11 ? fit : 0));
        ZeroMemory(dx, sizeof dx);
        fit = -1;
        arm();
        r = GetTextExtentExPointW(c.dc, textw, 11, maxes[i], &fit, dx, &sz);
        line("GetTextExtentExPointW(L\"Hello world\", max %d): ret=%d err=%s fit=%d size=%ld,%ld dx=%s",
             maxes[i], r, le(), fit, (long)sz.cx, (long)sz.cy, ints(dx, fit > 0 && fit <= 11 ? fit : 0));
    }
    ZeroMemory(dx, sizeof dx);
    arm();
    r = GetTextExtentExPointA(c.dc, "Hello", 5, 20, NULL, dx, &sz);
    line("GetTextExtentExPointA(\"Hello\", max 20, NULL fit): ret=%d err=%s size=%ld,%ld dx=%s", r, le(),
         (long)sz.cx, (long)sz.cy, ints(dx, 5));
    fit = -1;
    arm();
    r = GetTextExtentExPointA(c.dc, "Hello", 5, 20, &fit, NULL, &sz);
    line("GetTextExtentExPointA(\"Hello\", max 20, NULL dx): ret=%d err=%s fit=%d size=%ld,%ld", r, le(),
         fit, (long)sz.cx, (long)sz.cy);
    fit = -1;
    sz.cx = sz.cy = -1;
    arm();
    r = GetTextExtentExPointA(c.dc, "Hello", 0, 20, &fit, dx, &sz);
    line("GetTextExtentExPointA(count 0): ret=%d err=%s fit=%d size=%ld,%ld", r, le(), fit, (long)sz.cx,
         (long)sz.cy);
    ZeroMemory(dx, sizeof dx);
    fit = -1;
    arm();
    r = GetTextExtentExPointA(c.dc, "Hello", 5, -1, &fit, dx, &sz);
    line("GetTextExtentExPointA(\"Hello\", max -1): ret=%d err=%s fit=%d size=%ld,%ld", r, le(), fit,
         (long)sz.cx, (long)sz.cy);

    arm();
    r = GetTextExtentPointA(c.dc, "Hello", 5, &sz);
    line("GetTextExtentPointA(\"Hello\"): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    arm();
    r = GetTextExtentPointW(c.dc, L"Hello", 5, &sz);
    line("GetTextExtentPointW(L\"Hello\"): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    arm();
    r = GetTextExtentPointA(c.dc, "Hello", 0, &sz);
    line("GetTextExtentPointA(count 0): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);

    indices = (glyph_indices_fn)gdi_proc("GetGlyphIndicesW");
    extent_i = (extent_i_fn)gdi_proc("GetTextExtentPointI");
    extent_ex_i = (extent_ex_i_fn)gdi_proc("GetTextExtentExPointI");
    if (indices == NULL || extent_i == NULL || extent_ex_i == NULL) {
        canvas_close(&c);
        return;
    }
    ZeroMemory(gi, sizeof gi);
    arm();
    n = indices(c.dc, textw, 11, gi, GGI_MARK_NONEXISTING_GLYPHS);
    line("GetGlyphIndicesW(L\"Hello world\"): ret=%ld err=%s 'l' twice the same index: %s,"
         " 'H' and 'e' differ: %s", (long)n, le(), yesno(gi[2] == gi[3]), yesno(gi[0] != gi[1]));
    GetTextExtentPoint32W(c.dc, textw, 11, &wsz);
    arm();
    r = extent_i(c.dc, gi, 11, &sz);
    line("GetTextExtentPointI(the indices): ret=%d err=%s the same as GetTextExtentPoint32W's: %s", r,
         le(), yesno(sz.cx == wsz.cx && sz.cy == wsz.cy));
    ZeroMemory(dx, sizeof dx);
    fit = -1;
    arm();
    r = extent_ex_i(c.dc, gi, 11, 40, &fit, dx, &sz);
    {
        int dxw[16], fitw = -2;
        SIZE szw;

        ZeroMemory(dxw, sizeof dxw);
        GetTextExtentExPointW(c.dc, textw, 11, 40, &fitw, dxw, &szw);
        line("GetTextExtentExPointI(the indices, max 40): ret=%d err=%s fit, dx and size the same as"
             " GetTextExtentExPointW's: %s %s %s", r, le(), yesno(fit == fitw),
             yesno(memcmp(dx, dxw, sizeof dx) == 0), yesno(sz.cx == szw.cx && sz.cy == szw.cy));
    }
    arm();
    r = extent_i(c.dc, gi, 0, &sz);
    line("GetTextExtentPointI(count 0): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    canvas_close(&c);
}

/* --- placement ----------------------------------------------------- */

static void placement_a(HDC dc, const char *what, DWORD flags, int max)
{
    GCP_RESULTSA gr;
    char out[16];
    UINT order[16];
    int dx[16], caret[16];
    DWORD r;

    ZeroMemory(&gr, sizeof gr);
    ZeroMemory(out, sizeof out);
    ZeroMemory(order, sizeof order);
    ZeroMemory(dx, sizeof dx);
    ZeroMemory(caret, sizeof caret);
    gr.lStructSize = sizeof gr;
    gr.lpOutString = out;
    gr.lpOrder = order;
    gr.lpDx = dx;
    gr.lpCaretPos = caret;
    gr.nGlyphs = 16;
    arm();
    r = GetCharacterPlacementA(dc, "Hello", 5, max, &gr, flags);
    line("GetCharacterPlacementA(\"Hello\", %s): ret=%lu,%lu err=%s nGlyphs=%u nMaxFit=%d out=\"%s\"",
         what, (unsigned long)LOWORD(r), (unsigned long)HIWORD(r), le(), gr.nGlyphs, gr.nMaxFit, out);
    line("  dx=%s caret=%s order=%s", ints(dx, 5), ints(caret, 5), uints(order, 5));
}

static void placement_w(HDC dc, const char *what, DWORD flags, int max)
{
    GCP_RESULTSW gr;
    WCHAR out[16];
    UINT order[16];
    int dx[16], caret[16];
    DWORD r;

    ZeroMemory(&gr, sizeof gr);
    ZeroMemory(out, sizeof out);
    ZeroMemory(order, sizeof order);
    ZeroMemory(dx, sizeof dx);
    ZeroMemory(caret, sizeof caret);
    gr.lStructSize = sizeof gr;
    gr.lpOutString = out;
    gr.lpOrder = order;
    gr.lpDx = dx;
    gr.lpCaretPos = caret;
    gr.nGlyphs = 16;
    arm();
    r = GetCharacterPlacementW(dc, L"Hello", 5, max, &gr, flags);
    line("GetCharacterPlacementW(L\"Hello\", %s): ret=%lu,%lu err=%s nGlyphs=%u nMaxFit=%d out=\"%s\"",
         what, (unsigned long)LOWORD(r), (unsigned long)HIWORD(r), le(), gr.nGlyphs, gr.nMaxFit, ws(out));
    line("  dx=%s caret=%s order=%s", ints(dx, 5), ints(caret, 5), uints(order, 5));
}

static void sec_placement(void)
{
    canvas_t c;
    GCP_RESULTSA gr;
    DWORD r;
    SIZE sz;

    if (!canvas_open(&c, 8, 8)) {
        return;
    }
    GetTextExtentPoint32A(c.dc, "Hello", 5, &sz);
    line("extent of \"Hello\": %ld,%ld", (long)sz.cx, (long)sz.cy);
    placement_a(c.dc, "0", 0, 0);
    placement_w(c.dc, "0", 0, 0);
    placement_a(c.dc, "GCP_MAXEXTENT, 20", GCP_MAXEXTENT, 20);
    placement_w(c.dc, "GCP_MAXEXTENT, 20", GCP_MAXEXTENT, 20);
    arm();
    r = GetCharacterPlacementA(c.dc, "Hello", 5, 0, NULL, 0);
    line("GetCharacterPlacementA(\"Hello\", NULL results): ret=%lu,%lu err=%s", (unsigned long)LOWORD(r),
         (unsigned long)HIWORD(r), le());
    arm();
    r = GetCharacterPlacementW(c.dc, L"Hello", 5, 0, NULL, 0);
    line("GetCharacterPlacementW(L\"Hello\", NULL results): ret=%lu,%lu err=%s", (unsigned long)LOWORD(r),
         (unsigned long)HIWORD(r), le());
    ZeroMemory(&gr, sizeof gr);
    gr.lStructSize = sizeof gr;
    arm();
    r = GetCharacterPlacementA(c.dc, "Hello", 0, 0, &gr, 0);
    line("GetCharacterPlacementA(count 0): ret=%lu,%lu err=%s", (unsigned long)LOWORD(r),
         (unsigned long)HIWORD(r), le());
    canvas_close(&c);
}

/* --- polytext ------------------------------------------------------ */

static void sec_polytext(void)
{
    canvas_t c;
    POLYTEXTA pa[2];
    POLYTEXTW pw[2];
    BOOL r;

    if (!canvas_open(&c, 96, 48)) {
        return;
    }
    ZeroMemory(pa, sizeof pa);
    pa[0].x = 4;
    pa[0].y = 2;
    pa[0].n = 2;
    pa[0].lpstr = "Ab";
    pa[1].x = 30;
    pa[1].y = 26;
    pa[1].n = 3;
    pa[1].lpstr = "abc";
    canvas_clear(&c);
    arm();
    r = PolyTextOutA(c.dc, pa, 2);
    line("PolyTextOutA(\"Ab\" at 4,2; \"abc\" at 30,26): ret=%d err=%s", r, le());
    line("  rows 0-23: %s", box_rows(&c, 0, 24));
    line("  rows 24-47: %s", box_rows(&c, 24, 48));

    ZeroMemory(pw, sizeof pw);
    pw[0].x = 4;
    pw[0].y = 2;
    pw[0].n = 2;
    pw[0].lpstr = L"Ab";
    pw[1].x = 30;
    pw[1].y = 26;
    pw[1].n = 3;
    pw[1].lpstr = L"abc";
    canvas_clear(&c);
    arm();
    r = PolyTextOutW(c.dc, pw, 2);
    line("PolyTextOutW(L\"Ab\" at 4,2; L\"abc\" at 30,26): ret=%d err=%s", r, le());
    line("  rows 0-23: %s", box_rows(&c, 0, 24));
    line("  rows 24-47: %s", box_rows(&c, 24, 48));

    pa[1].uiFlags = ETO_OPAQUE;
    pa[1].rcl.left = 20;
    pa[1].rcl.top = 24;
    pa[1].rcl.right = 90;
    pa[1].rcl.bottom = 46;
    canvas_clear(&c);
    arm();
    r = PolyTextOutA(c.dc, pa, 2);
    line("PolyTextOutA, the second ETO_OPAQUE over 20,24-90,46: ret=%d err=%s", r, le());
    line("  rows 0-23: %s", box_rows(&c, 0, 24));
    line("  rows 24-47: %s", box_rows(&c, 24, 48));

    canvas_clear(&c);
    arm();
    r = PolyTextOutA(c.dc, pa, 0);
    line("PolyTextOutA(count 0): ret=%d err=%s %s", r, le(), box(&c));
    canvas_close(&c);
}

/* --- charset ------------------------------------------------------- */

static void print_ci(const char *what, BOOL r, const CHARSETINFO *ci)
{
    line("TranslateCharsetInfo(%s): ret=%d err=%s ciCharset=%u ciACP=%u fsCsb=0x%08lX,0x%08lX"
         " fsUsb=0x%08lX,0x%08lX,0x%08lX,0x%08lX", what, r, le(), ci->ciCharset, ci->ciACP,
         (unsigned long)ci->fs.fsCsb[0], (unsigned long)ci->fs.fsCsb[1],
         (unsigned long)ci->fs.fsUsb[0], (unsigned long)ci->fs.fsUsb[1],
         (unsigned long)ci->fs.fsUsb[2], (unsigned long)ci->fs.fsUsb[3]);
}

static void sec_charset(void)
{
    static const UINT charsets[] = { 0, 2, 128, 161, 204, 238, 255, 99 };
    static const UINT pages[] = { 1252, 1250, 932, 437, 0 };
    static DWORD sigs[][2] = { { 0x00000001, 0 }, { 0x00000002, 0 }, { 0x00020000, 0 },
                               { 0x00000006, 0 }, { 0, 0 } };
    canvas_t c;
    FONTSIGNATURE fs;
    CHARSETINFO ci;
    char what[64];
    int cs;
    DWORD info;
    BOOL r;
    int i;

    if (!canvas_open(&c, 8, 8)) {
        return;
    }
    arm();
    cs = GetTextCharset(c.dc);
    line("GetTextCharset(SYSTEM_FONT): ret=%d err=%s", cs, le());
    ZeroMemory(&fs, sizeof fs);
    arm();
    cs = GetTextCharsetInfo(c.dc, &fs, 0);
    line("GetTextCharsetInfo(SYSTEM_FONT): ret=%d err=%s fsCsb=0x%08lX,0x%08lX"
         " fsUsb=0x%08lX,0x%08lX,0x%08lX,0x%08lX", cs, le(), (unsigned long)fs.fsCsb[0],
         (unsigned long)fs.fsCsb[1], (unsigned long)fs.fsUsb[0], (unsigned long)fs.fsUsb[1],
         (unsigned long)fs.fsUsb[2], (unsigned long)fs.fsUsb[3]);
    arm();
    cs = GetTextCharsetInfo(c.dc, NULL, 0);
    line("GetTextCharsetInfo(SYSTEM_FONT, NULL): ret=%d err=%s", cs, le());
    arm();
    info = GetFontLanguageInfo(c.dc);
    line("GetFontLanguageInfo(SYSTEM_FONT): ret=0x%08lX err=%s", (unsigned long)info, le());
    arm();
    cs = GetTextCharset(NULL);
    line("GetTextCharset(NULL): ret=%d err=%s", cs, le());
    arm();
    info = GetFontLanguageInfo(NULL);
    line("GetFontLanguageInfo(NULL): ret=0x%08lX err=%s", (unsigned long)info, le());

    for (i = 0; i < (int)(sizeof charsets / sizeof charsets[0]); i++) {
        ZeroMemory(&ci, sizeof ci);
        arm();
        r = TranslateCharsetInfo((DWORD *)(DWORD)charsets[i], &ci, TCI_SRCCHARSET);
        sprintf(what, "%u, TCI_SRCCHARSET", charsets[i]);
        print_ci(what, r, &ci);
    }
    for (i = 0; i < (int)(sizeof pages / sizeof pages[0]); i++) {
        ZeroMemory(&ci, sizeof ci);
        arm();
        r = TranslateCharsetInfo((DWORD *)(DWORD)pages[i], &ci, TCI_SRCCODEPAGE);
        sprintf(what, "%u, TCI_SRCCODEPAGE", pages[i]);
        print_ci(what, r, &ci);
    }
    for (i = 0; i < (int)(sizeof sigs / sizeof sigs[0]); i++) {
        ZeroMemory(&ci, sizeof ci);
        arm();
        r = TranslateCharsetInfo(sigs[i], &ci, TCI_SRCFONTSIG);
        sprintf(what, "fsCsb 0x%08lX, TCI_SRCFONTSIG", (unsigned long)sigs[i][0]);
        print_ci(what, r, &ci);
    }
    ZeroMemory(&ci, sizeof ci);
    arm();
    r = TranslateCharsetInfo((DWORD *)(DWORD)0, &ci, 7);
    print_ci("0, flag 7", r, &ci);
    canvas_close(&c);
}

static const section_t sections[] = {
    { "metrics", sec_metrics, F2KT_ALWAYS },
    { "align", sec_align, F2KT_ALWAYS },
    { "updatecp", sec_updatecp, F2KT_ALWAYS },
    { "extra", sec_extra, F2KT_ALWAYS },
    { "justify", sec_justify, F2KT_ALWAYS },
    { "extentex", sec_extentex, F2KT_ALWAYS },
    { "placement", sec_placement, F2KT_ALWAYS },
    { "polytext", sec_polytext, F2KT_ALWAYS },
    { "charset", sec_charset, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("txlayout", sections, argc, argv);
}
