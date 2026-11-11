/*
 * mapmode - a DC's coordinate spaces and its saved states: SetMapMode
 * and GetMapMode across every mode, SetWindowExtEx/GetWindowExtEx,
 * SetViewportExtEx/GetViewportExtEx, SetWindowOrgEx/GetWindowOrgEx and
 * SetViewportOrgEx/GetViewportOrgEx, LPtoDP and DPtoLP and their
 * rounding, OffsetViewportOrgEx, OffsetWindowOrgEx, ScaleViewportExtEx
 * and ScaleWindowExtEx, MM_ISOTROPIC's adjustment of the viewport,
 * drawing through a mapping, and SaveDC/RestoreDC, relative and
 * absolute.
 *
 * Every DC is a memory DC (CreateCompatibleDC of NULL). The metric
 * modes' extents and MM_ISOTROPIC's adjusted viewport follow the
 * screen's size in millimeters and in pixels (GetDeviceCaps' HORZSIZE,
 * VERTSIZE, HORZRES and VERTRES), which differ from machine to machine:
 * they print only as relations (their signs, the units per pixel the
 * mode means within 1%, the same as another mode's or not). MM_TEXT's
 * and MM_ANISOTROPIC's extents, origins and points are the program's
 * own and print as numbers.
 *
 * The drawing surface is a canvas: a memory DC holding a 32-bit
 * top-down DIB section, filled white through its bits pointer and read
 * back through it (GdiFlush first) as rows of letters: # black,
 * . white, R red, ? any other (counted).
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   modes      GetMapMode of a new DC; SetMapMode to MM_LOMETRIC,
 *              MM_HIMETRIC, MM_LOENGLISH, MM_HIENGLISH, MM_TWIPS,
 *              MM_ISOTROPIC, MM_ANISOTROPIC and MM_TEXT in turn (the
 *              previous mode, the extents and origins as relations, an
 *              LPtoDP's signs), MM_ANISOTROPIC straight from MM_TEXT,
 *              and the modes 0 and 9
 *   extorg     in MM_TEXT: SetWindowExtEx and SetViewportExtEx (ignored),
 *              SetWindowOrgEx, SetViewportOrgEx, a NULL previous point,
 *              LPtoDP and DPtoLP; in MM_ANISOTROPIC: the extents, zero
 *              and negative ones, and LPtoDP and DPtoLP of points whose
 *              mapping falls on halves
 *   offset     OffsetViewportOrgEx and OffsetWindowOrgEx, twice each;
 *              ScaleViewportExtEx and ScaleWindowExtEx, by a zero
 *              denominator, to a zero extent, with a NULL previous
 *              size; the same in MM_TEXT
 *   isotropic  MM_ISOTROPIC: a 1000x1000 window, a 400x-300 viewport
 *              asked for and the one it gets (relations), the window
 *              changed to 1000x500 after and the viewport asked for
 *              again; MM_ANISOTROPIC from it keeping the extents
 *   drawing    PatBlt through a window origin in MM_TEXT, and through
 *              MM_ANISOTROPIC scaling 8x6 to 16x12, upright and flipped;
 *              Rectangle through the scaling
 *   savedc     SaveDC three times over changed states (mapping, window
 *              origin, text color, background mode, ROP2, brush,
 *              bitmap), RestoreDC(-1) twice, SaveDC again, RestoreDC(1),
 *              then RestoreDC with nothing saved, beyond the levels
 *              saved, 0 and -2; the bitmap a restore deselected
 *              selected into another DC; SaveDC of a deleted DC
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat mapmode):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% mapmode.c user32.lib gdi32.lib
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

static HBITMAP dib32(int w, int h, DWORD **bits)
{
    BITMAPINFO bi;
    void *p = NULL;
    HBITMAP b;

    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    b = CreateDIBSection(NULL, &bi, DIB_RGB_COLORS, &p, NULL, 0);
    *bits = (DWORD *)p;
    return b;
}

static int canvas_open(canvas_t *c, int w, int h)
{
    c->w = w;
    c->h = h;
    c->dc = CreateCompatibleDC(NULL);
    c->bmp = dib32(w, h, &c->bits);
    if (c->dc == NULL || c->bmp == NULL || c->bits == NULL) {
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

/* A mapping mode by name. Rotates through a few buffers, as le() does. */
static const char *mode_name(int m)
{
    static char bufs[4][16];
    static int next;
    char *buf = bufs[next++ & 3];

    switch (m) {
    case MM_TEXT: return "MM_TEXT";
    case MM_LOMETRIC: return "MM_LOMETRIC";
    case MM_HIMETRIC: return "MM_HIMETRIC";
    case MM_LOENGLISH: return "MM_LOENGLISH";
    case MM_HIENGLISH: return "MM_HIENGLISH";
    case MM_TWIPS: return "MM_TWIPS";
    case MM_ISOTROPIC: return "MM_ISOTROPIC";
    case MM_ANISOTROPIC: return "MM_ANISOTROPIC";
    }
    sprintf(buf, "%d", m);
    return buf;
}

/* n points as "x,y x,y". Rotates through a few buffers, as le() does. */
static const char *pts(const POINT *p, int n)
{
    static char bufs[4][256];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    for (i = 0; i < n && k < (int)sizeof bufs[0] - 26; i++) {
        k += sprintf(b + k, "%s%ld,%ld", i ? " " : "", (long)p[i].x, (long)p[i].y);
    }
    b[k] = '\0';
    return b;
}

static void lp_to_dp(HDC dc, const POINT *in, int n)
{
    POINT p[8];
    BOOL r;

    memcpy(p, in, (size_t)n * sizeof(POINT));
    arm();
    r = LPtoDP(dc, p, n);
    line("LPtoDP(%s): ret=%d err=%s -> %s", pts(in, n), r, le(), pts(p, n));
}

static void dp_to_lp(HDC dc, const POINT *in, int n)
{
    POINT p[8];
    BOOL r;

    memcpy(p, in, (size_t)n * sizeof(POINT));
    arm();
    r = DPtoLP(dc, p, n);
    line("DPtoLP(%s): ret=%d err=%s -> %s", pts(in, n), r, le(), pts(p, n));
}

/* The extents and origins, as numbers (the program's own values only). */
static void mapping(HDC dc)
{
    SIZE we, ve;
    POINT wo, vo;

    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    GetWindowOrgEx(dc, &wo);
    GetViewportOrgEx(dc, &vo);
    line("  window ext %ld,%ld org %ld,%ld; viewport ext %ld,%ld org %ld,%ld", (long)we.cx, (long)we.cy,
         (long)wo.x, (long)wo.y, (long)ve.cx, (long)ve.cy, (long)vo.x, (long)vo.y);
}

/* Whether a and b agree within 1% of b. */
static int near1(double a, double b)
{
    double d = a - b;

    if (d < 0) {
        d = -d;
    }
    if (b < 0) {
        b = -b;
    }
    return d <= b / 100.0;
}

/* --- modes --------------------------------------------------------- */

static const struct metric_s {
    int mode;
    double per_mm;      /* logical units per millimeter */
} metric[] = {
    { MM_LOMETRIC, 10.0 },
    { MM_HIMETRIC, 100.0 },
    { MM_LOENGLISH, 100.0 / 25.4 },
    { MM_HIENGLISH, 1000.0 / 25.4 },
    { MM_TWIPS, 1440.0 / 25.4 },
    { 0, 0.0 }
};

/* A metric mode's extents and origins, as relations to the device's size. */
static void metric_relations(HDC dc, double per_mm)
{
    SIZE we, ve;
    POINT wo, vo, p;
    double mm_x, mm_y;

    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    GetWindowOrgEx(dc, &wo);
    GetViewportOrgEx(dc, &vo);
    mm_x = (double)GetDeviceCaps(dc, HORZSIZE) / (double)GetDeviceCaps(dc, HORZRES);
    mm_y = (double)GetDeviceCaps(dc, VERTSIZE) / (double)GetDeviceCaps(dc, VERTRES);
    line("  window ext positive: %s; viewport ext x positive: %s y negative: %s; origins 0,0: %s",
         yesno(we.cx > 0 && we.cy > 0), yesno(ve.cx > 0), yesno(ve.cy < 0),
         yesno(wo.x == 0 && wo.y == 0 && vo.x == 0 && vo.y == 0));
    line("  units per pixel the mode's (HORZSIZE / HORZRES, VERTSIZE / VERTRES) within 1%%: x %s y %s",
         yesno(ve.cx != 0 && near1((double)we.cx / (double)ve.cx, per_mm * mm_x)),
         yesno(ve.cy != 0 && near1(-(double)we.cy / (double)ve.cy, per_mm * mm_y)));
    p.x = 1000;
    p.y = 1000;
    LPtoDP(dc, &p, 1);
    line("  LPtoDP(1000,1000): x positive %s y negative %s", yesno(p.x > 0), yesno(p.y < 0));
}

static int same_extents(HDC dc, const SIZE *we, const SIZE *ve)
{
    SIZE w, v;

    GetWindowExtEx(dc, &w);
    GetViewportExtEx(dc, &v);
    return w.cx == we->cx && w.cy == we->cy && v.cx == ve->cx && v.cy == ve->cy;
}

static void set_mode(HDC dc, int mode)
{
    int prev, got;

    arm();
    prev = SetMapMode(dc, mode);
    line("SetMapMode(%s): previous=%s err=%s", mode_name(mode), mode_name(prev), le());
    arm();
    got = GetMapMode(dc);
    line("GetMapMode: %s err=%s", mode_name(got), le());
}

static void sec_modes(void)
{
    HDC dc;
    SIZE lo_we, lo_ve, we, ve;
    int i, got;

    dc = CreateCompatibleDC(NULL);
    arm();
    got = GetMapMode(dc);
    line("GetMapMode(a new DC): %s err=%s", mode_name(got), le());
    mapping(dc);
    for (i = 0; metric[i].mode != 0; i++) {
        set_mode(dc, metric[i].mode);
        metric_relations(dc, metric[i].per_mm);
        if (metric[i].mode == MM_LOMETRIC) {
            GetWindowExtEx(dc, &lo_we);
            GetViewportExtEx(dc, &lo_ve);
        }
    }
    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    set_mode(dc, MM_ISOTROPIC);
    line("  extents MM_TWIPS's: %s MM_LOMETRIC's: %s", yesno(same_extents(dc, &we, &ve)),
         yesno(same_extents(dc, &lo_we, &lo_ve)));
    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    set_mode(dc, MM_ANISOTROPIC);
    line("  extents MM_ISOTROPIC's: %s MM_LOMETRIC's: %s", yesno(same_extents(dc, &we, &ve)),
         yesno(same_extents(dc, &lo_we, &lo_ve)));
    set_mode(dc, MM_TEXT);
    mapping(dc);
    set_mode(dc, MM_ANISOTROPIC);
    line("  extents MM_LOMETRIC's: %s; window ext 1,1: %s", yesno(same_extents(dc, &lo_we, &lo_ve)),
         yesno(GetWindowExtEx(dc, &we) && we.cx == 1 && we.cy == 1));
    set_mode(dc, MM_ISOTROPIC);
    line("  extents MM_LOMETRIC's: %s", yesno(same_extents(dc, &lo_we, &lo_ve)));
    set_mode(dc, MM_TEXT);
    set_mode(dc, 0);
    set_mode(dc, 9);
    DeleteDC(dc);
}

/* --- extorg -------------------------------------------------------- */

static void set_window_ext(HDC dc, int x, int y)
{
    SIZE prev;
    BOOL r;

    prev.cx = prev.cy = -99;
    arm();
    r = SetWindowExtEx(dc, x, y, &prev);
    line("SetWindowExtEx(%d, %d): ret=%d err=%s previous=%ld,%ld", x, y, r, le(), (long)prev.cx,
         (long)prev.cy);
}

static void set_viewport_ext(HDC dc, int x, int y)
{
    SIZE prev;
    BOOL r;

    prev.cx = prev.cy = -99;
    arm();
    r = SetViewportExtEx(dc, x, y, &prev);
    line("SetViewportExtEx(%d, %d): ret=%d err=%s previous=%ld,%ld", x, y, r, le(), (long)prev.cx,
         (long)prev.cy);
}

static void set_window_org(HDC dc, int x, int y)
{
    POINT prev;
    BOOL r;

    prev.x = prev.y = -99;
    arm();
    r = SetWindowOrgEx(dc, x, y, &prev);
    line("SetWindowOrgEx(%d, %d): ret=%d err=%s previous=%ld,%ld", x, y, r, le(), (long)prev.x,
         (long)prev.y);
}

static void set_viewport_org(HDC dc, int x, int y)
{
    POINT prev;
    BOOL r;

    prev.x = prev.y = -99;
    arm();
    r = SetViewportOrgEx(dc, x, y, &prev);
    line("SetViewportOrgEx(%d, %d): ret=%d err=%s previous=%ld,%ld", x, y, r, le(), (long)prev.x,
         (long)prev.y);
}

static void get_all(HDC dc)
{
    SIZE we, ve;
    POINT wo, vo;
    BOOL r1, r2, r3, r4;

    we.cx = we.cy = ve.cx = ve.cy = -99;
    wo.x = wo.y = vo.x = vo.y = -99;
    arm();
    r1 = GetWindowExtEx(dc, &we);
    r2 = GetViewportExtEx(dc, &ve);
    r3 = GetWindowOrgEx(dc, &wo);
    r4 = GetViewportOrgEx(dc, &vo);
    line("GetWindowExtEx %ld,%ld GetViewportExtEx %ld,%ld GetWindowOrgEx %ld,%ld GetViewportOrgEx"
         " %ld,%ld: rets %d %d %d %d err=%s", (long)we.cx, (long)we.cy, (long)ve.cx, (long)ve.cy,
         (long)wo.x, (long)wo.y, (long)vo.x, (long)vo.y, r1, r2, r3, r4, le());
}

static void sec_extorg(void)
{
    static const POINT text_lp[3] = { { 0, 0 }, { 5, 7 }, { 10, 20 } };
    static const POINT text_dp[2] = { { 0, 0 }, { -3, 4 } };
    static const POINT aniso_lp[7] = {
        { 10, 20 }, { 11, 20 }, { 13, 21 }, { 9, 19 }, { 7, 20 }, { -10, 0 }, { 110, 220 }
    };
    static const POINT aniso_dp[5] = { { 3, 4 }, { 4, 4 }, { 3, 5 }, { 4, 3 }, { 0, 0 } };
    HDC dc;
    BOOL r;

    dc = CreateCompatibleDC(NULL);
    line("-- MM_TEXT");
    get_all(dc);
    set_window_ext(dc, 2, 3);
    set_viewport_ext(dc, 4, 5);
    get_all(dc);
    set_window_org(dc, 5, 7);
    set_viewport_org(dc, -3, 4);
    get_all(dc);
    lp_to_dp(dc, text_lp, 3);
    dp_to_lp(dc, text_dp, 2);
    arm();
    r = SetWindowOrgEx(dc, 0, 0, NULL);
    line("SetWindowOrgEx(0, 0, NULL): ret=%d err=%s", r, le());
    arm();
    r = SetViewportOrgEx(dc, 0, 0, NULL);
    line("SetViewportOrgEx(0, 0, NULL): ret=%d err=%s", r, le());

    line("-- MM_ANISOTROPIC, its extents first set to 1,1");
    SetMapMode(dc, MM_ANISOTROPIC);
    SetWindowExtEx(dc, 1, 1, NULL);
    SetViewportExtEx(dc, 1, 1, NULL);
    set_window_ext(dc, 100, 200);
    set_viewport_ext(dc, 50, -400);
    set_window_ext(dc, 0, 10);
    set_window_ext(dc, 10, 0);
    set_viewport_ext(dc, 0, 0);
    get_all(dc);
    set_window_org(dc, 10, 20);
    set_viewport_org(dc, 3, 4);
    lp_to_dp(dc, aniso_lp, 7);
    dp_to_lp(dc, aniso_dp, 5);
    set_window_ext(dc, -100, 200);
    get_all(dc);
    lp_to_dp(dc, aniso_lp, 3);
    DeleteDC(dc);
}

/* --- offset -------------------------------------------------------- */

static void scale_vp(HDC dc, int xn, int xd, int yn, int yd)
{
    SIZE prev;
    BOOL r;

    prev.cx = prev.cy = -99;
    arm();
    r = ScaleViewportExtEx(dc, xn, xd, yn, yd, &prev);
    line("ScaleViewportExtEx(%d/%d, %d/%d): ret=%d err=%s previous=%ld,%ld", xn, xd, yn, yd, r, le(),
         (long)prev.cx, (long)prev.cy);
}

static void scale_win(HDC dc, int xn, int xd, int yn, int yd)
{
    SIZE prev;
    BOOL r;

    prev.cx = prev.cy = -99;
    arm();
    r = ScaleWindowExtEx(dc, xn, xd, yn, yd, &prev);
    line("ScaleWindowExtEx(%d/%d, %d/%d): ret=%d err=%s previous=%ld,%ld", xn, xd, yn, yd, r, le(),
         (long)prev.cx, (long)prev.cy);
}

static void offset_vp(HDC dc, int x, int y)
{
    POINT prev;
    BOOL r;

    prev.x = prev.y = -99;
    arm();
    r = OffsetViewportOrgEx(dc, x, y, &prev);
    line("OffsetViewportOrgEx(%d, %d): ret=%d err=%s previous=%ld,%ld", x, y, r, le(), (long)prev.x,
         (long)prev.y);
}

static void offset_win(HDC dc, int x, int y)
{
    POINT prev;
    BOOL r;

    prev.x = prev.y = -99;
    arm();
    r = OffsetWindowOrgEx(dc, x, y, &prev);
    line("OffsetWindowOrgEx(%d, %d): ret=%d err=%s previous=%ld,%ld", x, y, r, le(), (long)prev.x,
         (long)prev.y);
}

static void sec_offset(void)
{
    static const POINT probe[2] = { { 0, 0 }, { 20, 40 } };
    HDC dc;
    BOOL r;

    dc = CreateCompatibleDC(NULL);
    line("-- MM_ANISOTROPIC: window ext 100,200, viewport ext 50,-400");
    SetMapMode(dc, MM_ANISOTROPIC);
    SetWindowExtEx(dc, 100, 200, NULL);
    SetViewportExtEx(dc, 50, -400, NULL);
    offset_vp(dc, 3, -2);
    offset_vp(dc, 3, -2);
    offset_win(dc, -5, 6);
    offset_win(dc, -5, 6);
    get_all(dc);
    lp_to_dp(dc, probe, 2);
    arm();
    r = OffsetViewportOrgEx(dc, 1, 1, NULL);
    line("OffsetViewportOrgEx(1, 1, NULL): ret=%d err=%s", r, le());
    arm();
    r = OffsetWindowOrgEx(dc, 1, 1, NULL);
    line("OffsetWindowOrgEx(1, 1, NULL): ret=%d err=%s", r, le());
    scale_vp(dc, 3, 2, 1, 4);
    scale_win(dc, 1, 2, 5, 1);
    get_all(dc);
    lp_to_dp(dc, probe, 2);
    scale_vp(dc, 1, 0, 1, 1);
    scale_win(dc, 0, 1, 1, 1);
    scale_vp(dc, 1, 100, 1, 1000);
    get_all(dc);
    arm();
    r = ScaleViewportExtEx(dc, 2, 1, 2, 1, NULL);
    line("ScaleViewportExtEx(2/1, 2/1, NULL): ret=%d err=%s", r, le());
    arm();
    r = ScaleWindowExtEx(dc, 2, 1, 2, 1, NULL);
    line("ScaleWindowExtEx(2/1, 2/1, NULL): ret=%d err=%s", r, le());
    get_all(dc);

    line("-- MM_TEXT");
    SetMapMode(dc, MM_TEXT);
    SetWindowOrgEx(dc, 0, 0, NULL);
    SetViewportOrgEx(dc, 0, 0, NULL);
    scale_vp(dc, 2, 1, 3, 1);
    scale_win(dc, 2, 1, 3, 1);
    offset_vp(dc, 4, 5);
    offset_win(dc, 1, -1);
    get_all(dc);
    lp_to_dp(dc, probe, 2);
    DeleteDC(dc);
}

/* --- isotropic ----------------------------------------------------- */

/* The viewport MM_ISOTROPIC gave, as relations: its signs, which
 * extent was kept, and the physical size of a logical unit in x and y
 * (the window's extents over the viewport's, in millimeters). */
static int units_equal(HDC dc)
{
    SIZE we, ve;
    double mm_x, mm_y, unit_x, unit_y;

    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    if (ve.cx == 0 || ve.cy == 0 || we.cx == 0 || we.cy == 0) {
        return 0;
    }
    mm_x = (double)GetDeviceCaps(dc, HORZSIZE) / (double)GetDeviceCaps(dc, HORZRES);
    mm_y = (double)GetDeviceCaps(dc, VERTSIZE) / (double)GetDeviceCaps(dc, VERTRES);
    unit_x = (double)ve.cx * mm_x / (double)we.cx;
    unit_y = -(double)ve.cy * mm_y / (double)we.cy;
    return near1(unit_x, unit_y);
}

static void iso_relations(HDC dc, int asked_x, int asked_y)
{
    SIZE we, ve;

    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    line("  window ext %ld,%ld; viewport x positive %s y negative %s; x kept (%d) %s y kept (%d) %s",
         (long)we.cx, (long)we.cy, yesno(ve.cx > 0), yesno(ve.cy < 0), asked_x, yesno(ve.cx == asked_x),
         asked_y, yesno(ve.cy == asked_y));
    line("  a logical unit as long in x as in y, within 1%%: %s; the viewport within the one asked"
         " for: %s", yesno(units_equal(dc)), yesno(ve.cx <= asked_x && -ve.cy <= -asked_y));
}

static void sec_isotropic(void)
{
    HDC dc;
    SIZE ve, ve2, we;
    POINT p;
    BOOL r;

    dc = CreateCompatibleDC(NULL);
    SetMapMode(dc, MM_ISOTROPIC);
    line("MM_ISOTROPIC");
    set_window_ext(dc, 1000, 1000);
    arm();
    r = SetViewportExtEx(dc, 400, -300, NULL);
    line("SetViewportExtEx(400, -300): ret=%d err=%s", r, le());
    iso_relations(dc, 400, -300);
    p.x = 1000;
    p.y = 1000;
    LPtoDP(dc, &p, 1);
    GetViewportExtEx(dc, &ve);
    line("  LPtoDP(1000,1000): the viewport's extents: %s", yesno(p.x == ve.cx && p.y == ve.cy));

    arm();
    r = SetWindowExtEx(dc, 1000, 500, NULL);
    line("SetWindowExtEx(1000, 500): ret=%d err=%s", r, le());
    GetViewportExtEx(dc, &ve2);
    line("  the viewport unchanged: %s; a logical unit as long in x as in y, within 1%%: %s",
         yesno(ve2.cx == ve.cx && ve2.cy == ve.cy), yesno(units_equal(dc)));
    arm();
    r = SetViewportExtEx(dc, 400, -300, NULL);
    line("SetViewportExtEx(400, -300): ret=%d err=%s", r, le());
    iso_relations(dc, 400, -300);

    GetWindowExtEx(dc, &we);
    GetViewportExtEx(dc, &ve);
    set_mode(dc, MM_ANISOTROPIC);
    line("  extents MM_ISOTROPIC's: %s", yesno(same_extents(dc, &we, &ve)));
    arm();
    r = SetViewportExtEx(dc, 400, -300, NULL);
    line("SetViewportExtEx(400, -300): ret=%d err=%s", r, le());
    GetViewportExtEx(dc, &ve);
    line("  viewport ext %ld,%ld", (long)ve.cx, (long)ve.cy);
    DeleteDC(dc);
}

/* --- drawing ------------------------------------------------------- */

static void sec_drawing(void)
{
    canvas_t c;
    HGDIOBJ oldb, oldp;
    HBRUSH red;
    BOOL r;

    if (!canvas_open(&c, 16, 12)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    SetWindowOrgEx(c.dc, -2, -1, NULL);
    arm();
    r = PatBlt(c.dc, 0, 0, 3, 2, BLACKNESS);
    line("MM_TEXT, window origin -2,-1: PatBlt(0, 0, 3, 2, BLACKNESS): ret=%d err=%s", r, le());
    letter_rows(&c);

    SetWindowOrgEx(c.dc, 0, 0, NULL);
    SetMapMode(c.dc, MM_ANISOTROPIC);
    SetWindowExtEx(c.dc, 8, 6, NULL);
    SetViewportExtEx(c.dc, 16, 12, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PatBlt(c.dc, 1, 1, 3, 2, BLACKNESS);
    line("MM_ANISOTROPIC, window ext 8,6, viewport ext 16,12: PatBlt(1, 1, 3, 2, BLACKNESS):"
         " ret=%d err=%s", r, le());
    letter_rows(&c);

    red = CreateSolidBrush(RGB(255, 0, 0));
    oldb = SelectObject(c.dc, red);
    oldp = SelectObject(c.dc, GetStockObject(BLACK_PEN));
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = Rectangle(c.dc, 1, 1, 6, 5);
    line("the same: Rectangle(1, 1, 6, 5), black pen, red brush: ret=%d err=%s", r, le());
    letter_rows(&c);
    SelectObject(c.dc, oldp);
    SelectObject(c.dc, oldb);
    DeleteObject(red);

    SetViewportExtEx(c.dc, 16, -12, NULL);
    SetViewportOrgEx(c.dc, 0, 12, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PatBlt(c.dc, 1, 1, 3, 2, BLACKNESS);
    line("flipped, viewport ext 16,-12, origin 0,12: PatBlt(1, 1, 3, 2, BLACKNESS): ret=%d err=%s", r,
         le());
    letter_rows(&c);
    canvas_close(&c);
}

/* --- savedc -------------------------------------------------------- */

static void dc_state(canvas_t *c, HBITMAP other, const char *label)
{
    POINT wo;
    COLORREF tc;
    HGDIOBJ brush, bmp;
    const char *bname;
    int mode, bk, rop;

    mode = GetMapMode(c->dc);
    GetWindowOrgEx(c->dc, &wo);
    tc = GetTextColor(c->dc);
    bk = GetBkMode(c->dc);
    rop = GetROP2(c->dc);
    brush = GetCurrentObject(c->dc, OBJ_BRUSH);
    bmp = GetCurrentObject(c->dc, OBJ_BITMAP);
    if (brush == GetStockObject(WHITE_BRUSH)) {
        bname = "WHITE_BRUSH";
    } else if (brush == GetStockObject(BLACK_BRUSH)) {
        bname = "BLACK_BRUSH";
    } else if (brush == GetStockObject(GRAY_BRUSH)) {
        bname = "GRAY_BRUSH";
    } else {
        bname = "another";
    }
    line("  %s: %s, window org %ld,%ld, text 0x%06lX, background mode %d, ROP2 %d, brush %s,"
         " bitmap %s", label, mode_name(mode), (long)wo.x, (long)wo.y, (unsigned long)tc, bk, rop,
         bname, bmp == (HGDIOBJ)c->bmp ? "the canvas's" : bmp == (HGDIOBJ)other ? "the other" : "neither");
}

static void save(HDC dc)
{
    int n;

    arm();
    n = SaveDC(dc);
    line("SaveDC: ret=%d err=%s", n, le());
}

static void restore(HDC dc, int level)
{
    BOOL r;

    arm();
    r = RestoreDC(dc, level);
    line("RestoreDC(%d): ret=%d err=%s", level, r, le());
}

static void sec_savedc(void)
{
    canvas_t c;
    HBITMAP other;
    DWORD *obits;
    HDC dc2, gone;
    HGDIOBJ prev;
    int n;

    if (!canvas_open(&c, 4, 4)) {
        return;
    }
    other = dib32(2, 2, &obits);
    dc_state(&c, other, "new");
    save(c.dc);
    SetMapMode(c.dc, MM_ANISOTROPIC);
    SetWindowOrgEx(c.dc, 5, 5, NULL);
    SetTextColor(c.dc, RGB(255, 0, 0));
    SetBkMode(c.dc, TRANSPARENT);
    SetROP2(c.dc, R2_XORPEN);
    SelectObject(c.dc, GetStockObject(BLACK_BRUSH));
    dc_state(&c, other, "changed once");
    save(c.dc);
    SetMapMode(c.dc, MM_LOMETRIC);
    SetWindowOrgEx(c.dc, 7, -7, NULL);
    SetTextColor(c.dc, RGB(0, 255, 0));
    SetBkMode(c.dc, OPAQUE);
    SetROP2(c.dc, R2_NOT);
    SelectObject(c.dc, GetStockObject(GRAY_BRUSH));
    SelectObject(c.dc, other);
    dc_state(&c, other, "changed twice");
    save(c.dc);
    SetTextColor(c.dc, RGB(0, 0, 255));
    dc_state(&c, other, "changed thrice");

    restore(c.dc, -1);
    dc_state(&c, other, "after");
    restore(c.dc, -1);
    dc_state(&c, other, "after");
    save(c.dc);
    save(c.dc);
    restore(c.dc, 1);
    dc_state(&c, other, "after");
    restore(c.dc, -1);
    save(c.dc);
    restore(c.dc, 5);
    restore(c.dc, 0);
    restore(c.dc, -2);
    restore(c.dc, 1);
    dc_state(&c, other, "after");

    dc2 = CreateCompatibleDC(NULL);
    arm();
    prev = SelectObject(dc2, other);
    line("the other bitmap selected into another DC: previous non-NULL %s err=%s", yesno(prev != NULL),
         le());
    SelectObject(dc2, prev);
    DeleteDC(dc2);
    DeleteObject(other);
    canvas_close(&c);

    gone = CreateCompatibleDC(NULL);
    DeleteDC(gone);
    arm();
    n = SaveDC(gone);
    line("SaveDC(a deleted DC): ret=%d err=%s", n, le());
}

static const section_t sections[] = {
    { "modes", sec_modes, F2KT_ALWAYS },
    { "extorg", sec_extorg, F2KT_ALWAYS },
    { "offset", sec_offset, F2KT_ALWAYS },
    { "isotropic", sec_isotropic, F2KT_ALWAYS },
    { "drawing", sec_drawing, F2KT_ALWAYS },
    { "savedc", sec_savedc, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("mapmode", sections, argc, argv);
}
