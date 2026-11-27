/*
 * dcstate - gdi32's device contexts and their state beyond the mapping
 * and SaveDC: GetDCOrgEx, CreateICA/W, ResetDCA/W and CancelDC,
 * GetBoundsRect/SetBoundsRect, GetRelAbs/SetRelAbs, GetLayout/SetLayout,
 * the DC brush and pen (GetDCBrushColor/SetDCBrushColor, GetDCPenColor/
 * SetDCPenColor, DC_BRUSH and DC_PEN), GdiGetBatchLimit/
 * GdiSetBatchLimit and GdiFlush, GetAspectRatioFilterEx, EnumObjects,
 * and GetCurrentObject.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled through its bits
 * pointer before each drawing and read back through it (GdiFlush
 * first), as rows of letters, one per pixel's low 24 bits: # black,
 * . white, R red, G green, B blue, ? any other.
 *
 * GetDCBrushColor, SetDCBrushColor, GetDCPenColor, SetDCPenColor,
 * GetLayout and SetLayout are Windows 2000's additions, and GetRelAbs
 * and SetRelAbs are no SDK header's: the program finds them with
 * GetProcAddress, as MSVC 6's headers and import library may lack them,
 * and says so when gdi32 does not export them.
 *
 * The org section's window is a hidden popup at a fixed place on the
 * screen, so its DC's origin is a fixed point; the screen's own sizes
 * print only as relations. Conventions as the other fixtures on f2kt.h:
 * every call under observation is armed with the last-error sentinel
 * and its line prints ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   org       GetDCOrgEx of a memory DC, the screen's DC, a hidden
 *             popup's client and window DCs (at 100,80, a one-pixel
 *             border), a NULL DC
 *   ic        CreateICA/W of the display: GetObjectType, its
 *             capabilities against the screen DC's, a font selected and
 *             its metrics against a memory DC's, PatBlt on it, DeleteDC;
 *             a driver that does not exist
 *   resetdc   ResetDCA/W of a memory DC and of a display DC with a
 *             DEVMODE of the display's settings; CancelDC of both and of
 *             NULL
 *   bounds    GetBoundsRect of a new DC; SetBoundsRect with DCB_ENABLE,
 *             DCB_ACCUMULATE, DCB_RESET and DCB_DISABLE, each with the
 *             rectangle a PatBlt and a LineTo accumulate
 *   relabs    GetRelAbs of a new DC, SetRelAbs with RELATIVE, ABSOLUTE
 *             and 3, a NULL DC
 *   layout    GetLayout of a new DC, SetLayout with LAYOUT_RTL and
 *             LAYOUT_BITMAPORIENTATIONPRESERVED: a PatBlt and a BitBlt of
 *             four colored columns mirrored or not; a NULL DC
 *   dccolor   GetDCBrushColor and GetDCPenColor of a new DC, the stock
 *             DC_BRUSH and DC_PEN (GetObjectType, GetObjectW), set and
 *             drawn with, changed while selected; a NULL DC
 *   batch     GdiGetBatchLimit, GdiSetBatchLimit with 1, 0 and 10000,
 *             GdiFlush
 *   aspect    GetAspectRatioFilterEx without and with SetMapperFlags'
 *             ASPECT_FILTERING, against GetDeviceCaps' ASPECTX and
 *             ASPECTY
 *   enumobj   EnumObjects of a memory DC's pens and brushes: how many,
 *             the first four of each; a callback that stops at two; an
 *             undefined type
 *   curobj    GetCurrentObject of a new memory DC's pen, brush, font,
 *             palette and bitmap against the stock objects, after
 *             SelectObject, OBJ_EXTPEN, an undefined type, a NULL DC
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat dcstate):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% dcstate.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* Windows 2000's additions, which MSVC 6's headers may lack. */
#ifndef DC_BRUSH
#define DC_BRUSH 18
#endif
#ifndef DC_PEN
#define DC_PEN 19
#endif
#ifndef LAYOUT_RTL
#define LAYOUT_RTL 0x00000001
#endif
#ifndef LAYOUT_BITMAPORIENTATIONPRESERVED
#define LAYOUT_BITMAPORIENTATIONPRESERVED 0x00000008
#endif
#ifndef ENUM_CURRENT_SETTINGS
#define ENUM_CURRENT_SETTINGS ((DWORD)-1)
#endif
#ifndef ABSOLUTE
#define ABSOLUTE 1
#endif
#ifndef RELATIVE
#define RELATIVE 2
#endif

typedef COLORREF (WINAPI *get_color_fn)(HDC);
typedef COLORREF (WINAPI *set_color_fn)(HDC, COLORREF);
typedef DWORD (WINAPI *get_layout_fn)(HDC);
typedef DWORD (WINAPI *set_layout_fn)(HDC, DWORD);
typedef int (WINAPI *get_relabs_fn)(HDC, DWORD);
typedef int (WINAPI *set_relabs_fn)(HDC, int);

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
    int x, y;

    GdiFlush();
    for (y = 0; y < c->h; y++) {
        for (x = 0; x < c->w && x < (int)sizeof row - 1; x++) {
            row[x] = letter(c->bits[y * c->w + x]);
        }
        row[x] = '\0';
        line("  row %2d: %s", y, row);
    }
}

static FARPROC gdi_proc(const char *name)
{
    FARPROC p = GetProcAddress(GetModuleHandleA("gdi32.dll"), name);

    if (p == NULL) {
        line("%s: not exported by gdi32", name);
    }
    return p;
}

static const char *rect_text(const RECT *r)
{
    static char bufs[4][64];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%ld,%ld-%ld,%ld", (long)r->left, (long)r->top, (long)r->right, (long)r->bottom);
    return b;
}

/* --- org ----------------------------------------------------------- */

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

static void print_org(const char *what, HDC dc)
{
    POINT p;
    BOOL r;

    p.x = p.y = -7;
    arm();
    r = GetDCOrgEx(dc, &p);
    line("GetDCOrgEx(%s): ret=%d err=%s %ld,%ld", what, r, le(), (long)p.x, (long)p.y);
}

static void sec_org(void)
{
    WNDCLASSA wc;
    canvas_t c;
    HWND hwnd;
    HDC dc;
    POINT p;

    if (canvas_open(&c, 4, 4)) {
        print_org("a memory DC", c.dc);
        canvas_close(&c);
    }
    dc = GetDC(NULL);
    print_org("GetDC(NULL)", dc);
    ReleaseDC(NULL, dc);

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "F2KDcstateOrg";
    RegisterClassA(&wc);
    hwnd = CreateWindowExA(0, "F2KDcstateOrg", "", WS_POPUP | WS_BORDER, 100, 80, 64, 48, NULL, NULL,
                           wc.hInstance, NULL);
    line("a hidden WS_POPUP | WS_BORDER window at 100,80, 64x48: non-NULL %s", yesno(hwnd != NULL));
    if (hwnd != NULL) {
        dc = GetDC(hwnd);
        print_org("its GetDC", dc);
        p.x = p.y = 0;
        ClientToScreen(hwnd, &p);
        line("  ClientToScreen(0,0): %ld,%ld", (long)p.x, (long)p.y);
        ReleaseDC(hwnd, dc);
        dc = GetWindowDC(hwnd);
        print_org("its GetWindowDC", dc);
        ReleaseDC(hwnd, dc);
        DestroyWindow(hwnd);
    }
    UnregisterClassA("F2KDcstateOrg", GetModuleHandleA(NULL));
    print_org("NULL", NULL);
}

/* --- ic ------------------------------------------------------------ */

static void sec_ic(void)
{
    static const int caps[] = { TECHNOLOGY, HORZRES, VERTRES, BITSPIXEL, PLANES, RASTERCAPS, LOGPIXELSX };
    static const char *names[] = { "TECHNOLOGY", "HORZRES", "VERTRES", "BITSPIXEL", "PLANES",
                                   "RASTERCAPS", "LOGPIXELSX" };
    HDC ic, sdc, mdc;
    TEXTMETRICA tm, mtm;
    HGDIOBJ old;
    BOOL r;
    int i;

    arm();
    ic = CreateICA("DISPLAY", NULL, NULL, NULL);
    line("CreateICA(\"DISPLAY\", NULL, NULL, NULL): non-NULL %s err=%s", yesno(ic != NULL), le());
    if (ic != NULL) {
        line("  GetObjectType: %lu", (unsigned long)GetObjectType(ic));
        sdc = GetDC(NULL);
        line("  GetDeviceCaps(TECHNOLOGY): %d", GetDeviceCaps(ic, TECHNOLOGY));
        for (i = 0; i < (int)(sizeof caps / sizeof caps[0]); i++) {
            line("  GetDeviceCaps(%s) the same as the screen DC's: %s", names[i],
                 yesno(GetDeviceCaps(ic, caps[i]) == GetDeviceCaps(sdc, caps[i])));
        }
        ReleaseDC(NULL, sdc);
        arm();
        old = SelectObject(ic, GetStockObject(ANSI_VAR_FONT));
        line("  SelectObject(ANSI_VAR_FONT): non-NULL %s err=%s", yesno(old != NULL), le());
        ZeroMemory(&tm, sizeof tm);
        ZeroMemory(&mtm, sizeof mtm);
        GetTextMetricsA(ic, &tm);
        mdc = CreateCompatibleDC(NULL);
        SelectObject(mdc, GetStockObject(ANSI_VAR_FONT));
        GetTextMetricsA(mdc, &mtm);
        DeleteDC(mdc);
        line("  its metrics the same as a memory DC's: %s",
             yesno(tm.tmHeight == mtm.tmHeight && tm.tmAveCharWidth == mtm.tmAveCharWidth));
        arm();
        r = PatBlt(ic, 0, 0, 4, 4, BLACKNESS);
        line("  PatBlt(BLACKNESS): ret=%d err=%s", r, le());
        arm();
        r = DeleteDC(ic);
        line("  DeleteDC: ret=%d err=%s", r, le());
    }
    arm();
    ic = CreateICW(L"DISPLAY", NULL, NULL, NULL);
    line("CreateICW(L\"DISPLAY\", NULL, NULL, NULL): non-NULL %s err=%s", yesno(ic != NULL), le());
    if (ic != NULL) {
        line("  GetObjectType: %lu GetDeviceCaps(TECHNOLOGY): %d", (unsigned long)GetObjectType(ic),
             GetDeviceCaps(ic, TECHNOLOGY));
        DeleteDC(ic);
    }
    arm();
    ic = CreateICA("F2KNOSUCHDRIVER", NULL, NULL, NULL);
    line("CreateICA(\"F2KNOSUCHDRIVER\", NULL, NULL, NULL): non-NULL %s err=%s", yesno(ic != NULL), le());
    if (ic != NULL) {
        DeleteDC(ic);
    }
}

/* --- resetdc ------------------------------------------------------- */

static void sec_resetdc(void)
{
    DEVMODEA dma;
    DEVMODEW dmw;
    HDC mdc, ddc, r;
    BOOL ok;

    ZeroMemory(&dma, sizeof dma);
    dma.dmSize = sizeof dma;
    ok = EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dma);
    line("EnumDisplaySettingsA(ENUM_CURRENT_SETTINGS): ret=%d", ok);
    ZeroMemory(&dmw, sizeof dmw);
    dmw.dmSize = sizeof dmw;
    EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dmw);

    mdc = CreateCompatibleDC(NULL);
    arm();
    r = ResetDCA(mdc, &dma);
    line("ResetDCA(a memory DC, the display's DEVMODE): non-NULL %s err=%s the same DC %s",
         yesno(r != NULL), le(), yesno(r == mdc));
    arm();
    r = ResetDCW(mdc, &dmw);
    line("ResetDCW(a memory DC, the display's DEVMODE): non-NULL %s err=%s the same DC %s",
         yesno(r != NULL), le(), yesno(r == mdc));
    arm();
    ok = CancelDC(mdc);
    line("CancelDC(a memory DC): ret=%d err=%s", ok, le());
    DeleteDC(mdc);

    ddc = CreateDCA("DISPLAY", NULL, NULL, NULL);
    arm();
    r = ResetDCA(ddc, &dma);
    line("ResetDCA(CreateDCA(\"DISPLAY\"), the display's DEVMODE): non-NULL %s err=%s the same DC %s",
         yesno(r != NULL), le(), yesno(r == ddc));
    arm();
    r = ResetDCW(ddc, &dmw);
    line("ResetDCW(the same): non-NULL %s err=%s the same DC %s", yesno(r != NULL), le(),
         yesno(r == ddc));
    arm();
    ok = CancelDC(ddc);
    line("CancelDC(the display DC): ret=%d err=%s", ok, le());
    DeleteDC(ddc);
    arm();
    ok = CancelDC(NULL);
    line("CancelDC(NULL): ret=%d err=%s", ok, le());
}

/* --- bounds -------------------------------------------------------- */

static void print_bounds(HDC dc, const char *what, UINT flags)
{
    RECT r;
    UINT ret;

    SetRect(&r, -7, -7, -7, -7);
    arm();
    ret = GetBoundsRect(dc, &r, flags);
    line("GetBoundsRect(%s): ret=0x%X err=%s rect=%s", what, ret, le(), rect_text(&r));
}

static void sec_bounds(void)
{
    canvas_t c;
    RECT r;
    UINT ret;

    if (!canvas_open(&c, 32, 16)) {
        return;
    }
    print_bounds(c.dc, "a new DC, 0", 0);
    arm();
    ret = SetBoundsRect(c.dc, NULL, DCB_ENABLE);
    line("SetBoundsRect(NULL, DCB_ENABLE): ret=0x%X err=%s", ret, le());
    print_bounds(c.dc, "0", 0);
    PatBlt(c.dc, 2, 3, 4, 5, BLACKNESS);
    print_bounds(c.dc, "after PatBlt 2,3 4x5, 0", 0);
    MoveToEx(c.dc, 20, 1, NULL);
    LineTo(c.dc, 25, 10);
    print_bounds(c.dc, "after LineTo 20,1 to 25,10, DCB_RESET", DCB_RESET);
    print_bounds(c.dc, "0", 0);
    SetRect(&r, 10, 10, 12, 14);
    arm();
    ret = SetBoundsRect(c.dc, &r, DCB_ACCUMULATE);
    line("SetBoundsRect(10,10-12,14, DCB_ACCUMULATE): ret=0x%X err=%s", ret, le());
    print_bounds(c.dc, "0", 0);
    PatBlt(c.dc, 1, 1, 2, 2, BLACKNESS);
    print_bounds(c.dc, "after PatBlt 1,1 2x2, 0", 0);
    arm();
    ret = SetBoundsRect(c.dc, NULL, DCB_RESET);
    line("SetBoundsRect(NULL, DCB_RESET): ret=0x%X err=%s", ret, le());
    print_bounds(c.dc, "0", 0);
    arm();
    ret = SetBoundsRect(c.dc, NULL, DCB_DISABLE);
    line("SetBoundsRect(NULL, DCB_DISABLE): ret=0x%X err=%s", ret, le());
    PatBlt(c.dc, 5, 5, 3, 3, BLACKNESS);
    print_bounds(c.dc, "after PatBlt 5,5 3x3, 0", 0);
    arm();
    ret = SetBoundsRect(NULL, NULL, DCB_ENABLE);
    line("SetBoundsRect(NULL DC): ret=0x%X err=%s", ret, le());
    canvas_close(&c);
}

/* --- relabs -------------------------------------------------------- */

static void sec_relabs(void)
{
    get_relabs_fn get;
    set_relabs_fn set;
    HDC dc;
    int r;

    get = (get_relabs_fn)gdi_proc("GetRelAbs");
    set = (set_relabs_fn)gdi_proc("SetRelAbs");
    if (get == NULL || set == NULL) {
        return;
    }
    dc = CreateCompatibleDC(NULL);
    arm();
    r = get(dc, 0);
    line("GetRelAbs(a new DC): ret=%d err=%s", r, le());
    arm();
    r = set(dc, RELATIVE);
    line("SetRelAbs(RELATIVE): previous=%d err=%s now=%d", r, le(), get(dc, 0));
    arm();
    r = set(dc, ABSOLUTE);
    line("SetRelAbs(ABSOLUTE): previous=%d err=%s now=%d", r, le(), get(dc, 0));
    arm();
    r = set(dc, 3);
    line("SetRelAbs(3): ret=%d err=%s now=%d", r, le(), get(dc, 0));
    arm();
    r = set(NULL, RELATIVE);
    line("SetRelAbs(NULL, RELATIVE): ret=%d err=%s", r, le());
    arm();
    r = get(NULL, 0);
    line("GetRelAbs(NULL): ret=%d err=%s", r, le());
    DeleteDC(dc);
}

/* --- layout -------------------------------------------------------- */

static void sec_layout(void)
{
    get_layout_fn get;
    set_layout_fn set;
    canvas_t c, src;
    DWORD r;
    BOOL ok;

    get = (get_layout_fn)gdi_proc("GetLayout");
    set = (set_layout_fn)gdi_proc("SetLayout");
    if (get == NULL || set == NULL) {
        return;
    }
    if (!canvas_open(&c, 16, 2)) {
        return;
    }
    if (!canvas_open(&src, 4, 1)) {
        canvas_close(&c);
        return;
    }
    /* The source's columns: red, green, blue, black. */
    GdiFlush();
    src.bits[0] = 0x00FF0000;
    src.bits[1] = 0x0000FF00;
    src.bits[2] = 0x000000FF;
    src.bits[3] = 0x00000000;

    arm();
    r = get(c.dc);
    line("GetLayout(a new DC): ret=0x%lX err=%s", (unsigned long)r, le());
    arm();
    r = set(c.dc, LAYOUT_RTL);
    line("SetLayout(LAYOUT_RTL): previous=0x%lX err=%s now=0x%lX", (unsigned long)r, le(),
         (unsigned long)get(c.dc));
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 3, 1, BLACKNESS);
    ok = BitBlt(c.dc, 0, 1, 4, 1, src.dc, 0, 0, SRCCOPY);
    line("  PatBlt(0, 0, 3x1, BLACKNESS) and BitBlt(0, 1, 4x1) of red, green, blue, black: BitBlt ret=%d",
         ok);
    letter_rows(&c);

    arm();
    r = set(c.dc, LAYOUT_RTL | LAYOUT_BITMAPORIENTATIONPRESERVED);
    line("SetLayout(LAYOUT_RTL | LAYOUT_BITMAPORIENTATIONPRESERVED): previous=0x%lX err=%s now=0x%lX",
         (unsigned long)r, le(), (unsigned long)get(c.dc));
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 3, 1, BLACKNESS);
    BitBlt(c.dc, 0, 1, 4, 1, src.dc, 0, 0, SRCCOPY);
    letter_rows(&c);

    arm();
    r = set(c.dc, 0);
    line("SetLayout(0): previous=0x%lX err=%s now=0x%lX", (unsigned long)r, le(), (unsigned long)get(c.dc));
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 3, 1, BLACKNESS);
    BitBlt(c.dc, 0, 1, 4, 1, src.dc, 0, 0, SRCCOPY);
    letter_rows(&c);

    arm();
    r = set(c.dc, 0x80);
    line("SetLayout(0x80): ret=0x%lX err=%s now=0x%lX", (unsigned long)r, le(), (unsigned long)get(c.dc));
    set(c.dc, 0);
    arm();
    r = get(NULL);
    line("GetLayout(NULL): ret=0x%lX err=%s", (unsigned long)r, le());
    arm();
    r = set(NULL, LAYOUT_RTL);
    line("SetLayout(NULL, LAYOUT_RTL): ret=0x%lX err=%s", (unsigned long)r, le());
    canvas_close(&src);
    canvas_close(&c);
}

/* --- dccolor ------------------------------------------------------- */

static void sec_dccolor(void)
{
    get_color_fn get_brush, get_pen;
    set_color_fn set_brush, set_pen;
    canvas_t c;
    HGDIOBJ dcb, dcp;
    LOGBRUSH lb;
    LOGPEN lp;
    COLORREF r;
    int n;

    get_brush = (get_color_fn)gdi_proc("GetDCBrushColor");
    set_brush = (set_color_fn)gdi_proc("SetDCBrushColor");
    get_pen = (get_color_fn)gdi_proc("GetDCPenColor");
    set_pen = (set_color_fn)gdi_proc("SetDCPenColor");
    if (get_brush == NULL || set_brush == NULL || get_pen == NULL || set_pen == NULL) {
        return;
    }
    if (!canvas_open(&c, 8, 3)) {
        return;
    }
    arm();
    r = get_brush(c.dc);
    line("GetDCBrushColor(a new DC): ret=0x%06lX err=%s", (unsigned long)r, le());
    arm();
    r = get_pen(c.dc);
    line("GetDCPenColor(a new DC): ret=0x%06lX err=%s", (unsigned long)r, le());

    arm();
    dcb = GetStockObject(DC_BRUSH);
    line("GetStockObject(DC_BRUSH): non-NULL %s err=%s GetObjectType=%lu", yesno(dcb != NULL), le(),
         (unsigned long)GetObjectType(dcb));
    ZeroMemory(&lb, sizeof lb);
    arm();
    n = GetObjectW(dcb, sizeof lb, &lb);
    line("  GetObjectW(LOGBRUSH): ret=%d err=%s lbStyle=%u lbColor=0x%06lX", n, le(), lb.lbStyle,
         (unsigned long)lb.lbColor);
    arm();
    dcp = GetStockObject(DC_PEN);
    line("GetStockObject(DC_PEN): non-NULL %s err=%s GetObjectType=%lu", yesno(dcp != NULL), le(),
         (unsigned long)GetObjectType(dcp));
    ZeroMemory(&lp, sizeof lp);
    arm();
    n = GetObjectW(dcp, sizeof lp, &lp);
    line("  GetObjectW(LOGPEN): ret=%d err=%s lopnStyle=%u lopnWidth=%ld lopnColor=0x%06lX", n, le(),
         lp.lopnStyle, (long)lp.lopnWidth.x, (unsigned long)lp.lopnColor);

    arm();
    r = set_brush(c.dc, RGB(255, 0, 0));
    line("SetDCBrushColor(red): previous=0x%06lX err=%s now=0x%06lX", (unsigned long)r, le(),
         (unsigned long)get_brush(c.dc));
    arm();
    r = set_pen(c.dc, RGB(0, 255, 0));
    line("SetDCPenColor(green): previous=0x%06lX err=%s now=0x%06lX", (unsigned long)r, le(),
         (unsigned long)get_pen(c.dc));
    canvas_fill(&c, 0x00FFFFFF);
    SelectObject(c.dc, dcb);
    SelectObject(c.dc, dcp);
    PatBlt(c.dc, 0, 0, 4, 1, PATCOPY);
    set_brush(c.dc, RGB(0, 0, 255));
    PatBlt(c.dc, 4, 0, 4, 1, PATCOPY);
    MoveToEx(c.dc, 0, 1, NULL);
    LineTo(c.dc, 8, 1);
    set_pen(c.dc, RGB(0, 0, 0));
    MoveToEx(c.dc, 4, 2, NULL);
    LineTo(c.dc, 8, 2);
    line("DC_BRUSH and DC_PEN selected: PatBlt 0,0 4x1 red, blue set, PatBlt 4,0 4x1; LineTo row 1"
         " green; black set, LineTo 4..8 on row 2:");
    letter_rows(&c);
    ZeroMemory(&lb, sizeof lb);
    GetObjectW(dcb, sizeof lb, &lb);
    line("  GetObjectW(DC_BRUSH) now: lbColor=0x%06lX", (unsigned long)lb.lbColor);

    arm();
    r = set_brush(c.dc, 0x01000002);
    line("SetDCBrushColor(PALETTEINDEX(2)): previous=0x%06lX err=%s now=0x%08lX", (unsigned long)r, le(),
         (unsigned long)get_brush(c.dc));
    arm();
    r = set_brush(NULL, RGB(255, 0, 0));
    line("SetDCBrushColor(NULL, red): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = get_brush(NULL);
    line("GetDCBrushColor(NULL): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = set_pen(NULL, RGB(255, 0, 0));
    line("SetDCPenColor(NULL, red): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = get_pen(NULL);
    line("GetDCPenColor(NULL): ret=0x%08lX err=%s", (unsigned long)r, le());
    canvas_close(&c);
}

/* --- batch --------------------------------------------------------- */

static void sec_batch(void)
{
    DWORD r;
    BOOL ok;

    arm();
    r = GdiGetBatchLimit();
    line("GdiGetBatchLimit: ret=%lu err=%s", (unsigned long)r, le());
    arm();
    r = GdiSetBatchLimit(1);
    line("GdiSetBatchLimit(1): previous=%lu err=%s now=%lu", (unsigned long)r, le(),
         (unsigned long)GdiGetBatchLimit());
    arm();
    r = GdiSetBatchLimit(10000);
    line("GdiSetBatchLimit(10000): ret=%lu err=%s now=%lu", (unsigned long)r, le(),
         (unsigned long)GdiGetBatchLimit());
    arm();
    r = GdiSetBatchLimit(0);
    line("GdiSetBatchLimit(0): previous=%lu err=%s now=%lu", (unsigned long)r, le(),
         (unsigned long)GdiGetBatchLimit());
    arm();
    ok = GdiFlush();
    line("GdiFlush: ret=%d err=%s", ok, le());
}

/* --- aspect -------------------------------------------------------- */

static void sec_aspect(void)
{
    HDC dc;
    SIZE sz;
    DWORD prev;
    BOOL r;

    dc = CreateCompatibleDC(NULL);
    sz.cx = sz.cy = -7;
    arm();
    r = GetAspectRatioFilterEx(dc, &sz);
    line("GetAspectRatioFilterEx(a new DC): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    arm();
    prev = SetMapperFlags(dc, ASPECT_FILTERING);
    line("SetMapperFlags(ASPECT_FILTERING): previous=0x%lX err=%s", (unsigned long)prev, le());
    sz.cx = sz.cy = -7;
    arm();
    r = GetAspectRatioFilterEx(dc, &sz);
    line("GetAspectRatioFilterEx: ret=%d err=%s %ld,%ld; ASPECTX=%d ASPECTY=%d", r, le(), (long)sz.cx,
         (long)sz.cy, GetDeviceCaps(dc, ASPECTX), GetDeviceCaps(dc, ASPECTY));
    arm();
    r = GetAspectRatioFilterEx(NULL, &sz);
    line("GetAspectRatioFilterEx(NULL): ret=%d err=%s", r, le());
    DeleteDC(dc);
}

/* --- enumobj ------------------------------------------------------- */

typedef struct {
    int type;
    int n;
    int stop;
} enum_t;

static int CALLBACK enum_object(LPVOID obj, LPARAM data)
{
    enum_t *e = (enum_t *)data;

    if (e->n < 4) {
        if (e->type == OBJ_PEN) {
            const LOGPEN *lp = (const LOGPEN *)obj;

            line("  pen %d: lopnStyle=%u lopnWidth=%ld lopnColor=0x%06lX", e->n, lp->lopnStyle,
                 (long)lp->lopnWidth.x, (unsigned long)lp->lopnColor);
        } else {
            const LOGBRUSH *lb = (const LOGBRUSH *)obj;

            line("  brush %d: lbStyle=%u lbColor=0x%06lX lbHatch=%lu", e->n, lb->lbStyle,
                 (unsigned long)lb->lbColor, (unsigned long)lb->lbHatch);
        }
    }
    e->n++;
    return e->stop == 0 || e->n < e->stop;
}

static void sec_enumobj(void)
{
    HDC dc;
    enum_t e;
    int r;

    dc = CreateCompatibleDC(NULL);
    e.type = OBJ_PEN;
    e.n = 0;
    e.stop = 0;
    arm();
    r = EnumObjects(dc, OBJ_PEN, (GOBJENUMPROC)enum_object, (LPARAM)&e);
    line("EnumObjects(OBJ_PEN): ret=%d err=%s pens=%d", r, le(), e.n);
    e.type = OBJ_BRUSH;
    e.n = 0;
    arm();
    r = EnumObjects(dc, OBJ_BRUSH, (GOBJENUMPROC)enum_object, (LPARAM)&e);
    line("EnumObjects(OBJ_BRUSH): ret=%d err=%s brushes=%d", r, le(), e.n);
    e.type = OBJ_BRUSH;
    e.n = 0;
    e.stop = 2;
    arm();
    r = EnumObjects(dc, OBJ_BRUSH, (GOBJENUMPROC)enum_object, (LPARAM)&e);
    line("EnumObjects(OBJ_BRUSH), the callback answering 0 at the second: ret=%d err=%s calls=%d", r,
         le(), e.n);
    e.n = 0;
    e.stop = 0;
    arm();
    r = EnumObjects(dc, OBJ_FONT, (GOBJENUMPROC)enum_object, (LPARAM)&e);
    line("EnumObjects(OBJ_FONT): ret=%d err=%s calls=%d", r, le(), e.n);
    DeleteDC(dc);
}

/* --- curobj -------------------------------------------------------- */

static void sec_curobj(void)
{
    static const struct cur_s {
        const char *name;
        UINT type;
        int stock;
    } curs[] = {
        { "OBJ_PEN", OBJ_PEN, BLACK_PEN },
        { "OBJ_BRUSH", OBJ_BRUSH, WHITE_BRUSH },
        { "OBJ_FONT", OBJ_FONT, SYSTEM_FONT },
        { "OBJ_PAL", OBJ_PAL, DEFAULT_PALETTE },
        { NULL, 0, 0 }
    };
    HDC dc;
    HGDIOBJ h;
    HPEN pen;
    HBRUSH brush;
    LOGBRUSH lb;
    BITMAP bm;
    int i, n;

    dc = CreateCompatibleDC(NULL);
    for (i = 0; curs[i].name != NULL; i++) {
        arm();
        h = GetCurrentObject(dc, curs[i].type);
        line("GetCurrentObject(a new memory DC, %s): non-NULL %s err=%s the stock object %s", curs[i].name,
             yesno(h != NULL), le(), yesno(h == GetStockObject(curs[i].stock)));
    }
    arm();
    h = GetCurrentObject(dc, OBJ_BITMAP);
    ZeroMemory(&bm, sizeof bm);
    n = GetObjectA(h, sizeof bm, &bm);
    line("GetCurrentObject(OBJ_BITMAP): non-NULL %s err=%s GetObjectA=%d %ldx%ld, %u bpp", yesno(h != NULL),
         le(), n, (long)bm.bmWidth, (long)bm.bmHeight, bm.bmBitsPixel);
    pen = CreatePen(PS_DOT, 1, RGB(1, 2, 3));
    brush = CreateSolidBrush(RGB(4, 5, 6));
    SelectObject(dc, pen);
    SelectObject(dc, brush);
    line("after SelectObject of a pen and a brush: OBJ_PEN theirs %s, OBJ_BRUSH theirs %s",
         yesno(GetCurrentObject(dc, OBJ_PEN) == pen), yesno(GetCurrentObject(dc, OBJ_BRUSH) == brush));
    arm();
    h = GetCurrentObject(dc, OBJ_EXTPEN);
    line("GetCurrentObject(OBJ_EXTPEN), a CreatePen pen selected: non-NULL %s err=%s the pen %s",
         yesno(h != NULL), le(), yesno(h == pen));
    SelectObject(dc, GetStockObject(BLACK_PEN));
    SelectObject(dc, GetStockObject(WHITE_BRUSH));
    DeleteObject(pen);
    DeleteObject(brush);
    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    pen = ExtCreatePen(PS_GEOMETRIC | PS_SOLID, 3, &lb, 0, NULL);
    SelectObject(dc, pen);
    arm();
    h = GetCurrentObject(dc, OBJ_EXTPEN);
    line("GetCurrentObject(OBJ_EXTPEN), an ExtCreatePen pen selected: non-NULL %s err=%s the pen %s",
         yesno(h != NULL), le(), yesno(h == pen));
    arm();
    h = GetCurrentObject(dc, OBJ_PEN);
    line("GetCurrentObject(OBJ_PEN), the same: non-NULL %s err=%s the pen %s", yesno(h != NULL), le(),
         yesno(h == pen));
    SelectObject(dc, GetStockObject(BLACK_PEN));
    DeleteObject(pen);
    arm();
    h = GetCurrentObject(dc, 99);
    line("GetCurrentObject(99): non-NULL %s err=%s", yesno(h != NULL), le());
    arm();
    h = GetCurrentObject(dc, OBJ_DC);
    line("GetCurrentObject(OBJ_DC): non-NULL %s err=%s", yesno(h != NULL), le());
    arm();
    h = GetCurrentObject(NULL, OBJ_PEN);
    line("GetCurrentObject(NULL, OBJ_PEN): non-NULL %s err=%s", yesno(h != NULL), le());
    DeleteDC(dc);
}

static const section_t sections[] = {
    { "org", sec_org, F2KT_ALWAYS },
    { "ic", sec_ic, F2KT_ALWAYS },
    { "resetdc", sec_resetdc, F2KT_ALWAYS },
    { "bounds", sec_bounds, F2KT_ALWAYS },
    { "relabs", sec_relabs, F2KT_ALWAYS },
    { "layout", sec_layout, F2KT_ALWAYS },
    { "dccolor", sec_dccolor, F2KT_ALWAYS },
    { "batch", sec_batch, F2KT_ALWAYS },
    { "aspect", sec_aspect, F2KT_ALWAYS },
    { "enumobj", sec_enumobj, F2KT_ALWAYS },
    { "curobj", sec_curobj, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("dcstate", sections, argc, argv);
}
