/*
 * palette - gdi32's palettes and colour calls as a true-colour display
 * serves them: CreatePalette, GetPaletteEntries/SetPaletteEntries,
 * ResizePalette, AnimatePalette, GetNearestPaletteIndex, GetNearestColor,
 * CreateHalftonePalette, SelectPalette, RealizePalette and UpdateColors,
 * GetSystemPaletteEntries and GetSystemPaletteUse/SetSystemPaletteUse,
 * a DIB section made with DIB_PAL_COLORS through a selected palette
 * (GetDIBColorTable/SetDIBColorTable), GetColorAdjustment/
 * SetColorAdjustment, and GetDeviceGammaRamp/SetDeviceGammaRamp.
 *
 * The capture machine's display is true colour (RASTERCAPS without
 * RC_PALETTE), F2K's too: the palette calls are then mostly
 * bookkeeping, and the device-facing ones (RealizePalette,
 * UpdateColors, the system palette, the gamma ramp) print what Windows
 * 2000 answers for a device with no palette. The system section prints
 * the screen's palette capabilities first, so a capture taken in a
 * palette mode shows itself. A palette entry prints as RRGGBB/flags.
 *
 * SetSystemPaletteUse is asked only for SYSPAL_STATIC (the default)
 * and SYSPAL_NOSTATIC, and put back at once to what it answered;
 * SetDeviceGammaRamp is given only the ramp GetDeviceGammaRamp read,
 * so the display is never left changed.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints (a palette prints as
 * the same as another or not).
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create    CreatePalette of four entries: GetObjectType, GetObjectW's
 *             entry count, GetPaletteEntries of all, the count alone, a
 *             range past the end and one beyond it; a palette of no
 *             entries and of version 0x200; DEFAULT_PALETTE's entries
 *   entries   SetPaletteEntries within, across the end and beyond it,
 *             on DEFAULT_PALETTE, each read back
 *   resize    ResizePalette larger, smaller, to 0, and of DEFAULT_PALETTE
 *   nearest   GetNearestPaletteIndex of exact, near and PALETTEINDEX
 *             colours; GetNearestColor of RGB, PALETTEINDEX and
 *             PALETTERGB colours on a memory DC with and without the
 *             palette selected, and on the screen DC; SetPixel of them
 *             into a 32-bit DIB section, read back
 *   halftone  CreateHalftonePalette of the screen DC, a memory DC and
 *             NULL: its size, its first and last four entries and a
 *             checksum of all
 *   select    SelectPalette into a memory DC and the screen DC, in the
 *             foreground and the background, RealizePalette and
 *             UpdateColors on each, GetCurrentObject's palette, a brush
 *             given as the palette
 *   system    RASTERCAPS' RC_PALETTE, SIZEPALETTE, NUMRESERVED and
 *             NUMCOLORS; GetSystemPaletteUse, SetSystemPaletteUse;
 *             GetSystemPaletteEntries' count and entries
 *   animate   AnimatePalette over PC_RESERVED and plain entries, and
 *             past the end
 *   dibpal    an 8-bit DIB section made with DIB_PAL_COLORS indices
 *             {3, 2, 1, 0} with the palette selected, and without:
 *             GetDIBColorTable, SetDIBColorTable, GetPixel of each index
 *   adjust    GetColorAdjustment of a new DC, SetColorAdjustment and the
 *             values read back, a gamma out of range, a wrong caSize
 *   gamma     GetDeviceGammaRamp of the screen DC (whether it is the
 *             identity) and SetDeviceGammaRamp of the same ramp; of a
 *             memory DC
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat palette):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% palette.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* A LOGPALETTE of up to 16 entries. */
typedef struct {
    WORD palVersion;
    WORD palNumEntries;
    PALETTEENTRY e[16];
} pal16_t;

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
    SelectPalette(c->dc, (HPALETTE)GetStockObject(DEFAULT_PALETTE), FALSE);
    SelectObject(c->dc, c->old);
    DeleteObject(c->bmp);
    DeleteDC(c->dc);
    c->dc = NULL;
}

/* n palette entries as RRGGBB/flags. Rotates through a few buffers. */
static const char *entries_text(const PALETTEENTRY *p, int n)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    b[0] = '\0';
    for (i = 0; i < n && k < (int)sizeof bufs[0] - 16; i++) {
        k += sprintf(b + k, "%s%02X%02X%02X/%u", i ? " " : "", p[i].peRed, p[i].peGreen, p[i].peBlue,
                     p[i].peFlags);
    }
    return b;
}

/* The test palette: red, green, blue and grey, no flags. */
static HPALETTE make_palette(void)
{
    pal16_t lp;

    ZeroMemory(&lp, sizeof lp);
    lp.palVersion = 0x300;
    lp.palNumEntries = 4;
    lp.e[0].peRed = 255;
    lp.e[1].peGreen = 255;
    lp.e[2].peBlue = 255;
    lp.e[3].peRed = lp.e[3].peGreen = lp.e[3].peBlue = 128;
    return CreatePalette((LOGPALETTE *)&lp);
}

static void print_entries(const char *what, HPALETTE pal, UINT start, UINT count)
{
    PALETTEENTRY e[32];
    UINT n;

    FillMemory(e, sizeof e, 0xEE);
    arm();
    n = GetPaletteEntries(pal, start, count, e);
    line("GetPaletteEntries(%s, %u, %u): ret=%u err=%s %s", what, start, count, n, le(),
         entries_text(e, n <= 32 ? (int)n : 0));
}

/* --- create -------------------------------------------------------- */

static void sec_create(void)
{
    pal16_t lp;
    HPALETTE pal, other;
    WORD count;
    UINT n;
    int r;

    arm();
    pal = make_palette();
    line("CreatePalette(4 entries: red, green, blue, grey): non-NULL %s err=%s GetObjectType=%lu",
         yesno(pal != NULL), le(), (unsigned long)GetObjectType(pal));
    if (pal == NULL) {
        return;
    }
    count = 0xEEEE;
    arm();
    r = GetObjectW(pal, sizeof count, &count);
    line("GetObjectW(sizeof(WORD)): ret=%d err=%s count=%u", r, le(), count);
    arm();
    r = GetObjectW(pal, 0, NULL);
    line("GetObjectW(0, NULL): ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 4);
    arm();
    n = GetPaletteEntries(pal, 0, 0, NULL);
    line("GetPaletteEntries(it, 0, 0, NULL): ret=%u err=%s", n, le());
    arm();
    n = GetPaletteEntries(pal, 0, 8, NULL);
    line("GetPaletteEntries(it, 0, 8, NULL): ret=%u err=%s", n, le());
    print_entries("it", pal, 2, 4);
    print_entries("it", pal, 5, 1);
    DeleteObject(pal);

    ZeroMemory(&lp, sizeof lp);
    lp.palVersion = 0x300;
    lp.palNumEntries = 0;
    arm();
    other = CreatePalette((LOGPALETTE *)&lp);
    line("CreatePalette(0 entries): non-NULL %s err=%s", yesno(other != NULL), le());
    if (other != NULL) {
        print_entries("it", other, 0, 4);
        DeleteObject(other);
    }
    lp.palVersion = 0x200;
    lp.palNumEntries = 2;
    lp.e[0].peRed = 1;
    lp.e[1].peBlue = 2;
    arm();
    other = CreatePalette((LOGPALETTE *)&lp);
    line("CreatePalette(version 0x200, 2 entries): non-NULL %s err=%s", yesno(other != NULL), le());
    if (other != NULL) {
        print_entries("it", other, 0, 2);
        DeleteObject(other);
    }

    pal = (HPALETTE)GetStockObject(DEFAULT_PALETTE);
    arm();
    n = GetPaletteEntries(pal, 0, 0, NULL);
    line("GetPaletteEntries(DEFAULT_PALETTE, 0, 0, NULL): ret=%u err=%s", n, le());
    print_entries("DEFAULT_PALETTE", pal, 0, 10);
    print_entries("DEFAULT_PALETTE", pal, 10, 10);
}

/* --- entries ------------------------------------------------------- */

static void sec_entries(void)
{
    PALETTEENTRY e[3];
    HPALETTE pal;
    UINT n;

    pal = make_palette();
    ZeroMemory(e, sizeof e);
    e[0].peRed = e[0].peGreen = 255;
    e[1].peGreen = e[1].peBlue = 255;
    e[1].peFlags = PC_NOCOLLAPSE;
    e[2].peRed = e[2].peBlue = 255;
    e[2].peFlags = PC_RESERVED;
    arm();
    n = SetPaletteEntries(pal, 1, 2, e);
    line("SetPaletteEntries(1, 2: yellow, cyan/PC_NOCOLLAPSE): ret=%u err=%s", n, le());
    print_entries("it", pal, 0, 4);
    arm();
    n = SetPaletteEntries(pal, 3, 3, e);
    line("SetPaletteEntries(3, 3): ret=%u err=%s", n, le());
    print_entries("it", pal, 0, 4);
    arm();
    n = SetPaletteEntries(pal, 4, 1, e);
    line("SetPaletteEntries(4, 1): ret=%u err=%s", n, le());
    arm();
    n = SetPaletteEntries(pal, 0, 0, e);
    line("SetPaletteEntries(0, 0): ret=%u err=%s", n, le());
    arm();
    n = SetPaletteEntries(pal, 0, 1, &e[2]);
    line("SetPaletteEntries(0, 1: magenta/PC_RESERVED): ret=%u err=%s", n, le());
    print_entries("it", pal, 0, 1);
    arm();
    n = SetPaletteEntries((HPALETTE)GetStockObject(DEFAULT_PALETTE), 0, 1, e);
    line("SetPaletteEntries(DEFAULT_PALETTE, 0, 1): ret=%u err=%s", n, le());
    print_entries("DEFAULT_PALETTE", (HPALETTE)GetStockObject(DEFAULT_PALETTE), 0, 1);
    DeleteObject(pal);
    arm();
    n = SetPaletteEntries(pal, 0, 1, e);
    line("SetPaletteEntries(the palette, deleted): ret=%u err=%s", n, le());
}

/* --- resize -------------------------------------------------------- */

static void sec_resize(void)
{
    HPALETTE pal;
    BOOL r;

    pal = make_palette();
    arm();
    r = ResizePalette(pal, 6);
    line("ResizePalette(4 to 6): ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 8);
    arm();
    r = ResizePalette(pal, 2);
    line("ResizePalette(6 to 2): ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 8);
    arm();
    r = ResizePalette(pal, 3);
    line("ResizePalette(2 to 3): ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 8);
    arm();
    r = ResizePalette(pal, 0);
    line("ResizePalette(3 to 0): ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 8);
    arm();
    r = ResizePalette(pal, 1025);
    line("ResizePalette(1025): ret=%d err=%s", r, le());
    DeleteObject(pal);
    arm();
    r = ResizePalette((HPALETTE)GetStockObject(DEFAULT_PALETTE), 30);
    line("ResizePalette(DEFAULT_PALETTE, 30): ret=%d err=%s", r, le());
    print_entries("DEFAULT_PALETTE", (HPALETTE)GetStockObject(DEFAULT_PALETTE), 18, 4);
}

/* --- nearest ------------------------------------------------------- */

static void sec_nearest(void)
{
    static const struct col_s {
        const char *name;
        COLORREF c;
    } cols[] = {
        { "RGB(255,0,0)", RGB(255, 0, 0) },
        { "RGB(250,10,10)", RGB(250, 10, 10) },
        { "RGB(0,0,0)", RGB(0, 0, 0) },
        { "RGB(128,128,129)", RGB(128, 128, 129) },
        { "RGB(100,100,200)", RGB(100, 100, 200) },
        { "PALETTEINDEX(1)", PALETTEINDEX(1) },
        { "PALETTEINDEX(9)", PALETTEINDEX(9) },
        { "PALETTERGB(1,2,3)", PALETTERGB(1, 2, 3) },
        { "RGB(1,2,3)", RGB(1, 2, 3) },
        { NULL, 0 }
    };
    canvas_t c;
    HPALETTE pal;
    HDC sdc;
    UINT idx;
    COLORREF r, set;
    int i;

    pal = make_palette();
    if (!canvas_open(&c, 9, 2)) {
        DeleteObject(pal);
        return;
    }
    sdc = GetDC(NULL);
    for (i = 0; cols[i].name != NULL; i++) {
        arm();
        idx = GetNearestPaletteIndex(pal, cols[i].c);
        line("GetNearestPaletteIndex(%s): ret=%u err=%s", cols[i].name, idx, le());
    }
    for (i = 0; cols[i].name != NULL; i++) {
        arm();
        r = GetNearestColor(c.dc, cols[i].c);
        line("GetNearestColor(the memory DC, %s): ret=0x%08lX err=%s; the screen DC's the same: %s",
             cols[i].name, (unsigned long)r, le(), yesno(GetNearestColor(sdc, cols[i].c) == r));
    }
    GdiFlush();
    for (i = 0; cols[i].name != NULL; i++) {
        set = SetPixel(c.dc, i, 0, cols[i].c);
        line("SetPixel(%d, 0, %s), the default palette: ret=0x%08lX", i, cols[i].name, (unsigned long)set);
    }
    SelectPalette(c.dc, pal, FALSE);
    for (i = 0; cols[i].name != NULL; i++) {
        arm();
        r = GetNearestColor(c.dc, cols[i].c);
        line("GetNearestColor(the memory DC, the palette selected, %s): ret=0x%08lX err=%s", cols[i].name,
             (unsigned long)r, le());
        set = SetPixel(c.dc, i, 1, cols[i].c);
        line("  SetPixel(%d, 1): ret=0x%08lX", i, (unsigned long)set);
    }
    GdiFlush();
    for (i = 0; cols[i].name != NULL; i++) {
        line("pixels %d,0 and %d,1: 0x%08lX 0x%08lX", i, i, (unsigned long)c.bits[i],
             (unsigned long)c.bits[9 + i]);
    }
    arm();
    idx = GetNearestPaletteIndex(NULL, RGB(0, 0, 0));
    line("GetNearestPaletteIndex(NULL): ret=0x%X err=%s", idx, le());
    arm();
    r = GetNearestColor(NULL, RGB(1, 2, 3));
    line("GetNearestColor(NULL): ret=0x%08lX err=%s", (unsigned long)r, le());
    ReleaseDC(NULL, sdc);
    canvas_close(&c);
    DeleteObject(pal);
}

/* --- halftone ------------------------------------------------------ */

static void print_halftone(const char *what, HDC dc, HPALETTE *keep)
{
    PALETTEENTRY e[256];
    HPALETTE pal;
    UINT n, i;
    DWORD sum = 0, x = 0, v;

    arm();
    pal = CreateHalftonePalette(dc);
    line("CreateHalftonePalette(%s): non-NULL %s err=%s", what, yesno(pal != NULL), le());
    if (pal == NULL) {
        return;
    }
    n = GetPaletteEntries(pal, 0, 0, NULL);
    ZeroMemory(e, sizeof e);
    GetPaletteEntries(pal, 0, n <= 256 ? n : 256, e);
    for (i = 0; i < n && i < 256; i++) {
        v = e[i].peRed | ((DWORD)e[i].peGreen << 8) | ((DWORD)e[i].peBlue << 16) | ((DWORD)e[i].peFlags << 24);
        sum += v * (i + 1);
        x ^= v;
    }
    line("  entries=%u first: %s", n, entries_text(e, n >= 4 ? 4 : (int)n));
    line("  last: %s checksum=0x%08lX xor=0x%08lX", entries_text(n >= 4 ? e + n - 4 : e, n >= 4 ? 4 : 0),
         (unsigned long)sum, (unsigned long)x);
    if (keep != NULL && *keep != NULL) {
        PALETTEENTRY f[256];
        UINT m = GetPaletteEntries(*keep, 0, 0, NULL);

        ZeroMemory(f, sizeof f);
        GetPaletteEntries(*keep, 0, m <= 256 ? m : 256, f);
        line("  the same entries as the screen DC's: %s", yesno(m == n && memcmp(e, f, sizeof e) == 0));
        DeleteObject(pal);
    } else if (keep != NULL) {
        *keep = pal;
    } else {
        DeleteObject(pal);
    }
}

static void sec_halftone(void)
{
    HPALETTE screen = NULL;
    HDC sdc, mdc;

    sdc = GetDC(NULL);
    print_halftone("the screen DC", sdc, &screen);
    ReleaseDC(NULL, sdc);
    mdc = CreateCompatibleDC(NULL);
    print_halftone("a memory DC", mdc, &screen);
    DeleteDC(mdc);
    print_halftone("NULL", NULL, NULL);
    if (screen != NULL) {
        DeleteObject(screen);
    }
}

/* --- select -------------------------------------------------------- */

static void sec_select(void)
{
    HPALETTE pal, prev, def;
    HDC mdc, sdc;
    HBRUSH brush;
    UINT n;
    BOOL r;

    def = (HPALETTE)GetStockObject(DEFAULT_PALETTE);
    pal = make_palette();
    mdc = CreateCompatibleDC(NULL);
    arm();
    prev = SelectPalette(mdc, pal, FALSE);
    line("SelectPalette(a memory DC, the palette, FALSE): non-NULL %s err=%s DEFAULT_PALETTE %s",
         yesno(prev != NULL), le(), yesno(prev == def));
    line("  GetCurrentObject(OBJ_PAL) the palette: %s", yesno(GetCurrentObject(mdc, OBJ_PAL) == pal));
    arm();
    n = RealizePalette(mdc);
    line("  RealizePalette: ret=0x%X err=%s", n, le());
    arm();
    n = RealizePalette(mdc);
    line("  RealizePalette again: ret=0x%X err=%s", n, le());
    arm();
    r = UpdateColors(mdc);
    line("  UpdateColors: ret=%d err=%s", r, le());
    arm();
    prev = SelectPalette(mdc, def, TRUE);
    line("SelectPalette(the memory DC, DEFAULT_PALETTE, TRUE): the palette %s err=%s", yesno(prev == pal),
         le());
    arm();
    n = RealizePalette(mdc);
    line("  RealizePalette: ret=0x%X err=%s", n, le());

    sdc = GetDC(NULL);
    arm();
    prev = SelectPalette(sdc, pal, TRUE);
    line("SelectPalette(the screen DC, the palette, TRUE): DEFAULT_PALETTE %s err=%s", yesno(prev == def),
         le());
    arm();
    n = RealizePalette(sdc);
    line("  RealizePalette: ret=0x%X err=%s", n, le());
    arm();
    r = UpdateColors(sdc);
    line("  UpdateColors: ret=%d err=%s", r, le());
    arm();
    prev = SelectPalette(sdc, def, FALSE);
    line("SelectPalette(the screen DC, DEFAULT_PALETTE, FALSE): the palette %s err=%s", yesno(prev == pal),
         le());
    RealizePalette(sdc);
    ReleaseDC(NULL, sdc);

    brush = CreateSolidBrush(RGB(1, 2, 3));
    arm();
    prev = SelectPalette(mdc, (HPALETTE)brush, FALSE);
    line("SelectPalette(a brush): non-NULL %s err=%s", yesno(prev != NULL), le());
    DeleteObject(brush);
    arm();
    prev = SelectPalette(NULL, pal, FALSE);
    line("SelectPalette(NULL DC): non-NULL %s err=%s", yesno(prev != NULL), le());
    arm();
    n = RealizePalette(NULL);
    line("RealizePalette(NULL): ret=0x%X err=%s", n, le());
    SelectPalette(mdc, def, FALSE);
    DeleteDC(mdc);
    DeleteObject(pal);
}

/* --- system -------------------------------------------------------- */

static void sec_system(void)
{
    PALETTEENTRY e[8];
    HDC sdc, mdc;
    UINT r, prev;

    sdc = GetDC(NULL);
    line("the screen DC: RC_PALETTE %s SIZEPALETTE=%d NUMRESERVED=%d NUMCOLORS=%d",
         yesno(GetDeviceCaps(sdc, RASTERCAPS) & RC_PALETTE), GetDeviceCaps(sdc, SIZEPALETTE),
         GetDeviceCaps(sdc, NUMRESERVED), GetDeviceCaps(sdc, NUMCOLORS));
    arm();
    r = GetSystemPaletteUse(sdc);
    line("GetSystemPaletteUse(the screen DC): ret=%u err=%s", r, le());
    arm();
    prev = SetSystemPaletteUse(sdc, SYSPAL_STATIC);
    line("SetSystemPaletteUse(SYSPAL_STATIC): ret=%u err=%s", prev, le());
    arm();
    prev = SetSystemPaletteUse(sdc, SYSPAL_NOSTATIC);
    line("SetSystemPaletteUse(SYSPAL_NOSTATIC): ret=%u err=%s now=%u", prev, le(), GetSystemPaletteUse(sdc));
    if (prev != SYSPAL_ERROR) {
        SetSystemPaletteUse(sdc, prev);
    }
    arm();
    prev = SetSystemPaletteUse(sdc, 7);
    line("SetSystemPaletteUse(7): ret=%u err=%s", prev, le());
    if (prev != SYSPAL_ERROR) {
        SetSystemPaletteUse(sdc, prev);
    }
    arm();
    r = GetSystemPaletteEntries(sdc, 0, 0, NULL);
    line("GetSystemPaletteEntries(the screen DC, 0, 0, NULL): ret=%u err=%s", r, le());
    FillMemory(e, sizeof e, 0xEE);
    arm();
    r = GetSystemPaletteEntries(sdc, 0, 4, e);
    line("GetSystemPaletteEntries(the screen DC, 0, 4): ret=%u err=%s %s", r, le(),
         entries_text(e, r <= 4 ? (int)r : 0));
    ReleaseDC(NULL, sdc);

    mdc = CreateCompatibleDC(NULL);
    arm();
    r = GetSystemPaletteUse(mdc);
    line("GetSystemPaletteUse(a memory DC): ret=%u err=%s", r, le());
    arm();
    r = GetSystemPaletteEntries(mdc, 0, 4, e);
    line("GetSystemPaletteEntries(a memory DC, 0, 4): ret=%u err=%s", r, le());
    DeleteDC(mdc);
    arm();
    r = GetSystemPaletteUse(NULL);
    line("GetSystemPaletteUse(NULL): ret=%u err=%s", r, le());
}

/* --- animate ------------------------------------------------------- */

static void sec_animate(void)
{
    PALETTEENTRY e[4];
    HPALETTE pal;
    BOOL r;
    int i;

    pal = make_palette();
    ZeroMemory(e, sizeof e);
    GetPaletteEntries(pal, 0, 4, e);
    e[1].peFlags = PC_RESERVED;
    e[2].peFlags = PC_RESERVED;
    SetPaletteEntries(pal, 0, 4, e);
    print_entries("the palette, 1 and 2 PC_RESERVED", pal, 0, 4);
    for (i = 0; i < 4; i++) {
        e[i].peRed = (BYTE)(0x10 * (i + 1));
        e[i].peGreen = 0x22;
        e[i].peBlue = 0x33;
        e[i].peFlags = (BYTE)(i == 0 ? 0 : PC_RESERVED);
    }
    arm();
    r = AnimatePalette(pal, 0, 4, e);
    line("AnimatePalette(0, 4: 102233 202233/PC_RESERVED 302233/PC_RESERVED 402233/PC_RESERVED):"
         " ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 4);
    arm();
    r = AnimatePalette(pal, 3, 4, e);
    line("AnimatePalette(3, 4): ret=%d err=%s", r, le());
    print_entries("it", pal, 0, 4);
    arm();
    r = AnimatePalette(pal, 6, 1, e);
    line("AnimatePalette(6, 1): ret=%d err=%s", r, le());
    DeleteObject(pal);
}

/* --- dibpal -------------------------------------------------------- */

static void dib_pal_colors(const char *what, HDC dc)
{
    struct {
        BITMAPINFOHEADER h;
        WORD idx[4];
    } bi;
    RGBQUAD q[8];
    HBITMAP bmp;
    HGDIOBJ old;
    BYTE *bits = NULL;
    UINT n;
    int i;

    ZeroMemory(&bi, sizeof bi);
    bi.h.biSize = sizeof bi.h;
    bi.h.biWidth = 4;
    bi.h.biHeight = -1;
    bi.h.biPlanes = 1;
    bi.h.biBitCount = 8;
    bi.h.biCompression = BI_RGB;
    bi.h.biClrUsed = 4;
    bi.idx[0] = 3;
    bi.idx[1] = 2;
    bi.idx[2] = 1;
    bi.idx[3] = 0;
    arm();
    bmp = CreateDIBSection(dc, (BITMAPINFO *)&bi, DIB_PAL_COLORS, (void **)&bits, NULL, 0);
    line("CreateDIBSection(8 bpp, DIB_PAL_COLORS {3, 2, 1, 0}, %s): non-NULL %s err=%s", what,
         yesno(bmp != NULL), le());
    if (bmp == NULL || bits == NULL) {
        return;
    }
    for (i = 0; i < 4; i++) {
        bits[i] = (BYTE)i;
    }
    old = SelectObject(dc, bmp);
    FillMemory(q, sizeof q, 0xEE);
    arm();
    n = GetDIBColorTable(dc, 0, 8, q);
    line("  GetDIBColorTable(0, 8): ret=%u err=%s", n, le());
    for (i = 0; i < (int)n && i < 8; i++) {
        line("    %d: %02X%02X%02X/%u GetPixel(%d, 0)=0x%06lX", i, q[i].rgbRed, q[i].rgbGreen, q[i].rgbBlue,
             q[i].rgbReserved, i, i < 4 ? (unsigned long)GetPixel(dc, i, 0) : 0ul);
    }
    q[0].rgbRed = 0x12;
    q[0].rgbGreen = 0x34;
    q[0].rgbBlue = 0x56;
    q[0].rgbReserved = 0;
    arm();
    n = SetDIBColorTable(dc, 0, 1, q);
    line("  SetDIBColorTable(0, 1: 123456): ret=%u err=%s GetPixel(0, 0)=0x%06lX", n, le(),
         (unsigned long)GetPixel(dc, 0, 0));
    SelectObject(dc, old);
    DeleteObject(bmp);
}

static void sec_dibpal(void)
{
    HPALETTE pal;
    HDC dc;

    dc = CreateCompatibleDC(NULL);
    pal = make_palette();
    SelectPalette(dc, pal, FALSE);
    dib_pal_colors("the palette selected", dc);
    SelectPalette(dc, (HPALETTE)GetStockObject(DEFAULT_PALETTE), FALSE);
    dib_pal_colors("DEFAULT_PALETTE selected", dc);
    DeleteDC(dc);
    DeleteObject(pal);
}

/* --- adjust -------------------------------------------------------- */

static void print_ca(const char *what, BOOL r, const COLORADJUSTMENT *ca)
{
    line("%s: ret=%d err=%s caSize=%u caFlags=%u caIlluminantIndex=%u gamma=%u,%u,%u black=%u white=%u"
         " contrast=%d brightness=%d colorfulness=%d tint=%d", what, r, le(), ca->caSize, ca->caFlags,
         ca->caIlluminantIndex, ca->caRedGamma, ca->caGreenGamma, ca->caBlueGamma, ca->caReferenceBlack,
         ca->caReferenceWhite, ca->caContrast, ca->caBrightness, ca->caColorfulness, ca->caRedGreenTint);
}

static void sec_adjust(void)
{
    COLORADJUSTMENT ca, set;
    HDC dc;
    BOOL r;

    dc = CreateCompatibleDC(NULL);
    FillMemory(&ca, sizeof ca, 0xEE);
    arm();
    r = GetColorAdjustment(dc, &ca);
    print_ca("GetColorAdjustment(a new DC)", r, &ca);
    set = ca;
    set.caSize = sizeof set;
    set.caRedGamma = 20000;
    set.caContrast = 50;
    set.caBrightness = -30;
    set.caFlags = CA_NEGATIVE;
    arm();
    r = SetColorAdjustment(dc, &set);
    line("SetColorAdjustment(red gamma 20000, contrast 50, brightness -30, CA_NEGATIVE): ret=%d err=%s", r,
         le());
    FillMemory(&ca, sizeof ca, 0xEE);
    r = GetColorAdjustment(dc, &ca);
    print_ca("  GetColorAdjustment", r, &ca);
    set.caRedGamma = 1000;
    arm();
    r = SetColorAdjustment(dc, &set);
    line("SetColorAdjustment(red gamma 1000): ret=%d err=%s", r, le());
    set.caRedGamma = 20000;
    set.caSize = 4;
    arm();
    r = SetColorAdjustment(dc, &set);
    line("SetColorAdjustment(caSize 4): ret=%d err=%s", r, le());
    FillMemory(&ca, sizeof ca, 0xEE);
    r = GetColorAdjustment(dc, &ca);
    print_ca("  GetColorAdjustment", r, &ca);
    arm();
    r = GetColorAdjustment(NULL, &ca);
    line("GetColorAdjustment(NULL): ret=%d err=%s", r, le());
    DeleteDC(dc);
}

/* --- gamma --------------------------------------------------------- */

static WORD ramp[3][256];

static void sec_gamma(void)
{
    HDC sdc, mdc;
    BOOL r;
    int i, c, ident8 = 1, ident257 = 1;

    sdc = GetDC(NULL);
    FillMemory(ramp, sizeof ramp, 0xEE);
    arm();
    r = GetDeviceGammaRamp(sdc, ramp);
    for (c = 0; c < 3; c++) {
        for (i = 0; i < 256; i++) {
            if (ramp[c][i] != (WORD)(i << 8)) {
                ident8 = 0;
            }
            if (ramp[c][i] != (WORD)(i * 257)) {
                ident257 = 0;
            }
        }
    }
    line("GetDeviceGammaRamp(the screen DC): ret=%d err=%s; i<<8: %s; i*257: %s", r, le(),
         yesno(r && ident8), yesno(r && ident257));
    if (r) {
        arm();
        r = SetDeviceGammaRamp(sdc, ramp);
        line("SetDeviceGammaRamp(the screen DC, the ramp read): ret=%d err=%s", r, le());
    }
    ReleaseDC(NULL, sdc);
    mdc = CreateCompatibleDC(NULL);
    arm();
    r = GetDeviceGammaRamp(mdc, ramp);
    line("GetDeviceGammaRamp(a memory DC): ret=%d err=%s", r, le());
    DeleteDC(mdc);
    arm();
    r = GetDeviceGammaRamp(NULL, ramp);
    line("GetDeviceGammaRamp(NULL): ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "entries", sec_entries, F2KT_ALWAYS },
    { "resize", sec_resize, F2KT_ALWAYS },
    { "nearest", sec_nearest, F2KT_ALWAYS },
    { "halftone", sec_halftone, F2KT_ALWAYS },
    { "select", sec_select, F2KT_ALWAYS },
    { "system", sec_system, F2KT_ALWAYS },
    { "animate", sec_animate, F2KT_ALWAYS },
    { "dibpal", sec_dibpal, F2KT_ALWAYS },
    { "adjust", sec_adjust, F2KT_ALWAYS },
    { "gamma", sec_gamma, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("palette", sections, argc, argv);
}
