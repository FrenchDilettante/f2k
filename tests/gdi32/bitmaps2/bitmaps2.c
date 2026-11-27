/*
 * bitmaps2 - gdi32's bitmap calls beyond the bitmaps fixture's:
 * CreateBitmapIndirect, GetBitmapBits/SetBitmapBits,
 * CreateDiscardableBitmap, GetBitmapDimensionEx/SetBitmapDimensionEx,
 * GetDIBColorTable/SetDIBColorTable on DIB sections, MaskBlt, PlgBlt,
 * GdiAlphaBlend, GdiTransparentBlt and GdiGradientFill (and msimg32's
 * AlphaBlend, TransparentBlt and GradientFill over them), and
 * CreateDIBPatternBrush/CreateDIBPatternBrushPt.
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, filled through its bits
 * pointer before each drawing and read back through it (GdiFlush
 * first), as rows of letters, one per pixel's low 24 bits: # black,
 * . white, R red, G green, B blue, ? any other (counted, the first
 * printed), or as hex values where the blend's arithmetic is the point.
 *
 * In Windows 2000 the blends are gdi32's GdiAlphaBlend,
 * GdiTransparentBlt and GdiGradientFill; msimg32.dll exports AlphaBlend,
 * TransparentBlt and GradientFill over them. The program finds gdi32's
 * with GetProcAddress (no SDK header declares them, and MSVC 6's import
 * library lacks them), declares their structures itself, and loads
 * msimg32 only in its own section, so it runs where msimg32 is missing;
 * a missing export prints as such. msimg32's exports print only as the
 * same as gdi32's or not, and their results against gdi32's.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   indirect   CreateBitmapIndirect of an 8x2 1-bit and a 2x2 32-bit
 *              bitmap: GetObjectW's BITMAP, GetBitmapBits whole, short
 *              and long, SetBitmapBits and the bits read back; a width
 *              of 0; GetBitmapBits of a DIB section
 *   discard    CreateDiscardableBitmap of a memory DC (its 1-bit
 *              bitmap) and of the screen DC: the size and depth
 *   dimension  GetBitmapDimensionEx of a new bitmap, SetBitmapDimensionEx
 *              and its previous value, of a DIB section
 *   colortable GetDIBColorTable of an 8-bit DIB section of four colours
 *              (all, from 2, from 4), SetDIBColorTable and GetPixel
 *              after it; a 4-bit one with biClrUsed 0; a 32-bit one; a
 *              device bitmap
 *   maskblt    MaskBlt of red over blue through a 1-bit mask, with
 *              MAKEROP4(SRCCOPY, the destination); no mask; a mask that
 *              is not 1-bit
 *   plgblt     PlgBlt of a 4x4 four-colour source translated, rotated
 *              by 90 degrees, mirrored, through a mask, and onto three
 *              points in a line
 *   alpha      GdiAlphaBlend with a constant alpha of 128, with
 *              AC_SRC_ALPHA over premultiplied pixels, stretched, and a
 *              source rectangle past the source's edge (hex)
 *   transparent GdiTransparentBlt with white transparent, stretched, and
 *              a negative width
 *   gradient   GdiGradientFill of a horizontal and a vertical rectangle
 *              (hex), a triangle (a checksum and its corners), and an
 *              undefined mode
 *   msimg32    msimg32.dll's AlphaBlend, TransparentBlt and GradientFill:
 *              exported, the same as gdi32's, and AlphaBlend's result
 *              against GdiAlphaBlend's
 *   dibpattern CreateDIBPatternBrushPt of a packed 8x8 1-bit checker and
 *              of a 2x2 32-bit DIB, CreateDIBPatternBrush of the same
 *              checker in global memory: GetObjectW's LOGBRUSH, each
 *              blitted
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat bitmaps2):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% bitmaps2.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

#ifndef MAKEROP4
#define MAKEROP4(fore, back) (DWORD)((((back) << 8) & 0xFF000000) | (fore))
#endif

/* The blends' structures, which MSVC 6's headers may lack (wingdi.h's
 * BLENDFUNCTION, TRIVERTEX, GRADIENT_RECT and GRADIENT_TRIANGLE). */
typedef struct {
    BYTE BlendOp;
    BYTE BlendFlags;
    BYTE SourceConstantAlpha;
    BYTE AlphaFormat;
} blend_t;

typedef struct {
    LONG x;
    LONG y;
    USHORT Red;
    USHORT Green;
    USHORT Blue;
    USHORT Alpha;
} vertex_t;

typedef struct {
    ULONG UpperLeft;
    ULONG LowerRight;
} grect_t;

typedef struct {
    ULONG Vertex1;
    ULONG Vertex2;
    ULONG Vertex3;
} gtri_t;

#define F2K_AC_SRC_OVER 0x00
#define F2K_AC_SRC_ALPHA 0x01
#define F2K_GRADIENT_FILL_RECT_H 0
#define F2K_GRADIENT_FILL_RECT_V 1
#define F2K_GRADIENT_FILL_TRIANGLE 2

typedef BOOL (WINAPI *alpha_fn)(HDC, int, int, int, int, HDC, int, int, int, int, blend_t);
typedef BOOL (WINAPI *transparent_fn)(HDC, int, int, int, int, HDC, int, int, int, int, UINT);
typedef BOOL (WINAPI *gradient_fn)(HDC, vertex_t *, ULONG, void *, ULONG, ULONG);

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
    int x, y, other = 0;

    GdiFlush();
    for (y = 0; y < c->h; y++) {
        for (x = 0; x < c->w && x < (int)sizeof row - 1; x++) {
            v = c->bits[y * c->w + x];
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
}

/* n 32-bit values as hex. Rotates through a few buffers, as le() does. */
static const char *hexdwords(const DWORD *p, int n)
{
    static char bufs[4][256];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    b[0] = '\0';
    for (i = 0; i < n && k < (int)sizeof bufs[0] - 10; i++) {
        k += sprintf(b + k, "%s%08lX", i ? " " : "", (unsigned long)p[i]);
    }
    return b;
}

static const char *hexbytes(const BYTE *p, int n)
{
    static char bufs[4][128];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    b[0] = '\0';
    for (i = 0; i < n && k < (int)sizeof bufs[0] - 4; i++) {
        k += sprintf(b + k, "%s%02X", i ? " " : "", p[i]);
    }
    return b;
}

static void hex_rows(canvas_t *c)
{
    int y;

    GdiFlush();
    for (y = 0; y < c->h; y++) {
        line("  row %d: %s", y, hexdwords(c->bits + y * c->w, c->w));
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

static void print_bitmap(const char *what, HGDIOBJ bmp)
{
    BITMAP bm;
    int n;

    ZeroMemory(&bm, sizeof bm);
    arm();
    n = GetObjectW(bmp, sizeof bm, &bm);
    line("  GetObjectW(%s, BITMAP): ret=%d err=%s %ldx%ld bmWidthBytes=%ld bmPlanes=%u bmBitsPixel=%u"
         " bmBits %s", what, n, le(), (long)bm.bmWidth, (long)bm.bmHeight, (long)bm.bmWidthBytes,
         bm.bmPlanes, bm.bmBitsPixel, bm.bmBits == NULL ? "NULL" : "non-NULL");
}

/* --- indirect ------------------------------------------------------ */

static void sec_indirect(void)
{
    static BYTE mono[4] = { 0xA5, 0x00, 0x3C, 0x00 };
    static DWORD deep[4] = { 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00123456 };
    static const BYTE set[2] = { 0xF0, 0x0F };
    BITMAP bm;
    HBITMAP bmp;
    BYTE buf[32];
    canvas_t c;
    LONG n;

    ZeroMemory(&bm, sizeof bm);
    bm.bmWidth = 8;
    bm.bmHeight = 2;
    bm.bmWidthBytes = 2;
    bm.bmPlanes = 1;
    bm.bmBitsPixel = 1;
    bm.bmBits = mono;
    arm();
    bmp = CreateBitmapIndirect(&bm);
    line("CreateBitmapIndirect(8x2, 1 bpp, rows A5 and 3C): non-NULL %s err=%s", yesno(bmp != NULL), le());
    if (bmp != NULL) {
        print_bitmap("it", bmp);
        FillMemory(buf, sizeof buf, 0xEE);
        arm();
        n = GetBitmapBits(bmp, 4, buf);
        line("  GetBitmapBits(4): ret=%ld err=%s %s", (long)n, le(), hexbytes(buf, 4));
        FillMemory(buf, sizeof buf, 0xEE);
        arm();
        n = GetBitmapBits(bmp, 1, buf);
        line("  GetBitmapBits(1): ret=%ld err=%s %s", (long)n, le(), hexbytes(buf, 4));
        FillMemory(buf, sizeof buf, 0xEE);
        arm();
        n = GetBitmapBits(bmp, 32, buf);
        line("  GetBitmapBits(32): ret=%ld err=%s %s", (long)n, le(), hexbytes(buf, 6));
        arm();
        n = GetBitmapBits(bmp, 0, NULL);
        line("  GetBitmapBits(0, NULL): ret=%ld err=%s", (long)n, le());
        arm();
        n = SetBitmapBits(bmp, 2, set);
        FillMemory(buf, sizeof buf, 0xEE);
        GetBitmapBits(bmp, 4, buf);
        line("  SetBitmapBits(2: F0 0F): ret=%ld err=%s; read back: %s", (long)n, le(), hexbytes(buf, 4));
        DeleteObject(bmp);
    }

    bm.bmWidth = 2;
    bm.bmHeight = 2;
    bm.bmWidthBytes = 8;
    bm.bmBitsPixel = 32;
    bm.bmBits = deep;
    arm();
    bmp = CreateBitmapIndirect(&bm);
    line("CreateBitmapIndirect(2x2, 32 bpp): non-NULL %s err=%s", yesno(bmp != NULL), le());
    if (bmp != NULL) {
        print_bitmap("it", bmp);
        FillMemory(buf, sizeof buf, 0xEE);
        arm();
        n = GetBitmapBits(bmp, 16, buf);
        line("  GetBitmapBits(16): ret=%ld err=%s %s", (long)n, le(), hexbytes(buf, 16));
        DeleteObject(bmp);
    }

    bm.bmWidth = 0;
    arm();
    bmp = CreateBitmapIndirect(&bm);
    line("CreateBitmapIndirect(width 0): non-NULL %s err=%s", yesno(bmp != NULL), le());
    if (bmp != NULL) {
        print_bitmap("it", bmp);
        {
            HDC dc = CreateCompatibleDC(NULL);

            line("  a new memory DC's 1x1 bitmap: %s", yesno(bmp == (HBITMAP)GetCurrentObject(dc, OBJ_BITMAP)));
            DeleteDC(dc);
        }
        DeleteObject(bmp);
    }

    if (canvas_open(&c, 2, 1)) {
        c.bits[0] = 0x00112233;
        c.bits[1] = 0x00445566;
        FillMemory(buf, sizeof buf, 0xEE);
        arm();
        n = GetBitmapBits(c.bmp, 8, buf);
        line("GetBitmapBits(a 2x1 32-bit DIB section, 8): ret=%ld err=%s %s", (long)n, le(), hexbytes(buf, 8));
        canvas_close(&c);
    }
}

/* --- discard ------------------------------------------------------- */

static void sec_discard(void)
{
    HDC mdc, sdc;
    HBITMAP bmp;
    BITMAP bm;

    mdc = CreateCompatibleDC(NULL);
    arm();
    bmp = CreateDiscardableBitmap(mdc, 8, 4);
    line("CreateDiscardableBitmap(a memory DC, 8, 4): non-NULL %s err=%s", yesno(bmp != NULL), le());
    if (bmp != NULL) {
        print_bitmap("it", bmp);
        DeleteObject(bmp);
    }
    DeleteDC(mdc);
    sdc = GetDC(NULL);
    arm();
    bmp = CreateDiscardableBitmap(sdc, 8, 4);
    line("CreateDiscardableBitmap(the screen DC, 8, 4): non-NULL %s err=%s", yesno(bmp != NULL), le());
    if (bmp != NULL) {
        ZeroMemory(&bm, sizeof bm);
        GetObjectW(bmp, sizeof bm, &bm);
        line("  %ldx%ld, the screen's depth: %s", (long)bm.bmWidth, (long)bm.bmHeight,
             yesno(bm.bmBitsPixel * bm.bmPlanes == GetDeviceCaps(sdc, BITSPIXEL) * GetDeviceCaps(sdc, PLANES)));
        DeleteObject(bmp);
    }
    ReleaseDC(NULL, sdc);
}

/* --- dimension ----------------------------------------------------- */

static void sec_dimension(void)
{
    HBITMAP bmp;
    canvas_t c;
    SIZE sz;
    BOOL r;

    bmp = CreateBitmap(8, 8, 1, 1, NULL);
    sz.cx = sz.cy = -7;
    arm();
    r = GetBitmapDimensionEx(bmp, &sz);
    line("GetBitmapDimensionEx(a new bitmap): ret=%d err=%s %ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    sz.cx = sz.cy = -7;
    arm();
    r = SetBitmapDimensionEx(bmp, 100, 50, &sz);
    line("SetBitmapDimensionEx(100, 50): ret=%d err=%s previous=%ld,%ld", r, le(), (long)sz.cx, (long)sz.cy);
    arm();
    r = SetBitmapDimensionEx(bmp, -3, 7, NULL);
    line("SetBitmapDimensionEx(-3, 7, NULL): ret=%d err=%s", r, le());
    GetBitmapDimensionEx(bmp, &sz);
    line("  GetBitmapDimensionEx: %ld,%ld", (long)sz.cx, (long)sz.cy);
    DeleteObject(bmp);
    arm();
    r = GetBitmapDimensionEx(bmp, &sz);
    line("GetBitmapDimensionEx(the bitmap, deleted): ret=%d err=%s", r, le());
    if (canvas_open(&c, 2, 2)) {
        arm();
        r = SetBitmapDimensionEx(c.bmp, 20, 30, NULL);
        sz.cx = sz.cy = -7;
        GetBitmapDimensionEx(c.bmp, &sz);
        line("SetBitmapDimensionEx(a DIB section, 20, 30): ret=%d err=%s; read back %ld,%ld", r, le(),
             (long)sz.cx, (long)sz.cy);
        canvas_close(&c);
    }
}

/* --- colortable ---------------------------------------------------- */

static void print_table(HDC dc, UINT start, UINT count)
{
    /* Room for a whole 8-bit table: Windows writes every entry it has (256 for an
     * 8-bit DIB section, whatever biClrUsed said), so a smaller buffer overruns. */
    RGBQUAD q[256];
    UINT n, i;
    char text[256];
    int k = 0;

    FillMemory(q, sizeof q, 0xEE);
    arm();
    n = GetDIBColorTable(dc, start, count, q);
    text[0] = '\0';
    for (i = 0; i < n && i < 16; i++) {
        k += sprintf(text + k, " %02X%02X%02X/%u", q[i].rgbRed, q[i].rgbGreen, q[i].rgbBlue, q[i].rgbReserved);
    }
    line("  GetDIBColorTable(%u, %u): ret=%u err=%s%s", start, count, n, le(), text);
}

static HBITMAP dib8(HDC dc, int bpp, int used, BYTE **bits)
{
    struct {
        BITMAPINFOHEADER h;
        RGBQUAD q[16];
    } bi;

    ZeroMemory(&bi, sizeof bi);
    bi.h.biSize = sizeof bi.h;
    bi.h.biWidth = 4;
    bi.h.biHeight = -1;
    bi.h.biPlanes = 1;
    bi.h.biBitCount = (WORD)bpp;
    bi.h.biCompression = BI_RGB;
    bi.h.biClrUsed = used;
    bi.q[0].rgbRed = 255;
    bi.q[1].rgbGreen = 255;
    bi.q[2].rgbBlue = 255;
    bi.q[3].rgbRed = bi.q[3].rgbGreen = bi.q[3].rgbBlue = 255;
    return CreateDIBSection(dc, (BITMAPINFO *)&bi, DIB_RGB_COLORS, (void **)bits, NULL, 0);
}

static void sec_colortable(void)
{
    RGBQUAD q[2];
    HBITMAP bmp, ddb;
    HGDIOBJ old;
    BYTE *bits = NULL;
    canvas_t c;
    HDC dc;
    UINT n;
    int i;

    ZeroMemory(q, sizeof q);
    dc = CreateCompatibleDC(NULL);
    bmp = dib8(dc, 8, 4, &bits);
    line("an 8-bit 4x1 DIB section of 4 colours (red, green, blue, white): non-NULL %s",
         yesno(bmp != NULL && bits != NULL));
    if (bmp != NULL && bits != NULL) {
        for (i = 0; i < 4; i++) {
            bits[i] = (BYTE)i;
        }
        old = SelectObject(dc, bmp);
        print_table(dc, 0, 256);
        print_table(dc, 2, 4);
        print_table(dc, 4, 1);
        ZeroMemory(q, sizeof q);
        q[1].rgbRed = 0x12;
        q[1].rgbGreen = 0x34;
        q[1].rgbBlue = 0x56;
        arm();
        n = SetDIBColorTable(dc, 1, 2, q);
        line("  SetDIBColorTable(1, 2: 000000 123456): ret=%u err=%s", n, le());
        print_table(dc, 0, 4);
        line("  GetPixel 0..3: 0x%06lX 0x%06lX 0x%06lX 0x%06lX", (unsigned long)GetPixel(dc, 0, 0),
             (unsigned long)GetPixel(dc, 1, 0), (unsigned long)GetPixel(dc, 2, 0),
             (unsigned long)GetPixel(dc, 3, 0));
        arm();
        n = SetDIBColorTable(dc, 3, 4, q);
        line("  SetDIBColorTable(3, 4): ret=%u err=%s", n, le());
        arm();
        n = SetDIBColorTable(dc, 4, 1, q);
        line("  SetDIBColorTable(4, 1): ret=%u err=%s", n, le());
        SelectObject(dc, old);
        DeleteObject(bmp);
    }
    bits = NULL;
    bmp = dib8(dc, 4, 0, &bits);
    line("a 4-bit DIB section with biClrUsed 0: non-NULL %s", yesno(bmp != NULL));
    if (bmp != NULL) {
        old = SelectObject(dc, bmp);
        print_table(dc, 0, 16);
        SelectObject(dc, old);
        DeleteObject(bmp);
    }
    DeleteDC(dc);
    if (canvas_open(&c, 2, 2)) {
        line("a 32-bit DIB section:");
        print_table(c.dc, 0, 4);
        canvas_close(&c);
    }
    dc = CreateCompatibleDC(NULL);
    ddb = CreateBitmap(4, 4, 1, 1, NULL);
    old = SelectObject(dc, ddb);
    line("a 1-bit device bitmap:");
    print_table(dc, 0, 2);
    arm();
    n = SetDIBColorTable(dc, 0, 1, q);
    line("  SetDIBColorTable(0, 1): ret=%u err=%s", n, le());
    SelectObject(dc, old);
    DeleteObject(ddb);
    DeleteDC(dc);
}

/* --- maskblt ------------------------------------------------------- */

static void sec_maskblt(void)
{
    /* Rows 1010 and 1100, word-aligned. */
    static const BYTE maskbits[4] = { 0xA0, 0x00, 0xC0, 0x00 };
    canvas_t dst, src, wide;
    HBITMAP mask;
    BOOL r;

    if (!canvas_open(&dst, 4, 2)) {
        return;
    }
    if (!canvas_open(&src, 4, 2)) {
        canvas_close(&dst);
        return;
    }
    canvas_fill(&src, 0x00FF0000);
    mask = CreateBitmap(4, 2, 1, 1, maskbits);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = MaskBlt(dst.dc, 0, 0, 4, 2, src.dc, 0, 0, mask, 0, 0, MAKEROP4(SRCCOPY, 0x00AA0029));
    line("MaskBlt(red over blue, mask rows 1010 and 1100, MAKEROP4(SRCCOPY, D)): ret=%d err=%s", r, le());
    letter_rows(&dst);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = MaskBlt(dst.dc, 0, 0, 4, 2, src.dc, 0, 0, mask, 0, 0, MAKEROP4(0x00AA0029, SRCCOPY));
    line("MaskBlt(the same, MAKEROP4(D, SRCCOPY)): ret=%d err=%s", r, le());
    letter_rows(&dst);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = MaskBlt(dst.dc, 1, 0, 3, 2, src.dc, 0, 0, mask, 1, 0, MAKEROP4(SRCCOPY, BLACKNESS));
    line("MaskBlt(to 1,0 3x2, mask from 1,0, MAKEROP4(SRCCOPY, BLACKNESS)): ret=%d err=%s", r, le());
    letter_rows(&dst);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = MaskBlt(dst.dc, 0, 0, 4, 2, src.dc, 0, 0, NULL, 0, 0, MAKEROP4(SRCCOPY, 0x00AA0029));
    line("MaskBlt(no mask): ret=%d err=%s", r, le());
    letter_rows(&dst);

    if (canvas_open(&wide, 4, 2)) {
        canvas_fill(&dst, 0x000000FF);
        arm();
        r = MaskBlt(dst.dc, 0, 0, 4, 2, src.dc, 0, 0, wide.bmp, 0, 0, MAKEROP4(SRCCOPY, 0x00AA0029));
        line("MaskBlt(a 32-bit mask): ret=%d err=%s", r, le());
        letter_rows(&dst);
        canvas_close(&wide);
    }
    DeleteObject(mask);
    canvas_close(&src);
    canvas_close(&dst);
}

/* --- plgblt -------------------------------------------------------- */

static void plg(canvas_t *dst, canvas_t *src, HBITMAP mask, const char *what, int x0, int y0, int x1,
                int y1, int x2, int y2)
{
    POINT p[3];
    BOOL r;

    p[0].x = x0;
    p[0].y = y0;
    p[1].x = x1;
    p[1].y = y1;
    p[2].x = x2;
    p[2].y = y2;
    canvas_fill(dst, 0x00FFFFFF);
    arm();
    r = PlgBlt(dst->dc, p, src->dc, 0, 0, 4, 4, mask, 0, 0);
    line("PlgBlt(%s: %d,%d %d,%d %d,%d): ret=%d err=%s", what, x0, y0, x1, y1, x2, y2, r, le());
    letter_rows(dst);
}

static void sec_plgblt(void)
{
    /* A checker of 2x2 cells, word-aligned rows: 1100 1100 0011 0011. */
    static const BYTE maskbits[8] = { 0xC0, 0, 0xC0, 0, 0x30, 0, 0x30, 0 };
    canvas_t dst, src;
    HBITMAP mask;
    int x, y;

    if (!canvas_open(&dst, 8, 8)) {
        return;
    }
    if (!canvas_open(&src, 4, 4)) {
        canvas_close(&dst);
        return;
    }
    /* Quadrants: red, green over blue, black. */
    GdiFlush();
    for (y = 0; y < 4; y++) {
        for (x = 0; x < 4; x++) {
            src.bits[y * 4 + x] = y < 2 ? (x < 2 ? 0x00FF0000 : 0x0000FF00) : (x < 2 ? 0x000000FF : 0);
        }
    }
    line("the source: 4x4, red and green over blue and black");
    plg(&dst, &src, NULL, "translated", 2, 2, 6, 2, 2, 6);
    plg(&dst, &src, NULL, "rotated 90 degrees clockwise", 6, 2, 6, 6, 2, 2);
    plg(&dst, &src, NULL, "mirrored", 6, 2, 2, 2, 6, 6);
    plg(&dst, &src, NULL, "doubled", 0, 0, 8, 0, 0, 8);
    mask = CreateBitmap(4, 4, 1, 1, maskbits);
    plg(&dst, &src, mask, "translated, through a checker mask", 2, 2, 6, 2, 2, 6);
    DeleteObject(mask);
    plg(&dst, &src, NULL, "three points in a line", 0, 0, 4, 4, 8, 8);
    canvas_close(&src);
    canvas_close(&dst);
}

/* --- alpha --------------------------------------------------------- */

static void sec_alpha(void)
{
    alpha_fn alpha;
    canvas_t dst, src;
    blend_t bf;
    BOOL r;

    alpha = (alpha_fn)gdi_proc("GdiAlphaBlend");
    if (alpha == NULL) {
        return;
    }
    if (!canvas_open(&dst, 4, 1)) {
        return;
    }
    if (!canvas_open(&src, 4, 1)) {
        canvas_close(&dst);
        return;
    }
    bf.BlendOp = F2K_AC_SRC_OVER;
    bf.BlendFlags = 0;
    bf.SourceConstantAlpha = 128;
    bf.AlphaFormat = 0;
    canvas_fill(&src, 0x00FF0000);
    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
    line("GdiAlphaBlend(red over white, constant alpha 128): ret=%d err=%s", r, le());
    hex_rows(&dst);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
    line("GdiAlphaBlend(red over blue, constant alpha 128): ret=%d err=%s", r, le());
    hex_rows(&dst);

    GdiFlush();
    src.bits[0] = 0xFFFF0000;
    src.bits[1] = 0x80800000;
    src.bits[2] = 0x00000000;
    src.bits[3] = 0x40004000;
    bf.SourceConstantAlpha = 255;
    bf.AlphaFormat = F2K_AC_SRC_ALPHA;
    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
    line("GdiAlphaBlend(AC_SRC_ALPHA: FFFF0000 80800000 00000000 40004000 over white): ret=%d err=%s", r, le());
    hex_rows(&dst);

    bf.SourceConstantAlpha = 128;
    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
    line("GdiAlphaBlend(the same, constant alpha 128 too): ret=%d err=%s", r, le());
    hex_rows(&dst);

    bf.SourceConstantAlpha = 255;
    bf.AlphaFormat = 0;
    canvas_fill(&src, 0x00FF0000);
    GdiFlush();
    src.bits[1] = 0x000000FF;
    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 2, 1, bf);
    line("GdiAlphaBlend(red, blue stretched to 4, constant alpha 255): ret=%d err=%s", r, le());
    hex_rows(&dst);

    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 2, 0, 4, 1, bf);
    line("GdiAlphaBlend(a source rectangle past the source's edge): ret=%d err=%s", r, le());
    hex_rows(&dst);

    bf.BlendOp = 1;
    arm();
    r = alpha(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
    line("GdiAlphaBlend(BlendOp 1): ret=%d err=%s", r, le());
    canvas_close(&src);
    canvas_close(&dst);
}

/* --- transparent --------------------------------------------------- */

static void sec_transparent(void)
{
    transparent_fn tb;
    canvas_t dst, src;
    BOOL r;
    int i;

    tb = (transparent_fn)gdi_proc("GdiTransparentBlt");
    if (tb == NULL) {
        return;
    }
    if (!canvas_open(&dst, 8, 2)) {
        return;
    }
    if (!canvas_open(&src, 4, 2)) {
        canvas_close(&dst);
        return;
    }
    GdiFlush();
    for (i = 0; i < 8; i++) {
        src.bits[i] = (i + i / 4) % 2 ? 0x00FFFFFF : 0x00FF0000;
    }
    line("the source: 4x2, rows R.R. and .R.R");
    canvas_fill(&dst, 0x000000FF);
    arm();
    r = tb(dst.dc, 0, 0, 4, 2, src.dc, 0, 0, 4, 2, RGB(255, 255, 255));
    line("GdiTransparentBlt(onto blue, white transparent): ret=%d err=%s", r, le());
    letter_rows(&dst);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = tb(dst.dc, 0, 0, 8, 2, src.dc, 0, 0, 4, 2, RGB(255, 0, 0));
    line("GdiTransparentBlt(stretched to 8x2, red transparent): ret=%d err=%s", r, le());
    letter_rows(&dst);

    canvas_fill(&dst, 0x000000FF);
    arm();
    r = tb(dst.dc, 0, 0, -4, 2, src.dc, 0, 0, 4, 2, RGB(255, 255, 255));
    line("GdiTransparentBlt(width -4): ret=%d err=%s", r, le());
    letter_rows(&dst);
    canvas_close(&src);
    canvas_close(&dst);
}

/* --- gradient ------------------------------------------------------ */

static void vertex(vertex_t *v, LONG x, LONG y, USHORT r, USHORT g, USHORT b)
{
    v->x = x;
    v->y = y;
    v->Red = r;
    v->Green = g;
    v->Blue = b;
    v->Alpha = 0;
}

static void sec_gradient(void)
{
    gradient_fn gf;
    canvas_t c;
    vertex_t v[3];
    grect_t gr;
    gtri_t gt;
    DWORD sum;
    BOOL r;
    int i;

    gf = (gradient_fn)gdi_proc("GdiGradientFill");
    if (gf == NULL) {
        return;
    }
    if (!canvas_open(&c, 8, 1)) {
        return;
    }
    vertex(&v[0], 0, 0, 0, 0, 0);
    vertex(&v[1], 8, 1, 0xFF00, 0x8000, 0);
    gr.UpperLeft = 0;
    gr.LowerRight = 1;
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = gf(c.dc, v, 2, &gr, 1, F2K_GRADIENT_FILL_RECT_H);
    line("GdiGradientFill(0,0 black to 8,1 FF00,8000,0000, GRADIENT_FILL_RECT_H): ret=%d err=%s", r, le());
    hex_rows(&c);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = gf(c.dc, v, 2, &gr, 1, 3);
    line("GdiGradientFill(mode 3): ret=%d err=%s", r, le());
    hex_rows(&c);
    canvas_close(&c);

    if (!canvas_open(&c, 1, 4)) {
        return;
    }
    vertex(&v[0], 0, 0, 0, 0, 0xFF00);
    vertex(&v[1], 1, 4, 0xFF00, 0, 0);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = gf(c.dc, v, 2, &gr, 1, F2K_GRADIENT_FILL_RECT_V);
    line("GdiGradientFill(0,0 blue to 1,4 red, GRADIENT_FILL_RECT_V): ret=%d err=%s", r, le());
    hex_rows(&c);
    canvas_close(&c);

    if (!canvas_open(&c, 8, 8)) {
        return;
    }
    vertex(&v[0], 0, 0, 0xFF00, 0, 0);
    vertex(&v[1], 8, 0, 0, 0xFF00, 0);
    vertex(&v[2], 0, 8, 0, 0, 0xFF00);
    gt.Vertex1 = 0;
    gt.Vertex2 = 1;
    gt.Vertex3 = 2;
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = gf(c.dc, v, 3, &gt, 1, F2K_GRADIENT_FILL_TRIANGLE);
    GdiFlush();
    sum = 0;
    for (i = 0; i < 64; i++) {
        sum += c.bits[i] * (DWORD)(i + 1);
    }
    line("GdiGradientFill(0,0 red, 8,0 green, 0,8 blue, GRADIENT_FILL_TRIANGLE): ret=%d err=%s", r, le());
    line("  corners 0,0 7,0 0,7 7,7: %08lX %08lX %08lX %08lX; checksum 0x%08lX", (unsigned long)c.bits[0],
         (unsigned long)c.bits[7], (unsigned long)c.bits[56], (unsigned long)c.bits[63], (unsigned long)sum);
    letter_rows(&c);
    canvas_close(&c);
}

/* --- msimg32 ------------------------------------------------------- */

static void sec_msimg32(void)
{
    static const char *pairs[3][2] = { { "AlphaBlend", "GdiAlphaBlend" },
                                       { "TransparentBlt", "GdiTransparentBlt" },
                                       { "GradientFill", "GdiGradientFill" } };
    HMODULE msimg, gdi;
    FARPROC p, q;
    canvas_t dst, src;
    DWORD mine[4];
    blend_t bf;
    BOOL r;
    int i;

    arm();
    msimg = LoadLibraryA("msimg32.dll");
    line("LoadLibraryA(\"msimg32.dll\"): non-NULL %s err=%s", yesno(msimg != NULL), le());
    if (msimg == NULL) {
        return;
    }
    gdi = GetModuleHandleA("gdi32.dll");
    for (i = 0; i < 3; i++) {
        p = GetProcAddress(msimg, pairs[i][0]);
        q = GetProcAddress(gdi, pairs[i][1]);
        line("  %s: exported %s, the same as gdi32's %s: %s", pairs[i][0], yesno(p != NULL), pairs[i][1],
             yesno(p != NULL && p == q));
    }
    p = GetProcAddress(msimg, "AlphaBlend");
    q = GetProcAddress(gdi, "GdiAlphaBlend");
    if (p != NULL && q != NULL && canvas_open(&dst, 4, 1)) {
        if (canvas_open(&src, 4, 1)) {
            bf.BlendOp = F2K_AC_SRC_OVER;
            bf.BlendFlags = 0;
            bf.SourceConstantAlpha = 96;
            bf.AlphaFormat = 0;
            canvas_fill(&src, 0x00FF0000);
            canvas_fill(&dst, 0x000000FF);
            ((alpha_fn)q)(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
            GdiFlush();
            memcpy(mine, dst.bits, sizeof mine);
            canvas_fill(&dst, 0x000000FF);
            arm();
            r = ((alpha_fn)p)(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 4, 1, bf);
            GdiFlush();
            line("  AlphaBlend(red over blue, constant alpha 96): ret=%d err=%s, GdiAlphaBlend's pixels: %s", r,
                 le(), yesno(memcmp(mine, dst.bits, sizeof mine) == 0));
            canvas_close(&src);
        }
        canvas_close(&dst);
    }
    FreeLibrary(msimg);
}

/* --- dibpattern ---------------------------------------------------- */

static void print_brush(HBRUSH b)
{
    LOGBRUSH lb;
    int n;

    ZeroMemory(&lb, sizeof lb);
    arm();
    n = GetObjectW(b, sizeof lb, &lb);
    line("  GetObjectW(LOGBRUSH): ret=%d err=%s lbStyle=%u lbColor=0x%lX lbHatch %s GetObjectType=%lu", n, le(),
         lb.lbStyle, (unsigned long)lb.lbColor, lb.lbHatch == 0 ? "0" : "nonzero",
         (unsigned long)GetObjectType(b));
}

static void blit_brush(HBRUSH b, int w, int h)
{
    canvas_t c;
    HGDIOBJ old;
    BOOL r;

    if (!canvas_open(&c, w, h)) {
        return;
    }
    canvas_fill(&c, 0x00FFFFFF);
    old = SelectObject(c.dc, b);
    arm();
    r = PatBlt(c.dc, 0, 0, w, h, PATCOPY);
    line("  PatBlt %dx%d: ret=%d err=%s", w, h, r, le());
    letter_rows(&c);
    SelectObject(c.dc, old);
    canvas_close(&c);
}

static void sec_dibpattern(void)
{
    struct {
        BITMAPINFOHEADER h;
        RGBQUAD q[2];
        DWORD rows[8];
    } mono;
    struct {
        BITMAPINFOHEADER h;
        DWORD px[4];
    } deep;
    HGLOBAL g;
    HBRUSH b;
    int i;

    ZeroMemory(&mono, sizeof mono);
    mono.h.biSize = sizeof mono.h;
    mono.h.biWidth = 8;
    mono.h.biHeight = 8;
    mono.h.biPlanes = 1;
    mono.h.biBitCount = 1;
    mono.h.biCompression = BI_RGB;
    mono.q[0].rgbRed = 255;
    mono.q[1].rgbBlue = 255;
    for (i = 0; i < 8; i++) {
        mono.rows[i] = (i & 1) ? 0x55 : 0xAA;
    }
    arm();
    b = CreateDIBPatternBrushPt(&mono, DIB_RGB_COLORS);
    line("CreateDIBPatternBrushPt(a bottom-up 8x8 1-bit checker, 0 red 1 blue, the bottom row AA):"
         " non-NULL %s err=%s", yesno(b != NULL), le());
    if (b != NULL) {
        print_brush(b);
        blit_brush(b, 8, 2);
        DeleteObject(b);
    }

    g = GlobalAlloc(GMEM_MOVEABLE, sizeof mono);
    memcpy(GlobalLock(g), &mono, sizeof mono);
    GlobalUnlock(g);
    arm();
    b = CreateDIBPatternBrush(g, DIB_RGB_COLORS);
    line("CreateDIBPatternBrush(the same in global memory): non-NULL %s err=%s", yesno(b != NULL), le());
    if (b != NULL) {
        print_brush(b);
        blit_brush(b, 8, 2);
        DeleteObject(b);
    }
    GlobalFree(g);

    ZeroMemory(&deep, sizeof deep);
    deep.h.biSize = sizeof deep.h;
    deep.h.biWidth = 2;
    deep.h.biHeight = -2;
    deep.h.biPlanes = 1;
    deep.h.biBitCount = 32;
    deep.h.biCompression = BI_RGB;
    deep.px[0] = 0x00FF0000;
    deep.px[1] = 0x0000FF00;
    deep.px[2] = 0x000000FF;
    deep.px[3] = 0x00000000;
    arm();
    b = CreateDIBPatternBrushPt(&deep, DIB_RGB_COLORS);
    line("CreateDIBPatternBrushPt(a top-down 2x2 32-bit DIB: RG over B#): non-NULL %s err=%s", yesno(b != NULL),
         le());
    if (b != NULL) {
        print_brush(b);
        blit_brush(b, 4, 4);
        DeleteObject(b);
    }
    arm();
    b = CreateDIBPatternBrushPt(&mono, 7);
    line("CreateDIBPatternBrushPt(usage 7): non-NULL %s err=%s", yesno(b != NULL), le());
    if (b != NULL) {
        DeleteObject(b);
    }
}

static const section_t sections[] = {
    { "indirect", sec_indirect, F2KT_ALWAYS },
    { "discard", sec_discard, F2KT_ALWAYS },
    { "dimension", sec_dimension, F2KT_ALWAYS },
    { "colortable", sec_colortable, F2KT_ALWAYS },
    { "maskblt", sec_maskblt, F2KT_ALWAYS },
    { "plgblt", sec_plgblt, F2KT_ALWAYS },
    { "alpha", sec_alpha, F2KT_ALWAYS },
    { "transparent", sec_transparent, F2KT_ALWAYS },
    { "gradient", sec_gradient, F2KT_ALWAYS },
    { "msimg32", sec_msimg32, F2KT_ALWAYS },
    { "dibpattern", sec_dibpattern, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("bitmaps2", sections, argc, argv);
}
