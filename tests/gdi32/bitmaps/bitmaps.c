/*
 * bitmaps - gdi32's bitmaps and blits, read back pixel by pixel: memory
 * DCs (CreateCompatibleDC) and the bitmap a new one holds, device-
 * dependent bitmaps (CreateBitmap, CreateCompatibleBitmap,
 * CreateDIBitmap) and DIB sections (CreateDIBSection), GetObjectA/W on
 * each, BitBlt's raster operations and its monochrome and color
 * conversions, StretchBlt and the stretch modes, GetDIBits and
 * SetDIBits, SetDIBitsToDevice and StretchDIBits, pattern brushes and
 * the brush origin, GetObjectType for each kind of object, and user32's
 * LoadBitmapA/W and LoadImageA/W over a system bitmap and the program's
 * own (bitmaps.rc, compiled by the resource compiler and linked in).
 *
 * Every pixel printed is read from a DIB section or a bitmap of an
 * explicit format: never from the screen, and never as the screen's
 * format. A bitmap that follows the screen's format (CreateCompatible-
 * Bitmap of the screen DC, CreateDIBitmap of it, LoadBitmap's) prints
 * its size, and its depth only as a relation (the screen's: yes); its
 * pixels print only as read back as written or not. The screen's depth
 * is GetDeviceCaps(BITSPIXEL) * GetDeviceCaps(PLANES) of GetDC(NULL).
 *
 * The drawing surface is a canvas: a memory DC (CreateCompatibleDC of
 * NULL) holding a 32-bit top-down DIB section, written and read through
 * its bits pointer (GdiFlush first), one 0x00RRGGBB value per pixel,
 * printed in hex as stored (the top byte too). A row of letters stands
 * for a pixel's low 24 bits where the colors are few: # black, . white,
 * R red, G green, B blue, ? any other (counted, the first printed), and
 * the count of pixels whose top byte is set follows when any is.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address prints (a handle prints as
 * non-NULL or not, and as the same as another or not).
 *
 * Sections (run all with no argument, or one by name):
 *
 *   compat    CreateCompatibleDC(NULL) and of the screen DC, GetObject-
 *             Type of it, the default bitmap it holds (GetCurrentObject,
 *             GetObjectW/A), the same for both DCs or not;
 *             CreateCompatibleBitmap of the screen DC (relations), of
 *             the memory DC (the default bitmap's format), at 0x0, and
 *             of a memory DC holding a DIB section (GetObjectW's
 *             DIBSECTION); SelectObject of one bitmap into two DCs
 *   create    CreateBitmap 5x3 at 1, 2, 4, 8, 16, 24 and 32 bits per
 *             pixel, with 4 planes, at 33 bits, at 0x0 and at a
 *             negative width; GetObjectW/A of each (BITMAP), and of an
 *             8x2 one with initial bits through a DIBSECTION-sized and
 *             a short buffer
 *   dibsect   CreateDIBSection 32-bit top-down and bottom-up (GetObjectW
 *             of DIBSECTION and BITMAP, the bits pointer written, then
 *             GetPixel and PatBlt, the memory read back), 8-bit with a
 *             4-color table and 1-bit with a 2-color table (PatBlt in
 *             a color of the table and one outside it), 24-bit
 *             bottom-up, 16-bit BI_BITFIELDS 5-6-5; a 0-bit header, a
 *             bad usage and a 0 width
 *   blit      BitBlt between canvases with SRCCOPY, SRCPAINT, SRCAND,
 *             SRCINVERT, SRCERASE, NOTSRCCOPY, MERGECOPY, PATCOPY,
 *             PATINVERT, DSTINVERT, BLACKNESS and WHITENESS over fixed
 *             destination, source and brush values; offsets, an
 *             overlapping blit within one canvas, the surface's edge,
 *             a source origin left of the source, and no source DC
 *   mono      a monochrome bitmap blitted to color (its 0 bits as the
 *             destination's text color, its 1 bits as its background
 *             color), color to monochrome (the source's background
 *             color to 1), monochrome to monochrome, and a 1-bit DIB
 *             section with a color table to color
 *   stretch   SetStretchBltMode/GetStretchBltMode over each mode and two
 *             invalid ones; StretchBlt shrinking a color canvas and a
 *             monochrome bitmap under BLACKONWHITE, WHITEONBLACK and
 *             COLORONCOLOR, enlarging 3x2 to 7x5, and mirroring by a
 *             negative destination and source width
 *   dibits    GetDIBits' header of 5x3 bitmaps at 1, 4, 8, 24 and 32
 *             bits; SetDIBits into a 32-bit bitmap from a 24-bit
 *             top-down and an 8-bit bottom-up DIB and one scan line,
 *             GetDIBits back top-down, bottom-up, one scan line, and
 *             more lines than the bitmap has; GetDIBits as 24, 16, 8, 4
 *             and 1 bits (the color tables it fills); SetDIBits of
 *             colors into a monochrome bitmap; a NULL bitmap, no lines,
 *             and a bitmap selected into a DC
 *   todevice  SetDIBitsToDevice of a 5x4 bottom-up DIB whole, a part
 *             of it, one band of its scan lines, and top-down;
 *             StretchDIBits enlarged, a part, mirrored, with SRCINVERT,
 *             top-down, and from a 1-bit DIB with a color table
 *   createdib CreateDIBitmap of the screen DC with and without CBM_INIT
 *             (relations), of a memory DC holding its default bitmap,
 *             of 1-bit DIBs with a black and white and with a red and
 *             blue table, and with a bad usage
 *   pattern   CreatePatternBrush of an 8x8 monochrome bitmap (GetObjectW
 *             of the brush, PatBlt in the DC's text and background
 *             colors), SetBrushOrgEx/GetBrushOrgEx and PatBlt again,
 *             the bitmap deleted after; of an 8x8 32-bit bitmap; of
 *             NULL
 *   objtype   GetObjectType of each kind of object: pens, an extended
 *             pen, brushes, a font, the default palette, a region,
 *             bitmaps, memory and screen DCs, a deleted object, NULL
 *   load      LoadBitmapW/A of OBM_CLOSE and OBM_CHECK (relations), of
 *             the program's bitmap by number and by name, and of one it
 *             lacks; LoadImageW/A of it as a DIB section (its DIBSECTION
 *             and stored rows), stretched to 16x8, as a device bitmap,
 *             monochrome, of OBM_CLOSE, and of one it lacks
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat bitmaps):
 *   rc bitmaps.rc
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% bitmaps.c bitmaps.res user32.lib gdi32.lib
 */

/* The OBM_ system bitmaps' ids are declared only with OEMRESOURCE. */
#define OEMRESOURCE
#include "../common/f2kt.h"

/* A BITMAPINFO with room for any color table, or BI_BITFIELDS' masks. */
typedef struct {
    BITMAPINFOHEADER h;
    RGBQUAD c[256];
} bmi_t;

/* A memory DC holding a 32-bit top-down DIB section of w x h pixels. */
typedef struct {
    HDC dc;
    HBITMAP bmp;
    HGDIOBJ old;
    DWORD *bits;
    int w;
    int h;
} canvas_t;

/* The program's own bitmap (bitmaps.rc): 8x8, 4 bits, the VGA colors;
 * the pixel x, y (from the top) holds the index (x + 2 * y) mod 16. */
#define OWN_BITMAP 300
#define MISSING_BITMAP 399

static const DWORD vga[16] = {
    0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0,
    0x808080, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF
};

/* --- helpers ------------------------------------------------------- */

static void header(bmi_t *b, LONG w, LONG h, WORD bpp)
{
    ZeroMemory(b, sizeof *b);
    b->h.biSize = sizeof b->h;
    b->h.biWidth = w;
    b->h.biHeight = h;
    b->h.biPlanes = 1;
    b->h.biBitCount = bpp;
    b->h.biCompression = BI_RGB;
}

/* Color table entry i of b, from 0x00RRGGBB. */
static void set_color(bmi_t *b, int i, DWORD rgb)
{
    b->c[i].rgbRed = (BYTE)(rgb >> 16);
    b->c[i].rgbGreen = (BYTE)(rgb >> 8);
    b->c[i].rgbBlue = (BYTE)rgb;
    b->c[i].rgbReserved = 0;
}

/* A color table entry as 0xAARRGGBB, AA its rgbReserved. */
static DWORD color_of(const RGBQUAD *q)
{
    return ((DWORD)q->rgbReserved << 24) | ((DWORD)q->rgbRed << 16) | ((DWORD)q->rgbGreen << 8)
        | (DWORD)q->rgbBlue;
}

static DWORD crc32_of(const BYTE *p, DWORD n)
{
    DWORD crc = 0xFFFFFFFFu;
    DWORD i;
    int k;

    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* n bytes as hex pairs. Rotates through a few buffers, as le() does. */
static const char *hexbytes(const BYTE *p, int n)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    for (i = 0; i < n && k < (int)sizeof bufs[0] - 4; i++) {
        k += sprintf(b + k, "%s%02X", i ? " " : "", p[i]);
    }
    b[k] = '\0';
    return b;
}

/* n 32-bit values as hex. Rotates through a few buffers. */
static const char *hexdwords(const DWORD *p, int n)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int i, k = 0;

    for (i = 0; i < n && k < (int)sizeof bufs[0] - 10; i++) {
        k += sprintf(b + k, "%s%08lX", i ? " " : "", (unsigned long)p[i]);
    }
    b[k] = '\0';
    return b;
}

static int screen_bpp(void)
{
    HDC s = GetDC(NULL);
    int bpp = GetDeviceCaps(s, BITSPIXEL) * GetDeviceCaps(s, PLANES);

    ReleaseDC(NULL, s);
    return bpp;
}

static int canvas_open(canvas_t *c, int w, int h)
{
    bmi_t b;
    void *p;

    c->w = w;
    c->h = h;
    c->bits = NULL;
    c->bmp = NULL;
    c->old = NULL;
    c->dc = CreateCompatibleDC(NULL);
    if (c->dc == NULL) {
        line("canvas %dx%d: CreateCompatibleDC failed err=%lu", w, h, (unsigned long)GetLastError());
        return 0;
    }
    header(&b, w, -h, 32);
    p = NULL;
    c->bmp = CreateDIBSection(c->dc, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    if (c->bmp == NULL || p == NULL) {
        line("canvas %dx%d: CreateDIBSection failed err=%lu", w, h, (unsigned long)GetLastError());
        if (c->bmp != NULL) {
            DeleteObject(c->bmp);
        }
        DeleteDC(c->dc);
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

static void canvas_set(canvas_t *c, const DWORD *v)
{
    GdiFlush();
    memcpy(c->bits, v, (size_t)(c->w * c->h) * sizeof(DWORD));
}

static void hex_rows(canvas_t *c, const char *label)
{
    int y;

    GdiFlush();
    for (y = 0; y < c->h; y++) {
        line("  %s row %d: %s", label, y, hexdwords(c->bits + y * c->w, c->w));
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

static void print_bitmap(const char *label, const BITMAP *bm)
{
    line("  %s: bmType=%ld bmWidth=%ld bmHeight=%ld bmWidthBytes=%ld bmPlanes=%u bmBitsPixel=%u"
         " bmBits non-NULL %s", label, (long)bm->bmType, (long)bm->bmWidth, (long)bm->bmHeight,
         (long)bm->bmWidthBytes, (unsigned)bm->bmPlanes, (unsigned)bm->bmBitsPixel,
         yesno(bm->bmBits != NULL));
}

/* A bitmap of the screen's format: its size, and its depth as relations. */
static void print_bitmap_rel(const char *label, const BITMAP *bm, int bpp)
{
    line("  %s: bmType=%ld bmWidth=%ld bmHeight=%ld bmPlanes=%u bmBitsPixel the screen's: %s"
         " bmWidthBytes the width's at that depth, word-aligned: %s bmBits non-NULL %s", label,
         (long)bm->bmType, (long)bm->bmWidth, (long)bm->bmHeight, (unsigned)bm->bmPlanes,
         yesno(bm->bmBitsPixel == bpp),
         yesno(bm->bmWidthBytes == (bm->bmWidth * bm->bmBitsPixel + 15) / 16 * 2),
         yesno(bm->bmBits != NULL));
}

/* GetObjectW and GetObjectA of a bitmap of an explicit format. */
static void get_bitmap(const char *label, HBITMAP hb)
{
    BITMAP w, a;
    int nw, na, n0;

    ZeroMemory(&w, sizeof w);
    ZeroMemory(&a, sizeof a);
    arm();
    nw = GetObjectW(hb, sizeof w, &w);
    line("GetObjectW(%s, sizeof(BITMAP)): ret=%d err=%s", label, nw, le());
    if (nw > 0) {
        print_bitmap("BITMAP", &w);
    }
    arm();
    na = GetObjectA(hb, sizeof a, &a);
    line("GetObjectA(%s, sizeof(BITMAP)): ret=%d err=%s the same as GetObjectW's: %s", label, na,
         le(), yesno(na == nw && memcmp(&a, &w, sizeof a) == 0));
    arm();
    n0 = GetObjectW(hb, 0, NULL);
    line("GetObjectW(%s, 0, NULL): ret=%d err=%s", label, n0, le());
}

/* GetObjectW of a bitmap of the screen's format. */
static void get_bitmap_rel(const char *label, HBITMAP hb, int bpp)
{
    BITMAP w;
    int n;

    ZeroMemory(&w, sizeof w);
    arm();
    n = GetObjectW(hb, sizeof w, &w);
    line("GetObjectW(%s, sizeof(BITMAP)): ret=%d err=%s", label, n, le());
    if (n > 0) {
        print_bitmap_rel("BITMAP", &w, bpp);
    }
}

/* A DIBSECTION's fields; bits, when given, is the pointer it should hold. */
static void print_ds(const DIBSECTION *ds, const void *bits)
{
    const BITMAPINFOHEADER *h = &ds->dsBmih;

    line("  dsBm: bmType=%ld bmWidth=%ld bmHeight=%ld bmWidthBytes=%ld bmPlanes=%u bmBitsPixel=%u"
         " bmBits %s %s", (long)ds->dsBm.bmType, (long)ds->dsBm.bmWidth, (long)ds->dsBm.bmHeight,
         (long)ds->dsBm.bmWidthBytes, (unsigned)ds->dsBm.bmPlanes, (unsigned)ds->dsBm.bmBitsPixel,
         bits != NULL ? "the bits pointer:" : "non-NULL",
         yesno(bits != NULL ? ds->dsBm.bmBits == bits : ds->dsBm.bmBits != NULL));
    line("  dsBmih: biSize=%lu biWidth=%ld biHeight=%ld biPlanes=%u biBitCount=%u biCompression=%lu"
         " biSizeImage=%lu biXPelsPerMeter=%ld biYPelsPerMeter=%ld biClrUsed=%lu biClrImportant=%lu",
         (unsigned long)h->biSize, (long)h->biWidth, (long)h->biHeight, (unsigned)h->biPlanes,
         (unsigned)h->biBitCount, (unsigned long)h->biCompression, (unsigned long)h->biSizeImage,
         (long)h->biXPelsPerMeter, (long)h->biYPelsPerMeter, (unsigned long)h->biClrUsed,
         (unsigned long)h->biClrImportant);
    line("  dsBitfields=%08lX %08lX %08lX dshSection NULL %s dsOffset=%lu",
         (unsigned long)ds->dsBitfields[0], (unsigned long)ds->dsBitfields[1],
         (unsigned long)ds->dsBitfields[2], yesno(ds->dshSection == NULL),
         (unsigned long)ds->dsOffset);
}

/* A bitmap's pixels as 32-bit top-down rows, through GetDIBits (the
 * bitmap must not be selected into a DC). Returns GetDIBits' answer. */
static int read32(HBITMAP hb, int w, int h, DWORD *out)
{
    bmi_t b;
    HDC ref;
    int n;

    header(&b, w, -h, 32);
    ZeroMemory(out, (size_t)(w * h) * sizeof(DWORD));
    ref = CreateCompatibleDC(NULL);
    n = GetDIBits(ref, hb, 0, (UINT)h, out, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    DeleteDC(ref);
    return n;
}

/* A bitmap's pixels as 1-bit rows (at most 32 pixels wide), through
 * GetDIBits bottom-up, printed from the top, with the table it fills. */
static void mono_read(const char *label, HBITMAP hb, int w, int h)
{
    bmi_t b;
    BYTE buf[256];
    HDC ref;
    int n, y;

    header(&b, w, h, 1);
    ZeroMemory(buf, sizeof buf);
    ref = CreateCompatibleDC(NULL);
    arm();
    n = GetDIBits(ref, hb, 0, (UINT)h, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("  %s as 1 bit: GetDIBits ret=%d err=%s table %08lX %08lX", label, n, le(),
         (unsigned long)color_of(&b.c[0]), (unsigned long)color_of(&b.c[1]));
    for (y = 0; y < h && y < 64; y++) {
        line("  %s row %d: %s", label, y, hexbytes(buf + (h - 1 - y) * 4, (w + 7) / 8));
    }
    DeleteDC(ref);
}

/* Whether the bitmap's pixels are the program's own bitmap's (read as 32 bits). */
static int as_own_bitmap(HBITMAP hb)
{
    DWORD px[64];
    int x, y;

    if (read32(hb, 8, 8, px) != 8) {
        return 0;
    }
    for (y = 0; y < 8; y++) {
        for (x = 0; x < 8; x++) {
            if ((px[y * 8 + x] & 0x00FFFFFF) != vga[(x + 2 * y) & 15]) {
                return 0;
            }
        }
    }
    return 1;
}

/* --- compat -------------------------------------------------------- */

static void sec_compat(void)
{
    HDC mem, mem2, screen;
    HGDIOBJ cur, cur2, prev, again;
    HBITMAP b, dib;
    DIBSECTION ds;
    bmi_t bi;
    void *p;
    DWORD type;
    int bpp, n;
    BOOL r;

    bpp = screen_bpp();
    arm();
    mem = CreateCompatibleDC(NULL);
    line("CreateCompatibleDC(NULL): non-NULL %s err=%s", yesno(mem != NULL), le());
    if (mem == NULL) {
        return;
    }
    arm();
    type = GetObjectType(mem);
    line("GetObjectType(mem): ret=%lu err=%s", (unsigned long)type, le());
    n = GetDeviceCaps(mem, BITSPIXEL) * GetDeviceCaps(mem, PLANES);
    line("GetDeviceCaps(mem, BITSPIXEL) * GetDeviceCaps(mem, PLANES): the screen's %s", yesno(n == bpp));
    arm();
    cur = GetCurrentObject(mem, OBJ_BITMAP);
    line("GetCurrentObject(mem, OBJ_BITMAP): non-NULL %s err=%s", yesno(cur != NULL), le());
    get_bitmap("the default bitmap", (HBITMAP)cur);

    screen = GetDC(NULL);
    arm();
    mem2 = CreateCompatibleDC(screen);
    line("CreateCompatibleDC(screen DC): non-NULL %s err=%s", yesno(mem2 != NULL), le());
    cur2 = GetCurrentObject(mem2, OBJ_BITMAP);
    line("its default bitmap the same as the first's: %s", yesno(cur2 == cur));

    arm();
    b = CreateCompatibleBitmap(screen, 16, 8);
    line("CreateCompatibleBitmap(screen DC, 16, 8): non-NULL %s err=%s", yesno(b != NULL), le());
    if (b != NULL) {
        get_bitmap_rel("it", b, bpp);
        arm();
        prev = SelectObject(mem2, b);
        line("SelectObject(mem2, it): previous the default bitmap %s err=%s", yesno(prev == cur), le());
        arm();
        again = SelectObject(mem, b);
        line("SelectObject(mem, it) while mem2 holds it: NULL %s err=%s", yesno(again == NULL), le());
        if (again != NULL) {
            SelectObject(mem, again);
        }
        SelectObject(mem2, cur2);
        DeleteObject(b);
    }

    arm();
    b = CreateCompatibleBitmap(mem, 16, 8);
    line("CreateCompatibleBitmap(mem, 16, 8): non-NULL %s err=%s", yesno(b != NULL), le());
    if (b != NULL) {
        get_bitmap("it", b);
        DeleteObject(b);
    }

    arm();
    b = CreateCompatibleBitmap(screen, 0, 0);
    line("CreateCompatibleBitmap(screen DC, 0, 0): non-NULL %s err=%s the default bitmap %s",
         yesno(b != NULL), le(), yesno(b == (HBITMAP)cur));
    if (b != NULL) {
        get_bitmap("it", b);
        if (b != (HBITMAP)cur) {
            DeleteObject(b);
        }
    }

    header(&bi, 4, -2, 32);
    p = NULL;
    dib = CreateDIBSection(mem, (BITMAPINFO *)&bi, DIB_RGB_COLORS, &p, NULL, 0);
    prev = SelectObject(mem, dib);
    line("mem holds a 4x2 32-bit DIB section: %s", yesno(dib != NULL && prev != NULL));
    arm();
    b = CreateCompatibleBitmap(mem, 5, 3);
    line("CreateCompatibleBitmap(mem, 5, 3): non-NULL %s err=%s", yesno(b != NULL), le());
    if (b != NULL) {
        ZeroMemory(&ds, sizeof ds);
        arm();
        n = GetObjectW(b, sizeof ds, &ds);
        line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
        if (n == (int)sizeof ds) {
            print_ds(&ds, NULL);
        } else if (n > 0) {
            print_bitmap_rel("BITMAP", &ds.dsBm, bpp);
        }
        DeleteObject(b);
    }
    SelectObject(mem, prev);
    DeleteObject(dib);

    arm();
    r = DeleteDC(mem2);
    line("DeleteDC(mem2): ret=%d err=%s", r, le());
    ReleaseDC(NULL, screen);
    arm();
    r = DeleteDC(mem);
    line("DeleteDC(mem): ret=%d err=%s", r, le());
}

/* --- create -------------------------------------------------------- */

static void created(const char *what, HBITMAP b)
{
    line("%s: non-NULL %s err=%s", what, yesno(b != NULL), le());
    if (b != NULL) {
        get_bitmap("it", b);
        DeleteObject(b);
    }
}

static void sec_create(void)
{
    static const WORD bpps[] = { 1, 2, 4, 8, 16, 24, 32 };
    static const BYTE mono_bits[] = { 0xA5, 0x00, 0x3C, 0x00 };
    char what[64];
    HBITMAP b;
    HDC mem;
    HGDIOBJ cur;
    BITMAP bm;
    DIBSECTION ds;
    int i, n;

    for (i = 0; i < (int)(sizeof bpps / sizeof bpps[0]); i++) {
        sprintf(what, "CreateBitmap(5, 3, 1, %u, NULL)", (unsigned)bpps[i]);
        arm();
        b = CreateBitmap(5, 3, 1, bpps[i], NULL);
        created(what, b);
    }
    arm();
    b = CreateBitmap(5, 3, 4, 1, NULL);
    created("CreateBitmap(5, 3, 4, 1, NULL)", b);
    arm();
    b = CreateBitmap(5, 3, 1, 33, NULL);
    created("CreateBitmap(5, 3, 1, 33, NULL)", b);
    arm();
    b = CreateBitmap(-5, 3, 1, 1, NULL);
    created("CreateBitmap(-5, 3, 1, 1, NULL)", b);

    mem = CreateCompatibleDC(NULL);
    cur = GetCurrentObject(mem, OBJ_BITMAP);
    arm();
    b = CreateBitmap(0, 0, 1, 1, NULL);
    line("CreateBitmap(0, 0, 1, 1, NULL): non-NULL %s err=%s a memory DC's default bitmap %s",
         yesno(b != NULL), le(), yesno(b == (HBITMAP)cur));
    if (b != NULL) {
        get_bitmap("it", b);
        if (b != (HBITMAP)cur) {
            DeleteObject(b);
        }
    }
    DeleteDC(mem);

    arm();
    b = CreateBitmap(8, 2, 1, 1, mono_bits);
    line("CreateBitmap(8, 2, 1, 1, bits A5 00 3C 00): non-NULL %s err=%s", yesno(b != NULL), le());
    if (b == NULL) {
        return;
    }
    get_bitmap("it", b);
    mono_read("it", b, 8, 2);
    ZeroMemory(&ds, sizeof ds);
    arm();
    n = GetObjectW(b, sizeof ds, &ds);
    line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
    ZeroMemory(&bm, sizeof bm);
    arm();
    n = GetObjectW(b, sizeof bm - 4, &bm);
    line("GetObjectW(it, sizeof(BITMAP) - 4): ret=%d err=%s bmWidth=%ld", n, le(), (long)bm.bmWidth);
    DeleteObject(b);
}

/* --- dibsect ------------------------------------------------------- */

static void dib_32(LONG height)
{
    bmi_t b;
    HBITMAP h;
    HDC mem;
    HGDIOBJ old;
    DIBSECTION ds;
    BITMAP bm;
    COLORREF c;
    DWORD *bits;
    void *p;
    int n, x, y;
    BOOL r;

    line("-- 4x%ld, 32 bits, %s", (long)(height < 0 ? -height : height),
         height < 0 ? "top-down" : "bottom-up");
    header(&b, 4, height, 32);
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    line("CreateDIBSection(NULL, 4x%ld, 32 bits, DIB_RGB_COLORS): non-NULL %s bits non-NULL %s err=%s",
         (long)height, yesno(h != NULL), yesno(p != NULL), le());
    if (h == NULL || p == NULL) {
        if (h != NULL) {
            DeleteObject(h);
        }
        return;
    }
    bits = (DWORD *)p;
    ZeroMemory(&ds, sizeof ds);
    arm();
    n = GetObjectW(h, sizeof ds, &ds);
    line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
    print_ds(&ds, p);
    ZeroMemory(&bm, sizeof bm);
    arm();
    n = GetObjectW(h, sizeof bm, &bm);
    line("GetObjectW(it, sizeof(BITMAP)): ret=%d err=%s bmBits the bits pointer: %s", n, le(),
         yesno(bm.bmBits == p));

    /* Memory row y, column x: 0x00100000 * (y + 1) + 0x00000100 * (x + 1). */
    for (y = 0; y < 3; y++) {
        for (x = 0; x < 4; x++) {
            bits[y * 4 + x] = 0x00100000u * (DWORD)(y + 1) + 0x00000100u * (DWORD)(x + 1);
        }
    }
    line("memory written: row y, column x holds 0x00100000 * (y + 1) + 0x00000100 * (x + 1)");
    mem = CreateCompatibleDC(NULL);
    old = SelectObject(mem, h);
    arm();
    c = GetPixel(mem, 0, 0);
    line("GetPixel(0, 0): 0x%08lX err=%s", (unsigned long)c, le());
    arm();
    c = GetPixel(mem, 3, 2);
    line("GetPixel(3, 2): 0x%08lX err=%s", (unsigned long)c, le());
    arm();
    c = GetPixel(mem, 4, 0);
    line("GetPixel(4, 0): 0x%08lX err=%s", (unsigned long)c, le());
    arm();
    r = PatBlt(mem, 0, 0, 2, 1, BLACKNESS);
    line("PatBlt(0, 0, 2, 1, BLACKNESS): ret=%d err=%s", r, le());
    GdiFlush();
    for (y = 0; y < 3; y++) {
        line("  memory row %d: %s", y, hexdwords(bits + y * 4, 4));
    }
    SelectObject(mem, old);
    DeleteDC(mem);
    arm();
    r = DeleteObject(h);
    line("DeleteObject(it): ret=%d err=%s", r, le());
}

/* A palettized DIB section: its memory rows after PatBlt in two brushes. */
static void dib_indexed(WORD bpp, const DWORD *table, int colors, const BYTE *init, int stride,
                        COLORREF first, COLORREF second)
{
    bmi_t b;
    HBITMAP h;
    HDC mem;
    HGDIOBJ old, oldb;
    HBRUSH brush;
    DIBSECTION ds;
    COLORREF c;
    BYTE *bits;
    void *p;
    int i, n, y, w;
    BOOL r;

    w = bpp == 8 ? 4 : 8;
    line("-- %dx2, %u bits, top-down, %d colors", w, (unsigned)bpp, colors);
    header(&b, w, -2, bpp);
    b.h.biClrUsed = (DWORD)colors;
    for (i = 0; i < colors; i++) {
        set_color(&b, i, table[i]);
    }
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    line("CreateDIBSection: non-NULL %s bits non-NULL %s err=%s", yesno(h != NULL), yesno(p != NULL),
         le());
    if (h == NULL || p == NULL) {
        if (h != NULL) {
            DeleteObject(h);
        }
        return;
    }
    bits = (BYTE *)p;
    ZeroMemory(&ds, sizeof ds);
    arm();
    n = GetObjectW(h, sizeof ds, &ds);
    line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
    print_ds(&ds, p);
    memcpy(bits, init, (size_t)(2 * stride));
    line("memory written: %s / %s", hexbytes(bits, stride), hexbytes(bits + stride, stride));
    mem = CreateCompatibleDC(NULL);
    old = SelectObject(mem, h);
    arm();
    c = GetPixel(mem, 0, 0);
    line("GetPixel(0, 0): 0x%08lX err=%s", (unsigned long)c, le());
    arm();
    c = GetPixel(mem, 1, 1);
    line("GetPixel(1, 1): 0x%08lX err=%s", (unsigned long)c, le());

    brush = CreateSolidBrush(first);
    oldb = SelectObject(mem, brush);
    arm();
    r = PatBlt(mem, 0, 0, w / 2, 1, PATCOPY);
    line("PatBlt(0, 0, %d, 1, PATCOPY) in 0x%06lX: ret=%d err=%s", w / 2, (unsigned long)first, r,
         le());
    SelectObject(mem, oldb);
    DeleteObject(brush);
    brush = CreateSolidBrush(second);
    oldb = SelectObject(mem, brush);
    arm();
    r = PatBlt(mem, w / 2, 1, w / 2, 1, PATCOPY);
    line("PatBlt(%d, 1, %d, 1, PATCOPY) in 0x%06lX: ret=%d err=%s", w / 2, w / 2,
         (unsigned long)second, r, le());
    SelectObject(mem, oldb);
    DeleteObject(brush);
    GdiFlush();
    for (y = 0; y < 2; y++) {
        line("  memory row %d: %s", y, hexbytes(bits + y * stride, stride));
    }
    SelectObject(mem, old);
    DeleteDC(mem);
    DeleteObject(h);
}

static void sec_dibsect(void)
{
    static const DWORD table8[4] = { 0x000000, 0xFF0000, 0x00FF00, 0xFFFFFF };
    static const BYTE init8[8] = { 0, 1, 2, 3, 3, 2, 1, 0 };
    static const DWORD table1[2] = { 0xFF0000, 0xFFFFFF };
    static const BYTE init1[8] = { 0xA5, 0, 0, 0, 0x0F, 0, 0, 0 };
    bmi_t b;
    HBITMAP h;
    HDC mem;
    HGDIOBJ old, oldb;
    HBRUSH brush;
    DIBSECTION ds;
    COLORREF c;
    DWORD *masks;
    BYTE *bytes;
    void *p;
    int n;
    BOOL r;

    dib_32(-3);
    dib_32(3);
    dib_indexed(8, table8, 4, init8, 4, RGB(0, 255, 0), RGB(0xC0, 0x10, 0x10));
    dib_indexed(1, table1, 2, init1, 4, RGB(0, 0, 0), RGB(255, 255, 255));

    line("-- 3x2, 24 bits, bottom-up");
    header(&b, 3, 2, 24);
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    line("CreateDIBSection: non-NULL %s bits non-NULL %s err=%s", yesno(h != NULL), yesno(p != NULL),
         le());
    if (h != NULL && p != NULL) {
        ZeroMemory(&ds, sizeof ds);
        arm();
        n = GetObjectW(h, sizeof ds, &ds);
        line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
        print_ds(&ds, p);
        bytes = (BYTE *)p;
        for (n = 0; n < 24; n++) {
            bytes[n] = (BYTE)(0x10 + n);
        }
        line("memory written: byte i holds 0x10 + i, 24 bytes");
        mem = CreateCompatibleDC(NULL);
        old = SelectObject(mem, h);
        arm();
        c = GetPixel(mem, 0, 0);
        line("GetPixel(0, 0): 0x%08lX err=%s", (unsigned long)c, le());
        arm();
        c = GetPixel(mem, 2, 1);
        line("GetPixel(2, 1): 0x%08lX err=%s", (unsigned long)c, le());
        SelectObject(mem, old);
        DeleteDC(mem);
    }
    if (h != NULL) {
        DeleteObject(h);
    }

    line("-- 2x1, 16 bits, BI_BITFIELDS F800 07E0 001F");
    header(&b, 2, -1, 16);
    b.h.biCompression = BI_BITFIELDS;
    masks = (DWORD *)b.c;
    masks[0] = 0xF800;
    masks[1] = 0x07E0;
    masks[2] = 0x001F;
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    line("CreateDIBSection: non-NULL %s bits non-NULL %s err=%s", yesno(h != NULL), yesno(p != NULL),
         le());
    if (h != NULL && p != NULL) {
        ZeroMemory(&ds, sizeof ds);
        arm();
        n = GetObjectW(h, sizeof ds, &ds);
        line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
        print_ds(&ds, p);
        mem = CreateCompatibleDC(NULL);
        old = SelectObject(mem, h);
        brush = CreateSolidBrush(RGB(255, 0, 0));
        oldb = SelectObject(mem, brush);
        arm();
        r = PatBlt(mem, 0, 0, 1, 1, PATCOPY);
        line("PatBlt(0, 0, 1, 1, PATCOPY) in red: ret=%d err=%s", r, le());
        SelectObject(mem, oldb);
        DeleteObject(brush);
        brush = CreateSolidBrush(RGB(0x80, 0x80, 0x80));
        oldb = SelectObject(mem, brush);
        arm();
        r = PatBlt(mem, 1, 0, 1, 1, PATCOPY);
        line("PatBlt(1, 0, 1, 1, PATCOPY) in 0x808080: ret=%d err=%s", r, le());
        SelectObject(mem, oldb);
        DeleteObject(brush);
        GdiFlush();
        line("  memory: %s", hexbytes((BYTE *)p, 4));
        arm();
        c = GetPixel(mem, 1, 0);
        line("GetPixel(1, 0): 0x%08lX err=%s", (unsigned long)c, le());
        SelectObject(mem, old);
        DeleteDC(mem);
    }
    if (h != NULL) {
        DeleteObject(h);
    }

    line("-- refused");
    header(&b, 4, 2, 0);
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    line("CreateDIBSection(biBitCount 0): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        DeleteObject(h);
    }
    header(&b, 4, 2, 32);
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, 7, &p, NULL, 0);
    line("CreateDIBSection(usage 7): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        DeleteObject(h);
    }
    header(&b, 0, 2, 32);
    p = NULL;
    arm();
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    line("CreateDIBSection(biWidth 0): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        DeleteObject(h);
    }
}

/* --- blit ---------------------------------------------------------- */

static const DWORD blit_d[6] = {
    0x00000000, 0x00000000, 0x00FFFFFF, 0x00FFFFFF, 0x00F0CC0F, 0x00336699
};
static const DWORD blit_s[6] = {
    0x00000000, 0x00FFFFFF, 0x00000000, 0x00FFFFFF, 0x000F33F0, 0x00CC9966
};

static const struct rop_s {
    const char *name;
    DWORD rop;
} rops[] = {
    { "SRCCOPY", SRCCOPY },
    { "SRCPAINT", SRCPAINT },
    { "SRCAND", SRCAND },
    { "SRCINVERT", SRCINVERT },
    { "SRCERASE", SRCERASE },
    { "NOTSRCCOPY", NOTSRCCOPY },
    { "MERGECOPY", MERGECOPY },
    { "PATCOPY", PATCOPY },
    { "PATINVERT", PATINVERT },
    { "DSTINVERT", DSTINVERT },
    { "BLACKNESS", BLACKNESS },
    { "WHITENESS", WHITENESS },
    { NULL, 0 }
};

static void sec_blit(void)
{
    canvas_t dst, src;
    HBRUSH brush;
    HGDIOBJ oldb;
    int i;
    BOOL r;

    if (!canvas_open(&dst, 6, 1)) {
        return;
    }
    if (!canvas_open(&src, 6, 1)) {
        canvas_close(&dst);
        return;
    }
    canvas_set(&src, blit_s);
    brush = CreateSolidBrush(RGB(0x20, 0x40, 0x80));
    oldb = SelectObject(dst.dc, brush);
    line("destination (6x1): %s", hexdwords(blit_d, 6));
    line("source (6x1):      %s", hexdwords(blit_s, 6));
    line("brush: solid, RGB(0x20, 0x40, 0x80)");
    for (i = 0; rops[i].name != NULL; i++) {
        canvas_set(&dst, blit_d);
        arm();
        r = BitBlt(dst.dc, 0, 0, 6, 1, src.dc, 0, 0, rops[i].rop);
        GdiFlush();
        line("BitBlt(dst, 0, 0, 6, 1, src, 0, 0, %s): ret=%d err=%s -> %s", rops[i].name, r, le(),
             hexdwords(dst.bits, 6));
    }

    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 1, 0, 3, 1, src.dc, 2, 0, SRCCOPY);
    GdiFlush();
    line("BitBlt(dst, 1, 0, 3, 1, src, 2, 0, SRCCOPY): ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 6));
    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 1, 0, 5, 1, dst.dc, 0, 0, SRCCOPY);
    GdiFlush();
    line("BitBlt(dst, 1, 0, 5, 1, dst, 0, 0, SRCCOPY), overlapping: ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 6));
    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 0, 0, 5, 1, dst.dc, 1, 0, SRCCOPY);
    GdiFlush();
    line("BitBlt(dst, 0, 0, 5, 1, dst, 1, 0, SRCCOPY), overlapping: ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 6));
    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 4, 0, 6, 1, src.dc, 0, 0, SRCCOPY);
    GdiFlush();
    line("BitBlt(dst, 4, 0, 6, 1, src, 0, 0, SRCCOPY), past the edge: ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 6));
    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 0, 0, 6, 1, src.dc, -2, 0, SRCCOPY);
    GdiFlush();
    line("BitBlt(dst, 0, 0, 6, 1, src, -2, 0, SRCCOPY), left of the source: ret=%d err=%s -> %s", r,
         le(), hexdwords(dst.bits, 6));
    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 0, 0, 6, 1, NULL, 0, 0, SRCCOPY);
    GdiFlush();
    line("BitBlt(dst, 0, 0, 6, 1, NULL, 0, 0, SRCCOPY): ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 6));
    canvas_set(&dst, blit_d);
    arm();
    r = BitBlt(dst.dc, 0, 0, 6, 1, NULL, 0, 0, PATCOPY);
    GdiFlush();
    line("BitBlt(dst, 0, 0, 6, 1, NULL, 0, 0, PATCOPY): ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 6));

    SelectObject(dst.dc, oldb);
    DeleteObject(brush);
    canvas_close(&src);
    canvas_close(&dst);
}

/* --- mono ---------------------------------------------------------- */

static void sec_mono(void)
{
    static const BYTE mono2[4] = { 0xA5, 0x00, 0x0F, 0x00 };
    static const BYTE mono1[2] = { 0xA5, 0x00 };
    static const BYTE zero1[2] = { 0x00, 0x00 };
    static const DWORD colors8[8] = {
        0x0000FF00, 0x00FF0000, 0x0000FF00, 0x00FFFFFF, 0x00000000, 0x0000FF00, 0x000000FF, 0x0000FE00
    };
    canvas_t dst, src;
    HBITMAP mono, monob, h1;
    HDC mdc, mdc2, sdc;
    HGDIOBJ oldm, oldm2, olds;
    bmi_t b;
    void *p;
    BOOL r;

    if (!canvas_open(&dst, 8, 2)) {
        return;
    }
    mono = CreateBitmap(8, 2, 1, 1, mono2);
    mdc = CreateCompatibleDC(NULL);
    oldm = SelectObject(mdc, mono);
    SetTextColor(mdc, RGB(0, 255, 0));
    SetBkColor(mdc, RGB(255, 255, 255));
    line("-- monochrome 8x2 (rows A5, 0F) to color; the source DC's text green, background white");
    SetTextColor(dst.dc, RGB(255, 0, 0));
    SetBkColor(dst.dc, RGB(0, 0, 255));
    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    r = BitBlt(dst.dc, 0, 0, 8, 2, mdc, 0, 0, SRCCOPY);
    line("BitBlt SRCCOPY, the destination's text red, background blue: ret=%d err=%s", r, le());
    letter_rows(&dst);
    SetTextColor(dst.dc, RGB(0, 0, 0));
    SetBkColor(dst.dc, RGB(255, 255, 255));
    canvas_fill(&dst, 0x000000FF);
    arm();
    r = BitBlt(dst.dc, 0, 0, 8, 2, mdc, 0, 0, SRCCOPY);
    line("BitBlt SRCCOPY, the destination's text black, background white: ret=%d err=%s", r, le());
    letter_rows(&dst);
    SetTextColor(dst.dc, RGB(255, 0, 0));
    SetBkColor(dst.dc, RGB(255, 255, 255));
    canvas_fill(&dst, 0x0000FF00);
    arm();
    r = BitBlt(dst.dc, 0, 0, 8, 2, mdc, 0, 0, SRCAND);
    line("BitBlt SRCAND over green, the destination's text red, background white: ret=%d err=%s", r,
         le());
    letter_rows(&dst);
    SelectObject(mdc, oldm);
    DeleteObject(mono);
    canvas_close(&dst);

    line("-- color 8x1 to monochrome: %s", hexdwords(colors8, 8));
    if (!canvas_open(&src, 8, 1)) {
        DeleteDC(mdc);
        return;
    }
    canvas_set(&src, colors8);
    SetTextColor(src.dc, RGB(255, 0, 0));
    monob = CreateBitmap(8, 1, 1, 1, zero1);
    mdc2 = CreateCompatibleDC(NULL);
    oldm2 = SelectObject(mdc2, monob);
    SetBkColor(src.dc, RGB(0, 255, 0));
    arm();
    r = BitBlt(mdc2, 0, 0, 8, 1, src.dc, 0, 0, SRCCOPY);
    line("BitBlt SRCCOPY, the source's background green: ret=%d err=%s", r, le());
    SelectObject(mdc2, oldm2);
    mono_read("the monochrome bitmap", monob, 8, 1);
    oldm2 = SelectObject(mdc2, monob);
    SetBkColor(src.dc, RGB(255, 255, 255));
    arm();
    r = BitBlt(mdc2, 0, 0, 8, 1, src.dc, 0, 0, SRCCOPY);
    line("BitBlt SRCCOPY, the source's background white: ret=%d err=%s", r, le());
    SelectObject(mdc2, oldm2);
    mono_read("the monochrome bitmap", monob, 8, 1);
    canvas_close(&src);

    line("-- monochrome to monochrome (A5), the destination's text red, background blue");
    mono = CreateBitmap(8, 1, 1, 1, mono1);
    oldm = SelectObject(mdc, mono);
    oldm2 = SelectObject(mdc2, monob);
    SetTextColor(mdc2, RGB(255, 0, 0));
    SetBkColor(mdc2, RGB(0, 0, 255));
    arm();
    r = BitBlt(mdc2, 0, 0, 8, 1, mdc, 0, 0, SRCCOPY);
    line("BitBlt SRCCOPY: ret=%d err=%s", r, le());
    SelectObject(mdc2, oldm2);
    mono_read("the destination", monob, 8, 1);
    SelectObject(mdc, oldm);
    DeleteObject(mono);
    DeleteObject(monob);
    DeleteDC(mdc2);
    DeleteDC(mdc);

    line("-- a 1-bit DIB section (A5, table red, green) to color, the destination's text black,"
         " background white");
    header(&b, 8, -1, 1);
    set_color(&b, 0, 0xFF0000);
    set_color(&b, 1, 0x00FF00);
    p = NULL;
    h1 = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    if (h1 == NULL || p == NULL || !canvas_open(&dst, 8, 1)) {
        line("the DIB section or canvas: not made");
        if (h1 != NULL) {
            DeleteObject(h1);
        }
        return;
    }
    *(BYTE *)p = 0xA5;
    sdc = CreateCompatibleDC(NULL);
    olds = SelectObject(sdc, h1);
    SetTextColor(dst.dc, RGB(0, 0, 0));
    SetBkColor(dst.dc, RGB(255, 255, 255));
    arm();
    r = BitBlt(dst.dc, 0, 0, 8, 1, sdc, 0, 0, SRCCOPY);
    line("BitBlt SRCCOPY: ret=%d err=%s", r, le());
    letter_rows(&dst);
    SelectObject(sdc, olds);
    DeleteDC(sdc);
    DeleteObject(h1);
    canvas_close(&dst);
}

/* --- stretch ------------------------------------------------------- */

static const struct mode_s {
    const char *name;
    int mode;
} modes[] = {
    { "BLACKONWHITE", BLACKONWHITE },
    { "WHITEONBLACK", WHITEONBLACK },
    { "COLORONCOLOR", COLORONCOLOR },
    { "HALFTONE", HALFTONE },
    { "0", 0 },
    { "5", 5 },
    { NULL, 0 }
};

static const DWORD stretch_src[16] = {
    0x00FF0000, 0x0000FF00, 0x000000FF, 0x00FFFFFF, 0x00000000, 0x00FF00FF, 0x00808080, 0x0000FFFF,
    0x000F0F0F, 0x00F0F0F0, 0x0000FF00, 0x00FF0000, 0x00FFFFFF, 0x00000000, 0x00123456, 0x00654321
};

static void sec_stretch(void)
{
    static const BYTE m8[2] = { 0xB4, 0x00 };
    static const BYTE m4[2] = { 0x00, 0x00 };
    canvas_t dst, src, big, small;
    HBITMAP b8, b4;
    HDC dc8, dc4;
    HGDIOBJ old8, old4;
    DWORD px[6];
    int i, prev, got, x, y;
    BOOL r;

    if (!canvas_open(&dst, 4, 1)) {
        return;
    }
    arm();
    got = GetStretchBltMode(dst.dc);
    line("GetStretchBltMode(a new DC): ret=%d err=%s", got, le());
    for (i = 0; modes[i].name != NULL; i++) {
        arm();
        prev = SetStretchBltMode(dst.dc, modes[i].mode);
        line("SetStretchBltMode(dst, %s): previous=%d err=%s", modes[i].name, prev, le());
        arm();
        got = GetStretchBltMode(dst.dc);
        line("GetStretchBltMode(dst): ret=%d err=%s", got, le());
    }

    if (!canvas_open(&src, 8, 2)) {
        canvas_close(&dst);
        return;
    }
    canvas_set(&src, stretch_src);
    line("-- 8x2 color to 4x1; source rows %s / %s", hexdwords(stretch_src, 8),
         hexdwords(stretch_src + 8, 8));
    for (i = 0; i < 3; i++) {
        SetStretchBltMode(dst.dc, modes[i].mode);
        canvas_fill(&dst, 0x00777777);
        arm();
        r = StretchBlt(dst.dc, 0, 0, 4, 1, src.dc, 0, 0, 8, 2, SRCCOPY);
        GdiFlush();
        line("StretchBlt under %s: ret=%d err=%s -> %s", modes[i].name, r, le(), hexdwords(dst.bits, 4));
    }

    line("-- monochrome 8x1 (B4) to 4x1");
    b8 = CreateBitmap(8, 1, 1, 1, m8);
    b4 = CreateBitmap(4, 1, 1, 1, m4);
    dc8 = CreateCompatibleDC(NULL);
    dc4 = CreateCompatibleDC(NULL);
    old8 = SelectObject(dc8, b8);
    for (i = 0; i < 3; i++) {
        old4 = SelectObject(dc4, b4);
        SetStretchBltMode(dc4, modes[i].mode);
        PatBlt(dc4, 0, 0, 4, 1, BLACKNESS);
        arm();
        r = StretchBlt(dc4, 0, 0, 4, 1, dc8, 0, 0, 8, 1, SRCCOPY);
        line("StretchBlt under %s: ret=%d err=%s", modes[i].name, r, le());
        SelectObject(dc4, old4);
        mono_read("the 4x1", b4, 4, 1);
    }
    SelectObject(dc8, old8);
    DeleteDC(dc8);
    DeleteDC(dc4);
    DeleteObject(b8);
    DeleteObject(b4);

    line("-- 3x2 to 7x5 under COLORONCOLOR; source pixel x, y: 0x00110000 * (y + 1) + 0x11 * (x + 1)");
    if (canvas_open(&small, 3, 2)) {
        if (canvas_open(&big, 7, 5)) {
            for (y = 0; y < 2; y++) {
                for (x = 0; x < 3; x++) {
                    px[y * 3 + x] = 0x00110000u * (DWORD)(y + 1) + 0x11u * (DWORD)(x + 1);
                }
            }
            canvas_set(&small, px);
            canvas_fill(&big, 0);
            SetStretchBltMode(big.dc, COLORONCOLOR);
            arm();
            r = StretchBlt(big.dc, 0, 0, 7, 5, small.dc, 0, 0, 3, 2, SRCCOPY);
            line("StretchBlt(big, 0, 0, 7, 5, small, 0, 0, 3, 2, SRCCOPY): ret=%d err=%s", r, le());
            hex_rows(&big, "big");
            canvas_close(&big);
        }
        canvas_close(&small);
    }

    line("-- mirrored, the source's first row's first four pixels");
    SetStretchBltMode(dst.dc, COLORONCOLOR);
    canvas_fill(&dst, 0x00777777);
    arm();
    r = StretchBlt(dst.dc, 3, 0, -4, 1, src.dc, 0, 0, 4, 1, SRCCOPY);
    GdiFlush();
    line("StretchBlt(dst, 3, 0, -4, 1, src, 0, 0, 4, 1, SRCCOPY): ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 4));
    canvas_fill(&dst, 0x00777777);
    arm();
    r = StretchBlt(dst.dc, 0, 0, 4, 1, src.dc, 3, 0, -4, 1, SRCCOPY);
    GdiFlush();
    line("StretchBlt(dst, 0, 0, 4, 1, src, 3, 0, -4, 1, SRCCOPY): ret=%d err=%s -> %s", r, le(),
         hexdwords(dst.bits, 4));
    canvas_close(&src);
    canvas_close(&dst);
}

/* --- dibits -------------------------------------------------------- */

static void query_header(HDC ref, WORD bpp)
{
    HBITMAP hb;
    bmi_t b;
    DWORD *masks;
    int n;

    hb = CreateBitmap(5, 3, 1, bpp, NULL);
    ZeroMemory(&b, sizeof b);
    b.h.biSize = sizeof b.h;
    arm();
    n = GetDIBits(ref, hb, 0, 3, NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("GetDIBits(a 5x3 %u-bit bitmap, 0, 3, NULL, biBitCount 0): ret=%d err=%s", (unsigned)bpp, n,
         le());
    line("  biWidth=%ld biHeight=%ld biPlanes=%u biBitCount=%u biCompression=%lu biSizeImage=%lu"
         " biClrUsed=%lu biClrImportant=%lu", (long)b.h.biWidth, (long)b.h.biHeight,
         (unsigned)b.h.biPlanes, (unsigned)b.h.biBitCount, (unsigned long)b.h.biCompression,
         (unsigned long)b.h.biSizeImage, (unsigned long)b.h.biClrUsed,
         (unsigned long)b.h.biClrImportant);
    if (b.h.biCompression == BI_BITFIELDS) {
        masks = (DWORD *)b.c;
        line("  masks %08lX %08lX %08lX", (unsigned long)masks[0], (unsigned long)masks[1],
             (unsigned long)masks[2]);
    }
    DeleteObject(hb);
}

static void print_read32(HBITMAP hb, const char *what)
{
    DWORD px[8];
    int n;

    arm();
    n = read32(hb, 4, 2, px);
    line("GetDIBits(%s, 32 bits, top-down): ret=%d err=%s -> %s / %s", what, n, le(),
         hexdwords(px, 4), hexdwords(px + 4, 4));
}

/* GetDIBits of the 4x2 bitmap at bpp bits, bottom-up: the table and rows. */
static void read_as(HDC ref, HBITMAP hb, WORD bpp)
{
    bmi_t b;
    BYTE buf[64];
    char table[200];
    int n, i, k, stride, colors;

    header(&b, 4, 2, bpp);
    ZeroMemory(buf, sizeof buf);
    arm();
    n = GetDIBits(ref, hb, 0, 2, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    stride = (4 * bpp + 31) / 32 * 4;
    line("GetDIBits(%u bits, bottom-up): ret=%d err=%s biSizeImage=%lu biClrUsed=%lu", (unsigned)bpp,
         n, le(), (unsigned long)b.h.biSizeImage, (unsigned long)b.h.biClrUsed);
    colors = bpp <= 8 ? 1 << bpp : 0;
    if (colors == 256) {
        line("  table: CRC-32 %08lX, entries 0-3 %08lX %08lX %08lX %08lX",
             (unsigned long)crc32_of((const BYTE *)b.c, sizeof b.c), (unsigned long)color_of(&b.c[0]),
             (unsigned long)color_of(&b.c[1]), (unsigned long)color_of(&b.c[2]),
             (unsigned long)color_of(&b.c[3]));
    } else if (colors != 0) {
        k = 0;
        for (i = 0; i < colors; i++) {
            k += sprintf(table + k, "%s%06lX", i ? " " : "", (unsigned long)color_of(&b.c[i]));
        }
        line("  table: %s", table);
    }
    line("  stored row 0 (the bottom): %s", hexbytes(buf, stride));
    line("  stored row 1 (the top):    %s", hexbytes(buf + stride, stride));
}

static void sec_dibits(void)
{
    static const WORD bpps[] = { 1, 4, 8, 24, 32 };
    static const BYTE src24[24] = {
        0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x80, 0x80, 0x80, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x80
    };
    static const BYTE src8[8] = { 0, 1, 2, 3, 3, 3, 0, 0 };
    static const DWORD one_row[4] = { 0x00ABCDEF, 0x00ABCDEF, 0x00ABCDEF, 0x00ABCDEF };
    static const DWORD vga8[8] = {
        0x00FF0000, 0x0000FF00, 0x000000FF, 0x00FFFFFF, 0x00000000, 0x00808080, 0x00C0C0C0, 0x00800000
    };
    static const DWORD to_mono[8] = {
        0x00FFFFFF, 0x00000000, 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00808080, 0x00C0C0C0, 0x0000FFFF
    };
    static const BYTE zero1[2] = { 0, 0 };
    HDC ref, mem;
    HBITMAP ddb, mono;
    HGDIOBJ old;
    bmi_t b;
    DWORD buf[24];
    int i, n;

    ref = CreateCompatibleDC(NULL);
    for (i = 0; i < (int)(sizeof bpps / sizeof bpps[0]); i++) {
        query_header(ref, bpps[i]);
    }

    ddb = CreateBitmap(4, 2, 1, 32, NULL);
    line("-- a 4x2 32-bit bitmap (CreateBitmap): non-NULL %s", yesno(ddb != NULL));
    if (ddb == NULL) {
        DeleteDC(ref);
        return;
    }
    header(&b, 4, -2, 24);
    arm();
    n = SetDIBits(ref, ddb, 0, 2, src24, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("SetDIBits(24 bits, top-down: red green blue white / black gray silver maroon): ret=%d err=%s",
         n, le());
    print_read32(ddb, "it");
    header(&b, 4, 2, 32);
    ZeroMemory(buf, sizeof buf);
    arm();
    n = GetDIBits(ref, ddb, 0, 2, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("GetDIBits(it, 32 bits, bottom-up): ret=%d err=%s -> stored %s / %s", n, le(),
         hexdwords(buf, 4), hexdwords(buf + 4, 4));

    header(&b, 4, 2, 8);
    b.h.biClrUsed = 4;
    set_color(&b, 0, 0x000080);
    set_color(&b, 1, 0x808000);
    set_color(&b, 2, 0x008080);
    set_color(&b, 3, 0x800080);
    arm();
    n = SetDIBits(ref, ddb, 0, 2, src8, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("SetDIBits(8 bits, bottom-up, table navy olive teal purple, stored 00 01 02 03 / 03 03 00 00):"
         " ret=%d err=%s", n, le());
    print_read32(ddb, "it");

    header(&b, 4, 2, 32);
    arm();
    n = SetDIBits(ref, ddb, 1, 1, one_row, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("SetDIBits(32 bits, bottom-up, height 2, scan 1, 1 line of 00ABCDEF): ret=%d err=%s", n, le());
    print_read32(ddb, "it");
    header(&b, 4, 2, 32);
    ZeroMemory(buf, sizeof buf);
    arm();
    n = GetDIBits(ref, ddb, 1, 1, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("GetDIBits(it, 32 bits, bottom-up, height 2, scan 1, 1 line): ret=%d err=%s -> %s", n, le(),
         hexdwords(buf, 4));
    header(&b, 4, 2, 32);
    ZeroMemory(buf, sizeof buf);
    arm();
    n = GetDIBits(ref, ddb, 0, 5, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("GetDIBits(it, 32 bits, bottom-up, height 2, scan 0, 5 lines): ret=%d err=%s", n, le());

    header(&b, 4, -2, 32);
    arm();
    n = SetDIBits(ref, ddb, 0, 2, vga8, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("SetDIBits(32 bits, top-down: %s / %s): ret=%d err=%s", hexdwords(vga8, 4),
         hexdwords(vga8 + 4, 4), n, le());
    read_as(ref, ddb, 24);
    read_as(ref, ddb, 16);
    read_as(ref, ddb, 8);
    read_as(ref, ddb, 4);
    read_as(ref, ddb, 1);

    line("-- colors into an 8x1 monochrome bitmap: %s", hexdwords(to_mono, 8));
    mono = CreateBitmap(8, 1, 1, 1, zero1);
    header(&b, 8, 1, 32);
    arm();
    n = SetDIBits(ref, mono, 0, 1, to_mono, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("SetDIBits(32 bits): ret=%d err=%s", n, le());
    mono_read("it", mono, 8, 1);

    line("-- refused");
    header(&b, 4, 2, 32);
    arm();
    n = GetDIBits(ref, NULL, 0, 2, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("GetDIBits(ref, NULL, ...): ret=%d err=%s", n, le());
    header(&b, 4, 2, 32);
    arm();
    n = SetDIBits(ref, ddb, 0, 0, vga8, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("SetDIBits(ref, it, 0, 0 lines, ...): ret=%d err=%s", n, le());
    mem = CreateCompatibleDC(NULL);
    old = SelectObject(mem, mono);
    header(&b, 8, 1, 1);
    ZeroMemory(buf, sizeof buf);
    arm();
    n = GetDIBits(ref, mono, 0, 1, buf, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("GetDIBits of the monochrome bitmap while a DC holds it: ret=%d err=%s -> %s", n, le(),
         hexbytes((BYTE *)buf, 1));
    SelectObject(mem, old);
    DeleteDC(mem);
    DeleteObject(mono);
    DeleteObject(ddb);
    DeleteDC(ref);
}

/* --- todevice ------------------------------------------------------ */

static DWORD pv(int x, int y)
{
    return 0x00110000u * (DWORD)(y + 1) + 0x11u * (DWORD)(x + 1);
}

static void sec_todevice(void)
{
    static const BYTE mono_bits[8] = { 0x0F, 0, 0, 0, 0xA5, 0, 0, 0 };
    canvas_t dst;
    bmi_t bu, td, b1;
    DWORD up[20], down[20];
    int x, y, n;

    if (!canvas_open(&dst, 8, 6)) {
        return;
    }
    for (y = 0; y < 4; y++) {
        for (x = 0; x < 5; x++) {
            up[(3 - y) * 5 + x] = pv(x, y);
            down[y * 5 + x] = pv(x, y);
        }
    }
    header(&bu, 5, 4, 32);
    header(&td, 5, -4, 32);
    line("the source: 5x4, 32 bits; the pixel x, y (from the top) 0x00110000 * (y + 1) + 0x11 * (x + 1)");
    line("the canvas: 8x6, filled with 0 before each call");

    canvas_fill(&dst, 0);
    arm();
    n = SetDIBitsToDevice(dst.dc, 0, 0, 5, 4, 0, 0, 0, 4, up, (BITMAPINFO *)&bu, DIB_RGB_COLORS);
    line("SetDIBitsToDevice(dst, 0, 0, 5, 4, 0, 0, 0, 4, bottom-up): ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0);
    arm();
    n = SetDIBitsToDevice(dst.dc, 2, 1, 3, 2, 1, 1, 0, 4, up, (BITMAPINFO *)&bu, DIB_RGB_COLORS);
    line("SetDIBitsToDevice(dst, 2, 1, 3, 2, 1, 1, 0, 4, bottom-up): ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0);
    arm();
    n = SetDIBitsToDevice(dst.dc, 0, 0, 5, 4, 0, 0, 1, 2, up + 5, (BITMAPINFO *)&bu, DIB_RGB_COLORS);
    line("SetDIBitsToDevice(dst, 0, 0, 5, 4, 0, 0, 1, 2, stored rows 1-2 of the bottom-up DIB):"
         " ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0);
    arm();
    n = SetDIBitsToDevice(dst.dc, 0, 0, 5, 4, 0, 0, 0, 4, down, (BITMAPINFO *)&td, DIB_RGB_COLORS);
    line("SetDIBitsToDevice(dst, 0, 0, 5, 4, 0, 0, 0, 4, top-down): ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");

    SetStretchBltMode(dst.dc, COLORONCOLOR);
    canvas_fill(&dst, 0);
    arm();
    n = StretchDIBits(dst.dc, 0, 0, 8, 6, 0, 0, 5, 4, up, (BITMAPINFO *)&bu, DIB_RGB_COLORS, SRCCOPY);
    line("StretchDIBits(dst, 0, 0, 8, 6, 0, 0, 5, 4, bottom-up, SRCCOPY) under COLORONCOLOR:"
         " ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0);
    arm();
    n = StretchDIBits(dst.dc, 1, 1, 3, 2, 1, 1, 3, 2, up, (BITMAPINFO *)&bu, DIB_RGB_COLORS, SRCCOPY);
    line("StretchDIBits(dst, 1, 1, 3, 2, 1, 1, 3, 2, bottom-up, SRCCOPY): ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0);
    arm();
    n = StretchDIBits(dst.dc, 4, 0, -5, 4, 0, 0, 5, 4, up, (BITMAPINFO *)&bu, DIB_RGB_COLORS, SRCCOPY);
    line("StretchDIBits(dst, 4, 0, -5, 4, 0, 0, 5, 4, bottom-up, SRCCOPY): ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0);
    arm();
    n = StretchDIBits(dst.dc, 0, 0, 5, 4, 0, 0, 5, 4, down, (BITMAPINFO *)&td, DIB_RGB_COLORS, SRCCOPY);
    line("StretchDIBits(dst, 0, 0, 5, 4, 0, 0, 5, 4, top-down, SRCCOPY): ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");
    canvas_fill(&dst, 0x00FFFFFF);
    arm();
    n = StretchDIBits(dst.dc, 0, 0, 5, 4, 0, 0, 5, 4, up, (BITMAPINFO *)&bu, DIB_RGB_COLORS,
                      SRCINVERT);
    line("StretchDIBits(dst, 0, 0, 5, 4, 0, 0, 5, 4, bottom-up, SRCINVERT) over 00FFFFFF:"
         " ret=%d err=%s", n, le());
    hex_rows(&dst, "dst");

    header(&b1, 8, 2, 1);
    set_color(&b1, 0, 0xFF0000);
    set_color(&b1, 1, 0x0000FF);
    SetTextColor(dst.dc, RGB(0, 255, 0));
    SetBkColor(dst.dc, RGB(255, 255, 255));
    canvas_fill(&dst, 0);
    arm();
    n = StretchDIBits(dst.dc, 0, 0, 8, 2, 0, 0, 8, 2, mono_bits, (BITMAPINFO *)&b1, DIB_RGB_COLORS,
                      SRCCOPY);
    line("StretchDIBits(dst, 0, 0, 8, 2, 0, 0, 8, 2, 1 bit bottom-up, stored 0F / A5, table red blue,"
         " SRCCOPY), the DC's text green, background white: ret=%d err=%s", n, le());
    letter_rows(&dst);
    canvas_close(&dst);
}

/* --- createdib ----------------------------------------------------- */

static void sec_createdib(void)
{
    static const DWORD pix[8] = {
        0x00000000, 0x00FFFFFF, 0x00FF0000, 0x0000FF00, 0x000000FF, 0x00FFFFFF, 0x00000000, 0x00808080
    };
    static const BYTE mono_bits[8] = { 0xA5, 0, 0, 0, 0x0F, 0, 0, 0 };
    HDC screen, ref;
    HBITMAP h;
    BITMAP bm;
    bmi_t b, b1;
    DWORD px[8];
    int bpp, n;

    bpp = screen_bpp();
    screen = GetDC(NULL);
    ref = CreateCompatibleDC(NULL);
    header(&b, 4, -2, 32);
    line("the DIB: 4x2, 32 bits, top-down: %s / %s", hexdwords(pix, 4), hexdwords(pix + 4, 4));

    arm();
    h = CreateDIBitmap(screen, &b.h, CBM_INIT, pix, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("CreateDIBitmap(screen DC, CBM_INIT): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        get_bitmap_rel("it", h, bpp);
        n = read32(h, 4, 2, px);
        line("  read back as written (GetDIBits, 32 bits): %s", yesno(n == 2
             && memcmp(px, pix, sizeof px) == 0));
        DeleteObject(h);
    }

    arm();
    h = CreateDIBitmap(screen, &b.h, 0, NULL, NULL, 0);
    line("CreateDIBitmap(screen DC, 0, NULL, NULL, 0): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        get_bitmap_rel("it", h, bpp);
        DeleteObject(h);
    }

    arm();
    h = CreateDIBitmap(ref, &b.h, CBM_INIT, pix, (BITMAPINFO *)&b, DIB_RGB_COLORS);
    line("CreateDIBitmap(a memory DC holding its default bitmap, CBM_INIT): non-NULL %s err=%s",
         yesno(h != NULL), le());
    if (h != NULL) {
        get_bitmap("it", h);
        mono_read("it", h, 4, 2);
        DeleteObject(h);
    }

    header(&b1, 8, 2, 1);
    set_color(&b1, 0, 0x000000);
    set_color(&b1, 1, 0xFFFFFF);
    arm();
    h = CreateDIBitmap(screen, &b1.h, CBM_INIT, mono_bits, (BITMAPINFO *)&b1, DIB_RGB_COLORS);
    line("CreateDIBitmap(screen DC, CBM_INIT, 8x2 1 bit bottom-up, stored A5 / 0F, table black white):"
         " non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        ZeroMemory(&bm, sizeof bm);
        GetObjectW(h, sizeof bm, &bm);
        line("  bmWidth=%ld bmHeight=%ld bmPlanes=%u bmBitsPixel 1: %s the screen's: %s",
             (long)bm.bmWidth, (long)bm.bmHeight, (unsigned)bm.bmPlanes, yesno(bm.bmBitsPixel == 1),
             yesno(bm.bmBitsPixel == bpp));
        mono_read("it", h, 8, 2);
        DeleteObject(h);
    }
    set_color(&b1, 0, 0xFF0000);
    set_color(&b1, 1, 0x0000FF);
    arm();
    h = CreateDIBitmap(screen, &b1.h, CBM_INIT, mono_bits, (BITMAPINFO *)&b1, DIB_RGB_COLORS);
    line("CreateDIBitmap(screen DC, CBM_INIT, the same, table red blue): non-NULL %s err=%s",
         yesno(h != NULL), le());
    if (h != NULL) {
        ZeroMemory(&bm, sizeof bm);
        GetObjectW(h, sizeof bm, &bm);
        line("  bmWidth=%ld bmHeight=%ld bmPlanes=%u bmBitsPixel 1: %s the screen's: %s",
             (long)bm.bmWidth, (long)bm.bmHeight, (unsigned)bm.bmPlanes, yesno(bm.bmBitsPixel == 1),
             yesno(bm.bmBitsPixel == bpp));
        DeleteObject(h);
    }

    arm();
    h = CreateDIBitmap(ref, &b.h, CBM_INIT, pix, (BITMAPINFO *)&b, 7);
    line("CreateDIBitmap(usage 7): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        DeleteObject(h);
    }
    DeleteDC(ref);
    ReleaseDC(NULL, screen);
}

/* --- pattern ------------------------------------------------------- */

static void sec_pattern(void)
{
    /* 8x8, rows word-aligned: E0 E0 E0 00 00 00 00 01 */
    static const BYTE pat_bits[16] = {
        0xE0, 0, 0xE0, 0, 0xE0, 0, 0x00, 0, 0x00, 0, 0x00, 0, 0x00, 0, 0x01, 0
    };
    DWORD quad[64];
    DWORD before[128];
    canvas_t c;
    HBITMAP pat;
    HBRUSH brush;
    HGDIOBJ oldb;
    LOGBRUSH lb;
    POINT pt;
    DWORD type;
    int n, x, y;
    BOOL r;

    if (!canvas_open(&c, 16, 8)) {
        return;
    }
    pat = CreateBitmap(8, 8, 1, 1, pat_bits);
    line("-- an 8x8 monochrome pattern, rows E0 E0 E0 00 00 00 00 01");
    arm();
    brush = CreatePatternBrush(pat);
    line("CreatePatternBrush(it): non-NULL %s err=%s", yesno(brush != NULL), le());
    if (brush == NULL) {
        DeleteObject(pat);
        canvas_close(&c);
        return;
    }
    arm();
    type = GetObjectType(brush);
    line("GetObjectType(the brush): ret=%lu err=%s", (unsigned long)type, le());
    ZeroMemory(&lb, sizeof lb);
    arm();
    n = GetObjectW(brush, sizeof lb, &lb);
    line("GetObjectW(the brush, sizeof(LOGBRUSH)): ret=%d err=%s lbStyle=%u lbColor=0x%06lX"
         " lbHatch the bitmap: %s", n, le(), lb.lbStyle, (unsigned long)lb.lbColor,
         yesno((DWORD)lb.lbHatch == (DWORD)pat));
    oldb = SelectObject(c.dc, brush);
    SetTextColor(c.dc, RGB(255, 0, 0));
    SetBkColor(c.dc, RGB(0, 0, 255));
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PatBlt(c.dc, 0, 0, 16, 8, PATCOPY);
    line("PatBlt(0, 0, 16, 8, PATCOPY), text red, background blue: ret=%d err=%s", r, le());
    letter_rows(&c);
    arm();
    r = SetBrushOrgEx(c.dc, 3, 2, &pt);
    line("SetBrushOrgEx(3, 2): ret=%d err=%s previous=%ld,%ld", r, le(), (long)pt.x, (long)pt.y);
    pt.x = pt.y = -1;
    arm();
    r = GetBrushOrgEx(c.dc, &pt);
    line("GetBrushOrgEx: ret=%d err=%s origin=%ld,%ld", r, le(), (long)pt.x, (long)pt.y);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PatBlt(c.dc, 0, 0, 16, 8, PATCOPY);
    line("PatBlt(0, 0, 16, 8, PATCOPY): ret=%d err=%s", r, le());
    letter_rows(&c);
    arm();
    r = SetBrushOrgEx(c.dc, 9, -1, &pt);
    line("SetBrushOrgEx(9, -1): ret=%d err=%s previous=%ld,%ld", r, le(), (long)pt.x, (long)pt.y);
    pt.x = pt.y = -1;
    arm();
    r = GetBrushOrgEx(c.dc, &pt);
    line("GetBrushOrgEx: ret=%d err=%s origin=%ld,%ld", r, le(), (long)pt.x, (long)pt.y);
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PatBlt(c.dc, 0, 0, 16, 8, PATCOPY);
    line("PatBlt(0, 0, 16, 8, PATCOPY): ret=%d err=%s", r, le());
    letter_rows(&c);
    SetBrushOrgEx(c.dc, 0, 0, NULL);
    canvas_fill(&c, 0x00FFFFFF);
    PatBlt(c.dc, 0, 0, 16, 8, PATCOPY);
    GdiFlush();
    memcpy(before, c.bits, sizeof before);
    arm();
    r = DeleteObject(pat);
    line("DeleteObject(the bitmap) with the brush alive: ret=%d err=%s", r, le());
    canvas_fill(&c, 0x00FFFFFF);
    arm();
    r = PatBlt(c.dc, 0, 0, 16, 8, PATCOPY);
    GdiFlush();
    line("PatBlt at the origin 0,0 again: ret=%d err=%s the same pixels as before the deletion: %s", r,
         le(), yesno(memcmp(before, c.bits, sizeof before) == 0));
    SelectObject(c.dc, oldb);
    DeleteObject(brush);

    line("-- an 8x8 32-bit pattern (CreateBitmap): quadrants red, green / blue, white");
    for (y = 0; y < 8; y++) {
        for (x = 0; x < 8; x++) {
            quad[y * 8 + x] = y < 4 ? (x < 4 ? 0x00FF0000 : 0x0000FF00) : (x < 4 ? 0x000000FF : 0x00FFFFFF);
        }
    }
    pat = CreateBitmap(8, 8, 1, 32, quad);
    arm();
    brush = CreatePatternBrush(pat);
    line("CreatePatternBrush(it): non-NULL %s err=%s", yesno(brush != NULL), le());
    if (brush != NULL) {
        oldb = SelectObject(c.dc, brush);
        SetBrushOrgEx(c.dc, 2, 0, NULL);
        canvas_fill(&c, 0);
        arm();
        r = PatBlt(c.dc, 0, 0, 16, 8, PATCOPY);
        line("PatBlt(0, 0, 16, 8, PATCOPY) at the origin 2,0: ret=%d err=%s", r, le());
        letter_rows(&c);
        SelectObject(c.dc, oldb);
        DeleteObject(brush);
    }
    DeleteObject(pat);

    arm();
    brush = CreatePatternBrush(NULL);
    line("CreatePatternBrush(NULL): non-NULL %s err=%s", yesno(brush != NULL), le());
    if (brush != NULL) {
        DeleteObject(brush);
    }
    canvas_close(&c);
}

/* --- objtype ------------------------------------------------------- */

static void type_of(const char *what, HGDIOBJ h)
{
    DWORD t;

    arm();
    t = GetObjectType(h);
    line("GetObjectType(%s): ret=%lu err=%s", what, (unsigned long)t, le());
}

static void sec_objtype(void)
{
    LOGBRUSH lb;
    LOGFONTW lf;
    HGDIOBJ h;
    HBITMAP bmp;
    HDC dc, screen;
    bmi_t b;
    void *p;

    h = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
    type_of("CreatePen's", h);
    DeleteObject(h);
    type_of("GetStockObject(BLACK_PEN)", GetStockObject(BLACK_PEN));
    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    h = ExtCreatePen(PS_GEOMETRIC | PS_SOLID, 3, &lb, 0, NULL);
    type_of("ExtCreatePen's (geometric)", h);
    DeleteObject(h);
    h = ExtCreatePen(PS_COSMETIC | PS_SOLID, 1, &lb, 0, NULL);
    type_of("ExtCreatePen's (cosmetic)", h);
    DeleteObject(h);
    h = CreateSolidBrush(RGB(255, 0, 0));
    type_of("CreateSolidBrush's", h);
    DeleteObject(h);
    h = CreateHatchBrush(HS_CROSS, RGB(255, 0, 0));
    type_of("CreateHatchBrush's", h);
    DeleteObject(h);
    bmp = CreateBitmap(8, 8, 1, 1, NULL);
    h = CreatePatternBrush(bmp);
    type_of("CreatePatternBrush's", h);
    DeleteObject(h);
    type_of("GetStockObject(WHITE_BRUSH)", GetStockObject(WHITE_BRUSH));
    type_of("GetStockObject(NULL_BRUSH)", GetStockObject(NULL_BRUSH));
    ZeroMemory(&lf, sizeof lf);
    lf.lfHeight = -12;
    lstrcpyW(lf.lfFaceName, L"Arial");
    h = CreateFontIndirectW(&lf);
    type_of("CreateFontIndirectW's", h);
    DeleteObject(h);
    type_of("GetStockObject(SYSTEM_FONT)", GetStockObject(SYSTEM_FONT));
    type_of("GetStockObject(DEFAULT_PALETTE)", GetStockObject(DEFAULT_PALETTE));
    h = CreateRectRgn(0, 0, 4, 4);
    type_of("CreateRectRgn's", h);
    DeleteObject(h);
    type_of("CreateBitmap's", bmp);
    header(&b, 4, 4, 32);
    p = NULL;
    h = CreateDIBSection(NULL, (BITMAPINFO *)&b, DIB_RGB_COLORS, &p, NULL, 0);
    type_of("CreateDIBSection's", h);
    DeleteObject(h);
    dc = CreateCompatibleDC(NULL);
    type_of("CreateCompatibleDC's", dc);
    type_of("a memory DC's default bitmap", GetCurrentObject(dc, OBJ_BITMAP));
    type_of("a memory DC's default pen", GetCurrentObject(dc, OBJ_PEN));
    DeleteDC(dc);
    type_of("a deleted memory DC", dc);
    screen = GetDC(NULL);
    type_of("GetDC(NULL)'s", screen);
    ReleaseDC(NULL, screen);
    dc = CreateDCA("DISPLAY", NULL, NULL, NULL);
    type_of("CreateDCA(\"DISPLAY\")'s", dc);
    DeleteDC(dc);
    DeleteObject(bmp);
    type_of("a deleted bitmap", bmp);
    type_of("NULL", NULL);
}

/* --- load ---------------------------------------------------------- */

static void obm(const char *name, int id, int bpp)
{
    HBITMAP w, w2, a, img;
    BITMAP bw, ba, bi;
    DWORD type;

    arm();
    w = LoadBitmapW(NULL, MAKEINTRESOURCEW(id));
    line("LoadBitmapW(NULL, %s): non-NULL %s err=%s", name, yesno(w != NULL), le());
    if (w == NULL) {
        return;
    }
    type = GetObjectType(w);
    ZeroMemory(&bw, sizeof bw);
    GetObjectW(w, sizeof bw, &bw);
    line("  GetObjectType=%lu bmWidth above 0: %s bmHeight above 0: %s bmPlanes=%u bmBitsPixel the"
         " screen's: %s", (unsigned long)type, yesno(bw.bmWidth > 0), yesno(bw.bmHeight > 0),
         (unsigned)bw.bmPlanes, yesno(bw.bmBitsPixel == bpp));
    arm();
    w2 = LoadBitmapW(NULL, MAKEINTRESOURCEW(id));
    line("LoadBitmapW(NULL, %s) again: non-NULL %s err=%s the same handle: %s", name, yesno(w2 != NULL),
         le(), yesno(w2 == w));
    arm();
    a = LoadBitmapA(NULL, MAKEINTRESOURCEA(id));
    line("LoadBitmapA(NULL, %s): non-NULL %s err=%s", name, yesno(a != NULL), le());
    if (a != NULL) {
        ZeroMemory(&ba, sizeof ba);
        GetObjectW(a, sizeof ba, &ba);
        line("  its BITMAP the same as the W form's: %s", yesno(memcmp(&ba, &bw, sizeof ba) == 0));
    }
    arm();
    img = (HBITMAP)LoadImageW(NULL, MAKEINTRESOURCEW(id), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
    line("LoadImageW(NULL, %s, IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR): non-NULL %s err=%s", name,
         yesno(img != NULL), le());
    if (img != NULL) {
        ZeroMemory(&bi, sizeof bi);
        GetObjectW(img, sizeof bi, &bi);
        line("  its BITMAP the same as LoadBitmapW's: %s", yesno(memcmp(&bi, &bw, sizeof bi) == 0));
        DeleteObject(img);
    }
    if (a != NULL) {
        DeleteObject(a);
    }
    if (w2 != NULL && w2 != w) {
        DeleteObject(w2);
    }
    DeleteObject(w);
}

/* The stored rows of a DIB section LoadImage made. */
static void stored_rows(const DIBSECTION *ds)
{
    const BYTE *bits = (const BYTE *)ds->dsBm.bmBits;
    LONG rows = ds->dsBm.bmHeight;
    LONG y;

    if (bits == NULL || rows > 16 || ds->dsBm.bmWidthBytes > 32) {
        line("  (rows not printed)");
        return;
    }
    for (y = 0; y < rows; y++) {
        line("  stored row %ld: %s", (long)y, hexbytes(bits + y * ds->dsBm.bmWidthBytes,
             (int)ds->dsBm.bmWidthBytes));
    }
}

static void sec_load(void)
{
    HINSTANCE inst;
    HBITMAP h, h2;
    DIBSECTION ds, ds2;
    DWORD px[128];
    int bpp, n, y;

    bpp = screen_bpp();
    inst = GetModuleHandleW(NULL);

    obm("OBM_CLOSE", OBM_CLOSE, bpp);
    obm("OBM_CHECK", OBM_CHECK, bpp);

    line("-- the program's bitmap (bitmaps.rc): 8x8, 4 bits, the pixel x, y holds VGA color"
         " (x + 2 * y) mod 16");
    arm();
    h = LoadBitmapW(inst, MAKEINTRESOURCEW(OWN_BITMAP));
    line("LoadBitmapW(inst, 300): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        get_bitmap_rel("it", h, bpp);
        line("  its pixels the file's (GetDIBits, 32 bits): %s", yesno(as_own_bitmap(h)));
        DeleteObject(h);
    }
    arm();
    h = LoadBitmapW(inst, L"F2KBMP");
    line("LoadBitmapW(inst, L\"F2KBMP\"): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        line("  its pixels the file's: %s", yesno(as_own_bitmap(h)));
        DeleteObject(h);
    }
    arm();
    h = LoadBitmapA(inst, "F2KBMP");
    line("LoadBitmapA(inst, \"F2KBMP\"): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        line("  its pixels the file's: %s", yesno(as_own_bitmap(h)));
        DeleteObject(h);
    }
    arm();
    h = LoadBitmapW(inst, MAKEINTRESOURCEW(MISSING_BITMAP));
    line("LoadBitmapW(inst, 399), which the program lacks: non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        DeleteObject(h);
    }

    arm();
    h = (HBITMAP)LoadImageW(inst, MAKEINTRESOURCEW(OWN_BITMAP), IMAGE_BITMAP, 0, 0,
                            LR_CREATEDIBSECTION);
    line("LoadImageW(inst, 300, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION): non-NULL %s err=%s",
         yesno(h != NULL), le());
    ZeroMemory(&ds, sizeof ds);
    if (h != NULL) {
        arm();
        n = GetObjectW(h, sizeof ds, &ds);
        line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
        print_ds(&ds, NULL);
        stored_rows(&ds);
        line("  its pixels the file's: %s", yesno(as_own_bitmap(h)));
    }
    arm();
    h2 = (HBITMAP)LoadImageA(inst, "F2KBMP", IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
    line("LoadImageA(inst, \"F2KBMP\", IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION): non-NULL %s err=%s",
         yesno(h2 != NULL), le());
    if (h2 != NULL) {
        ZeroMemory(&ds2, sizeof ds2);
        GetObjectW(h2, sizeof ds2, &ds2);
        ds2.dsBm.bmBits = ds.dsBm.bmBits;
        line("  its DIBSECTION the same as LoadImageW's, but for its bits: %s",
             yesno(memcmp(&ds, &ds2, sizeof ds) == 0));
        DeleteObject(h2);
    }
    if (h != NULL) {
        DeleteObject(h);
    }

    arm();
    h = (HBITMAP)LoadImageW(inst, MAKEINTRESOURCEW(OWN_BITMAP), IMAGE_BITMAP, 16, 8,
                            LR_CREATEDIBSECTION);
    line("LoadImageW(inst, 300, IMAGE_BITMAP, 16, 8, LR_CREATEDIBSECTION): non-NULL %s err=%s",
         yesno(h != NULL), le());
    if (h != NULL) {
        ZeroMemory(&ds, sizeof ds);
        arm();
        n = GetObjectW(h, sizeof ds, &ds);
        line("GetObjectW(it, sizeof(DIBSECTION)): ret=%d err=%s", n, le());
        print_ds(&ds, NULL);
        arm();
        n = read32(h, 16, 8, px);
        line("GetDIBits(it, 32 bits, top-down): ret=%d err=%s", n, le());
        for (y = 0; y < 8; y++) {
            line("  row %d: %s", y, hexdwords(px + y * 16, 16));
        }
        DeleteObject(h);
    }

    arm();
    h = (HBITMAP)LoadImageW(inst, MAKEINTRESOURCEW(OWN_BITMAP), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
    line("LoadImageW(inst, 300, IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR): non-NULL %s err=%s",
         yesno(h != NULL), le());
    if (h != NULL) {
        get_bitmap_rel("it", h, bpp);
        line("  its pixels the file's: %s", yesno(as_own_bitmap(h)));
        DeleteObject(h);
    }

    arm();
    h = (HBITMAP)LoadImageW(inst, MAKEINTRESOURCEW(OWN_BITMAP), IMAGE_BITMAP, 0, 0, LR_MONOCHROME);
    line("LoadImageW(inst, 300, IMAGE_BITMAP, 0, 0, LR_MONOCHROME): non-NULL %s err=%s",
         yesno(h != NULL), le());
    if (h != NULL) {
        get_bitmap("it", h);
        mono_read("it", h, 8, 8);
        DeleteObject(h);
    }

    arm();
    h = (HBITMAP)LoadImageW(inst, MAKEINTRESOURCEW(MISSING_BITMAP), IMAGE_BITMAP, 0, 0,
                            LR_CREATEDIBSECTION);
    line("LoadImageW(inst, 399, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION), which the program lacks:"
         " non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        DeleteObject(h);
    }
}

static const section_t sections[] = {
    { "compat", sec_compat, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "dibsect", sec_dibsect, F2KT_ALWAYS },
    { "blit", sec_blit, F2KT_ALWAYS },
    { "mono", sec_mono, F2KT_ALWAYS },
    { "stretch", sec_stretch, F2KT_ALWAYS },
    { "dibits", sec_dibits, F2KT_ALWAYS },
    { "todevice", sec_todevice, F2KT_ALWAYS },
    { "createdib", sec_createdib, F2KT_ALWAYS },
    { "pattern", sec_pattern, F2KT_ALWAYS },
    { "objtype", sec_objtype, F2KT_ALWAYS },
    { "load", sec_load, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or buffer would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("bitmaps", sections, argc, argv);
}
