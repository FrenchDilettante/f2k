/*
 * icons - user32's icons and cursors as images: GetIconInfo, CreateIcon,
 * CreateCursor, CreateIconIndirect, CreateIconFromResource(Ex),
 * LookupIconIdFromDirectory(Ex), DrawIcon and DrawIconEx, CopyImage and
 * CopyIcon, DestroyIcon and DestroyCursor, PrivateExtractIcons(Ex)A/W,
 * LoadCursorFromFileA/W, GetCursorFrameInfo and SetSystemCursor.
 *
 * The program carries its own icon and cursor (icons.rc: icon group
 * 100, three images, 16x16 4-bit, 32x32 4-bit and 32x32 8-bit; cursor
 * group 200, one 32x32 monochrome image with its hotspot at 5, 7; the
 * cursor's file again as raw data, F2KCURF). icons.rc gives each
 * image's formula; the img_* functions below are the same formulas.
 *
 * No handle value is printed: whether one came back, whether two are
 * the same, and what GetIconInfo says of it (fIcon, the hotspot, the
 * mask's and the colour bitmap's sizes and depths; a colour bitmap's
 * depth prints as "screen" when it is the screen's, which is the
 * machine's). Drawings go into a 32-bit top-down DIB section filled
 * with 0x123456 first, read back after GdiFlush: as the number of
 * pixels that differ from the image the drawing should show (a
 * transparent pixel shows the background), and as grids for the 16x16
 * ones, a pixel as a character: '.' the background, a hex digit the
 * VGA colour of that index (0 black, F white), '?' anything else.
 *
 * Every export of this fixture but CopyIcon, CreateIconIndirect,
 * DestroyIcon, LoadIconA/W, LoadCursorA and LoadImageA is reached
 * through GetProcAddress: F2K's user32 lacks them, and MSVC 6's
 * user32.lib lacks some (PrivateExtractIcons*, GetCursorFrameInfo); a
 * section needing one F2K lacks prints "<name>: absent" and stops.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   stock     LoadIconA of six stock icons and LoadCursorA of four
 *             stock cursors, GetIconInfo of each; LoadIconW of
 *             IDI_APPLICATION, the same handle as A's or not;
 *             GetIconInfo of NULL
 *   create    CreateIcon of a 16x16 monochrome icon and of a 32-bit
 *             one, CreateCursor (hotspot 3, 4), CreateIconIndirect of
 *             an icon, a cursor and a monochrome icon, and with no
 *             mask: GetIconInfo of each and its drawing against the
 *             bits given; DestroyIcon and DestroyCursor of each, twice
 *             for some, DestroyCursor of an icon, DestroyIcon of a
 *             stock icon and GetIconInfo of it after
 *   lookup    the icon group's and the cursor group's entries as
 *             rc wrote them; LookupIconIdFromDirectory and
 *             LookupIconIdFromDirectoryEx over them at 16, 24, 32, 48
 *             and 0 pixels, LR_DEFAULTCOLOR and LR_MONOCHROME, and
 *             with the wrong fIcon: the entry each id names
 *   fromres   CreateIconFromResource of each RT_ICON image and of the
 *             RT_CURSOR image, CreateIconFromResourceEx at 16x16 and
 *             0x0, versions 0x20000 and 0x10000, and of 64 zero bytes:
 *             GetIconInfo of each and its drawing
 *   draw      DrawIconEx of the 16x16 icon with DI_NORMAL, DI_MASK,
 *             DI_IMAGE and no flags (grids), with a flicker-free brush,
 *             stretched to 32x32; of the 32x32 icon with
 *             DI_DEFAULTSIZE; DrawIcon of both icons and of the
 *             cursor; DrawIconEx with no DC and with no icon
 *   copy      CopyImage of the 32x32 icon: as it is, to 16x16 (with
 *             and without LR_COPYFROMRESOURCE), LR_COPYRETURNORG at
 *             its own size and another, LR_COPYDELETEORG (GetIconInfo
 *             of the original after); of the cursor; of NULL and with
 *             an unknown type; of a 32-bit 8x8 bitmap as it is, to
 *             16x16, LR_MONOCHROME and LR_CREATEDIBSECTION; CopyIcon
 *   extract   PrivateExtractIconsA/W over the program's own file: the
 *             count, the icon at 32x32 and 16x16, an index past the
 *             last, a missing file; PrivateExtractIconExA/W: the count
 *             and the large and small icons of index 0
 *   cursors   LoadCursorFromFileA/W of the program's cursor written
 *             beside it as f2kicon.cur (deleted at the end) and of a
 *             missing file; GetCursorFrameInfo of that cursor and of
 *             IDC_ARROW; SetSystemCursor of NULL (a refusal: no system
 *             cursor is changed); DestroyCursor of the file's cursor,
 *             twice
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat icons):
 *   rc icons.rc
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% icons.c icons.res user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* Older SDK headers may lack these. */
#ifndef LR_COPYFROMRESOURCE
#define LR_COPYFROMRESOURCE 0x4000
#endif
#ifndef LR_CREATEDIBSECTION
#define LR_CREATEDIBSECTION 0x2000
#endif
#ifndef DI_DEFAULTSIZE
#define DI_DEFAULTSIZE 0x0008
#endif
#ifndef OCR_NORMAL_
#define OCR_NORMAL_ 32512
#endif

#define OWN_ICON 100
#define OWN_CURSOR 200
#define BG 0x123456UL

/* --- the exports, resolved ----------------------------------------- */

typedef HANDLE (WINAPI *copy_image_t)(HANDLE, UINT, int, int, UINT);
typedef HICON (WINAPI *create_icon_t)(HINSTANCE, int, int, BYTE, BYTE, const BYTE *, const BYTE *);
typedef HCURSOR (WINAPI *create_cursor_t)(HINSTANCE, int, int, int, int, const void *, const void *);
typedef HICON (WINAPI *from_res_t)(PBYTE, DWORD, BOOL, DWORD);
typedef HICON (WINAPI *from_res_ex_t)(PBYTE, DWORD, BOOL, DWORD, int, int, UINT);
typedef BOOL (WINAPI *destroy_cursor_t)(HCURSOR);
typedef BOOL (WINAPI *get_icon_info_t)(HICON, ICONINFO *);
typedef BOOL (WINAPI *draw_icon_t)(HDC, int, int, HICON);
typedef BOOL (WINAPI *draw_icon_ex_t)(HDC, int, int, HICON, int, int, UINT, HBRUSH, UINT);
typedef int (WINAPI *lookup_t)(PBYTE, BOOL);
typedef int (WINAPI *lookup_ex_t)(PBYTE, BOOL, int, int, UINT);
typedef UINT (WINAPI *extract_a_t)(LPCSTR, int, int, int, HICON *, UINT *, UINT, UINT);
typedef UINT (WINAPI *extract_w_t)(LPCWSTR, int, int, int, HICON *, UINT *, UINT, UINT);
typedef UINT (WINAPI *extract_ex_a_t)(LPCSTR, int, HICON *, HICON *, UINT);
typedef UINT (WINAPI *extract_ex_w_t)(LPCWSTR, int, HICON *, HICON *, UINT);
typedef HCURSOR (WINAPI *from_file_a_t)(LPCSTR);
typedef HCURSOR (WINAPI *from_file_w_t)(LPCWSTR);
typedef BOOL (WINAPI *set_system_cursor_t)(HCURSOR, DWORD);
typedef HCURSOR (WINAPI *frame_info_t)(HCURSOR, DWORD, DWORD, DWORD *, DWORD *);

static copy_image_t p_CopyImage;
static create_icon_t p_CreateIcon;
static create_cursor_t p_CreateCursor;
static from_res_t p_CreateIconFromResource;
static from_res_ex_t p_CreateIconFromResourceEx;
static destroy_cursor_t p_DestroyCursor;
static get_icon_info_t p_GetIconInfo;
static draw_icon_t p_DrawIcon;
static draw_icon_ex_t p_DrawIconEx;
static lookup_t p_LookupIconIdFromDirectory;
static lookup_ex_t p_LookupIconIdFromDirectoryEx;
static extract_a_t p_PrivateExtractIconsA;
static extract_w_t p_PrivateExtractIconsW;
static extract_ex_a_t p_PrivateExtractIconExA;
static extract_ex_w_t p_PrivateExtractIconExW;
static from_file_a_t p_LoadCursorFromFileA;
static from_file_w_t p_LoadCursorFromFileW;
static set_system_cursor_t p_SetSystemCursor;
static frame_info_t p_GetCursorFrameInfo;

static HINSTANCE inst;
static int screen_bpp;

static FARPROC resolve(const char *name)
{
    return GetProcAddress(GetModuleHandleA("user32.dll"), name);
}

static void resolve_all(void)
{
    HDC dc;

    p_CopyImage = (copy_image_t)resolve("CopyImage");
    p_CreateIcon = (create_icon_t)resolve("CreateIcon");
    p_CreateCursor = (create_cursor_t)resolve("CreateCursor");
    p_CreateIconFromResource = (from_res_t)resolve("CreateIconFromResource");
    p_CreateIconFromResourceEx = (from_res_ex_t)resolve("CreateIconFromResourceEx");
    p_DestroyCursor = (destroy_cursor_t)resolve("DestroyCursor");
    p_GetIconInfo = (get_icon_info_t)resolve("GetIconInfo");
    p_DrawIcon = (draw_icon_t)resolve("DrawIcon");
    p_DrawIconEx = (draw_icon_ex_t)resolve("DrawIconEx");
    p_LookupIconIdFromDirectory = (lookup_t)resolve("LookupIconIdFromDirectory");
    p_LookupIconIdFromDirectoryEx = (lookup_ex_t)resolve("LookupIconIdFromDirectoryEx");
    p_PrivateExtractIconsA = (extract_a_t)resolve("PrivateExtractIconsA");
    p_PrivateExtractIconsW = (extract_w_t)resolve("PrivateExtractIconsW");
    p_PrivateExtractIconExA = (extract_ex_a_t)resolve("PrivateExtractIconExA");
    p_PrivateExtractIconExW = (extract_ex_w_t)resolve("PrivateExtractIconExW");
    p_LoadCursorFromFileA = (from_file_a_t)resolve("LoadCursorFromFileA");
    p_LoadCursorFromFileW = (from_file_w_t)resolve("LoadCursorFromFileW");
    p_SetSystemCursor = (set_system_cursor_t)resolve("SetSystemCursor");
    p_GetCursorFrameInfo = (frame_info_t)resolve("GetCursorFrameInfo");
    inst = GetModuleHandleA(NULL);
    dc = GetDC(NULL);
    screen_bpp = GetDeviceCaps(dc, BITSPIXEL) * GetDeviceCaps(dc, PLANES);
    ReleaseDC(NULL, dc);
}

/* Whether an export is there; prints "<name>: absent" when not. */
static int have(FARPROC p, const char *name)
{
    if (p == NULL) {
        line("%s: absent", name);
        return 0;
    }
    return 1;
}

#define HAVE(f) have((FARPROC)p_##f, #f)

/* --- the images (icons.rc's formulas) ------------------------------ */

static const DWORD vga[16] = {
    0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0,
    0x808080, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF
};

/* Each gives the VGA index of the pixel x, y, or -1 where transparent. */
typedef int (*image_t)(int x, int y);

static int img16(int x, int y)
{
    return x + y < 4 ? -1 : ((x / 2) + (y / 2)) % 15 + 1;
}

static int img32a(int x, int y)
{
    return x + y < 8 ? -1 : ((x / 4) + (y / 4)) % 15 + 1;
}

static int img32b(int x, int y)
{
    return x + y < 8 ? -1 : 15 - ((x / 4) + (y / 4)) % 15;
}

static int imgcur(int x, int y)
{
    if (x >= 4 && x < 28 && y >= 4 && y < 28) {
        return x < 16 ? 15 : 0;
    }
    return -1;
}

/* The monochrome icon and cursor the create section makes: transparent
 * where x < 4, white where y < 8, black elsewhere. */
static int imgmono(int x, int y)
{
    if (x < 4) {
        return -1;
    }
    return y < 8 ? 15 : 0;
}

/* --- the canvas ---------------------------------------------------- */

typedef struct {
    HDC dc;
    HBITMAP bmp;
    HGDIOBJ old;
    DWORD *bits;
    int w;
    int h;
} canvas_t;

static int canvas_open(canvas_t *c, int w, int h)
{
    BITMAPINFO bi;
    void *bits;

    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    c->dc = CreateCompatibleDC(NULL);
    bits = NULL;
    c->bmp = CreateDIBSection(c->dc, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    if (c->dc == NULL || c->bmp == NULL || bits == NULL) {
        line("(the canvas could not be made)");
        return 0;
    }
    c->old = SelectObject(c->dc, c->bmp);
    c->bits = (DWORD *)bits;
    c->w = w;
    c->h = h;
    return 1;
}

static void canvas_fill(canvas_t *c, DWORD rgb)
{
    int i;

    GdiFlush();
    for (i = 0; i < c->w * c->h; i++) {
        c->bits[i] = rgb;
    }
}

static void canvas_close(canvas_t *c)
{
    SelectObject(c->dc, c->old);
    DeleteObject(c->bmp);
    DeleteDC(c->dc);
}

static DWORD pixel(canvas_t *c, int x, int y)
{
    return c->bits[y * c->w + x] & 0xFFFFFF;
}

static char pixel_char(DWORD p)
{
    int i;

    if (p == BG) {
        return '.';
    }
    for (i = 0; i < 16; i++) {
        if (p == vga[i]) {
            return "0123456789ABCDEF"[i];
        }
    }
    return '?';
}

/* The canvas's top-left w x h pixels as rows of characters. */
static void canvas_grid(canvas_t *c, int w, int h)
{
    char row[80];
    int x, y;

    GdiFlush();
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            row[x] = pixel_char(pixel(c, x, y));
        }
        row[w] = '\0';
        line("  %s", row);
    }
}

/* How many of the canvas's top-left (image size * scale) pixels differ
 * from the image drawn at that scale over `bg`. */
static int mismatches_over(canvas_t *c, image_t img, int size, int scale, DWORD bg)
{
    int x, y, n, v;
    DWORD want;

    GdiFlush();
    n = 0;
    for (y = 0; y < size * scale; y++) {
        for (x = 0; x < size * scale; x++) {
            v = img(x / scale, y / scale);
            want = v < 0 ? bg : vga[v];
            if (pixel(c, x, y) != want) {
                n++;
            }
        }
    }
    return n;
}

static int mismatches(canvas_t *c, image_t img, int size, int scale)
{
    return mismatches_over(c, img, size, scale, BG);
}

/* Whether every pixel of the canvas is still the background. */
static int untouched(canvas_t *c)
{
    int i;

    GdiFlush();
    for (i = 0; i < c->w * c->h; i++) {
        if ((c->bits[i] & 0xFFFFFF) != BG) {
            return 0;
        }
    }
    return 1;
}

/* --- icon helpers -------------------------------------------------- */

static const char *depth(int bpp)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (bpp == screen_bpp && bpp != 1) {
        return "screen";
    }
    sprintf(b, "%d", bpp);
    return b;
}

/* An icon's or cursor's size from GetIconInfo: 0 when it fails. */
static int icon_size(HICON h, int *w, int *ht)
{
    ICONINFO ii;
    BITMAP bm;

    *w = 0;
    *ht = 0;
    if (h == NULL || p_GetIconInfo == NULL || !p_GetIconInfo(h, &ii)) {
        return 0;
    }
    if (GetObjectA(ii.hbmMask, sizeof bm, &bm) == sizeof bm) {
        *w = bm.bmWidth;
        *ht = ii.hbmColor != NULL ? bm.bmHeight : bm.bmHeight / 2;
    }
    DeleteObject(ii.hbmMask);
    if (ii.hbmColor != NULL) {
        DeleteObject(ii.hbmColor);
    }
    return 1;
}

/* GetIconInfo of h, printed under `what`. */
static void describe(const char *what, HICON h)
{
    ICONINFO ii;
    BITMAP bm;
    char mask[48];
    char colour[48];
    const char *err;
    BOOL ok;

    if (h == NULL) {
        line("  %s: no handle", what);
        return;
    }
    ZeroMemory(&ii, sizeof ii);
    arm();
    ok = p_GetIconInfo(h, &ii);
    err = le();
    if (!ok) {
        line("  %s: GetIconInfo ret=0 err=%s", what, err);
        return;
    }
    strcpy(mask, "none");
    if (ii.hbmMask != NULL && GetObjectA(ii.hbmMask, sizeof bm, &bm) == sizeof bm) {
        sprintf(mask, "%ldx%ld %s bit", bm.bmWidth, bm.bmHeight, depth(bm.bmBitsPixel * bm.bmPlanes));
    }
    strcpy(colour, "none");
    if (ii.hbmColor != NULL && GetObjectA(ii.hbmColor, sizeof bm, &bm) == sizeof bm) {
        sprintf(colour, "%ldx%ld %s bit", bm.bmWidth, bm.bmHeight, depth(bm.bmBitsPixel * bm.bmPlanes));
    }
    line("  %s: GetIconInfo ret=1 err=%s fIcon=%d hotspot=%lu,%lu mask=%s colour=%s", what, err,
         (int)ii.fIcon, ii.xHotspot, ii.yHotspot, mask, colour);
    if (ii.hbmMask != NULL) {
        DeleteObject(ii.hbmMask);
    }
    if (ii.hbmColor != NULL) {
        DeleteObject(ii.hbmColor);
    }
}

/* Draws h at its own size on a fresh canvas (DrawIconEx DI_NORMAL) and
 * prints how many pixels differ from `img`. */
static void check_drawn(const char *what, HICON h, image_t img, int size)
{
    canvas_t c;
    BOOL ok;

    if (h == NULL || p_DrawIconEx == NULL || !canvas_open(&c, 32, 32)) {
        return;
    }
    canvas_fill(&c, BG);
    ok = p_DrawIconEx(c.dc, 0, 0, h, 0, 0, 0, NULL, DI_NORMAL);
    line("  %s drawn at its size: ret=%d, pixels not the image's: %d", what, ok,
         mismatches(&c, img, size, 1));
    canvas_close(&c);
}

static HICON load_icon(int size)
{
    return (HICON)LoadImageA(inst, MAKEINTRESOURCEA(OWN_ICON), IMAGE_ICON, size, size, 0);
}

static HCURSOR load_cursor(void)
{
    return (HCURSOR)LoadImageA(inst, MAKEINTRESOURCEA(OWN_CURSOR), IMAGE_CURSOR, 0, 0, 0);
}

/* A resource's bits and size, or NULL. */
static BYTE *resource(LPCSTR name, LPCSTR type, DWORD *size)
{
    HRSRC r;
    HGLOBAL g;

    *size = 0;
    r = FindResourceA(inst, name, type);
    if (r == NULL) {
        return NULL;
    }
    g = LoadResource(inst, r);
    if (g == NULL) {
        return NULL;
    }
    *size = SizeofResource(inst, r);
    return (BYTE *)LockResource(g);
}

static WORD word_at(const BYTE *p)
{
    return (WORD)(p[0] | (p[1] << 8));
}

static DWORD dword_at(const BYTE *p)
{
    return (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

/* --- stock --------------------------------------------------------- */

static void sec_stock(void)
{
    static const struct { LPCSTR id; const char *name; } icons[] = {
        { IDI_APPLICATION, "IDI_APPLICATION" }, { IDI_HAND, "IDI_HAND" },
        { IDI_QUESTION, "IDI_QUESTION" }, { IDI_EXCLAMATION, "IDI_EXCLAMATION" },
        { IDI_ASTERISK, "IDI_ASTERISK" }, { IDI_WINLOGO, "IDI_WINLOGO" },
    };
    static const struct { LPCSTR id; const char *name; } cursors[] = {
        { IDC_ARROW, "IDC_ARROW" }, { IDC_IBEAM, "IDC_IBEAM" },
        { IDC_WAIT, "IDC_WAIT" }, { IDC_CROSS, "IDC_CROSS" },
    };
    ICONINFO ii;
    HICON h, hw;
    int i;
    BOOL ok;

    if (!HAVE(GetIconInfo)) {
        return;
    }
    for (i = 0; i < (int)(sizeof icons / sizeof icons[0]); i++) {
        arm();
        h = LoadIconA(NULL, icons[i].id);
        line("LoadIconA(NULL, %s): non-NULL %s err=%s", icons[i].name, yesno(h != NULL), le());
        describe(icons[i].name, h);
    }
    for (i = 0; i < (int)(sizeof cursors / sizeof cursors[0]); i++) {
        arm();
        h = LoadCursorA(NULL, cursors[i].id);
        line("LoadCursorA(NULL, %s): non-NULL %s err=%s", cursors[i].name, yesno(h != NULL), le());
        describe(cursors[i].name, h);
    }
    h = LoadIconA(NULL, IDI_APPLICATION);
    arm();
    hw = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    line("LoadIconW(NULL, IDI_APPLICATION): non-NULL %s err=%s, the same as LoadIconA's %s",
         yesno(hw != NULL), le(), yesno(hw == h));
    arm();
    ok = p_GetIconInfo(NULL, &ii);
    line("GetIconInfo(NULL): ret=%d err=%s", ok, le());
}

/* --- create -------------------------------------------------------- */

static BYTE mono_and[16 * 2];
static BYTE mono_xor[16 * 2];
static BYTE colour_and[16 * 2];
static DWORD colour_xor[16 * 16];

static void make_bits(void)
{
    int x, y, v;

    ZeroMemory(mono_and, sizeof mono_and);
    ZeroMemory(mono_xor, sizeof mono_xor);
    ZeroMemory(colour_and, sizeof colour_and);
    for (y = 0; y < 16; y++) {
        for (x = 0; x < 16; x++) {
            v = imgmono(x, y);
            if (v < 0) {
                mono_and[y * 2 + x / 8] |= (BYTE)(0x80 >> (x % 8));
            } else if (v == 15) {
                mono_xor[y * 2 + x / 8] |= (BYTE)(0x80 >> (x % 8));
            }
            v = img16(x, y);
            if (v < 0) {
                colour_and[y * 2 + x / 8] |= (BYTE)(0x80 >> (x % 8));
                colour_xor[y * 16 + x] = 0;
            } else {
                colour_xor[y * 16 + x] = vga[v];
            }
        }
    }
}

/* CreateIconIndirect of the given bitmaps, printed and described. */
static HICON indirect(const char *what, BOOL icon, DWORD hx, DWORD hy, HBITMAP mask, HBITMAP colour)
{
    ICONINFO ii;
    HICON h;

    ii.fIcon = icon;
    ii.xHotspot = hx;
    ii.yHotspot = hy;
    ii.hbmMask = mask;
    ii.hbmColor = colour;
    arm();
    h = CreateIconIndirect(&ii);
    line("CreateIconIndirect(%s): non-NULL %s err=%s", what, yesno(h != NULL), le());
    describe("it", h);
    return h;
}

static void sec_create(void)
{
    HICON mono, colour, ind, indcur, indmono, none, stock;
    HCURSOR cur;
    HBITMAP mask, cbmp, mmask;
    BOOL ok;
    ICONINFO ii;

    if (!HAVE(GetIconInfo) || !HAVE(CreateIcon) || !HAVE(CreateCursor) || !HAVE(DrawIconEx)
        || !HAVE(DestroyCursor)) {
        return;
    }
    make_bits();

    arm();
    mono = p_CreateIcon(inst, 16, 16, 1, 1, mono_and, mono_xor);
    line("CreateIcon(16x16, 1 plane, 1 bit): non-NULL %s err=%s", yesno(mono != NULL), le());
    describe("it", mono);
    check_drawn("it", mono, imgmono, 16);

    arm();
    colour = p_CreateIcon(inst, 16, 16, 1, 32, colour_and, (const BYTE *)colour_xor);
    line("CreateIcon(16x16, 1 plane, 32 bits): non-NULL %s err=%s", yesno(colour != NULL), le());
    describe("it", colour);
    check_drawn("it", colour, img16, 16);

    arm();
    cur = p_CreateCursor(inst, 3, 4, 16, 16, mono_and, mono_xor);
    line("CreateCursor(hotspot 3,4, 16x16): non-NULL %s err=%s", yesno(cur != NULL), le());
    describe("it", cur);
    check_drawn("it", cur, imgmono, 16);

    mask = CreateBitmap(16, 16, 1, 1, colour_and);
    cbmp = CreateBitmap(16, 16, 1, 32, colour_xor);
    ind = indirect("an icon, a 16x16 mask, a 32-bit colour bitmap", TRUE, 0, 0, mask, cbmp);
    check_drawn("it", ind, img16, 16);
    indcur = indirect("a cursor, hotspot 2,9, the same bitmaps", FALSE, 2, 9, mask, cbmp);
    check_drawn("it", indcur, img16, 16);
    {
        BYTE both[16 * 2 * 2];

        memcpy(both, mono_and, sizeof mono_and);
        memcpy(both + sizeof mono_and, mono_xor, sizeof mono_xor);
        mmask = CreateBitmap(16, 32, 1, 1, both);
    }
    indmono = indirect("an icon, a 16x32 mask and no colour bitmap", TRUE, 0, 0, mmask, NULL);
    check_drawn("it", indmono, imgmono, 16);
    none = indirect("an icon with no mask", TRUE, 0, 0, NULL, cbmp);
    line("the bitmaps given still there after: mask %s colour %s",
         yesno(GetObjectA(mask, 0, NULL) != 0), yesno(GetObjectA(cbmp, 0, NULL) != 0));
    DeleteObject(mask);
    DeleteObject(cbmp);
    DeleteObject(mmask);

    arm();
    ok = DestroyIcon(colour);
    line("DestroyIcon(the 32-bit icon): ret=%d err=%s", ok, le());
    arm();
    ok = DestroyIcon(colour);
    line("DestroyIcon(it, again): ret=%d err=%s", ok, le());
    arm();
    ok = p_GetIconInfo(colour, &ii);
    line("GetIconInfo(it) after: ret=%d err=%s", ok, le());
    arm();
    ok = p_DestroyCursor(cur);
    line("DestroyCursor(the cursor): ret=%d err=%s", ok, le());
    arm();
    ok = p_DestroyCursor(cur);
    line("DestroyCursor(it, again): ret=%d err=%s", ok, le());
    arm();
    ok = p_DestroyCursor(mono);
    line("DestroyCursor(the monochrome icon): ret=%d err=%s", ok, le());
    arm();
    ok = DestroyIcon(indcur);
    line("DestroyIcon(the indirect cursor): ret=%d err=%s", ok, le());
    if (ind != NULL) {
        DestroyIcon(ind);
    }
    if (indmono != NULL) {
        DestroyIcon(indmono);
    }
    if (none != NULL) {
        DestroyIcon(none);
    }
    stock = LoadIconA(NULL, IDI_APPLICATION);
    arm();
    ok = DestroyIcon(stock);
    line("DestroyIcon(IDI_APPLICATION, shared): ret=%d err=%s", ok, le());
    arm();
    ok = p_GetIconInfo(stock, &ii);
    line("GetIconInfo(it) after: ret=%d err=%s", ok, le());
    if (ok) {
        DeleteObject(ii.hbmMask);
        if (ii.hbmColor != NULL) {
            DeleteObject(ii.hbmColor);
        }
    }
    line("LoadIconA(NULL, IDI_APPLICATION) after: the same handle %s",
         yesno(LoadIconA(NULL, IDI_APPLICATION) == stock));
}

/* --- lookup -------------------------------------------------------- */

static BYTE *group_icon;
static DWORD group_icon_size;
static BYTE *group_cursor;
static DWORD group_cursor_size;

static void load_groups(void)
{
    group_icon = resource(MAKEINTRESOURCEA(OWN_ICON), RT_GROUP_ICON, &group_icon_size);
    group_cursor = resource(MAKEINTRESOURCEA(OWN_CURSOR), RT_GROUP_CURSOR, &group_cursor_size);
}

static int group_count(const BYTE *g)
{
    return g == NULL ? 0 : word_at(g + 4);
}

/* Entry i's RT_ICON or RT_CURSOR id. */
static int entry_id(const BYTE *g, int i)
{
    return word_at(g + 6 + 14 * i + 12);
}

/* Which entry of the icon group an id names, as text. */
static const char *icon_entry(int id)
{
    static char bufs[4][48];
    static int next;
    char *b = bufs[next++ & 3];
    const BYTE *e;
    int i;

    if (id == 0) {
        return "0";
    }
    for (i = 0; i < group_count(group_icon); i++) {
        e = group_icon + 6 + 14 * i;
        if (word_at(e + 12) == id) {
            sprintf(b, "entry %d (%dx%d, %d bits)", i, e[0], e[1], word_at(e + 6));
            return b;
        }
    }
    for (i = 0; i < group_count(group_cursor); i++) {
        if (entry_id(group_cursor, i) == id) {
            sprintf(b, "the cursor group's entry %d", i);
            return b;
        }
    }
    return "an id in neither group";
}

/* An id PrivateExtractIcons reports: the group's own, or an entry's. */
static const char *icon_entry_or_group(UINT id)
{
    if (id == OWN_ICON) {
        return "the group's own (100)";
    }
    if (id == 0xEEEE) {
        return "untouched";
    }
    return icon_entry((int)id);
}

static void sec_lookup(void)
{
    static const struct { int cx; UINT flags; const char *what; } asks[] = {
        { 16, LR_DEFAULTCOLOR, "16x16, LR_DEFAULTCOLOR" },
        { 24, LR_DEFAULTCOLOR, "24x24, LR_DEFAULTCOLOR" },
        { 32, LR_DEFAULTCOLOR, "32x32, LR_DEFAULTCOLOR" },
        { 48, LR_DEFAULTCOLOR, "48x48, LR_DEFAULTCOLOR" },
        { 0, LR_DEFAULTCOLOR, "0x0, LR_DEFAULTCOLOR" },
        { 16, LR_MONOCHROME, "16x16, LR_MONOCHROME" },
        { 32, LR_MONOCHROME, "32x32, LR_MONOCHROME" },
    };
    const BYTE *e;
    int i, id;

    if (!HAVE(LookupIconIdFromDirectory) || !HAVE(LookupIconIdFromDirectoryEx)) {
        return;
    }
    load_groups();
    line("RT_GROUP_ICON %d: found %s, %lu bytes, type %d, %d entries", OWN_ICON, yesno(group_icon != NULL),
         group_icon_size, group_icon != NULL ? word_at(group_icon + 2) : -1, group_count(group_icon));
    for (i = 0; i < group_count(group_icon); i++) {
        e = group_icon + 6 + 14 * i;
        line("  entry %d: %dx%d colours %d planes %d bits %d bytes %lu, an RT_ICON of the program %s", i,
             e[0], e[1], e[2], word_at(e + 4), word_at(e + 6), dword_at(e + 8),
             yesno(FindResourceA(inst, MAKEINTRESOURCEA(word_at(e + 12)), RT_ICON) != NULL));
    }
    line("RT_GROUP_CURSOR %d: found %s, %lu bytes, type %d, %d entries", OWN_CURSOR,
         yesno(group_cursor != NULL), group_cursor_size,
         group_cursor != NULL ? word_at(group_cursor + 2) : -1, group_count(group_cursor));
    for (i = 0; i < group_count(group_cursor); i++) {
        e = group_cursor + 6 + 14 * i;
        line("  entry %d: width %d height %d planes %d bits %d bytes %lu, an RT_CURSOR of the program %s", i,
             word_at(e), word_at(e + 2), word_at(e + 4), word_at(e + 6), dword_at(e + 8),
             yesno(FindResourceA(inst, MAKEINTRESOURCEA(word_at(e + 12)), RT_CURSOR) != NULL));
    }
    if (group_icon == NULL || group_cursor == NULL) {
        return;
    }

    arm();
    id = p_LookupIconIdFromDirectory(group_icon, TRUE);
    line("LookupIconIdFromDirectory(the icon group, TRUE): %s err=%s", icon_entry(id), le());
    arm();
    id = p_LookupIconIdFromDirectory(group_cursor, FALSE);
    line("LookupIconIdFromDirectory(the cursor group, FALSE): %s err=%s", icon_entry(id), le());
    arm();
    id = p_LookupIconIdFromDirectory(group_icon, FALSE);
    line("LookupIconIdFromDirectory(the icon group, FALSE): %s err=%s", icon_entry(id), le());
    arm();
    id = p_LookupIconIdFromDirectory(group_cursor, TRUE);
    line("LookupIconIdFromDirectory(the cursor group, TRUE): %s err=%s", icon_entry(id), le());
    for (i = 0; i < (int)(sizeof asks / sizeof asks[0]); i++) {
        arm();
        id = p_LookupIconIdFromDirectoryEx(group_icon, TRUE, asks[i].cx, asks[i].cx, asks[i].flags);
        line("LookupIconIdFromDirectoryEx(the icon group, TRUE, %s): %s err=%s", asks[i].what,
             icon_entry(id), le());
    }
    arm();
    id = p_LookupIconIdFromDirectoryEx(group_icon, TRUE, 32, 16, LR_DEFAULTCOLOR);
    line("LookupIconIdFromDirectoryEx(the icon group, TRUE, 32x16, LR_DEFAULTCOLOR): %s err=%s",
         icon_entry(id), le());
    arm();
    id = p_LookupIconIdFromDirectoryEx(group_cursor, FALSE, 16, 16, LR_DEFAULTCOLOR);
    line("LookupIconIdFromDirectoryEx(the cursor group, FALSE, 16x16, LR_DEFAULTCOLOR): %s err=%s",
         icon_entry(id), le());
}

/* --- fromres ------------------------------------------------------- */

static void sec_fromres(void)
{
    static const image_t images[3] = { img16, img32a, img32b };
    static const int sizes[3] = { 16, 32, 32 };
    static BYTE zeros[64];
    BYTE *bits;
    DWORD size;
    HICON h;
    int i, n;
    char what[64];

    if (!HAVE(GetIconInfo) || !HAVE(CreateIconFromResource) || !HAVE(CreateIconFromResourceEx)
        || !HAVE(DrawIconEx)) {
        return;
    }
    load_groups();
    n = group_count(group_icon);
    for (i = 0; i < n && i < 3; i++) {
        bits = resource(MAKEINTRESOURCEA(entry_id(group_icon, i)), RT_ICON, &size);
        line("the icon group's entry %d: RT_ICON found %s, %lu bytes, a 40-byte header first %s", i,
             yesno(bits != NULL), size, yesno(bits != NULL && dword_at(bits) == 40));
        if (bits == NULL) {
            continue;
        }
        arm();
        h = p_CreateIconFromResource(bits, size, TRUE, 0x00030000);
        line("CreateIconFromResource(it, TRUE, 0x30000): non-NULL %s err=%s", yesno(h != NULL), le());
        describe("it", h);
        check_drawn("it", h, images[i], sizes[i]);
        if (h != NULL) {
            DestroyIcon(h);
        }
        if (i != 2) {
            continue;
        }
        arm();
        h = p_CreateIconFromResourceEx(bits, size, TRUE, 0x00030000, 16, 16, LR_DEFAULTCOLOR);
        line("CreateIconFromResourceEx(it, TRUE, 0x30000, 16x16): non-NULL %s err=%s", yesno(h != NULL),
             le());
        describe("it", h);
        if (h != NULL) {
            DestroyIcon(h);
        }
        arm();
        h = p_CreateIconFromResourceEx(bits, size, TRUE, 0x00030000, 0, 0, 0);
        line("CreateIconFromResourceEx(it, TRUE, 0x30000, 0x0, 0): non-NULL %s err=%s", yesno(h != NULL),
             le());
        describe("it", h);
        if (h != NULL) {
            DestroyIcon(h);
        }
        arm();
        h = p_CreateIconFromResource(bits, size, TRUE, 0x00020000);
        line("CreateIconFromResource(it, TRUE, 0x20000): non-NULL %s err=%s", yesno(h != NULL), le());
        describe("it", h);
        if (h != NULL) {
            DestroyIcon(h);
        }
        arm();
        h = p_CreateIconFromResource(bits, size, TRUE, 0x00010000);
        line("CreateIconFromResource(it, TRUE, 0x10000): non-NULL %s err=%s", yesno(h != NULL), le());
        if (h != NULL) {
            DestroyIcon(h);
        }
    }

    if (group_count(group_cursor) > 0) {
        bits = resource(MAKEINTRESOURCEA(entry_id(group_cursor, 0)), RT_CURSOR, &size);
        line("the cursor group's entry 0: RT_CURSOR found %s, %lu bytes", yesno(bits != NULL), size);
        if (bits != NULL) {
            line("  its first words: %u,%u, then a 40-byte header %s", word_at(bits), word_at(bits + 2),
                 yesno(dword_at(bits + 4) == 40));
            arm();
            h = p_CreateIconFromResource(bits, size, FALSE, 0x00030000);
            line("CreateIconFromResource(it, FALSE, 0x30000): non-NULL %s err=%s", yesno(h != NULL), le());
            describe("it", h);
            check_drawn("it", h, imgcur, 32);
            if (h != NULL) {
                DestroyIcon(h);
            }
        }
    }

    sprintf(what, "64 zero bytes");
    arm();
    h = p_CreateIconFromResource(zeros, sizeof zeros, TRUE, 0x00030000);
    line("CreateIconFromResource(%s, TRUE, 0x30000): non-NULL %s err=%s", what, yesno(h != NULL), le());
    if (h != NULL) {
        DestroyIcon(h);
    }
}

/* --- draw ---------------------------------------------------------- */

/* DrawIconEx of the 16x16 icon with `flags`, printed, with the grid. */
static void draw_grid(canvas_t *c, HICON h, UINT flags, const char *what)
{
    BOOL ok;

    canvas_fill(c, BG);
    arm();
    ok = p_DrawIconEx(c->dc, 0, 0, h, 0, 0, 0, NULL, flags);
    line("DrawIconEx(the 16x16 icon, 0x0, %s): ret=%d err=%s", what, ok, le());
    canvas_grid(c, 16, 16);
}

static void sec_draw(void)
{
    canvas_t c, big;
    HICON h16, h32;
    HCURSOR cur;
    HBRUSH lime;
    const char *e;
    BOOL ok;

    if (!HAVE(DrawIconEx) || !HAVE(DrawIcon)) {
        return;
    }
    h16 = load_icon(16);
    h32 = load_icon(32);
    cur = load_cursor();
    line("LoadImageA(the icon, 16x16): non-NULL %s; (32x32): non-NULL %s; (the cursor): non-NULL %s",
         yesno(h16 != NULL), yesno(h32 != NULL), yesno(cur != NULL));
    if (!canvas_open(&c, 16, 16)) {
        return;
    }
    if (!canvas_open(&big, 32, 32)) {
        canvas_close(&c);
        return;
    }

    draw_grid(&c, h16, DI_NORMAL, "DI_NORMAL");
    line("  pixels not the image's: %d", mismatches(&c, img16, 16, 1));
    draw_grid(&c, h16, DI_MASK, "DI_MASK");
    draw_grid(&c, h16, DI_IMAGE, "DI_IMAGE");
    canvas_fill(&c, BG);
    arm();
    ok = p_DrawIconEx(c.dc, 0, 0, h16, 0, 0, 0, NULL, 0);
    e = le();
    line("DrawIconEx(the 16x16 icon, 0x0, no flags): ret=%d err=%s, the canvas untouched %s", ok, e,
         yesno(untouched(&c)));

    lime = CreateSolidBrush(RGB(0, 255, 0));
    canvas_fill(&c, BG);
    arm();
    ok = p_DrawIconEx(c.dc, 0, 0, h16, 0, 0, 0, lime, DI_NORMAL);
    e = le();
    line("DrawIconEx(the 16x16 icon, a lime flicker-free brush, DI_NORMAL): ret=%d err=%s", ok, e);
    line("  pixels not the image's over lime: %d, over the background: %d",
         mismatches_over(&c, img16, 16, 1, 0x00FF00), mismatches(&c, img16, 16, 1));
    DeleteObject(lime);

    canvas_fill(&big, BG);
    arm();
    ok = p_DrawIconEx(big.dc, 0, 0, h16, 32, 32, 0, NULL, DI_NORMAL);
    e = le();
    line("DrawIconEx(the 16x16 icon, 32x32, DI_NORMAL): ret=%d err=%s, pixels not the image's doubled: %d",
         ok, e, mismatches(&big, img16, 16, 2));
    canvas_fill(&big, BG);
    arm();
    ok = p_DrawIconEx(big.dc, 0, 0, h16, 0, 0, 0, NULL, DI_NORMAL | DI_DEFAULTSIZE);
    e = le();
    line("DrawIconEx(the 16x16 icon, 0x0, DI_NORMAL|DI_DEFAULTSIZE): ret=%d err=%s, "
         "pixels not the image's doubled: %d", ok, e, mismatches(&big, img16, 16, 2));
    canvas_fill(&big, BG);
    arm();
    ok = p_DrawIconEx(big.dc, 0, 0, h32, 0, 0, 0, NULL, DI_NORMAL | DI_DEFAULTSIZE);
    e = le();
    line("DrawIconEx(the 32x32 icon, 0x0, DI_NORMAL|DI_DEFAULTSIZE): ret=%d err=%s, "
         "pixels not the 8-bit image's: %d, not the 4-bit one's: %d", ok, e, mismatches(&big, img32b, 32, 1),
         mismatches(&big, img32a, 32, 1));
    canvas_fill(&big, BG);
    arm();
    ok = p_DrawIcon(big.dc, 0, 0, h32);
    e = le();
    line("DrawIcon(the 32x32 icon): ret=%d err=%s, pixels not the 8-bit image's: %d", ok, e,
         mismatches(&big, img32b, 32, 1));
    canvas_fill(&big, BG);
    arm();
    ok = p_DrawIcon(big.dc, 0, 0, h16);
    e = le();
    line("DrawIcon(the 16x16 icon): ret=%d err=%s, pixels not the image's doubled: %d, "
         "not the image's at its size: %d", ok, e, mismatches(&big, img16, 16, 2), mismatches(&big, img16, 16, 1));
    canvas_fill(&big, BG);
    arm();
    ok = p_DrawIcon(big.dc, 0, 0, cur);
    e = le();
    line("DrawIcon(the cursor): ret=%d err=%s, pixels not the image's: %d", ok, e,
         mismatches(&big, imgcur, 32, 1));
    arm();
    ok = p_DrawIconEx(NULL, 0, 0, h16, 0, 0, 0, NULL, DI_NORMAL);
    e = le();
    line("DrawIconEx(no DC): ret=%d err=%s", ok, e);
    canvas_fill(&c, BG);
    arm();
    ok = p_DrawIconEx(c.dc, 0, 0, NULL, 0, 0, 0, NULL, DI_NORMAL);
    e = le();
    line("DrawIconEx(no icon): ret=%d err=%s, the canvas untouched %s", ok, e, yesno(untouched(&c)));
    arm();
    ok = p_DrawIcon(c.dc, 0, 0, NULL);
    e = le();
    line("DrawIcon(no icon): ret=%d err=%s", ok, e);

    canvas_close(&c);
    canvas_close(&big);
    if (h16 != NULL) {
        DestroyIcon(h16);
    }
    if (h32 != NULL) {
        DestroyIcon(h32);
    }
    if (cur != NULL && p_DestroyCursor != NULL) {
        p_DestroyCursor(cur);
    }
}

/* --- copy ---------------------------------------------------------- */

/* CopyImage, printed: whether a handle came back and whether it is the
 * original; returns it. */
static HANDLE copy(HANDLE h, UINT type, int cx, int cy, UINT flags, const char *what)
{
    HANDLE c;

    arm();
    c = p_CopyImage(h, type, cx, cy, flags);
    line("CopyImage(%s): non-NULL %s err=%s, the original %s", what, yesno(c != NULL), le(),
         yesno(c != NULL && c == h));
    return c;
}

static void bitmap_line(HBITMAP b)
{
    DIBSECTION ds;
    int n;

    if (b == NULL) {
        return;
    }
    n = GetObjectA(b, sizeof ds, &ds);
    line("  it: %ldx%ld %d bit, a DIB section %s", ds.dsBm.bmWidth, ds.dsBm.bmHeight,
         ds.dsBm.bmBitsPixel * ds.dsBm.bmPlanes, yesno(n == sizeof ds));
}

static void sec_copy(void)
{
    static DWORD bits[8 * 8];
    HICON h32, c, c16, cres, other, del, cur, ccur, ci;
    HBITMAP b, cb;
    ICONINFO ii;
    BOOL ok;
    int w, ht, i;

    if (!HAVE(CopyImage) || !HAVE(GetIconInfo) || !HAVE(DrawIconEx)) {
        return;
    }
    h32 = load_icon(32);
    line("LoadImageA(the icon, 32x32): non-NULL %s", yesno(h32 != NULL));

    c = (HICON)copy(h32, IMAGE_ICON, 0, 0, 0, "the icon, IMAGE_ICON, 0x0, 0");
    describe("it", c);
    check_drawn("it", c, img32b, 32);
    c16 = (HICON)copy(h32, IMAGE_ICON, 16, 16, 0, "the icon, IMAGE_ICON, 16x16, 0");
    describe("it", c16);
    cres = (HICON)copy(h32, IMAGE_ICON, 16, 16, LR_COPYFROMRESOURCE,
                       "the icon, IMAGE_ICON, 16x16, LR_COPYFROMRESOURCE");
    describe("it", cres);
    check_drawn("it", cres, img16, 16);
    copy(h32, IMAGE_ICON, 32, 32, LR_COPYRETURNORG, "the icon, IMAGE_ICON, 32x32, LR_COPYRETURNORG");
    copy(h32, IMAGE_ICON, 0, 0, LR_COPYRETURNORG, "the icon, IMAGE_ICON, 0x0, LR_COPYRETURNORG");
    other = (HICON)copy(h32, IMAGE_ICON, 16, 16, LR_COPYRETURNORG,
                        "the icon, IMAGE_ICON, 16x16, LR_COPYRETURNORG");
    icon_size(other, &w, &ht);
    line("  its size: %dx%d", w, ht);
    del = NULL;
    if (c != NULL) {
        del = (HICON)copy(c, IMAGE_ICON, 0, 0, LR_COPYDELETEORG, "the first copy, IMAGE_ICON, 0x0, LR_COPYDELETEORG");
        describe("it", del);
        arm();
        ok = p_GetIconInfo(c, &ii);
        line("  GetIconInfo(the first copy) after: ret=%d err=%s", ok, le());
        if (ok) {
            DeleteObject(ii.hbmMask);
            if (ii.hbmColor != NULL) {
                DeleteObject(ii.hbmColor);
            }
        }
    }

    cur = load_cursor();
    line("LoadImageA(the cursor): non-NULL %s", yesno(cur != NULL));
    ccur = (HICON)copy(cur, IMAGE_CURSOR, 0, 0, 0, "the cursor, IMAGE_CURSOR, 0x0, 0");
    describe("it", ccur);
    check_drawn("it", ccur, imgcur, 32);

    copy(NULL, IMAGE_ICON, 0, 0, 0, "NULL, IMAGE_ICON, 0x0, 0");
    copy(h32, 7, 0, 0, 0, "the icon, type 7, 0x0, 0");

    for (i = 0; i < 8 * 8; i++) {
        bits[i] = vga[i % 16];
    }
    b = CreateBitmap(8, 8, 1, 32, bits);
    line("CreateBitmap(8x8, 32 bits): non-NULL %s", yesno(b != NULL));
    cb = (HBITMAP)copy(b, IMAGE_BITMAP, 0, 0, 0, "it, IMAGE_BITMAP, 0x0, 0");
    bitmap_line(cb);
    if (cb != NULL && cb != b) {
        DeleteObject(cb);
    }
    cb = (HBITMAP)copy(b, IMAGE_BITMAP, 16, 16, 0, "it, IMAGE_BITMAP, 16x16, 0");
    bitmap_line(cb);
    if (cb != NULL && cb != b) {
        DeleteObject(cb);
    }
    cb = (HBITMAP)copy(b, IMAGE_BITMAP, 0, 0, LR_MONOCHROME, "it, IMAGE_BITMAP, 0x0, LR_MONOCHROME");
    bitmap_line(cb);
    if (cb != NULL && cb != b) {
        DeleteObject(cb);
    }
    cb = (HBITMAP)copy(b, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION, "it, IMAGE_BITMAP, 0x0, LR_CREATEDIBSECTION");
    bitmap_line(cb);
    if (cb != NULL && cb != b) {
        DeleteObject(cb);
    }
    DeleteObject(b);

    arm();
    ci = CopyIcon(h32);
    line("CopyIcon(the icon): non-NULL %s err=%s, the original %s", yesno(ci != NULL), le(),
         yesno(ci != NULL && ci == h32));
    describe("it", ci);
    check_drawn("it", ci, img32b, 32);

    if (ci != NULL && ci != h32) {
        DestroyIcon(ci);
    }
    if (ccur != NULL && ccur != cur) {
        DestroyIcon(ccur);
    }
    if (cur != NULL && p_DestroyCursor != NULL) {
        p_DestroyCursor(cur);
    }
    if (del != NULL) {
        DestroyIcon(del);
    }
    if (other != NULL && other != h32) {
        DestroyIcon(other);
    }
    if (cres != NULL) {
        DestroyIcon(cres);
    }
    if (c16 != NULL) {
        DestroyIcon(c16);
    }
    if (h32 != NULL) {
        DestroyIcon(h32);
    }
}

/* --- extract ------------------------------------------------------- */

static void sec_extract(void)
{
    char path[MAX_PATH];
    WCHAR wpath[MAX_PATH];
    HICON h, large, small;
    UINT n, id;
    int w, ht;

    if (!HAVE(PrivateExtractIconsA) || !HAVE(PrivateExtractIconsW) || !HAVE(PrivateExtractIconExA)
        || !HAVE(PrivateExtractIconExW) || !HAVE(GetIconInfo) || !HAVE(DrawIconEx)) {
        return;
    }
    load_groups();
    GetModuleFileNameA(NULL, path, sizeof path);
    GetModuleFileNameW(NULL, wpath, MAX_PATH);

    arm();
    n = p_PrivateExtractIconsA(path, 0, 32, 32, NULL, NULL, 0, 0);
    line("PrivateExtractIconsA(the program, 0, 32x32, no buffers): ret=%u err=%s", n, le());
    arm();
    n = p_PrivateExtractIconsW(wpath, 0, 32, 32, NULL, NULL, 0, 0);
    line("PrivateExtractIconsW(the program, 0, 32x32, no buffers): ret=%u err=%s", n, le());

    h = NULL;
    id = 0xEEEE;
    arm();
    n = p_PrivateExtractIconsA(path, 0, 32, 32, &h, &id, 1, 0);
    line("PrivateExtractIconsA(the program, 0, 32x32, 1): ret=%u err=%s, an icon %s, id %s", n, le(),
         yesno(h != NULL), icon_entry_or_group(id));
    describe("it", h);
    check_drawn("it", h, img32b, 32);
    if (h != NULL) {
        DestroyIcon(h);
    }
    h = NULL;
    id = 0xEEEE;
    arm();
    n = p_PrivateExtractIconsW(wpath, 0, 16, 16, &h, &id, 1, 0);
    line("PrivateExtractIconsW(the program, 0, 16x16, 1): ret=%u err=%s, an icon %s, id %s", n, le(),
         yesno(h != NULL), icon_entry_or_group(id));
    describe("it", h);
    check_drawn("it", h, img16, 16);
    if (h != NULL) {
        DestroyIcon(h);
    }
    h = NULL;
    arm();
    n = p_PrivateExtractIconsA(path, 1, 32, 32, &h, NULL, 1, 0);
    line("PrivateExtractIconsA(the program, index 1, 32x32, 1): ret=%u err=%s, an icon %s", n, le(),
         yesno(h != NULL));
    if (h != NULL) {
        DestroyIcon(h);
    }
    h = NULL;
    arm();
    n = p_PrivateExtractIconsA("f2knone.exe", 0, 32, 32, &h, NULL, 1, 0);
    line("PrivateExtractIconsA(a missing file, 0, 32x32, 1): ret=%u err=%s, an icon %s", n, le(),
         yesno(h != NULL));
    if (h != NULL) {
        DestroyIcon(h);
    }

    arm();
    n = p_PrivateExtractIconExA(path, -1, NULL, NULL, 0);
    line("PrivateExtractIconExA(the program, -1, NULL, NULL, 0): ret=%u err=%s", n, le());
    arm();
    n = p_PrivateExtractIconExW(wpath, -1, NULL, NULL, 0);
    line("PrivateExtractIconExW(the program, -1, NULL, NULL, 0): ret=%u err=%s", n, le());
    large = NULL;
    small = NULL;
    arm();
    n = p_PrivateExtractIconExA(path, 0, &large, &small, 1);
    line("PrivateExtractIconExA(the program, 0, large, small, 1): ret=%u err=%s", n, le());
    icon_size(large, &w, &ht);
    line("  large: %s %dx%d", yesno(large != NULL), w, ht);
    icon_size(small, &w, &ht);
    line("  small: %s %dx%d", yesno(small != NULL), w, ht);
    if (large != NULL) {
        DestroyIcon(large);
    }
    if (small != NULL) {
        DestroyIcon(small);
    }
    large = NULL;
    small = NULL;
    arm();
    n = p_PrivateExtractIconExW(wpath, 0, &large, &small, 1);
    line("PrivateExtractIconExW(the program, 0, large, small, 1): ret=%u err=%s", n, le());
    icon_size(large, &w, &ht);
    line("  large: %s %dx%d", yesno(large != NULL), w, ht);
    icon_size(small, &w, &ht);
    line("  small: %s %dx%d", yesno(small != NULL), w, ht);
    if (large != NULL) {
        DestroyIcon(large);
    }
    if (small != NULL) {
        DestroyIcon(small);
    }
    large = NULL;
    arm();
    n = p_PrivateExtractIconExA(path, 0, &large, NULL, 1);
    line("PrivateExtractIconExA(the program, 0, large, NULL, 1): ret=%u err=%s, large %s", n, le(),
         yesno(large != NULL));
    if (large != NULL) {
        DestroyIcon(large);
    }
}

/* --- cursors ------------------------------------------------------- */

/* The path of `name` beside the program. */
static void beside(char *out, const char *name)
{
    char *slash;

    GetModuleFileNameA(NULL, out, MAX_PATH);
    slash = strrchr(out, '\\');
    if (slash != NULL) {
        slash[1] = '\0';
    } else {
        out[0] = '\0';
    }
    strcat(out, name);
}

static void sec_cursors(void)
{
    char path[MAX_PATH];
    WCHAR wpath[MAX_PATH];
    BYTE *bits;
    DWORD size, written, rate, steps;
    HANDLE f;
    HCURSOR ca, cw, r, arrow;
    BOOL ok;

    if (!HAVE(LoadCursorFromFileA) || !HAVE(LoadCursorFromFileW) || !HAVE(GetCursorFrameInfo)
        || !HAVE(SetSystemCursor) || !HAVE(DestroyCursor) || !HAVE(GetIconInfo) || !HAVE(DrawIconEx)) {
        return;
    }
    bits = resource("F2KCURF", RT_RCDATA, &size);
    line("RCDATA F2KCURF: found %s, %lu bytes", yesno(bits != NULL), size);
    if (bits == NULL) {
        return;
    }
    beside(path, "f2kicon.cur");
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    written = 0;
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, bits, size, &written, NULL);
        CloseHandle(f);
    }
    line("f2kicon.cur written beside the program: %s", yesno(written == size));

    arm();
    ca = p_LoadCursorFromFileA(path);
    line("LoadCursorFromFileA(f2kicon.cur): non-NULL %s err=%s", yesno(ca != NULL), le());
    describe("it", ca);
    check_drawn("it", ca, imgcur, 32);
    arm();
    cw = p_LoadCursorFromFileW(wpath);
    line("LoadCursorFromFileW(f2kicon.cur): non-NULL %s err=%s, the same as A's %s", yesno(cw != NULL), le(),
         yesno(cw != NULL && cw == ca));
    describe("it", cw);
    arm();
    r = p_LoadCursorFromFileA("f2knone.cur");
    line("LoadCursorFromFileA(a missing file): non-NULL %s err=%s", yesno(r != NULL), le());
    arm();
    r = p_LoadCursorFromFileW(L"f2knone.cur");
    line("LoadCursorFromFileW(a missing file): non-NULL %s err=%s", yesno(r != NULL), le());

    if (ca != NULL) {
        rate = 0xEEEE;
        steps = 0xEEEE;
        arm();
        r = p_GetCursorFrameInfo(ca, 0, 0, &rate, &steps);
        line("GetCursorFrameInfo(the file's cursor, 0, step 0): the cursor itself %s, non-NULL %s err=%s "
             "rate=%lu steps=%lu", yesno(r == ca), yesno(r != NULL), le(), rate, steps);
    }
    arrow = LoadCursorA(NULL, IDC_ARROW);
    rate = 0xEEEE;
    steps = 0xEEEE;
    arm();
    r = p_GetCursorFrameInfo(arrow, 0, 0, &rate, &steps);
    line("GetCursorFrameInfo(IDC_ARROW, 0, step 0): the cursor itself %s, non-NULL %s err=%s rate=%lu steps=%lu",
         yesno(r == arrow), yesno(r != NULL), le(), rate, steps);

    arm();
    ok = p_SetSystemCursor(NULL, OCR_NORMAL_);
    line("SetSystemCursor(NULL, OCR_NORMAL): ret=%d err=%s", ok, le());

    if (cw != NULL && cw != ca) {
        p_DestroyCursor(cw);
    }
    arm();
    ok = p_DestroyCursor(ca);
    line("DestroyCursor(the file's cursor): ret=%d err=%s", ok, le());
    arm();
    ok = p_DestroyCursor(ca);
    line("DestroyCursor(it, again): ret=%d err=%s", ok, le());
    line("f2kicon.cur deleted: %s", yesno(DeleteFileA(path)));
}

static const section_t sections[] = {
    { "stock", sec_stock, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "lookup", sec_lookup, F2KT_ALWAYS },
    { "fromres", sec_fromres, F2KT_ALWAYS },
    { "draw", sec_draw, F2KT_ALWAYS },
    { "copy", sec_copy, F2KT_ALWAYS },
    { "extract", sec_extract, F2KT_ALWAYS },
    { "cursors", sec_cursors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    resolve_all();
    return run_sections("icons", sections, argc, argv);
}
