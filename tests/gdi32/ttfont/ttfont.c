/*
 * ttfont - a TrueType font file a program loads itself, as gdi32 and
 * win32k serve it: AddFontResourceExA/W and RemoveFontResourceExA/W
 * (FR_PRIVATE), AddFontResourceA/W and RemoveFontResourceA/W, the font
 * objects (CreateFontIndirectA/W, CreateFontA/W, GetObjectA/W) and
 * GetTextFaceA/W, the metrics (GetTextMetricsA/W,
 * GetOutlineTextMetricsA/W), the widths (GetCharWidth32A/W,
 * GetCharABCWidthsA/W, GetTextExtentPoint32A/W), the enumeration
 * (EnumFontFamiliesExA/W, EnumFontFamiliesA/W), the raw tables
 * (GetFontData), the glyphs (GetGlyphOutlineA/W), the font mapper's
 * dialog faces, and text drawn into a memory DC, read back pixel by
 * pixel.
 *
 * The font is f2ktahom.ttf, beside the program: Wine's Tahoma
 * (fonts/tahoma.ttf) with its names changed to "F2K Tahoma" by
 * scripts/font_rename.py, and nothing else. The real machine has
 * Microsoft's own Tahoma installed, so the program never asks for
 * "Tahoma" by name: the copy's own family name reaches only the copy,
 * and the capture is Windows 2000's font engine on the bytes F2K reads.
 *
 * Every section but load loads the copy at its start with
 * AddFontResourceExW(L"f2ktahom.ttf", FR_PRIVATE, 0), from the current
 * directory (the program's own, as tests\capture.bat and F2K run it),
 * and removes it at its end; a private font is the process's alone and
 * goes with it. The load section observes those calls themselves, then
 * adds the copy publicly (AddFontResourceA and AddFontResourceW) and
 * removes it; before and after, it removes any public copy a run that
 * ended early left behind, without printing it.
 *
 * AddFontResourceExA/W and RemoveFontResourceExA/W are Windows 2000's
 * additions: the program finds them with GetProcAddress, as MSVC 6's
 * headers and import library may lack them, and says so when gdi32
 * does not export them.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=; no handle value or address is printed (a handle prints
 * as non-NULL or not). What prints is the font's own (its metrics,
 * widths, tables and glyphs, in device pixels), never the machine's
 * other fonts', but for the faces the mapper section's names resolve to
 * and the stock SYSTEM_FONT's GetFontData answer. lfHeight is in pixels
 * too (-11 is 8 points at 96 DPI). The TEXTMETRIC fields
 * tmDigitizedAspectX and tmDigitizedAspectY are the display's logical
 * pixels per inch: the capture is to be taken at 96 DPI (the Small
 * Fonts setting), F2K's display's. The fonts are asked for by lfHeight
 * -11, -13 and -16 (11, 13 and 16 pixels per em, sizes the font holds
 * embedded bitmap strikes for), -24 (24 per em, which it does not) and
 * +16 (a cell height of 16 pixels), at weights 400 and 700 (the font
 * has no bold face of its own), with DEFAULT_CHARSET.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   load     AddFontResourceExA/W with FR_PRIVATE, the same file twice,
 *            removed by RemoveFontResourceExA/W, and once more when it
 *            is gone; a file that does not exist; AddFontResourceW and
 *            AddFontResourceA without FR_PRIVATE, removed by
 *            RemoveFontResourceW and RemoveFontResourceA, and once more
 *            when gone
 *   create   at each height and weight: CreateFontIndirectW, its
 *            LOGFONTW and LOGFONTA by GetObjectW and GetObjectA, and
 *            GetTextFaceW/A once it is selected into the screen DC
 *            (GetDC(NULL)); CreateFontIndirectA, CreateFontA and
 *            CreateFontW of the same font, as the same LOGFONTW and
 *            face or not; GetObjectW's size with no buffer;
 *            GetTextFaceW/A with no buffer and a short one; a face name
 *            no font has, as the same face as an empty face name's or
 *            not
 *   metrics  at each height and weight: every TEXTMETRICW and
 *            TEXTMETRICA field; at -11 and -24 (weight 400):
 *            GetOutlineTextMetricsW's fields and names, and
 *            GetOutlineTextMetricsA's names and sizes
 *   widths   at each height (weight 400), and -11 and -24 at weight
 *            700: GetCharWidth32W/A and GetCharABCWidthsW over
 *            0x20-0x7E, GetCharABCWidthsA as the same or not; the
 *            extents of fixed strings by GetTextExtentPoint32W/A, the
 *            empty one, and (W only, the A form's characters being the
 *            code page's) one holding U+4E00, which the font lacks
 *   enum     EnumFontFamiliesExW/A for "F2K Tahoma" in DEFAULT_CHARSET
 *            and ANSI_CHARSET, EnumFontFamiliesW/A for "F2K Tahoma":
 *            the calls, the return and every callback's LOGFONT, names,
 *            TEXTMETRIC, NEWTEXTMETRIC and FONTSIGNATURE fields and
 *            FontType; and a face no font has (no callback expected to
 *            name the machine's other fonts, which never print)
 *   data     GetFontData at -11: the sizes and CRC-32s of whole tables
 *            (head, hhea, maxp, OS/2, hmtx, cmap, name, post, loca,
 *            glyf, cvt, gasp, VDMX, EBLC, EBDT) and of the whole file;
 *            tables the font lacks (fpgm, prep, kern, hdmx); partial
 *            reads at the start, across the end and past the end of a
 *            table; and the stock SYSTEM_FONT's
 *   glyphs   GetGlyphOutlineW with GGO_METRICS and GGO_BITMAP at -11
 *            and -24 for a dozen characters and U+4E00, which the font
 *            lacks: the GLYPHMETRICS and the bitmap's rows in hex;
 *            GetGlyphOutlineA for three of them, as the same or not
 *   mapper   CreateFontW/A for "MS Shell Dlg 2" and "MS Shell Dlg" at
 *            -11: GetTextFaceW/A's answer alone, the face Windows 2000
 *            resolves each to
 *   pixels   TextOutW of a fixed string at -11 and -24
 *            (NONANTIALIASED_QUALITY) into a memory DC
 *            (CreateCompatibleDC) over a 32-bit top-down DIB section
 *            (CreateDIBSection) filled white (PatBlt WHITENESS), black
 *            text in TRANSPARENT mode, read back with GetPixel: '#'
 *            black, '.' white, '?' any other color
 *
 * Embedded bitmaps against outlines: the font carries bitmap strikes at
 * 8-13, 15 and 16 pixels per em. F2K's font work takes GGO_BITMAP to
 * render a glyph's outline, and text output at a strike's size to draw
 * the strike; the glyphs section's -11 rows set against the pixels
 * section's -11 text show what Windows 2000 does.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ttfont):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ttfont.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* Windows 2000's private-font flag, which MSVC 6's headers may lack. */
#ifndef FR_PRIVATE
#define FR_PRIVATE 0x10
#endif
/* Windows NT 4's quality for text drawn without antialiasing, whatever
 * the machine's font-smoothing setting. */
#ifndef NONANTIALIASED_QUALITY
#define NONANTIALIASED_QUALITY 3
#endif

/* AddFontResourceExA/W and RemoveFontResourceExA/W, as Windows 2000's
 * documentation declares them. */
typedef int (WINAPI *add_ex_a_fn)(LPCSTR name, DWORD fl, PVOID res);
typedef int (WINAPI *add_ex_w_fn)(LPCWSTR name, DWORD fl, PVOID res);
typedef BOOL (WINAPI *remove_ex_a_fn)(LPCSTR name, DWORD fl, PVOID res);
typedef BOOL (WINAPI *remove_ex_w_fn)(LPCWSTR name, DWORD fl, PVOID res);

static add_ex_a_fn add_ex_a;
static add_ex_w_fn add_ex_w;
static remove_ex_a_fn remove_ex_a;
static remove_ex_w_fn remove_ex_w;

#define FONT_FILE_A "f2ktahom.ttf"
#define FONT_FILE_W L"f2ktahom.ttf"
#define MISSING_A "f2knone.ttf"
#define MISSING_W L"f2knone.ttf"
#define FACE_A "F2K Tahoma"
#define FACE_W L"F2K Tahoma"
#define UNKNOWN_A "F2K No Such Face"
#define UNKNOWN_W L"F2K No Such Face"

/* The heights the create, metrics and widths sections ask for, and the
 * two weights. */
static const LONG heights[] = { -11, -13, -16, -24, 16 };
#define NHEIGHTS (sizeof heights / sizeof heights[0])
static const LONG weights[] = { 400, 700 };
#define NWEIGHTS (sizeof weights / sizeof weights[0])

/* The character range the widths section covers. */
#define FIRST_CHAR 0x20
#define LAST_CHAR 0x7E
#define NCHARS (LAST_CHAR - FIRST_CHAR + 1)

/* A character the font has no glyph for (its cmap maps no CJK). */
#define OUTSIDE 0x4E00

/* A GetFontData table tag: the tag's first character in the low byte. */
#define TAG(a, b, c, d) \
    ((DWORD)(BYTE)(a) | ((DWORD)(BYTE)(b) << 8) | ((DWORD)(BYTE)(c) << 16) | ((DWORD)(BYTE)(d) << 24))

/* --- helpers ------------------------------------------------------- */

/* A DWORD a GDI call answers, GDI_ERROR by name. */
static const char *gdw(DWORD v)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (v == GDI_ERROR) {
        return "GDI_ERROR";
    }
    sprintf(b, "%lu", v);
    return b;
}

static void copy_w(WCHAR *dst, const WCHAR *src, int n)
{
    int i;

    for (i = 0; i < n - 1 && src[i] != 0; i++) {
        dst[i] = src[i];
    }
    dst[i] = 0;
}

static void copy_a(char *dst, const char *src, int n)
{
    int i;

    for (i = 0; i < n - 1 && src[i] != 0; i++) {
        dst[i] = src[i];
    }
    dst[i] = 0;
}

/* A wide string of at most n units, to its terminator. */
static const char *wsz(const WCHAR *s, int n)
{
    int len;

    for (len = 0; len < n && s[len] != 0; len++) {
    }
    return wsn(s, len);
}

/* The first n units of a buffer, each one shown: printable ASCII as
 * itself, any other unit (the terminator included) as <U+XXXX>. */
static const char *units_w(const WCHAR *s, int n)
{
    static char buf[256];
    int i, len = 0;

    for (i = 0; i < n && len < (int)sizeof buf - 9; i++) {
        if (s[i] >= 0x20 && s[i] < 0x7F) {
            buf[len++] = (char)s[i];
        } else {
            len += sprintf(buf + len, "<U+%04X>", (unsigned)s[i]);
        }
    }
    buf[len] = '\0';
    return buf;
}

/* The same for bytes, any other byte as <XX>. */
static const char *units_a(const char *s, int n)
{
    static char buf[256];
    int i, len = 0;

    for (i = 0; i < n && len < (int)sizeof buf - 5; i++) {
        if ((BYTE)s[i] >= 0x20 && (BYTE)s[i] < 0x7F) {
            buf[len++] = s[i];
        } else {
            len += sprintf(buf + len, "<%02X>", (unsigned)(BYTE)s[i]);
        }
    }
    buf[len] = '\0';
    return buf;
}

static int same_w(const WCHAR *a, const WCHAR *b)
{
    int i;

    for (i = 0; a[i] == b[i]; i++) {
        if (a[i] == 0) {
            return 1;
        }
    }
    return 0;
}

/* The CRC-32 (IEEE 802.3, as zlib computes it) of n bytes. */
static DWORD crc32_of(const BYTE *p, DWORD n)
{
    DWORD c = 0xFFFFFFFFu;
    DWORD i;
    int k;

    for (i = 0; i < n; i++) {
        c ^= p[i];
        for (k = 0; k < 8; k++) {
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
        }
    }
    return c ^ 0xFFFFFFFFu;
}

/* n bytes in hex, into one of a few buffers. */
static const char *hex(const BYTE *p, DWORD n)
{
    static char bufs[2][200];
    static int next;
    char *b = bufs[next++ & 1];
    DWORD i;

    b[0] = '\0';
    for (i = 0; i < n && i < 64; i++) {
        sprintf(b + 2 * i, "%02X", p[i]);
    }
    return b;
}

/* Find the Windows 2000 additions in gdi32. */
static void resolve(void)
{
    HMODULE gdi = GetModuleHandleA("gdi32.dll");

    if (gdi == NULL) {
        return;
    }
    add_ex_a = (add_ex_a_fn)GetProcAddress(gdi, "AddFontResourceExA");
    add_ex_w = (add_ex_w_fn)GetProcAddress(gdi, "AddFontResourceExW");
    remove_ex_a = (remove_ex_a_fn)GetProcAddress(gdi, "RemoveFontResourceExA");
    remove_ex_w = (remove_ex_w_fn)GetProcAddress(gdi, "RemoveFontResourceExW");
}

/* The section's start: the copy, loaded privately. */
static void load_private(void)
{
    int r;

    if (add_ex_w == NULL) {
        line("AddFontResourceExW: not exported by gdi32");
        return;
    }
    arm();
    r = add_ex_w(FONT_FILE_W, FR_PRIVATE, NULL);
    line("AddFontResourceExW(L\"f2ktahom.ttf\", FR_PRIVATE, 0): ret=%d err=%s", r, le());
}

/* The section's end: the copy removed. */
static void unload_private(void)
{
    BOOL r;

    if (remove_ex_w == NULL) {
        line("RemoveFontResourceExW: not exported by gdi32");
        return;
    }
    arm();
    r = remove_ex_w(FONT_FILE_W, FR_PRIVATE, NULL);
    line("RemoveFontResourceExW(L\"f2ktahom.ttf\", FR_PRIVATE, 0): ret=%d err=%s", r, le());
}

/* Remove any public copy a run that ended early left in the session,
 * unprinted: how many there are depends on the runs before. */
static void clear_public(void)
{
    int i;

    for (i = 0; i < 8 && RemoveFontResourceW(FONT_FILE_W); i++) {
    }
}

static void fill_lfw(LOGFONTW *lf, LONG height, LONG weight, const WCHAR *face, BYTE quality)
{
    ZeroMemory(lf, sizeof *lf);
    lf->lfHeight = height;
    lf->lfWeight = weight;
    lf->lfCharSet = DEFAULT_CHARSET;
    lf->lfQuality = quality;
    copy_w(lf->lfFaceName, face, LF_FACESIZE);
}

static void fill_lfa(LOGFONTA *lf, LONG height, LONG weight, const char *face)
{
    ZeroMemory(lf, sizeof *lf);
    lf->lfHeight = height;
    lf->lfWeight = weight;
    lf->lfCharSet = DEFAULT_CHARSET;
    lf->lfQuality = DEFAULT_QUALITY;
    copy_a(lf->lfFaceName, face, LF_FACESIZE);
}

/* "F2K Tahoma" at a height and weight, DEFAULT_QUALITY (a helper: the
 * create section observes the creation itself). */
static HFONT make_font(LONG height, LONG weight)
{
    LOGFONTW lf;

    fill_lfw(&lf, height, weight, FACE_W, DEFAULT_QUALITY);
    return CreateFontIndirectW(&lf);
}

static int same_lfw(const LOGFONTW *a, const LOGFONTW *b)
{
    return a->lfHeight == b->lfHeight && a->lfWidth == b->lfWidth
        && a->lfEscapement == b->lfEscapement && a->lfOrientation == b->lfOrientation
        && a->lfWeight == b->lfWeight && a->lfItalic == b->lfItalic
        && a->lfUnderline == b->lfUnderline && a->lfStrikeOut == b->lfStrikeOut
        && a->lfCharSet == b->lfCharSet && a->lfOutPrecision == b->lfOutPrecision
        && a->lfClipPrecision == b->lfClipPrecision && a->lfQuality == b->lfQuality
        && a->lfPitchAndFamily == b->lfPitchAndFamily && same_w(a->lfFaceName, b->lfFaceName);
}

static void print_lfw(const char *label, const LOGFONTW *lf)
{
    line("%s lfHeight=%ld lfWidth=%ld lfEscapement=%ld lfOrientation=%ld lfWeight=%ld"
         " lfItalic=%u lfUnderline=%u lfStrikeOut=%u lfCharSet=%u", label,
         (long)lf->lfHeight, (long)lf->lfWidth, (long)lf->lfEscapement, (long)lf->lfOrientation,
         (long)lf->lfWeight, (unsigned)lf->lfItalic, (unsigned)lf->lfUnderline,
         (unsigned)lf->lfStrikeOut, (unsigned)lf->lfCharSet);
    line("%s lfOutPrecision=%u lfClipPrecision=%u lfQuality=%u lfPitchAndFamily=0x%02X"
         " lfFaceName=\"%s\"", label, (unsigned)lf->lfOutPrecision,
         (unsigned)lf->lfClipPrecision, (unsigned)lf->lfQuality,
         (unsigned)lf->lfPitchAndFamily, wsz(lf->lfFaceName, LF_FACESIZE));
}

static void print_lfa(const char *label, const LOGFONTA *lf)
{
    char face[LF_FACESIZE + 1];

    copy_a(face, lf->lfFaceName, LF_FACESIZE + 1);
    line("%s lfHeight=%ld lfWidth=%ld lfEscapement=%ld lfOrientation=%ld lfWeight=%ld"
         " lfItalic=%u lfUnderline=%u lfStrikeOut=%u lfCharSet=%u", label,
         (long)lf->lfHeight, (long)lf->lfWidth, (long)lf->lfEscapement, (long)lf->lfOrientation,
         (long)lf->lfWeight, (unsigned)lf->lfItalic, (unsigned)lf->lfUnderline,
         (unsigned)lf->lfStrikeOut, (unsigned)lf->lfCharSet);
    line("%s lfOutPrecision=%u lfClipPrecision=%u lfQuality=%u lfPitchAndFamily=0x%02X"
         " lfFaceName=\"%s\"", label, (unsigned)lf->lfOutPrecision,
         (unsigned)lf->lfClipPrecision, (unsigned)lf->lfQuality,
         (unsigned)lf->lfPitchAndFamily, face);
}

static void print_tmw(const char *label, const TEXTMETRICW *tm)
{
    line("%s tmHeight=%ld tmAscent=%ld tmDescent=%ld tmInternalLeading=%ld"
         " tmExternalLeading=%ld tmAveCharWidth=%ld tmMaxCharWidth=%ld", label,
         (long)tm->tmHeight, (long)tm->tmAscent, (long)tm->tmDescent,
         (long)tm->tmInternalLeading, (long)tm->tmExternalLeading, (long)tm->tmAveCharWidth,
         (long)tm->tmMaxCharWidth);
    line("%s tmWeight=%ld tmOverhang=%ld tmDigitizedAspectX=%ld tmDigitizedAspectY=%ld", label,
         (long)tm->tmWeight, (long)tm->tmOverhang, (long)tm->tmDigitizedAspectX,
         (long)tm->tmDigitizedAspectY);
    line("%s tmFirstChar=0x%04X tmLastChar=0x%04X tmDefaultChar=0x%04X tmBreakChar=0x%04X"
         " tmItalic=%u tmUnderlined=%u tmStruckOut=%u tmPitchAndFamily=0x%02X tmCharSet=%u",
         label, (unsigned)tm->tmFirstChar, (unsigned)tm->tmLastChar,
         (unsigned)tm->tmDefaultChar, (unsigned)tm->tmBreakChar, (unsigned)tm->tmItalic,
         (unsigned)tm->tmUnderlined, (unsigned)tm->tmStruckOut,
         (unsigned)tm->tmPitchAndFamily, (unsigned)tm->tmCharSet);
}

static void print_tma(const char *label, const TEXTMETRICA *tm)
{
    line("%s tmHeight=%ld tmAscent=%ld tmDescent=%ld tmInternalLeading=%ld"
         " tmExternalLeading=%ld tmAveCharWidth=%ld tmMaxCharWidth=%ld", label,
         (long)tm->tmHeight, (long)tm->tmAscent, (long)tm->tmDescent,
         (long)tm->tmInternalLeading, (long)tm->tmExternalLeading, (long)tm->tmAveCharWidth,
         (long)tm->tmMaxCharWidth);
    line("%s tmWeight=%ld tmOverhang=%ld tmDigitizedAspectX=%ld tmDigitizedAspectY=%ld", label,
         (long)tm->tmWeight, (long)tm->tmOverhang, (long)tm->tmDigitizedAspectX,
         (long)tm->tmDigitizedAspectY);
    line("%s tmFirstChar=0x%02X tmLastChar=0x%02X tmDefaultChar=0x%02X tmBreakChar=0x%02X"
         " tmItalic=%u tmUnderlined=%u tmStruckOut=%u tmPitchAndFamily=0x%02X tmCharSet=%u",
         label, (unsigned)tm->tmFirstChar, (unsigned)tm->tmLastChar,
         (unsigned)tm->tmDefaultChar, (unsigned)tm->tmBreakChar, (unsigned)tm->tmItalic,
         (unsigned)tm->tmUnderlined, (unsigned)tm->tmStruckOut,
         (unsigned)tm->tmPitchAndFamily, (unsigned)tm->tmCharSet);
}

static int same_tmw(const TEXTMETRICW *a, const TEXTMETRICW *b)
{
    return a->tmHeight == b->tmHeight && a->tmAscent == b->tmAscent
        && a->tmDescent == b->tmDescent && a->tmInternalLeading == b->tmInternalLeading
        && a->tmExternalLeading == b->tmExternalLeading && a->tmAveCharWidth == b->tmAveCharWidth
        && a->tmMaxCharWidth == b->tmMaxCharWidth && a->tmWeight == b->tmWeight
        && a->tmOverhang == b->tmOverhang && a->tmDigitizedAspectX == b->tmDigitizedAspectX
        && a->tmDigitizedAspectY == b->tmDigitizedAspectY && a->tmFirstChar == b->tmFirstChar
        && a->tmLastChar == b->tmLastChar && a->tmDefaultChar == b->tmDefaultChar
        && a->tmBreakChar == b->tmBreakChar && a->tmItalic == b->tmItalic
        && a->tmUnderlined == b->tmUnderlined && a->tmStruckOut == b->tmStruckOut
        && a->tmPitchAndFamily == b->tmPitchAndFamily && a->tmCharSet == b->tmCharSet;
}

/* Integers, 16 to a line, each line headed by its first character. */
static void print_ints(const char *label, const int *v, int n, int first)
{
    char buf[200];
    int i, k, len;

    for (i = 0; i < n; i += 16) {
        len = 0;
        for (k = i; k < n && k < i + 16; k++) {
            len += sprintf(buf + len, " %d", v[k]);
        }
        line("%s 0x%02X:%s", label, first + i, buf);
    }
}

/* --- load ---------------------------------------------------------- */

/* The private loads and removals. */
static void load_ex(void)
{
    int r;
    BOOL b;

    arm();
    r = add_ex_w(FONT_FILE_W, FR_PRIVATE, NULL);
    line("AddFontResourceExW(L\"f2ktahom.ttf\", FR_PRIVATE, 0): ret=%d err=%s", r, le());
    arm();
    r = add_ex_a(FONT_FILE_A, FR_PRIVATE, NULL);
    line("AddFontResourceExA(\"f2ktahom.ttf\", FR_PRIVATE, 0) (the same file again): ret=%d err=%s",
         r, le());
    arm();
    b = remove_ex_a(FONT_FILE_A, FR_PRIVATE, NULL);
    line("RemoveFontResourceExA(\"f2ktahom.ttf\", FR_PRIVATE, 0): ret=%d err=%s", b, le());
    arm();
    b = remove_ex_w(FONT_FILE_W, FR_PRIVATE, NULL);
    line("RemoveFontResourceExW(L\"f2ktahom.ttf\", FR_PRIVATE, 0): ret=%d err=%s", b, le());
    arm();
    b = remove_ex_w(FONT_FILE_W, FR_PRIVATE, NULL);
    line("RemoveFontResourceExW(L\"f2ktahom.ttf\", FR_PRIVATE, 0) (once more): ret=%d err=%s", b,
         le());

    arm();
    r = add_ex_w(MISSING_W, FR_PRIVATE, NULL);
    line("AddFontResourceExW(L\"f2knone.ttf\", FR_PRIVATE, 0) (no such file): ret=%d err=%s", r,
         le());
    arm();
    r = add_ex_a(MISSING_A, FR_PRIVATE, NULL);
    line("AddFontResourceExA(\"f2knone.ttf\", FR_PRIVATE, 0) (no such file): ret=%d err=%s", r,
         le());
    arm();
    b = remove_ex_w(MISSING_W, FR_PRIVATE, NULL);
    line("RemoveFontResourceExW(L\"f2knone.ttf\", FR_PRIVATE, 0): ret=%d err=%s", b, le());
    arm();
    b = remove_ex_a(MISSING_A, FR_PRIVATE, NULL);
    line("RemoveFontResourceExA(\"f2knone.ttf\", FR_PRIVATE, 0): ret=%d err=%s", b, le());
}

/* The public loads and removals. */
static void public_load(void)
{
    int r;
    BOOL b;

    arm();
    r = AddFontResourceW(FONT_FILE_W);
    line("AddFontResourceW(L\"f2ktahom.ttf\"): ret=%d err=%s", r, le());
    arm();
    b = RemoveFontResourceW(FONT_FILE_W);
    line("RemoveFontResourceW(L\"f2ktahom.ttf\"): ret=%d err=%s", b, le());
    arm();
    b = RemoveFontResourceW(FONT_FILE_W);
    line("RemoveFontResourceW(L\"f2ktahom.ttf\") (once more): ret=%d err=%s", b, le());
    arm();
    r = AddFontResourceA(FONT_FILE_A);
    line("AddFontResourceA(\"f2ktahom.ttf\"): ret=%d err=%s", r, le());
    arm();
    b = RemoveFontResourceA(FONT_FILE_A);
    line("RemoveFontResourceA(\"f2ktahom.ttf\"): ret=%d err=%s", b, le());
    arm();
    b = RemoveFontResourceA(FONT_FILE_A);
    line("RemoveFontResourceA(\"f2ktahom.ttf\") (once more): ret=%d err=%s", b, le());
    arm();
    r = AddFontResourceW(MISSING_W);
    line("AddFontResourceW(L\"f2knone.ttf\") (no such file): ret=%d err=%s", r, le());
    arm();
    r = AddFontResourceA(MISSING_A);
    line("AddFontResourceA(\"f2knone.ttf\") (no such file): ret=%d err=%s", r, le());
}

static void sec_load(void)
{
    clear_public();
    line("gdi32 exports AddFontResourceExA: %s, AddFontResourceExW: %s", yesno(add_ex_a != NULL),
         yesno(add_ex_w != NULL));
    line("gdi32 exports RemoveFontResourceExA: %s, RemoveFontResourceExW: %s",
         yesno(remove_ex_a != NULL), yesno(remove_ex_w != NULL));
    if (add_ex_a != NULL && add_ex_w != NULL && remove_ex_a != NULL && remove_ex_w != NULL) {
        load_ex();
    }
    public_load();
    clear_public();
}

/* --- create -------------------------------------------------------- */

/* The face a font gets once selected into dc (a helper: no line). */
static void face_of(HDC dc, HFONT font, WCHAR *face)
{
    HGDIOBJ prev;

    face[0] = 0;
    prev = SelectObject(dc, font);
    GetTextFaceW(dc, LF_FACESIZE, face);
    SelectObject(dc, prev);
}

/* A font of another creation call, against the CreateFontIndirectW one. */
static void against(HDC dc, const char *what, HFONT font, const LOGFONTW *lfw, const WCHAR *facew)
{
    LOGFONTW other;
    WCHAR face[LF_FACESIZE];
    int r;

    line("%s: non-NULL %s err=%s", what, yesno(font != NULL), le());
    if (font == NULL) {
        return;
    }
    ZeroMemory(&other, sizeof other);
    r = GetObjectW(font, sizeof other, &other);
    face_of(dc, font, face);
    line("  its LOGFONTW the same as CreateFontIndirectW's: %s (GetObjectW ret=%d);"
         " its face the same: %s", yesno(same_lfw(&other, lfw)), r, yesno(same_w(face, facew)));
    DeleteObject(font);
}

static void sec_create(void)
{
    HDC dc;
    HFONT font;
    HGDIOBJ prev;
    LOGFONTW in_w, lfw;
    LOGFONTA in_a, lfa;
    WCHAR facew[LF_FACESIZE + 8];
    char facea[LF_FACESIZE + 8];
    WCHAR known[LF_FACESIZE], empty[LF_FACESIZE];
    unsigned h, w;
    int r;

    load_private();
    dc = GetDC(NULL);

    for (h = 0; h < NHEIGHTS; h++) {
        for (w = 0; w < NWEIGHTS; w++) {
            line("-- lfHeight %ld, lfWeight %ld", (long)heights[h], (long)weights[w]);
            fill_lfw(&in_w, heights[h], weights[w], FACE_W, DEFAULT_QUALITY);
            arm();
            font = CreateFontIndirectW(&in_w);
            line("CreateFontIndirectW: non-NULL %s err=%s", yesno(font != NULL), le());
            if (font == NULL) {
                continue;
            }
            ZeroMemory(&lfw, sizeof lfw);
            arm();
            r = GetObjectW(font, sizeof lfw, &lfw);
            line("GetObjectW(font, sizeof(LOGFONTW)): ret=%d err=%s", r, le());
            print_lfw(" ", &lfw);
            ZeroMemory(&lfa, sizeof lfa);
            arm();
            r = GetObjectA(font, sizeof lfa, &lfa);
            line("GetObjectA(font, sizeof(LOGFONTA)): ret=%d err=%s", r, le());
            print_lfa(" ", &lfa);

            prev = SelectObject(dc, font);
            ZeroMemory(facew, sizeof facew);
            arm();
            r = GetTextFaceW(dc, LF_FACESIZE, facew);
            line("GetTextFaceW(dc, 32, buf): ret=%d err=%s face=\"%s\"", r, le(), ws(facew));
            ZeroMemory(facea, sizeof facea);
            arm();
            r = GetTextFaceA(dc, LF_FACESIZE, facea);
            line("GetTextFaceA(dc, 32, buf): ret=%d err=%s face=\"%s\"", r, le(), facea);
            SelectObject(dc, prev);

            fill_lfa(&in_a, heights[h], weights[w], FACE_A);
            arm();
            against(dc, "CreateFontIndirectA", CreateFontIndirectA(&in_a), &lfw, facew);
            arm();
            against(dc, "CreateFontA",
                    CreateFontA(heights[h], 0, 0, 0, weights[w], FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH, FACE_A), &lfw, facew);
            arm();
            against(dc, "CreateFontW",
                    CreateFontW(heights[h], 0, 0, 0, weights[w], FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH, FACE_W), &lfw, facew);
            DeleteObject(font);
        }
    }

    line("-- the buffers, at lfHeight -11");
    font = make_font(-11, 400);
    arm();
    r = GetObjectW(font, 0, NULL);
    line("GetObjectW(font, 0, NULL): ret=%d err=%s", r, le());
    arm();
    r = GetObjectA(font, 0, NULL);
    line("GetObjectA(font, 0, NULL): ret=%d err=%s", r, le());
    prev = SelectObject(dc, font);
    arm();
    r = GetTextFaceW(dc, 0, NULL);
    line("GetTextFaceW(dc, 0, NULL): ret=%d err=%s", r, le());
    arm();
    r = GetTextFaceA(dc, 0, NULL);
    line("GetTextFaceA(dc, 0, NULL): ret=%d err=%s", r, le());
    for (r = 0; r < LF_FACESIZE + 8; r++) {
        facew[r] = '#';
        facea[r] = '#';
    }
    arm();
    r = GetTextFaceW(dc, 4, facew);
    line("GetTextFaceW(dc, 4, buf) (buf filled with '#'): ret=%d err=%s buf=%s", r, le(),
         units_w(facew, 6));
    arm();
    r = GetTextFaceA(dc, 4, facea);
    line("GetTextFaceA(dc, 4, buf) (buf filled with '#'): ret=%d err=%s buf=%s", r, le(),
         units_a(facea, 6));
    SelectObject(dc, prev);
    DeleteObject(font);

    line("-- a face no font has, at lfHeight -11");
    fill_lfw(&in_w, -11, 400, UNKNOWN_W, DEFAULT_QUALITY);
    arm();
    font = CreateFontIndirectW(&in_w);
    line("CreateFontIndirectW(\"F2K No Such Face\"): non-NULL %s err=%s", yesno(font != NULL), le());
    if (font != NULL) {
        HFONT blank;

        ZeroMemory(&lfw, sizeof lfw);
        arm();
        r = GetObjectW(font, sizeof lfw, &lfw);
        line("GetObjectW(font, sizeof(LOGFONTW)): ret=%d err=%s lfFaceName=\"%s\"", r, le(),
             wsz(lfw.lfFaceName, LF_FACESIZE));
        face_of(dc, font, known);
        fill_lfw(&in_w, -11, 400, L"", DEFAULT_QUALITY);
        blank = CreateFontIndirectW(&in_w);
        face_of(dc, blank, empty);
        line("selected, the same face as an empty face name's: %s; \"F2K Tahoma\": %s",
             yesno(same_w(known, empty)), yesno(same_w(known, FACE_W)));
        DeleteObject(blank);
        DeleteObject(font);
    }

    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- metrics ------------------------------------------------------- */

/* The outline metrics' strings live in the buffer, at the offsets the
 * otmp* members hold. */
static DWORD otm_buf[512];
static DWORD otm_buf_a[512];

static const WCHAR *otm_string_w(const OUTLINETEXTMETRICW *otm, UINT size, PSTR at)
{
    DWORD offset = (DWORD)at;

    if (offset == 0 || offset >= size) {
        return L"(outside)";
    }
    return (const WCHAR *)((const BYTE *)otm + offset);
}

static const char *otm_string_a(const OUTLINETEXTMETRICA *otm, UINT size, PSTR at)
{
    DWORD offset = (DWORD)at;

    if (offset == 0 || offset >= size) {
        return "(outside)";
    }
    return (const char *)otm + offset;
}

static void outline_metrics(HDC dc, const TEXTMETRICW *tmw)
{
    OUTLINETEXTMETRICW *o = (OUTLINETEXTMETRICW *)otm_buf;
    OUTLINETEXTMETRICA *oa = (OUTLINETEXTMETRICA *)otm_buf_a;
    UINT size, sizea, r;

    arm();
    size = GetOutlineTextMetricsW(dc, 0, NULL);
    line("GetOutlineTextMetricsW(dc, 0, NULL): ret=%u err=%s", size, le());
    if (size == 0 || size > sizeof otm_buf) {
        return;
    }
    ZeroMemory(otm_buf, sizeof otm_buf);
    arm();
    r = GetOutlineTextMetricsW(dc, size, o);
    line("GetOutlineTextMetricsW(dc, %u, buf): ret=%u err=%s", size, r, le());
    if (r == 0) {
        return;
    }
    line("  otmSize=%u otmTextMetrics the same as GetTextMetricsW's: %s", o->otmSize,
         yesno(same_tmw(&o->otmTextMetrics, tmw)));
    line("  otmPanoseNumber=%u %u %u %u %u %u %u %u %u %u", (unsigned)o->otmPanoseNumber.bFamilyType,
         (unsigned)o->otmPanoseNumber.bSerifStyle, (unsigned)o->otmPanoseNumber.bWeight,
         (unsigned)o->otmPanoseNumber.bProportion, (unsigned)o->otmPanoseNumber.bContrast,
         (unsigned)o->otmPanoseNumber.bStrokeVariation, (unsigned)o->otmPanoseNumber.bArmStyle,
         (unsigned)o->otmPanoseNumber.bLetterform, (unsigned)o->otmPanoseNumber.bMidline,
         (unsigned)o->otmPanoseNumber.bXHeight);
    line("  otmfsSelection=0x%04X otmfsType=0x%04X otmsCharSlopeRise=%d otmsCharSlopeRun=%d"
         " otmItalicAngle=%d otmEMSquare=%u", o->otmfsSelection, o->otmfsType,
         o->otmsCharSlopeRise, o->otmsCharSlopeRun, o->otmItalicAngle, o->otmEMSquare);
    line("  otmAscent=%d otmDescent=%d otmLineGap=%u otmsCapEmHeight=%u otmsXHeight=%u",
         o->otmAscent, o->otmDescent, o->otmLineGap, o->otmsCapEmHeight, o->otmsXHeight);
    line("  otmrcFontBox=%ld %ld %ld %ld otmMacAscent=%d otmMacDescent=%d otmMacLineGap=%u"
         " otmusMinimumPPEM=%u", (long)o->otmrcFontBox.left, (long)o->otmrcFontBox.top,
         (long)o->otmrcFontBox.right, (long)o->otmrcFontBox.bottom, o->otmMacAscent,
         o->otmMacDescent, o->otmMacLineGap, o->otmusMinimumPPEM);
    line("  otmptSubscriptSize=%ld,%ld otmptSubscriptOffset=%ld,%ld otmptSuperscriptSize=%ld,%ld"
         " otmptSuperscriptOffset=%ld,%ld", (long)o->otmptSubscriptSize.x,
         (long)o->otmptSubscriptSize.y, (long)o->otmptSubscriptOffset.x,
         (long)o->otmptSubscriptOffset.y, (long)o->otmptSuperscriptSize.x,
         (long)o->otmptSuperscriptSize.y, (long)o->otmptSuperscriptOffset.x,
         (long)o->otmptSuperscriptOffset.y);
    line("  otmsStrikeoutSize=%u otmsStrikeoutPosition=%d otmsUnderscoreSize=%d"
         " otmsUnderscorePosition=%d", o->otmsStrikeoutSize, o->otmsStrikeoutPosition,
         o->otmsUnderscoreSize, o->otmsUnderscorePosition);
    line("  otmpFamilyName=\"%s\" otmpFaceName=\"%s\"", ws(otm_string_w(o, size, o->otmpFamilyName)),
         ws(otm_string_w(o, size, o->otmpFaceName)));
    line("  otmpStyleName=\"%s\" otmpFullName=\"%s\"", ws(otm_string_w(o, size, o->otmpStyleName)),
         ws(otm_string_w(o, size, o->otmpFullName)));

    arm();
    sizea = GetOutlineTextMetricsA(dc, 0, NULL);
    line("GetOutlineTextMetricsA(dc, 0, NULL): ret=%u err=%s", sizea, le());
    if (sizea == 0 || sizea > sizeof otm_buf_a) {
        return;
    }
    ZeroMemory(otm_buf_a, sizeof otm_buf_a);
    arm();
    r = GetOutlineTextMetricsA(dc, sizea, oa);
    line("GetOutlineTextMetricsA(dc, %u, buf): ret=%u err=%s", sizea, r, le());
    if (r == 0) {
        return;
    }
    line("  otmSize=%u; otmEMSquare, otmAscent, otmDescent, otmLineGap and otmrcFontBox the same"
         " as W's: %s", oa->otmSize,
         yesno(oa->otmEMSquare == o->otmEMSquare && oa->otmAscent == o->otmAscent
               && oa->otmDescent == o->otmDescent && oa->otmLineGap == o->otmLineGap
               && oa->otmrcFontBox.left == o->otmrcFontBox.left
               && oa->otmrcFontBox.top == o->otmrcFontBox.top
               && oa->otmrcFontBox.right == o->otmrcFontBox.right
               && oa->otmrcFontBox.bottom == o->otmrcFontBox.bottom));
    line("  otmpFamilyName=\"%s\" otmpFaceName=\"%s\"", otm_string_a(oa, sizea, oa->otmpFamilyName),
         otm_string_a(oa, sizea, oa->otmpFaceName));
    line("  otmpStyleName=\"%s\" otmpFullName=\"%s\"", otm_string_a(oa, sizea, oa->otmpStyleName),
         otm_string_a(oa, sizea, oa->otmpFullName));
}

static void sec_metrics(void)
{
    HDC dc;
    HFONT font;
    HGDIOBJ prev;
    TEXTMETRICW tmw;
    TEXTMETRICA tma;
    unsigned h, w;
    BOOL r;

    load_private();
    dc = GetDC(NULL);
    for (h = 0; h < NHEIGHTS; h++) {
        for (w = 0; w < NWEIGHTS; w++) {
            line("-- lfHeight %ld, lfWeight %ld", (long)heights[h], (long)weights[w]);
            font = make_font(heights[h], weights[w]);
            prev = SelectObject(dc, font);
            ZeroMemory(&tmw, sizeof tmw);
            arm();
            r = GetTextMetricsW(dc, &tmw);
            line("GetTextMetricsW: ret=%d err=%s", r, le());
            print_tmw(" ", &tmw);
            ZeroMemory(&tma, sizeof tma);
            arm();
            r = GetTextMetricsA(dc, &tma);
            line("GetTextMetricsA: ret=%d err=%s", r, le());
            print_tma(" ", &tma);
            if (weights[w] == 400 && (heights[h] == -11 || heights[h] == -24)) {
                outline_metrics(dc, &tmw);
            }
            SelectObject(dc, prev);
            DeleteObject(font);
        }
    }
    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- widths -------------------------------------------------------- */

static const char *const extent_a[] = {
    "",
    "Hello",
    "F2K Tahoma",
    "The quick brown fox jumps over the lazy dog.",
    "iiiiiiiiii",
    "WWWWWWWWWW",
    NULL
};

static const WCHAR *const extent_w[] = {
    L"",
    L"Hello",
    L"F2K Tahoma",
    L"The quick brown fox jumps over the lazy dog.",
    L"iiiiiiiiii",
    L"WWWWWWWWWW",
    NULL
};

/* 'A', U+4E00 (no glyph in the font), 'Z'. */
static const WCHAR outside_w[] = { 'A', OUTSIDE, 'Z', 0 };

static void widths_at(HDC dc, LONG height, LONG weight)
{
    HFONT font;
    HGDIOBJ prev;
    int cw[NCHARS], cwa[NCHARS], abc_line[3 * 8];
    ABC abc[NCHARS], abca[NCHARS];
    SIZE sz;
    BOOL r;
    int i, k, n, same;

    line("-- lfHeight %ld, lfWeight %ld", (long)height, (long)weight);
    font = make_font(height, weight);
    prev = SelectObject(dc, font);

    ZeroMemory(cw, sizeof cw);
    arm();
    r = GetCharWidth32W(dc, FIRST_CHAR, LAST_CHAR, cw);
    line("GetCharWidth32W(dc, 0x20, 0x7E): ret=%d err=%s", r, le());
    print_ints(" ", cw, NCHARS, FIRST_CHAR);
    ZeroMemory(cwa, sizeof cwa);
    arm();
    r = GetCharWidth32A(dc, FIRST_CHAR, LAST_CHAR, cwa);
    line("GetCharWidth32A(dc, 0x20, 0x7E): ret=%d err=%s", r, le());
    print_ints(" ", cwa, NCHARS, FIRST_CHAR);

    ZeroMemory(abc, sizeof abc);
    arm();
    r = GetCharABCWidthsW(dc, FIRST_CHAR, LAST_CHAR, abc);
    line("GetCharABCWidthsW(dc, 0x20, 0x7E): ret=%d err=%s (A, B, C for each)", r, le());
    for (i = 0; i < NCHARS; i += 8) {
        n = 0;
        for (k = i; k < NCHARS && k < i + 8; k++) {
            abc_line[n++] = abc[k].abcA;
            abc_line[n++] = (int)abc[k].abcB;
            abc_line[n++] = abc[k].abcC;
        }
        print_ints(" ", abc_line, n, FIRST_CHAR + i);
    }
    ZeroMemory(abca, sizeof abca);
    arm();
    r = GetCharABCWidthsA(dc, FIRST_CHAR, LAST_CHAR, abca);
    same = 1;
    for (k = 0; k < NCHARS; k++) {
        if (abca[k].abcA != abc[k].abcA || abca[k].abcB != abc[k].abcB
            || abca[k].abcC != abc[k].abcC) {
            same = 0;
        }
    }
    line("GetCharABCWidthsA(dc, 0x20, 0x7E): ret=%d err=%s the same as W's: %s", r, le(),
         yesno(same));

    for (i = 0; extent_w[i] != NULL; i++) {
        n = lstrlenW(extent_w[i]);
        sz.cx = -1;
        sz.cy = -1;
        arm();
        r = GetTextExtentPoint32W(dc, extent_w[i], n, &sz);
        line("GetTextExtentPoint32W(L\"%s\", %d): ret=%d err=%s cx=%ld cy=%ld", ws(extent_w[i]), n,
             r, le(), (long)sz.cx, (long)sz.cy);
        n = lstrlenA(extent_a[i]);
        sz.cx = -1;
        sz.cy = -1;
        arm();
        r = GetTextExtentPoint32A(dc, extent_a[i], n, &sz);
        line("GetTextExtentPoint32A(\"%s\", %d): ret=%d err=%s cx=%ld cy=%ld", extent_a[i], n, r,
             le(), (long)sz.cx, (long)sz.cy);
    }
    sz.cx = -1;
    sz.cy = -1;
    arm();
    r = GetTextExtentPoint32W(dc, outside_w, 3, &sz);
    line("GetTextExtentPoint32W(L\"%s\", 3): ret=%d err=%s cx=%ld cy=%ld", ws(outside_w), r, le(),
         (long)sz.cx, (long)sz.cy);
    sz.cx = -1;
    sz.cy = -1;
    arm();
    r = GetTextExtentPoint32W(dc, outside_w + 1, 1, &sz);
    line("GetTextExtentPoint32W(L\"%s\", 1): ret=%d err=%s cx=%ld cy=%ld", wsn(outside_w + 1, 1), r,
         le(), (long)sz.cx, (long)sz.cy);

    SelectObject(dc, prev);
    DeleteObject(font);
}

static void sec_widths(void)
{
    HDC dc;
    unsigned h;

    load_private();
    dc = GetDC(NULL);
    for (h = 0; h < NHEIGHTS; h++) {
        widths_at(dc, heights[h], 400);
    }
    widths_at(dc, -11, 700);
    widths_at(dc, -24, 700);
    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- enum ---------------------------------------------------------- */

static int enum_calls;

static void print_ntm_extra(DWORD flags, UINT size_em, UINT cell_height, UINT avg_width)
{
    line("  ntmFlags=0x%08lX ntmSizeEM=%u ntmCellHeight=%u ntmAvgWidth=%u", flags, size_em,
         cell_height, avg_width);
}

static void print_sig(const FONTSIGNATURE *sig)
{
    line("  ntmFontSig fsUsb=%08lX %08lX %08lX %08lX fsCsb=%08lX %08lX", sig->fsUsb[0],
         sig->fsUsb[1], sig->fsUsb[2], sig->fsUsb[3], sig->fsCsb[0], sig->fsCsb[1]);
}

static int CALLBACK enum_ex_w(CONST LOGFONTW *lf, CONST TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
    const ENUMLOGFONTEXW *e = (const ENUMLOGFONTEXW *)lf;
    const NEWTEXTMETRICEXW *n = (const NEWTEXTMETRICEXW *)tm;

    enum_calls++;
    line(" callback %d: FontType=0x%lX", enum_calls, type);
    print_lfw("  elfLogFont", &e->elfLogFont);
    line("  elfFullName=\"%s\" elfStyle=\"%s\" elfScript=\"%s\"",
         wsz(e->elfFullName, LF_FULLFACESIZE), wsz(e->elfStyle, LF_FACESIZE),
         wsz(e->elfScript, LF_FACESIZE));
    print_tmw("  ntmTm", (const TEXTMETRICW *)&n->ntmTm);
    print_ntm_extra(n->ntmTm.ntmFlags, n->ntmTm.ntmSizeEM, n->ntmTm.ntmCellHeight,
                    n->ntmTm.ntmAvgWidth);
    print_sig(&n->ntmFontSig);
    return 1;
}

static int CALLBACK enum_ex_a(CONST LOGFONTA *lf, CONST TEXTMETRICA *tm, DWORD type, LPARAM lp)
{
    const ENUMLOGFONTEXA *e = (const ENUMLOGFONTEXA *)lf;
    const NEWTEXTMETRICEXA *n = (const NEWTEXTMETRICEXA *)tm;

    enum_calls++;
    line(" callback %d: FontType=0x%lX", enum_calls, type);
    print_lfa("  elfLogFont", &e->elfLogFont);
    line("  elfFullName=\"%.64s\" elfStyle=\"%.32s\" elfScript=\"%.32s\"",
         (const char *)e->elfFullName, (const char *)e->elfStyle, (const char *)e->elfScript);
    print_tma("  ntmTm", (const TEXTMETRICA *)&n->ntmTm);
    print_ntm_extra(n->ntmTm.ntmFlags, n->ntmTm.ntmSizeEM, n->ntmTm.ntmCellHeight,
                    n->ntmTm.ntmAvgWidth);
    print_sig(&n->ntmFontSig);
    return 1;
}

static int CALLBACK enum_w(CONST LOGFONTW *lf, CONST TEXTMETRICW *tm, DWORD type, LPARAM lp)
{
    const ENUMLOGFONTW *e = (const ENUMLOGFONTW *)lf;
    const NEWTEXTMETRICW *n = (const NEWTEXTMETRICW *)tm;

    enum_calls++;
    line(" callback %d: FontType=0x%lX", enum_calls, type);
    print_lfw("  elfLogFont", &e->elfLogFont);
    line("  elfFullName=\"%s\" elfStyle=\"%s\"", wsz(e->elfFullName, LF_FULLFACESIZE),
         wsz(e->elfStyle, LF_FACESIZE));
    print_tmw("  ntmTm", (const TEXTMETRICW *)n);
    print_ntm_extra(n->ntmFlags, n->ntmSizeEM, n->ntmCellHeight, n->ntmAvgWidth);
    return 1;
}

static int CALLBACK enum_a(CONST LOGFONTA *lf, CONST TEXTMETRICA *tm, DWORD type, LPARAM lp)
{
    const ENUMLOGFONTA *e = (const ENUMLOGFONTA *)lf;
    const NEWTEXTMETRICA *n = (const NEWTEXTMETRICA *)tm;

    enum_calls++;
    line(" callback %d: FontType=0x%lX", enum_calls, type);
    print_lfa("  elfLogFont", &e->elfLogFont);
    line("  elfFullName=\"%.64s\" elfStyle=\"%.32s\"", (const char *)e->elfFullName,
         (const char *)e->elfStyle);
    print_tma("  ntmTm", (const TEXTMETRICA *)n);
    print_ntm_extra(n->ntmFlags, n->ntmSizeEM, n->ntmCellHeight, n->ntmAvgWidth);
    return 1;
}

static void enum_ex_w_for(HDC dc, const WCHAR *face, BYTE charset, const char *what)
{
    LOGFONTW lf;
    int r;

    ZeroMemory(&lf, sizeof lf);
    lf.lfCharSet = charset;
    copy_w(lf.lfFaceName, face, LF_FACESIZE);
    enum_calls = 0;
    line("EnumFontFamiliesExW(\"%s\", %s):", ws(face), what);
    arm();
    r = EnumFontFamiliesExW(dc, &lf, (FONTENUMPROCW)enum_ex_w, 0, 0);
    line(" ret=%d err=%s callbacks=%d", r, le(), enum_calls);
}

static void enum_ex_a_for(HDC dc, const char *face, BYTE charset, const char *what)
{
    LOGFONTA lf;
    int r;

    ZeroMemory(&lf, sizeof lf);
    lf.lfCharSet = charset;
    copy_a(lf.lfFaceName, face, LF_FACESIZE);
    enum_calls = 0;
    line("EnumFontFamiliesExA(\"%s\", %s):", face, what);
    arm();
    r = EnumFontFamiliesExA(dc, &lf, (FONTENUMPROCA)enum_ex_a, 0, 0);
    line(" ret=%d err=%s callbacks=%d", r, le(), enum_calls);
}

static void sec_enum(void)
{
    HDC dc;
    int r;

    load_private();
    dc = GetDC(NULL);

    enum_ex_w_for(dc, FACE_W, DEFAULT_CHARSET, "DEFAULT_CHARSET");
    enum_ex_w_for(dc, FACE_W, ANSI_CHARSET, "ANSI_CHARSET");
    enum_ex_w_for(dc, UNKNOWN_W, DEFAULT_CHARSET, "DEFAULT_CHARSET");
    enum_ex_a_for(dc, FACE_A, DEFAULT_CHARSET, "DEFAULT_CHARSET");
    enum_ex_a_for(dc, FACE_A, ANSI_CHARSET, "ANSI_CHARSET");
    enum_ex_a_for(dc, UNKNOWN_A, DEFAULT_CHARSET, "DEFAULT_CHARSET");

    enum_calls = 0;
    line("EnumFontFamiliesW(\"F2K Tahoma\"):");
    arm();
    r = EnumFontFamiliesW(dc, FACE_W, (FONTENUMPROCW)enum_w, 0);
    line(" ret=%d err=%s callbacks=%d", r, le(), enum_calls);
    enum_calls = 0;
    line("EnumFontFamiliesA(\"F2K Tahoma\"):");
    arm();
    r = EnumFontFamiliesA(dc, FACE_A, (FONTENUMPROCA)enum_a, 0);
    line(" ret=%d err=%s callbacks=%d", r, le(), enum_calls);
    enum_calls = 0;
    line("EnumFontFamiliesW(\"F2K No Such Face\"):");
    arm();
    r = EnumFontFamiliesW(dc, UNKNOWN_W, (FONTENUMPROCW)enum_w, 0);
    line(" ret=%d err=%s callbacks=%d", r, le(), enum_calls);
    enum_calls = 0;
    line("EnumFontFamiliesA(\"F2K No Such Face\"):");
    arm();
    r = EnumFontFamiliesA(dc, UNKNOWN_A, (FONTENUMPROCA)enum_a, 0);
    line(" ret=%d err=%s callbacks=%d", r, le(), enum_calls);

    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- data ---------------------------------------------------------- */

/* A whole table (0: the whole file): its size, then its bytes' CRC. */
static void whole_table(HDC dc, DWORD tag, const char *name)
{
    DWORD size, r;
    BYTE *buf;

    arm();
    size = GetFontData(dc, tag, 0, NULL, 0);
    line("GetFontData(%s, 0, NULL, 0): ret=%s err=%s", name, gdw(size), le());
    if (size == GDI_ERROR || size == 0) {
        return;
    }
    buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (buf == NULL) {
        line("  (no memory for %lu bytes)", size);
        return;
    }
    arm();
    r = GetFontData(dc, tag, 0, buf, size);
    line("GetFontData(%s, 0, buf, %lu): ret=%s err=%s crc32=0x%08lX", name, size, gdw(r), le(),
         crc32_of(buf, size));
    HeapFree(GetProcessHeap(), 0, buf);
}

/* A partial read: count bytes from offset, the buffer first filled
 * with 0xEE so the line shows what the call wrote. */
static void part(HDC dc, DWORD tag, const char *name, DWORD offset, DWORD count)
{
    BYTE buf[64];
    DWORD r;

    FillMemory(buf, sizeof buf, 0xEE);
    arm();
    r = GetFontData(dc, tag, offset, buf, count);
    line("GetFontData(%s, %lu, buf, %lu): ret=%s err=%s buf=%s", name, offset, count, gdw(r), le(),
         hex(buf, count));
}

static void sec_data(void)
{
    HDC dc;
    HFONT font;
    HGDIOBJ prev;
    DWORD r;

    load_private();
    dc = GetDC(NULL);
    font = make_font(-11, 400);
    prev = SelectObject(dc, font);

    whole_table(dc, TAG('h', 'e', 'a', 'd'), "'head'");
    whole_table(dc, TAG('h', 'h', 'e', 'a'), "'hhea'");
    whole_table(dc, TAG('m', 'a', 'x', 'p'), "'maxp'");
    whole_table(dc, TAG('O', 'S', '/', '2'), "'OS/2'");
    whole_table(dc, TAG('h', 'm', 't', 'x'), "'hmtx'");
    whole_table(dc, TAG('c', 'm', 'a', 'p'), "'cmap'");
    whole_table(dc, TAG('n', 'a', 'm', 'e'), "'name'");
    whole_table(dc, TAG('p', 'o', 's', 't'), "'post'");
    whole_table(dc, TAG('l', 'o', 'c', 'a'), "'loca'");
    whole_table(dc, TAG('g', 'l', 'y', 'f'), "'glyf'");
    whole_table(dc, TAG('c', 'v', 't', ' '), "'cvt '");
    whole_table(dc, TAG('g', 'a', 's', 'p'), "'gasp'");
    whole_table(dc, TAG('V', 'D', 'M', 'X'), "'VDMX'");
    whole_table(dc, TAG('E', 'B', 'L', 'C'), "'EBLC'");
    whole_table(dc, TAG('E', 'B', 'D', 'T'), "'EBDT'");
    whole_table(dc, TAG('f', 'p', 'g', 'm'), "'fpgm'");
    whole_table(dc, TAG('p', 'r', 'e', 'p'), "'prep'");
    whole_table(dc, TAG('k', 'e', 'r', 'n'), "'kern'");
    whole_table(dc, TAG('h', 'd', 'm', 'x'), "'hdmx'");
    whole_table(dc, 0, "0 (the whole file)");

    part(dc, 0, "0 (the whole file)", 0, 12);
    part(dc, TAG('h', 'e', 'a', 'd'), "'head'", 0, 16);
    part(dc, TAG('h', 'e', 'a', 'd'), "'head'", 50, 8);
    part(dc, TAG('h', 'e', 'a', 'd'), "'head'", 54, 4);
    part(dc, TAG('h', 'e', 'a', 'd'), "'head'", 100, 4);
    part(dc, TAG('n', 'a', 'm', 'e'), "'name'", 0, 6);
    part(dc, TAG('h', 'h', 'e', 'a'), "'hhea'", 4, 6);

    SelectObject(dc, GetStockObject(SYSTEM_FONT));
    arm();
    r = GetFontData(dc, TAG('h', 'e', 'a', 'd'), 0, NULL, 0);
    line("GetFontData('head', 0, NULL, 0) with the stock SYSTEM_FONT selected: ret=%s err=%s",
         gdw(r), le());

    SelectObject(dc, prev);
    DeleteObject(font);
    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- glyphs -------------------------------------------------------- */

/* The identity transformation: eM11 and eM22 are 1.0. */
static const MAT2 identity = { { 0, 1 }, { 0, 0 }, { 0, 0 }, { 0, 1 } };

/* A dozen characters: capitals, lower case with descenders, digits,
 * punctuation, the space, a Latin-1 letter and a Cyrillic one. */
static const WCHAR glyph_chars[] = {
    'A', 'g', 'W', 'i', 'j', 'y', '0', '@', '.', ' ', 0x00E9, 0x0416, OUTSIDE, 0
};

static BYTE glyph_buf[8192];
static BYTE glyph_buf_a[8192];

static int same_gm(const GLYPHMETRICS *a, const GLYPHMETRICS *b)
{
    return a->gmBlackBoxX == b->gmBlackBoxX && a->gmBlackBoxY == b->gmBlackBoxY
        && a->gmptGlyphOrigin.x == b->gmptGlyphOrigin.x
        && a->gmptGlyphOrigin.y == b->gmptGlyphOrigin.y && a->gmCellIncX == b->gmCellIncX
        && a->gmCellIncY == b->gmCellIncY;
}

static void print_gm(const char *label, const GLYPHMETRICS *gm)
{
    line("%s gmBlackBoxX=%u gmBlackBoxY=%u gmptGlyphOrigin=%ld,%ld gmCellIncX=%d gmCellIncY=%d",
         label, gm->gmBlackBoxX, gm->gmBlackBoxY, (long)gm->gmptGlyphOrigin.x,
         (long)gm->gmptGlyphOrigin.y, (int)gm->gmCellIncX, (int)gm->gmCellIncY);
}

/* A GGO_BITMAP buffer's rows: each DWORD-aligned, its first
 * (gmBlackBoxX + 7) / 8 bytes printed. */
static void print_rows(const GLYPHMETRICS *gm, const BYTE *bits, DWORD size)
{
    DWORD pitch = ((gm->gmBlackBoxX + 31) / 32) * 4;
    DWORD used = (gm->gmBlackBoxX + 7) / 8;
    DWORD y;

    for (y = 0; y < gm->gmBlackBoxY && (y + 1) * pitch <= size; y++) {
        line("  row %2lu: %s", y, hex(bits + y * pitch, used));
    }
}

static void glyphs_at(HDC dc, LONG height)
{
    HFONT font;
    HGDIOBJ prev;
    GLYPHMETRICS gm, gmb;
    DWORD r, size;
    int i;

    line("-- lfHeight %ld, lfWeight 400", (long)height);
    font = make_font(height, 400);
    prev = SelectObject(dc, font);
    for (i = 0; glyph_chars[i] != 0; i++) {
        ZeroMemory(&gm, sizeof gm);
        arm();
        r = GetGlyphOutlineW(dc, glyph_chars[i], GGO_METRICS, &gm, 0, NULL, &identity);
        line("U+%04X GetGlyphOutlineW(GGO_METRICS): ret=%s err=%s", (unsigned)glyph_chars[i],
             gdw(r), le());
        print_gm(" ", &gm);
        ZeroMemory(&gmb, sizeof gmb);
        arm();
        size = GetGlyphOutlineW(dc, glyph_chars[i], GGO_BITMAP, &gmb, 0, NULL, &identity);
        line("U+%04X GetGlyphOutlineW(GGO_BITMAP, 0, NULL): ret=%s err=%s", (unsigned)glyph_chars[i],
             gdw(size), le());
        if (size == GDI_ERROR || size == 0 || size > sizeof glyph_buf) {
            continue;
        }
        ZeroMemory(&gmb, sizeof gmb);
        ZeroMemory(glyph_buf, sizeof glyph_buf);
        arm();
        r = GetGlyphOutlineW(dc, glyph_chars[i], GGO_BITMAP, &gmb, size, glyph_buf, &identity);
        line("U+%04X GetGlyphOutlineW(GGO_BITMAP, %lu, buf): ret=%s err=%s; its metrics the same as"
             " GGO_METRICS's: %s", (unsigned)glyph_chars[i], size, gdw(r), le(),
             yesno(same_gm(&gm, &gmb)));
        if (r != GDI_ERROR) {
            print_rows(&gmb, glyph_buf, size);
        }
    }
    SelectObject(dc, prev);
    DeleteObject(font);
}

/* GetGlyphOutlineA for a character, against the W form's answer. */
static void glyph_a(HDC dc, char ch)
{
    GLYPHMETRICS gm, gma;
    DWORD r, ra, size, sizea, pitch, used, y;
    int same;

    ZeroMemory(&gm, sizeof gm);
    ZeroMemory(&gma, sizeof gma);
    arm();
    ra = GetGlyphOutlineA(dc, (UINT)(BYTE)ch, GGO_METRICS, &gma, 0, NULL, &identity);
    line("'%c' GetGlyphOutlineA(GGO_METRICS): ret=%s err=%s", ch, gdw(ra), le());
    r = GetGlyphOutlineW(dc, (UINT)(BYTE)ch, GGO_METRICS, &gm, 0, NULL, &identity);
    line("  ret and GLYPHMETRICS the same as GetGlyphOutlineW's: %s",
         yesno(r == ra && same_gm(&gm, &gma)));

    ZeroMemory(glyph_buf, sizeof glyph_buf);
    ZeroMemory(glyph_buf_a, sizeof glyph_buf_a);
    arm();
    sizea = GetGlyphOutlineA(dc, (UINT)(BYTE)ch, GGO_BITMAP, &gma, 0, NULL, &identity);
    line("'%c' GetGlyphOutlineA(GGO_BITMAP, 0, NULL): ret=%s err=%s", ch, gdw(sizea), le());
    size = GetGlyphOutlineW(dc, (UINT)(BYTE)ch, GGO_BITMAP, &gm, 0, NULL, &identity);
    if (sizea == GDI_ERROR || sizea == 0 || sizea > sizeof glyph_buf_a || size != sizea) {
        line("  the same size as GetGlyphOutlineW's: %s", yesno(size == sizea));
        return;
    }
    arm();
    ra = GetGlyphOutlineA(dc, (UINT)(BYTE)ch, GGO_BITMAP, &gma, sizea, glyph_buf_a, &identity);
    line("'%c' GetGlyphOutlineA(GGO_BITMAP, %lu, buf): ret=%s err=%s", ch, sizea, gdw(ra), le());
    r = GetGlyphOutlineW(dc, (UINT)(BYTE)ch, GGO_BITMAP, &gm, size, glyph_buf, &identity);
    same = r == ra && same_gm(&gm, &gma);
    if (same && r != GDI_ERROR) {
        pitch = ((gm.gmBlackBoxX + 31) / 32) * 4;
        used = (gm.gmBlackBoxX + 7) / 8;
        for (y = 0; y < gm.gmBlackBoxY && (y + 1) * pitch <= size; y++) {
            if (memcmp(glyph_buf + y * pitch, glyph_buf_a + y * pitch, used) != 0) {
                same = 0;
            }
        }
    }
    line("  ret, GLYPHMETRICS and rows the same as GetGlyphOutlineW's: %s", yesno(same));
}

static void sec_glyphs(void)
{
    HDC dc;
    HFONT font;
    HGDIOBJ prev;

    load_private();
    dc = GetDC(NULL);
    glyphs_at(dc, -11);
    glyphs_at(dc, -24);

    line("-- GetGlyphOutlineA, lfHeight -11 and -24, lfWeight 400");
    font = make_font(-11, 400);
    prev = SelectObject(dc, font);
    glyph_a(dc, 'A');
    glyph_a(dc, 'g');
    glyph_a(dc, '@');
    SelectObject(dc, prev);
    DeleteObject(font);
    font = make_font(-24, 400);
    prev = SelectObject(dc, font);
    glyph_a(dc, 'A');
    glyph_a(dc, 'g');
    glyph_a(dc, '@');
    SelectObject(dc, prev);
    DeleteObject(font);

    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- mapper -------------------------------------------------------- */

static void mapped(HDC dc, const char *face_a, const WCHAR *face_w)
{
    HFONT font;
    HGDIOBJ prev;
    WCHAR facew[LF_FACESIZE];
    char facea[LF_FACESIZE];
    int r;

    arm();
    font = CreateFontW(-11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH,
                       face_w);
    line("CreateFontW(-11, \"%s\"): non-NULL %s err=%s", ws(face_w), yesno(font != NULL), le());
    if (font != NULL) {
        prev = SelectObject(dc, font);
        ZeroMemory(facew, sizeof facew);
        arm();
        r = GetTextFaceW(dc, LF_FACESIZE, facew);
        line("  GetTextFaceW: ret=%d err=%s face=\"%s\"", r, le(), ws(facew));
        SelectObject(dc, prev);
        DeleteObject(font);
    }
    arm();
    font = CreateFontA(-11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH,
                       face_a);
    line("CreateFontA(-11, \"%s\"): non-NULL %s err=%s", face_a, yesno(font != NULL), le());
    if (font != NULL) {
        prev = SelectObject(dc, font);
        ZeroMemory(facea, sizeof facea);
        arm();
        r = GetTextFaceA(dc, LF_FACESIZE, facea);
        line("  GetTextFaceA: ret=%d err=%s face=\"%s\"", r, le(), facea);
        SelectObject(dc, prev);
        DeleteObject(font);
    }
}

static void sec_mapper(void)
{
    HDC dc;

    load_private();
    dc = GetDC(NULL);
    mapped(dc, "MS Shell Dlg 2", L"MS Shell Dlg 2");
    mapped(dc, "MS Shell Dlg", L"MS Shell Dlg");
    ReleaseDC(NULL, dc);
    unload_private();
}

/* --- pixels -------------------------------------------------------- */

static const WCHAR pixel_text[] = L"Wg0@ Hij!";

static void pixels_at(HDC screen, LONG height, int width, int rows)
{
    HDC mem;
    HBITMAP bmp;
    HFONT font;
    HGDIOBJ old_bmp, old_font;
    BITMAPINFO bi;
    LOGFONTW lf;
    void *bits;
    COLORREF c;
    char row[256];
    int x, y, n, other;
    BOOL r;

    line("-- lfHeight %ld, lfWeight 400, NONANTIALIASED_QUALITY: %dx%d, the text at 2,2", (long)height,
         width, rows);
    arm();
    mem = CreateCompatibleDC(screen);
    line("CreateCompatibleDC(screen): non-NULL %s err=%s", yesno(mem != NULL), le());
    if (mem == NULL) {
        return;
    }
    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = width;
    bi.bmiHeader.biHeight = -rows;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    bits = NULL;
    arm();
    bmp = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    line("CreateDIBSection(%dx%d, 32 bits, top-down): non-NULL %s bits non-NULL %s err=%s", width,
         rows, yesno(bmp != NULL), yesno(bits != NULL), le());
    if (bmp == NULL) {
        DeleteDC(mem);
        return;
    }
    arm();
    old_bmp = SelectObject(mem, bmp);
    line("SelectObject(mem, the DIB section): previous non-NULL %s err=%s", yesno(old_bmp != NULL),
         le());
    arm();
    r = PatBlt(mem, 0, 0, width, rows, WHITENESS);
    line("PatBlt(mem, 0, 0, %d, %d, WHITENESS): ret=%d err=%s", width, rows, r, le());

    fill_lfw(&lf, height, 400, FACE_W, NONANTIALIASED_QUALITY);
    arm();
    font = CreateFontIndirectW(&lf);
    line("CreateFontIndirectW: non-NULL %s err=%s", yesno(font != NULL), le());
    old_font = SelectObject(mem, font);
    arm();
    c = SetTextColor(mem, RGB(0, 0, 0));
    line("SetTextColor(mem, black): previous=0x%06lX err=%s", (unsigned long)c, le());
    arm();
    x = SetBkMode(mem, TRANSPARENT);
    line("SetBkMode(mem, TRANSPARENT): previous=%d err=%s", x, le());
    n = lstrlenW(pixel_text);
    arm();
    r = TextOutW(mem, 2, 2, pixel_text, n);
    line("TextOutW(mem, 2, 2, L\"%s\", %d): ret=%d err=%s", ws(pixel_text), n, r, le());

    other = 0;
    for (y = 0; y < rows; y++) {
        for (x = 0; x < width && x < (int)sizeof row - 1; x++) {
            c = GetPixel(mem, x, y);
            if (c == RGB(0, 0, 0)) {
                row[x] = '#';
            } else if (c == RGB(255, 255, 255)) {
                row[x] = '.';
            } else {
                row[x] = '?';
                other++;
            }
        }
        row[x] = '\0';
        line("row %2d: %s", y, row);
    }
    line("GetPixel: pixels neither black nor white: %d", other);

    SelectObject(mem, old_font);
    DeleteObject(font);
    SelectObject(mem, old_bmp);
    arm();
    r = DeleteObject(bmp);
    line("DeleteObject(the DIB section): ret=%d err=%s", r, le());
    arm();
    r = DeleteDC(mem);
    line("DeleteDC(mem): ret=%d err=%s", r, le());
}

static void sec_pixels(void)
{
    HDC dc;

    load_private();
    dc = GetDC(NULL);
    pixels_at(dc, -11, 64, 18);
    pixels_at(dc, -24, 128, 34);
    ReleaseDC(NULL, dc);
    unload_private();
}

static const section_t sections[] = {
    { "load", sec_load, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "metrics", sec_metrics, F2KT_ALWAYS },
    { "widths", sec_widths, F2KT_ALWAYS },
    { "enum", sec_enum, F2KT_ALWAYS },
    { "data", sec_data, F2KT_ALWAYS },
    { "glyphs", sec_glyphs, F2KT_ALWAYS },
    { "mapper", sec_mapper, F2KT_ALWAYS },
    { "pixels", sec_pixels, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad DC, object or buffer would fault: no dialog stops the
     * capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    resolve();
    return run_sections("ttfont", sections, argc, argv);
}
