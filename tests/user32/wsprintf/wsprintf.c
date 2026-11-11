/*
 * wsprintf - user32's own formatting: wsprintfA/W and wvsprintfA/W.
 *
 * wsprintf is not the C runtime's sprintf: Windows 2000's user32
 * documents its own type fields (c, C, d, i, s, S, u, x, X, with the
 * h and l size prefixes), the '-', '#' and '0' flags, a width and a
 * precision, and a 1024-character limit on what it writes. The
 * sections run each format through both forms, on the same inputs
 * where the arguments are numbers, and on the matching narrow and wide
 * arguments where they are strings and characters; they also give it
 * what it does not document (floating point, %o, %p, I64, '*', '+',
 * ' ') with numeric arguments only, so nothing it reads as a string
 * can be a bad pointer.
 *
 * Every buffer is filled with '#' before a call, and a result prints
 * as its first ret+1 units, so the terminator shows: the units
 * 0x20-0x7E as they are, a NUL as \0, any other ANSI byte as <XX>,
 * any other wide unit as <U+XXXX>. The A form's line carries
 * "wsprintfA", the W form's "wsprintfW". Strings converting between
 * the forms go through the ANSI code page, which `strings` prints
 * first (whether it is 1252).
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel, and its line
 * prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   ints     %d, %i, %u, %x, %X of 0, negative and extreme values;
 *            the '#', '-' and '0' flags, widths and precisions; the l
 *            and h size prefixes (h truncating to 16 bits); two
 *            conversions in one format
 *   strings  %s, %S, %hs, %ls of plain text, NULL and text outside
 *            ASCII (U+00E9, U+4E00; the bytes 0xE9 and 0x80), widths
 *            and precisions on strings; %c, %C, %hc, %lc, and a NUL
 *            character in the middle of the output
 *   others   %% and a lone % at the end, and what wsprintf does not
 *            document: %f, %e, %o, %p, %I64d, %I64x, a '*' width, the
 *            '+' and ' ' flags, an unknown type letter
 *   limit    output of 1023, 1024, 1025 and 1500 characters through
 *            %s, a 1100-character literal format, two strings crossing
 *            the limit, and a 1100-wide field: the return, where the
 *            terminator lands, and the units around unit 1024
 *   vprintf  wvsprintfA and wvsprintfW through a va_list: numbers, a
 *            string and a character in one format, a wide string from
 *            the A form and a narrow one from the W form, and 1500
 *            characters against the limit
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat wsprintf):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wsprintf.c user32.lib
 */

#include "../common/f2kt.h"

/* Every buffer, larger than any output: the limit section's units past
 * 1024 must stay as filled. */
#define BUF_UNITS 2100

static char bufa[BUF_UNITS];
static WCHAR bufw[BUF_UNITS];

static void fill(void)
{
    int i;

    for (i = 0; i < BUF_UNITS; i++) {
        bufa[i] = '#';
        bufw[i] = '#';
    }
}

/* `count` ANSI units as printed: 0x20-0x7E as they are, a NUL as \0,
 * any other byte as <XX>. Calls no API. Rotates through a few
 * buffers. */
static const char *units_a(const char *s, int count)
{
    static char bufs[4][1200];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;
    unsigned char c;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 8; i++) {
        c = (unsigned char)s[i];
        if (c == 0) {
            b[n++] = '\\';
            b[n++] = '0';
        } else if (c >= 0x20 && c <= 0x7E) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "<%02X>", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

/* The same for wide units: any other unit as <U+XXXX>. */
static const char *units_w(const WCHAR *s, int count)
{
    static char bufs[4][1200];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 12; i++) {
        if (s[i] == 0) {
            b[n++] = '\\';
            b[n++] = '0';
        } else if (s[i] >= 0x20 && s[i] <= 0x7E) {
            b[n++] = (char)s[i];
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)s[i]);
        }
    }
    b[n] = '\0';
    return b;
}

/* A format string as printed (NUL-terminated ANSI text). */
static const char *fmt_a(const char *s)
{
    return units_a(s, (int)strlen(s));
}

/* How many units of a result print: ret+1 (the terminator), within the
 * buffer; 0 for a return outside it. */
static int shown(int ret)
{
    if (ret < 0 || ret > 1100) {
        return 0;
    }
    return ret + 1;
}

/* The two lines of a pair: the A call's, then the W call's. */
static void show_pair(const char *fmt, const char *args, int ra, DWORD ea, int rw, DWORD ew)
{
    line("wsprintfA(\"%s\", %s): ret=%d err=%s \"%s\"", fmt_a(fmt), args, ra, le_of(ea),
         units_a(bufa, shown(ra)));
    line("wsprintfW(L\"%s\", %s): ret=%d err=%s \"%s\"", fmt_a(fmt), args, rw, le_of(ew),
         units_w(bufw, shown(rw)));
}

static void show_a(const char *fmt, const char *args, int r, DWORD e)
{
    line("wsprintfA(\"%s\", %s): ret=%d err=%s \"%s\"", fmt_a(fmt), args, r, le_of(e),
         units_a(bufa, shown(r)));
}

static void show_w(const char *fmt, const char *args, int r, DWORD e)
{
    line("wsprintfW(L\"%s\", %s): ret=%d err=%s \"%s\"", fmt_a(fmt), args, r, le_of(e),
         units_w(bufw, shown(r)));
}

/* One format through both forms, on the same numeric arguments. The
 * format is a string literal: L##fmt is its wide twin. */
#define PAIR0(fmt) \
    do { \
        int ra_, rw_; \
        DWORD ea_, ew_; \
        fill(); \
        arm(); \
        ra_ = wsprintfA(bufa, fmt); \
        ea_ = GetLastError(); \
        arm(); \
        rw_ = wsprintfW(bufw, L##fmt); \
        ew_ = GetLastError(); \
        show_pair(fmt, "no arguments", ra_, ea_, rw_, ew_); \
    } while (0)

#define PAIR1(fmt, desc, a1) \
    do { \
        int ra_, rw_; \
        DWORD ea_, ew_; \
        fill(); \
        arm(); \
        ra_ = wsprintfA(bufa, fmt, a1); \
        ea_ = GetLastError(); \
        arm(); \
        rw_ = wsprintfW(bufw, L##fmt, a1); \
        ew_ = GetLastError(); \
        show_pair(fmt, desc, ra_, ea_, rw_, ew_); \
    } while (0)

#define PAIR2(fmt, desc, a1, a2) \
    do { \
        int ra_, rw_; \
        DWORD ea_, ew_; \
        fill(); \
        arm(); \
        ra_ = wsprintfA(bufa, fmt, a1, a2); \
        ea_ = GetLastError(); \
        arm(); \
        rw_ = wsprintfW(bufw, L##fmt, a1, a2); \
        ew_ = GetLastError(); \
        show_pair(fmt, desc, ra_, ea_, rw_, ew_); \
    } while (0)

/* One A call and one W call, each with its own argument. */
#define ONE_A(fmt, desc, a1) \
    do { \
        int r_; \
        DWORD e_; \
        fill(); \
        arm(); \
        r_ = wsprintfA(bufa, fmt, a1); \
        e_ = GetLastError(); \
        show_a(fmt, desc, r_, e_); \
    } while (0)

#define ONE_W(fmt, desc, a1) \
    do { \
        int r_; \
        DWORD e_; \
        fill(); \
        arm(); \
        r_ = wsprintfW(bufw, L##fmt, a1); \
        e_ = GetLastError(); \
        show_w(fmt, desc, r_, e_); \
    } while (0)

/* --- ints ---------------------------------------------------------- */

static void sec_ints(void)
{
    PAIR1("%d", "0", 0);
    PAIR1("%d", "-42", -42);
    PAIR1("%d", "0x7FFFFFFF", 0x7FFFFFFF);
    PAIR1("%d", "0x80000000", (int)0x80000000);
    PAIR1("%i", "-7", -7);
    PAIR1("%u", "-1", -1);
    PAIR1("%u", "0x80000000", 0x80000000u);
    PAIR1("%x", "0xBEEF", 0xBEEF);
    PAIR1("%X", "0xBEEF", 0xBEEF);
    PAIR1("%x", "-1", -1);
    PAIR1("%#x", "0xBEEF", 0xBEEF);
    PAIR1("%#X", "0xBEEF", 0xBEEF);
    PAIR1("%#x", "0", 0);
    PAIR1("%#d", "42", 42);
    PAIR1("%5d", "42", 42);
    PAIR1("%-5d|", "42", 42);
    PAIR1("%05d", "42", 42);
    PAIR1("%05d", "-42", -42);
    PAIR1("%-05d|", "42", 42);
    PAIR1("%08X", "0xABC", 0xABC);
    PAIR1("%#08x", "0xABC", 0xABC);
    PAIR1("%2d", "12345", 12345);
    PAIR1("%.3d", "7", 7);
    PAIR1("%.3d", "-7", -7);
    PAIR1("%8.3d|", "-7", -7);
    PAIR1("%.0d|", "0", 0);
    PAIR1("%.5x", "0xAB", 0xAB);
    PAIR1("%ld", "-42L", -42L);
    PAIR1("%li", "-42L", -42L);
    PAIR1("%lu", "4000000000UL", 4000000000UL);
    PAIR1("%lx", "0xCAFEBABEUL", 0xCAFEBABEUL);
    PAIR1("%lX", "0xCAFEBABEUL", 0xCAFEBABEUL);
    PAIR1("%hd", "0x18000", 0x18000);
    PAIR1("%hd", "0x12345", 0x12345);
    PAIR1("%hu", "0x12345", 0x12345);
    PAIR1("%hu", "-1", -1);
    PAIR1("%hx", "0x12345", 0x12345);
    PAIR1("%hX", "0xFFFFABCD", 0xFFFFABCDu);
    PAIR2("%d %d", "1, 2", 1, 2);
    PAIR2("[%x-%u]", "255, 255", 255, 255);
}

/* --- strings ------------------------------------------------------- */

static void sec_strings(void)
{
    static const WCHAR abc_w[] = { 'a', 'b', 'c', 0 };
    static const WCHAR abcdef_w[] = { 'a', 'b', 'c', 'd', 'e', 'f', 0 };
    static const WCHAR ab_w[] = { 'a', 'b', 0 };
    static const WCHAR cafe_w[] = { 'c', 'a', 'f', 0x00E9, 0 };
    static const WCHAR cjk_w[] = { 'x', 0x4E00, 'y', 0 };

    line("ANSI code page 1252: %s", yesno(GetACP() == 1252));

    /* The A form: %s, %hs are narrow; %S, %ls wide. */
    ONE_A("%s", "\"abc\"", "abc");
    ONE_A("%s", "NULL", (const char *)NULL);
    ONE_A("[%5s]", "\"ab\"", "ab");
    ONE_A("[%-5s]", "\"ab\"", "ab");
    ONE_A("[%05s]", "\"ab\"", "ab");
    ONE_A("[%.2s]", "\"abcdef\"", "abcdef");
    ONE_A("[%5.2s]", "\"abcdef\"", "abcdef");
    ONE_A("[%.0s]", "\"abcdef\"", "abcdef");
    ONE_A("%s", "\"caf\\xE9\"", "caf\xE9");
    ONE_A("%hs", "\"abc\"", "abc");
    ONE_A("%hs", "NULL", (const char *)NULL);
    ONE_A("%S", "L\"abc\"", abc_w);
    ONE_A("%ls", "L\"abc\"", abc_w);
    ONE_A("%S", "NULL", (const WCHAR *)NULL);
    ONE_A("%ls", "NULL", (const WCHAR *)NULL);
    ONE_A("[%5S]", "L\"ab\"", ab_w);
    ONE_A("[%.2S]", "L\"abcdef\"", abcdef_w);
    ONE_A("%S", "L\"caf<U+00E9>\"", cafe_w);
    ONE_A("%S", "L\"x<U+4E00>y\"", cjk_w);

    /* The W form: %s, %ls are wide; %S, %hs narrow. */
    ONE_W("%s", "L\"abc\"", abc_w);
    ONE_W("%s", "NULL", (const WCHAR *)NULL);
    ONE_W("[%5s]", "L\"ab\"", ab_w);
    ONE_W("[%-5s]", "L\"ab\"", ab_w);
    ONE_W("[%05s]", "L\"ab\"", ab_w);
    ONE_W("[%.2s]", "L\"abcdef\"", abcdef_w);
    ONE_W("[%5.2s]", "L\"abcdef\"", abcdef_w);
    ONE_W("[%.0s]", "L\"abcdef\"", abcdef_w);
    ONE_W("%s", "L\"caf<U+00E9>\"", cafe_w);
    ONE_W("%s", "L\"x<U+4E00>y\"", cjk_w);
    ONE_W("%ls", "L\"abc\"", abc_w);
    ONE_W("%ls", "NULL", (const WCHAR *)NULL);
    ONE_W("%S", "\"abc\"", "abc");
    ONE_W("%hs", "\"abc\"", "abc");
    ONE_W("%S", "NULL", (const char *)NULL);
    ONE_W("%hs", "NULL", (const char *)NULL);
    ONE_W("[%5S]", "\"ab\"", "ab");
    ONE_W("[%.2S]", "\"abcdef\"", "abcdef");
    ONE_W("%S", "\"caf\\xE9\"", "caf\xE9");
    ONE_W("%S", "\"\\x80\"", "\x80");

    /* Characters: an int argument each. */
    ONE_A("%c", "'x'", 'x');
    ONE_A("%c", "0xE9", 0xE9);
    ONE_A("[%3c]", "'x'", 'x');
    ONE_A("[%-3c]", "'x'", 'x');
    ONE_A("%hc", "'z'", 'z');
    ONE_A("%C", "L'y'", (int)L'y');
    ONE_A("%C", "0x00E9", 0x00E9);
    ONE_A("%C", "0x4E00", 0x4E00);
    ONE_A("%lc", "L'w'", (int)L'w');
    ONE_A("a%cb", "0", 0);
    ONE_W("%c", "L'x'", (int)L'x');
    ONE_W("%c", "0x4E00", 0x4E00);
    ONE_W("[%3c]", "L'x'", (int)L'x');
    ONE_W("[%-3c]", "L'x'", (int)L'x');
    ONE_W("%lc", "L'w'", (int)L'w');
    ONE_W("%C", "'y'", 'y');
    ONE_W("%C", "0xE9", 0xE9);
    ONE_W("%C", "0x80", 0x80);
    ONE_W("%hc", "'z'", 'z');
    ONE_W("a%cb", "0", 0);
}

/* --- others -------------------------------------------------------- */

static void sec_others(void)
{
    __int64 big = 0x123456789ABCDEF0i64;
    __int64 minus5 = -5i64;

    PAIR0("100%%");
    PAIR0("%%d");
    PAIR0("100%");
    PAIR0("a%");
    PAIR1("%5%|", "1", 1);
    PAIR1("%o", "8", 8);
    PAIR1("%#o", "8", 8);
    PAIR1("%f", "1", 1);
    PAIR1("%e", "1", 1);
    PAIR1("%g", "1", 1);
    PAIR1("%p", "0x12AB34CD", 0x12AB34CD);
    PAIR1("%k", "1", 1);
    PAIR1("%+d", "5", 5);
    PAIR1("% d", "5", 5);
    PAIR2("[%*d]", "6, 42", 6, 42);
    PAIR2("[%.*d]", "4, 42", 4, 42);
    PAIR1("%I64d", "-5 as __int64", minus5);
    PAIR1("%I64x", "0x123456789ABCDEF0 as __int64", big);
    PAIR1("%I64u", "-5 as __int64", minus5);
    PAIR1("%I32d", "-5", -5);
    PAIR1("%Lx", "0xBEEF", 0xBEEF);
    PAIR1("%lld", "-5 as __int64", minus5);
}

/* --- limit --------------------------------------------------------- */

/* Where the terminator is in a buffer (BUF_UNITS when none), and its
 * units 1020-1027 ('#' where nothing was written). */
static void tail_a(const char *label, int r, DWORD e)
{
    int nul;

    for (nul = 0; nul < BUF_UNITS && bufa[nul] != '\0'; nul++) {
    }
    line("wsprintfA(%s): ret=%d err=%s terminator at %d, units 1020-1027 \"%s\"", label, r,
         le_of(e), nul, units_a(bufa + 1020, 8));
}

static void tail_w(const char *label, int r, DWORD e)
{
    int nul;

    for (nul = 0; nul < BUF_UNITS && bufw[nul] != 0; nul++) {
    }
    line("wsprintfW(%s): ret=%d err=%s terminator at %d, units 1020-1027 \"%s\"", label, r,
         le_of(e), nul, units_w(bufw + 1020, 8));
}

static void sec_limit(void)
{
    static char srca[1600];
    static WCHAR srcw[1600];
    static char fmta[1200];
    static WCHAR fmtw[1200];
    static const int lengths[] = { 1023, 1024, 1025, 1500 };
    char label[96];
    int i, k, r;
    DWORD e;

    /* Every source unit says where it is: '0'-'9' over and over. */
    for (i = 0; i < 1500; i++) {
        srca[i] = (char)('0' + i % 10);
        srcw[i] = (WCHAR)('0' + i % 10);
    }
    for (i = 0; i < 1100; i++) {
        fmta[i] = 'f';
        fmtw[i] = 'f';
    }
    fmta[1100] = '\0';
    fmtw[1100] = 0;

    for (k = 0; k < 4; k++) {
        srca[lengths[k]] = '\0';
        srcw[lengths[k]] = 0;
        sprintf(label, "\"%%s\", %d characters", lengths[k]);
        fill();
        arm();
        r = wsprintfA(bufa, "%s", srca);
        e = GetLastError();
        tail_a(label, r, e);
        fill();
        arm();
        r = wsprintfW(bufw, L"%s", srcw);
        e = GetLastError();
        tail_w(label, r, e);
        srca[lengths[k]] = (char)('0' + lengths[k] % 10);
        srcw[lengths[k]] = (WCHAR)('0' + lengths[k] % 10);
    }

    fill();
    arm();
    r = wsprintfA(bufa, fmta);
    e = GetLastError();
    tail_a("a format of 1100 literal characters", r, e);
    fill();
    arm();
    r = wsprintfW(bufw, fmtw);
    e = GetLastError();
    tail_w("a format of 1100 literal characters", r, e);

    srca[1000] = '\0';
    srcw[1000] = 0;
    fill();
    arm();
    r = wsprintfA(bufa, "%s|%s", srca, "abcdefghijklmnopqrstuvwxyz0123456789");
    e = GetLastError();
    tail_a("\"%s|%s\", 1000 characters and 36", r, e);
    fill();
    arm();
    r = wsprintfW(bufw, L"%s|%s", srcw, L"abcdefghijklmnopqrstuvwxyz0123456789");
    e = GetLastError();
    tail_w("\"%s|%s\", 1000 characters and 36", r, e);
    srca[1000] = '0';
    srcw[1000] = '0';

    fill();
    arm();
    r = wsprintfA(bufa, "%1100d", 5);
    e = GetLastError();
    tail_a("\"%1100d\", 5", r, e);
    fill();
    arm();
    r = wsprintfW(bufw, L"%1100d", 5);
    e = GetLastError();
    tail_w("\"%1100d\", 5", r, e);
}

/* --- vprintf ------------------------------------------------------- */

static DWORD v_err;

static int va_a(char *buf, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    arm();
    r = wvsprintfA(buf, fmt, ap);
    v_err = GetLastError();
    va_end(ap);
    return r;
}

static int va_w(WCHAR *buf, const WCHAR *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    arm();
    r = wvsprintfW(buf, fmt, ap);
    v_err = GetLastError();
    va_end(ap);
    return r;
}

static void sec_vprintf(void)
{
    static const WCHAR abc_w[] = { 'a', 'b', 'c', 0 };
    static const WCHAR cafe_w[] = { 'c', 'a', 'f', 0x00E9, 0 };
    static char srca[1600];
    static WCHAR srcw[1600];
    int i, r, nul;

    line("ANSI code page 1252: %s", yesno(GetACP() == 1252));

    fill();
    r = va_a(bufa, "%d|%5s|%c|%#x", -3, "ab", 'z', 0xAB);
    line("wvsprintfA(\"%%d|%%5s|%%c|%%#x\", -3, \"ab\", 'z', 0xAB): ret=%d err=%s \"%s\"", r,
         le_of(v_err), units_a(bufa, shown(r)));
    fill();
    r = va_w(bufw, L"%d|%5s|%c|%#x", -3, L"ab", (int)L'z', 0xAB);
    line("wvsprintfW(L\"%%d|%%5s|%%c|%%#x\", -3, L\"ab\", L'z', 0xAB): ret=%d err=%s \"%s\"", r,
         le_of(v_err), units_w(bufw, shown(r)));

    fill();
    r = va_a(bufa, "%S/%ls/%C", cafe_w, abc_w, 0x00E9);
    line("wvsprintfA(\"%%S/%%ls/%%C\", L\"caf<U+00E9>\", L\"abc\", 0x00E9): ret=%d err=%s \"%s\"", r,
         le_of(v_err), units_a(bufa, shown(r)));
    fill();
    r = va_w(bufw, L"%S/%hs/%C", "caf\xE9", "abc", 0xE9);
    line("wvsprintfW(L\"%%S/%%hs/%%C\", \"caf\\xE9\", \"abc\", 0xE9): ret=%d err=%s \"%s\"", r,
         le_of(v_err), units_w(bufw, shown(r)));

    fill();
    r = va_a(bufa, "%s", (const char *)NULL);
    line("wvsprintfA(\"%%s\", NULL): ret=%d err=%s \"%s\"", r, le_of(v_err),
         units_a(bufa, shown(r)));
    fill();
    r = va_w(bufw, L"%s", (const WCHAR *)NULL);
    line("wvsprintfW(L\"%%s\", NULL): ret=%d err=%s \"%s\"", r, le_of(v_err),
         units_w(bufw, shown(r)));

    for (i = 0; i < 1500; i++) {
        srca[i] = (char)('0' + i % 10);
        srcw[i] = (WCHAR)('0' + i % 10);
    }
    srca[1500] = '\0';
    srcw[1500] = 0;
    fill();
    r = va_a(bufa, "%s", srca);
    for (nul = 0; nul < BUF_UNITS && bufa[nul] != '\0'; nul++) {
    }
    line("wvsprintfA(\"%%s\", 1500 characters): ret=%d err=%s terminator at %d, units 1020-1027 \"%s\"",
         r, le_of(v_err), nul, units_a(bufa + 1020, 8));
    fill();
    r = va_w(bufw, L"%s", srcw);
    for (nul = 0; nul < BUF_UNITS && bufw[nul] != 0; nul++) {
    }
    line("wvsprintfW(L\"%%s\", 1500 characters): ret=%d err=%s terminator at %d, units 1020-1027 \"%s\"",
         r, le_of(v_err), nul, units_w(bufw + 1020, 8));
}

static const section_t sections[] = {
    { "ints", sec_ints, F2KT_ALWAYS },
    { "strings", sec_strings, F2KT_ALWAYS },
    { "others", sec_others, F2KT_ALWAYS },
    { "limit", sec_limit, F2KT_ALWAYS },
    { "vprintf", sec_vprintf, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A format wsprintf reads differently than documented could fault:
     * no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("wsprintf", sections, argc, argv);
}
