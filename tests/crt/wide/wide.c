/*
 * wide - the breadth of msvcrt.dll cmd.exe calls under /MD: wide
 * strings, wide character classes, wide formatting and scanning,
 * number conversions, the heap, qsort, rand, time and setlocale; and
 * beside them iswctype, the class functions' common form, and the
 * broken-down times (gmtime, localtime, mktime, _tzset).
 *
 * Deterministic inputs only. The wide functions' narrow twins are not
 * called: cmd.exe imports the wide ones alone, and every other import
 * is one more export the fixture needs before it loads.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   wcs      wcslen, wcscpy, wcsncpy (padding, no terminator when full),
 *            wcscat, wcscmp, wcsncmp, wcschr, wcsrchr, wcsstr, wcsspn
 *   case     _wcsicmp, _wcsnicmp, _wcslwr and _wcsupr over ASCII, Latin-1
 *            and a few letters beyond, in the "C" locale and after
 *            setlocale(LC_ALL, "")
 *   ctype    iswalpha, iswdigit, iswspace, iswxdigit, towlower and
 *            towupper over a fixed set of code points (ASCII, Latin-1,
 *            Greek, Cyrillic, Arabic-Indic digits, the Unicode spaces,
 *            CJK, fullwidth forms), in the "C" locale and after
 *            setlocale(LC_ALL, "")
 *   wctype   iswctype over ASCII, Latin-1, Greek, Arabic-Indic and
 *            ideographic characters, U+2028 and WEOF, for each class
 *            mask and a mask of two classes, in the "C" locale
 *   locale   setlocale's answers: the startup's locale, "", "C", a name
 *            that does not exist, one category set alone
 *   format   swprintf (MSVC 6's, without a count): integer conversions,
 *            flags, widths and precisions, %s/%S/%hs/%ls and
 *            %c/%C/%hc/%lc, %%; _snwprintf and _vsnwprintf: truncation
 *            (-1, no terminator), an exact fit, a count of 0
 *   scan     swscanf: integers in several bases, %s and %S, %[...] and
 *            %[^...], widths, %n, the count on a matching failure and on
 *            input failure
 *   numbers  _ultoa in radix 2, 8, 10, 16 and 36; _wtol; wcstol and
 *            wcstoul: base 0's prefixes, signs and blanks, overflow
 *            (LONG_MAX, LONG_MIN, ULONG_MAX and errno ERANGE), no
 *            digits, the end pointer as an offset
 *   memory   malloc, calloc (zeroed), realloc (growing and shrinking
 *            keep the contents, a NULL pointer, size 0), free, a failing
 *            malloc, memmove over overlapping ranges both ways
 *   sort     qsort over integers and over wide strings (wcscmp)
 *   rand     rand's first values without srand, after srand(1) and
 *            after srand(42)
 *   time     time(NULL) against time(&t), and after 2000-01-01
 *   calendar gmtime of fixed values (the epoch, a leap day, 2^31-1, a
 *            negative time); localtime under TZ=PST8PDT around 2001's
 *            daylight saving changes, in 2007, at the epoch and at
 *            2^31-1; whether gmtime and localtime share one buffer;
 *            mktime normalizing out-of-range fields, filling tm_wday
 *            and tm_yday, its tm_isdst answers, and its bounds (local
 *            times on either side of 1970-01-01 00:00:00 and
 *            2038-01-19 03:14:07 UTC); localtime under TZ=EST5, GMT0,
 *            IST-5:30 and NST3:30NDT. The time zone is the one the section sets
 *            itself (TZ, through _putenv, then _tzset), never the
 *            machine's, and every time_t is a fixed value
 *   wcstok   tokens and the buffer wcstok leaves: blanks and runs of
 *            delimiters, an empty delimiter set, only delimiters, an
 *            empty string, delimiters changed between calls, delimiters
 *            outside ASCII; a second string started between calls; another
 *            thread tokenizing between two calls (each thread's own
 *            position)
 *   wcstod   the double's bits, the end pointer as an offset and errno:
 *            signs, blanks, exponents (e, E, d, D, incomplete), "." and
 *            "-" alone, the empty string, hex, inf and nan (not parsed),
 *            a comma (the "C" locale), 30 digits, overflow, underflow,
 *            the denormal and normal limits, digits outside ASCII and a
 *            no-break space; a NULL end pointer
 *   wcsftime every conversion (%a to %Z, %z, %%) and the # flag over
 *            fixed struct tm values under TZ=PST8PDT (the section sets it)
 *            in the "C" locale, plain text, an empty format; buffers that
 *            fit exactly, a unit short, of 1 and of 0
 *
 * wcstok, wcstod and wcsftime are reached through GetProcAddress on
 * msvcrt.dll, so the program still loads where the DLL lacks them.
 *
 * The character class functions are called as (iswalpha)(c): MSVC 6's
 * headers define them as macros over iswctype, and cmd.exe imports them
 * by their own names.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat wide):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wide.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <wchar.h>
#include <locale.h>
#include <limits.h>
#include <time.h>

/* --- helpers ------------------------------------------------------- */

/* `n` units of a wide buffer as printed: printable ASCII as itself, a
 * zero unit as \0, tab and newline escaped, any other as <U+XXXX>. With
 * a negative `n`, up to the terminator. */
static const char *wq(const WCHAR *s, int n)
{
    static char bufs[4][1024];
    static int next;
    char *b = bufs[next++ & 3];
    int len = 0;
    int i;

    if (s == NULL) {
        return "(null)";
    }
    for (i = 0; (n < 0 ? s[i] != 0 : i < n) && len < (int)sizeof bufs[0] - 10; i++) {
        if (s[i] == 0) {
            len += sprintf(b + len, "\\0");
        } else if (s[i] == '\t') {
            len += sprintf(b + len, "\\t");
        } else if (s[i] == '\n') {
            len += sprintf(b + len, "\\n");
        } else if (s[i] >= 0x20 && s[i] < 0x7F) {
            b[len++] = (char)s[i];
        } else {
            len += sprintf(b + len, "<U+%04X>", (unsigned)s[i]);
        }
    }
    b[len] = 0;
    return b;
}

/* A pointer into `s` as printed: its offset, or NULL. Rotates through
 * eight buffers: one line can carry six. */
static const char *offset(const WCHAR *s, const WCHAR *p)
{
    static char bufs[8][16];
    static int next;
    char *b = bufs[next++ & 7];

    if (p == NULL) {
        return "NULL";
    }
    sprintf(b, "+%d", (int)(p - s));
    return b;
}

static void fill_w(WCHAR *buf, int n, WCHAR c)
{
    int i;

    for (i = 0; i < n; i++) {
        buf[i] = c;
    }
}

static void copy_w(WCHAR *to, const WCHAR *from)
{
    while ((*to++ = *from++) != 0) {
    }
}

static const char *str_or_null(const char *s)
{
    return s != NULL ? s : "NULL";
}

/* Letters and signs in and beyond Latin-1: A b C, space, 1 [ _ and
 * U+00E9 U+00C9 U+00FF U+0101 U+0100 U+03B1 U+0391 U+0436 U+0416. */
static const WCHAR mixed[] = {
    'A', 'b', 'C', ' ', '1', '[', '_', 0x00E9, 0x00C9, 0x00FF, 0x0101, 0x0100,
    0x03B1, 0x0391, 0x0436, 0x0416, 0
};
static const WCHAR e_acute[] = { 0x00E9, 0 };
static const WCHAR e_acute_upper[] = { 0x00C9, 0 };
static const WCHAR alpha_lower[] = { 0x03B1, 0 };
static const WCHAR alpha_upper[] = { 0x0391, 0 };

/* --- wcs ----------------------------------------------------------- */

static void sec_wcs(void)
{
    static const WCHAR list[] = L"a,b,c";
    static const WCHAR hay[] = L"haystack";
    WCHAR buf[16];
    WCHAR *r;

    line("wcslen: \"\" %u, \"abc\" %u, U+00E9 %u, mixed %u", (unsigned)wcslen(L""), (unsigned)wcslen(L"abc"),
         (unsigned)wcslen(e_acute), (unsigned)wcslen(mixed));

    fill_w(buf, 16, '#');
    r = wcscpy(buf, L"hello");
    line("wcscpy: [%s] returned the destination %s", wq(buf, 8), yesno(r == buf));

    fill_w(buf, 16, '#');
    r = wcsncpy(buf, L"ab", 6);
    line("wcsncpy(\"ab\", 6): [%s] returned the destination %s", wq(buf, 8), yesno(r == buf));
    fill_w(buf, 16, '#');
    wcsncpy(buf, L"abcdef", 4);
    line("wcsncpy(\"abcdef\", 4): [%s]", wq(buf, 6));
    fill_w(buf, 16, '#');
    wcsncpy(buf, L"abcd", 4);
    line("wcsncpy(\"abcd\", 4): [%s]", wq(buf, 6));
    fill_w(buf, 16, '#');
    wcsncpy(buf, L"abc", 0);
    line("wcsncpy(\"abc\", 0): [%s]", wq(buf, 4));

    fill_w(buf, 16, '#');
    copy_w(buf, L"ab");
    r = wcscat(buf, L"cd");
    line("wcscat(\"ab\", \"cd\"): [%s] returned the destination %s", wq(buf, 6), yesno(r == buf));
    r = wcscat(buf, L"");
    line("wcscat(\"abcd\", \"\"): [%s]", wq(buf, 6));
    r = wcscat(buf, mixed + 7);
    line("wcscat(\"abcd\", non-ASCII): [%s]", wq(buf, -1));

    line("wcscmp: (abc, abd) %d, (abc, abc) %d, (abd, abc) %d, (ab, abc) %d, (abc, ab) %d, (\"\", \"\") %d",
         wcscmp(L"abc", L"abd"), wcscmp(L"abc", L"abc"), wcscmp(L"abd", L"abc"), wcscmp(L"ab", L"abc"),
         wcscmp(L"abc", L"ab"), wcscmp(L"", L""));
    line("wcscmp: (U+00E9, z) %d, (a, A) %d, (U+0391, U+03B1) %d", wcscmp(e_acute, L"z"), wcscmp(L"a", L"A"),
         wcscmp(alpha_upper, alpha_lower));
    line("wcsncmp: (abcd, abce, 3) %d, (abcd, abce, 4) %d, (ab, abc, 5) %d, (x, y, 0) %d",
         wcsncmp(L"abcd", L"abce", 3), wcsncmp(L"abcd", L"abce", 4), wcsncmp(L"ab", L"abc", 5),
         wcsncmp(L"x", L"y", 0));

    line("wcschr(\"a,b,c\"): ',' %s, 'c' %s, 'z' %s, 0 %s", offset(list, wcschr(list, ',')),
         offset(list, wcschr(list, 'c')), offset(list, wcschr(list, 'z')), offset(list, wcschr(list, 0)));
    line("wcsrchr(\"a,b,c\"): ',' %s, 'a' %s, 'z' %s, 0 %s", offset(list, wcsrchr(list, ',')),
         offset(list, wcsrchr(list, 'a')), offset(list, wcsrchr(list, 'z')), offset(list, wcsrchr(list, 0)));
    line("wcschr(mixed, U+0436) %s, wcsrchr(mixed, U+00E9) %s", offset(mixed, wcschr(mixed, 0x0436)),
         offset(mixed, wcsrchr(mixed, 0x00E9)));
    line("wcsstr(\"haystack\"): \"st\" %s, \"stack\" %s, \"k\" %s, \"\" %s, \"stacks\" %s, \"x\" %s",
         offset(hay, wcsstr(hay, L"st")), offset(hay, wcsstr(hay, L"stack")), offset(hay, wcsstr(hay, L"k")),
         offset(hay, wcsstr(hay, L"")), offset(hay, wcsstr(hay, L"stacks")), offset(hay, wcsstr(hay, L"x")));
    line("wcsspn: (aabbcx, ab) %u, (xyz, ab) %u, (\"\", a) %u, (abc, \"\") %u, (abc, cba) %u",
         (unsigned)wcsspn(L"aabbcx", L"ab"), (unsigned)wcsspn(L"xyz", L"ab"), (unsigned)wcsspn(L"", L"a"),
         (unsigned)wcsspn(L"abc", L""), (unsigned)wcsspn(L"abc", L"cba"));
}

/* --- case ---------------------------------------------------------- */

static void case_round(const char *label)
{
    WCHAR buf[32];
    WCHAR *r;

    line("%s: _wcsicmp: (abc, ABC) %d, (abc, ABD) %d, (abd, ABC) %d, (a, AB) %d, (\"\", \"\") %d", label,
         _wcsicmp(L"abc", L"ABC"), _wcsicmp(L"abc", L"ABD"), _wcsicmp(L"abd", L"ABC"), _wcsicmp(L"a", L"AB"),
         _wcsicmp(L"", L""));
    line("%s: _wcsicmp: ([, a) %d, (_, A) %d, (U+00E9, U+00C9) %d, (U+00E9, E) %d, (U+03B1, U+0391) %d", label,
         _wcsicmp(L"[", L"a"), _wcsicmp(L"_", L"A"), _wcsicmp(e_acute, e_acute_upper), _wcsicmp(e_acute, L"E"),
         _wcsicmp(alpha_lower, alpha_upper));
    line("%s: _wcsnicmp: (abcX, ABCy, 3) %d, (abcX, ABCy, 4) %d, (ab, AB, 10) %d, (a, b, 0) %d", label,
         _wcsnicmp(L"abcX", L"ABCy", 3), _wcsnicmp(L"abcX", L"ABCy", 4), _wcsnicmp(L"ab", L"AB", 10),
         _wcsnicmp(L"a", L"b", 0));
    copy_w(buf, mixed);
    r = _wcslwr(buf);
    line("%s: _wcslwr: [%s] returned the string %s", label, wq(buf, -1), yesno(r == buf));
    copy_w(buf, mixed);
    r = _wcsupr(buf);
    line("%s: _wcsupr: [%s] returned the string %s", label, wq(buf, -1), yesno(r == buf));
}

static void sec_case(void)
{
    case_round("\"C\"");
    line("setlocale(LC_ALL, \"\"): %s", str_or_null(setlocale(LC_ALL, "")));
    case_round("\"\"");
    setlocale(LC_ALL, "C");
}

/* --- ctype --------------------------------------------------------- */

static const WCHAR points[] = {
    0x0009, 0x000A, 0x0020, 0x0030, 0x0039, 0x0041, 0x0046, 0x0047, 0x005F, 0x0061, 0x0066,
    0x007A, 0x007F, 0x00A0, 0x00AA, 0x00B2, 0x00B5, 0x00C9, 0x00D7, 0x00DF, 0x00E9, 0x00FF,
    0x0100, 0x0101, 0x0178, 0x0391, 0x03B1, 0x0416, 0x0436, 0x0660, 0x0669, 0x2000, 0x2028,
    0x3000, 0x4E00, 0xFEFF, 0xFF10, 0xFF21, 0xFF41
};

static void ctype_round(const char *label)
{
    int i;
    WCHAR c;

    for (i = 0; i < (int)(sizeof points / sizeof points[0]); i++) {
        c = points[i];
        line("%s: U+%04X: alpha %X digit %X space %X xdigit %X lower U+%04X upper U+%04X", label, (unsigned)c,
             (iswalpha)(c), (iswdigit)(c), (iswspace)(c), (iswxdigit)(c), (unsigned)(towlower)(c),
             (unsigned)(towupper)(c));
    }
}

static void sec_ctype(void)
{
    ctype_round("\"C\"");
    line("setlocale(LC_ALL, \"\"): %s", str_or_null(setlocale(LC_ALL, "")));
    ctype_round("\"\"");
    setlocale(LC_ALL, "C");
}

/* --- wctype ------------------------------------------------------- */

static void sec_wctype(void)
{
    static const unsigned short chars[] = {
        'A', 'z', '5', 'f', 'G', ' ', '\t', '\n', '!', '_', 0x7F, 0xA0, 0xB2, 0xC0, 0xE9, 0xD7,
        0x391, 0x3B1, 0x660, 0x2028, 0x3000, 0x4E00, 0xFFFF
    };
    static const struct {
        const char *name;
        unsigned short mask;
    } masks[] = {
        { "_UPPER", _UPPER }, { "_LOWER", _LOWER }, { "_DIGIT", _DIGIT },
        { "_SPACE", _SPACE }, { "_PUNCT", _PUNCT }, { "_CONTROL", _CONTROL },
        { "_BLANK", _BLANK }, { "_HEX", _HEX }, { "_ALPHA", _ALPHA },
        { "_ALPHA|_DIGIT", _ALPHA | _DIGIT }, { "0", 0 }
    };
    char text[512];
    int len;
    int i;
    int j;

    for (i = 0; i < (int)(sizeof chars / sizeof chars[0]); i++) {
        len = sprintf(text, "U+%04X:", (unsigned)chars[i]);
        for (j = 0; j < (int)(sizeof masks / sizeof masks[0]); j++) {
            len += sprintf(text + len, " %s %X", masks[j].name,
                           (unsigned)iswctype(chars[i], masks[j].mask));
        }
        line("%s", text);
    }
}

/* --- locale -------------------------------------------------------- */

static void sec_locale(void)
{
    line("setlocale(LC_ALL, NULL): %s", str_or_null(setlocale(LC_ALL, NULL)));
    line("setlocale(LC_ALL, \"\"): %s", str_or_null(setlocale(LC_ALL, "")));
    line("setlocale(LC_CTYPE, NULL): %s", str_or_null(setlocale(LC_CTYPE, NULL)));
    line("setlocale(LC_ALL, \"C\"): %s", str_or_null(setlocale(LC_ALL, "C")));
    line("setlocale(LC_ALL, \"zz-not-a-locale\"): %s", str_or_null(setlocale(LC_ALL, "zz-not-a-locale")));
    line("then setlocale(LC_ALL, NULL): %s", str_or_null(setlocale(LC_ALL, NULL)));
    line("setlocale(LC_NUMERIC, \"\"): %s", str_or_null(setlocale(LC_NUMERIC, "")));
    line("then setlocale(LC_ALL, NULL): %s", str_or_null(setlocale(LC_ALL, NULL)));
    line("setlocale(LC_ALL, \"C\"): %s", str_or_null(setlocale(LC_ALL, "C")));
}

/* --- format -------------------------------------------------------- */

static int vformat(WCHAR *buf, size_t count, const WCHAR *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = _vsnwprintf(buf, count, fmt, ap);
    va_end(ap);
    return n;
}

static void sec_format(void)
{
    WCHAR buf[160];
    int n;

    n = swprintf(buf, L"%d|%u|%x|%X|%o|%i|%%", -42, 42u, 255, 255, 8, -7);
    line("swprintf integers: %d [%s]", n, wq(buf, -1));
    n = swprintf(buf, L"[%5d][%-5d][%05d][%+d][% d][%.3d][%5.3d][%*d][%#x][%#X][%#o][%lu][%hd]", 42, 42, 42, 42,
                 42, 7, 7, 4, 9, 255, 255, 8, 4294967295ul, 70000);
    line("swprintf flags and widths: %d [%s]", n, wq(buf, -1));
    n = swprintf(buf, L"%s|%S|%hs|%ls|%.2s|%5s|%-5s|%s", L"wide", "narrow", "narrow", L"wide", L"wide", L"ab",
                 L"ab", mixed + 7);
    line("swprintf strings: %d [%s]", n, wq(buf, -1));
    n = swprintf(buf, L"%c|%C|%hc|%lc|%c", L'a', 'b', 'c', L'd', 0x00E9);
    line("swprintf characters: %d [%s]", n, wq(buf, -1));
    n = swprintf(buf, L"%S|%hs", "caf\xE9", "\xE9t\xE9");
    line("swprintf narrow non-ASCII: %d [%s]", n, wq(buf, -1));
    n = swprintf(buf, L"");
    line("swprintf empty: %d [%s]", n, wq(buf, 1));

    fill_w(buf, 20, '#');
    n = _snwprintf(buf, 5, L"%s", L"overflowing");
    line("_snwprintf(5, \"overflowing\"): %d [%s]", n, wq(buf, 8));
    fill_w(buf, 20, '#');
    n = _snwprintf(buf, 5, L"%s", L"abcde");
    line("_snwprintf(5, \"abcde\"): %d [%s]", n, wq(buf, 8));
    fill_w(buf, 20, '#');
    n = _snwprintf(buf, 6, L"%s", L"abcde");
    line("_snwprintf(6, \"abcde\"): %d [%s]", n, wq(buf, 8));
    fill_w(buf, 20, '#');
    n = _snwprintf(buf, 0, L"abc");
    line("_snwprintf(0, \"abc\"): %d [%s]", n, wq(buf, 4));
    fill_w(buf, 20, '#');
    n = _snwprintf(buf, 10, L"%d-%d", 12, 345);
    line("_snwprintf(10, \"%%d-%%d\"): %d [%s]", n, wq(buf, 8));

    fill_w(buf, 20, '#');
    n = vformat(buf, 6, L"%d|%s", 1234, L"tail");
    line("_vsnwprintf(6, \"%%d|%%s\"): %d [%s]", n, wq(buf, 9));
    fill_w(buf, 20, '#');
    n = vformat(buf, 9, L"%d|%s", 1234, L"tail");
    line("_vsnwprintf(9, \"%%d|%%s\"): %d [%s]", n, wq(buf, 11));
    fill_w(buf, 20, '#');
    n = vformat(buf, 20, L"%d|%s", 1234, L"tail");
    line("_vsnwprintf(20, \"%%d|%%s\"): %d [%s]", n, wq(buf, 11));
}

/* --- scan ---------------------------------------------------------- */

static void sec_scan(void)
{
    WCHAR w1[32];
    WCHAR w2[32];
    char nb[32];
    int a, b, c;
    unsigned u;
    int n;

    fill_w(w1, 32, 0);
    fill_w(w2, 32, 0);
    a = b = -999;
    u = 0;
    nb[0] = 0;
    n = swscanf(L"42 -17 0x1F word rest", L"%d %d %x %s %S", &a, &b, &u, w1, nb);
    line("swscanf(\"%%d %%d %%x %%s %%S\"): %d: %d %d %u [%s] [%s]", n, a, b, u, wq(w1, -1), nb);

    fill_w(w1, 32, 0);
    fill_w(w2, 32, 0);
    a = -999;
    n = swscanf(L"abc123def", L"%[a-z]%d%s", w1, &a, w2);
    line("swscanf(\"%%[a-z]%%d%%s\"): %d: [%s] %d [%s]", n, wq(w1, -1), a, wq(w2, -1));

    fill_w(w1, 32, 0);
    fill_w(w2, 32, 0);
    n = swscanf(L"key=value with spaces", L"%[^=]=%[^\n]", w1, w2);
    line("swscanf(\"%%[^=]=%%[^\\n]\"): %d: [%s] [%s]", n, wq(w1, -1), wq(w2, -1));

    a = b = -999;
    n = swscanf(L"12345", L"%3d%d", &a, &b);
    line("swscanf(\"%%3d%%d\", \"12345\"): %d: %d %d", n, a, b);

    a = b = c = -999;
    n = swscanf(L"0x1A 077 -5", L"%i %i %i", &a, &b, &c);
    line("swscanf(\"%%i %%i %%i\", \"0x1A 077 -5\"): %d: %d %d %d", n, a, b, c);

    a = b = -999;
    n = swscanf(L"10 20", L"%d%n", &a, &b);
    line("swscanf(\"%%d%%n\", \"10 20\"): %d: %d %d", n, a, b);

    a = b = -999;
    n = swscanf(L"7 x", L"%d %d", &a, &b);
    line("swscanf(\"%%d %%d\", \"7 x\"): %d: %d %d", n, a, b);

    a = -999;
    n = swscanf(L"x", L"%d", &a);
    line("swscanf(\"%%d\", \"x\"): %d: %d", n, a);

    a = -999;
    n = swscanf(L"", L"%d", &a);
    line("swscanf(\"%%d\", \"\"): %d: %d", n, a);

    a = -999;
    n = swscanf(L"   ", L"%d", &a);
    line("swscanf(\"%%d\", \"   \"): %d: %d", n, a);

    a = -999;
    n = swscanf(L"abc", L"abd%d", &a);
    line("swscanf(\"abd%%d\", \"abc\"): %d: %d", n, a);
}

/* --- numbers ------------------------------------------------------- */

static void show_wcstol(const WCHAR *s, int base)
{
    WCHAR *end = NULL;
    long v;
    int e;

    errno = 0;
    v = wcstol(s, &end, base);
    e = errno;
    line("wcstol(\"%s\", %d): %ld errno %d end %s", wq(s, -1), base, v, e, offset(s, end));
}

static void show_wcstoul(const WCHAR *s, int base)
{
    WCHAR *end = NULL;
    unsigned long v;
    int e;

    errno = 0;
    v = wcstoul(s, &end, base);
    e = errno;
    line("wcstoul(\"%s\", %d): %lu errno %d end %s", wq(s, -1), base, v, e, offset(s, end));
}

static void show_wtol(const WCHAR *s)
{
    long v;
    int e;

    errno = 0;
    v = _wtol(s);
    e = errno;
    line("_wtol(\"%s\"): %ld errno %d", wq(s, -1), v, e);
}

static void sec_numbers(void)
{
    static const unsigned long values[] = { 0, 1, 255, 123456789, 2147483648ul, ULONG_MAX };
    static const WCHAR arabic_digits[] = { 0x0661, 0x0662, 0 };
    static const WCHAR fullwidth_digits[] = { 0xFF11, 0xFF12, 0 };
    char b2[40], b8[40], b10[40], b16[40], b36[40];
    char *r;
    int i;

    for (i = 0; i < (int)(sizeof values / sizeof values[0]); i++) {
        r = _ultoa(values[i], b2, 2);
        _ultoa(values[i], b8, 8);
        _ultoa(values[i], b10, 10);
        _ultoa(values[i], b16, 16);
        _ultoa(values[i], b36, 36);
        line("_ultoa(%lu): radix 2 %s, 8 %s, 10 %s, 16 %s, 36 %s; returned the buffer %s", values[i], b2, b8, b10,
             b16, b36, yesno(r == b2));
    }

    show_wtol(L"123");
    show_wtol(L"  -123abc");
    show_wtol(L"+7");
    show_wtol(L"\t\n 42");
    show_wtol(L"");
    show_wtol(L"abc");
    show_wtol(L"0x1A");
    show_wtol(L"2147483647");
    show_wtol(L"2147483648");
    show_wtol(L"-2147483649");
    show_wtol(arabic_digits);

    show_wcstol(L"0x1A", 0);
    show_wcstol(L"0X1a", 0);
    show_wcstol(L"  -077", 0);
    show_wcstol(L"0", 0);
    show_wcstol(L"08", 0);
    show_wcstol(L"12abc", 0);
    show_wcstol(L"+42", 10);
    show_wcstol(L"-0x10", 0);
    show_wcstol(L"0x", 0);
    show_wcstol(L"0x", 16);
    show_wcstol(L"0x1A", 16);
    show_wcstol(L"0x1A", 10);
    show_wcstol(L"zz", 36);
    show_wcstol(L"ZZ", 36);
    show_wcstol(L"1010", 2);
    show_wcstol(L"2147483647", 10);
    show_wcstol(L"2147483648", 10);
    show_wcstol(L"-2147483648", 10);
    show_wcstol(L"-2147483649", 10);
    show_wcstol(L"99999999999999999999x", 10);
    show_wcstol(L"   ", 10);
    show_wcstol(L"", 10);
    show_wcstol(L"abc", 10);
    show_wcstol(L"- 5", 10);
    show_wcstol(L"12", 37);
    show_wcstol(arabic_digits, 10);
    show_wcstol(fullwidth_digits, 10);

    show_wcstoul(L"4294967295", 10);
    show_wcstoul(L"4294967296", 10);
    show_wcstoul(L"-1", 10);
    show_wcstoul(L"-4294967296", 10);
    show_wcstoul(L"0xFFFFFFFF", 16);
    show_wcstoul(L"0x100000000", 0);
    show_wcstoul(L"  +12", 0);
    show_wcstoul(L"-0x10", 0);
    show_wcstoul(L"017", 0);
    show_wcstoul(L"0", 0);
    show_wcstoul(L"", 0);
    show_wcstoul(L"x", 0);
}

/* --- memory -------------------------------------------------------- */

static void sec_memory(void)
{
    char *p;
    char *q;
    char *blocks[1000];
    char buf[16];
    char *r;
    int i;
    int kept;
    int zero;
    int all;
    int e;

    p = (char *)malloc(16);
    line("malloc(16): %s", yesno(p != NULL));
    if (p == NULL) {
        return;
    }
    for (i = 0; i < 16; i++) {
        p[i] = (char)('a' + i);
    }
    q = (char *)realloc(p, 4096);
    kept = q != NULL;
    for (i = 0; kept && i < 16; i++) {
        kept = q[i] == (char)('a' + i);
    }
    line("realloc(16 to 4096): %s, contents kept %s", yesno(q != NULL), yesno(kept));
    if (q == NULL) {
        return;
    }
    q[4095] = 'z';
    p = (char *)realloc(q, 8);
    kept = p != NULL;
    for (i = 0; kept && i < 8; i++) {
        kept = p[i] == (char)('a' + i);
    }
    line("realloc(4096 to 8): %s, contents kept %s", yesno(p != NULL), yesno(kept));
    free(p);

    p = (char *)realloc(NULL, 32);
    line("realloc(NULL, 32): a block %s", yesno(p != NULL));
    q = (char *)realloc(p, 0);
    line("realloc(the block, 0): %s", q == NULL ? "NULL" : "a block");
    if (q != NULL) {
        free(q);
    }

    p = (char *)malloc(64);
    if (p != NULL) {
        for (i = 0; i < 64; i++) {
            p[i] = (char)0xAB;
        }
        free(p);
    }
    p = (char *)calloc(8, 8);
    zero = p != NULL;
    for (i = 0; zero && i < 64; i++) {
        zero = p[i] == 0;
    }
    line("calloc(8, 8): %s, all zero %s", yesno(p != NULL), yesno(zero));
    free(p);

    p = (char *)malloc(0);
    line("malloc(0): %s", p == NULL ? "NULL" : "a block");
    free(p);
    p = (char *)calloc(0, 4);
    line("calloc(0, 4): %s", p == NULL ? "NULL" : "a block");
    free(p);

    errno = 0;
    p = (char *)malloc(0x7FFFFFF0);
    e = errno;
    line("malloc(0x7FFFFFF0): %s errno %d", p == NULL ? "NULL" : "a block", e);
    free(p);

    free(NULL);
    line("free(NULL): returned");

    all = 1;
    for (i = 0; i < 1000; i++) {
        blocks[i] = (char *)malloc(100 + i);
        if (blocks[i] == NULL) {
            all = 0;
        } else {
            blocks[i][0] = (char)i;
            blocks[i][99 + i] = (char)i;
        }
    }
    for (i = 0; i < 1000; i++) {
        if (blocks[i] != NULL && (blocks[i][0] != (char)i || blocks[i][99 + i] != (char)i)) {
            all = 0;
        }
        free(blocks[i]);
    }
    line("1000 blocks of 100 to 1099 bytes: allocated and intact %s", yesno(all));

    for (i = 0; i < 10; i++) {
        buf[i] = (char)('0' + i);
    }
    buf[10] = 0;
    r = (char *)memmove(buf + 2, buf, 5);
    line("memmove(buf + 2, buf, 5): [%s] returned the destination %s", buf, yesno(r == buf + 2));
    for (i = 0; i < 10; i++) {
        buf[i] = (char)('0' + i);
    }
    r = (char *)memmove(buf, buf + 2, 5);
    line("memmove(buf, buf + 2, 5): [%s] returned the destination %s", buf, yesno(r == buf));
    r = (char *)memmove(buf + 3, buf + 3, 4);
    line("memmove(buf + 3, buf + 3, 4): [%s]", buf);
    r = (char *)memmove(buf, buf + 5, 0);
    line("memmove(buf, buf + 5, 0): [%s] returned the destination %s", buf, yesno(r == buf));
}

/* --- sort ---------------------------------------------------------- */

static int __cdecl cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    return x < y ? -1 : x > y ? 1 : 0;
}

static int __cdecl cmp_wide(const void *a, const void *b)
{
    return wcscmp(*(const WCHAR * const *)a, *(const WCHAR * const *)b);
}

static void sec_sort(void)
{
    int ints[12] = { 42, -7, 1000, 0, 13, -2147483647, 8, 99, 2147483647, 5, -1, 64 };
    const WCHAR *words[6];
    char out[256];
    int len = 0;
    int i;

    qsort(ints, 12, sizeof ints[0], cmp_int);
    for (i = 0; i < 12; i++) {
        len += sprintf(out + len, " %d", ints[i]);
    }
    line("qsort(12 integers):%s", out);

    qsort(ints, 1, sizeof ints[0], cmp_int);
    qsort(ints, 0, sizeof ints[0], cmp_int);
    line("qsort of one and of no element: returned, first %d", ints[0]);

    words[0] = L"pear";
    words[1] = L"Apple";
    words[2] = L"apple";
    words[3] = e_acute;
    words[4] = L"banana";
    words[5] = L"";
    qsort((void *)words, 6, sizeof words[0], cmp_wide);
    len = 0;
    for (i = 0; i < 6; i++) {
        len += sprintf(out + len, " [%s]", wq(words[i], -1));
    }
    line("qsort(6 wide strings, wcscmp):%s", out);
}

/* --- rand ---------------------------------------------------------- */

static void eight(const char *what)
{
    int v[8];
    int i;

    for (i = 0; i < 8; i++) {
        v[i] = rand();
    }
    line("%s: %d %d %d %d %d %d %d %d", what, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
}

static void sec_rand(void)
{
    eight("rand without srand");
    srand(1);
    eight("rand after srand(1)");
    srand(42);
    eight("rand after srand(42)");
    srand(1);
    eight("rand after srand(1) again");
    line("RAND_MAX: %d", RAND_MAX);
}

/* --- time ---------------------------------------------------------- */

static void sec_time(void)
{
    time_t t = 0;
    time_t a;
    time_t b;
    long d;

    a = time(NULL);
    b = time(&t);
    d = (long)(b - a);
    line("time(&t) returned t: %s", yesno(b == t));
    line("time(NULL) within a second of time(&t): %s", yesno(d >= 0 && d <= 1));
    line("after 2000-01-01 00:00:00 UTC: %s", yesno(a > (time_t)946684800L));
}

/* --- calendar ----------------------------------------------------- */

static void show_tm(const char *what, const struct tm *t)
{
    if (t == NULL) {
        line("%s: NULL", what);
        return;
    }
    line("%s: %04d-%02d-%02d %02d:%02d:%02d wday %d yday %d isdst %d", what, t->tm_year + 1900,
         t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, t->tm_wday, t->tm_yday,
         t->tm_isdst);
}

static void show_gmtime(long value)
{
    char what[64];
    time_t t = value;

    sprintf(what, "gmtime(%ld)", value);
    show_tm(what, gmtime(&t));
}

static void show_localtime(long value)
{
    char what[64];
    time_t t = value;

    sprintf(what, "localtime(%ld)", value);
    show_tm(what, localtime(&t));
}

/* mktime over the fields given (tm_year from 1900, tm_mon from 0), its
 * tm_wday and tm_yday set to -9 so their filling shows. */
static void show_mktime(const char *what, int year, int mon, int mday, int hour, int min, int sec,
                        int isdst)
{
    struct tm t;
    time_t r;
    char label[96];

    t.tm_year = year;
    t.tm_mon = mon;
    t.tm_mday = mday;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = sec;
    t.tm_isdst = isdst;
    t.tm_wday = -9;
    t.tm_yday = -9;
    r = mktime(&t);
    if (r == (time_t)-1) {
        line("mktime(%s): -1", what);
        return;
    }
    sprintf(label, "mktime(%s): %ld", what, (long)r);
    show_tm(label, &t);
}

static void set_zone(const char *setting)
{
    int r = _putenv(setting);

    _tzset();
    line("_putenv(\"%s\") %d, _tzset", setting, r);
}

static void sec_calendar(void)
{
    time_t t = 0;
    struct tm *g;
    struct tm *l;

    set_zone("TZ=PST8PDT");

    show_gmtime(0);
    show_gmtime(86399);
    show_gmtime(86400);
    show_gmtime(951782400);     /* 2000-02-29 00:00:00 */
    show_gmtime(978307199);     /* 2000-12-31 23:59:59 */
    show_gmtime(1004259600);    /* 2001-10-28 09:00:00 */
    show_gmtime(2147483647);
    show_gmtime(-1);

    show_localtime(0);
    show_localtime(28799);
    show_localtime(28800);
    show_localtime(986119199);  /* 2001-04-01 09:59:59 UTC */
    show_localtime(986119200);
    show_localtime(992606400);  /* 2001-06-15 12:00:00 UTC */
    show_localtime(1004255999); /* 2001-10-28 07:59:59 UTC */
    show_localtime(1004256000);
    show_localtime(1004259599);
    show_localtime(1004259600);
    show_localtime(1174392000); /* 2007-03-20 12:00:00 UTC */
    show_localtime(2147483647);
    show_localtime(-1);

    g = gmtime(&t);
    l = localtime(&t);
    line("gmtime and localtime share one buffer: %s", yesno(g == l));

    show_mktime("2001-06-15 12:00:00, isdst -1", 101, 5, 15, 12, 0, 0, -1);
    show_mktime("2001-06-15 12:00:00, isdst 0", 101, 5, 15, 12, 0, 0, 0);
    show_mktime("2001-06-15 12:00:00, isdst 1", 101, 5, 15, 12, 0, 0, 1);
    show_mktime("2001-01-15 12:00:00, isdst -1", 101, 0, 15, 12, 0, 0, -1);
    show_mktime("2001-01-15 12:00:00, isdst 1", 101, 0, 15, 12, 0, 0, 1);
    show_mktime("2001-02-31", 101, 1, 31, 0, 0, 0, -1);
    show_mktime("2001-03-00", 101, 2, 0, 0, 0, 0, -1);
    show_mktime("month -1 of 2001", 101, -1, 15, 0, 0, 0, -1);
    show_mktime("month 12 of 2001", 101, 12, 1, 0, 0, 0, -1);
    show_mktime("month -13 of 2001", 101, -13, 1, 0, 0, 0, -1);
    show_mktime("2001-01-01 second 90061", 101, 0, 1, 0, 0, 90061, -1);
    show_mktime("2001-01-01 minute -1", 101, 0, 1, 0, -1, 0, -1);
    show_mktime("2000-02-28 hour 48", 100, 1, 28, 48, 0, 0, -1);
    show_mktime("2001-01-01 day 366", 101, 0, 366, 0, 0, 0, -1);
    show_mktime("2001-04-01 02:30:00, isdst -1", 101, 3, 1, 2, 30, 0, -1);
    show_mktime("2001-10-28 01:30:00, isdst -1", 101, 9, 28, 1, 30, 0, -1);
    show_mktime("2001-10-28 01:30:00, isdst 1", 101, 9, 28, 1, 30, 0, 1);
    show_mktime("1970-01-01 00:00:00, isdst 0", 70, 0, 1, 0, 0, 0, 0);
    show_mktime("1969-12-31 23:59:59, isdst 0", 69, 11, 31, 23, 59, 59, 0);
    show_mktime("1970-01-00 23:59:59, isdst 0", 70, 0, 0, 23, 59, 59, 0);
    show_mktime("2038-01-18 19:14:07, isdst 0", 138, 0, 18, 19, 14, 7, 0);
    show_mktime("2038-01-18 19:14:08, isdst 0", 138, 0, 18, 19, 14, 8, 0);
    show_mktime("2039-01-01", 139, 0, 1, 0, 0, 0, -1);
    show_mktime("1900-01-01", 0, 0, 1, 0, 0, 0, -1);

    set_zone("TZ=EST5");
    show_localtime(992606400);
    show_mktime("2001-06-15 12:00:00, isdst -1", 101, 5, 15, 12, 0, 0, -1);
    set_zone("TZ=GMT0");
    show_localtime(0);
    show_mktime("1970-01-01 00:00:00, isdst -1", 70, 0, 1, 0, 0, 0, -1);
    set_zone("TZ=IST-5:30");
    show_localtime(0);
    show_localtime(992606400);
    show_mktime("1970-01-01 05:30:00, isdst 0", 70, 0, 1, 5, 30, 0, 0);
    show_mktime("1970-01-01 05:29:59, isdst 0", 70, 0, 1, 5, 29, 59, 0);
    set_zone("TZ=NST3:30NDT");
    show_localtime(992606400);
    show_localtime(978307199);
}

/* --- wcstok -------------------------------------------------------- */

/* wcstok, wcstod and wcsftime are reached through GetProcAddress on
 * msvcrt.dll (cdecl, as its headers declare them): the program loads
 * where the DLL lacks them, its other sections intact. */
typedef wchar_t *(__cdecl *wcstok_fn)(wchar_t *string, const wchar_t *delimiters);
typedef double (__cdecl *wcstod_fn)(const wchar_t *string, wchar_t **end);
typedef size_t (__cdecl *wcsftime_fn)(wchar_t *buffer, size_t size, const wchar_t *format, const struct tm *t);

static wcstok_fn p_wcstok;
static wcstod_fn p_wcstod;
static wcsftime_fn p_wcsftime;

/* An msvcrt.dll export's address, printed as found or not. */
static FARPROC crt_export(const char *name)
{
    FARPROC fp = GetProcAddress(GetModuleHandleA("msvcrt.dll"), name);

    line("msvcrt exports %s: %s", name, yesno(fp != NULL));
    return fp;
}

/* wcstok over a copy of `src`: each token as its offset into the copy
 * and its text, the delimiters `later` (NULL: the same) from the second
 * call on; then the copy as wcstok left it, every unit up to its old
 * terminator. */
static void show_tokens(const WCHAR *src, const WCHAR *delims, const WCHAR *later)
{
    WCHAR buf[64];
    WCHAR *t;
    int len = (int)wcslen(src);
    int n = 0;

    copy_w(buf, src);
    t = p_wcstok(buf, delims);
    line("wcstok(\"%s\", \"%s\"%s%s%s):", wq(src, -1), wq(delims, -1), later != NULL ? ", then \"" : "",
         later != NULL ? wq(later, -1) : "", later != NULL ? "\"" : "");
    while (t != NULL && n < 20) {
        line("  token %d at %s: \"%s\"", n, offset(buf, t), wq(t, -1));
        n++;
        t = p_wcstok(NULL, later != NULL ? later : delims);
    }
    line("  then NULL; the buffer after: \"%s\"", wq(buf, len));
}

static WCHAR thread_buf[32];
static const char *thread_tokens[4];
static char thread_text[4][32];

static DWORD WINAPI tokenizing_thread(LPVOID param)
{
    WCHAR *t;
    int n = 0;

    (void)param;
    copy_w(thread_buf, L"p q r");
    for (t = p_wcstok(thread_buf, L" "); t != NULL && n < 4; t = p_wcstok(NULL, L" ")) {
        sprintf(thread_text[n], "%s", wq(t, -1));
        thread_tokens[n] = thread_text[n];
        n++;
    }
    return (DWORD)n;
}

static void sec_wcstok(void)
{
    static const WCHAR odd_delims[] = { 0x00E9, 0x3000, 0 };
    static const WCHAR odd_text[] = { 'x', 0x00E9, 'y', 0x3000, 0x3000, 'z', 0x00E9, 0 };
    WCHAR one[32];
    WCHAR two[32];
    WCHAR *t;
    HANDLE h;
    DWORD count = 0;

    p_wcstok = (wcstok_fn)crt_export("wcstok");
    if (p_wcstok == NULL) {
        return;
    }
    show_tokens(L"  a,b;;c d,", L" ,;", NULL);
    show_tokens(L"abc", L"", NULL);
    show_tokens(L",,,", L",", NULL);
    show_tokens(L"", L",", NULL);
    show_tokens(L"a,b c,d e", L",", L" ");
    show_tokens(L"no delimiters here", L",;", NULL);
    show_tokens(odd_text, odd_delims, NULL);

    /* Two strings in turn: the second call starts over, NULL continues it. */
    copy_w(one, L"1 2 3");
    copy_w(two, L"x-y-z");
    t = p_wcstok(one, L" ");
    line("wcstok(\"1 2 3\", \" \"): \"%s\"", wq(t, -1));
    t = p_wcstok(two, L"-");
    line("wcstok(\"x-y-z\", \"-\"): \"%s\"", wq(t, -1));
    t = p_wcstok(NULL, L"-");
    line("wcstok(NULL, \"-\"): \"%s\" (the second string's)", t != NULL ? wq(t, -1) : "NULL");

    /* Each thread's own position: a thread tokenizes between two calls. */
    copy_w(one, L"m n o");
    t = p_wcstok(one, L" ");
    line("wcstok(\"m n o\", \" \"): \"%s\"", wq(t, -1));
    h = CreateThread(NULL, 0, tokenizing_thread, NULL, 0, NULL);
    if (h != NULL) {
        WaitForSingleObject(h, WAIT_MS);
        GetExitCodeThread(h, &count);
        CloseHandle(h);
    }
    line("another thread's wcstok over \"p q r\": %lu tokens, the first \"%s\", the last \"%s\"", count,
         count > 0 ? thread_tokens[0] : "-", count > 0 ? thread_tokens[count - 1] : "-");
    t = p_wcstok(NULL, L" ");
    line("then wcstok(NULL, \" \") in this thread: \"%s\"", t != NULL ? wq(t, -1) : "NULL");
}

/* --- wcstod -------------------------------------------------------- */

/* wcstod of `s`: the double's bits, the end pointer as an offset, errno;
 * the end pointer NULL too when `null_end`. */
static void show_wcstod(const WCHAR *s)
{
    WCHAR *end = NULL;
    double d;
    DWORD halves[2];
    int e;

    errno = 0;
    d = p_wcstod(s, &end);
    e = errno;
    memcpy(halves, &d, sizeof halves);
    line("wcstod(\"%s\"): bits 0x%08lX%08lX end %s errno %d", wq(s, -1), halves[1], halves[0], offset(s, end), e);
}

static void sec_wcstod(void)
{
    static const WCHAR fullwidth[] = { 0xFF11, '.', '5', 0 };
    static const WCHAR arabic[] = { 0x0661, 0 };
    static const WCHAR nbsp[] = { 0x00A0, '7', 0 };
    double d;
    DWORD halves[2];

    p_wcstod = (wcstod_fn)crt_export("wcstod");
    if (p_wcstod == NULL) {
        return;
    }
    show_wcstod(L"1.5");
    show_wcstod(L"  -2.5e3xyz");
    show_wcstod(L"+.5");
    show_wcstod(L"5.");
    show_wcstod(L".");
    show_wcstod(L"-");
    show_wcstod(L"");
    show_wcstod(L"   ");
    show_wcstod(L"\t\n 7");
    show_wcstod(L"1e");
    show_wcstod(L"1e+");
    show_wcstod(L"1e-2");
    show_wcstod(L"1E2");
    show_wcstod(L"1d2");
    show_wcstod(L"1D-2");
    show_wcstod(L"0.1");
    show_wcstod(L"-0");
    show_wcstod(L"0x1A");
    show_wcstod(L"inf");
    show_wcstod(L"nan");
    show_wcstod(L"1,5");
    show_wcstod(L"123456789012345678901234567890");
    show_wcstod(L"1e400");
    show_wcstod(L"-1e400");
    show_wcstod(L"1e-400");
    show_wcstod(L"4.9e-324");
    show_wcstod(L"2.2250738585072014e-308");
    show_wcstod(L"1.7976931348623157e308");
    show_wcstod(L"1.7976931348623159e308");
    show_wcstod(fullwidth);
    show_wcstod(arabic);
    show_wcstod(nbsp);
    errno = 0;
    d = p_wcstod(L"6.25", NULL);
    memcpy(halves, &d, sizeof halves);
    line("wcstod(\"6.25\", NULL): bits 0x%08lX%08lX errno %d", halves[1], halves[0], errno);
}

/* --- wcsftime ------------------------------------------------------ */

static struct tm make_tm(int year, int mon, int mday, int hour, int min, int sec, int wday, int yday, int isdst)
{
    struct tm t;

    t.tm_year = year - 1900;
    t.tm_mon = mon - 1;
    t.tm_mday = mday;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = sec;
    t.tm_wday = wday;
    t.tm_yday = yday;
    t.tm_isdst = isdst;
    return t;
}

/* wcsftime into a buffer of `size` units (0xBEEF-filled): its count and
 * the text it says it wrote. */
static void show_wcsftime(const char *label, const WCHAR *format, const struct tm *t, size_t size)
{
    WCHAR buf[256];
    size_t r;

    fill_w(buf, 256, 0xBEEF);
    r = p_wcsftime(buf, size, format, t);
    if (r > 0) {
        line("wcsftime(\"%s\", %s, %u): %u \"%s\"", wq(format, -1), label, (unsigned)size, (unsigned)r,
             wq(buf, (int)r));
    } else {
        line("wcsftime(\"%s\", %s, %u): 0", wq(format, -1), label, (unsigned)size);
    }
}

static void sec_wcsftime(void)
{
    static const WCHAR *const formats[] = {
        L"%a %A %b %B",
        L"%c",
        L"%#c",
        L"%x",
        L"%#x",
        L"%X",
        L"%d %H %I %j %m %M %p %S",
        L"%U %w %W",
        L"%y %Y",
        L"%Z",
        L"%z",
        L"%%",
        L"%#d %#H %#I %#j %#m %#M %#S %#y %#U",
        L"plain text, no conversions",
        L"",
        NULL
    };
    struct tm t1 = make_tm(2001, 2, 3, 4, 5, 6, 6, 33, 0);
    struct tm t2 = make_tm(1999, 12, 31, 23, 59, 59, 5, 364, 0);
    struct tm t3 = make_tm(2000, 7, 4, 12, 0, 0, 2, 185, 1);
    struct tm t4 = make_tm(2000, 1, 1, 0, 30, 0, 6, 0, 0);
    int i;

    p_wcsftime = (wcsftime_fn)crt_export("wcsftime");
    if (p_wcsftime == NULL) {
        return;
    }
    set_zone("TZ=PST8PDT");
    line("setlocale(LC_ALL, NULL): %s", str_or_null(setlocale(LC_ALL, NULL)));
    for (i = 0; formats[i] != NULL; i++) {
        show_wcsftime("2001-02-03 04:05:06", formats[i], &t1, 256);
    }
    show_wcsftime("1999-12-31 23:59:59", L"%c %Z %j %U %W", &t2, 256);
    show_wcsftime("2000-07-04 12:00:00, isdst 1", L"%c %Z %j %U %W %p", &t3, 256);
    show_wcsftime("2000-01-01 00:30:00", L"%#c %I %p %U %W", &t4, 256);

    /* The buffer sizes: 8 characters need 9 units. */
    show_wcsftime("2001-02-03 04:05:06", L"%Y-%m-%d", &t1, 11);
    show_wcsftime("2001-02-03 04:05:06", L"%Y-%m-%d", &t1, 10);
    show_wcsftime("2001-02-03 04:05:06", L"%H:%M:%S", &t1, 9);
    show_wcsftime("2001-02-03 04:05:06", L"%H:%M:%S", &t1, 8);
    show_wcsftime("2001-02-03 04:05:06", L"%H:%M:%S", &t1, 1);
    show_wcsftime("2001-02-03 04:05:06", L"", &t1, 1);
    show_wcsftime("2001-02-03 04:05:06", L"%H", &t1, 0);
}

static const section_t sections[] = {
    { "wcs", sec_wcs, F2KT_ALWAYS },
    { "case", sec_case, F2KT_ALWAYS },
    { "ctype", sec_ctype, F2KT_ALWAYS },
    { "wctype", sec_wctype, F2KT_ALWAYS },
    { "locale", sec_locale, F2KT_ALWAYS },
    { "format", sec_format, F2KT_ALWAYS },
    { "scan", sec_scan, F2KT_ALWAYS },
    { "numbers", sec_numbers, F2KT_ALWAYS },
    { "memory", sec_memory, F2KT_ALWAYS },
    { "sort", sec_sort, F2KT_ALWAYS },
    { "rand", sec_rand, F2KT_ALWAYS },
    { "time", sec_time, F2KT_ALWAYS },
    { "calendar", sec_calendar, F2KT_ALWAYS },
    { "wcstok", sec_wcstok, F2KT_ALWAYS },
    { "wcstod", sec_wcstod, F2KT_ALWAYS },
    { "wcsftime", sec_wcsftime, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("wide", sections, argc, argv);
}
