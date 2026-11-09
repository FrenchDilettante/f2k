/*
 * strings - msvcrt.dll's number conversions, searches, path splitting
 * and wide formatting under /MD: _itow and its kin, _wtoi and atol,
 * abs and labs, strstr, wcspbrk and wcscspn, _wcsdup, _wcsrev,
 * _strcmpi, strncat and _strdup, _splitpath and _wsplitpath,
 * vswprintf, wprintf and fwprintf.
 *
 * Deterministic inputs only. Besides the functions under test, the
 * program calls only exports F2K's msvcrt already has (sprintf,
 * strcpy, strcmp, wcscpy, wcscmp, free, errno, fopen, fclose, fflush,
 * _open, _read and _close) and kernel32's DeleteFileA: every other
 * import is one more export the fixture needs before it loads. So the
 * narrow and wide twins are called only where both are under test.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   itow     _itow, _ltow and _ultow in radix 2, 8, 10, 16 and 36 over
 *            0, 1, -1, 255, INT_MIN, INT_MAX and ULONG_MAX (radix 2
 *            only below 65536); whether each returns the buffer
 *   atoi     _wtoi and atol over the same inputs: blanks and tabs,
 *            signs, trailing junk, an empty string, digits after junk,
 *            values beyond LONG_MAX and LONG_MIN, with errno
 *   abs      abs and labs over 0, 5, -5, INT_MIN and INT_MAX
 *   search   strstr, wcspbrk and wcscspn: found, not found, empty
 *            needles, sets and strings, matches at either end
 *   dupcase  _wcsdup (contents, a distinct block), _wcsrev (odd, even
 *            and empty lengths, the return), _strcmpi's sign (case,
 *            prefixes, Latin-1 bytes, letters against '_' and '[')
 *   catdup   strncat appending at most `count` characters and a NUL
 *            (the bytes after it untouched), counts of 0 and past the
 *            source, empty strings; _strdup's copy (equal, a distinct
 *            block)
 *   split    _splitpath and _wsplitpath over drive, UNC, relative,
 *            dotted and forward-slash paths, and NULL components
 *   wformat  vswprintf (MSVC 6's, without a count); wprintf and
 *            fwprintf to stdout; fwprintf into a file opened "w" and
 *            "wb": "\n" translation, U+00E9 and U+03B1 in the "C"
 *            locale, the bytes read back with _open and _read
 *
 * abs and labs are compiler intrinsics: `#pragma function(abs, labs)`
 * below makes cl call msvcrt's, and the program is built without /O,
 * so they stay calls.
 *
 * wprintf and fwprintf(stdout) write through the C runtime's stream
 * buffer, while line() writes with WriteFile: each is followed by
 * fflush(stdout) to keep the output in order.
 *
 * The wformat section writes strings.tmp in the current directory (the
 * fixture's own), deleting it at its start and its end.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat strings):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% strings.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <wchar.h>
#include <limits.h>
#include <io.h>
#include <fcntl.h>

#pragma function(abs, labs)

#define TEMP_FILE "strings.tmp"

/* --- helpers ------------------------------------------------------- */

/* A narrow string as printed: printable ASCII as itself, tab and
 * newline escaped, any other byte as \xHH. Rotates through eight
 * buffers. */
static const char *qa(const char *s)
{
    static char bufs[8][256];
    static int next;
    char *b = bufs[next++ & 7];
    int len = 0;
    int i;

    if (s == NULL) {
        return "NULL";
    }
    for (i = 0; s[i] != 0 && len < (int)sizeof bufs[0] - 8; i++) {
        if (s[i] == '\t') {
            len += sprintf(b + len, "\\t");
        } else if (s[i] == '\n') {
            len += sprintf(b + len, "\\n");
        } else if (s[i] >= 0x20 && s[i] < 0x7F) {
            b[len++] = s[i];
        } else {
            len += sprintf(b + len, "\\x%02X", (unsigned)(unsigned char)s[i]);
        }
    }
    b[len] = 0;
    return b;
}

/* A pointer into a narrow or a wide string as printed: its offset, or
 * NULL. Rotate through eight buffers: one line can carry several. */
static const char *off_a(const char *s, const char *p)
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

static const char *off_w(const WCHAR *s, const WCHAR *p)
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

/* A narrow ASCII string widened unit by unit into `to`. */
static void widen(WCHAR *to, const char *from)
{
    while ((*to++ = (WCHAR)(unsigned char)*from++) != 0) {
    }
}

static void fill_w(WCHAR *buf, int n, WCHAR c)
{
    int i;

    for (i = 0; i < n - 1; i++) {
        buf[i] = c;
    }
    buf[n - 1] = 0;
}

static int sign(int v)
{
    return v < 0 ? -1 : v > 0 ? 1 : 0;
}

/* `n` bytes as printed, NULs included: printable ASCII as itself, CR,
 * LF, NUL and the backslash escaped, any other byte as \xHH. Rotates
 * through four buffers. */
static const char *bytes_of(const char *s, int n)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int len = 0;
    int i;

    for (i = 0; i < n && len < (int)sizeof bufs[0] - 5; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\r') {
            len += sprintf(b + len, "\\r");
        } else if (c == '\n') {
            len += sprintf(b + len, "\\n");
        } else if (c == 0) {
            len += sprintf(b + len, "\\0");
        } else if (c == '\\') {
            len += sprintf(b + len, "\\\\");
        } else if (c >= 0x20 && c < 0x7F) {
            b[len++] = (char)c;
        } else {
            len += sprintf(b + len, "\\x%02X", c);
        }
    }
    b[len] = 0;
    return b;
}

static const WCHAR e_acute[] = { 0x00E9, 0 };
static const WCHAR alpha[] = { 0x03B1, 0 };

/* --- itow ---------------------------------------------------------- */

/* Windows 2000's _itow overruns an internal buffer on long radix-2
 * conversions (_itow(-1, buf, 2) faulted at 0x31313131 in the capture),
 * and _ltow and _ultow may share the flaw. So radix 2 converts only
 * values below 65536 (0, 1 and 255); for the others its slot prints
 * "skipped", and the other radixes still take every value. */

static const int radixes[] = { 2, 8, 10, 16, 36 };

/* Whether radix `radix` may convert a value: any radix but 2, and radix
 * 2 only for a value below 65536 (`short_enough`). */
static int converts(int radix, int short_enough)
{
    return radix != 2 || short_enough;
}

static void show_itow(int v)
{
    WCHAR buf[48];
    char out[512];
    int len;
    int same = 1;
    int i;
    WCHAR *r;

    len = sprintf(out, "_itow(%d):", v);
    for (i = 0; i < 5; i++) {
        if (!converts(radixes[i], v >= 0 && v < 65536)) {
            len += sprintf(out + len, " %d skipped", radixes[i]);
            continue;
        }
        fill_w(buf, 48, '#');
        r = _itow(v, buf, radixes[i]);
        same = same && r == buf;
        len += sprintf(out + len, " %d [%s]", radixes[i], ws(buf));
    }
    line("%s; returned the buffer %s", out, yesno(same));
}

static void show_ltow(long v)
{
    WCHAR buf[48];
    char out[512];
    int len;
    int same = 1;
    int i;
    WCHAR *r;

    len = sprintf(out, "_ltow(%ld):", v);
    for (i = 0; i < 5; i++) {
        if (!converts(radixes[i], v >= 0 && v < 65536L)) {
            len += sprintf(out + len, " %d skipped", radixes[i]);
            continue;
        }
        fill_w(buf, 48, '#');
        r = _ltow(v, buf, radixes[i]);
        same = same && r == buf;
        len += sprintf(out + len, " %d [%s]", radixes[i], ws(buf));
    }
    line("%s; returned the buffer %s", out, yesno(same));
}

static void show_ultow(unsigned long v)
{
    WCHAR buf[48];
    char out[512];
    int len;
    int same = 1;
    int i;
    WCHAR *r;

    len = sprintf(out, "_ultow(%lu):", v);
    for (i = 0; i < 5; i++) {
        if (!converts(radixes[i], v < 65536UL)) {
            len += sprintf(out + len, " %d skipped", radixes[i]);
            continue;
        }
        fill_w(buf, 48, '#');
        r = _ultow(v, buf, radixes[i]);
        same = same && r == buf;
        len += sprintf(out + len, " %d [%s]", radixes[i], ws(buf));
    }
    line("%s; returned the buffer %s", out, yesno(same));
}

/* The signed forms take 0, 1, -1, 255, INT_MIN and INT_MAX (ULONG_MAX
 * is -1 to them); _ultow takes INT_MIN's and -1's bits as 2147483648 and
 * ULONG_MAX. */
static void sec_itow(void)
{
    static const long values[] = { 0, 1, -1, 255, INT_MIN, INT_MAX };
    static const unsigned long uvalues[] = { 0, 1, 255, (unsigned long)INT_MIN, INT_MAX, ULONG_MAX };
    int i;

    for (i = 0; i < (int)(sizeof values / sizeof values[0]); i++) {
        show_itow((int)values[i]);
    }
    for (i = 0; i < (int)(sizeof values / sizeof values[0]); i++) {
        show_ltow(values[i]);
    }
    for (i = 0; i < (int)(sizeof uvalues / sizeof uvalues[0]); i++) {
        show_ultow(uvalues[i]);
    }
}

/* --- atoi ---------------------------------------------------------- */

static void sec_atoi(void)
{
    static const char *inputs[] = {
        "42", " \t 42", "\t-17", "+8", "-0", "123abc", "", "abc123", "  +-5", "- 5", "+",
        "2147483647", "2147483648", "-2147483648", "-2147483649", "99999999999", "-99999999999"
    };
    WCHAR w[64];
    int iv;
    long lv;
    int ie;
    int ae;
    int i;

    for (i = 0; i < (int)(sizeof inputs / sizeof inputs[0]); i++) {
        widen(w, inputs[i]);
        errno = 0;
        iv = _wtoi(w);
        ie = errno;
        errno = 0;
        lv = atol(inputs[i]);
        ae = errno;
        line("\"%s\": _wtoi %d errno %d, atol %ld errno %d", qa(inputs[i]), iv, ie, lv, ae);
    }
}

/* --- abs ----------------------------------------------------------- */

static void sec_abs(void)
{
    static const int values[] = { 0, 5, -5, INT_MIN, INT_MAX };
    int i;

    for (i = 0; i < (int)(sizeof values / sizeof values[0]); i++) {
        line("%d: abs %d, labs %ld", values[i], abs(values[i]), labs((long)values[i]));
    }
}

/* --- search -------------------------------------------------------- */

/* Each offset is taken against the very string searched: two equal
 * literals need not share storage. */
static void sec_search(void)
{
    static const char hay[] = "haystack";
    static const char empty[] = "";
    static const WCHAR s[] = L"abcdef";
    static const WCHAR wempty[] = L"";
    static const WCHAR latin[] = { 0x00E9, 0x03B1, 0 };

    line("strstr(\"haystack\"): \"st\" %s, \"stack\" %s, \"k\" %s, \"x\" %s, \"\" %s", off_a(hay, strstr(hay, "st")),
         off_a(hay, strstr(hay, "stack")), off_a(hay, strstr(hay, "k")), off_a(hay, strstr(hay, "x")),
         off_a(hay, strstr(hay, "")));
    line("strstr(\"haystack\"): \"haystack\" %s, \"haystacks\" %s, \"stacks\" %s",
         off_a(hay, strstr(hay, "haystack")), off_a(hay, strstr(hay, "haystacks")), off_a(hay, strstr(hay, "stacks")));
    line("strstr(\"\"): \"\" %s, \"a\" %s", off_a(empty, strstr(empty, "")), off_a(empty, strstr(empty, "a")));

    line("wcspbrk(\"abcdef\"): \"\" %s, \"xyz\" %s, \"a\" %s, \"f\" %s, \"zf\" %s, \"fa\" %s, \"dc\" %s",
         off_w(s, wcspbrk(s, L"")), off_w(s, wcspbrk(s, L"xyz")), off_w(s, wcspbrk(s, L"a")),
         off_w(s, wcspbrk(s, L"f")), off_w(s, wcspbrk(s, L"zf")), off_w(s, wcspbrk(s, L"fa")),
         off_w(s, wcspbrk(s, L"dc")));
    line("wcspbrk(\"\"): \"\" %s, \"a\" %s", off_w(wempty, wcspbrk(wempty, L"")),
         off_w(wempty, wcspbrk(wempty, L"a")));
    line("wcspbrk(U+00E9 U+03B1): U+03B1 %s, U+00E9 %s, \"e\" %s", off_w(latin, wcspbrk(latin, alpha)),
         off_w(latin, wcspbrk(latin, e_acute)), off_w(latin, wcspbrk(latin, L"e")));

    line("wcscspn(\"abcdef\"): \"\" %u, \"xyz\" %u, \"a\" %u, \"f\" %u, \"zf\" %u, \"fa\" %u, \"dc\" %u",
         (unsigned)wcscspn(s, L""), (unsigned)wcscspn(s, L"xyz"), (unsigned)wcscspn(s, L"a"),
         (unsigned)wcscspn(s, L"f"), (unsigned)wcscspn(s, L"zf"), (unsigned)wcscspn(s, L"fa"),
         (unsigned)wcscspn(s, L"dc"));
    line("wcscspn(\"\"): \"\" %u, \"a\" %u", (unsigned)wcscspn(wempty, L""), (unsigned)wcscspn(wempty, L"a"));
    line("wcscspn(U+00E9 U+03B1): U+03B1 %u, U+00E9 %u, \"e\" %u", (unsigned)wcscspn(latin, alpha),
         (unsigned)wcscspn(latin, e_acute), (unsigned)wcscspn(latin, L"e"));
}

/* --- dupcase ------------------------------------------------------- */

static void show_wcsdup(const char *what, const WCHAR *src)
{
    WCHAR *p;

    p = _wcsdup(src);
    if (p == NULL) {
        line("_wcsdup(%s): NULL", what);
        return;
    }
    line("_wcsdup(%s): [%s] equal %s, a distinct block %s", what, ws(p), yesno(wcscmp(p, src) == 0),
         yesno(p != src));
    free(p);
}

static void show_wcsrev(const char *what, const WCHAR *src)
{
    WCHAR buf[32];
    WCHAR *r;

    wcscpy(buf, src);
    r = _wcsrev(buf);
    line("_wcsrev(%s): [%s] returned the argument %s", what, ws(buf), yesno(r == buf));
}

static void show_strcmpi(const char *a, const char *b)
{
    line("_strcmpi(\"%s\", \"%s\"): %d", qa(a), qa(b), sign(_strcmpi(a, b)));
}

static void sec_dupcase(void)
{
    static const WCHAR mixed[] = { 'a', 0x00E9, 0x03B1, 'Z', 0 };
    static const WCHAR odd_mixed[] = { 'a', 0x03B1, 'b', 0 };

    show_wcsdup("\"duplicate me\"", L"duplicate me");
    show_wcsdup("a U+00E9 U+03B1 Z", mixed);
    show_wcsdup("\"\"", L"");

    show_wcsrev("\"abcde\"", L"abcde");
    show_wcsrev("\"abcd\"", L"abcd");
    show_wcsrev("\"\"", L"");
    show_wcsrev("\"x\"", L"x");
    show_wcsrev("a U+03B1 b", odd_mixed);

    show_strcmpi("abc", "abc");
    show_strcmpi("abc", "ABC");
    show_strcmpi("aBc", "AbC");
    show_strcmpi("abc", "abd");
    show_strcmpi("ABD", "abc");
    show_strcmpi("ab", "abc");
    show_strcmpi("abc", "ab");
    show_strcmpi("", "");
    show_strcmpi("", "a");
    show_strcmpi("\xE9", "\xC9");
    show_strcmpi("\xC9", "\xE9");
    show_strcmpi("\xE9", "e");
    show_strcmpi("a", "_");
    show_strcmpi("A", "_");
    show_strcmpi("_", "a");
    show_strcmpi("a", "[");
    show_strcmpi("A", "[");
    show_strcmpi("[", "a");
}

/* --- catdup -------------------------------------------------------- */

/* strncat(dest, src, count) into a 16-byte buffer of '#' holding dest:
 * every byte of the buffer afterwards. */
static void show_strncat(const char *dest, const char *src, unsigned count)
{
    char buf[16];
    char *r;
    int i;

    for (i = 0; i < (int)sizeof buf; i++) {
        buf[i] = '#';
    }
    strcpy(buf, dest);
    r = strncat(buf, src, count);
    line("strncat(\"%s\", \"%s\", %u): [%s] returns the buffer %s", dest, src, count,
         bytes_of(buf, sizeof buf), yesno(r == buf));
}

static void show_strdup(const char *what, const char *src)
{
    char *p = _strdup(src);

    if (p == NULL) {
        line("_strdup(%s): NULL", what);
        return;
    }
    line("_strdup(%s): [%s] equal %s, a distinct block %s", what, qa(p),
         yesno(strcmp(p, src) == 0), yesno(p != src));
    free(p);
}

static void sec_catdup(void)
{
    show_strncat("ab", "cdef", 2);
    show_strncat("ab", "cdef", 4);
    show_strncat("ab", "cdef", 9);
    show_strncat("ab", "cdef", 0);
    show_strncat("", "xyz", 2);
    show_strncat("ab", "", 3);
    show_strncat("", "", 1);

    show_strdup("\"duplicate me\"", "duplicate me");
    show_strdup("\"caf\\xE9\"", "caf\xE9");
    show_strdup("\"\"", "");
}

/* --- split --------------------------------------------------------- */

static const char *paths[] = {
    "C:\\dir\\sub\\file.ext", "\\\\server\\share\\dir\\file.txt", "file", "dir\\", "dir\\file.tar.gz",
    ".profile", "C:file", "c:/fwd/slash.x", ""
};

static void sec_split(void)
{
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    WCHAR wpath[128];
    WCHAR wdrive[_MAX_DRIVE];
    WCHAR wdir[_MAX_DIR];
    WCHAR wfname[_MAX_FNAME];
    WCHAR wext[_MAX_EXT];
    int i;

    for (i = 0; i < (int)(sizeof paths / sizeof paths[0]); i++) {
        strcpy(drive, "#");
        strcpy(dir, "#");
        strcpy(fname, "#");
        strcpy(ext, "#");
        _splitpath(paths[i], drive, dir, fname, ext);
        line("_splitpath(\"%s\"): [%s] [%s] [%s] [%s]", paths[i], drive, dir, fname, ext);
    }
    for (i = 0; i < (int)(sizeof paths / sizeof paths[0]); i++) {
        widen(wpath, paths[i]);
        widen(wdrive, "#");
        widen(wdir, "#");
        widen(wfname, "#");
        widen(wext, "#");
        _wsplitpath(wpath, wdrive, wdir, wfname, wext);
        line("_wsplitpath(\"%s\"): [%s] [%s] [%s] [%s]", paths[i], ws(wdrive), ws(wdir), ws(wfname), ws(wext));
    }

    strcpy(dir, "#");
    strcpy(ext, "#");
    _splitpath(paths[0], NULL, dir, NULL, ext);
    line("_splitpath(\"%s\", NULL, dir, NULL, ext): [%s] [%s]", paths[0], dir, ext);
    strcpy(drive, "#");
    strcpy(fname, "#");
    _splitpath(paths[0], drive, NULL, fname, NULL);
    line("_splitpath(\"%s\", drive, NULL, fname, NULL): [%s] [%s]", paths[0], drive, fname);
    _splitpath(paths[0], NULL, NULL, NULL, NULL);
    line("_splitpath(\"%s\", all NULL): returned", paths[0]);

    widen(wpath, paths[1]);
    widen(wdir, "#");
    widen(wext, "#");
    _wsplitpath(wpath, NULL, wdir, NULL, wext);
    line("_wsplitpath(\"%s\", NULL, dir, NULL, ext): [%s] [%s]", paths[1], ws(wdir), ws(wext));
    widen(wdrive, "#");
    widen(wfname, "#");
    _wsplitpath(wpath, wdrive, NULL, wfname, NULL);
    line("_wsplitpath(\"%s\", drive, NULL, fname, NULL): [%s] [%s]", paths[1], ws(wdrive), ws(wfname));
    _wsplitpath(wpath, NULL, NULL, NULL, NULL);
    line("_wsplitpath(\"%s\", all NULL): returned", paths[1]);
}

/* --- wformat ------------------------------------------------------- */

static int vsw(WCHAR *buf, const WCHAR *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vswprintf(buf, fmt, ap);
    va_end(ap);
    return n;
}

/* fwprintf(fmt, arg) into a fresh file opened with `mode`, then its raw
 * bytes as read back. */
static void to_file(const char *what, const char *mode, const WCHAR *fmt, const WCHAR *arg)
{
    FILE *f;
    unsigned char bytes[64];
    char hex[256];
    int len = 0;
    int n;
    int e;
    int fd;
    int got;
    int i;

    DeleteFileA(TEMP_FILE);
    f = fopen(TEMP_FILE, mode);
    if (f == NULL) {
        line("%s, \"%s\": fopen failed", what, mode);
        return;
    }
    errno = 0;
    n = fwprintf(f, fmt, arg);
    e = errno;
    fclose(f);

    fd = _open(TEMP_FILE, _O_RDONLY | _O_BINARY);
    if (fd == -1) {
        line("%s, \"%s\": fwprintf %d errno %d; _open failed", what, mode, n, e);
        return;
    }
    got = _read(fd, bytes, sizeof bytes);
    _close(fd);
    hex[0] = 0;
    for (i = 0; i < got; i++) {
        len += sprintf(hex + len, " %02X", (unsigned)bytes[i]);
    }
    line("%s, \"%s\": fwprintf %d errno %d; %d bytes:%s", what, mode, n, e, got, hex);
}

static void sec_wformat(void)
{
    static const WCHAR e_fmt[] = { '[', 0x00E9, ']', '\n', 0 };
    static const WCHAR alpha_fmt[] = { '[', 0x03B1, ']', '\n', 0 };
    static const char *modes[] = { "w", "wb" };
    WCHAR buf[128];
    int n;
    int i;

    DeleteFileA(TEMP_FILE);

    fill_w(buf, 128, '#');
    n = vsw(buf, L"%d|%u|%x|%5s|%-3c|%%", -7, 42u, 255, L"ab", L'z');
    line("vswprintf integers and padding: %d [%s]", n, ws(buf));
    fill_w(buf, 128, '#');
    n = vsw(buf, L"%s and %S and %hs", L"wide", "narrow", "short");
    line("vswprintf strings: %d [%s]", n, ws(buf));
    fill_w(buf, 128, '#');
    n = vsw(buf, L"%s|%c|%s", e_acute, 0x03B1, alpha);
    line("vswprintf non-ASCII: %d [%s]", n, ws(buf));
    fill_w(buf, 128, '#');
    n = vsw(buf, L"");
    line("vswprintf empty: %d [%s]", n, ws(buf));

    n = wprintf(L"wprintf: %d [%s] [%S]\n", 42, L"wide", "narrow");
    fflush(stdout);
    line("wprintf returned %d", n);
    n = wprintf(L"");
    fflush(stdout);
    line("wprintf(\"\") returned %d", n);
    n = fwprintf(stdout, L"fwprintf(stdout): %x [%s]\n", 255, L"wide");
    fflush(stdout);
    line("fwprintf(stdout) returned %d", n);

    for (i = 0; i < 2; i++) {
        to_file("\"a\\nb\\n\"", modes[i], L"a\nb\n", L"");
        to_file("U+00E9 in the format", modes[i], e_fmt, L"");
        to_file("U+00E9 through %s", modes[i], L"[%s]\n", e_acute);
        to_file("U+03B1 in the format", modes[i], alpha_fmt, L"");
        to_file("U+03B1 through %s", modes[i], L"[%s]\n", alpha);
    }

    line("DeleteFileA at the end: %s", yesno(DeleteFileA(TEMP_FILE)));
}

static const section_t sections[] = {
    { "itow", sec_itow, F2KT_ALWAYS },
    { "atoi", sec_atoi, F2KT_ALWAYS },
    { "abs", sec_abs, F2KT_ALWAYS },
    { "search", sec_search, F2KT_ALWAYS },
    { "dupcase", sec_dupcase, F2KT_ALWAYS },
    { "catdup", sec_catdup, F2KT_ALWAYS },
    { "split", sec_split, F2KT_ALWAYS },
    { "wformat", sec_wformat, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("strings", sections, argc, argv);
}
