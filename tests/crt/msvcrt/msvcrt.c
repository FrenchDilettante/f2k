/*
 * msvcrt - msvcrt.dll exports under /MD that no other crt fixture's
 * subject takes in: the floating-point functions ceil, floor, fabs and
 * modf, the compiler's _ftol, and the full paths _wfullpath and
 * _getdcwd make.
 *
 * Deterministic inputs only: doubles given by their bits where a sign
 * or a NaN matters, and paths printed only as relations (equal to
 * GetFullPathNameW's or GetCurrentDirectoryA's answer, ending with the
 * name given). Besides the functions under test, the program calls only
 * exports F2K's msvcrt already has (sprintf, strcmp, wcscmp, free,
 * _msize, errno, _controlfp) and kernel32's path calls. It creates no
 * file.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   math     ceil, floor and fabs over halves, signed zeros, values
 *            past 2^52, the infinities and NaNs (their bits, errno);
 *            modf's two parts over the same; _ftol (the compiler's
 *            double-to-integer conversion) to __int64 and long:
 *            truncation toward zero, the 32-bit and 64-bit limits,
 *            values beyond them, NaN, the control word kept
 *   paths    _wfullpath against GetFullPathNameW's answer: a relative
 *            name, dots, a drive-absolute path, a NULL buffer
 *            (allocated), a buffer too small, an empty path; _getdcwd
 *            for drive 0 and the current drive against
 *            GetCurrentDirectoryA, a NULL buffer, a buffer too small, an
 *            invalid drive number
 *
 * fabs has an intrinsic form: `#pragma function(fabs)` below makes cl
 * call msvcrt's. The program is built without /O, and each conversion
 * to an integer reads a volatile double, so _ftol stays a call.
 *
 * The program's name is the DLL's: the loader tells the two apart by
 * their full names (msvcrt.exe imports MSVCRT.dll), on Windows 2000 as
 * on F2K.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat msvcrt):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% msvcrt.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <malloc.h>
#include <errno.h>
#include <math.h>
#include <float.h>
#include <wchar.h>
#include <direct.h>

#pragma function(fabs)

/* A wide string as printed, to its terminator: ws()'s form, with CR
   and LF escaped so a line stays one line. */
static const char *wesc(const WCHAR *s)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int len = 0;
    int i;

    if (s == NULL) {
        return "(null)";
    }
    for (i = 0; s[i] != 0 && len < (int)sizeof bufs[0] - 10; i++) {
        if (s[i] == '\r') {
            len += sprintf(b + len, "\\r");
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

/* --- math ---------------------------------------------------------- */

typedef union {
    double d;
    unsigned long w[2];
} bits_t;

/* A double from its bits. */
static double from_bits(unsigned long high, unsigned long low)
{
    bits_t b;

    b.w[0] = low;
    b.w[1] = high;
    return b.d;
}

/* A double as printed: %g, then its bits. */
static const char *dbl(double d)
{
    static char bufs[4][64];
    static int next;
    char *b = bufs[next++ & 3];
    bits_t u;

    u.d = d;
    sprintf(b, "%g [%08lX%08lX]", d, u.w[1], u.w[0]);
    return b;
}

#define VALUE_COUNT 18

/* The values the rounding functions run over. */
static void values(double *v)
{
    v[0] = 2.5;
    v[1] = -2.5;
    v[2] = 2.0;
    v[3] = -2.0;
    v[4] = 0.5;
    v[5] = -0.5;
    v[6] = 0.2;
    v[7] = -0.2;
    v[8] = 0.0;
    v[9] = from_bits(0x80000000ul, 0);      /* -0.0 */
    v[10] = 4503599627370495.5;             /* 2^52 - 0.5 */
    v[11] = -4503599627370495.5;
    v[12] = 1e300;
    v[13] = -1e-300;
    v[14] = from_bits(0x7FF00000ul, 0);     /* +inf */
    v[15] = from_bits(0xFFF00000ul, 0);     /* -inf */
    v[16] = from_bits(0x7FF80000ul, 0);     /* a quiet NaN */
    v[17] = from_bits(0xFFF80000ul, 0);     /* the indefinite NaN */
}

/* (__int64)d and (long)d, each through _ftol, and whether the control
   word survives them. */
static void show_ftol(double d)
{
    volatile double v = d;
    __int64 q;
    long l;
    unsigned int before;
    unsigned int after;

    before = _controlfp(0, 0);
    q = (__int64)v;
    l = (long)v;
    after = _controlfp(0, 0);
    line("_ftol(%s): __int64 %I64d, long %ld, control word kept %s", dbl(d), q, l,
         yesno(before == after));
}

static void sec_math(void)
{
    double v[VALUE_COUNT];
    double c;
    double f;
    double a;
    double frac;
    double whole;
    int ce;
    int fe;
    int me;
    int i;

    values(v);
    for (i = 0; i < VALUE_COUNT; i++) {
        errno = 0;
        c = ceil(v[i]);
        ce = errno;
        errno = 0;
        f = floor(v[i]);
        fe = errno;
        a = fabs(v[i]);
        line("%s: ceil %s errno %d, floor %s errno %d, fabs %s", dbl(v[i]), dbl(c), ce, dbl(f),
             fe, dbl(a));
    }
    for (i = 0; i < VALUE_COUNT; i++) {
        errno = 0;
        whole = from_bits(0x12345678ul, 0x9ABCDEF0ul);
        frac = modf(v[i], &whole);
        me = errno;
        line("modf(%s): %s, integer part %s, errno %d", dbl(v[i]), dbl(frac), dbl(whole), me);
    }

    show_ftol(2.7);
    show_ftol(-2.7);
    show_ftol(3.5);
    show_ftol(-3.5);
    show_ftol(0.999);
    show_ftol(-0.999);
    show_ftol(0.0);
    show_ftol(from_bits(0x80000000ul, 0));
    show_ftol(2147483647.0);
    show_ftol(-2147483648.0);
    show_ftol(3000000000.0);
    show_ftol(1e10);
    show_ftol(-1e10);
    show_ftol(9.2e18);
    show_ftol(1e19);
    show_ftol(-1e19);
    show_ftol(from_bits(0x7FF00000ul, 0));
    show_ftol(from_bits(0x7FF80000ul, 0));
}

/* --- paths --------------------------------------------------------- */

/* Whether `s` ends with `tail`. */
static int ends_with(const WCHAR *s, const WCHAR *tail)
{
    int n = 0;
    int m = 0;

    while (s[n] != 0) {
        n++;
    }
    while (tail[m] != 0) {
        m++;
    }
    return n >= m && wcscmp(s + n - m, tail) == 0;
}

/* _wfullpath(buffer, rel, size) against GetFullPathNameW(rel). */
static void show_wfullpath(const char *what, const WCHAR *rel, int with_buffer, size_t size)
{
    WCHAR buf[MAX_PATH];
    WCHAR full[MAX_PATH];
    WCHAR *part;
    WCHAR *r;
    int e;

    full[0] = 0;
    GetFullPathNameW(rel, MAX_PATH, full, &part);
    errno = 0;
    r = _wfullpath(with_buffer ? buf : NULL, rel, size);
    e = errno;
    if (r == NULL) {
        line("_wfullpath(%s, %u): NULL errno %d", what, (unsigned)size, e);
        return;
    }
    line("_wfullpath(%s, %u): the buffer %s, GetFullPathNameW's answer %s, ends with \"%s\" %s",
         what, (unsigned)size, with_buffer ? yesno(r == buf) : "allocated",
         yesno(wcscmp(r, full) == 0), wesc(rel), yesno(ends_with(r, rel)));
    if (!with_buffer) {
        free(r);
    }
}

/* _getdcwd(drive, buffer, size) against GetCurrentDirectoryA. */
static void show_getdcwd(const char *what, int drive, int with_buffer, int size)
{
    char buf[MAX_PATH];
    char cwd[MAX_PATH];
    char *r;
    int e;

    GetCurrentDirectoryA(MAX_PATH, cwd);
    errno = 0;
    r = _getdcwd(drive, with_buffer ? buf : NULL, size);
    e = errno;
    if (r == NULL) {
        line("_getdcwd(%s, %d): NULL errno %d", what, size, e);
        return;
    }
    if (with_buffer) {
        line("_getdcwd(%s, %d): the buffer %s, GetCurrentDirectoryA's answer %s", what, size,
             yesno(r == buf), yesno(strcmp(r, cwd) == 0));
    } else {
        line("_getdcwd(%s, %d): allocated, GetCurrentDirectoryA's answer %s, _msize at least %d %s",
             what, size, yesno(strcmp(r, cwd) == 0), size, yesno((int)_msize(r) >= size));
        free(r);
    }
}

static void sec_paths(void)
{
    char cwd[MAX_PATH];
    int drive;
    WCHAR *r;

    show_wfullpath("\"fullpath.tmp\"", L"fullpath.tmp", 1, MAX_PATH);
    show_wfullpath("\"..\\\\x\\\\.\\\\y.txt\"", L"..\\x\\.\\y.txt", 1, MAX_PATH);
    show_wfullpath("\"sub/dir/../f.c\"", L"sub/dir/../f.c", 1, MAX_PATH);
    show_wfullpath("NULL buffer", L"fullpath.tmp", 0, 0);
    show_wfullpath("NULL buffer, size 3", L"fullpath.tmp", 0, 3);
    show_wfullpath("a buffer of 3", L"fullpath.tmp", 1, 3);
    show_wfullpath("\"\"", L"", 1, MAX_PATH);

    r = _wfullpath(NULL, L"C:\\a\\b\\..\\c\\.\\d", MAX_PATH);
    line("_wfullpath(\"C:\\\\a\\\\b\\\\..\\\\c\\\\.\\\\d\"): [%s]", wesc(r));
    free(r);
    r = _wfullpath(NULL, L"C:\\a\\..\\..\\b\\", MAX_PATH);
    line("_wfullpath(\"C:\\\\a\\\\..\\\\..\\\\b\\\\\"): [%s]", wesc(r));
    free(r);

    GetCurrentDirectoryA(MAX_PATH, cwd);
    drive = (cwd[0] >= 'a' ? cwd[0] - 'a' : cwd[0] - 'A') + 1;
    show_getdcwd("0", 0, 1, MAX_PATH);
    show_getdcwd("the current drive", drive, 1, MAX_PATH);
    show_getdcwd("0, NULL buffer", 0, 0, 0);
    show_getdcwd("0, NULL buffer", 0, 0, 1000);
    show_getdcwd("0, a buffer of 2", 0, 1, 2);
    show_getdcwd("0, NULL buffer of 2", 0, 0, 2);
    show_getdcwd("27", 27, 1, MAX_PATH);
}

static const section_t sections[] = {
    { "math", sec_math, F2KT_ALWAYS },
    { "paths", sec_paths, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("msvcrt", sections, argc, argv);
}
