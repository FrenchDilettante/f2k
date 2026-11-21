/*
 * msvcrt - msvcrt.dll exports under /MD that no other crt fixture's
 * subject takes in: the floating-point functions ceil, floor, fabs and
 * modf, the compiler's _ftol, the full paths _wfullpath and _getdcwd
 * make, _ismbblead under single-byte multibyte code pages, and the
 * corners of the formatted output and input engine.
 *
 * Deterministic inputs only: doubles given by their bits where a sign
 * or a NaN matters, and paths printed only as relations (equal to
 * GetFullPathNameW's or GetCurrentDirectoryA's answer, ending with the
 * name given). Besides the functions under test, the program calls only
 * exports F2K's msvcrt already has (sprintf, strcmp, wcscmp, free,
 * _msize, errno, _controlfp) and kernel32's path and code page calls.
 * It creates no file.
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
 *   mbblead  _ismbblead over every byte under the startup's multibyte
 *            code page and after _setmbcp(1252) (no lead byte; single
 *            bytes and values past 0xFF probed), 437, 850, _MB_CP_SBCS,
 *            a code page that does not exist, _MB_CP_OEM and _MB_CP_ANSI
 *            (_getmbcp against GetOEMCP and GetACP). No DBCS code page:
 *            which are installed is the machine's choice, and F2K
 *            carries no DBCS tables. The three are reached through
 *            GetProcAddress, so the program still loads where msvcrt.dll
 *            lacks them.
 *   printf   sprintf's corners as msvcrt 6 has them: "ll" and "L" on
 *            integers (beside "I64"), the infinities and NaNs through
 *            precisions, widths and flags, "+" and " " on %u, %#.0o
 *            of 0, %#p, a width on %c, unknown conversion letters
 *   scanf    swscanf's "%Ld" and "%lld" into an int with a guard word
 *            after it (does the store write past 32 bits?), sscanf's
 *            "%Ld" (through GetProcAddress), "%I64d" into an __int64
 *   snprintf _snprintf, _vsnprintf and _snwprintf with a count of 0
 *            (a NULL buffer too), the string's length exactly, and
 *            (size_t)-1: the return value and the buffer's first units
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

/* --- mbblead ------------------------------------------------------ */

/* _setmbcp's pseudo code pages, as MSVC 6's mbctype.h names them. */
#define MB_CP_SBCS 0
#define MB_CP_OEM -2
#define MB_CP_ANSI -3

/* _ismbblead, _setmbcp and _getmbcp are reached through GetProcAddress
   on msvcrt.dll (cdecl): the program loads where the DLL lacks them, its
   other sections intact. */
typedef int (__cdecl *ismbblead_fn)(unsigned int c);
typedef int (__cdecl *setmbcp_fn)(int cp);
typedef int (__cdecl *getmbcp_fn)(void);

static ismbblead_fn p_ismbblead;
static setmbcp_fn p_setmbcp;
static getmbcp_fn p_getmbcp;

/* The bytes _ismbblead takes as lead bytes under the current multibyte
   code page: how many, and the first and last. */
static void lead_bytes(const char *label)
{
    int count = 0;
    int first = -1;
    int last = -1;
    int c;

    for (c = 0; c < 256; c++) {
        if (p_ismbblead((unsigned int)c)) {
            count++;
            if (first < 0) {
                first = c;
            }
            last = c;
        }
    }
    if (count == 0) {
        line("  %s: _ismbblead takes no byte as a lead byte", label);
    } else {
        line("  %s: _ismbblead takes %d bytes as lead bytes, 0x%02X to 0x%02X", label, count, first, last);
    }
}

static void set_mbcp(const char *label, int cp)
{
    int r;
    int e;

    errno = 0;
    r = p_setmbcp(cp);
    e = errno;
    line("_setmbcp(%s): %d errno %d; _getmbcp() %d", label, r, e, p_getmbcp());
}

static void sec_mbblead(void)
{
    static const unsigned int probes[] = { 0x41, 0x80, 0x81, 0x9F, 0xA0, 0xE0, 0xE9, 0xFC, 0xFF, 0x181, 0xFFFFFF81u };
    int cp;
    int i;

    p_ismbblead = (ismbblead_fn)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "_ismbblead");
    p_setmbcp = (setmbcp_fn)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "_setmbcp");
    p_getmbcp = (getmbcp_fn)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "_getmbcp");
    line("msvcrt exports _ismbblead %s, _setmbcp %s, _getmbcp %s", yesno(p_ismbblead != NULL),
         yesno(p_setmbcp != NULL), yesno(p_getmbcp != NULL));
    if (p_ismbblead == NULL || p_setmbcp == NULL || p_getmbcp == NULL) {
        return;
    }
    cp = p_getmbcp();
    line("_getmbcp() at startup: is GetACP() %s, is 1252 %s", yesno(cp == (int)GetACP()), yesno(cp == 1252));
    lead_bytes("at startup");

    set_mbcp("1252", 1252);
    lead_bytes("1252");
    for (i = 0; i < (int)(sizeof probes / sizeof probes[0]); i++) {
        line("  _ismbblead(0x%X): %d", probes[i], p_ismbblead(probes[i]));
    }
    set_mbcp("437", 437);
    lead_bytes("437");
    set_mbcp("850", 850);
    lead_bytes("850");
    set_mbcp("_MB_CP_SBCS", MB_CP_SBCS);
    lead_bytes("_MB_CP_SBCS");
    line("  _ismbblead(0x81): %d", p_ismbblead(0x81));
    set_mbcp("12345, no such code page", 12345);
    lead_bytes("after 12345");
    errno = 0;
    i = p_setmbcp(MB_CP_OEM);
    line("_setmbcp(_MB_CP_OEM): %d errno %d; _getmbcp() is GetOEMCP() %s, is 437 %s", i, errno,
         yesno(p_getmbcp() == (int)GetOEMCP()), yesno(p_getmbcp() == 437));
    lead_bytes("_MB_CP_OEM");
    errno = 0;
    i = p_setmbcp(MB_CP_ANSI);
    line("_setmbcp(_MB_CP_ANSI): %d errno %d; _getmbcp() is GetACP() %s, is 1252 %s", i, errno,
         yesno(p_getmbcp() == (int)GetACP()), yesno(p_getmbcp() == 1252));
    lead_bytes("_MB_CP_ANSI");
}

/* --- printf, scanf, snprintf ---------------------------------------- */

/* `n` bytes as printed: printable ASCII as itself, NUL as \0, the rest
   as \xNN. */
static const char *besc(const char *s, int n)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int len = 0;
    int i;

    for (i = 0; i < n && len < (int)sizeof bufs[0] - 5; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == 0) {
            len += sprintf(b + len, "\\0");
        } else if (c >= 0x20 && c < 0x7F && c != '\\') {
            b[len++] = (char)c;
        } else {
            len += sprintf(b + len, "\\x%02X", c);
        }
    }
    b[len] = 0;
    return b;
}

/* One special double through the formats msvcrt rounds its digit
   string through. */
static void show_special(const char *what, double d)
{
    char b[512];
    int n;

    n = sprintf(b, "%f|%.0f|%.1f|%.2f|%.3f|%e|%.1e|%g|%.1g|%10.3f|%-10.1f|%+.1f|%#.0f|%010.2f|%E|%G",
                d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d);
    line("%s: %d [%s]", what, n, besc(b, n));
}

static void sec_printf(void)
{
    char b[256];
    __int64 v = 5;
    int n;

    /* msvcrt 6 has no "ll"; "L" sizes only floating point. Each call
       passes as many words as any reading of it takes. */
    n = sprintf(b, "%lld|%d", v, 7, 9);
    line("\"%%lld|%%d\" of (__int64)5, 7, 9: %d [%s]", n, besc(b, n));
    n = sprintf(b, "%Ld|%d", v, 7, 9);
    line("\"%%Ld|%%d\" of (__int64)5, 7, 9: %d [%s]", n, besc(b, n));
    n = sprintf(b, "%llx|%d", v, 7, 9);
    line("\"%%llx|%%d\" of (__int64)5, 7, 9: %d [%s]", n, besc(b, n));
    n = sprintf(b, "%I64d|%d", v, 7, 9);
    line("\"%%I64d|%%d\" of (__int64)5, 7, 9: %d [%s]", n, besc(b, n));

    show_special("+INF", from_bits(0x7FF00000, 0));
    show_special("-INF", from_bits(0xFFF00000, 0));
    show_special("QNAN", from_bits(0x7FF80000, 0));
    show_special("IND", from_bits(0xFFF80000, 0));
    show_special("SNAN", from_bits(0x7FF00000, 1));

    n = sprintf(b, "%+u|% u|%+d|% d", 5u, 5u, 5, 5);
    line("\"%%+u|%% u|%%+d|%% d\" of 5: %d [%s]", n, besc(b, n));
    n = sprintf(b, "%#.0o|%.0o|%#o|%#.0x|%#x", 0, 0, 8, 0, 0);
    line("\"%%#.0o|%%.0o|%%#o|%%#.0x|%%#x\" of 0, 0, 8, 0, 0: %d [%s]", n, besc(b, n));
    n = sprintf(b, "%p|%#p|%10p", (void *)0x1234, (void *)0x1234, (void *)0x1234);
    line("\"%%p|%%#p|%%10p\" of 0x1234: %d [%s]", n, besc(b, n));
    n = sprintf(b, "%5c|%-5c|%05c", 'x', 'x', 'x');
    line("\"%%5c|%%-5c|%%05c\" of 'x': %d [%s]", n, besc(b, n));
    n = sprintf(b, "a%yb|%d", 7, 8);
    line("\"a%%yb|%%d\" of 7, 8: %d [%s]", n, besc(b, n));
    n = sprintf(b, "[%5y][%-3k]", 7, 8);
    line("\"[%%5y][%%-3k]\" of 7, 8: %d [%s]", n, besc(b, n));
}

/* An int and the word after it, which a 32-bit store leaves alone. */
typedef struct {
    int value;
    unsigned long guard;
} guarded_t;

typedef int (__cdecl *sscanf_fn)(const char *s, const char *format, ...);

static void show_guarded(const char *what, int r, const guarded_t *g)
{
    line("%s: ret=%d value %d, the word after changed %s", what, r, g->value,
         yesno(g->guard != 0x5A5A5A5Aul));
}

static void sec_scanf(void)
{
    guarded_t g;
    __int64 q;
    sscanf_fn p_sscanf;
    int r;

    g.value = -1;
    g.guard = 0x5A5A5A5Aul;
    r = swscanf(L"5", L"%Ld", &g.value);
    show_guarded("swscanf(L\"5\", L\"%Ld\")", r, &g);
    g.value = -1;
    g.guard = 0x5A5A5A5Aul;
    r = swscanf(L"6", L"%lld", &g.value);
    show_guarded("swscanf(L\"6\", L\"%lld\")", r, &g);
    p_sscanf = (sscanf_fn)GetProcAddress(GetModuleHandleA("msvcrt.dll"), "sscanf");
    if (p_sscanf == NULL) {
        line("sscanf: no export");
    } else {
        g.value = -1;
        g.guard = 0x5A5A5A5Aul;
        r = p_sscanf("7", "%Ld", &g.value);
        show_guarded("sscanf(\"7\", \"%Ld\")", r, &g);
    }

    q = 0;
    r = swscanf(L"123456789012", L"%I64d", &q);
    line("swscanf(L\"123456789012\", L\"%%I64d\"): ret=%d [%08lX%08lX]", r,
         (unsigned long)(q >> 32), (unsigned long)(q & 0xFFFFFFFFul));
    q = 0;
    r = swscanf(L"-5", L"%I64d", &q);
    line("swscanf(L\"-5\", L\"%%I64d\"): ret=%d [%08lX%08lX]", r, (unsigned long)(q >> 32),
         (unsigned long)(q & 0xFFFFFFFFul));
}

/* _vsnprintf through its va_list. */
static int vsn(char *b, size_t count, const char *format, ...)
{
    va_list ap;
    int r;

    va_start(ap, format);
    r = _vsnprintf(b, count, format, ap);
    va_end(ap);
    return r;
}

static void fill(char *b)
{
    int i;

    for (i = 0; i < 8; i++) {
        b[i] = 'Z';
    }
}

static void wfill(WCHAR *b)
{
    int i;

    for (i = 0; i < 8; i++) {
        b[i] = L'Z';
    }
}

/* A wide buffer's first `n` units as printed: wesc's form, NUL as \0. */
static const char *wbuf(const WCHAR *s, int n)
{
    char b[8];
    int i;

    for (i = 0; i < n; i++) {
        b[i] = s[i] < 0x80 ? (char)s[i] : '?';
    }
    return besc(b, n);
}

static void sec_snprintf(void)
{
    char b[16];
    WCHAR w[16];
    int r;

    fill(b);
    r = _snprintf(b, 0, "abc");
    line("_snprintf(count 0, \"abc\"): ret=%d [%s]", r, besc(b, 5));
    fill(b);
    r = _snprintf(b, 0, "");
    line("_snprintf(count 0, \"\"): ret=%d [%s]", r, besc(b, 5));
    r = _snprintf(NULL, 0, "abc");
    line("_snprintf(NULL, count 0, \"abc\"): ret=%d", r);
    fill(b);
    r = _snprintf(b, 3, "abc");
    line("_snprintf(count 3, \"abc\"): ret=%d [%s]", r, besc(b, 5));

    fill(b);
    r = vsn(b, 0, "abc");
    line("_vsnprintf(count 0, \"abc\"): ret=%d [%s]", r, besc(b, 5));
    fill(b);
    r = vsn(b, 3, "abc");
    line("_vsnprintf(count 3, \"abc\"): ret=%d [%s]", r, besc(b, 5));

    wfill(w);
    r = _snwprintf(w, 0, L"abc");
    line("_snwprintf(count 0, L\"abc\"): ret=%d [%s]", r, wbuf(w, 5));
    wfill(w);
    r = _snwprintf(w, 3, L"abc");
    line("_snwprintf(count 3, L\"abc\"): ret=%d [%s]", r, wbuf(w, 5));

    /* A count past INT_MAX: msvcrt 6 takes the count as an int. */
    fill(b);
    r = _snprintf(b, (size_t)-1, "abc");
    line("_snprintf(count (size_t)-1, \"abc\"): ret=%d [%s]", r, besc(b, 5));
    fill(b);
    r = vsn(b, (size_t)-1, "abc");
    line("_vsnprintf(count (size_t)-1, \"abc\"): ret=%d [%s]", r, besc(b, 5));
    wfill(w);
    r = _snwprintf(w, (size_t)-1, L"abc");
    line("_snwprintf(count (size_t)-1, L\"abc\"): ret=%d [%s]", r, wbuf(w, 5));
}

static const section_t sections[] = {
    { "math", sec_math, F2KT_ALWAYS },
    { "paths", sec_paths, F2KT_ALWAYS },
    { "mbblead", sec_mbblead, F2KT_ALWAYS },
    { "printf", sec_printf, F2KT_ALWAYS },
    { "scanf", sec_scanf, F2KT_ALWAYS },
    { "snprintf", sec_snprintf, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("msvcrt", sections, argc, argv);
}
