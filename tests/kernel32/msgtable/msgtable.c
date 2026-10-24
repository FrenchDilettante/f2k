/*
 * msgtable - FormatMessageW and FormatMessageA over the program's own
 * message table, the way cmd.exe reads its messages
 * (FORMAT_MESSAGE_FROM_HMODULE, with inserts), and over strings
 * (FORMAT_MESSAGE_FROM_STRING), which cmd.exe formats too.
 *
 * The table comes from msgtable.mc, part of this fixture's source
 * though the source stamp covers only msgtable.c and f2kt.h: change
 * the .mc and rebuild. The ids are defined below, matching msgtable.mc,
 * so this file stands alone (mc's msgtable.h is a build intermediate).
 * The table's ids sit in two blocks, 0x100-0x10A and 0x200.
 *
 * Every result prints with its return value, its last error and its
 * text on one line, the text's first `ret` units with CR, LF, tab, NUL
 * and backslash as \r \n \t \0 \\ (the capture is line-based), any
 * other unit outside printable ASCII as <U+XXXX> (W) or \xHH (A). Each
 * FormatMessageW line is followed by its FormatMessageA twin on the
 * same inputs (the strings in the A call's width). No call passes
 * fewer arguments than its message's inserts read.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   lookup   a message by id from the NULL module and from
 *            GetModuleHandle(NULL), the second block, an id in the gap
 *            and one beyond both blocks, FROM_HMODULE|FROM_SYSTEM
 *            (falling back to system message 2; 0x102, in both tables;
 *            an id in neither), languages 0, 0x400, 0x409, 0x009, 0x809
 *            and 0x40C (which the table lacks)
 *   inserts  %1 string inserts (one used twice, one whose text holds
 *            % sequences), %1!d!-style numbers, !s! against !S!,
 *            %1!*.*s! (width and precision from the arguments), an
 *            insert before %0; through a va_list, then through
 *            FORMAT_MESSAGE_ARGUMENT_ARRAY
 *   ignore   FORMAT_MESSAGE_IGNORE_INSERTS: the inserts, escapes and
 *            %0 as it leaves them
 *   escapes  %% %n %r %. %! %t and percent-space, a message of only
 *            %0, a line ending in a blank, regular line breaks
 *   width    the FORMAT_MESSAGE_MAX_WIDTH_MASK byte: 0, small widths
 *            wrapping a long line (a word longer than the width), the
 *            mask itself (regular breaks dropped, hard ones kept), a
 *            width over inserted text
 *   buffers  the caller's buffer: an exact fit, one unit short, one
 *            unit, none (the return, the error, what the buffer holds,
 *            whether the units after it stay untouched);
 *            FORMAT_MESSAGE_ALLOCATE_BUFFER (its length, LocalSize,
 *            LocalFree) with nSize 0 and nSize as the least size; the
 *            empty message into both
 *   string   FORMAT_MESSAGE_FROM_STRING: the same inserts through a
 *            va_list and an array, the escapes and %0, CR LF in the
 *            string at width 0 and the mask, IGNORE_INSERTS, an empty
 *            string, a string of only an insert
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat msgtable),
 * the generated files deleted after the link:
 *   mc -U msgtable.mc   (msgtable.rc, msgtable.h, MSG00409.bin; -U
 *                       stores the texts in Unicode, as cmd.exe's are)
 *   rc msgtable.rc      (msgtable.res)
 *   cl /nologo /I .. msgtable.c msgtable.res
 */

#include "../common/f2kt.h"

/* The message ids, as msgtable.mc defines them. */
#define MSG_PLAIN    0x100
#define MSG_SHORT    0x101      /* "Short message.\r\n": 16 units */
#define MSG_INSERTS  0x102      /* also system message 258 */
#define MSG_NUMBERS  0x103
#define MSG_WIDTHS   0x104
#define MSG_STAR     0x105
#define MSG_ESCAPES  0x106
#define MSG_PROMPT   0x107
#define MSG_EMPTY    0x108
#define MSG_BLANK    0x109
#define MSG_LONG     0x10A
#define MSG_SECOND   0x200

/* Ids the table lacks: one in the gap between its blocks, one beyond
 * them with the customer bit set (no system message has it). */
#define MSG_GAP      0x150
#define MSG_BEYOND   0x20000999

/* A private flag for the helpers below: pass Arguments NULL. Cleared
 * before the call (FormatMessage's own flags stay below 0x4000). */
#define NO_ARGS 0x80000000u

#define FROM_MODULE (FORMAT_MESSAGE_FROM_HMODULE | NO_ARGS)

static WCHAR wbuf[1024];
static char abuf[1024];
#define WN (sizeof wbuf / sizeof wbuf[0])
#define AN (sizeof abuf)

/* The last error the helpers' call left. */
static DWORD g_err;

/* FormatMessageW with the arguments after `size`: none (NO_ARGS: NULL),
 * a DWORD array (FORMAT_MESSAGE_ARGUMENT_ARRAY: the one argument), or
 * the rest as the va_list. */
static DWORD fmw(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPWSTR buf, DWORD size, ...)
{
    va_list ap;
    va_list *args;
    DWORD n;

    va_start(ap, size);
    if (flags & NO_ARGS) {
        args = NULL;
    } else if (flags & FORMAT_MESSAGE_ARGUMENT_ARRAY) {
        args = (va_list *)va_arg(ap, DWORD *);
    } else {
        args = &ap;
    }
    arm();
    n = FormatMessageW(flags & ~NO_ARGS, source, id, lang, buf, size, args);
    g_err = GetLastError();
    va_end(ap);
    return n;
}

/* The same through FormatMessageA. */
static DWORD fma(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPSTR buf, DWORD size, ...)
{
    va_list ap;
    va_list *args;
    DWORD n;

    va_start(ap, size);
    if (flags & NO_ARGS) {
        args = NULL;
    } else if (flags & FORMAT_MESSAGE_ARGUMENT_ARRAY) {
        args = (va_list *)va_arg(ap, DWORD *);
    } else {
        args = &ap;
    }
    arm();
    n = FormatMessageA(flags & ~NO_ARGS, source, id, lang, buf, size, args);
    g_err = GetLastError();
    va_end(ap);
    return n;
}

/* A wide text's first `count` units as printed (see the header). */
static const char *vis_w(const WCHAR *s, DWORD count)
{
    static char bufs[2][900];
    static int next;
    char *b = bufs[next++ & 1];
    int n = 0;
    DWORD i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 10; i++) {
        WCHAR c = s[i];

        if (c == L'\r') {
            b[n++] = '\\';
            b[n++] = 'r';
        } else if (c == L'\n') {
            b[n++] = '\\';
            b[n++] = 'n';
        } else if (c == L'\t') {
            b[n++] = '\\';
            b[n++] = 't';
        } else if (c == 0) {
            b[n++] = '\\';
            b[n++] = '0';
        } else if (c == L'\\') {
            b[n++] = '\\';
            b[n++] = '\\';
        } else if (c >= 0x20 && c < 0x7F) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

/* The same, of an ANSI text's first `count` bytes. */
static const char *vis_a(const char *s, DWORD count)
{
    static char bufs[2][900];
    static int next;
    char *b = bufs[next++ & 1];
    int n = 0;
    DWORD i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 10; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\r') {
            b[n++] = '\\';
            b[n++] = 'r';
        } else if (c == '\n') {
            b[n++] = '\\';
            b[n++] = 'n';
        } else if (c == '\t') {
            b[n++] = '\\';
            b[n++] = 't';
        } else if (c == 0) {
            b[n++] = '\\';
            b[n++] = '0';
        } else if (c == '\\') {
            b[n++] = '\\';
            b[n++] = '\\';
        } else if (c >= 0x20 && c < 0x7F) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "\\x%02X", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

/* One result: its return, its last error, its text. */
static void show_w(const char *what, DWORD n)
{
    line("FormatMessageW %s: ret=%lu err=%s [%s]", what, n, le_of(g_err), vis_w(wbuf, n));
}

static void show_a(const char *what, DWORD n)
{
    line("FormatMessageA %s: ret=%lu err=%s [%s]", what, n, le_of(g_err), vis_a(abuf, n));
}

/* A table message with no inserts read (Arguments NULL), W then A. */
static void plain(const char *what, DWORD flags, DWORD id, DWORD lang)
{
    show_w(what, fmw(flags | NO_ARGS, NULL, id, lang, wbuf, WN));
    show_a(what, fma(flags | NO_ARGS, NULL, id, lang, abuf, AN));
}

/* A string with no inserts read (Arguments NULL), W then A. */
static void plain_string(const char *what, DWORD flags, const WCHAR *wtext, const char *atext)
{
    show_w(what, fmw(FORMAT_MESSAGE_FROM_STRING | flags | NO_ARGS, wtext, 0, 0, wbuf, WN));
    show_a(what, fma(FORMAT_MESSAGE_FROM_STRING | flags | NO_ARGS, atext, 0, 0, abuf, AN));
}

/* --- lookup --------------------------------------------------------- */

static void sec_lookup(void)
{
    static const DWORD langs[] = {
        0,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        MAKELANGID(LANG_ENGLISH, SUBLANG_NEUTRAL),
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_UK),
        MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH),
    };
    const DWORD both = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    HMODULE self_w;
    HMODULE self_a;
    char what[64];
    int i;

    plain("plain, NULL module", FORMAT_MESSAGE_FROM_HMODULE, MSG_PLAIN, 0);

    self_w = GetModuleHandleW(NULL);
    self_a = GetModuleHandleA(NULL);
    line("GetModuleHandleW(NULL) is GetModuleHandleA(NULL): %s", yesno(self_w != NULL && self_w == self_a));
    show_w("plain, GetModuleHandleW(NULL)", fmw(FROM_MODULE, self_w, MSG_PLAIN, 0, wbuf, WN));
    show_a("plain, GetModuleHandleA(NULL)", fma(FROM_MODULE, self_a, MSG_PLAIN, 0, abuf, AN));

    plain("the second block (0x200)", FORMAT_MESSAGE_FROM_HMODULE, MSG_SECOND, 0);
    plain("an id in the gap (0x150)", FORMAT_MESSAGE_FROM_HMODULE, MSG_GAP, 0);
    plain("an id beyond the blocks (0x20000999)", FORMAT_MESSAGE_FROM_HMODULE, MSG_BEYOND, 0);

    plain("module and system, 2 (system only)", both, 2, 0);
    plain("module and system, 0x102 (both)", both, MSG_INSERTS, 0);
    plain("module and system, 0x20000999 (neither)", both, MSG_BEYOND, 0);

    for (i = 0; i < (int)(sizeof langs / sizeof langs[0]); i++) {
        sprintf(what, "short, language 0x%04lX", langs[i]);
        plain(what, FORMAT_MESSAGE_FROM_HMODULE, MSG_SHORT, langs[i]);
    }
}

/* --- inserts -------------------------------------------------------- */

static void sec_inserts(void)
{
    const DWORD va = FORMAT_MESSAGE_FROM_HMODULE;
    const DWORD arr = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ARGUMENT_ARRAY;
    DWORD wa[6];
    DWORD aa[6];

    /* Through a va_list. */
    show_w("inserts, va_list", fmw(va, NULL, MSG_INSERTS, 0, wbuf, WN, L"one", L"two"));
    show_a("inserts, va_list", fma(va, NULL, MSG_INSERTS, 0, abuf, AN, "one", "two"));
    show_w("inserts holding %, va_list", fmw(va, NULL, MSG_INSERTS, 0, wbuf, WN, L"50%% off %2", L"two"));
    show_a("inserts holding %, va_list", fma(va, NULL, MSG_INSERTS, 0, abuf, AN, "50%% off %2", "two"));
    show_w("numbers, va_list",
           fmw(va, NULL, MSG_NUMBERS, 0, wbuf, WN, -42, 0xBEEFu, 4000000000u, 42, 7, 255));
    show_a("numbers, va_list",
           fma(va, NULL, MSG_NUMBERS, 0, abuf, AN, -42, 0xBEEFu, 4000000000u, 42, 7, 255));
    show_w("widths, va_list", fmw(va, NULL, MSG_WIDTHS, 0, wbuf, WN, L"wide", "narrow"));
    show_a("widths, va_list", fma(va, NULL, MSG_WIDTHS, 0, abuf, AN, "narrow", L"wide"));
    show_w("star, va_list", fmw(va, NULL, MSG_STAR, 0, wbuf, WN, 8, 3, L"abcdef", L"four", 6, L"xy"));
    show_a("star, va_list", fma(va, NULL, MSG_STAR, 0, abuf, AN, 8, 3, "abcdef", "four", 6, "xy"));
    show_w("prompt, va_list", fmw(va, NULL, MSG_PROMPT, 0, wbuf, WN, L"file.txt"));
    show_a("prompt, va_list", fma(va, NULL, MSG_PROMPT, 0, abuf, AN, "file.txt"));

    /* Through an argument array (DWORD_PTR is a DWORD here; MSVC 6's
     * headers may lack the name). */
    wa[0] = (DWORD)L"one";
    wa[1] = (DWORD)L"two";
    aa[0] = (DWORD)"one";
    aa[1] = (DWORD)"two";
    show_w("inserts, array", fmw(arr, NULL, MSG_INSERTS, 0, wbuf, WN, wa));
    show_a("inserts, array", fma(arr, NULL, MSG_INSERTS, 0, abuf, AN, aa));

    wa[0] = aa[0] = (DWORD)-42;
    wa[1] = aa[1] = 0xBEEF;
    wa[2] = aa[2] = 4000000000u;
    wa[3] = aa[3] = 42;
    wa[4] = aa[4] = 7;
    wa[5] = aa[5] = 255;
    show_w("numbers, array", fmw(arr, NULL, MSG_NUMBERS, 0, wbuf, WN, wa));
    show_a("numbers, array", fma(arr, NULL, MSG_NUMBERS, 0, abuf, AN, aa));

    wa[0] = (DWORD)L"wide";
    wa[1] = (DWORD)"narrow";
    aa[0] = (DWORD)"narrow";
    aa[1] = (DWORD)L"wide";
    show_w("widths, array", fmw(arr, NULL, MSG_WIDTHS, 0, wbuf, WN, wa));
    show_a("widths, array", fma(arr, NULL, MSG_WIDTHS, 0, abuf, AN, aa));

    wa[0] = aa[0] = 8;
    wa[1] = aa[1] = 3;
    wa[2] = (DWORD)L"abcdef";
    aa[2] = (DWORD)"abcdef";
    wa[3] = (DWORD)L"four";
    aa[3] = (DWORD)"four";
    wa[4] = aa[4] = 6;
    wa[5] = (DWORD)L"xy";
    aa[5] = (DWORD)"xy";
    show_w("star, array", fmw(arr, NULL, MSG_STAR, 0, wbuf, WN, wa));
    show_a("star, array", fma(arr, NULL, MSG_STAR, 0, abuf, AN, aa));

    wa[0] = (DWORD)L"file.txt";
    aa[0] = (DWORD)"file.txt";
    show_w("prompt, array", fmw(arr, NULL, MSG_PROMPT, 0, wbuf, WN, wa));
    show_a("prompt, array", fma(arr, NULL, MSG_PROMPT, 0, abuf, AN, aa));
}

/* --- ignore --------------------------------------------------------- */

static void sec_ignore(void)
{
    const DWORD f = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS;

    plain("ignore, inserts", f, MSG_INSERTS, 0);
    plain("ignore, numbers", f, MSG_NUMBERS, 0);
    plain("ignore, widths", f, MSG_WIDTHS, 0);
    plain("ignore, star", f, MSG_STAR, 0);
    plain("ignore, escapes", f, MSG_ESCAPES, 0);
    plain("ignore, prompt", f, MSG_PROMPT, 0);
    plain("ignore, empty", f, MSG_EMPTY, 0);
}

/* --- escapes -------------------------------------------------------- */

static void sec_escapes(void)
{
    const DWORD f = FORMAT_MESSAGE_FROM_HMODULE;

    plain("escapes", f, MSG_ESCAPES, 0);
    plain("empty", f, MSG_EMPTY, 0);
    plain("a line ending in a blank", f, MSG_BLANK, 0);
    plain("long", f, MSG_LONG, 0);
}

/* --- width ---------------------------------------------------------- */

static void sec_width(void)
{
    static const DWORD widths[] = { 0, 20, 40, FORMAT_MESSAGE_MAX_WIDTH_MASK };
    const DWORD f = FORMAT_MESSAGE_FROM_HMODULE;
    char what[64];
    int i;

    for (i = 0; i < (int)(sizeof widths / sizeof widths[0]); i++) {
        sprintf(what, "long, width %lu", widths[i]);
        plain(what, f | widths[i], MSG_LONG, 0);
    }
    plain("short, width 1", f | 1, MSG_SHORT, 0);
    plain("plain, width 255", f | FORMAT_MESSAGE_MAX_WIDTH_MASK, MSG_PLAIN, 0);
    plain("escapes, width 20", f | 20, MSG_ESCAPES, 0);
    plain("escapes, width 255", f | FORMAT_MESSAGE_MAX_WIDTH_MASK, MSG_ESCAPES, 0);
    plain("a line ending in a blank, width 255", f | FORMAT_MESSAGE_MAX_WIDTH_MASK, MSG_BLANK, 0);
    plain("a line ending in a blank, width 20", f | 20, MSG_BLANK, 0);
    show_w("inserts, width 12", fmw(f | 12, NULL, MSG_INSERTS, 0, wbuf, WN, L"alpha beta", L"gamma"));
    show_a("inserts, width 12", fma(f | 12, NULL, MSG_INSERTS, 0, abuf, AN, "alpha beta", "gamma"));
    show_w("prompt, width 255",
           fmw(f | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, MSG_PROMPT, 0, wbuf, WN, L"file.txt"));
    show_a("prompt, width 255",
           fma(f | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, MSG_PROMPT, 0, abuf, AN, "file.txt"));
}

/* --- buffers -------------------------------------------------------- */

/* The short message (16 units) into a buffer of `size` units, the
 * buffer filled with '#' first: the buffer's `size` units as they are
 * after the call, and whether the two units after them stayed '#'. */
static void sized(DWORD id, DWORD size)
{
    DWORD n;
    int i;

    for (i = 0; i < 64; i++) {
        wbuf[i] = L'#';
        abuf[i] = '#';
    }
    n = fmw(FROM_MODULE, NULL, id, 0, wbuf, size);
    line("FormatMessageW 0x%lX, size %lu: ret=%lu err=%s buffer [%s] after it untouched %s", id, size, n,
         le_of(g_err), vis_w(wbuf, size), yesno(wbuf[size] == L'#' && wbuf[size + 1] == L'#'));
    n = fma(FROM_MODULE, NULL, id, 0, abuf, size);
    line("FormatMessageA 0x%lX, size %lu: ret=%lu err=%s buffer [%s] after it untouched %s", id, size, n,
         le_of(g_err), vis_a(abuf, size), yesno(abuf[size] == '#' && abuf[size + 1] == '#'));
}

/* FORMAT_MESSAGE_ALLOCATE_BUFFER, nSize the least size: the text, its
 * terminator, the block's size against the text and nSize, LocalFree. */
static void allocated(DWORD id, DWORD least)
{
    const DWORD f = FORMAT_MESSAGE_ALLOCATE_BUFFER | FROM_MODULE;
    WCHAR *wblock = (WCHAR *)0x1234;
    char *ablock = (char *)0x1234;
    DWORD n;

    n = fmw(f, NULL, id, 0, (LPWSTR)&wblock, least);
    if (n == 0) {
        line("FormatMessageW 0x%lX allocated, nSize %lu: ret=0 err=%s block null %s", id, least, le_of(g_err),
             yesno(wblock == NULL));
    } else {
        line("FormatMessageW 0x%lX allocated, nSize %lu: ret=%lu err=%s [%s] terminated %s", id, least, n,
             le_of(g_err), vis_w(wblock, n), yesno(wblock[n] == 0));
        line("LocalSize (W) holds the text and its terminator: %s, at least nSize: %s",
             yesno(LocalSize(wblock) >= (n + 1) * sizeof(WCHAR)),
             yesno(LocalSize(wblock) >= least * sizeof(WCHAR)));
        line("LocalFree (W): %s", yesno(LocalFree(wblock) == NULL));
    }

    n = fma(f, NULL, id, 0, (LPSTR)&ablock, least);
    if (n == 0) {
        line("FormatMessageA 0x%lX allocated, nSize %lu: ret=0 err=%s block null %s", id, least, le_of(g_err),
             yesno(ablock == NULL));
    } else {
        line("FormatMessageA 0x%lX allocated, nSize %lu: ret=%lu err=%s [%s] terminated %s", id, least, n,
             le_of(g_err), vis_a(ablock, n), yesno(ablock[n] == 0));
        line("LocalSize (A) holds the text and its terminator: %s, at least nSize: %s",
             yesno(LocalSize(ablock) >= n + 1), yesno(LocalSize(ablock) >= least));
        line("LocalFree (A): %s", yesno(LocalFree(ablock) == NULL));
    }
}

static void sec_buffers(void)
{
    sized(MSG_SHORT, 17);       /* the text and its terminator */
    sized(MSG_SHORT, 16);       /* one short: no room for the terminator */
    sized(MSG_SHORT, 15);
    sized(MSG_SHORT, 1);
    sized(MSG_SHORT, 0);
    sized(MSG_EMPTY, 8);
    allocated(MSG_SHORT, 0);
    allocated(MSG_SHORT, 200);
    allocated(MSG_PLAIN, 10);   /* nSize below the text's length */
    allocated(MSG_EMPTY, 0);
}

/* --- string --------------------------------------------------------- */

static void sec_string(void)
{
    const DWORD va = FORMAT_MESSAGE_FROM_STRING;
    const DWORD arr = FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY;
    DWORD wa[6];
    DWORD aa[6];

    show_w("string inserts, va_list",
           fmw(va, L"Inserts: %1, %2, and %1 again.", 0, 0, wbuf, WN, L"one", L"two"));
    show_a("string inserts, va_list",
           fma(va, "Inserts: %1, %2, and %1 again.", 0, 0, abuf, AN, "one", "two"));
    show_w("string numbers, va_list",
           fmw(va, L"Numbers: %1!d!, %2!08lX!, %3!u!, [%4!5d!], [%5!-5d!], %6!x!.", 0, 0, wbuf, WN,
               -42, 0xBEEFu, 4000000000u, 42, 7, 255));
    show_a("string numbers, va_list",
           fma(va, "Numbers: %1!d!, %2!08lX!, %3!u!, [%4!5d!], [%5!-5d!], %6!x!.", 0, 0, abuf, AN,
               -42, 0xBEEFu, 4000000000u, 42, 7, 255));
    show_w("string widths, va_list",
           fmw(va, L"Strings: %1!s! (the call's width), %2!S! (the other).", 0, 0, wbuf, WN, L"wide", "narrow"));
    show_a("string widths, va_list",
           fma(va, "Strings: %1!s! (the call's width), %2!S! (the other).", 0, 0, abuf, AN, "narrow", L"wide"));

    wa[0] = aa[0] = 8;
    wa[1] = aa[1] = 3;
    wa[2] = (DWORD)L"abcdef";
    aa[2] = (DWORD)"abcdef";
    wa[3] = (DWORD)L"four";
    aa[3] = (DWORD)"four";
    wa[4] = aa[4] = 6;
    wa[5] = (DWORD)L"xy";
    aa[5] = (DWORD)"xy";
    show_w("string star, array", fmw(arr, L"Star: [%1!*.*s!] %4 [%5!*s!]", 0, 0, wbuf, WN, wa));
    show_a("string star, array", fma(arr, "Star: [%1!*.*s!] %4 [%5!*s!]", 0, 0, abuf, AN, aa));

    wa[0] = (DWORD)L"just the insert";
    aa[0] = (DWORD)"just the insert";
    show_w("string of only an insert, array", fmw(arr, L"%1", 0, 0, wbuf, WN, wa));
    show_a("string of only an insert, array", fma(arr, "%1", 0, 0, abuf, AN, aa));

    plain_string("string escapes", 0, L"100%% sure.%nHard break; %. %! then%ttab, stops here%0never shown",
                 "100%% sure.%nHard break; %. %! then%ttab, stops here%0never shown");
    plain_string("string prompt", 0, L"Prompt (Y/N)? %0", "Prompt (Y/N)? %0");
    plain_string("string with CR LF", 0, L"Two lines\r\nby CR LF in the string.\r\n",
                 "Two lines\r\nby CR LF in the string.\r\n");
    plain_string("string with CR LF, width 255", FORMAT_MESSAGE_MAX_WIDTH_MASK,
                 L"Two lines\r\nby CR LF in the string.\r\n", "Two lines\r\nby CR LF in the string.\r\n");
    plain_string("string, ignore", FORMAT_MESSAGE_IGNORE_INSERTS, L"Inserts: %1, %2, and %1 again.",
                 "Inserts: %1, %2, and %1 again.");
    plain_string("empty string", 0, L"", "");
}

static const section_t sections[] = {
    { "lookup", sec_lookup, F2KT_ALWAYS },
    { "inserts", sec_inserts, F2KT_ALWAYS },
    { "ignore", sec_ignore, F2KT_ALWAYS },
    { "escapes", sec_escapes, F2KT_ALWAYS },
    { "width", sec_width, F2KT_ALWAYS },
    { "buffers", sec_buffers, F2KT_ALWAYS },
    { "string", sec_string, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("msgtable", sections, argc, argv);
}
