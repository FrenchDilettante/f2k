/*
 * lstr - kernel32's lstr string functions: lstrlenA/W, lstrcpyA/W,
 * lstrcpynA/W and lstrcatA/W, over good strings and bad pointers.
 *
 * Windows 2000 runs each of them inside structured exception handling:
 * a bad pointer, NULL included, makes the call return 0 or NULL instead
 * of faulting. The sections print what each call returned, the last
 * error (whether a caught fault sets it is what the capture tells), and
 * what reached the destination. Each section turns the fault dialog off
 * first (SetErrorMode), so a fault the function does not catch ends the
 * process with its status instead of waiting on a dialog.
 *
 * The bad memory is one VirtualAlloc'd region of three pages, set up at
 * a section's start and freed at its end, every byte of it filled with
 * the sentinel 0x5A first ('Z'; a W unit of it is U+5A5A):
 *
 *   page 0  read-write; the edge cases sit at its very end, so the next
 *           byte is the no-access page's first
 *   page 1  PAGE_NOACCESS: a pointer to its start is the bad source,
 *           and what an edge string runs into
 *   page 2  PAGE_READONLY: holds "ro" at its start and L"ro" 64 bytes
 *           in, each with its terminator; a destination nothing may
 *           write
 *
 * Buffers on the stack are filled with the sentinel before each call
 * too, so a line shows exactly which units the call wrote: a buffer
 * prints as its first few units, a NUL as \0, a byte outside ASCII as
 * \xHH, a W unit outside ASCII as <U+XXXX>. No pointer is printed: a
 * returned pointer prints as "dest" (the destination passed), "NULL",
 * or "another pointer".
 *
 * Sections (run all with no argument, or one by name):
 *
 *   len   lstrlenA, then lstrlenW: "", "abc", a string outside ASCII
 *         (A: the byte 0xE9; W: U+00E9 and U+4E2D), NULL, a pointer
 *         to the no-access page, and four characters with no NUL that
 *         run into the no-access page
 *   cpy   lstrcpyA, then lstrcpyW: a copy (the return and what the
 *         buffer holds), an empty source, a NULL destination, a NULL
 *         source, a source in the no-access page, a destination in the
 *         read-only page, and a destination three characters before
 *         the no-access page (what reached it before the fault)
 *   cpyn  lstrcpynA, then lstrcpynW, of "abcde" with counts 0, 1, 5, 6
 *         and 10 into a sentinel-filled buffer (the buffer past the
 *         NUL: no padding), count -1 with a short source, a NULL
 *         destination, a NULL source, and a read-only destination
 *   cat   lstrcatA, then lstrcatW: appending, onto an empty string,
 *         an empty string appended, a NULL destination, a NULL source,
 *         a read-only destination, and a source in the no-access page;
 *         every line says whether the return is the destination
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat lstr):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% lstr.c
 */

#include "../common/f2kt.h"

/* The sentinel every buffer holds before a call. */
#define FILL_A 0x5A
#define FILL_W 0x5A5A

/* The read-only page's W string, this many bytes into the page. */
#define RO_W_OFFSET 64

static DWORD page;
static char *arena;

/* The no-access page's start. */
static char *noaccess(void)
{
    return arena + page;
}

/* The read-only page's strings: "ro" and L"ro". */
static char *ro_a(void)
{
    return arena + 2 * page;
}

static WCHAR *ro_w(void)
{
    return (WCHAR *)(arena + 2 * page + RO_W_OFFSET);
}

/* The last n bytes (units) of the read-write page, just before the
 * no-access page. */
static char *edge_a(int n)
{
    return arena + page - n;
}

static WCHAR *edge_w(int n)
{
    return (WCHAR *)(arena + page) - n;
}

static void fill_a(char *p, int n)
{
    memset(p, FILL_A, n);
}

static void fill_w(WCHAR *p, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        p[i] = FILL_W;
    }
}

/* Set up the three pages; 0 (with a line saying so) if that failed. */
static int arena_open(void)
{
    SYSTEM_INFO si;
    DWORD old;
    BOOL ok;

    GetSystemInfo(&si);
    page = si.dwPageSize;
    arena = (char *)VirtualAlloc(NULL, 3 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (arena == NULL) {
        line("pages set up: no (VirtualAlloc err=%lu)", GetLastError());
        return 0;
    }
    memset(arena, FILL_A, 3 * page);
    memcpy(ro_a(), "ro", 3);
    memcpy(ro_w(), L"ro", 3 * sizeof(WCHAR));
    ok = VirtualProtect(arena + page, page, PAGE_NOACCESS, &old)
         && VirtualProtect(arena + 2 * page, page, PAGE_READONLY, &old);
    line("pages set up (read-write, no-access, read-only): %s", yesno(ok));
    if (!ok) {
        VirtualFree(arena, 0, MEM_RELEASE);
        arena = NULL;
        return 0;
    }
    return 1;
}

static void arena_close(void)
{
    line("pages freed: %s", yesno(VirtualFree(arena, 0, MEM_RELEASE)));
    arena = NULL;
}

/* A returned pointer, as a relation to the destination passed. */
static const char *rel(const void *r, const void *dest)
{
    if (r == NULL) {
        return "NULL";
    }
    if (r == dest) {
        return "dest";
    }
    return "another pointer";
}

/* The first `count` bytes of an A buffer as printed: NUL as \0, a
 * backslash doubled, a byte outside printable ASCII as \xHH. */
static const char *vis_a(const char *s, int count)
{
    static char bufs[4][256];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 8; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == 0) {
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

/* The same, of a W buffer's first `count` units (<U+XXXX> outside
 * printable ASCII). */
static const char *vis_w(const WCHAR *s, int count)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 10; i++) {
        WCHAR c = s[i];

        if (c == 0) {
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

/* --- len ------------------------------------------------------------ */

static void len_a(const char *what, const char *s)
{
    int n;

    arm();
    n = lstrlenA(s);
    line("lstrlenA(%s): ret=%d err=%s", what, n, le());
}

static void len_w(const char *what, const WCHAR *s)
{
    int n;

    arm();
    n = lstrlenW(s);
    line("lstrlenW(%s): ret=%d err=%s", what, n, le());
}

/* lstrlenA/W return the length in characters, without the NUL; NULL
 * gives 0. A pointer to the no-access page faults on its first read,
 * the edge string on its fifth (four 'a's, then the no-access page,
 * with no NUL before it): what does each return, and is the last error
 * set? */
static void sec_len(void)
{
    int i;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (!arena_open()) {
        return;
    }

    len_a("\"\"", "");
    len_a("\"abc\"", "abc");
    len_a("\"caf\\xE9\"", "caf\xE9");
    len_a("NULL", NULL);
    len_a("a no-access page", noaccess());
    fill_a(edge_a(16), 16);
    memset(edge_a(4), 'a', 4);
    len_a("\"aaaa\" running into a no-access page", edge_a(4));

    len_w("\"\"", L"");
    len_w("\"abc\"", L"abc");
    len_w("\"caf<U+00E9><U+4E2D>\"", L"caf\x00E9\x4E2D");
    len_w("NULL", NULL);
    len_w("a no-access page", (const WCHAR *)noaccess());
    fill_w(edge_w(8), 8);
    for (i = 0; i < 4; i++) {
        edge_w(4)[i] = L'a';
    }
    len_w("\"aaaa\" running into a no-access page", edge_w(4));

    arena_close();
}

/* --- cpy ------------------------------------------------------------ */

/* lstrcpyA(dest, src), labelled `what`; then the return, the last error
 * and, when `show` is not NULL, its first `nshow` bytes. */
static void cpy_a(const char *what, char *dest, const char *src, const char *show, int nshow)
{
    const char *e;
    char *r;

    arm();
    r = lstrcpyA(dest, src);
    e = le();
    if (show != NULL) {
        line("lstrcpyA(%s): ret=%s err=%s dest [%s]", what, rel(r, dest), e, vis_a(show, nshow));
    } else {
        line("lstrcpyA(%s): ret=%s err=%s", what, rel(r, dest), e);
    }
}

static void cpy_w(const char *what, WCHAR *dest, const WCHAR *src, const WCHAR *show, int nshow)
{
    const char *e;
    WCHAR *r;

    arm();
    r = lstrcpyW(dest, src);
    e = le();
    if (show != NULL) {
        line("lstrcpyW(%s): ret=%s err=%s dest [%s]", what, rel(r, dest), e, vis_w(show, nshow));
    } else {
        line("lstrcpyW(%s): ret=%s err=%s", what, rel(r, dest), e);
    }
}

/* lstrcpyA/W return the destination, or NULL on failure. A copy into a
 * sentinel-filled buffer (the units after the NUL untouched?), an empty
 * source, then the failures: a NULL destination, a NULL source and a
 * source in the no-access page (is the buffer written?), the read-only
 * page as the destination (still "ro" after?), and a destination three
 * characters before the no-access page, where the copy of "abcdefgh"
 * faults on its fourth character: what reached those three? */
static void sec_cpy(void)
{
    char buf[16];
    WCHAR wbuf[16];

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (!arena_open()) {
        return;
    }

    fill_a(buf, 16);
    cpy_a("buf, \"abc\"", buf, "abc", buf, 6);
    fill_a(buf, 16);
    cpy_a("buf, \"\"", buf, "", buf, 3);
    cpy_a("NULL, \"abc\"", NULL, "abc", NULL, 0);
    fill_a(buf, 16);
    cpy_a("buf, NULL", buf, NULL, buf, 3);
    fill_a(buf, 16);
    cpy_a("buf, a no-access page", buf, noaccess(), buf, 3);
    cpy_a("a read-only page holding \"ro\", \"abc\"", ro_a(), "abc", ro_a(), 4);
    fill_a(edge_a(16), 16);
    cpy_a("3 bytes before a no-access page, \"abcdefgh\"", edge_a(3), "abcdefgh", edge_a(3), 3);

    fill_w(wbuf, 16);
    cpy_w("buf, \"abc\"", wbuf, L"abc", wbuf, 6);
    fill_w(wbuf, 16);
    cpy_w("buf, \"\"", wbuf, L"", wbuf, 3);
    cpy_w("NULL, \"abc\"", NULL, L"abc", NULL, 0);
    fill_w(wbuf, 16);
    cpy_w("buf, NULL", wbuf, NULL, wbuf, 3);
    fill_w(wbuf, 16);
    cpy_w("buf, a no-access page", wbuf, (const WCHAR *)noaccess(), wbuf, 3);
    cpy_w("a read-only page holding \"ro\", \"abc\"", ro_w(), L"abc", ro_w(), 4);
    fill_w(edge_w(8), 8);
    cpy_w("3 units before a no-access page, \"abcdefgh\"", edge_w(3), L"abcdefgh", edge_w(3), 3);

    arena_close();
}

/* --- cpyn ----------------------------------------------------------- */

/* lstrcpynA(dest, src, count), labelled `what`; then the return, the
 * last error and, when `show` is not NULL, its first `nshow` bytes. */
static void cpyn_a(const char *what, char *dest, const char *src, int count, const char *show, int nshow)
{
    const char *e;
    char *r;

    arm();
    r = lstrcpynA(dest, src, count);
    e = le();
    if (show != NULL) {
        line("lstrcpynA(%s, %d): ret=%s err=%s dest [%s]", what, count, rel(r, dest), e,
             vis_a(show, nshow));
    } else {
        line("lstrcpynA(%s, %d): ret=%s err=%s", what, count, rel(r, dest), e);
    }
}

static void cpyn_w(const char *what, WCHAR *dest, const WCHAR *src, int count, const WCHAR *show, int nshow)
{
    const char *e;
    WCHAR *r;

    arm();
    r = lstrcpynW(dest, src, count);
    e = le();
    if (show != NULL) {
        line("lstrcpynW(%s, %d): ret=%s err=%s dest [%s]", what, count, rel(r, dest), e,
             vis_w(show, nshow));
    } else {
        line("lstrcpynW(%s, %d): ret=%s err=%s", what, count, rel(r, dest), e);
    }
}

/* lstrcpynA/W(dest, src, count) copy at most count-1 characters and
 * always write a NUL; unlike strncpy they do not pad. "abcde" (five
 * characters) with counts 0 (is anything written?), 1 (the NUL alone),
 * 5 (truncated to "abcd"), 6 (exactly fits) and 10 (room to spare: are
 * the units past the NUL still the sentinel?), each into a fresh
 * sentinel-filled buffer printed past the NUL. Then count -1 with "abc"
 * into a 64-unit buffer (the source's NUL ends the copy, so it is safe),
 * and the failures with count 5: a NULL destination, a NULL source (is
 * the buffer written?), the read-only page as the destination. */
static void sec_cpyn(void)
{
    static const int counts[] = { 0, 1, 5, 6, 10 };
    char buf[16];
    char big[64];
    WCHAR wbuf[16];
    WCHAR wbig[64];
    int i;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (!arena_open()) {
        return;
    }

    for (i = 0; i < (int)(sizeof counts / sizeof counts[0]); i++) {
        fill_a(buf, 16);
        cpyn_a("buf, \"abcde\"", buf, "abcde", counts[i], buf, 12);
    }
    fill_a(big, 64);
    cpyn_a("buf, \"abc\"", big, "abc", -1, big, 6);
    cpyn_a("NULL, \"abcde\"", NULL, "abcde", 5, NULL, 0);
    fill_a(buf, 16);
    cpyn_a("buf, NULL", buf, NULL, 5, buf, 3);
    cpyn_a("a read-only page holding \"ro\", \"abcde\"", ro_a(), "abcde", 5, ro_a(), 4);

    for (i = 0; i < (int)(sizeof counts / sizeof counts[0]); i++) {
        fill_w(wbuf, 16);
        cpyn_w("buf, \"abcde\"", wbuf, L"abcde", counts[i], wbuf, 12);
    }
    fill_w(wbig, 64);
    cpyn_w("buf, \"abc\"", wbig, L"abc", -1, wbig, 6);
    cpyn_w("NULL, \"abcde\"", NULL, L"abcde", 5, NULL, 0);
    fill_w(wbuf, 16);
    cpyn_w("buf, NULL", wbuf, NULL, 5, wbuf, 3);
    cpyn_w("a read-only page holding \"ro\", \"abcde\"", ro_w(), L"abcde", 5, ro_w(), 4);

    arena_close();
}

/* --- cat ------------------------------------------------------------ */

/* lstrcatA(dest, src), labelled `what`; then the return, the last error
 * and, when `show` is not NULL, its first `nshow` bytes. */
static void cat_a(const char *what, char *dest, const char *src, const char *show, int nshow)
{
    const char *e;
    char *r;

    arm();
    r = lstrcatA(dest, src);
    e = le();
    if (show != NULL) {
        line("lstrcatA(%s): ret=%s err=%s dest [%s]", what, rel(r, dest), e, vis_a(show, nshow));
    } else {
        line("lstrcatA(%s): ret=%s err=%s", what, rel(r, dest), e);
    }
}

static void cat_w(const char *what, WCHAR *dest, const WCHAR *src, const WCHAR *show, int nshow)
{
    const char *e;
    WCHAR *r;

    arm();
    r = lstrcatW(dest, src);
    e = le();
    if (show != NULL) {
        line("lstrcatW(%s): ret=%s err=%s dest [%s]", what, rel(r, dest), e, vis_w(show, nshow));
    } else {
        line("lstrcatW(%s): ret=%s err=%s", what, rel(r, dest), e);
    }
}

/* A sentinel-filled buffer starting with `text` and its NUL (set up
 * without the lstr functions). */
static void start_a(char *buf, const char *text)
{
    fill_a(buf, 16);
    memcpy(buf, text, strlen(text) + 1);
}

static void start_w(WCHAR *buf, const WCHAR *text)
{
    int i;

    fill_w(buf, 16);
    for (i = 0; text[i] != 0; i++) {
        buf[i] = text[i];
    }
    buf[i] = 0;
}

/* lstrcatA/W return the destination, or NULL on failure: is the return
 * the destination on each line? "ab" + "cd", "" + "xy", "ab" + "",
 * each in a sentinel-filled buffer printed past the NUL; then the
 * failures: a NULL destination, a NULL source and a source in the
 * no-access page onto "ab" (is "ab" still there, its NUL kept?), and
 * the read-only page holding "ro" as the destination. */
static void sec_cat(void)
{
    char buf[16];
    WCHAR wbuf[16];

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (!arena_open()) {
        return;
    }

    start_a(buf, "ab");
    cat_a("\"ab\", \"cd\"", buf, "cd", buf, 6);
    start_a(buf, "");
    cat_a("\"\", \"xy\"", buf, "xy", buf, 4);
    start_a(buf, "ab");
    cat_a("\"ab\", \"\"", buf, "", buf, 4);
    cat_a("NULL, \"cd\"", NULL, "cd", NULL, 0);
    start_a(buf, "ab");
    cat_a("\"ab\", NULL", buf, NULL, buf, 4);
    cat_a("a read-only page holding \"ro\", \"x\"", ro_a(), "x", ro_a(), 4);
    start_a(buf, "ab");
    cat_a("\"ab\", a no-access page", buf, noaccess(), buf, 4);

    start_w(wbuf, L"ab");
    cat_w("\"ab\", \"cd\"", wbuf, L"cd", wbuf, 6);
    start_w(wbuf, L"");
    cat_w("\"\", \"xy\"", wbuf, L"xy", wbuf, 4);
    start_w(wbuf, L"ab");
    cat_w("\"ab\", \"\"", wbuf, L"", wbuf, 4);
    cat_w("NULL, \"cd\"", NULL, L"cd", NULL, 0);
    start_w(wbuf, L"ab");
    cat_w("\"ab\", NULL", wbuf, NULL, wbuf, 4);
    cat_w("a read-only page holding \"ro\", \"x\"", ro_w(), L"x", ro_w(), 4);
    start_w(wbuf, L"ab");
    cat_w("\"ab\", a no-access page", wbuf, (const WCHAR *)noaccess(), wbuf, 4);

    arena_close();
}

static const section_t sections[] = {
    { "len", sec_len, F2KT_ALWAYS },
    { "cpy", sec_cpy, F2KT_ALWAYS },
    { "cpyn", sec_cpyn, F2KT_ALWAYS },
    { "cat", sec_cat, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("lstr", sections, argc, argv);
}
