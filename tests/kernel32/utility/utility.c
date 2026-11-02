/*
 * utility - small kernel32 exports programs call in passing: MulDiv,
 * the DBCS lead-byte tests, GetStringTypeEx, the user's language, the
 * system directory, the temporary directory and file names, local file
 * times, and a process's version.
 *
 * The real machine and F2K differ in the Windows directory's name, the
 * current directory (the fixture's own directory on the real machine,
 * \CORPUS on F2K), the time zone, the user's profile and the tick
 * count, so nothing printed depends on them:
 *
 * - A path prints with the current directory's prefix replaced by
 *   <cwd> and the Windows directory's by <windir> (the prefixes matched
 *   case-insensitively, up to a backslash or the path's end), the rest
 *   as returned, case included. Lengths print as relations to the
 *   path's length (ret=length, ret=length+1).
 * - Local times print only as relations: a round trip, a shift and
 *   its negative.
 * - The temporary path is asked for only once the section has set
 *   TMP, TEMP and USERPROFILE itself (or removed them), so the real
 *   machine's profile never shows.
 * - A temporary file name GetTempFileName numbers itself (uUnique 0,
 *   from the tick count) prints with its number replaced by <hex>,
 *   then the facts about it: how many digits, whether the return is
 *   that number, the file's existence and size.
 *
 * No DBCS code page (932, 936, 949, 950) is used: whether one is
 * installed is the machine's choice, and F2K carries no DBCS tables.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   muldiv      MulDiv: rounding to the nearest, halves away from zero,
 *               signs, the 64-bit intermediate, overflow and a zero
 *               denominator (-1)
 *   dbcs        IsDBCSLeadByte over bytes from 0x00 to 0xFF;
 *               IsDBCSLeadByteEx over some of them with CP_ACP,
 *               CP_OEMCP, 1252, 437, 850, CP_UTF8 and a page that does
 *               not exist
 *   stringtype  GetStringTypeExA and GetStringTypeExW with the user's,
 *               the system's and 0x0409's locale, CT_CTYPE1, 2 and 3,
 *               over a fixed string (count -1); an explicit count, a
 *               count of 0, flags 0 and 3, a NULL output; each result
 *               (words in hex, 0xBEEF where untouched) against
 *               GetStringTypeA/GetStringTypeW's on the same input
 *   langid      GetUserDefaultLangID, against the user's LCID's language
 *   sysdir      GetSystemDirectoryA/W: the path, a NULL buffer of size
 *               0, a buffer one short and one that fits; W against A
 *   temppath    GetTempPathA/W with TMP, TEMP and USERPROFILE set or
 *               removed in turn (TMP an existing directory without and
 *               with a trailing backslash, one that does not exist, a
 *               relative name, an empty value; then TEMP; then the
 *               profile; then nothing); buffers of size 0, one short,
 *               one that fits, and of 3
 *   tempfile    GetTempFileNameA/W in <cwd>\tfdir (emptied first):
 *               uUnique 0x1234 with the prefixes "abc", "abcdef" and
 *               "", 0xABCD, 0x12345, a trailing backslash; uUnique 0
 *               twice (a file created each time); a directory that does
 *               not exist with uUnique 0 and 0x1234
 *   filetime    LocalFileTimeToFileTime against FileTimeToLocalFileTime
 *               on fixed times: the round trip, the shifts' signs, the
 *               same buffer for input and output
 *   version     GetProcessVersion of 0, of the process's own id, and of
 *               an id no process has (3: real ids are multiples of 4)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat utility):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% utility.c
 */

#include "../common/f2kt.h"

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

/* The current and Windows directories as returned (the _raw one, which
 * new paths are built on), and without a trailing backslash (the
 * prefixes the printed paths are matched against). */
static char cwd_raw[MAX_PATH];
static char cwd_a[MAX_PATH];
static char win_a[MAX_PATH];
static WCHAR cwd_w[MAX_PATH];
static WCHAR win_w[MAX_PATH];

static int upper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
}

/* The length of the prefix `pre` that `s` starts with, case-insensitively,
 * followed by a backslash or the end; 0 when it does not. */
static size_t lead_a(const char *s, const char *pre)
{
    size_t n = strlen(pre);
    size_t i;

    if (n == 0) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] == '\0' || upper((unsigned char)s[i]) != upper((unsigned char)pre[i])) {
            return 0;
        }
    }
    if (s[n] != '\0' && s[n] != '\\') {
        return 0;
    }
    return n;
}

static size_t lead_w(const WCHAR *s, const WCHAR *pre)
{
    size_t n = wcslen(pre);
    size_t i;

    if (n == 0) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] == 0 || upper(s[i]) != upper(pre[i])) {
            return 0;
        }
    }
    if (s[n] != 0 && s[n] != '\\') {
        return 0;
    }
    return n;
}

/* A path as printed: <cwd> or <windir> for its prefix (the longer match),
 * the rest as returned. Calls no API. */
static const char *pa(const char *s)
{
    static char bufs[4][2 * MAX_PATH + 16];
    static int next;
    char *b = bufs[next++ & 3];
    size_t c, w;

    if (s == NULL) {
        return "(null)";
    }
    c = lead_a(s, cwd_a);
    w = lead_a(s, win_a);
    if (c != 0 && c >= w) {
        _snprintf(b, sizeof bufs[0] - 1, "<cwd>%s", s + c);
    } else if (w != 0) {
        _snprintf(b, sizeof bufs[0] - 1, "<windir>%s", s + w);
    } else {
        _snprintf(b, sizeof bufs[0] - 1, "%s", s);
    }
    b[sizeof bufs[0] - 1] = '\0';
    return b;
}

static const char *pw(const WCHAR *s)
{
    static char bufs[4][1100];
    static int next;
    char *b = bufs[next++ & 3];
    size_t c, w;

    if (s == NULL) {
        return "(null)";
    }
    c = lead_w(s, cwd_w);
    w = lead_w(s, win_w);
    if (c != 0 && c >= w) {
        _snprintf(b, sizeof bufs[0] - 1, "<cwd>%s", ws(s + c));
    } else if (w != 0) {
        _snprintf(b, sizeof bufs[0] - 1, "<windir>%s", ws(s + w));
    } else {
        _snprintf(b, sizeof bufs[0] - 1, "%s", ws(s));
    }
    b[sizeof bufs[0] - 1] = '\0';
    return b;
}

static void strip_slash_a(char *s)
{
    size_t n = strlen(s);

    if (n > 0 && s[n - 1] == '\\') {
        s[n - 1] = '\0';
    }
}

static void strip_slash_w(WCHAR *s)
{
    size_t n = wcslen(s);

    if (n > 0 && s[n - 1] == '\\') {
        s[n - 1] = 0;
    }
}

/* <cwd>\rel, built on the current directory as returned. */
static void at_cwd(char *out, const char *rel)
{
    size_t n = strlen(cwd_raw);

    if (n > 0 && cwd_raw[n - 1] == '\\') {
        sprintf(out, "%s%s", cwd_raw, rel);
    } else {
        sprintf(out, "%s\\%s", cwd_raw, rel);
    }
}

static void widen(WCHAR *out, int size, const char *s)
{
    if (MultiByteToWideChar(CP_ACP, 0, s, -1, out, size) == 0) {
        out[0] = 0;
    }
}

static void narrow(char *out, int size, const WCHAR *s)
{
    if (WideCharToMultiByte(CP_ACP, 0, s, -1, out, size, NULL, NULL) == 0) {
        out[0] = '\0';
    }
}

/* A return value against a length, as printed. */
static const char *rel_len(DWORD r, size_t len)
{
    static char bufs[4][32];
    static int next;
    char *b = bufs[next++ & 3];
    long d;

    if (r == 0) {
        return "ret=0";
    }
    d = (long)r - (long)len;
    if (d == 0) {
        return "ret=length";
    }
    sprintf(b, "ret=length%+ld", d);
    return b;
}

/* Output buffers start filled with a marker, to see what a call wrote. */
#define MARK_A 'Z'
#define MARK_W 0x5A5A

static void fill_a(char *b, size_t size)
{
    memset(b, MARK_A, size - 1);
    b[size - 1] = '\0';
}

static void fill_w(WCHAR *b, size_t count)
{
    size_t i;

    for (i = 0; i < count - 1; i++) {
        b[i] = MARK_W;
    }
    b[count - 1] = 0;
}

static int untouched_a(const char *b, size_t size)
{
    size_t i;

    for (i = 0; i < size - 1; i++) {
        if (b[i] != MARK_A) {
            return 0;
        }
    }
    return 1;
}

static int untouched_w(const WCHAR *b, size_t count)
{
    size_t i;

    for (i = 0; i < count - 1; i++) {
        if (b[i] != MARK_W) {
            return 0;
        }
    }
    return 1;
}

/* A returned path, or "(untouched)" when the call left the buffer alone. */
static const char *shown_a(const char *b, size_t size)
{
    return untouched_a(b, size) ? "(untouched)" : pa(b);
}

static const char *shown_w(const WCHAR *b, size_t count)
{
    return untouched_w(b, count) ? "(untouched)" : pw(b);
}

/* ------------------------------------------------------------------ */

static void muldiv(int a, int b, int c)
{
    int r;

    arm();
    r = MulDiv(a, b, c);
    line("MulDiv(%d, %d, %d) = %d err=%s", a, b, c, r, le());
}

static void sec_muldiv(void)
{
    int int_min = -2147483647 - 1;

    muldiv(10, 3, 2);
    muldiv(5, 1, 2);
    muldiv(-5, 1, 2);
    muldiv(5, 1, -2);
    muldiv(7, 1, 3);
    muldiv(-7, 1, 3);
    muldiv(0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF);  /* the 64-bit intermediate */
    muldiv(0x7FFFFFFF, 2, 1);                    /* overflow */
    muldiv(1, 1, 0);                             /* a zero denominator */
    muldiv(int_min, 1, 1);
    muldiv(int_min, -1, 1);                      /* overflow */
    muldiv(0, 5, 0);
}

/* ------------------------------------------------------------------ */

static void sec_dbcs(void)
{
    static const BYTE all[] = { 0x00, 0x41, 0x7F, 0x80, 0x81, 0x9F, 0xA0, 0xE0, 0xFE, 0xFF };
    static const BYTE some[] = { 0x41, 0x81, 0xE0, 0xFF };
    static const struct {
        UINT cp;
        const char *name;
    } pages[] = {
        { CP_ACP, "CP_ACP" },
        { CP_OEMCP, "CP_OEMCP" },
        { 1252, "1252" },
        { 437, "437" },
        { 850, "850" },
        { CP_UTF8, "CP_UTF8" },
        { 12345, "12345 (no such page)" },
    };
    BOOL r;
    int i, j;

    for (i = 0; i < (int)(sizeof all / sizeof all[0]); i++) {
        arm();
        r = IsDBCSLeadByte(all[i]);
        line("IsDBCSLeadByte(0x%02X) = %d err=%s", all[i], r, le());
    }
    for (i = 0; i < (int)(sizeof pages / sizeof pages[0]); i++) {
        for (j = 0; j < (int)(sizeof some / sizeof some[0]); j++) {
            arm();
            r = IsDBCSLeadByteEx(pages[i].cp, some[j]);
            line("IsDBCSLeadByteEx(%s, 0x%02X) = %d err=%s", pages[i].name, some[j], r, le());
        }
    }
}

/* ------------------------------------------------------------------ */

/* The input: letters, digits, a space, punctuation, a tab and a control
 * character, e-acute (0xE9 in code page 1252); the W one adds Greek
 * capital alpha, a CJK ideograph, the ideographic space and fullwidth A. */
static const char st_text[] = "Az09 !.\t\001\351";
static const WCHAR st_wtext[] = {
    'A', 'z', '0', '9', ' ', '!', '.', '\t', 0x0001, 0x00E9,
    0x0391, 0x4E2D, 0x3000, 0xFF21, 0
};

#define ST_WORDS 20
#define ST_UNSET 0xBEEF

static void st_fill(WORD *w)
{
    int i;

    for (i = 0; i < ST_WORDS; i++) {
        w[i] = ST_UNSET;
    }
}

static const char *st_words(const WORD *w, int n)
{
    static char bufs[2][ST_WORDS * 5 + 1];
    static int next;
    char *b = bufs[next++ & 1];
    int i, k = 0;

    b[0] = '\0';
    for (i = 0; i < n && i < ST_WORDS; i++) {
        k += sprintf(b + k, i == 0 ? "%04X" : " %04X", w[i]);
    }
    return b;
}

static const char *st_locale(LCID lcid)
{
    switch (lcid) {
    case LOCALE_USER_DEFAULT: return "LOCALE_USER_DEFAULT";
    case LOCALE_SYSTEM_DEFAULT: return "LOCALE_SYSTEM_DEFAULT";
    }
    return "0x0409";
}

static const char *st_type(DWORD type)
{
    static char b[16];

    switch (type) {
    case CT_CTYPE1: return "CT_CTYPE1";
    case CT_CTYPE2: return "CT_CTYPE2";
    case CT_CTYPE3: return "CT_CTYPE3";
    }
    sprintf(b, "%lu", type);
    return b;
}

/* GetStringTypeExA, then GetStringTypeA on the same input; `shown` words
 * printed (none for a NULL output). A fault prints as such. */
static void st_a(LCID lcid, DWORD type, int count, int shown, int null_out)
{
    WORD w1[ST_WORDS], w2[ST_WORDS];
    BOOL r1 = FALSE, r2 = FALSE;
    DWORD e1, e2;
    int f1 = 0, f2 = 0;
    int same;

    st_fill(w1);
    st_fill(w2);
    arm();
    __try {
        r1 = GetStringTypeExA(lcid, type, st_text, count, null_out ? NULL : w1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        f1 = 1;
    }
    e1 = GetLastError();
    arm();
    __try {
        r2 = GetStringTypeA(lcid, type, st_text, count, null_out ? NULL : w2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        f2 = 1;
    }
    e2 = GetLastError();
    same = r1 == r2 && f1 == f2 && e1 == e2 && memcmp(w1, w2, sizeof w1) == 0;
    if (f1) {
        line("GetStringTypeExA(%s, %s, count %d%s): faulted, the same as GetStringTypeA: %s",
             st_locale(lcid), st_type(type), count, null_out ? ", NULL output" : "", yesno(same));
        return;
    }
    line("GetStringTypeExA(%s, %s, count %d%s): ret=%d err=%s%s%s, the same as GetStringTypeA: %s",
         st_locale(lcid), st_type(type), count, null_out ? ", NULL output" : "", r1, le_of(e1),
         null_out ? "" : " words=", null_out ? "" : st_words(w1, shown), yesno(same));
}

static void st_w(LCID lcid, DWORD type, int count, int shown, int null_out)
{
    WORD w1[ST_WORDS], w2[ST_WORDS];
    BOOL r1 = FALSE, r2 = FALSE;
    DWORD e1, e2;
    int f1 = 0, f2 = 0;
    int same;

    st_fill(w1);
    st_fill(w2);
    arm();
    __try {
        r1 = GetStringTypeExW(lcid, type, st_wtext, count, null_out ? NULL : w1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        f1 = 1;
    }
    e1 = GetLastError();
    arm();
    __try {
        r2 = GetStringTypeW(type, st_wtext, count, null_out ? NULL : w2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        f2 = 1;
    }
    e2 = GetLastError();
    same = r1 == r2 && f1 == f2 && e1 == e2 && memcmp(w1, w2, sizeof w1) == 0;
    if (f1) {
        line("GetStringTypeExW(%s, %s, count %d%s): faulted, the same as GetStringTypeW: %s",
             st_locale(lcid), st_type(type), count, null_out ? ", NULL output" : "", yesno(same));
        return;
    }
    line("GetStringTypeExW(%s, %s, count %d%s): ret=%d err=%s%s%s, the same as GetStringTypeW: %s",
         st_locale(lcid), st_type(type), count, null_out ? ", NULL output" : "", r1, le_of(e1),
         null_out ? "" : " words=", null_out ? "" : st_words(w1, shown), yesno(same));
}

static void sec_stringtype(void)
{
    static const LCID locales[] = { LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT, 0x0409 };
    static const DWORD types[] = { CT_CTYPE1, CT_CTYPE2, CT_CTYPE3 };
    int alen = (int)strlen(st_text);
    int wlen = (int)wcslen(st_wtext);
    int i, j;

    /* Count -1: the characters, the terminator's slot and one past it. */
    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            st_a(locales[i], types[j], -1, alen + 2, 0);
        }
    }
    st_a(LOCALE_USER_DEFAULT, CT_CTYPE1, 4, 6, 0);
    st_a(LOCALE_USER_DEFAULT, CT_CTYPE1, alen, alen + 2, 0);
    st_a(LOCALE_USER_DEFAULT, CT_CTYPE1, 0, 2, 0);
    st_a(LOCALE_USER_DEFAULT, 0, -1, 2, 0);
    st_a(LOCALE_USER_DEFAULT, CT_CTYPE1 | CT_CTYPE2, -1, 2, 0);
    st_a(LOCALE_USER_DEFAULT, CT_CTYPE1, -1, 0, 1);

    for (i = 0; i < 3; i++) {
        for (j = 0; j < 3; j++) {
            st_w(locales[i], types[j], -1, wlen + 2, 0);
        }
    }
    st_w(LOCALE_USER_DEFAULT, CT_CTYPE1, 4, 6, 0);
    st_w(LOCALE_USER_DEFAULT, CT_CTYPE1, wlen, wlen + 2, 0);
    st_w(LOCALE_USER_DEFAULT, CT_CTYPE1, 0, 2, 0);
    st_w(LOCALE_USER_DEFAULT, 0, -1, 2, 0);
    st_w(LOCALE_USER_DEFAULT, CT_CTYPE1 | CT_CTYPE2, -1, 2, 0);
    st_w(LOCALE_USER_DEFAULT, CT_CTYPE1, -1, 0, 1);
}

/* ------------------------------------------------------------------ */

static void sec_langid(void)
{
    LANGID id;
    LCID lcid;
    const char *e;

    arm();
    id = GetUserDefaultLangID();
    e = le();
    lcid = GetUserDefaultLCID();
    line("GetUserDefaultLangID = 0x%04X err=%s, the language of GetUserDefaultLCID: %s",
         id, e, yesno(id == LANGIDFROMLCID(lcid)));
}

/* ------------------------------------------------------------------ */

static void sec_sysdir(void)
{
    char a[MAX_PATH + 8];
    WCHAR w[MAX_PATH + 8];
    WCHAR wa[MAX_PATH + 8];
    char full[MAX_PATH + 8];
    WCHAR wfull[MAX_PATH + 8];
    UINT r;
    size_t need, wneed;

    fill_a(a, sizeof a);
    arm();
    r = GetSystemDirectoryA(a, MAX_PATH);
    line("GetSystemDirectoryA(MAX_PATH): %s path=%s err=%s", rel_len(r, strlen(a)), shown_a(a, sizeof a), le());
    strcpy(full, a);
    need = strlen(full);

    arm();
    r = GetSystemDirectoryA(NULL, 0);
    line("GetSystemDirectoryA(NULL, 0): %s err=%s", rel_len(r, need), le());
    fill_a(a, sizeof a);
    arm();
    r = GetSystemDirectoryA(a, (UINT)need);
    line("GetSystemDirectoryA(length): %s buffer untouched: %s err=%s", rel_len(r, need), yesno(untouched_a(a, sizeof a)), le());
    fill_a(a, sizeof a);
    arm();
    r = GetSystemDirectoryA(a, (UINT)need + 1);
    line("GetSystemDirectoryA(length + 1): %s path=%s err=%s", rel_len(r, need), shown_a(a, sizeof a), le());

    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetSystemDirectoryW(w, MAX_PATH);
    line("GetSystemDirectoryW(MAX_PATH): %s path=%s err=%s", rel_len(r, wcslen(w)), shown_w(w, MAX_PATH + 8), le());
    wcscpy(wfull, w);
    wneed = wcslen(wfull);

    arm();
    r = GetSystemDirectoryW(NULL, 0);
    line("GetSystemDirectoryW(NULL, 0): %s err=%s", rel_len(r, wneed), le());
    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetSystemDirectoryW(w, (UINT)wneed);
    line("GetSystemDirectoryW(length): %s buffer untouched: %s err=%s", rel_len(r, wneed), yesno(untouched_w(w, MAX_PATH + 8)), le());
    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetSystemDirectoryW(w, (UINT)wneed + 1);
    line("GetSystemDirectoryW(length + 1): %s path=%s err=%s", rel_len(r, wneed), shown_w(w, MAX_PATH + 8), le());

    widen(wa, MAX_PATH + 8, full);
    line("the W path is the A path widened: %s", yesno(wcscmp(wa, wfull) == 0));
}

/* ------------------------------------------------------------------ */

static char tp_dir[MAX_PATH];       /* <cwd>\tpdir, made at the start */
static char tp_dirs[MAX_PATH];      /* <cwd>\tpdir\ */
static char tp_none[MAX_PATH];      /* <cwd>\tpnone, removed at the start */
static char tp_env[MAX_PATH];       /* <cwd>\tpenv, made at the start: TEMP */
static char tp_prof[MAX_PATH];      /* <cwd>\tpprof, made at the start: USERPROFILE */

static void tp_set(const char *name, const char *value)
{
    SetEnvironmentVariableA(name, value);
}

/* Set TMP, TEMP and USERPROFILE (NULL: removed), then GetTempPathA and W. */
static void tp_case(const char *tmp, const char *temp, const char *prof)
{
    char a[MAX_PATH + 8];
    WCHAR w[MAX_PATH + 8];
    DWORD r;

    tp_set("TMP", tmp);
    tp_set("TEMP", temp);
    tp_set("USERPROFILE", prof);
    line("TMP=%s TEMP=%s USERPROFILE=%s", tmp ? pa(tmp) : "(unset)", temp ? pa(temp) : "(unset)",
         prof ? pa(prof) : "(unset)");

    fill_a(a, sizeof a);
    arm();
    r = GetTempPathA(MAX_PATH, a);
    line("GetTempPathA: %s path=%s err=%s", rel_len(r, untouched_a(a, sizeof a) ? 0 : strlen(a)), shown_a(a, sizeof a), le());

    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetTempPathW(MAX_PATH, w);
    line("GetTempPathW: %s path=%s err=%s", rel_len(r, untouched_w(w, MAX_PATH + 8) ? 0 : wcslen(w)), shown_w(w, MAX_PATH + 8), le());
}

static void sec_temppath(void)
{
    char a[MAX_PATH + 8];
    WCHAR w[MAX_PATH + 8];
    DWORD r;
    size_t need, wneed;

    at_cwd(tp_dir, "tpdir");
    sprintf(tp_dirs, "%s\\", tp_dir);
    at_cwd(tp_none, "tpnone");
    at_cwd(tp_env, "tpenv");
    at_cwd(tp_prof, "tpprof");
    CreateDirectoryA(tp_dir, NULL);
    CreateDirectoryA(tp_env, NULL);
    CreateDirectoryA(tp_prof, NULL);
    RemoveDirectoryA(tp_none);

    tp_case(tp_dir, tp_env, tp_prof);
    tp_case(tp_dirs, tp_env, tp_prof);
    tp_case(tp_none, tp_env, tp_prof);
    tp_case("tprel", tp_env, tp_prof);
    tp_case("", tp_env, tp_prof);
    tp_case(NULL, tp_env, tp_prof);
    tp_case(NULL, NULL, tp_prof);
    tp_case(NULL, NULL, NULL);

    /* The buffer's size, with TMP the existing directory: its length
     * (as the full call returns it) is the path's, without a NUL. */
    tp_set("TMP", tp_dir);
    tp_set("TEMP", tp_env);
    tp_set("USERPROFILE", tp_prof);
    line("TMP=%s TEMP=%s USERPROFILE=%s", pa(tp_dir), pa(tp_env), pa(tp_prof));

    fill_a(a, sizeof a);
    GetTempPathA(MAX_PATH, a);
    need = strlen(a);
    fill_a(a, sizeof a);
    arm();
    r = GetTempPathA(0, a);
    line("GetTempPathA(0): %s buffer untouched: %s err=%s", rel_len(r, need), yesno(untouched_a(a, sizeof a)), le());
    fill_a(a, sizeof a);
    arm();
    r = GetTempPathA(3, a);
    line("GetTempPathA(3): %s buffer untouched: %s err=%s", rel_len(r, need), yesno(untouched_a(a, sizeof a)), le());
    fill_a(a, sizeof a);
    arm();
    r = GetTempPathA((DWORD)need, a);
    line("GetTempPathA(length): %s buffer untouched: %s err=%s", rel_len(r, need), yesno(untouched_a(a, sizeof a)), le());
    fill_a(a, sizeof a);
    arm();
    r = GetTempPathA((DWORD)need + 1, a);
    line("GetTempPathA(length + 1): %s path=%s err=%s", rel_len(r, need), shown_a(a, sizeof a), le());

    fill_w(w, MAX_PATH + 8);
    GetTempPathW(MAX_PATH, w);
    wneed = wcslen(w);
    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetTempPathW(0, w);
    line("GetTempPathW(0): %s buffer untouched: %s err=%s", rel_len(r, wneed), yesno(untouched_w(w, MAX_PATH + 8)), le());
    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetTempPathW(3, w);
    line("GetTempPathW(3): %s buffer untouched: %s err=%s", rel_len(r, wneed), yesno(untouched_w(w, MAX_PATH + 8)), le());
    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetTempPathW((DWORD)wneed, w);
    line("GetTempPathW(length): %s buffer untouched: %s err=%s", rel_len(r, wneed), yesno(untouched_w(w, MAX_PATH + 8)), le());
    fill_w(w, MAX_PATH + 8);
    arm();
    r = GetTempPathW((DWORD)wneed + 1, w);
    line("GetTempPathW(length + 1): %s path=%s err=%s", rel_len(r, wneed), shown_w(w, MAX_PATH + 8), le());

    RemoveDirectoryA(tp_dir);
    RemoveDirectoryA(tp_env);
    RemoveDirectoryA(tp_prof);
}

/* ------------------------------------------------------------------ */

static char tf_dir[MAX_PATH];       /* <cwd>\tfdir, emptied at the start */
static char tf_dirs[MAX_PATH];      /* <cwd>\tfdir\ */
static char tf_none[MAX_PATH];      /* <cwd>\tfnone, removed at the start */

/* Delete every file in tf_dir. */
static void tf_empty(void)
{
    char pattern[MAX_PATH + 8];
    char path[2 * MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    sprintf(pattern, "%s\\*", tf_dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            sprintf(path, "%s\\%s", tf_dir, fd.cFileName);
            DeleteFileA(path);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* A name with uUnique nonzero: its number is the caller's, so it prints
 * as returned; whether a file by that name exists. */
static void tf_a(const char *path, const char *pre, UINT u)
{
    char name[MAX_PATH + 8];
    UINT r;
    const char *e;

    fill_a(name, sizeof name);
    arm();
    r = GetTempFileNameA(path, pre, u, name);
    e = le();
    line("GetTempFileNameA(%s, \"%s\", 0x%X): ret=0x%X name=%s err=%s", pa(path), pre, u, r,
         shown_a(name, sizeof name), e);
    if (!untouched_a(name, sizeof name)) {
        line("  file exists: %s", yesno(GetFileAttributesA(name) != INVALID_FILE_ATTRIBUTES));
    }
}

static void tf_w(const WCHAR *path, const WCHAR *pre, UINT u)
{
    WCHAR name[MAX_PATH + 8];
    UINT r;
    const char *e;

    fill_w(name, MAX_PATH + 8);
    arm();
    r = GetTempFileNameW(path, pre, u, name);
    e = le();
    line("GetTempFileNameW(%s, \"%s\", 0x%X): ret=0x%X name=%s err=%s", pw(path), ws(pre), u, r,
         shown_w(name, MAX_PATH + 8), e);
    if (!untouched_w(name, MAX_PATH + 8)) {
        line("  file exists: %s", yesno(GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES));
    }
}

static int is_hex(int c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static unsigned hex_value(int c)
{
    if (c >= '0' && c <= '9') {
        return (unsigned)(c - '0');
    }
    return (unsigned)(upper(c) - 'A' + 10);
}

/* A name GetTempFileName numbered itself, as printed: its directory as a
 * path, then the prefix's `pre` characters as returned, the number as
 * <hex>, the rest as returned. Its digit count and value come back. */
static const char *tf_shape(const char *name, size_t pre, int *digits, unsigned long *value)
{
    static char b[2 * MAX_PATH + 32];
    char dir[MAX_PATH + 8];
    const char *slash = strrchr(name, '\\');
    const char *p;
    size_t i;

    *digits = 0;
    *value = 0;
    if (slash == NULL) {
        _snprintf(b, sizeof b - 1, "%s (no backslash)", name);
        b[sizeof b - 1] = '\0';
        return b;
    }
    memcpy(dir, name, (size_t)(slash - name));
    dir[slash - name] = '\0';
    p = slash + 1;
    for (i = 0; i < pre && p[i] != '\0'; i++) {
    }
    p += i;
    while (is_hex((unsigned char)*p)) {
        *value = *value * 16 + hex_value((unsigned char)*p);
        (*digits)++;
        p++;
    }
    _snprintf(b, sizeof b - 1, "%s\\%.*s<hex>%s", pa(dir), (int)i, slash + 1, p);
    b[sizeof b - 1] = '\0';
    return b;
}

/* uUnique 0: GetTempFileNameA numbers the name and creates the file. The
 * name comes back in `out` ("" when the call left the buffer alone). */
static void tf0_a(const char *path, char *out)
{
    char name[MAX_PATH + 8];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    UINT r;
    const char *e;
    int digits;
    unsigned long value;
    const char *shape;
    char size[24];

    out[0] = '\0';
    fill_a(name, sizeof name);
    arm();
    r = GetTempFileNameA(path, "abc", 0, name);
    e = le();
    if (untouched_a(name, sizeof name)) {
        line("GetTempFileNameA(%s, \"abc\", 0): %s name=(untouched) err=%s", pa(path),
             r == 0 ? "ret=0" : "ret nonzero", e);
        return;
    }
    strcpy(out, name);
    shape = tf_shape(name, 3, &digits, &value);
    line("GetTempFileNameA(%s, \"abc\", 0): %s name=%s err=%s", pa(path), r == 0 ? "ret=0" : "ret nonzero",
         shape, e);
    if (r == 0) {
        line("  file exists: %s", yesno(GetFileAttributesA(name) != INVALID_FILE_ATTRIBUTES));
        return;
    }
    h = FindFirstFileA(name, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        sprintf(size, "%lu", fd.nFileSizeLow);
        FindClose(h);
    } else {
        strcpy(size, "(no file)");
    }
    line("  1 to 4 hex digits: %s, the return is its number: %s, file exists: %s, size: %s",
         yesno(digits >= 1 && digits <= 4), yesno(value == r),
         yesno(GetFileAttributesA(name) != INVALID_FILE_ATTRIBUTES), size);
}

static void tf0_w(const WCHAR *path, WCHAR *out)
{
    WCHAR name[MAX_PATH + 8];
    char nname[2 * MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    UINT r;
    const char *e;
    int digits;
    unsigned long value;
    const char *shape;
    char size[24];

    out[0] = 0;
    fill_w(name, MAX_PATH + 8);
    arm();
    r = GetTempFileNameW(path, L"abc", 0, name);
    e = le();
    if (untouched_w(name, MAX_PATH + 8)) {
        line("GetTempFileNameW(%s, \"abc\", 0): %s name=(untouched) err=%s", pw(path),
             r == 0 ? "ret=0" : "ret nonzero", e);
        return;
    }
    wcscpy(out, name);
    narrow(nname, (int)sizeof nname, name);
    shape = tf_shape(nname, 3, &digits, &value);
    line("GetTempFileNameW(%s, \"abc\", 0): %s name=%s err=%s", pw(path), r == 0 ? "ret=0" : "ret nonzero",
         shape, e);
    if (r == 0) {
        line("  file exists: %s", yesno(GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES));
        return;
    }
    h = FindFirstFileW(name, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        sprintf(size, "%lu", fd.nFileSizeLow);
        FindClose(h);
    } else {
        strcpy(size, "(no file)");
    }
    line("  1 to 4 hex digits: %s, the return is its number: %s, file exists: %s, size: %s",
         yesno(digits >= 1 && digits <= 4), yesno(value == r),
         yesno(GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES), size);
}

static void sec_tempfile(void)
{
    WCHAR wdir[MAX_PATH], wdirs[MAX_PATH], wnone[MAX_PATH];
    char n1[MAX_PATH + 8], n2[MAX_PATH + 8];
    WCHAR wn1[MAX_PATH + 8], wn2[MAX_PATH + 8];

    at_cwd(tf_dir, "tfdir");
    sprintf(tf_dirs, "%s\\", tf_dir);
    at_cwd(tf_none, "tfnone");
    CreateDirectoryA(tf_dir, NULL);
    tf_empty();
    RemoveDirectoryA(tf_none);
    widen(wdir, MAX_PATH, tf_dir);
    widen(wdirs, MAX_PATH, tf_dirs);
    widen(wnone, MAX_PATH, tf_none);

    tf_a(tf_dir, "abc", 0x1234);
    tf_a(tf_dir, "abcdef", 0x1234);
    tf_a(tf_dir, "", 0x1234);
    tf_a(tf_dir, "abc", 0xABCD);
    tf_a(tf_dir, "abc", 0x12345);
    tf_a(tf_dirs, "abc", 0x1234);
    tf_a(tf_none, "abc", 0x1234);

    tf_w(wdir, L"abc", 0x1234);
    tf_w(wdir, L"abcdef", 0x1234);
    tf_w(wdir, L"", 0x1234);
    tf_w(wdir, L"abc", 0xABCD);
    tf_w(wdir, L"abc", 0x12345);
    tf_w(wdirs, L"abc", 0x1234);
    tf_w(wnone, L"abc", 0x1234);

    tf0_a(tf_dir, n1);
    tf0_a(tf_dir, n2);
    line("the second name differs: %s", yesno(strcmp(n1, n2) != 0));
    if (n1[0] != '\0') {
        DeleteFileA(n1);
    }
    if (n2[0] != '\0') {
        DeleteFileA(n2);
    }
    tf0_a(tf_none, n1);
    if (n1[0] != '\0') {
        DeleteFileA(n1);
    }

    tf0_w(wdir, wn1);
    tf0_w(wdir, wn2);
    line("the second name differs (W): %s", yesno(wcscmp(wn1, wn2) != 0));
    if (wn1[0] != 0) {
        DeleteFileW(wn1);
    }
    if (wn2[0] != 0) {
        DeleteFileW(wn2);
    }
    tf0_w(wnone, wn1);
    if (wn1[0] != 0) {
        DeleteFileW(wn1);
    }

    tf_empty();
    RemoveDirectoryA(tf_dir);
}

/* ------------------------------------------------------------------ */

/* Fixed UTC times, as FILETIME halves (low, high). */
static const struct {
    DWORD lo, hi;
    const char *name;
} ft_values[] = {
    { 0x256D4000, 0x01BF53EB, "2000-01-01 00:00:00" },
    { 0xE1D0A000, 0x01BFE353, "2000-07-01 12:00:00" },
    { 0xEA7BA400, 0x01B4A008, "1990-06-15 06:30:00" },
    { 0x1846C007, 0x01E21592, "2030-12-31 23:59:59.1234567" },
};

#define TICKS_PER_MINUTE 600000000

static unsigned __int64 ft64(const FILETIME *f)
{
    return ((unsigned __int64)f->dwHighDateTime << 32) | f->dwLowDateTime;
}

static void sec_filetime(void)
{
    FILETIME in, loc, back, utc, x, first_utc;
    BOOL r1, r2, r3;
    DWORD e1, e2, e3;
    __int64 to_local, to_utc, first_shift = 0;
    int same_shift = 1;
    int i;

    memset(&first_utc, 0, sizeof first_utc);
    for (i = 0; i < (int)(sizeof ft_values / sizeof ft_values[0]); i++) {
        in.dwLowDateTime = ft_values[i].lo;
        in.dwHighDateTime = ft_values[i].hi;

        arm();
        r1 = FileTimeToLocalFileTime(&in, &loc);
        e1 = GetLastError();
        arm();
        r2 = LocalFileTimeToFileTime(&loc, &back);
        e2 = GetLastError();
        line("%s UTC: FileTimeToLocalFileTime ret=%d err=%s, back with LocalFileTimeToFileTime ret=%d err=%s, the original: %s",
             ft_values[i].name, r1, le_of(e1), r2, le_of(e2), yesno(ft64(&back) == ft64(&in)));

        arm();
        r3 = LocalFileTimeToFileTime(&in, &utc);
        e3 = GetLastError();
        to_local = (__int64)(ft64(&loc) - ft64(&in));
        to_utc = (__int64)(ft64(&utc) - ft64(&in));
        line("%s local: LocalFileTimeToFileTime ret=%d err=%s, its shift the negative of FileTimeToLocalFileTime's: %s, whole minutes: %s",
             ft_values[i].name, r3, le_of(e3), yesno(to_utc == -to_local),
             yesno(to_utc % TICKS_PER_MINUTE == 0));
        if (i == 0) {
            first_shift = to_utc;
            first_utc = utc;
        } else if (to_utc != first_shift) {
            same_shift = 0;
        }
    }
    line("the same shift for every value: %s", yesno(same_shift));

    x.dwLowDateTime = ft_values[0].lo;
    x.dwHighDateTime = ft_values[0].hi;
    arm();
    r3 = LocalFileTimeToFileTime(&x, &x);
    line("LocalFileTimeToFileTime in place: ret=%d err=%s, the same result: %s", r3, le(),
         yesno(ft64(&x) == ft64(&first_utc)));
}

/* ------------------------------------------------------------------ */

static void sec_version(void)
{
    DWORD v0, vself, vbad;
    const char *e;

    arm();
    v0 = GetProcessVersion(0);
    line("GetProcessVersion(0) = 0x%08lX err=%s", v0, le());
    arm();
    vself = GetProcessVersion(GetCurrentProcessId());
    e = le();
    line("GetProcessVersion(own id) = 0x%08lX err=%s, the same as for 0: %s", vself, e, yesno(vself == v0));
    arm();
    vbad = GetProcessVersion(3);
    line("GetProcessVersion(3) = 0x%08lX err=%s", vbad, le());
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "muldiv", sec_muldiv, F2KT_ALWAYS },
    { "dbcs", sec_dbcs, F2KT_ALWAYS },
    { "stringtype", sec_stringtype, F2KT_ALWAYS },
    { "langid", sec_langid, F2KT_ALWAYS },
    { "sysdir", sec_sysdir, F2KT_ALWAYS },
    { "temppath", sec_temppath, F2KT_ALWAYS },
    { "tempfile", sec_tempfile, F2KT_ALWAYS },
    { "filetime", sec_filetime, F2KT_ALWAYS },
    { "version", sec_version, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetCurrentDirectoryA(MAX_PATH, cwd_raw);
    strcpy(cwd_a, cwd_raw);
    strip_slash_a(cwd_a);
    GetWindowsDirectoryA(win_a, MAX_PATH);
    strip_slash_a(win_a);
    GetCurrentDirectoryW(MAX_PATH, cwd_w);
    strip_slash_w(cwd_w);
    GetWindowsDirectoryW(win_w, MAX_PATH);
    strip_slash_w(win_w);
    return run_sections("utility", sections, argc, argv);
}
