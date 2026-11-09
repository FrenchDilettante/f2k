/*
 * profile - kernel32's profile functions: win.ini through
 * GetProfileIntA/W, GetProfileStringA/W and WriteProfileStringA/W, and
 * a private .ini through GetPrivateProfileStringA/W,
 * GetPrivateProfileIntA/W, GetPrivateProfileSectionA/W,
 * GetPrivateProfileSectionNamesA/W, WritePrivateProfileStringA/W and
 * WritePrivateProfileSectionA/W.
 *
 * win.ini is touched only through one section, [F2KProfile], named
 * after the fixture: every section that uses it removes it
 * (WriteProfileStringW(L"F2KProfile", NULL, NULL), unprinted) at its
 * start and at its end. No other win.ini section's keys or values are
 * read (they are the machine's); the list of win.ini's section names
 * prints only as whether F2KProfile is among them.
 *
 * The private file is profile.ini, beside the program and checked in
 * with it (CRLF line ends): a key before any section, comments, blanks
 * around keys and values, quoted values, numbers in several forms, an
 * empty value, a line without '=', a key repeated in another case, a
 * section repeated in another case, an empty section and a section
 * name with blanks inside its brackets. The program only reads it. The
 * write section works on profwork.ini, a copy it makes with CopyFileA,
 * and the new section on profnew.ini and profneww.ini, which only the
 * writes create; every scratch file is deleted (unprinted) at the
 * section's start and end. Every file is named by a full path, the
 * program's own directory (GetModuleFileNameA/W) and the file's name:
 * a name without a path would mean one in the Windows directory. No
 * path prints.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=. A string read back prints between brackets, its first
 * ret+2 units (at most the buffer's size), a NUL as '|' and a unit the
 * call left as the program filled it (with '#') as '#': so a list's
 * terminators and a short buffer's truncation both show. A file's bytes
 * after a write print line by line ("| " and the line, its CR LF
 * dropped), a byte below 0x20 or above 0x7E as \xNN, then whether the
 * file ends with CR LF.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   winini    [F2KProfile] in win.ini: GetProfileIntW/A and
 *             GetProfileStringW/A of a key not there (the defaults);
 *             WriteProfileStringW/A of values "1", "  42  ", "-5",
 *             "0x10", "12abc", "abc" and a quoted string, each read
 *             back by GetProfileIntW/A and GetProfileStringW/A; short
 *             buffers; the key list (a NULL key); a key deleted (a NULL
 *             value); the section names (NULL section and key), as
 *             F2KProfile among them or not, before and after the
 *             section is deleted (a NULL key)
 *   read      GetPrivateProfileStringA/W over profile.ini: each key of
 *             [First], other cases of the section and key names, the
 *             repeated section, a commented-out key, the padded
 *             section name, defaults (with trailing blanks, NULL),
 *             short buffers (5, 1 and 0 units), the key list of a
 *             section and the section list (NULL key, NULL section) in
 *             full and short, and a file that does not exist
 *   int       GetPrivateProfileIntA/W over [First]'s keys: 42, -7,
 *             0x1F, 12abc, a word, blanks, empty, missing (the
 *             default), and a missing file
 *   sections  GetPrivateProfileSectionA/W of [First], [Second],
 *             [Empty] and a missing section, in full and in a short
 *             buffer; GetPrivateProfileSectionNamesA/W in full and in a
 *             short buffer
 *   write     on profwork.ini (profile.ini's copy):
 *             WritePrivateProfileStringA/W adding a key, replacing one,
 *             deleting one (NULL value), deleting a section (NULL key),
 *             adding a section, writing into the repeated section;
 *             WritePrivateProfileSectionA/W filling the empty section
 *             and replacing one; the file's bytes after each step
 *   new       WritePrivateProfileStringA creating profnew.ini, and
 *             WritePrivateProfileStringW creating profneww.ini, each
 *             file's bytes; WritePrivateProfileStringW of U+00E9 and
 *             U+4E00 into each, the bytes, and both read back by
 *             GetPrivateProfileStringW and GetPrivateProfileStringA; a
 *             write into a directory that does not exist
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat profile):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% profile.c
 */

#include "../common/f2kt.h"

#define WIN_SECTION_A "F2KProfile"
#define WIN_SECTION_W L"F2KProfile"

/* The full paths of the files beside the program. */
static char ini_a[MAX_PATH + 16];
static WCHAR ini_w[MAX_PATH + 16];
static char work_a[MAX_PATH + 16];
static WCHAR work_w[MAX_PATH + 16];
static char new_a[MAX_PATH + 16];
static WCHAR new_w[MAX_PATH + 16];
static char neww_a[MAX_PATH + 16];
static WCHAR neww_w[MAX_PATH + 16];
static char none_a[MAX_PATH + 16];
static WCHAR none_w[MAX_PATH + 16];
static char nodir_a[MAX_PATH + 32];

/* A large buffer for win.ini's section names and the file dumps. */
static char big_a[32768];
static WCHAR big_w[16384];

/* The program's directory with `name` appended, into out (A form). */
static void beside_a(const char *name, char *out)
{
    char *slash;

    out[0] = '\0';
    if (GetModuleFileNameA(NULL, out, MAX_PATH) == 0) {
        out[0] = '\0';
    }
    slash = strrchr(out, '\\');
    if (slash != NULL) {
        slash[1] = '\0';
    } else {
        out[0] = '\0';
    }
    strcat(out, name);
}

/* The same, W form. */
static void beside_w(const WCHAR *name, WCHAR *out)
{
    WCHAR *slash;

    out[0] = 0;
    if (GetModuleFileNameW(NULL, out, MAX_PATH) == 0) {
        out[0] = 0;
    }
    slash = wcsrchr(out, L'\\');
    if (slash != NULL) {
        slash[1] = 0;
    } else {
        out[0] = 0;
    }
    wcscat(out, name);
}

static void paths(void)
{
    beside_a("profile.ini", ini_a);
    beside_w(L"profile.ini", ini_w);
    beside_a("profwork.ini", work_a);
    beside_w(L"profwork.ini", work_w);
    beside_a("profnew.ini", new_a);
    beside_w(L"profnew.ini", new_w);
    beside_a("profneww.ini", neww_a);
    beside_w(L"profneww.ini", neww_w);
    beside_a("profnone.ini", none_a);
    beside_w(L"profnone.ini", none_w);
    beside_a("profnodir\\profile.ini", nodir_a);
}

/* An argument as printed: NULL, or the string in quotes. */
static const char *show_a(const char *s)
{
    static char bufs[4][160];
    static int next;
    char *b = bufs[next++ & 3];

    if (s == NULL) {
        return "NULL";
    }
    _snprintf(b, sizeof bufs[0] - 1, "\"%s\"", s);
    b[sizeof bufs[0] - 1] = '\0';
    return b;
}

static const char *show_w(const WCHAR *s)
{
    static char bufs[4][160];
    static int next;
    char *b = bufs[next++ & 3];

    if (s == NULL) {
        return "NULL";
    }
    _snprintf(b, sizeof bufs[0] - 1, "L\"%s\"", ws(s));
    b[sizeof bufs[0] - 1] = '\0';
    return b;
}

/* A byte as printed: itself, or \xNN below 0x20 and above 0x7E. */
static int esc_byte(char *b, unsigned char c)
{
    if (c < 0x20 || c > 0x7E) {
        return sprintf(b, "\\x%02X", c);
    }
    b[0] = (char)c;
    return 1;
}

/* What a call left in a buffer: its first `count` units (at most
 * `size`), a NUL as '|', anything else escaped. */
static const char *got_a(const char *buf, DWORD count, DWORD size)
{
    static char bufs[2][2048];
    static int next;
    char *b = bufs[next++ & 1];
    DWORD i;
    int n = 0;

    if (count > size) {
        count = size;
    }
    for (i = 0; i < count && n < (int)sizeof bufs[0] - 8; i++) {
        if (buf[i] == '\0') {
            b[n++] = '|';
        } else {
            n += esc_byte(b + n, (unsigned char)buf[i]);
        }
    }
    b[n] = '\0';
    return b;
}

static const char *got_w(const WCHAR *buf, DWORD count, DWORD size)
{
    static WCHAR copy[1024];
    DWORD i;

    if (count > size) {
        count = size;
    }
    if (count > 1023) {
        count = 1023;
    }
    for (i = 0; i < count; i++) {
        copy[i] = buf[i] == 0 ? L'|' : buf[i];
    }
    copy[count] = 0;
    return ws(copy);
}

/* Fill a wide buffer with '#', so the units a call leaves show. */
static void fill_w(WCHAR *buf, DWORD count)
{
    DWORD i;

    for (i = 0; i < count; i++) {
        buf[i] = L'#';
    }
}

/* Remove the scratch files and win.ini's section, unprinted. */
static void tidy(void)
{
    DeleteFileA(work_a);
    DeleteFileA(new_a);
    DeleteFileA(neww_a);
    DeleteFileA(none_a);
    WriteProfileStringW(WIN_SECTION_W, NULL, NULL);
}

/* A file's bytes, line by line. */
static void dump(const char *what, const char *path)
{
    HANDLE f;
    DWORD size = 0;
    DWORD i;
    BOOL ok;
    char text[1024];
    int n = 0;

    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        line("%s: absent (err=%lu)", what, GetLastError());
        return;
    }
    ok = ReadFile(f, big_a, sizeof big_a, &size, NULL);
    CloseHandle(f);
    if (!ok) {
        line("%s: unreadable", what);
        return;
    }
    line("%s: %lu bytes", what, size);
    for (i = 0; i < size; i++) {
        if (big_a[i] == '\r' && i + 1 < size && big_a[i + 1] == '\n') {
            text[n] = '\0';
            line("| %s", text);
            n = 0;
            i++;
            continue;
        }
        if (n < (int)sizeof text - 8) {
            n += esc_byte(text + n, (unsigned char)big_a[i]);
        }
    }
    if (n > 0) {
        text[n] = '\0';
        line("| %s", text);
    }
    line("%s ends with CR LF: %s", what,
         yesno(size >= 2 && big_a[size - 2] == '\r' && big_a[size - 1] == '\n'));
}

/* --- winini -------------------------------------------------------- */

/* Whether a list of NUL-terminated names holds F2KProfile (any case). */
static int among_w(const WCHAR *list, DWORD count)
{
    DWORD i = 0;

    while (i < count && list[i] != 0) {
        if (_wcsicmp(list + i, WIN_SECTION_W) == 0) {
            return 1;
        }
        i += (DWORD)wcslen(list + i) + 1;
    }
    return 0;
}

static void win_names(void)
{
    DWORD r;

    arm();
    r = GetProfileStringW(NULL, NULL, L"", big_w, sizeof big_w / sizeof big_w[0]);
    line("GetProfileStringW(NULL, NULL, L\"\", 16384): ret>0 %s err=%s F2KProfile among them: %s",
         yesno(r > 0), le(), yesno(among_w(big_w, r)));
}

static void win_value_w(const WCHAR *value)
{
    BOOL w;
    UINT i;
    DWORD r;
    WCHAR buf[64];

    arm();
    w = WriteProfileStringW(WIN_SECTION_W, L"Value", value);
    line("WriteProfileStringW(L\"F2KProfile\", L\"Value\", %s): ret=%d err=%s", show_w(value), w,
         le());
    arm();
    i = GetProfileIntW(WIN_SECTION_W, L"Value", 99);
    line("  GetProfileIntW(..., L\"Value\", 99): ret=%d err=%s", (int)i, le());
    fill_w(buf, sizeof buf / sizeof buf[0]);
    arm();
    r = GetProfileStringW(WIN_SECTION_W, L"Value", L"dflt", buf, 64);
    line("  GetProfileStringW(..., L\"Value\", L\"dflt\", 64): ret=%lu err=%s [%s]", r, le(),
         got_w(buf, r + 2, 64));
}

static void win_value_a(const char *value)
{
    BOOL w;
    UINT i;
    DWORD r;
    char buf[64];

    arm();
    w = WriteProfileStringA(WIN_SECTION_A, "Value", value);
    line("WriteProfileStringA(\"F2KProfile\", \"Value\", %s): ret=%d err=%s", show_a(value), w, le());
    arm();
    i = GetProfileIntA(WIN_SECTION_A, "Value", 99);
    line("  GetProfileIntA(..., \"Value\", 99): ret=%d err=%s", (int)i, le());
    memset(buf, '#', sizeof buf);
    arm();
    r = GetProfileStringA(WIN_SECTION_A, "Value", "dflt", buf, 64);
    line("  GetProfileStringA(..., \"Value\", \"dflt\", 64): ret=%lu err=%s [%s]", r, le(),
         got_a(buf, r + 2, 64));
}

static void sec_winini(void)
{
    UINT i;
    DWORD r;
    BOOL w;
    WCHAR bw[64];
    char ba[64];

    tidy();

    arm();
    i = GetProfileIntW(WIN_SECTION_W, L"Mode", 7);
    line("GetProfileIntW(L\"F2KProfile\", L\"Mode\", 7), no such key: ret=%d err=%s", (int)i, le());
    arm();
    i = GetProfileIntA(WIN_SECTION_A, "Mode", 7);
    line("GetProfileIntA(\"F2KProfile\", \"Mode\", 7), no such key: ret=%d err=%s", (int)i, le());
    fill_w(bw, sizeof bw / sizeof bw[0]);
    arm();
    r = GetProfileStringW(WIN_SECTION_W, L"Mode", L"dflt", bw, 64);
    line("GetProfileStringW(L\"F2KProfile\", L\"Mode\", L\"dflt\", 64), no such key: ret=%lu err=%s [%s]",
         r, le(), got_w(bw, r + 2, 64));
    memset(ba, '#', sizeof ba);
    arm();
    r = GetProfileStringA(WIN_SECTION_A, "Mode", "dflt", ba, 64);
    line("GetProfileStringA(\"F2KProfile\", \"Mode\", \"dflt\", 64), no such key: ret=%lu err=%s [%s]",
         r, le(), got_a(ba, r + 2, 64));
    win_names();

    arm();
    w = WriteProfileStringW(WIN_SECTION_W, L"Mode", L"1");
    line("WriteProfileStringW(L\"F2KProfile\", L\"Mode\", L\"1\"): ret=%d err=%s", w, le());
    arm();
    i = GetProfileIntW(WIN_SECTION_W, L"Mode", 7);
    line("GetProfileIntW(L\"F2KProfile\", L\"Mode\", 7): ret=%d err=%s", (int)i, le());
    arm();
    i = GetProfileIntA(WIN_SECTION_A, "mode", 7);
    line("GetProfileIntA(\"F2KProfile\", \"mode\", 7): ret=%d err=%s", (int)i, le());
    win_names();

    win_value_w(L"  42  ");
    win_value_w(L"-5");
    win_value_w(L"0x10");
    win_value_w(L"12abc");
    win_value_w(L"abc");
    win_value_w(L"\"quoted value\"");
    win_value_w(L"");
    win_value_a("  42  ");
    win_value_a("-5");
    win_value_a("0x10");
    win_value_a("ansi text");

    /* Short buffers over "ansi text". */
    fill_w(bw, sizeof bw / sizeof bw[0]);
    arm();
    r = GetProfileStringW(WIN_SECTION_W, L"Value", L"dflt", bw, 5);
    line("GetProfileStringW(..., L\"Value\", L\"dflt\", 5): ret=%lu err=%s [%s]", r, le(),
         got_w(bw, r + 2, 64));
    memset(ba, '#', sizeof ba);
    arm();
    r = GetProfileStringA(WIN_SECTION_A, "Value", "dflt", ba, 5);
    line("GetProfileStringA(..., \"Value\", \"dflt\", 5): ret=%lu err=%s [%s]", r, le(),
         got_a(ba, r + 2, 64));

    /* The key list. */
    fill_w(bw, sizeof bw / sizeof bw[0]);
    arm();
    r = GetProfileStringW(WIN_SECTION_W, NULL, L"", bw, 64);
    line("GetProfileStringW(L\"F2KProfile\", NULL, L\"\", 64): ret=%lu err=%s [%s]", r, le(),
         got_w(bw, r + 2, 64));
    memset(ba, '#', sizeof ba);
    arm();
    r = GetProfileStringA(WIN_SECTION_A, NULL, "", ba, 64);
    line("GetProfileStringA(\"F2KProfile\", NULL, \"\", 64): ret=%lu err=%s [%s]", r, le(),
         got_a(ba, r + 2, 64));

    /* A key deleted. */
    arm();
    w = WriteProfileStringA(WIN_SECTION_A, "Mode", NULL);
    line("WriteProfileStringA(\"F2KProfile\", \"Mode\", NULL): ret=%d err=%s", w, le());
    arm();
    i = GetProfileIntW(WIN_SECTION_W, L"Mode", 7);
    line("GetProfileIntW(L\"F2KProfile\", L\"Mode\", 7): ret=%d err=%s", (int)i, le());
    fill_w(bw, sizeof bw / sizeof bw[0]);
    arm();
    r = GetProfileStringW(WIN_SECTION_W, NULL, L"", bw, 64);
    line("GetProfileStringW(L\"F2KProfile\", NULL, L\"\", 64): ret=%lu err=%s [%s]", r, le(),
         got_w(bw, r + 2, 64));

    /* The section deleted. */
    arm();
    w = WriteProfileStringW(WIN_SECTION_W, NULL, NULL);
    line("WriteProfileStringW(L\"F2KProfile\", NULL, NULL): ret=%d err=%s", w, le());
    fill_w(bw, sizeof bw / sizeof bw[0]);
    arm();
    r = GetProfileStringW(WIN_SECTION_W, L"Value", L"dflt", bw, 64);
    line("GetProfileStringW(L\"F2KProfile\", L\"Value\", L\"dflt\", 64): ret=%lu err=%s [%s]", r,
         le(), got_w(bw, r + 2, 64));
    win_names();

    tidy();
}

/* --- read ---------------------------------------------------------- */

static void read_a(const char *section, const char *key, const char *dflt, DWORD size)
{
    char buf[512];
    DWORD r;

    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileStringA(section, key, dflt, buf, size, ini_a);
    line("GetPrivateProfileStringA(%s, %s, %s, %lu): ret=%lu err=%s [%s]", show_a(section),
         show_a(key), show_a(dflt), size, r, le(), got_a(buf, r + 2, size));
}

static void read_w(const WCHAR *section, const WCHAR *key, const WCHAR *dflt, DWORD size)
{
    WCHAR buf[512];
    DWORD r;

    fill_w(buf, sizeof buf / sizeof buf[0]);
    arm();
    r = GetPrivateProfileStringW(section, key, dflt, buf, size, ini_w);
    line("GetPrivateProfileStringW(%s, %s, %s, %lu): ret=%lu err=%s [%s]", show_w(section),
         show_w(key), show_w(dflt), size, r, le(), got_w(buf, r + 2, size));
}

static void sec_read(void)
{
    static const char *keys[] = {
        "Name", "Spaced", "Quoted", "Single", "Half", "Number", "Blank", "Empty", "NoEquals",
        "Orphan", NULL
    };
    char buf[64];
    WCHAR wbuf[64];
    DWORD r;
    int k;

    tidy();
    for (k = 0; keys[k] != NULL; k++) {
        read_a("First", keys[k], "dflt", 64);
    }
    read_a("FIRST", "name", "dflt", 64);
    read_a("first", "Again", "dflt", 64);
    read_a("First", "Again", "dflt", 64);
    read_a("Second", "Key", "dflt", 64);
    read_a("Second", "Hidden", "dflt", 64);
    read_a("Padded", "Inner", "dflt", 64);
    read_a(" Padded ", "Inner", "dflt", 64);
    read_a("Missing", "Name", "dflt", 64);
    read_a("First", "Missing", "dflt  ", 64);
    read_a("First", "Missing", NULL, 64);
    read_a("First", "Name", "dflt", 5);
    read_a("First", "Name", "dflt", 1);
    read_a("First", NULL, "", 512);
    read_a("First", NULL, "", 10);
    read_a(NULL, NULL, "", 512);
    read_a(NULL, NULL, "", 10);

    read_w(L"First", L"Name", L"dflt", 64);
    read_w(L"First", L"Spaced", L"dflt", 64);
    read_w(L"First", L"Quoted", L"dflt", 64);
    read_w(L"First", L"Single", L"dflt", 64);
    read_w(L"First", L"Empty", L"dflt", 64);
    read_w(L"FIRST", L"name", L"dflt", 64);
    read_w(L"first", L"Again", L"dflt", 64);
    read_w(L"Second", L"Hidden", L"dflt", 64);
    read_w(L"First", L"Missing", L"dflt  ", 64);
    read_w(L"First", L"Missing", NULL, 64);
    read_w(L"First", L"Name", L"dflt", 5);
    read_w(L"First", L"Name", L"dflt", 1);
    read_w(L"First", NULL, L"", 512);
    read_w(L"First", NULL, L"", 10);
    read_w(NULL, NULL, L"", 512);
    read_w(NULL, NULL, L"", 10);

    /* No buffer room at all: the buffer stays as the program filled it. */
    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileStringA("First", "Name", "dflt", buf, 0, ini_a);
    line("GetPrivateProfileStringA(\"First\", \"Name\", \"dflt\", 0): ret=%lu err=%s first byte "
         "untouched %s", r, le(), yesno(buf[0] == '#'));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    r = GetPrivateProfileStringW(L"First", L"Name", L"dflt", wbuf, 0, ini_w);
    line("GetPrivateProfileStringW(L\"First\", L\"Name\", L\"dflt\", 0): ret=%lu err=%s first unit "
         "untouched %s", r, le(), yesno(wbuf[0] == L'#'));

    /* A file that does not exist. */
    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileStringA("First", "Name", "dflt", buf, 64, none_a);
    line("GetPrivateProfileStringA(\"First\", \"Name\", \"dflt\", 64), no such file: ret=%lu err=%s [%s]",
         r, le(), got_a(buf, r + 2, 64));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    r = GetPrivateProfileStringW(L"First", L"Name", L"dflt", wbuf, 64, none_w);
    line("GetPrivateProfileStringW(L\"First\", L\"Name\", L\"dflt\", 64), no such file: ret=%lu err=%s "
         "[%s]", r, le(), got_w(wbuf, r + 2, 64));
    tidy();
}

/* --- int ----------------------------------------------------------- */

static void sec_int(void)
{
    static const char *keys_a[] = {
        "Number", "Negative", "Hex", "Lead", "Name", "Spaced", "Quoted", "Blank", "Empty",
        "NoEquals", "Missing", NULL
    };
    static const WCHAR *keys_w[] = {
        L"Number", L"Negative", L"Hex", L"Lead", L"Name", L"Blank", L"Empty", L"Missing", NULL
    };
    UINT r;
    int k;

    tidy();
    for (k = 0; keys_a[k] != NULL; k++) {
        arm();
        r = GetPrivateProfileIntA("First", keys_a[k], 99, ini_a);
        line("GetPrivateProfileIntA(\"First\", \"%s\", 99): ret=%d err=%s", keys_a[k], (int)r, le());
    }
    arm();
    r = GetPrivateProfileIntA("First", "Missing", -3, ini_a);
    line("GetPrivateProfileIntA(\"First\", \"Missing\", -3): ret=%d err=%s", (int)r, le());
    for (k = 0; keys_w[k] != NULL; k++) {
        arm();
        r = GetPrivateProfileIntW(L"First", keys_w[k], 99, ini_w);
        line("GetPrivateProfileIntW(L\"First\", L\"%s\", 99): ret=%d err=%s", ws(keys_w[k]), (int)r,
             le());
    }
    arm();
    r = GetPrivateProfileIntA("First", "Number", 99, none_a);
    line("GetPrivateProfileIntA(\"First\", \"Number\", 99), no such file: ret=%d err=%s", (int)r, le());
    arm();
    r = GetPrivateProfileIntW(L"First", L"Number", 99, none_w);
    line("GetPrivateProfileIntW(L\"First\", L\"Number\", 99), no such file: ret=%d err=%s", (int)r,
         le());
    tidy();
}

/* --- sections ------------------------------------------------------ */

static void section_a(const char *name, DWORD size)
{
    char buf[512];
    DWORD r;

    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileSectionA(name, buf, size, ini_a);
    line("GetPrivateProfileSectionA(%s, %lu): ret=%lu err=%s [%s]", show_a(name), size, r, le(),
         got_a(buf, r + 2, size));
}

static void section_w(const WCHAR *name, DWORD size)
{
    WCHAR buf[512];
    DWORD r;

    fill_w(buf, sizeof buf / sizeof buf[0]);
    arm();
    r = GetPrivateProfileSectionW(name, buf, size, ini_w);
    line("GetPrivateProfileSectionW(%s, %lu): ret=%lu err=%s [%s]", show_w(name), size, r, le(),
         got_w(buf, r + 2, size));
}

static void sec_sections(void)
{
    char buf[512];
    WCHAR wbuf[512];
    DWORD r;

    tidy();
    section_a("First", 512);
    section_a("first", 512);
    section_a("Second", 512);
    section_a("Empty", 512);
    section_a("Missing", 512);
    section_a("First", 20);
    section_w(L"First", 512);
    section_w(L"Second", 512);
    section_w(L"Empty", 512);
    section_w(L"Missing", 512);
    section_w(L"First", 20);

    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileSectionNamesA(buf, 512, ini_a);
    line("GetPrivateProfileSectionNamesA(512): ret=%lu err=%s [%s]", r, le(), got_a(buf, r + 2, 512));
    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileSectionNamesA(buf, 10, ini_a);
    line("GetPrivateProfileSectionNamesA(10): ret=%lu err=%s [%s]", r, le(), got_a(buf, r + 2, 10));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    r = GetPrivateProfileSectionNamesW(wbuf, 512, ini_w);
    line("GetPrivateProfileSectionNamesW(512): ret=%lu err=%s [%s]", r, le(), got_w(wbuf, r + 2, 512));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    r = GetPrivateProfileSectionNamesW(wbuf, 10, ini_w);
    line("GetPrivateProfileSectionNamesW(10): ret=%lu err=%s [%s]", r, le(), got_w(wbuf, r + 2, 10));
    memset(buf, '#', sizeof buf);
    arm();
    r = GetPrivateProfileSectionNamesA(buf, 512, none_a);
    line("GetPrivateProfileSectionNamesA(512), no such file: ret=%lu err=%s [%s]", r, le(),
         got_a(buf, r + 2, 512));
    tidy();
}

/* --- write --------------------------------------------------------- */

static void sec_write(void)
{
    BOOL r;

    tidy();
    if (!CopyFileA(ini_a, work_a, FALSE)) {
        line("CopyFileA(profile.ini, profwork.ini) failed: err=%lu", GetLastError());
        return;
    }
    SetFileAttributesA(work_a, FILE_ATTRIBUTE_NORMAL);
    dump("profwork.ini, copied", work_a);

    arm();
    r = WritePrivateProfileStringA("Second", "Added", "new value", work_a);
    line("WritePrivateProfileStringA(\"Second\", \"Added\", \"new value\"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringW(L"First", L"number", L" 43 ", work_w);
    line("WritePrivateProfileStringW(L\"First\", L\"number\", L\" 43 \"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringA("First", "Spaced", NULL, work_a);
    line("WritePrivateProfileStringA(\"First\", \"Spaced\", NULL): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringA("First", "NoEquals", "now set", work_a);
    line("WritePrivateProfileStringA(\"First\", \"NoEquals\", \"now set\"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringW(L"Second", NULL, NULL, work_w);
    line("WritePrivateProfileStringW(L\"Second\", NULL, NULL): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringA("Third", "Key", "in a new section", work_a);
    line("WritePrivateProfileStringA(\"Third\", \"Key\", \"in a new section\"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringA("first", "Again", "changed", work_a);
    line("WritePrivateProfileStringA(\"first\", \"Again\", \"changed\"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileStringA("Missing", "Key", NULL, work_a);
    line("WritePrivateProfileStringA(\"Missing\", \"Key\", NULL), no such section: ret=%d err=%s", r,
         le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileSectionA("Empty", "One=1\0Two = 2\0Bare\0", work_a);
    line("WritePrivateProfileSectionA(\"Empty\", \"One=1|Two = 2|Bare||\"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileSectionW(L"Third", L"Only=w\0", work_w);
    line("WritePrivateProfileSectionW(L\"Third\", L\"Only=w||\"): ret=%d err=%s", r, le());
    dump("profwork.ini", work_a);

    arm();
    r = WritePrivateProfileSectionA("Fourth", "Made=by section\0", work_a);
    line("WritePrivateProfileSectionA(\"Fourth\", \"Made=by section||\"), a new section: ret=%d err=%s",
         r, le());
    dump("profwork.ini", work_a);
    tidy();
}

/* --- new ----------------------------------------------------------- */

static void sec_new(void)
{
    BOOL r;
    DWORD n;
    WCHAR wbuf[64];
    char buf[64];

    tidy();
    arm();
    r = WritePrivateProfileStringA("New", "Key", "value", new_a);
    line("WritePrivateProfileStringA(\"New\", \"Key\", \"value\"), profnew.ini absent: ret=%d err=%s",
         r, le());
    dump("profnew.ini", new_a);
    arm();
    r = WritePrivateProfileStringW(L"New", L"Accent", L"caf\x00E9", new_w);
    line("WritePrivateProfileStringW(L\"New\", L\"Accent\", L\"caf<U+00E9>\"): ret=%d err=%s", r, le());
    arm();
    r = WritePrivateProfileStringW(L"New", L"Ideograph", L"x\x4E00y", new_w);
    line("WritePrivateProfileStringW(L\"New\", L\"Ideograph\", L\"x<U+4E00>y\"): ret=%d err=%s", r, le());
    dump("profnew.ini", new_a);

    arm();
    r = WritePrivateProfileStringW(L"New", L"Key", L"value", neww_w);
    line("WritePrivateProfileStringW(L\"New\", L\"Key\", L\"value\"), profneww.ini absent: ret=%d err=%s",
         r, le());
    dump("profneww.ini", neww_a);
    arm();
    r = WritePrivateProfileStringW(L"New", L"Accent", L"caf\x00E9", neww_w);
    line("WritePrivateProfileStringW(L\"New\", L\"Accent\", L\"caf<U+00E9>\"): ret=%d err=%s", r, le());
    arm();
    r = WritePrivateProfileStringW(L"New", L"Ideograph", L"x\x4E00y", neww_w);
    line("WritePrivateProfileStringW(L\"New\", L\"Ideograph\", L\"x<U+4E00>y\"): ret=%d err=%s", r, le());
    dump("profneww.ini", neww_a);

    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    n = GetPrivateProfileStringW(L"New", L"Accent", L"dflt", wbuf, 64, new_w);
    line("GetPrivateProfileStringW(L\"New\", L\"Accent\"), profnew.ini: ret=%lu err=%s [%s]", n, le(),
         got_w(wbuf, n + 2, 64));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    n = GetPrivateProfileStringW(L"New", L"Ideograph", L"dflt", wbuf, 64, new_w);
    line("GetPrivateProfileStringW(L\"New\", L\"Ideograph\"), profnew.ini: ret=%lu err=%s [%s]", n,
         le(), got_w(wbuf, n + 2, 64));
    memset(buf, '#', sizeof buf);
    arm();
    n = GetPrivateProfileStringA("New", "Accent", "dflt", buf, 64, new_a);
    line("GetPrivateProfileStringA(\"New\", \"Accent\"), profnew.ini: ret=%lu err=%s [%s]", n, le(),
         got_a(buf, n + 2, 64));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    n = GetPrivateProfileStringW(L"New", L"Accent", L"dflt", wbuf, 64, neww_w);
    line("GetPrivateProfileStringW(L\"New\", L\"Accent\"), profneww.ini: ret=%lu err=%s [%s]", n, le(),
         got_w(wbuf, n + 2, 64));
    fill_w(wbuf, sizeof wbuf / sizeof wbuf[0]);
    arm();
    n = GetPrivateProfileStringW(L"New", L"Ideograph", L"dflt", wbuf, 64, neww_w);
    line("GetPrivateProfileStringW(L\"New\", L\"Ideograph\"), profneww.ini: ret=%lu err=%s [%s]", n,
         le(), got_w(wbuf, n + 2, 64));
    memset(buf, '#', sizeof buf);
    arm();
    n = GetPrivateProfileStringA("New", "Accent", "dflt", buf, 64, neww_a);
    line("GetPrivateProfileStringA(\"New\", \"Accent\"), profneww.ini: ret=%lu err=%s [%s]", n, le(),
         got_a(buf, n + 2, 64));

    arm();
    r = WritePrivateProfileStringA("New", "Key", "value", nodir_a);
    line("WritePrivateProfileStringA(\"New\", \"Key\", \"value\"), in a directory that does not exist: "
         "ret=%d err=%s", r, le());
    tidy();
}

static const section_t sections[] = {
    { "winini", sec_winini, F2KT_ALWAYS },
    { "read", sec_read, F2KT_ALWAYS },
    { "int", sec_int, F2KT_ALWAYS },
    { "sections", sec_sections, F2KT_ALWAYS },
    { "write", sec_write, F2KT_ALWAYS },
    { "new", sec_new, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    paths();
    return run_sections("profile", sections, argc, argv);
}
