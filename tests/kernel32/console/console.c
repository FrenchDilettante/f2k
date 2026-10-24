/*
 * console - the console calls cmd.exe makes at startup: the screen
 * buffer's description, the input and output modes, line and raw
 * reads, the title, and control handlers.
 *
 * tests/capture.bat redirects the standard output to a file, so no
 * section makes a console call on a standard handle: each opens
 * CONOUT$ and CONIN$ by name (CreateFileA, read and write access,
 * shared), and every section runs unattended. Reads only ever take
 * input the section queued itself first (WriteConsoleInput): a read
 * with nothing queued would wait forever. Each section restores the
 * modes and the title it changed before it ends, and prints the
 * output-mode lines only once that mode is restored. Nothing printed
 * depends on what ran before: no cursor or window positions, no saved
 * title.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   info   GetConsoleScreenBufferInfo on CONOUT$: the buffer and window
 *          sizes, whether the window and the cursor lie inside the
 *          buffer, the attributes, whether the largest window fits
 *          the buffer; on CONIN$, a file and a bogus handle (the
 *          errors); a one-character WriteConsoleW, then WriteConsoleA,
 *          after a CR: the cursor's move
 *   mode   GetConsoleMode and SetConsoleMode on CONIN$ and CONOUT$:
 *          the modes as the program finds them, values set and read
 *          back, echo without line input, undefined bits; on a file
 *          and a bogus handle
 *   read   ReadConsoleW, then ReadConsoleA, over key events queued by
 *          WriteConsoleInputW (WriteConsoleInputA for the A reads),
 *          echo off: in line mode a line and its CR LF, a buffer
 *          shorter than the line (the rest on the next read); in raw
 *          mode the characters as queued, a one-character read; the
 *          events left after each; FlushConsoleInputBuffer dropping
 *          queued input
 *   title  SetConsoleTitleW and GetConsoleTitleW: a title read back, a
 *          buffer that fits, one unit short, too small, of size 0; an
 *          empty title; a 300-character title; the A twins (the
 *          title as found is saved, never printed, and restored)
 *   ctrl   SetConsoleCtrlHandler: a handler added, added again,
 *          removed until the removal fails, a handler never added
 *          removed, NULL (ignoring Ctrl+C) on and off; no control
 *          event is ever generated
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat console):
 *   cl /nologo /I .. console.c
 */

#include "../common/f2kt.h"

/* A handle value no object has here. */
#define BOGUS ((HANDLE)0x1234)

/* What an out-parameter holds before the call, to see it untouched. */
#define UNSET 0xDEADBEEFu

static HANDLE con_in = INVALID_HANDLE_VALUE;
static HANDLE con_out = INVALID_HANDLE_VALUE;

static HANDLE open_console(const char *name)
{
    return CreateFileA(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
}

/* Both console handles, by name. */
static void open_both(void)
{
    con_in = open_console("CONIN$");
    con_out = open_console("CONOUT$");
    line("CONIN$ and CONOUT$ open: %s", yesno(con_in != INVALID_HANDLE_VALUE && con_out != INVALID_HANDLE_VALUE));
}

/* A file handle: the program's own image, opened for reading. */
static HANDLE open_image(void)
{
    char path[MAX_PATH];
    HANDLE h;

    GetModuleFileNameA(NULL, path, sizeof path);
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    line("the image file open: %s", yesno(h != INVALID_HANDLE_VALUE));
    return h;
}

/* A wide text's first `count` units as printed: CR, LF, tab, NUL and
 * backslash as \r \n \t \0 \\, any other unit outside printable ASCII
 * as <U+XXXX>. */
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

/* The same, of an ANSI text's first `count` bytes (\xHH outside ASCII). */
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

/* Lines kept until the output mode is restored (say(1, ...)), or
 * printed at once (say(0, ...)). */
static char later[32][200];
static int nlater;

static void say(int deferred, const char *fmt, ...)
{
    char buf[200];
    va_list ap;

    va_start(ap, fmt);
    _vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    buf[sizeof buf - 1] = '\0';
    if (!deferred) {
        line("%s", buf);
    } else if (nlater < (int)(sizeof later / sizeof later[0])) {
        strcpy(later[nlater++], buf);
    }
}

static void say_later(void)
{
    int i;

    for (i = 0; i < nlater; i++) {
        line("%s", later[i]);
    }
    nlater = 0;
}

/* --- info ----------------------------------------------------------- */

/* GetConsoleScreenBufferInfo where it fails: the return and the error. */
static void info_on(const char *what, HANDLE h)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    BOOL r;

    arm();
    r = GetConsoleScreenBufferInfo(h, &csbi);
    line("GetConsoleScreenBufferInfo(%s): ret=%d err=%s", what, r, le());
}

/* One character written after a CR: the column the CR left, the
 * cursor's move. The line is blanked again after. */
static void cursor_step(int wide)
{
    CONSOLE_SCREEN_BUFFER_INFO before;
    CONSOLE_SCREEN_BUFFER_INFO after;
    DWORD written = UNSET;
    DWORD ignored;
    const char *e;
    BOOL r;

    if (wide) {
        WriteConsoleW(con_out, L"\r", 1, &ignored, NULL);
    } else {
        WriteConsoleA(con_out, "\r", 1, &ignored, NULL);
    }
    GetConsoleScreenBufferInfo(con_out, &before);
    arm();
    if (wide) {
        r = WriteConsoleW(con_out, L"x", 1, &written, NULL);
    } else {
        r = WriteConsoleA(con_out, "x", 1, &written, NULL);
    }
    e = le();
    GetConsoleScreenBufferInfo(con_out, &after);
    if (wide) {
        WriteConsoleW(con_out, L"\r \r", 3, &ignored, NULL);
    } else {
        WriteConsoleA(con_out, "\r \r", 3, &ignored, NULL);
    }
    line("WriteConsole%s of one character: ret=%d written %lu err=%s", wide ? "W" : "A", r, written, e);
    line("cursor column after the CR: %d, moved by %d columns and %d rows (%s)", before.dwCursorPosition.X,
         after.dwCursorPosition.X - before.dwCursorPosition.X, after.dwCursorPosition.Y - before.dwCursorPosition.Y,
         wide ? "W" : "A");
}

static void sec_info(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    SMALL_RECT *w = &csbi.srWindow;
    COORD *c = &csbi.dwCursorPosition;
    HANDLE file;
    BOOL r;

    arm();
    con_out = open_console("CONOUT$");
    line("CreateFileA(CONOUT$): valid %s err=%s", yesno(con_out != INVALID_HANDLE_VALUE), le());
    arm();
    con_in = open_console("CONIN$");
    line("CreateFileA(CONIN$): valid %s err=%s", yesno(con_in != INVALID_HANDLE_VALUE), le());

    arm();
    r = GetConsoleScreenBufferInfo(con_out, &csbi);
    line("GetConsoleScreenBufferInfo(CONOUT$): ret=%d err=%s", r, le());
    if (r) {
        line("buffer size: %d x %d", csbi.dwSize.X, csbi.dwSize.Y);
        line("window size: %d x %d", w->Right - w->Left + 1, w->Bottom - w->Top + 1);
        line("window inside the buffer: %s",
             yesno(w->Left >= 0 && w->Top >= 0 && w->Left <= w->Right && w->Top <= w->Bottom
                   && w->Right < csbi.dwSize.X && w->Bottom < csbi.dwSize.Y));
        line("cursor inside the buffer: %s",
             yesno(c->X >= 0 && c->Y >= 0 && c->X < csbi.dwSize.X && c->Y < csbi.dwSize.Y));
        line("attributes: 0x%04X", (unsigned)csbi.wAttributes);
        line("largest window within the buffer size: %s",
             yesno(csbi.dwMaximumWindowSize.X <= csbi.dwSize.X && csbi.dwMaximumWindowSize.Y <= csbi.dwSize.Y));
    }

    info_on("CONIN$", con_in);
    file = open_image();
    info_on("the image file", file);
    CloseHandle(file);
    info_on("a bogus handle", BOGUS);

    cursor_step(1);
    cursor_step(0);
}

/* --- mode ----------------------------------------------------------- */

static void mode_get(int deferred, const char *what, HANDLE h)
{
    DWORD m = UNSET;
    BOOL r;

    arm();
    r = GetConsoleMode(h, &m);
    if (r) {
        say(deferred, "GetConsoleMode(%s): ret=%d err=%s mode 0x%lX", what, r, le(), m);
    } else {
        say(deferred, "GetConsoleMode(%s): ret=%d err=%s mode untouched %s", what, r, le(), yesno(m == UNSET));
    }
}

static void mode_set(int deferred, const char *what, HANDLE h, DWORD m)
{
    BOOL r;

    arm();
    r = SetConsoleMode(h, m);
    say(deferred, "SetConsoleMode(%s, 0x%lX): ret=%d err=%s", what, m, r, le());
}

/* A value set, then read back. */
static void mode_round(int deferred, const char *what, HANDLE h, DWORD m)
{
    mode_set(deferred, what, h, m);
    mode_get(deferred, what, h);
}

static void sec_mode(void)
{
    DWORD in0 = 0;
    DWORD out0 = 0;
    BOOL in_ok;
    BOOL out_ok;
    BOOL r;
    HANDLE file;

    open_both();
    in_ok = GetConsoleMode(con_in, &in0);
    out_ok = GetConsoleMode(con_out, &out0);

    /* Input: printed as it goes (the output mode stays as found). */
    mode_get(0, "CONIN$", con_in);
    mode_round(0, "CONIN$", con_in, ENABLE_PROCESSED_INPUT);
    mode_round(0, "CONIN$", con_in, 0);
    mode_round(0, "CONIN$", con_in, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT
                                    | ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT);
    mode_round(0, "CONIN$", con_in, ENABLE_ECHO_INPUT);     /* echo without line input */
    mode_round(0, "CONIN$", con_in, 0x20);                  /* a bit later systems define */
    mode_round(0, "CONIN$", con_in, 0x8000);                /* a bit no system defines */
    r = in_ok && SetConsoleMode(con_in, in0);
    line("CONIN$ mode restored: %s", yesno(r));

    /* Output: kept until the mode is restored. */
    mode_get(1, "CONOUT$", con_out);
    mode_round(1, "CONOUT$", con_out, ENABLE_PROCESSED_OUTPUT);
    mode_round(1, "CONOUT$", con_out, 0);
    mode_round(1, "CONOUT$", con_out, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
    mode_round(1, "CONOUT$", con_out, 0x8000);
    r = out_ok && SetConsoleMode(con_out, out0);
    say_later();
    line("CONOUT$ mode restored: %s", yesno(r));

    file = open_image();
    mode_get(0, "the image file", file);
    mode_set(0, "the image file", file, 0);
    CloseHandle(file);
    mode_get(0, "a bogus handle", BOGUS);
    mode_set(0, "a bogus handle", BOGUS, 0);
}

/* --- read ----------------------------------------------------------- */

/* Set 1 scan codes of the letters a-z. */
static const WORD scan_letters[26] = {
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
};

/* Queue `text` as typed: a key-down and a key-up record per character
 * (the character, its virtual-key code and scan code, a repeat count
 * of 1, no control keys), through WriteConsoleInputW or (narrow)
 * WriteConsoleInputA. The text holds lowercase letters, digits, spaces
 * and '\r' (Enter) only. */
static void queue(int wide, const char *text)
{
    INPUT_RECORD recs[64];
    DWORD count = 0;
    DWORD written = UNSET;
    BOOL r;
    int i;
    int k;

    memset(recs, 0, sizeof recs);
    for (i = 0; text[i] != '\0' && count + 2 <= sizeof recs / sizeof recs[0]; i++) {
        char ch = text[i];
        WORD vk;
        WORD sc;

        if (ch >= 'a' && ch <= 'z') {
            vk = (WORD)(ch - 'a' + 'A');
            sc = scan_letters[ch - 'a'];
        } else if (ch >= '1' && ch <= '9') {
            vk = (WORD)ch;
            sc = (WORD)(ch - '1' + 0x02);
        } else if (ch == '0') {
            vk = (WORD)'0';
            sc = 0x0B;
        } else if (ch == ' ') {
            vk = VK_SPACE;
            sc = 0x39;
        } else {
            vk = VK_RETURN;
            sc = 0x1C;
        }
        for (k = 0; k < 2; k++) {
            KEY_EVENT_RECORD *key = &recs[count].Event.KeyEvent;

            recs[count].EventType = KEY_EVENT;
            key->bKeyDown = k == 0;
            key->wRepeatCount = 1;
            key->wVirtualKeyCode = vk;
            key->wVirtualScanCode = sc;
            if (wide) {
                key->uChar.UnicodeChar = (WCHAR)(unsigned char)ch;
            } else {
                key->uChar.AsciiChar = ch;
            }
            key->dwControlKeyState = 0;
            count++;
        }
    }
    arm();
    if (wide) {
        r = WriteConsoleInputW(con_in, recs, count, &written);
    } else {
        r = WriteConsoleInputA(con_in, recs, count, &written);
    }
    line("WriteConsoleInput%s([%s]): ret=%d written %lu of %lu err=%s", wide ? "W" : "A",
         vis_a(text, (DWORD)strlen(text)), r, written, count, le());
}

static void events(const char *when)
{
    DWORD n = UNSET;
    BOOL r;

    arm();
    r = GetNumberOfConsoleInputEvents(con_in, &n);
    line("GetNumberOfConsoleInputEvents %s: ret=%d count %lu err=%s", when, r, n, le());
}

static void flush(void)
{
    BOOL r;

    arm();
    r = FlushConsoleInputBuffer(con_in);
    line("FlushConsoleInputBuffer: ret=%d err=%s", r, le());
}

/* One read of at most `size` units (size <= 64): what it returned. */
static void read_once(int wide, DWORD size)
{
    WCHAR wb[64];
    char ab[64];
    DWORD n = UNSET;
    const char *e;
    BOOL r;
    int i;

    for (i = 0; i < 64; i++) {
        wb[i] = L'#';
        ab[i] = '#';
    }
    arm();
    if (wide) {
        r = ReadConsoleW(con_in, wb, size, &n, NULL);
    } else {
        r = ReadConsoleA(con_in, ab, size, &n, NULL);
    }
    e = le();
    if (!r || n > size) {
        line("ReadConsole%s(%lu): ret=%d read %lu err=%s", wide ? "W" : "A", size, r, n, e);
        return;
    }
    line("ReadConsole%s(%lu): ret=%d read %lu err=%s [%s]", wide ? "W" : "A", size, r, n, e,
         wide ? vis_w(wb, n) : vis_a(ab, n));
}

static void input_mode(DWORD m)
{
    BOOL r;

    arm();
    r = SetConsoleMode(con_in, m);
    line("SetConsoleMode(CONIN$, 0x%lX): ret=%d err=%s", m, r, le());
}

/* The reads through ReadConsoleW or (narrow) ReadConsoleA, over input
 * queued through the same width's WriteConsoleInput. */
static void reads(int wide)
{
    /* Line mode, echo off. */
    input_mode(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT);
    flush();
    queue(wide, "dir abc\r");
    events("queued");
    read_once(wide, 64);
    events("after the read");

    /* A buffer shorter than the line: the rest comes on the next read.
     * A second line is queued before that read, so it returns at once
     * even if the rest were lost. */
    flush();
    queue(wide, "abcdefgh\r");
    read_once(wide, 4);
    queue(wide, "zz\r");
    read_once(wide, 64);
    events("after the reads");

    /* Raw mode: no line input. */
    input_mode(ENABLE_PROCESSED_INPUT);
    flush();
    queue(wide, "xyz\r");
    events("queued");
    read_once(wide, 64);
    events("after the read");
    flush();
    queue(wide, "pq");
    read_once(wide, 1);
    events("after the read");
    flush();
}

static void sec_read(void)
{
    DWORD in0 = 0;
    BOOL in_ok;
    BOOL r;

    open_both();
    in_ok = GetConsoleMode(con_in, &in0);

    reads(1);
    reads(0);

    /* FlushConsoleInputBuffer drops what is queued. */
    flush();
    queue(1, "abc");
    events("queued");
    flush();
    events("after the flush");

    r = in_ok && SetConsoleMode(con_in, in0);
    line("CONIN$ mode restored: %s", yesno(r));
}

/* --- title ---------------------------------------------------------- */

static WCHAR saved_title[1024];
static WCHAR wtitle[1100];
static char atitle[1100];

/* The units a title buffer shows: up to its first NUL (included), at
 * most `size`. */
static DWORD shown_w(DWORD size)
{
    DWORD i;

    for (i = 0; i < size; i++) {
        if (wtitle[i] == 0) {
            return i + 1;
        }
    }
    return size;
}

static DWORD shown_a(DWORD size)
{
    DWORD i;

    for (i = 0; i < size; i++) {
        if (atitle[i] == 0) {
            return i + 1;
        }
    }
    return size;
}

static void set_title_w(const char *what, const WCHAR *title)
{
    BOOL r;

    arm();
    r = SetConsoleTitleW(title);
    line("SetConsoleTitleW(%s): ret=%d err=%s", what, r, le());
}

static void set_title_a(const char *what, const char *title)
{
    BOOL r;

    arm();
    r = SetConsoleTitleA(title);
    line("SetConsoleTitleA(%s): ret=%d err=%s", what, r, le());
}

/* GetConsoleTitleW into a buffer of `size` units, filled with '#'
 * first: the return, what the buffer holds, the units after it. */
static void get_title_w(DWORD size)
{
    const char *e;
    DWORD n;
    int i;

    for (i = 0; i < (int)(sizeof wtitle / sizeof wtitle[0]); i++) {
        wtitle[i] = L'#';
    }
    arm();
    n = GetConsoleTitleW(wtitle, size);
    e = le();
    line("GetConsoleTitleW(%lu): ret=%lu err=%s buffer [%s] after it untouched %s", size, n, e,
         vis_w(wtitle, shown_w(size)), yesno(wtitle[size] == L'#' && wtitle[size + 1] == L'#'));
}

static void get_title_a(DWORD size)
{
    const char *e;
    DWORD n;
    int i;

    for (i = 0; i < (int)sizeof atitle; i++) {
        atitle[i] = '#';
    }
    arm();
    n = GetConsoleTitleA(atitle, size);
    e = le();
    line("GetConsoleTitleA(%lu): ret=%lu err=%s buffer [%s] after it untouched %s", size, n, e,
         vis_a(atitle, shown_a(size)), yesno(atitle[size] == '#' && atitle[size + 1] == '#'));
}

static void sec_title(void)
{
    WCHAR wlong[301];
    char along[301];
    const char *e;
    DWORD n;
    BOOL r;
    int i;

    /* The title as found, saved for the end (it names capture.bat's
     * window on the real machine: never printed). */
    if (GetConsoleTitleW(saved_title, sizeof saved_title / sizeof saved_title[0]) == 0) {
        saved_title[0] = 0;
    }

    for (i = 0; i < 300; i++) {
        wlong[i] = (WCHAR)('0' + i % 10);
        along[i] = (char)('0' + i % 10);
    }
    wlong[300] = 0;
    along[300] = 0;

    set_title_w("F2K title", L"F2K title");
    get_title_w(64);
    get_title_w(10);            /* the title and its terminator */
    get_title_w(9);             /* one short */
    get_title_w(4);
    get_title_w(0);
    set_title_w("an empty title", L"");
    get_title_w(64);
    set_title_w("300 characters", wlong);
    for (i = 0; i < 1024; i++) {
        wtitle[i] = L'#';
    }
    arm();
    n = GetConsoleTitleW(wtitle, 1024);
    e = le();
    line("GetConsoleTitleW(1024): ret=%lu err=%s the title set %s", n, e,
         yesno(n == 300 && memcmp(wtitle, wlong, sizeof wlong) == 0));

    set_title_a("F2K title", "F2K title");
    get_title_a(64);
    get_title_a(10);
    get_title_a(9);
    get_title_a(4);
    get_title_a(0);
    set_title_a("an empty title", "");
    get_title_a(64);
    set_title_a("300 characters", along);
    for (i = 0; i < 1024; i++) {
        atitle[i] = '#';
    }
    arm();
    n = GetConsoleTitleA(atitle, 1024);
    e = le();
    line("GetConsoleTitleA(1024): ret=%lu err=%s the title set %s", n, e,
         yesno(n == 300 && memcmp(atitle, along, sizeof along) == 0));

    r = SetConsoleTitleW(saved_title);
    line("title restored: %s", yesno(r));
}

/* --- ctrl ----------------------------------------------------------- */

static BOOL WINAPI handler(DWORD type)
{
    (void)type;
    return FALSE;
}

static BOOL WINAPI never_added(DWORD type)
{
    (void)type;
    return FALSE;
}

static void ctrl(const char *what, PHANDLER_ROUTINE routine, BOOL add)
{
    BOOL r;

    arm();
    r = SetConsoleCtrlHandler(routine, add);
    line("SetConsoleCtrlHandler(%s, %s): ret=%d err=%s", what, add ? "TRUE" : "FALSE", r, le());
}

static void sec_ctrl(void)
{
    const char *e;
    BOOL r;
    int i;

    ctrl("handler", handler, TRUE);
    ctrl("handler", handler, TRUE);         /* added twice */
    ctrl("handler", handler, FALSE);
    ctrl("handler", handler, FALSE);
    ctrl("handler", handler, FALSE);
    ctrl("a handler never added", never_added, FALSE);
    ctrl("NULL", NULL, TRUE);               /* ignore Ctrl+C */
    ctrl("NULL", NULL, FALSE);
    ctrl("NULL", NULL, FALSE);

    /* The same handler 20 times, then removed until a removal fails. */
    for (i = 0; i < 20; i++) {
        SetConsoleCtrlHandler(handler, TRUE);
    }
    for (i = 0; i < 40; i++) {
        arm();
        r = SetConsoleCtrlHandler(handler, FALSE);
        if (!r) {
            break;
        }
    }
    e = le();
    line("added 20 times: removals before one failed %d, its err=%s", i, e);
}

static const section_t sections[] = {
    { "info", sec_info, F2KT_ALWAYS },
    { "mode", sec_mode, F2KT_ALWAYS },
    { "read", sec_read, F2KT_ALWAYS },
    { "title", sec_title, F2KT_ALWAYS },
    { "ctrl", sec_ctrl, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("console", sections, argc, argv);
}
