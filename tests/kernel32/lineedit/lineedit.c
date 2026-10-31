/*
 * lineedit - the console's line editing and command history, as every
 * program's line-mode read gets them (cmd.exe's prompt among them):
 * moving within the line, deleting, insert and overtype, lines longer
 * than a row and at the buffer's bottom, and the history keys.
 *
 * tests/capture.bat redirects the standard output to a file, so every
 * section opens CONIN$ and CONOUT$ by name, as the console fixture does.
 * Each read is a line-mode read with echo (ENABLE_PROCESSED_INPUT,
 * ENABLE_LINE_INPUT, ENABLE_ECHO_INPUT, and ENABLE_INSERT_MODE unless
 * the section says otherwise), over key events the section queued
 * itself just before it (WriteConsoleInputW for ReadConsoleW,
 * WriteConsoleInputA for ReadConsoleA), always ending with Enter, so
 * every read completes. The records are filled in as a real keyboard
 * makes them: a key-down and a key-up record per key, the virtual-key
 * code, the set 1 scan code, the character (none for the cursor and
 * function keys), and the control-key state: ENHANCED_KEY for the gray
 * cursor keys, and Ctrl and Alt pressed and released around the keys
 * they modify, with LEFT_CTRL_PRESSED or LEFT_ALT_PRESSED set while
 * they are down.
 *
 * Windows 2000 may apply editing and history only to keys typed, not to
 * records queued: the capture shows which. Where it does not, the read
 * returns the characters as queued (the cursor and function keys carry
 * none), never hangs: a watchdog thread queues Esc and Enter should a
 * read still wait after 5 seconds (it says so after the read), up to
 * three times, then ends the program.
 *
 * Each read prints the keys queued (as {Name} for a key without a
 * character, C- for Ctrl, A- for Alt; Enter is added), what the read
 * returned, then the rows the echo left, read back from the line's
 * first row (ReadConsoleOutputCharacterW, trailing blanks trimmed), and
 * where the cursor went, relative to where the read began. A section
 * first clears the screen buffer and homes the cursor (cls's own
 * sequence), so no row holds anything from before.
 *
 * Every section runs twice: through the W calls, then the A calls. Each
 * half starts by clearing its program's history with Alt+F7 (one read
 * of Alt+F7 and Enter): Windows 2000 keeps a program's history after it
 * ends, for the next process of the same name. The input mode is
 * restored before a section ends.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   plain    a word, an empty line, spaces
 *   move     Left, Right, Home and End, and past the line's start
 *   words    Ctrl+Left and Ctrl+Right, from the end, the start and
 *            mid-word, past either end, over two spaces
 *   delete   Delete mid-line, at the start and at the end; Backspace
 *            mid-line, at the start and at the end; Esc clearing the
 *            line, mid-line and before more keys
 *   insert   with ENABLE_INSERT_MODE: typing mid-line, Insert toggling
 *            to overtype, whether the toggle outlives its line, toggled
 *            twice, overtyping past the end; without it, the same, and
 *            Backspace and Delete in overtype; the mode read back after
 *   long     lines longer than a row: 100 letters, then Home and a
 *            letter (the line redrawn across the wrap), Backspace and
 *            Delete across the row's end, Esc; 170 letters; 79, 80 and
 *            81 letters (the row's edge)
 *   bottom   lines typed on the buffer's last row: the echo scrolls the
 *            buffer; 100 and 170 letters, then edits redrawn over the
 *            scrolled rows (the last four rows printed)
 *   history  three lines, then Up, Down, PgUp and PgDn, past either
 *            end, Up before and after typed text, F5
 *   fkeys    F1 and F3 copying from the last line, Right at the line's
 *            end, F6 (^Z)
 *   search   F8 matching the typed start against the history, again,
 *            with no match, with nothing typed
 *   forget   Alt+F7 clearing the history: Up and F3 after it, Alt+F7
 *            mid-line
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat lineedit):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% lineedit.c
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers predate these input modes. */
#ifndef ENABLE_INSERT_MODE
#define ENABLE_INSERT_MODE 0x0020
#endif

/* Line input with echo, Ctrl+C processed. */
#define LINE_MODE (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)

/* What an out-parameter holds before the call, to see it untouched. */
#define UNSET 0xDEADBEEFu

#define MAX_RECORDS 800

static HANDLE con_in = INVALID_HANDLE_VALUE;
static HANDLE con_out = INVALID_HANDLE_VALUE;
static DWORD in_mode0;      /* the input mode as the section found it */
static BOOL in_mode_ok;
static WORD attr0;          /* the attribute as found (the clear's) */
static int width = 80;      /* the buffer's size */
static int height = 25;
static int wide;            /* this half: the W calls (1) or the A calls (0) */
static int bottom_mode;     /* print the buffer's last rows as the echo */

static HANDLE open_console(const char *name)
{
    return CreateFileA(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
}

static COORD xy(int x, int y)
{
    COORD c;

    c.X = (SHORT)x;
    c.Y = (SHORT)y;
    return c;
}

/* A row as printed: a number, or relative to the buffer's height (H-1
 * is its last row) within 20 of it. */
static const char *row_text(int y)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (y >= height - 20 && y != 0) {
        sprintf(b, "H%+d", y - height);
    } else {
        sprintf(b, "%d", y);
    }
    return b;
}

/* A wide text's first `count` units: CR, LF and backslash as \r \n \\,
 * any other unit outside printable ASCII as <U+XXXX>. */
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

/* The same, of an ANSI text (\xHH outside printable ASCII). */
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

/* --- keys -------------------------------------------------------------- */

typedef struct {
    const char *name;
    WORD vk;
    WORD scan;          /* set 1 */
    WCHAR ch;           /* the character the key types, 0 for none */
    DWORD state;        /* the control-key state while it is down */
} keydef_t;

/* The keys without a character of their own, and those whose character
 * is a control code, by the name the specs give them in braces. */
static const keydef_t named_keys[] = {
    { "Enter", VK_RETURN, 0x1C, L'\r', 0 },
    { "Esc", VK_ESCAPE, 0x01, 0x1B, 0 },
    { "BS", VK_BACK, 0x0E, 0x08, 0 },
    { "Left", VK_LEFT, 0x4B, 0, ENHANCED_KEY },
    { "Right", VK_RIGHT, 0x4D, 0, ENHANCED_KEY },
    { "Up", VK_UP, 0x48, 0, ENHANCED_KEY },
    { "Down", VK_DOWN, 0x50, 0, ENHANCED_KEY },
    { "Home", VK_HOME, 0x47, 0, ENHANCED_KEY },
    { "End", VK_END, 0x4F, 0, ENHANCED_KEY },
    { "PgUp", VK_PRIOR, 0x49, 0, ENHANCED_KEY },
    { "PgDn", VK_NEXT, 0x51, 0, ENHANCED_KEY },
    { "Ins", VK_INSERT, 0x52, 0, ENHANCED_KEY },
    { "Del", VK_DELETE, 0x53, 0, ENHANCED_KEY },
    { "F1", VK_F1, 0x3B, 0, 0 },
    { "F3", VK_F3, 0x3D, 0, 0 },
    { "F5", VK_F5, 0x3F, 0, 0 },
    { "F6", VK_F6, 0x40, 0, 0 },
    { "F8", VK_F8, 0x42, 0, 0 },
    { "C-Left", VK_LEFT, 0x4B, 0, ENHANCED_KEY | LEFT_CTRL_PRESSED },
    { "C-Right", VK_RIGHT, 0x4D, 0, ENHANCED_KEY | LEFT_CTRL_PRESSED },
    { "A-F7", VK_F7, 0x41, 0, LEFT_ALT_PRESSED },
    { NULL, 0, 0, 0, 0 }
};

/* Set 1 scan codes of the letters a-z. */
static const WORD scan_letters[26] = {
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
};

static INPUT_RECORD recs[MAX_RECORDS];

/* One key record into `r`: the character as this half's width holds it. */
static void record(INPUT_RECORD *r, int as_wide, BOOL down, WORD vk, WORD scan, WCHAR ch, DWORD state)
{
    KEY_EVENT_RECORD *k = &r->Event.KeyEvent;

    memset(r, 0, sizeof *r);
    r->EventType = KEY_EVENT;
    k->bKeyDown = down;
    k->wRepeatCount = 1;
    k->wVirtualKeyCode = vk;
    k->wVirtualScanCode = scan;
    if (as_wide) {
        k->uChar.UnicodeChar = ch;
    } else {
        k->uChar.AsciiChar = (CHAR)ch;
    }
    k->dwControlKeyState = state;
}

static int add(int n, BOOL down, WORD vk, WORD scan, WCHAR ch, DWORD state)
{
    if (n >= MAX_RECORDS) {
        return n;
    }
    record(&recs[n], wide, down, vk, scan, ch, state);
    return n + 1;
}

/* A key pressed and released, Ctrl and Alt around it as it needs them. */
static int press(int n, const keydef_t *k)
{
    if (k->state & LEFT_CTRL_PRESSED) {
        n = add(n, TRUE, VK_CONTROL, 0x1D, 0, LEFT_CTRL_PRESSED);
    }
    if (k->state & LEFT_ALT_PRESSED) {
        n = add(n, TRUE, VK_MENU, 0x38, 0, LEFT_ALT_PRESSED);
    }
    n = add(n, TRUE, k->vk, k->scan, k->ch, k->state);
    n = add(n, FALSE, k->vk, k->scan, k->ch, k->state);
    if (k->state & LEFT_ALT_PRESSED) {
        n = add(n, FALSE, VK_MENU, 0x38, 0, 0);
    }
    if (k->state & LEFT_CTRL_PRESSED) {
        n = add(n, FALSE, VK_CONTROL, 0x1D, 0, 0);
    }
    return n;
}

/* The records a spec makes: lowercase letters, digits and spaces as
 * typed, {Name} for a named key. -1 for anything else. */
static int build(const char *spec)
{
    keydef_t k;
    const char *p = spec;
    int n = 0;
    int i;

    while (*p != '\0') {
        if (*p == '{') {
            const char *end = strchr(p, '}');

            if (end == NULL) {
                return -1;
            }
            for (i = 0; named_keys[i].name != NULL; i++) {
                if ((int)strlen(named_keys[i].name) == end - p - 1
                    && strncmp(named_keys[i].name, p + 1, end - p - 1) == 0) {
                    break;
                }
            }
            if (named_keys[i].name == NULL) {
                return -1;
            }
            n = press(n, &named_keys[i]);
            p = end + 1;
            continue;
        }
        k.name = NULL;
        k.ch = (WCHAR)(unsigned char)*p;
        k.state = 0;
        if (*p >= 'a' && *p <= 'z') {
            k.vk = (WORD)(*p - 'a' + 'A');
            k.scan = scan_letters[*p - 'a'];
        } else if (*p >= '1' && *p <= '9') {
            k.vk = (WORD)*p;
            k.scan = (WORD)(*p - '1' + 0x02);
        } else if (*p == '0') {
            k.vk = (WORD)'0';
            k.scan = 0x0B;
        } else if (*p == ' ') {
            k.vk = VK_SPACE;
            k.scan = 0x39;
        } else {
            return -1;
        }
        n = press(n, &k);
        p++;
    }
    return n;
}

/* Queue a spec's records through this half's WriteConsoleInput: whether
 * all of them went in. */
static BOOL queue(const char *label, const char *spec)
{
    DWORD written = UNSET;
    const char *e;
    BOOL r;
    int n = build(spec);

    if (n < 0 || n >= MAX_RECORDS) {
        line("keys [%s]: not queued, the spec is malformed", label);
        return FALSE;
    }
    arm();
    if (wide) {
        r = WriteConsoleInputW(con_in, recs, (DWORD)n, &written);
    } else {
        r = WriteConsoleInputA(con_in, recs, (DWORD)n, &written);
    }
    e = le();
    line("keys [%s]: WriteConsoleInput%s ret=%d all written %s err=%s", label, wide ? "W" : "A", r,
         yesno(written == (DWORD)n), e);
    return r && written == (DWORD)n;
}

/* --- the watchdog ---------------------------------------------------- */

static HANDLE watch_done;
static LONG watch_fired;

/* Should the read still wait after WAIT_MS, queue Esc and Enter (an
 * unforeseen popup closed, the line ended); three times at most, then
 * end the program rather than hang. */
static DWORD WINAPI watchdog(LPVOID arg)
{
    INPUT_RECORD r[4];
    DWORD n;
    int i;

    (void)arg;
    record(&r[0], 1, TRUE, VK_ESCAPE, 0x01, 0x1B, 0);
    record(&r[1], 1, FALSE, VK_ESCAPE, 0x01, 0x1B, 0);
    record(&r[2], 1, TRUE, VK_RETURN, 0x1C, L'\r', 0);
    record(&r[3], 1, FALSE, VK_RETURN, 0x1C, L'\r', 0);
    for (i = 0; i < 3; i++) {
        if (WaitForSingleObject(watch_done, WAIT_MS) == WAIT_OBJECT_0) {
            return 0;
        }
        InterlockedIncrement(&watch_fired);
        WriteConsoleInputW(con_in, r, 4, &n);
    }
    if (WaitForSingleObject(watch_done, WAIT_MS) == WAIT_OBJECT_0) {
        return 0;
    }
    line("the read never returned: the program ends");
    if (in_mode_ok) {
        SetConsoleMode(con_in, in_mode0);
    }
    ExitProcess(3);
    return 0;
}

/* --- reads ----------------------------------------------------------- */

static WCHAR wbuf[600];
static char abuf[600];

/* One read of this half's width, under the watchdog: what it returned. */
static void read_line(void)
{
    HANDLE t;
    DWORD tid;
    DWORD n = UNSET;
    const char *e;
    BOOL r;

    watch_fired = 0;
    ResetEvent(watch_done);
    t = CreateThread(NULL, 0, watchdog, NULL, 0, &tid);
    arm();
    if (wide) {
        r = ReadConsoleW(con_in, wbuf, 590, &n, NULL);
    } else {
        r = ReadConsoleA(con_in, abuf, 590, &n, NULL);
    }
    e = le();
    SetEvent(watch_done);
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    if (!r || n > 590) {
        line("  ReadConsole%s: ret=%d read %lu err=%s", wide ? "W" : "A", r, n, e);
    } else {
        line("  ReadConsole%s: ret=%d read %lu err=%s [%s]", wide ? "W" : "A", r, n, e,
             wide ? vis_w(wbuf, n) : vis_a(abuf, n));
    }
    if (watch_fired != 0) {
        line("  the watchdog queued Esc and Enter: %ld time(s)", watch_fired);
    }
}

/* Row y as the screen shows it, trailing blanks trimmed. */
static void show_row(const char *label, int y)
{
    WCHAR text[512];
    DWORD got = 0;
    BOOL r;

    r = ReadConsoleOutputCharacterW(con_out, text, (DWORD)(width < 512 ? width : 512), xy(0, y), &got);
    if (!r) {
        line("  %s: read back failed, err=%lu", label, GetLastError());
        return;
    }
    while (got > 0 && text[got - 1] == L' ') {
        got--;
    }
    line("  %s: [%s]", label, vis_w(text, got));
}

/* One read over `spec` and Enter, queued just before it: the keys, the
 * result, the echo read back, and the cursor's move. */
static void edit_as(const char *label, const char *spec)
{
    static char full[1400];
    CONSOLE_SCREEN_BUFFER_INFO before;
    CONSOLE_SCREEN_BUFFER_INFO after;
    char name[24];
    DWORD n;
    int first, last, y;

    FlushConsoleInputBuffer(con_in);
    GetConsoleScreenBufferInfo(con_out, &before);
    /* The rows the echo may take start blank. */
    FillConsoleOutputCharacterW(con_out, L' ', (DWORD)width * 3, xy(0, before.dwCursorPosition.Y), &n);
    if (strlen(spec) + 8 >= sizeof full) {
        line("keys [%s]: the spec is too long", label);
        return;
    }
    strcpy(full, spec);
    strcat(full, "{Enter}");
    if (!queue(label, full)) {
        return;
    }
    read_line();
    GetConsoleScreenBufferInfo(con_out, &after);
    if (bottom_mode) {
        for (y = height - 4; y < height; y++) {
            sprintf(name, "row %s", row_text(y));
            show_row(name, y);
        }
    } else {
        first = before.dwCursorPosition.Y;
        last = after.dwCursorPosition.Y - 1;
        if (last < first) {
            last = first;
        }
        if (last > first + 3) {
            last = first + 3;
        }
        for (y = first; y <= last; y++) {
            if (first == last) {
                strcpy(name, "echo");
            } else {
                sprintf(name, "echo row %d", y - first);
            }
            show_row(name, y);
        }
    }
    line("  cursor after: %+d rows, column %d", after.dwCursorPosition.Y - before.dwCursorPosition.Y,
         after.dwCursorPosition.X);
    FlushConsoleInputBuffer(con_in);
}

static void edit(const char *spec)
{
    edit_as(spec, spec);
}

/* `count` letters (a to z, round again), then `suffix`. */
static void letters_then(const char *label, int count, const char *suffix)
{
    static char spec[1200];
    int i;

    for (i = 0; i < count && i < 600; i++) {
        spec[i] = (char)('a' + i % 26);
    }
    spec[i] = '\0';
    strcat(spec, suffix);
    edit_as(label, spec);
}

/* Clear this program's history: Alt+F7, then Enter. */
static void forget(void)
{
    edit("{A-F7}");
}

/* --- the section's frame ---------------------------------------------- */

/* cls: every cell blanked with the attribute as found, the cursor home. */
static void clear(void)
{
    DWORD cells = (DWORD)width * (DWORD)height;
    DWORD chars = 0;
    DWORD attrs = 0;
    BOOL a, b, c;

    a = FillConsoleOutputCharacterW(con_out, L' ', cells, xy(0, 0), &chars);
    b = FillConsoleOutputAttribute(con_out, attr0, cells, xy(0, 0), &attrs);
    c = SetConsoleCursorPosition(con_out, xy(0, 0));
    line("buffer cleared and the cursor homed: %s", yesno(a && b && c && chars == cells && attrs == cells));
}

static void set_mode(DWORD m)
{
    DWORD now = UNSET;
    const char *e;
    BOOL r;

    arm();
    r = SetConsoleMode(con_in, m);
    e = le();
    GetConsoleMode(con_in, &now);
    line("SetConsoleMode(CONIN$, 0x%lX): ret=%d err=%s, the mode now 0x%lX", m, r, e, now);
}

static void show_mode(void)
{
    DWORD m = UNSET;
    BOOL r;

    arm();
    r = GetConsoleMode(con_in, &m);
    line("GetConsoleMode(CONIN$): ret=%d err=%s mode 0x%lX", r, le(), m);
}

/* A section: both halves of its body, between the setup and the
 * restore. */
static void halves(void (*body)(void))
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    BOOL ok;
    int half;

    con_in = open_console("CONIN$");
    con_out = open_console("CONOUT$");
    ok = con_in != INVALID_HANDLE_VALUE && con_out != INVALID_HANDLE_VALUE
         && GetConsoleScreenBufferInfo(con_out, &csbi);
    line("CONIN$ and CONOUT$ open: %s", yesno(ok));
    if (!ok) {
        return;
    }
    width = csbi.dwSize.X;
    height = csbi.dwSize.Y;
    attr0 = csbi.wAttributes;
    in_mode_ok = GetConsoleMode(con_in, &in_mode0);
    watch_done = CreateEventA(NULL, TRUE, FALSE, NULL);

    for (half = 0; half < 2; half++) {
        wide = half == 0;
        line("-- %s", wide ? "W: WriteConsoleInputW and ReadConsoleW" : "A: WriteConsoleInputA and ReadConsoleA");
        clear();
        set_mode(LINE_MODE | ENABLE_INSERT_MODE);
        forget();
        body();
    }

    FlushConsoleInputBuffer(con_in);
    line("CONIN$ mode restored: %s", yesno(in_mode_ok && SetConsoleMode(con_in, in_mode0)));
    CloseHandle(watch_done);
    CloseHandle(con_in);
    CloseHandle(con_out);
}

/* --- the sections ----------------------------------------------------- */

static void body_plain(void)
{
    edit("abc");
    edit("");
    edit("hello world");
    edit("a  b ");
}

static void body_move(void)
{
    edit("abcd{Left}{Left}x");
    edit("abcd{Home}x");
    edit("abcd{Home}{End}x");
    edit("abcd{Home}{Right}{Right}x");
    edit("abcd{Left}{Left}{Right}x");
    edit("ab{Left}{Left}{Left}{Left}x");
    edit("{Left}{Home}{End}x");
}

static void body_words(void)
{
    edit("one two three{C-Left}x");
    edit("one two three{C-Left}{C-Left}x");
    edit("one two three{C-Left}{C-Left}{C-Left}{C-Left}x");
    edit("one two three{Home}{C-Right}x");
    edit("one two three{Home}{C-Right}{C-Right}x");
    edit("one two three{Home}{C-Right}{C-Right}{C-Right}{C-Right}x");
    edit("one two{Left}{Left}{C-Left}x");
    edit("one  two{C-Left}{C-Left}x");
}

static void body_delete(void)
{
    edit("abcd{Left}{Left}{Del}");
    edit("abcd{Home}{Del}{Del}");
    edit("abcd{Del}");
    edit("abcd{Left}{BS}");
    edit("abcd{Home}{BS}");
    edit("abcd{BS}{BS}x");
    edit("abc{Esc}");
    edit("abc{Esc}xy");
    edit("abcd{Left}{Left}{Esc}xy");
}

static void body_insert(void)
{
    edit("abcd{Home}xy");
    edit("abcd{Home}{Ins}xy");
    show_mode();
    edit("abcd{Home}xy");               /* the line after the toggle */
    edit("abcd{Home}{Ins}{Ins}xy");
    edit("ab{Home}{Ins}xyz");           /* overtyping past the end */
    set_mode(LINE_MODE);
    edit("abcd{Home}xy");
    edit("abcd{Home}{Ins}xy");
    show_mode();
    edit("abcd{Home}xy");
    edit("abcd{Left}{Left}{BS}x");
    edit("abcd{Left}{Left}{Del}x");
    set_mode(LINE_MODE | ENABLE_INSERT_MODE);
}

static void body_long(void)
{
    char lefts[300];
    int i;

    letters_then("100 letters", 100, "");
    letters_then("100 letters, Home, x", 100, "{Home}x");
    lefts[0] = '\0';
    for (i = 0; i < 25; i++) {
        strcat(lefts, "{Left}");
    }
    strcat(lefts, "{BS}{BS}");
    letters_then("100 letters, Left 25 times, BS twice", 100, lefts);
    lefts[0] = '\0';
    for (i = 0; i < 25; i++) {
        strcat(lefts, "{Left}");
    }
    strcat(lefts, "{Del}{Del}");
    letters_then("100 letters, Left 25 times, Del twice", 100, lefts);
    letters_then("100 letters, Esc, xy", 100, "{Esc}xy");
    letters_then("170 letters", 170, "");
    letters_then("170 letters, Home, x", 170, "{Home}x");
    letters_then("79 letters", 79, "");
    letters_then("80 letters", 80, "");
    letters_then("81 letters", 81, "");
}

/* A read begun on the buffer's last row (the buffer cleared first). */
static void at_bottom(const char *label, int count, const char *suffix)
{
    clear();
    SetConsoleCursorPosition(con_out, xy(0, height - 1));
    bottom_mode = 1;
    letters_then(label, count, suffix);
    bottom_mode = 0;
}

static void body_bottom(void)
{
    at_bottom("3 letters", 3, "");
    at_bottom("100 letters", 100, "");
    at_bottom("100 letters, Home, x", 100, "{Home}x");
    at_bottom("100 letters, Esc, xy", 100, "{Esc}xy");
    at_bottom("170 letters, Home, x", 170, "{Home}x");
}

static void body_history(void)
{
    edit("one");
    edit("two");
    edit("three");
    edit("{Up}");
    edit("{Up}{Up}");
    edit("{Up}{Up}{Up}{Up}{Up}{Up}{Up}{Up}");
    edit("{Up}{Down}");
    edit("{Down}");
    edit("{PgUp}");
    edit("{PgDn}");
    edit("{Up}x");
    edit("ab{Up}");
    edit("{Up}{Esc}");
    edit("{F5}");
    edit("{F5}{F5}");
}

static void body_fkeys(void)
{
    edit("abcdef");
    edit("{F1}{F1}");
    edit("abcdef");
    edit("{F3}");
    edit("abcdef");
    edit("xy{F3}");
    edit("abcdef");
    edit("{F1}{F1}{F1}{F3}");
    edit("abcdef");
    edit("{Right}{Right}");
    edit("abcdef");
    edit("abcdefgh{Home}{F3}");
    edit("{F6}");
    edit("ab{F6}cd");
}

static void body_search(void)
{
    edit("dir one");
    edit("echo two");
    edit("dir three");
    edit("d{F8}");
    edit("d{F8}{F8}");
    edit("e{F8}");
    edit("x{F8}");
    edit("{F8}");
    edit("dir t{F8}");
}

static void body_forget(void)
{
    edit("one");
    edit("two");
    forget();
    edit("{Up}");
    edit("{F3}");
    edit("three");
    edit("{Up}");
    edit("ab{A-F7}cd");
    edit("{Up}");
}

static void sec_plain(void) { halves(body_plain); }
static void sec_move(void) { halves(body_move); }
static void sec_words(void) { halves(body_words); }
static void sec_delete(void) { halves(body_delete); }
static void sec_insert(void) { halves(body_insert); }
static void sec_long(void) { halves(body_long); }
static void sec_bottom(void) { halves(body_bottom); }
static void sec_history(void) { halves(body_history); }
static void sec_fkeys(void) { halves(body_fkeys); }
static void sec_search(void) { halves(body_search); }
static void sec_forget(void) { halves(body_forget); }

static const section_t sections[] = {
    { "plain", sec_plain, F2KT_ALWAYS },
    { "move", sec_move, F2KT_ALWAYS },
    { "words", sec_words, F2KT_ALWAYS },
    { "delete", sec_delete, F2KT_ALWAYS },
    { "insert", sec_insert, F2KT_ALWAYS },
    { "long", sec_long, F2KT_ALWAYS },
    { "bottom", sec_bottom, F2KT_ALWAYS },
    { "history", sec_history, F2KT_ALWAYS },
    { "fkeys", sec_fkeys, F2KT_ALWAYS },
    { "search", sec_search, F2KT_ALWAYS },
    { "forget", sec_forget, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("lineedit", sections, argc, argv);
}
