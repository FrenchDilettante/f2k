/*
 * screen - the console's screen buffer as cls, color and a full-screen
 * program use it: the cursor's position and the window following it,
 * the text attribute, filling cells, reading them back, and scrolling
 * a rectangle.
 *
 * tests/capture.bat redirects the standard output to a file, so every
 * section opens CONOUT$ (and CONIN$, for the errors) by name, as the
 * console fixture does. Each section first clears the whole buffer and
 * homes the cursor with cls's own sequence: FillConsoleOutputCharacterW
 * and FillConsoleOutputAttribute over every cell (the attribute as the
 * section found it), then SetConsoleCursorPosition to the top-left
 * corner, which also brings the window back to the buffer's top. From
 * there it observes through what it reads back
 * (ReadConsoleOutputCharacterW and A, ReadConsoleOutputAttribute,
 * GetConsoleScreenBufferInfo).
 *
 * Positions print as buffer coordinates, from the cleared buffer's
 * top-left corner; those within 20 of the buffer's right or bottom edge
 * print relative to its size as W and H (W-1 is the last column, H the
 * first row past the last one), so nothing prints the size the console
 * happens to have. Text never goes through the buffer's last cell, so
 * no write scrolls the buffer. A section that changes the attribute
 * restores the one it found before it ends.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   cursor    SetConsoleCursorPosition inside the buffer, at its last
 *             column and row, one past them, negative; the window
 *             following the cursor down and up, and home again; a
 *             write's move and its wrap at the row's end
 *   attr      SetConsoleTextAttribute, then WriteConsoleA and
 *             WriteConsoleW: the written cells' attributes, the rest
 *             untouched; values with every bit, the high byte, zero;
 *             a character fill keeping the cells' attributes
 *   fill      FillConsoleOutputCharacterW and A, FillConsoleOutputAttribute:
 *             a count within a row, past the row's end (the next row),
 *             past the buffer's end (the count written), zero, a start
 *             outside the buffer; a non-ASCII character read back
 *             through both widths (code page 437)
 *   readback  ReadConsoleOutputCharacterW and A, ReadConsoleOutputAttribute:
 *             a count within a row, across the row's end, past the
 *             buffer's end, zero, a start outside the buffer, and the
 *             caller's buffer past the count
 *   scroll    ScrollConsoleScreenBufferW (and A, with a non-ASCII fill):
 *             a rectangle moved down and right over itself, up and left,
 *             to a place it does not overlap, onto itself; the fill of
 *             the uncovered cells
 *   clip      the same moves with a clip rectangle: inside, excluding
 *             the destination, a small one, one past the buffer's edges,
 *             one apart from both rectangles, an inverted one
 *   edges     a source partly and wholly outside the buffer, a
 *             destination partly outside (right, left and top, bottom)
 *             and wholly outside (right, below), an inverted source
 *   errors    every call above on CONIN$, on a file and on a bogus
 *             handle: the return, the error, the count
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat screen):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% screen.c
 */

#include "../common/f2kt.h"

/* A handle value no object has here. */
#define BOGUS ((HANDLE)0x1234)

/* What an out-parameter holds before the call, to see it untouched. */
#define UNSET 0xDEADBEEFu

/* The fill the scrolls leave behind: '.' on red, yellow. */
#define FILL_ATTR 0x4E

static HANDLE con_out = INVALID_HANDLE_VALUE;
static HANDLE con_in = INVALID_HANDLE_VALUE;
static WORD attr0;          /* the attribute as the section found it */
static int width = 80;      /* the buffer's size */
static int height = 25;

static HANDLE open_console(const char *name)
{
    return CreateFileA(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
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

static COORD xy(int x, int y)
{
    COORD c;

    c.X = (SHORT)x;
    c.Y = (SHORT)y;
    return c;
}

static SMALL_RECT rect(int left, int top, int right, int bottom)
{
    SMALL_RECT r;

    r.Left = (SHORT)left;
    r.Top = (SHORT)top;
    r.Right = (SHORT)right;
    r.Bottom = (SHORT)bottom;
    return r;
}

/* A coordinate as printed: a number, or relative to the buffer's size
 * (`sym`, W or H) within 20 of it. */
static const char *num(int v, int size, char sym)
{
    static char bufs[8][16];
    static int next;
    char *b = bufs[next++ & 7];

    if (v >= size - 20 && v != 0) {
        if (v == size) {
            sprintf(b, "%c", sym);
        } else {
            sprintf(b, "%c%+d", sym, v - size);
        }
    } else {
        sprintf(b, "%d", v);
    }
    return b;
}

static const char *pos(int x, int y)
{
    static char bufs[4][40];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "(%s,%s)", num(x, width, 'W'), num(y, height, 'H'));
    return b;
}

static const char *rect_text(const SMALL_RECT *r)
{
    static char bufs[2][80];
    static int next;
    char *b = bufs[next++ & 1];

    if (r == NULL) {
        return "none";
    }
    sprintf(b, "%s-%s", pos(r->Left, r->Top), pos(r->Right, r->Bottom));
    return b;
}

/* A count out-parameter as printed. */
static const char *count_text(DWORD n)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (n == UNSET) {
        return "untouched";
    }
    sprintf(b, "%lu", n);
    return b;
}

/* A wide text's first `count` units: printable ASCII as itself, any
 * other unit as <U+XXXX>. */
static const char *vis_w(const WCHAR *s, DWORD count)
{
    static char bufs[2][900];
    static int next;
    char *b = bufs[next++ & 1];
    int n = 0;
    DWORD i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 10; i++) {
        if (s[i] >= 0x20 && s[i] < 0x7F) {
            b[n++] = (char)s[i];
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)s[i]);
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

        if (c >= 0x20 && c < 0x7F) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "\\x%02X", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

/* Attributes as printed: two hex digits each (four above 0xFF), spaced. */
static const char *attr_list(const WORD *a, int n)
{
    static char b[48 * 5 + 1];
    int at = 0;
    int i;

    b[0] = '\0';
    for (i = 0; i < n && i < 48; i++) {
        at += sprintf(b + at, i == 0 ? "%02X" : " %02X", (unsigned)a[i]);
    }
    return b;
}

/* --- setup ------------------------------------------------------------ */

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

/* A section's start: the handles, the buffer as found, cleared. */
static void start(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    BOOL ok;

    con_out = open_console("CONOUT$");
    con_in = open_console("CONIN$");
    ok = con_out != INVALID_HANDLE_VALUE && con_in != INVALID_HANDLE_VALUE
         && GetConsoleScreenBufferInfo(con_out, &csbi);
    line("CONIN$ and CONOUT$ open: %s", yesno(ok));
    if (ok) {
        width = csbi.dwSize.X;
        height = csbi.dwSize.Y;
        attr0 = csbi.wAttributes;
    }
    clear();
}

static void restore_attr(void)
{
    BOOL r = SetConsoleTextAttribute(con_out, attr0);

    line("attribute restored: %s", yesno(r));
}

static void finish(void)
{
    CloseHandle(con_in);
    CloseHandle(con_out);
}

/* `n` cells from (x, y), read back: their text and attributes. */
static void cells(const char *label, int x, int y, int n)
{
    WCHAR text[48];
    WORD attrs[48];
    DWORD got_t = 0;
    DWORD got_a = 0;
    BOOL rt, ra;

    rt = ReadConsoleOutputCharacterW(con_out, text, (DWORD)n, xy(x, y), &got_t);
    ra = ReadConsoleOutputAttribute(con_out, attrs, (DWORD)n, xy(x, y), &got_a);
    if (!rt || !ra || got_t != (DWORD)n || got_a != (DWORD)n) {
        line("  %s %s: read back ret=%d,%d count %lu,%lu", label, pos(x, y), rt, ra, got_t, got_a);
        return;
    }
    line("  %s %s: [%s] %s", label, pos(x, y), vis_w(text, (DWORD)n), attr_list(attrs, n));
}

/* Rows y0..y0+rows-1, `cols` cells from column x0. */
static void show(int x0, int y0, int rows, int cols)
{
    int i;

    for (i = 0; i < rows; i++) {
        cells("row", x0, y0 + i, cols);
    }
}

/* The cursor and the window: the cursor's place, the window's top row,
 * the cursor's row within the window ("last" for its last row). */
static void where(const char *when)
{
    CONSOLE_SCREEN_BUFFER_INFO c;
    char row[16];
    int k;

    if (!GetConsoleScreenBufferInfo(con_out, &c)) {
        line("%s: GetConsoleScreenBufferInfo failed, err=%lu", when, GetLastError());
        return;
    }
    k = c.dwCursorPosition.Y - c.srWindow.Top;
    if (c.dwCursorPosition.Y == c.srWindow.Bottom) {
        strcpy(row, "last");
    } else {
        sprintf(row, "%d", k);
    }
    line("%s: cursor at %s, window top at row %s, the cursor in the window: %s (its row %s)", when,
         pos(c.dwCursorPosition.X, c.dwCursorPosition.Y), num(c.srWindow.Top, height, 'H'),
         yesno(c.dwCursorPosition.Y >= c.srWindow.Top && c.dwCursorPosition.Y <= c.srWindow.Bottom
               && c.dwCursorPosition.X >= c.srWindow.Left && c.dwCursorPosition.X <= c.srWindow.Right),
         row);
}

static void write_a(const char *text)
{
    DWORD n = UNSET;
    BOOL r;

    arm();
    r = WriteConsoleA(con_out, text, (DWORD)strlen(text), &n, NULL);
    line("WriteConsoleA([%s]): ret=%d written %s err=%s", text, r, count_text(n), le());
}

static void write_w(const WCHAR *text)
{
    DWORD n = UNSET;
    BOOL r;

    arm();
    r = WriteConsoleW(con_out, text, (DWORD)wcslen(text), &n, NULL);
    line("WriteConsoleW([%s]): ret=%d written %s err=%s", ws(text), r, count_text(n), le());
}

/* Text placed silently (the setup of a read or a scroll): the cursor at
 * (x, y), one WriteConsoleA. */
static void put(int x, int y, const char *text)
{
    DWORD n;

    SetConsoleCursorPosition(con_out, xy(x, y));
    WriteConsoleA(con_out, text, (DWORD)strlen(text), &n, NULL);
}

/* --- cursor ----------------------------------------------------------- */

static void set_cursor(int x, int y)
{
    BOOL r;

    arm();
    r = SetConsoleCursorPosition(con_out, xy(x, y));
    line("SetConsoleCursorPosition%s: ret=%d err=%s", pos(x, y), r, le());
}

static void sec_cursor(void)
{
    start();
    where("after the clear");

    set_cursor(5, 3);
    where("then");
    set_cursor(width - 1, 0);
    where("then");
    set_cursor(width, 0);               /* one column past */
    where("then");
    set_cursor(-1, 0);
    where("then");
    set_cursor(0, -1);
    where("then");
    set_cursor(0, height);              /* one row past */
    where("then");
    set_cursor(width - 1, height - 1);  /* the last cell: the window follows */
    where("then");
    set_cursor(0, 0);
    where("home");

    /* The window following: past its bottom, within it, above its top. */
    set_cursor(0, 30);
    where("then");
    set_cursor(0, 28);
    where("then");
    set_cursor(0, 2);
    where("then");
    set_cursor(0, 0);
    where("home");

    /* A write moves it; across the row's end it wraps. */
    write_a("abc");
    where("then");
    set_cursor(width - 2, 1);
    write_a("xyz");
    where("then");
    cells("cells", width - 3, 1, 3);
    cells("cells", 0, 2, 3);
    finish();
}

/* --- attr ------------------------------------------------------------- */

static void set_attr(WORD a)
{
    CONSOLE_SCREEN_BUFFER_INFO c;
    const char *e;
    BOOL r;

    arm();
    r = SetConsoleTextAttribute(con_out, a);
    e = le();
    c.wAttributes = 0xEEEE;
    GetConsoleScreenBufferInfo(con_out, &c);
    line("SetConsoleTextAttribute(0x%04X): ret=%d err=%s, the buffer's attribute now 0x%04X", (unsigned)a, r, e,
         (unsigned)c.wAttributes);
}

static void sec_attr(void)
{
    static const WORD values[] = { 0x0000, 0x00FF, 0x0100, 0x8000, 0xFFFF };
    int i;

    start();
    cells("as cleared", 0, 0, 6);

    set_attr(0x1E);
    write_a("abc");
    cells("cells", 0, 0, 6);
    set_attr(0x4F);
    SetConsoleCursorPosition(con_out, xy(0, 1));
    write_w(L"de");
    cells("cells", 0, 1, 6);

    for (i = 0; i < (int)(sizeof values / sizeof values[0]); i++) {
        set_attr(values[i]);
        SetConsoleCursorPosition(con_out, xy(0, 2 + i));
        write_a("x");
        cells("cells", 0, 2 + i, 2);
    }

    /* A character fill keeps the cells' attributes. */
    set_attr(0x2A);
    {
        DWORD n = UNSET;
        BOOL r;

        arm();
        r = FillConsoleOutputCharacterW(con_out, L'f', 3, xy(0, 0), &n);
        line("FillConsoleOutputCharacterW(f, 3 at %s): ret=%d written %s err=%s", pos(0, 0), r, count_text(n),
             le());
    }
    cells("cells", 0, 0, 6);

    restore_attr();
    finish();
}

/* --- fill ------------------------------------------------------------- */

static void fill_w(WCHAR ch, DWORD count, int x, int y)
{
    DWORD n = UNSET;
    BOOL r;

    arm();
    r = FillConsoleOutputCharacterW(con_out, ch, count, xy(x, y), &n);
    line("FillConsoleOutputCharacterW(%s, %lu at %s): ret=%d written %s err=%s", vis_w(&ch, 1), count, pos(x, y),
         r, count_text(n), le());
}

static void fill_a(char ch, DWORD count, int x, int y)
{
    DWORD n = UNSET;
    BOOL r;

    arm();
    r = FillConsoleOutputCharacterA(con_out, ch, count, xy(x, y), &n);
    line("FillConsoleOutputCharacterA(%s, %lu at %s): ret=%d written %s err=%s", vis_a(&ch, 1), count, pos(x, y),
         r, count_text(n), le());
}

static void fill_attr(WORD a, DWORD count, int x, int y)
{
    DWORD n = UNSET;
    BOOL r;

    arm();
    r = FillConsoleOutputAttribute(con_out, a, count, xy(x, y), &n);
    line("FillConsoleOutputAttribute(0x%02X, %lu at %s): ret=%d written %s err=%s", (unsigned)a, count, pos(x, y),
         r, count_text(n), le());
}

/* `n` cells' text read back through both widths. */
static void both_widths(int x, int y, int n)
{
    WCHAR w[16];
    char a[16];
    DWORD gw = 0;
    DWORD ga = 0;
    BOOL rw, ra;

    rw = ReadConsoleOutputCharacterW(con_out, w, (DWORD)n, xy(x, y), &gw);
    ra = ReadConsoleOutputCharacterA(con_out, a, (DWORD)n, xy(x, y), &ga);
    line("  read back at %s: W ret=%d [%s], A ret=%d [%s]", pos(x, y), rw, vis_w(w, gw <= 16 ? gw : 0), ra,
         vis_a(a, ga <= 16 ? ga : 0));
}

static void sec_fill(void)
{
    start();

    /* Within a row. */
    fill_w(L'x', 5, 2, 1);
    cells("cells", 0, 1, 10);
    fill_a('y', 5, 2, 2);
    cells("cells", 0, 2, 10);

    /* Past the row's end: the next row. */
    fill_w(L'p', 6, width - 3, 3);
    cells("cells", width - 5, 3, 5);
    cells("cells", 0, 4, 5);
    fill_a('q', 6, width - 3, 5);
    cells("cells", width - 5, 5, 5);
    cells("cells", 0, 6, 5);

    /* Past the buffer's end: up to it. */
    fill_w(L'z', 10, width - 4, height - 1);
    cells("cells", width - 6, height - 1, 6);
    fill_a('r', 10, width - 3, height - 1);
    cells("cells", width - 6, height - 1, 6);

    /* Nothing, and a start outside the buffer. */
    fill_w(L'n', 0, 0, 7);
    fill_a('n', 0, 0, 7);
    cells("cells", 0, 7, 3);
    fill_w(L'o', 3, width, 0);
    fill_w(L'o', 3, 0, height);
    fill_w(L'o', 3, -1, 0);
    fill_w(L'o', 3, 0, -1);
    fill_a('o', 3, width, 0);
    fill_a('o', 3, 0, height);
    fill_a('o', 3, -1, 0);
    cells("cells", 0, 0, 3);

    /* Attributes, the same ways. */
    fill_attr(0x2F, 5, 2, 8);
    cells("cells", 0, 8, 10);
    fill_attr(0x3F, 6, width - 3, 9);
    cells("cells", width - 5, 9, 5);
    cells("cells", 0, 10, 5);
    fill_attr(0x5F, 10, width - 4, height - 2);
    cells("cells", width - 6, height - 2, 6);
    fill_attr(0x6F, 10, width - 4, height - 1);
    cells("cells", width - 6, height - 1, 6);
    fill_attr(0x1F, 0, 0, 11);
    cells("cells", 0, 11, 3);
    fill_attr(0x1F, 3, width, 0);
    fill_attr(0x1F, 3, 0, height);
    fill_attr(0x1F, 3, -1, 0);

    /* Non-ASCII characters through both widths: e-acute (0x82 in code
     * page 437) and a box-drawing line (0xC4). */
    fill_w(0x00E9, 3, 0, 12);
    both_widths(0, 12, 3);
    fill_a((char)0x82, 3, 0, 13);
    both_widths(0, 13, 3);
    fill_w(0x2500, 3, 0, 14);
    both_widths(0, 14, 3);
    fill_a((char)0xC4, 3, 0, 15);
    both_widths(0, 15, 3);
    finish();
}

/* --- readback --------------------------------------------------------- */

/* ReadConsoleOutputCharacterW of `count` (at most 40) cells into a buffer
 * of '#': the return, the count, what came, and whether the buffer past
 * the count is untouched. */
static void rd_w(DWORD count, int x, int y)
{
    WCHAR buf[48];
    DWORD n = UNSET;
    const char *e;
    BOOL r;
    int i;
    int rest = 1;

    for (i = 0; i < 48; i++) {
        buf[i] = L'#';
    }
    arm();
    r = ReadConsoleOutputCharacterW(con_out, buf, count, xy(x, y), &n);
    e = le();
    if (n <= 40) {
        for (i = (int)n; i < 48; i++) {
            rest = rest && buf[i] == L'#';
        }
        line("ReadConsoleOutputCharacterW(%lu at %s): ret=%d read %s err=%s [%s] the rest untouched %s", count,
             pos(x, y), r, count_text(n), e, vis_w(buf, n), yesno(rest));
    } else {
        line("ReadConsoleOutputCharacterW(%lu at %s): ret=%d read %s err=%s", count, pos(x, y), r, count_text(n), e);
    }
}

static void rd_a(DWORD count, int x, int y)
{
    char buf[48];
    DWORD n = UNSET;
    const char *e;
    BOOL r;
    int i;
    int rest = 1;

    memset(buf, '#', sizeof buf);
    arm();
    r = ReadConsoleOutputCharacterA(con_out, buf, count, xy(x, y), &n);
    e = le();
    if (n <= 40) {
        for (i = (int)n; i < 48; i++) {
            rest = rest && buf[i] == '#';
        }
        line("ReadConsoleOutputCharacterA(%lu at %s): ret=%d read %s err=%s [%s] the rest untouched %s", count,
             pos(x, y), r, count_text(n), e, vis_a(buf, n), yesno(rest));
    } else {
        line("ReadConsoleOutputCharacterA(%lu at %s): ret=%d read %s err=%s", count, pos(x, y), r, count_text(n), e);
    }
}

static void rd_attr(DWORD count, int x, int y)
{
    WORD buf[48];
    DWORD n = UNSET;
    const char *e;
    BOOL r;
    int i;
    int rest = 1;

    for (i = 0; i < 48; i++) {
        buf[i] = 0xEEEE;
    }
    arm();
    r = ReadConsoleOutputAttribute(con_out, buf, count, xy(x, y), &n);
    e = le();
    if (n <= 40) {
        for (i = (int)n; i < 48; i++) {
            rest = rest && buf[i] == 0xEEEE;
        }
        line("ReadConsoleOutputAttribute(%lu at %s): ret=%d read %s err=%s [%s] the rest untouched %s", count,
             pos(x, y), r, count_text(n), e, attr_list(buf, (int)n), yesno(rest));
    } else {
        line("ReadConsoleOutputAttribute(%lu at %s): ret=%d read %s err=%s", count, pos(x, y), r, count_text(n), e);
    }
}

static void sec_readback(void)
{
    DWORD n;

    start();
    put(0, 0, "hello world");
    put(width - 3, 1, "abc");           /* the last three columns: the cursor wraps to row 2 */
    put(0, 2, "def");
    put(width - 3, height - 1, "zz");   /* the cursor stops on the last cell, unwritten */
    FillConsoleOutputAttribute(con_out, 0x1E, 5, xy(0, 0), &n);
    FillConsoleOutputAttribute(con_out, 0x2F, 6, xy(width - 3, 1), &n);
    FillConsoleOutputAttribute(con_out, 0x3F, 2, xy(width - 3, height - 1), &n);

    rd_w(5, 0, 0);
    rd_a(5, 0, 0);
    rd_attr(5, 0, 0);
    rd_w(16, 0, 0);
    rd_a(16, 0, 0);
    rd_attr(8, 0, 0);

    /* Across the row's end. */
    rd_w(6, width - 3, 1);
    rd_a(6, width - 3, 1);
    rd_attr(6, width - 3, 1);

    /* Past the buffer's end. */
    rd_w(10, width - 3, height - 1);
    rd_a(10, width - 3, height - 1);
    rd_attr(10, width - 3, height - 1);

    /* Nothing, and a start outside the buffer. */
    rd_w(0, 0, 0);
    rd_a(0, 0, 0);
    rd_attr(0, 0, 0);
    rd_w(5, width, 0);
    rd_w(5, 0, height);
    rd_w(5, -1, 0);
    rd_w(5, 0, -1);
    rd_a(5, width, 0);
    rd_a(5, 0, height);
    rd_a(5, -1, 0);
    rd_attr(5, width, 0);
    rd_attr(5, 0, height);
    rd_attr(5, -1, 0);
    finish();
}

/* --- scroll, clip, edges ---------------------------------------------- */

/* The pattern a scroll moves: `rows` rows from (x0, y0), row i the
 * letter A+i then the digits 0-9, its attribute (i+1)<<4 | 0x0F. Its
 * last cell is never the buffer's last column (the cursor would wrap
 * there and, on the last row, scroll the buffer). */
static void pattern(int x0, int y0, int rows)
{
    char text[12];
    int i;

    for (i = 0; i < rows; i++) {
        SetConsoleTextAttribute(con_out, (WORD)(((i + 1) << 4) | 0x0F));
        text[0] = (char)('A' + i);
        memcpy(text + 1, "0123456789", 10);
        text[11] = '\0';
        put(x0, y0 + i, text);
    }
    SetConsoleTextAttribute(con_out, attr0);
}

/* One scroll: through ScrollConsoleScreenBufferW (the fill '.' or `fw`)
 * or A (`fa`), the fill's attribute FILL_ATTR. */
static void scroll_ex(int wide, SMALL_RECT src, const SMALL_RECT *clip, int dx, int dy, WCHAR fw, char fa)
{
    CHAR_INFO fill;
    BOOL r;

    memset(&fill, 0, sizeof fill);
    fill.Attributes = FILL_ATTR;
    arm();
    if (wide) {
        fill.Char.UnicodeChar = fw;
        r = ScrollConsoleScreenBufferW(con_out, &src, clip, xy(dx, dy), &fill);
    } else {
        fill.Char.AsciiChar = fa;
        r = ScrollConsoleScreenBufferA(con_out, &src, clip, xy(dx, dy), &fill);
    }
    line("ScrollConsoleScreenBuffer%s(%s, clip %s, to %s, fill %s): ret=%d err=%s", wide ? "W" : "A",
         rect_text(&src), rect_text(clip), pos(dx, dy), wide ? vis_w(&fw, 1) : vis_a(&fa, 1), r, le());
}

static void scroll(SMALL_RECT src, const SMALL_RECT *clip, int dx, int dy)
{
    scroll_ex(1, src, clip, dx, dy, L'.', '.');
}

/* A case's heading, then a cleared buffer. */
static void begin(const char *what)
{
    line("-- %s", what);
    clear();
}

static void sec_scroll(void)
{
    start();

    begin("down two rows, over itself");
    pattern(0, 0, 4);
    scroll(rect(0, 0, 10, 3), NULL, 0, 2);
    show(0, 0, 7, 14);

    begin("right three columns, over itself");
    pattern(0, 0, 4);
    scroll(rect(0, 0, 10, 3), NULL, 3, 0);
    show(0, 0, 5, 16);

    begin("up and left two, over itself");
    pattern(0, 0, 6);
    scroll(rect(2, 2, 10, 5), NULL, 0, 0);
    show(0, 0, 7, 14);

    begin("to a place it does not overlap");
    pattern(0, 0, 2);
    scroll(rect(0, 0, 4, 1), NULL, 6, 4);
    show(0, 0, 7, 14);

    begin("onto itself");
    pattern(0, 0, 3);
    scroll(rect(0, 0, 10, 2), NULL, 0, 0);
    show(0, 0, 4, 14);

    begin("down two rows, A, the fill 0x82");
    pattern(0, 0, 4);
    scroll_ex(0, rect(0, 0, 10, 3), NULL, 0, 2, 0, (char)0x82);
    show(0, 0, 7, 14);
    both_widths(0, 0, 3);

    begin("down two rows, W, the fill U+00E9");
    pattern(0, 0, 4);
    scroll_ex(1, rect(0, 0, 10, 3), NULL, 0, 2, 0x00E9, 0);
    show(0, 0, 7, 14);
    both_widths(0, 0, 3);

    restore_attr();
    finish();
}

static void sec_clip(void)
{
    SMALL_RECT clip;

    start();

    begin("down two rows, the clip the left six columns");
    pattern(0, 0, 4);
    clip = rect(0, 0, 5, 4);
    scroll(rect(0, 0, 10, 3), &clip, 0, 2);
    show(0, 0, 7, 14);

    begin("down four rows, the clip the source's first two rows");
    pattern(0, 0, 4);
    clip = rect(0, 0, 10, 1);
    scroll(rect(0, 0, 10, 3), &clip, 0, 4);
    show(0, 0, 9, 14);

    begin("down two rows, a small clip");
    pattern(0, 0, 4);
    clip = rect(3, 1, 7, 4);
    scroll(rect(0, 0, 10, 3), &clip, 0, 2);
    show(0, 0, 7, 14);

    begin("down two rows, a clip past the buffer's edges");
    pattern(0, 0, 4);
    clip = rect(-5, -5, width + 5, 3);
    scroll(rect(0, 0, 10, 3), &clip, 0, 2);
    show(0, 0, 7, 14);

    begin("down two rows, a clip apart from both rectangles");
    pattern(0, 0, 4);
    clip = rect(20, 20, 30, 30);
    scroll(rect(0, 0, 10, 3), &clip, 0, 2);
    show(0, 0, 7, 14);

    begin("down two rows, an inverted clip");
    pattern(0, 0, 4);
    clip = rect(5, 0, 0, 3);
    scroll(rect(0, 0, 10, 3), &clip, 0, 2);
    show(0, 0, 7, 14);

    begin("down two rows, the clip the left six columns, A");
    pattern(0, 0, 4);
    clip = rect(0, 0, 5, 4);
    scroll_ex(0, rect(0, 0, 10, 3), &clip, 0, 2, 0, '.');
    show(0, 0, 7, 14);

    restore_attr();
    finish();
}

static void sec_edges(void)
{
    start();

    begin("a source past the right edge");
    pattern(width - 12, 0, 3);
    scroll(rect(width - 5, 0, width + 4, 2), NULL, 0, 5);
    show(width - 14, 0, 3, 14);
    show(0, 5, 3, 14);

    begin("a source wholly past the right edge");
    pattern(width - 12, 0, 3);
    scroll(rect(width, 0, width + 5, 2), NULL, 0, 5);
    show(width - 14, 0, 3, 14);
    show(0, 5, 3, 14);

    begin("a destination past the right edge");
    pattern(0, 0, 3);
    scroll(rect(0, 0, 10, 2), NULL, width - 5, 4);
    show(0, 0, 3, 14);
    show(width - 14, 4, 3, 14);

    begin("a destination past the left and top edges");
    pattern(0, 2, 3);
    scroll(rect(0, 2, 10, 4), NULL, -3, 0);
    show(0, 0, 6, 14);

    begin("a destination past the bottom edge");
    pattern(0, height - 4, 3);
    scroll(rect(0, height - 4, 10, height - 2), NULL, 0, height - 2);
    show(0, height - 4, 4, 14);

    begin("a destination wholly past the right edge");
    pattern(0, 0, 3);
    scroll(rect(0, 0, 10, 2), NULL, width + 2, 0);
    show(0, 0, 4, 14);

    begin("a destination wholly below the buffer");
    pattern(0, 0, 3);
    scroll(rect(0, 0, 10, 2), NULL, 0, height);
    show(0, 0, 4, 14);

    begin("an inverted source");
    pattern(0, 0, 3);
    scroll(rect(10, 0, 0, 2), NULL, 0, 4);
    show(0, 0, 7, 14);

    begin("a destination past the right edge, A");
    pattern(0, 0, 3);
    scroll_ex(0, rect(0, 0, 10, 2), NULL, width - 5, 4, 0, '.');
    show(0, 0, 3, 14);
    show(width - 14, 4, 3, 14);

    restore_attr();
    finish();
}

/* --- errors ----------------------------------------------------------- */

/* Every call on a handle that is no screen buffer. */
static void errors_on(const char *what, HANDLE h)
{
    SMALL_RECT src = rect(0, 0, 1, 1);
    CHAR_INFO fill;
    WCHAR wbuf[4];
    char abuf[4];
    WORD attrs[4];
    DWORD n;
    BOOL r;

    memset(&fill, 0, sizeof fill);
    fill.Attributes = FILL_ATTR;
    fill.Char.UnicodeChar = L'.';
    line("-- %s", what);

    arm();
    r = SetConsoleCursorPosition(h, xy(0, 0));
    line("SetConsoleCursorPosition: ret=%d err=%s", r, le());
    arm();
    r = SetConsoleTextAttribute(h, 0x07);
    line("SetConsoleTextAttribute: ret=%d err=%s", r, le());

    n = UNSET;
    arm();
    r = FillConsoleOutputCharacterW(h, L'x', 1, xy(0, 0), &n);
    line("FillConsoleOutputCharacterW: ret=%d written %s err=%s", r, count_text(n), le());
    n = UNSET;
    arm();
    r = FillConsoleOutputCharacterA(h, 'x', 1, xy(0, 0), &n);
    line("FillConsoleOutputCharacterA: ret=%d written %s err=%s", r, count_text(n), le());
    n = UNSET;
    arm();
    r = FillConsoleOutputAttribute(h, 0x07, 1, xy(0, 0), &n);
    line("FillConsoleOutputAttribute: ret=%d written %s err=%s", r, count_text(n), le());

    n = UNSET;
    arm();
    r = ReadConsoleOutputCharacterW(h, wbuf, 1, xy(0, 0), &n);
    line("ReadConsoleOutputCharacterW: ret=%d read %s err=%s", r, count_text(n), le());
    n = UNSET;
    arm();
    r = ReadConsoleOutputCharacterA(h, abuf, 1, xy(0, 0), &n);
    line("ReadConsoleOutputCharacterA: ret=%d read %s err=%s", r, count_text(n), le());
    n = UNSET;
    arm();
    r = ReadConsoleOutputAttribute(h, attrs, 1, xy(0, 0), &n);
    line("ReadConsoleOutputAttribute: ret=%d read %s err=%s", r, count_text(n), le());

    arm();
    r = ScrollConsoleScreenBufferW(h, &src, NULL, xy(0, 2), &fill);
    line("ScrollConsoleScreenBufferW: ret=%d err=%s", r, le());
    fill.Char.AsciiChar = '.';
    arm();
    r = ScrollConsoleScreenBufferA(h, &src, NULL, xy(0, 2), &fill);
    line("ScrollConsoleScreenBufferA: ret=%d err=%s", r, le());
}

static void sec_errors(void)
{
    HANDLE file;

    start();
    errors_on("CONIN$", con_in);
    file = open_image();
    errors_on("the image file", file);
    CloseHandle(file);
    errors_on("a bogus handle", BOGUS);
    finish();
}

static const section_t sections[] = {
    { "cursor", sec_cursor, F2KT_ALWAYS },
    { "attr", sec_attr, F2KT_ALWAYS },
    { "fill", sec_fill, F2KT_ALWAYS },
    { "readback", sec_readback, F2KT_ALWAYS },
    { "scroll", sec_scroll, F2KT_ALWAYS },
    { "clip", sec_clip, F2KT_ALWAYS },
    { "edges", sec_edges, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("screen", sections, argc, argv);
}
