/*
 * wintext - a window's text in user32: SetWindowTextA/W,
 * GetWindowTextA/W and GetWindowTextLengthA/W, the title
 * CreateWindowExA/W give, WM_SETTEXT, WM_GETTEXT and WM_GETTEXTLENGTH
 * sent with SendMessageA/W and handed to DefWindowProcA/W, the buffers'
 * truncation, the text crossing between the A and W forms, and a
 * procedure that answers WM_GETTEXT itself.
 *
 * The windows are hidden WS_POPUP windows of three classes the program
 * registers: F2KWintextW (RegisterClassW, a procedure handing every
 * message to DefWindowProcW), F2KWintextA (RegisterClassA, to
 * DefWindowProcA) and F2KWintextCustom (RegisterClassW, answering
 * WM_GETTEXT with L"from proc" and WM_GETTEXTLENGTH with 9 itself, and
 * WM_SETTEXT with FALSE while told to refuse it). Each procedure records
 * the WM_SETTEXT, WM_GETTEXT and WM_GETTEXTLENGTH it receives: which
 * procedure, the message, wParam, the text (WM_SETTEXT's as it arrives,
 * WM_GETTEXT's as the procedure's answer leaves it) and its return; the
 * records print after each call, never from inside the procedure, which
 * calls no API but DefWindowProc, so the last error printed is the
 * call's.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=. Wide text
 * prints through ws()/wsn(); ANSI text prints its bytes 0x20-0x7E as
 * they are and any other as <XX> (hex). A buffer's contents print unit
 * by unit, after a fill of '#', a NUL as '|'. Each section registers
 * the classes it uses (once per process), creates its own windows and
 * destroys them at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create    CreateWindowExW and CreateWindowExA with a title, an empty
 *             title and a NULL one: GetWindowTextW/A and
 *             GetWindowTextLengthW/A of each, the records made while
 *             the window was created
 *   setget    SetWindowTextW and SetWindowTextA, read back with
 *             GetWindowTextW/A and GetWindowTextLengthW/A: a text, the
 *             empty text, NULL; NULL and destroyed windows
 *   trunc     GetWindowTextW and GetWindowTextA of "abcdefgh" into
 *             buffers of 0, 1, 4, 8, 9 and 64 units: the returns and the
 *             buffers' first 10 units
 *   messages  SendMessageW/A WM_SETTEXT (a text, then NULL),
 *             WM_GETTEXTLENGTH and WM_GETTEXT with wParam 0, 5 and 64;
 *             DefWindowProcW/A called directly with the same messages
 *   cross     text set through the W form and read through the A form,
 *             and the reverse, with U+00E9 and U+4E00: the texts, both
 *             lengths, an A buffer too short for the converted text
 *   custom    the custom procedure's window, titled "real title":
 *             GetWindowTextW/A and GetWindowTextLengthW/A, then
 *             SetWindowTextW refused and accepted, each followed by
 *             DefWindowProcW's own WM_GETTEXT
 *   internal  InternalGetWindowText, found with GetProcAddress (the
 *             MSVC 6-era SDK declares it nowhere): the W and A windows
 *             titled "abcdefgh" into buffers of 0, 1, 4, 8, 9 and 64
 *             units, the custom window (whether its procedure is
 *             asked), an untitled window, text with U+00E9 and U+4E00,
 *             NULL and destroyed windows
 *   xproc     another process's window (this program run as
 *             "wintext.exe --xchild", a hidden window titled "xproc
 *             title" handing its text to DefWindowProcW): GetWindowTextW,
 *             then WM_GETTEXTLENGTH, WM_GETTEXT (64 and 5 units, W and A)
 *             and WM_SETTEXT (W and A) sent across the processes, each
 *             read back; the child's end and exit code (a fault in the
 *             child shows as 0xC0000005)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat wintext):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wintext.c user32.lib
 */

#include "../common/f2kt.h"

#define CLASS_A "F2KWintextA"

/* The procedures' records, printed after each call. */
#define MAX_RECORDS 16

typedef struct {
    const char *proc;
    UINT msg;
    WPARAM wparam;
    LRESULT ret;
    char text[96];
} record_t;

static record_t records[MAX_RECORDS];
static int record_count;
static int records_lost;

/* Whether the custom procedure refuses WM_SETTEXT. */
static int refuse_set;

/* A window created and destroyed again: its handle names no window. */
static HWND dead;

/* Copy a C string into a record's text, without an API call. */
static void copy_text(char *dst, const char *src)
{
    int i;

    for (i = 0; i < 95 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* ANSI text as printed: 0x20-0x7E as is, any other byte as <XX>; its
 * first `count` bytes, to its terminator for a negative count. Calls no
 * API. Rotates through a few buffers. */
static const char *asn(const char *s, int count)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;
    unsigned char c;

    if (s == NULL) {
        return "(null)";
    }
    for (i = 0; (count < 0 ? s[i] != '\0' : i < count) && n < (int)sizeof bufs[0] - 5; i++) {
        c = (unsigned char)s[i];
        if (c >= 0x20 && c <= 0x7E) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "<%02X>", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

static const char *as(const char *s)
{
    return asn(s, -1);
}

static void record(const char *proc, UINT msg, WPARAM wparam, LRESULT ret, const char *text)
{
    record_t *r;

    if (record_count >= MAX_RECORDS) {
        records_lost++;
        return;
    }
    r = &records[record_count++];
    r->proc = proc;
    r->msg = msg;
    r->wparam = wparam;
    r->ret = ret;
    copy_text(r->text, text != NULL ? text : "");
}

static void reset_records(void)
{
    record_count = 0;
    records_lost = 0;
}

static const char *msg_name(UINT msg)
{
    switch (msg) {
    case WM_SETTEXT: return "WM_SETTEXT";
    case WM_GETTEXT: return "WM_GETTEXT";
    case WM_GETTEXTLENGTH: return "WM_GETTEXTLENGTH";
    }
    return "?";
}

/* The records since the last reset, then a fresh start. */
static void print_records(void)
{
    int i;

    if (record_count == 0) {
        line("  procedures saw: nothing");
    }
    for (i = 0; i < record_count; i++) {
        if (records[i].msg == WM_GETTEXTLENGTH) {
            line("  procedure %s saw %s wParam=%lu ret=%ld", records[i].proc,
                 msg_name(records[i].msg), (unsigned long)records[i].wparam, (long)records[i].ret);
        } else {
            line("  procedure %s saw %s wParam=%lu text=\"%s\" ret=%ld", records[i].proc,
                 msg_name(records[i].msg), (unsigned long)records[i].wparam, records[i].text,
                 (long)records[i].ret);
        }
    }
    if (records_lost) {
        line("  (%d more not recorded)", records_lost);
    }
    reset_records();
}

static LRESULT CALLBACK proc_w(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    LRESULT r;
    char text[96];

    if (msg == WM_SETTEXT) {
        copy_text(text, lparam != 0 ? ws((const WCHAR *)lparam) : "(null)");
    }
    r = DefWindowProcW(hwnd, msg, wparam, lparam);
    if (msg == WM_SETTEXT) {
        record("W", msg, wparam, r, text);
    } else if (msg == WM_GETTEXT) {
        record("W", msg, wparam, r, lparam != 0 && r > 0 ? wsn((const WCHAR *)lparam, (int)r) : "");
    } else if (msg == WM_GETTEXTLENGTH) {
        record("W", msg, wparam, r, NULL);
    }
    return r;
}

static LRESULT CALLBACK proc_a(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    LRESULT r;
    char text[96];

    if (msg == WM_SETTEXT) {
        copy_text(text, lparam != 0 ? as((const char *)lparam) : "(null)");
    }
    r = DefWindowProcA(hwnd, msg, wparam, lparam);
    if (msg == WM_SETTEXT) {
        record("A", msg, wparam, r, text);
    } else if (msg == WM_GETTEXT) {
        record("A", msg, wparam, r, lparam != 0 && r > 0 ? asn((const char *)lparam, (int)r) : "");
    } else if (msg == WM_GETTEXTLENGTH) {
        record("A", msg, wparam, r, NULL);
    }
    return r;
}

static LRESULT CALLBACK proc_custom(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    static const WCHAR answer[] = { 'f', 'r', 'o', 'm', ' ', 'p', 'r', 'o', 'c', 0 };
    WCHAR *buf;
    LRESULT r;
    int i;
    char text[96];

    if (msg == WM_GETTEXT) {
        buf = (WCHAR *)lparam;
        i = 0;
        if (buf != NULL && wparam > 0) {
            for (; i + 1 < (int)wparam && answer[i] != 0; i++) {
                buf[i] = answer[i];
            }
            buf[i] = 0;
        }
        record("custom", msg, wparam, i, buf != NULL ? wsn(buf, i) : "");
        return i;
    }
    if (msg == WM_GETTEXTLENGTH) {
        record("custom", msg, wparam, 9, NULL);
        return 9;
    }
    if (msg == WM_SETTEXT) {
        copy_text(text, lparam != 0 ? ws((const WCHAR *)lparam) : "(null)");
        r = refuse_set ? FALSE : DefWindowProcW(hwnd, msg, wparam, lparam);
        record("custom", msg, wparam, r, text);
        return r;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* Register the three classes once per process, and make the dead
 * handle. */
static void setup(void)
{
    static BOOL registered;
    WNDCLASSW wcw;
    WNDCLASSA wca;
    BOOL ok = TRUE;
    HINSTANCE inst = GetModuleHandleA(NULL);

    drain();
    reset_records();
    refuse_set = 0;
    if (!registered) {
        ZeroMemory(&wcw, sizeof wcw);
        wcw.lpfnWndProc = proc_w;
        wcw.hInstance = inst;
        wcw.lpszClassName = L"F2KWintextW";
        ok = ok && RegisterClassW(&wcw) != 0;
        wcw.lpfnWndProc = proc_custom;
        wcw.lpszClassName = L"F2KWintextCustom";
        ok = ok && RegisterClassW(&wcw) != 0;
        ZeroMemory(&wca, sizeof wca);
        wca.lpfnWndProc = proc_a;
        wca.hInstance = inst;
        wca.lpszClassName = CLASS_A;
        ok = ok && RegisterClassA(&wca) != 0;
        registered = ok;
        dead = CreateWindowExA(0, CLASS_A, "dead", WS_POPUP, 0, 0, 10, 10, NULL, NULL, inst, NULL);
        if (dead != NULL) {
            DestroyWindow(dead);
        }
    }
    line("setup: the classes registered: %s", yesno(registered));
    reset_records();
}

static HWND make_w(const WCHAR *title)
{
    return CreateWindowExW(0, L"F2KWintextW", title, WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                           GetModuleHandleA(NULL), NULL);
}

static HWND make_a(const char *title)
{
    return CreateWindowExA(0, CLASS_A, title, WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                           GetModuleHandleA(NULL), NULL);
}

static void destroy(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
    reset_records();
}

/* The read-backs: GetWindowTextLengthW/A and GetWindowTextW/A into 64
 * units, each with its records. */
static void read_w(const char *name, HWND h)
{
    WCHAR buf[64];
    int r;

    arm();
    r = GetWindowTextLengthW(h);
    line("GetWindowTextLengthW(%s): ret=%d err=%s", name, r, le());
    print_records();
    buf[0] = '#';
    buf[1] = 0;
    arm();
    r = GetWindowTextW(h, buf, 64);
    line("GetWindowTextW(%s, buf, 64): ret=%d err=%s text=\"%s\"", name, r, le(), ws(buf));
    print_records();
}

static void read_a(const char *name, HWND h)
{
    char buf[64];
    int r;

    arm();
    r = GetWindowTextLengthA(h);
    line("GetWindowTextLengthA(%s): ret=%d err=%s", name, r, le());
    print_records();
    buf[0] = '#';
    buf[1] = '\0';
    arm();
    r = GetWindowTextA(h, buf, 64);
    line("GetWindowTextA(%s, buf, 64): ret=%d err=%s text=\"%s\"", name, r, le(), as(buf));
    print_records();
}

/* --- create -------------------------------------------------------- */

static void sec_create(void)
{
    HWND h;

    setup();
    arm();
    h = make_w(L"wide title");
    line("CreateWindowExW(F2KWintextW, L\"wide title\"): non-NULL %s err=%s", yesno(h != NULL),
         le());
    print_records();
    read_w("the W window", h);
    read_a("the W window", h);
    destroy(h);

    arm();
    h = make_a("ansi title");
    line("CreateWindowExA(F2KWintextA, \"ansi title\"): non-NULL %s err=%s", yesno(h != NULL),
         le());
    print_records();
    read_a("the A window", h);
    read_w("the A window", h);
    destroy(h);

    arm();
    h = make_w(L"");
    line("CreateWindowExW(F2KWintextW, L\"\"): non-NULL %s err=%s", yesno(h != NULL), le());
    print_records();
    read_w("the W window", h);
    destroy(h);

    arm();
    h = make_w(NULL);
    line("CreateWindowExW(F2KWintextW, NULL): non-NULL %s err=%s", yesno(h != NULL), le());
    print_records();
    read_w("the W window", h);
    destroy(h);

    arm();
    h = make_a(NULL);
    line("CreateWindowExA(F2KWintextA, NULL): non-NULL %s err=%s", yesno(h != NULL), le());
    print_records();
    read_a("the A window", h);
    destroy(h);
}

/* --- setget -------------------------------------------------------- */

static void set_w(const char *name, HWND h, const WCHAR *text)
{
    BOOL r;

    arm();
    r = SetWindowTextW(h, text);
    line("SetWindowTextW(%s, %s%s%s): ret=%d err=%s", name, text != NULL ? "L\"" : "",
         text != NULL ? ws(text) : "NULL", text != NULL ? "\"" : "", r, le());
    print_records();
}

static void set_a(const char *name, HWND h, const char *text)
{
    BOOL r;

    arm();
    r = SetWindowTextA(h, text);
    line("SetWindowTextA(%s, %s%s%s): ret=%d err=%s", name, text != NULL ? "\"" : "",
         text != NULL ? as(text) : "NULL", text != NULL ? "\"" : "", r, le());
    print_records();
}

static void sec_setget(void)
{
    HWND hw, ha;

    setup();
    hw = make_w(L"start");
    ha = make_a("start");
    line("the W and A windows created: %s", yesno(hw != NULL && ha != NULL));
    reset_records();

    set_w("the W window", hw, L"hello");
    read_w("the W window", hw);
    set_w("the W window", hw, L"");
    read_w("the W window", hw);
    set_w("the W window", hw, L"again");
    set_w("the W window", hw, NULL);
    read_w("the W window", hw);

    set_a("the A window", ha, "hello");
    read_a("the A window", ha);
    set_a("the A window", ha, "");
    read_a("the A window", ha);
    set_a("the A window", ha, "again");
    set_a("the A window", ha, NULL);
    read_a("the A window", ha);

    set_w("NULL", NULL, L"x");
    set_a("a destroyed window", dead, "x");
    read_w("NULL", NULL);
    read_a("a destroyed window", dead);

    destroy(hw);
    destroy(ha);
}

/* --- trunc --------------------------------------------------------- */

/* The first 10 units of a buffer, a NUL as '|'. */
static const char *units_w(const WCHAR *buf)
{
    static WCHAR shown[11];
    int i;

    for (i = 0; i < 10; i++) {
        shown[i] = buf[i] == 0 ? '|' : buf[i];
    }
    shown[10] = 0;
    return ws(shown);
}

static const char *units_a(const char *buf)
{
    static char shown[11];
    int i;

    for (i = 0; i < 10; i++) {
        shown[i] = buf[i] == '\0' ? '|' : buf[i];
    }
    shown[10] = '\0';
    return as(shown);
}

static void fill_w(WCHAR *buf, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        buf[i] = '#';
    }
}

static void fill_a(char *buf, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        buf[i] = '#';
    }
}

static void sec_trunc(void)
{
    static const int counts[] = { 0, 1, 4, 8, 9, 64 };
    HWND hw, ha;
    WCHAR bufw[64];
    char bufa[64];
    int i;
    int r;

    setup();
    hw = make_w(L"abcdefgh");
    ha = make_a("abcdefgh");
    line("the W and A windows created, titled \"abcdefgh\": %s", yesno(hw != NULL && ha != NULL));
    reset_records();

    for (i = 0; i < (int)(sizeof counts / sizeof counts[0]); i++) {
        fill_w(bufw, 64);
        arm();
        r = GetWindowTextW(hw, bufw, counts[i]);
        line("GetWindowTextW(the W window, buf, %d): ret=%d err=%s buffer=%s", counts[i], r, le(),
             units_w(bufw));
        print_records();
    }
    for (i = 0; i < (int)(sizeof counts / sizeof counts[0]); i++) {
        fill_a(bufa, 64);
        arm();
        r = GetWindowTextA(ha, bufa, counts[i]);
        line("GetWindowTextA(the A window, buf, %d): ret=%d err=%s buffer=%s", counts[i], r, le(),
             units_a(bufa));
        print_records();
    }
    destroy(hw);
    destroy(ha);
}

/* --- messages ------------------------------------------------------ */

static void sec_messages(void)
{
    static const int sizes[] = { 0, 5, 64 };
    HWND hw, ha;
    WCHAR bufw[64];
    char bufa[64];
    LRESULT r;
    int i;

    setup();
    hw = make_w(L"start");
    ha = make_a("start");
    line("the W and A windows created: %s", yesno(hw != NULL && ha != NULL));
    reset_records();

    arm();
    r = SendMessageW(hw, WM_SETTEXT, 0, (LPARAM)L"sent text");
    line("SendMessageW(the W window, WM_SETTEXT, 0, L\"sent text\"): ret=%ld err=%s", (long)r, le());
    print_records();
    arm();
    r = SendMessageW(hw, WM_GETTEXTLENGTH, 0, 0);
    line("SendMessageW(the W window, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    print_records();
    for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); i++) {
        fill_w(bufw, 64);
        arm();
        r = SendMessageW(hw, WM_GETTEXT, sizes[i], (LPARAM)bufw);
        line("SendMessageW(the W window, WM_GETTEXT, %d, buf): ret=%ld err=%s buffer=%s", sizes[i],
             (long)r, le(), units_w(bufw));
        print_records();
    }
    arm();
    r = SendMessageW(hw, WM_SETTEXT, 0, 0);
    line("SendMessageW(the W window, WM_SETTEXT, 0, NULL): ret=%ld err=%s", (long)r, le());
    print_records();
    arm();
    r = SendMessageW(hw, WM_GETTEXTLENGTH, 0, 0);
    line("SendMessageW(the W window, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    print_records();

    arm();
    r = SendMessageA(ha, WM_SETTEXT, 0, (LPARAM)"sent text");
    line("SendMessageA(the A window, WM_SETTEXT, 0, \"sent text\"): ret=%ld err=%s", (long)r, le());
    print_records();
    arm();
    r = SendMessageA(ha, WM_GETTEXTLENGTH, 0, 0);
    line("SendMessageA(the A window, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    print_records();
    for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); i++) {
        fill_a(bufa, 64);
        arm();
        r = SendMessageA(ha, WM_GETTEXT, sizes[i], (LPARAM)bufa);
        line("SendMessageA(the A window, WM_GETTEXT, %d, buf): ret=%ld err=%s buffer=%s", sizes[i],
             (long)r, le(), units_a(bufa));
        print_records();
    }
    arm();
    r = SendMessageA(ha, WM_SETTEXT, 0, 0);
    line("SendMessageA(the A window, WM_SETTEXT, 0, NULL): ret=%ld err=%s", (long)r, le());
    print_records();
    arm();
    r = SendMessageA(ha, WM_GETTEXTLENGTH, 0, 0);
    line("SendMessageA(the A window, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    print_records();

    /* DefWindowProc called directly, the window procedure not in the
     * call: the records show whether anything reached it. */
    arm();
    r = DefWindowProcW(hw, WM_SETTEXT, 0, (LPARAM)L"direct");
    line("DefWindowProcW(the W window, WM_SETTEXT, 0, L\"direct\"): ret=%ld err=%s", (long)r, le());
    print_records();
    arm();
    r = DefWindowProcW(hw, WM_GETTEXTLENGTH, 0, 0);
    line("DefWindowProcW(the W window, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    print_records();
    for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); i++) {
        fill_w(bufw, 64);
        arm();
        r = DefWindowProcW(hw, WM_GETTEXT, sizes[i], (LPARAM)bufw);
        line("DefWindowProcW(the W window, WM_GETTEXT, %d, buf): ret=%ld err=%s buffer=%s", sizes[i],
             (long)r, le(), units_w(bufw));
        print_records();
    }
    read_w("the W window", hw);

    arm();
    r = DefWindowProcA(ha, WM_SETTEXT, 0, (LPARAM)"direct");
    line("DefWindowProcA(the A window, WM_SETTEXT, 0, \"direct\"): ret=%ld err=%s", (long)r, le());
    print_records();
    arm();
    r = DefWindowProcA(ha, WM_GETTEXTLENGTH, 0, 0);
    line("DefWindowProcA(the A window, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    print_records();
    for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); i++) {
        fill_a(bufa, 64);
        arm();
        r = DefWindowProcA(ha, WM_GETTEXT, sizes[i], (LPARAM)bufa);
        line("DefWindowProcA(the A window, WM_GETTEXT, %d, buf): ret=%ld err=%s buffer=%s", sizes[i],
             (long)r, le(), units_a(bufa));
        print_records();
    }
    read_a("the A window", ha);

    destroy(hw);
    destroy(ha);
}

/* --- cross --------------------------------------------------------- */

static void sec_cross(void)
{
    /* "cafe" with U+00E9 for its e, a blank, U+4E00, "!" */
    static const WCHAR mixed[] = { 'c', 'a', 'f', 0x00E9, ' ', 0x4E00, '!', 0 };
    HWND hw, ha;
    char bufa[64];
    int r;

    setup();
    hw = make_w(L"start");
    ha = make_a("start");
    line("the W and A windows created: %s", yesno(hw != NULL && ha != NULL));
    reset_records();

    set_w("the A window", ha, mixed);
    read_a("the A window", ha);
    read_w("the A window", ha);

    set_a("the W window", hw, "caf\xE9!");
    read_w("the W window", hw);
    read_a("the W window", hw);

    set_w("the W window", hw, mixed);
    read_w("the W window", hw);
    read_a("the W window", hw);
    fill_a(bufa, 64);
    arm();
    r = GetWindowTextA(hw, bufa, 5);
    line("GetWindowTextA(the W window, buf, 5): ret=%d err=%s buffer=%s", r, le(), units_a(bufa));
    print_records();

    destroy(hw);
    destroy(ha);
}

/* --- custom -------------------------------------------------------- */

static void sec_custom(void)
{
    HWND h;
    WCHAR bufw[64];
    LRESULT r;

    setup();
    arm();
    h = CreateWindowExW(0, L"F2KWintextCustom", L"real title", WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    line("CreateWindowExW(F2KWintextCustom, L\"real title\"): non-NULL %s err=%s", yesno(h != NULL),
         le());
    print_records();

    read_w("the custom window", h);
    read_a("the custom window", h);

    refuse_set = 1;
    set_w("the custom window, refusing", h, L"refused");
    fill_w(bufw, 64);
    arm();
    r = DefWindowProcW(h, WM_GETTEXT, 64, (LPARAM)bufw);
    line("DefWindowProcW(the custom window, WM_GETTEXT, 64, buf): ret=%ld err=%s text=\"%s\"",
         (long)r, le(), r >= 0 && r < 64 ? wsn(bufw, (int)r) : "?");
    print_records();

    refuse_set = 0;
    set_w("the custom window, accepting", h, L"accepted");
    fill_w(bufw, 64);
    arm();
    r = DefWindowProcW(h, WM_GETTEXT, 64, (LPARAM)bufw);
    line("DefWindowProcW(the custom window, WM_GETTEXT, 64, buf): ret=%ld err=%s text=\"%s\"",
         (long)r, le(), r >= 0 && r < 64 ? wsn(bufw, (int)r) : "?");
    print_records();
    read_w("the custom window", h);

    destroy(h);
}

/* --- internal ------------------------------------------------------ */

typedef int (WINAPI *internal_fn)(HWND, LPWSTR, int);

static void internal_get(internal_fn fn, const char *name, HWND h, int count)
{
    WCHAR buf[64];
    int r;

    fill_w(buf, 64);
    arm();
    r = fn(h, buf, count);
    line("InternalGetWindowText(%s, buf, %d): ret=%d err=%s buffer=%s", name, count, r, le(),
         units_w(buf));
    print_records();
}

static void sec_internal(void)
{
    static const int counts[] = { 0, 1, 4, 8, 9, 64 };
    static const WCHAR mixed[] = { 'c', 'a', 'f', 0x00E9, 0x4E00, 0 };
    internal_fn fn;
    HWND hw, ha, hc, hn;
    int i;

    setup();
    fn = (internal_fn)GetProcAddress(GetModuleHandleA("user32.dll"), "InternalGetWindowText");
    line("GetProcAddress(user32, InternalGetWindowText): non-NULL %s", yesno(fn != NULL));
    if (fn == NULL) {
        return;
    }
    hw = make_w(L"abcdefgh");
    ha = make_a("abcdefgh");
    hc = CreateWindowExW(0, L"F2KWintextCustom", L"real title", WS_POPUP, 0, 0, 320, 200, NULL,
                         NULL, GetModuleHandleA(NULL), NULL);
    hn = make_w(NULL);
    line("the W and A windows titled \"abcdefgh\", the custom window titled \"real title\" and an "
         "untitled W window created: %s",
         yesno(hw != NULL && ha != NULL && hc != NULL && hn != NULL));
    reset_records();

    for (i = 0; i < 6; i++) {
        internal_get(fn, "the W window", hw, counts[i]);
    }
    for (i = 0; i < 6; i++) {
        internal_get(fn, "the A window", ha, counts[i]);
    }
    internal_get(fn, "the custom window", hc, 64);
    internal_get(fn, "the untitled window", hn, 64);
    set_w("the W window", hw, mixed);
    internal_get(fn, "the W window", hw, 64);
    internal_get(fn, "the W window", hw, 4);
    internal_get(fn, "NULL", NULL, 64);
    internal_get(fn, "a destroyed window", dead, 64);

    destroy(hw);
    destroy(ha);
    destroy(hc);
    destroy(hn);
}

/* --- xproc --------------------------------------------------------- */

#define XPROC_CLASS L"F2KWintextXproc"
#define XPROC_READY "F2KWintextXprocReady"

/* The child's procedure: its text is DefWindowProcW's; WM_CLOSE (or
 * the 10-second timer, should the parent never send it) ends it. */
static LRESULT CALLBACK xproc_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_TIMER:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/* wintext.exe --xchild: the other process of xproc. It prints nothing
 * (its output would land in the parent's block): it makes a hidden
 * window of its own class titled "xproc title", sets the parent's
 * event, and serves its messages until the window goes. */
static int xchild(void)
{
    WNDCLASSW wc;
    HWND h;
    HANDLE ready;
    MSG m;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = xproc_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = XPROC_CLASS;
    RegisterClassW(&wc);
    h = CreateWindowExW(0, XPROC_CLASS, L"xproc title", WS_POPUP, 0, 0, 100, 50, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    if (h == NULL) {
        return 3;
    }
    SetTimer(h, 1, 10000, NULL);
    ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, XPROC_READY);
    if (ready != NULL) {
        SetEvent(ready);
        CloseHandle(ready);
    }
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        DispatchMessageW(&m);
    }
    return 0;
}

static void sec_xproc(void)
{
    char path[MAX_PATH];
    char cmdline[MAX_PATH + 16];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE ready;
    HWND h;
    WCHAR bufw[64];
    char bufa[64];
    LRESULT r;
    DWORD code;
    DWORD w;
    BOOL ok;

    ready = CreateEventA(NULL, TRUE, FALSE, XPROC_READY);
    GetModuleFileNameA(NULL, path, sizeof path);
    sprintf(cmdline, "\"%s\" --xchild", path);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    arm();
    ok = CreateProcessA(path, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    line("CreateProcessA(wintext.exe --xchild): ret=%d err=%s", ok, le());
    if (!ok) {
        CloseHandle(ready);
        return;
    }
    w = WaitForSingleObject(ready, WAIT_MS);
    line("the child's window made: %s", wr(w));
    CloseHandle(ready);

    arm();
    h = FindWindowW(XPROC_CLASS, NULL);
    line("FindWindowW(F2KWintextXproc): non-NULL %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        line("the window's thread is the child's: %s",
             yesno(GetWindowThreadProcessId(h, NULL) == pi.dwThreadId));

        fill_w(bufw, 64);
        arm();
        r = GetWindowTextW(h, bufw, 64);
        line("GetWindowTextW(64): ret=%ld %s err=%s", (long)r, units_w(bufw), le());

        arm();
        r = SendMessageW(h, WM_GETTEXTLENGTH, 0, 0);
        line("SendMessageW(WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
        fill_w(bufw, 64);
        arm();
        r = SendMessageW(h, WM_GETTEXT, 64, (LPARAM)bufw);
        line("SendMessageW(WM_GETTEXT, 64): ret=%ld %s err=%s", (long)r, units_w(bufw), le());
        fill_w(bufw, 64);
        arm();
        r = SendMessageW(h, WM_GETTEXT, 5, (LPARAM)bufw);
        line("SendMessageW(WM_GETTEXT, 5): ret=%ld %s err=%s", (long)r, units_w(bufw), le());
        fill_a(bufa, 64);
        arm();
        r = SendMessageA(h, WM_GETTEXT, 64, (LPARAM)bufa);
        line("SendMessageA(WM_GETTEXT, 64): ret=%ld %s err=%s", (long)r, units_a(bufa), le());

        arm();
        r = SendMessageW(h, WM_SETTEXT, 0, (LPARAM)L"set across");
        line("SendMessageW(WM_SETTEXT, \"set across\"): ret=%ld err=%s", (long)r, le());
        fill_w(bufw, 64);
        arm();
        r = GetWindowTextW(h, bufw, 64);
        line("  GetWindowTextW(64) after: ret=%ld %s err=%s", (long)r, units_w(bufw), le());
        arm();
        r = SendMessageA(h, WM_SETTEXT, 0, (LPARAM)"set by A");
        line("SendMessageA(WM_SETTEXT, \"set by A\"): ret=%ld err=%s", (long)r, le());
        fill_a(bufa, 64);
        arm();
        r = SendMessageA(h, WM_GETTEXT, 64, (LPARAM)bufa);
        line("  SendMessageA(WM_GETTEXT, 64) after: ret=%ld %s err=%s", (long)r, units_a(bufa), le());

        PostMessageW(h, WM_CLOSE, 0, 0);
    }
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    line("the child ended: %s", wr(w));
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, WAIT_MS);
    }
    code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    line("the child's exit code: 0x%08lX", (unsigned long)code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "setget", sec_setget, F2KT_ALWAYS },
    { "trunc", sec_trunc, F2KT_ALWAYS },
    { "messages", sec_messages, F2KT_ALWAYS },
    { "cross", sec_cross, F2KT_ALWAYS },
    { "custom", sec_custom, F2KT_ALWAYS },
    { "internal", sec_internal, F2KT_ALWAYS },
    { "xproc", sec_xproc, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc >= 2 && strcmp(argv[1], "--xchild") == 0) {
        return xchild();
    }
    return run_sections("wintext", sections, argc, argv);
}
