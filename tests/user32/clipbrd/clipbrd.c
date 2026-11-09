/*
 * clipbrd - the clipboard in user32: OpenClipboard, CloseClipboard,
 * EmptyClipboard, SetClipboardData, GetClipboardData,
 * IsClipboardFormatAvailable, CountClipboardFormats,
 * EnumClipboardFormats, GetOpenClipboardWindow, GetClipboardOwner,
 * RegisterClipboardFormatA/W and GetClipboardFormatNameA/W; text put as
 * CF_UNICODETEXT, CF_TEXT or CF_OEMTEXT and read back in the others
 * (the conversions the system synthesises), the owner's
 * WM_DESTROYCLIPBOARD, and delayed rendering (WM_RENDERFORMAT,
 * WM_RENDERALLFORMATS).
 *
 * The machine's clipboard is left empty at both ends of every section:
 * each section opens it (with no window), empties it and closes it,
 * unprinted, at its start and at its end, and closes it before it
 * prints whenever it opened it. Each open is retried for up to a second
 * (40 times, 25 ms apart, the window's messages pumped in between), in
 * case another program holds it for a moment; the line prints the last
 * attempt's result. The capture expects no other program to put data
 * on the clipboard or ask for it while it runs (a VirtualBox VM's
 * shared clipboard set to Disabled).
 *
 * The text conversions depend on the code pages: each section that
 * converts prints whether the ANSI code page is 1252 and the OEM one
 * 437 (US English Windows 2000), as preconditions.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare
 * (yesno()); every call under observation is armed with the last-error
 * sentinel and its line prints ret= and err=. Clipboard data prints as
 * its text (wide through ws(), bytes with anything below 0x20 or above
 * 0x7E as \xNN), whether it ends with a NUL within its block, and
 * whether GlobalSize is exactly the text and its NUL. A registered
 * format prints as "registered", never by number. The windows are
 * hidden (explicit 320x200) and of a class the section registers; their
 * procedure records the clipboard messages sent to it from its own
 * thread (message, which window, wParam as a format), printed after the
 * calls, and answers WM_RENDERFORMAT and WM_RENDERALLFORMATS with text
 * when the section asks it to.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   open      OpenClipboard with the window, again with it open,
 *             CloseClipboard twice; GetOpenClipboardWindow while open
 *             and after; EmptyClipboard, SetClipboardData,
 *             GetClipboardData and IsClipboardFormatAvailable with the
 *             clipboard closed; OpenClipboard(NULL), EmptyClipboard and
 *             SetClipboardData with no owner; GetClipboardOwner after
 *             an empty with the window, and after the close
 *   unicode   CF_UNICODETEXT put (text with U+00E9, U+4E00 and CR LF):
 *             IsClipboardFormatAvailable for CF_UNICODETEXT, CF_TEXT,
 *             CF_OEMTEXT, CF_LOCALE and CF_BITMAP; GetClipboardData of
 *             each text format (its text, NUL and size) and of
 *             CF_LOCALE (its size, and whether it is the keyboard
 *             layout's language); the handle given back or not, asked
 *             twice, and in a second open
 *   text      the same with CF_TEXT put (U+00E9 as 0xE9, CR LF), then
 *             with CF_OEMTEXT put (0x82, U+00E9 in code page 437)
 *   formats   CountClipboardFormats and EnumClipboardFormats' order
 *             while open after an empty and a put, after the close, and
 *             in the next open; EnumClipboardFormats closed;
 *             RegisterClipboardFormatW/A of one name in two cases,
 *             GetClipboardFormatNameW/A (full, short, a predefined
 *             format); CF_TEXT, CF_UNICODETEXT and a registered format
 *             put together: the order and each text as put
 *   owner     two windows: the second's EmptyClipboard and the first's
 *             WM_DESTROYCLIPBOARD; the owner's own EmptyClipboard; the
 *             owner destroyed with text on the clipboard: the messages,
 *             GetClipboardOwner, and the text still there or not
 *   delayed   SetClipboardData(CF_UNICODETEXT, NULL): the formats
 *             available; GetClipboardData of CF_UNICODETEXT, then of
 *             CF_TEXT first, each sending WM_RENDERFORMAT (the
 *             procedure's own SetClipboardData result); the owner
 *             destroyed with a format still delayed (WM_RENDERALLFORMATS,
 *             the procedure opening the clipboard and putting the text)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat clipbrd):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% clipbrd.c user32.lib
 */

#include "../common/f2kt.h"

#ifndef CF_LOCALE
#define CF_LOCALE 16
#endif

#define CLASS_NAME "F2KClipbrd"
#define REGISTERED_W L"F2K Clipbrd Format"
#define REGISTERED_A "f2k clipbrd format"

/* The text the procedure renders. */
#define RENDERED_W L"rendered text"

/* The section's windows, and the format it registered. */
static HWND win[2];
static UINT registered;

/* How the procedure answers WM_RENDERFORMAT and WM_RENDERALLFORMATS. */
static int render_text;

/* The clipboard messages the procedure received from its own thread. */
#define LOG_MAX 16
static struct {
    UINT msg;
    HWND hwnd;
    WPARAM wparam;
} msg_log[LOG_MAX];
static int log_count;

/* What the procedure's own calls returned while rendering. */
static int render_open;
static int render_set;
static DWORD render_err;

/* The setup calls' last errors. */
static DWORD reg_err;

/* A moveable block holding a wide string and its NUL; NULL on failure. */
static HGLOBAL mem_w(const WCHAR *s)
{
    HGLOBAL h;
    WCHAR *p;
    DWORD bytes = (DWORD)((wcslen(s) + 1) * sizeof(WCHAR));

    h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h == NULL) {
        return NULL;
    }
    p = (WCHAR *)GlobalLock(h);
    memcpy(p, s, bytes);
    GlobalUnlock(h);
    return h;
}

/* The same for bytes. */
static HGLOBAL mem_a(const char *s)
{
    HGLOBAL h;
    char *p;
    DWORD bytes = (DWORD)strlen(s) + 1;

    h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h == NULL) {
        return NULL;
    }
    p = (char *)GlobalLock(h);
    memcpy(p, s, bytes);
    GlobalUnlock(h);
    return h;
}

/* The procedure's answer to a render request: the text, put. */
static void render(UINT format)
{
    HGLOBAL m = mem_w(RENDERED_W);

    SetLastError(F2KT_UNTOUCHED);
    render_set = SetClipboardData(format, m) != NULL;
    render_err = GetLastError();
    if (!render_set && m != NULL) {
        GlobalFree(m);
    }
}

static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_DESTROYCLIPBOARD || msg == WM_RENDERFORMAT || msg == WM_RENDERALLFORMATS) {
        /* Another program's request (a clipboard viewer's) is served
         * but not recorded: only this thread's own calls are. */
        if (!InSendMessage() && log_count < LOG_MAX) {
            msg_log[log_count].msg = msg;
            msg_log[log_count].hwnd = hwnd;
            msg_log[log_count].wparam = wparam;
            log_count++;
        }
        if (msg == WM_RENDERFORMAT && render_text) {
            render((UINT)wparam);
        }
        if (msg == WM_RENDERALLFORMATS && render_text) {
            render_open = OpenClipboard(hwnd) != FALSE;
            if (render_open) {
                if (GetClipboardOwner() == hwnd) {
                    render(CF_UNICODETEXT);
                }
                CloseClipboard();
            }
        }
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

/* Handle any message waiting, without waiting for one. */
static void pump(void)
{
    MSG m;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
}

/* A window as printed: which of the section's, NULL, or another. */
static const char *which(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == win[0]) {
        return "first";
    }
    if (h == win[1]) {
        return "second";
    }
    return "another";
}

/* A format as printed: its name, "registered", or its number. */
static const char *fmt_name(UINT f)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    switch (f) {
    case CF_TEXT: return "CF_TEXT";
    case CF_BITMAP: return "CF_BITMAP";
    case CF_OEMTEXT: return "CF_OEMTEXT";
    case CF_UNICODETEXT: return "CF_UNICODETEXT";
    case CF_LOCALE: return "CF_LOCALE";
    }
    if (f != 0 && f == registered) {
        return "registered";
    }
    if (f >= 0xC000) {
        return "another registered";
    }
    sprintf(b, "%u", f);
    return b;
}

static const char *msg_name(UINT m)
{
    switch (m) {
    case WM_DESTROYCLIPBOARD: return "WM_DESTROYCLIPBOARD";
    case WM_RENDERFORMAT: return "WM_RENDERFORMAT";
    case WM_RENDERALLFORMATS: return "WM_RENDERALLFORMATS";
    }
    return "?";
}

static void reset_log(void)
{
    log_count = 0;
    render_open = -1;
    render_set = -1;
    render_err = F2KT_UNTOUCHED;
}

static void print_log(void)
{
    int i;

    pump();
    line("messages received: %d", log_count);
    for (i = 0; i < log_count; i++) {
        if (msg_log[i].msg == WM_RENDERFORMAT) {
            line("  %s to %s, wParam=%s", msg_name(msg_log[i].msg), which(msg_log[i].hwnd),
                 fmt_name((UINT)msg_log[i].wparam));
        } else {
            line("  %s to %s", msg_name(msg_log[i].msg), which(msg_log[i].hwnd));
        }
    }
    if (render_open != -1) {
        line("  the procedure's OpenClipboard: ret=%d", render_open);
    }
    if (render_set != -1) {
        line("  the procedure's SetClipboardData: non-NULL %s err=%s", yesno(render_set),
             le_of(render_err));
    }
}

/* Open, retrying while another program holds the clipboard. */
static BOOL open_retry(HWND h)
{
    BOOL r = FALSE;
    int i;

    for (i = 0; i < 40; i++) {
        arm();
        r = OpenClipboard(h);
        if (r) {
            break;
        }
        pump();
        Sleep(25);
    }
    return r;
}

/* Leave the clipboard empty and closed, unprinted. */
static void clear(void)
{
    if (open_retry(NULL)) {
        EmptyClipboard();
        CloseClipboard();
    }
}

static void open_line(HWND h)
{
    BOOL r = open_retry(h);

    line("OpenClipboard(%s): ret=%d err=%s", which(h), r, le());
}

static void close_line(void)
{
    BOOL r;

    arm();
    r = CloseClipboard();
    line("CloseClipboard: ret=%d err=%s", r, le());
}

static void empty_line(void)
{
    BOOL r;

    arm();
    r = EmptyClipboard();
    line("EmptyClipboard: ret=%d err=%s", r, le());
}

/* Put a block; it is freed here if the call refuses it. Returns the
 * handle given back. */
static HANDLE set_line(UINT format, HGLOBAL m, const char *what)
{
    HANDLE r;

    arm();
    r = SetClipboardData(format, m);
    line("SetClipboardData(%s, %s): non-NULL %s err=%s the block given %s", fmt_name(format), what,
         yesno(r != NULL), le(), yesno(r != NULL && r == m));
    if (r == NULL && m != NULL) {
        GlobalFree(m);
    }
    return r;
}

static void available(UINT format)
{
    BOOL r;

    arm();
    r = IsClipboardFormatAvailable(format);
    line("IsClipboardFormatAvailable(%s): ret=%d err=%s", fmt_name(format), r, le());
}

/* GetClipboardData of a wide text format: its text, NUL and size. */
static HANDLE get_w(UINT format)
{
    HANDLE h;
    WCHAR *p;
    DWORD size;
    DWORD units;
    DWORD n;

    arm();
    h = GetClipboardData(format);
    line("GetClipboardData(%s): non-NULL %s err=%s", fmt_name(format), yesno(h != NULL), le());
    if (h == NULL) {
        return NULL;
    }
    size = GlobalSize(h);
    p = (WCHAR *)GlobalLock(h);
    if (p == NULL) {
        line("  GlobalLock failed");
        return h;
    }
    units = size / sizeof(WCHAR);
    for (n = 0; n < units && p[n] != 0; n++) {
    }
    line("  text [%s] NUL within the block %s, size the text and its NUL exactly %s",
         wsn(p, (int)n), yesno(n < units), yesno(size == (n + 1) * sizeof(WCHAR)));
    GlobalUnlock(h);
    return h;
}

/* The same for a byte text format. */
static HANDLE get_a(UINT format)
{
    HANDLE h;
    unsigned char *p;
    DWORD size;
    DWORD n;
    char text[512];
    int t = 0;

    arm();
    h = GetClipboardData(format);
    line("GetClipboardData(%s): non-NULL %s err=%s", fmt_name(format), yesno(h != NULL), le());
    if (h == NULL) {
        return NULL;
    }
    size = GlobalSize(h);
    p = (unsigned char *)GlobalLock(h);
    if (p == NULL) {
        line("  GlobalLock failed");
        return h;
    }
    for (n = 0; n < size && p[n] != 0; n++) {
        if (t < (int)sizeof text - 8) {
            if (p[n] < 0x20 || p[n] > 0x7E) {
                t += sprintf(text + t, "\\x%02X", p[n]);
            } else {
                text[t++] = (char)p[n];
            }
        }
    }
    text[t] = '\0';
    line("  text [%s] NUL within the block %s, size the text and its NUL exactly %s", text,
         yesno(n < size), yesno(size == n + 1));
    GlobalUnlock(h);
    return h;
}

/* The code pages the conversions depend on. */
static void code_pages(void)
{
    line("ANSI code page 1252: %s, OEM code page 437: %s", yesno(GetACP() == 1252),
         yesno(GetOEMCP() == 437));
}

/* Every format EnumClipboardFormats lists, in order. */
static void enum_line(const char *when)
{
    char list[512];
    int n = 0;
    int count = 0;
    UINT f = 0;

    list[0] = '\0';
    for (;;) {
        arm();
        f = EnumClipboardFormats(f);
        if (f == 0 || count >= 32) {
            break;
        }
        if (n < (int)sizeof list - 40) {
            n += sprintf(list + n, "%s%s", count ? " " : "", fmt_name(f));
        }
        count++;
    }
    line("EnumClipboardFormats, %s: [%s] ends err=%s", when, list, le());
}

static void count_line(const char *when)
{
    int r;

    arm();
    r = CountClipboardFormats();
    line("CountClipboardFormats, %s: ret=%d err=%s", when, r, le());
}

static HWND make_window(void)
{
    HWND h;

    arm();
    h = CreateWindowExA(0, CLASS_NAME, "clipbrd", WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    line("CreateWindowExA(%s, hidden, 320x200): non-NULL %s err=%s", CLASS_NAME,
         yesno(h != NULL), le());
    return h;
}

/* The section's start: the clipboard emptied, the class and windows. */
static void start(int windows)
{
    WNDCLASSA wc;
    ATOM a;

    clear();
    win[0] = NULL;
    win[1] = NULL;
    registered = 0;
    render_text = 0;
    reset_log();
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = CLASS_NAME;
    arm();
    a = RegisterClassA(&wc);
    reg_err = GetLastError();
    line("RegisterClassA(%s): atom nonzero %s err=%s", CLASS_NAME, yesno(a != 0), le_of(reg_err));
    win[0] = make_window();
    if (windows > 1) {
        win[1] = make_window();
    }
}

/* The section's end: the clipboard emptied and closed, the windows gone. */
static void finish(void)
{
    render_text = 0;
    clear();
    if (win[0] != NULL) {
        DestroyWindow(win[0]);
    }
    if (win[1] != NULL) {
        DestroyWindow(win[1]);
    }
    pump();
    UnregisterClassA(CLASS_NAME, GetModuleHandleA(NULL));
}

/* --- open ---------------------------------------------------------- */

static void sec_open(void)
{
    BOOL r;
    HANDLE d;

    start(1);

    open_line(win[0]);
    line("GetOpenClipboardWindow: %s", which(GetOpenClipboardWindow()));
    arm();
    r = OpenClipboard(win[0]);
    line("OpenClipboard(first), already open: ret=%d err=%s", r, le());
    close_line();
    line("GetOpenClipboardWindow: %s", which(GetOpenClipboardWindow()));
    close_line();

    /* Closed. */
    empty_line();
    set_line(CF_UNICODETEXT, mem_w(L"closed"), "L\"closed\"");
    arm();
    d = GetClipboardData(CF_UNICODETEXT);
    line("GetClipboardData(CF_UNICODETEXT), closed: non-NULL %s err=%s", yesno(d != NULL), le());
    available(CF_UNICODETEXT);

    /* No owner. */
    open_line(NULL);
    line("GetOpenClipboardWindow: %s", which(GetOpenClipboardWindow()));
    empty_line();
    line("GetClipboardOwner: %s", which(GetClipboardOwner()));
    set_line(CF_UNICODETEXT, mem_w(L"no owner"), "L\"no owner\"");
    close_line();
    available(CF_UNICODETEXT);

    /* The window as owner. */
    open_line(win[0]);
    empty_line();
    line("GetClipboardOwner: %s", which(GetClipboardOwner()));
    close_line();
    line("GetClipboardOwner, closed: %s", which(GetClipboardOwner()));

    finish();
}

/* --- unicode ------------------------------------------------------- */

static void sec_unicode(void)
{
    HANDLE given;
    HANDLE got;
    HANDLE text1;
    HANDLE text2;
    HANDLE locale;
    DWORD *p;

    start(1);
    code_pages();

    open_line(win[0]);
    empty_line();
    given = set_line(CF_UNICODETEXT, mem_w(L"Hello, clipboard: caf\x00E9 \x4E00!\r\nline two"),
                     "L\"Hello, clipboard: caf<U+00E9> <U+4E00>!\\r\\nline two\"");
    close_line();

    available(CF_UNICODETEXT);
    available(CF_TEXT);
    available(CF_OEMTEXT);
    available(CF_LOCALE);
    available(CF_BITMAP);

    open_line(win[0]);
    got = get_w(CF_UNICODETEXT);
    line("  the handle SetClipboardData gave back: %s", yesno(got != NULL && got == given));
    text1 = get_a(CF_TEXT);
    get_a(CF_OEMTEXT);
    arm();
    locale = GetClipboardData(CF_LOCALE);
    line("GetClipboardData(CF_LOCALE): non-NULL %s err=%s", yesno(locale != NULL), le());
    if (locale != NULL) {
        p = (DWORD *)GlobalLock(locale);
        line("  size 4: %s, the keyboard layout's language: %s", yesno(GlobalSize(locale) == 4),
             yesno(p != NULL &&
                   *p == MAKELCID(LOWORD((DWORD)GetKeyboardLayout(0)), SORT_DEFAULT)));
        if (p != NULL) {
            GlobalUnlock(locale);
        }
    }
    text2 = get_a(CF_TEXT);
    line("  the same handle as the first CF_TEXT: %s", yesno(text2 != NULL && text2 == text1));
    arm();
    got = GetClipboardData(CF_BITMAP);
    line("GetClipboardData(CF_BITMAP): non-NULL %s err=%s", yesno(got != NULL), le());
    close_line();

    open_line(win[0]);
    text2 = get_a(CF_TEXT);
    line("  the same handle as the first open's CF_TEXT: %s", yesno(text2 != NULL && text2 == text1));
    close_line();

    finish();
}

/* --- text ---------------------------------------------------------- */

static void sec_text(void)
{
    HANDLE given;
    HANDLE got;

    start(1);
    code_pages();

    open_line(win[0]);
    empty_line();
    given = set_line(CF_TEXT, mem_a("Caf\xE9 text\r\nline two"), "\"Caf\\xE9 text\\r\\nline two\"");
    close_line();
    available(CF_TEXT);
    available(CF_UNICODETEXT);
    available(CF_OEMTEXT);
    available(CF_LOCALE);
    open_line(win[0]);
    got = get_a(CF_TEXT);
    line("  the handle SetClipboardData gave back: %s", yesno(got != NULL && got == given));
    get_w(CF_UNICODETEXT);
    get_a(CF_OEMTEXT);
    close_line();

    open_line(win[0]);
    empty_line();
    given = set_line(CF_OEMTEXT, mem_a("Caf\x82 oem"), "\"Caf\\x82 oem\"");
    close_line();
    available(CF_OEMTEXT);
    available(CF_TEXT);
    available(CF_UNICODETEXT);
    available(CF_LOCALE);
    open_line(win[0]);
    got = get_a(CF_OEMTEXT);
    line("  the handle SetClipboardData gave back: %s", yesno(got != NULL && got == given));
    get_a(CF_TEXT);
    get_w(CF_UNICODETEXT);
    close_line();

    finish();
}

/* --- formats ------------------------------------------------------- */

static void sec_formats(void)
{
    UINT again;
    int r;
    WCHAR wname[64];
    char aname[64];
    HGLOBAL m;

    start(1);

    open_line(win[0]);
    empty_line();
    count_line("open, emptied");
    enum_line("open, emptied");
    set_line(CF_UNICODETEXT, mem_w(L"wide"), "L\"wide\"");
    count_line("open, after the put");
    enum_line("open, after the put");
    close_line();
    count_line("closed");
    enum_line("closed");
    open_line(win[0]);
    count_line("the next open");
    enum_line("the next open");
    close_line();

    arm();
    registered = RegisterClipboardFormatW(REGISTERED_W);
    line("RegisterClipboardFormatW(L\"F2K Clipbrd Format\"): in 0xC000-0xFFFF %s err=%s",
         yesno(registered >= 0xC000 && registered <= 0xFFFF), le());
    arm();
    again = RegisterClipboardFormatA(REGISTERED_A);
    line("RegisterClipboardFormatA(\"f2k clipbrd format\"): the same format %s err=%s",
         yesno(again == registered), le());
    arm();
    r = GetClipboardFormatNameW(registered, wname, 64);
    line("GetClipboardFormatNameW(registered, 64): ret=%d err=%s [%s]", r, le(),
         r > 0 ? wsn(wname, r) : "");
    arm();
    r = GetClipboardFormatNameA(registered, aname, 64);
    aname[63] = '\0';
    line("GetClipboardFormatNameA(registered, 64): ret=%d err=%s [%s]", r, le(), r > 0 ? aname : "");
    memset(aname, '#', sizeof aname);
    arm();
    r = GetClipboardFormatNameA(registered, aname, 4);
    line("GetClipboardFormatNameA(registered, 4): ret=%d err=%s NUL at 3 %s", r, le(),
         yesno(aname[3] == '\0'));
    arm();
    r = GetClipboardFormatNameW(CF_TEXT, wname, 64);
    line("GetClipboardFormatNameW(CF_TEXT, 64): ret=%d err=%s", r, le());

    open_line(win[0]);
    empty_line();
    set_line(CF_TEXT, mem_a("ansi"), "\"ansi\"");
    set_line(CF_UNICODETEXT, mem_w(L"wide"), "L\"wide\"");
    m = GlobalAlloc(GMEM_MOVEABLE, 4);
    set_line(registered, m, "4 bytes");
    count_line("open, three put");
    enum_line("open, three put");
    close_line();
    open_line(win[0]);
    count_line("the next open");
    enum_line("the next open");
    get_a(CF_TEXT);
    get_w(CF_UNICODETEXT);
    get_a(CF_OEMTEXT);
    close_line();

    finish();
}

/* --- owner --------------------------------------------------------- */

static void sec_owner(void)
{
    BOOL r;

    start(2);

    open_line(win[0]);
    empty_line();
    set_line(CF_UNICODETEXT, mem_w(L"first's"), "L\"first's\"");
    close_line();
    line("GetClipboardOwner: %s", which(GetClipboardOwner()));

    reset_log();
    open_line(win[1]);
    empty_line();
    print_log();
    line("GetClipboardOwner: %s", which(GetClipboardOwner()));
    available(CF_UNICODETEXT);
    set_line(CF_UNICODETEXT, mem_w(L"second's"), "L\"second's\"");
    close_line();

    reset_log();
    open_line(win[1]);
    empty_line();
    print_log();
    set_line(CF_UNICODETEXT, mem_w(L"second's again"), "L\"second's again\"");
    close_line();

    reset_log();
    arm();
    r = DestroyWindow(win[1]);
    line("DestroyWindow(second), the owner: ret=%d err=%s", r, le());
    print_log();
    line("GetClipboardOwner: %s", which(GetClipboardOwner()));
    win[1] = NULL;
    available(CF_UNICODETEXT);
    open_line(win[0]);
    get_w(CF_UNICODETEXT);
    close_line();

    finish();
}

/* --- delayed ------------------------------------------------------- */

static void sec_delayed(void)
{
    HANDLE r;
    BOOL b;

    start(1);
    render_text = 1;

    open_line(win[0]);
    empty_line();
    arm();
    r = SetClipboardData(CF_UNICODETEXT, NULL);
    line("SetClipboardData(CF_UNICODETEXT, NULL): non-NULL %s err=%s", yesno(r != NULL), le());
    close_line();
    available(CF_UNICODETEXT);
    available(CF_TEXT);
    available(CF_OEMTEXT);

    reset_log();
    open_line(win[0]);
    get_w(CF_UNICODETEXT);
    print_log();
    reset_log();
    get_a(CF_TEXT);
    print_log();
    close_line();

    open_line(win[0]);
    empty_line();
    arm();
    r = SetClipboardData(CF_UNICODETEXT, NULL);
    line("SetClipboardData(CF_UNICODETEXT, NULL): non-NULL %s err=%s", yesno(r != NULL), le());
    reset_log();
    get_a(CF_TEXT);
    print_log();
    close_line();

    open_line(win[0]);
    empty_line();
    arm();
    r = SetClipboardData(CF_UNICODETEXT, NULL);
    line("SetClipboardData(CF_UNICODETEXT, NULL): non-NULL %s err=%s", yesno(r != NULL), le());
    close_line();
    reset_log();
    arm();
    b = DestroyWindow(win[0]);
    line("DestroyWindow(first), the owner, CF_UNICODETEXT delayed: ret=%d err=%s", b, le());
    print_log();
    line("GetClipboardOwner: %s", which(GetClipboardOwner()));
    win[0] = NULL;
    available(CF_UNICODETEXT);
    open_line(NULL);
    get_w(CF_UNICODETEXT);
    close_line();

    finish();
}

static const section_t sections[] = {
    { "open", sec_open, F2KT_ALWAYS },
    { "unicode", sec_unicode, F2KT_ALWAYS },
    { "text", sec_text, F2KT_ALWAYS },
    { "formats", sec_formats, F2KT_ALWAYS },
    { "owner", sec_owner, F2KT_ALWAYS },
    { "delayed", sec_delayed, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("clipbrd", sections, argc, argv);
}
