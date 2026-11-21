/*
 * editctl - user32's built-in Edit control, single-line and ES_MULTILINE,
 * as a program drives it by messages: WM_SETTEXT, WM_GETTEXT and
 * WM_GETTEXTLENGTH; EM_SETSEL, EM_GETSEL and EM_REPLACESEL;
 * EM_LIMITTEXT and EM_GETLIMITTEXT; EM_GETLINECOUNT, EM_LINEINDEX,
 * EM_LINELENGTH, EM_LINEFROMCHAR and EM_GETLINE; EM_SETREADONLY;
 * EM_CANUNDO, EM_UNDO and EM_EMPTYUNDOBUFFER; EM_GETMODIFY and
 * EM_SETMODIFY; ES_UPPERCASE, ES_LOWERCASE and ES_NUMBER fed WM_CHAR;
 * and the notifications the parent receives, in order.
 *
 * The edits are children of a visible top-level window of the section's
 * own class (WS_POPUP | WS_BORDER, 322x322 at screen (40,40)), whose
 * procedure records the WM_COMMAND notifications it receives: the
 * control id, the notification code, and whether lParam is that
 * control. The records print after each call, never from inside the
 * procedure. Each section shows the parent, asks for the foreground
 * (SetForegroundWindow) and prints whether it is then the foreground
 * window, as the controls fixture does. Typing is WM_CHAR posted to the
 * edit (PostMessageW, one per character, then the queue dispatched),
 * the edit given the focus first: no key is pressed.
 *
 * The fonts F2K draws with are stand-ins for Windows', so nothing here
 * depends on a glyph's width: no position prints (EM_POSFROMCHAR is
 * left out; the caret's moves print as relations), the texts are short,
 * the single-line edits are ES_AUTOHSCROLL (without it, an edit refuses
 * what does not fit its width) and the multiline ones ES_AUTOHSCROLL |
 * ES_AUTOVSCROLL (no word wrap, nothing refused), and EN_HSCROLL and
 * EN_VSCROLL, which follow the text's width, are not recorded.
 *
 * The edits: "single", id 101, ES_LEFT | ES_AUTOHSCROLL, 280x24 at
 * (10,10); "multi", id 102, ES_MULTILINE | ES_AUTOHSCROLL |
 * ES_AUTOVSCROLL, 280x150 at (10,40); case's three more single-line
 * ones, ids 103-105, and one multiline, 106. All have WS_BORDER.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=. A text prints
 * with CR, LF and tab as \r, \n and \t. A buffer a call fills holds
 * "########" before the call, so what it left there shows. Each
 * section creates its windows and destroys them at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   single, multi and an "EDIT" made with CreateWindowExA,
 *            each with a text: its class, style and id, WM_GETDLGCODE,
 *            the text, EM_GETLIMITTEXT, EM_GETLINECOUNT, EM_GETSEL,
 *            EM_GETMODIFY, EM_CANUNDO, the notifications on creation
 *   text     WM_SETTEXT and WM_GETTEXT on both: the return, the text,
 *            WM_GETTEXTLENGTH, short buffers and none, SendMessageA's
 *            forms, an empty and a NULL text, CR LF and a bare LF
 *   select   EM_SETSEL (in order, inverted, -1, past the end) and
 *            EM_GETSEL (its return and its outputs); the caret's moves
 *            as relations; EM_REPLACESEL replacing, inserting and
 *            deleting, through SendMessageA too, CR LF in each edit
 *   limit    EM_GETLIMITTEXT's defaults; EM_LIMITTEXT, then typing,
 *            EM_REPLACESEL and WM_SETTEXT beyond the limit; a limit
 *            below the text; EM_LIMITTEXT(0); multi's line breaks
 *            against its limit
 *   lines    EM_GETLINECOUNT, EM_LINEINDEX, EM_LINELENGTH (-1 with a
 *            selection), EM_LINEFROMCHAR and EM_GETLINE (short buffers,
 *            SendMessageA) over four lines, an empty one included; an
 *            empty edit, a text ending in CR LF; the single-line edit
 *   readonly EM_SETREADONLY on and off: the style, typing,
 *            EM_REPLACESEL and WM_SETTEXT meanwhile; an edit created
 *            ES_READONLY
 *   undo     EM_CANUNDO, EM_UNDO (twice: undone, then redone) and
 *            EM_EMPTYUNDOBUFFER after EM_REPLACESEL with and without
 *            its undo flag, typing and WM_SETTEXT; WM_UNDO
 *   modify   EM_GETMODIFY after creation, WM_SETTEXT, typing,
 *            EM_REPLACESEL and EM_UNDO; EM_SETMODIFY
 *   case     ES_UPPERCASE, ES_LOWERCASE and ES_NUMBER edits, and a
 *            multiline ES_UPPERCASE one: typed text, WM_SETTEXT (W and
 *            A), EM_REPLACESEL; ES_UPPERCASE set with SetWindowLongW
 *            after creation
 *   notify   the notifications, in order: the focus coming and going,
 *            typing, a backspace, WM_SETTEXT on each edit, focused and
 *            not, EM_REPLACESEL, EM_SETSEL, WM_CLEAR with and without
 *            a selection, EM_UNDO, EN_MAXTEXT at the limit
 *   wantret  a dialog made from a template in memory
 *            (CreateDialogIndirectParamW, the system font) with a
 *            default OK button and four edits: multiline with and
 *            without ES_WANTRETURN, single-line with and without it.
 *            For each: WM_GETDLGCODE for Enter's WM_KEYDOWN, then Enter
 *            posted to it and pumped through IsDialogMessageW: whether
 *            the dialog got IDOK, the edit's text, the focus; and
 *            WM_CHAR '\r' sent straight to the multiline one without it
 *   autovscroll  multiline edits two lines high (the System font's
 *            tmHeight), without and with ES_AUTOVSCROLL: four lines
 *            typed, the text, the notifications (EN_MAXTEXT),
 *            EM_GETLINECOUNT and EM_GETFIRSTVISIBLELINE; EM_REPLACESEL
 *            and WM_SETTEXT past the visible lines
 *   margins  EM_GETMARGINS as created, after EM_SETMARGINS with each
 *            EC_ flag and none; EC_USEFONTINFO as relations; the
 *            caret's move when the left margin grows by 10
 *   linescroll  a two-line-high multiline edit holding six lines:
 *            EM_LINESCROLL's answers (down, up, past either end,
 *            sideways) and EM_GETFIRSTVISIBLELINE after each, EM_SCROLL
 *            with SB_LINEDOWN, SB_PAGEDOWN, SB_LINEUP and SB_PAGEUP; both
 *            on the single-line edit
 *   password EM_SETPASSWORDCHAR and EM_GETPASSWORDCHAR through
 *            SendMessageA and SendMessageW: cp1252's bullet 0x95 set by
 *            the A form and U+2022 by the W form, each read back by
 *            both; '*', 0, the ES_PASSWORD style after each, the text;
 *            an edit created ES_PASSWORD; a multiline edit
 *   gethandle  EM_GETHANDLE of the multiline edit, the single-line one
 *            and a multiline edit made by CreateWindowExA (through
 *            SendMessageA): non-NULL, the same twice, and whether the
 *            block LocalLock finds holds the text as UTF-16 or as bytes
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat editctl):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% editctl.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate them. */
#ifndef ES_WANTRETURN
#define ES_WANTRETURN 0x1000L
#endif
#ifndef EM_SETMARGINS
#define EM_SETMARGINS 0x00D3
#endif
#ifndef EM_GETMARGINS
#define EM_GETMARGINS 0x00D4
#endif
#ifndef EC_LEFTMARGIN
#define EC_LEFTMARGIN 0x0001
#endif
#ifndef EC_RIGHTMARGIN
#define EC_RIGHTMARGIN 0x0002
#endif
#ifndef EC_USEFONTINFO
#define EC_USEFONTINFO 0xFFFF
#endif

#define PARENT_CLASS L"F2KEditParent"

#define ID_SINGLE 101
#define ID_MULTI 102

#define SINGLE_STYLE (ES_LEFT | ES_AUTOHSCROLL)
#define MULTI_STYLE (ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL)

/* The buffer contents before a call fills it. */
#define UNFILLED_W L"########"
#define UNFILLED_A "########"

static HWND parent, single, multi;

/* --- What the parent records ------------------------------------------- */

#define MAX_COMMANDS 32

typedef struct {
    int id;
    int code;
    int from_control;
} command_t;

static command_t commands[MAX_COMMANDS];
static int command_count;

static LRESULT CALLBACK parent_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    command_t *c;
    int code;

    if (msg == WM_COMMAND && lparam != 0) {
        code = HIWORD(wparam);
        if (code != EN_HSCROLL && code != EN_VSCROLL && command_count < MAX_COMMANDS) {
            c = &commands[command_count++];
            c->id = LOWORD(wparam);
            c->code = code;
            c->from_control = GetDlgItem(hwnd, LOWORD(wparam)) == (HWND)lparam;
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static const char *code_name(int code)
{
    static char b[16];

    switch (code) {
    case EN_SETFOCUS: return "EN_SETFOCUS";
    case EN_KILLFOCUS: return "EN_KILLFOCUS";
    case EN_CHANGE: return "EN_CHANGE";
    case EN_UPDATE: return "EN_UPDATE";
    case EN_ERRSPACE: return "EN_ERRSPACE";
    case EN_MAXTEXT: return "EN_MAXTEXT";
    }
    sprintf(b, "0x%X", (unsigned)code);
    return b;
}

/* The notifications since the last print, on one line, then forgotten. */
static void print_commands(void)
{
    char buf[900];
    int n = 0;
    int i;

    if (command_count == 0) {
        line("  notifications: none");
        return;
    }
    for (i = 0; i < command_count && n < (int)sizeof buf - 64; i++) {
        n += sprintf(buf + n, "%s%d %s%s", i == 0 ? "" : ", ", commands[i].id, code_name(commands[i].code),
                     commands[i].from_control ? "" : " (lParam not the control)");
    }
    line("  notifications: %s", buf);
    command_count = 0;
}

/* --- Helpers ----------------------------------------------------------- */

static HINSTANCE instance(void)
{
    return GetModuleHandleW(NULL);
}

/* Dispatch what is queued, a bounded number of messages. */
static void drain(void)
{
    MSG m;
    int n = 0;

    while (n++ < 500 && PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        if (m.message == WM_QUIT) {
            continue;
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

/* A text as printed: CR, LF and tab escaped. */
static const char *esc(const char *t)
{
    static char bufs[4][1100];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;

    for (; *t != '\0' && n < (int)sizeof bufs[0] - 3; t++) {
        if (*t == '\r') {
            b[n++] = '\\';
            b[n++] = 'r';
        } else if (*t == '\n') {
            b[n++] = '\\';
            b[n++] = 'n';
        } else if (*t == '\t') {
            b[n++] = '\\';
            b[n++] = 't';
        } else {
            b[n++] = *t;
        }
    }
    b[n] = '\0';
    return b;
}

static const char *wesc(const WCHAR *s)
{
    return esc(ws(s));
}

static const char *wescn(const WCHAR *s, int count)
{
    return esc(wsn(s, count));
}

/* The edit's text, as a helper (not under observation). */
static void print_text(HWND h)
{
    WCHAR buf[256];

    buf[0] = 0;
    SendMessageW(h, WM_GETTEXT, 256, (LPARAM)buf);
    line("  text \"%s\"", wesc(buf));
}

/* A message whose answer is a number, then the notifications (ask()). */
static LRESULT ask(HWND h, UINT m, WPARAM wparam, LPARAM lparam, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, m, wparam, lparam);
    line("%s: ret=%ld err=%s", what, (long)r, le());
    print_commands();
    return r;
}

static void set_text(HWND h, const WCHAR *text, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, WM_SETTEXT, 0, (LPARAM)text);
    line("WM_SETTEXT(%s): ret=%ld err=%s", what, (long)r, le());
    print_commands();
    print_text(h);
}

/* Set a text without printing (WM_SETTEXT), the notifications forgotten. */
static void put_text(HWND h, const WCHAR *text)
{
    SendMessageW(h, WM_SETTEXT, 0, (LPARAM)text);
    command_count = 0;
}

/* EM_GETSEL: its return and its two outputs. */
static void get_sel(HWND h, const char *what)
{
    DWORD start = 0xA5A5A5A5u, end = 0xA5A5A5A5u;
    LRESULT r;

    arm();
    r = SendMessageW(h, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    line("EM_GETSEL(%s): ret=0x%08lX (%u, %u) err=%s start=%ld end=%ld", what, (unsigned long)r,
         (unsigned)LOWORD(r), (unsigned)HIWORD(r), le(), (long)start, (long)end);
}

static void set_sel(HWND h, int start, int end, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, EM_SETSEL, (WPARAM)start, (LPARAM)end);
    line("EM_SETSEL(%s, %d, %d): ret=%ld err=%s", what, start, end, (long)r, le());
    print_commands();
}

static void replace_sel(HWND h, BOOL undo, const WCHAR *text, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, EM_REPLACESEL, (WPARAM)undo, (LPARAM)text);
    line("EM_REPLACESEL(%s, %s, \"%s\"): ret=%ld err=%s", what, undo ? "TRUE" : "FALSE", wesc(text), (long)r,
         le());
    print_commands();
    print_text(h);
}

/* Type: WM_CHAR posted per character, then the queue dispatched. */
static void type(HWND h, const WCHAR *s, const char *what)
{
    int i;

    for (i = 0; s[i] != 0; i++) {
        PostMessageW(h, WM_CHAR, (WPARAM)s[i], 1);
    }
    drain();
    line("typed \"%s\" into %s (WM_CHAR posted)", wesc(s), what);
    print_commands();
    print_text(h);
}

static void focus(HWND h, const char *what)
{
    SetFocus(h);
    line("SetFocus(%s): the focus %s", what, yesno(GetFocus() == h));
    print_commands();
}

/* The parent: registered and created visible, the foreground asked for. */
static void open_parent(void)
{
    WNDCLASSW wc;
    ATOM a;
    DWORD err;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = parent_proc;
    wc.hInstance = instance();
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = PARENT_CLASS;
    arm();
    a = RegisterClassW(&wc);
    err = GetLastError();
    line("RegisterClassW(F2KEditParent): atom nonzero %s err=%s", yesno(a != 0), le_of(err));
    arm();
    parent = CreateWindowExW(0, PARENT_CLASS, L"F2K edit", WS_POPUP | WS_BORDER | WS_VISIBLE, 40, 40, 322, 322,
                             NULL, NULL, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExW(F2KEditParent, visible): non-NULL %s err=%s", yesno(parent != NULL), le_of(err));
    drain();
    SetForegroundWindow(parent);
    drain();
    line("SetForegroundWindow(the parent): the foreground %s", yesno(GetForegroundWindow() == parent));
    command_count = 0;
}

static void close_parent(void)
{
    if (parent != NULL) {
        DestroyWindow(parent);
    }
    drain();
    UnregisterClassW(PARENT_CLASS, instance());
    parent = NULL;
    single = NULL;
    multi = NULL;
}

/* An edit: WS_CHILD | WS_VISIBLE | WS_BORDER and the style. */
static HWND make_edit(DWORD style, int id, int x, int y, int w, int h, const WCHAR *text, const char *what)
{
    HWND e;
    DWORD err;

    arm();
    e = CreateWindowExW(0, L"Edit", text, WS_CHILD | WS_VISIBLE | WS_BORDER | style, x, y, w, h, parent,
                        (HMENU)id, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExW(\"Edit\", %s, id %d): non-NULL %s err=%s", what, id, yesno(e != NULL), le_of(err));
    drain();
    print_commands();
    return e;
}

static void open_edits(const WCHAR *single_text, const WCHAR *multi_text)
{
    single = make_edit(SINGLE_STYLE, ID_SINGLE, 10, 10, 280, 24, single_text, "single");
    multi = make_edit(MULTI_STYLE, ID_MULTI, 10, 40, 280, 150, multi_text, "multi");
}

static void print_style(HWND h)
{
    line("  style=0x%08lX", (unsigned long)GetWindowLongW(h, GWL_STYLE));
}

/* --- create ------------------------------------------------------------ */

static void describe(HWND h)
{
    WCHAR cls[32];
    char abuf[64];

    cls[0] = 0;
    GetClassNameW(h, cls, 32);
    line("  class %s style=0x%08lX id=%ld", ws(cls), (unsigned long)GetWindowLongW(h, GWL_STYLE),
         (long)GetWindowLongW(h, GWL_ID));
    print_text(h);
    abuf[0] = 0;
    SendMessageA(h, WM_GETTEXT, 64, (LPARAM)abuf);
    line("  text through SendMessageA \"%s\"", esc(abuf));
    ask(h, WM_GETDLGCODE, 0, 0, "WM_GETDLGCODE");
    ask(h, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT");
    ask(h, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT");
    get_sel(h, "as created");
    ask(h, EM_GETMODIFY, 0, 0, "EM_GETMODIFY");
    ask(h, EM_CANUNDO, 0, 0, "EM_CANUNDO");
}

static void sec_create(void)
{
    HWND a;
    DWORD err;

    open_parent();
    single = make_edit(SINGLE_STYLE, ID_SINGLE, 10, 10, 280, 24, L"Hi", "single, ES_LEFT | ES_AUTOHSCROLL, \"Hi\"");
    describe(single);
    multi = make_edit(MULTI_STYLE, ID_MULTI, 10, 40, 280, 150, L"Hi\r\nthere",
                      "multi, ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL, \"Hi\\r\\nthere\"");
    describe(multi);
    arm();
    a = CreateWindowExA(0, "EDIT", "Hi (A)", WS_CHILD | WS_VISIBLE | WS_BORDER | SINGLE_STYLE, 10, 200, 280, 24,
                        parent, (HMENU)103, GetModuleHandleA(NULL), NULL);
    err = GetLastError();
    line("CreateWindowExA(\"EDIT\", ES_LEFT | ES_AUTOHSCROLL, id 103, \"Hi (A)\"): non-NULL %s err=%s",
         yesno(a != NULL), le_of(err));
    drain();
    print_commands();
    if (a != NULL) {
        describe(a);
    }
    a = make_edit(SINGLE_STYLE, 104, 10, 230, 280, 24, NULL, "single, no text (NULL)");
    describe(a);
    close_parent();
}

/* --- text -------------------------------------------------------------- */

static void get_text(HWND h, int size, const char *what)
{
    WCHAR buf[32];
    LRESULT r;

    lstrcpyW(buf, UNFILLED_W);
    arm();
    r = SendMessageW(h, WM_GETTEXT, (WPARAM)size, (LPARAM)buf);
    line("WM_GETTEXT(%s, %d): ret=%ld err=%s buffer \"%s\"", what, size, (long)r, le(), wesc(buf));
}

static void get_text_a(HWND h, int size, const char *what)
{
    char buf[32];
    LRESULT r;

    lstrcpyA(buf, UNFILLED_A);
    arm();
    r = SendMessageA(h, WM_GETTEXT, (WPARAM)size, (LPARAM)buf);
    line("WM_GETTEXT(%s, %d) through SendMessageA: ret=%ld err=%s buffer \"%s\"", what, size, (long)r, le(),
         esc(buf));
}

static void text_of(HWND h, const char *name)
{
    LRESULT r;
    char what[64];

    set_text(h, L"Hello", name);
    sprintf(what, "WM_GETTEXTLENGTH(%s)", name);
    ask(h, WM_GETTEXTLENGTH, 0, 0, what);
    get_text(h, 32, name);
    get_text(h, 6, name);
    get_text(h, 5, name);
    get_text(h, 3, name);
    get_text(h, 1, name);
    get_text(h, 0, name);
    get_text_a(h, 32, name);
    get_text_a(h, 3, name);
    arm();
    r = SendMessageA(h, WM_SETTEXT, 0, (LPARAM)"Hello (A)");
    line("WM_SETTEXT(%s, \"Hello (A)\") through SendMessageA: ret=%ld err=%s", name, (long)r, le());
    print_commands();
    print_text(h);
    set_text(h, L"Hello (A)", "the same text again");
    set_text(h, L"", "an empty text");
    ask(h, WM_GETTEXTLENGTH, 0, 0, "WM_GETTEXTLENGTH");
    set_text(h, L"Back", "Back");
    set_text(h, NULL, "NULL");
    ask(h, WM_GETTEXTLENGTH, 0, 0, "WM_GETTEXTLENGTH");
    set_text(h, L"one\r\ntwo", "one\\r\\ntwo");
    ask(h, WM_GETTEXTLENGTH, 0, 0, "WM_GETTEXTLENGTH");
    ask(h, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT");
    set_text(h, L"a\nb", "a\\nb (a bare LF)");
    ask(h, WM_GETTEXTLENGTH, 0, 0, "WM_GETTEXTLENGTH");
    ask(h, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT");
    set_text(h, L"tab\there", "tab\\there");
}

static void sec_text(void)
{
    open_parent();
    open_edits(L"", L"");
    line("-- single");
    text_of(single, "single");
    line("-- multi");
    text_of(multi, "multi");
    close_parent();
}

/* --- select ------------------------------------------------------------ */

static void sec_select(void)
{
    POINT p0, p1;
    LRESULT r;

    open_parent();
    open_edits(L"Hello world", L"one\r\ntwo");
    focus(single, "single");
    get_sel(single, "single, focused");
    set_sel(single, 1, 3, "single");
    get_sel(single, "single");
    arm();
    r = SendMessageW(single, EM_GETSEL, 0, 0);
    line("EM_GETSEL(single, NULL, NULL): ret=0x%08lX err=%s", (unsigned long)r, le());
    set_sel(single, 4, 1, "single");
    get_sel(single, "single");
    set_sel(single, 0, -1, "single");
    get_sel(single, "single");
    set_sel(single, -1, 0, "single");
    get_sel(single, "single");
    set_sel(single, 2, 99, "single");
    get_sel(single, "single");
    set_sel(single, 99, 99, "single");
    get_sel(single, "single");

    set_sel(single, 0, 0, "single");
    p0.x = p0.y = -7;
    GetCaretPos(&p0);
    set_sel(single, 3, 3, "single");
    p1.x = p1.y = -7;
    GetCaretPos(&p1);
    line("  the caret (GetCaretPos) right of where it was at 0 %s, on the same line %s", yesno(p1.x > p0.x),
         yesno(p1.y == p0.y));
    set_sel(single, 0, 3, "single");
    p0 = p1;
    GetCaretPos(&p1);
    line("  the caret where it was at 3 %s", yesno(p1.x == p0.x && p1.y == p0.y));

    set_sel(single, 6, 11, "single (\"world\")");
    replace_sel(single, TRUE, L"there", "single");
    get_sel(single, "single");
    set_sel(single, 5, 5, "single");
    replace_sel(single, FALSE, L",", "single");
    get_sel(single, "single");
    set_sel(single, 0, 7, "single");
    replace_sel(single, TRUE, L"", "single");
    get_sel(single, "single");
    arm();
    r = SendMessageA(single, EM_REPLACESEL, TRUE, (LPARAM)"(A)");
    line("EM_REPLACESEL(single, TRUE, \"(A)\") through SendMessageA: ret=%ld err=%s", (long)r, le());
    print_commands();
    print_text(single);
    replace_sel(single, TRUE, L"\r\nx", "single");
    get_sel(single, "single");

    focus(multi, "multi");
    get_sel(multi, "multi, focused");
    set_sel(multi, 3, 3, "multi");
    replace_sel(multi, TRUE, L"\r\nnew", "multi");
    get_sel(multi, "multi");
    ask(multi, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT(multi)");
    set_sel(multi, 0, -1, "multi");
    get_sel(multi, "multi");
    set_sel(multi, 4, 5, "multi (across the line break)");
    get_sel(multi, "multi");
    replace_sel(multi, TRUE, L"", "multi");
    ask(multi, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT(multi)");
    close_parent();
}

/* --- limit ------------------------------------------------------------- */

static void sec_limit(void)
{
    open_parent();
    open_edits(L"", L"");
    ask(single, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT(single)");
    ask(multi, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT(multi)");
    ask(single, EM_LIMITTEXT, 5, 0, "EM_LIMITTEXT(single, 5)");
    ask(single, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT(single)");
    focus(single, "single");
    type(single, L"abcdefg", "single");
    set_text(single, L"abc", "single, abc");
    set_sel(single, 3, 3, "single");
    replace_sel(single, TRUE, L"XYZW", "single");
    set_sel(single, 0, 1, "single");
    replace_sel(single, TRUE, L"123", "single (a selection of 1, 3 in its place)");
    set_text(single, L"Hello world", "single, beyond the limit");
    ask(single, WM_GETTEXTLENGTH, 0, 0, "WM_GETTEXTLENGTH(single)");
    ask(single, EM_LIMITTEXT, 3, 0, "EM_LIMITTEXT(single, 3), below the text's length");
    print_text(single);
    set_sel(single, 99, 99, "single (to the end)");
    type(single, L"z", "single");
    ask(single, EM_LIMITTEXT, 0, 0, "EM_LIMITTEXT(single, 0)");
    ask(single, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT(single)");
    type(single, L"z", "single");

    ask(multi, EM_LIMITTEXT, 8, 0, "EM_LIMITTEXT(multi, 8)");
    ask(multi, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT(multi)");
    focus(multi, "multi");
    type(multi, L"ab\rcd\refg", "multi");
    ask(multi, WM_GETTEXTLENGTH, 0, 0, "WM_GETTEXTLENGTH(multi)");
    ask(multi, EM_LIMITTEXT, 0, 0, "EM_LIMITTEXT(multi, 0)");
    ask(multi, EM_GETLIMITTEXT, 0, 0, "EM_GETLIMITTEXT(multi)");
    close_parent();
}

/* --- lines ------------------------------------------------------------- */

/* EM_GETLINE: the buffer's first unit holds its size; what the call
 * copied prints, then the unit after it (the size word itself when
 * nothing was copied), in hex: EM_GETLINE adds no terminator. */
static void get_line(HWND h, int index, int size, const char *what)
{
    WCHAR buf[40];
    LRESULT r;
    int n;

    lstrcpyW(buf, L"################################");
    buf[0] = (WCHAR)size;
    arm();
    r = SendMessageW(h, EM_GETLINE, (WPARAM)index, (LPARAM)buf);
    n = r >= 0 && r < 32 ? (int)r : 0;
    line("EM_GETLINE(%s, %d, room for %d): ret=%ld err=%s copied \"%s\" then U+%04X", what, index, size, (long)r,
         le(), wescn(buf, n), (unsigned)buf[n]);
}

static void line_queries(HWND h, const char *name, const int *chars, int nchars, int nlines)
{
    char what[64];
    int i;

    sprintf(what, "EM_GETLINECOUNT(%s)", name);
    ask(h, EM_GETLINECOUNT, 0, 0, what);
    for (i = 0; i <= nlines; i++) {
        sprintf(what, "EM_LINEINDEX(%s, %d)", name, i);
        ask(h, EM_LINEINDEX, (WPARAM)i, 0, what);
    }
    for (i = 0; i < nchars; i++) {
        sprintf(what, "EM_LINELENGTH(%s, %d)", name, chars[i]);
        ask(h, EM_LINELENGTH, (WPARAM)chars[i], 0, what);
        sprintf(what, "EM_LINEFROMCHAR(%s, %d)", name, chars[i]);
        ask(h, EM_LINEFROMCHAR, (WPARAM)chars[i], 0, what);
    }
    for (i = 0; i <= nlines; i++) {
        get_line(h, i, 30, name);
    }
}

static void sec_lines(void)
{
    /* "one\r\ntwo two\r\n\r\nfour": lines at 0, 5, 14 and 16. */
    static const int multi_chars[] = { 0, 3, 5, 9, 12, 14, 16, 19, 20, 99 };
    static const int single_chars[] = { 0, 3, 5, 9 };
    char abuf[40];
    LRESULT r;
    DWORD err;
    int n;
    unsigned after;

    open_parent();
    open_edits(L"Hello", L"one\r\ntwo two\r\n\r\nfour");
    line("-- multi, \"one\\r\\ntwo two\\r\\n\\r\\nfour\"");
    line_queries(multi, "multi", multi_chars, 10, 4);
    get_line(multi, 1, 3, "multi");
    get_line(multi, 1, 7, "multi");
    get_line(multi, 1, 0, "multi");
    lstrcpyA(abuf, "################################");
    *(WORD *)abuf = 30;
    arm();
    r = SendMessageA(multi, EM_GETLINE, 1, (LPARAM)abuf);
    err = GetLastError();
    n = r >= 0 && r < 32 ? (int)r : 0;
    after = (unsigned char)abuf[n];
    abuf[n] = '\0';
    line("EM_GETLINE(multi, 1, room for 30) through SendMessageA: ret=%ld err=%s copied \"%s\" then 0x%02X",
         (long)r, le_of(err), esc(abuf), after);

    set_sel(multi, 9, 9, "multi");
    ask(multi, EM_LINEINDEX, (WPARAM)-1, 0, "EM_LINEINDEX(multi, -1), the caret on line 1");
    ask(multi, EM_LINEFROMCHAR, (WPARAM)-1, 0, "EM_LINEFROMCHAR(multi, -1)");
    ask(multi, EM_LINELENGTH, (WPARAM)-1, 0, "EM_LINELENGTH(multi, -1), no selection");
    set_sel(multi, 7, 16, "multi (from line 1 into line 3)");
    ask(multi, EM_LINELENGTH, (WPARAM)-1, 0, "EM_LINELENGTH(multi, -1)");
    ask(multi, EM_LINEFROMCHAR, (WPARAM)-1, 0, "EM_LINEFROMCHAR(multi, -1)");
    set_sel(multi, 6, 8, "multi (inside line 1)");
    ask(multi, EM_LINELENGTH, (WPARAM)-1, 0, "EM_LINELENGTH(multi, -1)");

    line("-- multi, empty");
    put_text(multi, L"");
    line_queries(multi, "multi", multi_chars, 2, 1);
    line("-- multi, \"a\\r\\n\"");
    put_text(multi, L"a\r\n");
    line_queries(multi, "multi", multi_chars, 2, 2);

    line("-- single, \"Hello\"");
    line_queries(single, "single", single_chars, 4, 1);
    get_line(single, 3, 30, "single");
    set_sel(single, 1, 3, "single");
    ask(single, EM_LINELENGTH, (WPARAM)-1, 0, "EM_LINELENGTH(single, -1)");
    ask(single, EM_LINEINDEX, (WPARAM)-1, 0, "EM_LINEINDEX(single, -1)");
    close_parent();
}

/* --- readonly ---------------------------------------------------------- */

static void sec_readonly(void)
{
    HWND ro;

    open_parent();
    open_edits(L"Hello", L"one");
    print_style(single);
    ask(single, EM_SETREADONLY, TRUE, 0, "EM_SETREADONLY(single, TRUE)");
    print_style(single);
    ask(single, WM_GETDLGCODE, 0, 0, "WM_GETDLGCODE(single)");
    focus(single, "single");
    set_sel(single, 5, 5, "single");
    type(single, L"x", "single, read-only");
    replace_sel(single, TRUE, L"X", "single, read-only");
    set_text(single, L"Set", "single, read-only, Set");
    ask(single, EM_SETREADONLY, TRUE, 0, "EM_SETREADONLY(single, TRUE) again");
    ask(single, EM_SETREADONLY, FALSE, 0, "EM_SETREADONLY(single, FALSE)");
    print_style(single);
    set_sel(single, 99, 99, "single (to the end)");
    type(single, L"y", "single");

    ask(multi, EM_SETREADONLY, TRUE, 0, "EM_SETREADONLY(multi, TRUE)");
    print_style(multi);
    focus(multi, "multi");
    type(multi, L"z\r", "multi, read-only");
    ask(multi, EM_SETREADONLY, FALSE, 0, "EM_SETREADONLY(multi, FALSE)");
    type(multi, L"z\r", "multi");

    ro = make_edit(SINGLE_STYLE | ES_READONLY, 103, 10, 200, 280, 24, L"fixed", "ES_LEFT | ES_AUTOHSCROLL | ES_READONLY");
    print_style(ro);
    focus(ro, "the ES_READONLY edit");
    type(ro, L"q", "the ES_READONLY edit");
    ask(ro, EM_SETREADONLY, FALSE, 0, "EM_SETREADONLY(the ES_READONLY edit, FALSE)");
    print_style(ro);
    type(ro, L"q", "that edit");
    close_parent();
}

/* --- undo -------------------------------------------------------------- */

static void sec_undo(void)
{
    open_parent();
    open_edits(L"Hello", L"");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single), as created");
    set_sel(single, 5, 5, "single");
    replace_sel(single, TRUE, L" world", "single");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single)");
    ask(single, EM_UNDO, 0, 0, "EM_UNDO(single)");
    print_text(single);
    get_sel(single, "single");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single)");
    ask(single, EM_UNDO, 0, 0, "EM_UNDO(single) again");
    print_text(single);
    ask(single, EM_EMPTYUNDOBUFFER, 0, 0, "EM_EMPTYUNDOBUFFER(single)");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single)");
    ask(single, EM_UNDO, 0, 0, "EM_UNDO(single), nothing to undo");
    print_text(single);
    replace_sel(single, FALSE, L"!", "single");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single)");
    ask(single, EM_UNDO, 0, 0, "EM_UNDO(single)");
    print_text(single);
    focus(single, "single");
    set_sel(single, 99, 99, "single (to the end)");
    ask(single, EM_EMPTYUNDOBUFFER, 0, 0, "EM_EMPTYUNDOBUFFER(single)");
    type(single, L"ab", "single");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single)");
    ask(single, WM_UNDO, 0, 0, "WM_UNDO(single)");
    print_text(single);
    set_text(single, L"New", "single, New");
    ask(single, EM_CANUNDO, 0, 0, "EM_CANUNDO(single)");
    ask(single, EM_UNDO, 0, 0, "EM_UNDO(single)");
    print_text(single);

    focus(multi, "multi");
    type(multi, L"ab\rc", "multi");
    ask(multi, EM_CANUNDO, 0, 0, "EM_CANUNDO(multi)");
    ask(multi, EM_UNDO, 0, 0, "EM_UNDO(multi)");
    print_text(multi);
    ask(multi, EM_UNDO, 0, 0, "EM_UNDO(multi) again");
    print_text(multi);
    close_parent();
}

/* --- modify ------------------------------------------------------------ */

static void sec_modify(void)
{
    open_parent();
    open_edits(L"Hello", L"one");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single), as created");
    set_text(single, L"Set", "single, Set");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    focus(single, "single");
    set_sel(single, 99, 99, "single (to the end)");
    type(single, L"a", "single");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    ask(single, EM_SETMODIFY, FALSE, 0, "EM_SETMODIFY(single, FALSE)");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    replace_sel(single, TRUE, L"b", "single");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    ask(single, EM_SETMODIFY, FALSE, 0, "EM_SETMODIFY(single, FALSE)");
    ask(single, EM_UNDO, 0, 0, "EM_UNDO(single)");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    ask(single, EM_SETMODIFY, TRUE, 0, "EM_SETMODIFY(single, TRUE)");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    set_text(single, L"Reset", "single, Reset");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");
    ask(single, EM_SETMODIFY, 5, 0, "EM_SETMODIFY(single, 5)");
    ask(single, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(single)");

    ask(multi, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(multi), as created");
    focus(multi, "multi");
    type(multi, L"\r", "multi");
    ask(multi, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(multi)");
    set_text(multi, L"two", "multi, two");
    ask(multi, EM_GETMODIFY, 0, 0, "EM_GETMODIFY(multi)");
    close_parent();
}

/* --- case -------------------------------------------------------------- */

static void case_of(HWND h, const char *name)
{
    LRESULT r;

    line("-- %s", name);
    print_style(h);
    focus(h, name);
    type(h, L"aB3c-D", name);
    set_text(h, L"aB3c", name);
    set_sel(h, 99, 99, name);
    replace_sel(h, TRUE, L"xY9", name);
    arm();
    r = SendMessageA(h, WM_SETTEXT, 0, (LPARAM)"aB3");
    line("WM_SETTEXT(%s, \"aB3\") through SendMessageA: ret=%ld err=%s", name, (long)r, le());
    print_commands();
    print_text(h);
}

static void sec_case(void)
{
    HWND up, low, num, mup;
    LONG style;

    open_parent();
    single = make_edit(SINGLE_STYLE, ID_SINGLE, 10, 10, 280, 24, L"", "single");
    up = make_edit(SINGLE_STYLE | ES_UPPERCASE, 103, 10, 40, 280, 24, L"", "ES_LEFT | ES_AUTOHSCROLL | ES_UPPERCASE");
    low = make_edit(SINGLE_STYLE | ES_LOWERCASE, 104, 10, 70, 280, 24, L"", "ES_LEFT | ES_AUTOHSCROLL | ES_LOWERCASE");
    num = make_edit(SINGLE_STYLE | ES_NUMBER, 105, 10, 100, 280, 24, L"", "ES_LEFT | ES_AUTOHSCROLL | ES_NUMBER");
    mup = make_edit(MULTI_STYLE | ES_UPPERCASE, 106, 10, 130, 280, 100, L"",
                    "ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_UPPERCASE");
    case_of(up, "the ES_UPPERCASE edit");
    case_of(low, "the ES_LOWERCASE edit");
    case_of(num, "the ES_NUMBER edit");
    line("-- the multiline ES_UPPERCASE edit");
    print_style(mup);
    focus(mup, "the multiline ES_UPPERCASE edit");
    type(mup, L"ab\rcD", "the multiline ES_UPPERCASE edit");

    line("-- single, ES_UPPERCASE added by SetWindowLongW");
    style = GetWindowLongW(single, GWL_STYLE);
    arm();
    SetWindowLongW(single, GWL_STYLE, style | ES_UPPERCASE);
    line("SetWindowLongW(single, GWL_STYLE, | ES_UPPERCASE): err=%s", le());
    print_style(single);
    focus(single, "single");
    type(single, L"ab", "single");
    set_text(single, L"cd", "single, cd");
    close_parent();
}

/* --- notify ------------------------------------------------------------ */

static void sec_notify(void)
{
    open_parent();
    open_edits(L"", L"");
    focus(single, "single");
    type(single, L"a", "single");
    type(single, L"bc", "single");
    type(single, L"\b", "single (a backspace)");
    set_sel(single, 0, 1, "single");
    type(single, L"\b", "single (a backspace over a selection)");
    set_text(single, L"Set", "single, focused, Set");
    set_text(multi, L"Set", "multi, not focused, Set");
    focus(multi, "multi");
    set_text(multi, L"Again", "multi, focused, Again");
    set_text(single, L"Again", "single, not focused, Again");
    type(multi, L"x\r", "multi");
    set_sel(multi, 0, 2, "multi");
    ask(multi, WM_CLEAR, 0, 0, "WM_CLEAR(multi), a selection");
    print_text(multi);
    set_sel(multi, 0, 0, "multi");
    ask(multi, WM_CLEAR, 0, 0, "WM_CLEAR(multi), no selection");
    replace_sel(multi, TRUE, L"rep", "multi");
    replace_sel(single, TRUE, L"rep", "single, not focused");
    ask(multi, EM_UNDO, 0, 0, "EM_UNDO(multi)");
    print_text(multi);
    ask(single, EM_LIMITTEXT, 2, 0, "EM_LIMITTEXT(single, 2)");
    focus(single, "single");
    set_text(single, L"", "single, empty");
    type(single, L"abc", "single");
    replace_sel(single, TRUE, L"z", "single, at the limit");
    ask(single, EM_SETREADONLY, TRUE, 0, "EM_SETREADONLY(single, TRUE)");
    ask(single, EM_SETMODIFY, TRUE, 0, "EM_SETMODIFY(single, TRUE)");
    focus(parent, "the parent");
    close_parent();
}

/* --- wantret ----------------------------------------------------------- */

/* A dialog template built in DWORD-aligned memory: the header, then
 * each item DWORD-aligned, its class by atom (0x0080 Button, 0x0081
 * Edit). No menu, the default class, no font (the system font). */
static DWORD template_dwords[256];
static WORD *template_at;

static void tw(WORD v)
{
    *template_at++ = v;
}

static void tw_string(const WCHAR *s)
{
    do {
        tw(*s);
    } while (*s++ != 0);
}

static void tw_align(void)
{
    if (((BYTE *)template_at - (BYTE *)template_dwords) & 3) {
        tw(0);
    }
}

static void template_begin(DWORD style, WORD count, short cx, short cy, const WCHAR *caption)
{
    ZeroMemory(template_dwords, sizeof template_dwords);
    template_at = (WORD *)template_dwords;
    tw(LOWORD(style));
    tw(HIWORD(style));
    tw(0);
    tw(0);
    tw(count);
    tw(10);
    tw(10);
    tw((WORD)cx);
    tw((WORD)cy);
    tw(0);
    tw(0);
    tw_string(caption);
}

static void template_item(DWORD style, short x, short y, short cx, short cy, WORD id, WORD atom,
                          const WCHAR *text)
{
    tw_align();
    style |= WS_CHILD | WS_VISIBLE;
    tw(LOWORD(style));
    tw(HIWORD(style));
    tw(0);
    tw(0);
    tw((WORD)x);
    tw((WORD)y);
    tw((WORD)cx);
    tw((WORD)cy);
    tw(id);
    tw(0xFFFF);
    tw(atom);
    tw_string(text);
    tw(0);
}

#define MAX_DLG_COMMANDS 8

static int dlg_command_ids[MAX_DLG_COMMANDS];
static int dlg_command_from[MAX_DLG_COMMANDS];
static int dlg_command_count;

/* The dialog's procedure: records IDOK and IDCANCEL, handles nothing. */
static BOOL CALLBACK wantret_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_INITDIALOG) {
        return TRUE;
    }
    if (msg == WM_COMMAND && (LOWORD(wparam) == IDOK || LOWORD(wparam) == IDCANCEL)) {
        if (dlg_command_count < MAX_DLG_COMMANDS) {
            dlg_command_ids[dlg_command_count] = LOWORD(wparam);
            dlg_command_from[dlg_command_count] = lparam != 0 && GetDlgItem(hwnd, LOWORD(wparam)) == (HWND)lparam;
            dlg_command_count++;
        }
        return TRUE;
    }
    return FALSE;
}

/* Take what is queued through IsDialogMessageW, dispatching what it declines. */
static void dialog_pump(HWND dlg)
{
    MSG m;
    int n;

    for (n = 0; n < 200 && PeekMessageW(&m, NULL, 0, 0, PM_REMOVE); n++) {
        if (m.message == WM_QUIT) {
            continue;
        }
        if (!IsDialogMessageW(dlg, &m)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}

static void print_dlg_commands(void)
{
    int i;

    if (dlg_command_count == 0) {
        line("  the dialog received no IDOK or IDCANCEL");
    }
    for (i = 0; i < dlg_command_count; i++) {
        line("  the dialog received %s, lParam the button %s", dlg_command_ids[i] == IDOK ? "IDOK" : "IDCANCEL",
             yesno(dlg_command_from[i]));
    }
    dlg_command_count = 0;
}

static const char *dlg_focus(HWND dlg)
{
    static char buf[24];
    HWND f = GetFocus();

    if (f == NULL) {
        return "none";
    }
    if (f == dlg) {
        return "the dialog";
    }
    sprintf(buf, "id %d", GetDlgCtrlID(f));
    return buf;
}

/* Enter in one of the dialog's edits: its dialog code, then Enter
 * posted to it and pumped. */
static void enter_in(HWND dlg, int id, const char *name)
{
    HWND e = GetDlgItem(dlg, id);
    MSG m;
    LRESULT code;
    LPARAM down = 1 | (0x1C << 16);

    line("-- %d, %s", id, name);
    if (e == NULL) {
        line("  no such control");
        return;
    }
    SetFocus(e);
    SendMessageW(e, WM_SETTEXT, 0, (LPARAM)L"ab");
    SendMessageW(e, EM_SETSEL, 2, 2);
    dialog_pump(dlg);
    dlg_command_count = 0;
    ZeroMemory(&m, sizeof m);
    m.hwnd = e;
    m.message = WM_KEYDOWN;
    m.wParam = VK_RETURN;
    m.lParam = down;
    arm();
    code = SendMessageW(e, WM_GETDLGCODE, VK_RETURN, (LPARAM)&m);
    line("WM_GETDLGCODE(%d, Enter's WM_KEYDOWN): ret=0x%04lX err=%s", id, (unsigned long)code, le());
    PostMessageW(e, WM_KEYDOWN, VK_RETURN, down);
    PostMessageW(e, WM_KEYUP, VK_RETURN, down | 0xC0000000);
    dialog_pump(dlg);
    line("Enter posted to %d, pumped through IsDialogMessageW: the focus %s", id, dlg_focus(dlg));
    print_dlg_commands();
    print_text(e);
}

static void sec_wantret(void)
{
    HWND dlg;
    HWND e;
    DWORD err;
    LRESULT r;

    drain();
    template_begin(WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME, 5, 200, 120, L"F2K wantret");
    template_item(BS_DEFPUSHBUTTON | WS_TABSTOP, 150, 5, 40, 14, IDOK, 0x0080, L"OK");
    template_item(ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL | WS_BORDER | WS_TABSTOP, 5, 5, 130, 24, 101,
                  0x0081, L"");
    template_item(ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_WANTRETURN | WS_BORDER | WS_TABSTOP, 5, 35,
                  130, 24, 102, 0x0081, L"");
    template_item(ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 5, 65, 130, 12, 103, 0x0081, L"");
    template_item(ES_AUTOHSCROLL | ES_WANTRETURN | WS_BORDER | WS_TABSTOP, 5, 85, 130, 12, 104, 0x0081, L"");
    dlg_command_count = 0;
    arm();
    dlg = CreateDialogIndirectParamW(instance(), (const DLGTEMPLATE *)template_dwords, NULL, (DLGPROC)wantret_proc,
                                     0);
    err = GetLastError();
    line("CreateDialogIndirectParamW(OK, 101 multiline, 102 multiline | ES_WANTRETURN, 103 single, 104 single | "
         "ES_WANTRETURN): non-NULL %s err=%s", yesno(dlg != NULL), le_of(err));
    if (dlg == NULL) {
        return;
    }
    ShowWindow(dlg, SW_SHOWNORMAL);
    SetForegroundWindow(dlg);
    dialog_pump(dlg);
    line("the dialog shown: the foreground %s", yesno(GetForegroundWindow() == dlg));
    line("102's style=0x%08lX, 104's style=0x%08lX", (unsigned long)GetWindowLongW(GetDlgItem(dlg, 102), GWL_STYLE),
         (unsigned long)GetWindowLongW(GetDlgItem(dlg, 104), GWL_STYLE));
    enter_in(dlg, 101, "ES_MULTILINE");
    enter_in(dlg, 102, "ES_MULTILINE | ES_WANTRETURN");
    enter_in(dlg, 103, "single-line");
    enter_in(dlg, 104, "single-line, ES_WANTRETURN");
    line("-- 101, WM_CHAR '\\r' sent to it");
    e = GetDlgItem(dlg, 101);
    SendMessageW(e, WM_SETTEXT, 0, (LPARAM)L"ab");
    SendMessageW(e, EM_SETSEL, 2, 2);
    arm();
    r = SendMessageW(e, WM_CHAR, '\r', 1 | (0x1C << 16));
    line("SendMessageW(101, WM_CHAR, '\\r'): ret=%ld err=%s", (long)r, le());
    print_dlg_commands();
    print_text(e);
    DestroyWindow(dlg);
    drain();
}

/* --- autovscroll, linescroll ---------------------------------------- */

/* The System font's line height, which edits given no font use. */
static int line_height(void)
{
    HDC dc = GetDC(NULL);
    HGDIOBJ old = SelectObject(dc, GetStockObject(SYSTEM_FONT));
    TEXTMETRICA tm;

    ZeroMemory(&tm, sizeof tm);
    GetTextMetricsA(dc, &tm);
    SelectObject(dc, old);
    ReleaseDC(NULL, dc);
    return tm.tmHeight;
}

/* A multiline edit two and a half lines high (its border included):
 * two whole lines show. */
static HWND short_edit(DWORD style, int id, int y, const WCHAR *text, const char *what)
{
    int h = line_height();

    return make_edit(style, id, 10, y, 280, 2 * h + h / 2 + 2, text, what);
}

static void sec_autovscroll(void)
{
    HWND no;
    HWND yes_;

    open_parent();
    no = short_edit(ES_MULTILINE | ES_AUTOHSCROLL, 103, 10, L"", "ES_MULTILINE | ES_AUTOHSCROLL, two lines high");
    yes_ = short_edit(MULTI_STYLE, 104, 80, L"", "ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL, two lines high");
    line("-- no ES_AUTOVSCROLL");
    focus(no, "103");
    type(no, L"a\rb\rc\rd", "103");
    ask(no, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT(103)");
    ask(no, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    set_sel(no, 99, 99, "103 (to the end)");
    replace_sel(no, TRUE, L"\r\nx", "103");
    set_text(no, L"1\r\n2\r\n3\r\n4", "103, four lines");
    ask(no, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT(103)");
    line("-- ES_AUTOVSCROLL");
    focus(yes_, "104");
    type(yes_, L"a\rb\rc\rd", "104");
    ask(yes_, EM_GETLINECOUNT, 0, 0, "EM_GETLINECOUNT(104)");
    ask(yes_, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(104)");
    close_parent();
}

static void sec_linescroll(void)
{
    HWND e;

    open_parent();
    single = make_edit(SINGLE_STYLE, ID_SINGLE, 10, 10, 280, 24, L"Hello", "single");
    e = short_edit(MULTI_STYLE, 103, 40, L"1\r\n2\r\n3\r\n4\r\n5\r\n6", "multi, two lines high, six lines");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_LINESCROLL, 0, 2, "EM_LINESCROLL(103, 0, 2)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_LINESCROLL, 0, -1, "EM_LINESCROLL(103, 0, -1)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_LINESCROLL, 0, -10, "EM_LINESCROLL(103, 0, -10)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_LINESCROLL, 0, 100, "EM_LINESCROLL(103, 0, 100)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_LINESCROLL, 3, 0, "EM_LINESCROLL(103, 3, 0), sideways");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_LINESCROLL, 0, -100, "EM_LINESCROLL(103, 0, -100)");
    ask(e, EM_SCROLL, SB_LINEDOWN, 0, "EM_SCROLL(103, SB_LINEDOWN)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_SCROLL, SB_PAGEDOWN, 0, "EM_SCROLL(103, SB_PAGEDOWN)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_SCROLL, SB_LINEUP, 0, "EM_SCROLL(103, SB_LINEUP)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_SCROLL, SB_PAGEUP, 0, "EM_SCROLL(103, SB_PAGEUP)");
    ask(e, EM_GETFIRSTVISIBLELINE, 0, 0, "EM_GETFIRSTVISIBLELINE(103)");
    ask(e, EM_SCROLL, 99, 0, "EM_SCROLL(103, 99)");
    ask(single, EM_LINESCROLL, 0, 1, "EM_LINESCROLL(single, 0, 1)");
    ask(single, EM_SCROLL, SB_LINEDOWN, 0, "EM_SCROLL(single, SB_LINEDOWN)");
    close_parent();
}

/* --- margins ----------------------------------------------------------- */

static LRESULT margins(HWND h, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, EM_GETMARGINS, 0, 0);
    line("EM_GETMARGINS(%s): ret=0x%08lX err=%s left=%u right=%u", what, (unsigned long)r, le(),
         (unsigned)LOWORD(r), (unsigned)HIWORD(r));
    return r;
}

static void margins_of(HWND h, const char *name)
{
    char what[96];
    LRESULT r;

    line("-- %s", name);
    margins(h, "as created");
    sprintf(what, "EM_SETMARGINS(%s, EC_LEFTMARGIN | EC_RIGHTMARGIN, 3, 5)", name);
    ask(h, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(3, 5), what);
    margins(h, name);
    sprintf(what, "EM_SETMARGINS(%s, EC_LEFTMARGIN, 7, 9)", name);
    ask(h, EM_SETMARGINS, EC_LEFTMARGIN, MAKELONG(7, 9), what);
    margins(h, name);
    sprintf(what, "EM_SETMARGINS(%s, EC_RIGHTMARGIN, 11, 13)", name);
    ask(h, EM_SETMARGINS, EC_RIGHTMARGIN, MAKELONG(11, 13), what);
    margins(h, name);
    sprintf(what, "EM_SETMARGINS(%s, 0, 1, 1)", name);
    ask(h, EM_SETMARGINS, 0, MAKELONG(1, 1), what);
    margins(h, name);
    sprintf(what, "EM_SETMARGINS(%s, EC_LEFTMARGIN | EC_RIGHTMARGIN, EC_USEFONTINFO, EC_USEFONTINFO)", name);
    ask(h, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(EC_USEFONTINFO, EC_USEFONTINFO), what);
    arm();
    r = SendMessageW(h, EM_GETMARGINS, 0, 0);
    line("EM_GETMARGINS(%s): err=%s left the same as right %s, left 0xFFFF %s, left below 16 %s", name, le(),
         yesno(LOWORD(r) == HIWORD(r)), yesno(LOWORD(r) == 0xFFFF), yesno(LOWORD(r) < 16));
}

static void sec_margins(void)
{
    POINT p0, p1;
    LRESULT r;
    int left;

    open_parent();
    open_edits(L"Hello", L"Hello");
    margins_of(single, "single");
    margins_of(multi, "multi");
    line("-- the caret in single as its left margin grows by 10");
    ask(single, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(2, 2), "EM_SETMARGINS(single, both, 2, 2)");
    focus(single, "single");
    set_sel(single, 0, 0, "single");
    p0.x = p0.y = -7;
    GetCaretPos(&p0);
    r = margins(single, "single");
    left = LOWORD(r);
    ask(single, EM_SETMARGINS, EC_LEFTMARGIN, MAKELONG(left + 10, 0), "EM_SETMARGINS(single, EC_LEFTMARGIN, + 10)");
    set_sel(single, 1, 1, "single");
    set_sel(single, 0, 0, "single");
    p1.x = p1.y = -7;
    GetCaretPos(&p1);
    line("  the caret (GetCaretPos) 10 pixels right of where it was %s, on the same row %s", yesno(p1.x - p0.x == 10),
         yesno(p1.y == p0.y));
    close_parent();
}

/* --- password ---------------------------------------------------------- */

static void get_password(HWND h, const char *what)
{
    LRESULT a;
    LRESULT w;
    DWORD ea;
    DWORD ew;

    arm();
    a = SendMessageA(h, EM_GETPASSWORDCHAR, 0, 0);
    ea = GetLastError();
    arm();
    w = SendMessageW(h, EM_GETPASSWORDCHAR, 0, 0);
    ew = GetLastError();
    line("EM_GETPASSWORDCHAR(%s): SendMessageA ret=0x%lX err=%s, SendMessageW ret=0x%lX err=%s; ES_PASSWORD %s",
         what, (unsigned long)a, le_of(ea), (unsigned long)w, le_of(ew),
         yesno((GetWindowLongW(h, GWL_STYLE) & ES_PASSWORD) != 0));
}

static void set_password(HWND h, int ansi, WPARAM c, const char *what)
{
    LRESULT r;

    arm();
    r = ansi ? SendMessageA(h, EM_SETPASSWORDCHAR, c, 0) : SendMessageW(h, EM_SETPASSWORDCHAR, c, 0);
    line("EM_SETPASSWORDCHAR(%s, 0x%lX) through SendMessage%s: ret=%ld err=%s", what, (unsigned long)c,
         ansi ? "A" : "W", (long)r, le());
    print_commands();
}

static void sec_password(void)
{
    HWND pw;

    open_parent();
    open_edits(L"secret", L"secret");
    pw = make_edit(SINGLE_STYLE | ES_PASSWORD, 103, 10, 200, 280, 24, L"secret", "ES_LEFT | ES_AUTOHSCROLL | ES_PASSWORD");
    get_password(pw, "the ES_PASSWORD edit, as created");
    print_text(pw);
    get_password(single, "single, as created");
    set_password(single, 1, 0x95, "single");
    get_password(single, "single");
    set_password(single, 0, 0x2022, "single");
    get_password(single, "single");
    set_password(single, 0, '*', "single");
    get_password(single, "single");
    print_text(single);
    set_password(single, 1, 0, "single");
    get_password(single, "single");
    set_password(multi, 1, '*', "multi");
    get_password(multi, "multi");
    close_parent();
}

/* --- gethandle --------------------------------------------------------- */

static void handle_of(HWND h, int ansi, const WCHAR *wide, const char *bytes, const char *what)
{
    HLOCAL m;
    HLOCAL again;
    DWORD err;
    const BYTE *p;
    int n = lstrlenA(bytes);

    arm();
    m = (HLOCAL)(ansi ? SendMessageA(h, EM_GETHANDLE, 0, 0) : SendMessageW(h, EM_GETHANDLE, 0, 0));
    err = GetLastError();
    again = (HLOCAL)(ansi ? SendMessageA(h, EM_GETHANDLE, 0, 0) : SendMessageW(h, EM_GETHANDLE, 0, 0));
    line("EM_GETHANDLE(%s) through SendMessage%s: non-NULL %s err=%s, the same again %s", what, ansi ? "A" : "W",
         yesno(m != NULL), le_of(err), yesno(again == m));
    if (m == NULL) {
        return;
    }
    p = (const BYTE *)LocalLock(m);
    if (p == NULL) {
        line("  LocalLock: NULL");
        return;
    }
    line("  the block holds the text as UTF-16 %s, as bytes %s", yesno(memcmp(p, wide, (size_t)(n + 1) * 2) == 0),
         yesno(memcmp(p, bytes, (size_t)n + 1) == 0));
    LocalUnlock(m);
}

static void sec_gethandle(void)
{
    HWND a;
    DWORD err;

    open_parent();
    open_edits(L"abc", L"abc\r\nde");
    handle_of(multi, 0, L"abc\r\nde", "abc\r\nde", "multi");
    handle_of(single, 0, L"abc", "abc", "single");
    arm();
    a = CreateWindowExA(0, "EDIT", "abc\r\nde", WS_CHILD | WS_VISIBLE | WS_BORDER | MULTI_STYLE, 10, 200, 280, 60,
                        parent, (HMENU)103, GetModuleHandleA(NULL), NULL);
    err = GetLastError();
    line("CreateWindowExA(\"EDIT\", multiline, id 103, \"abc\\r\\nde\"): non-NULL %s err=%s", yesno(a != NULL),
         le_of(err));
    drain();
    command_count = 0;
    if (a != NULL) {
        handle_of(a, 1, L"abc\r\nde", "abc\r\nde", "the A edit");
        handle_of(a, 0, L"abc\r\nde", "abc\r\nde", "the A edit");
    }
    close_parent();
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "text", sec_text, F2KT_ALWAYS },
    { "select", sec_select, F2KT_ALWAYS },
    { "limit", sec_limit, F2KT_ALWAYS },
    { "lines", sec_lines, F2KT_ALWAYS },
    { "readonly", sec_readonly, F2KT_ALWAYS },
    { "undo", sec_undo, F2KT_ALWAYS },
    { "modify", sec_modify, F2KT_ALWAYS },
    { "case", sec_case, F2KT_ALWAYS },
    { "notify", sec_notify, F2KT_ALWAYS },
    { "wantret", sec_wantret, F2KT_ALWAYS },
    { "autovscroll", sec_autovscroll, F2KT_ALWAYS },
    { "margins", sec_margins, F2KT_ALWAYS },
    { "linescroll", sec_linescroll, F2KT_ALWAYS },
    { "password", sec_password, F2KT_ALWAYS },
    { "gethandle", sec_gethandle, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("editctl", sections, argc, argv);
}
