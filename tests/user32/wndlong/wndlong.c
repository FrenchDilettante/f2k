/*
 * wndlong - a window's data through GetWindowLongW/A and
 * SetWindowLongW/A: GWL_STYLE and GWL_EXSTYLE (and the
 * WM_STYLECHANGING/WM_STYLECHANGED a change sends), GWL_ID,
 * GWL_USERDATA, GWL_HINSTANCE and GWL_HWNDPARENT, GWL_WNDPROC
 * (subclassing: the chain through CallWindowProcW/A, the procedure
 * values the W and A forms answer, IsWindowUnicode), a dialog's
 * DWL_MSGRESULT, DWL_DLGPROC and DWL_USER, and the class's extra bytes
 * (cbWndExtra) through GetWindowLongW/SetWindowLongW and
 * GetWindowWord/SetWindowWord.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare
 * (yesno()): a procedure value prints as equal to a given procedure or
 * not. Every call under observation is armed with the last-error
 * sentinel and its line prints ret= and err=; styles print in hex. A
 * SetWindowLong answer of 0 can be a success (the previous value was
 * 0), so the sentinel shows whether it touched the last error. The
 * window procedures record what they receive; the records print after
 * the calls, never from inside a procedure. Each section registers its
 * own classes (W, as calc's, unless it says A) and creates hidden
 * windows, destroyed at its end.
 *
 * The dialog of the dialog section comes from a template the program
 * builds in memory (no resource): a DLGTEMPLATE with no controls, no
 * menu, the default class and an empty caption, in the system font,
 * created with CreateDialogIndirectParamW.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   style     GWL_STYLE and GWL_EXSTYLE through both forms; SetWindowLongW
 *             of each: the previous value, the value after, and the
 *             WM_STYLECHANGING/WM_STYLECHANGED the procedure receives
 *             (wParam, the STYLESTRUCT's old and new)
 *   id        a child's GWL_ID and SetWindowLongW of it, GWL_HWNDPARENT
 *             of a child and of a top-level window, GWL_HINSTANCE
 *   userdata  GWL_USERDATA: 0 at creation, set and read back through
 *             both forms, the previous value each set returns
 *   extra     a class with 12 extra bytes: their zeros at creation,
 *             SetWindowLongW/GetWindowLongW at 0, 4 and 8, at 9 and 12
 *             (past the end) and at an index no GWL_ value names;
 *             SetWindowWord/GetWindowWord at 0 and 10, and 11; a class
 *             with none
 *   wndproc   GWL_WNDPROC of a W class's window and of an A class's
 *             through both forms; SetWindowLongW subclassing (the
 *             previous procedure, the chain a sent message takes through
 *             CallWindowProcW, its return); SetWindowLongA subclassing a
 *             W window (IsWindowUnicode before and after, the chain
 *             through CallWindowProcA); restoring the procedures
 *   dialog    CreateDialogIndirectParamW: the dialog's class,
 *             DWL_DLGPROC through both forms, GWL_WNDPROC against
 *             DefDlgProcW/A, DWL_USER set and read back, DWL_MSGRESULT
 *             as SendMessageW's answer when the procedure sets it and
 *             returns TRUE, or returns FALSE
 *   errors    GetWindowLongW/SetWindowLongW on NULL and on a destroyed
 *             window
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat wndlong):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wndlong.c user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate them. */
#ifndef GWL_USERDATA
#define GWL_USERDATA (-21)
#endif
#ifndef DWL_MSGRESULT
#define DWL_MSGRESULT 0
#endif
#ifndef DWL_DLGPROC
#define DWL_DLGPROC 4
#endif
#ifndef DWL_USER
#define DWL_USER 8
#endif

#define EXTRA_BYTES 12

/* The message the subclassing chain is observed with, and the one the
 * dialog's procedure answers through DWL_MSGRESULT. */
#define WM_PROBE (WM_USER + 1)
#define WM_RESULT_TRUE (WM_USER + 2)
#define WM_RESULT_FALSE (WM_USER + 3)

/* --- What the procedures record --------------------------------------- */

#define MAX_STEPS 16

/* The chain a message takes: which procedure ran, in order. */
static const char *steps[MAX_STEPS];
static int step_count;

/* The style messages the base procedure received. */
typedef struct {
    UINT msg;
    WPARAM wparam;
    DWORD old_style;
    DWORD new_style;
} style_event;

static style_event style_events[MAX_STEPS];
static int style_count;

static WNDPROC prev_w;          /* what SetWindowLongW(GWL_WNDPROC) returned */
static WNDPROC prev_a;          /* what SetWindowLongA(GWL_WNDPROC) returned */

static void reset_records(void)
{
    step_count = 0;
    style_count = 0;
}

static void step(const char *who)
{
    if (step_count < MAX_STEPS) {
        steps[step_count++] = who;
    }
}

static void print_steps(void)
{
    char buf[256];
    int i;

    buf[0] = 0;
    for (i = 0; i < step_count; i++) {
        if (i > 0) {
            strcat(buf, " -> ");
        }
        strcat(buf, steps[i]);
    }
    line("  the chain: %s", step_count == 0 ? "(no procedure ran)" : buf);
}

static const char *style_msg_name(UINT msg)
{
    return msg == WM_STYLECHANGING ? "WM_STYLECHANGING" : "WM_STYLECHANGED";
}

static void print_style_events(void)
{
    int i;

    line("  the procedure received %d style messages", style_count);
    for (i = 0; i < style_count; i++) {
        line("    %s wParam=%ld old=0x%08lX new=0x%08lX", style_msg_name(style_events[i].msg),
             (long)(int)style_events[i].wparam, (unsigned long)style_events[i].old_style,
             (unsigned long)style_events[i].new_style);
    }
}

/* The classes' procedure: records the style messages and its own place in
 * a chain, answers WM_PROBE with 10. */
static LRESULT CALLBACK base_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    STYLESTRUCT *ss;

    if (msg == WM_PROBE) {
        step("base");
        return 10;
    }
    if ((msg == WM_STYLECHANGING || msg == WM_STYLECHANGED) && style_count < MAX_STEPS) {
        ss = (STYLESTRUCT *)lparam;
        style_events[style_count].msg = msg;
        style_events[style_count].wparam = wparam;
        style_events[style_count].old_style = ss != NULL ? ss->styleOld : 0;
        style_events[style_count].new_style = ss != NULL ? ss->styleNew : 0;
        style_count++;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/* The same for an A class. */
static LRESULT CALLBACK base_proc_a(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_PROBE) {
        step("base A");
        return 10;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

/* A W subclass: passes WM_PROBE on through CallWindowProcW and adds 100. */
static LRESULT CALLBACK sub_w(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    LRESULT r;

    if (msg == WM_PROBE) {
        step("subclass W");
        r = CallWindowProcW(prev_w, hwnd, msg, wparam, lparam);
        return r + 100;
    }
    return CallWindowProcW(prev_w, hwnd, msg, wparam, lparam);
}

/* An A subclass: passes WM_PROBE on through CallWindowProcA and adds 1000. */
static LRESULT CALLBACK sub_a(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    LRESULT r;

    if (msg == WM_PROBE) {
        step("subclass A");
        r = CallWindowProcA(prev_a, hwnd, msg, wparam, lparam);
        return r + 1000;
    }
    return CallWindowProcA(prev_a, hwnd, msg, wparam, lparam);
}

/* --- Helpers ----------------------------------------------------------- */

static HINSTANCE instance(void)
{
    return GetModuleHandleA(NULL);
}

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

/* Register a W class of the base procedure with `extra` window bytes. */
static void register_w(const WCHAR *name, const char *shown, int extra)
{
    WNDCLASSW wc;
    ATOM a;
    DWORD err;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = base_proc;
    wc.cbWndExtra = extra;
    wc.hInstance = instance();
    wc.lpszClassName = name;
    arm();
    a = RegisterClassW(&wc);
    err = GetLastError();
    line("RegisterClassW(%s, %d extra bytes): atom nonzero %s err=%s", shown, extra, yesno(a != 0),
         le_of(err));
}

/* A hidden window of a class: top-level (WS_OVERLAPPED | WS_CAPTION) or
 * a child of `parent` with id `id`. */
static HWND make_w(const WCHAR *cls, const char *shown, HWND parent, int id)
{
    HWND h;
    DWORD err;
    DWORD style = parent != NULL ? WS_CHILD : WS_OVERLAPPED | WS_CAPTION;

    arm();
    h = CreateWindowExW(0, cls, L"wndlong", style, 10, 10, 200, 100, parent, (HMENU)id, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExW(%s, %s): non-NULL %s err=%s", shown, parent != NULL ? "child" : "top-level",
         yesno(h != NULL), le_of(err));
    return h;
}

static void destroy(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
    drain();
}

static void get_long(HWND h, int index, const char *name)
{
    LONG w;
    LONG a;
    const char *ew;

    arm();
    w = GetWindowLongW(h, index);
    ew = le();
    arm();
    a = GetWindowLongA(h, index);
    line("GetWindowLongW(%s): ret=0x%08lX err=%s; GetWindowLongA the same %s err=%s", name,
         (unsigned long)w, ew, yesno(a == w), le());
}

/* --- style ------------------------------------------------------------- */

static void set_style(HWND h, int index, const char *name, DWORD value)
{
    LONG r;

    reset_records();
    arm();
    r = SetWindowLongW(h, index, (LONG)value);
    line("SetWindowLongW(%s, 0x%08lX): ret=0x%08lX err=%s", name, (unsigned long)value, (unsigned long)r,
         le());
    line("  GetWindowLongW after: 0x%08lX", (unsigned long)GetWindowLongW(h, index));
    print_style_events();
}

static void sec_style(void)
{
    HWND h;
    LONG style;
    LONG ex;

    drain();
    register_w(L"F2KWndlongStyle", "F2KWndlongStyle", 0);
    h = make_w(L"F2KWndlongStyle", "F2KWndlongStyle", NULL, 0);
    if (h == NULL) {
        return;
    }
    get_long(h, GWL_STYLE, "GWL_STYLE");
    get_long(h, GWL_EXSTYLE, "GWL_EXSTYLE");
    style = GetWindowLongW(h, GWL_STYLE);
    ex = GetWindowLongW(h, GWL_EXSTYLE);
    set_style(h, GWL_STYLE, "GWL_STYLE", (DWORD)style | WS_THICKFRAME);
    set_style(h, GWL_STYLE, "GWL_STYLE", (DWORD)style);
    set_style(h, GWL_EXSTYLE, "GWL_EXSTYLE", (DWORD)ex | WS_EX_TOOLWINDOW);
    set_style(h, GWL_EXSTYLE, "GWL_EXSTYLE", (DWORD)ex);
    reset_records();
    arm();
    style = SetWindowLongA(h, GWL_STYLE, GetWindowLongA(h, GWL_STYLE) | WS_SYSMENU);
    line("SetWindowLongA(GWL_STYLE, | WS_SYSMENU): ret=0x%08lX err=%s after 0x%08lX", (unsigned long)style,
         le(), (unsigned long)GetWindowLongA(h, GWL_STYLE));
    print_style_events();
    destroy(h);
}

/* --- id ---------------------------------------------------------------- */

static void sec_id(void)
{
    HWND parent;
    HWND child;
    LONG r;

    drain();
    register_w(L"F2KWndlongId", "F2KWndlongId", 0);
    parent = make_w(L"F2KWndlongId", "F2KWndlongId", NULL, 0);
    child = make_w(L"F2KWndlongId", "F2KWndlongId", parent, 77);
    if (parent == NULL || child == NULL) {
        destroy(parent);
        return;
    }
    get_long(child, GWL_ID, "child, GWL_ID");
    arm();
    r = SetWindowLongW(child, GWL_ID, 88);
    line("SetWindowLongW(child, GWL_ID, 88): ret=%ld err=%s after %ld", (long)r, le(),
         (long)GetWindowLongW(child, GWL_ID));
    arm();
    r = SetWindowLongA(child, GWL_ID, 99);
    line("SetWindowLongA(child, GWL_ID, 99): ret=%ld err=%s after %ld", (long)r, le(),
         (long)GetWindowLongA(child, GWL_ID));
    get_long(parent, GWL_ID, "top-level, GWL_ID");

    arm();
    r = GetWindowLongW(child, GWL_HWNDPARENT);
    line("GetWindowLongW(child, GWL_HWNDPARENT): the parent %s non-NULL %s err=%s",
         yesno((HWND)r == parent), yesno(r != 0), le());
    arm();
    r = GetWindowLongW(parent, GWL_HWNDPARENT);
    line("GetWindowLongW(top-level, GWL_HWNDPARENT): non-NULL %s err=%s", yesno(r != 0), le());
    arm();
    r = GetWindowLongW(child, GWL_HINSTANCE);
    line("GetWindowLongW(child, GWL_HINSTANCE): the module %s err=%s", yesno((HINSTANCE)r == instance()),
         le());
    arm();
    r = GetWindowLongA(parent, GWL_HINSTANCE);
    line("GetWindowLongA(top-level, GWL_HINSTANCE): the module %s err=%s",
         yesno((HINSTANCE)r == instance()), le());
    destroy(parent);
}

/* --- userdata ---------------------------------------------------------- */

static void sec_userdata(void)
{
    HWND h;
    LONG r;

    drain();
    register_w(L"F2KWndlongUser", "F2KWndlongUser", 0);
    h = make_w(L"F2KWndlongUser", "F2KWndlongUser", NULL, 0);
    if (h == NULL) {
        return;
    }
    get_long(h, GWL_USERDATA, "GWL_USERDATA");
    arm();
    r = SetWindowLongW(h, GWL_USERDATA, 0x12345678);
    line("SetWindowLongW(GWL_USERDATA, 0x12345678): ret=0x%08lX err=%s", (unsigned long)r, le());
    get_long(h, GWL_USERDATA, "GWL_USERDATA");
    arm();
    r = SetWindowLongA(h, GWL_USERDATA, -5);
    line("SetWindowLongA(GWL_USERDATA, -5): ret=0x%08lX err=%s", (unsigned long)r, le());
    get_long(h, GWL_USERDATA, "GWL_USERDATA");
    arm();
    r = SetWindowLongW(h, GWL_USERDATA, 0);
    line("SetWindowLongW(GWL_USERDATA, 0): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = SetWindowLongW(h, GWL_USERDATA, 0);
    line("SetWindowLongW(GWL_USERDATA, 0) again: ret=0x%08lX err=%s", (unsigned long)r, le());
    destroy(h);
}

/* --- extra ------------------------------------------------------------- */

static void set_extra(HWND h, int index, LONG value)
{
    LONG r;

    arm();
    r = SetWindowLongW(h, index, value);
    line("SetWindowLongW(%d, 0x%08lX): ret=0x%08lX err=%s", index, (unsigned long)value, (unsigned long)r,
         le());
}

static void get_extra(HWND h, int index)
{
    LONG r;

    arm();
    r = GetWindowLongW(h, index);
    line("GetWindowLongW(%d): ret=0x%08lX err=%s", index, (unsigned long)r, le());
}

static void sec_extra(void)
{
    HWND h;
    HWND none;
    WORD w;

    drain();
    register_w(L"F2KWndlongExtra", "F2KWndlongExtra", EXTRA_BYTES);
    register_w(L"F2KWndlongNone", "F2KWndlongNone", 0);
    h = make_w(L"F2KWndlongExtra", "F2KWndlongExtra", NULL, 0);
    if (h == NULL) {
        return;
    }
    get_extra(h, 0);
    get_extra(h, 4);
    get_extra(h, 8);
    set_extra(h, 0, 0x11111111);
    set_extra(h, 4, 0x22222222);
    set_extra(h, 8, 0x33333333);
    set_extra(h, 0, 0x44444444);
    get_extra(h, 0);
    get_extra(h, 4);
    get_extra(h, 8);
    get_extra(h, 2);
    set_extra(h, 9, 0x55555555);
    get_extra(h, 9);
    set_extra(h, 12, 0x66666666);
    get_extra(h, 12);
    get_extra(h, -100);
    set_extra(h, -100, 1);
    get_extra(h, 8);

    arm();
    w = SetWindowWord(h, 0, 0xABCD);
    line("SetWindowWord(0, 0xABCD): ret=0x%04X err=%s", (unsigned)w, le());
    arm();
    w = GetWindowWord(h, 0);
    line("GetWindowWord(0): ret=0x%04X err=%s", (unsigned)w, le());
    get_extra(h, 0);
    arm();
    w = SetWindowWord(h, 10, 0x1234);
    line("SetWindowWord(10, 0x1234): ret=0x%04X err=%s", (unsigned)w, le());
    arm();
    w = GetWindowWord(h, 10);
    line("GetWindowWord(10): ret=0x%04X err=%s", (unsigned)w, le());
    get_extra(h, 8);
    arm();
    w = GetWindowWord(h, 11);
    line("GetWindowWord(11): ret=0x%04X err=%s", (unsigned)w, le());
    arm();
    w = SetWindowWord(h, 11, 1);
    line("SetWindowWord(11, 1): ret=0x%04X err=%s", (unsigned)w, le());
    destroy(h);

    none = make_w(L"F2KWndlongNone", "F2KWndlongNone", NULL, 0);
    if (none != NULL) {
        get_extra(none, 0);
        set_extra(none, 0, 1);
        destroy(none);
    }
}

/* --- wndproc ----------------------------------------------------------- */

static void probe(HWND h, int ansi)
{
    LRESULT r;

    step_count = 0;
    arm();
    r = ansi ? SendMessageA(h, WM_PROBE, 0, 0) : SendMessageW(h, WM_PROBE, 0, 0);
    line("%s(WM_PROBE): ret=%ld err=%s", ansi ? "SendMessageA" : "SendMessageW", (long)r, le());
    print_steps();
}

static void print_procs(HWND h, const char *who)
{
    LONG w = GetWindowLongW(h, GWL_WNDPROC);
    LONG a = GetWindowLongA(h, GWL_WNDPROC);

    line("%s: GWL_WNDPROC through W: base %s subclass W %s subclass A %s", who,
         yesno(w == (LONG)base_proc), yesno(w == (LONG)sub_w), yesno(w == (LONG)sub_a));
    line("%s: GWL_WNDPROC through A: base %s subclass W %s subclass A %s; the same as through W %s", who,
         yesno(a == (LONG)base_proc), yesno(a == (LONG)sub_w), yesno(a == (LONG)sub_a), yesno(a == w));
    line("%s: IsWindowUnicode %s", who, yesno(IsWindowUnicode(h)));
}

static void sec_wndproc(void)
{
    HWND h;
    HWND ha;
    WNDCLASSA wca;
    ATOM atom;
    LONG r;
    LONG w;
    LONG a;
    DWORD err;

    drain();
    register_w(L"F2KWndlongProc", "F2KWndlongProc", 0);
    h = make_w(L"F2KWndlongProc", "F2KWndlongProc", NULL, 0);
    if (h == NULL) {
        return;
    }
    print_procs(h, "W class");
    probe(h, 0);

    arm();
    r = SetWindowLongW(h, GWL_WNDPROC, (LONG)sub_w);
    prev_w = (WNDPROC)r;
    line("SetWindowLongW(GWL_WNDPROC, subclass W): previous is base %s non-NULL %s err=%s",
         yesno(r == (LONG)base_proc), yesno(r != 0), le());
    print_procs(h, "subclassed W");
    probe(h, 0);
    probe(h, 1);

    arm();
    r = SetWindowLongA(h, GWL_WNDPROC, (LONG)sub_a);
    prev_a = (WNDPROC)r;
    line("SetWindowLongA(GWL_WNDPROC, subclass A): previous is subclass W %s non-NULL %s err=%s",
         yesno(r == (LONG)sub_w), yesno(r != 0), le());
    print_procs(h, "subclassed A over W");
    probe(h, 0);
    probe(h, 1);

    arm();
    r = SetWindowLongA(h, GWL_WNDPROC, (LONG)prev_a);
    line("SetWindowLongA(GWL_WNDPROC, the value it returned): previous is subclass A %s err=%s",
         yesno(r == (LONG)sub_a), le());
    print_procs(h, "A subclass removed");
    arm();
    r = SetWindowLongW(h, GWL_WNDPROC, (LONG)prev_w);
    line("SetWindowLongW(GWL_WNDPROC, the value it returned): previous is subclass W %s err=%s",
         yesno(r == (LONG)sub_w), le());
    print_procs(h, "restored");
    probe(h, 0);
    destroy(h);

    ZeroMemory(&wca, sizeof wca);
    wca.lpfnWndProc = base_proc_a;
    wca.hInstance = instance();
    wca.lpszClassName = "F2KWndlongProcA";
    arm();
    atom = RegisterClassA(&wca);
    err = GetLastError();
    line("RegisterClassA(F2KWndlongProcA): atom nonzero %s err=%s", yesno(atom != 0), le_of(err));
    arm();
    ha = CreateWindowExA(0, "F2KWndlongProcA", "wndlong", WS_OVERLAPPED | WS_CAPTION, 10, 10, 200, 100,
                         NULL, NULL, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExA(F2KWndlongProcA, top-level): non-NULL %s err=%s", yesno(ha != NULL), le_of(err));
    if (ha != NULL) {
        w = GetWindowLongW(ha, GWL_WNDPROC);
        a = GetWindowLongA(ha, GWL_WNDPROC);
        line("A class: GWL_WNDPROC through A is its procedure %s, through W %s; IsWindowUnicode %s",
             yesno(a == (LONG)base_proc_a), yesno(w == (LONG)base_proc_a), yesno(IsWindowUnicode(ha)));
        probe(ha, 0);
        arm();
        r = SetWindowLongW(ha, GWL_WNDPROC, (LONG)sub_w);
        prev_w = (WNDPROC)r;
        line("SetWindowLongW(A window, GWL_WNDPROC, subclass W): previous is its procedure %s "
             "non-NULL %s err=%s IsWindowUnicode %s",
             yesno(r == (LONG)base_proc_a), yesno(r != 0), le(), yesno(IsWindowUnicode(ha)));
        probe(ha, 1);
        destroy(ha);
    }
}

/* --- dialog ------------------------------------------------------------ */

static BOOL CALLBACK dlg_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_INITDIALOG:
        return TRUE;
    case WM_RESULT_TRUE:
        step("dialog procedure, TRUE");
        SetWindowLongW(hwnd, DWL_MSGRESULT, 55);
        return TRUE;
    case WM_RESULT_FALSE:
        step("dialog procedure, FALSE");
        SetWindowLongW(hwnd, DWL_MSGRESULT, 66);
        return FALSE;
    }
    return FALSE;
}

/* A DLGTEMPLATE with no controls, built in DWORD-aligned memory: style,
 * extended style, the count, x, y, cx, cy, then no menu, the default
 * class and an empty caption. */
static DWORD template_words[8];

static const DLGTEMPLATE *build_template(void)
{
    WORD *w = (WORD *)template_words;
    DWORD style = WS_POPUP | WS_CAPTION | DS_MODALFRAME;

    ZeroMemory(template_words, sizeof template_words);
    w[0] = LOWORD(style);
    w[1] = HIWORD(style);
    w[2] = 0;
    w[3] = 0;
    w[4] = 0;
    w[5] = 10;
    w[6] = 10;
    w[7] = 100;
    w[8] = 50;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    return (const DLGTEMPLATE *)template_words;
}

static void sec_dialog(void)
{
    HWND dlg;
    HMODULE user32;
    FARPROC defdlg_w;
    FARPROC defdlg_a;
    WCHAR cls[64];
    LONG w;
    LONG a;
    LONG r;
    LRESULT s;

    drain();
    arm();
    dlg = CreateDialogIndirectParamW(instance(), build_template(), NULL, (DLGPROC)dlg_proc, 0);
    line("CreateDialogIndirectParamW(no controls, system font): non-NULL %s err=%s", yesno(dlg != NULL),
         le());
    if (dlg == NULL) {
        return;
    }
    cls[0] = 0;
    GetClassNameW(dlg, cls, 64);
    line("class %s IsWindowUnicode %s", ws(cls), yesno(IsWindowUnicode(dlg)));

    arm();
    w = GetWindowLongW(dlg, DWL_DLGPROC);
    line("GetWindowLongW(DWL_DLGPROC): the procedure %s non-NULL %s err=%s", yesno(w == (LONG)dlg_proc),
         yesno(w != 0), le());
    arm();
    a = GetWindowLongA(dlg, DWL_DLGPROC);
    line("GetWindowLongA(DWL_DLGPROC): the procedure %s the same as through W %s err=%s",
         yesno(a == (LONG)dlg_proc), yesno(a == w), le());

    user32 = GetModuleHandleA("user32.dll");
    defdlg_w = GetProcAddress(user32, "DefDlgProcW");
    defdlg_a = GetProcAddress(user32, "DefDlgProcA");
    w = GetWindowLongW(dlg, GWL_WNDPROC);
    a = GetWindowLongA(dlg, GWL_WNDPROC);
    line("GWL_WNDPROC through W: DefDlgProcW %s DefDlgProcA %s; through A: DefDlgProcW %s DefDlgProcA %s",
         yesno(w == (LONG)defdlg_w), yesno(w == (LONG)defdlg_a), yesno(a == (LONG)defdlg_w),
         yesno(a == (LONG)defdlg_a));

    get_long(dlg, DWL_USER, "DWL_USER");
    arm();
    r = SetWindowLongW(dlg, DWL_USER, 0x0BADF00D);
    line("SetWindowLongW(DWL_USER, 0x0BADF00D): ret=0x%08lX err=%s", (unsigned long)r, le());
    get_long(dlg, DWL_USER, "DWL_USER");
    get_long(dlg, DWL_MSGRESULT, "DWL_MSGRESULT");

    step_count = 0;
    arm();
    s = SendMessageW(dlg, WM_RESULT_TRUE, 0, 0);
    line("SendMessageW(WM_USER+2: DWL_MSGRESULT 55, TRUE): ret=%ld err=%s", (long)s, le());
    print_steps();
    get_long(dlg, DWL_MSGRESULT, "DWL_MSGRESULT");
    step_count = 0;
    arm();
    s = SendMessageW(dlg, WM_RESULT_FALSE, 0, 0);
    line("SendMessageW(WM_USER+3: DWL_MSGRESULT 66, FALSE): ret=%ld err=%s", (long)s, le());
    print_steps();
    get_long(dlg, DWL_MSGRESULT, "DWL_MSGRESULT");
    destroy(dlg);
}

/* --- errors ------------------------------------------------------------ */

static void sec_errors(void)
{
    HWND h;
    LONG r;

    drain();
    arm();
    r = GetWindowLongW(NULL, GWL_STYLE);
    line("GetWindowLongW(NULL, GWL_STYLE): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = SetWindowLongW(NULL, GWL_USERDATA, 1);
    line("SetWindowLongW(NULL, GWL_USERDATA, 1): ret=0x%08lX err=%s", (unsigned long)r, le());
    register_w(L"F2KWndlongGone", "F2KWndlongGone", 4);
    h = make_w(L"F2KWndlongGone", "F2KWndlongGone", NULL, 0);
    destroy(h);
    arm();
    r = GetWindowLongW(h, GWL_STYLE);
    line("GetWindowLongW(a destroyed window, GWL_STYLE): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = GetWindowLongA(h, 0);
    line("GetWindowLongA(a destroyed window, 0): ret=0x%08lX err=%s", (unsigned long)r, le());
    arm();
    r = SetWindowLongW(h, GWL_USERDATA, 1);
    line("SetWindowLongW(a destroyed window, GWL_USERDATA, 1): ret=0x%08lX err=%s", (unsigned long)r, le());
}

static const section_t sections[] = {
    { "style", sec_style, F2KT_ALWAYS },
    { "id", sec_id, F2KT_ALWAYS },
    { "userdata", sec_userdata, F2KT_ALWAYS },
    { "extra", sec_extra, F2KT_ALWAYS },
    { "wndproc", sec_wndproc, F2KT_ALWAYS },
    { "dialog", sec_dialog, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("wndlong", sections, argc, argv);
}
