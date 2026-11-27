/*
 * listbox - user32's built-in ListBox control as a program drives it by
 * messages and keys: LB_ADDSTRING, LB_INSERTSTRING, LB_DELETESTRING,
 * LB_FINDSTRING(EXACT), LB_GETTEXT(LEN), LB_GETCOUNT, LB_SETCURSEL,
 * LB_GETCURSEL, LB_SELECTSTRING, LB_SETITEMDATA/LB_GETITEMDATA,
 * LB_SETTOPINDEX, LB_GETITEMHEIGHT and LB_GETITEMRECT; LBS_SORT;
 * LBS_MULTIPLESEL and LBS_EXTENDEDSEL; owner-draw fixed and variable
 * list boxes and the WM_MEASUREITEM, WM_DRAWITEM and WM_DELETEITEM their
 * parent receives; the LBN_* notifications; keyboard navigation; LB_DIR,
 * DlgDirListA/W and DlgDirSelectExA/W over a directory the program
 * makes itself; GetListBoxInfo; the error returns; and a list box in a
 * dialog built from a template in memory.
 *
 * The list boxes are children of a visible top-level window of the
 * fixture's own class, whose procedure records what it receives
 * (WM_COMMAND's id and code, WM_MEASUREITEM, WM_DRAWITEM and
 * WM_DELETEITEM's fields); the records print after the calls, never
 * from inside the procedure. Keys are WM_KEYDOWN and WM_CHAR sent to the
 * list box itself, no key is pressed; the one double click is the mouse
 * messages posted to the list box, as tests/user32/controls posts them.
 *
 * Nothing printed depends on a font: the list boxes whose geometry
 * prints have no border and their item height set (LB_SETITEMHEIGHT, or
 * the parent's WM_MEASUREITEM answer); a default item height prints only
 * against the System font's tmHeight. Conventions as the other fixtures
 * on f2kt.h: no handle value or address prints; every call under
 * observation is armed with the last-error sentinel and its line prints
 * ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   basic    an unsorted LBS_NOTIFY list box: its class name; adding,
 *            inserting, finding, reading and deleting strings; item
 *            data; the current selection and LB_SELECTSTRING; the top
 *            index; the default item height; and the error returns of
 *            each with a bad index
 *   sort     LBS_SORT: the indices LB_ADDSTRING answers and the order,
 *            LB_INSERTSTRING not sorting, LB_FINDSTRING over it
 *   multi    LBS_MULTIPLESEL and LBS_EXTENDEDSEL: LB_SETSEL,
 *            LB_GETSEL, LB_GETSELCOUNT, LB_GETSELITEMS, LB_SELITEMRANGE
 *            and LB_SELITEMRANGEEX, LB_GETCARETINDEX, and what a
 *            single-selection list box answers to them
 *   ownerfix an LBS_OWNERDRAWFIXED list box without LBS_HASSTRINGS: the
 *            WM_MEASUREITEM it sends on creation (the parent answers 18),
 *            its items as data, LB_GETTEXT of one, LB_GETITEMRECT, the
 *            WM_DRAWITEMs of a repaint and of LB_SETCURSEL, and the
 *            WM_DELETEITEMs of LB_DELETESTRING and DestroyWindow
 *   ownervar an LBS_OWNERDRAWVARIABLE | LBS_HASSTRINGS list box: one
 *            WM_MEASUREITEM per item added (the parent answers 10 plus
 *            5 times the index), LB_GETITEMHEIGHT and LB_GETITEMRECT of
 *            each, LB_SETITEMHEIGHT
 *   notify   the LBN_SETFOCUS, LBN_KILLFOCUS, LBN_SELCHANGE and
 *            LBN_DBLCLK notifications, with and without LBS_NOTIFY:
 *            SetFocus, LB_SETCURSEL, a key, a posted double click
 *   keys     a list box of 20 items, 20 pixels high each, 5 showing:
 *            Down, Up, End, Home, PgDn, PgUp, at either end too; the
 *            caret, the selection, the top index and the LBN_SELCHANGEs
 *            after each; type-ahead (WM_CHAR) on fresh list boxes; Down
 *            and Space in an LBS_MULTIPLESEL one
 *   dir      LB_DIR over f2klbdir (made in the current directory with
 *            a.txt, b.txt, c.dat, noext and the subdirectory sub, and
 *            removed at the end) with DDL_READWRITE, DDL_DIRECTORY and
 *            DDL_EXCLUSIVE, and on a missing directory; DlgDirListA/W:
 *            the path buffer after, the current directory it leaves;
 *            DlgDirSelectExA/W on a file, a file without extension, a
 *            subdirectory, [..] and no selection
 *   info     GetListBoxInfo and LB_GETLISTBOXINFO (items per column),
 *            and of a window that is no list box; LB_INITSTORAGE, and
 *            one too large to hold (LB_ERRSPACE)
 *   dialog   a dialog made with CreateDialogIndirectParamW from a
 *            template in memory holding a list box by the class atom
 *            0x0083 and one by the name "ListBox": the dialog made,
 *            each item's class name, WM_GETDLGCODE, and the strings
 *            WM_INITDIALOG added
 *
 * GetListBoxInfo is found with GetProcAddress: MSVC 6's headers and
 * import library predate it.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat listbox):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% listbox.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

#ifndef LB_GETLISTBOXINFO
#define LB_GETLISTBOXINFO 0x01B2
#endif
#ifndef LB_INITSTORAGE
#define LB_INITSTORAGE 0x01A8
#endif
#ifndef ODT_LISTBOX
#define ODT_LISTBOX 2
#endif

#define PARENT_CLASS L"F2KListBoxParent"
#define LB_ID 300

typedef DWORD(WINAPI *getlistboxinfo_t)(HWND);

/* --- What the parent records --------------------------------------- */

#define MAX_EVENTS 64

typedef struct {
    UINT msg;
    int id;
    int code;
    int from_control;
    UINT ctl_type, ctl_id, item_id, action, state;
    LONG left, top, right, bottom;
    UINT height_in;
    DWORD data;
} event_t;

static event_t events[MAX_EVENTS];
static int event_count;
static int events_lost;
/* What WM_MEASUREITEM answers: a fixed height, or 10 + 5 * itemID. */
static UINT measure_fixed = 18;
static int measure_variable;

static void reset_events(void)
{
    event_count = 0;
    events_lost = 0;
}

static event_t *new_event(UINT msg)
{
    if (event_count >= MAX_EVENTS) {
        events_lost++;
        return NULL;
    }
    ZeroMemory(&events[event_count], sizeof events[0]);
    events[event_count].msg = msg;
    return &events[event_count++];
}

static LRESULT CALLBACK parent_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    event_t *e;

    switch (msg) {
    case WM_COMMAND:
        if (lparam != 0 && (e = new_event(msg)) != NULL) {
            e->id = LOWORD(wparam);
            e->code = HIWORD(wparam);
            e->from_control = GetDlgItem(hwnd, LOWORD(wparam)) == (HWND)lparam;
        }
        return 0;
    case WM_MEASUREITEM: {
        MEASUREITEMSTRUCT *m = (MEASUREITEMSTRUCT *)lparam;

        if ((e = new_event(msg)) != NULL) {
            e->ctl_type = m->CtlType;
            e->ctl_id = m->CtlID;
            e->item_id = m->itemID;
            e->height_in = m->itemHeight;
            e->data = (DWORD)m->itemData;
        }
        m->itemHeight = measure_variable ? 10 + 5 * m->itemID : measure_fixed;
        return TRUE;
    }
    case WM_DRAWITEM: {
        const DRAWITEMSTRUCT *d = (const DRAWITEMSTRUCT *)lparam;

        if ((e = new_event(msg)) != NULL) {
            e->ctl_type = d->CtlType;
            e->ctl_id = d->CtlID;
            e->item_id = d->itemID;
            e->action = d->itemAction;
            e->state = d->itemState;
            e->left = d->rcItem.left;
            e->top = d->rcItem.top;
            e->right = d->rcItem.right;
            e->bottom = d->rcItem.bottom;
            e->data = (DWORD)d->itemData;
        }
        return TRUE;
    }
    case WM_DELETEITEM: {
        const DELETEITEMSTRUCT *d = (const DELETEITEMSTRUCT *)lparam;

        if ((e = new_event(msg)) != NULL) {
            e->ctl_type = d->CtlType;
            e->ctl_id = d->CtlID;
            e->item_id = d->itemID;
            e->data = (DWORD)d->itemData;
        }
        return TRUE;
    }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static const char *lbn_name(int code)
{
    static char buf[16];

    switch (code) {
    case LBN_ERRSPACE: return "LBN_ERRSPACE";
    case LBN_SELCHANGE: return "LBN_SELCHANGE";
    case LBN_DBLCLK: return "LBN_DBLCLK";
    case LBN_SELCANCEL: return "LBN_SELCANCEL";
    case LBN_SETFOCUS: return "LBN_SETFOCUS";
    case LBN_KILLFOCUS: return "LBN_KILLFOCUS";
    }
    sprintf(buf, "code %d", code);
    return buf;
}

/* The records since the last print, then none. */
static void print_events(void)
{
    int i;
    const event_t *e;

    if (event_count == 0) {
        line("  the parent received nothing");
    }
    for (i = 0; i < event_count; i++) {
        e = &events[i];
        switch (e->msg) {
        case WM_COMMAND:
            line("  WM_COMMAND id=%d %s lParam is the control %s", e->id, lbn_name(e->code),
                 yesno(e->from_control));
            break;
        case WM_MEASUREITEM:
            line("  WM_MEASUREITEM CtlType=%u CtlID=%u itemID=%u itemData=0x%lX", e->ctl_type, e->ctl_id,
                 e->item_id, e->data);
            break;
        case WM_DRAWITEM:
            line("  WM_DRAWITEM CtlType=%u CtlID=%u itemID=%d itemAction=0x%X itemState=0x%X rcItem=%ld %ld %ld %ld "
                 "itemData=0x%lX",
                 e->ctl_type, e->ctl_id, (int)e->item_id, e->action, e->state, e->left, e->top, e->right,
                 e->bottom, e->data);
            break;
        case WM_DELETEITEM:
            line("  WM_DELETEITEM CtlType=%u CtlID=%u itemID=%u itemData=0x%lX", e->ctl_type, e->ctl_id,
                 e->item_id, e->data);
            break;
        }
    }
    if (events_lost) {
        line("  (%d more not recorded)", events_lost);
    }
    reset_events();
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

static HWND open_parent(void)
{
    static int registered;
    WNDCLASSW wc;
    HWND h;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = parent_proc;
        wc.hInstance = instance();
        wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = PARENT_CLASS;
        registered = RegisterClassW(&wc) != 0;
    }
    h = CreateWindowExW(0, PARENT_CLASS, L"F2K listbox", WS_POPUP | WS_BORDER | WS_VISIBLE, 40, 40, 322, 322,
                        NULL, NULL, instance(), NULL);
    line("the parent: made %s", yesno(registered && h != NULL));
    if (h != NULL) {
        SetForegroundWindow(h);
        drain();
    }
    reset_events();
    return h;
}

static void close_parent(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
    drain();
    reset_events();
}

/* A list box of the parent, id LB_ID, borderless, its client cx x cy. */
static HWND make_lb(HWND parent, DWORD style, int cx, int cy)
{
    return CreateWindowExW(0, L"ListBox", L"", WS_CHILD | WS_VISIBLE | style, 10, 10, cx, cy, parent,
                           (HMENU)LB_ID, instance(), NULL);
}

/* One message under observation: its answer and the last error. */
static LRESULT sm(HWND h, UINT msg, WPARAM w, LPARAM l, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, msg, w, l);
    line("%s: ret=%ld err=%s", what, (long)r, le());
    return r;
}

static LRESULT add(HWND h, const WCHAR *s)
{
    char what[96];

    sprintf(what, "LB_ADDSTRING(\"%s\")", ws(s));
    return sm(h, LB_ADDSTRING, 0, (LPARAM)s, what);
}

/* The items' texts in order, on one line. */
static void print_items(HWND h)
{
    char buf[512];
    WCHAR t[64];
    int n, i, k = 0;

    n = (int)SendMessageW(h, LB_GETCOUNT, 0, 0);
    buf[0] = 0;
    for (i = 0; i < n && k < (int)sizeof buf - 80; i++) {
        t[0] = 0;
        if (SendMessageW(h, LB_GETTEXTLEN, i, 0) < 60) {
            SendMessageW(h, LB_GETTEXT, i, (LPARAM)t);
        }
        k += sprintf(buf + k, "%s\"%s\"", i ? " " : "", ws(t));
    }
    line("  %d items: %s", n, buf);
}

/* The System font's tmHeight, which a list box with no font set takes
 * for its item height. */
static LONG system_font_height(void)
{
    HDC dc = GetDC(NULL);
    HGDIOBJ old;
    TEXTMETRICA tm;

    ZeroMemory(&tm, sizeof tm);
    old = SelectObject(dc, GetStockObject(SYSTEM_FONT));
    GetTextMetricsA(dc, &tm);
    SelectObject(dc, old);
    ReleaseDC(NULL, dc);
    return tm.tmHeight;
}

static const char *class_of(HWND h)
{
    static WCHAR b[64];

    b[0] = 0;
    GetClassNameW(h, b, 64);
    return ws(b);
}

/* --- basic ------------------------------------------------------------- */

static void sec_basic(void)
{
    HWND parent, lb;
    WCHAR t[64];
    char a[64];
    LRESULT r;

    parent = open_parent();
    lb = make_lb(parent, LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 150, 60);
    line("CreateWindowExW(\"ListBox\", LBS_NOTIFY | LBS_NOINTEGRALHEIGHT), 150x60: non-NULL %s, class %s", yesno(lb != NULL),
         class_of(lb));
    if (lb == NULL) {
        close_parent(parent);
        return;
    }
    print_events();
    sm(lb, LB_GETCOUNT, 0, 0, "LB_GETCOUNT, empty");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL, empty");
    add(lb, L"pear");
    add(lb, L"apple");
    add(lb, L"banana");
    sm(lb, LB_INSERTSTRING, 1, (LPARAM)L"cherry", "LB_INSERTSTRING(1, \"cherry\")");
    sm(lb, LB_INSERTSTRING, (WPARAM)-1, (LPARAM)L"Blueberry", "LB_INSERTSTRING(-1, \"Blueberry\")");
    sm(lb, LB_INSERTSTRING, 9, (LPARAM)L"fig", "LB_INSERTSTRING(9, \"fig\"), past the end");
    print_items(lb);
    sm(lb, LB_GETTEXTLEN, 2, 0, "LB_GETTEXTLEN(2)");
    t[0] = 0;
    arm();
    r = SendMessageW(lb, LB_GETTEXT, 2, (LPARAM)t);
    line("LB_GETTEXT(2), SendMessageW: ret=%ld err=%s text \"%s\"", (long)r, le(), ws(t));
    a[0] = 0;
    arm();
    r = SendMessageA(lb, LB_GETTEXT, 3, (LPARAM)a);
    line("LB_GETTEXT(3), SendMessageA: ret=%ld err=%s text \"%s\"", (long)r, le(), a);
    sm(lb, LB_GETTEXT, 9, (LPARAM)t, "LB_GETTEXT(9), no such item");
    sm(lb, LB_GETTEXTLEN, 9, 0, "LB_GETTEXTLEN(9)");
    sm(lb, LB_FINDSTRING, (WPARAM)-1, (LPARAM)L"b", "LB_FINDSTRING(-1, \"b\")");
    sm(lb, LB_FINDSTRING, 3, (LPARAM)L"b", "LB_FINDSTRING(3, \"b\")");
    sm(lb, LB_FINDSTRING, 4, (LPARAM)L"b", "LB_FINDSTRING(4, \"b\"), wrapping");
    sm(lb, LB_FINDSTRING, (WPARAM)-1, (LPARAM)L"APP", "LB_FINDSTRING(-1, \"APP\")");
    sm(lb, LB_FINDSTRING, (WPARAM)-1, (LPARAM)L"kiwi", "LB_FINDSTRING(-1, \"kiwi\")");
    sm(lb, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)L"BANANA", "LB_FINDSTRINGEXACT(-1, \"BANANA\")");
    sm(lb, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)L"ban", "LB_FINDSTRINGEXACT(-1, \"ban\")");
    sm(lb, LB_GETITEMDATA, 0, 0, "LB_GETITEMDATA(0), never set");
    sm(lb, LB_SETITEMDATA, 0, 0x1234, "LB_SETITEMDATA(0, 0x1234)");
    sm(lb, LB_GETITEMDATA, 0, 0, "LB_GETITEMDATA(0)");
    sm(lb, LB_SETITEMDATA, 9, 1, "LB_SETITEMDATA(9)");
    sm(lb, LB_GETITEMDATA, 9, 0, "LB_GETITEMDATA(9)");
    sm(lb, LB_SETCURSEL, 2, 0, "LB_SETCURSEL(2)");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
    sm(lb, LB_SETCURSEL, 9, 0, "LB_SETCURSEL(9)");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
    sm(lb, LB_SETCURSEL, (WPARAM)-1, 0, "LB_SETCURSEL(-1)");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
    sm(lb, LB_SELECTSTRING, (WPARAM)-1, (LPARAM)L"ch", "LB_SELECTSTRING(-1, \"ch\")");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
    sm(lb, LB_SELECTSTRING, (WPARAM)-1, (LPARAM)L"zz", "LB_SELECTSTRING(-1, \"zz\")");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
    print_events();
    line("LB_GETITEMHEIGHT(0) is the System font's tmHeight: %s",
         yesno(SendMessageW(lb, LB_GETITEMHEIGHT, 0, 0) == system_font_height()));
    sm(lb, LB_SETITEMHEIGHT, 0, 20, "LB_SETITEMHEIGHT(0, 20)");
    sm(lb, LB_GETITEMHEIGHT, 0, 0, "LB_GETITEMHEIGHT(0)");
    sm(lb, LB_GETITEMHEIGHT, 9, 0, "LB_GETITEMHEIGHT(9)");
    sm(lb, LB_SETTOPINDEX, 2, 0, "LB_SETTOPINDEX(2)");
    sm(lb, LB_GETTOPINDEX, 0, 0, "LB_GETTOPINDEX");
    sm(lb, LB_SETTOPINDEX, 9, 0, "LB_SETTOPINDEX(9)");
    sm(lb, LB_GETTOPINDEX, 0, 0, "LB_GETTOPINDEX");
    {
        RECT rc;

        SetRect(&rc, -7, -7, -7, -7);
        arm();
        r = SendMessageW(lb, LB_GETITEMRECT, 3, (LPARAM)&rc);
        line("LB_GETITEMRECT(3), top index 2: ret=%ld err=%s rect=%ld %ld %ld %ld", (long)r, le(), rc.left, rc.top,
             rc.right, rc.bottom);
        SetRect(&rc, -7, -7, -7, -7);
        arm();
        r = SendMessageW(lb, LB_GETITEMRECT, 0, (LPARAM)&rc);
        line("LB_GETITEMRECT(0), above the top: ret=%ld err=%s rect=%ld %ld %ld %ld", (long)r, le(), rc.left, rc.top,
             rc.right, rc.bottom);
        arm();
        r = SendMessageW(lb, LB_GETITEMRECT, 9, (LPARAM)&rc);
        line("LB_GETITEMRECT(9): ret=%ld err=%s", (long)r, le());
    }
    sm(lb, LB_DELETESTRING, 1, 0, "LB_DELETESTRING(1)");
    sm(lb, LB_DELETESTRING, 9, 0, "LB_DELETESTRING(9)");
    print_items(lb);
    sm(lb, LB_RESETCONTENT, 0, 0, "LB_RESETCONTENT");
    sm(lb, LB_GETCOUNT, 0, 0, "LB_GETCOUNT");
    print_events();
    close_parent(parent);
}

/* --- sort -------------------------------------------------------------- */

static void sec_sort(void)
{
    HWND parent, lb;

    parent = open_parent();
    lb = make_lb(parent, LBS_SORT | LBS_NOINTEGRALHEIGHT, 150, 100);
    line("CreateWindowExW(\"ListBox\", LBS_SORT): non-NULL %s", yesno(lb != NULL));
    if (lb == NULL) {
        close_parent(parent);
        return;
    }
    line("its style has LBS_NOTIFY %s, LBS_SORT %s", yesno(GetWindowLongW(lb, GWL_STYLE) & LBS_NOTIFY),
         yesno(GetWindowLongW(lb, GWL_STYLE) & LBS_SORT));
    add(lb, L"pear");
    add(lb, L"apple");
    add(lb, L"Banana");
    add(lb, L"cherry");
    add(lb, L"apricot");
    add(lb, L"10");
    add(lb, L"9");
    print_items(lb);
    sm(lb, LB_INSERTSTRING, 0, (LPARAM)L"zebra", "LB_INSERTSTRING(0, \"zebra\")");
    sm(lb, LB_INSERTSTRING, (WPARAM)-1, (LPARAM)L"aardvark", "LB_INSERTSTRING(-1, \"aardvark\")");
    print_items(lb);
    sm(lb, LB_FINDSTRING, (WPARAM)-1, (LPARAM)L"ap", "LB_FINDSTRING(-1, \"ap\")");
    sm(lb, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)L"banana", "LB_FINDSTRINGEXACT(-1, \"banana\")");
    print_events();
    close_parent(parent);
}

/* --- multi ------------------------------------------------------------- */

static void print_sel(HWND lb)
{
    int items[16];
    char buf[128];
    LRESULT n;
    DWORD e;
    int i, k = 0;

    for (i = 0; i < 16; i++) {
        items[i] = -7;
    }
    arm();
    n = SendMessageW(lb, LB_GETSELITEMS, 16, (LPARAM)items);
    e = GetLastError();
    buf[0] = 0;
    for (i = 0; i < (int)n && i < 16; i++) {
        k += sprintf(buf + k, " %d", items[i]);
    }
    line("  LB_GETSELCOUNT %ld, LB_GETSELITEMS ret=%ld err=%s:%s, LB_GETCARETINDEX %ld",
         (long)SendMessageW(lb, LB_GETSELCOUNT, 0, 0), (long)n, le_of(e), buf,
         (long)SendMessageW(lb, LB_GETCARETINDEX, 0, 0));
}

static HWND multi_box(HWND parent, DWORD style, const char *name)
{
    static const WCHAR *const names[] = { L"a", L"b", L"c", L"d", L"e", L"f" };
    HWND lb = make_lb(parent, style | LBS_NOINTEGRALHEIGHT, 150, 100);
    int i;

    line("CreateWindowExW(\"ListBox\", %s), 6 items: non-NULL %s", name, yesno(lb != NULL));
    for (i = 0; lb != NULL && i < 6; i++) {
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)names[i]);
    }
    return lb;
}

static void sec_multi(void)
{
    HWND parent, lb;
    int items[4];

    parent = open_parent();
    lb = multi_box(parent, LBS_NOTIFY | LBS_MULTIPLESEL, "LBS_NOTIFY | LBS_MULTIPLESEL");
    if (lb != NULL) {
        print_sel(lb);
        sm(lb, LB_SETSEL, TRUE, 1, "LB_SETSEL(TRUE, 1)");
        sm(lb, LB_SETSEL, TRUE, 3, "LB_SETSEL(TRUE, 3)");
        sm(lb, LB_GETSEL, 0, 3, "LB_GETSEL(3)");
        sm(lb, LB_GETSEL, 2, 0, "LB_GETSEL(2)");
        sm(lb, LB_GETSEL, 9, 0, "LB_GETSEL(9)");
        print_sel(lb);
        sm(lb, LB_SETSEL, TRUE, -1, "LB_SETSEL(TRUE, -1)");
        print_sel(lb);
        sm(lb, LB_SELITEMRANGE, FALSE, MAKELPARAM(0, 2), "LB_SELITEMRANGE(FALSE, 0 to 2)");
        print_sel(lb);
        sm(lb, LB_SETSEL, FALSE, 9, "LB_SETSEL(FALSE, 9)");
        sm(lb, LB_SETCURSEL, 1, 0, "LB_SETCURSEL(1)");
        sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
        sm(lb, LB_SETCARETINDEX, 4, FALSE, "LB_SETCARETINDEX(4)");
        sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
        sm(lb, LB_GETSELITEMS, 2, (LPARAM)items, "LB_GETSELITEMS(2 slots), 3 selected");
        print_events();
        DestroyWindow(lb);
    }
    lb = multi_box(parent, LBS_EXTENDEDSEL, "LBS_EXTENDEDSEL");
    if (lb != NULL) {
        sm(lb, LB_SELITEMRANGEEX, 1, 3, "LB_SELITEMRANGEEX(1, 3)");
        print_sel(lb);
        sm(lb, LB_SELITEMRANGEEX, 3, 2, "LB_SELITEMRANGEEX(3, 2)");
        print_sel(lb);
        sm(lb, LB_SETSEL, TRUE, 5, "LB_SETSEL(TRUE, 5)");
        print_sel(lb);
        DestroyWindow(lb);
    }
    lb = multi_box(parent, LBS_NOTIFY, "LBS_NOTIFY, single selection");
    if (lb != NULL) {
        sm(lb, LB_SETSEL, TRUE, 1, "LB_SETSEL(TRUE, 1)");
        sm(lb, LB_GETSELCOUNT, 0, 0, "LB_GETSELCOUNT");
        sm(lb, LB_GETSELITEMS, 4, (LPARAM)items, "LB_GETSELITEMS");
        sm(lb, LB_SELITEMRANGE, TRUE, MAKELPARAM(0, 2), "LB_SELITEMRANGE(TRUE, 0 to 2)");
        sm(lb, LB_SELITEMRANGEEX, 0, 2, "LB_SELITEMRANGEEX(0, 2)");
        sm(lb, LB_SETCURSEL, 2, 0, "LB_SETCURSEL(2)");
        sm(lb, LB_GETSEL, 2, 0, "LB_GETSEL(2)");
        sm(lb, LB_GETCARETINDEX, 0, 0, "LB_GETCARETINDEX");
        DestroyWindow(lb);
    }
    print_events();
    close_parent(parent);
}

/* --- ownerfix ---------------------------------------------------------- */

static void sec_ownerfix(void)
{
    HWND parent, lb;
    DWORD buf[2];
    RECT rc;
    LRESULT r;
    UINT h_in;

    parent = open_parent();
    measure_variable = 0;
    measure_fixed = 18;
    lb = make_lb(parent, LBS_OWNERDRAWFIXED | LBS_NOINTEGRALHEIGHT, 150, 100);
    line("CreateWindowExW(\"ListBox\", LBS_OWNERDRAWFIXED), the parent answering 18: non-NULL %s",
         yesno(lb != NULL));
    h_in = event_count > 0 ? events[0].height_in : 0;
    print_events();
    line("  WM_MEASUREITEM's itemHeight on entry is the System font's tmHeight: %s",
         yesno((LONG)h_in == system_font_height()));
    if (lb == NULL) {
        close_parent(parent);
        return;
    }
    sm(lb, LB_ADDSTRING, 0, 0x1111, "LB_ADDSTRING(0x1111)");
    sm(lb, LB_ADDSTRING, 0, 0x2222, "LB_ADDSTRING(0x2222)");
    sm(lb, LB_INSERTSTRING, 1, 0x3333, "LB_INSERTSTRING(1, 0x3333)");
    sm(lb, LB_GETITEMDATA, 1, 0, "LB_GETITEMDATA(1)");
    sm(lb, LB_GETTEXTLEN, 1, 0, "LB_GETTEXTLEN(1)");
    buf[0] = buf[1] = 0x77777777;
    arm();
    r = SendMessageW(lb, LB_GETTEXT, 1, (LPARAM)buf);
    line("LB_GETTEXT(1): ret=%ld err=%s buffer 0x%lX 0x%lX", (long)r, le(), buf[0], buf[1]);
    sm(lb, LB_FINDSTRING, (WPARAM)-1, 0x2222, "LB_FINDSTRING(-1, 0x2222)");
    sm(lb, LB_GETITEMHEIGHT, 0, 0, "LB_GETITEMHEIGHT(0)");
    SetRect(&rc, -7, -7, -7, -7);
    arm();
    r = SendMessageW(lb, LB_GETITEMRECT, 2, (LPARAM)&rc);
    line("LB_GETITEMRECT(2): ret=%ld err=%s rect=%ld %ld %ld %ld", (long)r, le(), rc.left, rc.top, rc.right,
         rc.bottom);
    print_events();
    InvalidateRect(lb, NULL, TRUE);
    UpdateWindow(lb);
    line("InvalidateRect and UpdateWindow:");
    print_events();
    sm(lb, LB_SETCURSEL, 1, 0, "LB_SETCURSEL(1)");
    UpdateWindow(lb);
    print_events();
    sm(lb, LB_SETCURSEL, 2, 0, "LB_SETCURSEL(2)");
    UpdateWindow(lb);
    print_events();
    sm(lb, LB_DELETESTRING, 0, 0, "LB_DELETESTRING(0)");
    UpdateWindow(lb);
    print_events();
    arm();
    r = DestroyWindow(lb);
    line("DestroyWindow(the list box): ret=%ld err=%s", (long)r, le());
    print_events();
    close_parent(parent);
}

/* --- ownervar ---------------------------------------------------------- */

static void sec_ownervar(void)
{
    static const WCHAR *const names[] = { L"one", L"two", L"three", L"four" };
    HWND parent, lb;
    RECT rc;
    LRESULT r;
    int i;
    char what[64];

    parent = open_parent();
    measure_variable = 1;
    lb = make_lb(parent, LBS_OWNERDRAWVARIABLE | LBS_HASSTRINGS | LBS_NOINTEGRALHEIGHT, 150, 100);
    line("CreateWindowExW(\"ListBox\", LBS_OWNERDRAWVARIABLE | LBS_HASSTRINGS), the parent answering 10 + 5 * itemID: "
         "non-NULL %s",
         yesno(lb != NULL));
    print_events();
    if (lb == NULL) {
        measure_variable = 0;
        close_parent(parent);
        return;
    }
    for (i = 0; i < 4; i++) {
        add(lb, names[i]);
        if (event_count > 0 && events[0].msg == WM_MEASUREITEM) {
            /* itemData of a string item is no fixed value: print whether
             * it is zero. */
            events[0].data = events[0].data != 0;
        }
        print_events();
    }
    sm(lb, LB_INSERTSTRING, 1, (LPARAM)L"inserted", "LB_INSERTSTRING(1, \"inserted\")");
    if (event_count > 0 && events[0].msg == WM_MEASUREITEM) {
        events[0].data = events[0].data != 0;
    }
    print_events();
    for (i = 0; i < 5; i++) {
        sprintf(what, "LB_GETITEMHEIGHT(%d)", i);
        sm(lb, LB_GETITEMHEIGHT, i, 0, what);
        SetRect(&rc, -7, -7, -7, -7);
        arm();
        r = SendMessageW(lb, LB_GETITEMRECT, i, (LPARAM)&rc);
        line("  LB_GETITEMRECT(%d): ret=%ld err=%s rect=%ld %ld %ld %ld", i, (long)r, le(), rc.left, rc.top,
             rc.right, rc.bottom);
    }
    sm(lb, LB_SETITEMHEIGHT, 2, 30, "LB_SETITEMHEIGHT(2, 30)");
    sm(lb, LB_GETITEMHEIGHT, 2, 0, "LB_GETITEMHEIGHT(2)");
    sm(lb, LB_SETITEMHEIGHT, 2, 300, "LB_SETITEMHEIGHT(2, 300)");
    sm(lb, LB_GETITEMHEIGHT, 2, 0, "LB_GETITEMHEIGHT(2)");
    SetRect(&rc, -7, -7, -7, -7);
    arm();
    r = SendMessageW(lb, LB_GETITEMRECT, 3, (LPARAM)&rc);
    line("LB_GETITEMRECT(3): ret=%ld err=%s rect=%ld %ld %ld %ld", (long)r, le(), rc.left, rc.top, rc.right,
         rc.bottom);
    print_events();
    DestroyWindow(lb);
    measure_variable = 0;
    print_events();
    close_parent(parent);
}

/* --- notify ------------------------------------------------------------ */

#define AT(x, y) MAKELPARAM((x), (y))

static void notify_box(HWND parent, DWORD style, const char *name)
{
    static const UINT msgs[] = { WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_LBUTTONUP };
    HWND lb;
    int i;

    lb = make_lb(parent, style | LBS_NOINTEGRALHEIGHT, 150, 100);
    line("CreateWindowExW(\"ListBox\", %s), 3 items 20 high: non-NULL %s", name, yesno(lb != NULL));
    if (lb == NULL) {
        return;
    }
    SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)L"one");
    SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)L"two");
    SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)L"three");
    SendMessageW(lb, LB_SETITEMHEIGHT, 0, 20);
    drain();
    reset_events();
    SetFocus(lb);
    drain();
    line("SetFocus(the list box): the focus %s", yesno(GetFocus() == lb));
    print_events();
    sm(lb, LB_SETCURSEL, 1, 0, "LB_SETCURSEL(1)");
    print_events();
    sm(lb, WM_KEYDOWN, VK_DOWN, 0, "WM_KEYDOWN(VK_DOWN)");
    sm(lb, LB_GETCURSEL, 0, 0, "LB_GETCURSEL");
    print_events();
    for (i = 0; i < 4; i++) {
        PostMessageW(lb, msgs[i], msgs[i] == WM_LBUTTONUP ? 0 : MK_LBUTTON, AT(5, 25));
    }
    drain();
    line("a double click on item 1 (down, up, WM_LBUTTONDBLCLK, up posted at 5,25): LB_GETCURSEL %ld",
         (long)SendMessageW(lb, LB_GETCURSEL, 0, 0));
    print_events();
    SetFocus(parent);
    drain();
    line("SetFocus(the parent):");
    print_events();
    DestroyWindow(lb);
    drain();
    reset_events();
}

static void sec_notify(void)
{
    HWND parent = open_parent();

    if (parent == NULL) {
        return;
    }
    line("the parent: foreground %s", yesno(GetForegroundWindow() == parent));
    notify_box(parent, LBS_NOTIFY, "LBS_NOTIFY");
    notify_box(parent, 0, "no LBS_NOTIFY");
    close_parent(parent);
}

/* --- keys -------------------------------------------------------------- */

static const WCHAR *const nato[] = {
    L"alpha", L"bravo", L"charlie", L"delta", L"dingo", L"foxtrot", L"golf", L"hotel", L"india", L"juliet",
    L"kilo", L"lima", L"mike", L"november", L"oscar", L"papa", L"quebec", L"romeo", L"sierra", L"tango"
};

static HWND key_box(HWND parent, DWORD style)
{
    HWND lb = make_lb(parent, style | LBS_NOINTEGRALHEIGHT, 150, 100);
    int i;

    if (lb == NULL) {
        return NULL;
    }
    for (i = 0; i < 20; i++) {
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)nato[i]);
    }
    SendMessageW(lb, LB_SETITEMHEIGHT, 0, 20);
    SetFocus(lb);
    drain();
    reset_events();
    return lb;
}

static int selchanges(void)
{
    int i, n = 0;

    for (i = 0; i < event_count; i++) {
        n += events[i].msg == WM_COMMAND && events[i].code == LBN_SELCHANGE;
    }
    reset_events();
    return n;
}

static void key(HWND lb, UINT vk, const char *name)
{
    LRESULT r;
    DWORD e;

    arm();
    r = SendMessageW(lb, WM_KEYDOWN, vk, 0);
    e = GetLastError();
    line("%s: ret=%ld err=%s; caret %ld, selection %ld, top %ld, LBN_SELCHANGE %d", name, (long)r, le_of(e),
         (long)SendMessageW(lb, LB_GETCARETINDEX, 0, 0), (long)SendMessageW(lb, LB_GETCURSEL, 0, 0),
         (long)SendMessageW(lb, LB_GETTOPINDEX, 0, 0), selchanges());
}

static void type_ahead(HWND parent, int from, WCHAR c)
{
    HWND lb = key_box(parent, LBS_NOTIFY);
    LRESULT r;
    DWORD e;

    if (lb == NULL) {
        return;
    }
    SendMessageW(lb, LB_SETCURSEL, from, 0);
    reset_events();
    arm();
    r = SendMessageW(lb, WM_CHAR, c, 0);
    e = GetLastError();
    line("a fresh list box at item %d, WM_CHAR '%c': ret=%ld err=%s; selection %ld, LBN_SELCHANGE %d", from, (char)c,
         (long)r, le_of(e), (long)SendMessageW(lb, LB_GETCURSEL, 0, 0), selchanges());
    DestroyWindow(lb);
    drain();
}

static void sec_keys(void)
{
    HWND parent, lb;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    lb = key_box(parent, LBS_NOTIFY);
    line("LBS_NOTIFY, 20 items 20 high, 5 showing: non-NULL %s, the focus %s", yesno(lb != NULL),
         yesno(lb != NULL && GetFocus() == lb));
    if (lb != NULL) {
        key(lb, VK_DOWN, "Down, no selection");
        key(lb, VK_DOWN, "Down");
        key(lb, VK_UP, "Up");
        key(lb, VK_UP, "Up");
        key(lb, VK_UP, "Up at the first item");
        key(lb, VK_END, "End");
        key(lb, VK_DOWN, "Down at the last item");
        key(lb, VK_HOME, "Home");
        key(lb, VK_NEXT, "PgDn");
        key(lb, VK_NEXT, "PgDn");
        key(lb, VK_PRIOR, "PgUp");
        key(lb, VK_PRIOR, "PgUp");
        key(lb, VK_PRIOR, "PgUp at the first item");
        key(lb, VK_RIGHT, "Right");
        key(lb, VK_LEFT, "Left");
        DestroyWindow(lb);
        drain();
    }
    type_ahead(parent, 0, L'd');
    type_ahead(parent, 3, L'd');
    type_ahead(parent, 4, L'D');
    type_ahead(parent, 4, L'z');
    lb = key_box(parent, LBS_NOTIFY | LBS_MULTIPLESEL);
    line("LBS_NOTIFY | LBS_MULTIPLESEL: non-NULL %s", yesno(lb != NULL));
    if (lb != NULL) {
        key(lb, VK_DOWN, "Down");
        key(lb, VK_DOWN, "Down");
        key(lb, VK_SPACE, "Space");
        line("  LB_GETSELCOUNT %ld, LB_GETSEL(2) %ld", (long)SendMessageW(lb, LB_GETSELCOUNT, 0, 0),
             (long)SendMessageW(lb, LB_GETSEL, 2, 0));
        key(lb, VK_SPACE, "Space");
        line("  LB_GETSELCOUNT %ld", (long)SendMessageW(lb, LB_GETSELCOUNT, 0, 0));
        DestroyWindow(lb);
        drain();
    }
    close_parent(parent);
}

/* --- dir --------------------------------------------------------------- */

static const char *const dir_files[] = { "f2klbdir\\a.txt", "f2klbdir\\b.txt", "f2klbdir\\c.dat",
                                         "f2klbdir\\noext" };

static void dir_remove(void)
{
    int i;

    for (i = 0; i < 4; i++) {
        DeleteFileA(dir_files[i]);
    }
    RemoveDirectoryA("f2klbdir\\sub");
    RemoveDirectoryA("f2klbdir");
}

static int dir_make(void)
{
    HANDLE f;
    int i, ok;

    dir_remove();
    ok = CreateDirectoryA("f2klbdir", NULL) && CreateDirectoryA("f2klbdir\\sub", NULL);
    for (i = 0; i < 4; i++) {
        f = CreateFileA(dir_files[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        ok = ok && f != INVALID_HANDLE_VALUE;
        if (f != INVALID_HANDLE_VALUE) {
            CloseHandle(f);
        }
    }
    return ok;
}

/* Whether the current directory is f2klbdir's (it ends "\f2klbdir"),
 * and back to `home`. */
static void check_cwd(const char *home)
{
    char cwd[MAX_PATH];
    int n;

    cwd[0] = 0;
    n = (int)GetCurrentDirectoryA(MAX_PATH, cwd);
    line("  the current directory is f2klbdir now: %s; unchanged: %s",
         yesno(n >= 9 && _stricmp(cwd + n - 9, "\\f2klbdir") == 0), yesno(_stricmp(cwd, home) == 0));
    SetCurrentDirectoryA(home);
}

static void dir_lb(HWND lb, UINT attr, const char *spec, const char *what)
{
    LRESULT r;

    SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    arm();
    r = SendMessageA(lb, LB_DIR, attr, (LPARAM)spec);
    line("LB_DIR(%s, \"%s\"): ret=%ld err=%s", what, spec, (long)r, le());
    print_items(lb);
}

static void select_ex(HWND parent, HWND lb, int index, int wide)
{
    char a[64];
    WCHAR w[64];
    WCHAR t[64];
    BOOL r;

    t[0] = 0;
    SendMessageW(lb, LB_GETTEXT, index, (LPARAM)t);
    SendMessageW(lb, LB_SETCURSEL, index, 0);
    strcpy(a, "untouched");
    lstrcpyW(w, L"untouched");
    arm();
    if (wide) {
        r = DlgDirSelectExW(parent, w, 64, LB_ID);
        line("DlgDirSelectExW, \"%s\" selected: ret=%d err=%s buffer \"%s\"", index < 0 ? "none" : ws(t), r, le(),
             ws(w));
    } else {
        r = DlgDirSelectExA(parent, a, 64, LB_ID);
        line("DlgDirSelectExA, \"%s\" selected: ret=%d err=%s buffer \"%s\"", index < 0 ? "none" : ws(t), r, le(), a);
    }
}

static int find(HWND lb, const WCHAR *s)
{
    return (int)SendMessageW(lb, LB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)s);
}

static void sec_dir(void)
{
    HWND parent, lb;
    char home[MAX_PATH];
    char spec[64];
    WCHAR wspec[64];
    int r;

    home[0] = 0;
    GetCurrentDirectoryA(MAX_PATH, home);
    line("f2klbdir with a.txt, b.txt, c.dat, noext and sub made: %s", yesno(dir_make()));
    parent = open_parent();
    lb = make_lb(parent, LBS_SORT | LBS_NOINTEGRALHEIGHT, 150, 100);
    line("CreateWindowExW(\"ListBox\", LBS_SORT): non-NULL %s", yesno(lb != NULL));
    if (lb != NULL) {
        dir_lb(lb, DDL_READWRITE, "f2klbdir\\*.txt", "DDL_READWRITE");
        dir_lb(lb, DDL_READWRITE, "f2klbdir\\*", "DDL_READWRITE");
        dir_lb(lb, DDL_DIRECTORY, "f2klbdir\\*", "DDL_DIRECTORY");
        dir_lb(lb, DDL_DIRECTORY | DDL_EXCLUSIVE, "f2klbdir\\*", "DDL_DIRECTORY | DDL_EXCLUSIVE");
        dir_lb(lb, DDL_DIRECTORY, "f2klbdir\\*.txt", "DDL_DIRECTORY");
        dir_lb(lb, DDL_READWRITE, "f2knone\\*.*", "DDL_READWRITE, a missing directory");
        dir_lb(lb, DDL_READWRITE, "f2klbdir\\*.zzz", "DDL_READWRITE, nothing matching");

        SendMessageW(lb, LB_RESETCONTENT, 0, 0);
        strcpy(spec, "f2klbdir\\*.txt");
        arm();
        r = DlgDirListA(parent, spec, LB_ID, 0, DDL_DIRECTORY);
        line("DlgDirListA(\"f2klbdir\\*.txt\", DDL_DIRECTORY): ret=%d err=%s buffer after \"%s\"", r, le(), spec);
        print_items(lb);
        select_ex(parent, lb, find(lb, L"a.txt"), 0);
        select_ex(parent, lb, find(lb, L"[sub]"), 0);
        select_ex(parent, lb, find(lb, L"[..]"), 0);
        check_cwd(home);

        SendMessageW(lb, LB_RESETCONTENT, 0, 0);
        lstrcpyW(wspec, L"f2klbdir\\*");
        arm();
        r = DlgDirListW(parent, wspec, LB_ID, 0, DDL_READWRITE);
        line("DlgDirListW(\"f2klbdir\\*\", DDL_READWRITE): ret=%d err=%s buffer after \"%s\"", r, le(), ws(wspec));
        print_items(lb);
        select_ex(parent, lb, find(lb, L"noext"), 1);
        select_ex(parent, lb, find(lb, L"c.dat"), 1);
        select_ex(parent, lb, -1, 1);
        select_ex(parent, lb, -1, 0);
        check_cwd(home);

        strcpy(spec, "f2knone\\*.*");
        arm();
        r = DlgDirListA(parent, spec, LB_ID, 0, DDL_READWRITE);
        line("DlgDirListA(\"f2knone\\*.*\"), a missing directory: ret=%d err=%s buffer after \"%s\"", r, le(), spec);
        check_cwd(home);
        strcpy(spec, "f2klbdir\\*.txt");
        arm();
        r = DlgDirListA(parent, spec, 999, 0, DDL_READWRITE);
        line("DlgDirListA(\"f2klbdir\\*.txt\"), no control 999: ret=%d err=%s", r, le());
        check_cwd(home);
    }
    close_parent(parent);
    dir_remove();
    line("f2klbdir removed: %s", yesno(GetFileAttributesA("f2klbdir") == INVALID_FILE_ATTRIBUTES));
}

/* --- info -------------------------------------------------------------- */

static void sec_info(void)
{
    HWND parent, lb;
    getlistboxinfo_t get;
    DWORD r;

    get = (getlistboxinfo_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetListBoxInfo");
    line("GetListBoxInfo exported: %s", yesno(get != NULL));
    parent = open_parent();
    lb = make_lb(parent, LBS_NOINTEGRALHEIGHT, 150, 100);
    line("a list box, 100 high: non-NULL %s", yesno(lb != NULL));
    if (lb != NULL) {
        SendMessageW(lb, LB_SETITEMHEIGHT, 0, 20);
        sm(lb, LB_GETLISTBOXINFO, 0, 0, "LB_GETLISTBOXINFO, items 20 high");
        if (get != NULL) {
            arm();
            r = get(lb);
            line("GetListBoxInfo(it): ret=%lu err=%s", r, le());
            arm();
            r = get(parent);
            line("GetListBoxInfo(the parent, no list box): ret=%lu err=%s", r, le());
            arm();
            r = get(NULL);
            line("GetListBoxInfo(NULL): ret=%lu err=%s", r, le());
        }
        SendMessageW(lb, LB_SETITEMHEIGHT, 0, 30);
        sm(lb, LB_GETLISTBOXINFO, 0, 0, "LB_GETLISTBOXINFO, items 30 high");
        sm(lb, LB_INITSTORAGE, 100, 2000, "LB_INITSTORAGE(100 items, 2000 bytes)");
        sm(lb, LB_GETCOUNT, 0, 0, "LB_GETCOUNT");
        sm(lb, LB_INITSTORAGE, 0x10000000, 0x7FFFFFF0, "LB_INITSTORAGE(0x10000000 items, 0x7FFFFFF0 bytes)");
        sm(lb, LB_ADDSTRING, 0, (LPARAM)L"after", "LB_ADDSTRING after it");
    }
    close_parent(parent);
}

/* --- dialog ------------------------------------------------------------ */

static WORD *put_word(WORD *p, WORD w)
{
    *p++ = w;
    return p;
}

static WORD *put_string(WORD *p, const WCHAR *s)
{
    do {
        *p++ = *s;
    } while (*s++ != 0);
    return p;
}

static WORD *align4(WORD *p, const WORD *base)
{
    if (((p - base) & 1) != 0) {
        *p++ = 0;
    }
    return p;
}

/* An item: x, y, cx, cy, id, style, and the class as the atom or a name. */
static WORD *put_item(WORD *p, const WORD *base, short x, short y, short cx, short cy, WORD id, DWORD style,
                      WORD atom, const WCHAR *name)
{
    DLGITEMTEMPLATE *it;

    p = align4(p, base);
    it = (DLGITEMTEMPLATE *)p;
    it->style = style;
    it->dwExtendedStyle = 0;
    it->x = x;
    it->y = y;
    it->cx = cx;
    it->cy = cy;
    it->id = id;
    p = (WORD *)(it + 1);
    if (name == NULL) {
        p = put_word(p, 0xFFFF);
        p = put_word(p, atom);
    } else {
        p = put_string(p, name);
    }
    p = put_string(p, L"");
    p = put_word(p, 0);
    return p;
}

static BOOL CALLBACK dialog_proc(HWND dlg, UINT msg, WPARAM wparam, LPARAM lparam)
{
    (void)wparam;
    (void)lparam;
    if (msg == WM_INITDIALOG) {
        SendDlgItemMessageW(dlg, 401, LB_ADDSTRING, 0, (LPARAM)L"by atom");
        SendDlgItemMessageW(dlg, 402, LB_ADDSTRING, 0, (LPARAM)L"by name");
        SendDlgItemMessageW(dlg, 402, LB_ADDSTRING, 0, (LPARAM)L"second");
        return TRUE;
    }
    return FALSE;
}

static void sec_dialog(void)
{
    static DWORD tmpl_dwords[128];
    WORD *tmpl = (WORD *)tmpl_dwords;
    DLGTEMPLATE *d;
    WORD *p;
    HWND dlg, item;
    int id;
    WCHAR t[64];

    ZeroMemory(tmpl_dwords, sizeof tmpl_dwords);
    d = (DLGTEMPLATE *)tmpl;
    d->style = WS_POPUP | WS_CAPTION | WS_VISIBLE | DS_MODALFRAME;
    d->cdit = 2;
    d->x = 10;
    d->y = 10;
    d->cx = 160;
    d->cy = 100;
    p = (WORD *)(d + 1);
    p = put_word(p, 0);
    p = put_word(p, 0);
    p = put_string(p, L"F2K list box dialog");
    p = put_item(p, tmpl, 5, 5, 70, 60, 401, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_SORT,
                 0x0083, NULL);
    p = put_item(p, tmpl, 80, 5, 70, 60, 402, WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY, 0, L"ListBox");
    /* No last error prints: in a process of its own this is its first
     * window, which leaves 183 on Windows 2000 (guiwin's err183pop). */
    dlg = CreateDialogIndirectParamW(instance(), d, NULL, (DLGPROC)dialog_proc, 0);
    line("CreateDialogIndirectParamW, a list box by atom 0x0083 and one by name: non-NULL %s", yesno(dlg != NULL));
    if (dlg == NULL) {
        return;
    }
    for (id = 401; id <= 402; id++) {
        item = GetDlgItem(dlg, id);
        t[0] = 0;
        SendMessageW(item, LB_GETTEXT, 0, (LPARAM)t);
        line("  item %d: found %s, class %s, WM_GETDLGCODE 0x%lX, LB_GETCOUNT %ld, first \"%s\"", id,
             yesno(item != NULL), class_of(item), (unsigned long)SendMessageW(item, WM_GETDLGCODE, 0, 0),
             (long)SendMessageW(item, LB_GETCOUNT, 0, 0), ws(t));
    }
    arm();
    id = DestroyWindow(dlg);
    line("DestroyWindow(the dialog): ret=%d err=%s", id, le());
    drain();
}

static const section_t sections[] = {
    { "basic", sec_basic, F2KT_ALWAYS },
    { "sort", sec_sort, F2KT_ALWAYS },
    { "multi", sec_multi, F2KT_ALWAYS },
    { "ownerfix", sec_ownerfix, F2KT_ALWAYS },
    { "ownervar", sec_ownervar, F2KT_ALWAYS },
    { "notify", sec_notify, F2KT_ALWAYS },
    { "keys", sec_keys, F2KT_ALWAYS },
    { "dir", sec_dir, F2KT_ALWAYS },
    { "info", sec_info, F2KT_ALWAYS },
    { "dialog", sec_dialog, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("listbox", sections, argc, argv);
}
