/*
 * combobox - user32's built-in ComboBox control as a program drives it
 * by messages and keys: CBS_SIMPLE, CBS_DROPDOWN and CBS_DROPDOWNLIST,
 * their children (the Edit and the ComboLBox list, by class name) and
 * GetComboBoxInfo; the CB_* item messages that mirror the list box's;
 * CB_SHOWDROPDOWN, CB_GETDROPPEDSTATE and CB_GETDROPPEDCONTROLRECT;
 * CB_SETEDITSEL, CB_GETEDITSEL and CB_LIMITTEXT; the CBN_*
 * notifications the parent receives, in order; DlgDirListComboBoxA/W
 * and DlgDirSelectComboBoxExA/W over a directory the program makes
 * itself; and combo boxes in a dialog built from a template in memory.
 *
 * The combo boxes are children of a visible top-level window of the
 * fixture's own class, whose procedure records the WM_COMMAND
 * notifications it receives (the id, the code, whether lParam is the
 * combo box); the records print after the calls, never from inside the
 * procedure. Keys are WM_KEYDOWN sent to the combo box and WM_CHAR sent
 * to its edit, no key is pressed. Each combo box is 150 wide and made
 * 120 high, the height its list drops to.
 *
 * Nothing printed depends on a font: no item or field height prints (the
 * list's item height only against the System font's tmHeight), and
 * rectangles print as relations to the combo box's own. Conventions as
 * the other fixtures on f2kt.h: no handle value or address prints; a
 * window prints by what it is ("the combo", "its Edit child", "NULL"),
 * every call under observation is armed with the last-error sentinel
 * and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   a combo box of each style: its class name and style, its
 *            child windows' classes, WM_GETDLGCODE, GetComboBoxInfo
 *            (hwndItem, hwndList's class and parent, the list shown,
 *            stateButton), and GetComboBoxInfo's errors
 *   items    CB_ADDSTRING, CB_INSERTSTRING, CB_DELETESTRING,
 *            CB_GETCOUNT, CB_GETLBTEXT(LEN), CB_FINDSTRING(EXACT),
 *            CB_SETCURSEL, CB_GETCURSEL, CB_SELECTSTRING, item data and
 *            the error returns on a CBS_DROPDOWN combo box, the edit's
 *            text after each selection; WM_GETTEXT of a
 *            CBS_DROPDOWNLIST one; CBS_SORT
 *   drop     CB_SHOWDROPDOWN TRUE and FALSE on each style: the return,
 *            CB_GETDROPPEDSTATE, the list shown, the notifications;
 *            CB_GETDROPPEDCONTROLRECT against the combo box's rectangle
 *   edit     CB_SETEDITSEL and CB_GETEDITSEL on a CBS_DROPDOWN combo
 *            box and a CBS_DROPDOWNLIST one; CB_LIMITTEXT and text
 *            typed past the limit
 *   notify   the CBN_* notifications in order: SetFocus to and from a
 *            CBS_DROPDOWNLIST combo box, Down, F4, Down and Enter, F4
 *            and Esc; SetFocus and typing into a CBS_DROPDOWN one
 *   dir      DlgDirListComboBoxA/W over f2kcbdir (made in the current
 *            directory with a.txt, b.txt and the subdirectory sub, and
 *            removed at the end): the items, the path buffer after, the
 *            current directory; DlgDirSelectComboBoxExA/W on a file and
 *            a subdirectory
 *   dialog   a dialog made with CreateDialogIndirectParamW from a
 *            template in memory holding a CBS_DROPDOWNLIST combo box by
 *            the class atom 0x0085 and a CBS_DROPDOWN one by the name
 *            "ComboBox": the dialog made, each item's class name, its
 *            list's class, WM_GETDLGCODE, the strings WM_INITDIALOG
 *            added
 *
 * GetComboBoxInfo is found with GetProcAddress: MSVC 6's headers and
 * import library predate it.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat combobox):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% combobox.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

#define PARENT_CLASS L"F2KComboBoxParent"
#define CB_ID 500

/* COMBOBOXINFO, which MSVC 6's headers predate. */
typedef struct {
    DWORD cbSize;
    RECT rcItem;
    RECT rcButton;
    DWORD stateButton;
    HWND hwndCombo;
    HWND hwndItem;
    HWND hwndList;
} combo_info_t;

typedef BOOL(WINAPI *getcomboboxinfo_t)(HWND, combo_info_t *);

static getcomboboxinfo_t get_info;

/* --- What the parent records --------------------------------------- */

#define MAX_EVENTS 64

typedef struct {
    int id;
    int code;
    int from_control;
} event_t;

static event_t events[MAX_EVENTS];
static int event_count;
static int events_lost;

static void reset_events(void)
{
    event_count = 0;
    events_lost = 0;
}

static LRESULT CALLBACK parent_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_COMMAND && lparam != 0) {
        if (event_count < MAX_EVENTS) {
            events[event_count].id = LOWORD(wparam);
            events[event_count].code = (short)HIWORD(wparam);
            events[event_count].from_control = GetDlgItem(hwnd, LOWORD(wparam)) == (HWND)lparam;
            event_count++;
        } else {
            events_lost++;
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static const char *cbn_name(int code)
{
    static char buf[16];

    switch (code) {
    case CBN_ERRSPACE: return "CBN_ERRSPACE";
    case CBN_SELCHANGE: return "CBN_SELCHANGE";
    case CBN_DBLCLK: return "CBN_DBLCLK";
    case CBN_SETFOCUS: return "CBN_SETFOCUS";
    case CBN_KILLFOCUS: return "CBN_KILLFOCUS";
    case CBN_EDITCHANGE: return "CBN_EDITCHANGE";
    case CBN_EDITUPDATE: return "CBN_EDITUPDATE";
    case CBN_DROPDOWN: return "CBN_DROPDOWN";
    case CBN_CLOSEUP: return "CBN_CLOSEUP";
    case CBN_SELENDOK: return "CBN_SELENDOK";
    case CBN_SELENDCANCEL: return "CBN_SELENDCANCEL";
    }
    sprintf(buf, "code %d", code);
    return buf;
}

/* The notifications since the last print, on one line, then none. */
static void print_events(void)
{
    char buf[900];
    int i, k = 0;

    buf[0] = 0;
    for (i = 0; i < event_count && k < (int)sizeof buf - 40; i++) {
        k += sprintf(buf + k, " %s%s%s", cbn_name(events[i].code), events[i].id == CB_ID ? "" : "(other id)",
                     events[i].from_control ? "" : "(other lParam)");
    }
    line("  notifications:%s%s", event_count ? buf : " none", events_lost ? " (and more)" : "");
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
    h = CreateWindowExW(0, PARENT_CLASS, L"F2K combobox", WS_POPUP | WS_BORDER | WS_VISIBLE, 40, 40, 322, 322,
                        NULL, NULL, instance(), NULL);
    line("the parent: made %s", yesno(registered && h != NULL));
    if (h != NULL) {
        SetForegroundWindow(h);
        drain();
    }
    get_info = (getcomboboxinfo_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetComboBoxInfo");
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

static const char *style_name(DWORD style)
{
    switch (style & 3) {
    case CBS_SIMPLE: return "CBS_SIMPLE";
    case CBS_DROPDOWN: return "CBS_DROPDOWN";
    }
    return "CBS_DROPDOWNLIST";
}

/* A combo box of the parent, id CB_ID, 150x120. */
static HWND make_cb(HWND parent, DWORD style)
{
    HWND h = CreateWindowExW(0, L"ComboBox", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | style, 10, 10, 150, 120,
                             parent, (HMENU)CB_ID, instance(), NULL);

    drain();
    reset_events();
    return h;
}

static LRESULT sm(HWND h, UINT msg, WPARAM w, LPARAM l, const char *what)
{
    LRESULT r;

    arm();
    r = SendMessageW(h, msg, w, l);
    line("%s: ret=%ld err=%s", what, (long)r, le());
    return r;
}

static const char *class_of(HWND h)
{
    static WCHAR b[2][64];
    static int next;
    WCHAR *s = b[next++ & 1];

    s[0] = 0;
    if (h != NULL) {
        GetClassNameW(h, s, 64);
    }
    return ws(s);
}

/* A window as printed against the combo box it belongs to. */
static const char *what_window(HWND h, HWND combo, HWND parent)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == combo) {
        return "the combo";
    }
    if (h == parent) {
        return "the parent";
    }
    if (h == GetDesktopWindow()) {
        return "the desktop";
    }
    if (GetParent(h) == combo) {
        return "a child of the combo";
    }
    return "another window";
}

static const char *text_of(HWND h)
{
    static WCHAR t[2][64];
    static int next;
    WCHAR *s = t[next++ & 1];

    s[0] = 0;
    SendMessageW(h, WM_GETTEXT, 64, (LPARAM)s);
    return ws(s);
}

/* The items' texts in order, on one line. */
static void print_items(HWND h)
{
    char buf[512];
    WCHAR t[64];
    int n, i, k = 0;

    n = (int)SendMessageW(h, CB_GETCOUNT, 0, 0);
    buf[0] = 0;
    for (i = 0; i < n && k < (int)sizeof buf - 80; i++) {
        t[0] = 0;
        if (SendMessageW(h, CB_GETLBTEXTLEN, i, 0) < 60) {
            SendMessageW(h, CB_GETLBTEXT, i, (LPARAM)t);
        }
        k += sprintf(buf + k, "%s\"%s\"", i ? " " : "", ws(t));
    }
    line("  %d items: %s", n, buf);
}

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

/* --- create ------------------------------------------------------------ */

static void describe(HWND parent, DWORD style)
{
    HWND cb, child;
    combo_info_t ci;
    BOOL r;
    int n = 0;
    char kids[200];
    int k = 0;

    cb = make_cb(parent, style);
    line("CreateWindowExW(\"ComboBox\", %s): non-NULL %s, class %s, style low bits 0x%lX", style_name(style),
         yesno(cb != NULL), class_of(cb), (unsigned long)(GetWindowLongW(cb, GWL_STYLE) & 0xFFFF));
    if (cb == NULL) {
        return;
    }
    kids[0] = 0;
    for (child = GetWindow(cb, GW_CHILD); child != NULL && n < 8; child = GetWindow(child, GW_HWNDNEXT)) {
        k += sprintf(kids + k, " %s", class_of(child));
        n++;
    }
    line("  its children:%s", n ? kids : " none");
    line("  WM_GETDLGCODE: 0x%lX", (unsigned long)SendMessageW(cb, WM_GETDLGCODE, 0, 0));
    if (get_info == NULL) {
        line("  GetComboBoxInfo: not exported");
    } else {
        ZeroMemory(&ci, sizeof ci);
        ci.cbSize = sizeof ci;
        arm();
        r = get_info(cb, &ci);
        line("  GetComboBoxInfo: ret=%d err=%s hwndCombo %s, hwndItem %s (%s)", r, le(),
             what_window(ci.hwndCombo, cb, parent), what_window(ci.hwndItem, cb, parent), class_of(ci.hwndItem));
        line("    hwndList: class %s, parent %s, owner %s, shown %s", class_of(ci.hwndList),
             what_window(GetParent(ci.hwndList), cb, parent),
             what_window(GetWindow(ci.hwndList, GW_OWNER), cb, parent), yesno(IsWindowVisible(ci.hwndList)));
        line("    stateButton 0x%lX, rcButton empty %s, rcItem inside the client %s", ci.stateButton,
             yesno(IsRectEmpty(&ci.rcButton)), yesno(ci.rcItem.left >= 0 && ci.rcItem.top >= 0 &&
                                                     ci.rcItem.right <= 150 && ci.rcItem.right > ci.rcItem.left));
        line("    the list's item height is the System font's tmHeight: %s",
             yesno(SendMessageW(cb, CB_GETITEMHEIGHT, 0, 0) == system_font_height()));
    }
    DestroyWindow(cb);
    drain();
}

static void sec_create(void)
{
    HWND parent;
    combo_info_t ci;
    BOOL r;

    parent = open_parent();
    line("GetComboBoxInfo exported: %s", yesno(get_info != NULL));
    if (parent == NULL) {
        return;
    }
    describe(parent, CBS_SIMPLE);
    describe(parent, CBS_DROPDOWN);
    describe(parent, CBS_DROPDOWNLIST);
    if (get_info != NULL) {
        HWND cb = make_cb(parent, CBS_DROPDOWN);

        ZeroMemory(&ci, sizeof ci);
        arm();
        r = get_info(cb, &ci);
        line("GetComboBoxInfo, cbSize 0: ret=%d err=%s", r, le());
        ci.cbSize = sizeof ci;
        arm();
        r = get_info(parent, &ci);
        line("GetComboBoxInfo(the parent, no combo box): ret=%d err=%s", r, le());
        arm();
        r = get_info(NULL, &ci);
        line("GetComboBoxInfo(NULL): ret=%d err=%s", r, le());
        DestroyWindow(cb);
    }
    close_parent(parent);
}

/* --- items ------------------------------------------------------------- */

static void sec_items(void)
{
    HWND parent, cb;
    WCHAR t[64];
    char a[64];
    LRESULT r;
    DWORD e;

    parent = open_parent();
    cb = make_cb(parent, CBS_DROPDOWN);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWN): non-NULL %s", yesno(cb != NULL));
    if (cb == NULL) {
        close_parent(parent);
        return;
    }
    sm(cb, CB_GETCOUNT, 0, 0, "CB_GETCOUNT, empty");
    sm(cb, CB_GETCURSEL, 0, 0, "CB_GETCURSEL, empty");
    sm(cb, CB_ADDSTRING, 0, (LPARAM)L"pear", "CB_ADDSTRING(\"pear\")");
    sm(cb, CB_ADDSTRING, 0, (LPARAM)L"apple", "CB_ADDSTRING(\"apple\")");
    sm(cb, CB_INSERTSTRING, 1, (LPARAM)L"banana", "CB_INSERTSTRING(1, \"banana\")");
    sm(cb, CB_INSERTSTRING, (WPARAM)-1, (LPARAM)L"Blueberry", "CB_INSERTSTRING(-1, \"Blueberry\")");
    sm(cb, CB_INSERTSTRING, 9, (LPARAM)L"fig", "CB_INSERTSTRING(9, \"fig\"), past the end");
    print_items(cb);
    sm(cb, CB_GETLBTEXTLEN, 1, 0, "CB_GETLBTEXTLEN(1)");
    t[0] = 0;
    arm();
    r = SendMessageW(cb, CB_GETLBTEXT, 1, (LPARAM)t);
    line("CB_GETLBTEXT(1), SendMessageW: ret=%ld err=%s text \"%s\"", (long)r, le(), ws(t));
    a[0] = 0;
    arm();
    r = SendMessageA(cb, CB_GETLBTEXT, 3, (LPARAM)a);
    line("CB_GETLBTEXT(3), SendMessageA: ret=%ld err=%s text \"%s\"", (long)r, le(), a);
    sm(cb, CB_GETLBTEXT, 9, (LPARAM)t, "CB_GETLBTEXT(9), no such item");
    sm(cb, CB_GETLBTEXTLEN, 9, 0, "CB_GETLBTEXTLEN(9)");
    sm(cb, CB_FINDSTRING, (WPARAM)-1, (LPARAM)L"b", "CB_FINDSTRING(-1, \"b\")");
    sm(cb, CB_FINDSTRING, 1, (LPARAM)L"b", "CB_FINDSTRING(1, \"b\")");
    sm(cb, CB_FINDSTRING, (WPARAM)-1, (LPARAM)L"kiwi", "CB_FINDSTRING(-1, \"kiwi\")");
    sm(cb, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)L"APPLE", "CB_FINDSTRINGEXACT(-1, \"APPLE\")");
    sm(cb, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)L"app", "CB_FINDSTRINGEXACT(-1, \"app\")");
    sm(cb, CB_SETITEMDATA, 2, 0x55, "CB_SETITEMDATA(2, 0x55)");
    sm(cb, CB_GETITEMDATA, 2, 0, "CB_GETITEMDATA(2)");
    sm(cb, CB_GETITEMDATA, 9, 0, "CB_GETITEMDATA(9)");
    sm(cb, CB_SETCURSEL, 2, 0, "CB_SETCURSEL(2)");
    line("  CB_GETCURSEL %ld, the edit's text \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
    sm(cb, CB_SETCURSEL, 9, 0, "CB_SETCURSEL(9)");
    line("  CB_GETCURSEL %ld, the edit's text \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
    sm(cb, CB_SETCURSEL, (WPARAM)-1, 0, "CB_SETCURSEL(-1)");
    line("  CB_GETCURSEL %ld, the edit's text \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
    sm(cb, CB_SELECTSTRING, (WPARAM)-1, (LPARAM)L"pe", "CB_SELECTSTRING(-1, \"pe\")");
    line("  CB_GETCURSEL %ld, the edit's text \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
    sm(cb, CB_SELECTSTRING, (WPARAM)-1, (LPARAM)L"zz", "CB_SELECTSTRING(-1, \"zz\")");
    line("  CB_GETCURSEL %ld, the edit's text \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
    arm();
    r = SendMessageW(cb, WM_SETTEXT, 0, (LPARAM)L"typed");
    e = GetLastError();
    line("WM_SETTEXT(\"typed\"): ret=%ld err=%s; CB_GETCURSEL %ld, the edit's text \"%s\"", (long)r, le_of(e),
         (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
    sm(cb, CB_DELETESTRING, 0, 0, "CB_DELETESTRING(0)");
    sm(cb, CB_DELETESTRING, 9, 0, "CB_DELETESTRING(9)");
    print_items(cb);
    sm(cb, CB_RESETCONTENT, 0, 0, "CB_RESETCONTENT");
    line("  CB_GETCOUNT %ld, the edit's text \"%s\"", (long)SendMessageW(cb, CB_GETCOUNT, 0, 0), text_of(cb));
    print_events();
    DestroyWindow(cb);
    drain();

    cb = make_cb(parent, CBS_DROPDOWNLIST | CBS_SORT);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWNLIST | CBS_SORT): non-NULL %s", yesno(cb != NULL));
    if (cb != NULL) {
        sm(cb, CB_ADDSTRING, 0, (LPARAM)L"pear", "CB_ADDSTRING(\"pear\")");
        sm(cb, CB_ADDSTRING, 0, (LPARAM)L"apple", "CB_ADDSTRING(\"apple\")");
        sm(cb, CB_ADDSTRING, 0, (LPARAM)L"Banana", "CB_ADDSTRING(\"Banana\")");
        print_items(cb);
        line("WM_GETTEXT, no selection: \"%s\"", text_of(cb));
        sm(cb, CB_SETCURSEL, 1, 0, "CB_SETCURSEL(1)");
        line("WM_GETTEXT: \"%s\", WM_GETTEXTLENGTH %ld", text_of(cb),
             (long)SendMessageW(cb, WM_GETTEXTLENGTH, 0, 0));
        sm(cb, WM_SETTEXT, 0, (LPARAM)L"pear", "WM_SETTEXT(\"pear\")");
        line("  CB_GETCURSEL %ld, WM_GETTEXT \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
        sm(cb, WM_SETTEXT, 0, (LPARAM)L"kiwi", "WM_SETTEXT(\"kiwi\")");
        line("  CB_GETCURSEL %ld, WM_GETTEXT \"%s\"", (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), text_of(cb));
        print_events();
        DestroyWindow(cb);
    }
    close_parent(parent);
}

/* --- drop -------------------------------------------------------------- */

static void drop_one(HWND parent, DWORD style)
{
    HWND cb;
    combo_info_t ci;
    RECT dropped, own;
    LRESULT r;

    cb = make_cb(parent, style);
    line("CreateWindowExW(\"ComboBox\", %s), 150x120, 3 items: non-NULL %s", style_name(style), yesno(cb != NULL));
    if (cb == NULL) {
        return;
    }
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"one");
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"two");
    SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"three");
    ZeroMemory(&ci, sizeof ci);
    ci.cbSize = sizeof ci;
    if (get_info != NULL) {
        get_info(cb, &ci);
    }
    GetWindowRect(cb, &own);
    SetRect(&dropped, -7, -7, -7, -7);
    arm();
    r = SendMessageW(cb, CB_GETDROPPEDCONTROLRECT, 0, (LPARAM)&dropped);
    line("CB_GETDROPPEDCONTROLRECT: ret=%ld err=%s; its left, top and right the combo's %s %s %s, its height %ld",
         (long)r, le(), yesno(dropped.left == own.left), yesno(dropped.top == own.top),
         yesno(dropped.right == own.right), dropped.bottom - dropped.top);
    line("  the combo's own height less than 120: %s", yesno(own.bottom - own.top < 120));
    sm(cb, CB_GETDROPPEDSTATE, 0, 0, "CB_GETDROPPEDSTATE");
    sm(cb, CB_SHOWDROPDOWN, TRUE, 0, "CB_SHOWDROPDOWN(TRUE)");
    drain();
    line("  CB_GETDROPPEDSTATE %ld, the list shown %s", (long)SendMessageW(cb, CB_GETDROPPEDSTATE, 0, 0),
         yesno(ci.hwndList != NULL && IsWindowVisible(ci.hwndList)));
    print_events();
    sm(cb, CB_SHOWDROPDOWN, TRUE, 0, "CB_SHOWDROPDOWN(TRUE) again");
    print_events();
    sm(cb, CB_SHOWDROPDOWN, FALSE, 0, "CB_SHOWDROPDOWN(FALSE)");
    drain();
    line("  CB_GETDROPPEDSTATE %ld, the list shown %s", (long)SendMessageW(cb, CB_GETDROPPEDSTATE, 0, 0),
         yesno(ci.hwndList != NULL && IsWindowVisible(ci.hwndList)));
    print_events();
    sm(cb, CB_SHOWDROPDOWN, FALSE, 0, "CB_SHOWDROPDOWN(FALSE) again");
    print_events();
    DestroyWindow(cb);
    drain();
    reset_events();
}

static void sec_drop(void)
{
    HWND parent = open_parent();

    if (parent == NULL) {
        return;
    }
    line("the parent: foreground %s", yesno(GetForegroundWindow() == parent));
    drop_one(parent, CBS_SIMPLE);
    drop_one(parent, CBS_DROPDOWN);
    drop_one(parent, CBS_DROPDOWNLIST);
    close_parent(parent);
}

/* --- edit -------------------------------------------------------------- */

static void get_sel(HWND cb)
{
    DWORD s = 0x7777, e = 0x7777;
    LRESULT r;
    DWORD err;

    arm();
    r = SendMessageW(cb, CB_GETEDITSEL, (WPARAM)&s, (LPARAM)&e);
    err = GetLastError();
    line("  CB_GETEDITSEL: ret=0x%lX err=%s start %lu end %lu", (unsigned long)r, le_of(err), s, e);
}

static void type(HWND edit, const char *s)
{
    for (; *s; s++) {
        SendMessageW(edit, WM_CHAR, (WPARAM)(unsigned char)*s, 1);
    }
}

static void sec_edit(void)
{
    HWND parent, cb;
    combo_info_t ci;

    parent = open_parent();
    cb = make_cb(parent, CBS_DROPDOWN | CBS_AUTOHSCROLL);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWN | CBS_AUTOHSCROLL): non-NULL %s", yesno(cb != NULL));
    if (cb != NULL) {
        SendMessageW(cb, WM_SETTEXT, 0, (LPARAM)L"hello");
        reset_events();
        get_sel(cb);
        sm(cb, CB_SETEDITSEL, 0, MAKELPARAM(1, 3), "CB_SETEDITSEL(1, 3)");
        get_sel(cb);
        sm(cb, CB_SETEDITSEL, 0, MAKELPARAM(0, -1), "CB_SETEDITSEL(0, -1)");
        get_sel(cb);
        sm(cb, CB_SETEDITSEL, 0, MAKELPARAM(-1, 0), "CB_SETEDITSEL(-1, 0)");
        get_sel(cb);
        sm(cb, CB_LIMITTEXT, 7, 0, "CB_LIMITTEXT(7)");
        ZeroMemory(&ci, sizeof ci);
        ci.cbSize = sizeof ci;
        if (get_info != NULL && get_info(cb, &ci) && ci.hwndItem != NULL) {
            SetFocus(ci.hwndItem);
            drain();
            reset_events();
            SendMessageW(cb, CB_SETEDITSEL, 0, MAKELPARAM(5, 5));
            type(ci.hwndItem, "abcd");
            line("WM_CHAR a, b, c, d to the edit at the end: its text \"%s\", EM_GETLIMITTEXT %ld", text_of(cb),
                 (long)SendMessageW(ci.hwndItem, EM_GETLIMITTEXT, 0, 0));
            print_events();
        }
        sm(cb, CB_LIMITTEXT, 0, 0, "CB_LIMITTEXT(0)");
        line("  EM_GETLIMITTEXT of the edit: %ld", (long)SendMessageW(ci.hwndItem, EM_GETLIMITTEXT, 0, 0));
        SetFocus(parent);
        drain();
        DestroyWindow(cb);
        drain();
        reset_events();
    }
    cb = make_cb(parent, CBS_DROPDOWNLIST);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWNLIST): non-NULL %s", yesno(cb != NULL));
    if (cb != NULL) {
        sm(cb, CB_SETEDITSEL, 0, MAKELPARAM(1, 3), "CB_SETEDITSEL(1, 3)");
        get_sel(cb);
        sm(cb, CB_LIMITTEXT, 7, 0, "CB_LIMITTEXT(7)");
        DestroyWindow(cb);
    }
    close_parent(parent);
}

/* --- notify ------------------------------------------------------------ */

static void key(HWND cb, UINT vk, const char *name)
{
    LRESULT r;
    DWORD e;

    arm();
    r = SendMessageW(cb, WM_KEYDOWN, vk, 0);
    e = GetLastError();
    drain();
    line("%s: ret=%ld err=%s; CB_GETCURSEL %ld, dropped %ld", name, (long)r, le_of(e),
         (long)SendMessageW(cb, CB_GETCURSEL, 0, 0), (long)SendMessageW(cb, CB_GETDROPPEDSTATE, 0, 0));
    print_events();
}

static void focus_to(HWND h, const char *name, HWND cb)
{
    SetFocus(h);
    drain();
    line("SetFocus(%s): the focus is the combo %s, a child of it %s", name, yesno(GetFocus() == cb),
         yesno(GetFocus() != NULL && GetParent(GetFocus()) == cb));
    print_events();
}

static void sec_notify(void)
{
    HWND parent, cb;
    combo_info_t ci;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    line("the parent: foreground %s", yesno(GetForegroundWindow() == parent));
    cb = make_cb(parent, CBS_DROPDOWNLIST);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWNLIST), 3 items: non-NULL %s", yesno(cb != NULL));
    if (cb != NULL) {
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"one");
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"two");
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"three");
        sm(cb, CB_SETCURSEL, 0, 0, "CB_SETCURSEL(0)");
        print_events();
        focus_to(cb, "the combo", cb);
        key(cb, VK_DOWN, "Down");
        key(cb, VK_F4, "F4");
        key(cb, VK_DOWN, "Down, dropped");
        key(cb, VK_RETURN, "Enter");
        key(cb, VK_F4, "F4");
        key(cb, VK_UP, "Up, dropped");
        key(cb, VK_ESCAPE, "Esc");
        key(cb, VK_F4, "F4");
        focus_to(parent, "the parent, dropped", cb);
        line("  dropped %ld", (long)SendMessageW(cb, CB_GETDROPPEDSTATE, 0, 0));
        DestroyWindow(cb);
        drain();
        reset_events();
    }
    cb = make_cb(parent, CBS_DROPDOWN | CBS_AUTOHSCROLL);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWN | CBS_AUTOHSCROLL), 3 items: non-NULL %s", yesno(cb != NULL));
    if (cb != NULL) {
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"one");
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"two");
        SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)L"three");
        reset_events();
        focus_to(cb, "the combo", cb);
        ZeroMemory(&ci, sizeof ci);
        ci.cbSize = sizeof ci;
        if (get_info != NULL && get_info(cb, &ci) && ci.hwndItem != NULL) {
            type(ci.hwndItem, "t");
            line("WM_CHAR 't' to the edit: its text \"%s\", CB_GETCURSEL %ld", text_of(cb),
                 (long)SendMessageW(cb, CB_GETCURSEL, 0, 0));
            print_events();
        }
        key(cb, VK_DOWN, "Down");
        line("  the edit's text \"%s\"", text_of(cb));
        sm(cb, CB_SETCURSEL, 2, 0, "CB_SETCURSEL(2)");
        print_events();
        focus_to(parent, "the parent", cb);
        DestroyWindow(cb);
        drain();
        reset_events();
    }
    close_parent(parent);
}

/* --- dir --------------------------------------------------------------- */

static const char *const dir_files[] = { "f2kcbdir\\a.txt", "f2kcbdir\\b.txt" };

static void dir_remove(void)
{
    DeleteFileA(dir_files[0]);
    DeleteFileA(dir_files[1]);
    RemoveDirectoryA("f2kcbdir\\sub");
    RemoveDirectoryA("f2kcbdir");
}

static int dir_make(void)
{
    HANDLE f;
    int i, ok;

    dir_remove();
    ok = CreateDirectoryA("f2kcbdir", NULL) && CreateDirectoryA("f2kcbdir\\sub", NULL);
    for (i = 0; i < 2; i++) {
        f = CreateFileA(dir_files[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        ok = ok && f != INVALID_HANDLE_VALUE;
        if (f != INVALID_HANDLE_VALUE) {
            CloseHandle(f);
        }
    }
    return ok;
}

static void check_cwd(const char *home)
{
    char cwd[MAX_PATH];
    int n;

    cwd[0] = 0;
    n = (int)GetCurrentDirectoryA(MAX_PATH, cwd);
    line("  the current directory is f2kcbdir now: %s; unchanged: %s",
         yesno(n >= 9 && _stricmp(cwd + n - 9, "\\f2kcbdir") == 0), yesno(_stricmp(cwd, home) == 0));
    SetCurrentDirectoryA(home);
}

static void select_ex(HWND parent, HWND cb, const WCHAR *item, int wide)
{
    char a[64];
    WCHAR w[64];
    BOOL r;

    SendMessageW(cb, CB_SETCURSEL, SendMessageW(cb, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)item), 0);
    strcpy(a, "untouched");
    lstrcpyW(w, L"untouched");
    arm();
    if (wide) {
        r = DlgDirSelectComboBoxExW(parent, w, 64, CB_ID);
        line("DlgDirSelectComboBoxExW, \"%s\" selected: ret=%d err=%s buffer \"%s\"", ws(item), r, le(), ws(w));
    } else {
        r = DlgDirSelectComboBoxExA(parent, a, 64, CB_ID);
        line("DlgDirSelectComboBoxExA, \"%s\" selected: ret=%d err=%s buffer \"%s\"", ws(item), r, le(), a);
    }
}

static void sec_dir(void)
{
    HWND parent, cb;
    char home[MAX_PATH];
    char spec[64];
    WCHAR wspec[64];
    int r;

    home[0] = 0;
    GetCurrentDirectoryA(MAX_PATH, home);
    line("f2kcbdir with a.txt, b.txt and sub made: %s", yesno(dir_make()));
    parent = open_parent();
    cb = make_cb(parent, CBS_DROPDOWNLIST | CBS_SORT);
    line("CreateWindowExW(\"ComboBox\", CBS_DROPDOWNLIST | CBS_SORT): non-NULL %s", yesno(cb != NULL));
    if (cb != NULL) {
        strcpy(spec, "f2kcbdir\\*.txt");
        arm();
        r = DlgDirListComboBoxA(parent, spec, CB_ID, 0, DDL_DIRECTORY);
        line("DlgDirListComboBoxA(\"f2kcbdir\\*.txt\", DDL_DIRECTORY): ret=%d err=%s buffer after \"%s\"", r, le(),
             spec);
        print_items(cb);
        select_ex(parent, cb, L"a.txt", 0);
        select_ex(parent, cb, L"[sub]", 0);
        check_cwd(home);

        SendMessageW(cb, CB_RESETCONTENT, 0, 0);
        lstrcpyW(wspec, L"f2kcbdir\\*");
        arm();
        r = DlgDirListComboBoxW(parent, wspec, CB_ID, 0, DDL_READWRITE);
        line("DlgDirListComboBoxW(\"f2kcbdir\\*\", DDL_READWRITE): ret=%d err=%s buffer after \"%s\"", r, le(),
             ws(wspec));
        print_items(cb);
        select_ex(parent, cb, L"b.txt", 1);
        check_cwd(home);

        strcpy(spec, "f2knone\\*.*");
        arm();
        r = DlgDirListComboBoxA(parent, spec, CB_ID, 0, DDL_READWRITE);
        line("DlgDirListComboBoxA(\"f2knone\\*.*\"), a missing directory: ret=%d err=%s", r, le());
        check_cwd(home);
        SendMessageW(cb, CB_RESETCONTENT, 0, 0);
        sm(cb, CB_DIR, DDL_READWRITE, (LPARAM)L"f2kcbdir\\*.txt", "CB_DIR(DDL_READWRITE, \"f2kcbdir\\*.txt\")");
        print_items(cb);
    }
    close_parent(parent);
    dir_remove();
    line("f2kcbdir removed: %s", yesno(GetFileAttributesA("f2kcbdir") == INVALID_FILE_ATTRIBUTES));
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
        SendDlgItemMessageW(dlg, 601, CB_ADDSTRING, 0, (LPARAM)L"by atom");
        SendDlgItemMessageW(dlg, 601, CB_SETCURSEL, 0, 0);
        SendDlgItemMessageW(dlg, 602, CB_ADDSTRING, 0, (LPARAM)L"by name");
        SendDlgItemMessageW(dlg, 602, CB_ADDSTRING, 0, (LPARAM)L"second");
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
    combo_info_t ci;
    int id;

    get_info = (getcomboboxinfo_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetComboBoxInfo");
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
    p = put_string(p, L"F2K combo box dialog");
    p = put_item(p, tmpl, 5, 5, 70, 60, 601, WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST, 0x0085, NULL);
    p = put_item(p, tmpl, 80, 5, 70, 60, 602, WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWN, 0, L"ComboBox");
    /* No last error prints: in a process of its own this is its first
     * window, which leaves 183 on Windows 2000 (guiwin's err183pop). */
    dlg = CreateDialogIndirectParamW(instance(), d, NULL, (DLGPROC)dialog_proc, 0);
    line("CreateDialogIndirectParamW, a combo box by atom 0x0085 and one by name: non-NULL %s", yesno(dlg != NULL));
    if (dlg == NULL) {
        return;
    }
    for (id = 601; id <= 602; id++) {
        item = GetDlgItem(dlg, id);
        ZeroMemory(&ci, sizeof ci);
        ci.cbSize = sizeof ci;
        if (get_info != NULL) {
            get_info(item, &ci);
        }
        line("  item %d: found %s, class %s, its list's class %s, WM_GETDLGCODE 0x%lX, CB_GETCOUNT %ld, text \"%s\"",
             id, yesno(item != NULL), class_of(item), class_of(ci.hwndList),
             (unsigned long)SendMessageW(item, WM_GETDLGCODE, 0, 0), (long)SendMessageW(item, CB_GETCOUNT, 0, 0),
             text_of(item));
    }
    arm();
    id = DestroyWindow(dlg);
    line("DestroyWindow(the dialog): ret=%d err=%s", id, le());
    drain();
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "items", sec_items, F2KT_ALWAYS },
    { "drop", sec_drop, F2KT_ALWAYS },
    { "edit", sec_edit, F2KT_ALWAYS },
    { "notify", sec_notify, F2KT_ALWAYS },
    { "dir", sec_dir, F2KT_ALWAYS },
    { "dialog", sec_dialog, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("combobox", sections, argc, argv);
}
