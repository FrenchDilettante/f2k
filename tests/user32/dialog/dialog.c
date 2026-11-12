/*
 * dialog - user32's dialog manager over the program's own dialog
 * resources (dialog.rc): CreateDialogParamW/A and the controls a
 * template becomes, a DIALOGEX template, the GetDlgItem family
 * (GetDlgItem, GetDlgCtrlID, SetDlgItemTextW/A, GetDlgItemTextW/A,
 * SendDlgItemMessageW, SetDlgItemInt, GetDlgItemInt, CheckDlgButton,
 * IsDlgButtonChecked, CheckRadioButton), DialogBoxParamW/A and
 * EndDialog's value, GetDialogBaseUnits and MapDialogRect,
 * IsDialogMessageW/A over posted Tab, Shift+Tab, Enter and Esc, and
 * MessageBoxW/A.
 *
 * Nothing waits for a person. A modal dialog ends itself: its
 * WM_INITDIALOG posts it a command, on which it calls EndDialog, and a
 * 3-second timer of its own ends it too should that command never
 * arrive (the block says so). A message box is ended by a watcher
 * thread the section starts before calling MessageBox: every 100 ms it
 * looks for the box (class #32770, the box's caption) and posts it the
 * command of the button to press. Should the box outlast that command,
 * the watcher posts it WM_CLOSE; should it find no box within five
 * seconds, or the box outlast WM_CLOSE, it posts WM_QUIT to the
 * section's thread, which ends the box's loop. The block says which.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare
 * (yesno()); a control prints by its id. Every call under observation
 * is armed with the last-error sentinel and its line prints ret= and
 * err=. The dialog procedures record what they receive; the records
 * print after the calls, never from inside a procedure. A control's
 * position prints only as its template rectangle, in dialog units,
 * mapped by MapDialogRect, minus its window's rectangle in the dialog's
 * client coordinates: the pixels depend on the dialog font. Only the
 * units section prints base units in pixels: the capture is to be taken
 * at 96 DPI (the Small Fonts setting), F2K's display's. Each section
 * creates its dialogs and windows and destroys them at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   CreateDialogParamW of the main template (100), hidden:
 *            the messages its procedure receives (WM_SETFONT,
 *            WM_INITDIALOG with its lParam and the control its wParam
 *            names), the dialog's class, styles and caption, and every
 *            control in order (class, id, styles, text, position), the
 *            focus; CreateDialogParamA of the same; a template that
 *            does not exist
 *   ex       the DIALOGEX template (101): the dialog's and controls'
 *            extended styles and positions
 *   default  the template (103) placed at -32768, -32768 (0x8000 in its
 *            signed words, CW_USEDEFAULT): the dialog's size, whether
 *            its client origin lands on the screen (the cascade spot
 *            itself varies with the machine, so only the yes/no prints),
 *            and the control's place against the template
 *   items    GetDlgItem (every id, one that does not exist, a NULL
 *            dialog), GetDlgCtrlID (a control, the dialog, NULL),
 *            SetDlgItemTextW/A and GetDlgItemTextW/A with buffers that
 *            fit and short ones, SendDlgItemMessageW
 *   ints     SetDlgItemInt signed and unsigned, GetDlgItemInt over
 *            texts that are and are not numbers, signed and unsigned,
 *            its translated flag and a NULL one
 *   buttons  CheckDlgButton and IsDlgButtonChecked on a check box, a
 *            radio button, a push button and a static, CheckRadioButton
 *            over the radio group
 *   modal    DialogBoxParamW and DialogBoxParamA ended by a posted
 *            command (EndDialog's value, the WM_INITDIALOG lParam,
 *            whether the dialog was visible then, IsWindowUnicode),
 *            EndDialog inside WM_INITDIALOG, a template that does not
 *            exist, EndDialog on a window that is not a dialog and on
 *            NULL
 *   units    GetDialogBaseUnits; MapDialogRect on the dialog with no
 *            font (102) against it; MapDialogRect of (0,0,4,8) on the
 *            dialogs with the dialog font (100, 101), in pixels; each
 *            dialog's client size against its mapped template size
 *   keys     the main dialog, shown: WM_KEYDOWN/WM_KEYUP pairs posted
 *            to the focus (Tab, Tab, Shift+Tab through
 *            SetKeyboardState, Enter, Enter from a radio button, Esc),
 *            each pumped through IsDialogMessageW (its answer per
 *            message), the focus after and the commands the dialog
 *            received, DM_GETDEFID; a Tab pumped through
 *            IsDialogMessageA; IsDialogMessageW of another window's
 *            message
 *   msgbox   MessageBoxW (MB_OK, MB_OKCANCEL, MB_YESNO) and MessageBoxA
 *            (MB_OK), each ended by the timer: the return, the box's
 *            class, caption and controls (class, id, text)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat dialog):
 *   rc dialog.rc
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% dialog.c dialog.res user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate them. */
#ifndef DC_HASDEFID
#define DC_HASDEFID 0x534B
#endif
#ifndef DM_GETDEFID
#define DM_GETDEFID (WM_USER + 0)
#endif

/* The templates (dialog.rc). */
#define DLG_MAIN 100
#define DLG_EX 101
#define DLG_SYSFONT 102
#define DLG_DEFAULT 103
#define DLG_MISSING 999

/* The command the modal dialogs post themselves, and their timer. */
#define ID_END 900
#define END_TIMER 7
#define END_TIMEOUT_MS 3000

/* A control of a template: its id and its rectangle in dialog units. */
typedef struct {
    int id;
    int x, y, cx, cy;
} tmpl_item;

/* dialog.rc's controls, in template order. */
static const tmpl_item main_items[] = {
    { 1, 140, 8, 50, 14 },
    { 2, 140, 26, 50, 14 },
    { 132, 140, 44, 50, 14 },
    { 110, 8, 8, 40, 8 },
    { 111, 52, 8, 60, 8 },
    { 120, 8, 22, 120, 50 },
    { 121, 14, 34, 60, 10 },
    { 122, 14, 46, 60, 10 },
    { 123, 14, 58, 60, 10 },
    { 130, 8, 78, 80, 10 },
    { 131, 8, 92, 80, 10 },
    { 0, 0, 0, 0, 0 }
};
static const tmpl_item ex_items[] = {
    { 140, 6, 6, 50, 10 },
    { 1, 64, 40, 50, 14 },
    { 0, 0, 0, 0, 0 }
};
static const tmpl_item default_items[] = {
    { 1, 25, 30, 50, 14 },
    { 0, 0, 0, 0, 0 }
};

/* The dialogs' sizes in dialog units. */
#define MAIN_CX 200
#define MAIN_CY 110
#define EX_CX 120
#define EX_CY 60
#define SYSFONT_CX 100
#define SYSFONT_CY 50

/* --- What the dialog procedures record ------------------------------ */

#define MAX_EVENTS 32

typedef struct {
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
    int focus_id;       /* WM_INITDIALOG: the id of the control wParam names */
    int from_control;   /* WM_COMMAND: lParam is the control the id names */
} event_t;

static event_t events[MAX_EVENTS];
static int event_count;

/* The modal procedure's facts. */
static int modal_mode;          /* 0: end on the posted command, 1: end in WM_INITDIALOG */
static int modal_visible;       /* IsWindowVisible when the command came, -1 if it never came */
static int modal_unicode;       /* IsWindowUnicode in WM_INITDIALOG */
static LPARAM modal_param;      /* WM_INITDIALOG's lParam */
static int modal_timed_out;

static void reset_events(void)
{
    event_count = 0;
}

static void record(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    event_t *e;

    if (event_count >= MAX_EVENTS) {
        return;
    }
    e = &events[event_count++];
    e->msg = msg;
    e->wparam = wparam;
    e->lparam = lparam;
    e->focus_id = 0;
    e->from_control = 0;
    if (msg == WM_INITDIALOG) {
        e->focus_id = wparam != 0 ? GetDlgCtrlID((HWND)wparam) : -1;
    }
    if (msg == WM_COMMAND) {
        e->from_control = lparam != 0 && GetDlgItem(hwnd, LOWORD(wparam)) == (HWND)lparam;
    }
}

static const char *msg_name(UINT msg)
{
    static char buf[16];

    switch (msg) {
    case WM_SETFONT: return "WM_SETFONT";
    case WM_INITDIALOG: return "WM_INITDIALOG";
    case WM_COMMAND: return "WM_COMMAND";
    case WM_SHOWWINDOW: return "WM_SHOWWINDOW";
    case WM_DESTROY: return "WM_DESTROY";
    case WM_NCDESTROY: return "WM_NCDESTROY";
    case WM_KEYDOWN: return "WM_KEYDOWN";
    case WM_KEYUP: return "WM_KEYUP";
    case WM_CHAR: return "WM_CHAR";
    case WM_SYSKEYDOWN: return "WM_SYSKEYDOWN";
    case WM_SYSKEYUP: return "WM_SYSKEYUP";
    case WM_SYSCHAR: return "WM_SYSCHAR";
    }
    sprintf(buf, "0x%04X", msg);
    return buf;
}

static void print_events(const char *who)
{
    int i;
    event_t *e;

    line("%s received %d of the recorded messages", who, event_count);
    for (i = 0; i < event_count; i++) {
        e = &events[i];
        switch (e->msg) {
        case WM_SETFONT:
            line("  WM_SETFONT: font non-NULL %s lParam=%ld", yesno(e->wparam != 0), (long)e->lparam);
            break;
        case WM_INITDIALOG:
            line("  WM_INITDIALOG: lParam=0x%lX focus control id=%d", (unsigned long)e->lparam,
                 e->focus_id);
            break;
        case WM_COMMAND:
            line("  WM_COMMAND: id=%u code=%u lParam %s", (unsigned)LOWORD(e->wparam),
                 (unsigned)HIWORD(e->wparam),
                 e->lparam == 0 ? "NULL" : (e->from_control ? "the control" : "another window"));
            break;
        case WM_SHOWWINDOW:
            line("  WM_SHOWWINDOW: wParam=%lu lParam=%ld", (unsigned long)e->wparam, (long)e->lparam);
            break;
        default:
            line("  %s", msg_name(e->msg));
            break;
        }
    }
}

/* The modeless dialogs' procedure: records the interesting messages and
 * handles none of them (the commands included: a modeless dialog is
 * destroyed by the section). */
static BOOL CALLBACK recorder(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_SETFONT:
    case WM_INITDIALOG:
    case WM_SHOWWINDOW:
    case WM_DESTROY:
    case WM_NCDESTROY:
        record(hwnd, msg, wparam, lparam);
        return msg == WM_INITDIALOG;
    case WM_COMMAND:
        record(hwnd, msg, wparam, lparam);
        return TRUE;
    }
    return FALSE;
}

/* The modal dialogs' procedure: posts itself ID_END from WM_INITDIALOG
 * and ends on it (mode 0), or ends inside WM_INITDIALOG (mode 1). */
static BOOL CALLBACK modal(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_INITDIALOG:
        record(hwnd, msg, wparam, lparam);
        modal_param = lparam;
        modal_unicode = IsWindowUnicode(hwnd) != FALSE;
        if (modal_mode == 1) {
            EndDialog(hwnd, 77);
            return TRUE;
        }
        SetTimer(hwnd, END_TIMER, END_TIMEOUT_MS, NULL);
        PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(ID_END, 0), 0);
        return TRUE;
    case WM_COMMAND:
        record(hwnd, msg, wparam, lparam);
        if (LOWORD(wparam) == ID_END) {
            modal_visible = IsWindowVisible(hwnd) != FALSE;
            KillTimer(hwnd, END_TIMER);
            EndDialog(hwnd, 1234);
        }
        return TRUE;
    case WM_TIMER:
        if (wparam == END_TIMER) {
            modal_timed_out = 1;
            KillTimer(hwnd, END_TIMER);
            EndDialog(hwnd, -2);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

/* --- Helpers ----------------------------------------------------------- */

static HINSTANCE instance(void)
{
    return GetModuleHandleA(NULL);
}

/* Empty the queue, so one step's leftovers never reach the next. */
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

/* A dialog of the main template, created hidden; NULL on failure. */
static HWND open_main(void)
{
    HWND dlg;

    reset_events();
    arm();
    dlg = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_MAIN), NULL, (DLGPROC)recorder, 0x1234);
    line("CreateDialogParamW(100, NULL, proc, 0x1234): non-NULL %s err=%s", yesno(dlg != NULL), le());
    return dlg;
}

static void close_dialog(HWND dlg)
{
    if (dlg != NULL) {
        DestroyWindow(dlg);
    }
    drain();
}

/* A window's class and text, as printed. */
static const char *class_of(HWND h)
{
    static WCHAR buf[2][64];
    static int next;
    WCHAR *b = buf[next++ & 1];

    b[0] = 0;
    GetClassNameW(h, b, 64);
    return ws(b);
}

static const char *text_of(HWND h)
{
    static WCHAR buf[2][128];
    static int next;
    WCHAR *b = buf[next++ & 1];

    b[0] = 0;
    GetWindowTextW(h, b, 128);
    return ws(b);
}

/* A control's position against its template rectangle: the mapped
 * template rectangle minus the window's, in the dialog's client
 * coordinates (left, top, right, bottom). */
static void print_position(HWND dlg, HWND ctl, const tmpl_item *t)
{
    RECT mapped;
    RECT actual;

    mapped.left = t->x;
    mapped.top = t->y;
    mapped.right = t->x + t->cx;
    mapped.bottom = t->y + t->cy;
    MapDialogRect(dlg, &mapped);
    GetWindowRect(ctl, &actual);
    MapWindowPoints(NULL, dlg, (POINT *)&actual, 2);
    line("    template rect mapped minus window rect: %ld %ld %ld %ld", mapped.left - actual.left,
         mapped.top - actual.top, mapped.right - actual.right, mapped.bottom - actual.bottom);
}

/* Every control of a dialog in Z order, against its template's table. */
static void print_controls(HWND dlg, const tmpl_item *items)
{
    HWND c;
    int i = 0;

    for (c = GetWindow(dlg, GW_CHILD); c != NULL; c = GetWindow(c, GW_HWNDNEXT), i++) {
        line("  control %d: class %s id=%d style=0x%08lX exstyle=0x%08lX text \"%s\"", i, class_of(c),
             (int)GetWindowLongW(c, GWL_ID), (unsigned long)GetWindowLongW(c, GWL_STYLE),
             (unsigned long)GetWindowLongW(c, GWL_EXSTYLE), text_of(c));
        if (items[i].id != 0 && items[i].id == (int)GetWindowLongW(c, GWL_ID)) {
            print_position(dlg, c, &items[i]);
        } else {
            line("    not the template's control %d", i);
        }
    }
    line("  %d controls", i);
}

static void print_dialog(HWND dlg)
{
    line("dialog: class %s style=0x%08lX exstyle=0x%08lX caption \"%s\" visible %s", class_of(dlg),
         (unsigned long)GetWindowLongW(dlg, GWL_STYLE), (unsigned long)GetWindowLongW(dlg, GWL_EXSTYLE),
         text_of(dlg), yesno(IsWindowVisible(dlg)));
}

static const char *focus_label(void)
{
    static char buf[16];
    HWND f = GetFocus();

    if (f == NULL) {
        return "none";
    }
    sprintf(buf, "id %d", GetDlgCtrlID(f));
    return buf;
}

/* --- create ------------------------------------------------------------ */

static void sec_create(void)
{
    HWND dlg;

    drain();
    dlg = open_main();
    if (dlg == NULL) {
        return;
    }
    print_events("the procedure");
    print_dialog(dlg);
    line("IsWindowUnicode: %s", yesno(IsWindowUnicode(dlg)));
    print_controls(dlg, main_items);
    line("focus: %s", focus_label());
    reset_events();
    close_dialog(dlg);
    print_events("on DestroyWindow, the procedure");

    reset_events();
    arm();
    dlg = CreateDialogParamA(instance(), MAKEINTRESOURCEA(DLG_MAIN), NULL, (DLGPROC)recorder, 0x5678);
    line("CreateDialogParamA(100, NULL, proc, 0x5678): non-NULL %s err=%s", yesno(dlg != NULL), le());
    if (dlg != NULL) {
        print_events("the procedure");
        print_dialog(dlg);
        line("IsWindowUnicode: %s", yesno(IsWindowUnicode(dlg)));
        print_controls(dlg, main_items);
        close_dialog(dlg);
    }

    reset_events();
    arm();
    dlg = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_MISSING), NULL, (DLGPROC)recorder, 0);
    line("CreateDialogParamW(999, a template that does not exist): non-NULL %s err=%s",
         yesno(dlg != NULL), le());
    print_events("the procedure");
    close_dialog(dlg);
}

/* --- default ----------------------------------------------------------- */

/* A template placed at -32768, -32768 (0x8000, CW_USEDEFAULT): where the
 * system puts the dialog, printed as machine-independent facts only (the
 * cascade spot and the screen's size vary): the window's size, and
 * whether the client origin is on the screen. */
static void sec_default(void)
{
    HWND dlg;
    RECT wr;
    POINT origin;
    int sw;
    int sh;

    drain();
    reset_events();
    arm();
    dlg = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_DEFAULT), NULL, (DLGPROC)recorder, 0);
    line("CreateDialogParamW(103, template at -32768, -32768): non-NULL %s err=%s", yesno(dlg != NULL),
         le());
    if (dlg == NULL) {
        return;
    }
    print_dialog(dlg);
    GetWindowRect(dlg, &wr);
    sw = GetSystemMetrics(SM_CXSCREEN);
    sh = GetSystemMetrics(SM_CYSCREEN);
    origin.x = 0;
    origin.y = 0;
    ClientToScreen(dlg, &origin);
    line("window rect size %ld x %ld; client origin on the screen %s", wr.right - wr.left,
         wr.bottom - wr.top, yesno(origin.x >= 0 && origin.y >= 0 && origin.x < sw && origin.y < sh));
    print_controls(dlg, default_items);
    close_dialog(dlg);
}

/* --- ex ---------------------------------------------------------------- */

static void sec_ex(void)
{
    HWND dlg;
    RECT client;
    RECT mapped;

    drain();
    reset_events();
    arm();
    dlg = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_EX), NULL, (DLGPROC)recorder, 0x2222);
    line("CreateDialogParamW(101, DIALOGEX): non-NULL %s err=%s", yesno(dlg != NULL), le());
    if (dlg == NULL) {
        return;
    }
    print_events("the procedure");
    print_dialog(dlg);
    print_controls(dlg, ex_items);
    GetClientRect(dlg, &client);
    SetRect(&mapped, 0, 0, EX_CX, EX_CY);
    MapDialogRect(dlg, &mapped);
    line("client size minus the mapped template size: %ld %ld", client.right - mapped.right,
         client.bottom - mapped.bottom);
    close_dialog(dlg);
}

/* --- items ------------------------------------------------------------- */

static void sec_items(void)
{
    HWND dlg;
    HWND h;
    const tmpl_item *t;
    WCHAR wbuf[32];
    char abuf[32];
    UINT n;
    int id;
    BOOL b;
    LRESULT r;

    drain();
    dlg = open_main();
    if (dlg == NULL) {
        return;
    }
    for (t = main_items; t->id != 0; t++) {
        arm();
        h = GetDlgItem(dlg, t->id);
        line("GetDlgItem(dlg, %d): non-NULL %s err=%s class %s", t->id, yesno(h != NULL), le(),
             h != NULL ? class_of(h) : "-");
        arm();
        id = GetDlgCtrlID(h);
        line("GetDlgCtrlID of it: %d err=%s", id, le());
    }
    arm();
    h = GetDlgItem(dlg, 555);
    line("GetDlgItem(dlg, 555, no such control): non-NULL %s err=%s", yesno(h != NULL), le());
    arm();
    h = GetDlgItem(NULL, 1);
    line("GetDlgItem(NULL, 1): non-NULL %s err=%s", yesno(h != NULL), le());
    arm();
    id = GetDlgCtrlID(dlg);
    line("GetDlgCtrlID(the dialog): %d err=%s", id, le());
    arm();
    id = GetDlgCtrlID(NULL);
    line("GetDlgCtrlID(NULL): %d err=%s", id, le());

    arm();
    n = GetDlgItemTextW(dlg, 110, wbuf, 32);
    line("GetDlgItemTextW(dlg, 110, 32): ret=%u err=%s \"%s\"", n, le(), ws(wbuf));
    arm();
    b = SetDlgItemTextW(dlg, 111, L"Wide <\x00E9>");
    line("SetDlgItemTextW(dlg, 111, L\"Wide <U+00E9>\"): ret=%d err=%s", b, le());
    arm();
    n = GetDlgItemTextW(dlg, 111, wbuf, 32);
    line("GetDlgItemTextW(dlg, 111, 32): ret=%u err=%s \"%s\"", n, le(), ws(wbuf));
    arm();
    n = GetDlgItemTextA(dlg, 111, abuf, 32);
    line("GetDlgItemTextA(dlg, 111, 32): ret=%u err=%s \"%s\"", n, le(), abuf);
    lstrcpyW(wbuf, L"xxxxxxxxxx");
    arm();
    n = GetDlgItemTextW(dlg, 111, wbuf, 4);
    line("GetDlgItemTextW(dlg, 111, 4): ret=%u err=%s \"%s\"", n, le(), ws(wbuf));
    lstrcpyA(abuf, "xxxxxxxxxx");
    arm();
    n = GetDlgItemTextA(dlg, 111, abuf, 4);
    line("GetDlgItemTextA(dlg, 111, 4): ret=%u err=%s \"%s\"", n, le(), abuf);
    lstrcpyW(wbuf, L"xxxxxxxxxx");
    arm();
    n = GetDlgItemTextW(dlg, 111, wbuf, 0);
    line("GetDlgItemTextW(dlg, 111, 0): ret=%u err=%s buffer \"%s\"", n, le(), ws(wbuf));
    arm();
    b = SetDlgItemTextA(dlg, 111, "Narrow");
    line("SetDlgItemTextA(dlg, 111, \"Narrow\"): ret=%d err=%s", b, le());
    arm();
    n = GetDlgItemTextW(dlg, 111, wbuf, 32);
    line("GetDlgItemTextW(dlg, 111, 32): ret=%u err=%s \"%s\"", n, le(), ws(wbuf));
    arm();
    b = SetDlgItemTextW(dlg, 111, L"");
    line("SetDlgItemTextW(dlg, 111, L\"\"): ret=%d err=%s", b, le());
    arm();
    n = GetDlgItemTextW(dlg, 111, wbuf, 32);
    line("GetDlgItemTextW(dlg, 111, 32): ret=%u err=%s \"%s\"", n, le(), ws(wbuf));
    arm();
    b = SetDlgItemTextW(dlg, 555, L"none");
    line("SetDlgItemTextW(dlg, 555, no such control): ret=%d err=%s", b, le());
    lstrcpyW(wbuf, L"xxxxxxxxxx");
    arm();
    n = GetDlgItemTextW(dlg, 555, wbuf, 32);
    line("GetDlgItemTextW(dlg, 555, no such control): ret=%u err=%s buffer \"%s\"", n, le(), ws(wbuf));
    arm();
    b = SetDlgItemTextW(dlg, 1, L"Fine");
    line("SetDlgItemTextW(dlg, 1, L\"Fine\"): ret=%d err=%s", b, le());
    arm();
    r = SendDlgItemMessageW(dlg, 1, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageW(dlg, 1, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    arm();
    r = SendDlgItemMessageW(dlg, 555, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageW(dlg, 555, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    close_dialog(dlg);
}

/* --- ints -------------------------------------------------------------- */

static void get_int(HWND dlg, const WCHAR *text, const char *shown)
{
    UINT v;
    BOOL ok;

    SetDlgItemTextW(dlg, 111, text);
    ok = 7;
    arm();
    v = GetDlgItemInt(dlg, 111, &ok, TRUE);
    line("\"%s\" signed: ret=%ld translated=%d err=%s", shown, (long)(int)v, ok, le());
    ok = 7;
    arm();
    v = GetDlgItemInt(dlg, 111, &ok, FALSE);
    line("\"%s\" unsigned: ret=%lu translated=%d err=%s", shown, (unsigned long)v, ok, le());
}

static void sec_ints(void)
{
    HWND dlg;
    WCHAR wbuf[32];
    BOOL b;
    UINT v;
    BOOL ok;

    drain();
    dlg = open_main();
    if (dlg == NULL) {
        return;
    }
    arm();
    b = SetDlgItemInt(dlg, 111, (UINT)-42, TRUE);
    GetDlgItemTextW(dlg, 111, wbuf, 32);
    line("SetDlgItemInt(dlg, 111, -42, signed): ret=%d err=%s text \"%s\"", b, le(), ws(wbuf));
    arm();
    b = SetDlgItemInt(dlg, 111, (UINT)-42, FALSE);
    GetDlgItemTextW(dlg, 111, wbuf, 32);
    line("SetDlgItemInt(dlg, 111, -42, unsigned): ret=%d err=%s text \"%s\"", b, le(), ws(wbuf));
    arm();
    b = SetDlgItemInt(dlg, 111, 0, TRUE);
    GetDlgItemTextW(dlg, 111, wbuf, 32);
    line("SetDlgItemInt(dlg, 111, 0, signed): ret=%d err=%s text \"%s\"", b, le(), ws(wbuf));
    arm();
    b = SetDlgItemInt(dlg, 555, 5, TRUE);
    line("SetDlgItemInt(dlg, 555, no such control): ret=%d err=%s", b, le());

    get_int(dlg, L"123", "123");
    get_int(dlg, L"-42", "-42");
    get_int(dlg, L"+5", "+5");
    get_int(dlg, L"  7", "  7");
    get_int(dlg, L"7  ", "7  ");
    get_int(dlg, L"12abc", "12abc");
    get_int(dlg, L"abc", "abc");
    get_int(dlg, L"", "");
    get_int(dlg, L"2147483647", "2147483647");
    get_int(dlg, L"2147483648", "2147483648");
    get_int(dlg, L"-2147483648", "-2147483648");
    get_int(dlg, L"4294967295", "4294967295");
    get_int(dlg, L"4294967296", "4294967296");
    get_int(dlg, L"0x10", "0x10");

    SetDlgItemTextW(dlg, 111, L"99");
    arm();
    v = GetDlgItemInt(dlg, 111, NULL, TRUE);
    line("\"99\" signed, NULL translated: ret=%ld err=%s", (long)(int)v, le());
    ok = 7;
    arm();
    v = GetDlgItemInt(dlg, 555, &ok, TRUE);
    line("GetDlgItemInt(dlg, 555, no such control): ret=%ld translated=%d err=%s", (long)(int)v, ok,
         le());
    close_dialog(dlg);
}

/* --- buttons ----------------------------------------------------------- */

static void print_checks(HWND dlg)
{
    line("  checked: 121=%u 122=%u 123=%u 130=%u 131=%u", IsDlgButtonChecked(dlg, 121),
         IsDlgButtonChecked(dlg, 122), IsDlgButtonChecked(dlg, 123), IsDlgButtonChecked(dlg, 130),
         IsDlgButtonChecked(dlg, 131));
}

static void check(HWND dlg, int id, UINT state, const char *what)
{
    BOOL b;
    UINT s;

    arm();
    b = CheckDlgButton(dlg, id, state);
    line("CheckDlgButton(dlg, %d, %u) (%s): ret=%d err=%s", id, state, what, b, le());
    arm();
    s = IsDlgButtonChecked(dlg, id);
    line("IsDlgButtonChecked(dlg, %d): ret=%u err=%s", id, s, le());
}

static void radio(HWND dlg, int first, int last, int id)
{
    BOOL b;

    arm();
    b = CheckRadioButton(dlg, first, last, id);
    line("CheckRadioButton(dlg, %d, %d, %d): ret=%d err=%s", first, last, id, b, le());
    print_checks(dlg);
}

static void sec_buttons(void)
{
    HWND dlg;
    UINT s;

    drain();
    dlg = open_main();
    if (dlg == NULL) {
        return;
    }
    print_checks(dlg);
    check(dlg, 130, BST_CHECKED, "auto check box");
    check(dlg, 130, BST_UNCHECKED, "auto check box");
    check(dlg, 131, BST_CHECKED, "check box");
    check(dlg, 131, BST_INDETERMINATE, "a two-state check box");
    check(dlg, 131, BST_UNCHECKED, "check box");
    check(dlg, 122, BST_CHECKED, "radio button");
    print_checks(dlg);
    check(dlg, 1, BST_CHECKED, "push button");
    check(dlg, 110, BST_CHECKED, "static");
    check(dlg, 555, BST_CHECKED, "no such control");
    arm();
    s = IsDlgButtonChecked(NULL, 130);
    line("IsDlgButtonChecked(NULL, 130): ret=%u err=%s", s, le());

    radio(dlg, 121, 123, 121);
    radio(dlg, 121, 123, 123);
    radio(dlg, 121, 122, 122);
    radio(dlg, 121, 123, 130);
    radio(dlg, 123, 121, 122);
    radio(dlg, 121, 123, 555);
    close_dialog(dlg);
}

/* --- modal ------------------------------------------------------------- */

static void reset_modal(int mode)
{
    reset_events();
    modal_mode = mode;
    modal_visible = -1;
    modal_unicode = -1;
    modal_param = 0;
    modal_timed_out = 0;
}

static void print_modal(void)
{
    print_events("the procedure");
    line("WM_INITDIALOG lParam=0x%lX IsWindowUnicode=%d visible at the command=%d timed out %s",
         (unsigned long)modal_param, modal_unicode, modal_visible, yesno(modal_timed_out));
}

static void sec_modal(void)
{
    int r;
    HWND plain;
    BOOL b;

    drain();
    reset_modal(0);
    arm();
    r = DialogBoxParamW(instance(), MAKEINTRESOURCEW(DLG_MAIN), NULL, (DLGPROC)modal, 0x5678);
    line("DialogBoxParamW(100, NULL, proc, 0x5678), ended by EndDialog(1234): ret=%d err=%s", r, le());
    print_modal();
    drain();

    reset_modal(0);
    arm();
    r = DialogBoxParamA(instance(), MAKEINTRESOURCEA(DLG_MAIN), NULL, (DLGPROC)modal, 0x9ABC);
    line("DialogBoxParamA(100, NULL, proc, 0x9ABC), ended by EndDialog(1234): ret=%d err=%s", r, le());
    print_modal();
    drain();

    reset_modal(1);
    arm();
    r = DialogBoxParamW(instance(), MAKEINTRESOURCEW(DLG_MAIN), NULL, (DLGPROC)modal, 0x1111);
    line("DialogBoxParamW(100), EndDialog(77) inside WM_INITDIALOG: ret=%d err=%s", r, le());
    print_modal();
    drain();

    reset_modal(0);
    arm();
    r = DialogBoxParamW(instance(), MAKEINTRESOURCEW(DLG_MISSING), NULL, (DLGPROC)modal, 0);
    line("DialogBoxParamW(999, a template that does not exist): ret=%d err=%s", r, le());
    print_modal();
    drain();

    plain = CreateWindowExW(0, L"Static", L"plain", WS_POPUP, 0, 0, 50, 20, NULL, NULL, instance(),
                            NULL);
    arm();
    b = EndDialog(plain, 5);
    line("EndDialog(a Static window, 5): ret=%d err=%s IsWindow after %s", b, le(),
         yesno(IsWindow(plain)));
    if (plain != NULL) {
        DestroyWindow(plain);
    }
    arm();
    b = EndDialog(NULL, 5);
    line("EndDialog(NULL, 5): ret=%d err=%s", b, le());
    drain();
}

/* --- units ------------------------------------------------------------- */

static void print_units(HWND dlg, int cx, int cy, const char *what)
{
    RECT r;
    RECT client;
    BOOL b;

    SetRect(&r, 0, 0, 4, 8);
    arm();
    b = MapDialogRect(dlg, &r);
    line("MapDialogRect(%s, 0,0,4,8): ret=%d err=%s -> %ld,%ld,%ld,%ld", what, b, le(), r.left, r.top,
         r.right, r.bottom);
    GetClientRect(dlg, &client);
    SetRect(&r, 0, 0, cx, cy);
    MapDialogRect(dlg, &r);
    line("  client size minus the mapped template size: %ld %ld", client.right - r.right,
         client.bottom - r.bottom);
}

static void sec_units(void)
{
    LONG units;
    HWND sysfont;
    HWND main_dlg;
    HWND ex;
    RECT r;
    BOOL b;
    int bx, by;

    drain();
    arm();
    units = GetDialogBaseUnits();
    bx = LOWORD(units);
    by = HIWORD(units);
    line("GetDialogBaseUnits: ret x=%d y=%d err=%s", bx, by, le());

    sysfont = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_SYSFONT), NULL, (DLGPROC)recorder, 0);
    line("CreateDialogParamW(102, no font): non-NULL %s", yesno(sysfont != NULL));
    if (sysfont != NULL) {
        SetRect(&r, 0, 0, 4, 8);
        arm();
        b = MapDialogRect(sysfont, &r);
        line("MapDialogRect(102, 0,0,4,8): ret=%d err=%s right==base x %s bottom==base y %s", b, le(),
             yesno(r.right == bx), yesno(r.bottom == by));
        SetRect(&r, 0, 0, 100, 50);
        MapDialogRect(sysfont, &r);
        line("MapDialogRect(102, 0,0,100,50): right==MulDiv(100, base x, 4) %s "
             "bottom==MulDiv(50, base y, 8) %s",
             yesno(r.right == MulDiv(100, bx, 4)), yesno(r.bottom == MulDiv(50, by, 8)));
        print_units(sysfont, SYSFONT_CX, SYSFONT_CY, "102, no font");
        print_dialog(sysfont);
        close_dialog(sysfont);
    }

    main_dlg = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_MAIN), NULL, (DLGPROC)recorder, 0);
    line("CreateDialogParamW(100, MS Shell Dlg 8): non-NULL %s", yesno(main_dlg != NULL));
    if (main_dlg != NULL) {
        print_units(main_dlg, MAIN_CX, MAIN_CY, "100");
        close_dialog(main_dlg);
    }
    ex = CreateDialogParamW(instance(), MAKEINTRESOURCEW(DLG_EX), NULL, (DLGPROC)recorder, 0);
    line("CreateDialogParamW(101, DIALOGEX, MS Shell Dlg 8): non-NULL %s", yesno(ex != NULL));
    if (ex != NULL) {
        print_units(ex, EX_CX, EX_CY, "101");
        close_dialog(ex);
    }

    SetRect(&r, 0, 0, 4, 8);
    arm();
    b = MapDialogRect(NULL, &r);
    line("MapDialogRect(NULL): ret=%d err=%s", b, le());
}

/* --- keys -------------------------------------------------------------- */

#define MAX_PUMPED 16

/* The keystroke messages a pump took, and IsDialogMessage's answers. */
static UINT pumped_msg[MAX_PUMPED];
static WPARAM pumped_wparam[MAX_PUMPED];
static BOOL pumped_ret[MAX_PUMPED];
static int pumped_count;

static int is_key_message(UINT msg)
{
    return msg == WM_KEYDOWN || msg == WM_KEYUP || msg == WM_CHAR || msg == WM_SYSKEYDOWN ||
           msg == WM_SYSKEYUP || msg == WM_SYSCHAR;
}

/* Take every queued message through IsDialogMessageW (or A), dispatching
 * those it declines; a bounded number of them. */
static void pump(HWND dlg, int ansi)
{
    MSG m;
    BOOL r;
    BOOL got;
    int n;

    pumped_count = 0;
    for (n = 0; n < 200; n++) {
        got = ansi ? PeekMessageA(&m, NULL, 0, 0, PM_REMOVE) : PeekMessageW(&m, NULL, 0, 0, PM_REMOVE);
        if (!got) {
            break;
        }
        if (m.message == WM_QUIT) {
            continue;
        }
        r = ansi ? IsDialogMessageA(dlg, &m) : IsDialogMessageW(dlg, &m);
        if (is_key_message(m.message) && pumped_count < MAX_PUMPED) {
            pumped_msg[pumped_count] = m.message;
            pumped_wparam[pumped_count] = m.wParam;
            pumped_ret[pumped_count] = r;
            pumped_count++;
        }
        if (!r) {
            TranslateMessage(&m);
            if (ansi) {
                DispatchMessageA(&m);
            } else {
                DispatchMessageW(&m);
            }
        }
    }
}

static void print_pumped(const char *form)
{
    int i;

    for (i = 0; i < pumped_count; i++) {
        line("  %s(%s wParam=0x%02lX): ret=%d", form, msg_name(pumped_msg[i]),
             (unsigned long)pumped_wparam[i], pumped_ret[i]);
    }
}

/* Post a key's press and release to the focus (the dialog if none), as
 * the keyboard would deliver them, and pump them. */
static void press(HWND dlg, UINT vk, UINT scan, const char *name, int ansi)
{
    HWND target = GetFocus();
    LPARAM down = 1 | ((LPARAM)scan << 16);
    LPARAM up = down | 0xC0000000;

    if (target == NULL) {
        target = dlg;
    }
    reset_events();
    PostMessageW(target, WM_KEYDOWN, vk, down);
    PostMessageW(target, WM_KEYUP, vk, up);
    pump(dlg, ansi);
    line("%s, through %s:", name, ansi ? "IsDialogMessageA" : "IsDialogMessageW");
    print_pumped(ansi ? "IsDialogMessageA" : "IsDialogMessageW");
    line("  focus after: %s", focus_label());
    print_events("  the procedure");
}

static void print_defid(HWND dlg)
{
    LRESULT r;

    r = SendMessageW(dlg, DM_GETDEFID, 0, 0);
    line("DM_GETDEFID: has one %s id=%u", yesno(HIWORD(r) == DC_HASDEFID), (unsigned)LOWORD(r));
}

static void sec_keys(void)
{
    HWND dlg;
    HWND other;
    BYTE saved[256];
    BYTE shifted[256];
    MSG m;
    BOOL r;
    HWND radio2;

    drain();
    dlg = open_main();
    if (dlg == NULL) {
        return;
    }
    ShowWindow(dlg, SW_SHOWNORMAL);
    SetForegroundWindow(dlg);
    drain();
    line("the dialog shown: foreground %s active %s focus %s", yesno(GetForegroundWindow() == dlg),
         yesno(GetActiveWindow() == dlg), focus_label());
    print_defid(dlg);

    press(dlg, VK_TAB, 0x0F, "Tab", 0);
    press(dlg, VK_TAB, 0x0F, "Tab", 0);

    GetKeyboardState(saved);
    CopyMemory(shifted, saved, sizeof shifted);
    shifted[VK_SHIFT] = 0x80;
    shifted[VK_LSHIFT] = 0x80;
    SetKeyboardState(shifted);
    press(dlg, VK_TAB, 0x0F, "Shift+Tab (VK_SHIFT down in the thread's key state)", 0);
    SetKeyboardState(saved);

    print_defid(dlg);
    press(dlg, VK_RETURN, 0x1C, "Enter", 0);
    print_defid(dlg);

    radio2 = GetDlgItem(dlg, 122);
    SetFocus(radio2);
    line("SetFocus(122): focus %s", focus_label());
    print_defid(dlg);
    press(dlg, VK_RETURN, 0x1C, "Enter", 0);
    press(dlg, VK_ESCAPE, 0x01, "Esc", 0);
    press(dlg, VK_TAB, 0x0F, "Tab", 1);

    other = CreateWindowExW(0, L"Static", L"other", WS_POPUP, 0, 0, 50, 20, NULL, NULL, instance(),
                            NULL);
    ZeroMemory(&m, sizeof m);
    m.hwnd = other;
    m.message = WM_KEYDOWN;
    m.wParam = VK_TAB;
    m.lParam = 1 | (0x0F << 16);
    arm();
    r = IsDialogMessageW(dlg, &m);
    line("IsDialogMessageW(dlg, Tab for another top-level window): ret=%d err=%s focus %s", r, le(),
         focus_label());
    if (other != NULL) {
        DestroyWindow(other);
    }
    close_dialog(dlg);
}

/* --- msgbox ------------------------------------------------------------ */

#define MAX_BOX_CONTROLS 8
#define BOX_TICK_MS 100
#define BOX_TRIES 50            /* five seconds to find the box */
#define BOX_GRACE_TRIES 20      /* two seconds for it to go after a post */

static HANDLE box_thread;
static DWORD box_owner;         /* the thread that runs the box */
static const WCHAR *box_title;  /* the caption the watcher looks for */
static int box_answer;          /* the button id the watcher presses */
static int box_found;
static int box_closed;          /* the command was not enough: WM_CLOSE */
static int box_gave_up;         /* WM_QUIT ended the box's loop */
static char box_class[64];
static char box_caption[128];
static char box_controls[MAX_BOX_CONTROLS][160];
static int box_control_count;

/* The box's class, caption and controls, recorded for printing after. */
static void record_box(HWND box)
{
    HWND c;
    int i = 0;

    sprintf(box_class, "%.60s", class_of(box));
    sprintf(box_caption, "%.120s", text_of(box));
    for (c = GetWindow(box, GW_CHILD); c != NULL && i < MAX_BOX_CONTROLS; c = GetWindow(c, GW_HWNDNEXT)) {
        sprintf(box_controls[i], "class %.40s id=%d text \"%.80s\"", class_of(c), GetDlgCtrlID(c),
                text_of(c));
        i++;
    }
    box_control_count = i;
}

/* Whether the box is still there after a post, given a grace period. */
static int box_outlasts(HWND box)
{
    int i;

    for (i = 0; i < BOX_GRACE_TRIES; i++) {
        Sleep(BOX_TICK_MS);
        if (!IsWindow(box)) {
            return 0;
        }
    }
    return 1;
}

/* The watcher: finds the box by its class and caption, records it, and
   presses the button of the section's choice; failing that, closes it;
   failing that, ends the box's loop with WM_QUIT. */
static DWORD WINAPI box_watch(LPVOID unused)
{
    HWND box = NULL;
    int i;

    (void)unused;
    for (i = 0; i < BOX_TRIES && box == NULL; i++) {
        Sleep(BOX_TICK_MS);
        box = FindWindowW(L"#32770", box_title);
    }
    if (box == NULL) {
        box_gave_up = 1;
        PostThreadMessageW(box_owner, WM_QUIT, 0, 0);
        return 0;
    }
    box_found = 1;
    record_box(box);
    PostMessageW(box, WM_COMMAND, MAKEWPARAM(box_answer, BN_CLICKED),
                 (LPARAM)GetDlgItem(box, box_answer));
    if (!box_outlasts(box)) {
        return 0;
    }
    box_closed = 1;
    PostMessageW(box, WM_CLOSE, 0, 0);
    if (!box_outlasts(box)) {
        return 0;
    }
    box_gave_up = 1;
    PostThreadMessageW(box_owner, WM_QUIT, 0, 0);
    return 0;
}

static void arm_box(const WCHAR *title, int answer)
{
    DWORD id;

    box_owner = GetCurrentThreadId();
    box_title = title;
    box_answer = answer;
    box_found = 0;
    box_closed = 0;
    box_gave_up = 0;
    box_class[0] = 0;
    box_caption[0] = 0;
    box_control_count = 0;
    box_thread = CreateThread(NULL, 0, box_watch, NULL, 0, &id);
}

static void print_box(void)
{
    int i;
    MSG m;

    if (box_thread != NULL) {
        WaitForSingleObject(box_thread, 15000);
        CloseHandle(box_thread);
        box_thread = NULL;
    }
    line("  the watcher found the box %s, closed it %s, gave up %s", yesno(box_found),
         yesno(box_closed), yesno(box_gave_up));
    if (box_found) {
        line("  box: class %s caption \"%s\", %d controls", box_class, box_caption, box_control_count);
        for (i = 0; i < box_control_count; i++) {
            line("    %s", box_controls[i]);
        }
    }
    /* The WM_QUIT that ended a box the watcher gave up on. */
    while (PeekMessageW(&m, NULL, WM_QUIT, WM_QUIT, PM_REMOVE)) {
    }
}

static void sec_msgbox(void)
{
    int r;

    drain();
    arm_box(L"F2K caption", IDOK);
    arm();
    r = MessageBoxW(NULL, L"F2K message box", L"F2K caption", MB_OK);
    line("MessageBoxW(NULL, MB_OK), IDOK posted: ret=%d err=%s", r, le());
    print_box();

    arm_box(L"F2K caption", IDCANCEL);
    arm();
    r = MessageBoxW(NULL, L"Second <\x00E9>", L"F2K caption", MB_OKCANCEL);
    line("MessageBoxW(NULL, MB_OKCANCEL), IDCANCEL posted: ret=%d err=%s", r, le());
    print_box();

    arm_box(L"F2K caption", IDNO);
    arm();
    r = MessageBoxW(NULL, L"Third", L"F2K caption", MB_YESNO);
    line("MessageBoxW(NULL, MB_YESNO), IDNO posted: ret=%d err=%s", r, le());
    print_box();

    arm_box(L"F2K narrow caption", IDOK);
    arm();
    r = MessageBoxA(NULL, "F2K narrow box", "F2K narrow caption", MB_OK);
    line("MessageBoxA(NULL, MB_OK), IDOK posted: ret=%d err=%s", r, le());
    print_box();
    drain();
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "ex", sec_ex, F2KT_ALWAYS },
    { "default", sec_default, F2KT_ALWAYS },
    { "items", sec_items, F2KT_ALWAYS },
    { "ints", sec_ints, F2KT_ALWAYS },
    { "buttons", sec_buttons, F2KT_ALWAYS },
    { "modal", sec_modal, F2KT_ALWAYS },
    { "units", sec_units, F2KT_ALWAYS },
    { "keys", sec_keys, F2KT_ALWAYS },
    { "msgbox", sec_msgbox, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("dialog", sections, argc, argv);
}
