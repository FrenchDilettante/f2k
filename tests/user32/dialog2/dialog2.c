/*
 * dialog2 - the dialog manager's in-memory templates and the rest of
 * its exports: CreateDialogIndirectParamW/A and the undocumented
 * CreateDialogIndirectParamAorW, DialogBoxIndirectParamW/A/AorW,
 * GetNextDlgTabItem, GetNextDlgGroupItem, SendDlgItemMessageA, the
 * unsuffixed IsDialogMessage (the A form's alias), MessageBoxExW/A and
 * MessageBoxIndirectW/A.
 *
 * Every template is built in memory by the program (DLGTEMPLATE without
 * and with DS_SETFONT, and DLGTEMPLATEEX), so the fixture carries no
 * resource script. The controls are the predefined classes by atom
 * (0x0080 Button, 0x0081 Edit, 0x0082 Static), or a class name.
 *
 * The exports F2K's user32 lacks (catalogued only in
 * userland/user32/exports.toml) and those MSVC 6's user32.lib may not
 * carry (the undocumented AorW pair, the IsDialogMessage alias) are
 * reached through GetProcAddress: a missing one prints "<Name>: absent"
 * and fails its own block, never the program's load.
 *
 * The AorW pair's last parameter: ReactOS's user32 (and Wine's) calls
 * it with 0 from the W form and DLG_ISANSI (2) from the A form, so 2
 * means ANSI; the section also passes 1, whose meaning the capture
 * decides (IsWindowUnicode of the dialog shows which form it made).
 *
 * Nothing waits for a person. A modal dialog ends itself: its
 * WM_INITDIALOG posts it a command, on which it calls EndDialog, and a
 * 3-second timer ends it should the command never come (the block says
 * so). A message box is ended by a watcher thread, as the dialog
 * fixture's: every 100 ms it looks for the box (class #32770, the
 * section's caption), records its controls and posts it the command of
 * the button to press; should the box outlast it, WM_CLOSE; should it
 * find no box within five seconds, or the box outlast WM_CLOSE, WM_QUIT
 * to the section's thread. The block says which.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare; a
 * control prints by its id ("NULL" for no window, "other" for a window
 * outside the dialog). Every call under observation is armed with the
 * last-error sentinel. The dialog procedure records what it receives;
 * the records print after the calls. No position or size prints.
 * Dialogs are hidden but where a section needs one shown (tabs, groups,
 * alias), and the modal ones and the message boxes, which show
 * themselves briefly; each is destroyed before its section ends.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   indirect  CreateDialogIndirectParamW of a template with no font and
 *             of one with DS_SETFONT: the messages (WM_SETFONT,
 *             WM_INITDIALOG's lParam), IsWindowUnicode, the caption,
 *             WM_GETFONT, every control (class, id, styles, text);
 *             CreateDialogIndirectParamA of the DS_SETFONT one; a
 *             control of an unregistered class without and with
 *             DS_NOFAILCREATE, both forms
 *   ex        a DLGTEMPLATEEX (help ids, extended styles, a 32-bit
 *             control id) through CreateDialogIndirectParamW and A
 *   aorw      CreateDialogIndirectParamAorW with flags 0, 1 and 2, and
 *             DialogBoxIndirectParamAorW with 0 and 2: the return,
 *             IsWindowUnicode, WM_INITDIALOG's lParam
 *   modal     DialogBoxIndirectParamW and A ended by EndDialog(1234)
 *             from a posted command, by EndDialog(77) inside
 *             WM_INITDIALOG, and over a template whose control's class
 *             is unregistered
 *   tabs      a shown dialog of ten controls (tab stops, groups, a
 *             disabled and a hidden one, a static, two radio groups):
 *             GetNextDlgTabItem from each control and from NULL, both
 *             ways; a NULL dialog, a window outside the dialog
 *   groups    the same dialog: GetNextDlgGroupItem from each control
 *             and from NULL, both ways; a NULL dialog
 *   senditem  SendDlgItemMessageA's WM_SETTEXT, WM_GETTEXTLENGTH and
 *             WM_GETTEXT on an edit against SendDlgItemMessageW's, a
 *             missing id, a NULL dialog
 *   alias     IsDialogMessage (the alias) and IsDialogMessageA over a
 *             Tab posted to the shown dialog's focus: each answer, the
 *             focus after; another window's message
 *   msgboxex  MessageBoxExW and A with language 0, English (US) and
 *             French (Windows 2000's user32 carries English strings
 *             only): the return, the last error, the box's controls
 *   msgboxind MessageBoxIndirectW and A: MB_OKCANCEL answered Cancel,
 *             MB_USERICON with the stock IDI_EXCLAMATION (hInstance
 *             NULL), and a cbSize of 0
 *
 * The capture needs the desktop left alone while the modal dialogs and
 * the message boxes come and go (the watcher finds them by caption).
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat dialog2):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% dialog2.c user32.lib
 */

#include "../common/f2kt.h"

/* The undocumented flag of the AorW pair: the A forms pass it. */
#define DLG_ISANSI_ 2

typedef HWND (WINAPI *create_indirect_a_t)(HINSTANCE, LPCDLGTEMPLATEA, HWND, DLGPROC, LPARAM);
typedef HWND (WINAPI *create_indirect_aorw_t)(HINSTANCE, LPCVOID, HWND, DLGPROC, LPARAM, DWORD);
typedef int (WINAPI *box_indirect_t)(HINSTANCE, LPCVOID, HWND, DLGPROC, LPARAM);
typedef int (WINAPI *box_indirect_aorw_t)(HINSTANCE, LPCVOID, HWND, DLGPROC, LPARAM, DWORD);
typedef HWND (WINAPI *next_item_t)(HWND, HWND, BOOL);
typedef LONG (WINAPI *send_item_a_t)(HWND, int, UINT, WPARAM, LPARAM);
typedef BOOL (WINAPI *is_dialog_message_t)(HWND, LPMSG);
typedef int (WINAPI *message_box_ex_w_t)(HWND, LPCWSTR, LPCWSTR, UINT, WORD);
typedef int (WINAPI *message_box_ex_a_t)(HWND, LPCSTR, LPCSTR, UINT, WORD);
typedef int (WINAPI *message_box_indirect_w_t)(const MSGBOXPARAMSW *);
typedef int (WINAPI *message_box_indirect_a_t)(const MSGBOXPARAMSA *);

/* An export of user32 by name, or NULL; prints "<name>: absent" then. */
static FARPROC user32_export(const char *name)
{
    FARPROC p = GetProcAddress(GetModuleHandleA("user32.dll"), name);

    if (p == NULL) {
        line("%s: absent", name);
    }
    return p;
}

static HINSTANCE instance(void)
{
    return GetModuleHandleA(NULL);
}

static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* --- templates ---------------------------------------------------------- */

#define ATOM_BUTTON 0x0080
#define ATOM_EDIT 0x0081
#define ATOM_STATIC 0x0082

/* The template under construction: DWORD-aligned, as the calls need. */
static DWORD tbuf[1024];
static WORD *tw;
static int tpos;        /* in WORDs */
static int tcount_at;   /* where the item count sits */
static int tex;         /* a DLGTEMPLATEEX */

static void put_w(WORD w)
{
    tw[tpos++] = w;
}

static void put_dw(DWORD d)
{
    put_w(LOWORD(d));
    put_w(HIWORD(d));
}

static void put_str(const WCHAR *s)
{
    do {
        put_w(*s);
    } while (*s++ != 0);
}

static void align4(void)
{
    if (tpos & 1) {
        put_w(0);
    }
}

/* A template's header; font NULL for none (DS_SETFONT is the caller's). */
static void tpl_begin(int ex, DWORD style, DWORD exstyle, DWORD help, const WCHAR *title,
                      const WCHAR *font)
{
    tw = (WORD *)tbuf;
    tpos = 0;
    tex = ex;
    if (ex) {
        put_w(1);                /* dlgVer */
        put_w(0xFFFF);           /* signature */
        put_dw(help);
        put_dw(exstyle);
        put_dw(style);
    } else {
        put_dw(style);
        put_dw(exstyle);
    }
    tcount_at = tpos;
    put_w(0);                    /* cdit, counted as items come */
    put_w(10);                   /* x, y, cx, cy */
    put_w(10);
    put_w(160);
    put_w(100);
    put_w(0);                    /* no menu */
    put_w(0);                    /* the dialog class */
    put_str(title);
    if (font != NULL) {
        put_w(8);                /* point size */
        if (ex) {
            put_w(FW_NORMAL);
            put_w(0);            /* italic, charset */
        }
        put_str(font);
    }
}

/* One control: by class atom (cls NULL) or class name. */
static void tpl_item(DWORD style, DWORD exstyle, DWORD help, short y, DWORD id, WORD atom,
                     const WCHAR *cls, const WCHAR *text)
{
    align4();
    if (tex) {
        put_dw(help);
        put_dw(exstyle);
        put_dw(style);
    } else {
        put_dw(style);
        put_dw(exstyle);
    }
    put_w(4);                    /* x */
    put_w((WORD)y);
    put_w(60);                   /* cx */
    put_w(8);                    /* cy */
    if (tex) {
        put_dw(id);
    } else {
        put_w((WORD)id);
    }
    if (cls == NULL) {
        put_w(0xFFFF);
        put_w(atom);
    } else {
        put_str(cls);
    }
    put_str(text);
    put_w(0);                    /* no creation data */
    tw[tcount_at]++;
}

static LPCDLGTEMPLATEW tpl(void)
{
    return (LPCDLGTEMPLATEW)tbuf;
}

#define CHILD (WS_CHILD | WS_VISIBLE)
#define CAPTION L"F2K dialog2 \x00E9"

/* The plain template: two controls, with or without the dialog font. */
static void tpl_plain(DWORD extra)
{
    tpl_begin(0, WS_POPUP | WS_CAPTION | DS_MODALFRAME | extra, 0, 0, CAPTION,
              (extra & DS_SETFONT) ? L"MS Sans Serif" : NULL);
    tpl_item(CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 4, IDOK, ATOM_BUTTON, NULL, L"OK");
    tpl_item(CHILD | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 16, 101, ATOM_EDIT, NULL,
             L"text \x00E9");
}

/* --- the dialog procedure's record ------------------------------------ */

#define ID_END 9001
#define END_TIMER 9002
#define END_TIMEOUT_MS 3000

static int rec_setfont;
static int rec_init;
static LPARAM rec_lparam;
static int rec_unicode;
static int rec_visible;
static int rec_timer;
static int end_value;           /* EndDialog's value on ID_END */
static int end_in_init;         /* EndDialog(77) inside WM_INITDIALOG */
static int modal_mode;          /* post ID_END at WM_INITDIALOG */

static void reset(int modal, int in_init)
{
    rec_setfont = 0;
    rec_init = 0;
    rec_lparam = 0;
    rec_unicode = 0;
    rec_visible = 0;
    rec_timer = 0;
    end_value = 1234;
    modal_mode = modal;
    end_in_init = in_init;
}

static BOOL CALLBACK recorder(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_SETFONT:
        rec_setfont++;
        return FALSE;
    case WM_INITDIALOG:
        rec_init++;
        rec_lparam = lparam;
        rec_unicode = IsWindowUnicode(hwnd);
        rec_visible = IsWindowVisible(hwnd);
        if (end_in_init) {
            EndDialog(hwnd, 77);
        } else if (modal_mode) {
            SetTimer(hwnd, END_TIMER, END_TIMEOUT_MS, NULL);
            PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(ID_END, 0), 0);
        }
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wparam) == ID_END) {
            KillTimer(hwnd, END_TIMER);
            EndDialog(hwnd, end_value);
            return TRUE;
        }
        return FALSE;
    case WM_TIMER:
        if (wparam == END_TIMER) {
            KillTimer(hwnd, END_TIMER);
            rec_timer = 1;
            EndDialog(hwnd, -2);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

static void print_record(void)
{
    line("  the procedure: WM_SETFONT %d time(s), WM_INITDIALOG %d time(s) lParam=0x%lX", rec_setfont,
         rec_init, (unsigned long)rec_lparam);
    if (rec_init) {
        line("  at WM_INITDIALOG: IsWindowUnicode %s, visible %s", yesno(rec_unicode),
             yesno(rec_visible));
    }
    if (rec_timer) {
        line("  ended by the timer");
    }
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

/* A made dialog: its class, styles, caption, font and controls. */
static void print_dialog(HWND dlg)
{
    HWND c;
    int i = 0;

    line("  dialog: class %s style=0x%08lX exstyle=0x%08lX IsWindowUnicode %s caption \"%s\"",
         class_of(dlg), (unsigned long)GetWindowLongW(dlg, GWL_STYLE),
         (unsigned long)GetWindowLongW(dlg, GWL_EXSTYLE), yesno(IsWindowUnicode(dlg)), text_of(dlg));
    line("  WM_GETFONT: non-NULL %s", yesno(SendMessageW(dlg, WM_GETFONT, 0, 0) != 0));
    for (c = GetWindow(dlg, GW_CHILD); c != NULL; c = GetWindow(c, GW_HWNDNEXT), i++) {
        line("  control %d: class %s id=0x%lX style=0x%08lX exstyle=0x%08lX text \"%s\"", i,
             class_of(c), (unsigned long)GetWindowLongW(c, GWL_ID),
             (unsigned long)GetWindowLongW(c, GWL_STYLE),
             (unsigned long)GetWindowLongW(c, GWL_EXSTYLE), text_of(c));
        line("    its font the dialog's: %s",
             yesno(SendMessageW(c, WM_GETFONT, 0, 0) == SendMessageW(dlg, WM_GETFONT, 0, 0)));
    }
    line("  %d controls", i);
}

static void close_dialog(HWND dlg)
{
    DestroyWindow(dlg);
    drain();
}

/* A modeless creation, printed: W (form 'W'), A ('A'). */
static HWND create(int form, const char *what, LPARAM lp)
{
    create_indirect_a_t a;
    HWND dlg = NULL;
    DWORD err;

    reset(0, 0);
    if (form == 'A') {
        a = (create_indirect_a_t)user32_export("CreateDialogIndirectParamA");
        if (a == NULL) {
            return NULL;
        }
        arm();
        dlg = a(instance(), (LPCDLGTEMPLATEA)tbuf, NULL, (DLGPROC)recorder, lp);
    } else {
        arm();
        dlg = CreateDialogIndirectParamW(instance(), tpl(), NULL, (DLGPROC)recorder, lp);
    }
    err = GetLastError();
    line("CreateDialogIndirectParam%c(%s): non-NULL %s err=%s", form, what, yesno(dlg != NULL),
         le_of(err));
    print_record();
    return dlg;
}

/* --- indirect ----------------------------------------------------------- */

static void sec_indirect(void)
{
    HWND dlg;
    int form;

    drain();
    tpl_plain(0);
    dlg = create('W', "no font", 0x1234);
    if (dlg != NULL) {
        print_dialog(dlg);
        close_dialog(dlg);
    }
    tpl_plain(DS_SETFONT);
    dlg = create('W', "DS_SETFONT", 0x5678);
    if (dlg != NULL) {
        print_dialog(dlg);
        close_dialog(dlg);
    }
    dlg = create('A', "DS_SETFONT", 0x9ABC);
    if (dlg != NULL) {
        print_dialog(dlg);
        close_dialog(dlg);
    }

    for (form = 'A'; form <= 'W'; form += 'W' - 'A') {
        tpl_begin(0, WS_POPUP | WS_CAPTION | DS_SETFONT, 0, 0, CAPTION, L"MS Sans Serif");
        tpl_item(CHILD, 0, 0, 4, 301, 0, L"F2KNoSuchClass", L"x");
        tpl_item(CHILD, 0, 0, 16, 302, ATOM_STATIC, NULL, L"static");
        dlg = create(form, "a control of an unregistered class", 1);
        if (dlg != NULL) {
            print_dialog(dlg);
            close_dialog(dlg);
        }
        tpl_begin(0, WS_POPUP | WS_CAPTION | DS_SETFONT | DS_NOFAILCREATE, 0, 0, CAPTION,
                  L"MS Sans Serif");
        tpl_item(CHILD, 0, 0, 4, 301, 0, L"F2KNoSuchClass", L"x");
        tpl_item(CHILD, 0, 0, 16, 302, ATOM_STATIC, NULL, L"static");
        dlg = create(form, "the same, DS_NOFAILCREATE", 2);
        if (dlg != NULL) {
            print_dialog(dlg);
            close_dialog(dlg);
        }
    }
}

/* --- ex ------------------------------------------------------------------ */

static void tpl_ex(void)
{
    tpl_begin(1, WS_POPUP | WS_CAPTION | DS_SETFONT | DS_MODALFRAME, WS_EX_CONTEXTHELP, 4242,
              L"F2K dialog2 ex", L"MS Sans Serif");
    tpl_item(CHILD | WS_TABSTOP, 0, 11, 4, IDOK, ATOM_BUTTON, NULL, L"OK");
    tpl_item(CHILD | WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, 12, 16, 0x12345, ATOM_EDIT, NULL,
             L"wide id");
    tpl_item(CHILD, WS_EX_STATICEDGE, 0, 28, 103, ATOM_STATIC, NULL, L"edged");
}

static void sec_ex(void)
{
    HWND dlg;

    drain();
    tpl_ex();
    dlg = create('W', "DLGTEMPLATEEX", 0x11);
    if (dlg != NULL) {
        print_dialog(dlg);
        line("  GetDlgItem(0x12345): non-NULL %s, GetDlgItem(0x2345): non-NULL %s",
             yesno(GetDlgItem(dlg, 0x12345) != NULL), yesno(GetDlgItem(dlg, 0x2345) != NULL));
        close_dialog(dlg);
    }
    tpl_ex();
    dlg = create('A', "DLGTEMPLATEEX", 0x22);
    if (dlg != NULL) {
        print_dialog(dlg);
        close_dialog(dlg);
    }
}

/* --- aorw ----------------------------------------------------------------- */

static void sec_aorw(void)
{
    static const DWORD flags[3] = { 0, 1, DLG_ISANSI_ };
    create_indirect_aorw_t c;
    box_indirect_aorw_t b;
    HWND dlg;
    DWORD err;
    int i, r;

    drain();
    c = (create_indirect_aorw_t)user32_export("CreateDialogIndirectParamAorW");
    if (c != NULL) {
        for (i = 0; i < 3; i++) {
            tpl_plain(DS_SETFONT);
            reset(0, 0);
            arm();
            dlg = c(instance(), tbuf, NULL, (DLGPROC)recorder, 0x100 + i, flags[i]);
            err = GetLastError();
            line("CreateDialogIndirectParamAorW(flags %lu): non-NULL %s err=%s",
                 (unsigned long)flags[i], yesno(dlg != NULL), le_of(err));
            print_record();
            if (dlg != NULL) {
                line("  IsWindowUnicode: %s, caption \"%s\"", yesno(IsWindowUnicode(dlg)), text_of(dlg));
                close_dialog(dlg);
            }
        }
    }
    b = (box_indirect_aorw_t)user32_export("DialogBoxIndirectParamAorW");
    if (b != NULL) {
        for (i = 0; i < 3; i += 2) {
            tpl_plain(DS_SETFONT);
            reset(1, 0);
            arm();
            r = b(instance(), tbuf, NULL, (DLGPROC)recorder, 0x200 + i, flags[i]);
            line("DialogBoxIndirectParamAorW(flags %lu), ended by EndDialog(1234): ret=%d err=%s",
                 (unsigned long)flags[i], r, le());
            print_record();
            drain();
        }
    }
}

/* --- modal ----------------------------------------------------------------- */

static void modal(int form, const char *what, int in_init, LPARAM lp)
{
    box_indirect_t a;
    int r;

    reset(1, in_init);
    if (form == 'A') {
        a = (box_indirect_t)user32_export("DialogBoxIndirectParamA");
        if (a == NULL) {
            return;
        }
        arm();
        r = a(instance(), tbuf, NULL, (DLGPROC)recorder, lp);
    } else {
        a = (box_indirect_t)user32_export("DialogBoxIndirectParamW");
        if (a == NULL) {
            return;
        }
        arm();
        r = a(instance(), tbuf, NULL, (DLGPROC)recorder, lp);
    }
    line("DialogBoxIndirectParam%c(%s): ret=%d err=%s", form, what, r, le());
    print_record();
    drain();
}

static void sec_modal(void)
{
    int form;

    drain();
    for (form = 'W'; form >= 'A'; form -= 'W' - 'A') {
        tpl_plain(DS_SETFONT);
        modal(form, "ended by EndDialog(1234)", 0, 0x4321);
        tpl_plain(0);
        modal(form, "no font, ended by EndDialog(1234)", 0, 0x4322);
        tpl_plain(DS_SETFONT);
        modal(form, "EndDialog(77) inside WM_INITDIALOG", 1, 0x4323);
        tpl_begin(0, WS_POPUP | WS_CAPTION | DS_SETFONT, 0, 0, CAPTION, L"MS Sans Serif");
        tpl_item(CHILD, 0, 0, 4, 301, 0, L"F2KNoSuchClass", L"x");
        modal(form, "a control of an unregistered class", 0, 0x4324);
    }
}

/* --- tabs and groups ----------------------------------------------------- */

/* The order dialog: ten controls, shown. */
static const int order_ids[10] = { 201, 202, 203, 204, 205, 206, 207, 208, 209, 210 };

static HWND order_dialog(void)
{
    HWND dlg;

    tpl_begin(0, WS_POPUP | WS_CAPTION | WS_VISIBLE | DS_SETFONT, 0, 0, L"F2K dialog2 order",
              L"MS Sans Serif");
    tpl_item(CHILD | WS_TABSTOP | WS_GROUP, 0, 0, 4, 201, ATOM_BUTTON, NULL, L"one");
    tpl_item(CHILD | WS_TABSTOP | WS_BORDER, 0, 0, 14, 202, ATOM_EDIT, NULL, L"");
    tpl_item(CHILD | WS_TABSTOP | WS_GROUP | WS_DISABLED, 0, 0, 24, 203, ATOM_BUTTON, NULL,
             L"disabled");
    tpl_item(WS_CHILD | WS_TABSTOP, 0, 0, 34, 204, ATOM_BUTTON, NULL, L"hidden");
    tpl_item(CHILD | WS_GROUP, 0, 0, 44, 205, ATOM_STATIC, NULL, L"static");
    tpl_item(CHILD | WS_TABSTOP | WS_GROUP | BS_RADIOBUTTON, 0, 0, 54, 206, ATOM_BUTTON, NULL,
             L"r1");
    tpl_item(CHILD | BS_RADIOBUTTON, 0, 0, 64, 207, ATOM_BUTTON, NULL, L"r2");
    tpl_item(CHILD | WS_DISABLED | BS_RADIOBUTTON, 0, 0, 74, 208, ATOM_BUTTON, NULL, L"r3");
    tpl_item(CHILD | BS_RADIOBUTTON, 0, 0, 84, 209, ATOM_BUTTON, NULL, L"r4");
    tpl_item(CHILD | WS_TABSTOP | WS_GROUP, 0, 0, 94, 210, ATOM_BUTTON, NULL, L"last");
    reset(0, 0);
    dlg = CreateDialogIndirectParamW(instance(), tpl(), NULL, (DLGPROC)recorder, 0);
    line("the order dialog (201 tab group; 202 tab; 203 tab group disabled; 204 tab hidden; "
         "205 static group; 206 tab group radio; 207, 208 disabled, 209 radios; 210 tab group): "
         "made %s", yesno(dlg != NULL));
    return dlg;
}

/* A window as printed: its id within the dialog. */
static const char *who(HWND dlg, HWND h)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (h == NULL) {
        return "NULL";
    }
    if (h == dlg) {
        return "the dialog";
    }
    if (GetParent(h) != dlg) {
        return "other";
    }
    sprintf(b, "%ld", (long)GetWindowLongW(h, GWL_ID));
    return b;
}

static void walk(HWND dlg, next_item_t next, const char *name)
{
    HWND from, r;
    int i;
    char prev_buf[256];

    for (i = -1; i < 10; i++) {
        from = i < 0 ? NULL : GetDlgItem(dlg, order_ids[i]);
        arm();
        r = next(dlg, from, FALSE);
        sprintf(prev_buf, "%s err=%s", who(dlg, r), le());
        arm();
        r = next(dlg, from, TRUE);
        line("%s(dlg, %s): next %s, previous %s err=%s", name, who(dlg, from), prev_buf, who(dlg, r),
             le());
    }
}

static void around(HWND dlg, next_item_t next, const char *name)
{
    HWND other, r;

    arm();
    r = next(NULL, NULL, FALSE);
    line("%s(NULL, NULL, FALSE): %s err=%s", name, who(dlg, r), le());
    arm();
    r = next(NULL, GetDlgItem(dlg, 201), FALSE);
    line("%s(NULL, 201, FALSE): %s err=%s", name, who(dlg, r), le());
    other = CreateWindowExW(0, L"Button", L"outside", WS_POPUP | WS_TABSTOP, 0, 0, 40, 20, NULL, NULL,
                            instance(), NULL);
    arm();
    r = next(dlg, other, FALSE);
    line("%s(dlg, a popup outside it, FALSE): %s err=%s", name, who(dlg, r), le());
    DestroyWindow(other);
}

static void sec_tabs(void)
{
    next_item_t next;
    HWND dlg;

    drain();
    next = (next_item_t)user32_export("GetNextDlgTabItem");
    if (next == NULL) {
        return;
    }
    dlg = order_dialog();
    if (dlg == NULL) {
        return;
    }
    walk(dlg, next, "GetNextDlgTabItem");
    around(dlg, next, "GetNextDlgTabItem");
    close_dialog(dlg);
}

static void sec_groups(void)
{
    next_item_t next;
    HWND dlg;

    drain();
    next = (next_item_t)user32_export("GetNextDlgGroupItem");
    if (next == NULL) {
        return;
    }
    dlg = order_dialog();
    if (dlg == NULL) {
        return;
    }
    walk(dlg, next, "GetNextDlgGroupItem");
    around(dlg, next, "GetNextDlgGroupItem");
    close_dialog(dlg);
}

/* --- senditem ------------------------------------------------------------- */

/* ANSI bytes as printed: outside 0x20-0x7E as <XX>. */
static const char *bytes(const char *s)
{
    static char b[256];
    int n = 0;

    for (; *s != 0 && n < 240; s++) {
        if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7E) {
            n += sprintf(b + n, "<%02X>", (unsigned char)*s);
        } else {
            b[n++] = *s;
        }
    }
    b[n] = 0;
    return b;
}

static void sec_senditem(void)
{
    send_item_a_t send_a;
    HWND dlg;
    LONG r;
    char abuf[32];
    WCHAR wbuf[32];

    drain();
    send_a = (send_item_a_t)user32_export("SendDlgItemMessageA");
    if (send_a == NULL) {
        return;
    }
    tpl_plain(DS_SETFONT);
    dlg = create('W', "DS_SETFONT", 0);
    if (dlg == NULL) {
        return;
    }
    arm();
    r = send_a(dlg, 101, WM_SETTEXT, 0, (LPARAM)"caf\xE9 A");
    line("SendDlgItemMessageA(101, WM_SETTEXT, \"caf<E9> A\"): ret=%ld err=%s", (long)r, le());
    arm();
    r = send_a(dlg, 101, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageA(101, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    memset(abuf, 0, sizeof abuf);
    arm();
    r = send_a(dlg, 101, WM_GETTEXT, sizeof abuf, (LPARAM)abuf);
    line("SendDlgItemMessageA(101, WM_GETTEXT, 32): ret=%ld err=%s \"%s\"", (long)r, le(), bytes(abuf));
    memset(abuf, 0, sizeof abuf);
    arm();
    r = send_a(dlg, 101, WM_GETTEXT, 4, (LPARAM)abuf);
    line("SendDlgItemMessageA(101, WM_GETTEXT, 4): ret=%ld err=%s \"%s\"", (long)r, le(), bytes(abuf));
    memset(wbuf, 0, sizeof wbuf);
    arm();
    r = (LONG)SendDlgItemMessageW(dlg, 101, WM_GETTEXT, 32, (LPARAM)wbuf);
    line("SendDlgItemMessageW(101, WM_GETTEXT, 32): ret=%ld err=%s \"%s\"", (long)r, le(), ws(wbuf));
    arm();
    r = (LONG)SendDlgItemMessageW(dlg, 101, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageW(101, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    arm();
    r = send_a(dlg, IDOK, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageA(IDOK, WM_GETTEXTLENGTH): ret=%ld err=%s", (long)r, le());
    arm();
    r = send_a(dlg, 999, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageA(999, a missing id): ret=%ld err=%s", (long)r, le());
    arm();
    r = (LONG)SendDlgItemMessageW(dlg, 999, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageW(999, a missing id): ret=%ld err=%s", (long)r, le());
    arm();
    r = send_a(NULL, 101, WM_GETTEXTLENGTH, 0, 0);
    line("SendDlgItemMessageA(NULL, 101): ret=%ld err=%s", (long)r, le());
    close_dialog(dlg);
}

/* --- alias ----------------------------------------------------------------- */

/* Post Tab's down and up to the focus, then pump them through `fn`. */
static void tab_through(HWND dlg, is_dialog_message_t fn, const char *name)
{
    HWND focus = GetFocus();
    MSG m;
    BOOL r;

    PostMessageW(focus, WM_KEYDOWN, VK_TAB, 0x000F0001);
    PostMessageW(focus, WM_KEYUP, VK_TAB, 0xC00F0001);
    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        if (m.message != WM_KEYDOWN && m.message != WM_KEYUP) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
            continue;
        }
        arm();
        r = fn(dlg, &m);
        line("%s(dlg, %s Tab to %s): ret=%d err=%s", name, m.message == WM_KEYDOWN ? "WM_KEYDOWN" : "WM_KEYUP",
             who(dlg, m.hwnd), r, le());
        if (!r) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
    line("  the focus after: %s", who(dlg, GetFocus()));
}

static void sec_alias(void)
{
    is_dialog_message_t alias;
    HWND dlg, other;
    MSG m;
    BOOL r;

    drain();
    alias = (is_dialog_message_t)user32_export("IsDialogMessage");
    if (alias == NULL) {
        return;
    }
    dlg = order_dialog();
    if (dlg == NULL) {
        return;
    }
    SetFocus(GetDlgItem(dlg, 201));
    line("SetFocus(201): the focus %s", who(dlg, GetFocus()));
    tab_through(dlg, alias, "IsDialogMessage");
    tab_through(dlg, (is_dialog_message_t)IsDialogMessageA, "IsDialogMessageA");

    other = CreateWindowExW(0, L"Button", L"outside", WS_POPUP, 0, 0, 40, 20, NULL, NULL, instance(),
                            NULL);
    PostMessageW(other, WM_KEYDOWN, VK_TAB, 0x000F0001);
    if (PeekMessageW(&m, other, WM_KEYDOWN, WM_KEYDOWN, PM_REMOVE)) {
        arm();
        r = alias(dlg, &m);
        line("IsDialogMessage(dlg, WM_KEYDOWN Tab to a popup outside it): ret=%d err=%s", r, le());
        arm();
        r = IsDialogMessageA(dlg, &m);
        line("IsDialogMessageA(dlg, the same): ret=%d err=%s", r, le());
    }
    DestroyWindow(other);
    line("  the focus after: %s", who(dlg, GetFocus()));
    close_dialog(dlg);
}

/* --- message boxes ---------------------------------------------------------- */

#define MAX_BOX_CONTROLS 8
#define BOX_TICK_MS 100
#define BOX_TRIES 50            /* five seconds to find the box */
#define BOX_GRACE_TRIES 20      /* two seconds for it to go after a post */

static HANDLE box_thread;
static DWORD box_owner;
static const WCHAR *box_title;
static int box_answer;
static int box_found;
static int box_closed;
static int box_gave_up;
static char box_caption[128];
static char box_controls[MAX_BOX_CONTROLS][160];
static int box_control_count;

static void record_box(HWND box)
{
    HWND c;
    int i = 0;

    sprintf(box_caption, "%.120s", text_of(box));
    for (c = GetWindow(box, GW_CHILD); c != NULL && i < MAX_BOX_CONTROLS; c = GetWindow(c, GW_HWNDNEXT)) {
        sprintf(box_controls[i], "class %.40s id=%d style=0x%08lX text \"%.80s\"", class_of(c),
                GetDlgCtrlID(c), (unsigned long)GetWindowLongW(c, GWL_STYLE), text_of(c));
        i++;
    }
    box_control_count = i;
}

static int box_outlasts(HWND box, int tries)
{
    int i;

    for (i = 0; i < tries; i++) {
        Sleep(BOX_TICK_MS);
        if (!IsWindow(box)) {
            return 0;
        }
    }
    return 1;
}

static DWORD WINAPI box_watch(LPVOID unused)
{
    HWND box = NULL;
    HWND button;
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
    button = GetDlgItem(box, box_answer);
    PostMessageW(box, WM_COMMAND, MAKEWPARAM(box_answer, BN_CLICKED), (LPARAM)button);
    if (!box_outlasts(box, BOX_GRACE_TRIES)) {
        return 0;
    }
    box_closed = 1;
    PostMessageW(box, WM_CLOSE, 0, 0);
    if (!box_outlasts(box, BOX_GRACE_TRIES)) {
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
        line("  box: caption \"%s\", %d controls", box_caption, box_control_count);
        for (i = 0; i < box_control_count; i++) {
            line("    %s", box_controls[i]);
        }
    }
    while (PeekMessageW(&m, NULL, WM_QUIT, WM_QUIT, PM_REMOVE)) {
    }
}

static const struct {
    WORD lang;
    const char *name;
} langs[3] = {
    { 0, "0" },
    { MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), "English (US)" },
    { MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH), "French" },
};

static void sec_msgboxex(void)
{
    message_box_ex_w_t w;
    message_box_ex_a_t a;
    int i, r;

    drain();
    w = (message_box_ex_w_t)user32_export("MessageBoxExW");
    a = (message_box_ex_a_t)user32_export("MessageBoxExA");
    for (i = 0; w != NULL && i < 3; i++) {
        arm_box(L"F2K dialog2 box ex", IDCANCEL);
        arm();
        r = w(NULL, L"F2K box \x00E9", L"F2K dialog2 box ex", MB_OKCANCEL, langs[i].lang);
        line("MessageBoxExW(NULL, MB_OKCANCEL, language %s), IDCANCEL posted: ret=%d err=%s",
             langs[i].name, r, le());
        print_box();
    }
    for (i = 0; a != NULL && i < 3; i++) {
        arm_box(L"F2K dialog2 box ex A", IDOK);
        arm();
        r = a(NULL, "F2K narrow box", "F2K dialog2 box ex A", MB_OK, langs[i].lang);
        line("MessageBoxExA(NULL, MB_OK, language %s), IDOK posted: ret=%d err=%s", langs[i].name, r,
             le());
        print_box();
    }
}

static void sec_msgboxind(void)
{
    message_box_indirect_w_t w;
    message_box_indirect_a_t a;
    MSGBOXPARAMSW pw;
    MSGBOXPARAMSA pa;
    int r;

    drain();
    w = (message_box_indirect_w_t)user32_export("MessageBoxIndirectW");
    a = (message_box_indirect_a_t)user32_export("MessageBoxIndirectA");
    if (w != NULL) {
        ZeroMemory(&pw, sizeof pw);
        pw.cbSize = sizeof pw;
        pw.lpszText = L"F2K indirect \x00E9";
        pw.lpszCaption = L"F2K dialog2 box ind";
        pw.dwStyle = MB_OKCANCEL;
        arm_box(pw.lpszCaption, IDCANCEL);
        arm();
        r = w(&pw);
        line("MessageBoxIndirectW(MB_OKCANCEL), IDCANCEL posted: ret=%d err=%s", r, le());
        print_box();

        pw.dwStyle = MB_OK | MB_USERICON;
        pw.hInstance = NULL;
        pw.lpszIcon = (LPCWSTR)IDI_EXCLAMATION;
        arm_box(pw.lpszCaption, IDOK);
        arm();
        r = w(&pw);
        line("MessageBoxIndirectW(MB_OK | MB_USERICON, NULL, IDI_EXCLAMATION), IDOK posted: ret=%d err=%s",
             r, le());
        print_box();

        pw.dwStyle = MB_OK;
        pw.lpszIcon = NULL;
        pw.cbSize = 0;
        arm_box(pw.lpszCaption, IDOK);
        arm();
        r = w(&pw);
        line("MessageBoxIndirectW(cbSize 0, MB_OK), IDOK posted: ret=%d err=%s", r, le());
        print_box();
    }
    if (a != NULL) {
        ZeroMemory(&pa, sizeof pa);
        pa.cbSize = sizeof pa;
        pa.lpszText = "F2K indirect narrow";
        pa.lpszCaption = "F2K dialog2 box ind A";
        pa.dwStyle = MB_OKCANCEL;
        arm_box(L"F2K dialog2 box ind A", IDCANCEL);
        arm();
        r = a(&pa);
        line("MessageBoxIndirectA(MB_OKCANCEL), IDCANCEL posted: ret=%d err=%s", r, le());
        print_box();

        pa.dwStyle = MB_OK | MB_USERICON;
        pa.lpszIcon = (LPCSTR)IDI_EXCLAMATION;
        arm_box(L"F2K dialog2 box ind A", IDOK);
        arm();
        r = a(&pa);
        line("MessageBoxIndirectA(MB_OK | MB_USERICON, NULL, IDI_EXCLAMATION), IDOK posted: ret=%d err=%s",
             r, le());
        print_box();
    }
}

static const section_t sections[] = {
    { "indirect", sec_indirect, F2KT_ALWAYS },
    { "ex", sec_ex, F2KT_ALWAYS },
    { "aorw", sec_aorw, F2KT_ALWAYS },
    { "modal", sec_modal, F2KT_ALWAYS },
    { "tabs", sec_tabs, F2KT_ALWAYS },
    { "groups", sec_groups, F2KT_ALWAYS },
    { "senditem", sec_senditem, F2KT_ALWAYS },
    { "alias", sec_alias, F2KT_ALWAYS },
    { "msgboxex", sec_msgboxex, F2KT_ALWAYS },
    { "msgboxind", sec_msgboxind, F2KT_ALWAYS },
    { NULL, NULL, 0 },
};

int main(int argc, char **argv)
{
    return run_sections("dialog2", sections, argc, argv);
}
