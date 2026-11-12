/*
 * controls - user32's built-in Button and Static controls as a program
 * drives them by messages: the button styles (push, default push, check
 * box, auto check box, three-state, radio and auto radio buttons, group
 * box), BM_SETCHECK/BM_GETCHECK, BM_GETSTATE/BM_SETSTATE, BM_CLICK and
 * the BN_CLICKED it sends the parent, BM_SETSTYLE and the default
 * button's style, WM_GETDLGCODE's answers; the Static styles (text,
 * frames, rectangles, icons), their text through WM_GETTEXT and
 * WM_SETTEXT, and STM_SETICON/STM_GETICON and STM_SETIMAGE/STM_GETIMAGE.
 *
 * The controls are children of a visible top-level window of the
 * section's own class (its client area at a fixed spot), whose
 * procedure records the WM_COMMAND notifications it receives: the
 * control id, the notification code, and whether lParam is that
 * control. The records print after the calls, never from inside the
 * procedure. BM_CLICK may fail when its window is not active (the
 * public documentation says so of a dialog box), so the click section
 * activates the parent first and prints whether it is the foreground
 * and the active window.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare
 * (yesno()); a control prints by its id. Every call under observation
 * is armed with the last-error sentinel and its line prints ret= and
 * err=. Styles and answers print in hex. Each section creates its
 * windows and destroys them at its end.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   a button of each style, created with CreateWindowExW (and
 *            one with CreateWindowExA and the class name "BUTTON"): its
 *            class name, style, id, text, WM_GETDLGCODE's answer,
 *            BM_GETCHECK and BM_GETSTATE
 *   check    BM_SETCHECK with BST_CHECKED, BST_INDETERMINATE and
 *            BST_UNCHECKED on each style: its return, BM_GETCHECK and
 *            BM_GETSTATE after, the radio group's checks, and any
 *            notification
 *   click    BM_CLICK on each style (the auto check box and the
 *            auto three-state one repeatedly, a radio button of the
 *            auto group, the group box, a disabled push button): the
 *            notifications, the checks after, the focus
 *   default  BM_SETSTYLE turning the push button into the default one
 *            and back, the style and WM_GETDLGCODE after each;
 *            BM_SETSTATE's pushed state and BM_GETSTATE's focus bit
 *   static   a Static of each style (SS_LEFT, SS_CENTER, SS_RIGHT,
 *            SS_SIMPLE, SS_LEFTNOWORDWRAP, SS_NOPREFIX, frames, etched
 *            lines, rectangles), created with CreateWindowExW: its class
 *            name, style, WM_GETTEXT and WM_GETTEXTLENGTH,
 *            WM_GETDLGCODE, STM_GETICON; WM_SETTEXT on a text static
 *            and a frame read back through SendMessageW and
 *            SendMessageA; one created with CreateWindowExA
 *   icon     an SS_ICON static: STM_SETICON's previous icon,
 *            STM_GETICON, its size against SM_CXICON/SM_CYICON,
 *            STM_SETIMAGE and STM_GETIMAGE with IMAGE_ICON and
 *            IMAGE_BITMAP, WM_GETDLGCODE; STM_SETICON on a text static
 *   ownerdraw  a BS_OWNERDRAW button (id 7) of the parent: InvalidateRect
 *            plus UpdateWindow sends it WM_PAINT, and the parent's
 *            recorded WM_DRAWITEM prints wParam and the whole
 *            DRAWITEMSTRUCT (CtlType, CtlID, itemID, itemAction,
 *            itemState, hwndItem against the button, hDC, rcItem in the
 *            parent's client, itemData)
 *   drawdc   the DC a BS_OWNERDRAW button's WM_DRAWITEM carries, as the
 *            parent finds it: background mode and color, text color,
 *            the font selected (the one WM_SETFONT gave the button, the
 *            stock SYSTEM_FONT or DEFAULT_GUI_FONT; its face, height
 *            and weight), the brush, and whether WM_CTLCOLORBTN came
 *            first; for a button given DEFAULT_GUI_FONT and for one
 *            given no font, against the parent's own GetDC
 *   edges    a text Static of each edge (none, SS_SUNKEN,
 *            WS_EX_STATICEDGE, WS_EX_CLIENTEDGE, WS_BORDER, and
 *            SS_SUNKEN with WS_EX_CLIENTEDGE): the style and extended
 *            style read back, the client area's inset on each side,
 *            and the edge's pixels as the screen shows them
 *   centred  a single-line text Static of each alignment, with and
 *            without SS_CENTERIMAGE, its text DEFAULT_GUI_FONT in red
 *            on blue (WM_CTLCOLORSTATIC): the rows and columns the text
 *            covers in the client area as the screen shows it
 *
 * The edges and centred sections read the screen (GetPixel on the
 * controls' DCs): the parent is made topmost first, and each control
 * prints the window WindowFromPoint finds at its centre (the control,
 * its parent, or another window), so a capture another window hid
 * shows as such.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat controls):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% controls.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate them. */
#ifndef SS_ETCHEDHORZ
#define SS_ETCHEDHORZ 0x00000010L
#endif
#ifndef SS_ETCHEDVERT
#define SS_ETCHEDVERT 0x00000011L
#endif
#ifndef SS_ETCHEDFRAME
#define SS_ETCHEDFRAME 0x00000012L
#endif
#ifndef STM_SETIMAGE
#define STM_SETIMAGE 0x0172
#endif
#ifndef STM_GETIMAGE
#define STM_GETIMAGE 0x0173
#endif
#ifndef BST_INDETERMINATE
#define BST_INDETERMINATE 0x0002
#endif
#ifndef BST_PUSHED
#define BST_PUSHED 0x0004
#endif
#ifndef BST_FOCUS
#define BST_FOCUS 0x0008
#endif
#ifndef BS_OWNERDRAW
#define BS_OWNERDRAW 0x0000000BL
#endif
#ifndef WM_DRAWITEM
#define WM_DRAWITEM 0x002B
#endif
#ifndef SS_CENTERIMAGE
#define SS_CENTERIMAGE 0x00000200L
#endif
#ifndef SS_SUNKEN
#define SS_SUNKEN 0x00001000L
#endif
#ifndef WS_EX_CLIENTEDGE
#define WS_EX_CLIENTEDGE 0x00000200L
#endif
#ifndef WS_EX_STATICEDGE
#define WS_EX_STATICEDGE 0x00020000L
#endif
#ifndef DEFAULT_GUI_FONT
#define DEFAULT_GUI_FONT 17
#endif

#define PARENT_CLASS L"F2KControlsParent"

/* The buttons: id, style (WS_CHILD | WS_VISIBLE added), text. */
typedef struct {
    int id;
    DWORD style;
    const WCHAR *text;
    const char *name;
} button_t;

static const button_t buttons[] = {
    { 101, BS_PUSHBUTTON, L"Push", "BS_PUSHBUTTON" },
    { 102, BS_DEFPUSHBUTTON, L"Default", "BS_DEFPUSHBUTTON" },
    { 103, BS_CHECKBOX, L"Check", "BS_CHECKBOX" },
    { 104, BS_AUTOCHECKBOX, L"Auto check", "BS_AUTOCHECKBOX" },
    { 105, BS_AUTORADIOBUTTON | WS_GROUP, L"Radio 1", "BS_AUTORADIOBUTTON | WS_GROUP" },
    { 106, BS_AUTORADIOBUTTON, L"Radio 2", "BS_AUTORADIOBUTTON" },
    { 107, BS_AUTORADIOBUTTON, L"Radio 3", "BS_AUTORADIOBUTTON" },
    { 108, BS_GROUPBOX | WS_GROUP, L"Group", "BS_GROUPBOX | WS_GROUP" },
    { 109, BS_3STATE, L"Three", "BS_3STATE" },
    { 110, BS_AUTO3STATE, L"Auto three", "BS_AUTO3STATE" },
    { 111, BS_RADIOBUTTON | WS_GROUP, L"Plain radio", "BS_RADIOBUTTON | WS_GROUP" },
    { 0, 0, NULL, NULL }
};

#define BUTTON_COUNT 11

/* The statics: id, style (WS_CHILD | WS_VISIBLE added), text. */
static const button_t statics[] = {
    { 201, SS_LEFT, L"Left text", "SS_LEFT" },
    { 202, SS_CENTER, L"Centred", "SS_CENTER" },
    { 203, SS_RIGHT, L"Right", "SS_RIGHT" },
    { 204, SS_SIMPLE, L"Simple", "SS_SIMPLE" },
    { 205, SS_LEFTNOWORDWRAP, L"No wrap", "SS_LEFTNOWORDWRAP" },
    { 206, SS_LEFT | SS_NOPREFIX, L"&No prefix", "SS_LEFT | SS_NOPREFIX" },
    { 207, SS_BLACKFRAME, L"frame", "SS_BLACKFRAME" },
    { 208, SS_GRAYFRAME, L"", "SS_GRAYFRAME" },
    { 209, SS_ETCHEDFRAME, L"etched", "SS_ETCHEDFRAME" },
    { 210, SS_ETCHEDHORZ, L"", "SS_ETCHEDHORZ" },
    { 211, SS_ETCHEDVERT, L"", "SS_ETCHEDVERT" },
    { 212, SS_BLACKRECT, L"rect", "SS_BLACKRECT" },
    { 213, SS_WHITERECT, L"", "SS_WHITERECT" },
    { 0, 0, NULL, NULL }
};

/* --- What the parent records --------------------------------------- */

#define MAX_COMMANDS 16

typedef struct {
    int id;
    int code;
    int from_control;
} command_t;

static command_t commands[MAX_COMMANDS];
static int command_count;

static void reset_commands(void)
{
    command_count = 0;
}

/* A WM_DRAWITEM the parent received: wParam, and the DRAWITEMSTRUCT as
 * it arrived (rcItem in the parent's client coordinates). */
#define MAX_DRAWITEMS 8

typedef struct {
    int wparam;
    UINT ctl_type;
    UINT ctl_id;
    UINT item_id;
    UINT item_action;
    UINT item_state;
    int hwnd_is_button;
    int hdc_nonnull;
    LONG left, top, right, bottom;
    UINT item_data;
    /* The DC as the parent found it, before drawing anything. */
    int bk_mode;
    COLORREF bk_color;
    COLORREF text_color;
    int getfont_null;
    int font_is_getfont;
    int font_is_system;
    int font_is_gui;
    char face[LF_FACESIZE];
    LONG tm_height;
    LONG tm_weight;
    int brush_is_white;
    int ctlcolor_before;
} drawitem_t;

static drawitem_t drawitems[MAX_DRAWITEMS];
static int drawitem_count;
static HWND ownerdraw_button;

/* The WM_CTLCOLORBTN messages the parent received; and, while the
 * centred section runs, the brush its WM_CTLCOLORSTATIC answers with
 * (red text on blue). */
static int ctlcolorbtn_count;
static HBRUSH marked_brush;

/* Whether the parent records the DC each WM_DRAWITEM carries (the
 * drawdc section alone: its reads are calls of their own). */
static int record_dc;

static LRESULT CALLBACK parent_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    command_t *c;

    if (msg == WM_COMMAND && command_count < MAX_COMMANDS) {
        c = &commands[command_count++];
        c->id = LOWORD(wparam);
        c->code = HIWORD(wparam);
        c->from_control = lparam != 0 && GetDlgItem(hwnd, LOWORD(wparam)) == (HWND)lparam;
        return 0;
    }
    if (msg == WM_DRAWITEM && drawitem_count < MAX_DRAWITEMS) {
        const DRAWITEMSTRUCT *d = (const DRAWITEMSTRUCT *)lparam;
        drawitem_t *o = &drawitems[drawitem_count++];
        HGDIOBJ font;
        HGDIOBJ given;
        TEXTMETRICA tm;

        if (record_dc) {
            font = GetCurrentObject(d->hDC, OBJ_FONT);
            given = (HGDIOBJ)SendMessageW(d->hwndItem, WM_GETFONT, 0, 0);
            ZeroMemory(&tm, sizeof tm);
            GetTextMetricsA(d->hDC, &tm);
            o->bk_mode = GetBkMode(d->hDC);
            o->bk_color = GetBkColor(d->hDC);
            o->text_color = GetTextColor(d->hDC);
            o->getfont_null = (given == NULL);
            o->font_is_getfont = (font != NULL && font == given);
            o->font_is_system = (font == GetStockObject(SYSTEM_FONT));
            o->font_is_gui = (font == GetStockObject(DEFAULT_GUI_FONT));
            o->face[0] = 0;
            GetTextFaceA(d->hDC, LF_FACESIZE, o->face);
            o->tm_height = tm.tmHeight;
            o->tm_weight = tm.tmWeight;
            o->brush_is_white = (GetCurrentObject(d->hDC, OBJ_BRUSH) == GetStockObject(WHITE_BRUSH));
            o->ctlcolor_before = ctlcolorbtn_count;
        }
        o->wparam = (int)wparam;
        o->ctl_type = d->CtlType;
        o->ctl_id = d->CtlID;
        o->item_id = d->itemID;
        o->item_action = d->itemAction;
        o->item_state = d->itemState;
        o->hwnd_is_button = (d->hwndItem == ownerdraw_button);
        o->hdc_nonnull = (d->hDC != NULL);
        o->left = d->rcItem.left;
        o->top = d->rcItem.top;
        o->right = d->rcItem.right;
        o->bottom = d->rcItem.bottom;
        o->item_data = d->itemData;
        return 0;
    }
    if (msg == WM_CTLCOLORBTN) {
        ctlcolorbtn_count++;
    }
    if (msg == WM_CTLCOLORSTATIC && marked_brush != NULL) {
        SetTextColor((HDC)wparam, RGB(255, 0, 0));
        SetBkColor((HDC)wparam, RGB(0, 0, 255));
        return (LRESULT)marked_brush;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void print_commands(void)
{
    int i;

    if (command_count == 0) {
        line("  the parent received no WM_COMMAND");
    }
    for (i = 0; i < command_count; i++) {
        line("  the parent received WM_COMMAND id=%d code=%d lParam is the control %s", commands[i].id,
             commands[i].code, yesno(commands[i].from_control));
    }
}

static void print_drawitems(void)
{
    int i;

    if (drawitem_count == 0) {
        line("  the parent received no WM_DRAWITEM");
    }
    for (i = 0; i < drawitem_count; i++) {
        line("  the parent received WM_DRAWITEM wParam=%d CtlType=%u CtlID=%u itemID=%u "
             "itemAction=0x%X itemState=0x%X hwndItem is the button %s hDC non-NULL %s "
             "rcItem=%ld %ld %ld %ld itemData=%u",
             drawitems[i].wparam, drawitems[i].ctl_type, drawitems[i].ctl_id, drawitems[i].item_id,
             drawitems[i].item_action, drawitems[i].item_state, yesno(drawitems[i].hwnd_is_button),
             yesno(drawitems[i].hdc_nonnull), drawitems[i].left, drawitems[i].top, drawitems[i].right,
             drawitems[i].bottom, drawitems[i].item_data);
    }
}

/* --- Helpers ----------------------------------------------------------- */

static HINSTANCE instance(void)
{
    return GetModuleHandleA(NULL);
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

/* The parent: registered (once per process) and created visible, its
 * client area 320x320 at a fixed spot. */
static HWND open_parent(void)
{
    WNDCLASSW wc;
    HWND h;
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
    line("RegisterClassW(F2KControlsParent): atom nonzero %s err=%s", yesno(a != 0), le_of(err));
    arm();
    h = CreateWindowExW(0, PARENT_CLASS, L"F2K controls", WS_POPUP | WS_BORDER | WS_VISIBLE, 40, 40,
                        322, 322, NULL, NULL, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExW(F2KControlsParent, visible): non-NULL %s err=%s", yesno(h != NULL), le_of(err));
    drain();
    reset_commands();
    return h;
}

static void close_parent(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
    drain();
}

/* A control: WS_CHILD | WS_VISIBLE and the style, 140x20 in a column. */
static HWND make_control(HWND parent, const WCHAR *cls, const button_t *b, int row)
{
    return CreateWindowExW(0, cls, b->text, WS_CHILD | WS_VISIBLE | b->style, 10 + 150 * (row / 14),
                           10 + 22 * (row % 14), 140, 20, parent, (HMENU)b->id, instance(), NULL);
}

static void make_buttons(HWND parent, HWND *out)
{
    int i;

    for (i = 0; buttons[i].id != 0; i++) {
        out[i] = make_control(parent, L"Button", &buttons[i], i);
    }
}

static const char *class_of(HWND h)
{
    static WCHAR buf[2][64];
    static int next;
    WCHAR *b = buf[next++ & 1];

    b[0] = 0;
    GetClassNameW(h, b, 64);
    return ws(b);
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

static void print_radios(HWND *b)
{
    line("  checks: 105=%ld 106=%ld 107=%ld", (long)SendMessageW(b[4], BM_GETCHECK, 0, 0),
         (long)SendMessageW(b[5], BM_GETCHECK, 0, 0), (long)SendMessageW(b[6], BM_GETCHECK, 0, 0));
}

/* --- create ------------------------------------------------------------ */

static void sec_create(void)
{
    HWND parent;
    HWND h[BUTTON_COUNT];
    HWND a;
    WCHAR text[64];
    int i;
    LRESULT code;
    LRESULT check;
    LRESULT state;
    DWORD err;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    for (i = 0; buttons[i].id != 0; i++) {
        arm();
        h[i] = make_control(parent, L"Button", &buttons[i], i);
        err = GetLastError();
        line("CreateWindowExW(\"Button\", %s, id %d): non-NULL %s err=%s", buttons[i].name, buttons[i].id,
             yesno(h[i] != NULL), le_of(err));
        if (h[i] == NULL) {
            continue;
        }
        text[0] = 0;
        GetWindowTextW(h[i], text, 64);
        line("  class %s style=0x%08lX id=%ld text \"%s\"", class_of(h[i]),
             (unsigned long)GetWindowLongW(h[i], GWL_STYLE), (long)GetWindowLongW(h[i], GWL_ID), ws(text));
        arm();
        code = SendMessageW(h[i], WM_GETDLGCODE, 0, 0);
        line("  WM_GETDLGCODE: ret=0x%04lX err=%s", (unsigned long)code, le());
        arm();
        check = SendMessageW(h[i], BM_GETCHECK, 0, 0);
        line("  BM_GETCHECK: ret=%ld err=%s", (long)check, le());
        arm();
        state = SendMessageW(h[i], BM_GETSTATE, 0, 0);
        line("  BM_GETSTATE: ret=0x%04lX err=%s", (unsigned long)state, le());
    }
    arm();
    a = CreateWindowExA(0, "BUTTON", "Narrow", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 170, 10, 140, 20,
                        parent, (HMENU)120, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExA(\"BUTTON\", BS_PUSHBUTTON, id 120): non-NULL %s err=%s", yesno(a != NULL),
         le_of(err));
    if (a != NULL) {
        line("  class %s style=0x%08lX IsWindowUnicode %s", class_of(a),
             (unsigned long)GetWindowLongW(a, GWL_STYLE), yesno(IsWindowUnicode(a)));
    }
    drain();
    print_commands();
    close_parent(parent);
}

/* --- check ------------------------------------------------------------- */

static void set_check(HWND *h, int i, WPARAM state)
{
    LRESULT r;
    LRESULT check;
    LRESULT st;

    reset_commands();
    arm();
    r = SendMessageW(h[i], BM_SETCHECK, state, 0);
    line("BM_SETCHECK(%d, %s, %lu): ret=%ld err=%s", buttons[i].id, buttons[i].name, (unsigned long)state,
         (long)r, le());
    arm();
    check = SendMessageW(h[i], BM_GETCHECK, 0, 0);
    st = SendMessageW(h[i], BM_GETSTATE, 0, 0);
    line("  BM_GETCHECK: ret=%ld err=%s BM_GETSTATE=0x%04lX", (long)check, le(), (unsigned long)st);
    drain();
    print_commands();
}

static void sec_check(void)
{
    HWND parent;
    HWND h[BUTTON_COUNT];
    int i;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    make_buttons(parent, h);
    drain();
    for (i = 0; buttons[i].id != 0; i++) {
        if (h[i] == NULL) {
            line("button %d not created", buttons[i].id);
            continue;
        }
        set_check(h, i, BST_CHECKED);
        set_check(h, i, BST_INDETERMINATE);
        set_check(h, i, BST_UNCHECKED);
    }
    set_check(h, 4, BST_CHECKED);
    set_check(h, 5, BST_CHECKED);
    line("the auto radio group after checking 105 then 106 by BM_SETCHECK:");
    print_radios(h);
    close_parent(parent);
}

/* --- click ------------------------------------------------------------- */

static void click(HWND *h, int i, const char *what)
{
    LRESULT r;

    reset_commands();
    arm();
    r = SendMessageW(h[i], BM_CLICK, 0, 0);
    line("BM_CLICK(%d, %s%s): ret=%ld err=%s", buttons[i].id, buttons[i].name, what, (long)r, le());
    drain();
    print_commands();
    line("  BM_GETCHECK=%ld BM_GETSTATE=0x%04lX focus %s", (long)SendMessageW(h[i], BM_GETCHECK, 0, 0),
         (unsigned long)SendMessageW(h[i], BM_GETSTATE, 0, 0), focus_label());
}

static void sec_click(void)
{
    HWND parent;
    HWND h[BUTTON_COUNT];
    int i;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    make_buttons(parent, h);
    for (i = 0; i < BUTTON_COUNT; i++) {
        if (h[i] == NULL) {
            line("button %d not created", buttons[i].id);
            close_parent(parent);
            return;
        }
    }
    SetForegroundWindow(parent);
    SetActiveWindow(parent);
    drain();
    line("the parent: foreground %s active %s", yesno(GetForegroundWindow() == parent),
         yesno(GetActiveWindow() == parent));

    click(h, 0, "");
    click(h, 1, "");
    click(h, 2, "");
    click(h, 3, "");
    click(h, 3, ", again");
    click(h, 5, "");
    print_radios(h);
    click(h, 6, "");
    print_radios(h);
    click(h, 7, "");
    click(h, 8, "");
    click(h, 9, "");
    click(h, 9, ", again");
    click(h, 9, ", a third time");
    click(h, 10, "");
    EnableWindow(h[0], FALSE);
    click(h, 0, ", disabled");
    close_parent(parent);
}

/* --- default ----------------------------------------------------------- */

static void set_style(HWND *h, int i, DWORD style, const char *name)
{
    LRESULT r;

    arm();
    r = SendMessageW(h[i], BM_SETSTYLE, style, TRUE);
    line("BM_SETSTYLE(%d, %s, redraw): ret=%ld err=%s", buttons[i].id, name, (long)r, le());
    line("  style=0x%08lX WM_GETDLGCODE=0x%04lX", (unsigned long)GetWindowLongW(h[i], GWL_STYLE),
         (unsigned long)SendMessageW(h[i], WM_GETDLGCODE, 0, 0));
}

static void sec_default(void)
{
    HWND parent;
    HWND h[BUTTON_COUNT];
    LRESULT r;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    make_buttons(parent, h);
    if (h[0] == NULL || h[1] == NULL || h[3] == NULL) {
        line("buttons not created");
        close_parent(parent);
        return;
    }
    set_style(h, 0, BS_DEFPUSHBUTTON, "BS_DEFPUSHBUTTON");
    set_style(h, 1, BS_PUSHBUTTON, "BS_PUSHBUTTON");
    set_style(h, 0, BS_PUSHBUTTON, "BS_PUSHBUTTON");
    set_style(h, 3, BS_CHECKBOX, "BS_CHECKBOX");

    arm();
    r = SendMessageW(h[0], BM_SETSTATE, TRUE, 0);
    line("BM_SETSTATE(101, TRUE): ret=%ld err=%s BM_GETSTATE=0x%04lX pushed %s", (long)r, le(),
         (unsigned long)SendMessageW(h[0], BM_GETSTATE, 0, 0),
         yesno((SendMessageW(h[0], BM_GETSTATE, 0, 0) & BST_PUSHED) != 0));
    arm();
    r = SendMessageW(h[0], BM_SETSTATE, FALSE, 0);
    line("BM_SETSTATE(101, FALSE): ret=%ld err=%s BM_GETSTATE=0x%04lX", (long)r, le(),
         (unsigned long)SendMessageW(h[0], BM_GETSTATE, 0, 0));
    SetFocus(h[0]);
    line("SetFocus(101): focus %s BM_GETSTATE=0x%04lX focus bit %s", focus_label(),
         (unsigned long)SendMessageW(h[0], BM_GETSTATE, 0, 0),
         yesno((SendMessageW(h[0], BM_GETSTATE, 0, 0) & BST_FOCUS) != 0));
    drain();
    print_commands();
    close_parent(parent);
}

/* --- static ------------------------------------------------------------ */

static void sec_static(void)
{
    HWND parent;
    HWND s;
    HWND first = NULL;
    HWND frame = NULL;
    HWND a;
    WCHAR wbuf[64];
    char abuf[64];
    LRESULT r;
    DWORD err;
    int i;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    for (i = 0; statics[i].id != 0; i++) {
        arm();
        s = make_control(parent, L"Static", &statics[i], i);
        err = GetLastError();
        line("CreateWindowExW(\"Static\", %s, id %d): non-NULL %s err=%s", statics[i].name, statics[i].id,
             yesno(s != NULL), le_of(err));
        if (s == NULL) {
            continue;
        }
        if (i == 0) {
            first = s;
        }
        if (statics[i].id == 207) {
            frame = s;
        }
        wbuf[0] = 0;
        arm();
        r = SendMessageW(s, WM_GETTEXT, 64, (LPARAM)wbuf);
        line("  class %s style=0x%08lX WM_GETTEXT: ret=%ld err=%s \"%s\"", class_of(s),
             (unsigned long)GetWindowLongW(s, GWL_STYLE), (long)r, le(), ws(wbuf));
        line("  WM_GETTEXTLENGTH=%ld WM_GETDLGCODE=0x%04lX STM_GETICON non-NULL %s",
             (long)SendMessageW(s, WM_GETTEXTLENGTH, 0, 0), (unsigned long)SendMessageW(s, WM_GETDLGCODE, 0, 0),
             yesno(SendMessageW(s, STM_GETICON, 0, 0) != 0));
    }

    if (first != NULL) {
        arm();
        r = SendMessageW(first, WM_SETTEXT, 0, (LPARAM)L"New <\x00E9> text");
        line("WM_SETTEXT(201, L\"New <U+00E9> text\"): ret=%ld err=%s", (long)r, le());
        wbuf[0] = 0;
        arm();
        r = SendMessageW(first, WM_GETTEXT, 64, (LPARAM)wbuf);
        line("  SendMessageW WM_GETTEXT: ret=%ld err=%s \"%s\"", (long)r, le(), ws(wbuf));
        abuf[0] = 0;
        arm();
        r = SendMessageA(first, WM_GETTEXT, 64, (LPARAM)abuf);
        line("  SendMessageA WM_GETTEXT: ret=%ld err=%s \"%s\"", (long)r, le(), abuf);
        lstrcpyW(wbuf, L"xxxxxxxx");
        arm();
        r = SendMessageW(first, WM_GETTEXT, 4, (LPARAM)wbuf);
        line("  SendMessageW WM_GETTEXT, 4 units: ret=%ld err=%s \"%s\"", (long)r, le(), ws(wbuf));
        arm();
        r = SendMessageA(first, WM_GETTEXTLENGTH, 0, 0);
        line("  SendMessageA WM_GETTEXTLENGTH: ret=%ld err=%s", (long)r, le());
    }
    if (frame != NULL) {
        arm();
        r = SendMessageW(frame, WM_SETTEXT, 0, (LPARAM)L"framed");
        wbuf[0] = 0;
        SendMessageW(frame, WM_GETTEXT, 64, (LPARAM)wbuf);
        line("WM_SETTEXT(207, SS_BLACKFRAME, L\"framed\"): ret=%ld err=%s read back \"%s\"", (long)r, le(),
             ws(wbuf));
    }
    arm();
    a = CreateWindowExA(0, "STATIC", "Narrow static", WS_CHILD | WS_VISIBLE | SS_LEFT, 170, 300, 140, 20,
                        parent, (HMENU)220, instance(), NULL);
    err = GetLastError();
    line("CreateWindowExA(\"STATIC\", SS_LEFT, id 220): non-NULL %s err=%s", yesno(a != NULL), le_of(err));
    if (a != NULL) {
        wbuf[0] = 0;
        SendMessageW(a, WM_GETTEXT, 64, (LPARAM)wbuf);
        line("  class %s IsWindowUnicode %s WM_GETTEXT \"%s\"", class_of(a), yesno(IsWindowUnicode(a)),
             ws(wbuf));
    }
    drain();
    print_commands();
    close_parent(parent);
}

/* --- icon -------------------------------------------------------------- */

static void print_size(HWND s)
{
    RECT r;

    GetWindowRect(s, &r);
    line("  size minus (SM_CXICON, SM_CYICON): %ld %ld", (r.right - r.left) - GetSystemMetrics(SM_CXICON),
         (r.bottom - r.top) - GetSystemMetrics(SM_CYICON));
}

static void sec_icon(void)
{
    HWND parent;
    HWND s;
    HWND text;
    HICON app;
    HICON hand;
    LRESULT r;
    DWORD err;

    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    app = LoadIconW(NULL, MAKEINTRESOURCEW(32512));
    hand = LoadIconW(NULL, MAKEINTRESOURCEW(32513));
    line("LoadIconW(NULL, IDI_APPLICATION) non-NULL %s, IDI_HAND non-NULL %s, the same %s",
         yesno(app != NULL), yesno(hand != NULL), yesno(app == hand));
    arm();
    s = CreateWindowExW(0, L"Static", L"", WS_CHILD | WS_VISIBLE | SS_ICON, 10, 10, 0, 0, parent, (HMENU)301,
                        instance(), NULL);
    err = GetLastError();
    line("CreateWindowExW(\"Static\", SS_ICON, empty text, 0x0): non-NULL %s err=%s", yesno(s != NULL),
         le_of(err));
    if (s == NULL) {
        close_parent(parent);
        return;
    }
    line("  style=0x%08lX WM_GETDLGCODE=0x%04lX", (unsigned long)GetWindowLongW(s, GWL_STYLE),
         (unsigned long)SendMessageW(s, WM_GETDLGCODE, 0, 0));
    arm();
    r = SendMessageW(s, STM_GETICON, 0, 0);
    line("STM_GETICON: non-NULL %s err=%s", yesno(r != 0), le());

    arm();
    r = SendMessageW(s, STM_SETICON, (WPARAM)app, 0);
    line("STM_SETICON(IDI_APPLICATION): previous non-NULL %s err=%s", yesno(r != 0), le());
    arm();
    r = SendMessageW(s, STM_GETICON, 0, 0);
    line("STM_GETICON: == IDI_APPLICATION %s err=%s", yesno((HICON)r == app), le());
    print_size(s);

    arm();
    r = SendMessageW(s, STM_SETIMAGE, IMAGE_ICON, (LPARAM)hand);
    line("STM_SETIMAGE(IMAGE_ICON, IDI_HAND): previous == IDI_APPLICATION %s non-NULL %s err=%s",
         yesno((HICON)r == app), yesno(r != 0), le());
    arm();
    r = SendMessageW(s, STM_GETIMAGE, IMAGE_ICON, 0);
    line("STM_GETIMAGE(IMAGE_ICON): == IDI_HAND %s err=%s", yesno((HICON)r == hand), le());
    arm();
    r = SendMessageW(s, STM_GETICON, 0, 0);
    line("STM_GETICON: == IDI_HAND %s err=%s", yesno((HICON)r == hand), le());
    arm();
    r = SendMessageW(s, STM_GETIMAGE, IMAGE_BITMAP, 0);
    line("STM_GETIMAGE(IMAGE_BITMAP): non-NULL %s err=%s", yesno(r != 0), le());
    arm();
    r = SendMessageW(s, STM_SETICON, 0, 0);
    line("STM_SETICON(NULL): previous == IDI_HAND %s err=%s", yesno((HICON)r == hand), le());
    arm();
    r = SendMessageW(s, STM_GETICON, 0, 0);
    line("STM_GETICON: non-NULL %s err=%s", yesno(r != 0), le());

    text = CreateWindowExW(0, L"Static", L"Text", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 60, 140, 20, parent,
                           (HMENU)302, instance(), NULL);
    if (text != NULL) {
        arm();
        r = SendMessageW(text, STM_SETICON, (WPARAM)app, 0);
        line("STM_SETICON(IDI_APPLICATION) on an SS_LEFT static: previous non-NULL %s err=%s",
             yesno(r != 0), le());
        arm();
        r = SendMessageW(text, STM_GETICON, 0, 0);
        line("  STM_GETICON: == IDI_APPLICATION %s non-NULL %s err=%s style=0x%08lX", yesno((HICON)r == app),
             yesno(r != 0), le(), (unsigned long)GetWindowLongW(text, GWL_STYLE));
    }
    drain();
    print_commands();
    close_parent(parent);
}

/* --- ownerdraw --------------------------------------------------------- */

/* A BS_OWNERDRAW button (id 7) of the parent: InvalidateRect arms it and
 * UpdateWindow sends the WM_PAINT, which the button answers with
 * WM_DRAWITEM to the parent; the records print after. */
static void sec_ownerdraw(void)
{
    HWND parent;
    HWND b;
    BOOL r;

    drain();
    parent = open_parent();
    reset_commands();
    drawitem_count = 0;
    ownerdraw_button = NULL;
    arm();
    b = CreateWindowExW(0, L"Button", L"Draw me", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 10, 10, 140,
                        20, parent, (HMENU)7, instance(), NULL);
    line("CreateWindowExW(Button, WS_CHILD|WS_VISIBLE|BS_OWNERDRAW, id 7): non-NULL %s err=%s id=%d",
         yesno(b != NULL), le(), b != NULL ? (int)GetWindowLongW(b, GWL_ID) : 0);
    ownerdraw_button = b;
    drain();
    arm();
    r = InvalidateRect(b, NULL, TRUE);
    line("InvalidateRect(the button, NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    r = UpdateWindow(b);
    line("UpdateWindow(the button): ret=%d err=%s", r, le());
    print_drawitems();
    close_parent(parent);
}

/* --- drawdc ------------------------------------------------------------ */

/* Whether two channels are within `slack` of each other. */
static int within(int a, int b, int slack)
{
    return a - b <= slack && b - a <= slack;
}

/* The system colors a color is, by name: those whose GetSysColor is
 * within `slack` of it on each channel (0: exactly), or "none";
 * CLR_INVALID as such (a pixel GetPixel cannot read). */
static const char *colors_of(COLORREF c, int slack)
{
    static const struct {
        int index;
        const char *name;
    } named[] = {
        { COLOR_BTNFACE, "BTNFACE" },
        { COLOR_BTNSHADOW, "BTNSHADOW" },
        { COLOR_BTNHIGHLIGHT, "BTNHIGHLIGHT" },
        { COLOR_3DDKSHADOW, "3DDKSHADOW" },
        { COLOR_3DLIGHT, "3DLIGHT" },
        { COLOR_BTNTEXT, "BTNTEXT" },
        { COLOR_WINDOW, "WINDOW" },
        { COLOR_WINDOWTEXT, "WINDOWTEXT" },
        { COLOR_WINDOWFRAME, "WINDOWFRAME" },
        { -1, NULL }
    };
    static char buf[8][160];
    static int next;
    char *b = buf[next++ & 7];
    COLORREF s;
    int i;

    if (c == CLR_INVALID) {
        return "CLR_INVALID";
    }
    b[0] = 0;
    for (i = 0; named[i].name != NULL; i++) {
        s = GetSysColor(named[i].index);
        if (within(GetRValue(s), GetRValue(c), slack) && within(GetGValue(s), GetGValue(c), slack)
            && within(GetBValue(s), GetBValue(c), slack)) {
            if (b[0] != 0) {
                lstrcatA(b, " ");
            }
            lstrcatA(b, named[i].name);
        }
    }
    if (b[0] == 0) {
        lstrcpyA(b, "none");
    }
    return b;
}

static void print_dc_states(void)
{
    int i;

    if (drawitem_count == 0) {
        line("  the parent received no WM_DRAWITEM");
    }
    for (i = 0; i < drawitem_count; i++) {
        line("  WM_DRAWITEM CtlID=%u: WM_CTLCOLORBTN before it %d", drawitems[i].ctl_id,
             drawitems[i].ctlcolor_before);
        line("    bk mode %d bk color 0x%06lX (%s) text color 0x%06lX (%s)", drawitems[i].bk_mode,
             (unsigned long)drawitems[i].bk_color, colors_of(drawitems[i].bk_color, 0),
             (unsigned long)drawitems[i].text_color, colors_of(drawitems[i].text_color, 0));
        line("    font: WM_GETFONT NULL %s, the WM_GETFONT one %s, SYSTEM_FONT %s, DEFAULT_GUI_FONT %s",
             yesno(drawitems[i].getfont_null), yesno(drawitems[i].font_is_getfont),
             yesno(drawitems[i].font_is_system), yesno(drawitems[i].font_is_gui));
        line("    face \"%s\" height %ld weight %ld; brush WHITE_BRUSH %s", drawitems[i].face,
             drawitems[i].tm_height, drawitems[i].tm_weight, yesno(drawitems[i].brush_is_white));
    }
}

/* Two BS_OWNERDRAW buttons, id 8 given DEFAULT_GUI_FONT by WM_SETFONT
 * and id 9 given none, each painted through InvalidateRect and
 * UpdateWindow; the parent records the DC each WM_DRAWITEM carries
 * before drawing anything. The parent's own GetDC prints first, the
 * state a fresh DC starts in. */
static void sec_drawdc(void)
{
    HWND parent;
    HWND a;
    HWND b;
    HDC dc;
    HGDIOBJ gui;
    TEXTMETRICA tm;
    char face[LF_FACESIZE];
    LRESULT r;

    drain();
    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    gui = GetStockObject(DEFAULT_GUI_FONT);
    line("GetStockObject(DEFAULT_GUI_FONT) non-NULL %s, the same as SYSTEM_FONT %s", yesno(gui != NULL),
         yesno(gui == GetStockObject(SYSTEM_FONT)));
    dc = GetDC(parent);
    ZeroMemory(&tm, sizeof tm);
    GetTextMetricsA(dc, &tm);
    face[0] = 0;
    GetTextFaceA(dc, LF_FACESIZE, face);
    line("the parent's GetDC: bk mode %d bk color 0x%06lX (%s) text color 0x%06lX (%s)", GetBkMode(dc),
         (unsigned long)GetBkColor(dc), colors_of(GetBkColor(dc), 0), (unsigned long)GetTextColor(dc),
         colors_of(GetTextColor(dc), 0));
    line("  font SYSTEM_FONT %s face \"%s\" height %ld weight %ld; brush WHITE_BRUSH %s",
         yesno(GetCurrentObject(dc, OBJ_FONT) == GetStockObject(SYSTEM_FONT)), face, tm.tmHeight, tm.tmWeight,
         yesno(GetCurrentObject(dc, OBJ_BRUSH) == GetStockObject(WHITE_BRUSH)));
    ReleaseDC(parent, dc);

    arm();
    a = CreateWindowExW(0, L"Button", L"Font", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 10, 10, 140, 20, parent,
                        (HMENU)8, instance(), NULL);
    line("CreateWindowExW(Button, BS_OWNERDRAW, id 8): non-NULL %s err=%s", yesno(a != NULL), le());
    arm();
    b = CreateWindowExW(0, L"Button", L"No font", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 10, 40, 140, 20, parent,
                        (HMENU)9, instance(), NULL);
    line("CreateWindowExW(Button, BS_OWNERDRAW, id 9): non-NULL %s err=%s", yesno(b != NULL), le());
    if (a == NULL || b == NULL) {
        close_parent(parent);
        return;
    }
    ownerdraw_button = a;
    arm();
    r = SendMessageW(a, WM_SETFONT, (WPARAM)gui, FALSE);
    line("WM_SETFONT(id 8, DEFAULT_GUI_FONT, FALSE): ret=%ld err=%s", (long)r, le());
    line("WM_GETFONT(id 8): DEFAULT_GUI_FONT %s", yesno((HGDIOBJ)SendMessageW(a, WM_GETFONT, 0, 0) == gui));
    line("WM_GETFONT(id 9): NULL %s", yesno(SendMessageW(b, WM_GETFONT, 0, 0) == 0));
    drain();

    drawitem_count = 0;
    record_dc = 1;
    ctlcolorbtn_count = 0;
    InvalidateRect(a, NULL, TRUE);
    UpdateWindow(a);
    ctlcolorbtn_count = 0;
    InvalidateRect(b, NULL, TRUE);
    UpdateWindow(b);
    record_dc = 0;
    line("id 8 painted, then id 9:");
    print_dc_states();
    close_parent(parent);
}

/* --- edges, centred ---------------------------------------------------- */

typedef struct {
    int id;
    DWORD style;
    DWORD ex_style;
    const char *name;
} edged_t;

static const edged_t edged[] = {
    { 401, SS_LEFT, 0, "SS_LEFT" },
    { 402, SS_LEFT | SS_SUNKEN, 0, "SS_LEFT | SS_SUNKEN" },
    { 403, SS_LEFT, WS_EX_STATICEDGE, "SS_LEFT, WS_EX_STATICEDGE" },
    { 404, SS_LEFT, WS_EX_CLIENTEDGE, "SS_LEFT, WS_EX_CLIENTEDGE" },
    { 405, SS_LEFT | WS_BORDER, 0, "SS_LEFT | WS_BORDER" },
    { 406, SS_LEFT | SS_SUNKEN, WS_EX_CLIENTEDGE, "SS_LEFT | SS_SUNKEN, WS_EX_CLIENTEDGE" },
    { 0, 0, 0, NULL }
};

static const edged_t centred[] = {
    { 501, SS_LEFT, 0, "SS_LEFT" },
    { 502, SS_RIGHT, 0, "SS_RIGHT" },
    { 503, SS_LEFT | SS_CENTERIMAGE, 0, "SS_LEFT | SS_CENTERIMAGE" },
    { 504, SS_RIGHT | SS_CENTERIMAGE, 0, "SS_RIGHT | SS_CENTERIMAGE" },
    { 505, SS_CENTER | SS_CENTERIMAGE, 0, "SS_CENTER | SS_CENTERIMAGE" },
    { 506, SS_RIGHT | SS_CENTERIMAGE, WS_EX_CLIENTEDGE, "SS_RIGHT | SS_CENTERIMAGE, WS_EX_CLIENTEDGE" },
    { 0, 0, 0, NULL }
};

/* The parent made topmost (not activated), so the screen shows its
 * controls whatever window is in the foreground. */
static void raise_parent(HWND parent)
{
    BOOL r;

    arm();
    r = SetWindowPos(parent, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    line("SetWindowPos(the parent, HWND_TOPMOST, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE): ret=%d err=%s", r, le());
}

/* A control painted (its frame and client) and on the screen: the
 * window WindowFromPoint finds at its centre. */
static void paint_and_find(HWND parent, HWND s)
{
    RECT wr;
    POINT p;
    HWND found;

    UpdateWindow(s);
    drain();
    GetWindowRect(s, &wr);
    p.x = (wr.left + wr.right) / 2;
    p.y = (wr.top + wr.bottom) / 2;
    found = WindowFromPoint(p);
    line("  WindowFromPoint(its centre): %s",
         found == s ? "the control" : found == parent ? "its parent" : "another window");
}

/* A Static of `e`, 120x30, its text "0.". */
static HWND make_edged(HWND parent, const edged_t *e, int row)
{
    return CreateWindowExW(e->ex_style, L"Static", L"0.", WS_CHILD | WS_VISIBLE | e->style, 10 + 150 * (row / 7),
                           10 + 40 * (row % 7), 120, 30, parent, (HMENU)e->id, instance(), NULL);
}

static void sec_edges(void)
{
    HWND parent;
    HWND s;
    HDC dc;
    RECT wr;
    RECT cr;
    POINT origin;
    LONG w;
    LONG h;
    int i;

    drain();
    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    raise_parent(parent);
    for (i = 0; edged[i].id != 0; i++) {
        arm();
        s = make_edged(parent, &edged[i], i);
        line("CreateWindowExW(\"Static\", %s, id %d, 120x30): non-NULL %s err=%s", edged[i].name, edged[i].id,
             yesno(s != NULL), le());
        if (s == NULL) {
            continue;
        }
        line("  style=0x%08lX ex style=0x%08lX", (unsigned long)GetWindowLongW(s, GWL_STYLE),
             (unsigned long)GetWindowLongW(s, GWL_EXSTYLE));
        GetWindowRect(s, &wr);
        GetClientRect(s, &cr);
        origin.x = 0;
        origin.y = 0;
        ClientToScreen(s, &origin);
        w = wr.right - wr.left;
        h = wr.bottom - wr.top;
        line("  client %ldx%ld, inset left %ld top %ld right %ld bottom %ld", cr.right, cr.bottom,
             origin.x - wr.left, origin.y - wr.top, wr.right - (origin.x + cr.right),
             wr.bottom - (origin.y + cr.bottom));
        paint_and_find(parent, s);
        dc = GetWindowDC(s);
        line("  the window's pixels: (0,0) %s; (1,1) %s; (2,2) %s", colors_of(GetPixel(dc, 0, 0), 8),
             colors_of(GetPixel(dc, 1, 1), 8), colors_of(GetPixel(dc, 2, 2), 8));
        line("    (w-1,h-1) %s; (w-2,h-2) %s; (w-3,h-3) %s; (w-1,0) %s; (0,h-1) %s",
             colors_of(GetPixel(dc, w - 1, h - 1), 8), colors_of(GetPixel(dc, w - 2, h - 2), 8),
             colors_of(GetPixel(dc, w - 3, h - 3), 8), colors_of(GetPixel(dc, w - 1, 0), 8),
             colors_of(GetPixel(dc, 0, h - 1), 8));
        ReleaseDC(s, dc);
    }
    close_parent(parent);
}

/* Red: the text WM_CTLCOLORSTATIC asks for (a channel's slack of 16,
 * for a screen of fewer colors). */
static int is_red(COLORREF c)
{
    return GetRValue(c) >= 0xF0 && GetGValue(c) <= 0x10 && GetBValue(c) <= 0x10;
}

static int is_blue(COLORREF c)
{
    return GetRValue(c) <= 0x10 && GetGValue(c) <= 0x10 && GetBValue(c) >= 0xF0;
}

static void sec_centred(void)
{
    HWND parent;
    HWND s;
    HDC dc;
    HGDIOBJ gui;
    HGDIOBJ old;
    RECT cr;
    SIZE extent;
    TEXTMETRICA tm;
    COLORREF c;
    int x;
    int y;
    int top;
    int bottom;
    int left;
    int right;
    int red;
    int blue;
    int other;
    int i;

    drain();
    parent = open_parent();
    if (parent == NULL) {
        return;
    }
    raise_parent(parent);
    gui = GetStockObject(DEFAULT_GUI_FONT);
    dc = GetDC(parent);
    old = SelectObject(dc, gui);
    ZeroMemory(&tm, sizeof tm);
    GetTextMetricsA(dc, &tm);
    extent.cx = 0;
    extent.cy = 0;
    GetTextExtentPoint32A(dc, "0.", 2, &extent);
    SelectObject(dc, old);
    ReleaseDC(parent, dc);
    line("DEFAULT_GUI_FONT: height %ld ascent %ld; \"0.\" extent %ldx%ld", tm.tmHeight, tm.tmAscent, extent.cx,
         extent.cy);
    marked_brush = CreateSolidBrush(RGB(0, 0, 255));
    for (i = 0; centred[i].id != 0; i++) {
        arm();
        s = make_edged(parent, &centred[i], i);
        line("CreateWindowExW(\"Static\", %s, id %d, 120x30, \"0.\"): non-NULL %s err=%s", centred[i].name,
             centred[i].id, yesno(s != NULL), le());
        if (s == NULL) {
            continue;
        }
        SendMessageW(s, WM_SETFONT, (WPARAM)gui, FALSE);
        InvalidateRect(s, NULL, TRUE);
        paint_and_find(parent, s);
        GetClientRect(s, &cr);
        dc = GetDC(s);
        top = -1;
        bottom = -1;
        left = -1;
        right = -1;
        red = 0;
        blue = 0;
        other = 0;
        for (y = 0; y < cr.bottom; y++) {
            for (x = 0; x < cr.right; x++) {
                c = GetPixel(dc, x, y);
                if (is_red(c)) {
                    red++;
                    if (top < 0) {
                        top = y;
                    }
                    bottom = y;
                    if (left < 0 || x < left) {
                        left = x;
                    }
                    if (x > right) {
                        right = x;
                    }
                } else if (is_blue(c)) {
                    blue++;
                } else {
                    other++;
                }
            }
        }
        ReleaseDC(s, dc);
        line("  client %ldx%ld: red %d blue %d other %d", cr.right, cr.bottom, red, blue, other);
        if (red > 0) {
            line("  the text's rows %d..%d (above it %d, below it %ld), columns %d..%d (left of it %d, right of "
                 "it %ld)",
                 top, bottom, top, cr.bottom - 1 - bottom, left, right, left, cr.right - 1 - right);
        }
    }
    close_parent(parent);
    DeleteObject(marked_brush);
    marked_brush = NULL;
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "check", sec_check, F2KT_ALWAYS },
    { "click", sec_click, F2KT_ALWAYS },
    { "default", sec_default, F2KT_ALWAYS },
    { "static", sec_static, F2KT_ALWAYS },
    { "icon", sec_icon, F2KT_ALWAYS },
    { "ownerdraw", sec_ownerdraw, F2KT_ALWAYS },
    { "drawdc", sec_drawdc, F2KT_ALWAYS },
    { "edges", sec_edges, F2KT_ALWAYS },
    { "centred", sec_centred, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("controls", sections, argc, argv);
}
