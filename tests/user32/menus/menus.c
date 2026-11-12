/*
 * menus - menus loaded from the program's own MENU resource (menus.rc,
 * compiled by rc and linked in), as user32 and win32k serve them:
 * LoadMenuW/LoadMenuA, IsMenu, DestroyMenu, GetMenuItemCount,
 * GetMenuItemID, GetSubMenu, GetMenuState, GetMenuStringA/W,
 * CheckMenuItem, CheckMenuRadioItem, EnableMenuItem, and a window's
 * menu through GetMenu and SetMenu. Then how the handles of user
 * objects of different kinds relate: windows, menus (CreateMenu),
 * accelerator tables (CreateAcceleratorTableW), the stock cursor and
 * icon and a copied icon (CopyIcon); each kind's calls on the others'
 * handles, before and after many reuses of a window's slot; and the
 * handles' low words (the slot) and high words as relations. Then a
 * window's menu bar (its height in the non-client area, DrawMenuBar,
 * WM_NCHITTEST over it) and the keyboard menu loop, driven by
 * SendInput into the program's own foreground window: the messages
 * the window's procedure receives, Alt and F10 to the menu, the
 * mnemonics, the arrows, Enter and Esc.
 *
 * Menu 200 (menus.rc), by position: 0 "&File", a popup holding &New
 * (201), &Open (202, grayed), a separator, &Recent (a popup holding
 * First, 205) and E&xit (203, checked); 1 "&View", a popup holding
 * &Standard (211, checked), S&cientific (212) and &Programmer (213);
 * 2 "&Help" (220), an item of the bar itself. 299 names no item and no
 * resource.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare
 * (yesno()); every call under observation is armed with the last-error
 * sentinel and its line prints ret= and err=. Menu states and flags
 * print in hex, the -1 answers as -1. A string a call fills is printed
 * from a buffer holding "########" before the call, so what it left
 * there shows. Each section through window, and kinds, loads its own
 * copy of menu 200 and destroys it at its end; the window section's
 * windows are hidden, of a class it registers itself. A handle's low
 * and high words print only as relations: equal or not, and a high
 * word's change as a small number.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   load     LoadMenuW and LoadMenuA of 200 (the same menu or not), by
 *            "#200", IsMenu of each; 299, missing, through both;
 *            DestroyMenu, IsMenu after, and DestroyMenu once more
 *   items    GetMenuItemCount of the bar and the popups, and of NULL;
 *            by position: GetMenuItemID, GetMenuState, GetSubMenu and
 *            GetMenuStringW, one past the last item included;
 *            GetSubMenu twice (the same popup or not); by command,
 *            through the bar: GetMenuState, GetMenuStringW/A of items
 *            in the popups and the nested popup, and 299; short
 *            buffers and none
 *   check    CheckMenuItem's previous state by command and by position
 *            (checking, unchecking, twice, a grayed item, a popup's
 *            item of the bar, 299, a position past the end) and
 *            GetMenuState after; CheckMenuRadioItem by command and by
 *            position, through the popup and through the bar, a check
 *            outside the range, ids no item has, and the three items'
 *            states after each
 *   enable   EnableMenuItem's previous state by command and by
 *            position (MF_ENABLED, MF_DISABLED, MF_GRAYED, both;
 *            twice; a checked item; a popup's item of the bar; 299, a
 *            position past the end) and GetMenuState after
 *   window   a hidden WS_OVERLAPPEDWINDOW window: GetMenu with none,
 *            SetMenu, GetMenu (the menu or not), SetMenu(NULL) and the
 *            menu still there; the menu set again and the window
 *            destroyed: IsMenu after; a window created with the menu
 *            as its hMenu; SetMenu on a child window; SetMenu of a
 *            destroyed menu
 *   kinds    one object of each kind: a hidden popup window, a
 *            CreateMenu menu and menu 200, a one-entry accelerator
 *            table, the arrow cursor, the application icon and a
 *            CopyIcon copy (all different, their low words too);
 *            IsWindow, IsMenu, GetMenuItemCount, CopyAcceleratorTableW
 *            (NULL, 0) and GetWindowLongW(GWL_STYLE) of each;
 *            DestroyMenu, DestroyAcceleratorTable, DestroyIcon and
 *            DestroyWindow on the other kinds' handles, and every
 *            object still there after; each destroyed by its own call
 *   reuse    a window, a menu and a table held with the arrow cursor,
 *            while 40 windows, then 40 menus, then 40 tables are made
 *            and destroyed one after another: as counts, the other
 *            kinds' calls on each new handle and its own kind's call
 *            on the held objects, the new handles against the held
 *            ones and the earlier ones (different from all, in an
 *            earlier one's slot, the high word's step there), and the
 *            earlier, destroyed handles refused by their kind's call
 *   slots    8 of each of windows, menus, tables and icons alive at
 *            once (any two with the same low word); window W1, menu
 *            M, window W2 made in turn (M's low word between theirs,
 *            low(W2) - low(W1) 2); an object made at once after
 *            another's destruction, window/window, window/menu,
 *            menu/window, menu/table, window/icon, icon/window (the
 *            same low word, the high word's change); IsWindow and
 *            IsMenu of a live handle with its high word 0, 0xFFFF or
 *            one more
 *   bar      a hidden WS_OVERLAPPEDWINDOW window, 320x200, created
 *            with menu 200: the client origin's offset less the frame
 *            and caption metrics (the menu bar's height, and whether
 *            it is SM_CYMENU) and the window and client sizes, with
 *            the menu, after SetMenu(NULL) and after SetMenu again;
 *            DrawMenuBar of the window and of NULL; the window shown
 *            (SW_SHOWNOACTIVATE) and WM_NCHITTEST down its middle
 *            column, from 2 pixels above to 2 below, as runs of equal
 *            answers; IsMenu after the window's destruction
 *   keyloop  the keyboard menu loop: Alt, V, Down, Enter; then
 *            GetMenuState of 211, 212 and 213
 *   keyesc   F10, Right, Down, Esc, Esc; Alt, Z (no item's mnemonic),
 *            Esc; Alt, Esc
 *   keychar  Alt held over V, then Up (from the popup's first item)
 *            and Enter; Alt, F, Down (onto the grayed Open), Enter,
 *            Esc, Esc
 *   edit     menus made by CreateMenu and CreatePopupMenu, edited:
 *            AppendMenuW/A (a separator, a NULL text, a NULL menu),
 *            InsertMenuW/A by position (0, -1, past the end) and by
 *            command (in the popup, through the bar, missing),
 *            ModifyMenuW/A (text, id, check, into a separator, into a
 *            popup), DeleteMenu and RemoveMenu by position and by
 *            command, and a popup removed (IsMenu after: still there)
 *            against one deleted (destroyed); every item after each
 *            step, and the popups after DestroyMenu of their bar
 *   info     GetMenuItemInfoW of each MIIM_* mask alone and all of them,
 *            the members it leaves (the struct filled with 0xA5 bytes
 *            before); the string's length through a NULL buffer, short
 *            and exact cch; a popup item, a separator, by command,
 *            nested, missing; cbSize 44 (NT 4's), 0 and 52;
 *            GetMenuItemInfoA on the same inputs; SetMenuItemInfoW and
 *            SetMenuItemInfoA of each mask, read back; a popup
 *            attached and detached (IsMenu after); calls that fail
 *   insitem  InsertMenuItemW (and InsertMenuItemA) by position (0, -1,
 *            past the end) and by command, each mask, cbSize 44 and 0;
 *            the items after, and some read back
 *   default  SetMenuDefaultItem by command and by position (a grayed
 *            item, a popup, a separator, -1, missing ids, an item of
 *            a popup) and GetMenuDefaultItem after each, with and
 *            without GMDI_USEDISABLED and GMDI_GOINTOPOPUPS; MFS_DEFAULT
 *            through SetMenuItemInfoW on two items
 *   sysmenu  GetSystemMenu of a hidden WS_OVERLAPPEDWINDOW window: its
 *            items' ids, states and texts; the same copy again; edited,
 *            then bRevert TRUE (the copy destroyed or not) and a fresh
 *            copy; the windows without minimize and maximize boxes,
 *            a tool window, a popup without WS_SYSMENU, a child; the
 *            copy after DestroyWindow
 *   itemrect GetMenuCheckMarkDimensions against SM_CXMENUCHECK and
 *            SM_CYMENUCHECK; GetMenuItemRect of a shown window's bar
 *            items, as relations (one row, side by side, the height
 *            against SM_CYMENU, against the client area), of a hidden
 *            window's, past the end, of a popup not shown, NULL ones
 *   track    TrackPopupMenu and TrackPopupMenuEx of a popup owned by a
 *            visible window, ended without input (below): the return,
 *            how it ended, and the menu messages the owner received
 *            in order (WM_ENTERMENULOOP, WM_INITMENU, WM_INITMENUPOPUP,
 *            WM_MENUSELECT, WM_UNINITMENUPOPUP, WM_CANCELMODE,
 *            WM_EXITMENULOOP, WM_COMMAND); a NULL menu, a NULL owner
 *   cues     whether menus show their access keys' underlines:
 *            SystemParametersInfoW(SPI_GETKEYBOARDCUES); WM_QUERYUISTATE
 *            of a hidden WS_OVERLAPPEDWINDOW window with menu 200 and of
 *            its child button, once shown, and after WM_CHANGEUISTATE
 *            clears, sets and initializes UISF_HIDEACCEL; of a dialog
 *            made from a template in memory (CreateDialogIndirectParamW)
 *
 * The keyboard sections type into a visible WS_OVERLAPPEDWINDOW window
 * at (60,70), 320x200, of a class each registers, with a fresh copy of
 * menu 200, made the foreground and focus window (SetForegroundWindow,
 * SetFocus); each prints whether it is the foreground window, and
 * sends nothing when it is not, so no keystroke ever reaches another
 * window. Each batch is one SendInput call (found with GetProcAddress,
 * its structures declared here, as keyinput does), every key pressed
 * released in it, each event with its set-1 scan code and the arrows
 * extended. The procedure records the menu messages (WM_SYSCOMMAND,
 * WM_ENTERMENULOOP, WM_EXITMENULOOP, WM_INITMENU, WM_INITMENUPOPUP,
 * WM_UNINITMENUPOPUP, WM_MENUSELECT, WM_MENUCHAR, WM_COMMAND,
 * WM_CAPTURECHANGED, WM_CANCELMODE), never printing inside the
 * procedure, and passes every message to DefWindowProcW but
 * WM_COMMAND, answered 0. WM_ENTERIDLE is not recorded (how many come
 * depends on how fast the input arrives), nor are the key and
 * character messages (those after the loop ends race the WM_COMMAND
 * it posts). A menu prints by its place in menu 200 ("the bar",
 * "File's popup", "View's popup", "Recent's popup"), a window as "the
 * window" or "another window". Each batch sets a 3-second timer on the
 * window: a loop still running then is ended from the window's
 * WM_TIMER, which the loop dispatches, with EndMenu (found with
 * GetProcAddress), recorded as "EndMenu at the deadline". The program
 * pumps (PeekMessageW, TranslateMessage, DispatchMessageW,
 * MsgWaitForMultipleObjects between) until WM_EXITMENULOOP has come
 * and 300 ms pass with nothing queued, or 4 seconds pass, and prints
 * whether the loop ended, then the records. Nobody types on the real
 * machine while it runs.
 *
 * The menu-editing sections (edit through track) print a menu's items
 * by position: id (hex for the system menu's SC_* ids), GetMenuState,
 * text (a tab as \t). Item positions on the screen print only as
 * relations. track ends each menu without input: a watcher thread
 * sends the owner WM_CANCELMODE (SendNotifyMessageW) half a second in,
 * which DefWindowProc answers by ending the menu; failing that, it
 * posts an Escape key-down 2 s later; failing that too, it ends the
 * process 2 s after, so the capture cannot hang. The popup opens away
 * from the mouse pointer, so no item is selected under it. itemrect
 * and track show their windows on the screen.
 *
 * kinds' calls on another kind's handle each validate the handle as
 * their own kind's and fail on any other, so none of them destroys
 * anything on Windows. reuse's and slots' relations hold only while no
 * other process makes or destroys a user object meanwhile: the VM runs
 * nothing else, but a "no", or a count short of its trials, in one
 * capture can be another process's allocation. Their objects are
 * hidden popup windows of a class each section registers, empty menus,
 * one-entry tables and copies of the application icon; each section
 * destroys them and unregisters its class at its end.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat menus):
 *   rc menus.rc
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% menus.c menus.res user32.lib
 */

#include "../common/f2kt.h"

/* menus.rc's ids. */
#define MENU_ID 200
#define ID_NEW 201
#define ID_OPEN 202
#define ID_EXIT 203
#define ID_FIRST 205
#define ID_STANDARD 211
#define ID_SCIENTIFIC 212
#define ID_PROGRAMMER 213
#define ID_HELP 220
#define ID_NONE 299

/* The MSVC 6 headers may predate these. */
#ifndef INPUT_KEYBOARD
#define INPUT_KEYBOARD 1
#endif
#ifndef KEYEVENTF_EXTENDEDKEY
#define KEYEVENTF_EXTENDEDKEY 0x0001
#endif
#ifndef KEYEVENTF_KEYUP
#define KEYEVENTF_KEYUP 0x0002
#endif
#ifndef WM_UNINITMENUPOPUP
#define WM_UNINITMENUPOPUP 0x0125
#endif
#ifndef WM_ENTERMENULOOP
#define WM_ENTERMENULOOP 0x0211
#endif
#ifndef WM_EXITMENULOOP
#define WM_EXITMENULOOP 0x0212
#endif
#ifndef WM_CAPTURECHANGED
#define WM_CAPTURECHANGED 0x0215
#endif
#ifndef HTCLOSE
#define HTCLOSE 20
#endif
#ifndef HTHELP
#define HTHELP 21
#endif

/* The buffer contents before a call fills it. */
#define UNFILLED_W L"########"
#define UNFILLED_A "########"

static HMENU load_menu(void)
{
    return LoadMenuW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(MENU_ID));
}

/* A DWORD answer that may be -1, as printed. */
static long as_long(DWORD v)
{
    return (long)v;
}

/* GetMenuState of one item, printed. */
static void print_state(HMENU m, UINT item, UINT flags, const char *what)
{
    UINT s;

    arm();
    s = GetMenuState(m, item, flags);
    if (s == (UINT)-1) {
        line("GetMenuState(%s): ret=-1 err=%s", what, le());
    } else {
        line("GetMenuState(%s): ret=0x%X err=%s", what, s, le());
    }
}

/* --- load ---------------------------------------------------------- */

static void sec_load(void)
{
    HINSTANCE inst;
    HMENU w, a, named, missing;
    BOOL r;

    inst = GetModuleHandleW(NULL);

    arm();
    w = LoadMenuW(inst, MAKEINTRESOURCEW(MENU_ID));
    line("LoadMenuW(200): non-NULL %s err=%s", yesno(w != NULL), le());
    arm();
    r = IsMenu(w);
    line("IsMenu(LoadMenuW's): ret=%d err=%s", r, le());

    arm();
    a = LoadMenuA(inst, MAKEINTRESOURCEA(MENU_ID));
    line("LoadMenuA(200): non-NULL %s err=%s the same menu as LoadMenuW's %s", yesno(a != NULL), le(),
         yesno(a == w));
    arm();
    r = IsMenu(a);
    line("IsMenu(LoadMenuA's): ret=%d err=%s", r, le());

    arm();
    named = LoadMenuW(inst, L"#200");
    line("LoadMenuW(\"#200\"): non-NULL %s err=%s the same menu as LoadMenuW's %s", yesno(named != NULL),
         le(), yesno(named == w));

    arm();
    missing = LoadMenuW(inst, MAKEINTRESOURCEW(ID_NONE));
    line("LoadMenuW(299): non-NULL %s err=%s", yesno(missing != NULL), le());
    arm();
    missing = LoadMenuA(inst, MAKEINTRESOURCEA(ID_NONE));
    line("LoadMenuA(299): non-NULL %s err=%s", yesno(missing != NULL), le());

    arm();
    r = DestroyMenu(w);
    line("DestroyMenu(LoadMenuW's): ret=%d err=%s", r, le());
    arm();
    r = IsMenu(w);
    line("IsMenu(it) after: ret=%d err=%s", r, le());
    arm();
    r = DestroyMenu(w);
    line("DestroyMenu(it) again: ret=%d err=%s", r, le());

    if (a != NULL && a != w) {
        arm();
        r = DestroyMenu(a);
        line("DestroyMenu(LoadMenuA's): ret=%d err=%s", r, le());
    }
    if (named != NULL && named != w && named != a) {
        arm();
        r = DestroyMenu(named);
        line("DestroyMenu(\"#200\"'s): ret=%d err=%s", r, le());
    }
}

/* --- items --------------------------------------------------------- */

/* By position: the item's id, state, popup and text. */
static void print_position(HMENU m, const char *menu_name, int pos)
{
    UINT id;
    UINT s;
    HMENU sub;
    WCHAR buf[32];
    int n;

    arm();
    id = GetMenuItemID(m, pos);
    line("GetMenuItemID(%s, %d): ret=%ld err=%s", menu_name, pos, as_long(id), le());
    arm();
    s = GetMenuState(m, pos, MF_BYPOSITION);
    if (s == (UINT)-1) {
        line("GetMenuState(%s, %d, MF_BYPOSITION): ret=-1 err=%s", menu_name, pos, le());
    } else {
        line("GetMenuState(%s, %d, MF_BYPOSITION): ret=0x%X err=%s", menu_name, pos, s, le());
    }
    arm();
    sub = GetSubMenu(m, pos);
    line("GetSubMenu(%s, %d): non-NULL %s err=%s", menu_name, pos, yesno(sub != NULL), le());
    lstrcpyW(buf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, pos, buf, 32, MF_BYPOSITION);
    line("GetMenuStringW(%s, %d, 32, MF_BYPOSITION): ret=%d err=%s buffer \"%s\"", menu_name, pos, n, le(),
         ws(buf));
}

static void sec_items(void)
{
    HMENU m, file, view, recent, again;
    int i, n;
    WCHAR wbuf[32];
    char abuf[32];

    m = load_menu();
    line("LoadMenuW(200): non-NULL %s", yesno(m != NULL));
    file = GetSubMenu(m, 0);
    view = GetSubMenu(m, 1);
    recent = GetSubMenu(file, 3);

    arm();
    n = GetMenuItemCount(m);
    line("GetMenuItemCount(bar): ret=%d err=%s", n, le());
    arm();
    n = GetMenuItemCount(file);
    line("GetMenuItemCount(File): ret=%d err=%s", n, le());
    arm();
    n = GetMenuItemCount(view);
    line("GetMenuItemCount(View): ret=%d err=%s", n, le());
    arm();
    n = GetMenuItemCount(recent);
    line("GetMenuItemCount(Recent): ret=%d err=%s", n, le());
    arm();
    n = GetMenuItemCount(NULL);
    line("GetMenuItemCount(NULL): ret=%d err=%s", n, le());

    for (i = 0; i <= 3; i++) {
        print_position(m, "bar", i);
    }
    for (i = 0; i <= 5; i++) {
        print_position(file, "File", i);
    }
    print_position(recent, "Recent", 0);

    arm();
    again = GetSubMenu(m, 0);
    line("GetSubMenu(bar, 0) again: the same popup %s err=%s", yesno(again == file), le());
    arm();
    again = GetSubMenu(file, 3);
    line("GetSubMenu(File, 3) again: the same popup %s err=%s", yesno(again == recent), le());

    print_state(m, ID_NEW, MF_BYCOMMAND, "bar, 201 New, MF_BYCOMMAND");
    print_state(m, ID_OPEN, MF_BYCOMMAND, "bar, 202 Open, MF_BYCOMMAND");
    print_state(m, ID_EXIT, MF_BYCOMMAND, "bar, 203 Exit, MF_BYCOMMAND");
    print_state(m, ID_FIRST, MF_BYCOMMAND, "bar, 205 First, MF_BYCOMMAND");
    print_state(m, ID_STANDARD, MF_BYCOMMAND, "bar, 211 Standard, MF_BYCOMMAND");
    print_state(m, ID_HELP, MF_BYCOMMAND, "bar, 220 Help, MF_BYCOMMAND");
    print_state(m, ID_NONE, MF_BYCOMMAND, "bar, 299, MF_BYCOMMAND");
    print_state(file, ID_FIRST, MF_BYCOMMAND, "File, 205 First, MF_BYCOMMAND");

    lstrcpyW(wbuf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, ID_EXIT, wbuf, 32, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 203, 32, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), ws(wbuf));
    lstrcpyW(wbuf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, ID_FIRST, wbuf, 32, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 205, 32, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), ws(wbuf));
    lstrcpyW(wbuf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, ID_HELP, wbuf, 32, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 220, 32, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), ws(wbuf));
    lstrcpyW(wbuf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, ID_NONE, wbuf, 32, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 299, 32, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), ws(wbuf));
    lstrcpyW(wbuf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, ID_EXIT, wbuf, 3, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 203, 3, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), ws(wbuf));
    lstrcpyW(wbuf, UNFILLED_W);
    arm();
    n = GetMenuStringW(m, ID_EXIT, wbuf, 1, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 203, 1, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), ws(wbuf));
    arm();
    n = GetMenuStringW(m, ID_EXIT, NULL, 0, MF_BYCOMMAND);
    line("GetMenuStringW(bar, 203, NULL, 0, MF_BYCOMMAND): ret=%d err=%s", n, le());

    lstrcpyA(abuf, UNFILLED_A);
    arm();
    n = GetMenuStringA(m, ID_EXIT, abuf, 32, MF_BYCOMMAND);
    line("GetMenuStringA(bar, 203, 32, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), abuf);
    lstrcpyA(abuf, UNFILLED_A);
    arm();
    n = GetMenuStringA(m, 0, abuf, 32, MF_BYPOSITION);
    line("GetMenuStringA(bar, 0, 32, MF_BYPOSITION): ret=%d err=%s buffer \"%s\"", n, le(), abuf);
    lstrcpyA(abuf, UNFILLED_A);
    arm();
    n = GetMenuStringA(file, 2, abuf, 32, MF_BYPOSITION);
    line("GetMenuStringA(File, 2, 32, MF_BYPOSITION): ret=%d err=%s buffer \"%s\"", n, le(), abuf);
    lstrcpyA(abuf, UNFILLED_A);
    arm();
    n = GetMenuStringA(m, ID_NONE, abuf, 32, MF_BYCOMMAND);
    line("GetMenuStringA(bar, 299, 32, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), abuf);
    lstrcpyA(abuf, UNFILLED_A);
    arm();
    n = GetMenuStringA(m, ID_EXIT, abuf, 3, MF_BYCOMMAND);
    line("GetMenuStringA(bar, 203, 3, MF_BYCOMMAND): ret=%d err=%s buffer \"%s\"", n, le(), abuf);
    arm();
    n = GetMenuStringA(m, ID_EXIT, NULL, 0, MF_BYCOMMAND);
    line("GetMenuStringA(bar, 203, NULL, 0, MF_BYCOMMAND): ret=%d err=%s", n, le());

    DestroyMenu(m);
}

/* --- check --------------------------------------------------------- */

static void check_item(HMENU m, UINT item, UINT flags, const char *what)
{
    DWORD r;

    arm();
    r = CheckMenuItem(m, item, flags);
    if (r == (DWORD)-1) {
        line("CheckMenuItem(%s): ret=-1 err=%s", what, le());
    } else {
        line("CheckMenuItem(%s): ret=0x%lX err=%s", what, r, le());
    }
}

static void print_view(HMENU view)
{
    print_state(view, 0, MF_BYPOSITION, "View, 0 Standard");
    print_state(view, 1, MF_BYPOSITION, "View, 1 Scientific");
    print_state(view, 2, MF_BYPOSITION, "View, 2 Programmer");
}

static void radio(HMENU m, UINT first, UINT last, UINT check, UINT flags, const char *what)
{
    BOOL r;

    arm();
    r = CheckMenuRadioItem(m, first, last, check, flags);
    line("CheckMenuRadioItem(%s): ret=%d err=%s", what, r, le());
}

static void sec_check(void)
{
    HMENU m, file, view;

    m = load_menu();
    line("LoadMenuW(200): non-NULL %s", yesno(m != NULL));
    file = GetSubMenu(m, 0);
    view = GetSubMenu(m, 1);

    check_item(m, ID_EXIT, MF_BYCOMMAND | MF_UNCHECKED, "bar, 203 Exit, MF_BYCOMMAND | MF_UNCHECKED");
    print_state(m, ID_EXIT, MF_BYCOMMAND, "bar, 203 Exit");
    check_item(m, ID_EXIT, MF_BYCOMMAND | MF_UNCHECKED, "bar, 203 Exit, MF_UNCHECKED again");
    check_item(m, ID_NEW, MF_BYCOMMAND | MF_CHECKED, "bar, 201 New, MF_BYCOMMAND | MF_CHECKED");
    print_state(m, ID_NEW, MF_BYCOMMAND, "bar, 201 New");
    check_item(m, ID_NEW, MF_BYCOMMAND | MF_CHECKED, "bar, 201 New, MF_CHECKED again");
    check_item(file, 1, MF_BYPOSITION | MF_CHECKED, "File, 1 Open (grayed), MF_BYPOSITION | MF_CHECKED");
    print_state(file, 1, MF_BYPOSITION, "File, 1 Open");
    check_item(m, ID_FIRST, MF_BYCOMMAND | MF_CHECKED, "bar, 205 First (nested), MF_CHECKED");
    print_state(m, ID_FIRST, MF_BYCOMMAND, "bar, 205 First");
    check_item(m, 1, MF_BYPOSITION | MF_CHECKED, "bar, 1 View (a popup), MF_BYPOSITION | MF_CHECKED");
    print_state(m, 1, MF_BYPOSITION, "bar, 1 View");
    check_item(m, 1, MF_BYPOSITION | MF_UNCHECKED, "bar, 1 View, MF_BYPOSITION | MF_UNCHECKED");
    check_item(m, ID_NONE, MF_BYCOMMAND | MF_CHECKED, "bar, 299, MF_CHECKED");
    check_item(file, 9, MF_BYPOSITION | MF_CHECKED, "File, 9, MF_BYPOSITION | MF_CHECKED");

    print_view(view);
    radio(view, ID_STANDARD, ID_PROGRAMMER, ID_SCIENTIFIC, MF_BYCOMMAND, "View, 211-213, 212, MF_BYCOMMAND");
    print_view(view);
    radio(view, 0, 2, 2, MF_BYPOSITION, "View, 0-2, 2, MF_BYPOSITION");
    print_view(view);
    radio(m, ID_STANDARD, ID_PROGRAMMER, ID_STANDARD, MF_BYCOMMAND, "bar, 211-213, 211, MF_BYCOMMAND");
    print_view(view);
    radio(view, 0, 1, 2, MF_BYPOSITION, "View, 0-1, 2 (outside), MF_BYPOSITION");
    print_view(view);
    radio(view, 290, 295, 291, MF_BYCOMMAND, "View, 290-295, 291 (no such items), MF_BYCOMMAND");
    print_view(view);
    check_item(view, ID_SCIENTIFIC, MF_BYCOMMAND | MF_CHECKED, "View, 212 Scientific, MF_CHECKED");
    print_view(view);

    DestroyMenu(m);
}

/* --- enable -------------------------------------------------------- */

static void enable_item(HMENU m, UINT item, UINT flags, const char *what)
{
    BOOL r;

    arm();
    r = EnableMenuItem(m, item, flags);
    line("EnableMenuItem(%s): ret=%ld err=%s", what, (long)r, le());
}

static void sec_enable(void)
{
    HMENU m, file;

    m = load_menu();
    line("LoadMenuW(200): non-NULL %s", yesno(m != NULL));
    file = GetSubMenu(m, 0);

    enable_item(m, ID_OPEN, MF_BYCOMMAND | MF_ENABLED, "bar, 202 Open (grayed), MF_ENABLED");
    print_state(m, ID_OPEN, MF_BYCOMMAND, "bar, 202 Open");
    enable_item(m, ID_OPEN, MF_BYCOMMAND | MF_ENABLED, "bar, 202 Open, MF_ENABLED again");
    enable_item(m, ID_NEW, MF_BYCOMMAND | MF_DISABLED, "bar, 201 New, MF_DISABLED");
    print_state(m, ID_NEW, MF_BYCOMMAND, "bar, 201 New");
    enable_item(m, ID_NEW, MF_BYCOMMAND | MF_GRAYED, "bar, 201 New, MF_GRAYED");
    print_state(m, ID_NEW, MF_BYCOMMAND, "bar, 201 New");
    enable_item(m, ID_NEW, MF_BYCOMMAND | MF_GRAYED | MF_DISABLED, "bar, 201 New, MF_GRAYED | MF_DISABLED");
    print_state(m, ID_NEW, MF_BYCOMMAND, "bar, 201 New");
    enable_item(m, ID_NEW, MF_BYCOMMAND | MF_ENABLED, "bar, 201 New, MF_ENABLED");
    print_state(m, ID_NEW, MF_BYCOMMAND, "bar, 201 New");
    enable_item(file, 4, MF_BYPOSITION | MF_GRAYED, "File, 4 Exit (checked), MF_BYPOSITION | MF_GRAYED");
    print_state(file, 4, MF_BYPOSITION, "File, 4 Exit");
    enable_item(m, ID_FIRST, MF_BYCOMMAND | MF_GRAYED, "bar, 205 First (nested), MF_GRAYED");
    print_state(m, ID_FIRST, MF_BYCOMMAND, "bar, 205 First");
    enable_item(m, 0, MF_BYPOSITION | MF_GRAYED, "bar, 0 File (a popup), MF_BYPOSITION | MF_GRAYED");
    print_state(m, 0, MF_BYPOSITION, "bar, 0 File");
    enable_item(m, 0, MF_BYPOSITION | MF_ENABLED, "bar, 0 File, MF_BYPOSITION | MF_ENABLED");
    enable_item(m, ID_HELP, MF_BYCOMMAND | MF_DISABLED, "bar, 220 Help, MF_DISABLED");
    print_state(m, ID_HELP, MF_BYCOMMAND, "bar, 220 Help");
    enable_item(m, ID_NONE, MF_BYCOMMAND | MF_ENABLED, "bar, 299, MF_ENABLED");
    enable_item(m, 7, MF_BYPOSITION | MF_ENABLED, "bar, 7, MF_BYPOSITION | MF_ENABLED");

    DestroyMenu(m);
}

/* --- window -------------------------------------------------------- */

static LRESULT CALLBACK plain(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void sec_window(void)
{
    WNDCLASSW wc;
    HINSTANCE inst;
    ATOM atom;
    HWND h, child;
    HMENU m, m2, got;
    BOOL r;

    inst = GetModuleHandleW(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = plain;
    wc.hInstance = inst;
    wc.lpszClassName = L"F2KMenusWindow";
    arm();
    atom = RegisterClassW(&wc);
    line("RegisterClassW(F2KMenusWindow): atom nonzero %s err=%s", yesno(atom != 0), le());

    arm();
    h = CreateWindowExW(0, L"F2KMenusWindow", L"menus", WS_OVERLAPPEDWINDOW, 0, 0, 320, 200, NULL, NULL,
                        inst, NULL);
    line("CreateWindowExW(F2KMenusWindow, WS_OVERLAPPEDWINDOW, hidden, 320x200): non-NULL %s err=%s",
         yesno(h != NULL), le());

    arm();
    got = GetMenu(h);
    line("GetMenu(window) with none: NULL %s err=%s", yesno(got == NULL), le());

    m = load_menu();
    line("LoadMenuW(200): non-NULL %s", yesno(m != NULL));
    arm();
    r = SetMenu(h, m);
    line("SetMenu(window, menu): ret=%d err=%s", r, le());
    arm();
    got = GetMenu(h);
    line("GetMenu(window): the menu %s err=%s", yesno(got == m), le());

    arm();
    r = SetMenu(h, NULL);
    line("SetMenu(window, NULL): ret=%d err=%s", r, le());
    arm();
    got = GetMenu(h);
    line("GetMenu(window): NULL %s err=%s", yesno(got == NULL), le());
    arm();
    r = IsMenu(m);
    line("IsMenu(menu) once taken off: ret=%d err=%s", r, le());

    arm();
    r = SetMenu(h, m);
    line("SetMenu(window, menu) again: ret=%d err=%s", r, le());
    arm();
    r = DestroyWindow(h);
    line("DestroyWindow(window): ret=%d err=%s", r, le());
    arm();
    r = IsMenu(m);
    line("IsMenu(menu) after its window's destruction: ret=%d err=%s", r, le());

    m2 = load_menu();
    arm();
    h = CreateWindowExW(0, L"F2KMenusWindow", L"menus", WS_OVERLAPPEDWINDOW, 0, 0, 320, 200, NULL, m2,
                        inst, NULL);
    line("CreateWindowExW(F2KMenusWindow, WS_OVERLAPPEDWINDOW, hMenu the menu): non-NULL %s err=%s",
         yesno(h != NULL), le());
    arm();
    got = GetMenu(h);
    line("GetMenu(window): the menu %s err=%s", yesno(got == m2), le());

    arm();
    child = CreateWindowExW(0, L"F2KMenusWindow", L"child", WS_CHILD, 0, 0, 50, 50, h, (HMENU)7, inst,
                            NULL);
    line("CreateWindowExW(F2KMenusWindow, WS_CHILD, id 7): non-NULL %s err=%s", yesno(child != NULL), le());
    m = load_menu();
    arm();
    r = SetMenu(child, m);
    line("SetMenu(child window, a second menu): ret=%d err=%s", r, le());
    arm();
    r = IsMenu(m);
    line("IsMenu(the second menu) after: ret=%d err=%s", r, le());
    DestroyMenu(m);

    m = load_menu();
    DestroyMenu(m);
    arm();
    r = SetMenu(h, m);
    line("SetMenu(window, a destroyed menu): ret=%d err=%s", r, le());
    arm();
    got = GetMenu(h);
    line("GetMenu(window): the menu it was created with %s err=%s", yesno(got == m2), le());

    DestroyWindow(h);
}

/* --- the handles of user objects of different kinds ---------------- */

/* The kinds make() makes: a hidden popup window of the running
 * section's class, an empty menu (CreateMenu), a table of one
 * accelerator (CreateAcceleratorTableW) and a copy of the stock
 * application icon (CopyIcon). */
#define K_WINDOW 0
#define K_MENU 1
#define K_TABLE 2
#define K_ICON 3

static const char *const kind_names[] = { "window", "menu", "table", "icon" };

/* A kind's own call accepting a handle (accepts()), as printed. */
static const char *const own_calls[] = {
    "IsWindow TRUE", "IsMenu TRUE", "CopyAcceleratorTableW(NULL, 0) nonzero"
};

/* The running section's window class, and the stock application icon
 * CopyIcon copies (register_handles_class() sets both). */
static const WCHAR *handles_class;
static HICON app_icon;

static void register_handles_class(const WCHAR *name)
{
    WNDCLASSW wc;
    ATOM atom;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = plain;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = name;
    arm();
    atom = RegisterClassW(&wc);
    line("RegisterClassW(%s): atom nonzero %s err=%s", ws(name), yesno(atom != 0), le());
    handles_class = name;
    app_icon = LoadIconA(NULL, IDI_APPLICATION);
}

static HANDLE make(int kind)
{
    ACCEL a;

    switch (kind) {
    case K_WINDOW:
        return (HANDLE)CreateWindowExW(0, handles_class, L"handles", WS_POPUP, 0, 0, 64, 64, NULL, NULL,
                                       GetModuleHandleW(NULL), NULL);
    case K_MENU:
        return (HANDLE)CreateMenu();
    case K_TABLE:
        a.fVirt = (BYTE)(FVIRTKEY | FCONTROL);
        a.key = 'N';
        a.cmd = ID_NEW;
        return (HANDLE)CreateAcceleratorTableW(&a, 1);
    }
    return (HANDLE)CopyIcon(app_icon);
}

static void unmake(int kind, HANDLE h)
{
    if (h == NULL) {
        return;
    }
    switch (kind) {
    case K_WINDOW:
        DestroyWindow((HWND)h);
        break;
    case K_MENU:
        DestroyMenu((HMENU)h);
        break;
    case K_TABLE:
        DestroyAcceleratorTable((HACCEL)h);
        break;
    default:
        DestroyIcon((HICON)h);
        break;
    }
}

/* Whether a window, menu or table's own call takes h for one of its
 * kind: IsWindow, IsMenu, or CopyAcceleratorTableW's count of h's
 * entries (a table here holds one). Each only reads. */
static int accepts(int kind, HANDLE h)
{
    switch (kind) {
    case K_WINDOW:
        return IsWindow((HWND)h) != FALSE;
    case K_MENU:
        return IsMenu((HMENU)h) != FALSE;
    }
    return CopyAcceleratorTableW((HACCEL)h, NULL, 0) != 0;
}

static WORD low_of(HANDLE h)
{
    return LOWORD((DWORD)h);
}

static WORD high_of(HANDLE h)
{
    return HIWORD((DWORD)h);
}

/* --- kinds --------------------------------------------------------- */

#define KINDS_OBJECTS 7

static const char *const object_names[KINDS_OBJECTS] = {
    "window", "CreateMenu's menu", "menu 200", "table", "the arrow cursor", "the application icon",
    "CopyIcon's icon"
};

static void sec_kinds(void)
{
    HANDLE o[KINDS_OBJECTS];
    int i, j, distinct, low_distinct, n;
    BOOL r;
    LONG style;

    register_handles_class(L"F2KKindsWindow");

    arm();
    o[0] = make(K_WINDOW);
    line("CreateWindowExW(F2KKindsWindow, WS_POPUP, hidden): non-NULL %s err=%s", yesno(o[0] != NULL), le());
    arm();
    o[1] = make(K_MENU);
    line("CreateMenu: non-NULL %s err=%s", yesno(o[1] != NULL), le());
    o[2] = (HANDLE)load_menu();
    line("LoadMenuW(200): non-NULL %s", yesno(o[2] != NULL));
    arm();
    o[3] = make(K_TABLE);
    line("CreateAcceleratorTableW(one entry): non-NULL %s err=%s", yesno(o[3] != NULL), le());
    o[4] = (HANDLE)LoadCursorA(NULL, IDC_ARROW);
    line("LoadCursorA(NULL, IDC_ARROW): non-NULL %s", yesno(o[4] != NULL));
    o[5] = (HANDLE)app_icon;
    line("LoadIconA(NULL, IDI_APPLICATION): non-NULL %s", yesno(o[5] != NULL));
    arm();
    o[6] = make(K_ICON);
    line("CopyIcon(the application icon): non-NULL %s err=%s the same icon %s", yesno(o[6] != NULL), le(),
         yesno(o[6] == o[5]));

    distinct = 1;
    low_distinct = 1;
    for (i = 0; i < KINDS_OBJECTS; i++) {
        for (j = i + 1; j < KINDS_OBJECTS; j++) {
            if (o[i] == o[j]) {
                distinct = 0;
            }
            if (low_of(o[i]) == low_of(o[j])) {
                low_distinct = 0;
            }
        }
    }
    line("the seven handles all different: %s; their low words all different: %s", yesno(distinct),
         yesno(low_distinct));

    /* Each kind's calls that only read, on every object. */
    for (i = 0; i < KINDS_OBJECTS; i++) {
        arm();
        r = IsWindow((HWND)o[i]);
        line("IsWindow(%s): ret=%d err=%s", object_names[i], r, le());
        arm();
        r = IsMenu((HMENU)o[i]);
        line("IsMenu(%s): ret=%d err=%s", object_names[i], r, le());
        arm();
        n = GetMenuItemCount((HMENU)o[i]);
        line("GetMenuItemCount(%s): ret=%d err=%s", object_names[i], n, le());
        arm();
        n = CopyAcceleratorTableW((HACCEL)o[i], NULL, 0);
        line("CopyAcceleratorTableW(%s, NULL, 0): ret=%d err=%s", object_names[i], n, le());
        arm();
        style = GetWindowLongW((HWND)o[i], GWL_STYLE);
        line("GetWindowLongW(%s, GWL_STYLE): nonzero %s err=%s", object_names[i], yesno(style != 0), le());
    }

    /* Each kind's destruction on handles of the other kinds. Each call
     * validates its handle as its own kind's and fails on any other, so
     * none of these destroys anything on Windows. */
    arm();
    r = DestroyMenu((HMENU)o[0]);
    line("DestroyMenu(window): ret=%d err=%s", r, le());
    arm();
    r = DestroyMenu((HMENU)o[3]);
    line("DestroyMenu(table): ret=%d err=%s", r, le());
    arm();
    r = DestroyMenu((HMENU)o[6]);
    line("DestroyMenu(CopyIcon's icon): ret=%d err=%s", r, le());
    arm();
    r = DestroyAcceleratorTable((HACCEL)o[1]);
    line("DestroyAcceleratorTable(CreateMenu's menu): ret=%d err=%s", r, le());
    arm();
    r = DestroyAcceleratorTable((HACCEL)o[0]);
    line("DestroyAcceleratorTable(window): ret=%d err=%s", r, le());
    arm();
    r = DestroyAcceleratorTable((HACCEL)o[6]);
    line("DestroyAcceleratorTable(CopyIcon's icon): ret=%d err=%s", r, le());
    arm();
    r = DestroyIcon((HICON)o[1]);
    line("DestroyIcon(CreateMenu's menu): ret=%d err=%s", r, le());
    arm();
    r = DestroyIcon((HICON)o[0]);
    line("DestroyIcon(window): ret=%d err=%s", r, le());
    arm();
    r = DestroyIcon((HICON)o[3]);
    line("DestroyIcon(table): ret=%d err=%s", r, le());
    arm();
    r = DestroyWindow((HWND)o[1]);
    line("DestroyWindow(CreateMenu's menu): ret=%d err=%s", r, le());
    arm();
    r = DestroyWindow((HWND)o[3]);
    line("DestroyWindow(table): ret=%d err=%s", r, le());
    arm();
    r = DestroyWindow((HWND)o[6]);
    line("DestroyWindow(CopyIcon's icon): ret=%d err=%s", r, le());

    line("after them: IsWindow(window) %d, IsMenu(CreateMenu's menu) %d, IsMenu(menu 200) %d, "
         "CopyAcceleratorTableW(table, NULL, 0) %d",
         IsWindow((HWND)o[0]), IsMenu((HMENU)o[1]), IsMenu((HMENU)o[2]),
         CopyAcceleratorTableW((HACCEL)o[3], NULL, 0));

    /* Each object destroyed by its own kind's call. */
    arm();
    r = DestroyIcon((HICON)o[6]);
    line("DestroyIcon(CopyIcon's icon): ret=%d err=%s", r, le());
    arm();
    r = DestroyAcceleratorTable((HACCEL)o[3]);
    line("DestroyAcceleratorTable(table): ret=%d err=%s", r, le());
    arm();
    r = DestroyMenu((HMENU)o[2]);
    line("DestroyMenu(menu 200): ret=%d err=%s", r, le());
    arm();
    r = DestroyMenu((HMENU)o[1]);
    line("DestroyMenu(CreateMenu's menu): ret=%d err=%s", r, le());
    arm();
    r = DestroyWindow((HWND)o[0]);
    line("DestroyWindow(window): ret=%d err=%s", r, le());

    arm();
    r = IsWindow((HWND)o[0]);
    line("IsWindow(the destroyed window): ret=%d err=%s", r, le());
    arm();
    r = IsMenu((HMENU)o[1]);
    line("IsMenu(the destroyed CreateMenu's menu): ret=%d err=%s", r, le());
    arm();
    n = CopyAcceleratorTableW((HACCEL)o[3], NULL, 0);
    line("CopyAcceleratorTableW(the destroyed table, NULL, 0): ret=%d err=%s", n, le());

    UnregisterClassW(L"F2KKindsWindow", GetModuleHandleW(NULL));
}

/* --- reuse --------------------------------------------------------- */

#define ROUNDS 40

/* One call's answers over the rounds: how often it said TRUE, and its
 * last error, as the first call left it and how often the same. */
typedef struct {
    int calls;
    int yes;
    DWORD first_err;
    int same_err;
} tally_t;

static void tally_init(tally_t *t)
{
    t->calls = 0;
    t->yes = 0;
    t->first_err = F2KT_UNTOUCHED;
    t->same_err = 0;
}

/* accepts(kind, h), armed, into the tally. */
static void tally(tally_t *t, int kind, HANDLE h)
{
    int r;
    DWORD e;

    arm();
    r = accepts(kind, h);
    e = GetLastError();
    if (t->calls == 0) {
        t->first_err = e;
    }
    if (e == t->first_err) {
        t->same_err++;
    }
    t->calls++;
    if (r) {
        t->yes++;
    }
}

static void print_tally(const char *what, const tally_t *t)
{
    line("%s: %d of %d, the first call's err=%s, the same err in %d", what, t->yes, t->calls, le_of(t->first_err),
         t->same_err);
}

/* reuse's objects held across the rounds: a window, a menu and a table
 * (by kind), and the arrow cursor. */
#define LIVE_CURSOR 3
static HANDLE live[4];
static const char *const live_names[4] = { "window", "menu", "table", "arrow cursor" };

/* ROUNDS objects of one kind made and destroyed one after another, the
 * live objects held: each new handle tried by the other kinds' calls,
 * the live objects by this kind's, and each new handle against the
 * earlier ones (all destroyed by then). */
static void churn(int kind)
{
    HANDLE seen[ROUNDS];
    tally_t wrong[3], held[4];
    char what[96];
    HANDLE h;
    int i, j, k, ok, is_new, shares, latest;
    int made, fresh, equal_live, in_slot, slot_checks, slot_accepted, earlier, earlier_accepted;
    int up1, up2, up3, up_other, d;

    for (k = 0; k < 3; k++) {
        tally_init(&wrong[k]);
    }
    for (k = 0; k < 4; k++) {
        tally_init(&held[k]);
    }
    made = fresh = equal_live = in_slot = slot_checks = slot_accepted = earlier = earlier_accepted = 0;
    up1 = up2 = up3 = up_other = 0;

    for (i = 0; i < ROUNDS; i++) {
        h = make(kind);
        seen[i] = h;
        if (h == NULL) {
            continue;
        }
        made++;
        for (k = 0; k < 3; k++) {
            if (k != kind) {
                tally(&wrong[k], k, h);
            }
        }
        for (k = 0; k < 4; k++) {
            if (k != kind) {
                tally(&held[k], kind, live[k]);
            }
            if (live[k] != NULL && live[k] == h) {
                equal_live++;
            }
        }
        is_new = 1;
        shares = 0;
        latest = -1;
        for (j = 0; j < i; j++) {
            if (seen[j] == NULL) {
                continue;
            }
            if (seen[j] == h) {
                is_new = 0;
                continue;
            }
            earlier++;
            ok = accepts(kind, seen[j]);
            if (ok) {
                earlier_accepted++;
            }
            if (low_of(seen[j]) == low_of(h)) {
                shares = 1;
                latest = j;
                slot_checks++;
                if (ok) {
                    slot_accepted++;
                }
            }
        }
        fresh += is_new;
        in_slot += shares;
        if (latest >= 0) {
            /* The high word against the slot's last earlier handle. */
            d = (int)(short)(WORD)(high_of(h) - high_of(seen[latest]));
            if (d == 1) {
                up1++;
            } else if (d == 2) {
                up2++;
            } else if (d == 3) {
                up3++;
            } else {
                up_other++;
            }
        }
        unmake(kind, h);
    }

    line("%ss made and destroyed one after another: %d of %d made", kind_names[kind], made, ROUNDS);
    for (k = 0; k < 3; k++) {
        if (k != kind) {
            sprintf(what, "%s for a new %s", own_calls[k], kind_names[kind]);
            print_tally(what, &wrong[k]);
        }
    }
    for (k = 0; k < 4; k++) {
        if (k != kind) {
            sprintf(what, "%s for the live %s", own_calls[kind], live_names[k]);
            print_tally(what, &held[k]);
        }
    }
    line("a new %s's handle equal to a live object's: %d of %d", kind_names[kind], equal_live, made);
    line("a new %s's handle different from every earlier one's: %d of %d", kind_names[kind], fresh, made);
    line("a new %s in an earlier one's slot (the same low word): %d of %d", kind_names[kind], in_slot, made);
    line("its high word less the slot's last earlier one's: 1 in %d, 2 in %d, 3 in %d, otherwise in %d", up1, up2,
         up3, up_other);
    line("%s for an earlier, destroyed %s in the new one's slot: %d of %d", own_calls[kind], kind_names[kind],
         slot_accepted, slot_checks);
    line("%s for any earlier, destroyed %s: %d of %d", own_calls[kind], kind_names[kind], earlier_accepted,
         earlier);
}

static void sec_reuse(void)
{
    register_handles_class(L"F2KReuseWindow");

    live[K_WINDOW] = make(K_WINDOW);
    live[K_MENU] = make(K_MENU);
    live[K_TABLE] = make(K_TABLE);
    live[LIVE_CURSOR] = (HANDLE)LoadCursorA(NULL, IDC_ARROW);
    line("held: a window %s, a menu %s, a table %s, the arrow cursor %s", yesno(live[K_WINDOW] != NULL),
         yesno(live[K_MENU] != NULL), yesno(live[K_TABLE] != NULL), yesno(live[LIVE_CURSOR] != NULL));

    churn(K_WINDOW);
    churn(K_MENU);
    churn(K_TABLE);

    line("held after: IsWindow(window) %d, IsMenu(menu) %d, CopyAcceleratorTableW(table, NULL, 0) %d",
         IsWindow((HWND)live[K_WINDOW]), IsMenu((HMENU)live[K_MENU]),
         CopyAcceleratorTableW((HACCEL)live[K_TABLE], NULL, 0));

    unmake(K_TABLE, live[K_TABLE]);
    unmake(K_MENU, live[K_MENU]);
    unmake(K_WINDOW, live[K_WINDOW]);
    UnregisterClassW(L"F2KReuseWindow", GetModuleHandleW(NULL));
}

/* --- slots --------------------------------------------------------- */

/* Each relation below holds only while no other process makes or
 * destroys a user object between the calls: the VM runs nothing else,
 * but a "no" (or a count short of the trials) in one capture can be
 * another process's allocation. Each is repeated TRIALS times. */
#define TRIALS 5
#define TOGETHER 8

/* A `next` made at once after a `freed`'s destruction: whether it took
 * the freed slot (the same low word) and how its high word differs. */
static void taken(int freed, int next)
{
    HANDLE a, b;
    WORD la, ha;
    int t, made, same, differs, n;
    char changes[96];

    made = same = differs = n = 0;
    changes[0] = '\0';
    for (t = 0; t < TRIALS; t++) {
        a = make(freed);
        la = low_of(a);
        ha = high_of(a);
        unmake(freed, a);
        b = make(next);
        if (a != NULL && b != NULL) {
            made++;
            if (low_of(b) == la) {
                same++;
                if (high_of(b) != ha) {
                    differs++;
                }
                n += sprintf(changes + n, " %+d", (int)(short)(WORD)(high_of(b) - ha));
            } else {
                n += sprintf(changes + n, " -");
            }
        }
        unmake(next, b);
    }
    line("%s made at once after a %s's destruction: both made in %d of %d, the same low word in %d, "
         "a different high word in %d; the high word's change:%s",
         kind_names[next], kind_names[freed], made, TRIALS, same, differs, changes);
}

static void sec_slots(void)
{
    HANDLE w1, m, w2;
    HANDLE all[4 * TOGETHER];
    int t, i, j, k, made, between, two, one, equal, same_handle, same_low;
    WORD lw1, lm, lw2;
    BOOL r;

    register_handles_class(L"F2KSlotsWindow");

    /* Whatever a kind's first object brings with it is made before the
     * trials. */
    for (k = K_WINDOW; k <= K_ICON; k++) {
        unmake(k, make(k));
    }

    /* Objects of all four kinds alive at once: in one table their low
     * words all differ. */
    for (i = 0; i < 4 * TOGETHER; i++) {
        all[i] = make(i % 4);
    }
    made = same_handle = same_low = 0;
    for (i = 0; i < 4 * TOGETHER; i++) {
        if (all[i] == NULL) {
            continue;
        }
        made++;
        for (j = i + 1; j < 4 * TOGETHER; j++) {
            if (all[j] == NULL) {
                continue;
            }
            if (all[i] == all[j]) {
                same_handle++;
            }
            if (low_of(all[i]) == low_of(all[j])) {
                same_low++;
            }
        }
    }
    line("%d each of windows, menus, tables and icons alive at once: made %d of %d", TOGETHER, made,
         4 * TOGETHER);
    line("pairs of them with the same handle: %d; with the same low word: %d", same_handle, same_low);
    for (i = 4 * TOGETHER - 1; i >= 0; i--) {
        unmake(i % 4, all[i]);
    }

    /* Window W1, menu M, window W2, made one after another. */
    made = between = two = one = equal = 0;
    for (t = 0; t < TRIALS; t++) {
        w1 = make(K_WINDOW);
        m = make(K_MENU);
        w2 = make(K_WINDOW);
        if (w1 != NULL && m != NULL && w2 != NULL) {
            made++;
            lw1 = low_of(w1);
            lm = low_of(m);
            lw2 = low_of(w2);
            if ((lm > lw1 && lm < lw2) || (lm < lw1 && lm > lw2)) {
                between++;
            }
            if ((int)lw2 - (int)lw1 == 2) {
                two++;
            }
            if ((int)lm - (int)lw1 == 1) {
                one++;
            }
            if (lm == lw1 || lm == lw2) {
                equal++;
            }
        }
        unmake(K_WINDOW, w2);
        unmake(K_MENU, m);
        unmake(K_WINDOW, w1);
    }
    line("window W1, menu M, window W2 made one after another: all three made in %d of %d", made, TRIALS);
    line("M's low word strictly between W1's and W2's: %d of %d", between, made);
    line("low(W2) - low(W1) is 2: %d of %d", two, made);
    line("low(M) - low(W1) is 1: %d of %d", one, made);
    line("M's low word equal to W1's or W2's: %d of %d", equal, made);

    taken(K_WINDOW, K_WINDOW);
    taken(K_WINDOW, K_MENU);
    taken(K_MENU, K_WINDOW);
    taken(K_MENU, K_TABLE);
    taken(K_WINDOW, K_ICON);
    taken(K_ICON, K_WINDOW);

    /* A live window's and menu's handles with their high word replaced:
     * 0, 0xFFFF, and one more than their own (the slot's next handle). */
    w1 = make(K_WINDOW);
    m = make(K_MENU);
    line("a window and a menu: non-NULL %s %s", yesno(w1 != NULL), yesno(m != NULL));
    arm();
    r = IsWindow((HWND)(DWORD)low_of(w1));
    line("IsWindow(the window's low word, high word 0): ret=%d err=%s", r, le());
    arm();
    r = IsWindow((HWND)(0xFFFF0000u | low_of(w1)));
    line("IsWindow(the window's low word, high word 0xFFFF): ret=%d err=%s", r, le());
    arm();
    r = IsWindow((HWND)((DWORD)w1 + 0x10000u));
    line("IsWindow(the window's handle, high word one more): ret=%d err=%s", r, le());
    arm();
    r = IsMenu((HMENU)(DWORD)low_of(m));
    line("IsMenu(the menu's low word, high word 0): ret=%d err=%s", r, le());
    arm();
    r = IsMenu((HMENU)(0xFFFF0000u | low_of(m)));
    line("IsMenu(the menu's low word, high word 0xFFFF): ret=%d err=%s", r, le());
    arm();
    r = IsMenu((HMENU)((DWORD)m + 0x10000u));
    line("IsMenu(the menu's handle, high word one more): ret=%d err=%s", r, le());
    unmake(K_MENU, m);
    unmake(K_WINDOW, w1);

    UnregisterClassW(L"F2KSlotsWindow", GetModuleHandleW(NULL));
}

/* --- the menu bar and the keyboard menu loop: shared ---------------- */

/* Dispatch what is queued: a shown window's WM_PAINT stays queued
 * until its procedure paints, so it is dispatched, never dropped. */
static void pump_queued(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

static const char *ht_name(LRESULT r)
{
    switch (r) {
    case HTERROR: return "HTERROR";
    case HTTRANSPARENT: return "HTTRANSPARENT";
    case HTNOWHERE: return "HTNOWHERE";
    case HTCLIENT: return "HTCLIENT";
    case HTCAPTION: return "HTCAPTION";
    case HTSYSMENU: return "HTSYSMENU";
    case HTGROWBOX: return "HTGROWBOX";
    case HTMENU: return "HTMENU";
    case HTHSCROLL: return "HTHSCROLL";
    case HTVSCROLL: return "HTVSCROLL";
    case HTMINBUTTON: return "HTMINBUTTON";
    case HTMAXBUTTON: return "HTMAXBUTTON";
    case HTLEFT: return "HTLEFT";
    case HTRIGHT: return "HTRIGHT";
    case HTTOP: return "HTTOP";
    case HTTOPLEFT: return "HTTOPLEFT";
    case HTTOPRIGHT: return "HTTOPRIGHT";
    case HTBOTTOM: return "HTBOTTOM";
    case HTBOTTOMLEFT: return "HTBOTTOMLEFT";
    case HTBOTTOMRIGHT: return "HTBOTTOMRIGHT";
    case HTBORDER: return "HTBORDER";
    case HTCLOSE: return "HTCLOSE";
    case HTHELP: return "HTHELP";
    }
    return "?";
}

/* WM_NCHITTEST at `count` points down a column from (x, y), printed as
 * runs of equal answers: each run's offsets from the scan's start,
 * [first, past its last), and its code. */
static void scan_column(HWND h, const char *what, int x, int y, int count)
{
    char buf[900];
    int n;
    int i;
    int start;
    LRESULT run;
    LRESULT r;

    n = sprintf(buf, "%s:", what);
    start = 0;
    run = SendMessageW(h, WM_NCHITTEST, 0, MAKELPARAM(x, y));
    r = run;
    for (i = 1; i <= count; i++) {
        if (i < count) {
            r = SendMessageW(h, WM_NCHITTEST, 0, MAKELPARAM(x, y + i));
        }
        if (i == count || r != run) {
            if (n < (int)sizeof buf - 48) {
                n += sprintf(buf + n, "%s [%d,%d) %ld %s", start == 0 ? "" : ",", start, i,
                             (long)run, ht_name(run));
            }
            start = i;
            run = r;
        }
    }
    line("%s", buf);
}

/* --- bar ----------------------------------------------------------- */

/* The window's frame, menu bar and client area, as the window and the
 * metrics give them. */
static void print_bar(HWND h, const char *when)
{
    RECT wr, cr;
    POINT origin;
    long band;

    GetWindowRect(h, &wr);
    GetClientRect(h, &cr);
    origin.x = 0;
    origin.y = 0;
    ClientToScreen(h, &origin);
    band = origin.y - wr.top - GetSystemMetrics(SM_CYFRAME) - GetSystemMetrics(SM_CYCAPTION);
    line("%s: the client origin's offset less the frame: %ld; less the frame and caption, the menu "
         "bar's height: %ld (SM_CYMENU: %s)",
         when, origin.x - wr.left - GetSystemMetrics(SM_CXFRAME), band,
         yesno(band == GetSystemMetrics(SM_CYMENU)));
    line("  window %ldx%ld, client %ldx%ld", wr.right - wr.left, wr.bottom - wr.top, cr.right,
         cr.bottom);
}

static void sec_bar(void)
{
    WNDCLASSW wc;
    HINSTANCE inst;
    ATOM atom;
    HWND h;
    HMENU m;
    BOOL r;
    RECT wr;

    inst = GetModuleHandleW(NULL);
    pump_queued();
    UnregisterClassW(L"F2KMenusBar", inst);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = plain;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"F2KMenusBar";
    atom = RegisterClassW(&wc);
    m = load_menu();
    h = CreateWindowExW(0, L"F2KMenusBar", L"menus", WS_OVERLAPPEDWINDOW, 60, 70, 320, 200, NULL, m,
                        inst, NULL);
    line("setup: the class, menu 200 and a hidden WS_OVERLAPPEDWINDOW window with it, 320x200: %s",
         yesno(atom != 0 && m != NULL && h != NULL));
    if (h == NULL) {
        if (m != NULL) {
            DestroyMenu(m);
        }
        UnregisterClassW(L"F2KMenusBar", inst);
        return;
    }
    print_bar(h, "created with the menu");
    arm();
    r = SetMenu(h, NULL);
    line("SetMenu(h, NULL): ret=%d err=%s", r, le());
    print_bar(h, "without the menu");
    arm();
    r = SetMenu(h, m);
    line("SetMenu(h, menu): ret=%d err=%s", r, le());
    print_bar(h, "with the menu again");
    arm();
    r = DrawMenuBar(h);
    line("DrawMenuBar(h): ret=%d err=%s", r, le());
    arm();
    r = DrawMenuBar(NULL);
    line("DrawMenuBar(NULL): ret=%d err=%s", r, le());

    ShowWindow(h, SW_SHOWNOACTIVATE);
    pump_queued();
    GetWindowRect(h, &wr);
    scan_column(h, "WM_NCHITTEST down the middle column, from 2 above", (wr.left + wr.right) / 2,
                wr.top - 2, wr.bottom - wr.top + 4);
    DestroyWindow(h);
    pump_queued();
    arm();
    r = IsMenu(m);
    line("IsMenu(the menu) after its window's destruction: ret=%d err=%s", r, le());
    UnregisterClassW(L"F2KMenusBar", inst);
}

/* --- the keyboard menu loop ---------------------------------------- */

/* SendInput's structures in their public layout (MOUSEINPUT is the
 * union's largest member, so the record is 28 bytes, as INPUT is). */
typedef struct {
    LONG dx;
    LONG dy;
    DWORD mouseData;
    DWORD dwFlags;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_mouse_input;

typedef struct {
    WORD wVk;
    WORD wScan;
    DWORD dwFlags;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_keybd_input;

typedef struct {
    DWORD type;
    union {
        f2k_mouse_input mi;
        f2k_keybd_input ki;
    } u;
} f2k_input;

typedef UINT (WINAPI *send_input_fn)(UINT count, f2k_input *inputs, int size);
typedef BOOL (WINAPI *end_menu_fn)(void);

static send_input_fn send_input;
static end_menu_fn end_menu;

/* One input event: a key going down or up, with its set-1 scan code. */
typedef struct {
    WORD vk;
    WORD scan;
    DWORD flags;
} stroke_t;

#define DOWN 0
#define UP KEYEVENTF_KEYUP
#define EXT KEYEVENTF_EXTENDEDKEY

#define MAX_STROKES 16

/* The scan codes of the keys the batches press. */
#define SCAN_ALT 0x38
#define SCAN_V 0x2F
#define SCAN_F 0x21
#define SCAN_Z 0x2C
#define SCAN_UP 0x48
#define SCAN_DOWN 0x50
#define SCAN_RIGHT 0x4D
#define SCAN_ENTER 0x1C
#define SCAN_ESC 0x01
#define SCAN_F10 0x44

/* The guard timer: a menu loop still running at its deadline is ended
 * from the window's WM_TIMER, which the loop dispatches. */
#define GUARD_TIMER 1
#define GUARD_MS 3000

/* What the procedure received, printed after the batch. The guard's
 * EndMenu is recorded as a WM_TIMER. */
typedef struct {
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
} menu_record;

#define MAX_MENU_RECORDS 64

static menu_record menu_records[MAX_MENU_RECORDS];
static int menu_record_count;
static int menu_records_lost;
static int exit_seen;
static HWND key_window;

/* The messages recorded. WM_ENTERIDLE is not: how many come depends on
 * how fast the input arrives. Nor are the key and character messages:
 * those after the loop ends race the WM_COMMAND it posts. */
static int is_menu_message(UINT msg)
{
    switch (msg) {
    case WM_SYSCOMMAND:
    case WM_ENTERMENULOOP:
    case WM_EXITMENULOOP:
    case WM_INITMENU:
    case WM_INITMENUPOPUP:
    case WM_UNINITMENUPOPUP:
    case WM_MENUSELECT:
    case WM_MENUCHAR:
    case WM_COMMAND:
    case WM_CAPTURECHANGED:
    case WM_CANCELMODE:
        return 1;
    }
    return 0;
}

static void record_menu(UINT msg, WPARAM wparam, LPARAM lparam)
{
    menu_record *r;

    if (menu_record_count == MAX_MENU_RECORDS) {
        menu_records_lost++;
        return;
    }
    r = &menu_records[menu_record_count++];
    r->msg = msg;
    r->wparam = wparam;
    r->lparam = lparam;
}

/* The procedure: the menu messages recorded, then every message to
 * DefWindowProcW but WM_COMMAND, answered 0. */
static LRESULT CALLBACK menu_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_TIMER && wparam == GUARD_TIMER) {
        KillTimer(hwnd, GUARD_TIMER);
        record_menu(WM_TIMER, wparam, 0);
        if (end_menu != NULL) {
            end_menu();
        }
        return 0;
    }
    if (is_menu_message(msg)) {
        record_menu(msg, wparam, lparam);
    }
    if (msg == WM_EXITMENULOOP) {
        exit_seen = 1;
    }
    if (msg == WM_COMMAND) {
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static const char *menu_name(HMENU m)
{
    HMENU bar;
    HMENU file;

    if (m == NULL) {
        return "NULL";
    }
    bar = GetMenu(key_window);
    if (bar == NULL) {
        return "another menu";
    }
    file = GetSubMenu(bar, 0);
    if (m == bar) {
        return "the bar";
    }
    if (m == file) {
        return "File's popup";
    }
    if (m == GetSubMenu(bar, 1)) {
        return "View's popup";
    }
    if (file != NULL && m == GetSubMenu(file, 3)) {
        return "Recent's popup";
    }
    return "another menu";
}

static const char *window_name(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == key_window) {
        return "the window";
    }
    return "another window";
}

static const char *sc_name(WPARAM command)
{
    switch (command & 0xFFF0) {
    case SC_KEYMENU: return "SC_KEYMENU";
    case SC_MOUSEMENU: return "SC_MOUSEMENU";
    case SC_CLOSE: return "SC_CLOSE";
    case SC_MINIMIZE: return "SC_MINIMIZE";
    case SC_MAXIMIZE: return "SC_MAXIMIZE";
    case SC_RESTORE: return "SC_RESTORE";
    case SC_MOVE: return "SC_MOVE";
    case SC_SIZE: return "SC_SIZE";
    case SC_TASKLIST: return "SC_TASKLIST";
    }
    return "?";
}

static void print_menu_records(void)
{
    int i;
    menu_record *r;

    line("received: %d message(s)%s", menu_record_count, menu_records_lost ? ", more lost" : "");
    for (i = 0; i < menu_record_count; i++) {
        r = &menu_records[i];
        switch (r->msg) {
        case WM_TIMER:
            line("  EndMenu at the deadline");
            break;
        case WM_SYSCOMMAND:
            line("  WM_SYSCOMMAND wParam=0x%04lX (%s) lParam=0x%08lX", (unsigned long)r->wparam,
                 sc_name(r->wparam), (unsigned long)r->lparam);
            break;
        case WM_ENTERMENULOOP:
            line("  WM_ENTERMENULOOP wParam=%lu", (unsigned long)r->wparam);
            break;
        case WM_EXITMENULOOP:
            line("  WM_EXITMENULOOP wParam=%lu", (unsigned long)r->wparam);
            break;
        case WM_INITMENU:
            line("  WM_INITMENU %s", menu_name((HMENU)r->wparam));
            break;
        case WM_INITMENUPOPUP:
            line("  WM_INITMENUPOPUP %s position %u system menu %u", menu_name((HMENU)r->wparam),
                 (unsigned)LOWORD(r->lparam), (unsigned)HIWORD(r->lparam));
            break;
        case WM_UNINITMENUPOPUP:
            line("  WM_UNINITMENUPOPUP %s lParam=0x%08lX", menu_name((HMENU)r->wparam),
                 (unsigned long)r->lparam);
            break;
        case WM_MENUSELECT:
            line("  WM_MENUSELECT item %u flags 0x%04X %s", (unsigned)LOWORD(r->wparam),
                 (unsigned)HIWORD(r->wparam), menu_name((HMENU)r->lparam));
            break;
        case WM_MENUCHAR:
            line("  WM_MENUCHAR char 0x%04X flags 0x%04X %s", (unsigned)LOWORD(r->wparam),
                 (unsigned)HIWORD(r->wparam), menu_name((HMENU)r->lparam));
            break;
        case WM_COMMAND:
            line("  WM_COMMAND wParam=0x%08lX lParam %s", (unsigned long)r->wparam,
                 window_name((HWND)r->lparam));
            break;
        case WM_CAPTURECHANGED:
            line("  WM_CAPTURECHANGED lParam %s", window_name((HWND)r->lparam));
            break;
        case WM_CANCELMODE:
            line("  WM_CANCELMODE");
            break;
        }
    }
}

/* Pump until the menu loop has ended (WM_EXITMENULOOP) and 300 ms
 * pass with nothing queued, or 4 seconds pass; whether it ended. */
static int pump_menu_batch(void)
{
    MSG m;
    DWORD start;
    DWORD last;
    DWORD now;
    int got;

    start = GetTickCount();
    last = start;
    for (;;) {
        got = 0;
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            got = 1;
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        now = GetTickCount();
        if (got) {
            last = now;
        }
        if (exit_seen && now - last >= 300) {
            break;
        }
        if (now - start >= 4000) {
            break;
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, 50, QS_ALLINPUT);
    }
    pump_queued();
    return exit_seen;
}

/* Inject one batch into the window, if it is the foreground window,
 * pump it through the menu loop and print what the procedure
 * received. */
static void type_menu_keys(const char *what, const stroke_t *strokes, int n)
{
    f2k_input in[MAX_STROKES];
    UINT sent;
    int i;
    int ended;

    line("-- %s", what);
    if (send_input == NULL) {
        line("SendInput: not exported by user32, no input sent");
        return;
    }
    if (key_window == NULL || GetForegroundWindow() != key_window) {
        line("the window is not the foreground window: no input sent");
        return;
    }
    ZeroMemory(in, sizeof in);
    for (i = 0; i < n && i < MAX_STROKES; i++) {
        in[i].type = INPUT_KEYBOARD;
        in[i].u.ki.wVk = strokes[i].vk;
        in[i].u.ki.wScan = strokes[i].scan;
        in[i].u.ki.dwFlags = strokes[i].flags;
    }
    pump_queued();
    menu_record_count = 0;
    menu_records_lost = 0;
    exit_seen = 0;
    SetTimer(key_window, GUARD_TIMER, GUARD_MS, NULL);
    arm();
    sent = send_input((UINT)n, in, (int)sizeof(f2k_input));
    line("SendInput(%d events): ret=%u err=%s", n, sent, le());
    ended = pump_menu_batch();
    KillTimer(key_window, GUARD_TIMER);
    line("the menu loop ended: %s", yesno(ended));
    print_menu_records();
}

/* The section's window: a visible WS_OVERLAPPEDWINDOW of a class it
 * registers, with a fresh copy of menu 200, made the foreground and
 * focus window. */
static void open_key_window(const WCHAR *class_name, const char *class_text)
{
    WNDCLASSW wc;
    HINSTANCE inst;
    HMODULE user;
    HMENU m;
    ATOM atom;
    BOOL r;

    inst = GetModuleHandleW(NULL);
    user = GetModuleHandleA("user32.dll");
    send_input = NULL;
    end_menu = NULL;
    if (user != NULL) {
        send_input = (send_input_fn)GetProcAddress(user, "SendInput");
        end_menu = (end_menu_fn)GetProcAddress(user, "EndMenu");
    }
    pump_queued();
    UnregisterClassW(class_name, inst);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = menu_proc;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;
    atom = RegisterClassW(&wc);
    m = load_menu();
    key_window = CreateWindowExW(0, class_name, L"menus", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 60, 70,
                                 320, 200, NULL, m, inst, NULL);
    line("setup: the class %s, menu 200 and a visible WS_OVERLAPPEDWINDOW window with it: %s",
         class_text, yesno(atom != 0 && m != NULL && key_window != NULL));
    line("EndMenu exported: %s", yesno(end_menu != NULL));
    if (key_window == NULL) {
        if (m != NULL) {
            DestroyMenu(m);
        }
        return;
    }
    arm();
    r = SetForegroundWindow(key_window);
    line("SetForegroundWindow(h): ret=%d err=%s", r, le());
    SetFocus(key_window);
    pump_queued();
    line("the foreground window: %s; the focus: %s", yesno(GetForegroundWindow() == key_window),
         yesno(GetFocus() == key_window));
}

static void close_key_window(const WCHAR *class_name)
{
    if (key_window != NULL) {
        DestroyWindow(key_window);
        key_window = NULL;
    }
    pump_queued();
    UnregisterClassW(class_name, GetModuleHandleW(NULL));
}

/* --- keyloop ------------------------------------------------------- */

static void sec_keyloop(void)
{
    static const stroke_t keys[] = {
        { VK_MENU, SCAN_ALT, DOWN }, { VK_MENU, SCAN_ALT, UP },
        { 'V', SCAN_V, DOWN }, { 'V', SCAN_V, UP },
        { VK_DOWN, SCAN_DOWN, DOWN | EXT }, { VK_DOWN, SCAN_DOWN, UP | EXT },
        { VK_RETURN, SCAN_ENTER, DOWN }, { VK_RETURN, SCAN_ENTER, UP }
    };
    HMENU bar;

    open_key_window(L"F2KMenusKeyloop", "F2KMenusKeyloop");
    type_menu_keys("Alt, V, Down, Enter", keys, 8);
    bar = key_window != NULL ? GetMenu(key_window) : NULL;
    if (bar != NULL) {
        print_state(bar, ID_STANDARD, MF_BYCOMMAND, "211 after");
        print_state(bar, ID_SCIENTIFIC, MF_BYCOMMAND, "212 after");
        print_state(bar, ID_PROGRAMMER, MF_BYCOMMAND, "213 after");
    }
    close_key_window(L"F2KMenusKeyloop");
}

/* --- keyesc -------------------------------------------------------- */

static void sec_keyesc(void)
{
    static const stroke_t f10[] = {
        { VK_F10, SCAN_F10, DOWN }, { VK_F10, SCAN_F10, UP },
        { VK_RIGHT, SCAN_RIGHT, DOWN | EXT }, { VK_RIGHT, SCAN_RIGHT, UP | EXT },
        { VK_DOWN, SCAN_DOWN, DOWN | EXT }, { VK_DOWN, SCAN_DOWN, UP | EXT },
        { VK_ESCAPE, SCAN_ESC, DOWN }, { VK_ESCAPE, SCAN_ESC, UP },
        { VK_ESCAPE, SCAN_ESC, DOWN }, { VK_ESCAPE, SCAN_ESC, UP }
    };
    static const stroke_t unknown[] = {
        { VK_MENU, SCAN_ALT, DOWN }, { VK_MENU, SCAN_ALT, UP },
        { 'Z', SCAN_Z, DOWN }, { 'Z', SCAN_Z, UP },
        { VK_ESCAPE, SCAN_ESC, DOWN }, { VK_ESCAPE, SCAN_ESC, UP }
    };
    static const stroke_t alone[] = {
        { VK_MENU, SCAN_ALT, DOWN }, { VK_MENU, SCAN_ALT, UP },
        { VK_ESCAPE, SCAN_ESC, DOWN }, { VK_ESCAPE, SCAN_ESC, UP }
    };

    open_key_window(L"F2KMenusKeyesc", "F2KMenusKeyesc");
    type_menu_keys("F10, Right, Down, Esc, Esc", f10, 10);
    type_menu_keys("Alt, Z (no item's mnemonic), Esc", unknown, 6);
    type_menu_keys("Alt, Esc", alone, 4);
    close_key_window(L"F2KMenusKeyesc");
}

/* --- keychar ------------------------------------------------------- */

static void sec_keychar(void)
{
    static const stroke_t held[] = {
        { VK_MENU, SCAN_ALT, DOWN }, { 'V', SCAN_V, DOWN }, { 'V', SCAN_V, UP }, { VK_MENU, SCAN_ALT, UP },
        { VK_UP, SCAN_UP, DOWN | EXT }, { VK_UP, SCAN_UP, UP | EXT },
        { VK_RETURN, SCAN_ENTER, DOWN }, { VK_RETURN, SCAN_ENTER, UP }
    };
    static const stroke_t grayed[] = {
        { VK_MENU, SCAN_ALT, DOWN }, { VK_MENU, SCAN_ALT, UP },
        { 'F', SCAN_F, DOWN }, { 'F', SCAN_F, UP },
        { VK_DOWN, SCAN_DOWN, DOWN | EXT }, { VK_DOWN, SCAN_DOWN, UP | EXT },
        { VK_RETURN, SCAN_ENTER, DOWN }, { VK_RETURN, SCAN_ENTER, UP },
        { VK_ESCAPE, SCAN_ESC, DOWN }, { VK_ESCAPE, SCAN_ESC, UP },
        { VK_ESCAPE, SCAN_ESC, DOWN }, { VK_ESCAPE, SCAN_ESC, UP }
    };

    open_key_window(L"F2KMenusKeychar", "F2KMenusKeychar");
    type_menu_keys("Alt+V held, Up, Enter", held, 8);
    type_menu_keys("Alt, F, Down (onto the grayed Open), Enter, Esc, Esc", grayed, 12);
    close_key_window(L"F2KMenusKeychar");
}

/* --- Menu editing: edit, info, insitem, default, sysmenu, itemrect,
 * track ------------------------------------------------------------- */

/* The MSVC 6 headers predate Windows 2000's additions to menus: the
 * MENUITEMINFO masks that come with its hbmpItem member, the
 * GetMenuDefaultItem flags (WM_UNINITMENUPOPUP is defined above). */
#ifndef MIIM_STRING
#define MIIM_STRING 0x00000040
#endif
#ifndef MIIM_BITMAP
#define MIIM_BITMAP 0x00000080
#endif
#ifndef MIIM_FTYPE
#define MIIM_FTYPE 0x00000100
#endif
#ifndef GMDI_USEDISABLED
#define GMDI_USEDISABLED 0x0001
#endif
#ifndef GMDI_GOINTOPOPUPS
#define GMDI_GOINTOPOPUPS 0x0002
#endif

/* Windows 2000's MENUITEMINFO, hbmpItem included (48 bytes); the MSVC 6
 * headers' struct stops before it (44 bytes, NT 4's size). The calls
 * take it through a cast, their A and W forms alike (dwTypeData points
 * at a WCHAR or a char buffer). */
typedef struct {
    UINT cbSize;
    UINT fMask;
    UINT fType;
    UINT fState;
    UINT wID;
    HMENU hSubMenu;
    HBITMAP hbmpChecked;
    HBITMAP hbmpUnchecked;
    DWORD dwItemData;
    void *dwTypeData;
    UINT cch;
    HBITMAP hbmpItem;
} mii_t;

#define MII_SIZE ((UINT)sizeof(mii_t))
#define MII_NT4_SIZE ((UINT)(sizeof(mii_t) - sizeof(HBITMAP)))

/* What a GetMenuItemInfo call finds in a member it left alone: the
 * struct is filled with 0xA5 bytes before the call. */
#define MII_PATTERN 0xA5A5A5A5u

/* The predefined menu bitmaps' values (HBMMENU_*, Windows 2000). */
#define F2K_HBMMENU_CALLBACK ((HBITMAP)-1)
#define F2K_HBMMENU_POPUP_CLOSE ((HBITMAP)8)

/* The ids the editing sections give their items. */
#define ID_EDIT_BASE 300
#define ID_EDIT_NONE 399

/* The section's known handles, which the printers name. */
static HMENU known_menu_a;
static HMENU known_menu_b;
static HBITMAP known_bitmap;

/* A handle a call returned or left, as printed. */
static const char *handle_label(const void *h)
{
    if ((DWORD)h == MII_PATTERN) {
        return "untouched";
    }
    if (h == NULL) {
        return "NULL";
    }
    if (known_menu_a != NULL && h == (const void *)known_menu_a) {
        return "menu A";
    }
    if (known_menu_b != NULL && h == (const void *)known_menu_b) {
        return "menu B";
    }
    if (known_bitmap != NULL && h == (const void *)known_bitmap) {
        return "the bitmap";
    }
    if ((DWORD)h <= 11 || h == (const void *)F2K_HBMMENU_CALLBACK) {
        return "a predefined HBMMENU value";
    }
    return "other";
}

/* A UINT member, as printed: "untouched", or its value. */
static const char *uint_label(UINT v)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (v == MII_PATTERN) {
        return "untouched";
    }
    sprintf(b, "%ld", (long)v);
    return b;
}

/* A menu's text as printed: ws(), with a tab shown as \t. */
static const char *menu_text(const WCHAR *s)
{
    static char bufs[4][1100];
    static int next;
    char *b = bufs[next++ & 3];
    const char *t = ws(s);
    int n = 0;

    for (; *t != '\0' && n < (int)sizeof bufs[0] - 3; t++) {
        if (*t == '\t') {
            b[n++] = '\\';
            b[n++] = 't';
        } else {
            b[n++] = *t;
        }
    }
    b[n] = '\0';
    return b;
}

/* Every item of a menu by position: its id (in hex for the system
 * menu's SC_* ids), its state and its text. */
static void dump_menu(HMENU m, const char *name, int hex)
{
    int n, i;
    UINT id, s;
    WCHAR buf[64];

    arm();
    n = GetMenuItemCount(m);
    line("  %s: GetMenuItemCount ret=%d err=%s", name, n, le());
    for (i = 0; i < n && i < 32; i++) {
        id = GetMenuItemID(m, i);
        s = GetMenuState(m, i, MF_BYPOSITION);
        buf[0] = 0;
        GetMenuStringW(m, i, buf, 64, MF_BYPOSITION);
        if (id == (UINT)-1) {
            line("  %s %d: id=-1 state=0x%X text \"%s\"", name, i, s, menu_text(buf));
        } else if (hex) {
            line("  %s %d: id=0x%X state=0x%X text \"%s\"", name, i, id, s, menu_text(buf));
        } else {
            line("  %s %d: id=%u state=0x%X text \"%s\"", name, i, id, s, menu_text(buf));
        }
    }
}

static void append_w(HMENU m, UINT flags, UINT id, const WCHAR *text, const char *what)
{
    BOOL r;

    arm();
    r = AppendMenuW(m, flags, id, text);
    line("AppendMenuW(%s): ret=%d err=%s", what, r, le());
}

static void insert_w(HMENU m, UINT pos, UINT flags, UINT id, const WCHAR *text, const char *what)
{
    BOOL r;

    arm();
    r = InsertMenuW(m, pos, flags, id, text);
    line("InsertMenuW(%s): ret=%d err=%s", what, r, le());
}

static void modify_w(HMENU m, UINT pos, UINT flags, UINT id, const WCHAR *text, const char *what)
{
    BOOL r;

    arm();
    r = ModifyMenuW(m, pos, flags, id, text);
    line("ModifyMenuW(%s): ret=%d err=%s", what, r, le());
}

static void delete_item(HMENU m, UINT pos, UINT flags, const char *what)
{
    BOOL r;

    arm();
    r = DeleteMenu(m, pos, flags);
    line("DeleteMenu(%s): ret=%d err=%s", what, r, le());
}

static void remove_item(HMENU m, UINT pos, UINT flags, const char *what)
{
    BOOL r;

    arm();
    r = RemoveMenu(m, pos, flags);
    line("RemoveMenu(%s): ret=%d err=%s", what, r, le());
}

/* --- edit ---------------------------------------------------------- */

static void sec_edit(void)
{
    HMENU p, bar, more, bar2, kept, gone, got;
    BOOL r;

    arm();
    p = CreatePopupMenu();
    line("CreatePopupMenu: non-NULL %s err=%s", yesno(p != NULL), le());
    append_w(p, MF_STRING, 301, L"&One", "popup, MF_STRING, 301 &One");
    append_w(p, MF_STRING, 302, L"&Two", "popup, MF_STRING, 302 &Two");
    append_w(p, MF_SEPARATOR, 0, NULL, "popup, MF_SEPARATOR, 0, NULL");
    arm();
    r = AppendMenuA(p, MF_STRING | MF_CHECKED, 303, "T&hree");
    line("AppendMenuA(popup, MF_STRING | MF_CHECKED, 303 T&hree): ret=%d err=%s", r, le());
    append_w(p, MF_STRING | MF_GRAYED, 304, L"Four", "popup, MF_STRING | MF_GRAYED, 304 Four");
    append_w(p, MF_STRING, 308, NULL, "popup, MF_STRING, 308, NULL text");
    append_w(NULL, MF_STRING, 309, L"Nowhere", "NULL, MF_STRING, 309 Nowhere");
    dump_menu(p, "popup", 0);

    insert_w(p, 0, MF_BYPOSITION | MF_STRING, 305, L"Zero", "popup, 0, MF_BYPOSITION | MF_STRING, 305 Zero");
    insert_w(p, 302, MF_BYCOMMAND | MF_STRING, 306, L"Before two",
             "popup, 302, MF_BYCOMMAND | MF_STRING, 306 Before two");
    insert_w(p, (UINT)-1, MF_BYPOSITION | MF_STRING, 307, L"Last",
             "popup, -1, MF_BYPOSITION | MF_STRING, 307 Last");
    insert_w(p, 99, MF_BYPOSITION | MF_STRING, 310, L"Far",
             "popup, 99 (past the end), MF_BYPOSITION | MF_STRING, 310 Far");
    insert_w(p, ID_EDIT_NONE, MF_BYCOMMAND | MF_STRING, 311, L"Lost",
             "popup, 399 (no such item), MF_BYCOMMAND | MF_STRING, 311 Lost");
    arm();
    r = InsertMenuA(p, 1, MF_BYPOSITION | MF_STRING, 312, "Zero (A)");
    line("InsertMenuA(popup, 1, MF_BYPOSITION | MF_STRING, 312 Zero (A)): ret=%d err=%s", r, le());
    dump_menu(p, "popup", 0);

    arm();
    bar = CreateMenu();
    line("CreateMenu: non-NULL %s err=%s", yesno(bar != NULL), le());
    append_w(bar, MF_POPUP | MF_STRING, (UINT)p, L"&Edit", "bar, MF_POPUP | MF_STRING, the popup, &Edit");
    append_w(bar, MF_STRING, 320, L"&Go", "bar, MF_STRING, 320 &Go");
    dump_menu(bar, "bar", 0);
    insert_w(bar, 304, MF_BYCOMMAND | MF_STRING, 313, L"Nested",
             "bar, 304 (in the popup), MF_BYCOMMAND | MF_STRING, 313 Nested");
    dump_menu(bar, "bar", 0);
    dump_menu(p, "popup", 0);

    modify_w(bar, 301, MF_BYCOMMAND | MF_STRING, 321, L"Uno",
             "bar, 301 (in the popup), MF_BYCOMMAND | MF_STRING, 321 Uno");
    modify_w(p, 1, MF_BYPOSITION | MF_STRING | MF_CHECKED, 322, L"Checked",
             "popup, 1, MF_BYPOSITION | MF_STRING | MF_CHECKED, 322 Checked");
    arm();
    r = ModifyMenuA(p, 2, MF_BYPOSITION | MF_STRING, 323, "Changed (A)");
    line("ModifyMenuA(popup, 2, MF_BYPOSITION | MF_STRING, 323 Changed (A)): ret=%d err=%s", r, le());
    modify_w(p, 304, MF_BYCOMMAND | MF_SEPARATOR, 0, NULL, "popup, 304 Four, MF_BYCOMMAND | MF_SEPARATOR");
    modify_w(p, 303, MF_BYCOMMAND | MF_STRING, 303, L"Three again",
             "popup, 303 (checked), MF_BYCOMMAND | MF_STRING, 303 Three again");
    modify_w(p, ID_EDIT_NONE, MF_BYCOMMAND | MF_STRING, 324, L"Lost",
             "popup, 399 (no such item), MF_BYCOMMAND | MF_STRING");
    modify_w(p, 50, MF_BYPOSITION | MF_STRING, 325, L"Lost", "popup, 50 (past the end), MF_BYPOSITION");
    dump_menu(p, "popup", 0);
    more = CreatePopupMenu();
    AppendMenuW(more, MF_STRING, 341, L"Inside");
    modify_w(bar, 1, MF_BYPOSITION | MF_POPUP | MF_STRING, (UINT)more, L"&More",
             "bar, 1 &Go, MF_BYPOSITION | MF_POPUP | MF_STRING, a second popup, &More");
    dump_menu(bar, "bar", 0);
    arm();
    got = GetSubMenu(bar, 1);
    line("  GetSubMenu(bar, 1): the second popup %s err=%s", yesno(got == more), le());

    delete_item(p, 0, MF_BYPOSITION, "popup, 0, MF_BYPOSITION");
    delete_item(bar, 321, MF_BYCOMMAND, "bar, 321 (in the popup), MF_BYCOMMAND");
    delete_item(p, 321, MF_BYCOMMAND, "popup, 321 again, MF_BYCOMMAND");
    delete_item(p, ID_EDIT_NONE, MF_BYCOMMAND, "popup, 399 (no such item), MF_BYCOMMAND");
    delete_item(p, 40, MF_BYPOSITION, "popup, 40 (past the end), MF_BYPOSITION");
    remove_item(p, 0, MF_BYPOSITION, "popup, 0, MF_BYPOSITION");
    remove_item(p, 307, MF_BYCOMMAND, "popup, 307 Last, MF_BYCOMMAND");
    remove_item(p, ID_EDIT_NONE, MF_BYCOMMAND, "popup, 399 (no such item), MF_BYCOMMAND");
    remove_item(p, 40, MF_BYPOSITION, "popup, 40 (past the end), MF_BYPOSITION");
    delete_item(NULL, 0, MF_BYPOSITION, "NULL, 0, MF_BYPOSITION");
    remove_item(NULL, 0, MF_BYPOSITION, "NULL, 0, MF_BYPOSITION");
    dump_menu(p, "popup", 0);

    /* A popup taken off a bar by RemoveMenu, another by DeleteMenu. */
    bar2 = CreateMenu();
    kept = CreatePopupMenu();
    AppendMenuW(kept, MF_STRING, 331, L"Kept");
    gone = CreatePopupMenu();
    AppendMenuW(gone, MF_STRING, 332, L"Gone");
    append_w(bar2, MF_POPUP | MF_STRING, (UINT)kept, L"&Removed", "a second bar, MF_POPUP, popup K, &Removed");
    append_w(bar2, MF_POPUP | MF_STRING, (UINT)gone, L"&Deleted", "a second bar, MF_POPUP, popup D, &Deleted");
    remove_item(bar2, 0, MF_BYPOSITION, "the second bar, 0 &Removed (popup K), MF_BYPOSITION");
    arm();
    r = IsMenu(kept);
    line("  IsMenu(popup K) after: ret=%d err=%s", r, le());
    dump_menu(kept, "popup K", 0);
    delete_item(bar2, 0, MF_BYPOSITION, "the second bar, 0 &Deleted (popup D), MF_BYPOSITION");
    arm();
    r = IsMenu(gone);
    line("  IsMenu(popup D) after: ret=%d err=%s", r, le());
    dump_menu(bar2, "the second bar", 0);

    /* DestroyMenu of the bar takes its popups with it. */
    arm();
    r = DestroyMenu(bar);
    line("DestroyMenu(bar): ret=%d err=%s", r, le());
    arm();
    r = IsMenu(p);
    line("  IsMenu(the popup) after: ret=%d err=%s", r, le());
    arm();
    r = IsMenu(more);
    line("  IsMenu(the second popup) after: ret=%d err=%s", r, le());
    DestroyMenu(bar2);
    DestroyMenu(kept);
}

/* --- info ---------------------------------------------------------- */

/* The members a GetMenuItemInfo call left, and its buffer. */
static void print_mii(const mii_t *mi)
{
    line("  fType=0x%X fState=0x%X wID=%s hSubMenu=%s hbmpChecked=%s hbmpUnchecked=%s", mi->fType, mi->fState,
         uint_label(mi->wID), handle_label(mi->hSubMenu), handle_label(mi->hbmpChecked),
         handle_label(mi->hbmpUnchecked));
    line("  dwItemData=0x%lX dwTypeData=%s cch=%s hbmpItem=%s", mi->dwItemData,
         mi->dwTypeData == NULL ? "NULL" : ((DWORD)mi->dwTypeData == MII_PATTERN ? "untouched" : "set"),
         uint_label(mi->cch), handle_label(mi->hbmpItem));
}

/* GetMenuItemInfoW: the struct filled with the pattern, then cbSize,
 * fMask, dwTypeData (a 32-unit buffer holding "########", or NULL) and
 * cch set. */
static void get_info_w(HMENU m, UINT item, BOOL by_position, UINT size, UINT mask, int with_buffer, UINT cch,
                       const char *what)
{
    mii_t mi;
    WCHAR buf[32];
    BOOL r;

    lstrcpyW(buf, UNFILLED_W);
    memset(&mi, 0xA5, sizeof mi);
    mi.cbSize = size;
    mi.fMask = mask;
    mi.dwTypeData = with_buffer ? (void *)buf : NULL;
    mi.cch = cch;
    arm();
    r = GetMenuItemInfoW(m, item, by_position, (LPMENUITEMINFOW)&mi);
    line("GetMenuItemInfoW(%s): ret=%d err=%s", what, r, le());
    print_mii(&mi);
    if (with_buffer) {
        line("  buffer \"%s\" dwTypeData the buffer %s", ws(buf), yesno(mi.dwTypeData == (void *)buf));
    }
}

/* GetMenuItemInfoA, the same way. */
static void get_info_a(HMENU m, UINT item, BOOL by_position, UINT size, UINT mask, int with_buffer, UINT cch,
                       const char *what)
{
    mii_t mi;
    char buf[32];
    BOOL r;

    lstrcpyA(buf, UNFILLED_A);
    memset(&mi, 0xA5, sizeof mi);
    mi.cbSize = size;
    mi.fMask = mask;
    mi.dwTypeData = with_buffer ? (void *)buf : NULL;
    mi.cch = cch;
    arm();
    r = GetMenuItemInfoA(m, item, by_position, (LPMENUITEMINFOA)&mi);
    line("GetMenuItemInfoA(%s): ret=%d err=%s", what, r, le());
    print_mii(&mi);
    if (with_buffer) {
        line("  buffer \"%s\" dwTypeData the buffer %s", buf, yesno(mi.dwTypeData == (void *)buf));
    }
}

/* A zeroed struct of Windows 2000's size with fMask set. */
static void mii_init(mii_t *mi, UINT mask)
{
    ZeroMemory(mi, sizeof *mi);
    mi->cbSize = MII_SIZE;
    mi->fMask = mask;
}

static void set_info_w(HMENU m, UINT item, BOOL by_position, mii_t *mi, const char *what)
{
    BOOL r;

    arm();
    r = SetMenuItemInfoW(m, item, by_position, (LPMENUITEMINFOW)mi);
    line("SetMenuItemInfoW(%s): ret=%d err=%s", what, r, le());
}

static void sec_info(void)
{
    HMENU p, sub, attached;
    mii_t mi;
    BOOL r;
    UINT id;

    /* The popup: 0 &Alpha (401, checked), 1 &Sub (menu B, holding
     * Inner, 411), 2 a separator, 3 Gamma (403, grayed). */
    p = CreatePopupMenu();
    sub = CreatePopupMenu();
    known_menu_a = p;
    known_menu_b = sub;
    known_bitmap = LoadBitmapW(NULL, MAKEINTRESOURCEW(32760));
    line("CreatePopupMenu twice (menu A, menu B): non-NULL %s; LoadBitmapW(NULL, OBM_CHECK): non-NULL %s",
         yesno(p != NULL && sub != NULL), yesno(known_bitmap != NULL));
    AppendMenuW(p, MF_STRING | MF_CHECKED, 401, L"&Alpha");
    AppendMenuW(sub, MF_STRING, 411, L"Inner");
    AppendMenuW(p, MF_POPUP | MF_STRING, (UINT)sub, L"&Sub");
    AppendMenuW(p, MF_SEPARATOR, 0, NULL);
    AppendMenuW(p, MF_STRING | MF_GRAYED, 403, L"Gamma");
    dump_menu(p, "menu A", 0);

    /* Each mask alone, then all of them, on 0 &Alpha. */
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STATE, 1, 20, "A, 0, by position, MIIM_STATE");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_ID, 1, 20, "A, 0, by position, MIIM_ID");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_SUBMENU, 1, 20, "A, 0, by position, MIIM_SUBMENU");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_CHECKMARKS, 1, 20, "A, 0, by position, MIIM_CHECKMARKS");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_TYPE, 1, 20, "A, 0, by position, MIIM_TYPE, cch 20");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_DATA, 1, 20, "A, 0, by position, MIIM_DATA");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 20, "A, 0, by position, MIIM_STRING, cch 20");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_BITMAP, 1, 20, "A, 0, by position, MIIM_BITMAP");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_FTYPE, 1, 20, "A, 0, by position, MIIM_FTYPE");
    get_info_w(p, 0, TRUE, MII_SIZE, 0x1FF, 1, 20, "A, 0, by position, every mask, cch 20");
    get_info_w(p, 0, TRUE, MII_SIZE, 0, 1, 20, "A, 0, by position, no mask");

    /* The string's length and cch: no buffer, a short one, one unit
     * short of the terminator, exactly enough, none at all. */
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 0, 20, "A, 0, MIIM_STRING, dwTypeData NULL, cch 20");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 0, 0, "A, 0, MIIM_STRING, dwTypeData NULL, cch 0");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_TYPE, 0, 20, "A, 0, MIIM_TYPE, dwTypeData NULL, cch 20");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 3, "A, 0, MIIM_STRING, cch 3");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 6, "A, 0, MIIM_STRING, cch 6 (the length)");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 7, "A, 0, MIIM_STRING, cch 7");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 0, "A, 0, MIIM_STRING, cch 0");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_TYPE, 1, 3, "A, 0, MIIM_TYPE, cch 3");
    get_info_a(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 20, "A, 0, MIIM_STRING, cch 20");
    get_info_a(p, 0, TRUE, MII_SIZE, MIIM_STRING, 0, 20, "A, 0, MIIM_STRING, dwTypeData NULL, cch 20");
    get_info_a(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 3, "A, 0, MIIM_STRING, cch 3");
    get_info_a(p, 0, TRUE, MII_SIZE, MIIM_TYPE, 1, 20, "A, 0, MIIM_TYPE, cch 20");

    /* The popup item, the separator, by command, nested, missing. */
    get_info_w(p, 1, TRUE, MII_SIZE, MIIM_SUBMENU | MIIM_ID | MIIM_STATE | MIIM_FTYPE | MIIM_STRING, 1, 20,
               "A, 1 &Sub, by position, MIIM_SUBMENU | MIIM_ID | MIIM_STATE | MIIM_FTYPE | MIIM_STRING");
    get_info_w(p, 1, TRUE, MII_SIZE, MIIM_TYPE, 1, 20, "A, 1 &Sub, by position, MIIM_TYPE");
    get_info_w(p, 2, TRUE, MII_SIZE, MIIM_TYPE | MIIM_ID | MIIM_STATE, 1, 20,
               "A, 2 the separator, MIIM_TYPE | MIIM_ID | MIIM_STATE");
    get_info_w(p, 2, TRUE, MII_SIZE, MIIM_FTYPE | MIIM_STRING, 1, 20,
               "A, 2 the separator, MIIM_FTYPE | MIIM_STRING");
    get_info_w(p, 403, FALSE, MII_SIZE, MIIM_ID | MIIM_STATE | MIIM_STRING, 1, 20,
               "A, 403 Gamma, by command, MIIM_ID | MIIM_STATE | MIIM_STRING");
    get_info_w(p, 411, FALSE, MII_SIZE, MIIM_ID | MIIM_STRING, 1, 20,
               "A, 411 Inner (in menu B), by command, MIIM_ID | MIIM_STRING");
    get_info_w(p, 499, FALSE, MII_SIZE, MIIM_ID, 1, 20, "A, 499 (no such item), by command, MIIM_ID");
    get_info_w(p, 9, TRUE, MII_SIZE, MIIM_ID, 1, 20, "A, 9 (past the end), by position, MIIM_ID");
    get_info_w(NULL, 0, TRUE, MII_SIZE, MIIM_ID, 1, 20, "NULL, 0, by position, MIIM_ID");

    /* cbSize: NT 4's, with the old masks and the new; none; too large. */
    get_info_w(p, 0, TRUE, MII_NT4_SIZE, MIIM_TYPE | MIIM_ID, 1, 20, "A, 0, cbSize 44, MIIM_TYPE | MIIM_ID");
    get_info_w(p, 0, TRUE, MII_NT4_SIZE, MIIM_STRING, 1, 20, "A, 0, cbSize 44, MIIM_STRING");
    get_info_w(p, 0, TRUE, 0, MIIM_ID, 1, 20, "A, 0, cbSize 0, MIIM_ID");
    get_info_w(p, 0, TRUE, MII_SIZE + 4, MIIM_ID, 1, 20, "A, 0, cbSize 52, MIIM_ID");

    /* SetMenuItemInfoW, each mask, then the item read back. */
    mii_init(&mi, MIIM_STRING);
    mi.dwTypeData = L"&Beta";
    mi.cch = 2;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_STRING &Beta, cch 2");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING | MIIM_FTYPE, 1, 20, "A, 0 after, MIIM_STRING | MIIM_FTYPE");
    mii_init(&mi, MIIM_STRING);
    mi.dwTypeData = "&Beta (A)";
    arm();
    r = SetMenuItemInfoA(p, 0, TRUE, (LPMENUITEMINFOA)&mi);
    line("SetMenuItemInfoA(A, 0, MIIM_STRING &Beta (A)): ret=%d err=%s", r, le());
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STRING, 1, 20, "A, 0 after, MIIM_STRING");
    mii_init(&mi, MIIM_FTYPE);
    mi.fType = MFT_RADIOCHECK | MFT_RIGHTJUSTIFY;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_FTYPE MFT_RADIOCHECK | MFT_RIGHTJUSTIFY");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_FTYPE | MIIM_STRING, 1, 20, "A, 0 after, MIIM_FTYPE | MIIM_STRING");
    mii_init(&mi, MIIM_STATE);
    mi.fState = MFS_CHECKED | MFS_DEFAULT | MFS_HILITE;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_STATE MFS_CHECKED | MFS_DEFAULT | MFS_HILITE");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STATE, 1, 20, "A, 0 after, MIIM_STATE");
    print_state(p, 0, MF_BYPOSITION, "A, 0 after");
    mii_init(&mi, MIIM_STATE);
    mi.fState = MFS_DISABLED;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_STATE MFS_DISABLED");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_STATE, 1, 20, "A, 0 after, MIIM_STATE");
    mii_init(&mi, MIIM_ID);
    mi.wID = 421;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_ID 421");
    arm();
    id = GetMenuItemID(p, 0);
    line("  GetMenuItemID(A, 0) after: ret=%ld err=%s", as_long(id), le());
    mii_init(&mi, MIIM_DATA);
    mi.dwItemData = 0x1234;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_DATA 0x1234");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_DATA, 1, 20, "A, 0 after, MIIM_DATA");
    mii_init(&mi, MIIM_CHECKMARKS);
    mi.hbmpChecked = known_bitmap;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_CHECKMARKS the bitmap, NULL");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_CHECKMARKS, 1, 20, "A, 0 after, MIIM_CHECKMARKS");
    mii_init(&mi, MIIM_BITMAP);
    mi.hbmpItem = F2K_HBMMENU_POPUP_CLOSE;
    set_info_w(p, 0, TRUE, &mi, "A, 0, MIIM_BITMAP HBMMENU_POPUP_CLOSE");
    get_info_w(p, 0, TRUE, MII_SIZE, MIIM_BITMAP | MIIM_FTYPE | MIIM_STRING, 1, 20,
               "A, 0 after, MIIM_BITMAP | MIIM_FTYPE | MIIM_STRING");
    mii_init(&mi, MIIM_TYPE);
    mi.fType = MFT_STRING;
    mi.dwTypeData = L"Typed";
    set_info_w(p, 3, TRUE, &mi, "A, 3 Gamma, MIIM_TYPE MFT_STRING Typed");
    get_info_w(p, 3, TRUE, MII_SIZE, MIIM_TYPE, 1, 20, "A, 3 after, MIIM_TYPE");
    mii_init(&mi, MIIM_TYPE | MIIM_STRING);
    mi.fType = MFT_STRING;
    mi.dwTypeData = L"Both";
    set_info_w(p, 3, TRUE, &mi, "A, 3, MIIM_TYPE | MIIM_STRING Both");
    get_info_w(p, 3, TRUE, MII_SIZE, MIIM_STRING, 1, 20, "A, 3 after, MIIM_STRING");

    /* A popup attached to an item and taken off again. */
    attached = CreatePopupMenu();
    AppendMenuW(attached, MF_STRING, 431, L"Attached");
    known_menu_b = attached;
    mii_init(&mi, MIIM_SUBMENU);
    mi.hSubMenu = attached;
    set_info_w(p, 403, FALSE, &mi, "A, 403, by command, MIIM_SUBMENU a new popup (now menu B)");
    get_info_w(p, 3, TRUE, MII_SIZE, MIIM_SUBMENU | MIIM_ID, 1, 20, "A, 3 after, MIIM_SUBMENU | MIIM_ID");
    print_state(p, 3, MF_BYPOSITION, "A, 3 after");
    mii_init(&mi, MIIM_SUBMENU);
    mi.hSubMenu = NULL;
    set_info_w(p, 3, TRUE, &mi, "A, 3, MIIM_SUBMENU NULL");
    get_info_w(p, 3, TRUE, MII_SIZE, MIIM_SUBMENU | MIIM_ID, 1, 20, "A, 3 after, MIIM_SUBMENU | MIIM_ID");
    arm();
    r = IsMenu(attached);
    line("  IsMenu(menu B) after: ret=%d err=%s", r, le());
    known_menu_b = sub;

    /* Calls that fail. */
    mii_init(&mi, MIIM_ID);
    mi.wID = 450;
    set_info_w(p, 499, FALSE, &mi, "A, 499 (no such item), by command, MIIM_ID");
    set_info_w(p, 9, TRUE, &mi, "A, 9 (past the end), by position, MIIM_ID");
    set_info_w(NULL, 0, TRUE, &mi, "NULL, 0, MIIM_ID");
    mi.cbSize = 0;
    set_info_w(p, 0, TRUE, &mi, "A, 0, cbSize 0, MIIM_ID");
    dump_menu(p, "menu A", 0);

    DestroyMenu(p);
    if (IsMenu(attached)) {
        DestroyMenu(attached);
    }
    known_menu_a = NULL;
    known_menu_b = NULL;
    known_bitmap = NULL;
}

/* --- insitem ------------------------------------------------------- */

static void insert_item_w(HMENU m, UINT item, BOOL by_position, mii_t *mi, const char *what)
{
    BOOL r;

    arm();
    r = InsertMenuItemW(m, item, by_position, (LPMENUITEMINFOW)mi);
    line("InsertMenuItemW(%s): ret=%d err=%s", what, r, le());
}

static void sec_insitem(void)
{
    HMENU p, sub;
    mii_t mi;
    BOOL r;

    p = CreatePopupMenu();
    sub = CreatePopupMenu();
    known_menu_a = p;
    known_menu_b = sub;
    line("CreatePopupMenu twice (menu A, menu B): non-NULL %s", yesno(p != NULL && sub != NULL));
    AppendMenuW(sub, MF_STRING, 511, L"Inner");

    mii_init(&mi, MIIM_ID | MIIM_STRING);
    mi.wID = 501;
    mi.dwTypeData = L"First";
    insert_item_w(p, 0, TRUE, &mi, "A (empty), 0, by position, MIIM_ID | MIIM_STRING 501 First");
    mi.wID = 502;
    mi.dwTypeData = L"Second";
    insert_item_w(p, 5, TRUE, &mi, "A, 5 (past the end), by position, 502 Second");
    mi.wID = 503;
    mi.dwTypeData = L"Before first";
    insert_item_w(p, 501, FALSE, &mi, "A, 501, by command, 503 Before first");
    mi.wID = 504;
    mi.dwTypeData = L"Lost";
    insert_item_w(p, 599, FALSE, &mi, "A, 599 (no such item), by command, 504 Lost");
    mi.wID = 505;
    mi.dwTypeData = L"Appended";
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, by position, 505 Appended");
    mii_init(&mi, MIIM_FTYPE);
    mi.fType = MFT_SEPARATOR;
    insert_item_w(p, 1, TRUE, &mi, "A, 1, MIIM_FTYPE MFT_SEPARATOR");
    mii_init(&mi, MIIM_TYPE | MIIM_ID);
    mi.fType = MFT_STRING;
    mi.wID = 506;
    mi.dwTypeData = L"Typed";
    insert_item_w(p, 0, TRUE, &mi, "A, 0, MIIM_TYPE | MIIM_ID MFT_STRING 506 Typed");
    mii_init(&mi, MIIM_ID | MIIM_STRING | MIIM_STATE);
    mi.wID = 507;
    mi.dwTypeData = L"Checked default";
    mi.fState = MFS_CHECKED | MFS_DEFAULT;
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, MIIM_ID | MIIM_STRING | MIIM_STATE MFS_CHECKED | MFS_DEFAULT 507");
    mii_init(&mi, MIIM_ID | MIIM_STRING | MIIM_STATE);
    mi.wID = 508;
    mi.dwTypeData = L"Grayed";
    mi.fState = MFS_GRAYED;
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, MIIM_STATE MFS_GRAYED 508 Grayed");
    mii_init(&mi, MIIM_SUBMENU | MIIM_STRING | MIIM_ID);
    mi.hSubMenu = sub;
    mi.wID = 509;
    mi.dwTypeData = L"&Sub";
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, MIIM_SUBMENU menu B | MIIM_STRING | MIIM_ID 509 &Sub");
    mii_init(&mi, MIIM_ID | MIIM_DATA);
    mi.wID = 510;
    mi.dwItemData = 0x5678;
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, MIIM_ID | MIIM_DATA 510 0x5678 (no string)");
    mii_init(&mi, MIIM_ID | MIIM_STRING);
    mi.wID = 512;
    mi.dwTypeData = "Wide? no (A)";
    arm();
    r = InsertMenuItemA(p, (UINT)-1, TRUE, (LPMENUITEMINFOA)&mi);
    line("InsertMenuItemA(A, -1, by position, MIIM_ID | MIIM_STRING 512 Wide? no (A)): ret=%d err=%s", r, le());
    mii_init(&mi, MIIM_TYPE | MIIM_ID);
    mi.cbSize = MII_NT4_SIZE;
    mi.fType = MFT_STRING;
    mi.wID = 513;
    mi.dwTypeData = L"Old size";
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, cbSize 44, MIIM_TYPE | MIIM_ID 513 Old size");
    mii_init(&mi, MIIM_ID | MIIM_STRING);
    mi.cbSize = 0;
    mi.wID = 514;
    mi.dwTypeData = L"No size";
    insert_item_w(p, (UINT)-1, TRUE, &mi, "A, -1, cbSize 0, 514 No size");
    mii_init(&mi, MIIM_ID | MIIM_STRING);
    mi.wID = 515;
    mi.dwTypeData = L"Nowhere";
    insert_item_w(NULL, 0, TRUE, &mi, "NULL, 0, 515 Nowhere");
    dump_menu(p, "menu A", 0);

    get_info_w(p, 4, TRUE, MII_SIZE, 0x1FF, 1, 20, "A, 4, by position, every mask");
    get_info_w(p, 507, FALSE, MII_SIZE, MIIM_STATE | MIIM_FTYPE, 1, 20, "A, 507, by command, MIIM_STATE | MIIM_FTYPE");
    get_info_w(p, 509, FALSE, MII_SIZE, MIIM_SUBMENU | MIIM_ID, 1, 20, "A, 509, by command, MIIM_SUBMENU | MIIM_ID");
    get_info_w(p, 510, FALSE, MII_SIZE, MIIM_DATA | MIIM_FTYPE | MIIM_STRING, 1, 20,
               "A, 510, by command, MIIM_DATA | MIIM_FTYPE | MIIM_STRING");

    DestroyMenu(p);
    known_menu_a = NULL;
    known_menu_b = NULL;
}

/* --- default ------------------------------------------------------- */

static void get_default(HMENU m, UINT by_position, UINT flags, const char *what)
{
    UINT r;

    arm();
    r = GetMenuDefaultItem(m, by_position, flags);
    line("GetMenuDefaultItem(%s): ret=%ld err=%s", what, as_long(r), le());
}

static void set_default(HMENU m, UINT item, UINT by_position, const char *what)
{
    BOOL r;

    arm();
    r = SetMenuDefaultItem(m, item, by_position);
    line("SetMenuDefaultItem(%s): ret=%d err=%s", what, r, le());
}

/* The default item, each way of asking. */
static void get_defaults(HMENU m)
{
    get_default(m, FALSE, 0, "A, by command, 0");
    get_default(m, TRUE, 0, "A, by position, 0");
    get_default(m, FALSE, GMDI_USEDISABLED, "A, by command, GMDI_USEDISABLED");
    get_default(m, FALSE, GMDI_GOINTOPOPUPS, "A, by command, GMDI_GOINTOPOPUPS");
    get_default(m, TRUE, GMDI_GOINTOPOPUPS, "A, by position, GMDI_GOINTOPOPUPS");
    get_default(m, FALSE, GMDI_USEDISABLED | GMDI_GOINTOPOPUPS,
                "A, by command, GMDI_USEDISABLED | GMDI_GOINTOPOPUPS");
}

static void sec_default(void)
{
    HMENU p, sub;
    mii_t mi;

    /* Menu A: 0 A (601), 1 B (602, grayed), 2 a separator, 3 C (603),
     * 4 &D, a popup holding 0 X (611), 1 Y (612). */
    p = CreatePopupMenu();
    sub = CreatePopupMenu();
    line("CreatePopupMenu twice (menu A, menu B): non-NULL %s", yesno(p != NULL && sub != NULL));
    AppendMenuW(p, MF_STRING, 601, L"A");
    AppendMenuW(p, MF_STRING | MF_GRAYED, 602, L"B");
    AppendMenuW(p, MF_SEPARATOR, 0, NULL);
    AppendMenuW(p, MF_STRING, 603, L"C");
    AppendMenuW(sub, MF_STRING, 611, L"X");
    AppendMenuW(sub, MF_STRING, 612, L"Y");
    AppendMenuW(p, MF_POPUP | MF_STRING, (UINT)sub, L"&D");

    line("-- none set");
    get_defaults(p);
    set_default(p, 603, FALSE, "A, 603 C, by command");
    print_state(p, 603, MF_BYCOMMAND, "A, 603 C");
    get_defaults(p);
    set_default(p, 1, TRUE, "A, 1 B (grayed), by position");
    print_state(p, 603, MF_BYCOMMAND, "A, 603 C");
    print_state(p, 602, MF_BYCOMMAND, "A, 602 B");
    get_defaults(p);
    set_default(p, 4, TRUE, "A, 4 &D (the popup), by position");
    line("-- menu B's default none");
    get_defaults(p);
    set_default(sub, 612, FALSE, "B, 612 Y, by command");
    line("-- menu B's default 612 Y");
    get_defaults(p);
    set_default(p, 2, TRUE, "A, 2 the separator, by position");
    get_defaults(p);
    set_default(p, (UINT)-1, FALSE, "A, -1 (none), by command");
    print_state(p, 4, MF_BYPOSITION, "A, 4 &D");
    get_defaults(p);
    set_default(p, 699, FALSE, "A, 699 (no such item), by command");
    set_default(p, 9, TRUE, "A, 9 (past the end), by position");
    set_default(p, 611, FALSE, "A, 611 X (in menu B), by command");
    get_default(sub, FALSE, 0, "B, by command, 0");
    get_defaults(p);
    set_default(NULL, 0, TRUE, "NULL, 0, by position");
    get_default(NULL, FALSE, 0, "NULL, by command, 0");

    /* MFS_DEFAULT given through SetMenuItemInfoW, to two items. */
    set_default(p, (UINT)-1, FALSE, "A, -1 (none), by command");
    mii_init(&mi, MIIM_STATE);
    mi.fState = MFS_DEFAULT;
    set_info_w(p, 3, TRUE, &mi, "A, 3 C, MIIM_STATE MFS_DEFAULT");
    get_default(p, FALSE, 0, "A, by command, 0");
    set_info_w(p, 0, TRUE, &mi, "A, 0 A, MIIM_STATE MFS_DEFAULT");
    get_default(p, FALSE, 0, "A, by command, 0");
    print_state(p, 0, MF_BYPOSITION, "A, 0 A");
    print_state(p, 3, MF_BYPOSITION, "A, 3 C");

    DestroyMenu(p);
}

/* --- The windows of sysmenu, itemrect and track -------------------- */

#define OWNER_CLASS L"F2KMenusOwner"

/* The menu messages the owner window's procedure records (track). */
#define MAX_TRACK_RECORDS 32

typedef struct {
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
} track_record_t;

static track_record_t track_records[MAX_TRACK_RECORDS];
static int track_record_count;

static LRESULT CALLBACK owner_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_INITMENU:
    case WM_INITMENUPOPUP:
    case WM_UNINITMENUPOPUP:
    case WM_MENUSELECT:
    case WM_ENTERMENULOOP:
    case WM_EXITMENULOOP:
    case WM_CANCELMODE:
    case WM_COMMAND:
        if (track_record_count < MAX_TRACK_RECORDS) {
            track_records[track_record_count].msg = msg;
            track_records[track_record_count].wparam = wparam;
            track_records[track_record_count].lparam = lparam;
            track_record_count++;
        }
        break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void register_owner(void)
{
    WNDCLASSW wc;
    ATOM atom;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = owner_proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = OWNER_CLASS;
    arm();
    atom = RegisterClassW(&wc);
    line("RegisterClassW(F2KMenusOwner): atom nonzero %s err=%s", yesno(atom != 0), le());
}

static void unregister_owner(void)
{
    UnregisterClassW(OWNER_CLASS, GetModuleHandleW(NULL));
}

/* Dispatch what is queued, a bounded number of messages. */
static void drain_menus(void)
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

/* --- sysmenu ------------------------------------------------------- */

static HWND owner_window(DWORD ex_style, DWORD style, HWND parent, const char *what)
{
    HWND h;

    arm();
    h = CreateWindowExW(ex_style, OWNER_CLASS, L"menus", style, 40, 40, 320, 200, parent, NULL,
                        GetModuleHandleW(NULL), NULL);
    line("CreateWindowExW(F2KMenusOwner, %s): non-NULL %s err=%s", what, yesno(h != NULL), le());
    return h;
}

static HMENU system_menu(HWND h, BOOL revert, const char *what)
{
    HMENU m;

    arm();
    m = GetSystemMenu(h, revert);
    line("GetSystemMenu(%s): non-NULL %s err=%s", what, yesno(m != NULL), le());
    return m;
}

static void sec_sysmenu(void)
{
    HWND h, other, child;
    HMENU sys, again;
    BOOL r;

    register_owner();
    h = owner_window(0, WS_OVERLAPPEDWINDOW, NULL, "WS_OVERLAPPEDWINDOW, hidden");

    sys = system_menu(h, FALSE, "the window, FALSE");
    arm();
    r = IsMenu(sys);
    line("  IsMenu(it): ret=%d err=%s", r, le());
    dump_menu(sys, "system menu", 1);
    again = system_menu(h, FALSE, "the window, FALSE, again");
    line("  the same menu %s", yesno(again == sys));
    append_w(sys, MF_STRING, 0x0010, L"Custom", "the system menu, MF_STRING, 0x10 Custom");
    delete_item(sys, SC_SIZE, MF_BYCOMMAND, "the system menu, SC_SIZE, MF_BYCOMMAND");
    dump_menu(sys, "system menu", 1);

    system_menu(h, TRUE, "the window, TRUE");
    arm();
    r = IsMenu(sys);
    line("  IsMenu(the copy) after: ret=%d err=%s", r, le());
    again = system_menu(h, FALSE, "the window, FALSE, after the revert");
    line("  the copy reverted from %s", yesno(again == sys));
    dump_menu(again, "system menu", 1);
    system_menu(h, TRUE, "the window, TRUE, again");

    other = owner_window(0, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, NULL,
                         "WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, hidden");
    sys = system_menu(other, FALSE, "that window, FALSE");
    dump_menu(sys, "system menu", 1);
    DestroyWindow(other);

    other = owner_window(WS_EX_TOOLWINDOW, WS_POPUP | WS_CAPTION | WS_SYSMENU, NULL,
                         "WS_EX_TOOLWINDOW, WS_POPUP | WS_CAPTION | WS_SYSMENU, hidden");
    sys = system_menu(other, FALSE, "that window, FALSE");
    dump_menu(sys, "system menu", 1);
    DestroyWindow(other);

    other = owner_window(0, WS_POPUP, NULL, "WS_POPUP, hidden");
    sys = system_menu(other, FALSE, "that window (no WS_SYSMENU), FALSE");
    if (sys != NULL) {
        dump_menu(sys, "system menu", 1);
    }
    DestroyWindow(other);

    child = owner_window(0, WS_CHILD | WS_CAPTION | WS_SYSMENU, h, "WS_CHILD | WS_CAPTION | WS_SYSMENU");
    sys = system_menu(child, FALSE, "the child window, FALSE");
    if (sys != NULL) {
        dump_menu(sys, "system menu", 1);
    }
    DestroyWindow(child);

    sys = system_menu(h, FALSE, "the first window, FALSE");
    arm();
    r = DestroyWindow(h);
    line("DestroyWindow(the first window): ret=%d err=%s", r, le());
    arm();
    r = IsMenu(sys);
    line("  IsMenu(its system menu) after: ret=%d err=%s", r, le());
    system_menu(h, FALSE, "the destroyed window, FALSE");
    system_menu(NULL, FALSE, "NULL, FALSE");
    unregister_owner();
}

/* --- itemrect ------------------------------------------------------ */

static void item_rect(HWND h, HMENU m, UINT pos, RECT *rc, const char *what)
{
    BOOL r;

    SetRect(rc, -1, -1, -1, -1);
    arm();
    r = GetMenuItemRect(h, m, pos, rc);
    line("GetMenuItemRect(%s): ret=%d err=%s", what, r, le());
}

static void sec_itemrect(void)
{
    HWND h;
    HMENU bar, file, edit;
    RECT r[4], wr;
    POINT client;
    LONG dims;
    int i;
    int cx, cy;
    DWORD err;

    register_owner();

    arm();
    dims = GetMenuCheckMarkDimensions();
    err = GetLastError();
    cx = GetSystemMetrics(SM_CXMENUCHECK);
    cy = GetSystemMetrics(SM_CYMENUCHECK);
    line("GetMenuCheckMarkDimensions: nonzero %s err=%s width (low word) is SM_CXMENUCHECK %s height (high word) "
         "is SM_CYMENUCHECK %s",
         yesno(dims != 0), le_of(err), yesno(LOWORD(dims) == cx), yesno(HIWORD(dims) == cy));

    /* The bar: 0 &File (a popup), 1 &Edit (a popup), 2 &Help (220). */
    bar = CreateMenu();
    file = CreatePopupMenu();
    edit = CreatePopupMenu();
    AppendMenuW(file, MF_STRING, 701, L"&New");
    AppendMenuW(edit, MF_STRING, 702, L"&Copy");
    AppendMenuW(bar, MF_POPUP | MF_STRING, (UINT)file, L"&File");
    AppendMenuW(bar, MF_POPUP | MF_STRING, (UINT)edit, L"&Edit");
    AppendMenuW(bar, MF_STRING, ID_HELP, L"&Help");
    arm();
    h = CreateWindowExW(0, OWNER_CLASS, L"menus", WS_OVERLAPPEDWINDOW, 40, 40, 320, 200, NULL, bar,
                        GetModuleHandleW(NULL), NULL);
    line("CreateWindowExW(F2KMenusOwner, WS_OVERLAPPEDWINDOW, hidden, the bar): non-NULL %s err=%s",
         yesno(h != NULL), le());
    item_rect(h, bar, 0, &r[0], "the hidden window, the bar, 0");

    ShowWindow(h, SW_SHOWNORMAL);
    UpdateWindow(h);
    drain_menus();
    line("shown: visible %s", yesno(IsWindowVisible(h)));
    for (i = 0; i < 4; i++) {
        char what[48];

        sprintf(what, "the window, the bar, %d", i);
        item_rect(h, bar, i, &r[i], what);
    }
    GetWindowRect(h, &wr);
    client.x = 0;
    client.y = 0;
    ClientToScreen(h, &client);
    for (i = 0; i < 3; i++) {
        line("  item %d: width positive %s height - SM_CYMENU %d top the same as item 0's %s inside the window "
             "rectangle %s",
             i, yesno(r[i].right > r[i].left), (int)(r[i].bottom - r[i].top) - GetSystemMetrics(SM_CYMENU),
             yesno(r[i].top == r[0].top),
             yesno(r[i].left >= wr.left && r[i].right <= wr.right && r[i].top >= wr.top && r[i].bottom <= wr.bottom));
    }
    line("  item 1's left - item 0's right %d, item 2's left - item 1's right %d", (int)(r[1].left - r[0].right),
         (int)(r[2].left - r[1].right));
    line("  item 0's left - the client area's left %d, the client area's top - item 0's bottom %d",
         (int)(r[0].left - client.x), (int)(client.y - r[0].bottom));
    item_rect(NULL, bar, 0, &r[3], "NULL, the bar, 0");
    item_rect(h, file, 0, &r[3], "the window, &File's popup (not shown), 0");
    item_rect(NULL, file, 0, &r[3], "NULL, &File's popup (not shown), 0");
    item_rect(h, NULL, 0, &r[3], "the window, NULL, 0");

    DestroyWindow(h);
    drain_menus();
    unregister_owner();
}

/* --- track --------------------------------------------------------- */

/* TrackPopupMenu runs a modal loop until the menu ends, and nothing here
 * presses a key or clicks. A watcher thread ends it: half a second in,
 * it sends the owner WM_CANCELMODE (SendNotifyMessageW: the menu loop
 * takes sent messages as it waits for input, and DefWindowProc's
 * WM_CANCELMODE ends the menu); should the menu still run 2 s later, it
 * posts the owner an Escape key-down, which the loop reads as a key;
 * and should it run 2 s more, it prints a line and ends the process,
 * so the capture never hangs. The block prints which one the menu
 * ended after. */
static HWND track_owner;
static HANDLE track_done;
static volatile LONG track_stage;

static DWORD WINAPI track_watch(LPVOID unused)
{
    (void)unused;
    if (WaitForSingleObject(track_done, 500) == WAIT_OBJECT_0) {
        return 0;
    }
    track_stage = 1;
    SendNotifyMessageW(track_owner, WM_CANCELMODE, 0, 0);
    if (WaitForSingleObject(track_done, 2000) == WAIT_OBJECT_0) {
        return 0;
    }
    track_stage = 2;
    PostMessageW(track_owner, WM_KEYDOWN, VK_ESCAPE, 0x00010001);
    if (WaitForSingleObject(track_done, 2000) == WAIT_OBJECT_0) {
        return 0;
    }
    line("the menu did not end: the process ends");
    ExitProcess(3);
    return 0;
}

static const char *menu_label(HMENU m, HMENU popup)
{
    if (m == NULL) {
        return "NULL";
    }
    return m == popup ? "the popup" : "other";
}

static void print_track_records(HMENU popup)
{
    int i;
    const track_record_t *r;

    if (track_record_count == 0) {
        line("  the owner received no menu message");
    }
    for (i = 0; i < track_record_count; i++) {
        r = &track_records[i];
        switch (r->msg) {
        case WM_INITMENU:
            line("  WM_INITMENU menu %s", menu_label((HMENU)r->wparam, popup));
            break;
        case WM_INITMENUPOPUP:
            line("  WM_INITMENUPOPUP menu %s index=%d system menu=%d", menu_label((HMENU)r->wparam, popup),
                 (int)LOWORD(r->lparam), (int)HIWORD(r->lparam));
            break;
        case WM_UNINITMENUPOPUP:
            line("  WM_UNINITMENUPOPUP menu %s", menu_label((HMENU)r->wparam, popup));
            break;
        case WM_MENUSELECT:
            line("  WM_MENUSELECT item=%u flags=0x%X menu %s", (unsigned)LOWORD(r->wparam),
                 (unsigned)HIWORD(r->wparam), menu_label((HMENU)r->lparam, popup));
            break;
        case WM_ENTERMENULOOP:
            line("  WM_ENTERMENULOOP wParam=%ld", (long)r->wparam);
            break;
        case WM_EXITMENULOOP:
            line("  WM_EXITMENULOOP wParam=%ld", (long)r->wparam);
            break;
        case WM_CANCELMODE:
            line("  WM_CANCELMODE");
            break;
        case WM_COMMAND:
            line("  WM_COMMAND id=%u code=%u", (unsigned)LOWORD(r->wparam), (unsigned)HIWORD(r->wparam));
            break;
        }
    }
}

/* One tracking call: ex 0 is TrackPopupMenu, 1 TrackPopupMenuEx. */
static void track(HMENU popup, HWND owner, int ex, UINT flags, int x, int y, const char *what)
{
    static const char *const ended[] = { "by itself", "after WM_CANCELMODE", "after the Escape key-down" };
    HANDLE thread;
    DWORD tid;
    BOOL r;
    DWORD err;

    drain_menus();
    track_record_count = 0;
    track_stage = 0;
    ResetEvent(track_done);
    thread = CreateThread(NULL, 0, track_watch, NULL, 0, &tid);
    arm();
    if (ex) {
        r = TrackPopupMenuEx(popup, flags, x, y, owner, NULL);
    } else {
        r = TrackPopupMenu(popup, flags, x, y, 0, owner, NULL);
    }
    err = GetLastError();
    SetEvent(track_done);
    WaitForSingleObject(thread, WAIT_MS);
    CloseHandle(thread);
    line("%s(%s): ret=%d err=%s, ended %s", ex ? "TrackPopupMenuEx" : "TrackPopupMenu", what, r, le_of(err),
         ended[track_stage]);
    print_track_records(popup);
    drain_menus();
}

static void sec_track(void)
{
    HMENU popup;
    POINT cursor;
    int x, y;

    register_owner();
    track_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    arm();
    track_owner = CreateWindowExW(0, OWNER_CLASS, L"menus", WS_POPUP | WS_CAPTION | WS_VISIBLE, 40, 40, 200, 120,
                                  NULL, NULL, GetModuleHandleW(NULL), NULL);
    line("CreateWindowExW(F2KMenusOwner, WS_POPUP | WS_CAPTION | WS_VISIBLE): non-NULL %s err=%s",
         yesno(track_owner != NULL), le());
    SetForegroundWindow(track_owner);
    drain_menus();
    line("SetForegroundWindow(it): the foreground %s", yesno(GetForegroundWindow() == track_owner));

    /* The popup: 0 &Open (801), 1 a separator, 2 &Close (802). It opens
     * away from the mouse pointer, so no item lies under it. */
    popup = CreatePopupMenu();
    AppendMenuW(popup, MF_STRING, 801, L"&Open");
    AppendMenuW(popup, MF_SEPARATOR, 0, NULL);
    AppendMenuW(popup, MF_STRING, 802, L"&Close");
    GetCursorPos(&cursor);
    x = cursor.x < 300 ? cursor.x + 150 : cursor.x - 300;
    y = 40;

    track(popup, track_owner, 0, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, x, y,
          "the popup, TPM_RETURNCMD, the window");
    track(popup, track_owner, 0, TPM_LEFTALIGN | TPM_TOPALIGN, x, y, "the popup, no TPM_RETURNCMD, the window");
    track(popup, track_owner, 1, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD, x, y,
          "the popup, TPM_RETURNCMD, the window, no TPMPARAMS");
    track(NULL, track_owner, 0, TPM_RETURNCMD, x, y, "NULL, TPM_RETURNCMD, the window");
    track(popup, NULL, 0, TPM_RETURNCMD, x, y, "the popup, TPM_RETURNCMD, NULL");

    DestroyMenu(popup);
    DestroyWindow(track_owner);
    drain_menus();
    CloseHandle(track_done);
    unregister_owner();
}

/* --- cues -------------------------------------------------------------- */

#ifndef SPI_GETKEYBOARDCUES
#define SPI_GETKEYBOARDCUES 0x100A
#endif
#ifndef WM_CHANGEUISTATE
#define WM_CHANGEUISTATE 0x0127
#endif
#ifndef WM_QUERYUISTATE
#define WM_QUERYUISTATE 0x0129
#endif
#ifndef UIS_SET
#define UIS_SET 1
#endif
#ifndef UIS_CLEAR
#define UIS_CLEAR 2
#endif
#ifndef UIS_INITIALIZE
#define UIS_INITIALIZE 3
#endif
#ifndef UISF_HIDEFOCUS
#define UISF_HIDEFOCUS 0x1
#endif
#ifndef UISF_HIDEACCEL
#define UISF_HIDEACCEL 0x2
#endif

static void print_uistate(HWND top, HWND child, const char *when)
{
    line("%s: WM_QUERYUISTATE the window 0x%lX, its button 0x%lX", when,
         (unsigned long)SendMessageW(top, WM_QUERYUISTATE, 0, 0),
         (unsigned long)SendMessageW(child, WM_QUERYUISTATE, 0, 0));
}

static void change_uistate(HWND top, HWND child, WORD action, const char *what)
{
    SendMessageW(top, WM_CHANGEUISTATE, MAKEWPARAM(action, UISF_HIDEACCEL), 0);
    pump_queued();
    print_uistate(top, child, what);
}

static BOOL CALLBACK cues_dialog_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return FALSE;
}

static void sec_cues(void)
{
    WNDCLASSW wc;
    HINSTANCE inst;
    ATOM atom;
    HWND h;
    HWND b;
    HWND d;
    HMENU m;
    BOOL r;
    BOOL cues;
    DWORD dialog[16];
    DLGTEMPLATE *t;
    WORD *p;

    inst = GetModuleHandleW(NULL);
    pump_queued();
    cues = 7;
    arm();
    r = SystemParametersInfoW(SPI_GETKEYBOARDCUES, 0, &cues, 0);
    line("SystemParametersInfoW(SPI_GETKEYBOARDCUES): ret=%d err=%s value=%d", r, le(), cues);

    UnregisterClassW(L"F2KMenusCues", inst);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = plain;
    wc.hInstance = inst;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"F2KMenusCues";
    atom = RegisterClassW(&wc);
    m = load_menu();
    h = CreateWindowExW(0, L"F2KMenusCues", L"menus", WS_OVERLAPPEDWINDOW, 60, 70, 320, 200, NULL, m, inst,
                        NULL);
    b = h != NULL ? CreateWindowExW(0, L"Button", L"&Button", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 10, 10, 100,
                                    24, h, (HMENU)1, inst, NULL)
                  : NULL;
    line("setup: the class, menu 200, a hidden WS_OVERLAPPEDWINDOW window with it and a child button: %s",
         yesno(atom != 0 && m != NULL && h != NULL && b != NULL));
    if (h != NULL && b != NULL) {
        print_uistate(h, b, "hidden");
        ShowWindow(h, SW_SHOWNOACTIVATE);
        UpdateWindow(h);
        pump_queued();
        print_uistate(h, b, "shown");
        change_uistate(h, b, UIS_CLEAR, "WM_CHANGEUISTATE(UIS_CLEAR, UISF_HIDEACCEL)");
        change_uistate(h, b, UIS_SET, "WM_CHANGEUISTATE(UIS_SET, UISF_HIDEACCEL)");
        change_uistate(h, b, UIS_INITIALIZE, "WM_CHANGEUISTATE(UIS_INITIALIZE, UISF_HIDEACCEL)");
    }
    if (h != NULL) {
        DestroyWindow(h);
    }
    pump_queued();
    UnregisterClassW(L"F2KMenusCues", inst);

    /* A dialog of no controls: WS_POPUP | WS_CAPTION | WS_SYSMENU, no
     * menu, the default class, the title "cues". */
    ZeroMemory(dialog, sizeof dialog);
    t = (DLGTEMPLATE *)dialog;
    t->style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    t->cdit = 0;
    t->x = 10;
    t->y = 10;
    t->cx = 100;
    t->cy = 50;
    p = (WORD *)(t + 1);
    *p++ = 0;
    *p++ = 0;
    *p++ = 'c';
    *p++ = 'u';
    *p++ = 'e';
    *p++ = 's';
    *p++ = 0;
    arm();
    d = CreateDialogIndirectParamW(inst, t, NULL, cues_dialog_proc, 0);
    line("CreateDialogIndirectParamW(a hidden dialog of no controls): non-NULL %s err=%s", yesno(d != NULL), le());
    if (d != NULL) {
        line("  WM_QUERYUISTATE 0x%lX", (unsigned long)SendMessageW(d, WM_QUERYUISTATE, 0, 0));
        DestroyWindow(d);
    }
    pump_queued();
}

static const section_t sections[] = {
    { "load", sec_load, F2KT_ALWAYS },
    { "items", sec_items, F2KT_ALWAYS },
    { "check", sec_check, F2KT_ALWAYS },
    { "enable", sec_enable, F2KT_ALWAYS },
    { "window", sec_window, F2KT_ALWAYS },
    { "kinds", sec_kinds, F2KT_ALWAYS },
    { "reuse", sec_reuse, F2KT_ALWAYS },
    { "slots", sec_slots, F2KT_ALWAYS },
    { "bar", sec_bar, F2KT_ALWAYS },
    { "keyloop", sec_keyloop, F2KT_ALWAYS },
    { "keyesc", sec_keyesc, F2KT_ALWAYS },
    { "keychar", sec_keychar, F2KT_ALWAYS },
    { "edit", sec_edit, F2KT_ALWAYS },
    { "info", sec_info, F2KT_ALWAYS },
    { "insitem", sec_insitem, F2KT_ALWAYS },
    { "default", sec_default, F2KT_ALWAYS },
    { "sysmenu", sec_sysmenu, F2KT_ALWAYS },
    { "itemrect", sec_itemrect, F2KT_ALWAYS },
    { "track", sec_track, F2KT_ALWAYS },
    { "cues", sec_cues, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("menus", sections, argc, argv);
}
