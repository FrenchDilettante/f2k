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
 * handles' low words (the slot) and high words as relations.
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

static const section_t sections[] = {
    { "load", sec_load, F2KT_ALWAYS },
    { "items", sec_items, F2KT_ALWAYS },
    { "check", sec_check, F2KT_ALWAYS },
    { "enable", sec_enable, F2KT_ALWAYS },
    { "window", sec_window, F2KT_ALWAYS },
    { "kinds", sec_kinds, F2KT_ALWAYS },
    { "reuse", sec_reuse, F2KT_ALWAYS },
    { "slots", sec_slots, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("menus", sections, argc, argv);
}
