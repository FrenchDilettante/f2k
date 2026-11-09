/*
 * menus - menus loaded from the program's own MENU resource (menus.rc,
 * compiled by rc and linked in), as user32 and win32k serve them:
 * LoadMenuW/LoadMenuA, IsMenu, DestroyMenu, GetMenuItemCount,
 * GetMenuItemID, GetSubMenu, GetMenuState, GetMenuStringA/W,
 * CheckMenuItem, CheckMenuRadioItem, EnableMenuItem, and a window's
 * menu through GetMenu and SetMenu.
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
 * there shows. Each section loads its own copy of menu 200 and destroys
 * it at its end; the window section's windows are hidden, of a class
 * it registers itself.
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

static const section_t sections[] = {
    { "load", sec_load, F2KT_ALWAYS },
    { "items", sec_items, F2KT_ALWAYS },
    { "check", sec_check, F2KT_ALWAYS },
    { "enable", sec_enable, F2KT_ALWAYS },
    { "window", sec_window, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("menus", sections, argc, argv);
}
