/*
 * accel - keyboard accelerators from the program's own ACCELERATORS
 * resource (accel.rc, compiled by rc and linked in), as user32 and
 * win32k serve them: LoadAcceleratorsW/A, CreateAcceleratorTableW/A,
 * CopyAcceleratorTableW/A, DestroyAcceleratorTable, and
 * TranslateAcceleratorW/A on keyboard messages the program posts to its
 * own window.
 *
 * Table 300 (accel.rc): 301 the character "A" (ASCII), 302 "^C" (the
 * character 3), 303 F5, 304 Ctrl+Z, 305 Alt+X, 306 Shift+Delete, 307 K
 * (NOINVERT), the last five virtual keys. Menu 310: one popup, &Edit,
 * holding &Refresh (303) and &Undo (304, grayed). 399 names no
 * resource.
 *
 * Each case posts one message (PostMessageW, or PostMessageA in the
 * ansi section) to the section's hidden window, takes it back with
 * PeekMessage (PM_REMOVE, filtered on the window and the message, so
 * nothing waits), and hands it to TranslateAccelerator. Its lParam is
 * a keyboard's: a repeat count of 1 and the key's scan code, the
 * extended-key bit for Delete, the context bit (29) for the
 * WM_SYSKEYDOWN cases, the previous-state and transition bits for a
 * WM_KEYUP. Posted messages do not change the thread's key state, so
 * the modifiers a case needs are set with SetKeyboardState (the state
 * GetKeyboardState read at the section's start, Ctrl, Shift and Alt
 * cleared or set), printed once through GetKeyState, and the saved
 * state is restored at the section's end. After each call, anything
 * queued for the window is dispatched, and the window procedure's
 * record of the messages it received (WM_COMMAND, WM_SYSCOMMAND,
 * WM_INITMENU and WM_INITMENUPOPUP; the procedure answers 0 to each
 * without DefWindowProc) prints, in order; the rest go to
 * DefWindowProc.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare
 * (yesno()); every call under observation is armed with the last-error
 * sentinel and its line prints ret= and err=. Each section registers
 * its own window class and creates its own hidden window, destroyed at
 * its end, and starts by draining its thread's queue.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   load       LoadAcceleratorsW of 300, twice, LoadAcceleratorsA of
 *              300 and LoadAcceleratorsW of "#300" (the same table or
 *              not), 399 through both; CopyAcceleratorTableW's count
 *              with no buffer, its entries (fVirt, key, cmd), a buffer
 *              of 3 (the entries past it untouched or not),
 *              CopyAcceleratorTableA's entries against the W form's,
 *              and a NULL table; DestroyAcceleratorTable of each table
 *              loaded, CopyAcceleratorTableW and DestroyAcceleratorTable
 *              once more on the first
 *   translate  TranslateAcceleratorW with no modifier down: WM_KEYDOWN
 *              F5, Z, K, A and Delete, a WM_KEYUP of F5, WM_CHAR "A",
 *              "a" and 3, WM_SYSKEYDOWN X; with Ctrl down: WM_KEYDOWN Z
 *              and F5, WM_CHAR 3; with Shift down: WM_KEYDOWN Delete,
 *              WM_CHAR "A"; with Alt down: WM_SYSKEYDOWN X and F5,
 *              WM_KEYDOWN X with no context bit; a NULL table, and a
 *              NULL window
 *   ansi       TranslateAcceleratorA over LoadAcceleratorsA's table on
 *              messages posted with PostMessageA to a window of a class
 *              registered with RegisterClassA: WM_KEYDOWN F5 and K,
 *              WM_CHAR "A", Ctrl+Z, Alt+X, and a WM_KEYDOWN Z with no
 *              modifier
 *   menu       TranslateAcceleratorW on a window holding menu 310: F5
 *              (an enabled item's command), Ctrl+Z (a grayed item's),
 *              K (no item's), Ctrl+Z again once EnableMenuItem has
 *              enabled its item, and F5 while EnableWindow has disabled
 *              the window
 *   create     CreateAcceleratorTableW and A with no entries (count 0,
 *              and -1 for the W form), CreateAcceleratorTableW of NULL
 *              (inside __try); one entry, its count and entries through
 *              CopyAcceleratorTableW, a second table of it (the same
 *              one or not), DestroyAcceleratorTable of each, the first
 *              again, and a copy after; entries whose fVirt carries
 *              0x80, 0x40 and every bit, copied back; the A form's
 *              character keys (0x80, Ctrl+'a', the virtual key 0x80, a
 *              key above 0xFF): the caller's array after the call, the
 *              entries through CopyAcceleratorTableW and A; 1000
 *              entries copied back whole; and TranslateAcceleratorW of
 *              F6 and F7 on a table whose first entry (F6) carries 0x80,
 *              the flag that ends a resource's table
 *   alias      TranslateAccelerator, the unsuffixed export (reached
 *              through GetProcAddress: the SDK's headers map the name to
 *              the A or W form), whether it is the same entry as
 *              TranslateAcceleratorA, and the ansi section's cases
 *              through it
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat accel):
 *   rc accel.rc
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% accel.c accel.res user32.lib
 */

#include "../common/f2kt.h"

/* accel.rc's ids. */
#define TABLE_ID 300
#define MENU_ID 310
#define MISSING_ID 399
#define ID_UNDO 304

/* The keys' scan codes (set 1, as a US keyboard makes them). */
#define SCAN_A 0x1E
#define SCAN_C 0x2E
#define SCAN_K 0x25
#define SCAN_X 0x2D
#define SCAN_Z 0x2C
#define SCAN_F5 0x3F
#define SCAN_DELETE 0x53

/* A key-down message's lParam: a repeat count of 1 and the scan code. */
#define KEY_LPARAM(scan) ((LPARAM)(1 | ((DWORD)(scan) << 16)))
#define EXTENDED_BIT ((LPARAM)0x01000000)
#define CONTEXT_BIT ((LPARAM)0x20000000)
#define UP_BITS ((LPARAM)0xC0000000)

/* What the window procedure received, printed after each call. */
typedef struct {
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
} received_t;

#define MAX_RECEIVED 16

static received_t received[MAX_RECEIVED];
static int received_count;

/* The menu the menu section's window holds, and its popup. */
static HMENU window_menu;
static HMENU window_popup;

/* The thread's key state at the section's start. */
static BYTE saved_keys[256];

/* The alias section's TranslateAccelerator, which the ANSI cases call in
 * place of TranslateAcceleratorA while it is set. */
typedef int (WINAPI *translate_t)(HWND, HACCEL, LPMSG);
static translate_t alias_translate;

static void record(UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (received_count < MAX_RECEIVED) {
        received[received_count].msg = msg;
        received[received_count].wparam = wparam;
        received[received_count].lparam = lparam;
    }
    received_count++;
}

static int recorded(UINT msg)
{
    return msg == WM_COMMAND || msg == WM_SYSCOMMAND || msg == WM_INITMENU || msg == WM_INITMENUPOPUP;
}

static LRESULT CALLBACK recorder_w(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (recorded(msg)) {
        record(msg, wparam, lparam);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static LRESULT CALLBACK recorder_a(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (recorded(msg)) {
        record(msg, wparam, lparam);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

static void print_received(void)
{
    int i;
    received_t *r;

    if (received_count == 0) {
        line("  received: nothing");
        return;
    }
    if (received_count > MAX_RECEIVED) {
        line("  received: %d messages, the first %d recorded", received_count, MAX_RECEIVED);
    }
    for (i = 0; i < received_count && i < MAX_RECEIVED; i++) {
        r = &received[i];
        switch (r->msg) {
        case WM_COMMAND:
            line("  received WM_COMMAND: HIWORD(wParam)=%u LOWORD(wParam)=%u lParam=%ld",
                 (unsigned)HIWORD(r->wparam), (unsigned)LOWORD(r->wparam), (long)r->lparam);
            break;
        case WM_SYSCOMMAND:
            line("  received WM_SYSCOMMAND: wParam=0x%lX lParam=%ld", (unsigned long)r->wparam,
                 (long)r->lparam);
            break;
        case WM_INITMENU:
            line("  received WM_INITMENU: wParam == the window's menu %s lParam=%ld",
                 yesno(window_menu != NULL && (HMENU)r->wparam == window_menu), (long)r->lparam);
            break;
        case WM_INITMENUPOPUP:
            line("  received WM_INITMENUPOPUP: wParam == the Edit popup %s LOWORD(lParam)=%u HIWORD(lParam)=%u",
                 yesno(window_popup != NULL && (HMENU)r->wparam == window_popup),
                 (unsigned)LOWORD(r->lparam), (unsigned)HIWORD(r->lparam));
            break;
        }
    }
}

/* Empty the queue, so one case's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* Dispatch whatever is queued for the window after a call. */
static void pump(HWND h, int ansi)
{
    MSG m;
    int n;

    for (n = 0; n < 32; n++) {
        if (ansi ? !PeekMessageA(&m, h, 0, 0, PM_REMOVE) : !PeekMessageW(&m, h, 0, 0, PM_REMOVE)) {
            break;
        }
        if (ansi) {
            DispatchMessageA(&m);
        } else {
            DispatchMessageW(&m);
        }
    }
}

/* Ctrl, Shift and Alt as the next cases see them (the saved state with
 * those three set or cleared), printed through GetKeyState. */
static void set_modifiers(int ctrl, int shift, int alt)
{
    BYTE k[256];

    memcpy(k, saved_keys, sizeof k);
    k[VK_CONTROL] = k[VK_LCONTROL] = (BYTE)(ctrl ? 0x80 : 0);
    k[VK_RCONTROL] = 0;
    k[VK_SHIFT] = k[VK_LSHIFT] = (BYTE)(shift ? 0x80 : 0);
    k[VK_RSHIFT] = 0;
    k[VK_MENU] = k[VK_LMENU] = (BYTE)(alt ? 0x80 : 0);
    k[VK_RMENU] = 0;
    SetKeyboardState(k);
    line("keys: Ctrl down %s, Shift down %s, Alt down %s", yesno(GetKeyState(VK_CONTROL) < 0),
         yesno(GetKeyState(VK_SHIFT) < 0), yesno(GetKeyState(VK_MENU) < 0));
}

static void save_keys(void)
{
    GetKeyboardState(saved_keys);
}

static void restore_keys(void)
{
    SetKeyboardState(saved_keys);
}

/* One case: post the message to h, take it back, translate it for
 * target through the table, and print the call and what the window
 * received. */
static void try_case(HWND h, HWND target, HACCEL table, int ansi, UINT msg, WPARAM wparam, LPARAM lparam,
                     const char *what)
{
    MSG m;
    BOOL got;
    int r;

    drain();
    if (ansi) {
        PostMessageA(h, msg, wparam, lparam);
        got = PeekMessageA(&m, h, msg, msg, PM_REMOVE);
    } else {
        PostMessageW(h, msg, wparam, lparam);
        got = PeekMessageW(&m, h, msg, msg, PM_REMOVE);
    }
    if (!got) {
        line("%s: the posted message did not come back", what);
        return;
    }
    received_count = 0;
    arm();
    if (ansi && alias_translate != NULL) {
        r = alias_translate(target, table, &m);
        line("TranslateAccelerator(%s): ret=%d err=%s", what, r, le());
    } else if (ansi) {
        r = TranslateAcceleratorA(target, table, &m);
        line("TranslateAcceleratorA(%s): ret=%d err=%s", what, r, le());
    } else {
        r = TranslateAcceleratorW(target, table, &m);
        line("TranslateAcceleratorW(%s): ret=%d err=%s", what, r, le());
    }
    pump(h, ansi);
    print_received();
}

/* The section's hidden window, of a class it registers (W or A). */
static HWND open_window(const char *class_name, int ansi)
{
    WNDCLASSW wcw;
    WNDCLASSA wca;
    WCHAR wname[64];
    ATOM a;
    HWND h;

    if (ansi) {
        ZeroMemory(&wca, sizeof wca);
        wca.lpfnWndProc = recorder_a;
        wca.hInstance = GetModuleHandleA(NULL);
        wca.lpszClassName = class_name;
        arm();
        a = RegisterClassA(&wca);
        line("RegisterClassA(%s): atom nonzero %s err=%s", class_name, yesno(a != 0), le());
        arm();
        h = CreateWindowExA(0, class_name, "accel", WS_OVERLAPPEDWINDOW, 0, 0, 320, 200, NULL, NULL,
                            GetModuleHandleA(NULL), NULL);
        line("CreateWindowExA(%s, WS_OVERLAPPEDWINDOW, hidden, 320x200): non-NULL %s err=%s", class_name,
             yesno(h != NULL), le());
        return h;
    }
    MultiByteToWideChar(CP_ACP, 0, class_name, -1, wname, 64);
    ZeroMemory(&wcw, sizeof wcw);
    wcw.lpfnWndProc = recorder_w;
    wcw.hInstance = GetModuleHandleW(NULL);
    wcw.lpszClassName = wname;
    arm();
    a = RegisterClassW(&wcw);
    line("RegisterClassW(%s): atom nonzero %s err=%s", class_name, yesno(a != 0), le());
    arm();
    h = CreateWindowExW(0, wname, L"accel", WS_OVERLAPPEDWINDOW, 0, 0, 320, 200, NULL, NULL,
                        GetModuleHandleW(NULL), NULL);
    line("CreateWindowExW(%s, WS_OVERLAPPEDWINDOW, hidden, 320x200): non-NULL %s err=%s", class_name,
         yesno(h != NULL), le());
    return h;
}

static HACCEL load_table(void)
{
    HACCEL t;

    arm();
    t = LoadAcceleratorsW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(TABLE_ID));
    line("LoadAcceleratorsW(300): non-NULL %s err=%s", yesno(t != NULL), le());
    return t;
}

/* --- load ---------------------------------------------------------- */

static void print_entries(const ACCEL *e, int n)
{
    int i;

    for (i = 0; i < n && i < 16; i++) {
        line("  entry %d: fVirt=0x%02X key=%u cmd=%u", i, (unsigned)e[i].fVirt, (unsigned)e[i].key,
             (unsigned)e[i].cmd);
    }
}

static void destroy_table(HACCEL t, const char *what)
{
    BOOL r;

    arm();
    r = DestroyAcceleratorTable(t);
    line("DestroyAcceleratorTable(%s): ret=%d err=%s", what, r, le());
}

static void sec_load(void)
{
    HINSTANCE inst;
    HACCEL w, w2, a, named, missing;
    ACCEL tw[16];
    ACCEL ta[16];
    int n, i, same;

    drain();
    inst = GetModuleHandleW(NULL);

    arm();
    w = LoadAcceleratorsW(inst, MAKEINTRESOURCEW(TABLE_ID));
    line("LoadAcceleratorsW(300): non-NULL %s err=%s", yesno(w != NULL), le());
    arm();
    w2 = LoadAcceleratorsW(inst, MAKEINTRESOURCEW(TABLE_ID));
    line("LoadAcceleratorsW(300) again: non-NULL %s err=%s the same table %s", yesno(w2 != NULL), le(),
         yesno(w2 == w));
    arm();
    a = LoadAcceleratorsA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(TABLE_ID));
    line("LoadAcceleratorsA(300): non-NULL %s err=%s the same table as LoadAcceleratorsW's %s",
         yesno(a != NULL), le(), yesno(a == w));
    arm();
    named = LoadAcceleratorsW(inst, L"#300");
    line("LoadAcceleratorsW(\"#300\"): non-NULL %s err=%s the same table as LoadAcceleratorsW's %s",
         yesno(named != NULL), le(), yesno(named == w));
    arm();
    missing = LoadAcceleratorsW(inst, MAKEINTRESOURCEW(MISSING_ID));
    line("LoadAcceleratorsW(399): non-NULL %s err=%s", yesno(missing != NULL), le());
    arm();
    missing = LoadAcceleratorsA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(MISSING_ID));
    line("LoadAcceleratorsA(399): non-NULL %s err=%s", yesno(missing != NULL), le());

    arm();
    n = CopyAcceleratorTableW(w, NULL, 0);
    line("CopyAcceleratorTableW(table, NULL, 0): ret=%d err=%s", n, le());
    memset(tw, 0xEE, sizeof tw);
    arm();
    n = CopyAcceleratorTableW(w, tw, 16);
    line("CopyAcceleratorTableW(table, buffer, 16): ret=%d err=%s", n, le());
    print_entries(tw, n);

    memset(ta, 0xEE, sizeof ta);
    arm();
    n = CopyAcceleratorTableA(w, ta, 16);
    line("CopyAcceleratorTableA(table, buffer, 16): ret=%d err=%s", n, le());
    print_entries(ta, n);
    same = 1;
    for (i = 0; i < n && i < 16; i++) {
        if (ta[i].fVirt != tw[i].fVirt || ta[i].key != tw[i].key || ta[i].cmd != tw[i].cmd) {
            same = 0;
        }
    }
    line("  CopyAcceleratorTableA's entries the same as CopyAcceleratorTableW's: %s", yesno(same));

    memset(ta, 0xEE, sizeof ta);
    arm();
    n = CopyAcceleratorTableW(w, ta, 3);
    line("CopyAcceleratorTableW(table, buffer, 3): ret=%d err=%s", n, le());
    print_entries(ta, n < 3 ? n : 3);
    line("  the entry past the third untouched: %s", yesno(ta[3].fVirt == 0xEE && ta[3].key == 0xEEEE &&
                                                           ta[3].cmd == 0xEEEE));

    arm();
    n = CopyAcceleratorTableW(NULL, NULL, 0);
    line("CopyAcceleratorTableW(NULL, NULL, 0): ret=%d err=%s", n, le());

    destroy_table(w, "LoadAcceleratorsW's");
    arm();
    n = CopyAcceleratorTableW(w, NULL, 0);
    line("CopyAcceleratorTableW(it, NULL, 0) after: ret=%d err=%s", n, le());
    destroy_table(w, "it, again");
    if (w2 != NULL && w2 != w) {
        destroy_table(w2, "the second LoadAcceleratorsW's");
    }
    if (a != NULL && a != w && a != w2) {
        destroy_table(a, "LoadAcceleratorsA's");
    }
    if (named != NULL && named != w && named != w2 && named != a) {
        destroy_table(named, "\"#300\"'s");
    }
}

/* --- translate ----------------------------------------------------- */

static void sec_translate(void)
{
    HWND h;
    HACCEL t;

    drain();
    save_keys();
    window_menu = NULL;
    window_popup = NULL;
    h = open_window("F2KAccelTranslate", 0);
    t = load_table();

    set_modifiers(0, 0, 0);
    try_case(h, h, t, 0, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5");
    try_case(h, h, t, 0, WM_KEYUP, VK_F5, KEY_LPARAM(SCAN_F5) | UP_BITS, "WM_KEYUP F5");
    try_case(h, h, t, 0, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z");
    try_case(h, h, t, 0, WM_KEYDOWN, 'K', KEY_LPARAM(SCAN_K), "WM_KEYDOWN K");
    try_case(h, h, t, 0, WM_KEYDOWN, 'A', KEY_LPARAM(SCAN_A), "WM_KEYDOWN A");
    try_case(h, h, t, 0, WM_KEYDOWN, VK_DELETE, KEY_LPARAM(SCAN_DELETE) | EXTENDED_BIT, "WM_KEYDOWN Delete");
    try_case(h, h, t, 0, WM_CHAR, 'A', KEY_LPARAM(SCAN_A), "WM_CHAR 'A'");
    try_case(h, h, t, 0, WM_CHAR, 'a', KEY_LPARAM(SCAN_A), "WM_CHAR 'a'");
    try_case(h, h, t, 0, WM_CHAR, 3, KEY_LPARAM(SCAN_C), "WM_CHAR 3");
    try_case(h, h, t, 0, WM_SYSKEYDOWN, 'X', KEY_LPARAM(SCAN_X) | CONTEXT_BIT,
             "WM_SYSKEYDOWN X, context bit, Alt up");

    set_modifiers(1, 0, 0);
    try_case(h, h, t, 0, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z, Ctrl down");
    try_case(h, h, t, 0, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5, Ctrl down");
    try_case(h, h, t, 0, WM_CHAR, 3, KEY_LPARAM(SCAN_C), "WM_CHAR 3, Ctrl down");

    set_modifiers(0, 1, 0);
    try_case(h, h, t, 0, WM_KEYDOWN, VK_DELETE, KEY_LPARAM(SCAN_DELETE) | EXTENDED_BIT,
             "WM_KEYDOWN Delete, Shift down");
    try_case(h, h, t, 0, WM_CHAR, 'A', KEY_LPARAM(SCAN_A), "WM_CHAR 'A', Shift down");

    set_modifiers(0, 0, 1);
    try_case(h, h, t, 0, WM_SYSKEYDOWN, 'X', KEY_LPARAM(SCAN_X) | CONTEXT_BIT,
             "WM_SYSKEYDOWN X, context bit, Alt down");
    try_case(h, h, t, 0, WM_SYSKEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5) | CONTEXT_BIT,
             "WM_SYSKEYDOWN F5, context bit, Alt down");
    try_case(h, h, t, 0, WM_KEYDOWN, 'X', KEY_LPARAM(SCAN_X), "WM_KEYDOWN X, no context bit, Alt down");

    set_modifiers(0, 0, 0);
    try_case(h, h, NULL, 0, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5, a NULL table");
    try_case(h, NULL, t, 0, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5, a NULL window");

    restore_keys();
    DestroyAcceleratorTable(t);
    DestroyWindow(h);
}

/* --- ansi ---------------------------------------------------------- */

static void sec_ansi(void)
{
    HWND h;
    HACCEL t;

    drain();
    save_keys();
    window_menu = NULL;
    window_popup = NULL;
    h = open_window("F2KAccelAnsi", 1);
    arm();
    t = LoadAcceleratorsA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(TABLE_ID));
    line("LoadAcceleratorsA(300): non-NULL %s err=%s", yesno(t != NULL), le());

    set_modifiers(0, 0, 0);
    try_case(h, h, t, 1, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5");
    try_case(h, h, t, 1, WM_KEYDOWN, 'K', KEY_LPARAM(SCAN_K), "WM_KEYDOWN K");
    try_case(h, h, t, 1, WM_CHAR, 'A', KEY_LPARAM(SCAN_A), "WM_CHAR 'A'");
    try_case(h, h, t, 1, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z");

    set_modifiers(1, 0, 0);
    try_case(h, h, t, 1, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z, Ctrl down");

    set_modifiers(0, 0, 1);
    try_case(h, h, t, 1, WM_SYSKEYDOWN, 'X', KEY_LPARAM(SCAN_X) | CONTEXT_BIT,
             "WM_SYSKEYDOWN X, context bit, Alt down");

    restore_keys();
    DestroyAcceleratorTable(t);
    DestroyWindow(h);
}

/* --- alias --------------------------------------------------------- */

static void sec_alias(void)
{
    HMODULE user32;
    HWND h;
    HACCEL t;

    drain();
    user32 = GetModuleHandleA("user32.dll");
    alias_translate = (translate_t)GetProcAddress(user32, "TranslateAccelerator");
    if (alias_translate == NULL) {
        line("TranslateAccelerator: absent");
        return;
    }
    line("TranslateAccelerator: the same entry as TranslateAcceleratorA %s",
         yesno((FARPROC)alias_translate == GetProcAddress(user32, "TranslateAcceleratorA")));
    save_keys();
    window_menu = NULL;
    window_popup = NULL;
    h = open_window("F2KAccelAlias", 1);
    arm();
    t = LoadAcceleratorsA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(TABLE_ID));
    line("LoadAcceleratorsA(300): non-NULL %s err=%s", yesno(t != NULL), le());

    set_modifiers(0, 0, 0);
    try_case(h, h, t, 1, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5");
    try_case(h, h, t, 1, WM_CHAR, 'A', KEY_LPARAM(SCAN_A), "WM_CHAR 'A'");
    try_case(h, h, t, 1, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z");

    set_modifiers(1, 0, 0);
    try_case(h, h, t, 1, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z, Ctrl down");

    restore_keys();
    alias_translate = NULL;
    DestroyAcceleratorTable(t);
    DestroyWindow(h);
}

/* --- menu ---------------------------------------------------------- */

static void sec_menu(void)
{
    HWND h;
    HACCEL t;
    BOOL r;

    drain();
    save_keys();
    window_menu = NULL;
    window_popup = NULL;
    h = open_window("F2KAccelMenu", 0);
    t = load_table();

    window_menu = LoadMenuW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(MENU_ID));
    window_popup = GetSubMenu(window_menu, 0);
    arm();
    r = SetMenu(h, window_menu);
    line("SetMenu(window, menu 310): ret=%d err=%s", r, le());

    set_modifiers(0, 0, 0);
    try_case(h, h, t, 0, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5, Refresh's command");
    try_case(h, h, t, 0, WM_KEYDOWN, 'K', KEY_LPARAM(SCAN_K), "WM_KEYDOWN K, no item's command");

    set_modifiers(1, 0, 0);
    try_case(h, h, t, 0, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z, Ctrl down, Undo's command (grayed)");
    arm();
    r = EnableMenuItem(window_menu, ID_UNDO, MF_BYCOMMAND | MF_ENABLED);
    line("EnableMenuItem(menu, 304 Undo, MF_ENABLED): ret=%ld err=%s", (long)r, le());
    try_case(h, h, t, 0, WM_KEYDOWN, 'Z', KEY_LPARAM(SCAN_Z), "WM_KEYDOWN Z, Ctrl down, Undo's command (enabled)");

    set_modifiers(0, 0, 0);
    arm();
    r = EnableWindow(h, FALSE);
    line("EnableWindow(window, FALSE): ret=%d err=%s", r, le());
    try_case(h, h, t, 0, WM_KEYDOWN, VK_F5, KEY_LPARAM(SCAN_F5), "WM_KEYDOWN F5, the window disabled");
    EnableWindow(h, TRUE);

    restore_keys();
    DestroyAcceleratorTable(t);
    DestroyWindow(h);
    window_menu = NULL;
    window_popup = NULL;
}

/* --- create -------------------------------------------------------- */

#define MANY 1000

static ACCEL many[MANY];
static ACCEL many_back[MANY];

static void set_entry(ACCEL *e, BYTE virt, WORD key, WORD cmd)
{
    e->fVirt = virt;
    e->key = key;
    e->cmd = cmd;
}

/* CreateAcceleratorTableW (ansi 0) or A of `n` entries, printed. */
static HACCEL create(ACCEL *e, int n, int ansi, const char *what)
{
    HACCEL t;

    arm();
    t = ansi ? CreateAcceleratorTableA(e, n) : CreateAcceleratorTableW(e, n);
    line("CreateAcceleratorTable%s(%s): non-NULL %s err=%s", ansi ? "A" : "W", what, yesno(t != NULL),
         le());
    return t;
}

/* A table's entries copied back through the W or A form, printed. */
static void copy_back(HACCEL t, int ansi, const char *what)
{
    ACCEL e[16];
    int n;

    memset(e, 0xEE, sizeof e);
    arm();
    n = ansi ? CopyAcceleratorTableA(t, e, 16) : CopyAcceleratorTableW(t, e, 16);
    line("CopyAcceleratorTable%s(%s, buffer, 16): ret=%d err=%s", ansi ? "A" : "W", what, n, le());
    print_entries(e, n);
}

static void sec_create(void)
{
    ACCEL one[1];
    ACCEL three[3];
    ACCEL ansi[4];
    ACCEL marked[2];
    HACCEL t, t2, tm;
    HWND h;
    int n, i, same;
    int faulted;

    drain();
    set_entry(&one[0], FVIRTKEY | FCONTROL, 'S', 401);

    /* No entries, and a negative count (the W form only: Windows 2000's
     * A form walks the count's entries before it checks it). */
    create(one, 0, 0, "1 entry, count 0");
    create(one, 0, 1, "1 entry, count 0");
    create(one, -1, 0, "1 entry, count -1");
    faulted = 0;
    t = NULL;
    __try {
        arm();
        t = CreateAcceleratorTableW(NULL, 1);
        line("CreateAcceleratorTableW(NULL, count 1): non-NULL %s err=%s", yesno(t != NULL), le());
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    if (faulted) {
        line("CreateAcceleratorTableW(NULL, count 1): faulted");
    }

    /* One entry, copied back, two tables of it, destroyed. */
    t = create(one, 1, 0, "Ctrl+S, 401");
    arm();
    n = CopyAcceleratorTableW(t, NULL, 0);
    line("CopyAcceleratorTableW(it, NULL, 0): ret=%d err=%s", n, le());
    copy_back(t, 0, "it");
    t2 = create(one, 1, 0, "the same entry again");
    line("  the same table as the first: %s", yesno(t2 == t));
    destroy_table(t2, "the second");
    destroy_table(t, "the first");
    destroy_table(t, "the first, again");
    arm();
    n = CopyAcceleratorTableW(t, NULL, 0);
    line("CopyAcceleratorTableW(the first, NULL, 0) after: ret=%d err=%s", n, le());

    /* fVirt's other bits: 0x80 (the resource's last-entry flag) and 0x40. */
    set_entry(&three[0], 0x80 | FVIRTKEY, VK_F6, 402);
    set_entry(&three[1], 0x40 | FVIRTKEY, VK_F7, 403);
    set_entry(&three[2], 0xFF, VK_F8, 404);
    t = create(three, 3, 0, "fVirt 0x81, 0x41, 0xFF");
    copy_back(t, 0, "it");
    destroy_table(t, "it");

    /* The A form's character keys: from the ANSI code page (1252 on the
     * real machine), a virtual key left alone, a key above 0xFF. */
    set_entry(&ansi[0], 0, 0x80, 410);
    set_entry(&ansi[1], FCONTROL, 'a', 411);
    set_entry(&ansi[2], FVIRTKEY, 0x80, 412);
    set_entry(&ansi[3], 0, 0x1241, 413);
    t = create(ansi, 4, 1, "0x80, Ctrl+'a', the virtual key 0x80, 0x1241");
    line("  the caller's keys after: %u %u %u %u", (unsigned)ansi[0].key, (unsigned)ansi[1].key,
         (unsigned)ansi[2].key, (unsigned)ansi[3].key);
    copy_back(t, 0, "it");
    copy_back(t, 1, "it");
    destroy_table(t, "it");

    /* Many entries. */
    for (i = 0; i < MANY; i++) {
        set_entry(&many[i], (BYTE)(FVIRTKEY | ((i % 4) << 2)), (WORD)(0x30 + i % 64), (WORD)(1000 + i));
    }
    t = create(many, MANY, 0, "1000 entries");
    arm();
    n = CopyAcceleratorTableW(t, NULL, 0);
    line("CopyAcceleratorTableW(it, NULL, 0): ret=%d err=%s", n, le());
    memset(many_back, 0xEE, sizeof many_back);
    arm();
    n = CopyAcceleratorTableW(t, many_back, MANY);
    same = n == MANY;
    for (i = 0; i < n && i < MANY; i++) {
        if (many_back[i].fVirt != many[i].fVirt || many_back[i].key != many[i].key ||
            many_back[i].cmd != many[i].cmd) {
            same = 0;
        }
    }
    line("CopyAcceleratorTableW(it, buffer, 1000): ret=%d err=%s, every entry as given %s", n, le(),
         yesno(same));
    destroy_table(t, "it");

    /* A table whose first entry carries 0x80: does the translation stop
     * there? F6 is the first entry's, F7 the second's. */
    set_entry(&marked[0], 0x80 | FVIRTKEY, VK_F6, 421);
    set_entry(&marked[1], FVIRTKEY, VK_F7, 422);
    h = open_window("F2KAccelCreate", 0);
    tm = create(marked, 2, 0, "F6 with fVirt 0x81, F7");
    save_keys();
    set_modifiers(0, 0, 0);
    try_case(h, h, tm, 0, WM_KEYDOWN, VK_F6, KEY_LPARAM(0x40), "WM_KEYDOWN F6");
    try_case(h, h, tm, 0, WM_KEYDOWN, VK_F7, KEY_LPARAM(0x41), "WM_KEYDOWN F7");
    restore_keys();
    destroy_table(tm, "it");
    DestroyWindow(h);
    drain();
}

static const section_t sections[] = {
    { "load", sec_load, F2KT_ALWAYS },
    { "translate", sec_translate, F2KT_ALWAYS },
    { "ansi", sec_ansi, F2KT_ALWAYS },
    { "menu", sec_menu, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "alias", sec_alias, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("accel", sections, argc, argv);
}
