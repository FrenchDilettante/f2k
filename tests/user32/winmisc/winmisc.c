/*
 * winmisc - the rest of user32's window calls: reparenting (SetParent),
 * the ancestry and search calls (GetAncestor, FindWindowExA/W,
 * RealChildWindowFromPoint, RealGetWindowClass/A/W), the information
 * calls (GetWindowInfo, GetTitleBarInfo, GetWindowModuleFileName/A/W),
 * minimizing and restoring (CloseWindow, OpenIcon), owned popups
 * (ShowOwnedPopups, AnyPopup), EnumThreadWindows, FlashWindow(Ex),
 * Get/SetClassWord, Get/SetInternalWindowPos, and the help ids
 * (Get/SetWindowContextHelpId, Get/SetMenuContextHelpId).
 *
 * Every export observed here is reached through GetProcAddress: MSVC
 * 6's user32.lib predates several of them, some are undocumented, and
 * F2K's user32 lacks them all yet, so a missing one prints
 * "<Name>: absent" and fails its own block, not the program's load.
 *
 * No handle value is printed: a window prints by the name the section
 * gave it (P1, C, G...), "the desktop", "NULL" or "another window".
 * Positions print only for the fixture's own windows, relative to
 * their parent's client area or as the coordinates the section gave.
 * Every window is hidden but where a section says otherwise; none is
 * made with CW_USEDEFAULT, and each section destroys its own.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   setparent  a WS_CHILD window C (shown, in a hidden parent P1) moved
 *              under P2: the return, the messages C receives, GetParent,
 *              IsChild and C's position in its new parent; moved back,
 *              then to NULL (the desktop) once hidden; a popup Q put
 *              under P1 (GetParent against GetAncestor(GA_PARENT)) and
 *              back; refusals: a parent under its own child, a window
 *              under itself, a destroyed window either way
 *   ancestor   GetAncestor GA_PARENT, GA_ROOT and GA_ROOTOWNER of a
 *              top-level window, a child, a grandchild, an owned popup,
 *              a message-only window and the desktop; GetParent of each
 *              beside it; flags 0 and 4, a destroyed window
 *   findwin    FindWindowExA/W over three children of one class (titles
 *              "one", "two", "one"): every child in turn, by title, past
 *              the last, by class atom; top level (parent NULL) by a
 *              unique class; a message-only window found under
 *              HWND_MESSAGE and not under NULL; a destroyed parent
 *   realclass  RealGetWindowClassA/W and RealGetWindowClass (the A
 *              alias) of the fixture's own class, an Edit, a superclass
 *              of Button that calls Button's procedure, a Button
 *              subclassed by SetWindowLong; a 4-unit buffer; beside
 *              GetClassNameA; RealChildWindowFromPoint over a group box
 *              holding a push button, a static, a hidden child and
 *              empty client area, beside ChildWindowFromPointEx with
 *              CWP_SKIPINVISIBLE
 *   info       GetWindowInfo (cbSize right and 0) of an overlapped
 *              window and a popup: each field against GetWindowRect,
 *              GetClientRect, GetWindowLong, the class atom; the border
 *              widths, status and creator version as numbers;
 *              GetTitleBarInfo (cbSize right and 0): the title bar's
 *              offsets in its window and its six states
 *   iconic     CloseWindow and OpenIcon of an overlapped window at
 *              -2000,-2000: IsIconic and IsWindowVisible after each;
 *              CloseWindow of a child; a destroyed window. The window
 *              shows minimized, then restored and active: leave the
 *              desktop alone while this block runs
 *   popups     ShowOwnedPopups(FALSE, TRUE) over an owner's two popups,
 *              one shown (off screen, not activated) and one hidden: each
 *              one's visibility and the WM_SHOWWINDOW it receives;
 *              AnyPopup while the shown popup is up (yes whatever else
 *              the desktop holds)
 *   enumthr    EnumThreadWindows of the program's thread (its three
 *              top-level windows found, its child not, windows of
 *              another thread not), stopped by the callback after one;
 *              of a second thread holding one window; of a thread
 *              holding none
 *   flash      FlashWindow(TRUE) twice and (FALSE) of a hidden window,
 *              the WM_NCACTIVATE each sends; FlashWindowEx FLASHW_CAPTION
 *              and FLASHW_STOP, cbSize 0; a destroyed window
 *   classword  GetClassWord/SetClassWord over a class with 8 extra bytes:
 *              offsets 0, 1, 6, 7 and 8, GCW_ATOM against the class's
 *              atom, GCL_STYLE's low word read and written, a destroyed
 *              window
 *   modname    GetWindowModuleFileNameA/W and the unsuffixed alias of
 *              the fixture's window and of the desktop window, against
 *              GetModuleFileNameA/W; buffers of 0 and 5 units; a
 *              destroyed window
 *   intpos     GetInternalWindowPos of a hidden window against
 *              GetWindowPlacement; SetInternalWindowPos with SW_HIDE and a
 *              new normal rectangle and minimized point: the placement
 *              after, still hidden
 *   helpid     Get/SetWindowContextHelpId and Get/SetMenuContextHelpId:
 *              fresh, set, read back, cleared, a destroyed window and
 *              menu
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat winmisc):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% winmisc.c user32.lib
 */

#include "../common/f2kt.h"

/* Constants the MSVC 6 headers lack (WINVER 0x0500's). */
#define GA_PARENT_ 1
#define GA_ROOT_ 2
#define GA_ROOTOWNER_ 3
#define HWND_MESSAGE_ ((HWND)-3)
#define CWP_SKIPINVISIBLE_ 0x0001
#define FLASHW_STOP_ 0
#define FLASHW_CAPTION_ 1
#define GCW_ATOM_ (-32)
#define GCL_STYLE_ (-26)

typedef struct {
    DWORD cbSize;
    RECT rcWindow;
    RECT rcClient;
    DWORD dwStyle;
    DWORD dwExStyle;
    DWORD dwWindowStatus;
    UINT cxWindowBorders;
    UINT cyWindowBorders;
    ATOM atomWindowType;
    WORD wCreatorVersion;
} windowinfo_t;

typedef struct {
    DWORD cbSize;
    RECT rcTitleBar;
    DWORD rgstate[6];
} titlebarinfo_t;

typedef struct {
    UINT cbSize;
    HWND hwnd;
    DWORD dwFlags;
    UINT uCount;
    DWORD dwTimeout;
} flashwinfo_t;

typedef HWND (WINAPI *set_parent_t)(HWND, HWND);
typedef HWND (WINAPI *get_ancestor_t)(HWND, UINT);
typedef HWND (WINAPI *find_ex_a_t)(HWND, HWND, LPCSTR, LPCSTR);
typedef HWND (WINAPI *find_ex_w_t)(HWND, HWND, LPCWSTR, LPCWSTR);
typedef UINT (WINAPI *real_class_a_t)(HWND, LPSTR, UINT);
typedef UINT (WINAPI *real_class_w_t)(HWND, LPWSTR, UINT);
typedef HWND (WINAPI *real_child_t)(HWND, POINT);
typedef BOOL (WINAPI *window_info_t)(HWND, windowinfo_t *);
typedef BOOL (WINAPI *title_info_t)(HWND, titlebarinfo_t *);
typedef BOOL (WINAPI *hwnd_bool_t)(HWND);
typedef BOOL (WINAPI *show_owned_t)(HWND, BOOL);
typedef BOOL (WINAPI *any_popup_t)(void);
typedef BOOL (WINAPI *enum_thread_t)(DWORD, WNDENUMPROC, LPARAM);
typedef BOOL (WINAPI *flash_t)(HWND, BOOL);
typedef BOOL (WINAPI *flash_ex_t)(flashwinfo_t *);
typedef WORD (WINAPI *get_class_word_t)(HWND, int);
typedef WORD (WINAPI *set_class_word_t)(HWND, int, WORD);
typedef UINT (WINAPI *module_a_t)(HWND, LPSTR, UINT);
typedef UINT (WINAPI *module_w_t)(HWND, LPWSTR, UINT);
typedef UINT (WINAPI *get_intpos_t)(HWND, RECT *, POINT *);
typedef BOOL (WINAPI *set_intpos_t)(HWND, UINT, RECT *, POINT *);
typedef BOOL (WINAPI *set_wnd_help_t)(HWND, DWORD);
typedef DWORD (WINAPI *get_wnd_help_t)(HWND);
typedef BOOL (WINAPI *set_menu_help_t)(HMENU, DWORD);
typedef DWORD (WINAPI *get_menu_help_t)(HMENU);

#define CLS "F2KWinMisc"
#define CLS_EXTRA "F2KWinMiscExtra"
#define CLS_TOP "F2KWinMiscTop"
#define CLS_SUPER "F2KWinMiscSuper"

/* --- helpers ------------------------------------------------------- */

static HINSTANCE inst;

/* An export of user32 by name, or NULL with "<name>: absent" printed. */
static FARPROC resolve(const char *name)
{
    FARPROC p = GetProcAddress(GetModuleHandleA("user32.dll"), name);

    if (p == NULL) {
        line("%s: absent", name);
    }
    return p;
}

/* The windows a section names, for who(). */
#define NAMED_MAX 12
static HWND named_h[NAMED_MAX];
static const char *named_s[NAMED_MAX];
static int named_n;

static void name_window(HWND h, const char *s)
{
    if (named_n < NAMED_MAX) {
        named_h[named_n] = h;
        named_s[named_n] = s;
        named_n++;
    }
}

static const char *who(HWND h)
{
    int i;

    if (h == NULL) {
        return "NULL";
    }
    if (h == GetDesktopWindow()) {
        return "the desktop";
    }
    for (i = 0; i < named_n; i++) {
        if (named_h[i] == h) {
            return named_s[i];
        }
    }
    return "another window";
}

/* The message log of the window being watched. */
#define LOG_MAX 48
static HWND watched;
static UINT log_msg[LOG_MAX];
static WPARAM log_wp[LOG_MAX];
static LPARAM log_lp[LOG_MAX];
static int log_n;
static int log_lost;

static void log_reset(HWND h)
{
    watched = h;
    log_n = 0;
    log_lost = 0;
}

static const char *msg_name(UINT m)
{
    static char b[16];

    switch (m) {
    case WM_MOVE: return "WM_MOVE";
    case WM_SIZE: return "WM_SIZE";
    case WM_ACTIVATE: return "WM_ACTIVATE";
    case WM_SETFOCUS: return "WM_SETFOCUS";
    case WM_KILLFOCUS: return "WM_KILLFOCUS";
    case WM_PAINT: return "WM_PAINT";
    case WM_ERASEBKGND: return "WM_ERASEBKGND";
    case WM_SHOWWINDOW: return "WM_SHOWWINDOW";
    case WM_ACTIVATEAPP: return "WM_ACTIVATEAPP";
    case WM_CHILDACTIVATE: return "WM_CHILDACTIVATE";
    case WM_GETMINMAXINFO: return "WM_GETMINMAXINFO";
    case WM_WINDOWPOSCHANGING: return "WM_WINDOWPOSCHANGING";
    case WM_WINDOWPOSCHANGED: return "WM_WINDOWPOSCHANGED";
    case WM_STYLECHANGING: return "WM_STYLECHANGING";
    case WM_STYLECHANGED: return "WM_STYLECHANGED";
    case WM_GETICON: return "WM_GETICON";
    case WM_NCCALCSIZE: return "WM_NCCALCSIZE";
    case WM_NCPAINT: return "WM_NCPAINT";
    case WM_NCACTIVATE: return "WM_NCACTIVATE";
    case WM_SYSCOMMAND: return "WM_SYSCOMMAND";
    case WM_PARENTNOTIFY: return "WM_PARENTNOTIFY";
    case WM_QUERYOPEN: return "WM_QUERYOPEN";
    case WM_SETCURSOR: return "WM_SETCURSOR";
    case WM_NCHITTEST: return "WM_NCHITTEST";
    case 0x0127: return "WM_CHANGEUISTATE";
    case 0x0128: return "WM_UPDATEUISTATE";
    case 0x0129: return "WM_QUERYUISTATE";
    }
    sprintf(b, "0x%04X", m);
    return b;
}

/* The log, one message a line, with the parameters that say something. */
static void log_print(const char *label)
{
    int i;

    line("  %s received %d message(s)%s", label, log_n, log_lost ? " (log full)" : "");
    for (i = 0; i < log_n; i++) {
        switch (log_msg[i]) {
        case WM_SHOWWINDOW:
            line("    WM_SHOWWINDOW wParam=%lu lParam=%ld", (unsigned long)log_wp[i], (long)log_lp[i]);
            break;
        case WM_NCACTIVATE:
            line("    WM_NCACTIVATE wParam=%lu", (unsigned long)log_wp[i]);
            break;
        case WM_MOVE:
            line("    WM_MOVE x=%d y=%d", (short)LOWORD(log_lp[i]), (short)HIWORD(log_lp[i]));
            break;
        default:
            line("    %s", msg_name(log_msg[i]));
            break;
        }
    }
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (hwnd == watched && watched != NULL) {
        if (log_n < LOG_MAX) {
            log_msg[log_n] = msg;
            log_wp[log_n] = wp;
            log_lp[log_n] = lp;
            log_n++;
        } else {
            log_lost = 1;
        }
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void drain(void)
{
    MSG m;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageA(&m);
    }
}

static void register_classes(void)
{
    WNDCLASSA wc;
    static int done;

    if (done) {
        return;
    }
    done = 1;
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.lpszClassName = CLS;
    RegisterClassA(&wc);
    wc.lpszClassName = CLS_TOP;
    RegisterClassA(&wc);
    wc.lpszClassName = CLS_EXTRA;
    wc.cbClsExtra = 8;
    wc.style = CS_DBLCLKS;
    RegisterClassA(&wc);
}

static HWND top(const char *title, DWORD style, int x, int y)
{
    return CreateWindowExA(0, CLS, title, style, x, y, 300, 200, NULL, NULL, inst, NULL);
}

static HWND child(HWND parent, const char *title, DWORD style, int x, int y)
{
    return CreateWindowExA(0, CLS, title, WS_CHILD | style, x, y, 60, 40, parent, NULL, inst, NULL);
}

static HWND popup(HWND owner, const char *title, DWORD style, int x, int y)
{
    return CreateWindowExA(0, CLS, title, WS_POPUP | style, x, y, 60, 40, owner, NULL, inst, NULL);
}

/* A window made and destroyed at once: a stale handle. */
static HWND stale_window(void)
{
    HWND h = top("stale", WS_OVERLAPPED, 40, 40);

    DestroyWindow(h);
    return h;
}

/* A window's position in its parent's client area. */
static void print_pos(const char *label, HWND h)
{
    RECT r;
    HWND parent = GetParent(h);

    GetWindowRect(h, &r);
    if (parent != NULL) {
        MapWindowPoints(NULL, parent, (POINT *)&r, 2);
    }
    line("  %s at %ld,%ld size %ldx%ld", label, r.left, r.top, r.right - r.left, r.bottom - r.top);
}

/* --- setparent ----------------------------------------------------- */

static void sec_setparent(void)
{
    set_parent_t set_parent = (set_parent_t)resolve("SetParent");
    get_ancestor_t get_ancestor = (get_ancestor_t)resolve("GetAncestor");
    HWND p1, p2, c, q, gone, r;

    if (set_parent == NULL || get_ancestor == NULL) {
        return;
    }
    register_classes();
    p1 = top("P1", WS_OVERLAPPEDWINDOW, 40, 40);
    p2 = top("P2", WS_OVERLAPPEDWINDOW, 80, 80);
    c = child(p1, "C", WS_VISIBLE, 10, 20);
    q = popup(NULL, "Q", 0, 120, 120);
    name_window(p1, "P1");
    name_window(p2, "P2");
    name_window(c, "C");
    name_window(q, "Q");
    drain();

    log_reset(c);
    arm();
    r = set_parent(c, p2);
    line("SetParent(C shown, P2): returned %s err=%s", who(r), le());
    log_print("C");
    log_reset(NULL);
    drain();
    line("  GetParent(C)=%s IsChild(P2, C) %s IsChild(P1, C) %s", who(GetParent(c)),
         yesno(IsChild(p2, c)), yesno(IsChild(p1, c)));
    line("  C's WS_VISIBLE %s", yesno((GetWindowLongA(c, GWL_STYLE) & WS_VISIBLE) != 0));
    print_pos("C", c);

    arm();
    r = set_parent(c, p1);
    line("SetParent(C, P1): returned %s err=%s", who(r), le());
    line("  GetParent(C)=%s", who(GetParent(c)));

    ShowWindow(c, SW_HIDE);
    drain();
    log_reset(c);
    arm();
    r = set_parent(c, NULL);
    line("SetParent(C hidden, NULL): returned %s err=%s", who(r), le());
    log_print("C");
    log_reset(NULL);
    line("  GetParent(C)=%s GetAncestor(C, GA_PARENT)=%s WS_CHILD %s", who(GetParent(c)),
         who(get_ancestor(c, GA_PARENT_)), yesno((GetWindowLongA(c, GWL_STYLE) & WS_CHILD) != 0));
    arm();
    r = set_parent(c, p1);
    line("SetParent(C, P1) again: returned %s err=%s", who(r), le());

    arm();
    r = set_parent(q, p1);
    line("SetParent(popup Q, P1): returned %s err=%s", who(r), le());
    line("  GetParent(Q)=%s GetAncestor(Q, GA_PARENT)=%s IsChild(P1, Q) %s", who(GetParent(q)),
         who(get_ancestor(q, GA_PARENT_)), yesno(IsChild(p1, q)));
    arm();
    r = set_parent(q, NULL);
    line("SetParent(Q, NULL): returned %s err=%s", who(r), le());
    line("  GetAncestor(Q, GA_PARENT)=%s", who(get_ancestor(q, GA_PARENT_)));

    arm();
    r = set_parent(p1, c);
    line("SetParent(P1, its child C): returned %s err=%s", who(r), le());
    line("  GetAncestor(P1, GA_PARENT)=%s GetParent(C)=%s", who(get_ancestor(p1, GA_PARENT_)),
         who(GetParent(c)));
    arm();
    r = set_parent(c, c);
    line("SetParent(C, C): returned %s err=%s", who(r), le());

    gone = stale_window();
    arm();
    r = set_parent(gone, p1);
    line("SetParent(destroyed, P1): returned %s err=%s", who(r), le());
    arm();
    r = set_parent(c, gone);
    line("SetParent(C, destroyed): returned %s err=%s", who(r), le());
    line("  GetParent(C)=%s", who(GetParent(c)));

    DestroyWindow(q);
    DestroyWindow(p2);
    DestroyWindow(p1);
    if (IsWindow(c)) {
        DestroyWindow(c);
    }
    drain();
    named_n = 0;
}

/* --- ancestor ------------------------------------------------------ */

static void print_ancestors(get_ancestor_t get_ancestor, const char *label, HWND h)
{
    line("%s: GA_PARENT=%s GA_ROOT=%s GA_ROOTOWNER=%s GetParent=%s", label,
         who(get_ancestor(h, GA_PARENT_)), who(get_ancestor(h, GA_ROOT_)),
         who(get_ancestor(h, GA_ROOTOWNER_)), who(GetParent(h)));
}

static void sec_ancestor(void)
{
    get_ancestor_t get_ancestor = (get_ancestor_t)resolve("GetAncestor");
    HWND p1, c, g, o, oo, m, gone, r;

    if (get_ancestor == NULL) {
        return;
    }
    register_classes();
    p1 = top("P1", WS_OVERLAPPEDWINDOW, 40, 40);
    c = child(p1, "C", 0, 10, 10);
    g = child(c, "G", 0, 5, 5);
    o = popup(p1, "O", 0, 60, 60);
    oo = popup(o, "OO", 0, 70, 70);
    m = CreateWindowExA(0, CLS, "M", 0, 0, 0, 10, 10, HWND_MESSAGE_, NULL, inst, NULL);
    line("message-only window made: %s", yesno(m != NULL));
    name_window(p1, "P1");
    name_window(c, "C");
    name_window(g, "G");
    name_window(o, "O");
    name_window(oo, "OO");
    name_window(m, "M");

    print_ancestors(get_ancestor, "P1", p1);
    print_ancestors(get_ancestor, "C", c);
    print_ancestors(get_ancestor, "G", g);
    print_ancestors(get_ancestor, "O (owned by P1)", o);
    print_ancestors(get_ancestor, "OO (owned by O)", oo);
    if (m != NULL) {
        print_ancestors(get_ancestor, "M (message-only)", m);
        r = get_ancestor(get_ancestor(m, GA_PARENT_), GA_PARENT_);
        line("M's parent's GA_PARENT=%s", who(r));
    }
    print_ancestors(get_ancestor, "the desktop", GetDesktopWindow());
    arm();
    r = get_ancestor(g, 0);
    line("GetAncestor(G, 0)=%s err=%s", who(r), le());
    arm();
    r = get_ancestor(g, 4);
    line("GetAncestor(G, 4)=%s err=%s", who(r), le());
    gone = stale_window();
    arm();
    r = get_ancestor(gone, GA_PARENT_);
    line("GetAncestor(destroyed, GA_PARENT)=%s err=%s", who(r), le());
    arm();
    r = get_ancestor(NULL, GA_PARENT_);
    line("GetAncestor(NULL, GA_PARENT)=%s err=%s", who(r), le());

    if (m != NULL) {
        DestroyWindow(m);
    }
    DestroyWindow(oo);
    DestroyWindow(o);
    DestroyWindow(p1);
    drain();
    named_n = 0;
}

/* --- findwin ------------------------------------------------------- */

static void sec_findwin(void)
{
    static const WCHAR cls_w[] = { 'F', '2', 'K', 'W', 'i', 'n', 'M', 'i', 's', 'c', 0 };
    static const WCHAR top_w[] = { 'F', '2', 'K', 'W', 'i', 'n', 'M', 'i', 's', 'c', 'T', 'o', 'p', 0 };
    static const WCHAR one_w[] = { 'o', 'n', 'e', 0 };
    find_ex_a_t find_a = (find_ex_a_t)resolve("FindWindowExA");
    find_ex_w_t find_w = (find_ex_w_t)resolve("FindWindowExW");
    HWND p1, a, b, c, t, m, gone, r, after;
    ATOM atom;
    int i;

    if (find_a == NULL || find_w == NULL) {
        return;
    }
    register_classes();
    p1 = top("P1", WS_OVERLAPPEDWINDOW, 40, 40);
    a = child(p1, "one", 0, 0, 0);
    b = child(p1, "two", 0, 0, 50);
    c = child(p1, "one", 0, 0, 100);
    t = CreateWindowExA(0, CLS_TOP, "F2K winmisc top", WS_POPUP, 40, 40, 30, 30, NULL, NULL, inst, NULL);
    m = CreateWindowExA(0, CLS_TOP, "F2K winmisc msg", 0, 0, 0, 10, 10, HWND_MESSAGE_, NULL, inst, NULL);
    name_window(p1, "P1");
    name_window(a, "A(one)");
    name_window(b, "B(two)");
    name_window(c, "C(one)");
    name_window(t, "T");
    name_window(m, "M");

    after = NULL;
    for (i = 0; i < 4; i++) {
        arm();
        r = find_a(p1, after, CLS, NULL);
        line("FindWindowExA(P1, %s, class, NULL)=%s err=%s", who(after), who(r), le());
        if (r == NULL) {
            break;
        }
        after = r;
    }
    after = NULL;
    for (i = 0; i < 3; i++) {
        arm();
        r = find_w(p1, after, cls_w, one_w);
        line("FindWindowExW(P1, %s, class, \"one\")=%s err=%s", who(after), who(r), le());
        if (r == NULL) {
            break;
        }
        after = r;
    }
    arm();
    r = find_a(p1, NULL, NULL, "two");
    line("FindWindowExA(P1, NULL, NULL, \"two\")=%s err=%s", who(r), le());
    arm();
    r = find_a(p1, NULL, NULL, "");
    line("FindWindowExA(P1, NULL, NULL, \"\")=%s err=%s", who(r), le());
    atom = (ATOM)GetClassLongA(a, GCW_ATOM_);
    arm();
    r = find_a(p1, NULL, (LPCSTR)MAKEINTATOM(atom), "two");
    line("FindWindowExA(P1, NULL, class atom, \"two\")=%s err=%s", who(r), le());
    arm();
    r = find_a(p1, NULL, "F2KNoSuchClass", NULL);
    line("FindWindowExA(P1, NULL, an unregistered class, NULL)=%s err=%s", who(r), le());

    arm();
    r = find_a(NULL, NULL, CLS_TOP, "F2K winmisc top");
    line("FindWindowExA(NULL, NULL, top class, its title)=%s err=%s", who(r), le());
    arm();
    r = find_w(NULL, NULL, top_w, NULL);
    line("FindWindowExW(NULL, NULL, top class, NULL)=%s err=%s", who(r), le());
    arm();
    r = find_a(GetDesktopWindow(), NULL, CLS_TOP, NULL);
    line("FindWindowExA(the desktop, NULL, top class, NULL)=%s err=%s", who(r), le());
    arm();
    r = find_a(NULL, NULL, CLS_TOP, "F2K winmisc msg");
    line("FindWindowExA(NULL, NULL, top class, the message window's title)=%s err=%s", who(r), le());
    arm();
    r = find_a(HWND_MESSAGE_, NULL, CLS_TOP, NULL);
    line("FindWindowExA(HWND_MESSAGE, NULL, top class, NULL)=%s err=%s", who(r), le());
    arm();
    r = find_a(p1, b, NULL, NULL);
    line("FindWindowExA(P1, B, NULL, NULL)=%s err=%s", who(r), le());
    arm();
    r = find_a(p1, t, NULL, NULL);
    line("FindWindowExA(P1, T (not its child), NULL, NULL)=%s err=%s", who(r), le());

    gone = stale_window();
    arm();
    r = find_a(gone, NULL, NULL, NULL);
    line("FindWindowExA(destroyed, NULL, NULL, NULL)=%s err=%s", who(r), le());

    if (m != NULL) {
        DestroyWindow(m);
    }
    DestroyWindow(t);
    DestroyWindow(p1);
    drain();
    named_n = 0;
}

/* --- realclass ----------------------------------------------------- */

static WNDPROC button_proc;

static LRESULT CALLBACK super_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return CallWindowProcA(button_proc, hwnd, msg, wp, lp);
}

static LRESULT CALLBACK sub_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return CallWindowProcA(button_proc, hwnd, msg, wp, lp);
}

static void real_class(real_class_a_t ra, real_class_a_t alias, real_class_w_t rw, const char *label,
                       HWND h)
{
    char a[64];
    WCHAR w[64];
    char cn[64];
    UINT n;

    GetClassNameA(h, cn, sizeof cn);
    memset(a, 0, sizeof a);
    arm();
    n = ra(h, a, sizeof a);
    line("%s (class %s): RealGetWindowClassA ret=%u err=%s \"%s\"", label, cn, n, le(), a);
    memset(w, 0, sizeof w);
    arm();
    n = rw(h, w, 64);
    line("  RealGetWindowClassW ret=%u err=%s \"%s\"", n, le(), ws(w));
    if (alias != NULL) {
        memset(a, 0, sizeof a);
        arm();
        n = alias(h, a, sizeof a);
        line("  RealGetWindowClass ret=%u err=%s \"%s\"", n, le(), a);
    }
}

static void point_at(real_child_t rc, HWND parent, const char *label, int x, int y)
{
    POINT pt;
    HWND r, e;

    pt.x = x;
    pt.y = y;
    arm();
    r = rc(parent, pt);
    line("RealChildWindowFromPoint(%s %d,%d)=%s err=%s", label, x, y, who(r), le());
    e = ChildWindowFromPointEx(parent, pt, CWP_SKIPINVISIBLE_);
    line("  ChildWindowFromPointEx(CWP_SKIPINVISIBLE)=%s", who(e));
}

static void sec_realclass(void)
{
    real_class_a_t ra = (real_class_a_t)resolve("RealGetWindowClassA");
    real_class_a_t alias = (real_class_a_t)resolve("RealGetWindowClass");
    real_class_w_t rw = (real_class_w_t)resolve("RealGetWindowClassW");
    real_child_t rc = (real_child_t)resolve("RealChildWindowFromPoint");
    HWND p, own, edit, sup, sub, group, push, stat, hid;
    WNDCLASSA wc;
    char a[8];
    WCHAR w[8];
    UINT n;

    if (ra == NULL || rw == NULL || rc == NULL) {
        return;
    }
    register_classes();
    GetClassInfoA(NULL, "Button", &wc);
    button_proc = wc.lpfnWndProc;
    wc.lpfnWndProc = super_proc;
    wc.hInstance = inst;
    wc.lpszClassName = CLS_SUPER;
    RegisterClassA(&wc);

    p = top("P", WS_OVERLAPPED, 40, 40);
    own = child(p, "own", 0, 0, 0);
    edit = CreateWindowExA(0, "Edit", "", WS_CHILD, 0, 0, 50, 20, p, NULL, inst, NULL);
    sup = CreateWindowExA(0, CLS_SUPER, "s", WS_CHILD | BS_PUSHBUTTON, 0, 0, 50, 20, p, NULL, inst,
                          NULL);
    sub = CreateWindowExA(0, "Button", "b", WS_CHILD | BS_PUSHBUTTON, 0, 0, 50, 20, p, NULL, inst, NULL);
    SetWindowLongA(sub, GWL_WNDPROC, (LONG)sub_proc);
    line("windows made: %s", yesno(own && edit && sup && sub));

    real_class(ra, alias, rw, "own window", own);
    real_class(ra, alias, rw, "Edit", edit);
    real_class(ra, alias, rw, "superclass of Button", sup);
    real_class(ra, alias, rw, "Button subclassed", sub);
    memset(a, 0, sizeof a);
    arm();
    n = ra(edit, a, 4);
    line("RealGetWindowClassA(Edit, 4 units) ret=%u err=%s \"%s\"", n, le(), a);
    memset(w, 0, sizeof w);
    arm();
    n = rw(edit, w, 4);
    line("RealGetWindowClassW(Edit, 4 units) ret=%u err=%s \"%s\"", n, le(), ws(w));
    DestroyWindow(own);
    DestroyWindow(edit);
    DestroyWindow(sup);
    DestroyWindow(sub);

    /* The group box covers 10,10-210,160 and holds the push button at
     * 30,40-110,70; the static at 250,10, the hidden child at 250,100. */
    group = CreateWindowExA(0, "Button", "g", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, 10, 200, 150, p,
                            NULL, inst, NULL);
    push = CreateWindowExA(0, "Button", "p", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 30, 40, 80, 30, p,
                           NULL, inst, NULL);
    stat = CreateWindowExA(0, "Static", "s", WS_CHILD | WS_VISIBLE, 250, 10, 40, 40, p, NULL, inst, NULL);
    hid = CreateWindowExA(0, CLS, "h", WS_CHILD, 250, 100, 40, 40, p, NULL, inst, NULL);
    name_window(p, "P");
    name_window(group, "the group box");
    name_window(push, "the push button");
    name_window(stat, "the static");
    name_window(hid, "the hidden child");
    point_at(rc, p, "the push button", 50, 50);
    point_at(rc, p, "the group box's empty area", 150, 120);
    point_at(rc, p, "the group box's frame", 10, 80);
    point_at(rc, p, "the static", 260, 20);
    point_at(rc, p, "the hidden child", 260, 110);
    point_at(rc, p, "nothing", 230, 180);
    point_at(rc, p, "outside", -5, -5);

    DestroyWindow(p);
    UnregisterClassA(CLS_SUPER, inst);
    drain();
    named_n = 0;
}

/* --- info ---------------------------------------------------------- */

static void window_info(window_info_t wi, const char *label, HWND h)
{
    windowinfo_t info;
    RECT wr, cr;
    BOOL ok;

    GetWindowRect(h, &wr);
    GetClientRect(h, &cr);
    MapWindowPoints(h, NULL, (POINT *)&cr, 2);
    memset(&info, 0xCC, sizeof info);
    info.cbSize = sizeof info;
    arm();
    ok = wi(h, &info);
    line("GetWindowInfo(%s): ret=%d err=%s", label, ok, le());
    line("  rcWindow as GetWindowRect %s, rcClient as the client area on screen %s",
         yesno(EqualRect(&info.rcWindow, &wr)), yesno(EqualRect(&info.rcClient, &cr)));
    line("  dwStyle as GWL_STYLE %s, dwExStyle as GWL_EXSTYLE %s",
         yesno(info.dwStyle == (DWORD)GetWindowLongA(h, GWL_STYLE)),
         yesno(info.dwExStyle == (DWORD)GetWindowLongA(h, GWL_EXSTYLE)));
    line("  dwWindowStatus=0x%lX cxWindowBorders=%u cyWindowBorders=%u", info.dwWindowStatus,
         info.cxWindowBorders, info.cyWindowBorders);
    line("  atomWindowType as the class atom %s, wCreatorVersion=0x%04X",
         yesno(info.atomWindowType == (ATOM)GetClassLongA(h, GCW_ATOM_)), info.wCreatorVersion);
    memset(&info, 0xCC, sizeof info);
    info.cbSize = 0;
    arm();
    ok = wi(h, &info);
    line("GetWindowInfo(%s, cbSize 0): ret=%d err=%s, cbSize after=%lu", label, ok, le(), info.cbSize);
}

static void title_info(title_info_t ti, const char *label, HWND h)
{
    titlebarinfo_t info;
    RECT wr;
    BOOL ok;
    int i;

    GetWindowRect(h, &wr);
    memset(&info, 0xCC, sizeof info);
    info.cbSize = sizeof info;
    arm();
    ok = ti(h, &info);
    line("GetTitleBarInfo(%s): ret=%d err=%s", label, ok, le());
    line("  rcTitleBar from the window's corner: %ld,%ld to %ld from the right, height %ld",
         info.rcTitleBar.left - wr.left, info.rcTitleBar.top - wr.top, wr.right - info.rcTitleBar.right,
         info.rcTitleBar.bottom - info.rcTitleBar.top);
    for (i = 0; i < 6; i++) {
        line("  rgstate[%d]=0x%08lX", i, info.rgstate[i]);
    }
    memset(&info, 0xCC, sizeof info);
    info.cbSize = 0;
    arm();
    ok = ti(h, &info);
    line("GetTitleBarInfo(%s, cbSize 0): ret=%d err=%s", label, ok, le());
}

static void sec_info(void)
{
    window_info_t wi = (window_info_t)resolve("GetWindowInfo");
    title_info_t ti = (title_info_t)resolve("GetTitleBarInfo");
    HWND ov, pop, gone;
    windowinfo_t info;
    BOOL ok;

    if (wi == NULL || ti == NULL) {
        return;
    }
    register_classes();
    ov = CreateWindowExA(0, CLS, "overlapped", WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, NULL, NULL, inst,
                         NULL);
    pop = CreateWindowExA(WS_EX_TOOLWINDOW, CLS, "popup", WS_POPUP | WS_BORDER, 60, 60, 100, 80, NULL,
                          NULL, inst, NULL);
    window_info(wi, "overlapped", ov);
    window_info(wi, "popup", pop);
    title_info(ti, "overlapped", ov);
    title_info(ti, "popup", pop);
    gone = stale_window();
    info.cbSize = sizeof info;
    arm();
    ok = wi(gone, &info);
    line("GetWindowInfo(destroyed): ret=%d err=%s", ok, le());
    DestroyWindow(ov);
    DestroyWindow(pop);
    drain();
}

/* --- iconic -------------------------------------------------------- */

static void state(const char *label, HWND h)
{
    line("  %s: IsIconic %s IsWindowVisible %s IsZoomed %s", label, yesno(IsIconic(h)),
         yesno(IsWindowVisible(h)), yesno(IsZoomed(h)));
}

static void sec_iconic(void)
{
    hwnd_bool_t close_window = (hwnd_bool_t)resolve("CloseWindow");
    hwnd_bool_t open_icon = (hwnd_bool_t)resolve("OpenIcon");
    HWND w, c, gone;
    BOOL ok;

    if (close_window == NULL || open_icon == NULL) {
        return;
    }
    register_classes();
    w = CreateWindowExA(0, CLS, "iconic", WS_OVERLAPPEDWINDOW, -2000, -2000, 300, 200, NULL, NULL, inst,
                        NULL);
    c = child(w, "c", 0, 0, 0);
    state("hidden", w);
    arm();
    ok = close_window(w);
    line("CloseWindow(hidden window): ret=%d err=%s", ok, le());
    state("after", w);
    arm();
    ok = close_window(w);
    line("CloseWindow(again): ret=%d err=%s", ok, le());
    state("after", w);
    arm();
    ok = open_icon(w);
    line("OpenIcon: ret=%d err=%s", ok, le());
    state("after", w);
    arm();
    ok = open_icon(w);
    line("OpenIcon(again): ret=%d err=%s", ok, le());
    state("after", w);
    arm();
    ok = close_window(c);
    line("CloseWindow(a child): ret=%d err=%s", ok, le());
    state("the child after", c);
    gone = stale_window();
    arm();
    ok = close_window(gone);
    line("CloseWindow(destroyed): ret=%d err=%s", ok, le());
    arm();
    ok = open_icon(gone);
    line("OpenIcon(destroyed): ret=%d err=%s", ok, le());
    DestroyWindow(w);
    drain();
}

/* --- popups -------------------------------------------------------- */

static void sec_popups(void)
{
    show_owned_t show_owned = (show_owned_t)resolve("ShowOwnedPopups");
    any_popup_t any_popup = (any_popup_t)resolve("AnyPopup");
    HWND owner, shown, hidden, gone;
    BOOL ok;

    if (show_owned == NULL || any_popup == NULL) {
        return;
    }
    register_classes();
    owner = top("owner", WS_OVERLAPPEDWINDOW, 40, 40);
    shown = popup(owner, "shown", WS_BORDER, -2000, -2000);
    hidden = popup(owner, "hidden", WS_BORDER, -2000, -1900);
    ShowWindow(shown, SW_SHOWNA);
    drain();
    line("the shown popup visible %s, the hidden one %s", yesno(IsWindowVisible(shown)),
         yesno(IsWindowVisible(hidden)));
    arm();
    ok = any_popup();
    line("AnyPopup with the shown popup up: ret=%d err=%s", ok != 0, le());

    log_reset(shown);
    arm();
    ok = show_owned(owner, FALSE);
    line("ShowOwnedPopups(owner, FALSE): ret=%d err=%s", ok, le());
    log_print("the shown popup");
    log_reset(NULL);
    line("  shown popup visible %s, hidden popup visible %s", yesno(IsWindowVisible(shown)),
         yesno(IsWindowVisible(hidden)));
    log_reset(shown);
    arm();
    ok = show_owned(owner, TRUE);
    line("ShowOwnedPopups(owner, TRUE): ret=%d err=%s", ok, le());
    log_print("the shown popup");
    log_reset(NULL);
    line("  shown popup visible %s, hidden popup visible %s", yesno(IsWindowVisible(shown)),
         yesno(IsWindowVisible(hidden)));
    log_reset(shown);
    arm();
    ok = show_owned(owner, TRUE);
    line("ShowOwnedPopups(owner, TRUE) again: ret=%d err=%s", ok, le());
    log_print("the shown popup");
    log_reset(NULL);
    gone = stale_window();
    arm();
    ok = show_owned(gone, FALSE);
    line("ShowOwnedPopups(destroyed, FALSE): ret=%d err=%s", ok, le());
    DestroyWindow(owner);
    drain();
}

/* --- enumthr ------------------------------------------------------- */

#define SEEN_MAX 32
static HWND seen[SEEN_MAX];
static int seen_n;
static int seen_stop;

static BOOL CALLBACK enum_cb(HWND h, LPARAM lp)
{
    if (seen_n < SEEN_MAX) {
        seen[seen_n] = h;
    }
    seen_n++;
    return !(seen_stop && seen_n >= 1);
}

static int was_seen(HWND h)
{
    int i;

    for (i = 0; i < seen_n && i < SEEN_MAX; i++) {
        if (seen[i] == h) {
            return 1;
        }
    }
    return 0;
}

static HWND thread_window;
static HANDLE thread_ready;
static HANDLE thread_quit;

static DWORD WINAPI window_thread(LPVOID arg)
{
    if (arg != NULL) {
        thread_window = top("other thread's", WS_OVERLAPPED, 40, 40);
    }
    SetEvent(thread_ready);
    WaitForSingleObject(thread_quit, WAIT_MS);
    if (thread_window != NULL && arg != NULL) {
        DestroyWindow(thread_window);
    }
    return 0;
}

static void sec_enumthr(void)
{
    enum_thread_t enum_thread = (enum_thread_t)resolve("EnumThreadWindows");
    HWND a, b, c, ch;
    HANDLE th;
    DWORD tid;
    BOOL ok;

    if (enum_thread == NULL) {
        return;
    }
    register_classes();
    a = top("a", WS_OVERLAPPED, 40, 40);
    b = top("b", WS_OVERLAPPED, 40, 40);
    c = popup(a, "c", 0, 40, 40);
    ch = child(a, "child", 0, 0, 0);
    thread_ready = CreateEventA(NULL, FALSE, FALSE, NULL);
    thread_quit = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, window_thread, (LPVOID)1, 0, &tid);
    WaitForSingleObject(thread_ready, WAIT_MS);

    seen_n = 0;
    seen_stop = 0;
    arm();
    ok = enum_thread(GetCurrentThreadId(), enum_cb, 0);
    line("EnumThreadWindows(this thread): ret=%d err=%s", ok, le());
    line("  a %s, b %s, c (owned popup) %s, the child %s, the other thread's %s", yesno(was_seen(a)),
         yesno(was_seen(b)), yesno(was_seen(c)), yesno(was_seen(ch)), yesno(was_seen(thread_window)));

    seen_n = 0;
    seen_stop = 1;
    arm();
    ok = enum_thread(GetCurrentThreadId(), enum_cb, 0);
    line("EnumThreadWindows(this thread), stopped after one: ret=%d err=%s, called %d time(s)", ok, le(),
         seen_n);

    seen_n = 0;
    seen_stop = 0;
    arm();
    ok = enum_thread(tid, enum_cb, 0);
    line("EnumThreadWindows(the other thread): ret=%d err=%s, called %d time(s), its window %s", ok, le(),
         seen_n, yesno(was_seen(thread_window)));
    SetEvent(thread_quit);
    WaitForSingleObject(th, WAIT_MS);
    CloseHandle(th);
    thread_window = NULL;

    ResetEvent(thread_quit);
    th = CreateThread(NULL, 0, window_thread, NULL, 0, &tid);
    WaitForSingleObject(thread_ready, WAIT_MS);
    seen_n = 0;
    arm();
    ok = enum_thread(tid, enum_cb, 0);
    line("EnumThreadWindows(a thread with no window): ret=%d err=%s, called %d time(s)", ok, le(), seen_n);
    SetEvent(thread_quit);
    WaitForSingleObject(th, WAIT_MS);
    CloseHandle(th);
    seen_n = 0;
    arm();
    ok = enum_thread(tid, enum_cb, 0);
    line("EnumThreadWindows(an ended thread): ret=%d err=%s, called %d time(s)", ok, le(), seen_n);

    CloseHandle(thread_ready);
    CloseHandle(thread_quit);
    DestroyWindow(c);
    DestroyWindow(a);
    DestroyWindow(b);
    drain();
}

/* --- flash --------------------------------------------------------- */

static void sec_flash(void)
{
    flash_t flash = (flash_t)resolve("FlashWindow");
    flash_ex_t flash_ex = (flash_ex_t)resolve("FlashWindowEx");
    flashwinfo_t fi;
    HWND w, gone;
    BOOL ok;

    if (flash == NULL || flash_ex == NULL) {
        return;
    }
    register_classes();
    w = top("flash", WS_OVERLAPPEDWINDOW, 40, 40);
    drain();

    log_reset(w);
    arm();
    ok = flash(w, TRUE);
    line("FlashWindow(hidden, TRUE): nonzero %s err=%s", yesno(ok), le());
    log_print("the window");
    log_reset(w);
    arm();
    ok = flash(w, TRUE);
    line("FlashWindow(hidden, TRUE) again: nonzero %s err=%s", yesno(ok), le());
    log_print("the window");
    log_reset(w);
    arm();
    ok = flash(w, FALSE);
    line("FlashWindow(hidden, FALSE): nonzero %s err=%s", yesno(ok), le());
    log_print("the window");
    log_reset(NULL);

    ZeroMemory(&fi, sizeof fi);
    fi.cbSize = sizeof fi;
    fi.hwnd = w;
    fi.dwFlags = FLASHW_CAPTION_;
    fi.uCount = 1;
    arm();
    ok = flash_ex(&fi);
    line("FlashWindowEx(FLASHW_CAPTION, count 1): nonzero %s err=%s", yesno(ok), le());
    fi.dwFlags = FLASHW_STOP_;
    fi.uCount = 0;
    arm();
    ok = flash_ex(&fi);
    line("FlashWindowEx(FLASHW_STOP): nonzero %s err=%s", yesno(ok), le());
    fi.cbSize = 0;
    arm();
    ok = flash_ex(&fi);
    line("FlashWindowEx(cbSize 0): nonzero %s err=%s", yesno(ok), le());
    drain();

    gone = stale_window();
    arm();
    ok = flash(gone, TRUE);
    line("FlashWindow(destroyed): nonzero %s err=%s", yesno(ok), le());
    fi.cbSize = sizeof fi;
    fi.hwnd = gone;
    fi.dwFlags = FLASHW_STOP_;
    arm();
    ok = flash_ex(&fi);
    line("FlashWindowEx(destroyed): nonzero %s err=%s", yesno(ok), le());
    DestroyWindow(w);
    drain();
}

/* --- classword ----------------------------------------------------- */

static void sec_classword(void)
{
    get_class_word_t get_word = (get_class_word_t)resolve("GetClassWord");
    set_class_word_t set_word = (set_class_word_t)resolve("SetClassWord");
    static const int offsets[] = { 0, 1, 6, 7, 8 };
    HWND w, gone;
    WORD v;
    ATOM atom;
    int i;

    if (get_word == NULL || set_word == NULL) {
        return;
    }
    register_classes();
    w = CreateWindowExA(0, CLS_EXTRA, "extra", WS_OVERLAPPED, 40, 40, 100, 100, NULL, NULL, inst, NULL);
    atom = (ATOM)GetClassLongA(w, GCW_ATOM_);
    for (i = 0; i < (int)(sizeof offsets / sizeof offsets[0]); i++) {
        arm();
        v = set_word(w, offsets[i], (WORD)(0x1200 + i));
        line("SetClassWord(%d, 0x%04X): ret=0x%04X err=%s", offsets[i], 0x1200 + i, v, le());
        arm();
        v = get_word(w, offsets[i]);
        line("  GetClassWord(%d): 0x%04X err=%s", offsets[i], v, le());
    }
    arm();
    v = get_word(w, GCW_ATOM_);
    line("GetClassWord(GCW_ATOM): the class atom %s err=%s", yesno(v != 0 && v == atom), le());
    arm();
    v = get_word(w, GCL_STYLE_);
    line("GetClassWord(GCL_STYLE): 0x%04X err=%s", v, le());
    arm();
    v = set_word(w, GCL_STYLE_, CS_DBLCLKS | CS_HREDRAW);
    line("SetClassWord(GCL_STYLE, CS_DBLCLKS|CS_HREDRAW): ret=0x%04X err=%s", v, le());
    line("  GetClassLongA(GCL_STYLE) after: 0x%08lX", (unsigned long)GetClassLongA(w, GCL_STYLE));
    arm();
    v = get_word(w, -1);
    line("GetClassWord(-1): 0x%04X err=%s", v, le());
    gone = stale_window();
    arm();
    v = get_word(gone, 0);
    line("GetClassWord(destroyed, 0): 0x%04X err=%s", v, le());
    arm();
    v = set_word(gone, 0, 1);
    line("SetClassWord(destroyed, 0, 1): 0x%04X err=%s", v, le());
    DestroyWindow(w);
    drain();
}

/* --- modname ------------------------------------------------------- */

static void module_name(module_a_t ma, module_a_t alias, module_w_t mw, const char *label, HWND h)
{
    char path[MAX_PATH], a[MAX_PATH];
    WCHAR wpath[MAX_PATH], w[MAX_PATH];
    UINT n;

    GetModuleFileNameA(NULL, path, MAX_PATH);
    GetModuleFileNameW(NULL, wpath, MAX_PATH);
    a[0] = '\0';
    arm();
    n = ma(h, a, MAX_PATH);
    line("GetWindowModuleFileNameA(%s): ret=%u err=%s, the program's path %s, ret its length %s", label, n,
         le(), yesno(strcmp(a, path) == 0), yesno(n == strlen(a)));
    if (alias != NULL) {
        a[0] = '\0';
        arm();
        n = alias(h, a, MAX_PATH);
        line("GetWindowModuleFileName(%s): ret=%u err=%s, the program's path %s", label, n, le(),
             yesno(strcmp(a, path) == 0));
    }
    w[0] = 0;
    arm();
    n = mw(h, w, MAX_PATH);
    line("GetWindowModuleFileNameW(%s): ret=%u err=%s, the program's path %s, ret its length %s", label, n,
         le(), yesno(lstrcmpW(w, wpath) == 0), yesno(n == (UINT)lstrlenW(w)));
}

static void sec_modname(void)
{
    module_a_t ma = (module_a_t)resolve("GetWindowModuleFileNameA");
    module_a_t alias = (module_a_t)resolve("GetWindowModuleFileName");
    module_w_t mw = (module_w_t)resolve("GetWindowModuleFileNameW");
    char path[MAX_PATH], a[8];
    WCHAR wpath[MAX_PATH], w[8];
    HWND h, gone;
    UINT n;

    if (ma == NULL || mw == NULL) {
        return;
    }
    register_classes();
    GetModuleFileNameA(NULL, path, MAX_PATH);
    GetModuleFileNameW(NULL, wpath, MAX_PATH);
    h = top("mod", WS_OVERLAPPED, 40, 40);
    module_name(ma, alias, mw, "the program's window", h);
    module_name(ma, alias, mw, "the desktop", GetDesktopWindow());

    memset(a, 'x', sizeof a);
    arm();
    n = ma(h, a, 0);
    line("GetWindowModuleFileNameA(0 units): ret=%u err=%s, buffer untouched %s", n, le(), yesno(a[0] == 'x'));
    memset(a, 'x', sizeof a);
    arm();
    n = ma(h, a, 5);
    line("GetWindowModuleFileNameA(5 units): ret=%u err=%s, terminated at %d %s, the path's first %u %s",
         n, le(), n < 5 ? (int)n : 4, yesno(a[n < 5 ? n : 4] == '\0'), n,
         yesno(n <= 5 && memcmp(a, path, n) == 0));
    for (n = 0; n < 8; n++) {
        w[n] = 'x';
    }
    arm();
    n = mw(h, w, 5);
    line("GetWindowModuleFileNameW(5 units): ret=%u err=%s, terminated at %d %s, the path's first %u %s",
         n, le(), n < 5 ? (int)n : 4, yesno(w[n < 5 ? n : 4] == 0), n,
         yesno(n <= 5 && memcmp(w, wpath, n * sizeof(WCHAR)) == 0));
    gone = stale_window();
    arm();
    n = ma(gone, path, MAX_PATH);
    line("GetWindowModuleFileNameA(destroyed): ret=%u err=%s", n, le());
    DestroyWindow(h);
    drain();
}

/* --- intpos -------------------------------------------------------- */

static void print_placement(HWND h)
{
    WINDOWPLACEMENT wp;

    wp.length = sizeof wp;
    GetWindowPlacement(h, &wp);
    line("  GetWindowPlacement: showCmd=%u rcNormal %ld %ld %ld %ld ptMin %ld,%ld", wp.showCmd,
         wp.rcNormalPosition.left, wp.rcNormalPosition.top, wp.rcNormalPosition.right,
         wp.rcNormalPosition.bottom, wp.ptMinPosition.x, wp.ptMinPosition.y);
}

static void sec_intpos(void)
{
    get_intpos_t get_pos = (get_intpos_t)resolve("GetInternalWindowPos");
    set_intpos_t set_pos = (set_intpos_t)resolve("SetInternalWindowPos");
    HWND h, gone;
    RECT r;
    POINT pt;
    UINT cmd;
    BOOL ok;

    if (get_pos == NULL || set_pos == NULL) {
        return;
    }
    register_classes();
    h = CreateWindowExA(0, CLS, "pos", WS_OVERLAPPEDWINDOW, 40, 40, 300, 200, NULL, NULL, inst, NULL);
    memset(&r, 0xCC, sizeof r);
    memset(&pt, 0xCC, sizeof pt);
    arm();
    cmd = get_pos(h, &r, &pt);
    line("GetInternalWindowPos(hidden window): ret=%u err=%s rc %ld %ld %ld %ld pt %ld,%ld", cmd, le(),
         r.left, r.top, r.right, r.bottom, pt.x, pt.y);
    print_placement(h);
    arm();
    cmd = get_pos(h, NULL, NULL);
    line("GetInternalWindowPos(NULL, NULL): ret=%u err=%s", cmd, le());

    SetRect(&r, 50, 60, 250, 210);
    pt.x = 7;
    pt.y = 9;
    arm();
    ok = set_pos(h, SW_HIDE, &r, &pt);
    line("SetInternalWindowPos(SW_HIDE, 50 60 250 210, 7,9): ret=%d err=%s", ok, le());
    line("  IsWindowVisible %s", yesno(IsWindowVisible(h)));
    print_placement(h);
    memset(&r, 0xCC, sizeof r);
    memset(&pt, 0xCC, sizeof pt);
    arm();
    cmd = get_pos(h, &r, &pt);
    line("GetInternalWindowPos after: ret=%u err=%s rc %ld %ld %ld %ld pt %ld,%ld", cmd, le(), r.left,
         r.top, r.right, r.bottom, pt.x, pt.y);
    GetWindowRect(h, &r);
    line("  GetWindowRect %ld %ld %ld %ld", r.left, r.top, r.right, r.bottom);

    gone = stale_window();
    arm();
    cmd = get_pos(gone, &r, &pt);
    line("GetInternalWindowPos(destroyed): ret=%u err=%s", cmd, le());
    DestroyWindow(h);
    drain();
}

/* --- helpid -------------------------------------------------------- */

static void sec_helpid(void)
{
    set_wnd_help_t set_wh = (set_wnd_help_t)resolve("SetWindowContextHelpId");
    get_wnd_help_t get_wh = (get_wnd_help_t)resolve("GetWindowContextHelpId");
    set_menu_help_t set_mh = (set_menu_help_t)resolve("SetMenuContextHelpId");
    get_menu_help_t get_mh = (get_menu_help_t)resolve("GetMenuContextHelpId");
    HWND h, gone;
    HMENU m, pm, dead;
    DWORD id;
    BOOL ok;

    if (set_wh == NULL || get_wh == NULL || set_mh == NULL || get_mh == NULL) {
        return;
    }
    register_classes();
    h = top("help", WS_OVERLAPPED, 40, 40);
    m = CreateMenu();
    pm = CreatePopupMenu();

    arm();
    id = get_wh(h);
    line("GetWindowContextHelpId(fresh window): %lu err=%s", id, le());
    arm();
    ok = set_wh(h, 1234);
    line("SetWindowContextHelpId(1234): ret=%d err=%s", ok, le());
    arm();
    id = get_wh(h);
    line("GetWindowContextHelpId: %lu err=%s", id, le());
    arm();
    ok = set_wh(h, 0xFFFFFFFFu);
    line("SetWindowContextHelpId(0xFFFFFFFF): ret=%d err=%s", ok, le());
    arm();
    id = get_wh(h);
    line("GetWindowContextHelpId: 0x%08lX err=%s", id, le());
    arm();
    ok = set_wh(h, 0);
    line("SetWindowContextHelpId(0): ret=%d err=%s", ok, le());
    arm();
    id = get_wh(h);
    line("GetWindowContextHelpId: %lu err=%s", id, le());
    gone = stale_window();
    arm();
    ok = set_wh(gone, 5);
    line("SetWindowContextHelpId(destroyed, 5): ret=%d err=%s", ok, le());
    arm();
    id = get_wh(gone);
    line("GetWindowContextHelpId(destroyed): %lu err=%s", id, le());

    arm();
    id = get_mh(m);
    line("GetMenuContextHelpId(fresh menu): %lu err=%s", id, le());
    arm();
    ok = set_mh(m, 77);
    line("SetMenuContextHelpId(menu, 77): ret=%d err=%s", ok, le());
    arm();
    id = get_mh(m);
    line("GetMenuContextHelpId(menu): %lu err=%s", id, le());
    arm();
    ok = set_mh(pm, 88);
    line("SetMenuContextHelpId(popup menu, 88): ret=%d err=%s", ok, le());
    arm();
    id = get_mh(pm);
    line("GetMenuContextHelpId(popup menu): %lu err=%s, the menu's still %lu", id, le(), get_mh(m));
    arm();
    ok = set_mh(m, 0);
    line("SetMenuContextHelpId(menu, 0): ret=%d err=%s", ok, le());
    arm();
    id = get_mh(m);
    line("GetMenuContextHelpId(menu): %lu err=%s", id, le());
    dead = CreateMenu();
    DestroyMenu(dead);
    arm();
    ok = set_mh(dead, 5);
    line("SetMenuContextHelpId(destroyed menu, 5): ret=%d err=%s", ok, le());
    arm();
    id = get_mh(dead);
    line("GetMenuContextHelpId(destroyed menu): %lu err=%s", id, le());

    DestroyMenu(pm);
    DestroyMenu(m);
    DestroyWindow(h);
    drain();
}

/* --- main ---------------------------------------------------------- */

static const section_t sections[] = {
    { "setparent", sec_setparent, F2KT_ALWAYS },
    { "ancestor", sec_ancestor, F2KT_ALWAYS },
    { "findwin", sec_findwin, F2KT_ALWAYS },
    { "realclass", sec_realclass, F2KT_ALWAYS },
    { "info", sec_info, F2KT_ALWAYS },
    { "iconic", sec_iconic, F2KT_ALWAYS },
    { "popups", sec_popups, F2KT_ALWAYS },
    { "enumthr", sec_enumthr, F2KT_ALWAYS },
    { "flash", sec_flash, F2KT_ALWAYS },
    { "classword", sec_classword, F2KT_ALWAYS },
    { "modname", sec_modname, F2KT_ALWAYS },
    { "intpos", sec_intpos, F2KT_ALWAYS },
    { "helpid", sec_helpid, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    inst = GetModuleHandleA(NULL);
    return run_sections("winmisc", sections, argc, argv);
}
