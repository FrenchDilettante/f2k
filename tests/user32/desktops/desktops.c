/*
 * desktops - window stations and desktops beyond the process's own
 * (the basics, GetProcessWindowStation, GetThreadDesktop and
 * GetUserObjectInformation, are winsta's): enumerating, opening,
 * creating and closing them, moving threads and the process between
 * them, their flags and security, and the USER and GDI objects a
 * process owns.
 *
 * No handle value is printed: only whether one came back and how two
 * compare. Names print only where they are the fixture's own (F2KDesk1,
 * F2KSta1) or Windows 2000's fixed ones (WinSta0, Default, Winlogon,
 * Disconnect); an enumeration prints whether a name was found, never
 * its list, which depends on the services and logons of the machine.
 * Counts print as relations (one more after a creation). Lines that
 * show an access check answer as the capture's account (see
 * fixture.toml).
 *
 * Every export observed is reached through GetProcAddress: the MSVC 6
 * era user32.lib predates some (GetGuiResources), and F2K's user32
 * lacks most, so a missing one prints "<Name>: absent" and ends its
 * section only. GetUserObjectInformationA/W, GetProcessWindowStation
 * and GetThreadDesktop, which F2K has, are imported.
 *
 * Nothing changes what the screen shows: the only SwitchDesktop that
 * runs switches to the input desktop itself; no window is shown; every
 * desktop and station the fixture makes is closed again before its
 * section ends (desktops with no handle left go away); a thread moved
 * to another desktop is a thread of the fixture's own, which ends.
 * LockWorkStation is never called.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   enumsta   EnumWindowStationsA/W: the return, the error, whether
 *             WinSta0 was listed and whether every name was nonempty
 *   enumdesk  EnumDesktopsA/W of the process's window station and of
 *             NULL (the process's): whether Default, Winlogon and
 *             Disconnect were listed; of a bogus handle
 *   opensta   OpenWindowStationA/W of WinSta0 (its name through the
 *             handle, the same handle as the process's or not), of a
 *             name no station has; CloseWindowStation of the opened
 *             handles, of one already closed, and of the process's own
 *             window station handle
 *   opendesk  OpenDesktopA/W of Default (its name, the same handle as
 *             the thread's or not), Winlogon and Disconnect (refused or
 *             not, as the capture's account), a name no desktop has;
 *             CloseDesktop of the opened handles, of one already
 *             closed, and of the thread's own desktop handle
 *   input     OpenInputDesktop: its name against the thread's
 *             desktop's; SwitchDesktop of it (the desktop already on
 *             the screen), of NULL; CloseDesktop of it
 *   create    CreateDesktopA of F2KDesk1 on the process's window
 *             station (its name, UOI_FLAGS), EnumDesktopsA listing it,
 *             CreateDesktopW of the same name (the same desktop or
 *             another), OpenDesktopA of it; SetUserObjectInformationA
 *             and W of UOI_FLAGS (fInherit set, then cleared) read back
 *             through GetUserObjectInformationA; EnumDesktopWindows of
 *             it (no window); every handle closed and OpenDesktopA of
 *             the name again
 *   thread    SetThreadDesktop of F2KDesk1 from the main thread, which
 *             owns a window (refused); a new thread's SetThreadDesktop
 *             of it, GetThreadDesktop after, a hidden window it makes
 *             there; EnumDesktopWindows of F2KDesk1, of the thread
 *             desktop and of NULL finding (or not) the new thread's
 *             window and the main thread's; SetThreadDesktop of NULL
 *   station   CreateWindowStationA of F2KSta1 (its name, UOI_FLAGS,
 *             EnumWindowStationsA listing it), CreateWindowStationW of
 *             the same name; SetProcessWindowStation to it,
 *             GetProcessWindowStation after, CreateDesktopA of F2KDesk2
 *             there, back to the original; a new thread's
 *             SetThreadDesktop of F2KDesk2 (a desktop of another
 *             station); SetProcessWindowStation of NULL; everything
 *             closed
 *   security  GetUserObjectSecurity of the window station and the
 *             thread's desktop with DACL_SECURITY_INFORMATION and
 *             OWNER_SECURITY_INFORMATION: the size query's return and
 *             error, the size nonzero, then the descriptor: whether it
 *             carries a DACL (SE_DACL_PRESENT and an offset) and an
 *             owner; SetUserObjectSecurity of F2KDesk1 with its own
 *             DACL read back; of a bogus handle
 *   gui       GetGuiResources of the process: GR_USEROBJECTS around a
 *             second hidden window's creation and destruction,
 *             GR_GDIOBJECTS around a pen's; of flag 2, and of a NULL
 *             process handle
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat desktops):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% desktops.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* A handle value no object has. */
#define BOGUS_HANDLE ((HANDLE)0x7FFFFFFC)

/* The access rights asked for (winuser.h's, and GENERIC_ALL). */
#define DESK_READOBJECTS_ 0x0001
#define DESK_ENUMERATE_ 0x0040
#define STA_ENUMDESKTOPS_ 0x0001
#define STA_READATTRIBUTES_ 0x0002
#define STA_ENUMERATE_ 0x0100
#define STA_ALL_ACCESS_ 0x037F

/* GetGuiResources' flags (winuser.h has them for WINVER 0x0500 only). */
#define GR_GDIOBJECTS_ 0
#define GR_USEROBJECTS_ 1

/* SECURITY_DESCRIPTOR_CONTROL's DACL bit. */
#define SE_DACL_PRESENT_ 0x0004

typedef BOOL (CALLBACK *name_proc_a)(LPSTR, LPARAM);
typedef BOOL (CALLBACK *name_proc_w)(LPWSTR, LPARAM);

typedef BOOL (WINAPI *enum_sta_a_t)(name_proc_a, LPARAM);
typedef BOOL (WINAPI *enum_sta_w_t)(name_proc_w, LPARAM);
typedef BOOL (WINAPI *enum_desk_a_t)(HWINSTA, name_proc_a, LPARAM);
typedef BOOL (WINAPI *enum_desk_w_t)(HWINSTA, name_proc_w, LPARAM);
typedef HWINSTA (WINAPI *open_sta_a_t)(LPCSTR, BOOL, DWORD);
typedef HWINSTA (WINAPI *open_sta_w_t)(LPCWSTR, BOOL, DWORD);
typedef BOOL (WINAPI *close_sta_t)(HWINSTA);
typedef HWINSTA (WINAPI *create_sta_a_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HWINSTA (WINAPI *create_sta_w_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HDESK (WINAPI *open_desk_a_t)(LPCSTR, DWORD, BOOL, DWORD);
typedef HDESK (WINAPI *open_desk_w_t)(LPCWSTR, DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *close_desk_t)(HDESK);
typedef HDESK (WINAPI *create_desk_a_t)(LPCSTR, LPCSTR, void *, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HDESK (WINAPI *create_desk_w_t)(LPCWSTR, LPCWSTR, void *, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HDESK (WINAPI *open_input_t)(DWORD, BOOL, DWORD);
typedef BOOL (WINAPI *switch_desk_t)(HDESK);
typedef BOOL (WINAPI *set_thread_desk_t)(HDESK);
typedef BOOL (WINAPI *set_proc_sta_t)(HWINSTA);
typedef BOOL (WINAPI *enum_desk_wnd_t)(HDESK, WNDENUMPROC, LPARAM);
typedef BOOL (WINAPI *get_sec_t)(HANDLE, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
typedef BOOL (WINAPI *set_sec_t)(HANDLE, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef BOOL (WINAPI *set_info_t)(HANDLE, int, PVOID, DWORD);
typedef DWORD (WINAPI *gui_res_t)(HANDLE, DWORD);

/* The export by name, or NULL with "<name>: absent" printed. */
static FARPROC resolve(const char *name)
{
    FARPROC p = GetProcAddress(GetModuleHandleA("user32.dll"), name);

    if (p == NULL) {
        line("%s: absent", name);
    }
    return p;
}

/* --- helpers ------------------------------------------------------- */

static const WCHAR W_WINSTA0[] = { 'W', 'i', 'n', 'S', 't', 'a', '0', 0 };
static const WCHAR W_DEFAULT[] = { 'D', 'e', 'f', 'a', 'u', 'l', 't', 0 };
static const WCHAR W_DESK1[] = { 'F', '2', 'K', 'D', 'e', 's', 'k', '1', 0 };
static const WCHAR W_STA1[] = { 'F', '2', 'K', 'S', 't', 'a', '1', 0 };

/* An object's name through GetUserObjectInformationA, or "(failed)". */
static const char *name_of(HANDLE h)
{
    static char bufs[2][128];
    static int next;
    char *b = bufs[next++ & 1];
    DWORD needed;

    if (!GetUserObjectInformationA(h, UOI_NAME, b, sizeof bufs[0], &needed)) {
        return "(failed)";
    }
    return b;
}

/* The same through GetUserObjectInformationW, printed as ws() prints. */
static const char *name_of_w(HANDLE h)
{
    static WCHAR b[128];
    DWORD needed;

    if (!GetUserObjectInformationW(h, UOI_NAME, b, sizeof b, &needed)) {
        return "(failed)";
    }
    return ws(b);
}

/* The thread's desktop. */
static HDESK thread_desktop(void)
{
    return GetThreadDesktop(GetCurrentThreadId());
}

/* What an enumeration's callback looks for: the names, which were
 * found, and whether an empty name came. */
#define MAX_WANTED 4

typedef struct {
    const char *wanted[MAX_WANTED];
    int found[MAX_WANTED];
    int count;
    int empty;
} names_t;

static void names_init(names_t *n, const char *a, const char *b, const char *c)
{
    ZeroMemory(n, sizeof *n);
    n->wanted[0] = a;
    n->wanted[1] = b;
    n->wanted[2] = c;
}

static void names_see(names_t *n, const char *name)
{
    int i;

    n->count++;
    if (name[0] == '\0') {
        n->empty = 1;
    }
    for (i = 0; i < MAX_WANTED; i++) {
        if (n->wanted[i] != NULL && _stricmp(n->wanted[i], name) == 0) {
            n->found[i] = 1;
        }
    }
}

static BOOL CALLBACK name_cb_a(LPSTR name, LPARAM lp)
{
    names_see((names_t *)lp, name);
    return TRUE;
}

static BOOL CALLBACK name_cb_w(LPWSTR name, LPARAM lp)
{
    char narrow[256];
    int i;

    for (i = 0; name[i] != 0 && i < (int)sizeof narrow - 1; i++) {
        narrow[i] = name[i] < 0x80 ? (char)name[i] : '?';
    }
    narrow[i] = '\0';
    names_see((names_t *)lp, narrow);
    return TRUE;
}

/* The callback's findings, one line. */
static void names_print(const names_t *n)
{
    char buf[256];
    int len = 0;
    int i;

    for (i = 0; i < MAX_WANTED; i++) {
        if (n->wanted[i] != NULL) {
            len += sprintf(buf + len, "%s%s %s", i ? ", " : "", n->wanted[i], yesno(n->found[i]));
        }
    }
    buf[len] = '\0';
    line("  listed: %s; any names: %s; an empty one: %s", buf, yesno(n->count > 0), yesno(n->empty));
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static int class_registered;

static HWND make_window(void)
{
    if (!class_registered) {
        WNDCLASSA wc;

        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = wndproc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = "F2KDesktops";
        RegisterClassA(&wc);
        class_registered = 1;
    }
    return CreateWindowExA(0, "F2KDesktops", "d", WS_POPUP, 0, 0, 40, 20, NULL, NULL,
                           GetModuleHandleA(NULL), NULL);
}

/* EnumDesktopWindows' callback: how many windows, and whether two
 * windows of interest were among them. */
typedef struct {
    HWND a, b;
    int count;
    int saw_a, saw_b;
} windows_t;

static BOOL CALLBACK window_cb(HWND hwnd, LPARAM lp)
{
    windows_t *w = (windows_t *)lp;

    w->count++;
    if (hwnd == w->a) {
        w->saw_a = 1;
    }
    if (hwnd == w->b) {
        w->saw_b = 1;
    }
    return TRUE;
}

/* --- enumsta ------------------------------------------------------- */

static void sec_enumsta(void)
{
    enum_sta_a_t enum_a = (enum_sta_a_t)resolve("EnumWindowStationsA");
    enum_sta_w_t enum_w = (enum_sta_w_t)resolve("EnumWindowStationsW");
    names_t n;
    BOOL r;

    if (enum_a == NULL || enum_w == NULL) {
        return;
    }
    names_init(&n, "WinSta0", NULL, NULL);
    arm();
    r = enum_a(name_cb_a, (LPARAM)&n);
    line("EnumWindowStationsA: ret=%d err=%s", r, le());
    names_print(&n);
    names_init(&n, "WinSta0", NULL, NULL);
    arm();
    r = enum_w(name_cb_w, (LPARAM)&n);
    line("EnumWindowStationsW: ret=%d err=%s", r, le());
    names_print(&n);
}

/* --- enumdesk ------------------------------------------------------ */

static void sec_enumdesk(void)
{
    enum_desk_a_t enum_a = (enum_desk_a_t)resolve("EnumDesktopsA");
    enum_desk_w_t enum_w = (enum_desk_w_t)resolve("EnumDesktopsW");
    names_t n;
    BOOL r;

    if (enum_a == NULL || enum_w == NULL) {
        return;
    }
    names_init(&n, "Default", "Winlogon", "Disconnect");
    arm();
    r = enum_a(GetProcessWindowStation(), name_cb_a, (LPARAM)&n);
    line("EnumDesktopsA(the process's window station): ret=%d err=%s", r, le());
    names_print(&n);
    names_init(&n, "Default", "Winlogon", "Disconnect");
    arm();
    r = enum_w(GetProcessWindowStation(), name_cb_w, (LPARAM)&n);
    line("EnumDesktopsW(the process's window station): ret=%d err=%s", r, le());
    names_print(&n);
    names_init(&n, "Default", "Winlogon", "Disconnect");
    arm();
    r = enum_a(NULL, name_cb_a, (LPARAM)&n);
    line("EnumDesktopsA(NULL): ret=%d err=%s", r, le());
    names_print(&n);
    names_init(&n, "Default", NULL, NULL);
    arm();
    r = enum_a((HWINSTA)BOGUS_HANDLE, name_cb_a, (LPARAM)&n);
    line("EnumDesktopsA(a bogus handle): ret=%d err=%s, names listed %s", r, le(), yesno(n.count > 0));
    names_init(&n, "Default", NULL, NULL);
    arm();
    r = enum_w((HWINSTA)BOGUS_HANDLE, name_cb_w, (LPARAM)&n);
    line("EnumDesktopsW(a bogus handle): ret=%d err=%s, names listed %s", r, le(), yesno(n.count > 0));
}

/* --- opensta ------------------------------------------------------- */

static void sec_opensta(void)
{
    open_sta_a_t open_a = (open_sta_a_t)resolve("OpenWindowStationA");
    open_sta_w_t open_w = (open_sta_w_t)resolve("OpenWindowStationW");
    close_sta_t close = (close_sta_t)resolve("CloseWindowStation");
    HWINSTA a, w, none;
    BOOL r;

    if (open_a == NULL || open_w == NULL || close == NULL) {
        return;
    }
    arm();
    a = open_a("WinSta0", FALSE, STA_ENUMDESKTOPS_ | STA_READATTRIBUTES_);
    line("OpenWindowStationA(WinSta0): non-NULL %s err=%s", yesno(a != NULL), le());
    if (a != NULL) {
        line("  its name %s, the process's handle %s", name_of(a),
             yesno(a == GetProcessWindowStation()));
    }
    arm();
    w = open_w(W_WINSTA0, FALSE, STA_ENUMDESKTOPS_ | STA_READATTRIBUTES_);
    line("OpenWindowStationW(WinSta0): non-NULL %s err=%s", yesno(w != NULL), le());
    if (w != NULL) {
        line("  its name %s, the A call's handle %s", name_of_w(w), yesno(w == a));
    }
    arm();
    none = open_a("F2KNoSuchStation", FALSE, STA_READATTRIBUTES_);
    line("OpenWindowStationA(F2KNoSuchStation): non-NULL %s err=%s", yesno(none != NULL), le());
    if (none != NULL) {
        close(none);
    }
    if (a != NULL) {
        arm();
        r = close(a);
        line("CloseWindowStation(the A handle): ret=%d err=%s", r, le());
        arm();
        r = close(a);
        line("CloseWindowStation(it, again): ret=%d err=%s", r, le());
    }
    if (w != NULL) {
        arm();
        r = close(w);
        line("CloseWindowStation(the W handle): ret=%d err=%s", r, le());
    }
    arm();
    r = close(GetProcessWindowStation());
    line("CloseWindowStation(the process's window station): ret=%d err=%s", r, le());
    line("  GetProcessWindowStation after: non-NULL %s, its name %s",
         yesno(GetProcessWindowStation() != NULL), name_of(GetProcessWindowStation()));
}

/* --- opendesk ------------------------------------------------------ */

static void open_named(open_desk_a_t open_a, close_desk_t close, const char *name)
{
    HDESK h;

    arm();
    h = open_a(name, 0, FALSE, DESK_READOBJECTS_);
    line("OpenDesktopA(%s): non-NULL %s err=%s", name, yesno(h != NULL), le());
    if (h != NULL) {
        line("  its name %s", name_of(h));
        close(h);
    }
}

static void sec_opendesk(void)
{
    open_desk_a_t open_a = (open_desk_a_t)resolve("OpenDesktopA");
    open_desk_w_t open_w = (open_desk_w_t)resolve("OpenDesktopW");
    close_desk_t close = (close_desk_t)resolve("CloseDesktop");
    HDESK a, w;
    BOOL r;

    if (open_a == NULL || open_w == NULL || close == NULL) {
        return;
    }
    arm();
    a = open_a("Default", 0, FALSE, DESK_READOBJECTS_ | DESK_ENUMERATE_);
    line("OpenDesktopA(Default): non-NULL %s err=%s", yesno(a != NULL), le());
    if (a != NULL) {
        line("  its name %s, the thread's handle %s", name_of(a), yesno(a == thread_desktop()));
    }
    arm();
    w = open_w(W_DEFAULT, 0, FALSE, DESK_READOBJECTS_ | DESK_ENUMERATE_);
    line("OpenDesktopW(Default): non-NULL %s err=%s", yesno(w != NULL), le());
    if (w != NULL) {
        line("  its name %s, the A call's handle %s", name_of_w(w), yesno(w == a));
    }
    open_named(open_a, close, "Winlogon");
    open_named(open_a, close, "Disconnect");
    open_named(open_a, close, "F2KNoSuchDesktop");
    if (a != NULL) {
        arm();
        r = close(a);
        line("CloseDesktop(the A handle): ret=%d err=%s", r, le());
        arm();
        r = close(a);
        line("CloseDesktop(it, again): ret=%d err=%s", r, le());
    }
    if (w != NULL) {
        arm();
        r = close(w);
        line("CloseDesktop(the W handle): ret=%d err=%s", r, le());
    }
    arm();
    r = close(thread_desktop());
    line("CloseDesktop(the thread's desktop): ret=%d err=%s", r, le());
    line("  GetThreadDesktop after: non-NULL %s, its name %s", yesno(thread_desktop() != NULL),
         name_of(thread_desktop()));
}

/* --- input --------------------------------------------------------- */

static void sec_input(void)
{
    open_input_t open_input = (open_input_t)resolve("OpenInputDesktop");
    switch_desk_t switch_to = (switch_desk_t)resolve("SwitchDesktop");
    close_desk_t close = (close_desk_t)resolve("CloseDesktop");
    HDESK h;
    BOOL r;

    if (open_input == NULL || switch_to == NULL || close == NULL) {
        return;
    }
    arm();
    h = open_input(0, FALSE, DESK_READOBJECTS_ | 0x0100 /* DESKTOP_SWITCHDESKTOP */);
    line("OpenInputDesktop: non-NULL %s err=%s", yesno(h != NULL), le());
    if (h == NULL) {
        return;
    }
    line("  its name %s, the thread's desktop's %s, the thread's handle %s", name_of(h),
         name_of(thread_desktop()), yesno(h == thread_desktop()));
    arm();
    r = switch_to(h);
    line("SwitchDesktop(the input desktop): ret=%d err=%s", r, le());
    arm();
    r = switch_to(NULL);
    line("SwitchDesktop(NULL): ret=%d err=%s", r, le());
    arm();
    r = close(h);
    line("CloseDesktop(the input desktop's handle): ret=%d err=%s", r, le());
}

/* --- create -------------------------------------------------------- */

static void print_flags(HANDLE h, const char *what)
{
    USEROBJECTFLAGS f;
    DWORD needed;
    BOOL r;

    ZeroMemory(&f, sizeof f);
    arm();
    r = GetUserObjectInformationA(h, UOI_FLAGS, &f, sizeof f, &needed);
    line("  %s UOI_FLAGS: ret=%d err=%s fInherit=%d fReserved=%d dwFlags=0x%lX", what, r, le(),
         f.fInherit, f.fReserved, f.dwFlags);
}

static void sec_create(void)
{
    create_desk_a_t create_a = (create_desk_a_t)resolve("CreateDesktopA");
    create_desk_w_t create_w = (create_desk_w_t)resolve("CreateDesktopW");
    open_desk_a_t open_a = (open_desk_a_t)resolve("OpenDesktopA");
    close_desk_t close = (close_desk_t)resolve("CloseDesktop");
    enum_desk_a_t enum_a = (enum_desk_a_t)resolve("EnumDesktopsA");
    enum_desk_wnd_t enum_windows = (enum_desk_wnd_t)resolve("EnumDesktopWindows");
    set_info_t set_a = (set_info_t)resolve("SetUserObjectInformationA");
    set_info_t set_w = (set_info_t)resolve("SetUserObjectInformationW");
    HDESK d, d2, o;
    names_t n;
    windows_t win;
    USEROBJECTFLAGS f;
    BOOL r;

    if (create_a == NULL || create_w == NULL || open_a == NULL || close == NULL || enum_a == NULL
        || enum_windows == NULL || set_a == NULL || set_w == NULL) {
        return;
    }
    arm();
    d = create_a("F2KDesk1", NULL, NULL, 0, GENERIC_ALL, NULL);
    line("CreateDesktopA(F2KDesk1): non-NULL %s err=%s", yesno(d != NULL), le());
    if (d == NULL) {
        return;
    }
    line("  its name %s, the thread's handle %s", name_of(d), yesno(d == thread_desktop()));
    print_flags(d, "its");
    names_init(&n, "F2KDesk1", "Default", NULL);
    arm();
    r = enum_a(GetProcessWindowStation(), name_cb_a, (LPARAM)&n);
    line("EnumDesktopsA(the process's window station): ret=%d err=%s", r, le());
    names_print(&n);

    arm();
    d2 = create_w(W_DESK1, NULL, NULL, 0, GENERIC_ALL, NULL);
    line("CreateDesktopW(F2KDesk1 again): non-NULL %s err=%s", yesno(d2 != NULL), le());
    if (d2 != NULL) {
        line("  its name %s, the first handle %s", name_of_w(d2), yesno(d2 == d));
    }
    arm();
    o = open_a("F2KDesk1", 0, FALSE, DESK_READOBJECTS_);
    line("OpenDesktopA(F2KDesk1): non-NULL %s err=%s", yesno(o != NULL), le());

    f.fInherit = TRUE;
    f.fReserved = FALSE;
    f.dwFlags = 0;
    arm();
    r = set_a(d, UOI_FLAGS, &f, sizeof f);
    line("SetUserObjectInformationA(it, UOI_FLAGS, fInherit 1): ret=%d err=%s", r, le());
    print_flags(d, "read back");
    f.fInherit = FALSE;
    arm();
    r = set_w(d, UOI_FLAGS, &f, sizeof f);
    line("SetUserObjectInformationW(it, UOI_FLAGS, fInherit 0): ret=%d err=%s", r, le());
    print_flags(d, "read back");
    arm();
    r = set_a(d, UOI_FLAGS, &f, sizeof f - 1);
    line("SetUserObjectInformationA(it, UOI_FLAGS, one byte short): ret=%d err=%s", r, le());
    arm();
    r = set_a(d, UOI_NAME, "F2KDeskX", 9);
    line("SetUserObjectInformationA(it, UOI_NAME): ret=%d err=%s", r, le());
    line("  its name after %s", name_of(d));

    ZeroMemory(&win, sizeof win);
    arm();
    r = enum_windows(d, window_cb, (LPARAM)&win);
    line("EnumDesktopWindows(F2KDesk1): ret=%d err=%s windows=%d", r, le(), win.count);

    if (o != NULL) {
        arm();
        r = close(o);
        line("CloseDesktop(the opened handle): ret=%d err=%s", r, le());
    }
    if (d2 != NULL) {
        arm();
        r = close(d2);
        line("CloseDesktop(the W call's handle): ret=%d err=%s", r, le());
    }
    arm();
    r = close(d);
    line("CloseDesktop(the A call's handle): ret=%d err=%s", r, le());
    arm();
    o = open_a("F2KDesk1", 0, FALSE, DESK_READOBJECTS_);
    line("OpenDesktopA(F2KDesk1) once every handle is closed: non-NULL %s err=%s", yesno(o != NULL),
         le());
    if (o != NULL) {
        close(o);
    }
}

/* --- thread -------------------------------------------------------- */

/* What the new thread does and finds, printed by the main thread. */
static struct {
    set_thread_desk_t set;
    HDESK target;
    BOOL set_ret;
    DWORD set_err;
    int same_handle;
    char name[64];
    HWND window;
    DWORD window_err;
    BOOL null_ret;
    DWORD null_err;
    HANDLE go_on;       /* the main thread has looked: destroy and end */
    HANDLE ready;       /* the thread has done its part */
} kid;

static DWORD WINAPI kid_main(void *unused)
{
    DWORD needed;

    (void)unused;
    SetLastError(F2KT_UNTOUCHED);
    kid.set_ret = kid.set(kid.target);
    kid.set_err = GetLastError();
    kid.same_handle = GetThreadDesktop(GetCurrentThreadId()) == kid.target;
    if (!GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, kid.name,
                                   sizeof kid.name, &needed)) {
        strcpy(kid.name, "(failed)");
    }
    if (kid.set_ret) {
        SetLastError(F2KT_UNTOUCHED);
        kid.window = make_window();
        kid.window_err = GetLastError();
    }
    SetEvent(kid.ready);
    WaitForSingleObject(kid.go_on, WAIT_MS);
    if (kid.window != NULL) {
        DestroyWindow(kid.window);
    }
    return 0;
}

/* Starts the new thread on `target` and waits for its part. */
static HANDLE kid_start(set_thread_desk_t set, HDESK target)
{
    DWORD tid;
    HANDLE t;

    ZeroMemory(&kid, sizeof kid);
    kid.set = set;
    kid.target = target;
    kid.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    kid.go_on = CreateEventA(NULL, TRUE, FALSE, NULL);
    t = CreateThread(NULL, 0, kid_main, NULL, 0, &tid);
    WaitForSingleObject(kid.ready, WAIT_MS);
    return t;
}

static void kid_end(HANDLE t)
{
    SetEvent(kid.go_on);
    WaitForSingleObject(t, WAIT_MS);
    CloseHandle(t);
    CloseHandle(kid.ready);
    CloseHandle(kid.go_on);
}

static void enum_line(enum_desk_wnd_t enum_windows, HDESK d, const char *what, HWND main_window)
{
    windows_t win;
    BOOL r;

    ZeroMemory(&win, sizeof win);
    win.a = kid.window;
    win.b = main_window;
    arm();
    r = enum_windows(d, window_cb, (LPARAM)&win);
    line("EnumDesktopWindows(%s): ret=%d err=%s, the new thread's window %s, the main thread's %s",
         what, r, le(), yesno(win.saw_a), yesno(win.saw_b));
}

static void sec_thread(void)
{
    create_desk_a_t create_a = (create_desk_a_t)resolve("CreateDesktopA");
    close_desk_t close = (close_desk_t)resolve("CloseDesktop");
    set_thread_desk_t set = (set_thread_desk_t)resolve("SetThreadDesktop");
    enum_desk_wnd_t enum_windows = (enum_desk_wnd_t)resolve("EnumDesktopWindows");
    HDESK d;
    HWND main_window;
    HANDLE t;
    BOOL r;

    if (create_a == NULL || close == NULL || set == NULL || enum_windows == NULL) {
        return;
    }
    main_window = make_window();
    line("the main thread's hidden window: non-NULL %s", yesno(main_window != NULL));
    arm();
    d = create_a("F2KDesk1", NULL, NULL, 0, GENERIC_ALL, NULL);
    line("CreateDesktopA(F2KDesk1): non-NULL %s err=%s", yesno(d != NULL), le());
    if (d == NULL) {
        DestroyWindow(main_window);
        return;
    }
    arm();
    r = set(d);
    line("SetThreadDesktop(F2KDesk1) from the main thread, which has a window: ret=%d err=%s", r, le());
    line("  the thread's desktop after %s", name_of(thread_desktop()));
    arm();
    r = set(thread_desktop());
    line("SetThreadDesktop(its own desktop) from the main thread: ret=%d err=%s", r, le());

    t = kid_start(set, d);
    line("a new thread's SetThreadDesktop(F2KDesk1): ret=%d err=%s", kid.set_ret, le_of(kid.set_err));
    line("  its GetThreadDesktop after: the handle given %s, its name %s", yesno(kid.same_handle),
         kid.name);
    line("  a hidden window made there: non-NULL %s err=%s", yesno(kid.window != NULL),
         le_of(kid.window_err));
    enum_line(enum_windows, d, "F2KDesk1", main_window);
    enum_line(enum_windows, thread_desktop(), "the main thread's desktop", main_window);
    enum_line(enum_windows, NULL, "NULL", main_window);
    kid_end(t);

    arm();
    r = set(NULL);
    line("SetThreadDesktop(NULL): ret=%d err=%s", r, le());
    DestroyWindow(main_window);
    arm();
    r = close(d);
    line("CloseDesktop(F2KDesk1) once the thread has ended: ret=%d err=%s", r, le());
}

/* --- station ------------------------------------------------------- */

static void sec_station(void)
{
    create_sta_a_t create_a = (create_sta_a_t)resolve("CreateWindowStationA");
    create_sta_w_t create_w = (create_sta_w_t)resolve("CreateWindowStationW");
    close_sta_t close_sta = (close_sta_t)resolve("CloseWindowStation");
    enum_sta_a_t enum_a = (enum_sta_a_t)resolve("EnumWindowStationsA");
    set_proc_sta_t set_proc = (set_proc_sta_t)resolve("SetProcessWindowStation");
    create_desk_a_t create_desk = (create_desk_a_t)resolve("CreateDesktopA");
    close_desk_t close_desk = (close_desk_t)resolve("CloseDesktop");
    set_thread_desk_t set_thread = (set_thread_desk_t)resolve("SetThreadDesktop");
    HWINSTA original, s, s2;
    HDESK d = NULL;
    HANDLE t;
    names_t n;
    BOOL r;

    if (create_a == NULL || create_w == NULL || close_sta == NULL || enum_a == NULL || set_proc == NULL
        || create_desk == NULL || close_desk == NULL || set_thread == NULL) {
        return;
    }
    original = GetProcessWindowStation();
    arm();
    s = create_a("F2KSta1", 0, STA_ALL_ACCESS_ | STANDARD_RIGHTS_REQUIRED, NULL);
    line("CreateWindowStationA(F2KSta1): non-NULL %s err=%s", yesno(s != NULL), le());
    if (s == NULL) {
        return;
    }
    line("  its name %s", name_of(s));
    print_flags(s, "its");
    names_init(&n, "F2KSta1", "WinSta0", NULL);
    arm();
    r = enum_a(name_cb_a, (LPARAM)&n);
    line("EnumWindowStationsA: ret=%d err=%s", r, le());
    names_print(&n);
    arm();
    s2 = create_w(W_STA1, 0, STA_ALL_ACCESS_ | STANDARD_RIGHTS_REQUIRED, NULL);
    line("CreateWindowStationW(F2KSta1 again): non-NULL %s err=%s", yesno(s2 != NULL), le());
    if (s2 != NULL) {
        line("  its name %s, the first handle %s", name_of_w(s2), yesno(s2 == s));
        close_sta(s2);
    }

    arm();
    r = set_proc(s);
    line("SetProcessWindowStation(F2KSta1): ret=%d err=%s", r, le());
    line("  GetProcessWindowStation after: F2KSta1's handle %s, its name %s",
         yesno(GetProcessWindowStation() == s), name_of(GetProcessWindowStation()));
    line("  the thread's desktop after: %s", name_of(thread_desktop()));
    arm();
    d = create_desk("F2KDesk2", NULL, NULL, 0, GENERIC_ALL, NULL);
    line("CreateDesktopA(F2KDesk2) there: non-NULL %s err=%s", yesno(d != NULL), le());
    if (d != NULL) {
        line("  its name %s", name_of(d));
    }
    arm();
    r = set_proc(original);
    line("SetProcessWindowStation(the original): ret=%d err=%s", r, le());
    line("  GetProcessWindowStation after: the original handle %s, its name %s",
         yesno(GetProcessWindowStation() == original), name_of(GetProcessWindowStation()));

    if (d != NULL) {
        t = kid_start(set_thread, d);
        line("a new thread's SetThreadDesktop(F2KDesk2, on F2KSta1): ret=%d err=%s", kid.set_ret,
             le_of(kid.set_err));
        line("  its desktop after: %s", kid.name);
        kid_end(t);
    }
    arm();
    r = set_proc(NULL);
    line("SetProcessWindowStation(NULL): ret=%d err=%s", r, le());
    if (d != NULL) {
        arm();
        r = close_desk(d);
        line("CloseDesktop(F2KDesk2): ret=%d err=%s", r, le());
    }
    arm();
    r = close_sta(s);
    line("CloseWindowStation(F2KSta1): ret=%d err=%s", r, le());
}

/* --- security ------------------------------------------------------ */

static BYTE sd_buf[4096];

/* The self-relative descriptor's control word and offsets, read in
 * place (SECURITY_DESCRIPTOR_RELATIVE: revision, Sbz1, control, then the
 * owner, group, SACL and DACL offsets). */
static void sd_describe(const BYTE *sd, int *dacl, int *owner)
{
    WORD control = *(const WORD *)(sd + 2);
    DWORD owner_off = *(const DWORD *)(sd + 4);
    DWORD dacl_off = *(const DWORD *)(sd + 16);

    *dacl = (control & SE_DACL_PRESENT_) != 0 && dacl_off != 0;
    *owner = owner_off != 0;
}

static void security_of(get_sec_t get, HANDLE h, const char *what, SECURITY_INFORMATION si,
                        const char *si_name)
{
    DWORD needed = 0;
    BOOL r;
    int dacl, owner;

    arm();
    r = get(h, &si, NULL, 0, &needed);
    line("GetUserObjectSecurity(%s, %s, size query): ret=%d err=%s, a size %s", what, si_name, r,
         le(), yesno(needed > 0));
    if (needed == 0 || needed > sizeof sd_buf) {
        return;
    }
    arm();
    r = get(h, &si, sd_buf, sizeof sd_buf, &needed);
    sd_describe(sd_buf, &dacl, &owner);
    line("GetUserObjectSecurity(%s, %s): ret=%d err=%s, a DACL %s, an owner %s", what, si_name, r,
         le(), yesno(r && dacl), yesno(r && owner));
}

static void sec_security(void)
{
    get_sec_t get = (get_sec_t)resolve("GetUserObjectSecurity");
    set_sec_t set = (set_sec_t)resolve("SetUserObjectSecurity");
    create_desk_a_t create_a = (create_desk_a_t)resolve("CreateDesktopA");
    close_desk_t close = (close_desk_t)resolve("CloseDesktop");
    SECURITY_INFORMATION si;
    DWORD needed;
    HDESK d;
    BOOL r;

    if (get == NULL || set == NULL || create_a == NULL || close == NULL) {
        return;
    }
    security_of(get, GetProcessWindowStation(), "the window station", DACL_SECURITY_INFORMATION,
                "DACL");
    security_of(get, GetProcessWindowStation(), "the window station", OWNER_SECURITY_INFORMATION,
                "owner");
    security_of(get, thread_desktop(), "the thread's desktop", DACL_SECURITY_INFORMATION, "DACL");
    security_of(get, thread_desktop(), "the thread's desktop", OWNER_SECURITY_INFORMATION, "owner");

    arm();
    d = create_a("F2KDesk1", NULL, NULL, 0, GENERIC_ALL, NULL);
    line("CreateDesktopA(F2KDesk1): non-NULL %s err=%s", yesno(d != NULL), le());
    if (d != NULL) {
        security_of(get, d, "F2KDesk1", DACL_SECURITY_INFORMATION, "DACL");
        si = DACL_SECURITY_INFORMATION;
        needed = 0;
        if (get(d, &si, sd_buf, sizeof sd_buf, &needed)) {
            arm();
            r = set(d, &si, sd_buf);
            line("SetUserObjectSecurity(F2KDesk1, DACL, its own DACL): ret=%d err=%s", r, le());
        }
        close(d);
    }
    si = DACL_SECURITY_INFORMATION;
    arm();
    r = get(BOGUS_HANDLE, &si, sd_buf, sizeof sd_buf, &needed);
    line("GetUserObjectSecurity(a bogus handle): ret=%d err=%s", r, le());
    arm();
    r = set(BOGUS_HANDLE, &si, sd_buf);
    line("SetUserObjectSecurity(a bogus handle): ret=%d err=%s", r, le());
}

/* --- gui ----------------------------------------------------------- */

static void sec_gui(void)
{
    gui_res_t get = (gui_res_t)resolve("GetGuiResources");
    HWND first, second;
    HPEN pen;
    DWORD before, after, gone;

    if (get == NULL) {
        return;
    }
    first = make_window();
    line("a first hidden window: non-NULL %s", yesno(first != NULL));
    arm();
    before = get(GetCurrentProcess(), GR_USEROBJECTS_);
    line("GetGuiResources(GR_USEROBJECTS): nonzero %s err=%s", yesno(before != 0), le());
    second = make_window();
    after = get(GetCurrentProcess(), GR_USEROBJECTS_);
    DestroyWindow(second);
    gone = get(GetCurrentProcess(), GR_USEROBJECTS_);
    line("  after a second window: %+ld; after its destruction: %+ld", (long)(after - before),
         (long)(gone - before));
    DestroyWindow(first);

    arm();
    before = get(GetCurrentProcess(), GR_GDIOBJECTS_);
    line("GetGuiResources(GR_GDIOBJECTS): ret nonzero %s err=%s", yesno(before != 0), le());
    pen = CreatePen(PS_SOLID, 1, RGB(1, 2, 3));
    after = get(GetCurrentProcess(), GR_GDIOBJECTS_);
    DeleteObject(pen);
    gone = get(GetCurrentProcess(), GR_GDIOBJECTS_);
    line("  after CreatePen: %+ld; after DeleteObject: %+ld", (long)(after - before),
         (long)(gone - before));

    arm();
    before = get(GetCurrentProcess(), 2);
    line("GetGuiResources(flag 2): ret=%lu err=%s", before, le());
    arm();
    before = get(NULL, GR_USEROBJECTS_);
    line("GetGuiResources(NULL, GR_USEROBJECTS): ret=%lu err=%s", before, le());
}

static const section_t sections[] = {
    { "enumsta", sec_enumsta, F2KT_ALWAYS },
    { "enumdesk", sec_enumdesk, F2KT_ALWAYS },
    { "opensta", sec_opensta, F2KT_ALWAYS },
    { "opendesk", sec_opendesk, F2KT_ALWAYS },
    { "input", sec_input, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "thread", sec_thread, F2KT_ALWAYS },
    { "station", sec_station, F2KT_ALWAYS },
    { "security", sec_security, F2KT_ALWAYS },
    { "gui", sec_gui, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("desktops", sections, argc, argv);
}
