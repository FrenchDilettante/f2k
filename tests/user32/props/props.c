/*
 * props - window properties in user32: SetPropW/A, GetPropW/A and
 * RemovePropW/A, by string and by atom, and EnumPropsW/A and
 * EnumPropsExW/A.
 *
 * A property's name is a global atom: a string names the atom of that
 * string (GlobalAddAtom's, case-insensitive; "#291" is the integer atom
 * 291), and MAKEINTATOM names an atom directly, so a property set one
 * way is found the other. The sections set, read, replace and remove
 * properties on a hidden WS_POPUP window of the program's own class,
 * from its own thread and from a second one, and watch what a
 * property's name does to the global atom table (GlobalFindAtomW).
 *
 * The values are the program's own constants (0x1111 and so on) and
 * print as they are; atoms and handles never print, only whether one
 * came back. Every name starts with "F2KProps", and every section
 * deletes the global atoms of its names at its start and end, so a run
 * finds the table as the last one left it.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel, and its line
 * prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   string  SetPropW and GetPropW by name, GetPropA of the same name,
 *           a name in other case, a second property, replacing a value
 *           through SetPropA, RemovePropW and RemovePropA (the value
 *           returned, then nothing), a property whose value is 0
 *   atom    a property set by GlobalAddAtomW's atom and read by name
 *           (W and A), set again by name and read by atom, removed by
 *           atom; "#291" against MAKEINTATOM(291), both ways; an atom
 *           nothing was set under
 *   refs    the property name's global atom: found or not before
 *           SetPropW, after it, after a second SetPropW of the same
 *           name, after RemovePropW, and after the window is destroyed
 *           with the property still set
 *   thread  a second thread reading, setting and removing properties
 *           of the first thread's window, and the first reading what
 *           it left
 *   errors  NULL, destroyed and another process's windows; a name
 *           never set; the empty name and a 300-character one; a NULL
 *           name (inside __try)
 *   enum    EnumPropsW/A and EnumPropsExW/A (found with GetProcAddress,
 *           so the program loads where user32 lacks them) over four
 *           properties (three names and MAKEINTATOM(291)): each one
 *           received, its value, their order against the order set,
 *           the return, the window and lParam passed; a callback
 *           answering FALSE early; a window with none, NULL and a
 *           destroyed window; a callback removing each property it is
 *           given, then the list after
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat props):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% props.c user32.lib
 */

#include "../common/f2kt.h"

/* MAKEINTATOM for each form: the SDK's gives the TCHAR pointer. */
#define ATOM_W(a) ((LPCWSTR)(DWORD)(WORD)(a))
#define ATOM_A(a) ((LPCSTR)(DWORD)(WORD)(a))

static const WCHAR *const names[] = {
    L"F2KPropsOne", L"F2KPropsTwo", L"F2KPropsZero", L"F2KPropsAtom", L"F2KPropsRef",
    L"F2KPropsShared", L"F2KPropsThread", L"F2KPropsNever", L"#291", NULL
};

/* Delete every global atom of the fixture's names: a property left
 * behind by an earlier run holds one reference each time it was set. */
static void forget_atoms(void)
{
    ATOM a;
    int i, n;

    for (i = 0; names[i] != NULL; i++) {
        if (names[i][0] == '#') {
            continue;
        }
        for (n = 0; n < 64; n++) {
            a = GlobalFindAtomW(names[i]);
            if (a == 0) {
                break;
            }
            GlobalDeleteAtom(a);
        }
    }
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/* The class, once per process, and a hidden window of it. */
static HWND make_window(void)
{
    static BOOL registered;
    WNDCLASSW wc;
    HWND h;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = wndproc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.lpszClassName = L"F2KProps";
        registered = RegisterClassW(&wc) != 0;
    }
    h = CreateWindowExW(0, L"F2KProps", L"props", WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    line("setup: the window created: %s", yesno(h != NULL));
    return h;
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

static void set_w(const char *label, HWND h, LPCWSTR name, DWORD value)
{
    BOOL r;

    arm();
    r = SetPropW(h, name, (HANDLE)value);
    line("SetPropW(%s, 0x%lX): ret=%d err=%s", label, value, r, le());
}

static void set_a(const char *label, HWND h, LPCSTR name, DWORD value)
{
    BOOL r;

    arm();
    r = SetPropA(h, name, (HANDLE)value);
    line("SetPropA(%s, 0x%lX): ret=%d err=%s", label, value, r, le());
}

static void get_w(const char *label, HWND h, LPCWSTR name)
{
    HANDLE r;

    arm();
    r = GetPropW(h, name);
    line("GetPropW(%s): ret=0x%lX err=%s", label, (DWORD)r, le());
}

static void get_a(const char *label, HWND h, LPCSTR name)
{
    HANDLE r;

    arm();
    r = GetPropA(h, name);
    line("GetPropA(%s): ret=0x%lX err=%s", label, (DWORD)r, le());
}

static void remove_w(const char *label, HWND h, LPCWSTR name)
{
    HANDLE r;

    arm();
    r = RemovePropW(h, name);
    line("RemovePropW(%s): ret=0x%lX err=%s", label, (DWORD)r, le());
}

static void remove_a(const char *label, HWND h, LPCSTR name)
{
    HANDLE r;

    arm();
    r = RemovePropA(h, name);
    line("RemovePropA(%s): ret=0x%lX err=%s", label, (DWORD)r, le());
}

static void end_section(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
    drain();
    forget_atoms();
}

/* --- string -------------------------------------------------------- */

static void sec_string(void)
{
    HWND h;

    forget_atoms();
    h = make_window();
    set_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne", 0x1111);
    get_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne");
    get_a("h, \"F2KPropsOne\"", h, "F2KPropsOne");
    get_w("h, L\"f2kpropsONE\"", h, L"f2kpropsONE");
    set_w("h, L\"F2KPropsTwo\"", h, L"F2KPropsTwo", 0x2222);
    get_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne");
    get_w("h, L\"F2KPropsTwo\"", h, L"F2KPropsTwo");
    set_a("h, \"F2KPropsOne\"", h, "F2KPropsOne", 0x3333);
    get_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne");
    remove_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne");
    get_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne");
    remove_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne");
    get_w("h, L\"F2KPropsTwo\"", h, L"F2KPropsTwo");
    remove_a("h, \"f2kpropstwo\"", h, "f2kpropstwo");
    get_a("h, \"F2KPropsTwo\"", h, "F2KPropsTwo");
    set_w("h, L\"F2KPropsZero\"", h, L"F2KPropsZero", 0);
    get_w("h, L\"F2KPropsZero\"", h, L"F2KPropsZero");
    remove_w("h, L\"F2KPropsZero\"", h, L"F2KPropsZero");
    end_section(h);
}

/* --- atom ---------------------------------------------------------- */

static void sec_atom(void)
{
    HWND h;
    ATOM a;

    forget_atoms();
    h = make_window();
    a = GlobalAddAtomW(L"F2KPropsAtom");
    line("GlobalAddAtomW(L\"F2KPropsAtom\"): nonzero %s, a string atom (0xC000-0xFFFF) %s",
         yesno(a != 0), yesno(a >= 0xC000));

    set_w("h, MAKEINTATOM(the atom)", h, ATOM_W(a), 0x4444);
    get_w("h, L\"F2KPropsAtom\"", h, L"F2KPropsAtom");
    get_a("h, \"F2KPropsAtom\"", h, "F2KPropsAtom");
    get_w("h, MAKEINTATOM(the atom)", h, ATOM_W(a));
    set_w("h, L\"F2KPropsAtom\"", h, L"F2KPropsAtom", 0x5555);
    get_w("h, MAKEINTATOM(the atom)", h, ATOM_W(a));
    get_a("h, MAKEINTATOM(the atom)", h, ATOM_A(a));
    remove_w("h, MAKEINTATOM(the atom)", h, ATOM_W(a));
    get_w("h, L\"F2KPropsAtom\"", h, L"F2KPropsAtom");

    set_w("h, L\"#291\"", h, L"#291", 0x6666);
    get_w("h, MAKEINTATOM(291)", h, ATOM_W(291));
    remove_w("h, MAKEINTATOM(291)", h, ATOM_W(291));
    set_w("h, MAKEINTATOM(291)", h, ATOM_W(291), 0x7777);
    get_w("h, L\"#291\"", h, L"#291");
    get_a("h, \"#291\"", h, "#291");
    remove_a("h, \"#291\"", h, "#291");
    get_w("h, MAKEINTATOM(291)", h, ATOM_W(291));

    get_w("h, MAKEINTATOM(0xBFFF), nothing set", h, ATOM_W(0xBFFF));
    remove_w("h, MAKEINTATOM(0xBFFF), nothing set", h, ATOM_W(0xBFFF));

    if (a != 0) {
        GlobalDeleteAtom(a);
    }
    end_section(h);
}

/* --- refs ---------------------------------------------------------- */

static void found(const char *when)
{
    ATOM a;

    arm();
    a = GlobalFindAtomW(L"F2KPropsRef");
    line("GlobalFindAtomW(L\"F2KPropsRef\") %s: found %s err=%s", when, yesno(a != 0), le());
}

static void sec_refs(void)
{
    HWND h;
    BOOL destroyed;

    forget_atoms();
    h = make_window();
    found("before SetPropW");
    set_w("h, L\"F2KPropsRef\"", h, L"F2KPropsRef", 1);
    found("after SetPropW");
    set_w("h, L\"F2KPropsRef\"", h, L"F2KPropsRef", 2);
    found("after the second SetPropW");
    remove_w("h, L\"F2KPropsRef\"", h, L"F2KPropsRef");
    found("after RemovePropW");
    forget_atoms();
    found("after its atoms are deleted");
    set_w("h, L\"F2KPropsRef\"", h, L"F2KPropsRef", 3);
    found("after SetPropW");
    arm();
    destroyed = DestroyWindow(h);
    line("DestroyWindow(h), the property still set: ret=%d err=%s", destroyed, le());
    found("after DestroyWindow");
    end_section(NULL);
}

/* --- thread -------------------------------------------------------- */

typedef struct {
    HWND target;
    HANDLE got;
    DWORD got_err;
    BOOL set;
    DWORD set_err;
    HANDLE removed;
    DWORD removed_err;
} thread_job;

static DWORD WINAPI prop_thread(LPVOID param)
{
    thread_job *job = (thread_job *)param;

    arm();
    job->got = GetPropW(job->target, L"F2KPropsShared");
    job->got_err = GetLastError();
    arm();
    job->set = SetPropW(job->target, L"F2KPropsThread", (HANDLE)0x8888);
    job->set_err = GetLastError();
    arm();
    job->removed = RemovePropW(job->target, L"F2KPropsShared");
    job->removed_err = GetLastError();
    return 0;
}

static void sec_thread(void)
{
    HWND h;
    HANDLE t;
    DWORD tid, w;
    thread_job job;

    forget_atoms();
    h = make_window();
    set_w("h, L\"F2KPropsShared\"", h, L"F2KPropsShared", 0x1234);
    ZeroMemory(&job, sizeof job);
    job.target = h;
    t = CreateThread(NULL, 0, prop_thread, &job, 0, &tid);
    w = t != NULL ? WaitForSingleObject(t, WAIT_MS) : WAIT_FAILED;
    line("the second thread ran: %s", wr(w));
    if (w == WAIT_OBJECT_0) {
        line("second thread: GetPropW(h, L\"F2KPropsShared\"): ret=0x%lX err=%s", (DWORD)job.got,
             le_of(job.got_err));
        line("second thread: SetPropW(h, L\"F2KPropsThread\", 0x8888): ret=%d err=%s", job.set,
             le_of(job.set_err));
        line("second thread: RemovePropW(h, L\"F2KPropsShared\"): ret=0x%lX err=%s",
             (DWORD)job.removed, le_of(job.removed_err));
    }
    if (t != NULL) {
        CloseHandle(t);
    }
    get_w("h, L\"F2KPropsThread\"", h, L"F2KPropsThread");
    get_w("h, L\"F2KPropsShared\"", h, L"F2KPropsShared");
    remove_w("h, L\"F2KPropsThread\"", h, L"F2KPropsThread");
    remove_w("h, L\"F2KPropsShared\"", h, L"F2KPropsShared");
    end_section(h);
}

/* --- errors -------------------------------------------------------- */

/* A call with a NULL name, inside __try: 0 = SetPropW, 1 = GetPropW,
 * 2 = RemovePropW. */
static void null_name(HWND h, int which)
{
    static const char *const labels[] = {
        "SetPropW(h, NULL, 0x9999)", "GetPropW(h, NULL)", "RemovePropW(h, NULL)"
    };
    DWORD r = 0;
    int faulted = 0;

    arm();
    __try {
        if (which == 0) {
            r = (DWORD)SetPropW(h, NULL, (HANDLE)0x9999);
        } else if (which == 1) {
            r = (DWORD)GetPropW(h, NULL);
        } else {
            r = (DWORD)RemovePropW(h, NULL);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    if (faulted) {
        line("%s: faulted err=%s", labels[which], le());
    } else {
        line("%s: ret=0x%lX err=%s", labels[which], r, le());
    }
}

static void sec_errors(void)
{
    static WCHAR long_name[301];
    HWND h, dead;
    int i;

    forget_atoms();
    dead = make_window();
    DestroyWindow(dead);
    h = make_window();

    set_w("NULL, L\"F2KPropsOne\"", NULL, L"F2KPropsOne", 1);
    get_w("NULL, L\"F2KPropsOne\"", NULL, L"F2KPropsOne");
    remove_w("NULL, L\"F2KPropsOne\"", NULL, L"F2KPropsOne");
    set_w("a destroyed window, L\"F2KPropsOne\"", dead, L"F2KPropsOne", 1);
    get_w("a destroyed window, L\"F2KPropsOne\"", dead, L"F2KPropsOne");
    remove_w("a destroyed window, L\"F2KPropsOne\"", dead, L"F2KPropsOne");
    get_w("the desktop window, L\"F2KPropsNever\"", GetDesktopWindow(), L"F2KPropsNever");

    get_w("h, L\"F2KPropsNever\", never set", h, L"F2KPropsNever");
    remove_w("h, L\"F2KPropsNever\", never set", h, L"F2KPropsNever");
    get_a("h, \"F2KPropsNever\", never set", h, "F2KPropsNever");

    set_w("h, L\"\"", h, L"", 0xAAAA);
    get_w("h, L\"\"", h, L"");
    remove_w("h, L\"\"", h, L"");

    for (i = 0; i < 300; i++) {
        long_name[i] = (WCHAR)('a' + i % 26);
    }
    long_name[300] = 0;
    set_w("h, a 300-character name", h, long_name, 0xBBBB);
    get_w("h, a 300-character name", h, long_name);
    remove_w("h, a 300-character name", h, long_name);

    null_name(h, 0);
    null_name(h, 1);
    null_name(h, 2);
    end_section(h);
}

/* --- enum ---------------------------------------------------------- */

/* EnumPropsA/W and EnumPropsExA/W, found with GetProcAddress so that
 * the program still loads where user32 lacks them (the other sections
 * run regardless); their callbacks in the MSVC 6 headers' shapes. */
typedef BOOL (CALLBACK *enum_w_cb)(HWND, LPCWSTR, HANDLE);
typedef BOOL (CALLBACK *enum_a_cb)(HWND, LPCSTR, HANDLE);
typedef BOOL (CALLBACK *enum_ex_w_cb)(HWND, LPWSTR, HANDLE, DWORD);
typedef BOOL (CALLBACK *enum_ex_a_cb)(HWND, LPSTR, HANDLE, DWORD);
typedef int (WINAPI *enum_w_fn)(HWND, enum_w_cb);
typedef int (WINAPI *enum_a_fn)(HWND, enum_a_cb);
typedef int (WINAPI *enum_ex_w_fn)(HWND, enum_ex_w_cb, LPARAM);
typedef int (WINAPI *enum_ex_a_fn)(HWND, enum_ex_a_cb, LPARAM);

/* What the callbacks saw: each property's name (one of the section's
 * four by index, or "other") and value, in the order received. */
#define ENUM_MAX 16
static int enum_seen;
static int enum_name[ENUM_MAX];         /* 0..2 the string names, 3 "#291", -1 other */
static DWORD enum_value[ENUM_MAX];
static HWND enum_hwnd_seen;
static DWORD enum_param_seen;
static int enum_stop_after;             /* answer FALSE at this call (1-based), 0 never */
static int enum_remove;                 /* RemovePropW each property it is given */
static BOOL enum_removed_ok;

static const WCHAR *const enum_names_w[] = { L"F2KPropsOne", L"F2KPropsTwo", L"F2KPropsZero" };
static const char *const enum_names_a[] = { "F2KPropsOne", "F2KPropsTwo", "F2KPropsZero" };

static void enum_reset(int stop_after, int remove)
{
    enum_seen = 0;
    enum_hwnd_seen = NULL;
    enum_param_seen = 0;
    enum_stop_after = stop_after;
    enum_remove = remove;
    enum_removed_ok = TRUE;
}

/* Record one call; the name is a string or an integer atom (a high
 * word of zero). */
static BOOL enum_record(HWND h, const WCHAR *wname, const char *aname, HANDLE v)
{
    DWORD n = wname != NULL ? (DWORD)wname : (DWORD)aname;
    int i, which = -1;

    enum_hwnd_seen = h;
    if (HIWORD(n) == 0) {
        which = LOWORD(n) == 291 ? 3 : -1;
    } else {
        for (i = 0; i < 3; i++) {
            if (wname != NULL ? lstrcmpW(wname, enum_names_w[i]) == 0
                              : lstrcmpA(aname, enum_names_a[i]) == 0) {
                which = i;
            }
        }
    }
    if (enum_seen < ENUM_MAX) {
        enum_name[enum_seen] = which;
        enum_value[enum_seen] = (DWORD)v;
    }
    enum_seen++;
    if (enum_remove && wname != NULL
        && RemovePropW(h, HIWORD(n) == 0 ? ATOM_W(LOWORD(n)) : wname) != v) {
        enum_removed_ok = FALSE;
    }
    return enum_stop_after == 0 || enum_seen < enum_stop_after;
}

static BOOL CALLBACK enum_w(HWND h, LPCWSTR name, HANDLE v)
{
    return enum_record(h, name, NULL, v);
}

static BOOL CALLBACK enum_a(HWND h, LPCSTR name, HANDLE v)
{
    return enum_record(h, NULL, name, v);
}

static BOOL CALLBACK enum_ex_w(HWND h, LPWSTR name, HANDLE v, DWORD param)
{
    enum_param_seen = param;
    return enum_record(h, name, NULL, v);
}

static BOOL CALLBACK enum_ex_a(HWND h, LPSTR name, HANDLE v, DWORD param)
{
    enum_param_seen = param;
    return enum_record(h, NULL, name, v);
}

/* The properties received, each by name, in the order received, then
 * whether that order is the order they were set in, its reverse, or
 * neither (the section sets One, Two, Zero, then #291). */
static void enum_report(HWND h, int ret, const char *err)
{
    static const char *const label[] = { "F2KPropsOne", "F2KPropsTwo", "F2KPropsZero", "#291" };
    int i, forward = 1, backward = 1;

    line("  ret=%d err=%s, %d call(s), the window passed is h: %s", ret, err, enum_seen,
         enum_seen == 0 ? "-" : yesno(enum_hwnd_seen == h));
    for (i = 0; i < enum_seen && i < ENUM_MAX; i++) {
        line("  %s = 0x%lX", enum_name[i] < 0 ? "another property" : label[enum_name[i]],
             enum_value[i]);
        if (enum_name[i] != i) {
            forward = 0;
        }
        if (enum_name[i] != enum_seen - 1 - i) {
            backward = 0;
        }
    }
    if (enum_seen > 1) {
        line("  the order: %s", forward ? "as set" : backward ? "the reverse of the order set" : "neither");
    }
}

static void sec_enum(void)
{
    HMODULE user = GetModuleHandleA("user32.dll");
    enum_w_fn ew = (enum_w_fn)GetProcAddress(user, "EnumPropsW");
    enum_a_fn ea = (enum_a_fn)GetProcAddress(user, "EnumPropsA");
    enum_ex_w_fn exw = (enum_ex_w_fn)GetProcAddress(user, "EnumPropsExW");
    enum_ex_a_fn exa = (enum_ex_a_fn)GetProcAddress(user, "EnumPropsExA");
    HWND h, empty, dead;
    int r;

    line("GetProcAddress(user32, EnumPropsW/A, EnumPropsExW/A): %s %s %s %s", yesno(ew != NULL),
         yesno(ea != NULL), yesno(exw != NULL), yesno(exa != NULL));
    if (ew == NULL || ea == NULL || exw == NULL || exa == NULL) {
        return;
    }
    forget_atoms();
    h = make_window();
    empty = make_window();
    dead = make_window();
    DestroyWindow(dead);
    set_w("h, L\"F2KPropsOne\"", h, L"F2KPropsOne", 0x1111);
    set_w("h, L\"F2KPropsTwo\"", h, L"F2KPropsTwo", 0x2222);
    set_w("h, L\"F2KPropsZero\"", h, L"F2KPropsZero", 0);
    set_w("h, MAKEINTATOM(291)", h, ATOM_W(291), 0x3333);

    line("EnumPropsW(h):");
    enum_reset(0, 0);
    arm();
    r = ew(h, enum_w);
    enum_report(h, r, le());
    line("EnumPropsA(h):");
    enum_reset(0, 0);
    arm();
    r = ea(h, enum_a);
    enum_report(h, r, le());
    line("EnumPropsExW(h, lParam 0x5A5A):");
    enum_reset(0, 0);
    arm();
    r = exw(h, enum_ex_w, 0x5A5A);
    enum_report(h, r, le());
    line("  the lParam received: 0x%lX", enum_param_seen);
    line("EnumPropsExA(h, lParam 0xA5A5):");
    enum_reset(0, 0);
    arm();
    r = exa(h, enum_ex_a, 0xA5A5);
    enum_report(h, r, le());
    line("  the lParam received: 0x%lX", enum_param_seen);

    line("EnumPropsW(h), the callback answering FALSE at its first call:");
    enum_reset(1, 0);
    arm();
    r = ew(h, enum_w);
    enum_report(h, r, le());
    line("EnumPropsExW(h), the callback answering FALSE at its second call:");
    enum_reset(2, 0);
    arm();
    r = exw(h, enum_ex_w, 0);
    enum_report(h, r, le());

    line("EnumPropsW(a window with no properties):");
    enum_reset(0, 0);
    arm();
    r = ew(empty, enum_w);
    enum_report(empty, r, le());
    line("EnumPropsExW(a window with no properties):");
    enum_reset(0, 0);
    arm();
    r = exw(empty, enum_ex_w, 0);
    enum_report(empty, r, le());
    line("EnumPropsW(NULL):");
    enum_reset(0, 0);
    arm();
    r = ew(NULL, enum_w);
    enum_report(NULL, r, le());
    line("EnumPropsW(a destroyed window):");
    enum_reset(0, 0);
    arm();
    r = ew(dead, enum_w);
    enum_report(dead, r, le());

    line("EnumPropsExW(h), the callback removing each property it is given:");
    enum_reset(0, 1);
    arm();
    r = exw(h, enum_ex_w, 0);
    enum_report(h, r, le());
    line("  each RemovePropW answered the value given: %s", yesno(enum_removed_ok));
    line("EnumPropsW(h) after:");
    enum_reset(0, 0);
    arm();
    r = ew(h, enum_w);
    enum_report(h, r, le());

    DestroyWindow(empty);
    end_section(h);
}

static const section_t sections[] = {
    { "string", sec_string, F2KT_ALWAYS },
    { "atom", sec_atom, F2KT_ALWAYS },
    { "refs", sec_refs, F2KT_ALWAYS },
    { "thread", sec_thread, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { "enum", sec_enum, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A NULL name goes to the calls: a fault __try does not catch ends
     * the process without a dialog. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("props", sections, argc, argv);
}
