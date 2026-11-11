/*
 * wintree - the window tree in user32: parents and owners (GetParent,
 * GetWindow GW_OWNER), the thread and process a window belongs to
 * (GetWindowThreadProcessId), enumeration (EnumWindows,
 * EnumChildWindows), the z-order (GetTopWindow, BringWindowToTop) and
 * an owner's last active pop-up (GetLastActivePopup).
 *
 * Every window is the program's own, of its class F2KWintree (a
 * procedure handing everything to DefWindowProcW), created at explicit
 * coordinates; all are hidden but for `popup`'s, which activates them.
 * A window prints by its label (top, popup, child...), never by its
 * handle: "NULL", "the desktop", or "another window" for one the
 * program did not make. Thread and process ids print only as
 * relations to the program's own. Enumeration goes over every window
 * on the desktop, so the callbacks keep only the program's own windows
 * and print their order: the other windows, the console's and the
 * shell's among them, never show. GetTopWindow(NULL), the desktop's top
 * window, is another program's and is not called.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel, and its line
 * prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   parent  GetParent and GetWindow(GW_OWNER) of an unowned top-level
 *           window, an owned pop-up, an owned overlapped window, a
 *           child and a grandchild; the owned pop-up with WS_POPUP
 *           taken off its style and put back; the desktop, NULL and a
 *           destroyed window
 *   ids     GetWindowThreadProcessId of the program's own window (with
 *           and without the process id's pointer), of a second
 *           thread's window, of the desktop window, and of NULL and a
 *           destroyed window (the process id left or not)
 *   enum    EnumWindows: the program's windows in the order it gives
 *           them (unowned pop-ups, an owned one, children left out),
 *           the lParam passed through, and a callback stopping at the
 *           second; EnumChildWindows of a parent with children and a
 *           grandchild, of a child, of a window with none, of NULL,
 *           stopped early, and of a destroyed window
 *   zorder  GetTopWindow of a parent of three children, after
 *           BringWindowToTop of each, of a window with no children and
 *           of a destroyed window; BringWindowToTop of three top-level
 *           pop-ups and their order through EnumWindows; of NULL and a
 *           destroyed window
 *   popup   GetLastActivePopup of a shown owner as two owned pop-ups
 *           are shown and activated, the owner activated again, a
 *           pop-up hidden, and each destroyed; of a pop-up itself, of
 *           an unowned window, of NULL. The section asks for the
 *           foreground first and prints whether it got it
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat wintree):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wintree.c user32.lib
 */

#include "../common/f2kt.h"

/* The program's windows by label. */
#define MAX_KNOWN 16

static HWND known[MAX_KNOWN];
static const char *known_label[MAX_KNOWN];
static int known_count;

static void forget_all(void)
{
    known_count = 0;
}

static void know(HWND h, const char *label)
{
    if (h != NULL && known_count < MAX_KNOWN) {
        known[known_count] = h;
        known_label[known_count] = label;
        known_count++;
    }
}

/* The desktop window, asked for at each section's start. */
static HWND desktop;

/* A window as printed. Calls no API. */
static const char *label(HWND h)
{
    int i;

    if (h == NULL) {
        return "NULL";
    }
    if (h == desktop) {
        return "the desktop";
    }
    for (i = 0; i < known_count; i++) {
        if (known[i] == h) {
            return known_label[i];
        }
    }
    return "another window";
}

static int is_known(HWND h)
{
    int i;

    for (i = 0; i < known_count; i++) {
        if (known[i] == h) {
            return 1;
        }
    }
    return 0;
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void register_class(void)
{
    static BOOL registered;
    WNDCLASSW wc;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = wndproc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"F2KWintree";
        registered = RegisterClassW(&wc) != 0;
    }
}

/* A window of the class, known by `name`; its creation prints only
 * when it fails. */
static HWND make(const char *name, DWORD style, HWND parent, int x, int y, int w, int h)
{
    HWND r;

    register_class();
    r = CreateWindowExW(0, L"F2KWintree", L"wintree", style, x, y, w, h, parent, NULL,
                        GetModuleHandleA(NULL), NULL);
    if (r == NULL) {
        line("setup: CreateWindowExW(%s) failed, err=%lu", name, GetLastError());
    }
    know(r, name);
    return r;
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

/* A window made and destroyed again: its handle names no window. */
static HWND make_dead(void)
{
    HWND h = make("a destroyed window", WS_POPUP, NULL, 0, 0, 10, 10);

    if (h != NULL) {
        DestroyWindow(h);
    }
    return h;
}

static void start(void)
{
    desktop = GetDesktopWindow();
    forget_all();
    drain();
}

/* Destroy the program's windows, the owners and parents last. */
static void finish(void)
{
    int i;

    for (i = known_count - 1; i >= 0; i--) {
        if (IsWindow(known[i])) {
            DestroyWindow(known[i]);
        }
    }
    drain();
    forget_all();
}

/* --- parent -------------------------------------------------------- */

static void parent_of(HWND h)
{
    HWND p, o;
    DWORD ep, eo;

    arm();
    p = GetParent(h);
    ep = GetLastError();
    arm();
    o = GetWindow(h, GW_OWNER);
    eo = GetLastError();
    line("%s: GetParent=%s err=%s, GetWindow(GW_OWNER)=%s err=%s", label(h), label(p), le_of(ep),
         label(o), le_of(eo));
}

static void sec_parent(void)
{
    HWND top, popup, ownedov, child, grand, dead;
    LONG style;

    start();
    top = make("top", WS_OVERLAPPED | WS_CAPTION, NULL, 0, 0, 320, 200);
    popup = make("popup (owned by top)", WS_POPUP, top, 10, 10, 100, 100);
    ownedov = make("overlapped (owned by top)", WS_OVERLAPPED | WS_CAPTION, top, 20, 20, 100, 100);
    child = make("child (of top)", WS_CHILD, top, 0, 0, 100, 100);
    grand = make("grandchild (of child)", WS_CHILD, child, 0, 0, 50, 50);
    dead = make_dead();

    parent_of(top);
    parent_of(popup);
    parent_of(ownedov);
    parent_of(child);
    parent_of(grand);

    style = GetWindowLongW(popup, GWL_STYLE);
    SetWindowLongW(popup, GWL_STYLE, (style & ~WS_POPUP) | WS_CAPTION);
    line("popup's style set to WS_CAPTION without WS_POPUP: WS_POPUP %s",
         yesno((GetWindowLongW(popup, GWL_STYLE) & WS_POPUP) != 0));
    parent_of(popup);
    SetWindowLongW(popup, GWL_STYLE, style);
    line("popup's style put back: WS_POPUP %s",
         yesno((GetWindowLongW(popup, GWL_STYLE) & WS_POPUP) != 0));
    parent_of(popup);

    parent_of(desktop);
    parent_of(NULL);
    parent_of(dead);
    finish();
}

/* --- ids ----------------------------------------------------------- */

typedef struct {
    HANDLE ready;
    HANDLE done;
    HWND window;
} thread_window;

static DWORD WINAPI window_thread(LPVOID param)
{
    thread_window *tw = (thread_window *)param;

    register_class();
    tw->window = CreateWindowExW(0, L"F2KWintree", L"wintree thread", WS_POPUP, 0, 0, 50, 50,
                                 NULL, NULL, GetModuleHandleA(NULL), NULL);
    SetEvent(tw->ready);
    WaitForSingleObject(tw->done, WAIT_MS);
    if (tw->window != NULL) {
        DestroyWindow(tw->window);
    }
    return 0;
}

/* The pid sentinel: no process has this id. */
#define PID_UNSET 0xF2F2F2F2u

static void ids_of(HWND h, DWORD thread_expected)
{
    DWORD tid, pid = PID_UNSET;
    const char *e;

    arm();
    tid = GetWindowThreadProcessId(h, &pid);
    e = le();
    line("GetWindowThreadProcessId(%s, &pid): err=%s, thread id nonzero %s, the expected thread "
         "%s, this thread %s; pid set %s, this process %s",
         label(h), e, yesno(tid != 0), yesno(tid == thread_expected),
         yesno(tid == GetCurrentThreadId()), yesno(pid != PID_UNSET),
         yesno(pid == GetCurrentProcessId()));
}

static void sec_ids(void)
{
    HWND own, dead;
    DWORD tid, worker_tid = 0;
    thread_window tw;
    HANDLE t;
    DWORD w;

    start();
    own = make("own", WS_POPUP, NULL, 0, 0, 100, 100);
    dead = make_dead();

    ids_of(own, GetCurrentThreadId());
    arm();
    tid = GetWindowThreadProcessId(own, NULL);
    line("GetWindowThreadProcessId(own, NULL): err=%s, this thread %s", le(),
         yesno(tid == GetCurrentThreadId()));

    tw.ready = CreateEventA(NULL, TRUE, FALSE, NULL);
    tw.done = CreateEventA(NULL, TRUE, FALSE, NULL);
    tw.window = NULL;
    t = CreateThread(NULL, 0, window_thread, &tw, 0, &worker_tid);
    w = t != NULL ? WaitForSingleObject(tw.ready, WAIT_MS) : WAIT_FAILED;
    line("the second thread made its window: %s, %s", wr(w), yesno(tw.window != NULL));
    know(tw.window, "the second thread's window");
    if (w == WAIT_OBJECT_0 && tw.window != NULL) {
        ids_of(tw.window, worker_tid);
    }
    SetEvent(tw.done);
    if (t != NULL) {
        line("the second thread ended: %s", wr(WaitForSingleObject(t, WAIT_MS)));
        CloseHandle(t);
    }
    CloseHandle(tw.ready);
    CloseHandle(tw.done);

    ids_of(desktop, 0);
    ids_of(NULL, 0);
    ids_of(dead, 0);
    finish();
}

/* --- enum ---------------------------------------------------------- */

#define MAX_SEEN 32

typedef struct {
    LPARAM magic;
    int lparam_ok;
    int stop_after;     /* 0: never stop */
    int seen_count;
    HWND seen[MAX_SEEN];
} enum_state;

/* Keep the program's own windows only, in the order given. */
static BOOL CALLBACK enum_cb(HWND h, LPARAM lparam)
{
    enum_state *st = (enum_state *)lparam;

    if (st->magic != 0x0F2C0DE5) {
        return FALSE;
    }
    st->lparam_ok = 1;
    if (is_known(h) && st->seen_count < MAX_SEEN) {
        st->seen[st->seen_count++] = h;
        if (st->stop_after != 0 && st->seen_count >= st->stop_after) {
            return FALSE;
        }
    }
    return TRUE;
}

static void init_state(enum_state *st, int stop_after)
{
    ZeroMemory(st, sizeof *st);
    st->magic = 0x0F2C0DE5;
    st->stop_after = stop_after;
}

/* The program's windows seen, in order, as one line's tail. */
static const char *order(const enum_state *st)
{
    static char buf[512];
    int n = 0;
    int i;

    buf[0] = '\0';
    for (i = 0; i < st->seen_count && n < (int)sizeof buf - 64; i++) {
        n += sprintf(buf + n, "%s%s", i == 0 ? "" : ", ", label(st->seen[i]));
    }
    if (st->seen_count == 0) {
        sprintf(buf, "none");
    }
    return buf;
}

static void enum_windows(const char *what, int stop_after)
{
    enum_state st;
    BOOL r;

    init_state(&st, stop_after);
    arm();
    r = EnumWindows(enum_cb, (LPARAM)&st);
    line("EnumWindows%s: ret=%d err=%s, lParam passed %s; ours in order: %s", what, r, le(),
         yesno(st.lparam_ok), order(&st));
}

static void enum_children(HWND parent, const char *what, int stop_after)
{
    enum_state st;
    BOOL r;

    init_state(&st, stop_after);
    arm();
    r = EnumChildWindows(parent, enum_cb, (LPARAM)&st);
    line("EnumChildWindows(%s)%s: ret=%d err=%s, lParam passed %s; ours in order: %s",
         label(parent), what, r, le(), yesno(st.lparam_ok), order(&st));
}

static void sec_enum(void)
{
    HWND a, b, c, d, a1, a2, a1a, dead;

    start();
    a = make("A", WS_POPUP, NULL, 0, 0, 200, 200);
    b = make("B", WS_POPUP, NULL, 10, 10, 200, 200);
    c = make("C", WS_POPUP, NULL, 20, 20, 200, 200);
    d = make("D (owned by A)", WS_POPUP, a, 30, 30, 100, 100);
    a1 = make("A1 (child of A)", WS_CHILD, a, 0, 0, 100, 100);
    a2 = make("A2 (child of A)", WS_CHILD, a, 100, 0, 100, 100);
    a1a = make("A1a (child of A1)", WS_CHILD, a1, 0, 0, 50, 50);
    dead = make_dead();
    (void)b;
    (void)c;
    (void)d;
    (void)a2;

    enum_windows("", 0);
    enum_windows(", the callback stopping at our second", 2);
    enum_children(a, "", 0);
    enum_children(a1, "", 0);
    enum_children(a1a, ", no children", 0);
    enum_children(b, ", no children", 0);
    enum_children(a, ", the callback stopping at our first", 1);
    enum_children(NULL, "", 0);
    enum_children(dead, "", 0);
    finish();
}

/* --- zorder -------------------------------------------------------- */

static void top_of(HWND h)
{
    HWND r;

    arm();
    r = GetTopWindow(h);
    line("GetTopWindow(%s): %s err=%s", label(h), label(r), le());
}

static void bring(HWND h)
{
    BOOL r;

    arm();
    r = BringWindowToTop(h);
    line("BringWindowToTop(%s): ret=%d err=%s", label(h), r, le());
}

static void sec_zorder(void)
{
    HWND p, k1, k2, k3, t1, t2, t3, dead;

    start();
    p = make("P", WS_POPUP, NULL, 0, 0, 300, 300);
    k1 = make("K1 (child of P)", WS_CHILD, p, 0, 0, 100, 100);
    k2 = make("K2 (child of P)", WS_CHILD, p, 50, 50, 100, 100);
    k3 = make("K3 (child of P)", WS_CHILD, p, 100, 100, 100, 100);
    t1 = make("T1", WS_POPUP, NULL, 10, 10, 100, 100);
    t2 = make("T2", WS_POPUP, NULL, 20, 20, 100, 100);
    t3 = make("T3", WS_POPUP, NULL, 30, 30, 100, 100);
    dead = make_dead();

    top_of(p);
    enum_children(p, "", 0);
    bring(k1);
    top_of(p);
    enum_children(p, "", 0);
    bring(k3);
    top_of(p);
    enum_children(p, "", 0);
    bring(k2);
    top_of(p);
    enum_children(p, "", 0);
    top_of(k1);

    enum_windows("", 0);
    bring(t1);
    enum_windows("", 0);
    bring(t3);
    enum_windows("", 0);
    bring(t2);
    enum_windows("", 0);

    bring(NULL);
    top_of(dead);
    bring(dead);
    finish();
}

/* --- popup --------------------------------------------------------- */

static void last_popup(HWND h)
{
    HWND r;
    const char *e;

    arm();
    r = GetLastActivePopup(h);
    e = le();
    line("GetLastActivePopup(%s): %s err=%s; the active window: %s", label(h), label(r), e,
         label(GetActiveWindow()));
}

static void sec_popup(void)
{
    HWND owner, p1, p2, lone;

    start();
    owner = make("owner", WS_OVERLAPPEDWINDOW, NULL, 40, 40, 320, 240);
    lone = make("lone", WS_POPUP, NULL, 0, 0, 50, 50);
    ShowWindow(owner, SW_SHOW);
    SetForegroundWindow(owner);
    drain();
    line("SetForegroundWindow(owner): owner is the foreground: %s",
         yesno(GetForegroundWindow() == owner));

    last_popup(owner);
    p1 = make("P1 (owned by owner)", WS_POPUP | WS_CAPTION, owner, 60, 60, 200, 120);
    last_popup(owner);
    ShowWindow(p1, SW_SHOW);
    drain();
    line("P1 shown");
    last_popup(owner);
    p2 = make("P2 (owned by owner)", WS_POPUP | WS_CAPTION, owner, 80, 80, 200, 120);
    ShowWindow(p2, SW_SHOW);
    drain();
    line("P2 shown");
    last_popup(owner);
    last_popup(p1);
    last_popup(p2);

    SetActiveWindow(owner);
    drain();
    line("SetActiveWindow(owner)");
    last_popup(owner);
    SetActiveWindow(p1);
    drain();
    line("SetActiveWindow(P1)");
    last_popup(owner);
    ShowWindow(p1, SW_HIDE);
    drain();
    line("P1 hidden");
    last_popup(owner);
    ShowWindow(p1, SW_SHOW);
    SetActiveWindow(p1);
    drain();
    line("P1 shown and active again");
    last_popup(owner);
    DestroyWindow(p1);
    drain();
    line("P1 destroyed");
    known_label[2] = "the destroyed P1";
    last_popup(owner);
    DestroyWindow(p2);
    drain();
    line("P2 destroyed");
    known_label[3] = "the destroyed P2";
    last_popup(owner);

    last_popup(lone);
    last_popup(NULL);
    finish();
}

static const section_t sections[] = {
    { "parent", sec_parent, F2KT_ALWAYS },
    { "ids", sec_ids, F2KT_ALWAYS },
    { "enum", sec_enum, F2KT_ALWAYS },
    { "zorder", sec_zorder, F2KT_ALWAYS },
    { "popup", sec_popup, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* NULL and destroyed windows go to the calls: should one fault, no
     * dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("wintree", sections, argc, argv);
}
