/*
 * shell - the shell-integration half of user32 that explorer and
 * taskmgr import: the shell, progman and taskman windows, the shell
 * hook window, Alt+Tab information, EndTask, PaintDesktop,
 * DrawCaptionTempA/W, CascadeWindows and TileWindows, hot keys,
 * SwitchToThisWindow and SendMessageCallbackA/W.
 *
 * Every export observed here is resolved through GetProcAddress (the
 * MSVC 6-era user32.lib predates most of them, and several are
 * undocumented): a missing one prints "<Name>: absent" and its section
 * goes on without it.
 *
 * No handle value, process id or address is printed: only whether a
 * handle came back, how two compare, and whose process a window is.
 * Positions print relative to the fixture's own parent window's client
 * area, whose size is fixed; with the standard scheme they are the same
 * on any machine.
 *
 * The environment: on the capture machine explorer runs and holds the
 * shell, progman and taskman windows, so `windows` prints them as found
 * and as another process's, and `setshell` prints SetShellWindow and
 * SetShellWindowEx refused (Windows 2000 refuses both while a shell
 * window exists). SetProgmanWindow and SetTaskmanWindow are not called:
 * Windows 2000 sets them unchecked, and the call would take them from
 * explorer.
 *
 * Nothing touches a window the fixture did not make: CascadeWindows and
 * TileWindows arrange only the fixture's own children inside its own
 * parent (never with a NULL parent, which would arrange the desktop's
 * windows), and EndTask ends only a child process the fixture starts
 * (this program run as `shell.exe --endkid`), whose one hidden window it
 * finds by its class and title.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   windows    GetShellWindow, GetProgmanWindow, GetTaskmanWindow:
 *              found or not, each a window, its class name (A and W),
 *              whether it is this process's, the progman window against
 *              the shell window
 *   setshell   SetShellWindow and SetShellWindowEx of the fixture's own
 *              hidden popup while explorer holds the shell window: the
 *              return and error, and GetShellWindow unchanged
 *   shellhook  RegisterWindowMessageA("SHELLHOOK"), RegisterShellHook-
 *              Window of the fixture's hidden window, twice, and
 *              DeregisterShellHookWindow twice; a destroyed window's
 *   alttab     GetAltTabInfo, GetAltTabInfoA and GetAltTabInfoW with no
 *              Alt+Tab window up: of NULL and of the fixture's window,
 *              a wrong cbSize; the return and error
 *   endtask    a child process (shell.exe --endkid) makes a hidden
 *              window and waits; EndTask(it, FALSE, TRUE): the return,
 *              whether the child ended in time, whether its exit code is
 *              the one its own message loop returns, and the messages
 *              the child's window received (printed by the child)
 *   paintdesk  PaintDesktop into a memory DC and into the fixture's own
 *              window's DC: the return only (the wallpaper and the
 *              desktop colour are the machine's)
 *   caption    DrawCaptionTempA and W into a 32-bit DIB section filled
 *              with a colour no scheme uses, active and inactive, with
 *              text: the return, whether any and every pixel changed,
 *              whether more than one colour was drawn
 *   arrange    CascadeWindows and TileWindows (vertical, horizontal)
 *              over four captioned children of the fixture's own shown
 *              400x300 popup, all of them, one disabled with
 *              MDITILE_SKIPDISABLED, one hidden, and within a rectangle:
 *              the count arranged and each child's rectangle in the
 *              parent's client coordinates
 *   hotkey     RegisterHotKey of Ctrl+Alt+Shift+F23 on the fixture's
 *              window, the same id with another key, the same chord
 *              under another id, a thread hot key (NULL window), a
 *              destroyed window; UnregisterHotKey of each, again, and
 *              whether any WM_HOTKEY came (no key is pressed)
 *   switchto   SwitchToThisWindow of the fixture's own shown window,
 *              with fAltTab TRUE and FALSE: whether it became the
 *              foreground window (takes the foreground: leave the
 *              desktop alone while it runs)
 *   callback   SendMessageCallbackA and W to a window of this thread
 *              (the order of the procedure, the callback and the
 *              return) and of another thread (the callback not called
 *              before the sender retrieves messages, then once): the
 *              callback's window, message, data and result against the
 *              send's; and to a destroyed window
 *
 * `arrange` and `switchto` show the fixture's own windows; `switchto`
 * takes the foreground, so run it with the desktop left alone.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat shell):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% shell.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 SDK headers lack these (winuser.h for WINVER 0x0500). */
#define MDITILE_VERTICAL_ 0x0000
#define MDITILE_HORIZONTAL_ 0x0001
#define MDITILE_SKIPDISABLED_ 0x0002
#define DC_ACTIVE_ 0x0001
#define DC_TEXT_ 0x0008
#define MOD_ALT_ 0x0001
#define MOD_CONTROL_ 0x0002
#define MOD_SHIFT_ 0x0004
#define VK_F23_ 0x86
#define VK_F22_ 0x85
#define VK_F21_ 0x84

typedef struct {
    DWORD cbSize;
    int cItems;
    int cColumns;
    int cRows;
    int iColFocus;
    int iRowFocus;
    int cxItem;
    int cyItem;
    POINT ptStart;
} alttabinfo_t;

typedef HWND (WINAPI *get_window_t)(void);
typedef BOOL (WINAPI *set_shell_t)(HWND);
typedef BOOL (WINAPI *set_shell_ex_t)(HWND, HWND);
typedef BOOL (WINAPI *hook_window_t)(HWND);
typedef BOOL (WINAPI *alt_tab_a_t)(HWND, int, alttabinfo_t *, LPSTR, UINT);
typedef BOOL (WINAPI *alt_tab_w_t)(HWND, int, alttabinfo_t *, LPWSTR, UINT);
typedef BOOL (WINAPI *end_task_t)(HWND, BOOL, BOOL);
typedef BOOL (WINAPI *paint_desktop_t)(HDC);
typedef BOOL (WINAPI *caption_a_t)(HWND, HDC, const RECT *, HFONT, HICON, LPCSTR, UINT);
typedef BOOL (WINAPI *caption_w_t)(HWND, HDC, const RECT *, HFONT, HICON, LPCWSTR, UINT);
typedef WORD (WINAPI *arrange_t)(HWND, UINT, const RECT *, UINT, const HWND *);
typedef BOOL (WINAPI *reg_hotkey_t)(HWND, int, UINT, UINT);
typedef BOOL (WINAPI *unreg_hotkey_t)(HWND, int);
typedef void (WINAPI *switch_to_t)(HWND, BOOL);
typedef void (CALLBACK *sendasync_t)(HWND, UINT, DWORD, LRESULT);
typedef BOOL (WINAPI *send_cb_t)(HWND, UINT, WPARAM, LPARAM, sendasync_t, DWORD);

/* user32's export, or NULL (printed as absent). */
static FARPROC resolve(const char *name)
{
    FARPROC p = GetProcAddress(GetModuleHandleA("user32.dll"), name);

    if (p == NULL) {
        line("%s: absent", name);
    }
    return p;
}

static void drain(void)
{
    MSG m;

    /* A WM_PAINT comes back until its window is validated: validate it, or the
     * loop never ends once a shown window needs painting. */
    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
        if (m.message == WM_PAINT) {
            ValidateRect(m.hwnd, NULL);
        }
    }
}

static LRESULT CALLBACK plain_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void register_plain(void)
{
    WNDCLASSA wc;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = plain_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "F2KShell";
    RegisterClassA(&wc);
}

/* A hidden popup of the fixture's own. */
static HWND hidden_popup(void)
{
    register_plain();
    return CreateWindowExA(0, "F2KShell", "F2K shell", WS_POPUP, 0, 0, 200, 100, NULL, NULL,
                           GetModuleHandleA(NULL), NULL);
}

/* --- windows ------------------------------------------------------- */

static void describe(const char *what, HWND h)
{
    char a[64];
    WCHAR w[64];
    DWORD pid = 0;
    int n;

    line("%s: non-NULL %s err=%s", what, yesno(h != NULL), le());
    if (h == NULL) {
        return;
    }
    line("  IsWindow: %s", yesno(IsWindow(h)));
    arm();
    n = GetClassNameA(h, a, sizeof a);
    line("  GetClassNameA: ret=%d \"%s\" err=%s", n, n > 0 ? a : "", le());
    arm();
    n = GetClassNameW(h, w, sizeof w / sizeof w[0]);
    line("  GetClassNameW: ret=%d \"%s\" err=%s", n, n > 0 ? ws(w) : "", le());
    GetWindowThreadProcessId(h, &pid);
    line("  this process's: %s", yesno(pid == GetCurrentProcessId()));
}

static void sec_windows(void)
{
    get_window_t shell = (get_window_t)resolve("GetShellWindow");
    get_window_t progman = (get_window_t)resolve("GetProgmanWindow");
    get_window_t taskman = (get_window_t)resolve("GetTaskmanWindow");
    HWND s = NULL, p = NULL, t = NULL;

    if (shell != NULL) {
        arm();
        s = shell();
        describe("GetShellWindow", s);
    }
    if (progman != NULL) {
        arm();
        p = progman();
        describe("GetProgmanWindow", p);
    }
    if (taskman != NULL) {
        arm();
        t = taskman();
        describe("GetTaskmanWindow", t);
    }
    if (shell != NULL && progman != NULL) {
        line("the progman window is the shell window: %s", yesno(p == s));
    }
    if (shell != NULL && taskman != NULL) {
        line("the taskman window is the shell window: %s", yesno(t == s));
    }
    if (shell != NULL) {
        line("the shell window is the desktop window: %s", yesno(s == GetDesktopWindow()));
    }
}

/* --- setshell ------------------------------------------------------ */

static void sec_setshell(void)
{
    get_window_t shell = (get_window_t)resolve("GetShellWindow");
    set_shell_t set = (set_shell_t)resolve("SetShellWindow");
    set_shell_ex_t set_ex = (set_shell_ex_t)resolve("SetShellWindowEx");
    HWND before = NULL, h;
    BOOL r;

    if (shell == NULL) {
        return;
    }
    before = shell();
    line("a shell window held: %s", yesno(before != NULL));
    if (before == NULL) {
        /* Never take an empty shell slot: the machine would keep it. */
        line("no shell window: SetShellWindow not called");
        return;
    }
    h = hidden_popup();
    line("the fixture's hidden popup: non-NULL %s", yesno(h != NULL));
    if (set != NULL) {
        arm();
        r = set(h);
        line("SetShellWindow(the popup): ret=%d err=%s", r, le());
        line("  GetShellWindow unchanged: %s", yesno(shell() == before));
    }
    if (set_ex != NULL) {
        arm();
        r = set_ex(h, h);
        line("SetShellWindowEx(the popup, the popup): ret=%d err=%s", r, le());
        line("  GetShellWindow unchanged: %s", yesno(shell() == before));
    }
    DestroyWindow(h);
    line("GetShellWindow after the popup's destruction unchanged: %s", yesno(shell() == before));
}

/* --- shellhook ----------------------------------------------------- */

static void sec_shellhook(void)
{
    hook_window_t reg = (hook_window_t)resolve("RegisterShellHookWindow");
    hook_window_t dereg = (hook_window_t)resolve("DeregisterShellHookWindow");
    UINT m;
    HWND h, dead;

    arm();
    m = RegisterWindowMessageA("SHELLHOOK");
    line("RegisterWindowMessageA(SHELLHOOK): in 0xC000..0xFFFF %s err=%s",
         yesno(m >= 0xC000 && m <= 0xFFFF), le());
    h = hidden_popup();
    if (reg != NULL) {
        arm();
        line("RegisterShellHookWindow(the popup): ret=%d err=%s", reg(h), le());
        arm();
        line("RegisterShellHookWindow(the popup) again: ret=%d err=%s", reg(h), le());
    }
    if (dereg != NULL) {
        arm();
        line("DeregisterShellHookWindow(the popup): ret=%d err=%s", dereg(h), le());
        arm();
        line("DeregisterShellHookWindow(the popup) again: ret=%d err=%s", dereg(h), le());
    }
    dead = hidden_popup();
    DestroyWindow(dead);
    if (reg != NULL) {
        arm();
        line("RegisterShellHookWindow(a destroyed window): ret=%d err=%s", reg(dead), le());
    }
    if (dereg != NULL) {
        arm();
        line("DeregisterShellHookWindow(a destroyed window): ret=%d err=%s", dereg(dead), le());
    }
    DestroyWindow(h);
    drain();
}

/* --- alttab -------------------------------------------------------- */

static void alttab_case(alt_tab_a_t fa, alt_tab_w_t fw, const char *name, HWND h, const char *hname,
                        DWORD size)
{
    alttabinfo_t ati;
    char a[64];
    WCHAR w[64];
    BOOL r;

    memset(&ati, 0, sizeof ati);
    ati.cbSize = size;
    arm();
    if (fa != NULL) {
        r = fa(h, -1, &ati, a, sizeof a);
    } else {
        r = fw(h, -1, &ati, w, 64);
    }
    line("%s(%s, -1, cbSize %lu): ret=%d err=%s", name, hname, size, r, le());
}

static void sec_alttab(void)
{
    alt_tab_a_t plain = (alt_tab_a_t)resolve("GetAltTabInfo");
    alt_tab_a_t fa = (alt_tab_a_t)resolve("GetAltTabInfoA");
    alt_tab_w_t fw = (alt_tab_w_t)resolve("GetAltTabInfoW");
    HWND h = hidden_popup();

    if (plain != NULL) {
        alttab_case(plain, NULL, "GetAltTabInfo", NULL, "NULL", sizeof(alttabinfo_t));
        alttab_case(plain, NULL, "GetAltTabInfo", h, "the popup", sizeof(alttabinfo_t));
    }
    if (fa != NULL) {
        alttab_case(fa, NULL, "GetAltTabInfoA", NULL, "NULL", sizeof(alttabinfo_t));
        alttab_case(fa, NULL, "GetAltTabInfoA", h, "the popup", sizeof(alttabinfo_t));
        alttab_case(fa, NULL, "GetAltTabInfoA", NULL, "NULL", 0);
    }
    if (fw != NULL) {
        alttab_case(NULL, fw, "GetAltTabInfoW", NULL, "NULL", sizeof(alttabinfo_t));
        alttab_case(NULL, fw, "GetAltTabInfoW", h, "the popup", sizeof(alttabinfo_t));
        alttab_case(NULL, fw, "GetAltTabInfoW", NULL, "NULL", 0);
    }
    DestroyWindow(h);
}

/* --- endtask ------------------------------------------------------- */

#define KID_EXIT 7
#define KID_EVENT "F2KShellKidReady"
#define KID_CLASS "F2KShellKid"
#define KID_TITLE "F2K shell kid"

static const char *msg_name(UINT m)
{
    switch (m) {
    case WM_QUERYENDSESSION: return "WM_QUERYENDSESSION";
    case WM_ENDSESSION: return "WM_ENDSESSION";
    case WM_CLOSE: return "WM_CLOSE";
    case WM_DESTROY: return "WM_DESTROY";
    case WM_SYSCOMMAND: return "WM_SYSCOMMAND";
    }
    return NULL;
}

static LRESULT CALLBACK kid_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    const char *n = msg_name(msg);

    if (n != NULL) {
        if (msg == WM_SYSCOMMAND) {
            line("  the child's window received %s 0x%04X", n, (unsigned)(wParam & 0xFFF0));
        } else {
            line("  the child's window received %s", n);
        }
    }
    if (msg == WM_DESTROY) {
        PostQuitMessage(KID_EXIT);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* The child: one hidden top-level window, its message loop, the quit
 * code its exit code. Prints only what its window receives. */
static int endkid(void)
{
    WNDCLASSA wc;
    HWND h;
    HANDLE ready;
    MSG m;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = kid_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = KID_CLASS;
    RegisterClassA(&wc);
    h = CreateWindowExA(0, KID_CLASS, KID_TITLE, WS_OVERLAPPEDWINDOW, 0, 0, 200, 100, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    if (h == NULL) {
        return 3;
    }
    ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, KID_EVENT);
    if (ready != NULL) {
        SetEvent(ready);
        CloseHandle(ready);
    }
    /* Ten seconds at most, so a missed end never leaves it behind. */
    SetTimer(h, 1, 10000, NULL);
    while (GetMessageA(&m, NULL, 0, 0) > 0) {
        if (m.message == WM_TIMER) {
            DestroyWindow(h);
            continue;
        }
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    return (int)m.wParam;
}

static void sec_endtask(void)
{
    end_task_t end_task = (end_task_t)resolve("EndTask");
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH + 32];
    char self[MAX_PATH];
    HANDLE ready;
    HWND kid;
    DWORD pid = 0, w, code = 0;
    BOOL r;
    DWORD e;

    if (end_task == NULL) {
        return;
    }
    GetModuleFileNameA(NULL, self, sizeof self);
    sprintf(cmd, "\"%s\" --endkid", self);
    ready = CreateEventA(NULL, TRUE, FALSE, KID_EVENT);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        line("CreateProcessA(shell.exe --endkid): failed err=%lu", GetLastError());
        CloseHandle(ready);
        return;
    }
    line("the child started: yes");
    w = WaitForSingleObject(ready, WAIT_MS);
    line("the child's window made: %s", yesno(w == WAIT_OBJECT_0));
    kid = FindWindowA(KID_CLASS, KID_TITLE);
    if (kid != NULL) {
        GetWindowThreadProcessId(kid, &pid);
    }
    line("FindWindowA(its class, its title): the child's window %s",
         yesno(kid != NULL && pid == pi.dwProcessId));
    if (kid == NULL || pid != pi.dwProcessId) {
        TerminateProcess(pi.hProcess, 1);
    } else {
        /* Nothing prints between EndTask and the child's end: the
         * child's lines come first, then these. */
        arm();
        r = end_task(kid, FALSE, TRUE);
        e = GetLastError();
        w = WaitForSingleObject(pi.hProcess, 15000);
        line("EndTask(the child's window, FALSE, TRUE): ret=%d err=%s", r, le_of(e));
        line("the child ended within 15 s: %s", yesno(w == WAIT_OBJECT_0));
        if (w != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, WAIT_MS);
        } else {
            GetExitCodeProcess(pi.hProcess, &code);
            line("its exit code its message loop's (%d): %s", KID_EXIT, yesno(code == KID_EXIT));
        }
        line("IsWindow(the child's window) after: %s", yesno(IsWindow(kid)));
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(ready);
}

/* --- paintdesk ----------------------------------------------------- */

static void sec_paintdesk(void)
{
    paint_desktop_t paint = (paint_desktop_t)resolve("PaintDesktop");
    HDC screen, mem, wdc;
    HBITMAP bmp, old;
    HWND h;

    if (paint == NULL) {
        return;
    }
    screen = GetDC(NULL);
    mem = CreateCompatibleDC(screen);
    bmp = CreateCompatibleBitmap(screen, 64, 64);
    old = (HBITMAP)SelectObject(mem, bmp);
    arm();
    line("PaintDesktop(a memory DC): ret=%d err=%s", paint(mem), le());
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, screen);

    h = hidden_popup();
    wdc = GetDC(h);
    arm();
    line("PaintDesktop(the hidden popup's DC): ret=%d err=%s", paint(wdc), le());
    ReleaseDC(h, wdc);
    DestroyWindow(h);
    arm();
    line("PaintDesktop(NULL): ret=%d err=%s", paint(NULL), le());
}

/* --- caption ------------------------------------------------------- */

#define CAP_W 200
#define CAP_H 24
#define SENTINEL 0x00123457u

static void caption_case(caption_a_t fa, caption_w_t fw, HWND h, UINT flags, const char *what)
{
    BITMAPINFO bi;
    DWORD *bits = NULL;
    HBITMAP dib, old;
    HDC dc;
    RECT rc;
    BOOL r;
    int i, changed = 0, distinct = 0;
    DWORD first = 0;
    static const WCHAR wtext[] = { 'F', '2', 'K', ' ', 'c', 'a', 'p', 't', 'i', 'o', 'n', 0 };

    ZeroMemory(&bi, sizeof bi);
    bi.bmiHeader.biSize = sizeof bi.bmiHeader;
    bi.bmiHeader.biWidth = CAP_W;
    bi.bmiHeader.biHeight = -CAP_H;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    dc = CreateCompatibleDC(NULL);
    dib = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    if (dib == NULL || bits == NULL) {
        line("CreateDIBSection: failed");
        DeleteDC(dc);
        return;
    }
    old = (HBITMAP)SelectObject(dc, dib);
    for (i = 0; i < CAP_W * CAP_H; i++) {
        bits[i] = SENTINEL;
    }
    SetRect(&rc, 0, 0, CAP_W, CAP_H);
    arm();
    if (fa != NULL) {
        r = fa(h, dc, &rc, NULL, NULL, "F2K caption", flags);
    } else {
        r = fw(h, dc, &rc, NULL, NULL, wtext, flags);
    }
    line("DrawCaptionTemp%s(the popup, %s): ret=%d err=%s", fa != NULL ? "A" : "W", what, r, le());
    GdiFlush();
    for (i = 0; i < CAP_W * CAP_H; i++) {
        DWORD p = bits[i] & 0x00FFFFFF;

        if (p != SENTINEL) {
            if (changed == 0) {
                first = p;
            } else if (p != first) {
                distinct = 1;
            }
            changed++;
        }
    }
    line("  any pixel drawn: %s, every pixel: %s, more than one colour: %s", yesno(changed > 0),
         yesno(changed == CAP_W * CAP_H), yesno(distinct));
    SelectObject(dc, old);
    DeleteObject(dib);
    DeleteDC(dc);
}

static void sec_caption(void)
{
    caption_a_t fa = (caption_a_t)resolve("DrawCaptionTempA");
    caption_w_t fw = (caption_w_t)resolve("DrawCaptionTempW");
    HWND h = hidden_popup();

    if (fa != NULL) {
        caption_case(fa, NULL, h, DC_ACTIVE_ | DC_TEXT_, "DC_ACTIVE|DC_TEXT");
        caption_case(fa, NULL, h, DC_TEXT_, "DC_TEXT");
        caption_case(fa, NULL, h, DC_ACTIVE_, "DC_ACTIVE");
    }
    if (fw != NULL) {
        caption_case(NULL, fw, h, DC_ACTIVE_ | DC_TEXT_, "DC_ACTIVE|DC_TEXT");
        caption_case(NULL, fw, h, DC_TEXT_, "DC_TEXT");
        caption_case(NULL, fw, h, DC_ACTIVE_, "DC_ACTIVE");
    }
    DestroyWindow(h);
}

/* --- arrange ------------------------------------------------------- */

#define KIDS 4

static void print_kids(HWND parent, HWND *kids)
{
    RECT r;
    int i;

    for (i = 0; i < KIDS; i++) {
        GetWindowRect(kids[i], &r);
        MapWindowPoints(NULL, parent, (POINT *)&r, 2);
        line("  child %d: %ld %ld %ld %ld", i, r.left, r.top, r.right, r.bottom);
    }
}

/* Every child back to its starting place, shown and enabled. */
static void reset_kids(HWND *kids)
{
    int i;

    for (i = 0; i < KIDS; i++) {
        EnableWindow(kids[i], TRUE);
        SetWindowPos(kids[i], NULL, 10 + 20 * i, 10 + 20 * i, 120, 80,
                     SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
}

static void arrange(arrange_t f, const char *name, HWND parent, UINT how, const char *hname,
                    const RECT *rc, HWND *kids)
{
    WORD n;

    arm();
    n = f(parent, how, rc, KIDS, kids);
    line("%s(the parent, %s, %s, 4 children): ret=%u err=%s", name, hname,
         rc != NULL ? "rect 20 10 220 210" : "NULL", (unsigned)n, le());
    print_kids(parent, kids);
}

static void sec_arrange(void)
{
    arrange_t cascade = (arrange_t)resolve("CascadeWindows");
    arrange_t tile = (arrange_t)resolve("TileWindows");
    HWND parent, kids[KIDS];
    RECT rc, client;
    int i;

    register_plain();
    parent = CreateWindowExA(WS_EX_TOOLWINDOW, "F2KShell", "F2K arrange", WS_POPUP | WS_CLIPCHILDREN,
                             0, 0, 400, 300, NULL, NULL, GetModuleHandleA(NULL), NULL);
    for (i = 0; i < KIDS; i++) {
        kids[i] = CreateWindowExA(0, "F2KShell", "kid",
                                  WS_CHILD | WS_CAPTION | WS_THICKFRAME | WS_CLIPSIBLINGS, 0, 0, 120,
                                  80, parent, (HMENU)(100 + i), GetModuleHandleA(NULL), NULL);
    }
    ShowWindow(parent, SW_SHOWNOACTIVATE);
    GetClientRect(parent, &client);
    line("the parent's client: %ld x %ld", client.right, client.bottom);
    SetRect(&rc, 20, 10, 220, 210);

    if (cascade != NULL) {
        reset_kids(kids);
        arrange(cascade, "CascadeWindows", parent, 0, "0", NULL, kids);
        reset_kids(kids);
        arrange(cascade, "CascadeWindows", parent, 0, "0", &rc, kids);
        reset_kids(kids);
        EnableWindow(kids[1], FALSE);
        line("child 1 disabled");
        arrange(cascade, "CascadeWindows", parent, MDITILE_SKIPDISABLED_, "MDITILE_SKIPDISABLED", NULL,
                kids);
        reset_kids(kids);
        ShowWindow(kids[2], SW_HIDE);
        line("child 2 hidden");
        arrange(cascade, "CascadeWindows", parent, 0, "0", NULL, kids);
    }
    if (tile != NULL) {
        reset_kids(kids);
        arrange(tile, "TileWindows", parent, MDITILE_VERTICAL_, "MDITILE_VERTICAL", NULL, kids);
        reset_kids(kids);
        arrange(tile, "TileWindows", parent, MDITILE_HORIZONTAL_, "MDITILE_HORIZONTAL", NULL, kids);
        reset_kids(kids);
        arrange(tile, "TileWindows", parent, MDITILE_VERTICAL_, "MDITILE_VERTICAL", &rc, kids);
        reset_kids(kids);
        EnableWindow(kids[1], FALSE);
        line("child 1 disabled");
        arrange(tile, "TileWindows", parent, MDITILE_HORIZONTAL_ | MDITILE_SKIPDISABLED_,
                "MDITILE_HORIZONTAL|MDITILE_SKIPDISABLED", NULL, kids);
    }
    DestroyWindow(parent);
    drain();
}

/* --- hotkey -------------------------------------------------------- */

#define HOT_MODS (MOD_ALT_ | MOD_CONTROL_ | MOD_SHIFT_)

static void sec_hotkey(void)
{
    reg_hotkey_t reg = (reg_hotkey_t)resolve("RegisterHotKey");
    unreg_hotkey_t unreg = (unreg_hotkey_t)resolve("UnregisterHotKey");
    HWND h, dead;
    MSG m;
    int hot = 0;

    if (reg == NULL || unreg == NULL) {
        return;
    }
    h = hidden_popup();
    dead = hidden_popup();
    DestroyWindow(dead);
    drain();
    arm();
    line("RegisterHotKey(the popup, 1, Ctrl+Alt+Shift+F23): ret=%d err=%s",
         reg(h, 1, HOT_MODS, VK_F23_), le());
    arm();
    line("RegisterHotKey(the popup, 1, Ctrl+Alt+Shift+F22): ret=%d err=%s",
         reg(h, 1, HOT_MODS, VK_F22_), le());
    arm();
    line("RegisterHotKey(the popup, 2, Ctrl+Alt+Shift+F23): ret=%d err=%s",
         reg(h, 2, HOT_MODS, VK_F23_), le());
    arm();
    line("RegisterHotKey(NULL, 1, Ctrl+Alt+Shift+F21): ret=%d err=%s", reg(NULL, 1, HOT_MODS, VK_F21_),
         le());
    arm();
    line("RegisterHotKey(a destroyed window, 3, Ctrl+Alt+F21): ret=%d err=%s",
         reg(dead, 3, MOD_ALT_ | MOD_CONTROL_, VK_F21_), le());
    arm();
    line("UnregisterHotKey(the popup, 2): ret=%d err=%s", unreg(h, 2), le());
    arm();
    line("UnregisterHotKey(the popup, 1): ret=%d err=%s", unreg(h, 1), le());
    arm();
    line("UnregisterHotKey(the popup, 1) again: ret=%d err=%s", unreg(h, 1), le());
    arm();
    line("RegisterHotKey(the popup, 2, Ctrl+Alt+Shift+F23) once freed: ret=%d err=%s",
         reg(h, 2, HOT_MODS, VK_F23_), le());
    arm();
    line("UnregisterHotKey(the popup, 2): ret=%d err=%s", unreg(h, 2), le());
    arm();
    line("UnregisterHotKey(the popup, 1) a third time: ret=%d err=%s", unreg(h, 1), le());
    arm();
    line("UnregisterHotKey(NULL, 1): ret=%d err=%s", unreg(NULL, 1), le());
    arm();
    line("UnregisterHotKey(NULL, 1) again: ret=%d err=%s", unreg(NULL, 1), le());
    arm();
    line("UnregisterHotKey(a destroyed window, 3): ret=%d err=%s", unreg(dead, 3), le());
    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
        if (m.message == WM_HOTKEY) {
            hot++;
        }
    }
    line("WM_HOTKEY received: %d", hot);
    DestroyWindow(h);
}

/* --- switchto ------------------------------------------------------ */

static void sec_switchto(void)
{
    switch_to_t sw = (switch_to_t)resolve("SwitchToThisWindow");
    HWND h;

    if (sw == NULL) {
        return;
    }
    register_plain();
    h = CreateWindowExA(0, "F2KShell", "F2K switch", WS_OVERLAPPEDWINDOW, 0, 0, 240, 120, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    ShowWindow(h, SW_SHOWNOACTIVATE);
    line("the fixture's window shown: %s", yesno(IsWindowVisible(h)));
    arm();
    sw(h, TRUE);
    line("SwitchToThisWindow(it, TRUE): err=%s", le());
    drain();
    line("  the foreground window: %s", yesno(GetForegroundWindow() == h));
    line("  iconic: %s", yesno(IsIconic(h)));
    ShowWindow(h, SW_MINIMIZE);
    drain();
    line("minimized: %s", yesno(IsIconic(h)));
    arm();
    sw(h, FALSE);
    line("SwitchToThisWindow(it, FALSE): err=%s", le());
    drain();
    line("  the foreground window: %s", yesno(GetForegroundWindow() == h));
    line("  iconic: %s", yesno(IsIconic(h)));
    arm();
    sw(h, TRUE);
    line("SwitchToThisWindow(it, TRUE) while minimized: err=%s", le());
    drain();
    line("  the foreground window: %s", yesno(GetForegroundWindow() == h));
    line("  iconic: %s", yesno(IsIconic(h)));
    DestroyWindow(h);
    drain();
}

/* --- callback ------------------------------------------------------ */

#define CB_MSG (WM_USER + 7)
#define CB_RESULT 0x1234
#define CB_DATA 0x5678

static char order[128];
static int cb_calls;
static HWND cb_hwnd;
static UINT cb_msg;
static DWORD cb_data;
static LRESULT cb_result;
static HANDLE handled;

static void note(const char *what)
{
    if (strlen(order) + strlen(what) + 2 < sizeof order) {
        if (order[0] != '\0') {
            strcat(order, " ");
        }
        strcat(order, what);
    }
}

static LRESULT CALLBACK cb_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == CB_MSG) {
        if (handled != NULL) {
            SetEvent(handled);
        } else {
            note("procedure");
        }
        return CB_RESULT + (LRESULT)wParam;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void CALLBACK callback(HWND hwnd, UINT msg, DWORD data, LRESULT result)
{
    cb_calls++;
    cb_hwnd = hwnd;
    cb_msg = msg;
    cb_data = data;
    cb_result = result;
    if (handled == NULL) {
        note("callback");
    }
}

static void print_callback(HWND target, WPARAM wParam)
{
    line("  callback calls: %d", cb_calls);
    if (cb_calls > 0) {
        line("  its window the target: %s, its message the sent one: %s, its data the given: %s, "
             "its result the procedure's: %s",
             yesno(cb_hwnd == target), yesno(cb_msg == CB_MSG), yesno(cb_data == CB_DATA),
             yesno(cb_result == CB_RESULT + (LRESULT)wParam));
    }
}

static HWND cb_window(void)
{
    WNDCLASSW wc;
    static const WCHAR cls[] = { 'F', '2', 'K', 'S', 'h', 'e', 'l', 'l', 'C', 'B', 0 };

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = cb_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = cls;
    RegisterClassW(&wc);
    return CreateWindowExW(0, cls, cls, WS_POPUP, 0, 0, 50, 50, NULL, NULL, GetModuleHandleA(NULL),
                           NULL);
}

static HWND other_window;
static HANDLE other_ready;
static HANDLE other_stop;

static DWORD WINAPI other_thread(LPVOID arg)
{
    MSG m;

    (void)arg;
    other_window = cb_window();
    SetEvent(other_ready);
    for (;;) {
        DWORD w = MsgWaitForMultipleObjects(1, &other_stop, FALSE, INFINITE, QS_ALLINPUT);

        if (w == WAIT_OBJECT_0) {
            break;
        }
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            DispatchMessageW(&m);
        }
    }
    DestroyWindow(other_window);
    return 0;
}

static void same_thread(send_cb_t f, const char *name, HWND h, WPARAM wParam)
{
    BOOL r;

    order[0] = '\0';
    cb_calls = 0;
    arm();
    r = f(h, CB_MSG, wParam, 0, callback, CB_DATA);
    note("return");
    line("%s(a window of this thread): ret=%d err=%s", name, r, le());
    line("  in order: %s", order);
    print_callback(h, wParam);
    order[0] = '\0';
    drain();
    line("  after a retrieval: callback calls %d, in order: %s", cb_calls, order[0] ? order : "-");
}

static void other_thread_case(send_cb_t f, const char *name, WPARAM wParam)
{
    BOOL r;
    DWORD start;
    MSG m;

    cb_calls = 0;
    ResetEvent(handled);
    arm();
    r = f(other_window, CB_MSG, wParam, 0, callback, CB_DATA);
    line("%s(a window of another thread): ret=%d err=%s", name, r, le());
    line("  the procedure ran: %s", yesno(WaitForSingleObject(handled, WAIT_MS) == WAIT_OBJECT_0));
    Sleep(200);
    line("  callback calls before any retrieval: %d", cb_calls);
    start = GetTickCount();
    while (cb_calls == 0 && GetTickCount() - start < WAIT_MS) {
        MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_ALLINPUT);
        PeekMessageA(&m, NULL, 0, 0, PM_NOREMOVE);
    }
    line("  once the sender peeks:");
    print_callback(other_window, wParam);
    drain();
    line("  callback calls after more retrievals: %d", cb_calls);
}

static void sec_callback(void)
{
    send_cb_t fa = (send_cb_t)resolve("SendMessageCallbackA");
    send_cb_t fw = (send_cb_t)resolve("SendMessageCallbackW");
    HWND h, dead;
    HANDLE t;

    h = cb_window();
    dead = cb_window();
    DestroyWindow(dead);
    drain();
    if (fa != NULL) {
        same_thread(fa, "SendMessageCallbackA", h, 1);
    }
    if (fw != NULL) {
        same_thread(fw, "SendMessageCallbackW", h, 2);
    }
    handled = CreateEventA(NULL, FALSE, FALSE, NULL);
    other_ready = CreateEventA(NULL, FALSE, FALSE, NULL);
    other_stop = CreateEventA(NULL, TRUE, FALSE, NULL);
    t = CreateThread(NULL, 0, other_thread, NULL, 0, NULL);
    WaitForSingleObject(other_ready, WAIT_MS);
    if (fa != NULL) {
        other_thread_case(fa, "SendMessageCallbackA", 3);
    }
    if (fw != NULL) {
        other_thread_case(fw, "SendMessageCallbackW", 4);
    }
    SetEvent(other_stop);
    WaitForSingleObject(t, WAIT_MS);
    CloseHandle(t);
    CloseHandle(other_ready);
    CloseHandle(other_stop);
    CloseHandle(handled);
    handled = NULL;
    cb_calls = 0;
    if (fa != NULL) {
        arm();
        line("SendMessageCallbackA(a destroyed window): ret=%d err=%s",
             fa(dead, CB_MSG, 0, 0, callback, CB_DATA), le());
    }
    if (fw != NULL) {
        arm();
        line("SendMessageCallbackW(a destroyed window): ret=%d err=%s",
             fw(dead, CB_MSG, 0, 0, callback, CB_DATA), le());
    }
    drain();
    line("  callback calls: %d", cb_calls);
    DestroyWindow(h);
    drain();
}

static const section_t sections[] = {
    { "windows", sec_windows, F2KT_ALWAYS },
    { "setshell", sec_setshell, F2KT_ALWAYS },
    { "shellhook", sec_shellhook, F2KT_ALWAYS },
    { "alttab", sec_alttab, F2KT_ALWAYS },
    { "endtask", sec_endtask, F2KT_ALWAYS },
    { "paintdesk", sec_paintdesk, F2KT_ALWAYS },
    { "caption", sec_caption, F2KT_ALWAYS },
    { "arrange", sec_arrange, F2KT_ALWAYS },
    { "hotkey", sec_hotkey, F2KT_ALWAYS },
    { "switchto", sec_switchto, F2KT_ALWAYS },
    { "callback", sec_callback, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--endkid") == 0) {
        return endkid();
    }
    return run_sections("shell", sections, argc, argv);
}
