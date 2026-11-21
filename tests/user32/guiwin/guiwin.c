/*
 * guiwin - the window lifecycle and cursor calls of user32:
 * CreateWindowExA/W, DestroyWindow, GetDesktopWindow, IsWindow and
 * LoadCursorA/W.
 *
 * No handle value is printed: only whether one came back and how two
 * compare. A module-level wndproc counts the WM_NCCREATE, WM_CREATE
 * and WM_DESTROY messages it receives and records the last message it
 * saw; the counts print after the calls that delivered them, since
 * creation and destruction send those messages synchronously. The
 * suite runs each section as its own process, so each section that
 * needs a window registers the class and creates its own. Windows are
 * created at an explicit 320x200 and never shown, no window position
 * is printed (CW_USEDEFAULT varies with the machine), a paint is
 * forced synchronously with UpdateWindow, and posted messages are
 * drained with GetMessage after a PostQuitMessage, so the loop always
 * ends.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   register class "F2KGuiWin"; CreateWindowExA of a
 *            WS_OVERLAPPEDWINDOW window, IsWindow on it and the
 *            wndproc's WM_NCCREATE/WM_CREATE counts; CreateWindowExW
 *            on the same class; CreateWindowExA against an
 *            unregistered class name
 *   desktop  GetDesktopWindow, and IsWindow on it
 *   destroy  DestroyWindow of the section's own window (its
 *            WM_DESTROY count), IsWindow on the dead handle, and a
 *            second DestroyWindow of it
 *   cursor   LoadCursorA/W of the IDC_ARROW stock cursor, and
 *            LoadCursorA of a non-stock id
 *   refuse   CreateWindowExA/W of a class whose procedure refuses the
 *            creation: WM_NCCREATE answering 0, WM_CREATE answering -1,
 *            and WM_CREATE answering -2; the return, the last error,
 *            and the creation and destruction messages the procedure
 *            received, in order
 *   uniq     the section's first window's handle (its high word
 *            nonzero); the window destroyed and another made at once:
 *            the new handle against the old (the same, the same low
 *            word, the high word one more), IsWindow and DestroyWindow
 *            of the stale handle, and the new window after
 *
 * refuse and uniq make WS_POPUP windows at an explicit position. uniq's
 * low-word relation holds while no other program makes a user object
 * between the destruction and the creation.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guiwin):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guiwin.c user32.lib
 */

#include "../common/f2kt.h"

/* What the wndproc has seen so far. */
static int n_nccreate;
static int n_create;
static int n_destroy;
static UINT last_msg;

/* The process instance, once asked for. */
static HINSTANCE hinst;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    last_msg = msg;
    switch (msg) {
    case WM_NCCREATE:
        n_nccreate++;
        break;
    case WM_CREATE:
        n_create++;
        break;
    case WM_DESTROY:
        n_destroy++;
        PostQuitMessage(0);
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* Drain the thread's posted messages: the WM_QUIT the wndproc posted
 * on WM_DESTROY, or the one the caller posts, ends the loop. */
static void drain(void)
{
    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

/* Register "F2KGuiWin" (the first call in the process does) and create
 * one 320x200 WS_OVERLAPPEDWINDOW window of it. */
static HWND make_window(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    ATOM a;

    if (hinst == NULL) {
        arm();
        hinst = GetModuleHandleA(NULL);
        line("GetModuleHandleA(NULL): non-NULL %s err=%s", yesno(hinst != NULL), le());
        ZeroMemory(&wc, sizeof wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = wndproc;
        wc.hInstance = hinst;
        wc.lpszClassName = "F2KGuiWin";
        arm();
        a = RegisterClassA(&wc);
        line("RegisterClassA(F2KGuiWin): nonzero %s err=%s", yesno(a != 0), le());
    }
    arm();
    hwnd = CreateWindowExA(0, "F2KGuiWin", "t", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                           NULL, NULL, hinst, NULL);
    line("CreateWindowExA(F2KGuiWin): non-NULL %s err=%s", yesno(hwnd != NULL), le());
    return hwnd;
}

/* --- create -------------------------------------------------------- */

static void sec_create(void)
{
    HWND hwnd, hwnd_w, hwnd_bad;
    BOOL r;

    hwnd = make_window();

    arm();
    r = IsWindow(hwnd);
    line("IsWindow(the new window): %s err=%s", yesno(r), le());

    line("wndproc: WM_NCCREATE=%d WM_CREATE=%d last=0x%lX",
         n_nccreate, n_create, (unsigned long)last_msg);

    arm();
    r = UpdateWindow(hwnd);
    line("UpdateWindow: ret=%d err=%s", r, le());

    arm();
    hwnd_w = CreateWindowExW(0, L"F2KGuiWin", L"t", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                             NULL, NULL, hinst, NULL);
    line("CreateWindowExW(F2KGuiWin): non-NULL %s err=%s", yesno(hwnd_w != NULL), le());

    arm();
    hwnd_bad = CreateWindowExA(0, "NoSuchClass", "t", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                               NULL, NULL, hinst, NULL);
    line("CreateWindowExA(NoSuchClass): NULL %s err=%s", yesno(hwnd_bad == NULL), le());

    PostQuitMessage(0);
    drain();
    line("wndproc: WM_NCCREATE=%d WM_CREATE=%d WM_DESTROY=%d last=0x%lX",
         n_nccreate, n_create, n_destroy, (unsigned long)last_msg);
}

/* --- desktop ------------------------------------------------------- */

static void sec_desktop(void)
{
    HWND hwnd;
    BOOL r;

    arm();
    hwnd = GetDesktopWindow();
    line("GetDesktopWindow: non-NULL %s err=%s", yesno(hwnd != NULL), le());
    arm();
    r = IsWindow(hwnd);
    line("IsWindow(the desktop window): %s err=%s", yesno(r), le());
}

/* --- destroy ------------------------------------------------------- */

static void sec_destroy(void)
{
    HWND hwnd;
    BOOL r;

    hwnd = make_window();

    arm();
    r = DestroyWindow(hwnd);
    line("DestroyWindow: ret=%d err=%s", r, le());
    line("wndproc: WM_DESTROY=%d last=0x%lX", n_destroy, (unsigned long)last_msg);

    arm();
    r = IsWindow(hwnd);
    line("IsWindow(the destroyed window): %s err=%s", yesno(r), le());

    arm();
    r = DestroyWindow(hwnd);
    line("DestroyWindow(the destroyed window): ret=%d err=%s", r, le());

    drain();
    line("wndproc: WM_DESTROY=%d last=0x%lX", n_destroy, (unsigned long)last_msg);
}

/* --- cursor -------------------------------------------------------- */

static void sec_cursor(void)
{
    HCURSOR c_arrow_a, c_arrow_w, c_other;

    arm();
    c_arrow_a = LoadCursorA(NULL, IDC_ARROW);
    line("LoadCursorA(IDC_ARROW): non-NULL %s err=%s", yesno(c_arrow_a != NULL), le());
    arm();
    c_arrow_w = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    line("LoadCursorW(IDC_ARROW): non-NULL %s err=%s", yesno(c_arrow_w != NULL), le());
    line("the A and W cursors are the same: %s", yesno(c_arrow_a == c_arrow_w));
    arm();
    c_other = LoadCursorA(NULL, MAKEINTRESOURCE(32767));
    line("LoadCursorA(32767): NULL %s err=%s", yesno(c_other == NULL), le());
}

/* --- refuse ------------------------------------------------------- */

/* What the refusing procedure answers: 0 lets every message through,
 * 1 refuses WM_NCCREATE (0), 2 refuses WM_CREATE (-1), 3 answers
 * WM_CREATE with -2. */
static int refuse_mode;

/* The creation and destruction messages it received, in order. */
static char refuse_log[256];

static void refuse_note(const char *name)
{
    if (strlen(refuse_log) + strlen(name) + 2 < sizeof refuse_log) {
        if (refuse_log[0] != '\0') {
            strcat(refuse_log, " ");
        }
        strcat(refuse_log, name);
    }
}

static LRESULT CALLBACK refuse_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_GETMINMAXINFO:
        refuse_note("WM_GETMINMAXINFO");
        break;
    case WM_NCCREATE:
        refuse_note("WM_NCCREATE");
        if (refuse_mode == 1) {
            return 0;
        }
        break;
    case WM_NCCALCSIZE:
        refuse_note("WM_NCCALCSIZE");
        break;
    case WM_CREATE:
        refuse_note("WM_CREATE");
        if (refuse_mode == 2) {
            return -1;
        }
        if (refuse_mode == 3) {
            return -2;
        }
        break;
    case WM_DESTROY:
        refuse_note("WM_DESTROY");
        break;
    case WM_NCDESTROY:
        refuse_note("WM_NCDESTROY");
        break;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void refuse_create(const char *what, int mode, int wide)
{
    HWND h;
    DWORD e;

    refuse_mode = mode;
    refuse_log[0] = '\0';
    arm();
    if (wide) {
        h = CreateWindowExW(0, L"F2KGuiWinRefuse", L"t", WS_POPUP, 10, 10, 200, 100, NULL, NULL,
                            hinst, NULL);
    } else {
        h = CreateWindowExA(0, "F2KGuiWinRefuse", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL,
                            hinst, NULL);
    }
    e = GetLastError();
    line("CreateWindowEx%s, %s: NULL %s err=%s", wide ? "W" : "A", what, yesno(h == NULL), le_of(e));
    line("  the procedure received: %s", refuse_log);
    refuse_mode = 0;
    if (h != NULL) {
        line("  IsWindow: %s", yesno(IsWindow(h)));
        DestroyWindow(h);
    }
}

static void sec_refuse(void)
{
    WNDCLASSA wc;

    hinst = GetModuleHandleA(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = refuse_proc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWinRefuse";
    RegisterClassA(&wc);

    refuse_create("let through", 0, 0);
    refuse_create("WM_NCCREATE answering 0", 1, 0);
    refuse_create("WM_NCCREATE answering 0", 1, 1);
    refuse_create("WM_CREATE answering -1", 2, 0);
    refuse_create("WM_CREATE answering -1", 2, 1);
    refuse_create("WM_CREATE answering -2", 3, 0);
}

/* --- uniq ---------------------------------------------------------- */

static HWND uniq_create(void)
{
    return CreateWindowExA(0, "F2KGuiWin", "t", WS_POPUP, 10, 10, 200, 100, NULL, NULL, hinst,
                           NULL);
}

static void sec_uniq(void)
{
    WNDCLASSA wc;
    HWND h1, h2;
    BOOL r;

    hinst = GetModuleHandleA(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = hinst;
    wc.lpszClassName = "F2KGuiWin";
    RegisterClassA(&wc);

    h1 = uniq_create();
    line("the first window: non-NULL %s, its high word nonzero %s", yesno(h1 != NULL),
         yesno(HIWORD((DWORD)h1) != 0));
    arm();
    r = DestroyWindow(h1);
    line("DestroyWindow(the first): ret=%d err=%s", r, le());
    h2 = uniq_create();
    line("a second window made at once: non-NULL %s, its high word nonzero %s", yesno(h2 != NULL),
         yesno(HIWORD((DWORD)h2) != 0));
    line("  the first's handle %s, its low word %s, its high word plus one %s", yesno(h2 == h1),
         yesno(LOWORD((DWORD)h2) == LOWORD((DWORD)h1)),
         yesno(HIWORD((DWORD)h2) == (WORD)(HIWORD((DWORD)h1) + 1)));
    arm();
    r = IsWindow(h1);
    line("IsWindow(the first, destroyed): %s err=%s", yesno(r), le());
    arm();
    r = DestroyWindow(h1);
    line("DestroyWindow(the first, destroyed): ret=%d err=%s", r, le());
    arm();
    r = IsWindow(h2);
    line("IsWindow(the second) after: %s err=%s", yesno(r), le());
    if (IsWindow(h2)) {
        DestroyWindow(h2);
    }
    PostQuitMessage(0);
    drain();
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "desktop", sec_desktop, F2KT_ALWAYS },
    { "destroy", sec_destroy, F2KT_ALWAYS },
    { "cursor", sec_cursor, F2KT_ALWAYS },
    { "refuse", sec_refuse, F2KT_ALWAYS },
    { "uniq", sec_uniq, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad class name or a dead window handle goes to the calls:
     * should one fault, no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guiwin", sections, argc, argv);
}
