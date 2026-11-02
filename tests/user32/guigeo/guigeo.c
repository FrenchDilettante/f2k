/*
 * guigeo - window geometry and visibility in user32: ShowWindow,
 * ShowWindowAsync, UpdateWindow, SetWindowPos, MoveWindow, GetWindowRect
 * and IsWindowVisible.
 *
 * Conventions as in common/f2kt.h: every call under observation is
 * armed with the sentinel and prints ret= and err=; no handle values,
 * addresses or raw timings are printed. Visibility prints as yes/no,
 * rects as four plain numbers. Each section registers its own class and
 * creates one hidden 320x200 window at explicit coordinates (creation
 * never uses CW_USEDEFAULT), so no line depends on where the system
 * would have placed a window; MoveWindow/SetWindowPos set the position
 * before any GetWindowRect prints it. ShowWindowAsync's effect is
 * applied while the thread's queue is next read, so each async call is
 * followed by a silent drain (PeekMessage/DispatchMessage until the
 * queue is empty); the messages it retrieves are not printed. The
 * wndproc counts the WM_PAINT messages it handles in a global, printed
 * after the calls that could have sent them. GetClientRect is not
 * covered here: window decoration differs deliberately, so client sizes
 * are not printed.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   show     ShowWindow SW_SHOW, SW_HIDE, SW_SHOW again, each with its
 *            return and IsWindowVisible after; then ShowWindowAsync
 *            SW_HIDE and SW_SHOW, each with a queue drain after it and
 *            IsWindowVisible
 *   move     MoveWindow to 100,100 sized 300x250, and the GetWindowRect
 *            after it
 *   setpos   SetWindowPos to 50,60 sized 200x150 and the rect after it,
 *            then a SWP_NOSIZE|SWP_NOMOVE call changing only z-order
 *   update   ShowWindow(SW_SHOW), InvalidateRect, then UpdateWindow
 *            twice: the return and the wndproc's WM_PAINT count
 *   errors   MoveWindow, GetWindowRect, SetWindowPos and IsWindowVisible
 *            on a bogus handle
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guigeo):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guigeo.c user32.lib
 */

#include "../common/f2kt.h"

/* A window handle no window has. */
#define BOGUS_HWND ((HWND)0x7FFFFFFC)

/* The WM_PAINT messages the wndproc has handled; printed after the
 * calls that could have sent them. */
static int paint_count;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;

        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        paint_count++;
        return 0;
    }
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

/* Read the thread's queue until it is empty. Dispatching a retrieved
 * WM_PAINT validates the window in the wndproc, so the loop ends; the
 * messages themselves are not printed. */
static void drain(void)
{
    MSG m;

    while (PeekMessage(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessage(&m);
    }
}

/* Register `class_name` and create one hidden 320x200 window of it at
 * explicit coordinates. */
static HWND make_window(const char *class_name)
{
    WNDCLASS wc;
    HINSTANCE inst;
    HWND h;

    inst = (HINSTANCE)GetModuleHandle(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;
    RegisterClass(&wc);
    h = CreateWindowEx(0, class_name, "F2K guigeo", WS_OVERLAPPEDWINDOW,
                       0, 0, 320, 200, NULL, NULL, inst, NULL);
    return h;
}

/* --- show ---------------------------------------------------------- */

static void sec_show(void)
{
    HWND h;
    BOOL r;
    int v;

    h = make_window("F2KGuigeoShow");
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(SW_SHOW): ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindow(h, SW_HIDE);
    line("ShowWindow(SW_HIDE): ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(SW_SHOW) again: ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindowAsync(h, SW_HIDE);
    line("ShowWindowAsync(SW_HIDE): ret=%d err=%s", r, le());
    drain();
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible after the queue drained: %s err=%s", yesno(v), le());
    arm();
    r = ShowWindowAsync(h, SW_SHOW);
    line("ShowWindowAsync(SW_SHOW): ret=%d err=%s", r, le());
    drain();
    arm();
    v = IsWindowVisible(h);
    line("IsWindowVisible after the queue drained: %s err=%s", yesno(v), le());
}

/* --- move ---------------------------------------------------------- */

static void sec_move(void)
{
    HWND h;
    RECT rc;
    BOOL r;

    h = make_window("F2KGuigeoMove");
    arm();
    r = MoveWindow(h, 100, 100, 300, 250, TRUE);
    line("MoveWindow(100, 100, 300, 250, TRUE): ret=%d err=%s", r, le());
    arm();
    r = GetWindowRect(h, &rc);
    line("GetWindowRect: ret=%d err=%s rect=%ld %ld %ld %ld", r, le(),
         rc.left, rc.top, rc.right, rc.bottom);
}

/* --- setpos -------------------------------------------------------- */

static void sec_setpos(void)
{
    HWND h;
    RECT rc;
    BOOL r;

    h = make_window("F2KGuigeoSetPos");
    arm();
    r = SetWindowPos(h, HWND_TOP, 50, 60, 200, 150, SWP_NOACTIVATE);
    line("SetWindowPos(HWND_TOP, 50, 60, 200, 150, SWP_NOACTIVATE): ret=%d err=%s", r, le());
    arm();
    r = GetWindowRect(h, &rc);
    line("GetWindowRect: ret=%d err=%s rect=%ld %ld %ld %ld", r, le(),
         rc.left, rc.top, rc.right, rc.bottom);
    arm();
    r = SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    line("SetWindowPos(HWND_TOP, SWP_NOSIZE|SWP_NOMOVE): ret=%d err=%s", r, le());
}

/* --- update -------------------------------------------------------- */

static void sec_update(void)
{
    HWND h;
    BOOL r;

    h = make_window("F2KGuigeoUpdate");
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(SW_SHOW): ret=%d err=%s", r, le());
    paint_count = 0;
    arm();
    r = InvalidateRect(h, NULL, TRUE);
    line("InvalidateRect(NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    r = UpdateWindow(h);
    line("UpdateWindow: ret=%d err=%s paints=%d", r, le(), paint_count);
    arm();
    r = UpdateWindow(h);
    line("UpdateWindow again: ret=%d err=%s paints=%d", r, le(), paint_count);
}

/* --- errors -------------------------------------------------------- */

static void sec_errors(void)
{
    HWND h;
    RECT rc;
    BOOL r;
    int v;

    h = make_window("F2KGuigeoErrors");
    (void)h;
    arm();
    r = MoveWindow(BOGUS_HWND, 1, 2, 3, 4, TRUE);
    line("MoveWindow(a bogus handle): ret=%d err=%s", r, le());
    arm();
    r = GetWindowRect(BOGUS_HWND, &rc);
    line("GetWindowRect(a bogus handle): ret=%d err=%s", r, le());
    arm();
    r = SetWindowPos(BOGUS_HWND, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    line("SetWindowPos(a bogus handle): ret=%d err=%s", r, le());
    arm();
    v = IsWindowVisible(BOGUS_HWND);
    line("IsWindowVisible(a bogus handle): %s err=%s", yesno(v), le());
}

static const section_t sections[] = {
    { "show", sec_show, 0 },
    { "move", sec_move, 0 },
    { "setpos", sec_setpos, 0 },
    { "update", sec_update, 0 },
    { "errors", sec_errors, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bogus handle goes to the calls: should one fault, no dialog
     * stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guigeo", sections, argc, argv);
}
