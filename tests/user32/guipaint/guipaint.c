/*
 * guipaint - the user32 paint path: InvalidateRect, ValidateRect,
 * GetUpdateRect, BeginPaint and EndPaint, and the class background
 * erase (a class with hbrBackground = (HBRUSH)(COLOR_WINDOW+1)) as
 * PAINTSTRUCT.fErase inside BeginPaint.
 *
 * Conventions as in common/f2kt.h: every call under observation is
 * armed with the last-error sentinel and its line prints ret= and
 * err=; no handle value, address or thread id is printed (handles
 * print only as yes/no comparisons); rects and coordinates print as
 * plain numbers, and only client-relative ones (the client origin is
 * 0,0), so no line depends on where the window sits. The wndproc
 * handles WM_PAINT with BeginPaint/EndPaint and records what it saw
 * in globals, printed after the calls that could have sent the
 * message; it answers WM_DESTROY with PostQuitMessage(0) so a drain
 * ends. Each section first drains the queue (a PeekMessage PM_REMOVE
 * loop), then creates a fresh hidden 320x200 WS_POPUP window at
 * explicit coordinates (0,0), so the client area is exactly 320x200
 * and the sections are independent.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   invalidate  InvalidateRect(h, NULL, TRUE); GetUpdateRect(h, &rc,
 *               FALSE) reports the whole client rect; ValidateRect(h,
 *               NULL) clears it; GetUpdateRect then reports none
 *   subrect     InvalidateRect of {10,10,50,40} with erase FALSE;
 *               GetUpdateRect reports that rect; ValidateRect of it;
 *               GetUpdateRect reports none; then the same rect with
 *               erase TRUE, observed through BeginPaint's PAINTSTRUCT
 *               (fErase, rcPaint) and EndPaint
 *   paint       ShowWindow(SW_SHOW), InvalidateRect(h, NULL, TRUE),
 *               UpdateWindow: the wndproc-recorded WM_PAINT (count,
 *               hdc non-NULL, fErase, rcPaint, EndPaint return), then
 *               GetUpdateRect reports none
 *   beginend    InvalidateRect(h, NULL, TRUE), then BeginPaint and
 *               EndPaint called directly: the DC, the error, fErase,
 *               rcPaint, and EndPaint's return
 *   resize      ShowWindow(SW_SHOW) and UpdateWindow, then SetWindowPos
 *               to a bigger size: GetUpdateRect and BeginPaint's
 *               PAINTSTRUCT after the resize (the update region a shown
 *               window's resize leaves), then the same resize with
 *               SWP_NOREDRAW
 *   errors      BeginPaint on a bogus handle, EndPaint with a NULL
 *               PAINTSTRUCT, InvalidateRect and GetUpdateRect on a
 *               bogus handle
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guipaint):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guipaint.c user32.lib
 */

#include "../common/f2kt.h"

/* A window handle no window has. */
#define BOGUS_HWND ((HWND)0x7FFFFFFC)

/* What the wndproc recorded on its last WM_PAINT; printed after the
 * calls that could have sent it. */
static int paint_count;
static int paint_hdc_nonnull;
static int paint_ferase;
static LONG paint_left, paint_top, paint_right, paint_bottom;
static BOOL paint_end_ret;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc;

        hdc = BeginPaint(hwnd, &ps);
        paint_hdc_nonnull = (hdc != NULL);
        paint_ferase = ps.fErase;
        paint_left = ps.rcPaint.left;
        paint_top = ps.rcPaint.top;
        paint_right = ps.rcPaint.right;
        paint_bottom = ps.rcPaint.bottom;
        paint_end_ret = EndPaint(hwnd, &ps);
        paint_count++;
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hwnd, msg, wparam, lparam);
    }
}

static void reset_paint(void)
{
    paint_count = 0;
    paint_hdc_nonnull = 0;
    paint_ferase = 0;
    paint_left = paint_top = paint_right = paint_bottom = 0;
    paint_end_ret = 0;
}

/* Read the thread's queue until it is empty, dispatching what comes:
 * a retrieved WM_PAINT is handled (and validates the window), so the
 * loop ends; the messages themselves are not printed. */
static void drain(void)
{
    MSG m;

    while (PeekMessage(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessage(&m);
    }
}

/* Register `class_name` and create one hidden 320x200 window of it at
 * explicit coordinates; WS_POPUP, so the client area is exactly the
 * 320x200 given. */
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
    h = CreateWindowEx(0, class_name, "F2K guipaint", WS_POPUP,
                       0, 0, 320, 200, NULL, NULL, inst, NULL);
    return h;
}

/* --- invalidate ---------------------------------------------------- */

static void sec_invalidate(void)
{
    HWND h;
    RECT rc;
    BOOL r;

    drain();
    reset_paint();
    h = make_window("F2KGuipaintInvalidate");
    arm();
    r = InvalidateRect(h, NULL, TRUE);
    line("InvalidateRect(h, NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    r = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE): ret=%d err=%s rc=%ld %ld %ld %ld", r, le(),
         rc.left, rc.top, rc.right, rc.bottom);
    arm();
    r = ValidateRect(h, NULL);
    line("ValidateRect(h, NULL): ret=%d err=%s", r, le());
    arm();
    r = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE) after ValidateRect: ret=%d err=%s", r, le());
}

/* --- subrect ------------------------------------------------------- */

static void sec_subrect(void)
{
    HWND h;
    RECT r = { 10, 10, 50, 40 };
    RECT rc;
    PAINTSTRUCT ps;
    HDC hdc;
    BOOL b;

    drain();
    reset_paint();
    h = make_window("F2KGuipaintSubrect");
    arm();
    b = InvalidateRect(h, &r, FALSE);
    line("InvalidateRect(h, {10 10 50 40}, FALSE): ret=%d err=%s", b, le());
    arm();
    b = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE): ret=%d err=%s rc=%ld %ld %ld %ld", b, le(),
         rc.left, rc.top, rc.right, rc.bottom);
    arm();
    b = ValidateRect(h, &r);
    line("ValidateRect(h, {10 10 50 40}): ret=%d err=%s", b, le());
    arm();
    b = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE) after ValidateRect: ret=%d err=%s", b, le());
    arm();
    b = InvalidateRect(h, &r, TRUE);
    line("InvalidateRect(h, {10 10 50 40}, TRUE): ret=%d err=%s", b, le());
    arm();
    hdc = BeginPaint(h, &ps);
    line("BeginPaint(h, &ps) on the erased subrect: non-NULL %s err=%s fErase=%d "
         "rcPaint=%ld %ld %ld %ld",
         yesno(hdc != NULL), le(), ps.fErase, ps.rcPaint.left, ps.rcPaint.top,
         ps.rcPaint.right, ps.rcPaint.bottom);
    arm();
    b = EndPaint(h, &ps);
    line("EndPaint(h, &ps): ret=%d err=%s", b, le());
}

/* --- paint --------------------------------------------------------- */

static void sec_paint(void)
{
    HWND h;
    RECT rc;
    BOOL r;

    drain();
    reset_paint();
    h = make_window("F2KGuipaintPaint");
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(h, SW_SHOW): ret=%d err=%s", r, le());
    arm();
    r = InvalidateRect(h, NULL, TRUE);
    line("InvalidateRect(h, NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    r = UpdateWindow(h);
    line("UpdateWindow(h): ret=%d err=%s", r, le());
    line("wndproc WM_PAINT: count=%d hdc non-NULL %s fErase=%d rcPaint=%ld %ld %ld %ld "
         "EndPaint ret=%d",
         paint_count, yesno(paint_hdc_nonnull), paint_ferase,
         paint_left, paint_top, paint_right, paint_bottom, paint_end_ret);
    arm();
    r = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE) after the paint: ret=%d err=%s", r, le());
}

/* --- beginend ------------------------------------------------------ */

static void sec_beginend(void)
{
    HWND h;
    PAINTSTRUCT ps;
    HDC hdc;
    BOOL r;

    drain();
    reset_paint();
    h = make_window("F2KGuipaintBeginend");
    arm();
    r = InvalidateRect(h, NULL, TRUE);
    line("InvalidateRect(h, NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    hdc = BeginPaint(h, &ps);
    line("BeginPaint(h, &ps): non-NULL %s err=%s fErase=%d rcPaint=%ld %ld %ld %ld",
         yesno(hdc != NULL), le(), ps.fErase, ps.rcPaint.left, ps.rcPaint.top,
         ps.rcPaint.right, ps.rcPaint.bottom);
    arm();
    r = EndPaint(h, &ps);
    line("EndPaint(h, &ps): ret=%d err=%s", r, le());
}

/* --- errors -------------------------------------------------------- */

static void sec_errors(void)
{
    HWND h;
    RECT rc;
    PAINTSTRUCT ps;
    HDC hdc;
    BOOL r;

    drain();
    reset_paint();
    h = make_window("F2KGuipaintErrors");
    arm();
    hdc = BeginPaint(BOGUS_HWND, &ps);
    line("BeginPaint(a bogus handle, &ps): NULL %s err=%s", yesno(hdc == NULL), le());
    arm();
    r = EndPaint(h, NULL);
    line("EndPaint(h, NULL): ret=%d err=%s", r, le());
    arm();
    r = InvalidateRect(BOGUS_HWND, NULL, TRUE);
    line("InvalidateRect(a bogus handle, NULL, TRUE): ret=%d err=%s", r, le());
    arm();
    r = GetUpdateRect(BOGUS_HWND, &rc, FALSE);
    line("GetUpdateRect(a bogus handle, &rc, FALSE): ret=%d err=%s", r, le());
}

/* --- resize -------------------------------------------------------- */

/* A shown window's resize: SetWindowPos to a bigger size, then what
 * GetUpdateRect and BeginPaint report; and the SWP_NOREDRAW variant. */
static void sec_resize(void)
{
    HWND h;
    RECT rc;
    PAINTSTRUCT ps;
    HDC hdc;
    BOOL r;

    drain();
    reset_paint();
    h = make_window("F2KGuipaintResize");
    arm();
    r = ShowWindow(h, SW_SHOW);
    line("ShowWindow(h, SW_SHOW): ret=%d err=%s", r, le());
    arm();
    r = UpdateWindow(h);
    line("UpdateWindow(h): ret=%d err=%s", r, le());
    arm();
    r = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE) after the show's paint: ret=%d err=%s", r, le());
    arm();
    r = SetWindowPos(h, HWND_TOP, 0, 0, 400, 300, SWP_NOZORDER | SWP_NOACTIVATE);
    line("SetWindowPos(h, HWND_TOP, 0, 0, 400, 300, SWP_NOZORDER|SWP_NOACTIVATE): ret=%d err=%s",
         r, le());
    arm();
    r = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE) after the resize: ret=%d err=%s rc=%ld %ld %ld %ld", r, le(),
         rc.left, rc.top, rc.right, rc.bottom);
    arm();
    hdc = BeginPaint(h, &ps);
    line("BeginPaint(h, &ps) after the resize: non-NULL %s err=%s fErase=%d rcPaint=%ld %ld %ld %ld",
         yesno(hdc != NULL), le(), ps.fErase, ps.rcPaint.left, ps.rcPaint.top, ps.rcPaint.right,
         ps.rcPaint.bottom);
    arm();
    r = EndPaint(h, &ps);
    line("EndPaint(h, &ps): ret=%d err=%s", r, le());
    arm();
    r = SetWindowPos(h, HWND_TOP, 0, 0, 500, 350, SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW);
    line("SetWindowPos(h, HWND_TOP, 0, 0, 500, 350, SWP_NOZORDER|SWP_NOACTIVATE|SWP_NOREDRAW): "
         "ret=%d err=%s",
         r, le());
    arm();
    r = GetUpdateRect(h, &rc, FALSE);
    line("GetUpdateRect(h, &rc, FALSE) after the SWP_NOREDRAW resize: ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "invalidate", sec_invalidate, F2KT_ALWAYS },
    { "subrect", sec_subrect, F2KT_ALWAYS },
    { "paint", sec_paint, F2KT_ALWAYS },
    { "beginend", sec_beginend, F2KT_ALWAYS },
    { "resize", sec_resize, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bogus handle goes to the calls: should one fault, no dialog
     * stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guipaint", sections, argc, argv);
}
