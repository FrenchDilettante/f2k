/*
 * calcprobe - THROWAWAY debug capture, not a fixture: starts calc.exe,
 * finds its main window and dumps what it is made of, so the real
 * machine's calc and F2K's can be compared line by line:
 *
 *   - win.ini's [SciCalc] settings (calc's mode);
 *   - the main window: class, title, styles, place and size, client
 *     size and inset, the class's and the window's icons, the menu bar's
 *     items, and the system metrics its frame is made of;
 *   - every child window: id, class, styles, place and size in the main
 *     window's client area, text, and font (WM_GETFONT, then GetObject).
 *
 * Each line goes to standard output and to OutputDebugStringA (on F2K,
 * COM1's "F2K: debug:" lines). calc is closed with WM_CLOSE at the
 * end, and left running if it is still there 5 seconds later.
 *
 * Only calls F2K implements find the windows (FindWindowA "SciCalc",
 * GetWindow's child chain, SendMessageA), so the probe runs on both;
 * calc is never terminated (the F2K run whose probe terminated it
 * ended in a kernel panic).
 *
 * Usage: calcprobe [path to calc.exe]   (default: calc.exe, on PATH)
 *   Windows 2000:  calcprobe > calcprobe.txt
 *   F2K:           fish calcprobe.exe   (read the COM1 log)
 *
 * Build (MSVC 6):
 *   cl /nologo calcprobe.c user32.lib gdi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>

static void out(const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    _vsnprintf(buf, sizeof buf - 3, fmt, ap);
    va_end(ap);
    buf[sizeof buf - 3] = 0;
    lstrcatA(buf, "\r\n");
    fputs(buf, stdout);
    fflush(stdout);
    OutputDebugStringA(buf);
}

static HWND main_window;

static const char *text_of(HWND h)
{
    static char buf[128];

    buf[0] = 0;
    SendMessageA(h, WM_GETTEXT, sizeof buf, (LPARAM)buf);
    return buf;
}

static void print_font(HWND h)
{
    DWORD font;
    LOGFONTA lf;

    font = (DWORD)SendMessageA(h, WM_GETFONT, 0, 0);
    if (font == 0) {
        out("    font: none (WM_GETFONT NULL)");
        return;
    }
    ZeroMemory(&lf, sizeof lf);
    if (GetObjectA((HGDIOBJ)font, sizeof lf, &lf) == 0) {
        out("    font: WM_GETFONT non-NULL, GetObject failed err=%lu", GetLastError());
        return;
    }
    out("    font: \"%s\" height %ld width %ld weight %ld italic %d charset %d quality %d pitch 0x%X", lf.lfFaceName,
        lf.lfHeight, lf.lfWidth, lf.lfWeight, lf.lfItalic, lf.lfCharSet, lf.lfQuality, lf.lfPitchAndFamily);
}

static void dump_child(HWND h)
{
    char cls[64];
    RECT r;
    POINT p;

    cls[0] = 0;
    GetClassNameA(h, cls, sizeof cls);
    GetWindowRect(h, &r);
    p.x = r.left;
    p.y = r.top;
    ScreenToClient(main_window, &p);
    out("child id %d class \"%s\" style 0x%08lX ex 0x%08lX at %ld,%ld size %ldx%ld visible %d", GetDlgCtrlID(h),
        cls, (unsigned long)GetWindowLongA(h, GWL_STYLE), (unsigned long)GetWindowLongA(h, GWL_EXSTYLE), p.x, p.y,
        r.right - r.left, r.bottom - r.top, IsWindowVisible(h) ? 1 : 0);
    out("    screen %ld,%ld,%ld,%ld text \"%s\"", r.left, r.top, r.right, r.bottom, text_of(h));
    print_font(h);
}

static void dump_menu(HMENU m)
{
    char item[64];
    int n;
    int i;

    if (m == NULL) {
        out("menu: none");
        return;
    }
    n = GetMenuItemCount(m);
    out("menu: %d items", n);
    for (i = 0; i < n; i++) {
        item[0] = 0;
        GetMenuStringA(m, i, item, sizeof item, MF_BYPOSITION);
        out("  item %d \"%s\" state 0x%X", i, item, GetMenuState(m, i, MF_BYPOSITION));
    }
}

int main(int argc, char **argv)
{
    char command[MAX_PATH + 2];
    char value[64];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    RECT wr;
    RECT cr;
    POINT origin;
    DWORD icon;
    HWND child;
    int waited;

    out("calcprobe: begin");
    GetProfileStringA("SciCalc", "layout", "(none)", value, sizeof value);
    out("win.ini [SciCalc] layout=%s", value);
    GetProfileStringA("SciCalc", "UseSep", "(none)", value, sizeof value);
    out("win.ini [SciCalc] UseSep=%s", value);
    out("metrics: SM_CXSCREEN %d SM_CYSCREEN %d SM_CYCAPTION %d SM_CYMENU %d SM_CXFIXEDFRAME %d SM_CYFIXEDFRAME %d "
        "SM_CXFRAME %d SM_CYFRAME %d SM_CXEDGE %d SM_CXBORDER %d SM_CXSMICON %d SM_CXSIZE %d SM_CYSIZE %d",
        GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), GetSystemMetrics(SM_CYCAPTION),
        GetSystemMetrics(SM_CYMENU), GetSystemMetrics(SM_CXFIXEDFRAME), GetSystemMetrics(SM_CYFIXEDFRAME),
        GetSystemMetrics(SM_CXFRAME), GetSystemMetrics(SM_CYFRAME), GetSystemMetrics(SM_CXEDGE),
        GetSystemMetrics(SM_CXBORDER), GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CXSIZE),
        GetSystemMetrics(SM_CYSIZE));

    lstrcpyA(command, argc > 1 ? argv[1] : "calc.exe");
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        out("CreateProcessA(%s) failed err=%lu", command, GetLastError());
        return 1;
    }
    for (waited = 0; waited < 10000 && main_window == NULL; waited += 100) {
        Sleep(100);
        main_window = FindWindowA("SciCalc", NULL);
    }
    if (main_window == NULL) {
        out("no SciCalc window after 10 s: calc closed");
        PostThreadMessageA(pi.dwThreadId, WM_QUIT, 0, 0);
        WaitForSingleObject(pi.hProcess, 5000);
        return 1;
    }
    /* Let calc finish its own sizing and painting. */
    Sleep(1500);
    out("found after about %d ms; visible %d", waited, IsWindowVisible(main_window) ? 1 : 0);

    GetClassNameA(main_window, value, sizeof value);
    out("main class \"%s\" title \"%s\"", value, text_of(main_window));
    out("main style 0x%08lX ex 0x%08lX", (unsigned long)GetWindowLongA(main_window, GWL_STYLE),
        (unsigned long)GetWindowLongA(main_window, GWL_EXSTYLE));
    GetWindowRect(main_window, &wr);
    GetClientRect(main_window, &cr);
    origin.x = 0;
    origin.y = 0;
    ClientToScreen(main_window, &origin);
    out("main screen %ld,%ld,%ld,%ld", wr.left, wr.top, wr.right, wr.bottom);
    out("main window at %ld,%ld size %ldx%ld; client %ldx%ld inset left %ld top %ld right %ld bottom %ld", wr.left,
        wr.top, wr.right - wr.left, wr.bottom - wr.top, cr.right, cr.bottom, origin.x - wr.left, origin.y - wr.top,
        wr.right - (origin.x + cr.right), wr.bottom - (origin.y + cr.bottom));
    out("class icons: GCL_HICON non-NULL %d GCL_HICONSM non-NULL %d", GetClassLongA(main_window, GCL_HICON) != 0,
        GetClassLongA(main_window, GCL_HICONSM) != 0);
    icon = (DWORD)SendMessageA(main_window, WM_GETICON, ICON_SMALL, 0);
    out("WM_GETICON(ICON_SMALL) non-NULL %d", icon != 0);
    icon = (DWORD)SendMessageA(main_window, WM_GETICON, ICON_BIG, 0);
    out("WM_GETICON(ICON_BIG) non-NULL %d", icon != 0);
    dump_menu(GetMenu(main_window));
    print_font(main_window);
    for (child = GetWindow(main_window, GW_CHILD); child != NULL; child = GetWindow(child, GW_HWNDNEXT)) {
        dump_child(child);
    }

    PostMessageA(main_window, WM_CLOSE, 0, 0);
    if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0) {
        out("calc still running 5 s after WM_CLOSE (left running)");
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    out("calcprobe: end");
    return 0;
}
