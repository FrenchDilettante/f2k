/*
 * guidisp - the device and display settings half of user32, and the
 * screen DC of gdi32: EnumDisplaySettingsA/W, ChangeDisplaySettingsA/W,
 * EnumDisplayDevicesA/W, GetSystemMetrics, SystemParametersInfoA/W,
 * GetSysColor, GetSysColorBrush, SetSysColors, MonitorFromWindow,
 * MonitorFromPoint, MonitorFromRect, EnumDisplayMonitors,
 * GetMonitorInfoA; and gdi32's CreateDCA, GetDeviceCaps, DeleteDC.
 *
 * Conventions as in common/f2kt.h: every call under observation is
 * armed with the sentinel and its line prints ret= and err=; no handle
 * value, address or thread id is printed, only whether one came back
 * and how two compare (yesno()); wide text prints through ws(); colors
 * print as 0x%06lX; rects as four plain numbers. Pixel dimensions,
 * monitor rects and colors are machine and scheme facts, so they print
 * raw. The monitors section creates one hidden 320x200 window at 0,0
 * (creation never uses CW_USEDEFAULT) and destroys it before it ends;
 * the queue is drained around it.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   enum      EnumDisplaySettingsA of the current settings, of mode 0,
 *             and of mode 9999 (ret and err only), the DEVMODE fields
 *             with each of the first two; the W twin of the current
 *             settings
 *   change    ChangeDisplaySettingsA of the current mode with flags 0
 *             and CDS_TEST, of a bogus 1x1x1 mode, and of NULL; the W
 *             twin of the current mode
 *   devices   EnumDisplayDevicesA/W resolved by GetProcAddress (the
 *             MSVC 6-era user32.lib predates them): of device 0
 *             (DeviceName as text, whether DeviceString is nonempty)
 *             and of device 1
 *   caps      CreateDCA("DISPLAY"), GetDeviceCaps of HORZRES, VERTRES,
 *             BITSPIXEL, PLANES, LOGPIXELSX, NUMCOLORS, then DeleteDC
 *   metrics   GetSystemMetrics of SM_CXSCREEN, SM_CYSCREEN,
 *             SM_CMOUSEBUTTONS, SM_CYCAPTION, SM_CXFRAME;
 *             SystemParametersInfoA/W SPI_GETWORKAREA and the rect
 *             each returns
 *   colors    GetSysColor of COLOR_WINDOW, COLOR_DESKTOP,
 *             COLOR_BTNTEXT; GetSysColorBrush(COLOR_WINDOW);
 *             SetSysColors to RGB(1,2,3) and back to the old value
 *   monitors  EnumDisplayMonitors with a counting callback; a hidden
 *             window's MonitorFromWindow; GetMonitorInfoA of the
 *             monitor (rcMonitor, rcWork, the primary flag);
 *             MonitorFromPoint far off-screen with
 *             MONITOR_DEFAULTTONULL; MonitorFromRect with
 *             MONITOR_DEFAULTTOPRIMARY
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guidisp):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guidisp.c user32.lib gdi32.lib
 */

/* The multi-monitor API (HMONITOR, EnumDisplayMonitors, MonitorFrom*,
 * GetMonitorInfoA/W) is declared by the SDK headers only when WINVER is
 * 0x0500 or later; Windows 2000 itself is 5.0. */
#ifndef WINVER
#define WINVER 0x0500
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif

#include "../common/f2kt.h"

/* The setup calls' last errors, captured where each call ran. */
static DWORD reg_err;
static DWORD create_err;

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProc(hwnd, msg, wparam, lparam);
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* Register the section's class; the result prints through reg_err. */
static ATOM register_class(const char *name)
{
    WNDCLASS wc;
    HMODULE inst;
    ATOM a;

    inst = GetModuleHandle(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = name;
    arm();
    a = RegisterClass(&wc);
    reg_err = GetLastError();
    return a;
}

/* A hidden window of the class, explicit 320x200 at 0,0. */
static HWND make_window(const char *class_name)
{
    HMODULE inst;
    HWND h;

    inst = GetModuleHandle(NULL);
    arm();
    h = CreateWindowEx(0, class_name, "F2K guidisp", WS_POPUP, 0, 0, 320, 200,
                       NULL, NULL, inst, NULL);
    create_err = GetLastError();
    return h;
}

/* --- enum ---------------------------------------------------------- */

static void sec_enum(void)
{
    DEVMODEA dm;
    DEVMODEW dmw;
    BOOL r;

    memset(&dm, 0, sizeof dm);
    dm.dmSize = sizeof dm;
    arm();
    r = EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm);
    line("EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm): ret=%d err=%s "
         "dmSize=%lu dmPelsWidth=%lu dmPelsHeight=%lu dmBitsPerPel=%lu dmFields=0x%lX",
         r, le(), (unsigned long)dm.dmSize, (unsigned long)dm.dmPelsWidth,
         (unsigned long)dm.dmPelsHeight, (unsigned long)dm.dmBitsPerPel,
         (unsigned long)dm.dmFields);

    memset(&dm, 0, sizeof dm);
    dm.dmSize = sizeof dm;
    arm();
    r = EnumDisplaySettingsA(NULL, 0, &dm);
    line("EnumDisplaySettingsA(NULL, 0, &dm): ret=%d err=%s "
         "dmSize=%lu dmPelsWidth=%lu dmPelsHeight=%lu dmBitsPerPel=%lu dmFields=0x%lX",
         r, le(), (unsigned long)dm.dmSize, (unsigned long)dm.dmPelsWidth,
         (unsigned long)dm.dmPelsHeight, (unsigned long)dm.dmBitsPerPel,
         (unsigned long)dm.dmFields);

    memset(&dm, 0, sizeof dm);
    dm.dmSize = sizeof dm;
    arm();
    r = EnumDisplaySettingsA(NULL, 9999, &dm);
    line("EnumDisplaySettingsA(NULL, 9999, &dm): ret=%d err=%s", r, le());

    memset(&dmw, 0, sizeof dmw);
    dmw.dmSize = sizeof dmw;
    arm();
    r = EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dmw);
    line("EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dmw): ret=%d err=%s "
         "dmSize=%lu dmPelsWidth=%lu dmPelsHeight=%lu dmBitsPerPel=%lu dmFields=0x%lX",
         r, le(), (unsigned long)dmw.dmSize, (unsigned long)dmw.dmPelsWidth,
         (unsigned long)dmw.dmPelsHeight, (unsigned long)dmw.dmBitsPerPel,
         (unsigned long)dmw.dmFields);
}

/* --- change -------------------------------------------------------- */

static void sec_change(void)
{
    DEVMODEA dm;
    DEVMODEW dmw;
    LONG r;

    memset(&dm, 0, sizeof dm);
    dm.dmSize = sizeof dm;
    EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm);
    arm();
    r = ChangeDisplaySettingsA(&dm, 0);
    line("ChangeDisplaySettingsA(&dm current, 0): ret=%ld err=%s", (long)r, le());
    arm();
    r = ChangeDisplaySettingsA(&dm, CDS_TEST);
    line("ChangeDisplaySettingsA(&dm current, CDS_TEST): ret=%ld err=%s", (long)r, le());

    memset(&dm, 0, sizeof dm);
    dm.dmSize = sizeof dm;
    dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;
    dm.dmPelsWidth = 1;
    dm.dmPelsHeight = 1;
    dm.dmBitsPerPel = 1;
    arm();
    r = ChangeDisplaySettingsA(&dm, 0);
    line("ChangeDisplaySettingsA(&dm 1x1x1, 0): ret=%ld err=%s", (long)r, le());

    arm();
    r = ChangeDisplaySettingsA(NULL, 0);
    line("ChangeDisplaySettingsA(NULL, 0): ret=%ld err=%s", (long)r, le());

    memset(&dmw, 0, sizeof dmw);
    dmw.dmSize = sizeof dmw;
    EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dmw);
    arm();
    r = ChangeDisplaySettingsW(&dmw, 0);
    line("ChangeDisplaySettingsW(&dmw current, 0): ret=%ld err=%s", (long)r, le());
}

/* --- devices ------------------------------------------------------- */

/* EnumDisplayDevicesA/W are Windows 2000 additions: the MSVC 6-era
 * user32.lib predates them, so resolve them by name at run time (the
 * established pattern for exports the import library lacks). */
typedef BOOL (WINAPI *PFN_EnumDisplayDevicesA)(LPCSTR, DWORD, DISPLAY_DEVICEA *, DWORD);
typedef BOOL (WINAPI *PFN_EnumDisplayDevicesW)(LPCWSTR, DWORD, DISPLAY_DEVICEW *, DWORD);

static void sec_devices(void)
{
    DISPLAY_DEVICEA dd;
    DISPLAY_DEVICEW ddw;
    PFN_EnumDisplayDevicesA pfnA;
    PFN_EnumDisplayDevicesW pfnW;
    HMODULE user32;
    BOOL r;

    arm();
    user32 = GetModuleHandleA("user32.dll");
    line("GetModuleHandleA(\"user32.dll\"): non-NULL %s err=%s", yesno(user32 != NULL), le());
    arm();
    pfnA = (PFN_EnumDisplayDevicesA)GetProcAddress(user32, "EnumDisplayDevicesA");
    line("GetProcAddress(user32, EnumDisplayDevicesA): non-NULL %s err=%s",
         yesno(pfnA != NULL), le());
    arm();
    pfnW = (PFN_EnumDisplayDevicesW)GetProcAddress(user32, "EnumDisplayDevicesW");
    line("GetProcAddress(user32, EnumDisplayDevicesW): non-NULL %s err=%s",
         yesno(pfnW != NULL), le());

    if (pfnA != NULL) {
        memset(&dd, 0, sizeof dd);
        dd.cb = sizeof dd;
        arm();
        r = pfnA(NULL, 0, &dd, 0);
        line("EnumDisplayDevicesA(NULL, 0, &dd, 0): ret=%d err=%s DeviceName=%s "
             "DeviceString nonempty %s",
             r, le(), dd.DeviceName, yesno(dd.DeviceString[0] != 0));

        memset(&dd, 0, sizeof dd);
        dd.cb = sizeof dd;
        arm();
        r = pfnA(NULL, 1, &dd, 0);
        line("EnumDisplayDevicesA(NULL, 1, &dd, 0): ret=%d err=%s", r, le());
    }

    if (pfnW != NULL) {
        memset(&ddw, 0, sizeof ddw);
        ddw.cb = sizeof ddw;
        arm();
        r = pfnW(NULL, 0, &ddw, 0);
        line("EnumDisplayDevicesW(NULL, 0, &ddw, 0): ret=%d err=%s DeviceName=%s "
             "DeviceString nonempty %s",
             r, le(), ws(ddw.DeviceName), yesno(ddw.DeviceString[0] != 0));
    }
}

/* --- caps ---------------------------------------------------------- */

static void sec_caps(void)
{
    HDC sdc;
    int v;
    BOOL r;

    arm();
    sdc = CreateDCA("DISPLAY", NULL, NULL, NULL);
    line("CreateDCA(\"DISPLAY\", NULL, NULL, NULL): non-NULL %s err=%s", yesno(sdc != NULL), le());
    if (sdc != NULL) {
        arm();
        v = GetDeviceCaps(sdc, HORZRES);
        line("GetDeviceCaps(HORZRES): ret=%d err=%s", v, le());
        arm();
        v = GetDeviceCaps(sdc, VERTRES);
        line("GetDeviceCaps(VERTRES): ret=%d err=%s", v, le());
        arm();
        v = GetDeviceCaps(sdc, BITSPIXEL);
        line("GetDeviceCaps(BITSPIXEL): ret=%d err=%s", v, le());
        arm();
        v = GetDeviceCaps(sdc, PLANES);
        line("GetDeviceCaps(PLANES): ret=%d err=%s", v, le());
        arm();
        v = GetDeviceCaps(sdc, LOGPIXELSX);
        line("GetDeviceCaps(LOGPIXELSX): ret=%d err=%s", v, le());
        arm();
        v = GetDeviceCaps(sdc, NUMCOLORS);
        line("GetDeviceCaps(NUMCOLORS): ret=%d err=%s", v, le());
        arm();
        r = DeleteDC(sdc);
        line("DeleteDC(sdc): ret=%d err=%s", r, le());
    }
}

/* --- metrics ------------------------------------------------------- */

static void sec_metrics(void)
{
    RECT rc;
    int v;
    BOOL r;

    arm();
    v = GetSystemMetrics(SM_CXSCREEN);
    line("GetSystemMetrics(SM_CXSCREEN): ret=%d err=%s", v, le());
    arm();
    v = GetSystemMetrics(SM_CYSCREEN);
    line("GetSystemMetrics(SM_CYSCREEN): ret=%d err=%s", v, le());
    arm();
    v = GetSystemMetrics(SM_CMOUSEBUTTONS);
    line("GetSystemMetrics(SM_CMOUSEBUTTONS): ret=%d err=%s", v, le());
    arm();
    v = GetSystemMetrics(SM_CYCAPTION);
    line("GetSystemMetrics(SM_CYCAPTION): ret=%d err=%s", v, le());
    arm();
    v = GetSystemMetrics(SM_CXFRAME);
    line("GetSystemMetrics(SM_CXFRAME): ret=%d err=%s", v, le());

    memset(&rc, 0, sizeof rc);
    arm();
    r = SystemParametersInfoA(SPI_GETWORKAREA, 0, &rc, 0);
    line("SystemParametersInfoA(SPI_GETWORKAREA, 0, &rc, 0): ret=%d err=%s "
         "workarea=%ld %ld %ld %ld",
         r, le(), rc.left, rc.top, rc.right, rc.bottom);

    memset(&rc, 0, sizeof rc);
    arm();
    r = SystemParametersInfoW(SPI_GETWORKAREA, 0, &rc, 0);
    line("SystemParametersInfoW(SPI_GETWORKAREA, 0, &rc, 0): ret=%d err=%s "
         "workarea=%ld %ld %ld %ld",
         r, le(), rc.left, rc.top, rc.right, rc.bottom);
}

/* --- colors -------------------------------------------------------- */

static void sec_colors(void)
{
    DWORD c;
    HBRUSH b;
    COLORREF old;
    COLORREF setc;
    int idx;
    BOOL r;

    arm();
    c = GetSysColor(COLOR_WINDOW);
    line("GetSysColor(COLOR_WINDOW): color=0x%06lX err=%s", (unsigned long)c, le());
    arm();
    c = GetSysColor(COLOR_DESKTOP);
    line("GetSysColor(COLOR_DESKTOP): color=0x%06lX err=%s", (unsigned long)c, le());
    arm();
    c = GetSysColor(COLOR_BTNTEXT);
    line("GetSysColor(COLOR_BTNTEXT): color=0x%06lX err=%s", (unsigned long)c, le());

    arm();
    b = GetSysColorBrush(COLOR_WINDOW);
    line("GetSysColorBrush(COLOR_WINDOW): non-NULL %s err=%s", yesno(b != NULL), le());

    old = GetSysColor(COLOR_WINDOW);
    idx = COLOR_WINDOW;
    setc = RGB(1, 2, 3);
    arm();
    r = SetSysColors(1, &idx, &setc);
    line("SetSysColors(1, {COLOR_WINDOW}, {RGB(1,2,3)}): ret=%d err=%s", r, le());
    arm();
    c = GetSysColor(COLOR_WINDOW);
    line("GetSysColor(COLOR_WINDOW) after the set: color=0x%06lX err=%s", (unsigned long)c, le());
    arm();
    r = SetSysColors(1, &idx, &old);
    line("SetSysColors(1, {COLOR_WINDOW}, old): ret=%d err=%s", r, le());
}

/* --- monitors ------------------------------------------------------ */

/* Counts the monitors EnumDisplayMonitors reports through its lParam. */
static BOOL CALLBACK count_monitor(HMONITOR hmon, HDC dc, LPRECT r, LPARAM p)
{
    (void)hmon;
    (void)dc;
    (void)r;
    *((int *)p) += 1;
    return TRUE;
}

static void sec_monitors(void)
{
    ATOM a;
    HWND h;
    HMONITOR hm;
    HMONITOR hm2;
    /* MONITORINFO, not MONITORINFOA: the Windows 2000-era SDK has only the
     * plain name (the A/W typedefs came in a later SDK). */
    MONITORINFO mi;
    POINT pt;
    RECT rc;
    int count;
    BOOL r;

    drain();
    count = 0;
    arm();
    r = EnumDisplayMonitors(NULL, NULL, count_monitor, (LPARAM)&count);
    line("EnumDisplayMonitors(NULL, NULL, count_monitor, &count): ret=%d err=%s count=%d",
         r, le(), count);

    a = register_class("F2KGuidispMon");
    line("RegisterClass(F2KGuidispMon): atom nonzero %s err=%s", yesno(a != 0), le_of(reg_err));
    h = make_window("F2KGuidispMon");
    line("CreateWindowEx(F2KGuidispMon, hidden, 320x200 at 0,0): non-NULL %s err=%s",
         yesno(h != NULL), le_of(create_err));

    arm();
    hm = MonitorFromWindow(h, MONITOR_DEFAULTTOPRIMARY);
    line("MonitorFromWindow(h, MONITOR_DEFAULTTOPRIMARY): non-NULL %s err=%s",
         yesno(hm != NULL), le());

    if (hm != NULL) {
        memset(&mi, 0, sizeof mi);
        mi.cbSize = sizeof mi;
        arm();
        r = GetMonitorInfoA(hm, &mi);
        line("GetMonitorInfoA(hm, &mi): ret=%d err=%s "
             "rcMonitor=%ld %ld %ld %ld rcWork=%ld %ld %ld %ld primary %s",
             r, le(), mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right,
             mi.rcMonitor.bottom, mi.rcWork.left, mi.rcWork.top, mi.rcWork.right,
             mi.rcWork.bottom, yesno((mi.dwFlags & MONITORINFOF_PRIMARY) != 0));
    }

    pt.x = -10000;
    pt.y = -10000;
    arm();
    hm2 = MonitorFromPoint(pt, MONITOR_DEFAULTTONULL);
    line("MonitorFromPoint({-10000, -10000}, MONITOR_DEFAULTTONULL): NULL %s err=%s",
         yesno(hm2 == NULL), le());

    rc.left = 0;
    rc.top = 0;
    rc.right = 100;
    rc.bottom = 100;
    arm();
    hm2 = MonitorFromRect(&rc, MONITOR_DEFAULTTOPRIMARY);
    line("MonitorFromRect({0, 0, 100, 100}, MONITOR_DEFAULTTOPRIMARY): non-NULL %s err=%s",
         yesno(hm2 != NULL), le());

    if (h != NULL) {
        arm();
        r = DestroyWindow(h);
        line("DestroyWindow(h): ret=%d err=%s", r, le());
    }
    drain();
}

static const section_t sections[] = {
    { "enum", sec_enum, F2KT_ALWAYS },
    { "change", sec_change, F2KT_ALWAYS },
    { "devices", sec_devices, F2KT_ALWAYS },
    { "caps", sec_caps, F2KT_ALWAYS },
    { "metrics", sec_metrics, F2KT_ALWAYS },
    { "colors", sec_colors, F2KT_ALWAYS },
    { "monitors", sec_monitors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bogus mode or a bogus handle goes to the calls: should one
     * fault, no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guidisp", sections, argc, argv);
}
