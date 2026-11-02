/*
 * guidc - the device-context calls of user32 (GetDC, GetDCEx,
 * GetWindowDC, ReleaseDC, WindowFromDC) and the gdi32 text, object and
 * pixel calls over those DCs (TextOutA/W, ExtTextOutA/W, SetTextColor,
 * SetBkColor, SetBkMode, GetTextExtentPoint32A/W, GetTextMetricsA/W,
 * GetStockObject, SelectObject, DeleteObject, SetPixel, GetPixel).
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line
 * prints ret= and err=; no handle value, address or thread id is
 * printed, handles compare through yesno(); colors print as 0x%06lX,
 * rects and coordinates as plain numbers. Each section that needs a
 * window registers its own class and creates one hidden 320x200 window
 * at explicit coordinates, and destroys it before it ends; every
 * section starts by draining the queue (a PeekMessageA PM_REMOVE loop)
 * so the sections are independent. The wndproc answers WM_PAINT with
 * BeginPaint/EndPaint and WM_DESTROY with PostQuitMessage.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   dc       GetDC(h) and the WindowFromDC round trip, ReleaseDC; the
 *            screen DC from GetDC(NULL); GetWindowDC;
 *            GetDCEx(h, NULL, DCX_WINDOW); ReleaseDC of each
 *   text     TextOutA/W; ExtTextOutA/W with ETO_OPAQUE over a rect;
 *            SetTextColor and SetBkColor (each prints the previous
 *            color), SetBkMode TRANSPARENT then OPAQUE (the previous
 *            mode)
 *   extent   GetTextExtentPoint32A/W (cx, cy); GetTextMetricsA/W
 *            (tmHeight, tmAveCharWidth)
 *   objects  GetStockObject(WHITE_BRUSH) and GetStockObject(SYSTEM_FONT);
 *            SelectObject of the brush (the previous object non-NULL);
 *            DeleteObject of it
 *   pixel    on the screen DC: SetPixel (the previous color), GetPixel
 *            (the color read back), ReleaseDC
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guidc):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guidc.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;

        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

/* Empty the queue, so one section's leftovers never reach the next. */
static void drain(void)
{
    MSG m;

    while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
    }
}

/* Register the class and create one hidden 320x200 window of it at
 * 0,0, printing both calls. */
static HWND make_window(const char *class_name)
{
    WNDCLASS wc;
    HINSTANCE inst;
    ATOM a;
    HWND h;

    inst = (HINSTANCE)GetModuleHandle(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;
    arm();
    a = RegisterClass(&wc);
    line("RegisterClass(%s): atom nonzero %s err=%s", class_name, yesno(a != 0), le());
    arm();
    h = CreateWindowEx(0, class_name, "guidc", WS_POPUP, 0, 0, 320, 200, NULL, NULL, inst, NULL);
    line("CreateWindowEx(%s, hidden, 0,0 320x200): non-NULL %s err=%s", class_name,
         yesno(h != NULL), le());
    return h;
}

static void destroy_window(HWND h)
{
    if (h != NULL) {
        DestroyWindow(h);
    }
}

/* --- dc ------------------------------------------------------------ */

static void sec_dc(void)
{
    HWND h, back;
    HDC hdc, sdc, wdc, edc;
    int r;

    drain();
    h = make_window("F2KGuidcDc");

    arm();
    hdc = GetDC(h);
    line("GetDC(h): non-NULL %s err=%s", yesno(hdc != NULL), le());
    arm();
    back = WindowFromDC(hdc);
    line("WindowFromDC(hdc)==h: %s err=%s", yesno(back == h), le());
    arm();
    r = ReleaseDC(h, hdc);
    line("ReleaseDC(h, hdc): ret=%d err=%s", r, le());

    arm();
    sdc = GetDC(NULL);
    line("GetDC(NULL) (the screen): non-NULL %s err=%s", yesno(sdc != NULL), le());
    arm();
    wdc = GetWindowDC(h);
    line("GetWindowDC(h): non-NULL %s err=%s", yesno(wdc != NULL), le());
    arm();
    edc = GetDCEx(h, NULL, DCX_WINDOW);
    line("GetDCEx(h, NULL, DCX_WINDOW): non-NULL %s err=%s", yesno(edc != NULL), le());

    arm();
    r = ReleaseDC(h, edc);
    line("ReleaseDC(h, the GetDCEx DC): ret=%d err=%s", r, le());
    arm();
    r = ReleaseDC(h, wdc);
    line("ReleaseDC(h, the GetWindowDC DC): ret=%d err=%s", r, le());
    arm();
    r = ReleaseDC(NULL, sdc);
    line("ReleaseDC(NULL, the screen DC): ret=%d err=%s", r, le());

    destroy_window(h);
}

/* --- text ---------------------------------------------------------- */

static void sec_text(void)
{
    HWND h;
    HDC hdc;
    RECT rc;
    COLORREF prev;
    int r, mode;

    drain();
    h = make_window("F2KGuidcText");
    arm();
    hdc = GetDC(h);
    line("GetDC(h): non-NULL %s err=%s", yesno(hdc != NULL), le());

    arm();
    r = TextOutA(hdc, 5, 5, "Hi", 2);
    line("TextOutA(hdc, 5, 5, \"Hi\", 2): ret=%d err=%s", r, le());
    arm();
    r = TextOutW(hdc, 5, 25, L"Hi", 2);
    line("TextOutW(hdc, 5, 25, L\"Hi\", 2): ret=%d err=%s", r, le());

    rc.left = 0;
    rc.top = 40;
    rc.right = 100;
    rc.bottom = 60;
    arm();
    r = ExtTextOutA(hdc, 0, 40, ETO_OPAQUE, &rc, "abc", 3, NULL);
    line("ExtTextOutA(hdc, 0, 40, ETO_OPAQUE, rect 0 40 100 60, \"abc\", 3, NULL): ret=%d err=%s",
         r, le());
    arm();
    r = ExtTextOutW(hdc, 0, 40, ETO_OPAQUE, &rc, L"abc", 3, NULL);
    line("ExtTextOutW(hdc, 0, 40, ETO_OPAQUE, rect 0 40 100 60, L\"abc\", 3, NULL): ret=%d err=%s",
         r, le());

    arm();
    prev = SetTextColor(hdc, RGB(255, 0, 0));
    line("SetTextColor(hdc, RGB(255,0,0)): previous=0x%06lX err=%s", (unsigned long)prev, le());
    arm();
    prev = SetBkColor(hdc, RGB(0, 0, 255));
    line("SetBkColor(hdc, RGB(0,0,255)): previous=0x%06lX err=%s", (unsigned long)prev, le());
    arm();
    mode = SetBkMode(hdc, TRANSPARENT);
    line("SetBkMode(hdc, TRANSPARENT): previous=%d err=%s", mode, le());
    arm();
    mode = SetBkMode(hdc, OPAQUE);
    line("SetBkMode(hdc, OPAQUE): previous=%d err=%s", mode, le());

    arm();
    r = ReleaseDC(h, hdc);
    line("ReleaseDC(h, hdc): ret=%d err=%s", r, le());
    destroy_window(h);
}

/* --- extent -------------------------------------------------------- */

static void sec_extent(void)
{
    HWND h;
    HDC hdc;
    SIZE sz;
    TEXTMETRICA tma;
    TEXTMETRICW tmw;
    int r;

    drain();
    h = make_window("F2KGuidcExtent");
    arm();
    hdc = GetDC(h);
    line("GetDC(h): non-NULL %s err=%s", yesno(hdc != NULL), le());

    arm();
    r = GetTextExtentPoint32A(hdc, "Hello", 5, &sz);
    line("GetTextExtentPoint32A(hdc, \"Hello\", 5, &sz): ret=%d err=%s cx=%ld cy=%ld", r, le(),
         (long)sz.cx, (long)sz.cy);
    arm();
    r = GetTextExtentPoint32W(hdc, L"Hello", 5, &sz);
    line("GetTextExtentPoint32W(hdc, L\"Hello\", 5, &sz): ret=%d err=%s cx=%ld cy=%ld", r, le(),
         (long)sz.cx, (long)sz.cy);

    arm();
    r = GetTextMetricsA(hdc, &tma);
    line("GetTextMetricsA(hdc, &tm): ret=%d err=%s tmHeight=%ld tmAveCharWidth=%ld", r, le(),
         (long)tma.tmHeight, (long)tma.tmAveCharWidth);
    arm();
    r = GetTextMetricsW(hdc, &tmw);
    line("GetTextMetricsW(hdc, &tm): ret=%d err=%s tmHeight=%ld tmAveCharWidth=%ld", r, le(),
         (long)tmw.tmHeight, (long)tmw.tmAveCharWidth);

    arm();
    r = ReleaseDC(h, hdc);
    line("ReleaseDC(h, hdc): ret=%d err=%s", r, le());
    destroy_window(h);
}

/* --- objects ------------------------------------------------------- */

static void sec_objects(void)
{
    HWND h;
    HDC hdc;
    HGDIOBJ brush, font, prev;
    int r;

    drain();
    h = make_window("F2KGuidcObjects");
    arm();
    hdc = GetDC(h);
    line("GetDC(h): non-NULL %s err=%s", yesno(hdc != NULL), le());

    arm();
    brush = GetStockObject(WHITE_BRUSH);
    line("GetStockObject(WHITE_BRUSH): non-NULL %s err=%s", yesno(brush != NULL), le());
    arm();
    font = GetStockObject(SYSTEM_FONT);
    line("GetStockObject(SYSTEM_FONT): non-NULL %s err=%s", yesno(font != NULL), le());
    arm();
    prev = SelectObject(hdc, brush);
    line("SelectObject(hdc, the WHITE_BRUSH): previous non-NULL %s err=%s", yesno(prev != NULL),
         le());
    arm();
    r = DeleteObject(brush);
    line("DeleteObject(the WHITE_BRUSH): ret=%d err=%s", r, le());

    arm();
    r = ReleaseDC(h, hdc);
    line("ReleaseDC(h, hdc): ret=%d err=%s", r, le());
    destroy_window(h);
}

/* --- pixel --------------------------------------------------------- */

static void sec_pixel(void)
{
    HDC sdc;
    COLORREF prev, c;
    int r;

    drain();
    arm();
    sdc = GetDC(NULL);
    line("GetDC(NULL) (the screen): non-NULL %s err=%s", yesno(sdc != NULL), le());
    arm();
    prev = SetPixel(sdc, 100, 100, RGB(1, 2, 3));
    line("SetPixel(sdc, 100, 100, RGB(1,2,3)): previous=0x%06lX err=%s", (unsigned long)prev, le());
    arm();
    c = GetPixel(sdc, 100, 100);
    line("GetPixel(sdc, 100, 100): 0x%06lX err=%s", (unsigned long)c, le());
    arm();
    r = ReleaseDC(NULL, sdc);
    line("ReleaseDC(NULL, sdc): ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "dc", sec_dc, F2KT_ALWAYS },
    { "text", sec_text, F2KT_ALWAYS },
    { "extent", sec_extent, F2KT_ALWAYS },
    { "objects", sec_objects, F2KT_ALWAYS },
    { "pixel", sec_pixel, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad DC or object would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("guidc", sections, argc, argv);
}
