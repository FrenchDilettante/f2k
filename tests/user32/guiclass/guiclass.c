/*
 * guiclass - window class registration in user32: RegisterClassA/W,
 * RegisterClassExA/W, UnregisterClassA/W, GetClassInfoA/W and
 * GetClassNameA/W.
 *
 * Atoms are never printed as values: a registration line prints whether
 * the returned atom is nonzero, a query line whether the returned atom
 * matches the registered one, and handles compare through yesno. A
 * buffer handed to a call starts filled with 0xCC bytes. Each section
 * registers its own classes silently first and unregisters them again at
 * the end, so every section runs alone (the suite runs each section as
 * its own process) and in order with no argument. GetClassName takes a
 * window handle, so the sections that call it create a 320x200 window
 * of the registered class at an explicit position (nothing absolute is
 * printed), destroy it again, and drain posted messages with GetMessage.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   register    RegisterClassA of a full WNDCLASSA (CS_HREDRAW|CS_VREDRAW,
 *               a local wndproc, hInstance GetModuleHandleA(NULL),
 *               hCursor LoadCursorA(NULL,IDC_ARROW), hbrBackground
 *               (HBRUSH)(COLOR_WINDOW+1), class "F2KGuiClass"), then
 *               RegisterClassExA, RegisterClassExW and RegisterClassW of
 *               the wide-named class L"F2KGuiClassW": nonzero atom, err
 *   query       GetClassInfoA/W of the registered classes by their atoms:
 *               ret, err, and the style, background brush and wndproc
 *               read back equal to the registered ones; GetClassNameA/W
 *               on a window of the class: ret, err, the text in the
 *               buffer
 *   duplicate   RegisterClassA/W again with the same class names: ret,
 *               err
 *   unregister  UnregisterClassA of the atom, and again; UnregisterClassW
 *               of the wide atom: ret, err; then the name and the info
 *               of the unregistered class: ret, err
 *   errors      RegisterClassA with a NULL wndproc; GetClassInfoA with a
 *               bogus atom 0x7FFF: ret, err
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat guiclass):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guiclass.c user32.lib
 */

#include "../common/f2kt.h"

/* The module handle every class is registered with. */
static HINSTANCE g_hinst;

static LRESULT CALLBACK gui_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hwnd, msg, wparam, lparam);
    }
}

/* Fill a WNDCLASSA the same way every time. */
static void fill_class_a(WNDCLASSA *wc, const char *name)
{
    memset(wc, 0, sizeof *wc);
    wc->style = CS_HREDRAW | CS_VREDRAW;
    wc->lpfnWndProc = gui_wndproc;
    wc->hInstance = g_hinst;
    wc->hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc->hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc->lpszClassName = name;
}

/* The W twin. */
static void fill_class_w(WNDCLASSW *wc, const WCHAR *name)
{
    memset(wc, 0, sizeof *wc);
    wc->style = CS_HREDRAW | CS_VREDRAW;
    wc->lpfnWndProc = gui_wndproc;
    wc->hInstance = g_hinst;
    wc->hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc->hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc->lpszClassName = name;
}

/* Fill a WNDCLASSEXA the same way every time. */
static void fill_ex_a(WNDCLASSEXA *wc, const char *name)
{
    memset(wc, 0, sizeof *wc);
    wc->cbSize = sizeof *wc;
    wc->style = CS_HREDRAW | CS_VREDRAW;
    wc->lpfnWndProc = gui_wndproc;
    wc->hInstance = g_hinst;
    wc->hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc->hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc->lpszClassName = name;
}

/* The W twin. */
static void fill_ex_w(WNDCLASSEXW *wc, const WCHAR *name)
{
    memset(wc, 0, sizeof *wc);
    wc->cbSize = sizeof *wc;
    wc->style = CS_HREDRAW | CS_VREDRAW;
    wc->lpfnWndProc = gui_wndproc;
    wc->hInstance = g_hinst;
    wc->hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc->hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc->lpszClassName = name;
}

/* A 320x200 window of `class_name` at an explicit position. */
static HWND make_window(const char *class_name)
{
    return CreateWindowExA(0, class_name, "F2K guiclass", WS_OVERLAPPEDWINDOW,
                           0, 0, 320, 200, NULL, NULL, g_hinst, NULL);
}

/* Drain posted messages until WM_QUIT. */
static void drain(void)
{
    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

/* --- register ------------------------------------------------------ */

static void sec_register(void)
{
    WNDCLASSA wc;
    WNDCLASSEXA wcex;
    WNDCLASSEXW wcexw;
    WNDCLASSW wcw;
    ATOM a, ax, axw, aw;

    fill_class_a(&wc, "F2KGuiClass");
    arm();
    a = RegisterClassA(&wc);
    line("RegisterClassA(\"F2KGuiClass\"): nonzero %s err=%s", yesno(a != 0), le());

    fill_ex_a(&wcex, "F2KGuiClassEx");
    arm();
    ax = RegisterClassExA(&wcex);
    line("RegisterClassExA(\"F2KGuiClassEx\"): nonzero %s err=%s", yesno(ax != 0), le());

    fill_ex_w(&wcexw, L"F2KGuiClassExW");
    arm();
    axw = RegisterClassExW(&wcexw);
    line("RegisterClassExW(L\"F2KGuiClassExW\"): nonzero %s err=%s", yesno(axw != 0), le());

    fill_class_w(&wcw, L"F2KGuiClassW");
    arm();
    aw = RegisterClassW(&wcw);
    line("RegisterClassW(L\"F2KGuiClassW\"): nonzero %s err=%s", yesno(aw != 0), le());

    /* Leave nothing behind: the next section (or run) registers the
     * same names again. */
    UnregisterClassA((LPCSTR)(DWORD)a, g_hinst);
    UnregisterClassA((LPCSTR)(DWORD)ax, g_hinst);
    UnregisterClassW((LPCWSTR)(DWORD)axw, g_hinst);
    UnregisterClassW((LPCWSTR)(DWORD)aw, g_hinst);
}

/* --- query --------------------------------------------------------- */

static void sec_query(void)
{
    WNDCLASSA wc, out;
    WNDCLASSW wcw, outw;
    ATOM a, aw, r;
    HWND hwnd;
    BOOL br;
    char buf[64];
    WCHAR wbuf[64];
    int n;

    /* Setup, silent: the two standard classes. */
    fill_class_a(&wc, "F2KGuiClass");
    a = RegisterClassA(&wc);
    fill_class_w(&wcw, L"F2KGuiClassW");
    aw = RegisterClassW(&wcw);

    memset(&out, 0xCC, sizeof out);
    arm();
    r = GetClassInfoA(g_hinst, (LPCSTR)(DWORD)a, &out);
    line("GetClassInfoA(hinst, atom): nonzero %s same atom %s err=%s",
         yesno(r != 0), yesno(r == a), le());
    line("GetClassInfoA read back: style %s hbrBackground %s lpfnWndProc %s",
         yesno(out.style == (CS_HREDRAW | CS_VREDRAW)),
         yesno(out.hbrBackground == (HBRUSH)(COLOR_WINDOW + 1)),
         yesno(out.lpfnWndProc == gui_wndproc));

    memset(&outw, 0xCC, sizeof outw);
    arm();
    r = GetClassInfoW(g_hinst, (LPCWSTR)(DWORD)aw, &outw);
    line("GetClassInfoW(hinst, wide atom): nonzero %s same atom %s err=%s",
         yesno(r != 0), yesno(r == aw), le());
    line("GetClassInfoW read back: style %s hbrBackground %s lpfnWndProc %s",
         yesno(outw.style == (CS_HREDRAW | CS_VREDRAW)),
         yesno(outw.hbrBackground == (HBRUSH)(COLOR_WINDOW + 1)),
         yesno(outw.lpfnWndProc == gui_wndproc));

    arm();
    hwnd = make_window("F2KGuiClass");
    line("CreateWindowExA(\"F2KGuiClass\", 320x200): non-NULL %s err=%s",
         yesno(hwnd != NULL), le());

    memset(buf, 0xCC, sizeof buf);
    arm();
    n = GetClassNameA(hwnd, buf, (int)sizeof buf);
    buf[sizeof buf - 1] = '\0';
    line("GetClassNameA: ret=%d err=%s", n, le());
    line("GetClassNameA buffer: %s", buf);

    memset(wbuf, 0xCC, sizeof wbuf);
    arm();
    n = GetClassNameW(hwnd, wbuf, (int)(sizeof wbuf / sizeof wbuf[0]));
    wbuf[sizeof wbuf / sizeof wbuf[0] - 1] = 0;
    line("GetClassNameW: ret=%d err=%s", n, le());
    line("GetClassNameW buffer: %s", ws(wbuf));

    arm();
    br = DestroyWindow(hwnd);
    line("DestroyWindow: ret=%d err=%s", br, le());
    drain();

    UnregisterClassA((LPCSTR)(DWORD)a, g_hinst);
    UnregisterClassW((LPCWSTR)(DWORD)aw, g_hinst);
}

/* --- duplicate ----------------------------------------------------- */

static void sec_duplicate(void)
{
    WNDCLASSA wc;
    WNDCLASSW wcw;
    ATOM a, aw, r;

    /* Setup, silent: the two standard classes. */
    fill_class_a(&wc, "F2KGuiClass");
    a = RegisterClassA(&wc);
    fill_class_w(&wcw, L"F2KGuiClassW");
    aw = RegisterClassW(&wcw);

    arm();
    r = RegisterClassA(&wc);
    line("RegisterClassA(\"F2KGuiClass\") again: nonzero %s err=%s", yesno(r != 0), le());

    arm();
    r = RegisterClassW(&wcw);
    line("RegisterClassW(L\"F2KGuiClassW\") again: nonzero %s err=%s", yesno(r != 0), le());

    UnregisterClassA((LPCSTR)(DWORD)a, g_hinst);
    UnregisterClassW((LPCWSTR)(DWORD)aw, g_hinst);
}

/* --- unregister ---------------------------------------------------- */

static void sec_unregister(void)
{
    WNDCLASSA wc, out;
    WNDCLASSW wcw;
    ATOM a, aw, r;
    HWND hwnd;
    BOOL br;
    char buf[64];
    int n;

    /* Setup, silent: the two standard classes. */
    fill_class_a(&wc, "F2KGuiClass");
    a = RegisterClassA(&wc);
    fill_class_w(&wcw, L"F2KGuiClassW");
    aw = RegisterClassW(&wcw);

    /* A window of the class, destroyed again: a class with windows
     * does not unregister, and a window handle is what GetClassName
     * takes. */
    arm();
    hwnd = make_window("F2KGuiClass");
    line("CreateWindowExA(\"F2KGuiClass\", 320x200): non-NULL %s err=%s",
         yesno(hwnd != NULL), le());
    arm();
    br = DestroyWindow(hwnd);
    line("DestroyWindow: ret=%d err=%s", br, le());
    drain();

    arm();
    br = UnregisterClassA((LPCSTR)(DWORD)a, g_hinst);
    line("UnregisterClassA(atom): ret=%d err=%s", br, le());
    arm();
    br = UnregisterClassA((LPCSTR)(DWORD)a, g_hinst);
    line("UnregisterClassA(atom) again: ret=%d err=%s", br, le());
    arm();
    br = UnregisterClassW((LPCWSTR)(DWORD)aw, g_hinst);
    line("UnregisterClassW(wide atom): ret=%d err=%s", br, le());

    memset(buf, 0xCC, sizeof buf);
    arm();
    n = GetClassNameA(hwnd, buf, (int)sizeof buf);
    buf[sizeof buf - 1] = '\0';
    line("GetClassNameA(the destroyed window): ret=%d err=%s", n, le());

    memset(&out, 0xCC, sizeof out);
    arm();
    r = GetClassInfoA(g_hinst, (LPCSTR)(DWORD)a, &out);
    line("GetClassInfoA(the unregistered atom): nonzero %s err=%s", yesno(r != 0), le());
}

/* --- errors -------------------------------------------------------- */

static void sec_errors(void)
{
    WNDCLASSA wc, out;
    ATOM r;

    fill_class_a(&wc, "F2KGuiClass");
    wc.lpfnWndProc = NULL;
    arm();
    r = RegisterClassA(&wc);
    line("RegisterClassA(lpfnWndProc NULL): nonzero %s err=%s", yesno(r != 0), le());

    memset(&out, 0xCC, sizeof out);
    arm();
    r = GetClassInfoA(g_hinst, (LPCSTR)(DWORD)0x7FFF, &out);
    line("GetClassInfoA(atom 0x7FFF): ret=%d err=%s", (int)r, le());
}

static const section_t sections[] = {
    { "register", sec_register, F2KT_ALWAYS },
    { "query", sec_query, F2KT_ALWAYS },
    { "duplicate", sec_duplicate, F2KT_ALWAYS },
    { "unregister", sec_unregister, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* Bogus atoms and arguments go to the calls: should one fault, no
     * dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    g_hinst = GetModuleHandleA(NULL);
    return run_sections("guiclass", sections, argc, argv);
}
