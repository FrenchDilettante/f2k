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
 *   infoex      GetClassInfoExW and GetClassInfoExA of a class
 *               registered with RegisterClassExW (8 class bytes, 4
 *               window bytes, an icon and no small icon, a menu name):
 *               by name and by atom, with cbSize 0, with hInstance
 *               NULL, of a name never registered; every field read
 *               back, as a value or as the same as the registered one;
 *               the system classes Button and #32770 with hInstance
 *               NULL: their style and extra bytes
 *   classlong   GetClassLongW and GetClassLongA of each GCL_ index on a
 *               window of a class registered with RegisterClassExW;
 *               SetClassLongW and SetClassLongA of the class's extra
 *               bytes (in range, straddling the end, past it), of
 *               GCL_STYLE, GCL_HBRBACKGROUND and GCL_WNDPROC (the
 *               window's own procedure left as it was), each read back;
 *               NULL and destroyed windows, a bad index, and the
 *               desktop window's class style
 *
 * Handles, procedures and pointers in infoex and classlong print only
 * as the same as the registered ones or not; a menu name prints as its
 * text, read inside __try.
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

/* --- infoex -------------------------------------------------------- */

static const WCHAR menu_name_w[] = { 'F', '2', 'K', 'M', 'e', 'n', 'u', 0 };

/* A wide text as printed, read inside __try: "(null)", the text, or
 * "(unreadable)". */
static const char *safe_ws(const WCHAR *s)
{
    const char *r = "(unreadable)";

    __try {
        r = ws(s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r = "(unreadable)";
    }
    return r;
}

/* An ANSI text as printed, read inside __try, its bytes 0x20-0x7E only
 * (any other as '?'). */
static const char *safe_as(const char *s)
{
    static char buf[4][80];
    static int next;
    char *b = buf[next++ & 3];
    int i;

    if (s == NULL) {
        return "(null)";
    }
    __try {
        for (i = 0; i < 79 && s[i] != '\0'; i++) {
            b[i] = (s[i] >= 0x20 && s[i] <= 0x7E) ? s[i] : '?';
        }
        b[i] = '\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "(unreadable)";
    }
    return b;
}

/* A small icon as read back: NULL, the class's large icon, or another. */
static const char *icon_sm(HICON sm, HICON large)
{
    if (sm == NULL) {
        return "NULL";
    }
    return sm == large ? "the large icon" : "another icon";
}

/* The fields of a WNDCLASSEXW read back, against the registered ones
 * (`name` the pointer passed to the query, `by_name` whether it was a
 * name rather than an atom). */
static void print_ex_w(const WNDCLASSEXW *c, const WCHAR *name, int by_name, HICON icon,
                       HCURSOR cursor)
{
    line("  cbSize=%u style=0x%X cbClsExtra=%d cbWndExtra=%d", c->cbSize, c->style, c->cbClsExtra,
         c->cbWndExtra);
    line("  lpfnWndProc ours %s, hInstance ours %s, hIcon the registered %s, hIconSm %s, "
         "hCursor the arrow %s, hbrBackground COLOR_WINDOW+1 %s",
         yesno(c->lpfnWndProc == gui_wndproc), yesno(c->hInstance == g_hinst),
         yesno(c->hIcon == icon), icon_sm(c->hIconSm, c->hIcon), yesno(c->hCursor == cursor),
         yesno(c->hbrBackground == (HBRUSH)(COLOR_WINDOW + 1)));
    line("  lpszMenuName the registered pointer %s, text \"%s\"; lpszClassName the name passed %s%s%s%s",
         yesno(c->lpszMenuName == menu_name_w),
         c->lpszMenuName == NULL ? "(null)" : safe_ws(c->lpszMenuName),
         yesno(c->lpszClassName == name), by_name ? ", text \"" : "",
         by_name ? safe_ws(c->lpszClassName) : "", by_name ? "\"" : "");
}

/* A system class's fields: values that are not handles, and the rest as
 * relations. */
static void print_system(const WNDCLASSEXW *c)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    char brush[32];

    if (c->hbrBackground == NULL) {
        sprintf(brush, "NULL");
    } else if ((DWORD)c->hbrBackground <= 32) {
        sprintf(brush, "color index+1 %lu", (DWORD)c->hbrBackground);
    } else {
        sprintf(brush, "a brush");
    }
    line("  style=0x%X cbClsExtra=%d cbWndExtra=%d lpfnWndProc non-NULL %s, hInstance %s, "
         "hIcon NULL %s, hCursor the arrow %s, hbrBackground %s, lpszMenuName NULL %s",
         c->style, c->cbClsExtra, c->cbWndExtra, yesno(c->lpfnWndProc != NULL),
         c->hInstance == NULL ? "NULL" : c->hInstance == (HINSTANCE)user ? "user32's" : "another",
         yesno(c->hIcon == NULL), yesno(c->hCursor == LoadCursorA(NULL, IDC_ARROW)), brush,
         yesno(c->lpszMenuName == NULL));
}

static void sec_infoex(void)
{
    static const WCHAR name[] = { 'F', '2', 'K', 'G', 'u', 'i', 'C', 'l', 'a', 's', 's', 'I',
                                  'n', 'f', 'o', 0 };
    static const WCHAR none[] = { 'F', '2', 'K', 'G', 'u', 'i', 'C', 'l', 'a', 's', 's', 'N',
                                  'o', 'n', 'e', 0 };
    static const WCHAR button[] = { 'B', 'u', 't', 't', 'o', 'n', 0 };
    static const WCHAR dialog[] = { '#', '3', '2', '7', '7', '0', 0 };
    WNDCLASSEXW wc, out;
    WNDCLASSEXA outa;
    HICON icon;
    HCURSOR cursor;
    ATOM a, r;

    icon = LoadIconA(NULL, IDI_APPLICATION);
    cursor = LoadCursorA(NULL, IDC_ARROW);
    fill_ex_w(&wc, name);
    wc.cbClsExtra = 8;
    wc.cbWndExtra = 4;
    wc.hIcon = icon;
    wc.hIconSm = NULL;
    wc.lpszMenuName = menu_name_w;
    arm();
    a = RegisterClassExW(&wc);
    line("RegisterClassExW(L\"F2KGuiClassInfo\", 8 class bytes, 4 window bytes, an icon, no small "
         "icon, menu L\"F2KMenu\"): nonzero %s err=%s",
         yesno(a != 0), le());

    memset(&out, 0xCC, sizeof out);
    out.cbSize = sizeof out;
    arm();
    r = GetClassInfoExW(g_hinst, name, &out);
    line("GetClassInfoExW(hinst, L\"F2KGuiClassInfo\"): nonzero %s, the class's atom %s err=%s",
         yesno(r != 0), yesno(r == a), le());
    print_ex_w(&out, name, 1, icon, cursor);

    memset(&out, 0xCC, sizeof out);
    out.cbSize = sizeof out;
    arm();
    r = GetClassInfoExW(g_hinst, (LPCWSTR)(DWORD)a, &out);
    line("GetClassInfoExW(hinst, its atom): nonzero %s, the class's atom %s err=%s",
         yesno(r != 0), yesno(r == a), le());
    print_ex_w(&out, (LPCWSTR)(DWORD)a, 0, icon, cursor);

    memset(&out, 0xCC, sizeof out);
    out.cbSize = 0;
    arm();
    r = GetClassInfoExW(g_hinst, name, &out);
    line("GetClassInfoExW(hinst, L\"F2KGuiClassInfo\"), cbSize 0: nonzero %s err=%s cbSize=%u "
         "style=0x%X",
         yesno(r != 0), le(), out.cbSize, out.style);

    memset(&outa, 0xCC, sizeof outa);
    outa.cbSize = sizeof outa;
    arm();
    r = GetClassInfoExA(g_hinst, "F2KGuiClassInfo", &outa);
    line("GetClassInfoExA(hinst, \"F2KGuiClassInfo\"): nonzero %s, the class's atom %s err=%s",
         yesno(r != 0), yesno(r == a), le());
    line("  cbSize=%u style=0x%X cbClsExtra=%d cbWndExtra=%d lpfnWndProc ours %s, hIcon the "
         "registered %s, hIconSm %s, lpszMenuName \"%s\", lpszClassName \"%s\"",
         outa.cbSize, outa.style, outa.cbClsExtra, outa.cbWndExtra,
         yesno(outa.lpfnWndProc == gui_wndproc), yesno(outa.hIcon == icon),
         icon_sm(outa.hIconSm, outa.hIcon), safe_as(outa.lpszMenuName),
         safe_as(outa.lpszClassName));

    memset(&out, 0xCC, sizeof out);
    out.cbSize = sizeof out;
    arm();
    r = GetClassInfoExW(NULL, name, &out);
    line("GetClassInfoExW(NULL, L\"F2KGuiClassInfo\"): nonzero %s err=%s", yesno(r != 0), le());

    memset(&out, 0xCC, sizeof out);
    out.cbSize = sizeof out;
    arm();
    r = GetClassInfoExW(g_hinst, none, &out);
    line("GetClassInfoExW(hinst, L\"F2KGuiClassNone\"), never registered: nonzero %s err=%s",
         yesno(r != 0), le());

    memset(&out, 0xCC, sizeof out);
    out.cbSize = sizeof out;
    arm();
    r = GetClassInfoExW(NULL, button, &out);
    line("GetClassInfoExW(NULL, L\"Button\"): nonzero %s err=%s", yesno(r != 0), le());
    if (r != 0) {
        print_system(&out);
    }

    memset(&out, 0xCC, sizeof out);
    out.cbSize = sizeof out;
    arm();
    r = GetClassInfoExW(NULL, dialog, &out);
    line("GetClassInfoExW(NULL, L\"#32770\"): nonzero %s, 32770 %s err=%s", yesno(r != 0),
         yesno(r == 32770), le());
    if (r != 0) {
        print_system(&out);
    }

    UnregisterClassW(name, g_hinst);
}

/* --- classlong ----------------------------------------------------- */

static LRESULT CALLBACK other_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void get_long(HWND h, const char *index_name, int index)
{
    DWORD w, a;
    DWORD ew, ea;

    arm();
    w = GetClassLongW(h, index);
    ew = GetLastError();
    arm();
    a = GetClassLongA(h, index);
    ea = GetLastError();
    line("GetClassLongW(%s)=0x%lX err=%s, GetClassLongA=0x%lX err=%s", index_name, w, le_of(ew),
         a, le_of(ea));
}

/* A value that is a handle, procedure or pointer: as relations. */
static void get_long_rel(HWND h, const char *index_name, int index, DWORD expected)
{
    DWORD w, a;
    DWORD ew, ea;

    arm();
    w = GetClassLongW(h, index);
    ew = GetLastError();
    arm();
    a = GetClassLongA(h, index);
    ea = GetLastError();
    line("GetClassLongW(%s): the registered value %s, nonzero %s err=%s; GetClassLongA: the "
         "registered value %s, nonzero %s err=%s",
         index_name, yesno(w == expected), yesno(w != 0), le_of(ew), yesno(a == expected),
         yesno(a != 0), le_of(ea));
}

static void set_long_w(HWND h, const char *index_name, int index, DWORD value)
{
    DWORD r;

    arm();
    r = SetClassLongW(h, index, (LONG)value);
    line("SetClassLongW(%s, 0x%lX): ret=0x%lX err=%s", index_name, value, r, le());
}

static void sec_classlong(void)
{
    static const WCHAR name[] = { 'F', '2', 'K', 'G', 'u', 'i', 'C', 'l', 'a', 's', 's', 'L',
                                  'o', 'n', 'g', 0 };
    WNDCLASSEXW wc;
    HICON icon;
    HCURSOR cursor;
    HWND h, dead;
    ATOM a;
    DWORD r;

    icon = LoadIconA(NULL, IDI_APPLICATION);
    cursor = LoadCursorA(NULL, IDC_ARROW);
    fill_ex_w(&wc, name);
    wc.cbClsExtra = 8;
    wc.hIcon = icon;
    wc.lpszMenuName = menu_name_w;
    a = RegisterClassExW(&wc);
    dead = CreateWindowExW(0, name, L"dead", WS_POPUP, 0, 0, 10, 10, NULL, NULL, g_hinst, NULL);
    DestroyWindow(dead);
    PostQuitMessage(0);
    drain();
    h = CreateWindowExW(0, name, L"F2K guiclass", WS_OVERLAPPEDWINDOW, 0, 0, 320, 200, NULL, NULL,
                        g_hinst, NULL);
    line("RegisterClassExW(L\"F2KGuiClassLong\", 8 class bytes) and a window of it: %s",
         yesno(a != 0 && h != NULL));

    get_long(h, "GCL_STYLE", GCL_STYLE);
    get_long(h, "GCL_CBCLSEXTRA", GCL_CBCLSEXTRA);
    get_long(h, "GCL_CBWNDEXTRA", GCL_CBWNDEXTRA);
    get_long(h, "GCL_HBRBACKGROUND", GCL_HBRBACKGROUND);
    get_long_rel(h, "GCL_HCURSOR", GCL_HCURSOR, (DWORD)cursor);
    get_long_rel(h, "GCL_HICON", GCL_HICON, (DWORD)icon);
    get_long_rel(h, "GCL_HICONSM, against the large icon", GCL_HICONSM, (DWORD)icon);
    get_long_rel(h, "GCL_HMODULE", GCL_HMODULE, (DWORD)g_hinst);
    get_long_rel(h, "GCL_WNDPROC", GCL_WNDPROC, (DWORD)gui_wndproc);
    get_long_rel(h, "GCW_ATOM", GCW_ATOM, (DWORD)a);
    get_long_rel(h, "GCL_MENUNAME", GCL_MENUNAME, (DWORD)menu_name_w);
    get_long(h, "0", 0);
    get_long(h, "4", 4);

    set_long_w(h, "0", 0, 0x11223344);
    get_long(h, "0", 0);
    arm();
    r = SetClassLongA(h, 4, 0x55667788);
    line("SetClassLongA(4, 0x55667788): ret=0x%lX err=%s", r, le());
    get_long(h, "4", 4);
    get_long(h, "2", 2);
    get_long(h, "5", 5);
    get_long(h, "8", 8);
    set_long_w(h, "5", 5, 0x99);
    set_long_w(h, "8", 8, 0x99);
    get_long(h, "-100", -100);

    set_long_w(h, "GCL_STYLE", GCL_STYLE, CS_HREDRAW);
    get_long(h, "GCL_STYLE", GCL_STYLE);
    set_long_w(h, "GCL_STYLE", GCL_STYLE, CS_HREDRAW | CS_VREDRAW);
    set_long_w(h, "GCL_HBRBACKGROUND", GCL_HBRBACKGROUND, COLOR_BTNFACE + 1);
    get_long(h, "GCL_HBRBACKGROUND", GCL_HBRBACKGROUND);

    arm();
    r = SetClassLongW(h, GCL_WNDPROC, (LONG)other_wndproc);
    line("SetClassLongW(GCL_WNDPROC, another procedure): the registered procedure %s err=%s",
         yesno(r == (DWORD)gui_wndproc), le());
    get_long_rel(h, "GCL_WNDPROC", GCL_WNDPROC, (DWORD)other_wndproc);
    line("the window's own procedure still the registered one: %s",
         yesno(GetWindowLongW(h, GWL_WNDPROC) == (LONG)gui_wndproc));
    SetClassLongW(h, GCL_WNDPROC, (LONG)gui_wndproc);

    get_long(NULL, "GCL_STYLE, NULL window", GCL_STYLE);
    get_long(dead, "GCL_STYLE, a destroyed window", GCL_STYLE);
    get_long(GetDesktopWindow(), "GCL_STYLE, the desktop window", GCL_STYLE);

    /* The quit message drain() ends on, whichever procedure the window
     * was left with. */
    DestroyWindow(h);
    PostQuitMessage(0);
    drain();
    UnregisterClassW(name, g_hinst);
}

static const section_t sections[] = {
    { "register", sec_register, F2KT_ALWAYS },
    { "query", sec_query, F2KT_ALWAYS },
    { "duplicate", sec_duplicate, F2KT_ALWAYS },
    { "unregister", sec_unregister, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { "infoex", sec_infoex, F2KT_ALWAYS },
    { "classlong", sec_classlong, F2KT_ALWAYS },
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
