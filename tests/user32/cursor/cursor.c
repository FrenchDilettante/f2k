/*
 * cursor - the cursor calls user32 has beyond the mouse messages:
 * ShowCursor's display counter, SetCursor and GetCursor, ClipCursor
 * and GetClipCursor, GetCursorInfo, the double-click time,
 * SwapMouseButton, TrackMouseEvent's WM_MOUSELEAVE and WM_MOUSEHOVER,
 * mouse_event, GetMouseMovePointsEx and DragDetect.
 *
 * The sections that move the cursor or press a button work on a
 * visible top-most popup of the program's own, 200x150, centred on the
 * screen; each saves the cursor's position at its start and puts it
 * back at its end, and ClipCursor(NULL) ends every section that clips.
 * The input sections (mouseev, points, drag) ask for the foreground
 * (SetForegroundWindow), print whether the window has it, and inject
 * nothing when it has not; before a press they check WindowFromPoint
 * at that point is the window, and every button pressed is released.
 * Nobody touches the real machine's mouse while it runs: tests\capture
 * .bat runs from a console that is the foreground, so a program it
 * starts may take the foreground.
 *
 * The settings sections (dblclk, swap) change system-wide values and
 * put them back at their end.
 *
 * Only relations print: points as their difference from a point the
 * program computed from the window's rectangle or the screen's
 * metrics, cursors as one of the stock cursors the program loaded or
 * "another", counts as the change from the value before. mouse_event's
 * absolute coordinates are normalised to 0-65535 across the screen:
 * the program sends the middle of the pixel's interval,
 * ((2x + 1) * 32768) / width.
 *
 * GetCursorInfo, TrackMouseEvent, GetMouseMovePointsEx and DragDetect
 * are found with GetProcAddress (MSVC 6's headers declare the first
 * three for Windows 2000 or NT 4 SP3 only), their structures declared
 * here in their public layout; a section says so and stops when user32
 * does not export one.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed; every call under observation is armed with the
 * last-error sentinel and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   show    ShowCursor(TRUE) twice, FALSE three times and TRUE once:
 *           each count against the first; a second thread's first
 *           ShowCursor(TRUE) and FALSE (whether the counter is the
 *           thread's or shared); GetCursorInfo's CURSOR_SHOWING at
 *           each count's sign
 *   setget  SetCursor's previous cursor and GetCursor after: the arrow,
 *           the I-beam, NULL, the arrow again; a second thread's
 *           GetCursor and SetCursor; a destroyed cursor of the
 *           program's own (CreateCursor, DestroyCursor) given to
 *           SetCursor
 *   clip    ClipCursor of a rectangle inside the screen, GetClipCursor
 *           against it, SetCursorPos outside it on each side (where the
 *           cursor lands, against the rectangle's edges); a rectangle
 *           partly off the screen, an empty and an inverted one;
 *           ClipCursor(NULL) and GetClipCursor against the screen;
 *           GetClipCursor(NULL) inside __try
 *   info    GetCursorInfo with cbSize right, 0 and too big: the return,
 *           the flags, the cursor against GetCursor, the point against
 *           GetCursorPos
 *   dblclk  GetDoubleClickTime; SetDoubleClickTime of 700, 0 (the
 *           default), 10, 6000 and back: each return and the time read
 *           after; the machine's own time put back
 *   swap    SwapMouseButton(TRUE), TRUE again, FALSE, FALSE again: each
 *           return as zero or not and SM_SWAPBUTTON after; the setting
 *           put back
 *   track   TrackMouseEvent (cbSize right and wrong) on the window:
 *           TME_LEAVE with the cursor outside the window (WM_MOUSELEAVE
 *           at once), with it inside then moved out by SetCursorPos;
 *           TME_QUERY while tracking and not; TME_HOVER with
 *           HOVER_DEFAULT and 100 ms and the cursor held still inside
 *           (WM_MOUSEHOVER and how long it took, as a band against
 *           SPI_GETMOUSEHOVERTIME); TME_CANCEL; a window of another
 *           thread; NULL
 *   mouseev mouse_event: an absolute move to the window's centre, a
 *           left press and release there: the messages received and
 *           GetCursorPos after, as relations
 *   points  GetMouseMovePointsEx after three absolute mouse_event moves:
 *           the count, whether the first point is the last move and
 *           the second the one before, with GMMP_USE_DISPLAY_POINTS;
 *           a point never moved to; a bad resolution, cbSize and
 *           buffer count
 *   drag    DragDetect from a press on the window: a move past
 *           SM_CXDRAG (TRUE), a release in place (FALSE), and no
 *           button down (whether it returns at once); a second thread
 *           injects the moves and releases with mouse_event, and a
 *           watchdog releases the button after 3 s whatever happens
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat cursor):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% cursor.c user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate these. */
#ifndef WM_MOUSEHOVER
#define WM_MOUSEHOVER 0x02A1
#endif
#ifndef WM_MOUSELEAVE
#define WM_MOUSELEAVE 0x02A3
#endif
#ifndef SPI_GETMOUSEHOVERTIME
#define SPI_GETMOUSEHOVERTIME 0x0066
#endif
#ifndef SM_CXDRAG
#define SM_CXDRAG 68
#define SM_CYDRAG 69
#endif

#define F2K_TME_HOVER 0x00000001
#define F2K_TME_LEAVE 0x00000002
#define F2K_TME_QUERY 0x40000000
#define F2K_TME_CANCEL 0x80000000
#define F2K_HOVER_DEFAULT 0xFFFFFFFF
#define F2K_CURSOR_SHOWING 0x00000001
#define F2K_GMMP_USE_DISPLAY_POINTS 1
#define F2K_GMMP_USE_HIGH_RESOLUTION_POINTS 2

typedef struct {
    DWORD cbSize;
    DWORD dwFlags;
    HWND hwndTrack;
    DWORD dwHoverTime;
} f2k_tme;

typedef struct {
    DWORD cbSize;
    DWORD flags;
    HCURSOR hCursor;
    POINT ptScreenPos;
} f2k_cursorinfo;

typedef struct {
    int x;
    int y;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_mmp;

typedef BOOL (WINAPI *track_fn)(f2k_tme *);
typedef BOOL (WINAPI *cursorinfo_fn)(f2k_cursorinfo *);
typedef int (WINAPI *movepoints_fn)(UINT, f2k_mmp *, f2k_mmp *, int, DWORD);
typedef BOOL (WINAPI *dragdetect_fn)(HWND, POINT);

static track_fn track_mouse_event;
static cursorinfo_fn get_cursor_info;
static movepoints_fn get_mouse_move_points;
static dragdetect_fn drag_detect;

static HWND main_window;
static POINT saved_pos;
static HCURSOR c_arrow, c_ibeam, c_wait, c_cross;

/* What the procedure received. */
#define MAX_RECORDS 64
static UINT records[MAX_RECORDS];
static LPARAM record_lp[MAX_RECORDS];
static DWORD record_tick[MAX_RECORDS];
static int record_count;

static LRESULT CALLBACK cursor_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == WM_MOUSEMOVE || msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP || msg == WM_MOUSEHOVER
        || msg == WM_MOUSELEAVE) {
        if (msg == WM_MOUSEMOVE && record_count > 0 && records[record_count - 1] == WM_MOUSEMOVE
            && record_lp[record_count - 1] == lparam) {
            /* the same move again: dropped */
        } else if (record_count < MAX_RECORDS) {
            records[record_count] = msg;
            record_lp[record_count] = lparam;
            record_tick[record_count] = GetTickCount();
            record_count++;
        }
    }
    if (msg == WM_SETCURSOR) {
        /* Leave the cursor as the section set it. */
        return TRUE;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static const char *msg_name(UINT msg)
{
    switch (msg) {
    case WM_MOUSEMOVE: return "WM_MOUSEMOVE";
    case WM_LBUTTONDOWN: return "WM_LBUTTONDOWN";
    case WM_LBUTTONUP: return "WM_LBUTTONUP";
    case WM_MOUSEHOVER: return "WM_MOUSEHOVER";
    case WM_MOUSELEAVE: return "WM_MOUSELEAVE";
    }
    return "?";
}

static void resolve(void)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    track_mouse_event = (track_fn)GetProcAddress(user, "TrackMouseEvent");
    get_cursor_info = (cursorinfo_fn)GetProcAddress(user, "GetCursorInfo");
    get_mouse_move_points = (movepoints_fn)GetProcAddress(user, "GetMouseMovePointsEx");
    drag_detect = (dragdetect_fn)GetProcAddress(user, "DragDetect");
    c_arrow = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    c_ibeam = LoadCursorW(NULL, (LPCWSTR)IDC_IBEAM);
    c_wait = LoadCursorW(NULL, (LPCWSTR)IDC_WAIT);
    c_cross = LoadCursorW(NULL, (LPCWSTR)IDC_CROSS);
}

static const char *cursor_name(HCURSOR c)
{
    if (c == NULL) {
        return "NULL";
    }
    if (c == c_arrow) {
        return "the arrow";
    }
    if (c == c_ibeam) {
        return "the I-beam";
    }
    if (c == c_wait) {
        return "the hourglass";
    }
    if (c == c_cross) {
        return "the cross";
    }
    return "another cursor";
}

static void dispatch_queued(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

/* Pump for `ms` milliseconds, or until `until` arrives (0: the whole
 * time); whether it arrived. */
static int pump(DWORD ms, UINT until)
{
    DWORD start = GetTickCount(), elapsed;
    int i;

    for (;;) {
        dispatch_queued();
        if (until != 0) {
            for (i = 0; i < record_count; i++) {
                if (records[i] == until) {
                    return 1;
                }
            }
        }
        elapsed = GetTickCount() - start;
        if (elapsed >= ms) {
            return 0;
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, ms - elapsed, QS_ALLINPUT);
    }
}

static void print_records(const char *what)
{
    int i;

    line("%s: %d message(s)", what, record_count);
    for (i = 0; i < record_count; i++) {
        line("  %s", msg_name(records[i]));
    }
}

static HWND make_window(void)
{
    static BOOL registered;
    WNDCLASSW wc;
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = cursor_proc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"F2KCursor";
        registered = RegisterClassW(&wc) != 0;
    }
    main_window = CreateWindowExW(WS_EX_TOPMOST, L"F2KCursor", L"cursor", WS_POPUP | WS_VISIBLE,
                                  (cx - 200) / 2, (cy - 150) / 2, 200, 150, NULL, NULL,
                                  GetModuleHandleA(NULL), NULL);
    line("setup: the window created: %s", yesno(main_window != NULL));
    UpdateWindow(main_window);
    pump(50, 0);
    return main_window;
}

static void end_window(void)
{
    if (main_window != NULL) {
        DestroyWindow(main_window);
        main_window = NULL;
    }
    dispatch_queued();
}

static void save_pos(void)
{
    GetCursorPos(&saved_pos);
}

static void restore_pos(void)
{
    SetCursorPos(saved_pos.x, saved_pos.y);
}

/* The window's centre on the screen. */
static POINT centre(void)
{
    RECT r;
    POINT p;

    GetWindowRect(main_window, &r);
    p.x = (r.left + r.right) / 2;
    p.y = (r.top + r.bottom) / 2;
    return p;
}

/* Where the cursor is, against a point. */
static void pos_against(const char *what, int x, int y)
{
    POINT p;

    GetCursorPos(&p);
    line("%s: the cursor is off (%d, %d) from it", what, p.x - x, p.y - y);
}

static int foreground(void)
{
    SetForegroundWindow(main_window);
    pump(100, 0);
    line("the window is the foreground window: %s", yesno(GetForegroundWindow() == main_window));
    return GetForegroundWindow() == main_window;
}

/* mouse_event's absolute coordinate for a pixel. */
static DWORD norm(int v, int size)
{
    return (DWORD)(((2 * v + 1) * 32768) / size);
}

static void abs_move(int x, int y)
{
    mouse_event(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, norm(x, GetSystemMetrics(SM_CXSCREEN)),
                norm(y, GetSystemMetrics(SM_CYSCREEN)), 0, 0);
}

/* --- show ---------------------------------------------------------- */

static int show(BOOL on)
{
    int r;

    arm();
    r = ShowCursor(on);
    return r;
}

static void showing(void)
{
    f2k_cursorinfo ci;

    if (get_cursor_info == NULL) {
        return;
    }
    ZeroMemory(&ci, sizeof ci);
    ci.cbSize = sizeof ci;
    get_cursor_info(&ci);
    line("  GetCursorInfo: CURSOR_SHOWING %s", yesno((ci.flags & F2K_CURSOR_SHOWING) != 0));
}

static int thread_first[2];
static DWORD thread_err[2];

static DWORD WINAPI show_thread(LPVOID param)
{
    arm();
    thread_first[0] = ShowCursor(TRUE);
    thread_err[0] = GetLastError();
    arm();
    thread_first[1] = ShowCursor(FALSE);
    thread_err[1] = GetLastError();
    return 0;
}

static void sec_show(void)
{
    int base, r, i;
    static const BOOL steps[] = { TRUE, TRUE, FALSE, FALSE, FALSE, TRUE };
    HANDLE t;
    DWORD tid;

    base = ShowCursor(TRUE);
    ShowCursor(FALSE);
    line("the counter at the start: %s", base - 1 >= 0 ? "0 or more" : "below 0");
    for (i = 0; i < 6; i++) {
        r = show(steps[i]);
        line("ShowCursor(%s): ret=start%+d err=%s", steps[i] ? "TRUE" : "FALSE", r - (base - 1), le());
        showing();
    }
    t = CreateThread(NULL, 0, show_thread, NULL, 0, &tid);
    line("a second thread ran: %s", wr(t != NULL ? WaitForSingleObject(t, WAIT_MS) : WAIT_FAILED));
    if (t != NULL) {
        CloseHandle(t);
    }
    line("second thread: ShowCursor(TRUE): ret=start%+d err=%s", thread_first[0] - (base - 1),
         le_of(thread_err[0]));
    line("second thread: ShowCursor(FALSE): ret=start%+d err=%s", thread_first[1] - (base - 1),
         le_of(thread_err[1]));
    r = show(TRUE);
    line("ShowCursor(TRUE) on the first thread after: ret=start%+d err=%s", r - (base - 1), le());
    /* Back to the start. */
    while (r > base - 1) {
        r = ShowCursor(FALSE);
    }
    while (r < base - 1) {
        r = ShowCursor(TRUE);
    }
    line("the counter put back: %s", yesno(r == base - 1));
}

/* --- setget -------------------------------------------------------- */

static HCURSOR thread_get, thread_prev;

static DWORD WINAPI setget_thread(LPVOID param)
{
    thread_get = GetCursor();
    thread_prev = SetCursor(c_cross);
    return 0;
}

static void set_cursor(const char *what, HCURSOR c)
{
    HCURSOR r;

    arm();
    r = SetCursor(c);
    line("SetCursor(%s): ret=%s err=%s", what, cursor_name(r), le());
    arm();
    r = GetCursor();
    line("  GetCursor: %s err=%s", cursor_name(r), le());
}

static void sec_setget(void)
{
    HANDLE t;
    DWORD tid;
    HCURSOR own;
    BYTE and_mask[128], xor_mask[128];
    HCURSOR r;

    make_window();
    set_cursor("the arrow", c_arrow);
    set_cursor("the I-beam", c_ibeam);
    set_cursor("NULL", NULL);
    set_cursor("the arrow", c_arrow);
    set_cursor("the hourglass", c_wait);
    t = CreateThread(NULL, 0, setget_thread, NULL, 0, &tid);
    line("a second thread ran: %s", wr(t != NULL ? WaitForSingleObject(t, WAIT_MS) : WAIT_FAILED));
    if (t != NULL) {
        CloseHandle(t);
    }
    line("second thread: GetCursor: %s", cursor_name(thread_get));
    line("second thread: SetCursor(the cross): ret=%s", cursor_name(thread_prev));
    arm();
    r = GetCursor();
    line("GetCursor on the first thread after: %s err=%s", cursor_name(r), le());

    memset(and_mask, 0xFF, sizeof and_mask);
    memset(xor_mask, 0x00, sizeof xor_mask);
    own = CreateCursor(GetModuleHandleA(NULL), 0, 0, 32, 32, and_mask, xor_mask);
    line("CreateCursor: non-NULL %s", yesno(own != NULL));
    arm();
    r = SetCursor(own);
    line("SetCursor(the program's cursor): ret=%s err=%s", cursor_name(r), le());
    arm();
    r = GetCursor();
    line("  GetCursor is it: %s err=%s", yesno(r == own), le());
    SetCursor(c_arrow);
    arm();
    line("DestroyCursor(it): ret=%d err=%s", DestroyCursor(own), le());
    arm();
    r = SetCursor(own);
    line("SetCursor(the destroyed cursor): ret=%s err=%s", cursor_name(r), le());
    arm();
    r = GetCursor();
    line("  GetCursor: %s err=%s", cursor_name(r), le());
    SetCursor(c_arrow);
    end_window();
}

/* --- clip ---------------------------------------------------------- */

static void clip_now(const char *what, const RECT *want)
{
    RECT got;
    BOOL r;

    arm();
    r = GetClipCursor(&got);
    if (want != NULL) {
        line("GetClipCursor %s: ret=%d err=%s, off (%ld, %ld, %ld, %ld) from it", what, r, le(),
             got.left - want->left, got.top - want->top, got.right - want->right,
             got.bottom - want->bottom);
    } else {
        line("GetClipCursor %s: ret=%d err=%s", what, r, le());
    }
}

static void clip(const char *what, const RECT *rc)
{
    BOOL r;

    arm();
    r = ClipCursor(rc);
    line("ClipCursor(%s): ret=%d err=%s", what, r, le());
}

static void sec_clip(void)
{
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);
    RECT in, part, screen, empty, inverted, got;
    int faulted = 0;

    save_pos();
    SetRect(&screen, 0, 0, cx, cy);
    SetRect(&in, cx / 4, cy / 4, cx / 2, cy / 2);
    SetRect(&part, cx - 50, cy - 40, cx + 100, cy + 100);
    SetRect(&empty, cx / 4, cy / 4, cx / 4, cy / 4);
    SetRect(&inverted, cx / 2, cy / 2, cx / 4, cy / 4);

    clip_now("at the start, against the screen", &screen);
    clip("a rectangle inside the screen", &in);
    clip_now("against it", &in);
    SetCursorPos(0, 0);
    pos_against("SetCursorPos(0, 0), against its top-left corner", in.left, in.top);
    SetCursorPos(cx - 1, cy - 1);
    pos_against("SetCursorPos(the screen's last pixel), against its bottom-right corner", in.right,
                in.bottom);
    SetCursorPos(cx / 3, 0);
    pos_against("SetCursorPos(above it), against (x, its top)", cx / 3, in.top);
    SetCursorPos(cx / 3, cy / 3);
    pos_against("SetCursorPos(inside it)", cx / 3, cy / 3);
    clip("a rectangle partly off the screen", &part);
    clip_now("against the part on the screen", &part);
    GetClipCursor(&got);
    line("  its right and bottom are the screen's: %s", yesno(got.right == cx && got.bottom == cy));
    clip("an empty rectangle", &empty);
    clip_now("against it", &empty);
    SetCursorPos(0, 0);
    pos_against("SetCursorPos(0, 0), against its corner", empty.left, empty.top);
    clip("an inverted rectangle", &inverted);
    clip_now("against the screen", &screen);
    clip("NULL", NULL);
    clip_now("after, against the screen", &screen);
    SetCursorPos(0, 0);
    pos_against("SetCursorPos(0, 0)", 0, 0);
    __try {
        arm();
        GetClipCursor(NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    line("GetClipCursor(NULL): faulted %s", yesno(faulted));
    ClipCursor(NULL);
    restore_pos();
}

/* --- info ---------------------------------------------------------- */

static void info(const char *what, DWORD size)
{
    f2k_cursorinfo ci[2];
    BOOL r;
    POINT p;

    ZeroMemory(ci, sizeof ci);
    ci[0].cbSize = size;
    arm();
    r = get_cursor_info(&ci[0]);
    line("GetCursorInfo(cbSize %s): ret=%d err=%s", what, r, le());
    if (r) {
        GetCursorPos(&p);
        line("  flags=0x%lX, the cursor: %s, the point is GetCursorPos's: %s", ci[0].flags,
             cursor_name(ci[0].hCursor), yesno(ci[0].ptScreenPos.x == p.x && ci[0].ptScreenPos.y == p.y));
    }
}

static void sec_info(void)
{
    POINT c;

    line("GetProcAddress(user32, GetCursorInfo): non-NULL %s", yesno(get_cursor_info != NULL));
    if (get_cursor_info == NULL) {
        return;
    }
    save_pos();
    make_window();
    c = centre();
    SetCursorPos(c.x, c.y);
    SetCursor(c_cross);
    pump(100, 0);
    info("20", 20);
    info("0", 0);
    info("40", 40);
    end_window();
    restore_pos();
}

/* --- dblclk -------------------------------------------------------- */

static void dblclk(UINT ms)
{
    BOOL r;
    UINT t;

    arm();
    r = SetDoubleClickTime(ms);
    t = GetDoubleClickTime();
    line("SetDoubleClickTime(%u): ret=%d err=%s, GetDoubleClickTime after: %u", ms, r, le(), t);
}

static void sec_dblclk(void)
{
    UINT start;

    arm();
    start = GetDoubleClickTime();
    line("GetDoubleClickTime: the machine's own (500 by default) err=%s", le());
    dblclk(700);
    dblclk(0);
    dblclk(10);
    dblclk(6000);
    SetDoubleClickTime(start);
    line("the time put back: %s", yesno(GetDoubleClickTime() == start));
}

/* --- swap ---------------------------------------------------------- */

static void swap(BOOL on)
{
    BOOL r;

    arm();
    r = SwapMouseButton(on);
    line("SwapMouseButton(%s): ret is non-zero %s err=%s, SM_SWAPBUTTON after: %d", on ? "TRUE" : "FALSE",
         yesno(r != 0), le(), GetSystemMetrics(SM_SWAPBUTTON));
}

static void sec_swap(void)
{
    int start = GetSystemMetrics(SM_SWAPBUTTON);

    SwapMouseButton(FALSE);
    line("the buttons set unswapped first: SM_SWAPBUTTON %d", GetSystemMetrics(SM_SWAPBUTTON));
    swap(TRUE);
    swap(TRUE);
    swap(FALSE);
    swap(FALSE);
    SwapMouseButton(start != 0);
    line("the setting put back: %s", yesno(GetSystemMetrics(SM_SWAPBUTTON) == start));
}

/* --- track --------------------------------------------------------- */

static void track(const char *what, DWORD flags, HWND h, DWORD hover, DWORD size)
{
    f2k_tme t;
    BOOL r;

    t.cbSize = size;
    t.dwFlags = flags;
    t.hwndTrack = h;
    t.dwHoverTime = hover;
    arm();
    r = track_mouse_event(&t);
    line("TrackMouseEvent(%s): ret=%d err=%s", what, r, le());
}

static void query(void)
{
    f2k_tme t;
    BOOL r;

    ZeroMemory(&t, sizeof t);
    t.cbSize = sizeof t;
    t.dwFlags = F2K_TME_QUERY;
    arm();
    r = track_mouse_event(&t);
    line("TrackMouseEvent(TME_QUERY): ret=%d err=%s, flags=0x%lX, the window: %s, hover time %s", r, le(),
         t.dwFlags, t.hwndTrack == main_window ? "the section's" : t.hwndTrack == NULL ? "NULL" : "another",
         t.dwHoverTime == 0 ? "0" : "non-zero");
}

static HWND other_window;
static HANDLE other_ready, other_done;

static DWORD WINAPI other_thread(LPVOID param)
{
    MSG m;

    other_window = CreateWindowExW(0, L"F2KCursor", L"other", WS_POPUP, 0, 0, 10, 10, NULL, NULL,
                                   GetModuleHandleA(NULL), NULL);
    SetEvent(other_ready);
    while (MsgWaitForMultipleObjects(1, &other_done, FALSE, WAIT_MS, QS_ALLINPUT) == WAIT_OBJECT_0 + 1) {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            DispatchMessageW(&m);
        }
    }
    DestroyWindow(other_window);
    return 0;
}

static void sec_track(void)
{
    POINT c;
    RECT r;
    UINT hover = 0;
    DWORD start;
    int got;
    HANDLE t;
    DWORD tid;

    line("GetProcAddress(user32, TrackMouseEvent): non-NULL %s", yesno(track_mouse_event != NULL));
    if (track_mouse_event == NULL) {
        return;
    }
    save_pos();
    make_window();
    GetWindowRect(main_window, &r);
    c = centre();
    SystemParametersInfoW(SPI_GETMOUSEHOVERTIME, 0, &hover, 0);

    SetCursorPos(r.left - 20, r.top - 20);
    pump(100, 0);
    record_count = 0;
    track("TME_LEAVE, the cursor outside the window", F2K_TME_LEAVE, main_window, 0, sizeof(f2k_tme));
    got = pump(300, WM_MOUSELEAVE);
    print_records("received in 300 ms");
    query();

    SetCursorPos(c.x, c.y);
    pump(100, 0);
    record_count = 0;
    track("TME_LEAVE, the cursor inside", F2K_TME_LEAVE, main_window, 0, sizeof(f2k_tme));
    query();
    pump(300, 0);
    print_records("received in 300 ms with the cursor still");
    record_count = 0;
    SetCursorPos(r.left - 20, r.top - 20);
    got = pump(1000, WM_MOUSELEAVE);
    print_records("the cursor moved out with SetCursorPos, received");
    line("WM_MOUSELEAVE came: %s", yesno(got));
    query();

    SetCursorPos(c.x, c.y);
    pump(100, 0);
    record_count = 0;
    start = GetTickCount();
    track("TME_HOVER, HOVER_DEFAULT", F2K_TME_HOVER, main_window, F2K_HOVER_DEFAULT, sizeof(f2k_tme));
    query();
    got = pump(hover + 1000, WM_MOUSEHOVER);
    line("WM_MOUSEHOVER came: %s, within SPI_GETMOUSEHOVERTIME and 300 ms more: %s", yesno(got),
         got ? band(record_tick[record_count - 1] - start, hover > 50 ? hover - 50 : 0, hover + 300) : "-");
    query();
    record_count = 0;
    start = GetTickCount();
    track("TME_HOVER, 100 ms", F2K_TME_HOVER, main_window, 100, sizeof(f2k_tme));
    got = pump(1000, WM_MOUSEHOVER);
    line("WM_MOUSEHOVER came: %s, in 50 to 400 ms: %s", yesno(got),
         got ? band(record_tick[record_count - 1] - start, 50, 400) : "-");

    track("TME_LEAVE", F2K_TME_LEAVE, main_window, 0, sizeof(f2k_tme));
    track("TME_LEAVE | TME_CANCEL", F2K_TME_LEAVE | F2K_TME_CANCEL, main_window, 0, sizeof(f2k_tme));
    query();
    record_count = 0;
    SetCursorPos(r.left - 20, r.top - 20);
    pump(500, 0);
    print_records("the cursor moved out after the cancel, received");

    track("TME_LEAVE, cbSize 0", F2K_TME_LEAVE, main_window, 0, 0);
    track("TME_LEAVE, cbSize 20", F2K_TME_LEAVE, main_window, 0, 20);
    track("TME_LEAVE, NULL window", F2K_TME_LEAVE, NULL, 0, sizeof(f2k_tme));
    other_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    other_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    t = CreateThread(NULL, 0, other_thread, NULL, 0, &tid);
    WaitForSingleObject(other_ready, WAIT_MS);
    track("TME_LEAVE, another thread's window", F2K_TME_LEAVE, other_window, 0, sizeof(f2k_tme));
    SetEvent(other_done);
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    CloseHandle(other_ready);
    CloseHandle(other_done);
    dispatch_queued();
    end_window();
    restore_pos();
}

/* --- mouseev ------------------------------------------------------- */

static void sec_mouseev(void)
{
    POINT c;
    int got;

    save_pos();
    make_window();
    c = centre();
    SetCursorPos(c.x - 30, c.y - 30);
    if (!foreground()) {
        end_window();
        restore_pos();
        return;
    }
    record_count = 0;
    abs_move(c.x, c.y);
    got = pump(1000, WM_MOUSEMOVE);
    print_records("mouse_event(an absolute move to the centre), received");
    line("WM_MOUSEMOVE came: %s", yesno(got));
    pos_against("GetCursorPos, against the centre", c.x, c.y);
    if (WindowFromPoint(c) != main_window) {
        line("the window is not under the centre: no press");
    } else {
        record_count = 0;
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
        got = pump(1000, WM_LBUTTONUP);
        print_records("mouse_event(a left press and release), received");
        line("WM_LBUTTONUP came: %s", yesno(got));
        line("the button is up after: %s", yesno((GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0));
    }
    end_window();
    restore_pos();
}

/* --- points -------------------------------------------------------- */

static void move_points(const char *what, int x, int y, UINT res, UINT size, int n)
{
    f2k_mmp in, out[70];
    int r;

    ZeroMemory(&in, sizeof in);
    ZeroMemory(out, sizeof out);
    in.x = x;
    in.y = y;
    arm();
    r = get_mouse_move_points(size, &in, out, n, res);
    line("GetMouseMovePointsEx(%s): ret %s err=%s", what, r < 0 ? "-1" : r == 0 ? "0" : r == 1 ? "1" : "2 or more",
         le());
}

static void sec_points(void)
{
    POINT c;
    f2k_mmp in, out[64];
    int r;

    line("GetProcAddress(user32, GetMouseMovePointsEx): non-NULL %s", yesno(get_mouse_move_points != NULL));
    if (get_mouse_move_points == NULL) {
        return;
    }
    save_pos();
    make_window();
    c = centre();
    if (!foreground()) {
        end_window();
        restore_pos();
        return;
    }
    abs_move(c.x - 40, c.y - 30);
    pump(50, 0);
    abs_move(c.x - 20, c.y - 10);
    pump(50, 0);
    abs_move(c.x, c.y);
    pump(100, 0);
    ZeroMemory(&in, sizeof in);
    ZeroMemory(out, sizeof out);
    in.x = c.x;
    in.y = c.y;
    arm();
    r = get_mouse_move_points(sizeof(f2k_mmp), &in, out, 64, F2K_GMMP_USE_DISPLAY_POINTS);
    line("GetMouseMovePointsEx(the last move, 64 points, GMMP_USE_DISPLAY_POINTS): 3 or more %s err=%s",
         yesno(r >= 3), le());
    if (r >= 2) {
        line("  the first is the last move: %s; the second the one before: %s",
             yesno(out[0].x == c.x && out[0].y == c.y), yesno(out[1].x == c.x - 20 && out[1].y == c.y - 10));
        line("  the first's time is not before the second's: %s", yesno(out[0].time >= out[1].time));
    }
    move_points("a point never moved to, display points", 3, 3, F2K_GMMP_USE_DISPLAY_POINTS,
                sizeof(f2k_mmp), 64);
    move_points("the last move, resolution 7", c.x, c.y, 7, sizeof(f2k_mmp), 64);
    move_points("the last move, cbSize 8", c.x, c.y, F2K_GMMP_USE_DISPLAY_POINTS, 8, 64);
    move_points("the last move, 65 points", c.x, c.y, F2K_GMMP_USE_DISPLAY_POINTS, sizeof(f2k_mmp), 65);
    end_window();
    restore_pos();
}

/* --- drag ---------------------------------------------------------- */

static int drag_action;     /* 1 move past the drag rectangle, 2 release in place */
static POINT drag_from;
static HANDLE drag_go;

static DWORD WINAPI drag_thread(LPVOID param)
{
    int dx = GetSystemMetrics(SM_CXDRAG);

    WaitForSingleObject(drag_go, WAIT_MS);
    Sleep(200);
    if (drag_action == 1) {
        abs_move(drag_from.x + dx * 2 + 4, drag_from.y);
        Sleep(200);
    }
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    return 0;
}

static DWORD WINAPI watchdog(LPVOID param)
{
    if (WaitForSingleObject((HANDLE)param, 3000) == WAIT_TIMEOUT) {
        mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    }
    return 0;
}

static void drag(const char *what, int action, int press)
{
    HANDLE t, w, done;
    DWORD tid, start, took;
    BOOL r;

    record_count = 0;
    drag_action = action;
    drag_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    done = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetCursorPos(drag_from.x, drag_from.y);
    pump(100, 0);
    w = CreateThread(NULL, 0, watchdog, done, 0, &tid);
    if (press) {
        mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
        pump(1000, WM_LBUTTONDOWN);
        t = CreateThread(NULL, 0, drag_thread, NULL, 0, &tid);
    } else {
        t = NULL;
    }
    SetEvent(drag_go);
    start = GetTickCount();
    arm();
    r = drag_detect(main_window, drag_from);
    took = GetTickCount() - start;
    line("DragDetect(%s): ret=%d err=%s, returned within 100 ms: %s", what, r, le(), band(took, 0, 100));
    SetEvent(done);
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    if (w != NULL) {
        WaitForSingleObject(w, WAIT_MS);
        CloseHandle(w);
    }
    CloseHandle(drag_go);
    CloseHandle(done);
    pump(200, 0);
    line("  the button is up after: %s; GetCapture after: %s",
         yesno((GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0), GetCapture() == NULL ? "NULL" : "a window");
}

static void sec_drag(void)
{
    line("GetProcAddress(user32, DragDetect): non-NULL %s", yesno(drag_detect != NULL));
    if (drag_detect == NULL) {
        return;
    }
    save_pos();
    make_window();
    drag_from = centre();
    if (!foreground()) {
        end_window();
        restore_pos();
        return;
    }
    if (WindowFromPoint(drag_from) != main_window) {
        line("the window is not under the centre: no press");
    } else {
        drag("a press, then a move past SM_CXDRAG", 1, 1);
        drag("a press, then a release in place", 2, 1);
    }
    drag("no button down", 0, 0);
    end_window();
    restore_pos();
}

static const section_t sections[] = {
    { "show", sec_show, F2KT_ALWAYS },
    { "setget", sec_setget, F2KT_ALWAYS },
    { "clip", sec_clip, F2KT_ALWAYS },
    { "info", sec_info, F2KT_ALWAYS },
    { "dblclk", sec_dblclk, F2KT_ALWAYS },
    { "swap", sec_swap, F2KT_ALWAYS },
    { "track", sec_track, F2KT_ALWAYS },
    { "mouseev", sec_mouseev, F2KT_ALWAYS },
    { "points", sec_points, F2KT_ALWAYS },
    { "drag", sec_drag, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    resolve();
    return run_sections("cursor", sections, argc, argv);
}
