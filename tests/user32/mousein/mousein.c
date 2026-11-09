/*
 * mousein - mouse input injected with SendInput into the program's own
 * foreground window, as its window procedure receives it: the
 * non-client hit-test codes (WM_NCHITTEST, DefWindowProc's answers),
 * WM_MOUSEMOVE, WM_LBUTTONDOWN and WM_LBUTTONUP with their client
 * points and MK_ flags, the mouse capture (SetCapture, GetCapture,
 * ReleaseCapture, WM_CAPTURECHANGED), a click on a Button control and
 * its BN_CLICKED, and GetCursorPos after each move.
 *
 * Each section creates a visible top-most overlapped window (caption,
 * sizing border, system menu, minimize and maximize boxes) of a class
 * it registers itself, centred on the screen, with a push button at
 * client (16, 16), 80x28, id 101, asks for the foreground
 * (SetForegroundWindow) and prints whether its window is the
 * foreground window. tests\capture.bat runs from a console that is the
 * foreground, so a program it starts may take the foreground. When the
 * window is not the foreground window the section says so and sends no
 * input (the check is made again before every SendInput); before every
 * button press it checks that WindowFromPoint at that point is the
 * window it means to press on, and presses nothing otherwise, so no
 * click ever lands on another window. Every button pressed is released
 * in the same SendInput call. Each section saves the cursor's position
 * at its start and puts it back (SetCursorPos) at its end. Nobody
 * touches the real machine's mouse while it runs.
 *
 * Every point is computed from the window's own rectangle
 * (GetWindowRect, GetClientRect, ClientToScreen) and the system
 * metrics, never fixed screen coordinates, and only relations print: a
 * point a message carries prints as the named point of the section it
 * is within one pixel of, with its difference from it, never as
 * coordinates. SendInput's absolute coordinates are normalised to
 * 0-65535 across the screen (SM_CXSCREEN, SM_CYSCREEN): the program
 * sends the middle of the pixel's interval, ((2x + 1) * 32768) / width.
 * Before each injection the cursor is placed at the section's start
 * point with SetCursorPos and the move that causes is pumped away, so
 * the records start from a known place.
 *
 * The procedure records WM_MOUSEMOVE (a move to the same point with
 * the same flags as the one before it is dropped), WM_LBUTTONDOWN,
 * WM_LBUTTONUP, WM_CAPTURECHANGED (which window gains the capture) and
 * WM_COMMAND (the control's id, the notification code, which window
 * sent it); the records print after the input, never from inside the
 * procedure. After each SendInput the program pumps its queue
 * (PeekMessageW, TranslateMessage, DispatchMessageW,
 * MsgWaitForMultipleObjects between) until the message the batch ends
 * with arrives, or 2 seconds pass, and prints whether it arrived.
 *
 * SendInput is NT 4 SP3's: MSVC 6's headers may not declare it (f2kt.h
 * builds for NT 4), so the program finds it with GetProcAddress, its
 * structures declared here in their public layout, and says so when
 * user32 does not export it. The input sections print SM_SWAPBUTTON
 * first: with the buttons swapped, the left button's events are the
 * right button's.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare;
 * every call under observation is armed with the last-error sentinel
 * and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   hittest  WM_NCHITTEST sent to the window (DefWindowProcW answers)
 *            at points on its caption, system-menu box, close box, top,
 *            left, right and bottom borders, top-left and bottom-right
 *            corners, client area, over the button, and outside it on
 *            either side: the codes; no input
 *   move     one absolute move to the client area's centre: the
 *            WM_MOUSEMOVE records and GetCursorPos, as relations to the
 *            point sent
 *   click    a move, a left press and a release at the client area's
 *            centre: the records (points, MK_ flags) and GetCursorPos
 *   capture  SetCapture onto the window, onto the button, back onto the
 *            window, and ReleaseCapture, each return and GetCapture
 *            after, with the window's WM_CAPTURECHANGED records; then,
 *            with the window holding the capture, a press in the client
 *            area, a move onto its caption (outside the client area)
 *            and a release there: the records, then ReleaseCapture
 *   button   a move, a press and a release at the button's centre: the
 *            parent's records (BN_CLICKED) and GetCursorPos
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat mousein):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% mousein.c user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate these. */
#ifndef INPUT_MOUSE
#define INPUT_MOUSE 0
#endif
#ifndef MOUSEEVENTF_MOVE
#define MOUSEEVENTF_MOVE 0x0001
#endif
#ifndef MOUSEEVENTF_LEFTDOWN
#define MOUSEEVENTF_LEFTDOWN 0x0002
#endif
#ifndef MOUSEEVENTF_LEFTUP
#define MOUSEEVENTF_LEFTUP 0x0004
#endif
#ifndef MOUSEEVENTF_ABSOLUTE
#define MOUSEEVENTF_ABSOLUTE 0x8000
#endif
#ifndef WM_CAPTURECHANGED
#define WM_CAPTURECHANGED 0x0215
#endif

/* SendInput's structures in their public layout (MOUSEINPUT is the
 * union's largest member, so the record is 28 bytes, as INPUT is). */
typedef struct {
    LONG dx;
    LONG dy;
    DWORD mouseData;
    DWORD dwFlags;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_mouse_input;

typedef struct {
    WORD wVk;
    WORD wScan;
    DWORD dwFlags;
    DWORD time;
    DWORD dwExtraInfo;
} f2k_keybd_input;

typedef struct {
    DWORD type;
    union {
        f2k_mouse_input mi;
        f2k_keybd_input ki;
    } u;
} f2k_input;

typedef UINT (WINAPI *send_input_fn)(UINT count, f2k_input *inputs, int size);

static send_input_fn send_input;

#define BUTTON_ID 101

/* The section's window and its button. */
static HWND main_window;
static HWND button_window;

/* What the procedure received, printed after the input. */
typedef struct {
    UINT msg;
    WPARAM wparam;
    int x;          /* the client point (mouse messages) */
    int y;
    HWND other;     /* the window gaining the capture, or the control */
    WORD id;        /* WM_COMMAND's control id and code */
    WORD code;
} record_t;

#define MAX_RECORDS 64

static record_t records[MAX_RECORDS];
static int record_count;
static int records_lost;

/* The batch's end: this message (a WM_MOUSEMOVE within one pixel of
 * wait_x, wait_y when wait_near is set). */
static UINT wait_msg;
static int wait_near;
static int wait_x;
static int wait_y;
static int batch_done;

/* The section's named points, in the window's client coordinates. */
typedef struct {
    const char *name;
    POINT pt;
} named_t;

#define MAX_POINTS 4

static named_t points[MAX_POINTS];
static int point_count;

/* The setup calls' last errors, captured where each call ran. */
static DWORD reg_err;
static DWORD create_err;

static int point_in_client(int x, int y);

static int near1(int a, int b)
{
    return a - b >= -1 && a - b <= 1;
}

static LRESULT CALLBACK mouse_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    record_t *r;
    int x;
    int y;

    if (msg == WM_MOUSEMOVE || msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP || msg == WM_CAPTURECHANGED
        || (msg == WM_COMMAND && lparam != 0)) {
        x = (int)(short)LOWORD(lparam);
        y = (int)(short)HIWORD(lparam);
        if (msg == WM_MOUSEMOVE && record_count > 0 && records[record_count - 1].msg == WM_MOUSEMOVE
            && records[record_count - 1].x == x && records[record_count - 1].y == y
            && records[record_count - 1].wparam == wparam) {
            /* The same move again: dropped. */
        } else if (record_count == MAX_RECORDS) {
            records_lost++;
        } else {
            r = &records[record_count++];
            r->msg = msg;
            r->wparam = wparam;
            r->x = x;
            r->y = y;
            r->other = (msg == WM_CAPTURECHANGED || msg == WM_COMMAND) ? (HWND)lparam : NULL;
            r->id = LOWORD(wparam);
            r->code = HIWORD(wparam);
        }
        if (msg == wait_msg && (!wait_near || (near1(x, wait_x) && near1(y, wait_y)))) {
            batch_done = 1;
        }
        if (msg == WM_COMMAND) {
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static const char *which(HWND w)
{
    if (w == NULL) {
        return "NULL";
    }
    if (w == main_window) {
        return "the window";
    }
    if (w == button_window) {
        return "the button";
    }
    return "another window";
}

static const char *msg_name(UINT msg)
{
    switch (msg) {
    case WM_MOUSEMOVE: return "WM_MOUSEMOVE";
    case WM_LBUTTONDOWN: return "WM_LBUTTONDOWN";
    case WM_LBUTTONUP: return "WM_LBUTTONUP";
    case WM_CAPTURECHANGED: return "WM_CAPTURECHANGED";
    case WM_COMMAND: return "WM_COMMAND";
    }
    return "?";
}

/* A client point as printed: the named point it is within one pixel of,
 * and its difference from it. */
static const char *where(int x, int y)
{
    static char bufs[2][96];
    static int next;
    char *b = bufs[next++ & 1];
    int i;

    for (i = 0; i < point_count; i++) {
        if (near1(x, points[i].pt.x) && near1(y, points[i].pt.y)) {
            sprintf(b, "at %s (off by %d, %d)", points[i].name, x - points[i].pt.x, y - points[i].pt.y);
            return b;
        }
    }
    return "at none of the section's points";
}

static void print_records(void)
{
    int i;
    record_t *r;

    line("received: %d message(s)%s", record_count, records_lost ? ", more lost" : "");
    for (i = 0; i < record_count; i++) {
        r = &records[i];
        if (r->msg == WM_CAPTURECHANGED) {
            line("  WM_CAPTURECHANGED: the capture goes to %s", which(r->other));
        } else if (r->msg == WM_COMMAND) {
            line("  WM_COMMAND: id=%u code=%u%s from %s", r->id, r->code,
                 r->code == BN_CLICKED ? " (BN_CLICKED)" : "", which(r->other));
        } else {
            line("  %s wParam=0x%04lX %s; outside the client area: %s", msg_name(r->msg),
                 (unsigned long)r->wparam, where(r->x, r->y), yesno(!point_in_client(r->x, r->y)));
        }
    }
}

static void reset_records(UINT msg, int nearby, int x, int y)
{
    record_count = 0;
    records_lost = 0;
    wait_msg = msg;
    wait_near = nearby;
    wait_x = x;
    wait_y = y;
    batch_done = 0;
}

static void dispatch_queued(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

/* Pump until the batch's last message arrives or `limit` milliseconds
 * pass, then dispatch what is left; whether it arrived. */
static int pump_batch(DWORD limit)
{
    DWORD start;
    DWORD elapsed;

    start = GetTickCount();
    for (;;) {
        dispatch_queued();
        if (batch_done) {
            break;
        }
        elapsed = GetTickCount() - start;
        if (elapsed >= limit) {
            break;
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, limit - elapsed, QS_ALLINPUT);
    }
    dispatch_queued();
    return batch_done;
}

static int point_in_client(int x, int y)
{
    RECT rc;

    GetClientRect(main_window, &rc);
    return x >= rc.left && x < rc.right && y >= rc.top && y < rc.bottom;
}

/* Name a point of the section, in the window's client coordinates. */
static void name_point(const char *name, int x, int y)
{
    if (point_count < MAX_POINTS) {
        points[point_count].name = name;
        points[point_count].pt.x = x;
        points[point_count].pt.y = y;
        point_count++;
    }
}

static POINT to_screen(int x, int y)
{
    POINT p;

    p.x = x;
    p.y = y;
    ClientToScreen(main_window, &p);
    return p;
}

/* A screen coordinate as SendInput's absolute one: the middle of the
 * pixel's interval of 0-65535. */
static LONG normalise(LONG v, int size)
{
    return ((2 * v + 1) * 32768L) / size;
}

static void set_move(f2k_input *in, POINT screen)
{
    ZeroMemory(in, sizeof *in);
    in->type = INPUT_MOUSE;
    in->u.mi.dx = normalise(screen.x, GetSystemMetrics(SM_CXSCREEN));
    in->u.mi.dy = normalise(screen.y, GetSystemMetrics(SM_CYSCREEN));
    in->u.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
}

static void set_button(f2k_input *in, DWORD flags)
{
    ZeroMemory(in, sizeof *in);
    in->type = INPUT_MOUSE;
    in->u.mi.dwFlags = flags;
}

/* Whether input may go: SendInput is there and the window is the
 * foreground window; says why not otherwise. */
static int may_send(void)
{
    if (send_input == NULL) {
        line("SendInput: not exported by user32, no input sent");
        return 0;
    }
    if (main_window == NULL || GetForegroundWindow() != main_window) {
        line("the window is not the foreground window: no input sent");
        return 0;
    }
    return 1;
}

/* Whether WindowFromPoint at a client point of the window is `expected`,
 * printed. */
static int point_is(const char *name, int x, int y, HWND expected)
{
    POINT p;
    HWND w;

    p = to_screen(x, y);
    arm();
    w = WindowFromPoint(p);
    line("WindowFromPoint(%s): %s err=%s", name, which(w), le());
    return w == expected;
}

/* Place the cursor at the section's start point and pump the move it
 * causes away, so the records start from there. */
static void place_cursor(int x, int y)
{
    POINT p;
    POINT now;

    p = to_screen(x, y);
    reset_records(WM_MOUSEMOVE, 1, x, y);
    SetCursorPos(p.x, p.y);
    pump_batch(500);
    GetCursorPos(&now);
    line("the cursor placed at the start point: %s", yesno(near1(now.x, p.x) && near1(now.y, p.y)));
}

/* Send the batch, pump until its last message, print the records and
 * where GetCursorPos finds the cursor. */
static void send_batch(f2k_input *in, int n, UINT last_msg, int nearby, int x, int y)
{
    UINT sent;
    int arrived;
    POINT now;

    dispatch_queued();
    reset_records(last_msg, nearby, x, y);
    arm();
    sent = send_input((UINT)n, in, (int)sizeof(f2k_input));
    line("SendInput(%d events): ret=%u err=%s", n, sent, le());
    arrived = pump_batch(2000);
    line("the batch arrived: %s", yesno(arrived));
    print_records();
    arm();
    if (GetCursorPos(&now)) {
        ScreenToClient(main_window, &now);
        line("GetCursorPos: %s", where(now.x, now.y));
    } else {
        line("GetCursorPos: failed err=%s", le());
    }
}

/* Find SendInput in user32. */
static void resolve(void)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    if (user != NULL) {
        send_input = (send_input_fn)GetProcAddress(user, "SendInput");
    }
}

/* The section's window: registered, created centred on the screen with
 * its button, made the foreground window. */
static void open_window(const WCHAR *class_name, const char *class_print)
{
    WNDCLASSW wc;
    HMODULE inst;
    ATOM a;
    BOOL r;
    int cx;
    int cy;

    resolve();
    dispatch_queued();
    point_count = 0;
    inst = GetModuleHandle(NULL);
    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = mouse_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;
    arm();
    a = RegisterClassW(&wc);
    reg_err = GetLastError();
    line("RegisterClassW(%s): atom nonzero %s err=%s", class_print, yesno(a != 0), le_of(reg_err));
    cx = GetSystemMetrics(SM_CXSCREEN);
    cy = GetSystemMetrics(SM_CYSCREEN);
    arm();
    main_window = CreateWindowExW(WS_EX_TOPMOST, class_name, L"mousein", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                  (cx - 320) / 2, (cy - 240) / 2, 320, 240, NULL, NULL, inst, NULL);
    create_err = GetLastError();
    line("CreateWindowExW(%s, visible, top-most, centred, 320x240): non-NULL %s err=%s", class_print,
         yesno(main_window != NULL), le_of(create_err));
    if (main_window == NULL) {
        button_window = NULL;
        return;
    }
    arm();
    button_window = CreateWindowExW(0, L"Button", L"Press", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 16, 16, 80,
                                    28, main_window, (HMENU)BUTTON_ID, inst, NULL);
    create_err = GetLastError();
    line("CreateWindowExW(Button, BS_PUSHBUTTON, id 101): non-NULL %s err=%s", yesno(button_window != NULL),
         le_of(create_err));
    UpdateWindow(main_window);
    arm();
    r = SetForegroundWindow(main_window);
    line("SetForegroundWindow(h): ret=%d err=%s", r, le());
    dispatch_queued();
    line("the foreground window: %s", yesno(GetForegroundWindow() == main_window));
}

static void close_window(const WCHAR *class_name)
{
    if (main_window != NULL) {
        DestroyWindow(main_window);
    }
    dispatch_queued();
    main_window = NULL;
    button_window = NULL;
    UnregisterClassW(class_name, GetModuleHandle(NULL));
}

/* The client area's centre. */
static POINT client_centre(void)
{
    RECT rc;
    POINT p;

    GetClientRect(main_window, &rc);
    p.x = rc.right / 2;
    p.y = rc.bottom / 2;
    return p;
}

/* The start point: three quarters across and down the client area,
 * clear of the button and of the centre. */
static POINT start_point(void)
{
    RECT rc;
    POINT p;

    GetClientRect(main_window, &rc);
    p.x = rc.right * 3 / 4;
    p.y = rc.bottom * 3 / 4;
    return p;
}

static void print_swap(void)
{
    line("SM_SWAPBUTTON: %s", yesno(GetSystemMetrics(SM_SWAPBUTTON) != 0));
}

/* --- hittest ------------------------------------------------------- */

static const char *ht_name(LRESULT code)
{
    switch (code) {
    case HTERROR: return "HTERROR";
    case HTTRANSPARENT: return "HTTRANSPARENT";
    case HTNOWHERE: return "HTNOWHERE";
    case HTCLIENT: return "HTCLIENT";
    case HTCAPTION: return "HTCAPTION";
    case HTSYSMENU: return "HTSYSMENU";
    case HTGROWBOX: return "HTGROWBOX";
    case HTMENU: return "HTMENU";
    case HTHSCROLL: return "HTHSCROLL";
    case HTVSCROLL: return "HTVSCROLL";
    case HTMINBUTTON: return "HTMINBUTTON";
    case HTMAXBUTTON: return "HTMAXBUTTON";
    case HTLEFT: return "HTLEFT";
    case HTRIGHT: return "HTRIGHT";
    case HTTOP: return "HTTOP";
    case HTTOPLEFT: return "HTTOPLEFT";
    case HTTOPRIGHT: return "HTTOPRIGHT";
    case HTBOTTOM: return "HTBOTTOM";
    case HTBOTTOMLEFT: return "HTBOTTOMLEFT";
    case HTBOTTOMRIGHT: return "HTBOTTOMRIGHT";
    case HTBORDER: return "HTBORDER";
    case HTCLOSE: return "HTCLOSE";
    case HTHELP: return "HTHELP";
    }
    return "?";
}

static void hit(const char *name, int x, int y)
{
    LRESULT r;

    arm();
    r = SendMessageW(main_window, WM_NCHITTEST, 0, MAKELPARAM(x, y));
    line("WM_NCHITTEST at %s: ret=%ld (%s) err=%s", name, (long)r, ht_name(r), le());
}

static void sec_hittest(void)
{
    RECT wr;
    POINT p;
    int fx;
    int fy;
    int caption_y;
    int mid_x;
    int mid_y;

    open_window(L"F2KMouseinHittest", "F2KMouseinHittest");
    if (main_window == NULL) {
        return;
    }
    GetWindowRect(main_window, &wr);
    fx = GetSystemMetrics(SM_CXFRAME);
    fy = GetSystemMetrics(SM_CYFRAME);
    caption_y = wr.top + fy + GetSystemMetrics(SM_CYCAPTION) / 2;
    mid_x = (wr.left + wr.right) / 2;
    mid_y = (wr.top + wr.bottom) / 2;
    hit("the caption's middle", mid_x, caption_y);
    hit("the system-menu box (SM_CXSIZE/2 in from the frame)", wr.left + fx + GetSystemMetrics(SM_CXSIZE) / 2,
        caption_y);
    hit("the close box (SM_CXSIZE/2 + 2 in from the frame)", wr.right - fx - 2 - GetSystemMetrics(SM_CXSIZE) / 2,
        caption_y);
    hit("the top border (1 in)", mid_x, wr.top + 1);
    hit("the left border (1 in)", wr.left + 1, mid_y);
    hit("the right border (2 in)", wr.right - 2, mid_y);
    hit("the bottom border (2 in)", mid_x, wr.bottom - 2);
    hit("the top-left corner (1 in)", wr.left + 1, wr.top + 1);
    hit("the bottom-right corner (2 in)", wr.right - 2, wr.bottom - 2);
    p = client_centre();
    p = to_screen(p.x, p.y);
    hit("the client area's centre", p.x, p.y);
    p = to_screen(16 + 40, 16 + 14);
    hit("the button's centre", p.x, p.y);
    hit("10 left of the window", wr.left - 10, mid_y);
    hit("10 right of the window", wr.right + 10, mid_y);
    close_window(L"F2KMouseinHittest");
}

/* --- move ---------------------------------------------------------- */

static void sec_move(void)
{
    POINT saved;
    POINT start;
    POINT target;
    f2k_input in[1];

    GetCursorPos(&saved);
    open_window(L"F2KMouseinMove", "F2KMouseinMove");
    print_swap();
    if (may_send()) {
        start = start_point();
        target = client_centre();
        name_point("the start point", start.x, start.y);
        name_point("the point sent", target.x, target.y);
        place_cursor(start.x, start.y);
        if (may_send()) {
            set_move(&in[0], to_screen(target.x, target.y));
            send_batch(in, 1, WM_MOUSEMOVE, 1, target.x, target.y);
        }
    }
    close_window(L"F2KMouseinMove");
    SetCursorPos(saved.x, saved.y);
}

/* --- click --------------------------------------------------------- */

static void sec_click(void)
{
    POINT saved;
    POINT start;
    POINT target;
    f2k_input in[3];

    GetCursorPos(&saved);
    open_window(L"F2KMouseinClick", "F2KMouseinClick");
    print_swap();
    if (may_send()) {
        start = start_point();
        target = client_centre();
        name_point("the start point", start.x, start.y);
        name_point("the point sent", target.x, target.y);
        place_cursor(start.x, start.y);
        if (point_is("the point sent", target.x, target.y, main_window) && may_send()) {
            set_move(&in[0], to_screen(target.x, target.y));
            set_button(&in[1], MOUSEEVENTF_LEFTDOWN);
            set_button(&in[2], MOUSEEVENTF_LEFTUP);
            send_batch(in, 3, WM_LBUTTONUP, 0, 0, 0);
        } else {
            line("no click sent");
        }
    }
    close_window(L"F2KMouseinClick");
    SetCursorPos(saved.x, saved.y);
}

/* --- capture ------------------------------------------------------- */

static void capture_step(const char *what, HWND target)
{
    HWND previous;

    arm();
    previous = SetCapture(target);
    line("SetCapture(%s): previous %s err=%s; GetCapture: %s", what, which(previous), le(),
         which(GetCapture()));
}

static void sec_capture(void)
{
    POINT saved;
    POINT start;
    POINT caption;
    RECT wr;
    BOOL r;
    f2k_input in[3];

    GetCursorPos(&saved);
    open_window(L"F2KMouseinCapture", "F2KMouseinCapture");
    if (main_window == NULL) {
        SetCursorPos(saved.x, saved.y);
        return;
    }
    print_swap();

    /* The capture moved between the window and its button, no input. */
    dispatch_queued();
    reset_records(0, 0, 0, 0);
    arm();
    line("GetCapture at the start: %s err=%s", which(GetCapture()), le());
    capture_step("the window", main_window);
    capture_step("the button", button_window);
    capture_step("the window", main_window);
    arm();
    r = ReleaseCapture();
    line("ReleaseCapture: ret=%d err=%s; GetCapture: %s", r, le(), which(GetCapture()));
    dispatch_queued();
    print_records();

    /* A press in the client area, a move onto the caption and a release
     * there, the window holding the capture. */
    if (may_send()) {
        start = start_point();
        GetWindowRect(main_window, &wr);
        caption.x = (wr.left + wr.right) / 2;
        caption.y = wr.top + GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CYCAPTION) / 2;
        ScreenToClient(main_window, &caption);
        name_point("the start point", start.x, start.y);
        name_point("the caption point", caption.x, caption.y);
        place_cursor(start.x, start.y);
        if (point_is("the start point", start.x, start.y, main_window)
            && point_is("the caption point", caption.x, caption.y, main_window) && may_send()) {
            capture_step("the window", main_window);
            set_button(&in[0], MOUSEEVENTF_LEFTDOWN);
            set_move(&in[1], to_screen(caption.x, caption.y));
            set_button(&in[2], MOUSEEVENTF_LEFTUP);
            send_batch(in, 3, WM_LBUTTONUP, 0, 0, 0);
            arm();
            line("GetCapture after the release: %s err=%s", which(GetCapture()), le());
            reset_records(0, 0, 0, 0);
            arm();
            r = ReleaseCapture();
            line("ReleaseCapture: ret=%d err=%s; GetCapture: %s", r, le(), which(GetCapture()));
            dispatch_queued();
            print_records();
        } else {
            line("no press sent");
        }
    }
    close_window(L"F2KMouseinCapture");
    SetCursorPos(saved.x, saved.y);
}

/* --- button -------------------------------------------------------- */

static void sec_button(void)
{
    POINT saved;
    POINT start;
    POINT target;
    f2k_input in[3];

    GetCursorPos(&saved);
    open_window(L"F2KMouseinButton", "F2KMouseinButton");
    print_swap();
    if (may_send()) {
        start = start_point();
        target.x = 16 + 40;
        target.y = 16 + 14;
        name_point("the start point", start.x, start.y);
        name_point("the button's centre", target.x, target.y);
        place_cursor(start.x, start.y);
        if (point_is("the button's centre", target.x, target.y, button_window) && may_send()) {
            set_move(&in[0], to_screen(target.x, target.y));
            set_button(&in[1], MOUSEEVENTF_LEFTDOWN);
            set_button(&in[2], MOUSEEVENTF_LEFTUP);
            send_batch(in, 3, WM_COMMAND, 0, 0, 0);
        } else {
            line("no click sent");
        }
    }
    close_window(L"F2KMouseinButton");
    SetCursorPos(saved.x, saved.y);
}

static const section_t sections[] = {
    { "hittest", sec_hittest, F2KT_ALWAYS },
    { "move", sec_move, F2KT_ALWAYS },
    { "click", sec_click, F2KT_ALWAYS },
    { "capture", sec_capture, F2KT_ALWAYS },
    { "button", sec_button, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("mousein", sections, argc, argv);
}
