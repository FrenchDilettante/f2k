/*
 * keyinput - keystrokes injected with SendInput into the program's own
 * foreground window, as a window procedure receives them: WM_KEYDOWN,
 * WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP, and the characters
 * TranslateMessage makes of them for the keyboard layout (WM_CHAR,
 * WM_SYSCHAR, WM_DEADCHAR, WM_SYSDEADCHAR), with GetKeyState as the
 * procedure reads it during each message.
 *
 * Each section creates a small visible pop-up window of a class it
 * registers itself, asks for the foreground (SetForegroundWindow) and
 * the focus, and prints whether its window is the foreground window.
 * tests\capture.bat runs from a console that is the foreground, so a
 * program it starts may take the foreground; the input goes only to
 * the foreground window, so when the program's window is not it, the
 * section says so and sends nothing (the check is made again before
 * every SendInput): no keystroke ever reaches another window. Every
 * key pressed is released in the same SendInput call, modifiers
 * included. Nobody types on the real machine while it runs.
 *
 * The procedure records the key and character messages it receives
 * (the message, wParam, lParam, and the down bit of GetKeyState for
 * VK_SHIFT, VK_CONTROL, VK_MENU and the message's own key, read inside
 * the procedure) and answers 0 to each of them, so DefWindowProc never
 * acts on one (Alt would otherwise enter the menu mode); the records
 * print after the input, never from inside the procedure. Only the
 * down bit (0x8000) of GetKeyState prints: the toggle bit (0x0001)
 * depends on the machine's history. lParam prints as eight hex digits
 * and decomposed: the repeat count (bits 0-15), the scan code (16-23),
 * the extended bit (24), the context code (29), the previous state
 * (30) and the transition state (31).
 *
 * After each SendInput the program pumps its queue (PeekMessage,
 * TranslateMessage, DispatchMessage, MsgWaitForMultipleObjects between)
 * until the key-up of the batch's last key arrives, or 2 seconds pass,
 * and prints whether the batch arrived. Every input event gives its
 * US-layout set-1 scan code in wScan, but where a section observes
 * otherwise. Each section starts by printing the conditions its
 * characters depend on: whether the thread's keyboard layout is US
 * English (0409) and whether Caps Lock and Num Lock are on, as the
 * thread's key state reads them.
 *
 * SendInput is NT 4 SP3's: MSVC 6's headers may not declare it (f2kt.h
 * builds for NT 4), so the program finds it with GetProcAddress, its
 * structures declared here in their public layout, and says so when
 * user32 does not export it.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value or
 * address is printed, only whether one came back and how two compare;
 * every call under observation is armed with the last-error sentinel
 * and its line prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   letters    'A', Shift+A, and the digit '2'
 *   symbols    the keys calc reads: Shift+'=' ('+'), '=', '.', and the
 *              numeric keypad's VK_ADD, VK_SUBTRACT, VK_MULTIPLY,
 *              VK_DIVIDE (an extended key) and VK_DECIMAL
 *   control    Enter, Escape, Backspace, Tab, and Ctrl+C
 *   alt        Alt+F, and Alt pressed and released alone
 *   extended   the four arrows and Delete, with KEYEVENTF_EXTENDEDKEY
 *   scancode   'a' given by its scan code alone (KEYEVENTF_SCANCODE,
 *              0x1E, no virtual key), and 'A' by its virtual key with
 *              wScan 0
 *   repeat     'B' pressed twice before its one release
 *   ansi       'A', Shift+A and Enter into a window of a class
 *              registered with RegisterClassA, pumped through
 *              PeekMessageA and DispatchMessageA
 *   typeahead  which window a keystroke goes to when the focus moves
 *              after the keystroke and before the read: 'X' (down and
 *              up) typed into a pop-up holding two child windows, A
 *              and B, of its class, with nothing read until the focus
 *              has moved. SendInput is followed by Sleep(100), so the
 *              keystroke is in the queue before the focus moves
 *              whether SendInput puts it there itself or the raw input
 *              thread does. Each key and character message a read
 *              hands out prints with its window (A, B, the pop-up,
 *              NULL or other) and GetFocus as the read left it. The
 *              cases: the focus moved from A to B; the keystroke
 *              peeked (PM_NOREMOVE) with the focus on A, then the
 *              focus moved to B; the focus moved to B, then a read
 *              filtered for A's window, then one for B's; the focus
 *              taken away (SetFocus(NULL), the pop-up still active);
 *              the same, then a read filtered for WM_KEYDOWN alone,
 *              then one for WM_SYSKEYDOWN alone; the keystroke typed
 *              with no focus, then the focus given to A; and A, the
 *              focus, destroyed before the read
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat keyinput):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% keyinput.c user32.lib
 */

#include "../common/f2kt.h"

/* The MSVC 6 headers may predate these. */
#ifndef INPUT_KEYBOARD
#define INPUT_KEYBOARD 1
#endif
#ifndef KEYEVENTF_EXTENDEDKEY
#define KEYEVENTF_EXTENDEDKEY 0x0001
#endif
#ifndef KEYEVENTF_KEYUP
#define KEYEVENTF_KEYUP 0x0002
#endif
#ifndef KEYEVENTF_SCANCODE
#define KEYEVENTF_SCANCODE 0x0008
#endif
#ifndef VK_OEM_PLUS
#define VK_OEM_PLUS 0xBB
#endif
#ifndef VK_OEM_PERIOD
#define VK_OEM_PERIOD 0xBE
#endif
#ifndef WM_SYSDEADCHAR
#define WM_SYSDEADCHAR 0x0107
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

/* One input event: a key going down or up. */
typedef struct {
    WORD vk;
    WORD scan;
    DWORD flags;
} stroke_t;

#define DOWN 0
#define UP KEYEVENTF_KEYUP
#define EXT KEYEVENTF_EXTENDEDKEY

/* What the procedure received, printed after the input. */
typedef struct {
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
    int shift;
    int ctrl;
    int alt;
    int self;      /* the message's own key's down bit; -1 for a character */
} record_t;

#define MAX_RECORDS 64

static record_t records[MAX_RECORDS];
static int record_count;
static int records_lost;

/* The batch's end: the key-up of this key. */
static WPARAM wait_vk;
static int batch_done;

/* The setup calls' last errors, captured where each call ran. */
static DWORD reg_err;
static DWORD create_err;

static int is_key_message(UINT msg)
{
    return msg == WM_KEYDOWN || msg == WM_KEYUP || msg == WM_SYSKEYDOWN || msg == WM_SYSKEYUP;
}

static int is_recorded(UINT msg)
{
    return is_key_message(msg) || msg == WM_CHAR || msg == WM_SYSCHAR || msg == WM_DEADCHAR
        || msg == WM_SYSDEADCHAR;
}

static int down_bit(int vk)
{
    return (GetKeyState(vk) & 0x8000) != 0;
}

/* Record one key or character message, with the key state as the
 * procedure reads it. */
static void record(UINT msg, WPARAM wparam, LPARAM lparam)
{
    record_t *r;

    if (record_count == MAX_RECORDS) {
        records_lost++;
    } else {
        r = &records[record_count++];
        r->msg = msg;
        r->wparam = wparam;
        r->lparam = lparam;
        r->shift = down_bit(VK_SHIFT);
        r->ctrl = down_bit(VK_CONTROL);
        r->alt = down_bit(VK_MENU);
        r->self = is_key_message(msg) ? down_bit((int)wparam) : -1;
    }
    if ((msg == WM_KEYUP || msg == WM_SYSKEYUP) && wparam == wait_vk) {
        batch_done = 1;
    }
}

/* The procedures: every key and character message recorded and answered
 * 0, everything else to DefWindowProc. */
static LRESULT CALLBACK key_proc_w(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (is_recorded(msg)) {
        record(msg, wparam, lparam);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static LRESULT CALLBACK key_proc_a(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (is_recorded(msg)) {
        record(msg, wparam, lparam);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

static void reset_records(WPARAM vk)
{
    record_count = 0;
    records_lost = 0;
    wait_vk = vk;
    batch_done = 0;
}

static const char *msg_name(UINT msg)
{
    switch (msg) {
    case WM_KEYDOWN: return "WM_KEYDOWN";
    case WM_KEYUP: return "WM_KEYUP";
    case WM_SYSKEYDOWN: return "WM_SYSKEYDOWN";
    case WM_SYSKEYUP: return "WM_SYSKEYUP";
    case WM_CHAR: return "WM_CHAR";
    case WM_SYSCHAR: return "WM_SYSCHAR";
    case WM_DEADCHAR: return "WM_DEADCHAR";
    case WM_SYSDEADCHAR: return "WM_SYSDEADCHAR";
    }
    return "?";
}

static void print_records(void)
{
    int i;
    record_t *r;
    DWORD lp;

    line("received: %d message(s)%s", record_count, records_lost ? ", more lost" : "");
    for (i = 0; i < record_count; i++) {
        r = &records[i];
        lp = (DWORD)r->lparam;
        line("  %s wParam=0x%04lX lParam=0x%08lX (repeat %lu, scan 0x%02lX, extended %lu, "
             "context %lu, previous %lu, transition %lu) down: shift %s ctrl %s alt %s%s%s",
             msg_name(r->msg), (unsigned long)r->wparam, (unsigned long)lp,
             (unsigned long)(lp & 0xFFFF), (unsigned long)((lp >> 16) & 0xFF),
             (unsigned long)((lp >> 24) & 1), (unsigned long)((lp >> 29) & 1),
             (unsigned long)((lp >> 30) & 1), (unsigned long)((lp >> 31) & 1),
             yesno(r->shift), yesno(r->ctrl), yesno(r->alt),
             r->self < 0 ? "" : " key ", r->self < 0 ? "" : yesno(r->self));
    }
}

/* Dispatch whatever is queued, W or A. */
static void dispatch_queued(int ansi)
{
    MSG m;

    if (ansi) {
        while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
    } else {
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}

/* Pump until the batch's last key-up arrives or 2 seconds pass, then
 * dispatch what is left; whether the batch arrived. */
static int pump_batch(int ansi)
{
    DWORD start;
    DWORD elapsed;

    start = GetTickCount();
    for (;;) {
        dispatch_queued(ansi);
        if (batch_done) {
            break;
        }
        elapsed = GetTickCount() - start;
        if (elapsed >= 2000) {
            break;
        }
        MsgWaitForMultipleObjects(0, NULL, FALSE, 2000 - elapsed, QS_ALLINPUT);
    }
    dispatch_queued(ansi);
    return batch_done;
}

/* Find SendInput in user32. */
static void resolve(void)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    if (user != NULL) {
        send_input = (send_input_fn)GetProcAddress(user, "SendInput");
    }
}

/* Inject one batch into the window, if it is the foreground window, and
 * print what the procedure received. */
static void type_keys(HWND h, int ansi, const char *what, const stroke_t *strokes, int n, WORD last_vk)
{
    f2k_input in[8];
    UINT sent;
    int i;
    int arrived;

    line("-- %s", what);
    if (send_input == NULL) {
        line("SendInput: not exported by user32, no input sent");
        return;
    }
    if (h == NULL || GetForegroundWindow() != h) {
        line("the window is not the foreground window: no input sent");
        return;
    }
    ZeroMemory(in, sizeof in);
    for (i = 0; i < n && i < 8; i++) {
        in[i].type = INPUT_KEYBOARD;
        in[i].u.ki.wVk = strokes[i].vk;
        in[i].u.ki.wScan = strokes[i].scan;
        in[i].u.ki.dwFlags = strokes[i].flags;
    }
    dispatch_queued(ansi);
    reset_records(last_vk);
    arm();
    sent = send_input((UINT)n, in, (int)sizeof(f2k_input));
    line("SendInput(%d events): ret=%u err=%s", n, sent, le());
    arrived = pump_batch(ansi);
    line("the batch arrived: %s", yesno(arrived));
    print_records();
}

/* The section's window: registered, created, made the foreground and
 * focus window, the conditions the characters depend on printed. */
static HWND open_window(int ansi, const char *class_name)
{
    WNDCLASSW wcw;
    WNDCLASSA wca;
    WCHAR class_w[64];
    HMODULE inst;
    ATOM a;
    HWND h;
    BOOL r;
    HKL layout;

    resolve();
    dispatch_queued(ansi);
    inst = GetModuleHandle(NULL);
    if (ansi) {
        ZeroMemory(&wca, sizeof wca);
        wca.lpfnWndProc = key_proc_a;
        wca.hInstance = inst;
        wca.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wca.lpszClassName = class_name;
        arm();
        a = RegisterClassA(&wca);
        reg_err = GetLastError();
        line("RegisterClassA(%s): atom nonzero %s err=%s", class_name, yesno(a != 0), le_of(reg_err));
        arm();
        h = CreateWindowExA(0, class_name, "keyinput", WS_POPUP | WS_BORDER | WS_VISIBLE, 40, 40, 160, 80,
                            NULL, NULL, inst, NULL);
        create_err = GetLastError();
        line("CreateWindowExA(%s, visible pop-up): non-NULL %s err=%s", class_name, yesno(h != NULL),
             le_of(create_err));
    } else {
        MultiByteToWideChar(CP_ACP, 0, class_name, -1, class_w, 64);
        ZeroMemory(&wcw, sizeof wcw);
        wcw.lpfnWndProc = key_proc_w;
        wcw.hInstance = inst;
        wcw.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wcw.lpszClassName = class_w;
        arm();
        a = RegisterClassW(&wcw);
        reg_err = GetLastError();
        line("RegisterClassW(%s): atom nonzero %s err=%s", class_name, yesno(a != 0), le_of(reg_err));
        arm();
        h = CreateWindowExW(0, class_w, L"keyinput", WS_POPUP | WS_BORDER | WS_VISIBLE, 40, 40, 160, 80,
                            NULL, NULL, inst, NULL);
        create_err = GetLastError();
        line("CreateWindowExW(%s, visible pop-up): non-NULL %s err=%s", class_name, yesno(h != NULL),
             le_of(create_err));
    }
    if (h == NULL) {
        return NULL;
    }
    arm();
    r = SetForegroundWindow(h);
    line("SetForegroundWindow(h): ret=%d err=%s", r, le());
    SetFocus(h);
    dispatch_queued(ansi);
    line("the foreground window: %s; the focus: %s", yesno(GetForegroundWindow() == h),
         yesno(GetFocus() == h));
    layout = GetKeyboardLayout(0);
    line("keyboard layout US English (0409): %s", yesno(LOWORD((DWORD)layout) == 0x0409));
    line("Caps Lock on: %s; Num Lock on: %s", yesno(GetKeyState(VK_CAPITAL) & 1),
         yesno(GetKeyState(VK_NUMLOCK) & 1));
    return h;
}

static void close_window(HWND h, int ansi, const char *class_name)
{
    WCHAR class_w[64];

    if (h != NULL) {
        DestroyWindow(h);
    }
    dispatch_queued(ansi);
    if (ansi) {
        UnregisterClassA(class_name, GetModuleHandle(NULL));
    } else {
        MultiByteToWideChar(CP_ACP, 0, class_name, -1, class_w, 64);
        UnregisterClassW(class_w, GetModuleHandle(NULL));
    }
}

#define COUNT(a) ((int)(sizeof(a) / sizeof((a)[0])))

/* --- letters ------------------------------------------------------- */

static const stroke_t key_a[] = {
    { 'A', 0x1E, DOWN }, { 'A', 0x1E, UP }
};
static const stroke_t shift_a[] = {
    { VK_SHIFT, 0x2A, DOWN }, { 'A', 0x1E, DOWN }, { 'A', 0x1E, UP }, { VK_SHIFT, 0x2A, UP }
};
static const stroke_t key_2[] = {
    { '2', 0x03, DOWN }, { '2', 0x03, UP }
};

static void sec_letters(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputLetters");
    type_keys(h, 0, "'A'", key_a, COUNT(key_a), 'A');
    type_keys(h, 0, "Shift+A", shift_a, COUNT(shift_a), VK_SHIFT);
    type_keys(h, 0, "'2'", key_2, COUNT(key_2), '2');
    close_window(h, 0, "F2KKeyinputLetters");
}

/* --- symbols ------------------------------------------------------- */

static const stroke_t shift_equals[] = {
    { VK_SHIFT, 0x2A, DOWN }, { VK_OEM_PLUS, 0x0D, DOWN }, { VK_OEM_PLUS, 0x0D, UP },
    { VK_SHIFT, 0x2A, UP }
};
static const stroke_t key_equals[] = {
    { VK_OEM_PLUS, 0x0D, DOWN }, { VK_OEM_PLUS, 0x0D, UP }
};
static const stroke_t key_period[] = {
    { VK_OEM_PERIOD, 0x34, DOWN }, { VK_OEM_PERIOD, 0x34, UP }
};
static const stroke_t pad_add[] = {
    { VK_ADD, 0x4E, DOWN }, { VK_ADD, 0x4E, UP }
};
static const stroke_t pad_subtract[] = {
    { VK_SUBTRACT, 0x4A, DOWN }, { VK_SUBTRACT, 0x4A, UP }
};
static const stroke_t pad_multiply[] = {
    { VK_MULTIPLY, 0x37, DOWN }, { VK_MULTIPLY, 0x37, UP }
};
static const stroke_t pad_divide[] = {
    { VK_DIVIDE, 0x35, DOWN | EXT }, { VK_DIVIDE, 0x35, UP | EXT }
};
static const stroke_t pad_decimal[] = {
    { VK_DECIMAL, 0x53, DOWN }, { VK_DECIMAL, 0x53, UP }
};

static void sec_symbols(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputSymbols");
    type_keys(h, 0, "Shift+'='", shift_equals, COUNT(shift_equals), VK_SHIFT);
    type_keys(h, 0, "'='", key_equals, COUNT(key_equals), VK_OEM_PLUS);
    type_keys(h, 0, "'.'", key_period, COUNT(key_period), VK_OEM_PERIOD);
    type_keys(h, 0, "keypad +", pad_add, COUNT(pad_add), VK_ADD);
    type_keys(h, 0, "keypad -", pad_subtract, COUNT(pad_subtract), VK_SUBTRACT);
    type_keys(h, 0, "keypad *", pad_multiply, COUNT(pad_multiply), VK_MULTIPLY);
    type_keys(h, 0, "keypad / (extended)", pad_divide, COUNT(pad_divide), VK_DIVIDE);
    type_keys(h, 0, "keypad decimal point", pad_decimal, COUNT(pad_decimal), VK_DECIMAL);
    close_window(h, 0, "F2KKeyinputSymbols");
}

/* --- control ------------------------------------------------------- */

static const stroke_t key_enter[] = {
    { VK_RETURN, 0x1C, DOWN }, { VK_RETURN, 0x1C, UP }
};
static const stroke_t key_escape[] = {
    { VK_ESCAPE, 0x01, DOWN }, { VK_ESCAPE, 0x01, UP }
};
static const stroke_t key_back[] = {
    { VK_BACK, 0x0E, DOWN }, { VK_BACK, 0x0E, UP }
};
static const stroke_t key_tab[] = {
    { VK_TAB, 0x0F, DOWN }, { VK_TAB, 0x0F, UP }
};
static const stroke_t ctrl_c[] = {
    { VK_CONTROL, 0x1D, DOWN }, { 'C', 0x2E, DOWN }, { 'C', 0x2E, UP }, { VK_CONTROL, 0x1D, UP }
};

static void sec_control(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputControl");
    type_keys(h, 0, "Enter", key_enter, COUNT(key_enter), VK_RETURN);
    type_keys(h, 0, "Escape", key_escape, COUNT(key_escape), VK_ESCAPE);
    type_keys(h, 0, "Backspace", key_back, COUNT(key_back), VK_BACK);
    type_keys(h, 0, "Tab", key_tab, COUNT(key_tab), VK_TAB);
    type_keys(h, 0, "Ctrl+C", ctrl_c, COUNT(ctrl_c), VK_CONTROL);
    close_window(h, 0, "F2KKeyinputControl");
}

/* --- alt ----------------------------------------------------------- */

static const stroke_t alt_f[] = {
    { VK_MENU, 0x38, DOWN }, { 'F', 0x21, DOWN }, { 'F', 0x21, UP }, { VK_MENU, 0x38, UP }
};
static const stroke_t alt_alone[] = {
    { VK_MENU, 0x38, DOWN }, { VK_MENU, 0x38, UP }
};

static void sec_alt(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputAlt");
    type_keys(h, 0, "Alt+F", alt_f, COUNT(alt_f), VK_MENU);
    type_keys(h, 0, "Alt alone", alt_alone, COUNT(alt_alone), VK_MENU);
    close_window(h, 0, "F2KKeyinputAlt");
}

/* --- extended ------------------------------------------------------ */

static const stroke_t key_left[] = {
    { VK_LEFT, 0x4B, DOWN | EXT }, { VK_LEFT, 0x4B, UP | EXT }
};
static const stroke_t key_right[] = {
    { VK_RIGHT, 0x4D, DOWN | EXT }, { VK_RIGHT, 0x4D, UP | EXT }
};
static const stroke_t key_up[] = {
    { VK_UP, 0x48, DOWN | EXT }, { VK_UP, 0x48, UP | EXT }
};
static const stroke_t key_down[] = {
    { VK_DOWN, 0x50, DOWN | EXT }, { VK_DOWN, 0x50, UP | EXT }
};
static const stroke_t key_delete[] = {
    { VK_DELETE, 0x53, DOWN | EXT }, { VK_DELETE, 0x53, UP | EXT }
};

static void sec_extended(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputExtended");
    type_keys(h, 0, "Left", key_left, COUNT(key_left), VK_LEFT);
    type_keys(h, 0, "Right", key_right, COUNT(key_right), VK_RIGHT);
    type_keys(h, 0, "Up", key_up, COUNT(key_up), VK_UP);
    type_keys(h, 0, "Down", key_down, COUNT(key_down), VK_DOWN);
    type_keys(h, 0, "Delete", key_delete, COUNT(key_delete), VK_DELETE);
    close_window(h, 0, "F2KKeyinputExtended");
}

/* --- scancode ------------------------------------------------------ */

static const stroke_t scan_a[] = {
    { 0, 0x1E, DOWN | KEYEVENTF_SCANCODE }, { 0, 0x1E, UP | KEYEVENTF_SCANCODE }
};
static const stroke_t vk_a_no_scan[] = {
    { 'A', 0, DOWN }, { 'A', 0, UP }
};

static void sec_scancode(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputScancode");
    type_keys(h, 0, "scan code 0x1E alone (KEYEVENTF_SCANCODE)", scan_a, COUNT(scan_a), 'A');
    type_keys(h, 0, "'A' with wScan 0", vk_a_no_scan, COUNT(vk_a_no_scan), 'A');
    close_window(h, 0, "F2KKeyinputScancode");
}

/* --- repeat -------------------------------------------------------- */

static const stroke_t repeat_b[] = {
    { 'B', 0x30, DOWN }, { 'B', 0x30, DOWN }, { 'B', 0x30, UP }
};

static void sec_repeat(void)
{
    HWND h;

    h = open_window(0, "F2KKeyinputRepeat");
    type_keys(h, 0, "'B' down twice, then up", repeat_b, COUNT(repeat_b), 'B');
    close_window(h, 0, "F2KKeyinputRepeat");
}

/* --- ansi ---------------------------------------------------------- */

static void sec_ansi(void)
{
    HWND h;

    h = open_window(1, "F2KKeyinputAnsi");
    type_keys(h, 1, "'A'", key_a, COUNT(key_a), 'A');
    type_keys(h, 1, "Shift+A", shift_a, COUNT(shift_a), VK_SHIFT);
    type_keys(h, 1, "Enter", key_enter, COUNT(key_enter), VK_RETURN);
    close_window(h, 1, "F2KKeyinputAnsi");
}

/* --- typeahead ---------------------------------------------------- */

/* The section's windows: the pop-up and its two children. */
static HWND ta_top;
static HWND ta_a;
static HWND ta_b;

/* A key or character message as a read handed it out, and the focus as
 * the read left it. */
typedef struct {
    UINT msg;
    WPARAM wparam;
    LPARAM lparam;
    HWND hwnd;
    HWND focus;
} read_t;

static read_t reads[MAX_RECORDS];
static int read_count;
static int reads_lost;

static const stroke_t key_x[] = {
    { 'X', 0x2D, DOWN }, { 'X', 0x2D, UP }
};

/* A window as it relates to the section's windows. */
static const char *relation(HWND w)
{
    if (w == NULL) {
        return "NULL";
    }
    if (w == ta_a) {
        return "A";
    }
    if (w == ta_b) {
        return "B";
    }
    if (w == ta_top) {
        return "the pop-up";
    }
    return "other";
}

/* Note a key or character message a read handed out; the batch ends
 * with the key-up of its key. */
static void note_read(const MSG *m)
{
    read_t *r;

    if (!is_recorded(m->message)) {
        return;
    }
    if (read_count == MAX_RECORDS) {
        reads_lost++;
    } else {
        r = &reads[read_count++];
        r->msg = m->message;
        r->wparam = m->wParam;
        r->lparam = m->lParam;
        r->hwnd = m->hwnd;
        r->focus = GetFocus();
    }
    if ((m->message == WM_KEYUP || m->message == WM_SYSKEYUP) && m->wParam == wait_vk) {
        batch_done = 1;
    }
}

/* Read out whatever is queued, translated and dispatched, each key and
 * character message noted. */
static void read_queued(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        note_read(&m);
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

/* Read until the batch's key-up is read or 2 seconds pass (a Sleep
 * between the reads), then print what was read. */
static void read_batch(void)
{
    DWORD start;
    int i;
    read_t *r;

    start = GetTickCount();
    for (;;) {
        read_queued();
        if (batch_done || GetTickCount() - start >= 2000) {
            break;
        }
        Sleep(10);
    }
    read_queued();
    line("the batch arrived: %s", yesno(batch_done));
    line("read: %d message(s)%s", read_count, reads_lost ? ", more lost" : "");
    for (i = 0; i < read_count; i++) {
        r = &reads[i];
        line("  %s wParam=0x%04lX lParam=0x%08lX window %s, focus %s", msg_name(r->msg),
             (unsigned long)r->wparam, (unsigned long)(DWORD)r->lparam, relation(r->hwnd),
             relation(r->focus));
    }
}

/* One read with a filter, PM_REMOVE, printed: what it found, its
 * window, the focus. What it takes out is neither translated nor
 * dispatched. */
static void filtered_read(const char *what, HWND hwnd, UINT min, UINT max)
{
    MSG m;

    if (PeekMessageW(&m, hwnd, min, max, PM_REMOVE)) {
        line("PeekMessageW(%s, PM_REMOVE): found yes: %s wParam=0x%04lX lParam=0x%08lX window %s, "
             "focus %s", what, msg_name(m.message), (unsigned long)m.wParam,
             (unsigned long)(DWORD)m.lParam, relation(m.hwnd), relation(GetFocus()));
        if ((m.message == WM_KEYUP || m.message == WM_SYSKEYUP) && m.wParam == wait_vk) {
            batch_done = 1;
        }
    } else {
        line("PeekMessageW(%s, PM_REMOVE): found no", what);
    }
}

/* Give the focus to `w` (NULL takes it away), whatever is queued read
 * out, and print where the focus is. */
static void focus_on(HWND w)
{
    SetFocus(w);
    read_queued();
    line("the focus: %s; the active window: %s", relation(GetFocus()), relation(GetActiveWindow()));
}

/* 'X' typed, if the pop-up is the foreground window, and nothing read;
 * whether it was sent. */
static int type_ahead(const char *what)
{
    f2k_input in[2];
    UINT sent;
    int i;

    line("-- %s", what);
    if (send_input == NULL) {
        line("SendInput: not exported by user32, no input sent");
        return 0;
    }
    if (GetForegroundWindow() != ta_top) {
        line("the window is not the foreground window: no input sent");
        return 0;
    }
    ZeroMemory(in, sizeof in);
    for (i = 0; i < COUNT(key_x); i++) {
        in[i].type = INPUT_KEYBOARD;
        in[i].u.ki.wVk = key_x[i].vk;
        in[i].u.ki.wScan = key_x[i].scan;
        in[i].u.ki.dwFlags = key_x[i].flags;
    }
    reset_records('X');
    read_count = 0;
    reads_lost = 0;
    arm();
    sent = send_input((UINT)COUNT(key_x), in, (int)sizeof(f2k_input));
    line("SendInput(%d events): ret=%u err=%s", COUNT(key_x), sent, le());
    Sleep(100);
    return 1;
}

/* The focus moves from A to B after the keystroke. */
static void ahead_moved(void)
{
    focus_on(ta_a);
    if (!type_ahead("'X' with the focus on A, then SetFocus(B), then read")) {
        return;
    }
    SetFocus(ta_b);
    line("SetFocus(B): the focus: %s", relation(GetFocus()));
    read_batch();
}

/* The keystroke peeked while the focus is on A, then the focus moves to
 * B. */
static void ahead_peeked(void)
{
    MSG m;
    BOOL got;

    focus_on(ta_a);
    if (!type_ahead("'X' with the focus on A, peeked (PM_NOREMOVE), then SetFocus(B), then read")) {
        return;
    }
    got = PeekMessageW(&m, NULL, WM_KEYFIRST, WM_KEYLAST, PM_NOREMOVE);
    if (got) {
        line("PeekMessageW(NULL, WM_KEYFIRST..WM_KEYLAST, PM_NOREMOVE): found yes: %s wParam=0x%04lX "
             "window %s, focus %s", msg_name(m.message), (unsigned long)m.wParam, relation(m.hwnd),
             relation(GetFocus()));
    } else {
        line("PeekMessageW(NULL, WM_KEYFIRST..WM_KEYLAST, PM_NOREMOVE): found no");
    }
    SetFocus(ta_b);
    line("SetFocus(B): the focus: %s", relation(GetFocus()));
    read_batch();
}

/* The focus moves to B, then reads filtered by window: A's, then B's. */
static void ahead_window_filter(void)
{
    focus_on(ta_a);
    if (!type_ahead("'X' with the focus on A, then SetFocus(B), then read for A's window, then B's")) {
        return;
    }
    SetFocus(ta_b);
    line("SetFocus(B): the focus: %s", relation(GetFocus()));
    filtered_read("A, WM_KEYFIRST..WM_KEYLAST", ta_a, WM_KEYFIRST, WM_KEYLAST);
    filtered_read("B, WM_KEYFIRST..WM_KEYLAST", ta_b, WM_KEYFIRST, WM_KEYLAST);
    read_batch();
}

/* The focus taken away after the keystroke: the pop-up stays active. */
static void ahead_unfocused(void)
{
    focus_on(ta_a);
    if (!type_ahead("'X' with the focus on A, then SetFocus(NULL), then read")) {
        return;
    }
    SetFocus(NULL);
    line("SetFocus(NULL): the focus: %s; the active window: %s", relation(GetFocus()),
         relation(GetActiveWindow()));
    read_batch();
}

/* The focus taken away, then reads filtered by message: WM_KEYDOWN
 * alone, then WM_SYSKEYDOWN alone. */
static void ahead_message_filter(void)
{
    focus_on(ta_a);
    if (!type_ahead("'X' with the focus on A, then SetFocus(NULL), then read for WM_KEYDOWN, then "
                    "WM_SYSKEYDOWN")) {
        return;
    }
    SetFocus(NULL);
    line("SetFocus(NULL): the focus: %s; the active window: %s", relation(GetFocus()),
         relation(GetActiveWindow()));
    filtered_read("NULL, WM_KEYDOWN..WM_KEYDOWN", NULL, WM_KEYDOWN, WM_KEYDOWN);
    filtered_read("NULL, WM_SYSKEYDOWN..WM_SYSKEYDOWN", NULL, WM_SYSKEYDOWN, WM_SYSKEYDOWN);
    read_batch();
}

/* The keystroke typed with no focus, then the focus given to A. */
static void ahead_focused(void)
{
    focus_on(NULL);
    if (!type_ahead("'X' with no focus, then SetFocus(A), then read")) {
        return;
    }
    SetFocus(ta_a);
    line("SetFocus(A): the focus: %s", relation(GetFocus()));
    read_batch();
}

/* A, the focus, destroyed after the keystroke. */
static void ahead_destroyed(void)
{
    BOOL r;

    focus_on(ta_a);
    if (!type_ahead("'X' with the focus on A, then DestroyWindow(A), then read")) {
        return;
    }
    r = DestroyWindow(ta_a);
    line("DestroyWindow(A): ret=%d; the focus: %s", r, relation(GetFocus()));
    read_batch();
}

/* A child window of the section's class, `id` 1 for A, 2 for B. */
static HWND ahead_child(int id)
{
    HWND w;

    w = CreateWindowExW(0, L"F2KKeyinputTypeahead", L"", WS_CHILD | WS_VISIBLE, 10 + 70 * (id - 1), 10,
                        60, 40, ta_top, (HMENU)id, GetModuleHandle(NULL), NULL);
    line("CreateWindowExW(F2KKeyinputTypeahead, child %s): non-NULL %s", id == 1 ? "A" : "B",
         yesno(w != NULL));
    return w;
}

static void sec_typeahead(void)
{
    ta_top = open_window(0, "F2KKeyinputTypeahead");
    if (ta_top != NULL) {
        ta_a = ahead_child(1);
        ta_b = ahead_child(2);
        if (ta_a != NULL && ta_b != NULL) {
            ahead_moved();
            ahead_peeked();
            ahead_window_filter();
            ahead_unfocused();
            ahead_message_filter();
            ahead_focused();
            ahead_destroyed();
        }
    }
    close_window(ta_top, 0, "F2KKeyinputTypeahead");
}

static const section_t sections[] = {
    { "letters", sec_letters, F2KT_ALWAYS },
    { "symbols", sec_symbols, F2KT_ALWAYS },
    { "control", sec_control, F2KT_ALWAYS },
    { "alt", sec_alt, F2KT_ALWAYS },
    { "extended", sec_extended, F2KT_ALWAYS },
    { "scancode", sec_scancode, F2KT_ALWAYS },
    { "repeat", sec_repeat, F2KT_ALWAYS },
    { "ansi", sec_ansi, F2KT_ALWAYS },
    { "typeahead", sec_typeahead, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad handle or window would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("keyinput", sections, argc, argv);
}
