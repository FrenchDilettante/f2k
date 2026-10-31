/*
 * ctrl - console control events: Ctrl+C and Ctrl+Break delivered to a
 * process group, the handlers' order and thread, the default handler,
 * the ignore flag and its inheritance, and GenerateConsoleCtrlEvent's
 * refusals.
 *
 * The children are ctrlkid.exe, the companion program built beside this
 * one, which does what its first argument says (ctrlkid.c lists its
 * modes) and prints its lines ("kid: ...", "grandkid: ...") through the
 * standard output it inherits, so they land in the output where it
 * prints them. Every section's events go through GenerateConsoleCtrlEvent
 * into the process group of a child the section started with
 * CREATE_NEW_PROCESS_GROUP, and only while that child is alive: never
 * group 0, which would reach every process of the console (on the real
 * machine, the cmd.exe running tests/capture.bat), never a group no
 * process here leads (the lone section asks about those, from a console
 * of its own). The child sets a named event (F2KCtrlReady) once its
 * handlers are in place, and the events go only after it; it prints what
 * reached it once the Ctrl+Break the program sends last (the fence) has
 * come. This program prints nothing while a child may print: what it
 * sends is printed once the child has ended, then the child's end. Every
 * wait is bounded, and a child that outlasts its bound is terminated.
 *
 * This program registers a handler of its own (answering TRUE) for each
 * section and says at the end what reached it: no event sent to a
 * child's group should.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   order    CTRL_BREAK_EVENT to a child with three handlers, the one
 *            answering TRUE registered first, second, then last: the
 *            order they run in (the last registered first), their thread
 *            (the main one or not, one thread for every handler of an
 *            event or not), TRUE ending the chain; a handler registered
 *            twice
 *   default  every handler answering FALSE, no handler at all, and
 *            SetConsoleCtrlHandler(NULL, TRUE) with a handler answering
 *            FALSE: the default handler ends the child, whose exit code
 *            this program sees (STATUS_CONTROL_C_EXIT, 0xC000013A)
 *   ctrlc    CTRL_C_EVENT to the child's group, which the documentation
 *            says its processes do not receive, then the fence: the child
 *            as started, after SetConsoleCtrlHandler(NULL, FALSE) (Ctrl+C
 *            processed again), after SetConsoleCtrlHandler(NULL, TRUE)
 *            (ignored), and a Ctrl+Break into the ignoring one
 *   inherit  the same CTRL_C_EVENT into a group of two: the child and a
 *            grandchild it starts (no group of its own, so in the
 *            child's), each with its ignore flag as started or set: the
 *            flag the grandchild inherits from the child, and its own
 *   errors   GenerateConsoleCtrlEvent with events other than CTRL_C_EVENT
 *            and CTRL_BREAK_EVENT (2, 3, 5, 6, 0xFFFFFFFF), each into a
 *            fresh child's group: the return, the error, and whether the
 *            child saw anything
 *   lone     a child in a console of its own (CREATE_NEW_CONSOLE, a
 *            window opens briefly on the real machine) and a group of its
 *            own, which sends CTRL_BREAK_EVENT to groups no process of
 *            its console leads: this program's id (another console), its
 *            grandchild's (in its console, not a group's root), an ended
 *            process's; the returns, the errors, and whether anything
 *            reached it or its grandchild. Its output comes back through
 *            a standard output this program hands it (STARTF_USESTDHANDLES)
 *
 * Named-only section (interactive: tests/capture.bat leaves it out; it is
 * captured by hand into overrides.txt):
 *
 *   keys     real Ctrl+C and Ctrl+Break from the keyboard, during a line
 *            read with echo (ReadConsoleW, then ReadConsoleA: what it
 *            returns, its last error, the echoed row read back, so
 *            whether ^C shows, the input events left) and while a child
 *            waits (ctrlkid sit, in this program's group, its handler
 *            answering FALSE: its handler's line and exit code); after
 *            each, which events this program's handler saw, and on which
 *            thread. Run it in a console window with the output
 *            redirected (ctrl.exe keys > keys.txt). Each step prints its
 *            marker line to the output, shows the same prompt on the
 *            console, and waits for its keys, to press once the prompt
 *            shows:
 *
 *              marker line                                  keys
 *              step 1: type abc, then press Ctrl+C          a b c Ctrl+C
 *              step 2: type abc, then press Ctrl+C          a b c Ctrl+C
 *              step 3: type abc, then press Ctrl+Break      a b c Ctrl+Break
 *              step 4: press Ctrl+C                         Ctrl+C
 *              step 5: press Ctrl+Break                     Ctrl+Break
 *
 *            (Ctrl+Break: Ctrl and the Pause/Break key.) A read still
 *            waiting 30 s after its prompt gets an Enter queued, and says
 *            so after it; step 4 or 5 with no key in 60 s says so.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ctrl):
 *   cl /nologo /MD ctrlkid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ctrl.c
 */

#include "../common/f2kt.h"

/* The event a child sets once its handlers are in place. */
#define READY "F2KCtrlReady"

/* A child's longest life: its own bounds, a grandchild's nested in them. */
#define KID_BOUND (3 * WAIT_MS)

/* How long the keys section waits for a person. */
#define KEY_WAIT_MS 30000

/* What an out-parameter holds before the call, to see it untouched. */
#define UNSET 0xDEADBEEFu

/* Line input with echo, Ctrl+C processed. */
#define LINE_MODE (ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)

static char kid[MAX_PATH];          /* ctrlkid.exe beside this program */
static HANDLE ev_ready;
static DWORD main_tid;

/* An exit code as printed: an NTSTATUS-like one in hex. */
static const char *code_text(DWORD code)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, code >= 0x80000000u ? "0x%08lX" : "%lu", code);
    return b;
}

static const char *event_name(DWORD e)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    switch (e) {
    case CTRL_C_EVENT: return "CTRL_C_EVENT";
    case CTRL_BREAK_EVENT: return "CTRL_BREAK_EVENT";
    case CTRL_CLOSE_EVENT: return "CTRL_CLOSE_EVENT";
    case CTRL_LOGOFF_EVENT: return "CTRL_LOGOFF_EVENT";
    case CTRL_SHUTDOWN_EVENT: return "CTRL_SHUTDOWN_EVENT";
    }
    sprintf(b, e >= 0x80000000u ? "0x%08lX" : "%lu", e);
    return b;
}

/* Lines kept while a child may print, printed once it has ended. */
static char later[16][200];
static int nlater;

static void say_later(const char *fmt, ...)
{
    va_list ap;

    if (nlater >= (int)(sizeof later / sizeof later[0])) {
        return;
    }
    va_start(ap, fmt);
    _vsnprintf(later[nlater], sizeof later[0] - 1, fmt, ap);
    va_end(ap);
    later[nlater][sizeof later[0] - 1] = '\0';
    nlater++;
}

static void flush_later(void)
{
    int i;

    for (i = 0; i < nlater; i++) {
        line("%s", later[i]);
    }
    nlater = 0;
}

/* --- this program's own handler --------------------------------------- */

static LONG guard_counts[8];

static BOOL WINAPI guard(DWORD type)
{
    InterlockedIncrement(&guard_counts[type < 7 ? type : 7]);
    return TRUE;
}

static void guard_on(void)
{
    memset(guard_counts, 0, sizeof guard_counts);
    SetConsoleCtrlHandler(guard, TRUE);
}

static void guard_off(void)
{
    LONG others = 0;
    int i;

    for (i = 2; i < 8; i++) {
        others += guard_counts[i];
    }
    line("this program's handler saw: Ctrl+C %ld, Ctrl+Break %ld, other events %ld", guard_counts[0],
         guard_counts[1], others);
    SetConsoleCtrlHandler(guard, FALSE);
}

/* --- children ------------------------------------------------------- */

/* Wait for a child's end (ending it, should it outlast the bound), print
 * what was kept for after it, then its end. */
static void reap(PROCESS_INFORMATION *pi, DWORD bound)
{
    DWORD code = 0xF2F2F2F2u;
    DWORD w;

    w = WaitForSingleObject(pi->hProcess, bound);
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(pi->hProcess, 0xDEAD);
        WaitForSingleObject(pi->hProcess, WAIT_MS);
    }
    GetExitCodeProcess(pi->hProcess, &code);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
    flush_later();
    line("the child's end: %s, exit code %s", wr(w), code_text(code));
}

/* Start ctrlkid with `args` and wait until it is ready. */
static BOOL start_kid(const char *args, DWORD flags, PROCESS_INFORMATION *pi)
{
    char cmd[200];
    STARTUPINFOA si;

    sprintf(cmd, "ctrlkid %s", args);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(pi, 0, sizeof *pi);
    ResetEvent(ev_ready);
    arm();
    if (!CreateProcessA(kid, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, pi)) {
        line("ctrlkid not started, err=%s", le());
        return FALSE;
    }
    if (WaitForSingleObject(ev_ready, WAIT_MS) != WAIT_OBJECT_0) {
        say_later("ctrlkid never ready");
        reap(pi, 0);
        return FALSE;
    }
    return TRUE;
}

/* An event into the child's group, while the child is alive: kept for
 * after the child's end. */
static void send_event(DWORD event, const PROCESS_INFORMATION *pi)
{
    const char *e;
    BOOL r;

    if (WaitForSingleObject(pi->hProcess, 0) != WAIT_TIMEOUT) {
        say_later("GenerateConsoleCtrlEvent(%s, the child's group): not sent, the child has ended", event_name(event));
        return;
    }
    arm();
    r = GenerateConsoleCtrlEvent(event, pi->dwProcessId);
    e = le();
    say_later("GenerateConsoleCtrlEvent(%s, the child's group): ret=%d err=%s", event_name(event), r, e);
}

/* `event` into the child's group, then the fence. Before the fence, a
 * short wait on the child: should the event end it, the fence is not
 * sent (the group would lead nothing). The wait is a liveness check; the
 * child itself reports only after the fence. */
static void send_then_fence(DWORD event, const PROCESS_INFORMATION *pi)
{
    send_event(event, pi);
    WaitForSingleObject(pi->hProcess, 300);
    send_event(CTRL_BREAK_EVENT, pi);
}

/* --- order, default --------------------------------------------------- */

static void chain_case(const char *spec, const char *what)
{
    PROCESS_INFORMATION pi;
    char args[40];

    line("-- %s (ctrlkid chain %s)", what, spec);
    sprintf(args, "chain %s", spec);
    if (!start_kid(args, CREATE_NEW_PROCESS_GROUP, &pi)) {
        return;
    }
    send_event(CTRL_BREAK_EVENT, &pi);
    reap(&pi, KID_BOUND);
}

static void sec_order(void)
{
    guard_on();
    chain_case("TFF", "three handlers, the first registered answering TRUE");
    chain_case("FTF", "three handlers, the second registered answering TRUE");
    chain_case("FFT", "three handlers, the last registered answering TRUE");
    chain_case("TF2", "the second handler registered twice");
    guard_off();
}

static void sec_default(void)
{
    guard_on();
    chain_case("FFF", "three handlers answering FALSE");
    chain_case("-", "no handler");
    chain_case("IF", "Ctrl+C ignored, one handler answering FALSE");
    guard_off();
}

/* --- ctrlc, inherit, errors ------------------------------------------ */

static void listen_case(const char *op, DWORD event, const char *what)
{
    PROCESS_INFORMATION pi;
    char args[80];

    line("-- %s (ctrlkid listen, %s): %s, then the fence", what, op, event_name(event));
    sprintf(args, "listen %s %s kid", READY, op);
    if (!start_kid(args, CREATE_NEW_PROCESS_GROUP, &pi)) {
        return;
    }
    send_then_fence(event, &pi);
    reap(&pi, KID_BOUND);
}

static void sec_ctrlc(void)
{
    guard_on();
    listen_case("keep", CTRL_C_EVENT, "the child as started");
    listen_case("process", CTRL_C_EVENT, "Ctrl+C processed again");
    listen_case("ignore", CTRL_C_EVENT, "Ctrl+C ignored");
    listen_case("ignore", CTRL_BREAK_EVENT, "Ctrl+C ignored, a Ctrl+Break");
    guard_off();
}

static void family_case(const char *op, const char *op2, const char *what)
{
    PROCESS_INFORMATION pi;
    char args[80];

    line("-- %s (ctrlkid family %s %s): CTRL_C_EVENT, then the fence", what, op, op2);
    sprintf(args, "family %s %s", op, op2);
    if (!start_kid(args, CREATE_NEW_PROCESS_GROUP, &pi)) {
        return;
    }
    send_then_fence(CTRL_C_EVENT, &pi);
    reap(&pi, KID_BOUND);
}

static void sec_inherit(void)
{
    guard_on();
    family_case("keep", "keep", "both as started");
    family_case("process", "keep", "the child processing Ctrl+C, the grandchild as started");
    family_case("process", "ignore", "the child processing Ctrl+C, the grandchild ignoring it");
    family_case("keep", "process", "the child as started, the grandchild processing Ctrl+C");
    guard_off();
}

static void sec_errors(void)
{
    static const DWORD bad[] = { 2, 3, 5, 6, 0xFFFFFFFFu };
    int i;

    guard_on();
    for (i = 0; i < (int)(sizeof bad / sizeof bad[0]); i++) {
        listen_case("process", bad[i], "an event GenerateConsoleCtrlEvent does not generate");
    }
    guard_off();
}

/* --- lone ------------------------------------------------------------- */

static void sec_lone(void)
{
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE dup = NULL;
    char cmd[100];
    BOOL r;

    guard_on();
    r = DuplicateHandle(GetCurrentProcess(), out, GetCurrentProcess(), &dup, 0, TRUE, DUPLICATE_SAME_ACCESS);
    line("the standard output duplicated, inheritable: %s", yesno(r));
    if (!r) {
        dup = out;
    }
    line("-- ctrlkid lone, in a console and a group of its own");
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdOutput = dup;
    si.hStdError = dup;
    sprintf(cmd, "ctrlkid lone %lu", GetCurrentProcessId());
    arm();
    if (!CreateProcessA(kid, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si,
                        &pi)) {
        line("ctrlkid not started, err=%s", le());
    } else {
        reap(&pi, 4 * WAIT_MS);
    }
    if (r) {
        CloseHandle(dup);
    }
    guard_off();
}

/* --- keys (interactive) ----------------------------------------------- */

static HANDLE con_in = INVALID_HANDLE_VALUE;
static HANDLE con_out = INVALID_HANDLE_VALUE;
static int width = 80;

/* What this program's handler saw during a step. */
static LONG key_calls;
static DWORD key_types[8];
static int key_on_main[8];
static HANDLE key_seen;         /* manual-reset: the handler ran */

static BOOL WINAPI key_handler(DWORD type)
{
    LONG i = InterlockedIncrement(&key_calls) - 1;

    if (i < 8) {
        key_types[i] = type;
        key_on_main[i] = GetCurrentThreadId() == main_tid;
    }
    SetEvent(key_seen);
    return TRUE;
}

static void key_reset(void)
{
    key_calls = 0;
    ResetEvent(key_seen);
}

static void key_log(void)
{
    LONG n = key_calls;
    LONG i;

    if (n == 0) {
        line("this program's handler: did not run");
    }
    for (i = 0; i < n && i < 8; i++) {
        line("this program's handler: %s, on the main thread %s", event_name(key_types[i]), yesno(key_on_main[i]));
    }
}

/* A text's first `count` units as printed: CR, LF and backslash as \r,
 * \n and \\, any other unit outside printable ASCII as <U+XXXX>. */
static const char *vis_w(const WCHAR *s, DWORD count)
{
    static char bufs[2][900];
    static int next;
    char *b = bufs[next++ & 1];
    int n = 0;
    DWORD i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 10; i++) {
        if (s[i] == L'\r') {
            n += sprintf(b + n, "\\r");
        } else if (s[i] == L'\n') {
            n += sprintf(b + n, "\\n");
        } else if (s[i] == L'\\') {
            n += sprintf(b + n, "\\\\");
        } else if (s[i] >= 0x20 && s[i] < 0x7F) {
            b[n++] = (char)s[i];
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)s[i]);
        }
    }
    b[n] = '\0';
    return b;
}

/* The same, of an ANSI text (\xHH outside printable ASCII). */
static const char *vis_a(const char *s, DWORD count)
{
    static char bufs[2][900];
    static int next;
    char *b = bufs[next++ & 1];
    int n = 0;
    DWORD i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 10; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\r') {
            n += sprintf(b + n, "\\r");
        } else if (c == '\n') {
            n += sprintf(b + n, "\\n");
        } else if (c == '\\') {
            n += sprintf(b + n, "\\\\");
        } else if (c >= 0x20 && c < 0x7F) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "\\x%02X", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

/* The marker line on the output, the same prompt on the console. */
static void prompt(int step, const char *what)
{
    char text[200];
    DWORD n;

    line("step %d: %s", step, what);
    sprintf(text, "\r\n[ctrl keys] step %d: %s\r\n", step, what);
    WriteConsoleA(con_out, text, (DWORD)strlen(text), &n, NULL);
}

/* The read's watchdog: an Enter queued should the read still wait after
 * KEY_WAIT_MS; the program ends should even that not end it. */
static HANDLE key_done;
static LONG key_fired;

static DWORD WINAPI key_watchdog(LPVOID arg)
{
    INPUT_RECORD r[2];
    DWORD n;
    int i;

    (void)arg;
    memset(r, 0, sizeof r);
    for (i = 0; i < 2; i++) {
        r[i].EventType = KEY_EVENT;
        r[i].Event.KeyEvent.bKeyDown = i == 0;
        r[i].Event.KeyEvent.wRepeatCount = 1;
        r[i].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
        r[i].Event.KeyEvent.wVirtualScanCode = 0x1C;
        r[i].Event.KeyEvent.uChar.UnicodeChar = L'\r';
    }
    if (WaitForSingleObject(key_done, KEY_WAIT_MS) == WAIT_OBJECT_0) {
        return 0;
    }
    InterlockedIncrement(&key_fired);
    WriteConsoleInputW(con_in, r, 2, &n);
    if (WaitForSingleObject(key_done, WAIT_MS) == WAIT_OBJECT_0) {
        return 0;
    }
    line("the read never returned: the program ends");
    ExitProcess(3);
    return 0;
}

static void key_read(int step, int wide, const char *what)
{
    CONSOLE_SCREEN_BUFFER_INFO before;
    CONSOLE_SCREEN_BUFFER_INFO after;
    static WCHAR wb[80];
    static char ab[80];
    WCHAR row[256];
    DWORD n = UNSET;
    DWORD left = UNSET;
    DWORD got = 0;
    DWORD tid;
    const char *e;
    HANDLE t;
    BOOL r;

    key_reset();
    FlushConsoleInputBuffer(con_in);
    prompt(step, what);
    GetConsoleScreenBufferInfo(con_out, &before);
    FillConsoleOutputCharacterW(con_out, L' ', (DWORD)width * 2, before.dwCursorPosition, &got);

    key_fired = 0;
    ResetEvent(key_done);
    t = CreateThread(NULL, 0, key_watchdog, NULL, 0, &tid);
    arm();
    if (wide) {
        r = ReadConsoleW(con_in, wb, 64, &n, NULL);
    } else {
        r = ReadConsoleA(con_in, ab, 64, &n, NULL);
    }
    e = le();
    SetEvent(key_done);
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    /* The handler's thread may come after the read has returned. */
    WaitForSingleObject(key_seen, WAIT_MS);
    GetConsoleScreenBufferInfo(con_out, &after);
    GetNumberOfConsoleInputEvents(con_in, &left);

    if (!r || n > 64) {
        line("ReadConsole%s: ret=%d read %lu err=%s", wide ? "W" : "A", r, n, e);
    } else if (wide) {
        line("ReadConsoleW: ret=%d read %lu err=%s [%s]", r, n, e, vis_w(wb, n));
    } else {
        line("ReadConsoleA: ret=%d read %lu err=%s [%s]", r, n, e, vis_a(ab, n));
    }
    if (key_fired != 0) {
        line("the watchdog queued an Enter");
    }
    got = 0;
    ReadConsoleOutputCharacterW(con_out, row, (DWORD)(width < 256 ? width : 256), before.dwCursorPosition, &got);
    while (got > 0 && row[got - 1] == L' ') {
        got--;
    }
    line("the echoed row: [%s]", vis_w(row, got));
    line("cursor after: %+d rows, column %d", after.dwCursorPosition.Y - before.dwCursorPosition.Y,
         after.dwCursorPosition.X);
    line("input events left: %lu", left);
    key_log();
    FlushConsoleInputBuffer(con_in);
}

static void key_child(int step, const char *what)
{
    PROCESS_INFORMATION pi;
    DWORD w;

    key_reset();
    if (!start_kid("sit", 0, &pi)) {
        return;
    }
    prompt(step, what);
    w = WaitForSingleObject(key_seen, 2 * KEY_WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        say_later("no key within 60 s");
    }
    reap(&pi, WAIT_MS);
    key_log();
}

static void sec_keys(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD in0 = 0;
    BOOL in_ok;
    BOOL r;

    con_in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    con_out = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, 0, NULL);
    line("CONIN$ and CONOUT$ open: %s",
         yesno(con_in != INVALID_HANDLE_VALUE && con_out != INVALID_HANDLE_VALUE));
    if (GetConsoleScreenBufferInfo(con_out, &csbi)) {
        width = csbi.dwSize.X;
    }
    in_ok = GetConsoleMode(con_in, &in0);
    key_seen = CreateEventA(NULL, TRUE, FALSE, NULL);
    key_done = CreateEventA(NULL, TRUE, FALSE, NULL);
    arm();
    r = SetConsoleMode(con_in, LINE_MODE);
    line("SetConsoleMode(CONIN$, 0x%lX): ret=%d err=%s", (DWORD)LINE_MODE, r, le());
    arm();
    r = SetConsoleCtrlHandler(key_handler, TRUE);
    line("SetConsoleCtrlHandler(handler, TRUE): ret=%d err=%s", r, le());

    key_read(1, 1, "type abc, then press Ctrl+C");
    key_read(2, 0, "type abc, then press Ctrl+C");
    key_read(3, 1, "type abc, then press Ctrl+Break");
    key_child(4, "press Ctrl+C");
    key_child(5, "press Ctrl+Break");

    SetConsoleCtrlHandler(key_handler, FALSE);
    line("CONIN$ mode restored: %s", yesno(in_ok && SetConsoleMode(con_in, in0)));
    CloseHandle(con_in);
    CloseHandle(con_out);
}

static const section_t sections[] = {
    { "order", sec_order, F2KT_ALWAYS },
    { "default", sec_default, F2KT_ALWAYS },
    { "ctrlc", sec_ctrlc, F2KT_ALWAYS },
    { "inherit", sec_inherit, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { "lone", sec_lone, F2KT_ALWAYS },
    { "keys", sec_keys, F2KT_INTERACTIVE },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    char *p;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    main_tid = GetCurrentThreadId();
    GetModuleFileNameA(NULL, kid, sizeof kid - 16);
    p = strrchr(kid, '\\');
    if (p != NULL) {
        p[1] = '\0';
    } else {
        kid[0] = '\0';
    }
    strcat(kid, "ctrlkid.exe");
    ev_ready = CreateEventA(NULL, TRUE, FALSE, READY);
    return run_sections("ctrl", sections, argc, argv);
}
