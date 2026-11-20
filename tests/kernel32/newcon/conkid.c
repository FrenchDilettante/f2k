/*
 * conkid - the newcon fixture's companion program: the child newcon.exe
 * starts with or without a console of its own, which reports what it
 * sees of its console.
 *
 * It never prints through its standard handles, which may lead to a
 * console the capture cannot see: every line goes to the report handle,
 * an inherited pipe's write end whose value the parent passes on the
 * command line, and the parent prints what comes out of it once the
 * child has ended. Every line starts "kid: " and is one WriteFile, CR LF
 * terminated. It calls SetErrorMode first, so a fault ends it quietly
 * with the exception's code. It never prints a handle, a window, an id
 * or an absolute path: a title holding the parent's directory (the
 * F2KHOME variable the parent sets) prints it as <home>. The calls
 * kernel32 may lack (AllocConsole, FreeConsole, GetConsoleWindow) are
 * reached through GetProcAddress, so the program loads without them and
 * says so.
 *
 * Command line: conkid <mode> <report> <program's mark> <own mark>
 * <window>, <report> the report handle in hex, <program's mark> a text
 * the parent wrote into its own console, <own mark> a text this program
 * writes into its console, <window> the parent's console window in hex
 * (0 for none).
 *
 * The console summary, printed by several modes:
 *
 *   std: in X, out X, err X  each standard handle: NULL, INVALID, or its
 *                 file type and whether GetConsoleMode takes it
 *   window: none, the program's or another (GetConsoleWindow)
 *   title: the program's (the parent's title), [the title], or the
 *                 error
 *   CONOUT$: the error, or whether the parent's mark is in this console
 *                 (scanning its whole screen buffer: the same console or
 *                 not); for a console not the parent's, the buffer and
 *                 window sizes, whether the cursor is at the origin, and
 *                 the attributes; then the own mark written at the start
 *                 of a row (WriteConsoleA) and read back
 *                 (ReadConsoleOutputCharacterA)
 *
 * Modes:
 *
 *   report    the summary; exit 21
 *   detached  (started with DETACHED_PROCESS) the summary;
 *             GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) with no
 *             console; AllocConsole, the summary again, FreeConsole;
 *             exit 22
 *   alloc     (started in the parent's console) AllocConsole while
 *             attached; FreeConsole; the summary with no console;
 *             WriteConsoleA on the old standard output; FreeConsole
 *             again; AllocConsole; the summary in the new console;
 *             AllocConsole again; FreeConsole; exit 23
 *   ctrl      (started with CREATE_NEW_CONSOLE) a handler counting the
 *             control events (answering TRUE), event F2KNewconReady set,
 *             a wait (5 s) for event F2KNewconGo, 500 ms more, the counts
 *             so far (what the parent's GenerateConsoleCtrlEvent into its
 *             id brought); then, only in a console that is not the
 *             parent's, GenerateConsoleCtrlEvent CTRL_C_EVENT and
 *             CTRL_BREAK_EVENT into group 0 (this console's processes:
 *             this one), and the counts once each came (1 s at most for
 *             Ctrl+C, 2 s for Ctrl+Break); exit 24
 *   (anything else) that the mode is unknown; exit 100
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat newcon):
 *   cl /nologo /MD conkid.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The last-error sentinel, as common/f2kt.h's. */
#define UNTOUCHED 0x0F2F2F2Fu

/* The parent's console title (newcon.c sets it). */
#define PARENT_TITLE "F2K newcon"

typedef BOOL (WINAPI *bool_fn)(void);
typedef HWND (WINAPI *window_fn)(void);

static HANDLE report = INVALID_HANDLE_VALUE;
static const char *parent_mark = "";
static const char *own_mark = "";
static HWND parent_window;
static char home[MAX_PATH];
static bool_fn alloc_console, free_console;
static window_fn console_window;
static volatile LONG ctrl_c, ctrl_break;

/* One line to the report handle: "kid: ", the text, CR LF, one WriteFile. */
static void say(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    DWORD written;

    strcpy(buf, "kid: ");
    va_start(ap, fmt);
    n = _vsnprintf(buf + 5, sizeof buf - 7, fmt, ap);
    va_end(ap);
    if (n < 0) {
        n = sizeof buf - 7;
    }
    n += 5;
    buf[n++] = '\r';
    buf[n++] = '\n';
    WriteFile(report, buf, (DWORD)n, &written, NULL);
}

static const char *le_of(DWORD e)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (e == UNTOUCHED) {
        return "-";
    }
    sprintf(b, "%lu", e);
    return b;
}

/* `s` with every occurrence of the parent's directory as <home>. */
static const char *scrub(const char *s)
{
    static char b[1024];
    size_t len = strlen(home);
    int n = 0;

    while (*s != 0 && n < (int)sizeof b - 8) {
        if (len != 0 && _strnicmp(s, home, len) == 0) {
            strcpy(b + n, "<home>");
            n += 6;
            s += len;
        } else {
            b[n++] = *s++;
        }
    }
    b[n] = 0;
    return b;
}

/* A standard handle as the summary prints it. */
static const char *std_desc(DWORD which)
{
    static char bufs[3][96];
    static int next;
    char *b = bufs[next++ % 3];
    HANDLE h = GetStdHandle(which);
    DWORD type, te, mode, ce;
    BOOL r;

    if (h == NULL) {
        return "NULL";
    }
    if (h == INVALID_HANDLE_VALUE) {
        return "INVALID";
    }
    SetLastError(UNTOUCHED);
    type = GetFileType(h);
    te = GetLastError();
    SetLastError(UNTOUCHED);
    r = GetConsoleMode(h, &mode);
    ce = GetLastError();
    if (r) {
        sprintf(b, "type %lu err=%s, console mode ok", type, le_of(te));
    } else {
        sprintf(b, "type %lu err=%s, console mode err=%s", type, le_of(te), le_of(ce));
    }
    return b;
}

/* Whether `text` starts somewhere in a row of the screen buffer. */
static int holds(HANDLE h, const char *text)
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    static char row[1024];
    DWORD n;
    COORD at;
    SHORT y;
    int width;

    if (*text == 0 || !GetConsoleScreenBufferInfo(h, &info)) {
        return 0;
    }
    width = info.dwSize.X < (SHORT)sizeof row - 1 ? info.dwSize.X : (int)sizeof row - 1;
    for (y = 0; y < info.dwSize.Y; y++) {
        at.X = 0;
        at.Y = y;
        n = 0;
        if (!ReadConsoleOutputCharacterA(h, row, (DWORD)width, at, &n)) {
            return 0;
        }
        row[n] = 0;
        if (strstr(row, text) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* The summary (see the header). */
static void summary(void)
{
    char title[256];
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE h;
    HWND w;
    DWORD n, e, done;
    COORD at;
    char back[128];
    size_t len = strlen(own_mark);

    say("std: in %s, out %s, err %s", std_desc(STD_INPUT_HANDLE), std_desc(STD_OUTPUT_HANDLE),
        std_desc(STD_ERROR_HANDLE));
    if (console_window == NULL) {
        say("window: kernel32 has no GetConsoleWindow");
    } else {
        w = console_window();
        say("window: %s", w == NULL ? "none" : w == parent_window ? "the program's" : "another");
    }
    SetLastError(UNTOUCHED);
    n = GetConsoleTitleA(title, sizeof title);
    e = GetLastError();
    if (n == 0) {
        say("title: ret=0 err=%s", le_of(e));
    } else if (strcmp(title, PARENT_TITLE) == 0) {
        say("title: the program's");
    } else {
        say("title: [%s]", scrub(title));
    }

    SetLastError(UNTOUCHED);
    h = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    e = GetLastError();
    if (h == INVALID_HANDLE_VALUE) {
        say("CONOUT$: err=%s", le_of(e));
        return;
    }
    if (holds(h, parent_mark)) {
        say("CONOUT$: the program's mark in this console: yes");
    } else if (GetConsoleScreenBufferInfo(h, &info)) {
        say("CONOUT$: the program's mark in this console: no; buffer %dx%d, window %dx%d, cursor at the origin: %s,"
            " attributes 0x%02X", info.dwSize.X, info.dwSize.Y, info.srWindow.Right - info.srWindow.Left + 1,
            info.srWindow.Bottom - info.srWindow.Top + 1,
            info.dwCursorPosition.X == 0 && info.dwCursorPosition.Y == 0 ? "yes" : "no", info.wAttributes);
    } else {
        say("CONOUT$: the program's mark in this console: no; GetConsoleScreenBufferInfo err=%lu",
            GetLastError());
    }
    if (GetConsoleScreenBufferInfo(h, &info) && info.dwCursorPosition.X != 0) {
        WriteConsoleA(h, "\r\n", 2, &done, NULL);
        GetConsoleScreenBufferInfo(h, &info);
    }
    at = info.dwCursorPosition;
    SetLastError(UNTOUCHED);
    if (!WriteConsoleA(h, own_mark, (DWORD)len, &done, NULL)) {
        say("its mark: WriteConsoleA err=%s", le_of(GetLastError()));
    } else {
        WriteConsoleA(h, "\r\n", 2, &done, NULL);
        n = 0;
        memset(back, 0, sizeof back);
        ReadConsoleOutputCharacterA(h, back, len < sizeof back - 1 ? (DWORD)len : sizeof back - 1, at, &n);
        say("its mark written and read back: %s", n == len && memcmp(back, own_mark, len) == 0 ? "yes" : "no");
    }
    CloseHandle(h);
}

static void call_bool(const char *name, bool_fn fn)
{
    BOOL r;
    DWORD e;

    if (fn == NULL) {
        say("%s: kernel32 has none", name);
        return;
    }
    SetLastError(UNTOUCHED);
    r = fn();
    e = GetLastError();
    say("%s: ret=%d err=%s", name, r, le_of(e));
}

static void detached(void)
{
    BOOL r;
    DWORD e;

    summary();
    SetLastError(UNTOUCHED);
    r = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0);
    e = GetLastError();
    say("GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0), no console: ret=%d err=%s", r, le_of(e));
    call_bool("AllocConsole", alloc_console);
    summary();
    call_bool("FreeConsole", free_console);
}

static void alloc(void)
{
    HANDLE old = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD done = UNTOUCHED, e;
    BOOL r;

    call_bool("AllocConsole, attached", alloc_console);
    call_bool("FreeConsole", free_console);
    summary();
    SetLastError(UNTOUCHED);
    r = WriteConsoleA(old, "x", 1, &done, NULL);
    e = GetLastError();
    say("WriteConsoleA(the old standard output): ret=%d err=%s", r, le_of(e));
    call_bool("FreeConsole, no console", free_console);
    call_bool("AllocConsole", alloc_console);
    summary();
    call_bool("AllocConsole, again", alloc_console);
    call_bool("FreeConsole", free_console);
}

static BOOL WINAPI counter(DWORD type)
{
    if (type == CTRL_C_EVENT) {
        InterlockedIncrement((LONG *)&ctrl_c);
    } else if (type == CTRL_BREAK_EVENT) {
        InterlockedIncrement((LONG *)&ctrl_break);
    }
    return TRUE;
}

/* Wait up to `ms` for *count to be nonzero. */
static void await_count(volatile LONG *count, DWORD ms)
{
    DWORD start = GetTickCount();

    while (*count == 0 && GetTickCount() - start < ms) {
        Sleep(10);
    }
}

static void ctrl(void)
{
    HANDLE ready, go, h;
    BOOL r;
    DWORD e;
    int own;

    SetConsoleCtrlHandler(counter, TRUE);
    ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, "F2KNewconReady");
    go = OpenEventA(SYNCHRONIZE, FALSE, "F2KNewconGo");
    if (ready == NULL || go == NULL) {
        say("ctrl: an event is missing");
        return;
    }
    SetEvent(ready);
    if (WaitForSingleObject(go, 5000) != WAIT_OBJECT_0) {
        say("ctrl: no go in 5 s");
    }
    Sleep(500);
    say("before its own events: Ctrl+C %ld, Ctrl+Break %ld", ctrl_c, ctrl_break);
    h = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    own = h != INVALID_HANDLE_VALUE && !holds(h, parent_mark);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    if (!own) {
        say("not in a console of its own: no event sent");
        return;
    }
    SetLastError(UNTOUCHED);
    r = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    e = GetLastError();
    say("GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0): ret=%d err=%s", r, le_of(e));
    await_count(&ctrl_c, 1000);
    SetLastError(UNTOUCHED);
    r = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0);
    e = GetLastError();
    say("GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0): ret=%d err=%s", r, le_of(e));
    await_count(&ctrl_break, 2000);
    Sleep(300);
    say("after them: Ctrl+C %ld, Ctrl+Break %ld", ctrl_c, ctrl_break);
}

int main(int argc, char **argv)
{
    HMODULE k32;
    DWORD n;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    n = GetEnvironmentVariableA("F2KHOME", home, sizeof home);
    if (n == 0 || n >= sizeof home) {
        home[0] = 0;
    }
    if (argc < 6) {
        return 101;
    }
    report = (HANDLE)strtoul(argv[2], NULL, 16);
    parent_mark = argv[3];
    own_mark = argv[4];
    parent_window = (HWND)strtoul(argv[5], NULL, 16);
    k32 = GetModuleHandleA("kernel32.dll");
    alloc_console = (bool_fn)(void *)GetProcAddress(k32, "AllocConsole");
    free_console = (bool_fn)(void *)GetProcAddress(k32, "FreeConsole");
    console_window = (window_fn)(void *)GetProcAddress(k32, "GetConsoleWindow");

    if (strcmp(argv[1], "report") == 0) {
        summary();
        return 21;
    } else if (strcmp(argv[1], "detached") == 0) {
        detached();
        return 22;
    } else if (strcmp(argv[1], "alloc") == 0) {
        alloc();
        return 23;
    } else if (strcmp(argv[1], "ctrl") == 0) {
        ctrl();
        return 24;
    }
    say("unknown mode [%s]", argv[1]);
    return 100;
}
