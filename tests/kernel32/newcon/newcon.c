/*
 * newcon - consoles for child processes: a child inheriting the
 * program's console, one with a console of its own (CREATE_NEW_CONSOLE)
 * and one with none (DETACHED_PROCESS), AllocConsole and FreeConsole,
 * control events across consoles, and a second screen buffer
 * (CreateConsoleScreenBuffer, SetConsoleActiveScreenBuffer).
 *
 * The children are conkid.exe, the companion program built beside this
 * one (conkid.c lists its modes and the console summary it prints).
 * What a child writes to a console of its own never reaches the capture,
 * so a child reports through a pipe it inherits, whose write end's value
 * is on its command line; the program prints the report ("  > kid: ...")
 * once the child has ended, then the child's exit code. The program
 * never prints a handle, a window, an id or a path; a console's sameness
 * shows through marks: each section writes a mark of its own (made of
 * its process id and the tick count, never printed) on its console
 * through CONOUT$, which a child looks for in its own console, and each
 * child writes its own mark, which the program then looks for in its
 * console ("the child's mark on the program's console: yes/no"). The
 * program's console title is set to "F2K newcon" for each section and
 * put back at its end.
 *
 * The standard handles a child is given, as each line says:
 *   - "console handles": none in STARTUPINFO, the program's own set (for
 *     the CreateProcess call alone) to inheritable CONIN$ and CONOUT$
 *     handles of its console, so the child's do not depend on how the
 *     program itself was started (the capture redirects its standard
 *     output to a file);
 *   - "pipes": STARTF_USESTDHANDLES, the input a pipe holding one line
 *     (its write end closed), the output and error one pipe, which the
 *     program prints after the report ("  out> ...").
 *
 * Every wait is bounded (5 s): a child that outlives it is terminated,
 * so no section leaves a process or a console window behind. A child
 * with a console of its own opens a window on the real machine for its
 * short life (conkid's own ends with it).
 *
 * Sections (run all with no argument, or one by name):
 *
 *   inherit     no creation flags: the child in the program's console,
 *               with console handles and with pipes
 *   newconsole  CREATE_NEW_CONSOLE: with console handles, with pipes,
 *               with STARTUPINFO's lpTitle, dwXCountChars/dwYCountChars
 *               (STARTF_USECOUNTCHARS) and dwFillAttribute
 *               (STARTF_USEFILLATTRIBUTE), and hidden
 *               (STARTF_USESHOWWINDOW, SW_HIDE)
 *   detached    DETACHED_PROCESS, with console handles and with pipes:
 *               the child with no console, GenerateConsoleCtrlEvent
 *               there, then AllocConsole's console; DETACHED_PROCESS with
 *               CREATE_NEW_CONSOLE (refused)
 *   alloc       AllocConsole and FreeConsole in a child of the program's
 *               console (conkid alloc); the program's console still
 *               answering after the child's FreeConsole
 *   ctrl        a child with a console of its own (CREATE_NEW_CONSOLE,
 *               then with CREATE_NEW_PROCESS_GROUP too): the program's
 *               GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT) into its id,
 *               which is no group of the program's console; the child's
 *               own CTRL_C_EVENT and CTRL_BREAK_EVENT into group 0 of its
 *               console; whether any reached the program's handler. No
 *               event goes to group 0 of the program's console (on the
 *               real machine, the cmd.exe running tests/capture.bat)
 *   buffers     CreateConsoleScreenBuffer in the program's console: the
 *               new buffer's type, mode and size against the active
 *               one's, writing to it while it is inactive (the text read
 *               back, the active buffer without it), its refusals;
 *               SetConsoleActiveScreenBuffer to it (CONOUT$ then opening
 *               it), and back; the active buffer's refusals. The original
 *               buffer is always made active again before the section
 *               ends
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat newcon):
 *   cl /nologo /MD conkid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% newcon.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>

/* The MSVC 6 SDK headers predate it. */
#ifndef CONSOLE_TEXTMODE_BUFFER
#define CONSOLE_TEXTMODE_BUFFER 1
#endif

#define PARENT_TITLE "F2K newcon"

/* How a child's standard handles are given. */
#define STD_CONSOLE 0
#define STD_PIPES 1

typedef HWND (WINAPI *window_fn)(void);
typedef HANDLE (WINAPI *create_buffer_fn)(DWORD, DWORD, const SECURITY_ATTRIBUTES *, DWORD, LPVOID);
typedef BOOL (WINAPI *set_active_fn)(HANDLE);

static char home[MAX_PATH];         /* the program's directory, no trailing backslash */
static char kid[MAX_PATH];          /* home\conkid.exe */
static char mark[64];               /* the section's mark on its console */
static char old_title[512];
static HWND window;                 /* the program's console window (NULL when none or unknown) */
static window_fn console_window;
static create_buffer_fn create_buffer;
static set_active_fn set_active;
static volatile LONG seen_c, seen_break;
static int marks;

/* --- helpers ------------------------------------------------------- */

static const char *code_text(DWORD code)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, code >= 0x80000000u ? "0x%08lX" : "%lu", code);
    return b;
}

static HANDLE open_conout(BOOL inherit)
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = inherit;
    return CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                       OPEN_EXISTING, 0, NULL);
}

/* Whether `text` starts somewhere in a row of the screen buffer `h`. */
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

/* Whether the program's console holds `text`. */
static int console_holds(const char *text)
{
    HANDLE h = open_conout(FALSE);
    int r;

    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    r = holds(h, text);
    CloseHandle(h);
    return r;
}

/* A fresh mark into `b`, never printed. */
static void new_mark(char *b, const char *what)
{
    sprintf(b, "F2K-%s-%lu-%lu-%d", what, GetCurrentProcessId(), GetTickCount(), ++marks);
}

/* A section's start: the title set, the section's mark written on the
 * program's console at the start of a row. */
static void begin(void)
{
    HANDLE h;
    CONSOLE_SCREEN_BUFFER_INFO info;
    DWORD done;

    SetCurrentDirectoryA(home);
    old_title[0] = 0;
    GetConsoleTitleA(old_title, sizeof old_title);
    SetConsoleTitleA(PARENT_TITLE);
    window = console_window != NULL ? console_window() : NULL;
    new_mark(mark, "newcon");
    h = open_conout(FALSE);
    if (h == INVALID_HANDLE_VALUE) {
        line("setup: CONOUT$ err=%lu", GetLastError());
        return;
    }
    if (GetConsoleScreenBufferInfo(h, &info) && info.dwCursorPosition.X != 0) {
        WriteConsoleA(h, "\r\n", 2, &done, NULL);
    }
    WriteConsoleA(h, mark, (DWORD)strlen(mark), &done, NULL);
    WriteConsoleA(h, "\r\n", 2, &done, NULL);
    CloseHandle(h);
}

static void end(void)
{
    if (old_title[0] != 0) {
        SetConsoleTitleA(old_title);
    }
}

/* Read a pipe until every write end is gone; print it a line per CR LF,
 * each after `prefix`. */
static void drain(HANDLE r, const char *prefix)
{
    static char all[8192];
    char chunk[512];
    DWORD n, i, kept = 0, from;

    for (;;) {
        n = 0;
        if (!ReadFile(r, chunk, sizeof chunk, &n, NULL) || n == 0) {
            break;
        }
        for (i = 0; i < n && kept < sizeof all; i++) {
            all[kept++] = chunk[i];
        }
    }
    from = 0;
    for (i = 1; i < kept; i++) {
        if (all[i] == '\n' && all[i - 1] == '\r') {
            all[i - 1] = 0;
            line("%s%s", prefix, all + from);
            from = i + 1;
        }
    }
    if (from < kept) {
        all[kept < sizeof all ? kept : sizeof all - 1] = 0;
        line("%s%s (no line end)", prefix, all + from);
    }
}

static int pipe_pair(HANDLE *r, HANDLE *w, int keep_read)
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(r, w, &sa, 0)) {
        line("  setup: CreatePipe err=%lu", GetLastError());
        return 0;
    }
    SetHandleInformation(keep_read ? *r : *w, HANDLE_FLAG_INHERIT, 0);
    return 1;
}

/* Called once the child has started, before the program waits for it. */
typedef void (*during_fn)(PROCESS_INFORMATION *pi);

/* Start conkid <mode> with `flags`, its standard handles given as `std`
 * says and `si` (or none) adding to STARTUPINFO; print CreateProcess's
 * answer, then once the child has ended (5 s at most) its report, its
 * standard output for pipes, its exit code and whether its mark is on
 * the program's console. */
static void run_kid(const char *label, const char *mode, DWORD flags, int std, const STARTUPINFOA *extra,
                    during_fn during)
{
    static char cmd[512];
    char own[64];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE rr = NULL, rw = NULL, ir = NULL, iw = NULL, orr = NULL, ow = NULL;
    HANDLE cin = INVALID_HANDLE_VALUE, cout = INVALID_HANDLE_VALUE;
    HANDLE old_in, old_out, old_err;
    SECURITY_ATTRIBUTES sa;
    DWORD w, code = 0xF2F2F2F2u, done;
    BOOL ok;
    char err[16];

    line("%s:", label);
    if (!pipe_pair(&rr, &rw, 1)) {
        return;
    }
    new_mark(own, "kid");
    if (extra != NULL) {
        si = *extra;
    } else {
        memset(&si, 0, sizeof si);
    }
    si.cb = sizeof si;
    old_in = GetStdHandle(STD_INPUT_HANDLE);
    old_out = GetStdHandle(STD_OUTPUT_HANDLE);
    old_err = GetStdHandle(STD_ERROR_HANDLE);
    if (std == STD_PIPES) {
        if (!pipe_pair(&ir, &iw, 0) || !pipe_pair(&orr, &ow, 1)) {
            CloseHandle(rr);
            CloseHandle(rw);
            return;
        }
        WriteFile(iw, "a line for the child\r\n", 22, &done, NULL);
        CloseHandle(iw);
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdInput = ir;
        si.hStdOutput = ow;
        si.hStdError = ow;
    } else {
        sa.nLength = sizeof sa;
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        cin = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                          OPEN_EXISTING, 0, NULL);
        cout = open_conout(TRUE);
        SetStdHandle(STD_INPUT_HANDLE, cin);
        SetStdHandle(STD_OUTPUT_HANDLE, cout);
        SetStdHandle(STD_ERROR_HANDLE, cout);
    }
    sprintf(cmd, "conkid %s %lX %s %s %lX", mode, (unsigned long)rw, mark, own, (unsigned long)window);
    memset(&pi, 0, sizeof pi);
    arm();
    ok = CreateProcessA(kid, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);
    strcpy(err, le());
    SetStdHandle(STD_INPUT_HANDLE, old_in);
    SetStdHandle(STD_OUTPUT_HANDLE, old_out);
    SetStdHandle(STD_ERROR_HANDLE, old_err);
    if (cin != INVALID_HANDLE_VALUE) {
        CloseHandle(cin);
    }
    if (cout != INVALID_HANDLE_VALUE) {
        CloseHandle(cout);
    }
    if (ir != NULL) {
        CloseHandle(ir);
    }
    if (ow != NULL) {
        CloseHandle(ow);
    }
    CloseHandle(rw);
    line("  CreateProcessA: ret=%d err=%s", ok, err);
    if (ok) {
        if (during != NULL) {
            during(&pi);
        }
        w = WaitForSingleObject(pi.hProcess, WAIT_MS);
        if (w != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, 0xDEAD);
            WaitForSingleObject(pi.hProcess, WAIT_MS);
            line("  the child overran 5 s: terminated");
        }
    }
    drain(rr, "  > ");
    CloseHandle(rr);
    if (orr != NULL) {
        drain(orr, "  out> ");
        CloseHandle(orr);
    }
    if (ok) {
        GetExitCodeProcess(pi.hProcess, &code);
        line("  the child's end: exit code %s; its mark on the program's console: %s", code_text(code),
             yesno(console_holds(own)));
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

/* --- inherit ------------------------------------------------------- */

static void sec_inherit(void)
{
    begin();
    run_kid("no flags, console handles", "report", 0, STD_CONSOLE, NULL, NULL);
    run_kid("no flags, pipes", "report", 0, STD_PIPES, NULL, NULL);
    end();
}

/* --- newconsole ---------------------------------------------------- */

static void sec_newconsole(void)
{
    STARTUPINFOA si;

    begin();
    run_kid("CREATE_NEW_CONSOLE, console handles", "report", CREATE_NEW_CONSOLE, STD_CONSOLE, NULL, NULL);
    run_kid("CREATE_NEW_CONSOLE, pipes", "report", CREATE_NEW_CONSOLE, STD_PIPES, NULL, NULL);
    memset(&si, 0, sizeof si);
    si.lpTitle = "F2K a title of its own";
    si.dwFlags = STARTF_USECOUNTCHARS | STARTF_USEFILLATTRIBUTE;
    si.dwXCountChars = 100;
    si.dwYCountChars = 200;
    si.dwFillAttribute = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY | BACKGROUND_BLUE;
    run_kid("CREATE_NEW_CONSOLE, lpTitle, 100x200 characters, attributes 0x1E, pipes", "report",
            CREATE_NEW_CONSOLE, STD_PIPES, &si, NULL);
    memset(&si, 0, sizeof si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    run_kid("CREATE_NEW_CONSOLE, SW_HIDE, pipes", "report", CREATE_NEW_CONSOLE, STD_PIPES, &si, NULL);
    end();
}

/* --- detached ------------------------------------------------------ */

static void sec_detached(void)
{
    begin();
    run_kid("DETACHED_PROCESS, console handles", "detached", DETACHED_PROCESS, STD_CONSOLE, NULL, NULL);
    run_kid("DETACHED_PROCESS, pipes", "detached", DETACHED_PROCESS, STD_PIPES, NULL, NULL);
    run_kid("DETACHED_PROCESS | CREATE_NEW_CONSOLE, pipes", "report", DETACHED_PROCESS | CREATE_NEW_CONSOLE,
            STD_PIPES, NULL, NULL);
    end();
}

/* --- alloc --------------------------------------------------------- */

static void sec_alloc(void)
{
    HANDLE h;
    DWORD mode;
    BOOL r;
    char err[16];

    begin();
    run_kid("no flags, console handles: AllocConsole and FreeConsole in the child", "alloc", 0, STD_CONSOLE,
            NULL, NULL);
    h = open_conout(FALSE);
    arm();
    r = GetConsoleMode(h, &mode);
    strcpy(err, le());
    line("the program's console after the child's FreeConsole: GetConsoleMode(CONOUT$) ret=%d err=%s", r, err);
    line("the program's mark still on it: %s", yesno(holds(h, mark)));
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    end();
}

/* --- ctrl ---------------------------------------------------------- */

static HANDLE ready, go;

static BOOL WINAPI program_handler(DWORD type)
{
    if (type == CTRL_C_EVENT) {
        InterlockedIncrement((LONG *)&seen_c);
    } else if (type == CTRL_BREAK_EVENT) {
        InterlockedIncrement((LONG *)&seen_break);
    }
    return TRUE;
}

static void send_break(PROCESS_INFORMATION *pi)
{
    BOOL r;
    char err[16];

    if (WaitForSingleObject(ready, WAIT_MS) != WAIT_OBJECT_0) {
        line("  the child never got ready");
        SetEvent(go);
        return;
    }
    arm();
    r = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi->dwProcessId);
    strcpy(err, le());
    line("  GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, the child's id): ret=%d err=%s", r, err);
    SetEvent(go);
}

static void sec_ctrl(void)
{
    begin();
    ready = CreateEventA(NULL, TRUE, FALSE, "F2KNewconReady");
    go = CreateEventA(NULL, TRUE, FALSE, "F2KNewconGo");
    if (ready == NULL || go == NULL) {
        line("setup: CreateEventA err=%lu", GetLastError());
        end();
        return;
    }
    seen_c = 0;
    seen_break = 0;
    SetConsoleCtrlHandler(program_handler, TRUE);
    run_kid("CREATE_NEW_CONSOLE, pipes", "ctrl", CREATE_NEW_CONSOLE, STD_PIPES, NULL, send_break);
    ResetEvent(ready);
    ResetEvent(go);
    run_kid("CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, pipes", "ctrl",
            CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP, STD_PIPES, NULL, send_break);
    Sleep(300);
    line("the program's handler saw: Ctrl+C %ld, Ctrl+Break %ld", seen_c, seen_break);
    SetConsoleCtrlHandler(program_handler, FALSE);
    CloseHandle(ready);
    CloseHandle(go);
    end();
}

/* --- buffers ------------------------------------------------------- */

static void show_info(const char *label, HANDLE h, const CONSOLE_SCREEN_BUFFER_INFO *active)
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    BOOL r;
    char err[16];

    arm();
    r = GetConsoleScreenBufferInfo(h, &info);
    strcpy(err, le());
    if (!r) {
        line("GetConsoleScreenBufferInfo(%s): ret=0 err=%s", label, err);
        return;
    }
    line("GetConsoleScreenBufferInfo(%s): ret=1 err=%s; the active buffer's size: %s; the active window's size: %s;"
         " the window at the origin: %s; the cursor at the origin: %s; the active buffer's attributes: %s",
         label, err,
         yesno(info.dwSize.X == active->dwSize.X && info.dwSize.Y == active->dwSize.Y),
         yesno(info.dwSize.X == active->srWindow.Right - active->srWindow.Left + 1
               && info.dwSize.Y == active->srWindow.Bottom - active->srWindow.Top + 1),
         yesno(info.srWindow.Left == 0 && info.srWindow.Top == 0),
         yesno(info.dwCursorPosition.X == 0 && info.dwCursorPosition.Y == 0),
         yesno(info.wAttributes == active->wAttributes));
}

/* `count` characters of buffer `h` at the origin, printed. */
static void show_row(const char *label, HANDLE h, DWORD count)
{
    char buf[80];
    COORD at;
    DWORD n = F2KT_UNTOUCHED;
    BOOL r;
    char err[16];

    at.X = 0;
    at.Y = 0;
    memset(buf, 0, sizeof buf);
    arm();
    r = ReadConsoleOutputCharacterA(h, buf, count < sizeof buf - 1 ? count : sizeof buf - 1, at, &n);
    strcpy(err, le());
    line("ReadConsoleOutputCharacterA(%s, at 0,0, %lu): ret=%d err=%s [%s]", label, count, r, err, r ? buf : "");
}

static void set_active_line(const char *label, HANDLE h)
{
    BOOL r;
    char err[16];

    arm();
    r = set_active(h);
    strcpy(err, le());
    line("SetConsoleActiveScreenBuffer(%s): ret=%d err=%s", label, r, err);
}

static void sec_buffers(void)
{
    CONSOLE_SCREEN_BUFFER_INFO active;
    HANDLE original, buffer, bad, again, rp, wp, in;
    DWORD mode = F2KT_UNTOUCHED, done = F2KT_UNTOUCHED, type;
    BOOL r;
    char err[16];
    static const char text[] = "inactive text";

    begin();
    if (create_buffer == NULL || set_active == NULL) {
        line("kernel32 has no %s", create_buffer == NULL ? "CreateConsoleScreenBuffer" : "SetConsoleActiveScreenBuffer");
        end();
        return;
    }
    original = open_conout(FALSE);
    if (original == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(original, &active)) {
        line("setup: CONOUT$ err=%lu", GetLastError());
        end();
        return;
    }

    arm();
    buffer = create_buffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           CONSOLE_TEXTMODE_BUFFER, NULL);
    strcpy(err, le());
    line("CreateConsoleScreenBuffer(read and write, shared, CONSOLE_TEXTMODE_BUFFER): %s err=%s",
         buffer == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : buffer == NULL ? "NULL" : "a handle", err);
    if (buffer == INVALID_HANDLE_VALUE || buffer == NULL) {
        CloseHandle(original);
        end();
        return;
    }
    arm();
    type = GetFileType(buffer);
    line("GetFileType(the new buffer): %lu err=%s", type, le());
    arm();
    r = GetConsoleMode(buffer, &mode);
    strcpy(err, le());
    line("GetConsoleMode(the new buffer): ret=%d err=%s mode 0x%lX", r, err, mode);
    show_info("the new buffer", buffer, &active);

    arm();
    r = WriteConsoleA(buffer, text, sizeof text - 1, &done, NULL);
    strcpy(err, le());
    line("WriteConsoleA(the new buffer, inactive, [%s]): ret=%d err=%s, %lu written", text, r, err, done);
    show_row("the new buffer", buffer, sizeof text - 1);
    arm();
    r = WriteFile(buffer, "!", 1, &done, NULL);
    strcpy(err, le());
    line("WriteFile(the new buffer, [!]): ret=%d err=%s", r, err);
    show_row("the new buffer", buffer, sizeof text);
    line("the active buffer holds the text: %s", yesno(holds(original, text)));

    arm();
    bad = create_buffer(GENERIC_READ | GENERIC_WRITE, 0, NULL, 2, NULL);
    strcpy(err, le());
    line("CreateConsoleScreenBuffer(flags 2): %s err=%s",
         bad == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : bad == NULL ? "NULL" : "a handle", err);
    if (bad != INVALID_HANDLE_VALUE && bad != NULL) {
        CloseHandle(bad);
    }

    set_active_line("the new buffer", buffer);
    again = open_conout(FALSE);
    if (again == INVALID_HANDLE_VALUE) {
        line("CONOUT$ opened then: err=%lu", GetLastError());
    } else {
        show_row("CONOUT$ opened then", again, sizeof text);
        line("the section's mark in it: %s", yesno(holds(again, mark)));
        CloseHandle(again);
    }
    show_info("the original buffer, inactive", original, &active);
    set_active_line("the original buffer", original);
    again = open_conout(FALSE);
    if (again == INVALID_HANDLE_VALUE) {
        line("CONOUT$ opened after it: err=%lu", GetLastError());
    } else {
        line("CONOUT$ opened after it: the section's mark in it: %s", yesno(holds(again, mark)));
        CloseHandle(again);
    }

    set_active_line("NULL", NULL);
    set_active_line("INVALID_HANDLE_VALUE", INVALID_HANDLE_VALUE);
    if (CreatePipe(&rp, &wp, NULL, 0)) {
        set_active_line("a pipe's write end", wp);
        CloseHandle(rp);
        CloseHandle(wp);
    }
    in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                     OPEN_EXISTING, 0, NULL);
    if (in != INVALID_HANDLE_VALUE) {
        set_active_line("CONIN$", in);
        CloseHandle(in);
    }
    /* Whatever the refusals did, the original buffer is the active one
     * again before the new one goes. */
    set_active(original);
    arm();
    r = CloseHandle(buffer);
    strcpy(err, le());
    line("CloseHandle(the new buffer, inactive): ret=%d err=%s", r, err);
    CloseHandle(original);
    end();
}

static const section_t sections[] = {
    { "inherit", sec_inherit, F2KT_ALWAYS },
    { "newconsole", sec_newconsole, F2KT_ALWAYS },
    { "detached", sec_detached, F2KT_ALWAYS },
    { "alloc", sec_alloc, F2KT_ALWAYS },
    { "ctrl", sec_ctrl, F2KT_ALWAYS },
    { "buffers", sec_buffers, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    HMODULE k32;
    char *p;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, home, sizeof home);
    p = strrchr(home, '\\');
    if (p != NULL) {
        *p = 0;
    }
    sprintf(kid, "%s\\conkid.exe", home);
    SetCurrentDirectoryA(home);
    SetEnvironmentVariableA("F2KHOME", home);
    k32 = GetModuleHandleA("kernel32.dll");
    console_window = (window_fn)(void *)GetProcAddress(k32, "GetConsoleWindow");
    create_buffer = (create_buffer_fn)(void *)GetProcAddress(k32, "CreateConsoleScreenBuffer");
    set_active = (set_active_fn)(void *)GetProcAddress(k32, "SetConsoleActiveScreenBuffer");
    return run_sections("newcon", sections, argc, argv);
}
