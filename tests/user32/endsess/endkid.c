/*
 * endkid - the endsess fixture's companion program, for F2K's own boots
 * of the session's end (tests/core/kernel/test_kernel.py): a program
 * with a window, whose procedure answers WM_QUERYENDSESSION as told and
 * prints each WM_QUERYENDSESSION and WM_ENDSESSION it receives. The
 * real machine's capture never runs it.
 *
 *   endkid yes|no [shutdown]
 *
 * - It makes a hidden top-level window whose procedure answers
 *   WM_QUERYENDSESSION TRUE (yes) or FALSE (no).
 * - With "shutdown", it then asks for the session's end itself:
 *   ExitWindowsEx(EWX_SHUTDOWN, 0), without enabling
 *   SeShutdownPrivilege. Windows 2000 refuses that call
 *   (ERROR_PRIVILEGE_NOT_HELD, the exitwin capture), so the program
 *   never shuts a real machine down; F2K checks no privilege, and its
 *   session's end then asks this program's window. No other request is
 *   ever made: a logoff needs no privilege.
 * - It pumps its messages (PeekMessageA, a 20 ms Sleep between two
 *   empty looks). WM_ENDSESSION with wParam FALSE (the session's end
 *   cancelled) ends it with 0. Otherwise it ends itself with 1 after 30
 *   seconds: the session's end ends the program after WM_ENDSESSION
 *   TRUE, and the bound only ends a run that is never ended.
 *
 * Every line it prints starts with "endkid: " and is one WriteFile, CR
 * LF terminated, through the standard output it inherits. It calls
 * SetErrorMode first, so a fault ends it quietly with the exception's
 * code.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat endsess):
 *   cl /nologo /MD endkid.c user32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The last-error sentinel, as common/f2kt.h's. */
#define UNTOUCHED 0x0F2F2F2Fu

/* How long the program waits for the session's end at most. */
#define BOUND_MS 30000

/* The procedure's answer to WM_QUERYENDSESSION. */
static BOOL answer;

/* Print one line, "endkid: " first: formatted, CR LF appended, one
 * WriteFile. */
static void say(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    int n;
    DWORD written;

    strcpy(buf, "endkid: ");
    va_start(ap, fmt);
    n = _vsnprintf(buf + 8, sizeof buf - 10, fmt, ap);
    va_end(ap);
    if (n < 0) {
        n = sizeof buf - 10;
    }
    n += 8;
    buf[n++] = '\r';
    buf[n++] = '\n';
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &written, NULL);
}

/* The last error as printed: "-" when the sentinel survived. */
static const char *le(void)
{
    static char buf[16];
    DWORD e = GetLastError();

    if (e == UNTOUCHED) {
        return "-";
    }
    sprintf(buf, "%lu", e);
    return buf;
}

static LRESULT CALLBACK procedure(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_QUERYENDSESSION:
        say("WM_QUERYENDSESSION wParam=%lu lParam=0x%08lX: answers %s", (unsigned long)wparam,
            (unsigned long)lparam, answer ? "TRUE" : "FALSE");
        return answer;
    case WM_ENDSESSION:
        say("WM_ENDSESSION wParam=%lu lParam=0x%08lX", (unsigned long)wparam, (unsigned long)lparam);
        if (!wparam) {
            PostQuitMessage(0);
        }
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

int main(int argc, char **argv)
{
    WNDCLASSA wc;
    HWND h;
    MSG m;
    BOOL r;
    DWORD start;
    int shutdown;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc < 2 || (strcmp(argv[1], "yes") != 0 && strcmp(argv[1], "no") != 0)
        || (argc > 2 && strcmp(argv[2], "shutdown") != 0) || argc > 3) {
        say("usage: endkid yes|no [shutdown]");
        return 2;
    }
    answer = strcmp(argv[1], "yes") == 0;
    shutdown = argc > 2;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = procedure;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "F2KEndkid";
    if (RegisterClassA(&wc) == 0) {
        say("RegisterClassA failed, err=%lu", GetLastError());
        return 1;
    }
    h = CreateWindowExA(0, "F2KEndkid", "endkid", WS_POPUP, 0, 0, 320, 200, NULL, NULL,
                        GetModuleHandleA(NULL), NULL);
    if (h == NULL) {
        say("CreateWindowExA failed, err=%lu", GetLastError());
        return 1;
    }
    say("window made; it answers WM_QUERYENDSESSION %s", answer ? "TRUE" : "FALSE");
    start = GetTickCount();

    if (shutdown) {
        SetLastError(UNTOUCHED);
        r = ExitWindowsEx(EWX_SHUTDOWN, 0);
        say("ExitWindowsEx(EWX_SHUTDOWN): ret=%d err=%s", r, le());
    }

    for (;;) {
        while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
            if (m.message == WM_QUIT) {
                say("the session goes on: done");
                DestroyWindow(h);
                return 0;
            }
            DispatchMessageA(&m);
        }
        if (GetTickCount() - start >= BOUND_MS) {
            say("no session's end within %d s: done", BOUND_MS / 1000);
            DestroyWindow(h);
            return 1;
        }
        Sleep(20);
    }
}
