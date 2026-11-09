/*
 * shutkid - the shutparm fixture's companion program: the child
 * shutparm.exe starts once it has set its own shutdown parameters, which
 * reports the parameters it starts with (a child inherits nothing, the
 * documentation says: every process starts at level 0x280), then sets
 * its own and reads them back.
 *
 * Every line it prints starts with "kid: " and is one WriteFile, CR LF
 * terminated, through the standard output it inherits. It calls
 * SetErrorMode first, so a fault ends it quietly with the exception's
 * code. It takes no argument, waits for nothing, and exits 0.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat shutparm):
 *   cl /nologo /MD shutkid.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The last-error sentinel, as common/f2kt.h's. */
#define UNTOUCHED 0x0F2F2F2Fu

/* What an out-parameter holds before the call, to see it untouched. */
#define UNSET 0xDEADBEEFu

#ifndef SHUTDOWN_NORETRY
#define SHUTDOWN_NORETRY 0x00000001
#endif

/* Print one line, "kid: " first: formatted, CR LF appended, one WriteFile. */
static void say(const char *fmt, ...)
{
    char buf[512];
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
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &written, NULL);
}

/* The last error as printed: "-" when the sentinel survived. */
static const char *le(void)
{
    static char bufs[4][16];
    static int next;
    DWORD e = GetLastError();
    char *b = bufs[next++ & 3];

    if (e == UNTOUCHED) {
        return "-";
    }
    sprintf(b, "%lu", e);
    return b;
}

/* GetProcessShutdownParameters, printed as `what`. */
static void show(const char *what)
{
    DWORD level = UNSET;
    DWORD flags = UNSET;
    BOOL r;

    SetLastError(UNTOUCHED);
    r = GetProcessShutdownParameters(&level, &flags);
    say("%s: ret=%d err=%s level=0x%lX flags=0x%lX", what, r, le(), level, flags);
}

int main(void)
{
    BOOL r;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    show("started with");
    SetLastError(UNTOUCHED);
    r = SetProcessShutdownParameters(0x101, 0);
    say("set 0x101, 0: ret=%d err=%s", r, le());
    show("then");
    return 0;
}
