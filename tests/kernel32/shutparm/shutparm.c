/*
 * shutparm - a process's shutdown parameters: SetProcessShutdownParameters
 * and GetProcessShutdownParameters, the level that orders the session's
 * end (the highest level is asked first) and the SHUTDOWN_NORETRY flag.
 *
 * The documentation gives the levels' ranges: 0x000-0x0FF reserved for
 * the system, 0x100-0x1FF the applications' last, 0x200-0x2FF their "in
 * between", 0x300-0x3FF their first; every process starts at 0x280, with
 * no flag. It names no error for a level or a flag outside them, and
 * Windows 2000 refuses neither: every level is kept, and a flag other than
 * SHUTDOWN_NORETRY leaves the parameters as they were, the call still
 * answering TRUE.
 *
 * Nothing here ends the session: the program never calls ExitWindowsEx,
 * and the parameters it sets are its own, gone when it ends. Each call
 * prints its return and its last error (armed before it); each read
 * prints the level and the flags, which hold 0xDEADBEEF before the call.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   default  the parameters a process starts with
 *   bands    each band's edges (0x100, 0x1FF, 0x200, 0x280, 0x2FF,
 *            0x300, 0x3FF), with no flag and with SHUTDOWN_NORETRY, each
 *            read back after it is set
 *   invalid  from a known setting (0x300, SHUTDOWN_NORETRY): levels in
 *            the system's range (0x000, 0x001, 0x080, 0x0FF) and above
 *            the applications' (0x400, 0x401, 0x4FF, 0x500, 0xFFF,
 *            0x10000, 0x7FFFFFFF, 0xFFFFFFFF) with no flag; flags other
 *            than SHUTDOWN_NORETRY (0x2, 0x3, 0x4, 0x80000000,
 *            0xFFFFFFFF) with level 0x280; a level outside the bands
 *            with a flag other than SHUTDOWN_NORETRY. After each, the
 *            parameters read back: whether the call changed them
 *   child    this process at 0x3FF with SHUTDOWN_NORETRY, then a child,
 *            shutkid.exe (the companion program built beside this one),
 *            which prints the parameters it starts with, sets its own
 *            (0x101) and reads them back; then the child's end, and this
 *            process's parameters again. The child inherits this
 *            program's standard output and prints through it; this
 *            program prints nothing while the child runs. The wait is
 *            bounded, and a child that outlasts it is terminated
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat shutparm):
 *   cl /nologo /MD shutkid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% shutparm.c
 */

#include "../common/f2kt.h"

#ifndef SHUTDOWN_NORETRY
#define SHUTDOWN_NORETRY 0x00000001
#endif

/* What an out-parameter holds before the call, to see it untouched. */
#define UNSET 0xDEADBEEFu

static char kid[MAX_PATH];          /* shutkid.exe beside this program */

/* An exit code as printed: an NTSTATUS-like one in hex. */
static const char *code_text(DWORD code)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, code >= 0x80000000u ? "0x%08lX" : "%lu", code);
    return b;
}

/* GetProcessShutdownParameters, printed as `what`. */
static void show(const char *what)
{
    DWORD level = UNSET;
    DWORD flags = UNSET;
    BOOL r;

    arm();
    r = GetProcessShutdownParameters(&level, &flags);
    line("%s: ret=%d err=%s level=0x%lX flags=0x%lX", what, r, le(), level, flags);
}

/* SetProcessShutdownParameters(level, flags), printed, then the read
 * back. */
static void set_and_show(DWORD level, DWORD flags)
{
    BOOL r;

    arm();
    r = SetProcessShutdownParameters(level, flags);
    line("set 0x%lX, 0x%lX: ret=%d err=%s", level, flags, r, le());
    show("read back");
}

static void sec_default(void)
{
    show("at the start");
}

static void sec_bands(void)
{
    static const DWORD levels[] = { 0x100, 0x1FF, 0x200, 0x280, 0x2FF, 0x300, 0x3FF };
    int i;

    for (i = 0; i < (int)(sizeof levels / sizeof levels[0]); i++) {
        set_and_show(levels[i], 0);
        set_and_show(levels[i], SHUTDOWN_NORETRY);
    }
}

static void sec_invalid(void)
{
    static const DWORD levels[] = {
        0x000, 0x001, 0x080, 0x0FF,
        0x400, 0x401, 0x4FF, 0x500, 0xFFF, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF
    };
    static const DWORD flags[] = { 0x2, 0x3, 0x4, 0x80000000, 0xFFFFFFFF };
    int i;

    line("the known setting:");
    set_and_show(0x300, SHUTDOWN_NORETRY);
    line("levels:");
    for (i = 0; i < (int)(sizeof levels / sizeof levels[0]); i++) {
        set_and_show(levels[i], 0);
    }
    line("flags:");
    for (i = 0; i < (int)(sizeof flags / sizeof flags[0]); i++) {
        set_and_show(0x280, flags[i]);
    }
    line("both:");
    set_and_show(0x0FF, 0x2);
    set_and_show(0x400, 0x2);
}

static void sec_child(void)
{
    char cmd[32];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 0xF2F2F2F2u;
    DWORD w;
    BOOL r;

    set_and_show(0x3FF, SHUTDOWN_NORETRY);
    strcpy(cmd, "shutkid");
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    arm();
    r = CreateProcessA(kid, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (!r) {
        line("shutkid not started, err=%s", le());
        return;
    }
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 0xDEAD);
        WaitForSingleObject(pi.hProcess, WAIT_MS);
    }
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    line("the child's end: %s, exit code %s", wr(w), code_text(code));
    show("this process after the child");
}

static const section_t sections[] = {
    { "default", sec_default, F2KT_ALWAYS },
    { "bands", sec_bands, F2KT_ALWAYS },
    { "invalid", sec_invalid, F2KT_ALWAYS },
    { "child", sec_child, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    char *p;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, kid, sizeof kid - 16);
    p = strrchr(kid, '\\');
    if (p != NULL) {
        p[1] = '\0';
    } else {
        kid[0] = '\0';
    }
    strcat(kid, "shutkid.exe");
    return run_sections("shutparm", sections, argc, argv);
}
