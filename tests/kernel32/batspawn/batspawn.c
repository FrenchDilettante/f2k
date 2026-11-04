/*
 * batspawn - CreateProcess on batch files. A .bat or .cmd file is no
 * image: CreateProcessA and CreateProcessW run it through the command
 * processor instead, with a command line of their own making. The
 * sections write the batch files themselves, and observe which program
 * runs them, the command line it is given, and what refuses to run.
 *
 * The command processor is blkid.exe, the companion program built beside
 * this one, standing in for cmd.exe: it prints its own command line and
 * its image's path relative to this program's directory, and exits 0; it
 * runs nothing (blkid.c). ComSpec names it, and a copy of it named
 * cmd.exe sits in the current directory, which the program search takes
 * before the system directory: the output shows whether CreateProcess
 * finds the command processor through ComSpec (BLKID.EXE) or by
 * searching for cmd (SCRATCH\CMD.EXE). The realcmd section takes the
 * copy away, and the machine's own cmd.exe runs the batch files.
 *
 * Everything the program creates goes in SCRATCH, a directory beside it,
 * which each section empties first and removes at its end, so no cmd.exe
 * is left behind. Each section runs with SCRATCH its current directory,
 * F2KHOME naming the program's directory (the children print paths
 * relative to it), and ComSpec as the section sets it, restored at its
 * end. A child prints through the standard handles it inherits, so its
 * lines land between the case's heading and its result.
 *
 * The batch files, in SCRATCH, each run with echo off:
 *
 *   job.bat              prints "job.bat ran: [<its name>] [<arguments>]",
 *                        then exit 4
 *   job.cmd              the same with job.cmd, then exit /b 3
 *   with space\job.bat   prints "spaced job.bat ran: [<arguments>]", then
 *                        exit 5
 *   empty.bat            empty
 *   notbat.txt           a batch file's text, named .txt
 *
 * A case's heading names the application name, then the command line.
 * Each case runs through CreateProcessA, then CreateProcessW on the same
 * inputs.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   comspec   which program runs job.bat, the copy as cmd.exe in the
 *             current directory throughout: ComSpec naming blkid.exe,
 *             unset, and naming a missing file
 *   cmdline   the command line the command processor is given, with
 *             ComSpec naming blkid.exe and the copy in the current
 *             directory: the application name NULL and set (alone, with
 *             the same name as the command line, another command line,
 *             another batch file's name, an absolute path); a .cmd; an
 *             upper-case .BAT; arguments with quotes; a name with a
 *             space, quoted and not, as the command line and as the
 *             application name; then what does not run: the name without
 *             its extension, an empty .bat, and a .txt
 *   realcmd   no copy in the current directory: whether ComSpec was set
 *             when the program started; ComSpec as the program found it
 *             (the machine's own cmd.exe running job.bat, job.cmd and the
 *             name with a space, their output and the exit codes exit 4,
 *             exit /b 3 and exit 5 leave), unset, and naming blkid.exe
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat batspawn):
 *   cl /nologo /MD blkid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% batspawn.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>

static char home[MAX_PATH];             /* the program's directory, no trailing backslash */
static char kid[MAX_PATH];              /* home\blkid.exe */
static char saved_comspec[MAX_PATH];    /* ComSpec as the program found it */
static int had_comspec;

/* --- helpers ------------------------------------------------------- */

/* A path under the program's directory. */
static const char *at(const char *rel)
{
    static char bufs[4][2 * MAX_PATH];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s\\%s", home, rel);
    return b;
}

static WCHAR *widen(const char *s, WCHAR *buf, int size)
{
    if (s == NULL) {
        return NULL;
    }
    MultiByteToWideChar(CP_ACP, 0, s, -1, buf, size);
    return buf;
}

/* An exit code as printed: an NTSTATUS-like one in hex. */
static const char *code_text(DWORD code)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, code >= 0x80000000u ? "0x%08lX" : "%lu", code);
    return b;
}

/* Empty a directory (`dir` ends in a backslash; one level of
 * subdirectories deep) without printing. */
static void wipe(const char *dir)
{
    char pat[2 * MAX_PATH];
    char path[2 * MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE f;

    sprintf(pat, "%s*", dir);
    f = FindFirstFileA(pat, &fd);
    if (f == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }
        sprintf(path, "%s%s", dir, fd.cFileName);
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            strcat(path, "\\");
            wipe(path);
            path[strlen(path) - 1] = 0;
            RemoveDirectoryA(path);
        } else {
            DeleteFileA(path);
        }
    } while (FindNextFileA(f, &fd));
    FindClose(f);
}

static void make_file(const char *path, const char *text)
{
    DWORD n;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (f == INVALID_HANDLE_VALUE) {
        line("setup: a file not created, err=%lu", GetLastError());
        return;
    }
    WriteFile(f, text, (DWORD)strlen(text), &n, NULL);
    CloseHandle(f);
}

/* ComSpec set to `value`, or removed for NULL. */
static void set_comspec(const char *value)
{
    SetEnvironmentVariableA("ComSpec", value);
}

static void restore_comspec(void)
{
    SetEnvironmentVariableA("ComSpec", had_comspec ? saved_comspec : NULL);
}

/* A section's start: SCRATCH empty, the batch files written, with
 * `plant` blkid.exe copied there as cmd.exe; SCRATCH the current
 * directory. */
static void setup(int plant)
{
    SetCurrentDirectoryA(home);
    CreateDirectoryA(at("SCRATCH"), NULL);
    wipe(at("SCRATCH\\"));
    CreateDirectoryA(at("SCRATCH\\with space"), NULL);
    make_file(at("SCRATCH\\job.bat"), "@echo off\r\necho job.bat ran: [%~nx0] [%*]\r\nexit 4\r\n");
    make_file(at("SCRATCH\\job.cmd"), "@echo off\r\necho job.cmd ran: [%~nx0] [%*]\r\nexit /b 3\r\n");
    make_file(at("SCRATCH\\with space\\job.bat"), "@echo off\r\necho spaced job.bat ran: [%*]\r\nexit 5\r\n");
    make_file(at("SCRATCH\\empty.bat"), "");
    make_file(at("SCRATCH\\notbat.txt"), "@echo off\r\necho notbat.txt ran\r\n");
    if (plant && !CopyFileA(kid, at("SCRATCH\\cmd.exe"), FALSE)) {
        line("setup: blkid.exe not copied as cmd.exe, err=%lu", GetLastError());
    }
    SetCurrentDirectoryA(at("SCRATCH"));
}

/* A section's end: SCRATCH gone, ComSpec as the program found it. */
static void teardown(void)
{
    SetCurrentDirectoryA(home);
    wipe(at("SCRATCH\\"));
    RemoveDirectoryA(at("SCRATCH"));
    restore_comspec();
}

/* CreateProcessA, or (wide) CreateProcessW on the same inputs widened,
 * inheriting handles. The last error is armed just before the call, and
 * left as it set it. */
static BOOL launch(int wide, const char *app, const char *cmd, PROCESS_INFORMATION *pi)
{
    static char cmdbuf[2048];
    static WCHAR wapp[2 * MAX_PATH], wcmd[2048];
    STARTUPINFOA si;
    STARTUPINFOW siw;
    WCHAR *a, *c;

    memset(pi, 0, sizeof *pi);
    if (!wide) {
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        if (cmd != NULL) {
            strcpy(cmdbuf, cmd);
        }
        arm();
        return CreateProcessA(app, cmd != NULL ? cmdbuf : NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, pi);
    }
    memset(&siw, 0, sizeof siw);
    siw.cb = sizeof siw;
    a = widen(app, wapp, sizeof wapp / sizeof wapp[0]);
    c = widen(cmd, wcmd, sizeof wcmd / sizeof wcmd[0]);
    arm();
    return CreateProcessW(a, c, NULL, NULL, TRUE, 0, NULL, NULL, &siw, pi);
}

/* Wait for a started child's end (ending it, should it outlast the
 * bound) and close its handles: its exit code, and the wait's result. */
static DWORD finish(PROCESS_INFORMATION *pi, DWORD *wait)
{
    DWORD code = 0xF2F2F2F2u, w;

    w = WaitForSingleObject(pi->hProcess, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(pi->hProcess, 0xDEAD);
        WaitForSingleObject(pi->hProcess, WAIT_MS);
    }
    GetExitCodeProcess(pi->hProcess, &code);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
    *wait = w;
    return code;
}

/* One case as the sections print it: a heading, whatever the child
 * prints, then the call's result and the child's end. */
static void create(int wide, const char *label, const char *app, const char *cmd)
{
    PROCESS_INFORMATION pi;
    char err[16];
    BOOL r;
    DWORD code, w;

    line("%s(%s):", wide ? "CreateProcessW" : "CreateProcessA", label);
    r = launch(wide, app, cmd, &pi);
    strcpy(err, le());
    if (!r) {
        line("  ret=0 err=%s", err);
        return;
    }
    code = finish(&pi, &w);
    line("  ret=%d err=%s; the child's end: %s, exit code %s", r, err, wr(w), code_text(code));
}

/* --- comspec ------------------------------------------------------- */

static void comspec_cases(int wide)
{
    set_comspec(kid);
    create(wide, "ComSpec blkid.exe: NULL, job.bat one", NULL, "job.bat one");
    set_comspec(NULL);
    create(wide, "ComSpec unset: NULL, job.bat one", NULL, "job.bat one");
    set_comspec(at("SCRATCH\\none.exe"));
    create(wide, "ComSpec a missing file: NULL, job.bat one", NULL, "job.bat one");
}

static void sec_comspec(void)
{
    setup(1);
    comspec_cases(0);
    comspec_cases(1);
    teardown();
}

/* --- cmdline ------------------------------------------------------- */

static void cmdline_cases(int wide)
{
    char absolute[2 * MAX_PATH];

    strcpy(absolute, at("SCRATCH\\job.bat"));
    create(wide, "NULL, job.bat", NULL, "job.bat");
    create(wide, "NULL, job.bat with arguments", NULL, "job.bat one \"two words\" three");
    create(wide, "NULL, job.cmd x", NULL, "job.cmd x");
    create(wide, "NULL, JOB.BAT x", NULL, "JOB.BAT x");
    create(wide, "job.bat, NULL", "job.bat", NULL);
    create(wide, "job.bat, job.bat x", "job.bat", "job.bat x");
    create(wide, "job.bat, other words y", "job.bat", "other words y");
    create(wide, "job.cmd, job.bat z", "job.cmd", "job.bat z");
    create(wide, "job.bat by its absolute path, NULL", absolute, NULL);
    create(wide, "NULL, with space\\job.bat x unquoted", NULL, "with space\\job.bat x");
    create(wide, "NULL, with space\\job.bat x quoted", NULL, "\"with space\\job.bat\" x");
    create(wide, "with space\\job.bat, NULL", "with space\\job.bat", NULL);
    create(wide, "with space\\job.bat, job x", "with space\\job.bat", "job x");
    create(wide, "NULL, job x", NULL, "job x");
    create(wide, "NULL, empty.bat", NULL, "empty.bat");
    create(wide, "NULL, notbat.txt", NULL, "notbat.txt");
    create(wide, "notbat.txt, NULL", "notbat.txt", NULL);
}

static void sec_cmdline(void)
{
    setup(1);
    set_comspec(kid);
    cmdline_cases(0);
    cmdline_cases(1);
    teardown();
}

/* --- realcmd ------------------------------------------------------- */

static void realcmd_cases(int wide)
{
    restore_comspec();
    create(wide, "ComSpec as found: NULL, job.bat one", NULL, "job.bat one");
    create(wide, "ComSpec as found: NULL, job.cmd two", NULL, "job.cmd two");
    create(wide, "ComSpec as found: NULL, with space\\job.bat three quoted", NULL,
           "\"with space\\job.bat\" three");
    set_comspec(NULL);
    create(wide, "ComSpec unset: NULL, job.bat four", NULL, "job.bat four");
    set_comspec(kid);
    create(wide, "ComSpec blkid.exe: NULL, job.bat five", NULL, "job.bat five");
}

static void sec_realcmd(void)
{
    setup(0);
    line("ComSpec when the program started: %s", had_comspec ? "set" : "unset");
    realcmd_cases(0);
    realcmd_cases(1);
    teardown();
}

/* --- main ---------------------------------------------------------- */

static const section_t sections[] = {
    { "comspec", sec_comspec, F2KT_ALWAYS },
    { "cmdline", sec_cmdline, F2KT_ALWAYS },
    { "realcmd", sec_realcmd, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    char *p;
    DWORD n;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, home, sizeof home);
    p = strrchr(home, '\\');
    if (p != NULL) {
        *p = 0;
    }
    sprintf(kid, "%s\\blkid.exe", home);
    n = GetEnvironmentVariableA("ComSpec", saved_comspec, sizeof saved_comspec);
    had_comspec = n != 0 && n < sizeof saved_comspec;
    /* The children print paths relative to F2KHOME. */
    SetEnvironmentVariableA("F2KHOME", home);
    return run_sections("batspawn", sections, argc, argv);
}
