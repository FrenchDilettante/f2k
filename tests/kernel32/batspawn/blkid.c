/*
 * blkid - the batspawn fixture's companion program: the stand-in
 * command processor. batspawn.exe points ComSpec at it, and copies it
 * as cmd.exe into its current directory, so whichever of the two
 * CreateProcess starts for a batch file prints what it was given.
 *
 * It prints its own command line (GetCommandLineA), then its image's
 * path, and exits 0. Every line starts "blkid: " and is one WriteFile,
 * CR LF terminated, as the fixtures' lines are. It calls SetErrorMode
 * first, so a fault ends it quietly with the exception's code. It never
 * prints an absolute path: the parent's directory (the F2KHOME variable
 * the parent sets) prints as <home>, and the image's path relative to
 * it, upper-cased (BLKID.EXE, SCRATCH\CMD.EXE).
 *
 * It runs nothing: a batch file given to it never runs.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat batspawn):
 *   cl /nologo /MD blkid.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static char home[MAX_PATH];     /* F2KHOME; empty when unset */

/* Print one line: "blkid: ", the text, CR LF, one WriteFile. */
static void say(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    DWORD written;

    strcpy(buf, "blkid: ");
    va_start(ap, fmt);
    n = _vsnprintf(buf + 7, sizeof buf - 9, fmt, ap);
    va_end(ap);
    if (n < 0) {
        n = sizeof buf - 9;
    }
    n += 7;
    buf[n++] = '\r';
    buf[n++] = '\n';
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &written, NULL);
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

/* A path relative to the parent's directory, upper-cased. */
static const char *relative(const char *path)
{
    static char b[MAX_PATH];
    size_t len = strlen(home);
    int i;

    if (len == 0) {
        return "(F2KHOME unset)";
    }
    if (_strnicmp(path, home, len) != 0 || path[len] != '\\') {
        return "outside the parent's directory";
    }
    for (i = 0; path[len + 1 + i] != 0 && i < MAX_PATH - 1; i++) {
        b[i] = (char)toupper((unsigned char)path[len + 1 + i]);
    }
    b[i] = 0;
    return b;
}

int main(void)
{
    char path[MAX_PATH];
    DWORD n;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    n = GetEnvironmentVariableA("F2KHOME", home, sizeof home);
    if (n == 0 || n >= sizeof home) {
        home[0] = 0;
    }
    say("command line [%s]", scrub(GetCommandLineA()));
    path[0] = 0;
    GetModuleFileNameA(NULL, path, sizeof path);
    say("image %s", relative(path));
    return 0;
}
