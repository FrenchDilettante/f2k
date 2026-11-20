/*
 * pipekid - the pipe fixture's companion program: the child pipe.exe
 * starts with pipes for its standard handles, doing what its first
 * argument says, and the stand-in command processor the popen section
 * points COMSPEC at.
 *
 * Every line it prints starts "pipekid: " and is one WriteFile, CR LF
 * terminated, as the fixtures' lines are; cat and upper pass their input
 * on as it came instead. It calls SetErrorMode first, so a fault ends it
 * quietly with the exception's code. It never prints an absolute path:
 * where one would show, the parent's directory (the F2KHOME variable the
 * parent sets) prints as <home>.
 *
 * Modes:
 *
 *   emit <n>      n lines, "pipekid: line <i>", each one WriteFile to the
 *                 standard output; a write that fails ends it, the error
 *                 its exit code (one line to the standard error says so)
 *   cat           the standard input to the standard output as it is, one
 *                 WriteFile per ReadFile, until a read returns 0 bytes or
 *                 fails; a write that fails ends it, the error its exit
 *                 code
 *   upper         the same, in capitals
 *   count         reads the standard input to its end, then prints the
 *                 lines (LFs) and bytes it read and how the last read
 *                 ended (0 bytes read, or the error: 109 for a broken
 *                 pipe)
 *   exit <n>      exit with code n (decimal, or hex as 0x...); prints
 *                 nothing
 *   types         each standard handle's file type and handle flags
 *   blob <n>      n bytes (byte i is i mod 251) to the standard output in
 *                 one WriteFile; a write that fails ends it, the error
 *                 its exit code (one line to the standard error says so)
 *   crtin         the C runtime's view of a piped standard input: _isatty
 *                 and GetConsoleMode of each standard handle, then every
 *                 line fgets reads from stdin (text mode), escaped, then
 *                 feof and ferror
 *   fread         fread of 7 bytes at a time from stdin (text mode) until
 *                 it returns 0, each count and the bytes, then feof
 *   peekin        PeekNamedPipe on the standard input (the parent wrote
 *                 into it and closed it before the start), one ReadFile,
 *                 PeekNamedPipe again (the pipe drained and its writer
 *                 gone), and PeekNamedPipe on the standard output (a
 *                 pipe's write end)
 *   /c <command>  a stand-in command processor: prints its own command
 *                 line (the parent's directory as <home>), then runs the
 *                 rest of it after the switch, as it stands, with
 *                 CreateProcessA (the program searched for as CreateProcess
 *                 does, its standard handles this one's, inherited), and
 *                 exits with the command's exit code (1 if it could not be
 *                 started). The command is ended after 8 seconds, should
 *                 it overrun, so the caller's wait always ends.
 *   (anything else) that the mode is unknown; exit 100
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat pipe):
 *   cl /nologo /MD pipekid.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <io.h>

/* The last-error sentinel, as common/f2kt.h's. */
#define UNTOUCHED 0x0F2F2F2Fu

/* How long the stand-in command processor lets its command run. */
#define COMMAND_MS 8000

static char home[MAX_PATH];     /* F2KHOME; empty when unset */

/* Print one line to `to`: "pipekid: ", the text, CR LF, one WriteFile. */
static void say(HANDLE to, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    DWORD written;

    strcpy(buf, "pipekid: ");
    va_start(ap, fmt);
    n = _vsnprintf(buf + 9, sizeof buf - 11, fmt, ap);
    va_end(ap);
    if (n < 0) {
        n = sizeof buf - 11;
    }
    n += 9;
    buf[n++] = '\r';
    buf[n++] = '\n';
    WriteFile(to, buf, (DWORD)n, &written, NULL);
}

static HANDLE out(void)
{
    return GetStdHandle(STD_OUTPUT_HANDLE);
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

static int emit(int count)
{
    char buf[64];
    DWORD written, e;
    int i, len;

    for (i = 1; i <= count; i++) {
        len = sprintf(buf, "pipekid: line %d\r\n", i);
        SetLastError(UNTOUCHED);
        if (!WriteFile(out(), buf, (DWORD)len, &written, NULL)) {
            e = GetLastError();
            say(GetStdHandle(STD_ERROR_HANDLE), "emit: line %d not written, err=%s", i, le_of(e));
            return (int)e;
        }
    }
    return 0;
}

/* cat, or upper with `capitals`. */
static int pass_on(int capitals)
{
    char buf[512];
    DWORD n, written, i;

    for (;;) {
        n = 0;
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof buf, &n, NULL) || n == 0) {
            return 0;
        }
        if (capitals) {
            for (i = 0; i < n; i++) {
                buf[i] = (char)toupper((unsigned char)buf[i]);
            }
        }
        SetLastError(UNTOUCHED);
        if (!WriteFile(out(), buf, n, &written, NULL)) {
            return (int)GetLastError();
        }
    }
}

static void count(void)
{
    char buf[4096];
    DWORD n, i, bytes = 0, lines = 0, e = UNTOUCHED;
    BOOL r = FALSE;

    for (;;) {
        n = 0;
        SetLastError(UNTOUCHED);
        r = ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof buf, &n, NULL);
        e = GetLastError();
        if (!r || n == 0) {
            break;
        }
        bytes += n;
        for (i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                lines++;
            }
        }
    }
    if (r) {
        say(out(), "count: %lu lines, %lu bytes; the last read: ret=%d, 0 bytes, err=%s", lines, bytes, r,
            le_of(e));
    } else {
        say(out(), "count: %lu lines, %lu bytes; the last read: ret=%d err=%s", lines, bytes, r, le_of(e));
    }
}

static void report_handle(const char *name, HANDLE h)
{
    DWORD type, flags, e;

    if (h == NULL) {
        say(out(), "%s: NULL", name);
        return;
    }
    if (h == INVALID_HANDLE_VALUE) {
        say(out(), "%s: INVALID_HANDLE_VALUE", name);
        return;
    }
    SetLastError(UNTOUCHED);
    type = GetFileType(h);
    e = GetLastError();
    flags = UNTOUCHED;
    if (GetHandleInformation(h, &flags)) {
        say(out(), "%s: type %lu err=%s, flags 0x%lX", name, type, le_of(e), flags);
    } else {
        say(out(), "%s: type %lu err=%s, GetHandleInformation err=%lu", name, type, le_of(e), GetLastError());
    }
}

static void types(void)
{
    report_handle("standard input", GetStdHandle(STD_INPUT_HANDLE));
    report_handle("standard output", GetStdHandle(STD_OUTPUT_HANDLE));
    report_handle("standard error", GetStdHandle(STD_ERROR_HANDLE));
}

static int blob(DWORD size)
{
    BYTE *buf = (BYTE *)malloc(size + 1);
    DWORD i, written = 0, e;

    if (buf == NULL) {
        say(GetStdHandle(STD_ERROR_HANDLE), "blob: no memory");
        return 8;
    }
    for (i = 0; i < size; i++) {
        buf[i] = (BYTE)(i % 251);
    }
    SetLastError(UNTOUCHED);
    if (!WriteFile(out(), buf, size, &written, NULL)) {
        e = GetLastError();
        say(GetStdHandle(STD_ERROR_HANDLE), "blob: not written, err=%s", le_of(e));
        free(buf);
        return (int)e;
    }
    free(buf);
    return 0;
}

/* Bytes as printed: printable ASCII as it is, CR and LF as \r and \n,
 * any other byte as \xNN. */
static const char *esc(const char *p, int n)
{
    static char b[600];
    int i, k = 0;

    for (i = 0; i < n && k < (int)sizeof b - 8; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\r') {
            b[k++] = '\\';
            b[k++] = 'r';
        } else if (c == '\n') {
            b[k++] = '\\';
            b[k++] = 'n';
        } else if (c < 0x20 || c >= 0x7F) {
            k += sprintf(b + k, "\\x%02X", c);
        } else {
            b[k++] = (char)c;
        }
    }
    b[k] = 0;
    return b;
}

static const char *const std_names[3] = { "stdin", "stdout", "stderr" };
static const DWORD std_ids[3] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };

static void crtin(void)
{
    char buf[256];
    DWORD mode, e;
    BOOL r;
    int i, lines = 0;

    for (i = 0; i < 3; i++) {
        mode = UNTOUCHED;
        SetLastError(UNTOUCHED);
        r = GetConsoleMode(GetStdHandle(std_ids[i]), &mode);
        e = GetLastError();
        say(out(), "crtin: %s: _isatty %s; GetConsoleMode ret=%d err=%s", std_names[i],
            _isatty(i) ? "yes" : "no", r, le_of(e));
    }
    while (fgets(buf, sizeof buf, stdin) != NULL) {
        lines++;
        say(out(), "crtin: fgets [%s]", esc(buf, (int)strlen(buf)));
    }
    say(out(), "crtin: %d lines; feof %s, ferror %s", lines, feof(stdin) ? "yes" : "no",
        ferror(stdin) ? "yes" : "no");
}

static void fread_in(void)
{
    char buf[8];
    size_t n;

    for (;;) {
        n = fread(buf, 1, 7, stdin);
        if (n == 0) {
            break;
        }
        say(out(), "fread: %u [%s]", (unsigned)n, esc(buf, (int)n));
    }
    say(out(), "fread: 0; feof %s, ferror %s", feof(stdin) ? "yes" : "no", ferror(stdin) ? "yes" : "no");
}

static void peek_line(const char *label, HANDLE h)
{
    char buf[64];
    DWORD rd = UNTOUCHED, total = UNTOUCHED, left = UNTOUCHED, e;
    BOOL r;

    SetLastError(UNTOUCHED);
    r = PeekNamedPipe(h, buf, sizeof buf, &rd, &total, &left);
    e = GetLastError();
    if (r && rd <= sizeof buf) {
        say(out(), "peekin: PeekNamedPipe(%s): ret=%d err=%s; read %lu, total %lu [%s]", label, r, le_of(e),
            rd, total, esc(buf, (int)rd));
    } else {
        say(out(), "peekin: PeekNamedPipe(%s): ret=%d err=%s", label, r, le_of(e));
    }
}

static void peekin(void)
{
    char buf[64];
    DWORD n = UNTOUCHED, e;
    BOOL r;

    peek_line("stdin", GetStdHandle(STD_INPUT_HANDLE));
    SetLastError(UNTOUCHED);
    r = ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof buf, &n, NULL);
    e = GetLastError();
    say(out(), "peekin: ReadFile 64: ret=%d n=%s err=%s [%s]", r, le_of(n), le_of(e),
        esc(buf, r && n <= sizeof buf ? (int)n : 0));
    peek_line("stdin, drained", GetStdHandle(STD_INPUT_HANDLE));
    peek_line("stdout", GetStdHandle(STD_OUTPUT_HANDLE));
}

/* The command line past the program's name and the /c switch; NULL when
 * the switch is not there. */
static const char *after_switch(const char *p)
{
    if (*p == '"') {
        p++;
        while (*p != 0 && *p != '"') {
            p++;
        }
        if (*p == '"') {
            p++;
        }
    } else {
        while (*p != 0 && *p != ' ' && *p != '\t') {
            p++;
        }
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (p[0] != '/' || (p[1] != 'c' && p[1] != 'C')) {
        return NULL;
    }
    p += 2;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/* The stand-in command processor. */
static int command(void)
{
    static char cmd[4096];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    const char *rest;
    DWORD code = 1;

    say(out(), "/c: command line [%s]", scrub(GetCommandLineA()));
    rest = after_switch(GetCommandLineA());
    if (rest == NULL || *rest == 0) {
        say(out(), "/c: no command");
        return 1;
    }
    strncpy(cmd, rest, sizeof cmd - 1);
    cmd[sizeof cmd - 1] = 0;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    SetLastError(UNTOUCHED);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        say(out(), "/c: not started, err=%s", le_of(GetLastError()));
        return 1;
    }
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, COMMAND_MS) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 0xDEAD);
        WaitForSingleObject(pi.hProcess, 5000);
        say(out(), "/c: the command overran, ended");
    }
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return (int)code;
}

int main(int argc, char **argv)
{
    const char *mode = argc >= 2 ? argv[1] : "";
    DWORD n;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    n = GetEnvironmentVariableA("F2KHOME", home, sizeof home);
    if (n == 0 || n >= sizeof home) {
        home[0] = 0;
    }

    if (strcmp(mode, "emit") == 0 && argc >= 3) {
        return emit(atoi(argv[2]));
    } else if (strcmp(mode, "cat") == 0) {
        return pass_on(0);
    } else if (strcmp(mode, "upper") == 0) {
        return pass_on(1);
    } else if (strcmp(mode, "count") == 0) {
        count();
    } else if (strcmp(mode, "exit") == 0 && argc >= 3) {
        return (int)strtoul(argv[2], NULL, 0);
    } else if (strcmp(mode, "types") == 0) {
        types();
    } else if (strcmp(mode, "blob") == 0 && argc >= 3) {
        return blob((DWORD)strtoul(argv[2], NULL, 0));
    } else if (strcmp(mode, "crtin") == 0) {
        crtin();
    } else if (strcmp(mode, "fread") == 0) {
        fread_in();
    } else if (strcmp(mode, "peekin") == 0) {
        peekin();
    } else if (_stricmp(mode, "/c") == 0) {
        return command();
    } else {
        say(out(), "unknown mode [%s]", scrub(mode));
        return 100;
    }
    return 0;
}
