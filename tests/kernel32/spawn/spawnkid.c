/*
 * spawnkid - the spawn fixture's companion program: the child spawn.exe
 * starts, doing what its first argument says.
 *
 * Every line it prints starts "kid: " and is one WriteFile, CR LF
 * terminated, as the fixtures' lines are. It calls SetErrorMode first,
 * so a fault ends it quietly with the exception's code. It never prints
 * an absolute path: where one would show, the parent's directory (the
 * F2KHOME variable the parent sets) prints as <home>, and the image and
 * current directory print relative to it.
 *
 * Modes:
 *
 *   (none), args    the command line (GetCommandLineA) and argv
 *   exit <n>        exit with code n (decimal, or hex as 0x...); prints
 *                   nothing
 *   out             one line to the standard output, one to the
 *                   standard error
 *   read            one line read from the standard input (one ReadFile),
 *                   printed; the parent runs it only with a file there
 *   sleep <ms>      sleep, then exit 0; prints nothing
 *   crash           write to NULL: the process ends with 0xC0000005
 *   env <name>...   each variable's value, or that it is unset
 *   envall          the environment block's entries in order, those
 *                   starting with "=" (the per-drive current directories,
 *                   absolute paths) left out
 *   where           the image's path and the current directory, relative
 *                   to F2KHOME
 *   handles <file>  into <file> (its standard handles may not reach the
 *                   parent's output): whether STARTF_USESTDHANDLES was
 *                   given, and each standard handle's file type and error
 *   probe <h>...    each handle value's file type, error and, for a disk
 *                   file, size; never the value
 *   wait <r> <g>    set event <r>, wait for event <g> (20 s at most), exit
 *                   0 (1 if it never came, 2 if an event is missing)
 *   signal <name>   set event <name>, exit 0 (2 if it is missing); prints
 *                   nothing
 *   usedup <file>   SetEvent on the handle value <file> holds (the parent
 *                   duplicated it into this process)
 *   mark            the dword at e_res2 in its own image's DOS header
 *                   (zero in the file; the parent writes one there)
 *   crtinfo         the STARTUPINFO's cbReserved2 and lpReserved2 as the
 *                   C runtime's parent left them: the count at its start,
 *                   then per descriptor whether a handle follows, and from
 *                   descriptor 3 on its flags byte and file type (the
 *                   standard handles' flags and types depend on how the
 *                   parent was started); then which of the C runtime's
 *                   descriptors 0 to 5 are open
 *   flags <h>...    each handle value's GetHandleInformation flags and
 *                   file type, or the error; never the value
 *   later <ms> <n>  sleep, then ExitProcess(n); prints nothing
 *   lastthread      the main thread ends with ExitThread(5) while a
 *                   second thread runs on, which ends 200 ms later with
 *                   ExitThread(6), the process's last; prints nothing
 *   handoff         a second thread sleeping, then NtTerminateProcess
 *                   (NULL, 3), which ends it and leaves the caller
 *                   running, then the caller ends with ExitThread(4);
 *                   prints nothing
 *   (anything else) that the mode is unknown, then what where prints;
 *                   exit 100
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat spawn):
 *   cl /nologo /MD spawnkid.c
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

static char home[MAX_PATH];     /* F2KHOME; empty when unset */

/* Print one line to `to`: "kid: ", the text, CR LF, one WriteFile. */
static void say(HANDLE to, const char *fmt, ...)
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
    WriteFile(to, buf, (DWORD)n, &written, NULL);
}

static HANDLE out(void)
{
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

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

/* `s` with every occurrence of the parent's directory as <home>. */
static const char *scrub(const char *s)
{
    static char bufs[2][1024];
    static int next;
    char *b = bufs[next++ & 1];
    size_t len = strlen(home);
    int n = 0;

    while (*s != 0 && n < (int)sizeof bufs[0] - 8) {
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

/* A path relative to the parent's directory, upper-cased: "." for the
 * directory itself. */
static const char *relative(const char *path)
{
    static char b[MAX_PATH];
    size_t len = strlen(home);
    int i;

    if (len == 0) {
        return "(F2KHOME unset)";
    }
    if (_strnicmp(path, home, len) != 0 || (path[len] != 0 && path[len] != '\\')) {
        return "outside the parent's directory";
    }
    if (path[len] == 0 || path[len + 1] == 0) {
        return ".";
    }
    for (i = 0; path[len + 1 + i] != 0 && i < MAX_PATH - 1; i++) {
        b[i] = (char)toupper((unsigned char)path[len + 1 + i]);
    }
    b[i] = 0;
    return b;
}

static void show_args(int argc, char **argv)
{
    int i;

    say(out(), "command line [%s]", scrub(GetCommandLineA()));
    say(out(), "argc %d", argc);
    for (i = 0; i < argc; i++) {
        say(out(), "argv[%d] [%s]", i, scrub(argv[i]));
    }
}

static void read_line(void)
{
    char buf[256];
    DWORD n = 0;
    BOOL r;

    SetLastError(UNTOUCHED);
    r = ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof buf - 1, &n, NULL);
    buf[r ? n : 0] = 0;
    buf[strcspn(buf, "\r\n")] = 0;
    say(out(), "read: ret=%d err=%s [%s]", r, le(), buf);
}

static void show_env(int argc, char **argv)
{
    char value[512];
    DWORD n;
    int i;

    for (i = 2; i < argc; i++) {
        n = GetEnvironmentVariableA(argv[i], value, sizeof value);
        if (n == 0 || n >= sizeof value) {
            say(out(), "%s unset", argv[i]);
        } else {
            say(out(), "%s=[%s]", argv[i], scrub(value));
        }
    }
}

static void show_all_env(void)
{
    char *block = GetEnvironmentStrings();
    char *p;
    int n = 0;

    if (block == NULL) {
        say(out(), "no environment block");
        return;
    }
    for (p = block; *p != 0; p += strlen(p) + 1) {
        if (*p != '=') {
            n++;
        }
    }
    say(out(), "environment: %d entries", n);
    for (p = block; *p != 0; p += strlen(p) + 1) {
        if (*p != '=') {
            say(out(), "[%s]", scrub(p));
        }
    }
    FreeEnvironmentStringsA(block);
}

static void show_where(void)
{
    char path[MAX_PATH];
    char cwd[MAX_PATH];

    path[0] = 0;
    cwd[0] = 0;
    GetModuleFileNameA(NULL, path, sizeof path);
    GetCurrentDirectoryA(sizeof cwd, cwd);
    say(out(), "image %s", relative(path));
    say(out(), "current directory %s", relative(cwd));
}

static void report_handle(HANDLE to, const char *name, HANDLE h)
{
    DWORD type;

    if (h == NULL) {
        say(to, "%s: NULL", name);
        return;
    }
    if (h == INVALID_HANDLE_VALUE) {
        say(to, "%s: INVALID_HANDLE_VALUE", name);
        return;
    }
    SetLastError(UNTOUCHED);
    type = GetFileType(h);
    say(to, "%s: type %lu err=%s", name, type, le());
}

static int report_handles(const char *file)
{
    STARTUPINFOA si;
    HANDLE to = CreateFileA(file, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);

    if (to == INVALID_HANDLE_VALUE) {
        return 3;
    }
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    GetStartupInfoA(&si);
    say(to, "STARTF_USESTDHANDLES: %s", (si.dwFlags & STARTF_USESTDHANDLES) ? "yes" : "no");
    report_handle(to, "standard input", GetStdHandle(STD_INPUT_HANDLE));
    report_handle(to, "standard output", GetStdHandle(STD_OUTPUT_HANDLE));
    report_handle(to, "standard error", GetStdHandle(STD_ERROR_HANDLE));
    CloseHandle(to);
    return 0;
}

static void probe(int argc, char **argv)
{
    HANDLE h;
    DWORD type, size;
    const char *err;
    int i;

    for (i = 2; i < argc; i++) {
        h = (HANDLE)strtoul(argv[i], NULL, 0);
        SetLastError(UNTOUCHED);
        type = GetFileType(h);
        err = le();
        if (type == FILE_TYPE_DISK) {
            size = GetFileSize(h, NULL);
            say(out(), "handle %d: type %lu err=%s size %lu", i - 1, type, err, size);
        } else {
            say(out(), "handle %d: type %lu err=%s", i - 1, type, err);
        }
    }
}

static int wait_for(const char *ready_name, const char *go_name)
{
    HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
    HANDLE go = OpenEventA(SYNCHRONIZE, FALSE, go_name);

    if (ready == NULL || go == NULL) {
        return 2;
    }
    SetEvent(ready);
    return WaitForSingleObject(go, 20000) == WAIT_OBJECT_0 ? 0 : 1;
}

static int signal_event(const char *name)
{
    HANDLE h = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);

    if (h == NULL) {
        return 2;
    }
    SetEvent(h);
    return 0;
}

static void use_duplicate(const char *file)
{
    char text[32];
    DWORD n = 0;
    HANDLE f, h;
    BOOL r;

    f = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        say(out(), "usedup: no file");
        return;
    }
    ReadFile(f, text, sizeof text - 1, &n, NULL);
    CloseHandle(f);
    text[n] = 0;
    h = (HANDLE)strtoul(text, NULL, 0);
    SetLastError(UNTOUCHED);
    r = SetEvent(h);
    say(out(), "SetEvent on the duplicated handle: ret=%d err=%s", r, le());
}

static void crt_info(void)
{
    STARTUPINFOA si;
    BYTE *p;
    HANDLE h;
    DWORD type;
    int count, i;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    GetStartupInfoA(&si);
    say(out(), "cbReserved2 %u, lpReserved2 %s", si.cbReserved2, si.lpReserved2 != NULL ? "set" : "NULL");
    if (si.lpReserved2 != NULL && si.cbReserved2 >= 4) {
        p = si.lpReserved2;
        count = *(UNALIGNED int *)p;
        say(out(), "the count at its start %d, the size 4 + 5 per descriptor: %s", count,
            si.cbReserved2 == 4 + 5 * count ? "yes" : "no");
        for (i = 0; i < count && 4 + count + 4 * i + 4 <= (int)si.cbReserved2; i++) {
            h = *(UNALIGNED HANDLE *)(p + 4 + count + 4 * i);
            if (i < 3) {
                say(out(), "descriptor %d: %s", i, h == INVALID_HANDLE_VALUE || h == NULL ? "no handle" : "a handle");
            } else if (h == INVALID_HANDLE_VALUE || h == NULL) {
                say(out(), "descriptor %d: flags 0x%02X, no handle", i, p[4 + i]);
            } else {
                SetLastError(UNTOUCHED);
                type = GetFileType(h);
                say(out(), "descriptor %d: flags 0x%02X, a handle of type %lu err=%s", i, p[4 + i], type, le());
            }
        }
    }
    for (i = 0; i < 6; i++) {
        say(out(), "C runtime descriptor %d: %s", i, _get_osfhandle(i) == -1 ? "closed" : "open");
    }
}

/* lastthread's second thread: the process's last to end. */
static DWORD WINAPI last_thread(LPVOID arg)
{
    (void)arg;
    Sleep(200);
    ExitThread(6);
    return 0;
}

/* handoff's second thread, for the first step to end. */
static DWORD WINAPI sleeper(LPVOID arg)
{
    (void)arg;
    Sleep(60000);
    return 0;
}

/* handoff: ExitProcess's first step alone (every other thread ended, the
 * caller running on), then the caller's own end. */
static void hand_off(void)
{
    typedef LONG (WINAPI *terminate_fn)(HANDLE, LONG);
    terminate_fn terminate =
        (terminate_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateProcess");
    DWORD id;

    CloseHandle(CreateThread(NULL, 0, sleeper, NULL, 0, &id));
    Sleep(50);
    terminate(NULL, 3);
    ExitThread(4);
}

static void show_flags(int argc, char **argv)
{
    HANDLE h;
    DWORD flags, type;
    const char *err;
    int i;

    for (i = 2; i < argc; i++) {
        h = (HANDLE)strtoul(argv[i], NULL, 0);
        flags = UNTOUCHED;
        SetLastError(UNTOUCHED);
        if (GetHandleInformation(h, &flags)) {
            type = GetFileType(h);
            say(out(), "handle %d: flags 0x%lX, type %lu", i - 1, flags, type);
        } else {
            err = le();
            say(out(), "handle %d: ret=0 err=%s", i - 1, err);
        }
    }
}

int main(int argc, char **argv)
{
    const char *mode = argc >= 2 ? argv[1] : "args";
    BYTE *image;
    DWORD n;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    n = GetEnvironmentVariableA("F2KHOME", home, sizeof home);
    if (n == 0 || n >= sizeof home) {
        home[0] = 0;
    }

    if (strcmp(mode, "args") == 0) {
        show_args(argc, argv);
    } else if (strcmp(mode, "exit") == 0 && argc >= 3) {
        return (int)strtoul(argv[2], NULL, 0);
    } else if (strcmp(mode, "out") == 0) {
        say(out(), "to the standard output");
        say(GetStdHandle(STD_ERROR_HANDLE), "to the standard error");
    } else if (strcmp(mode, "read") == 0) {
        read_line();
    } else if (strcmp(mode, "sleep") == 0 && argc >= 3) {
        Sleep(strtoul(argv[2], NULL, 0));
    } else if (strcmp(mode, "crash") == 0) {
        *(volatile int *)0 = 1;
    } else if (strcmp(mode, "env") == 0) {
        show_env(argc, argv);
    } else if (strcmp(mode, "envall") == 0) {
        show_all_env();
    } else if (strcmp(mode, "where") == 0) {
        show_where();
    } else if (strcmp(mode, "handles") == 0 && argc >= 3) {
        return report_handles(argv[2]);
    } else if (strcmp(mode, "probe") == 0) {
        probe(argc, argv);
    } else if (strcmp(mode, "wait") == 0 && argc >= 4) {
        return wait_for(argv[2], argv[3]);
    } else if (strcmp(mode, "signal") == 0 && argc >= 3) {
        return signal_event(argv[2]);
    } else if (strcmp(mode, "usedup") == 0 && argc >= 3) {
        use_duplicate(argv[2]);
    } else if (strcmp(mode, "crtinfo") == 0) {
        crt_info();
    } else if (strcmp(mode, "flags") == 0) {
        show_flags(argc, argv);
    } else if (strcmp(mode, "later") == 0 && argc >= 4) {
        Sleep(strtoul(argv[2], NULL, 0));
        ExitProcess((UINT)strtoul(argv[3], NULL, 0));
    } else if (strcmp(mode, "lastthread") == 0) {
        CloseHandle(CreateThread(NULL, 0, last_thread, NULL, 0, &n));
        ExitThread(5);
    } else if (strcmp(mode, "handoff") == 0) {
        hand_off();
    } else if (strcmp(mode, "mark") == 0) {
        image = (BYTE *)GetModuleHandleA(NULL);
        say(out(), "header mark 0x%08lX",
             *(DWORD *)(image + FIELD_OFFSET(IMAGE_DOS_HEADER, e_res2)));
    } else {
        say(out(), "unknown mode [%s]", scrub(mode));
        show_where();
        return 100;
    }
    return 0;
}
