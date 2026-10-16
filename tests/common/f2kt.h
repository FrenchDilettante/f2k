/*
 * f2kt.h - the corpus fixtures' shared reporting and section helpers.
 *
 * Every fixture built on the C runtime includes this header. It sets
 * the conventions the real-machine captures and the F2K suite share:
 *
 * - Output is one line per WriteFile on the standard output handle,
 *   CR LF terminated. A line is never split or reordered, whichever
 *   thread prints it, and nothing depends on CRT stdio buffering (so
 *   a capture redirected to a file matches the console).
 *
 * - Fixtures observe, they do not assert: a line prints what a call
 *   returned (`ret=0 err=288`), and the real-machine capture is the
 *   expectation. Only machine-independent facts are printed: no
 *   addresses, handle values, thread ids, absolute paths, or raw
 *   timings (timing-shaped facts print as a verdict against a band).
 *
 * - The last-error value is armed with a sentinel before a call
 *   (`arm()`) and printed through `le()`: "-" when the call left it
 *   untouched, the number otherwise. This pins both the error codes
 *   and which calls clear or keep the value on success.
 *
 * - A fixture is a list of sections. With no argument every
 *   non-terminal section runs in order; `<fixture> <section>` runs
 *   that one section alone (the suite runs each section as its own
 *   process). Named-only sections run only when named: those that end
 *   the process themselves, and those whose output depends on how the
 *   program is launched (an interactive console versus a redirect).
 *
 * Build: included by relative path ("../common/f2kt.h"); the
 * fixtures need no extra compiler flags for it.
 */

#ifndef F2KT_H
#define F2KT_H

/* QueueUserAPC, waitable timers, TryEnterCriticalSection, SwitchToThread
 * and SignalObjectAndWait are declared only for NT 4 and later. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The MSVC 6 SDK headers predate these. */
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif
#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#endif

/* The last-error sentinel: no API sets it, so seeing it means untouched. */
#define F2KT_UNTOUCHED 0x0F2F2F2Fu

/* Bounded waits: a wait the contract says is satisfied uses this instead
 * of INFINITE, so a kernel bug shows as a wrong result, not a hang. */
#define WAIT_MS 5000

typedef struct {
    const char *name;
    void (*run)(void);
    int named_only;         /* runs only when named: it ends the process, or its output depends on how it is launched */
} section_t;

static HANDLE f2kt_stdout;

/* Print one line: formatted, CR LF appended, one WriteFile. */
static void line(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    DWORD written;

    va_start(ap, fmt);
    n = _vsnprintf(buf, sizeof buf - 2, fmt, ap);
    va_end(ap);
    if (n < 0) {
        n = sizeof buf - 2;
    }
    buf[n++] = '\r';
    buf[n++] = '\n';
    if (f2kt_stdout == NULL) {
        f2kt_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    WriteFile(f2kt_stdout, buf, (DWORD)n, &written, NULL);
}

/* Arm the last-error sentinel before the call under observation. */
static void arm(void)
{
    SetLastError(F2KT_UNTOUCHED);
}

/* The last error as printed: "-" when the sentinel survived. Rotates
 * through a few buffers so one line can carry several values; call it
 * from the reporting (main) thread only. */
static const char *le(void)
{
    static char bufs[4][16];
    static int next;
    DWORD e = GetLastError();
    char *b = bufs[next++ & 3];

    if (e == F2KT_UNTOUCHED) {
        return "-";
    }
    sprintf(b, "%lu", e);
    return b;
}

/* The same, for a value captured earlier (by a child thread). */
static const char *le_of(DWORD e)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (e == F2KT_UNTOUCHED) {
        return "-";
    }
    sprintf(b, "%lu", e);
    return b;
}

static const char *yesno(int v)
{
    return v ? "yes" : "no";
}

/* A wait result by name where it has one, the number otherwise. */
static const char *wr(DWORD r)
{
    static char bufs[4][24];
    static int next;
    char *b = bufs[next++ & 3];

    switch (r) {
    case WAIT_OBJECT_0: return "WAIT_OBJECT_0";
    case WAIT_TIMEOUT: return "WAIT_TIMEOUT";
    case WAIT_ABANDONED: return "WAIT_ABANDONED";
    case WAIT_IO_COMPLETION: return "WAIT_IO_COMPLETION";
    case WAIT_FAILED: return "WAIT_FAILED";
    }
    if (r > WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS) {
        sprintf(b, "WAIT_OBJECT_0+%lu", r - WAIT_OBJECT_0);
    } else if (r > WAIT_ABANDONED && r < WAIT_ABANDONED + MAXIMUM_WAIT_OBJECTS) {
        sprintf(b, "WAIT_ABANDONED+%lu", r - WAIT_ABANDONED);
    } else {
        sprintf(b, "%lu", r);
    }
    return b;
}

/* elapsed in [lo, hi] milliseconds, as a verdict. */
static const char *band(DWORD elapsed, DWORD lo, DWORD hi)
{
    return (elapsed >= lo && elapsed <= hi) ? "yes" : "no";
}

/* Run the selected sections: every non-terminal one with no argument,
 * the named one otherwise. Returns the process exit code. */
static int run_sections(const char *fixture, const section_t *sections, int argc, char **argv)
{
    const section_t *s;
    int ran = 0;

    for (s = sections; s->name != NULL; s++) {
        if (argc < 2 ? s->named_only : _stricmp(argv[1], s->name) != 0) {
            continue;
        }
        line("== %s", s->name);
        s->run();
        ran++;
    }
    if (ran == 0) {
        line("%s: unknown section %s", fixture, argv[1]);
        return 2;
    }
    line("%s: done", fixture);
    return 0;
}

#endif /* F2KT_H */
