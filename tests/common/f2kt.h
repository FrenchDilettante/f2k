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
 *   the process themselves (F2KT_NAMED), and those whose output depends
 *   on how the program is launched, an interactive console versus a
 *   redirect (F2KT_INTERACTIVE: tests/capture.bat cannot take them).
 *
 * - Two arguments describe the fixture rather than run it:
 *   `<fixture> --list` prints its sections, one per line, an
 *   interactive one followed by " interactive" (tests/capture.bat
 *   iterates over them); `<fixture> --source` prints the CRC of the
 *   source it was built from (see below; capture.bat records it).
 *
 * Build: included by relative path ("../common/f2kt.h"). tests/build.bat
 * defines F2KT_SOURCE_CRC, the CRC-32 of the fixture's source and this
 * header (line ends normalized to LF; tests/common/srcsum.c computes it),
 * which the binary carries as "F2KT-SOURCE-CRC=0x...": the repository's
 * tests check it against the checked-in sources, so a stale binary shows.
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

/* A section's named_only values. */
#define F2KT_ALWAYS 0       /* runs with no argument too */
#define F2KT_NAMED 1        /* runs only when named: it ends the process itself */
#define F2KT_INTERACTIVE 2  /* runs only when named: its output needs an interactive console */

typedef struct {
    const char *name;
    void (*run)(void);
    int named_only;         /* F2KT_ALWAYS, F2KT_NAMED or F2KT_INTERACTIVE */
} section_t;

/* The source the binary was built from (tests/build.bat defines the CRC). */
#define F2KT_TEXT_(x) #x
#define F2KT_TEXT(x) F2KT_TEXT_(x)
#ifdef F2KT_SOURCE_CRC
static const char f2kt_source[] = "F2KT-SOURCE-CRC=" F2KT_TEXT(F2KT_SOURCE_CRC);
#else
static const char f2kt_source[] = "F2KT-SOURCE-CRC=unknown";
#endif

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

/* A wide string as printed, its first `count` units (to its terminator for
 * a negative count): a unit below 0x100 as its byte (but for 0x80-0x9F,
 * which code page 1252 does not map one to one), any other as <U+XXXX>;
 * "(null)" for NULL. It calls no API, so the last error stays as the call
 * under observation left it. Rotates through a few buffers, as le() does. */
static const char *wsn(const WCHAR *s, int count)
{
    static char bufs[4][1024];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;

    if (s == NULL) {
        return "(null)";
    }
    for (i = 0; (count < 0 ? s[i] != 0 : i < count) && n < (int)sizeof bufs[0] - 9; i++) {
        if (s[i] < 0x100 && (s[i] < 0x80 || s[i] > 0x9F)) {
            b[n++] = (char)s[i];
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)s[i]);
        }
    }
    b[n] = '\0';
    return b;
}

/* The same, to the terminator. */
static const char *ws(const WCHAR *s)
{
    return wsn(s, -1);
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

    if (argc >= 2 && strcmp(argv[1], "--list") == 0) {
        for (s = sections; s->name != NULL; s++) {
            line("%s%s", s->name, s->named_only == F2KT_INTERACTIVE ? " interactive" : "");
        }
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--source") == 0) {
        line("%s %s", fixture, f2kt_source);
        return 0;
    }
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
