/*
 * ctrlkid - the ctrl fixture's companion program: the child ctrl.exe
 * starts, which registers console control handlers and reports which
 * control events reached it, doing what its first argument says.
 *
 * Every line it prints starts with its tag ("kid: ", or the tag its
 * mode names) and is one WriteFile, CR LF terminated, through the
 * standard output it inherits. It calls SetErrorMode first, so a fault
 * ends it quietly with the exception's code. It never prints an id, a
 * handle or a path. It synchronises with its parent through named
 * events, never through timing alone: it sets the ready event once its
 * handlers are in place, and every wait is bounded.
 *
 * A handler that records (listen, family, tally, lone) answers TRUE and
 * only counts: the events per type, whether any ran on the main thread.
 * The count is printed by the main thread once the Ctrl+Break the parent
 * sends last (the fence) has arrived, and a further 500 ms for any
 * event still on its way (the shortest safe bound for an event that
 * should not come).
 *
 * Modes:
 *
 *   chain <spec>     handlers registered in the order <spec> gives them:
 *                    T or F a new handler answering TRUE or FALSE (at
 *                    most four), a digit 1-4 that handler registered
 *                    again, I SetConsoleCtrlHandler(NULL, TRUE), - none;
 *                    then F2KCtrlReady set, and a wait (5 s) for a
 *                    handler answering TRUE. Each handler prints the
 *                    event, whether it runs on the main thread and on the
 *                    thread the first one ran on. Exit 0 once a handler
 *                    answered TRUE, 1 if none did in time; the default
 *                    handler ends it otherwise
 *   listen <ready> <op> <tag>
 *                    <op> applied (keep: nothing; ignore:
 *                    SetConsoleCtrlHandler(NULL, TRUE); process:
 *                    SetConsoleCtrlHandler(NULL, FALSE)), a recording
 *                    handler registered, event <ready> set; then the
 *                    events seen, after the fence; prints as <tag>
 *   family <op> <op2>
 *                    <op> applied, a recording handler registered, then a
 *                    grandchild started with no group of its own, so in
 *                    this program's (ctrlkid listen F2KCtrlInner <op2>
 *                    grandkid), and once it is ready F2KCtrlReady set;
 *                    after the fence it waits for the grandchild's end
 *                    (which prints first), then prints its own
 *   lone <id>        run by the parent in a console of its own, with a
 *                    process group of its own: a grandchild (tally) in
 *                    its group, then GenerateConsoleCtrlEvent's
 *                    CTRL_BREAK_EVENT into groups no process of this
 *                    console leads: <id> (the parent, in another
 *                    console), the grandchild (in this console, not a
 *                    group's root), an ended process; after each, a
 *                    Ctrl+Break into its own group as the fence, and the
 *                    Ctrl+Breaks this process saw since the last; then
 *                    the grandchild stopped, which prints its own count
 *   tally <ready> <stop>
 *                    a recording handler, event <ready> set, then a wait
 *                    for event <stop> (20 s); prints its count as
 *                    "grandkid"
 *   sit              (the interactive keys section) a handler answering
 *                    FALSE that prints the event, F2KCtrlReady set, then
 *                    a wait (60 s) for the key the parent asks for; the
 *                    default handler ends it, exit 1 if nothing came
 *   exit             exit 0 at once; prints nothing
 *   (anything else)  that the mode is unknown; exit 100
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ctrl):
 *   cl /nologo /MD ctrlkid.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The last-error sentinel, as common/f2kt.h's. */
#define UNTOUCHED 0x0F2F2F2Fu

#define WAIT_MS 5000
#define GRACE_MS 500
#define READY "F2KCtrlReady"
#define INNER "F2KCtrlInner"
#define LONE_READY "F2KCtrlLoneReady"
#define LONE_STOP "F2KCtrlLoneStop"

static const char *tag = "kid";
static DWORD main_tid;
static char self[MAX_PATH];

/* Print one line: the tag, ": ", the text, CR LF, one WriteFile. */
static void say(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    int n;
    DWORD written;
    int m;

    n = sprintf(buf, "%s: ", tag);
    va_start(ap, fmt);
    m = _vsnprintf(buf + n, sizeof buf - n - 2, fmt, ap);
    va_end(ap);
    n = m < 0 ? (int)sizeof buf - 2 : n + m;
    buf[n++] = '\r';
    buf[n++] = '\n';
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)n, &written, NULL);
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

static const char *yesno(int v)
{
    return v ? "yes" : "no";
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

/* Set the named event the parent (or this program's parent) waits on. */
static int signal_ready(const char *name)
{
    HANDLE e = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);

    if (e == NULL) {
        say("event %s missing, err=%lu", name, GetLastError());
        return 0;
    }
    SetEvent(e);
    CloseHandle(e);
    return 1;
}

/* --- chain --------------------------------------------------------- */

#define MAX_HANDLERS 4

static BOOL answers[MAX_HANDLERS];
static HANDLE handled;          /* set by a handler answering TRUE */
static LONG ran;                /* handler calls so far */
static DWORD first_tid;         /* the thread the first call ran on */

static BOOL handle(int i, DWORD type)
{
    DWORD tid = GetCurrentThreadId();

    if (InterlockedIncrement(&ran) == 1) {
        first_tid = tid;
    }
    say("handler %d: event %lu, on the main thread %s, on the first handler's thread %s, answers %s", i + 1, type,
        yesno(tid == main_tid), yesno(tid == first_tid), answers[i] ? "TRUE" : "FALSE");
    if (answers[i]) {
        SetEvent(handled);
    }
    return answers[i];
}

static BOOL WINAPI handler1(DWORD type) { return handle(0, type); }
static BOOL WINAPI handler2(DWORD type) { return handle(1, type); }
static BOOL WINAPI handler3(DWORD type) { return handle(2, type); }
static BOOL WINAPI handler4(DWORD type) { return handle(3, type); }

static PHANDLER_ROUTINE const routines[MAX_HANDLERS] = { handler1, handler2, handler3, handler4 };

static int chain(const char *spec)
{
    const char *p;
    int n = 0;
    int all = 1;

    handled = CreateEventA(NULL, TRUE, FALSE, NULL);
    for (p = spec; *p != '\0'; p++) {
        if ((*p == 'T' || *p == 'F') && n < MAX_HANDLERS) {
            answers[n] = *p == 'T';
            all = SetConsoleCtrlHandler(routines[n], TRUE) && all;
            n++;
        } else if (*p >= '1' && *p <= '0' + MAX_HANDLERS && *p - '1' < n) {
            all = SetConsoleCtrlHandler(routines[*p - '1'], TRUE) && all;
        } else if (*p == 'I') {
            all = SetConsoleCtrlHandler(NULL, TRUE) && all;
        }
    }
    say("registered [%s]: every call ret=1 %s", spec, yesno(all));
    if (!signal_ready(READY)) {
        return 2;
    }
    if (WaitForSingleObject(handled, WAIT_MS) == WAIT_OBJECT_0) {
        say("a handler answered TRUE: the main thread runs on");
        return 0;
    }
    say("no handler answered TRUE within the bound");
    return 1;
}

/* --- the recording handler ------------------------------------------ */

static LONG counts[8];          /* events by type; 7 for any above 6 */
static LONG on_main;            /* calls on the main thread */
static HANDLE seen_break;       /* auto-reset: a Ctrl+Break came */
static HANDLE seen_other;       /* auto-reset: any other event came */

static BOOL WINAPI recorder(DWORD type)
{
    InterlockedIncrement(&counts[type < 7 ? type : 7]);
    if (GetCurrentThreadId() == main_tid) {
        InterlockedIncrement(&on_main);
    }
    SetEvent(type == CTRL_BREAK_EVENT ? seen_break : seen_other);
    return TRUE;
}

static void recording(void)
{
    BOOL r;

    seen_break = CreateEventA(NULL, FALSE, FALSE, NULL);
    seen_other = CreateEventA(NULL, FALSE, FALSE, NULL);
    SetLastError(UNTOUCHED);
    r = SetConsoleCtrlHandler(recorder, TRUE);
    if (!r) {
        say("SetConsoleCtrlHandler(recorder, TRUE): ret=0 err=%s", le());
    }
}

/* The fence: wait for the Ctrl+Break, then for any other event still
 * on its way. */
static void await_fence(void)
{
    if (WaitForSingleObject(seen_break, WAIT_MS) != WAIT_OBJECT_0) {
        say("the fence (Ctrl+Break) never came");
    }
    WaitForSingleObject(seen_other, GRACE_MS);
}

static void report(void)
{
    char others[200];
    int n = 0;
    int i;

    others[0] = '\0';
    for (i = 2; i < 8; i++) {
        if (counts[i] == 0) {
            continue;
        }
        if (i == 7) {
            n += sprintf(others + n, "%sabove 6 x%ld", n != 0 ? ", " : "", counts[i]);
        } else {
            n += sprintf(others + n, "%sevent %d x%ld", n != 0 ? ", " : "", i, counts[i]);
        }
    }
    if (n == 0) {
        strcpy(others, "none");
    }
    say("seen: Ctrl+C %ld, Ctrl+Break %ld, other events %s; on the main thread %s", counts[0], counts[1], others,
        yesno(on_main != 0));
}

/* Ignore or process Ctrl+C, as <op> says. */
static void apply(const char *op)
{
    BOOL r;

    if (strcmp(op, "ignore") == 0 || strcmp(op, "process") == 0) {
        SetLastError(UNTOUCHED);
        r = SetConsoleCtrlHandler(NULL, strcmp(op, "ignore") == 0);
        say("SetConsoleCtrlHandler(NULL, %s): ret=%d err=%s", strcmp(op, "ignore") == 0 ? "TRUE" : "FALSE", r, le());
    }
}

/* --- listen, family ---------------------------------------------- */

static int listen_mode(const char *ready, const char *op)
{
    apply(op);
    recording();
    if (!signal_ready(ready)) {
        return 2;
    }
    await_fence();
    report();
    return 0;
}

/* Start ctrlkid with `args` in this console and process group; its
 * standard handles are this program's. */
static BOOL start(const char *args, DWORD flags, PROCESS_INFORMATION *pi)
{
    char cmd[MAX_PATH + 100];
    STARTUPINFOA si;

    sprintf(cmd, "ctrlkid %s", args);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(pi, 0, sizeof *pi);
    SetLastError(UNTOUCHED);
    if (!CreateProcessA(self, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, pi)) {
        say("the grandchild not started, err=%s", le());
        return FALSE;
    }
    return TRUE;
}

/* Wait for a child's end (ending it, should it outlast the bound): its
 * exit code. */
static DWORD reap(PROCESS_INFORMATION *pi, DWORD bound)
{
    DWORD code = 0xF2F2F2F2u;

    if (WaitForSingleObject(pi->hProcess, bound) != WAIT_OBJECT_0) {
        say("the grandchild outlasted its bound: terminated");
        TerminateProcess(pi->hProcess, 0xDEAD);
        WaitForSingleObject(pi->hProcess, WAIT_MS);
    }
    GetExitCodeProcess(pi->hProcess, &code);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
    return code;
}

static int family(const char *op, const char *op2)
{
    PROCESS_INFORMATION pi;
    HANDLE inner;
    char args[100];
    DWORD code;

    apply(op);
    recording();
    inner = CreateEventA(NULL, TRUE, FALSE, INNER);
    ResetEvent(inner);
    sprintf(args, "listen %s %s grandkid", INNER, op2);
    if (!start(args, 0, &pi)) {
        return 2;
    }
    if (WaitForSingleObject(inner, WAIT_MS) != WAIT_OBJECT_0) {
        say("the grandchild never ready");
        TerminateProcess(pi.hProcess, 0xDEAD);
        reap(&pi, WAIT_MS);
        return 2;
    }
    if (!signal_ready(READY)) {
        TerminateProcess(pi.hProcess, 0xDEAD);
        reap(&pi, WAIT_MS);
        return 2;
    }
    await_fence();
    code = reap(&pi, 2 * WAIT_MS);
    say("the grandchild's exit code %s", code_text(code));
    report();
    CloseHandle(inner);
    return 0;
}

/* --- lone, tally ----------------------------------------------------- */

static int tally(const char *ready, const char *stop_name)
{
    HANDLE stop = OpenEventA(SYNCHRONIZE, FALSE, stop_name);

    tag = "grandkid";
    if (stop == NULL) {
        say("event %s missing, err=%lu", stop_name, GetLastError());
        return 2;
    }
    recording();
    if (!signal_ready(ready)) {
        return 2;
    }
    if (WaitForSingleObject(stop, 4 * WAIT_MS) != WAIT_OBJECT_0) {
        say("never told to stop");
    }
    report();
    CloseHandle(stop);
    return 0;
}

/* One Ctrl+Break into `group`, then the fence into this program's own
 * group: the Ctrl+Breaks this program saw for both. */
static void lone_case(const char *what, DWORD group)
{
    LONG before = counts[1];
    const char *e;
    BOOL r;

    SetLastError(UNTOUCHED);
    r = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, group);
    e = le();
    say("GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, %s): ret=%d err=%s", what, r, e);
    SetLastError(UNTOUCHED);
    r = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, GetCurrentProcessId());
    if (!r) {
        say("the fence not sent, err=%s", le());
    }
    while (counts[1] < before + 1) {
        if (WaitForSingleObject(seen_break, WAIT_MS) != WAIT_OBJECT_0) {
            say("the fence never came");
            break;
        }
    }
    /* A second one, should the first call have reached this program. */
    while (counts[1] < before + 2) {
        if (WaitForSingleObject(seen_break, GRACE_MS) != WAIT_OBJECT_0) {
            break;
        }
    }
    say("Ctrl+Breaks this program saw for both: %ld", counts[1] - before);
}

static int lone(const char *parent)
{
    PROCESS_INFORMATION pi;
    PROCESS_INFORMATION ended;
    HANDLE ready, stop;
    DWORD code;
    char args[100];

    recording();
    ready = CreateEventA(NULL, TRUE, FALSE, LONE_READY);
    stop = CreateEventA(NULL, TRUE, FALSE, LONE_STOP);
    ResetEvent(ready);
    ResetEvent(stop);
    sprintf(args, "tally %s %s", LONE_READY, LONE_STOP);
    if (!start(args, 0, &pi)) {
        return 2;
    }
    if (WaitForSingleObject(ready, WAIT_MS) != WAIT_OBJECT_0) {
        say("the grandchild never ready");
        TerminateProcess(pi.hProcess, 0xDEAD);
        reap(&pi, WAIT_MS);
        return 2;
    }
    /* A process that has ended: its id leads nothing. */
    if (!start("exit", 0, &ended)) {
        SetEvent(stop);
        reap(&pi, WAIT_MS);
        return 2;
    }
    WaitForSingleObject(ended.hProcess, WAIT_MS);

    lone_case("the parent's id, in another console", (DWORD)strtoul(parent, NULL, 0));
    lone_case("the grandchild's id, not a group's root", pi.dwProcessId);
    lone_case("an ended process's id", ended.dwProcessId);
    reap(&ended, WAIT_MS);

    SetEvent(stop);
    code = reap(&pi, 2 * WAIT_MS);
    say("the grandchild's exit code %s; the fences it shared: 3", code_text(code));
    CloseHandle(ready);
    CloseHandle(stop);
    return 0;
}

/* --- sit ----------------------------------------------------------- */

static BOOL WINAPI sitter(DWORD type)
{
    say("handler: event %lu, on the main thread %s, answers FALSE", type, yesno(GetCurrentThreadId() == main_tid));
    return FALSE;
}

static int sit(void)
{
    HANDLE never = CreateEventA(NULL, TRUE, FALSE, NULL);

    SetConsoleCtrlHandler(sitter, TRUE);
    if (!signal_ready(READY)) {
        return 2;
    }
    WaitForSingleObject(never, 60000);
    say("no event within 60 s");
    return 1;
}

int main(int argc, char **argv)
{
    const char *mode = argc >= 2 ? argv[1] : "";

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    main_tid = GetCurrentThreadId();
    GetModuleFileNameA(NULL, self, sizeof self);

    if (strcmp(mode, "chain") == 0 && argc >= 3) {
        return chain(argv[2]);
    } else if (strcmp(mode, "listen") == 0 && argc >= 5) {
        tag = argv[4];
        return listen_mode(argv[2], argv[3]);
    } else if (strcmp(mode, "family") == 0 && argc >= 4) {
        return family(argv[2], argv[3]);
    } else if (strcmp(mode, "lone") == 0 && argc >= 3) {
        return lone(argv[2]);
    } else if (strcmp(mode, "tally") == 0 && argc >= 4) {
        return tally(argv[2], argv[3]);
    } else if (strcmp(mode, "sit") == 0) {
        return sit();
    } else if (strcmp(mode, "exit") == 0) {
        return 0;
    }
    say("unknown mode [%s]", mode);
    return 100;
}
