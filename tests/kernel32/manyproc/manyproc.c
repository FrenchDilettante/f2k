/*
 * manyproc - many processes alive at once, and how Windows 2000 hands
 * out and takes back their client ids (the process and thread ids, one
 * table for both: PspCidTable).
 *
 * Its companion program, mpkid.exe (built beside it from mpkid.c, with
 * no C runtime), is the child every section starts, from this program's
 * own directory, as a detached console process (DETACHED_PROCESS: no
 * console, no window). Ids are machine-specific: only their relations
 * print.
 *
 * Sections:
 *
 *   alive  600 children ("mpkid hold"), each releasing one shared
 *          semaphore once and then waiting on one event: how many were
 *          started, how many released the semaphore, how many were still
 *          active together; their process and thread ids as relations
 *          (multiples of 4, distinct, none of them this process's or this
 *          thread's); then the event set, and how many ended and with
 *          exit code 0. A creation that fails ends the creating there,
 *          its error printed: the counts then show how far the machine
 *          went.
 *   reuse  child A ("mpkid quit", exit code 7) waited for, and
 *          OpenProcess by its id while its handles are still open; then
 *          A's handles closed and one more child, B, started: B's process
 *          and thread ids against A's. Windows 2000 frees an ended
 *          process's id at its end, and its id table reuses the last
 *          freed entry first: B takes A's process id, and its thread A's
 *          thread id.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat manyproc):
 *   cl /nologo mpkid.c /link /NODEFAULTLIB /ENTRY:KidMain /SUBSYSTEM:CONSOLE /STACK:0x10000,0x1000 kernel32.lib
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% manyproc.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>

/* How many children alive at once: past F2K's old 64 and 512 caps. */
#define CHILDREN 600

/* The longest wait for one child to get ready or to end. */
#define CHILD_MS 60000

static char kid[MAX_PATH];          /* home\mpkid.exe */
static PROCESS_INFORMATION kids[CHILDREN];
static DWORD ids[2 * CHILDREN + 2];

/* mpkid.exe beside this program; 0 if the path does not fit. */
static int find_kid(void)
{
    DWORD n = GetModuleFileNameA(NULL, kid, sizeof kid);
    char *slash;

    if (n == 0 || n >= sizeof kid) {
        return 0;
    }
    slash = strrchr(kid, '\\');
    if (slash == NULL || (slash + 1 - kid) + sizeof "mpkid.exe" > sizeof kid) {
        return 0;
    }
    strcpy(slash + 1, "mpkid.exe");
    return 1;
}

/* Start mpkid with args, detached; CreateProcessA's answer. */
static BOOL start_kid(const char *args, PROCESS_INFORMATION *pi)
{
    STARTUPINFOA si;
    char command[MAX_PATH + 256];

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(pi, 0, sizeof *pi);
    _snprintf(command, sizeof command - 1, "\"%s\" %s", kid, args);
    command[sizeof command - 1] = '\0';
    return CreateProcessA(kid, command, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, pi);
}

static int by_value(const void *a, const void *b)
{
    DWORD x = *(const DWORD *)a;
    DWORD y = *(const DWORD *)b;

    return x < y ? -1 : x > y;
}

/* Whether the n values are distinct (sorts them). */
static int distinct(DWORD *v, int n)
{
    int i;

    qsort(v, n, sizeof *v, by_value);
    for (i = 1; i < n; i++) {
        if (v[i] == v[i - 1]) {
            return 0;
        }
    }
    return 1;
}

static void sec_alive(void)
{
    char ready_name[64];
    char go_name[64];
    char args[160];
    HANDLE ready;
    HANDLE go;
    int made = 0;
    int readied = 0;
    int active = 0;
    int ended = 0;
    int zero = 0;
    int pid4 = 1;
    int tid4 = 1;
    int i;
    DWORD code;

    if (!find_kid()) {
        line("mpkid.exe's path: too long");
        return;
    }
    sprintf(ready_name, "f2kt-manyproc-%lu-ready", GetCurrentProcessId());
    sprintf(go_name, "f2kt-manyproc-%lu-go", GetCurrentProcessId());
    ready = CreateSemaphoreA(NULL, 0, CHILDREN, ready_name);
    go = CreateEventA(NULL, TRUE, FALSE, go_name);
    if (ready == NULL || go == NULL) {
        line("the semaphore and the event: not made err=%s", le());
        return;
    }
    sprintf(args, "hold %s %s", ready_name, go_name);

    for (i = 0; i < CHILDREN; i++) {
        arm();
        if (!start_kid(args, &kids[i])) {
            line("CreateProcessA, child %d: failed err=%s", i + 1, le());
            break;
        }
        CloseHandle(kids[i].hThread);
        made++;
    }
    line("children started: %d of %d", made, CHILDREN);

    for (i = 0; i < made; i++) {
        if (WaitForSingleObject(ready, CHILD_MS) != WAIT_OBJECT_0) {
            break;
        }
        readied++;
    }
    for (i = 0; i < made; i++) {
        if (GetExitCodeProcess(kids[i].hProcess, &code) && code == STILL_ACTIVE) {
            active++;
        }
    }
    line("ready (each released the semaphore once): %d, still active all together: %d", readied, active);

    for (i = 0; i < made; i++) {
        pid4 &= (kids[i].dwProcessId & 3) == 0 && kids[i].dwProcessId != 0;
        tid4 &= (kids[i].dwThreadId & 3) == 0 && kids[i].dwThreadId != 0;
        ids[i] = kids[i].dwProcessId;
    }
    line("their process ids: multiples of 4 %s, distinct %s", yesno(pid4), yesno(distinct(ids, made)));
    for (i = 0; i < made; i++) {
        ids[i] = kids[i].dwThreadId;
    }
    line("their thread ids: multiples of 4 %s, distinct %s", yesno(tid4), yesno(distinct(ids, made)));
    for (i = 0; i < made; i++) {
        ids[2 * i] = kids[i].dwProcessId;
        ids[2 * i + 1] = kids[i].dwThreadId;
    }
    ids[2 * made] = GetCurrentProcessId();
    ids[2 * made + 1] = GetCurrentThreadId();
    line("no id twice among their process and thread ids, this process's and this thread's: %s",
        yesno(distinct(ids, 2 * made + 2)));

    SetEvent(go);
    for (i = 0; i < made; i++) {
        if (WaitForSingleObject(kids[i].hProcess, CHILD_MS) == WAIT_OBJECT_0) {
            ended++;
        }
        if (GetExitCodeProcess(kids[i].hProcess, &code) && code == 0) {
            zero++;
        }
        CloseHandle(kids[i].hProcess);
    }
    line("the event set: ended %d, with exit code 0 %d", ended, zero);
    CloseHandle(go);
    CloseHandle(ready);
}

static void sec_reuse(void)
{
    PROCESS_INFORMATION a;
    PROCESS_INFORMATION b;
    HANDLE h;
    DWORD w;
    DWORD code = 0;

    if (!find_kid()) {
        line("mpkid.exe's path: too long");
        return;
    }
    arm();
    if (!start_kid("quit", &a)) {
        line("child A: not started err=%s", le());
        return;
    }
    w = WaitForSingleObject(a.hProcess, CHILD_MS);
    GetExitCodeProcess(a.hProcess, &code);
    line("child A: its end %s, exit code %lu", wr(w), code);

    arm();
    h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, a.dwProcessId);
    line("OpenProcess by A's id, A ended, its handles open: opened %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        CloseHandle(h);
    }
    CloseHandle(a.hThread);
    CloseHandle(a.hProcess);

    arm();
    if (!start_kid("quit", &b)) {
        line("child B, A's handles closed: not started err=%s", le());
        return;
    }
    line("child B, started once A's handles were closed: its process id A's %s, its thread id A's %s",
        yesno(b.dwProcessId == a.dwProcessId), yesno(b.dwThreadId == a.dwThreadId));
    line("  its process id A's thread id %s, its thread id A's process id %s",
        yesno(b.dwProcessId == a.dwThreadId), yesno(b.dwThreadId == a.dwProcessId));
    w = WaitForSingleObject(b.hProcess, CHILD_MS);
    code = 0;
    GetExitCodeProcess(b.hProcess, &code);
    line("child B: its end %s, exit code %lu", wr(w), code);
    CloseHandle(b.hThread);
    CloseHandle(b.hProcess);
}

static const section_t sections[] = {
    { "alive", sec_alive, F2KT_ALWAYS },
    { "reuse", sec_reuse, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("manyproc", sections, argc, argv);
}
