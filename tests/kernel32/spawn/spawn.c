/*
 * spawn - child processes: creating them, waiting for them, their
 * handles, what they inherit, their memory seen from the parent, and the
 * C runtime's _spawn family and system().
 *
 * The children are spawnkid.exe, the companion program built beside
 * this one, which does what its first argument says (spawnkid.c lists
 * its modes). A child prints its lines ("kid: ...") through the standard
 * handles it inherits, so they land in the output where it prints them:
 * the parent prints a heading before it starts a child and its own next
 * line only once the child has ended, so every line's place is fixed.
 * A child never prints an absolute path: the parent sets F2KHOME to its
 * own directory, and the child prints paths relative to it.
 *
 * Everything the parent and its children create goes in SCRATCH, a
 * directory beside the program, which each section empties first (as
 * fswrite's). Each section starts in the program's directory, its
 * current directory, with PATH as the program found it.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   layout      Windows 2000's fixed addresses: the parent's TEB and PEB,
 *               from the PEB the image base, process parameters (their
 *               flags and command line buffer), process heap and
 *               environment, from the TEB the stack base and limit, and a
 *               second thread's TEB and stack; then a running child's PEB
 *               (NtQueryInformationProcess, ProcessBasicInformation) and
 *               TEB (NtQueryInformationThread), the same fields read with
 *               ReadProcessMemory, and whether a second child's are the
 *               same. These addresses print as values, the one exception
 *               to the corpus rule: Windows 2000 has no address
 *               randomization, so they are the same on every run, and
 *               they settle where F2K puts them.
 *   create      CreateProcessA, then CreateProcessW on the same inputs:
 *               the application name against the command line, .exe
 *               added, the search order (the program's directory, the
 *               current directory, the system directory, PATH; only
 *               relations print), a relative path, quoting and spaces
 *               (and the unquoted path a shorter name catches), a missing
 *               program and directory, a directory, a text file
 *               (ERROR_BAD_EXE_FORMAT), an empty file, a DLL, an empty
 *               command line, NULL for both names
 *   wait        WaitForSingleObject and GetExitCodeProcess/Thread on a
 *               running child (STILL_ACTIVE) and after its end, exit codes
 *               (0, 1, 255, 256, 259, large ones), a crash's 0xC0000005,
 *               WaitForMultipleObjects over two children
 *   handles     the handles and ids CreateProcessA returns (nonzero,
 *               distinct; never their values), OpenProcess on a child's
 *               id and TerminateProcess through handles with and without
 *               PROCESS_TERMINATE, CREATE_SUSPENDED with SuspendThread and
 *               ResumeThread, TerminateProcess on a child that never ran,
 *               DuplicateHandle of an event into a child (which sets it)
 *               and back
 *   inherit     STARTF_USESTDHANDLES with inheritable files as the
 *               child's standard output and error (read back) and input,
 *               what the child finds in its standard handles with
 *               bInheritHandles TRUE and FALSE, a handle not marked
 *               inheritable passed by value, then marked with
 *               SetHandleInformation
 *   environment custom environment blocks (ANSI, Unicode with
 *               CREATE_UNICODE_ENVIRONMENT, unsorted, empty) and NULL
 *               (the parent's, with variables it set and removed)
 *   curdir      lpCurrentDirectory: NULL, absolute, with a trailing
 *               backslash, relative, missing, a file; whether the program
 *               is searched for there; the parent's own current directory
 *   memory      ReadProcessMemory on a suspended child (its PEB's image
 *               base, its image's first page against the file), partial
 *               reads across the image's end, bad addresses, a NULL
 *               handle, a handle without PROCESS_VM_READ, the parent's own
 *               memory; WriteProcessMemory of a dword into the child's
 *               (read-only) image header, read back and printed by the
 *               child once resumed, a second child's unchanged, and the
 *               write errors
 *   binarytype  GetBinaryTypeA and GetBinaryTypeW on the program, the
 *               companion with and without .exe, kernel32.dll, text files
 *               named .txt and .exe, an empty file, a directory, a missing
 *               file and directory: the type and the error
 *   spawn       msvcrt's _spawnl, _spawnv, _spawnlp/_spawnvp (the PATH
 *               search, against _spawnl's none), _spawnle/_spawnve
 *               (environments), _P_WAIT's exit code, _P_NOWAIT with
 *               _cwait (twice on one handle), and the errors' errno and
 *               _doserrno
 *   system      system(NULL), an echo, exit codes through "exit 3" and a
 *               program. F2K has no cmd.exe on its disk (system runs the
 *               command processor COMSPEC names): this block is expected
 *               to stay failing there.
 *   detach      CreateProcessA/W with DETACHED_PROCESS and with
 *               CREATE_NEW_CONSOLE (the child prints nothing, exits with
 *               a code: the return, the error and the exit code print),
 *               and _spawnl(_P_DETACH) of a child that sets an event.
 *               F2K logs these through its stub path for now: this block
 *               is expected to stay failing there. On the real machine,
 *               CREATE_NEW_CONSOLE opens a console window briefly.
 *
 * Named-only section (it ends the program):
 *
 *   overlay     _spawnl(_P_OVERLAY): the program is replaced, and the
 *               child's output follows its last line (capture.bat waits
 *               for the child before it closes the block)
 *
 * No section runs a DOS program: a non-image file named .exe would start
 * the DOS machine (NTVDM), so the text files CreateProcess sees are named
 * .txt; GetBinaryType alone, which runs nothing, sees one named .exe.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat spawn):
 *   cl /nologo /MD spawnkid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% spawn.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <process.h>

/* ntdll's information queries, which no import library declares:
 * reached through GetProcAddress. */
typedef LONG (WINAPI *query_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {                    /* ProcessBasicInformation (0) */
    LONG ExitStatus;
    DWORD PebBaseAddress;
    DWORD AffinityMask;
    LONG BasePriority;
    DWORD UniqueProcessId;
    DWORD InheritedFromUniqueProcessId;
} process_basic_t;

typedef struct {                    /* ThreadBasicInformation (0) */
    LONG ExitStatus;
    DWORD TebBaseAddress;
    DWORD UniqueProcess;
    DWORD UniqueThread;
    DWORD AffinityMask;
    LONG Priority;
    LONG BasePriority;
} thread_basic_t;

/* A process's fixed addresses, as the layout section prints them. */
typedef struct {
    DWORD teb, peb, image, params, flags, heap, env, cmdline, stack_base, stack_limit;
} layout_t;

static const char *const layout_names[] = {
    "TEB", "PEB", "image base", "process parameters", "their flags", "process heap",
    "environment", "command line buffer", "stack base", "stack limit"
};

/* The events a child in "wait" mode sets and waits for. */
#define READY "F2KSpawnReady"
#define GO "F2KSpawnGo"
#define WAITING "spawnkid wait " READY " " GO

static char home[MAX_PATH];         /* the program's directory, no trailing backslash */
static char kid[MAX_PATH];          /* home\spawnkid.exe */
static char saved_path[32768];      /* PATH as the program found it */
static int had_path;
static layout_t at_start;           /* the parent's layout as main found it */
static query_fn query_process;      /* NtQueryInformationProcess */
static query_fn query_thread;       /* NtQueryInformationThread */
static HANDLE ev_ready, ev_go;

/* --- helpers ------------------------------------------------------- */

static DWORD fs_dword(DWORD where)
{
    DWORD v;

    __asm {
        mov ecx, where
        mov eax, fs:[ecx]
        mov v, eax
    }
    return v;
}

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

/* A section's start: the current directory the program's, SCRATCH there
 * and empty. */
static void reset(void)
{
    SetCurrentDirectoryA(home);
    CreateDirectoryA(at("SCRATCH"), NULL);
    wipe(at("SCRATCH\\"));
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

/* A file's lines, each under `label`. */
static void show_file(const char *label, const char *path)
{
    char buf[2048];
    DWORD n = 0;
    HANDLE f;
    char *p, *e;
    int lines = 0;

    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        line("  %s: missing, err=%lu", label, GetLastError());
        return;
    }
    ReadFile(f, buf, sizeof buf - 1, &n, NULL);
    CloseHandle(f);
    buf[n] = 0;
    for (p = buf; *p != 0; p = e) {
        e = p + strcspn(p, "\r\n");
        line("  %s: [%.*s]", label, (int)(e - p), p);
        lines++;
        if (*e == '\r') {
            e++;
        }
        if (*e == '\n') {
            e++;
        }
    }
    if (lines == 0) {
        line("  %s: empty", label);
    }
}

/* PATH set to a directory under the program's (CreateProcess searches
 * the process environment's), and back as the program found it. */
static void set_path(const char *rel)
{
    SetEnvironmentVariableA("PATH", at(rel));
}

static void restore_path(void)
{
    SetEnvironmentVariableA("PATH", had_path ? saved_path : NULL);
}

/* CreateProcessA, or (wide) CreateProcessW on the same inputs widened;
 * `custom` gives the STARTUPINFO's flags and standard handles. The last
 * error is armed just before the call, and left as it set it. */
static BOOL launch(int wide, const char *app, const char *cmd, BOOL inherit, DWORD flags,
                   void *env, const char *dir, const STARTUPINFOA *custom, PROCESS_INFORMATION *pi)
{
    static char cmdbuf[2048];
    static WCHAR wapp[2 * MAX_PATH], wcmd[2048], wdir[2 * MAX_PATH];
    STARTUPINFOA si;
    STARTUPINFOW siw;
    WCHAR *a, *c, *d;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (custom != NULL) {
        si.dwFlags = custom->dwFlags;
        si.hStdInput = custom->hStdInput;
        si.hStdOutput = custom->hStdOutput;
        si.hStdError = custom->hStdError;
    }
    memset(pi, 0, sizeof *pi);
    if (!wide) {
        if (cmd != NULL) {
            strcpy(cmdbuf, cmd);
        }
        arm();
        return CreateProcessA(app, cmd != NULL ? cmdbuf : NULL, NULL, NULL, inherit, flags, env, dir,
                              &si, pi);
    }
    memset(&siw, 0, sizeof siw);
    siw.cb = sizeof siw;
    siw.dwFlags = si.dwFlags;
    siw.hStdInput = si.hStdInput;
    siw.hStdOutput = si.hStdOutput;
    siw.hStdError = si.hStdError;
    a = widen(app, wapp, sizeof wapp / sizeof wapp[0]);
    c = widen(cmd, wcmd, sizeof wcmd / sizeof wcmd[0]);
    d = widen(dir, wdir, sizeof wdir / sizeof wdir[0]);
    arm();
    return CreateProcessW(a, c, NULL, NULL, inherit, flags, env, d, &siw, pi);
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
    if (wait != NULL) {
        *wait = w;
    }
    return code;
}

/* One creation as the sections print it: a heading, whatever the child
 * prints, then the call's result and the child's end. A fault in the
 * call prints its code instead. */
static void create_ex(int wide, const char *label, const char *app, const char *cmd, BOOL inherit,
                      DWORD flags, void *env, const char *dir, const STARTUPINFOA *custom)
{
    PROCESS_INFORMATION pi;
    char err[16];
    BOOL r = FALSE;
    DWORD code, w;

    line("%s(%s):", wide ? "CreateProcessW" : "CreateProcessA", label);
    __try {
        r = launch(wide, app, cmd, inherit, flags, env, dir, custom, &pi);
        strcpy(err, le());
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        line("  faulted: 0x%08lX", GetExceptionCode());
        return;
    }
    if (!r) {
        line("  ret=0 err=%s", err);
        return;
    }
    code = finish(&pi, &w);
    line("  ret=%d err=%s; the child's end: %s, exit code %s", r, err, wr(w), code_text(code));
}

static void create(int wide, const char *label, const char *app, const char *cmd)
{
    create_ex(wide, label, app, cmd, TRUE, 0, NULL, NULL, NULL);
}

/* Start a child in "wait" mode and let it run until it has set READY:
 * it then waits for GO. */
static BOOL start_waiting(PROCESS_INFORMATION *pi)
{
    ResetEvent(ev_ready);
    ResetEvent(ev_go);
    if (!launch(0, kid, WAITING, TRUE, 0, NULL, NULL, NULL, pi)) {
        line("the waiting child: not started, err=%s", le());
        return FALSE;
    }
    if (WaitForSingleObject(ev_ready, WAIT_MS) != WAIT_OBJECT_0) {
        line("the waiting child: never ready");
        TerminateProcess(pi->hProcess, 0xDEAD);
        finish(pi, NULL);
        return FALSE;
    }
    return TRUE;
}

/* A dword of another process: whether all four bytes were read. */
static int peek(HANDLE process, DWORD where, DWORD *v)
{
    DWORD n = 0;

    *v = 0;
    return ReadProcessMemory(process, (LPCVOID)where, v, sizeof *v, &n) && n == sizeof *v;
}

/* --- layout -------------------------------------------------------- */

static void own_layout(layout_t *l)
{
    l->teb = fs_dword(0x18);
    l->peb = fs_dword(0x30);
    l->image = *(DWORD *)(l->peb + 0x08);
    l->params = *(DWORD *)(l->peb + 0x10);
    l->heap = *(DWORD *)(l->peb + 0x18);
    l->flags = *(DWORD *)(l->params + 0x08);
    l->cmdline = *(DWORD *)(l->params + 0x44);
    l->env = *(DWORD *)(l->params + 0x48);
    l->stack_base = *(DWORD *)(l->teb + 0x04);
    l->stack_limit = *(DWORD *)(l->teb + 0x08);
}

/* The same fields of a child, read with ReadProcessMemory at the PEB and
 * TEB addresses ntdll's queries give; how many reads failed. */
static int child_layout(HANDLE process, HANDLE thread, layout_t *l)
{
    process_basic_t pb;
    thread_basic_t tb;
    ULONG len;
    int failed = 0;

    memset(l, 0, sizeof *l);
    memset(&pb, 0, sizeof pb);
    memset(&tb, 0, sizeof tb);
    failed += query_process(process, 0, &pb, sizeof pb, &len) != 0;
    failed += query_thread(thread, 0, &tb, sizeof tb, &len) != 0;
    l->peb = pb.PebBaseAddress;
    l->teb = tb.TebBaseAddress;
    failed += !peek(process, l->peb + 0x08, &l->image);
    failed += !peek(process, l->peb + 0x10, &l->params);
    failed += !peek(process, l->peb + 0x18, &l->heap);
    failed += !peek(process, l->params + 0x08, &l->flags);
    failed += !peek(process, l->params + 0x44, &l->cmdline);
    failed += !peek(process, l->params + 0x48, &l->env);
    failed += !peek(process, l->teb + 0x04, &l->stack_base);
    failed += !peek(process, l->teb + 0x08, &l->stack_limit);
    return failed;
}

static void show_layout(const char *who, const layout_t *l)
{
    line("%s: TEB 0x%08lX, PEB 0x%08lX, image base 0x%08lX", who, l->teb, l->peb, l->image);
    line("%s: process parameters 0x%08lX (flags 0x%08lX), process heap 0x%08lX", who, l->params,
         l->flags, l->heap);
    line("%s: environment 0x%08lX, command line buffer 0x%08lX", who, l->env, l->cmdline);
    line("%s: stack base 0x%08lX, limit 0x%08lX", who, l->stack_base, l->stack_limit);
}

static DWORD thread_teb, thread_peb, thread_base, thread_limit;

static DWORD WINAPI layout_thread(LPVOID parameter)
{
    (void)parameter;
    thread_teb = fs_dword(0x18);
    thread_peb = fs_dword(0x30);
    thread_base = fs_dword(0x04);
    thread_limit = fs_dword(0x08);
    return 0;
}

static void sec_layout(void)
{
    layout_t children[2];
    PROCESS_INFORMATION pi;
    process_basic_t pb;
    thread_basic_t tb;
    char differ[256];
    HANDLE t;
    DWORD id, code;
    ULONG len;
    LONG st;
    int i, failed;

    show_layout("parent", &at_start);
    line("parent: the TEB's PEB pointer the PEB: %s",
         yesno(*(DWORD *)(at_start.teb + 0x30) == at_start.peb));

    arm();
    t = CreateThread(NULL, 0, layout_thread, NULL, 0, &id);
    if (t == NULL) {
        line("CreateThread: err=%s", le());
    } else {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
        line("second thread: TEB 0x%08lX, its PEB pointer the PEB: %s", thread_teb,
             yesno(thread_peb == at_start.peb));
        line("second thread: stack base 0x%08lX, limit 0x%08lX", thread_base, thread_limit);
    }

    if (query_process == NULL || query_thread == NULL) {
        line("ntdll's NtQueryInformationProcess and NtQueryInformationThread: not found");
        return;
    }
    for (i = 0; i < 2; i++) {
        if (!start_waiting(&pi)) {
            return;
        }
        if (i == 0) {
            memset(&pb, 0, sizeof pb);
            len = 0xF2F2;
            st = query_process(pi.hProcess, 0, &pb, sizeof pb, &len);
            line("NtQueryInformationProcess(ProcessBasicInformation): status 0x%08lX, length %lu", st, len);
            line("  ExitStatus 0x%08lX, UniqueProcessId the child's id: %s, "
                 "InheritedFromUniqueProcessId the parent's: %s", pb.ExitStatus,
                 yesno(pb.UniqueProcessId == pi.dwProcessId),
                 yesno(pb.InheritedFromUniqueProcessId == GetCurrentProcessId()));
            len = 0xF2F2;
            st = query_process(pi.hProcess, 0, &pb, sizeof pb - 4, &len);
            line("NtQueryInformationProcess, a buffer 4 bytes short: status 0x%08lX", st);
            memset(&tb, 0, sizeof tb);
            len = 0xF2F2;
            st = query_thread(pi.hThread, 0, &tb, sizeof tb, &len);
            line("NtQueryInformationThread(ThreadBasicInformation): status 0x%08lX, length %lu", st, len);
            line("  ExitStatus 0x%08lX, its client id the child's process and thread: %s",
                 tb.ExitStatus,
                 yesno(tb.UniqueProcess == pi.dwProcessId && tb.UniqueThread == pi.dwThreadId));
        }
        failed = child_layout(pi.hProcess, pi.hThread, &children[i]);
        if (i == 0) {
            show_layout("child", &children[0]);
            line("child: reads failed: %d", failed);
        }
        SetEvent(ev_go);
        code = finish(&pi, NULL);
        if (i == 0) {
            line("child: exit code %s", code_text(code));
        }
    }
    differ[0] = 0;
    for (i = 0; i < (int)(sizeof layout_names / sizeof layout_names[0]); i++) {
        if (((DWORD *)&children[0])[i] != ((DWORD *)&children[1])[i]) {
            strcat(differ, differ[0] != 0 ? ", " : " (differ: ");
            strcat(differ, layout_names[i]);
        }
    }
    if (differ[0] != 0) {
        strcat(differ, ")");
    }
    line("a second child: the same addresses: %s%s", yesno(differ[0] == 0), differ);
}

/* --- create -------------------------------------------------------- */

/* SCRATCH as the create cases expect it: copies of spawnkid.exe in sub
 * (as spawnkid.exe and kidcopy.exe), in other (kidcopy.exe) and in
 * "with space" (as "kid copy.exe"), a text file and an empty one. */
static void create_setup(void)
{
    reset();
    CreateDirectoryA(at("SCRATCH\\sub"), NULL);
    CreateDirectoryA(at("SCRATCH\\other"), NULL);
    CreateDirectoryA(at("SCRATCH\\with space"), NULL);
    CopyFileA(kid, at("SCRATCH\\sub\\spawnkid.exe"), FALSE);
    CopyFileA(kid, at("SCRATCH\\sub\\kidcopy.exe"), FALSE);
    CopyFileA(kid, at("SCRATCH\\other\\kidcopy.exe"), FALSE);
    CopyFileA(kid, at("SCRATCH\\with space\\kid copy.exe"), FALSE);
    make_file(at("SCRATCH\\notexe.txt"), "not a program\r\n");
    make_file(at("SCRATCH\\empty.txt"), "");
}

static void create_cases(int wide)
{
    char cmd[2 * MAX_PATH];
    char sys[MAX_PATH];

    create_setup();
    create(wide, "the application name, absolute, and a command line", kid,
           "spawnkid args one \"two words\"");
    create(wide, "the application name alone, relative", "spawnkid.exe", NULL);
    create(wide, "the application name without .exe", "spawnkid", "spawnkid args");
    create(wide, "a command line alone", NULL, "spawnkid.exe args x");
    create(wide, "a command line alone, .exe left out", NULL, "spawnkid args x");
    sprintf(cmd, "\"%s\" args absolute", kid);
    create(wide, "a command line alone, the absolute path quoted", NULL, cmd);
    create(wide, "arguments with quotes and backslashes", NULL,
           "spawnkid args \"a b\" c\\\"d \"\" e\\\\\"f g\"");

    /* The search: the program's directory, the current directory, the
     * system directory, PATH. */
    SetCurrentDirectoryA(at("SCRATCH\\sub"));
    create(wide, "spawnkid, another in the current directory", NULL, "spawnkid where");
    create(wide, "kidcopy, in the current directory", NULL, "kidcopy where");
    set_path("SCRATCH\\other");
    create(wide, "kidcopy, in the current directory and on PATH", NULL, "kidcopy where");
    SetCurrentDirectoryA(at("SCRATCH"));
    create(wide, "kidcopy, on PATH only", NULL, "kidcopy where");
    restore_path();
    create(wide, "sub\\kidcopy, under the current directory", NULL, "sub\\kidcopy where");
    SetCurrentDirectoryA(at("SCRATCH\\other"));
    create(wide, "SCRATCH\\sub\\kidcopy, under the program's directory only", NULL,
           "SCRATCH\\sub\\kidcopy where");
    SetCurrentDirectoryA(home);
    create(wide, "kernel32.dll, in the system directory", NULL, "kernel32.dll");
    create(wide, "kernel32, .exe added", NULL, "kernel32");
    create(wide, "a name found nowhere", NULL, "kidnone args");

    /* What cannot run. */
    create(wide, "a missing application name", "SCRATCH\\kidnone.exe", "kidnone");
    create(wide, "an application name in a missing directory", "SCRATCH\\nodir\\kidnone.exe", "kidnone");
    create(wide, "a directory as the command line", NULL, "SCRATCH\\sub");
    create(wide, "a directory as the application name", "SCRATCH\\sub", "sub");
    create(wide, "a text file as the application name", "SCRATCH\\notexe.txt", "notexe");
    create(wide, "a text file as the command line", NULL, "SCRATCH\\notexe.txt args");
    create(wide, "an empty file as the application name", "SCRATCH\\empty.txt", "empty");
    GetSystemDirectoryA(sys, sizeof sys);
    strcat(sys, "\\kernel32.dll");
    create(wide, "a DLL as the application name, kernel32.dll", sys, "kernel32");

    /* Spaces and quotes: the unquoted path runs the first name that
     * exists, "SCRATCH\with" then "SCRATCH\with space\kid" then the
     * whole; the child, its first argument no mode, prints where it is. */
    create(wide, "a quoted path with spaces", NULL, "\"SCRATCH\\with space\\kid copy.exe\" args a");
    create(wide, "the same path as the application name, unquoted", "SCRATCH\\with space\\kid copy.exe",
           "kid args b");
    create(wide, "the same path unquoted in the command line", NULL, "SCRATCH\\with space\\kid copy.exe");
    CopyFileA(kid, at("SCRATCH\\with.exe"), FALSE);
    create(wide, "the same, with SCRATCH\\with.exe there", NULL, "SCRATCH\\with space\\kid copy.exe");

    create(wide, "an empty command line", NULL, "");
    create(wide, "NULL for both", NULL, NULL);
}

static void sec_create(void)
{
    create_cases(0);
    create_cases(1);
    SetCurrentDirectoryA(home);
}

/* --- wait ---------------------------------------------------------- */

static void exit_code_of(const char *arg)
{
    PROCESS_INFORMATION pi;
    char cmd[64];
    DWORD code, w;

    sprintf(cmd, "spawnkid exit %s", arg);
    if (!launch(0, kid, cmd, TRUE, 0, NULL, NULL, NULL, &pi)) {
        line("spawnkid exit %s: not started, err=%s", arg, le());
        return;
    }
    code = finish(&pi, &w);
    line("spawnkid exit %s: its end %s, GetExitCodeProcess %s", arg, wr(w), code_text(code));
}

static void sec_wait(void)
{
    PROCESS_INFORMATION pi, other;
    HANDLE both[2];
    DWORD code, w;
    BOOL r;

    line("a child waiting on an event:");
    if (start_waiting(&pi)) {
        arm();
        w = WaitForSingleObject(pi.hProcess, 0);
        line("  WaitForSingleObject(process, 0): %s err=%s", wr(w), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(pi.hProcess, &code);
        line("  GetExitCodeProcess, running: ret=%d code=%s err=%s", r, code_text(code), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeThread(pi.hThread, &code);
        line("  GetExitCodeThread, running: ret=%d code=%s err=%s", r, code_text(code), le());
        SetEvent(ev_go);
        arm();
        w = WaitForSingleObject(pi.hProcess, WAIT_MS);
        line("  WaitForSingleObject(process), the event set: %s err=%s", wr(w), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(pi.hProcess, &code);
        line("  GetExitCodeProcess, ended: ret=%d code=%s err=%s", r, code_text(code), le());
        arm();
        w = WaitForSingleObject(pi.hProcess, 0);
        line("  WaitForSingleObject(process, 0) again: %s err=%s", wr(w), le());
        arm();
        w = WaitForSingleObject(pi.hThread, WAIT_MS);
        line("  WaitForSingleObject(thread): %s err=%s", wr(w), le());
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    exit_code_of("0");
    exit_code_of("1");
    exit_code_of("255");
    exit_code_of("256");
    exit_code_of("259");
    exit_code_of("0x12345678");
    exit_code_of("0x7FFFFFFF");
    exit_code_of("0xFFFFFFFF");
    if (launch(0, kid, "spawnkid crash", TRUE, 0, NULL, NULL, NULL, &pi)) {
        code = finish(&pi, &w);
        line("spawnkid crash: its end %s, GetExitCodeProcess %s", wr(w), code_text(code));
    }

    line("WaitForMultipleObjects, a waiting child and spawnkid exit 2:");
    if (start_waiting(&pi)) {
        if (launch(0, kid, "spawnkid exit 2", TRUE, 0, NULL, NULL, NULL, &other)) {
            both[0] = pi.hProcess;
            both[1] = other.hProcess;
            arm();
            w = WaitForMultipleObjects(2, both, FALSE, WAIT_MS);
            line("  any: %s err=%s", wr(w), le());
            arm();
            w = WaitForMultipleObjects(2, both, TRUE, 0);
            line("  all, at once: %s err=%s", wr(w), le());
            SetEvent(ev_go);
            arm();
            w = WaitForMultipleObjects(2, both, TRUE, WAIT_MS);
            line("  all, the event set: %s err=%s", wr(w), le());
            code = finish(&other, NULL);
            line("  exit codes: %s and %s", code_text(finish(&pi, NULL)), code_text(code));
        } else {
            SetEvent(ev_go);
            finish(&pi, NULL);
        }
    }
}

/* --- handles ------------------------------------------------------- */

static void sec_handles(void)
{
    PROCESS_INFORMATION pi;
    HANDLE opened, limited, terminator, ev, back, in_child;
    DWORD code, w, ret;
    BOOL r;
    char text[32];
    char err[16];

    reset();

    if (launch(0, kid, "spawnkid exit 7", TRUE, 0, NULL, NULL, NULL, &pi)) {
        line("CreateProcessA: process and thread handles nonzero: %s, distinct: %s",
             yesno(pi.hProcess != NULL && pi.hThread != NULL), yesno(pi.hProcess != pi.hThread));
        line("CreateProcessA: process and thread ids nonzero: %s, distinct: %s, the process's not the "
             "parent's: %s", yesno(pi.dwProcessId != 0 && pi.dwThreadId != 0),
             yesno(pi.dwProcessId != pi.dwThreadId), yesno(pi.dwProcessId != GetCurrentProcessId()));
        w = WaitForSingleObject(pi.hProcess, WAIT_MS);
        line("spawnkid exit 7: its end %s", wr(w));
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(pi.hProcess, &code);
        line("GetExitCodeProcess: ret=%d code=%s err=%s", r, code_text(code), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeThread(pi.hThread, &code);
        line("GetExitCodeThread, its thread: ret=%d code=%s err=%s", r, code_text(code), le());
        finish(&pi, NULL);
    }

    line("a waiting child, opened by its id:");
    if (start_waiting(&pi)) {
        arm();
        opened = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pi.dwProcessId);
        line("  OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE): opened %s, a new handle %s err=%s",
             yesno(opened != NULL), yesno(opened != NULL && opened != pi.hProcess), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(opened, &code);
        line("  GetExitCodeProcess through it: ret=%d code=%s err=%s", r, code_text(code), le());
        limited = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi.dwProcessId);
        arm();
        r = TerminateProcess(limited, 41);
        line("  TerminateProcess(41), a handle without PROCESS_TERMINATE: ret=%d err=%s", r, le());
        arm();
        terminator = OpenProcess(PROCESS_TERMINATE, FALSE, pi.dwProcessId);
        line("  OpenProcess(PROCESS_TERMINATE): opened %s err=%s", yesno(terminator != NULL), le());
        arm();
        r = TerminateProcess(terminator, 42);
        line("  TerminateProcess(42) through it: ret=%d err=%s", r, le());
        arm();
        w = WaitForSingleObject(opened, WAIT_MS);
        line("  WaitForSingleObject, the first opened handle: %s err=%s", wr(w), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(pi.hProcess, &code);
        line("  GetExitCodeProcess: ret=%d code=%s err=%s", r, code_text(code), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeThread(pi.hThread, &code);
        line("  GetExitCodeThread, its thread: ret=%d code=%s err=%s", r, code_text(code), le());
        arm();
        r = TerminateProcess(pi.hProcess, 43);
        line("  TerminateProcess(43), the process ended: ret=%d err=%s", r, le());
        code = 0xF2F2F2F2u;
        GetExitCodeProcess(pi.hProcess, &code);
        line("  GetExitCodeProcess after it: %s", code_text(code));
        CloseHandle(opened);
        CloseHandle(limited);
        CloseHandle(terminator);
        finish(&pi, NULL);
    }
    arm();
    opened = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 0);
    line("OpenProcess, id 0: ret null %s err=%s", yesno(opened == NULL), le());
    if (opened != NULL) {
        CloseHandle(opened);
    }

    line("CreateProcessA(CREATE_SUSPENDED), spawnkid args resumed:");
    if (launch(0, kid, "spawnkid args resumed", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        arm();
        w = WaitForSingleObject(pi.hProcess, 0);
        line("  WaitForSingleObject(process, 0): %s err=%s", wr(w), le());
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(pi.hProcess, &code);
        line("  GetExitCodeProcess: ret=%d code=%s err=%s", r, code_text(code), le());
        arm();
        ret = SuspendThread(pi.hThread);
        line("  SuspendThread: ret=%lu err=%s", ret, le());
        arm();
        ret = ResumeThread(pi.hThread);
        line("  ResumeThread: ret=%lu err=%s", ret, le());
        arm();
        ret = ResumeThread(pi.hThread);
        strcpy(err, le());
        code = finish(&pi, &w);
        line("  ResumeThread, the last: ret=%lu err=%s; the child's end: %s, exit code %s", ret, err,
             wr(w), code_text(code));
    }

    line("CreateProcessA(CREATE_SUSPENDED), spawnkid args never, then TerminateProcess(44):");
    if (launch(0, kid, "spawnkid args never", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        arm();
        r = TerminateProcess(pi.hProcess, 44);
        line("  TerminateProcess: ret=%d err=%s", r, le());
        w = WaitForSingleObject(pi.hProcess, WAIT_MS);
        code = 0xF2F2F2F2u;
        GetExitCodeThread(pi.hThread, &code);
        line("  the child's end: %s, its thread's exit code %s, the process's %s", wr(w), code_text(code),
             code_text(finish(&pi, NULL)));
    }

    line("DuplicateHandle of an event into a suspended child, spawnkid usedup:");
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (launch(0, kid, "spawnkid usedup SCRATCH\\dup.txt", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        in_child = NULL;
        arm();
        r = DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &in_child, 0, FALSE,
                            DUPLICATE_SAME_ACCESS);
        line("  into the child: ret=%d err=%s, a value: %s", r, le(), yesno(in_child != NULL));
        back = NULL;
        arm();
        r = DuplicateHandle(pi.hProcess, in_child, GetCurrentProcess(), &back, 0, FALSE,
                            DUPLICATE_SAME_ACCESS);
        line("  back from the child: ret=%d err=%s", r, le());
        if (back != NULL) {
            SetEvent(back);
            line("  the same event: %s", yesno(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0));
            ResetEvent(ev);
            CloseHandle(back);
        }
        sprintf(text, "%lu", (DWORD)in_child);
        make_file(at("SCRATCH\\dup.txt"), text);
        ResumeThread(pi.hThread);
        code = finish(&pi, &w);
        line("  the child's end: %s, exit code %s; the event set by the child: %s", wr(w),
             code_text(code), yesno(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0));
    }
    CloseHandle(ev);
}

/* --- inherit ------------------------------------------------------- */

static HANDLE open_file(const char *rel, DWORD access, DWORD disposition, BOOL inheritable)
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = inheritable;
    return CreateFileA(at(rel), access, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, disposition,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

/* STARTF_USESTDHANDLES with inheritable files for the three handles. */
static void std_files(STARTUPINFOA *si, const char *out, const char *err)
{
    memset(si, 0, sizeof *si);
    si->cb = sizeof *si;
    si->dwFlags = STARTF_USESTDHANDLES;
    si->hStdInput = open_file("SCRATCH\\in.txt", GENERIC_READ, OPEN_EXISTING, TRUE);
    si->hStdOutput = open_file(out, GENERIC_WRITE, CREATE_ALWAYS, TRUE);
    si->hStdError = open_file(err, GENERIC_WRITE, CREATE_ALWAYS, TRUE);
}

static void close_std_files(STARTUPINFOA *si)
{
    CloseHandle(si->hStdInput);
    CloseHandle(si->hStdOutput);
    CloseHandle(si->hStdError);
}

static void inherit_cases(int wide)
{
    STARTUPINFOA si;
    HANDLE a, b, holes[16];
    char cmd[128];
    BOOL r;
    int i;

    reset();
    make_file(at("SCRATCH\\in.txt"), "a line from in.txt\r\nanother line\r\n");

    std_files(&si, "SCRATCH\\out.txt", "SCRATCH\\err.txt");
    create_ex(wide, "STARTF_USESTDHANDLES, files for all three, spawnkid out", kid, "spawnkid out", TRUE, 0,
              NULL, NULL, &si);
    close_std_files(&si);
    show_file("out.txt", at("SCRATCH\\out.txt"));
    show_file("err.txt", at("SCRATCH\\err.txt"));

    std_files(&si, "SCRATCH\\out.txt", "SCRATCH\\err.txt");
    create_ex(wide, "STARTF_USESTDHANDLES, files for all three, spawnkid read", kid, "spawnkid read", TRUE,
              0, NULL, NULL, &si);
    close_std_files(&si);
    show_file("out.txt", at("SCRATCH\\out.txt"));

    std_files(&si, "SCRATCH\\out.txt", "SCRATCH\\err.txt");
    create_ex(wide, "STARTF_USESTDHANDLES, files for all three, spawnkid handles", kid,
              "spawnkid handles SCRATCH\\report.txt", TRUE, 0, NULL, NULL, &si);
    show_file("report.txt", at("SCRATCH\\report.txt"));
    create_ex(wide, "the same, bInheritHandles FALSE", kid, "spawnkid handles SCRATCH\\report.txt", FALSE,
              0, NULL, NULL, &si);
    close_std_files(&si);
    show_file("report.txt", at("SCRATCH\\report.txt"));

    /* Two handles by value: the first inheritable, the second not. The
     * placeholders, never inherited, leave free slots below them in the
     * child's handle table for the child's own handles. */
    for (i = 0; i < 16; i++) {
        holes[i] = CreateEventA(NULL, TRUE, FALSE, NULL);
    }
    make_file(at("SCRATCH\\a.txt"), "inheritable");
    make_file(at("SCRATCH\\b.txt"), "not inherited");
    a = open_file("SCRATCH\\a.txt", GENERIC_READ, OPEN_EXISTING, TRUE);
    b = open_file("SCRATCH\\b.txt", GENERIC_READ, OPEN_EXISTING, FALSE);
    sprintf(cmd, "spawnkid probe %lu %lu", (DWORD)a, (DWORD)b);
    create_ex(wide, "spawnkid probe, an inheritable handle (11 bytes) and one not (13 bytes)", kid, cmd,
              TRUE, 0, NULL, NULL, NULL);
    arm();
    r = SetHandleInformation(b, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    line("SetHandleInformation(HANDLE_FLAG_INHERIT), the second: ret=%d err=%s", r, le());
    sprintf(cmd, "spawnkid probe %lu", (DWORD)b);
    create_ex(wide, "spawnkid probe, the second, now inheritable", kid, cmd, TRUE, 0, NULL, NULL, NULL);
    CloseHandle(a);
    CloseHandle(b);
    for (i = 0; i < 16; i++) {
        CloseHandle(holes[i]);
    }
}

static void sec_inherit(void)
{
    inherit_cases(0);
    inherit_cases(1);
}

/* --- environment --------------------------------------------------- */

static void environment_cases(int wide)
{
    /* Each literal's own terminator ends the block. */
    static const char ansi[] = "F2KA=one\0F2KB=two words\0";
    static const char unsorted[] = "ZED=last letter, first\0ALPHA=first letter, last\0";
    static const char empty[] = "\0";
    static const WCHAR unicode[] = L"F2KW=wide\0F2KX=also wide\0";

    create_ex(wide, "an ANSI block", kid, "spawnkid envall", TRUE, 0, (void *)ansi, NULL, NULL);
    create_ex(wide, "an unsorted ANSI block", kid, "spawnkid envall", TRUE, 0, (void *)unsorted, NULL, NULL);
    create_ex(wide, "a Unicode block, CREATE_UNICODE_ENVIRONMENT", kid, "spawnkid envall", TRUE,
              CREATE_UNICODE_ENVIRONMENT, (void *)unicode, NULL, NULL);
    create_ex(wide, "an empty block", kid, "spawnkid envall", TRUE, 0, (void *)empty, NULL, NULL);
    create_ex(wide, "NULL, the parent's environment", kid, "spawnkid env F2KINHERIT F2KGONE F2KWIDE F2KA",
              TRUE, 0, NULL, NULL, NULL);
}

static void sec_environment(void)
{
    BOOL r;

    arm();
    r = SetEnvironmentVariableA("F2KINHERIT", "from the parent");
    line("SetEnvironmentVariableA(F2KINHERIT): ret=%d err=%s", r, le());
    SetEnvironmentVariableA("F2KGONE", "soon gone");
    arm();
    r = SetEnvironmentVariableA("F2KGONE", NULL);
    line("SetEnvironmentVariableA(F2KGONE, NULL), the variable set: ret=%d err=%s", r, le());
    arm();
    r = SetEnvironmentVariableW(L"F2KWIDE", L"set wide");
    line("SetEnvironmentVariableW(F2KWIDE): ret=%d err=%s", r, le());
    environment_cases(0);
    environment_cases(1);
}

/* --- curdir -------------------------------------------------------- */

static void curdir_cases(int wide)
{
    char dir[2 * MAX_PATH];

    create_ex(wide, "lpCurrentDirectory NULL", kid, "spawnkid where", TRUE, 0, NULL, NULL, NULL);
    create_ex(wide, "lpCurrentDirectory SCRATCH\\sub, absolute", kid, "spawnkid where", TRUE, 0, NULL,
              at("SCRATCH\\sub"), NULL);
    sprintf(dir, "%s\\", at("SCRATCH\\sub"));
    create_ex(wide, "lpCurrentDirectory SCRATCH\\sub\\, absolute", kid, "spawnkid where", TRUE, 0, NULL, dir,
              NULL);
    create_ex(wide, "lpCurrentDirectory SCRATCH\\sub, relative", kid, "spawnkid where", TRUE, 0, NULL,
              "SCRATCH\\sub", NULL);
    create_ex(wide, "lpCurrentDirectory a missing directory", kid, "spawnkid where", TRUE, 0, NULL,
              at("SCRATCH\\nodir"), NULL);
    create_ex(wide, "lpCurrentDirectory a file", kid, "spawnkid where", TRUE, 0, NULL,
              at("SCRATCH\\afile.txt"), NULL);
    create_ex(wide, "lpCurrentDirectory SCRATCH\\sub, the only one holding kidcopy", NULL, "kidcopy where",
              TRUE, 0, NULL, at("SCRATCH\\sub"), NULL);
    SetCurrentDirectoryA(at("SCRATCH"));
    create_ex(wide, "lpCurrentDirectory NULL, the parent's current directory SCRATCH", kid, "spawnkid where",
              TRUE, 0, NULL, NULL, NULL);
    SetCurrentDirectoryA(home);
}

static void sec_curdir(void)
{
    reset();
    CreateDirectoryA(at("SCRATCH\\sub"), NULL);
    CopyFileA(kid, at("SCRATCH\\sub\\kidcopy.exe"), FALSE);
    make_file(at("SCRATCH\\afile.txt"), "a file\r\n");
    curdir_cases(0);
    curdir_cases(1);
}

/* --- memory -------------------------------------------------------- */

static void sec_memory(void)
{
    PROCESS_INFORMATION pi;
    process_basic_t pb;
    BYTE page[4096];
    BYTE file[512];
    HANDLE limited, f;
    DWORD base = 0, lfanew, size = 0, image_base, mark = 0x4B324632u, got, n, w, code;
    DWORD local = 0x5A5A5A5Au, copy = 0;
    DWORD header = FIELD_OFFSET(IMAGE_DOS_HEADER, e_res2);
    ULONG len;
    BOOL r;

    if (query_process == NULL) {
        line("ntdll's NtQueryInformationProcess: not found");
        return;
    }
    line("a suspended child, spawnkid mark:");
    if (!launch(0, kid, "spawnkid mark", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        line("  not started, err=%s", le());
        return;
    }
    memset(&pb, 0, sizeof pb);
    query_process(pi.hProcess, 0, &pb, sizeof pb, &len);

    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(pi.hProcess, (LPCVOID)(pb.PebBaseAddress + 0x08), &base, 4, &n);
    line("ReadProcessMemory, the PEB's image base: ret=%d n=%lu err=%s", r, n, le());
    n = 0xF2F2;
    memset(page, 0, sizeof page);
    arm();
    r = ReadProcessMemory(pi.hProcess, (LPCVOID)base, page, sizeof page, &n);
    line("ReadProcessMemory, the image's first page: ret=%d n=%lu err=%s", r, n, le());
    line("  MZ: %s", yesno(page[0] == 'M' && page[1] == 'Z'));
    lfanew = *(DWORD *)(page + 0x3C);
    if (lfanew < sizeof page - sizeof(IMAGE_NT_HEADERS)) {
        image_base = *(DWORD *)(page + lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.ImageBase));
        size = *(DWORD *)(page + lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.SizeOfImage));
        line("  PE signature: %s, the image base its header's ImageBase: %s",
             yesno(memcmp(page + lfanew, "PE\0\0", 4) == 0), yesno(image_base == base));
    }
    f = CreateFileA(kid, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    n = 0;
    if (f != INVALID_HANDLE_VALUE) {
        ReadFile(f, file, sizeof file, &n, NULL);
        CloseHandle(f);
    }
    line("  its first 512 bytes the file's: %s", yesno(n == sizeof file && memcmp(page, file, sizeof file) == 0));

    if (size != 0) {
        n = 0xF2F2;
        arm();
        r = ReadProcessMemory(pi.hProcess, (LPCVOID)(base + size - 8), page, 16, &n);
        line("ReadProcessMemory, 16 bytes across the image's end: ret=%d n=%lu err=%s", r, n, le());
    }
    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(pi.hProcess, NULL, page, 4, &n);
    line("ReadProcessMemory, address 0: ret=%d n=%lu err=%s", r, n, le());
    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(pi.hProcess, (LPCVOID)0x80000000u, page, 4, &n);
    line("ReadProcessMemory, address 0x80000000: ret=%d n=%lu err=%s", r, n, le());
    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(pi.hProcess, (LPCVOID)base, page, 0, &n);
    line("ReadProcessMemory, 0 bytes: ret=%d n=%lu err=%s", r, n, le());
    arm();
    r = ReadProcessMemory(pi.hProcess, (LPCVOID)base, page, 4, NULL);
    line("ReadProcessMemory, no count: ret=%d err=%s", r, le());
    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(NULL, (LPCVOID)base, page, 4, &n);
    line("ReadProcessMemory, a NULL handle: ret=%d n=%lu err=%s", r, n, le());
    limited = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi.dwProcessId);
    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(limited, (LPCVOID)base, page, 4, &n);
    line("ReadProcessMemory, a handle without PROCESS_VM_READ: ret=%d n=%lu err=%s", r, n, le());
    n = 0xF2F2;
    arm();
    r = ReadProcessMemory(GetCurrentProcess(), &local, &copy, 4, &n);
    line("ReadProcessMemory, the parent's own memory: ret=%d n=%lu err=%s, the value: %s", r, n, le(),
         yesno(copy == local));

    n = 0xF2F2;
    arm();
    r = WriteProcessMemory(pi.hProcess, (LPVOID)(base + header), &mark, 4, &n);
    line("WriteProcessMemory, a dword at the header's e_res2: ret=%d n=%lu err=%s", r, n, le());
    got = 0;
    arm();
    r = ReadProcessMemory(pi.hProcess, (LPCVOID)(base + header), &got, 4, &n);
    line("  read back: ret=%d err=%s, the dword written: %s", r, le(), yesno(got == mark));
    n = 0xF2F2;
    arm();
    r = WriteProcessMemory(pi.hProcess, NULL, &mark, 4, &n);
    line("WriteProcessMemory, address 0: ret=%d n=%lu err=%s", r, n, le());
    if (size != 0) {
        n = 0xF2F2;
        arm();
        r = WriteProcessMemory(pi.hProcess, (LPVOID)(base + size - 2), &mark, 4, &n);
        line("WriteProcessMemory, 4 bytes across the image's end: ret=%d n=%lu err=%s", r, n, le());
    }
    n = 0xF2F2;
    arm();
    r = WriteProcessMemory(limited, (LPVOID)(base + header), &mark, 4, &n);
    line("WriteProcessMemory, a handle without PROCESS_VM_WRITE: ret=%d n=%lu err=%s", r, n, le());
    CloseHandle(limited);

    line("the child resumed:");
    ResumeThread(pi.hThread);
    code = finish(&pi, &w);
    line("  its end: %s, exit code %s", wr(w), code_text(code));
    create(0, "a second child, not written to", kid, "spawnkid mark");
}

/* --- binarytype ---------------------------------------------------- */

static void binary(int wide, const char *label, const char *path)
{
    WCHAR wpath[2 * MAX_PATH];
    DWORD type = 0xF2F2F2F2u;
    char shown[16];
    BOOL r;

    if (wide) {
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, sizeof wpath / sizeof wpath[0]);
        arm();
        r = GetBinaryTypeW(wpath, &type);
    } else {
        arm();
        r = GetBinaryTypeA(path, &type);
    }
    if (type == 0xF2F2F2F2u) {
        strcpy(shown, "untouched");
    } else {
        sprintf(shown, "%lu", type);
    }
    line("GetBinaryType%s(%s): ret=%d type=%s err=%s", wide ? "W" : "A", label, r, shown, le());
}

static void binary_both(const char *label, const char *path)
{
    binary(0, label, path);
    binary(1, label, path);
}

static void sec_binarytype(void)
{
    char self[MAX_PATH];
    char sys[MAX_PATH];

    reset();
    CreateDirectoryA(at("SCRATCH\\sub"), NULL);
    make_file(at("SCRATCH\\notexe.txt"), "not a program\r\n");
    make_file(at("SCRATCH\\notexe.exe"), "not a program\r\n");
    make_file(at("SCRATCH\\empty.txt"), "");
    GetModuleFileNameA(NULL, self, sizeof self);
    GetSystemDirectoryA(sys, sizeof sys);
    strcat(sys, "\\kernel32.dll");

    binary_both("the program itself", self);
    binary_both("spawnkid.exe", "spawnkid.exe");
    binary_both("spawnkid, no extension", "spawnkid");
    binary_both("kernel32.dll in the system directory", sys);
    binary_both("a text file, .txt", "SCRATCH\\notexe.txt");
    binary_both("a text file named .exe", "SCRATCH\\notexe.exe");
    binary_both("an empty file", "SCRATCH\\empty.txt");
    binary_both("a directory", "SCRATCH\\sub");
    binary_both("a missing file", "SCRATCH\\missing.exe");
    binary_both("a file in a missing directory", "SCRATCH\\nodir\\missing.exe");
}

/* --- spawn --------------------------------------------------------- */

static void clear_errno(void)
{
    errno = 0;
    _doserrno = 0;
}

static void spawned(int r)
{
    line("  ret=%d errno=%d _doserrno=%lu", r, errno, _doserrno);
}

/* A return that may be a process handle, as printed. */
static const char *handle_kind(int r)
{
    return r == -1 ? "-1" : r == 0 ? "0" : "a handle";
}

static void sec_spawn(void)
{
    static const char *const args_v[] = { "spawnkid", "args", "x", "y z", NULL };
    static const char *const where_v[] = { "kidcopy", "where", NULL };
    static const char *const env_v[] = { "spawnkid", "env", "F2KE", "F2KSPAWN", NULL };
    static const char *const envp[] = { "F2KE=one", "F2KF=two words", NULL };
    static const char *const nowait_v[] = { "spawnkid", "args", "nowait", NULL };
    static char path[sizeof saved_path + 8];
    int r, h, status;

    reset();
    CreateDirectoryA(at("SCRATCH\\other"), NULL);
    CopyFileA(kid, at("SCRATCH\\other\\kidcopy.exe"), FALSE);
    make_file(at("SCRATCH\\notexe.txt"), "not a program\r\n");
    r = _putenv("F2KSPAWN=through _putenv");
    line("_putenv(F2KSPAWN): ret=%d", r);

    line("_spawnl(_P_WAIT), spawnkid exit 5:");
    clear_errno();
    spawned(_spawnl(_P_WAIT, kid, "spawnkid", "exit", "5", NULL));
    line("_spawnl(_P_WAIT), spawnkid args with \"a b\" and c:");
    clear_errno();
    spawned(_spawnl(_P_WAIT, kid, "spawnkid", "args", "a b", "c", NULL));
    line("_spawnl(_P_WAIT), spawnkid (relative, no extension) exit 6:");
    clear_errno();
    spawned(_spawnl(_P_WAIT, "spawnkid", "spawnkid", "exit", "6", NULL));
    line("_spawnv(_P_WAIT), spawnkid args x \"y z\":");
    clear_errno();
    spawned(_spawnv(_P_WAIT, kid, args_v));

    /* The PATH search, from SCRATCH: PATH through _putenv, which the
     * C runtime's getenv sees. */
    SetCurrentDirectoryA(at("SCRATCH"));
    sprintf(path, "PATH=%s", home);
    _putenv(path);
    line("_spawnlp(_P_WAIT), spawnkid where, PATH the program's directory:");
    clear_errno();
    spawned(_spawnlp(_P_WAIT, "spawnkid", "spawnkid", "where", NULL));
    sprintf(path, "PATH=%s", at("SCRATCH\\other"));
    _putenv(path);
    line("_spawnvp(_P_WAIT), kidcopy where, PATH SCRATCH\\other:");
    clear_errno();
    spawned(_spawnvp(_P_WAIT, "kidcopy", where_v));
    line("_spawnl(_P_WAIT), kidcopy where, PATH SCRATCH\\other:");
    clear_errno();
    spawned(_spawnl(_P_WAIT, "kidcopy", "kidcopy", "where", NULL));
    line("_spawnlp(_P_WAIT), a name found nowhere:");
    clear_errno();
    spawned(_spawnlp(_P_WAIT, "kidnone", "kidnone", NULL));
    sprintf(path, "PATH=%s", had_path ? saved_path : "");
    _putenv(path);
    SetCurrentDirectoryA(home);

    line("_spawnle(_P_WAIT), spawnkid envall, F2KE and F2KF:");
    clear_errno();
    spawned(_spawnle(_P_WAIT, kid, "spawnkid", "envall", NULL, envp));
    line("_spawnve(_P_WAIT), spawnkid env F2KE F2KSPAWN, F2KE and F2KF:");
    clear_errno();
    spawned(_spawnve(_P_WAIT, kid, env_v, envp));
    line("_spawnve(_P_WAIT), spawnkid env F2KE F2KSPAWN, NULL: the parent's environment:");
    clear_errno();
    spawned(_spawnve(_P_WAIT, kid, env_v, NULL));

    clear_errno();
    h = _spawnl(_P_NOWAIT, kid, "spawnkid", "exit", "9", NULL);
    line("_spawnl(_P_NOWAIT), spawnkid exit 9: ret %s errno=%d", handle_kind(h), errno);
    status = 0xF2F2;
    clear_errno();
    r = _cwait(&status, h, _WAIT_CHILD);
    line("  _cwait: ret the handle %s, status %s errno=%d", yesno(r == h), code_text((DWORD)status), errno);
    status = 0xF2F2;
    clear_errno();
    r = _cwait(&status, h, _WAIT_CHILD);
    line("  _cwait again, the same handle: ret %s, status %s errno=%d", r == h ? "the handle" : handle_kind(r),
         code_text((DWORD)status), errno);

    line("_spawnv(_P_NOWAIT), spawnkid args nowait, then _cwait:");
    clear_errno();
    h = _spawnv(_P_NOWAIT, kid, nowait_v);
    status = 0xF2F2;
    r = _cwait(&status, h, _WAIT_CHILD);
    line("  _spawnv: ret %s; _cwait: ret the handle %s, status %s errno=%d", handle_kind(h), yesno(r == h),
         code_text((DWORD)status), errno);

    clear_errno();
    h = _spawnl(_P_NOWAIT, kid, "spawnkid", "crash", NULL);
    status = 0xF2F2;
    r = _cwait(&status, h, _WAIT_CHILD);
    line("_spawnl(_P_NOWAIT), spawnkid crash: ret %s; _cwait: ret the handle %s, status %s errno=%d",
         handle_kind(h), yesno(r == h), code_text((DWORD)status), errno);
    clear_errno();
    h = _spawnl(_P_NOWAIT, kid, "spawnkid", "exit", "2", NULL);
    r = _cwait(NULL, h, _WAIT_CHILD);
    line("_spawnl(_P_NOWAIT), spawnkid exit 2: ret %s; _cwait, no status: ret the handle %s errno=%d",
         handle_kind(h), yesno(r == h), errno);

    line("_spawnl(_P_WAIT), a missing program:");
    clear_errno();
    spawned(_spawnl(_P_WAIT, "SCRATCH\\kidnone.exe", "kidnone", NULL));
    line("_spawnl(_P_WAIT), a text file:");
    clear_errno();
    spawned(_spawnl(_P_WAIT, "SCRATCH\\notexe.txt", "notexe", NULL));
    clear_errno();
    r = _spawnl(99, kid, "spawnkid", "exit", "1", NULL);
    line("_spawnl, mode 99, spawnkid exit 1: ret %s errno=%d _doserrno=%lu", handle_kind(r), errno, _doserrno);
}

/* --- overlay (named only) ------------------------------------------ */

static void sec_overlay(void)
{
    int r;

    line("_spawnl(_P_OVERLAY), spawnkid args overlaid: the program ends, its replacement prints next");
    clear_errno();
    r = _spawnl(_P_OVERLAY, kid, "spawnkid", "args", "overlaid", NULL);
    line("_spawnl(_P_OVERLAY) returned: ret=%d errno=%d", r, errno);
}

/* --- system -------------------------------------------------------- */

/* F2K has no cmd.exe on its disk: this block is expected to stay
 * failing there. */
static void sec_system(void)
{
    int r;

    clear_errno();
    r = system(NULL);
    line("system(NULL), a command processor: ret=%d errno=%d", r, errno);
    line("system(\"echo system: through the command processor\"):");
    clear_errno();
    r = system("echo system: through the command processor");
    line("  ret=%d errno=%d", r, errno);
    clear_errno();
    r = system("exit 3");
    line("system(\"exit 3\"): ret=%d errno=%d", r, errno);
    clear_errno();
    r = system("spawnkid exit 4");
    line("system(\"spawnkid exit 4\"): ret=%d errno=%d", r, errno);
}

/* --- detach -------------------------------------------------------- */

/* F2K logs these through its stub path for now: this block is expected
 * to stay failing there. */
static void sec_detach(void)
{
    HANDLE ev;
    DWORD w;
    int r;

    create_ex(0, "DETACHED_PROCESS, spawnkid exit 12", kid, "spawnkid exit 12", TRUE, DETACHED_PROCESS, NULL,
              NULL, NULL);
    create_ex(1, "DETACHED_PROCESS, spawnkid exit 12", kid, "spawnkid exit 12", TRUE, DETACHED_PROCESS, NULL,
              NULL, NULL);
    create_ex(0, "CREATE_NEW_CONSOLE, spawnkid exit 13", kid, "spawnkid exit 13", TRUE, CREATE_NEW_CONSOLE,
              NULL, NULL, NULL);
    create_ex(1, "CREATE_NEW_CONSOLE, spawnkid exit 13", kid, "spawnkid exit 13", TRUE, CREATE_NEW_CONSOLE,
              NULL, NULL, NULL);
    ev = CreateEventA(NULL, TRUE, FALSE, "F2KSpawnDetached");
    ResetEvent(ev);
    clear_errno();
    r = _spawnl(_P_DETACH, kid, "spawnkid", "signal", "F2KSpawnDetached", NULL);
    line("_spawnl(_P_DETACH), spawnkid signal: ret %s errno=%d", handle_kind(r), errno);
    w = WaitForSingleObject(ev, WAIT_MS);
    line("  the detached child set the event: %s", yesno(w == WAIT_OBJECT_0));
    CloseHandle(ev);
}

static const section_t sections[] = {
    { "layout", sec_layout, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "wait", sec_wait, F2KT_ALWAYS },
    { "handles", sec_handles, F2KT_ALWAYS },
    { "inherit", sec_inherit, F2KT_ALWAYS },
    { "environment", sec_environment, F2KT_ALWAYS },
    { "curdir", sec_curdir, F2KT_ALWAYS },
    { "memory", sec_memory, F2KT_ALWAYS },
    { "binarytype", sec_binarytype, F2KT_ALWAYS },
    { "spawn", sec_spawn, F2KT_ALWAYS },
    { "system", sec_system, F2KT_ALWAYS },
    { "detach", sec_detach, F2KT_ALWAYS },
    { "overlay", sec_overlay, F2KT_NAMED },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    static char home_entry[MAX_PATH + 16];
    HMODULE ntdll;
    char *p;
    DWORD n;

    own_layout(&at_start);      /* first: the environment moves once a variable is set */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, home, sizeof home);
    p = strrchr(home, '\\');
    if (p != NULL) {
        *p = 0;
    }
    sprintf(kid, "%s\\spawnkid.exe", home);
    SetCurrentDirectoryA(home);
    n = GetEnvironmentVariableA("PATH", saved_path, sizeof saved_path);
    had_path = n != 0 && n < sizeof saved_path;
    /* The children print paths relative to F2KHOME. Set both ways: the
     * process environment (CreateProcess's children inherit it) and the
     * C runtime's copy (what _spawn's children might be given). */
    SetEnvironmentVariableA("F2KHOME", home);
    sprintf(home_entry, "F2KHOME=%s", home);
    _putenv(home_entry);
    ntdll = GetModuleHandleA("ntdll.dll");
    query_process = (query_fn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    query_thread = (query_fn)GetProcAddress(ntdll, "NtQueryInformationThread");
    ev_ready = CreateEventA(NULL, TRUE, FALSE, READY);
    ev_go = CreateEventA(NULL, TRUE, FALSE, GO);
    return run_sections("spawn", sections, argc, argv);
}
