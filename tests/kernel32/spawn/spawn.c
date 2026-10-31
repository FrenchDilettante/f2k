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
 *   ended       a child that has ended, its process handle kept:
 *               NtQueryInformationProcess on it (exit status, its id, its
 *               parent this program), OpenProcess by its id while the
 *               handle holds it (GetExitCodeProcess, a wait,
 *               TerminateProcess) and once every handle is closed; a
 *               running child's parent id
 *   unstarted   the exit codes a child's thread and process end with:
 *               TerminateProcess (7, 0xC0000005) and TerminateThread (45)
 *               on a suspended child that never ran, TerminateProcess
 *               (46) and TerminateThread (47) on a running one, and a
 *               suspended child resumed to its own exit (3)
 *   dupclose    DUPLICATE_CLOSE_SOURCE out of a suspended child: back
 *               into this program, with no target process, into a handle
 *               that names no process; whether the child's handle is
 *               still there after each; and within this program
 *   remote      VirtualAllocEx, VirtualQueryEx, VirtualProtectEx and
 *               VirtualFreeEx in a suspended child; WriteProcessMemory
 *               into its read-write, read-only, execute-read, no-access
 *               and reserved pages (what each leaves of the page's
 *               protection, what was written); its image base, address 0
 *               and 0x80000000 queried; a handle with PROCESS_VM_READ
 *               only; FlushInstructionCache through handles with each
 *               access right alone, this program's, and NULL
 *   selfmem     ReadProcessMemory and WriteProcessMemory on this program's
 *               own memory through a real handle (DuplicateHandle of the
 *               pseudo-handle), OpenProcess's handle and the pseudo-handle:
 *               reads and writes crossing from committed into reserved
 *               pages, into a read-only page, a buffer crossing into a
 *               reserved page: the return, the count and the error
 *   crtfds      msvcrt's descriptors handed to a child: three files
 *               _open'ed (one _O_NOINHERIT, one append text), then
 *               _spawnl(_P_WAIT) of spawnkid crtinfo (the STARTUPINFO's
 *               cbReserved2 and lpReserved2 as the child finds them), again
 *               with one closed, and CreateProcessA with no block
 *   inheritflags GetHandleInformation's flags on an inheritable file, the
 *               same protected from close, CONOUT$ opened inheritable and
 *               not, protecting CONOUT$; what a child finds behind each
 *               value with bInheritHandles TRUE and FALSE (spawnkid flags)
 *   binaryforms GetBinaryTypeA/W on headers made in SCRATCH: a DOS
 *               program (e_lfarlc 0x1C), a new header past the file's end,
 *               NE headers for Windows, OS/2 and an unknown target, an LE
 *               header, a PE signature with nothing after it, a bare
 *               64-byte MZ header, a DOS program named .txt, text files
 *               named .com, .pif and with no extension
 *   twice       TerminateProcess on a child twice in a row (11, then 22)
 *               before it runs, then once more after its end: each call's
 *               answer and the exit codes (the parent on one CPU above
 *               the child, so the child runs only once the parent waits)
 *   lastcode    the exit code of a child whose main thread ends with
 *               ExitThread(5) before its last thread ends with
 *               ExitThread(6), and of one that calls NtTerminateProcess
 *               (NULL, 3) and then ends with ExitThread(4)
 *   termrace    twenty children, each terminated at once by
 *               TerminateProcess (11) from one thread and TerminateThread
 *               (22) of its only thread from another: how many ended
 *               with 11 or 22, whether each call ever succeeded, and the
 *               distinct errors each call's refusals gave
 *   remoteexit  CreateRemoteThread into a child again and again while the
 *               child exits on its own (ExitProcess(3) after 50 ms): the
 *               distinct errors of the refusals; then once more after its
 *               end
 *   nothread    CreateFileMappingA refusing PAGE_EXECUTE_READ | SEC_IMAGE;
 *               then, on an image section NtCreateSection makes with
 *               execute access, NtCreateProcess with no thread: its
 *               handle's state, then the handle closed; another
 *               terminated with no thread (TerminateProcess), waited for
 *               and closed
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
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

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

/* --- ended --------------------------------------------------------- */

static void sec_ended(void)
{
    PROCESS_INFORMATION pi;
    process_basic_t pb;
    HANDLE again;
    DWORD id, code, w;
    ULONG len;
    LONG st;
    BOOL r;

    reset();
    if (query_process == NULL) {
        line("ntdll's NtQueryInformationProcess: not found");
        return;
    }
    if (!launch(0, kid, "spawnkid exit 5", TRUE, 0, NULL, NULL, NULL, &pi)) {
        line("spawnkid exit 5: not started, err=%s", le());
        return;
    }
    id = pi.dwProcessId;
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    CloseHandle(pi.hThread);
    line("spawnkid exit 5: its end %s; its thread handle closed, its process handle kept", wr(w));
    memset(&pb, 0, sizeof pb);
    len = F2KT_UNTOUCHED;
    st = query_process(pi.hProcess, 0, &pb, sizeof pb, &len);
    line("NtQueryInformationProcess(ProcessBasicInformation), the ended child: 0x%08lX, length %lu", st, len);
    line("  exit status %s, a PEB %s, its id CreateProcess's %s, its parent this program %s",
         code_text((DWORD)pb.ExitStatus), yesno(pb.PebBaseAddress != 0), yesno(pb.UniqueProcessId == id),
         yesno(pb.InheritedFromUniqueProcessId == GetCurrentProcessId()));
    arm();
    again = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, id);
    line("OpenProcess by its id, a handle still holding it: opened %s err=%s", yesno(again != NULL), le());
    if (again != NULL) {
        code = 0xF2F2F2F2u;
        arm();
        r = GetExitCodeProcess(again, &code);
        line("  GetExitCodeProcess through it: ret=%d code=%s err=%s", r, code_text(code), le());
        line("  WaitForSingleObject(0) on it: %s", wr(WaitForSingleObject(again, 0)));
        CloseHandle(again);
    }
    arm();
    again = OpenProcess(PROCESS_TERMINATE, FALSE, id);
    line("OpenProcess(PROCESS_TERMINATE) by its id: opened %s err=%s", yesno(again != NULL), le());
    if (again != NULL) {
        arm();
        r = TerminateProcess(again, 9);
        line("  TerminateProcess(9) through it: ret=%d err=%s", r, le());
        CloseHandle(again);
    }
    CloseHandle(pi.hProcess);
    arm();
    again = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, id);
    line("OpenProcess by its id, every handle closed: opened %s err=%s", yesno(again != NULL), le());
    if (again != NULL) {
        CloseHandle(again);
    }

    line("a waiting child:");
    if (start_waiting(&pi)) {
        memset(&pb, 0, sizeof pb);
        st = query_process(pi.hProcess, 0, &pb, sizeof pb, &len);
        line("  NtQueryInformationProcess: 0x%08lX, exit status %s, its parent this program %s", st,
             code_text((DWORD)pb.ExitStatus), yesno(pb.InheritedFromUniqueProcessId == GetCurrentProcessId()));
        SetEvent(ev_go);
        code = finish(&pi, &w);
        line("  its end: %s, exit code %s", wr(w), code_text(code));
    }
}

/* --- unstarted ----------------------------------------------------- */

/* A child ended by `what` (its return and error given): its end, its
 * thread's exit code, the process's. */
static void show_end(PROCESS_INFORMATION *pi, const char *what, BOOL r, const char *err)
{
    DWORD w, thread_code = 0xF2F2F2F2u, process_code;

    w = WaitForSingleObject(pi->hProcess, WAIT_MS);
    GetExitCodeThread(pi->hThread, &thread_code);
    process_code = finish(pi, NULL);
    line("  %s: ret=%d err=%s; the child's end: %s, its thread's exit code %s, the process's %s", what, r,
         err, wr(w), code_text(thread_code), code_text(process_code));
}

static void sec_unstarted(void)
{
    PROCESS_INFORMATION pi;
    char err[16];
    BOOL r;

    reset();
    line("CreateProcessA(CREATE_SUSPENDED), spawnkid args never, never resumed:");
    if (launch(0, kid, "spawnkid args never", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        arm();
        r = TerminateProcess(pi.hProcess, 7);
        strcpy(err, le());
        show_end(&pi, "TerminateProcess(7)", r, err);
    }
    if (launch(0, kid, "spawnkid args never", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        arm();
        r = TerminateProcess(pi.hProcess, 0xC0000005u);
        strcpy(err, le());
        show_end(&pi, "TerminateProcess(0xC0000005)", r, err);
    }
    if (launch(0, kid, "spawnkid args never", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        arm();
        r = TerminateThread(pi.hThread, 45);
        strcpy(err, le());
        show_end(&pi, "TerminateThread(45), its only thread", r, err);
    }
    line("a running child (it set its ready event and waits for another):");
    if (start_waiting(&pi)) {
        arm();
        r = TerminateProcess(pi.hProcess, 46);
        strcpy(err, le());
        show_end(&pi, "TerminateProcess(46)", r, err);
    }
    if (start_waiting(&pi)) {
        arm();
        r = TerminateThread(pi.hThread, 47);
        strcpy(err, le());
        show_end(&pi, "TerminateThread(47), its only thread", r, err);
    }
    line("CreateProcessA(CREATE_SUSPENDED), spawnkid exit 3, resumed:");
    if (launch(0, kid, "spawnkid exit 3", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        arm();
        r = ResumeThread(pi.hThread) != (DWORD)-1;
        strcpy(err, le());
        show_end(&pi, "ResumeThread", r, err);
    }
}

/* --- dupclose ------------------------------------------------------ */

/* The child's handle `value` duplicated back out of it: whether it is
 * still open there. */
static void still_there(const char *label, HANDLE child, HANDLE value)
{
    HANDLE again = NULL;
    BOOL r;

    arm();
    r = DuplicateHandle(child, value, GetCurrentProcess(), &again, 0, FALSE, DUPLICATE_SAME_ACCESS);
    line("  %s: ret=%d err=%s", label, r, le());
    if (again != NULL) {
        CloseHandle(again);
    }
}

static void sec_dupclose(void)
{
    PROCESS_INFORMATION pi;
    HANDLE ev, in_child, back, own, dup;
    BOOL r;

    reset();
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    line("a suspended child, spawnkid args never, an event duplicated into it:");
    if (!launch(0, kid, "spawnkid args never", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        line("  not started, err=%s", le());
        CloseHandle(ev);
        return;
    }
    in_child = NULL;
    DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &in_child, 0, FALSE, DUPLICATE_SAME_ACCESS);
    back = NULL;
    arm();
    r = DuplicateHandle(pi.hProcess, in_child, GetCurrentProcess(), &back, 0, FALSE,
                        DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    line("  back out of it, DUPLICATE_CLOSE_SOURCE: ret=%d err=%s", r, le());
    if (back != NULL) {
        SetEvent(back);
        line("  the same event: %s", yesno(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0));
        ResetEvent(ev);
        CloseHandle(back);
    }
    still_there("the child's handle, duplicated out again", pi.hProcess, in_child);

    in_child = NULL;
    DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &in_child, 0, FALSE, DUPLICATE_SAME_ACCESS);
    arm();
    r = DuplicateHandle(pi.hProcess, in_child, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    line("  a second one, DUPLICATE_CLOSE_SOURCE with no target process: ret=%d err=%s", r, le());
    still_there("the second, duplicated out again", pi.hProcess, in_child);

    in_child = NULL;
    DuplicateHandle(GetCurrentProcess(), ev, pi.hProcess, &in_child, 0, FALSE, DUPLICATE_SAME_ACCESS);
    arm();
    r = DuplicateHandle(pi.hProcess, in_child, ev, &back, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    line("  a third one, DUPLICATE_CLOSE_SOURCE into an event's handle (no process): ret=%d err=%s", r, le());
    still_there("the third, duplicated out again", pi.hProcess, in_child);

    TerminateProcess(pi.hProcess, 0);
    finish(&pi, NULL);

    own = CreateEventA(NULL, TRUE, FALSE, NULL);
    dup = NULL;
    arm();
    r = DuplicateHandle(GetCurrentProcess(), own, GetCurrentProcess(), &dup, 0, FALSE,
                        DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    line("DuplicateHandle within this program, DUPLICATE_CLOSE_SOURCE: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(own);
    line("  CloseHandle on the source then: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(dup);
    line("  CloseHandle on the duplicate: ret=%d err=%s", r, le());
    CloseHandle(ev);
}

/* --- remote -------------------------------------------------------- */

/* VirtualQueryEx at `at` in `process`, as printed; the region's size
 * only when `sized` (a free region's runs to wherever the next
 * allocation is). */
static void query_at(const char *label, HANDLE process, LPCVOID at, int sized)
{
    MEMORY_BASIC_INFORMATION mbi;
    char region[24];
    DWORD n;

    memset(&mbi, 0, sizeof mbi);
    arm();
    n = VirtualQueryEx(process, at, &mbi, sizeof mbi);
    if (n == 0) {
        line("%s: ret=0 err=%s", label, le());
        return;
    }
    if (sized) {
        sprintf(region, " region 0x%lX", mbi.RegionSize);
    } else {
        region[0] = 0;
    }
    line("%s: ret=%lu, base the address %s, allocation base the address %s, state 0x%lX protect 0x%lX "
         "type 0x%lX allocprotect 0x%lX%s", label, n, yesno(mbi.BaseAddress == at),
         yesno(mbi.AllocationBase == at), mbi.State, mbi.Protect, mbi.Type, mbi.AllocationProtect, region);
}

static void remote_write(const char *label, HANDLE process, BYTE *at, const BYTE *data)
{
    DWORD n = 0xF2F2;
    BOOL r;

    arm();
    r = WriteProcessMemory(process, at, (LPVOID)data, 16, &n);
    line("%s: ret=%d n=%lu err=%s", label, r, n, le());
}

static void remote_protect(const char *label, HANDLE process, BYTE *at, DWORD protect)
{
    DWORD old = 0xF2F2;
    BOOL r;

    arm();
    r = VirtualProtectEx(process, at, 0x1000, protect, &old);
    line("%s: ret=%d old 0x%lX err=%s", label, r, old, le());
}

static void remote_flush(const char *label, DWORD access, DWORD id, LPCVOID at)
{
    HANDLE h = OpenProcess(access, FALSE, id);
    BOOL r;

    arm();
    r = FlushInstructionCache(h, at, 16);
    line("FlushInstructionCache, a handle with %s only: ret=%d err=%s", label, r, le());
    if (h != NULL) {
        CloseHandle(h);
    }
}

static void sec_remote(void)
{
    static const BYTE data[16] = "F2K remote data";
    PROCESS_INFORMATION pi;
    process_basic_t pb;
    BYTE got[16];
    HANDLE limited;
    BYTE *a, *c;
    DWORD image = 0, w, code, n;
    ULONG len;
    BOOL r;

    reset();
    if (query_process == NULL) {
        line("ntdll's NtQueryInformationProcess: not found");
        return;
    }
    line("a suspended child, spawnkid exit 0:");
    if (!launch(0, kid, "spawnkid exit 0", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        line("  not started, err=%s", le());
        return;
    }
    arm();
    a = (BYTE *)VirtualAllocEx(pi.hProcess, NULL, 0x20000, MEM_RESERVE, PAGE_NOACCESS);
    line("VirtualAllocEx(MEM_RESERVE, 128 KiB): non-null %s, on the 64 KiB granularity %s err=%s",
         yesno(a != NULL), yesno(((DWORD)a & 0xFFFF) == 0), le());
    if (a == NULL) {
        TerminateProcess(pi.hProcess, 0);
        finish(&pi, NULL);
        return;
    }
    query_at("VirtualQueryEx, the reservation", pi.hProcess, a, 1);
    arm();
    c = (BYTE *)VirtualAllocEx(pi.hProcess, a, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    line("VirtualAllocEx(MEM_COMMIT, its first page): the address %s err=%s", yesno(c == a), le());
    query_at("VirtualQueryEx, the committed page", pi.hProcess, a, 1);
    query_at("VirtualQueryEx, the page after it", pi.hProcess, a + 0x1000, 1);

    remote_write("WriteProcessMemory into the committed page", pi.hProcess, a, data);
    remote_protect("VirtualProtectEx(PAGE_READONLY)", pi.hProcess, a, PAGE_READONLY);
    remote_write("WriteProcessMemory into the read-only page", pi.hProcess, a + 16, data);
    query_at("  VirtualQueryEx after it", pi.hProcess, a, 1);
    remote_protect("VirtualProtectEx(PAGE_EXECUTE_READ)", pi.hProcess, a, PAGE_EXECUTE_READ);
    remote_write("WriteProcessMemory into the execute-read page", pi.hProcess, a + 32, data);
    query_at("  VirtualQueryEx after it", pi.hProcess, a, 1);
    remote_protect("VirtualProtectEx(PAGE_NOACCESS)", pi.hProcess, a, PAGE_NOACCESS);
    remote_write("WriteProcessMemory into the no-access page", pi.hProcess, a + 48, data);
    query_at("  VirtualQueryEx after it", pi.hProcess, a, 1);
    remote_protect("VirtualProtectEx(PAGE_READWRITE)", pi.hProcess, a, PAGE_READWRITE);
    remote_write("WriteProcessMemory into the reserved page after it", pi.hProcess, a + 0x1000, data);
    memset(got, 0, sizeof got);
    ReadProcessMemory(pi.hProcess, a, got, 16, &n);
    line("read back: the first write there %s", yesno(memcmp(got, data, 16) == 0));
    memset(got, 0, sizeof got);
    ReadProcessMemory(pi.hProcess, a + 16, got, 16, &n);
    line("  the read-only page's %s", yesno(memcmp(got, data, 16) == 0));
    memset(got, 0, sizeof got);
    ReadProcessMemory(pi.hProcess, a + 32, got, 16, &n);
    line("  the execute-read page's %s", yesno(memcmp(got, data, 16) == 0));
    memset(got, 0, sizeof got);
    ReadProcessMemory(pi.hProcess, a + 48, got, 16, &n);
    line("  the no-access page's %s", yesno(memcmp(got, data, 16) == 0));

    memset(&pb, 0, sizeof pb);
    query_process(pi.hProcess, 0, &pb, sizeof pb, &len);
    peek(pi.hProcess, pb.PebBaseAddress + 0x08, &image);
    query_at("VirtualQueryEx, the child's image base", pi.hProcess, (LPCVOID)image, 1);
    query_at("VirtualQueryEx, address 0", pi.hProcess, NULL, 1);
    query_at("VirtualQueryEx, address 0x80000000", pi.hProcess, (LPCVOID)0x80000000u, 1);

    limited = OpenProcess(PROCESS_VM_READ, FALSE, pi.dwProcessId);
    query_at("VirtualQueryEx, a handle with PROCESS_VM_READ only", limited, a, 1);
    arm();
    c = (BYTE *)VirtualAllocEx(limited, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    line("VirtualAllocEx, the same handle: non-null %s err=%s", yesno(c != NULL), le());
    remote_protect("VirtualProtectEx, the same handle", limited, a, PAGE_READONLY);
    CloseHandle(limited);

    arm();
    r = FlushInstructionCache(pi.hProcess, a, 16);
    line("FlushInstructionCache, CreateProcess's handle: ret=%d err=%s", r, le());
    remote_flush("PROCESS_VM_WRITE", PROCESS_VM_WRITE, pi.dwProcessId, a);
    remote_flush("PROCESS_VM_OPERATION", PROCESS_VM_OPERATION, pi.dwProcessId, a);
    remote_flush("PROCESS_QUERY_INFORMATION", PROCESS_QUERY_INFORMATION, pi.dwProcessId, a);
    arm();
    r = FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    line("FlushInstructionCache, this program, NULL, 0 bytes: ret=%d err=%s", r, le());
    arm();
    r = FlushInstructionCache(NULL, NULL, 0);
    line("FlushInstructionCache, a NULL handle: ret=%d err=%s", r, le());

    arm();
    r = VirtualFreeEx(pi.hProcess, a, 0, MEM_RELEASE);
    line("VirtualFreeEx(MEM_RELEASE): ret=%d err=%s", r, le());
    query_at("VirtualQueryEx, the released address", pi.hProcess, a, 0);
    arm();
    r = VirtualFreeEx(pi.hProcess, a, 0, MEM_RELEASE);
    line("VirtualFreeEx(MEM_RELEASE) again: ret=%d err=%s", r, le());

    line("the child resumed:");
    ResumeThread(pi.hThread);
    code = finish(&pi, &w);
    line("  its end: %s, exit code %s", wr(w), code_text(code));
}

/* --- selfmem ------------------------------------------------------- */

static void self_copy(int write, const char *label, HANDLE process, BYTE *at, BYTE *buffer, DWORD size)
{
    DWORD n = 0xF2F2;
    BOOL r;

    arm();
    if (write) {
        r = WriteProcessMemory(process, at, buffer, size, &n);
    } else {
        r = ReadProcessMemory(process, at, buffer, size, &n);
    }
    line("%s: ret=%d n=0x%lX err=%s", label, r, n, le());
}

/* How many of the reservation's leading bytes hold `value`. */
static DWORD run_of(const BYTE *p, DWORD size, BYTE value)
{
    DWORD i;

    for (i = 0; i < size && p[i] == value; i++) {
    }
    return i;
}

static void pattern(BYTE *p, DWORD size)
{
    DWORD i;

    for (i = 0; i < size; i++) {
        p[i] = (BYTE)(i * 7 + 3);
    }
}

static void sec_selfmem(void)
{
    static BYTE buf[0x6000];
    MEMORY_BASIC_INFORMATION mbi;
    HANDLE self, opened;
    BYTE *p;
    DWORD old;
    char err[16];
    BOOL r;

    self = NULL;
    arm();
    r = DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &self, 0, FALSE,
                        DUPLICATE_SAME_ACCESS);
    strcpy(err, le());
    line("DuplicateHandle of the current process's pseudo-handle: ret=%d err=%s, a real handle %s", r, err,
         yesno(self != NULL && self != GetCurrentProcess()));
    opened = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE,
                         GetCurrentProcessId());
    line("OpenProcess, this program's own id: opened %s", yesno(opened != NULL));
    p = (BYTE *)VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS);
    VirtualAlloc(p, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    pattern(p, 0x2000);

    line("8 KiB committed at the start of a 64 KiB reservation, the rest reserved:");
    self_copy(0, "  ReadProcessMemory, the duplicated handle, 8 KiB", self, p, buf, 0x2000);
    line("    the bytes: %s", yesno(memcmp(buf, p, 0x2000) == 0));
    self_copy(0, "  12 KiB, across into the reserved page", self, p, buf, 0x3000);
    self_copy(0, "  4 KiB from 2 KiB before the reserved page", self, p + 0x1800, buf, 0x1000);
    self_copy(0, "  16 bytes from 8 bytes before it", self, p + 0x1FF8, buf, 16);
    self_copy(0, "  4 KiB, all reserved", self, p + 0x2000, buf, 0x1000);
    self_copy(0, "  12 KiB through OpenProcess's handle", opened, p, buf, 0x3000);
    self_copy(0, "  12 KiB through the pseudo-handle", GetCurrentProcess(), p, buf, 0x3000);
    self_copy(0, "  4 KiB into a buffer crossing into the reserved page", self, buf, p + 0x1800, 0x1000);
    line("    the buffer's committed part filled: %s", yesno(memcmp(p + 0x1800, buf, 0x800) == 0));

    pattern(p, 0x2000);
    memset(buf, 0x5A, 0x3000);
    self_copy(1, "  WriteProcessMemory, 12 KiB across into the reserved page", self, p, buf, 0x3000);
    line("    bytes written from the start: 0x%lX", run_of(p, 0x2000, 0x5A));
    pattern(p, 0x2000);
    self_copy(1, "  16 bytes from 8 bytes before the reserved page", self, p + 0x1FF8, buf, 16);
    line("    bytes written: 0x%lX", run_of(p + 0x1FF8, 8, 0x5A));
    pattern(p, 0x2000);
    VirtualProtect(p + 0x1000, 0x1000, PAGE_READONLY, &old);
    self_copy(1, "  4 KiB into the second page, now read-only", self, p + 0x1000, buf, 0x1000);
    VirtualQuery(p + 0x1000, &mbi, sizeof mbi);
    line("    its protection after: 0x%lX, bytes written: 0x%lX", mbi.Protect, run_of(p + 0x1000, 0x1000, 0x5A));
    VirtualProtect(p + 0x1000, 0x1000, PAGE_READWRITE, &old);
    pattern(p, 0x2000);
    VirtualProtect(p + 0x1000, 0x1000, PAGE_READONLY, &old);
    self_copy(1, "  8 KiB over both pages, the second read-only", self, p, buf, 0x2000);
    line("    bytes written from the start: 0x%lX", run_of(p, 0x2000, 0x5A));

    VirtualFree(p, 0, MEM_RELEASE);
    if (opened != NULL) {
        CloseHandle(opened);
    }
    if (self != NULL) {
        CloseHandle(self);
    }
}

/* --- crtfds -------------------------------------------------------- */

static void sec_crtfds(void)
{
    int a, b, c, r;

    reset();
    make_file(at("SCRATCH\\a.txt"), "first\r\n");
    make_file(at("SCRATCH\\b.txt"), "second\r\n");
    a = _open(at("SCRATCH\\a.txt"), _O_RDONLY | _O_BINARY);
    b = _open(at("SCRATCH\\b.txt"), _O_RDONLY | _O_NOINHERIT);
    c = _open(at("SCRATCH\\c.txt"), _O_WRONLY | _O_CREAT | _O_APPEND | _O_TEXT, _S_IREAD | _S_IWRITE);
    line("_open: a.txt read binary %d, b.txt read _O_NOINHERIT %d, c.txt write append text %d", a, b, c);
    line("_spawnl(_P_WAIT), spawnkid crtinfo:");
    r = _spawnl(_P_WAIT, kid, "spawnkid", "crtinfo", NULL);
    line("  ret %d", r);
    if (b >= 0) {
        _close(b);
    }
    line("b.txt closed, _spawnl(_P_WAIT), spawnkid crtinfo:");
    r = _spawnl(_P_WAIT, kid, "spawnkid", "crtinfo", NULL);
    line("  ret %d", r);
    if (a >= 0) {
        _close(a);
    }
    if (c >= 0) {
        _close(c);
    }
    create(0, "no C runtime block, spawnkid crtinfo", kid, "spawnkid crtinfo");
}

/* --- inheritflags -------------------------------------------------- */

static const char *flags_of(HANDLE h)
{
    static char bufs[4][32];
    static int next;
    char *b = bufs[next++ & 3];
    DWORD flags = F2KT_UNTOUCHED;

    arm();
    if (GetHandleInformation(h, &flags)) {
        sprintf(b, "flags 0x%lX", flags);
    } else {
        sprintf(b, "ret=0 err=%s", le());
    }
    return b;
}

static HANDLE open_console(BOOL inheritable)
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = inheritable;
    return CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                       OPEN_EXISTING, 0, NULL);
}

static void sec_inheritflags(void)
{
    HANDLE plain, guarded, con_yes, con_no;
    char cmd[160];
    char err[16];
    BOOL r;

    reset();
    make_file(at("SCRATCH\\a.txt"), "a\r\n");
    plain = open_file("SCRATCH\\a.txt", GENERIC_READ, OPEN_EXISTING, TRUE);
    guarded = open_file("SCRATCH\\a.txt", GENERIC_READ, OPEN_EXISTING, TRUE);
    SetHandleInformation(guarded, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    con_yes = open_console(TRUE);
    con_no = open_console(FALSE);
    line("an inheritable file: %s; the same, protected from close: %s", flags_of(plain), flags_of(guarded));
    line("CONOUT$ opened inheritable: %s; not inheritable: %s", flags_of(con_yes), flags_of(con_no));
    arm();
    r = SetHandleInformation(con_no, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
    strcpy(err, le());
    line("SetHandleInformation(PROTECT_FROM_CLOSE), CONOUT$: ret=%d err=%s, %s", r, err, flags_of(con_no));
    SetHandleInformation(con_no, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    sprintf(cmd, "spawnkid flags %lu %lu %lu %lu", (DWORD)plain, (DWORD)guarded, (DWORD)con_yes,
            (DWORD)con_no);
    create_ex(0, "spawnkid flags, the four in that order", kid, cmd, TRUE, 0, NULL, NULL, NULL);
    create_ex(0, "the same, bInheritHandles FALSE", kid, cmd, FALSE, 0, NULL, NULL, NULL);
    SetHandleInformation(guarded, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    CloseHandle(plain);
    CloseHandle(guarded);
    CloseHandle(con_yes);
    CloseHandle(con_no);
}

/* --- binaryforms --------------------------------------------------- */

/* A file of `size` bytes, zero but for a DOS header: "MZ", e_lfarlc
 * (the relocation table's offset: 0x40 or more announces a new header)
 * and e_lfanew; at e_lfanew, when `sig` is given, its two bytes and, at
 * 0x36 past it, `target` (an NE header's target operating system). */
static void make_header(const char *rel, WORD lfarlc, DWORD lfanew, const char *sig, BYTE target, DWORD size)
{
    BYTE b[512];
    DWORD n;
    HANDLE f;

    memset(b, 0, sizeof b);
    b[0] = 'M';
    b[1] = 'Z';
    *(WORD *)(b + 0x18) = lfarlc;
    *(DWORD *)(b + 0x3C) = lfanew;
    if (sig != NULL && lfanew + 0x40 <= sizeof b) {
        b[lfanew] = sig[0];
        b[lfanew + 1] = sig[1];
        b[lfanew + 0x36] = target;
    }
    f = CreateFileA(at(rel), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        line("setup: %s not created, err=%lu", rel, GetLastError());
        return;
    }
    WriteFile(f, b, size, &n, NULL);
    CloseHandle(f);
}

static void sec_binaryforms(void)
{
    reset();
    make_header("SCRATCH\\dos.exe", 0x1C, 0, NULL, 0, 512);
    make_header("SCRATCH\\dosfar.exe", 0x40, 0x400, NULL, 0, 512);
    make_header("SCRATCH\\win16.exe", 0x40, 0x80, "NE", 2, 512);
    make_header("SCRATCH\\os2.exe", 0x40, 0x80, "NE", 1, 512);
    make_header("SCRATCH\\netarget0.exe", 0x40, 0x80, "NE", 0, 512);
    make_header("SCRATCH\\le.exe", 0x40, 0x80, "LE", 0, 512);
    make_header("SCRATCH\\pecut.exe", 0x40, 0x80, "PE", 0, 512);
    make_header("SCRATCH\\mzonly.exe", 0x40, 0, NULL, 0, 64);
    make_header("SCRATCH\\dos.txt", 0x1C, 0, NULL, 0, 512);
    make_file(at("SCRATCH\\text.com"), "not a program\r\n");
    make_file(at("SCRATCH\\text.pif"), "not a program\r\n");
    make_file(at("SCRATCH\\text"), "not a program\r\n");

    binary_both("an MZ header, e_lfarlc 0x1C (a DOS program)", "SCRATCH\\dos.exe");
    binary_both("e_lfarlc 0x40, e_lfanew past the file's end", "SCRATCH\\dosfar.exe");
    binary_both("an NE header, target 2 (Windows)", "SCRATCH\\win16.exe");
    binary_both("an NE header, target 1 (OS/2)", "SCRATCH\\os2.exe");
    binary_both("an NE header, target 0 (unknown)", "SCRATCH\\netarget0.exe");
    binary_both("an LE header", "SCRATCH\\le.exe");
    binary_both("a PE signature, nothing after it", "SCRATCH\\pecut.exe");
    binary_both("an MZ header alone, 64 bytes, e_lfanew 0", "SCRATCH\\mzonly.exe");
    binary_both("a DOS program named .txt", "SCRATCH\\dos.txt");
    binary_both("a text file named .com", "SCRATCH\\text.com");
    binary_both("a text file named .pif", "SCRATCH\\text.pif");
    binary_both("a text file with no extension", "SCRATCH\\text");
}

/* --- twice -------------------------------------------------------- */

/* One CPU for the process and its children, the calling thread above
 * them: a child it terminates or starts runs only once it waits. */
static DWORD pinned_from;

static void pin(void)
{
    DWORD process_mask = 1, system_mask = 1;

    GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask);
    pinned_from = process_mask;
    SetProcessAffinityMask(GetCurrentProcess(), 1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

static void unpin(void)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    SetProcessAffinityMask(GetCurrentProcess(), pinned_from);
}

static void sec_twice(void)
{
    PROCESS_INFORMATION pi;
    DWORD code, w;
    BOOL r;

    reset();
    pin();
    if (!launch(0, kid, "spawnkid sleep 60000", TRUE, CREATE_SUSPENDED, NULL, NULL, NULL, &pi)) {
        line("spawnkid sleep: not started, err=%s", le());
        unpin();
        return;
    }
    SetProcessAffinityMask(pi.hProcess, 1);
    arm();
    r = TerminateProcess(pi.hProcess, 11);
    line("TerminateProcess(11) ret=%d err=%s", r, le());
    arm();
    r = TerminateProcess(pi.hProcess, 22);
    line("TerminateProcess(22) at once ret=%d err=%s", r, le());
    unpin();
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    code = 0;
    arm();
    r = GetExitCodeProcess(pi.hProcess, &code);
    line("its end: %s; GetExitCodeProcess ret=%d code=%s err=%s", wr(w), r, code_text(code), le());
    arm();
    r = TerminateProcess(pi.hProcess, 33);
    line("TerminateProcess(33) after its end ret=%d err=%s", r, le());
    code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    line("exit code then: %s", code_text(code));
    code = 0;
    GetExitCodeThread(pi.hThread, &code);
    line("its thread's exit code: %s", code_text(code));
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

/* --- lastcode ----------------------------------------------------- */

static void last_code(const char *mode)
{
    PROCESS_INFORMATION pi;
    char cmd[64];
    DWORD code, w;

    sprintf(cmd, "spawnkid %s", mode);
    if (!launch(0, kid, cmd, TRUE, 0, NULL, NULL, NULL, &pi)) {
        line("%s: not started, err=%s", mode, le());
        return;
    }
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    code = 0;
    GetExitCodeThread(pi.hThread, &code);
    line("%s: its end %s; its main thread's exit code %s", mode, wr(w), code_text(code));
    code = finish(&pi, NULL);
    line("%s: the process's exit code %s", mode, code_text(code));
}

static void sec_lastcode(void)
{
    reset();
    last_code("lastthread");
    last_code("handoff");
}

/* --- termrace ----------------------------------------------------- */

/* The distinct error codes a racing call answered, printed sorted. */
typedef struct {
    DWORD codes[8];
    int count;
} errors_t;

static void note_error(errors_t *e, DWORD code)
{
    int i;

    for (i = 0; i < e->count; i++) {
        if (e->codes[i] == code) {
            return;
        }
    }
    if (e->count < 8) {
        e->codes[e->count++] = code;
    }
}

static const char *errors_text(errors_t *e)
{
    static char buf[160];
    DWORD t;
    int i, j, n = 0;

    for (i = 0; i < e->count; i++) {
        for (j = i + 1; j < e->count; j++) {
            if (e->codes[j] < e->codes[i]) {
                t = e->codes[i];
                e->codes[i] = e->codes[j];
                e->codes[j] = t;
            }
        }
    }
    buf[0] = 0;
    for (i = 0; i < e->count; i++) {
        n += sprintf(buf + n, "%s%s", i > 0 ? " " : "", le_of(e->codes[i]));
    }
    return e->count > 0 ? buf : "none";
}

static HANDLE race_go;
static HANDLE race_thread_handle;
static BOOL race_thread_ok;
static DWORD race_thread_err;

static DWORD WINAPI race_terminate_thread(LPVOID parameter)
{
    (void)parameter;
    WaitForSingleObject(race_go, WAIT_MS);
    SetLastError(F2KT_UNTOUCHED);
    race_thread_ok = TerminateThread(race_thread_handle, 22);
    race_thread_err = GetLastError();
    return 0;
}

static void sec_termrace(void)
{
    PROCESS_INFORMATION pi;
    HANDLE t;
    DWORD id, code, err;
    BOOL r;
    errors_t process_errors, thread_errors;
    int i, ended = 0, codes = 0, process_ok = 0, thread_ok = 0;

    memset(&process_errors, 0, sizeof process_errors);
    memset(&thread_errors, 0, sizeof thread_errors);

    reset();
    for (i = 0; i < 20; i++) {
        if (!launch(0, kid, "spawnkid sleep 60000", TRUE, 0, NULL, NULL, NULL, &pi)) {
            line("spawnkid sleep: not started, err=%s", le());
            return;
        }
        Sleep(20);
        race_thread_handle = pi.hThread;
        race_go = CreateEventA(NULL, TRUE, FALSE, NULL);
        t = CreateThread(NULL, 0, race_terminate_thread, NULL, 0, &id);
        SetEvent(race_go);
        SetLastError(F2KT_UNTOUCHED);
        r = TerminateProcess(pi.hProcess, 11);
        err = GetLastError();
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
        CloseHandle(race_go);
        if (WaitForSingleObject(pi.hProcess, WAIT_MS) == WAIT_OBJECT_0) {
            ended++;
        }
        code = finish(&pi, NULL);
        if (code == 11 || code == 22) {
            codes++;
        }
        process_ok += r != 0;
        thread_ok += race_thread_ok != 0;
        if (!r) {
            note_error(&process_errors, err);
        }
        if (!race_thread_ok) {
            note_error(&thread_errors, race_thread_err);
        }
    }
    line("children ended: %d of 20", ended);
    line("exit codes 11 or 22: %d of 20", codes);
    line("TerminateProcess's refusals: %s", errors_text(&process_errors));
    line("TerminateThread's refusals: %s", errors_text(&thread_errors));
    line("TerminateProcess succeeded at least once: %s", yesno(process_ok > 0));
    line("TerminateThread succeeded at least once: %s", yesno(thread_ok > 0));
}

/* --- remoteexit --------------------------------------------------- */

static void sec_remoteexit(void)
{
    PROCESS_INFORMATION pi;
    LPTHREAD_START_ROUTINE exit_thread;
    HANDLE t;
    DWORD id, err, w;
    errors_t refusals;
    int made = 0, tries = 0;

    memset(&refusals, 0, sizeof refusals);

    reset();
    /* kernel32 sits at the same address in every process. */
    exit_thread = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                                          "ExitThread");
    if (!launch(0, kid, "spawnkid later 50 3", TRUE, 0, NULL, NULL, NULL, &pi)) {
        line("spawnkid later: not started, err=%s", le());
        return;
    }
    while (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT && tries < 100000) {
        tries++;
        SetLastError(F2KT_UNTOUCHED);
        t = CreateRemoteThread(pi.hProcess, NULL, 0, exit_thread, NULL, 0, &id);
        err = GetLastError();
        if (t != NULL) {
            made++;
            WaitForSingleObject(t, WAIT_MS);
            CloseHandle(t);
        } else {
            note_error(&refusals, err);
        }
    }
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    line("the child's end: %s", wr(w));
    line("threads made in it while it ran: %s", yesno(made > 0));
    line("its refusals while it exited: %s", errors_text(&refusals));
    arm();
    t = CreateRemoteThread(pi.hProcess, NULL, 0, exit_thread, NULL, 0, &id);
    line("CreateRemoteThread after its end: %s err=%s", t != NULL ? "made" : "NULL", le());
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    line("its exit code: %s", code_text(finish(&pi, NULL)));
}

/* --- nothread ----------------------------------------------------- */

typedef LONG (WINAPI *create_process_fn)(HANDLE *, ACCESS_MASK, void *, HANDLE, BOOLEAN, HANDLE,
                                          HANDLE, HANDLE);

static void sec_nothread(void)
{
    typedef LONG (WINAPI *create_section_fn)(HANDLE *, ACCESS_MASK, void *, LARGE_INTEGER *, ULONG,
                                             ULONG, HANDLE);
    create_process_fn create_process;
    create_section_fn create_section;
    HANDLE file, section, process;
    DWORD code, w;
    LONG status;
    BOOL r;

    reset();
    create_process =
        (create_process_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcess");
    create_section =
        (create_section_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    file = CreateFileA(kid, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       0, NULL);
    /* CreateFileMapping takes no execute protection on Windows 2000. */
    arm();
    section = CreateFileMappingA(file, NULL, PAGE_EXECUTE_READ | SEC_IMAGE, 0, 0, NULL);
    line("CreateFileMappingA(PAGE_EXECUTE_READ | SEC_IMAGE): %s err=%s",
         section != NULL ? "made" : "NULL", le());
    if (section != NULL) {
        CloseHandle(section);
    }
    /* The section NtCreateProcess maps: execute access, through ntdll. */
    section = NULL;
    status = create_section(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE,
                            file);
    line("NtCreateSection(SEC_IMAGE, PAGE_EXECUTE) status=0x%08lX", (unsigned long)status);
    CloseHandle(file);
    if (status < 0) {
        return;
    }

    process = NULL;
    status = create_process(&process, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), FALSE,
                            section, NULL, NULL);
    line("NtCreateProcess status=0x%08lX", (unsigned long)status);
    if (status >= 0) {
        w = WaitForSingleObject(process, 0);
        code = 0;
        arm();
        r = GetExitCodeProcess(process, &code);
        line("  WaitForSingleObject(0) %s; GetExitCodeProcess ret=%d code=%s err=%s", wr(w), r,
             code_text(code), le());
        arm();
        r = CloseHandle(process);
        line("  CloseHandle ret=%d err=%s", r, le());
    }

    process = NULL;
    status = create_process(&process, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), FALSE,
                            section, NULL, NULL);
    line("NtCreateProcess again status=0x%08lX", (unsigned long)status);
    if (status >= 0) {
        arm();
        r = TerminateProcess(process, 7);
        line("  TerminateProcess(7) ret=%d err=%s", r, le());
        w = WaitForSingleObject(process, WAIT_MS);
        code = 0;
        arm();
        r = GetExitCodeProcess(process, &code);
        line("  its end: %s; GetExitCodeProcess ret=%d code=%s err=%s", wr(w), r, code_text(code),
             le());
        arm();
        r = CloseHandle(process);
        line("  CloseHandle ret=%d err=%s", r, le());
    }
    CloseHandle(section);
    line("the program runs on: yes");
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
    { "ended", sec_ended, F2KT_ALWAYS },
    { "unstarted", sec_unstarted, F2KT_ALWAYS },
    { "dupclose", sec_dupclose, F2KT_ALWAYS },
    { "remote", sec_remote, F2KT_ALWAYS },
    { "selfmem", sec_selfmem, F2KT_ALWAYS },
    { "crtfds", sec_crtfds, F2KT_ALWAYS },
    { "inheritflags", sec_inheritflags, F2KT_ALWAYS },
    { "binaryforms", sec_binaryforms, F2KT_ALWAYS },
    { "twice", sec_twice, F2KT_ALWAYS },
    { "lastcode", sec_lastcode, F2KT_ALWAYS },
    { "termrace", sec_termrace, F2KT_ALWAYS },
    { "remoteexit", sec_remoteexit, F2KT_ALWAYS },
    { "nothread", sec_nothread, F2KT_ALWAYS },
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
