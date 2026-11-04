/*
 * toolhelp - the ToolHelp snapshot: CreateToolhelp32Snapshot,
 * Process32First/Next and their W forms, Thread32First/Next, over the
 * program's own processes and threads, the idle and System processes,
 * the calls' errors, and the snapshot handle itself; and ntdll's
 * NtQuerySystemInformation(SystemProcessInformation) beneath them.
 *
 * The real machine runs other processes (services, Explorer) that vary
 * from boot to boot, and F2K runs none of them, so nothing printed
 * depends on them: only the program's own processes and threads print,
 * found by their ids, never the whole list. No process id, thread id or
 * handle value prints: a parent prints as a relation ("its parent is
 * this program: yes"), the idle and System processes' thread counts as
 * relations (as many as the processors, more than one), and the System
 * process's id as relations (nonzero, a multiple of 4, the lowest after
 * 0). A name prints upper-cased, its final component alone, with
 * whether the snapshot gave the name alone or a path, so no directory
 * shows.
 *
 * The children are thkid.exe, the companion program built beside this
 * one, which prints nothing (thkid.c lists its modes); they wait on
 * named events this program sets, so each snapshot finds them where the
 * section expects. Every wait is bounded at 5 s; a child that outlives
 * one is ended. A process or thread that ended and whose handles are
 * closed may stay listed a moment while the system drops its last
 * references (the Win32 server keeps handles of its own), so its
 * disappearance prints as a verdict over 2 s of snapshots.
 *
 * The layout section prints the sizes and field offsets of the
 * structures this program uses. PROCESSENTRY32 and THREADENTRY32 come
 * from MSVC 6's tlhelp32.h. PROCESSENTRY32W, and the W functions, are
 * declared here and reached through GetProcAddress, as MSVC 6's
 * tlhelp32.h and kernel32.lib may predate them (Windows 2000's kernel32
 * added them); the declaration follows the Platform SDK's. MSVC 6's
 * headers have no SYSTEM_PROCESS_INFORMATION or SYSTEM_THREAD_INFORMATION
 * at all: they are declared here from public documentation (Nebbett's
 * Windows NT/2000 Native API Reference, MSDN's partial winternl.h
 * declaration), so their sizes and offsets print what this program
 * declares, pinning the layout F2K must give, and the lines after them
 * read the real chain through those declarations (this program's own
 * entry, found by its id, and its thread): those, and the errors
 * section's too-small-buffer line, are the real check.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   layout   sizeof and field offsets of PROCESSENTRY32, PROCESSENTRY32W
 *            and THREADENTRY32, SYSTEM_PROCESS_INFORMATION and
 *            SYSTEM_THREAD_INFORMATION; the chain NtQuerySystemInformation
 *            gives read through them: every entry and its threads inside
 *            the buffer, every NextEntryOffset a multiple of 8, every
 *            thread's ClientId naming its entry's process, every
 *            ImageName inside the buffer; this program's entry (its
 *            thread count, ImageName, BasePriority, SessionId, parent, VM
 *            counters' peaks) and its thread (ClientId, priorities,
 *            state)
 *   self     a process snapshot: the walk's returns and errors; this
 *            program's entry: szExeFile (the name alone or a path, and
 *            the name), cntThreads 1, pcPriClassBase, its parent as a
 *            relation, cntUsage, th32ModuleID, th32DefaultHeapID (zero
 *            or not), dwFlags; the same through Process32FirstW/NextW;
 *            after CreateThread, cntThreads 2 and the Thread32 walk: both
 *            threads, their tpBasePri, the new (waiting) thread's
 *            tpDeltaPri; after SetThreadPriority(THREAD_PRIORITY_HIGHEST)
 *            and SetPriorityClass(HIGH_PRIORITY_CLASS), the priorities
 *            the snapshot gives; once the thread has ended and its handle
 *            is closed, cntThreads back to 1
 *   child    a child holding (thkid hold, with one more thread): listed,
 *            its name, this program its parent, its threads; once it has
 *            ended, while its handles are open (listed, its threads), and
 *            once they are closed (gone); a child created suspended and
 *            terminated; a child that starts a grandchild and ends: the
 *            grandchild's parent is the ended child, which stays listed
 *            while this program holds its handle
 *   system   the entries for PID 0 and the System process: their names,
 *            parents, pcPriClassBase, thread counts as relations, the
 *            idle threads' ids and tpBasePri; every PID a multiple of 4
 *            and distinct; every thread owned by a listed process, as
 *            many as the cntThreads summed; NtQuerySystemInformation's
 *            view of the same two (the idle process's empty ImageName)
 *   errors   Process32Next on a fresh snapshot; Process32First again
 *            (rewinding); Process32First, Process32FirstW and Thread32First
 *            with a wrong dwSize; Process32Next and Thread32Next past the
 *            end, twice; Thread32First on a process snapshot and
 *            Process32First on a thread snapshot; a snapshot of nothing
 *            (flags 0); TH32CS_SNAPPROCESS of a PID no process has;
 *            TH32CS_SNAPMODULE of 0 (this process) and of a PID no
 *            process has; Process32First and Thread32First on an event,
 *            on NULL and on INVALID_HANDLE_VALUE (a failed snapshot's);
 *            NtQuerySystemInformation(SystemProcessInformation) into 16
 *            bytes and into none: its status, and the length it reports
 *            as a relation to the buffer's
 *   handle   the snapshot handle: its object type (NtQueryObject's
 *            ObjectTypeInformation), its basic information (attributes,
 *            granted access, handle count), GetHandleInformation, with
 *            and without TH32CS_INHERIT; CloseHandle, twice;
 *            Process32First on the closed handle
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat toolhelp):
 *   cl /nologo /MD thkid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% toolhelp.c
 */

#include "../common/f2kt.h"
#include <tlhelp32.h>
#include <ctype.h>

#ifndef TH32CS_SNAPHEAPLIST
#define TH32CS_SNAPHEAPLIST 0x00000001
#endif
#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif
#ifndef TH32CS_SNAPTHREAD
#define TH32CS_SNAPTHREAD 0x00000004
#endif
#ifndef TH32CS_SNAPMODULE
#define TH32CS_SNAPMODULE 0x00000008
#endif
#ifndef TH32CS_INHERIT
#define TH32CS_INHERIT 0x80000000
#endif

/* --- what MSVC 6's headers lack ------------------------------------ */

/* PROCESSENTRY32W (the Platform SDK's tlhelp32.h): PROCESSENTRY32 with a
 * wide szExeFile. */
typedef struct {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    DWORD th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    WCHAR szExeFile[MAX_PATH];
} proc_entry_w_t;

/* Process32FirstW and Process32NextW (hSnapshot, lppe). */
typedef BOOL (WINAPI *process_w_fn)(HANDLE, proc_entry_w_t *);

/* UNICODE_STRING (winternl.h). */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} ustring_t;

/* CLIENT_ID (winternl.h): the process's id, then the thread's. */
typedef struct {
    ULONG UniqueProcess;
    ULONG UniqueThread;
} client_id_t;

/* SYSTEM_THREAD_INFORMATION (Nebbett's SYSTEM_THREADS; MSDN's partial
 * declaration names the same places): 0x40 bytes, the last 4 the
 * structure's padding to its 8-byte alignment. */
typedef struct {
    LARGE_INTEGER KernelTime;           /* 0x00 */
    LARGE_INTEGER UserTime;             /* 0x08 */
    LARGE_INTEGER CreateTime;           /* 0x10 */
    ULONG WaitTime;                     /* 0x18 */
    PVOID StartAddress;                 /* 0x1C */
    client_id_t ClientId;               /* 0x20 */
    LONG Priority;                      /* 0x28: KPRIORITY */
    LONG BasePriority;                  /* 0x2C */
    ULONG ContextSwitches;              /* 0x30 */
    ULONG ThreadState;                  /* 0x34: 2 is Running */
    ULONG WaitReason;                   /* 0x38 */
} sys_thread_t;

/* SYSTEM_PROCESS_INFORMATION, NtQuerySystemInformation's class 5
 * (Nebbett's SYSTEM_PROCESSES for Windows 2000; MSDN's winternl.h names
 * SessionId and the VM counters): each entry followed by its threads'
 * SYSTEM_THREAD_INFORMATION, the next entry NextEntryOffset bytes on (0
 * for the last). Nebbett's six reserved words at 0x08 (MSDN's
 * Reserved1, with the three times), and the word at 0x54 (MSDN's
 * Reserved3), are declared under the names they carry later. Windows
 * 2000's VM_COUNTERS ends at PeakPagefileUsage; the word at 0x84 is
 * where the I/O counters' 8-byte alignment puts them, which MSDN's
 * declaration names PrivatePageCount. */
typedef struct {
    ULONG NextEntryOffset;              /* 0x00 */
    ULONG NumberOfThreads;              /* 0x04 */
    ULONG Reserved1[6];                 /* 0x08 */
    LARGE_INTEGER CreateTime;           /* 0x20 */
    LARGE_INTEGER UserTime;             /* 0x28 */
    LARGE_INTEGER KernelTime;           /* 0x30 */
    ustring_t ImageName;                /* 0x38 */
    LONG BasePriority;                  /* 0x40: KPRIORITY */
    ULONG UniqueProcessId;              /* 0x44 */
    ULONG InheritedFromUniqueProcessId; /* 0x48 */
    ULONG HandleCount;                  /* 0x4C */
    ULONG SessionId;                    /* 0x50 */
    ULONG PageDirectoryBase;            /* 0x54 */
    ULONG PeakVirtualSize;              /* 0x58: VM_COUNTERS */
    ULONG VirtualSize;                  /* 0x5C */
    ULONG PageFaultCount;               /* 0x60 */
    ULONG PeakWorkingSetSize;           /* 0x64 */
    ULONG WorkingSetSize;               /* 0x68 */
    ULONG QuotaPeakPagedPoolUsage;      /* 0x6C */
    ULONG QuotaPagedPoolUsage;          /* 0x70 */
    ULONG QuotaPeakNonPagedPoolUsage;   /* 0x74 */
    ULONG QuotaNonPagedPoolUsage;       /* 0x78 */
    ULONG PagefileUsage;                /* 0x7C */
    ULONG PeakPagefileUsage;            /* 0x80 */
    ULONG PrivatePageCount;             /* 0x84 */
    LARGE_INTEGER ReadOperationCount;   /* 0x88: IO_COUNTERS */
    LARGE_INTEGER WriteOperationCount;  /* 0x90 */
    LARGE_INTEGER OtherOperationCount;  /* 0x98 */
    LARGE_INTEGER ReadTransferCount;    /* 0xA0 */
    LARGE_INTEGER WriteTransferCount;   /* 0xA8 */
    LARGE_INTEGER OtherTransferCount;   /* 0xB0 */
} sys_process_t;                        /* 0xB8: the threads follow */

#define SYSTEM_PROCESS_INFO 5           /* SystemProcessInformation */
#define INFO_LENGTH_MISMATCH ((LONG)0xC0000004)

/* PUBLIC_OBJECT_BASIC_INFORMATION (winternl.h), NtQueryObject's class 0
 * (ObjectBasicInformation): 56 bytes. */
typedef struct {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} object_basic_t;

#define OBJECT_BASIC 0                  /* ObjectBasicInformation */
#define OBJECT_TYPE 2                   /* ObjectTypeInformation: a UNICODE_STRING first */

/* NtQuerySystemInformation(SystemInformationClass, SystemInformation,
 * SystemInformationLength, ReturnLength). */
typedef LONG (WINAPI *query_system_fn)(ULONG, PVOID, ULONG, PULONG);
/* NtQueryObject(Handle, ObjectInformationClass, ObjectInformation,
 * ObjectInformationLength, ReturnLength). */
typedef LONG (WINAPI *query_object_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static query_system_fn query_system;    /* NtQuerySystemInformation */
static query_object_fn query_object;    /* NtQueryObject */
static process_w_fn process_first_w;    /* Process32FirstW */
static process_w_fn process_next_w;     /* Process32NextW */

static char kid[MAX_PATH];              /* the program's directory\thkid.exe */
static DWORD self_pid;

/* The events thkid's hold mode waits on. */
#define READY "F2KT-TOOLHELP-READY"
#define GO "F2KT-TOOLHELP-GO"

/* A PID no process has: real ids are multiples of 4. */
#define NO_PID 3

/* --- helpers ------------------------------------------------------- */

/* The upper-cased final path component of `path`, into `out`. */
static const char *basename_upper(const char *path, char *out, int size)
{
    const char *b = path;
    const char *p;
    int n = 0;

    for (p = path; *p != 0; p++) {
        if (*p == '\\' || *p == '/' || *p == ':') {
            b = p + 1;
        }
    }
    while (*b != 0 && n < size - 1) {
        out[n++] = (char)toupper((unsigned char)*b++);
    }
    out[n] = 0;
    return out;
}

/* The same for a wide path, its first `count` units (to its terminator
 * for a negative count), printed as ws() prints: a unit below 0x80
 * upper-cased, any other as <U+XXXX>. Rotates through two buffers. */
static const char *wbase_upper(const WCHAR *s, int count)
{
    static char bufs[2][1024];
    static int next;
    char *b = bufs[next++ & 1];
    int start = 0;
    int n = 0;
    int i;

    if (s == NULL) {
        return "(null)";
    }
    for (i = 0; count < 0 ? s[i] != 0 : i < count; i++) {
        if (s[i] == '\\' || s[i] == '/' || s[i] == ':') {
            start = i + 1;
        }
    }
    for (i = start; (count < 0 ? s[i] != 0 : i < count) && n < (int)sizeof bufs[0] - 9; i++) {
        if (s[i] < 0x80) {
            b[n++] = (char)toupper((int)s[i]);
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)s[i]);
        }
    }
    b[n] = 0;
    return b;
}

/* Whether a wide string's first `count` units hold a path separator. */
static int wpath(const WCHAR *s, int count)
{
    int i;

    for (i = 0; s != NULL && (count < 0 ? s[i] != 0 : i < count); i++) {
        if (s[i] == '\\' || s[i] == '/') {
            return 1;
        }
    }
    return 0;
}

/* A returned length against the buffer's, as a relation. */
static const char *len_rel(ULONG len, ULONG size)
{
    if (len == F2KT_UNTOUCHED) {
        return "untouched";
    }
    if (len == 0) {
        return "zero";
    }
    return len > size ? "larger than the buffer" : "within the buffer";
}

static int handle_ok(HANDLE h)
{
    return h != INVALID_HANDLE_VALUE && h != NULL;
}

/* --- snapshots, read whole ----------------------------------------- */

#define TH_MAX_PROCS 1024
#define TH_MAX_THREADS 8192

static PROCESSENTRY32 procs[TH_MAX_PROCS];
static int nprocs;
static THREADENTRY32 thr[TH_MAX_THREADS];
static int nthr;

/* How a walk went: the first call (Process32First or Thread32First), the
 * last error the first successful Next left (F2KT_UNTOUCHED when none
 * ran), and the call that ended the walk. */
typedef struct {
    BOOL first;
    DWORD first_err;
    DWORD next_err;
    BOOL end;
    DWORD end_err;
} walk_t;

static walk_t pwalk;
static walk_t twalk;
static DWORD take_err;                  /* CreateToolhelp32Snapshot's last error */

/* Take a snapshot with `flags` (of PID 0) and read its processes into
 * procs and, with TH32CS_SNAPTHREAD, its threads into thr, printing
 * nothing; the walks' results go in pwalk and twalk. Returns whether
 * the snapshot was made. */
static int take(DWORD flags)
{
    HANDLE snap;
    BOOL r;

    nprocs = 0;
    nthr = 0;
    memset(&pwalk, 0, sizeof pwalk);
    memset(&twalk, 0, sizeof twalk);
    pwalk.next_err = F2KT_UNTOUCHED;
    twalk.next_err = F2KT_UNTOUCHED;
    arm();
    snap = CreateToolhelp32Snapshot(flags, 0);
    take_err = GetLastError();
    if (!handle_ok(snap)) {
        return 0;
    }
    if (flags & TH32CS_SNAPPROCESS) {
        procs[0].dwSize = sizeof(PROCESSENTRY32);
        arm();
        r = Process32First(snap, &procs[0]);
        pwalk.first = r;
        pwalk.first_err = GetLastError();
        while (r && nprocs < TH_MAX_PROCS - 1) {
            nprocs++;
            procs[nprocs].dwSize = sizeof(PROCESSENTRY32);
            arm();
            r = Process32Next(snap, &procs[nprocs]);
            if (r && nprocs == 1) {
                pwalk.next_err = GetLastError();
            }
        }
        pwalk.end = r;
        pwalk.end_err = GetLastError();
    }
    if (flags & TH32CS_SNAPTHREAD) {
        thr[0].dwSize = sizeof(THREADENTRY32);
        arm();
        r = Thread32First(snap, &thr[0]);
        twalk.first = r;
        twalk.first_err = GetLastError();
        while (r && nthr < TH_MAX_THREADS - 1) {
            nthr++;
            thr[nthr].dwSize = sizeof(THREADENTRY32);
            arm();
            r = Thread32Next(snap, &thr[nthr]);
            if (r && nthr == 1) {
                twalk.next_err = GetLastError();
            }
        }
        twalk.end = r;
        twalk.end_err = GetLastError();
    }
    CloseHandle(snap);
    return 1;
}

/* The last snapshot's first entry for `pid`, or NULL. */
static PROCESSENTRY32 *proc_of(DWORD pid)
{
    int i;

    for (i = 0; i < nprocs; i++) {
        if (procs[i].th32ProcessID == pid) {
            return &procs[i];
        }
    }
    return NULL;
}

/* How many entries the last snapshot has for `pid`. */
static int times_listed(DWORD pid)
{
    int i, n = 0;

    for (i = 0; i < nprocs; i++) {
        if (procs[i].th32ProcessID == pid) {
            n++;
        }
    }
    return n;
}

/* The last snapshot's entry for thread `tid` owned by `pid`, or NULL. */
static THREADENTRY32 *thread_of(DWORD tid, DWORD pid)
{
    int i;

    for (i = 0; i < nthr; i++) {
        if (thr[i].th32ThreadID == tid && thr[i].th32OwnerProcessID == pid) {
            return &thr[i];
        }
    }
    return NULL;
}

/* How many thread entries the last snapshot has for process `pid`. */
static int threads_listed(DWORD pid)
{
    int i, n = 0;

    for (i = 0; i < nthr; i++) {
        if (thr[i].th32OwnerProcessID == pid) {
            n++;
        }
    }
    return n;
}

/* The last snapshot's entry for a child of this program's, by its id and
 * its parent (so a recycled id is not taken for it), or NULL. */
static PROCESSENTRY32 *kid_of(DWORD pid)
{
    int i;

    for (i = 0; i < nprocs; i++) {
        if (procs[i].th32ProcessID == pid && procs[i].th32ParentProcessID == self_pid) {
            return &procs[i];
        }
    }
    return NULL;
}

/* Whether this program's child `pid` is gone from the snapshots within
 * 2 s. */
static int kid_gone(DWORD pid)
{
    int i;

    for (i = 0; i < 40; i++) {
        if (take(TH32CS_SNAPPROCESS) && kid_of(pid) == NULL) {
            return 1;
        }
        Sleep(50);
    }
    return 0;
}

/* --- NtQuerySystemInformation's chain ------------------------------ */

static BYTE *chain;                     /* the buffer, VirtualAlloc's */
static ULONG chain_size;
static int chain_broken;                /* an entry would leave the buffer */

static void free_chain(void)
{
    if (chain != NULL) {
        VirtualFree(chain, 0, MEM_RELEASE);
    }
    chain = NULL;
    chain_size = 0;
}

/* The chain (SystemProcessInformation) into a buffer of 64 KiB, doubled
 * while it is too small, up to 16 MiB. Returns the call's status (-1
 * when there is no buffer). */
static LONG query_chain(void)
{
    ULONG size = 64 * 1024;
    ULONG len;
    LONG status = -1;

    free_chain();
    while (size <= 16 * 1024 * 1024) {
        chain = (BYTE *)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        if (chain == NULL) {
            return -1;
        }
        chain_size = size;
        len = 0;
        status = query_system(SYSTEM_PROCESS_INFO, chain, size, &len);
        if (status != INFO_LENGTH_MISMATCH) {
            return status;
        }
        free_chain();
        size *= 2;
    }
    return status;
}

/* The chain's entry after `p` (the first for NULL), or NULL at its end,
 * or where the entry or its threads would leave the buffer (then
 * chain_broken is set). */
static sys_process_t *chain_next(sys_process_t *p)
{
    ULONG at;
    sys_process_t *e;

    if (p == NULL) {
        chain_broken = 0;
        at = 0;
    } else if (p->NextEntryOffset == 0) {
        return NULL;
    } else {
        at = (ULONG)((BYTE *)p - chain) + p->NextEntryOffset;
    }
    if (at >= chain_size || chain_size - at < sizeof(sys_process_t)) {
        chain_broken = 1;
        return NULL;
    }
    e = (sys_process_t *)(chain + at);
    if (e->NumberOfThreads > (chain_size - at - sizeof(sys_process_t)) / sizeof(sys_thread_t)) {
        chain_broken = 1;
        return NULL;
    }
    return e;
}

/* The chain's entry for `pid`, or NULL. */
static sys_process_t *chain_entry(ULONG pid)
{
    sys_process_t *p;

    for (p = chain_next(NULL); p != NULL; p = chain_next(p)) {
        if (p->UniqueProcessId == pid) {
            return p;
        }
    }
    return NULL;
}

/* Whether an entry's ImageName is empty or inside the buffer. */
static int name_inside(const sys_process_t *p)
{
    const BYTE *b = (const BYTE *)p->ImageName.Buffer;

    if (p->ImageName.Length == 0) {
        return 1;
    }
    return b >= chain && b <= chain + chain_size && (ULONG)(chain + chain_size - b) >= p->ImageName.Length;
}

/* --- layout -------------------------------------------------------- */

#define SHOW_SIZE(type) line("sizeof(%s) %u", #type, (unsigned)sizeof(type))
#define SHOW_OFF(type, field) line("  %s at 0x%02lX", #field, (unsigned long)FIELD_OFFSET(type, field))

static void sec_layout(void)
{
    sys_process_t *p;
    sys_process_t *mine = NULL;
    sys_thread_t *t;
    sys_thread_t *me = NULL;
    LONG status;
    ULONG i;
    int entries = 0, aligned = 1, owners = 1, names = 1, parent_listed = 0, broken;

    line("tlhelp32.h (MSVC 6):");
    SHOW_SIZE(PROCESSENTRY32);
    SHOW_OFF(PROCESSENTRY32, dwSize);
    SHOW_OFF(PROCESSENTRY32, cntUsage);
    SHOW_OFF(PROCESSENTRY32, th32ProcessID);
    SHOW_OFF(PROCESSENTRY32, th32DefaultHeapID);
    SHOW_OFF(PROCESSENTRY32, th32ModuleID);
    SHOW_OFF(PROCESSENTRY32, cntThreads);
    SHOW_OFF(PROCESSENTRY32, th32ParentProcessID);
    SHOW_OFF(PROCESSENTRY32, pcPriClassBase);
    SHOW_OFF(PROCESSENTRY32, dwFlags);
    SHOW_OFF(PROCESSENTRY32, szExeFile);
    SHOW_SIZE(THREADENTRY32);
    SHOW_OFF(THREADENTRY32, dwSize);
    SHOW_OFF(THREADENTRY32, cntUsage);
    SHOW_OFF(THREADENTRY32, th32ThreadID);
    SHOW_OFF(THREADENTRY32, th32OwnerProcessID);
    SHOW_OFF(THREADENTRY32, tpBasePri);
    SHOW_OFF(THREADENTRY32, tpDeltaPri);
    SHOW_OFF(THREADENTRY32, dwFlags);

    line("declared here, PROCESSENTRY32W:");
    SHOW_SIZE(proc_entry_w_t);
    SHOW_OFF(proc_entry_w_t, szExeFile);

    line("declared here, SYSTEM_PROCESS_INFORMATION:");
    SHOW_SIZE(sys_process_t);
    SHOW_OFF(sys_process_t, NextEntryOffset);
    SHOW_OFF(sys_process_t, NumberOfThreads);
    SHOW_OFF(sys_process_t, Reserved1);
    SHOW_OFF(sys_process_t, CreateTime);
    SHOW_OFF(sys_process_t, UserTime);
    SHOW_OFF(sys_process_t, KernelTime);
    SHOW_OFF(sys_process_t, ImageName);
    SHOW_OFF(sys_process_t, ImageName.Buffer);
    SHOW_OFF(sys_process_t, BasePriority);
    SHOW_OFF(sys_process_t, UniqueProcessId);
    SHOW_OFF(sys_process_t, InheritedFromUniqueProcessId);
    SHOW_OFF(sys_process_t, HandleCount);
    SHOW_OFF(sys_process_t, SessionId);
    SHOW_OFF(sys_process_t, PageDirectoryBase);
    SHOW_OFF(sys_process_t, PeakVirtualSize);
    SHOW_OFF(sys_process_t, VirtualSize);
    SHOW_OFF(sys_process_t, PageFaultCount);
    SHOW_OFF(sys_process_t, PeakWorkingSetSize);
    SHOW_OFF(sys_process_t, WorkingSetSize);
    SHOW_OFF(sys_process_t, QuotaPeakPagedPoolUsage);
    SHOW_OFF(sys_process_t, QuotaPagedPoolUsage);
    SHOW_OFF(sys_process_t, QuotaPeakNonPagedPoolUsage);
    SHOW_OFF(sys_process_t, QuotaNonPagedPoolUsage);
    SHOW_OFF(sys_process_t, PagefileUsage);
    SHOW_OFF(sys_process_t, PeakPagefileUsage);
    SHOW_OFF(sys_process_t, PrivatePageCount);
    SHOW_OFF(sys_process_t, ReadOperationCount);
    SHOW_OFF(sys_process_t, WriteOperationCount);
    SHOW_OFF(sys_process_t, OtherOperationCount);
    SHOW_OFF(sys_process_t, ReadTransferCount);
    SHOW_OFF(sys_process_t, WriteTransferCount);
    SHOW_OFF(sys_process_t, OtherTransferCount);

    line("declared here, SYSTEM_THREAD_INFORMATION:");
    SHOW_SIZE(sys_thread_t);
    SHOW_OFF(sys_thread_t, KernelTime);
    SHOW_OFF(sys_thread_t, UserTime);
    SHOW_OFF(sys_thread_t, CreateTime);
    SHOW_OFF(sys_thread_t, WaitTime);
    SHOW_OFF(sys_thread_t, StartAddress);
    SHOW_OFF(sys_thread_t, ClientId.UniqueProcess);
    SHOW_OFF(sys_thread_t, ClientId.UniqueThread);
    SHOW_OFF(sys_thread_t, Priority);
    SHOW_OFF(sys_thread_t, BasePriority);
    SHOW_OFF(sys_thread_t, ContextSwitches);
    SHOW_OFF(sys_thread_t, ThreadState);
    SHOW_OFF(sys_thread_t, WaitReason);

    line("NtQuerySystemInformation(SystemProcessInformation), read through these declarations:");
    if (query_system == NULL) {
        line("  NtQuerySystemInformation not found");
        return;
    }
    status = query_chain();
    line("  status=0x%08lX", (unsigned long)status);
    if (status < 0) {
        free_chain();
        return;
    }
    for (p = chain_next(NULL); p != NULL; p = chain_next(p)) {
        entries++;
        if (p->NextEntryOffset % 8 != 0) {
            aligned = 0;
        }
        if (!name_inside(p)) {
            names = 0;
        }
        t = (sys_thread_t *)(p + 1);
        for (i = 0; i < p->NumberOfThreads; i++) {
            if (t[i].ClientId.UniqueProcess != p->UniqueProcessId) {
                owners = 0;
            }
        }
        if (p->UniqueProcessId == self_pid) {
            mine = p;
        }
    }
    broken = chain_broken;
    if (mine != NULL) {
        parent_listed = chain_entry(mine->InheritedFromUniqueProcessId) != NULL;
    }
    line("  every entry and its threads inside the buffer: %s; more than two entries: %s",
         yesno(!broken), yesno(entries > 2));
    line("  every NextEntryOffset a multiple of 8: %s; every thread's ClientId.UniqueProcess its entry's UniqueProcessId: %s; every ImageName inside the buffer or empty: %s",
         yesno(aligned), yesno(owners), yesno(names));
    line("  this program's entry: %s", mine != NULL ? "found" : "not found");
    if (mine == NULL) {
        free_chain();
        return;
    }
    line("  NumberOfThreads %lu, BasePriority %ld, SessionId %lu, HandleCount nonzero: %s",
         mine->NumberOfThreads, mine->BasePriority, mine->SessionId, yesno(mine->HandleCount != 0));
    line("  ImageName [%s], the name alone: %s, MaximumLength = Length + 2: %s",
         wbase_upper(mine->ImageName.Buffer, mine->ImageName.Length / 2),
         yesno(!wpath(mine->ImageName.Buffer, mine->ImageName.Length / 2)),
         yesno(mine->ImageName.MaximumLength == mine->ImageName.Length + 2));
    line("  InheritedFromUniqueProcessId: itself: %s, an entry of the chain: %s",
         yesno(mine->InheritedFromUniqueProcessId == self_pid), yesno(parent_listed));
    line("  the peaks at least the current values: virtual size %s, working set %s, pagefile usage %s",
         yesno(mine->PeakVirtualSize >= mine->VirtualSize),
         yesno(mine->PeakWorkingSetSize >= mine->WorkingSetSize),
         yesno(mine->PeakPagefileUsage >= mine->PagefileUsage));
    t = (sys_thread_t *)(mine + 1);
    for (i = 0; i < mine->NumberOfThreads; i++) {
        if (t[i].ClientId.UniqueThread == GetCurrentThreadId()) {
            me = &t[i];
        }
    }
    line("  this thread among its threads: %s", yesno(me != NULL));
    if (me != NULL) {
        line("  this thread: BasePriority %ld, Priority at least BasePriority: %s, ThreadState %lu",
             me->BasePriority, yesno(me->Priority >= me->BasePriority), me->ThreadState);
    }
    free_chain();
}

/* --- self ---------------------------------------------------------- */

static HANDLE waiter_event;

/* self's second thread: it waits until the section lets it end. */
static DWORD WINAPI waiter(LPVOID arg)
{
    (void)arg;
    WaitForSingleObject(waiter_event, WAIT_MS);
    return 0;
}

/* The tpBasePri of thread `tid` of this program in the last snapshot, or
 * -99 when it is not there. */
static LONG base_pri(DWORD tid)
{
    THREADENTRY32 *t = thread_of(tid, self_pid);

    return t != NULL ? t->tpBasePri : -99;
}

static void sec_self(void)
{
    PROCESSENTRY32 *me;
    PROCESSENTRY32 mine;
    proc_entry_w_t pw;
    proc_entry_w_t mine_w;
    THREADENTRY32 *t;
    HANDLE snap, th;
    DWORD tid, w;
    BOOL r, first;
    char base[MAX_PATH];
    char first_err[16];
    int found, ok, i;

    ok = take(TH32CS_SNAPPROCESS);
    line("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0): a handle: %s err=%s", yesno(ok), le_of(take_err));
    if (!ok) {
        return;
    }
    line("Process32First: ret=%d err=%s; Process32Next while it finds entries: err=%s; at the end: ret=%d err=%s",
         pwalk.first, le_of(pwalk.first_err), le_of(pwalk.next_err), pwalk.end, le_of(pwalk.end_err));
    line("more than two entries: %s", yesno(nprocs > 2));
    line("this program: listed %d time(s)", times_listed(self_pid));
    me = proc_of(self_pid);
    if (me == NULL) {
        return;
    }
    mine = *me;
    line("  szExeFile: the name alone: %s, [%s]", yesno(strchr(mine.szExeFile, '\\') == NULL),
         basename_upper(mine.szExeFile, base, sizeof base));
    line("  cntThreads %lu, pcPriClassBase %ld", mine.cntThreads, mine.pcPriClassBase);
    line("  th32ParentProcessID: itself: %s, listed: %s", yesno(mine.th32ParentProcessID == self_pid),
         yesno(proc_of(mine.th32ParentProcessID) != NULL));
    line("  cntUsage %lu, th32ModuleID %lu, th32DefaultHeapID zero: %s, dwFlags 0x%lX", mine.cntUsage,
         mine.th32ModuleID, yesno(mine.th32DefaultHeapID == 0), mine.dwFlags);

    line("Process32FirstW and Process32NextW, the same walk:");
    if (process_first_w == NULL || process_next_w == NULL) {
        line("  Process32FirstW or Process32NextW not found");
    } else {
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (handle_ok(snap)) {
            memset(&pw, 0, sizeof pw);
            memset(&mine_w, 0, sizeof mine_w);
            found = 0;
            pw.dwSize = sizeof pw;
            arm();
            r = process_first_w(snap, &pw);
            first = r;
            strcpy(first_err, le());
            while (r) {
                if (pw.th32ProcessID == self_pid) {
                    found++;
                    mine_w = pw;
                }
                pw.dwSize = sizeof pw;
                arm();
                r = process_next_w(snap, &pw);
            }
            line("  Process32FirstW: ret=%d err=%s; at the end: ret=%d err=%s", first, first_err, r, le());
            line("  this program: listed %d time(s)", found);
            if (found) {
                line("  szExeFile: the name alone: %s, [%s]", yesno(!wpath(mine_w.szExeFile, -1)),
                     wbase_upper(mine_w.szExeFile, -1));
                line("  the same as Process32First's: name %s, cntThreads %s, parent %s, pcPriClassBase %s",
                     yesno(strcmp(wbase_upper(mine_w.szExeFile, -1), base) == 0),
                     yesno(mine_w.cntThreads == mine.cntThreads),
                     yesno(mine_w.th32ParentProcessID == mine.th32ParentProcessID),
                     yesno(mine_w.pcPriClassBase == mine.pcPriClassBase));
            }
            CloseHandle(snap);
        } else {
            line("  no snapshot");
        }
    }

    line("a second thread, waiting:");
    waiter_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, waiter, NULL, 0, &tid);
    if (waiter_event == NULL || th == NULL) {
        line("  no thread");
        return;
    }
    ok = take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
    line("  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0): a handle: %s err=%s", yesno(ok),
         le_of(take_err));
    line("  Thread32First: ret=%d err=%s; Thread32Next while it finds entries: err=%s; at the end: ret=%d err=%s",
         twalk.first, le_of(twalk.first_err), le_of(twalk.next_err), twalk.end, le_of(twalk.end_err));
    me = proc_of(self_pid);
    if (me != NULL) {
        line("  cntThreads %lu; Thread32 entries for this program %d; this thread among them %s, the new one %s",
             me->cntThreads, threads_listed(self_pid), yesno(thread_of(GetCurrentThreadId(), self_pid) != NULL),
             yesno(thread_of(tid, self_pid) != NULL));
    }
    t = thread_of(GetCurrentThreadId(), self_pid);
    if (t != NULL) {
        line("  this thread: tpBasePri %ld, cntUsage %lu, dwFlags 0x%lX", t->tpBasePri, t->cntUsage, t->dwFlags);
    }
    t = thread_of(tid, self_pid);
    if (t != NULL) {
        line("  the new thread: tpBasePri %ld, tpDeltaPri %ld, cntUsage %lu, dwFlags 0x%lX", t->tpBasePri,
             t->tpDeltaPri, t->cntUsage, t->dwFlags);
    }

    arm();
    r = SetThreadPriority(th, THREAD_PRIORITY_HIGHEST);
    line("SetThreadPriority(the new thread, THREAD_PRIORITY_HIGHEST): ret=%d err=%s", r, le());
    take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
    t = thread_of(tid, self_pid);
    if (t != NULL) {
        line("  the new thread: tpBasePri %ld, tpDeltaPri %ld; this thread: tpBasePri %ld", t->tpBasePri,
             t->tpDeltaPri, base_pri(GetCurrentThreadId()));
    }
    arm();
    r = SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    line("SetPriorityClass(HIGH_PRIORITY_CLASS): ret=%d err=%s", r, le());
    take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
    me = proc_of(self_pid);
    if (me != NULL) {
        line("  pcPriClassBase %ld; tpBasePri: this thread %ld, the new thread %ld", me->pcPriClassBase,
             base_pri(GetCurrentThreadId()), base_pri(tid));
    }
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    SetThreadPriority(th, THREAD_PRIORITY_NORMAL);
    take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
    me = proc_of(self_pid);
    if (me != NULL) {
        line("back to NORMAL_PRIORITY_CLASS and THREAD_PRIORITY_NORMAL: pcPriClassBase %ld; tpBasePri: this thread %ld, the new thread %ld",
             me->pcPriClassBase, base_pri(GetCurrentThreadId()), base_pri(tid));
    }

    SetEvent(waiter_event);
    w = WaitForSingleObject(th, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        TerminateThread(th, 57005);
        WaitForSingleObject(th, WAIT_MS);
    }
    CloseHandle(th);
    CloseHandle(waiter_event);
    for (i = 0; i < 40; i++) {
        take(TH32CS_SNAPPROCESS);
        me = proc_of(self_pid);
        if (me != NULL && me->cntThreads == 1) {
            break;
        }
        Sleep(50);
    }
    line("the new thread ended (%s), its handle closed: cntThreads back to 1 within 2 s: %s", wr(w),
         yesno(i < 40));
}

/* --- child --------------------------------------------------------- */

/* Start thkid with `args`, printing CreateProcessA's result. */
static BOOL start_kid(const char *args, DWORD flags, PROCESS_INFORMATION *pi)
{
    char cmd[2 * MAX_PATH + 128];
    STARTUPINFOA si;
    BOOL r;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(pi, 0, sizeof *pi);
    sprintf(cmd, "\"%s\" %s", kid, args);
    arm();
    r = CreateProcessA(kid, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, pi);
    line("  CreateProcessA: ret=%d err=%s", r, le());
    return r;
}

/* What the last snapshot (processes and threads) holds of this program's
 * child `pid`, whose first thread is `tid`. */
static void show_kid(const char *label, DWORD pid, DWORD tid)
{
    PROCESSENTRY32 *p = proc_of(pid);
    char base[MAX_PATH];

    if (p == NULL) {
        line("  %s: listed: no", label);
        return;
    }
    line("  %s: listed: yes; [%s], the name alone: %s; its parent is this program: %s", label,
         basename_upper(p->szExeFile, base, sizeof base), yesno(strchr(p->szExeFile, '\\') == NULL),
         yesno(p->th32ParentProcessID == self_pid));
    line("  %s: cntThreads %lu, Thread32 entries for it %d, its first thread among them %s, pcPriClassBase %ld",
         label, p->cntThreads, threads_listed(pid), yesno(thread_of(tid, pid) != NULL), p->pcPriClassBase);
}

/* Wait for a child to end (ending it after 5 s), printing how it ended. */
static void reap(const char *label, HANDLE process)
{
    DWORD w, code = F2KT_UNTOUCHED;

    w = WaitForSingleObject(process, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(process, 57005);
        WaitForSingleObject(process, WAIT_MS);
    }
    GetExitCodeProcess(process, &code);
    line("  %s: %s, exit code %lu", label, wr(w), code);
}

static void sec_child(void)
{
    PROCESS_INFORMATION pi;
    PROCESSENTRY32 *g = NULL;
    HANDLE ready, go, gh = NULL;
    DWORD w, gpid = 0;
    BOOL r;
    char base[MAX_PATH];
    int i;

    ready = CreateEventA(NULL, TRUE, FALSE, READY);
    go = CreateEventA(NULL, TRUE, FALSE, GO);
    if (ready == NULL || go == NULL) {
        line("no events");
        return;
    }
    ResetEvent(ready);
    ResetEvent(go);

    line("a child holding, with one more thread (thkid hold):");
    if (start_kid("hold " READY " " GO " 1", 0, &pi)) {
        line("  ready: %s", wr(WaitForSingleObject(ready, WAIT_MS)));
        take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
        show_kid("running", pi.dwProcessId, pi.dwThreadId);
        SetEvent(go);
        reap("told to end", pi.hProcess);
        take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
        show_kid("ended, its handles open", pi.dwProcessId, pi.dwThreadId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        line("  its handles closed: gone within 2 s: %s", yesno(kid_gone(pi.dwProcessId)));
    }
    ResetEvent(ready);
    ResetEvent(go);

    line("a child created suspended, never resumed:");
    if (start_kid("hold " READY " " GO " 0", CREATE_SUSPENDED, &pi)) {
        take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
        show_kid("suspended", pi.dwProcessId, pi.dwThreadId);
        arm();
        r = TerminateProcess(pi.hProcess, 7);
        line("  TerminateProcess(7): ret=%d err=%s", r, le());
        reap("terminated", pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        line("  its handles closed: gone within 2 s: %s", yesno(kid_gone(pi.dwProcessId)));
    }

    line("a child that starts a grandchild and ends (thkid nest):");
    if (start_kid("nest " READY " " GO, 0, &pi)) {
        reap("the child ended", pi.hProcess);
        line("  the grandchild ready: %s", wr(WaitForSingleObject(ready, WAIT_MS)));
        take(TH32CS_SNAPPROCESS);
        for (i = 0; i < nprocs; i++) {
            if (procs[i].th32ParentProcessID == pi.dwProcessId && procs[i].th32ProcessID != pi.dwProcessId) {
                g = &procs[i];
                gpid = g->th32ProcessID;
            }
        }
        line("  a process whose parent is the ended child: %s", g != NULL ? "listed" : "not listed");
        if (g != NULL) {
            line("  it: [%s], cntThreads %lu", basename_upper(g->szExeFile, base, sizeof base), g->cntThreads);
        }
        line("  the ended child, its handles open: listed as this program's child: %s",
             yesno(kid_of(pi.dwProcessId) != NULL));
        if (gpid != 0) {
            arm();
            gh = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, gpid);
            line("  OpenProcess on the grandchild: a handle: %s err=%s", yesno(gh != NULL), le());
        }
        SetEvent(go);
        if (gh != NULL) {
            w = WaitForSingleObject(gh, WAIT_MS);
            if (w != WAIT_OBJECT_0) {
                TerminateProcess(gh, 57005);
                WaitForSingleObject(gh, WAIT_MS);
            }
            line("  the grandchild, told to end: %s", wr(w));
            CloseHandle(gh);
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    SetEvent(go);
    CloseHandle(ready);
    CloseHandle(go);
}

/* --- system -------------------------------------------------------- */

static void sec_system(void)
{
    SYSTEM_INFO si;
    PROCESSENTRY32 *p0;
    PROCESSENTRY32 *sys = NULL;
    sys_process_t *c = NULL;
    LONG status;
    DWORD lowest = 0, sum = 0;
    int i, j, ok, mult4 = 1, distinct = 1, owned = 1, zero_ids = 1, base0 = 1;

    GetSystemInfo(&si);
    ok = take(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD);
    line("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0): a handle: %s err=%s", yesno(ok),
         le_of(take_err));
    if (!ok) {
        return;
    }
    line("the first entry is PID 0: %s", yesno(nprocs > 0 && procs[0].th32ProcessID == 0));
    p0 = proc_of(0);
    if (p0 == NULL) {
        line("PID 0: not listed");
    } else {
        line("PID 0: [%s]; parent PID 0: %s; pcPriClassBase %ld; cntThreads as many as the processors: %s",
             p0->szExeFile, yesno(p0->th32ParentProcessID == 0), p0->pcPriClassBase,
             yesno(p0->cntThreads == si.dwNumberOfProcessors));
        for (i = 0; i < nthr; i++) {
            if (thr[i].th32OwnerProcessID == 0) {
                if (thr[i].th32ThreadID != 0) {
                    zero_ids = 0;
                }
                if (thr[i].tpBasePri != 0) {
                    base0 = 0;
                }
            }
        }
        line("  its Thread32 entries: as many as its cntThreads: %s; every one's thread id 0: %s, tpBasePri 0: %s",
             yesno(threads_listed(0) == (int)p0->cntThreads), yesno(zero_ids), yesno(base0));
    }

    for (i = 0; i < nprocs; i++) {
        if (procs[i].th32ProcessID != 0 && (lowest == 0 || procs[i].th32ProcessID < lowest)) {
            lowest = procs[i].th32ProcessID;
        }
        if (sys == NULL && _stricmp(procs[i].szExeFile, "System") == 0) {
            sys = &procs[i];
        }
        if (procs[i].th32ProcessID % 4 != 0) {
            mult4 = 0;
        }
        for (j = 0; j < i; j++) {
            if (procs[j].th32ProcessID == procs[i].th32ProcessID) {
                distinct = 0;
            }
        }
        sum += procs[i].cntThreads;
    }
    if (sys == NULL) {
        line("an entry named System: no");
    } else {
        line("an entry named System: yes [%s]; the second entry: %s", sys->szExeFile, yesno(sys == &procs[1]));
        line("  its PID: nonzero %s, a multiple of 4 %s, the lowest after 0 %s, below this program's %s",
             yesno(sys->th32ProcessID != 0), yesno(sys->th32ProcessID % 4 == 0),
             yesno(sys->th32ProcessID == lowest), yesno(sys->th32ProcessID < self_pid));
        line("  parent PID 0: %s; pcPriClassBase %ld; cntThreads more than one: %s; as many Thread32 entries: %s",
             yesno(sys->th32ParentProcessID == 0), sys->pcPriClassBase, yesno(sys->cntThreads > 1),
             yesno(threads_listed(sys->th32ProcessID) == (int)sys->cntThreads));
    }
    line("every PID a multiple of 4: %s; distinct: %s", yesno(mult4), yesno(distinct));
    for (i = 0; i < nthr; i++) {
        if (proc_of(thr[i].th32OwnerProcessID) == NULL) {
            owned = 0;
        }
    }
    line("Thread32 entries: as many as the cntThreads summed: %s; each owned by a listed process: %s",
         yesno(sum == (DWORD)nthr), yesno(owned));

    line("NtQuerySystemInformation(SystemProcessInformation):");
    if (query_system == NULL) {
        line("  NtQuerySystemInformation not found");
        return;
    }
    status = query_chain();
    line("  status=0x%08lX", (unsigned long)status);
    if (status >= 0) {
        c = chain_next(NULL);
    }
    if (c == NULL) {
        line("  no entries");
    } else {
        line("  the first entry: UniqueProcessId 0: %s; ImageName Length %u, Buffer NULL: %s; InheritedFromUniqueProcessId 0: %s",
             yesno(c->UniqueProcessId == 0), (unsigned)c->ImageName.Length, yesno(c->ImageName.Buffer == NULL),
             yesno(c->InheritedFromUniqueProcessId == 0));
        line("  its NumberOfThreads as many as the processors: %s; BasePriority %ld",
             yesno(c->NumberOfThreads == si.dwNumberOfProcessors), c->BasePriority);
    }
    c = sys != NULL && status >= 0 ? chain_entry(sys->th32ProcessID) : NULL;
    if (c == NULL) {
        line("  the System process's entry: not found");
    } else if (!name_inside(c)) {
        line("  the System process's entry: its ImageName outside the buffer");
    } else {
        line("  the System process's entry: ImageName [%s]; InheritedFromUniqueProcessId 0: %s; BasePriority %ld; NumberOfThreads more than one: %s",
             wsn(c->ImageName.Buffer, c->ImageName.Length / 2), yesno(c->InheritedFromUniqueProcessId == 0),
             c->BasePriority, yesno(c->NumberOfThreads > 1));
    }
    free_chain();
}

/* --- errors -------------------------------------------------------- */

/* Process32First on `snap` with dwSize `size`, in a buffer larger than
 * PROCESSENTRY32 and PROCESSENTRY32W. */
static void first_sized(const char *label, HANDLE snap, DWORD size)
{
    struct {
        PROCESSENTRY32 e;
        DWORD extra[80];
    } big;
    BOOL r;

    memset(&big, 0, sizeof big);
    big.e.dwSize = size;
    arm();
    r = Process32First(snap, &big.e);
    line("Process32First, dwSize %s: ret=%d err=%s, dwSize left %lu", label, r, le(), big.e.dwSize);
}

/* Process32First and Thread32First on a handle that is no snapshot. */
static void not_snapshot(const char *label, HANDLE h)
{
    PROCESSENTRY32 pe;
    THREADENTRY32 te;
    BOOL r;

    pe.dwSize = sizeof pe;
    arm();
    r = Process32First(h, &pe);
    line("Process32First on %s: ret=%d err=%s", label, r, le());
    te.dwSize = sizeof te;
    arm();
    r = Thread32First(h, &te);
    line("Thread32First on %s: ret=%d err=%s", label, r, le());
}

/* CreateToolhelp32Snapshot(flags, pid), the handle closed again. */
static void try_snapshot(const char *label, DWORD flags, DWORD pid)
{
    HANDLE snap;
    DWORD err;

    arm();
    snap = CreateToolhelp32Snapshot(flags, pid);
    err = GetLastError();
    line("CreateToolhelp32Snapshot(%s): a handle: %s, INVALID_HANDLE_VALUE: %s err=%s", label, yesno(handle_ok(snap)),
         yesno(snap == INVALID_HANDLE_VALUE), le_of(err));
    if (handle_ok(snap)) {
        CloseHandle(snap);
    }
}

static void sec_errors(void)
{
    PROCESSENTRY32 pe;
    THREADENTRY32 te;
    proc_entry_w_t pw;
    HANDLE snap, ev;
    ULONG small[4];
    ULONG len;
    LONG status;
    BOOL r;
    int i;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (!handle_ok(snap)) {
        line("no snapshot");
        return;
    }
    pe.dwSize = sizeof pe;
    pe.th32ProcessID = 0xFFFFFFFFu;
    arm();
    r = Process32Next(snap, &pe);
    line("Process32Next on a fresh snapshot: ret=%d err=%s, PID 0 (the first entry): %s", r, le(),
         yesno(r && pe.th32ProcessID == 0));
    pe.dwSize = sizeof pe;
    Process32Next(snap, &pe);
    pe.dwSize = sizeof pe;
    pe.th32ProcessID = 0xFFFFFFFFu;
    arm();
    r = Process32First(snap, &pe);
    line("Process32First after two entries: ret=%d err=%s, PID 0 again: %s", r, le(), yesno(r && pe.th32ProcessID == 0));

    first_sized("0", snap, 0);
    first_sized("sizeof - 1", snap, sizeof(PROCESSENTRY32) - 1);
    first_sized("sizeof + 4", snap, sizeof(PROCESSENTRY32) + 4);
    first_sized("sizeof(PROCESSENTRY32W)", snap, sizeof(proc_entry_w_t));
    if (process_first_w != NULL) {
        memset(&pw, 0, sizeof pw);
        pw.dwSize = sizeof(PROCESSENTRY32);
        arm();
        r = process_first_w(snap, &pw);
        line("Process32FirstW, dwSize sizeof(PROCESSENTRY32): ret=%d err=%s", r, le());
        memset(&pw, 0, sizeof pw);
        pw.dwSize = 0;
        arm();
        r = process_first_w(snap, &pw);
        line("Process32FirstW, dwSize 0: ret=%d err=%s", r, le());
    } else {
        line("Process32FirstW not found");
    }
    memset(&te, 0, sizeof te);
    te.dwSize = 0;
    arm();
    r = Thread32First(snap, &te);
    line("Thread32First, dwSize 0: ret=%d err=%s", r, le());
    memset(&te, 0, sizeof te);
    te.dwSize = sizeof te - 1;
    arm();
    r = Thread32First(snap, &te);
    line("Thread32First, dwSize sizeof - 1: ret=%d err=%s", r, le());

    pe.dwSize = sizeof pe;
    r = Process32First(snap, &pe);
    for (i = 0; r && i < TH_MAX_PROCS; i++) {
        pe.dwSize = sizeof pe;
        r = Process32Next(snap, &pe);
    }
    pe.dwSize = sizeof pe;
    arm();
    r = Process32Next(snap, &pe);
    line("Process32Next past the end: ret=%d err=%s", r, le());
    pe.dwSize = sizeof pe;
    arm();
    r = Process32Next(snap, &pe);
    line("Process32Next past the end again: ret=%d err=%s", r, le());
    te.dwSize = sizeof te;
    r = Thread32First(snap, &te);
    for (i = 0; r && i < TH_MAX_THREADS; i++) {
        te.dwSize = sizeof te;
        r = Thread32Next(snap, &te);
    }
    te.dwSize = sizeof te;
    arm();
    r = Thread32Next(snap, &te);
    line("Thread32Next past the end: ret=%d err=%s", r, le());
    te.dwSize = sizeof te;
    arm();
    r = Thread32Next(snap, &te);
    line("Thread32Next past the end again: ret=%d err=%s", r, le());
    CloseHandle(snap);

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (handle_ok(snap)) {
        te.dwSize = sizeof te;
        arm();
        r = Thread32First(snap, &te);
        line("Thread32First on a TH32CS_SNAPPROCESS snapshot: ret=%d err=%s", r, le());
        CloseHandle(snap);
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (handle_ok(snap)) {
        pe.dwSize = sizeof pe;
        arm();
        r = Process32First(snap, &pe);
        line("Process32First on a TH32CS_SNAPTHREAD snapshot: ret=%d err=%s", r, le());
        CloseHandle(snap);
    }
    arm();
    snap = CreateToolhelp32Snapshot(0, 0);
    line("CreateToolhelp32Snapshot(0, 0): a handle: %s err=%s", yesno(handle_ok(snap)), le());
    if (handle_ok(snap)) {
        pe.dwSize = sizeof pe;
        arm();
        r = Process32First(snap, &pe);
        line("  Process32First on it: ret=%d err=%s", r, le());
        te.dwSize = sizeof te;
        arm();
        r = Thread32First(snap, &te);
        line("  Thread32First on it: ret=%d err=%s", r, le());
        CloseHandle(snap);
    }
    try_snapshot("TH32CS_SNAPPROCESS, a PID no process has", TH32CS_SNAPPROCESS, NO_PID);
    try_snapshot("TH32CS_SNAPMODULE, 0", TH32CS_SNAPMODULE, 0);
    try_snapshot("TH32CS_SNAPMODULE, a PID no process has", TH32CS_SNAPMODULE, NO_PID);

    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    not_snapshot("an event", ev);
    CloseHandle(ev);
    not_snapshot("NULL", NULL);
    not_snapshot("INVALID_HANDLE_VALUE", INVALID_HANDLE_VALUE);

    if (query_system == NULL) {
        line("NtQuerySystemInformation not found");
        return;
    }
    len = F2KT_UNTOUCHED;
    status = query_system(SYSTEM_PROCESS_INFO, small, sizeof small, &len);
    line("NtQuerySystemInformation(SystemProcessInformation) into 16 bytes: status=0x%08lX, the length it reports: %s",
         (unsigned long)status, len_rel(len, sizeof small));
    len = F2KT_UNTOUCHED;
    status = query_system(SYSTEM_PROCESS_INFO, NULL, 0, &len);
    line("NtQuerySystemInformation(SystemProcessInformation) into none: status=0x%08lX, the length it reports: %s",
         (unsigned long)status, len_rel(len, 0));
    status = query_system(SYSTEM_PROCESS_INFO, small, sizeof small, NULL);
    line("NtQuerySystemInformation(SystemProcessInformation) into 16 bytes, no ReturnLength: status=0x%08lX",
         (unsigned long)status);
}

/* --- handle -------------------------------------------------------- */

/* A handle's basic information and type name, through NtQueryObject. */
static void show_object(HANDLE h)
{
    static ULONG info[256];             /* 1 KiB, aligned for the structure */
    object_basic_t basic;
    ustring_t *us = (ustring_t *)info;
    BYTE *from = (BYTE *)info;
    ULONG len;
    LONG status;

    if (query_object == NULL) {
        line("  NtQueryObject not found");
        return;
    }
    memset(&basic, 0xCC, sizeof basic);
    len = F2KT_UNTOUCHED;
    status = query_object(h, OBJECT_BASIC, &basic, sizeof basic, &len);
    if (status >= 0) {
        line("  basic information: status=0x%08lX; attributes 0x%lX, granted access 0x%08lX, handle count %lu",
             (unsigned long)status, basic.Attributes, basic.GrantedAccess, basic.HandleCount);
    } else {
        line("  basic information: status=0x%08lX", (unsigned long)status);
    }
    memset(info, 0, sizeof info);
    len = F2KT_UNTOUCHED;
    status = query_object(h, OBJECT_TYPE, info, sizeof info, &len);
    if (status >= 0 && us->Buffer != NULL && (BYTE *)us->Buffer >= from
        && (BYTE *)us->Buffer + us->Length <= from + sizeof info) {
        line("  type: status=0x%08lX [%s]", (unsigned long)status, wsn(us->Buffer, us->Length / 2));
    } else if (status >= 0) {
        line("  type: status=0x%08lX, Length %u, its characters %s", (unsigned long)status, (unsigned)us->Length,
             us->Buffer == NULL ? "NULL" : "outside the buffer");
    } else {
        line("  type: status=0x%08lX", (unsigned long)status);
    }
}

static void show_flags(HANDLE h)
{
    DWORD flags = F2KT_UNTOUCHED;
    BOOL r;

    arm();
    r = GetHandleInformation(h, &flags);
    line("  GetHandleInformation: ret=%d err=%s, flags 0x%lX", r, le(), flags);
}

static void sec_handle(void)
{
    PROCESSENTRY32 pe;
    HANDLE snap;
    BOOL r;

    arm();
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    line("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0): a handle: %s err=%s", yesno(handle_ok(snap)), le());
    if (!handle_ok(snap)) {
        return;
    }
    show_object(snap);
    show_flags(snap);
    arm();
    r = CloseHandle(snap);
    line("CloseHandle: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(snap);
    line("CloseHandle again: ret=%d err=%s", r, le());
    pe.dwSize = sizeof pe;
    arm();
    r = Process32First(snap, &pe);
    line("Process32First on the closed handle: ret=%d err=%s", r, le());

    arm();
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_INHERIT, 0);
    line("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_INHERIT, 0): a handle: %s err=%s",
         yesno(handle_ok(snap)), le());
    if (!handle_ok(snap)) {
        return;
    }
    show_object(snap);
    show_flags(snap);
    pe.dwSize = sizeof pe;
    arm();
    r = Process32First(snap, &pe);
    line("  Process32First: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(snap);
    line("  CloseHandle: ret=%d err=%s", r, le());
}

/* --- main ---------------------------------------------------------- */

static const section_t sections[] = {
    { "layout", sec_layout, F2KT_ALWAYS },
    { "self", sec_self, F2KT_ALWAYS },
    { "child", sec_child, F2KT_ALWAYS },
    { "system", sec_system, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { "handle", sec_handle, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    char home[MAX_PATH];
    HMODULE ntdll, k32;
    char *p;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, home, sizeof home);
    p = strrchr(home, '\\');
    if (p != NULL) {
        *p = 0;
    }
    sprintf(kid, "%s\\thkid.exe", home);
    self_pid = GetCurrentProcessId();
    ntdll = GetModuleHandleA("ntdll.dll");
    query_system = (query_system_fn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    query_object = (query_object_fn)GetProcAddress(ntdll, "NtQueryObject");
    k32 = GetModuleHandleA("kernel32.dll");
    process_first_w = (process_w_fn)GetProcAddress(k32, "Process32FirstW");
    process_next_w = (process_w_fn)GetProcAddress(k32, "Process32NextW");
    return run_sections("toolhelp", sections, argc, argv);
}
