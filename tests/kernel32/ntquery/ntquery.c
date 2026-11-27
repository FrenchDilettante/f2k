/*
 * ntquery - the introspection surface, called ntdll-direct through
 * GetProcAddress as the corpus pattern for ntdll calls: the system and
 * process/thread information queries, a PEB read through
 * ReadProcessMemory, and the service manager.
 *
 * Sections:
 *
 *   sysinfo    NtQuerySystemInformation class 5 (SystemProcessInformation):
 *              the status and whether it filled the buffer.
 *   procinfo   NtQueryInformationProcess class 0 (ProcessBasicInformation):
 *              the status and whether the PEB address came back non-NULL.
 *   threadinfo NtQueryInformationThread class 0 (ThreadBasicInformation)
 *              with a buffer of the class's size: the status, the length
 *              answered, and the fields as relations (the TEB the one fs
 *              points at, the client id the calling process's and thread's
 *              ids); then the same class with a 256-byte buffer, which
 *              Windows 2000 refuses with STATUS_INFO_LENGTH_MISMATCH.
 *   pebread    the section's own PEB address (NtQueryInformationProcess,
 *              as procinfo: each section runs as its own process), then
 *              ReadProcessMemory of the PEB's first fields on the current
 *              process: the byte count, and the fields as relations
 *              (BeingDebugged, ImageBaseAddress the program's module
 *              handle, ProcessHeap the process heap).
 *   scmfail    OpenSCManagerA: Windows 2000 answers a handle, its last
 *              error left at 997 (ERROR_IO_PENDING).
 *   children   NtQuerySystemInformation class 5 with 60 children alive
 *              (this program again, run as "ntquery --kid <ready> <go>":
 *              detached, each releasing one shared semaphore once and
 *              then waiting on one event): into 1 KiB, the status and
 *              the length reported (Windows 2000 reports none); then into
 *              a buffer room for all, the status, and the listing walked:
 *              how many entries are the children (by their ids), how many
 *              of those name this program's parent, hold one thread and
 *              carry this program's image name, and whether this program
 *              is listed too. A creation that fails ends the creating
 *              there, its error printed.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ntquery):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ntquery.c kernel32.lib advapi32.lib
 */

#include "../common/f2kt.h"
#include <ctype.h>

typedef LONG(WINAPI *nqsi_fn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqip_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqit_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* How many children the children section keeps alive. */
#define CHILDREN 60

/* The longest wait for one child to get ready or to end, and a child's
 * longest wait for the event. */
#define CHILD_MS 60000

/* The structures declared here, as the fixtures that call ntdll directly
 * do (the MSVC 6 SDK headers predate them), from their public
 * documentation. */
typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    unsigned long UniqueProcessId;
    PVOID Reserved3;
} f2kt_process_basic_information;

/* THREAD_BASIC_INFORMATION: 28 bytes. */
typedef struct {
    LONG ExitStatus;
    PVOID TebBaseAddress;
    HANDLE UniqueProcess;   /* the CLIENT_ID */
    HANDLE UniqueThread;
    ULONG AffinityMask;     /* KAFFINITY */
    LONG Priority;          /* KPRIORITY */
    LONG BasePriority;
} f2kt_thread_basic_information;

/* The PEB's first fields. */
typedef struct {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
} f2kt_peb_head;

/* SYSTEM_PROCESS_INFORMATION's head (Nebbett's SYSTEM_PROCESSES for
 * Windows 2000; the toolhelp fixture declares the whole of it): the
 * fields the children section reads. */
typedef struct {
    ULONG NextEntryOffset;              /* 0x00 */
    ULONG NumberOfThreads;              /* 0x04 */
    ULONG Reserved1[6];                 /* 0x08 */
    LARGE_INTEGER CreateTime;           /* 0x20 */
    LARGE_INTEGER UserTime;             /* 0x28 */
    LARGE_INTEGER KernelTime;           /* 0x30 */
    USHORT NameLength;                  /* 0x38: ImageName, a UNICODE_STRING */
    USHORT NameMaximumLength;
    WCHAR *NameBuffer;
    LONG BasePriority;                  /* 0x40 */
    ULONG UniqueProcessId;              /* 0x44 */
    ULONG InheritedFromUniqueProcessId; /* 0x48 */
} f2kt_process_entry_head;

static nqsi_fn g_nqsi;
static nqip_fn g_nqip;
static nqit_fn g_nqit;

static void resolve(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_nqsi = (nqsi_fn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_nqip = (nqip_fn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    g_nqit = (nqit_fn)GetProcAddress(ntdll, "NtQueryInformationThread");
}

/* The TEB's fields at fs: its self pointer (0x18, what NtCurrentTeb
 * answers) and its PEB pointer (0x30). */
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

static void sec_sysinfo(void)
{
    static char buf[65536];
    ULONG rl = 0;
    LONG st;

    if (g_nqsi == NULL) {
        line("NtQuerySystemInformation not found");
        return;
    }
    arm();
    st = g_nqsi(5, buf, sizeof buf, &rl);
    line("NtQuerySystemInformation(5): status=0x%08lX err=%s filled=%s", (unsigned long)st, le(),
        rl > 0 ? "yes" : "no");
}

static void sec_procinfo(void)
{
    f2kt_process_basic_information pbi;
    ULONG rl = 0;
    LONG st;

    if (g_nqip == NULL) {
        line("NtQueryInformationProcess not found");
        return;
    }
    memset(&pbi, 0, sizeof pbi);
    arm();
    st = g_nqip(GetCurrentProcess(), 0, &pbi, sizeof pbi, &rl);
    line("NtQueryInformationProcess(0): status=0x%08lX err=%s peb=%s", (unsigned long)st, le(),
        pbi.PebBaseAddress != NULL ? "set" : "null");
}

static void sec_threadinfo(void)
{
    f2kt_thread_basic_information tbi;
    static char big[256];
    ULONG rl;
    LONG st;

    if (g_nqit == NULL) {
        line("NtQueryInformationThread not found");
        return;
    }
    memset(&tbi, 0, sizeof tbi);
    rl = 0;
    arm();
    st = g_nqit(GetCurrentThread(), 0, &tbi, sizeof tbi, &rl);
    line("NtQueryInformationThread(0, %u bytes): status=0x%08lX err=%s length=%lu", (unsigned)sizeof tbi,
        (unsigned long)st, le(), (unsigned long)rl);
    if (st >= 0) {
        line("ExitStatus=0x%08lX, TEB set: %s, the one fs points at: %s", (unsigned long)tbi.ExitStatus,
            yesno(tbi.TebBaseAddress != NULL), yesno((DWORD)tbi.TebBaseAddress == fs_dword(0x18)));
        line("ClientId: the process id: %s, the thread id: %s",
            yesno((DWORD)tbi.UniqueProcess == GetCurrentProcessId()),
            yesno((DWORD)tbi.UniqueThread == GetCurrentThreadId()));
        line("AffinityMask set: %s, BasePriority=%ld", yesno(tbi.AffinityMask != 0), (long)tbi.BasePriority);
    }

    rl = 0;
    arm();
    st = g_nqit(GetCurrentThread(), 0, big, sizeof big, &rl);
    line("NtQueryInformationThread(0, %u bytes): status=0x%08lX err=%s", (unsigned)sizeof big,
        (unsigned long)st, le());
}

static void sec_pebread(void)
{
    f2kt_process_basic_information pbi;
    f2kt_peb_head peb;
    ULONG rl = 0;
    DWORD n = 0;
    LONG st;
    BOOL ok;

    if (g_nqip == NULL) {
        line("NtQueryInformationProcess not found");
        return;
    }
    memset(&pbi, 0, sizeof pbi);
    arm();
    st = g_nqip(GetCurrentProcess(), 0, &pbi, sizeof pbi, &rl);
    line("NtQueryInformationProcess(0): status=0x%08lX err=%s peb=%s, the TEB's: %s", (unsigned long)st, le(),
        pbi.PebBaseAddress != NULL ? "set" : "null", yesno((DWORD)pbi.PebBaseAddress == fs_dword(0x30)));
    if (st < 0 || pbi.PebBaseAddress == NULL) {
        return;
    }

    memset(&peb, 0xCC, sizeof peb);
    arm();
    ok = ReadProcessMemory(GetCurrentProcess(), pbi.PebBaseAddress, &peb, sizeof peb, &n);
    line("ReadProcessMemory(own PEB, %u bytes): ret=%d err=%s read=%lu", (unsigned)sizeof peb, ok, le(),
        (unsigned long)n);
    if (!ok) {
        return;
    }
    line("the bytes a direct read sees: %s", yesno(memcmp(&peb, pbi.PebBaseAddress, sizeof peb) == 0));
    line("BeingDebugged=%u, ImageBaseAddress the program's module handle: %s", (unsigned)peb.BeingDebugged,
        yesno(peb.ImageBaseAddress == (PVOID)GetModuleHandleA(NULL)));
    line("Ldr set: %s, ProcessParameters set: %s, ProcessHeap the process heap: %s", yesno(peb.Ldr != NULL),
        yesno(peb.ProcessParameters != NULL), yesno(peb.ProcessHeap == (PVOID)GetProcessHeap()));
}

static void sec_scmfail(void)
{
    HANDLE h;

    arm();
    h = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    line("OpenSCManagerA: ret=%s err=%s", h != NULL ? "ok" : "null", le());
    if (h != NULL) {
        CloseServiceHandle(h);
    }
}

/* The children section's child: release <ready> once, wait for <go>. */
static int kid(const char *ready_name, const char *go_name)
{
    HANDLE ready = OpenSemaphoreA(SEMAPHORE_MODIFY_STATE, FALSE, ready_name);
    HANDLE go = OpenEventA(SYNCHRONIZE, FALSE, go_name);

    if (ready == NULL || go == NULL) {
        return 2;
    }
    if (!ReleaseSemaphore(ready, 1, NULL)) {
        return 3;
    }
    return WaitForSingleObject(go, 2 * CHILD_MS) == WAIT_OBJECT_0 ? 0 : 1;
}

/* Whether the counted name is this program's file name (any case). */
static int our_name(const WCHAR *name, USHORT bytes)
{
    static const char self[] = "ntquery.exe";
    unsigned i;

    if (name == NULL || bytes != 2 * (sizeof self - 1)) {
        return 0;
    }
    for (i = 0; i < sizeof self - 1; i++) {
        if (name[i] >= 0x80 || tolower((char)name[i]) != self[i]) {
            return 0;
        }
    }
    return 1;
}

static void sec_children(void)
{
    static PROCESS_INFORMATION kids[CHILDREN];
    static char buf[512 * 1024];
    STARTUPINFOA si;
    char self[MAX_PATH];
    char command[MAX_PATH + 256];
    char ready_name[64];
    char go_name[64];
    const f2kt_process_entry_head *e;
    HANDLE ready;
    HANDLE go;
    ULONG rl;
    LONG st;
    int made = 0;
    int readied = 0;
    int found = 0;
    int parented = 0;
    int single = 0;
    int named = 0;
    int listed = 0;
    int entries = 0;
    int i;
    DWORD n;
    DWORD code;
    ULONG at;

    if (g_nqsi == NULL) {
        line("NtQuerySystemInformation not found");
        return;
    }
    n = GetModuleFileNameA(NULL, self, sizeof self);
    if (n == 0 || n >= sizeof self) {
        line("this program's path: too long");
        return;
    }
    sprintf(ready_name, "f2kt-ntquery-%lu-ready", GetCurrentProcessId());
    sprintf(go_name, "f2kt-ntquery-%lu-go", GetCurrentProcessId());
    ready = CreateSemaphoreA(NULL, 0, CHILDREN, ready_name);
    go = CreateEventA(NULL, TRUE, FALSE, go_name);
    if (ready == NULL || go == NULL) {
        line("the semaphore and the event: not made err=%s", le());
        return;
    }
    _snprintf(command, sizeof command - 1, "\"%s\" --kid %s %s", self, ready_name, go_name);
    command[sizeof command - 1] = '\0';
    for (i = 0; i < CHILDREN; i++) {
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        arm();
        if (!CreateProcessA(self, command, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &kids[i])) {
            line("CreateProcessA, child %d: failed err=%s", i + 1, le());
            break;
        }
        CloseHandle(kids[i].hThread);
        made++;
    }
    for (i = 0; i < made; i++) {
        if (WaitForSingleObject(ready, CHILD_MS) != WAIT_OBJECT_0) {
            break;
        }
        readied++;
    }
    line("children started: %d of %d, ready: %d", made, CHILDREN, readied);

    rl = 0;
    arm();
    st = g_nqsi(5, buf, 1024, &rl);
    line("NtQuerySystemInformation(5) into 1024 bytes: status=0x%08lX err=%s, the length it reports: %s",
        (unsigned long)st, le(), rl == 0 ? "zero" : rl > 1024 ? "more than the buffer" : "within the buffer");

    rl = 0;
    arm();
    st = g_nqsi(5, buf, sizeof buf, &rl);
    line("NtQuerySystemInformation(5) into %u KiB: status=0x%08lX err=%s, a length reported: %s",
        (unsigned)(sizeof buf / 1024), (unsigned long)st, le(), yesno(rl != 0 && rl <= sizeof buf));
    if (st >= 0) {
        at = 0;
        for (;;) {
            e = (const f2kt_process_entry_head *)(buf + at);
            entries++;
            if (e->UniqueProcessId == GetCurrentProcessId()) {
                listed++;
            }
            for (i = 0; i < made; i++) {
                if (kids[i].dwProcessId == e->UniqueProcessId) {
                    found++;
                    parented += e->InheritedFromUniqueProcessId == GetCurrentProcessId();
                    single += e->NumberOfThreads == 1;
                    named += our_name(e->NameBuffer, e->NameLength);
                    break;
                }
            }
            if (e->NextEntryOffset == 0 || at + e->NextEntryOffset >= sizeof buf || entries > 100000) {
                break;
            }
            at += e->NextEntryOffset;
        }
        line("the listing: more than its children's entries %s, this program listed once %s",
            yesno(entries > found), yesno(listed == 1));
        line("the children found: %d; naming this program their parent %d, with one thread %d, "
            "named ntquery.exe %d", found, parented, single, named);
    }

    SetEvent(go);
    found = 0;
    for (i = 0; i < made; i++) {
        if (WaitForSingleObject(kids[i].hProcess, CHILD_MS) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(kids[i].hProcess, &code) && code == 0) {
            found++;
        }
        CloseHandle(kids[i].hProcess);
    }
    line("the event set: ended with exit code 0 %d", found);
    CloseHandle(go);
    CloseHandle(ready);
}

static const section_t sections[] = {
    { "sysinfo", sec_sysinfo, F2KT_ALWAYS },
    { "procinfo", sec_procinfo, F2KT_ALWAYS },
    { "threadinfo", sec_threadinfo, F2KT_ALWAYS },
    { "pebread", sec_pebread, F2KT_ALWAYS },
    { "scmfail", sec_scmfail, F2KT_ALWAYS },
    { "children", sec_children, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    resolve();
    if (argc >= 4 && strcmp(argv[1], "--kid") == 0) {
        return kid(argv[2], argv[3]);
    }
    return run_sections("ntquery", sections, argc, argv);
}
