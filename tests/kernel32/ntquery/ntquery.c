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
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ntquery):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ntquery.c kernel32.lib advapi32.lib
 */

#include "../common/f2kt.h"

typedef LONG(WINAPI *nqsi_fn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqip_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqit_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

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

static const section_t sections[] = {
    { "sysinfo", sec_sysinfo, F2KT_ALWAYS },
    { "procinfo", sec_procinfo, F2KT_ALWAYS },
    { "threadinfo", sec_threadinfo, F2KT_ALWAYS },
    { "pebread", sec_pebread, F2KT_ALWAYS },
    { "scmfail", sec_scmfail, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    resolve();
    return run_sections("ntquery", sections, argc, argv);
}
