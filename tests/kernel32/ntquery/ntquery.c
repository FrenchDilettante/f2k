/*
 * ntquery - the introspection surface, called ntdll-direct through
 * GetProcAddress as the corpus pattern for ntdll calls: the system and
 * process/thread information queries, a PEB read through
 * ReadProcessMemory, and the service manager's absence or presence.
 *
 * Sections:
 *
 *   sysinfo    NtQuerySystemInformation class 5 (SystemProcessInformation):
 *              the status and whether it filled the buffer.
 *   procinfo   NtQueryInformationProcess class 0 (ProcessBasicInformation):
 *              the status and whether the PEB address came back non-NULL.
 *   threadinfo NtQueryInformationThread class 0 (ThreadBasicInformation):
 *              the status.
 *   pebread    ReadProcessMemory of the first bytes of the own PEB (found
 *              by procinfo): the status and the byte count.
 *   scmfail    OpenSCManagerA: on a machine running the service manager it
 *              answers a handle; on one without, the error.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ntquery):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ntquery.c kernel32.lib advapi32.lib
 */

#include "../common/f2kt.h"

typedef LONG(WINAPI *nqsi_fn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqip_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqit_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *rpm_fn)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);

/* The structures declared here, as the fixtures that call ntdll directly
 * do (the MSVC 6 SDK headers predate them). */
typedef struct {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    unsigned long UniqueProcessId;
    PVOID Reserved3;
} f2kt_process_basic_information;

static nqsi_fn g_nqsi;
static nqip_fn g_nqip;
static nqit_fn g_nqit;
static rpm_fn g_rpm;
static f2kt_process_basic_information g_pbi;

static void resolve(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_nqsi = (nqsi_fn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_nqip = (nqip_fn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    g_nqit = (nqit_fn)GetProcAddress(ntdll, "NtQueryInformationThread");
    g_rpm = (rpm_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadProcessMemory");
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
    ULONG rl = 0;
    LONG st;

    if (g_nqip == NULL) {
        line("NtQueryInformationProcess not found");
        return;
    }
    memset(&g_pbi, 0, sizeof g_pbi);
    arm();
    st = g_nqip(GetCurrentProcess(), 0, &g_pbi, sizeof g_pbi, &rl);
    line("NtQueryInformationProcess(0): status=0x%08lX err=%s peb=%s", (unsigned long)st, le(),
        g_pbi.PebBaseAddress != NULL ? "set" : "null");
}

static void sec_threadinfo(void)
{
    static char buf[256];
    ULONG rl = 0;
    LONG st;

    if (g_nqit == NULL) {
        line("NtQueryInformationThread not found");
        return;
    }
    arm();
    st = g_nqit(GetCurrentThread(), 0, buf, sizeof buf, &rl);
    line("NtQueryInformationThread(0): status=0x%08lX err=%s", (unsigned long)st, le());
}

static void sec_pebread(void)
{
    char buf[0x40];
    SIZE_T n = 0;
    LONG st;

    if (g_rpm == NULL || g_pbi.PebBaseAddress == NULL) {
        line("ReadProcessMemory or PEB unavailable");
        return;
    }
    arm();
    st = g_rpm(GetCurrentProcess(), g_pbi.PebBaseAddress, buf, sizeof buf, &n);
    line("ReadProcessMemory(PEB): status=0x%08lX err=%s read=%lu", (unsigned long)st, le(),
        (unsigned long)n);
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
