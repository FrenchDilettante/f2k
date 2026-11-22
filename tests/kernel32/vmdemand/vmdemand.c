/*
 * vmdemand - the demand-paging surface: what a commit charges and where the
 * commit limit bites, large reservations with a bounded touched slice,
 * MEM_RESET and protection transitions over committed, reserved and mapped
 * pages, the commit numbers the system reports, page-out/page-in round
 * trips, file-backed section page-in, and NtQueryVirtualMemory over every
 * region state.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   commitlimit   GlobalMemoryStatus and NtQuerySystemInformation's
 *                 performance class (the commit limit, total and available),
 *                 then MEM_COMMIT in 32 MiB chunks until the limit refuses:
 *                 how far the charge got (as a relation), the failing
 *                 call's Win32 error and the failing Nt call's status,
 *                 and that freeing returns the charge
 *   reservelarge  a 1 GiB reservation: what VirtualQuery and
 *                 NtQueryVirtualMemory report over it, committing 16 MiB at
 *                 each end and touching only that, what the query reports
 *                 over the committed and still-reserved parts, an interior
 *                 commit, release
 *   resetcommit   MEM_RESET over committed private pages, over reserved
 *                 pages, with MEM_COMMIT, over a paging-file view; decommit
 *                 and recommit of half a region and what the query and the
 *                 contents report after each
 *   prottrans     protection transitions on a committed region:
 *                 PAGE_READONLY to PAGE_READWRITE to PAGE_NOACCESS to
 *                 PAGE_EXECUTE_READ, what IsBadReadPtr/IsBadWritePtr and
 *                 VirtualQuery report at each, bogus protections and sizes,
 *                 a transition on a reserved region, and NtProtectVirtualMemory
 *                 called directly
 *   sysinfo       NtQuerySystemInformation's performance class against
 *                 GlobalMemoryStatus: the commit limit/total/peak as
 *                 relations between the two, the fault counts nonzero
 *   pageroundtrip a pattern written to 16 MiB of committed private memory,
 *                 read back through NtReadVirtualMemory and written through
 *                 NtWriteVirtualMemory, then a second 16 MiB written (the
 *                 pressure) and the first read back again
 *   filepagein    a file-backed section: the view reads the file's bytes,
 *                 a copy-on-write view's writes stay private and leave the
 *                 file alone while mapped and after unmap, a write view's
 *                 writes reach the file once unmapped, a remap after the
 *                 file changed on disk sees the new bytes
 *   ntqueryvm     NtQueryVirtualMemory over a free region, a reserved one,
 *                 a committed one, a mapped view and the image, a 32 MiB
 *                 commit over free space and the query over it, a buffer
 *                 too short, an unknown information class
 *   trimpressure  16 MiB committed and patterned, a second 16 MiB committed
 *                 and written, the first's pattern intact afterwards, the
 *                 available commit dropping, the first still committed;
 *                 the eviction this observes needs the small-RAM boot the
 *                 declaration asks for (-m 32M on the IDE disk)
 *
 * No test writes more than tens of MiB: large-VA cases reserve big and touch
 * a bounded slice; commits in the limit loop are charged, only their first
 * page is touched.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat vmdemand):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% vmdemand.c kernel32.lib
 */

#include "../common/f2kt.h"

#define F2KT_PAGE 0x1000u

/* ntdll's services, reached through GetProcAddress as the corpus pattern
 * for ntdll calls: no import library MSVC 6 has declares them. */
typedef LONG(WINAPI *nqsi_fn)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *nqvm_fn)(HANDLE, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI *navm_fn)(HANDLE, PVOID *, ULONG, ULONG *, ULONG, ULONG);
typedef LONG(WINAPI *nrvm_fn)(HANDLE, PVOID, PVOID, ULONG, ULONG *);
typedef LONG(WINAPI *npvm_fn)(HANDLE, PVOID *, ULONG *, ULONG, ULONG *);

static nqsi_fn g_nqsi;
static nqvm_fn g_nqvm;
static navm_fn g_navm;
static nrvm_fn g_nrvm;
static nrvm_fn g_nwvm;
static npvm_fn g_npvm;

/* SYSTEM_PERFORMANCE_INFORMATION, declared here from its public layout (the
 * MSVC 6 SDK headers predate it); only the fields up to DemandZeroCount are
 * read, and the query gets a 512-byte buffer, room for the whole structure. */
typedef struct {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
} f2kt_system_performance_information;

#define F2KT_SYSTEM_PERFORMANCE_INFORMATION 2
#define F2KT_MEMORY_BASIC_INFORMATION 0

#define F2KT_STATUS_COMMITMENT_LIMIT 0xC000012Du
#define F2KT_STATUS_INVALID_INFO_CLASS 0xC0000003u
#define F2KT_STATUS_INFO_LENGTH_MISMATCH 0xC0000004u

static void resolve(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    g_nqsi = (nqsi_fn)GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_nqvm = (nqvm_fn)GetProcAddress(ntdll, "NtQueryVirtualMemory");
    g_navm = (navm_fn)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    g_nrvm = (nrvm_fn)GetProcAddress(ntdll, "NtReadVirtualMemory");
    g_nwvm = (nrvm_fn)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    g_npvm = (npvm_fn)GetProcAddress(ntdll, "NtProtectVirtualMemory");
}

/* VirtualAlloc of `addr` with `type`, as printed: NULL, the address asked
   for, or another, with the error. */
static void try_alloc(const char *label, void *addr, DWORD size, DWORD type, DWORD protect)
{
    void *p;
    const char *e;

    arm();
    p = VirtualAlloc(addr, size, type, protect);
    e = le();
    line("VirtualAlloc(%s): %s err=%s", label, p == NULL ? "NULL" : p == addr ? "the address" : "another address", e);
}

/* The state and protection VirtualQuery gives `addr`. */
static void state_of(const char *label, const void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery(addr, &mbi, sizeof mbi) == 0) {
        line("%s: VirtualQuery failed", label);
        return;
    }
    line("%s: state 0x%lX protect 0x%lX", label, mbi.State, mbi.Protect);
}

/* VirtualProtect of the first page of `v`: the return, the old protection
   when it succeeds, the error. */
static void try_protect(const char *label, void *v, DWORD size, DWORD protect)
{
    DWORD old = 0;
    BOOL r;
    const char *e;

    arm();
    r = VirtualProtect(v, size, protect, &old);
    e = le();
    if (r) {
        line("VirtualProtect(%s, 0x%lX): ret=1 old 0x%lX err=%s", label, protect, old, e);
    } else {
        line("VirtualProtect(%s, 0x%lX): ret=0 err=%s", label, protect, e);
    }
}

/* A fill pattern and its checksum over `size` bytes at `p`. */
static void fill_pattern(BYTE *p, DWORD size)
{
    DWORD i;

    for (i = 0; i < size; i++) {
        p[i] = (BYTE)(i * 31 + 7);
    }
}

static DWORD checksum(const BYTE *p, DWORD size)
{
    DWORD sum = 0;
    DWORD i;

    for (i = 0; i < size; i++) {
        sum = sum * 33 + p[i];
    }
    return sum;
}

/* --- commitlimit ----------------------------------------------------------- */

#define F2KT_CHUNK (32u * 1024u * 1024u)
#define F2KT_MAX_CHUNKS 48
#define F2KT_ERROR_COMMITMENT_LIMIT 1455u

static void sec_commitlimit(void)
{
    MEMORYSTATUS gms;
    SYSTEM_INFO si;
    BYTE buf[512];
    ULONG retlen = 0;
    LONG st;
    f2kt_system_performance_information *spi;
    void *chunks[F2KT_MAX_CHUNKS];
    DWORD n = 0;
    DWORD i;
    int refused = 0;
    DWORD refused_err = 0;
    void *p;
    PVOID base;
    ULONG size;

    GetSystemInfo(&si);
    gms.dwLength = sizeof gms;
    GlobalMemoryStatus(&gms);
    line("GlobalMemoryStatus: total page file > 0: %s, avail <= total: %s, total a page multiple: %s",
         yesno(gms.dwTotalPageFile > 0), yesno(gms.dwAvailPageFile <= gms.dwTotalPageFile),
         yesno(gms.dwTotalPageFile % si.dwPageSize == 0));

    if (g_nqsi == NULL) {
        line("NtQuerySystemInformation not found");
    } else {
        memset(buf, 0, sizeof buf);
        arm();
        st = g_nqsi(F2KT_SYSTEM_PERFORMANCE_INFORMATION, buf, sizeof buf, &retlen);
        spi = (f2kt_system_performance_information *)buf;
        line("NtQuerySystemInformation(performance): status=0x%08lX err=%s retlen>=128: %s", (unsigned long)st,
             le(), yesno(retlen >= 128));
        line("committed <= limit: %s", yesno(spi->CommittedPages <= spi->CommitLimit));
        line("peak >= committed: %s", yesno(spi->PeakCommitment >= spi->CommittedPages));
        line("limit in pages == dwTotalPageFile/pages: %s", yesno((spi->CommitLimit << 12) == gms.dwTotalPageFile));
        line("avail == (limit-committed) pages: %s",
             yesno(((spi->CommitLimit - spi->CommittedPages) << 12) == gms.dwAvailPageFile));
    }

    /* Commit in chunks until the limit refuses; only each chunk's first
     * page is touched. */
    for (i = 0; i < F2KT_MAX_CHUNKS; i++) {
        arm();
        p = VirtualAlloc(NULL, F2KT_CHUNK, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p == NULL) {
            refused = 1;
            refused_err = GetLastError();
            break;
        }
        chunks[n++] = p;
        ((volatile BYTE *)p)[0] = 1;
    }
    line("a chunk was refused at the limit: %s, its error the commitment limit (1455): %s", yesno(refused),
         yesno(refused_err == F2KT_ERROR_COMMITMENT_LIMIT));
    line("chunks committed before the limit: at least 2: %s", yesno(n >= 2));

    /* The same refusal through the Nt call, for its status. */
    if (g_navm != NULL) {
        base = NULL;
        size = F2KT_CHUNK;
        st = g_navm(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT, PAGE_READWRITE);
        line("NtAllocateVirtualMemory(32 MiB commit) past the limit: status=0x%08lX is 0x%08lX: %s",
             (unsigned long)st, F2KT_STATUS_COMMITMENT_LIMIT, yesno((unsigned long)st == F2KT_STATUS_COMMITMENT_LIMIT));
    }

    for (i = 0; i < n; i++) {
        VirtualFree(chunks[i], 0, MEM_RELEASE);
    }
    arm();
    p = VirtualAlloc(NULL, F2KT_CHUNK, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    line("after freeing every chunk, one more commits: %s err=%s", yesno(p != NULL), le());
    if (p != NULL) {
        VirtualFree(p, 0, MEM_RELEASE);
    }
}

/* --- reservelarge ---------------------------------------------------------- */

#define F2KT_BIG (0x40000000u)      /* 1 GiB */
/* 16 MiB: two of them exceed the small-RAM boot's free frames, so on a
 * system that commits eagerly the second commit fails where a demand-paging
 * system only charges. */
#define F2KT_SLICE (16u * 1024u * 1024u)

static void sec_reservelarge(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *r, *head, *tail, *mid;
    DWORD sum_head, sum_tail;
    ULONG retlen;
    LONG st;

    arm();
    r = (BYTE *)VirtualAlloc(NULL, F2KT_BIG, MEM_RESERVE, PAGE_READWRITE);
    line("reserve 1 GiB: %s err=%s", r == NULL ? "NULL" : "ok", le());
    if (r == NULL) {
        return;
    }
    if (VirtualQuery(r, &mbi, sizeof mbi) != 0) {
        line("over the reservation: state 0x2000: %s, protect 0x0: %s, region 1 GiB: %s, alloc base is it: %s, "
             "below 0x7FFF0000: %s", yesno(mbi.State == MEM_RESERVE), yesno(mbi.Protect == 0),
             yesno(mbi.RegionSize == F2KT_BIG), yesno(mbi.AllocationBase == r), yesno((DWORD)r < 0x7FFF0000u));
    }
    if (g_nqvm != NULL) {
        arm();
        st = g_nqvm(GetCurrentProcess(), r, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
        line("NtQueryVirtualMemory over it: status=0x%08lX same state as VirtualQuery: %s", (unsigned long)st,
             yesno(mbi.State == MEM_RESERVE));
    }

    head = (BYTE *)VirtualAlloc(r, F2KT_SLICE, MEM_COMMIT, PAGE_READWRITE);
    tail = (BYTE *)VirtualAlloc(r + F2KT_BIG - F2KT_SLICE, F2KT_SLICE, MEM_COMMIT, PAGE_READWRITE);
    line("commit 16 MiB at each end: head %s, tail %s", yesno(head == r),
         yesno(tail == r + F2KT_BIG - F2KT_SLICE));
    if (head == r && tail != NULL) {
        fill_pattern(head, F2KT_SLICE);
        fill_pattern(tail, F2KT_SLICE);
        sum_head = checksum(head, F2KT_SLICE);
        sum_tail = checksum(tail, F2KT_SLICE);
        line("the touched slices read back: head %s, tail %s", yesno(checksum(head, F2KT_SLICE) == sum_head),
             yesno(checksum(tail, F2KT_SLICE) == sum_tail));
    }
    if (VirtualQuery(r, &mbi, sizeof mbi) != 0) {
        line("over the committed head: state 0x1000: %s, region 16 MiB: %s", yesno(mbi.State == MEM_COMMIT),
             yesno(mbi.RegionSize == F2KT_SLICE));
    }
    mid = r + F2KT_SLICE;
    if (VirtualQuery(mid, &mbi, sizeof mbi) != 0) {
        line("over the still-reserved middle: state 0x2000: %s, region 1 GiB - 32 MiB: %s",
             yesno(mbi.State == MEM_RESERVE), yesno(mbi.RegionSize == F2KT_BIG - 2 * F2KT_SLICE));
    }
    arm();
    tail = (BYTE *)VirtualAlloc(mid + 0x400000, F2KT_PAGE * 16, MEM_COMMIT, PAGE_READWRITE);
    line("an interior commit: %s err=%s", tail == NULL ? "NULL" : "ok", le());
    state_of("then", mid + 0x400000);

    arm();
    line("release the 1 GiB: ret=%d err=%s", VirtualFree(r, 0, MEM_RELEASE), le());
    if (VirtualQuery(r, &mbi, sizeof mbi) != 0) {
        line("after release: state 0x10000: %s", yesno(mbi.State == MEM_FREE));
    }
}

/* --- resetcommit ----------------------------------------------------------- */

static void sec_resetcommit(void)
{
    BYTE *p, *r;
    HANDLE h;
    BYTE *v;
    volatile DWORD *dword_at;

    p = (BYTE *)VirtualAlloc(NULL, 0x400000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memset(p, 0x5A, 0x400000);
    try_alloc("committed private, MEM_RESET", p, 0x400000, MEM_RESET, PAGE_READWRITE);
    state_of("then", p);
    dword_at = (volatile DWORD *)p;
    line("first dword zero after MEM_RESET: %s", yesno(*dword_at == 0));
    try_alloc("committed private, MEM_RESET|MEM_COMMIT", p, 0x400000, MEM_RESET | MEM_COMMIT, PAGE_READWRITE);
    try_alloc("NULL, MEM_RESET|MEM_COMMIT", NULL, 0x10000, MEM_RESET | MEM_COMMIT, PAGE_READWRITE);

    r = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_RESERVE, PAGE_READWRITE);
    try_alloc("reserved, MEM_RESET", r, 0x100000, MEM_RESET, PAGE_READWRITE);
    state_of("then", r);
    try_alloc("reserved, MEM_RESET|MEM_COMMIT", r, 0x100000, MEM_RESET | MEM_COMMIT, PAGE_READWRITE);
    try_alloc("reserved, MEM_COMMIT", r, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    state_of("then", r);
    VirtualFree(r, 0, MEM_RELEASE);

    arm();
    line("decommit half: ret=%d err=%s", VirtualFree(p, 0x200000, MEM_DECOMMIT), le());
    state_of("the decommitted half", p);
    state_of("the kept half", p + 0x200000);
    arm();
    p = (BYTE *)VirtualAlloc(p, 0x200000, MEM_COMMIT, PAGE_READWRITE);
    line("recommit the half: %s err=%s", p == NULL ? "NULL" : "ok", le());
    state_of("then", p);
    dword_at = (volatile DWORD *)p;
    line("first dword of the recommitted half zero: %s", yesno(*dword_at == 0));
    VirtualFree(p, 0, MEM_RELEASE);

    /* A paging-file-backed view. */
    arm();
    h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x100000, NULL);
    line("CreateFileMapping(paging, 1 MiB): ret=%s err=%s", h ? "ok" : "null", le());
    if (h != NULL) {
        arm();
        v = (BYTE *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0x100000);
        line("MapViewOfFile: ret=%s err=%s", v ? "ok" : "null", le());
        if (v != NULL) {
            try_alloc("the paging view, MEM_RESET", v, 0x100000, MEM_RESET, PAGE_READWRITE);
            state_of("then", v);
            try_alloc("the paging view, MEM_COMMIT", v, F2KT_PAGE, MEM_COMMIT, PAGE_READWRITE);
            UnmapViewOfFile(v);
        }
        CloseHandle(h);
    }
}

/* --- prottrans ------------------------------------------------------------- */

static void sec_prottrans(void)
{
    BYTE *p, *r;
    PVOID base;
    ULONG size;
    DWORD old = 0;
    LONG st;

    p = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY);
    line("committed PAGE_READONLY: IsBadWritePtr %s, IsBadReadPtr %s", yesno(IsBadWritePtr(p, 0x1000) != 0),
         yesno(IsBadReadPtr(p, 0x1000) != 0));
    try_protect("to PAGE_READWRITE", p, 0x100000, PAGE_READWRITE);
    state_of("then", p);
    line("now IsBadWritePtr %s", yesno(IsBadWritePtr(p, 0x1000) != 0));
    ((volatile BYTE *)p)[0] = 1;
    line("a write went through: %s", yesno(p[0] == 1));
    try_protect("to PAGE_NOACCESS", p, 0x100000, PAGE_NOACCESS);
    state_of("then", p);
    line("IsBadReadPtr %s, IsBadWritePtr %s", yesno(IsBadReadPtr(p, 0x1000) != 0),
         yesno(IsBadWritePtr(p, 0x1000) != 0));
    try_protect("to PAGE_EXECUTE_READ", p, 0x100000, PAGE_EXECUTE_READ);
    state_of("then", p);
    try_protect("bogus 0x40", p, 0x100000, 0x40);
    try_protect("size 0", p, 0, PAGE_READWRITE);

    r = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_RESERVE, PAGE_READWRITE);
    try_protect("the reserved region to PAGE_NOACCESS", r, 0x100000, PAGE_NOACCESS);
    state_of("then", r);
    VirtualFree(r, 0, MEM_RELEASE);

    if (g_npvm != NULL) {
        base = p;
        size = 0x100000;
        old = 0;
        st = g_npvm(GetCurrentProcess(), &base, &size, PAGE_READWRITE, &old);
        line("NtProtectVirtualMemory to PAGE_READWRITE: status=0x%08lX old 0x%lX", (unsigned long)st, old);
    }
    VirtualFree(p, 0, MEM_RELEASE);
}

/* --- sysinfo --------------------------------------------------------------- */

static void sec_sysinfo(void)
{
    MEMORYSTATUS gms;
    BYTE buf[512];
    ULONG retlen = 0;
    LONG st;
    f2kt_system_performance_information *spi;

    if (g_nqsi == NULL) {
        line("NtQuerySystemInformation not found");
        return;
    }
    gms.dwLength = sizeof gms;
    GlobalMemoryStatus(&gms);
    memset(buf, 0, sizeof buf);
    arm();
    st = g_nqsi(F2KT_SYSTEM_PERFORMANCE_INFORMATION, buf, sizeof buf, &retlen);
    spi = (f2kt_system_performance_information *)buf;
    line("performance class: status=0x%08lX err=%s retlen>=128: %s", (unsigned long)st, le(), yesno(retlen >= 128));
    line("commit: limit pages == dwTotalPageFile/pages: %s, avail == (limit-committed): %s",
         yesno((spi->CommitLimit << 12) == gms.dwTotalPageFile),
         yesno(((spi->CommitLimit - spi->CommittedPages) << 12) == gms.dwAvailPageFile));
    line("fault counts nonzero: page faults %s, demand zero %s, transitions %s, copy-on-write %s",
         yesno(spi->PageFaultCount > 0), yesno(spi->DemandZeroCount > 0), yesno(spi->TransitionCount > 0),
         yesno(spi->CopyOnWriteCount > 0));
    line("memory load %lu <= 100: %s", gms.dwMemoryLoad, yesno(gms.dwMemoryLoad <= 100));
}

/* --- pageroundtrip --------------------------------------------------------- */

/* 16 MiB: two regions of it written exceed the small-RAM boot's free frames. */
#define F2KT_PATTERN (16u * 1024u * 1024u)

static void sec_pageroundtrip(void)
{
    BYTE *a, *b, *tmp;
    DWORD sum1, sum2;
    ULONG n = 0;
    LONG st;

    a = (BYTE *)VirtualAlloc(NULL, F2KT_PATTERN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    b = (BYTE *)VirtualAlloc(NULL, F2KT_PATTERN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    tmp = (BYTE *)VirtualAlloc(NULL, F2KT_PAGE * 16, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (a == NULL || b == NULL || tmp == NULL) {
        line("the allocations: a %s, b %s, tmp %s", yesno(a != NULL), yesno(b != NULL), yesno(tmp != NULL));
        return;
    }
    fill_pattern(a, F2KT_PATTERN);
    sum1 = checksum(a, F2KT_PATTERN);
    line("pattern written, checksum taken: %s", yesno(checksum(a, F2KT_PATTERN) == sum1));

    if (g_nrvm != NULL) {
        st = g_nrvm(GetCurrentProcess(), a, tmp, F2KT_PAGE * 16, &n);
        line("NtReadVirtualMemory of the first 64 KiB: status=0x%08lX bytes=%lu equal: %s", (unsigned long)st, n,
             yesno(n == F2KT_PAGE * 16 && memcmp(tmp, a, F2KT_PAGE * 16) == 0));
    }
    if (g_nwvm != NULL) {
        /* Write one flipped byte through the Nt call, read it back, restore. */
        tmp[0] = (BYTE)(a[0] ^ 0xFF);
        st = g_nwvm(GetCurrentProcess(), a, tmp, 1, &n);
        line("NtWriteVirtualMemory of one byte: status=0x%08lX bytes=%lu read back: %s", (unsigned long)st, n,
             yesno(a[0] == tmp[0]));
        tmp[0] = (BYTE)(a[0] ^ 0xFF);
        g_nwvm(GetCurrentProcess(), a, tmp, 1, &n);
    }

    fill_pattern(b, F2KT_PATTERN);
    sum2 = checksum(a, F2KT_PATTERN);
    line("the first 16 MiB intact after the second 16 MiB was written: %s", yesno(sum2 == sum1));
    state_of("the first region", a);
    state_of("the second region", b);
    VirtualFree(a, 0, MEM_RELEASE);
    VirtualFree(b, 0, MEM_RELEASE);
    VirtualFree(tmp, 0, MEM_RELEASE);
}

/* --- filepagein ------------------------------------------------------------ */

static void sec_filepagein(void)
{
    char path[MAX_PATH];
    char *slash;
    HANDLE f, m;
    BYTE *v, *c, *w;
    BYTE head[16];
    DWORD n, put, i;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG retlen;
    LONG st;

    GetModuleFileNameA(NULL, path, MAX_PATH);
    slash = strrchr(path, '\\');
    strcpy(slash != NULL ? slash + 1 : path, "VMPAGEIN.TMP");
    DeleteFileA(path);
    f = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        arm();
        line("CreateFile(VMPAGEIN.TMP): bad err=%s", le());
        return;
    }
    for (i = 0; i < 0x10000; i += sizeof head) {
        memset(head, (BYTE)(i * 7 + 3), sizeof head);
        WriteFile(f, head, sizeof head, &put, NULL);
    }
    arm();
    m = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0, 0, NULL);
    line("CreateFileMapping(file, PAGE_READWRITE): ret=%s err=%s", m ? "ok" : "null", le());
    if (m == NULL) {
        CloseHandle(f);
        DeleteFileA(path);
        return;
    }
    v = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    line("FILE_MAP_READ view: %s", yesno(v != NULL));
    if (v != NULL) {
        line("the view reads the file's bytes: first %s, last %s", yesno(v[0] == 3), yesno(v[0xFFFF] == (BYTE)(0xFFF0 * 7 + 3)));
        if (g_nqvm != NULL) {
            st = g_nqvm(GetCurrentProcess(), v, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
            line("NtQueryVirtualMemory over the view: status=0x%08lX type 0x40000 (MEM_MAPPED): %s state 0x1000: %s",
                 (unsigned long)st, yesno(mbi.Type == MEM_MAPPED), yesno(mbi.State == MEM_COMMIT));
        }
        c = (BYTE *)MapViewOfFile(m, FILE_MAP_COPY, 0, 0, 0);
        line("FILE_MAP_COPY view: %s", yesno(c != NULL));
        if (c != NULL) {
            memset(c, 'B', 16);
            line("the copy view's write: the read view still sees the file byte: %s", yesno(v[0] == 3));
            UnmapViewOfFile(c);
        }
        UnmapViewOfFile(v);
    }
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    memset(head, 0, sizeof head);
    ReadFile(f, head, sizeof head, &n, NULL);
    line("the file unchanged while a copy view was mapped: %s", yesno(n == sizeof head && head[0] == 3));

    /* A write view, unmapped: the file takes the write. */
    w = (BYTE *)MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0);
    line("FILE_MAP_WRITE view: %s", yesno(w != NULL));
    if (w != NULL) {
        memset(w, 'C', 16);
        UnmapViewOfFile(w);
    }
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    memset(head, 0, sizeof head);
    ReadFile(f, head, sizeof head, &n, NULL);
    line("the file changed after the write view was unmapped: %s", yesno(n == sizeof head && head[0] == 'C'));

    /* Change the file on disk with no view mapped, then map again. */
    SetFilePointer(f, 0, NULL, FILE_BEGIN);
    memset(head, 'D', sizeof head);
    WriteFile(f, head, sizeof head, &put, NULL);
    v = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    line("a remap after the file changed on disk sees the new byte: %s", yesno(v != NULL && v[0] == 'D'));
    if (v != NULL) {
        UnmapViewOfFile(v);
    }
    CloseHandle(m);
    CloseHandle(f);
    DeleteFileA(path);
}

/* --- ntqueryvm ------------------------------------------------------------- */

static void sec_ntqueryvm(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *r, *p;
    HANDLE h;
    BYTE *v;
    PVOID base;
    ULONG size;
    ULONG retlen;
    LONG st;
    void *image;

    if (g_nqvm == NULL) {
        line("NtQueryVirtualMemory not found");
        return;
    }

    /* A free region: reserve one and release it, then query the hole. */
    r = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_RESERVE, PAGE_READWRITE);
    VirtualFree(r, 0, MEM_RELEASE);
    st = g_nqvm(GetCurrentProcess(), r, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
    line("free region: status=0x%08lX retlen==sizeof: %s state 0x10000: %s", (unsigned long)st,
         yesno(retlen == sizeof mbi), yesno(mbi.State == MEM_FREE));

    r = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_RESERVE, PAGE_READWRITE);
    st = g_nqvm(GetCurrentProcess(), r, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
    line("reserved: status=0x%08lX state 0x2000: %s protect 0x0: %s region 1 MiB: %s", (unsigned long)st,
         yesno(mbi.State == MEM_RESERVE), yesno(mbi.Protect == 0), yesno(mbi.RegionSize == 0x100000));
    p = (BYTE *)VirtualAlloc(r, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    st = g_nqvm(GetCurrentProcess(), r, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
    line("committed head of it: status=0x%08lX state 0x1000: %s protect 0x4: %s region 64 KiB: %s", (unsigned long)st,
         yesno(mbi.State == MEM_COMMIT), yesno(mbi.Protect == PAGE_READWRITE), yesno(mbi.RegionSize == 0x10000));
    VirtualFree(r, 0, MEM_RELEASE);

    /* A 32 MiB commit over free space — more than the small-RAM boot's free
     * frames, so on a system that commits eagerly it is refused where a
     * demand-paging system only charges. */
    if (g_navm != NULL) {
        base = NULL;
        size = F2KT_CHUNK;
        arm();
        st = g_navm(GetCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        line("a 32 MiB commit over free space: status=0x%08lX", (unsigned long)st);
        if (base != NULL) {
            st = g_nqvm(GetCurrentProcess(), base, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
            line("over the 32 MiB: status=0x%08lX state 0x1000: %s region 32 MiB: %s", (unsigned long)st,
                 yesno(mbi.State == MEM_COMMIT), yesno(mbi.RegionSize == F2KT_CHUNK));
            VirtualFree(base, 0, MEM_RELEASE);
        }
    }

    h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x100000, NULL);
    v = h != NULL ? (BYTE *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0x100000) : NULL;
    if (v != NULL) {
        st = g_nqvm(GetCurrentProcess(), v, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
        line("a paging-file view: status=0x%08lX state 0x1000: %s type 0x40000: %s", (unsigned long)st,
             yesno(mbi.State == MEM_COMMIT), yesno(mbi.Type == MEM_MAPPED));
        UnmapViewOfFile(v);
    }
    if (h != NULL) {
        CloseHandle(h);
    }

    image = GetModuleHandleA(NULL);
    st = g_nqvm(GetCurrentProcess(), image, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
    line("the image: status=0x%08lX type 0x1000000: %s alloc base is the module: %s", (unsigned long)st,
         yesno(mbi.Type == MEM_IMAGE), yesno(mbi.AllocationBase == image));

    p = (BYTE *)VirtualAlloc(NULL, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    st = g_nqvm(GetCurrentProcess(), p, F2KT_MEMORY_BASIC_INFORMATION, &mbi, 16, &retlen);
    line("a 16-byte buffer: status=0x%08lX is 0x%08lX (info length mismatch): %s", (unsigned long)st,
         F2KT_STATUS_INFO_LENGTH_MISMATCH, yesno((unsigned long)st == F2KT_STATUS_INFO_LENGTH_MISMATCH));
    st = g_nqvm(GetCurrentProcess(), p, 99, &mbi, sizeof mbi, &retlen);
    line("class 99: status=0x%08lX is 0x%08lX (invalid info class): %s", (unsigned long)st,
         F2KT_STATUS_INVALID_INFO_CLASS, yesno((unsigned long)st == F2KT_STATUS_INVALID_INFO_CLASS));
    VirtualFree(p, 0, MEM_RELEASE);
}

/* --- trimpressure ---------------------------------------------------------- */

static void sec_trimpressure(void)
{
    MEMORYSTATUS gms;
    BYTE *a, *b;
    DWORD sum1, sum2;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG retlen;
    LONG st;

    gms.dwLength = sizeof gms;
    GlobalMemoryStatus(&gms);
    a = (BYTE *)VirtualAlloc(NULL, F2KT_PATTERN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    b = (BYTE *)VirtualAlloc(NULL, F2KT_PATTERN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (a == NULL || b == NULL) {
        line("the allocations: a %s, b %s", yesno(a != NULL), yesno(b != NULL));
        return;
    }
    fill_pattern(a, F2KT_PATTERN);
    sum1 = checksum(a, F2KT_PATTERN);
    fill_pattern(b, F2KT_PATTERN);
    sum2 = checksum(a, F2KT_PATTERN);
    line("the first 16 MiB intact after the second 16 MiB: %s", yesno(sum2 == sum1));
    GlobalMemoryStatus(&gms);
    line("available commit still > 0: %s", yesno(gms.dwAvailPageFile > 0));
    if (g_nqvm != NULL) {
        st = g_nqvm(GetCurrentProcess(), a, F2KT_MEMORY_BASIC_INFORMATION, &mbi, sizeof mbi, &retlen);
        line("the first region after the pressure: status=0x%08lX still state 0x1000: %s", (unsigned long)st,
             yesno(mbi.State == MEM_COMMIT));
    }
    VirtualFree(a, 0, MEM_RELEASE);
    VirtualFree(b, 0, MEM_RELEASE);
}

/* --- main ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "commitlimit", sec_commitlimit, F2KT_ALWAYS },
    { "reservelarge", sec_reservelarge, F2KT_ALWAYS },
    { "resetcommit", sec_resetcommit, F2KT_ALWAYS },
    { "prottrans", sec_prottrans, F2KT_ALWAYS },
    { "sysinfo", sec_sysinfo, F2KT_ALWAYS },
    { "pageroundtrip", sec_pageroundtrip, F2KT_ALWAYS },
    { "filepagein", sec_filepagein, F2KT_ALWAYS },
    { "ntqueryvm", sec_ntqueryvm, F2KT_ALWAYS },
    { "trimpressure", sec_trimpressure, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    resolve();
    return run_sections("vmdemand", sections, argc, argv);
}
