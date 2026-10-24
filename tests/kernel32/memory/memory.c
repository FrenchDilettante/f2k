/*
 * memory - allocation, address space, and stacks.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   sysinfo  GetSystemInfo and GlobalMemoryStatus: page size,
 *            allocation granularity, the user address range
 *   malloc   the C runtime heap the way programs use it: thousands of
 *            small blocks (the small-block heap, its 32 KiB groups
 *            committed and decommitted underneath), more than 1 MiB of
 *            small blocks (a second reservation), large blocks of 4 and
 *            16 MiB and 32 MiB cumulatively, calloc zeroing over dirty
 *            memory, realloc growing a buffer by doubling from 2 KiB to
 *            4 MiB with its contents intact, _msize, _heapchk
 *   heap     the Win32 heap: the process heap, HeapSize, zeroing,
 *            HeapReAlloc in place and moving, private heaps that are
 *            distinct and independent (destroying one leaves the others
 *            and the CRT's blocks intact), a capped heap refusing to
 *            grow, HEAP_GENERATE_EXCEPTIONS, HeapValidate
 *   local    LocalAlloc/GlobalAlloc: fixed and moveable blocks, locks,
 *            sizes, reallocation, handles from pointers
 *   virtual  VirtualAlloc/VirtualFree/VirtualQuery: reservation
 *            granularity, partial commits, region queries, decommit and
 *            recommit (zeroed again), release, explicit addresses and
 *            their conflicts, many reservations, a 256 MiB reservation
 *            committed in pieces, invalid requests
 *   protect  VirtualProtect and its effects: read-only and no-access
 *            pages fault (caught with __try), guard pages fire once,
 *            IsBadReadPtr/IsBadWritePtr/IsBadCodePtr/IsBadStringPtrA
 *   image    the program image as VirtualQuery reports it: each
 *            section's protection, the image type, the headers
 *   mapping  CreateFileMapping over the paging file: two views alias,
 *            offset views and their granularity, named mappings,
 *            views outliving the handle, UnmapViewOfFile
 *   stack    stack growth on the main thread (recursion, a 64 KiB
 *            local, _alloca), the stack reservation and guard page, a
 *            child thread with a requested stack size, a child that
 *            overflows and catches it
 *
 * The named mappings run twice: through the A calls, then through their
 * W twins on the same names (the W lines carry the W names, or "(W)");
 * image also finds its base through GetModuleHandleW, and protect probes
 * a wide literal with IsBadStringPtrW (its limit in characters).
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo memory.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <malloc.h>
#include <errno.h>

#define KB 1024u
#define MB (1024u * 1024u)

/* --- helpers ------------------------------------------------------- */

static void fill(BYTE *p, DWORD n, DWORD seed)
{
    DWORD i;

    for (i = 0; i < n; i++) {
        p[i] = (BYTE)(seed + i * 31 + (i >> 8));
    }
}

static int check(const BYTE *p, DWORD n, DWORD seed)
{
    DWORD i;

    for (i = 0; i < n; i++) {
        if (p[i] != (BYTE)(seed + i * 31 + (i >> 8))) {
            return 0;
        }
    }
    return 1;
}

static int all_zero(const BYTE *p, DWORD n)
{
    DWORD i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Touch one byte per page and the last byte; verify them back. */
static int touch_pages(BYTE *p, DWORD n, BYTE tag)
{
    DWORD i;

    for (i = 0; i < n; i += 4096) {
        p[i] = (BYTE)(tag + i / 4096);
    }
    p[n - 1] = tag;
    for (i = 0; i < n; i += 4096) {
        if (p[i] != (BYTE)(tag + i / 4096)) {
            return 0;
        }
    }
    return p[n - 1] == tag;
}

static DWORD lcg_state;

static DWORD lcg(void)
{
    lcg_state = lcg_state * 1103515245u + 12345u;
    return (lcg_state >> 8) & 0xFFFFFF;
}

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

static void query(const char *what, const void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD n;

    arm();
    n = VirtualQuery(addr, &mbi, sizeof mbi);
    if (n == 0) {
        line("%s: VirtualQuery ret=0 err=%s", what, le());
        return;
    }
    line("%s: state 0x%lX protect 0x%lX type 0x%lX region 0x%lX allocprotect 0x%lX",
         what, mbi.State, mbi.Protect, mbi.Type, mbi.RegionSize, mbi.AllocationProtect);
}

/* --- sysinfo ------------------------------------------------------- */

static void sec_sysinfo(void)
{
    SYSTEM_INFO si;
    MEMORYSTATUS ms;

    GetSystemInfo(&si);
    line("page size 0x%lX granularity 0x%lX", si.dwPageSize, si.dwAllocationGranularity);
    line("application range 0x%08lX..0x%08lX",
         (DWORD)si.lpMinimumApplicationAddress, (DWORD)si.lpMaximumApplicationAddress);
    line("processor architecture %u, processors %lu", si.wProcessorArchitecture, si.dwNumberOfProcessors);

    ms.dwLength = sizeof ms;
    GlobalMemoryStatus(&ms);
    line("GlobalMemoryStatus: length %lu, total virtual 0x%08lX, physical at least 16 MiB %s",
         ms.dwLength, ms.dwTotalVirtual, yesno(ms.dwTotalPhys >= 16 * MB));
}

/* --- malloc -------------------------------------------------------- */

#define SMALL_BLOCKS 3000

static BYTE *blocks[SMALL_BLOCKS];
static DWORD sizes[SMALL_BLOCKS];

static void sec_malloc(void)
{
    int i, j, round;
    int ok, aligned, nulls;
    BYTE *p;
    BYTE *q;
    DWORD n;
    DWORD total;

    /* 1000 small blocks of 1..1000 bytes. */
    ok = 1;
    aligned = 1;
    nulls = 0;
    for (i = 0; i < 1000; i++) {
        sizes[i] = (DWORD)(i * 37) % 1000 + 1;
        blocks[i] = (BYTE *)malloc(sizes[i]);
        if (blocks[i] == NULL) {
            nulls++;
            continue;
        }
        aligned &= ((DWORD)blocks[i] & 7) == 0;
        fill(blocks[i], sizes[i], i);
    }
    for (i = 0; i < 1000; i++) {
        ok &= blocks[i] != NULL && check(blocks[i], sizes[i], i);
    }
    line("1000 small blocks: failures %d, 8-byte aligned %s, contents intact %s", nulls, yesno(aligned), yesno(ok));

    for (i = 1; i < 1000; i += 2) {
        free(blocks[i]);
        sizes[i] = (DWORD)(i * 53) % 900 + 17;
        blocks[i] = (BYTE *)malloc(sizes[i]);
        if (blocks[i] != NULL) {
            fill(blocks[i], sizes[i], i + 7);
        }
    }
    ok = 1;
    for (i = 0; i < 1000; i++) {
        ok &= blocks[i] != NULL && check(blocks[i], sizes[i], (i & 1) ? i + 7 : i);
    }
    line("odd blocks freed and reallocated: everything intact %s", yesno(ok));
    for (i = 0; i < 1000; i++) {
        free(blocks[i]);
        blocks[i] = NULL;
    }

    /* Churn: allocate 200, verify, free in a scrambled order; 20 rounds. */
    ok = 1;
    lcg_state = 1;
    for (round = 0; round < 20; round++) {
        for (i = 0; i < 200; i++) {
            sizes[i] = lcg() % 1016 + 1;
            blocks[i] = (BYTE *)malloc(sizes[i]);
            if (blocks[i] == NULL) {
                ok = 0;
            } else {
                fill(blocks[i], sizes[i], round * 1000 + i);
            }
        }
        for (i = 0; i < 200; i++) {
            j = (i * 7) % 200;
            ok &= blocks[j] != NULL && check(blocks[j], sizes[j], round * 1000 + j);
            free(blocks[j]);
            blocks[j] = NULL;
        }
    }
    line("20 rounds of 200 blocks freed in scrambled order: intact %s", yesno(ok));

    /* Past 1 MiB of small blocks: the small-block heap needs more regions. */
    for (round = 0; round < 2; round++) {
        nulls = 0;
        for (i = 0; i < SMALL_BLOCKS; i++) {
            sizes[i] = 500;
            blocks[i] = (BYTE *)malloc(500);
            if (blocks[i] == NULL) {
                nulls++;
            } else {
                fill(blocks[i], 500, i + round);
            }
        }
        ok = 1;
        for (i = 0; i < SMALL_BLOCKS; i++) {
            ok &= blocks[i] != NULL && check(blocks[i], 500, i + round);
            free(blocks[i]);
            blocks[i] = NULL;
        }
        line("1.5 MiB of 500-byte blocks, pass %d: failures %d, intact %s", round + 1, nulls, yesno(ok));
    }

    /* Large blocks. */
    p = (BYTE *)malloc(4 * MB);
    line("malloc(4 MiB): %s", p != NULL && touch_pages(p, 4 * MB, 0x41) ? "ok" : "failed");
    free(p);
    p = (BYTE *)malloc(16 * MB);
    line("malloc(16 MiB): %s", p != NULL && touch_pages(p, 16 * MB, 0x42) ? "ok" : "failed");
    free(p);
    nulls = 0;
    ok = 1;
    for (i = 0; i < 32; i++) {
        blocks[i] = (BYTE *)malloc(MB);
        if (blocks[i] == NULL) {
            nulls++;
        } else {
            ok &= touch_pages(blocks[i], MB, (BYTE)i);
        }
    }
    for (i = 0; i < 32; i++) {
        free(blocks[i]);
        blocks[i] = NULL;
    }
    line("32 blocks of 1 MiB live at once: failures %d, intact %s", nulls, yesno(ok));

    p = (BYTE *)malloc(0);
    q = (BYTE *)malloc(0);
    line("malloc(0): non-null %s, distinct %s", yesno(p != NULL && q != NULL), yesno(p != q));
    free(p);
    free(q);
    errno = 0;
    p = (BYTE *)malloc(0x7FFFFFF0);
    line("malloc(0x7FFFFFF0): null %s errno %d", yesno(p == NULL), errno);
    free(p);
    free(NULL);
    line("free(NULL): survived");

    /* calloc over dirty memory. */
    p = (BYTE *)malloc(4000);
    if (p != NULL) {
        memset(p, 0xFF, 4000);
    }
    free(p);
    p = (BYTE *)malloc(400);
    if (p != NULL) {
        memset(p, 0xFF, 400);
    }
    free(p);
    p = (BYTE *)calloc(1000, 4);
    q = (BYTE *)calloc(100, 4);
    line("calloc over freed dirty blocks: large zero %s, small zero %s",
         yesno(p != NULL && all_zero(p, 4000)), yesno(q != NULL && all_zero(q, 400)));
    free(p);
    free(q);

    /* realloc: double a buffer from 2 KiB to 4 MiB, contents intact. */
    n = 2 * KB;
    p = (BYTE *)malloc(n);
    ok = p != NULL;
    if (ok) {
        fill(p, n, 99);
    }
    total = n;
    while (ok && n < 4 * MB) {
        q = (BYTE *)realloc(p, n * 2);
        if (q == NULL) {
            ok = 0;
            break;
        }
        p = q;
        ok = check(p, n, 99);
        fill(p + n, n, 99 + n);
        ok &= check(p + n, n, 99 + n);
        /* Re-fill the whole buffer with one seed so the next check covers it. */
        fill(p, n * 2, 99);
        n *= 2;
        total = n;
    }
    line("realloc doubling 2 KiB -> 4 MiB: %s (reached %lu KiB)", ok ? "ok" : "failed", total / KB);
    q = ok ? (BYTE *)realloc(p, 100) : NULL;
    line("realloc shrink 4 MiB -> 100 bytes: %s", q != NULL && check(q, 100, 99) ? "ok" : "failed");
    free(q != NULL ? q : p);

    p = (BYTE *)realloc(NULL, 50);
    line("realloc(NULL, 50): non-null %s", yesno(p != NULL));
    q = (BYTE *)realloc(p, 0);
    line("realloc(p, 0): returned null %s", yesno(q == NULL));

    p = (BYTE *)malloc(500);
    fill(p, 500, 5);
    p = (BYTE *)realloc(p, 5000);
    ok = p != NULL && check(p, 500, 5);
    p = (BYTE *)realloc(p, 300);
    ok &= p != NULL && check(p, 300, 5);
    line("realloc across the small-block threshold and back: %s", ok ? "ok" : "failed");
    free(p);

    p = (BYTE *)malloc(100);
    q = (BYTE *)malloc(5000);
    line("_msize: malloc(100) -> %u, malloc(5000) -> %u", _msize(p), _msize(q));
    free(p);
    free(q);

    line("_heapchk: %d", _heapchk());
}

/* --- heap ---------------------------------------------------------- */

static void sec_heap(void)
{
    HANDLE ph, h1, h2, hx;
    BYTE *p, *q, *a, *b, *a1, *a2, *m, *pp, *big;
    DWORD sz;
    int count, ok, raised;
    DWORD code;
    BOOL r;

    ph = GetProcessHeap();
    line("GetProcessHeap: non-null %s", yesno(ph != NULL));

    p = (BYTE *)HeapAlloc(ph, 0, 100);
    arm();
    sz = HeapSize(ph, 0, p);
    line("HeapAlloc(100): 8-byte aligned %s, HeapSize %lu err=%s", yesno(((DWORD)p & 7) == 0), sz, le());
    fill(p, 100, 1);

    q = (BYTE *)HeapAlloc(ph, HEAP_ZERO_MEMORY, 4096);
    line("HEAP_ZERO_MEMORY: zero %s", yesno(q != NULL && all_zero(q, 4096)));
    HeapFree(ph, 0, q);

    q = (BYTE *)HeapReAlloc(ph, 0, p, 10000);
    line("HeapReAlloc grow: contents %s, HeapSize %lu",
         q != NULL && check(q, 100, 1) ? "intact" : "lost", q != NULL ? HeapSize(ph, 0, q) : 0);
    p = q != NULL ? q : p;
    q = (BYTE *)HeapReAlloc(ph, HEAP_ZERO_MEMORY, p, 20000);
    line("HeapReAlloc grow with HEAP_ZERO_MEMORY: extension zero %s",
         yesno(q != NULL && check(q, 100, 1) && all_zero(q + 10000, 10000)));
    p = q != NULL ? q : p;
    q = (BYTE *)HeapReAlloc(ph, HEAP_REALLOC_IN_PLACE_ONLY, p, 50);
    line("HeapReAlloc in-place shrink: same block %s, HeapSize %lu", yesno(q == p), HeapSize(ph, 0, p));
    arm();
    r = HeapFree(ph, 0, p);
    line("HeapFree: ret=%d err=%s", r, le());

    a = (BYTE *)HeapAlloc(ph, 0, 64);
    b = (BYTE *)HeapAlloc(ph, 0, 64);
    arm();
    q = (BYTE *)HeapReAlloc(ph, HEAP_REALLOC_IN_PLACE_ONLY, a, 64 * KB);
    line("HeapReAlloc in-place growth into a neighbour: null %s err=%s", yesno(q == NULL), le());
    HeapFree(ph, 0, a);
    HeapFree(ph, 0, b);

    h1 = HeapCreate(0, 0, 0);
    h2 = HeapCreate(0, 64 * KB, 128 * KB);
    line("HeapCreate: growable %s, capped %s, distinct from each other and the process heap %s",
         yesno(h1 != NULL), yesno(h2 != NULL), yesno(h1 != h2 && h1 != ph && h2 != ph));

    a1 = (BYTE *)HeapAlloc(h1, 0, 1000);
    a2 = (BYTE *)HeapAlloc(h2, 0, 1000);
    m = (BYTE *)malloc(1000);
    pp = (BYTE *)HeapAlloc(ph, 0, 1000);
    fill(a1, 1000, 11);
    fill(a2, 1000, 22);
    fill(m, 1000, 33);
    fill(pp, 1000, 44);
    line("blocks from four heaps are distinct: %s", yesno(a1 != a2 && a1 != m && a1 != pp && a2 != m && a2 != pp && m != pp));

    big = (BYTE *)HeapAlloc(h1, 0, 8 * MB);
    line("growable heap: 8 MiB block %s", big != NULL && touch_pages(big, 8 * MB, 0x55) ? "ok" : "failed");

    count = 0;
    while (count < 64 && HeapAlloc(h2, 0, 16 * KB) != NULL) {
        count++;
    }
    line("capped heap (128 KiB): 16 KiB blocks before refusal %d", count);
    arm();
    r = HeapValidate(h2, 0, NULL);
    line("HeapValidate(capped): ret=%d err=%s", r, le());

    arm();
    r = HeapDestroy(h1);
    line("HeapDestroy(growable): ret=%d err=%s", r, le());
    ok = check(a2, 1000, 22) && check(m, 1000, 33) && check(pp, 1000, 44);
    line("after destroying one heap the others are intact: %s", yesno(ok));
    arm();
    r = HeapDestroy(h2);
    line("HeapDestroy(capped): ret=%d err=%s", r, le());
    ok = check(m, 1000, 33) && check(pp, 1000, 44);
    line("CRT and process heap blocks still intact: %s", yesno(ok));
    free(m);
    HeapFree(ph, 0, pp);

    hx = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0, 64 * KB);
    raised = 0;
    code = 0;
    __try {
        for (count = 0; count < 64; count++) {
            HeapAlloc(hx, 0, 16 * KB);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        raised = 1;
        code = GetExceptionCode();
    }
    line("HEAP_GENERATE_EXCEPTIONS over the cap: raised %s code 0x%08lX", yesno(raised), code);
    HeapDestroy(hx);
}

/* --- local --------------------------------------------------------- */

static void sec_local(void)
{
    HLOCAL l, l2;
    HGLOBAL g, g2;
    BYTE *p;
    UINT flags;

    l = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, 100);
    line("LocalAlloc(fixed, zeroinit): zero %s, LocalSize %u",
         yesno(l != NULL && all_zero((BYTE *)l, 100)), LocalSize(l));
    fill((BYTE *)l, 100, 3);
    l2 = LocalReAlloc(l, 5000, LMEM_MOVEABLE);
    line("LocalReAlloc(5000, moveable): contents %s, LocalSize %u",
         l2 != NULL && check((BYTE *)l2, 100, 3) ? "intact" : "lost", LocalSize(l2));
    line("LocalFree: returned null %s", yesno(LocalFree(l2 != NULL ? l2 : l) == NULL));

    l = LocalAlloc(LMEM_MOVEABLE, 200);
    p = (BYTE *)LocalLock(l);
    flags = LocalFlags(l);
    line("LocalAlloc(moveable): handle is not the pointer %s, lock count %u",
         yesno(p != NULL && (void *)p != (void *)l), flags & LMEM_LOCKCOUNT);
    line("LocalHandle(pointer) gives the handle back: %s", yesno(LocalHandle(p) == l));
    LocalUnlock(l);
    line("LocalFree(moveable): returned null %s", yesno(LocalFree(l) == NULL));

    g = GlobalAlloc(GMEM_FIXED, 100);
    line("GlobalAlloc(fixed): usable as a pointer %s, GlobalSize %lu",
         yesno(g != NULL && GlobalLock(g) == (void *)g), GlobalSize(g));
    GlobalUnlock(g);
    line("GlobalFree: returned null %s", yesno(GlobalFree(g) == NULL));

    g = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 300);
    p = (BYTE *)GlobalLock(g);
    line("GlobalAlloc(moveable, zeroinit): zero %s, handle from pointer %s",
         yesno(p != NULL && all_zero(p, 300)), yesno(GlobalHandle(p) == g));
    fill(p, 300, 9);
    GlobalUnlock(g);
    g2 = GlobalReAlloc(g, 9000, GMEM_MOVEABLE);
    p = (BYTE *)GlobalLock(g2);
    line("GlobalReAlloc(9000): contents %s, GlobalSize %lu",
         p != NULL && check(p, 300, 9) ? "intact" : "lost", GlobalSize(g2));
    GlobalUnlock(g2);
    line("GlobalFree(moveable): returned null %s", yesno(GlobalFree(g2) == NULL));
}

/* --- virtual ------------------------------------------------------- */

static void sec_virtual(void)
{
    BYTE *p, *big, *c, *q;
    BYTE *many[64];
    int i, ok, nulls;
    BOOL r;

    arm();
    p = (BYTE *)VirtualAlloc(NULL, 1, MEM_RESERVE, PAGE_NOACCESS);
    line("reserve 1 byte: non-null %s, 64 KiB aligned %s err=%s",
         yesno(p != NULL), yesno(((DWORD)p & 0xFFFF) == 0), le());
    query("reserved byte", p);
    arm();
    r = VirtualFree(p, 0, MEM_RELEASE);
    line("release: ret=%d err=%s", r, le());
    query("released", p);

    big = (BYTE *)VirtualAlloc(NULL, MB, MEM_RESERVE, PAGE_READWRITE);
    line("reserve 1 MiB: non-null %s", yesno(big != NULL));
    if (big == NULL) {
        return;
    }
    arm();
    c = (BYTE *)VirtualAlloc(big + 0x10000, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    line("commit two pages inside: at the requested address %s err=%s", yesno(c == big + 0x10000), le());
    query("region before the commit", big);
    query("committed pages", big + 0x10000);
    query("region after the commit", big + 0x12000);
    line("committed pages are zero: %s", yesno(c != NULL && all_zero(c, 0x2000)));
    if (c != NULL) {
        fill(c, 0x2000, 7);
    }
    arm();
    r = VirtualFree(big + 0x10000, 0x2000, MEM_DECOMMIT);
    line("decommit: ret=%d err=%s", r, le());
    query("decommitted", big + 0x10000);
    c = (BYTE *)VirtualAlloc(big + 0x10000, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    line("recommit: zero again %s", yesno(c != NULL && all_zero(c, 0x2000)));
    if (c != NULL) {
        fill(c, 0x2000, 8);
    }
    q = (BYTE *)VirtualAlloc(big + 0x11000, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    line("commit overlapping a committed page: ok %s, its contents kept %s",
         yesno(q == big + 0x11000), yesno(c != NULL && check(c, 0x2000, 8)));
    arm();
    r = VirtualFree(big, 0x1000, MEM_RELEASE);
    line("release with a nonzero size: ret=%d err=%s", r, le());
    arm();
    r = VirtualFree(big + 0x10000, 0, MEM_RELEASE);
    line("release not at the allocation base: ret=%d err=%s", r, le());
    arm();
    r = VirtualFree(big, 0, MEM_RELEASE);
    line("release the 1 MiB reservation: ret=%d err=%s", r, le());

    arm();
    p = (BYTE *)VirtualAlloc((void *)0x20000000, 0x10000, MEM_RESERVE, PAGE_READWRITE);
    line("reserve at 0x20000000: returned 0x%08lX err=%s", (DWORD)p, le());
    arm();
    q = (BYTE *)VirtualAlloc((void *)0x20000000, 0x10000, MEM_RESERVE, PAGE_READWRITE);
    line("reserve the same range again: returned 0x%08lX err=%s", (DWORD)q, le());
    VirtualFree(p, 0, MEM_RELEASE);
    arm();
    p = (BYTE *)VirtualAlloc((void *)0x30001234, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    line("reserve+commit at 0x30001234: returned 0x%08lX err=%s", (DWORD)p, le());
    query("its region", p != NULL ? p : (BYTE *)0x30001234);
    if (p != NULL) {
        VirtualFree((void *)((DWORD)p & 0xFFFF0000u), 0, MEM_RELEASE);
    }
    arm();
    p = (BYTE *)VirtualAlloc((void *)0x40000000, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    line("commit without a reservation: returned 0x%08lX err=%s", (DWORD)p, le());

    p = (BYTE *)VirtualAlloc(NULL, 3 * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    line("reserve+commit 3 pages: zero %s", yesno(p != NULL && all_zero(p, 3 * 4096)));
    VirtualFree(p, 0, MEM_RELEASE);

    nulls = 0;
    ok = 1;
    for (i = 0; i < 64; i++) {
        many[i] = (BYTE *)VirtualAlloc(NULL, 64 * KB, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (many[i] == NULL) {
            nulls++;
        } else {
            many[i][0] = (BYTE)i;
        }
    }
    for (i = 0; i < 64; i++) {
        if (many[i] != NULL) {
            ok &= many[i][0] == (BYTE)i;
            ok &= VirtualFree(many[i], 0, MEM_RELEASE) != 0;
        }
    }
    line("64 reservations of 64 KiB: failures %d, all distinct and released %s", nulls, yesno(ok));

    big = (BYTE *)VirtualAlloc(NULL, 256 * MB, MEM_RESERVE, PAGE_READWRITE);
    line("reserve 256 MiB: non-null %s", yesno(big != NULL));
    if (big != NULL) {
        ok = 1;
        for (i = 0; i < 16; i++) {
            c = (BYTE *)VirtualAlloc(big + i * 16 * MB, 256 * KB, MEM_COMMIT, PAGE_READWRITE);
            ok &= c != NULL && touch_pages(c, 256 * KB, (BYTE)i);
        }
        line("commit 16 pieces of 256 KiB across it: %s", ok ? "ok" : "failed");
        query("an uncommitted gap", big + 8 * MB);
        VirtualFree(big, 0, MEM_RELEASE);
    }

    arm();
    p = (BYTE *)VirtualAlloc(NULL, 0, MEM_RESERVE, PAGE_READWRITE);
    line("reserve 0 bytes: returned 0x%08lX err=%s", (DWORD)p, le());
    arm();
    p = (BYTE *)VirtualAlloc(NULL, 4096, MEM_RESERVE, 0x7);
    line("reserve with a bad protection: returned 0x%08lX err=%s", (DWORD)p, le());
    arm();
    p = (BYTE *)VirtualAlloc((void *)0x80000000, 4096, MEM_RESERVE, PAGE_READWRITE);
    line("reserve at 0x80000000: returned 0x%08lX err=%s", (DWORD)p, le());
    query("0x80000000", (void *)0x80000000);
}

/* --- protect ------------------------------------------------------- */

static DWORD fault_code;
static DWORD fault_info[2];

static int fault_filter(EXCEPTION_POINTERS *ep)
{
    fault_code = ep->ExceptionRecord->ExceptionCode;
    fault_info[0] = ep->ExceptionRecord->NumberParameters > 0 ? ep->ExceptionRecord->ExceptionInformation[0] : 0;
    fault_info[1] = ep->ExceptionRecord->NumberParameters > 1 ? ep->ExceptionRecord->ExceptionInformation[1] : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}

/* Write (or read) one byte at `p` under __try: 0 when it worked. */
static int probe(BYTE *p, int write)
{
    volatile BYTE v;

    fault_code = 0;
    __try {
        if (write) {
            *(volatile BYTE *)p = 0x5A;
        } else {
            v = *(volatile BYTE *)p;
        }
    } __except (fault_filter(GetExceptionInformation())) {
        return 1;
    }
    return 0;
}

static const char rdata_text[] = "read-only";
static const WCHAR rdata_wtext[] = L"read-only";

static int code_probe(void)
{
    return 1;
}

static void sec_protect(void)
{
    BYTE *p;
    DWORD old;
    BOOL r;
    int faulted;

    p = (BYTE *)VirtualAlloc(NULL, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p == NULL) {
        line("protect: VirtualAlloc failed");
        return;
    }
    fill(p, 0x3000, 1);

    arm();
    r = VirtualProtect(p, 0x1000, PAGE_READONLY, &old);
    line("VirtualProtect read-only: ret=%d old 0x%lX err=%s", r, old, le());
    query("read-only page", p);
    line("read-only page still reads: %s", yesno(!probe(p, 0) && check(p, 0x1000, 1)));
    faulted = probe(p, 1);
    line("write to it: faulted %s code 0x%08lX write %lu address matches %s",
         yesno(faulted), fault_code, fault_info[0], yesno(fault_info[1] == (DWORD)p));
    line("IsBadWritePtr %d IsBadReadPtr %d", IsBadWritePtr(p, 4), IsBadReadPtr(p, 4));

    arm();
    r = VirtualProtect(p + 0x1000, 0x1000, PAGE_NOACCESS, &old);
    line("VirtualProtect no-access: ret=%d old 0x%lX err=%s", r, old, le());
    faulted = probe(p + 0x1000, 0);
    line("read from it: faulted %s code 0x%08lX write %lu", yesno(faulted), fault_code, fault_info[0]);
    line("IsBadReadPtr %d", IsBadReadPtr(p + 0x1000, 4));

    arm();
    r = VirtualProtect(p + 0x2000, 0x1000, PAGE_READWRITE | PAGE_GUARD, &old);
    line("VirtualProtect guard: ret=%d old 0x%lX err=%s", r, old, le());
    faulted = probe(p + 0x2000, 0);
    line("first touch: faulted %s code 0x%08lX", yesno(faulted), fault_code);
    faulted = probe(p + 0x2000, 0);
    line("second touch: faulted %s", yesno(faulted));
    query("guard page after firing", p + 0x2000);

    arm();
    r = VirtualProtect(p, 0x3000, PAGE_READWRITE, &old);
    line("VirtualProtect all back to read-write: ret=%d old 0x%lX err=%s", r, old, le());
    line("contents survived the protection changes: %s", yesno(check(p, 0x3000, 1)));
    arm();
    r = VirtualProtect(p, 0x10000, PAGE_READWRITE, &old);
    line("VirtualProtect past the committed range: ret=%d err=%s", r, le());
    VirtualFree(p, 0, MEM_RELEASE);

    line("IsBadReadPtr(NULL) %d", IsBadReadPtr(NULL, 1));
    line("IsBadWritePtr(.rdata) %d", IsBadWritePtr((void *)rdata_text, 1));
    line("IsBadCodePtr(function) %d", IsBadCodePtr((FARPROC)code_probe));
    line("IsBadStringPtrA(literal) %d", IsBadStringPtrA(rdata_text, 64));
    line("IsBadStringPtrW(literal) %d", IsBadStringPtrW(rdata_wtext, 64));
    line("IsBadReadPtr(0x80000000) %d", IsBadReadPtr((void *)0x80000000, 1));
}

/* --- image --------------------------------------------------------- */

static void sec_image(void)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    MEMORY_BASIC_INFORMATION mbi;
    char name[9];
    WORD i;

    query("headers", base);
    VirtualQuery(base, &mbi, sizeof mbi);
    line("headers: allocation base is the image %s", yesno(mbi.AllocationBase == base));
    line("GetModuleHandleW(NULL): the same base %s", yesno((BYTE *)GetModuleHandleW(NULL) == base));
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy(name, sec[i].Name, 8);
        name[8] = 0;
        VirtualQuery(base + sec[i].VirtualAddress, &mbi, sizeof mbi);
        line("section %s: protect 0x%lX type 0x%lX same allocation %s",
             name, mbi.Protect, mbi.Type, yesno(mbi.AllocationBase == base));
    }
    query("past the image end", base + nt->OptionalHeader.SizeOfImage);
}

/* --- mapping ------------------------------------------------------- */

/* The named mappings, through the A calls or (wide) their W twins. */
static void named_mappings(int wide)
{
    const char *aw = wide ? "W" : "A";
    const char *tag = wide ? " (W)" : "";
    HANDLE m2, m3, o;
    BYTE *v4;

    arm();
    m2 = wide ? CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, L"F2K.memory.map")
              : CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, "F2K.memory.map");
    line("named mapping%s: non-null %s err=%s", tag, yesno(m2 != NULL), le());
    arm();
    m3 = wide ? CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, L"F2K.memory.map")
              : CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, "F2K.memory.map");
    line("named mapping again%s: non-null %s err=%s", tag, yesno(m3 != NULL), le());
    if (m3 != NULL) {
        CloseHandle(m3);
    }
    o = wide ? OpenFileMappingW(FILE_MAP_READ, FALSE, L"F2K.memory.map")
             : OpenFileMappingA(FILE_MAP_READ, FALSE, "F2K.memory.map");
    if (m2 != NULL && o != NULL) {
        v4 = (BYTE *)MapViewOfFile(m2, FILE_MAP_WRITE, 0, 0, 0);
        v4[100] = 0xA5;
        UnmapViewOfFile(v4);
        v4 = (BYTE *)MapViewOfFile(o, FILE_MAP_READ, 0, 0, 0);
        line("OpenFileMapping%s sees the named mapping's data: %s", aw, yesno(v4 != NULL && v4[100] == 0xA5));
        UnmapViewOfFile(v4);
    }
    arm();
    m3 = wide ? OpenFileMappingW(FILE_MAP_READ, FALSE, L"F2K.memory.nosuch")
              : OpenFileMappingA(FILE_MAP_READ, FALSE, "F2K.memory.nosuch");
    line("OpenFileMapping%s(missing): null %s err=%s", aw, yesno(m3 == NULL), le());
    if (m3 != NULL) {
        CloseHandle(m3);
    }
    /* Close every handle, so the W pass creates the name afresh. */
    if (o != NULL) {
        CloseHandle(o);
    }
    CloseHandle(m2);
}

static void sec_mapping(void)
{
    HANDLE m;
    BYTE *v1, *v2, *v3, *v4;
    MEMORY_BASIC_INFORMATION mbi;
    BOOL r;

    arm();
    m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MB, NULL);
    line("CreateFileMappingA(paging file, 1 MiB): non-null %s err=%s", yesno(m != NULL), le());
    if (m == NULL) {
        return;
    }
    v1 = (BYTE *)MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0);
    v2 = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    line("two views: both mapped %s, distinct %s, zero %s", yesno(v1 != NULL && v2 != NULL),
         yesno(v1 != v2), yesno(v1 != NULL && all_zero(v1, MB)));
    if (v1 == NULL || v2 == NULL) {
        return;
    }
    fill(v1, MB, 77);
    line("a write through one view shows in the other: %s", yesno(check(v2, MB, 77)));
    VirtualQuery(v1, &mbi, sizeof mbi);
    line("view: type 0x%lX protect 0x%lX region 0x%lX", mbi.Type, mbi.Protect, mbi.RegionSize);

    v3 = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0x10000, 0x1000);
    line("view at offset 64 KiB: sees the data %s", yesno(v3 != NULL && v3[0] == v1[0x10000]));
    arm();
    v4 = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0x1000, 0x1000);
    line("view at offset 4 KiB: null %s err=%s", yesno(v4 == NULL), le());

    named_mappings(0);
    named_mappings(1);

    arm();
    r = CloseHandle(m);
    line("close the mapping handle with views mapped: ret=%d err=%s", r, le());
    line("views still valid: %s", yesno(check(v2, MB, 77)));
    arm();
    r = UnmapViewOfFile(v1);
    line("UnmapViewOfFile: ret=%d err=%s", r, le());
    line("the other view keeps the data: %s", yesno(check(v2, MB, 77)));
    arm();
    r = UnmapViewOfFile(v1);
    line("UnmapViewOfFile again: ret=%d err=%s", r, le());
    if (v3 != NULL) {
        UnmapViewOfFile(v3);
    }
    UnmapViewOfFile(v2);
}

/* --- stack --------------------------------------------------------- */

static DWORD recurse(DWORD depth)
{
    volatile BYTE pad[1024];

    pad[1023] = (BYTE)depth;
    pad[0] = (BYTE)depth;
    if (depth == 0) {
        return 0;
    }
    return recurse(depth - 1) + pad[0] - pad[1023];
}

static int big_local(void)
{
    volatile BYTE buf[64 * 1024];

    buf[0] = 1;
    buf[sizeof buf - 1] = 2;
    return buf[0] + buf[sizeof buf - 1];
}

static volatile DWORD overflow_depth;

static void overflow(void)
{
    volatile BYTE pad[1024];

    pad[0] = 1;
    overflow_depth++;
    overflow();
    pad[1023] = pad[0];
}

/* The stack reservation of the calling thread: its TEB stack base minus
 * the allocation base of the reservation holding a local. */
static DWORD reservation(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD local = 0;

    VirtualQuery(&local, &mbi, sizeof mbi);
    return fs_dword(0x04) - (DWORD)mbi.AllocationBase;
}

typedef struct {
    DWORD depth_ok;
    DWORD reserve;
    DWORD code;
    DWORD survived;
} stack_report;

static DWORD WINAPI stack_child(LPVOID param)
{
    stack_report *r = (stack_report *)param;
    DWORD kb = r->depth_ok;

    r->depth_ok = recurse(kb) == 0;
    r->reserve = reservation();
    return 0;
}

static DWORD WINAPI overflow_child(LPVOID param)
{
    stack_report *r = (stack_report *)param;

    r->code = 0;
    __try {
        overflow();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r->code = GetExceptionCode();
    }
    r->survived = 1;
    return 0;
}

static void child(const char *what, LPTHREAD_START_ROUTINE fn, DWORD stack, stack_report *r)
{
    HANDLE h;
    DWORD w;

    h = CreateThread(NULL, stack, fn, r, 0, NULL);
    if (h == NULL) {
        line("%s: CreateThread failed err=%lu", what, GetLastError());
        return;
    }
    w = WaitForSingleObject(h, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        line("%s: wait %s", what, wr(w));
    }
    CloseHandle(h);
}

static void sec_stack(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *a;
    stack_report r;

    line("main: 256 KiB of recursion %s", recurse(256) == 0 ? "ok" : "failed");
    line("main: a 64 KiB local %s", big_local() == 3 ? "ok" : "failed");
    a = (BYTE *)_alloca(200 * KB);
    a[0] = 1;
    a[200 * KB - 1] = 2;
    line("main: _alloca(200 KiB) %s", a[0] + a[200 * KB - 1] == 3 ? "ok" : "failed");
    line("main: stack reservation 0x%lX", reservation());
    VirtualQuery((void *)(fs_dword(0x08) - 0x1000), &mbi, sizeof mbi);
    line("main: page below the stack limit: protect 0x%lX state 0x%lX", mbi.Protect, mbi.State);

    r.depth_ok = 200;
    child("child with a 256 KiB stack", stack_child, 256 * KB, &r);
    line("child with a 256 KiB stack: 200 KiB of recursion %s, reservation 0x%lX",
         r.depth_ok ? "ok" : "failed", r.reserve);
    r.depth_ok = 3 * 1024;
    child("child with a 4 MiB stack", stack_child, 4 * MB, &r);
    line("child with a 4 MiB stack: 3 MiB of recursion %s, reservation 0x%lX",
         r.depth_ok ? "ok" : "failed", r.reserve);
    r.depth_ok = 512;
    child("child with the default stack", stack_child, 0, &r);
    line("child with the default stack: 512 KiB of recursion %s, reservation 0x%lX",
         r.depth_ok ? "ok" : "failed", r.reserve);

    r.survived = 0;
    overflow_depth = 0;
    child("overflowing child", overflow_child, 0, &r);
    line("overflowing child: caught code 0x%08lX, survived %s", r.code, yesno(r.survived));
}

static const section_t sections[] = {
    { "sysinfo", sec_sysinfo, 0 },
    { "malloc", sec_malloc, 0 },
    { "heap", sec_heap, 0 },
    { "local", sec_local, 0 },
    { "virtual", sec_virtual, 0 },
    { "protect", sec_protect, 0 },
    { "image", sec_image, 0 },
    { "mapping", sec_mapping, 0 },
    { "stack", sec_stack, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("memory", sections, argc, argv);
}
