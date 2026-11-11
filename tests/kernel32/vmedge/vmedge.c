/*
 * vmedge - the virtual-memory and sections corners: a thread's stack
 * walked down to its overflow, a commit over a mapped view, and unmapping
 * an image view.
 *
 * Sections:
 *
 *   guardwalk  a thread of its own, with the image's stack sizes (1 MiB
 *              reserved), recurses until STATUS_STACK_OVERFLOW, a filter
 *              counting every STATUS_GUARD_PAGE_VIOLATION it sees on the
 *              way and continuing past it. Windows 2000 grows a thread's
 *              stack in the kernel, so the thread sees none: an earlier
 *              capture, the walk on the main thread, counted 0. Before and
 *              after the walk the thread surveys its stack's reservation
 *              (VirtualQuery, page by page): the reservation, its guard
 *              pages and its uncommitted ones, how many of its pages lie
 *              below the deepest frame's at the overflow, and whether the
 *              TEB's stack limit is then the lowest committed page. Counts
 *              and relations only.
 *   commitview a MEM_COMMIT over a mapped view: over a paging-file-backed
 *              section Windows 2000 commits (succeeds); over a file-backed
 *              one (the program's own file) it fails with error 5,
 *              ERROR_ACCESS_DENIED, the error STATUS_ALREADY_COMMITTED
 *              maps to. A private region's reserve-then-commit is the
 *              sanity line.
 *   unmapimage NtUnmapViewOfSection(ProcessHandle, BaseAddress) over image
 *              views, narrowed to what a program can watch and survive:
 *              unmapping its own image would leave it no code to return
 *              into. So: a private region of its own (no view), then a
 *              suspended copy of the program, whose image sits at the same
 *              base: unmapped through an address inside the view (the
 *              documentation says any address within a view names it),
 *              its region queried afterwards, and unmapped again. The
 *              child never runs; it is terminated and reaped.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat vmedge):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% vmedge.c kernel32.lib
 */

#include "../common/f2kt.h"

/* NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress):
 * no import library MSVC 6 has declares it, so it is reached through
 * GetProcAddress. */
typedef LONG(WINAPI *unmap_fn)(HANDLE, PVOID);

#define F2KT_GUARD_PAGE 0x80000001u
#define F2KT_PAGE 0x1000u

/* The TEB's fields at fs: StackBase (4) and StackLimit (8). */
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

/* --- guardwalk ------------------------------------------------------------ */

/* A survey of the calling thread's stack reservation, in pages. */
typedef struct {
    DWORD base;             /* the reservation's AllocationBase */
    DWORD reserve;          /* the reservation: StackBase - AllocationBase */
    DWORD uncommitted;      /* MEM_RESERVE pages */
    DWORD guard;            /* committed pages with PAGE_GUARD */
    DWORD committed;        /* committed pages without it */
    DWORD lowest;           /* the lowest committed page without PAGE_GUARD */
} stack_survey;

typedef struct {
    stack_survey before;
    stack_survey after;
    DWORD guards;           /* the guard-page violations the filter saw */
    DWORD code;             /* the exception that ended the walk */
    DWORD deepest;          /* the lowest frame's address */
    DWORD limit;            /* the TEB's StackLimit after the overflow */
} walk_report;

static walk_report g_walk;

static void survey(stack_survey *s)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD local = 0;
    DWORD base;
    DWORD top;
    DWORD p;
    DWORD pages;

    memset(s, 0, sizeof *s);
    if (VirtualQuery(&local, &mbi, sizeof mbi) == 0) {
        return;
    }
    base = (DWORD)mbi.AllocationBase;
    top = fs_dword(0x04);
    s->base = base;
    s->reserve = (top - base) / F2KT_PAGE;
    for (p = base; p < top; p += pages * F2KT_PAGE) {
        if (VirtualQuery((LPCVOID)p, &mbi, sizeof mbi) == 0 || mbi.RegionSize == 0) {
            return;
        }
        pages = mbi.RegionSize / F2KT_PAGE;
        if (p + mbi.RegionSize > top) {
            pages = (top - p) / F2KT_PAGE;
        }
        if (mbi.State == MEM_RESERVE) {
            s->uncommitted += pages;
        } else if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) != 0) {
            s->guard += pages;
        } else if (mbi.State == MEM_COMMIT) {
            if (s->committed == 0) {
                s->lowest = p;
            }
            s->committed += pages;
        }
    }
}

static void recurse(void)
{
    volatile char pad[2048];

    pad[0] = 1;
    if ((DWORD)&pad[0] < g_walk.deepest) {
        g_walk.deepest = (DWORD)&pad[0];
    }
    recurse();
    pad[1] = 2; /* keeps the call from being a tail call */
}

/* GetExceptionInformation is legal in the filter only, so the filter
 * records the code for the report. A guard-page violation, were the thread
 * to see one, is counted and continued past: the guard is gone once it
 * fired, so the access then succeeds. */
static LONG guard_filter(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == F2KT_GUARD_PAGE) {
        g_walk.guards++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    g_walk.code = code;
    return EXCEPTION_EXECUTE_HANDLER;
}

static DWORD WINAPI walk_thread(LPVOID p)
{
    (void)p;
    survey(&g_walk.before);
    __try {
        recurse();
    } __except (guard_filter(GetExceptionInformation())) {
    }
    /* Back at the thread's first frame, the stack as the overflow left it. */
    g_walk.limit = fs_dword(0x08);
    survey(&g_walk.after);
    return 0;
}

static void sec_guardwalk(void)
{
    HANDLE t;
    DWORD w;
    walk_report *r = &g_walk;

    memset(r, 0, sizeof *r);
    r->deepest = 0xFFFFFFFFu;
    /* A stack size of 0: the image header's, 1 MiB reserved. */
    arm();
    t = CreateThread(NULL, 0, walk_thread, NULL, 0, NULL);
    line("CreateThread: ret=%s err=%s", t != NULL ? "ok" : "null", le());
    if (t == NULL) {
        return;
    }
    w = WaitForSingleObject(t, WAIT_MS);
    line("wait=%s", wr(w));
    CloseHandle(t);
    if (w != WAIT_OBJECT_0) {
        return;
    }
    line("before: reserve=%lu pages, all surveyed: %s, guard pages=%lu", r->before.reserve,
        yesno(r->before.uncommitted + r->before.guard + r->before.committed == r->before.reserve),
        r->before.guard);
    line("walk: guard-page exceptions seen=%lu code=0x%08lX", r->guards, r->code);
    line("after: all surveyed: %s, guard pages=%lu, uncommitted pages=%lu",
        yesno(r->after.uncommitted + r->after.guard + r->after.committed == r->after.reserve),
        r->after.guard, r->after.uncommitted);
    line("after: pages below the deepest frame's page=%lu",
        ((r->deepest & ~(F2KT_PAGE - 1)) - r->after.base) / F2KT_PAGE);
    line("after: stack limit at the lowest committed page: %s", yesno(r->limit == r->after.lowest));
}

/* --- commitview ------------------------------------------------------------ */

static void sec_commitview(void)
{
    HANDLE h;
    LPVOID view;
    LPVOID p;

    /* A paging-file-backed section, mapped, then committed over. */
    arm();
    h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL);
    line("CreateFileMapping(paging): ret=%s err=%s", h ? "ok" : "null", le());
    if (h != NULL) {
        arm();
        view = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0x10000);
        line("MapViewOfFile: ret=%s err=%s", view ? "ok" : "null", le());
        if (view != NULL) {
            arm();
            p = VirtualAlloc(view, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            line("commit over paging view: ret=%s err=%s", p ? "ok" : "null", le());
            UnmapViewOfFile(view);
        }
        CloseHandle(h);
    }

    /* A file-backed section (the program's own file, mapped as data), then
     * committed over. */
    {
        char path[MAX_PATH];
        HANDLE fh;

        GetModuleFileNameA(NULL, path, MAX_PATH);
        arm();
        fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        line("CreateFile(own image): ret=%s err=%s", fh == INVALID_HANDLE_VALUE ? "bad" : "ok", le());
        if (fh != INVALID_HANDLE_VALUE) {
            arm();
            h = CreateFileMappingA(fh, NULL, PAGE_READONLY, 0, 0, NULL);
            line("CreateFileMapping(file): ret=%s err=%s", h ? "ok" : "null", le());
            if (h != NULL) {
                arm();
                view = MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0);
                line("MapViewOfFile(file): ret=%s err=%s", view ? "ok" : "null", le());
                if (view != NULL) {
                    arm();
                    p = VirtualAlloc(view, 0x1000, MEM_COMMIT, PAGE_READWRITE);
                    line("commit over file view: ret=%s err=%s", p ? "ok" : "null", le());
                    UnmapViewOfFile(view);
                }
                CloseHandle(h);
            }
            CloseHandle(fh);
        }
    }

    /* A private region: reserve then commit, the sanity line. */
    arm();
    p = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_READWRITE);
    arm();
    p = VirtualAlloc(p, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    line("private reserve+commit: ret=%s err=%s", p ? "ok" : "null", le());
}

/* --- unmapimage ------------------------------------------------------------ */

static void sec_unmapimage(void)
{
    unmap_fn unmap;
    BYTE *base;
    BYTE *priv;
    char path[MAX_PATH];
    char cmd[MAX_PATH + 32];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    MEMORY_BASIC_INFORMATION mbi;
    LONG st;
    BOOL ok;
    DWORD n;

    unmap = (unmap_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    if (unmap == NULL) {
        line("NtUnmapViewOfSection not found");
        return;
    }
    base = (BYTE *)GetModuleHandleA(NULL);

    /* A private region is no view. */
    priv = (BYTE *)VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (priv != NULL) {
        arm();
        st = unmap(GetCurrentProcess(), priv);
        line("NtUnmapViewOfSection(own private region): status=0x%08lX err=%s", (unsigned long)st, le());
        VirtualFree(priv, 0, MEM_RELEASE);
    }

    /* A suspended copy of the program: its image, at the same base as
     * this one's, is unmapped from here, so no code of ours goes. */
    GetModuleFileNameA(NULL, path, MAX_PATH);
    sprintf(cmd, "\"%s\" never-runs", path);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    arm();
    ok = CreateProcessA(path, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    line("CreateProcess(suspended copy): ret=%d err=%s", ok, le());
    if (!ok) {
        return;
    }

    arm();
    n = VirtualQueryEx(pi.hProcess, base, &mbi, sizeof mbi);
    line("VirtualQueryEx(child, our base): ret=%s err=%s image=%s its base=%s", n != 0 ? "ok" : "0", le(),
        yesno(n != 0 && mbi.Type == MEM_IMAGE), yesno(n != 0 && mbi.AllocationBase == base));

    arm();
    st = unmap(pi.hProcess, base + F2KT_PAGE);
    line("NtUnmapViewOfSection(child, inside its image): status=0x%08lX err=%s", (unsigned long)st, le());

    arm();
    n = VirtualQueryEx(pi.hProcess, base, &mbi, sizeof mbi);
    line("VirtualQueryEx(child, our base): ret=%s err=%s free=%s", n != 0 ? "ok" : "0", le(),
        yesno(n != 0 && mbi.State == MEM_FREE));

    arm();
    st = unmap(pi.hProcess, base);
    line("NtUnmapViewOfSection(child, its image again): status=0x%08lX err=%s", (unsigned long)st, le());

    /* Its exit code depends on how far its thread got before the
     * termination (tests/kernel32/toolhelp), so only the end prints. */
    arm();
    ok = TerminateProcess(pi.hProcess, 7);
    line("TerminateProcess(child): ret=%d err=%s", ok, le());
    line("child ended: %s", wr(WaitForSingleObject(pi.hProcess, WAIT_MS)));
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

/* --- main ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "guardwalk", sec_guardwalk, F2KT_ALWAYS },
    { "commitview", sec_commitview, F2KT_ALWAYS },
    { "unmapimage", sec_unmapimage, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("vmedge", sections, argc, argv);
}
