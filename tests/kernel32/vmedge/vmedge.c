/*
 * vmedge - the virtual-memory and sections corners: the stack's overflow
 * boundary, a commit over a mapped view, and unmapping an image view.
 *
 * Sections:
 *
 *   guardwalk  a handler continues on every guard-page violation and
 *              walks the stack down; the platform's overflow fires one
 *              guard earlier than a kernel that plants the lowest guard
 *              one page too low: the count of guards before the overflow
 *              pins the boundary.
 *   commitview a MEM_COMMIT over a mapped view: over a paging-file-backed
 *              section the platform commits (succeeds); over a
 *              file-backed section it answers STATUS_ALREADY_COMMITTED.
 *              A commit over any view must not be refused as conflicting.
 *              A private region's reserve-then-commit is the sanity line.
 *   unmapimage NtUnmapViewOfSection of the program's own image (named-only:
 *              on the platform the view unmaps and the process faults on
 *              the next instruction fetch, ending 0xC0000005 before the
 *              status line prints).
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat vmedge):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% vmedge.c kernel32.lib
 */

#include "../common/f2kt.h"

typedef LONG(WINAPI *unmap_fn)(LPVOID);

#define F2KT_GUARD_PAGE 0x80000001u
#define F2KT_STACK_OVERFLOW 0xC00000FDu

/* --- guardwalk ------------------------------------------------------------ */

static int g_guards;
static LONG g_code;

static void recurse(void)
{
    volatile char pad[2048];
    pad[0] = 1;
    recurse();
    pad[1] = 2; /* keeps the call from being a tail call */
}

/* GetExceptionInformation is legal in the filter only, so the filter
 * records the code for the line printed after the __try. */
static LONG guard_filter(PEXCEPTION_POINTERS ep)
{
    LONG code = (LONG)ep->ExceptionRecord->ExceptionCode;

    if (code == (LONG)F2KT_GUARD_PAGE) {
        g_guards++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    g_code = code;
    return EXCEPTION_EXECUTE_HANDLER;
}

static void sec_guardwalk(void)
{
    g_guards = 0;
    g_code = 0;
    __try {
        recurse();
    } __except (guard_filter(GetExceptionInformation())) {
    }
    line("guards=%d code=0x%08lX", g_guards, (unsigned long)g_code);
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

    /* A file-backed section (the program's own image file), mapped, then
     * committed over: STATUS_ALREADY_COMMITTED on the platform. */
    {
        char path[MAX_PATH];
        HANDLE fh;

        arm();
        GetModuleFileNameA(NULL, path, MAX_PATH);
        arm();
        fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        line("CreateFile(own image): ret=%s err=%s", fh == INVALID_HANDLE_VALUE ? "bad" : "ok", le());
        if (fh != INVALID_HANDLE_VALUE) {
            arm();
            h = CreateFileMappingA(fh, NULL, PAGE_READONLY, 0, 0, NULL);
            if (h != NULL) {
                view = MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0);
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

    /* A private region: reserve then commit, the sanity line both sides do. */
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
    LPVOID base;
    LONG st;

    unmap = (unmap_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    if (unmap == NULL) {
        line("NtUnmapViewOfSection not found");
        return;
    }
    base = GetModuleHandleA(NULL);
    line("unmapping own image");
    arm();
    st = unmap(base);
    /* On the platform the image view unmaps (status 0) and this line never
     * prints: the next fetch faults, exit 0xC0000005. A kernel that
     * refuses image views answers STATUS_NOT_MAPPED_VIEW and prints. */
    line("NtUnmapViewOfSection(own image): status=0x%08lX err=%s", (unsigned long)st, le());
}

/* --- main ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "guardwalk", sec_guardwalk, F2KT_ALWAYS },
    { "commitview", sec_commitview, F2KT_ALWAYS },
    { "unmapimage", sec_unmapimage, F2KT_NAMED },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("vmedge", sections, argc, argv);
}
