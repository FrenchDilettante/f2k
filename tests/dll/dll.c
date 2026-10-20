/*
 * dll - a program and its companion DLL (f2kcom.dll, beside it).
 *
 * The program-driven dynamic linking: the program loads a DLL that is
 * not in its import table, resolves its exports by GetProcAddress,
 * calls them, and frees it - everything the rest of the corpus has
 * only had done for it at start-up.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   load    LoadLibraryA finds f2kcom.dll in the program's directory
 *           (with and without the extension, in any case), the
 *           reference count of repeated loads, GetModuleHandleA's
 *           view of a loaded DLL, GetModuleFileNameA, FreeLibrary
 *           counting down to the unload, a name nothing exports
 *   proc    GetProcAddress on the loaded DLL: by name, by ordinal
 *           (f2kcom.def pins them), a name and an ordinal it does
 *           not export, and the null pointer
 *   call    the calls into the DLL: f2k_sum, f2k_greet's string,
 *           f2k_next's counter, and the counter reset by the unload
 *           and reload
 *
 * The companion (f2kcom.c) has no C runtime and no entry point: a
 * loaded DLL's entry point is never called, so nothing this fixture
 * observes can come from load time, and its exports are plain
 * functions over its own mapped data.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo /LD f2kcom.c /link /NODEFAULTLIB /NOENTRY /DEF:f2kcom.def
 *   cl /nologo dll.c
 */

#include "../common/f2kt.h"
#include <ctype.h>

/* The companion's exports, as GetProcAddress hands them back. */
typedef int (__stdcall *sum_fn)(int, int);
typedef const char *(__stdcall *greet_fn)(void);
typedef int (__stdcall *next_fn)(void);

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

/* --- load ---------------------------------------------------------- */

static void sec_load(void)
{
    HMODULE h, again;
    char path[MAX_PATH];
    char base[MAX_PATH];
    BOOL r;

    arm();
    h = LoadLibraryA("f2kcom.dll");
    line("LoadLibraryA(f2kcom.dll): loaded %s err=%s", yesno(h != NULL), le());
    if (h == NULL) {
        return;
    }
    arm();
    again = LoadLibraryA("f2kcom.dll");
    line("LoadLibraryA(f2kcom.dll), again: same module %s err=%s", yesno(again == h), le());
    arm();
    again = LoadLibraryA("F2KCOM.DLL");
    line("LoadLibraryA(F2KCOM.DLL), another case: same module %s err=%s", yesno(again == h), le());
    arm();
    again = GetModuleHandleA("f2kcom.dll");
    line("GetModuleHandleA(f2kcom.dll): same module %s err=%s", yesno(again == h), le());
    arm();
    GetModuleFileNameA(h, path, sizeof path);
    line("GetModuleFileNameA(f2kcom): %s err=%s", basename_upper(path, base, sizeof base), le());

    arm();
    r = FreeLibrary(h);
    line("FreeLibrary, of three loads: ret=%d err=%s", r, le());
    arm();
    again = GetModuleHandleA("f2kcom.dll");
    line("GetModuleHandleA, after one FreeLibrary: same module %s err=%s", yesno(again == h), le());
    arm();
    r = FreeLibrary(h);
    line("FreeLibrary, of two: ret=%d err=%s", r, le());
    arm();
    again = GetModuleHandleA("f2kcom.dll");
    line("GetModuleHandleA, after two: same module %s err=%s", yesno(again == h), le());
    arm();
    r = FreeLibrary(h);
    line("FreeLibrary, the last: ret=%d err=%s", r, le());
    arm();
    again = GetModuleHandleA("f2kcom.dll");
    line("GetModuleHandleA, after the last FreeLibrary: ret null %s err=%s", yesno(again == NULL), le());

    arm();
    again = LoadLibraryA("nosuch.dll");
    line("LoadLibraryA(nosuch.dll): ret null %s err=%s", yesno(again == NULL), le());
    arm();
    again = LoadLibraryA("f2kcom");
    line("LoadLibraryA(f2kcom), no extension: loaded %s err=%s", yesno(again != NULL), le());
    if (again != NULL) {
        arm();
        r = FreeLibrary(again);
        line("FreeLibrary, the extensionless load: ret=%d err=%s", r, le());
    }
}

/* --- proc ---------------------------------------------------------- */

static void sec_proc(void)
{
    HMODULE h;
    FARPROC sum, fp;
    BOOL r;

    arm();
    h = LoadLibraryA("f2kcom.dll");
    line("LoadLibraryA(f2kcom.dll): loaded %s err=%s", yesno(h != NULL), le());
    if (h == NULL) {
        return;
    }

    arm();
    sum = GetProcAddress(h, "f2k_sum");
    line("GetProcAddress(f2k_sum): found %s err=%s", yesno(sum != NULL), le());
    arm();
    fp = GetProcAddress(h, "f2k_greet");
    line("GetProcAddress(f2k_greet): found %s err=%s", yesno(fp != NULL), le());
    arm();
    fp = GetProcAddress(h, "f2k_next");
    line("GetProcAddress(f2k_next): found %s err=%s", yesno(fp != NULL), le());
    arm();
    fp = GetProcAddress(h, "f2k_nosuch");
    line("GetProcAddress(f2k_nosuch): ret null %s err=%s", yesno(fp == NULL), le());

    arm();
    fp = GetProcAddress(h, (LPCSTR)(DWORD)1);
    line("GetProcAddress(ordinal 1) is f2k_sum: %s err=%s", yesno(fp != NULL && fp == sum), le());
    arm();
    fp = GetProcAddress(h, (LPCSTR)(DWORD)3);
    line("GetProcAddress(ordinal 3): found %s err=%s", yesno(fp != NULL), le());
    arm();
    fp = GetProcAddress(h, (LPCSTR)(DWORD)99);
    line("GetProcAddress(ordinal 99): ret null %s err=%s", yesno(fp == NULL), le());
    arm();
    fp = GetProcAddress(h, NULL);
    line("GetProcAddress(NULL): ret null %s err=%s", yesno(fp == NULL), le());

    arm();
    r = FreeLibrary(h);
    line("FreeLibrary: ret=%d err=%s", r, le());
}

/* --- call ---------------------------------------------------------- */

static void sec_call(void)
{
    HMODULE h;
    sum_fn sum;
    greet_fn greet;
    next_fn next;
    BOOL r;

    arm();
    h = LoadLibraryA("f2kcom.dll");
    line("LoadLibraryA(f2kcom.dll): loaded %s err=%s", yesno(h != NULL), le());
    if (h == NULL) {
        return;
    }
    sum = (sum_fn)GetProcAddress(h, "f2k_sum");
    greet = (greet_fn)GetProcAddress(h, "f2k_greet");
    next = (next_fn)GetProcAddress(h, "f2k_next");
    if (sum != NULL) {
        line("f2k_sum(2, 3) = %d", sum(2, 3));
        line("f2k_sum(-40, 42) = %d", sum(-40, 42));
    }
    if (greet != NULL) {
        line("f2k_greet() = %s", greet());
    }
    if (next != NULL) {
        line("f2k_next() = %d", next());
        line("f2k_next() = %d", next());
        line("f2k_next() = %d", next());
    }
    arm();
    r = FreeLibrary(h);
    line("FreeLibrary: ret=%d err=%s", r, le());

    arm();
    h = LoadLibraryA("f2kcom.dll");
    line("LoadLibraryA(f2kcom.dll), reloaded: loaded %s err=%s", yesno(h != NULL), le());
    if (h != NULL) {
        next = (next_fn)GetProcAddress(h, "f2k_next");
        if (next != NULL) {
            line("f2k_next(), after the reload: %d", next());
        }
        arm();
        r = FreeLibrary(h);
        line("FreeLibrary: ret=%d err=%s", r, le());
    }
}

static const section_t sections[] = {
    { "load", sec_load, 0 },
    { "proc", sec_proc, 0 },
    { "call", sec_call, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("dll", sections, argc, argv);
}
