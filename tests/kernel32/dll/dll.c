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
 *   loadex  LoadLibraryExA, then LoadLibraryExW, on f2kcom.dll: flags 0
 *           (the module LoadLibraryA and GetModuleHandleA then find,
 *           a call into it); LOAD_WITH_ALTERED_SEARCH_PATH with the
 *           DLL's full path and with its bare name;
 *           LOAD_LIBRARY_AS_DATAFILE with the DLL not loaded (the
 *           handle's low bit, "MZ" at it, whether GetModuleHandleA
 *           finds a module, GetProcAddress on it) and while it is
 *           loaded (the same module or not); DONT_RESOLVE_DLL_REFERENCES
 *           (the module GetModuleHandleA and a later LoadLibraryA find,
 *           calls into it); each FreeLibrary and whether the DLL is
 *           unloaded after; a DLL that does not exist under each flag, a
 *           file handle, an unknown flag. Handles print only as
 *           relations; the full path never prints. LoadLibraryExA and W
 *           are reached through GetProcAddress, so the program still
 *           loads where kernel32 lacks them.
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

/* --- loadex -------------------------------------------------------- */

/* LoadLibraryEx's flags, which MSVC 6's headers have; kept beside the
   section in case. */
#ifndef DONT_RESOLVE_DLL_REFERENCES
#define DONT_RESOLVE_DLL_REFERENCES 0x00000001
#endif
#ifndef LOAD_LIBRARY_AS_DATAFILE
#define LOAD_LIBRARY_AS_DATAFILE 0x00000002
#endif
#ifndef LOAD_WITH_ALTERED_SEARCH_PATH
#define LOAD_WITH_ALTERED_SEARCH_PATH 0x00000008
#endif

static char com_path[MAX_PATH];     /* f2kcom.dll's full path, beside the program */
static WCHAR com_path_w[MAX_PATH];

/* LoadLibraryExA and W are reached through GetProcAddress: the program
   loads where kernel32 lacks them, its other sections intact. */
typedef HMODULE (WINAPI *load_library_ex_a_fn)(LPCSTR name, HANDLE file, DWORD flags);
typedef HMODULE (WINAPI *load_library_ex_w_fn)(LPCWSTR name, HANDLE file, DWORD flags);

static load_library_ex_a_fn load_ex_a;
static load_library_ex_w_fn load_ex_w;

/* LoadLibraryExA of `name`, or (wide) LoadLibraryExW of `wname`. */
static HMODULE load_ex(int wide, const char *name, const WCHAR *wname, HANDLE file, DWORD flags)
{
    return wide ? load_ex_w(wname, file, flags) : load_ex_a(name, file, flags);
}

/* Unload f2kcom.dll whatever its count, so each case starts afresh. */
static void unload_com(void)
{
    HMODULE h;
    int n = 0;

    while ((h = GetModuleHandleA("f2kcom.dll")) != NULL && n++ < 16) {
        FreeLibrary(h);
    }
}

/* Whether the DOS header's "MZ" is at the handle, its low bits cleared
   (a fault reading it prints as no). */
static int mz_at(HMODULE h)
{
    int found = 0;

    __try {
        found = *(const WORD *)((DWORD)h & ~(DWORD)3) == IMAGE_DOS_SIGNATURE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        found = 0;
    }
    return found;
}

/* GetProcAddress(h, "f2k_sum") under __try: found, not found, or the
   exception code. */
static const char *sum_through(HMODULE h, sum_fn *out)
{
    static char text[40];
    FARPROC fp = NULL;

    __try {
        fp = GetProcAddress(h, "f2k_sum");
        strcpy(text, fp != NULL ? "found" : "not found");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sprintf(text, "faulted 0x%08lX", GetExceptionCode());
    }
    if (out != NULL) {
        *out = (sum_fn)fp;
    }
    return text;
}

static void loadex_block(int wide)
{
    const char *fn = wide ? "LoadLibraryExW" : "LoadLibraryExA";
    HMODULE h, again, normal;
    sum_fn sum;
    next_fn next;
    BOOL r;
    const char *e;

    /* Flags 0: LoadLibrary's own behaviour. */
    unload_com();
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", NULL, 0);
    e = le();
    line("%s(f2kcom.dll, 0): loaded %s err=%s", fn, yesno(h != NULL), e);
    if (h != NULL) {
        line("  GetModuleHandleA finds the same module: %s", yesno(GetModuleHandleA("f2kcom.dll") == h));
        again = LoadLibraryA("f2kcom.dll");
        line("  LoadLibraryA after it: the same module %s", yesno(again == h));
        if (again != NULL) {
            FreeLibrary(again);
        }
        line("  GetProcAddress(f2k_sum): %s", sum_through(h, &sum));
        if (sum != NULL) {
            line("  f2k_sum(2, 3) = %d", sum(2, 3));
        }
        arm();
        r = FreeLibrary(h);
        e = le();
        line("  FreeLibrary: ret=%d err=%s; unloaded %s", r, e, yesno(GetModuleHandleA("f2kcom.dll") == NULL));
    }

    /* LOAD_WITH_ALTERED_SEARCH_PATH: a full path, then the bare name. */
    unload_com();
    arm();
    h = load_ex(wide, com_path, com_path_w, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    e = le();
    line("%s(<the program's directory>\\f2kcom.dll, LOAD_WITH_ALTERED_SEARCH_PATH): loaded %s err=%s", fn,
         yesno(h != NULL), e);
    if (h != NULL) {
        line("  GetModuleHandleA finds the same module: %s", yesno(GetModuleHandleA("f2kcom.dll") == h));
        arm();
        r = FreeLibrary(h);
        e = le();
        line("  FreeLibrary: ret=%d err=%s; unloaded %s", r, e, yesno(GetModuleHandleA("f2kcom.dll") == NULL));
    }
    unload_com();
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    e = le();
    line("%s(f2kcom.dll, LOAD_WITH_ALTERED_SEARCH_PATH): loaded %s err=%s", fn, yesno(h != NULL), e);
    if (h != NULL) {
        arm();
        r = FreeLibrary(h);
        e = le();
        line("  FreeLibrary: ret=%d err=%s; unloaded %s", r, e, yesno(GetModuleHandleA("f2kcom.dll") == NULL));
    }

    /* LOAD_LIBRARY_AS_DATAFILE, the DLL not loaded otherwise. */
    unload_com();
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    e = le();
    line("%s(f2kcom.dll, LOAD_LIBRARY_AS_DATAFILE): a handle %s err=%s", fn, yesno(h != NULL), e);
    if (h != NULL) {
        line("  its low bit set %s, \"MZ\" at it (low bits cleared) %s", yesno(((DWORD)h & 1) != 0),
             yesno(mz_at(h)));
        line("  GetModuleHandleA(f2kcom.dll) finds a module: %s", yesno(GetModuleHandleA("f2kcom.dll") != NULL));
        line("  GetProcAddress(f2k_sum) on it: %s", sum_through(h, NULL));
        arm();
        r = FreeLibrary(h);
        e = le();
        line("  FreeLibrary: ret=%d err=%s", r, e);
    }

    /* LOAD_LIBRARY_AS_DATAFILE while the DLL is loaded. */
    unload_com();
    normal = LoadLibraryA("f2kcom.dll");
    line("LoadLibraryA(f2kcom.dll) first: loaded %s", yesno(normal != NULL));
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    e = le();
    line("%s(f2kcom.dll, LOAD_LIBRARY_AS_DATAFILE), loaded already: a handle %s, the loaded module %s, its low "
         "bit set %s err=%s",
         fn, yesno(h != NULL), yesno(h != NULL && h == normal), yesno(((DWORD)h & 1) != 0), e);
    if (h != NULL) {
        arm();
        r = FreeLibrary(h);
        e = le();
        line("  FreeLibrary of it: ret=%d err=%s; the module still loaded %s", r, e,
             yesno(GetModuleHandleA("f2kcom.dll") == normal));
    }
    if (normal != NULL) {
        arm();
        r = FreeLibrary(normal);
        e = le();
        line("  FreeLibrary of LoadLibraryA's: ret=%d err=%s; unloaded %s", r, e,
             yesno(GetModuleHandleA("f2kcom.dll") == NULL));
    }

    /* DONT_RESOLVE_DLL_REFERENCES. */
    unload_com();
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    e = le();
    line("%s(f2kcom.dll, DONT_RESOLVE_DLL_REFERENCES): loaded %s err=%s", fn, yesno(h != NULL), e);
    if (h != NULL) {
        line("  GetModuleHandleA finds the same module: %s", yesno(GetModuleHandleA("f2kcom.dll") == h));
        line("  GetProcAddress(f2k_sum): %s", sum_through(h, &sum));
        if (sum != NULL) {
            line("  f2k_sum(-40, 42) = %d", sum(-40, 42));
        }
        next = (next_fn)GetProcAddress(h, "f2k_next");
        if (next != NULL) {
            line("  f2k_next() = %d", next());
        }
        again = LoadLibraryA("f2kcom.dll");
        line("  LoadLibraryA after it: the same module %s", yesno(again == h));
        if (again != NULL) {
            arm();
            r = FreeLibrary(again);
            e = le();
            line("  FreeLibrary of LoadLibraryA's: ret=%d err=%s; still loaded %s", r, e,
                 yesno(GetModuleHandleA("f2kcom.dll") == h));
        }
        arm();
        r = FreeLibrary(h);
        e = le();
        line("  FreeLibrary: ret=%d err=%s; unloaded %s", r, e, yesno(GetModuleHandleA("f2kcom.dll") == NULL));
    }

    /* The refusals. */
    unload_com();
    arm();
    h = load_ex(wide, "nosuch.dll", L"nosuch.dll", NULL, 0);
    e = le();
    line("%s(nosuch.dll, 0): ret null %s err=%s", fn, yesno(h == NULL), e);
    arm();
    h = load_ex(wide, "nosuch.dll", L"nosuch.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);
    e = le();
    line("%s(nosuch.dll, LOAD_LIBRARY_AS_DATAFILE): ret null %s err=%s", fn, yesno(h == NULL), e);
    if (h != NULL) {
        FreeLibrary(h);
    }
    arm();
    h = load_ex(wide, "nosuch.dll", L"nosuch.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    e = le();
    line("%s(nosuch.dll, DONT_RESOLVE_DLL_REFERENCES): ret null %s err=%s", fn, yesno(h == NULL), e);
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", (HANDLE)1, 0);
    e = le();
    line("%s(f2kcom.dll, a file handle of 1, 0): ret null %s err=%s", fn, yesno(h == NULL), e);
    if (h != NULL) {
        FreeLibrary(h);
    }
    arm();
    h = load_ex(wide, "f2kcom.dll", L"f2kcom.dll", NULL, 0x80000000);
    e = le();
    line("%s(f2kcom.dll, 0x80000000): ret null %s err=%s", fn, yesno(h == NULL), e);
    if (h != NULL) {
        FreeLibrary(h);
    }
    unload_com();
}

static void sec_loadex(void)
{
    char *slash;

    GetModuleFileNameA(NULL, com_path, sizeof com_path);
    slash = strrchr(com_path, '\\');
    strcpy(slash != NULL ? slash + 1 : com_path, "f2kcom.dll");
    MultiByteToWideChar(CP_ACP, 0, com_path, -1, com_path_w, MAX_PATH);
    load_ex_a = (load_library_ex_a_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExA");
    load_ex_w = (load_library_ex_w_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExW");
    line("kernel32 exports LoadLibraryExA %s, LoadLibraryExW %s", yesno(load_ex_a != NULL), yesno(load_ex_w != NULL));
    if (load_ex_a == NULL || load_ex_w == NULL) {
        return;
    }
    loadex_block(0);
    loadex_block(1);
}

static const section_t sections[] = {
    { "load", sec_load, 0 },
    { "proc", sec_proc, 0 },
    { "call", sec_call, 0 },
    { "loadex", sec_loadex, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("dll", sections, argc, argv);
}
