/*
 * dllmain - DLL entry points: what the loader calls, when, and in
 * which order.
 *
 * The companion DLLs (beside the program, built with no C runtime,
 * each with a DllMain) record every call of their entry point in
 * f2kbase.dll's log: the DLL, the reason, whether lpReserved was
 * NULL, and the calling thread. The program reads the log and prints
 * it; it never asserts an order, it shows the one it got.
 *
 *   f2kbase.dll  the log (its own DllMain records into it too)
 *   f2kmid.dll   imports f2kbase.dll
 *   f2kdep.dll   imports f2kbase.dll
 *   f2kdyn.dll   imports f2kbase.dll and f2kdep.dll; loaded at run time
 *   f2kfail.dll  imports f2kbase.dll; its DllMain answers FALSE to
 *                DLL_PROCESS_ATTACH
 *   f2ksub.dll   imports f2kbase.dll; in the dllsub subdirectory only
 *
 * The program imports f2kbase.dll and f2kmid.dll statically (their
 * import libraries); the others it loads by name.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   attach   the entry-point calls made before main: the static DLLs'
 *            DLL_PROCESS_ATTACH, with lpReserved non-NULL, on the
 *            main thread
 *   order    f2kbase.dll, which f2kmid.dll imports, initialized
 *            before it
 *   threads  a created thread's DLL_THREAD_ATTACH and
 *            DLL_THREAD_DETACH, then DisableThreadLibraryCalls on
 *            f2kmid.dll (and on a handle naming no module) and a second
 *            thread
 *   dynamic  LoadLibraryA of f2kdyn.dll (its new dependency attached
 *            first, lpReserved NULL), FreeLibrary's detach; a static
 *            DLL loaded and freed again (no call); f2kfail.dll's
 *            FALSE failing LoadLibraryA (its error, and what the
 *            loader called)
 *   search   f2ksub.dll not found from the program's directory, found
 *            through the current directory once it is dllsub;
 *            f2kdyn.dll still found in the program's directory
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat dllmain):
 * the DLLs first, each with no C runtime and DllMain its entry point,
 * at the base its .def names (F2K never relocates an image):
 *   cl /nologo /LD f2kbase.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kbase.def kernel32.lib
 *   cl /nologo /LD f2kmid.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kmid.def kernel32.lib f2kbase.lib
 *   (f2kdep, f2kfail and f2ksub as f2kmid; f2kdyn with f2kdep.lib too;
 *   f2ksub.dll moved into dllsub\)
 *   cl /nologo /I .. dllmain.c f2kbase.lib f2kmid.lib
 */

#include "../common/f2kt.h"
#include <ctype.h>

/* f2kbase.dll: the log of the entry-point calls. */
int __stdcall f2kb_count(void);
int __stdcall f2kb_get(int index, char *dll, int size, DWORD *reason, int *reserved_null,
                       DWORD *thread);

/* f2kmid.dll: an export, so the program imports it. */
int __stdcall f2km_value(void);

/* The main thread, the thread a section created (0: none yet), and
 * how many calls the log held when main began. */
static DWORD main_thread;
static DWORD new_thread;
static int at_start;

static const char *reason_name(DWORD reason)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH: return "DLL_PROCESS_ATTACH";
    case DLL_PROCESS_DETACH: return "DLL_PROCESS_DETACH";
    case DLL_THREAD_ATTACH: return "DLL_THREAD_ATTACH";
    case DLL_THREAD_DETACH: return "DLL_THREAD_DETACH";
    }
    return "an unknown reason";
}

static const char *thread_name(DWORD thread)
{
    if (thread == main_thread) {
        return "the main thread";
    }
    if (new_thread != 0 && thread == new_thread) {
        return "the created thread";
    }
    return "another thread";
}

/* Print the log's calls from `from` up to `to`. */
static void show(int from, int to)
{
    char dll[16];
    DWORD reason, thread;
    int null, i;

    for (i = from; i < to; i++) {
        if (!f2kb_get(i, dll, sizeof dll, &reason, &null, &thread)) {
            line("  call %d: not in the log", i);
            continue;
        }
        line("  %s: %s, lpReserved %s, on %s", dll, reason_name(reason),
             null ? "NULL" : "non-NULL", thread_name(thread));
    }
}

/* The log's calls since `mark`, under a heading. */
static void show_since(const char *heading, int mark)
{
    int now = f2kb_count();

    line("%s: %d", heading, now - mark);
    show(mark, now);
}

/* Where module `dll` (as the log names it) has its first call of
 * `reason`, from `from` on: -1 for none. */
static int find(const char *dll, DWORD reason, int from)
{
    char name[16];
    DWORD r, thread;
    int null, i, n = f2kb_count();

    for (i = from; i < n; i++) {
        if (f2kb_get(i, name, sizeof name, &r, &null, &thread) && r == reason &&
            strcmp(name, dll) == 0) {
            return i;
        }
    }
    return -1;
}

/* The upper-cased last `parts` components of `path`, into `out`. */
static const char *tail_upper(const char *path, int parts, char *out, int size)
{
    const char *b = path + strlen(path);
    int n = 0;

    while (b > path) {
        if (b[-1] == '\\' || b[-1] == '/' || b[-1] == ':') {
            if (--parts == 0) {
                break;
            }
        }
        b--;
    }
    while (*b != 0 && n < size - 1) {
        out[n++] = (char)toupper((unsigned char)*b++);
    }
    out[n] = 0;
    return out;
}

/* --- attach -------------------------------------------------------- */

static void sec_attach(void)
{
    line("entry-point calls before main: %d", at_start);
    show(0, at_start);
    line("f2km_value() = %d", f2km_value());
}

/* --- order --------------------------------------------------------- */

static void sec_order(void)
{
    int base = find("f2kbase", DLL_PROCESS_ATTACH, 0);
    int mid = find("f2kmid", DLL_PROCESS_ATTACH, 0);

    line("f2kbase attached before main: %s", yesno(base >= 0 && base < at_start));
    line("f2kmid attached before main: %s", yesno(mid >= 0 && mid < at_start));
    line("f2kbase (which f2kmid imports) attached before f2kmid: %s",
         yesno(base >= 0 && mid >= 0 && base < mid));
}

/* --- threads ------------------------------------------------------- */

static DWORD WINAPI thread_main(LPVOID parameter)
{
    (void)parameter;
    return 0;
}

/* Create a thread that returns at once, wait for it, and print the
 * entry-point calls its life made. */
static void one_thread(const char *heading)
{
    HANDLE h;
    DWORD id = 0, r;
    int mark = f2kb_count();

    arm();
    h = CreateThread(NULL, 0, thread_main, NULL, 0, &id);
    line("CreateThread: created %s err=%s", yesno(h != NULL), le());
    if (h == NULL) {
        return;
    }
    new_thread = id;
    r = WaitForSingleObject(h, WAIT_MS);
    line("its end: %s", wr(r));
    CloseHandle(h);
    show_since(heading, mark);
    new_thread = 0;
}

static void sec_threads(void)
{
    HMODULE mid;
    BOOL r;

    one_thread("entry-point calls of a created thread");

    mid = GetModuleHandleA("f2kmid.dll");
    arm();
    r = DisableThreadLibraryCalls(mid);
    line("DisableThreadLibraryCalls(f2kmid): ret=%d err=%s", r, le());
    arm();
    r = DisableThreadLibraryCalls((HMODULE)0x12340000);
    line("DisableThreadLibraryCalls, a handle naming no module: ret=%d err=%s", r, le());

    one_thread("entry-point calls of a second thread, f2kmid's thread calls off");
}

/* --- dynamic ------------------------------------------------------- */

static void sec_dynamic(void)
{
    HMODULE h, again;
    BOOL r;
    int mark;

    mark = f2kb_count();
    arm();
    h = LoadLibraryA("f2kdyn.dll");
    line("LoadLibraryA(f2kdyn.dll): loaded %s err=%s", yesno(h != NULL), le());
    show_since("entry-point calls of the load", mark);
    if (h != NULL) {
        mark = f2kb_count();
        arm();
        r = FreeLibrary(h);
        line("FreeLibrary(f2kdyn): ret=%d err=%s", r, le());
        show_since("entry-point calls of the free", mark);
        arm();
        again = GetModuleHandleA("f2kdep.dll");
        line("GetModuleHandleA(f2kdep.dll), after: ret null %s err=%s", yesno(again == NULL), le());
    }

    again = GetModuleHandleA("f2kmid.dll");
    mark = f2kb_count();
    arm();
    h = LoadLibraryA("f2kmid.dll");
    line("LoadLibraryA(f2kmid.dll), a static DLL: same module %s err=%s",
         yesno(h != NULL && h == again), le());
    if (h != NULL) {
        arm();
        r = FreeLibrary(h);
        line("FreeLibrary(f2kmid): ret=%d err=%s", r, le());
    }
    show_since("entry-point calls of the static DLL's load and free", mark);

    mark = f2kb_count();
    arm();
    h = LoadLibraryA("f2kfail.dll");
    line("LoadLibraryA(f2kfail.dll), its DllMain answering FALSE: ret null %s err=%s",
         yesno(h == NULL), le());
    show_since("entry-point calls of the failed load", mark);
    arm();
    again = GetModuleHandleA("f2kfail.dll");
    line("GetModuleHandleA(f2kfail.dll), after: ret null %s err=%s", yesno(again == NULL), le());
}

/* --- search -------------------------------------------------------- */

static void sec_search(void)
{
    HMODULE sub, dyn;
    char path[MAX_PATH];
    char shown[MAX_PATH];
    BOOL r;
    int mark;

    arm();
    sub = LoadLibraryA("f2ksub.dll");
    line("LoadLibraryA(f2ksub.dll), the current directory the program's: ret null %s err=%s",
         yesno(sub == NULL), le());
    if (sub != NULL) {
        FreeLibrary(sub);
    }

    arm();
    r = SetCurrentDirectoryA("dllsub");
    line("SetCurrentDirectoryA(dllsub): ret=%d err=%s", r, le());
    if (!r) {
        return;
    }
    mark = f2kb_count();
    arm();
    sub = LoadLibraryA("f2ksub.dll");
    line("LoadLibraryA(f2ksub.dll), the current directory dllsub: loaded %s err=%s",
         yesno(sub != NULL), le());
    if (sub != NULL) {
        arm();
        GetModuleFileNameA(sub, path, sizeof path);
        line("GetModuleFileNameA(f2ksub): %s err=%s", tail_upper(path, 2, shown, sizeof shown), le());
    }
    show_since("entry-point calls of the load", mark);

    arm();
    dyn = LoadLibraryA("f2kdyn.dll");
    line("LoadLibraryA(f2kdyn.dll), the current directory dllsub: loaded %s err=%s",
         yesno(dyn != NULL), le());
    if (dyn != NULL) {
        arm();
        GetModuleFileNameA(dyn, path, sizeof path);
        line("GetModuleFileNameA(f2kdyn): %s err=%s", tail_upper(path, 1, shown, sizeof shown), le());
        FreeLibrary(dyn);
    }
    if (sub != NULL) {
        arm();
        r = FreeLibrary(sub);
        line("FreeLibrary(f2ksub): ret=%d err=%s", r, le());
    }
    arm();
    r = SetCurrentDirectoryA("..");
    line("SetCurrentDirectoryA(..): ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "attach", sec_attach, 0 },
    { "order", sec_order, 0 },
    { "threads", sec_threads, 0 },
    { "dynamic", sec_dynamic, 0 },
    { "search", sec_search, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    main_thread = GetCurrentThreadId();
    at_start = f2kb_count();
    return run_sections("dllmain", sections, argc, argv);
}
