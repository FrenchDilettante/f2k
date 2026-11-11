/*
 * process - msvcrt.dll's view of its process under /MD: the command
 * line's data exports, the environment through getenv, and the C++
 * heap operators beside _msize and _expand, and the threads
 * _beginthreadex starts.
 *
 * The data exports (_acmdln, _wcmdln, __argc, __argv) and the C++
 * operators (operator new, ??2@YAPAXI@Z, and operator delete,
 * ??3@YAXPAX@Z) are reached through GetProcAddress on msvcrt.dll: a data
 * export's address is the variable's own, and the operators are called
 * through cdecl function pointers. This keeps the fixture C, and keeps
 * clear of MSVC 6's stdlib.h, which under /MD turns __argc and __argv
 * into (*__p___argc()) and (*__p___argv()). The calls are still the
 * section's own, as the kernel32 fixtures reach ntdll's exports.
 *
 * _beginthreadex and _endthreadex are reached the same way. Every
 * other import is one F2K's msvcrt already implements: each one it
 * lacks is one more export the fixture needs before it loads.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   cmdline  whether each data export resolves; _acmdln and _wcmdln
 *            against GetCommandLineA and GetCommandLineW (the same
 *            pointer, the same text); __argc and __argv against
 *            __p___argc and __p___argv and main's own; argv[0]'s final
 *            path component, argv[1], argv[argc]; the command line's
 *            tail after the program name (capture.bat runs
 *            `process.exe cmdline`: the program's path differs from
 *            machine to machine, so only relations are printed, never
 *            the path)
 *   getenv   getenv over variables the section sets itself: after
 *            _putenv, in another case, a missing name, after _putenv's
 *            removal, after SetEnvironmentVariableA behind the C
 *            runtime's back, the empty name and a name holding '='
 *            (those two print only whether a value came back)
 *   heap     operator new for 1, 100 and 0 bytes (0 gives a unique
 *            block), _msize on them and on malloc'd blocks of 1, 100
 *            and 5000 bytes, operator delete on each and on NULL;
 *            _expand shrinking a 5000-byte block to 100 and to the
 *            same size
 *   beginthread  _beginthreadex: a routine's return value as the
 *            thread's exit code, read through the handle the C runtime
 *            leaves open once the thread has ended (then closed by the
 *            section: CloseHandle's answer), the id against the child's
 *            own; _endthreadex(55) in a thread started suspended (a
 *            200 ms wait before ResumeThread, the code after the call
 *            never run); a 64 KiB stack; no id pointer; errno set in the
 *            thread and this thread's errno untouched
 *
 * Not tested: _expand growing a block (whether there is room after it
 * depends on the heap's layout), and _msize(NULL) and _expand(NULL),
 * which may fault in the real C runtime.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat process):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% process.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <malloc.h>
#include <errno.h>

typedef void *(__cdecl *new_fn)(unsigned int size);
typedef void (__cdecl *delete_fn)(void *block);

/* main's own argc and argv, as the startup's __getmainargs gave them. */
static int g_argc;
static char **g_argv;

/* --- helpers ------------------------------------------------------- */

/* An msvcrt.dll export's address, or NULL. */
static FARPROC crt_export(const char *name)
{
    HMODULE crt = GetModuleHandleA("msvcrt.dll");

    if (crt == NULL) {
        return NULL;
    }
    return GetProcAddress(crt, name);
}

/* The command line after the program name and the blanks after it. */
static const char *skip_program(const char *p)
{
    if (*p == '"') {
        p++;
        while (*p != 0 && *p != '"') {
            p++;
        }
        if (*p == '"') {
            p++;
        }
    } else {
        while (*p != 0 && *p != ' ' && *p != '\t') {
            p++;
        }
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/* The same, of a wide command line. */
static const WCHAR *skip_program_w(const WCHAR *p)
{
    if (*p == L'"') {
        p++;
        while (*p != 0 && *p != L'"') {
            p++;
        }
        if (*p == L'"') {
            p++;
        }
    } else {
        while (*p != 0 && *p != L' ' && *p != L'\t') {
            p++;
        }
    }
    while (*p == L' ' || *p == L'\t') {
        p++;
    }
    return p;
}

/* A path's final component: what follows its last '\', '/' or ':'. */
static const char *final_component(const char *p)
{
    const char *last = p;

    for (; *p != 0; p++) {
        if (*p == '\\' || *p == '/' || *p == ':') {
            last = p + 1;
        }
    }
    return last;
}

/* --- cmdline ------------------------------------------------------- */

static void sec_cmdline(void)
{
    char **acmdln = (char **)crt_export("_acmdln");
    WCHAR **wcmdln = (WCHAR **)crt_export("_wcmdln");
    int *argc_var = (int *)crt_export("__argc");
    char ***argv_var = (char ***)crt_export("__argv");
    char *a;
    WCHAR *w;
    char **argv;
    int argc;

    line("_acmdln resolved: %s, _wcmdln resolved: %s, __argc resolved: %s, __argv resolved: %s",
         yesno(acmdln != NULL), yesno(wcmdln != NULL), yesno(argc_var != NULL), yesno(argv_var != NULL));

    if (acmdln != NULL) {
        a = GetCommandLineA();
        line("_acmdln against GetCommandLineA(): the same pointer %s, the same text %s", yesno(*acmdln == a),
             yesno(*acmdln != NULL && strcmp(*acmdln, a) == 0));
    }
    if (wcmdln != NULL) {
        w = GetCommandLineW();
        line("_wcmdln against GetCommandLineW(): the same pointer %s, the same text %s", yesno(*wcmdln == w),
             yesno(*wcmdln != NULL && wcscmp(*wcmdln, w) == 0));
    }

    if (argc_var != NULL) {
        argc = *argc_var;
        line("__argc: %d, *__p___argc() %s, at __p___argc()'s address %s, main's argc %s", argc,
             yesno(argc == *__p___argc()), yesno(argc_var == __p___argc()), yesno(argc == g_argc));
    }
    if (argv_var != NULL) {
        argv = *argv_var;
        line("__argv: *__p___argv() %s, at __p___argv()'s address %s, main's argv %s", yesno(argv == *__p___argv()),
             yesno(argv_var == __p___argv()), yesno(argv == g_argv));
        if (argc_var != NULL && argv != NULL) {
            argc = *argc_var;
            line("argv[0]'s final component is process.exe: %s",
                 yesno(argc >= 1 && argv[0] != NULL && _stricmp(final_component(argv[0]), "process.exe") == 0));
            line("argv[1]: [%s]", argc >= 2 && argv[1] != NULL ? argv[1] : "(none)");
            line("argv[argc] is NULL: %s", yesno(argc >= 0 && argv[argc] == NULL));
        }
    }

    if (acmdln != NULL && *acmdln != NULL) {
        line("command line tail: [%s]", skip_program(*acmdln));
    }
    if (wcmdln != NULL && *wcmdln != NULL) {
        line("command line tail (W): [%s]", ws(skip_program_w(*wcmdln)));
    }
}

/* --- getenv -------------------------------------------------------- */

/* A value of a variable the section set itself, as printed: in brackets
 * (its first 60 characters), or NULL. Rotates through two buffers. */
static const char *value(const char *v)
{
    static char bufs[2][64];
    static int next;
    char *b = bufs[next++ & 1];
    int n = 0;

    if (v == NULL) {
        return "NULL";
    }
    b[n++] = '[';
    while (*v != 0 && n < 61) {
        b[n++] = *v++;
    }
    b[n++] = ']';
    b[n] = 0;
    return b;
}

static void sec_getenv(void)
{
    char *upper;
    char *lower;
    char *v;
    int r;
    BOOL ok;

    /* None of the section's variables is set as it starts. */
    _putenv("F2KT_A=");
    _putenv("F2KT_B=");
    SetEnvironmentVariableA("F2KT_B", NULL);

    r = _putenv("F2KT_A=one");
    line("_putenv(\"F2KT_A=one\"): %d", r);
    upper = getenv("F2KT_A");
    line("getenv(\"F2KT_A\"): %s", value(upper));
    lower = getenv("f2kt_a");
    line("getenv(\"f2kt_a\"): %s, the same pointer %s", value(lower), yesno(lower == upper));
    v = getenv("F2KT_MISSING");
    line("getenv(\"F2KT_MISSING\"): %s", v == NULL ? "NULL" : "a value");
    v = getenv("");
    line("getenv(\"\"): %s", v == NULL ? "NULL" : "a value");
    v = getenv("F2KT_A=x");
    line("getenv(\"F2KT_A=x\"): %s", v == NULL ? "NULL" : "a value");

    r = _putenv("F2KT_A=");
    line("_putenv(\"F2KT_A=\"): %d", r);
    line("getenv(\"F2KT_A\") after: %s", value(getenv("F2KT_A")));

    arm();
    ok = SetEnvironmentVariableA("F2KT_B", "two");
    line("SetEnvironmentVariableA(\"F2KT_B\", \"two\"): ret=%d err=%s", ok, le());
    line("getenv(\"F2KT_B\") after: %s", value(getenv("F2KT_B")));

    SetEnvironmentVariableA("F2KT_B", NULL);
}

/* --- heap ---------------------------------------------------------- */

/* A block as printed: whether there is one, and its _msize. */
static void show_block(const char *label, void *p)
{
    if (p == NULL) {
        line("%s: NULL", label);
        return;
    }
    line("%s: a block, _msize %u", label, (unsigned)_msize(p));
}

static void sec_heap(void)
{
    new_fn op_new = (new_fn)crt_export("??2@YAPAXI@Z");
    delete_fn op_delete = (delete_fn)crt_export("??3@YAXPAX@Z");
    void *n1;
    void *n100;
    void *n0;
    void *n0b;
    char *m1;
    char *m100;
    char *m5000;
    char *p;
    char *q;
    char *r;
    int kept;
    int i;

    line("operator new resolved: %s, operator delete resolved: %s", yesno(op_new != NULL), yesno(op_delete != NULL));
    if (op_new == NULL || op_delete == NULL) {
        return;
    }

    n1 = op_new(1);
    show_block("new(1)", n1);
    n100 = op_new(100);
    show_block("new(100)", n100);
    if (n100 != NULL) {
        for (i = 0; i < 100; i++) {
            ((char *)n100)[i] = (char)0x5A;
        }
    }
    n0 = op_new(0);
    show_block("new(0)", n0);
    n0b = op_new(0);
    show_block("new(0) again", n0b);
    line("the two new(0) blocks distinct: %s", yesno(n0 != NULL && n0b != NULL && n0 != n0b));

    m1 = (char *)malloc(1);
    show_block("malloc(1)", m1);
    m100 = (char *)malloc(100);
    show_block("malloc(100)", m100);
    m5000 = (char *)malloc(5000);
    show_block("malloc(5000)", m5000);
    free(m1);
    free(m100);
    free(m5000);

    op_delete(n1);
    op_delete(n100);
    op_delete(n0);
    op_delete(n0b);
    line("delete on each new block: returned");
    op_delete(NULL);
    line("delete(NULL): returned");

    p = (char *)malloc(5000);
    if (p == NULL) {
        line("malloc(5000): NULL");
        return;
    }
    for (i = 0; i < 100; i++) {
        p[i] = (char)('a' + i % 26);
    }
    q = (char *)_expand(p, 100);
    kept = q != NULL;
    for (i = 0; kept && i < 100; i++) {
        kept = q[i] == (char)('a' + i % 26);
    }
    if (q == NULL) {
        line("_expand(a 5000-byte block, 100): NULL");
        free(p);
        return;
    }
    line("_expand(a 5000-byte block, 100): a block, the same pointer %s, _msize %u, contents kept %s", yesno(q == p),
         (unsigned)_msize(q), yesno(kept));
    r = (char *)_expand(q, 100);
    if (r == NULL) {
        line("_expand(that block, 100): NULL");
        free(q);
        return;
    }
    line("_expand(that block, 100): a block, the same pointer %s, _msize %u", yesno(r == q), (unsigned)_msize(r));
    free(r);
}

/* --- beginthread -------------------------------------------------- */

/* _beginthreadex and _endthreadex, through GetProcAddress (cdecl, as
   process.h declares them). */
typedef unsigned (__stdcall *thread_routine)(void *param);
typedef unsigned long (__cdecl *beginthreadex_fn)(void *security, unsigned stack, thread_routine routine,
                                                  void *param, unsigned flags, unsigned *id);
typedef void (__cdecl *endthreadex_fn)(unsigned code);

static beginthreadex_fn begin_ex;
static endthreadex_fn end_ex;
static volatile DWORD child_id;
static volatile int after_end;

static unsigned __stdcall plus_seventy(void *param)
{
    child_id = GetCurrentThreadId();
    return (unsigned)param + 70;
}

static unsigned __stdcall ends_with_55(void *param)
{
    (void)param;
    end_ex(55);
    after_end = 1;
    return 1;
}

static unsigned __stdcall own_errno(void *param)
{
    (void)param;
    errno = ERANGE;
    return (unsigned)errno;
}

/* Wait for a thread _beginthreadex started, then print its exit code
   through the handle (which the C runtime leaves open) and close it. */
static void finish_thread(unsigned long h)
{
    DWORD w, code = 0xDEADDEAD;
    BOOL r;
    const char *e;

    w = WaitForSingleObject((HANDLE)h, WAIT_MS);
    arm();
    r = GetExitCodeThread((HANDLE)h, &code);
    e = le();
    line("  its end: %s; GetExitCodeThread through the handle: ret=%d code %lu err=%s", wr(w), r, r ? code : 0, e);
    arm();
    r = CloseHandle((HANDLE)h);
    e = le();
    line("  CloseHandle: ret=%d err=%s", r, e);
}

static void sec_beginthread(void)
{
    unsigned long h;
    unsigned tid = 0;
    DWORD w, n;

    begin_ex = (beginthreadex_fn)crt_export("_beginthreadex");
    end_ex = (endthreadex_fn)crt_export("_endthreadex");
    line("msvcrt exports _beginthreadex %s, _endthreadex %s", yesno(begin_ex != NULL), yesno(end_ex != NULL));
    if (begin_ex == NULL || end_ex == NULL) {
        return;
    }
    child_id = 0;
    h = begin_ex(NULL, 0, plus_seventy, (void *)7, 0, &tid);
    line("_beginthreadex(a routine returning its parameter plus 70, 7): a handle %s, an id %s", yesno(h != 0),
         yesno(tid != 0));
    if (h != 0) {
        WaitForSingleObject((HANDLE)h, WAIT_MS);
        line("  the id the child's own: %s", yesno(tid == child_id));
        finish_thread(h);
    }

    after_end = 0;
    h = begin_ex(NULL, 0, ends_with_55, NULL, CREATE_SUSPENDED, &tid);
    line("_beginthreadex(a routine calling _endthreadex(55), CREATE_SUSPENDED): a handle %s", yesno(h != 0));
    if (h != 0) {
        w = WaitForSingleObject((HANDLE)h, 200);
        line("  a 200 ms wait while it is suspended: %s", wr(w));
        n = ResumeThread((HANDLE)h);
        line("  ResumeThread: %lu", n);
        finish_thread(h);
        line("  the code after _endthreadex ran: %s", yesno(after_end));
    }

    h = begin_ex(NULL, 0x10000, plus_seventy, (void *)1, 0, &tid);
    line("_beginthreadex(a 64 KiB stack, 1): a handle %s", yesno(h != 0));
    if (h != 0) {
        finish_thread(h);
    }

    h = begin_ex(NULL, 0, plus_seventy, (void *)2, 0, NULL);
    line("_beginthreadex(no id pointer, 2): a handle %s", yesno(h != 0));
    if (h != 0) {
        finish_thread(h);
    }

    errno = 0;
    h = begin_ex(NULL, 0, own_errno, NULL, 0, &tid);
    line("_beginthreadex(a routine setting errno to ERANGE and returning it): a handle %s", yesno(h != 0));
    if (h != 0) {
        finish_thread(h);
        line("  this thread's errno still 0: %s", yesno(errno == 0));
    }
}

static const section_t sections[] = {
    { "cmdline", sec_cmdline, F2KT_ALWAYS },
    { "getenv", sec_getenv, F2KT_ALWAYS },
    { "heap", sec_heap, F2KT_ALWAYS },
    { "beginthread", sec_beginthread, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    g_argc = argc;
    g_argv = argv;
    return run_sections("process", sections, argc, argv);
}
