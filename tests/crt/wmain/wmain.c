/*
 * wmain - msvcrt.dll's wide startup, as a /MD program whose main is
 * wmain meets it (cmd.exe's own): the startup linked into the program
 * (wmainCRTStartup, from msvcrt.lib) calls __wgetmainargs, and wmain
 * receives argv and envp in their wide form.
 *
 * The program's argv and environment differ from machine to machine,
 * so the sections that print them run the program again as a child
 * ("wmain kid <what>", handled before the section table, not a
 * section) with a command line and an environment block of their own,
 * through CreateProcessW; the child prints through the standard handles
 * it inherits, and the section waits for it (5 seconds at most, then
 * ends it) before printing its exit code. Pointers print only as
 * relations.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   args         the program's own argc and argv[1], argv[0]'s final
 *                path component; then a child's command line
 *                (`wmain.exe kid args one "two words" back\slash "tail\\"
 *                a\\\"b "q\"uote" "" x"y z"w`, e acute and alpha, as
 *                __wgetmainargs splits it): argc, every argv entry,
 *                argv[argc], *__p___wargv() and *__p___argc() against
 *                wmain's
 *   env          a child started with an environment block of its own
 *                (CREATE_UNICODE_ENVIRONMENT: F2KA=one, =F2K=hidden,
 *                F2KB=two words, F2KW=alpha and e acute, f2kc=lower):
 *                envp's entries in order, envp against *__p___winitenv()
 *                and *__p__wenviron(), the narrow *__p__environ() and
 *                *__p___initenv() of a wide program, _wgetenv; getenv
 *                and whether the narrow environment exists after it
 *   accessors    in the program itself: *__p___wargv(), *__p___winitenv(),
 *                *__p__wenviron() and *__p___argc() against wmain's argv,
 *                envp and argc; the narrow *__p___argv(), *__p__environ()
 *                and *__p___initenv(); envp against GetEnvironmentStringsW's
 *                block (the entries not starting with '=', in order;
 *                whether a PATH entry is there, never a value)
 *   getmainargs  __wgetmainargs called directly, twice: argc and argv's
 *                strings against wmain's, the pointers against wmain's
 *                and the accessors' after each call; __getmainargs, the
 *                narrow form, in the same wide program
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat wmain):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wmain.c
 * (the linker picks wmainCRTStartup for a program whose main is wmain).
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <wchar.h>

/* msvcrt.dll's startup calls and accessors. __wgetmainargs,
 * __getmainargs, _startupinfo and __p___winitenv are not in the public
 * headers; the others are declared here as stdlib.h declares them under
 * /MD. */
typedef struct {
    int newmode;
} f2k_startupinfo;

__declspec(dllimport) void __cdecl __wgetmainargs(int *argc, wchar_t ***argv, wchar_t ***envp, int expand,
                                                  f2k_startupinfo *info);
__declspec(dllimport) void __cdecl __getmainargs(int *argc, char ***argv, char ***envp, int expand,
                                                 f2k_startupinfo *info);
__declspec(dllimport) wchar_t *** __cdecl __p___winitenv(void);
__declspec(dllimport) char *** __cdecl __p___initenv(void);
__declspec(dllimport) wchar_t *** __cdecl __p___wargv(void);
__declspec(dllimport) char *** __cdecl __p___argv(void);
__declspec(dllimport) int * __cdecl __p___argc(void);
__declspec(dllimport) wchar_t *** __cdecl __p__wenviron(void);
__declspec(dllimport) char *** __cdecl __p__environ(void);

/* wmain's own arguments. */
static int g_argc;
static wchar_t **g_argv;
static wchar_t **g_envp;

/* --- helpers ------------------------------------------------------- */

/* The upper-cased final path component of `path`, narrowed (ASCII). */
static const char *basename_upper(const wchar_t *path)
{
    static char out[MAX_PATH];
    const wchar_t *b = path;
    const wchar_t *p;
    int n = 0;

    for (p = path; *p != 0; p++) {
        if (*p == '\\' || *p == '/' || *p == ':') {
            b = p + 1;
        }
    }
    while (*b != 0 && n < MAX_PATH - 1) {
        wchar_t c = *b++;

        out[n++] = (char)(c >= 'a' && c <= 'z' ? c - 'a' + 'A' : (c < 0x80 ? c : '?'));
    }
    out[n] = 0;
    return out;
}

static int starts_nocase(const wchar_t *s, const char *prefix)
{
    for (; *prefix != 0; s++, prefix++) {
        wchar_t a = *s;
        char b = *prefix;

        if (a >= 'a' && a <= 'z') a = (wchar_t)(a - 'a' + 'A');
        if (b >= 'a' && b <= 'z') b = (char)(b - 'a' + 'A');
        if (a != (wchar_t)b) {
            return 0;
        }
    }
    return 1;
}

/* Start this program as a child with `tail` after its name on the
 * command line and `env` (NULL: this program's own) as its environment;
 * wait for it and print its exit code. */
static void run_child(const wchar_t *tail, const wchar_t *env)
{
    static wchar_t cmd[1024];
    wchar_t path[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD w, code;
    BOOL r;

    GetModuleFileNameW(NULL, path, MAX_PATH);
    wcscpy(cmd, L"wmain.exe ");
    wcscat(cmd, tail);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    r = CreateProcessW(path, cmd, NULL, NULL, TRUE, env != NULL ? CREATE_UNICODE_ENVIRONMENT : 0, (void *)env,
                       NULL, &si, &pi);
    if (!r) {
        line("CreateProcessW failed err=%lu", GetLastError());
        return;
    }
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 99);
        WaitForSingleObject(pi.hProcess, WAIT_MS);
        line("the child did not end within 5 seconds: ended");
    }
    code = 0xDEADDEAD;
    GetExitCodeProcess(pi.hProcess, &code);
    line("the child's exit code: %lu", code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

/* --- the children -------------------------------------------------- */

static int kid_args(void)
{
    int i;

    line("kid: argc %d", g_argc);
    for (i = 0; i < g_argc; i++) {
        line("kid: argv[%d] [%s]", i, ws(g_argv[i]));
    }
    line("kid: argv[argc] NULL %s", yesno(g_argv[g_argc] == NULL));
    line("kid: *__p___wargv() is argv %s, *__p___argc() is argc %s", yesno(*__p___wargv() == g_argv),
         yesno(*__p___argc() == g_argc));
    return 0;
}

static int kid_env(void)
{
    wchar_t **p;
    wchar_t *block;
    wchar_t *e;
    const wchar_t *value;
    char *narrow;
    int count = 0;
    int kept = 0;

    for (p = g_envp; *p != NULL; p++) {
        line("kid: envp[%d] [%s]", count, ws(*p));
        count++;
    }
    line("kid: envp entries %d", count);
    line("kid: envp is *__p___winitenv() %s, is *__p__wenviron() %s", yesno(g_envp == *__p___winitenv()),
         yesno(g_envp == *__p__wenviron()));
    line("kid: the narrow *__p__environ() NULL %s, *__p___initenv() NULL %s", yesno(*__p__environ() == NULL),
         yesno(*__p___initenv() == NULL));
    block = GetEnvironmentStringsW();
    if (block != NULL) {
        for (e = block; *e != 0; e += wcslen(e) + 1) {
            if (e[0] != '=') {
                kept++;
            }
        }
        FreeEnvironmentStringsW(block);
    }
    line("kid: GetEnvironmentStringsW's entries not starting with '=': %d", kept);
    value = _wgetenv(L"F2KB");
    line("kid: _wgetenv(F2KB) [%s], _wgetenv(F2KC) [%s], _wgetenv(F2K) [%s]", ws(value), ws(_wgetenv(L"F2KC")),
         ws(_wgetenv(L"F2K")));
    narrow = getenv("F2KA");
    line("kid: getenv(F2KA) [%s]; the narrow *__p__environ() NULL after it %s", narrow != NULL ? narrow : "(null)",
         yesno(*__p__environ() == NULL));
    return 0;
}

/* --- args ---------------------------------------------------------- */

static void sec_args(void)
{
    static const wchar_t tail[] = {
        'k', 'i', 'd', ' ', 'a', 'r', 'g', 's', ' ', 'o', 'n', 'e', ' ',
        '"', 't', 'w', 'o', ' ', 'w', 'o', 'r', 'd', 's', '"', ' ',
        'b', 'a', 'c', 'k', '\\', 's', 'l', 'a', 's', 'h', ' ',
        '"', 't', 'a', 'i', 'l', '\\', '\\', '"', ' ',
        'a', '\\', '\\', '\\', '"', 'b', ' ',
        '"', 'q', '\\', '"', 'u', 'o', 't', 'e', '"', ' ',
        '"', '"', ' ',
        'x', '"', 'y', ' ', 'z', '"', 'w', ' ',
        0x00E9, 0x03B1, 0
    };

    line("argc %d, argv[1] [%s], argv[0]'s final component %s", g_argc, g_argc > 1 ? ws(g_argv[1]) : "-",
         basename_upper(g_argv[0]));
    line("argv[argc] NULL %s", yesno(g_argv[g_argc] == NULL));
    line("the child's command line: wmain.exe %s", ws(tail));
    run_child(tail, NULL);
}

/* --- env ----------------------------------------------------------- */

static void sec_env(void)
{
    static const wchar_t block[] = {
        'F', '2', 'K', 'A', '=', 'o', 'n', 'e', 0,
        '=', 'F', '2', 'K', '=', 'h', 'i', 'd', 'd', 'e', 'n', 0,
        'F', '2', 'K', 'B', '=', 't', 'w', 'o', ' ', 'w', 'o', 'r', 'd', 's', 0,
        'F', '2', 'K', 'W', '=', 0x03B1, 0x00E9, 0,
        'f', '2', 'k', 'c', '=', 'l', 'o', 'w', 'e', 'r', 0,
        0
    };

    line("the child's environment: F2KA=one, =F2K=hidden, F2KB=two words, F2KW=<U+03B1><U+00E9>, f2kc=lower");
    run_child(L"kid env", block);
}

/* --- accessors ----------------------------------------------------- */

static void sec_accessors(void)
{
    wchar_t *block;
    wchar_t *e;
    wchar_t *next;
    wchar_t **p;
    int kept = 0;
    int count = 0;
    int in_order = 1;
    int all_found = 1;
    int path_in_envp = 0;
    int path_in_block = 0;
    int equals_in_envp = 0;

    line("*__p___wargv() is argv %s, *__p___argc() is argc %s", yesno(*__p___wargv() == g_argv),
         yesno(*__p___argc() == g_argc));
    line("*__p___winitenv() is envp %s, *__p__wenviron() is envp %s", yesno(*__p___winitenv() == g_envp),
         yesno(*__p__wenviron() == g_envp));
    line("the narrow ones: *__p___argv() NULL %s, *__p__environ() NULL %s, *__p___initenv() NULL %s",
         yesno(*__p___argv() == NULL), yesno(*__p__environ() == NULL), yesno(*__p___initenv() == NULL));

    block = GetEnvironmentStringsW();
    line("GetEnvironmentStringsW: a block %s", yesno(block != NULL));
    if (block == NULL) {
        return;
    }
    for (e = block; *e != 0; e += wcslen(e) + 1) {
        if (e[0] != '=') {
            kept++;
        }
        if (starts_nocase(e, "PATH=")) {
            path_in_block = 1;
        }
    }
    next = block;
    for (p = g_envp; *p != NULL; p++) {
        count++;
        if (starts_nocase(*p, "PATH=")) {
            path_in_envp = 1;
        }
        if ((*p)[0] == '=') {
            equals_in_envp = 1;
        }
        while (*next != 0 && next[0] == '=') {
            next += wcslen(next) + 1;
        }
        if (*next == 0) {
            all_found = 0;
            continue;
        }
        if (wcscmp(*p, next) != 0) {
            in_order = 0;
        }
        next += wcslen(next) + 1;
    }
    line("envp entries: as many as the block's not starting with '=': %s", yesno(count == kept));
    line("envp entries: the block's not starting with '=', in order: %s", yesno(all_found && in_order));
    line("envp entries starting with '=': %s", yesno(equals_in_envp));
    line("a PATH entry: in envp %s, in the block %s", yesno(path_in_envp), yesno(path_in_block));
    FreeEnvironmentStringsW(block);
}

/* --- getmainargs --------------------------------------------------- */

/* Whether two argument vectors hold the same strings. */
static int same_args(int argc, wchar_t **a, wchar_t **b)
{
    int i;

    for (i = 0; i < argc; i++) {
        if (a[i] == NULL || b[i] == NULL || wcscmp(a[i], b[i]) != 0) {
            return 0;
        }
    }
    return 1;
}

static void sec_getmainargs(void)
{
    f2k_startupinfo info;
    int argc1 = -1, argc2 = -1, nargc = -1;
    wchar_t **argv1 = NULL, **argv2 = NULL;
    wchar_t **envp1 = NULL, **envp2 = NULL;
    char **nargv = NULL;
    char **nenvp = NULL;
    char **q;
    wchar_t **p;
    int wcount = 0, ncount = 0;

    info.newmode = 0;
    __wgetmainargs(&argc1, &argv1, &envp1, 0, &info);
    line("__wgetmainargs: argc is wmain's %s; argv's strings wmain's %s", yesno(argc1 == g_argc),
         yesno(argc1 == g_argc && argv1 != NULL && same_args(argc1, argv1, g_argv)));
    line("  argv is wmain's %s, envp is wmain's %s", yesno(argv1 == g_argv), yesno(envp1 == g_envp));
    line("  *__p___wargv() is its argv %s, *__p___winitenv() is its envp %s, *__p__wenviron() is its envp %s",
         yesno(*__p___wargv() == argv1), yesno(*__p___winitenv() == envp1), yesno(*__p__wenviron() == envp1));

    info.newmode = 0;
    __wgetmainargs(&argc2, &argv2, &envp2, 0, &info);
    line("__wgetmainargs, again: argc the same %s; argv the first call's %s, envp the first call's %s",
         yesno(argc2 == argc1), yesno(argv2 == argv1), yesno(envp2 == envp1));
    line("  argv's strings wmain's %s", yesno(argc2 == g_argc && argv2 != NULL && same_args(argc2, argv2, g_argv)));

    info.newmode = 0;
    __getmainargs(&nargc, &nargv, &nenvp, 0, &info);
    line("__getmainargs, in the wide program: argc is wmain's %s, argv[1] [%s]", yesno(nargc == g_argc),
         nargv != NULL && nargc > 1 ? nargv[1] : "-");
    line("  *__p___argv() is its argv %s, *__p___initenv() is its envp %s, *__p__environ() is its envp %s",
         yesno(*__p___argv() == nargv), yesno(*__p___initenv() == nenvp), yesno(*__p__environ() == nenvp));
    for (p = g_envp; *p != NULL; p++) {
        wcount++;
    }
    if (nenvp != NULL) {
        for (q = nenvp; *q != NULL; q++) {
            ncount++;
        }
    }
    line("  its envp has as many entries as wmain's: %s", yesno(nenvp != NULL && ncount == wcount));
    line("  *__p___wargv() still the second call's argv %s", yesno(*__p___wargv() == argv2));
}

static const section_t sections[] = {
    { "args", sec_args, F2KT_ALWAYS },
    { "env", sec_env, F2KT_ALWAYS },
    { "accessors", sec_accessors, F2KT_ALWAYS },
    { "getmainargs", sec_getmainargs, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int wmain(int argc, wchar_t **argv, wchar_t **envp)
{
    static char narrow[8][64];
    static char *nargv[9];
    int i, n;

    g_argc = argc;
    g_argv = argv;
    g_envp = envp;
    if (argc >= 3 && wcscmp(argv[1], L"kid") == 0) {
        if (wcscmp(argv[2], L"args") == 0) {
            return kid_args();
        }
        if (wcscmp(argv[2], L"env") == 0) {
            return kid_env();
        }
        line("kid: no such mode");
        return 2;
    }
    n = argc < 8 ? argc : 8;
    for (i = 0; i < n; i++) {
        WideCharToMultiByte(CP_ACP, 0, argv[i], -1, narrow[i], 64, NULL, NULL);
        narrow[i][63] = 0;
        nargv[i] = narrow[i];
    }
    nargv[n] = NULL;
    return run_sections("wmain", sections, n, nargv);
}
