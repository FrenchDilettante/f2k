/*
 * crt - msvcrt.dll's startup and exit protocol, as a /MD program meets
 * it (cmd.exe's own startup and exit).
 *
 * Built with /MD: the C runtime is msvcrt.dll's, and the startup code
 * linked into the program (from msvcrt.lib) calls its __set_app_type,
 * __p__fmode, __p__commode, _controlfp, _initterm, __getmainargs,
 * __setusermatherr and exit, and runs main under _XcptFilter.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   args       argc and argv as __getmainargs splits the command line
 *              (capture.bat runs `crt args one "two words" back\slash
 *              "tail\\" a\\\"b "q\"uote" "" x"y z"w`), __argc and __argv
 *              against main's
 *   env        envp against _environ and __initenv, and against
 *              GetEnvironmentStrings' block: the entries the C runtime
 *              keeps, and whether a PATH entry is there (never a value)
 *   modes      _fmode and _commode as the startup leaves them;
 *              _controlfp's initial control word, a precision and a
 *              rounding field set and restored
 *   init       .CRT$XIU and .CRT$XCU initializers (_initterm's tables):
 *              that they ran before main, in which order, and whether
 *              __getmainargs had run by then
 *
 * Named-only sections (each ends the process its own way):
 *
 *   exit       atexit handlers, then exit(3): the handlers run in reverse
 *              order, and stdout's buffered text is flushed after them
 *   _exit      an atexit handler and buffered stdout text, then _exit(4):
 *              neither the handler nor the text should show
 *   return     an atexit handler, then main returns 9: the startup's
 *              exit(9) runs it
 *   unhandled  an access violation in main: the startup's _XcptFilter,
 *              the exit code
 *
 * stdout's buffering depends on what it is (a console: flushed at each
 * call; a file, as on the real machine: when full): a section observing
 * buffered output sets stdout's buffer itself (setvbuf, _IOFBF), so the
 * output is the same either way. line() writes with WriteFile, not
 * through the CRT's buffer.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat crt):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% crt.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <float.h>

/* msvcrt.dll's accessors for _commode and __initenv, which the startup
 * code calls and the public headers do not declare. */
__declspec(dllimport) int * __cdecl __p__commode(void);
__declspec(dllimport) char *** __cdecl __p___initenv(void);

static int g_argc;
static char **g_argv;
static char **g_envp;
static int return_code;     /* set by the return section: main's return value */

/* --- the initializers (_initterm's tables) ------------------------- */

/* What ran before main, in order: each initializer appends its name and
 * __argc as it found it (0 before __getmainargs has run). */
static char init_log[512];
static int init_len;
static int main_entered;

static void log_init(const char *what)
{
    init_len += sprintf(init_log + init_len, "%s%s (main entered %s, __argc %d)", init_len != 0 ? ", " : "",
                        what, yesno(main_entered), __argc);
}

static void __cdecl init_xiu(void)
{
    log_init("XIU");
}

static void __cdecl init_xcu_first(void)
{
    log_init("XCU first");
}

static void __cdecl init_xcu_second(void)
{
    log_init("XCU second");
}

/* The documented way to run code before main: a function pointer in the
 * .CRT$XI* (C initializers) or .CRT$XC* (C++ constructors) sections, which
 * the linker sorts by name between the startup's own __xi_a/__xi_z and
 * __xc_a/__xc_z bounds. Not static, so the compiler keeps them. */
#pragma data_seg(".CRT$XIU")
void (__cdecl *f2k_xiu)(void) = init_xiu;
#pragma data_seg(".CRT$XCU")
void (__cdecl *f2k_xcu_first)(void) = init_xcu_first;
void (__cdecl *f2k_xcu_second)(void) = init_xcu_second;
#pragma data_seg()

/* --- helpers ------------------------------------------------------- */

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
        out[n++] = (char)(*b >= 'a' && *b <= 'z' ? *b - 'a' + 'A' : *b);
        b++;
    }
    out[n] = 0;
    return out;
}

/* strlen's count, without importing it. */
static int str_len(const char *s)
{
    int n = 0;

    while (s[n] != 0) {
        n++;
    }
    return n;
}

/* Whether `s` starts with `prefix`, ASCII letters in either case. */
static int starts_nocase(const char *s, const char *prefix)
{
    for (; *prefix != 0; s++, prefix++) {
        char a = *s;
        char b = *prefix;

        if (a >= 'a' && a <= 'z') a = (char)(a - 'a' + 'A');
        if (b >= 'a' && b <= 'z') b = (char)(b - 'a' + 'A');
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

/* --- args ---------------------------------------------------------- */

static void sec_args(void)
{
    char base[MAX_PATH];
    int i;

    line("argc: %d", g_argc);
    for (i = 0; i < g_argc; i++) {
        if (i == 0) {
            line("argv[0]: %s", basename_upper(g_argv[0], base, sizeof base));
        } else {
            line("argv[%d]: [%s]", i, g_argv[i]);
        }
    }
    line("argv[argc] is NULL: %s", yesno(g_argv[g_argc] == NULL));
    line("__argc is argc: %s, __argv is argv: %s", yesno(__argc == g_argc), yesno(__argv == g_argv));
}

/* --- env ----------------------------------------------------------- */

static void sec_env(void)
{
    char *block;
    char *e;
    char **p;
    int kept = 0;
    int count = 0;
    int all_found = 1;
    int in_order = 1;
    int path_in_envp = 0;
    int path_in_block = 0;
    int equals_in_envp = 0;
    char *next;

    line("envp is _environ: %s", yesno(g_envp == _environ));
    line("envp is __initenv: %s", yesno(g_envp == *__p___initenv()));

    block = GetEnvironmentStrings();
    line("GetEnvironmentStrings: a block %s", yesno(block != NULL));
    if (block == NULL) {
        return;
    }
    for (e = block; *e != 0; e += str_len(e) + 1) {
        if (e[0] != '=') {
            kept++;
        }
        if (starts_nocase(e, "PATH=")) {
            path_in_block = 1;
        }
    }
    /* Every envp entry, in order, is the block's next entry not starting
       with '=' (the per-drive current directories cmd.exe keeps there). */
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
            next += str_len(next) + 1;
        }
        if (*next == 0) {
            all_found = 0;
            continue;
        }
        if (strcmp(*p, next) != 0) {
            in_order = 0;
        }
        next += str_len(next) + 1;
    }
    line("envp entries: as many as the block's not starting with '=': %s", yesno(count == kept));
    line("envp entries: the block's not starting with '=', in order: %s", yesno(all_found && in_order));
    line("envp entries starting with '=': %s", yesno(equals_in_envp));
    line("a PATH entry: in envp %s, in the block %s", yesno(path_in_envp), yesno(path_in_block));
    FreeEnvironmentStringsA(block);
}

/* --- modes --------------------------------------------------------- */

static void sec_modes(void)
{
    unsigned int initial;
    unsigned int r;

    line("_fmode: 0x%X", _fmode);
    line("_commode: 0x%X", *__p__commode());

    initial = _controlfp(0, 0);
    line("_controlfp(0, 0): 0x%08X", initial);
    line("fields: precision 0x%X rounding 0x%X infinity 0x%X exception mask 0x%X",
         initial & _MCW_PC, initial & _MCW_RC, initial & _MCW_IC, initial & _MCW_EM);
    r = _controlfp(_PC_24, _MCW_PC);
    line("_controlfp(_PC_24, _MCW_PC): 0x%08X", r);
    r = _controlfp(_RC_CHOP, _MCW_RC);
    line("_controlfp(_RC_CHOP, _MCW_RC): 0x%08X", r);
    r = _controlfp(initial, _MCW_PC | _MCW_RC);
    line("restored: 0x%08X, as at first: %s", r, yesno(r == initial));
    line("_controlfp(0, 0): 0x%08X", _controlfp(0, 0));
}

/* --- init ---------------------------------------------------------- */

static void sec_init(void)
{
    line("before main: %s", init_log[0] != 0 ? init_log : "nothing");
    line("argc in main: %d", g_argc);
}

/* --- the exit paths (named only) ----------------------------------- */

static char stdout_buffer[512];

/* stdout buffered in full, whatever it is (see the header). */
static void buffer_stdout(void)
{
    int r = setvbuf(stdout, stdout_buffer, _IOFBF, sizeof stdout_buffer);

    line("setvbuf(stdout, _IOFBF, %d): %d", (int)sizeof stdout_buffer, r);
}

static void at_first(void)
{
    line("atexit: the first registered");
}

static void at_second(void)
{
    printf("atexit: the second registered, through printf\n");
}

static void at_third(void)
{
    line("atexit: the third registered");
}

static void sec_exit(void)
{
    int r1, r2, r3;

    buffer_stdout();
    r1 = atexit(at_first);
    r2 = atexit(at_second);
    r3 = atexit(at_third);
    line("atexit: %d %d %d", r1, r2, r3);
    printf("exit: printf before exit, not flushed\n");
    line("exit: calling exit(3)");
    exit(3);
}

static void sec_quick_exit(void)
{
    int r;

    buffer_stdout();
    r = atexit(at_first);
    line("atexit: %d", r);
    printf("_exit: printf before _exit, not flushed\n");
    line("_exit: calling _exit(4)");
    _exit(4);
}

static void sec_return(void)
{
    int r;

    r = atexit(at_first);
    line("atexit: %d", r);
    line("return: main returns 9");
    return_code = 9;
}

static void sec_unhandled(void)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    line("unhandled: writing to NULL");
    *(volatile int *)0 = 1;
    line("unhandled: survived");
}

static const section_t sections[] = {
    { "args", sec_args, F2KT_ALWAYS },
    { "env", sec_env, F2KT_ALWAYS },
    { "modes", sec_modes, F2KT_ALWAYS },
    { "init", sec_init, F2KT_ALWAYS },
    { "exit", sec_exit, F2KT_NAMED },
    { "_exit", sec_quick_exit, F2KT_NAMED },
    { "return", sec_return, F2KT_NAMED },
    { "unhandled", sec_unhandled, F2KT_NAMED },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv, char **envp)
{
    int r;

    main_entered = 1;
    g_argc = argc;
    g_argv = argv;
    g_envp = envp;
    r = run_sections("crt", sections, argc, argv);
    return r != 0 ? r : return_code;
}
