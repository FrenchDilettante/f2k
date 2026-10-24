/*
 * runtime - the process environment a C program starts into.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   args       argc/argv as the CRT splits the command line (the suite
 *              and capture.bat run `runtime args one "two words"
 *              back\slash "q\"uote"`), the raw command line's tail,
 *              the module file name
 *   version    GetVersion, GetVersionExA, the CRT's version globals
 *   module     GetModuleHandleA, GetProcAddress, LoadLibraryA,
 *              FreeLibrary, GetModuleFileNameA on kernel32, the
 *              program's own PE headers read through memory
 *   teb        the TEB and PEB as compilers and runtimes use them:
 *              self pointer, PEB image base and process heap, client
 *              ids, stack bounds, the last-error slot, the SEH chain,
 *              the PEB's OS version and image subsystem fields
 *   lasterror  SetLastError/GetLastError, which calls keep or set the
 *              value, FormatMessageA over system messages (into the
 *              caller's buffer, an allocated one, by line width)
 *   env        the environment block, Set/GetEnvironmentVariableA,
 *              ExpandEnvironmentStringsA, the CRT's getenv/_putenv
 *   locale     code pages, MultiByteToWideChar/WideCharToMultiByte
 *              tables and edge cases, LCMapString, GetStringType,
 *              CompareString, locale info, the CRT's setlocale
 *   crt        CRT formatting and parsing, floating point, qsort,
 *              setjmp/longjmp, rand, string helpers
 *   seh        structured exception handling: hardware faults and
 *              RaiseException caught by __except, filter results
 *              (continue search / continue execution), __finally on
 *              normal and abnormal exits, unwinding through frames,
 *              stack overflow
 *   windir     GetWindowsDirectoryA: the answer, the return with room,
 *              with too little (the size needed) and with none
 *   filetime   CompareFileTime: equal, earlier, later, the high dword
 *              alone, the low and high dwords' top bits (unsigned)
 *   lstrcmp    lstrcmpA and lstrcmpiA: case, word sort (hyphens and
 *              apostrophes), prefixes, digits, Latin-1 letters, NULL
 *              arguments (under __try); the sign only
 *   threadlocale  GetThreadLocale, SetThreadLocale to French and back,
 *              invalid and default LCIDs; GetUserDefaultLCID beside it
 *   localtime  SetLocalTime to the current time (GetLocalTime's), then
 *              invalid fields: the return and the error, never the time
 *   debugbreak DebugBreak caught by __except: the exception code, the
 *              filter's calls, which module the exception address lies
 *              in (kernel32, ntdll, the program), never the address
 *
 * Named-only sections:
 *
 *   console    std handles, GetFileType, WriteConsoleA, console code
 *              pages, printf/puts/stderr through the CRT. Capture on an
 *              interactive console: a redirect changes these answers.
 *   unhandled  SetUnhandledExceptionFilter: the filter sees an access
 *              violation and the process exits with its code
 *   exit       atexit handlers run in reverse order, then exit(7)
 *
 * The A calls' observations run twice: through the A calls, then through
 * their W twins on the same inputs, each W line right after its A line
 * (the W lines carry the W names, or "(W)"): the command line and module
 * file name (args, beside one line for GetStartupInfoW against
 * GetStartupInfoA), GetVersionExW (version, with the EX sizes of both),
 * the module calls (module, teb), FormatMessageW (lasterror),
 * GetEnvironmentVariableW and ExpandEnvironmentStringsW (env, beside
 * GetEnvironmentStringsA by its own name), WriteConsoleW (console),
 * GetWindowsDirectoryW (windir) and lstrcmpW and lstrcmpiW (lstrcmp).
 * The locale section enumerates the system locales through both
 * EnumSystemLocalesA and EnumSystemLocalesW.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo runtime.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <io.h>

/* Windows 2000's additions, which MSVC 6's headers may lack. */
#ifndef LOCALE_RETURN_NUMBER
#define LOCALE_RETURN_NUMBER 0x20000000
#endif
#ifndef LCID_SUPPORTED
#define LCID_SUPPORTED 0x00000002
#endif
#ifndef WC_NO_BEST_FIT_CHARS
#define WC_NO_BEST_FIT_CHARS 0x00000400
#endif

/* GetEnvironmentStringsA by its own name: windows.h maps the name onto
   GetEnvironmentStrings, the same function's unsuffixed export. */
#ifdef GetEnvironmentStringsA
#undef GetEnvironmentStringsA
#endif
WINBASEAPI LPSTR WINAPI GetEnvironmentStringsA(VOID);

/* OSVERSIONINFOEXA and OSVERSIONINFOEXW as Windows 2000 lays them out
   (156 and 284 bytes), which MSVC 6's headers may lack. */
typedef struct {
    OSVERSIONINFOA base;
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
} f2k_osviexa;

typedef struct {
    OSVERSIONINFOW base;
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
} f2k_osviexw;

static int g_argc;
static char **g_argv;

/* --- helpers ------------------------------------------------------- */

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

/* The command line after the program name, as GetCommandLineA has it. */
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

/* The same, of GetCommandLineW's. */
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

/* A wide string's units below 0x100 as their bytes (any other as '?'),
   into `out`: a wide path for basename_upper and is_absolute. */
static const char *narrow_w(const WCHAR *w, char *out, int size)
{
    int n = 0;

    while (*w != 0 && n < size - 1) {
        out[n++] = *w < 0x100 ? (char)*w : '?';
        w++;
    }
    out[n] = 0;
    return out;
}

/* Whether a narrow and a wide string hold the same text, unit by unit
   (both NULL agree). */
/* The STARTUPINFO fields that differ between the A and W forms, by name, into `out`
 * ("none" when they agree): which ones, not their values, which are the machine's. */
static void startup_differences(const STARTUPINFOA *a, const STARTUPINFOW *w, char *out)
{
    out[0] = '\0';
    if (w->cb != a->cb) strcat(out, " cb");
    if (w->dwX != a->dwX) strcat(out, " dwX");
    if (w->dwY != a->dwY) strcat(out, " dwY");
    if (w->dwXSize != a->dwXSize) strcat(out, " dwXSize");
    if (w->dwYSize != a->dwYSize) strcat(out, " dwYSize");
    if (w->dwXCountChars != a->dwXCountChars) strcat(out, " dwXCountChars");
    if (w->dwYCountChars != a->dwYCountChars) strcat(out, " dwYCountChars");
    if (w->dwFillAttribute != a->dwFillAttribute) strcat(out, " dwFillAttribute");
    if (w->dwFlags != a->dwFlags) strcat(out, " dwFlags");
    if (w->wShowWindow != a->wShowWindow) strcat(out, " wShowWindow");
    if (w->cbReserved2 != a->cbReserved2) strcat(out, " cbReserved2");
    if (w->lpReserved2 != a->lpReserved2) strcat(out, " lpReserved2");
    if (w->hStdInput != a->hStdInput) strcat(out, " hStdInput");
    if (w->hStdOutput != a->hStdOutput) strcat(out, " hStdOutput");
    if (w->hStdError != a->hStdError) strcat(out, " hStdError");
    if (out[0] == '\0') strcpy(out, " none");
}

static int same_text(const char *a, const WCHAR *w)
{
    int i;

    if (a == NULL || w == NULL) {
        return a == NULL && w == NULL;
    }
    for (i = 0; a[i] != 0 && (WCHAR)(unsigned char)a[i] == w[i]; i++) {
    }
    return a[i] == 0 && w[i] == 0;
}

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

static int is_absolute(const char *path)
{
    return (path[0] != 0 && path[1] == ':' && path[2] == '\\') ||
           (path[0] == '\\' && path[1] == '\\');
}

/* One row of hex words: "<label> <first>: xxxx xxxx ...". */
static void row_w(const char *label, int first, const WCHAR *w, int n)
{
    char buf[256];
    int i;
    int len = sprintf(buf, "%s %02X:", label, first);

    for (i = 0; i < n; i++) {
        len += sprintf(buf + len, " %04X", (unsigned)w[i]);
    }
    line("%s", buf);
}

static void row_b(const char *label, int first, const BYTE *b, int n)
{
    char buf[256];
    int i;
    int len = sprintf(buf, "%s %02X:", label, first);

    for (i = 0; i < n; i++) {
        len += sprintf(buf + len, " %02X", (unsigned)b[i]);
    }
    line("%s", buf);
}

/* --- args ---------------------------------------------------------- */

static void sec_args(void)
{
    char path[MAX_PATH];
    char small[8];
    char base[MAX_PATH];
    char narrow[MAX_PATH];
    WCHAR wpath[MAX_PATH];
    WCHAR wsmall[8];
    STARTUPINFOA sa;
    STARTUPINFOW sw;
    const char *p1;
    DWORD n;
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
    line("__argc matches: %s", yesno(__argc == g_argc));
    line("command line tail: [%s]", skip_program(GetCommandLineA()));
    line("command line tail (W): [%s]", ws(skip_program_w(GetCommandLineW())));

    arm();
    n = GetModuleFileNameA(NULL, path, sizeof path);
    line("GetModuleFileNameA: name %s, length matches: %s, absolute: %s, err=%s",
         basename_upper(path, base, sizeof base), yesno(n == strlen(path)), yesno(is_absolute(path)), le());
    wpath[0] = 0;
    arm();
    n = GetModuleFileNameW(NULL, wpath, sizeof wpath / sizeof wpath[0]);
    p1 = le();
    narrow_w(wpath, narrow, sizeof narrow);
    line("GetModuleFileNameW: name %s, length matches: %s, absolute: %s, err=%s",
         basename_upper(narrow, base, sizeof base), yesno(n == wcslen(wpath)), yesno(is_absolute(narrow)), p1);
    line("_pgmptr matches: %s", yesno(_pgmptr != NULL && strcmp(_pgmptr, path) == 0));

    memset(small, 'x', sizeof small);
    arm();
    n = GetModuleFileNameA(NULL, small, 4);
    line("GetModuleFileNameA into 4 bytes: ret=%lu terminated at 3: %s err=%s",
         n, yesno(small[3] == 0), le());
    for (i = 0; i < 8; i++) {
        wsmall[i] = L'x';
    }
    arm();
    n = GetModuleFileNameW(NULL, wsmall, 4);
    line("GetModuleFileNameW into 4 characters: ret=%lu terminated at 3: %s err=%s",
         n, yesno(wsmall[3] == 0), le());

    memset(&sa, 0xCC, sizeof sa);
    memset(&sw, 0xCC, sizeof sw);
    GetStartupInfoA(&sa);
    GetStartupInfoW(&sw);
    line("GetStartupInfoW: cb %lu, fields as GetStartupInfoA's: %s, title and desktop as GetStartupInfoA's: %s",
         sw.cb,
         yesno(sw.cb == sa.cb && sw.dwX == sa.dwX && sw.dwY == sa.dwY && sw.dwXSize == sa.dwXSize &&
               sw.dwYSize == sa.dwYSize && sw.dwXCountChars == sa.dwXCountChars &&
               sw.dwYCountChars == sa.dwYCountChars && sw.dwFillAttribute == sa.dwFillAttribute &&
               sw.dwFlags == sa.dwFlags && sw.wShowWindow == sa.wShowWindow && sw.cbReserved2 == sa.cbReserved2 &&
               sw.lpReserved2 == sa.lpReserved2 && sw.hStdInput == sa.hStdInput &&
               sw.hStdOutput == sa.hStdOutput && sw.hStdError == sa.hStdError),
         yesno(same_text(sa.lpTitle, sw.lpTitle) && same_text(sa.lpDesktop, sw.lpDesktop)));
    startup_differences(&sa, &sw, narrow);
    line("GetStartupInfoW: the fields that differ:%s", narrow);
}

/* --- version ------------------------------------------------------- */

static void sec_version(void)
{
    OSVERSIONINFOA vi;
    OSVERSIONINFOW wi;
    f2k_osviexa xa;
    f2k_osviexw xw;
    const char *p1;
    DWORD v;
    BOOL r;

    v = GetVersion();
    line("GetVersion: 0x%08lX (major %lu, minor %lu, build %lu, nt %s)",
         v, v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0x7FFF, yesno((v & 0x80000000u) == 0));

    vi.dwOSVersionInfoSize = sizeof vi;
    arm();
    r = GetVersionExA(&vi);
    line("GetVersionExA: ret=%d %lu.%lu build %lu platform %lu csd [%s] err=%s",
         r, vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, vi.dwPlatformId,
         vi.szCSDVersion, le());
    memset(&wi, 0, sizeof wi);
    wi.dwOSVersionInfoSize = sizeof wi;
    arm();
    r = GetVersionExW(&wi);
    p1 = le();
    line("GetVersionExW: ret=%d %lu.%lu build %lu platform %lu csd [%s] err=%s",
         r, wi.dwMajorVersion, wi.dwMinorVersion, wi.dwBuildNumber, wi.dwPlatformId,
         ws(wi.szCSDVersion), p1);

    vi.dwOSVersionInfoSize = 10;
    arm();
    r = GetVersionExA(&vi);
    line("GetVersionExA with a bad size: ret=%d err=%s", r, le());
    wi.dwOSVersionInfoSize = 10;
    arm();
    r = GetVersionExW(&wi);
    line("GetVersionExW with a bad size: ret=%d err=%s", r, le());

    memset(&xa, 0, sizeof xa);
    xa.base.dwOSVersionInfoSize = sizeof xa;
    arm();
    r = GetVersionExA(&xa.base);
    line("GetVersionExA, the EX size: ret=%d %lu.%lu build %lu platform %lu csd [%s] service pack %u.%u err=%s",
         r, xa.base.dwMajorVersion, xa.base.dwMinorVersion, xa.base.dwBuildNumber, xa.base.dwPlatformId,
         xa.base.szCSDVersion, (unsigned)xa.wServicePackMajor, (unsigned)xa.wServicePackMinor, le());
    memset(&xw, 0, sizeof xw);
    xw.base.dwOSVersionInfoSize = sizeof xw;
    arm();
    r = GetVersionExW(&xw.base);
    p1 = le();
    line("GetVersionExW, the EX size: ret=%d %lu.%lu build %lu platform %lu csd [%s] service pack %u.%u err=%s",
         r, xw.base.dwMajorVersion, xw.base.dwMinorVersion, xw.base.dwBuildNumber, xw.base.dwPlatformId,
         ws(xw.base.szCSDVersion), (unsigned)xw.wServicePackMajor, (unsigned)xw.wServicePackMinor, p1);

    line("CRT: _osver 0x%X _winmajor %u _winminor %u _winver 0x%X",
         _osver, _winmajor, _winminor, _winver);
}

/* --- module -------------------------------------------------------- */

/* A path of `length` characters naming kernel32.dll in a directory that does not exist. */
static const char *kernel32_path(int length)
{
    static char name[400];

    memset(name, 'd', length - 13);
    strcpy(name + length - 13, "\\kernel32.dll");
    return name;
}

/* The same, wide. */
static const WCHAR *kernel32_path_w(int length)
{
    static WCHAR name[400];
    int i;

    for (i = 0; i < length - 13; i++) {
        name[i] = L'd';
    }
    wcscpy(name + length - 13, L"\\kernel32.dll");
    return name;
}

/* Module and export names around MAX_PATH. */
static void module_lengths(HMODULE k32)
{
    static char export_name[301];
    HMODULE h;
    FARPROC fp;

    arm();
    h = GetModuleHandleA(kernel32_path(260));
    line("GetModuleHandleA, a 260-character path: ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = GetModuleHandleW(kernel32_path_w(260));
    line("GetModuleHandleW, a 260-character path: ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = GetModuleHandleA(kernel32_path(261));
    line("GetModuleHandleA, a 261-character path: ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = GetModuleHandleW(kernel32_path_w(261));
    line("GetModuleHandleW, a 261-character path: ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = LoadLibraryA(kernel32_path(261));
    line("LoadLibraryA, a 261-character path: ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = LoadLibraryW(kernel32_path_w(261));
    line("LoadLibraryW, a 261-character path: ret null %s err=%s", yesno(h == NULL), le());
    if (h != NULL) {
        FreeLibrary(h);
    }
    memset(export_name, 'x', 300);
    memcpy(export_name, "GetTickCount", 12);
    arm();
    fp = GetProcAddress(k32, export_name);
    line("GetProcAddress, a 300-character name: ret null %s err=%s", yesno(fp == NULL), le());
}

static void sec_module(void)
{
    HMODULE self;
    HMODULE k32;
    HMODULE h;
    FARPROC fp;
    char path[MAX_PATH];
    char base[MAX_PATH];
    char narrow[MAX_PATH];
    WCHAR wpath[MAX_PATH];
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    const char *p1;
    DWORD t0, t1;
    BOOL r;

    self = GetModuleHandleA(NULL);
    line("GetModuleHandleA(NULL): 0x%08lX", (DWORD)self);
    line("GetModuleHandleW(NULL): 0x%08lX", (DWORD)GetModuleHandleW(NULL));

    dos = (IMAGE_DOS_HEADER *)self;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)self + dos->e_lfanew);
    line("own headers: MZ %s, PE %s, ImageBase matches %s, entry point inside image %s",
         yesno(dos->e_magic == IMAGE_DOS_SIGNATURE), yesno(nt->Signature == IMAGE_NT_SIGNATURE),
         yesno(nt->OptionalHeader.ImageBase == (DWORD)self),
         yesno(nt->OptionalHeader.AddressOfEntryPoint < nt->OptionalHeader.SizeOfImage));

    k32 = GetModuleHandleA("kernel32.dll");
    line("GetModuleHandleA(kernel32.dll): found %s", yesno(k32 != NULL));
    h = GetModuleHandleW(L"kernel32.dll");
    line("GetModuleHandleW(kernel32.dll): found %s", yesno(h != NULL));
    line("GetModuleHandleA(KERNEL32) same module: %s", yesno(GetModuleHandleA("KERNEL32") == k32));
    line("GetModuleHandleW(KERNEL32) same module: %s", yesno(GetModuleHandleW(L"KERNEL32") == k32));
    arm();
    h = GetModuleHandleA("nosuch.dll");
    line("GetModuleHandleA(nosuch.dll): ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = GetModuleHandleW(L"nosuch.dll");
    line("GetModuleHandleW(nosuch.dll): ret null %s err=%s", yesno(h == NULL), le());

    arm();
    path[0] = 0;
    GetModuleFileNameA(k32, path, sizeof path);
    line("GetModuleFileNameA(kernel32): %s err=%s", basename_upper(path, base, sizeof base), le());
    arm();
    wpath[0] = 0;
    GetModuleFileNameW(k32, wpath, sizeof wpath / sizeof wpath[0]);
    p1 = le();
    line("GetModuleFileNameW(kernel32): %s err=%s", basename_upper(narrow_w(wpath, narrow, sizeof narrow), base,
         sizeof base), p1);

    if (k32 != NULL) {
        dos = (IMAGE_DOS_HEADER *)k32;
        line("kernel32 headers: MZ %s", yesno(dos->e_magic == IMAGE_DOS_SIGNATURE));
    }

    arm();
    fp = GetProcAddress(k32, "GetTickCount");
    line("GetProcAddress(GetTickCount): found %s err=%s", yesno(fp != NULL), le());
    if (fp != NULL) {
        t0 = GetTickCount();
        t1 = ((DWORD (WINAPI *)(void))fp)();
        line("GetTickCount through the pointer agrees: %s", yesno(t1 - t0 < 1000));
    }
    arm();
    fp = GetProcAddress(k32, "NoSuchExport");
    line("GetProcAddress(NoSuchExport): ret null %s err=%s", yesno(fp == NULL), le());
    arm();
    fp = GetProcAddress(k32, "gettickcount");
    line("GetProcAddress is case-sensitive: %s err=%s", yesno(fp == NULL), le());

    arm();
    h = LoadLibraryA("kernel32.dll");
    line("LoadLibraryA(kernel32.dll): same module %s err=%s", yesno(h == k32), le());
    arm();
    r = FreeLibrary(h);
    line("FreeLibrary: ret=%d err=%s", r, le());
    arm();
    h = LoadLibraryW(L"kernel32.dll");
    line("LoadLibraryW(kernel32.dll): same module %s err=%s", yesno(h == k32), le());
    arm();
    r = FreeLibrary(h);
    line("FreeLibrary (W): ret=%d err=%s", r, le());
    arm();
    h = LoadLibraryA("nosuch.dll");
    line("LoadLibraryA(nosuch.dll): ret null %s err=%s", yesno(h == NULL), le());
    arm();
    h = LoadLibraryW(L"nosuch.dll");
    line("LoadLibraryW(nosuch.dll): ret null %s err=%s", yesno(h == NULL), le());

    module_lengths(k32);
}

/* --- teb ----------------------------------------------------------- */

static void sec_teb(void)
{
    DWORD teb, peb, base, limit, chain;
    DWORD local = 0;

    teb = fs_dword(0x18);
    line("fs:[18h] self pointer: %s", yesno(teb != 0 && *(DWORD *)(teb + 0x18) == teb));
    line("fs:[20h] process id matches: %s", yesno(fs_dword(0x20) == GetCurrentProcessId()));
    line("fs:[24h] thread id matches: %s", yesno(fs_dword(0x24) == GetCurrentThreadId()));

    base = fs_dword(0x04);
    limit = fs_dword(0x08);
    line("stack base above limit, a local between: %s",
         yesno(base > limit && (DWORD)&local < base && (DWORD)&local >= limit));

    SetLastError(1234);
    line("fs:[34h] last error slot: %lu", fs_dword(0x34));
    SetLastError(0);

    chain = fs_dword(0x00);
    line("fs:[0] SEH chain has a frame: %s", yesno(chain != 0 && chain != 0xFFFFFFFFu));

    peb = fs_dword(0x30);
    line("fs:[30h] PEB present: %s", yesno(peb != 0));
    if (peb != 0) {
        line("PEB BeingDebugged: %u", (unsigned)*(BYTE *)(peb + 0x02));
        line("PEB ImageBaseAddress matches: %s",
             yesno(*(DWORD *)(peb + 0x08) == (DWORD)GetModuleHandleA(NULL)));
        line("PEB ImageBaseAddress matches (W): %s",
             yesno(*(DWORD *)(peb + 0x08) == (DWORD)GetModuleHandleW(NULL)));
        line("PEB ProcessHeap matches: %s", yesno(*(DWORD *)(peb + 0x18) == (DWORD)GetProcessHeap()));
        line("PEB OS version: %lu.%lu build %u CSD 0x%04X platform %lu", *(DWORD *)(peb + 0xA4),
             *(DWORD *)(peb + 0xA8), (unsigned)*(WORD *)(peb + 0xAC), (unsigned)*(WORD *)(peb + 0xAE),
             *(DWORD *)(peb + 0xB0));
        line("PEB image subsystem: %lu version %lu.%lu", *(DWORD *)(peb + 0xB4), *(DWORD *)(peb + 0xB8),
             *(DWORD *)(peb + 0xBC));
    }
}

/* --- lasterror ----------------------------------------------------- */

/* A system message into the caller's buffer, through FormatMessageA or (wide) FormatMessageW. */
static void message(DWORD code, int wide)
{
    const char *aw = wide ? "W" : "A";
    char buf[256];
    WCHAR wbuf[256];
    DWORD n;
    char *p;
    WCHAR *q;

    arm();
    if (wide) {
        n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), wbuf, sizeof wbuf / sizeof wbuf[0], NULL);
    } else {
        n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof buf, NULL);
    }
    if (n == 0) {
        line("FormatMessage%s(%lu): ret=0 err=%s", aw, code, le());
        return;
    }
    if (wide) {
        for (q = wbuf; *q != 0; q++) {
            if (*q == L'\r' || *q == L'\n') {
                *q = 0;
                break;
            }
        }
        line("FormatMessageW(%lu): ret=%lu [%s]", code, n, ws(wbuf));
        return;
    }
    for (p = buf; *p != 0; p++) {
        if (*p == '\r' || *p == '\n') {
            *p = 0;
            break;
        }
    }
    line("FormatMessageA(%lu): ret=%lu [%s]", code, n, buf);
}

/* A formatted message with its line breaks shown: CR as \r, LF as \n. */
static const char *shown(const char *text)
{
    static char out[512];
    char *o = out;

    for (; *text != 0 && o < out + sizeof out - 3; text++) {
        if (*text == '\r' || *text == '\n') {
            *o++ = '\\';
            *o++ = *text == '\r' ? 'r' : 'n';
        } else {
            *o++ = *text;
        }
    }
    *o = 0;
    return out;
}

/* The same, of a wide message (printed as ws() prints). */
static const char *shown_w(const WCHAR *text)
{
    static WCHAR out[512];
    WCHAR *o = out;

    for (; *text != 0 && o < out + sizeof out / sizeof out[0] - 3; text++) {
        if (*text == L'\r' || *text == L'\n') {
            *o++ = L'\\';
            *o++ = *text == L'\r' ? L'r' : L'n';
        } else {
            *o++ = *text;
        }
    }
    *o = 0;
    return ws(out);
}

/* FORMAT_MESSAGE_ALLOCATE_BUFFER: the block and its least size (nSize). */
static void message_allocated(DWORD code, DWORD least)
{
    char *block = (char *)0x1234;
    DWORD n;

    arm();
    n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&block, least, NULL);
    if (n == 0) {
        line("FormatMessageA(%lu) allocated, at least %lu: ret=0 block null %s err=%s", code, least,
             yesno(block == NULL), le());
        return;
    }
    line("FormatMessageA(%lu) allocated, at least %lu: ret=%lu [%s] LocalSize at least %s err=%s", code, least, n,
         shown(block), yesno(LocalSize(block) >= (least > n + 1 ? least : n + 1)), le());
    line("LocalFree of the block: %s", yesno(LocalFree(block) == NULL));
}

/* The same through FormatMessageW: nSize and the count are characters. */
static void message_allocated_w(DWORD code, DWORD least)
{
    WCHAR *block = (WCHAR *)0x1234;
    const char *p1;
    DWORD n;

    arm();
    n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&block, least, NULL);
    p1 = le();
    if (n == 0) {
        line("FormatMessageW(%lu) allocated, at least %lu: ret=0 block null %s err=%s", code, least,
             yesno(block == NULL), p1);
        return;
    }
    line("FormatMessageW(%lu) allocated, at least %lu: ret=%lu [%s] LocalSize at least %s err=%s", code, least, n,
         shown_w(block), yesno(LocalSize(block) >= (least > n + 1 ? least : n + 1) * sizeof(WCHAR)), p1);
    line("LocalFree of the block (W): %s", yesno(LocalFree(block) == NULL));
}

/* The width byte: FORMAT_MESSAGE_MAX_WIDTH_MASK or a line width. */
static void message_width(DWORD code, DWORD width)
{
    char buf[256];
    DWORD n;

    arm();
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | width, NULL, code,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof buf, NULL);
    line("FormatMessageA(%lu) width %lu: ret=%lu [%s] err=%s", code, width, n, n != 0 ? shown(buf) : "", le());
}

/* The same through FormatMessageW. */
static void message_width_w(DWORD code, DWORD width)
{
    WCHAR buf[256];
    const char *p1;
    DWORD n;

    arm();
    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | width, NULL, code,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof buf / sizeof buf[0], NULL);
    p1 = le();
    line("FormatMessageW(%lu) width %lu: ret=%lu [%s] err=%s", code, width, n, n != 0 ? shown_w(buf) : "", p1);
}

static void sec_lasterror(void)
{
    HANDLE h;
    BOOL r;

    SetLastError(1234);
    line("set then get: %lu", GetLastError());
    GetTickCount();
    line("kept across a successful GetTickCount: %lu", GetLastError());
    SetLastError(0);
    line("cleared: %lu", GetLastError());

    arm();
    r = CloseHandle((HANDLE)0x1234);
    line("CloseHandle(bogus): ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(NULL);
    line("CloseHandle(NULL): ret=%d err=%s", r, le());
    arm();
    h = GetStdHandle(42);
    line("GetStdHandle(42): ret INVALID_HANDLE_VALUE %s err=%s", yesno(h == INVALID_HANDLE_VALUE), le());

    message(2, 0);
    message(2, 1);
    message(5, 0);
    message(5, 1);
    message(0x01234567, 0);
    message(0x01234567, 1);
    message_allocated(5, 0);
    message_allocated_w(5, 0);
    message_allocated(5, 200);
    message_allocated_w(5, 200);
    message_allocated(0x01234567, 0);
    message_allocated_w(0x01234567, 0);
    message_width(2, FORMAT_MESSAGE_MAX_WIDTH_MASK);
    message_width_w(2, FORMAT_MESSAGE_MAX_WIDTH_MASK);
    message_width(2, 20);
    message_width_w(2, 20);
    message_width(5, 5);
    message_width_w(5, 5);
}

/* --- env ----------------------------------------------------------- */

static int block_has(const char *block, const char *entry)
{
    const char *p;

    for (p = block; *p != 0; p += strlen(p) + 1) {
        if (strcmp(p, entry) == 0) {
            return 1;
        }
    }
    return 0;
}

static int block_has_w(const WCHAR *block, const WCHAR *entry)
{
    const WCHAR *p;

    for (p = block; *p != 0; p += wcslen(p) + 1) {
        if (wcscmp(p, entry) == 0) {
            return 1;
        }
    }
    return 0;
}

/* The index of the entry starting with `prefix` (exact case) in a wide block, or -1. */
static int block_index_w(const WCHAR *block, const WCHAR *prefix)
{
    const WCHAR *p;
    int i;

    for (p = block, i = 0; *p != 0; p += wcslen(p) + 1, i++) {
        if (wcsncmp(p, prefix, wcslen(prefix)) == 0) {
            return i;
        }
    }
    return -1;
}

/* An entry's name length: up to its first '=' past the first character. */
static int name_length_w(const WCHAR *entry)
{
    const WCHAR *eq = wcschr(entry + 1, L'=');

    return eq != NULL ? (int)(eq - entry) : (int)wcslen(entry);
}

/* Whether a wide block's entries are in order by their upper-cased names. */
static int block_sorted_w(const WCHAR *block)
{
    const WCHAR *p, *q;
    int i, n, m;

    for (p = block; *p != 0 && p[wcslen(p) + 1] != 0; p = q) {
        q = p + wcslen(p) + 1;
        n = name_length_w(p);
        m = name_length_w(q);
        for (i = 0; i < n && i < m && towupper(p[i]) == towupper(q[i]); i++) {
        }
        if (i < n && (i == m || towupper(p[i]) > towupper(q[i]))) {
            return 0;
        }
    }
    return 1;
}

/* The narrow forms' string lengths: values and names around the counted string's 32767
   characters, a name past MAX_PATH. */
static char big[32769];
static WCHAR wbig[301];

static void env_lengths(void)
{
    DWORD n;
    BOOL r;
    int i;

    memset(big, 'v', 32767);
    big[32767] = 0;
    arm();
    r = SetEnvironmentVariableA("F2KLONG", big);
    line("SetEnvironmentVariableA, a 32767-character value: ret=%d err=%s", r, le());
    big[32766] = 0;
    arm();
    r = SetEnvironmentVariableA("F2KLONG", big);
    line("SetEnvironmentVariableA, a 32766-character value: ret=%d err=%s", r, le());
    arm();
    n = GetEnvironmentVariableA("F2KLONG", NULL, 0);
    line("its size query: ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableW(L"F2KLONG", NULL, 0);
    line("its size query (W): ret=%lu err=%s", n, le());
    SetEnvironmentVariableA("F2KLONG", NULL);

    big[300] = 0;
    for (i = 0; i < 300; i++) {
        wbig[i] = L'v';
    }
    wbig[300] = 0;
    arm();
    r = SetEnvironmentVariableA(big, "long name");
    line("SetEnvironmentVariableA, a 300-character name: ret=%d err=%s", r, le());
    arm();
    n = GetEnvironmentVariableA(big, NULL, 0);
    line("its size query: ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableW(wbig, NULL, 0);
    line("its size query (W): ret=%lu err=%s", n, le());
    SetEnvironmentVariableA(big, NULL);
}

static void sec_env(void)
{
    char buf[128];
    WCHAR wbuf[128];
    char *block;
    WCHAR *wblock;
    const char *g;
    const char *p1;
    DWORD n;
    BOOL r;

    wbuf[0] = 0;
    arm();
    r = SetEnvironmentVariableA("F2KTEST", "first");
    line("SetEnvironmentVariableA: ret=%d err=%s", r, le());
    arm();
    n = GetEnvironmentVariableA("F2KTEST", NULL, 0);
    line("size query: ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableW(L"F2KTEST", NULL, 0);
    line("size query (W): ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableA("F2KTEST", buf, sizeof buf);
    line("get: ret=%lu [%s] err=%s", n, buf, le());
    arm();
    n = GetEnvironmentVariableW(L"F2KTEST", wbuf, sizeof wbuf / sizeof wbuf[0]);
    p1 = le();
    line("get (W): ret=%lu [%s] err=%s", n, ws(wbuf), p1);
    arm();
    n = GetEnvironmentVariableA("F2KTEST", buf, 3);
    line("get into 3 bytes: ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableW(L"F2KTEST", wbuf, 3);
    line("get into 3 characters (W): ret=%lu err=%s", n, le());

    SetEnvironmentVariableA("F2KTEST", "second value");
    arm();
    n = GetEnvironmentVariableA("f2ktest", buf, sizeof buf);
    line("get by lower-case name: ret=%lu [%s] err=%s", n, buf, le());
    arm();
    n = GetEnvironmentVariableW(L"f2ktest", wbuf, sizeof wbuf / sizeof wbuf[0]);
    p1 = le();
    line("get by lower-case name (W): ret=%lu [%s] err=%s", n, ws(wbuf), p1);

    block = GetEnvironmentStrings();
    line("GetEnvironmentStrings: has the entry %s", yesno(block != NULL && block_has(block, "F2KTEST=second value")));
    if (block != NULL) {
        arm();
        r = FreeEnvironmentStringsA(block);
        line("FreeEnvironmentStringsA: ret=%d err=%s", r, le());
    }
    block = GetEnvironmentStringsA();
    line("GetEnvironmentStringsA: has the entry %s",
         yesno(block != NULL && block_has(block, "F2KTEST=second value")));
    if (block != NULL) {
        arm();
        r = FreeEnvironmentStringsA(block);
        line("FreeEnvironmentStringsA (GetEnvironmentStringsA's block): ret=%d err=%s", r, le());
    }
    wblock = GetEnvironmentStringsW();
    line("GetEnvironmentStringsW: has the entry %s",
         yesno(wblock != NULL && block_has_w(wblock, L"F2KTEST=second value")));
    if (wblock != NULL) {
        FreeEnvironmentStringsW(wblock);
    }

    arm();
    r = SetEnvironmentVariableA("F2KTEST", NULL);
    line("delete: ret=%d err=%s", r, le());
    arm();
    n = GetEnvironmentVariableA("F2KTEST", buf, sizeof buf);
    line("get after delete: ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableW(L"F2KTEST", wbuf, sizeof wbuf / sizeof wbuf[0]);
    line("get after delete (W): ret=%lu err=%s", n, le());

    g = getenv("F2KTEST");
    line("CRT getenv sees the OS-level variable: %s", yesno(g != NULL));
    line("CRT _putenv: %d", _putenv("F2KCRT=crt value"));
    g = getenv("F2KCRT");
    line("CRT getenv after _putenv: [%s]", g != NULL ? g : "(null)");
    n = GetEnvironmentVariableA("F2KCRT", buf, sizeof buf);
    line("OS sees the _putenv variable: ret=%lu [%s]", n, n != 0 ? buf : "");
    n = GetEnvironmentVariableW(L"F2KCRT", wbuf, sizeof wbuf / sizeof wbuf[0]);
    line("OS sees the _putenv variable (W): ret=%lu [%s]", n, n != 0 ? ws(wbuf) : "");

    arm();
    n = ExpandEnvironmentStringsA("[%F2KCRT%] [%F2KNOSUCH%]", buf, sizeof buf);
    line("ExpandEnvironmentStringsA: ret=%lu [%s] err=%s", n, buf, le());
    arm();
    n = ExpandEnvironmentStringsW(L"[%F2KCRT%] [%F2KNOSUCH%]", wbuf, sizeof wbuf / sizeof wbuf[0]);
    p1 = le();
    line("ExpandEnvironmentStringsW: ret=%lu [%s] err=%s", n, ws(wbuf), p1);
    arm();
    n = ExpandEnvironmentStringsA("[%F2KNOSUCH%F2KCRT%] [%%] [100%]", buf, sizeof buf);
    line("ExpandEnvironmentStringsA, an unset reference before a set one: ret=%lu [%s] err=%s", n, buf, le());
    arm();
    n = ExpandEnvironmentStringsW(L"[%F2KNOSUCH%F2KCRT%] [%%] [100%]", wbuf, sizeof wbuf / sizeof wbuf[0]);
    p1 = le();
    line("ExpandEnvironmentStringsW, an unset reference before a set one: ret=%lu [%s] err=%s", n, ws(wbuf), p1);

    SetEnvironmentVariableA("F2KORDERB", "b");
    SetEnvironmentVariableA("F2KORDERA", "a");
    SetEnvironmentVariableA("f2korderb", "b2");
    wblock = GetEnvironmentStringsW();
    if (wblock != NULL) {
        line("block order: F2KORDERA before the replaced B %s, B spelled as the last set %s, the block sorted %s",
             yesno(block_index_w(wblock, L"F2KORDERA=a") >= 0 &&
                   block_index_w(wblock, L"F2KORDERA=a") < block_index_w(wblock, L"f2korderb=b2")),
             yesno(block_index_w(wblock, L"f2korderb=b2") >= 0), yesno(block_sorted_w(wblock)));
        FreeEnvironmentStringsW(wblock);
    }
    SetEnvironmentVariableA("F2KORDERA", NULL);
    SetEnvironmentVariableA("F2KORDERB", NULL);

    env_lengths();
}

/* --- locale -------------------------------------------------------- */

static void cpinfo(UINT cp, const char *name)
{
    CPINFO ci;
    BOOL r;

    memset(&ci, 0, sizeof ci);
    arm();
    r = GetCPInfo(cp, &ci);
    line("GetCPInfo(%s): ret=%d max %u default %02X %02X lead %02X %02X err=%s", name, r,
         ci.MaxCharSize, ci.DefaultChar[0], ci.DefaultChar[1], ci.LeadByte[0], ci.LeadByte[1], le());
}

static void mb_table(UINT cp, const char *label)
{
    BYTE in[128];
    WCHAR w[128];
    int i, n;

    for (i = 0; i < 128; i++) {
        in[i] = (BYTE)(0x80 + i);
    }
    arm();
    n = MultiByteToWideChar(cp, 0, (const char *)in, 128, w, 128);
    line("%s: ret=%d err=%s", label, n, le());
    if (n == 128) {
        for (i = 0; i < 128; i += 16) {
            row_w(label, 0x80 + i, &w[i], 16);
        }
    }
}

/* EnumSystemLocales: whether US English (00000409) is among the locales
   enumerated; never a count, which is the machine's. */
static int saw_0409;

static BOOL CALLBACK locale_seen_a(LPSTR name)
{
    if (strcmp(name, "00000409") == 0) {
        saw_0409 = 1;
    }
    return TRUE;
}

static BOOL CALLBACK locale_seen_w(LPWSTR name)
{
    if (wcscmp(name, L"00000409") == 0) {
        saw_0409 = 1;
    }
    return TRUE;
}

static void sec_locale(void)
{
    BYTE in[256];
    BYTE out[256];
    WCHAR w[256];
    WORD types[256];
    char buf[128];
    char *loc;
    const char *p1;
    BOOL used;
    DWORD number;
    int i, n;
    BOOL r;

    line("GetACP: %u", GetACP());
    line("GetOEMCP: %u", GetOEMCP());
    line("IsValidCodePage: 1252 %d, 437 %d, 12345 %d",
         IsValidCodePage(1252), IsValidCodePage(437), IsValidCodePage(12345));
    cpinfo(CP_ACP, "CP_ACP");
    cpinfo(CP_OEMCP, "CP_OEMCP");
    cpinfo(1252, "1252");
    cpinfo(437, "437");
    cpinfo(850, "850");
    cpinfo(CP_UTF8, "CP_UTF8");
    cpinfo(12345, "12345");

    mb_table(1252, "1252->W");
    mb_table(437, "437->W");

    arm();
    n = MultiByteToWideChar(1252, 0, "abc", -1, NULL, 0);
    line("MultiByteToWideChar size query (-1): ret=%d err=%s", n, le());
    arm();
    n = MultiByteToWideChar(1252, 0, "abc", -1, w, 2);
    line("MultiByteToWideChar into 2: ret=%d err=%s", n, le());
    arm();
    n = MultiByteToWideChar(1252, 0x80, "abc", -1, w, 8);
    line("MultiByteToWideChar bad flags: ret=%d err=%s", n, le());
    arm();
    n = MultiByteToWideChar(12345, 0, "abc", -1, w, 8);
    line("MultiByteToWideChar bad code page: ret=%d err=%s", n, le());
    arm();
    n = MultiByteToWideChar(CP_UTF8, 0, "\xC3\xA9\xE2\x82\xAC", -1, w, 8);
    line("UTF-8 decode: ret=%d %04X %04X %04X err=%s", n, w[0], w[1], w[2], le());
    arm();
    n = MultiByteToWideChar(CP_UTF8, 0, "a\xC3(b", -1, w, 8);
    line("UTF-8 decode of a broken sequence: ret=%d %04X %04X %04X %04X err=%s",
         n, w[0], w[1], w[2], w[3], le());

    w[0] = 0x20AC;
    w[1] = 0x0100;
    w[2] = 0x4E2D;
    w[3] = 'A';
    w[4] = 0;
    used = 7;
    arm();
    n = WideCharToMultiByte(1252, 0, w, -1, (char *)out, sizeof out, NULL, &used);
    line("W->1252 with lpUsedDefaultChar: ret=%d %02X %02X %02X %02X used=%d err=%s",
         n, out[0], out[1], out[2], out[3], used, le());
    used = 7;
    arm();
    n = WideCharToMultiByte(1252, 0, w, -1, (char *)out, sizeof out, "#", &used);
    line("W->1252 with default '#': ret=%d %02X %02X %02X %02X used=%d err=%s",
         n, out[0], out[1], out[2], out[3], used, le());
    arm();
    n = WideCharToMultiByte(437, 0, w, -1, (char *)out, sizeof out, NULL, NULL);
    line("W->437: ret=%d %02X %02X %02X %02X err=%s", n, out[0], out[1], out[2], out[3], le());
    arm();
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, (char *)out, sizeof out, NULL, NULL);
    line("W->UTF-8: ret=%d %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X err=%s", n,
         out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8], out[9], le());
    arm();
    n = WideCharToMultiByte(1252, 0, w, -1, NULL, 0, NULL, NULL);
    line("W->1252 size query: ret=%d err=%s", n, le());
    arm();
    n = WideCharToMultiByte(1252, 0, w, -1, (char *)out, 2, NULL, NULL);
    line("W->1252 into 2: ret=%d err=%s", n, le());
    used = 7;
    arm();
    n = WideCharToMultiByte(1252, WC_NO_BEST_FIT_CHARS, w, -1, (char *)out, sizeof out, NULL, &used);
    line("W->1252 with WC_NO_BEST_FIT_CHARS: ret=%d %02X %02X %02X %02X used=%d err=%s",
         n, out[0], out[1], out[2], out[3], used, le());
    arm();
    n = WideCharToMultiByte(1252, 0, w, -1, (char *)out, -1, NULL, NULL);
    line("W->1252 into -1: ret=%d err=%s", n, le());
    arm();
    n = WideCharToMultiByte(CP_UTF8, WC_NO_BEST_FIT_CHARS, w, -1, (char *)out, sizeof out, NULL, NULL);
    line("W->UTF-8 with WC_NO_BEST_FIT_CHARS: ret=%d err=%s", n, le());

    in[0] = 0x01;
    in[1] = 0x0D;
    in[2] = 0x1F;
    in[3] = 0x7F;
    arm();
    n = MultiByteToWideChar(437, MB_USEGLYPHCHARS, (const char *)in, 4, w, 4);
    line("437->W with MB_USEGLYPHCHARS: ret=%d %04X %04X %04X %04X err=%s", n, w[0], w[1], w[2], w[3], le());
    arm();
    n = MultiByteToWideChar(1252, MB_USEGLYPHCHARS, (const char *)in, 4, w, 4);
    line("1252->W with MB_USEGLYPHCHARS: ret=%d %04X %04X %04X %04X err=%s", n, w[0], w[1], w[2], w[3], le());

    for (i = 0; i < 224; i++) {
        in[i] = (BYTE)(0x20 + i);
    }
    arm();
    n = LCMapStringA(LOCALE_SYSTEM_DEFAULT, LCMAP_UPPERCASE, (const char *)in, 224, (char *)out, 224);
    line("LCMapStringA upper: ret=%d err=%s", n, le());
    if (n == 224) {
        for (i = 0; i < 224; i += 16) {
            row_b("upper", 0x20 + i, &out[i], 16);
        }
    }
    arm();
    n = LCMapStringA(LOCALE_SYSTEM_DEFAULT, LCMAP_LOWERCASE, (const char *)in, 224, (char *)out, 224);
    line("LCMapStringA lower: ret=%d err=%s", n, le());
    if (n == 224) {
        for (i = 0; i < 224; i += 16) {
            row_b("lower", 0x20 + i, &out[i], 16);
        }
    }
    for (i = 0; i < 256; i++) {
        w[i] = (WCHAR)i;
    }
    arm();
    n = LCMapStringW(LOCALE_SYSTEM_DEFAULT, LCMAP_UPPERCASE, w, 256, (WCHAR *)types, 256);
    line("LCMapStringW upper over U+0000..U+00FF: ret=%d err=%s", n, le());
    if (n == 256) {
        for (i = 0xC0; i < 0x100; i += 16) {
            row_w("upperW", i, (WCHAR *)&types[i], 16);
        }
    }

    for (i = 0; i < 256; i++) {
        in[i] = (BYTE)i;
    }
    arm();
    r = GetStringTypeA(LOCALE_SYSTEM_DEFAULT, CT_CTYPE1, (const char *)in, 256, types);
    line("GetStringTypeA CT_CTYPE1: ret=%d err=%s", r, le());
    if (r) {
        for (i = 0; i < 256; i += 16) {
            row_w("ctype1", i, (WCHAR *)&types[i], 16);
        }
    }
    arm();
    r = GetStringTypeW(CT_CTYPE1, w, 256, types);
    line("GetStringTypeW CT_CTYPE1 over U+0080..U+00FF: ret=%d err=%s", r, le());
    if (r) {
        for (i = 0x80; i < 0x100; i += 16) {
            row_w("ctype1W", i, (WCHAR *)&types[i], 16);
        }
    }
    types[0] = 0xCCCC;
    arm();
    r = GetStringTypeW(CT_CTYPE1, w, 0, types);
    line("GetStringTypeW, a zero count: ret=%d untouched %s err=%s", r, yesno(types[0] == 0xCCCC), le());
    arm();
    r = GetStringTypeA(LOCALE_SYSTEM_DEFAULT, CT_CTYPE1, (const char *)in, 0, types);
    line("GetStringTypeA, a zero count: ret=%d err=%s", r, le());

    line("CompareStringA apple/Banana: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "apple", -1, "Banana", -1));
    line("CompareStringA abc/ABC ignore case: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, "abc", -1, "ABC", -1));
    line("CompareStringA abc/ABC: %d", CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "abc", -1, "ABC", -1));
    line("CompareStringA co-op/coop: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "co-op", -1, "coop", -1));
    line("CompareStringA co-op/coop string sort: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, SORT_STRINGSORT, "co-op", -1, "coop", -1));
    line("CompareStringA co-op/co'op: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "co-op", -1, "co'op", -1));
    line("CompareStringA co-op/coo-p: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "co-op", -1, "coo-p", -1));
    line("CompareStringA co-op/co-o-p: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "co-op", -1, "co-o-p", -1));

    line("GetUserDefaultLCID: 0x%04lX", GetUserDefaultLCID());
    line("GetSystemDefaultLCID: 0x%04lX", GetSystemDefaultLCID());
    saw_0409 = 0;
    arm();
    r = EnumSystemLocalesA(locale_seen_a, LCID_SUPPORTED);
    p1 = le();
    line("EnumSystemLocalesA(LCID_SUPPORTED): ret=%d err=%s, 00000409 among them: %s", r, p1, yesno(saw_0409));
    saw_0409 = 0;
    arm();
    r = EnumSystemLocalesW(locale_seen_w, LCID_SUPPORTED);
    p1 = le();
    line("EnumSystemLocalesW(LCID_SUPPORTED): ret=%d err=%s, 00000409 among them: %s", r, p1, yesno(saw_0409));
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, buf, sizeof buf);
    line("LOCALE_SENGLANGUAGE: ret=%d [%s]", n, n ? buf : "");
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_IDEFAULTANSICODEPAGE, buf, sizeof buf);
    line("LOCALE_IDEFAULTANSICODEPAGE: ret=%d [%s]", n, n ? buf : "");
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL, buf, sizeof buf);
    line("LOCALE_SDECIMAL: ret=%d [%s]", n, n ? buf : "");
    number = 0xCCCCCCCC;
    arm();
    n = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER, (WCHAR *)&number, 2);
    line("LOCALE_IDEFAULTANSICODEPAGE as a number (W): ret=%d %lu err=%s", n, number, le());
    number = 0xCCCCCCCC;
    arm();
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_ILANGUAGE | LOCALE_RETURN_NUMBER, (char *)&number, 4);
    line("LOCALE_ILANGUAGE as a number (A): ret=%d 0x%lX err=%s", n, number, le());
    arm();
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_ILANGUAGE | LOCALE_RETURN_NUMBER, NULL, 0);
    line("LOCALE_ILANGUAGE as a number, size query (A): ret=%d err=%s", n, le());
    arm();
    n = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER, (WCHAR *)&number, 1);
    line("LOCALE_IDEFAULTANSICODEPAGE as a number into 1 (W): ret=%d err=%s", n, le());
    arm();
    n = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL | LOCALE_RETURN_NUMBER, (WCHAR *)&number, 2);
    line("LOCALE_SDECIMAL as a number (W): ret=%d err=%s", n, le());

    line("C locale: toupper(E9) %02X isalpha(E9) %d", toupper(0xE9), isalpha(0xE9) != 0);
    loc = setlocale(LC_ALL, "");
    line("setlocale(LC_ALL, \"\"): [%s]", loc != NULL ? loc : "(null)");
    line("user locale: toupper(E9) %02X isalpha(E9) %d", toupper(0xE9), isalpha(0xE9) != 0);
    sprintf(buf, "%.2f", 1.5);
    line("user locale: %%.2f of 1.5 [%s]", buf);
    setlocale(LC_ALL, "C");
}

/* --- crt ----------------------------------------------------------- */

static jmp_buf jump;

static void jump_from(int depth)
{
    if (depth == 0) {
        longjmp(jump, 7);
    }
    jump_from(depth - 1);
}

static int cmp_int(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

static void sec_crt(void)
{
    char buf[256];
    char word[32];
    int ints[8] = { 5, -3, 9, 0, 7, -3, 2, 1 };
    int key = 7;
    int *found;
    int i, x, n;
    unsigned u;
    double d;
    volatile int marker;
    __int64 big = 1234567890123i64;
    char *end;
    long l;

    sprintf(buf, "%d|%u|%x|%X|%o|%c|%s|%5d|%-5d|%05d|%+d", -42, 42u, 255, 255, 8, 'z', "str", 42, 42, 42, 42);
    line("sprintf ints: %s", buf);
    sprintf(buf, "%I64d|%I64X|%p", big, big, (void *)0x1234);
    line("sprintf wide: %s", buf);
    sprintf(buf, "%f|%.2f|%e|%E|%g|%G|%10.3f|%-10.3f|", 3.14159265, 2.675, 12345.678, 0.000123, 0.0001, 1e20, -1.5, 1.5);
    line("sprintf floats: %s", buf);
    sprintf(buf, "%.20f|%.17g|%.17g", 0.1, 1.0 / 3.0, sqrt(2.0));
    line("sprintf precision: %s", buf);
    d = 0.0;
    sprintf(buf, "%f|%f|%f", 1.0 / d, -1.0 / d, d / d);
    line("sprintf specials: %s", buf);
    sprintf(buf, "%s|%.3s|%5s|%-5s|", "abcdef", "abcdef", "ab", "ab");
    line("sprintf strings: %s", buf);
    n = _snprintf(buf, 5, "%s", "overflowing");
    line("_snprintf into 5: ret=%d", n);

    n = sscanf("42 0x1F 3.5 word 077", "%d %x %lf %31s %o", &x, &u, &d, word, &i);
    line("sscanf: n=%d %d %u %.2f [%s] %d", n, x, u, d, word, i);

    errno = 0;
    l = strtol("2147483648", &end, 10);
    line("strtol overflow: %ld errno=%d rest [%s]", l, errno, end);
    errno = 0;
    u = strtoul("-1", NULL, 10);
    line("strtoul(-1): %u errno=%d", u, errno);
    line("strtol base 0: %ld %ld %ld", strtol("0x1A", NULL, 0), strtol("  -077", NULL, 0), strtol("12abc", NULL, 0));
    errno = 0;
    d = strtod("1e309", &end);
    line("strtod overflow: %g errno=%d", d, errno);
    line("strtod/atof: %.17g %.17g", strtod("1.7976931348623157e308", NULL), atof("  -2.5e-3xyz"));
    line("atoi: %d %d", atoi("  123abc"), atoi("-0"));

    line("math: floor %.1f ceil %.1f fmod %.2f pow %.17g sin %.17g atan2 %.17g",
         floor(-2.5), ceil(-2.5), fmod(7.5, 2.0), pow(2.0, 0.5), sin(1.0), atan2(1.0, -1.0));
    d = -2.7;
    line("float to int truncates: %d %d", (int)d, (int)-d);
    line("_controlfp default: 0x%08X", _controlfp(0, 0));

    qsort(ints, 8, sizeof ints[0], cmp_int);
    line("qsort: %d %d %d %d %d %d %d %d", ints[0], ints[1], ints[2], ints[3], ints[4], ints[5], ints[6], ints[7]);
    found = (int *)bsearch(&key, ints, 8, sizeof ints[0], cmp_int);
    line("bsearch(7): index %d", found != NULL ? (int)(found - ints) : -1);

    marker = 1;
    n = setjmp(jump);
    if (n == 0) {
        marker = 2;
        jump_from(3);
        line("longjmp: did not jump");
    } else {
        line("longjmp: setjmp returned %d, marker %d", n, marker);
    }

    srand(1);
    x = rand();
    n = rand();
    i = rand();
    line("rand after srand(1): %d %d %d", x, n, i);

    strcpy(buf, "0123456789");
    memmove(buf + 2, buf, 5);
    line("memmove overlap: %s", buf);
    strcpy(buf, "MiXeD case");
    line("_strupr/_strlwr: %s", _strupr(buf));
    line("strstr: %s, strchr: %s, strrchr: %s", strstr("haystack", "st"), strchr("a,b,c", ','), strrchr("a,b,c", ','));
    line("_itoa: %s", _itoa(255, buf, 16));
    line("_stricmp: %d, strncmp: %d", _stricmp("ABC", "abc"), strncmp("abcd", "abce", 3));
}

/* --- seh ----------------------------------------------------------- */

static DWORD seen_code;
static DWORD seen_flags;
static DWORD seen_params;
static DWORD seen_info[2];
static char trail[256];

static void mark(const char *what)
{
    if (trail[0] != 0) {
        strcat(trail, ", ");
    }
    strcat(trail, what);
}

static int capture(EXCEPTION_POINTERS *ep, int result)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;

    seen_code = er->ExceptionCode;
    seen_flags = er->ExceptionFlags;
    seen_params = er->NumberParameters;
    seen_info[0] = er->NumberParameters > 0 ? er->ExceptionInformation[0] : 0;
    seen_info[1] = er->NumberParameters > 1 ? er->ExceptionInformation[1] : 0;
    return result;
}

static void report(const char *what, int handled)
{
    line("%s: handled %s code 0x%08lX flags %lu params %lu info %lX %lX",
         what, yesno(handled), seen_code, seen_flags, seen_params, seen_info[0], seen_info[1]);
}

static volatile int zero_int;

static void raise_inner(void)
{
    __try {
        mark("inner try");
        RaiseException(0xE0000002, 0, 0, NULL);
    } __finally {
        mark(AbnormalTermination() ? "inner finally (abnormal)" : "inner finally");
    }
}

static int filter_mark(const char *what, int result)
{
    mark(what);
    return result;
}

static DWORD overflow_depth;

static void overflow(void)
{
    volatile char pad[1024];

    pad[0] = 1;
    overflow_depth++;
    overflow();
    pad[1023] = pad[0];
}

static void sec_seh(void)
{
    DWORD args[2];
    int handled;
    volatile int x;

    handled = 0;
    __try {
        *(volatile int *)0 = 1;
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("write to NULL", handled);

    handled = 0;
    __try {
        x = *(volatile int *)0x10;
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("read from 0x10", handled);

    handled = 0;
    __try {
        x = 1 / zero_int;
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("integer divide by zero", handled);

    handled = 0;
    __try {
        __asm int 3
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("int 3", handled);

    handled = 0;
    __try {
        __asm _emit 0x0F
        __asm _emit 0x0B
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("ud2", handled);

    handled = 0;
    __try {
        __asm hlt
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("hlt", handled);

    args[0] = 11;
    args[1] = 22;
    handled = 0;
    __try {
        RaiseException(0xE0F2F2F2, 0, 2, args);
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("RaiseException with two arguments", handled);

    handled = 0;
    __try {
        RaiseException(0xE0000001, EXCEPTION_NONCONTINUABLE, 0, NULL);
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("RaiseException noncontinuable", handled);

    handled = 0;
    __try {
        RaiseException(0xE0000003, 0, 0, NULL);
        line("continue execution: RaiseException returned");
    } __except (capture(GetExceptionInformation(), EXCEPTION_CONTINUE_EXECUTION)) {
        handled = 1;
    }
    line("continue execution: handler ran %s", yesno(handled));

    trail[0] = 0;
    __try {
        __try {
            raise_inner();
        } __except (filter_mark("middle filter (continue search)", EXCEPTION_CONTINUE_SEARCH)) {
            mark("middle handler");
        }
    } __except (filter_mark("outer filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("outer handler");
    }
    line("unwind order: %s", trail);

    trail[0] = 0;
    __try {
        mark("try");
        __leave;
    } __finally {
        mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
    }
    line("__leave: %s", trail);

    trail[0] = 0;
    __try {
        mark("try");
    } __finally {
        mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
    }
    line("normal exit: %s", trail);

    /* Last: the overflow consumes the stack's guard page. */
    handled = 0;
    overflow_depth = 0;
    __try {
        overflow();
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    line("stack overflow: handled %s code 0x%08lX deeper than 256 frames %s",
         yesno(handled), seen_code, yesno(overflow_depth > 256));
}

/* --- windir -------------------------------------------------------- */

/* GetWindowsDirectoryA into `size` characters, then GetWindowsDirectoryW
   into as many: the return, the text where it fit, and whether a buffer
   too small was left as it was. */
static void windir_into(const char *label, UINT size)
{
    char buf[MAX_PATH];
    WCHAR wbuf[MAX_PATH];
    const char *p1;
    UINT n;
    int i;

    memset(buf, '#', sizeof buf);
    arm();
    n = GetWindowsDirectoryA(buf, size);
    p1 = le();
    if (n != 0 && n < size) {
        line("GetWindowsDirectoryA into %s: ret=%u [%s] err=%s", label, n, buf, p1);
    } else {
        line("GetWindowsDirectoryA into %s: ret=%u untouched %s err=%s", label, n, yesno(buf[0] == '#'), p1);
    }
    for (i = 0; i < MAX_PATH; i++) {
        wbuf[i] = L'#';
    }
    arm();
    n = GetWindowsDirectoryW(wbuf, size);
    p1 = le();
    if (n != 0 && n < size) {
        line("GetWindowsDirectoryW into %s: ret=%u [%s] err=%s", label, n, ws(wbuf), p1);
    } else {
        line("GetWindowsDirectoryW into %s: ret=%u untouched %s err=%s", label, n, yesno(wbuf[0] == L'#'), p1);
    }
}

static void sec_windir(void)
{
    char buf[MAX_PATH];
    UINT length;

    windir_into("MAX_PATH", MAX_PATH);
    length = GetWindowsDirectoryA(buf, sizeof buf);
    if (length == 0 || length >= sizeof buf) {
        line("GetWindowsDirectoryA: no answer to size the buffers by");
        return;
    }
    windir_into("its length + 1", length + 1);
    windir_into("its length", length);
    windir_into("1", 1);
    windir_into("0", 0);
}

/* --- filetime ------------------------------------------------------ */

static void compare_times(const char *what, DWORD hi1, DWORD lo1, DWORD hi2, DWORD lo2)
{
    FILETIME a, b;
    LONG r;

    a.dwHighDateTime = hi1;
    a.dwLowDateTime = lo1;
    b.dwHighDateTime = hi2;
    b.dwLowDateTime = lo2;
    arm();
    r = CompareFileTime(&a, &b);
    line("CompareFileTime(%08lX:%08lX, %08lX:%08lX) %s: %ld err=%s", hi1, lo1, hi2, lo2, what, r, le());
}

static void sec_filetime(void)
{
    FILETIME a;
    LONG r;

    compare_times("equal", 1, 5, 1, 5);
    compare_times("earlier", 1, 4, 1, 5);
    compare_times("later", 1, 6, 1, 5);
    compare_times("the high dword only, lower", 1, 5, 2, 5);
    compare_times("the high dword only, higher", 2, 5, 1, 5);
    compare_times("the high dword decides over the low", 1, 0xFFFFFFFF, 2, 0);
    compare_times("the low dword's top bit set, first", 1, 0x80000000, 1, 0x7FFFFFFF);
    compare_times("the low dword's top bit set, second", 1, 0x7FFFFFFF, 1, 0x80000000);
    compare_times("the high dword's top bit set, first", 0x80000000, 0, 0x7FFFFFFF, 0);
    compare_times("the high dword's top bit set, second", 0x7FFFFFFF, 0, 0x80000000, 0);
    compare_times("zero and the largest", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF);
    a.dwHighDateTime = 3;
    a.dwLowDateTime = 7;
    arm();
    r = CompareFileTime(&a, &a);
    line("CompareFileTime(one FILETIME twice): %ld err=%s", r, le());
}

/* --- lstrcmp ------------------------------------------------------- */

/* One string pair, the A and W forms of the same text (the A text in code
   page 1252: E9 is e acute, C9 E acute). */
typedef struct {
    const char *label;
    const char *a1;
    const char *a2;
    const WCHAR *w1;
    const WCHAR *w2;
} str_pair;

static const str_pair str_pairs[] = {
    { "a, a", "a", "a", L"a", L"a" },
    { "a, A", "a", "A", L"a", L"A" },
    { "A, a", "A", "a", L"A", L"a" },
    { "a, B", "a", "B", L"a", L"B" },
    { "A, b", "A", "b", L"A", L"b" },
    { "abc, ABC", "abc", "ABC", L"abc", L"ABC" },
    { "co-op, coop", "co-op", "coop", L"co-op", L"coop" },
    { "coop, co-op", "coop", "co-op", L"coop", L"co-op" },
    { "co-op, cop", "co-op", "cop", L"co-op", L"cop" },
    { "co'op, coop", "co'op", "coop", L"co'op", L"coop" },
    { "co'op, co-op", "co'op", "co-op", L"co'op", L"co-op" },
    { "it's, its", "it's", "its", L"it's", L"its" },
    { "it's, itself", "it's", "itself", L"it's", L"itself" },
    { "ab, abc", "ab", "abc", L"ab", L"abc" },
    { "abc, ab", "abc", "ab", L"abc", L"ab" },
    { "empty, a", "", "a", L"", L"a" },
    { "empty, empty", "", "", L"", L"" },
    { "1, 2", "1", "2", L"1", L"2" },
    { "10, 9", "10", "9", L"10", L"9" },
    { "a1, a10", "a1", "a10", L"a1", L"a10" },
    { "a, 1", "a", "1", L"a", L"1" },
    { "e acute, e", "\xE9", "e", L"\x00E9", L"e" },
    { "e acute, f", "\xE9", "f", L"\x00E9", L"f" },
    { "e acute, E acute", "\xE9", "\xC9", L"\x00E9", L"\x00C9" },
    { "e acute, E", "\xE9", "E", L"\x00E9", L"E" },
    { "NULL, a", NULL, "a", NULL, L"a" },
    { "a, NULL", "a", NULL, L"a", NULL },
    { "NULL, NULL", NULL, NULL, NULL, NULL },
    { "NULL, empty", NULL, "", NULL, L"" },
    { NULL, NULL, NULL, NULL, NULL }
};

/* lstrcmpA (0), lstrcmpW (1), lstrcmpiA (2) or lstrcmpiW (3), under
   __try: what a NULL argument does is what the NULL pairs observe, and
   a fault must not stop the fixture on a dialog. */
static int compare_strings(int which, const str_pair *p, int *faulted)
{
    int r = 0;

    *faulted = 0;
    __try {
        switch (which) {
        case 0:
            r = lstrcmpA(p->a1, p->a2);
            break;
        case 1:
            r = lstrcmpW(p->w1, p->w2);
            break;
        case 2:
            r = lstrcmpiA(p->a1, p->a2);
            break;
        default:
            r = lstrcmpiW(p->w1, p->w2);
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *faulted = 1;
    }
    return r;
}

static void sec_lstrcmp(void)
{
    static const char *const names[4] = { "lstrcmpA", "lstrcmpW", "lstrcmpiA", "lstrcmpiW" };
    const str_pair *p;
    const char *p1;
    int which, r, faulted;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    for (p = str_pairs; p->label != NULL; p++) {
        for (which = 0; which < 4; which++) {
            arm();
            r = compare_strings(which, p, &faulted);
            p1 = le();
            if (faulted) {
                line("%s(%s): faulted", names[which], p->label);
            } else {
                /* The sign only: the contract is the sign. */
                line("%s(%s): %d err=%s", names[which], p->label, r < 0 ? -1 : r > 0 ? 1 : 0, p1);
            }
        }
    }
}

/* --- threadlocale -------------------------------------------------- */

static void set_thread_locale(const char *label, LCID lcid)
{
    const char *p1;
    BOOL r;

    arm();
    r = SetThreadLocale(lcid);
    p1 = le();
    line("SetThreadLocale(%s): ret=%d err=%s, GetThreadLocale now 0x%04lX", label, r, p1, GetThreadLocale());
}

static void sec_threadlocale(void)
{
    LCID initial;
    const char *p1;

    arm();
    initial = GetThreadLocale();
    p1 = le();
    line("GetThreadLocale: 0x%04lX err=%s", initial, p1);
    line("GetUserDefaultLCID: 0x%04lX", GetUserDefaultLCID());
    set_thread_locale("0x040C, French", 0x040C);
    line("GetUserDefaultLCID after: 0x%04lX", GetUserDefaultLCID());
    set_thread_locale("0x12345678, invalid", 0x12345678);
    set_thread_locale("0", 0);
    set_thread_locale("LOCALE_USER_DEFAULT", LOCALE_USER_DEFAULT);
    set_thread_locale("LOCALE_SYSTEM_DEFAULT", LOCALE_SYSTEM_DEFAULT);
    set_thread_locale("the initial value", initial);
}

/* --- localtime ----------------------------------------------------- */

/* SetLocalTime on one SYSTEMTIME: the return and the error, never the
   time itself. The VM account is an administrator; SetLocalTime enables
   the system-time privilege itself. */
static void set_local_time(const char *label, const SYSTEMTIME *st)
{
    const char *p1;
    BOOL r;

    arm();
    r = SetLocalTime(st);
    p1 = le();
    line("SetLocalTime(%s): ret=%d err=%s", label, r, p1);
}

static void sec_localtime(void)
{
    SYSTEMTIME now;
    SYSTEMTIME bad;

    /* The current time set again: harmless (a few milliseconds back). */
    GetLocalTime(&now);
    set_local_time("the current time", &now);
    GetLocalTime(&now);
    bad = now;
    bad.wDayOfWeek = 9;
    set_local_time("the current time, a day of week of 9", &bad);
    bad = now;
    bad.wMonth = 13;
    set_local_time("month 13", &bad);
    bad = now;
    bad.wMonth = 0;
    set_local_time("month 0", &bad);
    bad = now;
    bad.wDay = 32;
    set_local_time("day 32", &bad);
    bad = now;
    bad.wMonth = 2;
    bad.wDay = 30;
    set_local_time("February 30", &bad);
    bad = now;
    bad.wHour = 24;
    set_local_time("hour 24", &bad);
    bad = now;
    bad.wMinute = 60;
    set_local_time("minute 60", &bad);
}

/* --- debugbreak ---------------------------------------------------- */

static int break_calls;
static DWORD break_code;
static DWORD break_flags;
static DWORD break_params;
static DWORD break_address;

static int break_filter(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;

    break_calls++;
    break_code = er->ExceptionCode;
    break_flags = er->ExceptionFlags;
    break_params = er->NumberParameters;
    break_address = (DWORD)er->ExceptionAddress;
    return EXCEPTION_EXECUTE_HANDLER;
}

/* Whether an address lies inside a loaded module's image: between its
   handle and the handle plus SizeOfImage, from its own headers. */
static int inside_module(DWORD address, HMODULE h)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;

    if (h == NULL) {
        return 0;
    }
    dos = (IMAGE_DOS_HEADER *)h;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)h + dos->e_lfanew);
    return address >= (DWORD)h && address - (DWORD)h < nt->OptionalHeader.SizeOfImage;
}

static void sec_debugbreak(void)
{
    int handled = 0;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    break_calls = 0;
    break_address = 0;
    __try {
        DebugBreak();
        line("DebugBreak returned");
    } __except (break_filter(GetExceptionInformation())) {
        handled = 1;
    }
    line("DebugBreak: handled %s, filter calls %d, code 0x%08lX flags %lu params %lu", yesno(handled), break_calls,
         break_code, break_flags, break_params);
    line("DebugBreak: exception address inside kernel32 %s, inside ntdll %s, inside the program %s",
         yesno(inside_module(break_address, GetModuleHandleA("kernel32.dll"))),
         yesno(inside_module(break_address, GetModuleHandleA("ntdll.dll"))),
         yesno(inside_module(break_address, GetModuleHandleA(NULL))));
}

/* --- console (named only) ------------------------------------------ */

static void sec_console(void)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written;
    DWORD mode;
    BOOL r;

    line("std handles valid: in %s out %s err %s",
         yesno(in != NULL && in != INVALID_HANDLE_VALUE), yesno(out != NULL && out != INVALID_HANDLE_VALUE),
         yesno(err != NULL && err != INVALID_HANDLE_VALUE));
    line("std handles distinct: %s", yesno(in != out && out != err && in != err));
    line("GetFileType: in %lu out %lu err %lu", GetFileType(in), GetFileType(out), GetFileType(err));
    line("GetConsoleCP %u GetConsoleOutputCP %u", GetConsoleCP(), GetConsoleOutputCP());
    arm();
    r = GetConsoleMode(out, &mode);
    line("GetConsoleMode(out): ret=%d err=%s", r, le());

    arm();
    r = WriteFile(out, "console: WriteFile\r\n", 20, &written, NULL);
    line("WriteFile: ret=%d written=%lu err=%s", r, written, le());
    arm();
    r = WriteConsoleA(out, "console: WriteConsoleA\r\n", 24, &written, NULL);
    line("WriteConsoleA: ret=%d written=%lu err=%s", r, written, le());
    arm();
    r = WriteConsoleW(out, L"console: WriteConsoleW\r\n", 24, &written, NULL);
    line("WriteConsoleW: ret=%d written=%lu err=%s", r, written, le());
    arm();
    r = WriteFile(err, "console: WriteFile to stderr\r\n", 30, &written, NULL);
    line("WriteFile(stderr): ret=%d written=%lu err=%s", r, written, le());

    printf("console: printf %d %s\n", 42, "text");
    fflush(stdout);
    puts("console: puts");
    fflush(stdout);
    fprintf(stderr, "console: fprintf(stderr)\n");
    putchar('c');
    putchar('\n');
    fflush(stdout);
    line("console: _write returned %d", _write(1, "console: _write\n", 16));
    line("console: _isatty(1) %d", _isatty(1) != 0);
}

/* --- unhandled (named only) ---------------------------------------- */

static LONG WINAPI last_chance(EXCEPTION_POINTERS *ep)
{
    line("unhandled filter: code 0x%08lX", ep->ExceptionRecord->ExceptionCode);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void sec_unhandled(void)
{
    LPTOP_LEVEL_EXCEPTION_FILTER prev;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    prev = SetUnhandledExceptionFilter(last_chance);
    line("SetUnhandledExceptionFilter: a previous filter %s", yesno(prev != NULL));
    *(volatile int *)0 = 1;
    line("unhandled: survived");
}

/* --- exit (named only) --------------------------------------------- */

static void at_one(void)
{
    line("atexit: first registered");
}

static void at_two(void)
{
    line("atexit: second registered");
}

static void at_three(void)
{
    line("atexit: third registered");
}

static void sec_exit(void)
{
    int r1, r2, r3;

    r1 = atexit(at_one);
    r2 = atexit(at_two);
    r3 = atexit(at_three);
    line("atexit: %d %d %d", r1, r2, r3);
    line("exit: calling exit(7)");
    exit(7);
}

static const section_t sections[] = {
    { "args", sec_args, 0 },
    { "version", sec_version, 0 },
    { "module", sec_module, 0 },
    { "teb", sec_teb, 0 },
    { "lasterror", sec_lasterror, 0 },
    { "env", sec_env, 0 },
    { "locale", sec_locale, 0 },
    { "crt", sec_crt, 0 },
    { "seh", sec_seh, 0 },
    { "windir", sec_windir, 0 },
    { "filetime", sec_filetime, 0 },
    { "lstrcmp", sec_lstrcmp, 0 },
    { "threadlocale", sec_threadlocale, 0 },
    { "localtime", sec_localtime, 0 },
    { "debugbreak", sec_debugbreak, 0 },
    { "console", sec_console, F2KT_INTERACTIVE },
    { "unhandled", sec_unhandled, 1 },
    { "exit", sec_exit, 1 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    g_argc = argc;
    g_argv = argv;
    return run_sections("runtime", sections, argc, argv);
}
