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
 *              ids, stack bounds, the last-error slot, the SEH chain
 *   lasterror  SetLastError/GetLastError, which calls keep or set the
 *              value, FormatMessageA over system messages
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

    arm();
    n = GetModuleFileNameA(NULL, path, sizeof path);
    line("GetModuleFileNameA: name %s, length matches: %s, absolute: %s, err=%s",
         basename_upper(path, base, sizeof base), yesno(n == strlen(path)), yesno(is_absolute(path)), le());
    line("_pgmptr matches: %s", yesno(_pgmptr != NULL && strcmp(_pgmptr, path) == 0));

    memset(small, 'x', sizeof small);
    arm();
    n = GetModuleFileNameA(NULL, small, 4);
    line("GetModuleFileNameA into 4 bytes: ret=%lu terminated at 3: %s err=%s",
         n, yesno(small[3] == 0), le());
}

/* --- version ------------------------------------------------------- */

static void sec_version(void)
{
    OSVERSIONINFOA vi;
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

    vi.dwOSVersionInfoSize = 10;
    arm();
    r = GetVersionExA(&vi);
    line("GetVersionExA with a bad size: ret=%d err=%s", r, le());

    line("CRT: _osver 0x%X _winmajor %u _winminor %u _winver 0x%X",
         _osver, _winmajor, _winminor, _winver);
}

/* --- module -------------------------------------------------------- */

static void sec_module(void)
{
    HMODULE self;
    HMODULE k32;
    HMODULE h;
    FARPROC fp;
    char path[MAX_PATH];
    char base[MAX_PATH];
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD t0, t1;
    BOOL r;

    self = GetModuleHandleA(NULL);
    line("GetModuleHandleA(NULL): 0x%08lX", (DWORD)self);

    dos = (IMAGE_DOS_HEADER *)self;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)self + dos->e_lfanew);
    line("own headers: MZ %s, PE %s, ImageBase matches %s, entry point inside image %s",
         yesno(dos->e_magic == IMAGE_DOS_SIGNATURE), yesno(nt->Signature == IMAGE_NT_SIGNATURE),
         yesno(nt->OptionalHeader.ImageBase == (DWORD)self),
         yesno(nt->OptionalHeader.AddressOfEntryPoint < nt->OptionalHeader.SizeOfImage));

    k32 = GetModuleHandleA("kernel32.dll");
    line("GetModuleHandleA(kernel32.dll): found %s", yesno(k32 != NULL));
    line("GetModuleHandleA(KERNEL32) same module: %s", yesno(GetModuleHandleA("KERNEL32") == k32));
    arm();
    h = GetModuleHandleA("nosuch.dll");
    line("GetModuleHandleA(nosuch.dll): ret null %s err=%s", yesno(h == NULL), le());

    arm();
    path[0] = 0;
    GetModuleFileNameA(k32, path, sizeof path);
    line("GetModuleFileNameA(kernel32): %s err=%s", basename_upper(path, base, sizeof base), le());

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
    h = LoadLibraryA("nosuch.dll");
    line("LoadLibraryA(nosuch.dll): ret null %s err=%s", yesno(h == NULL), le());
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
        line("PEB ProcessHeap matches: %s", yesno(*(DWORD *)(peb + 0x18) == (DWORD)GetProcessHeap()));
    }
}

/* --- lasterror ----------------------------------------------------- */

static void message(DWORD code)
{
    char buf[256];
    DWORD n;
    char *p;

    arm();
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof buf, NULL);
    if (n == 0) {
        line("FormatMessageA(%lu): ret=0 err=%s", code, le());
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

static void sec_lasterror(void)
{
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

    message(2);
    message(5);
    message(0x01234567);
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

static void sec_env(void)
{
    char buf[128];
    char *block;
    WCHAR *wblock;
    const char *g;
    DWORD n;
    BOOL r;

    arm();
    r = SetEnvironmentVariableA("F2KTEST", "first");
    line("SetEnvironmentVariableA: ret=%d err=%s", r, le());
    arm();
    n = GetEnvironmentVariableA("F2KTEST", NULL, 0);
    line("size query: ret=%lu err=%s", n, le());
    arm();
    n = GetEnvironmentVariableA("F2KTEST", buf, sizeof buf);
    line("get: ret=%lu [%s] err=%s", n, buf, le());
    arm();
    n = GetEnvironmentVariableA("F2KTEST", buf, 3);
    line("get into 3 bytes: ret=%lu err=%s", n, le());

    SetEnvironmentVariableA("F2KTEST", "second value");
    arm();
    n = GetEnvironmentVariableA("f2ktest", buf, sizeof buf);
    line("get by lower-case name: ret=%lu [%s] err=%s", n, buf, le());

    block = GetEnvironmentStrings();
    line("GetEnvironmentStrings: has the entry %s", yesno(block != NULL && block_has(block, "F2KTEST=second value")));
    if (block != NULL) {
        arm();
        r = FreeEnvironmentStringsA(block);
        line("FreeEnvironmentStringsA: ret=%d err=%s", r, le());
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

    g = getenv("F2KTEST");
    line("CRT getenv sees the OS-level variable: %s", yesno(g != NULL));
    line("CRT _putenv: %d", _putenv("F2KCRT=crt value"));
    g = getenv("F2KCRT");
    line("CRT getenv after _putenv: [%s]", g != NULL ? g : "(null)");
    n = GetEnvironmentVariableA("F2KCRT", buf, sizeof buf);
    line("OS sees the _putenv variable: ret=%lu [%s]", n, n != 0 ? buf : "");

    arm();
    n = ExpandEnvironmentStringsA("[%F2KCRT%] [%F2KNOSUCH%]", buf, sizeof buf);
    line("ExpandEnvironmentStringsA: ret=%lu [%s] err=%s", n, buf, le());
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

static void sec_locale(void)
{
    BYTE in[256];
    BYTE out[256];
    WCHAR w[256];
    WORD types[256];
    char buf[128];
    char *loc;
    BOOL used;
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

    line("CompareStringA apple/Banana: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "apple", -1, "Banana", -1));
    line("CompareStringA abc/ABC ignore case: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, "abc", -1, "ABC", -1));
    line("CompareStringA abc/ABC: %d", CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "abc", -1, "ABC", -1));
    line("CompareStringA co-op/coop: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, 0, "co-op", -1, "coop", -1));
    line("CompareStringA co-op/coop string sort: %d",
         CompareStringA(LOCALE_SYSTEM_DEFAULT, SORT_STRINGSORT, "co-op", -1, "coop", -1));

    line("GetUserDefaultLCID: 0x%04lX", GetUserDefaultLCID());
    line("GetSystemDefaultLCID: 0x%04lX", GetSystemDefaultLCID());
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, buf, sizeof buf);
    line("LOCALE_SENGLANGUAGE: ret=%d [%s]", n, n ? buf : "");
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_IDEFAULTANSICODEPAGE, buf, sizeof buf);
    line("LOCALE_IDEFAULTANSICODEPAGE: ret=%d [%s]", n, n ? buf : "");
    n = GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL, buf, sizeof buf);
    line("LOCALE_SDECIMAL: ret=%d [%s]", n, n ? buf : "");

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
    { "console", sec_console, 1 },
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
