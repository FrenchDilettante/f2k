/*
 * exitwin - ExitWindowsEx and ntdll's NtShutdownSystem refused: what a
 * program that asks for a shutdown without SeShutdownPrivilege enabled
 * gets back. A shutdown that goes ahead cannot be captured, so none is
 * ever asked for: every call here is one Windows 2000 refuses.
 *
 * Safety: this program must never shut down, restart or log
 * off the machine it is captured on.
 *
 * - Before every ExitWindowsEx or NtShutdownSystem call, guard() checks
 *   that this process's token holds SeShutdownPrivilege (its LUID looked
 *   up, and the public value 19) and that it is disabled, and that the
 *   thread has no token of its own (OpenThreadToken: ERROR_NO_TOKEN). If
 *   any of that fails, the section prints why and stops before the call.
 *   Nothing in this program enables a privilege.
 * - Every ExitWindowsEx call carries an action bit, EWX_SHUTDOWN,
 *   EWX_REBOOT or EWX_POWEROFF, each of which needs the privilege.
 *   EWX_LOGOFF is 0, so a value with no action bit would be a logoff,
 *   which needs no privilege: no call here has one.
 * - A call that succeeds anyway ends its section at once.
 * - Every section runs only when named (F2KT_NAMED), so running the
 *   program with no argument calls nothing. tests\capture.bat runs each
 *   by name.
 *
 * On F2K these sections never run (fixture.toml's skip): F2K checks no
 * shutdown privilege, so a call Windows 2000 refuses would really shut
 * the test boot down.
 *
 * Sections (each by name only):
 *
 *   actions     ExitWindowsEx with EWX_SHUTDOWN, EWX_REBOOT and
 *               EWX_POWEROFF, each alone, with EWX_FORCE, with
 *               EWX_FORCEIFHUNG and with both: the return and the error
 *   flags       ExitWindowsEx with values Windows 2000 does not document:
 *               two or three action bits together, an action with
 *               EWX_QUICKRESOLVE (0x20) or EWX_RESTARTAPPS (0x40), the
 *               later versions' names for bits Windows 2000 does not
 *               define, EWX_SHUTDOWN with a nonzero
 *               dwReserved: the return and the error (whether Windows 2000
 *               checks the flags before the privilege is not documented,
 *               so these are guarded and skipped on F2K like the rest)
 *   ntshutdown  NtShutdownSystem (through GetProcAddress) with the
 *               actions ShutdownNoReboot (0), ShutdownReboot (1) and
 *               ShutdownPowerOff (2), and the out-of-range 3 and
 *               0xFFFFFFFF: the status
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat exitwin):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% exitwin.c user32.lib advapi32.lib
 */

#include "../common/f2kt.h"

/* EWX_FORCEIFHUNG is Windows 2000's: the MSVC 6 headers may predate it. */
#ifndef EWX_FORCEIFHUNG
#define EWX_FORCEIFHUNG 0x00000010
#endif
#ifndef EWX_POWEROFF
#define EWX_POWEROFF 0x00000008
#endif
/* Bits Windows 2000 does not define, under the names later versions gave
 * them: EWX_QUICKRESOLVE (Windows XP) and EWX_RESTARTAPPS (Windows
 * Vista). */
#ifndef EWX_QUICKRESOLVE
#define EWX_QUICKRESOLVE 0x00000020
#endif
#ifndef EWX_RESTARTAPPS
#define EWX_RESTARTAPPS 0x00000040
#endif

/* SeShutdownPrivilege's public LUID (winnt.h's SE_SHUTDOWN_PRIVILEGE). */
#define SHUTDOWN_LUID 19

/* NtShutdownSystem(Action): SHUTDOWN_ACTION's ShutdownNoReboot (0),
 * ShutdownReboot (1), ShutdownPowerOff (2). */
typedef LONG (WINAPI *shutdown_system_fn)(ULONG);

static shutdown_system_fn shutdown_system;  /* NtShutdownSystem */

/* --- the guard ----------------------------------------------------- */

static ULONG guard_buf[1024];           /* 4 KiB, aligned for the structure */

/* 1 when SeShutdownPrivilege is held, disabled, in this process's token,
 * and the thread has no token of its own; 0 otherwise, having printed
 * why. `quiet`: print nothing when it holds. */
static int guard(int quiet)
{
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)guard_buf;
    HANDLE token = NULL;
    LUID luid;
    DWORD len = 0, count, i, e;
    BOOL ok;
    int found = -1;

    if (!LookupPrivilegeValueA(NULL, "SeShutdownPrivilege", &luid)) {
        line("guard: LookupPrivilegeValueA(SeShutdownPrivilege) failed, err=%lu: not calling", GetLastError());
        return 0;
    }
    if (luid.LowPart != SHUTDOWN_LUID || luid.HighPart != 0) {
        line("guard: SeShutdownPrivilege is not LUID 19 here: not calling");
        return 0;
    }
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        CloseHandle(token);
        line("guard: this thread has a token of its own: not calling");
        return 0;
    }
    e = GetLastError();
    if (e != ERROR_NO_TOKEN) {
        line("guard: OpenThreadToken failed with err=%lu, not ERROR_NO_TOKEN: not calling", e);
        return 0;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        line("guard: OpenProcessToken failed, err=%lu: not calling", GetLastError());
        return 0;
    }
    memset(guard_buf, 0, sizeof guard_buf);
    ok = GetTokenInformation(token, TokenPrivileges, guard_buf, sizeof guard_buf, &len);
    e = GetLastError();
    CloseHandle(token);
    if (!ok) {
        line("guard: GetTokenInformation(TokenPrivileges) failed, err=%lu: not calling", e);
        return 0;
    }
    count = tp->PrivilegeCount;
    if (count > (sizeof guard_buf - sizeof(DWORD)) / sizeof(LUID_AND_ATTRIBUTES)) {
        line("guard: the privilege count is out of range: not calling");
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (tp->Privileges[i].Luid.LowPart == luid.LowPart && tp->Privileges[i].Luid.HighPart == luid.HighPart) {
            found = (int)i;
        }
    }
    if (found < 0) {
        line("guard: SeShutdownPrivilege is not held: not calling");
        return 0;
    }
    if (tp->Privileges[found].Attributes & SE_PRIVILEGE_ENABLED) {
        line("guard: SeShutdownPrivilege is ENABLED: not calling");
        return 0;
    }
    if (!quiet) {
        line("guard: SeShutdownPrivilege held and disabled, no thread token: yes");
    }
    return 1;
}

/* ExitWindowsEx(flags, reserved), the guard checked first; 0 when the
 * section must stop (the guard failed, or the call succeeded). */
static int exit_windows(const char *label, UINT flags, DWORD reserved)
{
    BOOL r;

    if ((flags & (EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF)) == 0) {
        line("%s: no action bit, a logoff: never called", label);
        return 0;
    }
    if (!guard(1)) {
        return 0;
    }
    arm();
    r = ExitWindowsEx(flags, reserved);
    line("ExitWindowsEx(%s): ret=%d err=%s", label, r, le());
    if (r) {
        line("  it succeeded: no further call");
        return 0;
    }
    return 1;
}

/* --- actions ------------------------------------------------------- */

static void sec_actions(void)
{
    static const struct {
        UINT flags;
        const char *name;
    } actions[] = {
        { EWX_SHUTDOWN, "EWX_SHUTDOWN" },
        { EWX_REBOOT, "EWX_REBOOT" },
        { EWX_POWEROFF, "EWX_POWEROFF" },
    }, modifiers[] = {
        { 0, "" },
        { EWX_FORCE, " | EWX_FORCE" },
        { EWX_FORCEIFHUNG, " | EWX_FORCEIFHUNG" },
        { EWX_FORCE | EWX_FORCEIFHUNG, " | EWX_FORCE | EWX_FORCEIFHUNG" },
    };
    char label[80];
    int a, m;

    if (!guard(0)) {
        return;
    }
    for (a = 0; a < 3; a++) {
        for (m = 0; m < 4; m++) {
            sprintf(label, "%s%s", actions[a].name, modifiers[m].name);
            if (!exit_windows(label, actions[a].flags | modifiers[m].flags, 0)) {
                return;
            }
        }
    }
}

/* --- flags --------------------------------------------------------- */

static void sec_flags(void)
{
    static const struct {
        UINT flags;
        DWORD reserved;
        const char *name;
    } calls[] = {
        { EWX_SHUTDOWN | EWX_REBOOT, 0, "EWX_SHUTDOWN | EWX_REBOOT" },
        { EWX_SHUTDOWN | EWX_POWEROFF, 0, "EWX_SHUTDOWN | EWX_POWEROFF" },
        { EWX_REBOOT | EWX_POWEROFF, 0, "EWX_REBOOT | EWX_POWEROFF" },
        { EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF, 0, "EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF" },
        { EWX_SHUTDOWN | EWX_QUICKRESOLVE, 0, "EWX_SHUTDOWN | EWX_QUICKRESOLVE" },
        { EWX_SHUTDOWN | EWX_RESTARTAPPS, 0, "EWX_SHUTDOWN | EWX_RESTARTAPPS" },
        { EWX_REBOOT | EWX_QUICKRESOLVE, 0, "EWX_REBOOT | EWX_QUICKRESOLVE" },
        { EWX_SHUTDOWN, 1, "EWX_SHUTDOWN, dwReserved 1" },
    };
    int i;

    if (!guard(0)) {
        return;
    }
    for (i = 0; i < (int)(sizeof calls / sizeof calls[0]); i++) {
        if (!exit_windows(calls[i].name, calls[i].flags, calls[i].reserved)) {
            return;
        }
    }
}

/* --- ntshutdown ---------------------------------------------------- */

static void sec_ntshutdown(void)
{
    static const struct {
        ULONG action;
        const char *name;
    } actions[] = {
        { 0, "ShutdownNoReboot (0)" },
        { 1, "ShutdownReboot (1)" },
        { 2, "ShutdownPowerOff (2)" },
        { 3, "3, out of range" },
        { 0xFFFFFFFFu, "0xFFFFFFFF, out of range" },
    };
    LONG status;
    int i;

    if (shutdown_system == NULL) {
        line("NtShutdownSystem not found");
        return;
    }
    if (!guard(0)) {
        return;
    }
    for (i = 0; i < 5; i++) {
        if (!guard(1)) {
            return;
        }
        status = shutdown_system(actions[i].action);
        line("NtShutdownSystem(%s): status=0x%08lX", actions[i].name, (unsigned long)status);
        if (status >= 0) {
            line("  it succeeded: no further call");
            return;
        }
    }
}

/* --- main ---------------------------------------------------------- */

/* Named only: running the program with no argument calls nothing. */
static const section_t sections[] = {
    { "actions", sec_actions, F2KT_NAMED },
    { "flags", sec_flags, F2KT_NAMED },
    { "ntshutdown", sec_ntshutdown, F2KT_NAMED },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    shutdown_system = (shutdown_system_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtShutdownSystem");
    return run_sections("exitwin", sections, argc, argv);
}
