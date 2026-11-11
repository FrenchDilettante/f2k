/*
 * startup - GetStartupInfoA's string fields: on the platform they are
 * converted from the process parameters (lpReserved from the shell info,
 * lpDesktop from the desktop info, lpTitle from the window title), so a
 * process launched on a desktop carries lpDesktop = "Winsta0\Default",
 * never NULL.
 *
 * Sections:
 *
 *   startup  GetStartupInfoA's lpDesktop, lpTitle and lpReserved: the
 *            desktop string where there is one, the null-ness of the
 *            other two.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat startup):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% startup.c kernel32.lib
 */

#include "../common/f2kt.h"

static void sec_startup(void)
{
    STARTUPINFOA si;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    arm();
    GetStartupInfoA(&si);
    line("GetStartupInfoA: err=%s", le());
    line("lpDesktop=%s", si.lpDesktop != NULL ? si.lpDesktop : "(null)");
    line("lpTitle %s lpReserved %s", si.lpTitle != NULL ? "(set)" : "(null)",
        si.lpReserved != NULL ? "(set)" : "(null)");
}

static const section_t sections[] = {
    { "startup", sec_startup, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("startup", sections, argc, argv);
}
