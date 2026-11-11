/*
 * lcid - CompareString's locale validation: on the platform an LCID no
 * language is installed for is refused before comparing (return 0,
 * ERROR_INVALID_PARAMETER); a valid LCID compares as usual.
 *
 * Sections:
 *
 *   badlcid  CompareStringA and CompareStringW with an uninstalled LCID
 *            (0x9999), then the same calls with the US English LCID
 *            (0x0409) as the sanity line.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat lcid):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% lcid.c kernel32.lib
 */

#include "../common/f2kt.h"

#define F2KT_BAD_LCID 0x9999u
#define F2KT_US_LCID 0x0409u

static void sec_badlcid(void)
{
    int r;

    arm();
    r = CompareStringA(F2KT_BAD_LCID, NORM_IGNORECASE, "abc", -1, "ABC", -1);
    line("CompareStringA(0x9999): ret=%d err=%s", r, le());
    arm();
    r = CompareStringW(F2KT_BAD_LCID, NORM_IGNORECASE, L"abc", -1, L"ABC", -1);
    line("CompareStringW(0x9999): ret=%d err=%s", r, le());
    arm();
    r = CompareStringA(F2KT_US_LCID, NORM_IGNORECASE, "abc", -1, "ABC", -1);
    line("CompareStringA(0x0409): ret=%d err=%s", r, le());
    arm();
    r = CompareStringW(F2KT_US_LCID, NORM_IGNORECASE, L"abc", -1, L"ABC", -1);
    line("CompareStringW(0x0409): ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "badlcid", sec_badlcid, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("lcid", sections, argc, argv);
}
