/*
 * gditext - a screen DC of gdi32's own and text drawn through it, with
 * no window: CreateDCA of the DISPLAY driver, TextOutA, SetTextColor,
 * SetBkColor, ExtTextOutA with ETO_OPAQUE over its rectangle, DeleteDC.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel and its line
 * prints ret= and err=; no handle value is printed (the DC compares
 * through yesno()); colors print as 0x%06lX, rects and coordinates as
 * plain numbers. The text goes onto the screen itself, over whatever
 * the desktop shows: nothing reads it back.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   paint    CreateDCA("DISPLAY", NULL, NULL, NULL); TextOutA of a line
 *            at (8, 8) in the DC's default colors; SetTextColor red and
 *            SetBkColor yellow (each prints the previous color); a
 *            second line through ExtTextOutA with ETO_OPAQUE over a
 *            rectangle around it; DeleteDC
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat gditext):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% gditext.c gdi32.lib
 */

#include "../common/f2kt.h"

/* --- paint --------------------------------------------------------- */

static void sec_paint(void)
{
    static const char first[] = "TextOutA on the screen DC";
    static const char second[] = "ExtTextOutA, red on yellow";
    HDC sdc;
    RECT rc;
    COLORREF prev;
    int r;

    arm();
    sdc = CreateDCA("DISPLAY", NULL, NULL, NULL);
    line("CreateDCA(\"DISPLAY\", NULL, NULL, NULL): non-NULL %s err=%s", yesno(sdc != NULL), le());

    arm();
    r = TextOutA(sdc, 8, 8, first, (int)(sizeof first - 1));
    line("TextOutA(sdc, 8, 8, \"%s\", %d): ret=%d err=%s", first, (int)(sizeof first - 1), r, le());

    arm();
    prev = SetTextColor(sdc, RGB(255, 0, 0));
    line("SetTextColor(sdc, RGB(255,0,0)): previous=0x%06lX err=%s", (unsigned long)prev, le());
    arm();
    prev = SetBkColor(sdc, RGB(255, 255, 0));
    line("SetBkColor(sdc, RGB(255,255,0)): previous=0x%06lX err=%s", (unsigned long)prev, le());

    rc.left = 4;
    rc.top = 28;
    rc.right = 260;
    rc.bottom = 52;
    arm();
    r = ExtTextOutA(sdc, 8, 32, ETO_OPAQUE, &rc, second, (UINT)(sizeof second - 1), NULL);
    line("ExtTextOutA(sdc, 8, 32, ETO_OPAQUE, rect 4 28 260 52, \"%s\", %d, NULL): ret=%d err=%s",
         second, (int)(sizeof second - 1), r, le());

    arm();
    r = DeleteDC(sdc);
    line("DeleteDC(sdc): ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "paint", sec_paint, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A bad DC would fault: no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("gditext", sections, argc, argv);
}
