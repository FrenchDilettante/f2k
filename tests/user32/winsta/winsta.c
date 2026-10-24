/*
 * winsta - the window station and desktop calls cmd.exe imports from
 * user32: GetProcessWindowStation, GetThreadDesktop and
 * GetUserObjectInformation; and MessageBeep.
 *
 * No handle value is printed: only whether one came back and how two
 * compare. The names printed are those of the session capture.bat runs
 * in, the interactive one (WinSta0, Default). A buffer handed to a call
 * starts filled with 0xCC bytes and a length the call may write starts
 * as a marker printed "unset", so a line shows what the call wrote;
 * text prints a NUL as \0. UOI_USER_SID stays out: F2K has no security
 * yet.
 *
 * Each GetUserObjectInformationW line is followed by its A twin's on
 * the same inputs.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   handles  GetProcessWindowStation and GetThreadDesktop of the
 *            current thread: non-NULL, the same handle from a second
 *            call, the two different; GetThreadDesktop of a bogus
 *            thread id
 *   objects  GetUserObjectInformation's UOI_NAME, UOI_TYPE and
 *            UOI_FLAGS (the USEROBJECTFLAGS fields) of the window
 *            station and the desktop, and the length each reports
 *   sizes    the size queries (a NULL buffer of length 0: the return,
 *            the error, the length needed, in bytes) of each index for
 *            both objects; the name and the type into a buffer one
 *            character short, then exactly their size; UOI_FLAGS one
 *            byte short
 *   errors   an invalid index, a NULL handle, a bogus handle
 *   beep     MessageBeep of MB_OK, 0xFFFFFFFF and MB_ICONHAND (the
 *            return and the error; the machine may sound)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat winsta):
 *   cl /nologo /I .. winsta.c user32.lib
 */

#include "../common/f2kt.h"

/* A handle value no object has, and a thread id no thread has. */
#define BOGUS_HANDLE ((HANDLE)0x7FFFFFFC)
#define BOGUS_THREAD 0x7FFFFFFCu

/* What a length starts as, so a line shows whether the call wrote it. */
#define UNSET 0xF2F2F2F2u

/* The form of the call: 1 GetUserObjectInformationW, 0 its A twin. */
static int wide;

/* The buffer a call writes into. */
static union {
    BYTE b[512];
    WCHAR w[256];
} buf;

static const char *fn(void)
{
    return wide ? "GetUserObjectInformationW" : "GetUserObjectInformationA";
}

static const char *index_name(int index)
{
    static char b[16];

    switch (index) {
    case UOI_FLAGS: return "UOI_FLAGS";
    case UOI_NAME: return "UOI_NAME";
    case UOI_TYPE: return "UOI_TYPE";
    }
    sprintf(b, "%d", index);
    return b;
}

/* A number as printed, "unset" for the marker. */
static const char *number(DWORD v)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (v == UNSET) {
        return "unset";
    }
    sprintf(b, "%lu", v);
    return b;
}

/* The buffer as text, its first `units` units (W: WCHARs, A: bytes): a
 * NUL as \0, printable ASCII as itself, any other unit as <U+XXXX> (W)
 * or \xHH (A); "(none)" for no units. */
static const char *text(DWORD units)
{
    static char b[1100];
    DWORD i;
    unsigned u;
    int k = 0;

    if (units == 0) {
        return "(none)";
    }
    if (units > (wide ? sizeof buf.w / sizeof buf.w[0] : sizeof buf.b)) {
        units = wide ? sizeof buf.w / sizeof buf.w[0] : sizeof buf.b;
    }
    for (i = 0; i < units && k < (int)sizeof b - 12; i++) {
        u = wide ? buf.w[i] : buf.b[i];
        if (u == 0) {
            b[k++] = '\\';
            b[k++] = '0';
        } else if (u >= 0x20 && u < 0x7F) {
            b[k++] = (char)u;
        } else {
            k += sprintf(b + k, wide ? "<U+%04X>" : "\\x%02X", u);
        }
    }
    b[k] = 0;
    return b;
}

/* The units of the buffer before its first NUL; the whole buffer's
 * count when it holds none. */
static DWORD units_to_nul(void)
{
    DWORD n = wide ? sizeof buf.w / sizeof buf.w[0] : sizeof buf.b;
    DWORD i;

    for (i = 0; i < n; i++) {
        if ((wide ? buf.w[i] : buf.b[i]) == 0) {
            return i;
        }
    }
    return n;
}

/* Whether the buffer's first `n` bytes are as fill() left them. */
static int untouched(DWORD n)
{
    DWORD i;

    for (i = 0; i < n && i < sizeof buf.b; i++) {
        if (buf.b[i] != 0xCC) {
            return 0;
        }
    }
    return 1;
}

static void fill(void)
{
    memset(buf.b, 0xCC, sizeof buf.b);
}

static BOOL info(HANDLE h, int index, int with_buffer, DWORD length, DWORD *needed)
{
    void *p = with_buffer ? (void *)buf.b : NULL;

    if (wide) {
        return GetUserObjectInformationW(h, index, p, length, needed);
    }
    return GetUserObjectInformationA(h, index, p, length, needed);
}

/* The process's window station and the current thread's desktop. */
static HANDLE station(void)
{
    return (HANDLE)GetProcessWindowStation();
}

static HANDLE desktop(void)
{
    return (HANDLE)GetThreadDesktop(GetCurrentThreadId());
}

/* --- handles ------------------------------------------------------- */

static void sec_handles(void)
{
    HANDLE w1, w2, d1, d2, d3;

    arm();
    w1 = (HANDLE)GetProcessWindowStation();
    line("GetProcessWindowStation: non-NULL %s err=%s", yesno(w1 != NULL), le());
    arm();
    w2 = (HANDLE)GetProcessWindowStation();
    line("GetProcessWindowStation, again: the same handle %s err=%s", yesno(w2 == w1), le());
    arm();
    d1 = (HANDLE)GetThreadDesktop(GetCurrentThreadId());
    line("GetThreadDesktop(the current thread): non-NULL %s err=%s", yesno(d1 != NULL), le());
    arm();
    d2 = (HANDLE)GetThreadDesktop(GetCurrentThreadId());
    line("GetThreadDesktop(the current thread), again: the same handle %s err=%s",
         yesno(d2 == d1), le());
    line("the window station and the desktop handles differ: %s", yesno(w1 != d1));
    arm();
    d3 = (HANDLE)GetThreadDesktop(BOGUS_THREAD);
    line("GetThreadDesktop(a bogus thread id): NULL %s err=%s", yesno(d3 == NULL), le());
}

/* --- objects ------------------------------------------------------- */

/* One index of one object, into the whole buffer. */
static void show(HANDLE h, const char *what, int index)
{
    USEROBJECTFLAGS f;
    DWORD needed = UNSET;
    BOOL r;

    fill();
    arm();
    r = info(h, index, 1, sizeof buf.b, &needed);
    if (!r) {
        line("%s(%s, %s): ret=%d err=%s needed=%s", fn(), what, index_name(index), r, le(),
             number(needed));
    } else if (index == UOI_FLAGS) {
        memcpy(&f, buf.b, sizeof f);
        line("%s(%s, %s): ret=%d err=%s needed=%s fInherit=%d fReserved=%d dwFlags=0x%lX", fn(),
             what, index_name(index), r, le(), number(needed), f.fInherit, f.fReserved,
             f.dwFlags);
    } else {
        line("%s(%s, %s): ret=%d err=%s needed=%s text=%s", fn(), what, index_name(index), r, le(),
             number(needed), text(units_to_nul() + 1));
    }
}

static void sec_objects(void)
{
    static const int indexes[] = { UOI_NAME, UOI_TYPE, UOI_FLAGS };
    HANDLE objects[2];
    static const char *const names[] = { "the window station", "the desktop" };
    int o, i;

    objects[0] = station();
    objects[1] = desktop();
    for (o = 0; o < 2; o++) {
        for (i = 0; i < 3; i++) {
            for (wide = 1; wide >= 0; wide--) {
                show(objects[o], names[o], indexes[i]);
            }
        }
    }
}

/* --- sizes --------------------------------------------------------- */

static void size_query(HANDLE h, const char *what, int index)
{
    DWORD needed = UNSET;
    BOOL r;

    arm();
    r = info(h, index, 0, 0, &needed);
    line("%s(%s, %s, NULL, 0): ret=%d err=%s needed=%s", fn(), what, index_name(index), r, le(),
         number(needed));
}

/* The name or the type into a buffer one character short of it with
 * its terminator, then into one of exactly that size. */
static void short_and_exact(HANDLE h, const char *what, int index)
{
    DWORD needed = UNSET, unit = wide ? 2 : 1, n, length;
    BOOL r;

    fill();
    if (!info(h, index, 1, sizeof buf.b, &needed)) {
        line("%s(%s, %s): failed, err=%lu", fn(), what, index_name(index), GetLastError());
        return;
    }
    n = units_to_nul();

    length = n * unit;
    needed = UNSET;
    fill();
    arm();
    r = info(h, index, 1, length, &needed);
    line("%s(%s, %s, %lu bytes: one character short): ret=%d err=%s needed=%s buffer=%s", fn(),
         what, index_name(index), length, r, le(), number(needed), text(n));

    length = (n + 1) * unit;
    needed = UNSET;
    fill();
    arm();
    r = info(h, index, 1, length, &needed);
    line("%s(%s, %s, %lu bytes: exactly its size): ret=%d err=%s needed=%s buffer=%s", fn(),
         what, index_name(index), length, r, le(), number(needed), text(n + 1));
}

static void sec_sizes(void)
{
    static const int indexes[] = { UOI_NAME, UOI_TYPE, UOI_FLAGS };
    HANDLE objects[2];
    static const char *const names[] = { "the window station", "the desktop" };
    DWORD needed;
    BOOL r;
    int o, i;

    objects[0] = station();
    objects[1] = desktop();
    for (o = 0; o < 2; o++) {
        for (i = 0; i < 3; i++) {
            for (wide = 1; wide >= 0; wide--) {
                size_query(objects[o], names[o], indexes[i]);
            }
        }
    }
    for (o = 0; o < 2; o++) {
        for (i = 0; i < 2; i++) {
            for (wide = 1; wide >= 0; wide--) {
                short_and_exact(objects[o], names[o], indexes[i]);
            }
        }
    }
    for (o = 0; o < 2; o++) {
        for (wide = 1; wide >= 0; wide--) {
            needed = UNSET;
            fill();
            arm();
            r = info(objects[o], UOI_FLAGS, 1, sizeof(USEROBJECTFLAGS) - 1, &needed);
            line("%s(%s, UOI_FLAGS, %u bytes: one byte short): ret=%d err=%s needed=%s "
                 "buffer untouched: %s", fn(), names[o], (unsigned)(sizeof(USEROBJECTFLAGS) - 1),
                 r, le(), number(needed), yesno(untouched(sizeof(USEROBJECTFLAGS) - 1)));
        }
    }
}

/* --- errors -------------------------------------------------------- */

static void error_line(HANDLE h, const char *what, int index)
{
    DWORD needed = UNSET;
    BOOL r;

    fill();
    arm();
    r = info(h, index, 1, sizeof buf.b, &needed);
    line("%s(%s, %s): ret=%d err=%s needed=%s buffer untouched: %s", fn(), what,
         index_name(index), r, le(), number(needed), yesno(untouched(sizeof buf.b)));
}

static void sec_errors(void)
{
    HANDLE w = station();

    for (wide = 1; wide >= 0; wide--) {
        error_line(w, "the window station", 99);
    }
    for (wide = 1; wide >= 0; wide--) {
        error_line(NULL, "NULL", UOI_NAME);
    }
    for (wide = 1; wide >= 0; wide--) {
        error_line(BOGUS_HANDLE, "a bogus handle", UOI_NAME);
    }
}

/* --- beep ---------------------------------------------------------- */

static void sec_beep(void)
{
    BOOL r;

    arm();
    r = MessageBeep(MB_OK);
    line("MessageBeep(MB_OK): ret=%d err=%s", r, le());
    arm();
    r = MessageBeep(0xFFFFFFFF);
    line("MessageBeep(0xFFFFFFFF): ret=%d err=%s", r, le());
    arm();
    r = MessageBeep(MB_ICONHAND);
    line("MessageBeep(MB_ICONHAND): ret=%d err=%s", r, le());
}

static const section_t sections[] = {
    { "handles", sec_handles, 0 },
    { "objects", sec_objects, 0 },
    { "sizes", sec_sizes, 0 },
    { "errors", sec_errors, 0 },
    { "beep", sec_beep, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* Bogus handles and arguments go to the calls: should one fault, no
     * dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("winsta", sections, argc, argv);
}
