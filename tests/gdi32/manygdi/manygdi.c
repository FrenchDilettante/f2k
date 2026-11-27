/*
 * manygdi - gdi32's handle table at scale: the per-process quota on GDI
 * objects, a slot's reuse, a handle carried to another process, and the
 * type bits of each kind's handles.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   quota    CreateSolidBrush until it fails (at most 20,000): the
 *            number made, against the GDI objects the process owned
 *            before (GetGuiResources, reached through GetProcAddress),
 *            their sum and a band verdict (Windows 2000's
 *            GDIProcessHandleQuota is 10,000 by default), the failing
 *            call's last error; one DeleteObject, then a create
 *            succeeds on the freed slot and the next fails again; every
 *            brush deleted
 *   reuse    a brush made and deleted, then another made at once: the
 *            same handle, the same low word (the slot), the same bits
 *            16-23 (the type), a different high byte (bits 24-31, the
 *            slot's reuse count)
 *   foreign  a brush handed to a second copy of the program on its
 *            command line ("manygdi.exe --child <handle>"):
 *            GetObjectA, GetObjectType and DeleteObject on it there,
 *            then GetObjectA on it here
 *   raw      a memory DC, the screen's DC, a brush, a pen, a bitmap, a
 *            font, a region, and stock objects (a brush, a pen, a font,
 *            the palette, a memory DC's first bitmap): each handle's bits
 *            16-23 (the type, bit 23 the stock bit) and GetObjectType
 *
 * No handle value is printed in full but raw's two, and those lines are
 * masked: the low word is a table index and bits 24-31 a reuse count,
 * both the machine's own. Bits 16-23 are the point: they are what F2K's
 * handles must carry to look like Windows 2000's, so raw prints them
 * for each kind, and the whole value once for a brush and a stock
 * brush, for the record.
 *
 * reuse's and quota's slot relations hold while no other program makes
 * a GDI object between the deletion and the creation (Windows 2000's
 * table is system-wide): run on an idle machine.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat manygdi):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% manygdi.c user32.lib gdi32.lib
 */

#include "../common/f2kt.h"
#include <stdlib.h>

/* GetGuiResources' flag (winuser.h has it for WINVER 0x0500 only). */
#define GR_GDIOBJECTS_ 0

typedef DWORD (WINAPI *get_gui_resources_t)(HANDLE, DWORD);

/* The quota loop's bound: past the 16,384 entries of Windows 2000's
 * system-wide table, so a missing quota shows as the table's ceiling. */
#define QUOTA_BOUND 20000

static HBRUSH brushes[QUOTA_BOUND];

/* GDI objects the process owns (GetGuiResources), or -1 when user32
 * lacks the export. */
static long gdi_objects(void)
{
    get_gui_resources_t get;

    get = (get_gui_resources_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetGuiResources");
    if (get == NULL) {
        return -1;
    }
    return (long)get(GetCurrentProcess(), GR_GDIOBJECTS_);
}

/* --- quota --------------------------------------------------------- */

static void sec_quota(void)
{
    long before, at_refusal;
    int made, i;
    HBRUSH h;
    DWORD freed;
    const char *e;

    before = gdi_objects();
    if (before < 0) {
        line("GetGuiResources: absent");
    } else {
        line("GDI objects owned before: %ld", before);
    }
    made = 0;
    e = "-";
    while (made < QUOTA_BOUND) {
        arm();
        h = CreateSolidBrush(RGB(made & 0xFF, (made >> 8) & 0xFF, 0x40));
        if (h == NULL) {
            e = le();
            break;
        }
        brushes[made++] = h;
    }
    if (made == QUOTA_BOUND) {
        line("CreateSolidBrush: %d made, stopped at the loop's bound", made);
    } else {
        line("CreateSolidBrush: %d made, then NULL err=%s", made, e);
    }
    line("  within [9900, 10000]: %s", band((DWORD)made, 9900, 10000));
    at_refusal = gdi_objects();
    if (before >= 0) {
        line("  made plus owned before: %ld; GDI objects owned at the refusal: %ld",
             made + before, at_refusal);
    }
    if (made == 0) {
        return;
    }

    /* One freed: the next create takes its slot, the one after fails. */
    freed = (DWORD)brushes[made - 1];
    arm();
    i = DeleteObject(brushes[made - 1]);
    line("DeleteObject(the last): ret=%d err=%s", i, le());
    arm();
    h = CreateSolidBrush(RGB(1, 2, 3));
    e = le();
    line("CreateSolidBrush after it: non-NULL %s err=%s, the freed one's low word %s", yesno(h != NULL),
         e, yesno(h != NULL && LOWORD((DWORD)h) == LOWORD(freed)));
    if (h != NULL) {
        brushes[made - 1] = h;
        arm();
        h = CreateSolidBrush(RGB(4, 5, 6));
        e = le();
        line("CreateSolidBrush again: non-NULL %s err=%s", yesno(h != NULL), e);
        if (h != NULL && made < QUOTA_BOUND) {
            brushes[made++] = h;
        } else if (h != NULL) {
            DeleteObject(h);
        }
    } else {
        made--;
    }

    for (i = 0; i < made; i++) {
        if (!DeleteObject(brushes[i])) {
            break;
        }
    }
    line("every brush deleted: %s", yesno(i == made));
    if (before >= 0) {
        line("GDI objects owned after: as before %s", yesno(gdi_objects() == before));
    }
}

/* --- reuse --------------------------------------------------------- */

static void sec_reuse(void)
{
    HBRUSH a, b;
    DWORD x, y;
    BOOL r;

    a = CreateSolidBrush(RGB(0x10, 0x20, 0x30));
    x = (DWORD)a;
    arm();
    r = DeleteObject(a);
    line("a brush made and deleted: made %s, DeleteObject ret=%d err=%s", yesno(a != NULL), r, le());
    b = CreateSolidBrush(RGB(0x40, 0x50, 0x60));
    y = (DWORD)b;
    line("another made at once: non-NULL %s", yesno(b != NULL));
    line("  the same handle %s, the same low word %s, the same bits 16-23 %s, a different high byte %s",
         yesno(y == x), yesno(LOWORD(y) == LOWORD(x)), yesno(((y >> 16) & 0xFF) == ((x >> 16) & 0xFF)),
         yesno((y >> 24) != (x >> 24)));
    DeleteObject(b);
}

/* --- foreign ------------------------------------------------------- */

/* The child's report, packed into its exit code (it prints nothing: its
 * output would not reach the parent's capture): GetObjectA's return in
 * bits 0-7, GetObjectType's in bits 8-15, DeleteObject's in bit 16, and
 * each call's last error as a small code, three bits each from bit 20. */
static DWORD err_code(DWORD e)
{
    switch (e) {
    case F2KT_UNTOUCHED: return 0;
    case 0: return 1;
    case ERROR_INVALID_HANDLE: return 2;
    case ERROR_INVALID_PARAMETER: return 3;
    case ERROR_NOT_ENOUGH_MEMORY: return 4;
    case ERROR_ACCESS_DENIED: return 5;
    }
    return 7;
}

static const char *err_name(DWORD c)
{
    static const char *names[8] = { "-", "0", "6", "87", "8", "5", "?", "other" };

    return names[c & 7];
}

static int child(const char *handle)
{
    HBRUSH h;
    LOGBRUSH lb;
    int got;
    DWORD type, e1, e2, e3;
    BOOL r;

    h = (HBRUSH)strtoul(handle, NULL, 16);
    arm();
    got = GetObjectA(h, sizeof lb, &lb);
    e1 = GetLastError();
    arm();
    type = GetObjectType(h);
    e2 = GetLastError();
    arm();
    r = DeleteObject(h);
    e3 = GetLastError();
    return (int)(((DWORD)got & 0xFF) | ((type & 0xFF) << 8) | (r ? 0x10000 : 0) | (err_code(e1) << 20) |
                 (err_code(e2) << 23) | (err_code(e3) << 26));
}

static void sec_foreign(void)
{
    HBRUSH h;
    LOGBRUSH lb;
    char path[MAX_PATH];
    char cmdline[MAX_PATH + 32];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD w, code;
    BOOL ok;
    int got;

    h = CreateSolidBrush(RGB(0x12, 0x34, 0x56));
    line("a brush: non-NULL %s", yesno(h != NULL));
    if (h == NULL) {
        return;
    }
    GetModuleFileNameA(NULL, path, sizeof path);
    sprintf(cmdline, "\"%s\" --child %lx", path, (unsigned long)h);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    arm();
    ok = CreateProcessA(path, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    line("CreateProcessA(manygdi.exe --child): ret=%d err=%s", ok, le());
    if (!ok) {
        DeleteObject(h);
        return;
    }
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    line("the child ended: %s", wr(w));
    if (w == WAIT_OBJECT_0) {
        line("  there, GetObjectA(the brush, LOGBRUSH): ret=%lu err=%s", code & 0xFF, err_name(code >> 20));
        line("  there, GetObjectType(the brush): %lu err=%s", (code >> 8) & 0xFF, err_name(code >> 23));
        line("  there, DeleteObject(the brush): ret=%lu err=%s", (code >> 16) & 1, err_name(code >> 26));
    } else {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, WAIT_MS);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    arm();
    got = GetObjectA(h, sizeof lb, &lb);
    line("here after, GetObjectA(the brush, LOGBRUSH): ret=%d err=%s color 0x%06lX", got, le(),
         got != 0 ? (unsigned long)lb.lbColor : 0ul);
    arm();
    ok = DeleteObject(h);
    line("here, DeleteObject(the brush): ret=%d err=%s", ok, le());
}

/* --- raw ----------------------------------------------------------- */

/* One object's type bits: bits 16-23 of its handle (bits 16-22 the
 * type, bit 23 the stock bit), and GetObjectType's answer. */
static void type_bits(const char *what, HGDIOBJ h)
{
    if (h == NULL) {
        line("%s: NULL", what);
        return;
    }
    line("%s: bits 16-23 0x%02lX, GetObjectType %lu", what, ((DWORD)h >> 16) & 0xFF,
         GetObjectType(h));
}

static void sec_raw(void)
{
    HDC mem, screen;
    HBRUSH brush;
    HPEN pen;
    HBITMAP bitmap;
    HFONT font;
    HRGN region;

    mem = CreateCompatibleDC(NULL);
    screen = GetDC(NULL);
    brush = CreateSolidBrush(RGB(0x80, 0x40, 0x20));
    pen = CreatePen(PS_SOLID, 1, RGB(0x20, 0x40, 0x80));
    bitmap = CreateBitmap(8, 8, 1, 1, NULL);
    font = CreateFontA(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    region = CreateRectRgn(0, 0, 10, 10);

    type_bits("CreateCompatibleDC(NULL)", mem);
    type_bits("GetDC(NULL)", screen);
    type_bits("CreateSolidBrush", brush);
    type_bits("CreatePen(PS_SOLID)", pen);
    type_bits("CreateBitmap(8x8, 1 bpp)", bitmap);
    type_bits("CreateFontA", font);
    type_bits("CreateRectRgn", region);
    type_bits("GetStockObject(WHITE_BRUSH)", GetStockObject(WHITE_BRUSH));
    type_bits("GetStockObject(BLACK_PEN)", GetStockObject(BLACK_PEN));
    type_bits("GetStockObject(SYSTEM_FONT)", GetStockObject(SYSTEM_FONT));
    type_bits("GetStockObject(DEFAULT_PALETTE)", GetStockObject(DEFAULT_PALETTE));
    type_bits("a memory DC's first bitmap", mem != NULL ? GetCurrentObject(mem, OBJ_BITMAP) : NULL);

    /* The whole value, for the record: the one place a raw handle is the
     * point. Its low word (the table index) and bits 24-31 (the slot's
     * reuse count) are the machine's own, so fixture.toml masks these
     * two lines; what the capture shows of them is for reading, the
     * layout F2K's handles should take. */
    line("a brush's handle, raw: 0x%08lX", (DWORD)brush);
    line("WHITE_BRUSH's handle, raw: 0x%08lX", (DWORD)GetStockObject(WHITE_BRUSH));

    DeleteObject(region);
    DeleteObject(font);
    DeleteObject(bitmap);
    DeleteObject(pen);
    DeleteObject(brush);
    ReleaseDC(NULL, screen);
    DeleteDC(mem);
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "quota", sec_quota, F2KT_ALWAYS },
    { "reuse", sec_reuse, F2KT_ALWAYS },
    { "foreign", sec_foreign, F2KT_ALWAYS },
    { "raw", sec_raw, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A foreign or freed handle goes to the calls: should one fault, no
     * dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) {
        return child(argv[2]);
    }
    return run_sections("manygdi", sections, argc, argv);
}
