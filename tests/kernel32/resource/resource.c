/*
 * resource - a module's resources: kernel32's FindResourceA/W and
 * FindResourceExA/W, LoadResource, LockResource, SizeofResource and
 * FreeResource, and user32's LoadStringA/W, over the program's own
 * resources (resource.rc, compiled by rc and linked in):
 *
 *   101 RCDATA         "id 101 data"
 *   MIXEDNAME RCDATA   "named data" (MixedName in the script)
 *   ITEM MYTYPE        "custom type" (Item MyType in the script)
 *   7 300              "type 300" (a numbered type of its own)
 *   200 RCDATA         "english" in 0x0409, "francais" in 0x040C
 *   201 RCDATA         "neutral", in LANG_NEUTRAL alone
 *   STRINGTABLE        1 "first string", 2 "second", 17 "seventeen",
 *                      100 "a longer string for the short buffers"
 *
 * Everything is in US English (0x0409) but 200's French copy and 201.
 *
 * No handle or address is printed. A FindResource line prints whether
 * the call found the resource, the last error, and, where the line
 * names one, whether it found the same resource (the same HRSRC) as an
 * earlier call. A resource's data prints as its size, whether it lies
 * inside the module's image (its SizeOfImage from its headers), its
 * first bytes in hex and those bytes as text ('.' for a byte outside
 * printable ASCII). Before a LoadString call the buffer is filled with
 * '#' (A) or U+0023 (W), so a line shows what the call wrote.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   finda    FindResourceA (the name, then the type): by number, "#101",
 *            "#0101", the name in upper, lower and mixed case, a type of
 *            its own by name in either case and by number, "#10" for
 *            RT_RCDATA, a NULL module (the program's), the string block
 *            (RT_STRING, block 1), the resource in two languages and
 *            the neutral one; "#abc" (no digits after the '#') and "";
 *            and the errors: a name the type lacks, a type the module
 *            lacks, and kernel32's module for a type it lacks
 *   findw    FindResourceW, the same cases
 *   findexa  FindResourceExA (the type, then the name, then the
 *            language): the two-language resource in 0x0409, 0x040C,
 *            LANG_NEUTRAL with SUBLANG_NEUTRAL, SUBLANG_DEFAULT and
 *            SUBLANG_SYS_DEFAULT, 0x0809 and 0x0407; the neutral-only
 *            resource in 0x0409 and 0; names in either case; the
 *            arguments in FindResource's order (the name as the type);
 *            a NULL module; the type and name errors
 *   findexw  FindResourceExW, the same cases
 *   load     SizeofResource, LoadResource and LockResource over each
 *            resource (the two languages each through FindResourceExA),
 *            through the module and through NULL; LoadResource,
 *            SizeofResource and LockResource of NULL
 *   free     FreeResource's return for a loaded resource, twice, and
 *            for NULL; whether the data is still there after it
 *   stringa  LoadStringA: ids 1, 2, 17 and 100 into a buffer that fits,
 *            id 100 into 8 characters, 1 and 0, ids 3 (in block 1, no
 *            string) and 500 (no block), and a NULL instance
 *   stringw  LoadStringW, the same cases, and a buffer size of 0 (the
 *            buffer then given a pointer to the string, as later
 *            documentation describes)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat resource):
 *   rc resource.rc
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% resource.c resource.res user32.lib
 */

#include "../common/f2kt.h"

/* The numbered types the sections name: RT_STRING (6) and RT_RCDATA
 * (10), in each form, and the type of its own numbered 300. */
#define STRING_A MAKEINTRESOURCEA(6)
#define STRING_W MAKEINTRESOURCEW(6)
#define RCDATA_A MAKEINTRESOURCEA(10)
#define RCDATA_W MAKEINTRESOURCEW(10)
#define T300_A MAKEINTRESOURCEA(300)
#define T300_W MAKEINTRESOURCEW(300)

/* The languages the sections ask for. */
#define EN_US MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)
#define EN_UK MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_UK)
#define FRENCH MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH)
#define GERMAN MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN)
#define NEUTRAL MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)
#define USER_DEFAULT MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
#define SYS_DEFAULT MAKELANGID(LANG_NEUTRAL, SUBLANG_SYS_DEFAULT)

/* How many bytes of a resource's data print. */
#define SHOWN 32

/* The program's own module, and kernel32's. */
static HMODULE self;
static HMODULE k32;

/* A FindResource result: whether found, the last error (read first),
 * and, when `ref` is given, whether it is the same resource. */
static void found(const char *what, HRSRC h, HRSRC ref)
{
    const char *e = le();

    if (ref == NULL) {
        line("%s: found=%s err=%s", what, yesno(h != NULL), e);
    } else {
        line("%s: found=%s err=%s same=%s", what, yesno(h != NULL), e, yesno(h == ref));
    }
}

/* The first SHOWN bytes of `n` at `p`, in hex, then as text. Calls no
 * API. */
static const char *bytes(const void *p, DWORD n)
{
    static char b[4 * SHOWN + 32];
    const BYTE *at = (const BYTE *)p;
    DWORD shown = n < SHOWN ? n : SHOWN;
    DWORD i;
    int len = 0;

    for (i = 0; i < shown; i++) {
        len += sprintf(b + len, "%02X ", at[i]);
    }
    len += sprintf(b + len, "%s\"", n > shown ? "... " : "");
    for (i = 0; i < shown; i++) {
        b[len++] = (at[i] >= 0x20 && at[i] < 0x7F) ? (char)at[i] : '.';
    }
    b[len++] = '"';
    b[len] = '\0';
    return b;
}

/* Whether the `n` bytes at `p` lie inside the image of `mod` (its
 * SizeOfImage, from its headers). Calls no API. */
static int inside(HMODULE mod, const void *p, DWORD n)
{
    const BYTE *base = (const BYTE *)mod;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    const BYTE *at = (const BYTE *)p;

    return at >= base && at + n <= base + nt->OptionalHeader.SizeOfImage;
}

/* ------------------------------------------------------------------ */

static void sec_finda(void)
{
    HRSRC byid, h;

    arm();
    byid = FindResourceA(self, MAKEINTRESOURCEA(101), RCDATA_A);
    found("FindResourceA(101, RT_RCDATA)", byid, NULL);
    arm();
    h = FindResourceA(self, "#101", RCDATA_A);
    found("FindResourceA(\"#101\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceA(self, "#0101", RCDATA_A);
    found("FindResourceA(\"#0101\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceA(self, "#101", "#10");
    found("FindResourceA(\"#101\", \"#10\")", h, byid);
    arm();
    h = FindResourceA(NULL, MAKEINTRESOURCEA(101), RCDATA_A);
    found("FindResourceA(NULL module, 101, RT_RCDATA)", h, byid);

    arm();
    byid = FindResourceA(self, "MIXEDNAME", RCDATA_A);
    found("FindResourceA(\"MIXEDNAME\", RT_RCDATA)", byid, NULL);
    arm();
    h = FindResourceA(self, "mixedname", RCDATA_A);
    found("FindResourceA(\"mixedname\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceA(self, "MixedName", RCDATA_A);
    found("FindResourceA(\"MixedName\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceA(NULL, "mixedName", RCDATA_A);
    found("FindResourceA(NULL module, \"mixedName\", RT_RCDATA)", h, byid);

    arm();
    byid = FindResourceA(self, "ITEM", "MYTYPE");
    found("FindResourceA(\"ITEM\", \"MYTYPE\")", byid, NULL);
    arm();
    h = FindResourceA(self, "item", "mytype");
    found("FindResourceA(\"item\", \"mytype\")", h, byid);
    arm();
    h = FindResourceA(self, "Item", "MyType");
    found("FindResourceA(\"Item\", \"MyType\")", h, byid);
    arm();
    byid = FindResourceA(self, MAKEINTRESOURCEA(7), T300_A);
    found("FindResourceA(7, 300)", byid, NULL);
    arm();
    h = FindResourceA(self, "#7", "#300");
    found("FindResourceA(\"#7\", \"#300\")", h, byid);

    arm();
    h = FindResourceA(self, MAKEINTRESOURCEA(1), STRING_A);
    found("FindResourceA(1, RT_STRING)", h, NULL);
    arm();
    h = FindResourceA(self, MAKEINTRESOURCEA(200), RCDATA_A);
    found("FindResourceA(200, RT_RCDATA) (two languages)", h, NULL);
    arm();
    h = FindResourceA(self, MAKEINTRESOURCEA(201), RCDATA_A);
    found("FindResourceA(201, RT_RCDATA) (neutral)", h, NULL);

    arm();
    h = FindResourceA(self, "#abc", RCDATA_A);
    found("FindResourceA(\"#abc\", RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceA(self, "", RCDATA_A);
    found("FindResourceA(\"\", RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceA(self, MAKEINTRESOURCEA(999), RCDATA_A);
    found("FindResourceA(999, RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceA(self, "NOSUCHNAME", RCDATA_A);
    found("FindResourceA(\"NOSUCHNAME\", RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceA(self, MAKEINTRESOURCEA(101), "NOSUCHTYPE");
    found("FindResourceA(101, \"NOSUCHTYPE\")", h, NULL);
    arm();
    h = FindResourceA(self, MAKEINTRESOURCEA(101), MAKEINTRESOURCEA(999));
    found("FindResourceA(101, 999)", h, NULL);
    arm();
    h = FindResourceA(k32, MAKEINTRESOURCEA(1), "MYTYPE");
    found("FindResourceA(kernel32, 1, \"MYTYPE\")", h, NULL);
}

static void sec_findw(void)
{
    HRSRC byid, h;

    arm();
    byid = FindResourceW(self, MAKEINTRESOURCEW(101), RCDATA_W);
    found("FindResourceW(101, RT_RCDATA)", byid, NULL);
    arm();
    h = FindResourceW(self, L"#101", RCDATA_W);
    found("FindResourceW(\"#101\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceW(self, L"#0101", RCDATA_W);
    found("FindResourceW(\"#0101\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceW(self, L"#101", L"#10");
    found("FindResourceW(\"#101\", \"#10\")", h, byid);
    arm();
    h = FindResourceW(NULL, MAKEINTRESOURCEW(101), RCDATA_W);
    found("FindResourceW(NULL module, 101, RT_RCDATA)", h, byid);

    arm();
    byid = FindResourceW(self, L"MIXEDNAME", RCDATA_W);
    found("FindResourceW(\"MIXEDNAME\", RT_RCDATA)", byid, NULL);
    arm();
    h = FindResourceW(self, L"mixedname", RCDATA_W);
    found("FindResourceW(\"mixedname\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceW(self, L"MixedName", RCDATA_W);
    found("FindResourceW(\"MixedName\", RT_RCDATA)", h, byid);
    arm();
    h = FindResourceW(NULL, L"mixedName", RCDATA_W);
    found("FindResourceW(NULL module, \"mixedName\", RT_RCDATA)", h, byid);

    arm();
    byid = FindResourceW(self, L"ITEM", L"MYTYPE");
    found("FindResourceW(\"ITEM\", \"MYTYPE\")", byid, NULL);
    arm();
    h = FindResourceW(self, L"item", L"mytype");
    found("FindResourceW(\"item\", \"mytype\")", h, byid);
    arm();
    h = FindResourceW(self, L"Item", L"MyType");
    found("FindResourceW(\"Item\", \"MyType\")", h, byid);
    arm();
    byid = FindResourceW(self, MAKEINTRESOURCEW(7), T300_W);
    found("FindResourceW(7, 300)", byid, NULL);
    arm();
    h = FindResourceW(self, L"#7", L"#300");
    found("FindResourceW(\"#7\", \"#300\")", h, byid);

    arm();
    h = FindResourceW(self, MAKEINTRESOURCEW(1), STRING_W);
    found("FindResourceW(1, RT_STRING)", h, NULL);
    arm();
    h = FindResourceW(self, MAKEINTRESOURCEW(200), RCDATA_W);
    found("FindResourceW(200, RT_RCDATA) (two languages)", h, NULL);
    arm();
    h = FindResourceW(self, MAKEINTRESOURCEW(201), RCDATA_W);
    found("FindResourceW(201, RT_RCDATA) (neutral)", h, NULL);

    arm();
    h = FindResourceW(self, L"#abc", RCDATA_W);
    found("FindResourceW(\"#abc\", RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceW(self, L"", RCDATA_W);
    found("FindResourceW(\"\", RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceW(self, MAKEINTRESOURCEW(999), RCDATA_W);
    found("FindResourceW(999, RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceW(self, L"NOSUCHNAME", RCDATA_W);
    found("FindResourceW(\"NOSUCHNAME\", RT_RCDATA)", h, NULL);
    arm();
    h = FindResourceW(self, MAKEINTRESOURCEW(101), L"NOSUCHTYPE");
    found("FindResourceW(101, \"NOSUCHTYPE\")", h, NULL);
    arm();
    h = FindResourceW(self, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(999));
    found("FindResourceW(101, 999)", h, NULL);
    arm();
    h = FindResourceW(k32, MAKEINTRESOURCEW(1), L"MYTYPE");
    found("FindResourceW(kernel32, 1, \"MYTYPE\")", h, NULL);
}

static void sec_findexa(void)
{
    HRSRC en, fr, h;

    arm();
    en = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), EN_US);
    found("FindResourceExA(RT_RCDATA, 200, 0x0409)", en, NULL);
    arm();
    fr = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), FRENCH);
    found("FindResourceExA(RT_RCDATA, 200, 0x040C)", fr, NULL);
    line("0x0409's and 0x040C's the same: %s", yesno(en == fr));
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), NEUTRAL);
    found("FindResourceExA(RT_RCDATA, 200, LANG_NEUTRAL) against 0x0409's", h, en);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), USER_DEFAULT);
    found("FindResourceExA(RT_RCDATA, 200, SUBLANG_DEFAULT) against 0x0409's", h, en);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), SYS_DEFAULT);
    found("FindResourceExA(RT_RCDATA, 200, SUBLANG_SYS_DEFAULT) against 0x0409's", h, en);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), EN_UK);
    found("FindResourceExA(RT_RCDATA, 200, 0x0809)", h, NULL);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), GERMAN);
    found("FindResourceExA(RT_RCDATA, 200, 0x0407)", h, NULL);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(201), EN_US);
    found("FindResourceExA(RT_RCDATA, 201, 0x0409) (neutral)", h, NULL);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(201), NEUTRAL);
    found("FindResourceExA(RT_RCDATA, 201, LANG_NEUTRAL) (neutral)", h, NULL);

    arm();
    en = FindResourceExA(self, "MYTYPE", "ITEM", EN_US);
    found("FindResourceExA(\"MYTYPE\", \"ITEM\", 0x0409)", en, NULL);
    arm();
    h = FindResourceExA(self, "mytype", "item", EN_US);
    found("FindResourceExA(\"mytype\", \"item\", 0x0409)", h, en);
    arm();
    h = FindResourceExA(self, "#300", "#7", EN_US);
    found("FindResourceExA(\"#300\", \"#7\", 0x0409)", h, NULL);

    arm();
    en = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(101), EN_US);
    found("FindResourceExA(RT_RCDATA, 101, 0x0409)", en, NULL);
    arm();
    h = FindResourceExA(NULL, RCDATA_A, MAKEINTRESOURCEA(101), EN_US);
    found("FindResourceExA(NULL module, RT_RCDATA, 101, 0x0409)", h, en);
    arm();
    h = FindResourceExA(self, MAKEINTRESOURCEA(101), RCDATA_A, EN_US);
    found("FindResourceExA(101, RT_RCDATA, 0x0409) (the name as the type)", h, NULL);
    arm();
    h = FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(999), EN_US);
    found("FindResourceExA(RT_RCDATA, 999, 0x0409)", h, NULL);
    arm();
    h = FindResourceExA(self, "NOSUCHTYPE", MAKEINTRESOURCEA(101), EN_US);
    found("FindResourceExA(\"NOSUCHTYPE\", 101, 0x0409)", h, NULL);
}

static void sec_findexw(void)
{
    HRSRC en, fr, h;

    arm();
    en = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), EN_US);
    found("FindResourceExW(RT_RCDATA, 200, 0x0409)", en, NULL);
    arm();
    fr = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), FRENCH);
    found("FindResourceExW(RT_RCDATA, 200, 0x040C)", fr, NULL);
    line("0x0409's and 0x040C's the same: %s", yesno(en == fr));
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), NEUTRAL);
    found("FindResourceExW(RT_RCDATA, 200, LANG_NEUTRAL) against 0x0409's", h, en);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), USER_DEFAULT);
    found("FindResourceExW(RT_RCDATA, 200, SUBLANG_DEFAULT) against 0x0409's", h, en);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), SYS_DEFAULT);
    found("FindResourceExW(RT_RCDATA, 200, SUBLANG_SYS_DEFAULT) against 0x0409's", h, en);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), EN_UK);
    found("FindResourceExW(RT_RCDATA, 200, 0x0809)", h, NULL);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(200), GERMAN);
    found("FindResourceExW(RT_RCDATA, 200, 0x0407)", h, NULL);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(201), EN_US);
    found("FindResourceExW(RT_RCDATA, 201, 0x0409) (neutral)", h, NULL);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(201), NEUTRAL);
    found("FindResourceExW(RT_RCDATA, 201, LANG_NEUTRAL) (neutral)", h, NULL);

    arm();
    en = FindResourceExW(self, L"MYTYPE", L"ITEM", EN_US);
    found("FindResourceExW(\"MYTYPE\", \"ITEM\", 0x0409)", en, NULL);
    arm();
    h = FindResourceExW(self, L"mytype", L"item", EN_US);
    found("FindResourceExW(\"mytype\", \"item\", 0x0409)", h, en);
    arm();
    h = FindResourceExW(self, L"#300", L"#7", EN_US);
    found("FindResourceExW(\"#300\", \"#7\", 0x0409)", h, NULL);

    arm();
    en = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(101), EN_US);
    found("FindResourceExW(RT_RCDATA, 101, 0x0409)", en, NULL);
    arm();
    h = FindResourceExW(NULL, RCDATA_W, MAKEINTRESOURCEW(101), EN_US);
    found("FindResourceExW(NULL module, RT_RCDATA, 101, 0x0409)", h, en);
    arm();
    h = FindResourceExW(self, MAKEINTRESOURCEW(101), RCDATA_W, EN_US);
    found("FindResourceExW(101, RT_RCDATA, 0x0409) (the name as the type)", h, NULL);
    arm();
    h = FindResourceExW(self, RCDATA_W, MAKEINTRESOURCEW(999), EN_US);
    found("FindResourceExW(RT_RCDATA, 999, 0x0409)", h, NULL);
    arm();
    h = FindResourceExW(self, L"NOSUCHTYPE", MAKEINTRESOURCEW(101), EN_US);
    found("FindResourceExW(\"NOSUCHTYPE\", 101, 0x0409)", h, NULL);
}

/* A found resource's data, through the module and through NULL:
 * SizeofResource, LoadResource, LockResource, and the bytes. */
static void data(const char *what, HRSRC h)
{
    DWORD n, n0;
    HGLOBAL g, g0;
    LPVOID p;
    const char *en, *eg, *ep, *en0, *eg0;

    if (h == NULL) {
        line("%s: not found err=%s", what, le());
        return;
    }
    arm();
    n = SizeofResource(self, h);
    en = le();
    arm();
    g = LoadResource(self, h);
    eg = le();
    arm();
    p = LockResource(g);
    ep = le();
    line("%s: SizeofResource=%lu err=%s LoadResource: non-NULL=%s err=%s LockResource: its argument=%s err=%s",
         what, n, en, yesno(g != NULL), eg, yesno(p == (LPVOID)g), ep);
    arm();
    n0 = SizeofResource(NULL, h);
    en0 = le();
    arm();
    g0 = LoadResource(NULL, h);
    eg0 = le();
    line("  through NULL: SizeofResource the same=%s err=%s LoadResource the same=%s err=%s",
         yesno(n0 == n), en0, yesno(g0 == g), eg0);
    if (p != NULL) {
        line("  inside the image: %s bytes: %s", yesno(inside(self, p, n)), bytes(p, n));
    }
}

static void sec_load(void)
{
    DWORD n;
    HGLOBAL g;
    LPVOID p;

    data("101 RT_RCDATA", FindResourceA(self, MAKEINTRESOURCEA(101), RCDATA_A));
    data("MIXEDNAME RT_RCDATA", FindResourceA(self, "MIXEDNAME", RCDATA_A));
    data("ITEM MYTYPE", FindResourceA(self, "ITEM", "MYTYPE"));
    data("7 300", FindResourceA(self, MAKEINTRESOURCEA(7), T300_A));
    data("200 RT_RCDATA 0x0409", FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), EN_US));
    data("200 RT_RCDATA 0x040C", FindResourceExA(self, RCDATA_A, MAKEINTRESOURCEA(200), FRENCH));
    data("200 RT_RCDATA (FindResourceA)", FindResourceA(self, MAKEINTRESOURCEA(200), RCDATA_A));
    data("201 RT_RCDATA", FindResourceA(self, MAKEINTRESOURCEA(201), RCDATA_A));
    data("1 RT_STRING", FindResourceA(self, MAKEINTRESOURCEA(1), STRING_A));
    data("7 RT_STRING", FindResourceA(self, MAKEINTRESOURCEA(7), STRING_A));

    arm();
    n = SizeofResource(self, NULL);
    line("SizeofResource(NULL) = %lu err=%s", n, le());
    arm();
    g = LoadResource(self, NULL);
    line("LoadResource(NULL): non-NULL=%s err=%s", yesno(g != NULL), le());
    arm();
    p = LockResource(NULL);
    line("LockResource(NULL): non-NULL=%s err=%s", yesno(p != NULL), le());
}

static void sec_free(void)
{
    HRSRC h;
    HGLOBAL g;
    BYTE copy[8];
    BOOL r;

    h = FindResourceA(self, MAKEINTRESOURCEA(101), RCDATA_A);
    g = LoadResource(self, h);
    if (g == NULL) {
        line("101 RT_RCDATA: not loaded err=%s", le());
        return;
    }
    memcpy(copy, LockResource(g), sizeof copy);
    arm();
    r = FreeResource(g);
    line("FreeResource(loaded) = %d err=%s", r, le());
    line("the data still there: %s", yesno(memcmp(copy, LockResource(g), sizeof copy) == 0));
    arm();
    r = FreeResource(g);
    line("FreeResource(loaded) again = %d err=%s", r, le());
    arm();
    r = FreeResource(NULL);
    line("FreeResource(NULL) = %d err=%s", r, le());
}

/* A LoadStringA call into `size` bytes of a buffer filled with '#': its
 * return, the last error, and what the buffer holds to its first NUL
 * (within the size, and within the buffer). */
static void string_a(HINSTANCE inst, const char *what, UINT id, int size)
{
    char buf[64];
    int r, i;
    const char *e;

    memset(buf, '#', sizeof buf);
    arm();
    r = LoadStringA(inst, id, buf, size);
    e = le();
    for (i = 0; i < (int)sizeof buf && buf[i] != '\0'; i++) {
    }
    line("LoadStringA(%s%u, %d) = %d err=%s text=\"%.*s\" NUL at: %d", what, id, size, r, e,
         i, buf, i < (int)sizeof buf ? i : -1);
}

/* The same, for LoadStringW: the buffer filled with U+0023. */
static void string_w(HINSTANCE inst, const char *what, UINT id, int size)
{
    WCHAR buf[64];
    int r, i;
    const char *e;

    for (i = 0; i < 64; i++) {
        buf[i] = '#';
    }
    arm();
    r = LoadStringW(inst, id, buf, size);
    e = le();
    for (i = 0; i < 64 && buf[i] != 0; i++) {
    }
    line("LoadStringW(%s%u, %d) = %d err=%s text=\"%s\" NUL at: %d", what, id, size, r, e,
         wsn(buf, i), i < 64 ? i : -1);
}

static void sec_stringa(void)
{
    string_a(self, "", 1, 64);
    string_a(self, "", 2, 64);
    string_a(self, "", 17, 64);
    string_a(self, "", 100, 64);
    string_a(self, "", 100, 8);
    string_a(self, "", 100, 1);
    string_a(self, "", 100, 0);
    string_a(self, "", 3, 64);
    string_a(self, "", 500, 64);
    string_a(NULL, "NULL instance, ", 1, 64);
}

static void sec_stringw(void)
{
    const WCHAR *at = NULL;
    int r;
    const char *e;

    string_w(self, "", 1, 64);
    string_w(self, "", 2, 64);
    string_w(self, "", 17, 64);
    string_w(self, "", 100, 64);
    string_w(self, "", 100, 8);
    string_w(self, "", 100, 1);
    string_w(self, "", 3, 64);
    string_w(self, "", 500, 64);
    string_w(NULL, "NULL instance, ", 1, 64);

    arm();
    r = LoadStringW(self, 100, (LPWSTR)&at, 0);
    e = le();
    line("LoadStringW(100, size 0) = %d err=%s pointer given: %s", r, e, yesno(at != NULL));
    if (at != NULL && r > 0) {
        line("  the string there: \"%s\"", wsn(at, r));
    }
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "finda", sec_finda, F2KT_ALWAYS },
    { "findw", sec_findw, F2KT_ALWAYS },
    { "findexa", sec_findexa, F2KT_ALWAYS },
    { "findexw", sec_findexw, F2KT_ALWAYS },
    { "load", sec_load, F2KT_ALWAYS },
    { "free", sec_free, F2KT_ALWAYS },
    { "stringa", sec_stringa, F2KT_ALWAYS },
    { "stringw", sec_stringw, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    self = GetModuleHandleA(NULL);
    k32 = GetModuleHandleA("kernel32.dll");
    return run_sections("resource", sections, argc, argv);
}
