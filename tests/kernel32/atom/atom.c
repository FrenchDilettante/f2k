/*
 * atom - kernel32's global atoms: GlobalAddAtom, GlobalFindAtom,
 * GlobalGetAtomName and GlobalDeleteAtom, over the window station's
 * global atom table.
 *
 * The table is shared with every other program on the desktop, so every
 * name the fixture adds starts with "F2KAtomFixture", and each section
 * removes its names (every reference to them) at its start and its end.
 * A string atom's value is the table's choice: it prints only as a
 * relation (in 0xC000-0xFFFF, the same atom as another call's). An
 * integer atom's value is its number, and prints.
 *
 * The A calls run beside their W twins on the same names (the W lines
 * carry the W names, the A lines "(A)").
 *
 * Sections (run all with no argument, or one by name):
 *
 *   add       GlobalAddAtomW of a new name: a string atom; the same name
 *             again, in another case and through GlobalAddAtomA: the same
 *             atom; GlobalFindAtomW/A in either case; GlobalGetAtomNameW/A:
 *             the name as first added; a name outside ASCII and its
 *             other case
 *   refcount  a name added three times: GlobalDeleteAtom's answers, the
 *             name still found after one and two deletions and gone after
 *             the third; a fourth deletion; GlobalGetAtomNameW/A and
 *             GlobalFindAtomW/A after it
 *   integer   "#123", "#00123" and MAKEINTATOM(123) through GlobalAddAtomW/A
 *             and GlobalFindAtomW/A; GlobalGetAtomNameW/A of 123 and of
 *             0xBFFF; "#0", MAKEINTATOM(0), "#49151", "#49152", "#65535",
 *             and names that only look like numbers ("#12a", "#", "#-1",
 *             "# 12"); GlobalDeleteAtom of an integer atom, twice
 *   length    names of 255 and 256 characters through GlobalAddAtomW/A
 *             and GlobalFindAtomW/A; GlobalGetAtomNameW/A with buffers of
 *             256, 255, 10, 1 and 0 characters
 *   errors    a name never added; the empty name; a NULL name;
 *             GlobalDeleteAtom of 0 and of a string atom no longer in the
 *             table; GlobalGetAtomNameW/A of 0
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat atom):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% atom.c
 */

#include "../common/f2kt.h"

#define NAME_ONE "F2KAtomFixtureOne"
#define NAME_ONE_UPPER "F2KATOMFIXTUREONE"
#define NAME_ONE_LOWER "f2katomfixtureone"
#define NAME_COUNT "F2KAtomFixtureCount"
#define NAME_NEVER "F2KAtomFixtureNever"
#define NAME_GONE "F2KAtomFixtureGone"

/* The fixture's names, wide, and every one its sections may add. */
static const WCHAR name_one_w[] = L"F2KAtomFixtureOne";
static const WCHAR name_one_upper_w[] = L"F2KATOMFIXTUREONE";
static const WCHAR name_one_lower_w[] = L"f2katomfixtureone";
static const WCHAR name_count_w[] = L"F2KAtomFixtureCount";
static const WCHAR name_never_w[] = L"F2KAtomFixtureNever";
static const WCHAR name_gone_w[] = L"F2KAtomFixtureGone";
/* "F2KAtomFixture" and e acute, then E acute. */
static const WCHAR name_accent_w[] = { 'F', '2', 'K', 'A', 't', 'o', 'm', 'F', 'i', 'x', 't', 'u', 'r', 'e',
                                       0x00E9, 0 };
static const WCHAR name_accent_upper_w[] = { 'F', '2', 'K', 'A', 't', 'o', 'm', 'F', 'i', 'x', 't', 'u', 'r',
                                             'e', 0x00C9, 0 };

/* Names that look like integer atoms but are not: string atoms, if the
 * table takes them. Kept in sync with integer's. */
static const char *const not_numbers[] = { "#12a", "#", "#-1", "# 12", NULL };

/* --- helpers ------------------------------------------------------- */

/* A long name: "F2KAtomFixtureLong" padded with 'x' to `length`
 * characters. */
static const char *long_name(int length)
{
    static char name[300];

    memset(name, 'x', length);
    memcpy(name, "F2KAtomFixtureLong", 18);
    name[length] = 0;
    return name;
}

static const WCHAR *long_name_w(int length)
{
    static WCHAR name[300];
    const char *a = long_name(length);
    int i;

    for (i = 0; i <= length; i++) {
        name[i] = (WCHAR)(unsigned char)a[i];
    }
    return name;
}

/* Remove every reference to `name` the table holds. */
static void purge_w(const WCHAR *name)
{
    ATOM a;
    int n = 0;

    while ((a = GlobalFindAtomW(name)) != 0 && a >= 0xC000 && n++ < 1000) {
        GlobalDeleteAtom(a);
    }
}

static void purge_all(void)
{
    WCHAR wide[16];
    int i, j;

    purge_w(name_one_w);
    purge_w(name_count_w);
    purge_w(name_never_w);
    purge_w(name_gone_w);
    purge_w(name_accent_w);
    purge_w(name_accent_upper_w);
    purge_w(long_name_w(255));
    purge_w(long_name_w(256));
    purge_w(L"");
    for (i = 0; not_numbers[i] != NULL; i++) {
        for (j = 0; not_numbers[i][j] != 0; j++) {
            wide[j] = (WCHAR)not_numbers[i][j];
        }
        wide[j] = 0;
        purge_w(wide);
    }
}

/* A string atom's value as printed: whether it is one. */
static const char *string_atom(ATOM a)
{
    return a >= 0xC000 ? "a string atom" : (a == 0 ? "0" : "an integer atom");
}

/* --- add ----------------------------------------------------------- */

static void sec_add(void)
{
    ATOM first, a;
    WCHAR wbuf[64];
    char abuf[64];
    UINT n;
    const char *e;

    purge_all();
    arm();
    first = GlobalAddAtomW(name_one_w);
    e = le();
    line("GlobalAddAtomW(%s): %s err=%s", NAME_ONE, string_atom(first), e);
    if (first == 0) {
        return;
    }
    arm();
    a = GlobalAddAtomW(name_one_w);
    e = le();
    line("GlobalAddAtomW(%s), again: the same atom %s err=%s", NAME_ONE, yesno(a == first), e);
    arm();
    a = GlobalAddAtomW(name_one_upper_w);
    e = le();
    line("GlobalAddAtomW(%s): the same atom %s err=%s", NAME_ONE_UPPER, yesno(a == first), e);
    arm();
    a = GlobalAddAtomA(NAME_ONE_LOWER);
    e = le();
    line("GlobalAddAtomA(%s): the same atom %s err=%s", NAME_ONE_LOWER, yesno(a == first), e);

    arm();
    a = GlobalFindAtomW(name_one_w);
    e = le();
    line("GlobalFindAtomW(%s): the same atom %s err=%s", NAME_ONE, yesno(a == first), e);
    arm();
    a = GlobalFindAtomW(name_one_lower_w);
    e = le();
    line("GlobalFindAtomW(%s): the same atom %s err=%s", NAME_ONE_LOWER, yesno(a == first), e);
    arm();
    a = GlobalFindAtomA(NAME_ONE);
    e = le();
    line("  (A) GlobalFindAtomA(%s): the same atom %s err=%s", NAME_ONE, yesno(a == first), e);
    arm();
    a = GlobalFindAtomA(NAME_ONE_UPPER);
    e = le();
    line("  (A) GlobalFindAtomA(%s): the same atom %s err=%s", NAME_ONE_UPPER, yesno(a == first), e);

    memset(wbuf, 0, sizeof wbuf);
    arm();
    n = GlobalGetAtomNameW(first, wbuf, 64);
    e = le();
    line("GlobalGetAtomNameW(the atom, 64): ret=%u [%s] err=%s", n, ws(wbuf), e);
    memset(abuf, 0, sizeof abuf);
    arm();
    n = GlobalGetAtomNameA(first, abuf, 64);
    e = le();
    line("  (A) GlobalGetAtomNameA(the atom, 64): ret=%u [%s] err=%s", n, abuf, e);

    /* Four references: four deletions. */
    for (n = 0; n < 4; n++) {
        arm();
        a = GlobalDeleteAtom(first);
        e = le();
        line("GlobalDeleteAtom(the atom), reference %u of 4: ret=%s err=%s", n + 1,
             a == 0 ? "0" : (a == first ? "the atom" : "another value"), e);
    }
    arm();
    a = GlobalFindAtomW(name_one_w);
    e = le();
    line("GlobalFindAtomW(%s), after: ret=%s err=%s", NAME_ONE, a == 0 ? "0" : "found", e);

    /* Outside ASCII: e acute and E acute. */
    arm();
    first = GlobalAddAtomW(name_accent_w);
    e = le();
    line("GlobalAddAtomW(F2KAtomFixture<U+00E9>): %s err=%s", string_atom(first), e);
    arm();
    a = GlobalFindAtomW(name_accent_upper_w);
    e = le();
    line("GlobalFindAtomW(F2KAtomFixture<U+00C9>): the same atom %s err=%s", yesno(a != 0 && a == first), e);
    arm();
    a = GlobalFindAtomA("F2KAtomFixture\xC9");
    e = le();
    line("  (A) GlobalFindAtomA(F2KAtomFixture<C9>): the same atom %s err=%s", yesno(a != 0 && a == first), e);
    memset(abuf, 0, sizeof abuf);
    arm();
    n = GlobalGetAtomNameA(first, abuf, 64);
    e = le();
    line("  (A) GlobalGetAtomNameA(the atom, 64): ret=%u [%s] err=%s", n, abuf, e);
    purge_all();
}

/* --- refcount ------------------------------------------------------ */

static void sec_refcount(void)
{
    ATOM atom, a;
    WCHAR wbuf[64];
    char abuf[64];
    UINT n;
    int i;
    const char *e;

    purge_all();
    atom = GlobalAddAtomW(name_count_w);
    line("GlobalAddAtomW(%s): %s", NAME_COUNT, string_atom(atom));
    if (atom == 0) {
        return;
    }
    a = GlobalAddAtomW(name_count_w);
    line("GlobalAddAtomW(%s), a second time: the same atom %s", NAME_COUNT, yesno(a == atom));
    a = GlobalAddAtomA(NAME_COUNT);
    line("GlobalAddAtomA(%s), a third time: the same atom %s", NAME_COUNT, yesno(a == atom));

    for (i = 1; i <= 4; i++) {
        arm();
        a = GlobalDeleteAtom(atom);
        e = le();
        line("GlobalDeleteAtom, deletion %d: ret=%s err=%s", i, a == 0 ? "0" : (a == atom ? "the atom" : "another value"),
             e);
        arm();
        a = GlobalFindAtomW(name_count_w);
        e = le();
        line("  GlobalFindAtomW(%s): %s err=%s", NAME_COUNT, a == 0 ? "0" : (a == atom ? "the atom" : "another atom"),
             e);
        arm();
        a = GlobalFindAtomA(NAME_COUNT);
        e = le();
        line("  (A) GlobalFindAtomA(%s): %s err=%s", NAME_COUNT,
             a == 0 ? "0" : (a == atom ? "the atom" : "another atom"), e);
    }
    memset(wbuf, 0, sizeof wbuf);
    arm();
    n = GlobalGetAtomNameW(atom, wbuf, 64);
    e = le();
    line("GlobalGetAtomNameW(the deleted atom, 64): ret=%u err=%s", n, e);
    memset(abuf, 0, sizeof abuf);
    arm();
    n = GlobalGetAtomNameA(atom, abuf, 64);
    e = le();
    line("  (A) GlobalGetAtomNameA(the deleted atom, 64): ret=%u err=%s", n, e);
    purge_all();
}

/* --- integer ------------------------------------------------------- */

static void add_both(const char *label, const WCHAR *wname, const char *aname)
{
    ATOM a;
    const char *e;

    arm();
    a = GlobalAddAtomW(wname);
    e = le();
    if (a < 0xC000) {
        line("GlobalAddAtomW(%s): ret=%u err=%s", label, (unsigned)a, e);
    } else {
        line("GlobalAddAtomW(%s): %s err=%s", label, string_atom(a), e);
    }
    arm();
    a = GlobalAddAtomA(aname);
    e = le();
    if (a < 0xC000) {
        line("  (A) GlobalAddAtomA(%s): ret=%u err=%s", label, (unsigned)a, e);
    } else {
        line("  (A) GlobalAddAtomA(%s): %s err=%s", label, string_atom(a), e);
    }
}

static void find_both(const char *label, const WCHAR *wname, const char *aname)
{
    ATOM a;
    const char *e;

    arm();
    a = GlobalFindAtomW(wname);
    e = le();
    if (a < 0xC000) {
        line("GlobalFindAtomW(%s): ret=%u err=%s", label, (unsigned)a, e);
    } else {
        line("GlobalFindAtomW(%s): %s err=%s", label, string_atom(a), e);
    }
    arm();
    a = GlobalFindAtomA(aname);
    e = le();
    if (a < 0xC000) {
        line("  (A) GlobalFindAtomA(%s): ret=%u err=%s", label, (unsigned)a, e);
    } else {
        line("  (A) GlobalFindAtomA(%s): %s err=%s", label, string_atom(a), e);
    }
}

static void name_both(ATOM atom, int size)
{
    WCHAR wbuf[64];
    char abuf[64];
    UINT n;
    const char *e;

    memset(wbuf, 0, sizeof wbuf);
    arm();
    n = GlobalGetAtomNameW(atom, wbuf, size);
    e = le();
    line("GlobalGetAtomNameW(%u, %d): ret=%u [%s] err=%s", (unsigned)atom, size, n, ws(wbuf), e);
    memset(abuf, 0, sizeof abuf);
    arm();
    n = GlobalGetAtomNameA(atom, abuf, size);
    e = le();
    line("  (A) GlobalGetAtomNameA(%u, %d): ret=%u [%s] err=%s", (unsigned)atom, size, n, abuf, e);
}

static void sec_integer(void)
{
    WCHAR wide[16];
    ATOM a;
    int i, j;
    const char *e;

    purge_all();
    add_both("\"#123\"", L"#123", "#123");
    add_both("\"#00123\"", L"#00123", "#00123");
    add_both("MAKEINTATOM(123)", (LPCWSTR)MAKEINTATOM(123), (LPCSTR)MAKEINTATOM(123));
    find_both("\"#123\"", L"#123", "#123");
    find_both("MAKEINTATOM(456), never added", (LPCWSTR)MAKEINTATOM(456), (LPCSTR)MAKEINTATOM(456));
    find_both("\"#456\", never added", L"#456", "#456");
    name_both(123, 64);
    name_both(0xBFFF, 64);
    name_both(123, 3);

    add_both("\"#0\"", L"#0", "#0");
    add_both("MAKEINTATOM(0)", (LPCWSTR)MAKEINTATOM(0), (LPCSTR)MAKEINTATOM(0));
    add_both("\"#49151\"", L"#49151", "#49151");
    add_both("\"#49152\"", L"#49152", "#49152");
    add_both("\"#65535\"", L"#65535", "#65535");
    add_both("\"#65536\"", L"#65536", "#65536");
    for (i = 0; not_numbers[i] != NULL; i++) {
        char label[32];

        for (j = 0; not_numbers[i][j] != 0; j++) {
            wide[j] = (WCHAR)not_numbers[i][j];
        }
        wide[j] = 0;
        sprintf(label, "\"%s\"", not_numbers[i]);
        add_both(label, wide, not_numbers[i]);
    }

    arm();
    a = GlobalDeleteAtom(123);
    e = le();
    line("GlobalDeleteAtom(123): ret=%u err=%s", (unsigned)a, e);
    arm();
    a = GlobalDeleteAtom(123);
    e = le();
    line("GlobalDeleteAtom(123), again: ret=%u err=%s", (unsigned)a, e);
    find_both("\"#123\", after the deletions", L"#123", "#123");
    purge_all();
}

/* --- length -------------------------------------------------------- */

static void sec_length(void)
{
    static const int sizes[] = { 256, 255, 10, 1, 0 };
    WCHAR wbuf[300];
    char abuf[300];
    ATOM w255, a255, a;
    UINT n;
    int i;
    const char *e;

    purge_all();
    arm();
    w255 = GlobalAddAtomW(long_name_w(255));
    e = le();
    line("GlobalAddAtomW(a 255-character name): %s err=%s", string_atom(w255), e);
    arm();
    a255 = GlobalAddAtomA(long_name(255));
    e = le();
    line("  (A) GlobalAddAtomA(a 255-character name): %s, the same atom %s err=%s", string_atom(a255),
         yesno(a255 != 0 && a255 == w255), e);
    arm();
    a = GlobalFindAtomW(long_name_w(255));
    e = le();
    line("GlobalFindAtomW(a 255-character name): the same atom %s err=%s", yesno(a != 0 && a == w255), e);
    arm();
    a = GlobalFindAtomA(long_name(255));
    e = le();
    line("  (A) GlobalFindAtomA(a 255-character name): the same atom %s err=%s", yesno(a != 0 && a == w255), e);

    for (i = 0; i < (int)(sizeof sizes / sizeof sizes[0]); i++) {
        for (n = 0; n < 300; n++) {
            wbuf[n] = 0xBEEF;
        }
        arm();
        n = GlobalGetAtomNameW(w255, wbuf, sizes[i]);
        e = le();
        line("GlobalGetAtomNameW(the atom, %d): ret=%u, the name's first %u characters %s, terminated %s err=%s",
             sizes[i], n, n, yesno(n <= 255 && memcmp(wbuf, long_name_w(255), n * sizeof(WCHAR)) == 0),
             yesno(n < 300 && wbuf[n] == 0), e);
        memset(abuf, 0x7E, sizeof abuf);
        arm();
        n = GlobalGetAtomNameA(w255, abuf, sizes[i]);
        e = le();
        line("  (A) GlobalGetAtomNameA(the atom, %d): ret=%u, the name's first %u characters %s, terminated %s err=%s",
             sizes[i], n, n, yesno(n <= 255 && memcmp(abuf, long_name(255), n) == 0), yesno(n < 300 && abuf[n] == 0),
             e);
    }
    if (w255 != 0) {
        GlobalDeleteAtom(w255);
    }
    if (a255 != 0) {
        GlobalDeleteAtom(a255);
    }

    arm();
    a = GlobalAddAtomW(long_name_w(256));
    e = le();
    line("GlobalAddAtomW(a 256-character name): %s err=%s", string_atom(a), e);
    arm();
    a = GlobalAddAtomA(long_name(256));
    e = le();
    line("  (A) GlobalAddAtomA(a 256-character name): %s err=%s", string_atom(a), e);
    arm();
    a = GlobalFindAtomW(long_name_w(256));
    e = le();
    line("GlobalFindAtomW(a 256-character name): %s err=%s", string_atom(a), e);
    arm();
    a = GlobalFindAtomA(long_name(256));
    e = le();
    line("  (A) GlobalFindAtomA(a 256-character name): %s err=%s", string_atom(a), e);
    purge_all();
}

/* --- errors -------------------------------------------------------- */

static void sec_errors(void)
{
    ATOM gone, a;
    WCHAR wbuf[64];
    char abuf[64];
    UINT n;
    const char *e;

    purge_all();
    find_both(NAME_NEVER ", never added", name_never_w, NAME_NEVER);
    add_both("\"\"", L"", "");
    find_both("\"\"", L"", "");
    add_both("NULL", NULL, NULL);
    find_both("NULL", NULL, NULL);

    arm();
    a = GlobalDeleteAtom(0);
    e = le();
    line("GlobalDeleteAtom(0): ret=%u err=%s", (unsigned)a, e);

    gone = GlobalAddAtomW(name_gone_w);
    line("GlobalAddAtomW(%s): %s", NAME_GONE, string_atom(gone));
    if (gone != 0) {
        GlobalDeleteAtom(gone);
        arm();
        a = GlobalDeleteAtom(gone);
        e = le();
        line("GlobalDeleteAtom of it once it is gone: ret=%s err=%s",
             a == 0 ? "0" : (a == gone ? "the atom" : "another value"), e);
    }

    memset(wbuf, 0, sizeof wbuf);
    arm();
    n = GlobalGetAtomNameW(0, wbuf, 64);
    e = le();
    line("GlobalGetAtomNameW(0, 64): ret=%u err=%s", n, e);
    memset(abuf, 0, sizeof abuf);
    arm();
    n = GlobalGetAtomNameA(0, abuf, 64);
    e = le();
    line("  (A) GlobalGetAtomNameA(0, 64): ret=%u err=%s", n, e);
    purge_all();
}

static const section_t sections[] = {
    { "add", sec_add, F2KT_ALWAYS },
    { "refcount", sec_refcount, F2KT_ALWAYS },
    { "integer", sec_integer, F2KT_ALWAYS },
    { "length", sec_length, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("atom", sections, argc, argv);
}
