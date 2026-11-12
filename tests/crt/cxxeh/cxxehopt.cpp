/*
 * cxxehopt - cxxeh's prolog section, in a translation unit of its own:
 * tests\build.bat compiles it with /O1, where cxxeh.cpp has no
 * optimisation. At /O1 (and /Os) Visual C++ writes the prologue of a
 * function with C++ unwind state (an object to destroy, or a try block)
 * as "mov eax, <handler>; call _EH_prolog", msvcrt's, in place of the
 * frame set-up it otherwise writes inline. So each such function here
 * runs in the frame _EH_prolog builds: EBP its base, the unwind state at
 * [ebp-4], the registration on fs:[0], and ECX (a __thiscall member's
 * this) kept across the call.
 *
 *   prolog    whether the program's own import table names msvcrt's
 *             _EH_prolog (what shows the frames below are its); an
 *             exception thrown past a local with a destructor, caught by
 *             the caller; a function's own try and catch, its catch block
 *             returning; a __thiscall member function with a local, which
 *             checks this, returning and throwing to its caller, and one
 *             catching in a try of its own, reading the object in its
 *             catch block; three frames, the middle one's handler not
 *             matching; throw; from a catch block with an object in its
 *             scope; and two frames returning with no exception through
 *             their epilogues, the exception registration list as it was
 *             before them
 *
 * The classes' members are defined outside the classes: /O1 inlines only
 * what is declared inline (/Ob1), so each stays a call.
 *
 * Build (tests\build.bat cxxeh), before cxxeh.cpp, which links its object:
 *   cl /nologo /c /O1 /GX /GR /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% cxxehopt.cpp
 */

#include "../common/f2kt.h"

/* --- the steps ----------------------------------------------------- */

/* What the section's functions and objects did, in order. */
static char steps[600];

static void steps_reset(void)
{
    steps[0] = 0;
}

static void step(const char *what)
{
    size_t n = strlen(steps);

    if (n + strlen(what) + 2 < sizeof steps) {
        if (n != 0) {
            steps[n++] = ' ';
        }
        strcpy(steps + n, what);
    }
}

static void step_name(const char *prefix, const char *name)
{
    char buf[64];

    sprintf(buf, "%s%s", prefix, name);
    step(buf);
}

static void step_int(const char *prefix, int value)
{
    char buf[64];

    sprintf(buf, "%s%d", prefix, value);
    step(buf);
}

static void show_steps(const char *label)
{
    line("%s: %s", label, steps[0] != 0 ? steps : "(nothing)");
}

/* Throw value, on the steps first. */
static void raise_int(int value)
{
    step_int("throw ", value);
    throw value;
}

/* --- the program's imports ----------------------------------------- */

/* Whether the program's import table names msvcrt.dll's _EH_prolog: the
   import directory of its own image (GetModuleHandle(NULL)), and the
   names in each msvcrt.dll descriptor's import name table, which the
   loader leaves as the linker wrote it. The table's RVA is the
   descriptor's OriginalFirstThunk, read as Characteristics, the name
   every SDK's winnt.h gives it as a DWORD. */
static int imports_eh_prolog(void)
{
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *d;
    DWORD *thunk;

    if (dir->VirtualAddress == 0) {
        return 0;
    }
    for (d = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress); d->Name != 0; d++) {
        if (_stricmp((const char *)(base + d->Name), "msvcrt.dll") != 0 || d->Characteristics == 0) {
            continue;
        }
        for (thunk = (DWORD *)(base + d->Characteristics); *thunk != 0; thunk++) {
            /* The top bit (IMAGE_ORDINAL_FLAG) marks an import by ordinal. */
            if ((*thunk & 0x80000000UL) == 0 &&
                strcmp((const char *)((IMAGE_IMPORT_BY_NAME *)(base + *thunk))->Name, "_EH_prolog") == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* The head of the thread's exception registration list, fs:[0]. */
static void *registration_head(void)
{
    void *head;

    __asm {
        mov eax, fs:[0]
        mov head, eax
    }
    return head;
}

/* --- the classes --------------------------------------------------- */

/* Its construction and destruction on the steps. */
class Guard {
public:
    Guard(const char *n);
    ~Guard();
    const char *name;
};

Guard::Guard(const char *n) : name(n)
{
    step_name("+", name);
}

Guard::~Guard()
{
    step_name("-", name);
}

/* Its members are __thiscall functions with unwind state: this comes in
   ECX, and they read it after their call to _EH_prolog. */
class Tally {
public:
    Tally(int start);
    int add(int amount, const Tally *expected);
    int add_caught(int amount, const Tally *expected);
    int total;
};

Tally::Tally(int start) : total(start)
{
}

/* Adds amount to the total, or throws it if it is negative; expected is
   the object the caller called it on. */
int Tally::add(int amount, const Tally *expected)
{
    Guard local("in add");

    step(this == expected ? "this right" : "this wrong");
    if (amount < 0) {
        raise_int(amount);
    }
    total += amount;
    return total;
}

/* add, in a try of its own whose catch block reads the object. */
int Tally::add_caught(int amount, const Tally *expected)
{
    Guard local("in add_caught");

    try {
        return add(amount, expected);
    } catch (int v) {
        step_int("add_caught caught ", v);
        step(this == expected ? "this right in the catch block" : "this wrong in the catch block");
        return total;
    }
    return -1;
}

/* --- the frames ---------------------------------------------------- */

/* A local, then a call that throws: the exception leaves through this
   frame, whose unwind destroys the local. */
static void unwinds(int value)
{
    Guard local("local");

    raise_int(value);
    step("unwinds went on");
}

/* A try and catch of the function's own, an object outside the try and
   one inside it: the catch block returns. */
static int own_try(int value)
{
    Guard before("before the try");

    try {
        Guard inside("in the try");

        raise_int(value);
        step("own_try went on");
    } catch (int v) {
        step_int("own_try caught ", v);
        return v * 10;
    }
    return 0;
}

/* Three frames: deep throws, middle's handler does not match, outer's
   does. */
static void deep(int value)
{
    Guard local("deep");

    raise_int(value);
}

static void middle(int value)
{
    Guard local("middle");

    try {
        deep(value);
    } catch (double) {
        step("middle caught a double");
    }
    step("middle went on");
}

static int outer(int value)
{
    Guard local("outer");

    try {
        middle(value);
    } catch (int v) {
        step_int("outer caught ", v);
        return v + 1;
    }
    return 0;
}

/* throw; from a catch block of this frame, an object in its scope. */
static void rethrows(int value)
{
    Guard local("rethrows");

    try {
        raise_int(value);
    } catch (int) {
        Guard handler("in the handler");

        step("rethrowing");
        throw;
    }
}

/* No exception: each frame unlinks its registration in its epilogue. */
static int quiet_inner(int value)
{
    Guard local("quiet inner");

    try {
        Guard inside("quiet try");

        step("no throw");
    } catch (...) {
        step("quiet_inner caught something");
    }
    return value + 1;
}

static int quiet(int value)
{
    Guard local("quiet");

    return quiet_inner(value) * 2;
}

/* --- prolog -------------------------------------------------------- */

void sec_prolog(void)
{
    Tally tally(10);
    void *head;

    line("imports _EH_prolog: %s", yesno(imports_eh_prolog()));

    steps_reset();
    try {
        unwinds(1);
    } catch (int v) {
        step_int("caught ", v);
    }
    show_steps("a local, then a call that throws 1");

    steps_reset();
    step_int("returned ", own_try(2));
    show_steps("a try and catch of the function's own, throw 2");

    steps_reset();
    try {
        step_int("returned ", tally.add(5, &tally));
    } catch (int v) {
        step_int("caught ", v);
    }
    show_steps("Tally::add(5) on a Tally of 10");

    steps_reset();
    try {
        step_int("returned ", tally.add(-3, &tally));
    } catch (int v) {
        step_int("caught ", v);
    }
    show_steps("Tally::add(-3), which throws it");
    line("  the total: %d", tally.total);

    steps_reset();
    step_int("returned ", tally.add_caught(-4, &tally));
    show_steps("Tally::add_caught(-4), add throwing it into add_caught's catch block");

    steps_reset();
    step_int("returned ", outer(7));
    show_steps("three frames: deep throws 7, middle's catch (double) passes it, outer's catch (int) takes it");

    steps_reset();
    try {
        rethrows(8);
    } catch (int v) {
        step_int("caught ", v);
    }
    show_steps("throw; from a catch block, an object in its scope");

    steps_reset();
    head = registration_head();
    step_int("returned ", quiet(9));
    show_steps("two frames returning with no exception");
    line("  the registration list as before: %s", yesno(registration_head() == head));
}
