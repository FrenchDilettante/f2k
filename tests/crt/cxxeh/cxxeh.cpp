/*
 * cxxeh - C++ exception handling through msvcrt.dll under /MD: the
 * compiler's frames run on msvcrt's __CxxFrameHandler, a throw is
 * _CxxThrowException, and typeid, type_info, terminate, _purecall and
 * abort are msvcrt's own.
 *
 * The corpus's one C++ fixture, built with /GX (C++ exception handling)
 * and /GR (run-time type information: typeid of a polymorphic object
 * needs it). It includes common/f2kt.h as the C fixtures do.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   catch     throw and catch by value (int, double, a class: the copies
 *             the catch makes), by reference and const reference (no
 *             copy), by pointer (the same pointer, through void * too), a
 *             string literal; handlers that do not match (long, unsigned,
 *             char for an int) before catch (...); the thrown objects all
 *             destroyed after
 *   derived   a derived class caught by its base by reference (its
 *             virtual function the derived one's) and by value (sliced);
 *             a pointer to it caught as a pointer to the base; handlers
 *             tried in order (an unrelated class, the derived, the base);
 *             two levels of derivation; a base reached twice (ambiguous)
 *             and a private base, neither of which a base handler takes
 *   rethrow   throw; from a catch by reference (the change it made seen
 *             outside), from a catch by value (the copy's change not
 *             seen), from catch (...) (the type kept), from a function's
 *             catch block to its caller; a new exception thrown from a
 *             catch block (the first one destroyed)
 *   nested    an inner try whose handler does not match, the outer's
 *             does; a try and catch inside a catch block, the outer
 *             exception still current after; an exception thrown from an
 *             inner catch block to the outer try; three levels; a
 *             function with its own try called from a catch block
 *   unwind    the trail of constructions and destructions: locals across
 *             three frames; a temporary bound to an argument; a member
 *             whose constructor throws (the members before it destroyed,
 *             the object's own destructor not run) on the stack and
 *             through a class's operator new (its operator delete called
 *             or not); an array whose third element's constructor throws,
 *             on the stack and from new[]; an array unwound whole; an
 *             object in a catch block's scope
 *   seh       a C++ exception through a function with __try/__except:
 *             what its filter sees (the code 0xE06D7363, the flags, the
 *             parameter count and the first parameter, the magic number)
 *             when it answers EXCEPTION_CONTINUE_SEARCH (the C++ handler
 *             then catching it) and EXCEPTION_EXECUTE_HANDLER (whether the
 *             thrown object is ever destroyed); through __finally
 *             (AbnormalTermination); RaiseException and an access
 *             violation reaching catch (...) or not
 *   typeid    typeid of a polymorphic object through a base pointer:
 *             type_info::name, raw_name, == and != against typeid of the
 *             classes, before both ways; typeid of the static types
 *             (int, a pointer, the base pointer itself); typeid of
 *             *(Base *)0: the bad_typeid exception and its what()
 *   purecall  a child (this program, run with "kid purecall") whose base
 *             class's constructor calls a pure virtual function, reaching
 *             _purecall (MSVC 6 has no _set_purecall_handler): what the
 *             child writes to its standard output and error, and its
 *             exit code
 *   terminate children calling terminate() with a handler set_terminate
 *             installed (which ends the child with exit code 7), with
 *             none, with a handler that returns, and throwing an
 *             exception nothing catches with a handler installed: what
 *             they write and their exit codes
 *   abort     a child calling abort(): what it writes and its exit code
 *
 * The children are this program, started by CreateProcessA with "kid"
 * and their mode (not a section: main hands them over before the section
 * table), their standard output and error one pipe the section reads
 * once the child has ended (each waited for 5 seconds at most, then
 * terminated). They set SEM_NOGPFAULTERRORBOX first, so nothing waits
 * for a person.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat cxxeh):
 *   cl /nologo /GX /GR /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% cxxeh.cpp
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <eh.h>
#include <typeinfo.h>

/* --- the trail ----------------------------------------------------- */

/* What the constructors and destructors did, in order. */
static char trail[900];

static void trail_reset(void)
{
    trail[0] = 0;
}

static void note(const char *what)
{
    size_t n = strlen(trail);

    if (n + strlen(what) + 2 < sizeof trail) {
        if (n != 0) {
            trail[n++] = ' ';
        }
        strcpy(trail + n, what);
    }
}

static void note_name(const char *prefix, const char *name)
{
    char buf[64];

    sprintf(buf, "%s%s", prefix, name);
    note(buf);
}

static void note_int(const char *prefix, int value)
{
    char buf[64];

    sprintf(buf, "%s%d", prefix, value);
    note(buf);
}

static void show_trail(const char *label)
{
    line("%s: %s", label, trail[0] != 0 ? trail : "(nothing)");
}

/* --- the classes --------------------------------------------------- */

/* An exception object that counts itself. */
class Thing {
public:
    Thing(int i) : id(i) { live++; }
    Thing(const Thing &other) : id(other.id) { live++; copies++; }
    ~Thing() { live--; }
    int id;
    static int live;
    static int copies;
};

int Thing::live = 0;
int Thing::copies = 0;

static void thing_reset(void)
{
    Thing::live = 0;
    Thing::copies = 0;
}

class Base {
public:
    Base() {}
    virtual ~Base() {}
    virtual const char *name() const { return "Base"; }
};

class Derived : public Base {
public:
    virtual const char *name() const { return "Derived"; }
};

class More : public Derived {
public:
    virtual const char *name() const { return "More"; }
};

class Other {
public:
    int unused;
};

class LeftBase : public Base {
};

class RightBase : public Base {
};

/* Base twice: a handler for Base cannot take it. */
class Diamond : public LeftBase, public RightBase {
};

class Hidden : private Base {
};

/* Constructions and destructions on the trail. */
class Tracked {
public:
    Tracked(const char *n) : name(n) { note_name("+", name); }
    Tracked(const Tracked &other) : name(other.name) { note_name("+copy ", name); }
    ~Tracked() { note_name("-", name); }
    const char *name;
};

class Thrower {
public:
    Thrower(const char *n) { note_name("throwing in ", n); throw 1; }
    ~Thrower() { note("-thrower"); }
};

/* A member's constructor throws: a and b are built, c throws, d never is. */
class Holder {
public:
    Holder() : a("a"), b("b"), c("c"), d("d") { note("Holder's body"); }
    ~Holder() { note("~Holder"); }
    static void *operator new(size_t size)
    {
        note("Holder's operator new");
        return malloc(size);
    }
    static void operator delete(void *p)
    {
        note("Holder's operator delete");
        free(p);
    }
    Tracked a;
    Tracked b;
    Thrower c;
    Tracked d;
};

/* An array element: the one numbered fail_at throws. */
class Counted {
public:
    Counted()
    {
        index = made++;
        if (index == fail_at) {
            note_int("throwing in element ", index);
            throw index;
        }
        note_int("+", index);
    }
    ~Counted() { note_int("-", index); }
    int index;
    static int made;
    static int fail_at;
};

int Counted::made = 0;
int Counted::fail_at = -1;

/* --- catch --------------------------------------------------------- */

static Thing static_thing(9);

static void sec_catch(void)
{
    thing_reset();
    try {
        throw 42;
    } catch (int v) {
        line("throw 42, catch (int v): caught, v=%d", v);
    }
    try {
        throw 2.5;
    } catch (double d) {
        line("throw 2.5, catch (double d): caught, d is 2.5 %s", yesno(d == 2.5));
    }
    try {
        throw "a string literal";
    } catch (const char *s) {
        line("throw \"a string literal\", catch (const char *s): caught, s=[%s]", s);
    }

    thing_reset();
    try {
        throw Thing(1);
    } catch (Thing t) {
        line("throw Thing(1), catch (Thing t): caught, id %d, copies made by then %d, live %d", t.id, Thing::copies,
             Thing::live);
    }
    line("  after the handler: live %d", Thing::live);
    thing_reset();
    try {
        throw Thing(2);
    } catch (Thing &t) {
        line("throw Thing(2), catch (Thing &t): caught, id %d, copies made by then %d, live %d", t.id, Thing::copies,
             Thing::live);
        t.id = 3;
    }
    line("  after the handler: live %d", Thing::live);
    thing_reset();
    try {
        throw Thing(4);
    } catch (const Thing &t) {
        line("throw Thing(4), catch (const Thing &t): caught, id %d, copies made by then %d", t.id, Thing::copies);
    }
    line("  after the handler: live %d", Thing::live);

    try {
        throw &static_thing;
    } catch (Thing *p) {
        line("throw &static_thing, catch (Thing *p): caught, the same pointer %s", yesno(p == &static_thing));
    }
    try {
        throw &static_thing;
    } catch (void *p) {
        line("throw &static_thing, catch (void *p): caught, the same pointer %s", yesno(p == &static_thing));
    }

    try {
        throw 7;
    } catch (long) {
        line("throw 7: caught by catch (long)");
    } catch (unsigned int) {
        line("throw 7: caught by catch (unsigned int)");
    } catch (...) {
        line("throw 7, catch (long), catch (unsigned int), catch (...): caught by catch (...)");
    }
    try {
        throw 'c';
    } catch (int) {
        line("throw 'c': caught by catch (int)");
    } catch (char c) {
        line("throw 'c', catch (int), catch (char c): caught by catch (char), c=%c", c);
    }
    thing_reset();
    try {
        throw Thing(5);
    } catch (int) {
        line("throw Thing(5): caught by catch (int)");
    } catch (...) {
        line("throw Thing(5), catch (int), catch (...): caught by catch (...), live %d", Thing::live);
    }
    line("  after the handler: live %d", Thing::live);
}

/* --- derived ------------------------------------------------------- */

static void sec_derived(void)
{
    try {
        throw Derived();
    } catch (Base &b) {
        line("throw Derived(), catch (Base &b): caught, b.name() %s", b.name());
    }
    try {
        throw Derived();
    } catch (Base b) {
        line("throw Derived(), catch (Base b): caught, b.name() %s", b.name());
    }
    try {
        throw Derived();
    } catch (const Base &b) {
        line("throw Derived(), catch (const Base &b): caught, b.name() %s", b.name());
    }
    try {
        throw new Derived;
    } catch (Base *p) {
        line("throw new Derived, catch (Base *p): caught, p->name() %s", p->name());
        delete p;
    }
    try {
        throw Derived();
    } catch (Other &) {
        line("throw Derived(): caught by catch (Other &)");
    } catch (Derived &d) {
        line("throw Derived(), catch (Other &), catch (Derived &), catch (Base &): caught by catch (Derived &), %s",
             d.name());
    } catch (Base &) {
        line("throw Derived(): caught by catch (Base &)");
    }
    try {
        throw More();
    } catch (Derived &d) {
        line("throw More(), catch (Derived &d): caught, d.name() %s", d.name());
    }
    try {
        throw More();
    } catch (Base &b) {
        line("throw More(), catch (Base &b): caught, b.name() %s", b.name());
    }
    try {
        throw Diamond();
    } catch (Base &) {
        line("throw Diamond() (Base twice): caught by catch (Base &)");
    } catch (LeftBase &l) {
        line("throw Diamond() (Base twice), catch (Base &), catch (LeftBase &): caught by catch (LeftBase &), %s",
             l.name());
    } catch (...) {
        line("throw Diamond() (Base twice): caught by catch (...)");
    }
    try {
        throw Hidden();
    } catch (Base &) {
        line("throw Hidden() (a private Base): caught by catch (Base &)");
    } catch (...) {
        line("throw Hidden() (a private Base), catch (Base &), catch (...): caught by catch (...)");
    }
}

/* --- rethrow ------------------------------------------------------- */

static void rethrower(void)
{
    try {
        throw Thing(40);
    } catch (Thing &t) {
        t.id = 41;
        throw;
    }
}

static void sec_rethrow(void)
{
    int live_inside = -1;

    thing_reset();
    try {
        try {
            throw Thing(10);
        } catch (Thing &t) {
            t.id = 11;
            throw;
        }
    } catch (Thing &t) {
        line("throw; from catch (Thing &) after setting id 11: the outer handler sees id %d, copies %d", t.id,
             Thing::copies);
    }
    line("  after: live %d", Thing::live);

    thing_reset();
    try {
        try {
            throw Thing(30);
        } catch (Thing t) {
            t.id = 31;
            throw;
        }
    } catch (Thing &t) {
        line("throw; from catch (Thing) after setting the copy's id 31: the outer handler sees id %d", t.id);
    }
    line("  after: live %d", Thing::live);

    try {
        try {
            throw 2.5;
        } catch (...) {
            throw;
        }
    } catch (int) {
        line("throw; from catch (...) of 2.5: caught as int");
    } catch (double d) {
        line("throw; from catch (...) of 2.5: caught as double, d is 2.5 %s", yesno(d == 2.5));
    }

    thing_reset();
    try {
        rethrower();
    } catch (Thing &t) {
        line("throw; from a function's own catch block to its caller: id %d", t.id);
    }
    line("  after: live %d", Thing::live);

    thing_reset();
    try {
        try {
            throw Thing(20);
        } catch (Thing &) {
            throw Thing(21);
        }
    } catch (Thing &t) {
        live_inside = Thing::live;
        line("throw Thing(21) from catch (Thing &) of Thing(20): the outer handler sees id %d, live %d", t.id,
             live_inside);
    }
    line("  after: live %d", Thing::live);
}

/* --- nested -------------------------------------------------------- */

static int helper_with_try(void)
{
    try {
        throw 3;
    } catch (int v) {
        return v * 10;
    }
    return 0;
}

static void sec_nested(void)
{
    try {
        try {
            throw 1;
        } catch (char) {
            line("inner catch (char) of 1: caught");
        }
        line("after the inner try: reached");
    } catch (int v) {
        line("throw 1, inner catch (char), outer catch (int): the outer caught v=%d", v);
    }

    try {
        throw 1;
    } catch (int v) {
        try {
            throw 2.0;
        } catch (double d) {
            line("a try inside catch (int): the inner caught %g", d);
        }
        line("  back in the outer catch block: v=%d", v);
        try {
            throw;
        } catch (int again) {
            line("  throw; there rethrows the outer exception: %d", again);
        }
    }

    try {
        try {
            throw 1;
        } catch (int) {
            throw 'x';
        }
    } catch (char c) {
        line("throw 'x' from an inner catch (int): the outer catch (char) caught %c", c);
    }

    thing_reset();
    try {
        try {
            try {
                throw Thing(50);
            } catch (int) {
                line("level 3 catch (int): caught");
            }
        } catch (double) {
            line("level 2 catch (double): caught");
        }
    } catch (Thing &t) {
        line("three levels, Thing(50): the outermost catch (Thing &) caught id %d", t.id);
    }
    line("  after: live %d", Thing::live);

    try {
        throw 4;
    } catch (int v) {
        line("a function with its own try, called from catch (int) of %d: returned %d", v, helper_with_try());
    }
}

/* --- unwind -------------------------------------------------------- */

static void level3(void)
{
    Tracked c("c3");

    throw Tracked("thrown");
}

static void level2(void)
{
    Tracked b("b2");

    level3();
}

static void level1(void)
{
    Tracked a("a1");

    level2();
}

static void take(const Tracked &t, int fail)
{
    note_name("take sees ", t.name);
    if (fail) {
        throw 2;
    }
}

static void make_array(void)
{
    Counted array[4];

    note("array built");
}

static void sec_unwind(void)
{
    Holder *h;
    Counted *heap;

    trail_reset();
    try {
        level1();
    } catch (Tracked &t) {
        note_name("caught ", t.name);
    }
    show_trail("locals across three frames, a Tracked thrown");

    trail_reset();
    try {
        take(Tracked("temp"), 1);
    } catch (int) {
        note("caught");
    }
    show_trail("a temporary bound to an argument, the call throwing");

    trail_reset();
    try {
        Holder local;

        note("Holder built");
    } catch (int) {
        note("caught");
    }
    show_trail("a Holder on the stack, its member c throwing");

    trail_reset();
    h = NULL;
    try {
        h = new Holder;
        note("Holder built");
    } catch (int) {
        note("caught");
    }
    show_trail("new Holder, its member c throwing");
    line("  the pointer still NULL: %s", yesno(h == NULL));

    trail_reset();
    Counted::made = 0;
    Counted::fail_at = 2;
    try {
        make_array();
    } catch (int v) {
        note_int("caught ", v);
    }
    show_trail("Counted array[4] on the stack, element 2 throwing");

    trail_reset();
    Counted::made = 0;
    Counted::fail_at = 2;
    heap = NULL;
    try {
        heap = new Counted[4];
        note("array built");
    } catch (int v) {
        note_int("caught ", v);
    }
    show_trail("new Counted[4], element 2 throwing");
    line("  the pointer still NULL: %s", yesno(heap == NULL));

    trail_reset();
    Counted::made = 0;
    Counted::fail_at = -1;
    try {
        Counted whole[3];

        note("array built");
        throw 9;
    } catch (int v) {
        note_int("caught ", v);
    }
    show_trail("Counted whole[3] built, then throw 9");

    trail_reset();
    try {
        throw 5;
    } catch (int) {
        Tracked inside("in the handler");

        try {
            Tracked deeper("deeper");

            throw 6;
        } catch (int v) {
            note_int("caught ", v);
        }
    }
    show_trail("objects in a catch block's scope, another throw inside it");
}

/* --- seh ----------------------------------------------------------- */

static int seh_calls;
static DWORD seh_code;
static DWORD seh_flags;
static DWORD seh_params;
static DWORD seh_magic;
static int seh_abnormal;

static int seh_record(EXCEPTION_POINTERS *ep, int verdict)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;

    seh_calls++;
    seh_code = er->ExceptionCode;
    seh_flags = er->ExceptionFlags;
    seh_params = er->NumberParameters;
    seh_magic = er->NumberParameters > 0 ? (DWORD)er->ExceptionInformation[0] : 0;
    return verdict;
}

static void seh_reset(void)
{
    seh_calls = 0;
    seh_code = 0;
    seh_flags = 0;
    seh_params = 0;
    seh_magic = 0;
    seh_abnormal = -1;
}

static void show_seh(const char *label)
{
    line("  %s: called %d time(s); code 0x%08lX, flags %lu, %lu parameter(s), the first 0x%08lX", label, seh_calls,
         seh_code, seh_flags, seh_params, seh_magic);
}

static void throw_thing(int id)
{
    throw Thing(id);
}

/* No C++ object lives in the functions with __try: they may not mix. */
static int seh_passes(int id)
{
    __try {
        throw_thing(id);
    } __except (seh_record(GetExceptionInformation(), EXCEPTION_CONTINUE_SEARCH)) {
        return 1;
    }
    return 0;
}

static int seh_takes(int id)
{
    __try {
        throw_thing(id);
    } __except (seh_record(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        return 1;
    }
    return 0;
}

static void seh_finally(int id)
{
    __try {
        throw_thing(id);
    } __finally {
        seh_abnormal = AbnormalTermination();
    }
}

static void raise_custom(void)
{
    RaiseException(0xE0000001, 0, 0, NULL);
}

static void write_null(void)
{
    *(volatile int *)0 = 1;
}

static int catch_all(void (*fn)(void))
{
    try {
        fn();
    } catch (...) {
        return 1;
    }
    return 0;
}

static int catch_all_guarded(void (*fn)(void))
{
    __try {
        return catch_all(fn);
    } __except (seh_record(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        return 2;
    }
    return 0;
}

static const char *catch_all_verdict(int r)
{
    return r == 1 ? "caught by catch (...)" : (r == 2 ? "passed on to the outer __except" : "returned");
}

static void sec_seh(void)
{
    int r = -1;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    seh_reset();
    thing_reset();
    try {
        r = seh_passes(1);
        line("throw Thing(1) through __except (EXCEPTION_CONTINUE_SEARCH): returned %d", r);
    } catch (Thing &t) {
        line("throw Thing(1) through __except (EXCEPTION_CONTINUE_SEARCH): the C++ handler caught id %d", t.id);
    }
    show_seh("the filter");
    line("  after: live %d", Thing::live);

    seh_reset();
    thing_reset();
    try {
        r = seh_takes(2);
        line("throw Thing(2) into __except (EXCEPTION_EXECUTE_HANDLER): the __except block ran %s", yesno(r == 1));
    } catch (Thing &t) {
        line("throw Thing(2) into __except (EXCEPTION_EXECUTE_HANDLER): the C++ handler caught id %d", t.id);
    }
    show_seh("the filter");
    line("  after: live %d (the thrown object destroyed: %s)", Thing::live, yesno(Thing::live == 0));

    seh_reset();
    thing_reset();
    try {
        seh_finally(3);
        line("throw Thing(3) through __finally: returned");
    } catch (Thing &t) {
        line("throw Thing(3) through __finally: the C++ handler caught id %d", t.id);
    }
    line("  the __finally block ran %s, AbnormalTermination() %d", yesno(seh_abnormal != -1), seh_abnormal);
    line("  after: live %d", Thing::live);

    seh_reset();
    r = catch_all_guarded(raise_custom);
    line("RaiseException(0xE0000001) in a try with catch (...): %s", catch_all_verdict(r));
    if (r == 2) {
        show_seh("the outer filter");
    }
    seh_reset();
    r = catch_all_guarded(write_null);
    line("a write to NULL in a try with catch (...): %s", catch_all_verdict(r));
    if (r == 2) {
        show_seh("the outer filter");
    }
}

/* --- typeid -------------------------------------------------------- */

static void sec_typeid(void)
{
    Base *p = new Derived;
    Base *b = new Base;
    Base *none = NULL;
    int i = 0;

    const type_info &ti = typeid(*p);
    line("typeid(*p), p a Base * to a Derived: name() [%s], raw_name() [%s]", ti.name(), ti.raw_name());
    line("  == typeid(Derived) %d, == typeid(Base) %d, != typeid(Base) %d", ti == typeid(Derived), ti == typeid(Base),
         ti != typeid(Base));
    line("  the same object as typeid(Derived): %s", yesno(&ti == &typeid(Derived)));
    line("typeid(*b), b a Base * to a Base: name() [%s], == typeid(Base) %d", typeid(*b).name(),
         typeid(*b) == typeid(Base));
    line("typeid(Derived).before(typeid(Base)) %d, typeid(Base).before(typeid(Derived)) %d, "
         "typeid(Base).before(typeid(Base)) %d",
         typeid(Derived).before(typeid(Base)), typeid(Base).before(typeid(Derived)),
         typeid(Base).before(typeid(Base)));
    line("typeid(More).name() [%s], typeid(Other).name() [%s]", typeid(More).name(), typeid(Other).name());
    line("typeid(int).name() [%s], typeid(i).name() [%s], typeid(p).name() [%s], typeid(Derived *).name() [%s]",
         typeid(int).name(), typeid(i).name(), typeid(p).name(), typeid(Derived *).name());
    line("typeid(int) == typeid(i) %d, typeid(int) == typeid(long) %d", typeid(int) == typeid(i),
         typeid(int) == typeid(long));
    try {
        const type_info &bad = typeid(*none);

        line("typeid(*(Base *)0): returned [%s]", bad.name());
    } catch (bad_typeid &e) {
        line("typeid(*(Base *)0): bad_typeid caught, what() [%s]", e.what());
    } catch (...) {
        line("typeid(*(Base *)0): another exception caught by catch (...)");
    }
    delete p;
    delete b;
}

/* --- the children -------------------------------------------------- */

/* A base class whose constructor reaches its own pure virtual function
   through a member function: the call goes through Base's vtable, whose
   slot is _purecall. */
class PureBase {
public:
    PureBase() { call_it(); }
    virtual ~PureBase() {}
    void call_it() { pure(); }
    virtual void pure() = 0;
};

class PureDerived : public PureBase {
public:
    virtual void pure() { line("kid: PureDerived::pure ran"); }
};

static void __cdecl ending_terminate(void)
{
    line("kid: the terminate handler ran");
    _exit(7);
}

static void __cdecl returning_terminate(void)
{
    line("kid: the terminate handler ran and returns");
}

static void throw_unhandled(void)
{
    throw Thing(60);
}

/* A child's mode; returns its exit code if it gets that far. */
static int run_kid(const char *mode)
{
    terminate_function previous;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (strcmp(mode, "purecall") == 0) {
        line("kid: constructing a PureDerived");
        {
            PureDerived d;
        }
        line("kid: survived");
    } else if (strcmp(mode, "terminate") == 0) {
        previous = set_terminate(ending_terminate);
        line("kid: set_terminate's previous handler NULL %s", yesno(previous == NULL));
        terminate();
        line("kid: terminate returned");
    } else if (strcmp(mode, "termdefault") == 0) {
        line("kid: calling terminate() with no handler set");
        terminate();
        line("kid: terminate returned");
    } else if (strcmp(mode, "termreturn") == 0) {
        set_terminate(returning_terminate);
        line("kid: calling terminate() with a handler that returns");
        terminate();
        line("kid: terminate returned");
    } else if (strcmp(mode, "unhandled") == 0) {
        set_terminate(ending_terminate);
        line("kid: throwing Thing(60), which nothing catches");
        throw_unhandled();
        line("kid: the throw returned");
    } else if (strcmp(mode, "abort") == 0) {
        line("kid: calling abort()");
        abort();
        line("kid: abort returned");
    } else {
        line("kid: no such mode %s", mode);
        return 2;
    }
    return 0;
}

/* Run this program as a child in `mode`, its standard output and error
   one pipe; print what came through it, line by line, and the exit code. */
static void kid(const char *mode)
{
    char path[MAX_PATH];
    char cmd[MAX_PATH + 64];
    char out[4096];
    char text[600];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE rd, wr_end;
    DWORD got, total, w, code;
    DWORD i;
    int n;

    GetModuleFileNameA(NULL, path, sizeof path);
    sprintf(cmd, "\"%s\" kid %s", path, mode);
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr_end, &sa, 0)) {
        line("CreatePipe failed err=%lu", GetLastError());
        return;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdOutput = wr_end;
    si.hStdError = wr_end;
    if (!CreateProcessA(path, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        line("CreateProcessA(kid %s) failed err=%lu", mode, GetLastError());
        CloseHandle(rd);
        CloseHandle(wr_end);
        return;
    }
    CloseHandle(wr_end);
    CloseHandle(pi.hThread);
    w = WaitForSingleObject(pi.hProcess, WAIT_MS);
    if (w != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 99);
        WaitForSingleObject(pi.hProcess, WAIT_MS);
        line("the child (kid %s) did not end within 5 seconds: terminated", mode);
    }
    total = 0;
    while (total < sizeof out - 1 && ReadFile(rd, out + total, sizeof out - 1 - total, &got, NULL) && got > 0) {
        total += got;
    }
    out[total] = 0;
    CloseHandle(rd);

    /* Each line the child wrote, CR LF or LF ended, blank ones skipped. */
    n = 0;
    for (i = 0; i <= total; i++) {
        unsigned char c = (unsigned char)out[i];

        if (i == total || c == '\n') {
            text[n] = 0;
            if (n != 0) {
                line("  the child wrote: [%s]", text);
            }
            n = 0;
        } else if (c == '\r') {
            continue;
        } else if (n < (int)sizeof text - 6) {
            if (c >= 0x20 && c < 0x7F) {
                text[n++] = (char)c;
            } else {
                n += sprintf(text + n, "<%02X>", (unsigned)c);
            }
        }
    }
    code = 0xDEADDEAD;
    GetExitCodeProcess(pi.hProcess, &code);
    line("  its exit code: %lu (0x%08lX)", code, code);
    CloseHandle(pi.hProcess);
}

static void sec_purecall(void)
{
    line("kid purecall:");
    kid("purecall");
}

static void sec_terminate(void)
{
    line("kid terminate (a handler that ends the child):");
    kid("terminate");
    line("kid termdefault (no handler):");
    kid("termdefault");
    line("kid termreturn (a handler that returns):");
    kid("termreturn");
    line("kid unhandled (a handler that ends the child, an exception nothing catches):");
    kid("unhandled");
}

static void sec_abort(void)
{
    line("kid abort:");
    kid("abort");
}

static const section_t sections[] = {
    { "catch", sec_catch, F2KT_ALWAYS },
    { "derived", sec_derived, F2KT_ALWAYS },
    { "rethrow", sec_rethrow, F2KT_ALWAYS },
    { "nested", sec_nested, F2KT_ALWAYS },
    { "unwind", sec_unwind, F2KT_ALWAYS },
    { "seh", sec_seh, F2KT_ALWAYS },
    { "typeid", sec_typeid, F2KT_ALWAYS },
    { "purecall", sec_purecall, F2KT_ALWAYS },
    { "terminate", sec_terminate, F2KT_ALWAYS },
    { "abort", sec_abort, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "kid") == 0) {
        return run_kid(argv[2]);
    }
    return run_sections("cxxeh", sections, argc, argv);
}
