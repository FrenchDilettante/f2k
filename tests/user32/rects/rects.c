/*
 * rects - user32's rectangle helpers: SetRectEmpty, IsRectEmpty,
 * EqualRect, CopyRect, InflateRect, PtInRect, IntersectRect, UnionRect
 * and SubtractRect.
 *
 * The helpers keep no state: each takes rectangles in and gives one
 * back, so every line prints the inputs, the return and the rectangle
 * the call left, as (left,top,right,bottom). A destination starts as
 * (111,222,333,444), so a line shows whether a failing call wrote it.
 * The inputs cover the empty rectangles (zero width or height), the
 * inverted ones (right left of left, bottom above top), touching,
 * overlapping, nested and disjoint pairs, a destination that is one of
 * the sources, and coordinates near the 32-bit limits. `nulls` hands
 * each helper NULL pointers inside __try, and prints whether it
 * faulted.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel, and its line
 * prints ret= and err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   empty      SetRectEmpty; IsRectEmpty of a normal rectangle, zero
 *              width, zero height, inverted either way, all zero, and
 *              negative coordinates; EqualRect of equal rectangles,
 *              rectangles one coordinate apart, two different empty
 *              ones and two equal inverted ones; CopyRect, and onto
 *              itself
 *   inflate    InflateRect outwards, inwards, inwards past the middle
 *              (no reordering), by zero, of an inverted rectangle, and
 *              past the 32-bit limits
 *   pt         PtInRect at the corners and edges of (10,20,30,40)
 *              (left and top in, right and bottom out), inside, outside
 *              each side; in an inverted and an empty rectangle; with
 *              negative coordinates
 *   intersect  IntersectRect of overlapping, touching, disjoint and
 *              nested pairs, with an empty or inverted source, and into
 *              one of its sources
 *   union      UnionRect of overlapping and disjoint pairs, with one or
 *              both sources empty or inverted, and into one of its
 *              sources
 *   subtract   SubtractRect of (0,0,10,10) less a rectangle covering a
 *              whole side (left, right, top, bottom, exactly or past
 *              the edges), its middle, a corner, a full-height stripe,
 *              all of it, nothing of it, an empty and an inverted
 *              rectangle; an empty first rectangle; into the first
 *              source
 *   nulls      every helper with NULL for each pointer, inside __try:
 *              the return, or that it faulted
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat rects):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% rects.c user32.lib
 */

#include "../common/f2kt.h"

/* A rectangle from its four coordinates, without an API call. */
static RECT mk(LONG l, LONG t, LONG r, LONG b)
{
    RECT rc;

    rc.left = l;
    rc.top = t;
    rc.right = r;
    rc.bottom = b;
    return rc;
}

/* The destination's starting value. */
static RECT unset(void)
{
    return mk(111, 222, 333, 444);
}

/* A rectangle as printed. Rotates through a few buffers. */
static const char *rs(const RECT *rc)
{
    static char bufs[6][64];
    static int next;
    char *b = bufs[next++ % 6];

    sprintf(b, "(%ld,%ld,%ld,%ld)", rc->left, rc->top, rc->right, rc->bottom);
    return b;
}

/* --- empty --------------------------------------------------------- */

static void is_empty(const char *label, RECT a)
{
    BOOL r;

    arm();
    r = IsRectEmpty(&a);
    line("IsRectEmpty(%s, %s): ret=%d err=%s", label, rs(&a), r, le());
}

static void equal(const char *label, RECT a, RECT b)
{
    BOOL r;

    arm();
    r = EqualRect(&a, &b);
    line("EqualRect(%s, %s, %s): ret=%d err=%s", label, rs(&a), rs(&b), r, le());
}

static void sec_empty(void)
{
    RECT a, d;
    BOOL r;

    d = unset();
    arm();
    r = SetRectEmpty(&d);
    line("SetRectEmpty((111,222,333,444)): ret=%d err=%s rect=%s", r, le(), rs(&d));

    is_empty("normal", mk(0, 0, 10, 10));
    is_empty("zero width", mk(5, 0, 5, 10));
    is_empty("zero height", mk(0, 5, 10, 5));
    is_empty("inverted horizontally", mk(10, 0, 0, 10));
    is_empty("inverted vertically", mk(0, 10, 10, 0));
    is_empty("all zero", mk(0, 0, 0, 0));
    is_empty("negative", mk(-10, -10, -5, -5));
    is_empty("one by one", mk(3, 3, 4, 4));

    equal("equal", mk(1, 2, 3, 4), mk(1, 2, 3, 4));
    equal("left differs", mk(1, 2, 3, 4), mk(0, 2, 3, 4));
    equal("top differs", mk(1, 2, 3, 4), mk(1, 0, 3, 4));
    equal("right differs", mk(1, 2, 3, 4), mk(1, 2, 0, 4));
    equal("bottom differs", mk(1, 2, 3, 4), mk(1, 2, 3, 0));
    equal("two empty", mk(0, 0, 0, 0), mk(5, 5, 5, 9));
    equal("two inverted, equal", mk(10, 10, 0, 0), mk(10, 10, 0, 0));

    a = mk(-1, 2, 0x7FFFFFFF, (LONG)0x80000000);
    d = unset();
    arm();
    r = CopyRect(&d, &a);
    line("CopyRect(dst, %s): ret=%d err=%s rect=%s", rs(&a), r, le(), rs(&d));
    a = mk(5, 6, 7, 8);
    arm();
    r = CopyRect(&a, &a);
    line("CopyRect(a, a), a (5,6,7,8): ret=%d err=%s rect=%s", r, le(), rs(&a));
}

/* --- inflate ------------------------------------------------------- */

static void inflate(const char *label, RECT a, int dx, int dy)
{
    RECT in = a;
    BOOL r;

    arm();
    r = InflateRect(&a, dx, dy);
    line("InflateRect(%s %s, %d, %d): ret=%d err=%s rect=%s", label, rs(&in), dx, dy, r, le(),
         rs(&a));
}

static void sec_inflate(void)
{
    inflate("outwards", mk(0, 0, 10, 10), 2, 3);
    inflate("inwards", mk(0, 0, 10, 10), -2, -3);
    inflate("inwards past the middle", mk(0, 0, 10, 10), -6, -7);
    inflate("by zero", mk(0, 0, 10, 10), 0, 0);
    inflate("one way only", mk(0, 0, 10, 10), 4, -4);
    inflate("inverted", mk(10, 10, 0, 0), 2, 2);
    inflate("empty", mk(5, 5, 5, 5), 1, 1);
    inflate("near the limits", mk((LONG)0x80000001, 0, 0x7FFFFFFE, 0), 2, 0);
}

/* --- pt ------------------------------------------------------------ */

static void pt_in(const char *label, RECT a, LONG x, LONG y)
{
    POINT p;
    BOOL r;

    p.x = x;
    p.y = y;
    arm();
    r = PtInRect(&a, p);
    line("PtInRect(%s, (%ld,%ld)), %s: ret=%d err=%s", rs(&a), x, y, label, r, le());
}

static void sec_pt(void)
{
    RECT a = mk(10, 20, 30, 40);

    pt_in("top left corner", a, 10, 20);
    pt_in("top right corner", a, 30, 20);
    pt_in("bottom left corner", a, 10, 40);
    pt_in("bottom right corner", a, 30, 40);
    pt_in("last pixel in", a, 29, 39);
    pt_in("inside", a, 20, 30);
    pt_in("left of it", a, 9, 30);
    pt_in("right edge", a, 30, 30);
    pt_in("above it", a, 20, 19);
    pt_in("bottom edge", a, 20, 40);
    pt_in("inverted, the middle", mk(30, 40, 10, 20), 20, 30);
    pt_in("inverted, its left and top", mk(30, 40, 10, 20), 30, 40);
    pt_in("empty, its corner", mk(10, 10, 10, 10), 10, 10);
    pt_in("zero height", mk(10, 10, 20, 10), 15, 10);
    pt_in("negative, inside", mk(-30, -30, -10, -10), -20, -20);
    pt_in("negative, its right edge", mk(-30, -30, -10, -10), -10, -20);
}

/* --- intersect ----------------------------------------------------- */

static void intersect(const char *label, RECT a, RECT b)
{
    RECT d = unset();
    BOOL r;

    arm();
    r = IntersectRect(&d, &a, &b);
    line("IntersectRect(%s, %s, %s): ret=%d err=%s rect=%s", label, rs(&a), rs(&b), r, le(),
         rs(&d));
}

static void sec_intersect(void)
{
    RECT a = mk(0, 0, 10, 10);
    RECT b;
    BOOL r;

    intersect("overlapping", a, mk(5, 5, 15, 15));
    intersect("overlapping, the other way", mk(5, 5, 15, 15), a);
    intersect("touching on the right", a, mk(10, 0, 20, 10));
    intersect("touching at a corner", a, mk(10, 10, 20, 20));
    intersect("one pixel over", a, mk(9, 9, 20, 20));
    intersect("disjoint", a, mk(20, 20, 30, 30));
    intersect("overlapping across only", a, mk(5, 20, 15, 30));
    intersect("nested", a, mk(2, 2, 8, 8));
    intersect("equal", a, a);
    intersect("an empty one inside", a, mk(3, 3, 3, 8));
    intersect("an inverted one inside", a, mk(8, 8, 2, 2));
    intersect("an inverted first", mk(10, 10, 0, 0), mk(2, 2, 8, 8));
    intersect("both empty, the same", mk(3, 3, 3, 3), mk(3, 3, 3, 3));
    intersect("negative", mk(-10, -10, 0, 0), mk(-5, -20, 5, -5));

    a = mk(0, 0, 10, 10);
    b = mk(5, 5, 15, 15);
    arm();
    r = IntersectRect(&a, &a, &b);
    line("IntersectRect(a, a, b), a (0,0,10,10), b (5,5,15,15): ret=%d err=%s a=%s", r, le(),
         rs(&a));
    a = mk(0, 0, 10, 10);
    b = mk(20, 20, 30, 30);
    arm();
    r = IntersectRect(&b, &a, &b);
    line("IntersectRect(b, a, b), a (0,0,10,10), b (20,20,30,30): ret=%d err=%s b=%s", r, le(),
         rs(&b));
}

/* --- union --------------------------------------------------------- */

static void unite(const char *label, RECT a, RECT b)
{
    RECT d = unset();
    BOOL r;

    arm();
    r = UnionRect(&d, &a, &b);
    line("UnionRect(%s, %s, %s): ret=%d err=%s rect=%s", label, rs(&a), rs(&b), r, le(),
         rs(&d));
}

static void sec_union(void)
{
    RECT a = mk(0, 0, 10, 10);
    RECT b;
    BOOL r;

    unite("overlapping", a, mk(5, 5, 15, 15));
    unite("disjoint", a, mk(20, 20, 30, 30));
    unite("nested", a, mk(2, 2, 8, 8));
    unite("touching", a, mk(10, 0, 20, 10));
    unite("the second empty", a, mk(50, 50, 50, 60));
    unite("the first empty", mk(50, 50, 60, 50), a);
    unite("both empty", mk(50, 50, 50, 60), mk(70, 70, 80, 70));
    unite("the second inverted", a, mk(30, 30, 20, 20));
    unite("the first inverted", mk(30, 30, 20, 20), a);
    unite("both inverted", mk(30, 30, 20, 20), mk(10, 10, 0, 0));
    unite("negative", mk(-10, -10, -5, -5), mk(5, 5, 10, 10));

    a = mk(0, 0, 10, 10);
    b = mk(5, 5, 15, 15);
    arm();
    r = UnionRect(&a, &a, &b);
    line("UnionRect(a, a, b), a (0,0,10,10), b (5,5,15,15): ret=%d err=%s a=%s", r, le(), rs(&a));
}

/* --- subtract ------------------------------------------------------ */

static void subtract(const char *label, RECT a, RECT b)
{
    RECT d = unset();
    BOOL r;

    arm();
    r = SubtractRect(&d, &a, &b);
    line("SubtractRect(%s, %s, %s): ret=%d err=%s rect=%s", label, rs(&a), rs(&b), r, le(),
         rs(&d));
}

static void sec_subtract(void)
{
    RECT a = mk(0, 0, 10, 10);
    RECT b;
    BOOL r;

    subtract("the left half", a, mk(0, 0, 5, 10));
    subtract("the right half", a, mk(5, 0, 10, 10));
    subtract("the top", a, mk(0, 0, 10, 4));
    subtract("the bottom", a, mk(0, 6, 10, 10));
    subtract("the left, past the edges", a, mk(-5, -5, 5, 15));
    subtract("the top, past the edges", a, mk(-5, -5, 15, 5));
    subtract("the right, past three edges", a, mk(7, -1, 20, 11));
    subtract("the left, not the full height", a, mk(0, 0, 5, 9));
    subtract("the left, one row short at the top", a, mk(0, 1, 5, 10));
    subtract("the middle", a, mk(3, 3, 7, 7));
    subtract("a corner", a, mk(0, 0, 5, 5));
    subtract("a full-height stripe", a, mk(3, 0, 7, 10));
    subtract("a full-width band", a, mk(0, 3, 10, 7));
    subtract("all of it, exactly", a, a);
    subtract("all of it, and more", a, mk(-1, -1, 11, 11));
    subtract("nothing of it", a, mk(20, 20, 30, 30));
    subtract("touching on the right", a, mk(10, 0, 20, 10));
    subtract("an empty one", a, mk(0, 0, 0, 10));
    subtract("an inverted one over the left", a, mk(5, 10, 0, 0));
    subtract("from an empty one", mk(5, 5, 5, 5), mk(0, 0, 10, 10));
    subtract("from an empty one, nothing", mk(5, 5, 5, 5), mk(20, 20, 30, 30));
    subtract("from an inverted one", mk(10, 10, 0, 0), mk(0, 0, 5, 10));

    a = mk(0, 0, 10, 10);
    b = mk(0, 0, 5, 10);
    arm();
    r = SubtractRect(&a, &a, &b);
    line("SubtractRect(a, a, b), a (0,0,10,10), b (0,0,5,10): ret=%d err=%s a=%s", r, le(),
         rs(&a));
    a = mk(0, 0, 10, 10);
    b = mk(-1, -1, 11, 11);
    arm();
    r = SubtractRect(&a, &a, &b);
    line("SubtractRect(a, a, b), a (0,0,10,10), b (-1,-1,11,11): ret=%d err=%s a=%s", r, le(),
         rs(&a));
}

/* --- nulls --------------------------------------------------------- */

/* Which helper, and which of its pointers is NULL. */
enum {
    N_SETEMPTY, N_ISEMPTY, N_EQUAL1, N_EQUAL2, N_COPY_DST, N_COPY_SRC, N_INFLATE, N_PTIN,
    N_INTER_DST, N_INTER_SRC1, N_INTER_SRC2, N_UNION_DST, N_UNION_SRC1, N_UNION_SRC2,
    N_SUB_DST, N_SUB_SRC1, N_SUB_SRC2, N_COUNT
};

static const char *const null_labels[N_COUNT] = {
    "SetRectEmpty(NULL)",
    "IsRectEmpty(NULL)",
    "EqualRect(NULL, a)",
    "EqualRect(a, NULL)",
    "CopyRect(NULL, a)",
    "CopyRect(dst, NULL)",
    "InflateRect(NULL, 1, 1)",
    "PtInRect(NULL, (1,1))",
    "IntersectRect(NULL, a, b)",
    "IntersectRect(dst, NULL, b)",
    "IntersectRect(dst, a, NULL)",
    "UnionRect(NULL, a, b)",
    "UnionRect(dst, NULL, b)",
    "UnionRect(dst, a, NULL)",
    "SubtractRect(NULL, a, b)",
    "SubtractRect(dst, NULL, b)",
    "SubtractRect(dst, a, NULL)",
};

/* One helper with a NULL pointer: its return, or 0 and *faulted set. */
static BOOL null_call(int which, RECT *a, RECT *b, RECT *d, int *faulted)
{
    BOOL r = 0;
    POINT p;

    p.x = 1;
    p.y = 1;
    *faulted = 0;
    __try {
        switch (which) {
        case N_SETEMPTY: r = SetRectEmpty(NULL); break;
        case N_ISEMPTY: r = IsRectEmpty(NULL); break;
        case N_EQUAL1: r = EqualRect(NULL, a); break;
        case N_EQUAL2: r = EqualRect(a, NULL); break;
        case N_COPY_DST: r = CopyRect(NULL, a); break;
        case N_COPY_SRC: r = CopyRect(d, NULL); break;
        case N_INFLATE: r = InflateRect(NULL, 1, 1); break;
        case N_PTIN: r = PtInRect(NULL, p); break;
        case N_INTER_DST: r = IntersectRect(NULL, a, b); break;
        case N_INTER_SRC1: r = IntersectRect(d, NULL, b); break;
        case N_INTER_SRC2: r = IntersectRect(d, a, NULL); break;
        case N_UNION_DST: r = UnionRect(NULL, a, b); break;
        case N_UNION_SRC1: r = UnionRect(d, NULL, b); break;
        case N_UNION_SRC2: r = UnionRect(d, a, NULL); break;
        case N_SUB_DST: r = SubtractRect(NULL, a, b); break;
        case N_SUB_SRC1: r = SubtractRect(d, NULL, b); break;
        case N_SUB_SRC2: r = SubtractRect(d, a, NULL); break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *faulted = 1;
    }
    return r;
}

static void sec_nulls(void)
{
    RECT a, b, d;
    BOOL r;
    int faulted;
    int i;

    for (i = 0; i < N_COUNT; i++) {
        a = mk(0, 0, 10, 10);
        b = mk(5, 5, 15, 15);
        d = unset();
        arm();
        r = null_call(i, &a, &b, &d, &faulted);
        if (faulted) {
            line("%s, a (0,0,10,10), b (5,5,15,15): faulted err=%s", null_labels[i], le());
        } else {
            line("%s, a (0,0,10,10), b (5,5,15,15): ret=%d err=%s dst=%s", null_labels[i], r, le(),
                 rs(&d));
        }
    }
}

static const section_t sections[] = {
    { "empty", sec_empty, F2KT_ALWAYS },
    { "inflate", sec_inflate, F2KT_ALWAYS },
    { "pt", sec_pt, F2KT_ALWAYS },
    { "intersect", sec_intersect, F2KT_ALWAYS },
    { "union", sec_union, F2KT_ALWAYS },
    { "subtract", sec_subtract, F2KT_ALWAYS },
    { "nulls", sec_nulls, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* NULL pointers go to the helpers: a fault __try does not catch
     * ends the process without a dialog. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("rects", sections, argc, argv);
}
