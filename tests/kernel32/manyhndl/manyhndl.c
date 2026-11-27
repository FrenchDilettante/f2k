/*
 * manyhndl - many handles in one process's handle table, all to one
 * object (so no per-kind object limit is in play), and which entry the
 * table gives back after a close. Handle values are machine-specific:
 * only their relations print.
 *
 * Sections:
 *
 *   dup    100,000 DuplicateHandle calls on one event: how many
 *          succeeded (a failure ends the duplicating there, its error
 *          printed), whether the values are multiples of 4 and distinct
 *          (from each other and from the event's own); then one closed
 *          and one more duplicated: whether it is the closed one's value;
 *          then two closed, a and then b, and two more duplicated:
 *          whether the first is b's and the second a's (Windows 2000's
 *          handle table reuses the last freed entry first); the event
 *          still answering through its own handle; and how many of the
 *          closes succeeded.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat manyhndl):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% manyhndl.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>

/* How many duplicates: past F2K's old 1,024 handles and a 16K table. */
#define COPIES 100000

static HANDLE copies[COPIES];
static DWORD sorted[COPIES + 1];

static int by_value(const void *a, const void *b)
{
    DWORD x = *(const DWORD *)a;
    DWORD y = *(const DWORD *)b;

    return x < y ? -1 : x > y;
}

/* Whether the n values are distinct (sorts them). */
static int distinct(DWORD *v, int n)
{
    int i;

    qsort(v, n, sizeof *v, by_value);
    for (i = 1; i < n; i++) {
        if (v[i] == v[i - 1]) {
            return 0;
        }
    }
    return 1;
}

/* One more duplicate of ev into *h. */
static BOOL dup(HANDLE ev, HANDLE *h)
{
    return DuplicateHandle(GetCurrentProcess(), ev, GetCurrentProcess(), h, 0, FALSE, DUPLICATE_SAME_ACCESS);
}

static void sec_dup(void)
{
    HANDLE ev;
    HANDLE closed;
    HANDLE a;
    HANDLE b;
    BOOL ok;
    int made = 0;
    int closes = 0;
    int by4 = 1;
    int i;

    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (ev == NULL) {
        line("the event: not made err=%s", le());
        return;
    }
    for (i = 0; i < COPIES; i++) {
        arm();
        if (!dup(ev, &copies[i])) {
            line("DuplicateHandle, copy %d: failed err=%s", i + 1, le());
            break;
        }
        made++;
    }
    line("DuplicateHandle of one event: %d of %d made", made, COPIES);

    for (i = 0; i < made; i++) {
        by4 &= ((DWORD)copies[i] & 3) == 0 && copies[i] != NULL;
        sorted[i] = (DWORD)copies[i];
    }
    sorted[made] = (DWORD)ev;
    line("their values: multiples of 4 %s, distinct and none the event's own %s", yesno(by4),
        yesno(distinct(sorted, made + 1)));

    if (made >= 3) {
        closed = copies[made / 2];
        CloseHandle(closed);
        arm();
        ok = dup(ev, &copies[made / 2]);
        line("one closed, one more made: ret=%d err=%s, the closed one's value %s", ok, le(),
            yesno(ok && copies[made / 2] == closed));

        a = copies[0];
        b = copies[made - 1];
        CloseHandle(a);
        CloseHandle(b);
        ok = dup(ev, &copies[0]) && dup(ev, &copies[made - 1]);
        line("a then b closed, two more made: ret=%d, the first b's value %s, the second a's %s", ok,
            yesno(ok && copies[0] == b), yesno(ok && copies[made - 1] == a));
        if (!ok) {
            made = 0;   /* which ones are open is unknown: leave them to the process's end */
        }
    }

    SetEvent(ev);
    line("the event through its own handle, set: %s", wr(WaitForSingleObject(ev, 0)));
    for (i = 0; i < made; i++) {
        closes += CloseHandle(copies[i]) != 0;
    }
    line("the copies closed: %d", closes);
    CloseHandle(ev);
}

static const section_t sections[] = {
    { "dup", sec_dup, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("manyhndl", sections, argc, argv);
}
