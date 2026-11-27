/*
 * manywin - user32's handle table at scale: the per-process quota on
 * USER objects, many windows alive at once, one slot's uniqueness
 * count going round, and the low word's parity by kind.
 *
 * No handle value is printed: counts, verdicts, and the relations
 * between handles. The one exception is the high word of a handle's
 * slot at the wrap (wrap): those values are the wrap point itself
 * (0xFFFE then 0x0001, or wherever the count turns), the same on any
 * machine.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   quota    CreateMenu until it fails (at most 70,000): the number
 *            made, against the USER objects the process owned before
 *            (GetGuiResources, reached through GetProcAddress), their
 *            sum and a band verdict (Windows 2000's
 *            USERProcessHandleQuota is 10,000 by default), the failing
 *            call's last error; one DestroyMenu, then CreateMenu
 *            succeeds and the next fails again; every menu destroyed
 *   windows  2,000 hidden popup windows alive at once: how many were
 *            made, all distinct, IsWindow on each, the USER objects
 *            owned, then each destroyed and none left
 *   wrap     one menu created and destroyed 65,540 times, more than
 *            the 65,534 values a slot's count can take: whether every
 *            handle kept the first one's low word (the same slot), the
 *            high word one more each round but where it wraps to 1, the
 *            high words around its first turn, and whether 0 or 0xFFFF
 *            (the wildcards) ever came
 *   parity   8 hidden popup windows made in a row, then 8 menus: the
 *            parity of each kind's low words (all even, all odd, or
 *            mixed)
 *
 * wrap's and parity's relations hold while no other program makes or
 * frees a user object during the section: run on an idle machine. The
 * quota counts menus because they are the cheapest user object; windows
 * cost desktop heap, which might run out first.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat manywin):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% manywin.c user32.lib
 */

#include "../common/f2kt.h"
#include <stdlib.h>

/* GetGuiResources' flag (winuser.h has it for WINVER 0x0500 only). */
#define GR_USEROBJECTS_ 1

typedef DWORD (WINAPI *get_gui_resources_t)(HANDLE, DWORD);

/* The quota loop's bound: past the 64K values of a 16-bit low word, so a
 * missing quota shows as the table's own ceiling. */
#define QUOTA_BOUND 70000
#define WINDOWS_ALIVE 2000
#define WRAP_ROUNDS 65540
#define PARITY_EACH 8

static HMENU menus[QUOTA_BOUND];
static HWND windows[WINDOWS_ALIVE];
static WORD high_words[WRAP_ROUNDS + 1];

/* USER objects the process owns (GetGuiResources), or -1 when user32
 * lacks the export. */
static long user_objects(void)
{
    get_gui_resources_t get;

    get = (get_gui_resources_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetGuiResources");
    if (get == NULL) {
        return -1;
    }
    return (long)get(GetCurrentProcess(), GR_USEROBJECTS_);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void register_class(void)
{
    WNDCLASSA wc;

    ZeroMemory(&wc, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "F2KManyWin";
    RegisterClassA(&wc);
}

static HWND make_window(void)
{
    return CreateWindowExA(0, "F2KManyWin", "m", WS_POPUP, 0, 0, 40, 20, NULL, NULL,
                           GetModuleHandleA(NULL), NULL);
}

static int cmp_handle(const void *a, const void *b)
{
    DWORD x = *(const DWORD *)a;
    DWORD y = *(const DWORD *)b;

    return x < y ? -1 : x > y ? 1 : 0;
}

/* --- quota --------------------------------------------------------- */

static void sec_quota(void)
{
    long before, at_refusal;
    int made, i;
    HMENU h;
    const char *e;

    before = user_objects();
    if (before < 0) {
        line("GetGuiResources: absent");
    } else {
        line("USER objects owned before: %ld", before);
    }
    made = 0;
    e = "-";
    while (made < QUOTA_BOUND) {
        arm();
        h = CreateMenu();
        if (h == NULL) {
            e = le();
            break;
        }
        menus[made++] = h;
    }
    if (made == QUOTA_BOUND) {
        line("CreateMenu: %d made, stopped at the loop's bound", made);
    } else {
        line("CreateMenu: %d made, then NULL err=%s", made, e);
    }
    line("  within [9900, 10000]: %s", band((DWORD)made, 9900, 10000));
    at_refusal = user_objects();
    if (before >= 0) {
        line("  made plus owned before: %ld; USER objects owned at the refusal: %ld",
             made + before, at_refusal);
    }
    if (made == 0) {
        return;
    }

    /* One freed: the next create takes it, the one after fails again. */
    arm();
    i = DestroyMenu(menus[made - 1]);
    line("DestroyMenu(the last): ret=%d err=%s", i, le());
    arm();
    h = CreateMenu();
    e = le();
    line("CreateMenu after it: non-NULL %s err=%s", yesno(h != NULL), e);
    if (h != NULL) {
        menus[made - 1] = h;
        arm();
        h = CreateMenu();
        e = le();
        line("CreateMenu again: non-NULL %s err=%s", yesno(h != NULL), e);
        if (h != NULL && made < QUOTA_BOUND) {
            menus[made++] = h;
        } else if (h != NULL) {
            DestroyMenu(h);
        }
    } else {
        made--;
    }

    /* Every menu destroyed. */
    for (i = 0; i < made; i++) {
        if (!DestroyMenu(menus[i])) {
            break;
        }
    }
    line("every menu destroyed: %s", yesno(i == made));
    if (before >= 0) {
        line("USER objects owned after: as before %s", yesno(user_objects() == before));
    }
}

/* --- windows ------------------------------------------------------- */

static void sec_windows(void)
{
    static DWORD sorted[WINDOWS_ALIVE];
    long before;
    int made, i, distinct, alive, destroyed;
    HWND h;
    const char *e;

    register_class();
    before = user_objects();
    made = 0;
    e = "-";
    while (made < WINDOWS_ALIVE) {
        arm();
        h = make_window();
        if (h == NULL) {
            e = le();
            break;
        }
        windows[made++] = h;
    }
    if (made == WINDOWS_ALIVE) {
        line("CreateWindowExA: %d windows made", made);
    } else {
        line("CreateWindowExA: %d windows made, then NULL err=%s", made, e);
    }
    for (i = 0; i < made; i++) {
        sorted[i] = (DWORD)windows[i];
    }
    qsort(sorted, made, sizeof sorted[0], cmp_handle);
    distinct = 1;
    for (i = 1; i < made; i++) {
        if (sorted[i] == sorted[i - 1]) {
            distinct = 0;
        }
    }
    alive = 0;
    for (i = 0; i < made; i++) {
        alive += IsWindow(windows[i]) ? 1 : 0;
    }
    line("all distinct %s; IsWindow on each: %d alive", yesno(distinct), alive);
    if (before >= 0) {
        line("USER objects owned: %d more than before %s", made, yesno(user_objects() == before + made));
    }
    destroyed = 0;
    for (i = 0; i < made; i++) {
        destroyed += DestroyWindow(windows[i]) ? 1 : 0;
    }
    alive = 0;
    for (i = 0; i < made; i++) {
        alive += IsWindow(windows[i]) ? 1 : 0;
    }
    line("DestroyWindow on each: %d destroyed; IsWindow after: %d alive", destroyed, alive);
    if (before >= 0) {
        line("USER objects owned after: as before %s", yesno(user_objects() == before));
    }
}

/* --- wrap ---------------------------------------------------------- */

static void sec_wrap(void)
{
    HMENU h;
    WORD low;
    int i, made, moved, wildcard, wraps, jumps, first;

    /* high_words[0] is the first menu's, then one per round. */
    h = CreateMenu();
    if (h == NULL) {
        line("CreateMenu: NULL");
        return;
    }
    low = LOWORD((DWORD)h);
    high_words[0] = HIWORD((DWORD)h);
    DestroyMenu(h);
    made = 1;
    moved = 0;
    for (i = 1; i <= WRAP_ROUNDS; i++) {
        h = CreateMenu();
        if (h == NULL) {
            break;
        }
        made++;
        if (LOWORD((DWORD)h) != low) {
            moved++;
        }
        high_words[i] = HIWORD((DWORD)h);
        DestroyMenu(h);
    }
    line("%d rounds: every menu made %s, the first's low word every round %s", WRAP_ROUNDS,
         yesno(made == WRAP_ROUNDS + 1), yesno(moved == 0));
    if (made != WRAP_ROUNDS + 1) {
        return;
    }

    /* A step is one more; a turn is anything else: a wrap when it lands
       on 1, an odd jump otherwise. */
    wraps = 0;
    jumps = 0;
    first = 0;
    wildcard = 0;
    for (i = 0; i <= WRAP_ROUNDS; i++) {
        if (high_words[i] == 0 || high_words[i] == 0xFFFF) {
            wildcard = 1;
        }
        if (i == 0 || high_words[i] == (WORD)(high_words[i - 1] + 1)) {
            continue;
        }
        if (first == 0) {
            first = i;
        }
        if (high_words[i] == 1) {
            wraps++;
        } else {
            jumps++;
        }
    }
    line("the high word one more each round but at a wrap to 0x0001: %s; wrapped at least once %s",
         yesno(jumps == 0), yesno(wraps >= 1));
    line("high word 0 or 0xFFFF seen: %s", yesno(wildcard));
    if (first >= 2 && first + 1 <= WRAP_ROUNDS) {
        line("the first turn: 0x%04X, 0x%04X, then 0x%04X, 0x%04X", high_words[first - 2],
             high_words[first - 1], high_words[first], high_words[first + 1]);
    }
}

/* --- parity -------------------------------------------------------- */

/* "all even", "all odd" or "mixed", over the low words of n handles. */
static const char *parity(const DWORD *handles, int n)
{
    int i, odd = 0;

    for (i = 0; i < n; i++) {
        odd += handles[i] & 1;
    }
    return odd == 0 ? "all even" : odd == n ? "all odd" : "mixed";
}

static void sec_parity(void)
{
    DWORD w[PARITY_EACH], m[PARITY_EACH];
    int i, nw, nm;

    register_class();
    nw = 0;
    for (i = 0; i < PARITY_EACH; i++) {
        w[nw] = (DWORD)make_window();
        if (w[nw] != 0) {
            nw++;
        }
    }
    nm = 0;
    for (i = 0; i < PARITY_EACH; i++) {
        m[nm] = (DWORD)CreateMenu();
        if (m[nm] != 0) {
            nm++;
        }
    }
    line("%d windows made: their low words %s", nw, parity(w, nw));
    line("%d menus made: their low words %s", nm, parity(m, nm));
    for (i = 0; i < nw; i++) {
        DestroyWindow((HWND)w[i]);
    }
    for (i = 0; i < nm; i++) {
        DestroyMenu((HMENU)m[i]);
    }
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "quota", sec_quota, F2KT_ALWAYS },
    { "windows", sec_windows, F2KT_ALWAYS },
    { "wrap", sec_wrap, F2KT_ALWAYS },
    { "parity", sec_parity, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A refused handle goes to the calls: should one fault, no dialog
     * stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("manywin", sections, argc, argv);
}
