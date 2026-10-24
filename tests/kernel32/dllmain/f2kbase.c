/*
 * f2kbase - the dllmain fixture's log of entry-point calls (see
 * dllmain.c).
 *
 * Built with no C runtime, DllMain its entry point. Every companion
 * DLL's DllMain (this one's too) records its call here: the DLL's
 * name, the reason, whether lpReserved was NULL, and the calling
 * thread. The program reads the log back. The loader calls one entry
 * point at a time (it holds its lock), so the log needs no lock of
 * its own; the mapping zeroes it.
 */

#include <windows.h>

#define F2KB_CALLS 64
#define F2KB_NAME 12

static char names[F2KB_CALLS][F2KB_NAME];
static DWORD reasons[F2KB_CALLS];
static int nulls[F2KB_CALLS];
static DWORD threads[F2KB_CALLS];
static int count;

/* Record a call of `dll`'s entry point (past the log's room: dropped). */
void __stdcall f2kb_log(const char *dll, DWORD reason, LPVOID reserved)
{
    int i;

    if (count >= F2KB_CALLS) {
        return;
    }
    for (i = 0; i < F2KB_NAME - 1 && dll[i] != 0; i++) {
        names[count][i] = dll[i];
    }
    names[count][i] = 0;
    reasons[count] = reason;
    nulls[count] = reserved == NULL;
    threads[count] = GetCurrentThreadId();
    count++;
}

/* How many calls the log holds. */
int __stdcall f2kb_count(void)
{
    return count;
}

/* Call `index` of the log: its DLL's name (into `dll`, `size` bytes),
 * its reason, whether lpReserved was NULL, its thread. FALSE past the
 * log's end. */
int __stdcall f2kb_get(int index, char *dll, int size, DWORD *reason, int *reserved_null,
                       DWORD *thread)
{
    int i;

    if (index < 0 || index >= count || size <= 0) {
        return FALSE;
    }
    for (i = 0; i < size - 1 && names[index][i] != 0; i++) {
        dll[i] = names[index][i];
    }
    dll[i] = 0;
    *reason = reasons[index];
    *reserved_null = nulls[index];
    *thread = threads[index];
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    f2kb_log("f2kbase", reason, reserved);
    return TRUE;
}
