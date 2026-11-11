/*
 * threx - thread-level exception behavior: the second chance, the
 * dispatched context's state, the entry's return value, and the recorded
 * start address.
 *
 * Sections:
 *
 *   unhandled    a worker thread raises an exception no handler catches
 *                (named-only: on a kernel whose second chance ends the
 *                process, the process dies here). On the platform only
 *                that thread ends: the wait answers and the main thread
 *                prints after.
 *   context      a handler reads the CONTEXT dispatched for a raised
 *                exception: on the platform its flags carry the
 *                floating-point and debug-register state.
 *   mainret      main returns while a worker still runs (named-only: the
 *                process's end differs): on the platform the entry's
 *                return value ends the thread, not the process, so the
 *                worker's line still prints.
 *   threadstart  NtQueryInformationThread's ThreadQuerySetWin32StartAddress
 *                class (9): whether the start routine recorded the start
 *                address (it does on the platform).
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat threx):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% threx.c kernel32.lib
 */

#include "../common/f2kt.h"

/* NtQueryInformationThread's ThreadQuerySetWin32StartAddress. */
#define F2KT_THREAD_QUERY_SET_WIN32_START_ADDRESS 9

typedef LONG(WINAPI *nqit_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static DWORD g_flags;

/* --- unhandled: the second chance ends the thread, not the process ------ */

static DWORD WINAPI faulting_worker(LPVOID p)
{
    (void)p;
    RaiseException(0xC0000005u, 0, 0, NULL);
    return 0; /* never reached: no handler catches this */
}

static void sec_unhandled(void)
{
    HANDLE t;
    DWORD w;

    t = CreateThread(NULL, 0, faulting_worker, NULL, 0, NULL);
    if (t == NULL) {
        line("CreateThread: ret=null err=%s", le());
        return;
    }
    arm();
    w = WaitForSingleObject(t, WAIT_MS);
    line("wait=%s", wr(w));
    line("after=alive");
    CloseHandle(t);
}

/* --- context: the dispatched CONTEXT carries FP and debug state ---------- */

static LONG context_filter(PEXCEPTION_POINTERS ep)
{
    g_flags = ep->ContextRecord->ContextFlags;
    return EXCEPTION_EXECUTE_HANDLER;
}

static void sec_context(void)
{
    __try {
        RaiseException(0xC0000094u /* STATUS_FLOAT_DIVIDE_BY_ZERO */, 0, 0, NULL);
    } __except (context_filter(GetExceptionInformation())) {
    }
    line("ctxflags=0x%08lX fp=%s dbg=%s", (unsigned long)g_flags,
        yesno((g_flags & CONTEXT_FLOATING_POINT) != 0),
        yesno((g_flags & CONTEXT_DEBUG_REGISTERS) != 0));
}

/* --- mainret: the entry's return value ends the thread ------------------- */

static DWORD WINAPI late_worker(LPVOID p)
{
    (void)p;
    Sleep(500);
    line("worker=alive");
    return 0;
}

static void sec_mainret(void)
{
    HANDLE t = CreateThread(NULL, 0, late_worker, NULL, 0, NULL);
    line("main returning: thread=%s", t ? "ok" : "null");
    /* main's return goes to the thread's end on the platform: the worker
     * prints after it. A kernel that exits the process here never does. */
}

/* --- threadstart: the recorded start address ----------------------------- */

static void sec_threadstart(void)
{
    nqit_fn nqit;
    unsigned long addr = 0;
    ULONG rl = 0;
    LONG st;

    nqit = (nqit_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (nqit == NULL) {
        line("NtQueryInformationThread not found");
        return;
    }
    arm();
    st = nqit(GetCurrentThread(), F2KT_THREAD_QUERY_SET_WIN32_START_ADDRESS, &addr, sizeof addr, &rl);
    line("NtQueryInformationThread(9): status=0x%08lX err=%s recorded=%s", (unsigned long)st, le(),
        (st >= 0 && addr != 0) ? "yes" : "no");
}

/* --- main ---------------------------------------------------------------- */

static const section_t sections[] = {
    { "unhandled", sec_unhandled, F2KT_NAMED },
    { "context", sec_context, F2KT_ALWAYS },
    { "mainret", sec_mainret, F2KT_NAMED },
    { "threadstart", sec_threadstart, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("threx", sections, argc, argv);
}
