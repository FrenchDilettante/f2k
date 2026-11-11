/*
 * threx - thread-level exception behavior: the second chance, the
 * dispatched context's state, main's return, the recorded start address,
 * and the floating-point state a thread resumes with.
 *
 * Sections:
 *
 *   unhandled    a worker thread raises an exception no handler catches
 *                (named-only: it ends the process). On Windows 2000 the
 *                second chance ends the whole process, not the thread: it
 *                exits with the exception's code (0xC0000005 here, no
 *                dialog under SEM_NOGPFAULTERRORBOX), so neither the
 *                main thread's wait line nor the section's end prints.
 *   context      a handler reads the CONTEXT dispatched for a raised
 *                exception: on Windows 2000 its flags carry the
 *                floating-point and debug-register state.
 *   mainret      main returns while a worker sleeps (named-only: it ends
 *                the process). main returns into the C runtime's startup,
 *                which calls exit, and so ExitProcess: the process ends
 *                with main's return value and the worker's line never
 *                prints.
 *   threadstart  NtQueryInformationThread's ThreadQuerySetWin32StartAddress
 *                class (9): whether the start address was recorded (it is
 *                on Windows 2000).
 *   fpresume     whether a thread resumes with the floating-point state of
 *                the CONTEXT it resumes from. The x87 state is set (a
 *                control word rounding to nearest, 1.5 pushed in ST(0)),
 *                then:
 *                - an exception is raised and its filter changes the
 *                  dispatched CONTEXT's FloatSave (the control word
 *                  rounding toward zero, the exception masks kept; ST(0)
 *                  2.5) and continues execution, so the thread resumes
 *                  through NtContinue with that CONTEXT; the filter also
 *                  clears CONTEXT_EXTENDED_REGISTERS' bit, so FloatSave
 *                  alone carries the x87 state back;
 *                - a second thread sets the same state and waits; it is
 *                  suspended, its CONTEXT_FLOATING_POINT read and changed
 *                  the same way, set back with SetThreadContext, and
 *                  resumed.
 *                Each prints whether the control word and ST(0) the thread
 *                then reads are the new values ("new"), the ones from
 *                before ("before") or neither ("other"). Where CPUID
 *                reports FXSR and SSE, XMM0 goes the same two ways through
 *                CONTEXT_EXTENDED_REGISTERS (the FXSAVE image, XMM0 at
 *                offset 160; the exception's filter then clears
 *                CONTEXT_FLOATING_POINT's bit instead); otherwise one line
 *                says the processor has no SSE. MSVC 6's assembler knows
 *                neither CPUID nor the SSE instructions: they are emitted
 *                as bytes (_emit).
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat threx):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% threx.c kernel32.lib
 */

#include "../common/f2kt.h"

/* NtQueryInformationThread's ThreadQuerySetWin32StartAddress. */
#define F2KT_THREAD_QUERY_SET_WIN32_START_ADDRESS 9

typedef LONG(WINAPI *nqit_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static DWORD g_flags;

/* --- unhandled: the second chance ends the process ----------------------- */

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
    /* On Windows 2000 the process ends during this wait: these lines are
     * what a kernel that ended only the thread would print. */
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

/* --- mainret: main's return ends the process ------------------------------ */

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
    /* main returns into the C runtime's startup, whose exit ends the
     * process before the worker wakes: its line never prints. */
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

/* --- fpresume: the floating-point state a thread resumes with ------------ */

/* The i386 CONTEXT with its ExtendedRegisters (the FXSAVE image), which
 * MSVC 6's winnt.h predates: the layout of the later SDKs' public header. */
typedef struct {
    DWORD ContextFlags;
    DWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs, SegFs, SegEs, SegDs;
    DWORD Edi, Esi, Ebx, Edx, Ecx, Eax;
    DWORD Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    BYTE ExtendedRegisters[512];
} f2kt_context;

#define F2KT_CONTEXT_EXTENDED_REGISTERS (CONTEXT_i386 | 0x20L)
#define F2KT_FLOATING_BIT 0x08L         /* CONTEXT_FLOATING_POINT's own bit */
#define F2KT_EXTENDED_BIT 0x20L         /* CONTEXT_EXTENDED_REGISTERS' own bit */
#define F2KT_XMM0 160                   /* XMM0 in the FXSAVE image */
#define F2KT_FP_CODE 0xE0F2F0F1u        /* the section's raised exception */

/* Control words: 53-bit precision, every exception masked, rounding to
 * nearest (Windows' default) and toward zero. */
#define F2KT_CW_BEFORE 0x027F
#define F2KT_CW_NEW 0x0E7F

/* ST(0) in the 80-bit format FloatSave.RegisterArea holds: 1.5, then 2.5. */
static const BYTE st0_before[10] = { 0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0x3F };
static const BYTE st0_new[10] = { 0, 0, 0, 0, 0, 0, 0, 0xA0, 0x00, 0x40 };

static const BYTE xmm_before[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};
static const BYTE xmm_new[16] = {
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0xF0
};

/* CPUID function 1: FXSR (EDX bit 24) and SSE (bit 25). */
static int has_sse(void)
{
    DWORD features = 0;

    __asm {
        push ebx
        mov eax, 1
        _emit 0x0F                      /* cpuid */
        _emit 0xA2
        mov features, edx
        pop ebx
    }
    return (features & (1ul << 24)) != 0 && (features & (1ul << 25)) != 0;
}

/* Sets the known x87 state: the control word rounding to nearest, 1.5
 * pushed in ST(0). x87_get pops it: each x87_set has its one x87_get. */
static void x87_set(void)
{
    WORD cw = F2KT_CW_BEFORE;
    double v = 1.5;

    __asm {
        fldcw cw
        fld v
    }
}

/* Reads the control word and pops ST(0). */
static void x87_get(WORD *cw, double *v)
{
    WORD c;
    double d;

    __asm {
        fnstcw c
        fstp d
    }
    *cw = c;
    *v = d;
}

static void xmm0_load(const BYTE *p)
{
    __asm {
        mov eax, p
        _emit 0x0F                      /* movups xmm0, [eax] */
        _emit 0x10
        _emit 0x00
    }
}

static void xmm0_store(BYTE *p)
{
    __asm {
        mov eax, p
        _emit 0x0F                      /* movups [eax], xmm0 */
        _emit 0x11
        _emit 0x00
    }
}

static const char *cw_is(WORD cw)
{
    return cw == F2KT_CW_NEW ? "new" : cw == F2KT_CW_BEFORE ? "before" : "other";
}

static const char *st0_is(double v)
{
    return v == 2.5 ? "new" : v == 1.5 ? "before" : "other";
}

static const char *xmm_is(const BYTE *x)
{
    return memcmp(x, xmm_new, 16) == 0 ? "new" : memcmp(x, xmm_before, 16) == 0 ? "before" : "other";
}

/* What the exception's filter changes (0: FloatSave's x87 state, 1: XMM0
 * in ExtendedRegisters) and what it saw. */
static int g_fp_mode;
static DWORD g_fp_flags;
static int g_fp_seen_cw;
static int g_fp_seen_st0;
static int g_fp_seen_xmm;

static LONG fp_filter(PEXCEPTION_POINTERS ep)
{
    f2kt_context *c = (f2kt_context *)ep->ContextRecord;

    if (ep->ExceptionRecord->ExceptionCode != F2KT_FP_CODE) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    g_fp_flags = c->ContextFlags;
    if (g_fp_mode == 0) {
        g_fp_seen_cw = (c->FloatSave.ControlWord & 0xFFFF) == F2KT_CW_BEFORE;
        g_fp_seen_st0 = memcmp(c->FloatSave.RegisterArea, st0_before, 10) == 0;
        c->FloatSave.ControlWord = (c->FloatSave.ControlWord & 0xFFFF0000ul) | F2KT_CW_NEW;
        memcpy(c->FloatSave.RegisterArea, st0_new, 10);
        c->ContextFlags &= ~F2KT_EXTENDED_BIT;
    } else {
        g_fp_seen_xmm = memcmp(c->ExtendedRegisters + F2KT_XMM0, xmm_before, 16) == 0;
        memcpy(c->ExtendedRegisters + F2KT_XMM0, xmm_new, 16);
        c->ContextFlags &= ~F2KT_FLOATING_BIT;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* RaiseException returns once the filter continues execution. */
static void fp_raise(void)
{
    __try {
        RaiseException(F2KT_FP_CODE, 0, 0, NULL);
    } __except (fp_filter(GetExceptionInformation())) {
    }
}

/* The second thread: it sets the known state, waits to be changed, and
 * records what it then reads. */
static HANDLE g_fp_ready;
static HANDLE g_fp_go;
static int g_fp_sse;
static WORD g_worker_cw;
static double g_worker_st0;
static BYTE g_worker_xmm[16];

static DWORD WINAPI fp_worker(LPVOID p)
{
    (void)p;
    x87_set();
    if (g_fp_sse) {
        xmm0_load(xmm_before);
    }
    SetEvent(g_fp_ready);
    WaitForSingleObject(g_fp_go, WAIT_MS);
    x87_get(&g_worker_cw, &g_worker_st0);
    if (g_fp_sse) {
        xmm0_store(g_worker_xmm);
    }
    return 0;
}

static void fpresume_raise(int sse)
{
    WORD cw;
    double v;
    BYTE xmm[16];

    g_fp_mode = 0;
    g_fp_flags = 0;
    g_fp_seen_cw = 0;
    g_fp_seen_st0 = 0;
    x87_set();
    fp_raise();
    x87_get(&cw, &v);
    line("raise: dispatched flags=0x%08lX, cw as set: %s, st0 as set: %s", (unsigned long)g_fp_flags,
        yesno(g_fp_seen_cw), yesno(g_fp_seen_st0));
    line("raise: resumed from FloatSave changed: cw=%s st0=%s", cw_is(cw), st0_is(v));
    if (!sse) {
        return;
    }
    g_fp_mode = 1;
    g_fp_seen_xmm = 0;
    xmm0_load(xmm_before);
    fp_raise();
    xmm0_store(xmm);
    line("raise: xmm0 as set: %s", yesno(g_fp_seen_xmm));
    line("raise: resumed from ExtendedRegisters changed: xmm0=%s", xmm_is(xmm));
}

static void fpresume_thread(int sse)
{
    f2kt_context ctx;
    HANDLE t;
    DWORD n;
    DWORD w;
    BOOL ok;

    g_fp_sse = sse;
    g_worker_cw = 0;
    g_worker_st0 = 0;
    memset(g_worker_xmm, 0, sizeof g_worker_xmm);
    g_fp_ready = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_fp_go = CreateEventA(NULL, FALSE, FALSE, NULL);
    t = CreateThread(NULL, 0, fp_worker, NULL, 0, NULL);
    if (g_fp_ready == NULL || g_fp_go == NULL || t == NULL) {
        line("thread: CreateEvent or CreateThread failed");
        return;
    }
    if (WaitForSingleObject(g_fp_ready, WAIT_MS) != WAIT_OBJECT_0) {
        line("thread: the worker never got ready");
        SetEvent(g_fp_go);
        WaitForSingleObject(t, WAIT_MS);
        return;
    }

    arm();
    n = SuspendThread(t);
    line("thread: SuspendThread: ret=%lu err=%s", n, le());

    memset(&ctx, 0, sizeof ctx);
    ctx.ContextFlags = CONTEXT_FLOATING_POINT;
    arm();
    ok = GetThreadContext(t, (CONTEXT *)&ctx);
    line("thread: GetThreadContext(FLOATING_POINT): ret=%d err=%s, cw as set: %s, st0 as set: %s", ok, le(),
        yesno((ctx.FloatSave.ControlWord & 0xFFFF) == F2KT_CW_BEFORE),
        yesno(memcmp(ctx.FloatSave.RegisterArea, st0_before, 10) == 0));
    if (ok) {
        ctx.FloatSave.ControlWord = (ctx.FloatSave.ControlWord & 0xFFFF0000ul) | F2KT_CW_NEW;
        memcpy(ctx.FloatSave.RegisterArea, st0_new, 10);
        ctx.ContextFlags = CONTEXT_FLOATING_POINT;
        arm();
        ok = SetThreadContext(t, (CONTEXT *)&ctx);
        line("thread: SetThreadContext(FLOATING_POINT): ret=%d err=%s", ok, le());
    }

    if (sse) {
        memset(&ctx, 0, sizeof ctx);
        ctx.ContextFlags = F2KT_CONTEXT_EXTENDED_REGISTERS;
        arm();
        ok = GetThreadContext(t, (CONTEXT *)&ctx);
        line("thread: GetThreadContext(EXTENDED_REGISTERS): ret=%d err=%s, xmm0 as set: %s", ok, le(),
            yesno(memcmp(ctx.ExtendedRegisters + F2KT_XMM0, xmm_before, 16) == 0));
        if (ok) {
            memcpy(ctx.ExtendedRegisters + F2KT_XMM0, xmm_new, 16);
            ctx.ContextFlags = F2KT_CONTEXT_EXTENDED_REGISTERS;
            arm();
            ok = SetThreadContext(t, (CONTEXT *)&ctx);
            line("thread: SetThreadContext(EXTENDED_REGISTERS): ret=%d err=%s", ok, le());
        }
    }

    arm();
    n = ResumeThread(t);
    line("thread: ResumeThread: ret=%lu err=%s", n, le());
    SetEvent(g_fp_go);
    w = WaitForSingleObject(t, WAIT_MS);
    line("thread: resumed: %s, cw=%s st0=%s", wr(w), cw_is(g_worker_cw), st0_is(g_worker_st0));
    if (sse) {
        line("thread: resumed: xmm0=%s", xmm_is(g_worker_xmm));
    }
    CloseHandle(t);
    CloseHandle(g_fp_go);
    CloseHandle(g_fp_ready);
}

static void sec_fpresume(void)
{
    WORD saved;
    int sse = has_sse();

    __asm fnstcw saved
    if (sse) {
        line("processor: FXSR and SSE");
    } else {
        line("processor: no SSE, the extended state is not tested");
    }
    fpresume_raise(sse);
    __asm fldcw saved
    fpresume_thread(sse);
    __asm fldcw saved
}

/* --- main ---------------------------------------------------------------- */

static const section_t sections[] = {
    { "unhandled", sec_unhandled, F2KT_NAMED },
    { "context", sec_context, F2KT_ALWAYS },
    { "mainret", sec_mainret, F2KT_NAMED },
    { "threadstart", sec_threadstart, F2KT_ALWAYS },
    { "fpresume", sec_fpresume, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("threx", sections, argc, argv);
}
