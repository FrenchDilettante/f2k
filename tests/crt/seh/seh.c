/*
 * seh - structured exception handling and setjmp/longjmp under /MD:
 * msvcrt.dll's frame handler and jump buffer, as cmd.exe uses them.
 *
 * Built with /MD, every __try in this program registers msvcrt.dll's
 * _except_handler3 (MSVC's public scope-table frame layout); a return
 * out of a __try/__finally calls its _local_unwind2, AbnormalTermination
 * its _abnormal_termination. setjmp compiles into _setjmp3; in a function
 * with a __try, the compiler hands _setjmp3 the try level and
 * _seh_longjmp_unwind, which longjmp calls to run the __finally blocks
 * it jumps out of.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   faults    hardware faults caught by __except: the filter's record
 *             (code, flags, parameters), GetExceptionCode in the handler
 *   filters   the filter's results: EXECUTE_HANDLER, CONTINUE_SEARCH to
 *             an outer handler, CONTINUE_EXECUTION after the filter
 *             fixed the cause (a read-only page made writable), after a
 *             continuable RaiseException, and after a noncontinuable one
 *             (the exception that follows, and the record it chains)
 *   finally   __finally on a normal exit, after __leave, after a return
 *             out of the __try, and while an exception unwinds through
 *             it (through two functions, and past a CONTINUE_SEARCH
 *             filter); AbnormalTermination in each
 *   nested    three try levels in one function, an exception passing
 *             through them; sibling __try blocks after a handled one
 *   raise     RaiseException's arguments as the filter sees them: none,
 *             two, fifteen, sixteen, a NULL array, the noncontinuable
 *             flag, the reserved bit 28 of the code, a code without the
 *             customer bit
 *   setjmp    setjmp/longjmp: a plain jump, from nested calls, the value
 *             0 returned as 1, a volatile local's value after the jump,
 *             a buffer reused for several jumps
 *   sehjmp    longjmp out of __try blocks: from a call inside a
 *             __try/__finally of the setjmp's function, through a
 *             __finally in an intermediate function, out of an __except
 *             handler, and from an inner try level back to an outer one;
 *             which __finally blocks run
 *
 * The unwind sections: a fault inside a C runtime call that holds one
 * of its locks, caught by the program's __except. The unwind leaves the
 * call's frames, and the lock goes with them, so the same stream, or
 * another thread, can be used again. Every stdio line of a section is
 * flushed before the section's own lines print, so the order is the
 * same whether the standard output is a file or a console.
 *
 *   unwindout    printf("%s") of a bad pointer to stdout, caught; then
 *                printf again
 *   unwinderr    the same through fprintf(stderr)
 *   unwindfile   the same through fprintf to a file the program made
 *                (a buffered stream), then the file read back
 *   unwindgets   fgets into a bad buffer from a file, caught; then fgets
 *                into a good one: what the second call reads
 *   unwindwrite  _write(1) of a bad buffer (text mode reads it to
 *                translate line ends), caught; then _write(1) again
 *   unwindthread after a caught printf fault on the main thread, a
 *                second thread's printf (the stream's lock released, or
 *                the thread waits: the main thread's wait is bounded)
 *   filterprint  printf on stdout from inside an __except filter, while
 *                the faulting printf on the same stream is still active
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat seh):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% seh.c
 */

#include "../common/f2kt.h"
#include <setjmp.h>
#include <io.h>

/* --- helpers ------------------------------------------------------- */

static DWORD seen_code;
static DWORD seen_flags;
static DWORD seen_params;
static DWORD seen_info[EXCEPTION_MAXIMUM_PARAMETERS];
static DWORD seen_chained;      /* the chained record's code, 0 for none */
static int filter_calls;
static char trail[512];

/* Append to the trail (by hand: strcat would be one more import). */
static void mark(const char *what)
{
    int n = 0;

    while (trail[n] != 0) {
        n++;
    }
    if (n != 0 && n < (int)sizeof trail - 2) {
        trail[n++] = ',';
        trail[n++] = ' ';
    }
    while (*what != 0 && n < (int)sizeof trail - 1) {
        trail[n++] = *what++;
    }
    trail[n] = 0;
}

/* Record the exception the filter sees, and answer `result`. */
static int capture(EXCEPTION_POINTERS *ep, int result)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    DWORD i;

    filter_calls++;
    seen_code = er->ExceptionCode;
    seen_flags = er->ExceptionFlags;
    seen_params = er->NumberParameters;
    for (i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++) {
        seen_info[i] = i < er->NumberParameters ? er->ExceptionInformation[i] : 0;
    }
    seen_chained = er->ExceptionRecord != NULL ? er->ExceptionRecord->ExceptionCode : 0;
    return result;
}

static void clear_seen(void)
{
    int i;

    seen_code = 0;
    seen_flags = 0;
    seen_params = 0;
    seen_chained = 0;
    filter_calls = 0;
    for (i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++) {
        seen_info[i] = 0;
    }
}

/* The record as the filter saw it; the parameters only when `info`
 * (some carry addresses). */
static void report(const char *what, int handled, int info)
{
    char params[256];
    DWORD i;
    int n = 0;

    params[0] = 0;
    if (info) {
        for (i = 0; i < seen_params && i < EXCEPTION_MAXIMUM_PARAMETERS; i++) {
            n += sprintf(params + n, " %lX", (unsigned long)seen_info[i]);
        }
    }
    line("%s: handled %s code 0x%08lX flags %lu params %lu%s%s", what, yesno(handled), seen_code,
         seen_flags, seen_params, info && seen_params != 0 ? " info" : "", params);
}

static int filter_mark(const char *what, int result)
{
    mark(what);
    return result;
}

static volatile int zero_int;

/* --- faults -------------------------------------------------------- */

static void sec_faults(void)
{
    int handled;
    DWORD code;
    volatile int x;

    clear_seen();
    handled = 0;
    code = 0;
    __try {
        *(volatile int *)0 = 1;
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
        code = GetExceptionCode();
    }
    report("write to NULL", handled, 1);
    line("write to NULL: GetExceptionCode in the handler 0x%08lX", code);

    clear_seen();
    handled = 0;
    __try {
        x = *(volatile int *)0x10;
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("read from 0x10", handled, 1);

    clear_seen();
    handled = 0;
    code = 0;
    __try {
        x = 1 / zero_int;
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
        code = GetExceptionCode();
    }
    report("integer divide by zero", handled, 1);
    line("integer divide by zero: GetExceptionCode in the handler 0x%08lX", code);

    /* The breakpoint's parameters carry an address: not printed. */
    clear_seen();
    handled = 0;
    __try {
        __asm int 3
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("int 3", handled, 0);

    clear_seen();
    handled = 0;
    __try {
        __asm hlt
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report("hlt", handled, 1);

    /* A filter's GetExceptionCode, without the record. */
    code = 0;
    __try {
        *(volatile int *)0 = 2;
    } __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        handled = 1;
    }
    line("GetExceptionCode in the filter: 0x%08lX", code);
}

/* --- filters ------------------------------------------------------- */

static void raise_plain(DWORD code)
{
    RaiseException(code, 0, 0, NULL);
}

static void *ro_page;

/* The filter that fixes the cause: the page made writable, the faulting
 * write resumed. Anything else is handled. */
static int make_writable(EXCEPTION_POINTERS *ep)
{
    DWORD old;
    BOOL r;

    capture(ep, 0);
    mark("filter");
    if (seen_code != EXCEPTION_ACCESS_VIOLATION || filter_calls > 1) {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    r = VirtualProtect(ro_page, 4096, PAGE_READWRITE, &old);
    mark(r ? "page made writable" : "VirtualProtect failed");
    return r ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_EXECUTE_HANDLER;
}

/* The filter of the noncontinuable case: continue the first exception,
 * handle the next. */
static int continue_first(EXCEPTION_POINTERS *ep)
{
    char what[96];

    capture(ep, 0);
    sprintf(what, "filter 0x%08lX flags %lu", seen_code, seen_flags);
    mark(what);
    if (filter_calls == 1) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static void sec_filters(void)
{
    volatile int *page;
    volatile int handled;

    trail[0] = 0;
    __try {
        mark("try");
        raise_plain(0xE0000001);
        mark("not reached");
    } __except (filter_mark("filter (execute handler)", EXCEPTION_EXECUTE_HANDLER)) {
        mark("handler");
    }
    mark("after");
    line("execute handler: %s", trail);

    trail[0] = 0;
    __try {
        __try {
            raise_plain(0xE0000002);
        } __except (filter_mark("inner filter (continue search)", EXCEPTION_CONTINUE_SEARCH)) {
            mark("inner handler");
        }
        mark("not reached");
    } __except (filter_mark("outer filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("outer handler");
    }
    line("continue search, one function: %s", trail);

    trail[0] = 0;
    clear_seen();
    page = (volatile int *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    ro_page = (void *)page;
    line("VirtualAlloc(PAGE_READONLY): %s", yesno(page != NULL));
    if (page != NULL) {
        handled = 0;
        __try {
            mark("write");
            page[1] = 42;
            mark("write resumed");
        } __except (make_writable(GetExceptionInformation())) {
            handled = 1;
            mark("handler");
        }
        line("continue execution after the fix: %s", trail);
        line("continue execution after the fix: filter calls %d, code 0x%08lX, info %lX, value %d, handler ran %s",
             filter_calls, seen_code, (unsigned long)seen_info[0], page[1], yesno(handled));
        VirtualFree((void *)page, 0, MEM_RELEASE);
    }

    trail[0] = 0;
    clear_seen();
    handled = 0;
    __try {
        RaiseException(0xE0000003, 0, 0, NULL);
        mark("RaiseException returned");
    } __except (capture(GetExceptionInformation(), EXCEPTION_CONTINUE_EXECUTION)) {
        handled = 1;
    }
    line("continue execution, continuable: %s; filter calls %d, handler ran %s",
         trail, filter_calls, yesno(handled));

    trail[0] = 0;
    clear_seen();
    handled = 0;
    __try {
        RaiseException(0xE0000004, EXCEPTION_NONCONTINUABLE, 0, NULL);
        mark("RaiseException returned");
    } __except (continue_first(GetExceptionInformation())) {
        handled = 1;
        mark("handler");
    }
    line("continue execution, noncontinuable: %s", trail);
    line("continue execution, noncontinuable: filter calls %d, last code 0x%08lX flags %lu, chained 0x%08lX, handler ran %s",
         filter_calls, seen_code, seen_flags, seen_chained, yesno(handled));
}

/* --- finally ------------------------------------------------------- */

static int return_from_try(void)
{
    __try {
        mark("try");
        return 5;
    } __finally {
        mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
    }
    mark("not reached");
    return 0;
}

static void raise_inner(void)
{
    __try {
        mark("inner try");
        RaiseException(0xE0000005, 0, 0, NULL);
        mark("not reached");
    } __finally {
        mark(AbnormalTermination() ? "inner finally (abnormal)" : "inner finally");
    }
}

static void middle(void)
{
    __try {
        raise_inner();
    } __finally {
        mark(AbnormalTermination() ? "middle finally (abnormal)" : "middle finally");
    }
}

static void sec_finally(void)
{
    int r;

    trail[0] = 0;
    __try {
        mark("try");
    } __finally {
        mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
    }
    line("normal exit: %s", trail);

    trail[0] = 0;
    __try {
        mark("try");
        __leave;
        mark("not reached");
    } __finally {
        mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
    }
    line("__leave: %s", trail);

    trail[0] = 0;
    r = return_from_try();
    line("return out of __try: returned %d, %s", r, trail);

    trail[0] = 0;
    __try {
        middle();
    } __except (filter_mark("outer filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("outer handler");
    }
    line("unwind through two functions: %s", trail);

    trail[0] = 0;
    __try {
        __try {
            raise_inner();
        } __except (filter_mark("middle filter (continue search)", EXCEPTION_CONTINUE_SEARCH)) {
            mark("middle handler");
        }
    } __except (filter_mark("outer filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("outer handler");
    }
    line("unwind order: %s", trail);
}

/* --- nested -------------------------------------------------------- */

static void sec_nested(void)
{
    trail[0] = 0;
    __try {
        mark("level 0 try");
        __try {
            mark("level 1 try");
            __try {
                mark("level 2 try");
                RaiseException(0xE0000010, 0, 0, NULL);
                mark("not reached");
            } __finally {
                mark(AbnormalTermination() ? "level 2 finally (abnormal)" : "level 2 finally");
            }
            mark("not reached");
        } __except (filter_mark("level 1 filter (continue search)", EXCEPTION_CONTINUE_SEARCH)) {
            mark("level 1 handler");
        }
        mark("not reached");
    } __except (filter_mark("level 0 filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("level 0 handler");
    }
    line("three levels: %s", trail);

    /* After a handled exception the try level is back at the top: the
       next __try blocks catch their own. */
    trail[0] = 0;
    __try {
        RaiseException(0xE0000011, 0, 0, NULL);
    } __except (filter_mark("first filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("first handler");
    }
    __try {
        RaiseException(0xE0000012, 0, 0, NULL);
    } __except (filter_mark("second filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("second handler");
    }
    __try {
        mark("third try");
    } __except (filter_mark("third filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("third handler");
    }
    line("siblings: %s", trail);

    /* An exception raised in a handler goes to the enclosing level. */
    trail[0] = 0;
    __try {
        __try {
            RaiseException(0xE0000013, 0, 0, NULL);
        } __except (filter_mark("inner filter", EXCEPTION_EXECUTE_HANDLER)) {
            mark("inner handler raises");
            RaiseException(0xE0000014, 0, 0, NULL);
            mark("not reached");
        }
    } __except (capture(GetExceptionInformation(), filter_mark("outer filter", EXCEPTION_EXECUTE_HANDLER))) {
        mark("outer handler");
    }
    line("raised in a handler: %s; the outer filter saw 0x%08lX", trail, seen_code);
}

/* --- raise --------------------------------------------------------- */

static void raise_with(const char *what, DWORD code, DWORD flags, DWORD count, const DWORD *args)
{
    int handled = 0;

    clear_seen();
    __try {
        RaiseException(code, flags, count, args);
    } __except (capture(GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)) {
        handled = 1;
    }
    report(what, handled, 1);
}

static void sec_raise(void)
{
    DWORD args[16];
    int i;

    for (i = 0; i < 16; i++) {
        args[i] = (DWORD)(0x100 + i);
    }
    raise_with("no arguments", 0xE0000020, 0, 0, NULL);
    raise_with("two arguments", 0xE0000021, 0, 2, args);
    raise_with("fifteen arguments", 0xE0000022, 0, 15, args);
    raise_with("sixteen arguments", 0xE0000023, 0, 16, args);
    raise_with("three arguments, a NULL array", 0xE0000024, 0, 3, NULL);
    raise_with("noncontinuable", 0xE0000025, EXCEPTION_NONCONTINUABLE, 1, args);
    raise_with("code 0xF0000027 (bit 28 set)", 0xF0000027, 0, 0, NULL);
    raise_with("code 0x00000028 (customer bit clear)", 0x00000028, 0, 0, NULL);
}

/* --- setjmp -------------------------------------------------------- */

static jmp_buf plain_buf;

static void jump_down(int depth, int value)
{
    if (depth == 0) {
        longjmp(plain_buf, value);
    }
    jump_down(depth - 1, value);
}

static void sec_setjmp(void)
{
    volatile int n;
    volatile int marker;
    volatile int jumps;

    n = setjmp(plain_buf);
    if (n == 0) {
        longjmp(plain_buf, 3);
        line("plain: did not jump");
    } else {
        line("plain: setjmp returned %d", n);
    }

    n = setjmp(plain_buf);
    if (n == 0) {
        jump_down(5, 7);
        line("from nested calls: did not jump");
    } else {
        line("from nested calls: setjmp returned %d", n);
    }

    n = setjmp(plain_buf);
    if (n == 0) {
        longjmp(plain_buf, 0);
        line("value 0: did not jump");
    } else {
        line("value 0: setjmp returned %d", n);
    }

    n = setjmp(plain_buf);
    if (n == 0) {
        longjmp(plain_buf, -1);
    } else {
        line("value -1: setjmp returned %d", n);
    }

    marker = 1;
    n = setjmp(plain_buf);
    if (n == 0) {
        marker = 2;
        jump_down(1, 9);
    } else {
        line("volatile local: setjmp returned %d, marker %d", n, marker);
    }

    jumps = 0;
    n = setjmp(plain_buf);
    if (jumps < 3) {
        jumps++;
        jump_down(0, 10 + jumps);
    }
    line("reused buffer: %d jumps, setjmp last returned %d", jumps, n);
}

/* --- sehjmp -------------------------------------------------------- */

static jmp_buf seh_buf;

static void jump_seh(int depth, int value)
{
    if (depth == 0) {
        longjmp(seh_buf, value);
    }
    jump_seh(depth - 1, value);
}

/* setjmp outside any __try of this function; the longjmp from a call
 * inside its __try/__finally. */
static void jump_out_of_finally(void)
{
    volatile int n;

    trail[0] = 0;
    n = setjmp(seh_buf);
    if (n == 0) {
        __try {
            mark("try");
            jump_seh(2, 4);
            mark("not reached");
        } __finally {
            mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
        }
    } else {
        mark("back at setjmp");
    }
    line("out of this function's __try/__finally: setjmp returned %d; %s", n, trail);
}

static void middle_finally(void)
{
    __try {
        mark("middle try");
        jump_seh(0, 5);
        mark("not reached");
    } __finally {
        mark(AbnormalTermination() ? "middle finally (abnormal)" : "middle finally");
    }
}

/* The longjmp from a __try/__finally in a called function. */
static void jump_through_middle(void)
{
    volatile int n;

    trail[0] = 0;
    n = setjmp(seh_buf);
    if (n == 0) {
        __try {
            mark("try");
            middle_finally();
            mark("not reached");
        } __finally {
            mark(AbnormalTermination() ? "finally (abnormal)" : "finally");
        }
    } else {
        mark("back at setjmp");
    }
    line("through a called function's __finally: setjmp returned %d; %s", n, trail);
}

/* The longjmp out of an __except handler. */
static void jump_out_of_handler(void)
{
    volatile int n;

    trail[0] = 0;
    n = setjmp(seh_buf);
    if (n == 0) {
        __try {
            mark("try");
            RaiseException(0xE0000030, 0, 0, NULL);
        } __except (filter_mark("filter", EXCEPTION_EXECUTE_HANDLER)) {
            mark("handler");
            longjmp(seh_buf, 6);
        }
        mark("not reached");
    } else {
        mark("back at setjmp");
    }
    line("out of an __except handler: setjmp returned %d; %s", n, trail);

    /* The try levels still work after the jump. */
    trail[0] = 0;
    __try {
        RaiseException(0xE0000031, 0, 0, NULL);
    } __except (filter_mark("next filter", EXCEPTION_EXECUTE_HANDLER)) {
        mark("next handler");
    }
    line("after the jump, a new __try: %s", trail);
}

/* setjmp inside a __try (level 0), the longjmp from a level-1 __try:
 * only the level-1 __finally is jumped out of. */
static void jump_between_levels(void)
{
    volatile int n;

    trail[0] = 0;
    __try {
        n = setjmp(seh_buf);
        if (n == 0) {
            __try {
                mark("inner try");
                jump_seh(1, 8);
                mark("not reached");
            } __finally {
                mark(AbnormalTermination() ? "inner finally (abnormal)" : "inner finally");
            }
        } else {
            mark("back at setjmp");
        }
    } __finally {
        mark(AbnormalTermination() ? "outer finally (abnormal)" : "outer finally");
    }
    line("from an inner try level to an outer one: setjmp returned %d; %s", n, trail);
}

static void sec_sehjmp(void)
{
    jump_out_of_finally();
    jump_through_middle();
    jump_out_of_handler();
    jump_between_levels();
}

/* --- the unwind sections ------------------------------------------ */

/* A bad pointer for the C runtime to read or write: the first page is
 * never mapped. */
#define BAD ((char *)1)

/* `name` beside the program (the scratch files the unwind sections
 * make, each deleted first and last). */
static const char *beside(const char *name)
{
    static char path[2 * MAX_PATH];
    char *slash;

    GetModuleFileNameA(NULL, path, MAX_PATH);
    slash = strrchr(path, '\\');
    if (slash != NULL) {
        slash[1] = 0;
    }
    strcat(path, name);
    return path;
}

static void sec_unwindout(void)
{
    DWORD code = 0;

    fflush(stdout);
    __try {
        printf("before %s after\n", BAD);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    printf("caught 0x%08lX\n", code);
    printf("again\n");
    fflush(stdout);
    line("printf on stdout after the caught fault: done");
}

static void sec_unwinderr(void)
{
    DWORD code = 0;

    fflush(stdout);
    __try {
        fprintf(stderr, "before %s after\n", BAD);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    fprintf(stderr, "caught 0x%08lX\n", code);
    fprintf(stderr, "again\n");
    fflush(stderr);
    line("fprintf on stderr after the caught fault: done");
}

static void show_back(const char *path)
{
    char buf[128];
    FILE *f = fopen(path, "r");
    size_t n;

    if (f == NULL) {
        line("  the file: not opened");
        return;
    }
    while (fgets(buf, sizeof buf, f) != NULL) {
        n = strlen(buf);
        if (n > 0 && buf[n - 1] == '\n') {
            buf[--n] = 0;
        }
        line("  the file: [%s]", buf);
    }
    fclose(f);
}

static void sec_unwindfile(void)
{
    const char *path = beside("unwind.tmp");
    DWORD code = 0;
    FILE *f;

    DeleteFileA(path);
    f = fopen(path, "w");
    if (f == NULL) {
        line("fopen(unwind.tmp, w): NULL");
        return;
    }
    __try {
        fprintf(f, "before %s after\n", BAD);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    line("fprintf to the file: caught 0x%08lX", code);
    line("fprintf again ret=%d", fprintf(f, "again\n"));
    line("fclose ret=%d", fclose(f));
    show_back(path);
    DeleteFileA(path);
}

static void sec_unwindgets(void)
{
    const char *path = beside("unwind.tmp");
    char buf[64];
    DWORD code = 0;
    FILE *f;
    size_t n;

    DeleteFileA(path);
    f = fopen(path, "w");
    if (f == NULL) {
        line("fopen(unwind.tmp, w): NULL");
        return;
    }
    fputs("first line\nsecond line\n", f);
    fclose(f);
    f = fopen(path, "r");
    __try {
        fgets(BAD, 10, f);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    line("fgets into a bad buffer: caught 0x%08lX", code);
    if (fgets(buf, sizeof buf, f) == NULL) {
        line("fgets again: NULL");
    } else {
        n = strlen(buf);
        if (n > 0 && buf[n - 1] == '\n') {
            buf[--n] = 0;
        }
        line("fgets again: [%s]", buf);
    }
    fclose(f);
    DeleteFileA(path);
}

static void sec_unwindwrite(void)
{
    DWORD code = 0;
    int r = 0;

    __try {
        r = _write(1, BAD, 5);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    line("_write(1) of a bad buffer: ret=%d caught 0x%08lX", r, code);
    r = _write(1, "written again\n", 14);
    line("_write(1) again ret=%d", r);
}

static DWORD WINAPI unwind_printer(LPVOID parameter)
{
    (void)parameter;
    printf("the second thread printed\n");
    fflush(stdout);
    return 0;
}

static void sec_unwindthread(void)
{
    HANDLE t;
    DWORD id, w, code = 0;

    fflush(stdout);
    __try {
        printf("before %s", BAD);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    printf("[caught 0x%08lX]\n", code);
    fflush(stdout);
    t = CreateThread(NULL, 0, unwind_printer, NULL, 0, &id);
    w = WaitForSingleObject(t, WAIT_MS);
    CloseHandle(t);
    line("the second thread's end: %s", wr(w));
}

static int filter_printed(void)
{
    printf("in the filter\n");
    return EXCEPTION_EXECUTE_HANDLER;
}

static void sec_filterprint(void)
{
    DWORD code = 0;

    fflush(stdout);
    __try {
        printf("before %s after\n", BAD);
    } __except (code = GetExceptionCode(), filter_printed()) {
        printf("in the handler\n");
    }
    printf("caught 0x%08lX\n", code);
    fflush(stdout);
    line("printf from the filter: done");
}

static const section_t sections[] = {
    { "faults", sec_faults, F2KT_ALWAYS },
    { "filters", sec_filters, F2KT_ALWAYS },
    { "finally", sec_finally, F2KT_ALWAYS },
    { "nested", sec_nested, F2KT_ALWAYS },
    { "raise", sec_raise, F2KT_ALWAYS },
    { "setjmp", sec_setjmp, F2KT_ALWAYS },
    { "sehjmp", sec_sehjmp, F2KT_ALWAYS },
    { "unwindout", sec_unwindout, F2KT_ALWAYS },
    { "unwinderr", sec_unwinderr, F2KT_ALWAYS },
    { "unwindfile", sec_unwindfile, F2KT_ALWAYS },
    { "unwindgets", sec_unwindgets, F2KT_ALWAYS },
    { "unwindwrite", sec_unwindwrite, F2KT_ALWAYS },
    { "unwindthread", sec_unwindthread, F2KT_ALWAYS },
    { "filterprint", sec_filterprint, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("seh", sections, argc, argv);
}
