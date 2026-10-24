/*
 * bare - the image and process contract without a C runtime.
 *
 * No CRT: a custom entry point, kernel32 only. With no argument it
 * checks the image as the loader mapped it and exits with a bitmask of
 * the failed checks (0 when all pass):
 *
 *   bss       64 KiB of .bss reads all zero (then is scribbled over:
 *             the suite runs this twice in one boot, so the second run
 *             catches frames reused without re-zeroing)
 *   data      initialized .data reads back its initializers, including
 *             a three-page object with a zero middle
 *   rdata     a .rdata string hashes to its known value
 *   pointers  a pointer table and a function pointer table baked in by
 *             the linker point at the right places (the image sits at
 *             its preferred base, or was relocated correctly)
 *   esp       the entry stack is 4-byte aligned
 *   stack     256 KiB of stack is usable from the entry point (the main
 *             thread's stack grows on demand through its guard page)
 *
 * With an argument it runs one mode; each is one process in the suite,
 * and the process exit code is the observable:
 *
 *   ret          the entry point returns 42: the process exits with the
 *                entry point's return value
 *   exit-code    ExitProcess(0x87654321): all 32 bits reach the exit code
 *   badptr       WriteFile with kernel and unmapped user buffers fails
 *                with an error code; the process survives and exits 0
 *   data-exec    code copied into .data runs (no NX on Windows 2000)
 *   null-write, null-read, null-call, rdata-write, code-write,
 *   kernel-read, kernel-write, div-zero, ud2, int3, hlt, cli, io-in,
 *   into, stack-overflow
 *                the fault ends the process with its NTSTATUS exit code
 *                and the kernel carries on (the next process runs)
 *
 * The fault modes call SetErrorMode(SEM_NOGPFAULTERRORBOX) first, so
 * the real machine ends the process instead of showing the
 * application-error dialog.
 *
 * Replaces bsscheck and crash.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo bare.c /link /NODEFAULTLIB /ENTRY:BareMain /SUBSYSTEM:CONSOLE kernel32.lib
 *
 * No CRT means no _chkstk and no memset: every local stays below a
 * page and nothing is zero-initialized by the compiler.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* --- Output without a C runtime ------------------------------------ */

static HANDLE out;

static void put(const char *s)
{
    DWORD n = 0;
    DWORD written;

    while (s[n] != 0) {
        n++;
    }
    WriteFile(out, s, n, &written, NULL);
}

static void put_dec(DWORD v)
{
    char buf[12];
    int i = 11;

    buf[i] = 0;
    do {
        buf[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    put(&buf[i]);
}

static void put_hex(DWORD v)
{
    char buf[11];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 8; i++) {
        buf[2 + i] = "0123456789ABCDEF"[(v >> (28 - 4 * i)) & 0xF];
    }
    buf[10] = 0;
    put(buf);
}

static void verdict(const char *what, int ok)
{
    put(what);
    put(ok ? ": ok\r\n" : ": FAIL\r\n");
}

static int str_eq(const char *a, const char *b)
{
    while (*a != 0 && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/* --- The image under test ------------------------------------------ */

/* 16384 DWORDs = 64 KiB of .bss: sixteen pages of fresh-memory proof. */
static DWORD bss_probe[16384];

static DWORD data_probe[4] = { 0x01234567, 0x89ABCDEF, 0xF2F2F2F2, 0x00000001 };

/* Three pages of initialized .data: the zero middle is file-backed. */
static struct {
    DWORD head;
    BYTE mid[8184];
    DWORD tail;
} big_data = { 0x11111111, { 0 }, 0x22222222 };

static const char rdata_probe[] = "F2K rdata probe";
#define RDATA_FNV1A 0x9D6DCC3Au

static DWORD fn_seven(void)
{
    return 7;
}

static DWORD fn_nine(void)
{
    return 9;
}

static DWORD *ptr_table[2] = { &data_probe[0], &data_probe[3] };
static DWORD (*fn_table[2])(void) = { fn_seven, fn_nine };

/* mov eax, 42; ret - executed from .data in the data-exec mode. */
static BYTE exec_probe[8] = { 0xB8, 42, 0, 0, 0, 0xC3, 0x90, 0x90 };

static volatile DWORD zero_divisor;
static volatile DWORD recurse_forever = 1;

/* Touch 2 KiB per frame, highest address first, so the stack grows one
 * guard page at a time. Returns the deepest frame's marker. */
static DWORD stack_walk(DWORD depth)
{
    volatile BYTE pad[2048];

    pad[2047] = (BYTE)depth;
    pad[0] = (BYTE)depth;
    if (depth == 0) {
        return pad[0];
    }
    return stack_walk(depth - 1) + pad[2047] - pad[0];
}

static DWORD overflow(DWORD depth)
{
    volatile BYTE pad[1024];

    pad[1023] = (BYTE)depth;
    pad[0] = (BYTE)depth;
    if (recurse_forever) {
        return overflow(depth + 1) + pad[0];
    }
    return pad[1023];
}

/* --- Default mode: the image checks --------------------------------- */

static DWORD check_image(DWORD entry_esp)
{
    DWORD failed = 0;
    DWORD i;
    DWORD h;
    int ok;

    ok = 1;
    for (i = 0; i < 16384; i++) {
        if (bss_probe[i] != 0) {
            ok = 0;
            break;
        }
    }
    for (i = 0; i < 16384; i++) {
        bss_probe[i] = 0x5A5AA5A5u ^ i;
    }
    verdict("bss: 64 KiB zero", ok);
    failed |= ok ? 0 : 0x01;

    ok = data_probe[0] == 0x01234567 && data_probe[1] == 0x89ABCDEF &&
         data_probe[2] == 0xF2F2F2F2 && data_probe[3] == 0x00000001;
    verdict("data: initializers", ok);
    failed |= ok ? 0 : 0x02;

    ok = big_data.head == 0x11111111 && big_data.tail == 0x22222222;
    for (i = 0; i < sizeof big_data.mid; i++) {
        if (big_data.mid[i] != 0) {
            ok = 0;
            break;
        }
    }
    verdict("data: three-page object", ok);
    failed |= ok ? 0 : 0x04;

    h = 0x811C9DC5u;
    for (i = 0; rdata_probe[i] != 0; i++) {
        h = (h ^ (BYTE)rdata_probe[i]) * 0x01000193u;
    }
    ok = h == RDATA_FNV1A && i == 15;
    verdict("rdata: string hash", ok);
    failed |= ok ? 0 : 0x08;

    ok = ptr_table[0] == &data_probe[0] && ptr_table[1] - ptr_table[0] == 3 &&
         *ptr_table[1] == 1;
    verdict("pointers: data table", ok);
    failed |= ok ? 0 : 0x10;

    ok = fn_table[0]() == 7 && fn_table[1]() == 9;
    verdict("pointers: function table", ok);
    failed |= ok ? 0 : 0x20;

    ok = (entry_esp & 3) == 0;
    verdict("esp: 4-byte aligned at entry", ok);
    failed |= ok ? 0 : 0x40;

    /* Last: on a kernel without stack growth this faults. */
    ok = stack_walk(128) == 0;
    verdict("stack: 256 KiB usable", ok);
    failed |= ok ? 0 : 0x80;

    return failed;
}

/* --- Modes --------------------------------------------------------- */

static void badptr(void)
{
    DWORD written;
    BOOL r;

    SetLastError(0);
    r = WriteFile(out, (const void *)0x80000000, 4, &written, NULL);
    put("WriteFile from a kernel address: ret=");
    put_dec((DWORD)r);
    put(" err=");
    put_dec(GetLastError());
    put("\r\n");

    SetLastError(0);
    r = WriteFile(out, (const void *)0x00000010, 4, &written, NULL);
    put("WriteFile from an unmapped user address: ret=");
    put_dec((DWORD)r);
    put(" err=");
    put_dec(GetLastError());
    put("\r\n");

    put("badptr: survived\r\n");
}

static void fault(const char *mode)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    put("fault: ");
    put(mode);
    put("\r\n");

    if (str_eq(mode, "null-write")) {
        *(volatile DWORD *)0 = 0xDEADBEEFu;
    } else if (str_eq(mode, "null-read")) {
        zero_divisor = *(volatile DWORD *)0;
    } else if (str_eq(mode, "null-call")) {
        DWORD (*volatile fn)(void) = 0;
        fn();
    } else if (str_eq(mode, "rdata-write")) {
        *(volatile char *)rdata_probe = 'x';
    } else if (str_eq(mode, "code-write")) {
        *(volatile BYTE *)fn_seven = 0xC3;
    } else if (str_eq(mode, "kernel-read")) {
        zero_divisor = *(volatile DWORD *)0x80000000;
    } else if (str_eq(mode, "kernel-write")) {
        *(volatile DWORD *)0x80001000 = 1;
    } else if (str_eq(mode, "div-zero")) {
        zero_divisor = 1 / zero_divisor;
    } else if (str_eq(mode, "ud2")) {
        __asm _emit 0x0F
        __asm _emit 0x0B
    } else if (str_eq(mode, "int3")) {
        __asm int 3
    } else if (str_eq(mode, "hlt")) {
        __asm hlt
    } else if (str_eq(mode, "cli")) {
        __asm cli
    } else if (str_eq(mode, "io-in")) {
        __asm {
            mov dx, 0x60
            in al, dx
        }
    } else if (str_eq(mode, "into")) {
        __asm {
            mov al, 0x7F
            add al, 1
            into
        }
    } else if (str_eq(mode, "stack-overflow")) {
        overflow(0);
    } else {
        put("bare: unknown mode\r\n");
        ExitProcess(2);
    }
    put("fault: survived\r\n");
    ExitProcess(1);
}

/* The first word after the program name on the command line, or "". */
static const char *mode_arg(char *buf, int size)
{
    const char *p = GetCommandLineA();
    int n = 0;

    if (*p == '"') {
        p++;
        while (*p != 0 && *p != '"') {
            p++;
        }
        if (*p == '"') {
            p++;
        }
    } else {
        while (*p != 0 && *p != ' ' && *p != '\t') {
            p++;
        }
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    while (*p != 0 && *p != ' ' && *p != '\t' && n < size - 1) {
        buf[n++] = *p++;
    }
    buf[n] = 0;
    return buf;
}

DWORD WINAPI BareMain(void)
{
    DWORD entry_esp;
    char buf[32];
    const char *mode;
    DWORD failed;

    __asm mov entry_esp, esp

    out = GetStdHandle(STD_OUTPUT_HANDLE);
    mode = mode_arg(buf, sizeof buf);

    if (mode[0] == 0) {
        failed = check_image(entry_esp);
        put("bare: failed mask ");
        put_hex(failed);
        put("\r\n");
        ExitProcess(failed);
    }
    if (str_eq(mode, "ret")) {
        put("ret: returning 42 from the entry point\r\n");
        return 42;
    }
    if (str_eq(mode, "exit-code")) {
        put("exit-code: ExitProcess(0x87654321)\r\n");
        ExitProcess(0x87654321u);
    }
    if (str_eq(mode, "badptr")) {
        badptr();
        ExitProcess(0);
    }
    if (str_eq(mode, "data-exec")) {
        put("data-exec: returned ");
        put_dec(((DWORD (*)(void))(void *)exec_probe)());
        put("\r\n");
        ExitProcess(0);
    }
    fault(mode);
    return 1;
}
