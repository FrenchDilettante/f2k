/*
 * drvload - the plumbing a legacy driver lives on, and the NT layouts it
 * reads: ntdll's NtLoadDriver and NtUnloadDriver over a service key the
 * program writes itself, the DRIVER_OBJECT DriverEntry is handed, the
 * DEVICE_OBJECT IoCreateDevice makes, the IRPs the dispatch routines see,
 * and the unload. The program is the companion of drvload.sys (built
 * beside it from drvloadsys.c, common/f2kd.h): each driver section loads
 * the driver, asks it to run the section and prints what it returns,
 * then unloads it (common/f2kdhost.h); the program's own sections take
 * those steps one at a time and print each.
 *
 * Every NT status prints in hex. The driver prints no address: a pointer
 * prints as NULL or not, or as a relation (the driver's own, inside its
 * image, the device's); a process or thread as the caller's or not, or
 * the System process (PsInitialSystemProcess) or not. The structures'
 * fields print with their offsets in the DDK's declarations.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   load        the program's steps, each printed: NtLoadDriver with
 *               SeLoadDriverPrivilege disabled, on a service key that
 *               does not exist, on the fixture's key, and again while
 *               loaded; CreateFileA on \\.\F2Kdrvload; NtUnloadDriver,
 *               and again; CreateFileA once unloaded; a second load;
 *               NtUnloadDriver with the privilege disabled, then enabled;
 *               NtLoadDriver once the key is deleted
 *   entry       what DriverEntry saw: its IRQL, its process (the System
 *               process?) and previous mode; the DRIVER_OBJECT's fields
 *               (Type, Size, Flags, DriverStart against the image's
 *               header, DriverSize against its SizeOfImage, DriverSection,
 *               the DRIVER_EXTENSION and its ServiceKeyName, DriverName,
 *               HardwareDatabase, FastIoDispatch, DriverInit against the
 *               image's entry point, DriverStartIo, DriverUnload, the
 *               MajorFunction defaults: one routine, outside the image);
 *               the RegistryPath; then the DEVICE_OBJECT IoCreateDevice
 *               made (each field, DO_DEVICE_INITIALIZING still set) and
 *               the DriverObject's list
 *   create      the IRP_MJ_CREATE of the program's CreateFileA: IRQL,
 *               previous mode, the IRP's Type, Size, Flags, RequestorMode,
 *               StackCount and CurrentLocation, the stack location's
 *               codes, Create.Options, FileAttributes, ShareAccess and
 *               DesiredAccess, the FILE_OBJECT's fields, the device's
 *               flags once DriverEntry returned, and the process and
 *               thread it came in (the caller's?)
 *   ioctl       the IRP_MJ_DEVICE_CONTROL carrying the section itself: the
 *               same, with the buffered I/O fields and the lengths
 *   irps        every IRP since the load, in order (a second handle
 *               opened and closed first: its create, cleanup and close),
 *               each with its IRQL, modes and process
 *   device      IoCreateDevice with an extension (its size, place and
 *               contents, the DriverObject's list, and IoDeleteDevice's),
 *               exclusive with FILE_DEVICE_SECURE_OPEN, and of
 *               FILE_DEVICE_DISK (its VPB and sector size)
 *   unknown     what the I/O manager answers for the driver: an I/O
 *               control code it does not handle, a request too short
 *               for it, and ReadFile, WriteFile and FlushFileBuffers,
 *               whose major functions it never set
 *   unload      NtUnloadDriver with no handle open: its status, and what
 *               the unload routine saw (IRQL, process, the device still
 *               listed, then gone), read back from the F2KUnload value it
 *               writes under the service key
 *   unloadopen  NtUnloadDriver with a handle open: its status, whether
 *               the unload ran, CreateFileA and DeviceIoControl
 *               meanwhile, then the handle closed and what the unload saw
 *   pendirp     a request the driver holds pending (IoMarkIrpPending,
 *               STATUS_PENDING) from a thread's DeviceIoControl on a
 *               synchronous handle, completed by a second request on a
 *               second handle (the inverted call): whether the first
 *               still waits, the driver's record of both (the stack's
 *               Control, PendingReturned, the completing thread), then
 *               the first one's return, its bytes and its output
 *   names      IoCreateDevice on a name taken and in a directory that
 *               does not exist; IoCreateSymbolicLink on a name taken, a
 *               new one, to a device that does not exist; and
 *               IoDeleteSymbolicLink, twice. Last: on Windows 2000 the
 *               two refused IoCreateDevice calls leave a reference on the
 *               driver that is never dropped, so once it is unloaded its
 *               \Driver name is gone but its image stays loaded, and every
 *               later NtLoadDriver of the service fails with
 *               STATUS_OBJECT_NAME_NOT_FOUND until the machine restarts
 *
 * The program needs an administrator's token: SeLoadDriverPrivilege.
 *
 * Build (real Windows 2000 machine, MSVC 6 and the Windows 2000 DDK;
 * tests\build.bat drvload):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% drvload.c advapi32.lib
 *   and drvload.sys from drvloadsys.c (tests\build.bat's :driver)
 */

#define F2KD_NAME "drvload"
#include "../common/f2kt.h"
#include "../common/f2kdhost.h"

/* A service key that is never written. */
#define NO_KEY L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\F2KdrvloadNone"

/* CreateFileA on the device, as printed; closes what it opened. */
static void try_open(const char *label)
{
    HANDLE h;
    const char *e;

    arm();
    h = CreateFileA(F2KD_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    e = le();
    line("%s: CreateFileA(\\\\.\\F2Kdrvload): handle %s err=%s", label, yesno(h != INVALID_HANDLE_VALUE), e);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
}

/* The unload routine's record, printed (or that there is none). */
static void print_unload_record(const char *label)
{
    static char text[F2KD_OUTPUT];

    if (!f2kd_unload_record(text, sizeof text)) {
        line("%s: the unload routine's record: none", label);
        return;
    }
    line("%s: the unload routine's record:", label);
    f2kd_print(text, (DWORD)strlen(text));
}

static void sec_load(void)
{
    ULONG status;

    f2kd_leftover();
    line("the service key written: %s", yesno(f2kd_install()));
    line("SeLoadDriverPrivilege disabled: %s", yesno(f2kd_privilege(FALSE)));
    status = f2kd_load();
    line("NtLoadDriver(F2Kdrvload), the privilege disabled: %s", f2kd_status(status));
    if (status == F2KD_NO_CALL) {
        f2kd_remove();
        return;
    }
    if (status == 0) {
        f2kd_privilege(TRUE);
        f2kd_unload();
    }
    line("SeLoadDriverPrivilege enabled: %s", yesno(f2kd_privilege(TRUE)));
    line("NtLoadDriver(a key that does not exist): %s", f2kd_status(f2kd_nt("NtLoadDriver", NO_KEY)));
    line("NtLoadDriver(F2Kdrvload): %s", f2kd_status(f2kd_load()));
    line("NtLoadDriver(F2Kdrvload), loaded: %s", f2kd_status(f2kd_load()));
    try_open("loaded");
    line("NtUnloadDriver(F2Kdrvload): %s", f2kd_status(f2kd_unload()));
    line("NtUnloadDriver(F2Kdrvload), unloaded: %s", f2kd_status(f2kd_unload()));
    try_open("unloaded");
    line("NtLoadDriver(F2Kdrvload), again: %s", f2kd_status(f2kd_load()));
    try_open("loaded again");
    line("SeLoadDriverPrivilege disabled: %s", yesno(f2kd_privilege(FALSE)));
    line("NtUnloadDriver(F2Kdrvload), the privilege disabled: %s", f2kd_status(f2kd_unload()));
    line("SeLoadDriverPrivilege enabled: %s", yesno(f2kd_privilege(TRUE)));
    line("NtUnloadDriver(F2Kdrvload): %s", f2kd_status(f2kd_unload()));
    line("the service key deleted: %s", yesno(f2kd_remove()));
    line("NtLoadDriver(F2Kdrvload), its key deleted: %s", f2kd_status(f2kd_load()));
    f2kd_leftover();
}

F2KD_SECTION(entry)
F2KD_SECTION(create)
F2KD_SECTION(ioctl)
F2KD_SECTION(device)
F2KD_SECTION(names)

/* A second handle opened (no request of its own) and closed before the
 * driver lists the IRPs. */
static void sec_irps(void)
{
    HANDLE h;
    HANDLE second;

    if (!f2kd_begin()) {
        return;
    }
    h = f2kd_open();
    if (h != INVALID_HANDLE_VALUE) {
        second = CreateFileA(F2KD_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (second == INVALID_HANDLE_VALUE) {
            line("a second handle: err=%lu", GetLastError());
        } else {
            CloseHandle(second);
        }
        f2kd_call(h, "irps");
        CloseHandle(h);
    }
    f2kd_end();
}

static void sec_unknown(void)
{
    HANDLE h;
    char buf[64];
    DWORD got;
    BOOL ok;
    const char *e;

    if (!f2kd_begin()) {
        return;
    }
    h = f2kd_open();
    if (h != INVALID_HANDLE_VALUE) {
        got = 0xF2F2;
        arm();
        ok = DeviceIoControl(h, F2KD_IOCTL_UNKNOWN, buf, 8, buf, sizeof buf, &got, NULL);
        e = le();
        line("DeviceIoControl(a code the driver does not handle): ret=%d err=%s returned=%lu", ok, e, got);

        got = 0xF2F2;
        arm();
        ok = DeviceIoControl(h, F2KD_IOCTL_RUN, buf, 4, buf, sizeof buf, &got, NULL);
        e = le();
        line("DeviceIoControl(the run code, 4 bytes in; the driver answers STATUS_INVALID_PARAMETER): ret=%d "
             "err=%s returned=%lu", ok, e, got);

        got = 0xF2F2;
        arm();
        ok = ReadFile(h, buf, sizeof buf, &got, NULL);
        e = le();
        line("ReadFile: ret=%d err=%s read=%lu", ok, e, got);

        got = 0xF2F2;
        arm();
        ok = WriteFile(h, buf, 8, &got, NULL);
        e = le();
        line("WriteFile: ret=%d err=%s written=%lu", ok, e, got);

        arm();
        ok = FlushFileBuffers(h);
        e = le();
        line("FlushFileBuffers: ret=%d err=%s", ok, e);
        CloseHandle(h);
    }
    f2kd_end();
}

static void sec_unload(void)
{
    HANDLE h;

    if (!f2kd_begin()) {
        return;
    }
    h = f2kd_open();
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    line("NtUnloadDriver(F2Kdrvload), no handle open: %s", f2kd_status(f2kd_unload()));
    print_unload_record("when it returned");
    if (!f2kd_remove()) {
        line("f2kd: the service key: not deleted");
    }
}

static void sec_unloadopen(void)
{
    static char text[F2KD_OUTPUT];
    HANDLE h;
    char stamp[64];
    DWORD got;
    BOOL ok;
    const char *e;
    int waited;

    if (!f2kd_begin()) {
        return;
    }
    h = f2kd_open();
    if (h == INVALID_HANDLE_VALUE) {
        f2kd_end();
        return;
    }
    line("NtUnloadDriver(F2Kdrvload), a handle open: %s", f2kd_status(f2kd_unload()));
    line("the unload routine ran: %s", yesno(f2kd_unload_record(text, sizeof text)));
    try_open("unload pending");

    got = 0xF2F2;
    arm();
    ok = DeviceIoControl(h, F2KD_IOCTL_STAMP, NULL, 0, stamp, sizeof stamp, &got, NULL);
    e = le();
    line("DeviceIoControl on the open handle: ret=%d err=%s", ok, e);
    line("the unload routine ran: %s", yesno(f2kd_unload_record(text, sizeof text)));

    CloseHandle(h);
    /* The unload may run on another thread: up to two seconds for it. */
    for (waited = 0; waited < 100 && !f2kd_unload_record(text, sizeof text); waited++) {
        Sleep(20);
    }
    print_unload_record("the handle closed");
    line("NtUnloadDriver(F2Kdrvload), then: %s", f2kd_status(f2kd_unload()));
    if (!f2kd_remove()) {
        line("f2kd: the service key: not deleted");
    }
}

/* The pending request, issued by a thread of its own on the first
 * handle: its result, for the main thread to print. */
typedef struct {
    HANDLE h;
    BOOL ok;
    DWORD err;
    DWORD got;
    char out[64];
    volatile LONG done;
} pend_call_t;

static DWORD WINAPI pend_thread(LPVOID param)
{
    pend_call_t *c = (pend_call_t *)param;
    char in[4];

    memcpy(in, "ping", sizeof in);
    memset(c->out, '#', sizeof c->out);
    c->got = 0xF2F2;
    SetLastError(F2KT_UNTOUCHED);
    c->ok = DeviceIoControl(c->h, F2KD_IOCTL_PEND, in, sizeof in, c->out, sizeof c->out, &c->got, NULL);
    c->err = GetLastError();
    InterlockedExchange((LONG *)&c->done, 1);
    return 0;
}

/* A request the driver holds pending (the inverted call): a thread's
 * DeviceIoControl on a synchronous handle, which the driver marks pending
 * and keeps; the main thread, on a second handle (the first one's I/O
 * is serialized while the thread waits), asks whether it is held, then
 * releases it: the driver writes its output and completes it. Released
 * only while the thread still waits: a request that ended while the
 * driver holds its IRP has had its buffers freed. */
static void sec_pendirp(void)
{
    static pend_call_t call;
    static char text[F2KD_OUTPUT];
    HANDLE h;
    HANDLE second;
    HANDLE thread;
    DWORD tid;
    DWORD got;
    ULONG is_held = 0;
    BOOL waiting;
    BOOL ok;
    const char *e;
    int i;
    int n;

    if (!f2kd_begin()) {
        return;
    }
    h = f2kd_open();
    if (h == INVALID_HANDLE_VALUE) {
        f2kd_end();
        return;
    }
    second = CreateFileA(F2KD_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (second == INVALID_HANDLE_VALUE) {
        line("a second handle: err=%lu", GetLastError());
        CloseHandle(h);
        f2kd_end();
        return;
    }
    call.h = h;
    thread = CreateThread(NULL, 0, pend_thread, &call, 0, &tid);
    if (thread == NULL) {
        line("CreateThread: err=%lu", GetLastError());
        CloseHandle(second);
        CloseHandle(h);
        f2kd_end();
        return;
    }
    /* Up to five seconds for the driver to hold it. */
    for (i = 0; i < 250 && !call.done; i++) {
        is_held = 0;
        got = 0;
        if (DeviceIoControl(second, F2KD_IOCTL_HELD, NULL, 0, &is_held, sizeof is_held, &got, NULL) && is_held) {
            break;
        }
        Sleep(20);
    }
    line("the driver holds the first request: %s", yesno(is_held));
    waiting = WaitForSingleObject(thread, 200) == WAIT_TIMEOUT;
    line("the first DeviceIoControl (a synchronous handle) still waiting: %s", yesno(waiting));
    if (is_held && waiting) {
        got = 0xF2F2;
        arm();
        ok = DeviceIoControl(second, F2KD_IOCTL_RELEASE, NULL, 0, text, sizeof text, &got, NULL);
        e = le();
        line("DeviceIoControl(release, on the second handle): ret=%d err=%s, the driver's record:", ok, e);
        if (ok) {
            f2kd_print(text, got > sizeof text ? sizeof text : got);
        }
    } else if (is_held) {
        line("not released: the first DeviceIoControl ended while the driver holds its request");
    }
    line("the first DeviceIoControl returned: %s", yesno(WaitForSingleObject(thread, WAIT_MS) == WAIT_OBJECT_0));
    if (call.done) {
        line("  ret=%d err=%s returned=%lu", call.ok, le_of(call.err), call.got);
        n = call.got <= sizeof call.out ? (int)call.got : 0;
        line("  its output: \"%.*s\"", n > 0 && call.out[n - 1] == '\0' ? n - 1 : n, call.out);
        line("  the byte after it untouched: %s", yesno(n < (int)sizeof call.out && call.out[n] == '#'));
    }
    CloseHandle(thread);
    CloseHandle(second);
    CloseHandle(h);
    f2kd_end();
}

static const section_t sections[] = {
    { "load", sec_load, F2KT_ALWAYS },
    { "entry", sec_entry, F2KT_ALWAYS },
    { "create", sec_create, F2KT_ALWAYS },
    { "ioctl", sec_ioctl, F2KT_ALWAYS },
    { "irps", sec_irps, F2KT_ALWAYS },
    { "device", sec_device, F2KT_ALWAYS },
    { "unknown", sec_unknown, F2KT_ALWAYS },
    { "unload", sec_unload, F2KT_ALWAYS },
    { "unloadopen", sec_unloadopen, F2KT_ALWAYS },
    { "pendirp", sec_pendirp, F2KT_ALWAYS },
    { "names", sec_names, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("drvload", sections, argc, argv);
}
