/*
 * f2kd.h - the driver side of the corpus's kernel-mode fixtures.
 *
 * A kernel-mode fixture is a driver, <name>.sys (built from <name>sys.c),
 * and its companion program, <name>.exe (built from <name>.c on
 * common/f2kt.h and common/f2kdhost.h). The companion loads the driver
 * for each section, asks it to run the section through an I/O control
 * request, and prints the lines the driver returns: so a section is one
 * block of the capture, as a user-mode fixture's is, and the driver's
 * observations reach the capture through the companion's standard output.
 *
 * The driver follows common/f2kt.h's conventions:
 *
 * - Observe, don't assert: a line prints what a call returned (a status
 *   as 0x%08lX, a value, a relation); the real machine's capture is the
 *   expectation.
 * - Nothing machine-specific is printed: no addresses, ids, counts of
 *   devices or raw timings. The capture is taken on Windows 2000 in
 *   VirtualBox and compared with F2K under QEMU, whose virtual hardware
 *   differs (PCI ids, devices, BARs, IRQ lines, timing): a fact that
 *   depends on the machine prints as a relation or a verdict ("vector =
 *   0x30 + line: yes", a value in a band), or on a line the fixture's
 *   header names as one for fixture.toml's masks.
 * - Every call stays within its documented preconditions (IRQL above
 *   all: values taken at a raised IRQL are kept in locals and printed
 *   once it is lowered), everything changed is restored, every loop and
 *   wait is bounded, and no interrupt is ever connected: a driver's
 *   mistake stops the capture machine.
 *
 * What this header gives the fixture:
 *
 * - DriverEntry: copies the registry path, calls the fixture's entry
 *   hook (the DRIVER_OBJECT as the I/O manager hands it over), creates
 *   \Device\F2K<name> (FILE_DEVICE_UNKNOWN, no extension, not exclusive)
 *   and \DosDevices\F2K<name>, sets IRP_MJ_CREATE, IRP_MJ_CLOSE and
 *   IRP_MJ_DEVICE_CONTROL and DriverUnload, calls the ready hook (the
 *   device as IoCreateDevice made it, DO_DEVICE_INITIALIZING still set),
 *   then clears DO_DEVICE_INITIALIZING. What the two hooks print goes to
 *   the entry log, which a section prints with f2kd_print_log().
 * - The dispatch: every IRP goes to the fixture's irp hook first (what it
 *   prints goes to the IRP log), then F2KD_IOCTL_RUN runs the named
 *   section with line() writing into the request's output buffer, and
 *   F2KD_IOCTL_STAMP answers the source stamp; any other control code
 *   completes with STATUS_INVALID_DEVICE_REQUEST, every other IRP with
 *   STATUS_SUCCESS.
 * - DriverUnload: the unload hook (phase 0), the link and the device
 *   deleted, the unload hook again (phase 1); what it printed is written
 *   to the service key's F2KUnload value (REG_SZ), for the companion.
 * - line(), yesno(), and f2kd_request / f2kd_irp: the running section's
 *   request (the companion's process and thread ids) and IRP.
 *
 * The fixture defines F2KD_NAME, includes this header, writes its
 * sections and hooks, and ends with its tables:
 *
 *   static const f2kd_section_t sections[] = {
 *       { "entry", sec_entry },
 *       { NULL, NULL }
 *   };
 *   F2KD_FIXTURE(sections, entry_hook, ready_hook, irp_hook, unload_hook)
 *
 * (a hook may be NULL). The section names must be the companion's
 * (tests/harness/test_repository.py holds the two tables together).
 *
 * Text is formatted by ntoskrnl's _vsnprintf: the Windows 2000 DDK has
 * no RtlStringCb* functions. It formats no floating point.
 *
 * Build: tests\build.bat, from the Windows 2000 DDK's build environment
 * (BASEDIR set); see its :driver label for the compiler and linker lines.
 */

#ifndef F2KD_H
#define F2KD_H

#include <ntddk.h>
#include <stddef.h>
#include <stdarg.h>

#include "f2kdproto.h"

/* ntoskrnl exports it; the DDK's headers do not declare it. */
int __cdecl _vsnprintf(char *buffer, size_t count, const char *format, va_list args);

/* ntoskrnl exports it (data, so imported); the Windows 2000 DDK's
 * ntddk.h does not declare it (its IFS kit's ntifs.h does). */
extern __declspec(dllimport) PEPROCESS PsInitialSystemProcess;

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

/* The source the driver was built from (tests/build.bat defines the
 * CRC: the companion's, the driver's and the shared headers' sources). */
#define F2KD_TEXT_(x) #x
#define F2KD_TEXT(x) F2KD_TEXT_(x)
#ifdef F2KT_SOURCE_CRC
static const char f2kd_source[] = "F2KT-SOURCE-CRC=" F2KD_TEXT(F2KT_SOURCE_CRC);
#else
static const char f2kd_source[] = "F2KT-SOURCE-CRC=unknown";
#endif

typedef struct {
    const char *name;
    void (*run)(void);
} f2kd_section_t;

typedef struct {
    const f2kd_section_t *sections;
    /* DriverEntry, first thing: the DRIVER_OBJECT as handed over. */
    void (*entry)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
    /* DriverEntry, the device and link made and the dispatch set, before
     * DO_DEVICE_INITIALIZING is cleared. */
    void (*ready)(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject);
    /* Every IRP, as dispatched, before the header handles it. */
    void (*irp)(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION Stack);
    /* DriverUnload: phase 0 before the link and the device are deleted,
     * phase 1 after. */
    void (*unload)(PDRIVER_OBJECT DriverObject, int phase);
} f2kd_fixture_t;

/* The fixture's tables, defined at its end by F2KD_FIXTURE. */
static const f2kd_fixture_t *f2kd_fixture(void);

#define F2KD_FIXTURE(sections, entry, ready, irp, unload) \
    static const f2kd_fixture_t *f2kd_fixture(void) \
    { \
        static const f2kd_fixture_t fixture = { sections, entry, ready, irp, unload }; \
        return &fixture; \
    }

/* --- Text ------------------------------------------------------------ */

/* Where text goes: a buffer, how much it holds, and whether a line did
 * not fit (the rest are dropped, after a line saying so). */
typedef struct {
    char *buffer;
    ULONG capacity;
    ULONG used;
    BOOLEAN full;
} f2kd_text_t;

#define F2KD_LOG 8192
#define F2KD_TRUNCATED "f2kd: output truncated\n"

static char f2kd_entry_text[F2KD_LOG];
static char f2kd_irp_text[F2KD_LOG];
static char f2kd_unload_text[F2KD_LOG];
static f2kd_text_t f2kd_entry_log = { f2kd_entry_text, F2KD_LOG, 0, FALSE };
static f2kd_text_t f2kd_irp_log = { f2kd_irp_text, F2KD_LOG, 0, FALSE };
static f2kd_text_t f2kd_unload_log = { f2kd_unload_text, F2KD_LOG, 0, FALSE };

/* line()'s destination: a log while a hook runs, the request's output
 * buffer while a section runs, nothing otherwise. */
static f2kd_text_t *f2kd_out;

/* The running section's request and IRP (NULL outside a section). */
static const f2kd_request_t *f2kd_request;
static PIRP f2kd_irp;

/* The device DriverEntry made, and the registry path it was given
 * (copied: the I/O manager's string does not outlive DriverEntry). */
static PDEVICE_OBJECT f2kd_device;
static WCHAR f2kd_registry_path[256];

static void f2kd_append(f2kd_text_t *text, const char *bytes, ULONG count)
{
    ULONG room;

    if (text == NULL || text->full) {
        return;
    }
    room = text->capacity - (ULONG)(sizeof F2KD_TRUNCATED - 1);
    if (text->used + count > room) {
        RtlCopyMemory(text->buffer + text->used, F2KD_TRUNCATED, sizeof F2KD_TRUNCATED - 1);
        text->used += sizeof F2KD_TRUNCATED - 1;
        text->full = TRUE;
        return;
    }
    RtlCopyMemory(text->buffer + text->used, bytes, count);
    text->used += count;
}

/* Print one line: formatted, "\n" appended. */
static void line(const char *fmt, ...)
{
    char text[512];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = _vsnprintf(text, sizeof text - 1, fmt, ap);
    va_end(ap);
    if (n < 0) {
        n = sizeof text - 1;
    }
    text[n++] = '\n';
    f2kd_append(f2kd_out, text, (ULONG)n);
}

/* Print a log's lines as they were recorded. */
static void f2kd_print_log(const f2kd_text_t *log)
{
    f2kd_append(f2kd_out, log->buffer, log->used);
}

static const char *yesno(int v)
{
    return v ? "yes" : "no";
}

/* A counted wide string as printed: a unit below 0x80 as its byte, any
 * other as <U+XXXX> (as f2kt.h's ws() prints); "(null)" for a NULL
 * buffer. Rotates through a few buffers, so one line can carry several. */
static const char *f2kd_us(const UNICODE_STRING *s)
{
    static char bufs[4][300];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    USHORT i;

    if (s == NULL || s->Buffer == NULL) {
        return "(null)";
    }
    for (i = 0; i < s->Length / sizeof(WCHAR) && n < (int)sizeof bufs[0] - 9; i++) {
        WCHAR c = s->Buffer[i];
        int shift;
        if (c >= 0x20 && c < 0x80) {
            b[n++] = (char)c;
            continue;
        }
        b[n++] = '<';
        b[n++] = 'U';
        b[n++] = '+';
        for (shift = 12; shift >= 0; shift -= 4) {
            b[n++] = "0123456789ABCDEF"[(c >> shift) & 0xF];
        }
        b[n++] = '>';
    }
    b[n] = '\0';
    return b;
}

/* --- The dispatch ---------------------------------------------------- */

static int f2kd_same(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/* F2KD_IOCTL_RUN: the named section, its lines into the system buffer. */
static NTSTATUS f2kd_run(PIRP irp, PIO_STACK_LOCATION stack, ULONG *information)
{
    f2kd_request_t request;
    f2kd_text_t out;
    const f2kd_section_t *s;
    ULONG in_length = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_length = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (irp->AssociatedIrp.SystemBuffer == NULL || in_length < sizeof request
        || out_length < 2 * sizeof F2KD_TRUNCATED) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(&request, irp->AssociatedIrp.SystemBuffer, sizeof request);
    request.section[sizeof request.section - 1] = '\0';
    out.buffer = (char *)irp->AssociatedIrp.SystemBuffer;
    out.capacity = out_length;
    out.used = 0;
    out.full = FALSE;
    f2kd_out = &out;
    f2kd_request = &request;
    f2kd_irp = irp;
    for (s = f2kd_fixture()->sections; s->name != NULL; s++) {
        if (f2kd_same(s->name, request.section)) {
            break;
        }
    }
    if (s->name != NULL) {
        s->run();
    } else {
        line("f2kd: the driver has no section %s", request.section);
    }
    f2kd_out = NULL;
    f2kd_request = NULL;
    f2kd_irp = NULL;
    *information = out.used;
    return STATUS_SUCCESS;
}

/* F2KD_IOCTL_STAMP: the source stamp, NUL-terminated. */
static NTSTATUS f2kd_stamp(PIRP irp, PIO_STACK_LOCATION stack, ULONG *information)
{
    if (irp->AssociatedIrp.SystemBuffer == NULL
        || stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof f2kd_source) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, f2kd_source, sizeof f2kd_source);
    *information = sizeof f2kd_source;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI f2kd_dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    const f2kd_fixture_t *fixture = f2kd_fixture();
    NTSTATUS status = STATUS_SUCCESS;
    ULONG information = 0;

    if (fixture->irp != NULL) {
        f2kd_out = &f2kd_irp_log;
        fixture->irp(device, irp, stack);
        f2kd_out = NULL;
    }
    if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case F2KD_IOCTL_RUN:
            status = f2kd_run(irp, stack, &information);
            break;
        case F2KD_IOCTL_STAMP:
            status = f2kd_stamp(irp, stack, &information);
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* --- Load and unload ------------------------------------------------- */

/* The unload log, as the service key's F2KUnload value (REG_SZ). */
static void f2kd_save_unload_log(void)
{
    static WCHAR wide[F2KD_LOG + 1];
    ULONG i;

    for (i = 0; i < f2kd_unload_log.used; i++) {
        wide[i] = (WCHAR)(UCHAR)f2kd_unload_log.buffer[i];
    }
    wide[i] = 0;
    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, f2kd_registry_path, F2KD_WIDE(F2KD_UNLOAD_VALUE), REG_SZ,
                          wide, (i + 1) * sizeof(WCHAR));
}

static VOID NTAPI f2kd_unload(PDRIVER_OBJECT driver)
{
    UNICODE_STRING link;
    const f2kd_fixture_t *fixture = f2kd_fixture();

    if (fixture->unload != NULL) {
        f2kd_out = &f2kd_unload_log;
        fixture->unload(driver, 0);
    }
    RtlInitUnicodeString(&link, F2KD_LINK_NAME);
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(f2kd_device);
    if (fixture->unload != NULL) {
        fixture->unload(driver, 1);
        f2kd_out = NULL;
        f2kd_save_unload_log();
    }
}

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    const f2kd_fixture_t *fixture = f2kd_fixture();
    UNICODE_STRING device_name;
    UNICODE_STRING link;
    PDEVICE_OBJECT device;
    NTSTATUS status;
    ULONG count = 0;

    if (registry_path != NULL && registry_path->Buffer != NULL) {
        count = registry_path->Length / sizeof(WCHAR);
        if (count > sizeof f2kd_registry_path / sizeof(WCHAR) - 1) {
            count = sizeof f2kd_registry_path / sizeof(WCHAR) - 1;
        }
        RtlCopyMemory(f2kd_registry_path, registry_path->Buffer, count * sizeof(WCHAR));
    }
    f2kd_registry_path[count] = 0;

    f2kd_out = &f2kd_entry_log;
    if (fixture->entry != NULL) {
        fixture->entry(driver, registry_path);
    }
    RtlInitUnicodeString(&device_name, F2KD_DEVICE_NAME);
    status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        f2kd_out = NULL;
        return status;
    }
    RtlInitUnicodeString(&link, F2KD_LINK_NAME);
    status = IoCreateSymbolicLink(&link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        f2kd_out = NULL;
        return status;
    }
    f2kd_device = device;
    driver->MajorFunction[IRP_MJ_CREATE] = f2kd_dispatch;
    driver->MajorFunction[IRP_MJ_CLOSE] = f2kd_dispatch;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = f2kd_dispatch;
    driver->DriverUnload = f2kd_unload;
    if (fixture->ready != NULL) {
        fixture->ready(driver, device);
    }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    f2kd_out = NULL;
    return STATUS_SUCCESS;
}

#endif /* F2KD_H */
