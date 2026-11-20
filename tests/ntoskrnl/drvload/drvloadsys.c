/*
 * drvloadsys.c - drvload's driver, drvload.sys: what a legacy driver
 * meets from ntoskrnl as NtLoadDriver loads it, as the I/O manager sends
 * it IRPs, and as NtUnloadDriver unloads it. drvload.c, the companion
 * program, describes the sections; this file runs those the driver
 * answers (common/f2kd.h describes the protocol).
 *
 * The structures print through the DDK's own declarations, each field
 * with its offset (FIELD_OFFSET, the DDK's layout, which F2K's must be):
 * a value that is an address prints as a relation (NULL, the driver's
 * own, inside its image), a count or a code as itself.
 *
 * Build (Windows 2000 DDK build environment; tests\build.bat drvload):
 *   see tests\build.bat's :driver label (cl /Gz ... drvloadsys.c, link
 *   /DRIVER ... ntoskrnl.lib hal.lib /OUT:drvload.sys)
 */

#define F2KD_NAME "drvload"
#include "../common/f2kd.h"

/* NT 4 SP5's and Windows 2000's; older DDK headers lack the name. */
#ifndef FILE_DEVICE_SECURE_OPEN
#define FILE_DEVICE_SECURE_OPEN 0x00000100
#endif

/* What DriverEntry saw, for the later relations. */
static PEPROCESS entry_process;
static PDRIVER_DISPATCH default_dispatch;

/* The process the last IRP_MJ_CREATE came in (the opener's), for the
 * unload's relations. */
static HANDLE opener_pid;

/* --- helpers ------------------------------------------------------- */

static const char *null_or(const void *p)
{
    return p == NULL ? "NULL" : "non-NULL";
}

/* Whether an address lies in the driver's own image. */
static int in_image(PDRIVER_OBJECT driver, const void *p)
{
    ULONG_PTR start = (ULONG_PTR)driver->DriverStart;

    return start != 0 && (ULONG_PTR)p >= start && (ULONG_PTR)p < start + driver->DriverSize;
}

/* A field of the image's PE headers at DriverStart: the NT headers'
 * offset (e_lfanew, at 0x3C), then `at` bytes into them; 0 when the
 * image does not start with "MZ". */
static ULONG image_field(PDRIVER_OBJECT driver, ULONG at)
{
    const UCHAR *base = (const UCHAR *)driver->DriverStart;

    if (base == NULL || base[0] != 'M' || base[1] != 'Z') {
        return 0;
    }
    return *(const ULONG *)(base + *(const ULONG *)(base + 0x3C) + at);
}

/* A UNICODE_STRING's suffix, compared without regard to case. */
static int ends_with(const UNICODE_STRING *s, const WCHAR *suffix)
{
    USHORT n = 0;
    USHORT i;

    while (suffix[n] != 0) {
        n++;
    }
    if (s == NULL || s->Buffer == NULL || s->Length / sizeof(WCHAR) < n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        WCHAR a = s->Buffer[s->Length / sizeof(WCHAR) - n + i];
        WCHAR b = suffix[i];
        if (a >= 'a' && a <= 'z') {
            a = (WCHAR)(a - 'a' + 'A');
        }
        if (b >= 'a' && b <= 'z') {
            b = (WCHAR)(b - 'a' + 'A');
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static const char *major_name(UCHAR major)
{
    switch (major) {
    case IRP_MJ_CREATE: return "IRP_MJ_CREATE";
    case IRP_MJ_CLEANUP: return "IRP_MJ_CLEANUP";
    case IRP_MJ_CLOSE: return "IRP_MJ_CLOSE";
    case IRP_MJ_DEVICE_CONTROL: return "IRP_MJ_DEVICE_CONTROL";
    }
    return "IRP_MJ_(other)";
}

/* A device object's fields, at their offsets. */
static void print_device(const char *what, PDRIVER_OBJECT driver, PDEVICE_OBJECT d)
{
    line("%s: +0x%02lX Type=%d +0x%02lX Size=%u", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, Type), d->Type,
         (ULONG)FIELD_OFFSET(DEVICE_OBJECT, Size), d->Size);
    line("%s: +0x%02lX ReferenceCount=%ld", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, ReferenceCount),
         d->ReferenceCount);
    line("%s: +0x%02lX DriverObject is the driver's: %s", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, DriverObject),
         yesno(d->DriverObject == driver));
    line("%s: +0x%02lX NextDevice: %s", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, NextDevice),
         null_or(d->NextDevice));
    line("%s: +0x%02lX AttachedDevice: %s", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, AttachedDevice),
         null_or(d->AttachedDevice));
    line("%s: +0x%02lX CurrentIrp: %s", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, CurrentIrp),
         null_or(d->CurrentIrp));
    line("%s: +0x%02lX Flags=0x%08lX", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, Flags), d->Flags);
    line("%s: +0x%02lX Characteristics=0x%08lX", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, Characteristics),
         d->Characteristics);
    line("%s: +0x%02lX Vpb: %s", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, Vpb), null_or(d->Vpb));
    line("%s: +0x%02lX DeviceExtension: %s", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, DeviceExtension),
         null_or(d->DeviceExtension));
    line("%s: +0x%02lX DeviceType=0x%08lX", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, DeviceType), d->DeviceType);
    line("%s: +0x%02lX StackSize=%d", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, StackSize), d->StackSize);
    line("%s: +0x%02lX AlignmentRequirement=0x%08lX", what,
         (ULONG)FIELD_OFFSET(DEVICE_OBJECT, AlignmentRequirement), d->AlignmentRequirement);
    line("%s: +0x%02lX SectorSize=%u", what, (ULONG)FIELD_OFFSET(DEVICE_OBJECT, SectorSize), d->SectorSize);
    line("%s: +0x%02lX DeviceObjectExtension: %s, its Type=%d, its DeviceObject is the device: %s", what,
         (ULONG)FIELD_OFFSET(DEVICE_OBJECT, DeviceObjectExtension), null_or(d->DeviceObjectExtension),
         d->DeviceObjectExtension != NULL ? d->DeviceObjectExtension->Type : -1,
         yesno(d->DeviceObjectExtension != NULL && d->DeviceObjectExtension->DeviceObject == d));
}

/* --- DriverEntry's hooks ------------------------------------------- */

static void on_entry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    PDRIVER_EXTENSION extension = driver->DriverExtension;
    ULONG entry_rva = image_field(driver, 0x28);  /* OptionalHeader.AddressOfEntryPoint */
    ULONG size_of_image = image_field(driver, 0x50);  /* OptionalHeader.SizeOfImage */
    int same = 1;
    int null = 0;
    int inside = 0;
    int i;

    entry_process = PsGetCurrentProcess();
    default_dispatch = driver->MajorFunction[0];

    line("DriverEntry: IRQL=%u", KeGetCurrentIrql());
    line("DriverEntry: in the System process (PsInitialSystemProcess): %s",
         yesno(entry_process == PsInitialSystemProcess));
    line("DriverEntry: ExGetPreviousMode=%d", ExGetPreviousMode());

    line("DriverObject: +0x%02lX Type=%d +0x%02lX Size=%d", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, Type), driver->Type,
         (ULONG)FIELD_OFFSET(DRIVER_OBJECT, Size), driver->Size);
    line("DriverObject: +0x%02lX DeviceObject: %s", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DeviceObject),
         null_or(driver->DeviceObject));
    line("DriverObject: +0x%02lX Flags=0x%08lX", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, Flags), driver->Flags);
    line("DriverObject: +0x%02lX DriverStart is the image's header (MZ): %s",
         (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverStart),
         yesno(driver->DriverStart != NULL && ((UCHAR *)driver->DriverStart)[0] == 'M'
               && ((UCHAR *)driver->DriverStart)[1] == 'Z'));
    line("DriverObject: +0x%02lX DriverSize is the image's SizeOfImage: %s",
         (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverSize), yesno(size_of_image != 0 && driver->DriverSize == size_of_image));
    line("DriverObject: +0x%02lX DriverSection: %s", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverSection),
         null_or(driver->DriverSection));
    line("DriverObject: +0x%02lX DriverExtension: %s", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverExtension),
         null_or(extension));
    if (extension != NULL) {
        line("DriverExtension: +0x%02lX DriverObject is the driver's: %s",
             (ULONG)FIELD_OFFSET(DRIVER_EXTENSION, DriverObject), yesno(extension->DriverObject == driver));
        line("DriverExtension: +0x%02lX AddDevice: %s", (ULONG)FIELD_OFFSET(DRIVER_EXTENSION, AddDevice),
             null_or((void *)extension->AddDevice));
        line("DriverExtension: +0x%02lX Count=%lu", (ULONG)FIELD_OFFSET(DRIVER_EXTENSION, Count), extension->Count);
        line("DriverExtension: +0x%02lX ServiceKeyName=\"%s\" Length=%u MaximumLength=%u",
             (ULONG)FIELD_OFFSET(DRIVER_EXTENSION, ServiceKeyName), f2kd_us(&extension->ServiceKeyName),
             extension->ServiceKeyName.Length, extension->ServiceKeyName.MaximumLength);
    }
    line("DriverObject: +0x%02lX DriverName=\"%s\" Length=%u MaximumLength=%u",
         (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverName), f2kd_us(&driver->DriverName), driver->DriverName.Length,
         driver->DriverName.MaximumLength);
    line("DriverObject: +0x%02lX HardwareDatabase=\"%s\"", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, HardwareDatabase),
         f2kd_us(driver->HardwareDatabase));
    line("DriverObject: +0x%02lX FastIoDispatch: %s", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, FastIoDispatch),
         null_or(driver->FastIoDispatch));
    line("DriverObject: +0x%02lX DriverInit is DriverEntry: %s, the image's entry point: %s",
         (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverInit), yesno(driver->DriverInit == DriverEntry),
         yesno(entry_rva != 0 && (ULONG_PTR)driver->DriverInit == (ULONG_PTR)driver->DriverStart + entry_rva));
    line("DriverObject: +0x%02lX DriverStartIo: %s", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverStartIo),
         null_or((void *)driver->DriverStartIo));
    line("DriverObject: +0x%02lX DriverUnload: %s", (ULONG)FIELD_OFFSET(DRIVER_OBJECT, DriverUnload),
         null_or((void *)driver->DriverUnload));
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        same = same && driver->MajorFunction[i] == default_dispatch;
        null = null || driver->MajorFunction[i] == NULL;
        inside = inside || in_image(driver, (void *)driver->MajorFunction[i]);
    }
    line("DriverObject: +0x%02lX MajorFunction[0..%d]: one routine: %s, NULL: %s, in the driver's image: %s",
         (ULONG)FIELD_OFFSET(DRIVER_OBJECT, MajorFunction), IRP_MJ_MAXIMUM_FUNCTION, yesno(same), yesno(null),
         yesno(inside));
    line("DriverEntry: in the driver's image: %s", yesno(in_image(driver, (void *)DriverEntry)));

    line("RegistryPath=\"%s\" Length=%u MaximumLength=%u", f2kd_us(registry_path),
         registry_path != NULL ? registry_path->Length : 0, registry_path != NULL ? registry_path->MaximumLength : 0);
    line("RegistryPath ends with \\Services\\F2Kdrvload (any case): %s",
         yesno(ends_with(registry_path, L"\\Services\\F2Kdrvload")));
}

static void on_ready(PDRIVER_OBJECT driver, PDEVICE_OBJECT device)
{
    /* drvload watches IRP_MJ_CLEANUP too (the irps section). */
    driver->MajorFunction[IRP_MJ_CLEANUP] = f2kd_dispatch;

    print_device("IoCreateDevice", driver, device);
    line("IoCreateDevice: DriverObject->DeviceObject is the device: %s", yesno(driver->DeviceObject == device));
    line("dispatch set: IRP_MJ_READ still the default routine: %s",
         yesno(driver->MajorFunction[IRP_MJ_READ] == default_dispatch));
}

/* --- The IRPs ------------------------------------------------------ */

/* Every IRP since the load, in order, and the file objects they named
 * (numbered from 1 by their IRP_MJ_CREATE: an address can be reused). */
typedef struct {
    UCHAR major;
    UCHAR minor;
    KIRQL irql;
    CHAR requestor_mode;
    CHAR previous_mode;
    int file;
    HANDLE pid;
    HANDLE tid;
    int thread_is_irps;
    ULONG code;
} irp_record_t;

#define RECORDS 32
static irp_record_t records[RECORDS];
static int record_count;
static PFILE_OBJECT files[RECORDS];
static int file_count;

/* The first IRP_MJ_CREATE's fields, as text, and its process. */
static char create_text[4096];
static f2kd_text_t create_log = { create_text, sizeof create_text, 0, FALSE };
static HANDLE create_pid;
static HANDLE create_tid;

static int file_number(PFILE_OBJECT file, int create)
{
    int i;

    if (create && file_count < RECORDS) {
        files[file_count++] = file;
        return file_count;
    }
    for (i = file_count - 1; i >= 0; i--) {
        if (files[i] == file) {
            return i + 1;
        }
    }
    return 0;
}

static void record_create(PDEVICE_OBJECT device, PIRP irp, PIO_STACK_LOCATION stack)
{
    PFILE_OBJECT file = stack->FileObject;
    f2kd_text_t *saved = f2kd_out;

    f2kd_out = &create_log;
    create_pid = PsGetCurrentProcessId();
    create_tid = PsGetCurrentThreadId();
    line("IRP_MJ_CREATE: IRQL=%u ExGetPreviousMode=%d", KeGetCurrentIrql(), ExGetPreviousMode());
    line("Irp: +0x%02lX Type=%d +0x%02lX Size=%u (IoSizeOfIrp(StackCount)=%u)", (ULONG)FIELD_OFFSET(IRP, Type),
         irp->Type, (ULONG)FIELD_OFFSET(IRP, Size), irp->Size, (USHORT)IoSizeOfIrp(irp->StackCount));
    line("Irp: +0x%02lX Flags=0x%08lX", (ULONG)FIELD_OFFSET(IRP, Flags), irp->Flags);
    line("Irp: +0x%02lX AssociatedIrp.SystemBuffer: %s", (ULONG)FIELD_OFFSET(IRP, AssociatedIrp),
         null_or(irp->AssociatedIrp.SystemBuffer));
    line("Irp: +0x%02lX RequestorMode=%d", (ULONG)FIELD_OFFSET(IRP, RequestorMode), irp->RequestorMode);
    line("Irp: +0x%02lX StackCount=%d +0x%02lX CurrentLocation=%d", (ULONG)FIELD_OFFSET(IRP, StackCount),
         irp->StackCount, (ULONG)FIELD_OFFSET(IRP, CurrentLocation), irp->CurrentLocation);
    line("Irp: Tail.Overlay.Thread is the current thread: %s, OriginalFileObject is the stack's: %s",
         yesno(irp->Tail.Overlay.Thread == PsGetCurrentThread()),
         yesno(irp->Tail.Overlay.OriginalFileObject == file));
    line("stack: MajorFunction=%u MinorFunction=%u Flags=0x%02X Control=0x%02X", stack->MajorFunction,
         stack->MinorFunction, stack->Flags, stack->Control);
    line("stack: DeviceObject is the device: %s, FileObject: %s", yesno(stack->DeviceObject == device),
         null_or(file));
    line("stack: Create.Options: disposition=%lu options=0x%06lX", stack->Parameters.Create.Options >> 24,
         stack->Parameters.Create.Options & 0x00FFFFFF);
    line("stack: Create.FileAttributes=0x%04X ShareAccess=0x%04X EaLength=%lu",
         stack->Parameters.Create.FileAttributes, stack->Parameters.Create.ShareAccess,
         stack->Parameters.Create.EaLength);
    if (stack->Parameters.Create.SecurityContext != NULL) {
        line("stack: Create.SecurityContext->DesiredAccess=0x%08lX",
             stack->Parameters.Create.SecurityContext->DesiredAccess);
    } else {
        line("stack: Create.SecurityContext: NULL");
    }
    if (file != NULL) {
        line("FileObject: +0x%02lX Type=%d +0x%02lX Size=%d", (ULONG)FIELD_OFFSET(FILE_OBJECT, Type), file->Type,
             (ULONG)FIELD_OFFSET(FILE_OBJECT, Size), file->Size);
        line("FileObject: +0x%02lX DeviceObject is the device: %s", (ULONG)FIELD_OFFSET(FILE_OBJECT, DeviceObject),
             yesno(file->DeviceObject == device));
        line("FileObject: +0x%02lX FsContext: %s", (ULONG)FIELD_OFFSET(FILE_OBJECT, FsContext),
             null_or(file->FsContext));
        line("FileObject: +0x%02lX Flags=0x%08lX", (ULONG)FIELD_OFFSET(FILE_OBJECT, Flags), file->Flags);
        line("FileObject: +0x%02lX FileName=\"%s\" Length=%u", (ULONG)FIELD_OFFSET(FILE_OBJECT, FileName),
             f2kd_us(&file->FileName), file->FileName.Length);
        line("FileObject: +0x%02lX RelatedFileObject: %s", (ULONG)FIELD_OFFSET(FILE_OBJECT, RelatedFileObject),
             null_or(file->RelatedFileObject));
    }
    line("the device: Flags=0x%08lX ReferenceCount=%ld", device->Flags, device->ReferenceCount);
    f2kd_out = saved;
}

static void on_irp(PDEVICE_OBJECT device, PIRP irp, PIO_STACK_LOCATION stack)
{
    irp_record_t *r;

    if (stack->MajorFunction == IRP_MJ_CREATE) {
        opener_pid = PsGetCurrentProcessId();
        if (create_log.used == 0) {
            record_create(device, irp, stack);
        }
    }
    if (record_count >= RECORDS) {
        return;
    }
    r = &records[record_count++];
    r->major = stack->MajorFunction;
    r->minor = stack->MinorFunction;
    r->irql = KeGetCurrentIrql();
    r->requestor_mode = irp->RequestorMode;
    r->previous_mode = ExGetPreviousMode();
    r->file = file_number(stack->FileObject, stack->MajorFunction == IRP_MJ_CREATE);
    r->pid = PsGetCurrentProcessId();
    r->tid = PsGetCurrentThreadId();
    r->thread_is_irps = irp->Tail.Overlay.Thread == PsGetCurrentThread();
    r->code = stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ? stack->Parameters.DeviceIoControl.IoControlCode : 0;
}

/* --- Unload -------------------------------------------------------- */

static void on_unload(PDRIVER_OBJECT driver, int phase)
{
    PDEVICE_OBJECT d = driver->DeviceObject;

    if (phase == 0) {
        line("DriverUnload: IRQL=%u ExGetPreviousMode=%d", KeGetCurrentIrql(), ExGetPreviousMode());
        line("DriverUnload: in the System process: %s, in DriverEntry's: %s, in the last opener's: %s",
             yesno(PsGetCurrentProcess() == PsInitialSystemProcess), yesno(PsGetCurrentProcess() == entry_process),
             yesno(opener_pid != NULL && PsGetCurrentProcessId() == opener_pid));
        line("DriverUnload: DriverObject->DriverUnload is the routine running: %s",
             yesno(driver->DriverUnload == f2kd_unload));
        line("DriverUnload: DriverObject->DeviceObject is the device: %s", yesno(d == f2kd_device));
        if (d != NULL) {
            line("DriverUnload: the device's ReferenceCount=%ld, NextDevice: %s", d->ReferenceCount,
                 null_or(d->NextDevice));
        }
    } else {
        line("DriverUnload: after IoDeleteSymbolicLink and IoDeleteDevice: DriverObject->DeviceObject: %s",
             null_or(d));
    }
}

/* --- Sections ------------------------------------------------------ */

static void sec_entry(void)
{
    f2kd_print_log(&f2kd_entry_log);
}

static void sec_create(void)
{
    f2kd_print_log(&create_log);
    line("IRP_MJ_CREATE: in the caller's process: %s, thread: %s",
         yesno((ULONG)(ULONG_PTR)create_pid == f2kd_request->process_id),
         yesno((ULONG)(ULONG_PTR)create_tid == f2kd_request->thread_id));
}

static void sec_ioctl(void)
{
    PIRP irp = f2kd_irp;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT file = stack->FileObject;

    line("IRP_MJ_DEVICE_CONTROL: IRQL=%u ExGetPreviousMode=%d", KeGetCurrentIrql(), ExGetPreviousMode());
    line("IRP_MJ_DEVICE_CONTROL: in the caller's process: %s, thread: %s",
         yesno((ULONG)(ULONG_PTR)PsGetCurrentProcessId() == f2kd_request->process_id),
         yesno((ULONG)(ULONG_PTR)PsGetCurrentThreadId() == f2kd_request->thread_id));
    line("Irp: +0x%02lX Type=%d +0x%02lX Size=%u (IoSizeOfIrp(StackCount)=%u)", (ULONG)FIELD_OFFSET(IRP, Type),
         irp->Type, (ULONG)FIELD_OFFSET(IRP, Size), irp->Size, (USHORT)IoSizeOfIrp(irp->StackCount));
    line("Irp: +0x%02lX Flags=0x%08lX", (ULONG)FIELD_OFFSET(IRP, Flags), irp->Flags);
    line("Irp: +0x%02lX AssociatedIrp.SystemBuffer: %s", (ULONG)FIELD_OFFSET(IRP, AssociatedIrp),
         null_or(irp->AssociatedIrp.SystemBuffer));
    line("Irp: +0x%02lX RequestorMode=%d", (ULONG)FIELD_OFFSET(IRP, RequestorMode), irp->RequestorMode);
    line("Irp: +0x%02lX PendingReturned=%d +0x%02lX Cancel=%d", (ULONG)FIELD_OFFSET(IRP, PendingReturned),
         irp->PendingReturned, (ULONG)FIELD_OFFSET(IRP, Cancel), irp->Cancel);
    line("Irp: +0x%02lX StackCount=%d +0x%02lX CurrentLocation=%d", (ULONG)FIELD_OFFSET(IRP, StackCount),
         irp->StackCount, (ULONG)FIELD_OFFSET(IRP, CurrentLocation), irp->CurrentLocation);
    line("Irp: +0x%02lX UserBuffer: below 0x80000000: %s", (ULONG)FIELD_OFFSET(IRP, UserBuffer),
         yesno(irp->UserBuffer != NULL && (ULONG_PTR)irp->UserBuffer < 0x80000000));
    line("Irp: Tail.Overlay.Thread is the current thread: %s, OriginalFileObject is the stack's: %s",
         yesno(irp->Tail.Overlay.Thread == PsGetCurrentThread()),
         yesno(irp->Tail.Overlay.OriginalFileObject == file));
    line("stack: +0x%02lX MajorFunction=%u MinorFunction=%u Flags=0x%02X Control=0x%02X",
         (ULONG)FIELD_OFFSET(IO_STACK_LOCATION, MajorFunction), stack->MajorFunction, stack->MinorFunction,
         stack->Flags, stack->Control);
    line("stack: +0x%02lX DeviceIoControl: OutputBufferLength=%lu InputBufferLength=%lu IoControlCode=0x%08lX",
         (ULONG)FIELD_OFFSET(IO_STACK_LOCATION, Parameters), stack->Parameters.DeviceIoControl.OutputBufferLength,
         stack->Parameters.DeviceIoControl.InputBufferLength, stack->Parameters.DeviceIoControl.IoControlCode);
    line("stack: DeviceObject is the device: %s, FileObject: %s, its DeviceObject is the device: %s",
         yesno(stack->DeviceObject == f2kd_device), null_or(file),
         yesno(file != NULL && file->DeviceObject == f2kd_device));
    line("the device: Flags=0x%08lX ReferenceCount=%ld CurrentIrp: %s", f2kd_device->Flags,
         f2kd_device->ReferenceCount, null_or(f2kd_device->CurrentIrp));
}

static void sec_irps(void)
{
    int i;

    line("IRPs since the load: %d", record_count);
    for (i = 0; i < record_count; i++) {
        const irp_record_t *r = &records[i];
        const char *code = "";

        if (r->major == IRP_MJ_DEVICE_CONTROL) {
            code = r->code == F2KD_IOCTL_RUN ? " (run)" : r->code == F2KD_IOCTL_STAMP ? " (stamp)" : " (other)";
        }
        line("%s%s file#%d: MinorFunction=%u IRQL=%u RequestorMode=%d ExGetPreviousMode=%d", major_name(r->major),
             code, r->file, r->minor, r->irql, r->requestor_mode, r->previous_mode);
        line("  in the caller's process: %s, thread: %s, Tail.Overlay.Thread is the current thread: %s",
             yesno((ULONG)(ULONG_PTR)r->pid == f2kd_request->process_id),
             yesno((ULONG)(ULONG_PTR)r->tid == f2kd_request->thread_id), yesno(r->thread_is_irps));
    }
}

/* IoCreateDevice and IoDeleteDevice beside the driver's own device. */
static void sec_device(void)
{
    PDRIVER_OBJECT driver = f2kd_device->DriverObject;
    PDEVICE_OBJECT d = NULL;
    UNICODE_STRING name;
    NTSTATUS status;
    ULONG i;
    int zero = 1;

    status = IoCreateDevice(driver, 16, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &d);
    line("IoCreateDevice(extension 16, no name): 0x%08lX", status);
    if (NT_SUCCESS(status)) {
        line("  Size=%u, sizeof(DEVICE_OBJECT) + 16: %s", d->Size, yesno(d->Size == sizeof(DEVICE_OBJECT) + 16));
        line("  DeviceExtension follows the device object: %s", yesno(d->DeviceExtension == (PVOID)(d + 1)));
        for (i = 0; i < 16 && d->DeviceExtension != NULL; i++) {
            zero = zero && ((UCHAR *)d->DeviceExtension)[i] == 0;
        }
        line("  DeviceExtension zeroed: %s", yesno(zero));
        line("  Flags=0x%08lX StackSize=%d AlignmentRequirement=0x%08lX", d->Flags, d->StackSize,
             d->AlignmentRequirement);
        line("  DriverObject->DeviceObject is the new device: %s, its NextDevice the first: %s",
             yesno(driver->DeviceObject == d), yesno(d->NextDevice == f2kd_device));
        IoDeleteDevice(d);
        line("IoDeleteDevice: DriverObject->DeviceObject is the first again: %s, its NextDevice: %s",
             yesno(driver->DeviceObject == f2kd_device), null_or(f2kd_device->NextDevice));
    }

    d = NULL;
    RtlInitUnicodeString(&name, L"\\Device\\F2Kdrvload2");
    status = IoCreateDevice(driver, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &d);
    line("IoCreateDevice(\\Device\\F2Kdrvload2, FILE_DEVICE_SECURE_OPEN, exclusive): 0x%08lX", status);
    if (NT_SUCCESS(status)) {
        line("  Flags=0x%08lX Characteristics=0x%08lX", d->Flags, d->Characteristics);
        IoDeleteDevice(d);
    }

    d = NULL;
    status = IoCreateDevice(driver, 0, NULL, FILE_DEVICE_DISK, 0, FALSE, &d);
    line("IoCreateDevice(FILE_DEVICE_DISK, no name): 0x%08lX", status);
    if (NT_SUCCESS(status)) {
        line("  Flags=0x%08lX Vpb: %s SectorSize=%u AlignmentRequirement=0x%08lX", d->Flags, null_or(d->Vpb),
             d->SectorSize, d->AlignmentRequirement);
        IoDeleteDevice(d);
    }
}

/* The I/O manager's refusals: names taken, paths missing. */
static void sec_names(void)
{
    PDRIVER_OBJECT driver = f2kd_device->DriverObject;
    PDEVICE_OBJECT d;
    UNICODE_STRING name;
    UNICODE_STRING target;
    NTSTATUS status;

    RtlInitUnicodeString(&target, F2KD_DEVICE_NAME);

    d = (PDEVICE_OBJECT)(ULONG_PTR)0x0F2F2F2F;
    status = IoCreateDevice(driver, 0, &target, FILE_DEVICE_UNKNOWN, 0, FALSE, &d);
    line("IoCreateDevice(\\Device\\F2Kdrvload, taken): 0x%08lX, *DeviceObject: %s", status,
         d == (PDEVICE_OBJECT)(ULONG_PTR)0x0F2F2F2F ? "untouched" : d == NULL ? "NULL" : "set");
    if (NT_SUCCESS(status) && d != (PDEVICE_OBJECT)(ULONG_PTR)0x0F2F2F2F && d != NULL) {
        IoDeleteDevice(d);
    }

    d = (PDEVICE_OBJECT)(ULONG_PTR)0x0F2F2F2F;
    RtlInitUnicodeString(&name, L"\\F2KNoSuchDirectory\\F2Kdrvload");
    status = IoCreateDevice(driver, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &d);
    line("IoCreateDevice(\\F2KNoSuchDirectory\\F2Kdrvload): 0x%08lX, *DeviceObject: %s", status,
         d == (PDEVICE_OBJECT)(ULONG_PTR)0x0F2F2F2F ? "untouched" : d == NULL ? "NULL" : "set");
    if (NT_SUCCESS(status) && d != (PDEVICE_OBJECT)(ULONG_PTR)0x0F2F2F2F && d != NULL) {
        IoDeleteDevice(d);
    }

    RtlInitUnicodeString(&name, F2KD_LINK_NAME);
    line("IoCreateSymbolicLink(\\DosDevices\\F2Kdrvload, taken): 0x%08lX", IoCreateSymbolicLink(&name, &target));

    RtlInitUnicodeString(&name, L"\\DosDevices\\F2KdrvloadX");
    line("IoCreateSymbolicLink(\\DosDevices\\F2KdrvloadX): 0x%08lX", IoCreateSymbolicLink(&name, &target));
    line("IoDeleteSymbolicLink(\\DosDevices\\F2KdrvloadX): 0x%08lX", IoDeleteSymbolicLink(&name));
    line("IoDeleteSymbolicLink(\\DosDevices\\F2KdrvloadX), again: 0x%08lX", IoDeleteSymbolicLink(&name));

    RtlInitUnicodeString(&name, L"\\DosDevices\\F2KdrvloadY");
    RtlInitUnicodeString(&target, L"\\Device\\F2KdrvloadNone");
    status = IoCreateSymbolicLink(&name, &target);
    line("IoCreateSymbolicLink(\\DosDevices\\F2KdrvloadY to a device that does not exist): 0x%08lX", status);
    if (NT_SUCCESS(status)) {
        line("IoDeleteSymbolicLink(\\DosDevices\\F2KdrvloadY): 0x%08lX", IoDeleteSymbolicLink(&name));
    }
}

static const f2kd_section_t sections[] = {
    { "entry", sec_entry },
    { "create", sec_create },
    { "ioctl", sec_ioctl },
    { "irps", sec_irps },
    { "device", sec_device },
    { "names", sec_names },
    { NULL, NULL }
};

F2KD_FIXTURE(sections, on_entry, on_ready, on_irp, on_unload)
