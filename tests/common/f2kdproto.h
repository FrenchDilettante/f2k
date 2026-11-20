/*
 * f2kdproto.h - what a kernel-mode fixture's driver and its companion
 * program agree on: the names, the I/O control codes and the request.
 *
 * Included by common/f2kd.h (the driver's side, over ntddk.h) and by
 * common/f2kdhost.h (the companion's, over windows.h and winioctl.h):
 * it uses only what both define. The fixture defines F2KD_NAME, its
 * name as a string literal ("drvload"), before including either.
 *
 *   service key  HKLM\SYSTEM\CurrentControlSet\Services\F2K<name>
 *   driver       \Driver\F2K<name> (the I/O manager names it after the key)
 *   device       \Device\F2K<name>
 *   link         \DosDevices\F2K<name>, opened as \\.\F2K<name>
 *
 * F2KD_IOCTL_RUN carries an f2kd_request_t (the section's name, and the
 * companion's process and thread ids for the driver's relations) in, and
 * the section's text out: lines ending in "\n", as many as fit. It is
 * METHOD_BUFFERED: the request and the text share the I/O manager's
 * system buffer, so the driver copies the request out before it writes.
 * F2KD_IOCTL_STAMP returns the driver's "F2KT-SOURCE-CRC=..." text, which
 * the companion holds against its own (both are built from the same
 * sources, so a stale .sys shows).
 */

#ifndef F2KDPROTO_H
#define F2KDPROTO_H

#ifndef F2KD_NAME
#error "define F2KD_NAME, the fixture name, before including the f2kd headers"
#endif

/* "drvload" -> L"drvload" */
#define F2KD_WIDE_(s) L##s
#define F2KD_WIDE(s) F2KD_WIDE_(s)

#define F2KD_SERVICE "F2K" F2KD_NAME
#define F2KD_DEVICE_NAME L"\\Device\\F2K" F2KD_WIDE(F2KD_NAME)
#define F2KD_LINK_NAME L"\\DosDevices\\F2K" F2KD_WIDE(F2KD_NAME)
#define F2KD_WIN32_NAME "\\\\.\\F2K" F2KD_NAME

/* FILE_DEVICE_UNKNOWN, functions from 0x800 (the vendors' range). */
#define F2KD_DEVICE_TYPE 0x00000022
#define F2KD_IOCTL_RUN CTL_CODE(F2KD_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define F2KD_IOCTL_STAMP CTL_CODE(F2KD_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* A code the driver does not handle (drvload's unknown section). */
#define F2KD_IOCTL_UNKNOWN CTL_CODE(F2KD_DEVICE_TYPE, 0x8FF, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* The output buffer the companion offers a section. */
#define F2KD_OUTPUT 65536

typedef struct {
    char section[64];       /* NUL-terminated */
    ULONG process_id;       /* the companion's GetCurrentProcessId() */
    ULONG thread_id;        /* the companion's GetCurrentThreadId() */
} f2kd_request_t;

/* The value the driver's unload writes under its service key, with what
 * the fixture's unload hook observed (lines ending in "\n"), for the
 * companion to read once NtUnloadDriver has returned. */
#define F2KD_UNLOAD_VALUE "F2KUnload"

#endif /* F2KDPROTO_H */
