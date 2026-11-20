/*
 * f2kdhost.h - the companion side of the corpus's kernel-mode fixtures
 * (common/f2kd.h describes the driver side and the protocol).
 *
 * A kernel-mode fixture's companion, <name>.exe, is a sectioned fixture
 * on common/f2kt.h like any other: its section table lists the sections
 * (so `--list` and capture.bat need no driver), and a section the driver
 * runs is one line of it, F2KD_SECTION(<section>), whose body is
 * f2kd_run("<section>"):
 *
 *   1. f2kd_begin(): any leftover of an earlier run cleared (a crashed run
 *      can leave the driver loaded, its key written, or both: the key is
 *      written again, NtUnloadDriver called, the key deleted, their
 *      results ignored); SeLoadDriverPrivilege enabled (OpenProcessToken,
 *      LookupPrivilegeValueA, AdjustTokenPrivileges); the service key
 *      written, HKLM\SYSTEM\CurrentControlSet\Services\F2K<name>: Type 1
 *      (a kernel driver), Start 3 (on demand), ErrorControl 1, ImagePath
 *      "\??\<the full path of <name>.sys beside the program>"
 *      (REG_EXPAND_SZ); ntdll's NtLoadDriver on its registry name. The
 *      service control manager plays no part: F2K has no services.exe.
 *   2. f2kd_open(): \\.\F2K<name>, then F2KD_IOCTL_STAMP, held against the
 *      program's own stamp (a stale .sys prints a line saying so).
 *   3. f2kd_call(): F2KD_IOCTL_RUN with the section's name; the lines the
 *      driver returns, printed one per line().
 *   4. The handle closed; f2kd_end(): NtUnloadDriver, then the key and
 *      its subkeys deleted (Windows 2000 adds an Enum subkey to a legacy
 *      driver's key).
 *
 * A step that fails prints one line naming it, "f2kd: <step>: ...", and
 * the section stops; nothing prints when all goes well, so the block
 * holds the driver's lines alone. Those lines never print where the
 * machine's own setup shows (the path, the handle). ntdll's NtLoadDriver
 * and NtUnloadDriver are reached through GetProcAddress, as the fixtures
 * reach ntdll: the program loads where F2K's ntdll lacks them.
 *
 * drvload's sections take the steps one by one, to observe the plumbing
 * itself. The program needs an administrator's token (it holds
 * SeLoadDriverPrivilege, disabled until enabled).
 *
 * Include after "../common/f2kt.h", with F2KD_NAME defined.
 */

#ifndef F2KDHOST_H
#define F2KDHOST_H

#include <winioctl.h>

#include "f2kdproto.h"

/* The NT status of a step the program could not take at all (ntdll's
 * export missing): no NTSTATUS has this value. */
#define F2KD_NO_CALL 0x0F2F2F2Ful

/* The service key under HKLM, and its name in the registry's namespace. */
#define F2KD_KEY "SYSTEM\\CurrentControlSet\\Services\\" F2KD_SERVICE
#define F2KD_REGISTRY_NAME L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\F2K" F2KD_WIDE(F2KD_NAME)

/* ntdll's counted string; MSVC 6's headers have no winternl.h. */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} f2kd_unicode_t;

typedef LONG (WINAPI *f2kd_driver_fn)(f2kd_unicode_t *);

/* NtLoadDriver or NtUnloadDriver (`which`) on a registry name: its
 * status, or F2KD_NO_CALL where ntdll does not export it. */
static ULONG f2kd_nt(const char *which, const WCHAR *name)
{
    f2kd_driver_fn fn = (f2kd_driver_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), which);
    f2kd_unicode_t s;

    if (fn == NULL) {
        return F2KD_NO_CALL;
    }
    s.Length = (USHORT)(lstrlenW(name) * sizeof(WCHAR));
    s.MaximumLength = (USHORT)(s.Length + sizeof(WCHAR));
    s.Buffer = (WCHAR *)name;
    return (ULONG)fn(&s);
}

/* A status as printed: hex, or "(no export)" for F2KD_NO_CALL. Rotates
 * through a few buffers, as le() does. */
static const char *f2kd_status(ULONG status)
{
    static char bufs[4][24];
    static int next;
    char *b = bufs[next++ & 3];

    if (status == F2KD_NO_CALL) {
        return "(no export)";
    }
    sprintf(b, "0x%08lX", status);
    return b;
}

static ULONG f2kd_load(void)
{
    return f2kd_nt("NtLoadDriver", F2KD_REGISTRY_NAME);
}

static ULONG f2kd_unload(void)
{
    return f2kd_nt("NtUnloadDriver", F2KD_REGISTRY_NAME);
}

/* SeLoadDriverPrivilege enabled or disabled: whether every step worked
 * (AdjustTokenPrivileges answers TRUE with ERROR_NOT_ALL_ASSIGNED for a
 * privilege the token does not hold). */
static BOOL f2kd_privilege(BOOL enable)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    BOOL ok;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    ok = LookupPrivilegeValueA(NULL, "SeLoadDriverPrivilege", &tp.Privileges[0].Luid)
         && AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL)
         && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

/* The service key, written afresh: whether it was. */
static BOOL f2kd_install(void)
{
    char module[MAX_PATH];
    char full[MAX_PATH];
    char image[MAX_PATH + 8];
    char *file;
    char *dot;
    DWORD n;
    DWORD value;
    HKEY key;
    BOOL ok;

    n = GetModuleFileNameA(NULL, module, sizeof module);
    if (n == 0 || n >= sizeof module) {
        return FALSE;
    }
    n = GetFullPathNameA(module, sizeof full, full, &file);
    if (n == 0 || n >= sizeof full) {
        return FALSE;
    }
    dot = strrchr(full, '.');
    if (dot == NULL || (size_t)(dot - full) + 5 > sizeof full) {
        return FALSE;
    }
    strcpy(dot, ".sys");
    sprintf(image, "\\??\\%s", full);
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, F2KD_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &key, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }
    value = 1;
    ok = RegSetValueExA(key, "Type", 0, REG_DWORD, (const BYTE *)&value, sizeof value) == ERROR_SUCCESS;
    value = 3;
    ok = ok && RegSetValueExA(key, "Start", 0, REG_DWORD, (const BYTE *)&value, sizeof value) == ERROR_SUCCESS;
    value = 1;
    ok = ok && RegSetValueExA(key, "ErrorControl", 0, REG_DWORD, (const BYTE *)&value, sizeof value) == ERROR_SUCCESS;
    ok = ok && RegSetValueExA(key, "ImagePath", 0, REG_EXPAND_SZ, (const BYTE *)image,
                              (DWORD)strlen(image) + 1) == ERROR_SUCCESS;
    RegCloseKey(key);
    return ok;
}

/* A key and its subkeys, deleted (RegDeleteKeyA deletes no key that has
 * subkeys): whether it is gone. Bounded: four levels, 64 subkeys each. */
static BOOL f2kd_delete_tree(HKEY parent, const char *name, int depth)
{
    HKEY key;
    char sub[256];
    int i;

    if (RegOpenKeyExA(parent, name, 0, KEY_ALL_ACCESS, &key) != ERROR_SUCCESS) {
        return RegDeleteKeyA(parent, name) == ERROR_SUCCESS;
    }
    for (i = 0; i < 64 && depth > 0; i++) {
        if (RegEnumKeyA(key, 0, sub, sizeof sub) != ERROR_SUCCESS) {
            break;
        }
        if (!f2kd_delete_tree(key, sub, depth - 1)) {
            break;
        }
    }
    RegCloseKey(key);
    return RegDeleteKeyA(parent, name) == ERROR_SUCCESS;
}

static BOOL f2kd_remove(void)
{
    return f2kd_delete_tree(HKEY_LOCAL_MACHINE, F2KD_KEY, 4);
}

/* The F2KUnload value the driver's unload wrote (common/f2kd.h), into
 * `text`: whether there was one. */
static BOOL f2kd_unload_record(char *text, DWORD size)
{
    HKEY key;
    DWORD type;
    DWORD n = size - 1;
    LONG r;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, F2KD_KEY, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return FALSE;
    }
    r = RegQueryValueExA(key, F2KD_UNLOAD_VALUE, NULL, &type, (BYTE *)text, &n);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS || type != REG_SZ) {
        return FALSE;
    }
    text[n < size ? n : size - 1] = '\0';
    return TRUE;
}

/* Clear what a crashed run may have left: the key written again (the
 * unload reads it), the driver unloaded, the key deleted. Silent. */
static void f2kd_leftover(void)
{
    f2kd_privilege(TRUE);
    if (f2kd_install()) {
        f2kd_unload();
    }
    f2kd_remove();
}

/* Print text holding lines ending in "\n", one line() each. */
static void f2kd_print(char *text, DWORD count)
{
    DWORD start = 0;
    DWORD i;

    for (i = 0; i < count; i++) {
        if (text[i] == '\n') {
            text[i] = '\0';
            line("%s", text + start);
            start = i + 1;
        }
    }
    if (start < count) {
        text[count < F2KD_OUTPUT ? count : F2KD_OUTPUT - 1] = '\0';
        line("%s", text + start);
    }
}

/* The leftovers cleared, the privilege enabled, the key written and the
 * driver loaded: whether it was (a failed step prints its line). */
static BOOL f2kd_begin(void)
{
    ULONG status;

    f2kd_leftover();
    if (!f2kd_privilege(TRUE)) {
        line("f2kd: SeLoadDriverPrivilege: not enabled (err=%lu): run as an administrator", GetLastError());
        return FALSE;
    }
    if (!f2kd_install()) {
        line("f2kd: the service key: not written (err=%lu)", GetLastError());
        return FALSE;
    }
    status = f2kd_load();
    if (status != 0) {
        line("f2kd: NtLoadDriver: %s", f2kd_status(status));
        f2kd_remove();
        return FALSE;
    }
    return TRUE;
}

/* The driver unloaded and the key deleted (a failure prints its line). */
static void f2kd_end(void)
{
    ULONG status = f2kd_unload();

    if (status != 0) {
        line("f2kd: NtUnloadDriver: %s", f2kd_status(status));
    }
    if (!f2kd_remove()) {
        line("f2kd: the service key: not deleted");
    }
}

/* \\.\F2K<name> opened and its stamp checked: the handle, or
 * INVALID_HANDLE_VALUE (a failure prints its line). */
static HANDLE f2kd_open(void)
{
    HANDLE h;
    char stamp[64];
    DWORD got = 0;

    h = CreateFileA(F2KD_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        line("f2kd: CreateFileA(%s): err=%lu", F2KD_WIN32_NAME, GetLastError());
        return h;
    }
    memset(stamp, 0, sizeof stamp);
    if (!DeviceIoControl(h, F2KD_IOCTL_STAMP, NULL, 0, stamp, sizeof stamp - 1, &got, NULL)) {
        line("f2kd: the driver's stamp: err=%lu", GetLastError());
    } else if (strcmp(stamp, f2kt_source) != 0) {
        line("f2kd: the driver is built from other sources (%s) than the program (%s)", stamp, f2kt_source);
    }
    return h;
}

/* F2KD_IOCTL_RUN of a section on an open handle, its lines printed. */
static void f2kd_call(HANDLE h, const char *section)
{
    static char out[F2KD_OUTPUT];
    f2kd_request_t request;
    DWORD got = 0;

    memset(&request, 0, sizeof request);
    strncpy(request.section, section, sizeof request.section - 1);
    request.process_id = GetCurrentProcessId();
    request.thread_id = GetCurrentThreadId();
    if (!DeviceIoControl(h, F2KD_IOCTL_RUN, &request, sizeof request, out, sizeof out, &got, NULL)) {
        line("f2kd: the section's request: err=%lu", GetLastError());
        return;
    }
    f2kd_print(out, got > sizeof out ? sizeof out : got);
}

/* A section the driver runs, start to end. */
static void f2kd_run(const char *section)
{
    HANDLE h;

    if (!f2kd_begin()) {
        return;
    }
    h = f2kd_open();
    if (h != INVALID_HANDLE_VALUE) {
        f2kd_call(h, section);
        CloseHandle(h);
    }
    f2kd_end();
}

/* A section the driver runs: its companion function, sec_<name>. */
#define F2KD_SECTION(name) \
    static void sec_##name(void) \
    { \
        f2kd_run(#name); \
    }

#endif /* F2KDHOST_H */
