/*
 * token - the process token, the way a program that shuts the machine
 * down prepares: OpenProcessToken, LookupPrivilegeValueA/W,
 * AdjustTokenPrivileges and GetTokenInformation(TokenPrivileges), and
 * ntdll's NtOpenProcessToken and NtAdjustPrivilegesToken beneath them.
 *
 * Captured on an administrator account, whose token holds
 * SeShutdownPrivilege disabled and SeChangeNotifyPrivilege enabled. A
 * token holds other privileges too, which vary with the account and the
 * machine's policy: no section prints the list. They print only whether
 * SeShutdownPrivilege, SeChangeNotifyPrivilege (and in notheld,
 * SeTcbPrivilege) are listed and their attributes, and the list's size
 * as relations.
 *
 * The privileges are named by their public LUIDs (winnt.h's
 * SE_*_PRIVILEGE values, the same on every machine): SeTcbPrivilege 7,
 * SeShutdownPrivilege 19, SeDebugPrivilege 20, SeChangeNotifyPrivilege
 * 23. Only the lookup section looks them up by name.
 *
 * SeShutdownPrivilege is enabled here only to observe the calls that
 * enable it, and each section that enables it disables it again before
 * doing anything but adjust or query the token: nothing prints while it
 * is enabled. This program calls no shutdown function: a token is
 * the process's own copy, so nothing here reaches another process.
 * user32's exitwin fixture calls ExitWindowsEx and NtShutdownSystem only
 * after checking its own token holds the privilege disabled.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   open        OpenProcessToken(GetCurrentProcess()) with TOKEN_QUERY,
 *               and with TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, and on a
 *               real handle to this process: the handle's object type
 *               and granted access (NtQueryObject), CloseHandle, twice
 *   openerr     OpenProcessToken on NULL, on the current thread's
 *               pseudo-handle, on an event, on a handle to this process
 *               opened with SYNCHRONIZE alone, with no access asked for,
 *               and with a NULL out-pointer: the return, the error, the
 *               out-handle (untouched, NULL or a handle)
 *   lookup      LookupPrivilegeValueA/W with a NULL system name for
 *               SeShutdownPrivilege, SeChangeNotifyPrivilege,
 *               SeDebugPrivilege, the first in lower case, an unknown
 *               name, an empty name, a NULL name, a NULL LUID pointer;
 *               then SeShutdownPrivilege on an empty system name, the
 *               local computer's name, and the name with a leading \\:
 *               whether the LUID is the NULL case's (the name never
 *               prints)
 *   adjust      AdjustTokenPrivileges enabling SeShutdownPrivilege, again,
 *               the token's view while enabled, disabling it, again: each
 *               call's return, error, PreviousState (count, LUID,
 *               attributes) and ReturnLength; the token's view before and
 *               after; then the same with no PreviousState
 *   prevshort   PreviousState's buffer too short (room for the count
 *               alone, then no room), each followed at once by the
 *               disable, whose PreviousState shows whether the short call
 *               changed anything; ReturnLength against the buffer
 *   disableall  DisableAllPrivileges: the return, error, and PreviousState
 *               as relations (SeChangeNotifyPrivilege in it, its old
 *               attributes); SeChangeNotifyPrivilege's attributes after
 *               it; PreviousState given back as NewState, restoring them
 *   notheld     a privilege the token does not hold (SeTcbPrivilege, an
 *               administrator's token holds it not) enabled and disabled:
 *               ERROR_NOT_ALL_ASSIGNED; with SeShutdownPrivilege in the
 *               same call (the one held is enabled, then disabled at
 *               once); a LUID no privilege has
 *   query       GetTokenInformation(TokenPrivileges): the size with no
 *               buffer, a 4-byte buffer, the size it asked for; on a token
 *               opened without TOKEN_QUERY; on NULL
 *   native      ntdll's NtOpenProcessToken and NtAdjustPrivilegesToken,
 *               through GetProcAddress: their statuses for the same cases
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat token):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% token.c advapi32.lib
 */

#include "../common/f2kt.h"

/* The privileges' public LUIDs (winnt.h's SE_*_PRIVILEGE). */
#define TCB_LUID 7
#define SHUTDOWN_LUID 19
#define DEBUG_LUID 20
#define CHANGE_NOTIFY_LUID 23
/* A LUID no privilege has. */
#define NO_PRIVILEGE_LUID 0x10000

/* The out-handle's sentinel: no call returns it. */
#define UNTOUCHED_HANDLE ((HANDLE)F2KT_UNTOUCHED)

/* --- ntdll, through GetProcAddress --------------------------------- */

/* PUBLIC_OBJECT_BASIC_INFORMATION (winternl.h), NtQueryObject's class 0
 * (ObjectBasicInformation): 56 bytes. */
typedef struct {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} object_basic_t;

/* UNICODE_STRING (winternl.h): ObjectTypeInformation's first field. */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} ustring_t;

#define OBJECT_BASIC 0                  /* ObjectBasicInformation */
#define OBJECT_TYPE 2                   /* ObjectTypeInformation */

/* NtQueryObject(Handle, ObjectInformationClass, ObjectInformation,
 * ObjectInformationLength, ReturnLength). */
typedef LONG (WINAPI *query_object_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
/* NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle). */
typedef LONG (WINAPI *open_token_fn)(HANDLE, ACCESS_MASK, PHANDLE);
/* NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState,
 * BufferLength, PreviousState, ReturnLength). */
typedef LONG (WINAPI *adjust_token_fn)(HANDLE, BOOLEAN, TOKEN_PRIVILEGES *, ULONG, TOKEN_PRIVILEGES *, PULONG);

static query_object_fn query_object;    /* NtQueryObject */
static open_token_fn nt_open_token;     /* NtOpenProcessToken */
static adjust_token_fn nt_adjust_token; /* NtAdjustPrivilegesToken */

/* --- helpers ------------------------------------------------------- */

/* A TOKEN_PRIVILEGES with room for two entries. */
typedef struct {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[2];
} two_privileges_t;

/* An out-handle as printed. */
static const char *handle_text(HANDLE h)
{
    if (h == UNTOUCHED_HANDLE) {
        return "untouched";
    }
    return h == NULL ? "NULL" : "a handle";
}

/* A LUID as printed: high:low, or "untouched" for the sentinel. */
static const char *luid_text(const LUID *luid)
{
    static char bufs[4][32];
    static int next;
    char *b = bufs[next++ & 3];

    if (luid->LowPart == F2KT_UNTOUCHED && (DWORD)luid->HighPart == F2KT_UNTOUCHED) {
        return "untouched";
    }
    sprintf(b, "%ld:%lu", luid->HighPart, luid->LowPart);
    return b;
}

/* One privilege in a TOKEN_PRIVILEGES. */
static void set_privilege(TOKEN_PRIVILEGES *tp, int index, DWORD luid, DWORD attributes)
{
    tp->Privileges[index].Luid.LowPart = luid;
    tp->Privileges[index].Luid.HighPart = 0;
    tp->Privileges[index].Attributes = attributes;
}

/* Where a privilege sits in a TOKEN_PRIVILEGES of `count` entries; -1
 * when it is not listed. */
static int find_privilege(const TOKEN_PRIVILEGES *tp, DWORD count, DWORD luid)
{
    DWORD i;

    for (i = 0; i < count; i++) {
        if (tp->Privileges[i].Luid.LowPart == luid && tp->Privileges[i].Luid.HighPart == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* What GetTokenInformation(TokenPrivileges) says of the privileges this
 * program watches, taken at once and printed later. */
typedef struct {
    BOOL ret;
    DWORD err;
    int shutdown;                       /* the index, or -1 */
    DWORD shutdown_attributes;
    int change_notify;
    DWORD change_notify_attributes;
    int tcb;
    DWORD tcb_attributes;
} view_t;

static ULONG view_buf[1024];            /* 4 KiB, aligned for the structure */

static void take_view(HANDLE token, view_t *v)
{
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)view_buf;
    DWORD len = 0;
    DWORD count;

    memset(v, 0, sizeof *v);
    memset(view_buf, 0, sizeof view_buf);
    arm();
    v->ret = GetTokenInformation(token, TokenPrivileges, view_buf, sizeof view_buf, &len);
    v->err = GetLastError();
    count = v->ret ? tp->PrivilegeCount : 0;
    if (count > (sizeof view_buf - sizeof(DWORD)) / sizeof(LUID_AND_ATTRIBUTES)) {
        count = 0;
    }
    v->shutdown = find_privilege(tp, count, SHUTDOWN_LUID);
    v->shutdown_attributes = v->shutdown >= 0 ? tp->Privileges[v->shutdown].Attributes : 0;
    v->change_notify = find_privilege(tp, count, CHANGE_NOTIFY_LUID);
    v->change_notify_attributes = v->change_notify >= 0 ? tp->Privileges[v->change_notify].Attributes : 0;
    v->tcb = find_privilege(tp, count, TCB_LUID);
    v->tcb_attributes = v->tcb >= 0 ? tp->Privileges[v->tcb].Attributes : 0;
}

/* One watched privilege as printed. */
static const char *listed_text(int index, DWORD attributes)
{
    static char bufs[4][48];
    static int next;
    char *b = bufs[next++ & 3];

    if (index < 0) {
        return "listed: no";
    }
    sprintf(b, "listed: yes, attributes 0x%lX", attributes);
    return b;
}

static void show_view(const char *label, const view_t *v)
{
    if (!v->ret) {
        line("%s: GetTokenInformation(TokenPrivileges) ret=%d err=%s", label, v->ret, le_of(v->err));
        return;
    }
    line("%s: SeShutdownPrivilege %s; SeChangeNotifyPrivilege %s", label,
         listed_text(v->shutdown, v->shutdown_attributes),
         listed_text(v->change_notify, v->change_notify_attributes));
}

/* One AdjustTokenPrivileges (or NtAdjustPrivilegesToken) call, taken at
 * once and printed later. */
typedef struct {
    BOOL ret;                           /* the status, for the native call */
    DWORD err;
    DWORD buffer_length;
    DWORD return_length;
    ULONG previous[64];                 /* 256 bytes: PreviousState */
} adjust_t;

/* AdjustTokenPrivileges(token, FALSE, {luid: attributes}, buffer_length,
 * PreviousState, &ReturnLength). */
static void adjust_one(adjust_t *r, HANDLE token, DWORD luid, DWORD attributes, DWORD buffer_length)
{
    TOKEN_PRIVILEGES tp;

    tp.PrivilegeCount = 1;
    set_privilege(&tp, 0, luid, attributes);
    memset(r->previous, 0xCC, sizeof r->previous);
    r->buffer_length = buffer_length;
    r->return_length = F2KT_UNTOUCHED;
    arm();
    r->ret = AdjustTokenPrivileges(token, FALSE, &tp, buffer_length, (TOKEN_PRIVILEGES *)r->previous,
                                   &r->return_length);
    r->err = GetLastError();
}

/* The same through NtAdjustPrivilegesToken; ret holds the status. */
static void nt_adjust_one(adjust_t *r, HANDLE token, DWORD luid, DWORD attributes, DWORD buffer_length)
{
    TOKEN_PRIVILEGES tp;

    tp.PrivilegeCount = 1;
    set_privilege(&tp, 0, luid, attributes);
    memset(r->previous, 0xCC, sizeof r->previous);
    r->buffer_length = buffer_length;
    r->return_length = F2KT_UNTOUCHED;
    r->err = F2KT_UNTOUCHED;
    r->ret = nt_adjust_token(token, FALSE, &tp, buffer_length, (TOKEN_PRIVILEGES *)r->previous,
                             &r->return_length);
}

/* PreviousState as printed: untouched, or its count and its entries (as
 * many as the buffer given holds, four at most). */
static const char *previous_text(const adjust_t *r)
{
    static char b[256];
    const TOKEN_PRIVILEGES *tp = (const TOKEN_PRIVILEGES *)r->previous;
    DWORD fits, i;
    int n;

    if (r->previous[0] == 0xCCCCCCCCu) {
        return "PreviousState untouched";
    }
    n = sprintf(b, "PreviousState: count %lu", tp->PrivilegeCount);
    fits = r->buffer_length < sizeof(DWORD) ? 0
         : (r->buffer_length - sizeof(DWORD)) / sizeof(LUID_AND_ATTRIBUTES);
    for (i = 0; i < tp->PrivilegeCount && i < fits && i < 4; i++) {
        n += sprintf(b + n, ", [%s 0x%lX]", luid_text(&tp->Privileges[i].Luid), tp->Privileges[i].Attributes);
    }
    return b;
}

/* ReturnLength as printed: untouched, or its value. */
static const char *length_text(DWORD len)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (len == F2KT_UNTOUCHED) {
        return "untouched";
    }
    sprintf(b, "%lu", len);
    return b;
}

static void show_adjust(const char *label, const adjust_t *r)
{
    line("%s: ret=%d err=%s; %s; ReturnLength %s", label, r->ret, le_of(r->err), previous_text(r),
         length_text(r->return_length));
}

static void show_nt_adjust(const char *label, const adjust_t *r)
{
    line("%s: status=0x%08lX; %s; ReturnLength %s", label, (unsigned long)r->ret, previous_text(r),
         length_text(r->return_length));
}

/* OpenProcessToken(GetCurrentProcess(), access), printed; NULL when it
 * fails. */
static HANDLE open_token(DWORD access, const char *access_name)
{
    HANDLE token = UNTOUCHED_HANDLE;
    BOOL r;

    arm();
    r = OpenProcessToken(GetCurrentProcess(), access, &token);
    line("OpenProcessToken(GetCurrentProcess(), %s): ret=%d err=%s, %s", access_name, r, le(),
         handle_text(token));
    return r ? token : NULL;
}

/* A handle's type name and granted access, through NtQueryObject. */
static void show_object(HANDLE h)
{
    static ULONG info[256];             /* 1 KiB, aligned for the structure */
    object_basic_t basic;
    ustring_t *us = (ustring_t *)info;
    BYTE *from = (BYTE *)info;
    ULONG len;
    LONG status;

    if (query_object == NULL) {
        line("  NtQueryObject not found");
        return;
    }
    memset(info, 0, sizeof info);
    len = F2KT_UNTOUCHED;
    status = query_object(h, OBJECT_TYPE, info, sizeof info, &len);
    if (status >= 0 && us->Buffer != NULL && (BYTE *)us->Buffer >= from
        && (BYTE *)us->Buffer + us->Length <= from + sizeof info) {
        line("  type: status=0x%08lX [%s]", (unsigned long)status, wsn(us->Buffer, us->Length / 2));
    } else if (status >= 0) {
        line("  type: status=0x%08lX, Length %u, its characters %s", (unsigned long)status, (unsigned)us->Length,
             us->Buffer == NULL ? "NULL" : "outside the buffer");
    } else {
        line("  type: status=0x%08lX", (unsigned long)status);
    }
    memset(&basic, 0xCC, sizeof basic);
    len = F2KT_UNTOUCHED;
    status = query_object(h, OBJECT_BASIC, &basic, sizeof basic, &len);
    if (status >= 0) {
        line("  basic information: status=0x%08lX; attributes 0x%lX, granted access 0x%08lX",
             (unsigned long)status, basic.Attributes, basic.GrantedAccess);
    } else {
        line("  basic information: status=0x%08lX", (unsigned long)status);
    }
}

static void close_twice(HANDLE h)
{
    BOOL r;

    arm();
    r = CloseHandle(h);
    line("  CloseHandle: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(h);
    line("  CloseHandle again: ret=%d err=%s", r, le());
}

/* --- open ---------------------------------------------------------- */

static void sec_open(void)
{
    HANDLE token, process;
    BOOL r;

    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token != NULL) {
        show_object(token);
        close_twice(token);
    }
    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token != NULL) {
        show_object(token);
        close_twice(token);
    }

    arm();
    process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    line("OpenProcess(PROCESS_QUERY_INFORMATION, this process): a handle: %s err=%s", yesno(process != NULL), le());
    if (process == NULL) {
        return;
    }
    token = UNTOUCHED_HANDLE;
    arm();
    r = OpenProcessToken(process, TOKEN_QUERY, &token);
    line("OpenProcessToken(that handle, TOKEN_QUERY): ret=%d err=%s, %s", r, le(), handle_text(token));
    if (r) {
        show_object(token);
        close_twice(token);
    }
    CloseHandle(process);
}

/* --- openerr ------------------------------------------------------- */

/* OpenProcessToken(process, TOKEN_QUERY) expected to fail; a handle it
 * gives anyway is closed. */
static void open_on(const char *label, HANDLE process, DWORD access)
{
    HANDLE token = UNTOUCHED_HANDLE;
    BOOL r;

    arm();
    r = OpenProcessToken(process, access, &token);
    line("OpenProcessToken(%s): ret=%d err=%s, %s", label, r, le(), handle_text(token));
    if (r && token != NULL && token != UNTOUCHED_HANDLE) {
        show_object(token);
        CloseHandle(token);
    }
}

static void sec_openerr(void)
{
    HANDLE event, process;
    BOOL r = FALSE;
    DWORD e = 0;
    int faulted = 0;
    DWORD code = 0;

    open_on("NULL, TOKEN_QUERY", NULL, TOKEN_QUERY);
    open_on("GetCurrentThread(), TOKEN_QUERY", GetCurrentThread(), TOKEN_QUERY);
    event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (event != NULL) {
        open_on("an event, TOKEN_QUERY", event, TOKEN_QUERY);
        CloseHandle(event);
    }
    arm();
    process = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    line("OpenProcess(SYNCHRONIZE, this process): a handle: %s err=%s", yesno(process != NULL), le());
    if (process != NULL) {
        open_on("that handle, TOKEN_QUERY", process, TOKEN_QUERY);
        CloseHandle(process);
    }
    open_on("GetCurrentProcess(), no access", GetCurrentProcess(), 0);

    arm();
    __try {
        r = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, NULL);
        e = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
        code = GetExceptionCode();
    }
    if (faulted) {
        line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, NULL): faulted 0x%08lX", code);
    } else {
        line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, NULL): ret=%d err=%s", r, le_of(e));
    }
}

/* --- lookup -------------------------------------------------------- */

static const char *const lookup_names[] = {
    "SeShutdownPrivilege",
    "SeChangeNotifyPrivilege",
    "SeDebugPrivilege",
    "seshutdownprivilege",
    "SeNoSuchPrivilege",
    "",
    NULL
};

static const WCHAR *const lookup_names_w[] = {
    L"SeShutdownPrivilege",
    L"SeChangeNotifyPrivilege",
    L"SeDebugPrivilege",
    L"seshutdownprivilege",
    L"SeNoSuchPrivilege",
    L"",
    NULL
};

static void untouched_luid(LUID *luid)
{
    luid->LowPart = F2KT_UNTOUCHED;
    luid->HighPart = (LONG)F2KT_UNTOUCHED;
}

/* LookupPrivilegeValueA(system, name, luid) inside __try: the return, or
 * the fault's code in *code. */
static BOOL lookup_a(const char *system, const char *name, LUID *luid, DWORD *err, DWORD *code)
{
    BOOL r = FALSE;

    *code = 0;
    arm();
    __try {
        r = LookupPrivilegeValueA(system, name, luid);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return r;
}

static BOOL lookup_w(const WCHAR *system, const WCHAR *name, LUID *luid, DWORD *err, DWORD *code)
{
    BOOL r = FALSE;

    *code = 0;
    arm();
    __try {
        r = LookupPrivilegeValueW(system, name, luid);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return r;
}

static void show_lookup(const char *call, const char *label, BOOL r, DWORD err, DWORD code, const LUID *luid)
{
    if (code != 0) {
        line("%s(NULL, %s): faulted 0x%08lX", call, label, code);
    } else if (luid == NULL) {
        line("%s(NULL, %s): ret=%d err=%s", call, label, r, le_of(err));
    } else {
        line("%s(NULL, %s): ret=%d err=%s luid=%s", call, label, r, le_of(err), luid_text(luid));
    }
}

/* SeShutdownPrivilege looked up on a system name, A and W, against the
 * NULL case's LUID; the name itself never prints. */
static void lookup_on(const char *label, const char *system, const WCHAR *system_w, const LUID *expected)
{
    LUID luid;
    DWORD err, code;
    BOOL r;

    untouched_luid(&luid);
    r = lookup_a(system, "SeShutdownPrivilege", &luid, &err, &code);
    if (code != 0) {
        line("LookupPrivilegeValueA(%s, \"SeShutdownPrivilege\"): faulted 0x%08lX", label, code);
    } else {
        line("LookupPrivilegeValueA(%s, \"SeShutdownPrivilege\"): ret=%d err=%s, the NULL case's LUID: %s", label,
             r, le_of(err), yesno(memcmp(&luid, expected, sizeof luid) == 0));
    }
    untouched_luid(&luid);
    r = lookup_w(system_w, L"SeShutdownPrivilege", &luid, &err, &code);
    if (code != 0) {
        line("LookupPrivilegeValueW(%s, \"SeShutdownPrivilege\"): faulted 0x%08lX", label, code);
    } else {
        line("LookupPrivilegeValueW(%s, \"SeShutdownPrivilege\"): ret=%d err=%s, the NULL case's LUID: %s", label,
             r, le_of(err), yesno(memcmp(&luid, expected, sizeof luid) == 0));
    }
}

static void sec_lookup(void)
{
    char quoted[64];
    char computer[MAX_COMPUTERNAME_LENGTH + 1];
    char unc[MAX_COMPUTERNAME_LENGTH + 3];
    WCHAR computer_w[MAX_COMPUTERNAME_LENGTH + 1];
    WCHAR unc_w[MAX_COMPUTERNAME_LENGTH + 3];
    DWORD size, err, code;
    LUID luid, shutdown;
    BOOL r;
    int i;

    for (i = 0; lookup_names[i] != NULL; i++) {
        sprintf(quoted, "\"%s\"", lookup_names[i]);
        untouched_luid(&luid);
        r = lookup_a(NULL, lookup_names[i], &luid, &err, &code);
        show_lookup("LookupPrivilegeValueA", quoted, r, err, code, &luid);
        untouched_luid(&luid);
        r = lookup_w(NULL, lookup_names_w[i], &luid, &err, &code);
        show_lookup("LookupPrivilegeValueW", quoted, r, err, code, &luid);
    }
    untouched_luid(&shutdown);
    lookup_a(NULL, "SeShutdownPrivilege", &shutdown, &err, &code);
    lookup_on("\"\"", "", L"", &shutdown);
    size = sizeof computer;
    if (!GetComputerNameA(computer, &size)) {
        line("GetComputerNameA failed: err=%lu", GetLastError());
        return;
    }
    size = sizeof computer_w / sizeof computer_w[0];
    if (!GetComputerNameW(computer_w, &size)) {
        line("GetComputerNameW failed: err=%lu", GetLastError());
        return;
    }
    lookup_on("the local computer's name", computer, computer_w, &shutdown);
    sprintf(unc, "\\\\%s", computer);
    unc_w[0] = L'\\';
    unc_w[1] = L'\\';
    lstrcpyW(unc_w + 2, computer_w);
    lookup_on("\\\\ and the local computer's name", unc, unc_w, &shutdown);

    /* NULL pointers last: a fault caught inside the call leaves nothing
     * else in this process to run. */
    untouched_luid(&luid);
    r = lookup_a(NULL, NULL, &luid, &err, &code);
    show_lookup("LookupPrivilegeValueA", "NULL", r, err, code, &luid);
    untouched_luid(&luid);
    r = lookup_w(NULL, NULL, &luid, &err, &code);
    show_lookup("LookupPrivilegeValueW", "NULL", r, err, code, &luid);
    r = lookup_a(NULL, "SeShutdownPrivilege", NULL, &err, &code);
    show_lookup("LookupPrivilegeValueA", "\"SeShutdownPrivilege\", a NULL LUID pointer", r, err, code, NULL);
    r = lookup_w(NULL, L"SeShutdownPrivilege", NULL, &err, &code);
    show_lookup("LookupPrivilegeValueW", "\"SeShutdownPrivilege\", a NULL LUID pointer", r, err, code, NULL);
}

/* --- adjust -------------------------------------------------------- */

static void sec_adjust(void)
{
    TOKEN_PRIVILEGES tp;
    view_t before, during, after, last;
    adjust_t enable, again, disable, disable_again;
    HANDLE token;
    BOOL r1, r2;
    DWORD e1, e2;

    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    take_view(token, &before);
    /* Enabled, then disabled again before anything else: only a query in
     * between, and nothing printed until it is disabled. */
    adjust_one(&enable, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, sizeof enable.previous);
    adjust_one(&again, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, sizeof again.previous);
    take_view(token, &during);
    adjust_one(&disable, token, SHUTDOWN_LUID, 0, sizeof disable.previous);
    adjust_one(&disable_again, token, SHUTDOWN_LUID, 0, sizeof disable_again.previous);
    take_view(token, &after);

    show_view("before", &before);
    show_adjust("AdjustTokenPrivileges(enable SeShutdownPrivilege)", &enable);
    show_adjust("AdjustTokenPrivileges(enable it again)", &again);
    show_view("while enabled", &during);
    show_adjust("AdjustTokenPrivileges(disable it)", &disable);
    show_adjust("AdjustTokenPrivileges(disable it again)", &disable_again);
    show_view("after", &after);

    /* No PreviousState: BufferLength 0, PreviousState and ReturnLength
     * NULL. Disabled again by the very next call. */
    tp.PrivilegeCount = 1;
    set_privilege(&tp, 0, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED);
    arm();
    r1 = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    e1 = GetLastError();
    set_privilege(&tp, 0, SHUTDOWN_LUID, 0);
    arm();
    r2 = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    e2 = GetLastError();
    take_view(token, &last);
    line("AdjustTokenPrivileges(enable SeShutdownPrivilege, no PreviousState): ret=%d err=%s", r1, le_of(e1));
    line("AdjustTokenPrivileges(disable it, no PreviousState): ret=%d err=%s", r2, le_of(e2));
    show_view("after", &last);
    CloseHandle(token);
}

/* --- prevshort ----------------------------------------------------- */

static void show_short(const char *label, const adjust_t *r)
{
    show_adjust(label, r);
    if (r->return_length != F2KT_UNTOUCHED) {
        line("  ReturnLength more than the buffer given: %s; one entry's TOKEN_PRIVILEGES (%u): %s",
             yesno(r->return_length > r->buffer_length), (unsigned)sizeof(TOKEN_PRIVILEGES),
             yesno(r->return_length == sizeof(TOKEN_PRIVILEGES)));
    }
}

static void sec_prevshort(void)
{
    view_t before, after;
    adjust_t short1, disable1, short2, disable2;
    HANDLE token;

    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    take_view(token, &before);
    /* Each short call is followed at once by the disable: whether the
     * short call enabled the privilege shows in the disable's
     * PreviousState, never in a token left enabled. */
    adjust_one(&short1, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, sizeof(DWORD));
    adjust_one(&disable1, token, SHUTDOWN_LUID, 0, sizeof disable1.previous);
    adjust_one(&short2, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, 0);
    adjust_one(&disable2, token, SHUTDOWN_LUID, 0, sizeof disable2.previous);
    take_view(token, &after);

    show_view("before", &before);
    show_short("AdjustTokenPrivileges(enable SeShutdownPrivilege, PreviousState of 4 bytes)", &short1);
    show_adjust("AdjustTokenPrivileges(disable it)", &disable1);
    show_short("AdjustTokenPrivileges(enable SeShutdownPrivilege, PreviousState of 0 bytes)", &short2);
    show_adjust("AdjustTokenPrivileges(disable it)", &disable2);
    show_view("after", &after);
    CloseHandle(token);
}

/* --- disableall ---------------------------------------------------- */

static ULONG all_previous[1024];         /* 4 KiB: every enabled privilege */

static void sec_disableall(void)
{
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)all_previous;
    view_t before, during, after;
    HANDLE token;
    DWORD len, count, e, e2 = 0;
    BOOL r, r2 = FALSE;
    int sane, at;

    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    take_view(token, &before);
    memset(all_previous, 0xCC, sizeof all_previous);
    len = F2KT_UNTOUCHED;
    arm();
    r = AdjustTokenPrivileges(token, TRUE, NULL, sizeof all_previous, tp, &len);
    e = GetLastError();
    take_view(token, &during);
    count = tp->PrivilegeCount;
    sane = r && count != 0xCCCCCCCCu
        && count <= (sizeof all_previous - sizeof(DWORD)) / sizeof(LUID_AND_ATTRIBUTES);
    /* PreviousState given back as NewState restores what it disabled. */
    if (sane) {
        arm();
        r2 = AdjustTokenPrivileges(token, FALSE, tp, 0, NULL, NULL);
        e2 = GetLastError();
    }
    take_view(token, &after);

    show_view("before", &before);
    line("AdjustTokenPrivileges(DisableAllPrivileges): ret=%d err=%s", r, le_of(e));
    if (!sane) {
        line("  PreviousState: count %s; ReturnLength %s", count == 0xCCCCCCCCu ? "untouched" : "out of range",
             length_text(len));
        CloseHandle(token);
        return;
    }
    line("  PreviousState: at least one entry: %s; ReturnLength the count and its entries: %s",
         yesno(count >= 1), yesno(len == sizeof(DWORD) + count * sizeof(LUID_AND_ATTRIBUTES)));
    at = find_privilege(tp, count, CHANGE_NOTIFY_LUID);
    line("  SeChangeNotifyPrivilege in PreviousState: %s", listed_text(at, at >= 0 ? tp->Privileges[at].Attributes : 0));
    at = find_privilege(tp, count, SHUTDOWN_LUID);
    line("  SeShutdownPrivilege in PreviousState: %s", listed_text(at, at >= 0 ? tp->Privileges[at].Attributes : 0));
    show_view("after it", &during);
    line("AdjustTokenPrivileges(NewState = that PreviousState): ret=%d err=%s", r2, le_of(e2));
    show_view("after the restore", &after);
    CloseHandle(token);
}

/* --- notheld ------------------------------------------------------- */

static void sec_notheld(void)
{
    two_privileges_t both;
    view_t before, after;
    adjust_t tcb, tcb_off, none, mixed, disable;
    HANDLE token;
    BOOL r;
    DWORD e;

    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    take_view(token, &before);
    show_view("before", &before);
    line("before: SeTcbPrivilege %s", listed_text(before.tcb, before.tcb_attributes));
    if (!before.ret || before.tcb >= 0) {
        line("SeTcbPrivilege is held or the view failed: not adjusting it");
        CloseHandle(token);
        return;
    }
    adjust_one(&tcb, token, TCB_LUID, SE_PRIVILEGE_ENABLED, sizeof tcb.previous);
    adjust_one(&tcb_off, token, TCB_LUID, 0, sizeof tcb_off.previous);
    adjust_one(&none, token, NO_PRIVILEGE_LUID, SE_PRIVILEGE_ENABLED, sizeof none.previous);
    show_adjust("AdjustTokenPrivileges(enable SeTcbPrivilege)", &tcb);
    show_adjust("AdjustTokenPrivileges(disable SeTcbPrivilege)", &tcb_off);
    show_adjust("AdjustTokenPrivileges(enable LUID 0:65536, no privilege's)", &none);

    /* SeTcbPrivilege and SeShutdownPrivilege in one call: the held one is
     * enabled, and disabled again by the very next call. */
    both.PrivilegeCount = 2;
    set_privilege((TOKEN_PRIVILEGES *)&both, 0, TCB_LUID, SE_PRIVILEGE_ENABLED);
    set_privilege((TOKEN_PRIVILEGES *)&both, 1, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED);
    memset(mixed.previous, 0xCC, sizeof mixed.previous);
    mixed.buffer_length = sizeof mixed.previous;
    mixed.return_length = F2KT_UNTOUCHED;
    arm();
    r = AdjustTokenPrivileges(token, FALSE, (TOKEN_PRIVILEGES *)&both, sizeof mixed.previous,
                              (TOKEN_PRIVILEGES *)mixed.previous, &mixed.return_length);
    e = GetLastError();
    adjust_one(&disable, token, SHUTDOWN_LUID, 0, sizeof disable.previous);
    mixed.ret = r;
    mixed.err = e;
    take_view(token, &after);
    show_adjust("AdjustTokenPrivileges(enable SeTcbPrivilege and SeShutdownPrivilege)", &mixed);
    show_adjust("AdjustTokenPrivileges(disable SeShutdownPrivilege)", &disable);
    show_view("after", &after);
    line("after: SeTcbPrivilege %s", listed_text(after.tcb, after.tcb_attributes));
    CloseHandle(token);
}

/* --- query --------------------------------------------------------- */

static ULONG query_buf[1024];           /* 4 KiB */

static void sec_query(void)
{
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)query_buf;
    HANDLE token;
    DWORD len, len2, need, count;
    BOOL r;
    int at;

    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token == NULL) {
        return;
    }
    len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(token, TokenPrivileges, NULL, 0, &len);
    need = len;
    line("GetTokenInformation(TokenPrivileges, no buffer): ret=%d err=%s; ReturnLength the count and whole entries: %s",
         r, le(), yesno(len != F2KT_UNTOUCHED && len > sizeof(DWORD)
                        && (len - sizeof(DWORD)) % sizeof(LUID_AND_ATTRIBUTES) == 0));
    len2 = F2KT_UNTOUCHED;
    memset(query_buf, 0xCC, sizeof query_buf);
    arm();
    r = GetTokenInformation(token, TokenPrivileges, query_buf, sizeof(DWORD), &len2);
    line("GetTokenInformation(TokenPrivileges, 4 bytes): ret=%d err=%s; ReturnLength the same: %s; the buffer untouched: %s",
         r, le(), yesno(len2 == need), yesno(query_buf[0] == 0xCCCCCCCCu));
    if (need == F2KT_UNTOUCHED || need > sizeof query_buf) {
        line("no size to ask for");
        CloseHandle(token);
        return;
    }
    len2 = F2KT_UNTOUCHED;
    memset(query_buf, 0, sizeof query_buf);
    arm();
    r = GetTokenInformation(token, TokenPrivileges, query_buf, need, &len2);
    count = tp->PrivilegeCount;
    line("GetTokenInformation(TokenPrivileges, the size asked for): ret=%d err=%s; ReturnLength the same: %s", r, le(),
         yesno(len2 == need));
    if (r) {
        line("  count: at least 2: %s; the size the count's entries take: %s", yesno(count >= 2),
             yesno(need == sizeof(DWORD) + count * sizeof(LUID_AND_ATTRIBUTES)));
        at = find_privilege(tp, count, SHUTDOWN_LUID);
        line("  SeShutdownPrivilege %s", listed_text(at, at >= 0 ? tp->Privileges[at].Attributes : 0));
        at = find_privilege(tp, count, CHANGE_NOTIFY_LUID);
        line("  SeChangeNotifyPrivilege %s", listed_text(at, at >= 0 ? tp->Privileges[at].Attributes : 0));
    }
    CloseHandle(token);

    token = open_token(TOKEN_ADJUST_PRIVILEGES, "TOKEN_ADJUST_PRIVILEGES");
    if (token != NULL) {
        len = F2KT_UNTOUCHED;
        arm();
        r = GetTokenInformation(token, TokenPrivileges, query_buf, sizeof query_buf, &len);
        line("GetTokenInformation(TokenPrivileges) without TOKEN_QUERY: ret=%d err=%s; ReturnLength %s", r, le(),
             length_text(len));
        CloseHandle(token);
    }
    len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(NULL, TokenPrivileges, query_buf, sizeof query_buf, &len);
    line("GetTokenInformation(NULL, TokenPrivileges): ret=%d err=%s; ReturnLength %s", r, le(), length_text(len));
}

/* --- native -------------------------------------------------------- */

static void sec_native(void)
{
    view_t before, after;
    adjust_t enable, disable, short1, disable1, tcb;
    HANDLE token, other;
    LONG status, s2 = 0;
    int faulted = 0;
    DWORD code = 0;

    if (nt_open_token == NULL || nt_adjust_token == NULL) {
        line("NtOpenProcessToken or NtAdjustPrivilegesToken not found");
        return;
    }
    token = UNTOUCHED_HANDLE;
    status = nt_open_token(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES): status=0x%08lX, %s",
         (unsigned long)status, handle_text(token));
    if (status < 0 || token == NULL || token == UNTOUCHED_HANDLE) {
        return;
    }
    show_object(token);
    other = UNTOUCHED_HANDLE;
    status = nt_open_token(NULL, TOKEN_QUERY, &other);
    line("NtOpenProcessToken(NULL, TOKEN_QUERY): status=0x%08lX, %s", (unsigned long)status, handle_text(other));
    if (status >= 0 && other != NULL && other != UNTOUCHED_HANDLE) {
        CloseHandle(other);
    }
    other = UNTOUCHED_HANDLE;
    status = nt_open_token(GetCurrentThread(), TOKEN_QUERY, &other);
    line("NtOpenProcessToken(GetCurrentThread(), TOKEN_QUERY): status=0x%08lX, %s", (unsigned long)status,
         handle_text(other));
    if (status >= 0 && other != NULL && other != UNTOUCHED_HANDLE) {
        CloseHandle(other);
    }
    __try {
        s2 = nt_open_token(GetCurrentProcess(), TOKEN_QUERY, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
        code = GetExceptionCode();
    }
    if (faulted) {
        line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, NULL): faulted 0x%08lX", code);
    } else {
        line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, NULL): status=0x%08lX", (unsigned long)s2);
    }

    take_view(token, &before);
    /* Each enable is followed at once by the disable, nothing printed in
     * between. */
    nt_adjust_one(&enable, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, sizeof enable.previous);
    nt_adjust_one(&disable, token, SHUTDOWN_LUID, 0, sizeof disable.previous);
    nt_adjust_one(&short1, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, sizeof(DWORD));
    nt_adjust_one(&disable1, token, SHUTDOWN_LUID, 0, sizeof disable1.previous);
    take_view(token, &after);
    show_view("before", &before);
    show_nt_adjust("NtAdjustPrivilegesToken(enable SeShutdownPrivilege)", &enable);
    show_nt_adjust("NtAdjustPrivilegesToken(disable it)", &disable);
    show_nt_adjust("NtAdjustPrivilegesToken(enable SeShutdownPrivilege, PreviousState of 4 bytes)", &short1);
    show_nt_adjust("NtAdjustPrivilegesToken(disable it)", &disable1);
    show_view("after", &after);

    if (before.ret && before.tcb < 0) {
        nt_adjust_one(&tcb, token, TCB_LUID, SE_PRIVILEGE_ENABLED, sizeof tcb.previous);
        show_nt_adjust("NtAdjustPrivilegesToken(enable SeTcbPrivilege, not held)", &tcb);
    } else {
        line("SeTcbPrivilege is held or the view failed: not adjusting it");
    }
    status = nt_adjust_token(token, FALSE, NULL, 0, NULL, NULL);
    line("NtAdjustPrivilegesToken(no NewState, DisableAllPrivileges FALSE): status=0x%08lX", (unsigned long)status);
    status = nt_adjust_token(NULL, FALSE, NULL, 0, NULL, NULL);
    line("NtAdjustPrivilegesToken(NULL, no NewState): status=0x%08lX", (unsigned long)status);
    CloseHandle(token);
}

/* --- main ---------------------------------------------------------- */

static const section_t sections[] = {
    { "open", sec_open, F2KT_ALWAYS },
    { "openerr", sec_openerr, F2KT_ALWAYS },
    { "lookup", sec_lookup, F2KT_ALWAYS },
    { "adjust", sec_adjust, F2KT_ALWAYS },
    { "prevshort", sec_prevshort, F2KT_ALWAYS },
    { "disableall", sec_disableall, F2KT_ALWAYS },
    { "notheld", sec_notheld, F2KT_ALWAYS },
    { "query", sec_query, F2KT_ALWAYS },
    { "native", sec_native, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    HMODULE ntdll;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    ntdll = GetModuleHandleA("ntdll.dll");
    query_object = (query_object_fn)GetProcAddress(ntdll, "NtQueryObject");
    nt_open_token = (open_token_fn)GetProcAddress(ntdll, "NtOpenProcessToken");
    nt_adjust_token = (adjust_token_fn)GetProcAddress(ntdll, "NtAdjustPrivilegesToken");
    return run_sections("token", sections, argc, argv);
}
