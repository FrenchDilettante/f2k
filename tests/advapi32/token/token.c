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
 *   tokclass    GetTokenInformation's sizes, class by class (TokenUser,
 *               TokenGroups, TokenOwner, TokenPrimaryGroup,
 *               TokenDefaultDacl, TokenSource, TokenType,
 *               TokenImpersonationLevel, TokenStatistics,
 *               TokenRestrictedSids, TokenSessionId): the size query, a
 *               buffer a byte short, the size asked for; classes 0 and
 *               99; TokenSource without TOKEN_QUERY_SOURCE and TokenUser
 *               without TOKEN_QUERY
 *   toksids     TokenUser, TokenOwner, TokenPrimaryGroup and TokenGroups:
 *               each SID by what it is (below), the well-known groups
 *               listed and their attributes, the sizes as relations
 *   tokmisc     TokenDefaultDacl's ACEs, TokenSource's name,
 *               TokenType, TokenImpersonationLevel, TokenSessionId,
 *               TokenStatistics (its LUIDs as relations, its counts
 *               against TokenGroups' and TokenPrivileges', ModifiedId
 *               across an adjust); a DuplicateToken impersonation copy's
 *               type and level
 *   admin       "am I an administrator": the TokenGroups scan, then
 *               CheckTokenMembership with a NULL token, the primary
 *               token and an identification copy, over the well-known
 *               groups; AllocateAndInitializeSid, EqualSid, FreeSid
 *   privs       SeSystemtimePrivilege, SeBackupPrivilege,
 *               SeShutdownPrivilege and SeDebugPrivilege, which an
 *               administrator's token holds disabled: their lookup, each
 *               enabled and put back at once, then all four in one call
 *               and its PreviousState given back
 *
 * A SID prints by what it is, never by the machine's numbers: a
 * well-known one by its name and string form (Everyone, LOCAL,
 * INTERACTIVE, Authenticated Users, SYSTEM, BUILTIN\Administrators,
 * Users, Guests, Power Users), a logon SID as S-1-5-5-*-*, an account
 * domain's (S-1-5-21-*-*-*) by its RID below 1000 only; the token's
 * LUIDs print as zero or nonzero and as relations. CheckTokenMembership,
 * DuplicateToken, AllocateAndInitializeSid, EqualSid and FreeSid are
 * reached through GetProcAddress, so the program loads where advapi32
 * lacks them.
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

    if (index == -2) {
        return "the view failed";
    }
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

/* --- SIDs, printed by what they are -------------------------------- */

/* A SID with room for five sub-authorities, built by hand: the layout is
 * public (winnt.h's SID), so no advapi32 call builds the well-known ones. */
typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid5_t sid_local = { 1, 1, { 0, 0, 0, 0, 0, 2 }, { 0 } };
static const sid5_t sid_interactive = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 4 } };
static const sid5_t sid_authenticated = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 11 } };
static const sid5_t sid_system = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
static const sid5_t sid_admins = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };
static const sid5_t sid_users = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 545 } };
static const sid5_t sid_guests = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 546 } };
static const sid5_t sid_power_users = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 547 } };

/* A SID's size in bytes, from its sub-authority count. */
static DWORD sid_size(const void *sid)
{
    return 8 + 4 * (DWORD)((const BYTE *)sid)[1];
}

static DWORD sid_sub(const void *sid, int i)
{
    DWORD v;

    memcpy(&v, (const BYTE *)sid + 8 + 4 * i, sizeof v);
    return v;
}

/* The identifier authority's low 32 bits (the high 16 are 0 for every
 * authority Windows 2000 hands out). */
static DWORD sid_authority(const void *sid)
{
    const BYTE *a = (const BYTE *)sid + 2;

    return ((DWORD)a[2] << 24) | ((DWORD)a[3] << 16) | ((DWORD)a[4] << 8) | a[5];
}

/* An account domain's SID: S-1-5-21 and three more sub-authorities, then
 * the RID. */
static int is_account(const void *sid)
{
    return ((const BYTE *)sid)[1] == 5 && sid_authority(sid) == 5 && sid_sub(sid, 0) == 21;
}

/* A SID as printed: a well-known one by its name and string form, an
 * account domain's by its RID only below 1000 (the domain's numbers and a
 * user's RID are the machine's), a logon SID without its numbers, any
 * other in full. */
static const char *sid_text(const void *sid)
{
    static char bufs[4][96];
    static int next;
    char *b = bufs[next++ & 3];
    BYTE count;
    DWORD auth, s0;
    int n, i;

    if (sid == NULL) {
        return "NULL";
    }
    count = ((const BYTE *)sid)[1];
    auth = sid_authority(sid);
    s0 = count > 0 ? sid_sub(sid, 0) : 0;
    if (((const BYTE *)sid)[0] != 1 || count > 15) {
        return "not a SID";
    }
    if (count == 1 && auth == 1 && s0 == 0) {
        return "Everyone (S-1-1-0)";
    }
    if (count == 1 && auth == 2 && s0 == 0) {
        return "LOCAL (S-1-2-0)";
    }
    if (count == 1 && auth == 5) {
        switch (s0) {
        case 4: return "INTERACTIVE (S-1-5-4)";
        case 11: return "Authenticated Users (S-1-5-11)";
        case 18: return "SYSTEM (S-1-5-18)";
        }
    }
    if (count == 2 && auth == 5 && s0 == 32) {
        switch (sid_sub(sid, 1)) {
        case 544: return "BUILTIN\\Administrators (S-1-5-32-544)";
        case 545: return "BUILTIN\\Users (S-1-5-32-545)";
        case 546: return "BUILTIN\\Guests (S-1-5-32-546)";
        case 547: return "BUILTIN\\Power Users (S-1-5-32-547)";
        }
    }
    if (count == 3 && auth == 5 && s0 == 5) {
        return "a logon SID (S-1-5-5-*-*)";
    }
    if (is_account(sid)) {
        if (sid_sub(sid, 4) < 1000) {
            sprintf(b, "the account domain's RID %lu (S-1-5-21-*-*-*-%lu)", sid_sub(sid, 4), sid_sub(sid, 4));
        } else {
            sprintf(b, "the account domain's user RID, 1000 or more (S-1-5-21-*-*-*-*)");
        }
        return b;
    }
    n = sprintf(b, "S-1-%lu", auth);
    for (i = 0; i < count && n < (int)sizeof bufs[0] - 12; i++) {
        n += sprintf(b + n, "-%lu", sid_sub(sid, i));
    }
    return b;
}

/* --- GetTokenInformation, class by class --------------------------- */

#define CLASS_RESTRICTED_SIDS ((TOKEN_INFORMATION_CLASS)11)
#define CLASS_SESSION_ID ((TOKEN_INFORMATION_CLASS)12)

static ULONG info_buf[1024];            /* 4 KiB, aligned for every class */

/* GetTokenInformation(token, cls) the way a program sizes it: the size
 * query, the buffer a byte short of it, then exactly that size, which
 * leaves the answer in info_buf. `fixed` prints the size itself, for the
 * classes whose size is the structure's; the others print it as the
 * size the full call fills. Whether the full call succeeded. */
static BOOL query_class(HANDLE token, TOKEN_INFORMATION_CLASS cls, const char *name, int fixed)
{
    DWORD need = F2KT_UNTOUCHED, len;
    BOOL r;

    arm();
    r = GetTokenInformation(token, cls, NULL, 0, &need);
    if (fixed || need == F2KT_UNTOUCHED) {
        line("GetTokenInformation(%s, no buffer): ret=%d err=%s ReturnLength %s", name, r, le(),
             length_text(need));
    } else {
        line("GetTokenInformation(%s, no buffer): ret=%d err=%s ReturnLength given", name, r, le());
    }
    if (need == F2KT_UNTOUCHED || need == 0 || need > sizeof info_buf) {
        line("  no size to ask for");
        return FALSE;
    }
    memset(info_buf, 0xCC, sizeof info_buf);
    len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(token, cls, info_buf, need - 1, &len);
    line("  a buffer a byte short: ret=%d err=%s ReturnLength the same: %s; the buffer untouched: %s", r, le(),
         yesno(len == need), yesno(info_buf[0] == 0xCCCCCCCCu));
    memset(info_buf, 0xCC, sizeof info_buf);
    len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(token, cls, info_buf, need, &len);
    line("  the size asked for: ret=%d err=%s ReturnLength the same: %s", r, le(), yesno(len == need));
    return r;
}

static void sec_tokclass(void)
{
    HANDLE token;
    DWORD len;
    BOOL r;

    token = open_token(TOKEN_QUERY | TOKEN_QUERY_SOURCE, "TOKEN_QUERY | TOKEN_QUERY_SOURCE");
    if (token == NULL) {
        return;
    }
    query_class(token, TokenUser, "TokenUser", 0);
    query_class(token, TokenGroups, "TokenGroups", 0);
    query_class(token, TokenOwner, "TokenOwner", 0);
    query_class(token, TokenPrimaryGroup, "TokenPrimaryGroup", 0);
    query_class(token, TokenDefaultDacl, "TokenDefaultDacl", 0);
    query_class(token, TokenSource, "TokenSource", 1);
    query_class(token, TokenType, "TokenType", 1);
    query_class(token, TokenImpersonationLevel, "TokenImpersonationLevel", 1);
    query_class(token, TokenStatistics, "TokenStatistics", 1);
    query_class(token, CLASS_RESTRICTED_SIDS, "TokenRestrictedSids (11)", 1);
    query_class(token, CLASS_SESSION_ID, "TokenSessionId (12)", 1);
    len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)0, info_buf, sizeof info_buf, &len);
    line("GetTokenInformation(class 0): ret=%d err=%s ReturnLength %s", r, le(), length_text(len));
    len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)99, info_buf, sizeof info_buf, &len);
    line("GetTokenInformation(class 99): ret=%d err=%s ReturnLength %s", r, le(), length_text(len));
    CloseHandle(token);

    /* TokenSource needs TOKEN_QUERY_SOURCE, the rest TOKEN_QUERY. */
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token != NULL) {
        len = F2KT_UNTOUCHED;
        arm();
        r = GetTokenInformation(token, TokenSource, info_buf, sizeof info_buf, &len);
        line("GetTokenInformation(TokenSource) without TOKEN_QUERY_SOURCE: ret=%d err=%s ReturnLength %s", r, le(),
             length_text(len));
        CloseHandle(token);
    }
    token = open_token(TOKEN_QUERY_SOURCE, "TOKEN_QUERY_SOURCE");
    if (token != NULL) {
        len = F2KT_UNTOUCHED;
        arm();
        r = GetTokenInformation(token, TokenUser, info_buf, sizeof info_buf, &len);
        line("GetTokenInformation(TokenUser) without TOKEN_QUERY: ret=%d err=%s ReturnLength %s", r, le(),
             length_text(len));
        len = F2KT_UNTOUCHED;
        arm();
        r = GetTokenInformation(token, TokenSource, info_buf, sizeof info_buf, &len);
        line("GetTokenInformation(TokenSource) with TOKEN_QUERY_SOURCE alone: ret=%d err=%s ReturnLength %s", r,
             le(), length_text(len));
        CloseHandle(token);
    }
}

/* GetTokenInformation(token, cls) into info_buf, printed as one line. */
static BOOL fetch(HANDLE token, TOKEN_INFORMATION_CLASS cls, const char *name, DWORD *len)
{
    BOOL r;

    memset(info_buf, 0xCC, sizeof info_buf);
    *len = F2KT_UNTOUCHED;
    arm();
    r = GetTokenInformation(token, cls, info_buf, sizeof info_buf, len);
    line("GetTokenInformation(%s): ret=%d err=%s", name, r, le());
    return r;
}

/* Whether `sid` points inside info_buf, its whole size too. */
static int inside(const void *p, DWORD size)
{
    const BYTE *b = (const BYTE *)p;

    return b >= (const BYTE *)info_buf && b + size <= (const BYTE *)info_buf + sizeof info_buf;
}

/* --- toksids ------------------------------------------------------- */

/* The well-known groups looked for in TokenGroups. */
static const struct {
    const sid5_t *sid;
    const char *name;
} known_groups[] = {
    { &sid_everyone, "Everyone" },
    { &sid_local, "LOCAL" },
    { &sid_interactive, "INTERACTIVE" },
    { &sid_authenticated, "Authenticated Users" },
    { &sid_admins, "BUILTIN\\Administrators" },
    { &sid_users, "BUILTIN\\Users" },
    { &sid_power_users, "BUILTIN\\Power Users" },
    { &sid_guests, "BUILTIN\\Guests" },
    { &sid_system, "SYSTEM" },
    { NULL, NULL }
};

static int same_sid(const void *a, const void *b)
{
    return sid_size(a) == sid_size(b) && memcmp(a, b, sid_size(a)) == 0;
}

/* Two account SIDs of the same domain: S-1-5-21-a-b-c alike. */
static int same_domain(const void *a, const void *b)
{
    return is_account(a) && is_account(b) && sid_sub(a, 1) == sid_sub(b, 1) && sid_sub(a, 2) == sid_sub(b, 2)
        && sid_sub(a, 3) == sid_sub(b, 3);
}

static void sec_toksids(void)
{
    TOKEN_USER *tu = (TOKEN_USER *)info_buf;
    TOKEN_OWNER *to = (TOKEN_OWNER *)info_buf;
    TOKEN_PRIMARY_GROUP *tg = (TOKEN_PRIMARY_GROUP *)info_buf;
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)info_buf;
    sid5_t user;
    HANDLE token;
    DWORD len, count, i, total, named;
    int k, found, logon, rid513;

    memset(&user, 0, sizeof user);
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token == NULL) {
        return;
    }
    if (fetch(token, TokenUser, "TokenUser", &len) && inside(tu->User.Sid, 8)
        && inside(tu->User.Sid, sid_size(tu->User.Sid))) {
        line("  the user: %s, attributes 0x%lX", sid_text(tu->User.Sid), tu->User.Attributes);
        line("  ReturnLength the header (8) and the SID: %s",
             yesno(len == sizeof(TOKEN_USER) + sid_size(tu->User.Sid)));
        if (sid_size(tu->User.Sid) <= sizeof user) {
            memcpy(&user, tu->User.Sid, sid_size(tu->User.Sid));
        }
    }
    if (fetch(token, TokenOwner, "TokenOwner", &len) && inside(to->Owner, sid_size(to->Owner))) {
        line("  the default owner: %s; the user: %s", sid_text(to->Owner), yesno(same_sid(to->Owner, &user)));
        line("  ReturnLength the header (4) and the SID: %s", yesno(len == sizeof(TOKEN_OWNER) + sid_size(to->Owner)));
    }
    if (fetch(token, TokenPrimaryGroup, "TokenPrimaryGroup", &len) && inside(tg->PrimaryGroup, 8)) {
        line("  the primary group: %s; in the user's domain: %s", sid_text(tg->PrimaryGroup),
             yesno(same_domain(tg->PrimaryGroup, &user)));
        line("  ReturnLength the header (4) and the SID: %s",
             yesno(len == sizeof(TOKEN_PRIMARY_GROUP) + sid_size(tg->PrimaryGroup)));
    }
    if (!fetch(token, TokenGroups, "TokenGroups", &len)) {
        CloseHandle(token);
        return;
    }
    count = groups->GroupCount;
    if (count > 200) {
        line("  GroupCount out of range");
        CloseHandle(token);
        return;
    }
    total = sizeof(DWORD) + count * sizeof(SID_AND_ATTRIBUTES);
    named = 0;
    logon = -1;
    rid513 = -1;
    for (i = 0; i < count; i++) {
        if (!inside(groups->Groups[i].Sid, 8)) {
            line("  group %lu's SID outside the buffer", i);
            CloseHandle(token);
            return;
        }
        total += sid_size(groups->Groups[i].Sid);
        if (((BYTE *)groups->Groups[i].Sid)[1] == 3 && sid_authority(groups->Groups[i].Sid) == 5
            && sid_sub(groups->Groups[i].Sid, 0) == 5) {
            logon = (int)i;
            named++;
        } else if (is_account(groups->Groups[i].Sid) && sid_sub(groups->Groups[i].Sid, 4) == 513) {
            rid513 = (int)i;
            named++;
        } else {
            for (k = 0; known_groups[k].sid != NULL; k++) {
                if (same_sid(groups->Groups[i].Sid, known_groups[k].sid)) {
                    named++;
                    break;
                }
            }
        }
    }
    line("  GroupCount at least 5: %s; ReturnLength the count, the entries and the SIDs: %s", yesno(count >= 5),
         yesno(len == total));
    for (k = 0; known_groups[k].sid != NULL; k++) {
        found = -1;
        for (i = 0; i < count; i++) {
            if (same_sid(groups->Groups[i].Sid, known_groups[k].sid)) {
                found = (int)i;
                break;
            }
        }
        line("  %s: %s", known_groups[k].name,
             listed_text(found, found >= 0 ? groups->Groups[found].Attributes : 0));
    }
    line("  a logon SID (S-1-5-5-*-*): %s", listed_text(logon, logon >= 0 ? groups->Groups[logon].Attributes : 0));
    line("  the account domain's RID 513: %s, in the user's domain: %s",
         listed_text(rid513, rid513 >= 0 ? groups->Groups[rid513].Attributes : 0),
         yesno(rid513 >= 0 && same_domain(groups->Groups[rid513].Sid, &user)));
    line("  every group one of those: %s", yesno(named == count));
    found = 0;
    for (i = 0; i < count; i++) {
        if (same_sid(groups->Groups[i].Sid, &user)) {
            found = 1;
        }
    }
    line("  the user among the groups: %s", yesno(found));
    CloseHandle(token);
}

/* --- tokmisc ------------------------------------------------------- */

typedef BOOL (WINAPI *duplicate_token_fn)(HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE);

static duplicate_token_fn duplicate_token;      /* DuplicateToken */

static const char *luid_relation(const LUID *a)
{
    return (a->LowPart != 0 || a->HighPart != 0) ? "nonzero" : "zero";
}

static void show_statistics(const TOKEN_STATISTICS *s)
{
    line("  TokenType %d, ImpersonationLevel %d, ExpirationTime 0x%08lX%08lX", (int)s->TokenType,
         (int)s->ImpersonationLevel, (unsigned long)s->ExpirationTime.HighPart, s->ExpirationTime.LowPart);
    line("  DynamicCharged %lu, DynamicAvailable at most DynamicCharged: %s", s->DynamicCharged,
         yesno(s->DynamicAvailable <= s->DynamicCharged));
    line("  TokenId %s, AuthenticationId %s, ModifiedId %s; TokenId and AuthenticationId differ: %s",
         luid_relation(&s->TokenId), luid_relation(&s->AuthenticationId), luid_relation(&s->ModifiedId),
         yesno(memcmp(&s->TokenId, &s->AuthenticationId, sizeof(LUID)) != 0));
    line("  AuthenticationId the system logon's (0:999): %s",
         yesno(s->AuthenticationId.HighPart == 0 && s->AuthenticationId.LowPart == 999));
}

static DWORD class_count(HANDLE token, TOKEN_INFORMATION_CLASS cls)
{
    static ULONG b[1024];
    DWORD len;

    if (!GetTokenInformation(token, cls, b, sizeof b, &len)) {
        return (DWORD)-1;
    }
    return b[0];                        /* GroupCount, PrivilegeCount */
}

static void sec_tokmisc(void)
{
    TOKEN_DEFAULT_DACL *dd = (TOKEN_DEFAULT_DACL *)info_buf;
    TOKEN_SOURCE *src = (TOKEN_SOURCE *)info_buf;
    TOKEN_STATISTICS before, after, dup_stats;
    HANDLE token, dup;
    ACE_HEADER *ace;
    BYTE *p;
    DWORD len, groups, privileges;
    adjust_t on, off;
    char name[9];
    BOOL r;
    int i;

    memset(&before, 0, sizeof before);
    token = open_token(TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
                       "TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    if (fetch(token, TokenDefaultDacl, "TokenDefaultDacl", &len)) {
        if (dd->DefaultDacl == NULL) {
            line("  DefaultDacl NULL");
        } else if (!inside(dd->DefaultDacl, sizeof(ACL))) {
            line("  DefaultDacl outside the buffer");
        } else {
            line("  AclRevision %u, AceCount %u, AclSize %u; ReturnLength the header and AclSize: %s",
                 (unsigned)dd->DefaultDacl->AclRevision, (unsigned)dd->DefaultDacl->AceCount,
                 (unsigned)dd->DefaultDacl->AclSize, yesno(len == sizeof(TOKEN_DEFAULT_DACL) + dd->DefaultDacl->AclSize));
            p = (BYTE *)(dd->DefaultDacl + 1);
            for (i = 0; i < dd->DefaultDacl->AceCount && i < 8 && inside(p, sizeof(ACE_HEADER)); i++) {
                ace = (ACE_HEADER *)p;
                if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE || ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                    line("  ACE %d: type %u, flags 0x%X, mask 0x%08lX, %s", i, (unsigned)ace->AceType,
                         (unsigned)ace->AceFlags, ((ACCESS_ALLOWED_ACE *)p)->Mask,
                         sid_text(&((ACCESS_ALLOWED_ACE *)p)->SidStart));
                } else {
                    line("  ACE %d: type %u, flags 0x%X, size %u", i, (unsigned)ace->AceType, (unsigned)ace->AceFlags,
                         (unsigned)ace->AceSize);
                }
                if (ace->AceSize == 0) {
                    break;
                }
                p += ace->AceSize;
            }
        }
    }
    if (fetch(token, TokenSource, "TokenSource", &len)) {
        memcpy(name, src->SourceName, 8);
        name[8] = 0;
        line("  SourceName [%s], SourceIdentifier %s", name, luid_relation(&src->SourceIdentifier));
    }
    if (fetch(token, TokenType, "TokenType", &len)) {
        line("  TokenType %lu (1 TokenPrimary, 2 TokenImpersonation)", info_buf[0]);
    }
    if (fetch(token, TokenImpersonationLevel, "TokenImpersonationLevel", &len)) {
        line("  ImpersonationLevel %lu", info_buf[0]);
    }
    if (fetch(token, CLASS_SESSION_ID, "TokenSessionId (12)", &len)) {
        line("  SessionId %lu", info_buf[0]);
    }
    if (fetch(token, TokenStatistics, "TokenStatistics", &len)) {
        memcpy(&before, info_buf, sizeof before);
        show_statistics(&before);
        groups = class_count(token, TokenGroups);
        privileges = class_count(token, TokenPrivileges);
        line("  GroupCount TokenGroups' count: %s; PrivilegeCount TokenPrivileges' count: %s",
             yesno(before.GroupCount == groups), yesno(before.PrivilegeCount == privileges));
        /* SeShutdownPrivilege enabled and disabled at once, nothing
         * printed between: whether ModifiedId follows the change. */
        adjust_one(&on, token, SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED, sizeof on.previous);
        adjust_one(&off, token, SHUTDOWN_LUID, 0, sizeof off.previous);
        r = GetTokenInformation(token, TokenStatistics, &after, sizeof after, &len);
        line("after enabling and disabling SeShutdownPrivilege: ret=%d; ModifiedId changed: %s; TokenId the same: %s",
             r, yesno(r && memcmp(&before.ModifiedId, &after.ModifiedId, sizeof(LUID)) != 0),
             yesno(r && memcmp(&before.TokenId, &after.TokenId, sizeof(LUID)) == 0));
    }

    if (duplicate_token == NULL) {
        line("DuplicateToken not found");
        CloseHandle(token);
        return;
    }
    dup = UNTOUCHED_HANDLE;
    arm();
    r = duplicate_token(token, SecurityImpersonation, &dup);
    line("DuplicateToken(SecurityImpersonation): ret=%d err=%s, %s", r, le(), handle_text(dup));
    if (r && dup != NULL && dup != UNTOUCHED_HANDLE) {
        if (fetch(dup, TokenType, "TokenType of the duplicate", &len)) {
            line("  TokenType %lu", info_buf[0]);
        }
        if (fetch(dup, TokenImpersonationLevel, "TokenImpersonationLevel of the duplicate", &len)) {
            line("  ImpersonationLevel %lu", info_buf[0]);
        }
        if (GetTokenInformation(dup, TokenStatistics, &dup_stats, sizeof dup_stats, &len)) {
            line("  its statistics: TokenType %d, ImpersonationLevel %d; TokenId the primary's: %s; "
                 "AuthenticationId the primary's: %s",
                 (int)dup_stats.TokenType, (int)dup_stats.ImpersonationLevel,
                 yesno(memcmp(&dup_stats.TokenId, &before.TokenId, sizeof(LUID)) == 0),
                 yesno(memcmp(&dup_stats.AuthenticationId, &before.AuthenticationId, sizeof(LUID)) == 0));
        }
        CloseHandle(dup);
    }
    CloseHandle(token);
}

/* --- admin --------------------------------------------------------- */

typedef BOOL (WINAPI *check_membership_fn)(HANDLE, PSID, PBOOL);
typedef BOOL (WINAPI *allocate_sid_fn)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD,
                                       DWORD, DWORD, PSID *);
typedef BOOL (WINAPI *equal_sid_fn)(PSID, PSID);
typedef PVOID (WINAPI *free_sid_fn)(PSID);

static check_membership_fn check_membership;    /* CheckTokenMembership */
static allocate_sid_fn allocate_sid;            /* AllocateAndInitializeSid */
static equal_sid_fn equal_sid;                  /* EqualSid */
static free_sid_fn free_sid;                    /* FreeSid */

/* CheckTokenMembership(token, sid): the return, the error and the answer
 * (0xCC... printed as "untouched"). */
static void membership(HANDLE token, const char *tname, const void *sid, const char *sname)
{
    BOOL is = (BOOL)F2KT_UNTOUCHED;
    BOOL r = FALSE;
    DWORD e = 0, code = 0;

    arm();
    __try {
        r = check_membership(token, (PSID)sid, &is);
        e = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        code = GetExceptionCode();
    }
    if (code != 0) {
        line("CheckTokenMembership(%s, %s): faulted 0x%08lX", tname, sname, code);
        return;
    }
    if (is == (BOOL)F2KT_UNTOUCHED) {
        line("CheckTokenMembership(%s, %s): ret=%d err=%s IsMember untouched", tname, sname, r, le_of(e));
    } else {
        line("CheckTokenMembership(%s, %s): ret=%d err=%s IsMember=%d", tname, sname, r, le_of(e), is);
    }
}

static void sec_admin(void)
{
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    TOKEN_GROUPS *groups = (TOKEN_GROUPS *)info_buf;
    HANDLE token, dup;
    PSID admins = NULL;
    DWORD len, i;
    PVOID freed;
    BOOL r;
    int at;

    line("CheckTokenMembership exported: %s; AllocateAndInitializeSid, EqualSid, FreeSid: %s",
         yesno(check_membership != NULL), yesno(allocate_sid != NULL && equal_sid != NULL && free_sid != NULL));

    /* The classic check: the groups scan, as programs did before
     * CheckTokenMembership. */
    token = open_token(TOKEN_QUERY | TOKEN_DUPLICATE, "TOKEN_QUERY | TOKEN_DUPLICATE");
    if (token == NULL) {
        return;
    }
    if (fetch(token, TokenGroups, "TokenGroups", &len) && groups->GroupCount <= 200) {
        at = -1;
        for (i = 0; i < groups->GroupCount; i++) {
            if (inside(groups->Groups[i].Sid, 16) && same_sid(groups->Groups[i].Sid, &sid_admins)) {
                at = (int)i;
            }
        }
        line("  the groups scan: BUILTIN\\Administrators %s; enabled: %s",
             listed_text(at, at >= 0 ? groups->Groups[at].Attributes : 0),
             yesno(at >= 0 && (groups->Groups[at].Attributes & SE_GROUP_ENABLED) != 0));
    }

    if (allocate_sid != NULL && equal_sid != NULL && free_sid != NULL) {
        arm();
        r = allocate_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins);
        line("AllocateAndInitializeSid(S-1-5-32-544): ret=%d err=%s; the bytes of the hand-built SID: %s", r, le(),
             yesno(r && admins != NULL && memcmp(admins, &sid_admins, 16) == 0));
        if (r && admins != NULL) {
            arm();
            r = equal_sid(admins, (PSID)&sid_admins);
            line("EqualSid(it, the hand-built SID): ret=%d err=%s", r, le());
            arm();
            r = equal_sid(admins, (PSID)&sid_users);
            line("EqualSid(it, BUILTIN\\Users): ret=%d err=%s", r, le());
        }
    }
    if (check_membership != NULL) {
        membership(NULL, "NULL", &sid_admins, "BUILTIN\\Administrators");
        if (admins != NULL) {
            membership(NULL, "NULL", admins, "AllocateAndInitializeSid's");
        }
        membership(NULL, "NULL", &sid_users, "BUILTIN\\Users");
        membership(NULL, "NULL", &sid_everyone, "Everyone");
        membership(NULL, "NULL", &sid_interactive, "INTERACTIVE");
        membership(NULL, "NULL", &sid_guests, "BUILTIN\\Guests");
        membership(NULL, "NULL", &sid_system, "SYSTEM");
        membership(token, "the primary token", &sid_admins, "BUILTIN\\Administrators");
        if (duplicate_token != NULL) {
            dup = NULL;
            if (duplicate_token(token, SecurityIdentification, &dup) && dup != NULL) {
                membership(dup, "an identification token", &sid_admins, "BUILTIN\\Administrators");
                membership(dup, "an identification token", &sid_guests, "BUILTIN\\Guests");
                CloseHandle(dup);
            } else {
                line("DuplicateToken(SecurityIdentification) failed");
            }
        }
    }
    if (admins != NULL) {
        arm();
        freed = free_sid(admins);
        line("FreeSid: returned NULL: %s err=%s", yesno(freed == NULL), le());
    }
    CloseHandle(token);
}

/* --- privs --------------------------------------------------------- */

#define SYSTEMTIME_LUID 12
#define BACKUP_LUID 17

static const struct {
    DWORD luid;
    const char *name;
} admin_privileges[] = {
    { SYSTEMTIME_LUID, "SeSystemtimePrivilege" },
    { BACKUP_LUID, "SeBackupPrivilege" },
    { SHUTDOWN_LUID, "SeShutdownPrivilege" },
    { DEBUG_LUID, "SeDebugPrivilege" },
    { 0, NULL }
};

/* A TOKEN_PRIVILEGES with room for four entries. */
typedef struct {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[4];
} four_privileges_t;

/* A privilege as GetTokenInformation(TokenPrivileges) lists it now: its
 * index (-1: not listed) and attributes. */
static int privilege_state(HANDLE token, DWORD luid, DWORD *attributes)
{
    static ULONG b[1024];
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)b;
    DWORD len;
    int at;

    *attributes = 0;
    if (!GetTokenInformation(token, TokenPrivileges, b, sizeof b, &len) || tp->PrivilegeCount > 500) {
        return -2;
    }
    at = find_privilege(tp, tp->PrivilegeCount, luid);
    if (at >= 0) {
        *attributes = tp->Privileges[at].Attributes;
    }
    return at;
}

static void sec_privs(void)
{
    four_privileges_t all, previous;
    adjust_t on, back;
    HANDLE token;
    LUID luid;
    DWORD attributes[4], after, len, e, e2 = 0, a;
    int held[4], now, i;
    BOOL r, r2 = FALSE;
    char label[96];

    for (i = 0; admin_privileges[i].name != NULL; i++) {
        luid.LowPart = F2KT_UNTOUCHED;
        luid.HighPart = (LONG)F2KT_UNTOUCHED;
        arm();
        r = LookupPrivilegeValueA(NULL, admin_privileges[i].name, &luid);
        line("LookupPrivilegeValueA(NULL, \"%s\"): ret=%d err=%s luid=%s", admin_privileges[i].name, r, le(),
             luid_text(&luid));
    }
    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    for (i = 0; admin_privileges[i].name != NULL; i++) {
        held[i] = privilege_state(token, admin_privileges[i].luid, &attributes[i]);
    }
    for (i = 0; admin_privileges[i].name != NULL; i++) {
        /* Enabled, then put back as it was by the very next call. */
        adjust_one(&on, token, admin_privileges[i].luid, SE_PRIVILEGE_ENABLED, sizeof on.previous);
        adjust_one(&back, token, admin_privileges[i].luid, attributes[i] & SE_PRIVILEGE_ENABLED, sizeof back.previous);
        now = privilege_state(token, admin_privileges[i].luid, &after);
        line("%s before: %s", admin_privileges[i].name, listed_text(held[i], attributes[i]));
        sprintf(label, "AdjustTokenPrivileges(enable %s)", admin_privileges[i].name);
        show_adjust(label, &on);
        show_adjust("AdjustTokenPrivileges(put it back as it was)", &back);
        line("%s after: %s", admin_privileges[i].name, listed_text(now, after));
    }

    /* All four in one call, then PreviousState given back as NewState. */
    all.PrivilegeCount = 4;
    for (i = 0; i < 4; i++) {
        set_privilege((TOKEN_PRIVILEGES *)&all, i, admin_privileges[i].luid, SE_PRIVILEGE_ENABLED);
    }
    memset(&previous, 0xCC, sizeof previous);
    len = F2KT_UNTOUCHED;
    arm();
    r = AdjustTokenPrivileges(token, FALSE, (TOKEN_PRIVILEGES *)&all, sizeof previous, (TOKEN_PRIVILEGES *)&previous,
                              &len);
    e = GetLastError();
    if (r && previous.PrivilegeCount <= 4) {
        arm();
        r2 = AdjustTokenPrivileges(token, FALSE, (TOKEN_PRIVILEGES *)&previous, 0, NULL, NULL);
        e2 = GetLastError();
    }
    line("AdjustTokenPrivileges(enable all four): ret=%d err=%s; PreviousState count %s; ReturnLength %s", r, le_of(e),
         previous.PrivilegeCount == 0xCCCCCCCCu ? "untouched" : length_text(previous.PrivilegeCount),
         length_text(len));
    line("AdjustTokenPrivileges(NewState = that PreviousState): ret=%d err=%s", r2, le_of(e2));
    for (i = 0; admin_privileges[i].name != NULL; i++) {
        now = privilege_state(token, admin_privileges[i].luid, &a);
        line("%s after: %s; as before: %s", admin_privileges[i].name, listed_text(now, a),
             yesno(now == held[i] && a == attributes[i]));
    }
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
    { "tokclass", sec_tokclass, F2KT_ALWAYS },
    { "toksids", sec_toksids, F2KT_ALWAYS },
    { "tokmisc", sec_tokmisc, F2KT_ALWAYS },
    { "admin", sec_admin, F2KT_ALWAYS },
    { "privs", sec_privs, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    HMODULE ntdll, advapi32;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    ntdll = GetModuleHandleA("ntdll.dll");
    query_object = (query_object_fn)GetProcAddress(ntdll, "NtQueryObject");
    nt_open_token = (open_token_fn)GetProcAddress(ntdll, "NtOpenProcessToken");
    nt_adjust_token = (adjust_token_fn)GetProcAddress(ntdll, "NtAdjustPrivilegesToken");
    /* Through GetProcAddress, so the program loads where advapi32 lacks
     * them; the calls are still the sections' own. */
    advapi32 = GetModuleHandleA("advapi32.dll");
    duplicate_token = (duplicate_token_fn)GetProcAddress(advapi32, "DuplicateToken");
    check_membership = (check_membership_fn)GetProcAddress(advapi32, "CheckTokenMembership");
    allocate_sid = (allocate_sid_fn)GetProcAddress(advapi32, "AllocateAndInitializeSid");
    equal_sid = (equal_sid_fn)GetProcAddress(advapi32, "EqualSid");
    free_sid = (free_sid_fn)GetProcAddress(advapi32, "FreeSid");
    return run_sections("token", sections, argc, argv);
}
