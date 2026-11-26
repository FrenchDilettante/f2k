/*
 * privchk - privileges and token membership: LookupPrivilegeNameA/W and
 * LookupPrivilegeValueA/W (the size query, a short buffer, the name and
 * the LUID back, an unknown name, an unknown LUID), PrivilegeCheck over
 * the process token with SeShutdownPrivilege and SeDebugPrivilege
 * disabled, enabled and disabled again in between, AdjustTokenPrivileges
 * with PreviousState, CheckTokenMembership against well-known SIDs, and
 * a DuplicateToken copy checked in turn.
 *
 * Captured on an administrator account, whose token holds
 * SeShutdownPrivilege and SeDebugPrivilege disabled; the privileges are
 * named by their public LUIDs (winnt.h's SE_*_PRIVILEGE values):
 * SeSecurityPrivilege 8, SeShutdownPrivilege 19, SeDebugPrivilege 20.
 * A LUID prints as high:low (the public values, the same on every
 * machine); a SID prints in its string form (every SID here is
 * well-known). Nothing machine-specific prints.
 *
 * The security calls that advapi32 does not implement yet go through
 * GetProcAddress, so the program loads where advapi32 lacks them; the
 * token calls are direct. A section whose call is missing prints
 * "not found" and stops.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   lookup      LookupPrivilegeNameA/W and LookupPrivilegeValueA/W for
 *               SeShutdownPrivilege, SeDebugPrivilege and
 *               SeSecurityPrivilege (the size query, a short buffer,
 *               the exact size), an unknown name, an unknown LUID, a
 *               NULL name
 *   check       PrivilegeCheck with an empty set, with SeShutdown-
 *               Privilege disabled (not enabled), enabled through
 *               AdjustTokenPrivileges (enabled), disabled again; the
 *               same for SeDebugPrivilege
 *   adjust      AdjustTokenPrivileges enabling and disabling
 *               SeSecurityPrivilege with PreviousState (count, LUID,
 *               attributes) and ReturnLength, then put back
 *   membership  CheckTokenMembership with a NULL token and the primary
 *               token over Everyone, BUILTIN\Administrators,
 *               BUILTIN\Users and BUILTIN\Guests; CreateWellKnownSid
 *               against AllocateAndInitializeSid, EqualSid, FreeSid
 *   duplicate   DuplicateToken as an impersonation copy: its type and
 *               impersonation level, PrivilegeCheck and
 *               CheckTokenMembership on it
 *   tokengroups AdjustTokenGroups: a NULL NewState (refused), a valid
 *               NewState with a too-short PreviousState (the size asked
 *               for), ResetToDefault (the default group list back)
 *   setinfo     SetTokenInformation: an unknown class, TokenUser with a
 *               4-byte buffer, TokenType (a read-only class)
 *   duprestrict DuplicateTokenEx (type and level of the copy),
 *               IsTokenRestricted on the primary and the copies,
 *               CreateRestrictedToken with nothing disabled and
 *               IsTokenRestricted on the restricted copy
 *   threadtok   OpenThreadToken on the current thread (no token, then
 *               with OpenAsSelf after ImpersonateSelf), SetThreadToken
 *               clearing the thread's token again
 *   lookupdisp  LookupPrivilegeDisplayNameA/W for SeShutdownPrivilege
 *               (the size query, the exact size, the language id as a
 *               relation; the display text itself never prints), and an
 *               unknown name
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat privchk):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% privchk.c advapi32.lib
 */

#include "../common/f2kt.h"

/* The privileges' public LUIDs (winnt.h's SE_*_PRIVILEGE). */
#define SECURITY_LUID 8
#define SHUTDOWN_LUID 19
#define DEBUG_LUID 20

/* The well-known SID types CreateWellKnownSid takes (public values). */
#define WK_WORLD 1
#define WK_BUILTIN_ADMINS 26
#define WK_BUILTIN_USERS 27
#define WK_BUILTIN_GUESTS 28

/* --- the advapi32 security calls, through GetProcAddress ------------- */

typedef BOOL (WINAPI *lookup_name_a_fn)(LPCSTR, PLUID, LPSTR, LPDWORD);
typedef BOOL (WINAPI *lookup_name_w_fn)(LPCWSTR, PLUID, LPWSTR, LPDWORD);
typedef BOOL (WINAPI *priv_check_fn)(HANDLE, PPRIVILEGE_SET, PBOOL);
typedef BOOL (WINAPI *check_member_fn)(HANDLE, PSID, PBOOL);
typedef BOOL (WINAPI *dup_token_fn)(HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE);
typedef BOOL (WINAPI *alloc_sid_fn)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD,
                                    DWORD, DWORD, DWORD, PSID *);
typedef BOOL (WINAPI *wk_sid_fn)(DWORD, PSID, PSID, DWORD *);
typedef BOOL (WINAPI *equal_sid_fn)(PSID, PSID);
typedef PVOID (WINAPI *free_sid_fn)(PSID);

/* The remaining token surface (public signatures; the token information
 * classes and the impersonation level and token type enums are winnt.h's
 * public values). */
typedef BOOL (WINAPI *adjust_groups_fn)(HANDLE, BOOL, PTOKEN_GROUPS, DWORD, PTOKEN_GROUPS, PDWORD);
typedef BOOL (WINAPI *set_token_info_fn)(HANDLE, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *dup_token_ex_fn)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
                                       TOKEN_TYPE, PHANDLE);
typedef BOOL (WINAPI *create_restricted_fn)(HANDLE, DWORD, DWORD, PSID_AND_ATTRIBUTES, DWORD,
                                            PLUID_AND_ATTRIBUTES, DWORD, PSID_AND_ATTRIBUTES, PHANDLE);
typedef BOOL (WINAPI *is_restricted_fn)(HANDLE);
typedef BOOL (WINAPI *open_thread_token_fn)(HANDLE, DWORD, BOOL, PHANDLE);
typedef BOOL (WINAPI *set_thread_token_fn)(PHANDLE, HANDLE);
typedef BOOL (WINAPI *impersonate_self_fn)(SECURITY_IMPERSONATION_LEVEL);
typedef BOOL (WINAPI *lookup_display_a_fn)(LPCSTR, LPCSTR, LPSTR, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *lookup_display_w_fn)(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD, LPDWORD);

/* Token information classes (winnt.h's TOKEN_INFORMATION_CLASS values). */
#define TI_TOKEN_USER 1
#define TI_TOKEN_TYPE 8

static lookup_name_a_fn p_lookup_name_a;
static lookup_name_w_fn p_lookup_name_w;
static priv_check_fn p_priv_check;
static check_member_fn p_check_member;
static dup_token_fn p_dup_token;
static alloc_sid_fn p_alloc_sid;
static wk_sid_fn p_wk_sid;
static equal_sid_fn p_equal_sid;
static free_sid_fn p_free_sid;
static adjust_groups_fn p_adjust_groups;
static set_token_info_fn p_set_token_info;
static dup_token_ex_fn p_dup_token_ex;
static create_restricted_fn p_create_restricted;
static is_restricted_fn p_is_restricted;
static open_thread_token_fn p_open_thread_token;
static set_thread_token_fn p_set_thread_token;
static impersonate_self_fn p_impersonate_self;
static lookup_display_a_fn p_lookup_display_a;
static lookup_display_w_fn p_lookup_display_w;

static HMODULE adv;

/* --- the well-known SIDs, built by hand (the layout is public) -------- */

typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid5_t sid_admins = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };
static const sid5_t sid_users = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 545 } };
static const sid5_t sid_guests = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 546 } };

static const char *sid_text(const void *sid)
{
    static char bufs[4][96];
    static int next;
    char *b = bufs[next++ & 3];
    const BYTE *p = (const BYTE *)sid;
    DWORD auth, v;
    int n, i, count;

    if (sid == NULL) {
        return "NULL";
    }
    count = p[1];
    if (p[0] != 1 || count > 15) {
        return "not a SID";
    }
    auth = ((DWORD)p[4] << 24) | ((DWORD)p[5] << 16) | ((DWORD)p[6] << 8) | p[7];
    n = sprintf(b, "S-1-%lu", auth);
    for (i = 0; i < count && n < (int)sizeof bufs[0] - 12; i++) {
        memcpy(&v, p + 8 + 4 * i, sizeof v);
        n += sprintf(b + n, "-%lu", v);
    }
    return b;
}

static int have(const char *name, void *p)
{
    if (p == NULL) {
        line("%s not found", name);
        return 0;
    }
    return 1;
}

/* A LUID as printed: high:low. */
static const char *luid_text(const LUID *luid)
{
    static char bufs[4][32];
    static int next;
    char *b = bufs[next++ & 3];

    if (luid == NULL) {
        return "NULL";
    }
    sprintf(b, "%ld:%lu", luid->HighPart, luid->LowPart);
    return b;
}

/* OpenProcessToken on the current process, printed; NULL when it fails. */
static HANDLE open_token(DWORD access, const char *access_name)
{
    HANDLE token = NULL;
    BOOL r;

    arm();
    r = OpenProcessToken(GetCurrentProcess(), access, &token);
    line("OpenProcessToken(GetCurrentProcess(), %s): ret=%d err=%s, %s", access_name, r, le(),
         r && token != NULL ? "a handle" : "no handle");
    return r ? token : NULL;
}

/* AdjustTokenPrivileges setting one privilege, printed. */
static void set_priv(HANDLE token, const char *name, DWORD luid, DWORD attributes)
{
    TOKEN_PRIVILEGES tp;
    BOOL r;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = luid;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = attributes;
    arm();
    r = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    line("AdjustTokenPrivileges(%s %s): ret=%d err=%s", name,
         attributes & SE_PRIVILEGE_ENABLED ? "enable" : "disable", r, le());
}

/* PrivilegeCheck of one privilege (required enabled), printed. */
static void run_priv_check(HANDLE token, const char *label, DWORD luid)
{
    PRIVILEGE_SET ps;
    BOOL result = (BOOL)F2KT_UNTOUCHED;
    BOOL r;

    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    ps.Privilege[0].Luid.LowPart = luid;
    ps.Privilege[0].Luid.HighPart = 0;
    ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    arm();
    r = p_priv_check(token, &ps, &result);
    if (result == (BOOL)F2KT_UNTOUCHED) {
        line("PrivilegeCheck(%s): ret=%d err=%s result untouched", label, r, le());
    } else {
        line("PrivilegeCheck(%s): ret=%d err=%s result=%d", label, r, le(), result);
    }
}

/* CheckTokenMembership, printed. */
static void run_membership(HANDLE token, const char *tname, const void *sid, const char *sname)
{
    BOOL is = (BOOL)F2KT_UNTOUCHED;
    BOOL r;

    arm();
    r = p_check_member(token, (PSID)sid, &is);
    if (is == (BOOL)F2KT_UNTOUCHED) {
        line("CheckTokenMembership(%s, %s): ret=%d err=%s IsMember untouched", tname, sname, r, le());
    } else {
        line("CheckTokenMembership(%s, %s): ret=%d err=%s IsMember=%d", tname, sname, r, le(), is);
    }
}

/* --- lookup -------------------------------------------------------------- */

static const char *const priv_names[] = {
    "SeShutdownPrivilege",
    "SeDebugPrivilege",
    "SeSecurityPrivilege",
    "SeNoSuchPrivilege",
    NULL
};

static void sec_lookup(void)
{
    char name[128];
    WCHAR name_w[128];
    LUID luid;
    DWORD size, wsize;
    BOOL r;
    int i;

    if (!have("LookupPrivilegeNameA", (void *)p_lookup_name_a)
        || !have("LookupPrivilegeNameW", (void *)p_lookup_name_w)) {
        return;
    }
    for (i = 0; priv_names[i] != NULL; i++) {
        luid.LowPart = F2KT_UNTOUCHED;
        luid.HighPart = (LONG)F2KT_UNTOUCHED;
        arm();
        r = LookupPrivilegeValueA(NULL, priv_names[i], &luid);
        line("LookupPrivilegeValueA(NULL, \"%s\"): ret=%d err=%s luid=%s", priv_names[i], r, le(),
             luid.LowPart == F2KT_UNTOUCHED ? "untouched" : luid_text(&luid));
        if (!r) {
            continue;
        }
        size = 0;
        arm();
        r = p_lookup_name_a(NULL, &luid, name, &size);
        line("LookupPrivilegeNameA(%s, no buffer): ret=%d err=%s; the size needed %s", priv_names[i], r, le(),
             size == 0 ? "unset" : "set");
        if (size == 0 || size > sizeof name) {
            continue;
        }
        memset(name, 0xCC, sizeof name);
        arm();
        r = p_lookup_name_a(NULL, &luid, name, &size);
        line("LookupPrivilegeNameA(%s, the size asked for): ret=%d err=%s name=%s; the size now %lu",
             priv_names[i], r, le(), r ? name : "-", size);
        size--;
        arm();
        r = p_lookup_name_a(NULL, &luid, name, &size);
        line("LookupPrivilegeNameA(%s, one short): ret=%d err=%s", priv_names[i], r, le());
        wsize = sizeof name_w / sizeof name_w[0];
        memset(name_w, 0xCC, sizeof name_w);
        arm();
        r = p_lookup_name_w(NULL, &luid, name_w, &wsize);
        line("LookupPrivilegeNameW(%s, 128 units) (W): ret=%d err=%s name=%s", priv_names[i], r, le(),
             r ? ws(name_w) : "-");
    }
    /* An unknown LUID, and an unknown or NULL name. */
    luid.LowPart = 65536;
    luid.HighPart = 0;
    size = sizeof name;
    arm();
    r = p_lookup_name_a(NULL, &luid, name, &size);
    line("LookupPrivilegeNameA(an unknown LUID): ret=%d err=%s", r, le());
    wsize = sizeof name_w / sizeof name_w[0];
    arm();
    r = p_lookup_name_w(NULL, &luid, name_w, &wsize);
    line("LookupPrivilegeNameW(an unknown LUID) (W): ret=%d err=%s", r, le());
    arm();
    r = LookupPrivilegeValueA(NULL, "SeNoSuchPrivilege", &luid);
    line("LookupPrivilegeValueA(an unknown name): ret=%d err=%s", r, le());
    arm();
    r = LookupPrivilegeValueW(NULL, L"SeNoSuchPrivilege", &luid);
    line("LookupPrivilegeValueW(an unknown name) (W): ret=%d err=%s", r, le());
    arm();
    r = LookupPrivilegeValueA(NULL, NULL, &luid);
    line("LookupPrivilegeValueA(a NULL name): ret=%d err=%s", r, le());
}

/* --- check --------------------------------------------------------------- */

static void sec_check(void)
{
    PRIVILEGE_SET ps;
    HANDLE token;
    BOOL result = FALSE;
    BOOL r;

    if (!have("PrivilegeCheck", (void *)p_priv_check)) {
        return;
    }
    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    ps.PrivilegeCount = 0;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    result = (BOOL)F2KT_UNTOUCHED;
    arm();
    r = p_priv_check(token, &ps, &result);
    line("PrivilegeCheck(an empty set): ret=%d err=%s result=%d", r, le(), result);

    run_priv_check(token, "SeShutdownPrivilege, disabled", SHUTDOWN_LUID);
    set_priv(token, "SeShutdownPrivilege", SHUTDOWN_LUID, SE_PRIVILEGE_ENABLED);
    run_priv_check(token, "SeShutdownPrivilege, enabled", SHUTDOWN_LUID);
    set_priv(token, "SeShutdownPrivilege", SHUTDOWN_LUID, 0);
    run_priv_check(token, "SeShutdownPrivilege, disabled again", SHUTDOWN_LUID);

    run_priv_check(token, "SeDebugPrivilege, disabled", DEBUG_LUID);
    set_priv(token, "SeDebugPrivilege", DEBUG_LUID, SE_PRIVILEGE_ENABLED);
    run_priv_check(token, "SeDebugPrivilege, enabled", DEBUG_LUID);
    set_priv(token, "SeDebugPrivilege", DEBUG_LUID, 0);
    run_priv_check(token, "SeDebugPrivilege, disabled again", DEBUG_LUID);
    CloseHandle(token);
}

/* --- adjust -------------------------------------------------------------- */

static void sec_adjust(void)
{
    static ULONG previous[64];
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)previous;
    TOKEN_PRIVILEGES set;
    HANDLE token;
    LUID luid;
    DWORD len, count;
    BOOL r;

    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    arm();
    r = LookupPrivilegeValueA(NULL, "SeSecurityPrivilege", &luid);
    line("LookupPrivilegeValueA(NULL, \"SeSecurityPrivilege\"): ret=%d err=%s luid=%s", r, le(),
         r ? luid_text(&luid) : "-");
    if (!r) {
        CloseHandle(token);
        return;
    }
    set.PrivilegeCount = 1;
    set.Privileges[0].Luid = luid;
    set.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    memset(previous, 0xCC, sizeof previous);
    len = F2KT_UNTOUCHED;
    arm();
    r = AdjustTokenPrivileges(token, FALSE, &set, sizeof previous, tp, &len);
    count = tp->PrivilegeCount;
    line("AdjustTokenPrivileges(enable SeSecurityPrivilege, PreviousState): ret=%d err=%s", r, le());
    line("  PreviousState: count %s; ReturnLength %s; one entry's size: %s", count == 0xCCCCCCCCu ? "untouched" : "set",
         len == F2KT_UNTOUCHED ? "untouched" : "set",
         yesno(len != F2KT_UNTOUCHED && len == sizeof(DWORD) + count * sizeof(LUID_AND_ATTRIBUTES)));
    if (r && count != 0xCCCCCCCCu && count <= 16) {
        line("  its entry: luid %s, attributes 0x%lX", luid_text(&tp->Privileges[0].Luid),
             tp->Privileges[0].Attributes);
        arm();
        r = AdjustTokenPrivileges(token, FALSE, tp, 0, NULL, NULL);
        line("AdjustTokenPrivileges(NewState = that PreviousState, put back): ret=%d err=%s", r, le());
    } else {
        set_priv(token, "SeSecurityPrivilege", SECURITY_LUID, 0);
    }
    CloseHandle(token);
}

/* --- membership ---------------------------------------------------------- */

static void sec_membership(void)
{
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    static ULONG wk[64];
    HANDLE token;
    PSID admins = NULL;
    DWORD len;
    BOOL r;
    PVOID freed;

    if (!have("CheckTokenMembership", (void *)p_check_member)
        || !have("AllocateAndInitializeSid", (void *)p_alloc_sid) || !have("CreateWellKnownSid", (void *)p_wk_sid)
        || !have("EqualSid", (void *)p_equal_sid) || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    arm();
    r = p_alloc_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &admins);
    line("AllocateAndInitializeSid(S-1-5-32-544): ret=%d err=%s; %s", r, le(),
         r && admins != NULL ? sid_text(admins) : "-");
    len = sizeof wk;
    arm();
    r = p_wk_sid(WK_BUILTIN_ADMINS, NULL, wk, &len);
    line("CreateWellKnownSid(BuiltinAdministrators): ret=%d err=%s; %s", r, le(), r ? sid_text(wk) : "-");
    if (r && admins != NULL) {
        arm();
        r = p_equal_sid(admins, (PSID)wk);
        line("EqualSid(the two): ret=%d err=%s", r, le());
    }

    run_membership(NULL, "NULL", &sid_everyone, "Everyone (S-1-1-0)");
    run_membership(NULL, "NULL", &sid_admins, "BUILTIN\\Administrators");
    run_membership(NULL, "NULL", &sid_users, "BUILTIN\\Users");
    run_membership(NULL, "NULL", &sid_guests, "BUILTIN\\Guests");
    if (admins != NULL) {
        run_membership(NULL, "NULL", admins, "AllocateAndInitializeSid's");
    }
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token != NULL) {
        run_membership(token, "the primary token", &sid_everyone, "Everyone (S-1-1-0)");
        run_membership(token, "the primary token", &sid_admins, "BUILTIN\\Administrators");
        run_membership(token, "the primary token", &sid_guests, "BUILTIN\\Guests");
        CloseHandle(token);
    }
    if (admins != NULL) {
        arm();
        freed = p_free_sid(admins);
        line("FreeSid: returned NULL: %s err=%s", yesno(freed == NULL), le());
    }
}

/* --- duplicate ----------------------------------------------------------- */

static void sec_duplicate(void)
{
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    static ULONG info[256];
    HANDLE token, dup = NULL;
    PSID admins = NULL;
    DWORD len;
    BOOL r;

    if (!have("DuplicateToken", (void *)p_dup_token) || !have("PrivilegeCheck", (void *)p_priv_check)
        || !have("CheckTokenMembership", (void *)p_check_member)
        || !have("AllocateAndInitializeSid", (void *)p_alloc_sid) || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    token = open_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES,
                       "TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    arm();
    r = p_dup_token(token, SecurityImpersonation, &dup);
    line("DuplicateToken(SecurityImpersonation): ret=%d err=%s, %s", r, le(),
         r && dup != NULL ? "a handle" : "no handle");
    if (r && dup != NULL) {
        arm();
        r = GetTokenInformation(dup, TokenType, info, sizeof info, &len);
        line("GetTokenInformation(TokenType of the duplicate): ret=%d err=%s type=%lu", r, le(),
             r ? info[0] : 0);
        arm();
        r = GetTokenInformation(dup, TokenImpersonationLevel, info, sizeof info, &len);
        line("GetTokenInformation(TokenImpersonationLevel of the duplicate): ret=%d err=%s level=%lu", r, le(),
             r ? info[0] : 0);
        run_priv_check(dup, "SeShutdownPrivilege on the duplicate, disabled", SHUTDOWN_LUID);
        arm();
        r = p_alloc_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                        0, 0, 0, 0, 0, 0, &admins);
        if (r && admins != NULL) {
            run_membership(dup, "the duplicate", admins, "BUILTIN\\Administrators");
            run_membership(dup, "the duplicate", &sid_everyone, "Everyone (S-1-1-0)");
            p_free_sid(admins);
        }
        CloseHandle(dup);
    }
    CloseHandle(token);
}

/* --- tokengroups --------------------------------------------------------- */

static void sec_tokengroups(void)
{
    TOKEN_GROUPS ng;
    HANDLE token;
    DWORD len;
    BOOL r;

    if (!have("AdjustTokenGroups", (void *)p_adjust_groups)) {
        return;
    }
    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_GROUPS, "TOKEN_QUERY | TOKEN_ADJUST_GROUPS");
    if (token == NULL) {
        return;
    }
    len = F2KT_UNTOUCHED;
    arm();
    r = p_adjust_groups(token, FALSE, NULL, 0, NULL, &len);
    line("AdjustTokenGroups(ResetToDefault=FALSE, NewState NULL): ret=%d err=%s; ReturnLength %s", r, le(),
         len == F2KT_UNTOUCHED ? "untouched" : "set");

    memset(&ng, 0, sizeof ng);
    ng.GroupCount = 1;
    ng.Groups[0].Sid = (PSID)&sid_everyone;
    ng.Groups[0].Attributes = SE_GROUP_ENABLED;
    len = F2KT_UNTOUCHED;
    arm();
    r = p_adjust_groups(token, FALSE, &ng, 4, NULL, &len);
    line("AdjustTokenGroups(NewState one group, PreviousState 4 bytes): ret=%d err=%s; ReturnLength %s", r, le(),
         len == F2KT_UNTOUCHED ? "untouched" : "set");
    if (len != F2KT_UNTOUCHED) {
        line("  the ReturnLength %lu, past a DWORD: %s", len, yesno(len > sizeof(DWORD)));
    }
    len = F2KT_UNTOUCHED;
    arm();
    r = p_adjust_groups(token, TRUE, NULL, 0, NULL, &len);
    line("AdjustTokenGroups(ResetToDefault=TRUE, NewState NULL): ret=%d err=%s; ReturnLength %s", r, le(),
         len == F2KT_UNTOUCHED ? "untouched" : "set");
    CloseHandle(token);
}

/* --- setinfo ------------------------------------------------------------- */

static void sec_setinfo(void)
{
    DWORD dummy = 0;
    HANDLE token;
    BOOL r;

    if (!have("SetTokenInformation", (void *)p_set_token_info)) {
        return;
    }
    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT,
                       "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT");
    if (token == NULL) {
        return;
    }
    arm();
    r = p_set_token_info(token, 0xFFFF, &dummy, sizeof dummy);
    line("SetTokenInformation(class 0xFFFF): ret=%d err=%s", r, le());
    arm();
    r = p_set_token_info(token, TI_TOKEN_USER, &dummy, 4);
    line("SetTokenInformation(TokenUser, a 4-byte buffer): ret=%d err=%s", r, le());
    arm();
    r = p_set_token_info(token, TI_TOKEN_TYPE, &dummy, 4);
    line("SetTokenInformation(TokenType, a read-only class): ret=%d err=%s", r, le());
    CloseHandle(token);
}

/* --- duprestrict --------------------------------------------------------- */

static void sec_duprestrict(void)
{
    static ULONG info[256];
    HANDLE token, dup = NULL, rest = NULL;
    DWORD len;
    BOOL r;

    if (!have("DuplicateTokenEx", (void *)p_dup_token_ex) || !have("CreateRestrictedToken", (void *)p_create_restricted)
        || !have("IsTokenRestricted", (void *)p_is_restricted)) {
        return;
    }
    token = open_token(TOKEN_QUERY | TOKEN_DUPLICATE, "TOKEN_QUERY | TOKEN_DUPLICATE");
    if (token == NULL) {
        return;
    }
    arm();
    r = p_dup_token_ex(token, TOKEN_QUERY, NULL, SecurityImpersonation, TokenImpersonation, &dup);
    line("DuplicateTokenEx(TOKEN_QUERY, SecurityImpersonation, TokenImpersonation): ret=%d err=%s, %s", r, le(),
         r && dup != NULL ? "a handle" : "no handle");
    if (r && dup != NULL) {
        arm();
        r = GetTokenInformation(dup, TokenType, info, sizeof info, &len);
        line("GetTokenInformation(TokenType of the copy): ret=%d err=%s type=%lu", r, le(), r ? info[0] : 0);
        arm();
        r = GetTokenInformation(dup, TokenImpersonationLevel, info, sizeof info, &len);
        line("GetTokenInformation(TokenImpersonationLevel of the copy): ret=%d err=%s level=%lu", r, le(),
             r ? info[0] : 0);
        arm();
        r = p_is_restricted(dup);
        line("IsTokenRestricted(the DuplicateTokenEx copy): ret=%d err=%s", r, le());
        CloseHandle(dup);
    }
    arm();
    r = p_is_restricted(token);
    line("IsTokenRestricted(the primary token): ret=%d err=%s", r, le());
    arm();
    r = p_create_restricted(token, 0, 0, NULL, 0, NULL, 0, NULL, &rest);
    line("CreateRestrictedToken(flags 0, nothing disabled or restricted): ret=%d err=%s, %s", r, le(),
         r && rest != NULL ? "a handle" : "no handle");
    if (r && rest != NULL) {
        arm();
        r = p_is_restricted(rest);
        line("IsTokenRestricted(the restricted copy): ret=%d err=%s", r, le());
        CloseHandle(rest);
    }
    CloseHandle(token);
}

/* --- threadtok ----------------------------------------------------------- */

static void sec_threadtok(void)
{
    HANDLE tt = NULL, thr;
    BOOL r;

    if (!have("OpenThreadToken", (void *)p_open_thread_token) || !have("SetThreadToken", (void *)p_set_thread_token)
        || !have("ImpersonateSelf", (void *)p_impersonate_self)) {
        return;
    }
    arm();
    r = p_open_thread_token(GetCurrentThread(), TOKEN_QUERY, FALSE, &tt);
    line("OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, OpenAsSelf=FALSE): ret=%d err=%s, %s", r, le(),
         r && tt != NULL ? "a handle" : "no handle");
    if (tt != NULL) {
        CloseHandle(tt);
        tt = NULL;
    }
    arm();
    r = p_impersonate_self(SecurityImpersonation);
    line("ImpersonateSelf(SecurityImpersonation): ret=%d err=%s", r, le());
    arm();
    r = p_open_thread_token(GetCurrentThread(), TOKEN_QUERY, TRUE, &tt);
    line("OpenThreadToken(after ImpersonateSelf, OpenAsSelf=TRUE): ret=%d err=%s, %s", r, le(),
         r && tt != NULL ? "a handle" : "no handle");
    if (tt != NULL) {
        CloseHandle(tt);
    }
    arm();
    r = p_set_thread_token(NULL, NULL);
    line("SetThreadToken(NULL, NULL) (revert the impersonation): ret=%d err=%s", r, le());
    thr = GetCurrentThread();
    arm();
    r = p_set_thread_token(&thr, NULL);
    line("SetThreadToken(&current thread, NULL): ret=%d err=%s", r, le());
}

/* --- lookupdisp ---------------------------------------------------------- */

static void sec_lookupdisp(void)
{
    char disp[128];
    WCHAR dispw[128];
    DWORD cch, lang;
    BOOL r;

    if (!have("LookupPrivilegeDisplayNameA", (void *)p_lookup_display_a)
        || !have("LookupPrivilegeDisplayNameW", (void *)p_lookup_display_w)) {
        return;
    }
    cch = 0;
    lang = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_display_a(NULL, "SeShutdownPrivilege", NULL, &cch, &lang);
    line("LookupPrivilegeDisplayNameA(NULL, SeShutdownPrivilege, no buffer): ret=%d err=%s; cch %s lang %s", r, le(),
         cch == 0 ? "unset" : "set", lang == F2KT_UNTOUCHED ? "untouched" : "set");
    if (cch != 0 && cch <= sizeof disp) {
        cch = sizeof disp;
        lang = F2KT_UNTOUCHED;
        arm();
        r = p_lookup_display_a(NULL, "SeShutdownPrivilege", disp, &cch, &lang);
        line("LookupPrivilegeDisplayNameA(room): ret=%d err=%s; cch %lu, lang 0x%04lX, 0x0409: %s (the text never prints)",
             r, le(), cch, lang, yesno(lang == 0x0409));
    }
    cch = sizeof dispw / sizeof dispw[0];
    lang = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_display_w(NULL, L"SeShutdownPrivilege", dispw, &cch, &lang);
    line("LookupPrivilegeDisplayNameW(NULL, L\"SeShutdownPrivilege\") (W): ret=%d err=%s; cch %lu, lang 0x%04lX, 0x0409: %s",
         r, le(), cch, lang, yesno(lang == 0x0409));
    cch = sizeof disp;
    lang = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_display_a(NULL, "SeNoSuchPrivilege", disp, &cch, &lang);
    line("LookupPrivilegeDisplayNameA(an unknown name): ret=%d err=%s", r, le());
}

/* --- main --------------------------------------------------------------- */

static const section_t sections[] = {
    { "lookup", sec_lookup, F2KT_ALWAYS },
    { "check", sec_check, F2KT_ALWAYS },
    { "adjust", sec_adjust, F2KT_ALWAYS },
    { "membership", sec_membership, F2KT_ALWAYS },
    { "duplicate", sec_duplicate, F2KT_ALWAYS },
    { "tokengroups", sec_tokengroups, F2KT_ALWAYS },
    { "setinfo", sec_setinfo, F2KT_ALWAYS },
    { "duprestrict", sec_duprestrict, F2KT_ALWAYS },
    { "threadtok", sec_threadtok, F2KT_ALWAYS },
    { "lookupdisp", sec_lookupdisp, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    adv = GetModuleHandleA("advapi32.dll");
    p_lookup_name_a = (lookup_name_a_fn)GetProcAddress(adv, "LookupPrivilegeNameA");
    p_lookup_name_w = (lookup_name_w_fn)GetProcAddress(adv, "LookupPrivilegeNameW");
    p_priv_check = (priv_check_fn)GetProcAddress(adv, "PrivilegeCheck");
    p_check_member = (check_member_fn)GetProcAddress(adv, "CheckTokenMembership");
    p_dup_token = (dup_token_fn)GetProcAddress(adv, "DuplicateToken");
    p_alloc_sid = (alloc_sid_fn)GetProcAddress(adv, "AllocateAndInitializeSid");
    p_wk_sid = (wk_sid_fn)GetProcAddress(adv, "CreateWellKnownSid");
    p_equal_sid = (equal_sid_fn)GetProcAddress(adv, "EqualSid");
    p_free_sid = (free_sid_fn)GetProcAddress(adv, "FreeSid");
    p_adjust_groups = (adjust_groups_fn)GetProcAddress(adv, "AdjustTokenGroups");
    p_set_token_info = (set_token_info_fn)GetProcAddress(adv, "SetTokenInformation");
    p_dup_token_ex = (dup_token_ex_fn)GetProcAddress(adv, "DuplicateTokenEx");
    p_create_restricted = (create_restricted_fn)GetProcAddress(adv, "CreateRestrictedToken");
    p_is_restricted = (is_restricted_fn)GetProcAddress(adv, "IsTokenRestricted");
    p_open_thread_token = (open_thread_token_fn)GetProcAddress(adv, "OpenThreadToken");
    p_set_thread_token = (set_thread_token_fn)GetProcAddress(adv, "SetThreadToken");
    p_impersonate_self = (impersonate_self_fn)GetProcAddress(adv, "ImpersonateSelf");
    p_lookup_display_a = (lookup_display_a_fn)GetProcAddress(adv, "LookupPrivilegeDisplayNameA");
    p_lookup_display_w = (lookup_display_w_fn)GetProcAddress(adv, "LookupPrivilegeDisplayNameW");
    return run_sections("privchk", sections, argc, argv);
}
