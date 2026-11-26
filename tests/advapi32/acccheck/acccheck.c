/*
 * acccheck - the AccessCheck family over a real object, the process
 * handle, with a security descriptor and DACL this program builds by
 * hand (the layouts are public): a granted request against an allowed
 * mask, a deny ACE for a well-known SID winning in walk order, the
 * owner's implicit READ_CONTROL/WRITE_DAC, MAXIMUM_ALLOWED, the by-type
 * forms, AreAll/AreAnyAccessesGranted, and WRITE_OWNER/ACCESS_SYSTEM_
 * SECURITY with and without the privilege held.
 *
 * The token is the process's own, opened through a handle to the process
 * itself. The advapi32 security calls go through GetProcAddress, so the
 * program loads where advapi32 lacks them: a section whose call is
 * missing prints "not found" and stops. OpenProcessToken, GetToken-
 * Information and AdjustTokenPrivileges are called directly.
 *
 * Captured on an administrator account, whose token holds
 * SeSecurityPrivilege and SeTakeOwnershipPrivilege disabled; the
 * privileges are named by their public LUIDs (winnt.h's SE_*_PRIVILEGE
 * values): SeSecurityPrivilege 8, SeTakeOwnershipPrivilege 9. A SID
 * prints in its string form (every SID here is well-known); a mask
 * prints in hex; a status prints as 0x%08lX. Nothing machine-specific
 * prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   allowed    AccessCheck with a DACL allowing Everyone a mask: a
 *              request inside it (granted), the whole mask, one bit
 *              outside it (denied), the token opened from a handle to
 *              this process opened with OpenProcess
 *   denied     a deny ACE for Everyone before an allow for Everyone
 *              (denied), and the reverse order (granted): the walk order
 *   owner      the token's user as the SD's owner with an empty DACL:
 *              READ_CONTROL|WRITE_DAC granted to the owner, a plain bit
 *              denied
 *   maximum    MAXIMUM_ALLOWED against the allowed mask: granted all of
 *              it
 *   bytype     AccessCheckByType and AccessCheckByTypeResultList over a
 *              two-GUID type list: the granted masks and statuses per
 *              entry
 *   areall     AreAllAccessesGranted and AreAnyAccessesGranted over
 *              masks, and over a mask AccessCheck granted
 *   priv       ACCESS_SYSTEM_SECURITY with SeSecurityPrivilege disabled
 *              (denied), enabled (granted), disabled again (denied);
 *              WRITE_OWNER to the owner (granted), to a non-owner SD
 *              without SeTakeOwnershipPrivilege (denied), with it
 *              enabled (granted)
 *   effrights  GetEffectiveRightsFromAclA/W over the DACL of a built SD
 *              for an Everyone trustee: the granted mask against an
 *              allow, and against a deny first
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat acccheck):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% acccheck.c advapi32.lib
 */

#include "../common/f2kt.h"

/* The privileges' public LUIDs (winnt.h's SE_*_PRIVILEGE). */
#define SECURITY_LUID 8
#define TAKE_OWNERSHIP_LUID 9

/* --- the advapi32 security calls, through GetProcAddress ------------- */

/* A GUID as the type lists take it (16 bytes, the layout is public). */
typedef struct {
    DWORD data1;
    WORD data2;
    WORD data3;
    BYTE data4[8];
} f2kt_guid_t;

typedef BOOL (WINAPI *access_check_fn)(PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, PGENERIC_MAPPING,
                                        PPRIVILEGE_SET, PULONG, PACCESS_MASK, LONG *);
typedef BOOL (WINAPI *acbt_fn)(PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, DWORD, f2kt_guid_t *,
                               PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, LONG *);
typedef BOOL (WINAPI *acbtrl_fn)(PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, DWORD, f2kt_guid_t *,
                                 PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG, PACCESS_MASK, LONG *);
typedef BOOL (WINAPI *are_all_fn)(ACCESS_MASK, ACCESS_MASK);
typedef BOOL (WINAPI *are_any_fn)(ACCESS_MASK, ACCESS_MASK);
typedef BOOL (WINAPI *alloc_sid_fn)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD,
                                    DWORD, DWORD, DWORD, PSID *);
typedef BOOL (WINAPI *wk_sid_fn)(DWORD, PSID, PSID, DWORD *);
typedef BOOL (WINAPI *equal_sid_fn)(PSID, PSID);
typedef PVOID (WINAPI *free_sid_fn)(PSID);

/* GetEffectiveRightsFromAclA/W (public signatures). The trustee structure
 * is declared here (the layout is public). */
typedef struct f2kt_trustee {
    struct f2kt_trustee *pMultipleTrustee;
    int MultipleTrusteeOperation;
    int TrusteeForm;
    int TrusteeType;
    void *ptstrName;
} f2kt_trustee_t;

typedef DWORD (WINAPI *get_eff_rights_fn)(PACL, f2kt_trustee_t *, PACCESS_MASK);

/* TRUSTEE_FORM/TRUSTEE_TYPE values (winnt.h's). */
#define TF_NAME 1
#define TT_USER 1

static access_check_fn p_access_check;
static acbt_fn p_acbt;
static acbtrl_fn p_acbtrl;
static are_all_fn p_are_all;
static are_any_fn p_are_any;
static alloc_sid_fn p_alloc_sid;
static wk_sid_fn p_wk_sid;
static equal_sid_fn p_equal_sid;
static free_sid_fn p_free_sid;
static get_eff_rights_fn p_eff_rights_a, p_eff_rights_w;

static HMODULE adv;

/* --- the well-known SIDs, built by hand (the layout is public) -------- */

typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid5_t sid_system = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
static const sid5_t sid_admins = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };

/* The well-known SID types CreateWellKnownSid takes (public values). */
#define WK_WORLD 1
#define WK_LOCAL_SYSTEM 22
#define WK_BUILTIN_ADMINS 26

static DWORD sid_size(const void *sid)
{
    return 8 + 4 * (DWORD)((const BYTE *)sid)[1];
}

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

/* The SD's control word at offset 2: PSECURITY_DESCRIPTOR is opaque in
 * the MSVC 6 headers, so the header's fields are written at their public
 * offsets. */
static void sd_set_header(void *sd, unsigned control)
{
    ((BYTE *)sd)[0] = SECURITY_DESCRIPTOR_REVISION;
    *(unsigned short *)((BYTE *)sd + 2) = (unsigned short)control;
}

/* --- a self-relative SD built by hand --------------------------------- */

static ULONG sd_buf[512];               /* 2 KiB */
static ULONG user_sid[64];              /* the token's user SID */
static ULONG wk_buf[64];                /* a well-known SID built beside the SD */

typedef struct {
    int type;                           /* ACCESS_ALLOWED_ACE_TYPE or ACCESS_DENIED_ACE_TYPE */
    DWORD mask;
    const void *sid;
} ace_spec_t;

/* Builds a self-relative SD in sd_buf: owner `owner`, a DACL of the
 * `count` ACEs (none when count is 0, the DACL present but empty). */
static void build_sd(const void *owner, const ace_spec_t *aces, int count)
{
    BYTE *p = (BYTE *)sd_buf;
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    PACL acl;
    BYTE *q;
    DWORD off_owner, off_dacl;
    int i;

    memset(sd_buf, 0, sizeof sd_buf);
    off_owner = owner != NULL ? 20 : 0;
    off_dacl = 20 + (owner != NULL ? sid_size(owner) : 0);

    sd_set_header(sd, SE_SELF_RELATIVE | SE_DACL_PRESENT);
    if (owner != NULL) {
        memcpy(p + off_owner, owner, sid_size(owner));
        *(DWORD *)(p + 4) = off_owner;
    }
    acl = (PACL)(p + off_dacl);
    acl->AclRevision = ACL_REVISION;
    acl->AclSize = 8;
    acl->AceCount = (unsigned short)count;
    q = p + off_dacl + 8;
    for (i = 0; i < count; i++) {
        ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)q;
        DWORD ssize = sid_size(aces[i].sid);

        ace->Header.AceType = (BYTE)aces[i].type;
        ace->Header.AceFlags = 0;
        ace->Header.AceSize = (unsigned short)(sizeof(ACCESS_ALLOWED_ACE) + ssize);
        ace->Mask = aces[i].mask;
        memcpy(&ace->SidStart, aces[i].sid, ssize);
        q += ace->Header.AceSize;
    }
    acl->AclSize = (unsigned short)(q - (BYTE *)acl);
    *(DWORD *)(p + 12) = off_dacl;
}

/* --- helpers ----------------------------------------------------------- */

static int have(const char *name, void *p)
{
    if (p == NULL) {
        line("%s not found", name);
        return 0;
    }
    return 1;
}

static GENERIC_MAPPING mapping;
static BYTE priv_buf[256];

static void init_mapping(void)
{
    mapping.GenericRead = 0x80000000;
    mapping.GenericWrite = 0x40000000;
    mapping.GenericExecute = 0x20000000;
    mapping.GenericAll = 0x10000000;
}

/* OpenProcessToken on a handle to this process, printed. */
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

/* One AccessCheck, printed: ret, err, status, granted. */
static void run_check(const char *label, PSECURITY_DESCRIPTOR sd, HANDLE token, ACCESS_MASK requested)
{
    DWORD priv_len = sizeof priv_buf;
    ACCESS_MASK granted = 0;
    LONG status = 0;
    BOOL r;

    memset(priv_buf, 0, sizeof priv_buf);
    arm();
    r = p_access_check(sd, token, requested, &mapping, (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
    line("%s: ret=%d err=%s status=0x%08lX granted=0x%08lX", label, r, le(), (unsigned long)status,
         (unsigned long)granted);
}

/* The token's user SID copied into user_sid; whether it came. */
static int fetch_user(HANDLE token)
{
    static ULONG info[256];
    TOKEN_USER *tu = (TOKEN_USER *)info;
    DWORD len;

    memset(info, 0, sizeof info);
    if (!GetTokenInformation(token, TokenUser, info, sizeof info, &len)) {
        return 0;
    }
    if ((BYTE *)tu->User.Sid + sid_size(tu->User.Sid) > (BYTE *)info + sizeof info) {
        return 0;
    }
    memcpy(user_sid, tu->User.Sid, sid_size(tu->User.Sid));
    return 1;
}

/* A privilege's attributes in the token's list, or "not listed". */
static const char *priv_state(HANDLE token, DWORD luid)
{
    static ULONG info[1024];
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)info;
    DWORD len, i;

    if (!GetTokenInformation(token, TokenPrivileges, info, sizeof info, &len)) {
        return "the query failed";
    }
    if (tp->PrivilegeCount > 500) {
        return "the count out of range";
    }
    for (i = 0; i < tp->PrivilegeCount; i++) {
        if (tp->Privileges[i].Luid.LowPart == luid && tp->Privileges[i].Luid.HighPart == 0) {
            return (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "listed, enabled" : "listed, disabled";
        }
    }
    return "not listed";
}

/* AdjustTokenPrivileges setting one privilege's attributes, printed. */
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

/* --- allowed ------------------------------------------------------------ */

static void sec_allowed(void)
{
    static const ace_spec_t aces[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    HANDLE token, proc;
    PSID everyone = NULL;
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    BOOL r;

    if (!have("AccessCheck", (void *)p_access_check) || !have("AllocateAndInitializeSid", (void *)p_alloc_sid)
        || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    arm();
    r = p_alloc_sid(&nt, 1, 0, 0, 0, 0, 0, 0, 0, 0, &everyone);
    line("AllocateAndInitializeSid(S-1-1-0): ret=%d err=%s; %s", r, le(),
         r && everyone != NULL ? sid_text(everyone) : "-");
    build_sd(&sid_everyone, aces, 1);

    proc = NULL;
    arm();
    proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    line("OpenProcess(PROCESS_QUERY_INFORMATION, this process): a handle: %s err=%s", yesno(proc != NULL),
         le());
    if (proc != NULL) {
        token = NULL;
        arm();
        r = OpenProcessToken(proc, TOKEN_QUERY, &token);
        line("OpenProcessToken(that handle, TOKEN_QUERY): ret=%d err=%s, %s", r, le(),
             r && token != NULL ? "a handle" : "no handle");
        CloseHandle(proc);
    } else {
        token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    }
    if (token == NULL) {
        if (everyone != NULL) {
            p_free_sid(everyone);
        }
        return;
    }
    run_check("AccessCheck(requested 1, allow 0x000F01FF)", (PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001);
    run_check("AccessCheck(requested the whole allowed mask)", (PSECURITY_DESCRIPTOR)sd_buf, token, 0x000F01FF);
    run_check("AccessCheck(requested 4, outside the mask)", (PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000004);
    if (everyone != NULL) {
        PVOID freed;

        arm();
        freed = p_free_sid(everyone);
        line("FreeSid: returned NULL: %s err=%s", yesno(freed == NULL), le());
    }
    CloseHandle(token);
}

/* --- denied ------------------------------------------------------------- */

static void sec_denied(void)
{
    static const ace_spec_t deny_first[] = {
        { ACCESS_DENIED_ACE_TYPE, 0x000F01FF, &sid_everyone },
        { ACCESS_ALLOWED_ACE_TYPE, 0xFFFFFFFF, &sid_everyone }
    };
    static const ace_spec_t allow_first[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0xFFFFFFFF, &sid_everyone },
        { ACCESS_DENIED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    DWORD len;
    HANDLE token;
    BOOL r;

    if (!have("AccessCheck", (void *)p_access_check) || !have("CreateWellKnownSid", (void *)p_wk_sid)
        || !have("EqualSid", (void *)p_equal_sid) || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    len = sizeof wk_buf;
    arm();
    r = p_wk_sid(WK_LOCAL_SYSTEM, NULL, wk_buf, &len);
    line("CreateWellKnownSid(LocalSystem): ret=%d err=%s; %s", r, le(), r ? sid_text(wk_buf) : "-");
    arm();
    r = p_equal_sid((PSID)wk_buf, (PSID)&sid_system);
    line("EqualSid(it, the hand-built SYSTEM): ret=%d err=%s", r, le());

    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token == NULL) {
        return;
    }
    build_sd(&sid_everyone, deny_first, 2);
    run_check("deny Everyone 0x000F01FF before allow all, requested 1",
              (PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001);
    build_sd(&sid_everyone, allow_first, 2);
    run_check("allow all before deny Everyone 0x000F01FF, requested 1",
              (PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001);
    /* A deny for SYSTEM, which the token does not carry: no effect. */
    {
        static const ace_spec_t deny_system[] = {
            { ACCESS_DENIED_ACE_TYPE, 0xFFFFFFFF, &sid_system },
            { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
        };
        build_sd(&sid_everyone, deny_system, 2);
        run_check("deny SYSTEM (not in the token) before allow, requested 1",
                  (PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001);
    }
    CloseHandle(token);
}

/* --- owner -------------------------------------------------------------- */

static void sec_owner(void)
{
    static const ace_spec_t none[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0, &sid_everyone }
    };
    HANDLE token;
    PSID admins = NULL;
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    BOOL r;

    if (!have("AccessCheck", (void *)p_access_check) || !have("AllocateAndInitializeSid", (void *)p_alloc_sid)
        || !have("EqualSid", (void *)p_equal_sid) || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token == NULL) {
        return;
    }
    if (!fetch_user(token)) {
        line("GetTokenInformation(TokenUser) failed: err=%lu", GetLastError());
        CloseHandle(token);
        return;
    }
    line("TokenUser: %s", sid_text(user_sid));
    arm();
    r = p_alloc_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &admins);
    line("AllocateAndInitializeSid(S-1-5-32-544): ret=%d err=%s", r, le());
    if (r && admins != NULL) {
        arm();
        r = p_equal_sid(admins, (PSID)&sid_admins);
        line("EqualSid(it, the hand-built): ret=%d err=%s", r, le());
    }

    /* The owner gets READ_CONTROL and WRITE_DAC with an empty DACL. */
    build_sd(user_sid, none, 0);
    run_check("owner is the token's user, empty DACL, requested READ_CONTROL|WRITE_DAC",
              (PSECURITY_DESCRIPTOR)sd_buf, token, READ_CONTROL | WRITE_DAC);
    run_check("same, requested a plain bit 1", (PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001);
    /* An owner that is not the token's user: no owner rights. */
    build_sd(&sid_admins, none, 0);
    run_check("owner BUILTIN\\Administrators, empty DACL, requested READ_CONTROL|WRITE_DAC",
              (PSECURITY_DESCRIPTOR)sd_buf, token, READ_CONTROL | WRITE_DAC);
    if (admins != NULL) {
        p_free_sid(admins);
    }
    CloseHandle(token);
}

/* --- maximum ------------------------------------------------------------ */

static void sec_maximum(void)
{
    static const ace_spec_t aces[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    HANDLE token;
    PSID everyone = NULL;
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    ACCESS_MASK granted = 0;
    DWORD priv_len;
    LONG status = 0;
    BOOL r;

    if (!have("AccessCheck", (void *)p_access_check) || !have("AllocateAndInitializeSid", (void *)p_alloc_sid)
        || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    arm();
    r = p_alloc_sid(&nt, 1, 0, 0, 0, 0, 0, 0, 0, 0, &everyone);
    line("AllocateAndInitializeSid(S-1-1-0): ret=%d err=%s", r, le());
    build_sd(&sid_everyone, aces, 1);
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token == NULL) {
        return;
    }
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    arm();
    r = p_access_check((PSECURITY_DESCRIPTOR)sd_buf, token, MAXIMUM_ALLOWED, &mapping,
                       (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
    line("AccessCheck(MAXIMUM_ALLOWED, allow 0x000F01FF): ret=%d err=%s status=0x%08lX granted=0x%08lX",
         r, le(), (unsigned long)status, (unsigned long)granted);
    line("  granted the whole allowed mask: %s", yesno(granted == 0x000F01FF));
    if (everyone != NULL) {
        p_free_sid(everyone);
    }
    CloseHandle(token);
}

/* --- bytype ------------------------------------------------------------- */

static void sec_bytype(void)
{
    static const ace_spec_t aces[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    f2kt_guid_t types[2];
    ACCESS_MASK granted[2];
    LONG status[2];
    DWORD priv_len;
    HANDLE token;
    PSID everyone = NULL;
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    BOOL r;
    DWORD i;

    if (!have("AccessCheckByType", (void *)p_acbt)
        || !have("AccessCheckByTypeResultList", (void *)p_acbtrl)
        || !have("AllocateAndInitializeSid", (void *)p_alloc_sid) || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    arm();
    r = p_alloc_sid(&nt, 1, 0, 0, 0, 0, 0, 0, 0, 0, &everyone);
    line("AllocateAndInitializeSid(S-1-1-0): ret=%d err=%s", r, le());
    memset(types, 0, sizeof types);
    types[1].data1 = 1;                 /* two distinct zero-ish GUIDs */
    build_sd(&sid_everyone, aces, 1);
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token == NULL) {
        return;
    }
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    granted[0] = granted[1] = 0;
    status[0] = status[1] = 0;
    arm();
    r = p_acbt((PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001, 2, types, &mapping,
               (PPRIVILEGE_SET)priv_buf, &priv_len, &granted[0], &status[0]);
    line("AccessCheckByType(two types, requested 1): ret=%d err=%s status=0x%08lX granted=0x%08lX",
         r, le(), (unsigned long)status[0], (unsigned long)granted[0]);
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    arm();
    r = p_acbtrl((PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001, 2, types, &mapping,
                 (PPRIVILEGE_SET)priv_buf, &priv_len, granted, status);
    line("AccessCheckByTypeResultList(two types, requested 1): ret=%d err=%s", r, le());
    for (i = 0; i < 2; i++) {
        line("  type %lu: status=0x%08lX granted=0x%08lX", i, (unsigned long)status[i], (unsigned long)granted[i]);
    }
    if (everyone != NULL) {
        p_free_sid(everyone);
    }
    CloseHandle(token);
}

/* --- areall ------------------------------------------------------------- */

static void sec_areall(void)
{
    static const ace_spec_t aces[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    HANDLE token;
    PSID everyone = NULL;
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    ACCESS_MASK granted = 0;
    DWORD priv_len;
    LONG status = 0;
    BOOL r;

    if (!have("AreAllAccessesGranted", (void *)p_are_all)
        || !have("AreAnyAccessesGranted", (void *)p_are_any) || !have("AccessCheck", (void *)p_access_check)
        || !have("AllocateAndInitializeSid", (void *)p_alloc_sid) || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    arm();
    r = p_alloc_sid(&nt, 1, 0, 0, 0, 0, 0, 0, 0, 0, &everyone);
    line("AllocateAndInitializeSid(S-1-1-0): ret=%d err=%s", r, le());
    arm();
    r = p_are_all(0x000F01FF, 0x00000001);
    line("AreAllAccessesGranted(0x000F01FF, 1): ret=%d err=%s", r, le());
    arm();
    r = p_are_all(0x00000001, 0x000F01FF);
    line("AreAllAccessesGranted(1, 0x000F01FF): ret=%d err=%s", r, le());
    arm();
    r = p_are_any(0x00000001, 0x000F01FF);
    line("AreAnyAccessesGranted(1, 0x000F01FF): ret=%d err=%s", r, le());
    arm();
    r = p_are_any(0, 0x000F01FF);
    line("AreAnyAccessesGranted(0, 0x000F01FF): ret=%d err=%s", r, le());

    build_sd(&sid_everyone, aces, 1);
    token = open_token(TOKEN_QUERY, "TOKEN_QUERY");
    if (token != NULL) {
        priv_len = sizeof priv_buf;
        memset(priv_buf, 0, sizeof priv_buf);
        arm();
        r = p_access_check((PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001, &mapping,
                           (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
        line("AccessCheck(requested 1): ret=%d err=%s granted=0x%08lX", r, le(), (unsigned long)granted);
        arm();
        r = p_are_all(granted, 0x00000001);
        line("AreAllAccessesGranted(that granted, requested): ret=%d err=%s", r, le());
        CloseHandle(token);
    }
    if (everyone != NULL) {
        p_free_sid(everyone);
    }
}

/* --- priv --------------------------------------------------------------- */

static void sec_priv(void)
{
    static const ace_spec_t none[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0, &sid_everyone }
    };
    HANDLE token;
    PSID admins = NULL, system = NULL;
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    DWORD len;
    BOOL r;

    if (!have("AccessCheck", (void *)p_access_check) || !have("AllocateAndInitializeSid", (void *)p_alloc_sid)
        || !have("CreateWellKnownSid", (void *)p_wk_sid) || !have("EqualSid", (void *)p_equal_sid)
        || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    init_mapping();
    token = open_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, "TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES");
    if (token == NULL) {
        return;
    }
    line("SeSecurityPrivilege (LUID 8): %s; SeTakeOwnershipPrivilege (LUID 9): %s",
         priv_state(token, SECURITY_LUID), priv_state(token, TAKE_OWNERSHIP_LUID));
    if (!fetch_user(token)) {
        line("GetTokenInformation(TokenUser) failed");
        CloseHandle(token);
        return;
    }
    arm();
    r = p_alloc_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &admins);
    line("AllocateAndInitializeSid(S-1-5-32-544): ret=%d err=%s", r, le());
    len = sizeof wk_buf;
    arm();
    r = p_wk_sid(WK_LOCAL_SYSTEM, NULL, wk_buf, &len);
    line("CreateWellKnownSid(LocalSystem): ret=%d err=%s; %s", r, le(), r ? sid_text(wk_buf) : "-");
    system = (PSID)wk_buf;
    arm();
    r = p_equal_sid(system, (PSID)&sid_system);
    line("EqualSid(it, the hand-built SYSTEM): ret=%d err=%s", r, le());

    /* ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege enabled. */
    build_sd(user_sid, none, 0);
    run_check("ACCESS_SYSTEM_SECURITY, privilege disabled, empty DACL",
              (PSECURITY_DESCRIPTOR)sd_buf, token, ACCESS_SYSTEM_SECURITY);
    set_priv(token, "SeSecurityPrivilege", SECURITY_LUID, SE_PRIVILEGE_ENABLED);
    line("SeSecurityPrivilege now: %s", priv_state(token, SECURITY_LUID));
    run_check("ACCESS_SYSTEM_SECURITY, privilege enabled, empty DACL",
              (PSECURITY_DESCRIPTOR)sd_buf, token, ACCESS_SYSTEM_SECURITY);
    set_priv(token, "SeSecurityPrivilege", SECURITY_LUID, 0);
    line("SeSecurityPrivilege now: %s", priv_state(token, SECURITY_LUID));
    run_check("ACCESS_SYSTEM_SECURITY, disabled again, empty DACL",
              (PSECURITY_DESCRIPTOR)sd_buf, token, ACCESS_SYSTEM_SECURITY);

    /* WRITE_OWNER: the owner, or SeTakeOwnershipPrivilege enabled. */
    build_sd(user_sid, none, 0);
    run_check("WRITE_OWNER, the owner is the token's user, empty DACL",
              (PSECURITY_DESCRIPTOR)sd_buf, token, WRITE_OWNER);
    build_sd(system, none, 0);
    run_check("WRITE_OWNER, the owner is SYSTEM, privilege disabled, empty DACL",
              (PSECURITY_DESCRIPTOR)sd_buf, token, WRITE_OWNER);
    set_priv(token, "SeTakeOwnershipPrivilege", TAKE_OWNERSHIP_LUID, SE_PRIVILEGE_ENABLED);
    line("SeTakeOwnershipPrivilege now: %s", priv_state(token, TAKE_OWNERSHIP_LUID));
    run_check("WRITE_OWNER, the owner is SYSTEM, privilege enabled, empty DACL",
              (PSECURITY_DESCRIPTOR)sd_buf, token, WRITE_OWNER);
    set_priv(token, "SeTakeOwnershipPrivilege", TAKE_OWNERSHIP_LUID, 0);
    line("SeTakeOwnershipPrivilege now: %s", priv_state(token, TAKE_OWNERSHIP_LUID));

    if (admins != NULL) {
        p_free_sid(admins);
    }
    CloseHandle(token);
}

/* --- effrights ----------------------------------------------------------- */

static void sec_effrights(void)
{
    static const ace_spec_t allow[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    static const ace_spec_t deny_first[] = {
        { ACCESS_DENIED_ACE_TYPE, 0x000F01FF, &sid_everyone },
        { ACCESS_ALLOWED_ACE_TYPE, 0xFFFFFFFF, &sid_everyone }
    };
    f2kt_trustee_t tr;
    ACCESS_MASK mask;
    PACL dacl;
    DWORD ret;

    if (!have("GetEffectiveRightsFromAclA", (void *)p_eff_rights_a)
        || !have("GetEffectiveRightsFromAclW", (void *)p_eff_rights_w)) {
        return;
    }
    memset(&tr, 0, sizeof tr);
    tr.TrusteeForm = TF_NAME;
    tr.TrusteeType = TT_USER;
    tr.ptstrName = "Everyone";

    build_sd(&sid_everyone, allow, 1);
    dacl = (PACL)((BYTE *)sd_buf + *(DWORD *)((BYTE *)sd_buf + 12));
    mask = 0;
    arm();
    ret = p_eff_rights_a(dacl, &tr, &mask);
    line("GetEffectiveRightsFromAclA(allow Everyone 0x000F01FF): ret=%lu err=%s mask=0x%08lX", ret, le(),
         (unsigned long)mask);
    memset(&tr, 0, sizeof tr);
    tr.TrusteeForm = TF_NAME;
    tr.TrusteeType = TT_USER;
    tr.ptstrName = L"Everyone";
    mask = 0;
    arm();
    ret = p_eff_rights_w(dacl, &tr, &mask);
    line("GetEffectiveRightsFromAclW (W): ret=%lu err=%s mask=0x%08lX", ret, le(), (unsigned long)mask);

    build_sd(&sid_everyone, deny_first, 2);
    dacl = (PACL)((BYTE *)sd_buf + *(DWORD *)((BYTE *)sd_buf + 12));
    memset(&tr, 0, sizeof tr);
    tr.TrusteeForm = TF_NAME;
    tr.TrusteeType = TT_USER;
    tr.ptstrName = "Everyone";
    mask = 0;
    arm();
    ret = p_eff_rights_a(dacl, &tr, &mask);
    line("GetEffectiveRightsFromAclA(deny Everyone first): ret=%lu err=%s mask=0x%08lX", ret, le(),
         (unsigned long)mask);
}

/* --- main --------------------------------------------------------------- */

static const section_t sections[] = {
    { "allowed", sec_allowed, F2KT_ALWAYS },
    { "denied", sec_denied, F2KT_ALWAYS },
    { "owner", sec_owner, F2KT_ALWAYS },
    { "maximum", sec_maximum, F2KT_ALWAYS },
    { "bytype", sec_bytype, F2KT_ALWAYS },
    { "areall", sec_areall, F2KT_ALWAYS },
    { "priv", sec_priv, F2KT_ALWAYS },
    { "effrights", sec_effrights, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    adv = GetModuleHandleA("advapi32.dll");
    p_access_check = (access_check_fn)GetProcAddress(adv, "AccessCheck");
    p_acbt = (acbt_fn)GetProcAddress(adv, "AccessCheckByType");
    p_acbtrl = (acbtrl_fn)GetProcAddress(adv, "AccessCheckByTypeResultList");
    p_are_all = (are_all_fn)GetProcAddress(adv, "AreAllAccessesGranted");
    p_are_any = (are_any_fn)GetProcAddress(adv, "AreAnyAccessesGranted");
    p_alloc_sid = (alloc_sid_fn)GetProcAddress(adv, "AllocateAndInitializeSid");
    p_wk_sid = (wk_sid_fn)GetProcAddress(adv, "CreateWellKnownSid");
    p_equal_sid = (equal_sid_fn)GetProcAddress(adv, "EqualSid");
    p_free_sid = (free_sid_fn)GetProcAddress(adv, "FreeSid");
    p_eff_rights_a = (get_eff_rights_fn)GetProcAddress(adv, "GetEffectiveRightsFromAclA");
    p_eff_rights_w = (get_eff_rights_fn)GetProcAddress(adv, "GetEffectiveRightsFromAclW");
    return run_sections("acccheck", sections, argc, argv);
}
