/*
 * ntsvc - the NT-gate security services, called ntdll-direct through
 * GetProcAddress as the corpus pattern for ntdll calls (the prototypes
 * are declared here, as the kernel32 fixtures that call ntdll do; the
 * names are the public API's): NtAccessCheck (granted and denied),
 * NtPrivilegeCheck, NtQuerySecurityObject and NtSetSecurityObject on a
 * file handle and a process handle, and CreateFileA with a
 * SECURITY_ATTRIBUTES carrying a security descriptor (enforcement at
 * create), with the denied case. The fixture sits in advapi32's group
 * because that DLL's behavior is what the services stand behind; the one
 * advapi32 call it makes, OpenProcessToken, is direct.
 *
 * The security descriptors, ACLs and SIDs are built by hand (the layouts
 * are public), so no advapi32 security call is needed. The privileges are
 * named by their public LUIDs (winnt.h's SE_*_PRIVILEGE values):
 * SeShutdownPrivilege 19, SeDebugPrivilege 20, SeChangeNotifyPrivilege
 * 23. Captured on an administrator account, whose token holds
 * SeShutdownPrivilege and SeDebugPrivilege disabled and
 * SeChangeNotifyPrivilege enabled. Statuses print as 0x%08lX; a SID
 * prints in its string form (every SID here is well-known); a mask in
 * hex. Nothing machine-specific prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   ntaccesscheck  NtOpenProcessToken and advapi32's OpenProcessToken;
 *                  NtAccessCheck with a DACL allowing Everyone a mask
 *                  (granted), and a deny ACE for Everyone first (denied)
 *   ntprivcheck    NtQueryInformationToken(TokenPrivileges) for the
 *                  three privileges' attributes; NtPrivilegeCheck with
 *                  an empty set, SeShutdownPrivilege (disabled) and
 *                  SeChangeNotifyPrivilege (enabled)
 *   ntquerysecobj  NtQuerySecurityObject on a temp file's handle and on
 *                  the process handle: the size query, the exact size,
 *                  what is present; a closed handle
 *   ntsetsecobj    NtSetSecurityObject with a DACL on the file handle
 *                  and on the process handle, read back with
 *                  NtQuerySecurityObject; a closed handle
 *   createwithsd   CreateFileA with a SECURITY_ATTRIBUTES carrying an
 *                  allowing SD, a denying one (denied at create), and
 *                  a NULL SD; the temp file deleted again
 *   ntbytype       NtAccessCheckByType and NtAccessCheckByTypeResultList
 *                  over a two-GUID type list (granted, and a request
 *                  outside the allowed mask)
 *   ntgroups       NtAdjustGroupsToken: a NULL NewState (refused), a
 *                  valid NewState with a too-short PreviousState (the
 *                  size asked for)
 *   ntsetinfo      NtSetInformationToken: an unknown class, TokenUser
 *                  with a 4-byte buffer, TokenType (a read-only class)
 *   ntcreatefilter NtCreateToken with no object attributes (refused), and
 *                  NtFilterToken with nothing disabled (a copy)
 *   ntthreadtok    NtOpenThreadToken on the current thread (no token)
 *   ntrtlpriv      RtlAdjustPrivilege enabling and disabling
 *                  SeShutdownPrivilege (status, previous value)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat ntsvc):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ntsvc.c advapi32.lib
 */

#include "../common/f2kt.h"

/* --- the NT types and signatures, declared here ------------------------ */
/* NTSTATUS is the status type the Nt* calls answer; the MSVC 6 SDK
 * headers predate it. HANDLE, ACCESS_MASK, PSECURITY_DESCRIPTOR and
 * SECURITY_INFORMATION come from the public headers. */
typedef LONG NTSTATUS;

/* TokenPrivileges, the token information class. */
#define NT_TOKEN_PRIVILEGES 3

/* The privileges' public LUIDs (winnt.h's SE_*_PRIVILEGE). */
#define SHUTDOWN_LUID 19
#define DEBUG_LUID 20
#define CHANGE_NOTIFY_LUID 23

typedef NTSTATUS (WINAPI *nt_access_check_fn)(PSECURITY_DESCRIPTOR, HANDLE, ACCESS_MASK, PGENERIC_MAPPING,
                                               PPRIVILEGE_SET, PULONG, PACCESS_MASK, NTSTATUS *);
typedef NTSTATUS (WINAPI *nt_priv_check_fn)(HANDLE, PPRIVILEGE_SET, PBOOLEAN);
typedef NTSTATUS (WINAPI *nt_query_sec_fn)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
typedef NTSTATUS (WINAPI *nt_set_sec_fn)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
typedef NTSTATUS (WINAPI *nt_open_token_fn)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (WINAPI *nt_query_token_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* The remaining NT-gate services (public signatures; the token classes
 * and structures come from the public headers). */
typedef NTSTATUS (WINAPI *nt_access_check_by_type_fn)(PSECURITY_DESCRIPTOR, PSID, HANDLE, ACCESS_MASK, PVOID,
                                                      DWORD, PGENERIC_MAPPING, PPRIVILEGE_SET, PULONG,
                                                      PACCESS_MASK, NTSTATUS *);
typedef NTSTATUS (WINAPI *nt_adjust_groups_fn)(HANDLE, BOOLEAN, PTOKEN_GROUPS, ULONG, PTOKEN_GROUPS, PULONG);
typedef NTSTATUS (WINAPI *nt_set_info_fn)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (WINAPI *nt_create_token_fn)(PHANDLE, ACCESS_MASK, PVOID, int, PLUID, PLARGE_INTEGER, PTOKEN_USER,
                                              PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER,
                                              PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE);
typedef NTSTATUS (WINAPI *nt_filter_token_fn)(HANDLE, ULONG, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_GROUPS,
                                              PHANDLE);
typedef NTSTATUS (WINAPI *nt_open_thread_token_fn)(HANDLE, ACCESS_MASK, BOOLEAN, PHANDLE);
typedef NTSTATUS (WINAPI *rtl_adjust_priv_fn)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

/* A GUID as the type lists take it (16 bytes, the layout is public). */
typedef struct {
    DWORD data1;
    WORD data2;
    WORD data3;
    BYTE data4[8];
} f2kt_guid_t;

/* An object type list entry (the layout is public). */
typedef struct {
    WORD level;
    WORD sbz;
    f2kt_guid_t *objectType;
} f2kt_obj_type_list_t;

/* Token information classes (winnt.h's public values). */
#define NT_TI_TOKEN_USER 1
#define NT_TI_TOKEN_TYPE 8

static nt_access_check_fn p_nt_access_check;
static nt_priv_check_fn p_nt_priv_check;
static nt_query_sec_fn p_nt_query_sec;
static nt_set_sec_fn p_nt_set_sec;
static nt_open_token_fn p_nt_open_token;
static nt_query_token_fn p_nt_query_token;
static nt_access_check_by_type_fn p_nt_acbt;
static nt_access_check_by_type_fn p_nt_acbtrl;
static nt_adjust_groups_fn p_nt_adjust_groups;
static nt_set_info_fn p_nt_set_info;
static nt_create_token_fn p_nt_create_token;
static nt_filter_token_fn p_nt_filter_token;
static nt_open_thread_token_fn p_nt_open_thread_token;
static rtl_adjust_priv_fn p_rtl_adjust_priv;

static HMODULE ntdll;

/* --- the well-known SIDs, built by hand (the layout is public) -------- */

typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };

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

/* --- a self-relative SD built by hand --------------------------------- */

static ULONG sd_buf[512];               /* 2 KiB */
static ULONG out_buf[512];              /* 2 KiB */
static BYTE priv_buf[256];

typedef struct {
    int type;                           /* ACCESS_ALLOWED_ACE_TYPE or ACCESS_DENIED_ACE_TYPE */
    DWORD mask;
    const void *sid;
} ace_spec_t;

/* Builds a self-relative SD in sd_buf: owner Everyone, a DACL of the
 * `count` ACEs. */
static void build_sd(const ace_spec_t *aces, int count)
{
    BYTE *p = (BYTE *)sd_buf;
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    PACL acl;
    BYTE *q;
    DWORD off_owner, off_dacl;
    int i;

    memset(sd_buf, 0, sizeof sd_buf);
    off_owner = 20;
    off_dacl = off_owner + sid_size(&sid_everyone);

    ((BYTE *)sd)[0] = SECURITY_DESCRIPTOR_REVISION;
    *(unsigned short *)((BYTE *)sd + 2) = (unsigned short)(SE_SELF_RELATIVE | SE_DACL_PRESENT);
    memcpy(p + off_owner, &sid_everyone, sid_size(&sid_everyone));
    *(DWORD *)(p + 4) = off_owner;
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

static GENERIC_MAPPING mapping;

static void init_mapping(void)
{
    mapping.GenericRead = 0x80000000;
    mapping.GenericWrite = 0x40000000;
    mapping.GenericExecute = 0x20000000;
    mapping.GenericAll = 0x10000000;
}


/* The SD's control word at offset 2: PSECURITY_DESCRIPTOR is opaque in
 * the MSVC 6 headers, so the header's fields are read at their public
 * offsets. */
static unsigned sd_control(const void *sd)
{
    return *(const unsigned short *)((const BYTE *)sd + 2);
}

static int have(const char *name, void *p)
{
    if (p == NULL) {
        line("%s not found", name);
        return 0;
    }
    return 1;
}

/* A self-relative SD read back, as relations and the DACL's ACEs. */
static void show_sd(const char *label, const void *buf, ULONG len)
{
    const BYTE *p = (const BYTE *)buf;
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)buf;
    DWORD off_owner, off_dacl;
    const ACL *acl;
    const ACCESS_ALLOWED_ACE *ace;

    if (len < 20 || p[0] != SECURITY_DESCRIPTOR_REVISION) {
        line("%s: not a security descriptor (len %lu, revision %u)", label, len, (unsigned)p[0]);
        return;
    }
    off_owner = *(const DWORD *)(p + 4);
    off_dacl = *(const DWORD *)(p + 12);
    line("%s: Control 0x%04X, owner present: %s, DACL present: %s, length %lu", label,
         sd_control(sd), yesno(off_owner != 0 && off_owner < len),
         yesno((sd_control(sd) & SE_DACL_PRESENT) != 0 && off_dacl != 0 && off_dacl < len), len);
    if (off_owner != 0 && off_owner + 8 <= len) {
        line("  the owner: %s", sid_text(p + off_owner));
    }
    if ((sd_control(sd) & SE_DACL_PRESENT) != 0 && off_dacl != 0 && off_dacl + 8 <= len) {
        acl = (const ACL *)(p + off_dacl);
        line("  the DACL: revision %u, size %u, AceCount %u", (unsigned)acl->AclRevision,
             (unsigned)acl->AclSize, (unsigned)acl->AceCount);
        if (acl->AceCount >= 1 && off_dacl + 8 + sizeof(ACCESS_ALLOWED_ACE) + 8 <= len) {
            ace = (const ACCESS_ALLOWED_ACE *)(p + off_dacl + 8);
            line("  ACE 0: type %u, flags 0x%X, mask 0x%08lX, sid %s", (unsigned)ace->Header.AceType,
                 (unsigned)ace->Header.AceFlags, ace->Mask, sid_text(&ace->SidStart));
        }
    }
}

static const char name_a[] = "ntsvc.tmp";

/* CreateFileA the temp file, printed; NULL when it fails. */
static HANDLE make_file(DWORD access, LPSECURITY_ATTRIBUTES sa)
{
    HANDLE h;

    arm();
    h = CreateFileA(name_a, access, FILE_SHARE_READ | FILE_SHARE_WRITE, sa, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    line("CreateFileA(%s, access 0x%08lX, CREATE_ALWAYS%s): %s err=%s", name_a, access,
         sa != NULL ? ", with a SECURITY_ATTRIBUTES" : "", h != INVALID_HANDLE_VALUE && h != NULL ? "a handle" : "NULL",
         le());
    return (h == INVALID_HANDLE_VALUE) ? NULL : h;
}

/* --- ntaccesscheck ------------------------------------------------------- */

static void sec_ntaccesscheck(void)
{
    static const ace_spec_t allow[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    static const ace_spec_t deny_first[] = {
        { ACCESS_DENIED_ACE_TYPE, 0x000F01FF, &sid_everyone },
        { ACCESS_ALLOWED_ACE_TYPE, 0xFFFFFFFF, &sid_everyone }
    };
    HANDLE token = NULL, token2 = NULL;
    DWORD priv_len;
    ACCESS_MASK granted;
    NTSTATUS status;
    BOOL r;

    if (!have("NtAccessCheck", (void *)p_nt_access_check) || !have("NtOpenProcessToken", (void *)p_nt_open_token)) {
        return;
    }
    init_mapping();
    arm();
    status = p_nt_open_token(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): status=0x%08lX, %s", (unsigned long)status,
         status >= 0 && token != NULL ? "a handle" : "no handle");
    if (status < 0 || token == NULL) {
        return;
    }
    arm();
    r = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token2);
    line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): ret=%d err=%s, %s", r, le(),
         r && token2 != NULL ? "a handle" : "no handle");

    build_sd(allow, 1);
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    granted = 0;
    status = 0;
    arm();
    status = p_nt_access_check((PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001, &mapping,
                               (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
    line("NtAccessCheck(allow Everyone 0x000F01FF, requested 1): status=0x%08lX granted=0x%08lX err=%s",
         (unsigned long)status, (unsigned long)granted, le());
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    granted = 0;
    status = 0;
    arm();
    status = p_nt_access_check((PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000004, &mapping,
                               (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
    line("NtAccessCheck(same, requested 4, outside the mask): status=0x%08lX granted=0x%08lX err=%s",
         (unsigned long)status, (unsigned long)granted, le());

    build_sd(deny_first, 2);
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    granted = 0;
    status = 0;
    arm();
    status = p_nt_access_check((PSECURITY_DESCRIPTOR)sd_buf, token, 0x00000001, &mapping,
                               (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
    line("NtAccessCheck(deny Everyone first, requested 1): status=0x%08lX granted=0x%08lX err=%s",
         (unsigned long)status, (unsigned long)granted, le());
    if (token2 != NULL) {
        priv_len = sizeof priv_buf;
        memset(priv_buf, 0, sizeof priv_buf);
        granted = 0;
        status = 0;
        arm();
        status = p_nt_access_check((PSECURITY_DESCRIPTOR)sd_buf, token2, 0x00000001, &mapping,
                                   (PPRIVILEGE_SET)priv_buf, &priv_len, &granted, &status);
        line("NtAccessCheck(the advapi32-opened token, deny first, requested 1): status=0x%08lX granted=0x%08lX err=%s",
             (unsigned long)status, (unsigned long)granted, le());
        CloseHandle(token2);
    }
    CloseHandle(token);
}

/* --- ntprivcheck --------------------------------------------------------- */

static void sec_ntprivcheck(void)
{
    static ULONG info[1024];
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)info;
    HANDLE token = NULL;
    PRIVILEGE_SET ps;
    BOOLEAN result;
    ULONG len;
    NTSTATUS status;
    DWORD i, count;

    if (!have("NtPrivilegeCheck", (void *)p_nt_priv_check)
        || !have("NtQueryInformationToken", (void *)p_nt_query_token)
        || !have("NtOpenProcessToken", (void *)p_nt_open_token)) {
        return;
    }
    status = p_nt_open_token(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): status=0x%08lX, %s", (unsigned long)status,
         status >= 0 && token != NULL ? "a handle" : "no handle");
    if (status < 0 || token == NULL) {
        return;
    }
    len = sizeof info;
    arm();
    status = p_nt_query_token(token, NT_TOKEN_PRIVILEGES, info, len, &len);
    line("NtQueryInformationToken(TokenPrivileges): status=0x%08lX err=%s ReturnLength %lu", (unsigned long)status,
         le(), len);
    if (status >= 0) {
        count = tp->PrivilegeCount;
        if (count > 500) {
            count = 0;
        }
        for (i = 0; i < count; i++) {
            if ((tp->Privileges[i].Luid.LowPart == SHUTDOWN_LUID || tp->Privileges[i].Luid.LowPart == DEBUG_LUID
                 || tp->Privileges[i].Luid.LowPart == CHANGE_NOTIFY_LUID)
                && tp->Privileges[i].Luid.HighPart == 0) {
                line("  LUID %lu: attributes 0x%lX, enabled: %s", tp->Privileges[i].Luid.LowPart,
                     tp->Privileges[i].Attributes,
                     yesno((tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0));
            }
        }
    }

    ps.PrivilegeCount = 0;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    result = FALSE;
    arm();
    status = p_nt_priv_check(token, &ps, &result);
    line("NtPrivilegeCheck(an empty set): status=0x%08lX result=%d err=%s", (unsigned long)status, result, le());

    ps.PrivilegeCount = 1;
    ps.Privilege[0].Luid.LowPart = SHUTDOWN_LUID;
    ps.Privilege[0].Luid.HighPart = 0;
    ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    result = FALSE;
    arm();
    status = p_nt_priv_check(token, &ps, &result);
    line("NtPrivilegeCheck(SeShutdownPrivilege enabled, held disabled): status=0x%08lX result=%d err=%s",
         (unsigned long)status, result, le());

    ps.Privilege[0].Luid.LowPart = CHANGE_NOTIFY_LUID;
    result = FALSE;
    arm();
    status = p_nt_priv_check(token, &ps, &result);
    line("NtPrivilegeCheck(SeChangeNotifyPrivilege enabled, held enabled): status=0x%08lX result=%d err=%s",
         (unsigned long)status, result, le());
    CloseHandle(token);
}

/* --- ntquerysecobj ------------------------------------------------------- */

static void sec_ntquerysecobj(void)
{
    HANDLE h, proc;
    ULONG need, len;
    NTSTATUS status;

    if (!have("NtQuerySecurityObject", (void *)p_nt_query_sec)) {
        return;
    }
    h = make_file(GENERIC_READ | GENERIC_WRITE, NULL);
    if (h == NULL) {
        return;
    }
    need = F2KT_UNTOUCHED;
    arm();
    status = p_nt_query_sec(h, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                            NULL, 0, &need);
    line("NtQuerySecurityObject(the file handle, no buffer): status=0x%08lX err=%s; the size needed %s",
         (unsigned long)status, le(), need == F2KT_UNTOUCHED ? "untouched" : "set");
    if (need != F2KT_UNTOUCHED && need <= sizeof out_buf && need >= 20) {
        memset(out_buf, 0xCC, sizeof out_buf);
        len = need - 1;
        arm();
        status = p_nt_query_sec(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, len, &need);
        line("NtQuerySecurityObject(a byte short): status=0x%08lX err=%s; the buffer untouched: %s",
             (unsigned long)status, le(), yesno(out_buf[0] == 0xCCCCCCCCu));
        memset(out_buf, 0, sizeof out_buf);
        len = need;
        arm();
        status = p_nt_query_sec(h, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                (PSECURITY_DESCRIPTOR)out_buf, len, &need);
        line("NtQuerySecurityObject(the size asked for): status=0x%08lX err=%s", (unsigned long)status, le());
        if (status >= 0) {
            show_sd("the file's SD", out_buf, need);
        }
    }
    arm();
    status = p_nt_query_sec(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, sizeof out_buf, &len);
    line("NtQuerySecurityObject(the file handle, DACL, a big buffer): status=0x%08lX err=%s", (unsigned long)status,
         le());
    if (status >= 0) {
        show_sd("the file's DACL read", out_buf, len);
    }
    CloseHandle(h);

    proc = GetCurrentProcess();
    need = F2KT_UNTOUCHED;
    arm();
    status = p_nt_query_sec(proc, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                            NULL, 0, &need);
    line("NtQuerySecurityObject(the process handle, no buffer): status=0x%08lX err=%s; the size needed %s",
         (unsigned long)status, le(), need == F2KT_UNTOUCHED ? "untouched" : "set");
    if (need != F2KT_UNTOUCHED && need <= sizeof out_buf && need >= 20) {
        memset(out_buf, 0, sizeof out_buf);
        len = need;
        arm();
        status = p_nt_query_sec(proc, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                (PSECURITY_DESCRIPTOR)out_buf, len, &need);
        line("NtQuerySecurityObject(the process handle, the size asked for): status=0x%08lX err=%s",
             (unsigned long)status, le());
        if (status >= 0) {
            show_sd("the process's SD", out_buf, need);
        }
    }
    arm();
    status = p_nt_query_sec(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, sizeof out_buf, &len);
    line("NtQuerySecurityObject(a closed handle): status=0x%08lX err=%s", (unsigned long)status, le());
    arm();
    DeleteFileA(name_a);
    line("DeleteFileA(%s): err=%s", name_a, le());
}

/* --- ntsetsecobj --------------------------------------------------------- */

static void sec_ntsetsecobj(void)
{
    static const ace_spec_t allow[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    HANDLE h;
    ULONG need, len;
    NTSTATUS status;

    if (!have("NtSetSecurityObject", (void *)p_nt_set_sec) || !have("NtQuerySecurityObject", (void *)p_nt_query_sec)) {
        return;
    }
    h = make_file(GENERIC_READ | GENERIC_WRITE, NULL);
    if (h == NULL) {
        return;
    }
    build_sd(allow, 1);
    arm();
    status = p_nt_set_sec(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("NtSetSecurityObject(the file handle, DACL, allow Everyone 0x000F01FF): status=0x%08lX err=%s",
         (unsigned long)status, le());
    memset(out_buf, 0, sizeof out_buf);
    len = sizeof out_buf;
    arm();
    status = p_nt_query_sec(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, len, &need);
    line("NtQuerySecurityObject(the file handle, DACL, read back): status=0x%08lX err=%s", (unsigned long)status,
         le());
    if (status >= 0) {
        show_sd("the file's SD read back", out_buf, need);
    }
    arm();
    status = p_nt_set_sec(GetCurrentProcess(), DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("NtSetSecurityObject(the process handle, DACL): status=0x%08lX err=%s", (unsigned long)status, le());
    arm();
    status = p_nt_set_sec(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("NtSetSecurityObject(a closed handle): status=0x%08lX err=%s", (unsigned long)status, le());
    CloseHandle(h);
    arm();
    DeleteFileA(name_a);
    line("DeleteFileA(%s): err=%s", name_a, le());
}

/* --- createwithsd -------------------------------------------------------- */

static void sec_createwithsd(void)
{
    static const ace_spec_t allow[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0xFFFFFFFF, &sid_everyone }
    };
    static const ace_spec_t deny[] = {
        { ACCESS_DENIED_ACE_TYPE, 0xFFFFFFFF, &sid_everyone }
    };
    SECURITY_ATTRIBUTES sa;
    HANDLE h;
    BOOL r;

    build_sd(allow, 1);
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd_buf;
    sa.bInheritHandle = FALSE;
    h = make_file(GENERIC_READ | GENERIC_WRITE, &sa);
    if (h != NULL) {
        arm();
        r = CloseHandle(h);
        line("CloseHandle: ret=%d err=%s", r, le());
    }
    build_sd(deny, 1);
    sa.lpSecurityDescriptor = sd_buf;
    h = make_file(GENERIC_READ | GENERIC_WRITE, &sa);
    if (h != NULL) {
        arm();
        r = CloseHandle(h);
        line("CloseHandle(the denied case's handle, if any): ret=%d err=%s", r, le());
    }
    sa.lpSecurityDescriptor = NULL;
    h = make_file(GENERIC_READ | GENERIC_WRITE, &sa);
    if (h != NULL) {
        arm();
        r = CloseHandle(h);
        line("CloseHandle: ret=%d err=%s", r, le());
    }
    arm();
    DeleteFileA(name_a);
    line("DeleteFileA(%s): err=%s", name_a, le());
}

/* --- ntbytype ------------------------------------------------------------ */

static void sec_ntbytype(void)
{
    static const ace_spec_t allow[] = {
        { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
    };
    f2kt_guid_t types[2];
    f2kt_obj_type_list_t list[2];
    ACCESS_MASK granted[2];
    NTSTATUS status[2];
    HANDLE token = NULL;
    DWORD priv_len;
    NTSTATUS st;
    DWORD i;

    if (!have("NtAccessCheckByType", (void *)p_nt_acbt)
        || !have("NtAccessCheckByTypeResultList", (void *)p_nt_acbtrl)
        || !have("NtOpenProcessToken", (void *)p_nt_open_token)) {
        return;
    }
    init_mapping();
    st = p_nt_open_token(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): status=0x%08lX, %s", (unsigned long)st,
         st >= 0 && token != NULL ? "a handle" : "no handle");
    if (st < 0 || token == NULL) {
        return;
    }
    memset(types, 0, sizeof types);
    types[1].data1 = 1;                 /* two distinct zero-ish GUIDs */
    memset(list, 0, sizeof list);
    for (i = 0; i < 2; i++) {
        list[i].level = 1;              /* the object type itself */
        list[i].objectType = &types[i];
    }
    build_sd(allow, 1);
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    granted[0] = 0;
    status[0] = 0;
    arm();
    st = p_nt_acbt((PSECURITY_DESCRIPTOR)sd_buf, NULL, token, 0x00000001, list, 2, &mapping,
                   (PPRIVILEGE_SET)priv_buf, &priv_len, &granted[0], &status[0]);
    line("NtAccessCheckByType(two types, requested 1): status=0x%08lX granted=0x%08lX err=%s", (unsigned long)st,
         (unsigned long)granted[0], le());
    priv_len = sizeof priv_buf;
    memset(priv_buf, 0, sizeof priv_buf);
    granted[0] = granted[1] = 0;
    status[0] = status[1] = 0;
    arm();
    st = p_nt_acbtrl((PSECURITY_DESCRIPTOR)sd_buf, NULL, token, 0x00000004, list, 2, &mapping,
                     (PPRIVILEGE_SET)priv_buf, &priv_len, granted, status);
    line("NtAccessCheckByTypeResultList(two types, requested 4, outside the mask): status=0x%08lX err=%s",
         (unsigned long)st, le());
    for (i = 0; i < 2; i++) {
        line("  type %lu: status=0x%08lX granted=0x%08lX", i, (unsigned long)status[i], (unsigned long)granted[i]);
    }
    CloseHandle(token);
}

/* --- ntgroups ------------------------------------------------------------ */

static void sec_ntgroups(void)
{
    TOKEN_GROUPS ng;
    HANDLE token = NULL;
    ULONG len;
    NTSTATUS st;

    if (!have("NtAdjustGroupsToken", (void *)p_nt_adjust_groups)
        || !have("NtOpenProcessToken", (void *)p_nt_open_token)) {
        return;
    }
    st = p_nt_open_token(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_GROUPS, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_GROUPS): status=0x%08lX, %s",
         (unsigned long)st, st >= 0 && token != NULL ? "a handle" : "no handle");
    if (st < 0 || token == NULL) {
        return;
    }
    len = F2KT_UNTOUCHED;
    arm();
    st = p_nt_adjust_groups(token, FALSE, NULL, 0, NULL, &len);
    line("NtAdjustGroupsToken(ResetToDefault=FALSE, NewState NULL): status=0x%08lX err=%s; ReturnLength %s",
         (unsigned long)st, le(), len == F2KT_UNTOUCHED ? "untouched" : "set");
    memset(&ng, 0, sizeof ng);
    ng.GroupCount = 1;
    ng.Groups[0].Sid = (PSID)&sid_everyone;
    ng.Groups[0].Attributes = SE_GROUP_ENABLED;
    len = F2KT_UNTOUCHED;
    arm();
    st = p_nt_adjust_groups(token, FALSE, &ng, 4, NULL, &len);
    line("NtAdjustGroupsToken(NewState one group, PreviousState 4 bytes): status=0x%08lX err=%s; ReturnLength %s",
         (unsigned long)st, le(), len == F2KT_UNTOUCHED ? "untouched" : "set");
    CloseHandle(token);
}

/* --- ntsetinfo ----------------------------------------------------------- */

static void sec_ntsetinfo(void)
{
    DWORD dummy = 0;
    HANDLE token = NULL;
    NTSTATUS st;

    if (!have("NtSetInformationToken", (void *)p_nt_set_info)
        || !have("NtOpenProcessToken", (void *)p_nt_open_token)) {
        return;
    }
    st = p_nt_open_token(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS
                                                  | TOKEN_ADJUST_DEFAULT, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), adjust access): status=0x%08lX, %s", (unsigned long)st,
         st >= 0 && token != NULL ? "a handle" : "no handle");
    if (st < 0 || token == NULL) {
        return;
    }
    arm();
    st = p_nt_set_info(token, 0xFFFF, &dummy, sizeof dummy);
    line("NtSetInformationToken(class 0xFFFF): status=0x%08lX err=%s", (unsigned long)st, le());
    arm();
    st = p_nt_set_info(token, NT_TI_TOKEN_USER, &dummy, 4);
    line("NtSetInformationToken(TokenUser, a 4-byte buffer): status=0x%08lX err=%s", (unsigned long)st, le());
    arm();
    st = p_nt_set_info(token, NT_TI_TOKEN_TYPE, &dummy, 4);
    line("NtSetInformationToken(TokenType, a read-only class): status=0x%08lX err=%s", (unsigned long)st, le());
    CloseHandle(token);
}

/* --- ntcreatefilter ------------------------------------------------------ */

static void sec_ntcreatefilter(void)
{
    HANDLE token = NULL, newh = NULL, h = NULL;
    NTSTATUS st;

    if (!have("NtCreateToken", (void *)p_nt_create_token) || !have("NtFilterToken", (void *)p_nt_filter_token)
        || !have("NtOpenProcessToken", (void *)p_nt_open_token)) {
        return;
    }
    h = NULL;
    arm();
    st = p_nt_create_token(&h, TOKEN_QUERY, NULL, 1 /* TokenPrimary */, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                           NULL, NULL);
    line("NtCreateToken(TOKEN_QUERY, no object attributes, all else NULL): status=0x%08lX err=%s, %s",
         (unsigned long)st, le(), st >= 0 && h != NULL ? "a handle" : "no handle");
    if (st >= 0 && h != NULL) {
        CloseHandle(h);
    }
    st = p_nt_open_token(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token);
    line("NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE): status=0x%08lX, %s",
         (unsigned long)st, st >= 0 && token != NULL ? "a handle" : "no handle");
    if (st < 0 || token == NULL) {
        return;
    }
    newh = NULL;
    arm();
    st = p_nt_filter_token(token, 0, NULL, NULL, NULL, &newh);
    line("NtFilterToken(flags 0, nothing disabled or restricted): status=0x%08lX err=%s, %s", (unsigned long)st, le(),
         st >= 0 && newh != NULL ? "a handle" : "no handle");
    if (st >= 0 && newh != NULL) {
        CloseHandle(newh);
    }
    CloseHandle(token);
}

/* --- ntthreadtok --------------------------------------------------------- */

static void sec_ntthreadtok(void)
{
    HANDLE tt = NULL;
    NTSTATUS st;

    if (!have("NtOpenThreadToken", (void *)p_nt_open_thread_token)) {
        return;
    }
    arm();
    st = p_nt_open_thread_token(GetCurrentThread(), TOKEN_QUERY, FALSE, &tt);
    line("NtOpenThreadToken(GetCurrentThread(), TOKEN_QUERY, OpenAsSelf=FALSE): status=0x%08lX err=%s, %s",
         (unsigned long)st, le(), st >= 0 && tt != NULL ? "a handle" : "no handle");
    if (st >= 0 && tt != NULL) {
        CloseHandle(tt);
    }
}

/* --- ntrtlpriv ----------------------------------------------------------- */

static void sec_ntrtlpriv(void)
{
    BOOLEAN prev = FALSE;
    NTSTATUS st;

    if (!have("RtlAdjustPrivilege", (void *)p_rtl_adjust_priv)) {
        return;
    }
    prev = FALSE;
    arm();
    st = p_rtl_adjust_priv(SHUTDOWN_LUID, TRUE, FALSE, &prev);
    line("RtlAdjustPrivilege(SeShutdownPrivilege, enable, the process): status=0x%08lX err=%s previous=%d",
         (unsigned long)st, le(), prev);
    prev = FALSE;
    arm();
    st = p_rtl_adjust_priv(SHUTDOWN_LUID, FALSE, FALSE, &prev);
    line("RtlAdjustPrivilege(SeShutdownPrivilege, disable, the process): status=0x%08lX err=%s previous=%d",
         (unsigned long)st, le(), prev);
    prev = FALSE;
    arm();
    st = p_rtl_adjust_priv(65536, TRUE, FALSE, &prev);
    line("RtlAdjustPrivilege(an unknown privilege, enable): status=0x%08lX err=%s previous=%d", (unsigned long)st,
         le(), prev);
}

/* --- main --------------------------------------------------------------- */

static const section_t sections[] = {
    { "ntaccesscheck", sec_ntaccesscheck, F2KT_ALWAYS },
    { "ntprivcheck", sec_ntprivcheck, F2KT_ALWAYS },
    { "ntquerysecobj", sec_ntquerysecobj, F2KT_ALWAYS },
    { "ntsetsecobj", sec_ntsetsecobj, F2KT_ALWAYS },
    { "createwithsd", sec_createwithsd, F2KT_ALWAYS },
    { "ntbytype", sec_ntbytype, F2KT_ALWAYS },
    { "ntgroups", sec_ntgroups, F2KT_ALWAYS },
    { "ntsetinfo", sec_ntsetinfo, F2KT_ALWAYS },
    { "ntcreatefilter", sec_ntcreatefilter, F2KT_ALWAYS },
    { "ntthreadtok", sec_ntthreadtok, F2KT_ALWAYS },
    { "ntrtlpriv", sec_ntrtlpriv, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    ntdll = GetModuleHandleA("ntdll.dll");
    p_nt_access_check = (nt_access_check_fn)GetProcAddress(ntdll, "NtAccessCheck");
    p_nt_priv_check = (nt_priv_check_fn)GetProcAddress(ntdll, "NtPrivilegeCheck");
    p_nt_query_sec = (nt_query_sec_fn)GetProcAddress(ntdll, "NtQuerySecurityObject");
    p_nt_set_sec = (nt_set_sec_fn)GetProcAddress(ntdll, "NtSetSecurityObject");
    p_nt_open_token = (nt_open_token_fn)GetProcAddress(ntdll, "NtOpenProcessToken");
    p_nt_query_token = (nt_query_token_fn)GetProcAddress(ntdll, "NtQueryInformationToken");
    p_nt_acbt = (nt_access_check_by_type_fn)GetProcAddress(ntdll, "NtAccessCheckByType");
    p_nt_acbtrl = (nt_access_check_by_type_fn)GetProcAddress(ntdll, "NtAccessCheckByTypeResultList");
    p_nt_adjust_groups = (nt_adjust_groups_fn)GetProcAddress(ntdll, "NtAdjustGroupsToken");
    p_nt_set_info = (nt_set_info_fn)GetProcAddress(ntdll, "NtSetInformationToken");
    p_nt_create_token = (nt_create_token_fn)GetProcAddress(ntdll, "NtCreateToken");
    p_nt_filter_token = (nt_filter_token_fn)GetProcAddress(ntdll, "NtFilterToken");
    p_nt_open_thread_token = (nt_open_thread_token_fn)GetProcAddress(ntdll, "NtOpenThreadToken");
    p_rtl_adjust_priv = (rtl_adjust_priv_fn)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    return run_sections("ntsvc", sections, argc, argv);
}
