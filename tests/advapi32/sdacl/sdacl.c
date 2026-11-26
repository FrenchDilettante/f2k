/*
 * sdacl - security descriptors, ACLs and SIDs as advapi32 builds and
 * inspects them: InitializeSecurityDescriptor with the queries over it
 * (IsValidSecurityDescriptor, GetSecurityDescriptorLength,
 * GetSecurityDescriptorControl), the ACL calls (InitializeAcl, IsValidAcl,
 * AddAce with GetAce readback, FindFirstFreeAce, DeleteAce), the allowed
 * and denied ACE builders, the SID calls (AllocateAndInitializeSid,
 * InitializeSid, the queries, EqualSid/EqualPrefixSid, CopySid, the
 * string forms A and W, CreateWellKnownSid, FreeSid), and the
 * self-relative conversion with the owner/group/DACL/SACL round trips.
 *
 * The advapi32 security calls go through GetProcAddress, so the program
 * loads where advapi32 lacks them: a section whose call is missing prints
 * "not found" and stops. Every call under observation is armed with the
 * last-error sentinel first, and a NULL the real machine may fault on is
 * called inside __try, so the fault's code prints instead.
 *
 * A SID prints in its string form (every SID here is one this program
 * built, so its numbers are its own); a mask prints in hex. Nothing
 * machine-specific prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   initsd      InitializeSecurityDescriptor on a sentinel buffer, the
 *               revision and control it leaves, IsValidSecurityDescriptor
 *               (initialized, a bad revision, NULL), GetSecurityDescriptor-
 *               Length (the header's size, NULL), GetSecurityDescriptor-
 *               Control (values, NULL)
 *   acl         InitializeAcl (sizes, revisions, NULL), IsValidAcl, AddAce
 *               (two ACEs, a wrong revision, one past the ACL's end),
 *               GetAce readback (index 0, past the end), FindFirstFreeAce
 *               (where it points), DeleteAce (0, past the end)
 *   allowedace  AddAccessAllowedAce (masks, a NULL SID, a full ACL) with
 *               GetAce readback of each ACE's mask and SID
 *   deniedace   AddAccessDeniedAce and the ACE order it leaves: a deny
 *               first then an allow, and the reverse, each read back
 *   sid         AllocateAndInitializeSid (S-1-5-32-544, S-1-5), the
 *               queries (GetLengthSid, IsValidSid), EqualSid,
 *               EqualPrefixSid both ways, CopySid (enough, too small),
 *               ConvertSidToStringSidA/W (the string, NULL),
 *               CreateWellKnownSid (a size query, builtin admins and
 *               world, an unknown type), InitializeSid, FreeSid
 *   selfrel     an absolute SD made by hand converted with
 *               MakeSelfRelativeSD (a size query, then the length), read
 *               back (self-relative flag, valid, length); then the
 *               Set/GetSecurityDescriptorOwner/Group/Dacl/Sacl round
 *               trips (set, read back, a NULL DACL cleared)
 *   trustee     the trustee builders and queries: BuildTrusteeWithName/
 *               Sid/ObjectsAndName/ObjectsAndSid A and W, BuildImpersonate-
 *               Trustee A/W, BuildImpersonateExplicitAccessWithName A/W,
 *               GetTrusteeForm/Name/Type A and W, each read back
 *   objace      the object and audit ACE builders: AddAccessAllowedObject-
 *               Ace, AddAccessDeniedObjectAce, AddAuditAccessAce(Ex),
 *               AddAuditAccessObjectAce, AddAccessAllowedAceEx,
 *               AddAccessDeniedAceEx, each read back with GetAce
 *   strsd       ConvertSecurityDescriptorToStringSecurityDescriptorA/W
 *               (the SDDL string, freed) and ConvertStringSecurity-
 *               DescriptorToSecurityDescriptorA/W back (a good string, a
 *               bad one, a bad revision), read back
 *   privobj     the private object security: CreatePrivateObjectSecurity
 *               (Ex), DestroyPrivateObjectSecurity, Get/SetPrivateObject-
 *               Security (Ex), ConvertToAutoInheritPrivateObjectSecurity
 *               over the process token, with read-backs
 *   sdcorner    SetSecurityDescriptorControl, Get/SetSecurityDescriptor-
 *               RMControl, RtlCopySecurityDescriptor (ntdll), BuildSecurity-
 *               DescriptorA/W, ConvertAccessToSecurityDescriptorA/W,
 *               ConvertSecurityDescriptorToAccess(A/W, Named A/W)
 *   saclaudit   a SACL built with AddAuditAccessAce, GetAuditedPermissions-
 *               FromAclA/W over a trustee, SetEntriesInAuditListA/W
 *   sidmore     EqualDomainSid, GetWindowsAccountDomainSid (the size only,
 *               never the domain SID), GetSiteSidFromToken, GetMangled-
 *               SiteSid, IsWellKnownSid, LookupAccountNameA/W and
 *               LookupAccountSidA/W for Everyone
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat sdacl):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% sdacl.c advapi32.lib
 */

#include "../common/f2kt.h"

/* --- the advapi32 security calls, through GetProcAddress ------------- */

typedef BOOL (WINAPI *init_sd_fn)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *valid_sd_fn)(PSECURITY_DESCRIPTOR);
typedef DWORD (WINAPI *sd_len_fn)(PSECURITY_DESCRIPTOR);
typedef BOOL (WINAPI *sd_control_fn)(PSECURITY_DESCRIPTOR, unsigned short *, PULONG);
typedef BOOL (WINAPI *init_acl_fn)(PACL, DWORD, DWORD);
typedef BOOL (WINAPI *valid_acl_fn)(PACL);
typedef BOOL (WINAPI *add_ace_fn)(PACL, DWORD, DWORD, PVOID, DWORD);
typedef BOOL (WINAPI *get_ace_fn)(PACL, DWORD, LPVOID *);
typedef BOOL (WINAPI *find_free_ace_fn)(PACL, LPVOID *, DWORD);
typedef BOOL (WINAPI *del_ace_fn)(PACL, DWORD);
typedef BOOL (WINAPI *add_allowed_ace_fn)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *add_denied_ace_fn)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *alloc_sid_fn)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD,
                                    DWORD, DWORD, DWORD, PSID *);
typedef BOOL (WINAPI *init_sid_fn)(PSID, PSID_IDENTIFIER_AUTHORITY, BYTE);
typedef DWORD (WINAPI *len_sid_fn)(PSID);
typedef BOOL (WINAPI *valid_sid_fn)(PSID);
typedef BOOL (WINAPI *equal_sid_fn)(PSID, PSID);
typedef BOOL (WINAPI *equal_prefix_sid_fn)(PSID, PSID);
typedef DWORD (WINAPI *copy_sid_fn)(DWORD, PSID, PSID);
typedef BOOL (WINAPI *sid_to_str_a_fn)(PSID, LPSTR *);
typedef BOOL (WINAPI *sid_to_str_w_fn)(PSID, LPWSTR *);
typedef BOOL (WINAPI *create_wk_sid_fn)(DWORD, PSID, PSID, DWORD *);
typedef PVOID (WINAPI *free_sid_fn)(PSID);
typedef BOOL (WINAPI *make_self_rel_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG);
typedef BOOL (WINAPI *get_dacl_fn)(PSECURITY_DESCRIPTOR, LPBOOL, PACL *, LPBOOL);
typedef BOOL (WINAPI *set_dacl_fn)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef BOOL (WINAPI *get_owner_fn)(PSECURITY_DESCRIPTOR, PSID *, LPBOOL);
typedef BOOL (WINAPI *set_owner_fn)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *get_group_fn)(PSECURITY_DESCRIPTOR, PSID *, LPBOOL);
typedef BOOL (WINAPI *set_group_fn)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *get_sacl_fn)(PSECURITY_DESCRIPTOR, LPBOOL, PACL *, LPBOOL);
typedef BOOL (WINAPI *set_sacl_fn)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);

/* --- the trustee, explicit-access and accctrl layouts, declared here --- */
/* A GUID as the object-ACE and trustee calls take it (16 bytes, the layout
 * is public). */
typedef struct {
    DWORD data1;
    WORD data2;
    WORD data3;
    BYTE data4[8];
} f2kt_guid_t;

/* The trustee structure (the layout is public; the union is one pointer
 * here: the name, the SID, or the objects pointer, by the form). */
typedef struct f2kt_trustee {
    struct f2kt_trustee *pMultipleTrustee;
    int MultipleTrusteeOperation;
    int TrusteeForm;
    int TrusteeType;
    void *ptstrName;
} f2kt_trustee_t;

/* An explicit access entry (the layout is public). */
typedef struct {
    DWORD grfAccessPermissions;
    int grfAccessMode;
    DWORD grfInheritance;
    f2kt_trustee_t Trustee;
} f2kt_explicit_access_t;

/* The objects-and-SID / objects-and-name structures (the layouts are
 * public; the name one is declared at its widest, GUIDs included). */
typedef struct {
    DWORD ObjectsPresent;
    f2kt_guid_t ObjectTypeGuid;
    f2kt_guid_t InheritedObjectTypeGuid;
    PSID pSid;
} f2kt_objects_and_sid_t;

typedef struct {
    DWORD ObjectsPresent;
    f2kt_guid_t ObjectTypeGuid;
    f2kt_guid_t InheritedObjectTypeGuid;
    LPSTR pObjectTypeName;
    LPSTR pInheritedObjectTypeName;
    LPSTR ptstrName;
} f2kt_objects_and_name_t;

/* An accctrl access entry and an accctrl access/audit list (the layouts
 * are public). */
typedef struct {
    f2kt_trustee_t Trustee;
    ULONG fAccessFlags;
    ULONG Access;
    ULONG ProvSpecificAccess;
    ULONG Inheritance;
    void *lpInheritProperty;
} f2kt_actrl_entry_t;

typedef struct {
    ULONG cEntries;
    f2kt_actrl_entry_t *pAccessEntryList;
} f2kt_actrl_list_t;

/* The trustee builders and queries (public signatures; the A and W forms
 * share the shape, the string parameters passing as void *). */
typedef void (WINAPI *bt_name_fn)(f2kt_trustee_t *, void *);
typedef void (WINAPI *bt_sid_fn)(f2kt_trustee_t *, PSID);
typedef void (WINAPI *bt_objsid_fn)(f2kt_trustee_t *, f2kt_objects_and_sid_t *, f2kt_guid_t *, f2kt_guid_t *,
                                    PSID);
typedef void (WINAPI *bt_objname_fn)(f2kt_trustee_t *, f2kt_objects_and_name_t *, int, void *, void *, void *);
typedef void (WINAPI *bt_imp_fn)(f2kt_trustee_t *, f2kt_trustee_t *);
typedef void (WINAPI *bt_imp_ea_fn)(f2kt_explicit_access_t *, void *, f2kt_trustee_t *, DWORD, int, DWORD);
typedef DWORD (WINAPI *gt_form_fn)(f2kt_trustee_t *);
typedef void *(WINAPI *gt_name_fn)(f2kt_trustee_t *);
typedef DWORD (WINAPI *gt_type_fn)(f2kt_trustee_t *);

/* The object and audit ACE builders (public signatures). */
typedef BOOL (WINAPI *add_obj_ace_fn)(PACL, DWORD, DWORD, DWORD, f2kt_guid_t *, f2kt_guid_t *, PSID);
typedef BOOL (WINAPI *add_audit_ace_fn)(PACL, DWORD, DWORD, PSID, BOOL, BOOL);
typedef BOOL (WINAPI *add_audit_ace_ex_fn)(PACL, DWORD, DWORD, DWORD, PSID, BOOL, BOOL);
typedef BOOL (WINAPI *add_audit_obj_ace_fn)(PACL, DWORD, DWORD, DWORD, f2kt_guid_t *, f2kt_guid_t *, PSID,
                                            BOOL, BOOL);
typedef BOOL (WINAPI *add_ace_ex_fn)(PACL, DWORD, DWORD, DWORD, PSID);

/* The string security descriptor conversions (public signatures). */
typedef BOOL (WINAPI *sd_to_str_a_fn)(PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION, LPSTR *, PULONG);
typedef BOOL (WINAPI *sd_to_str_w_fn)(PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION, LPWSTR *, PULONG);
typedef BOOL (WINAPI *str_to_sd_a_fn)(LPCSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);
typedef BOOL (WINAPI *str_to_sd_w_fn)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);

/* The private object security calls (public signatures). */
typedef BOOL (WINAPI *open_process_token_fn)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *create_priv_obj_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                          BOOL, HANDLE, PGENERIC_MAPPING);
typedef BOOL (WINAPI *create_priv_obj_ex_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                             f2kt_guid_t *, BOOL, ULONG, HANDLE, PGENERIC_MAPPING);
typedef BOOL (WINAPI *destroy_priv_obj_fn)(PSECURITY_DESCRIPTOR *);
typedef BOOL (WINAPI *get_priv_obj_fn)(PSECURITY_DESCRIPTOR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD,
                                       PDWORD);
typedef BOOL (WINAPI *set_priv_obj_fn)(SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                       PGENERIC_MAPPING, HANDLE);
typedef BOOL (WINAPI *set_priv_obj_ex_fn)(SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                          ULONG, PGENERIC_MAPPING, HANDLE);
typedef BOOL (WINAPI *convert_auto_inherit_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR,
                                               PSECURITY_DESCRIPTOR *, f2kt_guid_t *, BOOL, PGENERIC_MAPPING);

/* The remaining SD corners (public signatures). */
typedef BOOL (WINAPI *set_sd_control_fn)(PSECURITY_DESCRIPTOR, unsigned short, unsigned short);
typedef DWORD (WINAPI *get_rm_fn)(PSECURITY_DESCRIPTOR, PUCHAR);
typedef DWORD (WINAPI *set_rm_fn)(PSECURITY_DESCRIPTOR, PUCHAR);
typedef DWORD (WINAPI *build_sd_fn)(f2kt_trustee_t *, f2kt_trustee_t *, ULONG, f2kt_explicit_access_t *, ULONG,
                                    f2kt_explicit_access_t *, PSECURITY_DESCRIPTOR, PULONG,
                                    PSECURITY_DESCRIPTOR *);
typedef DWORD (WINAPI *conv_access_to_sd_fn)(f2kt_actrl_list_t *, f2kt_actrl_list_t *, const void *,
                                             const void *, PSECURITY_DESCRIPTOR *);
typedef DWORD (WINAPI *conv_sd_to_access_fn)(HANDLE, int, PSECURITY_DESCRIPTOR, f2kt_actrl_list_t **,
                                             f2kt_actrl_list_t **, void *, void *);
typedef DWORD (WINAPI *conv_sd_to_access_named_fn)(const void *, int, PSECURITY_DESCRIPTOR, f2kt_actrl_list_t **,
                                                   f2kt_actrl_list_t **, void *, void *);

/* The ACL audit queries (public signatures). */
typedef DWORD (WINAPI *get_audited_perms_fn)(PACL, f2kt_trustee_t *, PACCESS_MASK, PACCESS_MASK);
typedef DWORD (WINAPI *set_entries_audit_a_fn)(ULONG, f2kt_actrl_entry_t *, int, LPCSTR, f2kt_actrl_list_t *,
                                               f2kt_actrl_list_t **);
typedef DWORD (WINAPI *set_entries_audit_w_fn)(ULONG, f2kt_actrl_entry_t *, int, LPCWSTR, f2kt_actrl_list_t *,
                                               f2kt_actrl_list_t **);

/* The remaining SID calls (public signatures). */
typedef BOOL (WINAPI *equal_domain_sid_fn)(PSID, PSID, LPBOOL);
typedef BOOL (WINAPI *get_windows_domain_fn)(PSID, PSID, DWORD *);
typedef DWORD (WINAPI *get_site_sid_token_fn)(HANDLE, PSID *);
typedef DWORD (WINAPI *get_mangled_site_fn)(PSID, PSID *);
typedef BOOL (WINAPI *is_well_known_fn)(PSID, DWORD);
typedef BOOL (WINAPI *lookup_account_name_a_fn)(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, DWORD *);
typedef BOOL (WINAPI *lookup_account_name_w_fn)(LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, DWORD *);
typedef BOOL (WINAPI *lookup_account_sid_a_fn)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, DWORD *);
typedef BOOL (WINAPI *lookup_account_sid_w_fn)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, DWORD *);

/* ntdll's copy of the security descriptor (public signature). */
typedef LONG (WINAPI *rtl_copy_sd_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR);

static init_sd_fn p_init_sd;
static valid_sd_fn p_valid_sd;
static sd_len_fn p_sd_len;
static sd_control_fn p_sd_control;
static init_acl_fn p_init_acl;
static valid_acl_fn p_valid_acl;
static add_ace_fn p_add_ace;
static get_ace_fn p_get_ace;
static find_free_ace_fn p_find_free;
static del_ace_fn p_del_ace;
static add_allowed_ace_fn p_add_allowed;
static add_denied_ace_fn p_add_denied;
static alloc_sid_fn p_alloc_sid;
static init_sid_fn p_init_sid;
static len_sid_fn p_len_sid;
static valid_sid_fn p_valid_sid;
static equal_sid_fn p_equal_sid;
static equal_prefix_sid_fn p_equal_prefix;
static copy_sid_fn p_copy_sid;
static sid_to_str_a_fn p_sid_str_a;
static sid_to_str_w_fn p_sid_str_w;
static create_wk_sid_fn p_wk_sid;
static free_sid_fn p_free_sid;
static make_self_rel_fn p_self_rel;
static get_dacl_fn p_get_dacl;
static set_dacl_fn p_set_dacl;
static get_owner_fn p_get_owner;
static set_owner_fn p_set_owner;
static get_group_fn p_get_group;
static set_group_fn p_set_group;
static get_sacl_fn p_get_sacl;
static set_sacl_fn p_set_sacl;

static bt_name_fn p_bt_name_a, p_bt_name_w;
static bt_sid_fn p_bt_sid_a, p_bt_sid_w;
static bt_objsid_fn p_bt_objsid_a, p_bt_objsid_w;
static bt_objname_fn p_bt_objname_a, p_bt_objname_w;
static bt_imp_fn p_bt_imp_a, p_bt_imp_w;
static bt_imp_ea_fn p_bt_imp_ea_a, p_bt_imp_ea_w;
static gt_form_fn p_gt_form_a, p_gt_form_w;
static gt_name_fn p_gt_name_a, p_gt_name_w;
static gt_type_fn p_gt_type_a, p_gt_type_w;

static add_obj_ace_fn p_add_allowed_obj;
static add_obj_ace_fn p_add_denied_obj;
static add_audit_ace_fn p_add_audit;
static add_audit_ace_ex_fn p_add_audit_ex;
static add_audit_obj_ace_fn p_add_audit_obj;
static add_ace_ex_fn p_add_allowed_ex;
static add_ace_ex_fn p_add_denied_ex;

static sd_to_str_a_fn p_sd_str_a;
static sd_to_str_w_fn p_sd_str_w;
static str_to_sd_a_fn p_str_sd_a;
static str_to_sd_w_fn p_str_sd_w;

static open_process_token_fn p_open_token;
static create_priv_obj_fn p_create_priv;
static create_priv_obj_ex_fn p_create_priv_ex;
static destroy_priv_obj_fn p_destroy_priv;
static get_priv_obj_fn p_get_priv;
static set_priv_obj_fn p_set_priv;
static set_priv_obj_ex_fn p_set_priv_ex;
static convert_auto_inherit_fn p_convert_auto;

static set_sd_control_fn p_set_sd_ctrl;
static get_rm_fn p_get_rm;
static set_rm_fn p_set_rm;
static build_sd_fn p_build_sd_a, p_build_sd_w;
static conv_access_to_sd_fn p_conv_acc_sd_a, p_conv_acc_sd_w;
static conv_sd_to_access_fn p_conv_sd_acc_a, p_conv_sd_acc_w;
static conv_sd_to_access_named_fn p_conv_sd_acc_named_a, p_conv_sd_acc_named_w;

static get_audited_perms_fn p_get_audited_a;
static get_audited_perms_fn p_get_audited_w;
static set_entries_audit_a_fn p_set_audit_a;
static set_entries_audit_w_fn p_set_audit_w;

static equal_domain_sid_fn p_equal_domain;
static get_windows_domain_fn p_get_win_domain;
static get_site_sid_token_fn p_get_site_token;
static get_mangled_site_fn p_get_mangled;
static is_well_known_fn p_is_wk;
static lookup_account_name_a_fn p_lookup_name_a;
static lookup_account_name_w_fn p_lookup_name_w;
static lookup_account_sid_a_fn p_lookup_sid_a;
static lookup_account_sid_w_fn p_lookup_sid_w;

static rtl_copy_sd_fn p_rtl_copy_sd;

static HMODULE adv;
static HMODULE ntdll;

/* --- buffers and helpers ---------------------------------------------- */

static ULONG sd_buf[512];               /* 2 KiB, aligned for the structures */
static ULONG rel_buf[512];              /* 2 KiB */
static ULONG acl_buf[256];              /* 1 KiB */
static ULONG ace_buf[64];               /* one ACE and a SID */
static ULONG sid_buf[64];               /* one SID */

/* The well-known SIDs this program builds by hand (the layout is
 * public): S-1-1-0, S-1-5-18, S-1-5-32-544, S-1-5-32, S-1-5. */
typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid5_t sid_system = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
static const sid5_t sid_admins = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };
static const sid5_t sid_builtin = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 32 } };

static DWORD sid_size(const void *sid)
{
    return 8 + 4 * (DWORD)((const BYTE *)sid)[1];
}

/* A SID as printed: its string form, every SID here being one this
 * program built. */
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
 * the MSVC 6 headers, so the header's fields are read at their public
 * offsets. */
static unsigned sd_control(const void *sd)
{
    return *(const unsigned short *)((const BYTE *)sd + 2);
}

/* Whether an export is there: a section whose call is missing prints
 * "not found" and stops. */
static int have(const char *name, void *p)
{
    if (p == NULL) {
        line("%s not found", name);
        return 0;
    }
    return 1;
}

/* Calls the real machine may fault on, each inside __try with its own
 * prototype: the return and the error, or the fault's code. */
static BOOL t_valid_sd(PSECURITY_DESCRIPTOR sd, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_valid_sd(sd);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static BOOL t_init_sd(PSECURITY_DESCRIPTOR sd, DWORD rev, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_init_sd(sd, rev);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static DWORD t_sd_len(PSECURITY_DESCRIPTOR sd, DWORD *err, DWORD *code)
{
    DWORD ret = 0;

    *code = 0;
    arm();
    __try {
        ret = p_sd_len(sd);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return ret;
}

static BOOL t_sd_control(PSECURITY_DESCRIPTOR sd, unsigned short *control, ULONG *revision, DWORD *err,
                         DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_sd_control(sd, control, revision);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static BOOL t_init_acl(PACL acl, DWORD size, DWORD rev, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_init_acl(acl, size, rev);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static BOOL t_valid_acl(PACL acl, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_valid_acl(acl);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static BOOL t_add_allowed(PACL acl, DWORD rev, DWORD mask, PSID sid, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_add_allowed(acl, rev, mask, sid);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static BOOL t_add_denied(PACL acl, DWORD rev, DWORD mask, PSID sid, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_add_denied(acl, rev, mask, sid);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

static BOOL t_sid_str_a(PSID sid, LPSTR *str, DWORD *err, DWORD *code, BOOL *ret)
{
    *code = 0;
    *ret = FALSE;
    arm();
    __try {
        *ret = p_sid_str_a(sid, str);
        *err = GetLastError();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        *err = F2KT_UNTOUCHED;
    }
    return TRUE;
}

/* One line for a __try call: faulted, or ret/err. */
static void show_tried(const char *label, BOOL ret, DWORD err, DWORD code)
{
    if (code != 0) {
        line("%s: faulted 0x%08lX", label, code);
    } else {
        line("%s: ret=%d err=%s", label, ret, le_of(err));
    }
}

/* --- initsd ------------------------------------------------------------ */

static void sec_initsd(void)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    unsigned short control;
    ULONG revision, len;
    BOOL r, ret;
    DWORD err, code;

    if (!have("InitializeSecurityDescriptor", (void *)p_init_sd)
        || !have("IsValidSecurityDescriptor", (void *)p_valid_sd)
        || !have("GetSecurityDescriptorLength", (void *)p_sd_len)
        || !have("GetSecurityDescriptorControl", (void *)p_sd_control)) {
        return;
    }
    memset(sd_buf, 0xCC, sizeof sd_buf);
    arm();
    r = p_init_sd(sd, SECURITY_DESCRIPTOR_REVISION);
    line("InitializeSecurityDescriptor(REVISION): ret=%d err=%s", r, le());
    line("  Revision %u, Control 0x%04X", (unsigned)((BYTE *)sd)[0], sd_control(sd));
    arm();
    r = p_valid_sd(sd);
    line("IsValidSecurityDescriptor(initialized): ret=%d err=%s", r, le());
    arm();
    len = p_sd_len(sd);
    line("GetSecurityDescriptorLength: ret=%lu err=%s; the header alone: %s", len, le(), yesno(len == 20));
    control = 0xCC;
    revision = F2KT_UNTOUCHED;
    arm();
    r = p_sd_control(sd, &control, &revision);
    line("GetSecurityDescriptorControl: ret=%d err=%s control=0x%04X revision=%s", r, le(),
         (unsigned)control, revision == F2KT_UNTOUCHED ? "untouched" : "set");
    if (revision != F2KT_UNTOUCHED) {
        line("  revision %lu, the revision given: %s", revision, yesno(revision == SECURITY_DESCRIPTOR_REVISION));
    }

    ((BYTE *)sd)[0] = 0x99;             /* a revision no SD has */
    arm();
    r = p_valid_sd(sd);
    line("IsValidSecurityDescriptor(revision 0x99): ret=%d err=%s", r, le());
    ((BYTE *)sd)[0] = 1;

    t_valid_sd(NULL, &err, &code, &ret);
    show_tried("IsValidSecurityDescriptor(NULL)", ret, err, code);
    t_init_sd(NULL, SECURITY_DESCRIPTOR_REVISION, &err, &code, &ret);
    show_tried("InitializeSecurityDescriptor(NULL, REVISION)", ret, err, code);
    len = t_sd_len(NULL, &err, &code);
    if (code != 0) {
        line("GetSecurityDescriptorLength(NULL): faulted 0x%08lX", code);
    } else {
        line("GetSecurityDescriptorLength(NULL): ret=%lu err=%s", len, le_of(err));
    }
    control = 0xCC;
    revision = F2KT_UNTOUCHED;
    t_sd_control(NULL, &control, &revision, &err, &code, &ret);
    show_tried("GetSecurityDescriptorControl(NULL)", ret, err, code);
}

/* --- ACL helpers ------------------------------------------------------- */

/* An allowed ACE in ace_buf for `sid` with `mask`. */
static DWORD make_allowed_ace(DWORD mask, const void *sid)
{
    ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)ace_buf;
    DWORD size = sid_size(sid);

    memset(ace_buf, 0, sizeof ace_buf);
    ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace->Header.AceFlags = 0;
    ace->Header.AceSize = (unsigned short)(sizeof(ACCESS_ALLOWED_ACE) + size);
    ace->Mask = mask;
    memcpy(&ace->SidStart, sid, size);
    return sizeof(ACCESS_ALLOWED_ACE) + size;
}

/* The ACEs of acl_buf, read back one per line. */
static void show_aces(const char *label)
{
    PACL acl = (PACL)acl_buf;
    LPVOID p;
    DWORD i;
    BOOL r;

    line("%s: AceCount %u, AclSize %u", label, (unsigned)acl->AceCount, (unsigned)acl->AclSize);
    for (i = 0; i < acl->AceCount && i < 8; i++) {
        p = NULL;
        arm();
        r = p_get_ace(acl, i, &p);
        if (r && p != NULL) {
            ACE_HEADER *h = (ACE_HEADER *)p;
            if (h->AceType == ACCESS_ALLOWED_ACE_TYPE || h->AceType == ACCESS_DENIED_ACE_TYPE) {
                line("  ACE %lu: GetAce ret=%d err=%s; type %u, flags 0x%X, mask 0x%08lX, sid %s", i, r, le(),
                     (unsigned)h->AceType, (unsigned)h->AceFlags, ((ACCESS_ALLOWED_ACE *)p)->Mask,
                     sid_text(&((ACCESS_ALLOWED_ACE *)p)->SidStart));
            } else {
                line("  ACE %lu: GetAce ret=%d err=%s; type %u, size %u", i, r, le(), (unsigned)h->AceType,
                     (unsigned)h->AceSize);
            }
        } else {
            line("  ACE %lu: GetAce ret=%d err=%s", i, r, le());
        }
    }
}

/* --- acl --------------------------------------------------------------- */

static void sec_acl(void)
{
    PACL acl = (PACL)acl_buf;
    LPVOID p;
    DWORD ace_size;
    BOOL r, ret;
    DWORD err, code;

    if (!have("InitializeAcl", (void *)p_init_acl) || !have("IsValidAcl", (void *)p_valid_acl)
        || !have("AddAce", (void *)p_add_ace) || !have("GetAce", (void *)p_get_ace)
        || !have("FindFirstFreeAce", (void *)p_find_free) || !have("DeleteAce", (void *)p_del_ace)) {
        return;
    }
    memset(acl_buf, 0xCC, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl(1024, ACL_REVISION): ret=%d err=%s", r, le());
    line("  AclRevision %u, AclSize %u, AceCount %u; AclSize the size given: %s",
         (unsigned)acl->AclRevision, (unsigned)acl->AclSize, (unsigned)acl->AceCount,
         yesno(acl->AclSize == sizeof acl_buf));
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl(empty): ret=%d err=%s", r, le());

    ace_size = make_allowed_ace(0x00000001, &sid_everyone);
    arm();
    r = p_add_ace(acl, ACL_REVISION, MAXDWORD, ace_buf, ace_size);
    line("AddAce(allowed, Everyone, mask 1): ret=%d err=%s; AceCount now %u", r, le(), (unsigned)acl->AceCount);
    ace_size = make_allowed_ace(0x00000002, &sid_system);
    arm();
    r = p_add_ace(acl, ACL_REVISION, MAXDWORD, ace_buf, ace_size);
    line("AddAce(allowed, SYSTEM, mask 2): ret=%d err=%s; AceCount now %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl(two ACEs): ret=%d err=%s", r, le());
    show_aces("after two AddAce");

    p = NULL;
    arm();
    r = p_get_ace(acl, 2, &p);
    line("GetAce(index 2, past the end): ret=%d err=%s, the ACE pointer %s", r, le(), p == NULL ? "NULL" : "set");
    p = NULL;
    arm();
    r = p_find_free(acl, &p, 0);
    line("FindFirstFreeAce: ret=%d err=%s; it points at the ACL's end: %s", r, le(),
         yesno(r && p != NULL && (BYTE *)p == (BYTE *)acl + acl->AclSize));

    arm();
    r = p_del_ace(acl, 0);
    line("DeleteAce(0): ret=%d err=%s; AceCount now %u", r, le(), (unsigned)acl->AceCount);
    show_aces("after DeleteAce(0)");
    arm();
    r = p_del_ace(acl, 5);
    line("DeleteAce(5, past the end): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);

    ace_size = make_allowed_ace(0x00000004, &sid_everyone);
    arm();
    r = p_add_ace(acl, ACL_REVISION + 1, MAXDWORD, ace_buf, ace_size);
    line("AddAce(a wrong revision): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);

    /* An ACL that fits exactly one ACE: the next AddAce has no room. */
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, 8 + sizeof(ACCESS_ALLOWED_ACE) + sid_size(&sid_everyone), ACL_REVISION);
    line("InitializeAcl(exactly one ACE): ret=%d err=%s; AclSize %u", r, le(), (unsigned)acl->AclSize);
    ace_size = make_allowed_ace(0x00000008, &sid_everyone);
    arm();
    r = p_add_ace(acl, ACL_REVISION, MAXDWORD, ace_buf, ace_size);
    line("AddAce(the one that fits): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_ace(acl, ACL_REVISION, MAXDWORD, ace_buf, ace_size);
    line("AddAce(one past that): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);

    arm();
    r = p_init_acl(acl, 4, ACL_REVISION);
    line("InitializeAcl(a 4-byte ACL): ret=%d err=%s", r, le());
    arm();
    r = p_init_acl(acl, sizeof acl_buf, 9);
    line("InitializeAcl(revision 9): ret=%d err=%s", r, le());
    t_init_acl(NULL, sizeof acl_buf, ACL_REVISION, &err, &code, &ret);
    show_tried("InitializeAcl(NULL, ...)", ret, err, code);
    t_valid_acl(NULL, &err, &code, &ret);
    show_tried("IsValidAcl(NULL)", ret, err, code);
    ((BYTE *)acl)[0] = 9;               /* a revision no ACL has */
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl(revision 9): ret=%d err=%s", r, le());
}

/* --- allowedace --------------------------------------------------------- */

static void sec_allowedace(void)
{
    PACL acl = (PACL)acl_buf;
    BOOL r, ret;
    DWORD err, code;

    if (!have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("GetAce", (void *)p_get_ace) || !have("IsValidAcl", (void *)p_valid_acl)) {
        return;
    }
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl(1024, ACL_REVISION): ret=%d err=%s", r, le());
    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0x000F01FF, (PSID)&sid_everyone);
    line("AddAccessAllowedAce(Everyone, 0x000F01FF): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0x00000001, (PSID)&sid_system);
    line("AddAccessAllowedAce(SYSTEM, 1): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl: ret=%d err=%s", r, le());
    show_aces("allowed ACEs");

    t_add_allowed(acl, ACL_REVISION, 0x00000002, NULL, &err, &code, &ret);
    show_tried("AddAccessAllowedAce(a NULL SID)", ret, err, code);
    line("  AceCount %u", (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed(acl, 9, 0x00000004, (PSID)&sid_everyone);
    line("AddAccessAllowedAce(revision 9): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);

    /* An ACL that fits exactly one allowed ACE: the next has no room. */
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, 8 + sizeof(ACCESS_ALLOWED_ACE) + sid_size(&sid_everyone), ACL_REVISION);
    line("InitializeAcl(exactly one allowed ACE): ret=%d err=%s; AclSize %u", r, le(), (unsigned)acl->AclSize);
    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0x00000001, (PSID)&sid_everyone);
    line("AddAccessAllowedAce(the one that fits): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0x00000002, (PSID)&sid_everyone);
    line("AddAccessAllowedAce(one past that): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
}

/* --- deniedace ---------------------------------------------------------- */

static void sec_deniedace(void)
{
    PACL acl = (PACL)acl_buf;
    BOOL r, ret;
    DWORD err, code;

    if (!have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("AddAccessDeniedAce", (void *)p_add_denied) || !have("GetAce", (void *)p_get_ace)
        || !have("IsValidAcl", (void *)p_valid_acl)) {
        return;
    }
    /* A deny ACE first, then an allow: the order the ACL keeps. */
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl(1024, ACL_REVISION): ret=%d err=%s", r, le());
    arm();
    r = p_add_denied(acl, ACL_REVISION, 0x000F01FF, (PSID)&sid_system);
    line("AddAccessDeniedAce(SYSTEM, 0x000F01FF) first: ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0xFFFFFFFF, (PSID)&sid_everyone);
    line("AddAccessAllowedAce(Everyone, all) second: ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    show_aces("deny first, then allow");
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl: ret=%d err=%s", r, le());

    /* The reverse: an allow first, then a deny. */
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl again: ret=%d err=%s", r, le());
    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0xFFFFFFFF, (PSID)&sid_everyone);
    line("AddAccessAllowedAce(Everyone, all) first: ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_denied(acl, ACL_REVISION, 0x00000001, (PSID)&sid_system);
    line("AddAccessDeniedAce(SYSTEM, 1) second: ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    show_aces("allow first, then deny");

    /* A deny ACE alone. */
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl(deny only): ret=%d err=%s", r, le());
    arm();
    r = p_add_denied(acl, ACL_REVISION, 0x00000010, (PSID)&sid_admins);
    line("AddAccessDeniedAce(BUILTIN\\Administrators, 0x10): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl(deny only): ret=%d err=%s", r, le());
    show_aces("deny only");
    t_add_denied(acl, ACL_REVISION, 0x00000020, NULL, &err, &code, &ret);
    show_tried("AddAccessDeniedAce(a NULL SID)", ret, err, code);
    line("  AceCount %u", (unsigned)acl->AceCount);
}

/* --- sid ---------------------------------------------------------------- */

/* The well-known SID types CreateWellKnownSid takes (public values). */
#define WK_WORLD 1
#define WK_INTERACTIVE 11
#define WK_AUTHENTICATED_USERS 17
#define WK_LOCAL_SYSTEM 22
#define WK_BUILTIN_ADMINS 26
#define WK_BUILTIN_USERS 27

static void sec_sid(void)
{
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL, bare = NULL;
    sid5_t prefix, hand;
    LPSTR str_a;
    LPWSTR str_w;
    DWORD len, r32, e, err, code;
    BOOL r, ret;
    PVOID freed;

    if (!have("AllocateAndInitializeSid", (void *)p_alloc_sid) || !have("GetLengthSid", (void *)p_len_sid)
        || !have("IsValidSid", (void *)p_valid_sid) || !have("EqualSid", (void *)p_equal_sid)
        || !have("EqualPrefixSid", (void *)p_equal_prefix) || !have("CopySid", (void *)p_copy_sid)
        || !have("ConvertSidToStringSidA", (void *)p_sid_str_a)
        || !have("ConvertSidToStringSidW", (void *)p_sid_str_w)
        || !have("CreateWellKnownSid", (void *)p_wk_sid) || !have("InitializeSid", (void *)p_init_sid)
        || !have("FreeSid", (void *)p_free_sid)) {
        return;
    }
    arm();
    r = p_alloc_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &admins);
    line("AllocateAndInitializeSid(S-1-5-32-544): ret=%d err=%s; the bytes of the hand-built SID: %s",
         r, le(), yesno(r && admins != NULL && memcmp(admins, &sid_admins, 16) == 0));
    if (r && admins != NULL) {
        arm();
        len = p_len_sid(admins);
        line("GetLengthSid: ret=%lu err=%s; 16: %s", len, le(), yesno(len == 16));
        arm();
        r = p_valid_sid(admins);
        line("IsValidSid: ret=%d err=%s", r, le());
        arm();
        r = p_equal_sid(admins, (PSID)&sid_admins);
        line("EqualSid(it, the hand-built): ret=%d err=%s", r, le());
        arm();
        r = p_equal_sid(admins, (PSID)&sid_everyone);
        line("EqualSid(it, Everyone): ret=%d err=%s", r, le());

        prefix = sid_builtin;           /* S-1-5-32: a prefix of the admins SID */
        arm();
        r = p_equal_prefix(admins, (PSID)&prefix);
        line("EqualPrefixSid(it, S-1-5-32): ret=%d err=%s", r, le());
        arm();
        r = p_equal_prefix((PSID)&prefix, admins);
        line("EqualPrefixSid(S-1-5-32, it): ret=%d err=%s", r, le());
        arm();
        r = p_equal_prefix(admins, admins);
        line("EqualPrefixSid(it, itself): ret=%d err=%s", r, le());

        memset(sid_buf, 0xCC, sizeof sid_buf);
        arm();
        r32 = p_copy_sid(sizeof sid_buf, (PSID)sid_buf, admins);
        line("CopySid(256, ...): ret=%lu err=%s; the copy the same: %s", r32, le(),
             yesno(r32 != 0 && memcmp(sid_buf, admins, 16) == 0));
        arm();
        r32 = p_copy_sid(4, (PSID)sid_buf, admins);
        line("CopySid(4, ...): ret=%lu err=%s", r32, le());

        str_a = NULL;
        arm();
        r = p_sid_str_a(admins, &str_a);
        line("ConvertSidToStringSidA: ret=%d err=%s string=%s", r, le(), r && str_a != NULL ? str_a : "(none)");
        str_w = NULL;
        arm();
        r = p_sid_str_w(admins, &str_w);
        line("ConvertSidToStringSidW: ret=%d err=%s string=%s", r, le(), r && str_w != NULL ? ws(str_w) : "(none)");
        t_sid_str_a(NULL, &str_a, &err, &code, &ret);
        show_tried("ConvertSidToStringSidA(NULL)", ret, err, code);

        arm();
        freed = p_free_sid(admins);
        e = GetLastError();
        line("FreeSid(it): returned NULL: %s err=%s", yesno(freed == NULL), le_of(e));
        admins = NULL;
    }

    /* S-1-5 with no sub-authorities. */
    arm();
    r = p_alloc_sid(&nt, 0, 0, 0, 0, 0, 0, 0, 0, 0, &bare);
    line("AllocateAndInitializeSid(S-1-5): ret=%d err=%s; %s", r, le(),
         r && bare != NULL ? sid_text(bare) : "-");
    if (r && bare != NULL) {
        arm();
        freed = p_free_sid(bare);
        line("FreeSid(S-1-5): returned NULL: %s err=%s", yesno(freed == NULL), le());
    }

    /* CreateWellKnownSid: a size query, then built. */
    len = 0;
    arm();
    r = p_wk_sid(WK_BUILTIN_ADMINS, NULL, sid_buf, &len);
    line("CreateWellKnownSid(BuiltinAdministrators, no buffer): ret=%d err=%s; the size it asks %s",
         r, le(), len == 0 ? "unset" : "set");
    if (len != 0) {
        line("  the size asked %lu, 16: %s", len, yesno(len == 16));
    }
    len = sizeof sid_buf;
    arm();
    r = p_wk_sid(WK_BUILTIN_ADMINS, NULL, sid_buf, &len);
    line("CreateWellKnownSid(BuiltinAdministrators, room): ret=%d err=%s; %s", r, le(), sid_text(sid_buf));
    arm();
    r = p_valid_sid((PSID)sid_buf);
    line("IsValidSid(the well-known): ret=%d err=%s", r, le());
    arm();
    r = p_equal_sid((PSID)sid_buf, (PSID)&sid_admins);
    line("EqualSid(it, the hand-built admins): ret=%d err=%s", r, le());
    len = sizeof sid_buf;
    arm();
    r = p_wk_sid(WK_WORLD, NULL, sid_buf, &len);
    line("CreateWellKnownSid(World): ret=%d err=%s; %s", r, le(), sid_text(sid_buf));
    len = sizeof sid_buf;
    arm();
    r = p_wk_sid(99, NULL, sid_buf, &len);
    line("CreateWellKnownSid(type 99): ret=%d err=%s", r, le());

    /* InitializeSid on a hand buffer. */
    memset(&hand, 0, sizeof hand);
    arm();
    r = p_init_sid((PSID)&hand, &nt, 2);
    line("InitializeSid(S-1-5, 2 sub-authorities): ret=%d err=%s", r, le());
    hand.sub[0] = SECURITY_BUILTIN_DOMAIN_RID;
    hand.sub[1] = DOMAIN_ALIAS_RID_USERS;
    arm();
    r = p_valid_sid((PSID)&hand);
    line("IsValidSid(the initialized): ret=%d err=%s; %s", r, le(), sid_text(&hand));
    arm();
    len = p_len_sid((PSID)&hand);
    line("GetLengthSid(it): ret=%lu err=%s", len, le());
}

/* --- selfrel ------------------------------------------------------------ */

/* An absolute SD by hand in sd_buf: header, then the owner SID, the
 * group SID and the DACL, with their offsets (the layout is public). */
static void make_absolute_sd(void)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    BYTE *p = (BYTE *)sd_buf;
    PACL acl = (PACL)acl_buf;
    DWORD off_owner, off_group, off_dacl;

    memset(sd_buf, 0, sizeof sd_buf);
    memset(acl_buf, 0, sizeof acl_buf);
    p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    p_add_allowed(acl, ACL_REVISION, 0x000F01FF, (PSID)&sid_everyone);
    ((BYTE *)sd)[0] = SECURITY_DESCRIPTOR_REVISION;
    *(unsigned short *)((BYTE *)sd + 2) = 0;    /* absolute */
    off_owner = 20;
    off_group = off_owner + sid_size(&sid_admins);
    off_dacl = off_group + sid_size(&sid_everyone);
    memcpy(p + off_owner, &sid_admins, sid_size(&sid_admins));
    memcpy(p + off_group, &sid_everyone, sid_size(&sid_everyone));
    memcpy(p + off_dacl, acl, acl->AclSize);
    *(DWORD *)(p + 4) = off_owner;      /* Owner offset */
    *(DWORD *)(p + 8) = off_group;      /* Group offset */
    *(DWORD *)(p + 12) = off_dacl;      /* Dacl offset */
    *(DWORD *)(p + 16) = 0;             /* Sacl offset */
}

static void sec_selfrel(void)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    PSECURITY_DESCRIPTOR rel = (PSECURITY_DESCRIPTOR)rel_buf;
    PSID owner, group;
    PACL dacl, sacl;
    BOOL present, defaulted;
    ULONG len;
    BOOL r;

    if (!have("MakeSelfRelativeSD", (void *)p_self_rel) || !have("IsValidSecurityDescriptor", (void *)p_valid_sd)
        || !have("GetSecurityDescriptorLength", (void *)p_sd_len)
        || !have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("GetSecurityDescriptorOwner", (void *)p_get_owner)
        || !have("SetSecurityDescriptorOwner", (void *)p_set_owner)
        || !have("GetSecurityDescriptorGroup", (void *)p_get_group)
        || !have("SetSecurityDescriptorGroup", (void *)p_set_group)
        || !have("GetSecurityDescriptorDacl", (void *)p_get_dacl)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)
        || !have("GetSecurityDescriptorSacl", (void *)p_get_sacl)
        || !have("SetSecurityDescriptorSacl", (void *)p_set_sacl) || !have("EqualSid", (void *)p_equal_sid)) {
        return;
    }
    make_absolute_sd();
    arm();
    r = p_valid_sd(sd);
    line("IsValidSecurityDescriptor(the absolute SD): ret=%d err=%s", r, le());

    len = 0;
    memset(rel_buf, 0xCC, sizeof rel_buf);
    arm();
    r = p_self_rel(sd, rel, &len);
    line("MakeSelfRelativeSD(no buffer): ret=%d err=%s; the size it asks %s", r, le(),
         len == 0 ? "unset" : "set");
    if (len != 0) {
        line("  the size asked %lu, past the header: %s", len, yesno(len > 20));
    }
    len = sizeof rel_buf;
    arm();
    r = p_self_rel(sd, rel, &len);
    line("MakeSelfRelativeSD(room): ret=%d err=%s; ReturnLength %lu", r, le(), len);
    arm();
    r = p_valid_sd(rel);
    line("IsValidSecurityDescriptor(the self-relative): ret=%d err=%s", r, le());
    line("  Control 0x%04X, self-relative: %s", sd_control(rel),
         yesno((sd_control(rel) & SE_SELF_RELATIVE) != 0));
    arm();
    len = p_sd_len(rel);
    line("GetSecurityDescriptorLength(the self-relative): ret=%lu err=%s", len, le());

    /* The owner/group/DACL/SACL round trips on the self-relative SD. */
    arm();
    r = p_set_owner(rel, (PSID)&sid_admins, FALSE);
    line("SetSecurityDescriptorOwner(admins, not defaulted): ret=%d err=%s", r, le());
    owner = NULL;
    defaulted = TRUE;
    arm();
    r = p_get_owner(rel, &owner, &defaulted);
    line("GetSecurityDescriptorOwner: ret=%d err=%s; the owner the one set: %s; defaulted: %s", r, le(),
         yesno(r && owner != NULL && p_equal_sid(owner, (PSID)&sid_admins)), yesno(r && defaulted));
    arm();
    r = p_set_group(rel, (PSID)&sid_everyone, FALSE);
    line("SetSecurityDescriptorGroup(Everyone, not defaulted): ret=%d err=%s", r, le());
    group = NULL;
    arm();
    r = p_get_group(rel, &group, &defaulted);
    line("GetSecurityDescriptorGroup: ret=%d err=%s; the group the one set: %s", r, le(),
         yesno(r && group != NULL && p_equal_sid(group, (PSID)&sid_everyone)));

    arm();
    r = p_set_dacl(rel, TRUE, (PACL)acl_buf, FALSE);
    line("SetSecurityDescriptorDacl(present, the ACL, not defaulted): ret=%d err=%s", r, le());
    present = FALSE;
    dacl = NULL;
    defaulted = TRUE;
    arm();
    r = p_get_dacl(rel, &present, &dacl, &defaulted);
    line("GetSecurityDescriptorDacl: ret=%d err=%s; present: %s; the ACL %s; defaulted: %s", r, le(),
         yesno(r && present), r && dacl != NULL ? "set" : "NULL", yesno(r && defaulted));
    if (r && dacl != NULL) {
        line("  its AceCount %u, AclSize %u", (unsigned)dacl->AceCount, (unsigned)dacl->AclSize);
    }
    arm();
    r = p_set_sacl(rel, TRUE, (PACL)acl_buf, FALSE);
    line("SetSecurityDescriptorSacl(present, the ACL, not defaulted): ret=%d err=%s", r, le());
    present = FALSE;
    sacl = NULL;
    arm();
    r = p_get_sacl(rel, &present, &sacl, &defaulted);
    line("GetSecurityDescriptorSacl: ret=%d err=%s; present: %s; the ACL %s", r, le(), yesno(r && present),
         r && sacl != NULL ? "set" : "NULL");

    /* A NULL DACL clears the present flag. */
    arm();
    r = p_set_dacl(rel, FALSE, NULL, FALSE);
    line("SetSecurityDescriptorDacl(not present, NULL): ret=%d err=%s", r, le());
    present = TRUE;
    dacl = (PACL)1;
    arm();
    r = p_get_dacl(rel, &present, &dacl, &defaulted);
    line("GetSecurityDescriptorDacl after the clear: ret=%d err=%s; present: %s; the ACL %s", r, le(),
         yesno(r && present), r && dacl != NULL ? "set" : "NULL");
    arm();
    r = p_set_owner(rel, NULL, FALSE);
    line("SetSecurityDescriptorOwner(NULL): ret=%d err=%s", r, le());
}

/* --- public enum values the new blocks use ------------------------------ */

/* TRUSTEE_FORM and TRUSTEE_TYPE (winnt.h's values). */
#define TF_SID 0
#define TF_NAME 1
#define TF_OBJECTS_AND_SID 3
#define TF_OBJECTS_AND_NAME 4
#define TT_UNKNOWN 0
#define TT_USER 1
/* MULTIPLE_TRUSTEE_OPERATION. */
#define MTO_NONE 0
#define MTO_IMPERSONATE 1
/* ACCESS_MODE. */
#define AM_GRANT 1
#define AM_SET_AUDIT_SUCCESS 5
/* The ObjectsPresent bits. */
#define OP_OBJECT_TYPE 0x1
#define OP_SID 0x2
/* SDDL_REVISION_1, the string SD revision this program asks for. */
#define SDDL_REVISION_1 1
/* SE_DACL_PROTECTED, the control bit SetSecurityDescriptorControl sets. */
#define SE_DACL_PROTECTED_C 0x1000
/* SE_KERNEL_OBJECT, the object type the handle access conversion takes. */
#define SE_KERNEL_OBJECT_T 6
/* The well-known SID types IsWellKnownSid takes (public values). */
#define WK_WORLD_T 1
#define WK_BUILTIN_ADMINS_T 26

/* A generic mapping for the private object calls. */
static GENERIC_MAPPING priv_mapping;

static void init_priv_mapping(void)
{
    priv_mapping.GenericRead = 0x80000000;
    priv_mapping.GenericWrite = 0x40000000;
    priv_mapping.GenericExecute = 0x20000000;
    priv_mapping.GenericAll = 0x10000000;
}

/* The ACEs of acl_buf, one per line, as type, size and mask (the mask
 * sits at offset 4 in every ACE type the new blocks add). */
static void show_aces_all(const char *label)
{
    PACL acl = (PACL)acl_buf;
    LPVOID p;
    DWORD i;
    BOOL r;

    line("%s: AceCount %u, AclSize %u", label, (unsigned)acl->AceCount, (unsigned)acl->AclSize);
    for (i = 0; i < acl->AceCount && i < 8; i++) {
        p = NULL;
        arm();
        r = p_get_ace(acl, i, &p);
        if (r && p != NULL) {
            ACE_HEADER *h = (ACE_HEADER *)p;
            line("  ACE %lu: GetAce ret=%d err=%s; type %u, flags 0x%X, size %u, mask 0x%08lX", i, r, le(),
                 (unsigned)h->AceType, (unsigned)h->AceFlags, (unsigned)h->AceSize,
                 (unsigned long)*(DWORD *)((BYTE *)p + 4));
        } else {
            line("  ACE %lu: GetAce ret=%d err=%s", i, r, le());
        }
    }
}

/* The DACL of the self-relative SD in buf, or NULL. */
static PACL dacl_of(const void *buf, DWORD len)
{
    const BYTE *p = (const BYTE *)buf;
    DWORD off_dacl;

    if (len < 20 || p[0] != SECURITY_DESCRIPTOR_REVISION) {
        return NULL;
    }
    off_dacl = *(const DWORD *)(p + 12);
    if ((sd_control(buf) & SE_DACL_PRESENT) == 0 || off_dacl == 0 || off_dacl + 8 > len) {
        return NULL;
    }
    return (PACL)(p + off_dacl);
}

/* --- trustee ------------------------------------------------------------ */

static void sec_trustee(void)
{
    static WCHAR wname[] = L"Everyone";
    static WCHAR wobjtype[] = L"F2KObjectType";
    f2kt_trustee_t tr, imp;
    f2kt_explicit_access_t ea;
    f2kt_objects_and_sid_t os;
    f2kt_objects_and_name_t on;
    ULONG form, type;
    void *name;
    DWORD r;

    if (!have("BuildTrusteeWithNameA", (void *)p_bt_name_a) || !have("BuildTrusteeWithNameW", (void *)p_bt_name_w)
        || !have("BuildTrusteeWithSidA", (void *)p_bt_sid_a) || !have("BuildTrusteeWithSidW", (void *)p_bt_sid_w)
        || !have("BuildTrusteeWithObjectsAndSidA", (void *)p_bt_objsid_a)
        || !have("BuildTrusteeWithObjectsAndSidW", (void *)p_bt_objsid_w)
        || !have("BuildTrusteeWithObjectsAndNameA", (void *)p_bt_objname_a)
        || !have("BuildTrusteeWithObjectsAndNameW", (void *)p_bt_objname_w)
        || !have("BuildImpersonateTrusteeA", (void *)p_bt_imp_a)
        || !have("BuildImpersonateTrusteeW", (void *)p_bt_imp_w)
        || !have("BuildImpersonateExplicitAccessWithNameA", (void *)p_bt_imp_ea_a)
        || !have("BuildImpersonateExplicitAccessWithNameW", (void *)p_bt_imp_ea_w)
        || !have("GetTrusteeFormA", (void *)p_gt_form_a) || !have("GetTrusteeFormW", (void *)p_gt_form_w)
        || !have("GetTrusteeNameA", (void *)p_gt_name_a) || !have("GetTrusteeNameW", (void *)p_gt_name_w)
        || !have("GetTrusteeTypeA", (void *)p_gt_type_a) || !have("GetTrusteeTypeW", (void *)p_gt_type_w)) {
        return;
    }
    memset(&tr, 0xCC, sizeof tr);
    p_bt_name_a(&tr, "Everyone");
    arm();
    form = p_gt_form_a(&tr);
    r = GetLastError();
    name = p_gt_name_a(&tr);
    type = p_gt_type_a(&tr);
    line("BuildTrusteeWithNameA(Everyone): form=%lu err=%s name=%s type=%lu", form, le_of(r),
         name != NULL ? (char *)name : "NULL", type);
    memset(&tr, 0xCC, sizeof tr);
    p_bt_name_w(&tr, wname);
    arm();
    form = p_gt_form_w(&tr);
    r = GetLastError();
    name = p_gt_name_w(&tr);
    type = p_gt_type_w(&tr);
    line("BuildTrusteeWithNameW (W): form=%lu err=%s name=%s type=%lu", form, le_of(r),
         name != NULL ? ws((const WCHAR *)name) : "(null)", type);

    memset(&tr, 0xCC, sizeof tr);
    p_bt_sid_a(&tr, (PSID)&sid_admins);
    arm();
    form = p_gt_form_a(&tr);
    r = GetLastError();
    name = p_gt_name_a(&tr);
    type = p_gt_type_a(&tr);
    line("BuildTrusteeWithSidA(S-1-5-32-544): form=%lu err=%s the name is the SID %s type=%lu", form, le_of(r),
         name != NULL ? sid_text(name) : "NULL", type);
    memset(&tr, 0xCC, sizeof tr);
    p_bt_sid_w(&tr, (PSID)&sid_admins);
    arm();
    form = p_gt_form_w(&tr);
    r = GetLastError();
    line("BuildTrusteeWithSidW (W): form=%lu err=%s", form, le_of(r));

    memset(&os, 0, sizeof os);
    os.ObjectsPresent = OP_OBJECT_TYPE | OP_SID;
    memset(&tr, 0xCC, sizeof tr);
    p_bt_objsid_a(&tr, &os, NULL, NULL, (PSID)&sid_admins);
    arm();
    form = p_gt_form_a(&tr);
    r = GetLastError();
    line("BuildTrusteeWithObjectsAndSidA: form=%lu err=%s (objects present 0x%lX)", form, le_of(r),
         (unsigned long)os.ObjectsPresent);
    memset(&tr, 0xCC, sizeof tr);
    p_bt_objsid_w(&tr, &os, NULL, NULL, (PSID)&sid_admins);
    arm();
    form = p_gt_form_w(&tr);
    r = GetLastError();
    line("BuildTrusteeWithObjectsAndSidW (W): form=%lu err=%s", form, le_of(r));

    memset(&on, 0, sizeof on);
    on.ObjectsPresent = OP_OBJECT_TYPE;
    memset(&tr, 0xCC, sizeof tr);
    p_bt_objname_a(&tr, &on, 1, "F2KObjectType", NULL, "Everyone");
    arm();
    form = p_gt_form_a(&tr);
    r = GetLastError();
    name = p_gt_name_a(&tr);
    line("BuildTrusteeWithObjectsAndNameA: form=%lu err=%s name=%s", form, le_of(r),
         name != NULL ? (char *)name : "NULL");
    memset(&tr, 0xCC, sizeof tr);
    p_bt_objname_w(&tr, &on, 1, wobjtype, NULL, wname);
    arm();
    form = p_gt_form_w(&tr);
    r = GetLastError();
    name = p_gt_name_w(&tr);
    line("BuildTrusteeWithObjectsAndNameW (W): form=%lu err=%s name=%s", form, le_of(r),
         name != NULL ? ws((const WCHAR *)name) : "(null)");

    memset(&tr, 0, sizeof tr);
    p_bt_name_a(&tr, "Everyone");
    memset(&imp, 0xCC, sizeof imp);
    p_bt_imp_a(&imp, &tr);
    arm();
    form = p_gt_form_a(&imp);
    r = GetLastError();
    name = p_gt_name_a(&imp);
    line("BuildImpersonateTrusteeA: operation=%d form=%lu err=%s name=%s", imp.MultipleTrusteeOperation, form,
         le_of(r), name != NULL ? (char *)name : "NULL");
    memset(&imp, 0xCC, sizeof imp);
    p_bt_imp_w(&imp, &tr);
    arm();
    form = p_gt_form_w(&imp);
    r = GetLastError();
    line("BuildImpersonateTrusteeW (W): operation=%d form=%lu err=%s", imp.MultipleTrusteeOperation, form, le_of(r));

    memset(&ea, 0xCC, sizeof ea);
    memset(&tr, 0, sizeof tr);
    p_bt_imp_ea_a(&ea, "Everyone", &tr, 0x000F01FF, AM_GRANT, 0);
    arm();
    form = p_gt_form_a(&ea.Trustee);
    r = GetLastError();
    name = p_gt_name_a(&ea.Trustee);
    line("BuildImpersonateExplicitAccessWithNameA: perms 0x%08lX mode %d inherit 0x%lX; trustee form=%lu err=%s name=%s",
         ea.grfAccessPermissions, ea.grfAccessMode, ea.grfInheritance, form, le_of(r),
         name != NULL ? (char *)name : "NULL");
    memset(&ea, 0xCC, sizeof ea);
    memset(&tr, 0, sizeof tr);
    p_bt_imp_ea_w(&ea, wname, &tr, 0x000F01FF, AM_GRANT, 0);
    arm();
    form = p_gt_form_w(&ea.Trustee);
    r = GetLastError();
    name = p_gt_name_w(&ea.Trustee);
    line("BuildImpersonateExplicitAccessWithNameW (W): perms 0x%08lX mode %d; trustee form=%lu err=%s name=%s",
         ea.grfAccessPermissions, ea.grfAccessMode, form, le_of(r),
         name != NULL ? ws((const WCHAR *)name) : "(null)");
}

/* --- objace ------------------------------------------------------------- */

static void sec_objace(void)
{
    PACL acl = (PACL)acl_buf;
    f2kt_guid_t guid;
    BOOL r;

    if (!have("InitializeAcl", (void *)p_init_acl) || !have("GetAce", (void *)p_get_ace)
        || !have("IsValidAcl", (void *)p_valid_acl) || !have("AddAccessAllowedObjectAce", (void *)p_add_allowed_obj)
        || !have("AddAccessDeniedObjectAce", (void *)p_add_denied_obj)
        || !have("AddAuditAccessAce", (void *)p_add_audit) || !have("AddAuditAccessAceEx", (void *)p_add_audit_ex)
        || !have("AddAuditAccessObjectAce", (void *)p_add_audit_obj)
        || !have("AddAccessAllowedAceEx", (void *)p_add_allowed_ex)
        || !have("AddAccessDeniedAceEx", (void *)p_add_denied_ex)) {
        return;
    }
    memset(&guid, 0, sizeof guid);
    guid.data1 = 0xF2F2F2F2u;
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl(1024, ACL_REVISION): ret=%d err=%s", r, le());

    arm();
    r = p_add_allowed_obj(acl, ACL_REVISION, 0, 0x000F01FF, NULL, NULL, (PSID)&sid_everyone);
    line("AddAccessAllowedObjectAce(Everyone, 0x000F01FF, no GUIDs): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_denied_obj(acl, ACL_REVISION, 0, 0x00000001, &guid, NULL, (PSID)&sid_system);
    line("AddAccessDeniedObjectAce(SYSTEM, 1, one GUID): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_audit(acl, ACL_REVISION, 0x000F01FF, (PSID)&sid_everyone, TRUE, TRUE);
    line("AddAuditAccessAce(Everyone, 0x000F01FF, success and failure): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_audit_ex(acl, ACL_REVISION, 0, 0x00000002, (PSID)&sid_everyone, TRUE, FALSE);
    line("AddAuditAccessAceEx(Everyone, 2, success only): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_audit_obj(acl, ACL_REVISION, 0, 0x00000004, NULL, NULL, (PSID)&sid_everyone, TRUE, TRUE);
    line("AddAuditAccessObjectAce(Everyone, 4, no GUIDs): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed_ex(acl, ACL_REVISION, 0, 0x00000008, (PSID)&sid_everyone);
    line("AddAccessAllowedAceEx(Everyone, 8): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_denied_ex(acl, ACL_REVISION, 0, 0x00000010, (PSID)&sid_everyone);
    line("AddAccessDeniedAceEx(Everyone, 0x10): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_valid_acl(acl);
    line("IsValidAcl: ret=%d err=%s", r, le());
    show_aces_all("the object/audit/ex ACEs");
}

/* --- strsd -------------------------------------------------------------- */

static void sec_strsd(void)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    PSECURITY_DESCRIPTOR rel = (PSECURITY_DESCRIPTOR)rel_buf;
    PSECURITY_DESCRIPTOR back = NULL;
    LPSTR s = NULL;
    LPWSTR sw = NULL;
    ULONG len, slen, backlen;
    PACL dacl;
    BOOL r;
    HLOCAL freed;

    if (!have("ConvertSecurityDescriptorToStringSecurityDescriptorA", (void *)p_sd_str_a)
        || !have("ConvertSecurityDescriptorToStringSecurityDescriptorW", (void *)p_sd_str_w)
        || !have("ConvertStringSecurityDescriptorToSecurityDescriptorA", (void *)p_str_sd_a)
        || !have("ConvertStringSecurityDescriptorToSecurityDescriptorW", (void *)p_str_sd_w)
        || !have("MakeSelfRelativeSD", (void *)p_self_rel) || !have("IsValidSecurityDescriptor", (void *)p_valid_sd)
        || !have("GetSecurityDescriptorLength", (void *)p_sd_len) || !have("GetAce", (void *)p_get_ace)
        || !have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)) {
        return;
    }
    make_absolute_sd();
    len = sizeof rel_buf;
    arm();
    r = p_self_rel(sd, rel, &len);
    line("MakeSelfRelativeSD: ret=%d err=%s; ReturnLength %lu", r, le(), len);
    if (!r) {
        return;
    }

    s = NULL;
    slen = 0;
    arm();
    r = p_sd_str_a(rel, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &s, &slen);
    line("ConvertSecurityDescriptorToStringSecurityDescriptorA: ret=%d err=%s string=%s", r, le(),
         r && s != NULL ? s : "(none)");
    if (r && s != NULL) {
        arm();
        freed = LocalFree(s);
        line("LocalFree(the string): returned NULL: %s err=%s", yesno(freed == NULL), le());
    }
    sw = NULL;
    slen = 0;
    arm();
    r = p_sd_str_w(rel, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sw, &slen);
    line("ConvertSecurityDescriptorToStringSecurityDescriptorW (W): ret=%d err=%s string=%s", r, le(),
         r && sw != NULL ? ws(sw) : "(none)");
    if (r && sw != NULL) {
        LocalFree(sw);
    }

    back = NULL;
    backlen = 0;
    arm();
    r = p_str_sd_a("D:(A;;000F01FF;;;S-1-1-0)", SDDL_REVISION_1, &back, &backlen);
    line("ConvertStringSecurityDescriptorToSecurityDescriptorA(D:(A;;000F01FF;;;S-1-1-0)): ret=%d err=%s; the SD %s",
         r, le(), r && back != NULL ? "set" : "NULL");
    if (r && back != NULL) {
        arm();
        r = p_valid_sd(back);
        line("  the SD back: IsValidSecurityDescriptor ret=%d err=%s", r, le());
        arm();
        len = p_sd_len(back);
        line("  GetSecurityDescriptorLength: ret=%lu err=%s", len, le());
        dacl = dacl_of(back, len);
        if (dacl != NULL) {
            line("  its DACL: AceCount %u, size %u", (unsigned)dacl->AceCount, (unsigned)dacl->AclSize);
            if (dacl->AceCount >= 1) {
                ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)((BYTE *)dacl + 8);
                line("  ACE 0: type %u, mask 0x%08lX, sid %s", (unsigned)ace->Header.AceType, ace->Mask,
                     sid_text(&ace->SidStart));
            }
        }
        LocalFree(back);
    }
    back = NULL;
    arm();
    r = p_str_sd_w(L"D:(A;;000F01FF;;;S-1-1-0)", SDDL_REVISION_1, &back, &backlen);
    line("ConvertStringSecurityDescriptorToSecurityDescriptorW (W): ret=%d err=%s; the SD %s", r, le(),
         r && back != NULL ? "set" : "NULL");
    if (r && back != NULL) {
        LocalFree(back);
    }
    back = NULL;
    arm();
    r = p_str_sd_a("not a security descriptor", SDDL_REVISION_1, &back, &backlen);
    line("ConvertStringSecurityDescriptorToSecurityDescriptorA(a bad string): ret=%d err=%s", r, le());
    back = NULL;
    arm();
    r = p_str_sd_a("D:(A;;1;;;S-1-1-0)", 9, &back, &backlen);
    line("ConvertStringSecurityDescriptorToSecurityDescriptorA(revision 9): ret=%d err=%s", r, le());
}

/* --- privobj ------------------------------------------------------------ */

static void sec_privobj(void)
{
    HANDLE token = NULL;
    PSECURITY_DESCRIPTOR priv = NULL, priv2 = NULL;
    DWORD need, need2;
    BOOL r;

    if (!have("CreatePrivateObjectSecurity", (void *)p_create_priv)
        || !have("CreatePrivateObjectSecurityEx", (void *)p_create_priv_ex)
        || !have("DestroyPrivateObjectSecurity", (void *)p_destroy_priv)
        || !have("GetPrivateObjectSecurity", (void *)p_get_priv)
        || !have("SetPrivateObjectSecurity", (void *)p_set_priv)
        || !have("SetPrivateObjectSecurityEx", (void *)p_set_priv_ex)
        || !have("ConvertToAutoInheritPrivateObjectSecurity", (void *)p_convert_auto)
        || !have("OpenProcessToken", (void *)p_open_token)
        || !have("IsValidSecurityDescriptor", (void *)p_valid_sd) || !have("GetSecurityDescriptorLength", (void *)p_sd_len)
        || !have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)) {
        return;
    }
    init_priv_mapping();
    arm();
    r = p_open_token(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): ret=%d err=%s, %s", r, le(),
         r && token != NULL ? "a handle" : "no handle");
    if (!r || token == NULL) {
        return;
    }
    make_absolute_sd();
    priv = NULL;
    arm();
    r = p_create_priv(NULL, (PSECURITY_DESCRIPTOR)sd_buf, &priv, FALSE, token, &priv_mapping);
    line("CreatePrivateObjectSecurity(no parent, the creator SD): ret=%d err=%s; the SD %s", r, le(),
         r && priv != NULL ? "set" : "NULL");
    if (r && priv != NULL) {
        arm();
        r = p_valid_sd(priv);
        line("  the private SD: IsValidSecurityDescriptor ret=%d err=%s", r, le());
        arm();
        need = p_sd_len(priv);
        line("  GetSecurityDescriptorLength: ret=%lu err=%s", need, le());

        need = F2KT_UNTOUCHED;
        arm();
        r = p_get_priv(priv, DACL_SECURITY_INFORMATION, NULL, 0, &need);
        line("GetPrivateObjectSecurity(no buffer): ret=%d err=%s; the size needed %s", r, le(),
             need == F2KT_UNTOUCHED ? "untouched" : "set");
        if (need != F2KT_UNTOUCHED && need <= sizeof rel_buf) {
            memset(rel_buf, 0, sizeof rel_buf);
            need2 = need;
            arm();
            r = p_get_priv(priv, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)rel_buf, need2, &need2);
            line("GetPrivateObjectSecurity(the size asked for): ret=%d err=%s", r, le());
            if (r) {
                PACL dacl = dacl_of(rel_buf, need2);
                line("  the DACL read: %s; AceCount %u", dacl != NULL ? "set" : "NULL",
                     dacl != NULL ? (unsigned)dacl->AceCount : 0);
            }
        }

        /* A second ACE in the ACL, copied into the SD's DACL, so the set
         * below carries both. */
        make_absolute_sd();
        arm();
        r = p_add_allowed((PACL)acl_buf, ACL_REVISION, 0x00000001, (PSID)&sid_everyone);
        line("AddAccessAllowedAce(another, Everyone, 1): ret=%d err=%s; AceCount %u", r, le(),
             (unsigned)((PACL)acl_buf)->AceCount);
        memcpy((BYTE *)sd_buf + *(DWORD *)((BYTE *)sd_buf + 12), acl_buf, ((PACL)acl_buf)->AclSize);
        arm();
        r = p_set_priv(DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf, &priv, &priv_mapping, token);
        line("SetPrivateObjectSecurity(DACL, a new SD): ret=%d err=%s", r, le());
        need2 = sizeof rel_buf;
        memset(rel_buf, 0, sizeof rel_buf);
        arm();
        r = p_get_priv(priv, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)rel_buf, need2, &need2);
        line("GetPrivateObjectSecurity(read back): ret=%d err=%s", r, le());
        if (r) {
            PACL dacl = dacl_of(rel_buf, need2);
            if (dacl != NULL && dacl->AceCount >= 1) {
                ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)((BYTE *)dacl + 8);
                line("  ACE 0: type %u, mask 0x%08lX, sid %s", (unsigned)ace->Header.AceType, ace->Mask,
                     sid_text(&ace->SidStart));
            }
        }

        priv2 = NULL;
        arm();
        r = p_create_priv_ex(NULL, (PSECURITY_DESCRIPTOR)sd_buf, &priv2, NULL, FALSE, 0, token, &priv_mapping);
        line("CreatePrivateObjectSecurityEx(no parent, no GUID, flags 0): ret=%d err=%s; the SD %s", r, le(),
             r && priv2 != NULL ? "set" : "NULL");
        if (r && priv2 != NULL) {
            arm();
            r = p_destroy_priv(&priv2);
            line("DestroyPrivateObjectSecurity(it): ret=%d err=%s; the pointer now %s", r, le(),
                 priv2 == NULL ? "NULL" : "set");
        }
        arm();
        r = p_set_priv_ex(DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf, &priv, 0, &priv_mapping, token);
        line("SetPrivateObjectSecurityEx(DACL, flags 0): ret=%d err=%s", r, le());

        priv2 = NULL;
        arm();
        r = p_convert_auto(NULL, priv, &priv2, NULL, FALSE, &priv_mapping);
        line("ConvertToAutoInheritPrivateObjectSecurity(no parent): ret=%d err=%s; the SD %s", r, le(),
             r && priv2 != NULL ? "set" : "NULL");
        if (r && priv2 != NULL) {
            arm();
            r = p_destroy_priv(&priv2);
            line("DestroyPrivateObjectSecurity(the converted): ret=%d err=%s; the pointer now %s", r, le(),
                 priv2 == NULL ? "NULL" : "set");
        }
        arm();
        r = p_destroy_priv(&priv);
        line("DestroyPrivateObjectSecurity(the first): ret=%d err=%s; the pointer now %s", r, le(),
             priv == NULL ? "NULL" : "set");
    }
    CloseHandle(token);
}

/* --- sdcorner ----------------------------------------------------------- */

static void sec_sdcorner(void)
{
    static WCHAR weveryone[] = L"Everyone";
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    f2kt_trustee_t owner, group;
    f2kt_explicit_access_t ea;
    f2kt_actrl_list_t empty_list;
    f2kt_actrl_list_t *alist, *aulist;
    LPSTR ownername, groupname;
    ULONG size;
    PSECURITY_DESCRIPTOR newsd;
    BYTE rm;
    DWORD ret;
    LONG st;
    BOOL r;

    if (!have("SetSecurityDescriptorControl", (void *)p_set_sd_ctrl)
        || !have("GetSecurityDescriptorRMControl", (void *)p_get_rm)
        || !have("SetSecurityDescriptorRMControl", (void *)p_set_rm)
        || !have("BuildSecurityDescriptorA", (void *)p_build_sd_a)
        || !have("BuildSecurityDescriptorW", (void *)p_build_sd_w)
        || !have("ConvertAccessToSecurityDescriptorA", (void *)p_conv_acc_sd_a)
        || !have("ConvertAccessToSecurityDescriptorW", (void *)p_conv_acc_sd_w)
        || !have("ConvertSecurityDescriptorToAccessA", (void *)p_conv_sd_acc_a)
        || !have("ConvertSecurityDescriptorToAccessW", (void *)p_conv_sd_acc_w)
        || !have("ConvertSecurityDescriptorToAccessNamedA", (void *)p_conv_sd_acc_named_a)
        || !have("ConvertSecurityDescriptorToAccessNamedW", (void *)p_conv_sd_acc_named_w)
        || !have("InitializeSecurityDescriptor", (void *)p_init_sd)
        || !have("BuildTrusteeWithNameA", (void *)p_bt_name_a)
        || !have("BuildTrusteeWithNameW", (void *)p_bt_name_w)) {
        return;
    }
    arm();
    r = p_init_sd(sd, SECURITY_DESCRIPTOR_REVISION);
    line("InitializeSecurityDescriptor(REVISION): ret=%d err=%s", r, le());

    arm();
    r = p_set_sd_ctrl(sd, SE_DACL_PROTECTED_C, SE_DACL_PROTECTED_C);
    line("SetSecurityDescriptorControl(SE_DACL_PROTECTED, set): ret=%d err=%s; the control now 0x%04X", r, le(),
         sd_control(sd));
    arm();
    r = p_set_sd_ctrl(sd, SE_DACL_PROTECTED_C, 0);
    line("SetSecurityDescriptorControl(SE_DACL_PROTECTED, clear): ret=%d err=%s; the control now 0x%04X", r, le(),
         sd_control(sd));

    rm = 0xCC;
    arm();
    ret = p_get_rm(sd, &rm);
    line("GetSecurityDescriptorRMControl: ret=%lu err=%s byte=0x%02X", ret, le(), (unsigned)rm);
    rm = 0;
    arm();
    ret = p_set_rm(sd, &rm);
    line("SetSecurityDescriptorRMControl(0): ret=%lu err=%s", ret, le());
    rm = 0xCC;
    arm();
    ret = p_get_rm(sd, &rm);
    line("GetSecurityDescriptorRMControl again: ret=%lu err=%s byte=0x%02X", ret, le(), (unsigned)rm);

    if (have("RtlCopySecurityDescriptor", (void *)p_rtl_copy_sd)) {
        memset(rel_buf, 0xCC, sizeof rel_buf);
        arm();
        st = p_rtl_copy_sd(sd, (PSECURITY_DESCRIPTOR)rel_buf);
        line("RtlCopySecurityDescriptor(ntdll): status=0x%08lX err=%s; the copy's control 0x%04X", st, le(),
             sd_control(rel_buf));
    }

    /* BuildSecurityDescriptorA: owner and group Everyone, one grant. */
    memset(&owner, 0, sizeof owner);
    p_bt_name_a(&owner, "Everyone");
    memset(&group, 0, sizeof group);
    p_bt_name_a(&group, "Everyone");
    memset(&ea, 0, sizeof ea);
    ea.grfAccessPermissions = 0x000F01FF;
    ea.grfAccessMode = AM_GRANT;
    ea.grfInheritance = 0;
    p_bt_name_a(&ea.Trustee, "Everyone");
    size = 0;
    newsd = NULL;
    arm();
    ret = p_build_sd_a(&owner, &group, 1, &ea, 0, NULL, NULL, &size, &newsd);
    line("BuildSecurityDescriptorA(no buffer): ret=%lu err=%s; the size needed %s", ret, le(),
         size == 0 ? "unset" : "set");
    if (size != 0 && size <= sizeof rel_buf) {
        size = sizeof rel_buf;
        newsd = (PSECURITY_DESCRIPTOR)rel_buf;
        memset(rel_buf, 0, sizeof rel_buf);
        arm();
        ret = p_build_sd_a(&owner, &group, 1, &ea, 0, NULL, NULL, &size, &newsd);
        line("BuildSecurityDescriptorA(the size asked for): ret=%lu err=%s; the SD %s, control 0x%04X, size %lu",
             ret, le(), newsd != NULL ? "set" : "NULL", sd_control(rel_buf), size);
    }
    /* The W form, with wide trustee names. */
    memset(&owner, 0, sizeof owner);
    p_bt_name_w(&owner, weveryone);
    memset(&group, 0, sizeof group);
    p_bt_name_w(&group, weveryone);
    memset(&ea, 0, sizeof ea);
    ea.grfAccessPermissions = 0x000F01FF;
    ea.grfAccessMode = AM_GRANT;
    p_bt_name_w(&ea.Trustee, weveryone);
    size = sizeof rel_buf;
    newsd = (PSECURITY_DESCRIPTOR)rel_buf;
    memset(rel_buf, 0, sizeof rel_buf);
    arm();
    ret = p_build_sd_w(&owner, &group, 1, &ea, 0, NULL, NULL, &size, &newsd);
    line("BuildSecurityDescriptorW (W): ret=%lu err=%s; the SD %s, control 0x%04X, size %lu", ret, le(),
         newsd != NULL ? "set" : "NULL", sd_control(rel_buf), size);

    /* ConvertAccessToSecurityDescriptorA/W from an empty access list. */
    memset(&empty_list, 0, sizeof empty_list);
    newsd = NULL;
    arm();
    ret = p_conv_acc_sd_a(&empty_list, NULL, "Everyone", "Everyone", &newsd);
    line("ConvertAccessToSecurityDescriptorA(empty list, owner/group names): ret=%lu err=%s; the SD %s", ret, le(),
         newsd != NULL ? "set" : "NULL");
    if (ret == 0 && newsd != NULL) {
        line("  its control 0x%04X", sd_control(newsd));
        LocalFree(newsd);
    }
    newsd = NULL;
    arm();
    ret = p_conv_acc_sd_w(&empty_list, NULL, weveryone, weveryone, &newsd);
    line("ConvertAccessToSecurityDescriptorW (W): ret=%lu err=%s; the SD %s", ret, le(),
         newsd != NULL ? "set" : "NULL");
    if (ret == 0 && newsd != NULL) {
        LocalFree(newsd);
    }

    /* ConvertSecurityDescriptorToAccessA/W over the process handle. */
    alist = NULL;
    aulist = NULL;
    ownername = NULL;
    groupname = NULL;
    arm();
    ret = p_conv_sd_acc_a(GetCurrentProcess(), SE_KERNEL_OBJECT_T, sd, &alist, &aulist, &ownername, &groupname);
    line("ConvertSecurityDescriptorToAccessA(the process handle, kernel object): ret=%lu err=%s; access list %s, "
         "audit list %s, owner %s, group %s", ret, le(), alist != NULL ? "set" : "NULL",
         aulist != NULL ? "set" : "NULL", ownername != NULL ? "set" : "NULL", groupname != NULL ? "set" : "NULL");
    if (alist != NULL) {
        LocalFree(alist);
    }
    if (aulist != NULL) {
        LocalFree(aulist);
    }
    if (ownername != NULL) {
        LocalFree(ownername);
    }
    if (groupname != NULL) {
        LocalFree(groupname);
    }
    {
        LPWSTR ownernamew = NULL, groupnamew = NULL;
        f2kt_actrl_list_t *alistw = NULL, *aulistw = NULL;

        arm();
        ret = p_conv_sd_acc_w(GetCurrentProcess(), SE_KERNEL_OBJECT_T, sd, &alistw, &aulistw, &ownernamew,
                              &groupnamew);
        line("ConvertSecurityDescriptorToAccessW (W): ret=%lu err=%s; access list %s, owner %s", ret, le(),
             alistw != NULL ? "set" : "NULL", ownernamew != NULL ? "set" : "NULL");
        if (alistw != NULL) {
            LocalFree(alistw);
        }
        if (aulistw != NULL) {
            LocalFree(aulistw);
        }
        if (ownernamew != NULL) {
            LocalFree(ownernamew);
        }
        if (groupnamew != NULL) {
            LocalFree(groupnamew);
        }
    }
    alist = NULL;
    aulist = NULL;
    ownername = NULL;
    groupname = NULL;
    arm();
    ret = p_conv_sd_acc_named_a(NULL, SE_KERNEL_OBJECT_T, sd, &alist, &aulist, &ownername, &groupname);
    line("ConvertSecurityDescriptorToAccessNamedA(NULL name, kernel object): ret=%lu err=%s; access list %s", ret,
         le(), alist != NULL ? "set" : "NULL");
    if (alist != NULL) {
        LocalFree(alist);
    }
    if (aulist != NULL) {
        LocalFree(aulist);
    }
    if (ownername != NULL) {
        LocalFree(ownername);
    }
    if (groupname != NULL) {
        LocalFree(groupname);
    }
    {
        LPWSTR ownernamew = NULL, groupnamew = NULL;
        f2kt_actrl_list_t *alistw = NULL, *aulistw = NULL;

        arm();
        ret = p_conv_sd_acc_named_w(NULL, SE_KERNEL_OBJECT_T, sd, &alistw, &aulistw, &ownernamew, &groupnamew);
        line("ConvertSecurityDescriptorToAccessNamedW (W): ret=%lu err=%s; access list %s", ret, le(),
             alistw != NULL ? "set" : "NULL");
        if (alistw != NULL) {
            LocalFree(alistw);
        }
        if (aulistw != NULL) {
            LocalFree(aulistw);
        }
        if (ownernamew != NULL) {
            LocalFree(ownernamew);
        }
        if (groupnamew != NULL) {
            LocalFree(groupnamew);
        }
    }
}

/* --- saclaudit ---------------------------------------------------------- */

static void sec_saclaudit(void)
{
    PACL acl = (PACL)acl_buf;
    f2kt_trustee_t tr;
    f2kt_actrl_entry_t entry;
    f2kt_actrl_list_t *newlist;
    ACCESS_MASK succ, fail;
    DWORD ret;
    BOOL r;

    if (!have("InitializeAcl", (void *)p_init_acl) || !have("AddAuditAccessAce", (void *)p_add_audit)
        || !have("GetAuditedPermissionsFromAclA", (void *)p_get_audited_a)
        || !have("GetAuditedPermissionsFromAclW", (void *)p_get_audited_w)
        || !have("SetEntriesInAuditListA", (void *)p_set_audit_a)
        || !have("SetEntriesInAuditListW", (void *)p_set_audit_w)) {
        return;
    }
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    line("InitializeAcl(1024, ACL_REVISION): ret=%d err=%s", r, le());
    arm();
    r = p_add_audit(acl, ACL_REVISION, 0x000F01FF, (PSID)&sid_everyone, TRUE, TRUE);
    line("AddAuditAccessAce(Everyone, 0x000F01FF, success and failure): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);

    memset(&tr, 0, sizeof tr);
    tr.TrusteeForm = TF_NAME;
    tr.TrusteeType = TT_USER;
    tr.ptstrName = "Everyone";
    succ = 0;
    fail = 0;
    arm();
    ret = p_get_audited_a(acl, &tr, &succ, &fail);
    line("GetAuditedPermissionsFromAclA(Everyone): ret=%lu err=%s success=0x%08lX failure=0x%08lX", ret, le(),
         (unsigned long)succ, (unsigned long)fail);
    memset(&tr, 0, sizeof tr);
    tr.TrusteeForm = TF_NAME;
    tr.TrusteeType = TT_USER;
    tr.ptstrName = L"Everyone";
    succ = 0;
    fail = 0;
    arm();
    ret = p_get_audited_w(acl, &tr, &succ, &fail);
    line("GetAuditedPermissionsFromAclW (W): ret=%lu err=%s success=0x%08lX failure=0x%08lX", ret, le(),
         (unsigned long)succ, (unsigned long)fail);

    memset(&entry, 0, sizeof entry);
    entry.Trustee.TrusteeForm = TF_NAME;
    entry.Trustee.TrusteeType = TT_USER;
    entry.Trustee.ptstrName = "Everyone";
    entry.fAccessFlags = 0x000F01FF;
    entry.Access = 0x000F01FF;
    newlist = NULL;
    arm();
    ret = p_set_audit_a(1, &entry, AM_SET_AUDIT_SUCCESS, NULL, NULL, &newlist);
    line("SetEntriesInAuditListA(1 entry, SET_AUDIT_SUCCESS, no old list): ret=%lu err=%s; the new list %s", ret, le(),
         newlist != NULL ? "set" : "NULL");
    if (ret == 0 && newlist != NULL) {
        line("  its cEntries %lu", (unsigned long)newlist->cEntries);
        LocalFree(newlist);
    }
    memset(&entry, 0, sizeof entry);
    entry.Trustee.TrusteeForm = TF_NAME;
    entry.Trustee.TrusteeType = TT_USER;
    entry.Trustee.ptstrName = L"Everyone";
    entry.fAccessFlags = 0x000F01FF;
    entry.Access = 0x000F01FF;
    newlist = NULL;
    arm();
    ret = p_set_audit_w(1, &entry, AM_SET_AUDIT_SUCCESS, NULL, NULL, &newlist);
    line("SetEntriesInAuditListW (W): ret=%lu err=%s; the new list %s", ret, le(), newlist != NULL ? "set" : "NULL");
    if (ret == 0 && newlist != NULL) {
        LocalFree(newlist);
    }
}

/* --- sidmore ------------------------------------------------------------ */

static void sec_sidmore(void)
{
    static const WCHAR wname_acct[] = L"Everyone";
    HANDLE token = NULL;
    BOOL eq, r;
    DWORD ret, len, cbSid, cchDom, use;
    PSID site;
    char dom[128];
    WCHAR domw[128];
    char name[128];
    WCHAR namew[128];

    if (!have("EqualDomainSid", (void *)p_equal_domain)
        || !have("GetWindowsAccountDomainSid", (void *)p_get_win_domain)
        || !have("GetSiteSidFromToken", (void *)p_get_site_token)
        || !have("GetMangledSiteSid", (void *)p_get_mangled) || !have("IsWellKnownSid", (void *)p_is_wk)
        || !have("LookupAccountNameA", (void *)p_lookup_name_a) || !have("LookupAccountNameW", (void *)p_lookup_name_w)
        || !have("LookupAccountSidA", (void *)p_lookup_sid_a) || !have("LookupAccountSidW", (void *)p_lookup_sid_w)
        || !have("OpenProcessToken", (void *)p_open_token)) {
        return;
    }
    eq = (BOOL)F2KT_UNTOUCHED;
    arm();
    r = p_equal_domain((PSID)&sid_admins, (PSID)&sid_builtin, &eq);
    line("EqualDomainSid(S-1-5-32-544, S-1-5-32): ret=%d err=%s equal=%d", r, le(), eq);
    eq = (BOOL)F2KT_UNTOUCHED;
    arm();
    r = p_equal_domain((PSID)&sid_admins, (PSID)&sid_everyone, &eq);
    line("EqualDomainSid(S-1-5-32-544, S-1-1-0): ret=%d err=%s equal=%d", r, le(), eq);

    len = 0;
    arm();
    r = p_get_win_domain((PSID)&sid_admins, (PSID)sid_buf, &len);
    line("GetWindowsAccountDomainSid(S-1-5-32-544): ret=%d err=%s; the size %s (the domain SID never prints)", r,
         le(), len == 0 ? "unset" : "set");

    arm();
    r = p_is_wk((PSID)&sid_everyone, WK_WORLD_T);
    line("IsWellKnownSid(S-1-1-0, World): ret=%d err=%s", r, le());
    arm();
    r = p_is_wk((PSID)&sid_admins, WK_BUILTIN_ADMINS_T);
    line("IsWellKnownSid(S-1-5-32-544, BuiltinAdministrators): ret=%d err=%s", r, le());
    arm();
    r = p_is_wk((PSID)&sid_everyone, WK_BUILTIN_ADMINS_T);
    line("IsWellKnownSid(S-1-1-0, BuiltinAdministrators): ret=%d err=%s", r, le());

    arm();
    r = p_open_token(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): ret=%d err=%s, %s", r, le(),
         r && token != NULL ? "a handle" : "no handle");
    if (r && token != NULL) {
        site = NULL;
        arm();
        ret = p_get_site_token(token, &site);
        line("GetSiteSidFromToken: ret=%lu err=%s; the site SID %s (never printed)", ret, le(),
             site != NULL ? "set" : "NULL");
        CloseHandle(token);
    }
    site = NULL;
    arm();
    ret = p_get_mangled((PSID)&sid_everyone, &site);
    line("GetMangledSiteSid(S-1-1-0): ret=%lu err=%s; the site SID %s (never printed)", ret, le(),
         site != NULL ? "set" : "NULL");

    /* LookupAccountNameA/W for Everyone: the size query, then the call. */
    cbSid = 0;
    cchDom = 0;
    use = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_name_a(NULL, "Everyone", NULL, &cbSid, NULL, &cchDom, &use);
    line("LookupAccountNameA(NULL, \"Everyone\", no buffers): ret=%d err=%s; cbSid %s cchDom %s use %s", r, le(),
         cbSid == 0 ? "unset" : "set", cchDom == 0 ? "unset" : "set", use == F2KT_UNTOUCHED ? "untouched" : "set");
    if (cbSid != 0 && cbSid <= sizeof sid_buf && cchDom <= sizeof dom) {
        cbSid = sizeof sid_buf;
        cchDom = sizeof dom;
        use = F2KT_UNTOUCHED;
        arm();
        r = p_lookup_name_a(NULL, "Everyone", (PSID)sid_buf, &cbSid, dom, &cchDom, &use);
        line("LookupAccountNameA(NULL, \"Everyone\", room): ret=%d err=%s; the SID %s; use %s", r, le(),
             r ? sid_text(sid_buf) : "-", use == F2KT_UNTOUCHED ? "untouched" : "set");
        if (r && use != F2KT_UNTOUCHED) {
            line("  use %lu (SidTypeWellKnownGroup 5: %s)", use, yesno(use == 5));
        }
    }
    cbSid = sizeof sid_buf;
    cchDom = sizeof domw;
    use = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_name_w(NULL, wname_acct, (PSID)sid_buf, &cbSid, domw, &cchDom, &use);
    line("LookupAccountNameW(NULL, L\"Everyone\") (W): ret=%d err=%s; the SID %s", r, le(), r ? sid_text(sid_buf) : "-");

    /* LookupAccountSidA/W for S-1-1-0: the name prints (well-known). */
    memset(name, 0, sizeof name);
    memset(dom, 0, sizeof dom);
    len = sizeof name;
    cbSid = sizeof dom;
    use = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_sid_a(NULL, (PSID)&sid_everyone, name, &len, dom, &cbSid, &use);
    line("LookupAccountSidA(NULL, S-1-1-0): ret=%d err=%s; the name %s; use %s", r, le(), r ? name : "-",
         use == F2KT_UNTOUCHED ? "untouched" : "set");
    if (r && use != F2KT_UNTOUCHED) {
        line("  use %lu (SidTypeWellKnownGroup 5: %s)", use, yesno(use == 5));
    }
    memset(namew, 0, sizeof namew);
    memset(domw, 0, sizeof domw);
    len = sizeof namew / sizeof namew[0];
    cbSid = sizeof domw / sizeof domw[0];
    use = F2KT_UNTOUCHED;
    arm();
    r = p_lookup_sid_w(NULL, (PSID)&sid_everyone, namew, &len, domw, &cbSid, &use);
    line("LookupAccountSidW(NULL, S-1-1-0) (W): ret=%d err=%s; the name %s", r, le(), r ? ws(namew) : "-");
}

/* --- main --------------------------------------------------------------- */

static const section_t sections[] = {
    { "initsd", sec_initsd, F2KT_ALWAYS },
    { "acl", sec_acl, F2KT_ALWAYS },
    { "allowedace", sec_allowedace, F2KT_ALWAYS },
    { "deniedace", sec_deniedace, F2KT_ALWAYS },
    { "sid", sec_sid, F2KT_ALWAYS },
    { "selfrel", sec_selfrel, F2KT_ALWAYS },
    { "trustee", sec_trustee, F2KT_ALWAYS },
    { "objace", sec_objace, F2KT_ALWAYS },
    { "strsd", sec_strsd, F2KT_ALWAYS },
    { "privobj", sec_privobj, F2KT_ALWAYS },
    { "sdcorner", sec_sdcorner, F2KT_ALWAYS },
    { "saclaudit", sec_saclaudit, F2KT_ALWAYS },
    { "sidmore", sec_sidmore, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    /* No static advapi32 import in this file, so the linker adds no import
     * entry and the module may not be loaded: force it in, or every lookup
     * below misses and the section prints only "not found". */
    adv = LoadLibraryA("advapi32.dll");
    p_init_sd = (init_sd_fn)GetProcAddress(adv, "InitializeSecurityDescriptor");
    p_valid_sd = (valid_sd_fn)GetProcAddress(adv, "IsValidSecurityDescriptor");
    p_sd_len = (sd_len_fn)GetProcAddress(adv, "GetSecurityDescriptorLength");
    p_sd_control = (sd_control_fn)GetProcAddress(adv, "GetSecurityDescriptorControl");
    p_init_acl = (init_acl_fn)GetProcAddress(adv, "InitializeAcl");
    p_valid_acl = (valid_acl_fn)GetProcAddress(adv, "IsValidAcl");
    p_add_ace = (add_ace_fn)GetProcAddress(adv, "AddAce");
    p_get_ace = (get_ace_fn)GetProcAddress(adv, "GetAce");
    p_find_free = (find_free_ace_fn)GetProcAddress(adv, "FindFirstFreeAce");
    p_del_ace = (del_ace_fn)GetProcAddress(adv, "DeleteAce");
    p_add_allowed = (add_allowed_ace_fn)GetProcAddress(adv, "AddAccessAllowedAce");
    p_add_denied = (add_denied_ace_fn)GetProcAddress(adv, "AddAccessDeniedAce");
    p_alloc_sid = (alloc_sid_fn)GetProcAddress(adv, "AllocateAndInitializeSid");
    p_init_sid = (init_sid_fn)GetProcAddress(adv, "InitializeSid");
    p_len_sid = (len_sid_fn)GetProcAddress(adv, "GetLengthSid");
    p_valid_sid = (valid_sid_fn)GetProcAddress(adv, "IsValidSid");
    p_equal_sid = (equal_sid_fn)GetProcAddress(adv, "EqualSid");
    p_equal_prefix = (equal_prefix_sid_fn)GetProcAddress(adv, "EqualPrefixSid");
    p_copy_sid = (copy_sid_fn)GetProcAddress(adv, "CopySid");
    p_sid_str_a = (sid_to_str_a_fn)GetProcAddress(adv, "ConvertSidToStringSidA");
    p_sid_str_w = (sid_to_str_w_fn)GetProcAddress(adv, "ConvertSidToStringSidW");
    p_wk_sid = (create_wk_sid_fn)GetProcAddress(adv, "CreateWellKnownSid");
    p_free_sid = (free_sid_fn)GetProcAddress(adv, "FreeSid");
    p_self_rel = (make_self_rel_fn)GetProcAddress(adv, "MakeSelfRelativeSD");
    p_get_dacl = (get_dacl_fn)GetProcAddress(adv, "GetSecurityDescriptorDacl");
    p_set_dacl = (set_dacl_fn)GetProcAddress(adv, "SetSecurityDescriptorDacl");
    p_get_owner = (get_owner_fn)GetProcAddress(adv, "GetSecurityDescriptorOwner");
    p_set_owner = (set_owner_fn)GetProcAddress(adv, "SetSecurityDescriptorOwner");
    p_get_group = (get_group_fn)GetProcAddress(adv, "GetSecurityDescriptorGroup");
    p_set_group = (set_group_fn)GetProcAddress(adv, "SetSecurityDescriptorGroup");
    p_get_sacl = (get_sacl_fn)GetProcAddress(adv, "GetSecurityDescriptorSacl");
    p_set_sacl = (set_sacl_fn)GetProcAddress(adv, "SetSecurityDescriptorSacl");
    p_bt_name_a = (bt_name_fn)GetProcAddress(adv, "BuildTrusteeWithNameA");
    p_bt_name_w = (bt_name_fn)GetProcAddress(adv, "BuildTrusteeWithNameW");
    p_bt_sid_a = (bt_sid_fn)GetProcAddress(adv, "BuildTrusteeWithSidA");
    p_bt_sid_w = (bt_sid_fn)GetProcAddress(adv, "BuildTrusteeWithSidW");
    p_bt_objsid_a = (bt_objsid_fn)GetProcAddress(adv, "BuildTrusteeWithObjectsAndSidA");
    p_bt_objsid_w = (bt_objsid_fn)GetProcAddress(adv, "BuildTrusteeWithObjectsAndSidW");
    p_bt_objname_a = (bt_objname_fn)GetProcAddress(adv, "BuildTrusteeWithObjectsAndNameA");
    p_bt_objname_w = (bt_objname_fn)GetProcAddress(adv, "BuildTrusteeWithObjectsAndNameW");
    p_bt_imp_a = (bt_imp_fn)GetProcAddress(adv, "BuildImpersonateTrusteeA");
    p_bt_imp_w = (bt_imp_fn)GetProcAddress(adv, "BuildImpersonateTrusteeW");
    p_bt_imp_ea_a = (bt_imp_ea_fn)GetProcAddress(adv, "BuildImpersonateExplicitAccessWithNameA");
    p_bt_imp_ea_w = (bt_imp_ea_fn)GetProcAddress(adv, "BuildImpersonateExplicitAccessWithNameW");
    p_gt_form_a = (gt_form_fn)GetProcAddress(adv, "GetTrusteeFormA");
    p_gt_form_w = (gt_form_fn)GetProcAddress(adv, "GetTrusteeFormW");
    p_gt_name_a = (gt_name_fn)GetProcAddress(adv, "GetTrusteeNameA");
    p_gt_name_w = (gt_name_fn)GetProcAddress(adv, "GetTrusteeNameW");
    p_gt_type_a = (gt_type_fn)GetProcAddress(adv, "GetTrusteeTypeA");
    p_gt_type_w = (gt_type_fn)GetProcAddress(adv, "GetTrusteeTypeW");
    p_add_allowed_obj = (add_obj_ace_fn)GetProcAddress(adv, "AddAccessAllowedObjectAce");
    p_add_denied_obj = (add_obj_ace_fn)GetProcAddress(adv, "AddAccessDeniedObjectAce");
    p_add_audit = (add_audit_ace_fn)GetProcAddress(adv, "AddAuditAccessAce");
    p_add_audit_ex = (add_audit_ace_ex_fn)GetProcAddress(adv, "AddAuditAccessAceEx");
    p_add_audit_obj = (add_audit_obj_ace_fn)GetProcAddress(adv, "AddAuditAccessObjectAce");
    p_add_allowed_ex = (add_ace_ex_fn)GetProcAddress(adv, "AddAccessAllowedAceEx");
    p_add_denied_ex = (add_ace_ex_fn)GetProcAddress(adv, "AddAccessDeniedAceEx");
    p_sd_str_a = (sd_to_str_a_fn)GetProcAddress(adv, "ConvertSecurityDescriptorToStringSecurityDescriptorA");
    p_sd_str_w = (sd_to_str_w_fn)GetProcAddress(adv, "ConvertSecurityDescriptorToStringSecurityDescriptorW");
    p_str_sd_a = (str_to_sd_a_fn)GetProcAddress(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorA");
    p_str_sd_w = (str_to_sd_w_fn)GetProcAddress(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    p_open_token = (open_process_token_fn)GetProcAddress(adv, "OpenProcessToken");
    p_create_priv = (create_priv_obj_fn)GetProcAddress(adv, "CreatePrivateObjectSecurity");
    p_create_priv_ex = (create_priv_obj_ex_fn)GetProcAddress(adv, "CreatePrivateObjectSecurityEx");
    p_destroy_priv = (destroy_priv_obj_fn)GetProcAddress(adv, "DestroyPrivateObjectSecurity");
    p_get_priv = (get_priv_obj_fn)GetProcAddress(adv, "GetPrivateObjectSecurity");
    p_set_priv = (set_priv_obj_fn)GetProcAddress(adv, "SetPrivateObjectSecurity");
    p_set_priv_ex = (set_priv_obj_ex_fn)GetProcAddress(adv, "SetPrivateObjectSecurityEx");
    p_convert_auto = (convert_auto_inherit_fn)GetProcAddress(adv, "ConvertToAutoInheritPrivateObjectSecurity");
    p_set_sd_ctrl = (set_sd_control_fn)GetProcAddress(adv, "SetSecurityDescriptorControl");
    p_get_rm = (get_rm_fn)GetProcAddress(adv, "GetSecurityDescriptorRMControl");
    p_set_rm = (set_rm_fn)GetProcAddress(adv, "SetSecurityDescriptorRMControl");
    p_build_sd_a = (build_sd_fn)GetProcAddress(adv, "BuildSecurityDescriptorA");
    p_build_sd_w = (build_sd_fn)GetProcAddress(adv, "BuildSecurityDescriptorW");
    p_conv_acc_sd_a = (conv_access_to_sd_fn)GetProcAddress(adv, "ConvertAccessToSecurityDescriptorA");
    p_conv_acc_sd_w = (conv_access_to_sd_fn)GetProcAddress(adv, "ConvertAccessToSecurityDescriptorW");
    p_conv_sd_acc_a = (conv_sd_to_access_fn)GetProcAddress(adv, "ConvertSecurityDescriptorToAccessA");
    p_conv_sd_acc_w = (conv_sd_to_access_fn)GetProcAddress(adv, "ConvertSecurityDescriptorToAccessW");
    p_conv_sd_acc_named_a = (conv_sd_to_access_named_fn)GetProcAddress(adv, "ConvertSecurityDescriptorToAccessNamedA");
    p_conv_sd_acc_named_w = (conv_sd_to_access_named_fn)GetProcAddress(adv, "ConvertSecurityDescriptorToAccessNamedW");
    p_get_audited_a = (get_audited_perms_fn)GetProcAddress(adv, "GetAuditedPermissionsFromAclA");
    p_get_audited_w = (get_audited_perms_fn)GetProcAddress(adv, "GetAuditedPermissionsFromAclW");
    p_set_audit_a = (set_entries_audit_a_fn)GetProcAddress(adv, "SetEntriesInAuditListA");
    p_set_audit_w = (set_entries_audit_w_fn)GetProcAddress(adv, "SetEntriesInAuditListW");
    p_equal_domain = (equal_domain_sid_fn)GetProcAddress(adv, "EqualDomainSid");
    p_get_win_domain = (get_windows_domain_fn)GetProcAddress(adv, "GetWindowsAccountDomainSid");
    p_get_site_token = (get_site_sid_token_fn)GetProcAddress(adv, "GetSiteSidFromToken");
    p_get_mangled = (get_mangled_site_fn)GetProcAddress(adv, "GetMangledSiteSid");
    p_is_wk = (is_well_known_fn)GetProcAddress(adv, "IsWellKnownSid");
    p_lookup_name_a = (lookup_account_name_a_fn)GetProcAddress(adv, "LookupAccountNameA");
    p_lookup_name_w = (lookup_account_name_w_fn)GetProcAddress(adv, "LookupAccountNameW");
    p_lookup_sid_a = (lookup_account_sid_a_fn)GetProcAddress(adv, "LookupAccountSidA");
    p_lookup_sid_w = (lookup_account_sid_w_fn)GetProcAddress(adv, "LookupAccountSidW");
    ntdll = GetModuleHandleA("ntdll.dll");
    p_rtl_copy_sd = (rtl_copy_sd_fn)GetProcAddress(ntdll, "RtlCopySecurityDescriptor");
    return run_sections("sdacl", sections, argc, argv);
}
