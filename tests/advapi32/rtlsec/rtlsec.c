/*
 * rtlsec - ntdll's Rtl* security exports, called directly through
 * GetProcAddress on GetModuleHandleA("ntdll.dll") as the corpus pattern
 * for ntdll calls (the prototypes are declared here, as the fixtures
 * that call ntdll do; the names are the public API's): the security
 * descriptor calls (create, length, validity, control and attributes,
 * the RM control, the owner/group/DACL/SACL get and set round trips, and
 * the self-relative conversions in both directions), the SID calls, the
 * ACL calls, the ACE builders, the LUID calls, the access-granted checks
 * and the object security calls. The fixture sits in advapi32's group
 * because that DLL's behavior the Rtl* calls stand behind; the one
 * advapi32 call it makes, OpenProcessToken, is direct.
 *
 * The descriptors, ACLs and SIDs are built by hand where a section needs
 * one without calling another section's export (the layouts are public),
 * so every export is pinned by the one section that calls it. Every call
 * under observation is armed with the last-error sentinel first; a call
 * the real machine may fault on is inside __try (GUARD below), so the
 * fault's code prints instead of ending the process.
 *
 * Output is machine-stable: only well-known SIDs (authority {0,0,0,0,0,5}
 * with the built-in sub-authorities 32/544, 32/545, 18, and Everyone) are
 * built and printed, in their string form; an SD the system built (a file's,
 * a new object's) prints its shape only - revision, control, which parts
 * are present - never the SIDs in it. Masks print in hex, statuses as
 * 0x%08lX.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   rtlsd     RtlCreateSecurityDescriptor, RtlLengthSecurityDescriptor,
 *             RtlValidSecurityDescriptor, RtlValidRelativeSecurity-
 *             Descriptor, the control and attributes get/set, the RM
 *             control get/set, the owner/group/DACL/SACL get/set round
 *             trips, RtlMakeSelfRelativeSD, RtlAbsoluteToSelfRelativeSD,
 *             RtlSelfRelativeToAbsoluteSD, RtlSelfRelativeToAbsoluteSD2
 *   rtlsid    RtlAllocateAndInitializeSid, RtlInitializeSid, the length
 *             and validity queries, RtlEqualSid, RtlEqualPrefixSid, the
 *             sub-authority and identifier-authority queries, RtlCopySid,
 *             RtlCopySidAndAttributesArray, RtlConvertSidToUnicodeString,
 *             RtlFreeSid
 *   rtlacl    RtlCreateAcl, RtlValidAcl, RtlQueryInformationAcl,
 *             RtlSetInformationAcl, RtlGetAce, RtlFirstFreeAce,
 *             RtlDeleteAce, RtlAddAce
 *   rtlace    the ACE builders: RtlAddAccessAllowedAce(Ex, ObjectAce),
 *             RtlAddAccessDeniedAce(Ex, ObjectAce),
 *             RtlAddAuditAccessAce(Ex, ObjectAce), RtlAddCompoundAce,
 *             each read back by walking the ACL by hand
 *   rtlluid   RtlEqualLuid, RtlCopyLuid, RtlCopyLuidAndAttributesArray
 *   rtlcheck  RtlAreAllAccessesGranted, RtlAreAnyAccessesGranted,
 *             RtlNewSecurityGrantedAccess over the process token
 *   rtlobj    RtlNewSecurityObject(Ex), RtlNewInstanceSecurityObject,
 *             RtlCreateUserSecurityObject, RtlDeleteSecurityObject,
 *             RtlConvertToAutoInheritSecurityObject, RtlCreateAndSetSD,
 *             RtlDefaultNpAcl, and RtlQuerySecurityObject/
 *             RtlSetSecurityObject(Ex) on a temp file's handle
 *   rtlself   RtlImpersonateSelf (last: it gives the thread a token)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat rtlsec):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% rtlsec.c advapi32.lib
 */

#include "../common/f2kt.h"

/* --- the Rtl* security calls, through GetProcAddress ------------------- */
/* NTSTATUS is the status type the calls answer; the MSVC 6 SDK headers
 * predate it. PSECURITY_DESCRIPTOR is opaque there, so a descriptor's
 * header fields are read at their public offsets (sd_control below). */
typedef LONG NTSTATUS;

/* A GUID as the object-ACE calls take it (16 bytes, the layout is public). */
typedef struct {
    DWORD data1;
    WORD data2;
    WORD data3;
    BYTE data4[8];
} f2kt_guid_t;

/* The control bit SetSecurityDescriptorControl takes for SE_DACL_PROTECTED
 * (public value). */
#ifndef SE_DACL_PROTECTED_C
#define SE_DACL_PROTECTED_C 0x1000
#endif

/* The ACE type bytes of the object and compound ACEs (public values; the
 * MSVC 6 headers predate them). */
#define F2KT_ACE_ALLOWED_COMPOUND 0x4
#define F2KT_ACE_ALLOWED_OBJECT 0x5
#define F2KT_ACE_DENIED_OBJECT 0x6
#define F2KT_ACE_AUDIT_OBJECT 0x7

/* The ACL information classes (public values) and their structures. */
#define F2KT_ACL_REVISION_INFO 1
#define F2KT_ACL_SIZE_INFO 2
typedef struct {
    ULONG AclRevision;
} f2kt_acl_revision_info_t;
typedef struct {
    ULONG AceCount;
    ULONG AclBytesInUse;
    ULONG AclBytesFree;
} f2kt_acl_size_info_t;

/* A UNICODE_STRING as the string calls take it (the layout is public). */
typedef struct {
    unsigned short Length;
    unsigned short MaximumLength;
    WCHAR *Buffer;
} f2kt_unicode_string_t;

/* SID_AND_ATTRIBUTES and LUID_AND_ATTRIBUTES (the layouts are public). */
typedef struct {
    PSID Sid;
    ULONG Attributes;
} f2kt_sid_and_attributes_t;
typedef struct {
    LUID Luid;
    ULONG Attributes;
} f2kt_luid_and_attributes_t;

/* The security descriptor calls. */
typedef NTSTATUS (WINAPI *rtl_create_sd_fn)(PSECURITY_DESCRIPTOR, DWORD);
typedef DWORD (WINAPI *rtl_sd_len_fn)(PSECURITY_DESCRIPTOR);
typedef BOOL (WINAPI *rtl_valid_sd_fn)(PSECURITY_DESCRIPTOR);
typedef BOOL (WINAPI *rtl_valid_rel_sd_fn)(PSECURITY_DESCRIPTOR, DWORD, DWORD);
typedef BOOL (WINAPI *rtl_get_control_fn)(PSECURITY_DESCRIPTOR, unsigned short *, PULONG);
typedef BOOL (WINAPI *rtl_set_control_fn)(PSECURITY_DESCRIPTOR, DWORD, DWORD);
typedef BOOL (WINAPI *rtl_set_attrs_fn)(PSECURITY_DESCRIPTOR, DWORD, PULONG);
typedef BOOL (WINAPI *rtl_get_rm_fn)(PSECURITY_DESCRIPTOR, PUCHAR);
typedef BOOL (WINAPI *rtl_set_rm_fn)(PSECURITY_DESCRIPTOR, PUCHAR);
typedef BOOL (WINAPI *rtl_get_owner_fn)(PSECURITY_DESCRIPTOR, PSID *, PULONG);
typedef BOOL (WINAPI *rtl_set_owner_fn)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *rtl_get_group_fn)(PSECURITY_DESCRIPTOR, PSID *, PULONG);
typedef BOOL (WINAPI *rtl_set_group_fn)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *rtl_get_dacl_fn)(PSECURITY_DESCRIPTOR, PULONG, PACL *, PULONG);
typedef BOOL (WINAPI *rtl_set_dacl_fn)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef BOOL (WINAPI *rtl_get_sacl_fn)(PSECURITY_DESCRIPTOR, PULONG, PACL *, PULONG);
typedef BOOL (WINAPI *rtl_set_sacl_fn)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef NTSTATUS (WINAPI *rtl_make_self_rel_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG);
typedef NTSTATUS (WINAPI *rtl_abs_to_self_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG);
typedef NTSTATUS (WINAPI *rtl_self_to_abs_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PULONG, PACL, PULONG,
                                             PACL, PULONG, PSID, PULONG, PSID, PULONG);
typedef NTSTATUS (WINAPI *rtl_self_to_abs2_fn)(PVOID, PULONG);

/* The SID calls. */
typedef NTSTATUS (WINAPI *rtl_init_sid_fn)(PSID, PSID_IDENTIFIER_AUTHORITY, BYTE);
typedef DWORD (WINAPI *rtl_len_req_sid_fn)(DWORD);
typedef DWORD (WINAPI *rtl_len_sid_fn)(PSID);
typedef BOOL (WINAPI *rtl_valid_sid_fn)(PSID);
typedef BOOL (WINAPI *rtl_equal_sid_fn)(PSID, PSID);
typedef BOOL (WINAPI *rtl_equal_prefix_fn)(PSID, PSID);
typedef PUCHAR (WINAPI *rtl_sub_count_fn)(PSID);
typedef PULONG (WINAPI *rtl_sub_sid_fn)(PSID, DWORD);
typedef PSID_IDENTIFIER_AUTHORITY (WINAPI *rtl_id_auth_fn)(PSID);
typedef NTSTATUS (WINAPI *rtl_alloc_sid_fn)(PSID_IDENTIFIER_AUTHORITY, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD,
                                            DWORD, DWORD, DWORD, PSID *);
typedef NTSTATUS (WINAPI *rtl_copy_sid_fn)(DWORD, PSID, PSID);
typedef NTSTATUS (WINAPI *rtl_copy_sid_attr_fn)(DWORD, PVOID, DWORD, PVOID, PSID, PSID *, PULONG);
typedef NTSTATUS (WINAPI *rtl_sid_to_unicode_fn)(f2kt_unicode_string_t *, PSID, BOOL);
typedef PVOID (WINAPI *rtl_free_sid_fn)(PSID);

/* The ACL calls. */
typedef BOOL (WINAPI *rtl_create_acl_fn)(PACL, DWORD, DWORD);
typedef BOOL (WINAPI *rtl_valid_acl_fn)(PACL);
typedef BOOL (WINAPI *rtl_query_acl_fn)(PACL, PVOID, DWORD, DWORD);
typedef BOOL (WINAPI *rtl_set_acl_fn)(PACL, PVOID, DWORD, DWORD);
typedef BOOL (WINAPI *rtl_get_ace_fn)(PACL, DWORD, PVOID *);
typedef BOOL (WINAPI *rtl_first_free_ace_fn)(PACL, PVOID *);
typedef BOOL (WINAPI *rtl_delete_ace_fn)(PACL, DWORD);
typedef BOOL (WINAPI *rtl_add_ace_fn)(PACL, DWORD, DWORD, PVOID, DWORD);

/* The ACE builders. */
typedef BOOL (WINAPI *rtl_add_allowed_ace_fn)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *rtl_add_ace_ex_fn)(PACL, DWORD, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *rtl_add_obj_ace_fn)(PACL, DWORD, DWORD, DWORD, f2kt_guid_t *, f2kt_guid_t *, PSID);
typedef BOOL (WINAPI *rtl_add_audit_ace_fn)(PACL, DWORD, DWORD, PSID, BOOL, BOOL);
typedef BOOL (WINAPI *rtl_add_audit_ex_fn)(PACL, DWORD, DWORD, DWORD, PSID, BOOL, BOOL);
typedef BOOL (WINAPI *rtl_add_audit_obj_fn)(PACL, DWORD, DWORD, DWORD, f2kt_guid_t *, f2kt_guid_t *, PSID, BOOL,
                                            BOOL);
typedef BOOL (WINAPI *rtl_add_compound_ace_fn)(PACL, DWORD, DWORD, DWORD, PSID, PSID);

/* The LUID calls. */
typedef BOOL (WINAPI *rtl_equal_luid_fn)(PLUID, PLUID);
typedef void (WINAPI *rtl_copy_luid_fn)(PLUID, PLUID);
typedef void (WINAPI *rtl_copy_luid_attr_fn)(DWORD, PVOID, PVOID);

/* The access checks. */
typedef BOOL (WINAPI *rtl_all_granted_fn)(DWORD, DWORD);
typedef BOOL (WINAPI *rtl_any_granted_fn)(DWORD, DWORD);
typedef NTSTATUS (WINAPI *rtl_new_granted_fn)(DWORD, PVOID, PULONG, HANDLE, PGENERIC_MAPPING, PULONG);

/* The object security calls. */
typedef NTSTATUS (WINAPI *rtl_new_sec_obj_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                              BOOL, HANDLE, PGENERIC_MAPPING);
typedef NTSTATUS (WINAPI *rtl_new_sec_obj_ex_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
                                                 PVOID, BOOL, DWORD, HANDLE, PGENERIC_MAPPING);
typedef NTSTATUS (WINAPI *rtl_new_instance_fn)(BOOL, BOOL, PVOID, PVOID, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR,
                                               PSECURITY_DESCRIPTOR *, BOOL, HANDLE, PGENERIC_MAPPING);
typedef NTSTATUS (WINAPI *rtl_create_user_sec_obj_fn)(PVOID, DWORD, PSID, PSID, BOOL, PGENERIC_MAPPING,
                                                      PSECURITY_DESCRIPTOR *);
typedef NTSTATUS (WINAPI *rtl_delete_sec_obj_fn)(PSECURITY_DESCRIPTOR);
typedef NTSTATUS (WINAPI *rtl_set_sec_obj_fn)(DWORD, PSECURITY_DESCRIPTOR, HANDLE, PGENERIC_MAPPING, HANDLE);
typedef NTSTATUS (WINAPI *rtl_set_sec_obj_ex_fn)(DWORD, PSECURITY_DESCRIPTOR, HANDLE, DWORD, PGENERIC_MAPPING,
                                                 HANDLE);
typedef NTSTATUS (WINAPI *rtl_query_sec_obj_fn)(HANDLE, DWORD, PSECURITY_DESCRIPTOR, DWORD, PULONG);
typedef NTSTATUS (WINAPI *rtl_convert_auto_inherit_fn)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR,
                                                       PSECURITY_DESCRIPTOR *, PVOID, BOOL, PGENERIC_MAPPING);
typedef NTSTATUS (WINAPI *rtl_create_and_set_sd_fn)(PVOID, DWORD, PSID, PSID, PSECURITY_DESCRIPTOR *);
typedef BOOL (WINAPI *rtl_default_np_acl_fn)(PACL);
typedef NTSTATUS (WINAPI *rtl_impersonate_self_fn)(DWORD);

static rtl_create_sd_fn p_create_sd;
static rtl_sd_len_fn p_sd_len;
static rtl_valid_sd_fn p_valid_sd;
static rtl_valid_rel_sd_fn p_valid_rel;
static rtl_get_control_fn p_get_control;
static rtl_set_control_fn p_set_control;
static rtl_set_attrs_fn p_set_attrs;
static rtl_get_rm_fn p_get_rm;
static rtl_set_rm_fn p_set_rm;
static rtl_get_owner_fn p_get_owner;
static rtl_set_owner_fn p_set_owner;
static rtl_get_group_fn p_get_group;
static rtl_set_group_fn p_set_group;
static rtl_get_dacl_fn p_get_dacl;
static rtl_set_dacl_fn p_set_dacl;
static rtl_get_sacl_fn p_get_sacl;
static rtl_set_sacl_fn p_set_sacl;
static rtl_make_self_rel_fn p_make_self_rel;
static rtl_abs_to_self_fn p_abs_to_self;
static rtl_self_to_abs_fn p_self_to_abs;
static rtl_self_to_abs2_fn p_self_to_abs2;

static rtl_init_sid_fn p_init_sid;
static rtl_len_req_sid_fn p_len_req_sid;
static rtl_len_sid_fn p_len_sid;
static rtl_valid_sid_fn p_valid_sid;
static rtl_equal_sid_fn p_equal_sid;
static rtl_equal_prefix_fn p_equal_prefix;
static rtl_sub_count_fn p_sub_count;
static rtl_sub_sid_fn p_sub_sid;
static rtl_id_auth_fn p_id_auth;
static rtl_alloc_sid_fn p_alloc_sid;
static rtl_copy_sid_fn p_copy_sid;
static rtl_copy_sid_attr_fn p_copy_sid_attr;
static rtl_sid_to_unicode_fn p_sid_to_unicode;
static rtl_free_sid_fn p_free_sid;

static rtl_create_acl_fn p_create_acl;
static rtl_valid_acl_fn p_valid_acl;
static rtl_query_acl_fn p_query_acl;
static rtl_set_acl_fn p_set_acl;
static rtl_get_ace_fn p_get_ace;
static rtl_first_free_ace_fn p_first_free;
static rtl_delete_ace_fn p_delete_ace;
static rtl_add_ace_fn p_add_ace;

static rtl_add_allowed_ace_fn p_add_allowed, p_add_denied;
static rtl_add_ace_ex_fn p_add_allowed_ex, p_add_denied_ex;
static rtl_add_obj_ace_fn p_add_allowed_obj, p_add_denied_obj;
static rtl_add_audit_ace_fn p_add_audit;
static rtl_add_audit_ex_fn p_add_audit_ex;
static rtl_add_audit_obj_fn p_add_audit_obj;
static rtl_add_compound_ace_fn p_add_compound;

static rtl_equal_luid_fn p_equal_luid;
static rtl_copy_luid_fn p_copy_luid;
static rtl_copy_luid_attr_fn p_copy_luid_attr;

static rtl_all_granted_fn p_all_granted;
static rtl_any_granted_fn p_any_granted;
static rtl_new_granted_fn p_new_granted;

static rtl_new_sec_obj_fn p_new_obj;
static rtl_new_sec_obj_ex_fn p_new_obj_ex;
static rtl_new_instance_fn p_new_instance;
static rtl_create_user_sec_obj_fn p_create_user_obj;
static rtl_delete_sec_obj_fn p_delete_sec_obj;
static rtl_set_sec_obj_fn p_set_sec_obj;
static rtl_set_sec_obj_ex_fn p_set_sec_obj_ex;
static rtl_query_sec_obj_fn p_query_sec_obj;
static rtl_convert_auto_inherit_fn p_convert_auto;
static rtl_create_and_set_sd_fn p_create_and_set_sd;
static rtl_default_np_acl_fn p_default_np_acl;
static rtl_impersonate_self_fn p_impersonate_self;

static HMODULE ntdll;

/* --- buffers and helpers ---------------------------------------------- */

static ULONG sd_buf[512];               /* 2 KiB, an absolute SD */
static ULONG rel_buf[512];              /* 2 KiB, a self-relative SD */
static ULONG out_buf[512];              /* 2 KiB, conversions and queries */
static ULONG conv_buf[1024];            /* 4 KiB, RtlSelfRelativeToAbsoluteSD's pieces */
static ULONG sd2_buf[1024];             /* 4 KiB, RtlSelfRelativeToAbsoluteSD2's buffer */
static ULONG acl_buf[256];              /* 1 KiB, an ACL */
static ULONG ace_buf[64];               /* one ACE and its SID */
static ULONG sid_buf[64];               /* one SID */
static ULONG tmp_buf[256];              /* 1 KiB, a hand-built ACL or SD */

/* The well-known SIDs this program builds by hand (the layout is
 * public): S-1-1-0, S-1-5-18, S-1-5-32-544, S-1-5-32-545, S-1-5-32, S-1-5. */
typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid5_t sid_system = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 18 } };
static const sid5_t sid_admins = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };
static const sid5_t sid_users = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 545 } };
static const sid5_t sid_builtin = { 1, 1, { 0, 0, 0, 0, 0, 5 }, { 32 } };

/* One ACE as the hand-built ACLs take it. */
typedef struct {
    int type;                           /* the ACE type byte */
    DWORD mask;
    const void *sid;
} ace_spec_t;

static const ace_spec_t allow_everyone[] = {
    { ACCESS_ALLOWED_ACE_TYPE, 0x000F01FF, &sid_everyone }
};
static const ace_spec_t audit_everyone[] = {
    { SYSTEM_AUDIT_ACE_TYPE, 0x000F01FF, &sid_everyone }
};

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

/* Whether the exports a section needs are there: a section whose call is
 * missing prints "not found" and stops. */
static int have(const char *name, void *p)
{
    if (p == NULL) {
        line("%s not found", name);
        return 0;
    }
    return 1;
}

static int have_all(int n, ...)
{
    va_list ap;
    int i, ok = 1;

    va_start(ap, n);
    for (i = 0; i < n; i++) {
        const char *name = va_arg(ap, const char *);
        void *p = va_arg(ap, void *);
        if (p == NULL) {
            line("%s not found", name);
            ok = 0;
        }
    }
    va_end(ap);
    return ok;
}

/* One call the real machine may fault on, inside __try: the fault's code
 * and the error print instead of ending the process. */
static DWORD g_code, g_err;
#define GUARD(stmt)                                                                                                    \
    do {                                                                                                               \
        g_code = 0;                                                                                                    \
        g_err = F2KT_UNTOUCHED;                                                                                        \
        __try {                                                                                                        \
            stmt;                                                                                                      \
            g_err = GetLastError();                                                                                    \
        } __except (EXCEPTION_EXECUTE_HANDLER) {                                                                      \
            g_code = GetExceptionCode();                                                                               \
            g_err = F2KT_UNTOUCHED;                                                                                    \
        }                                                                                                              \
    } while (0)

/* Builds an ACL in buf by hand (the layout is public): no Rtl call, so a
 * section that pins only the ACE builders can still give them an ACL. */
static void hand_acl(BYTE *buf, ULONG size, BYTE revision, const ace_spec_t *aces, int count)
{
    PACL acl = (PACL)buf;
    BYTE *q = buf + 8;
    int i;

    memset(buf, 0, size);
    acl->AclRevision = revision;
    acl->AclSize = 8;
    acl->AceCount = (unsigned short)count;
    for (i = 0; i < count; i++) {
        ACE_HEADER *h = (ACE_HEADER *)q;
        DWORD ssize = sid_size(aces[i].sid);

        h->AceType = (BYTE)aces[i].type;
        h->AceFlags = 0;
        h->AceSize = (unsigned short)(8 + ssize);
        *(DWORD *)(q + 4) = aces[i].mask;
        memcpy(q + 8, aces[i].sid, ssize);
        q += h->AceSize;
    }
    acl->AclSize = (unsigned short)(q - buf);
}

static ULONG acl_size(const BYTE *acl)
{
    return ((const ACL *)acl)->AclSize;
}

/* Builds an absolute SD in buf by hand: owner and group SIDs and a DACL
 * after the 20-byte header, as pointers (the absolute form). */
static void hand_abs_sd(BYTE *buf, ULONG size, const void *owner, const void *group, const BYTE *dacl,
                        ULONG dacl_size)
{
    BYTE *p = buf;
    ULONG off_owner, off_group, off_dacl;

    memset(buf, 0, size);
    off_owner = 20;
    off_group = off_owner + sid_size(owner);
    off_dacl = off_group + sid_size(group);
    p[0] = SECURITY_DESCRIPTOR_REVISION;
    *(unsigned short *)(p + 2) = SE_DACL_PRESENT;
    *(PSID *)(p + 4) = (PSID)(p + off_owner);
    *(PSID *)(p + 8) = (PSID)(p + off_group);
    *(PACL *)(p + 16) = (PACL)(p + off_dacl);
    memcpy(p + off_owner, owner, sid_size(owner));
    memcpy(p + off_group, group, sid_size(group));
    memcpy(p + off_dacl, dacl, dacl_size);
}

/* Builds a self-relative SD in buf by hand: owner and a DACL, at their
 * offsets in the 20-byte header. */
static void hand_self_rel_sd(BYTE *buf, ULONG size, const void *owner, const BYTE *dacl, ULONG dacl_size)
{
    BYTE *p = buf;
    ULONG off_owner, off_dacl;

    memset(buf, 0, size);
    off_owner = 20;
    off_dacl = off_owner + sid_size(owner);
    p[0] = SECURITY_DESCRIPTOR_REVISION;
    *(unsigned short *)(p + 2) = (unsigned short)(SE_SELF_RELATIVE | SE_DACL_PRESENT);
    *(DWORD *)(p + 4) = off_owner;     /* the owner */
    *(DWORD *)(p + 16) = off_dacl;     /* the DACL */
    memcpy(p + off_owner, owner, sid_size(owner));
    memcpy(p + off_dacl, dacl, dacl_size);
}

/* An SD's shape only: revision, control, which parts are present. Never
 * the SIDs in it - an SD the system built names the machine's account. */
static void show_sd_shape(const char *label, const BYTE *p)
{
    line("%s: revision %u, control 0x%04X; owner %s, group %s, SACL %s, DACL %s", label, (unsigned)p[0],
         sd_control(p), yesno(*(const DWORD *)(p + 4) != 0), yesno(*(const DWORD *)(p + 8) != 0),
         yesno(*(const DWORD *)(p + 12) != 0), yesno(*(const DWORD *)(p + 16) != 0));
}

/* Walks an ACL by hand, printing each ACE's header and mask: no Rtl call,
 * so a section that pins only the ACE builders can read them back. */
static void walk_aces(const char *label, const BYTE *acl)
{
    const ACE_HEADER *h;
    DWORD i, off, count = ((const ACL *)acl)->AceCount;

    line("%s: revision %u, size %u, AceCount %u", label, (unsigned)((const ACL *)acl)->AclRevision,
         (unsigned)((const ACL *)acl)->AclSize, (unsigned)count);
    off = 8;
    for (i = 0; i < count && i < 16 && off + 8 <= ((const ACL *)acl)->AclSize; i++) {
        h = (const ACE_HEADER *)(acl + off);
        line("  ACE %lu: type %u, flags 0x%X, size %u, mask 0x%08lX", i, (unsigned)h->AceType,
             (unsigned)h->AceFlags, (unsigned)h->AceSize, (unsigned long)*(const DWORD *)(acl + off + 4));
        off += h->AceSize;
    }
}

static void init_mapping(PGENERIC_MAPPING mapping)
{
    mapping->GenericRead = 0x80000000;
    mapping->GenericWrite = 0x40000000;
    mapping->GenericExecute = 0x20000000;
    mapping->GenericAll = 0x10000000;
}

/* --- rtlsd --------------------------------------------------------------- */

static void sec_rtlsd(void)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    BYTE *rel = (BYTE *)rel_buf;
    BYTE *conv = (BYTE *)conv_buf;
    unsigned short control;
    ULONG revision, len, rel_len, present, defaulted, need;
    ULONG abs_len, dacl_len, sacl_len, owner_len, group_len;
    PSID owner;
    PACL dacl;
    BYTE rm;
    LONG st;
    BOOL r;

    if (!have_all(21, "RtlCreateSecurityDescriptor", (void *)p_create_sd, "RtlLengthSecurityDescriptor",
                  (void *)p_sd_len, "RtlValidSecurityDescriptor", (void *)p_valid_sd,
                  "RtlValidRelativeSecurityDescriptor", (void *)p_valid_rel, "RtlGetControlSecurityDescriptor",
                  (void *)p_get_control, "RtlSetControlSecurityDescriptor", (void *)p_set_control,
                  "RtlSetAttributesSecurityDescriptor", (void *)p_set_attrs, "RtlGetSecurityDescriptorRMControl",
                  (void *)p_get_rm, "RtlSetSecurityDescriptorRMControl", (void *)p_set_rm,
                  "RtlGetOwnerSecurityDescriptor", (void *)p_get_owner, "RtlSetOwnerSecurityDescriptor",
                  (void *)p_set_owner, "RtlGetGroupSecurityDescriptor", (void *)p_get_group,
                  "RtlSetGroupSecurityDescriptor", (void *)p_set_group, "RtlGetDaclSecurityDescriptor",
                  (void *)p_get_dacl, "RtlSetDaclSecurityDescriptor", (void *)p_set_dacl,
                  "RtlGetSaclSecurityDescriptor", (void *)p_get_sacl, "RtlSetSaclSecurityDescriptor",
                  (void *)p_set_sacl, "RtlMakeSelfRelativeSD", (void *)p_make_self_rel,
                  "RtlAbsoluteToSelfRelativeSD", (void *)p_abs_to_self, "RtlSelfRelativeToAbsoluteSD",
                  (void *)p_self_to_abs, "RtlSelfRelativeToAbsoluteSD2", (void *)p_self_to_abs2)) {
        return;
    }

    memset(sd_buf, 0xCC, sizeof sd_buf);
    arm();
    st = p_create_sd(sd, SECURITY_DESCRIPTOR_REVISION);
    line("RtlCreateSecurityDescriptor(sd, REVISION): status=0x%08lX err=%s; control 0x%04X", (unsigned long)st, le(),
         sd_control(sd));

    arm();
    len = p_sd_len(sd);
    line("RtlLengthSecurityDescriptor(the initialized SD): ret=%lu err=%s", len, le());

    arm();
    r = p_valid_sd(sd);
    line("RtlValidSecurityDescriptor(the absolute SD): ret=%d err=%s", r, le());
    ((BYTE *)sd)[0] = 0xCC;
    arm();
    r = p_valid_sd(sd);
    line("RtlValidSecurityDescriptor(a bad revision): ret=%d err=%s", r, le());
    ((BYTE *)sd)[0] = SECURITY_DESCRIPTOR_REVISION;

    control = 0;
    revision = 0;
    arm();
    r = p_get_control(sd, &control, &revision);
    line("RtlGetControlSecurityDescriptor: ret=%d err=%s; control 0x%04X, revision %lu", r, le(), control, revision);

    arm();
    r = p_set_control(sd, SE_DACL_PROTECTED_C, SE_DACL_PROTECTED_C);
    line("RtlSetControlSecurityDescriptor(SE_DACL_PROTECTED, set): ret=%d err=%s; control now 0x%04X", r, le(),
         sd_control(sd));
    arm();
    r = p_set_control(sd, SE_DACL_PROTECTED_C, 0);
    line("RtlSetControlSecurityDescriptor(SE_DACL_PROTECTED, clear): ret=%d err=%s; control now 0x%04X", r, le(),
         sd_control(sd));

    revision = F2KT_UNTOUCHED;
    arm();
    r = p_set_attrs(sd, SE_DACL_PRESENT, &revision);
    line("RtlSetAttributesSecurityDescriptor(SE_DACL_PRESENT, &revision): ret=%d err=%s; control now 0x%04X, revision %s",
         r, le(), sd_control(sd), le_of(revision));
    arm();
    r = p_set_control(sd, 0xFFFF, 0);
    line("RtlSetControlSecurityDescriptor(all bits, clear): ret=%d err=%s; control now 0x%04X", r, le(),
         sd_control(sd));

    rm = 0xCC;
    arm();
    r = p_get_rm(sd, &rm);
    line("RtlGetSecurityDescriptorRMControl: ret=%d err=%s; byte 0x%02X", r, le(), (unsigned)rm);
    rm = 0;
    arm();
    r = p_set_rm(sd, &rm);
    line("RtlSetSecurityDescriptorRMControl(0): ret=%d err=%s", r, le());
    rm = 0xCC;
    arm();
    r = p_get_rm(sd, &rm);
    line("RtlGetSecurityDescriptorRMControl again: ret=%d err=%s; byte 0x%02X", r, le(), (unsigned)rm);

    /* The owner/group/DACL/SACL round trips, the ACLs built by hand. */
    hand_acl((BYTE *)tmp_buf, sizeof tmp_buf, ACL_REVISION, allow_everyone, 1);
    arm();
    r = p_set_owner(sd, (PSID)&sid_admins, FALSE);
    line("RtlSetOwnerSecurityDescriptor(S-1-5-32-544, not defaulted): ret=%d err=%s", r, le());
    owner = NULL;
    defaulted = F2KT_UNTOUCHED;
    arm();
    r = p_get_owner(sd, &owner, &defaulted);
    line("RtlGetOwnerSecurityDescriptor: ret=%d err=%s; owner %s, defaulted %s", r, le(),
         owner != NULL ? sid_text(owner) : "NULL", le_of(defaulted));

    arm();
    r = p_set_group(sd, (PSID)&sid_everyone, TRUE);
    line("RtlSetGroupSecurityDescriptor(S-1-1-0, defaulted): ret=%d err=%s", r, le());
    owner = NULL;
    defaulted = F2KT_UNTOUCHED;
    arm();
    r = p_get_group(sd, &owner, &defaulted);
    line("RtlGetGroupSecurityDescriptor: ret=%d err=%s; group %s, defaulted %s", r, le(),
         owner != NULL ? sid_text(owner) : "NULL", le_of(defaulted));

    arm();
    r = p_set_dacl(sd, TRUE, (PACL)tmp_buf, FALSE);
    line("RtlSetDaclSecurityDescriptor(present, one allowed ACE): ret=%d err=%s; control 0x%04X", r, le(),
         sd_control(sd));
    present = F2KT_UNTOUCHED;
    dacl = NULL;
    defaulted = F2KT_UNTOUCHED;
    arm();
    r = p_get_dacl(sd, &present, &dacl, &defaulted);
    line("RtlGetDaclSecurityDescriptor: ret=%d err=%s; present %s, the ACL %s, defaulted %s", r, le(),
         le_of(present), dacl != NULL ? "set" : "NULL", le_of(defaulted));
    if (dacl != NULL) {
        line("  the DACL: revision %u, size %u, AceCount %u", (unsigned)dacl->AclRevision, (unsigned)dacl->AclSize,
             (unsigned)dacl->AceCount);
    }
    arm();
    r = p_set_dacl(sd, FALSE, NULL, FALSE);
    line("RtlSetDaclSecurityDescriptor(not present, NULL): ret=%d err=%s; control 0x%04X", r, le(), sd_control(sd));
    present = F2KT_UNTOUCHED;
    dacl = NULL;
    arm();
    r = p_get_dacl(sd, &present, &dacl, &defaulted);
    line("RtlGetDaclSecurityDescriptor after the clear: ret=%d err=%s; present %s, the ACL %s", r, le(), le_of(present),
         dacl != NULL ? "set" : "NULL");
    arm();
    r = p_set_dacl(sd, TRUE, (PACL)tmp_buf, FALSE);
    line("RtlSetDaclSecurityDescriptor(back): ret=%d err=%s", r, le());

    hand_acl((BYTE *)tmp_buf, sizeof tmp_buf, ACL_REVISION, audit_everyone, 1);
    arm();
    r = p_set_sacl(sd, TRUE, (PACL)tmp_buf, FALSE);
    line("RtlSetSaclSecurityDescriptor(present, one audit ACE): ret=%d err=%s; control 0x%04X", r, le(),
         sd_control(sd));
    present = F2KT_UNTOUCHED;
    dacl = NULL;
    defaulted = F2KT_UNTOUCHED;
    arm();
    r = p_get_sacl(sd, &present, &dacl, &defaulted);
    line("RtlGetSaclSecurityDescriptor: ret=%d err=%s; present %s, the ACL %s, defaulted %s", r, le(), le_of(present),
         dacl != NULL ? "set" : "NULL", le_of(defaulted));

    /* The self-relative conversions. */
    len = 0;
    arm();
    st = p_make_self_rel(sd, (PSECURITY_DESCRIPTOR)rel, &len);
    line("RtlMakeSelfRelativeSD(size query): status=0x%08lX err=%s; the length needed %s", (unsigned long)st, le(),
         le_of(len));
    rel_len = len;
    if (len != 0 && len <= sizeof rel_buf) {
        arm();
        st = p_make_self_rel(sd, (PSECURITY_DESCRIPTOR)rel, &len);
        line("RtlMakeSelfRelativeSD(the length asked for): status=0x%08lX err=%s; length %lu, control 0x%04X",
             (unsigned long)st, le(), len, sd_control(rel));
        arm();
        len = p_sd_len((PSECURITY_DESCRIPTOR)rel);
        line("RtlLengthSecurityDescriptor(the self-relative SD): ret=%lu err=%s", len, le());
        arm();
        r = p_valid_sd((PSECURITY_DESCRIPTOR)rel);
        line("RtlValidSecurityDescriptor(the self-relative SD): ret=%d err=%s", r, le());
        arm();
        r = p_valid_rel((PSECURITY_DESCRIPTOR)rel, len, len);
        line("RtlValidRelativeSecurityDescriptor(len, len): ret=%d err=%s", r, le());
        arm();
        r = p_valid_rel((PSECURITY_DESCRIPTOR)rel, len - 1, len);
        line("RtlValidRelativeSecurityDescriptor(a byte short): ret=%d err=%s", r, le());
        arm();
        r = p_valid_rel((PSECURITY_DESCRIPTOR)rel, len, len + 8);
        line("RtlValidRelativeSecurityDescriptor(a longer requirement): ret=%d err=%s", r, le());
    }

    len = 0;
    arm();
    st = p_abs_to_self(sd, (PSECURITY_DESCRIPTOR)out_buf, &len);
    line("RtlAbsoluteToSelfRelativeSD(size query): status=0x%08lX err=%s; the length needed %s", (unsigned long)st,
         le(), le_of(len));
    if (len != 0 && len <= sizeof out_buf) {
        arm();
        st = p_abs_to_self(sd, (PSECURITY_DESCRIPTOR)out_buf, &len);
        line("RtlAbsoluteToSelfRelativeSD(the length asked for): status=0x%08lX err=%s; length %lu, control 0x%04X",
             (unsigned long)st, le(), len, sd_control(out_buf));
    }

    /* RtlSelfRelativeToAbsoluteSD: the pieces in conv_buf, after the
     * absolute SD it writes there. */
    if (rel_len != 0 && rel_len <= sizeof rel_buf) {
        abs_len = 0;
        dacl_len = 0;
        sacl_len = 0;
        owner_len = 0;
        group_len = 0;
        GUARD(st = p_self_to_abs((PSECURITY_DESCRIPTOR)rel, (PSECURITY_DESCRIPTOR)conv, &abs_len,
                                 (PACL)(conv + 256), &dacl_len, (PACL)(conv + 512), &sacl_len,
                                 (PSID)(conv + 640), &owner_len, (PSID)(conv + 768), &group_len));
        if (g_code != 0) {
            line("RtlSelfRelativeToAbsoluteSD(the size query): faulted 0x%08lX", g_code);
        } else {
            line("RtlSelfRelativeToAbsoluteSD(the size query): status=0x%08lX err=%s; abs %lu, DACL %lu, SACL %lu, owner %lu, group %lu",
                 (unsigned long)st, le_of(g_err), abs_len, dacl_len, sacl_len, owner_len, group_len);
        }
        if (g_code == 0 && abs_len != 0 && abs_len <= 1024 && dacl_len <= 1024 && sacl_len <= 1024 && owner_len <= 256
            && group_len <= 256) {
            GUARD(st = p_self_to_abs((PSECURITY_DESCRIPTOR)rel, (PSECURITY_DESCRIPTOR)conv, &abs_len,
                                     (PACL)(conv + 256), &dacl_len, (PACL)(conv + 512), &sacl_len,
                                     (PSID)(conv + 640), &owner_len, (PSID)(conv + 768), &group_len));
            if (g_code != 0) {
                line("RtlSelfRelativeToAbsoluteSD(the sizes asked for): faulted 0x%08lX", g_code);
            } else {
                line("RtlSelfRelativeToAbsoluteSD(the sizes asked for): status=0x%08lX err=%s", (unsigned long)st,
                     le_of(g_err));
                show_sd_shape("  the absolute SD", conv);
            }
        }

        /* RtlSelfRelativeToAbsoluteSD2 expands in place. */
        memcpy(sd2_buf, rel, rel_len);
        need = sizeof sd2_buf;
        GUARD(st = p_self_to_abs2(sd2_buf, &need));
        if (g_code != 0) {
            line("RtlSelfRelativeToAbsoluteSD2(a 4 KiB buffer): faulted 0x%08lX", g_code);
        } else {
            line("RtlSelfRelativeToAbsoluteSD2(a 4 KiB buffer): status=0x%08lX err=%s; the size now %lu",
                 (unsigned long)st, le_of(g_err), need);
            show_sd_shape("  the SD2 result", (const BYTE *)sd2_buf);
        }
        memcpy(sd2_buf, rel, rel_len);
        need = 8;
        GUARD(st = p_self_to_abs2(sd2_buf, &need));
        if (g_code != 0) {
            line("RtlSelfRelativeToAbsoluteSD2(an 8-byte buffer): faulted 0x%08lX", g_code);
        } else {
            line("RtlSelfRelativeToAbsoluteSD2(an 8-byte buffer): status=0x%08lX err=%s; the size now %lu",
                 (unsigned long)st, le_of(g_err), need);
        }
    }
}

/* --- rtlsid -------------------------------------------------------------- */

static void sec_rtlsid(void)
{
    static SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL, bare = NULL;
    PSID_IDENTIFIER_AUTHORITY ia;
    PUCHAR cnt;
    PULONG sub;
    f2kt_unicode_string_t us;
    WCHAR wbuf[64];
    f2kt_sid_and_attributes_t src[1], dst[1];
    BYTE sidspace[64];
    PSID next;
    DWORD len, r32, remaining, i;
    LONG st;
    BOOL r;
    PVOID freed;

    if (!have_all(14, "RtlInitializeSid", (void *)p_init_sid, "RtlLengthRequiredSid", (void *)p_len_req_sid,
                  "RtlLengthSid", (void *)p_len_sid, "RtlValidSid", (void *)p_valid_sid, "RtlEqualSid",
                  (void *)p_equal_sid, "RtlEqualPrefixSid", (void *)p_equal_prefix, "RtlSubAuthorityCountSid",
                  (void *)p_sub_count, "RtlSubAuthoritySid", (void *)p_sub_sid, "RtlIdentifierAuthoritySid",
                  (void *)p_id_auth, "RtlAllocateAndInitializeSid", (void *)p_alloc_sid, "RtlCopySid",
                  (void *)p_copy_sid, "RtlCopySidAndAttributesArray", (void *)p_copy_sid_attr,
                  "RtlConvertSidToUnicodeString", (void *)p_sid_to_unicode, "RtlFreeSid", (void *)p_free_sid)) {
        return;
    }

    arm();
    st = p_alloc_sid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins);
    line("RtlAllocateAndInitializeSid(S-1-5-32-544): status=0x%08lX err=%s; %s", (unsigned long)st, le(),
         admins != NULL ? sid_text(admins) : "NULL");
    if (admins != NULL) {
        arm();
        len = p_len_sid(admins);
        line("RtlLengthSid: ret=%lu err=%s; 16: %s", len, le(), yesno(len == 16));
        arm();
        r = p_valid_sid(admins);
        line("RtlValidSid: ret=%d err=%s", r, le());
        arm();
        r = p_equal_sid(admins, (PSID)&sid_admins);
        line("RtlEqualSid(it, the hand-built S-1-5-32-544): ret=%d err=%s", r, le());
        arm();
        r = p_equal_sid(admins, (PSID)&sid_everyone);
        line("RtlEqualSid(it, Everyone): ret=%d err=%s", r, le());
        arm();
        r = p_equal_prefix(admins, (PSID)&sid_builtin);
        line("RtlEqualPrefixSid(it, S-1-5-32): ret=%d err=%s", r, le());
        arm();
        r = p_equal_prefix((PSID)&sid_builtin, admins);
        line("RtlEqualPrefixSid(S-1-5-32, it): ret=%d err=%s", r, le());
        arm();
        r = p_equal_prefix(admins, admins);
        line("RtlEqualPrefixSid(it, itself): ret=%d err=%s", r, le());

        arm();
        cnt = p_sub_count(admins);
        line("RtlSubAuthorityCountSid: the count %s", cnt != NULL ? le_of((DWORD)*cnt) : "NULL");
        arm();
        sub = p_sub_sid(admins, 0);
        line("RtlSubAuthoritySid(0): %s", sub != NULL ? le_of(*sub) : "NULL");
        arm();
        sub = p_sub_sid(admins, 1);
        line("RtlSubAuthoritySid(1): %s", sub != NULL ? le_of(*sub) : "NULL");
        arm();
        sub = p_sub_sid(admins, 5);
        line("RtlSubAuthoritySid(5, past the end): %s", sub != NULL ? le_of(*sub) : "NULL");
        arm();
        ia = p_id_auth(admins);
        line("RtlIdentifierAuthoritySid: the authority %02X%02X%02X%02X%02X%02X",
             ia != NULL ? (unsigned)ia->Value[0] : 0, ia != NULL ? (unsigned)ia->Value[1] : 0,
             ia != NULL ? (unsigned)ia->Value[2] : 0, ia != NULL ? (unsigned)ia->Value[3] : 0,
             ia != NULL ? (unsigned)ia->Value[4] : 0, ia != NULL ? (unsigned)ia->Value[5] : 0);

        memset(sid_buf, 0xCC, sizeof sid_buf);
        arm();
        r32 = p_copy_sid((DWORD)sizeof sid_buf, (PSID)sid_buf, admins);
        line("RtlCopySid(256, ...): ret=%lu err=%s; the copy %s", r32, le(), sid_text(sid_buf));
        arm();
        r32 = p_copy_sid(4, (PSID)sid_buf, admins);
        line("RtlCopySid(4, ...): ret=%lu err=%s", r32, le());

        us.Length = 0;
        us.MaximumLength = (unsigned short)sizeof wbuf;
        us.Buffer = wbuf;
        arm();
        st = p_sid_to_unicode(&us, admins, FALSE);
        line("RtlConvertSidToUnicodeString(room, Allocate=FALSE): status=0x%08lX err=%s; string %s, length %u",
             (unsigned long)st, le(), ws(us.Buffer), (unsigned)us.Length);
        us.Length = 0;
        us.MaximumLength = 4;
        us.Buffer = wbuf;
        arm();
        st = p_sid_to_unicode(&us, admins, FALSE);
        line("RtlConvertSidToUnicodeString(a 4-byte buffer): status=0x%08lX err=%s; length %u", (unsigned long)st,
             le(), (unsigned)us.Length);
        us.Length = 0;
        us.MaximumLength = 0;
        us.Buffer = NULL;
        GUARD(st = p_sid_to_unicode(&us, admins, TRUE));
        if (g_code != 0) {
            line("RtlConvertSidToUnicodeString(Allocate=TRUE): faulted 0x%08lX", g_code);
        } else {
            line("RtlConvertSidToUnicodeString(Allocate=TRUE): status=0x%08lX err=%s; string %s, length %u",
                 (unsigned long)st, le_of(g_err), us.Buffer != NULL ? ws(us.Buffer) : "(null)",
                 (unsigned)us.Length);
            /* ntdll allocated the string from the process heap; the
             * fixture is short-lived, so it is left there. */
        }
        us.Length = 0;
        us.MaximumLength = (unsigned short)sizeof wbuf;
        us.Buffer = wbuf;
        GUARD(st = p_sid_to_unicode(&us, NULL, FALSE));
        if (g_code != 0) {
            line("RtlConvertSidToUnicodeString(NULL sid): faulted 0x%08lX", g_code);
        } else {
            line("RtlConvertSidToUnicodeString(NULL sid): status=0x%08lX err=%s", (unsigned long)st, le_of(g_err));
        }

        /* RtlCopySidAndAttributesArray: one entry, into a buffer laid out
         * as the array followed by the SID. */
        src[0].Sid = (PSID)&sid_admins;
        src[0].Attributes = 7;
        memset(dst, 0, sizeof dst);
        memset(sidspace, 0xCC, sizeof sidspace);
        next = NULL;
        remaining = F2KT_UNTOUCHED;
        arm();
        st = p_copy_sid_attr(1, src, (DWORD)(sizeof dst + sizeof sidspace), dst, (PSID)sidspace, &next, &remaining);
        line("RtlCopySidAndAttributesArray(1 entry): status=0x%08lX err=%s; remaining %s, the SID %s, the next SID %ld bytes on",
             (unsigned long)st, le(), le_of(remaining), sid_text(sidspace),
             next != NULL ? (long)((BYTE *)next - sidspace) : -1L);

        arm();
        freed = p_free_sid(admins);
        line("RtlFreeSid(it): returned NULL: %s err=%s", yesno(freed == NULL), le());
        admins = NULL;
    }

    /* S-1-5 with no sub-authorities. */
    arm();
    st = p_alloc_sid(&nt, 0, 0, 0, 0, 0, 0, 0, 0, 0, &bare);
    line("RtlAllocateAndInitializeSid(S-1-5): status=0x%08lX err=%s; %s", (unsigned long)st, le(),
         bare != NULL ? sid_text(bare) : "NULL");
    if (bare != NULL) {
        arm();
        freed = p_free_sid(bare);
        line("RtlFreeSid(S-1-5): returned NULL: %s err=%s", yesno(freed == NULL), le());
    }

    /* RtlInitializeSid by hand, the sub-authorities written through
     * RtlSubAuthoritySid. */
    memset(sid_buf, 0, sizeof sid_buf);
    arm();
    st = p_init_sid((PSID)sid_buf, &nt, 2);
    line("RtlInitializeSid(sid, the NT authority, 2): status=0x%08lX err=%s; the count %u", (unsigned long)st, le(),
         (unsigned)((BYTE *)sid_buf)[1]);
    sub = p_sub_sid((PSID)sid_buf, 0);
    if (sub != NULL) {
        *sub = SECURITY_BUILTIN_DOMAIN_RID;
    }
    sub = p_sub_sid((PSID)sid_buf, 1);
    if (sub != NULL) {
        *sub = DOMAIN_ALIAS_RID_ADMINS;
    }
    line("  after writing the sub-authorities: %s", sid_text(sid_buf));
    arm();
    len = p_len_sid((PSID)sid_buf);
    line("RtlLengthSid(the hand-initialized): ret=%lu err=%s", len, le());
    arm();
    r = p_valid_sid((PSID)sid_buf);
    line("RtlValidSid(the hand-initialized): ret=%d err=%s", r, le());
    arm();
    r = p_equal_sid((PSID)sid_buf, (PSID)&sid_admins);
    line("RtlEqualSid(it, the hand-built admins): ret=%d err=%s", r, le());

    for (i = 0; i <= 2; i++) {
        arm();
        len = p_len_req_sid(i);
        line("RtlLengthRequiredSid(%lu): ret=%lu err=%s", i, len, le());
    }
    arm();
    len = p_len_req_sid(15);
    line("RtlLengthRequiredSid(15): ret=%lu err=%s", len, le());
}

/* --- rtlacl -------------------------------------------------------------- */

static void sec_rtlacl(void)
{
    PACL acl = (PACL)acl_buf;
    ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)ace_buf;
    f2kt_acl_revision_info_t rev_info;
    f2kt_acl_size_info_t size_info;
    PVOID p;
    DWORD ssize, index;
    BOOL r;

    if (!have_all(8, "RtlCreateAcl", (void *)p_create_acl, "RtlValidAcl", (void *)p_valid_acl,
                  "RtlQueryInformationAcl", (void *)p_query_acl, "RtlSetInformationAcl", (void *)p_set_acl,
                  "RtlGetAce", (void *)p_get_ace, "RtlFirstFreeAce", (void *)p_first_free, "RtlDeleteAce",
                  (void *)p_delete_ace, "RtlAddAce", (void *)p_add_ace)) {
        return;
    }

    memset(acl_buf, 0xCC, sizeof acl_buf);
    arm();
    r = p_create_acl(acl, (DWORD)sizeof acl_buf, ACL_REVISION);
    line("RtlCreateAcl(1024, ACL_REVISION): ret=%d err=%s; revision %u, size %u, AceCount %u", r, le(),
         (unsigned)acl->AclRevision, (unsigned)acl->AclSize, (unsigned)acl->AceCount);
    arm();
    r = p_create_acl(acl, 8, ACL_REVISION);
    line("RtlCreateAcl(8, ACL_REVISION): ret=%d err=%s", r, le());
    arm();
    r = p_create_acl(acl, (DWORD)sizeof acl_buf, ACL_REVISION);
    line("RtlCreateAcl(1024, ACL_REVISION) again: ret=%d err=%s", r, le());

    arm();
    r = p_valid_acl(acl);
    line("RtlValidAcl: ret=%d err=%s", r, le());
    acl->AclRevision = 0xCC;
    arm();
    r = p_valid_acl(acl);
    line("RtlValidAcl(a bad revision): ret=%d err=%s", r, le());
    acl->AclRevision = ACL_REVISION;

    memset(&rev_info, 0, sizeof rev_info);
    arm();
    r = p_query_acl(acl, &rev_info, (DWORD)sizeof rev_info, F2KT_ACL_REVISION_INFO);
    line("RtlQueryInformationAcl(AclRevisionInformation): ret=%d err=%s; the revision %lu", r, le(), rev_info.AclRevision);
    memset(&size_info, 0, sizeof size_info);
    arm();
    r = p_query_acl(acl, &size_info, (DWORD)sizeof size_info, F2KT_ACL_SIZE_INFO);
    line("RtlQueryInformationAcl(AclSizeInformation): ret=%d err=%s; AceCount %lu, in use %lu, free %lu", r, le(),
         size_info.AceCount, size_info.AclBytesInUse, size_info.AclBytesFree);
    arm();
    r = p_query_acl(acl, &size_info, 4, F2KT_ACL_SIZE_INFO);
    line("RtlQueryInformationAcl(a 4-byte buffer): ret=%d err=%s", r, le());
    arm();
    r = p_query_acl(acl, &rev_info, (DWORD)sizeof rev_info, 0xFFFF);
    line("RtlQueryInformationAcl(an unknown class): ret=%d err=%s", r, le());

    rev_info.AclRevision = ACL_REVISION;
    arm();
    r = p_set_acl(acl, &rev_info, (DWORD)sizeof rev_info, F2KT_ACL_REVISION_INFO);
    line("RtlSetInformationAcl(AclRevisionInformation, ACL_REVISION): ret=%d err=%s", r, le());
    memset(&rev_info, 0, sizeof rev_info);
    arm();
    r = p_query_acl(acl, &rev_info, (DWORD)sizeof rev_info, F2KT_ACL_REVISION_INFO);
    line("RtlQueryInformationAcl(read back): ret=%d err=%s; the revision %lu", r, le(), rev_info.AclRevision);
    rev_info.AclRevision = 0xCC;
    arm();
    r = p_set_acl(acl, &rev_info, (DWORD)sizeof rev_info, F2KT_ACL_REVISION_INFO);
    line("RtlSetInformationAcl(a bad revision): ret=%d err=%s", r, le());
    memset(&size_info, 0, sizeof size_info);
    arm();
    r = p_set_acl(acl, &size_info, (DWORD)sizeof size_info, F2KT_ACL_SIZE_INFO);
    line("RtlSetInformationAcl(AclSizeInformation, read-only): ret=%d err=%s", r, le());

    /* One ACE built by hand, added with RtlAddAce. */
    ssize = sid_size(&sid_everyone);
    memset(ace_buf, 0, sizeof ace_buf);
    ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace->Header.AceFlags = 0;
    ace->Header.AceSize = (unsigned short)(sizeof(ACCESS_ALLOWED_ACE) + ssize);
    ace->Mask = 0x000F01FF;
    memcpy(&ace->SidStart, &sid_everyone, ssize);
    arm();
    r = p_add_ace(acl, ACL_REVISION, 0, ace_buf, ace->Header.AceSize);
    line("RtlAddAce(ACL_REVISION, index 0, one allowed ACE): ret=%d err=%s; AceCount %u, AclSize %u", r, le(),
         (unsigned)acl->AceCount, (unsigned)acl->AclSize);
    arm();
    r = p_add_ace(acl, ACL_REVISION, 0, ace_buf, ace->Header.AceSize);
    line("RtlAddAce(again at index 0): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_ace(acl, ACL_REVISION, 99, ace_buf, ace->Header.AceSize);
    line("RtlAddAce(index 99, past the end): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);

    for (index = 0; index < 3; index++) {
        p = NULL;
        arm();
        r = p_get_ace(acl, index, &p);
        if (r && p != NULL) {
            ACE_HEADER *h = (ACE_HEADER *)p;
            line("RtlGetAce(%lu): ret=%d err=%s; type %u, flags 0x%X, size %u, mask 0x%08lX, sid %s", index, r, le(),
                 (unsigned)h->AceType, (unsigned)h->AceFlags, (unsigned)h->AceSize,
                 (unsigned long)*(DWORD *)((BYTE *)p + 4), sid_text((BYTE *)p + 8));
        } else {
            line("RtlGetAce(%lu): ret=%d err=%s", index, r, le());
        }
    }

    p = NULL;
    arm();
    r = p_first_free(acl, &p);
    line("RtlFirstFreeAce: ret=%d err=%s; the ACE %s, %ld bytes into the ACL", r, le(),
         p != NULL ? "set" : "NULL", p != NULL ? (long)((BYTE *)p - (BYTE *)acl) : -1L);

    arm();
    r = p_delete_ace(acl, 0);
    line("RtlDeleteAce(0): ret=%d err=%s; AceCount %u, AclSize %u", r, le(), (unsigned)acl->AceCount,
         (unsigned)acl->AclSize);
    arm();
    r = p_delete_ace(acl, 99);
    line("RtlDeleteAce(99, past the end): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_valid_acl(acl);
    line("RtlValidAcl after the deletes: ret=%d err=%s", r, le());
}

/* --- rtlace -------------------------------------------------------------- */

static void sec_rtlace(void)
{
    PACL acl = (PACL)acl_buf;
    f2kt_guid_t guid;
    BOOL r;

    if (!have_all(10, "RtlAddAccessAllowedAce", (void *)p_add_allowed, "RtlAddAccessAllowedAceEx",
                  (void *)p_add_allowed_ex, "RtlAddAccessAllowedObjectAce", (void *)p_add_allowed_obj,
                  "RtlAddAccessDeniedAce", (void *)p_add_denied, "RtlAddAccessDeniedAceEx", (void *)p_add_denied_ex,
                  "RtlAddAccessDeniedObjectAce", (void *)p_add_denied_obj, "RtlAddAuditAccessAce", (void *)p_add_audit,
                  "RtlAddAuditAccessAceEx", (void *)p_add_audit_ex, "RtlAddAuditAccessObjectAce",
                  (void *)p_add_audit_obj, "RtlAddCompoundAce", (void *)p_add_compound)) {
        return;
    }

    memset(&guid, 0, sizeof guid);
    guid.data1 = 0xF2F2F2F2u;
    /* The ACL header by hand: RtlCreateAcl belongs to rtlacl. */
    memset(acl_buf, 0, sizeof acl_buf);
    acl->AclRevision = ACL_REVISION;
    acl->AclSize = (unsigned short)sizeof acl_buf;
    acl->AceCount = 0;

    arm();
    r = p_add_allowed(acl, ACL_REVISION, 0x000F01FF, (PSID)&sid_everyone);
    line("RtlAddAccessAllowedAce(Everyone, 0x000F01FF): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed_ex(acl, ACL_REVISION, 0, 0x00000008, (PSID)&sid_everyone);
    line("RtlAddAccessAllowedAceEx(Everyone, 8): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed_obj(acl, ACL_REVISION, 0, 0x00000010, NULL, NULL, (PSID)&sid_everyone);
    line("RtlAddAccessAllowedObjectAce(Everyone, 0x10, no GUIDs): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_allowed_obj(acl, ACL_REVISION, 0, 0x00000020, &guid, NULL, (PSID)&sid_system);
    line("RtlAddAccessAllowedObjectAce(SYSTEM, 0x20, one GUID): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_denied(acl, ACL_REVISION, 0x00000001, (PSID)&sid_everyone);
    line("RtlAddAccessDeniedAce(Everyone, 1): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_denied_ex(acl, ACL_REVISION, 0, 0x00000002, (PSID)&sid_everyone);
    line("RtlAddAccessDeniedAceEx(Everyone, 2): ret=%d err=%s; AceCount %u", r, le(), (unsigned)acl->AceCount);
    arm();
    r = p_add_denied_obj(acl, ACL_REVISION, 0, 0x00000004, NULL, NULL, (PSID)&sid_everyone);
    line("RtlAddAccessDeniedObjectAce(Everyone, 4, no GUIDs): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_audit(acl, ACL_REVISION, 0x00000040, (PSID)&sid_everyone, TRUE, TRUE);
    line("RtlAddAuditAccessAce(Everyone, 0x40, success and failure): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_audit_ex(acl, ACL_REVISION, 0, 0x00000080, (PSID)&sid_everyone, TRUE, FALSE);
    line("RtlAddAuditAccessAceEx(Everyone, 0x80, success only): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_audit_obj(acl, ACL_REVISION, 0, 0x00000100, NULL, NULL, (PSID)&sid_everyone, TRUE, TRUE);
    line("RtlAddAuditAccessObjectAce(Everyone, 0x100, no GUIDs): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);
    arm();
    r = p_add_compound(acl, ACL_REVISION, F2KT_ACE_ALLOWED_COMPOUND, 0x00000200, (PSID)&sid_system,
                       (PSID)&sid_everyone);
    line("RtlAddCompoundAce(compound, 0x200, SYSTEM and Everyone): ret=%d err=%s; AceCount %u", r, le(),
         (unsigned)acl->AceCount);

    walk_aces("the ACEs as added", (const BYTE *)acl);
}

/* --- rtlluid ------------------------------------------------------------- */

static void sec_rtlluid(void)
{
    LUID a, b, c;
    f2kt_luid_and_attributes_t src[2], dst[2];
    BOOL r;

    if (!have_all(3, "RtlEqualLuid", (void *)p_equal_luid, "RtlCopyLuid", (void *)p_copy_luid,
                  "RtlCopyLuidAndAttributesArray", (void *)p_copy_luid_attr)) {
        return;
    }

    a.LowPart = 19;
    a.HighPart = 0;
    b.LowPart = 20;
    b.HighPart = 0;
    memset(&c, 0, sizeof c);

    arm();
    r = p_equal_luid(&a, &a);
    line("RtlEqualLuid(19, 19): ret=%d err=%s", r, le());
    arm();
    r = p_equal_luid(&a, &b);
    line("RtlEqualLuid(19, 20): ret=%d err=%s", r, le());

    arm();
    p_copy_luid(&c, &a);
    line("RtlCopyLuid(19): low=%lu high=%ld err=%s", c.LowPart, c.HighPart, le());

    src[0].Luid = a;
    src[0].Attributes = 3;
    src[1].Luid = b;
    src[1].Attributes = 5;
    memset(dst, 0, sizeof dst);
    arm();
    p_copy_luid_attr(2, src, dst);
    line("RtlCopyLuidAndAttributesArray(2): dst0 low=%lu attr=%lu, dst1 low=%lu attr=%lu err=%s", dst[0].Luid.LowPart,
         dst[0].Attributes, dst[1].Luid.LowPart, dst[1].Attributes, le());
    memset(dst, 0, sizeof dst);
    arm();
    p_copy_luid_attr(1, src, dst);
    line("RtlCopyLuidAndAttributesArray(1): dst0 low=%lu attr=%lu err=%s", dst[0].Luid.LowPart, dst[0].Attributes,
         le());
}

/* --- rtlcheck ------------------------------------------------------------ */

static void sec_rtlcheck(void)
{
    GENERIC_MAPPING mapping;
    PRIVILEGE_SET privs;
    HANDLE token = NULL;
    ULONG priv_len, remaining;
    LONG st;
    BOOL r;

    if (!have_all(3, "RtlAreAllAccessesGranted", (void *)p_all_granted, "RtlAreAnyAccessesGranted",
                  (void *)p_any_granted, "RtlNewSecurityGrantedAccess", (void *)p_new_granted)) {
        return;
    }
    init_mapping(&mapping);

    arm();
    r = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): ret=%d err=%s, %s", r, le(),
         r && token != NULL ? "a handle" : "no handle");
    if (!r || token == NULL) {
        return;
    }

    arm();
    r = p_all_granted(0x000F01FF, 0x00000001);
    line("RtlAreAllAccessesGranted(0x000F01FF, 0x1): ret=%d err=%s", r, le());
    arm();
    r = p_all_granted(0x00000001, 0x000F01FF);
    line("RtlAreAllAccessesGranted(0x1, 0x000F01FF): ret=%d err=%s", r, le());
    arm();
    r = p_all_granted(0x000F01FF, 0x000F01FF);
    line("RtlAreAllAccessesGranted(0x000F01FF, 0x000F01FF): ret=%d err=%s", r, le());
    arm();
    r = p_any_granted(0x00000001, 0x00000002);
    line("RtlAreAnyAccessesGranted(0x1, 0x2): ret=%d err=%s", r, le());
    arm();
    r = p_any_granted(0x00000004, 0x00000002);
    line("RtlAreAnyAccessesGranted(0x4, 0x2): ret=%d err=%s", r, le());

    privs.PrivilegeCount = 0;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    priv_len = (ULONG)sizeof privs;
    remaining = F2KT_UNTOUCHED;
    arm();
    st = p_new_granted(0, &privs, &priv_len, token, &mapping, &remaining);
    line("RtlNewSecurityGrantedAccess(desired 0, the process token): status=0x%08lX err=%s; PrivilegesLength %lu, remaining %s",
         (unsigned long)st, le(), priv_len, le_of(remaining));
    priv_len = (ULONG)sizeof privs;
    remaining = F2KT_UNTOUCHED;
    GUARD(st = p_new_granted(0, NULL, &priv_len, token, &mapping, &remaining));
    if (g_code != 0) {
        line("RtlNewSecurityGrantedAccess(desired 0, no privileges buffer): faulted 0x%08lX", g_code);
    } else {
        line("RtlNewSecurityGrantedAccess(desired 0, no privileges buffer): status=0x%08lX err=%s; remaining %s",
             (unsigned long)st, le_of(g_err), le_of(remaining));
    }

    arm();
    r = CloseHandle(token);
    line("CloseHandle(the token): ret=%d err=%s", r, le());
}

/* --- rtlobj -------------------------------------------------------------- */

static void sec_rtlobj(void)
{
    static const char name_a[] = "rtlsec.tmp";
    GENERIC_MAPPING mapping;
    PSECURITY_DESCRIPTOR creator = (PSECURITY_DESCRIPTOR)tmp_buf;
    PSECURITY_DESCRIPTOR newsd = NULL, newsd_ex = NULL, newsd_inst = NULL, newsd_user = NULL, newsd_auto = NULL;
    PSECURITY_DESCRIPTOR newsd_set = NULL;
    f2kt_guid_t guid;
    BYTE aclspace[256];
    HANDLE token = NULL, h;
    ULONG need, len;
    LONG st;
    BOOL r;

    if (!have_all(11, "RtlNewSecurityObject", (void *)p_new_obj, "RtlNewSecurityObjectEx", (void *)p_new_obj_ex,
                  "RtlNewInstanceSecurityObject", (void *)p_new_instance, "RtlCreateUserSecurityObject",
                  (void *)p_create_user_obj, "RtlDeleteSecurityObject", (void *)p_delete_sec_obj,
                  "RtlSetSecurityObject", (void *)p_set_sec_obj, "RtlSetSecurityObjectEx", (void *)p_set_sec_obj_ex,
                  "RtlQuerySecurityObject", (void *)p_query_sec_obj, "RtlConvertToAutoInheritSecurityObject",
                  (void *)p_convert_auto, "RtlCreateAndSetSD", (void *)p_create_and_set_sd, "RtlDefaultNpAcl",
                  (void *)p_default_np_acl)) {
        return;
    }
    init_mapping(&mapping);
    memset(&guid, 0, sizeof guid);
    guid.data1 = 0xF2F2F2F2u;

    /* An absolute creator SD by hand: owner S-1-5-32-544, group Everyone,
     * a DACL allowing Everyone. */
    hand_acl(aclspace, sizeof aclspace, ACL_REVISION, allow_everyone, 1);
    hand_abs_sd((BYTE *)tmp_buf, sizeof tmp_buf, &sid_admins, &sid_everyone, aclspace, acl_size(aclspace));

    arm();
    r = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    line("OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY): ret=%d err=%s, %s", r, le(),
         r && token != NULL ? "a handle" : "no handle");
    if (!r || token == NULL) {
        return;
    }

    GUARD(st = p_new_obj(NULL, creator, &newsd, FALSE, token, &mapping));
    if (g_code != 0) {
        line("RtlNewSecurityObject(no parent, the creator SD): faulted 0x%08lX", g_code);
    } else {
        line("RtlNewSecurityObject(no parent, the creator SD): status=0x%08lX err=%s; the new SD %s",
             (unsigned long)st, le_of(g_err), newsd != NULL ? "set" : "NULL");
        if (newsd != NULL) {
            show_sd_shape("  it", (const BYTE *)newsd);
        }
    }

    GUARD(st = p_new_obj_ex(NULL, creator, &newsd_ex, &guid, FALSE, 0, token, &mapping));
    if (g_code != 0) {
        line("RtlNewSecurityObjectEx(no parent, one GUID, flags 0): faulted 0x%08lX", g_code);
    } else {
        line("RtlNewSecurityObjectEx(no parent, one GUID, flags 0): status=0x%08lX err=%s; the new SD %s",
             (unsigned long)st, le_of(g_err), newsd_ex != NULL ? "set" : "NULL");
        if (newsd_ex != NULL) {
            show_sd_shape("  it", (const BYTE *)newsd_ex);
        }
    }

    GUARD(st = p_new_instance(FALSE, TRUE, NULL, NULL, NULL, creator, &newsd_inst, FALSE, token, &mapping));
    if (g_code != 0) {
        line("RtlNewInstanceSecurityObject(creator changed, no parent): faulted 0x%08lX", g_code);
    } else {
        line("RtlNewInstanceSecurityObject(creator changed, no parent): status=0x%08lX err=%s; the new SD %s",
             (unsigned long)st, le_of(g_err), newsd_inst != NULL ? "set" : "NULL");
        if (newsd_inst != NULL) {
            show_sd_shape("  it", (const BYTE *)newsd_inst);
        }
    }

    GUARD(st = p_create_user_obj(NULL, 0, (PSID)&sid_admins, (PSID)&sid_everyone, FALSE, &mapping, &newsd_user));
    if (g_code != 0) {
        line("RtlCreateUserSecurityObject(no ACEs, owner admins, group Everyone): faulted 0x%08lX", g_code);
    } else {
        line("RtlCreateUserSecurityObject(no ACEs, owner admins, group Everyone): status=0x%08lX err=%s; the new SD %s",
             (unsigned long)st, le_of(g_err), newsd_user != NULL ? "set" : "NULL");
        if (newsd_user != NULL) {
            show_sd_shape("  it", (const BYTE *)newsd_user);
        }
    }

    if (newsd != NULL) {
        GUARD(st = p_delete_sec_obj(newsd));
        if (g_code != 0) {
            line("RtlDeleteSecurityObject(the SD RtlNewSecurityObject allocated): faulted 0x%08lX", g_code);
        } else {
            line("RtlDeleteSecurityObject(the SD RtlNewSecurityObject allocated): status=0x%08lX err=%s",
                 (unsigned long)st, le_of(g_err));
        }
        newsd = NULL;
    }

    /* A self-relative SD by hand, as the current descriptor. */
    hand_acl(aclspace, sizeof aclspace, ACL_REVISION, allow_everyone, 1);
    hand_self_rel_sd((BYTE *)out_buf, sizeof out_buf, &sid_everyone, aclspace, acl_size(aclspace));
    GUARD(st = p_convert_auto(NULL, (PSECURITY_DESCRIPTOR)out_buf, &newsd_auto, NULL, FALSE, &mapping));
    if (g_code != 0) {
        line("RtlConvertToAutoInheritSecurityObject(no parent, the hand-built SD): faulted 0x%08lX", g_code);
    } else {
        line("RtlConvertToAutoInheritSecurityObject(no parent, the hand-built SD): status=0x%08lX err=%s; the new SD %s",
             (unsigned long)st, le_of(g_err), newsd_auto != NULL ? "set" : "NULL");
        if (newsd_auto != NULL) {
            show_sd_shape("  it", (const BYTE *)newsd_auto);
        }
    }

    GUARD(st = p_create_and_set_sd(NULL, 0, (PSID)&sid_admins, (PSID)&sid_everyone, &newsd_set));
    if (g_code != 0) {
        line("RtlCreateAndSetSD(no ACEs, owner admins, group Everyone): faulted 0x%08lX", g_code);
    } else {
        line("RtlCreateAndSetSD(no ACEs, owner admins, group Everyone): status=0x%08lX err=%s; the new SD %s",
             (unsigned long)st, le_of(g_err), newsd_set != NULL ? "set" : "NULL");
        if (newsd_set != NULL) {
            show_sd_shape("  it", (const BYTE *)newsd_set);
        }
    }

    /* RtlDefaultNpAcl: the shape only, its ACEs name the account. */
    memset(acl_buf, 0, sizeof acl_buf);
    arm();
    r = p_default_np_acl((PACL)acl_buf);
    line("RtlDefaultNpAcl(a 1 KiB buffer): ret=%d err=%s; revision %u, size %u, AceCount %u", r, le(),
         (unsigned)((PACL)acl_buf)->AclRevision, (unsigned)((PACL)acl_buf)->AclSize, (unsigned)((PACL)acl_buf)->AceCount);

    /* The object handle calls, on a temp file. */
    arm();
    h = CreateFileA(name_a, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    line("CreateFileA(%s, CREATE_ALWAYS): %s err=%s", name_a,
         h != INVALID_HANDLE_VALUE && h != NULL ? "a handle" : "NULL", le());
    if (h != INVALID_HANDLE_VALUE && h != NULL) {
        need = F2KT_UNTOUCHED;
        GUARD(st = p_query_sec_obj(h, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                                          | DACL_SECURITY_INFORMATION,
                                   NULL, 0, &need));
        if (g_code != 0) {
            line("RtlQuerySecurityObject(the file handle, no buffer): faulted 0x%08lX", g_code);
        } else {
            line("RtlQuerySecurityObject(the file handle, no buffer): status=0x%08lX err=%s; the size needed %s",
                 (unsigned long)st, le_of(g_err), le_of(need));
        }
        if (need != F2KT_UNTOUCHED && need >= 20 && need <= sizeof out_buf) {
            memset(out_buf, 0, sizeof out_buf);
            len = need;
            arm();
            st = p_query_sec_obj(h, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
                                          | DACL_SECURITY_INFORMATION,
                                 (PSECURITY_DESCRIPTOR)out_buf, len, &need);
            line("RtlQuerySecurityObject(the size asked for): status=0x%08lX err=%s", (unsigned long)st, le());
            if (st >= 0) {
                show_sd_shape("  the file's SD", (const BYTE *)out_buf);
            }
        }

        hand_acl(aclspace, sizeof aclspace, ACL_REVISION, allow_everyone, 1);
        hand_self_rel_sd((BYTE *)rel_buf, sizeof rel_buf, &sid_everyone, aclspace, acl_size(aclspace));
        arm();
        st = p_set_sec_obj(DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)rel_buf, h, &mapping, token);
        line("RtlSetSecurityObject(the file handle, DACL): status=0x%08lX err=%s", (unsigned long)st, le());
        memset(out_buf, 0, sizeof out_buf);
        len = (ULONG)sizeof out_buf;
        arm();
        st = p_query_sec_obj(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, len, &need);
        line("RtlQuerySecurityObject(the DACL read back): status=0x%08lX err=%s", (unsigned long)st, le());
        if (st >= 0) {
            show_sd_shape("  the file's SD now", (const BYTE *)out_buf);
        }

        arm();
        st = p_set_sec_obj_ex(DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)rel_buf, h, 0, &mapping, token);
        line("RtlSetSecurityObjectEx(the file handle, DACL, flags 0): status=0x%08lX err=%s", (unsigned long)st, le());
        memset(out_buf, 0, sizeof out_buf);
        len = (ULONG)sizeof out_buf;
        arm();
        st = p_query_sec_obj(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, len, &need);
        line("RtlQuerySecurityObject(read back again): status=0x%08lX err=%s", (unsigned long)st, le());

        arm();
        r = CloseHandle(h);
        line("CloseHandle(the file): ret=%d err=%s", r, le());
        arm();
        st = p_query_sec_obj(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, (ULONG)sizeof out_buf,
                             &len);
        line("RtlQuerySecurityObject(a closed handle): status=0x%08lX err=%s", (unsigned long)st, le());
    }
    arm();
    r = DeleteFileA(name_a);
    line("DeleteFileA(%s): ret=%d err=%s", name_a, r, le());

    arm();
    r = CloseHandle(token);
    line("CloseHandle(the token): ret=%d err=%s", r, le());
}

/* --- rtlself ------------------------------------------------------------- */

static void sec_rtlself(void)
{
    LONG st;

    if (!have_all(1, "RtlImpersonateSelf", (void *)p_impersonate_self)) {
        return;
    }
    /* The impersonation levels (public values): anonymous 0,
     * identification 1, impersonation 2, delegation 3. */
    arm();
    st = p_impersonate_self(2);
    line("RtlImpersonateSelf(SecurityImpersonation): status=0x%08lX err=%s", (unsigned long)st, le());
    arm();
    st = p_impersonate_self(0);
    line("RtlImpersonateSelf(SecurityAnonymous): status=0x%08lX err=%s", (unsigned long)st, le());
    arm();
    st = p_impersonate_self(3);
    line("RtlImpersonateSelf(SecurityDelegation): status=0x%08lX err=%s", (unsigned long)st, le());
}

/* --- main ---------------------------------------------------------------- */

static const section_t sections[] = {
    { "rtlsd", sec_rtlsd, F2KT_ALWAYS },
    { "rtlsid", sec_rtlsid, F2KT_ALWAYS },
    { "rtlacl", sec_rtlacl, F2KT_ALWAYS },
    { "rtlace", sec_rtlace, F2KT_ALWAYS },
    { "rtlluid", sec_rtlluid, F2KT_ALWAYS },
    { "rtlcheck", sec_rtlcheck, F2KT_ALWAYS },
    { "rtlobj", sec_rtlobj, F2KT_ALWAYS },
    { "rtlself", sec_rtlself, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    ntdll = GetModuleHandleA("ntdll.dll");
    p_create_sd = (rtl_create_sd_fn)GetProcAddress(ntdll, "RtlCreateSecurityDescriptor");
    p_sd_len = (rtl_sd_len_fn)GetProcAddress(ntdll, "RtlLengthSecurityDescriptor");
    p_valid_sd = (rtl_valid_sd_fn)GetProcAddress(ntdll, "RtlValidSecurityDescriptor");
    p_valid_rel = (rtl_valid_rel_sd_fn)GetProcAddress(ntdll, "RtlValidRelativeSecurityDescriptor");
    p_get_control = (rtl_get_control_fn)GetProcAddress(ntdll, "RtlGetControlSecurityDescriptor");
    p_set_control = (rtl_set_control_fn)GetProcAddress(ntdll, "RtlSetControlSecurityDescriptor");
    p_set_attrs = (rtl_set_attrs_fn)GetProcAddress(ntdll, "RtlSetAttributesSecurityDescriptor");
    p_get_rm = (rtl_get_rm_fn)GetProcAddress(ntdll, "RtlGetSecurityDescriptorRMControl");
    p_set_rm = (rtl_set_rm_fn)GetProcAddress(ntdll, "RtlSetSecurityDescriptorRMControl");
    p_get_owner = (rtl_get_owner_fn)GetProcAddress(ntdll, "RtlGetOwnerSecurityDescriptor");
    p_set_owner = (rtl_set_owner_fn)GetProcAddress(ntdll, "RtlSetOwnerSecurityDescriptor");
    p_get_group = (rtl_get_group_fn)GetProcAddress(ntdll, "RtlGetGroupSecurityDescriptor");
    p_set_group = (rtl_set_group_fn)GetProcAddress(ntdll, "RtlSetGroupSecurityDescriptor");
    p_get_dacl = (rtl_get_dacl_fn)GetProcAddress(ntdll, "RtlGetDaclSecurityDescriptor");
    p_set_dacl = (rtl_set_dacl_fn)GetProcAddress(ntdll, "RtlSetDaclSecurityDescriptor");
    p_get_sacl = (rtl_get_sacl_fn)GetProcAddress(ntdll, "RtlGetSaclSecurityDescriptor");
    p_set_sacl = (rtl_set_sacl_fn)GetProcAddress(ntdll, "RtlSetSaclSecurityDescriptor");
    p_make_self_rel = (rtl_make_self_rel_fn)GetProcAddress(ntdll, "RtlMakeSelfRelativeSD");
    p_abs_to_self = (rtl_abs_to_self_fn)GetProcAddress(ntdll, "RtlAbsoluteToSelfRelativeSD");
    p_self_to_abs = (rtl_self_to_abs_fn)GetProcAddress(ntdll, "RtlSelfRelativeToAbsoluteSD");
    p_self_to_abs2 = (rtl_self_to_abs2_fn)GetProcAddress(ntdll, "RtlSelfRelativeToAbsoluteSD2");

    p_init_sid = (rtl_init_sid_fn)GetProcAddress(ntdll, "RtlInitializeSid");
    p_len_req_sid = (rtl_len_req_sid_fn)GetProcAddress(ntdll, "RtlLengthRequiredSid");
    p_len_sid = (rtl_len_sid_fn)GetProcAddress(ntdll, "RtlLengthSid");
    p_valid_sid = (rtl_valid_sid_fn)GetProcAddress(ntdll, "RtlValidSid");
    p_equal_sid = (rtl_equal_sid_fn)GetProcAddress(ntdll, "RtlEqualSid");
    p_equal_prefix = (rtl_equal_prefix_fn)GetProcAddress(ntdll, "RtlEqualPrefixSid");
    p_sub_count = (rtl_sub_count_fn)GetProcAddress(ntdll, "RtlSubAuthorityCountSid");
    p_sub_sid = (rtl_sub_sid_fn)GetProcAddress(ntdll, "RtlSubAuthoritySid");
    p_id_auth = (rtl_id_auth_fn)GetProcAddress(ntdll, "RtlIdentifierAuthoritySid");
    p_alloc_sid = (rtl_alloc_sid_fn)GetProcAddress(ntdll, "RtlAllocateAndInitializeSid");
    p_copy_sid = (rtl_copy_sid_fn)GetProcAddress(ntdll, "RtlCopySid");
    p_copy_sid_attr = (rtl_copy_sid_attr_fn)GetProcAddress(ntdll, "RtlCopySidAndAttributesArray");
    p_sid_to_unicode = (rtl_sid_to_unicode_fn)GetProcAddress(ntdll, "RtlConvertSidToUnicodeString");
    p_free_sid = (rtl_free_sid_fn)GetProcAddress(ntdll, "RtlFreeSid");

    p_create_acl = (rtl_create_acl_fn)GetProcAddress(ntdll, "RtlCreateAcl");
    p_valid_acl = (rtl_valid_acl_fn)GetProcAddress(ntdll, "RtlValidAcl");
    p_query_acl = (rtl_query_acl_fn)GetProcAddress(ntdll, "RtlQueryInformationAcl");
    p_set_acl = (rtl_set_acl_fn)GetProcAddress(ntdll, "RtlSetInformationAcl");
    p_get_ace = (rtl_get_ace_fn)GetProcAddress(ntdll, "RtlGetAce");
    p_first_free = (rtl_first_free_ace_fn)GetProcAddress(ntdll, "RtlFirstFreeAce");
    p_delete_ace = (rtl_delete_ace_fn)GetProcAddress(ntdll, "RtlDeleteAce");
    p_add_ace = (rtl_add_ace_fn)GetProcAddress(ntdll, "RtlAddAce");

    p_add_allowed = (rtl_add_allowed_ace_fn)GetProcAddress(ntdll, "RtlAddAccessAllowedAce");
    p_add_allowed_ex = (rtl_add_ace_ex_fn)GetProcAddress(ntdll, "RtlAddAccessAllowedAceEx");
    p_add_allowed_obj = (rtl_add_obj_ace_fn)GetProcAddress(ntdll, "RtlAddAccessAllowedObjectAce");
    p_add_denied = (rtl_add_allowed_ace_fn)GetProcAddress(ntdll, "RtlAddAccessDeniedAce");
    p_add_denied_ex = (rtl_add_ace_ex_fn)GetProcAddress(ntdll, "RtlAddAccessDeniedAceEx");
    p_add_denied_obj = (rtl_add_obj_ace_fn)GetProcAddress(ntdll, "RtlAddAccessDeniedObjectAce");
    p_add_audit = (rtl_add_audit_ace_fn)GetProcAddress(ntdll, "RtlAddAuditAccessAce");
    p_add_audit_ex = (rtl_add_audit_ex_fn)GetProcAddress(ntdll, "RtlAddAuditAccessAceEx");
    p_add_audit_obj = (rtl_add_audit_obj_fn)GetProcAddress(ntdll, "RtlAddAuditAccessObjectAce");
    p_add_compound = (rtl_add_compound_ace_fn)GetProcAddress(ntdll, "RtlAddCompoundAce");

    p_equal_luid = (rtl_equal_luid_fn)GetProcAddress(ntdll, "RtlEqualLuid");
    p_copy_luid = (rtl_copy_luid_fn)GetProcAddress(ntdll, "RtlCopyLuid");
    p_copy_luid_attr = (rtl_copy_luid_attr_fn)GetProcAddress(ntdll, "RtlCopyLuidAndAttributesArray");

    p_all_granted = (rtl_all_granted_fn)GetProcAddress(ntdll, "RtlAreAllAccessesGranted");
    p_any_granted = (rtl_any_granted_fn)GetProcAddress(ntdll, "RtlAreAnyAccessesGranted");
    p_new_granted = (rtl_new_granted_fn)GetProcAddress(ntdll, "RtlNewSecurityGrantedAccess");

    p_new_obj = (rtl_new_sec_obj_fn)GetProcAddress(ntdll, "RtlNewSecurityObject");
    p_new_obj_ex = (rtl_new_sec_obj_ex_fn)GetProcAddress(ntdll, "RtlNewSecurityObjectEx");
    p_new_instance = (rtl_new_instance_fn)GetProcAddress(ntdll, "RtlNewInstanceSecurityObject");
    p_create_user_obj = (rtl_create_user_sec_obj_fn)GetProcAddress(ntdll, "RtlCreateUserSecurityObject");
    p_delete_sec_obj = (rtl_delete_sec_obj_fn)GetProcAddress(ntdll, "RtlDeleteSecurityObject");
    p_set_sec_obj = (rtl_set_sec_obj_fn)GetProcAddress(ntdll, "RtlSetSecurityObject");
    p_set_sec_obj_ex = (rtl_set_sec_obj_ex_fn)GetProcAddress(ntdll, "RtlSetSecurityObjectEx");
    p_query_sec_obj = (rtl_query_sec_obj_fn)GetProcAddress(ntdll, "RtlQuerySecurityObject");
    p_convert_auto = (rtl_convert_auto_inherit_fn)GetProcAddress(ntdll, "RtlConvertToAutoInheritSecurityObject");
    p_create_and_set_sd = (rtl_create_and_set_sd_fn)GetProcAddress(ntdll, "RtlCreateAndSetSD");
    p_default_np_acl = (rtl_default_np_acl_fn)GetProcAddress(ntdll, "RtlDefaultNpAcl");
    p_impersonate_self = (rtl_impersonate_self_fn)GetProcAddress(ntdll, "RtlImpersonateSelf");

    return run_sections("rtlsec", sections, argc, argv);
}
