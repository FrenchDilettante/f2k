/*
 * filesec - file security on a temp file the fixture creates in its own
 * directory (filesec.tmp, deleted again at each section's end): the
 * GetFileSecurityA/W and SetFileSecurityA/W round trips (size query,
 * short buffer, exact, the DACL set and read back), GetNamedSecurity-
 * InfoA/W and SetNamedSecurityInfoA/W over the name, GetSecurityInfo
 * and SetSecurityInfo over the handle, and the error paths (a missing
 * path, a closed handle, a handle opened with no access).
 *
 * The SD set on the file is built with advapi32's own builders through
 * GetProcAddress (InitializeSecurityDescriptor, InitializeAcl,
 * AddAccessAllowedAce, SetSecurityDescriptorDacl), so the program loads
 * where advapi32 lacks them. The file security calls go through
 * GetProcAddress too. A SID prints in its string form (every SID here is
 * well-known); the file's owner is the account's, so it prints only as
 * present and a SID. Nothing machine-specific prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   getset   CreateFileA the temp file; GetFileSecurityA/W's size query,
 *            a byte short, the size asked for (the owner/group/DACL
 *            present flags); SetFileSecurityA/W with a DACL allowing
 *            Everyone a mask; GetFileSecurityA/W read back (AceCount, the
 *            ACE's type, mask and SID)
 *   named    GetNamedSecurityInfoA/W of the name (the error code it
 *            returns, what it set); SetNamedSecurityInfoA/W with the
 *            DACL; read back; GetSecurityInfo/SetSecurityInfo over the
 *            open handle, read back
 *   errors   the same calls on a path that does not exist, on a handle
 *            closed before the call, and on a handle opened with no
 *            access
 *   namedex  GetNamedSecurityInfoExA/W and SetNamedSecurityInfoExA/W
 *            over the name (no provider, no property, no lists), and on
 *            a path that does not exist
 *   kernelobj  GetKernelObjectSecurity and SetKernelObjectSecurity on
 *            the process handle: the size query, the size asked for,
 *            the DACL set and read back
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat filesec):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% filesec.c advapi32.lib
 */

#include "../common/f2kt.h"

/* The object type the named/handle calls take (public value). */
#define F2KT_SE_FILE_OBJECT 1

/* --- the advapi32 security calls, through GetProcAddress ------------- */

typedef BOOL (WINAPI *init_sd_fn)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *init_acl_fn)(PACL, DWORD, DWORD);
typedef BOOL (WINAPI *add_allowed_ace_fn)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *set_dacl_fn)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef BOOL (WINAPI *get_fs_a_fn)(LPCSTR, DWORD, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
typedef BOOL (WINAPI *get_fs_w_fn)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
typedef BOOL (WINAPI *set_fs_a_fn)(LPCSTR, DWORD, PSECURITY_DESCRIPTOR);
typedef BOOL (WINAPI *set_fs_w_fn)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR);
typedef DWORD (WINAPI *get_named_a_fn)(LPCSTR, DWORD, DWORD, PSID *, PSID *, PACL *, PACL *,
                                       PSECURITY_DESCRIPTOR *);
typedef DWORD (WINAPI *get_named_w_fn)(LPCWSTR, DWORD, DWORD, PSID *, PSID *, PACL *, PACL *,
                                        PSECURITY_DESCRIPTOR *);
typedef DWORD (WINAPI *set_named_a_fn)(LPCSTR, DWORD, DWORD, PSID, PSID, PACL, PACL);
typedef DWORD (WINAPI *set_named_w_fn)(LPCWSTR, DWORD, DWORD, PSID, PSID, PACL, PACL);
typedef DWORD (WINAPI *get_info_fn)(HANDLE, DWORD, DWORD, PSID *, PSID *, PACL *, PACL *,
                                    PSECURITY_DESCRIPTOR *);
typedef DWORD (WINAPI *set_info_fn)(HANDLE, DWORD, DWORD, PSECURITY_DESCRIPTOR);

/* The Ex forms over a name, and the kernel object calls (public
 * signatures; the access/audit lists and the overlapped stay opaque). */
typedef DWORD (WINAPI *get_named_ex_a_fn)(LPCSTR, DWORD, DWORD, LPCSTR, LPCSTR, void *, void *, LPSTR *,
                                          LPSTR *);
typedef DWORD (WINAPI *get_named_ex_w_fn)(LPCWSTR, DWORD, DWORD, LPCWSTR, LPCWSTR, void *, void *, LPWSTR *,
                                           LPWSTR *);
typedef DWORD (WINAPI *set_named_ex_a_fn)(LPCSTR, DWORD, DWORD, LPCSTR, void *, void *, LPSTR, LPSTR, void *);
typedef DWORD (WINAPI *set_named_ex_w_fn)(LPCWSTR, DWORD, DWORD, LPCWSTR, void *, void *, LPWSTR, LPWSTR, void *);
typedef BOOL (WINAPI *get_kernel_obj_fn)(HANDLE, DWORD, PSECURITY_DESCRIPTOR, DWORD, LPDWORD);
typedef BOOL (WINAPI *set_kernel_obj_fn)(HANDLE, DWORD, PSECURITY_DESCRIPTOR);

static init_sd_fn p_init_sd;
static init_acl_fn p_init_acl;
static add_allowed_ace_fn p_add_allowed;
static set_dacl_fn p_set_dacl;
static get_fs_a_fn p_get_fs_a;
static get_fs_w_fn p_get_fs_w;
static set_fs_a_fn p_set_fs_a;
static set_fs_w_fn p_set_fs_w;
static get_named_a_fn p_get_named_a;
static get_named_w_fn p_get_named_w;
static set_named_a_fn p_set_named_a;
static set_named_w_fn p_set_named_w;
static get_info_fn p_get_info;
static set_info_fn p_set_info;
static get_named_ex_a_fn p_get_named_ex_a;
static get_named_ex_w_fn p_get_named_ex_w;
static set_named_ex_a_fn p_set_named_ex_a;
static set_named_ex_w_fn p_set_named_ex_w;
static get_kernel_obj_fn p_get_kernel_obj;
static set_kernel_obj_fn p_set_kernel_obj;

static HMODULE adv;

/* --- buffers and helpers ---------------------------------------------- */

static ULONG sd_buf[512];               /* 2 KiB: the SD set on the file */
static ULONG out_buf[512];              /* 2 KiB: the SD read back */
static ULONG acl_buf[256];              /* 1 KiB */
static const char name_a[] = "filesec.tmp";
static const WCHAR name_w[] = L"filesec.tmp";
static const char missing_a[] = "filesec-none.tmp";
static const WCHAR missing_w[] = L"filesec-none.tmp";

/* The well-known SID built by hand (the layout is public): S-1-1-0. */
typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };

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

static int have(const char *name, void *p)
{
    if (p == NULL) {
        line("%s not found", name);
        return 0;
    }
    return 1;
}

/* CreateFileA the temp file, printed; NULL when it fails. */
static HANDLE make_file(DWORD access)
{
    HANDLE h;

    arm();
    h = CreateFileA(name_a, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    line("CreateFileA(%s, access 0x%08lX, CREATE_ALWAYS): %s err=%s", name_a, access,
         h != INVALID_HANDLE_VALUE && h != NULL ? "a handle" : "no handle", le());
    return (h == INVALID_HANDLE_VALUE) ? NULL : h;
}

/* DeleteFileA the temp file, printed. */
static void drop_file(HANDLE h)
{
    BOOL r;

    if (h != NULL) {
        arm();
        r = CloseHandle(h);
        line("CloseHandle: ret=%d err=%s", r, le());
    }
    arm();
    r = DeleteFileA(name_a);
    line("DeleteFileA(%s): ret=%d err=%s", name_a, r, le());
}

/* An absolute SD in sd_buf with a DACL allowing Everyone `mask`. */
static void build_sd(DWORD mask)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    PACL acl = (PACL)acl_buf;

    memset(sd_buf, 0, sizeof sd_buf);
    memset(acl_buf, 0, sizeof acl_buf);
    p_init_sd(sd, SECURITY_DESCRIPTOR_REVISION);
    p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    p_add_allowed(acl, ACL_REVISION, mask, (PSID)&sid_everyone);
    p_set_dacl(sd, TRUE, acl, FALSE);
}

/* A self-relative SD read back, printed as relations and the DACL's
 * first ACE (the file's owner is the account's, so it prints only as
 * present and a SID). */
static void show_sd(const char *label, const void *buf, DWORD len)
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
        line("  the owner: a SID: %s", yesno(p[off_owner] == 1));
    }
    if ((sd_control(sd) & SE_DACL_PRESENT) != 0 && off_dacl != 0 && off_dacl + 8 <= len) {
        acl = (const ACL *)(p + off_dacl);
        line("  the DACL: revision %u, size %u, AceCount %u", (unsigned)acl->AclRevision,
             (unsigned)acl->AclSize, (unsigned)acl->AceCount);
        if (acl->AceCount >= 1 && off_dacl + 8 + sizeof(ACCESS_ALLOWED_ACE) <= len) {
            ace = (const ACCESS_ALLOWED_ACE *)(p + off_dacl + 8);
            line("  ACE 0: type %u, flags 0x%X, mask 0x%08lX, sid %s", (unsigned)ace->Header.AceType,
                 (unsigned)ace->Header.AceFlags, ace->Mask, sid_text(&ace->SidStart));
        }
    }
}

#define WANT_INFO (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

/* --- getset -------------------------------------------------------------- */

static void sec_getset(void)
{
    HANDLE h;
    DWORD need, need2, len;
    BOOL r;

    if (!have("GetFileSecurityA", (void *)p_get_fs_a) || !have("GetFileSecurityW", (void *)p_get_fs_w)
        || !have("SetFileSecurityA", (void *)p_set_fs_a) || !have("SetFileSecurityW", (void *)p_set_fs_w)
        || !have("InitializeSecurityDescriptor", (void *)p_init_sd) || !have("InitializeAcl", (void *)p_init_acl)
        || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)) {
        return;
    }
    h = make_file(GENERIC_READ | GENERIC_WRITE);
    if (h == NULL) {
        return;
    }
    need = F2KT_UNTOUCHED;
    arm();
    r = p_get_fs_a(name_a, WANT_INFO, NULL, 0, &need);
    line("GetFileSecurityA(%s, no buffer): ret=%d err=%s; the size needed %s", name_a, r, le(),
         need == F2KT_UNTOUCHED ? "untouched" : "set");
    if (need != F2KT_UNTOUCHED && need <= sizeof out_buf) {
        memset(out_buf, 0xCC, sizeof out_buf);
        len = need - 1;
        arm();
        r = p_get_fs_a(name_a, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, len, &need2);
        line("GetFileSecurityA(a byte short): ret=%d err=%s; the size needed the same: %s; the buffer untouched: %s",
             r, le(), yesno(need2 == need), yesno(out_buf[0] == 0xCCCCCCCCu));
        memset(out_buf, 0, sizeof out_buf);
        len = need;
        arm();
        r = p_get_fs_a(name_a, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, len, &need2);
        line("GetFileSecurityA(the size asked for): ret=%d err=%s", r, le());
        if (r) {
            show_sd("the SD read back", out_buf, need2);
        }
        memset(out_buf, 0, sizeof out_buf);
        arm();
        r = p_get_fs_w(name_w, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, need, &need2);
        line("GetFileSecurityW(%s, the size asked for) (W): ret=%d err=%s", name_a, r, le());
        if (r) {
            show_sd("the SD read back (W)", out_buf, need2);
        }
    }

    build_sd(0x000F01FF);
    arm();
    r = p_set_fs_a(name_a, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("SetFileSecurityA(%s, DACL, allow Everyone 0x000F01FF): ret=%d err=%s", name_a, r, le());
    arm();
    r = p_set_fs_w(name_w, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("SetFileSecurityW(%s, DACL) (W): ret=%d err=%s", name_a, r, le());
    memset(out_buf, 0, sizeof out_buf);
    need2 = F2KT_UNTOUCHED;
    arm();
    r = p_get_fs_a(name_a, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, sizeof out_buf, &need2);
    line("GetFileSecurityA(%s, DACL, read back): ret=%d err=%s", name_a, r, le());
    if (r) {
        show_sd("the DACL read back", out_buf, need2);
    }
    memset(out_buf, 0, sizeof out_buf);
    arm();
    r = p_get_fs_w(name_w, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, sizeof out_buf, &need2);
    line("GetFileSecurityW(%s, DACL, read back) (W): ret=%d err=%s", name_a, r, le());
    if (r) {
        show_sd("the DACL read back (W)", out_buf, need2);
    }
    drop_file(h);
}

/* --- named --------------------------------------------------------------- */

static void sec_named(void)
{
    HANDLE h;
    PSID owner, group;
    PACL dacl, sacl;
    PSECURITY_DESCRIPTOR sd;
    DWORD ret;

    if (!have("GetNamedSecurityInfoA", (void *)p_get_named_a)
        || !have("GetNamedSecurityInfoW", (void *)p_get_named_w)
        || !have("SetNamedSecurityInfoA", (void *)p_set_named_a)
        || !have("SetNamedSecurityInfoW", (void *)p_set_named_w) || !have("GetSecurityInfo", (void *)p_get_info)
        || !have("SetSecurityInfo", (void *)p_set_info) || !have("InitializeSecurityDescriptor", (void *)p_init_sd)
        || !have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)) {
        return;
    }
    h = make_file(GENERIC_READ | GENERIC_WRITE);
    if (h == NULL) {
        return;
    }
    owner = group = NULL;
    dacl = sacl = NULL;
    sd = NULL;
    arm();
    ret = p_get_named_a(name_a, F2KT_SE_FILE_OBJECT, WANT_INFO, &owner, &group, &dacl, &sacl, &sd);
    line("GetNamedSecurityInfoA(%s, file, owner|group|DACL): ret=%lu err=%s; owner %s, group %s, DACL %s, SD %s",
         name_a, ret, le(), owner != NULL ? "set" : "NULL", group != NULL ? "set" : "NULL",
         dacl != NULL ? "set" : "NULL", sd != NULL ? "set" : "NULL");
    owner = group = NULL;
    dacl = sacl = NULL;
    sd = NULL;
    arm();
    ret = p_get_named_w(name_w, F2KT_SE_FILE_OBJECT, WANT_INFO, &owner, &group, &dacl, &sacl, &sd);
    line("GetNamedSecurityInfoW(%s, file, owner|group|DACL) (W): ret=%lu err=%s; SD %s", name_a, ret, le(),
         sd != NULL ? "set" : "NULL");

    build_sd(0x000F01FF);
    arm();
    ret = p_set_named_a(name_a, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, (PACL)acl_buf, NULL);
    line("SetNamedSecurityInfoA(%s, file, DACL, allow Everyone 0x000F01FF): ret=%lu err=%s", name_a, ret, le());
    arm();
    ret = p_set_named_w(name_w, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, (PACL)acl_buf, NULL);
    line("SetNamedSecurityInfoW(%s, file, DACL) (W): ret=%lu err=%s", name_a, ret, le());
    dacl = NULL;
    sd = NULL;
    arm();
    ret = p_get_named_a(name_a, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    line("GetNamedSecurityInfoA(%s, DACL, read back): ret=%lu err=%s; DACL %s", name_a, ret, le(),
         dacl != NULL ? "set" : "NULL");
    if (ret == 0 && dacl != NULL) {
        line("  the DACL: AceCount %u, size %u", (unsigned)dacl->AceCount, (unsigned)dacl->AclSize);
        if (dacl->AceCount >= 1) {
            ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)((BYTE *)dacl + 8);
            line("  ACE 0: type %u, mask 0x%08lX, sid %s", (unsigned)ace->Header.AceType, ace->Mask,
                 sid_text(&ace->SidStart));
        }
    }

    /* Over the handle: GetSecurityInfo/SetSecurityInfo. */
    owner = group = NULL;
    dacl = sacl = NULL;
    sd = NULL;
    arm();
    ret = p_get_info(h, F2KT_SE_FILE_OBJECT, WANT_INFO, &owner, &group, &dacl, &sacl, &sd);
    line("GetSecurityInfo(the handle, file, owner|group|DACL): ret=%lu err=%s; SD %s", ret, le(),
         sd != NULL ? "set" : "NULL");
    build_sd(0x00000001);
    arm();
    ret = p_set_info(h, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("SetSecurityInfo(the handle, file, DACL, allow Everyone 1): ret=%lu err=%s", ret, le());
    dacl = NULL;
    arm();
    ret = p_get_info(h, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, NULL);
    line("GetSecurityInfo(the handle, DACL, read back): ret=%lu err=%s; DACL %s", ret, le(),
         dacl != NULL ? "set" : "NULL");
    if (ret == 0 && dacl != NULL) {
        line("  the DACL: AceCount %u", (unsigned)dacl->AceCount);
    }
    drop_file(h);
}

/* --- errors -------------------------------------------------------------- */

static void sec_errors(void)
{
    HANDLE h, h0;
    PSID owner, group;
    PACL dacl, sacl;
    PSECURITY_DESCRIPTOR sd;
    DWORD ret, need;
    BOOL r;

    if (!have("GetFileSecurityA", (void *)p_get_fs_a) || !have("SetFileSecurityA", (void *)p_set_fs_a)
        || !have("GetNamedSecurityInfoA", (void *)p_get_named_a)
        || !have("SetNamedSecurityInfoA", (void *)p_set_named_a) || !have("GetSecurityInfo", (void *)p_get_info)
        || !have("SetSecurityInfo", (void *)p_set_info) || !have("InitializeSecurityDescriptor", (void *)p_init_sd)
        || !have("InitializeAcl", (void *)p_init_acl) || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)) {
        return;
    }
    build_sd(0x000F01FF);

    need = F2KT_UNTOUCHED;
    arm();
    r = p_get_fs_a(missing_a, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, sizeof out_buf, &need);
    line("GetFileSecurityA(a path that does not exist): ret=%d err=%s; the size needed %s", r, le(),
         need == F2KT_UNTOUCHED ? "untouched" : "set");
    arm();
    r = p_set_fs_a(missing_a, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("SetFileSecurityA(a path that does not exist): ret=%d err=%s", r, le());
    arm();
    ret = p_get_named_a(missing_a, F2KT_SE_FILE_OBJECT, WANT_INFO, &owner, &group, &dacl, &sacl, &sd);
    line("GetNamedSecurityInfoA(a path that does not exist): ret=%lu err=%s", ret, le());
    arm();
    ret = p_get_named_w(missing_w, F2KT_SE_FILE_OBJECT, WANT_INFO, &owner, &group, &dacl, &sacl, &sd);
    line("GetNamedSecurityInfoW(a path that does not exist) (W): ret=%lu err=%s", ret, le());
    arm();
    ret = p_set_named_a(missing_a, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, (PACL)acl_buf,
                        NULL);
    line("SetNamedSecurityInfoA(a path that does not exist): ret=%lu err=%s", ret, le());

    /* A handle closed before the call. */
    h = make_file(GENERIC_READ | GENERIC_WRITE);
    if (h == NULL) {
        return;
    }
    arm();
    r = CloseHandle(h);
    line("CloseHandle: ret=%d err=%s", r, le());
    arm();
    ret = p_get_info(h, F2KT_SE_FILE_OBJECT, WANT_INFO, &owner, &group, &dacl, &sacl, &sd);
    line("GetSecurityInfo(a closed handle): ret=%lu err=%s", ret, le());
    arm();
    ret = p_set_info(h, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("SetSecurityInfo(a closed handle): ret=%lu err=%s", ret, le());

    /* A handle opened with no access. */
    h0 = make_file(0);
    if (h0 != NULL) {
        arm();
        ret = p_get_info(h0, F2KT_SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd);
        line("GetSecurityInfo(a handle opened with no access, owner): ret=%lu err=%s", ret, le());
        arm();
        ret = p_set_info(h0, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
        line("SetSecurityInfo(a handle opened with no access, DACL): ret=%lu err=%s", ret, le());
        drop_file(h0);
    }
}

/* --- namedex ------------------------------------------------------------- */

static void sec_namedex(void)
{
    HANDLE h;
    void *alist, *aulist;
    LPSTR owner, group;
    LPWSTR ownerw, groupw;
    DWORD ret;

    if (!have("GetNamedSecurityInfoExA", (void *)p_get_named_ex_a)
        || !have("GetNamedSecurityInfoExW", (void *)p_get_named_ex_w)
        || !have("SetNamedSecurityInfoExA", (void *)p_set_named_ex_a)
        || !have("SetNamedSecurityInfoExW", (void *)p_set_named_ex_w)) {
        return;
    }
    h = make_file(GENERIC_READ | GENERIC_WRITE);
    if (h == NULL) {
        return;
    }
    alist = NULL;
    aulist = NULL;
    owner = NULL;
    group = NULL;
    arm();
    ret = p_get_named_ex_a(name_a, F2KT_SE_FILE_OBJECT, WANT_INFO, NULL, NULL, &alist, &aulist, &owner, &group);
    line("GetNamedSecurityInfoExA(%s, file, owner|group|DACL, no provider): ret=%lu err=%s; access %s, audit %s, "
         "owner %s, group %s", name_a, ret, le(), alist != NULL ? "set" : "NULL", aulist != NULL ? "set" : "NULL",
         owner != NULL ? "set" : "NULL", group != NULL ? "set" : "NULL");
    ownerw = NULL;
    groupw = NULL;
    alist = NULL;
    aulist = NULL;
    arm();
    ret = p_get_named_ex_w(name_w, F2KT_SE_FILE_OBJECT, WANT_INFO, NULL, NULL, &alist, &aulist, &ownerw, &groupw);
    line("GetNamedSecurityInfoExW(%s, file, owner|group|DACL, no provider) (W): ret=%lu err=%s; owner %s", name_a, ret,
         le(), ownerw != NULL ? "set" : "NULL");
    arm();
    ret = p_set_named_ex_a(name_a, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, NULL,
                           NULL);
    line("SetNamedSecurityInfoExA(%s, file, DACL, no lists): ret=%lu err=%s", name_a, ret, le());
    arm();
    ret = p_set_named_ex_w(name_w, F2KT_SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, NULL,
                           NULL);
    line("SetNamedSecurityInfoExW(%s, file, DACL, no lists) (W): ret=%lu err=%s", name_a, ret, le());
    arm();
    ret = p_get_named_ex_a(missing_a, F2KT_SE_FILE_OBJECT, WANT_INFO, NULL, NULL, NULL, NULL, NULL, NULL);
    line("GetNamedSecurityInfoExA(a path that does not exist): ret=%lu err=%s", ret, le());
    drop_file(h);
}

/* --- kernelobj ----------------------------------------------------------- */

static void sec_kernelobj(void)
{
    DWORD need, need2, len;
    BOOL r;

    if (!have("GetKernelObjectSecurity", (void *)p_get_kernel_obj)
        || !have("SetKernelObjectSecurity", (void *)p_set_kernel_obj)
        || !have("InitializeSecurityDescriptor", (void *)p_init_sd) || !have("InitializeAcl", (void *)p_init_acl)
        || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)) {
        return;
    }
    need = F2KT_UNTOUCHED;
    arm();
    r = p_get_kernel_obj(GetCurrentProcess(), WANT_INFO, NULL, 0, &need);
    line("GetKernelObjectSecurity(the process handle, no buffer): ret=%d err=%s; the size needed %s", r, le(),
         need == F2KT_UNTOUCHED ? "untouched" : "set");
    if (need != F2KT_UNTOUCHED && need <= sizeof out_buf) {
        memset(out_buf, 0, sizeof out_buf);
        need2 = need;
        arm();
        r = p_get_kernel_obj(GetCurrentProcess(), WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, need2, &need2);
        line("GetKernelObjectSecurity(the size asked for): ret=%d err=%s", r, le());
        if (r) {
            show_sd("the process's SD", out_buf, need2);
        }
    }
    build_sd(0x000F01FF);
    arm();
    r = p_set_kernel_obj(GetCurrentProcess(), DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("SetKernelObjectSecurity(the process handle, DACL, allow Everyone 0x000F01FF): ret=%d err=%s", r, le());
    memset(out_buf, 0, sizeof out_buf);
    len = sizeof out_buf;
    arm();
    r = p_get_kernel_obj(GetCurrentProcess(), DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, len, &need);
    line("GetKernelObjectSecurity(the process handle, DACL, read back): ret=%d err=%s", r, le());
    if (r) {
        show_sd("the process's DACL read back", out_buf, need);
    }
}

/* --- main --------------------------------------------------------------- */

static const section_t sections[] = {
    { "getset", sec_getset, F2KT_ALWAYS },
    { "named", sec_named, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { "namedex", sec_namedex, F2KT_ALWAYS },
    { "kernelobj", sec_kernelobj, F2KT_ALWAYS },
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
    p_init_acl = (init_acl_fn)GetProcAddress(adv, "InitializeAcl");
    p_add_allowed = (add_allowed_ace_fn)GetProcAddress(adv, "AddAccessAllowedAce");
    p_set_dacl = (set_dacl_fn)GetProcAddress(adv, "SetSecurityDescriptorDacl");
    p_get_fs_a = (get_fs_a_fn)GetProcAddress(adv, "GetFileSecurityA");
    p_get_fs_w = (get_fs_w_fn)GetProcAddress(adv, "GetFileSecurityW");
    p_set_fs_a = (set_fs_a_fn)GetProcAddress(adv, "SetFileSecurityA");
    p_set_fs_w = (set_fs_w_fn)GetProcAddress(adv, "SetFileSecurityW");
    p_get_named_a = (get_named_a_fn)GetProcAddress(adv, "GetNamedSecurityInfoA");
    p_get_named_w = (get_named_w_fn)GetProcAddress(adv, "GetNamedSecurityInfoW");
    p_set_named_a = (set_named_a_fn)GetProcAddress(adv, "SetNamedSecurityInfoA");
    p_set_named_w = (set_named_w_fn)GetProcAddress(adv, "SetNamedSecurityInfoW");
    p_get_info = (get_info_fn)GetProcAddress(adv, "GetSecurityInfo");
    p_set_info = (set_info_fn)GetProcAddress(adv, "SetSecurityInfo");
    p_get_named_ex_a = (get_named_ex_a_fn)GetProcAddress(adv, "GetNamedSecurityInfoExA");
    p_get_named_ex_w = (get_named_ex_w_fn)GetProcAddress(adv, "GetNamedSecurityInfoExW");
    p_set_named_ex_a = (set_named_ex_a_fn)GetProcAddress(adv, "SetNamedSecurityInfoExA");
    p_set_named_ex_w = (set_named_ex_w_fn)GetProcAddress(adv, "SetNamedSecurityInfoExW");
    p_get_kernel_obj = (get_kernel_obj_fn)GetProcAddress(adv, "GetKernelObjectSecurity");
    p_set_kernel_obj = (set_kernel_obj_fn)GetProcAddress(adv, "SetKernelObjectSecurity");
    return run_sections("filesec", sections, argc, argv);
}
