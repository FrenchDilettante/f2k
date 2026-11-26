/*
 * keysec - registry key security: a subkey of HKEY_CURRENT_USER created
 * with RegCreateKeyExA/W (deleted before and after each section), then
 * RegGetKeySecurity and RegSetKeySecurity over its handle: the size
 * query, a byte short, the size asked for (owner, group and DACL
 * present), the owner/group/DACL set with a security descriptor built
 * by advapi32's own builders and read back, and the error paths (a bogus
 * handle, a key opened read-only, a deleted key's open handle, a
 * missing key).
 *
 * The key lives at Software\F2KRegSec, the fixture's own, deleted at
 * each section's start and end. RegGetKeySecurity/RegSetKeySecurity and
 * the SD/ACL builders go through GetProcAddress, so the program loads
 * where advapi32 lacks them; the Reg* key calls are direct. A SID prints
 * in its string form (every SID here is well-known); the key's owner is
 * read back only as the one set. Nothing machine-specific prints.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create     RegCreateKeyExA/W the subkey (new, again, another case,
 *              an empty name, a bogus root), the disposition, RegCloseKey,
 *              RegDeleteKeyA/W
 *   roundtrip  RegGetKeySecurity's size query, a byte short, the size
 *              asked for (what is present); RegSetKeySecurity with the
 *              owner, group and DACL set; read back (the owner the one
 *              set, the DACL's ACEs)
 *   errors     RegGetKeySecurity/RegSetKeySecurity on a bogus handle,
 *              RegSetKeySecurity on a key opened read-only, both on a
 *              deleted key's open handle, RegDeleteKey of a missing key
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat keysec):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% keysec.c advapi32.lib
 */

#include "../common/f2kt.h"

/* The fixture's own subkey, deleted at each section's start and end. */
static const char sub_a[] = "Software\\F2KRegSec";
static const WCHAR sub_w[] = L"Software\\F2KRegSec";

/* --- the advapi32 security calls, through GetProcAddress ------------- */

typedef BOOL (WINAPI *init_sd_fn)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *init_acl_fn)(PACL, DWORD, DWORD);
typedef BOOL (WINAPI *add_allowed_ace_fn)(PACL, DWORD, DWORD, PSID);
typedef BOOL (WINAPI *set_dacl_fn)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
typedef BOOL (WINAPI *set_owner_fn)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef BOOL (WINAPI *set_group_fn)(PSECURITY_DESCRIPTOR, PSID, BOOL);
typedef LONG (WINAPI *get_key_sec_fn)(HKEY, DWORD, PSECURITY_DESCRIPTOR, LPDWORD);
typedef LONG (WINAPI *set_key_sec_fn)(HKEY, DWORD, PSECURITY_DESCRIPTOR);

static init_sd_fn p_init_sd;
static init_acl_fn p_init_acl;
static add_allowed_ace_fn p_add_allowed;
static set_dacl_fn p_set_dacl;
static set_owner_fn p_set_owner;
static set_group_fn p_set_group;
static get_key_sec_fn p_get_key_sec;
static set_key_sec_fn p_set_key_sec;

static HMODULE adv;

/* --- buffers and helpers ---------------------------------------------- */

static ULONG sd_buf[512];               /* 2 KiB */
static ULONG out_buf[512];              /* 2 KiB */
static ULONG acl_buf[256];              /* 1 KiB */

/* The well-known SIDs built by hand (the layout is public). */
typedef struct {
    BYTE revision;
    BYTE count;
    BYTE authority[6];
    DWORD sub[5];
} sid5_t;

static const sid5_t sid_everyone = { 1, 1, { 0, 0, 0, 0, 0, 1 }, { 0 } };
static const sid5_t sid_admins = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544 } };

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

static void build_sd(DWORD mask);

/* Delete the subkey, silently, so a section starts clean. A previous capture
 * trip may have left it with a restrictive DACL (the roundtrip section sets
 * one), and the plain delete then fails with ERROR_ACCESS_DENIED; the key's
 * owner always holds READ_CONTROL and WRITE_DAC regardless of the DACL, so
 * open with those, restore a permissive DACL, and delete again. Nothing here
 * prints, so the captures are unchanged. */
static void clean(void)
{
    HKEY key = NULL;

    RegDeleteKeyA(HKEY_CURRENT_USER, sub_a);
    RegDeleteKeyW(HKEY_CURRENT_USER, sub_w);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, sub_a, 0, READ_CONTROL | WRITE_DAC, &key) != 0)
        return;
    if (p_set_key_sec != NULL && p_init_sd != NULL && p_init_acl != NULL
        && p_add_allowed != NULL && p_set_dacl != NULL && p_set_owner != NULL && p_set_group != NULL) {
        build_sd(KEY_ALL_ACCESS);
        p_set_key_sec(key, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    }
    RegCloseKey(key);
    RegDeleteKeyA(HKEY_CURRENT_USER, sub_a);
}

/* A self-relative-looking SD is not needed: an absolute one built with
 * the builders, owner admins, group Everyone, DACL allowing Everyone
 * `mask`. */
static void build_sd(DWORD mask)
{
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)sd_buf;
    PACL acl = (PACL)acl_buf;

    memset(sd_buf, 0, sizeof sd_buf);
    memset(acl_buf, 0, sizeof acl_buf);
    p_init_sd(sd, SECURITY_DESCRIPTOR_REVISION);
    p_set_owner(sd, (PSID)&sid_admins, FALSE);
    p_set_group(sd, (PSID)&sid_everyone, FALSE);
    p_init_acl(acl, sizeof acl_buf, ACL_REVISION);
    p_add_allowed(acl, ACL_REVISION, mask, (PSID)&sid_everyone);
    p_set_dacl(sd, TRUE, acl, FALSE);
}

/* A self-relative SD read back, as relations and the DACL's ACEs; the
 * owner prints only as the one set (memcmp against the well-known SID). */
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
    if (off_owner != 0 && off_owner + sid_size(&sid_admins) <= len) {
        line("  the owner the one set (S-1-5-32-544): %s", yesno(memcmp(p + off_owner, &sid_admins, 16) == 0));
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

#define WANT_INFO (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

/* --- create -------------------------------------------------------------- */

static void sec_create(void)
{
    HKEY key = NULL;
    DWORD disp = F2KT_UNTOUCHED, ret;
    LONG r;

    clean();
    disp = F2KT_UNTOUCHED;
    arm();
    r = RegCreateKeyExA(HKEY_CURRENT_USER, sub_a, 0, NULL, 0, KEY_READ, NULL, &key, &disp);
    line("RegCreateKeyExA(%s, KEY_READ): ret=%ld err=%s; disposition %s, a handle: %s", sub_a, r, le(),
         disp == F2KT_UNTOUCHED ? "untouched" : (disp == REG_CREATED_NEW_KEY ? "new" : "existing"),
         yesno(key != NULL));
    if (key != NULL) {
        arm();
        r = RegCloseKey(key);
        line("RegCloseKey: ret=%ld err=%s", r, le());
        key = NULL;
    }
    disp = F2KT_UNTOUCHED;
    arm();
    r = RegCreateKeyExW(HKEY_CURRENT_USER, sub_w, 0, NULL, 0, KEY_READ, NULL, &key, &disp);
    line("RegCreateKeyExW(%s, KEY_READ) (W): ret=%ld err=%s; disposition %s", sub_a, r, le(),
         disp == F2KT_UNTOUCHED ? "untouched" : (disp == REG_CREATED_NEW_KEY ? "new" : "existing"));
    if (key != NULL) {
        arm();
        r = RegCloseKey(key);
        line("RegCloseKey: ret=%ld err=%s", r, le());
        key = NULL;
    }
    disp = F2KT_UNTOUCHED;
    arm();
    r = RegCreateKeyExA(HKEY_CURRENT_USER, sub_a, 0, NULL, 0, KEY_READ, NULL, &key, &disp);
    line("RegCreateKeyExA again: ret=%ld err=%s; disposition existing: %s", r, le(),
         yesno(disp == REG_OPENED_EXISTING_KEY));
    if (key != NULL) {
        arm();
        r = RegCloseKey(key);
        line("RegCloseKey: ret=%ld err=%s", r, le());
    }
    arm();
    r = RegCreateKeyExA(HKEY_CURRENT_USER, "", 0, NULL, 0, KEY_READ, NULL, &key, &disp);
    line("RegCreateKeyExA(an empty subkey name): ret=%ld err=%s", r, le());
    arm();
    r = RegCreateKeyExA((HKEY)0x1234, sub_a, 0, NULL, 0, KEY_READ, NULL, &key, &disp);
    line("RegCreateKeyExA(a bogus root): ret=%ld err=%s", r, le());
    arm();
    ret = RegDeleteKeyA(HKEY_CURRENT_USER, sub_a);
    line("RegDeleteKeyA(%s): ret=%lu err=%s", sub_a, ret, le());
    arm();
    ret = RegDeleteKeyW(HKEY_CURRENT_USER, sub_w);
    line("RegDeleteKeyW(%s) (W): ret=%lu err=%s", sub_a, ret, le());
    arm();
    ret = RegDeleteKeyA(HKEY_CURRENT_USER, sub_a);
    line("RegDeleteKeyA again (missing): ret=%lu err=%s", ret, le());
}

/* --- roundtrip ----------------------------------------------------------- */

static void sec_roundtrip(void)
{
    HKEY key = NULL;
    DWORD disp, need, need2;
    LONG r;

    if (!have("RegGetKeySecurity", (void *)p_get_key_sec) || !have("RegSetKeySecurity", (void *)p_set_key_sec)
        || !have("InitializeSecurityDescriptor", (void *)p_init_sd) || !have("InitializeAcl", (void *)p_init_acl)
        || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)
        || !have("SetSecurityDescriptorOwner", (void *)p_set_owner)
        || !have("SetSecurityDescriptorGroup", (void *)p_set_group)) {
        return;
    }
    clean();
    disp = 0;
    arm();
    r = RegCreateKeyExA(HKEY_CURRENT_USER, sub_a, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, &disp);
    line("RegCreateKeyExA(%s, KEY_ALL_ACCESS): ret=%ld err=%s, a handle: %s", sub_a, r, le(),
         yesno(key != NULL));
    if (key == NULL) {
        clean();
        return;
    }
    need = F2KT_UNTOUCHED;
    arm();
    r = p_get_key_sec(key, WANT_INFO, NULL, &need);
    line("RegGetKeySecurity(no buffer): ret=%ld err=%s; the size needed %s", r, le(),
         need == F2KT_UNTOUCHED ? "untouched" : "set");
    if (need != F2KT_UNTOUCHED && need <= sizeof out_buf) {
        memset(out_buf, 0xCC, sizeof out_buf);
        need2 = need - 1;
        arm();
        r = p_get_key_sec(key, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, &need2);
        line("RegGetKeySecurity(a byte short): ret=%ld err=%s; the size needed the same: %s; the buffer untouched: %s",
             r, le(), yesno(need2 == need), yesno(out_buf[0] == 0xCCCCCCCCu));
        memset(out_buf, 0, sizeof out_buf);
        need2 = need;
        arm();
        r = p_get_key_sec(key, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, &need2);
        line("RegGetKeySecurity(the size asked for): ret=%ld err=%s", r, le());
        if (r == 0) {
            show_sd("the key's SD", out_buf, need2);
        }
    }

    build_sd(0x000F01FF);
    arm();
    r = p_set_key_sec(key, WANT_INFO, (PSECURITY_DESCRIPTOR)sd_buf);
    line("RegSetKeySecurity(owner|group|DACL, admins/Everyone/allow 0x000F01FF): ret=%ld err=%s", r, le());
    memset(out_buf, 0, sizeof out_buf);
    need2 = sizeof out_buf;
    arm();
    r = p_get_key_sec(key, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, &need2);
    line("RegGetKeySecurity(read back): ret=%ld err=%s", r, le());
    if (r == 0) {
        show_sd("the key's SD read back", out_buf, need2);
    }
    /* Only the DACL this time. */
    build_sd(0x00000001);
    arm();
    r = p_set_key_sec(key, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("RegSetKeySecurity(DACL alone, allow Everyone 1): ret=%ld err=%s", r, le());
    memset(out_buf, 0, sizeof out_buf);
    need2 = sizeof out_buf;
    arm();
    r = p_get_key_sec(key, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)out_buf, &need2);
    line("RegGetKeySecurity(DACL, read back): ret=%ld err=%s", r, le());
    if (r == 0) {
        show_sd("the DACL read back", out_buf, need2);
    }

    arm();
    r = RegCloseKey(key);
    line("RegCloseKey: ret=%ld err=%s", r, le());
    arm();
    {
        DWORD ret = RegDeleteKeyA(HKEY_CURRENT_USER, sub_a);
        line("RegDeleteKeyA(%s): ret=%lu err=%s", sub_a, ret, le());
    }
}

/* --- errors -------------------------------------------------------------- */

static void sec_errors(void)
{
    HKEY key = NULL, ro = NULL;
    DWORD disp, need;
    LONG r;

    if (!have("RegGetKeySecurity", (void *)p_get_key_sec) || !have("RegSetKeySecurity", (void *)p_set_key_sec)
        || !have("InitializeSecurityDescriptor", (void *)p_init_sd) || !have("InitializeAcl", (void *)p_init_acl)
        || !have("AddAccessAllowedAce", (void *)p_add_allowed)
        || !have("SetSecurityDescriptorDacl", (void *)p_set_dacl)) {
        return;
    }
    build_sd(0x000F01FF);
    arm();
    r = p_get_key_sec((HKEY)0x1234, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, &need);
    line("RegGetKeySecurity(a bogus handle): ret=%ld err=%s", r, le());
    arm();
    r = p_set_key_sec((HKEY)0x1234, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
    line("RegSetKeySecurity(a bogus handle): ret=%ld err=%s", r, le());

    clean();
    disp = 0;
    arm();
    r = RegCreateKeyExA(HKEY_CURRENT_USER, sub_a, 0, NULL, 0, KEY_READ, NULL, &ro, &disp);
    line("RegCreateKeyExA(%s, KEY_READ): ret=%ld err=%s, a handle: %s", sub_a, r, le(), yesno(ro != NULL));
    if (ro != NULL) {
        arm();
        r = p_set_key_sec(ro, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
        line("RegSetKeySecurity(a key opened KEY_READ, DACL): ret=%ld err=%s", r, le());
        need = sizeof out_buf;
        arm();
        r = p_get_key_sec(ro, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, &need);
        line("RegGetKeySecurity(a key opened KEY_READ): ret=%ld err=%s", r, le());
        arm();
        r = RegCloseKey(ro);
        line("RegCloseKey: ret=%ld err=%s", r, le());
    }

    /* A deleted key's open handle. */
    disp = 0;
    arm();
    r = RegCreateKeyExW(HKEY_CURRENT_USER, sub_w, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, &disp);
    line("RegCreateKeyExW(%s, KEY_ALL_ACCESS) (W): ret=%ld err=%s, a handle: %s", sub_a, r, le(),
         yesno(key != NULL));
    if (key != NULL) {
        DWORD ret;

        arm();
        ret = RegDeleteKeyW(HKEY_CURRENT_USER, sub_w);
        line("RegDeleteKeyW(the open key's name): ret=%lu err=%s", ret, le());
        need = sizeof out_buf;
        arm();
        r = p_get_key_sec(key, WANT_INFO, (PSECURITY_DESCRIPTOR)out_buf, &need);
        line("RegGetKeySecurity(the deleted key's open handle): ret=%ld err=%s", r, le());
        arm();
        r = p_set_key_sec(key, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd_buf);
        line("RegSetKeySecurity(the deleted key's open handle): ret=%ld err=%s", r, le());
        arm();
        r = RegCloseKey(key);
        line("RegCloseKey(the deleted key's handle): ret=%ld err=%s", r, le());
    }
    clean();
}

/* --- main --------------------------------------------------------------- */

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "roundtrip", sec_roundtrip, F2KT_ALWAYS },
    { "errors", sec_errors, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    adv = GetModuleHandleA("advapi32.dll");
    p_init_sd = (init_sd_fn)GetProcAddress(adv, "InitializeSecurityDescriptor");
    p_init_acl = (init_acl_fn)GetProcAddress(adv, "InitializeAcl");
    p_add_allowed = (add_allowed_ace_fn)GetProcAddress(adv, "AddAccessAllowedAce");
    p_set_dacl = (set_dacl_fn)GetProcAddress(adv, "SetSecurityDescriptorDacl");
    p_set_owner = (set_owner_fn)GetProcAddress(adv, "SetSecurityDescriptorOwner");
    p_set_group = (set_group_fn)GetProcAddress(adv, "SetSecurityDescriptorGroup");
    p_get_key_sec = (get_key_sec_fn)GetProcAddress(adv, "RegGetKeySecurity");
    p_set_key_sec = (set_key_sec_fn)GetProcAddress(adv, "RegSetKeySecurity");
    return run_sections("keysec", sections, argc, argv);
}
