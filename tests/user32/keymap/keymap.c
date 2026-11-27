/*
 * keymap - keyboard layouts and the key mapping calls of user32:
 * MapVirtualKey(Ex)A/W, VkKeyScan(Ex)A/W, ToAscii(Ex), ToUnicode(Ex),
 * OemKeyScan, GetKeyNameTextA/W, GetKeyboardType, GetKBCodePage, the
 * layout calls (GetKeyboardLayout, GetKeyboardLayoutList,
 * LoadKeyboardLayoutA/W, ActivateKeyboardLayout, UnloadKeyboardLayout,
 * GetKeyboardLayoutNameA/W), keybd_event, BlockInput and
 * GetLastInputInfo.
 *
 * The capture machine's set of input locales is not known, so nothing
 * prints it, nor the identity of the thread's own layout: the list
 * prints as relations (a count of at least one, the thread's layout in
 * it). The tables print against the US layout, which every Windows 2000
 * carries (kbdus.dll): LoadKeyboardLayoutA("00000409", KLF_NOTELLSHELL)
 * gives its HKL, which the Ex forms take. The plain forms work on the
 * thread's own layout, so they print only what any Latin layout answers
 * alike, or their equality with the Ex form given GetKeyboardLayout(0).
 * Where a call has no Ex form (GetKeyNameText, OemKeyScan), the section
 * activates the US layout for its thread and restores the thread's own
 * one before it ends. A section unloads the US layout only when it was
 * not loaded before the section loaded it, so the user's own layouts are
 * never unloaded; its line reads the same either way.
 *
 * Every export but GetKeyboardLayout is reached through GetProcAddress
 * (MSVC 6's user32.lib predates some, and F2K lacks most): one missing
 * prints "<name>: absent" and ends its section alone.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   layouts   GetKeyboardLayout of the thread (0 and its own id),
 *             GetKeyboardLayoutList's count, the list filled, the
 *             thread's layout in it, a buffer of one
 *   load      LoadKeyboardLayoutA/W("00000409"): the HKL's words as
 *             relations, the same HKL twice, in the list after;
 *             LoadKeyboardLayoutA of a layout id no keyboard has; the
 *             unload of what the section added; UnloadKeyboardLayout
 *             of a bogus HKL
 *   activate  ActivateKeyboardLayout to US and back: the previous
 *             layouts returned, GetKeyboardLayout after each,
 *             GetKeyboardLayoutNameA/W while US is active; a bogus HKL
 *   mapvk     MapVirtualKeyExA over its four map types (every virtual
 *             key 0-255, every scan code 0-127) as a count and a sum,
 *             the W form and the plain forms on the thread's layout
 *             against them, notable keys' rows, a bad map type
 *   vkscan    VkKeyScanExA of every character 0x00-0x7F, sixteen a
 *             line; VkKeyScanExW against it, of U+00E9 and U+20AC; the
 *             plain forms of letters and digits against the Ex forms
 *   toascii   ToAsciiEx and ToUnicodeEx over keys with no modifier,
 *             Shift, Ctrl, Ctrl+Alt, Caps Lock, Caps Lock with Shift,
 *             Num Lock, a key's release, a buffer of 0, menu mode; the
 *             plain forms over letters and digits
 *   keyname   GetKeyNameTextA/W of scan codes, with the extended bit
 *             (1 << 24) and the don't-care bit (1 << 25), and short
 *             buffers (US activated for the section)
 *   oemscan   OemKeyScan of characters 0x00-0x7F (US activated)
 *   kbtype    GetKeyboardType(0), (1), (2), and (3); GetKBCodePage
 *             against GetOEMCP
 *   inject    GetLastInputInfo with a bad and a good size;
 *             keybd_event of VK_F24 down and up (a key no program
 *             binds): GetAsyncKeyState between, the last input's time
 *             after; BlockInput(FALSE) (never TRUE)
 *
 * GetKeyboardType's values are the capture machine's keyboard (a
 * VirtualBox VM's 101/102-key, type 4 subtype 0, 12 function keys).
 * inject's F24 goes to the foreground window, whatever it is: run with
 * the desktop left alone and the workstation unlocked.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat keymap):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% keymap.c user32.lib
 */

#include "../common/f2kt.h"

/* winuser.h has some of these for WINVER 0x0500 only. */
#define KLF_NOTELLSHELL_ 0x00000080
#define VK_F24_ 0x87
#define VK_LSHIFT_ 0xA0
#define VK_RSHIFT_ 0xA1
#define VK_LCONTROL_ 0xA2
#define VK_RMENU_ 0xA5
#define VK_OEM_1_ 0xBA
#define VK_OEM_PLUS_ 0xBB
#define VK_OEM_2_ 0xBF
#define VK_OEM_4_ 0xDB
#define VK_OEM_7_ 0xDE
#define VK_OEM_102_ 0xE2

typedef struct {
    UINT cbSize;
    DWORD dwTime;
} lastinput_t;

typedef UINT (WINAPI *map_vk_t)(UINT, UINT);
typedef UINT (WINAPI *map_vk_ex_t)(UINT, UINT, HKL);
typedef SHORT (WINAPI *vk_scan_a_t)(CHAR);
typedef SHORT (WINAPI *vk_scan_w_t)(WCHAR);
typedef SHORT (WINAPI *vk_scan_ex_a_t)(CHAR, HKL);
typedef SHORT (WINAPI *vk_scan_ex_w_t)(WCHAR, HKL);
typedef int (WINAPI *to_ascii_t)(UINT, UINT, const BYTE *, LPWORD, UINT);
typedef int (WINAPI *to_ascii_ex_t)(UINT, UINT, const BYTE *, LPWORD, UINT, HKL);
typedef int (WINAPI *to_unicode_t)(UINT, UINT, const BYTE *, LPWSTR, int, UINT);
typedef int (WINAPI *to_unicode_ex_t)(UINT, UINT, const BYTE *, LPWSTR, int, UINT, HKL);
typedef DWORD (WINAPI *oem_key_scan_t)(WORD);
typedef int (WINAPI *key_name_a_t)(LONG, LPSTR, int);
typedef int (WINAPI *key_name_w_t)(LONG, LPWSTR, int);
typedef int (WINAPI *kb_type_t)(int);
typedef UINT (WINAPI *kb_cp_t)(void);
typedef HKL (WINAPI *load_a_t)(LPCSTR, UINT);
typedef HKL (WINAPI *load_w_t)(LPCWSTR, UINT);
typedef BOOL (WINAPI *unload_t)(HKL);
typedef HKL (WINAPI *activate_t)(HKL, UINT);
typedef int (WINAPI *layout_list_t)(int, HKL *);
typedef BOOL (WINAPI *layout_name_a_t)(LPSTR);
typedef BOOL (WINAPI *layout_name_w_t)(LPWSTR);
typedef void (WINAPI *keybd_event_t)(BYTE, BYTE, DWORD, DWORD);
typedef BOOL (WINAPI *block_input_t)(BOOL);
typedef BOOL (WINAPI *last_input_t)(lastinput_t *);

static map_vk_t pMapVirtualKeyA;
static map_vk_t pMapVirtualKeyW;
static map_vk_ex_t pMapVirtualKeyExA;
static map_vk_ex_t pMapVirtualKeyExW;
static vk_scan_a_t pVkKeyScanA;
static vk_scan_w_t pVkKeyScanW;
static vk_scan_ex_a_t pVkKeyScanExA;
static vk_scan_ex_w_t pVkKeyScanExW;
static to_ascii_t pToAscii;
static to_ascii_ex_t pToAsciiEx;
static to_unicode_t pToUnicode;
static to_unicode_ex_t pToUnicodeEx;
static oem_key_scan_t pOemKeyScan;
static key_name_a_t pGetKeyNameTextA;
static key_name_w_t pGetKeyNameTextW;
static kb_type_t pGetKeyboardType;
static kb_cp_t pGetKBCodePage;
static load_a_t pLoadKeyboardLayoutA;
static load_w_t pLoadKeyboardLayoutW;
static unload_t pUnloadKeyboardLayout;
static activate_t pActivateKeyboardLayout;
static layout_list_t pGetKeyboardLayoutList;
static layout_name_a_t pGetKeyboardLayoutNameA;
static layout_name_w_t pGetKeyboardLayoutNameW;
static keybd_event_t pkeybd_event;
static block_input_t pBlockInput;
static last_input_t pGetLastInputInfo;

static FARPROC resolve(const char *name)
{
    return GetProcAddress(GetModuleHandleA("user32.dll"), name);
}

static void resolve_all(void)
{
    pMapVirtualKeyA = (map_vk_t)resolve("MapVirtualKeyA");
    pMapVirtualKeyW = (map_vk_t)resolve("MapVirtualKeyW");
    pMapVirtualKeyExA = (map_vk_ex_t)resolve("MapVirtualKeyExA");
    pMapVirtualKeyExW = (map_vk_ex_t)resolve("MapVirtualKeyExW");
    pVkKeyScanA = (vk_scan_a_t)resolve("VkKeyScanA");
    pVkKeyScanW = (vk_scan_w_t)resolve("VkKeyScanW");
    pVkKeyScanExA = (vk_scan_ex_a_t)resolve("VkKeyScanExA");
    pVkKeyScanExW = (vk_scan_ex_w_t)resolve("VkKeyScanExW");
    pToAscii = (to_ascii_t)resolve("ToAscii");
    pToAsciiEx = (to_ascii_ex_t)resolve("ToAsciiEx");
    pToUnicode = (to_unicode_t)resolve("ToUnicode");
    pToUnicodeEx = (to_unicode_ex_t)resolve("ToUnicodeEx");
    pOemKeyScan = (oem_key_scan_t)resolve("OemKeyScan");
    pGetKeyNameTextA = (key_name_a_t)resolve("GetKeyNameTextA");
    pGetKeyNameTextW = (key_name_w_t)resolve("GetKeyNameTextW");
    pGetKeyboardType = (kb_type_t)resolve("GetKeyboardType");
    pGetKBCodePage = (kb_cp_t)resolve("GetKBCodePage");
    pLoadKeyboardLayoutA = (load_a_t)resolve("LoadKeyboardLayoutA");
    pLoadKeyboardLayoutW = (load_w_t)resolve("LoadKeyboardLayoutW");
    pUnloadKeyboardLayout = (unload_t)resolve("UnloadKeyboardLayout");
    pActivateKeyboardLayout = (activate_t)resolve("ActivateKeyboardLayout");
    pGetKeyboardLayoutList = (layout_list_t)resolve("GetKeyboardLayoutList");
    pGetKeyboardLayoutNameA = (layout_name_a_t)resolve("GetKeyboardLayoutNameA");
    pGetKeyboardLayoutNameW = (layout_name_w_t)resolve("GetKeyboardLayoutNameW");
    pkeybd_event = (keybd_event_t)resolve("keybd_event");
    pBlockInput = (block_input_t)resolve("BlockInput");
    pGetLastInputInfo = (last_input_t)resolve("GetLastInputInfo");
}

/* Whether `p` was resolved; prints "<name>: absent" when not. */
static int have(const void *p, const char *name)
{
    if (p == NULL) {
        line("%s: absent", name);
        return 0;
    }
    return 1;
}

/* --- the US layout, loaded and released ----------------------------- */

#define MAX_LAYOUTS 64

static HKL us;
static int us_added;
static HKL own;

static int in_list(HKL h, const HKL *list, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (list[i] == h) {
            return 1;
        }
    }
    return 0;
}

/* Load US without activating it; whether it was loaded before is kept
 * for us_release. Prints one line. */
static int us_load(void)
{
    HKL before[MAX_LAYOUTS];
    int n;

    if (!have(pGetKeyboardLayoutList, "GetKeyboardLayoutList")
        || !have(pLoadKeyboardLayoutA, "LoadKeyboardLayoutA")
        || !have(pUnloadKeyboardLayout, "UnloadKeyboardLayout")) {
        return 0;
    }
    n = pGetKeyboardLayoutList(MAX_LAYOUTS, before);
    if (n < 0) {
        n = 0;
    }
    us = pLoadKeyboardLayoutA("00000409", KLF_NOTELLSHELL_);
    us_added = us != NULL && !in_list(us, before, n);
    line("the US layout loaded: %s", yesno(us != NULL));
    return us != NULL;
}

/* Unload US if the section added it; the line reads the same either way. */
static void us_release(void)
{
    BOOL ok = TRUE;

    if (us != NULL && us_added) {
        ok = pUnloadKeyboardLayout(us);
    }
    line("unloaded what the section added: %s", ok ? "ok" : "failed");
    us = NULL;
    us_added = 0;
}

/* Make US the thread's layout, keeping the thread's own; prints one line. */
static int us_activate(void)
{
    HKL prev;

    if (!have(pActivateKeyboardLayout, "ActivateKeyboardLayout")) {
        return 0;
    }
    own = GetKeyboardLayout(0);
    prev = pActivateKeyboardLayout(us, 0);
    line("the US layout activated: %s", yesno(prev != NULL && GetKeyboardLayout(0) == us));
    return prev != NULL;
}

static void us_restore(void)
{
    pActivateKeyboardLayout(own, 0);
    line("the thread's own layout restored: %s", yesno(GetKeyboardLayout(0) == own));
}

/* --- layouts --------------------------------------------------------- */

static void sec_layouts(void)
{
    HKL list[MAX_LAYOUTS];
    HKL one[1];
    HKL cur, mine;
    int n, filled, r;

    arm();
    cur = GetKeyboardLayout(0);
    line("GetKeyboardLayout(0): non-NULL %s err=%s", yesno(cur != NULL), le());
    arm();
    mine = GetKeyboardLayout(GetCurrentThreadId());
    line("GetKeyboardLayout(the thread's id): the same %s err=%s", yesno(mine == cur), le());
    if (!have(pGetKeyboardLayoutList, "GetKeyboardLayoutList")) {
        return;
    }
    arm();
    n = pGetKeyboardLayoutList(0, NULL);
    line("GetKeyboardLayoutList(0, NULL): at least 1 %s err=%s", yesno(n >= 1), le());
    memset(list, 0, sizeof list);
    arm();
    filled = pGetKeyboardLayoutList(MAX_LAYOUTS, list);
    line("GetKeyboardLayoutList(64, buffer): the count before %s err=%s", yesno(filled == n), le());
    line("  the thread's layout in it: %s", yesno(in_list(cur, list, filled)));
    line("  every entry non-NULL: %s", yesno(!in_list(NULL, list, filled)));
    one[0] = NULL;
    arm();
    r = pGetKeyboardLayoutList(1, one);
    line("GetKeyboardLayoutList(1, buffer): 1 %s, the list's first %s err=%s", yesno(r == 1),
         yesno(one[0] == list[0]), le());
}

/* --- load ------------------------------------------------------------ */

static void sec_load(void)
{
    HKL before[MAX_LAYOUTS], after[MAX_LAYOUTS];
    HKL a, w, bogus;
    int n, m, added;
    BOOL ok;
    DWORD word;

    if (!have(pGetKeyboardLayoutList, "GetKeyboardLayoutList")
        || !have(pLoadKeyboardLayoutA, "LoadKeyboardLayoutA")
        || !have(pLoadKeyboardLayoutW, "LoadKeyboardLayoutW")
        || !have(pUnloadKeyboardLayout, "UnloadKeyboardLayout")) {
        return;
    }
    n = pGetKeyboardLayoutList(MAX_LAYOUTS, before);
    if (n < 0) {
        n = 0;
    }
    arm();
    a = pLoadKeyboardLayoutA("00000409", KLF_NOTELLSHELL_);
    line("LoadKeyboardLayoutA(\"00000409\", KLF_NOTELLSHELL): non-NULL %s err=%s", yesno(a != NULL), le());
    word = (DWORD)a;
    line("  low word 0x0409 %s, high word 0x0409 %s", yesno(LOWORD(word) == 0x0409),
         yesno(HIWORD(word) == 0x0409));
    added = a != NULL && !in_list(a, before, n);
    arm();
    w = pLoadKeyboardLayoutW(L"00000409", KLF_NOTELLSHELL_);
    line("LoadKeyboardLayoutW(\"00000409\", KLF_NOTELLSHELL): the same HKL %s err=%s", yesno(w == a), le());
    m = pGetKeyboardLayoutList(MAX_LAYOUTS, after);
    line("  in the list after: %s, the thread's layout unchanged: %s", yesno(in_list(a, after, m)),
         yesno(GetKeyboardLayout(0) != a || in_list(a, before, n)));

    arm();
    bogus = pLoadKeyboardLayoutA("0000F00D", KLF_NOTELLSHELL_);
    line("LoadKeyboardLayoutA(\"0000F00D\"): non-NULL %s, the US HKL %s, the thread's own %s err=%s",
         yesno(bogus != NULL), yesno(bogus == a), yesno(bogus == GetKeyboardLayout(0)), le());
    if (bogus != NULL && bogus != a && !in_list(bogus, before, n)) {
        pUnloadKeyboardLayout(bogus);
    }

    ok = TRUE;
    if (added) {
        arm();
        ok = pUnloadKeyboardLayout(a);
    }
    line("unloaded what the section added: %s", ok ? "ok" : "failed");
    m = pGetKeyboardLayoutList(MAX_LAYOUTS, after);
    line("  the list as before: %s", yesno(m == n));

    arm();
    ok = pUnloadKeyboardLayout((HKL)0x0F2F0F2F);
    line("UnloadKeyboardLayout(a bogus HKL): ret=%d err=%s", ok, le());
}

/* --- activate -------------------------------------------------------- */

static void sec_activate(void)
{
    HKL mine, prev, back;
    char name[KL_NAMELENGTH + 8];
    WCHAR wname[KL_NAMELENGTH + 8];
    BOOL r;

    if (!have(pActivateKeyboardLayout, "ActivateKeyboardLayout")
        || !have(pGetKeyboardLayoutNameA, "GetKeyboardLayoutNameA")
        || !have(pGetKeyboardLayoutNameW, "GetKeyboardLayoutNameW") || !us_load()) {
        return;
    }
    mine = GetKeyboardLayout(0);
    memset(name, 0, sizeof name);
    arm();
    r = pGetKeyboardLayoutNameA(name);
    line("GetKeyboardLayoutNameA (the thread's own): ret=%d, eight characters %s err=%s", r,
         yesno(strlen(name) == 8), le());

    arm();
    prev = pActivateKeyboardLayout(us, 0);
    line("ActivateKeyboardLayout(US, 0): the thread's own returned %s err=%s", yesno(prev == mine), le());
    line("  GetKeyboardLayout(0) is US: %s", yesno(GetKeyboardLayout(0) == us));
    memset(name, 0, sizeof name);
    arm();
    r = pGetKeyboardLayoutNameA(name);
    line("GetKeyboardLayoutNameA: ret=%d \"%s\" err=%s", r, name, le());
    memset(wname, 0, sizeof wname);
    arm();
    r = pGetKeyboardLayoutNameW(wname);
    line("GetKeyboardLayoutNameW: ret=%d \"%s\" err=%s", r, ws(wname), le());

    arm();
    back = pActivateKeyboardLayout(mine, 0);
    line("ActivateKeyboardLayout(the thread's own, 0): US returned %s err=%s", yesno(back == us), le());
    line("  GetKeyboardLayout(0) the thread's own again: %s", yesno(GetKeyboardLayout(0) == mine));

    arm();
    prev = pActivateKeyboardLayout((HKL)0x0F2F0F2F, 0);
    line("ActivateKeyboardLayout(a bogus HKL, 0): non-NULL %s err=%s", yesno(prev != NULL), le());
    line("  the thread's layout unchanged: %s", yesno(GetKeyboardLayout(0) == mine));
    us_release();
}

/* --- mapvk ----------------------------------------------------------- */

static const char *const map_types[4] = {
    "VK_TO_VSC", "VSC_TO_VK", "VK_TO_CHAR", "VSC_TO_VK_EX"
};

/* The codes a map type takes: virtual keys 0-255, scan codes 0-127. */
static UINT map_codes(UINT type)
{
    return (type == 1 || type == 3) ? 128 : 256;
}

static void sec_mapvk(void)
{
    static const UINT vks[] = {
        'A', 'Z', '0', '9', VK_RETURN, VK_ESCAPE, VK_SPACE, VK_BACK, VK_TAB, VK_SHIFT,
        VK_LSHIFT_, VK_RSHIFT_, VK_CONTROL, VK_LCONTROL_, VK_MENU, VK_RMENU_, VK_LEFT,
        VK_HOME, VK_INSERT, VK_DELETE, VK_NUMPAD0, VK_NUMPAD9, VK_MULTIPLY, VK_DIVIDE,
        VK_DECIMAL, VK_F1, VK_F12, VK_CAPITAL, VK_NUMLOCK, VK_PAUSE, VK_OEM_1_, VK_OEM_PLUS_,
        VK_OEM_2_, VK_OEM_7_, VK_OEM_102_
    };
    static const UINT scans[] = {
        0x01, 0x0E, 0x10, 0x1C, 0x1D, 0x1E, 0x2A, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3B, 0x45,
        0x47, 0x48, 0x4B, 0x53, 0x56, 0x57, 0x58, 0x5B
    };
    HKL cur;
    UINT type, code, a, wv, nonzero;
    DWORD sum;
    int w_same, plain_same, plain_w_same;
    int i;

    if (!have(pMapVirtualKeyExA, "MapVirtualKeyExA") || !have(pMapVirtualKeyExW, "MapVirtualKeyExW")
        || !have(pMapVirtualKeyA, "MapVirtualKeyA") || !have(pMapVirtualKeyW, "MapVirtualKeyW")
        || !us_load()) {
        return;
    }
    cur = GetKeyboardLayout(0);
    for (type = 0; type < 4; type++) {
        nonzero = 0;
        sum = 0;
        w_same = 1;
        plain_same = 1;
        plain_w_same = 1;
        for (code = 0; code < map_codes(type); code++) {
            a = pMapVirtualKeyExA(code, type, us);
            wv = pMapVirtualKeyExW(code, type, us);
            if (a != 0) {
                nonzero++;
            }
            sum = sum * 31 + a;
            if (wv != a) {
                w_same = 0;
            }
            if (pMapVirtualKeyA(code, type) != pMapVirtualKeyExA(code, type, cur)) {
                plain_same = 0;
            }
            if (pMapVirtualKeyW(code, type) != pMapVirtualKeyExW(code, type, cur)) {
                plain_w_same = 0;
            }
        }
        line("MapVirtualKeyExA(0-%u, %s, US): %u nonzero, sum 0x%08lX", map_codes(type) - 1,
             map_types[type], nonzero, sum);
        line("  MapVirtualKeyExW the same: %s; MapVirtualKeyA/W as the Ex forms on the thread's layout: %s %s",
             yesno(w_same), yesno(plain_same), yesno(plain_w_same));
    }
    for (i = 0; i < (int)(sizeof vks / sizeof vks[0]); i++) {
        line("  VK 0x%02X: VK_TO_VSC 0x%02X VK_TO_CHAR 0x%08X", vks[i], pMapVirtualKeyExA(vks[i], 0, us),
             pMapVirtualKeyExA(vks[i], 2, us));
    }
    for (i = 0; i < (int)(sizeof scans / sizeof scans[0]); i++) {
        line("  scan 0x%02X: VSC_TO_VK 0x%02X VSC_TO_VK_EX 0x%02X", scans[i],
             pMapVirtualKeyExA(scans[i], 1, us), pMapVirtualKeyExA(scans[i], 3, us));
    }
    /* What every Latin layout maps alike, on the thread's own. */
    plain_same = 1;
    for (code = 'A'; code <= 'Z'; code++) {
        if (pMapVirtualKeyA(code, 2) != code) {
            plain_same = 0;
        }
    }
    line("MapVirtualKeyA('A'-'Z', VK_TO_CHAR): the letter itself %s", yesno(plain_same));
    line("MapVirtualKeyA(VK_RETURN, VK_TO_VSC)=0x%02X MapVirtualKeyW(VK_F1, VK_TO_VSC)=0x%02X",
         pMapVirtualKeyA(VK_RETURN, 0), pMapVirtualKeyW(VK_F1, 0));
    arm();
    a = pMapVirtualKeyExA('A', 4, us);
    line("MapVirtualKeyExA('A', 4, US): ret=%u err=%s", a, le());
    arm();
    a = pMapVirtualKeyExA(0x1E, 0, NULL);
    line("MapVirtualKeyExA('A', VK_TO_VSC, NULL): as the thread's layout %s err=%s",
         yesno(a == pMapVirtualKeyA('A', 0)), le());
    us_release();
}

/* --- vkscan ---------------------------------------------------------- */

static void sec_vkscan(void)
{
    char buf[256];
    int c, n, w_same, plain_same;
    SHORT r;

    if (!have(pVkKeyScanExA, "VkKeyScanExA") || !have(pVkKeyScanExW, "VkKeyScanExW")
        || !have(pVkKeyScanA, "VkKeyScanA") || !have(pVkKeyScanW, "VkKeyScanW") || !us_load()) {
        return;
    }
    for (c = 0; c < 0x80; c += 16) {
        int k;

        n = sprintf(buf, "VkKeyScanExA(0x%02X-0x%02X, US):", c, c + 15);
        for (k = c; k < c + 16; k++) {
            n += sprintf(buf + n, " %04X", (unsigned)(WORD)pVkKeyScanExA((CHAR)k, us));
        }
        line("%s", buf);
    }
    w_same = 1;
    for (c = 0; c < 0x80; c++) {
        if (pVkKeyScanExW((WCHAR)c, us) != pVkKeyScanExA((CHAR)c, us)) {
            w_same = 0;
        }
    }
    line("VkKeyScanExW(0x00-0x7F, US) the same: %s", yesno(w_same));
    arm();
    r = pVkKeyScanExW(0x00E9, us);
    line("VkKeyScanExW(U+00E9, US): %04X err=%s", (unsigned)(WORD)r, le());
    arm();
    r = pVkKeyScanExW(0x20AC, us);
    line("VkKeyScanExW(U+20AC, US): %04X err=%s", (unsigned)(WORD)r, le());
    arm();
    r = pVkKeyScanExA((CHAR)0xE9, us);
    line("VkKeyScanExA(0xE9, US): %04X err=%s", (unsigned)(WORD)r, le());

    /* Letters and digits, on any Latin layout: no shift state, the letter's
     * or digit's own key. */
    plain_same = 1;
    for (c = 'a'; c <= 'z'; c++) {
        if (pVkKeyScanA((CHAR)c) != c - 'a' + 'A' || pVkKeyScanW((WCHAR)c) != c - 'a' + 'A') {
            plain_same = 0;
        }
    }
    line("VkKeyScanA/W('a'-'z'): the letter's key, no shift %s", yesno(plain_same));
    plain_same = 1;
    for (c = '0'; c <= '9'; c++) {
        if (pVkKeyScanA((CHAR)c) != c || pVkKeyScanW((WCHAR)c) != c) {
            plain_same = 0;
        }
    }
    line("VkKeyScanA/W('0'-'9'): the digit's key, no shift %s", yesno(plain_same));
    line("VkKeyScanA('A')=%04X VkKeyScanW(' ')=%04X VkKeyScanA('\\r')=%04X",
         (unsigned)(WORD)pVkKeyScanA('A'), (unsigned)(WORD)pVkKeyScanW(L' '),
         (unsigned)(WORD)pVkKeyScanA('\r'));
    us_release();
}

/* --- toascii --------------------------------------------------------- */

typedef struct {
    const char *name;
    BYTE keys[4];   /* virtual keys held down (0 ends) */
    BYTE toggled;   /* a toggle key on, or 0 */
} kstate_t;

static const kstate_t kstates[] = {
    { "none", { 0 }, 0 },
    { "Shift", { VK_SHIFT, VK_LSHIFT_, 0 }, 0 },
    { "Ctrl", { VK_CONTROL, VK_LCONTROL_, 0 }, 0 },
    { "Ctrl+Alt", { VK_CONTROL, VK_LCONTROL_, VK_MENU, VK_RMENU_ }, 0 },
    { "CapsLock", { 0 }, VK_CAPITAL },
    { "CapsLock+Shift", { VK_SHIFT, VK_LSHIFT_, 0 }, VK_CAPITAL },
    { "NumLock", { 0 }, VK_NUMLOCK },
};

static void build_state(const kstate_t *s, BYTE *state)
{
    int i;

    memset(state, 0, 256);
    for (i = 0; i < 4 && s->keys[i] != 0; i++) {
        state[s->keys[i]] = 0x80;
    }
    if (s->toggled != 0) {
        state[s->toggled] = 0x01;
    }
}

/* ToAsciiEx's and ToUnicodeEx's answers for one key and state, one line. */
static void translate(UINT vk, const kstate_t *s, UINT scan_flags, UINT flags)
{
    BYTE state[256];
    WORD chars[4];
    WCHAR wbuf[8];
    UINT scan;
    int ra, rw;
    char abuf[32];
    int n, i;

    build_state(s, state);
    scan = pMapVirtualKeyExA(vk, 0, us) | scan_flags;
    memset(chars, 0, sizeof chars);
    memset(wbuf, 0, sizeof wbuf);
    ra = pToAsciiEx(vk, scan, state, chars, flags, us);
    rw = pToUnicodeEx(vk, scan, state, wbuf, 8, flags, us);
    n = 0;
    for (i = 0; i < (ra > 0 ? ra : 0) && i < 2; i++) {
        n += sprintf(abuf + n, " %02X", (unsigned)(chars[i] & 0xFF));
    }
    abuf[n] = '\0';
    line("  VK 0x%02X %s%s: ToAsciiEx=%d%s ToUnicodeEx=%d \"%s\"", vk, s->name,
         scan_flags & 0x8000 ? " (released)" : flags ? " (menu)" : "", ra, abuf, rw,
         wsn(wbuf, rw > 0 ? rw : 0));
}

static void sec_toascii(void)
{
    static const UINT keys[] = {
        'A', '1', '2', '6', VK_SPACE, VK_RETURN, VK_BACK, VK_ESCAPE, VK_TAB, VK_OEM_1_,
        VK_OEM_4_, VK_OEM_7_, VK_OEM_102_, VK_LEFT, VK_F1
    };
    static const UINT numpad[] = { VK_NUMPAD5, VK_DECIMAL, VK_MULTIPLY, VK_CLEAR };
    BYTE state[256];
    WORD chars[4];
    WCHAR wbuf[8];
    int i, k, r, ok;
    UINT c;

    if (!have(pToAsciiEx, "ToAsciiEx") || !have(pToUnicodeEx, "ToUnicodeEx")
        || !have(pToAscii, "ToAscii") || !have(pToUnicode, "ToUnicode")
        || !have(pMapVirtualKeyExA, "MapVirtualKeyExA") || !have(pMapVirtualKeyA, "MapVirtualKeyA")
        || !us_load()) {
        return;
    }
    for (k = 0; k < 6; k++) {
        line("with %s:", kstates[k].name);
        for (i = 0; i < (int)(sizeof keys / sizeof keys[0]); i++) {
            translate(keys[i], &kstates[k], 0, 0);
        }
    }
    line("the number pad:");
    for (i = 0; i < (int)(sizeof numpad / sizeof numpad[0]); i++) {
        translate(numpad[i], &kstates[0], 0, 0);
        translate(numpad[i], &kstates[6], 0, 0);
    }
    line("a release, and menu mode:");
    translate('A', &kstates[0], 0x8000, 0);
    translate('A', &kstates[0], 0, 1);
    translate('A', &kstates[3], 0, 1);

    build_state(&kstates[1], state);
    arm();
    r = pToUnicodeEx('A', pMapVirtualKeyExA('A', 0, us), state, wbuf, 0, 0, us);
    line("ToUnicodeEx('A', buffer of 0): ret=%d err=%s", r, le());

    /* The thread's own layout: letters and digits, alike on any Latin
     * layout. */
    ok = 1;
    for (c = 'A'; c <= 'Z'; c++) {
        build_state(&kstates[0], state);
        memset(chars, 0, sizeof chars);
        if (pToAscii(c, pMapVirtualKeyA(c, 0), state, chars, 0) != 1 || chars[0] != c - 'A' + 'a') {
            ok = 0;
        }
        build_state(&kstates[1], state);
        memset(wbuf, 0, sizeof wbuf);
        if (pToUnicode(c, pMapVirtualKeyA(c, 0), state, wbuf, 8, 0) != 1 || wbuf[0] != c) {
            ok = 0;
        }
    }
    line("ToAscii('A'-'Z') lower case, ToUnicode('A'-'Z', Shift) upper case: %s", yesno(ok));
    ok = 1;
    for (c = '0'; c <= '9'; c++) {
        build_state(&kstates[0], state);
        memset(chars, 0, sizeof chars);
        memset(wbuf, 0, sizeof wbuf);
        if (pToAscii(c, pMapVirtualKeyA(c, 0), state, chars, 0) != 1 || chars[0] != c
            || pToUnicode(c, pMapVirtualKeyA(c, 0), state, wbuf, 8, 0) != 1 || wbuf[0] != c) {
            ok = 0;
        }
    }
    line("ToAscii/ToUnicode('0'-'9'): the digit %s", yesno(ok));
    us_release();
}

/* --- keyname --------------------------------------------------------- */

static void key_name(LONG lparam, const char *what)
{
    char a[64];
    WCHAR w[64];
    int ra, rw;
    const char *ea;

    memset(a, 0, sizeof a);
    memset(w, 0, sizeof w);
    arm();
    ra = pGetKeyNameTextA(lparam, a, 64);
    ea = le();
    arm();
    rw = pGetKeyNameTextW(lparam, w, 64);
    line("  0x%08lX%s: A ret=%d \"%s\" err=%s, W ret=%d \"%s\" err=%s", (unsigned long)lparam, what, ra, a,
         ea, rw, ws(w), le());
}

static void sec_keyname(void)
{
    static const BYTE scans[] = {
        0x01, 0x02, 0x0C, 0x0E, 0x0F, 0x1C, 0x1D, 0x1E, 0x29, 0x2A, 0x2B, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3A, 0x3B, 0x44, 0x45, 0x46, 0x47, 0x48, 0x4A, 0x4C, 0x52, 0x53, 0x54, 0x56, 0x57,
        0x58, 0x5B, 0x70, 0x7F
    };
    static const BYTE extended[] = { 0x1C, 0x1D, 0x35, 0x37, 0x38, 0x45, 0x47, 0x48, 0x52, 0x53, 0x5B, 0x5C, 0x5D };
    char a[8];
    WCHAR w[8];
    int i, r;

    if (!have(pGetKeyNameTextA, "GetKeyNameTextA") || !have(pGetKeyNameTextW, "GetKeyNameTextW")
        || !us_load()) {
        return;
    }
    if (!us_activate()) {
        us_release();
        return;
    }
    line("scan codes:");
    for (i = 0; i < (int)(sizeof scans / sizeof scans[0]); i++) {
        key_name((LONG)scans[i] << 16, "");
    }
    line("extended (1 << 24):");
    for (i = 0; i < (int)(sizeof extended / sizeof extended[0]); i++) {
        key_name(((LONG)extended[i] << 16) | (1L << 24), "");
    }
    line("don't care (1 << 25):");
    key_name(0x2AL << 16 | (1L << 25), "");
    key_name(0x36L << 16 | (1L << 25), "");
    key_name(0x1DL << 16 | (1L << 24) | (1L << 25), "");
    key_name(0x38L << 16 | (1L << 24) | (1L << 25), "");
    key_name(0x1EL << 16 | 0x0001L | (1L << 30) | (1L << 31), " (a key message's other bits)");

    memset(a, 'x', sizeof a);
    arm();
    r = pGetKeyNameTextA(0x2AL << 16, a, 4);
    line("GetKeyNameTextA(Shift, buffer of 4): ret=%d \"%.4s\" err=%s", r, a, le());
    memset(w, 'x', sizeof w);
    arm();
    r = pGetKeyNameTextW(0x2AL << 16, w, 4);
    line("GetKeyNameTextW(Shift, buffer of 4): ret=%d \"%s\" err=%s", r, wsn(w, 4), le());
    a[0] = 'x';
    arm();
    r = pGetKeyNameTextA(0x2AL << 16, a, 0);
    line("GetKeyNameTextA(Shift, buffer of 0): ret=%d, the buffer untouched %s err=%s", r, yesno(a[0] == 'x'),
         le());
    us_restore();
    us_release();
}

/* --- oemscan --------------------------------------------------------- */

static void sec_oemscan(void)
{
    char buf[256];
    int c, n, k;

    if (!have(pOemKeyScan, "OemKeyScan") || !us_load()) {
        return;
    }
    if (!us_activate()) {
        us_release();
        return;
    }
    for (c = 0; c < 0x80; c += 8) {
        n = sprintf(buf, "OemKeyScan(0x%02X-0x%02X):", c, c + 7);
        for (k = c; k < c + 8; k++) {
            n += sprintf(buf + n, " %08lX", (unsigned long)pOemKeyScan((WORD)k));
        }
        line("%s", buf);
    }
    arm();
    line("OemKeyScan(0x0141): %08lX err=%s", (unsigned long)pOemKeyScan(0x0141), le());
    us_restore();
    us_release();
}

/* --- kbtype ---------------------------------------------------------- */

static void sec_kbtype(void)
{
    int i, r;
    UINT cp;

    if (!have(pGetKeyboardType, "GetKeyboardType") || !have(pGetKBCodePage, "GetKBCodePage")) {
        return;
    }
    for (i = 0; i < 4; i++) {
        arm();
        r = pGetKeyboardType(i);
        line("GetKeyboardType(%d): %d err=%s", i, r, le());
    }
    arm();
    cp = pGetKBCodePage();
    line("GetKBCodePage: GetOEMCP's %s err=%s", yesno(cp == GetOEMCP()), le());
}

/* --- inject ---------------------------------------------------------- */

static void sec_inject(void)
{
    lastinput_t li;
    DWORD t0, now;
    BOOL r;
    SHORT down, up;

    if (!have(pGetLastInputInfo, "GetLastInputInfo") || !have(pkeybd_event, "keybd_event")
        || !have(pBlockInput, "BlockInput")) {
        return;
    }
    li.cbSize = 0;
    li.dwTime = 0;
    arm();
    r = pGetLastInputInfo(&li);
    line("GetLastInputInfo(cbSize 0): ret=%d err=%s", r, le());
    li.cbSize = sizeof li;
    li.dwTime = 0;
    arm();
    r = pGetLastInputInfo(&li);
    now = GetTickCount();
    line("GetLastInputInfo(cbSize 8): ret=%d err=%s, dwTime at or before GetTickCount %s", r, le(),
         yesno(li.dwTime <= now));

    Sleep(100);
    t0 = GetTickCount();
    arm();
    pkeybd_event(VK_F24_, 0, 0, 0);
    line("keybd_event(VK_F24, down): err=%s", le());
    down = GetAsyncKeyState(VK_F24_);
    arm();
    pkeybd_event(VK_F24_, 0, KEYEVENTF_KEYUP, 0);
    line("keybd_event(VK_F24, up): err=%s", le());
    up = GetAsyncKeyState(VK_F24_);
    line("GetAsyncKeyState(VK_F24) between: down %s; after: down %s", yesno(down < 0), yesno(up < 0));
    li.cbSize = sizeof li;
    li.dwTime = 0;
    r = pGetLastInputInfo(&li);
    line("GetLastInputInfo after: ret=%d, dwTime at or after the keys %s", r,
         yesno((LONG)(li.dwTime - t0) >= 0));

    arm();
    r = pBlockInput(FALSE);
    line("BlockInput(FALSE): ret=%d err=%s", r, le());
}

/* ------------------------------------------------------------------ */

static const section_t sections[] = {
    { "layouts", sec_layouts, F2KT_ALWAYS },
    { "load", sec_load, F2KT_ALWAYS },
    { "activate", sec_activate, F2KT_ALWAYS },
    { "mapvk", sec_mapvk, F2KT_ALWAYS },
    { "vkscan", sec_vkscan, F2KT_ALWAYS },
    { "toascii", sec_toascii, F2KT_ALWAYS },
    { "keyname", sec_keyname, F2KT_ALWAYS },
    { "oemscan", sec_oemscan, F2KT_ALWAYS },
    { "kbtype", sec_kbtype, F2KT_ALWAYS },
    { "inject", sec_inject, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    resolve_all();
    return run_sections("keymap", sections, argc, argv);
}
