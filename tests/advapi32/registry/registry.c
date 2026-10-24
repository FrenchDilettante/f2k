/*
 * registry - the registry calls cmd.exe imports: RegCreateKeyEx,
 * RegOpenKeyEx, RegOpenKey, RegCloseKey, RegSetValueEx,
 * RegQueryValueEx, RegSetValue, RegQueryValue, RegEnumKey and
 * RegDeleteKey.
 *
 * Everything happens under HKEY_CURRENT_USER\Software\F2K (the F2K
 * tree). F2K boots with an empty registry, so the fixture reads nothing
 * it did not create: HKEY_CURRENT_USER exists, every key below it is
 * the fixture's own.
 *
 * Each section first deletes the F2K tree, silently, then observes in
 * two passes: the W calls, then their A twins on the same inputs (each
 * line names its function, W or A). A pass starts by deleting the tree
 * and ends by deleting it again, printing that it is gone, so the next
 * pass, section and run start from the same state. The deletion goes
 * bottom-up through RegEnumKeyW and RegDeleteKeyW (on NT RegDeleteKey
 * refuses a key with subkeys). The setup (the keys and values a check
 * reads, made through RegCreateKeyExW and RegSetValueExW) stays W and
 * prints nothing.
 *
 * The Reg* functions return their error code: a line prints the return
 * (ret=) and the last error (err=, "-" when untouched), which pins
 * whether they set it. A buffer handed to a call starts filled with
 * 0xCC bytes, and a result handle, disposition, type or size the call
 * may write starts as a marker printed "unset", so a line shows what
 * the call wrote. Text prints a NUL as \0.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create      RegCreateKeyEx creating F2K and three levels below it
 *               at once (REG_CREATED_NEW_KEY), again
 *               (REG_OPENED_EXISTING_KEY), a level the first call
 *               created, a path in other case, an empty subkey name, a
 *               NULL disposition, leading and trailing backslashes, a
 *               bogus root handle
 *   open        RegOpenKeyEx of existing keys (in other case too), of
 *               missing ones (what it leaves in the result), of an
 *               empty and a NULL subkey (a new handle to the same key),
 *               leading and trailing backslashes, a bogus and a NULL
 *               root, through a KEY_READ handle (a value set and a
 *               subkey created through it); RegOpenKey of a NULL and an
 *               empty subkey (whether the same handle comes back), a
 *               subkey, a missing one, HKEY_CURRENT_USER's NULL subkey
 *   close       RegCloseKey of an open key, of the same handle again,
 *               of NULL, of a bogus handle, of HKEY_CURRENT_USER (then
 *               used again); RegCloseKey has no A twin: one pass
 *   setvalue    RegSetValueEx of REG_SZ with and without its terminator
 *               counted, REG_EXPAND_SZ (not expanded when read),
 *               REG_MULTI_SZ, REG_DWORD, REG_BINARY, zero-length
 *               REG_BINARY and REG_SZ, each read back through
 *               RegQueryValueEx; a value overwritten with another type
 *               and back; the default value through a NULL name read
 *               through an empty one, and the reverse
 *   queryvalue  RegQueryValueEx's sizes on a REG_SZ: NULL data (the
 *               size alone), NULL data and size, a buffer of the data's
 *               size, one byte short and empty (the size reported, what
 *               was written), data with a NULL size, a NULL type; a
 *               missing value, the name in other case; a REG_DWORD
 *               read into 4 bytes and 3
 *   default     RegSetValue creating a subkey for its default value,
 *               and three levels; RegQueryValue of it (the size alone,
 *               exact, one byte short); the key's own default value
 *               (NULL and empty subkey, and as RegQueryValueEx sees
 *               it); a type other than REG_SZ; a subkey with no default
 *               value; a missing subkey; a default value of REG_DWORD
 *   enum        RegEnumKey over subkeys created out of order (the order
 *               it returns them in) to its end (ERROR_NO_MORE_ITEMS)
 *               and past it, buffers of 0, 3, 5 and 6 units for a
 *               5-letter name, a key with no subkeys, the order after a
 *               delete
 *   delete      RegDeleteKey of a key with subkeys (refused), a leaf
 *               down a path, the levels emptied above it, a name in
 *               other case, a deleted and a missing key, a bogus root;
 *               a key deleted while a handle to it is open: the handle
 *               queried, written, created under and enumerated, the
 *               name created anew, the old handle queried again and
 *               closed
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat registry):
 *   cl /nologo /I .. registry.c advapi32.lib
 */

#include "../common/f2kt.h"

/* The F2K tree, below HKEY_CURRENT_USER. */
#define TREE "Software\\F2K"

/* A handle value no key has. */
#define BOGUS_KEY ((HKEY)0x7FFFFFFC)

/* What a result handle, a disposition, a type or a size starts as, so a
 * line shows whether the call wrote it. */
#define UNSET_KEY ((HKEY)0x00F2F2F0)
#define UNSET 0xF2F2F2F2u

/* No buffer: the call gets NULL data. */
#define NO_DATA ((DWORD)-1)

/* A string literal's characters and its size, its terminator included. */
#define TXT(s) s, sizeof s

/* The pass: 1 the W calls, 0 their A twins. */
static int wide;

/* The buffer a call reads into. */
static union {
    BYTE b[1024];
    WCHAR w[512];
} buf;

/* --- printing ------------------------------------------------------ */

/* The pass's form of a function: "RegOpenKeyEx" as RegOpenKeyExW or
 * RegOpenKeyExA. */
static const char *fn(const char *name)
{
    static char bufs[4][48];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s%c", name, wide ? 'W' : 'A');
    return b;
}

/* A name argument as printed: NULL, or quoted. */
static const char *arg(const char *s)
{
    static char bufs[4][MAX_PATH + 4];
    static int next;
    char *b = bufs[next++ & 3];

    if (s == NULL) {
        return "NULL";
    }
    sprintf(b, "\"%s\"", s);
    return b;
}

/* A number as printed, "unset" for the marker. */
static const char *number(DWORD v)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    if (v == UNSET) {
        return "unset";
    }
    sprintf(b, "%lu", v);
    return b;
}

static const char *type_name(DWORD type)
{
    switch (type) {
    case REG_NONE: return "REG_NONE";
    case REG_SZ: return "REG_SZ";
    case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
    case REG_BINARY: return "REG_BINARY";
    case REG_DWORD: return "REG_DWORD";
    case REG_MULTI_SZ: return "REG_MULTI_SZ";
    }
    return number(type);
}

static const char *disposition_name(DWORD d)
{
    switch (d) {
    case REG_CREATED_NEW_KEY: return "REG_CREATED_NEW_KEY";
    case REG_OPENED_EXISTING_KEY: return "REG_OPENED_EXISTING_KEY";
    }
    return number(d);
}

/* A result handle as printed: never its value. */
static const char *result_name(HKEY k)
{
    if (k == UNSET_KEY) {
        return "unset";
    }
    return k == NULL ? "NULL" : "a handle";
}

/* `n` bytes as hex ("(none)" for none). */
static const char *hex(const BYTE *p, DWORD n)
{
    static char bufs[2][3 * 64 + 8];
    static int next;
    char *b = bufs[next++ & 1];
    DWORD i;
    int k = 0;

    if (n == 0) {
        return "(none)";
    }
    for (i = 0; i < n && i < 64; i++) {
        k += sprintf(b + k, i ? " %02X" : "%02X", p[i]);
    }
    if (n > 64) {
        sprintf(b + k, " ...");
    }
    return b;
}

/* The buffer as text, its first `units` units (W: WCHARs, A: bytes): a
 * NUL as \0, printable ASCII as itself, any other unit as <U+XXXX> (W)
 * or \xHH (A); "(none)" for no units. */
static const char *text(DWORD units)
{
    static char bufs[2][1100];
    static int next;
    char *b = bufs[next++ & 1];
    DWORD i;
    unsigned u;
    int k = 0;

    if (units == 0) {
        return "(none)";
    }
    if (units > (wide ? sizeof buf.w / sizeof buf.w[0] : sizeof buf.b)) {
        units = wide ? sizeof buf.w / sizeof buf.w[0] : sizeof buf.b;
    }
    for (i = 0; i < units && k < (int)sizeof bufs[0] - 12; i++) {
        u = wide ? buf.w[i] : buf.b[i];
        if (u == 0) {
            b[k++] = '\\';
            b[k++] = '0';
        } else if (u >= 0x20 && u < 0x7F) {
            b[k++] = (char)u;
        } else {
            k += sprintf(b + k, wide ? "<U+%04X>" : "\\x%02X", u);
        }
    }
    b[k] = 0;
    return b;
}

/* `cb` bytes of the buffer as data of `type`: text for the string types
 * (an odd byte left over in hex), bytes for the others. */
static const char *data_of(DWORD type, DWORD cb)
{
    static char b[1200];

    if (cb > sizeof buf.b) {
        cb = sizeof buf.b;
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        if (wide && cb % 2 != 0) {
            sprintf(b, "%s +%s", text(cb / 2), hex(buf.b + cb - 1, 1));
            return b;
        }
        return text(wide ? cb / 2 : cb);
    }
    return hex(buf.b, cb);
}

/* The buffer after a call that failed, or was given no size: its first
 * `room` bytes in hex, or only whether they are untouched when there
 * are many. */
static const char *buffer_after(DWORD room)
{
    DWORD i;

    if (room > sizeof buf.b) {
        room = sizeof buf.b;
    }
    if (room <= 16) {
        return hex(buf.b, room);
    }
    for (i = 0; i < room; i++) {
        if (buf.b[i] != 0xCC) {
            return "written";
        }
    }
    return "untouched";
}

static void fill(void)
{
    memset(buf.b, 0xCC, sizeof buf.b);
}

/* --- the calls, in the pass's form --------------------------------- */

/* An ASCII string as the W calls take it; NULL stays NULL. */
static WCHAR *wide_of(const char *s)
{
    static WCHAR bufs[4][MAX_PATH];
    static int next;
    WCHAR *b = bufs[next++ & 3];
    int i;

    if (s == NULL) {
        return NULL;
    }
    for (i = 0; s[i] != 0 && i < MAX_PATH - 1; i++) {
        b[i] = (WCHAR)(unsigned char)s[i];
    }
    b[i] = 0;
    return b;
}

static LONG create_ex(HKEY root, const char *sub, HKEY *out, DWORD *disposition)
{
    if (wide) {
        return RegCreateKeyExW(root, wide_of(sub), 0, NULL, REG_OPTION_NON_VOLATILE,
                               KEY_ALL_ACCESS, NULL, out, disposition);
    }
    return RegCreateKeyExA(root, (char *)sub, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                           NULL, out, disposition);
}

static LONG open_ex(HKEY root, const char *sub, REGSAM sam, HKEY *out)
{
    if (wide) {
        return RegOpenKeyExW(root, wide_of(sub), 0, sam, out);
    }
    return RegOpenKeyExA(root, (char *)sub, 0, sam, out);
}

static LONG open_key(HKEY root, const char *sub, HKEY *out)
{
    if (wide) {
        return RegOpenKeyW(root, wide_of(sub), out);
    }
    return RegOpenKeyA(root, (char *)sub, out);
}

static LONG delete_key(HKEY root, const char *sub)
{
    if (wide) {
        return RegDeleteKeyW(root, wide_of(sub));
    }
    return RegDeleteKeyA(root, (char *)sub);
}

/* RegEnumKey into the buffer, `cch` units of it. */
static LONG enum_key(HKEY key, DWORD index, DWORD cch)
{
    if (wide) {
        return RegEnumKeyW(key, index, buf.w, cch);
    }
    return RegEnumKeyA(key, index, (char *)buf.b, cch);
}

/* RegSetValueEx of text: `count` units of `chars` (its NULs included),
 * as the pass's characters; cbData is their size in bytes. */
static LONG set_text(HKEY key, const char *name, DWORD type, const char *chars, int count)
{
    WCHAR w[256];
    int i;

    if (wide) {
        for (i = 0; i < count; i++) {
            w[i] = (WCHAR)(unsigned char)chars[i];
        }
        return RegSetValueExW(key, wide_of(name), 0, type, (const BYTE *)w,
                              (DWORD)count * sizeof(WCHAR));
    }
    return RegSetValueExA(key, (char *)name, 0, type, (const BYTE *)chars, (DWORD)count);
}

static LONG set_raw(HKEY key, const char *name, DWORD type, const BYTE *data, DWORD cb)
{
    if (wide) {
        return RegSetValueExW(key, wide_of(name), 0, type, data, cb);
    }
    return RegSetValueExA(key, (char *)name, 0, type, data, cb);
}

static LONG query_ex(HKEY key, const char *name, DWORD *type, BYTE *data, DWORD *cb)
{
    if (wide) {
        return RegQueryValueExW(key, wide_of(name), NULL, type, data, cb);
    }
    return RegQueryValueExA(key, (char *)name, NULL, type, data, cb);
}

/* RegSetValue of `s`; cbData is its size in bytes, its terminator not
 * counted. */
static LONG set_default(HKEY key, const char *sub, DWORD type, const char *s)
{
    if (wide) {
        return RegSetValueW(key, wide_of(sub), type, wide_of(s),
                            (DWORD)strlen(s) * sizeof(WCHAR));
    }
    return RegSetValueA(key, (char *)sub, type, (char *)s, (DWORD)strlen(s));
}

static LONG query_default(HKEY key, const char *sub, int with_data, LONG *cb)
{
    if (wide) {
        return RegQueryValueW(key, wide_of(sub), with_data ? buf.w : NULL, cb);
    }
    return RegQueryValueA(key, (char *)sub, with_data ? (char *)buf.b : NULL, cb);
}

/* --- setup, through the W calls, silent ---------------------------- */

static void shut(HKEY k)
{
    if (k != NULL) {
        RegCloseKey(k);
    }
}

/* Create HKCU\Software\F2K\<path> ("" for F2K itself), the levels above
 * it too: its handle, or NULL. */
static HKEY make(const char *path)
{
    char full[MAX_PATH];
    HKEY k;

    sprintf(full, path[0] != 0 ? "%s\\%s" : "%s", TREE, path);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, wide_of(full), 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &k, NULL) != ERROR_SUCCESS) {
        return NULL;
    }
    return k;
}

static int exists(HKEY key, const char *sub)
{
    HKEY k;

    if (RegOpenKeyExW(key, wide_of(sub), 0, KEY_READ, &k) != ERROR_SUCCESS) {
        return 0;
    }
    RegCloseKey(k);
    return 1;
}

/* A key's subkeys as RegEnumKeyW lists them, comma-separated. */
static const char *subkeys(HKEY key)
{
    static char b[512];
    WCHAR name[256];
    DWORD i;
    int k = 0;

    b[0] = 0;
    for (i = 0; i < 16 && RegEnumKeyW(key, i, name, 256) == ERROR_SUCCESS; i++) {
        k += _snprintf(b + k, sizeof b - k - 1, "%s%s", i ? ", " : "", ws(name));
    }
    return b[0] != 0 ? b : "(none)";
}

/* Delete `name` below `parent` and everything below it, bottom-up;
 * whether it went. */
static int delete_tree(HKEY parent, const WCHAR *name)
{
    HKEY k;
    WCHAR child[256];

    if (RegOpenKeyExW(parent, name, 0, KEY_ALL_ACCESS, &k) != ERROR_SUCCESS) {
        return 0;
    }
    while (RegEnumKeyW(k, 0, child, 256) == ERROR_SUCCESS) {
        if (!delete_tree(k, child)) {
            break;
        }
    }
    RegCloseKey(k);
    return RegDeleteKeyW(parent, name) == ERROR_SUCCESS;
}

/* Delete the F2K tree: whether it is gone. */
static int wipe(void)
{
    delete_tree(HKEY_CURRENT_USER, wide_of(TREE));
    return !exists(HKEY_CURRENT_USER, TREE);
}

/* Run a section's observations through the W calls, then their A twins,
 * each pass from a deleted F2K tree, and delete it after. */
static void passes(void (*body)(void))
{
    for (wide = 1; wide >= 0; wide--) {
        wipe();
        line("-- the %s calls", wide ? "W" : "A");
        body();
        line("the F2K tree deleted: %s", yesno(wipe()));
    }
}

/* --- observed calls, one line each --------------------------------- */

/* RegCreateKeyEx of `sub` below `root` (printed as `where`): its handle,
 * which the caller closes, or NULL. */
static HKEY create_line(HKEY root, const char *where, const char *sub, const char *label,
                        int want_disposition)
{
    HKEY k = UNSET_KEY;
    DWORD d = UNSET;
    LONG r;

    arm();
    r = create_ex(root, sub, &k, want_disposition ? &d : NULL);
    line("%s(%s, %s)%s: ret=%ld err=%s result=%s disposition=%s", fn("RegCreateKeyEx"), where,
         arg(sub), label, r, le(), result_name(k),
         want_disposition ? disposition_name(d) : "not asked");
    return r == ERROR_SUCCESS && k != UNSET_KEY ? k : NULL;
}

/* RegOpenKeyEx of `sub` below `root`: its handle, or NULL. */
static HKEY open_line(HKEY root, const char *where, const char *sub, REGSAM sam,
                      const char *label)
{
    HKEY k = UNSET_KEY;
    LONG r;

    arm();
    r = open_ex(root, sub, sam, &k);
    line("%s(%s, %s)%s: ret=%ld err=%s result=%s", fn("RegOpenKeyEx"), where, arg(sub), label, r,
         le(), result_name(k));
    return r == ERROR_SUCCESS && k != UNSET_KEY ? k : NULL;
}

/* RegOpenKey of `sub` below `root`: whether the handle that came back is
 * `root` itself; a new one is closed. */
static void open_key_line(HKEY root, const char *where, const char *sub, const char *label)
{
    HKEY k = UNSET_KEY;
    LONG r;

    arm();
    r = open_key(root, sub, &k);
    line("%s(%s, %s)%s: ret=%ld err=%s result=%s the same handle: %s", fn("RegOpenKey"), where,
         arg(sub), label, r, le(), result_name(k), yesno(k == root));
    if (r == ERROR_SUCCESS && k != root && k != UNSET_KEY) {
        shut(k);
    }
}

static void delete_line(HKEY root, const char *where, const char *sub, const char *label)
{
    LONG r;

    arm();
    r = delete_key(root, sub);
    line("%s(%s, %s)%s: ret=%ld err=%s", fn("RegDeleteKey"), where, arg(sub), label, r, le());
}

/* RegSetValueEx of text, then the value read back. */
static void read_back(HKEY key, const char *name);

static void set_text_line(HKEY key, const char *name, DWORD type, const char *chars, int count,
                          const char *label)
{
    LONG r;

    arm();
    r = set_text(key, name, type, chars, count);
    line("%s(%s)%s: ret=%ld err=%s", fn("RegSetValueEx"), arg(name), label, r, le());
    read_back(key, name);
}

static void set_raw_line(HKEY key, const char *name, DWORD type, const BYTE *data, DWORD cb,
                         const char *label)
{
    LONG r;

    arm();
    r = set_raw(key, name, type, data, cb);
    line("%s(%s)%s: ret=%ld err=%s", fn("RegSetValueEx"), arg(name), label, r, le());
    read_back(key, name);
}

/* RegQueryValueEx of `name` into the whole buffer: the type, the size,
 * the data, and for the string types the next unit after the data (what
 * the call wrote past it). */
static void read_back(HKEY key, const char *name)
{
    DWORD type = UNSET, cb = sizeof buf.b;
    LONG r;
    int string;

    fill();
    arm();
    r = query_ex(key, name, &type, buf.b, &cb);
    if (r != ERROR_SUCCESS) {
        line("  %s(%s): ret=%ld err=%s type=%s cb=%s buffer=%s", fn("RegQueryValueEx"), arg(name), r,
             le(), type_name(type), number(cb), buffer_after(sizeof buf.b));
        return;
    }
    string = type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ;
    line("  %s(%s): ret=%ld err=%s type=%s cb=%s data=%s%s%s", fn("RegQueryValueEx"), arg(name), r,
         le(), type_name(type), number(cb), data_of(type, cb), string ? " next=" : "",
         string && cb + 2 <= sizeof buf.b ? hex(buf.b + cb, wide ? 2 : 1) : "");
}

/* RegQueryValueEx of `name`, a value of type `shape`: with or without a
 * type, a size, and a buffer of `room` bytes (NO_DATA: none). */
static void query_line(HKEY key, const char *name, const char *label, int want_type, DWORD room,
                       int want_cb, DWORD shape)
{
    DWORD type = UNSET, cb = room == NO_DATA ? 0 : room;
    LONG r;
    const char *after;

    fill();
    arm();
    r = query_ex(key, name, want_type ? &type : NULL, room == NO_DATA ? NULL : buf.b,
                 want_cb ? &cb : NULL);
    if (room == NO_DATA) {
        after = "no buffer";
    } else if (r == ERROR_SUCCESS && want_cb) {
        after = data_of(shape, cb);
    } else {
        after = buffer_after(room);
    }
    line("%s(%s)%s: ret=%ld err=%s type=%s cb=%s %s%s", fn("RegQueryValueEx"), arg(name), label, r,
         le(), want_type ? type_name(type) : "not asked", want_cb ? number(cb) : "not asked",
         room == NO_DATA ? "" : (r == ERROR_SUCCESS && want_cb ? "data=" : "buffer="), after);
}

/* RegSetValue of `s` as the default value of `sub`. */
static void set_default_line(HKEY key, const char *where, const char *sub, DWORD type,
                             const char *s, const char *label)
{
    LONG r;

    arm();
    r = set_default(key, sub, type, s);
    line("%s(%s, %s, %s, %s)%s: ret=%ld err=%s", fn("RegSetValue"), where, arg(sub),
         type_name(type), arg(s), label, r, le());
}

/* RegQueryValue of `sub`'s default value into `room` bytes of the buffer
 * (NO_DATA: none). */
static void query_default_line(HKEY key, const char *where, const char *sub, LONG room,
                               const char *label)
{
    LONG cb = room == (LONG)NO_DATA ? 0 : room;
    LONG r;

    fill();
    arm();
    r = query_default(key, sub, room != (LONG)NO_DATA, &cb);
    if (room == (LONG)NO_DATA) {
        line("%s(%s, %s)%s: ret=%ld err=%s cb=%ld no buffer", fn("RegQueryValue"), where, arg(sub),
             label, r, le(), cb);
    } else if (r == ERROR_SUCCESS) {
        line("%s(%s, %s)%s: ret=%ld err=%s cb=%ld data=%s", fn("RegQueryValue"), where, arg(sub),
             label, r, le(), cb, data_of(REG_SZ, (DWORD)cb));
    } else {
        line("%s(%s, %s)%s: ret=%ld err=%s cb=%ld buffer=%s", fn("RegQueryValue"), where, arg(sub),
             label, r, le(), cb, buffer_after((DWORD)room));
    }
}

/* RegEnumKey's entry `index` into `cch` units of the buffer. */
static LONG enum_line(HKEY key, const char *where, DWORD index, DWORD cch, const char *label)
{
    LONG r;

    fill();
    arm();
    r = enum_key(key, index, cch);
    if (r == ERROR_SUCCESS) {
        line("%s(%s, %lu, %lu units)%s: ret=%ld err=%s name=%s", fn("RegEnumKey"), where, index,
             cch, label, r, le(), wide ? ws(buf.w) : (const char *)buf.b);
    } else {
        line("%s(%s, %lu, %lu units)%s: ret=%ld err=%s buffer=%s", fn("RegEnumKey"), where, index,
             cch, label, r, le(), cch <= 16 ? text(cch) : buffer_after(cch));
    }
    return r;
}

/* Every subkey of `key`, by index, to the first failure. */
static void enum_all(HKEY key, const char *where)
{
    DWORD i;

    for (i = 0; i < 10; i++) {
        if (enum_line(key, where, i, 256, "") != ERROR_SUCCESS) {
            break;
        }
    }
}

/* --- create -------------------------------------------------------- */

static void create_body(void)
{
    HKEY k, one;

    k = create_line(HKEY_CURRENT_USER, "HKCU", TREE "\\one\\two\\three",
                    ", F2K and three levels below it missing", 1);
    shut(k);
    k = create_line(HKEY_CURRENT_USER, "HKCU", TREE "\\one\\two\\three", ", again", 1);
    shut(k);
    k = open_line(HKEY_CURRENT_USER, "HKCU", TREE "\\one\\two", KEY_READ,
                  ", a level the first call created");
    shut(k);
    one = create_line(HKEY_CURRENT_USER, "HKCU", TREE "\\one",
                      ", another level the first call created", 1);
    k = create_line(HKEY_CURRENT_USER, "HKCU", "SOFTWARE\\f2k\\ONE\\Two\\four",
                    ", the path in other case", 1);
    shut(k);
    if (one == NULL) {
        return;
    }
    k = create_line(one, "one", "", ", an empty subkey name", 1);
    line("  a new handle: %s", yesno(k != NULL && k != one));
    if (k != one) {
        shut(k);
    }
    k = create_line(one, "one", "five", ", a NULL disposition", 0);
    shut(k);
    k = create_line(one, "one", "\\six", ", a leading backslash", 1);
    shut(k);
    k = create_line(one, "one", "seven\\", ", a trailing backslash", 1);
    shut(k);
    k = create_line(BOGUS_KEY, "a bogus handle", "eight", "", 1);
    shut(k);
    line("  subkeys of one: %s", subkeys(one));
    shut(one);
    k = make("one\\two");
    if (k != NULL) {
        line("  subkeys of one\\two: %s", subkeys(k));
        shut(k);
    }
}

static void sec_create(void)
{
    passes(create_body);
}

/* --- open ---------------------------------------------------------- */

/* Whether `k`, opened from `top` by an empty or NULL name, is a new
 * handle to the same key: a value set through it read through `top`. */
static void same_key(HKEY top, HKEY k)
{
    static int probes;
    char name[16];
    WCHAR one[2];
    DWORD cb = sizeof buf.b;

    one[0] = 'x';
    one[1] = 0;
    sprintf(name, "probe%d", ++probes);
    if (k == NULL) {
        return;
    }
    RegSetValueExW(k, wide_of(name), 0, REG_SZ, (const BYTE *)one, sizeof one);
    line("  a new handle: %s, to the same key: %s", yesno(k != top),
         yesno(RegQueryValueExW(top, wide_of(name), NULL, NULL, buf.b, &cb) == ERROR_SUCCESS));
}

static void open_body(void)
{
    HKEY top, k, k2;
    LONG r;

    shut(make("Sub\\Inner"));
    top = make("");
    if (top == NULL) {
        line("setup: F2K not created");
        return;
    }
    k = open_line(HKEY_CURRENT_USER, "HKCU", TREE "\\Sub", KEY_ALL_ACCESS, "");
    shut(k);
    k = open_line(HKEY_CURRENT_USER, "HKCU", "software\\f2k\\SUB", KEY_ALL_ACCESS,
                  ", in other case");
    shut(k);
    k = open_line(top, "F2K", "Sub\\Inner", KEY_ALL_ACCESS, ", two levels down");
    shut(k);
    k = open_line(top, "F2K", "Missing", KEY_ALL_ACCESS, ", a missing key");
    shut(k);
    k = open_line(top, "F2K", "Missing\\Inner", KEY_ALL_ACCESS, ", below a missing key");
    shut(k);
    k = open_line(top, "F2K", "Sub\\Missing", KEY_ALL_ACCESS, ", missing below an existing key");
    shut(k);
    k = open_line(top, "F2K", "", KEY_ALL_ACCESS, ", an empty subkey name");
    same_key(top, k);
    if (k != top) {
        shut(k);
    }
    k = open_line(top, "F2K", NULL, KEY_ALL_ACCESS, ", a NULL subkey");
    same_key(top, k);
    if (k != top) {
        shut(k);
    }
    k = open_line(top, "F2K", "\\Sub", KEY_ALL_ACCESS, ", a leading backslash");
    shut(k);
    k = open_line(top, "F2K", "Sub\\", KEY_ALL_ACCESS, ", a trailing backslash");
    shut(k);
    k = open_line(BOGUS_KEY, "a bogus handle", "Sub", KEY_ALL_ACCESS, "");
    shut(k);
    k = open_line(NULL, "NULL", "Sub", KEY_ALL_ACCESS, "");
    shut(k);

    k = open_line(top, "F2K", "Sub", KEY_READ, ", KEY_READ");
    if (k != NULL) {
        arm();
        r = set_text(k, "v", REG_SZ, TXT("x"));
        line("  %s(\"v\") through it: ret=%ld err=%s", fn("RegSetValueEx"), r, le());
        k2 = create_line(k, "Sub (KEY_READ)", "New", ", through it", 1);
        shut(k2);
        k2 = open_line(k, "Sub (KEY_READ)", "Inner", KEY_ALL_ACCESS,
                       ", KEY_ALL_ACCESS through it");
        shut(k2);
        shut(k);
    }

    open_key_line(top, "F2K", NULL, ", a NULL subkey");
    open_key_line(top, "F2K", "", ", an empty subkey name");
    open_key_line(top, "F2K", "Sub", "");
    open_key_line(top, "F2K", "Missing", ", a missing key");
    open_key_line(HKEY_CURRENT_USER, "HKCU", NULL, ", a NULL subkey");
    shut(top);
}

static void sec_open(void)
{
    passes(open_body);
}

/* --- close --------------------------------------------------------- */

static void sec_close(void)
{
    HKEY k;
    LONG r;

    wipe();
    k = make("c");
    if (k == NULL) {
        line("setup: F2K\\c not created");
        return;
    }
    arm();
    r = RegCloseKey(k);
    line("RegCloseKey, an open key: ret=%ld err=%s", r, le());
    arm();
    r = RegCloseKey(k);
    line("RegCloseKey, the same handle again: ret=%ld err=%s", r, le());
    arm();
    r = RegCloseKey(NULL);
    line("RegCloseKey(NULL): ret=%ld err=%s", r, le());
    arm();
    r = RegCloseKey(BOGUS_KEY);
    line("RegCloseKey, a bogus handle: ret=%ld err=%s", r, le());
    arm();
    r = RegCloseKey(HKEY_CURRENT_USER);
    line("RegCloseKey(HKEY_CURRENT_USER): ret=%ld err=%s", r, le());
    for (wide = 1; wide >= 0; wide--) {
        k = open_line(HKEY_CURRENT_USER, "HKCU", TREE "\\c", KEY_READ, ", HKCU used again");
        shut(k);
    }
    line("the F2K tree deleted: %s", yesno(wipe()));
}

/* --- setvalue ------------------------------------------------------ */

static void setvalue_body(void)
{
    static const BYTE dword[4] = { 0x78, 0x56, 0x34, 0x12 };
    static const BYTE binary[5] = { 0x00, 0x01, 0xFE, 0xFF, 0x80 };
    HKEY top = make("");

    if (top == NULL) {
        line("setup: F2K not created");
        return;
    }
    set_text_line(top, "sz", REG_SZ, TXT("abc"), ", REG_SZ, its terminator counted");
    set_text_line(top, "noterm", REG_SZ, "abc", 3, ", REG_SZ, its terminator not counted");
    set_text_line(top, "expand", REG_EXPAND_SZ, TXT("%WINDIR%\\f2k"), ", REG_EXPAND_SZ");
    set_text_line(top, "multi", REG_MULTI_SZ, TXT("one\0two\0"), ", REG_MULTI_SZ");
    set_raw_line(top, "dword", REG_DWORD, dword, sizeof dword, ", REG_DWORD 0x12345678");
    set_raw_line(top, "binary", REG_BINARY, binary, sizeof binary, ", REG_BINARY");
    set_raw_line(top, "empty", REG_BINARY, binary, 0, ", REG_BINARY, 0 bytes");
    set_text_line(top, "emptysz", REG_SZ, "", 0, ", REG_SZ, 0 bytes");

    set_text_line(top, "over", REG_SZ, TXT("abc"), ", REG_SZ");
    set_raw_line(top, "over", REG_DWORD, dword, sizeof dword, ", overwritten with a REG_DWORD");
    set_text_line(top, "over", REG_SZ, TXT("longer text"), ", back to a longer REG_SZ");

    set_text_line(top, NULL, REG_SZ, TXT("dflt"), ", the default value");
    read_back(top, "");
    set_text_line(top, "", REG_SZ, TXT("other"), ", the default value");
    read_back(top, NULL);
    shut(top);
}

static void sec_setvalue(void)
{
    passes(setvalue_body);
}

/* --- queryvalue ---------------------------------------------------- */

static void queryvalue_body(void)
{
    static const WCHAR abc[] = { 'a', 'b', 'c', 0 };
    static const BYTE dword[4] = { 0x78, 0x56, 0x34, 0x12 };
    HKEY top = make("");
    DWORD size;

    if (top == NULL) {
        line("setup: F2K not created");
        return;
    }
    RegSetValueExW(top, wide_of("sz"), 0, REG_SZ, (const BYTE *)abc, sizeof abc);
    RegSetValueExW(top, wide_of("dw"), 0, REG_DWORD, dword, sizeof dword);
    /* "abc" and its terminator, in the pass's characters. */
    size = wide ? 8 : 4;
    line("value sz: REG_SZ \"abc\", its terminator counted (%lu bytes in the pass's characters)",
         size);
    query_line(top, "sz", ", NULL data: the size alone", 1, NO_DATA, 1, REG_SZ);
    query_line(top, "sz", ", NULL data and size", 1, NO_DATA, 0, REG_SZ);
    query_line(top, "sz", ", a buffer of the data's size", 1, size, 1, REG_SZ);
    query_line(top, "sz", ", one byte short", 1, size - 1, 1, REG_SZ);
    query_line(top, "sz", ", an empty buffer", 1, 0, 1, REG_SZ);
    query_line(top, "sz", ", data with a NULL size", 1, 64, 0, REG_SZ);
    query_line(top, "sz", ", a NULL type", 0, sizeof buf.b, 1, REG_SZ);
    query_line(top, "SZ", ", the name in other case", 1, sizeof buf.b, 1, REG_SZ);
    query_line(top, "missing", ", a missing value", 1, sizeof buf.b, 1, REG_SZ);
    query_line(top, "missing", ", a missing value, NULL data", 1, NO_DATA, 1, REG_SZ);
    query_line(top, "dw", ", a REG_DWORD into 4 bytes", 1, 4, 1, REG_DWORD);
    query_line(top, "dw", ", a REG_DWORD into 3 bytes", 1, 3, 1, REG_DWORD);
    shut(top);
}

static void sec_queryvalue(void)
{
    passes(queryvalue_body);
}

/* --- default ------------------------------------------------------- */

static void default_body(void)
{
    static const BYTE dword[4] = { 0x78, 0x56, 0x34, 0x12 };
    HKEY top = make(""), k;
    LONG size, unit = wide ? 2 : 1;

    if (top == NULL) {
        line("setup: F2K not created");
        return;
    }
    set_default_line(top, "F2K", "sv", REG_SZ, "hello", ", a missing subkey");
    line("  subkey sv exists: %s", yesno(exists(top, "sv")));
    query_default_line(top, "F2K", "sv", sizeof buf.b, "");
    query_default_line(top, "F2K", "sv", (LONG)NO_DATA, ", NULL data: the size alone");
    /* "hello" and its terminator, in the pass's characters. */
    size = 6 * unit;
    query_default_line(top, "F2K", "sv", size, ", a buffer of the data's size");
    query_default_line(top, "F2K", "sv", size - 1, ", one byte short");
    k = make("sv");
    if (k != NULL) {
        read_back(k, NULL);
        shut(k);
    }

    set_default_line(top, "F2K", "deep\\er\\est", REG_SZ, "deeper", ", three levels missing");
    query_default_line(top, "F2K", "deep\\er\\est", sizeof buf.b, "");

    set_default_line(top, "F2K", NULL, REG_SZ, "mine", ", a NULL subkey");
    query_default_line(top, "F2K", NULL, sizeof buf.b, ", a NULL subkey");
    query_default_line(top, "F2K", "", sizeof buf.b, ", an empty subkey name");
    read_back(top, NULL);

    set_default_line(top, "F2K", "sv", REG_DWORD, "x", ", a type other than REG_SZ");
    query_default_line(top, "F2K", "sv", sizeof buf.b, ", after");
    set_default_line(top, "F2K", "sv", REG_EXPAND_SZ, "y", ", a type other than REG_SZ");
    query_default_line(top, "F2K", "sv", sizeof buf.b, ", after");

    shut(make("nodef"));
    query_default_line(top, "F2K", "nodef", (LONG)NO_DATA,
                       ", a subkey with no default value, NULL data");
    query_default_line(top, "F2K", "nodef", sizeof buf.b, ", a subkey with no default value");
    query_default_line(top, "F2K", "missing", sizeof buf.b, ", a missing subkey");

    k = make("dw");
    if (k != NULL) {
        RegSetValueExW(k, NULL, 0, REG_DWORD, dword, sizeof dword);
        shut(k);
    }
    query_default_line(top, "F2K", "dw", sizeof buf.b, ", a default value of REG_DWORD");
    shut(top);
}

static void sec_default(void)
{
    passes(default_body);
}

/* --- enum ---------------------------------------------------------- */

static void enum_body(void)
{
    static const char *const order[] = { "delta", "Alpha", "charlie", "bravo", "Echo",
                                         "Alpha\\child" };
    HKEY top = make(""), k;
    int i;

    if (top == NULL) {
        line("setup: F2K not created");
        return;
    }
    for (i = 0; i < (int)(sizeof order / sizeof order[0]); i++) {
        shut(make(order[i]));
    }
    line("subkeys created in the order delta, Alpha, charlie, bravo, Echo; Alpha\\child below "
         "Alpha");
    enum_all(top, "F2K");
    enum_line(top, "F2K", 50, 256, ", far past the end");
    enum_line(top, "F2K", 0, 0, ", a 0-unit buffer");
    enum_line(top, "F2K", 0, 3, ", 3 units");
    enum_line(top, "F2K", 0, 5, ", room for the name, not its terminator");
    enum_line(top, "F2K", 0, 6, ", room for the name and its terminator");
    k = make("Alpha\\child");
    if (k != NULL) {
        enum_line(k, "child", 0, 256, ", a key with no subkeys");
        shut(k);
    }
    delete_tree(top, wide_of("charlie"));
    line("charlie deleted");
    enum_all(top, "F2K");
    shut(top);
}

static void sec_enum(void)
{
    passes(enum_body);
}

/* --- delete -------------------------------------------------------- */

static void delete_body(void)
{
    HKEY top = make(""), h, k;
    LONG r;

    if (top == NULL) {
        line("setup: F2K not created");
        return;
    }
    shut(make("a\\b\\c"));
    shut(make("Leaf"));
    shut(make("gone"));

    delete_line(top, "F2K", "a", ", a key with a subkey");
    line("  a exists: %s", yesno(exists(top, "a")));
    delete_line(top, "F2K", "a\\b\\c", ", a leaf two levels down");
    line("  a\\b exists: %s, a\\b\\c exists: %s", yesno(exists(top, "a\\b")),
         yesno(exists(top, "a\\b\\c")));
    delete_line(top, "F2K", "a\\b", ", the level emptied above it");
    delete_line(top, "F2K", "a", ", the next level up");
    line("  a exists: %s", yesno(exists(top, "a")));
    delete_line(top, "F2K", "LEAF", ", a leaf, named in other case");
    delete_line(top, "F2K", "Leaf", ", again");
    delete_line(top, "F2K", "missing\\x", ", below a missing key");
    delete_line(BOGUS_KEY, "a bogus handle", "gone", "");

    if (RegOpenKeyExW(top, wide_of("gone"), 0, KEY_ALL_ACCESS, &h) != ERROR_SUCCESS) {
        line("setup: F2K\\gone not opened");
        shut(top);
        return;
    }
    line("gone: a handle to it open");
    delete_line(top, "F2K", "gone", ", a key open through another handle");
    query_line(h, "x", ", through the deleted key's handle", 1, sizeof buf.b, 1, REG_SZ);
    arm();
    r = set_text(h, "x", REG_SZ, TXT("x"));
    line("%s(\"x\"), through the deleted key's handle: ret=%ld err=%s", fn("RegSetValueEx"), r,
         le());
    k = create_line(h, "gone (deleted)", "child", ", through the deleted key's handle", 1);
    shut(k);
    enum_line(h, "gone (deleted)", 0, 256, ", through the deleted key's handle");
    k = open_line(top, "F2K", "gone", KEY_ALL_ACCESS, ", after its delete");
    shut(k);
    k = create_line(top, "F2K", "gone", ", the name created anew", 1);
    if (k != NULL) {
        RegSetValueExW(k, wide_of("x"), 0, REG_BINARY, (const BYTE *)"x", 1);
        shut(k);
    }
    query_line(h, "x", ", the old handle, the name created anew with a value x", 1,
               sizeof buf.b, 1, REG_BINARY);
    arm();
    r = RegCloseKey(h);
    line("RegCloseKey, the deleted key's handle: ret=%ld err=%s", r, le());
    shut(top);
}

static void sec_delete(void)
{
    passes(delete_body);
}

static const section_t sections[] = {
    { "create", sec_create, 0 },
    { "open", sec_open, 0 },
    { "close", sec_close, 0 },
    { "setvalue", sec_setvalue, 0 },
    { "queryvalue", sec_queryvalue, 0 },
    { "default", sec_default, 0 },
    { "enum", sec_enum, 0 },
    { "delete", sec_delete, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* Bogus handles and arguments go to the calls: should one fault, no
     * dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("registry", sections, argc, argv);
}
