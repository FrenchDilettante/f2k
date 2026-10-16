/*
 * files - the read side of the file API over a known data tree.
 *
 * Reads tests/files/DATA (scripts/gen-files-data.py writes it; every
 * byte is defined by a formula, so the fixture verifies what it reads).
 * Paths are built from the directory of the program's own image, so the
 * same binary finds the tree wherever it runs; nothing machine-specific
 * is printed (no absolute paths, no timestamps, no free space).
 *
 * Capture on a FAT32 volume where possible: F2K's boot volume is FAT32,
 * and the file system name, attribute and timestamp details differ on
 * NTFS. Run setup.bat once first: it sets RDONLY.TXT read-only and
 * HIDDEN.TXT hidden (git cannot carry those attributes).
 *
 * Sections (run all with no argument, or one by name):
 *
 *   open        CreateFileA over path forms (case, forward slashes, . and
 *               .., long and short names, subdirectories, relative to a
 *               SetCurrentDirectoryA directory) and its failures (missing
 *               file or directory, a directory, wildcards, a trailing
 *               backslash, an overlong path, CREATE_NEW on an existing
 *               file, write access to a read-only file);
 *               GetCurrentDirectoryA, GetFullPathNameA, GetShortPathNameA
 *   read        ReadFile in chunks of 1, 7, 511, 512, 513, 4096, 65536
 *               and 200000 bytes; at, across and past end of file; empty
 *               and exactly sector- and page-sized files; a buffer the
 *               process cannot write
 *   seek        SetFilePointer from the start, the current position and
 *               the end; past the end; negative results; the high dword;
 *               bad move methods and handles
 *   meta        GetFileSize, GetFileType, GetFileAttributesA/ExA,
 *               GetFileInformationByHandle, GetFileTime, GetDriveTypeA,
 *               GetDiskFreeSpaceA, GetVolumeInformationA
 *   find        FindFirstFileA/FindNextFileA/FindClose over patterns
 *               (listings are sorted before printing)
 *   handles     64 handles to one file, independent positions, a
 *               duplicated handle sharing its position, share modes,
 *               closed handles
 *   crt         fopen/fread/fseek/ftell/fgets in binary and text modes,
 *               _open/_read/_lseek, _stat, _findfirst, _access, _fullpath
 *   mapping     a read-only file mapping: whole-file and offset views,
 *               view granularity, mapping past the end, an empty file,
 *               a write through a read-only view
 *   concurrent  three threads reading the tree at once
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo files.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BIG_SIZE 150000

static char base[MAX_PATH];         /* the image's directory, with its trailing backslash */

static void init_base(void)
{
    char *p;

    GetModuleFileNameA(NULL, base, sizeof base);
    p = strrchr(base, '\\');
    if (p != NULL) {
        p[1] = 0;
    } else {
        base[0] = 0;
    }
}

/* `rel` under the image's directory; rotating buffers. */
static const char *at(const char *rel)
{
    static char bufs[4][2 * MAX_PATH];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s%s", base, rel);
    return b;
}

static BYTE big_byte(DWORD i)
{
    return (BYTE)(i % 251);
}

static int big_ok(const BYTE *p, DWORD offset, DWORD n)
{
    DWORD i;

    for (i = 0; i < n; i++) {
        if (p[i] != big_byte(offset + i)) {
            return 0;
        }
    }
    return 1;
}

static HANDLE open_read(const char *rel)
{
    return CreateFileA(at(rel), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
}

static DWORD position(HANDLE h)
{
    return SetFilePointer(h, 0, NULL, FILE_CURRENT);
}

/* --- open ---------------------------------------------------------- */

static void try_open(const char *label, const char *path, DWORD access, DWORD disposition, DWORD flags)
{
    HANDLE h;
    char first = 0;
    DWORD got = 0;

    arm();
    h = CreateFileA(path, access, FILE_SHARE_READ, NULL, disposition, flags, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        line("%s: INVALID_HANDLE_VALUE err=%s", label, le());
        return;
    }
    line("%s: opened err=%s", label, le());
    if (!(flags & FILE_FLAG_BACKUP_SEMANTICS)) {
        ReadFile(h, &first, 1, &got, NULL);
        line("%s: first byte %02X (%lu read)", label, (unsigned)(BYTE)first, got);
    }
    CloseHandle(h);
}

static void sec_open(void)
{
    char longpath[400];
    char buf[MAX_PATH];
    char *file_part;
    DWORD n;
    BOOL r;
    int i;

    try_open("DATA\\SMALL.TXT", at("DATA\\SMALL.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("lower case", at("data\\small.txt"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("forward slash", at("DATA/SMALL.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("dot components", at("DATA\\.\\SUB\\..\\SMALL.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("long name", at("DATA\\Long File Name.txt"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("long name, other case", at("DATA\\LONG FILE NAME.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("short name", at("DATA\\LONGFI~1.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("subdirectories", at("DATA\\SUB\\DEEP\\LEAF.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("OPEN_ALWAYS on an existing file", at("DATA\\SMALL.TXT"), GENERIC_READ, OPEN_ALWAYS, 0);
    try_open("missing file", at("DATA\\NOSUCH.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("missing directory", at("NODIR\\SMALL.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("a directory", at("DATA\\SUB"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("a directory, backup semantics", at("DATA\\SUB"), GENERIC_READ, OPEN_EXISTING,
             FILE_FLAG_BACKUP_SEMANTICS);
    try_open("a wildcard", at("DATA\\SMA*.TXT"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("a trailing backslash", at("DATA\\SMALL.TXT\\"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("a file used as a directory", at("DATA\\SMALL.TXT\\X"), GENERIC_READ, OPEN_EXISTING, 0);
    try_open("an empty path", "", GENERIC_READ, OPEN_EXISTING, 0);
    strcpy(longpath, base);
    for (i = strlen(longpath); i < 300; i++) {
        longpath[i] = 'A';
    }
    longpath[300] = 0;
    try_open("a 300-character path", longpath, GENERIC_READ, OPEN_EXISTING, 0);
    try_open("CREATE_NEW on an existing file", at("DATA\\SMALL.TXT"), GENERIC_READ | GENERIC_WRITE, CREATE_NEW, 0);
    try_open("write access to a read-only file", at("DATA\\RDONLY.TXT"), GENERIC_WRITE, OPEN_EXISTING, 0);

    arm();
    r = SetCurrentDirectoryA(base);
    line("SetCurrentDirectoryA(image directory): ret=%d err=%s", r, le());
    n = GetCurrentDirectoryA(sizeof buf, buf);
    strcat(buf, n > 0 && buf[n - 1] == '\\' ? "" : "\\");
    line("GetCurrentDirectoryA matches: %s", yesno(n > 0 && _stricmp(buf, base) == 0));
    arm();
    n = GetCurrentDirectoryA(2, buf);
    line("GetCurrentDirectoryA into 2 bytes: returns the size needed %s err=%s", yesno(n > 2), le());
    try_open("relative to the current directory", "DATA\\SMALL.TXT", GENERIC_READ, OPEN_EXISTING, 0);
    try_open("relative with a leading .\\", ".\\DATA\\SUB\\DEEP\\LEAF.TXT", GENERIC_READ, OPEN_EXISTING, 0);
    arm();
    r = SetCurrentDirectoryA(at("DATA\\SUB"));
    line("SetCurrentDirectoryA(DATA\\SUB): ret=%d err=%s", r, le());
    try_open("..\\SMALL.TXT from DATA\\SUB", "..\\SMALL.TXT", GENERIC_READ, OPEN_EXISTING, 0);
    arm();
    r = SetCurrentDirectoryA(at("NODIR"));
    line("SetCurrentDirectoryA(missing): ret=%d err=%s", r, le());
    SetCurrentDirectoryA(base);

    arm();
    n = GetFullPathNameA("DATA\\SUB\\..\\SMALL.TXT", sizeof buf, buf, &file_part);
    line("GetFullPathNameA: length matches %s, under the image directory %s, file part [%s] err=%s",
         yesno(n == strlen(buf)), yesno(_stricmp(buf, at("DATA\\SMALL.TXT")) == 0),
         n != 0 ? file_part : "", le());
    arm();
    n = GetShortPathNameA(at("DATA\\Long File Name.txt"), buf, sizeof buf);
    file_part = strrchr(buf, '\\');
    line("GetShortPathNameA(long name): final component [%s] err=%s",
         n != 0 ? (file_part != NULL ? file_part + 1 : buf) : "", le());
}

/* --- read ---------------------------------------------------------- */

static BYTE chunk_buf[200000];

/* Read BIG.BIN from the start in `chunk`-byte reads up to `limit` bytes. */
static void read_in_chunks(DWORD chunk, DWORD limit)
{
    HANDLE h = open_read("DATA\\BIG.BIN");
    DWORD total = 0;
    DWORD calls = 0;
    DWORD got;
    int ok = h != INVALID_HANDLE_VALUE;

    while (ok && total < limit) {
        DWORD want = chunk < limit - total ? chunk : limit - total;

        if (!ReadFile(h, chunk_buf, want, &got, NULL)) {
            ok = 0;
            break;
        }
        calls++;
        if (got == 0) {
            break;
        }
        ok = big_ok(chunk_buf, total, got);
        total += got;
    }
    line("chunks of %lu up to %lu: %s, %lu bytes in %lu reads", chunk, limit, ok ? "ok" : "failed", total, calls);
    CloseHandle(h);
}

static void sec_read(void)
{
    HANDLE h;
    BYTE buf[1024];
    BYTE *guarded;
    const char *e;
    DWORD got;
    BOOL r;
    int i, ok;

    read_in_chunks(1, 2048);
    read_in_chunks(7, 16384);
    read_in_chunks(511, BIG_SIZE);
    read_in_chunks(512, BIG_SIZE);
    read_in_chunks(513, BIG_SIZE);
    read_in_chunks(4096, BIG_SIZE);
    read_in_chunks(65536, BIG_SIZE);
    read_in_chunks(200000, 200000);

    h = open_read("DATA\\BIG.BIN");
    SetFilePointer(h, BIG_SIZE - 10, NULL, FILE_BEGIN);
    r = ReadFile(h, buf, 100, &got, NULL);
    line("read across the end: ret=%d got %lu, bytes %s", r, got, yesno(big_ok(buf, BIG_SIZE - 10, got)));
    got = 7;
    arm();
    r = ReadFile(h, buf, 100, &got, NULL);
    line("read at the end: ret=%d got %lu err=%s", r, got, le());
    got = 7;
    r = ReadFile(h, buf, 0, &got, NULL);
    line("zero-byte read: ret=%d got %lu", r, got);
    SetFilePointer(h, BIG_SIZE + 5000, NULL, FILE_BEGIN);
    got = 7;
    r = ReadFile(h, buf, 100, &got, NULL);
    line("read past the end: ret=%d got %lu", r, got);

    guarded = (BYTE *)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY);
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    got = 7;
    arm();
    r = ReadFile(h, guarded, 100, &got, NULL);
    e = le();
    line("read into a read-only buffer: ret=%d got %lu err=%s, position after %lu", r, got, e, position(h));
    VirtualFree(guarded, 0, MEM_RELEASE);
    CloseHandle(h);

    h = open_read("DATA\\EMPTY.DAT");
    got = 7;
    r = ReadFile(h, buf, 100, &got, NULL);
    line("empty file: ret=%d got %lu", r, got);
    CloseHandle(h);

    h = open_read("DATA\\EXACT512.BIN");
    r = ReadFile(h, buf, 1024, &got, NULL);
    ok = got == 512;
    for (i = 0; ok && i < 512; i++) {
        ok = buf[i] == (BYTE)(i * 7);
    }
    line("512-byte file read with 1024: got %lu, bytes %s", got, yesno(ok));
    r = ReadFile(h, buf, 1024, &got, NULL);
    line("then: ret=%d got %lu", r, got);
    CloseHandle(h);

    h = open_read("DATA\\EXACT4K.BIN");
    ok = 1;
    for (i = 0; i < 4; i++) {
        r = ReadFile(h, buf, 1024, &got, NULL);
        ok &= r && got == 1024;
        for (got = 0; ok && got < 1024; got++) {
            ok = buf[got] == (BYTE)((i * 1024 + got) * 13);
        }
    }
    r = ReadFile(h, buf, 1024, &got, NULL);
    line("4096-byte file in four 1024-byte reads: %s, then got %lu", ok ? "ok" : "failed", got);
    CloseHandle(h);

    h = open_read("DATA\\SMALL.TXT");
    r = ReadFile(h, buf, sizeof buf, &got, NULL);
    buf[got < sizeof buf ? got : sizeof buf - 1] = 0;
    line("SMALL.TXT: got %lu, text matches %s", got, yesno(strcmp((char *)buf, "F2K files fixture: small text\r\n") == 0));
    CloseHandle(h);
}

/* --- seek ---------------------------------------------------------- */

static void sec_seek(void)
{
    HANDLE h = open_read("DATA\\BIG.BIN");
    BYTE buf[16];
    const char *e;
    DWORD r, got;
    LONG hi;

    r = SetFilePointer(h, 100, NULL, FILE_BEGIN);
    line("FILE_BEGIN 100: %lu", r);
    r = SetFilePointer(h, 50, NULL, FILE_CURRENT);
    ReadFile(h, buf, 4, &got, NULL);
    line("FILE_CURRENT +50: %lu, bytes there %s", r, yesno(got == 4 && big_ok(buf, 150, 4)));
    r = SetFilePointer(h, -20, NULL, FILE_CURRENT);
    line("FILE_CURRENT -20: %lu", r);
    r = SetFilePointer(h, -10, NULL, FILE_END);
    ReadFile(h, buf, 16, &got, NULL);
    line("FILE_END -10: %lu, read %lu bytes %s", r, got, yesno(big_ok(buf, BIG_SIZE - 10, got)));
    r = SetFilePointer(h, 0, NULL, FILE_END);
    line("FILE_END 0: %lu", r);
    r = SetFilePointer(h, 1000, NULL, FILE_END);
    got = 7;
    ReadFile(h, buf, 16, &got, NULL);
    line("FILE_END +1000: %lu, read there got %lu", r, got);

    arm();
    r = SetFilePointer(h, -1, NULL, FILE_BEGIN);
    e = le();
    line("FILE_BEGIN -1: 0x%08lX err=%s, position kept %lu", r, e, position(h));
    arm();
    r = SetFilePointer(h, -200000, NULL, FILE_CURRENT);
    e = le();
    line("FILE_CURRENT -200000: 0x%08lX err=%s, position kept %lu", r, e, position(h));

    hi = 0;
    arm();
    r = SetFilePointer(h, 5, &hi, FILE_BEGIN);
    line("with a high dword of 0: %lu high %ld err=%s", r, hi, le());
    hi = 1;
    arm();
    r = SetFilePointer(h, 0, &hi, FILE_BEGIN);
    line("to 4 GiB (high dword 1): 0x%08lX high %ld err=%s", r, hi, le());
    hi = 0;
    r = SetFilePointer(h, 0, &hi, FILE_CURRENT);
    line("read back: 0x%08lX high %ld", r, hi);
    hi = -1;
    r = SetFilePointer(h, -5, &hi, FILE_END);
    line("FILE_END -5 as a 64-bit distance: %lu high %ld", r, hi);

    arm();
    r = SetFilePointer(h, 0, NULL, 5);
    line("bad move method: 0x%08lX err=%s", r, le());
    CloseHandle(h);
    arm();
    r = SetFilePointer(h, 0, NULL, FILE_BEGIN);
    line("closed handle: 0x%08lX err=%s", r, le());
}

/* --- meta ---------------------------------------------------------- */

static void attrs(const char *rel)
{
    DWORD a;

    arm();
    a = GetFileAttributesA(at(rel));
    line("GetFileAttributesA(%s): 0x%08lX err=%s", rel, a, le());
}

static void sec_meta(void)
{
    HANDLE h;
    DWORD lo, hi, spc, bps, freec, totalc, serial, maxlen, fsflags;
    BY_HANDLE_FILE_INFORMATION info;
    WIN32_FILE_ATTRIBUTE_DATA ad;
    FILETIME ct, at_, wt;
    char root[4];
    char fsname[32];
    const char *rootp;
    BOOL r;

    h = open_read("DATA\\BIG.BIN");
    hi = 7;
    lo = GetFileSize(h, &hi);
    line("GetFileSize(BIG.BIN): %lu high %lu", lo, hi);
    line("GetFileType(file): %lu", GetFileType(h));
    arm();
    r = GetFileInformationByHandle(h, &info);
    line("GetFileInformationByHandle: ret=%d attributes 0x%lX size %lu high %lu links %lu err=%s", r,
         info.dwFileAttributes, info.nFileSizeLow, info.nFileSizeHigh, info.nNumberOfLinks, le());
    r = GetFileTime(h, &ct, &at_, &wt);
    line("GetFileTime: ret=%d write time set %s", r, yesno(wt.dwLowDateTime != 0 || wt.dwHighDateTime != 0));
    CloseHandle(h);
    h = open_read("DATA\\EMPTY.DAT");
    line("GetFileSize(EMPTY.DAT): %lu", GetFileSize(h, NULL));
    CloseHandle(h);
    arm();
    lo = GetFileSize((HANDLE)0x1234, NULL);
    line("GetFileSize(bogus): 0x%08lX err=%s", lo, le());

    attrs("DATA\\SMALL.TXT");
    attrs("DATA\\RDONLY.TXT");
    attrs("DATA\\HIDDEN.TXT");
    attrs("DATA");
    attrs("DATA\\SUB\\DEEP");
    attrs("DATA\\Long File Name.txt");
    attrs("DATA\\NOSUCH.TXT");
    attrs("NODIR\\NOSUCH.TXT");

    arm();
    r = GetFileAttributesExA(at("DATA\\SMALL.TXT"), GetFileExInfoStandard, &ad);
    line("GetFileAttributesExA(SMALL.TXT): ret=%d attributes 0x%lX size %lu err=%s", r,
         ad.dwFileAttributes, ad.nFileSizeLow, le());

    rootp = NULL;
    if (base[0] != 0 && base[1] == ':') {
        root[0] = base[0];
        root[1] = ':';
        root[2] = '\\';
        root[3] = 0;
        rootp = root;
    }
    line("image directory has a drive letter: %s", yesno(rootp != NULL));
    line("GetDriveTypeA(its root): %u", GetDriveTypeA(rootp));
    arm();
    r = GetDiskFreeSpaceA(rootp, &spc, &bps, &freec, &totalc);
    line("GetDiskFreeSpaceA: ret=%d bytes per sector %lu err=%s", r, bps, le());
    arm();
    r = GetVolumeInformationA(rootp, NULL, 0, &serial, &maxlen, &fsflags, fsname, sizeof fsname);
    line("GetVolumeInformationA: ret=%d max component %lu file system [%s] err=%s", r, maxlen, r ? fsname : "", le());
}

/* --- find ---------------------------------------------------------- */

typedef struct {
    char name[MAX_PATH];
    char alt[14];
    DWORD attrs;
    DWORD size;
} entry_t;

static entry_t entries[64];

static int cmp_entry(const void *a, const void *b)
{
    return _stricmp(((const entry_t *)a)->name, ((const entry_t *)b)->name);
}

static void listing(const char *pattern)
{
    WIN32_FIND_DATAA fd;
    HANDLE f;
    int n = 0;
    int i;
    BOOL r;

    arm();
    f = FindFirstFileA(at(pattern), &fd);
    if (f == INVALID_HANDLE_VALUE) {
        line("find %s: INVALID_HANDLE_VALUE err=%s", pattern, le());
        return;
    }
    do {
        if (n < 64) {
            strcpy(entries[n].name, fd.cFileName);
            strcpy(entries[n].alt, fd.cAlternateFileName);
            entries[n].attrs = fd.dwFileAttributes;
            entries[n].size = fd.nFileSizeLow;
            n++;
        }
        arm();
    } while (FindNextFileA(f, &fd));
    line("find %s: %d entries, ended with err=%s", pattern, n, le());
    qsort(entries, n, sizeof entries[0], cmp_entry);
    for (i = 0; i < n; i++) {
        line("  [%s] short [%s] attributes 0x%lX size %lu", entries[i].name, entries[i].alt, entries[i].attrs,
             (entries[i].attrs & FILE_ATTRIBUTE_DIRECTORY) ? 0 : entries[i].size);
    }
    arm();
    r = FindClose(f);
    line("  FindClose: ret=%d err=%s", r, le());
}

static void sec_find(void)
{
    listing("DATA\\*");
    listing("DATA\\*.*");
    listing("DATA\\*.TXT");
    listing("DATA\\S*");
    listing("DATA\\?????.TXT");
    listing("DATA\\Long*");
    listing("DATA\\SUB\\*");
    listing("DATA");
    listing("DATA\\*.XYZ");
    listing("NODIR\\*");
}

/* --- handles ------------------------------------------------------- */

static void sec_handles(void)
{
    HANDLE hs[64];
    HANDLE a, b, d;
    BYTE c;
    DWORD got;
    BOOL r;
    int i, opened;

    opened = 0;
    for (i = 0; i < 64; i++) {
        hs[i] = open_read("DATA\\SMALL.TXT");
        opened += hs[i] != INVALID_HANDLE_VALUE;
    }
    line("64 handles to one file: opened %d", opened);
    for (i = 0; i < 64; i++) {
        if (hs[i] != INVALID_HANDLE_VALUE) {
            CloseHandle(hs[i]);
        }
    }

    a = open_read("DATA\\BIG.BIN");
    b = open_read("DATA\\BIG.BIN");
    ReadFile(a, &c, 1, &got, NULL);
    ReadFile(a, &c, 1, &got, NULL);
    ReadFile(b, &c, 1, &got, NULL);
    line("two opens keep independent positions: %lu and %lu", position(a), position(b));
    DuplicateHandle(GetCurrentProcess(), a, GetCurrentProcess(), &d, 0, FALSE, DUPLICATE_SAME_ACCESS);
    ReadFile(d, &c, 1, &got, NULL);
    line("a duplicated handle shares its position: original now at %lu, byte %s", position(a),
         yesno(c == big_byte(2)));
    CloseHandle(d);
    CloseHandle(b);
    CloseHandle(a);

    a = CreateFileA(at("DATA\\SMALL.TXT"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    arm();
    b = CreateFileA(at("DATA\\SMALL.TXT"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    line("second open of a file opened without sharing: %s err=%s",
         b == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", le());
    if (b != INVALID_HANDLE_VALUE) {
        CloseHandle(b);
    }
    CloseHandle(a);
    a = open_read("DATA\\SMALL.TXT");
    arm();
    b = CreateFileA(at("DATA\\SMALL.TXT"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    line("exclusive open of a file already open: %s err=%s",
         b == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", le());
    if (b != INVALID_HANDLE_VALUE) {
        CloseHandle(b);
    }
    arm();
    r = CloseHandle(a);
    line("close: ret=%d err=%s", r, le());
    arm();
    r = CloseHandle(a);
    line("close again: ret=%d err=%s", r, le());
    arm();
    r = ReadFile(a, &c, 1, &got, NULL);
    line("read from the closed handle: ret=%d err=%s", r, le());
}

/* --- crt ----------------------------------------------------------- */

static void sec_crt(void)
{
    FILE *f;
    BYTE buf[1000];
    char text[64];
    char full[MAX_PATH];
    struct _stat st;
    struct _finddata_t fd;
    long fh;
    int fdn, count, r;
    size_t n;
    long pos;

    f = fopen(at("DATA\\BIG.BIN"), "rb");
    n = f != NULL ? fread(buf, 1, sizeof buf, f) : 0;
    line("fopen rb + fread: %u bytes %s", n, yesno(big_ok(buf, 0, n)));
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        pos = ftell(f);
        fseek(f, -1, SEEK_END);
        r = fgetc(f);
        line("fseek/ftell: size %ld, last byte %s, then EOF %s", pos, yesno(r == big_byte(BIG_SIZE - 1)),
             yesno(fgetc(f) == EOF && feof(f)));
        line("fclose: %d", fclose(f));
    }

    f = fopen(at("DATA\\SMALL.TXT"), "r");
    text[0] = 0;
    if (f != NULL) {
        fgets(text, sizeof text, f);
        fclose(f);
    }
    line("text mode fgets: length %u, ends with a bare newline %s", strlen(text),
         yesno(strlen(text) > 0 && text[strlen(text) - 1] == '\n' && (strlen(text) < 2 || text[strlen(text) - 2] != '\r')));
    f = fopen(at("DATA\\SMALL.TXT"), "rb");
    text[0] = 0;
    if (f != NULL) {
        fgets(text, sizeof text, f);
        fclose(f);
    }
    line("binary mode fgets: length %u", strlen(text));
    errno = 0;
    f = fopen(at("DATA\\NOSUCH.TXT"), "rb");
    line("fopen(missing): null %s errno %d", yesno(f == NULL), errno);

    fdn = _open(at("DATA\\BIG.BIN"), _O_RDONLY | _O_BINARY);
    line("_open: a descriptor above the standard three %s", yesno(fdn > 2));
    if (fdn >= 0) {
        r = _read(fdn, buf, 1000);
        pos = _lseek(fdn, 0, SEEK_END);
        line("_read 1000: %d, _lseek to the end: %ld, _eof %d", r, pos, _eof(fdn));
        line("_close: %d", _close(fdn));
    }

    r = _stat(at("DATA\\SMALL.TXT"), &st);
    line("_stat(SMALL.TXT): %d size %ld regular %s", r, st.st_size, yesno((st.st_mode & _S_IFREG) != 0));
    r = _stat(at("DATA\\SUB"), &st);
    line("_stat(DATA\\SUB): %d directory %s", r, yesno((st.st_mode & _S_IFDIR) != 0));
    errno = 0;
    r = _stat(at("DATA\\NOSUCH.TXT"), &st);
    line("_stat(missing): %d errno %d", r, errno);

    count = 0;
    fh = _findfirst(at("DATA\\*.TXT"), &fd);
    if (fh != -1) {
        do {
            count++;
        } while (_findnext(fh, &fd) == 0);
        _findclose(fh);
    }
    line("_findfirst/_findnext DATA\\*.TXT: %d", count);

    line("_access(SMALL.TXT, 0): %d", _access(at("DATA\\SMALL.TXT"), 0));
    errno = 0;
    r = _access(at("DATA\\RDONLY.TXT"), 2);
    line("_access(RDONLY.TXT, write): %d errno %d", r, errno);
    line("_fullpath folds .. like GetFullPathNameA: %s",
         yesno(_fullpath(full, at("DATA\\SUB\\..\\SMALL.TXT"), sizeof full) != NULL &&
               _stricmp(full, at("DATA\\SMALL.TXT")) == 0));
}

/* --- mapping ------------------------------------------------------- */

static void sec_mapping(void)
{
    HANDLE f, m, e;
    BYTE *v, *v2;
    int faulted;

    f = open_read("DATA\\BIG.BIN");
    arm();
    m = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
    line("CreateFileMappingA(BIG.BIN, read-only, whole file): created %s err=%s", yesno(m != NULL), le());
    if (m == NULL) {
        CloseHandle(f);
        return;
    }
    v = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    line("whole-file view: mapped %s, contents %s", yesno(v != NULL), yesno(v != NULL && big_ok(v, 0, BIG_SIZE)));
    v2 = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0x10000, 1000);
    line("view at offset 64 KiB: contents %s", yesno(v2 != NULL && big_ok(v2, 0x10000, 1000)));
    if (v2 != NULL) {
        UnmapViewOfFile(v2);
    }
    arm();
    v2 = (BYTE *)MapViewOfFile(m, FILE_MAP_READ, 0, 0x1000, 1000);
    line("view at offset 4 KiB: null %s err=%s", yesno(v2 == NULL), le());
    arm();
    v2 = (BYTE *)MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0);
    line("a writable view of a read-only mapping: null %s err=%s", yesno(v2 == NULL), le());

    faulted = 0;
    if (v != NULL) {
        __try {
            v[0] = 1;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            faulted = (int)GetExceptionCode();
        }
    }
    line("a write through the read-only view: faulted with 0x%08X", faulted);
    if (v != NULL) {
        UnmapViewOfFile(v);
    }
    CloseHandle(m);

    arm();
    m = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, BIG_SIZE + 100000, NULL);
    line("read-only mapping larger than the file: created %s err=%s", yesno(m != NULL), le());
    if (m != NULL) {
        CloseHandle(m);
    }
    CloseHandle(f);

    e = open_read("DATA\\EMPTY.DAT");
    arm();
    m = CreateFileMappingA(e, NULL, PAGE_READONLY, 0, 0, NULL);
    line("mapping an empty file: created %s err=%s", yesno(m != NULL), le());
    if (m != NULL) {
        CloseHandle(m);
    }
    CloseHandle(e);
}

/* --- concurrent ---------------------------------------------------- */

typedef struct {
    DWORD chunk;
    DWORD rounds;
    int slot;
    int ok;
} reader_t;

static DWORD WINAPI reader(LPVOID param)
{
    reader_t *r = (reader_t *)param;
    static BYTE bufs[3][8192];
    BYTE *buf = bufs[r->slot];
    DWORD round, total, got;
    HANDLE h;

    r->ok = 1;
    for (round = 0; round < r->rounds; round++) {
        h = open_read("DATA\\BIG.BIN");
        if (h == INVALID_HANDLE_VALUE) {
            r->ok = 0;
            return 0;
        }
        total = 0;
        while (ReadFile(h, buf, r->chunk, &got, NULL) && got != 0) {
            r->ok &= big_ok(buf, total, got);
            total += got;
        }
        r->ok &= total == BIG_SIZE;
        CloseHandle(h);
    }
    return 0;
}

static void sec_concurrent(void)
{
    reader_t rs[3];
    HANDLE hs[3];
    int i;

    rs[0].chunk = 512;
    rs[0].rounds = 1;
    rs[1].chunk = 4093;
    rs[1].rounds = 2;
    rs[2].chunk = 8192;
    rs[2].rounds = 3;
    for (i = 0; i < 3; i++) {
        rs[i].slot = i;
        hs[i] = CreateThread(NULL, 0, reader, &rs[i], 0, NULL);
    }
    for (i = 0; i < 3; i++) {
        if (hs[i] != NULL) {
            WaitForSingleObject(hs[i], 60000);
            CloseHandle(hs[i]);
        }
    }
    line("three threads reading BIG.BIN at once (512 x1, 4093 x2, 8192 x3): %s %s %s",
         rs[0].ok ? "ok" : "failed", rs[1].ok ? "ok" : "failed", rs[2].ok ? "ok" : "failed");
}

static const section_t sections[] = {
    { "open", sec_open, 0 },
    { "read", sec_read, 0 },
    { "seek", sec_seek, 0 },
    { "meta", sec_meta, 0 },
    { "find", sec_find, 0 },
    { "handles", sec_handles, 0 },
    { "crt", sec_crt, 0 },
    { "mapping", sec_mapping, 0 },
    { "concurrent", sec_concurrent, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    init_base();
    return run_sections("files", sections, argc, argv);
}
