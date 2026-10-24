/*
 * fswrite - the write side of the file API (parked until F2K writes).
 *
 * Works inside SCRATCH, a directory next to the program's image, which
 * it empties silently first so every run starts from the same state.
 * Like files, capture it on a FAT32 volume where possible.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   CreateFileA dispositions on new and existing files and
 *            their errors (CREATE_NEW, CREATE_ALWAYS, OPEN_ALWAYS,
 *            TRUNCATE_EXISTING, OPEN_EXISTING)
 *   write    WriteFile in chunks with a read-back, appending, a write
 *            past the end (the gap reads as zeros), SetEndOfFile
 *            shrinking and growing, FlushFileBuffers, writes through a
 *            read-only handle, zero-byte writes
 *   share    share modes between writers and readers, deleting an open
 *            file, FILE_FLAG_DELETE_ON_CLOSE
 *   names    MoveFileA, CopyFileA, DeleteFileA and their errors,
 *            read-only files, a created long file name and its short name,
 *            the short names of valid 8.3 names in mixed case (FS-8) and
 *            of names outside ASCII (FS-16)
 *   dirs     CreateDirectoryA/RemoveDirectoryA and their errors, a
 *            directory grown to 100 entries (spanning clusters)
 *   times    SetFileTime/GetFileTime round trip at a two-second boundary
 *   crt      fopen "w"/"a"/"r+" with text-mode translation, fwrite,
 *            remove, rename
 *
 * The create, share, names and dirs observations run twice: through the
 * A calls, then through their W twins on the same names (the W lines
 * carry the W names, or "(W)"); create and names empty SCRATCH between
 * the two runs, so both start from the same state. The setup (making
 * the files a check uses, emptying SCRATCH) stays A. The directory of
 * 100 files is listed and sized again through the W calls before it is
 * emptied, and the write and crt sizes are read again through
 * GetFileAttributesExW.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo fswrite.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static char base[MAX_PATH];         /* SCRATCH\ under the image's directory */
static WCHAR wbase[MAX_PATH];       /* the same, in the ANSI code page's Unicode */

static const char *at(const char *rel)
{
    static char bufs[4][2 * MAX_PATH];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s%s", base, rel);
    return b;
}

static const WCHAR *wat(const WCHAR *rel)
{
    static WCHAR bufs[4][2 * MAX_PATH];
    static int next;
    WCHAR *b = bufs[next++ & 3];

    wcscpy(b, wbase);
    wcscat(b, rel);
    return b;
}

static BYTE pattern(DWORD i)
{
    return (BYTE)(i * 7 + (i >> 9));
}

static DWORD file_size(const char *rel)
{
    WIN32_FILE_ATTRIBUTE_DATA ad;

    if (!GetFileAttributesExA(at(rel), GetFileExInfoStandard, &ad)) {
        return (DWORD)-1;
    }
    return ad.nFileSizeLow;
}

static DWORD file_size_w(const WCHAR *rel)
{
    WIN32_FILE_ATTRIBUTE_DATA ad;

    if (!GetFileAttributesExW(wat(rel), GetFileExInfoStandard, &ad)) {
        return (DWORD)-1;
    }
    return ad.nFileSizeLow;
}

/* The size of a name under SCRATCH through GetFileAttributesExA, or
   (wide) GetFileAttributesExW; its attributes through GetFileAttributesA
   or GetFileAttributesW. */
static DWORD size_of(int wide, const char *rel, const WCHAR *wrel)
{
    return wide ? file_size_w(wrel) : file_size(rel);
}

static DWORD attrs_of(int wide, const char *rel, const WCHAR *wrel)
{
    return wide ? GetFileAttributesW(wat(wrel)) : GetFileAttributesA(at(rel));
}

/* Empty SCRATCH (one level of subdirectories deep) without printing. */
static void wipe(const char *dir)
{
    char pat[2 * MAX_PATH];
    char path[2 * MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE f;

    sprintf(pat, "%s*", dir);
    f = FindFirstFileA(pat, &fd);
    if (f == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }
        sprintf(path, "%s%s", dir, fd.cFileName);
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            strcat(path, "\\");
            wipe(path);
            path[strlen(path) - 1] = 0;
            RemoveDirectoryA(path);
        } else {
            DeleteFileA(path);
        }
    } while (FindNextFileA(f, &fd));
    FindClose(f);
}

static void init_scratch(void)
{
    char *p;

    GetModuleFileNameA(NULL, base, sizeof base);
    p = strrchr(base, '\\');
    if (p != NULL) {
        p[1] = 0;
    } else {
        base[0] = 0;
    }
    strcat(base, "SCRATCH");
    CreateDirectoryA(base, NULL);
    strcat(base, "\\");
    MultiByteToWideChar(CP_ACP, 0, base, -1, wbase, MAX_PATH);
    wipe(base);
}

static HANDLE open_file(const char *rel, DWORD access, DWORD share, DWORD disposition)
{
    return CreateFileA(at(rel), access, share, NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL);
}

/* An open through CreateFileA, or (wide) CreateFileW, its result printed. */
static void try_create(int wide, const char *label, const char *rel, const WCHAR *wrel, DWORD access,
                       DWORD disposition)
{
    HANDLE h;
    const char *e;

    arm();
    h = wide ? CreateFileW(wat(wrel), access, 0, NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL)
             : open_file(rel, access, 0, disposition);
    e = le();
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    line("%s%s: %s err=%s, size now %ld", label, wide ? " (W)" : "",
         h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e, (LONG)size_of(wide, rel, wrel));
}

static void write_text(const char *rel, const char *text)
{
    HANDLE h = open_file(rel, GENERIC_WRITE, 0, CREATE_ALWAYS);
    DWORD put;

    WriteFile(h, text, strlen(text), &put, NULL);
    CloseHandle(h);
}

/* --- create -------------------------------------------------------- */

/* The dispositions, through CreateFileA or (wide) CreateFileW. */
static void create_cases(int wide)
{
    try_create(wide, "CREATE_NEW, new", "A.TXT", L"A.TXT", GENERIC_WRITE, CREATE_NEW);
    try_create(wide, "CREATE_NEW, existing", "A.TXT", L"A.TXT", GENERIC_WRITE, CREATE_NEW);
    write_text("A.TXT", "twelve bytes");
    try_create(wide, "CREATE_ALWAYS, existing", "A.TXT", L"A.TXT", GENERIC_WRITE, CREATE_ALWAYS);
    try_create(wide, "CREATE_ALWAYS, new", "B.TXT", L"B.TXT", GENERIC_WRITE, CREATE_ALWAYS);
    write_text("A.TXT", "twelve bytes");
    try_create(wide, "OPEN_ALWAYS, existing", "A.TXT", L"A.TXT", GENERIC_READ, OPEN_ALWAYS);
    try_create(wide, "OPEN_ALWAYS, new", "C.TXT", L"C.TXT", GENERIC_READ, OPEN_ALWAYS);
    try_create(wide, "TRUNCATE_EXISTING", "A.TXT", L"A.TXT", GENERIC_WRITE, TRUNCATE_EXISTING);
    try_create(wide, "TRUNCATE_EXISTING without write access", "A.TXT", L"A.TXT", GENERIC_READ,
               TRUNCATE_EXISTING);
    try_create(wide, "TRUNCATE_EXISTING, missing", "NOSUCH.TXT", L"NOSUCH.TXT", GENERIC_WRITE, TRUNCATE_EXISTING);
    try_create(wide, "OPEN_EXISTING, missing", "NOSUCH.TXT", L"NOSUCH.TXT", GENERIC_WRITE, OPEN_EXISTING);
    try_create(wide, "CREATE_NEW in a missing directory", "NODIR\\A.TXT", L"NODIR\\A.TXT", GENERIC_WRITE,
               CREATE_NEW);
    try_create(wide, "a bad disposition", "D.TXT", L"D.TXT", GENERIC_WRITE, 9);
}

static void sec_create(void)
{
    create_cases(0);
    wipe(base);
    create_cases(1);
}

/* --- write --------------------------------------------------------- */

static BYTE wbuf[100000];
static BYTE rbuf[100000];

static void sec_write(void)
{
    HANDLE h;
    DWORD i, put, got, total;
    const char *e;
    BOOL r;
    int ok;

    for (i = 0; i < sizeof wbuf; i++) {
        wbuf[i] = pattern(i);
    }
    h = open_file("W.BIN", GENERIC_WRITE, 0, CREATE_ALWAYS);
    ok = h != INVALID_HANDLE_VALUE;
    total = 0;
    while (ok && total < sizeof wbuf) {
        DWORD n = sizeof wbuf - total < 3000 ? sizeof wbuf - total : 3000;

        ok = WriteFile(h, wbuf + total, n, &put, NULL) && put == n;
        total += put;
    }
    line("100000 bytes in 3000-byte writes: %s, position %lu", ok ? "ok" : "failed",
         SetFilePointer(h, 0, NULL, FILE_CURRENT));
    arm();
    r = FlushFileBuffers(h);
    line("FlushFileBuffers: ret=%d err=%s", r, le());
    CloseHandle(h);
    line("size after close: %lu", file_size("W.BIN"));
    line("size after close (W): %lu", file_size_w(L"W.BIN"));

    h = open_file("W.BIN", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    ReadFile(h, rbuf, sizeof rbuf, &got, NULL);
    line("read back: %lu bytes, match %s", got, yesno(got == sizeof wbuf && memcmp(rbuf, wbuf, got) == 0));
    arm();
    r = WriteFile(h, wbuf, 10, &put, NULL);
    line("write through a read-only handle: ret=%d err=%s", r, le());
    CloseHandle(h);

    h = open_file("W.BIN", GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING);
    SetFilePointer(h, 0, NULL, FILE_END);
    WriteFile(h, "tail", 4, &put, NULL);
    line("append: size %lu", GetFileSize(h, NULL));
    SetFilePointer(h, 5000, NULL, FILE_END);
    WriteFile(h, "far", 3, &put, NULL);
    line("write 5000 past the end: size %lu", GetFileSize(h, NULL));
    SetFilePointer(h, 100004, NULL, FILE_BEGIN);
    ReadFile(h, rbuf, 5000, &got, NULL);
    ok = got == 5000;
    for (i = 0; ok && i < 5000; i++) {
        ok = rbuf[i] == 0;
    }
    line("the gap reads as zeros: %s", yesno(ok));
    SetFilePointer(h, 1000, NULL, FILE_BEGIN);
    arm();
    r = SetEndOfFile(h);
    e = le();
    line("SetEndOfFile at 1000: ret=%d err=%s, size %lu", r, e, GetFileSize(h, NULL));
    SetFilePointer(h, 70000, NULL, FILE_BEGIN);
    r = SetEndOfFile(h);
    SetFilePointer(h, 1000, NULL, FILE_BEGIN);
    ReadFile(h, rbuf, 69000, &got, NULL);
    ok = got == 69000;
    for (i = 0; ok && i < 69000; i++) {
        ok = rbuf[i] == 0;
    }
    line("SetEndOfFile growing to 70000: ret=%d size %lu, the extension zero %s", r, GetFileSize(h, NULL),
         yesno(ok));
    arm();
    r = WriteFile(h, wbuf, 0, &put, NULL);
    line("zero-byte write: ret=%d put %lu err=%s", r, put, le());
    CloseHandle(h);
}

/* --- share --------------------------------------------------------- */

/* The second open through CreateFileA, or (wide) CreateFileW. */
static void share_case(int wide, const char *label, DWORD a1, DWORD s1, DWORD a2, DWORD s2)
{
    HANDLE h1, h2;

    write_text("S.TXT", "share");
    h1 = open_file("S.TXT", a1, s1, OPEN_EXISTING);
    arm();
    h2 = wide ? CreateFileW(wat(L"S.TXT"), a2, s2, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
              : open_file("S.TXT", a2, s2, OPEN_EXISTING);
    line("%s%s: %s err=%s", label, wide ? " (W)" : "", h2 == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened",
         le());
    if (h2 != INVALID_HANDLE_VALUE) {
        CloseHandle(h2);
    }
    CloseHandle(h1);
}

/* The share modes and deletes, through the A calls or (wide) their W twins. */
static void share_block(int wide)
{
    const char *aw = wide ? "W" : "A";
    const char *tag = wide ? " (W)" : "";
    HANDLE h;
    const char *e;
    DWORD a;
    BOOL r;

    share_case(wide, "writer sharing read, then a second writer", GENERIC_WRITE, FILE_SHARE_READ, GENERIC_WRITE,
               FILE_SHARE_READ | FILE_SHARE_WRITE);
    share_case(wide, "writer sharing read, then a reader", GENERIC_WRITE, FILE_SHARE_READ, GENERIC_READ,
               FILE_SHARE_READ | FILE_SHARE_WRITE);
    share_case(wide, "reader sharing read, then a reader not sharing write", GENERIC_READ, FILE_SHARE_READ,
               GENERIC_READ, FILE_SHARE_READ);
    share_case(wide, "reader sharing read and write, then a writer", GENERIC_READ,
               FILE_SHARE_READ | FILE_SHARE_WRITE, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);

    write_text("S.TXT", "share");
    h = open_file("S.TXT", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    arm();
    r = wide ? DeleteFileW(wat(L"S.TXT")) : DeleteFileA(at("S.TXT"));
    line("DeleteFile%s of an open file: ret=%d err=%s", aw, r, le());
    CloseHandle(h);
    arm();
    r = wide ? DeleteFileW(wat(L"S.TXT")) : DeleteFileA(at("S.TXT"));
    line("DeleteFile%s after closing: ret=%d err=%s", aw, r, le());

    arm();
    h = wide ? CreateFileW(wat(L"T.TMP"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL)
             : CreateFileA(at("T.TMP"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    e = le();
    line("FILE_FLAG_DELETE_ON_CLOSE%s: created %s err=%s, exists while open %s", tag,
         yesno(h != INVALID_HANDLE_VALUE), e, yesno(attrs_of(wide, "T.TMP", L"T.TMP") != INVALID_FILE_ATTRIBUTES));
    CloseHandle(h);
    arm();
    a = attrs_of(wide, "T.TMP", L"T.TMP");
    line("after close%s: attributes 0x%08lX err=%s", tag, a, le());
}

static void sec_share(void)
{
    share_block(0);
    share_block(1);
}

/* --- names --------------------------------------------------------- */

/* A created name as the volume keeps it: GetShortPathNameA's final
   component, and the long and alternate names FindFirstFileA lists; or
   (wide) the same through GetShortPathNameW and FindFirstFileW. */
static void show_names(int wide, const char *rel, const WCHAR *wrel)
{
    char buf[MAX_PATH];
    WCHAR wb[MAX_PATH];
    WIN32_FIND_DATAA fd;
    WIN32_FIND_DATAW wfd;
    HANDLE f;
    char *p;
    WCHAR *wp;
    DWORD n;

    if (wide) {
        n = GetShortPathNameW(wat(wrel), wb, MAX_PATH);
        wp = wcsrchr(wb, L'\\');
        f = FindFirstFileW(wat(wrel), &wfd);
        if (f != INVALID_HANDLE_VALUE) {
            FindClose(f);
        }
        line("created [%s] (W): short name [%s], listed [%s] alternate [%s]", ws(wrel),
             n != 0 ? ws(wp != NULL ? wp + 1 : wb) : "", f != INVALID_HANDLE_VALUE ? ws(wfd.cFileName) : "",
             f != INVALID_HANDLE_VALUE ? ws(wfd.cAlternateFileName) : "");
        return;
    }
    n = GetShortPathNameA(at(rel), buf, sizeof buf);
    p = strrchr(buf, '\\');
    f = FindFirstFileA(at(rel), &fd);
    if (f != INVALID_HANDLE_VALUE) {
        FindClose(f);
    }
    line("created [%s]: short name [%s], listed [%s] alternate [%s]", rel,
         n != 0 ? (p != NULL ? p + 1 : buf) : "", f != INVALID_HANDLE_VALUE ? fd.cFileName : "",
         f != INVALID_HANDLE_VALUE ? fd.cAlternateFileName : "");
}

/* Moves, copies, deletes and names, through the A calls or (wide) their
   W twins. */
static void names_block(int wide)
{
    const char *aw = wide ? "W" : "A";
    const char *tag = wide ? " (W)" : "";
    char buf[MAX_PATH];
    WCHAR wb[MAX_PATH];
    const char *e;
    const char *sn;
    char *p;
    WCHAR *wp;
    DWORD n;
    BOOL r;

    write_text("M1.TXT", "move me");
    arm();
    r = wide ? MoveFileW(wat(L"M1.TXT"), wat(L"M2.TXT")) : MoveFileA(at("M1.TXT"), at("M2.TXT"));
    e = le();
    line("MoveFile%s rename: ret=%d err=%s, old gone %s, new size %lu", aw, r, e,
         yesno(attrs_of(wide, "M1.TXT", L"M1.TXT") == INVALID_FILE_ATTRIBUTES), size_of(wide, "M2.TXT", L"M2.TXT"));
    write_text("M3.TXT", "other");
    arm();
    r = wide ? MoveFileW(wat(L"M2.TXT"), wat(L"M3.TXT")) : MoveFileA(at("M2.TXT"), at("M3.TXT"));
    line("MoveFile%s onto an existing file: ret=%d err=%s", aw, r, le());
    CreateDirectoryA(at("MD"), NULL);
    arm();
    r = wide ? MoveFileW(wat(L"M2.TXT"), wat(L"MD\\M2.TXT")) : MoveFileA(at("M2.TXT"), at("MD\\M2.TXT"));
    line("MoveFile%s into a subdirectory: ret=%d err=%s", aw, r, le());
    arm();
    r = wide ? MoveFileW(wat(L"NOSUCH.TXT"), wat(L"X.TXT")) : MoveFileA(at("NOSUCH.TXT"), at("X.TXT"));
    line("MoveFile%s of a missing file: ret=%d err=%s", aw, r, le());

    arm();
    r = wide ? CopyFileW(wat(L"M3.TXT"), wat(L"C1.TXT"), TRUE) : CopyFileA(at("M3.TXT"), at("C1.TXT"), TRUE);
    e = le();
    line("CopyFile%s: ret=%d err=%s, size %lu", aw, r, e, size_of(wide, "C1.TXT", L"C1.TXT"));
    arm();
    r = wide ? CopyFileW(wat(L"M3.TXT"), wat(L"C1.TXT"), TRUE) : CopyFileA(at("M3.TXT"), at("C1.TXT"), TRUE);
    line("CopyFile%s onto an existing file, failing if it exists: ret=%d err=%s", aw, r, le());
    arm();
    r = wide ? CopyFileW(wat(L"MD\\M2.TXT"), wat(L"C1.TXT"), FALSE)
             : CopyFileA(at("MD\\M2.TXT"), at("C1.TXT"), FALSE);
    e = le();
    line("CopyFile%s overwriting: ret=%d err=%s, size %lu", aw, r, e, size_of(wide, "C1.TXT", L"C1.TXT"));

    arm();
    r = wide ? DeleteFileW(wat(L"NOSUCH.TXT")) : DeleteFileA(at("NOSUCH.TXT"));
    line("DeleteFile%s(missing): ret=%d err=%s", aw, r, le());
    arm();
    r = wide ? DeleteFileW(wat(L"MD")) : DeleteFileA(at("MD"));
    line("DeleteFile%s(a directory): ret=%d err=%s", aw, r, le());
    if (wide) {
        SetFileAttributesW(wat(L"C1.TXT"), FILE_ATTRIBUTE_READONLY);
    } else {
        SetFileAttributesA(at("C1.TXT"), FILE_ATTRIBUTE_READONLY);
    }
    line("read-only attribute set%s: 0x%08lX", tag, attrs_of(wide, "C1.TXT", L"C1.TXT"));
    arm();
    r = wide ? DeleteFileW(wat(L"C1.TXT")) : DeleteFileA(at("C1.TXT"));
    line("DeleteFile%s(read-only): ret=%d err=%s", aw, r, le());
    if (wide) {
        SetFileAttributesW(wat(L"C1.TXT"), FILE_ATTRIBUTE_NORMAL);
    } else {
        SetFileAttributesA(at("C1.TXT"), FILE_ATTRIBUTE_NORMAL);
    }
    arm();
    r = wide ? DeleteFileW(wat(L"C1.TXT")) : DeleteFileA(at("C1.TXT"));
    line("after clearing it%s: ret=%d err=%s", tag, r, le());

    write_text("A Long Created Name.txt", "long");
    arm();
    if (wide) {
        n = GetShortPathNameW(wat(L"A Long Created Name.txt"), wb, MAX_PATH);
        e = le();
        wp = wcsrchr(wb, L'\\');
        sn = n != 0 ? ws(wp != NULL ? wp + 1 : wb) : "";
    } else {
        n = GetShortPathNameA(at("A Long Created Name.txt"), buf, sizeof buf);
        e = le();
        p = strrchr(buf, '\\');
        sn = n != 0 ? (p != NULL ? p + 1 : buf) : "";
    }
    line("created a long name%s: size %lu, short name [%s] err=%s", tag,
         size_of(wide, "A Long Created Name.txt", L"A Long Created Name.txt"), sn, e);
    line("opened by its short name%s: size %lu", tag, size_of(wide, "ALONGC~1.TXT", L"ALONGC~1.TXT"));

    /* FS-8: a valid 8.3 name with a mixed-case part, then a long name
       with the same basis (its alias numbering). */
    write_text("Readme.txt", "mixed");
    show_names(wide, "Readme.txt", L"Readme.txt");
    write_text("NOTES.Txt", "mixed");
    show_names(wide, "NOTES.Txt", L"NOTES.Txt");
    write_text("Readme file.txt", "long");
    show_names(wide, "Readme file.txt", L"Readme file.txt");

    /* FS-16: short names in the OEM code page: an 8.3 name with a
       lower-case letter outside ASCII (e acute), and one with a
       character code page 437 lacks (the euro sign, U+20AC, byte 0x80
       in code page 1252). */
    write_text("caf\xe9.txt", "accent");
    show_names(wide, "caf\xe9.txt", L"caf\x00e9.txt");
    write_text("\x80uro.txt", "euro");
    show_names(wide, "\x80uro.txt", L"\x20acuro.txt");
}

static void sec_names(void)
{
    names_block(0);
    wipe(base);
    names_block(1);
}

/* --- dirs ---------------------------------------------------------- */

/* Directory creation and removal, through the A calls or (wide) their W
   twins. */
static void dirs_block(int wide)
{
    const char *aw = wide ? "W" : "A";
    const char *e;
    BOOL r;

    arm();
    r = wide ? CreateDirectoryW(wat(L"D1"), NULL) : CreateDirectoryA(at("D1"), NULL);
    e = le();
    line("CreateDirectory%s: ret=%d err=%s, attributes 0x%08lX", aw, r, e, attrs_of(wide, "D1", L"D1"));
    arm();
    r = wide ? CreateDirectoryW(wat(L"D1"), NULL) : CreateDirectoryA(at("D1"), NULL);
    line("CreateDirectory%s again: ret=%d err=%s", aw, r, le());
    arm();
    r = wide ? CreateDirectoryW(wat(L"NODIR\\D2"), NULL) : CreateDirectoryA(at("NODIR\\D2"), NULL);
    line("CreateDirectory%s under a missing parent: ret=%d err=%s", aw, r, le());
    write_text("D1\\F.TXT", "in a directory");
    arm();
    r = wide ? RemoveDirectoryW(wat(L"D1")) : RemoveDirectoryA(at("D1"));
    line("RemoveDirectory%s(not empty): ret=%d err=%s", aw, r, le());
    DeleteFileA(at("D1\\F.TXT"));
    arm();
    r = wide ? RemoveDirectoryW(wat(L"D1")) : RemoveDirectoryA(at("D1"));
    line("RemoveDirectory%s(empty): ret=%d err=%s", aw, r, le());
    arm();
    r = wide ? RemoveDirectoryW(wat(L"D1")) : RemoveDirectoryA(at("D1"));
    line("RemoveDirectory%s(missing): ret=%d err=%s", aw, r, le());
    write_text("NOTADIR.TXT", "x");
    arm();
    r = wide ? RemoveDirectoryW(wat(L"NOTADIR.TXT")) : RemoveDirectoryA(at("NOTADIR.TXT"));
    line("RemoveDirectory%s(a file): ret=%d err=%s", aw, r, le());
}

static void sec_dirs(void)
{
    char name[32];
    WCHAR wname[32];
    WIN32_FIND_DATAA fd;
    WIN32_FIND_DATAW wfd;
    HANDLE f;
    int i, count, ok;

    dirs_block(0);
    dirs_block(1);

    CreateDirectoryA(at("BIGDIR"), NULL);
    ok = 1;
    for (i = 0; i < 100; i++) {
        sprintf(name, "BIGDIR\\F%03d.TXT", i);
        write_text(name, "entry");
        ok &= file_size(name) == 5;
    }
    count = 0;
    f = FindFirstFileA(at("BIGDIR\\*.TXT"), &fd);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            count++;
        } while (FindNextFileA(f, &fd));
        FindClose(f);
    }
    line("100 files in one directory: all written %s, listed %d", yesno(ok), count);
    /* The same files sized and listed again through the W calls (written
       once: the hundred creations are the block's slow part). */
    ok = 1;
    wcscpy(wname, L"BIGDIR\\F000.TXT");
    for (i = 0; i < 100; i++) {
        wname[8] = (WCHAR)(L'0' + i / 100);
        wname[9] = (WCHAR)(L'0' + i / 10 % 10);
        wname[10] = (WCHAR)(L'0' + i % 10);
        ok &= file_size_w(wname) == 5;
    }
    count = 0;
    f = FindFirstFileW(wat(L"BIGDIR\\*.TXT"), &wfd);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            count++;
        } while (FindNextFileW(f, &wfd));
        FindClose(f);
    }
    line("100 files in one directory (W): all written %s, listed %d", yesno(ok), count);
    for (i = 0; i < 100; i++) {
        sprintf(name, "BIGDIR\\F%03d.TXT", i);
        DeleteFileA(at(name));
    }
    line("emptied and removed: %d", RemoveDirectoryA(at("BIGDIR")));
}

/* --- times --------------------------------------------------------- */

static void sec_times(void)
{
    SYSTEMTIME st;
    FILETIME ft, back, ct, at_;
    HANDLE h;
    BOOL r;

    write_text("TIME.TXT", "time");
    st.wYear = 2001;
    st.wMonth = 2;
    st.wDayOfWeek = 0;
    st.wDay = 3;
    st.wHour = 4;
    st.wMinute = 5;
    st.wSecond = 6;
    st.wMilliseconds = 0;
    SystemTimeToFileTime(&st, &ft);
    h = open_file("TIME.TXT", GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING);
    arm();
    r = SetFileTime(h, NULL, NULL, &ft);
    line("SetFileTime(last write = 2001-02-03 04:05:06): ret=%d err=%s", r, le());
    CloseHandle(h);
    h = open_file("TIME.TXT", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    GetFileTime(h, &ct, &at_, &back);
    CloseHandle(h);
    FileTimeToSystemTime(&back, &st);
    line("read back: %04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* --- crt ----------------------------------------------------------- */

static void sec_crt(void)
{
    FILE *f;
    char buf[64];
    size_t n;
    int r;

    f = fopen(at("CRT.TXT"), "w");
    fputs("line one\nline two\n", f);
    fclose(f);
    line("text-mode write of two lines: %lu bytes on disk", file_size("CRT.TXT"));
    line("text-mode write of two lines (W): %lu bytes on disk", file_size_w(L"CRT.TXT"));
    f = fopen(at("CRT.TXT"), "a");
    fprintf(f, "%d\n", 3);
    fclose(f);
    line("append: %lu bytes", file_size("CRT.TXT"));
    line("append (W): %lu bytes", file_size_w(L"CRT.TXT"));
    f = fopen(at("CRT.TXT"), "r+");
    fseek(f, 5, SEEK_SET);
    fputs("ONE", f);
    fseek(f, 0, SEEK_SET);
    fgets(buf, sizeof buf, f);
    fclose(f);
    line("r+ overwrite in place, read back: [%.*s]", (int)(strlen(buf) > 0 ? strlen(buf) - 1 : 0), buf);
    f = fopen(at("CRT.BIN"), "wb");
    n = fwrite("a\nb\n", 1, 4, f);
    fclose(f);
    line("binary fwrite of 4: %u written, %lu on disk", n, file_size("CRT.BIN"));
    line("binary fwrite of 4 (W): %lu on disk", file_size_w(L"CRT.BIN"));
    r = rename(at("CRT.BIN"), at("CRT2.BIN"));
    line("rename: %d, size under the new name %lu", r, file_size("CRT2.BIN"));
    line("rename (W): size under the new name %lu", file_size_w(L"CRT2.BIN"));
    r = remove(at("CRT2.BIN"));
    line("remove: %d", r);
    errno = 0;
    r = remove(at("CRT2.BIN"));
    line("remove again: %d errno %d", r, errno);
}

static const section_t sections[] = {
    { "create", sec_create, 0 },
    { "write", sec_write, 0 },
    { "share", sec_share, 0 },
    { "names", sec_names, 0 },
    { "dirs", sec_dirs, 0 },
    { "times", sec_times, 0 },
    { "crt", sec_crt, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    init_scratch();
    return run_sections("fswrite", sections, argc, argv);
}
