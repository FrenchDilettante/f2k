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
 *   movex    MoveFileExA: a rename; onto an existing file without and
 *            with MOVEFILE_REPLACE_EXISTING; MOVEFILE_COPY_ALLOWED and
 *            MOVEFILE_WRITE_THROUGH on one volume; a directory; into a
 *            subdirectory; a missing source; a NULL destination without
 *            MOVEFILE_DELAY_UNTIL_REBOOT (never that flag: it writes the
 *            registry); REPLACE_EXISTING onto a directory and onto a
 *            read-only file; then what is left on disk
 *   lock     LockFile and UnlockFile on LOCK.DAT through two handles
 *            (and a duplicate of the first, a read-only handle and one
 *            with no access): overlapping, repeated, adjacent, empty and
 *            past-the-end ranges through one handle; the second refused
 *            inside the first's ranges and granted outside; the reads and
 *            writes each handle's locks refuse the other (straddling a
 *            range too) and let their own through, with the file pointer
 *            after; the duplicate as the same open file; unlocks of the
 *            exact range, of a range never locked, of part of a range and
 *            of the other handle's range; a lock released by its handle's
 *            close; the refusals for a handle with no access,
 *            INVALID_HANDLE_VALUE and NULL. LockFile and UnlockFile are
 *            reached through GetProcAddress, so the program still loads
 *            where kernel32 lacks them.
 *   moveinto MoveFileEx's refusals that must leave both names as they
 *            were: a directory moved into itself and beneath itself, a
 *            replacing move onto a file another handle holds open (sharing
 *            all), one whose source is held open sharing read only; then
 *            the plain replacing move; then what is left on disk
 *   overwrite CREATE_ALWAYS, OPEN_ALWAYS and TRUNCATE_EXISTING while a
 *            reader holds the file sharing read only, or read and write
 *            (whether a truncating open is share-checked as a write even
 *            when it asks only to read), and CREATE_ALWAYS over a file
 *            with a mapped view; the size each leaves
 *   overlap  a FILE_FLAG_OVERLAPPED handle: WriteFile and ReadFile at
 *            offsets (in range, across, at and past the end, at 4 GiB)
 *            with an event and with none, GetOverlappedResult waiting and
 *            not (on a done request and on one marked STATUS_PENDING),
 *            four reads in flight, the file pointer after, ReadFile and
 *            WriteFile with no OVERLAPPED on that handle; an OVERLAPPED on
 *            a plain handle. Whether a call completes at once or answers
 *            ERROR_IO_PENDING is timing, never printed: each prints its
 *            end. GetOverlappedResult is reached through GetProcAddress.
 *   negoff   ReadFile and WriteFile through an OVERLAPPED on a plain
 *            handle at the offsets -1, -2, -16, the most negative and 200
 *            (sanity): the return, the error, the size and the pointer
 *   deep     a tree past MAX_PATH through \\?\: CreateDirectoryW nine
 *            levels deep, a file created, its attributes, reopened and
 *            read; the same path without \\?\ and through the A calls;
 *            DeleteFileW and RemoveDirectoryW
 *
 * The create, share, names, dirs, movex, moveinto and overwrite
 * observations run twice:
 * through the A calls, then through their W twins on the same names (the
 * W lines carry the W names, or "(W)"); create, names and movex empty
 * SCRATCH between the two runs (moveinto too), so both start from the same state. The
 * setup (making the files a check uses, emptying SCRATCH, listing what a
 * move left) stays A. The directory of 100 files is listed and sized
 * again through the W calls before it is emptied, and the write and crt
 * sizes are read again through GetFileAttributesExW.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo fswrite.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* Windows NT's MoveFileEx flag, which MSVC 6's headers may lack. */
#ifndef MOVEFILE_WRITE_THROUGH
#define MOVEFILE_WRITE_THROUGH 0x00000008
#endif

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

/* --- movex --------------------------------------------------------- */

/* What a name under SCRATCH is now, as printed: absent, a directory, or
   a file's size; read-only when it is. Through the A calls or (wide)
   their W twins. */
static const char *what_is(int wide, const char *rel, const WCHAR *wrel)
{
    static char bufs[4][48];
    static int next;
    char *b = bufs[next++ & 3];
    DWORD a = attrs_of(wide, rel, wrel);

    if (a == INVALID_FILE_ATTRIBUTES) {
        return "absent";
    }
    if (a & FILE_ATTRIBUTE_DIRECTORY) {
        strcpy(b, "a directory");
    } else {
        sprintf(b, "%lu bytes", size_of(wide, rel, wrel));
    }
    if (a & FILE_ATTRIBUTE_READONLY) {
        strcat(b, ", read-only");
    }
    return b;
}

/* MoveFileExA, or (wide) MoveFileExW, from one name under SCRATCH to
   another (NULL for none), under __try: a NULL destination might fault,
   and the fixture must not stop on a dialog. Prints the return, the
   error, and what both names are afterwards. */
static void move_ex(int wide, const char *from, const WCHAR *wfrom, const char *to, const WCHAR *wto,
                    DWORD flags, const char *flag_names)
{
    const char *aw = wide ? "W" : "A";
    const char *src = at(from);
    const char *dst = to != NULL ? at(to) : NULL;
    const WCHAR *wsrc = wat(wfrom);
    const WCHAR *wdst = wto != NULL ? wat(wto) : NULL;
    const char *e;
    BOOL r = FALSE;
    int faulted = 0;

    arm();
    __try {
        r = wide ? MoveFileExW(wsrc, wdst, flags) : MoveFileExA(src, dst, flags);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    e = le();
    if (faulted) {
        line("MoveFileEx%s(%s, %s, %s): faulted", aw, from, to != NULL ? to : "NULL", flag_names);
    } else if (to == NULL) {
        line("MoveFileEx%s(%s, NULL, %s): ret=%d err=%s, %s %s", aw, from, flag_names, r, e,
             from, what_is(wide, from, wfrom));
    } else {
        line("MoveFileEx%s(%s, %s, %s): ret=%d err=%s, %s %s, %s %s", aw, from, to, flag_names, r, e,
             from, what_is(wide, from, wfrom), to, what_is(wide, to, wto));
    }
}

static int cmp_left(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* What a directory under SCRATCH holds (`dir` relative, with its
   trailing backslash, or ""), sorted, each name with its size or
   "(directory)", and "read-only" where set. Listed through the A calls:
   the observation is the moves', not the listing's. */
static void left_in(const char *tag, const char *dir)
{
    static char names[32][MAX_PATH + 32];
    char pat[2 * MAX_PATH];
    char out[900];
    WIN32_FIND_DATAA fd;
    HANDLE f;
    int n = 0;
    int i;

    sprintf(pat, "%s%s*", base, dir);
    f = FindFirstFileA(pat, &fd);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0 || n == 32) {
                continue;
            }
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                sprintf(names[n], "%s (directory)", fd.cFileName);
            } else {
                sprintf(names[n], "%s %lu bytes", fd.cFileName, fd.nFileSizeLow);
            }
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
                strcat(names[n], " read-only");
            }
            n++;
        } while (FindNextFileA(f, &fd));
        FindClose(f);
    }
    qsort(names, n, sizeof names[0], cmp_left);
    out[0] = 0;
    for (i = 0; i < n && strlen(out) + strlen(names[i]) + 3 < sizeof out; i++) {
        if (i > 0) {
            strcat(out, ", ");
        }
        strcat(out, names[i]);
    }
    line("left in SCRATCH\\%s%s: %s", dir, tag, n != 0 ? out : "nothing");
}

/* MoveFileEx's cases, through MoveFileExA or (wide) MoveFileExW. The
   files they move are made through the A calls (setup). */
static void movex_block(int wide)
{
    const char *tag = wide ? " (W)" : "";

    write_text("X1.TXT", "first");
    move_ex(wide, "X1.TXT", L"X1.TXT", "X2.TXT", L"X2.TXT", 0, "0");
    write_text("X3.TXT", "existing!");
    move_ex(wide, "X2.TXT", L"X2.TXT", "X3.TXT", L"X3.TXT", 0, "0");
    move_ex(wide, "X2.TXT", L"X2.TXT", "X3.TXT", L"X3.TXT", MOVEFILE_REPLACE_EXISTING, "REPLACE_EXISTING");
    write_text("X4.TXT", "copy allowed");
    move_ex(wide, "X4.TXT", L"X4.TXT", "X5.TXT", L"X5.TXT", MOVEFILE_COPY_ALLOWED, "COPY_ALLOWED");
    move_ex(wide, "X5.TXT", L"X5.TXT", "X6.TXT", L"X6.TXT", MOVEFILE_WRITE_THROUGH, "WRITE_THROUGH");
    write_text("X7.TXT", "seven");
    move_ex(wide, "X6.TXT", L"X6.TXT", "X7.TXT", L"X7.TXT", MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED,
            "REPLACE_EXISTING | COPY_ALLOWED");

    CreateDirectoryA(at("XD1"), NULL);
    write_text("XD1\\IN.TXT", "inside");
    move_ex(wide, "XD1", L"XD1", "XD2", L"XD2", 0, "0");
    line("XD2\\IN.TXT after the directory moved%s: %s", tag, what_is(wide, "XD2\\IN.TXT", L"XD2\\IN.TXT"));
    move_ex(wide, "X7.TXT", L"X7.TXT", "XD2\\X7.TXT", L"XD2\\X7.TXT", 0, "0");

    move_ex(wide, "NOSUCH.TXT", L"NOSUCH.TXT", "X8.TXT", L"X8.TXT", 0, "0");
    write_text("X8.TXT", "eight");
    move_ex(wide, "X8.TXT", L"X8.TXT", NULL, NULL, 0, "0");

    write_text("X9.TXT", "nine");
    CreateDirectoryA(at("XD3"), NULL);
    move_ex(wide, "X9.TXT", L"X9.TXT", "XD3", L"XD3", MOVEFILE_REPLACE_EXISTING, "REPLACE_EXISTING");
    write_text("XR.TXT", "read-only");
    SetFileAttributesA(at("XR.TXT"), FILE_ATTRIBUTE_READONLY);
    move_ex(wide, "X9.TXT", L"X9.TXT", "XR.TXT", L"XR.TXT", MOVEFILE_REPLACE_EXISTING, "REPLACE_EXISTING");

    left_in(tag, "");
    left_in(tag, "XD2\\");
    left_in(tag, "XD3\\");
}

static void sec_movex(void)
{
    movex_block(0);
    wipe(base);
    movex_block(1);
}

/* --- lock ---------------------------------------------------------- */

/* LockFile and UnlockFile are reached through GetProcAddress: the program
   loads where kernel32 lacks them, its other sections intact. */
typedef BOOL (WINAPI *lock_file_fn)(HANDLE file, DWORD offset_low, DWORD offset_high, DWORD length_low,
                                    DWORD length_high);

static lock_file_fn lock_file;
static lock_file_fn unlock_file;

static void try_lock(const char *who, HANDLE h, DWORD offset, DWORD length)
{
    BOOL r;
    const char *e;

    arm();
    r = lock_file(h, offset, 0, length, 0);
    e = le();
    line("LockFile(%s, %lu, %lu): ret=%d err=%s", who, offset, length, r, e);
}

static void try_unlock(const char *who, HANDLE h, DWORD offset, DWORD length)
{
    BOOL r;
    const char *e;

    arm();
    r = unlock_file(h, offset, 0, length, 0);
    e = le();
    line("UnlockFile(%s, %lu, %lu): ret=%d err=%s", who, offset, length, r, e);
}

/* ReadFile of `length` bytes at `offset` through `h`: its answer, the
   count, the last error, and where the file pointer is after. */
static void try_read(const char *who, HANDLE h, DWORD offset, DWORD length)
{
    BYTE buf[64];
    DWORD got = 0xDEAD;
    BOOL r;
    const char *e;

    SetFilePointer(h, offset, NULL, FILE_BEGIN);
    arm();
    r = ReadFile(h, buf, length, &got, NULL);
    e = le();
    line("  ReadFile(%s, %lu bytes at %lu): ret=%d got %lu err=%s, the pointer at %lu", who, length, offset, r,
         got, e, SetFilePointer(h, 0, NULL, FILE_CURRENT));
}

static void try_write(const char *who, HANDLE h, DWORD offset, DWORD length)
{
    BYTE buf[64];
    DWORD put = 0xDEAD;
    BOOL r;
    const char *e;

    memset(buf, 'w', sizeof buf);
    SetFilePointer(h, offset, NULL, FILE_BEGIN);
    arm();
    r = WriteFile(h, buf, length, &put, NULL);
    e = le();
    line("  WriteFile(%s, %lu bytes at %lu): ret=%d put %lu err=%s, the pointer at %lu", who, length, offset, r,
         put, e, SetFilePointer(h, 0, NULL, FILE_CURRENT));
}

static void sec_lock(void)
{
    HANDLE h1, h2, dup, ro, none;
    BYTE data[100];
    DWORD i, put;

    lock_file = (lock_file_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LockFile");
    unlock_file = (lock_file_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "UnlockFile");
    line("kernel32 exports LockFile %s, UnlockFile %s", yesno(lock_file != NULL), yesno(unlock_file != NULL));
    if (lock_file == NULL || unlock_file == NULL) {
        return;
    }
    for (i = 0; i < sizeof data; i++) {
        data[i] = (BYTE)('a' + i % 26);
    }
    h1 = open_file("LOCK.DAT", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_ALWAYS);
    WriteFile(h1, data, sizeof data, &put, NULL);
    h2 = open_file("LOCK.DAT", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING);
    line("LOCK.DAT: 100 bytes written %s, two handles open %s", yesno(put == sizeof data),
         yesno(h1 != INVALID_HANDLE_VALUE && h2 != INVALID_HANDLE_VALUE));
    if (h1 == INVALID_HANDLE_VALUE || h2 == INVALID_HANDLE_VALUE) {
        return;
    }

    /* Ranges through one handle: overlapping, the same again, adjacent. */
    try_lock("the first handle", h1, 10, 20);
    try_lock("the first handle", h1, 10, 20);
    try_lock("the first handle", h1, 25, 10);
    try_lock("the first handle", h1, 5, 10);
    try_lock("the first handle", h1, 30, 10);
    try_lock("the first handle", h1, 0, 0);
    try_lock("the first handle", h1, 1000, 10);

    /* The second handle: refused inside the first's ranges, granted outside. */
    try_lock("the second", h2, 15, 1);
    try_lock("the second", h2, 29, 2);
    try_lock("the second", h2, 50, 10);

    /* Reads and writes a lock refuses, and those it lets through. */
    line("I/O through the second handle into the first's range 10-29:");
    try_read("the second", h2, 12, 4);
    try_write("the second", h2, 12, 4);
    try_read("the second", h2, 5, 10);
    try_read("the second", h2, 0, 10);
    try_write("the second", h2, 0, 5);
    line("I/O through the first handle into its own range and the second's 50-59:");
    try_read("the first handle", h1, 12, 4);
    try_write("the first handle", h1, 12, 4);
    try_read("the first handle", h1, 52, 4);
    try_write("the first handle", h1, 52, 4);

    /* A duplicate of the first handle: the same open file. */
    dup = NULL;
    DuplicateHandle(GetCurrentProcess(), h1, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
    line("a duplicate of the first handle:");
    try_read("the duplicate", dup, 12, 4);
    try_lock("the duplicate", dup, 12, 1);
    try_lock("the first handle", h1, 60, 5);
    try_unlock("the duplicate", dup, 60, 5);
    try_read("the second", h2, 61, 2);

    /* Unlocks: the exact range, a range never locked, part of a range,
       the other handle's range. */
    try_unlock("the first handle", h1, 10, 20);
    try_unlock("the first handle", h1, 10, 20);
    try_unlock("the first handle", h1, 30, 5);
    try_unlock("the second", h2, 30, 10);
    try_unlock("the first handle", h1, 70, 5);
    line("I/O through the second handle into 10-29 once unlocked:");
    try_read("the second", h2, 12, 4);
    try_unlock("the first handle", h1, 30, 10);
    try_unlock("the first handle", h1, 0, 0);
    try_unlock("the first handle", h1, 1000, 10);
    try_unlock("the second", h2, 50, 10);

    /* A lock goes with its handle's close. */
    try_lock("the second", h2, 70, 10);
    CloseHandle(h2);
    line("the second handle closed, holding 70-79:");
    try_read("the first handle", h1, 72, 4);
    try_lock("the first handle", h1, 70, 10);
    try_unlock("the first handle", h1, 70, 10);

    /* Handles with less access. */
    ro = open_file("LOCK.DAT", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING);
    line("a read-only handle: open %s", yesno(ro != INVALID_HANDLE_VALUE));
    if (ro != INVALID_HANDLE_VALUE) {
        try_lock("the read-only handle", ro, 0, 10);
        try_write("the first handle", h1, 2, 2);
        try_unlock("the read-only handle", ro, 0, 10);
        CloseHandle(ro);
    }
    none = open_file("LOCK.DAT", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING);
    line("a handle with no access: open %s", yesno(none != INVALID_HANDLE_VALUE));
    if (none != INVALID_HANDLE_VALUE) {
        try_lock("the handle with no access", none, 0, 10);
        try_unlock("the handle with no access", none, 0, 10);
        CloseHandle(none);
    }
    try_lock("INVALID_HANDLE_VALUE", INVALID_HANDLE_VALUE, 0, 10);
    try_unlock("INVALID_HANDLE_VALUE", INVALID_HANDLE_VALUE, 0, 10);
    try_lock("NULL", NULL, 0, 10);

    if (dup != NULL) {
        CloseHandle(dup);
    }
    CloseHandle(h1);
    DeleteFileA(at("LOCK.DAT"));
}

/* --- moveinto ------------------------------------------------------ */

/* MoveFileEx's refusals that must leave both names as they were: a
   directory moved into itself and beneath itself, a replacing move onto a
   file another handle holds open, and one whose source is held open
   without delete sharing; then the plain replacing move, which succeeds.
   Through MoveFileExA or (wide) MoveFileExW; the setup stays A. */
static void moveinto_block(int wide)
{
    const char *tag = wide ? " (W)" : "";
    HANDLE h;

    CreateDirectoryA(at("MD1"), NULL);
    CreateDirectoryA(at("MD1\\SUB"), NULL);
    write_text("MD1\\SUB\\IN.TXT", "inside");
    move_ex(wide, "MD1", L"MD1", "MD1\\MD2", L"MD1\\MD2", 0, "0");
    move_ex(wide, "MD1", L"MD1", "MD1\\SUB\\MD2", L"MD1\\SUB\\MD2", 0, "0");
    line("MD1\\SUB\\IN.TXT after the refusals%s: %s", tag, what_is(wide, "MD1\\SUB\\IN.TXT", L"MD1\\SUB\\IN.TXT"));

    write_text("MA.TXT", "source");
    write_text("MB.TXT", "target!!");
    h = open_file("MB.TXT", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING);
    move_ex(wide, "MA.TXT", L"MA.TXT", "MB.TXT", L"MB.TXT", MOVEFILE_REPLACE_EXISTING,
            "REPLACE_EXISTING, MB.TXT held open sharing all");
    CloseHandle(h);
    h = open_file("MA.TXT", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    move_ex(wide, "MA.TXT", L"MA.TXT", "MB.TXT", L"MB.TXT", MOVEFILE_REPLACE_EXISTING,
            "REPLACE_EXISTING, MA.TXT held open sharing read");
    CloseHandle(h);
    move_ex(wide, "MA.TXT", L"MA.TXT", "MB.TXT", L"MB.TXT", MOVEFILE_REPLACE_EXISTING, "REPLACE_EXISTING");

    left_in(tag, "");
    left_in(tag, "MD1\\");
}

static void sec_moveinto(void)
{
    moveinto_block(0);
    wipe(base);
    moveinto_block(1);
}

/* --- overwrite ----------------------------------------------------- */

/* A second open of O.TXT (twelve bytes, sharing read and write) while a
   first handle holds it: whether a disposition that truncates is checked
   against the first handle's sharing as a write, whatever access it asks
   for. Through CreateFileA or (wide) CreateFileW. */
static void overwrite_case(int wide, const char *label, DWORD a1, DWORD s1, DWORD a2, DWORD disposition)
{
    HANDLE h1, h2;
    const char *e;

    write_text("O.TXT", "twelve bytes");
    h1 = open_file("O.TXT", a1, s1, OPEN_EXISTING);
    arm();
    h2 = wide ? CreateFileW(wat(L"O.TXT"), a2, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, disposition,
                            FILE_ATTRIBUTE_NORMAL, NULL)
              : CreateFileA(at("O.TXT"), a2, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, disposition,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    e = le();
    if (h2 != INVALID_HANDLE_VALUE) {
        CloseHandle(h2);
    }
    CloseHandle(h1);
    line("%s%s: %s err=%s, size now %ld", label, wide ? " (W)" : "",
         h2 == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e, (LONG)size_of(wide, "O.TXT", L"O.TXT"));
}

static void overwrite_block(int wide)
{
    HANDLE h1, h2, m;
    void *v;
    const char *e;

    overwrite_case(wide, "a reader sharing read, then CREATE_ALWAYS for reading", GENERIC_READ, FILE_SHARE_READ,
                   GENERIC_READ, CREATE_ALWAYS);
    overwrite_case(wide, "a reader sharing read and write, then CREATE_ALWAYS for reading", GENERIC_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE, GENERIC_READ, CREATE_ALWAYS);
    overwrite_case(wide, "a reader sharing read, then OPEN_ALWAYS for reading", GENERIC_READ, FILE_SHARE_READ,
                   GENERIC_READ, OPEN_ALWAYS);
    overwrite_case(wide, "a reader sharing read, then CREATE_ALWAYS for writing", GENERIC_READ, FILE_SHARE_READ,
                   GENERIC_WRITE, CREATE_ALWAYS);
    overwrite_case(wide, "a reader sharing read, then TRUNCATE_EXISTING for writing", GENERIC_READ,
                   FILE_SHARE_READ, GENERIC_WRITE, TRUNCATE_EXISTING);

    /* A file with a mapped view: the view outlives its handles. */
    write_text("O.TXT", "twelve bytes");
    h1 = open_file("O.TXT", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING);
    m = CreateFileMappingA(h1, NULL, PAGE_READWRITE, 0, 0, NULL);
    v = m != NULL ? MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    if (m != NULL) {
        CloseHandle(m);
    }
    CloseHandle(h1);
    arm();
    h2 = wide ? CreateFileW(wat(L"O.TXT"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL)
              : CreateFileA(at("O.TXT"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    e = le();
    if (h2 != INVALID_HANDLE_VALUE) {
        CloseHandle(h2);
    }
    if (v != NULL) {
        UnmapViewOfFile(v);
    }
    line("a mapped view, then CREATE_ALWAYS for writing%s: %s err=%s (mapped %s), size now %ld", wide ? " (W)" : "",
         h2 == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e, yesno(v != NULL),
         (LONG)size_of(wide, "O.TXT", L"O.TXT"));
    DeleteFileA(at("O.TXT"));
}

static void sec_overwrite(void)
{
    overwrite_block(0);
    overwrite_block(1);
}

/* --- overlap ------------------------------------------------------- */

/* GetOverlappedResult is reached through GetProcAddress: the program
   loads where kernel32 lacks it, its other sections intact. */
typedef BOOL (WINAPI *overlapped_result_fn)(HANDLE file, LPOVERLAPPED overlapped, LPDWORD bytes, BOOL wait);

static overlapped_result_fn overlapped_result;

static void set_ov(OVERLAPPED *ov, DWORD low, DWORD high, HANDLE ev)
{
    memset(ov, 0, sizeof *ov);
    ov->Offset = low;
    ov->OffsetHigh = high;
    ov->hEvent = ev;
}

/* An overlapped ReadFile (or, `write`, WriteFile) seen to its end. Whether
   the call completes at once or answers ERROR_IO_PENDING is the machine's
   timing, so it prints as one verdict; the end is the same either way: a
   failure at once with any other error prints that error, otherwise
   GetOverlappedResult (waiting) gives the return, the bytes and the
   error. Then whether the event (or, with none, the file) is signaled. */
static void ov_io(const char *label, int write, HANDLE h, BYTE *buf, DWORD n, OVERLAPPED *ov)
{
    DWORD done = 0, got = 0, err;
    BOOL r;
    const char *e;

    SetLastError(F2KT_UNTOUCHED);
    r = write ? WriteFile(h, buf, n, &done, ov) : ReadFile(h, buf, n, &done, ov);
    err = GetLastError();
    if (!r && err != ERROR_IO_PENDING) {
        line("%s: ret=0 bytes 0 err=%s", label, le_of(err));
        return;
    }
    arm();
    r = overlapped_result(h, ov, &got, TRUE);
    e = le();
    line("%s: ret=%d bytes %lu err=%s, signaled %s", label, r, got, e,
         yesno(WaitForSingleObject(ov->hEvent != NULL ? ov->hEvent : h, 0) == WAIT_OBJECT_0));
}

static int zeros(const BYTE *p, DWORD n)
{
    DWORD i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void sec_overlap(void)
{
    HANDLE h, ev, evs[4];
    OVERLAPPED ov, ovs[4];
    DWORD i, got, w;
    BOOL r;
    const char *e;
    int ok;

    overlapped_result = (overlapped_result_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                                             "GetOverlappedResult");
    line("kernel32 exports GetOverlappedResult: %s", yesno(overlapped_result != NULL));
    if (overlapped_result == NULL) {
        return;
    }
    for (i = 0; i < 10100; i++) {
        wbuf[i] = pattern(i);
    }
    arm();
    h = CreateFileA(at("OV.BIN"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    line("CreateFileA(FILE_FLAG_OVERLAPPED): %s err=%s", h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened",
         le());
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    ev = CreateEventA(NULL, TRUE, FALSE, NULL);

    set_ov(&ov, 0, 0, ev);
    ov_io("WriteFile 8192 bytes at 0, an event", 1, h, wbuf, 8192, &ov);
    set_ov(&ov, 10000, 0, ev);
    ov_io("WriteFile 100 bytes at 10000, past the end", 1, h, wbuf + 10000, 100, &ov);
    line("GetFileSize: %lu", GetFileSize(h, NULL));

    set_ov(&ov, 4096, 0, ev);
    memset(rbuf, 0xEE, 1000);
    ov_io("ReadFile 1000 bytes at 4096, an event", 0, h, rbuf, 1000, &ov);
    line("the bytes read match: %s", yesno(memcmp(rbuf, wbuf + 4096, 1000) == 0));
    set_ov(&ov, 4096, 0, NULL);
    memset(rbuf, 0xEE, 1000);
    ov_io("ReadFile 1000 bytes at 4096, no event", 0, h, rbuf, 1000, &ov);
    line("the bytes read match: %s", yesno(memcmp(rbuf, wbuf + 4096, 1000) == 0));
    set_ov(&ov, 8192, 0, ev);
    memset(rbuf, 0xEE, 1808);
    ov_io("ReadFile 1808 bytes at 8192, the gap", 0, h, rbuf, 1808, &ov);
    line("the gap reads as zeros: %s", yesno(zeros(rbuf, 1808)));
    set_ov(&ov, 10050, 0, ev);
    ov_io("ReadFile 100 bytes at 10050, across the end", 0, h, rbuf, 100, &ov);
    set_ov(&ov, 10100, 0, ev);
    ov_io("ReadFile 100 bytes at 10100, at the end", 0, h, rbuf, 100, &ov);
    set_ov(&ov, 20000, 0, ev);
    ov_io("ReadFile 100 bytes at 20000, past the end", 0, h, rbuf, 100, &ov);
    set_ov(&ov, 0, 1, ev);
    ov_io("ReadFile 100 bytes at 4 GiB", 0, h, rbuf, 100, &ov);

    /* Four reads in flight at once, each with its own event. */
    ok = 1;
    for (i = 0; i < 4; i++) {
        evs[i] = CreateEventA(NULL, TRUE, FALSE, NULL);
        set_ov(&ovs[i], i * 2048, 0, evs[i]);
        if (!ReadFile(h, rbuf + i * 2048, 2048, &got, &ovs[i]) && GetLastError() != ERROR_IO_PENDING) {
            ok = 0;
        }
    }
    w = WaitForMultipleObjects(4, evs, TRUE, WAIT_MS);
    for (i = 0; i < 4; i++) {
        got = 0;
        if (!overlapped_result(h, &ovs[i], &got, TRUE) || got != 2048) {
            ok = 0;
        }
        CloseHandle(evs[i]);
    }
    line("four 2048-byte reads in flight: wait %s, each done with its bytes %s, the data matches %s", wr(w),
         yesno(ok), yesno(memcmp(rbuf, wbuf, 8192) == 0));

    /* GetOverlappedResult without waiting, on a finished request and on
       one still marked pending (STATUS_PENDING in Internal). */
    set_ov(&ov, 0, 0, ev);
    ov_io("ReadFile 16 bytes at 0", 0, h, rbuf, 16, &ov);
    got = 0;
    arm();
    r = overlapped_result(h, &ov, &got, FALSE);
    e = le();
    line("GetOverlappedResult(no wait) once done: ret=%d bytes %lu err=%s", r, got, e);
    set_ov(&ov, 0, 0, ev);
    ov.Internal = 0x103;
    got = 0;
    arm();
    r = overlapped_result(h, &ov, &got, FALSE);
    e = le();
    line("GetOverlappedResult(no wait) still pending: ret=%d err=%s", r, e);

    line("the file pointer after the overlapped I/O: %lu", SetFilePointer(h, 0, NULL, FILE_CURRENT));
    got = 12345;
    arm();
    r = ReadFile(h, rbuf, 100, &got, NULL);
    e = le();
    line("ReadFile with no OVERLAPPED on the overlapped handle: ret=%d bytes %lu err=%s", r, got, e);
    got = 12345;
    arm();
    r = WriteFile(h, wbuf, 100, &got, NULL);
    e = le();
    line("WriteFile with no OVERLAPPED on the overlapped handle: ret=%d bytes %lu err=%s, size %lu", r, got, e,
         GetFileSize(h, NULL));
    CloseHandle(h);

    /* An OVERLAPPED on a handle opened without the flag: done at once. */
    h = open_file("OV.BIN", GENERIC_READ, 0, OPEN_EXISTING);
    ResetEvent(ev);
    set_ov(&ov, 4096, 0, ev);
    memset(rbuf, 0xEE, 1000);
    got = 0;
    arm();
    r = ReadFile(h, rbuf, 1000, &got, &ov);
    e = le();
    line("ReadFile 1000 bytes at 4096 through an OVERLAPPED, a plain handle: ret=%d bytes %lu err=%s, match %s",
         r, got, e, yesno(memcmp(rbuf, wbuf + 4096, 1000) == 0));
    line("then the event signaled %s, the file pointer %lu", yesno(WaitForSingleObject(ev, 0) == WAIT_OBJECT_0),
         SetFilePointer(h, 0, NULL, FILE_CURRENT));
    got = 0;
    arm();
    r = overlapped_result(h, &ov, &got, FALSE);
    e = le();
    line("GetOverlappedResult(no wait) on it: ret=%d bytes %lu err=%s", r, got, e);
    CloseHandle(h);
    CloseHandle(ev);
    DeleteFileA(at("OV.BIN"));
}

/* --- negoff -------------------------------------------------------- */

/* ReadFile (or, `write`, WriteFile) of 4 bytes through an OVERLAPPED
   whose offset is high:low, on a plain handle whose file pointer is at
   100: the return, the bytes, the error, then the file's size and the
   pointer. The pointer goes back to 100 after. */
static void neg_io(const char *label, int write, HANDLE h, DWORD low, DWORD high)
{
    OVERLAPPED ov;
    DWORD n = 12345;
    BOOL r;
    const char *e;

    memset(&ov, 0, sizeof ov);
    ov.Offset = low;
    ov.OffsetHigh = high;
    arm();
    r = write ? WriteFile(h, "abcd", 4, &n, &ov) : ReadFile(h, rbuf, 4, &n, &ov);
    e = le();
    line("%s at %s (%08lX:%08lX): ret=%d bytes %lu err=%s, size %lu, pointer %lu", write ? "WriteFile" : "ReadFile",
         label, high, low, r, n, e, GetFileSize(h, NULL), SetFilePointer(h, 0, NULL, FILE_CURRENT));
    SetFilePointer(h, 100, NULL, FILE_BEGIN);
}

static void sec_negoff(void)
{
    HANDLE h;
    DWORD put;
    int write;

    for (put = 0; put < 1000; put++) {
        wbuf[put] = pattern(put);
    }
    h = open_file("NEG.BIN", GENERIC_READ | GENERIC_WRITE, 0, CREATE_ALWAYS);
    WriteFile(h, wbuf, 1000, &put, NULL);
    SetFilePointer(h, 100, NULL, FILE_BEGIN);
    for (write = 0; write < 2; write++) {
        neg_io("-1", write, h, 0xFFFFFFFF, 0xFFFFFFFF);
        neg_io("-2", write, h, 0xFFFFFFFE, 0xFFFFFFFF);
        neg_io("-16", write, h, 0xFFFFFFF0, 0xFFFFFFFF);
        neg_io("the most negative", write, h, 0, 0x80000000);
        neg_io("200 (sanity)", write, h, 200, 0);
    }
    CloseHandle(h);
    DeleteFileA(at("NEG.BIN"));
}

/* --- deep ---------------------------------------------------------- */

#define DEEP_LEVELS 8

/* One 40-character directory name, a level of the deep tree. */
static const WCHAR deep_segment[] = L"\\D012345678901234567890123456789012345678";

/* \\?\ and SCRATCH\DEEP followed by `levels` levels, into `out`. */
static WCHAR *deep_path(WCHAR *out, int levels)
{
    int i;

    wcscpy(out, L"\\\\?\\");
    wcscat(out, wbase);
    wcscat(out, L"DEEP");
    for (i = 0; i < levels; i++) {
        wcscat(out, deep_segment);
    }
    return out;
}

/* The deep tree removed, deepest first, without printing; the number of
   directories removed. */
static int deep_remove(void)
{
    WCHAR path[1024];
    int removed = 0;
    int i;

    deep_path(path, DEEP_LEVELS);
    wcscat(path, L"\\F.TXT");
    DeleteFileW(path);
    for (i = DEEP_LEVELS; i >= 0; i--) {
        if (RemoveDirectoryW(deep_path(path, i))) {
            removed++;
        }
    }
    return removed;
}

static void sec_deep(void)
{
    WCHAR path[1024];
    char apath[1024];
    BYTE got[8];
    HANDLE h;
    DWORD n, a, first_err = 0;
    int i, made = 0;
    BOOL r;
    const char *e;

    deep_remove();
    for (i = 0; i <= DEEP_LEVELS; i++) {
        if (CreateDirectoryW(deep_path(path, i), NULL)) {
            made++;
        } else if (first_err == 0) {
            first_err = GetLastError();
        }
    }
    line("CreateDirectoryW through \\\\?\\, nine levels: made %d, first err=%lu, the deepest past MAX_PATH %s", made,
         first_err, yesno(wcslen(path) - 4 > MAX_PATH));
    wcscat(path, L"\\F.TXT");
    WideCharToMultiByte(CP_ACP, 0, path, -1, apath, sizeof apath, NULL, NULL);

    arm();
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    e = le();
    line("CreateFileW(\\\\?\\ deep file, CREATE_NEW): %s err=%s", h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened",
         e);
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, "deep!", 5, &n, NULL);
        CloseHandle(h);
    }
    arm();
    a = GetFileAttributesW(path);
    line("GetFileAttributesW(\\\\?\\ deep file): 0x%08lX err=%s", a, le());
    arm();
    h = CreateFileW(path + 4, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    e = le();
    line("CreateFileW(the same path without \\\\?\\): %s err=%s",
         h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    arm();
    h = CreateFileA(apath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    e = le();
    line("CreateFileA(\\\\?\\ deep file): %s err=%s", h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    arm();
    a = GetFileAttributesA(apath);
    line("GetFileAttributesA(\\\\?\\ deep file): 0x%08lX err=%s", a, le());

    arm();
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    e = le();
    n = 0;
    if (h != INVALID_HANDLE_VALUE) {
        ReadFile(h, got, sizeof got, &n, NULL);
        CloseHandle(h);
    }
    line("CreateFileW(\\\\?\\ deep file, OPEN_EXISTING): %s err=%s, read %lu bytes, match %s",
         h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e, n, yesno(n == 5 && memcmp(got, "deep!", 5) == 0));
    arm();
    r = DeleteFileW(path);
    line("DeleteFileW(\\\\?\\ deep file): ret=%d err=%s", r, le());
    line("RemoveDirectoryW, deepest first: removed %d", deep_remove());
}

static const section_t sections[] = {
    { "create", sec_create, 0 },
    { "write", sec_write, 0 },
    { "share", sec_share, 0 },
    { "names", sec_names, 0 },
    { "dirs", sec_dirs, 0 },
    { "times", sec_times, 0 },
    { "crt", sec_crt, 0 },
    { "movex", sec_movex, 0 },
    { "lock", sec_lock, 0 },
    { "moveinto", sec_moveinto, 0 },
    { "overwrite", sec_overwrite, 0 },
    { "overlap", sec_overlap, 0 },
    { "negoff", sec_negoff, 0 },
    { "deep", sec_deep, 0 },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    init_scratch();
    return run_sections("fswrite", sections, argc, argv);
}
