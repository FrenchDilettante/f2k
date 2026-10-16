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
 *            read-only files, a created long file name and its short name
 *   dirs     CreateDirectoryA/RemoveDirectoryA and their errors, a
 *            directory grown to 100 entries (spanning clusters)
 *   times    SetFileTime/GetFileTime round trip at a two-second boundary
 *   crt      fopen "w"/"a"/"r+" with text-mode translation, fwrite,
 *            remove, rename
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo fswrite.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static char base[MAX_PATH];         /* SCRATCH\ under the image's directory */

static const char *at(const char *rel)
{
    static char bufs[4][2 * MAX_PATH];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s%s", base, rel);
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
    wipe(base);
}

static HANDLE open_file(const char *rel, DWORD access, DWORD share, DWORD disposition)
{
    return CreateFileA(at(rel), access, share, NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void try_create(const char *label, const char *rel, DWORD access, DWORD disposition)
{
    HANDLE h;
    const char *e;

    arm();
    h = open_file(rel, access, 0, disposition);
    e = le();
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    line("%s: %s err=%s, size now %ld", label, h == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", e,
         (LONG)file_size(rel));
}

static void write_text(const char *rel, const char *text)
{
    HANDLE h = open_file(rel, GENERIC_WRITE, 0, CREATE_ALWAYS);
    DWORD put;

    WriteFile(h, text, strlen(text), &put, NULL);
    CloseHandle(h);
}

/* --- create -------------------------------------------------------- */

static void sec_create(void)
{
    try_create("CREATE_NEW, new", "A.TXT", GENERIC_WRITE, CREATE_NEW);
    try_create("CREATE_NEW, existing", "A.TXT", GENERIC_WRITE, CREATE_NEW);
    write_text("A.TXT", "twelve bytes");
    try_create("CREATE_ALWAYS, existing", "A.TXT", GENERIC_WRITE, CREATE_ALWAYS);
    try_create("CREATE_ALWAYS, new", "B.TXT", GENERIC_WRITE, CREATE_ALWAYS);
    write_text("A.TXT", "twelve bytes");
    try_create("OPEN_ALWAYS, existing", "A.TXT", GENERIC_READ, OPEN_ALWAYS);
    try_create("OPEN_ALWAYS, new", "C.TXT", GENERIC_READ, OPEN_ALWAYS);
    try_create("TRUNCATE_EXISTING", "A.TXT", GENERIC_WRITE, TRUNCATE_EXISTING);
    try_create("TRUNCATE_EXISTING without write access", "A.TXT", GENERIC_READ, TRUNCATE_EXISTING);
    try_create("TRUNCATE_EXISTING, missing", "NOSUCH.TXT", GENERIC_WRITE, TRUNCATE_EXISTING);
    try_create("OPEN_EXISTING, missing", "NOSUCH.TXT", GENERIC_WRITE, OPEN_EXISTING);
    try_create("CREATE_NEW in a missing directory", "NODIR\\A.TXT", GENERIC_WRITE, CREATE_NEW);
    try_create("a bad disposition", "D.TXT", GENERIC_WRITE, 9);
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

static void share_case(const char *label, DWORD a1, DWORD s1, DWORD a2, DWORD s2)
{
    HANDLE h1, h2;

    write_text("S.TXT", "share");
    h1 = open_file("S.TXT", a1, s1, OPEN_EXISTING);
    arm();
    h2 = open_file("S.TXT", a2, s2, OPEN_EXISTING);
    line("%s: %s err=%s", label, h2 == INVALID_HANDLE_VALUE ? "INVALID_HANDLE_VALUE" : "opened", le());
    if (h2 != INVALID_HANDLE_VALUE) {
        CloseHandle(h2);
    }
    CloseHandle(h1);
}

static void sec_share(void)
{
    HANDLE h;
    const char *e;
    DWORD a;
    BOOL r;

    share_case("writer sharing read, then a second writer", GENERIC_WRITE, FILE_SHARE_READ, GENERIC_WRITE,
               FILE_SHARE_READ | FILE_SHARE_WRITE);
    share_case("writer sharing read, then a reader", GENERIC_WRITE, FILE_SHARE_READ, GENERIC_READ,
               FILE_SHARE_READ | FILE_SHARE_WRITE);
    share_case("reader sharing read, then a reader not sharing write", GENERIC_READ, FILE_SHARE_READ, GENERIC_READ,
               FILE_SHARE_READ);
    share_case("reader sharing read and write, then a writer", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
               GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);

    write_text("S.TXT", "share");
    h = open_file("S.TXT", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    arm();
    r = DeleteFileA(at("S.TXT"));
    line("DeleteFileA of an open file: ret=%d err=%s", r, le());
    CloseHandle(h);
    arm();
    r = DeleteFileA(at("S.TXT"));
    line("DeleteFileA after closing: ret=%d err=%s", r, le());

    arm();
    h = CreateFileA(at("T.TMP"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    e = le();
    line("FILE_FLAG_DELETE_ON_CLOSE: created %s err=%s, exists while open %s", yesno(h != INVALID_HANDLE_VALUE),
         e, yesno(GetFileAttributesA(at("T.TMP")) != INVALID_FILE_ATTRIBUTES));
    CloseHandle(h);
    arm();
    a = GetFileAttributesA(at("T.TMP"));
    line("after close: attributes 0x%08lX err=%s", a, le());
}

/* --- names --------------------------------------------------------- */

static void sec_names(void)
{
    char buf[MAX_PATH];
    const char *e;
    char *p;
    DWORD n;
    BOOL r;

    write_text("M1.TXT", "move me");
    arm();
    r = MoveFileA(at("M1.TXT"), at("M2.TXT"));
    e = le();
    line("MoveFileA rename: ret=%d err=%s, old gone %s, new size %lu", r, e,
         yesno(GetFileAttributesA(at("M1.TXT")) == INVALID_FILE_ATTRIBUTES), file_size("M2.TXT"));
    write_text("M3.TXT", "other");
    arm();
    r = MoveFileA(at("M2.TXT"), at("M3.TXT"));
    line("MoveFileA onto an existing file: ret=%d err=%s", r, le());
    CreateDirectoryA(at("MD"), NULL);
    arm();
    r = MoveFileA(at("M2.TXT"), at("MD\\M2.TXT"));
    line("MoveFileA into a subdirectory: ret=%d err=%s", r, le());
    arm();
    r = MoveFileA(at("NOSUCH.TXT"), at("X.TXT"));
    line("MoveFileA of a missing file: ret=%d err=%s", r, le());

    arm();
    r = CopyFileA(at("M3.TXT"), at("C1.TXT"), TRUE);
    e = le();
    line("CopyFileA: ret=%d err=%s, size %lu", r, e, file_size("C1.TXT"));
    arm();
    r = CopyFileA(at("M3.TXT"), at("C1.TXT"), TRUE);
    line("CopyFileA onto an existing file, failing if it exists: ret=%d err=%s", r, le());
    arm();
    r = CopyFileA(at("MD\\M2.TXT"), at("C1.TXT"), FALSE);
    e = le();
    line("CopyFileA overwriting: ret=%d err=%s, size %lu", r, e, file_size("C1.TXT"));

    arm();
    r = DeleteFileA(at("NOSUCH.TXT"));
    line("DeleteFileA(missing): ret=%d err=%s", r, le());
    arm();
    r = DeleteFileA(at("MD"));
    line("DeleteFileA(a directory): ret=%d err=%s", r, le());
    SetFileAttributesA(at("C1.TXT"), FILE_ATTRIBUTE_READONLY);
    line("read-only attribute set: 0x%08lX", GetFileAttributesA(at("C1.TXT")));
    arm();
    r = DeleteFileA(at("C1.TXT"));
    line("DeleteFileA(read-only): ret=%d err=%s", r, le());
    SetFileAttributesA(at("C1.TXT"), FILE_ATTRIBUTE_NORMAL);
    arm();
    r = DeleteFileA(at("C1.TXT"));
    line("after clearing it: ret=%d err=%s", r, le());

    write_text("A Long Created Name.txt", "long");
    arm();
    n = GetShortPathNameA(at("A Long Created Name.txt"), buf, sizeof buf);
    e = le();
    p = strrchr(buf, '\\');
    line("created a long name: size %lu, short name [%s] err=%s", file_size("A Long Created Name.txt"),
         n != 0 ? (p != NULL ? p + 1 : buf) : "", e);
    line("opened by its short name: size %lu", file_size("ALONGC~1.TXT"));
}

/* --- dirs ---------------------------------------------------------- */

static void sec_dirs(void)
{
    char name[32];
    WIN32_FIND_DATAA fd;
    HANDLE f;
    const char *e;
    BOOL r;
    int i, count, ok;

    arm();
    r = CreateDirectoryA(at("D1"), NULL);
    e = le();
    line("CreateDirectoryA: ret=%d err=%s, attributes 0x%08lX", r, e, GetFileAttributesA(at("D1")));
    arm();
    r = CreateDirectoryA(at("D1"), NULL);
    line("CreateDirectoryA again: ret=%d err=%s", r, le());
    arm();
    r = CreateDirectoryA(at("NODIR\\D2"), NULL);
    line("CreateDirectoryA under a missing parent: ret=%d err=%s", r, le());
    write_text("D1\\F.TXT", "in a directory");
    arm();
    r = RemoveDirectoryA(at("D1"));
    line("RemoveDirectoryA(not empty): ret=%d err=%s", r, le());
    DeleteFileA(at("D1\\F.TXT"));
    arm();
    r = RemoveDirectoryA(at("D1"));
    line("RemoveDirectoryA(empty): ret=%d err=%s", r, le());
    arm();
    r = RemoveDirectoryA(at("D1"));
    line("RemoveDirectoryA(missing): ret=%d err=%s", r, le());
    write_text("NOTADIR.TXT", "x");
    arm();
    r = RemoveDirectoryA(at("NOTADIR.TXT"));
    line("RemoveDirectoryA(a file): ret=%d err=%s", r, le());

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
    f = fopen(at("CRT.TXT"), "a");
    fprintf(f, "%d\n", 3);
    fclose(f);
    line("append: %lu bytes", file_size("CRT.TXT"));
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
    r = rename(at("CRT.BIN"), at("CRT2.BIN"));
    line("rename: %d, size under the new name %lu", r, file_size("CRT2.BIN"));
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
