/*
 * pipe - anonymous pipes: CreatePipe's two ends, I/O through them,
 * PeekNamedPipe and the file-system control beneath it, what closing an
 * end does to the other, waits for data and for room, pipes as a child's
 * standard handles, and the C runtime's _pipe, _popen, _pclose and
 * system().
 *
 * The children are pipekid.exe, the companion program built beside this
 * one, which does what its first argument says (pipekid.c lists its
 * modes). A child this program starts itself has pipes for its standard
 * handles (one section gives one a file), and the program reads what
 * comes out of them and prints it ("  > ..."), so every line's place is
 * fixed. The children of _popen for writing and of system() print
 * through the standard output they inherit instead, while this program
 * waits in _pclose or system() and prints nothing. No child prints an
 * absolute path: the program sets F2KHOME to its own directory, and
 * pipekid prints paths relative to it.
 *
 * No wait is unbounded. A thread whose call should wait gets 200 to
 * 500 ms to show it, then is woken (or ended); every other wait is
 * bounded at 5 s, and a child that outlives it is ended (its exit code
 * then 57005). A read the program makes itself is made only once data is
 * there or every write end is gone. No call is made on a handle another
 * thread is blocked in: Windows 2000 serializes a synchronous handle's
 * calls, so it would wait behind the blocked one.
 *
 * Files go in SCRATCH, a directory beside the program, which the
 * sections that use it empty first (as spawn's).
 *
 * Sections (run all with no argument, or one by name):
 *
 *   create   CreatePipe with sizes 0, 1, 4096 and 65536, and for each how
 *            many 1-byte writes a thread makes before one waits (and
 *            PeekNamedPipe's total then); GetFileType and
 *            GetHandleInformation of both ends, inheritable, not, and
 *            with no attributes; each end's attributes, granted access
 *            and handle count (NtQueryObject's basic information) and its
 *            name, each component made of hexadecimal digits printed as
 *            its length alone, so no process id or counter prints;
 *            ReadFile on the write end and WriteFile on the read end;
 *            GetFileSize (empty, and holding 5 bytes), SetFilePointer,
 *            GetFileInformationByHandle; FlushFileBuffers with nothing
 *            buffered
 *   io       a write and a read; a read shorter than the data; three
 *            writes read as one; zero-byte writes and reads (one on the
 *            empty pipe, in a thread); PeekNamedPipe with no buffer, a
 *            short one, a long one, no counts, over two writes, on the
 *            empty pipe
 *   peek     NtFsControlFile with the pipe-peek code (FSCTL_PIPE_PEEK,
 *            which never prints: only a real peek gives this output) on
 *            a pipe holding 13 distinctive bytes, into a buffer filled
 *            with 0xCC first: the status, the header's count, the 13
 *            bytes after the header, the I/O status's Information
 *            against the header plus 13, the bytes past them untouched;
 *            ReadFile then gets the same 13 bytes; the call on the empty
 *            pipe; PeekNamedPipe on 13 fresh bytes against the direct
 *            call's answers; the call on the write end (which lacks
 *            FILE_READ_DATA), and into buffers shorter than the header
 *            and as long as it
 *   ends     the write end closed with data left (the data, then the
 *            error, PeekNamedPipe before and after the data is read) and
 *            with nothing left; a duplicated write handle keeping the
 *            pipe open, a read waiting until it is closed; the read end
 *            closed: WriteFile's error, a zero-byte write,
 *            FlushFileBuffers and PeekNamedPipe on the write end
 *   block    a read waiting on the empty pipe, woken by a write; a
 *            10000-byte write into a 4096-byte pipe waiting
 *            (PeekNamedPipe's total meanwhile), still waiting after a
 *            1000-byte read, done once the rest is read; a waiting read
 *            ended by closing the write end; a waiting reader terminated,
 *            the pipe still usable; a waiting writer terminated (what the
 *            pipe keeps of its data); a waiting write ended by closing
 *            the read end
 *   child    a child's standard output as the pipe, read until the
 *            error; a child's standard input as the pipe (count, upper);
 *            two and three children joined by pipes, the program only
 *            plumbing (cmd.exe's a | b); each child's view of its
 *            handles (types), given in STARTUPINFO, and through
 *            SetStdHandle with none given; a reader child that ends
 *            before the program writes; a writer child whose reader
 *            closes its end (its write fails, the error its exit code)
 *   crt      _pipe in text mode (the descriptors, the handles'
 *            inheritance), _write's LF as the pipe holds it, _read's
 *            CR LF, a CR at the end of a read followed by LF, by another
 *            byte, by the end of the file; the end reading as 0; a
 *            Ctrl+Z in text mode; _pipe in binary mode, with and without
 *            _O_NOINHERIT: _write and _read unchanged, the end reading
 *            as 0, _write once the read end is closed
 *   popen    COMSPEC pointed at pipekid.exe, whose /c mode is a stand-in
 *            command processor that prints its command line first ("/c:
 *            command line [...]"), so the output shows whether _popen
 *            and system() ran it, and the command line msvcrt built:
 *            _popen with "r" and fgets, "w" and fputs, the t and b
 *            modes, _pclose's status, _pclose on a stream fopen opened,
 *            a bad mode; system(NULL), system() of a command's exit code
 *            and of one that prints. msvcrt's _popen moves the standard
 *            output while it starts the child (it hands fd 1 to the pipe
 *            and back), so the section prints through a private duplicate
 *            of the handle it started with, which msvcrt never sees, and
 *            each _popen prints whether the standard output handle it
 *            leaves is still the one the program started with
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat pipe):
 *   cl /nologo /MD pipekid.c
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% pipe.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>

/* ntdll's exports no import library declares, reached through
 * GetProcAddress, and their structures as the public headers declare
 * them (MSVC 6's headers have none of them). */

/* IO_STATUS_BLOCK (ntddk.h, winternl.h): the status, then the count. */
typedef struct {
    LONG Status;
    ULONG Information;
} io_status_t;

/* FILE_PIPE_PEEK_BUFFER (ntifs.h): four ULONGs, then the data. */
typedef struct {
    ULONG NamedPipeState;
    ULONG ReadDataAvailable;
    ULONG NumberOfMessages;
    ULONG MessageLength;
} peek_header_t;

#define HEADER ((ULONG)sizeof(peek_header_t))

/* PUBLIC_OBJECT_BASIC_INFORMATION (winternl.h), NtQueryObject's class 0
 * (ObjectBasicInformation): 56 bytes. */
typedef struct {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} object_basic_t;

/* UNICODE_STRING (winternl.h). OBJECT_NAME_INFORMATION (ntifs.h),
 * NtQueryObject's class 1 (ObjectNameInformation), is one, its buffer
 * after it. */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} ustring_t;

#define OBJECT_BASIC 0
#define OBJECT_NAME 1

/* FSCTL_PIPE_PEEK (ntifs.h): CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3,
 * METHOD_BUFFERED, FILE_READ_DATA). Never printed. */
#define PIPE_PEEK 0x0011400Cu

/* NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext,
 * IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength,
 * OutputBuffer, OutputBufferLength). */
typedef LONG (WINAPI *fs_control_fn)(HANDLE, HANDLE, PVOID, PVOID, io_status_t *, ULONG, PVOID, ULONG,
                                     PVOID, ULONG);
/* NtQueryObject(Handle, ObjectInformationClass, ObjectInformation,
 * ObjectInformationLength, ReturnLength). */
typedef LONG (WINAPI *query_object_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static char home[MAX_PATH];         /* the program's directory, no trailing backslash */
static char kid[MAX_PATH];          /* home\pipekid.exe */
static fs_control_fn fs_control;    /* NtFsControlFile */
static query_object_fn query_object; /* NtQueryObject */

/* --- helpers ------------------------------------------------------- */

/* A path under the program's directory. */
static const char *at(const char *rel)
{
    static char bufs[4][2 * MAX_PATH];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s\\%s", home, rel);
    return b;
}

/* Empty a directory (`dir` ends in a backslash) without printing. */
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

/* A section's start: the current directory the program's, SCRATCH there
 * and empty. */
static void reset(void)
{
    SetCurrentDirectoryA(home);
    CreateDirectoryA(at("SCRATCH"), NULL);
    wipe(at("SCRATCH\\"));
}

/* A count as printed: "-" while it holds the sentinel. */
static const char *num(DWORD v)
{
    static char bufs[8][16];
    static int next;
    char *b = bufs[next++ & 7];

    if (v == F2KT_UNTOUCHED) {
        return "-";
    }
    sprintf(b, "%lu", v);
    return b;
}

/* An exit code as printed: an NTSTATUS-like one in hex. */
static const char *code_text(DWORD code)
{
    static char bufs[4][16];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, code >= 0x80000000u ? "0x%08lX" : "%lu", code);
    return b;
}

/* Bytes as printed: printable ASCII as it is, CR and LF as \r and \n,
 * any other byte as \xNN. */
static const char *esc(const void *data, int n)
{
    static char bufs[4][600];
    static int next;
    char *b = bufs[next++ & 3];
    const BYTE *p = (const BYTE *)data;
    int i, k = 0;

    for (i = 0; i < n && k < (int)sizeof bufs[0] - 8; i++) {
        if (p[i] == '\r') {
            b[k++] = '\\';
            b[k++] = 'r';
        } else if (p[i] == '\n') {
            b[k++] = '\\';
            b[k++] = 'n';
        } else if (p[i] < 0x20 || p[i] >= 0x7F) {
            k += sprintf(b + k, "\\x%02X", p[i]);
        } else {
            b[k++] = (char)p[i];
        }
    }
    b[k] = 0;
    return b;
}

static const char *flags_of(HANDLE h)
{
    static char bufs[4][32];
    static int next;
    char *b = bufs[next++ & 3];
    DWORD flags = F2KT_UNTOUCHED;

    arm();
    if (GetHandleInformation(h, &flags)) {
        sprintf(b, "flags 0x%lX", flags);
    } else {
        sprintf(b, "flags: ret=0 err=%s", le());
    }
    return b;
}

static void closed(const char *label, HANDLE h)
{
    BOOL r;
    char err[16];

    arm();
    r = CloseHandle(h);
    strcpy(err, le());
    line("CloseHandle(%s): ret=%d err=%s", label, r, err);
}

/* WriteFile of `len` bytes, printed. */
static void put(HANDLE h, const char *text, DWORD len)
{
    DWORD n = F2KT_UNTOUCHED;
    BOOL r;
    char err[16];

    arm();
    r = WriteFile(h, text, len, &n, NULL);
    strcpy(err, le());
    line("WriteFile [%s], %lu bytes: ret=%d n=%s err=%s", esc(text, (int)len), len, r, num(n), err);
}

/* ReadFile of up to `len` bytes (64 at most), printed with what it read.
 * Called only where it cannot wait: data is there, or every write end is
 * closed. */
static void get(HANDLE h, DWORD len)
{
    BYTE buf[64];
    DWORD n = F2KT_UNTOUCHED;
    BOOL r;
    char err[16];

    arm();
    r = ReadFile(h, buf, len, &n, NULL);
    strcpy(err, le());
    if (r && n <= sizeof buf) {
        line("ReadFile %lu: ret=%d n=%lu err=%s [%s]", len, r, n, err, esc(buf, (int)n));
    } else {
        line("ReadFile %lu: ret=%d n=%s err=%s", len, r, num(n), err);
    }
}

/* What show_peek passes: the buffer, and which counts. */
#define PEEK_BUF 1
#define PEEK_READ 2
#define PEEK_TOTAL 4
#define PEEK_LEFT 8
#define PEEK_COUNTS (PEEK_READ | PEEK_TOTAL | PEEK_LEFT)
#define PEEK_ALL (PEEK_BUF | PEEK_COUNTS)

/* PeekNamedPipe with a buffer of `size` bytes (64 at most) or none, and
 * the counts `what` asks for, printed with what it copied. */
static void show_peek(const char *label, HANDLE h, DWORD size, int what)
{
    BYTE buf[64];
    DWORD rd = F2KT_UNTOUCHED, total = F2KT_UNTOUCHED, left = F2KT_UNTOUCHED;
    BOOL r;
    char err[16];

    memset(buf, 0xCC, sizeof buf);
    arm();
    r = PeekNamedPipe(h, (what & PEEK_BUF) ? buf : NULL, size, (what & PEEK_READ) ? &rd : NULL,
                      (what & PEEK_TOTAL) ? &total : NULL, (what & PEEK_LEFT) ? &left : NULL);
    strcpy(err, le());
    if (r && (what & PEEK_BUF) && rd <= sizeof buf) {
        line("PeekNamedPipe(%s): ret=%d err=%s; read %lu, total %s, left %s [%s]", label, r, err, rd,
             num(total), num(left), esc(buf, (int)rd));
    } else if (r && (what & PEEK_BUF)) {
        line("PeekNamedPipe(%s): ret=%d err=%s; read %s, total %s, left %s; the buffer's first 10 bytes [%s]",
             label, r, err, num(rd), num(total), num(left), esc(buf, 10));
    } else {
        line("PeekNamedPipe(%s): ret=%d err=%s; read %s, total %s, left %s", label, r, err, num(rd),
             num(total), num(left));
    }
}

/* PeekNamedPipe's total, unprinted (0 when it fails). */
static DWORD available(HANDLE h)
{
    DWORD total = 0;

    if (!PeekNamedPipe(h, NULL, 0, NULL, &total, NULL)) {
        return 0;
    }
    return total;
}

/* Read what the pipe holds, never waiting: until it is empty and
 * `writer` (a thread, or NULL) has ended, `room` is filled, or 5 s have
 * passed. The count read. */
static DWORD read_rest(HANDLE r, HANDLE writer, BYTE *dst, DWORD room)
{
    DWORD start = GetTickCount(), total, n, got = 0;

    while (got < room && GetTickCount() - start < WAIT_MS) {
        total = 0;
        if (!PeekNamedPipe(r, NULL, 0, NULL, &total, NULL)) {
            break;
        }
        if (total > 0) {
            n = 0;
            if (!ReadFile(r, dst + got, total < room - got ? total : room - got, &n, NULL)) {
                break;
            }
            got += n;
        } else if (writer == NULL || WaitForSingleObject(writer, 0) == WAIT_OBJECT_0) {
            break;
        } else {
            Sleep(10);
        }
    }
    return got;
}

/* --- calls made in a thread ---------------------------------------- */

#define JOB_READ 0
#define JOB_WRITE 1
#define JOB_FLUSH 2

/* One call a thread makes, and its result. */
typedef struct {
    HANDLE h;
    int kind;
    BYTE *buf;
    DWORD len;
    BOOL ret;
    DWORD n;
    DWORD err;
} job_t;

static DWORD WINAPI job_run(LPVOID arg)
{
    job_t *j = (job_t *)arg;

    SetLastError(F2KT_UNTOUCHED);
    if (j->kind == JOB_WRITE) {
        j->ret = WriteFile(j->h, j->buf, j->len, &j->n, NULL);
    } else if (j->kind == JOB_READ) {
        j->ret = ReadFile(j->h, j->buf, j->len, &j->n, NULL);
    } else {
        j->ret = FlushFileBuffers(j->h);
    }
    j->err = GetLastError();
    return 0;
}

static HANDLE job_start(job_t *j, HANDLE h, int kind, BYTE *buf, DWORD len)
{
    DWORD id;

    j->h = h;
    j->kind = kind;
    j->buf = buf;
    j->len = len;
    j->ret = 0xF2F2;
    j->n = F2KT_UNTOUCHED;
    j->err = F2KT_UNTOUCHED;
    return CreateThread(NULL, 0, job_run, j, 0, &id);
}

/* A job's result as printed. */
static const char *job_text(const job_t *j)
{
    static char bufs[2][64];
    static int next;
    char *b = bufs[next++ & 1];

    if (j->kind == JOB_FLUSH) {
        sprintf(b, "ret=%d err=%s", j->ret, le_of(j->err));
    } else {
        sprintf(b, "ret=%d n=%s err=%s", j->ret, num(j->n), le_of(j->err));
    }
    return b;
}

/* Whether a job's thread is still in its call after `ms`. */
static int still_waiting(HANDLE t, DWORD ms)
{
    return WaitForSingleObject(t, ms) == WAIT_TIMEOUT;
}

/* A job's thread waited for (bounded; one that overruns is terminated),
 * then closed. */
static void job_end(HANDLE t)
{
    if (WaitForSingleObject(t, WAIT_MS) != WAIT_OBJECT_0) {
        TerminateThread(t, 0xDEAD);
        WaitForSingleObject(t, WAIT_MS);
    }
    CloseHandle(t);
}

/* A call that may wait, made in a thread: its result, or that it was
 * still waiting after `ms` (the thread is then terminated). */
static void bounded(const char *label, HANDLE h, int kind, BYTE *buf, DWORD len, DWORD ms)
{
    job_t j;
    HANDLE t = job_start(&j, h, kind, buf, len);

    if (still_waiting(t, ms)) {
        TerminateThread(t, 0xDEAD);
        WaitForSingleObject(t, WAIT_MS);
        line("%s: still waiting after %lu ms (its thread terminated)", label, ms);
    } else {
        line("%s: %s", label, job_text(&j));
    }
    CloseHandle(t);
}

/* --- create -------------------------------------------------------- */

/* A thread's 1-byte writes, counted, until it is told to stop. */
typedef struct {
    HANDLE h;
    volatile LONG count;
    volatile LONG stop;
} trickle_t;

#define TRICKLE_CAP 70000

static DWORD WINAPI trickle(LPVOID arg)
{
    trickle_t *t = (trickle_t *)arg;
    char c = 'q';
    DWORD n;

    while (!t->stop && t->count < TRICKLE_CAP) {
        if (!WriteFile(t->h, &c, 1, &n, NULL)) {
            break;
        }
        t->count++;
    }
    return 0;
}

/* CreatePipe with `size`, then a thread's 1-byte writes until one waits
 * (the count unchanged for 200 ms): how many were done, and
 * PeekNamedPipe's total then. The pipe is then read until the writer,
 * told to stop, has ended. */
static void quota(DWORD size)
{
    static BYTE sink[4096];
    trickle_t tr;
    HANDLE r, w, t;
    DWORD id, start, total, n;
    LONG last = -1, done;
    int stable = 0, ended = 0;
    BOOL ok;
    char err[16];

    arm();
    ok = CreatePipe(&r, &w, NULL, size);
    strcpy(err, le());
    if (!ok) {
        line("CreatePipe(nSize %lu): ret=0 err=%s", size, err);
        return;
    }
    tr.h = w;
    tr.count = 0;
    tr.stop = 0;
    t = CreateThread(NULL, 0, trickle, &tr, 0, &id);
    start = GetTickCount();
    for (;;) {
        if (WaitForSingleObject(t, 100) != WAIT_TIMEOUT) {
            ended = 1;
            break;
        }
        done = tr.count;
        if (done == last) {
            if (++stable >= 2) {
                break;
            }
        } else {
            stable = 0;
            last = done;
        }
        if (GetTickCount() - start > WAIT_MS) {
            break;
        }
    }
    done = tr.count;
    total = F2KT_UNTOUCHED;
    PeekNamedPipe(r, NULL, 0, NULL, &total, NULL);
    if (ended) {
        line("CreatePipe(nSize %lu): ret=%d err=%s; no 1-byte write waited, %ld were done", size, ok, err,
             done);
    } else if (stable >= 2) {
        line("CreatePipe(nSize %lu): ret=%d err=%s; 1-byte writes done before one waits: %ld; PeekNamedPipe's total then: %s",
             size, ok, err, done, num(total));
    } else {
        line("CreatePipe(nSize %lu): ret=%d err=%s; the 1-byte writes still going after 5 s", size, ok, err);
    }

    tr.stop = 1;
    start = GetTickCount();
    while (GetTickCount() - start < WAIT_MS) {
        total = available(r);
        if (total > 0) {
            ReadFile(r, sink, total < sizeof sink ? total : sizeof sink, &n, NULL);
        } else if (WaitForSingleObject(t, 0) != WAIT_TIMEOUT) {
            break;
        } else {
            Sleep(10);
        }
    }
    job_end(t);
    CloseHandle(r);
    CloseHandle(w);
}

static void show_end(const char *name, HANDLE h)
{
    DWORD type;
    char err[16];

    arm();
    type = GetFileType(h);
    strcpy(err, le());
    line("  %s: GetFileType %lu err=%s, %s", name, type, err, flags_of(h));
}

static void ends_of(const char *label, SECURITY_ATTRIBUTES *sa)
{
    HANDLE r, w;
    BOOL ok;
    char err[16];

    arm();
    ok = CreatePipe(&r, &w, sa, 0);
    strcpy(err, le());
    line("CreatePipe(%s): ret=%d err=%s", label, ok, err);
    if (!ok) {
        return;
    }
    show_end("read end", r);
    show_end("write end", w);
    CloseHandle(r);
    CloseHandle(w);
}

/* A name as printed: each component (between backslashes and dots) made
 * of hexadecimal digits, a decimal digit among them, as its length
 * alone ("<8 hex>"); the rest as it is. */
static const char *masked(const WCHAR *s, int count)
{
    static char b[1024];
    int n = 0, i = 0, k, hex, digit;

    while (i < count && n < (int)sizeof b - 300) {
        if (s[i] == '\\' || s[i] == '.') {
            b[n++] = (char)s[i++];
            continue;
        }
        hex = 1;
        digit = 0;
        for (k = i; k < count && s[k] != '\\' && s[k] != '.'; k++) {
            if (s[k] >= '0' && s[k] <= '9') {
                digit = 1;
            } else if (!((s[k] >= 'a' && s[k] <= 'f') || (s[k] >= 'A' && s[k] <= 'F'))) {
                hex = 0;
            }
        }
        if (hex && digit) {
            n += sprintf(b + n, "<%d hex>", k - i);
        } else {
            n += sprintf(b + n, "%s", wsn(s + i, k - i > 32 ? 32 : k - i));
        }
        i = k;
    }
    b[n] = 0;
    return b;
}

/* An end's basic information and name, through NtQueryObject. */
static void show_object(const char *name, HANDLE h)
{
    static ULONG info[256];         /* 1 KiB, aligned for the structure */
    object_basic_t basic;
    ustring_t *us = (ustring_t *)info;
    BYTE *from = (BYTE *)info;
    ULONG len;
    LONG status;

    if (query_object == NULL) {
        line("  %s: NtQueryObject not found", name);
        return;
    }
    memset(&basic, 0xCC, sizeof basic);
    len = F2KT_UNTOUCHED;
    status = query_object(h, OBJECT_BASIC, &basic, sizeof basic, &len);
    if (status >= 0) {
        line("  %s: basic information: status=0x%08lX, length %s; attributes 0x%lX, granted access 0x%08lX, handle count %lu",
             name, (unsigned long)status, num(len), basic.Attributes, basic.GrantedAccess,
             basic.HandleCount);
    } else {
        line("  %s: basic information: status=0x%08lX, length %s", name, (unsigned long)status, num(len));
    }

    memset(info, 0xCC, sizeof info);
    len = F2KT_UNTOUCHED;
    status = query_object(h, OBJECT_NAME, info, sizeof info, &len);
    if (status >= 0 && us->Buffer != NULL && (BYTE *)us->Buffer >= from
        && (BYTE *)us->Buffer + us->Length <= from + sizeof info) {
        line("  %s: name: status=0x%08lX; its characters follow the structure: %s; MaximumLength = Length + 2: %s; length = 8 + MaximumLength: %s",
             name, (unsigned long)status, yesno(us->Buffer == (WCHAR *)(us + 1)),
             yesno(us->MaximumLength == us->Length + 2), yesno(len == 8 + (ULONG)us->MaximumLength));
        line("  %s: name [%s]", name, masked(us->Buffer, us->Length / 2));
    } else if (status >= 0) {
        line("  %s: name: status=0x%08lX, Length %u, its characters %s", name, (unsigned long)status,
             us->Length, us->Buffer == NULL ? "NULL" : "outside the buffer");
    } else {
        line("  %s: name: status=0x%08lX, length %s", name, (unsigned long)status, num(len));
    }
}

static void size_of(const char *label, HANDLE h)
{
    DWORD lo, hi = F2KT_UNTOUCHED;
    char err[16];

    arm();
    lo = GetFileSize(h, &hi);
    strcpy(err, le());
    line("GetFileSize(%s): %lu, high %s, err=%s", label, lo, num(hi), err);
}

static void pointer(const char *label, HANDLE h, LONG distance, DWORD method)
{
    static const char *const methods[] = { "FILE_BEGIN", "FILE_CURRENT", "FILE_END" };
    DWORD r;
    char err[16];

    arm();
    r = SetFilePointer(h, distance, NULL, method);
    strcpy(err, le());
    line("SetFilePointer(%s, %ld, %s): %lu err=%s", label, distance, methods[method], r, err);
}

static int zero_time(const FILETIME *t)
{
    return t->dwLowDateTime == 0 && t->dwHighDateTime == 0;
}

static void info_of(const char *label, HANDLE h)
{
    BY_HANDLE_FILE_INFORMATION fi;
    BOOL r;
    char err[16];

    memset(&fi, 0, sizeof fi);
    arm();
    r = GetFileInformationByHandle(h, &fi);
    strcpy(err, le());
    if (!r) {
        line("GetFileInformationByHandle(%s): ret=0 err=%s", label, err);
        return;
    }
    line("GetFileInformationByHandle(%s): ret=%d err=%s; attributes 0x%lX, links %lu, size %lu:%lu, times zero: %s %s %s, volume serial zero: %s, index zero: %s",
         label, r, err, fi.dwFileAttributes, fi.nNumberOfLinks, fi.nFileSizeHigh, fi.nFileSizeLow,
         yesno(zero_time(&fi.ftCreationTime)), yesno(zero_time(&fi.ftLastAccessTime)),
         yesno(zero_time(&fi.ftLastWriteTime)), yesno(fi.dwVolumeSerialNumber == 0),
         yesno(fi.nFileIndexHigh == 0 && fi.nFileIndexLow == 0));
}

static void sec_create(void)
{
    static const DWORD sizes[] = { 0, 1, 4096, 65536 };
    SECURITY_ATTRIBUTES sa;
    HANDLE r, w;
    BYTE buf[4];
    int i;

    for (i = 0; i < 4; i++) {
        quota(sizes[i]);
    }

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    ends_of("inheritable", &sa);
    sa.bInheritHandle = FALSE;
    ends_of("not inheritable", &sa);
    ends_of("no attributes", NULL);

    sa.bInheritHandle = TRUE;
    if (CreatePipe(&r, &w, &sa, 0)) {
        line("NtQueryObject on an inheritable pipe's ends:");
        show_object("read end", r);
        show_object("write end", w);
        CloseHandle(r);
        CloseHandle(w);
    }
    if (CreatePipe(&r, &w, NULL, 0)) {
        line("NtQueryObject on a pipe's ends, not inheritable:");
        show_object("read end", r);
        show_object("write end", w);
        CloseHandle(r);
        CloseHandle(w);
    }

    if (!CreatePipe(&r, &w, NULL, 0)) {
        line("CreatePipe: err=%lu", GetLastError());
        return;
    }
    line("I/O the wrong way, the pipe empty:");
    bounded("ReadFile on the write end, 1 byte", w, JOB_READ, buf, 1, 500);
    buf[0] = 'x';
    bounded("WriteFile on the read end, 1 byte", r, JOB_WRITE, buf, 1, 500);
    show_peek("the read end", r, 0, PEEK_COUNTS);

    line("file queries:");
    size_of("the read end, empty", r);
    size_of("the write end, empty", w);
    put(w, "12345", 5);
    size_of("the read end, 5 bytes in the pipe", r);
    size_of("the write end, 5 bytes in the pipe", w);
    pointer("the read end", r, 0, FILE_CURRENT);
    pointer("the read end", r, 10, FILE_BEGIN);
    pointer("the read end", r, 0, FILE_CURRENT);
    pointer("the write end", w, 0, FILE_END);
    get(r, 64);
    info_of("the read end", r);
    info_of("the write end", w);
    bounded("FlushFileBuffers(the write end), nothing buffered", w, JOB_FLUSH, NULL, 0, 500);
    bounded("FlushFileBuffers(the read end)", r, JOB_FLUSH, NULL, 0, 500);
    CloseHandle(r);
    CloseHandle(w);
}

/* --- io ------------------------------------------------------------ */

static void sec_io(void)
{
    HANDLE r, w, t;
    BYTE buf[16];
    job_t j;
    DWORD wres;

    if (!CreatePipe(&r, &w, NULL, 0)) {
        line("CreatePipe: err=%lu", GetLastError());
        return;
    }
    line("a write, then a read:");
    put(w, "hello", 5);
    get(r, 64);

    line("a read shorter than the data:");
    put(w, "0123456789", 10);
    get(r, 4);
    get(r, 64);

    line("three writes, one read:");
    put(w, "ab", 2);
    put(w, "cd", 2);
    put(w, "ef", 2);
    show_peek("no buffer", r, 0, PEEK_COUNTS);
    get(r, 64);

    line("zero-byte writes and reads:");
    put(w, "", 0);
    show_peek("after the zero-byte write", r, 0, PEEK_COUNTS);
    t = job_start(&j, r, JOB_READ, buf, 0);
    if (still_waiting(t, 500)) {
        line("ReadFile of 0 bytes on the empty pipe, in a thread: waiting after 500 ms");
        put(w, "x", 1);
        wres = WaitForSingleObject(t, WAIT_MS);
        line("  the thread after the write: %s; ReadFile %s", wr(wres), job_text(&j));
    } else {
        line("ReadFile of 0 bytes on the empty pipe, in a thread: %s", job_text(&j));
    }
    job_end(t);
    show_peek("after it", r, 0, PEEK_COUNTS);
    if (available(r) > 0) {
        get(r, 64);
    }
    put(w, "yz", 2);
    bounded("ReadFile of 0 bytes, 2 bytes in the pipe", r, JOB_READ, buf, 0, 500);
    show_peek("after it", r, 0, PEEK_COUNTS);
    get(r, 64);

    line("PeekNamedPipe:");
    put(w, "peekdata12", 10);
    show_peek("no buffer, size 0", r, 0, PEEK_COUNTS);
    show_peek("a 4-byte buffer", r, 4, PEEK_ALL);
    show_peek("a 64-byte buffer", r, 64, PEEK_ALL);
    show_peek("a 64-byte buffer, no counts", r, 64, PEEK_BUF);
    show_peek("no buffer, the total alone", r, 0, PEEK_TOTAL);
    put(w, "+more", 5);
    show_peek("two writes, a 64-byte buffer", r, 64, PEEK_ALL);
    get(r, 64);
    show_peek("the empty pipe, no buffer", r, 0, PEEK_COUNTS);
    show_peek("the empty pipe, a 64-byte buffer", r, 64, PEEK_ALL);
    CloseHandle(r);
    CloseHandle(w);
}

/* --- peek ---------------------------------------------------------- */

/* The distinctive runs: a NUL, bytes past 0x7F, no 0xCC. */
static const BYTE run1[13] = { 0x01, 0x02, 'F', '2', 'K', 0x00, 'p', 'e', 'e', 'k', 0xFE, 0xFF, 0x7F };
static const BYTE run2[13] = { 'r', 'u', 'n', 0x80, 0x0D, 0x0A, 0x00, 0x00, '2', 0xAA, 0x55, 0xC3, 0x33 };

#define OUT_SIZE 64

/* One direct peek into `out` (OUT_SIZE bytes, all 0xCC first), `size`
 * of them offered; the I/O status block starts as the sentinel. */
static LONG direct_peek(HANDLE h, BYTE *out, ULONG size, io_status_t *io)
{
    memset(out, 0xCC, OUT_SIZE);
    io->Status = (LONG)F2KT_UNTOUCHED;
    io->Information = F2KT_UNTOUCHED;
    return fs_control(h, NULL, NULL, NULL, io, PIPE_PEEK, NULL, 0, out, size);
}

static int all_cc(const BYTE *p, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0xCC) {
            return 0;
        }
    }
    return 1;
}

/* The I/O status block as printed. */
static const char *io_text(const io_status_t *io)
{
    static char b[64];

    if (io->Status == (LONG)F2KT_UNTOUCHED && io->Information == F2KT_UNTOUCHED) {
        return "untouched";
    }
    sprintf(b, "status=0x%08lX, Information %s", (unsigned long)io->Status, num(io->Information));
    return b;
}

static void sec_peek(void)
{
    static BYTE out[OUT_SIZE], again[OUT_SIZE];
    const peek_header_t *hd = (const peek_header_t *)out;
    const peek_header_t *hd2 = (const peek_header_t *)again;
    BYTE buf[64];
    io_status_t io, io2;
    HANDLE r, w;
    LONG status;
    DWORD n, rd, total, left;
    BOOL ok;
    char err[16];

    if (fs_control == NULL) {
        line("NtFsControlFile: not found");
        return;
    }
    if (!CreatePipe(&r, &w, NULL, 0)) {
        line("CreatePipe: err=%lu", GetLastError());
        return;
    }

    put(w, (const char *)run1, 13);
    line("NtFsControlFile(the pipe-peek code), the read end, a 64-byte buffer:");
    status = direct_peek(r, out, OUT_SIZE, &io);
    line("  status=0x%08lX; the I/O status: the same status: %s, Information = header + 13: %s",
         (unsigned long)status, yesno(io.Status == status), yesno(io.Information == HEADER + 13));
    line("  the header: state %lu, available %lu, messages %lu, message length %lu", hd->NamedPipeState,
         hd->ReadDataAvailable, hd->NumberOfMessages, hd->MessageLength);
    line("  the 13 bytes after the header are the ones written: %s; the bytes past them still 0xCC: %s",
         yesno(memcmp(out + HEADER, run1, 13) == 0), yesno(all_cc(out + HEADER + 13, OUT_SIZE - HEADER - 13)));
    n = F2KT_UNTOUCHED;
    arm();
    ok = ReadFile(r, buf, sizeof buf, &n, NULL);
    strcpy(err, le());
    line("ReadFile 64 then: ret=%d n=%s err=%s; the 13 bytes written: %s", ok, num(n), err,
         yesno(ok && n == 13 && memcmp(buf, run1, 13) == 0));

    status = direct_peek(r, out, OUT_SIZE, &io);
    if ((unsigned long)status < 0xC0000000u) {
        line("NtFsControlFile, the empty pipe: status=0x%08lX; I/O status %s; available %lu; the bytes past the header still 0xCC: %s",
             (unsigned long)status, io_text(&io), hd->ReadDataAvailable, yesno(all_cc(out + HEADER, OUT_SIZE - HEADER)));
    } else {
        line("NtFsControlFile, the empty pipe: status=0x%08lX; I/O status %s; the buffer untouched: %s",
             (unsigned long)status, io_text(&io), yesno(all_cc(out, OUT_SIZE)));
    }

    line("13 fresh bytes, the direct call, then PeekNamedPipe:");
    put(w, (const char *)run2, 13);
    status = direct_peek(r, again, OUT_SIZE, &io2);
    line("  NtFsControlFile: status=0x%08lX, available %lu, Information = header + 13: %s, the bytes the ones written: %s",
         (unsigned long)status, hd2->ReadDataAvailable, yesno(io2.Information == HEADER + 13),
         yesno(memcmp(again + HEADER, run2, 13) == 0));
    memset(buf, 0xCC, sizeof buf);
    rd = total = left = F2KT_UNTOUCHED;
    arm();
    ok = PeekNamedPipe(r, buf, sizeof buf, &rd, &total, &left);
    strcpy(err, le());
    line("  PeekNamedPipe, a 64-byte buffer: ret=%d err=%s; read %s, total %s, left %s", ok, err, num(rd),
         num(total), num(left));
    line("  the bytes the ones written: %s; the direct call's answers (the count read, the total, the bytes): %s",
         yesno(rd == 13 && memcmp(buf, run2, 13) == 0),
         yesno(rd <= sizeof buf && rd == io2.Information - HEADER && total == hd2->ReadDataAvailable
               && memcmp(buf, again + HEADER, rd) == 0));
    get(r, 64);

    line("the write end, and short buffers, 13 bytes in the pipe:");
    put(w, (const char *)run1, 13);
    status = direct_peek(w, out, OUT_SIZE, &io);
    line("NtFsControlFile, the write end: status=0x%08lX; I/O status %s; the buffer untouched: %s",
         (unsigned long)status, io_text(&io), yesno(all_cc(out, OUT_SIZE)));
    show_peek("the write end", w, 64, PEEK_ALL);
    status = direct_peek(r, out, 8, &io);
    line("NtFsControlFile, the read end, an 8-byte buffer: status=0x%08lX; I/O status %s; the buffer untouched: %s",
         (unsigned long)status, io_text(&io), yesno(all_cc(out, OUT_SIZE)));
    status = direct_peek(r, out, HEADER, &io);
    if ((unsigned long)status < 0xC0000000u) {
        line("NtFsControlFile, the read end, a buffer as long as the header: status=0x%08lX; I/O status %s; available %lu; past the header untouched: %s",
             (unsigned long)status, io_text(&io), hd->ReadDataAvailable, yesno(all_cc(out + HEADER, OUT_SIZE - HEADER)));
    } else {
        line("NtFsControlFile, the read end, a buffer as long as the header: status=0x%08lX; I/O status %s; the buffer untouched: %s",
             (unsigned long)status, io_text(&io), yesno(all_cc(out, OUT_SIZE)));
    }
    show_peek("the read end, after them", r, 0, PEEK_COUNTS);
    get(r, 64);
    CloseHandle(r);
    CloseHandle(w);
}

/* --- ends ---------------------------------------------------------- */

static void sec_ends(void)
{
    HANDLE r, w, w2, t;
    BYTE buf[64];
    job_t j;
    DWORD wres;
    BOOL ok;
    char err[16];

    line("the write end closed, 4 bytes left:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        put(w, "tail", 4);
        closed("the write end", w);
        show_peek("4 bytes left", r, 64, PEEK_ALL);
        get(r, 64);
        get(r, 64);
        get(r, 64);
        show_peek("drained", r, 64, PEEK_ALL);
        show_end("the read end", r);
        closed("the read end", r);
    }

    line("the write end closed, nothing left:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        closed("the write end", w);
        get(r, 64);
        closed("the read end", r);
    }

    line("a duplicated write handle keeps the pipe open:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        w2 = NULL;
        arm();
        ok = DuplicateHandle(GetCurrentProcess(), w, GetCurrentProcess(), &w2, 0, FALSE,
                             DUPLICATE_SAME_ACCESS);
        strcpy(err, le());
        line("DuplicateHandle(the write end): ret=%d err=%s", ok, err);
        closed("the write end", w);
        if (ok) {
            put(w2, "dup", 3);
            get(r, 64);
            t = job_start(&j, r, JOB_READ, buf, sizeof buf);
            line("a read in a thread, the duplicate open: waiting after 300 ms: %s", yesno(still_waiting(t, 300)));
            closed("the duplicate", w2);
            wres = WaitForSingleObject(t, WAIT_MS);
            line("  the thread once the duplicate is closed: %s; ReadFile %s", wr(wres), job_text(&j));
            job_end(t);
        }
        closed("the read end", r);
    }

    line("the read end closed, 4 bytes unread:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        put(w, "left", 4);
        closed("the read end", r);
        put(w, "x", 1);
        put(w, "", 0);
        bounded("FlushFileBuffers(the write end)", w, JOB_FLUSH, NULL, 0, 500);
        show_peek("the write end", w, 64, PEEK_ALL);
        show_end("the write end", w);
        closed("the write end", w);
    }
}

/* --- block --------------------------------------------------------- */

static BYTE big[10000], got[10000];

static void sec_block(void)
{
    HANDLE r, w, t;
    BYTE buf[64];
    job_t j;
    DWORD wres, total, n, code, received, i;
    int waiting;
    BOOL ok;
    char err[16];

    for (i = 0; i < sizeof big; i++) {
        big[i] = (BYTE)(i * 7 + i / 251);
    }

    line("a read on the empty pipe, in a thread, woken by a write:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        t = job_start(&j, r, JOB_READ, buf, sizeof buf);
        line("  waiting after 200 ms: %s", yesno(still_waiting(t, 200)));
        put(w, "wake", 4);
        wres = WaitForSingleObject(t, WAIT_MS);
        line("  the thread after the write: %s; ReadFile %s [%s]", wr(wres), job_text(&j),
             j.ret && j.n <= sizeof buf ? esc(buf, (int)j.n) : "");
        job_end(t);
        CloseHandle(r);
        CloseHandle(w);
    }

    line("a 10000-byte write into a 4096-byte pipe, in a thread:");
    if (CreatePipe(&r, &w, NULL, 4096)) {
        t = job_start(&j, w, JOB_WRITE, big, sizeof big);
        waiting = still_waiting(t, 300);
        total = F2KT_UNTOUCHED;
        PeekNamedPipe(r, NULL, 0, NULL, &total, NULL);
        line("  waiting after 300 ms: %s; PeekNamedPipe's total meanwhile: %s", yesno(waiting), num(total));
        n = F2KT_UNTOUCHED;
        arm();
        ok = ReadFile(r, got, 1000, &n, NULL);
        strcpy(err, le());
        line("  ReadFile 1000: ret=%d n=%s err=%s", ok, num(n), err);
        received = ok && n <= 1000 ? n : 0;
        line("  still waiting 200 ms after it: %s", yesno(still_waiting(t, 200)));
        received += read_rest(r, t, got + received, sizeof got - received);
        wres = WaitForSingleObject(t, WAIT_MS);
        line("  the write: %s, WriteFile %s; read in all %lu, the bytes as written: %s", wr(wres),
             job_text(&j), received, yesno(received == sizeof big && memcmp(got, big, sizeof big) == 0));
        job_end(t);
        CloseHandle(r);
        CloseHandle(w);
    }

    line("a read on the empty pipe, in a thread, ended by closing the write end:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        t = job_start(&j, r, JOB_READ, buf, sizeof buf);
        line("  waiting after 200 ms: %s", yesno(still_waiting(t, 200)));
        closed("the write end", w);
        wres = WaitForSingleObject(t, WAIT_MS);
        line("  the thread: %s; ReadFile %s", wr(wres), job_text(&j));
        job_end(t);
        CloseHandle(r);
    }

    line("a read on the empty pipe, its thread terminated:");
    if (CreatePipe(&r, &w, NULL, 0)) {
        t = job_start(&j, r, JOB_READ, buf, sizeof buf);
        waiting = still_waiting(t, 200);
        arm();
        ok = TerminateThread(t, 77);
        strcpy(err, le());
        wres = WaitForSingleObject(t, WAIT_MS);
        code = 0xF2F2F2F2u;
        GetExitCodeThread(t, &code);
        line("  waiting after 200 ms: %s; TerminateThread ret=%d err=%s; the thread: %s, exit code %s",
             yesno(waiting), ok, err, wr(wres), code_text(code));
        CloseHandle(t);
        show_peek("the pipe after it", r, 0, PEEK_COUNTS);
        put(w, "after", 5);
        get(r, 64);
        CloseHandle(r);
        CloseHandle(w);
    }

    line("a 10000-byte write into a 4096-byte pipe, its thread terminated:");
    if (CreatePipe(&r, &w, NULL, 4096)) {
        t = job_start(&j, w, JOB_WRITE, big, sizeof big);
        waiting = still_waiting(t, 300);
        arm();
        ok = TerminateThread(t, 78);
        strcpy(err, le());
        wres = WaitForSingleObject(t, WAIT_MS);
        code = 0xF2F2F2F2u;
        GetExitCodeThread(t, &code);
        line("  waiting after 300 ms: %s; TerminateThread ret=%d err=%s; the thread: %s, exit code %s",
             yesno(waiting), ok, err, wr(wres), code_text(code));
        CloseHandle(t);
        total = F2KT_UNTOUCHED;
        PeekNamedPipe(r, NULL, 0, NULL, &total, NULL);
        line("  PeekNamedPipe's total after it: %s", num(total));
        received = read_rest(r, NULL, got, sizeof got);
        line("  read then: %lu bytes, the write's first bytes: %s", received,
             yesno(memcmp(got, big, received) == 0));
        put(w, "after", 5);
        get(r, 64);
        CloseHandle(r);
        CloseHandle(w);
    }

    line("a 10000-byte write into a 4096-byte pipe, in a thread, ended by closing the read end:");
    if (CreatePipe(&r, &w, NULL, 4096)) {
        t = job_start(&j, w, JOB_WRITE, big, sizeof big);
        line("  waiting after 300 ms: %s", yesno(still_waiting(t, 300)));
        closed("the read end", r);
        wres = WaitForSingleObject(t, WAIT_MS);
        line("  the thread: %s; WriteFile %s", wr(wres), job_text(&j));
        job_end(t);
        CloseHandle(w);
    }
}

/* --- child --------------------------------------------------------- */

/* A child started, and the thread that ends it should it outlive its
 * bound. */
typedef struct {
    PROCESS_INFORMATION pi;
    HANDLE watchdog;
    int started;
} kid_t;

static DWORD WINAPI watch(LPVOID arg)
{
    HANDLE process = (HANDLE)arg;

    if (WaitForSingleObject(process, WAIT_MS) != WAIT_OBJECT_0) {
        TerminateProcess(process, 0xDEAD);
    }
    return 0;
}

/* Start pipekid with `args`, inheriting handles: its standard handles
 * in STARTUPINFO when `std`, else as the program's own are. */
static int start_kid(kid_t *k, const char *args, int std, HANDLE in, HANDLE out, HANDLE err)
{
    static char cmd[256];
    STARTUPINFOA si;
    DWORD id;
    BOOL ok;
    char e[16];

    memset(k, 0, sizeof *k);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (std) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = in;
        si.hStdOutput = out;
        si.hStdError = err;
    }
    sprintf(cmd, "pipekid %s", args);
    arm();
    ok = CreateProcessA(kid, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &k->pi);
    strcpy(e, le());
    if (!ok) {
        line("  pipekid %s: not started, err=%s", args, e);
        return 0;
    }
    k->started = 1;
    k->watchdog = CreateThread(NULL, 0, watch, k->pi.hProcess, 0, &id);
    return 1;
}

/* Wait for a started child's end: its exit code, printed. */
static void end_kid(kid_t *k, const char *args)
{
    DWORD code = 0xF2F2F2F2u, w;

    if (!k->started) {
        return;
    }
    if (k->watchdog != NULL) {
        WaitForSingleObject(k->watchdog, WAIT_MS + 2000);
        CloseHandle(k->watchdog);
    }
    w = WaitForSingleObject(k->pi.hProcess, WAIT_MS);
    GetExitCodeProcess(k->pi.hProcess, &code);
    line("  pipekid %s: %s, exit code %s", args, wr(w), code_text(code));
    CloseHandle(k->pi.hThread);
    CloseHandle(k->pi.hProcess);
    k->started = 0;
}

/* Which end of a child's pipe the program keeps for itself. */
#define KEEP_NONE 0
#define KEEP_READ 1
#define KEEP_WRITE 2

/* A pipe for children: CreatePipe makes both ends inheritable, then the
 * end the program keeps is made not inheritable, so no child holds it
 * (a reader whose own writer it held would never see the end). */
static int child_pipe(HANDLE *r, HANDLE *w, int keep)
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(r, w, &sa, 0)) {
        line("  setup: CreatePipe err=%lu", GetLastError());
        return 0;
    }
    if (keep == KEEP_READ) {
        SetHandleInformation(*r, HANDLE_FLAG_INHERIT, 0);
    } else if (keep == KEEP_WRITE) {
        SetHandleInformation(*w, HANDLE_FLAG_INHERIT, 0);
    }
    return 1;
}

/* An input with nothing in it: a pipe's read end, its write end closed
 * at once (a read gets the broken pipe's error). */
static HANDLE no_input(void)
{
    HANDLE r, w;

    if (!child_pipe(&r, &w, KEEP_NONE)) {
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(w);
    return r;
}

/* Read a child's output until every write end is gone, then print it, a
 * line per CR LF ("  > ..."), and how the last read ended. */
static void drain(HANDLE r)
{
    static BYTE all[8192];
    BYTE chunk[512];
    DWORD n, i, total = 0, kept = 0, from;
    BOOL ok;
    char err[16];

    for (;;) {
        n = 0;
        arm();
        ok = ReadFile(r, chunk, sizeof chunk, &n, NULL);
        strcpy(err, le());
        if (!ok || n == 0) {
            break;
        }
        total += n;
        for (i = 0; i < n && kept < sizeof all; i++) {
            all[kept++] = chunk[i];
        }
    }
    from = 0;
    for (i = 1; i < kept; i++) {
        if (all[i] == '\n' && all[i - 1] == '\r' && i - 1 >= from) {
            line("  > %s", esc(all + from, (int)(i - 1 - from)));
            from = i + 1;
        }
    }
    if (from < kept) {
        line("  > %s (no line end)", esc(all + from, (int)(kept - from)));
    }
    line("  the end of the output: ReadFile ret=%d err=%s, %lu bytes in all", ok, err, total);
}

/* Children joined by pipes, each one's output the next one's input, the
 * first one's input empty: the program only plumbing, then reading the
 * last one's output. Each pipe's write end is closed in the program
 * before the next child starts, so no child but its writer holds it. */
static void pipeline(const char *const *stages, int count)
{
    kid_t kids[3];
    HANDLE in, r, w;
    int i;

    memset(kids, 0, sizeof kids);
    in = no_input();
    for (i = 0; i < count; i++) {
        if (!child_pipe(&r, &w, i == count - 1 ? KEEP_READ : KEEP_NONE)) {
            break;
        }
        start_kid(&kids[i], stages[i], 1, in, w, w);
        CloseHandle(in);
        CloseHandle(w);
        in = r;
    }
    drain(in);
    CloseHandle(in);
    for (i = 0; i < count; i++) {
        end_kid(&kids[i], stages[i]);
    }
}

/* A child reading what the program writes into its standard input (the
 * write end then closed), its output read back. */
static void feed(const char *args, const char *const *pieces, int count)
{
    kid_t k;
    HANDLE ar, aw, br, bw;
    int i;

    if (!child_pipe(&ar, &aw, KEEP_WRITE)) {
        return;
    }
    if (!child_pipe(&br, &bw, KEEP_READ)) {
        CloseHandle(ar);
        CloseHandle(aw);
        return;
    }
    start_kid(&k, args, 1, ar, bw, bw);
    CloseHandle(ar);
    CloseHandle(bw);
    for (i = 0; i < count; i++) {
        put(aw, pieces[i], (DWORD)strlen(pieces[i]));
    }
    closed("the write end", aw);
    drain(br);
    CloseHandle(br);
    end_kid(&k, args);
}

static void sec_child(void)
{
    static const char *const one[] = { "emit 5" };
    static const char *const two[] = { "emit 3", "upper" };
    static const char *const two_count[] = { "emit 4", "count" };
    static const char *const three[] = { "emit 4", "cat", "count" };
    static const char *const lines[] = { "one\r\n", "two\r\n", "three\r\n" };
    static const char *const mixed[] = { "Mixed Case 1\r\n", "second, ", "unended" };
    SECURITY_ATTRIBUTES sa;
    HANDLE ar, aw, br, bw, f, in, old_in, old_out, old_err;
    BYTE buf[64];
    kid_t k;
    DWORD n;
    BOOL ok;
    char err[16];

    reset();
    line("pipekid emit 5, its standard output the pipe:");
    pipeline(one, 1);

    line("pipekid count, its standard input the pipe:");
    feed("count", lines, 3);
    line("pipekid upper, its standard input the pipe:");
    feed("upper", mixed, 3);

    line("pipekid emit 3 | pipekid upper, the program only plumbing:");
    pipeline(two, 2);
    line("pipekid emit 4 | pipekid count:");
    pipeline(two_count, 2);
    line("pipekid emit 4 | pipekid cat | pipekid count:");
    pipeline(three, 3);

    line("pipekid types, its handles in STARTUPINFO: input a pipe, output a pipe, error a file:");
    if (child_pipe(&ar, &aw, KEEP_WRITE)) {
        if (child_pipe(&br, &bw, KEEP_READ)) {
            sa.nLength = sizeof sa;
            sa.lpSecurityDescriptor = NULL;
            sa.bInheritHandle = TRUE;
            f = CreateFileA(at("SCRATCH\\types.txt"), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
            start_kid(&k, "types", 1, ar, bw, f);
            if (f != INVALID_HANDLE_VALUE) {
                CloseHandle(f);
            }
            CloseHandle(bw);
            drain(br);
            CloseHandle(br);
            end_kid(&k, "types");
        }
        CloseHandle(ar);
        CloseHandle(aw);
    }

    line("pipekid types, none in STARTUPINFO, the program's own set with SetStdHandle: input a pipe, output and error a pipe:");
    if (child_pipe(&ar, &aw, KEEP_WRITE)) {
        if (child_pipe(&br, &bw, KEEP_READ)) {
            old_in = GetStdHandle(STD_INPUT_HANDLE);
            old_out = GetStdHandle(STD_OUTPUT_HANDLE);
            old_err = GetStdHandle(STD_ERROR_HANDLE);
            SetStdHandle(STD_INPUT_HANDLE, ar);
            SetStdHandle(STD_OUTPUT_HANDLE, bw);
            SetStdHandle(STD_ERROR_HANDLE, bw);
            start_kid(&k, "types", 0, NULL, NULL, NULL);
            SetStdHandle(STD_INPUT_HANDLE, old_in);
            SetStdHandle(STD_OUTPUT_HANDLE, old_out);
            SetStdHandle(STD_ERROR_HANDLE, old_err);
            CloseHandle(bw);
            drain(br);
            CloseHandle(br);
            end_kid(&k, "types");
        }
        CloseHandle(ar);
        CloseHandle(aw);
    }

    line("pipekid exit 0, its standard input the pipe, ended before the program writes:");
    if (child_pipe(&ar, &aw, KEEP_WRITE)) {
        if (child_pipe(&br, &bw, KEEP_READ)) {
            start_kid(&k, "exit 0", 1, ar, bw, bw);
            CloseHandle(ar);
            CloseHandle(bw);
            end_kid(&k, "exit 0");
            put(aw, "late", 4);
            drain(br);
            CloseHandle(br);
        } else {
            CloseHandle(ar);
        }
        CloseHandle(aw);
    }

    line("pipekid emit 3000, its standard output the pipe, the read end closed after one read:");
    in = no_input();
    if (child_pipe(&br, &bw, KEEP_READ)) {
        start_kid(&k, "emit 3000", 1, in, bw, bw);
        CloseHandle(bw);
        n = 0;
        arm();
        ok = ReadFile(br, buf, sizeof buf, &n, NULL);
        strcpy(err, le());
        line("  ReadFile 64: ret=%d err=%s, some bytes: %s", ok, err, yesno(ok && n > 0));
        /* The child fills the pipe again and waits: the end finds it
         * waiting, whatever the timing. */
        Sleep(300);
        closed("the read end", br);
        end_kid(&k, "emit 3000");
    }
    CloseHandle(in);
}

/* --- crt ----------------------------------------------------------- */

static void clear_errno(void)
{
    errno = 0;
    _doserrno = 0;
}

static HANDLE osh(int fd)
{
    return (HANDLE)_get_osfhandle(fd);
}

static int crt_pipe(int *fds, int mode, const char *label)
{
    int r;

    fds[0] = fds[1] = -1;
    clear_errno();
    r = _pipe(fds, 4096, mode);
    line("_pipe(4096, %s): ret=%d errno=%d; two distinct descriptors above 2: %s", label, r, errno,
         yesno(r == 0 && fds[0] > 2 && fds[1] > 2 && fds[0] != fds[1]));
    if (r != 0) {
        return 0;
    }
    line("  the read end's handle: %s; the write end's: %s", flags_of(osh(fds[0])), flags_of(osh(fds[1])));
    return 1;
}

static void crt_write(int fd, const char *text, int len)
{
    int r;

    clear_errno();
    r = _write(fd, text, len);
    line("_write [%s], %d bytes: ret=%d errno=%d", esc(text, len), len, r, errno);
}

static void crt_read(int fd, int len)
{
    char buf[64];
    int r;

    clear_errno();
    r = _read(fd, buf, len);
    line("_read %d: ret=%d errno=%d [%s]", len, r, errno, r > 0 && r <= len ? esc(buf, r) : "");
}

/* WriteFile on a descriptor's handle: the bytes as they are. */
static void raw_write(int fd, const char *text, int len)
{
    DWORD n = 0;
    BOOL ok;

    ok = WriteFile(osh(fd), text, (DWORD)len, &n, NULL);
    line("WriteFile [%s] on its handle: ret=%d n=%lu", esc(text, len), ok, n);
}

/* ReadFile on a descriptor's handle: what the pipe holds. */
static void raw_read(int fd, int len)
{
    BYTE buf[64];
    DWORD n = 0;
    BOOL ok;

    ok = ReadFile(osh(fd), buf, (DWORD)len, &n, NULL);
    line("ReadFile %d on its handle: ret=%d n=%lu [%s]", len, ok, n, ok && n <= sizeof buf ? esc(buf, (int)n) : "");
}

static void crt_close(const char *label, int fd)
{
    int r;

    clear_errno();
    r = _close(fd);
    line("_close(%s): ret=%d errno=%d", label, r, errno);
}

static void sec_crt(void)
{
    int fds[2], r;

    line("text mode:");
    if (crt_pipe(fds, _O_TEXT, "_O_TEXT")) {
        crt_write(fds[1], "a\nb\n", 4);
        raw_read(fds[0], 64);
        crt_write(fds[1], "x\ny\n", 4);
        crt_read(fds[0], 64);
        line("a CR at the end of a read, LF next:");
        raw_write(fds[1], "ab\r", 3);
        raw_write(fds[1], "\ncd", 3);
        crt_read(fds[0], 3);
        crt_read(fds[0], 64);
        line("a CR at the end of a read, another byte next:");
        raw_write(fds[1], "ab\r", 3);
        raw_write(fds[1], "xy", 2);
        crt_read(fds[0], 3);
        crt_read(fds[0], 64);
        line("a CR at the end of a read, the end of the file next:");
        raw_write(fds[1], "ab\r", 3);
        crt_close("the write end", fds[1]);
        crt_read(fds[0], 3);
        crt_read(fds[0], 64);
        crt_read(fds[0], 64);
        crt_close("the read end", fds[0]);
    }

    line("a Ctrl+Z in text mode, then the end of the file:");
    if (crt_pipe(fds, _O_TEXT, "_O_TEXT")) {
        raw_write(fds[1], "a\032b", 3);
        crt_close("the write end", fds[1]);
        crt_read(fds[0], 64);
        crt_read(fds[0], 64);
        crt_close("the read end", fds[0]);
    }

    line("binary mode:");
    if (crt_pipe(fds, _O_BINARY, "_O_BINARY")) {
        crt_write(fds[1], "a\nb\r\n", 5);
        crt_read(fds[0], 64);
        crt_write(fds[1], "z", 1);
        crt_close("the write end", fds[1]);
        crt_read(fds[0], 64);
        crt_read(fds[0], 64);
        crt_close("the read end", fds[0]);
    }

    line("binary mode, _O_NOINHERIT, the read end closed:");
    if (crt_pipe(fds, _O_BINARY | _O_NOINHERIT, "_O_BINARY | _O_NOINHERIT")) {
        crt_close("the read end", fds[0]);
        clear_errno();
        r = _write(fds[1], "x", 1);
        line("_write [x], 1 byte: ret=%d errno=%d _doserrno=%lu", r, errno, _doserrno);
        crt_close("the write end", fds[1]);
    }
}

/* --- popen --------------------------------------------------------- */

/* The standard output handle the section started with. */
static HANDLE popen_stdout;

/* Whether _popen left the standard output handle as the section found
 * it: a program that keeps the handle GetStdHandle gave it sees this. */
static void popen_handle(void)
{
    line("  the standard output handle after _popen: %s",
         GetStdHandle(STD_OUTPUT_HANDLE) == popen_stdout ? "the same value" : "another value");
}

static void popen_read(const char *cmd, const char *mode)
{
    FILE *f;
    char buf[256];
    int r, lines = 0;

    line("_popen(\"%s\", \"%s\"), read with fgets:", cmd, mode);
    clear_errno();
    f = _popen(cmd, mode);
    if (f == NULL) {
        line("  NULL errno=%d", errno);
        return;
    }
    popen_handle();
    while (lines < 20 && fgets(buf, sizeof buf, f) != NULL) {
        line("  fgets: [%s]", esc(buf, (int)strlen(buf)));
        lines++;
    }
    clear_errno();
    r = _pclose(f);
    line("  %d lines; _pclose: ret=%d errno=%d", lines, r, errno);
}

/* _popen for writing: the child prints through the program's own
 * standard output, while the program waits in _pclose. */
static void popen_write(const char *cmd, const char *mode)
{
    FILE *f;
    int a, b, r;

    line("_popen(\"%s\", \"%s\"), \"one\\n\" and \"two\\n\" written with fputs:", cmd, mode);
    clear_errno();
    f = _popen(cmd, mode);
    if (f == NULL) {
        line("  NULL errno=%d", errno);
        return;
    }
    popen_handle();
    a = fputs("one\n", f);
    b = fputs("two\n", f);
    clear_errno();
    r = _pclose(f);
    line("  fputs: %s, %s; _pclose: ret=%d errno=%d", a >= 0 ? "done" : "EOF", b >= 0 ? "done" : "EOF", r,
         errno);
}

static void sec_popen(void)
{
    static char comspec[MAX_PATH + 16];
    HANDLE own = NULL;
    FILE *f;
    int r;

    /* line() keeps the handle it first printed through; _popen may close
     * that one. A private duplicate (the same file, so the same position
     * the children write at) carries the section's lines instead. */
    popen_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (DuplicateHandle(GetCurrentProcess(), popen_stdout, GetCurrentProcess(), &own, 0, FALSE,
                        DUPLICATE_SAME_ACCESS)) {
        f2kt_stdout = own;
    }
    reset();
    /* Both ways: the process environment, and the C runtime's copy, which
     * its getenv reads. */
    SetEnvironmentVariableA("COMSPEC", kid);
    sprintf(comspec, "COMSPEC=%s", kid);
    _putenv(comspec);
    line("COMSPEC: pipekid.exe in the program's directory");

    popen_read("pipekid emit 3", "r");
    popen_read("pipekid emit 2", "rt");
    popen_read("pipekid emit 2", "rb");
    popen_write("pipekid count", "w");
    popen_write("pipekid count", "wt");
    popen_write("pipekid count", "wb");
    popen_write("pipekid upper", "w");
    popen_read("pipekid exit 7", "r");

    f = fopen(at("SCRATCH\\plain.txt"), "w");
    if (f != NULL) {
        clear_errno();
        r = _pclose(f);
        line("_pclose on a stream fopen opened: ret=%d errno=%d", r, errno);
        /* Left open: had _pclose closed it after all, fclose would be
         * given a stream already gone. The process's end closes it. */
    } else {
        line("setup: fopen failed");
    }
    clear_errno();
    f = _popen("pipekid exit 1", "x");
    line("_popen(\"pipekid exit 1\", \"x\"): %s errno=%d", f != NULL ? "a stream" : "NULL", errno);
    if (f != NULL) {
        _pclose(f);
    }

    clear_errno();
    r = system(NULL);
    line("system(NULL): ret=%d errno=%d", r, errno);
    line("system(\"pipekid exit 4\"):");
    clear_errno();
    r = system("pipekid exit 4");
    line("  ret=%d errno=%d", r, errno);
    line("system(\"pipekid emit 2\"):");
    clear_errno();
    r = system("pipekid emit 2");
    line("  ret=%d errno=%d", r, errno);
}

static const section_t sections[] = {
    { "create", sec_create, F2KT_ALWAYS },
    { "io", sec_io, F2KT_ALWAYS },
    { "peek", sec_peek, F2KT_ALWAYS },
    { "ends", sec_ends, F2KT_ALWAYS },
    { "block", sec_block, F2KT_ALWAYS },
    { "child", sec_child, F2KT_ALWAYS },
    { "crt", sec_crt, F2KT_ALWAYS },
    { "popen", sec_popen, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    static char home_entry[MAX_PATH + 16];
    HMODULE ntdll;
    char *p;

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, home, sizeof home);
    p = strrchr(home, '\\');
    if (p != NULL) {
        *p = 0;
    }
    sprintf(kid, "%s\\pipekid.exe", home);
    SetCurrentDirectoryA(home);
    /* The children print paths relative to F2KHOME. Set both ways: the
     * process environment (CreateProcess's children inherit it) and the
     * C runtime's copy (what _popen's and system()'s may be given). */
    SetEnvironmentVariableA("F2KHOME", home);
    sprintf(home_entry, "F2KHOME=%s", home);
    _putenv(home_entry);
    ntdll = GetModuleHandleA("ntdll.dll");
    fs_control = (fs_control_fn)GetProcAddress(ntdll, "NtFsControlFile");
    query_object = (query_object_fn)GetProcAddress(ntdll, "NtQueryObject");
    return run_sections("pipe", sections, argc, argv);
}
