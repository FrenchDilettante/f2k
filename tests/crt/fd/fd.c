/*
 * fd - msvcrt.dll's descriptor layer and stdio streams under /MD, as
 * cmd.exe uses them: descriptors over Win32 handles, duplication and
 * redirection, text and binary modes, _iob's streams, fgets, _getch.
 *
 * Works inside SCRATCH, a directory next to the program's image, which
 * each section that uses it empties silently first, so every run starts
 * from the same state.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   osfhandle  _open_osfhandle over a CreateFileA handle (the lowest
 *              free descriptor), _get_osfhandle on it, on 0-2 and on
 *              descriptors that are not open (-1, errno EBADF), _close
 *              closing the handle too, a second _close failing,
 *              _open_osfhandle of an invalid handle
 *   dup        _dup and _dup2 sharing the file position, their errors;
 *              fd 1 redirected into a file with _dup2 (printf, fflush
 *              and _write land there), restored, the file read back,
 *              and whether GetStdHandle follows fd 1
 *   setmode    _setmode's previous modes, what "a\nb" puts in the file
 *              in text and in binary mode, _write's count and _tell
 *              after each, an invalid mode and descriptor
 *   stdio      _iob's three streams (their FILE fields), fprintf to
 *              &_iob[1] and stderr and printf, buffered in full, against
 *              line()'s direct writes, fflush; a file stream's buffer
 *              against the file's size
 *   fgets      fgets through _fdopen over _open_osfhandle, in text mode
 *              (CR LF read as LF, Ctrl-Z the end) and in binary mode: a
 *              short buffer, an empty line, the last line without its
 *              newline, the end of the file, the descriptor closed by
 *              fclose
 *   getch      _getch over key events the section queues itself
 *              (WriteConsoleInputW on CONIN$): characters, Enter,
 *              Escape, a lone Shift, an arrow key and a function key
 *              (two codes each); each _getch only after _kbhit says a
 *              key is waiting, so nothing ever blocks
 *
 * stdout's buffering depends on what it is (a console: flushed at each
 * call; a file, as on the real machine: when full): the stdio section
 * sets the standard streams' buffers itself (setvbuf, _IOFBF), so the
 * order of its lines is the same either way.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat fd):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% fd.c
 */

#include "../common/f2kt.h"
#include <stdlib.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <conio.h>

static char base[MAX_PATH];         /* SCRATCH\ under the image's directory */

static const char *at(const char *rel)
{
    static char bufs[4][2 * MAX_PATH];
    static int next;
    char *b = bufs[next++ & 3];

    sprintf(b, "%s%s", base, rel);
    return b;
}

/* Create SCRATCH if need be and delete the files in it, without
   printing. */
static void scratch(void)
{
    char pat[2 * MAX_PATH];
    char path[2 * MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE f;
    char *p;
    char *q;

    GetModuleFileNameA(NULL, base, sizeof base);
    p = NULL;
    for (q = base; *q != 0; q++) {
        if (*q == '\\') {
            p = q;
        }
    }
    p = p != NULL ? p + 1 : base;
    sprintf(p, "SCRATCH");
    CreateDirectoryA(base, NULL);
    sprintf(p, "SCRATCH\\");

    sprintf(pat, "%s*", base);
    f = FindFirstFileA(pat, &fd);
    if (f == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        sprintf(path, "%s%s", base, fd.cFileName);
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(path);
    } while (FindNextFileA(f, &fd));
    FindClose(f);
}

/* strlen's count, without importing it. */
static int str_len(const char *s)
{
    int n = 0;

    while (s[n] != 0) {
        n++;
    }
    return n;
}

static HANDLE create(const char *rel, DWORD access)
{
    return CreateFileA(at(rel), access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

/* Write `n` bytes into a new file under SCRATCH. */
static void make_file(const char *rel, const char *bytes, int n)
{
    HANDLE h = create(rel, GENERIC_WRITE);
    DWORD written;

    WriteFile(h, bytes, (DWORD)n, &written, NULL);
    CloseHandle(h);
}

/* Bytes as printed: printable ASCII as itself, the rest escaped. */
static const char *esc(const char *s, int n)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int len = 0;
    int i;

    for (i = 0; i < n && len < (int)sizeof bufs[0] - 5; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\r') {
            len += sprintf(b + len, "\\r");
        } else if (c == '\n') {
            len += sprintf(b + len, "\\n");
        } else if (c == '\\') {
            len += sprintf(b + len, "\\\\");
        } else if (c >= 0x20 && c < 0x7F) {
            b[len++] = (char)c;
        } else {
            len += sprintf(b + len, "\\x%02X", c);
        }
    }
    b[len] = 0;
    return b;
}

/* A file's bytes, read back through ReadFile, as printed. */
static const char *contents(const char *rel)
{
    char buf[256];
    DWORD got = 0;
    HANDLE h = CreateFileA(at(rel), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        return "(cannot open)";
    }
    ReadFile(h, buf, sizeof buf, &got, NULL);
    CloseHandle(h);
    return esc(buf, (int)got);
}

/* A stream over a file under SCRATCH: CreateFileA, then _open_osfhandle
   with `flags` (the descriptor's mode), then _fdopen with `mode`. (fopen
   would be one more import: cmd.exe does not use it.) */
static FILE *open_stream(const char *rel, DWORD access, DWORD disposition, int flags, const char *mode)
{
    HANDLE h = CreateFileA(at(rel), access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, disposition,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    int fd;

    if (h == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    fd = _open_osfhandle((long)h, flags);
    if (fd == -1) {
        CloseHandle(h);
        return NULL;
    }
    return _fdopen(fd, mode);
}

static const char *opened(long oh)
{
    return oh != -1 ? "valid" : "-1";
}

/* --- osfhandle ----------------------------------------------------- */

static void sec_osfhandle(void)
{
    HANDLE h;
    int fd;
    int r;
    long oh;
    DWORD type;

    scratch();
    h = create("os.txt", GENERIC_READ | GENERIC_WRITE);
    line("CreateFileA: %s", yesno(h != INVALID_HANDLE_VALUE));
    errno = 0;
    fd = _open_osfhandle((long)h, 0);
    line("_open_osfhandle(the handle, 0): fd %d errno %d", fd, errno);
    oh = _get_osfhandle(fd);
    line("_get_osfhandle(fd): the handle given: %s", yesno((HANDLE)oh == h));
    line("_get_osfhandle(0), (1), (2): %s %s %s", opened(_get_osfhandle(0)), opened(_get_osfhandle(1)),
         opened(_get_osfhandle(2)));
    line("_get_osfhandle(1) is GetStdHandle(STD_OUTPUT_HANDLE): %s",
         yesno((HANDLE)_get_osfhandle(1) == GetStdHandle(STD_OUTPUT_HANDLE)));
    errno = 0;
    oh = _get_osfhandle(-1);
    line("_get_osfhandle(-1): %ld errno %d", oh, errno);
    errno = 0;
    oh = _get_osfhandle(fd + 1);
    line("_get_osfhandle(fd + 1, never opened): %ld errno %d", oh, errno);
    errno = 0;
    oh = _get_osfhandle(5000);
    line("_get_osfhandle(5000): %ld errno %d", oh, errno);

    errno = 0;
    r = _close(fd);
    line("_close(fd): %d errno %d", r, errno);
    arm();
    type = GetFileType(h);
    line("GetFileType(the handle after _close): %lu err=%s", type, le());
    errno = 0;
    oh = _get_osfhandle(fd);
    line("_get_osfhandle(fd) after _close: %ld errno %d", oh, errno);
    errno = 0;
    r = _close(fd);
    line("_close(fd) again: %d errno %d", r, errno);

    errno = 0;
    fd = _open_osfhandle((long)INVALID_HANDLE_VALUE, 0);
    line("_open_osfhandle(INVALID_HANDLE_VALUE, 0): %d errno %d", fd, errno);

    h = create("os2.txt", GENERIC_READ | GENERIC_WRITE);
    fd = _open_osfhandle((long)h, _O_RDONLY);
    line("_open_osfhandle(a second handle, _O_RDONLY): fd %d", fd);
    errno = 0;
    r = _write(fd, "x", 1);
    line("_write to it: %d errno %d", r, errno);
    _close(fd);
}

/* --- dup ----------------------------------------------------------- */

static void sec_dup(void)
{
    HANDLE h;
    int fd, d, saved;
    int r, r2, w, n;
    int follows, follows_after;

    scratch();
    h = create("dup.txt", GENERIC_READ | GENERIC_WRITE);
    fd = _open_osfhandle((long)h, 0);
    errno = 0;
    d = _dup(fd);
    line("_dup(fd %d): fd %d errno %d, another handle: %s", fd, d, errno,
         yesno(_get_osfhandle(d) != -1 && _get_osfhandle(d) != _get_osfhandle(fd)));
    w = _write(fd, "ab", 2);
    r = _write(d, "cd", 2);
    line("_write(fd): %d, _write(the duplicate): %d, _tell(fd) %ld", w, r, _tell(fd));
    errno = 0;
    r = _dup2(fd, 10);
    line("_dup2(fd, 10): %d errno %d, fd 10 %s", r, errno, opened(_get_osfhandle(10)));
    w = _write(10, "ef", 2);
    line("_write(10): %d", w);
    errno = 0;
    r = _dup(-1);
    line("_dup(-1): %d errno %d", r, errno);
    errno = 0;
    r = _dup(77);
    line("_dup(77, not open): %d errno %d", r, errno);
    errno = 0;
    r = _dup2(77, 11);
    line("_dup2(77, 11): %d errno %d", r, errno);
    errno = 0;
    r = _dup2(fd, 5000);
    line("_dup2(fd, 5000): %d errno %d", r, errno);
    _close(10);
    _close(d);
    _close(fd);
    line("dup.txt: [%s]", contents("dup.txt"));

    /* fd 1 into a file. While fd 1 is the file, line() writes through a
       duplicate of the original standard output (_dup2 closes fd 1's
       handle, which line() would otherwise still hold). */
    h = create("out.txt", GENERIC_WRITE);
    fd = _open_osfhandle((long)h, _O_TEXT);
    fflush(stdout);
    saved = _dup(1);
    line("_dup(1): fd %d", saved);
    f2kt_stdout = (HANDLE)_get_osfhandle(saved);
    errno = 0;
    r = _dup2(fd, 1);
    follows = GetStdHandle(STD_OUTPUT_HANDLE) == (HANDLE)_get_osfhandle(1);
    n = printf("printf into fd 1\n");
    r2 = fflush(stdout);
    w = _write(1, "_write(1)\n", 10);
    line("_dup2(fd, 1): %d errno %d; GetStdHandle(STD_OUTPUT_HANDLE) is fd 1's handle: %s",
         r, errno, yesno(follows));
    line("printf: %d, fflush: %d, _write(1): %d", n, r2, w);
    r = _dup2(saved, 1);
    f2kt_stdout = (HANDLE)_get_osfhandle(1);
    follows_after = GetStdHandle(STD_OUTPUT_HANDLE) == f2kt_stdout;
    line("_dup2(saved, 1): %d; GetStdHandle(STD_OUTPUT_HANDLE) is fd 1's handle: %s", r, yesno(follows_after));
    _close(saved);
    _close(fd);
    line("out.txt: [%s]", contents("out.txt"));
    line("line() after the restore");
}

/* --- setmode ------------------------------------------------------- */

static void sec_setmode(void)
{
    HANDLE h;
    int fd;
    int prev, w;

    scratch();
    h = create("mode.txt", GENERIC_READ | GENERIC_WRITE);
    fd = _open_osfhandle((long)h, 0);
    line("_tell(new fd): %ld", _tell(fd));
    prev = _setmode(fd, _O_TEXT);
    line("_setmode(fd opened with 0, _O_TEXT): previous 0x%X", prev);
    w = _write(fd, "a\nb", 3);
    line("text: _write(\"a\\nb\") %d, _tell %ld", w, _tell(fd));
    w = _write(fd, "x\r\ny\n\n", 6);
    line("text: _write(\"x\\r\\ny\\n\\n\") %d, _tell %ld", w, _tell(fd));
    prev = _setmode(fd, _O_BINARY);
    line("_setmode(fd, _O_BINARY): previous 0x%X", prev);
    w = _write(fd, "a\nb", 3);
    line("binary: _write(\"a\\nb\") %d, _tell %ld", w, _tell(fd));
    prev = _setmode(fd, _O_BINARY);
    line("_setmode(fd, _O_BINARY) again: previous 0x%X", prev);
    errno = 0;
    prev = _setmode(fd, 0x1234);
    line("_setmode(fd, 0x1234): %d errno %d", prev, errno);
    errno = 0;
    prev = _setmode(77, _O_TEXT);
    line("_setmode(77, not open): %d errno %d", prev, errno);
    _close(fd);
    line("mode.txt: [%s]", contents("mode.txt"));

    h = create("mode2.txt", GENERIC_READ | GENERIC_WRITE);
    fd = _open_osfhandle((long)h, _O_TEXT);
    prev = _setmode(fd, _O_BINARY);
    line("_setmode(fd opened with _O_TEXT, _O_BINARY): previous 0x%X", prev);
    _close(fd);
}

/* --- stdio --------------------------------------------------------- */

static char out_buffer[256];
static char err_buffer[256];

static void show_stream(const char *what, FILE *f)
{
    line("%s: _file %d, _flag 0x%X, _cnt %d, buffered bytes %d, _bufsiz %d", what, f->_file, f->_flag,
         f->_cnt, f->_base != NULL ? (int)(f->_ptr - f->_base) : -1, f->_bufsiz);
}

static void sec_stdio(void)
{
    int r1, r2, n1, n2, n3;
    FILE *f;
    HANDLE h;

    scratch();
    line("sizeof(FILE): %d", (int)sizeof(FILE));
    show_stream("_iob[0]", &_iob[0]);
    show_stream("_iob[1]", &_iob[1]);
    show_stream("_iob[2]", &_iob[2]);
    line("stdin, stdout and stderr are &_iob[0], [1] and [2]: %s",
         yesno(stdin == &_iob[0] && stdout == &_iob[1] && stderr == &_iob[2]));

    r1 = setvbuf(stdout, out_buffer, _IOFBF, sizeof out_buffer);
    r2 = setvbuf(stderr, err_buffer, _IOFBF, sizeof err_buffer);
    line("setvbuf(stdout), setvbuf(stderr), _IOFBF %d bytes: %d %d", (int)sizeof out_buffer, r1, r2);
    n1 = fprintf(&_iob[1], "stdio: fprintf(&_iob[1]) %d\n", 1);
    show_stream("stdout after fprintf", stdout);
    n2 = fprintf(stderr, "stdio: fprintf(stderr) %s\n", "two");
    n3 = printf("stdio: printf %d|%s|%5.2f|%c\n", 3, "three", 2.5, 'z');
    show_stream("stderr after fprintf", stderr);
    line("stdio: line() after fprintf %d, fprintf(stderr) %d, printf %d", n1, n2, n3);
    r1 = fflush(stderr);
    line("fflush(stderr): %d", r1);
    r1 = fflush(&_iob[1]);
    line("fflush(&_iob[1]): %d", r1);
    show_stream("stdout after fflush", stdout);
    n1 = fprintf(stdout, "stdio: fprintf(stdout), then fflush(NULL)\n");
    r1 = fflush(NULL);
    line("fflush(NULL): %d", r1);

    f = open_stream("buf.txt", GENERIC_WRITE, CREATE_ALWAYS, _O_TEXT, "w");
    line("_fdopen(_open_osfhandle(a new file, _O_TEXT), \"w\"): %s", yesno(f != NULL));
    if (f == NULL) {
        return;
    }
    h = (HANDLE)_get_osfhandle(f->_file);
    n1 = fprintf(f, "abc\n");
    line("fprintf to the file: %d; the file's size before fflush %lu", n1, GetFileSize(h, NULL));
    show_stream("the file's stream", f);
    r1 = fflush(f);
    line("fflush: %d; the file's size after %lu", r1, GetFileSize(h, NULL));
    r1 = fclose(f);
    line("fclose: %d; buf.txt: [%s]", r1, contents("buf.txt"));
}

/* --- fgets --------------------------------------------------------- */

/* Read a stream to its end with fgets into `size` bytes (`short_size`
   for the third call), printing each result. */
static void read_lines(const char *what, FILE *f, int short_size)
{
    char buf[64];
    char *r;
    int i, j;

    for (i = 0; i < 10; i++) {
        for (j = 0; j < (int)sizeof buf; j++) {
            buf[j] = '#';
        }
        r = fgets(buf, i == 2 ? short_size : (int)sizeof buf, f);
        if (r == NULL) {
            line("%s: fgets %d: NULL, feof %s", what, i + 1, yesno(feof(f) != 0));
            return;
        }
        line("%s: fgets %d: [%s] the buffer returned: %s", what, i + 1, esc(buf, str_len(buf)),
             yesno(r == buf));
    }
}

static void sec_fgets(void)
{
    static const char lines_txt[] = "one\r\ntwo\nthree-is-long\r\n\r\nlast";
    static const char eof_txt[] = "a\r\nb\x1A" "c\r\n";
    FILE *f;
    int fd;

    scratch();
    make_file("lines.txt", lines_txt, sizeof lines_txt - 1);
    make_file("eof.txt", eof_txt, sizeof eof_txt - 1);

    f = open_stream("lines.txt", GENERIC_READ, OPEN_EXISTING, _O_RDONLY | _O_TEXT, "r");
    line("_fdopen(_open_osfhandle(lines.txt, _O_RDONLY | _O_TEXT), \"r\"): %s", yesno(f != NULL));
    if (f != NULL) {
        read_lines("text", f, 6);
        fclose(f);
    }

    f = open_stream("lines.txt", GENERIC_READ, OPEN_EXISTING, _O_RDONLY, "rb");
    line("_fdopen(_open_osfhandle(lines.txt, _O_RDONLY), \"rb\"): %s", yesno(f != NULL));
    if (f != NULL) {
        fd = f->_file;
        read_lines("binary", f, 6);
        fclose(f);
        line("the descriptor after fclose: %s", opened(_get_osfhandle(fd)));
    }

    f = open_stream("eof.txt", GENERIC_READ, OPEN_EXISTING, _O_RDONLY | _O_TEXT, "r");
    if (f != NULL) {
        read_lines("text with Ctrl-Z", f, 64);
        fclose(f);
    }
    f = open_stream("eof.txt", GENERIC_READ, OPEN_EXISTING, _O_RDONLY, "rb");
    if (f != NULL) {
        read_lines("binary with Ctrl-Z", f, 64);
        fclose(f);
    }
}

/* --- getch --------------------------------------------------------- */

static void key(INPUT_RECORD *r, BOOL down, WORD vk, WORD scan, WCHAR ch, DWORD state)
{
    char *b = (char *)r;
    int i;

    for (i = 0; i < (int)sizeof *r; i++) {
        b[i] = 0;
    }
    r->EventType = KEY_EVENT;
    r->Event.KeyEvent.bKeyDown = down;
    r->Event.KeyEvent.wRepeatCount = 1;
    r->Event.KeyEvent.wVirtualKeyCode = vk;
    r->Event.KeyEvent.wVirtualScanCode = scan;
    r->Event.KeyEvent.uChar.UnicodeChar = ch;
    r->Event.KeyEvent.dwControlKeyState = state;
}

/* Each key pressed and released: 'a', a lone Shift, Shift+'Z', '1',
   Enter, Escape, Up (an enhanced key) and F1. */
static int queue_keys(INPUT_RECORD *rec)
{
    static const struct {
        WORD vk;
        WORD scan;
        WCHAR ch;
        DWORD state;
    } keys[] = {
        { 0x41, 0x1E, L'a', 0 },
        { VK_SHIFT, 0x2A, 0, SHIFT_PRESSED },
        { 0x5A, 0x2C, L'Z', SHIFT_PRESSED },
        { 0x31, 0x02, L'1', 0 },
        { VK_RETURN, 0x1C, L'\r', 0 },
        { VK_ESCAPE, 0x01, 0x1B, 0 },
        { VK_UP, 0x48, 0, ENHANCED_KEY },
        { VK_F1, 0x3B, 0, 0 },
    };
    int n = 0;
    int i;

    for (i = 0; i < (int)(sizeof keys / sizeof keys[0]); i++) {
        key(&rec[n++], TRUE, keys[i].vk, keys[i].scan, keys[i].ch, keys[i].state);
        key(&rec[n++], FALSE, keys[i].vk, keys[i].scan, keys[i].ch, keys[i].state);
    }
    return n;
}

static void sec_getch(void)
{
    INPUT_RECORD rec[32];
    HANDLE in;
    DWORD written = 0;
    BOOL r;
    int n, i, c;
    char codes[256];
    int len = 0;

    in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                     OPEN_EXISTING, 0, NULL);
    line("CreateFileA(CONIN$): %s", yesno(in != INVALID_HANDLE_VALUE));
    if (in == INVALID_HANDLE_VALUE) {
        return;
    }
    arm();
    r = FlushConsoleInputBuffer(in);
    line("FlushConsoleInputBuffer: ret=%d err=%s", r, le());
    n = queue_keys(rec);
    arm();
    r = WriteConsoleInputW(in, rec, (DWORD)n, &written);
    line("WriteConsoleInputW(%d key events): ret=%d written=%lu err=%s", n, r, written, le());

    /* Never _getch without a key waiting: on the real machine it would
       wait for the keyboard. */
    codes[0] = 0;
    for (i = 0; i < 16 && _kbhit(); i++) {
        c = _getch();
        len += sprintf(codes + len, " 0x%02X", c);
    }
    line("_getch:%s", codes[0] != 0 ? codes : " nothing waiting");
    line("_getch calls: %d, then _kbhit: %d", i, _kbhit() != 0);

    FlushConsoleInputBuffer(in);
    CloseHandle(in);
}

static const section_t sections[] = {
    { "osfhandle", sec_osfhandle, F2KT_ALWAYS },
    { "dup", sec_dup, F2KT_ALWAYS },
    { "setmode", sec_setmode, F2KT_ALWAYS },
    { "stdio", sec_stdio, F2KT_ALWAYS },
    { "fgets", sec_fgets, F2KT_ALWAYS },
    { "getch", sec_getch, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("fd", sections, argc, argv);
}
