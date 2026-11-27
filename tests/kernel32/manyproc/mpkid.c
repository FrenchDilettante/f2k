/*
 * mpkid - the manyproc fixture's companion program: the child its
 * sections start, many at once, doing what its first argument says. It
 * prints nothing: the program observes it through its semaphore, its
 * event and its exit code. It is built with no C runtime and a 64 KiB
 * stack reservation, its only imports kernel32's, so that hundreds of it
 * cost the machine as little as a process can.
 *
 * Modes:
 *
 *   hold <ready> <go>  release semaphore <ready> once, wait for event
 *                      <go> (120 s at most), exit 0 (1 if it never came,
 *                      2 if the semaphore or the event is missing, 3 if
 *                      the release failed)
 *   quit               exit 7 at once
 *   (anything else)    exit 100
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat manyproc):
 *   cl /nologo mpkid.c /link /NODEFAULTLIB /ENTRY:KidMain /SUBSYSTEM:CONSOLE /STACK:0x10000,0x1000 kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The longest wait: the program sets <go> well before it passes. */
#define HOLD_MS 120000

/* The command line past the program's name (quoted or not). */
static const char *past_program(const char *s)
{
    if (*s == '"') {
        s++;
        while (*s != '\0' && *s != '"') {
            s++;
        }
        if (*s == '"') {
            s++;
        }
    } else {
        while (*s != '\0' && *s != ' ' && *s != '\t') {
            s++;
        }
    }
    return s;
}

/* The next blank-separated word of s into buf (size bytes, NUL-terminated,
 * cut short if longer); the rest of s. */
static const char *word(const char *s, char *buf, int size)
{
    int n = 0;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    while (*s != '\0' && *s != ' ' && *s != '\t') {
        if (n < size - 1) {
            buf[n++] = *s;
        }
        s++;
    }
    buf[n] = '\0';
    return s;
}

static int same(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static UINT hold(const char *ready_name, const char *go_name)
{
    HANDLE ready = OpenSemaphoreA(SEMAPHORE_MODIFY_STATE, FALSE, ready_name);
    HANDLE go = OpenEventA(SYNCHRONIZE, FALSE, go_name);

    if (ready == NULL || go == NULL) {
        return 2;
    }
    if (!ReleaseSemaphore(ready, 1, NULL)) {
        return 3;
    }
    return WaitForSingleObject(go, HOLD_MS) == WAIT_OBJECT_0 ? 0 : 1;
}

void WINAPI KidMain(void)
{
    char mode[16];
    char ready[96];
    char go[96];
    const char *rest = past_program(GetCommandLineA());

    rest = word(rest, mode, sizeof mode);
    if (same(mode, "hold")) {
        rest = word(rest, ready, sizeof ready);
        word(rest, go, sizeof go);
        ExitProcess(hold(ready, go));
    }
    ExitProcess(same(mode, "quit") ? 7 : 100);
}
