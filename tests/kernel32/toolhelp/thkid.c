/*
 * thkid - the toolhelp fixture's companion program: the child its child
 * section starts, doing what its first argument says. It prints nothing:
 * the program observes it through its snapshots, its events and its exit
 * code. It calls SetErrorMode first, so a fault ends it quietly with the
 * exception's code.
 *
 * Modes:
 *
 *   hold <ready> <go> <n>  start n more threads, each waiting for event
 *                          <go> (20 s at most); set event <ready>; wait
 *                          for <go> (20 s at most); exit 0 (1 if it never
 *                          came, 2 if an event is missing, 3 if a thread
 *                          could not be made)
 *   nest <ready> <go>      start "thkid hold <ready> <go> 0" from its own
 *                          image, close the handles CreateProcessA gave,
 *                          exit 0 (2 if it could not start it): its child
 *                          outlives it
 *   (anything else)        exit 100
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat toolhelp):
 *   cl /nologo /MD thkid.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The longest wait: the program sets <go> well before it passes. */
#define HOLD_MS 20000

static HANDLE go;

/* hold's other threads: they wait as its main thread does. */
static DWORD WINAPI holder(LPVOID arg)
{
    (void)arg;
    WaitForSingleObject(go, HOLD_MS);
    return 0;
}

static int hold(const char *ready_name, const char *go_name, int extra)
{
    HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, ready_name);
    HANDLE t;
    DWORD id;
    int i;

    go = OpenEventA(SYNCHRONIZE, FALSE, go_name);
    if (ready == NULL || go == NULL) {
        return 2;
    }
    for (i = 0; i < extra; i++) {
        t = CreateThread(NULL, 0, holder, NULL, 0, &id);
        if (t == NULL) {
            return 3;
        }
        CloseHandle(t);
    }
    SetEvent(ready);
    return WaitForSingleObject(go, HOLD_MS) == WAIT_OBJECT_0 ? 0 : 1;
}

static int nest(const char *ready_name, const char *go_name)
{
    char self[MAX_PATH];
    char cmd[2 * MAX_PATH + 128];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD n;

    n = GetModuleFileNameA(NULL, self, sizeof self);
    if (n == 0 || n >= sizeof self || strlen(ready_name) + strlen(go_name) > 100) {
        return 2;
    }
    sprintf(cmd, "\"%s\" hold %s %s 0", self, ready_name, go_name);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(self, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return 2;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

int main(int argc, char **argv)
{
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    if (argc >= 5 && strcmp(argv[1], "hold") == 0) {
        return hold(argv[2], argv[3], atoi(argv[4]));
    }
    if (argc >= 4 && strcmp(argv[1], "nest") == 0) {
        return nest(argv[2], argv[3]);
    }
    return 100;
}
