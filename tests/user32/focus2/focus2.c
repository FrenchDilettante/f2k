/*
 * focus2 - the focus and foreground calls the focus fixture leaves:
 * AttachThreadInput (the focus, active window and key state shared
 * across two threads, and its refusals), AllowSetForegroundWindow and
 * LockSetForegroundWindow (whether a child process of the program's
 * own may take the foreground).
 *
 * The sections make a visible top-most window of their own on the main
 * thread and ask for the foreground; each prints whether it has it and
 * stops when it has not. tests\capture.bat runs from a console that is
 * the foreground, so a program it starts may take it. Nobody touches
 * the machine while it runs.
 *
 * attach's second thread makes its own visible top-most window and
 * runs the calls the main thread hands it one at a time (an event
 * each way), pumping its queue between them. Windows print as which of
 * the section's windows they are; nothing else.
 *
 * foreground runs this program again as a child (focus2.exe --child)
 * that makes a top-most window, calls SetForegroundWindow, and reports
 * in its exit code whether the call returned TRUE (bit 1) and whether
 * its window became the foreground window (bit 0). The program takes
 * the foreground back between children.
 *
 * AllowSetForegroundWindow and LockSetForegroundWindow are found with
 * GetProcAddress (MSVC 6's headers declare them for Windows 2000 only);
 * the section says so and stops when one is missing.
 *
 * Conventions as the other fixtures on f2kt.h: no handle value,
 * process or thread id is printed; every call under observation is
 * armed with the last-error sentinel and its line prints ret= and
 * err=.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   attach      the second thread's GetFocus, GetActiveWindow and
 *               GetKeyState(VK_F12) (the main thread's keyboard state
 *               set with SetKeyboardState) before AttachThreadInput,
 *               after attaching it to the main thread, after its own
 *               SetFocus of its window, and after detaching; detaching
 *               again; attaching a thread to itself, to a thread id no
 *               thread has, and to a thread with no window
 *   foreground  SPI_GETFOREGROUNDLOCKTIMEOUT as zero or not; a child's
 *               SetForegroundWindow with nothing allowed, after
 *               AllowSetForegroundWindow(ASFW_ANY) and of its process
 *               id, and while LockSetForegroundWindow(LSFW_LOCK) holds;
 *               LSFW_UNLOCK twice; the refusals (an unknown process id,
 *               an unknown lock code)
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat focus2):
 *   cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% focus2.c user32.lib
 */

#include "../common/f2kt.h"

#define F2K_ASFW_ANY ((DWORD)-1)
#define F2K_LSFW_LOCK 1
#define F2K_LSFW_UNLOCK 2
#ifndef SPI_GETFOREGROUNDLOCKTIMEOUT
#define SPI_GETFOREGROUNDLOCKTIMEOUT 0x2000
#endif

typedef BOOL (WINAPI *allow_fn)(DWORD);
typedef BOOL (WINAPI *lock_fn)(UINT);

static allow_fn allow_set_fg;
static lock_fn lock_set_fg;

static HWND win_main, win_second;

static const char *which(HWND h)
{
    if (h == NULL) {
        return "NULL";
    }
    if (h == win_main) {
        return "the main thread's window";
    }
    if (h == win_second) {
        return "the second thread's window";
    }
    return "another window";
}

static LRESULT CALLBACK focus_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    return DefWindowProcW(h, m, w, l);
}

static HWND make(int x)
{
    static BOOL registered;
    WNDCLASSW wc;

    if (!registered) {
        ZeroMemory(&wc, sizeof wc);
        wc.lpfnWndProc = focus_proc;
        wc.hInstance = GetModuleHandleA(NULL);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"F2KFocus2";
        registered = RegisterClassW(&wc) != 0;
    }
    return CreateWindowExW(WS_EX_TOPMOST, L"F2KFocus2", L"focus2", WS_POPUP | WS_CAPTION | WS_VISIBLE, x, 100, 160,
                           100, NULL, NULL, GetModuleHandleA(NULL), NULL);
}

static void pump(void)
{
    MSG m;

    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        DispatchMessageW(&m);
    }
}

static int take_foreground(void)
{
    SetForegroundWindow(win_main);
    SetFocus(win_main);
    pump();
    Sleep(100);
    pump();
    return GetForegroundWindow() == win_main;
}

/* --- attach ------------------------------------------------------------ */

/* The jobs the second thread runs. */
enum { JOB_QUERY = 1, JOB_ATTACH, JOB_DETACH, JOB_SETFOCUS, JOB_END };

static int job;
static HANDLE job_go, job_done;
static DWORD main_tid;
static HWND got_focus, got_active;
static SHORT got_key;
static BOOL got_ret;
static DWORD got_err;

static DWORD WINAPI second_thread(LPVOID param)
{
    MSG m;

    win_second = make(300);
    SetEvent(job_done);
    for (;;) {
        DWORD w = MsgWaitForMultipleObjects(1, &job_go, FALSE, 10000, QS_ALLINPUT);

        if (w == WAIT_OBJECT_0 + 1) {
            while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
                DispatchMessageW(&m);
            }
            continue;
        }
        if (w != WAIT_OBJECT_0) {
            break;
        }
        ResetEvent(job_go);
        switch (job) {
        case JOB_QUERY:
            break;
        case JOB_ATTACH:
            arm();
            got_ret = AttachThreadInput(GetCurrentThreadId(), main_tid, TRUE);
            got_err = GetLastError();
            break;
        case JOB_DETACH:
            arm();
            got_ret = AttachThreadInput(GetCurrentThreadId(), main_tid, FALSE);
            got_err = GetLastError();
            break;
        case JOB_SETFOCUS:
            arm();
            got_ret = SetFocus(win_second) != NULL;
            got_err = GetLastError();
            break;
        }
        got_focus = GetFocus();
        got_active = GetActiveWindow();
        got_key = GetKeyState(VK_F12);
        if (job == JOB_END) {
            DestroyWindow(win_second);
            SetEvent(job_done);
            break;
        }
        SetEvent(job_done);
    }
    return 0;
}

static void run_job(int j)
{
    job = j;
    ResetEvent(job_done);
    SetEvent(job_go);
    while (MsgWaitForMultipleObjects(1, &job_done, FALSE, WAIT_MS, QS_ALLINPUT) == WAIT_OBJECT_0 + 1) {
        pump();
    }
}

static void state(const char *when)
{
    line("%s, on the second thread: GetFocus %s, GetActiveWindow %s, GetKeyState(VK_F12) %s", when, which(got_focus),
         which(got_active), (got_key & 1) ? "toggled" : "not toggled");
    line("  on the main thread: GetFocus %s, GetActiveWindow %s, GetKeyState(VK_F12) %s", which(GetFocus()),
         which(GetActiveWindow()), (GetKeyState(VK_F12) & 1) ? "toggled" : "not toggled");
}

static DWORD WINAPI idle_thread(LPVOID param)
{
    WaitForSingleObject((HANDLE)param, WAIT_MS);
    return 0;
}

static void attach_line(const char *what, DWORD from, DWORD to, BOOL on)
{
    BOOL r;

    arm();
    r = AttachThreadInput(from, to, on);
    line("AttachThreadInput(%s): ret=%d err=%s", what, r, le());
}

static void sec_attach(void)
{
    BYTE keys[256], saved[256];
    HANDLE t, idle, stop;
    DWORD tid, idle_tid;

    main_tid = GetCurrentThreadId();
    win_main = make(100);
    line("the main thread's window is the foreground window: %s", yesno(take_foreground()));
    if (GetForegroundWindow() != win_main) {
        DestroyWindow(win_main);
        return;
    }
    GetKeyboardState(saved);
    memcpy(keys, saved, sizeof keys);
    keys[VK_F12] |= 1;
    SetKeyboardState(keys);

    job_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    job_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    t = CreateThread(NULL, 0, second_thread, NULL, 0, &tid);
    WaitForSingleObject(job_done, WAIT_MS);
    take_foreground();
    run_job(JOB_QUERY);
    state("before");
    run_job(JOB_ATTACH);
    line("the second thread's AttachThreadInput(itself, the main thread, TRUE): ret=%d err=%s", got_ret,
         le_of(got_err));
    state("attached");
    run_job(JOB_SETFOCUS);
    line("the second thread's SetFocus(its window): a window returned %s err=%s", yesno(got_ret), le_of(got_err));
    state("then");
    run_job(JOB_DETACH);
    line("the second thread's AttachThreadInput(itself, the main thread, FALSE): ret=%d err=%s", got_ret,
         le_of(got_err));
    state("detached");
    run_job(JOB_DETACH);
    line("the second thread's AttachThreadInput(..., FALSE) again: ret=%d err=%s", got_ret, le_of(got_err));

    attach_line("this thread, itself, TRUE", main_tid, main_tid, TRUE);
    attach_line("this thread, a thread id no thread has, TRUE", main_tid, 0xFFFFFFF0, TRUE);
    stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    idle = CreateThread(NULL, 0, idle_thread, stop, 0, &idle_tid);
    attach_line("a thread with no window or queue, this thread, TRUE", idle_tid, main_tid, TRUE);
    attach_line("this thread, a thread with no window or queue, TRUE", main_tid, idle_tid, TRUE);
    AttachThreadInput(idle_tid, main_tid, FALSE);
    AttachThreadInput(main_tid, idle_tid, FALSE);
    SetEvent(stop);
    if (idle != NULL) {
        WaitForSingleObject(idle, WAIT_MS);
        CloseHandle(idle);
    }
    CloseHandle(stop);

    run_job(JOB_END);
    if (t != NULL) {
        WaitForSingleObject(t, WAIT_MS);
        CloseHandle(t);
    }
    CloseHandle(job_go);
    CloseHandle(job_done);
    SetKeyboardState(saved);
    DestroyWindow(win_main);
    win_main = win_second = NULL;
    pump();
}

/* --- foreground -------------------------------------------------------- */

static int child(void)
{
    HWND h;
    BOOL r;
    int code;

    h = make(400);
    pump();
    r = SetForegroundWindow(h);
    pump();
    Sleep(100);
    pump();
    code = (r ? 2 : 0) | (GetForegroundWindow() == h ? 1 : 0);
    DestroyWindow(h);
    return code;
}

static PROCESS_INFORMATION spawn_suspended(void)
{
    char path[MAX_PATH], cmd[MAX_PATH + 16];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    GetModuleFileNameA(NULL, path, sizeof path);
    sprintf(cmd, "\"%s\" --child", path);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        line("CreateProcessA: failed err=%lu", GetLastError());
    }
    return pi;
}

static void finish(const char *what, PROCESS_INFORMATION pi)
{
    DWORD code = 99;

    if (pi.hProcess == NULL) {
        return;
    }
    ResumeThread(pi.hThread);
    while (MsgWaitForMultipleObjects(1, &pi.hProcess, FALSE, WAIT_MS, QS_ALLINPUT) == WAIT_OBJECT_0 + 1) {
        pump();
    }
    GetExitCodeProcess(pi.hProcess, &code);
    line("%s: the child's SetForegroundWindow returned TRUE %s, its window became the foreground window %s", what,
         code == 99 ? "-" : yesno(code & 2), code == 99 ? "-" : yesno(code & 1));
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    line("  the main window is the foreground window again: %s", yesno(take_foreground()));
}

static void allow(const char *what, DWORD pid)
{
    BOOL r;

    arm();
    r = allow_set_fg(pid);
    line("AllowSetForegroundWindow(%s): ret=%d err=%s", what, r, le());
}

static void lockfg(const char *what, UINT code)
{
    BOOL r;

    arm();
    r = lock_set_fg(code);
    line("LockSetForegroundWindow(%s): ret=%d err=%s", what, r, le());
}

static void sec_foreground(void)
{
    DWORD timeout = 0;
    PROCESS_INFORMATION pi;

    line("GetProcAddress(user32, AllowSetForegroundWindow, LockSetForegroundWindow): %s %s",
         yesno(allow_set_fg != NULL), yesno(lock_set_fg != NULL));
    if (allow_set_fg == NULL || lock_set_fg == NULL) {
        return;
    }
    SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT, 0, &timeout, 0);
    line("SPI_GETFOREGROUNDLOCKTIMEOUT: %s", timeout ? "non-zero" : "0");
    win_main = make(100);
    line("the main window is the foreground window: %s", yesno(take_foreground()));
    if (GetForegroundWindow() != win_main) {
        DestroyWindow(win_main);
        win_main = NULL;
        return;
    }

    pi = spawn_suspended();
    finish("nothing allowed", pi);
    pi = spawn_suspended();
    allow("the child's process id", pi.dwProcessId);
    finish("its process id allowed", pi);
    pi = spawn_suspended();
    allow("ASFW_ANY", F2K_ASFW_ANY);
    finish("ASFW_ANY allowed", pi);
    allow("the program's own process id", GetCurrentProcessId());
    allow("a process id no process has", 0xFFFFFFF0);

    lockfg("LSFW_LOCK", F2K_LSFW_LOCK);
    pi = spawn_suspended();
    finish("locked", pi);
    pi = spawn_suspended();
    allow("ASFW_ANY, locked", F2K_ASFW_ANY);
    finish("locked, ASFW_ANY allowed", pi);
    lockfg("LSFW_LOCK again", F2K_LSFW_LOCK);
    lockfg("LSFW_UNLOCK", F2K_LSFW_UNLOCK);
    lockfg("LSFW_UNLOCK again", F2K_LSFW_UNLOCK);
    lockfg("code 7", 7);
    pi = spawn_suspended();
    finish("unlocked", pi);
    DestroyWindow(win_main);
    win_main = NULL;
    pump();
}

static const section_t sections[] = {
    { "attach", sec_attach, F2KT_ALWAYS },
    { "foreground", sec_foreground, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    HMODULE user = GetModuleHandleA("user32.dll");

    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        return child();
    }
    allow_set_fg = (allow_fn)GetProcAddress(user, "AllowSetForegroundWindow");
    lock_set_fg = (lock_fn)GetProcAddress(user, "LockSetForegroundWindow");
    return run_sections("focus2", sections, argc, argv);
}
