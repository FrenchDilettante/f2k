/*
 * hellogui - minimal Win32 GUI baseline.
 *
 * Registers a window class, creates and shows a window, paints
 * "Hello, world!" once with TextOut, then closes itself (WM_CLOSE ->
 * DestroyWindow -> PostQuitMessage), so the test needs no user
 * input and terminates with exit code 0. The first corpus test to
 * import user32.dll and gdi32.dll.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo hellogui.c user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc;

        hdc = BeginPaint(hwnd, &ps);
        TextOut(hdc, 20, 20, "Hello, world!", 13);
        EndPaint(hwnd, &ps);
        /* Drawn once; close the window so the test terminates by itself. */
        PostMessage(hwnd, WM_CLOSE, 0, 0);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE prev, PSTR cmd_line, int show)
{
    WNDCLASS wc;
    HWND hwnd;
    MSG msg;

    (void)prev;
    (void)cmd_line;

    ZeroMemory(&wc, sizeof(wc));
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "F2KHelloClass";
    if (RegisterClass(&wc) == 0) {
        return 1;
    }

    hwnd = CreateWindowEx(
        0, "F2KHelloClass", "F2K: Hello, world!",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
        NULL, NULL, instance, NULL
    );
    if (hwnd == NULL) {
        return 1;
    }

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
