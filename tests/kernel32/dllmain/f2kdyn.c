/*
 * f2kdyn - the DLL the dllmain program loads at run time (see
 * dllmain.c), importing f2kdep.dll, which nothing else loads, and
 * f2kbase.dll. Built with no C runtime, DllMain its entry point, which
 * records each call in f2kbase.dll's log.
 */

#include <windows.h>

void __stdcall f2kb_log(const char *dll, DWORD reason, LPVOID reserved);
int __stdcall f2kd_value(void);

/* An export over f2kdep.dll's (so it imports the DLL). */
int __stdcall f2ky_value(void)
{
    return f2kd_value() + 1;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    f2kb_log("f2kdyn", reason, reserved);
    return TRUE;
}
