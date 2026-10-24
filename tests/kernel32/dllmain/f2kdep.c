/*
 * f2kdep - the dependency f2kdyn.dll brings in (see dllmain.c):
 * nothing else loads it, so LoadLibrary of f2kdyn.dll loads it too,
 * and FreeLibrary's last reference unloads it. Built with no C
 * runtime, DllMain its entry point, which records each call in
 * f2kbase.dll's log.
 */

#include <windows.h>

void __stdcall f2kb_log(const char *dll, DWORD reason, LPVOID reserved);

/* The export f2kdyn.dll calls (so it imports the DLL). */
int __stdcall f2kd_value(void)
{
    return 3;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    f2kb_log("f2kdep", reason, reserved);
    return TRUE;
}
