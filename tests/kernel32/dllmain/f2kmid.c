/*
 * f2kmid - a DLL the dllmain program imports statically, importing
 * f2kbase.dll itself (see dllmain.c): the loader initializes it after
 * f2kbase.dll. Built with no C runtime, DllMain its entry point, which
 * records each call in f2kbase.dll's log.
 */

#include <windows.h>

void __stdcall f2kb_log(const char *dll, DWORD reason, LPVOID reserved);

/* The export the program calls (so it imports the DLL). */
int __stdcall f2km_value(void)
{
    return 7;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    f2kb_log("f2kmid", reason, reserved);
    return TRUE;
}
