/*
 * f2ksub - a DLL in the dllmain fixture's dllsub subdirectory alone
 * (see dllmain.c): LoadLibrary finds it by its bare name only once the
 * current directory is dllsub. Built with no C runtime, DllMain its
 * entry point, which records each call in f2kbase.dll's log.
 */

#include <windows.h>

void __stdcall f2kb_log(const char *dll, DWORD reason, LPVOID reserved);

/* An export, as the other companions have. */
int __stdcall f2ks_value(void)
{
    return 9;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    f2kb_log("f2ksub", reason, reserved);
    return TRUE;
}
