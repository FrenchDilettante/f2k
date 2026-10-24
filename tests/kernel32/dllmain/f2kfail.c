/*
 * f2kfail - a DLL whose DllMain answers FALSE to DLL_PROCESS_ATTACH
 * (see dllmain.c): LoadLibrary of it fails. Built with no C runtime,
 * DllMain its entry point, which records each call in f2kbase.dll's
 * log (what the loader calls around the refusal shows there).
 */

#include <windows.h>

void __stdcall f2kb_log(const char *dll, DWORD reason, LPVOID reserved);

/* An export, as the other companions have. */
int __stdcall f2kf_value(void)
{
    return 5;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    f2kb_log("f2kfail", reason, reserved);
    return reason != DLL_PROCESS_ATTACH;
}
