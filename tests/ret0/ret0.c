/*
 * ret0 - C runtime startup baseline.
 *
 * A plain console program: the default CRT entry point runs full
 * runtime initialization before main (command line, environment,
 * startup info, heap), then exits through the CRT exit path with the
 * value main returned.
 *
 * F2K passes when the kernel observes the process exiting with code 0.
 * Unlike exit0.c, this exercises the whole CRT startup import surface
 * (GetVersion, GetCommandLineA, GetStartupInfoA, heap functions,
 * ExitProcess, ...). Record the exact list with:
 *   dumpbin /dependents ret0.exe
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo ret0.c
 */

int main(void)
{
    return 0;
}
