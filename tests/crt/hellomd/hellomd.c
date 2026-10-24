/*
 * hellomd - hello built with /MD: the same program, its C runtime
 * msvcrt.dll's instead of the static copy, as cmd.exe's is. The
 * smallest proof of msvcrt's startup protocol plus printf.
 *
 * The source is core\hello\hello.c itself, included whole, so the two
 * programs can never drift apart.
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat hellomd):
 *   cl /nologo /MD hellomd.c
 */

#include "../../core/hello/hello.c"
