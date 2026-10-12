/*
 * hello - console output baseline.
 *
 * The CRT starts up exactly as in ret0, then printf writes
 * "Hello, world!" to stdout before exiting 0. The first corpus test
 * with observable output: F2K's first milestone target for it is
 * exit code 0; output verification starts once a console backend
 * exists.
 *
 * Build (real Windows 2000 machine, MSVC 6):
 *   cl /nologo hello.c
 */

#include <stdio.h>

int main(void)
{
    printf("Hello, world!\n");
    return 0;
}
