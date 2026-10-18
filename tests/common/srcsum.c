/*
 * srcsum.c - the CRC-32 of source files, as tests/build.bat stamps the
 * fixtures with it (F2KT_SOURCE_CRC, see f2kt.h).
 *
 *   srcsum <file>...    prints the CRC-32 of the files' contents, in
 *                       order, every CR LF read as LF: 8 hex digits
 *
 * The CRC is zlib's (reflected polynomial 0xEDB88320, initial and final
 * value 0xFFFFFFFF), so the repository's tests compute the same with
 * Python's zlib.crc32 over the LF-normalized files. Build: cl srcsum.c.
 */

#include <stdio.h>

static unsigned long table[256];

static void init_table(void)
{
    unsigned long c;
    int n, k;

    for (n = 0; n < 256; n++) {
        c = (unsigned long)n;
        for (k = 0; k < 8; k++) {
            c = (c & 1) ? 0xEDB88320UL ^ (c >> 1) : c >> 1;
        }
        table[n] = c;
    }
}

static unsigned long update(unsigned long crc, int byte)
{
    return table[(crc ^ (unsigned long)byte) & 0xFF] ^ (crc >> 8);
}

int main(int argc, char **argv)
{
    unsigned long crc = 0xFFFFFFFFUL;
    int i, c, held;
    FILE *f;

    init_table();
    for (i = 1; i < argc; i++) {
        f = fopen(argv[i], "rb");
        if (f == NULL) {
            fprintf(stderr, "srcsum: cannot open %s\n", argv[i]);
            return 1;
        }
        held = 0;
        while ((c = fgetc(f)) != EOF) {
            if (held) {
                if (c != '\n') {
                    crc = update(crc, '\r');
                }
                held = 0;
            }
            if (c == '\r') {
                held = 1;
                continue;
            }
            crc = update(crc, c);
        }
        if (held) {
            crc = update(crc, '\r');
        }
        fclose(f);
    }
    printf("%08lX\n", crc ^ 0xFFFFFFFFUL);
    return 0;
}
