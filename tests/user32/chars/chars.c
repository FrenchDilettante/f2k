/*
 * chars - user32's character case and classification: CharUpperW/A,
 * CharLowerW/A, CharUpperBuffW/A, CharLowerBuffW/A and
 * IsCharAlphaNumericW/A.
 *
 * CharUpper and CharLower take either a string, converted in place, or
 * a single character in the pointer's low word (the high word zero),
 * whose converted form comes back in the return's low word. The
 * sections run both forms over the same characters: ASCII, Latin-1
 * (U+00E9, U+00FF, whose capital is U+0178, U+00DF, which has no
 * single-character capital, U+00B5), the dotless and dotted Turkish i,
 * Greek, Cyrillic and fullwidth letters, a digit and punctuation. The
 * A forms run on the code page 1252 bytes of the same letters where
 * there are any (0xE9, 0xFF, whose capital 0x9F is in 0x80-0x9F, 0x9A,
 * 0xDF, 0xB5).
 *
 * The case mapping and the character types come from the locale
 * tables, so each section prints first whether the user and system
 * default locales are 0x0409 and the ANSI code page 1252. A string
 * prints unit by unit: 0x20-0x7E as they are, a NUL as '|', any other
 * wide unit as <U+XXXX> and any other byte as <XX>; a returned
 * character prints as the return's whole value in hex.
 *
 * Conventions as the other fixtures on f2kt.h: every call under
 * observation is armed with the last-error sentinel, and its line
 * prints ret= and err=. No pointer prints: a returned string pointer
 * prints as whether it is the one passed.
 *
 * Sections (run all with no argument, or one by name):
 *
 *   upper  CharUpperW of a string of the letters above, and of each
 *          letter as a single character (0 too); CharUpperA likewise
 *          over the 1252 bytes
 *   lower  CharLowerW and CharLowerA, the same over the capitals
 *   buff   CharUpperBuffW/A and CharLowerBuffW/A over "abC\0dEf" and
 *          its 1252 twin: the whole length (past the NUL), 3, 1 and 0
 *          units, the return and the buffer's first 8 units
 *   alnum  IsCharAlphaNumericW over letters, digits, '_', space, '.',
 *          U+00E9, U+00B2, U+00BD, U+00AA, U+0660, U+2160, U+4E00,
 *          U+FF10 and 0; IsCharAlphaNumericA over ASCII and the 1252
 *          bytes 0xE9, 0xB2, 0xAA, 0x8A, 0x80, 0xFF and 0
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat chars):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% chars.c user32.lib
 */

#include "../common/f2kt.h"

/* `count` wide units as printed. Calls no API. Rotates through a few
 * buffers. */
static const char *units_w(const WCHAR *s, int count)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 12; i++) {
        if (s[i] == 0) {
            b[n++] = '|';
        } else if (s[i] >= 0x20 && s[i] <= 0x7E) {
            b[n++] = (char)s[i];
        } else {
            n += sprintf(b + n, "<U+%04X>", (unsigned)s[i]);
        }
    }
    b[n] = '\0';
    return b;
}

/* The same for ANSI units. */
static const char *units_a(const char *s, int count)
{
    static char bufs[4][512];
    static int next;
    char *b = bufs[next++ & 3];
    int n = 0;
    int i;
    unsigned char c;

    for (i = 0; i < count && n < (int)sizeof bufs[0] - 8; i++) {
        c = (unsigned char)s[i];
        if (c == 0) {
            b[n++] = '|';
        } else if (c >= 0x20 && c <= 0x7E) {
            b[n++] = (char)c;
        } else {
            n += sprintf(b + n, "<%02X>", (unsigned)c);
        }
    }
    b[n] = '\0';
    return b;
}

static int len_w(const WCHAR *s)
{
    int n = 0;

    while (s[n] != 0) {
        n++;
    }
    return n;
}

/* What the case mapping and the character types depend on. */
static void locale_line(void)
{
    line("user default LCID is 0x0409: %s, system default LCID is 0x0409: %s, "
         "ANSI code page 1252: %s",
         yesno(GetUserDefaultLCID() == 0x0409), yesno(GetSystemDefaultLCID() == 0x0409),
         yesno(GetACP() == 1252));
}

/* The small letters, then their capitals as Unicode has them. */
static const WCHAR small_w[] = {
    'a', 'b', 'z', 0x00E9, 0x00FF, 0x00DF, 0x00B5, 0x0131, 'i', 0x03B1, 0x03C2, 0x0430, 0xFF41,
    '1', '!', 0
};
static const WCHAR capital_w[] = {
    'A', 'B', 'Z', 0x00C9, 0x0178, 0x0130, 'I', 0x0391, 0x03A3, 0x0410, 0xFF21, 0x039C,
    '1', '!', 0
};
static const char small_a[] = "abz\xE9\xFF\xDF\xB5\x9A" "1!";
static const char capital_a[] = "ABZ\xC9\x9F\x8A" "1!";

/* The string form, then each character alone. */
static void string_and_chars_w(const char *name, LPWSTR (WINAPI *fn)(LPWSTR), const WCHAR *src)
{
    WCHAR buf[64];
    LPWSTR r;
    int n, i;

    n = len_w(src);
    memcpy(buf, src, (n + 1) * sizeof(WCHAR));
    arm();
    r = fn(buf);
    line("%s(L\"%s\"): returns the string %s err=%s, now \"%s\"", name, units_w(src, n),
         yesno(r == buf), le(), units_w(buf, n));
    for (i = 0; i <= n; i++) {
        arm();
        r = fn((LPWSTR)(DWORD)src[i]);
        line("%s(character 0x%04X): ret=0x%08lX err=%s", name, (unsigned)src[i], (DWORD)r, le());
    }
}

static void string_and_chars_a(const char *name, LPSTR (WINAPI *fn)(LPSTR), const char *src)
{
    char buf[64];
    LPSTR r;
    int n, i;

    n = (int)strlen(src);
    memcpy(buf, src, n + 1);
    arm();
    r = fn(buf);
    line("%s(\"%s\"): returns the string %s err=%s, now \"%s\"", name, units_a(src, n),
         yesno(r == buf), le(), units_a(buf, n));
    for (i = 0; i <= n; i++) {
        arm();
        r = fn((LPSTR)(DWORD)(unsigned char)src[i]);
        line("%s(character 0x%02X): ret=0x%08lX err=%s", name, (unsigned)(unsigned char)src[i],
             (DWORD)r, le());
    }
}

/* --- upper --------------------------------------------------------- */

static void sec_upper(void)
{
    locale_line();
    string_and_chars_w("CharUpperW", CharUpperW, small_w);
    string_and_chars_a("CharUpperA", CharUpperA, small_a);
}

/* --- lower --------------------------------------------------------- */

static void sec_lower(void)
{
    locale_line();
    string_and_chars_w("CharLowerW", CharLowerW, capital_w);
    string_and_chars_a("CharLowerA", CharLowerA, capital_a);
}

/* --- buff ---------------------------------------------------------- */

static void buff_w(const char *name, DWORD (WINAPI *fn)(LPWSTR, DWORD), DWORD count)
{
    static const WCHAR src[] = { 'a', 'b', 'C', 0, 'd', 'E', 'f', 0x00E9 };
    WCHAR buf[8];
    DWORD r;

    memcpy(buf, src, sizeof buf);
    arm();
    r = fn(buf, count);
    line("%s(L\"%s\", %lu): ret=%lu err=%s, now \"%s\"", name, units_w(src, 8), count, r, le(),
         units_w(buf, 8));
}

static void buff_a(const char *name, DWORD (WINAPI *fn)(LPSTR, DWORD), DWORD count)
{
    static const char src[] = { 'a', 'b', 'C', 0, 'd', 'E', 'f', (char)0xE9 };
    char buf[8];
    DWORD r;

    memcpy(buf, src, sizeof buf);
    arm();
    r = fn(buf, count);
    line("%s(\"%s\", %lu): ret=%lu err=%s, now \"%s\"", name, units_a(src, 8), count, r, le(),
         units_a(buf, 8));
}

static void sec_buff(void)
{
    static const DWORD counts[] = { 8, 3, 1, 0 };
    int i;

    locale_line();
    for (i = 0; i < 4; i++) {
        buff_w("CharUpperBuffW", CharUpperBuffW, counts[i]);
    }
    for (i = 0; i < 4; i++) {
        buff_w("CharLowerBuffW", CharLowerBuffW, counts[i]);
    }
    for (i = 0; i < 4; i++) {
        buff_a("CharUpperBuffA", CharUpperBuffA, counts[i]);
    }
    for (i = 0; i < 4; i++) {
        buff_a("CharLowerBuffA", CharLowerBuffA, counts[i]);
    }
}

/* --- alnum --------------------------------------------------------- */

static void sec_alnum(void)
{
    static const WCHAR wide[] = {
        'a', 'Z', '0', '9', '_', ' ', '.', 0x00E9, 0x00B2, 0x00BD, 0x00AA, 0x0660, 0x2160, 0x4E00,
        0xFF10, 0
    };
    static const unsigned char narrow[] = {
        'a', 'Z', '0', '9', '_', ' ', '.', 0xE9, 0xB2, 0xAA, 0x8A, 0x80, 0xFF, 0
    };
    BOOL r;
    int i;

    locale_line();
    for (i = 0; i < (int)(sizeof wide / sizeof wide[0]); i++) {
        arm();
        r = IsCharAlphaNumericW(wide[i]);
        line("IsCharAlphaNumericW(0x%04X): %s err=%s", (unsigned)wide[i], yesno(r), le());
    }
    for (i = 0; i < (int)sizeof narrow; i++) {
        arm();
        r = IsCharAlphaNumericA((CHAR)narrow[i]);
        line("IsCharAlphaNumericA(0x%02X): %s err=%s", (unsigned)narrow[i], yesno(r), le());
    }
}

static const section_t sections[] = {
    { "upper", sec_upper, F2KT_ALWAYS },
    { "lower", sec_lower, F2KT_ALWAYS },
    { "buff", sec_buff, F2KT_ALWAYS },
    { "alnum", sec_alnum, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    /* A character goes where a pointer may be read: should one fault,
     * no dialog stops the capture. */
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    return run_sections("chars", sections, argc, argv);
}
