/*
 * locale - kernel32's locale formatting and queries: dates, times and
 * numbers formatted from fixed inputs, string folding, the code page
 * list and the language groups.
 *
 * Every input is fixed: a SYSTEMTIME the section fills in, a number
 * string, a picture string. Each formatting call runs under three
 * locales: LOCALE_USER_DEFAULT ("user"), LOCALE_SYSTEM_DEFAULT
 * ("system") and 0x0409 itself. Which LCID the machine's defaults are
 * prints only as "is 0x0409: yes/no", never as a value.
 *
 * A W call's text prints through ws() (a unit below 0x100 as its byte,
 * any other as <U+XXXX>); an A call's through aq() (printable ASCII as
 * itself, any other byte as <XX>). The A call runs right after its W
 * twin on the same input, its line tagged "(A)". A buffer the call did
 * not fill prints as "-".
 *
 * Sections (run all with no argument, or one by name):
 *
 *   date       GetDateFormatW/A: flags 0, DATE_SHORTDATE, DATE_LONGDATE,
 *              DATE_YEARMONTH, DATE_USE_ALT_CALENDAR and
 *              LOCALE_NOUSEROVERRIDE, and picture strings (every
 *              element's lengths, quotes, an escaped quote, the era, an
 *              empty picture), under the three locales; three more
 *              dates (the end of 1999, a leap day, a day of the week
 *              that does not match its date); the buffer-size query, a
 *              buffer that fits and one a unit short; then the errors:
 *              DATE_SHORTDATE with DATE_LONGDATE, a picture with a
 *              DATE_ flag, an unknown flag, month 13, February 30, a
 *              locale that does not exist, a NULL buffer with a size, a
 *              negative size; and the current date (NULL), as a length
 *   time       GetTimeFormatW/A: flags 0, TIME_NOSECONDS,
 *              TIME_NOMINUTESORSECONDS, TIME_NOTIMEMARKER,
 *              TIME_FORCE24HOURFORMAT, two of them and
 *              LOCALE_NOUSEROVERRIDE, and picture strings, at 04:05:06
 *              and 13:07:08 under the three locales; midnight and noon;
 *              the TIME_ flags applied to a picture; the buffer sizes;
 *              hour 24, minute 60, second 60, millisecond 1000, a
 *              month of 13 beside a valid time, an unknown flag, a
 *              locale that does not exist; and the current time (NULL),
 *              as a length
 *   number     GetNumberFormatW/A: the locales' own formats (NULL
 *              NUMBERFMT) over a set of values; NUMBERFMT's fields
 *              (NumDigits and its rounding, LeadingZero, Grouping 0, 3
 *              and 32, the separators, empty and long separators, each
 *              NegativeOrder 0-4) over positive, negative and
 *              fractional values; NegativeOrder 5, a NULL separator, a
 *              NUMBERFMT with LOCALE_NOUSEROVERRIDE, an unknown flag;
 *              strings that are not numbers (an exponent, letters,
 *              blanks, a plus sign, a lone minus, a comma, two points,
 *              two minus signs, an empty string); the buffer sizes; a
 *              locale that does not exist
 *   fold       FoldStringW/A: MAP_FOLDCZONE, MAP_FOLDDIGITS,
 *              MAP_PRECOMPOSED, MAP_COMPOSITE and MAP_EXPAND_LIGATURES
 *              alone and in pairs over letters and digits outside
 *              ASCII (the A form over code page 1252's bytes for them);
 *              an explicit count against -1; the size query and a short
 *              buffer; flags 0, an unknown flag, the pairs that may not
 *              go together, a source that is also the destination, a
 *              count of 0
 *   codepages  EnumSystemCodePagesW/A under CP_INSTALLED and
 *              CP_SUPPORTED: whether 1252, 437, 850 and 65001 are in
 *              the list, whether every entry is a decimal number,
 *              whether IsValidCodePage takes each installed one, the
 *              two counts and whether the installed are among the
 *              supported; a callback answering FALSE at once (how many
 *              calls); flags 0 and 3 and a NULL callback
 *   langgroup  IsValidLanguageGroup: Western Europe installed and
 *              supported, Central Europe, Japanese and Armenian
 *              supported, groups 0, 18 and 0xFFFF, flags 0, 3 and 4.
 *              Which groups beyond Western Europe are installed is the
 *              machine's choice, so only their support is asked.
 *
 * IsValidLanguageGroup is new in Windows 2000 and MSVC 6's headers lack
 * it: the section reaches it through GetProcAddress on kernel32 (the
 * call is still the section's own).
 *
 * Build (real Windows 2000 machine, MSVC 6; tests\build.bat locale):
 *   cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% locale.c
 */

#include "../common/f2kt.h"

/* Windows 2000's additions, which MSVC 6's headers may lack. */
#ifndef DATE_YEARMONTH
#define DATE_YEARMONTH 0x00000008
#endif
#ifndef MAP_EXPAND_LIGATURES
#define MAP_EXPAND_LIGATURES 0x00002000
#endif
#ifndef LGRPID_INSTALLED
#define LGRPID_INSTALLED 0x00000001
#endif
#ifndef LGRPID_SUPPORTED
#define LGRPID_SUPPORTED 0x00000002
#endif

typedef BOOL (WINAPI *is_valid_language_group_fn)(DWORD group, DWORD flags);

/* A locale no Windows 2000 machine has. */
#define NO_SUCH_LCID 0x1234

static const LCID lcids[3] = { LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT, 0x0409 };
static const char *const lcid_names[3] = { "user", "system", "0x0409" };

/* --- helpers ------------------------------------------------------- */

/* A byte string as printed: printable ASCII as itself, any other byte
 * as <XX>; its first `n` bytes, or to its terminator for a negative
 * `n`. Rotates through a few buffers, as ws() does. */
static const char *aq(const char *s, int n)
{
    static char bufs[4][1024];
    static int next;
    char *b = bufs[next++ & 3];
    int len = 0;
    int i;

    if (s == NULL) {
        return "(null)";
    }
    for (i = 0; (n < 0 ? s[i] != 0 : i < n) && len < (int)sizeof bufs[0] - 6; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c >= 0x20 && c < 0x7F) {
            b[len++] = (char)c;
        } else {
            len += sprintf(b + len, "<%02X>", (unsigned)c);
        }
    }
    b[len] = 0;
    return b;
}

/* An ASCII string widened into `out` (at most `size` units). */
static WCHAR *widen(const char *s, WCHAR *out, int size)
{
    int i;

    for (i = 0; s[i] != 0 && i < size - 1; i++) {
        out[i] = (WCHAR)(unsigned char)s[i];
    }
    out[i] = 0;
    return out;
}

static void fill_w(WCHAR *buf, int n)
{
    int i;

    for (i = 0; i < n; i++) {
        buf[i] = 0xBEEF;
    }
}

/* A W call's text: "-" for no text, the string up to its terminator
 * otherwise (within the units the call says it wrote). */
static const char *wtext(const WCHAR *buf, int ret, int size)
{
    if (ret <= 0 || size == 0 || buf == NULL) {
        return "-";
    }
    return wsn(buf, ret - 1);
}

static const char *atext(const char *buf, int ret, int size)
{
    if (ret <= 0 || size == 0 || buf == NULL) {
        return "-";
    }
    return aq(buf, ret - 1);
}

static SYSTEMTIME make_time(WORD year, WORD month, WORD dow, WORD day, WORD hour, WORD minute, WORD second,
                            WORD ms)
{
    SYSTEMTIME st;

    st.wYear = year;
    st.wMonth = month;
    st.wDayOfWeek = dow;
    st.wDay = day;
    st.wHour = hour;
    st.wMinute = minute;
    st.wSecond = second;
    st.wMilliseconds = ms;
    return st;
}

static void show_defaults(void)
{
    line("GetUserDefaultLCID is 0x0409: %s, GetSystemDefaultLCID is 0x0409: %s",
         yesno(GetUserDefaultLCID() == 0x0409), yesno(GetSystemDefaultLCID() == 0x0409));
}

/* --- date ---------------------------------------------------------- */

/* GetDateFormatW, then GetDateFormatA, on the same input: `size` units
 * of room (0: the size query, NULL buffer; -1: a NULL buffer with 10). */
static void date_case(LCID lcid, const char *lname, DWORD flags, const char *fname, const SYSTEMTIME *st,
                      const char *stname, const char *picture, int size)
{
    WCHAR wpic[128];
    WCHAR wbuf[128];
    char abuf[256];
    const WCHAR *wp = picture != NULL ? widen(picture, wpic, 128) : NULL;
    WCHAR *wout = size > 0 ? wbuf : NULL;
    char *aout = size > 0 ? abuf : NULL;
    int cch = size >= 0 ? size : 10;
    int r;
    const char *e;

    fill_w(wbuf, 128);
    memset(abuf, 0x7E, sizeof abuf);
    arm();
    r = GetDateFormatW(lcid, flags, st, wp, wout, cch);
    e = le();
    line("GetDateFormatW(%s, %s, %s, %s%s%s, %d): ret=%d [%s] err=%s", lname, fname, stname,
         picture != NULL ? "\"" : "", picture != NULL ? picture : "NULL", picture != NULL ? "\"" : "", cch, r,
         wtext(wout, r, size > 0 ? size : 0), e);
    arm();
    r = GetDateFormatA(lcid, flags, st, picture, aout, cch);
    e = le();
    line("  (A): ret=%d [%s] err=%s", r, atext(aout, r, size > 0 ? size : 0), e);
}

static const char *const date_pictures[] = {
    "dddd, MMMM dd, yyyy",
    "ddd d MMM yy",
    "M/d/y",
    "dd.MM.yyyy",
    "'Today is' dddd",
    "d''M",
    "'it''s' yyyy",
    "gg yyyy",
    "g y",
    "yyyy-MM-dd'T'",
    "MMMMM ddddd yyyyy",
    "abc xyz",
    "",
    NULL
};

static void sec_date(void)
{
    static const DWORD flags[] = {
        0, DATE_SHORTDATE, DATE_LONGDATE, DATE_YEARMONTH, DATE_USE_ALT_CALENDAR,
        DATE_LONGDATE | LOCALE_NOUSEROVERRIDE
    };
    static const char *const flag_names[] = {
        "0", "DATE_SHORTDATE", "DATE_LONGDATE", "DATE_YEARMONTH", "DATE_USE_ALT_CALENDAR",
        "DATE_LONGDATE|LOCALE_NOUSEROVERRIDE"
    };
    SYSTEMTIME st1 = make_time(2001, 2, 6, 3, 4, 5, 6, 7);
    SYSTEMTIME st2 = make_time(1999, 12, 5, 31, 23, 59, 59, 999);
    SYSTEMTIME st3 = make_time(2000, 2, 2, 29, 12, 0, 0, 0);
    SYSTEMTIME wrong_dow = make_time(2001, 2, 0, 3, 4, 5, 6, 7);
    SYSTEMTIME month13 = make_time(2001, 13, 6, 3, 4, 5, 6, 7);
    SYSTEMTIME feb30 = make_time(2001, 2, 5, 30, 4, 5, 6, 7);
    WCHAR wbuf[128];
    int i, j, r, need;
    const char *e;

    show_defaults();
    for (i = 0; i < 3; i++) {
        for (j = 0; j < (int)(sizeof flags / sizeof flags[0]); j++) {
            date_case(lcids[i], lcid_names[i], flags[j], flag_names[j], &st1, "2001-02-03", NULL, 128);
        }
    }
    for (i = 0; i < 3; i++) {
        for (j = 0; date_pictures[j] != NULL; j++) {
            date_case(lcids[i], lcid_names[i], 0, "0", &st1, "2001-02-03", date_pictures[j], 128);
        }
    }
    for (i = 0; i < 3; i++) {
        date_case(lcids[i], lcid_names[i], DATE_SHORTDATE, "DATE_SHORTDATE", &st2, "1999-12-31", NULL, 128);
        date_case(lcids[i], lcid_names[i], DATE_LONGDATE, "DATE_LONGDATE", &st2, "1999-12-31", NULL, 128);
        date_case(lcids[i], lcid_names[i], DATE_LONGDATE, "DATE_LONGDATE", &st3, "2000-02-29", NULL, 128);
    }
    date_case(0x0409, "0x0409", 0, "0", &wrong_dow, "2001-02-03, day of week 0", "dddd d MMMM yyyy", 128);
    date_case(0x0409, "0x0409", DATE_LONGDATE, "DATE_LONGDATE", &wrong_dow, "2001-02-03, day of week 0", NULL,
              128);

    /* The buffer sizes: the query, then exactly that, then one unit short. */
    for (i = 0; i < 3; i++) {
        arm();
        need = GetDateFormatW(lcids[i], DATE_LONGDATE, &st1, NULL, NULL, 0);
        e = le();
        line("GetDateFormatW(%s, DATE_LONGDATE), the size query: ret=%d err=%s", lcid_names[i], need, e);
        if (need > 1) {
            date_case(lcids[i], lcid_names[i], DATE_LONGDATE, "DATE_LONGDATE", &st1, "2001-02-03", NULL, need);
            date_case(lcids[i], lcid_names[i], DATE_LONGDATE, "DATE_LONGDATE", &st1, "2001-02-03", NULL,
                      need - 1);
        }
    }
    date_case(0x0409, "0x0409", 0, "0", &st1, "2001-02-03", "yyyy", 0);
    date_case(0x0409, "0x0409", 0, "0", &st1, "2001-02-03", "yyyy", 5);
    date_case(0x0409, "0x0409", 0, "0", &st1, "2001-02-03", "yyyy", 4);

    /* The errors. */
    date_case(0x0409, "0x0409", DATE_SHORTDATE | DATE_LONGDATE, "DATE_SHORTDATE|DATE_LONGDATE", &st1,
              "2001-02-03", NULL, 128);
    date_case(0x0409, "0x0409", DATE_SHORTDATE, "DATE_SHORTDATE", &st1, "2001-02-03", "yyyy", 128);
    date_case(0x0409, "0x0409", DATE_YEARMONTH | DATE_LONGDATE, "DATE_YEARMONTH|DATE_LONGDATE", &st1,
              "2001-02-03", NULL, 128);
    date_case(0x0409, "0x0409", 0x00000400, "0x400", &st1, "2001-02-03", NULL, 128);
    date_case(0x0409, "0x0409", 0, "0", &month13, "2001-13-03", NULL, 128);
    date_case(0x0409, "0x0409", 0, "0", &feb30, "2001-02-30", NULL, 128);
    date_case(NO_SUCH_LCID, "0x1234", 0, "0", &st1, "2001-02-03", NULL, 128);
    date_case(0x0409, "0x0409", 0, "0", &st1, "2001-02-03", NULL, -1);
    fill_w(wbuf, 128);
    arm();
    r = GetDateFormatW(0x0409, 0, &st1, NULL, wbuf, -1);
    e = le();
    line("GetDateFormatW(0x0409, 0, 2001-02-03, NULL, -1): ret=%d err=%s", r, e);
    arm();
    r = GetDateFormatA(0x0409, 0, &st1, NULL, (char *)wbuf, -1);
    e = le();
    line("  (A): ret=%d err=%s", r, e);

    /* The current date: its length only. */
    fill_w(wbuf, 128);
    arm();
    r = GetDateFormatW(0x0409, DATE_SHORTDATE, NULL, NULL, wbuf, 128);
    e = le();
    line("GetDateFormatW(0x0409, DATE_SHORTDATE, NULL): text %s, ret its length plus one %s err=%s",
         yesno(r > 1), yesno(r > 0 && (int)wcslen(wbuf) == r - 1), e);
    arm();
    r = GetDateFormatA(0x0409, DATE_SHORTDATE, NULL, NULL, (char *)wbuf, 128);
    e = le();
    line("  (A): text %s, ret its length plus one %s err=%s", yesno(r > 1),
         yesno(r > 0 && (int)strlen((char *)wbuf) == r - 1), e);
}

/* --- time ---------------------------------------------------------- */

static void time_case(LCID lcid, const char *lname, DWORD flags, const char *fname, const SYSTEMTIME *st,
                      const char *stname, const char *picture, int size)
{
    WCHAR wpic[128];
    WCHAR wbuf[128];
    char abuf[256];
    const WCHAR *wp = picture != NULL ? widen(picture, wpic, 128) : NULL;
    WCHAR *wout = size > 0 ? wbuf : NULL;
    char *aout = size > 0 ? abuf : NULL;
    int cch = size >= 0 ? size : 10;
    int r;
    const char *e;

    fill_w(wbuf, 128);
    memset(abuf, 0x7E, sizeof abuf);
    arm();
    r = GetTimeFormatW(lcid, flags, st, wp, wout, cch);
    e = le();
    line("GetTimeFormatW(%s, %s, %s, %s%s%s, %d): ret=%d [%s] err=%s", lname, fname, stname,
         picture != NULL ? "\"" : "", picture != NULL ? picture : "NULL", picture != NULL ? "\"" : "", cch, r,
         wtext(wout, r, size > 0 ? size : 0), e);
    arm();
    r = GetTimeFormatA(lcid, flags, st, picture, aout, cch);
    e = le();
    line("  (A): ret=%d [%s] err=%s", r, atext(aout, r, size > 0 ? size : 0), e);
}

static const char *const time_pictures[] = {
    "hh:mm:ss tt",
    "H:m:s",
    "h t",
    "HH'h'mm",
    "tt",
    "hhh:mmm:sss ttt",
    "h:mm' o''clock'",
    "",
    NULL
};

static void sec_time(void)
{
    static const DWORD flags[] = {
        0, TIME_NOSECONDS, TIME_NOMINUTESORSECONDS, TIME_NOTIMEMARKER, TIME_FORCE24HOURFORMAT,
        TIME_NOSECONDS | TIME_FORCE24HOURFORMAT, TIME_NOMINUTESORSECONDS | TIME_NOTIMEMARKER,
        LOCALE_NOUSEROVERRIDE
    };
    static const char *const flag_names[] = {
        "0", "TIME_NOSECONDS", "TIME_NOMINUTESORSECONDS", "TIME_NOTIMEMARKER", "TIME_FORCE24HOURFORMAT",
        "TIME_NOSECONDS|TIME_FORCE24HOURFORMAT", "TIME_NOMINUTESORSECONDS|TIME_NOTIMEMARKER",
        "LOCALE_NOUSEROVERRIDE"
    };
    SYSTEMTIME morning = make_time(2001, 2, 6, 3, 4, 5, 6, 7);
    SYSTEMTIME afternoon = make_time(2001, 2, 6, 3, 13, 7, 8, 9);
    SYSTEMTIME midnight = make_time(2001, 2, 6, 3, 0, 0, 0, 0);
    SYSTEMTIME noon = make_time(2001, 2, 6, 3, 12, 30, 45, 0);
    SYSTEMTIME hour24 = make_time(2001, 2, 6, 3, 24, 0, 0, 0);
    SYSTEMTIME minute60 = make_time(2001, 2, 6, 3, 4, 60, 0, 0);
    SYSTEMTIME second60 = make_time(2001, 2, 6, 3, 4, 5, 60, 0);
    SYSTEMTIME ms1000 = make_time(2001, 2, 6, 3, 4, 5, 6, 1000);
    SYSTEMTIME month13 = make_time(2001, 13, 6, 3, 4, 5, 6, 7);
    WCHAR wbuf[128];
    int i, j, r, need;
    const char *e;

    show_defaults();
    for (i = 0; i < 3; i++) {
        for (j = 0; j < (int)(sizeof flags / sizeof flags[0]); j++) {
            time_case(lcids[i], lcid_names[i], flags[j], flag_names[j], &morning, "04:05:06", NULL, 128);
            time_case(lcids[i], lcid_names[i], flags[j], flag_names[j], &afternoon, "13:07:08", NULL, 128);
        }
    }
    for (i = 0; i < 3; i++) {
        for (j = 0; time_pictures[j] != NULL; j++) {
            time_case(lcids[i], lcid_names[i], 0, "0", &morning, "04:05:06", time_pictures[j], 128);
            time_case(lcids[i], lcid_names[i], 0, "0", &afternoon, "13:07:08", time_pictures[j], 128);
        }
    }
    for (i = 0; i < 3; i++) {
        time_case(lcids[i], lcid_names[i], 0, "0", &midnight, "00:00:00", NULL, 128);
        time_case(lcids[i], lcid_names[i], 0, "0", &noon, "12:30:45", NULL, 128);
    }
    time_case(0x0409, "0x0409", 0, "0", &midnight, "00:00:00", "h:mm tt H:mm", 128);
    time_case(0x0409, "0x0409", 0, "0", &noon, "12:30:45", "h:mm tt H:mm", 128);

    /* The TIME_ flags applied to a picture. */
    for (j = 1; j < (int)(sizeof flags / sizeof flags[0]); j++) {
        time_case(0x0409, "0x0409", flags[j], flag_names[j], &afternoon, "13:07:08", "hh:mm:ss tt", 128);
        time_case(0x0409, "0x0409", flags[j], flag_names[j], &afternoon, "13:07:08", "tt h 'at' m:s", 128);
    }

    /* The buffer sizes. */
    for (i = 0; i < 3; i++) {
        arm();
        need = GetTimeFormatW(lcids[i], 0, &afternoon, NULL, NULL, 0);
        e = le();
        line("GetTimeFormatW(%s, 0), the size query: ret=%d err=%s", lcid_names[i], need, e);
        if (need > 1) {
            time_case(lcids[i], lcid_names[i], 0, "0", &afternoon, "13:07:08", NULL, need);
            time_case(lcids[i], lcid_names[i], 0, "0", &afternoon, "13:07:08", NULL, need - 1);
        }
    }

    /* The errors. */
    time_case(0x0409, "0x0409", 0, "0", &hour24, "24:00:00", NULL, 128);
    time_case(0x0409, "0x0409", 0, "0", &minute60, "04:60:00", NULL, 128);
    time_case(0x0409, "0x0409", 0, "0", &second60, "04:05:60", NULL, 128);
    time_case(0x0409, "0x0409", 0, "0", &ms1000, "04:05:06.1000", NULL, 128);
    time_case(0x0409, "0x0409", 0, "0", &month13, "month 13, 04:05:06", NULL, 128);
    time_case(0x0409, "0x0409", 0x00000400, "0x400", &morning, "04:05:06", NULL, 128);
    time_case(NO_SUCH_LCID, "0x1234", 0, "0", &morning, "04:05:06", NULL, 128);
    time_case(0x0409, "0x0409", 0, "0", &morning, "04:05:06", NULL, -1);

    /* The current time: its length only. */
    fill_w(wbuf, 128);
    arm();
    r = GetTimeFormatW(0x0409, TIME_FORCE24HOURFORMAT, NULL, NULL, wbuf, 128);
    e = le();
    line("GetTimeFormatW(0x0409, TIME_FORCE24HOURFORMAT, NULL): text %s, ret its length plus one %s err=%s",
         yesno(r > 1), yesno(r > 0 && (int)wcslen(wbuf) == r - 1), e);
    arm();
    r = GetTimeFormatA(0x0409, TIME_FORCE24HOURFORMAT, NULL, NULL, (char *)wbuf, 128);
    e = le();
    line("  (A): text %s, ret its length plus one %s err=%s", yesno(r > 1),
         yesno(r > 0 && (int)strlen((char *)wbuf) == r - 1), e);
}

/* --- number -------------------------------------------------------- */

/* A NUMBERFMT, as the section's tables give it: a NULL separator is a
 * NULL pointer. */
typedef struct {
    const char *label;
    UINT digits;
    UINT leading_zero;
    UINT grouping;
    const char *decimal;
    const char *thousand;
    UINT negative;
} number_format;

/* GetNumberFormatW, then GetNumberFormatA, on the same input; `fmt` NULL
 * for the locale's own format; `size` as date_case's. */
static void number_case(LCID lcid, const char *lname, DWORD flags, const char *fname, const char *value,
                        const number_format *fmt, int size)
{
    static WCHAR wdec[16], wthou[16];
    static char adec[16], athou[16];
    WCHAR wvalue[64];
    WCHAR wbuf[128];
    char abuf[256];
    NUMBERFMTW wf;
    NUMBERFMTA af;
    WCHAR *wout = size > 0 ? wbuf : NULL;
    char *aout = size > 0 ? abuf : NULL;
    int cch = size >= 0 ? size : 10;
    int r;
    const char *e;

    widen(value, wvalue, 64);
    if (fmt != NULL) {
        wf.NumDigits = af.NumDigits = fmt->digits;
        wf.LeadingZero = af.LeadingZero = fmt->leading_zero;
        wf.Grouping = af.Grouping = fmt->grouping;
        wf.NegativeOrder = af.NegativeOrder = fmt->negative;
        if (fmt->decimal != NULL) {
            widen(fmt->decimal, wdec, 16);
            strcpy(adec, fmt->decimal);
            wf.lpDecimalSep = wdec;
            af.lpDecimalSep = adec;
        } else {
            wf.lpDecimalSep = NULL;
            af.lpDecimalSep = NULL;
        }
        if (fmt->thousand != NULL) {
            widen(fmt->thousand, wthou, 16);
            strcpy(athou, fmt->thousand);
            wf.lpThousandSep = wthou;
            af.lpThousandSep = athou;
        } else {
            wf.lpThousandSep = NULL;
            af.lpThousandSep = NULL;
        }
    }
    fill_w(wbuf, 128);
    memset(abuf, 0x7E, sizeof abuf);
    arm();
    r = GetNumberFormatW(lcid, flags, wvalue, fmt != NULL ? &wf : NULL, wout, cch);
    e = le();
    line("GetNumberFormatW(%s, %s, \"%s\", %s, %d): ret=%d [%s] err=%s", lname, fname, value,
         fmt != NULL ? fmt->label : "NULL", cch, r, wtext(wout, r, size > 0 ? size : 0), e);
    arm();
    r = GetNumberFormatA(lcid, flags, value, fmt != NULL ? &af : NULL, aout, cch);
    e = le();
    line("  (A): ret=%d [%s] err=%s", r, atext(aout, r, size > 0 ? size : 0), e);
}

static const number_format number_formats[] = {
    { "{2, lz 1, group 3, \".\", \",\", neg 1}", 2, 1, 3, ".", ",", 1 },
    { "{0, lz 0, group 0, \",\", \".\", neg 0}", 0, 0, 0, ",", ".", 0 },
    { "{5, lz 0, group 3, \"<>\", \" \", neg 2}", 5, 0, 3, "<>", " ", 2 },
    { "{1, lz 1, group 32, \".\", \",\", neg 3}", 1, 1, 32, ".", ",", 3 },
    { "{3, lz 1, group 2, \".\", \"'\", neg 4}", 3, 1, 2, ".", "'", 4 },
    { "{9, lz 1, group 3, \"\", \"\", neg 1}", 9, 1, 3, "", "", 1 },
    { "{2, lz 1, group 3, \"dec.\", \"th,\", neg 1}", 2, 1, 3, "dec.", "th,", 1 },
    { NULL, 0, 0, 0, NULL, NULL, 0 }
};

static const number_format bad_formats[] = {
    { "{2, lz 1, group 3, \".\", \",\", neg 5}", 2, 1, 3, ".", ",", 5 },
    { "{2, lz 1, group 3, NULL, \",\", neg 1}", 2, 1, 3, NULL, ",", 1 },
    { "{2, lz 1, group 3, \".\", NULL, neg 1}", 2, 1, 3, ".", NULL, 1 },
    { "{2, lz 2, group 3, \".\", \",\", neg 1}", 2, 2, 3, ".", ",", 1 },
    { "{2, lz 1, group 10, \".\", \",\", neg 1}", 2, 1, 10, ".", ",", 1 },
    { "{10, lz 1, group 3, \".\", \",\", neg 1}", 10, 1, 3, ".", ",", 1 },
    { "{2, lz 1, group 3, \"12345\", \",\", neg 1}", 2, 1, 3, "12345", ",", 1 },
    { NULL, 0, 0, 0, NULL, NULL, 0 }
};

static const char *const default_values[] = {
    "1234567.891", "-1234.5", "0", "-0", "0.5", "-0.5", ".5", "1234", "00012.3400",
    "999999999999999999999.99999", NULL
};

static const char *const format_values[] = {
    "1234567.891", "-1234567.891", "0.5", "-0.5", "9.995", "-0.001", "123", NULL
};

static const char *const bad_values[] = {
    "1e5", "12a", "", " 12", "12 ", "+12", "-", "1,234", "1.2.3", "--1", "1.", ".", "0x10", "1-", NULL
};

static void sec_number(void)
{
    static const number_format plain = { "{2, lz 1, group 3, \".\", \",\", neg 1}", 2, 1, 3, ".", ",", 1 };
    int i, j, need;
    const char *e;
    WCHAR one_arabic[2];
    WCHAR wbuf[64];
    int r;

    show_defaults();
    for (i = 0; i < 3; i++) {
        for (j = 0; default_values[j] != NULL; j++) {
            number_case(lcids[i], lcid_names[i], 0, "0", default_values[j], NULL, 128);
        }
    }
    number_case(0x0409, "0x0409", LOCALE_NOUSEROVERRIDE, "LOCALE_NOUSEROVERRIDE", "-1234567.891", NULL, 128);
    number_case(LOCALE_USER_DEFAULT, "user", LOCALE_NOUSEROVERRIDE, "LOCALE_NOUSEROVERRIDE", "-1234567.891",
                NULL, 128);
    for (i = 0; number_formats[i].label != NULL; i++) {
        for (j = 0; format_values[j] != NULL; j++) {
            number_case(0x0409, "0x0409", 0, "0", format_values[j], &number_formats[i], 128);
        }
    }
    /* An explicit format is the same under any locale. */
    number_case(LOCALE_USER_DEFAULT, "user", 0, "0", "-1234567.891", &number_formats[1], 128);
    number_case(LOCALE_SYSTEM_DEFAULT, "system", 0, "0", "-1234567.891", &number_formats[1], 128);

    /* The errors. */
    for (i = 0; bad_formats[i].label != NULL; i++) {
        number_case(0x0409, "0x0409", 0, "0", "-1234.5", &bad_formats[i], 128);
    }
    number_case(0x0409, "0x0409", LOCALE_NOUSEROVERRIDE, "LOCALE_NOUSEROVERRIDE", "-1234.5", &plain, 128);
    number_case(0x0409, "0x0409", 0x00000001, "0x1", "-1234.5", NULL, 128);
    for (j = 0; bad_values[j] != NULL; j++) {
        number_case(0x0409, "0x0409", 0, "0", bad_values[j], NULL, 128);
    }
    one_arabic[0] = 0x0661;
    one_arabic[1] = 0;
    fill_w(wbuf, 64);
    arm();
    r = GetNumberFormatW(0x0409, 0, one_arabic, NULL, wbuf, 64);
    e = le();
    line("GetNumberFormatW(0x0409, 0, \"<U+0661>\", NULL, 64): ret=%d [%s] err=%s", r, wtext(wbuf, r, 64), e);
    number_case(NO_SUCH_LCID, "0x1234", 0, "0", "1234.5", NULL, 128);

    /* The buffer sizes. */
    for (i = 0; i < 3; i++) {
        arm();
        need = GetNumberFormatW(lcids[i], 0, L"-1234567.891", NULL, NULL, 0);
        e = le();
        line("GetNumberFormatW(%s, 0, \"-1234567.891\"), the size query: ret=%d err=%s", lcid_names[i], need, e);
        if (need > 1) {
            number_case(lcids[i], lcid_names[i], 0, "0", "-1234567.891", NULL, need);
            number_case(lcids[i], lcid_names[i], 0, "0", "-1234567.891", NULL, need - 1);
        }
    }
    number_case(0x0409, "0x0409", 0, "0", "1234.5", &plain, 0);
    number_case(0x0409, "0x0409", 0, "0", "1234.5", &plain, 9);
    number_case(0x0409, "0x0409", 0, "0", "1234.5", &plain, 8);
    number_case(0x0409, "0x0409", 0, "0", "1234.5", &plain, -1);
}

/* --- fold ---------------------------------------------------------- */

/* A FoldString case: the W source, and the A source in code page
 * 1252's bytes for the same characters where it has them (NULL where it
 * has none). */
typedef struct {
    const char *label;
    DWORD flags;
    const char *flag_names;
    const WCHAR *wsrc;
    const char *asrc;
} fold_case;

static const WCHAR fw_letters[] = { 0xFF21, 0xFF42, 0xFF13, 0x3000, 'x', 0xFF0C, 0 };
static const WCHAR odd_digits[] = { 0x00B2, 0x00B3, 0x00B9, 0x0661, 0x0967, 0xFF15, '9', 0 };
static const WCHAR decomposed[] = { 'e', 0x0301, ' ', 'a', 0x0308, ' ', 'n', 0x0303, ' ', 'x', 0x0301, 0 };
static const WCHAR precomposed[] = { 0x00E9, 0x00C5, 0x00F1, 0x00FC, 'z', 0 };
static const WCHAR ligatures[] = { 0x00E6, 0x00C6, 0xFB01, 0x0153, 0x00DF, 'o', 0 };
static const WCHAR mixed[] = { 0xFF21, 0x00B2, 0x00E9, 0x00E6, 'q', 0 };
static const WCHAR plain_w[] = { 'a', 'b', 'c', 0 };

static const fold_case fold_cases[] = {
    { "fullwidth", MAP_FOLDCZONE, "MAP_FOLDCZONE", fw_letters, NULL },
    { "digits", MAP_FOLDDIGITS, "MAP_FOLDDIGITS", odd_digits, "\xB2\xB3\xB9" "9" },
    { "decomposed", MAP_PRECOMPOSED, "MAP_PRECOMPOSED", decomposed, NULL },
    { "precomposed", MAP_PRECOMPOSED, "MAP_PRECOMPOSED", precomposed, "\xE9\xC5\xF1\xFCz" },
    { "precomposed", MAP_COMPOSITE, "MAP_COMPOSITE", precomposed, "\xE9\xC5\xF1\xFCz" },
    { "decomposed", MAP_COMPOSITE, "MAP_COMPOSITE", decomposed, NULL },
    { "ligatures", MAP_EXPAND_LIGATURES, "MAP_EXPAND_LIGATURES", ligatures, "\xE6\xC6\x9C\xDFo" },
    { "mixed", MAP_FOLDCZONE, "MAP_FOLDCZONE", mixed, NULL },
    { "mixed", MAP_FOLDCZONE | MAP_FOLDDIGITS, "MAP_FOLDCZONE|MAP_FOLDDIGITS", mixed, NULL },
    { "mixed", MAP_FOLDDIGITS | MAP_COMPOSITE, "MAP_FOLDDIGITS|MAP_COMPOSITE", mixed, NULL },
    { "mixed", MAP_FOLDCZONE | MAP_EXPAND_LIGATURES, "MAP_FOLDCZONE|MAP_EXPAND_LIGATURES", mixed, NULL },
    { "abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", plain_w, "abc" },
    { "abc", MAP_PRECOMPOSED, "MAP_PRECOMPOSED", plain_w, "abc" },
    { "abc", MAP_COMPOSITE, "MAP_COMPOSITE", plain_w, "abc" },
    /* The flags that are refused. */
    { "abc", 0, "0", plain_w, "abc" },
    { "abc", 0x00000100, "0x100", plain_w, "abc" },
    { "abc", MAP_PRECOMPOSED | MAP_COMPOSITE, "MAP_PRECOMPOSED|MAP_COMPOSITE", plain_w, "abc" },
    { "abc", MAP_EXPAND_LIGATURES | MAP_PRECOMPOSED, "MAP_EXPAND_LIGATURES|MAP_PRECOMPOSED", plain_w, "abc" },
    { "abc", MAP_EXPAND_LIGATURES | MAP_COMPOSITE, "MAP_EXPAND_LIGATURES|MAP_COMPOSITE", plain_w, "abc" },
    { NULL, 0, NULL, NULL, NULL }
};

/* FoldStringW on `src` (count `count`), into a buffer of `size` units
 * (0: the size query, NULL buffer). */
static void fold_w(const char *label, DWORD flags, const char *fname, const WCHAR *src, int count, int size)
{
    WCHAR wbuf[64];
    int r;
    const char *e;

    fill_w(wbuf, 64);
    arm();
    r = FoldStringW(flags, src, count, size > 0 ? wbuf : NULL, size);
    e = le();
    if (r > 0 && size > 0) {
        line("FoldStringW(%s, %s, %d, %d): ret=%d [%s]%s err=%s", fname, label, count, size, r,
             wsn(wbuf, count < 0 ? r - 1 : r), count < 0 ? (wbuf[r - 1] == 0 ? ", NUL last" : ", no NUL last") : "",
             e);
    } else {
        line("FoldStringW(%s, %s, %d, %d): ret=%d err=%s", fname, label, count, size, r, e);
    }
}

static void fold_a(const char *label, DWORD flags, const char *fname, const char *src, int count, int size)
{
    char abuf[64];
    int r;
    const char *e;

    memset(abuf, 0x7E, sizeof abuf);
    arm();
    r = FoldStringA(flags, src, count, size > 0 ? abuf : NULL, size);
    e = le();
    if (r > 0 && size > 0) {
        line("  (A) FoldStringA(%s, %s [%s], %d, %d): ret=%d [%s]%s err=%s", fname, label, aq(src, -1), count,
             size, r, aq(abuf, count < 0 ? r - 1 : r),
             count < 0 ? (abuf[r - 1] == 0 ? ", NUL last" : ", no NUL last") : "", e);
    } else {
        line("  (A) FoldStringA(%s, %s [%s], %d, %d): ret=%d err=%s", fname, label, aq(src, -1), count, size, r,
             e);
    }
}

static void sec_fold(void)
{
    WCHAR same[8];
    char asame[8];
    const fold_case *c;
    int r;
    const char *e;

    for (c = fold_cases; c->label != NULL; c++) {
        fold_w(c->label, c->flags, c->flag_names, c->wsrc, -1, 64);
        if (c->asrc != NULL) {
            fold_a(c->label, c->flags, c->flag_names, c->asrc, -1, 64);
        }
    }

    /* Explicit counts, against -1 (which counts the terminator). */
    fold_w("fullwidth", MAP_FOLDCZONE, "MAP_FOLDCZONE", fw_letters, 3, 64);
    fold_w("fullwidth", MAP_FOLDCZONE, "MAP_FOLDCZONE", fw_letters, 6, 64);
    fold_a("digits", MAP_FOLDDIGITS, "MAP_FOLDDIGITS", "\xB2\xB3\xB9" "9", 2, 64);
    fold_a("digits", MAP_FOLDDIGITS, "MAP_FOLDDIGITS", "\xB2\xB3\xB9" "9", 4, 64);

    /* The buffer sizes: the query, a buffer that fits, one short. */
    fold_w("ligatures", MAP_EXPAND_LIGATURES, "MAP_EXPAND_LIGATURES", ligatures, -1, 0);
    fold_a("ligatures", MAP_EXPAND_LIGATURES, "MAP_EXPAND_LIGATURES", "\xE6\xC6\x9C\xDFo", -1, 0);
    fold_w("precomposed", MAP_COMPOSITE, "MAP_COMPOSITE", precomposed, -1, 0);
    fold_w("precomposed", MAP_COMPOSITE, "MAP_COMPOSITE", precomposed, -1, 10);
    fold_w("precomposed", MAP_COMPOSITE, "MAP_COMPOSITE", precomposed, -1, 9);
    fold_w("abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", plain_w, -1, 4);
    fold_w("abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", plain_w, -1, 3);
    fold_a("abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", "abc", -1, 4);
    fold_a("abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", "abc", -1, 3);

    /* A count of 0, and the source as the destination. */
    fold_w("abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", plain_w, 0, 64);
    fold_a("abc", MAP_FOLDCZONE, "MAP_FOLDCZONE", "abc", 0, 64);
    same[0] = 'a';
    same[1] = 'b';
    same[2] = 0;
    arm();
    r = FoldStringW(MAP_FOLDCZONE, same, -1, same, 8);
    e = le();
    line("FoldStringW(MAP_FOLDCZONE, the source as the destination): ret=%d err=%s", r, e);
    strcpy(asame, "ab");
    arm();
    r = FoldStringA(MAP_FOLDCZONE, asame, -1, asame, 8);
    e = le();
    line("  (A): ret=%d err=%s", r, e);
}

/* --- codepages ----------------------------------------------------- */

static int cp_count;
static int cp_numeric;
static int cp_valid;
static int cp_1252, cp_437, cp_850, cp_65001;
static int cp_stop;

static void cp_reset(int stop)
{
    cp_count = 0;
    cp_numeric = 1;
    cp_valid = 1;
    cp_1252 = cp_437 = cp_850 = cp_65001 = 0;
    cp_stop = stop;
}

/* One entry, as a narrow string of what came back. */
static BOOL cp_note(const char *name)
{
    unsigned long n = 0;
    int i;

    cp_count++;
    if (name[0] == 0) {
        cp_numeric = 0;
    }
    for (i = 0; name[i] != 0; i++) {
        if (name[i] < '0' || name[i] > '9' || i > 6) {
            cp_numeric = 0;
            break;
        }
        n = n * 10 + (unsigned long)(name[i] - '0');
    }
    if (cp_numeric && !IsValidCodePage((UINT)n)) {
        cp_valid = 0;
    }
    if (n == 1252) cp_1252 = 1;
    if (n == 437) cp_437 = 1;
    if (n == 850) cp_850 = 1;
    if (n == 65001) cp_65001 = 1;
    return cp_stop ? FALSE : TRUE;
}

static BOOL CALLBACK cp_proc_w(LPWSTR name)
{
    char narrow[16];
    int i;

    for (i = 0; name[i] != 0 && i < 15; i++) {
        narrow[i] = name[i] < 0x80 ? (char)name[i] : '?';
    }
    narrow[i] = 0;
    return cp_note(narrow);
}

static BOOL CALLBACK cp_proc_a(LPSTR name)
{
    return cp_note(name);
}

static void cp_show(const char *call, const char *fname, BOOL r, const char *e, int show_count)
{
    line("%s(%s): ret=%d err=%s", call, fname, r, e);
    line("  1252 listed %s, 437 %s, 850 %s, 65001 %s; every entry a decimal number %s, IsValidCodePage of each %s",
         yesno(cp_1252), yesno(cp_437), yesno(cp_850), yesno(cp_65001), yesno(cp_numeric), yesno(cp_valid));
    if (show_count) {
        line("  entries: %d", cp_count);
    }
}

static void sec_codepages(void)
{
    int installed_w, supported_w, installed_a, supported_a;
    BOOL r;
    const char *e;

    cp_reset(0);
    arm();
    r = EnumSystemCodePagesW(cp_proc_w, CP_INSTALLED);
    e = le();
    cp_show("EnumSystemCodePagesW", "CP_INSTALLED", r, e, 1);
    installed_w = cp_count;
    cp_reset(0);
    arm();
    r = EnumSystemCodePagesA(cp_proc_a, CP_INSTALLED);
    e = le();
    cp_show("  (A) EnumSystemCodePagesA", "CP_INSTALLED", r, e, 0);
    installed_a = cp_count;

    cp_reset(0);
    arm();
    r = EnumSystemCodePagesW(cp_proc_w, CP_SUPPORTED);
    e = le();
    cp_show("EnumSystemCodePagesW", "CP_SUPPORTED", r, e, 1);
    supported_w = cp_count;
    cp_reset(0);
    arm();
    r = EnumSystemCodePagesA(cp_proc_a, CP_SUPPORTED);
    e = le();
    cp_show("  (A) EnumSystemCodePagesA", "CP_SUPPORTED", r, e, 0);
    supported_a = cp_count;

    line("the A counts are the W counts: installed %s, supported %s", yesno(installed_a == installed_w),
         yesno(supported_a == supported_w));
    line("installed no more than supported: %s", yesno(installed_w <= supported_w));

    /* A callback answering FALSE at once. */
    cp_reset(1);
    arm();
    r = EnumSystemCodePagesW(cp_proc_w, CP_INSTALLED);
    e = le();
    line("EnumSystemCodePagesW(CP_INSTALLED), the callback answering FALSE: ret=%d calls %d err=%s", r, cp_count,
         e);
    cp_reset(1);
    arm();
    r = EnumSystemCodePagesA(cp_proc_a, CP_INSTALLED);
    e = le();
    line("  (A): ret=%d calls %d err=%s", r, cp_count, e);

    /* The errors. */
    cp_reset(0);
    arm();
    r = EnumSystemCodePagesW(cp_proc_w, 0);
    e = le();
    line("EnumSystemCodePagesW(0): ret=%d calls %d err=%s", r, cp_count, e);
    cp_reset(0);
    arm();
    r = EnumSystemCodePagesA(cp_proc_a, 0);
    e = le();
    line("  (A): ret=%d calls %d err=%s", r, cp_count, e);
    cp_reset(0);
    arm();
    r = EnumSystemCodePagesW(cp_proc_w, CP_INSTALLED | CP_SUPPORTED);
    e = le();
    line("EnumSystemCodePagesW(CP_INSTALLED|CP_SUPPORTED): ret=%d calls %d err=%s", r, cp_count, e);
    cp_reset(0);
    arm();
    r = EnumSystemCodePagesA(cp_proc_a, CP_INSTALLED | CP_SUPPORTED);
    e = le();
    line("  (A): ret=%d calls %d err=%s", r, cp_count, e);
    arm();
    r = EnumSystemCodePagesW(NULL, CP_INSTALLED);
    e = le();
    line("EnumSystemCodePagesW(NULL, CP_INSTALLED): ret=%d err=%s", r, e);
    arm();
    r = EnumSystemCodePagesA(NULL, CP_INSTALLED);
    e = le();
    line("  (A): ret=%d err=%s", r, e);
}

/* --- langgroup ----------------------------------------------------- */

static void sec_langgroup(void)
{
    static const struct {
        DWORD group;
        DWORD flags;
        const char *label;
    } cases[] = {
        { 1, LGRPID_INSTALLED, "Western Europe (1), LGRPID_INSTALLED" },
        { 1, LGRPID_SUPPORTED, "Western Europe (1), LGRPID_SUPPORTED" },
        { 2, LGRPID_SUPPORTED, "Central Europe (2), LGRPID_SUPPORTED" },
        { 7, LGRPID_SUPPORTED, "Japanese (7), LGRPID_SUPPORTED" },
        { 17, LGRPID_SUPPORTED, "Armenian (17), LGRPID_SUPPORTED" },
        { 0, LGRPID_SUPPORTED, "0, LGRPID_SUPPORTED" },
        { 0, LGRPID_INSTALLED, "0, LGRPID_INSTALLED" },
        { 18, LGRPID_SUPPORTED, "18, LGRPID_SUPPORTED" },
        { 0xFFFF, LGRPID_SUPPORTED, "0xFFFF, LGRPID_SUPPORTED" },
        { 1, 0, "Western Europe (1), 0" },
        { 1, LGRPID_INSTALLED | LGRPID_SUPPORTED, "Western Europe (1), LGRPID_INSTALLED|LGRPID_SUPPORTED" },
        { 1, 4, "Western Europe (1), 4" },
        { 0, 0, NULL }
    };
    is_valid_language_group_fn is_valid;
    BOOL r;
    int i;

    is_valid = (is_valid_language_group_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                                          "IsValidLanguageGroup");
    line("IsValidLanguageGroup: exported %s", yesno(is_valid != NULL));
    if (is_valid == NULL) {
        return;
    }
    for (i = 0; cases[i].label != NULL; i++) {
        arm();
        r = is_valid(cases[i].group, cases[i].flags);
        line("IsValidLanguageGroup(%s): ret=%d err=%s", cases[i].label, r, le());
    }
}

static const section_t sections[] = {
    { "date", sec_date, F2KT_ALWAYS },
    { "time", sec_time, F2KT_ALWAYS },
    { "number", sec_number, F2KT_ALWAYS },
    { "fold", sec_fold, F2KT_ALWAYS },
    { "codepages", sec_codepages, F2KT_ALWAYS },
    { "langgroup", sec_langgroup, F2KT_ALWAYS },
    { NULL, NULL, 0 }
};

int main(int argc, char **argv)
{
    return run_sections("locale", sections, argc, argv);
}
