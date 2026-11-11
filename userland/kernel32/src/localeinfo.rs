//! Locales: the one this surface has — English (United States), LCID 0x0409, the user's and the
//! system's default alike — and the services that describe it.
//!
//! GetLocaleInfoA/W answer from the locale's table: the names, the number and currency formats, the
//! calendar's day and month names, the date and time formats — what the CRT's setlocale reads to
//! build its locale. A string comes back NUL-terminated, its length counting the terminator; a
//! size query (no buffer size) returns that length. With LOCALE_RETURN_NUMBER a numeric value
//! (the `I` types) comes back as a DWORD instead ([`number`]). The default-locale pseudo-LCIDs
//! (LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT) and the neutral ones name it.

/// The locale's identifier: English (United States).
pub const LCID_EN_US: u32 = 0x0409;
/// The default-locale pseudo-identifiers.
pub const LOCALE_USER_DEFAULT: u32 = 0x0400;
pub const LOCALE_SYSTEM_DEFAULT: u32 = 0x0800;

/// LOCALE_RETURN_NUMBER: the value as a DWORD, not a string.
pub const LOCALE_RETURN_NUMBER: u32 = 0x2000_0000;
/// The LCTYPE flags a query may carry beside the type: LOCALE_NOUSEROVERRIDE, LOCALE_USE_CP_ACP and
/// LOCALE_RETURN_NUMBER.
const LCTYPE_FLAGS: u32 = 0x8000_0000 | 0x4000_0000 | LOCALE_RETURN_NUMBER;

/// Whether an LCID names this surface's locale.
pub fn names_locale(lcid: u32) -> bool {
    matches!(
        lcid & 0xFFFF,
        0 | LOCALE_USER_DEFAULT | LOCALE_SYSTEM_DEFAULT | LCID_EN_US
    ) && lcid >> 16 == 0
}

/// The language identifiers of the locales Windows 2000 supports (its locale table's, as MSDN's
/// table of language identifiers lists them for Windows 2000), sorted.
const SUPPORTED_LANGUAGES: [u16; 120] = [
    0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0406, 0x0407, 0x0408, 0x0409, 0x040A, 0x040B, 0x040C,
    0x040D, 0x040E, 0x040F, 0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0418, 0x0419,
    0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, 0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425,
    0x0426, 0x0427, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042F, 0x0436, 0x0437, 0x0438, 0x0439,
    0x043E, 0x043F, 0x0441, 0x0443, 0x0444, 0x0449, 0x044E, 0x044F, 0x0457, 0x0801, 0x0804, 0x0807,
    0x0809, 0x080A, 0x080C, 0x0810, 0x0813, 0x0814, 0x0816, 0x081A, 0x081D, 0x082C, 0x083E, 0x0843,
    0x0C01, 0x0C04, 0x0C07, 0x0C09, 0x0C0A, 0x0C0C, 0x0C1A, 0x1001, 0x1004, 0x1007, 0x1009, 0x100A,
    0x100C, 0x1401, 0x1404, 0x1407, 0x1409, 0x140A, 0x140C, 0x1801, 0x1809, 0x180A, 0x180C, 0x1C01,
    0x1C09, 0x1C0A, 0x2001, 0x2009, 0x200A, 0x2401, 0x2409, 0x240A, 0x2801, 0x2809, 0x280A, 0x2C01,
    0x2C09, 0x2C0A, 0x3001, 0x300A, 0x3401, 0x340A, 0x3801, 0x380A, 0x3C01, 0x3C0A, 0x4001, 0x400A,
];

/// Whether an LCID names a locale Windows 2000 supports, as the NLS calls that take one check it
/// before anything else (CompareString's ERROR_INVALID_PARAMETER for one it does not): the
/// default-locale pseudo-LCIDs and the neutral one (the user's default), or a supported language
/// with the default sort. This surface describes one locale ([`names_locale`]); the others are
/// valid all the same, compared as it compares.
pub fn supported_locale(lcid: u32) -> bool {
    if lcid >> 16 != 0 {
        return false;
    }
    let language = lcid as u16;
    matches!(
        u32::from(language),
        0 | LOCALE_USER_DEFAULT | LOCALE_SYSTEM_DEFAULT
    ) || SUPPORTED_LANGUAGES.binary_search(&language).is_ok()
}

/// The locale's value for an LCTYPE (its flags ignored); none for a type it does not have.
pub fn info(lctype: u32) -> Option<&'static str> {
    const DAYS: [&str; 7] = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    const ABBREV_DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    const ABBREV_MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let lctype = lctype & !LCTYPE_FLAGS;
    Some(match lctype {
        0x01 => "0409",                    // LOCALE_ILANGUAGE
        0x02 => "English (United States)", // LOCALE_SLANGUAGE
        0x03 => "ENU",                     // LOCALE_SABBREVLANGNAME
        0x04 => "English",                 // LOCALE_SNATIVELANGNAME
        0x05 => "1",                       // LOCALE_ICOUNTRY
        0x06 => "United States",           // LOCALE_SCOUNTRY
        0x07 => "USA",                     // LOCALE_SABBREVCTRYNAME
        0x08 => "United States",           // LOCALE_SNATIVECTRYNAME
        0x09 => "0409",                    // LOCALE_IDEFAULTLANGUAGE
        0x0A => "1",                       // LOCALE_IDEFAULTCOUNTRY
        0x0B => "437",                     // LOCALE_IDEFAULTCODEPAGE
        0x0C => ",",                       // LOCALE_SLIST
        0x0D => "1",                       // LOCALE_IMEASURE
        0x0E => ".",                       // LOCALE_SDECIMAL
        0x0F => ",",                       // LOCALE_STHOUSAND
        0x10 => "3;0",                     // LOCALE_SGROUPING
        0x11 => "2",                       // LOCALE_IDIGITS
        0x12 => "1",                       // LOCALE_ILZERO
        0x13 => "0123456789",              // LOCALE_SNATIVEDIGITS
        0x14 => "$",                       // LOCALE_SCURRENCY
        0x15 => "USD",                     // LOCALE_SINTLSYMBOL
        0x16 => ".",                       // LOCALE_SMONDECIMALSEP
        0x17 => ",",                       // LOCALE_SMONTHOUSANDSEP
        0x18 => "3;0",                     // LOCALE_SMONGROUPING
        0x19 => "2",                       // LOCALE_ICURRDIGITS
        0x1A => "2",                       // LOCALE_IINTLCURRDIGITS
        0x1B => "0",                       // LOCALE_ICURRENCY
        0x1C => "0",                       // LOCALE_INEGCURR
        0x1D => "/",                       // LOCALE_SDATE
        0x1E => ":",                       // LOCALE_STIME
        0x1F => "M/d/yyyy",                // LOCALE_SSHORTDATE
        0x20 => "dddd, MMMM dd, yyyy",     // LOCALE_SLONGDATE
        0x21 => "0",                       // LOCALE_IDATE
        0x22 => "0",                       // LOCALE_ILDATE
        0x23 => "0",                       // LOCALE_ITIME
        0x24 => "1",                       // LOCALE_ICENTURY
        0x25 => "0",                       // LOCALE_ITLZERO
        0x26 => "0",                       // LOCALE_IDAYLZERO
        0x27 => "0",                       // LOCALE_IMONLZERO
        0x28 => "AM",                      // LOCALE_S1159
        0x29 => "PM",                      // LOCALE_S2359
        0x2A..=0x30 => DAYS[(lctype - 0x2A) as usize],
        0x31..=0x37 => ABBREV_DAYS[(lctype - 0x31) as usize],
        0x38..=0x43 => MONTHS[(lctype - 0x38) as usize],
        0x44..=0x4F => ABBREV_MONTHS[(lctype - 0x44) as usize],
        0x50 => "",                // LOCALE_SPOSITIVESIGN
        0x51 => "-",               // LOCALE_SNEGATIVESIGN
        0x52 => "3",               // LOCALE_IPOSSIGNPOSN
        0x53 => "0",               // LOCALE_INEGSIGNPOSN
        0x54 => "1",               // LOCALE_IPOSSYMPRECEDES
        0x55 => "0",               // LOCALE_IPOSSEPBYSPACE
        0x56 => "1",               // LOCALE_INEGSYMPRECEDES
        0x57 => "0",               // LOCALE_INEGSEPBYSPACE
        0x59 => "en",              // LOCALE_SISO639LANGNAME
        0x5A => "US",              // LOCALE_SISO3166CTRYNAME
        0x1001 => "English",       // LOCALE_SENGLANGUAGE
        0x1002 => "United States", // LOCALE_SENGCOUNTRY
        0x1003 => "h:mm:ss tt",    // LOCALE_STIMEFORMAT
        0x1004 => "1252",          // LOCALE_IDEFAULTANSICODEPAGE
        0x1005 => "0",             // LOCALE_ITIMEMARKPOSN
        0x1006 => "MMMM, yyyy",    // LOCALE_SYEARMONTH
        0x1007 => "US Dollar",     // LOCALE_SENGCURRNAME
        0x1008 => "US Dollar",     // LOCALE_SNATIVECURRNAME
        0x1009 => "1",             // LOCALE_ICALENDARTYPE
        0x100A => "1",             // LOCALE_IPAPERSIZE (letter)
        0x100B => "0",             // LOCALE_IOPTIONALCALENDAR
        0x100C => "6",             // LOCALE_IFIRSTDAYOFWEEK
        0x100D => "0",             // LOCALE_IFIRSTWEEKOFYEAR
        0x100E => "",              // LOCALE_SMONTHNAME13
        0x100F => "",              // LOCALE_SABBREVMONTHNAME13
        0x1010 => "1",             // LOCALE_INEGNUMBER
        0x1011 => "10000",         // LOCALE_IDEFAULTMACCODEPAGE
        0x1014 => "1",             // LOCALE_IDIGITSUBSTITUTION
        _ => return None,
    })
}

/// The radix a numeric LCTYPE's value is written in: 16 for the language ids, 10 for the other `I`
/// types; none for a type whose value is not a number.
fn radix(lctype: u32) -> Option<u32> {
    match lctype & !LCTYPE_FLAGS {
        0x01 | 0x09 => Some(16), // LOCALE_ILANGUAGE, LOCALE_IDEFAULTLANGUAGE
        0x05
        | 0x0A
        | 0x0B
        | 0x0D
        | 0x11
        | 0x12
        | 0x19..=0x1C
        | 0x21..=0x27
        | 0x52..=0x57
        | 0x1004
        | 0x1005
        | 0x1009..=0x100D
        | 0x1010
        | 0x1011
        | 0x1014 => Some(10),
        _ => None,
    }
}

/// The locale's value for a numeric LCTYPE, as LOCALE_RETURN_NUMBER returns it; none for a type
/// whose value is not a number (or one the locale lacks).
pub fn number(lctype: u32) -> Option<u32> {
    let radix = radix(lctype)?;
    info(lctype)?.chars().try_fold(0, |value: u32, digit| {
        Some(value * radix + digit.to_digit(radix)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture's three queries, and the names setlocale builds its locale name from.
    #[test]
    fn the_captured_values() {
        assert_eq!(info(0x1001), Some("English"));
        assert_eq!(info(0x1004), Some("1252"));
        assert_eq!(info(0x0E), Some("."));
        assert_eq!(info(0x1002), Some("United States"));
        assert_eq!(info(0x2A), Some("Monday"));
        assert_eq!(info(0x4F), Some("Dec"));
        assert_eq!(info(0x8000_0000 | 0x0E), Some("."), "flags ignored");
        assert_eq!(info(0x7777), None);
        assert!(
            names_locale(LOCALE_USER_DEFAULT) && names_locale(LCID_EN_US) && !names_locale(0x0407)
        );
    }

    /// Every numeric type's value is a number in its radix; the string types have none.
    #[test]
    fn the_numeric_types_parse() {
        for lctype in (0..0x60).chain(0x1000..0x1020) {
            if radix(lctype).is_some() {
                assert!(number(lctype).is_some(), "{lctype:#x}: {:?}", info(lctype));
            }
        }
        assert_eq!(number(0x01), Some(0x409));
        assert_eq!(number(LOCALE_RETURN_NUMBER | 0x1004), Some(1252));
        assert_eq!(
            (number(0x0E), number(0x10), number(0x1001)),
            (None, None, None)
        );
    }
}
