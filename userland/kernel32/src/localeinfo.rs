//! Locales: the three this surface describes — English (United States), LCID 0x0409, the user's
//! and the system's default alike; French (France), 0x040C; German (Germany), 0x0407 — and the
//! services that describe them.
//!
//! GetLocaleInfoA/W answer from the locale's table: the names, the number and currency formats, the
//! calendar's day and month names, the date and time formats — what the CRT's setlocale reads to
//! build its locale. A string comes back NUL-terminated, its length counting the terminator; a
//! size query (no buffer size) returns that length. With LOCALE_RETURN_NUMBER a numeric value
//! (the `I` types) comes back as a DWORD instead ([`number`]). The default-locale pseudo-LCIDs
//! (LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT) and the neutral ones name English. The French and
//! German values are Windows 2000's (pre-euro: the franc and the mark); the date, time and number
//! formats (`crate::nlsformat`) are English's alone.
//!
//! IsValidLocale knows the locales Windows 2000 supports, and the ones a machine with the Western
//! Europe and United States language group installs (the capture machine's).

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

/// The locale a default pseudo-locale or a neutral one stands for: English (United States).
fn resolved(lcid: u32) -> u32 {
    match lcid & 0xFFFF {
        0 | LOCALE_USER_DEFAULT | LOCALE_SYSTEM_DEFAULT => LCID_EN_US,
        language => language,
    }
}

/// French (France) and German (Germany).
pub const LCID_FR_FR: u32 = 0x040C;
pub const LCID_DE_DE: u32 = 0x0407;

/// Whether an LCID names a locale this surface describes (GetLocaleInfo's).
pub fn names_locale(lcid: u32) -> bool {
    lcid >> 16 == 0 && matches!(resolved(lcid), LCID_EN_US | LCID_FR_FR | LCID_DE_DE)
}

/// Whether an LCID names the locale whose date, time and number formats this surface has
/// (English's, `crate::nlsformat`'s).
pub fn formats_locale(lcid: u32) -> bool {
    lcid >> 16 == 0 && resolved(lcid) == LCID_EN_US
}

/// The primary languages of the Western Europe and United States language group, whose locales a
/// Windows 2000 machine with that group alone installs: Catalan, Danish, German, English, Spanish,
/// Finnish, French, Icelandic, Italian, Dutch, Norwegian, Portuguese, Swedish, Indonesian, Basque,
/// Afrikaans, Faeroese, Malay, Swahili.
const WESTERN_EUROPE: [u16; 19] = [
    0x03, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 0x0F, 0x10, 0x13, 0x14, 0x16, 0x1D, 0x21, 0x2D, 0x36,
    0x38, 0x3E, 0x41,
];

/// IsValidLocale's LCID_INSTALLED and LCID_SUPPORTED.
pub const LCID_INSTALLED: u32 = 1;
pub const LCID_SUPPORTED: u32 = 2;

/// IsValidLocale's answer: a locale Windows 2000 supports, with the default sort (no pseudo-locale,
/// no neutral one), and for LCID_INSTALLED one of the installed language group's; other flags
/// answer FALSE.
pub fn valid_locale(lcid: u32, flags: u32) -> bool {
    let language = lcid as u16;
    let supported = lcid >> 16 == 0 && SUPPORTED_LANGUAGES.binary_search(&language).is_ok();
    match flags {
        LCID_SUPPORTED => supported,
        LCID_INSTALLED => supported && WESTERN_EUROPE.contains(&(language & 0x3FF)),
        _ => false,
    }
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

/// LOCALE_FONTSIGNATURE: a LOCALESIGNATURE, sixteen units of bits, not a string.
pub const LOCALE_FONTSIGNATURE: u32 = 0x58;

/// A locale's LOCALESIGNATURE (LOCALE_FONTSIGNATURE): its Unicode subsets' and code pages' bits, as
/// Windows 2000's locale table holds them; none for a locale whose this surface lacks.
pub fn font_signature(lcid: u32) -> Option<[u16; 16]> {
    match resolved(lcid) {
        LCID_EN_US => Some([
            0x00AF, 0x8000, 0x38CB, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0000, 0x0000,
            0x8000, 0x01FF, 0x003F, 0x8000, 0xFFFF,
        ]),
        LCID_FR_FR => Some([
            0x002F, 0x8000, 0x3808, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0000, 0x0000,
            0x4000, 0x0013, 0x0000, 0x0000, 0xC5D4,
        ]),
        _ => None,
    }
}

/// A locale's value for an LCTYPE (its flags ignored); none for a locale this surface does not
/// describe, or a type it does not have.
pub fn info(lcid: u32, lctype: u32) -> Option<&'static str> {
    if lcid >> 16 != 0 {
        return None;
    }
    match resolved(lcid) {
        LCID_EN_US => english(lctype),
        LCID_FR_FR => french(lctype),
        LCID_DE_DE => german(lctype),
        _ => None,
    }
}

/// English (United States)'s values.
fn english(lctype: u32) -> Option<&'static str> {
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
        0x1012 => "037",           // LOCALE_IDEFAULTEBCDICCODEPAGE
        0x1014 => "1",             // LOCALE_IDIGITSUBSTITUTION
        _ => return None,
    })
}

/// The values French (France) and German (Germany) share, and differ from English's in.
fn european(lctype: u32) -> Option<&'static str> {
    Some(match lctype & !LCTYPE_FLAGS {
        0x0B => "850",         // LOCALE_IDEFAULTCODEPAGE
        0x0C => ";",           // LOCALE_SLIST
        0x0D => "0",           // LOCALE_IMEASURE (metric)
        0x0E | 0x16 => ",",    // LOCALE_SDECIMAL, LOCALE_SMONDECIMALSEP
        0x1B => "3",           // LOCALE_ICURRENCY (1 F)
        0x1C => "8",           // LOCALE_INEGCURR (-1 F)
        0x1E => ":",           // LOCALE_STIME
        0x21 | 0x22 => "1",    // LOCALE_IDATE, LOCALE_ILDATE (day first)
        0x23 => "1",           // LOCALE_ITIME (24 hours)
        0x25..=0x27 => "1",    // LOCALE_ITLZERO, LOCALE_IDAYLZERO, LOCALE_IMONLZERO
        0x28 | 0x29 => "",     // LOCALE_S1159, LOCALE_S2359
        0x52 | 0x53 => "1",    // LOCALE_IPOSSIGNPOSN, LOCALE_INEGSIGNPOSN
        0x54 | 0x56 => "0",    // LOCALE_IPOSSYMPRECEDES, LOCALE_INEGSYMPRECEDES
        0x55 | 0x57 => "1",    // LOCALE_IPOSSEPBYSPACE, LOCALE_INEGSEPBYSPACE
        0x1003 => "HH:mm:ss",  // LOCALE_STIMEFORMAT
        0x1006 => "MMMM yyyy", // LOCALE_SYEARMONTH
        0x100A => "9",         // LOCALE_IPAPERSIZE (A4)
        0x100C => "0",         // LOCALE_IFIRSTDAYOFWEEK (Monday)
        _ => return english(lctype),
    })
}

/// French (France)'s values.
fn french(lctype: u32) -> Option<&'static str> {
    const DAYS: [&str; 7] = [
        "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche",
    ];
    const ABBREV_DAYS: [&str; 7] = ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."];
    const MONTHS: [&str; 12] = [
        "janvier",
        "février",
        "mars",
        "avril",
        "mai",
        "juin",
        "juillet",
        "août",
        "septembre",
        "octobre",
        "novembre",
        "décembre",
    ];
    const ABBREV_MONTHS: [&str; 12] = [
        "janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.",
        "déc.",
    ];
    let lctype = lctype & !LCTYPE_FLAGS;
    Some(match lctype {
        0x01 | 0x09 => "040c",            // LOCALE_ILANGUAGE, LOCALE_IDEFAULTLANGUAGE
        0x02 => "French (Standard)",      // LOCALE_SLANGUAGE
        0x03 => "FRA",                    // LOCALE_SABBREVLANGNAME
        0x04 => "français",               // LOCALE_SNATIVELANGNAME
        0x05 | 0x0A => "33",              // LOCALE_ICOUNTRY, LOCALE_IDEFAULTCOUNTRY
        0x06 | 0x08 | 0x1002 => "France", // LOCALE_SCOUNTRY, SNATIVECTRYNAME, SENGCOUNTRY
        0x07 => "FRA",                    // LOCALE_SABBREVCTRYNAME
        0x0F | 0x17 => "\u{A0}",          // LOCALE_STHOUSAND, LOCALE_SMONTHOUSANDSEP
        0x14 => "F",                      // LOCALE_SCURRENCY
        0x15 => "FRF",                    // LOCALE_SINTLSYMBOL
        0x1D => "/",                      // LOCALE_SDATE
        0x1F => "dd/MM/yyyy",             // LOCALE_SSHORTDATE
        0x20 => "dddd d MMMM yyyy",       // LOCALE_SLONGDATE
        0x2A..=0x30 => DAYS[(lctype - 0x2A) as usize],
        0x31..=0x37 => ABBREV_DAYS[(lctype - 0x31) as usize],
        0x38..=0x43 => MONTHS[(lctype - 0x38) as usize],
        0x44..=0x4F => ABBREV_MONTHS[(lctype - 0x44) as usize],
        0x59 => "fr",               // LOCALE_SISO639LANGNAME
        0x5A => "FR",               // LOCALE_SISO3166CTRYNAME
        0x1001 => "French",         // LOCALE_SENGLANGUAGE
        0x1007 => "French Franc",   // LOCALE_SENGCURRNAME
        0x1008 => "franc français", // LOCALE_SNATIVECURRNAME
        0x1012 => "20297",          // LOCALE_IDEFAULTEBCDICCODEPAGE
        _ => return european(lctype),
    })
}

/// German (Germany)'s values.
fn german(lctype: u32) -> Option<&'static str> {
    const DAYS: [&str; 7] = [
        "Montag",
        "Dienstag",
        "Mittwoch",
        "Donnerstag",
        "Freitag",
        "Samstag",
        "Sonntag",
    ];
    const ABBREV_DAYS: [&str; 7] = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"];
    const MONTHS: [&str; 12] = [
        "Januar",
        "Februar",
        "März",
        "April",
        "Mai",
        "Juni",
        "Juli",
        "August",
        "September",
        "Oktober",
        "November",
        "Dezember",
    ];
    const ABBREV_MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mrz", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez",
    ];
    let lctype = lctype & !LCTYPE_FLAGS;
    Some(match lctype {
        0x01 | 0x09 => "0407",        // LOCALE_ILANGUAGE, LOCALE_IDEFAULTLANGUAGE
        0x02 => "German (Standard)",  // LOCALE_SLANGUAGE
        0x03 => "DEU",                // LOCALE_SABBREVLANGNAME
        0x04 => "Deutsch",            // LOCALE_SNATIVELANGNAME
        0x05 | 0x0A => "49",          // LOCALE_ICOUNTRY, LOCALE_IDEFAULTCOUNTRY
        0x06 | 0x1002 => "Germany",   // LOCALE_SCOUNTRY, LOCALE_SENGCOUNTRY
        0x07 => "DEU",                // LOCALE_SABBREVCTRYNAME
        0x08 => "Deutschland",        // LOCALE_SNATIVECTRYNAME
        0x0F | 0x17 => ".",           // LOCALE_STHOUSAND, LOCALE_SMONTHOUSANDSEP
        0x14 => "DM",                 // LOCALE_SCURRENCY
        0x15 => "DEM",                // LOCALE_SINTLSYMBOL
        0x1D => ".",                  // LOCALE_SDATE
        0x1F => "dd.MM.yyyy",         // LOCALE_SSHORTDATE
        0x20 => "dddd, d. MMMM yyyy", // LOCALE_SLONGDATE
        0x2A..=0x30 => DAYS[(lctype - 0x2A) as usize],
        0x31..=0x37 => ABBREV_DAYS[(lctype - 0x31) as usize],
        0x38..=0x43 => MONTHS[(lctype - 0x38) as usize],
        0x44..=0x4F => ABBREV_MONTHS[(lctype - 0x44) as usize],
        0x59 => "de",              // LOCALE_SISO639LANGNAME
        0x5A => "DE",              // LOCALE_SISO3166CTRYNAME
        0x1001 => "German",        // LOCALE_SENGLANGUAGE
        0x1007 => "German Mark",   // LOCALE_SENGCURRNAME
        0x1008 => "Deutsche Mark", // LOCALE_SNATIVECURRNAME
        0x100D => "2",             // LOCALE_IFIRSTWEEKOFYEAR (the first four-day week)
        0x1012 => "20273",         // LOCALE_IDEFAULTEBCDICCODEPAGE
        _ => return european(lctype),
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
        | 0x1010..=0x1012
        | 0x1014 => Some(10),
        _ => None,
    }
}

/// A locale's value for a numeric LCTYPE, as LOCALE_RETURN_NUMBER returns it; none for a type
/// whose value is not a number (or one the locale lacks).
pub fn number(lcid: u32, lctype: u32) -> Option<u32> {
    let radix = radix(lctype)?;
    info(lcid, lctype)?
        .chars()
        .try_fold(0, |value: u32, digit| {
            Some(value * radix + digit.to_digit(radix)?)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture's three queries, and the names setlocale builds its locale name from.
    #[test]
    fn the_captured_values() {
        let en = LCID_EN_US;
        assert_eq!(info(en, 0x1001), Some("English"));
        assert_eq!(info(LOCALE_USER_DEFAULT, 0x1004), Some("1252"));
        assert_eq!(info(en, 0x0E), Some("."));
        assert_eq!(info(en, 0x1002), Some("United States"));
        assert_eq!(info(en, 0x2A), Some("Monday"));
        assert_eq!(info(en, 0x4F), Some("Dec"));
        assert_eq!(info(en, 0x8000_0000 | 0x0E), Some("."), "flags ignored");
        assert_eq!(info(en, 0x7777), None);
        assert_eq!(info(en, 0x1012), Some("037"));
        assert!(names_locale(LOCALE_USER_DEFAULT) && names_locale(LCID_EN_US));
        assert!(names_locale(0x0407) && !names_locale(0x0C0C) && !names_locale(0x1234));
        assert!(formats_locale(0) && !formats_locale(LCID_FR_FR));
    }

    /// The locales fixture's French and German values.
    #[test]
    fn the_french_and_german_values() {
        let fr = LCID_FR_FR;
        assert_eq!(info(fr, 0x01), Some("040c"));
        assert_eq!(info(fr, 0x04), Some("français"));
        assert_eq!(info(fr, 0x0B), Some("850"));
        assert_eq!(info(fr, 0x0F), Some("\u{A0}"));
        assert_eq!(info(fr, 0x14), Some("F"));
        assert_eq!(info(fr, 0x20), Some("dddd d MMMM yyyy"));
        assert_eq!(info(fr, 0x1003), Some("HH:mm:ss"));
        assert_eq!(info(fr, 0x2A), Some("lundi"));
        assert_eq!(info(fr, 0x39), Some("février"));
        assert_eq!(info(fr, 0x0C), Some(";"));
        assert_eq!(info(LCID_DE_DE, 0x1001), Some("German"));
        assert_eq!(info(LCID_DE_DE, 0x0E), Some(","));
        assert_eq!(info(LCID_DE_DE, 0x2A), Some("Montag"));
        assert_eq!(info(LCID_DE_DE, 0x1F), Some("dd.MM.yyyy"));
        assert_eq!(info(0x1234, 0x1001), None);
        assert_eq!(font_signature(fr).map(|s| s[15]), Some(0xC5D4));
    }

    /// IsValidLocale: supported is Windows 2000's table, installed the Western Europe group's.
    #[test]
    fn the_valid_locales() {
        for lcid in [0x0409, 0x040C, 0x0407, 0x0C0C] {
            assert!(valid_locale(lcid, LCID_INSTALLED) && valid_locale(lcid, LCID_SUPPORTED));
        }
        for lcid in [0x0411, 0x0419] {
            assert!(!valid_locale(lcid, LCID_INSTALLED) && valid_locale(lcid, LCID_SUPPORTED));
        }
        for lcid in [0x1234, 0, LOCALE_USER_DEFAULT] {
            assert!(!valid_locale(lcid, LCID_INSTALLED) && !valid_locale(lcid, LCID_SUPPORTED));
        }
        assert!(!valid_locale(0x0409, 3));
    }

    /// Every numeric type's value is a number in its radix, in every locale; the string types have
    /// none.
    #[test]
    fn the_numeric_types_parse() {
        for lcid in [LCID_EN_US, LCID_FR_FR, LCID_DE_DE] {
            for lctype in (0..0x60).chain(0x1000..0x1020) {
                if radix(lctype).is_some() {
                    let value = info(lcid, lctype);
                    assert!(
                        number(lcid, lctype).is_some(),
                        "{lcid:#x} {lctype:#x}: {value:?}"
                    );
                }
            }
        }
        assert_eq!(number(LCID_EN_US, 0x01), Some(0x409));
        assert_eq!(number(LCID_FR_FR, 0x01), Some(0x40C));
        assert_eq!(
            number(LCID_EN_US, LOCALE_RETURN_NUMBER | 0x1004),
            Some(1252)
        );
        assert_eq!(
            (
                number(LCID_EN_US, 0x0E),
                number(LCID_EN_US, 0x10),
                number(LCID_EN_US, 0x1001)
            ),
            (None, None, None)
        );
    }
}
