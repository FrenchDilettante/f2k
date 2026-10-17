//! Locales: the one this surface has — English (United States), LCID 0x0409, the user's and the
//! system's default alike — and the services that describe it.
//!
//! GetLocaleInfoA/W answer from the locale's table: the names, the number and currency formats, the
//! calendar's day and month names, the date and time formats — what the CRT's setlocale reads to
//! build its locale. A string comes back NUL-terminated, its length counting the terminator; a
//! size query (no buffer size) returns that length. The default-locale pseudo-LCIDs
//! (LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT) and the neutral ones name it.

/// The locale's identifier: English (United States).
pub const LCID_EN_US: u32 = 0x0409;
/// The default-locale pseudo-identifiers.
pub const LOCALE_USER_DEFAULT: u32 = 0x0400;
pub const LOCALE_SYSTEM_DEFAULT: u32 = 0x0800;

/// The LCTYPE flags a query may carry beside the type.
const LCTYPE_FLAGS: u32 = 0x8000_0000 | 0x4000_0000 | 0x2000_0000;

/// Whether an LCID names this surface's locale.
pub fn names_locale(lcid: u32) -> bool {
    matches!(lcid & 0xFFFF, 0 | LOCALE_USER_DEFAULT | LOCALE_SYSTEM_DEFAULT | LCID_EN_US)
        && lcid >> 16 == 0
}

/// The locale's value for an LCTYPE (its flags ignored); none for a type it does not have.
pub fn info(lctype: u32) -> Option<&'static str> {
    const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    const ABBREV_DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "January", "February", "March", "April", "May", "June", "July", "August", "September",
        "October", "November", "December",
    ];
    const ABBREV_MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
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
        0x50 => "",                        // LOCALE_SPOSITIVESIGN
        0x51 => "-",                       // LOCALE_SNEGATIVESIGN
        0x52 => "3",                       // LOCALE_IPOSSIGNPOSN
        0x53 => "0",                       // LOCALE_INEGSIGNPOSN
        0x54 => "1",                       // LOCALE_IPOSSYMPRECEDES
        0x55 => "0",                       // LOCALE_IPOSSEPBYSPACE
        0x56 => "1",                       // LOCALE_INEGSYMPRECEDES
        0x57 => "0",                       // LOCALE_INEGSEPBYSPACE
        0x59 => "en",                      // LOCALE_SISO639LANGNAME
        0x5A => "US",                      // LOCALE_SISO3166CTRYNAME
        0x1001 => "English",               // LOCALE_SENGLANGUAGE
        0x1002 => "United States",         // LOCALE_SENGCOUNTRY
        0x1003 => "h:mm:ss tt",            // LOCALE_STIMEFORMAT
        0x1004 => "1252",                  // LOCALE_IDEFAULTANSICODEPAGE
        0x1005 => "0",                     // LOCALE_ITIMEMARKPOSN
        0x1006 => "MMMM, yyyy",            // LOCALE_SYEARMONTH
        0x1007 => "US Dollar",             // LOCALE_SENGCURRNAME
        0x1008 => "US Dollar",             // LOCALE_SNATIVECURRNAME
        0x1009 => "1",                     // LOCALE_ICALENDARTYPE
        0x100A => "1",                     // LOCALE_IPAPERSIZE (letter)
        0x100B => "0",                     // LOCALE_IOPTIONALCALENDAR
        0x100C => "6",                     // LOCALE_IFIRSTDAYOFWEEK
        0x100D => "0",                     // LOCALE_IFIRSTWEEKOFYEAR
        0x100E => "",                      // LOCALE_SMONTHNAME13
        0x100F => "",                      // LOCALE_SABBREVMONTHNAME13
        0x1010 => "1",                     // LOCALE_INEGNUMBER
        0x1011 => "10000",                 // LOCALE_IDEFAULTMACCODEPAGE
        0x1014 => "1",                     // LOCALE_IDIGITSUBSTITUTION
        _ => return None,
    })
}

// --- Services --------------------------------------------------------------------------------------

use crate::compat::error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NOACCESS};
use crate::user::syscall::write_user;
use crate::user::teb::set_last_error;

/// GetUserDefaultLCID and GetSystemDefaultLCID: the one locale.
pub fn svc_get_default_lcid(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = LCID_EN_US;
}

/// IsValidLocale: the one locale is installed and supported.
pub fn svc_is_valid_locale(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = u32::from(args[0] == LCID_EN_US);
}

/// GetLocaleInfoA/W's common body: the value, written in `unit`-byte characters (ASCII widened for
/// the W form). ERROR_INVALID_PARAMETER for another locale or a bad buffer argument,
/// ERROR_INVALID_FLAGS for an unknown type, ERROR_INSUFFICIENT_BUFFER for a buffer too small.
fn get_locale_info(frame: &mut crate::user::TrapFrame, args: &[u32], unit: u32) {
    let (lcid, lctype, buffer, size) = (args[0], args[1], args[2], args[3] as i32);
    frame.eax = 0;
    if !names_locale(lcid) || size < 0 || (size > 0 && buffer == 0) {
        return set_last_error(ERROR_INVALID_PARAMETER);
    }
    let Some(value) = info(lctype) else {
        return set_last_error(ERROR_INVALID_FLAGS);
    };
    let length = value.len() as u32 + 1;
    if size == 0 {
        frame.eax = length;
        return;
    }
    if (size as u32) < length {
        return set_last_error(ERROR_INSUFFICIENT_BUFFER);
    }
    for (i, byte) in value.bytes().chain(core::iter::once(0)).enumerate() {
        let at = buffer + i as u32 * unit;
        let ok = if unit == 1 {
            write_user(at, &[byte]).is_ok()
        } else {
            write_user(at, &(byte as u16).to_le_bytes()).is_ok()
        };
        if !ok {
            return set_last_error(ERROR_NOACCESS);
        }
    }
    frame.eax = length;
}

/// GetLocaleInfoA.
pub fn svc_get_locale_info_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    get_locale_info(frame, args, 1);
}

/// GetLocaleInfoW.
pub fn svc_get_locale_info_w(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    get_locale_info(frame, args, 2);
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
        assert!(names_locale(LOCALE_USER_DEFAULT) && names_locale(LCID_EN_US) && !names_locale(0x0407));
    }
}
