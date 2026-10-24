//! Time conversions: FILETIME (100 ns units since 1601-01-01 UTC) to and from SYSTEMTIME's civil
//! fields, as Windows 2000's RtlTimeToTimeFields and RtlTimeFieldsToTime convert them (the
//! proleptic Gregorian calendar; 1601-01-01 was a Monday).

/// 100 ns units per second.
pub const UNITS_PER_SECOND: u64 = 10_000_000;
/// 100 ns units per day.
pub const UNITS_PER_DAY: u64 = 86_400 * UNITS_PER_SECOND;

/// Days from 1601-01-01 to 1970-01-01.
const DAYS_1601_TO_1970: i64 = 134_774;

/// A SYSTEMTIME: the civil fields, in the structure's order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}

impl SystemTime {
    /// The structure's 16 bytes.
    pub fn to_bytes(self) -> [u8; 16] {
        let words = [
            self.year,
            self.month,
            self.day_of_week,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.milliseconds,
        ];
        let mut bytes = [0u8; 16];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of a day count since 1970-01-01 (H. Hinnant's civil_from_days).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// The FILETIME of a civil date and time of day (no range checks: the fields are taken as given).
pub fn filetime_from_fields(
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
) -> u64 {
    let days = days_from_civil(year as i64, month as u32, day as u32) + DAYS_1601_TO_1970;
    let seconds = hour as u64 * 3600 + minute as u64 * 60 + second as u64;
    days as u64 * UNITS_PER_DAY + seconds * UNITS_PER_SECOND
}

/// The SYSTEMTIME of a FILETIME (FileTimeToSystemTime's arithmetic; 1601-01-01 was a Monday).
pub fn system_time_from_filetime(filetime: u64) -> SystemTime {
    let days = filetime / UNITS_PER_DAY;
    let within = filetime % UNITS_PER_DAY;
    let (year, month, day) = civil_from_days(days as i64 - DAYS_1601_TO_1970);
    let seconds = within / UNITS_PER_SECOND;
    SystemTime {
        year: year as u16,
        month: month as u16,
        day_of_week: ((days + 1) % 7) as u16,
        day: day as u16,
        hour: (seconds / 3600) as u16,
        minute: (seconds / 60 % 60) as u16,
        second: (seconds % 60) as u16,
        milliseconds: (within % UNITS_PER_SECOND / 10_000) as u16,
    }
}

/// The FILETIME of a SYSTEMTIME (SystemTimeToFileTime): none for a field out of its range (the
/// day of the week is not consulted).
pub fn filetime_from_system_time(time: SystemTime) -> Option<u64> {
    let leap = |y: u16| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in_month = match time.month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap(time.year) => 29,
        2 => 28,
        _ => return None,
    };
    if !(1601..=30827).contains(&time.year)
        || !(1..=days_in_month).contains(&time.day)
        || time.hour > 23
        || time.minute > 59
        || time.second > 59
        || time.milliseconds > 999
    {
        return None;
    }
    let base = filetime_from_fields(
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
    );
    Some(base + time.milliseconds as u64 * 10_000)
}

impl SystemTime {
    /// The structure from its 16 bytes.
    pub fn from_bytes(bytes: &[u8; 16]) -> SystemTime {
        let word = |i: usize| u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
        SystemTime {
            year: word(0),
            month: word(1),
            day_of_week: word(2),
            day: word(3),
            hour: word(4),
            minute: word(5),
            second: word(6),
            milliseconds: word(7),
        }
    }
}

/// A TIME_FIELDS, the documented structure ntdll's conversions fill and read: the civil fields,
/// each a CSHORT, in its order (the day of the week last, where a SYSTEMTIME has it third).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TimeFields {
    pub year: i16,
    pub month: i16,
    pub day: i16,
    pub hour: i16,
    pub minute: i16,
    pub second: i16,
    pub milliseconds: i16,
    pub weekday: i16,
}

/// RtlTimeToTimeFields: the civil fields of a time (100 ns units since 1601), its day of the week
/// with them.
pub fn time_to_time_fields(time: i64) -> TimeFields {
    let civil = system_time_from_filetime(time as u64);
    TimeFields {
        year: civil.year as i16,
        month: civil.month as i16,
        day: civil.day as i16,
        hour: civil.hour as i16,
        minute: civil.minute as i16,
        second: civil.second as i16,
        milliseconds: civil.milliseconds as i16,
        weekday: civil.day_of_week as i16,
    }
}

/// RtlTimeFieldsToTime: the time of the civil fields; none (the call's FALSE) for a field out of
/// its range, the weekday not consulted ([`filetime_from_system_time`]'s ranges).
pub fn time_fields_to_time(fields: &TimeFields) -> Option<i64> {
    filetime_from_system_time(SystemTime {
        year: fields.year as u16,
        month: fields.month as u16,
        day_of_week: fields.weekday as u16,
        day: fields.day as u16,
        hour: fields.hour as u16,
        minute: fields.minute as u16,
        second: fields.second as u16,
        milliseconds: fields.milliseconds as u16,
    })
    .map(|time| time as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchors: the FILETIME epoch and the Unix epoch.
    #[test]
    fn the_epochs_convert() {
        assert_eq!(filetime_from_fields(1601, 1, 1, 0, 0, 0), 0);
        assert_eq!(
            filetime_from_fields(1970, 1, 1, 0, 0, 0),
            116_444_736_000_000_000
        );
        assert_eq!(
            filetime_from_fields(2000, 1, 1, 0, 0, 0),
            125_911_584_000_000_000
        );
    }

    /// A FILETIME round-trips through the civil fields, with the day of the week and milliseconds.
    #[test]
    fn a_filetime_converts_to_its_system_time() {
        let base = filetime_from_fields(2024, 2, 29, 13, 45, 30);
        let st = system_time_from_filetime(base + 1_234_5678);
        assert_eq!(
            st,
            SystemTime {
                year: 2024,
                month: 2,
                day_of_week: 4, // a Thursday
                day: 29,
                hour: 13,
                minute: 45,
                second: 31,
                milliseconds: 234,
            }
        );
        assert_eq!(
            system_time_from_filetime(0).day_of_week,
            1,
            "1601-01-01 was a Monday"
        );
        assert_eq!(filetime_from_system_time(st), Some(base + 1_234_0000));
        assert_eq!(SystemTime::from_bytes(&st.to_bytes()), st);
    }

    /// The TIME_FIELDS forms: a time's fields, the weekday last, and back; a field out of range,
    /// or one a CSHORT reads as negative, refused.
    #[test]
    fn time_fields_convert_both_ways() {
        let time = filetime_from_fields(2024, 2, 29, 13, 45, 30) as i64 + 2_340_000;
        let fields = time_to_time_fields(time);
        assert_eq!(
            fields,
            TimeFields {
                year: 2024,
                month: 2,
                day: 29,
                hour: 13,
                minute: 45,
                second: 30,
                milliseconds: 234,
                weekday: 4,
            }
        );
        assert_eq!(time_fields_to_time(&fields), Some(time));
        let any_weekday = TimeFields {
            weekday: 0,
            ..fields
        };
        assert_eq!(time_fields_to_time(&any_weekday), Some(time));
        assert_eq!(time_fields_to_time(&TimeFields { day: 30, ..fields }), None);
        assert_eq!(
            time_fields_to_time(&TimeFields { hour: -1, ..fields }),
            None
        );
    }

    /// SystemTimeToFileTime refuses a field out of its range (not the day of the week).
    #[test]
    fn out_of_range_fields_are_refused() {
        let st = SystemTime {
            year: 2001,
            month: 2,
            day_of_week: 9,
            day: 3,
            hour: 4,
            minute: 5,
            second: 6,
            milliseconds: 0,
        };
        assert!(filetime_from_system_time(st).is_some());
        assert_eq!(
            filetime_from_system_time(SystemTime { month: 13, ..st }),
            None
        );
        assert_eq!(
            filetime_from_system_time(SystemTime {
                day: 29,
                month: 2,
                ..st
            }),
            None
        );
        assert_eq!(
            filetime_from_system_time(SystemTime { year: 1600, ..st }),
            None
        );
        assert_eq!(
            filetime_from_system_time(SystemTime {
                milliseconds: 1000,
                ..st
            }),
            None
        );
    }
}
