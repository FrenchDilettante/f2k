//! Wall-clock time: the FILETIME and SYSTEMTIME the time services report, and the performance
//! counter.
//!
//! The kernel's clock counts from boot; the wall clock is that count plus the boot's own wall-clock
//! reading, taken once from the real-time clock (see [`crate::hw::rtc`]). A FILETIME is 100 ns
//! units since 1601-01-01 UTC, the same unit as the kernel's clock, so the sum needs no scaling.
//! With no time zone configured, local time is UTC: the time-zone services report a zero bias and
//! no daylight saving.
//!
//! The performance counter runs at the interval timer's input clock, 1193182 Hz — what the
//! platform's uniprocessor HAL reports — derived from the kernel's interrupt time, so it advances
//! at each clock interrupt.

use crate::hw::rtc::CivilTime;

/// The performance counter's frequency: the 8254's input clock.
pub const PERFORMANCE_FREQUENCY: u64 = 1_193_182;

/// 100 ns units per second.
const UNITS_PER_SECOND: u64 = 10_000_000;
/// 100 ns units per day.
const UNITS_PER_DAY: u64 = 86_400 * UNITS_PER_SECOND;

/// Days from 1601-01-01 to 1970-01-01.
const DAYS_1601_TO_1970: i64 = 134_774;

/// The wall clock's fallback when the real-time clock gives no valid reading: 2000-01-01 00:00.
pub const FALLBACK_BOOT: u64 = 125_911_584_000_000_000;

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
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of a day count since 1970-01-01 (H. Hinnant's civil_from_days).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// The FILETIME of a civil time.
pub fn filetime_from_civil(time: CivilTime) -> u64 {
    let days = days_from_civil(time.year as i64, time.month as u32, time.day as u32) + DAYS_1601_TO_1970;
    let seconds = time.hour as u64 * 3600 + time.minute as u64 * 60 + time.second as u64;
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

/// The FILETIME of a FAT timestamp (local time, which is UTC here): a date's year counts from
/// 1980, a time's seconds come in units of two, and the hundredths (0-199) add up to two seconds
/// more. A zero or impossible date is no time at all (zero).
pub fn fat_filetime(date: u16, time: u16, hundredths: u8) -> u64 {
    let (month, day) = (((date >> 5) & 0xF) as u8, (date & 0x1F) as u8);
    if date == 0 || !(1..=12).contains(&month) || day == 0 {
        return 0;
    }
    let civil = CivilTime {
        year: 1980 + (date >> 9),
        month,
        day,
        hour: (time >> 11) as u8,
        minute: ((time >> 5) & 0x3F) as u8,
        second: ((time & 0x1F) * 2) as u8,
    };
    filetime_from_civil(civil) + hundredths as u64 * 100_000
}

/// A clock reading (100 ns units) on the performance counter's scale.
pub fn performance_count(units: u64) -> u64 {
    units / UNITS_PER_SECOND * PERFORMANCE_FREQUENCY
        + units % UNITS_PER_SECOND * PERFORMANCE_FREQUENCY / UNITS_PER_SECOND
}

/// The boot's wall-clock reading, a FILETIME; set once at boot.
#[cfg(target_arch = "x86")]
static mut BOOT_FILETIME: u64 = FALLBACK_BOOT;

/// Record the boot's wall-clock reading from the real-time clock (the fallback when it has none).
/// Call once, at boot, while the kernel clock still reads zero.
#[cfg(target_arch = "x86")]
pub fn init<IoT: crate::hw::portio::Io>(io: &mut IoT) {
    let boot = crate::hw::rtc::read(io).map_or(FALLBACK_BOOT, filetime_from_civil);
    // SAFETY: written once at boot, before any reader runs.
    unsafe { BOOT_FILETIME = boot };
}

/// The boot's wall-clock reading.
#[cfg(target_arch = "x86")]
pub fn boot_filetime() -> u64 {
    // SAFETY: written once at boot; read-only afterwards.
    unsafe { BOOT_FILETIME }
}

/// The current wall-clock time, a FILETIME.
#[cfg(target_arch = "x86")]
pub fn system_filetime() -> u64 {
    boot_filetime() + crate::interrupt::clock::system_time()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn civil(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> CivilTime {
        CivilTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// The anchors: the FILETIME epoch, the Unix epoch, and the fallback boot time.
    #[test]
    fn the_epochs_convert() {
        assert_eq!(filetime_from_civil(civil(1601, 1, 1, 0, 0, 0)), 0);
        assert_eq!(filetime_from_civil(civil(1970, 1, 1, 0, 0, 0)), 116_444_736_000_000_000);
        assert_eq!(filetime_from_civil(civil(2000, 1, 1, 0, 0, 0)), FALLBACK_BOOT);
    }

    /// A FILETIME round-trips through the civil fields, with the day of the week and milliseconds.
    #[test]
    fn a_filetime_converts_to_its_system_time() {
        let base = filetime_from_civil(civil(2024, 2, 29, 13, 45, 30));
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
        assert_eq!(system_time_from_filetime(0).day_of_week, 1, "1601-01-01 was a Monday");
        assert_eq!(system_time_from_filetime(FALLBACK_BOOT).day_of_week, 6, "2000-01-01: Saturday");
    }

    /// FAT timestamps: 2026-10-16 18:42:30 plus 57 hundredths, and the no-time zero date.
    #[test]
    fn fat_timestamps_convert() {
        let date = ((2026 - 1980) << 9) | (10 << 5) | 16;
        let time = (18 << 11) | (42 << 5) | 15;
        let base = filetime_from_civil(civil(2026, 10, 16, 18, 42, 30));
        assert_eq!(fat_filetime(date, time, 57), base + 5_700_000);
        assert_eq!(fat_filetime(date, time, 0), base);
        assert_eq!(fat_filetime(0, 0, 0), 0);
    }

    /// The performance counter: a second is the frequency, without overflow far from boot.
    #[test]
    fn the_performance_count_scales_exactly() {
        assert_eq!(performance_count(UNITS_PER_SECOND), PERFORMANCE_FREQUENCY);
        assert_eq!(performance_count(2_000_000), 238_636);
        let year = 365 * UNITS_PER_DAY;
        assert_eq!(performance_count(year), 365 * 86_400 * PERFORMANCE_FREQUENCY);
    }
}
